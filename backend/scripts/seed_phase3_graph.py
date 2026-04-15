#!/usr/bin/env python3
"""
Phase 3 graph seed — A4 fixture generator.

Populates a minimal but policy-complete synthetic graph under
``organization_id = 1`` so the Phase 3 BFS engine has something to walk
during the A4 live canary.

Node layout (7 nodes, all organization_id=1)
--------------------------------------------
- HI       (node_type='identity', UUID) — Human Identity
- SPN      (node_type='identity', UUID) — Service Principal
- UAMI     (node_type='identity', UUID) — User-Assigned Managed Identity
- ROLE     (node_type='role',     UUID) — Contributor-like role def
- RG       (node_type='resource', UUID) — Resource Group (permission scope)
- KV       (node_type='resource', UUID) — Key Vault
- SA       (node_type='resource', UUID) — Storage Account

Edge layout (>= 5 edges, policy-compliant for FULL_BLAST_RADIUS_POLICY)
----------------------------------------------------------------------
1. HI   -HAS_ROLE->       ROLE
2. UAMI -HAS_ROLE->       ROLE
3. ROLE -HAS_PERMISSION-> RG
4. RG   -CAN_ACCESS->     KV   [HI, UAMI reach KV via 3-hop chain]
5. RG   -CAN_ACCESS->     SA   [HI, UAMI reach SA via 3-hop chain]
6. SPN  -OWNS->           SA   [shared leaf via different 1-hop path]
7. HI   -OWNS->           SA   [HI also reaches SA via OWNS]

Policy match — FULL_BLAST_RADIUS_POLICY.allowed_edge_sequences:
- [HAS_ROLE, HAS_PERMISSION, CAN_ACCESS]  -> HI/UAMI multi-hop chains
- [OWNS]                                  -> HI/SPN single-hop chains

Expected blast radius for HI: total_reachable == 2 (KV, SA).

Identity rows (Phase 3 profile loader contract)
-----------------------------------------------
The IdentityProfileBuilder SELECTs columns added by migration 085.
Each identity row is inserted with the Phase 3 columns populated plus
all legacy NOT NULL columns. Seed uses ``ON CONFLICT (identity_id)
DO UPDATE`` keyed by the unique index on ``identity_id`` (added below
if missing).

Idempotency
-----------
Re-running the script leaves the DB in the same terminal state:

* ``cloud_connections`` upsert via ON CONFLICT on the existing unique
  ``(organization_id, cloud, azure_directory_id)`` constraint.
* ``identities`` upsert via ON CONFLICT on ``identity_id`` — a partial
  unique index is created if one does not already exist so repeat
  runs never double-insert.
* ``graph_nodes`` upsert via ON CONFLICT on the pre-existing
  ``(cloud_connection_id, node_type, external_id)`` unique index.
* ``graph_edges`` DELETE-then-INSERT scoped to ``metadata->>'seed' =
  'phase3_a4'``; unaffected for any other edge in the table.

Usage
-----
From the ``backend`` directory::

    ./venv/bin/python scripts/seed_phase3_graph.py
    ./venv/bin/python scripts/seed_phase3_graph.py --verify
    ./venv/bin/python scripts/seed_phase3_graph.py --canary

``--verify`` runs the seed then asserts the count targets and prints the
seeded HI identity_id plus a forged JWT that can be handed to curl.
``--canary`` additionally invokes the mounted Flask+FastAPI stack via
its WSGI test client to hit ``GET /api/v1/identities/{HI}`` and asserts
``total_reachable >= 1``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

# Ensure backend package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2  # noqa: E402
import psycopg2.extras  # noqa: E402

ORG_ID: int = 1
ORG_2_ID: int = 2
CLOUD: str = "azure"
CONNECTION_LABEL: str = "phase3-a4-seed"
CONNECTION_LABEL_ORG2: str = "phase3-a4-org2-seed"
SEED_TAG: str = "phase3_a4"

# uuid5 namespace so every generated node id is stable across runs.
NS = uuid.UUID("00000000-0000-0000-0000-000000000042")


def nid(name: str) -> str:
    return str(uuid.uuid5(NS, f"phase3-a4:{name}"))


NODE_IDS: dict[str, str] = {
    "HI": nid("identity:HI"),
    "SPN": nid("identity:SPN"),
    "UAMI": nid("identity:UAMI"),
    "ROLE": nid("role:contributor"),
    "RG": nid("resource:rg-prod"),
    "KV": nid("resource:kv-secrets"),
    "SA": nid("resource:sa-logs"),
    # GTE-4 reverse direction: an identity that only exists under org 2 so
    # we can prove an org-1 JWT cannot reach it.
    "ORG2_HI": nid("org2:identity:HI"),
}

# (src_key, edge_type, tgt_key). Policy-compliant.
EDGES: list[tuple[str, str, str]] = [
    ("HI",   "HAS_ROLE",       "ROLE"),
    ("UAMI", "HAS_ROLE",       "ROLE"),
    ("ROLE", "HAS_PERMISSION", "RG"),
    ("RG",   "CAN_ACCESS",     "KV"),
    ("RG",   "CAN_ACCESS",     "SA"),
    ("SPN",  "OWNS",           "SA"),
    ("HI",   "OWNS",           "SA"),
]

NOW = datetime.now(timezone.utc)


def _dsn() -> str:
    """Resolve a DSN the seed script can connect to.

    Prefers ``DATABASE_URL`` from env (matches ``.env.local``), falls
    back to individual DB_* vars otherwise.
    """
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5434")
    user = os.getenv("DB_USER", "auditgraph")
    password = os.getenv("DB_PASSWORD", "auditgraph")
    db = os.getenv("DB_NAME", "auditgraph")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def _connect() -> psycopg2.extensions.connection:
    conn = psycopg2.connect(_dsn())
    conn.autocommit = False
    return conn


# ---------------------------------------------------------------------------
# Step 1: ensure cloud_connection
# ---------------------------------------------------------------------------


def ensure_cloud_connection(cur: psycopg2.extensions.cursor) -> int:
    """Return the id of the seed cloud_connection, creating it if missing."""
    cur.execute(
        """
        SELECT id FROM cloud_connections
         WHERE organization_id = %s
           AND cloud = %s
           AND azure_directory_id = %s
        """,
        (ORG_ID, CLOUD, "phase3-a4-dir"),
    )
    row = cur.fetchone()
    if row:
        return row[0]

    cur.execute(
        """
        INSERT INTO cloud_connections (
            organization_id, cloud, connection_type, label,
            azure_directory_id, status, display_order, metadata
        )
        VALUES (%s, 'azure', 'entra', %s, 'phase3-a4-dir',
                'active', 0, %s::jsonb)
        ON CONFLICT (organization_id, cloud, azure_directory_id)
        DO UPDATE SET label = EXCLUDED.label
        RETURNING id
        """,
        (ORG_ID, CONNECTION_LABEL, json.dumps({"seed": SEED_TAG})),
    )
    return cur.fetchone()[0]


def ensure_org2_cloud_connection(cur: psycopg2.extensions.cursor) -> int:
    """Return the id of the org-2 seed cloud_connection."""
    cur.execute(
        """
        SELECT id FROM cloud_connections
         WHERE organization_id = %s
           AND cloud = %s
           AND azure_directory_id = %s
        """,
        (ORG_2_ID, CLOUD, "phase3-a4-org2-dir"),
    )
    row = cur.fetchone()
    if row:
        return row[0]

    cur.execute(
        """
        INSERT INTO cloud_connections (
            organization_id, cloud, connection_type, label,
            azure_directory_id, status, display_order, metadata
        )
        VALUES (%s, 'azure', 'entra', %s, 'phase3-a4-org2-dir',
                'active', 0, %s::jsonb)
        ON CONFLICT (organization_id, cloud, azure_directory_id)
        DO UPDATE SET label = EXCLUDED.label
        RETURNING id
        """,
        (ORG_2_ID, CONNECTION_LABEL_ORG2, json.dumps({"seed": SEED_TAG})),
    )
    return cur.fetchone()[0]


# ---------------------------------------------------------------------------
# Step 2: ensure identities rows (Phase 3 profile loader contract)
# ---------------------------------------------------------------------------


IDENTITY_FIXTURES: list[dict[str, Any]] = [
    {
        "key": "HI",
        "identity_type": "human_user",
        "identity_category": "human_user",
        "display_name": "Phase3 Seed HI",
        "upn": "phase3-hi@auditgraph.local",
        "source": "azure_ad",
    },
    {
        "key": "SPN",
        "identity_type": "service_principal",
        "identity_category": "service_principal",
        "display_name": "Phase3 Seed SPN",
        "upn": None,
        "source": "azure_ad",
    },
    {
        "key": "UAMI",
        "identity_type": "managed_identity",
        "identity_category": "managed_identity_user",
        "display_name": "Phase3 Seed UAMI",
        "upn": None,
        "source": "azure_ad",
    },
]


#: Org 2 fixture — used to prove GTE-4 reverse direction
#: (org-1 JWT cannot reach an identity that exists only under org 2).
IDENTITY_FIXTURES_ORG2: list[dict[str, Any]] = [
    {
        "key": "ORG2_HI",
        "identity_type": "human_user",
        "identity_category": "human_user",
        "display_name": "Phase3 Seed Org2 HI",
        "upn": "phase3-org2-hi@auditgraph.local",
        "source": "azure_ad",
    },
]


#: Resource fixtures with distinct sensitivities so GTE-2 can prove
#: bucket disjointness with a non-empty bucket set (the bare graph
#: seed does NOT populate the `resources` table, so without this
#: fixture every blast-radius bucket would be trivially empty and
#: the disjointness assertion would be vacuous).
RESOURCE_FIXTURES: list[dict[str, Any]] = [
    {
        "key": "KV",
        "type": "key_vault",
        "name": "phase3-a4-kv-secrets",
        "sensitivity": "Critical",
        "cloud_path": "/subscriptions/phase3-a4/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-secrets",
    },
    {
        "key": "SA",
        "type": "storage",
        "name": "phase3-a4-sa-logs",
        "sensitivity": "High",
        "cloud_path": "/subscriptions/phase3-a4/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/salogs",
    },
]


def ensure_identity_unique_index(cur: psycopg2.extensions.cursor) -> None:
    """Create a unique index on identity_id if none exists.

    The profile builder reads ``WHERE identity_id = :id AND
    organization_id = :org``, so uniqueness on identity_id is enough
    for our seed. The partial predicate matches both org 1 and org 2
    fixtures via the shared uuid5 namespace.
    """
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_identities_seed_identity_id
        ON identities (identity_id)
        WHERE identity_id LIKE 'phase3-a4:%'
        """
    )


def _insert_identity_row(
    cur: psycopg2.extensions.cursor,
    *,
    fix: dict[str, Any],
    org_id: int,
) -> None:
    gid = str(uuid.uuid5(NS, f"phase3-a4:global:org{org_id}:{fix['key']}"))
    identity_id = NODE_IDS[fix["key"]]
    cur.execute(
        """
        INSERT INTO identities (
            identity_id, display_name, source, identity_type,
            identity_category, organization_id, status,
            global_identity_id, user_principal_name, cloud_id,
            is_federated_identity, federated_from,
            last_modified_at, discovered_at, created_at, cloud
        )
        VALUES (
            %s, %s, %s, %s,
            %s, %s, 'Active',
            %s::uuid, %s, 'azure',
            FALSE, NULL,
            %s, %s, %s, 'azure'
        )
        """,
        (
            identity_id,
            fix["display_name"],
            fix["source"],
            fix["identity_type"],
            fix["identity_category"],
            org_id,
            gid,
            fix["upn"],
            NOW,
            NOW - timedelta(days=1),
            NOW - timedelta(days=2),
        ),
    )


def ensure_identities(cur: psycopg2.extensions.cursor) -> None:
    ensure_identity_unique_index(cur)

    # Idempotency: hard-delete our seed rows first, then INSERT fresh.
    # The seed uses deterministic uuid5 ids so we can list them explicitly.
    seed_ids = [NODE_IDS[fix["key"]] for fix in IDENTITY_FIXTURES] + [
        NODE_IDS[fix["key"]] for fix in IDENTITY_FIXTURES_ORG2
    ]
    cur.execute(
        "DELETE FROM identities WHERE identity_id = ANY(%s)",
        (seed_ids,),
    )
    for fix in IDENTITY_FIXTURES:
        _insert_identity_row(cur, fix=fix, org_id=ORG_ID)
    for fix in IDENTITY_FIXTURES_ORG2:
        _insert_identity_row(cur, fix=fix, org_id=ORG_2_ID)


# ---------------------------------------------------------------------------
# Step 3: graph_nodes
# ---------------------------------------------------------------------------


GRAPH_NODE_FIXTURES: list[dict[str, Any]] = [
    {"key": "HI",   "node_type": "identity", "display_name": "Phase3 Seed HI"},
    {"key": "SPN",  "node_type": "identity", "display_name": "Phase3 Seed SPN"},
    {"key": "UAMI", "node_type": "identity", "display_name": "Phase3 Seed UAMI"},
    {"key": "ROLE", "node_type": "role",     "display_name": "Phase3 Seed Contributor"},
    {"key": "RG",   "node_type": "resource", "display_name": "Phase3 Seed RG"},
    {"key": "KV",   "node_type": "resource", "display_name": "Phase3 Seed KV"},
    {"key": "SA",   "node_type": "resource", "display_name": "Phase3 Seed SA"},
]


def ensure_graph_nodes(
    cur: psycopg2.extensions.cursor, cloud_connection_id: int
) -> None:
    for fix in GRAPH_NODE_FIXTURES:
        gn_id = NODE_IDS[fix["key"]]
        external_id = f"phase3-a4:{fix['key']}"
        cur.execute(
            """
            INSERT INTO graph_nodes (
                id, organization_id, cloud_connection_id, node_type,
                external_id, display_name, metadata
            )
            VALUES (%s::uuid, %s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (cloud_connection_id, node_type, external_id)
            DO UPDATE SET
                display_name = EXCLUDED.display_name,
                metadata = EXCLUDED.metadata
            """,
            (
                gn_id,
                ORG_ID,
                cloud_connection_id,
                fix["node_type"],
                external_id,
                fix["display_name"],
                json.dumps({"seed": SEED_TAG, "role_key": fix["key"]}),
            ),
        )


# ---------------------------------------------------------------------------
# Step 4: graph_edges (delete seed-tagged then insert for idempotency)
# ---------------------------------------------------------------------------


def ensure_graph_edges(
    cur: psycopg2.extensions.cursor, cloud_connection_id: int
) -> None:
    cur.execute(
        """
        DELETE FROM graph_edges
         WHERE organization_id = %s
           AND metadata->>'seed' = %s
        """,
        (ORG_ID, SEED_TAG),
    )

    meta = json.dumps({"seed": SEED_TAG})
    for src_key, edge_type, tgt_key in EDGES:
        src_id = NODE_IDS[src_key]
        tgt_id = NODE_IDS[tgt_key]
        src_type = next(
            f["node_type"] for f in GRAPH_NODE_FIXTURES if f["key"] == src_key
        )
        tgt_type = next(
            f["node_type"] for f in GRAPH_NODE_FIXTURES if f["key"] == tgt_key
        )
        cur.execute(
            """
            INSERT INTO graph_edges (
                organization_id, cloud_connection_id,
                source_node_id, target_node_id, edge_type,
                source_node_type, target_node_type,
                usage_confidence, cloud_provider,
                valid_at, invalidated_at, metadata
            )
            VALUES (
                %s, %s,
                %s::uuid, %s::uuid, %s,
                %s, %s,
                'high', 'azure',
                %s, NULL, %s::jsonb
            )
            """,
            (
                ORG_ID,
                cloud_connection_id,
                src_id,
                tgt_id,
                edge_type,
                src_type,
                tgt_type,
                NOW,
                meta,
            ),
        )


# ---------------------------------------------------------------------------
# Step 5: resources (for GTE-2 bucket disjointness validation)
# ---------------------------------------------------------------------------


def ensure_resources(cur: psycopg2.extensions.cursor) -> None:
    """Populate the `resources` table so IdentityBlastRadiusEngine can
    bucket reachable nodes by sensitivity.

    Without this, the blast_radius.{critical,high,medium}_resources
    arrays would be empty (the engine skips nodes missing from the
    loader fetch), and GTE-2 disjointness would be vacuous.
    """
    # Idempotent: hard-delete our seeded rows first, then re-insert.
    seed_resource_ids = [NODE_IDS[fix["key"]] for fix in RESOURCE_FIXTURES]
    cur.execute(
        "DELETE FROM resources WHERE organization_id = %s AND id = ANY(%s)",
        (ORG_ID, seed_resource_ids),
    )
    for fix in RESOURCE_FIXTURES:
        rid = NODE_IDS[fix["key"]]
        gid = str(uuid.uuid5(NS, f"phase3-a4:resource-global:{fix['key']}"))
        cur.execute(
            """
            INSERT INTO resources (
                organization_id, id, global_identity_id,
                cloud_id, cloud_provider, type, name, sensitivity
            )
            VALUES (%s, %s, %s::uuid, %s, 'azure', %s, %s, %s)
            """,
            (
                ORG_ID,
                rid,
                gid,
                fix["cloud_path"],
                fix["type"],
                fix["name"],
                fix["sensitivity"],
            ),
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def seed() -> dict[str, Any]:
    conn = _connect()
    try:
        with conn, conn.cursor() as cur:
            cc_id = ensure_cloud_connection(cur)
            cc_org2_id = ensure_org2_cloud_connection(cur)
            ensure_identities(cur)
            ensure_graph_nodes(cur, cc_id)
            ensure_graph_edges(cur, cc_id)
            ensure_resources(cur)

            cur.execute(
                "SELECT COUNT(*) FROM graph_nodes WHERE organization_id = %s",
                (ORG_ID,),
            )
            node_count = cur.fetchone()[0]
            cur.execute(
                """
                SELECT COUNT(*) FROM graph_edges
                 WHERE organization_id = %s
                   AND metadata->>'seed' = %s
                """,
                (ORG_ID, SEED_TAG),
            )
            edge_count = cur.fetchone()[0]
            cur.execute(
                "SELECT COUNT(*) FROM resources WHERE organization_id = %s AND id = ANY(%s)",
                (ORG_ID, [NODE_IDS[f["key"]] for f in RESOURCE_FIXTURES]),
            )
            resource_count = cur.fetchone()[0]
            cur.execute(
                "SELECT COUNT(*) FROM identities WHERE organization_id = %s AND identity_id = %s",
                (ORG_2_ID, NODE_IDS["ORG2_HI"]),
            )
            org2_identity_count = cur.fetchone()[0]
    finally:
        conn.close()

    return {
        "cloud_connection_id": cc_id,
        "cloud_connection_org2_id": cc_org2_id,
        "node_count": node_count,
        "edge_count": edge_count,
        "resource_count": resource_count,
        "org2_identity_count": org2_identity_count,
        "hi_identity_id": NODE_IDS["HI"],
        "spn_identity_id": NODE_IDS["SPN"],
        "uami_identity_id": NODE_IDS["UAMI"],
        "org2_hi_identity_id": NODE_IDS["ORG2_HI"],
    }


def forge_jwt(org_id: int = ORG_ID, audience: str = "auditgraph-tenant") -> str:
    """Forge a minimal Bearer JWT for the local dev CLIENT_JWT_SECRET."""
    import jwt

    secret = (
        os.getenv("CLIENT_JWT_SECRET")
        or os.getenv("ADMIN_JWT_SECRET")
        or os.getenv("JWT_SECRET")
        or "local-dev-client-secret"
    )
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1",
        "username": "phase3-a4-canary",
        "role": "admin",
        "type": "access",
        "ver": 1,
        "org_id": org_id,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def verify(result: dict[str, Any]) -> None:
    assert result["node_count"] >= 7, (
        f"expected >= 7 graph_nodes in org {ORG_ID}, got {result['node_count']}"
    )
    assert result["edge_count"] >= 5, (
        f"expected >= 5 seed graph_edges in org {ORG_ID}, got {result['edge_count']}"
    )
    assert result["resource_count"] == len(RESOURCE_FIXTURES), (
        f"expected {len(RESOURCE_FIXTURES)} seeded resources in org {ORG_ID}, "
        f"got {result['resource_count']}"
    )
    assert result["org2_identity_count"] == 1, (
        f"expected 1 org-2 identity row for GTE-4 reverse test, "
        f"got {result['org2_identity_count']}"
    )
    print(f"  ✓ node_count         = {result['node_count']} (>= 7)")
    print(f"  ✓ edge_count         = {result['edge_count']} (>= 5)")
    print(f"  ✓ resource_count     = {result['resource_count']} (== 2)")
    print(f"  ✓ org2_identity_count = {result['org2_identity_count']} (== 1)")


# ---------------------------------------------------------------------------
# Canary — GTE-1..4 validation harness
# ---------------------------------------------------------------------------


#: GTE-1 expected histogram. HI reaches SA via OWNS at depth 1 and KV via
#: HAS_ROLE→HAS_PERMISSION→CAN_ACCESS at depth 3. BFS is single-visit, so
#: SA is only recorded with first-edge OWNS (the shorter path wins).
EXPECTED_HISTOGRAM: dict[str, int] = {
    "OWNS": 1,      # SA reached via HI→OWNS
    "HAS_ROLE": 1,  # KV reached via HI→HAS_ROLE chain
}

#: GTE-3 expected total reachable resources (KV + SA = 2).
EXPECTED_TOTAL_REACHABLE: int = 2


def _assert_gte1_histogram(br: dict[str, Any]) -> None:
    """GTE-1 — histogram correctness (exact counts)."""
    got = br.get("reachable_by_path_type") or {}
    print(f"  [GTE-1] reachable_by_path_type = {got}")
    assert got == EXPECTED_HISTOGRAM, (
        f"[GTE-1] histogram mismatch — expected {EXPECTED_HISTOGRAM}, got {got}"
    )
    print(f"  ✓ [GTE-1] histogram exact match {EXPECTED_HISTOGRAM}")


def _assert_gte2_bucket_disjoint(br: dict[str, Any]) -> None:
    """GTE-2 — each reachable resource appears in exactly one bucket."""
    critical = br.get("critical_resources") or []
    high = br.get("high_resources") or []
    medium = br.get("medium_resources") or []

    all_ids: list[str] = []
    for bucket_name, bucket in (
        ("critical", critical),
        ("high", high),
        ("medium", medium),
    ):
        for item in bucket:
            rid = item.get("id")
            assert rid, f"[GTE-2] resource in {bucket_name} bucket missing 'id'"
            all_ids.append(rid)

    id_set = set(all_ids)
    assert len(all_ids) == len(id_set), (
        f"[GTE-2] bucket lists overlap — all_ids={all_ids}, unique={sorted(id_set)}"
    )

    # Cross-check against expected assignment from RESOURCE_FIXTURES.
    expected_critical = {
        NODE_IDS[f["key"]] for f in RESOURCE_FIXTURES if f["sensitivity"] == "Critical"
    }
    expected_high = {
        NODE_IDS[f["key"]] for f in RESOURCE_FIXTURES if f["sensitivity"] == "High"
    }
    got_critical_ids = {r["id"] for r in critical}
    got_high_ids = {r["id"] for r in high}

    assert got_critical_ids == expected_critical, (
        f"[GTE-2] critical bucket mismatch — expected {expected_critical}, "
        f"got {got_critical_ids}"
    )
    assert got_high_ids == expected_high, (
        f"[GTE-2] high bucket mismatch — expected {expected_high}, "
        f"got {got_high_ids}"
    )
    print(
        f"  [GTE-2] buckets: critical={len(critical)} high={len(high)} medium={len(medium)}"
    )
    print(f"  ✓ [GTE-2] bucket disjointness verified (no overlapping ids)")


def _assert_gte3_paths_intentional(br: dict[str, Any]) -> None:
    """GTE-3 — multi-path attribution: total_reachable=2 is intentional.

    The seed graph is constructed so that HI reaches exactly 2 resources
    via 2 distinct first-edge chains:
      * SA  via HI→OWNS              (1-hop, first-visit wins histogram)
      * KV  via HI→HAS_ROLE→…→KV      (3-hop chain)

    The +1 OWNS and +1 HAS_ROLE histogram entries are the attribution
    receipts for those two paths, summing to total_reachable=2.
    """
    tr = br.get("total_reachable")
    depth = br.get("traversal_depth")
    hist = br.get("reachable_by_path_type") or {}
    hist_sum = sum(hist.values())

    print(f"  [GTE-3] total_reachable = {tr}, traversal_depth = {depth}")
    print(f"  [GTE-3] histogram_sum   = {hist_sum}")

    assert tr == EXPECTED_TOTAL_REACHABLE, (
        f"[GTE-3] expected total_reachable == {EXPECTED_TOTAL_REACHABLE}, got {tr}"
    )
    assert hist_sum == EXPECTED_TOTAL_REACHABLE, (
        f"[GTE-3] histogram_sum ({hist_sum}) should equal "
        f"total_reachable ({EXPECTED_TOTAL_REACHABLE})"
    )
    # The 3-hop chain should actually be traversed (depth>=3 proves
    # the multi-edge chain from HI→ROLE→RG→KV was walked).
    assert isinstance(depth, int) and depth >= 3, (
        f"[GTE-3] expected traversal_depth >= 3, got {depth}"
    )
    print(f"  ✓ [GTE-3] paths=2 intentional "
          f"(SA via OWNS, KV via HAS_ROLE 3-hop chain)")


_FLASK_CLIENT_CACHE: Any = None


def _build_test_client() -> Any:
    """Build (or return cached) Flask+FastAPI mounted test client.

    Cached so canary / smoke / schema validation share one stack and
    the scheduler isn't started twice per invocation.
    """
    global _FLASK_CLIENT_CACHE
    if _FLASK_CLIENT_CACHE is not None:
        return _FLASK_CLIENT_CACHE

    # Defer so a bare seed run has no FastAPI/Flask dependency.
    os.environ.setdefault("APP_ENV", "local")
    # Blast radius engine is behind a feature flag read at import time —
    # force it on before create_app() touches FeatureFlags.
    os.environ.setdefault("USE_BLAST_RADIUS", "true")
    from app.main import create_app  # noqa: E402

    flask_app = create_app()
    _FLASK_CLIENT_CACHE = flask_app.test_client()
    return _FLASK_CLIENT_CACHE


def canary(result: dict[str, Any]) -> None:
    """Live canary via Flask+FastAPI mounted stack (in-process test client).

    Runs GTE-1..4 assertions against the seeded graph and reports each
    guarantee individually. Any single failure aborts with an explicit
    message so the failing guarantee is obvious in CI.
    """
    client = _build_test_client()

    hi_id = result["hi_identity_id"]
    org2_hi_id = result["org2_hi_identity_id"]
    path = f"/api/v1/identities/{hi_id}"
    org2_path = f"/api/v1/identities/{org2_hi_id}"
    org1_token = forge_jwt(org_id=ORG_ID)
    org2_token = forge_jwt(org_id=ORG_2_ID)

    # ------------------------------------------------------------------
    # Primary canary — GET org-1 HI with org-1 JWT
    # ------------------------------------------------------------------
    print(f"\nCANARY  GET {path}  (org_id={ORG_ID})")
    resp = client.get(path, headers={"Authorization": f"Bearer {org1_token}"})
    print(f"        HTTP {resp.status_code}")
    assert resp.status_code == 200, (
        f"expected 200 for HI canary, got {resp.status_code}: {resp.data[:500]!r}"
    )
    body = resp.get_json()
    assert isinstance(body, dict), f"expected dict body, got {type(body)}"

    br = body.get("blast_radius")
    assert br is not None, (
        "blast_radius is None — engine failed or USE_BLAST_RADIUS not set. "
        f"Body keys = {sorted(body.keys())}"
    )
    print(f"  ✓ canary HTTP 200 with blast_radius populated")

    # ------------------------------------------------------------------
    # GTE-1 — histogram correctness
    # ------------------------------------------------------------------
    print("\nGTE-1 — histogram correctness")
    _assert_gte1_histogram(br)

    # ------------------------------------------------------------------
    # GTE-2 — bucket disjointness
    # ------------------------------------------------------------------
    print("\nGTE-2 — bucket disjointness")
    _assert_gte2_bucket_disjoint(br)

    # ------------------------------------------------------------------
    # GTE-3 — multi-path attribution / intentional path count
    # ------------------------------------------------------------------
    print("\nGTE-3 — multi-path attribution")
    _assert_gte3_paths_intentional(br)

    # ------------------------------------------------------------------
    # GTE-4 — cross-org scope (both directions)
    # ------------------------------------------------------------------
    print("\nGTE-4 — cross-org scope enforcement")

    # Direction A: org-2 JWT → org-1 identity → must be 404/403
    resp_a = client.get(
        path, headers={"Authorization": f"Bearer {org2_token}"}
    )
    print(f"  [GTE-4a] GET {path}  (caller org_id={ORG_2_ID}) -> HTTP {resp_a.status_code}")
    assert resp_a.status_code in (403, 404), (
        f"[GTE-4a] expected 403/404 for org-2 caller on org-1 identity, "
        f"got {resp_a.status_code}"
    )
    print(f"  ✓ [GTE-4a] org-2 caller blocked from org-1 identity")

    # Direction B: org-1 JWT → org-2 identity → must be 404/403
    resp_b = client.get(
        org2_path, headers={"Authorization": f"Bearer {org1_token}"}
    )
    print(
        f"  [GTE-4b] GET {org2_path}  (caller org_id={ORG_ID}) -> HTTP {resp_b.status_code}"
    )
    assert resp_b.status_code in (403, 404), (
        f"[GTE-4b] expected 403/404 for org-1 caller on org-2 identity, "
        f"got {resp_b.status_code}"
    )
    print(f"  ✓ [GTE-4b] org-1 caller blocked from org-2 identity")

    print("\n  ✓ GTE-1..4 ALL GUARANTEES PASSED")

    # Stash the response body on the result dict so the Pydantic
    # validation step (A5 Part 3) can reuse it without a second round-trip.
    result["_canary_body"] = body


#: A3 smoke suite — 21 parameterized checks across the 18 functional
#: Phase 3 routes plus 3 auth/scope variants. Each entry is
#: ``(label, method, path_fn, headers_fn, expected_statuses, body_fn)``
#: where the *_fn callables take the canary ``result`` dict so the
#: suite can interpolate seeded identity/resource ids at call time.
#:
#: Every functional route is expected to return a non-500 status. The
#: exact OK vs 404 split depends on whether the seed happens to have
#: a matching row — each row lists both as acceptable so the suite is
#: deterministic against our minimal fixture.
A3_SMOKE_CASES: list[dict[str, Any]] = [
    # ---- 18 functional routes ------------------------------------
    # identities
    {"label": "GET  /identities",
     "method": "GET",
     "path": lambda r: "/api/v1/identities",
     "expect": {200}},
    {"label": "GET  /identities/{HI}",
     "method": "GET",
     "path": lambda r: f"/api/v1/identities/{r['hi_identity_id']}",
     "expect": {200}},
    {"label": "GET  /identities/{HI}/roles",
     "method": "GET",
     "path": lambda r: f"/api/v1/identities/{r['hi_identity_id']}/roles",
     "expect": {200}},
    {"label": "GET  /identities/{HI}/attack-paths",
     "method": "GET",
     "path": lambda r: f"/api/v1/identities/{r['hi_identity_id']}/attack-paths",
     "expect": {200}},
    {"label": "GET  /identities/{HI}/remediation",
     "method": "GET",
     "path": lambda r: f"/api/v1/identities/{r['hi_identity_id']}/remediation",
     "expect": {200}},
    {"label": "POST /identities/{HI}/remediation/nope/execute",
     "method": "POST",
     "path": lambda r: f"/api/v1/identities/{r['hi_identity_id']}/remediation/nope/execute",
     "body": lambda r: {},
     "expect": {200, 404, 422}},
    {"label": "GET  /identities/global/{bogus}",
     "method": "GET",
     "path": lambda r: "/api/v1/identities/global/00000000-0000-0000-0000-000000000000",
     "expect": {404, 422}},
    # resources
    {"label": "GET  /resources",
     "method": "GET",
     "path": lambda r: "/api/v1/resources",
     "expect": {200}},
    # Resource + snapshot routes validate their path params as int ge=1
    # (Phase 3 surrogate PKs). Use id=1 — no row exists so 404 is the
    # expected response; what we're proving is the route is reachable
    # and does not 500.
    {"label": "GET  /resources/1",
     "method": "GET",
     "path": lambda r: "/api/v1/resources/1",
     "expect": {200, 404}},
    {"label": "GET  /resources/1/identities",
     "method": "GET",
     "path": lambda r: "/api/v1/resources/1/identities",
     "expect": {200, 404}},
    # snapshots
    {"label": "GET  /snapshots",
     "method": "GET",
     "path": lambda r: "/api/v1/snapshots",
     "expect": {200}},
    {"label": "GET  /snapshots/1",
     "method": "GET",
     "path": lambda r: "/api/v1/snapshots/1",
     "expect": {200, 404}},
    {"label": "GET  /snapshots/1/identities",
     "method": "GET",
     "path": lambda r: "/api/v1/snapshots/1/identities",
     "expect": {200, 404}},
    {"label": "GET  /snapshots/1/identities/{HI}",
     "method": "GET",
     "path": lambda r: f"/api/v1/snapshots/1/identities/{r['hi_identity_id']}",
     "expect": {200, 404}},
    {"label": "POST /snapshots/capture",
     "method": "POST",
     "path": lambda r: "/api/v1/snapshots/capture",
     "body": lambda r: {"label": "phase3-a4-smoke"},
     "expect": {200, 201, 202, 400, 403, 422}},
    # additional 404 paths
    {"label": "GET  /identities/bogus-id",
     "method": "GET",
     "path": lambda r: "/api/v1/identities/phase3-a4-bogus",
     "expect": {404, 422}},
    {"label": "GET  /resources/bogus-id",
     "method": "GET",
     "path": lambda r: "/api/v1/resources/phase3-a4-bogus",
     "expect": {404, 422}},
    {"label": "GET  /resources/bogus-id/identities",
     "method": "GET",
     "path": lambda r: "/api/v1/resources/phase3-a4-bogus/identities",
     "expect": {404, 422}},
    # ---- 3 auth/scope variants -----------------------------------
    {"label": "GET  /identities (no auth)",
     "method": "GET",
     "path": lambda r: "/api/v1/identities",
     "no_auth": True,
     "expect": {401, 403}},
    {"label": "GET  /identities/{HI} (org-2 JWT)",
     "method": "GET",
     "path": lambda r: f"/api/v1/identities/{r['hi_identity_id']}",
     "jwt_org_id": 2,
     "expect": {403, 404}},
    {"label": "GET  /identities/{ORG2_HI} (org-1 JWT)",
     "method": "GET",
     "path": lambda r: f"/api/v1/identities/{r['org2_hi_identity_id']}",
     "jwt_org_id": 1,
     "expect": {403, 404}},
]


def run_a3_smoke(client: Any, result: dict[str, Any]) -> None:
    """Execute the 21 A3 smoke cases against the mounted Flask+FastAPI
    stack and assert every call either matches an expected status or
    (at minimum) is NOT a 500 internal error.
    """
    print("\nA3-SMOKE  regression suite")
    org1_hdr = {"Authorization": f"Bearer {forge_jwt(org_id=ORG_ID)}"}
    org2_hdr = {"Authorization": f"Bearer {forge_jwt(org_id=ORG_2_ID)}"}

    failures: list[str] = []
    for idx, case in enumerate(A3_SMOKE_CASES, start=1):
        path = case["path"](result)
        method = case["method"]

        if case.get("no_auth"):
            headers: dict[str, str] = {}
        elif case.get("jwt_org_id") == 2:
            headers = org2_hdr
        else:
            headers = org1_hdr

        if method == "GET":
            resp = client.get(path, headers=headers)
        elif method == "POST":
            body = case.get("body", lambda r: {})(result)
            resp = client.post(
                path,
                headers={**headers, "Content-Type": "application/json"},
                data=json.dumps(body),
            )
        else:
            raise AssertionError(f"unsupported method {method}")

        expected = case["expect"]
        status = resp.status_code
        ok = status != 500 and status in expected
        mark = "✓" if ok else "✗"
        print(f"  [{idx:02d}/21] {mark} HTTP {status:3d} (exp {sorted(expected)})  {case['label']}")
        if not ok:
            failures.append(
                f"[{idx:02d}] {case['label']}: HTTP {status} "
                f"not in expected {sorted(expected)}"
            )

    passed = len(A3_SMOKE_CASES) - len(failures)
    print(f"\n  A3-SMOKE: {passed}/{len(A3_SMOKE_CASES)} passed")
    assert not failures, (
        "A3 smoke regression — failures:\n  "
        + "\n  ".join(failures)
    )
    print(f"  ✓ A3-SMOKE regression: {len(A3_SMOKE_CASES)}/{len(A3_SMOKE_CASES)} passed")


def validate_schema(result: dict[str, Any]) -> None:
    """A5 Part 3 — validate the canary response body against the canonical
    IdentityState Pydantic schema. Re-parses the dict emitted by FastAPI
    through ``IdentityState.model_validate`` so any drift between the
    engine output and the response_model contract surfaces as a
    ValidationError with the exact field path.

    Additionally asserts that the 6 A5 required fields are populated
    (not None) — these are non-optional by contract.
    """
    body = result.get("_canary_body")
    assert isinstance(body, dict), (
        "validate_schema: canary body missing from result. "
        "Did --canary run first?"
    )

    # Lazy import so bare --verify doesn't require the full app stack.
    from app.schemas.identity import IdentityState  # noqa: E402

    print("\nA5-PART3  Pydantic schema validation")
    state = IdentityState.model_validate(body)
    print(f"  ✓ IdentityState.model_validate accepted response body")

    # A5 required fields — spec quote:
    # "lifecycle state, governance state, privilege level, blast radius,
    #  confidence score, last activity signal"
    required_checks: list[tuple[str, Any]] = [
        ("profile.display_name",         state.profile.display_name),
        ("activity.lifecycle_state",     state.activity.lifecycle_state),
        ("activity.activity_confidence", state.activity.activity_confidence),
        ("governance.classification",    state.governance.classification),
        ("governance.governance_confidence", state.governance.governance_confidence),
        ("privilege.privilege_level",    state.privilege.privilege_level),
        ("risk.score",                   state.risk.score),
        ("risk.label",                   state.risk.label),
        ("blast_radius",                 state.blast_radius),
    ]
    for field_path, value in required_checks:
        assert value is not None, (
            f"A5-PART3: required field '{field_path}' is None — "
            f"unexpected null in IdentityState contract"
        )
        print(f"  ✓ {field_path:40s} = {value!r}")

    # last-activity signal — at least one of last_sign_in_at /
    # last_activity_at must be present OR activity_confidence must be
    # explicitly 'none' (legitimate null with provenance).
    last_sig = state.activity.last_sign_in_at or state.activity.last_activity_at
    if last_sig is None:
        from app.schemas.identity import Confidence
        assert state.activity.activity_confidence == Confidence.NONE, (
            "A5-PART3: last_sign_in_at and last_activity_at are BOTH null "
            "but activity_confidence is not 'none' — this is an unexpected "
            "null in the contract"
        )
        print(f"  ✓ last-activity signal null is legitimate "
              f"(activity_confidence=none)")
    else:
        print(f"  ✓ activity.last_activity_signal = {last_sig!r}")

    # blast_radius populated — cross-check against the GTE-1 outcome.
    assert state.blast_radius is not None
    assert state.blast_radius.total_reachable == EXPECTED_TOTAL_REACHABLE
    print(f"  ✓ blast_radius.total_reachable = "
          f"{state.blast_radius.total_reachable}")

    print("  ✓ A5-PART3 Pydantic schema validation PASSED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Assert seed targets")
    parser.add_argument(
        "--canary",
        action="store_true",
        help="Run seed + verify + live canary against mounted stack",
    )
    parser.add_argument(
        "--validate-schema",
        action="store_true",
        help="After canary, validate response body against IdentityState schema",
    )
    parser.add_argument(
        "--a3-smoke",
        action="store_true",
        help="Run the 21-check A3 regression suite against all Phase 3 routes",
    )
    parser.add_argument(
        "--print-jwt",
        action="store_true",
        help="Print a forged Bearer JWT for curl",
    )
    args = parser.parse_args()

    print("=" * 72)
    print("Phase 3 A4 graph seed")
    print("=" * 72)
    result = seed()
    print(f"  cloud_connection_id      = {result['cloud_connection_id']}")
    print(f"  cloud_connection_org2_id = {result['cloud_connection_org2_id']}")
    print(f"  node_count               = {result['node_count']}")
    print(f"  edge_count               = {result['edge_count']}")
    print(f"  resource_count           = {result['resource_count']}")
    print(f"  org2_identity_count      = {result['org2_identity_count']}")
    print(f"  HI   identity_id         = {result['hi_identity_id']}")
    print(f"  SPN  identity_id         = {result['spn_identity_id']}")
    print(f"  UAMI identity_id         = {result['uami_identity_id']}")
    print(f"  ORG2_HI identity_id      = {result['org2_hi_identity_id']}")

    if args.verify or args.canary:
        print("\nVERIFY")
        verify(result)

    if args.print_jwt:
        print(f"\nJWT (org_id={ORG_ID}, aud=auditgraph-tenant):")
        print(forge_jwt())

    if args.canary:
        canary(result)

    if args.validate_schema:
        if "_canary_body" not in result:
            # --validate-schema implies --canary so users don't have
            # to pass both flags.
            canary(result)
        validate_schema(result)

    if args.a3_smoke:
        client = _build_test_client()
        run_a3_smoke(client, result)

    print("\nSEED COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
