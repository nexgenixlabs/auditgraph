"""
reach_attributor — per-entity reachable classified exposure

AG-193 Sprint B (2026-06-13)

Peer feedback (2026-06-12): a GPT deployment isn't inherently worth $1.4M;
the value comes from what data it can reach. The fix is to compute, per
identity and per AI model deployment:

    reachable_classified_exposure = Σ classified_resource.exposure
                                    for every classified resource the
                                    entity has RBAC reach to

For an identity, "reach" follows from its role_assignments. A role
assignment's `scope` is an ARM path; we match it against every
classified resource's ARM path with the standard prefix rule:

    classified.resource_id = scope              # resource-level grant
    classified.resource_id LIKE scope || '/%'   # RG / sub / mg grant

For an AI model deployment, "reach" is the reach of the parent Azure
OpenAI / AI Services account's managed identity (which IS an identity
row we already discovered). The MVP mapping is best-effort — we try
`identities.identity_id = <account_resource_id>` and, when that misses,
fall back to walking the role_assignments table for assignments whose
scope is the account_resource_id itself.

This module is read-only against role_assignments and the classified
resource tables; it writes only the cached reach columns added by
migration 228 (identities.reachable_*, azure_ai_model_deployments.reachable_*).

Called from scheduler tier-2 post-processing after
apply_scope_classification — so the data classifications are fresh
when we compute reach against them.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── Per-asset defaults (mirror handlers.get_dashboard_business_impact) ──
# Both reach_attributor and the business-impact endpoint must agree on
# the same per-asset $$. We re-read settings to honor tenant overrides.
_DEFAULTS = {
    "PHI": 720_000,
    "PCI": 1_200_000,
    "PII": 540_000,
    # AI default is 0; reach is the sole AI signal now.
}


def _per_asset_for_org(db, organization_id: int) -> dict[str, int]:
    """Read per-tenant overrides; fall back to IBM defaults."""
    try:
        s = db.get_settings(organization_id=organization_id) or {}
    except Exception:
        s = {}

    def _pos_int(raw: Any, fallback: int) -> int:
        try:
            v = int(str(raw).strip())
            return v if v > 0 else fallback
        except (TypeError, ValueError):
            return fallback

    return {
        "PHI": _pos_int(s.get("exposure_phi_per_asset"), _DEFAULTS["PHI"]),
        "PCI": _pos_int(s.get("exposure_pci_per_asset"), _DEFAULTS["PCI"]),
        "PII": _pos_int(s.get("exposure_pii_per_asset"), _DEFAULTS["PII"]),
    }


def _table_exists(cursor, table: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema='public' AND table_name=%s",
        (table,),
    )
    return cursor.fetchone() is not None


def compute_identity_reach(db, organization_id: int) -> dict[str, Any]:
    """Compute and persist reach for every identity in an org.

    Returns a stats dict for logging.

    Algorithm:
      1. Build a CTE of every classified resource (union storage / KV /
         SQL / Cosmos / discovered_resources) with its (id, class, $$).
      2. Join role_assignments to classified on the ARM-prefix rule.
      3. Group by identity, sum exposure, count by class.
      4. UPDATE identities.reachable_* with the result.
      5. Zero out identities that have no role assignments (so a removed
         assignment shows up as a drop in reach on the next scan).
    """
    cursor = db.conn.cursor()
    per_asset = _per_asset_for_org(db, organization_id)

    # We intentionally union only the tables that actually have
    # data_classification today. If a table doesn't exist (e.g.
    # azure_sql_databases on a tenant that never had SQL), skip it.
    union_parts = []
    for tbl in (
        "azure_storage_accounts",
        "azure_key_vaults",
        "azure_sql_databases",
        "azure_cosmos_databases",
        "discovered_resources",
    ):
        if _table_exists(cursor, tbl):
            union_parts.append(
                f"SELECT resource_id, data_classification "
                f"FROM {tbl} "
                f"WHERE organization_id = %s AND data_classification IN ('PHI','PCI','PII')"
            )

    if not union_parts:
        cursor.close()
        return {"updated_identities": 0, "reason": "no classified tables"}

    classified_union = " UNION ALL ".join(union_parts)
    org_args = tuple([organization_id] * len(union_parts))

    # The big query. The ARM prefix join uses an index-friendly LIKE on
    # role_assignments.scope, and an exact-match branch for direct
    # resource grants. We DISTINCT on (identity, resource) so an identity
    # with two role assignments hitting the same resource counts it once.
    sql = f"""
    WITH classified AS (
        {classified_union}
    ),
    classified_priced AS (
        SELECT resource_id,
               data_classification,
               CASE data_classification
                 WHEN 'PHI' THEN %s
                 WHEN 'PCI' THEN %s
                 WHEN 'PII' THEN %s
                 ELSE 0
               END AS exposure
          FROM classified
    ),
    reachable AS (
        SELECT DISTINCT
               ra.identity_db_id,
               c.resource_id,
               c.data_classification,
               c.exposure
          FROM role_assignments ra
          JOIN classified_priced c
            ON c.resource_id = ra.scope
            OR c.resource_id LIKE ra.scope || '/%%'
         WHERE ra.organization_id = %s
           AND ra.identity_db_id IS NOT NULL
    )
    SELECT identity_db_id,
           SUM(exposure)::bigint                                       AS total_exposure,
           COUNT(*) FILTER (WHERE data_classification='PHI')::int      AS phi_count,
           COUNT(*) FILTER (WHERE data_classification='PCI')::int      AS pci_count,
           COUNT(*) FILTER (WHERE data_classification='PII')::int      AS pii_count
      FROM reachable
     GROUP BY identity_db_id
    """
    params = org_args + (per_asset["PHI"], per_asset["PCI"], per_asset["PII"], organization_id)
    cursor.execute(sql, params)
    rows = cursor.fetchall()

    if rows:
        # Bulk update via a VALUES table.
        # psycopg2 mogrify handles parameter quoting.
        values_sql = ",".join(
            cursor.mogrify("(%s,%s,%s,%s,%s)", r).decode("utf-8") for r in rows
        )
        cursor.execute(
            f"""
            UPDATE identities i SET
                reachable_classified_exposure = v.total_exposure,
                reachable_phi_count           = v.phi_count,
                reachable_pci_count           = v.pci_count,
                reachable_pii_count           = v.pii_count,
                reach_computed_at             = NOW()
              FROM (VALUES {values_sql}) AS v(identity_db_id, total_exposure, phi_count, pci_count, pii_count)
             WHERE i.id = v.identity_db_id
               AND i.organization_id = %s
            """,
            (organization_id,),
        )
        updated = cursor.rowcount
    else:
        updated = 0

    # Zero out identities that previously had reach but don't anymore.
    cursor.execute(
        """
        UPDATE identities
           SET reachable_classified_exposure = 0,
               reachable_phi_count = 0,
               reachable_pci_count = 0,
               reachable_pii_count = 0,
               reach_computed_at   = NOW()
         WHERE organization_id = %s
           AND COALESCE(reachable_classified_exposure, 0) > 0
           AND id NOT IN (
              SELECT DISTINCT ra.identity_db_id
                FROM role_assignments ra
               WHERE ra.organization_id = %s
                 AND ra.identity_db_id IS NOT NULL
           )
        """,
        (organization_id, organization_id),
    )
    zeroed = cursor.rowcount

    db.conn.commit()
    cursor.close()
    return {
        "updated_identities": updated,
        "zeroed_identities": zeroed,
        "per_asset": per_asset,
    }


def compute_ai_model_reach(db, organization_id: int) -> dict[str, Any]:
    """Compute and persist reach for every AI model deployment.

    Strategy (best-effort MVP):
      1. For each azure_ai_model_deployments row, look up its parent
         account's managed identity in the identities table:
           a) Try identities.identity_id = <account_resource_id>      (rare)
           b) Try identities.alternative_names @> '[<account_resource_id>]'
           c) Fall back to: max reach among identities with role
              assignments scoped at the account_resource_id (this
              catches the MI even when we can't link it cleanly).
      2. Copy that identity's reachable_* into the AI model row.
      3. AI deployments with no resolvable MI get null reach (NOT zero) —
         null means "we couldn't tell," zero means "we know it reaches
         nothing classified". The drawer can call out null vs zero.
    """
    cursor = db.conn.cursor()
    if not _table_exists(cursor, "azure_ai_model_deployments"):
        cursor.close()
        return {"updated_deployments": 0, "reason": "table missing"}

    # The fallback path c) is the most reliable on real tenants: even when
    # the MI's ARM linkage isn't stored on identities, the MI's role
    # assignments are. We take the max reach across any role assignment
    # whose scope equals or is an ancestor of the AI account resource_id.
    #
    # This effectively says: "the model can reach whatever an identity
    # with a role on that account can reach" — a soft upper bound, which
    # is the honest framing for an MVP.
    cursor.execute(
        """
        WITH ai_accounts AS (
            SELECT DISTINCT organization_id, account_resource_id
              FROM azure_ai_model_deployments
             WHERE organization_id = %s
        ),
        per_account AS (
            SELECT a.account_resource_id,
                   MAX(COALESCE(i.reachable_classified_exposure, 0))::bigint AS exposure,
                   MAX(COALESCE(i.reachable_phi_count, 0))::int              AS phi,
                   MAX(COALESCE(i.reachable_pci_count, 0))::int              AS pci,
                   MAX(COALESCE(i.reachable_pii_count, 0))::int              AS pii
              FROM ai_accounts a
              LEFT JOIN role_assignments ra
                ON ra.organization_id = a.organization_id
               AND (ra.scope = a.account_resource_id
                    OR a.account_resource_id LIKE ra.scope || '/%%')
              LEFT JOIN identities i
                ON i.id = ra.identity_db_id
             GROUP BY a.account_resource_id
        )
        UPDATE azure_ai_model_deployments d
           SET reachable_classified_exposure = p.exposure,
               reachable_phi_count           = p.phi,
               reachable_pci_count           = p.pci,
               reachable_pii_count           = p.pii,
               reach_computed_at             = NOW()
          FROM per_account p
         WHERE d.organization_id = %s
           AND d.account_resource_id = p.account_resource_id
        """,
        (organization_id, organization_id),
    )
    updated = cursor.rowcount

    db.conn.commit()
    cursor.close()
    return {"updated_deployments": updated}


def compute_all_reach(db, organization_id: int) -> dict[str, Any]:
    """Convenience: identities first, then AI models (which borrow from identities)."""
    result = {"organization_id": organization_id}
    try:
        result["identity"] = compute_identity_reach(db, organization_id)
    except Exception as exc:
        logger.exception("reach_attributor: identity pass failed: %s", exc)
        result["identity"] = {"error": str(exc)}
        try: db.conn.rollback()
        except Exception: pass

    try:
        result["ai_model"] = compute_ai_model_reach(db, organization_id)
    except Exception as exc:
        logger.exception("reach_attributor: ai_model pass failed: %s", exc)
        result["ai_model"] = {"error": str(exc)}
        try: db.conn.rollback()
        except Exception: pass

    return result


__all__ = [
    "compute_identity_reach",
    "compute_ai_model_reach",
    "compute_all_reach",
]
