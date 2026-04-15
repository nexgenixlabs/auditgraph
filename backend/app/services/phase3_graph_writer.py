"""
Phase3GraphWriter — translate discovery output into graph_nodes + graph_edges.

This service is the single write path for the Phase 3 graph schema.  It is
called once at the end of each discovery run (after identity rows are
committed) and converts the discovery output — identities, role assignments,
permissions, ownership — into the ``graph_nodes`` and ``graph_edges`` tables
that the :class:`GraphTraversalEngine` reads at query time.

Design rules
------------
* **Sync DB** — uses the same :class:`Database` (psycopg2) that the
  discovery pipeline owns. No async SQLAlchemy.
* **Idempotent** — every node upserts on
  ``(cloud_connection_id, node_type, external_id)``; every edge upserts on
  ``(organization_id, cloud_connection_id, source_node_id, target_node_id,
  edge_type)`` — re-running the writer for the same discovery run produces
  the same result.
* **Error-isolated** — a failure inside ``write_from_discovery()`` is logged
  and swallowed. It must *never* abort the discovery run.
* **usage_confidence** — populated on every written edge based on activity
  recency: HIGH (<30 days), MEDIUM (30–90), LOW (90–180), NONE (>180 or
  unknown).
* **Temporal** — new edges get ``valid_at = NOW()``; edges from a previous
  run that are absent in the current run get ``invalidated_at = NOW()``.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Batch size for bulk INSERT operations.
_BATCH_SIZE: int = 500

#: Activity-recency thresholds (days) for usage_confidence assignment.
_CONFIDENCE_HIGH_DAYS: int = 30
_CONFIDENCE_MEDIUM_DAYS: int = 90
_CONFIDENCE_LOW_DAYS: int = 180


# ---------------------------------------------------------------------------
# Phase3GraphWriter
# ---------------------------------------------------------------------------


class Phase3GraphWriter:
    """Translate Azure discovery output into graph_nodes + graph_edges rows.

    Parameters
    ----------
    organization_id:
        Owning tenant (integer).
    cloud_connection_id:
        ``cloud_connections.id`` for this connection.
    db:
        Sync :class:`Database` instance (caller-owned, same transaction
        scope as the discovery pipeline).
    """

    def __init__(
        self,
        organization_id: int,
        cloud_connection_id: int,
        db: Any,
    ) -> None:
        if organization_id is None:
            raise ValueError("organization_id is required")
        if cloud_connection_id is None:
            raise ValueError("cloud_connection_id is required")
        if db is None:
            raise ValueError("db (Database) is required")
        self._org_id = int(organization_id)
        self._conn_id = int(cloud_connection_id)
        self._db = db

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def write_from_discovery(
        self,
        final_identities: list[dict[str, Any]],
        *,
        role_assignments: Optional[list[dict[str, Any]]] = None,
        permissions_map: Optional[dict[str, list[dict[str, Any]]]] = None,
    ) -> dict[str, int]:
        """Write graph nodes and edges from a completed discovery run.

        Returns a summary dict with counts::

            {"nodes_upserted": N, "edges_upserted": N, "edges_invalidated": N}
        """
        _start = time.perf_counter()
        summary = {"nodes_upserted": 0, "edges_upserted": 0, "edges_invalidated": 0}

        try:
            # 1. Collect all edge source_node_ids we will write this run
            #    (used at the end to invalidate stale edges).
            written_edge_keys: set[tuple[str, str, str]] = set()

            # 2. Upsert identity nodes
            identity_node_ids = self._upsert_identity_nodes(final_identities)
            summary["nodes_upserted"] += len(identity_node_ids)

            # 3. Upsert role nodes + HAS_ROLE edges from identity roles
            role_stats = self._write_role_edges(
                final_identities, identity_node_ids, written_edge_keys
            )
            summary["nodes_upserted"] += role_stats["nodes"]
            summary["edges_upserted"] += role_stats["edges"]

            # 4. Upsert permission nodes + HAS_PERMISSION edges
            perm_stats = self._write_permission_edges(
                final_identities, identity_node_ids, permissions_map,
                written_edge_keys,
            )
            summary["nodes_upserted"] += perm_stats["nodes"]
            summary["edges_upserted"] += perm_stats["edges"]

            # 5. Upsert resource nodes + CAN_ACCESS / BOUND_TO edges
            resource_stats = self._write_resource_edges(
                final_identities, identity_node_ids, written_edge_keys
            )
            summary["nodes_upserted"] += resource_stats["nodes"]
            summary["edges_upserted"] += resource_stats["edges"]

            # 6. Upsert subscription nodes + CONTAINS edges
            sub_stats = self._write_subscription_edges(
                final_identities, identity_node_ids, written_edge_keys
            )
            summary["nodes_upserted"] += sub_stats["nodes"]
            summary["edges_upserted"] += sub_stats["edges"]

            # 7. OWNS edges (identity → owned resources via Owner role)
            owns_stats = self._write_owns_edges(
                final_identities, identity_node_ids, written_edge_keys
            )
            summary["edges_upserted"] += owns_stats["edges"]

            # 8. MEMBER_OF edges (group membership from alternativeNames)
            member_stats = self._write_member_of_edges(
                final_identities, identity_node_ids, written_edge_keys
            )
            summary["nodes_upserted"] += member_stats["nodes"]
            summary["edges_upserted"] += member_stats["edges"]

            # 9. Invalidate edges from previous runs that are no longer present
            invalidated = self._invalidate_stale_edges(written_edge_keys)
            summary["edges_invalidated"] = invalidated

            self._db.safe_commit()

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "phase3_graph_writer: write_from_discovery failed "
                "org=%s conn=%s err=%s",
                self._org_id,
                self._conn_id,
                exc,
            )
            try:
                self._db._rollback()
            except Exception:  # noqa: BLE001
                pass
            return summary

        elapsed = (time.perf_counter() - _start) * 1000
        logger.info(
            "phase3_graph_writer: completed org=%s conn=%s "
            "nodes=%d edges=%d invalidated=%d in %.1fms",
            self._org_id,
            self._conn_id,
            summary["nodes_upserted"],
            summary["edges_upserted"],
            summary["edges_invalidated"],
            elapsed,
        )
        return summary

    # ------------------------------------------------------------------
    # Node upserts
    # ------------------------------------------------------------------

    def _upsert_node(
        self,
        node_type: str,
        external_id: str,
        display_name: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[str]:
        """Upsert a single graph_node and return its UUID (str).

        Uses the UNIQUE index ``(cloud_connection_id, node_type, external_id)``
        for conflict resolution.
        """
        try:
            cursor = self._db.conn.cursor()
            cursor.execute(
                """
                INSERT INTO graph_nodes
                    (organization_id, cloud_connection_id, node_type,
                     external_id, display_name, metadata)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (cloud_connection_id, node_type, external_id)
                DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    metadata     = EXCLUDED.metadata
                RETURNING id::text
                """,
                (
                    self._org_id,
                    self._conn_id,
                    node_type,
                    external_id,
                    display_name or f"{node_type}-{external_id[:20]}",
                    _json_dumps(metadata or {}),
                ),
            )
            row = cursor.fetchone()
            cursor.close()
            return row[0] if row else None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "phase3_graph_writer: _upsert_node failed type=%s ext=%s err=%s",
                node_type,
                external_id[:60],
                exc,
            )
            try:
                self._db._rollback()
            except Exception:  # noqa: BLE001
                pass
            return None

    def _upsert_identity_nodes(
        self, identities: list[dict[str, Any]]
    ) -> dict[str, str]:
        """Upsert all identity nodes. Returns {identity_id: node_uuid}."""
        result: dict[str, str] = {}
        for ident in identities:
            iid = ident.get("identity_id")
            if not iid:
                continue
            node_id = self._upsert_node(
                node_type="identity",
                external_id=iid,
                display_name=ident.get("display_name", ""),
                metadata={
                    "identity_category": ident.get("identity_category"),
                    "source": ident.get("source", "azure"),
                    "risk_level": ident.get("risk_level"),
                    "risk_score": ident.get("risk_score"),
                    "user_principal_name": ident.get("user_principal_name"),
                },
            )
            if node_id:
                result[iid] = node_id
        return result

    # ------------------------------------------------------------------
    # Edge upserts
    # ------------------------------------------------------------------

    def _upsert_edge(
        self,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
        *,
        source_node_type: str = "identity",
        target_node_type: str = "role",
        usage_confidence: str = "none",
        metadata: Optional[dict[str, Any]] = None,
        written_keys: Optional[set[tuple[str, str, str]]] = None,
    ) -> bool:
        """Upsert a single graph_edge. Returns True on success.

        Dedup key: ``(source_node_id, target_node_id, edge_type)``.
        """
        try:
            cursor = self._db.conn.cursor()
            # Check for existing edge (same source, target, edge_type, org, conn)
            cursor.execute(
                """
                SELECT id::text FROM graph_edges
                WHERE organization_id = %s
                  AND cloud_connection_id = %s
                  AND source_node_id = %s::uuid
                  AND target_node_id = %s::uuid
                  AND edge_type = %s
                LIMIT 1
                """,
                (self._org_id, self._conn_id, source_node_id, target_node_id, edge_type),
            )
            existing = cursor.fetchone()

            if existing:
                # Update existing edge — refresh validity + confidence
                cursor.execute(
                    """
                    UPDATE graph_edges
                    SET usage_confidence = %s,
                        cloud_provider   = 'azure',
                        valid_at         = NOW(),
                        invalidated_at   = NULL,
                        metadata         = %s::jsonb,
                        source_node_type = %s,
                        target_node_type = %s
                    WHERE id = %s::uuid
                    """,
                    (
                        usage_confidence,
                        _json_dumps(metadata or {}),
                        source_node_type,
                        target_node_type,
                        existing[0],
                    ),
                )
            else:
                # Insert new edge
                cursor.execute(
                    """
                    INSERT INTO graph_edges
                        (organization_id, cloud_connection_id,
                         source_node_id, target_node_id, edge_type,
                         source_node_type, target_node_type,
                         usage_confidence, cloud_provider,
                         valid_at, metadata)
                    VALUES (%s, %s, %s::uuid, %s::uuid, %s, %s, %s, %s, 'azure', NOW(), %s::jsonb)
                    """,
                    (
                        self._org_id,
                        self._conn_id,
                        source_node_id,
                        target_node_id,
                        edge_type,
                        source_node_type,
                        target_node_type,
                        usage_confidence,
                        _json_dumps(metadata or {}),
                    ),
                )

            cursor.close()

            if written_keys is not None:
                written_keys.add((source_node_id, target_node_id, edge_type))

            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "phase3_graph_writer: _upsert_edge failed %s→%s type=%s err=%s",
                source_node_id[:12],
                target_node_id[:12],
                edge_type,
                exc,
            )
            try:
                self._db._rollback()
            except Exception:  # noqa: BLE001
                pass
            return False

    # ------------------------------------------------------------------
    # Confidence derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_confidence(identity: dict[str, Any]) -> str:
        """Derive usage_confidence from identity activity recency.

        HIGH  — last activity within 30 days
        MEDIUM — 30–90 days
        LOW   — 90–180 days
        NONE  — >180 days or no activity data
        """
        last_activity = identity.get("last_activity_at") or identity.get("last_sign_in")
        if not last_activity:
            return "none"

        if isinstance(last_activity, str):
            try:
                last_activity = datetime.fromisoformat(
                    last_activity.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                return "none"

        if not isinstance(last_activity, datetime):
            return "none"

        now = datetime.now(timezone.utc)
        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)

        days = (now - last_activity).days

        if days <= _CONFIDENCE_HIGH_DAYS:
            return "high"
        if days <= _CONFIDENCE_MEDIUM_DAYS:
            return "medium"
        if days <= _CONFIDENCE_LOW_DAYS:
            return "low"
        return "none"

    # ------------------------------------------------------------------
    # Relationship writers
    # ------------------------------------------------------------------

    def _write_role_edges(
        self,
        identities: list[dict[str, Any]],
        identity_node_ids: dict[str, str],
        written_keys: set[tuple[str, str, str]],
    ) -> dict[str, int]:
        """Write HAS_ROLE edges for Azure RBAC + Entra directory roles."""
        stats = {"nodes": 0, "edges": 0}

        for ident in identities:
            iid = ident.get("identity_id")
            src_node = identity_node_ids.get(iid) if iid else None
            if not src_node:
                continue

            confidence = self._derive_confidence(ident)

            # Azure RBAC roles
            for role in ident.get("roles", []):
                role_name = role.get("role_name")
                if not role_name:
                    continue
                role_ext_id = f"rbac:{role_name}"
                role_node = self._upsert_node(
                    node_type="role",
                    external_id=role_ext_id,
                    display_name=role_name,
                    metadata={
                        "role_type": "azure_rbac",
                        "risk_level": role.get("risk_level"),
                    },
                )
                if role_node:
                    stats["nodes"] += 1
                    ok = self._upsert_edge(
                        source_node_id=src_node,
                        target_node_id=role_node,
                        edge_type="HAS_ROLE",
                        source_node_type="identity",
                        target_node_type="role",
                        usage_confidence=confidence,
                        metadata={
                            "scope": role.get("scope"),
                            "scope_type": role.get("scope_type"),
                            "role_type": "azure_rbac",
                        },
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

            # Entra directory roles
            for role in ident.get("entra_roles", []):
                role_name = role.get("role_name")
                if not role_name:
                    continue
                role_ext_id = f"entra:{role_name}"
                role_node = self._upsert_node(
                    node_type="role",
                    external_id=role_ext_id,
                    display_name=role_name,
                    metadata={
                        "role_type": "entra",
                        "risk_level": role.get("risk_level"),
                        "directory_scope": role.get("directory_scope"),
                    },
                )
                if role_node:
                    stats["nodes"] += 1
                    ok = self._upsert_edge(
                        source_node_id=src_node,
                        target_node_id=role_node,
                        edge_type="HAS_ROLE",
                        source_node_type="identity",
                        target_node_type="role",
                        usage_confidence=confidence,
                        metadata={
                            "role_type": "entra",
                            "directory_scope": role.get("directory_scope"),
                        },
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

        return stats

    def _write_permission_edges(
        self,
        identities: list[dict[str, Any]],
        identity_node_ids: dict[str, str],
        permissions_map: Optional[dict[str, list[dict[str, Any]]]],
        written_keys: set[tuple[str, str, str]],
    ) -> dict[str, int]:
        """Write HAS_PERMISSION edges for MS Graph API permissions."""
        stats = {"nodes": 0, "edges": 0}
        perm_map = permissions_map or {}

        for ident in identities:
            iid = ident.get("identity_id")
            src_node = identity_node_ids.get(iid) if iid else None
            if not src_node:
                continue

            confidence = self._derive_confidence(ident)

            # Permissions from the identity dict
            perms = ident.get("permissions", [])
            # Also check the permissions_map keyed by identity_id
            if iid in perm_map:
                perms = perms + perm_map[iid]

            seen_perms: set[str] = set()
            for perm in perms:
                perm_name = perm.get("permission_name")
                if not perm_name or perm_name in seen_perms:
                    continue
                seen_perms.add(perm_name)

                # Node type is "role" in the graph schema (permissions are
                # modeled as role-like nodes the identity "has").
                perm_ext_id = f"perm:{perm_name}"
                perm_node = self._upsert_node(
                    node_type="role",
                    external_id=perm_ext_id,
                    display_name=perm_name,
                    metadata={
                        "permission_type": perm.get("permission_type"),
                        "risk_level": perm.get("risk_level"),
                        "category": perm.get("category"),
                    },
                )
                if perm_node:
                    stats["nodes"] += 1
                    ok = self._upsert_edge(
                        source_node_id=src_node,
                        target_node_id=perm_node,
                        edge_type="HAS_PERMISSION",
                        source_node_type="identity",
                        target_node_type="role",
                        usage_confidence=confidence,
                        metadata={
                            "permission_type": perm.get("permission_type"),
                        },
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

        return stats

    def _write_resource_edges(
        self,
        identities: list[dict[str, Any]],
        identity_node_ids: dict[str, str],
        written_keys: set[tuple[str, str, str]],
    ) -> dict[str, int]:
        """Write resource nodes + CAN_ACCESS / BOUND_TO edges from role scopes.

        Creates two edge patterns per role assignment:
        1. identity → (CAN_ACCESS|BOUND_TO) → resource  (direct)
        2. role → (CAN_ACCESS) → resource  (for multi-hop BFS:
           identity → HAS_ROLE → role → CAN_ACCESS → resource)
        """
        stats = {"nodes": 0, "edges": 0}

        for ident in identities:
            iid = ident.get("identity_id")
            src_node = identity_node_ids.get(iid) if iid else None
            if not src_node:
                continue

            confidence = self._derive_confidence(ident)
            category = ident.get("identity_category", "")
            is_managed_identity = "managed_identity" in category

            for role in ident.get("roles", []):
                scope = role.get("scope")
                if not scope:
                    continue

                role_name = role.get("role_name")
                resource_name = role.get("resource_name") or _scope_leaf(scope)
                resource_type = role.get("resource_type") or "resource"

                resource_node = self._upsert_node(
                    node_type="resource",
                    external_id=scope,
                    display_name=resource_name,
                    metadata={
                        "resource_type": resource_type,
                        "scope_type": role.get("scope_type"),
                    },
                )
                if resource_node:
                    stats["nodes"] += 1

                    # 1. identity → resource (direct edge)
                    edge_type = "BOUND_TO" if is_managed_identity else "CAN_ACCESS"
                    ok = self._upsert_edge(
                        source_node_id=src_node,
                        target_node_id=resource_node,
                        edge_type=edge_type,
                        source_node_type="identity",
                        target_node_type="resource",
                        usage_confidence=confidence,
                        metadata={
                            "role_name": role_name,
                            "scope_type": role.get("scope_type"),
                        },
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

                    # 2. role → resource (multi-hop edge for BFS:
                    #    identity → HAS_ROLE → role → CAN_ACCESS → resource)
                    if role_name and not is_managed_identity:
                        role_ext_id = f"rbac:{role_name}"
                        role_node = self._lookup_node("role", role_ext_id)
                        if role_node:
                            ok = self._upsert_edge(
                                source_node_id=role_node,
                                target_node_id=resource_node,
                                edge_type="CAN_ACCESS",
                                source_node_type="role",
                                target_node_type="resource",
                                usage_confidence=confidence,
                                metadata={
                                    "role_name": role_name,
                                    "scope": scope,
                                },
                                written_keys=written_keys,
                            )
                            if ok:
                                stats["edges"] += 1

        return stats

    def _write_subscription_edges(
        self,
        identities: list[dict[str, Any]],
        identity_node_ids: dict[str, str],
        written_keys: set[tuple[str, str, str]],
    ) -> dict[str, int]:
        """Write subscription nodes + PART_OF edges (resource → subscription)."""
        stats = {"nodes": 0, "edges": 0}
        # Collect unique subscriptions from role scopes
        sub_nodes: dict[str, str] = {}  # {sub_id: node_uuid}

        for ident in identities:
            for role in ident.get("roles", []):
                sub_id = role.get("subscription_id")
                sub_name = role.get("subscription_name", "")
                if not sub_id:
                    continue
                if sub_id in sub_nodes:
                    continue

                node_id = self._upsert_node(
                    node_type="subscription",
                    external_id=sub_id,
                    display_name=sub_name or f"sub-{sub_id[:8]}",
                    metadata={"cloud": "azure"},
                )
                if node_id:
                    sub_nodes[sub_id] = node_id
                    stats["nodes"] += 1

        # Link resources to subscriptions via PART_OF
        # We need to look up resource nodes by scope containing the sub_id
        for ident in identities:
            iid = ident.get("identity_id")
            src_node = identity_node_ids.get(iid) if iid else None
            if not src_node:
                continue

            for role in ident.get("roles", []):
                sub_id = role.get("subscription_id")
                scope = role.get("scope")
                if not sub_id or not scope or sub_id not in sub_nodes:
                    continue

                # Look up the resource node we created for this scope
                resource_node = self._lookup_node("resource", scope)
                if resource_node and resource_node != sub_nodes[sub_id]:
                    ok = self._upsert_edge(
                        source_node_id=resource_node,
                        target_node_id=sub_nodes[sub_id],
                        edge_type="PART_OF",
                        source_node_type="resource",
                        target_node_type="subscription",
                        usage_confidence="high",
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

        return stats

    def _write_owns_edges(
        self,
        identities: list[dict[str, Any]],
        identity_node_ids: dict[str, str],
        written_keys: set[tuple[str, str, str]],
    ) -> dict[str, int]:
        """Write OWNS edges for identities with Owner-level roles."""
        stats = {"edges": 0}

        for ident in identities:
            iid = ident.get("identity_id")
            src_node = identity_node_ids.get(iid) if iid else None
            if not src_node:
                continue

            confidence = self._derive_confidence(ident)

            for role in ident.get("roles", []):
                role_name = (role.get("role_name") or "").lower()
                if "owner" not in role_name:
                    continue

                scope = role.get("scope")
                if not scope:
                    continue

                resource_node = self._lookup_node("resource", scope)
                if resource_node:
                    ok = self._upsert_edge(
                        source_node_id=src_node,
                        target_node_id=resource_node,
                        edge_type="OWNS",
                        source_node_type="identity",
                        target_node_type="resource",
                        usage_confidence=confidence,
                        metadata={"role_name": role.get("role_name")},
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

        return stats

    def _write_member_of_edges(
        self,
        identities: list[dict[str, Any]],
        identity_node_ids: dict[str, str],
        written_keys: set[tuple[str, str, str]],
    ) -> dict[str, int]:
        """Write MEMBER_OF edges for group membership.

        Azure managed identities expose group membership in
        ``alternativeNames``. Human users may have ``memberOf`` lists.
        """
        stats = {"nodes": 0, "edges": 0}

        for ident in identities:
            iid = ident.get("identity_id")
            src_node = identity_node_ids.get(iid) if iid else None
            if not src_node:
                continue

            confidence = self._derive_confidence(ident)

            # Groups from memberOf
            for group in ident.get("member_of", []):
                group_id = group if isinstance(group, str) else group.get("id")
                group_name = group if isinstance(group, str) else group.get("display_name", "")
                if not group_id:
                    continue

                group_node = self._upsert_node(
                    node_type="identity",
                    external_id=f"group:{group_id}",
                    display_name=group_name or f"group-{group_id[:8]}",
                    metadata={"identity_category": "group"},
                )
                if group_node:
                    stats["nodes"] += 1
                    ok = self._upsert_edge(
                        source_node_id=src_node,
                        target_node_id=group_node,
                        edge_type="MEMBER_OF",
                        source_node_type="identity",
                        target_node_type="identity",
                        usage_confidence=confidence,
                        written_keys=written_keys,
                    )
                    if ok:
                        stats["edges"] += 1

        return stats

    # ------------------------------------------------------------------
    # Temporal edge invalidation
    # ------------------------------------------------------------------

    def _invalidate_stale_edges(
        self, written_keys: set[tuple[str, str, str]]
    ) -> int:
        """Mark edges from previous runs as invalidated if they were not
        refreshed in this run.

        Only touches edges for this org + connection that still have
        ``invalidated_at IS NULL``.
        """
        if not written_keys:
            return 0

        try:
            cursor = self._db.conn.cursor()

            # Fetch all active edges for this org + connection
            cursor.execute(
                """
                SELECT id::text, source_node_id::text, target_node_id::text, edge_type
                FROM graph_edges
                WHERE organization_id = %s
                  AND cloud_connection_id = %s
                  AND invalidated_at IS NULL
                """,
                (self._org_id, self._conn_id),
            )
            active_edges = cursor.fetchall()

            stale_ids: list[str] = []
            for edge_row in active_edges:
                edge_id, src, tgt, etype = edge_row
                key = (src, tgt, etype)
                if key not in written_keys:
                    stale_ids.append(edge_id)

            if stale_ids:
                # Batch invalidate
                for offset in range(0, len(stale_ids), _BATCH_SIZE):
                    chunk = stale_ids[offset : offset + _BATCH_SIZE]
                    placeholders = ",".join(["%s"] * len(chunk))
                    cursor.execute(
                        f"""
                        UPDATE graph_edges
                        SET invalidated_at = NOW()
                        WHERE id::text IN ({placeholders})
                          AND organization_id = %s
                        """,
                        (*chunk, self._org_id),
                    )

            cursor.close()
            return len(stale_ids)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "phase3_graph_writer: _invalidate_stale_edges failed err=%s",
                exc,
            )
            return 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _lookup_node(self, node_type: str, external_id: str) -> Optional[str]:
        """Look up a node UUID by (cloud_connection_id, node_type, external_id)."""
        try:
            cursor = self._db.conn.cursor()
            cursor.execute(
                """
                SELECT id::text FROM graph_nodes
                WHERE cloud_connection_id = %s
                  AND node_type = %s
                  AND external_id = %s
                LIMIT 1
                """,
                (self._conn_id, node_type, external_id),
            )
            row = cursor.fetchone()
            cursor.close()
            return row[0] if row else None
        except Exception:  # noqa: BLE001
            return None


def _scope_leaf(scope: str) -> str:
    """Extract the last segment of an ARM scope path as a display name."""
    parts = scope.rstrip("/").split("/")
    return parts[-1] if parts else scope


def _json_dumps(obj: Any) -> str:
    """JSON-serialize for psycopg2 JSONB binding."""
    import json

    return json.dumps(obj, default=str)


__all__ = ["Phase3GraphWriter"]
