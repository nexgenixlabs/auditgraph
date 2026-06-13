"""
scope_classifier — apply Data Trust Zones to resources

AG-193 / AG-194 (Sprint 1) · 2026-06-12

Walks every classifiable resource for an org's latest discovery run
and applies CISO-asserted Data Trust Zones (stored in data_trust_zones).
Updates the data_classification + provenance columns on:

    - azure_storage_accounts
    - azure_key_vaults
    - azure_sql_databases (if present)
    - azure_cosmos_databases (if present)
    - discovered_resources (catch-all)

Does NOT overwrite higher-precedence classifications:
    - existing classification with source IN ('manual','regex_override','purview')
      stays untouched (those tiers outrank scope rules' tier 3)
    - existing classification with source IN ('tag','name_pattern')
      gets OVERWRITTEN by a scope rule match (tier 3 > tier 5/6)

Called at two points:
    1. Post-discovery scheduler tier 2 — re-classify after every scan
    2. Manual /api/data-trust-zones/recompute — after CRUD changes
"""

from __future__ import annotations

import logging
from typing import Any

from app.constants.data_classification import classify_resource

logger = logging.getLogger(__name__)


# Higher-precedence sources we MUST NOT overwrite.
_PROTECTED_SOURCES = frozenset({"manual", "regex_override", "purview"})


# Tables we walk + the columns we read/write. Each entry:
#   (table_name, key_columns_to_select_for_join, has_subscription, has_resource_group)
# subscription / RG are extracted from the resource_id ARM path when not present.
_TARGET_TABLES = [
    ("azure_storage_accounts",  True),
    ("azure_key_vaults",        True),
    ("azure_sql_databases",     True),
    ("azure_cosmos_databases",  True),
    ("discovered_resources",    True),
]


def _table_exists(cursor, table: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema='public' AND table_name=%s",
        (table,),
    )
    return cursor.fetchone() is not None


def _has_column(cursor, table: str, col: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name=%s AND column_name=%s",
        (table, col),
    )
    return cursor.fetchone() is not None


def load_active_scope_rules(cursor, organization_id: int) -> list[dict[str, Any]]:
    """Return the list of active (not revoked) Data Trust Zones for an org.

    Sorted by created_at DESC so more recently added rules match first.
    This is a convention — the matcher itself is first-match-wins.
    """
    cursor.execute(
        """
        SELECT id, classification, scope_type, scope_value
          FROM data_trust_zones
         WHERE organization_id = %s
           AND revoked_at IS NULL
         ORDER BY created_at DESC
        """,
        (organization_id,),
    )
    return [
        {
            "id": r[0],
            "classification": r[1],
            "scope_type": r[2],
            "scope_value": r[3],
        }
        for r in cursor.fetchall()
    ]


def _extract_sub_and_rg(resource_id: str | None) -> tuple[str | None, str | None]:
    """Pull subscription id + resource group name from an ARM resource_id.

    ARM format:
      /subscriptions/<sub>/resourceGroups/<rg>/providers/...
    Returns (None, None) if the path can't be parsed.
    """
    if not resource_id or not isinstance(resource_id, str):
        return (None, None)
    parts = resource_id.strip("/").split("/")
    sub = None
    rg = None
    try:
        if len(parts) >= 2 and parts[0].lower() == "subscriptions":
            sub = parts[1]
        if len(parts) >= 4 and parts[2].lower() == "resourcegroups":
            rg = parts[3]
    except (IndexError, AttributeError):
        pass
    return (sub, rg)


def apply_scope_classification(
    db, organization_id: int, run_id: int | None = None
) -> dict[str, Any]:
    """Apply Data Trust Zones to all classifiable resources for an org.

    Args:
      db: Database instance (tenant-scoped — RLS context already set)
      organization_id: org to recompute for
      run_id: optional — limit to a specific discovery run; None = current latest

    Returns:
      {
        'rules_active': N,
        'tables_walked': [...],
        'rows_updated': total,
        'by_classification': {PHI: int, PCI: int, ...},
        'skipped_protected': N,  # rows we left alone because higher tier owned them
      }

    Idempotent: re-running with the same rules + data → 0 updates.
    """
    cursor = db.conn.cursor()
    result: dict[str, Any] = {
        "rules_active": 0,
        "tables_walked": [],
        "rows_updated": 0,
        "by_classification": {},
        "skipped_protected": 0,
    }

    scope_rules = load_active_scope_rules(cursor, organization_id)
    result["rules_active"] = len(scope_rules)

    if not scope_rules:
        logger.info("scope_classifier: org=%s has no active rules; skipping",
                    organization_id)
        cursor.close()
        return result

    for table, _has_org in _TARGET_TABLES:
        if not _table_exists(cursor, table):
            continue
        if not _has_column(cursor, table, "classification_rule_id"):
            logger.warning("scope_classifier: %s missing classification_rule_id "
                           "(migration 226 not applied?); skipping",
                           table)
            continue

        # Different tables use different name columns. Pick the first
        # that exists: 'name', 'display_name', 'resource_name'.
        name_col = None
        for cand in ("name", "display_name", "resource_name"):
            if _has_column(cursor, table, cand):
                name_col = cand
                break
        if name_col is None:
            logger.warning("scope_classifier: %s has no name column (tried name/"
                           "display_name/resource_name); skipping", table)
            continue

        # tags column: discovered_resources has 'tags' jsonb; some tables may not.
        tags_col = "tags" if _has_column(cursor, table, "tags") else None
        sub_col = "subscription_id" if _has_column(cursor, table, "subscription_id") else None
        rg_col = "resource_group" if _has_column(cursor, table, "resource_group") else None

        cols = ["resource_id", name_col, "data_classification", "classification_source"]
        if tags_col: cols.append(tags_col)
        if sub_col: cols.append(sub_col)
        if rg_col: cols.append(rg_col)

        where_clauses = ["organization_id = %s"]
        params: list[Any] = [organization_id]
        if run_id is not None and _has_column(cursor, table, "discovery_run_id"):
            where_clauses.append("discovery_run_id = %s")
            params.append(run_id)

        sql = (
            f"SELECT {', '.join(cols)} FROM {table} "
            f"WHERE {' AND '.join(where_clauses)}"
        )
        try:
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
        except Exception as exc:
            logger.warning("scope_classifier: SELECT %s failed: %s", table, exc)
            try: db.conn.rollback()
            except Exception: pass
            continue

        result["tables_walked"].append(table)
        updates = 0
        protected = 0

        for row in rows:
            resource_id = row[0]
            name = row[1] or ""
            current_classification = row[2]
            current_source = row[3]
            tags = row[cols.index(tags_col)] if tags_col else None
            sub = row[cols.index(sub_col)] if sub_col else None
            rg = row[cols.index(rg_col)] if rg_col else None

            # Try to extract sub/RG from the resource_id ARM path if columns absent.
            if not sub or not rg:
                arm_sub, arm_rg = _extract_sub_and_rg(resource_id)
                sub = sub or arm_sub
                rg = rg or arm_rg

            # Skip higher-precedence rows (manual/regex_override/purview own them).
            if current_source in _PROTECTED_SOURCES:
                protected += 1
                continue

            # AG-198 Sprint 3 — query Purview (tier 4) when the integration
            # is enabled. The cache+graceful-degradation guarantee means
            # this is safe to call unconditionally; the function returns
            # None when disabled or unreachable, and the classify engine
            # falls through to tag/name.
            purview_label = None
            try:
                from app.config import FEATURE_PURVIEW_INTEGRATION
                if FEATURE_PURVIEW_INTEGRATION:
                    from app.engines.discovery.purview_classifier import (
                        get_purview_label_for_resource
                    )
                    purview_label = get_purview_label_for_resource(
                        organization_id, resource_id
                    )
            except Exception:
                purview_label = None

            verdict = classify_resource(
                name=name,
                tags=tags if isinstance(tags, dict) else None,
                scope_rules=scope_rules,
                subscription_id=sub,
                resource_group=rg,
                purview_label=purview_label,
            )

            # No verdict OR same as current → no work.
            if not verdict:
                continue
            if (verdict["classification"] == current_classification
                and current_source == verdict["source"]):
                continue

            # Write back when the verdict comes from a high-trust tier
            # (scope_rule or purview). Tag/name verdicts already get
            # written by discovery itself; re-running them here would
            # just churn the row.
            if verdict["source"] not in ("scope_rule", "purview"):
                continue

            try:
                cursor.execute(
                    f"""UPDATE {table}
                          SET data_classification        = %s,
                              classification_source      = %s,
                              classification_confidence  = %s,
                              classification_rule_id     = %s
                        WHERE organization_id = %s AND resource_id = %s""",
                    (
                        verdict["classification"],
                        verdict["source"],
                        verdict["confidence"],
                        verdict.get("rule_id"),
                        organization_id,
                        resource_id,
                    ),
                )
                if cursor.rowcount > 0:
                    updates += 1
                    cls = verdict["classification"]
                    result["by_classification"][cls] = (
                        result["by_classification"].get(cls, 0) + 1
                    )
            except Exception as exc:
                logger.warning("scope_classifier: UPDATE %s for %s failed: %s",
                               table, resource_id, exc)
                try: db.conn.rollback()
                except Exception: pass
                continue

        result["rows_updated"] += updates
        result["skipped_protected"] += protected
        if updates:
            logger.info("scope_classifier: %s updated=%d protected_skipped=%d",
                        table, updates, protected)

    try:
        db.conn.commit()
    except Exception as exc:
        logger.warning("scope_classifier: commit failed: %s", exc)
        try: db.conn.rollback()
        except Exception: pass

    cursor.close()
    return result


__all__ = [
    "apply_scope_classification",
    "load_active_scope_rules",
]
