"""Argus L3 — Attack Path Investigator (AG-187).

Public entry point: :func:`investigate_attack_path`.

Purpose
-------
A user asks Argus a question like::

    "Can an AI agent take over my subscription?"
    "Show attack paths from the storage account to PHI"
    "How could a guest exfiltrate data from key vault X?"

This module resolves the free-text ``source_query`` / ``target_query`` to
concrete entities (identity ids, resource ids, subscriptions) using the
identity + resource catalog, then looks for the strongest matching row in
``attack_paths``. If nothing is persisted and ``prefer_persisted=False`` the
investigator falls back to a live :class:`AttackPathEngine` run scoped to the
resolved source.

Design rules (mandated by AG-187):

* **No fake paths.** If we can't find a matching path we return
  ``{found: False, why: '...'}`` — the UI handles the empty state. We never
  fabricate nodes.
* **Cite the graph.** Resolution metadata (``source_resolved`` /
  ``target_resolved``) tells the caller exactly which row(s) we matched so
  the UI can deep-link to the entity, and ``resolution_confidence`` lets the
  caller down-weight low-confidence matches.
* **SAVEPOINT every DB query.** Resolution touches half a dozen tables and we
  must not poison the outer transaction when one of them is missing in older
  snapshots.
* **Reuse shared infra.** MITRE enrichment lives in
  ``app.constants.mitre``; scope-matching lives in
  ``app.services.access_resolution``. We don't re-implement either.

The caller provides ``cursor`` (the row factory does not matter — both tuple
and dict cursors are handled) so this function can run inside any open
transaction. ``organization_id`` is mandatory; callers pass the JWT org id.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Tunables
# ─────────────────────────────────────────────────────────────────────────────

# Keyword aliases for the "AI agent" resolution rule. Hits when the user's
# free-text source/target contains any of these tokens (case-insensitive).
_AI_AGENT_KEYWORDS = ("ai agent", "ai-agent", "agentic", "copilot agent",
                      "llm agent", "ai assistant")

# Resource-type keyword → SQL table. The matcher is keyword-driven, not
# regex-driven, so "show me my key vaults" and "kv" both work.
_RESOURCE_TYPE_KEYWORDS: dict[str, tuple[str, str]] = {
    # keyword              → (resource_kind_label, table_name)
    "key vault":             ("key_vault",        "azure_key_vaults"),
    "keyvault":              ("key_vault",        "azure_key_vaults"),
    "kv":                    ("key_vault",        "azure_key_vaults"),
    "storage account":       ("storage_account",  "azure_storage_accounts"),
    "storage":               ("storage_account",  "azure_storage_accounts"),
    "blob":                  ("storage_account",  "azure_storage_accounts"),
    "sql database":          ("sql_database",     "azure_sql_databases"),
    "sql db":                ("sql_database",     "azure_sql_databases"),
    "database":              ("sql_database",     "azure_sql_databases"),
    "subscription":          ("subscription",     None),
}

# Free-text → data-classification literal (uppercase, matches the SSOT in
# ``app.constants.data_classification.ALL_CLASSES``).
_CLASSIFICATION_KEYWORDS: dict[str, str] = {
    "phi":          "PHI",
    "pci":          "PCI",
    "pii":          "PII",
    "hr":           "HR",
    "source code":  "SOURCE",
    "source":       "SOURCE",
    "financial":    "FINANCIAL",
    "confidential": "CONFIDENTIAL",
}

# Tables that carry a ``data_classification`` column we can match against.
_CLASSIFIED_TABLES: tuple[tuple[str, str], ...] = (
    # (table_name, resource_kind_label)
    ("azure_storage_accounts", "storage_account"),
    ("azure_key_vaults",       "key_vault"),
    ("azure_sql_databases",    "sql_database"),
)

# Subscription IDs are GUIDs — capture them with a tolerant regex.
_UUID_RE = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    flags=re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Public types
# ─────────────────────────────────────────────────────────────────────────────

# Resolved entity descriptor. ``kind`` is one of:
#   'identity'      → matched an identities row (id = identity_id literal)
#   'resource'      → matched one or more Azure resources (id = resource_id or
#                     list of resource_ids when the match was a keyword)
#   'subscription'  → matched a subscription_id GUID
#   'class'         → matched a data-classification literal (covers many
#                     resources). id is the classification, ``resource_ids``
#                     enumerates the matched targets.
ResolvedEntity = dict


# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — every query is SAVEPOINT-wrapped
# ─────────────────────────────────────────────────────────────────────────────

def _savepoint(cursor: Any, name: str) -> bool:
    """Open a savepoint; return True on success. Safe to skip if the outer
    transaction can't take a savepoint (autocommit), in which case we log and
    fall through — the caller still gets exception isolation via try/except.
    """
    try:
        cursor.execute(f"SAVEPOINT {name}")
        return True
    except Exception as exc:
        logger.debug("argus_l3: SAVEPOINT %s failed: %s", name, exc)
        return False


def _release(cursor: Any, name: str) -> None:
    try:
        cursor.execute(f"RELEASE SAVEPOINT {name}")
    except Exception:
        pass


def _rollback_to(cursor: Any, name: str) -> None:
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {name}")
    except Exception:
        pass


def _cell(row: Any, idx: int, key: str) -> Any:
    """Return row[idx] for tuple cursors, row[key] for dict cursors.

    The investigator must work with both ``RealDictCursor`` and the default
    tuple cursor — this small adapter keeps the rest of the code uniform.
    """
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[idx]
    except (IndexError, KeyError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Resolution
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(n in text for n in needles)


def _extract_uuid(text: str) -> Optional[str]:
    m = _UUID_RE.search(text or "")
    return m.group(1).lower() if m else None


def _resolve_query(
    cursor: Any,
    organization_id: int,
    query: str,
) -> Optional[ResolvedEntity]:
    """Resolve a free-text ``query`` to one of the entity shapes above.

    Tried in order:
      1. Exact identity_id / resource_id literal               → high
      2. Display-name / resource-name substring                → medium
      3. AI-agent category keyword                             → medium
      4. Resource-type keyword (key vault, storage, …)         → medium
      5. Data-classification keyword (PHI / PCI / …)           → medium
      6. Subscription keyword + UUID                           → high

    Returns ``None`` when nothing matched (caller can decide whether that's
    fatal). Confidence is returned alongside so the caller can record it on
    the investigation result.
    """
    if not query:
        return None

    q = query.strip()
    q_low = q.lower()

    # ── 1. Literal identity_id / resource_id ─────────────────────────────
    # identity_id is typically a GUID; resource_id starts with '/subscriptions/'.
    # We attempt both literal lookups before falling back to fuzzy match.
    literal = _resolve_literal(cursor, organization_id, q)
    if literal is not None:
        return literal

    # ── 2. Subscription keyword + UUID ───────────────────────────────────
    # Done before generic substring so "subscription <guid>" doesn't trigger
    # a name match against unrelated rows.
    if "subscription" in q_low:
        uuid = _extract_uuid(q)
        if uuid:
            return {
                "kind": "subscription",
                "id": uuid,
                "label": f"Subscription {uuid}",
                "confidence": "high",
                "why": f"matched literal subscription id '{uuid}'",
            }

    # ── 3. AI-agent keyword ──────────────────────────────────────────────
    if _contains_any(q_low, _AI_AGENT_KEYWORDS):
        agents = _resolve_ai_agents(cursor, organization_id)
        if agents:
            return {
                "kind": "identity",
                "id": [a["identity_id"] for a in agents],
                "identity_db_ids": [a["id"] for a in agents],
                "label": f"{len(agents)} AI agent identit{'y' if len(agents) == 1 else 'ies'}",
                "items": agents,
                "confidence": "medium",
                "why": "matched AI-agent category (agent_classifications.agent_identity_type IN ('ai_agent','possible_ai_agent'))",
            }

    # ── 4. Classification keyword (PHI / PCI / …) ────────────────────────
    cls = _detect_classification(q_low)
    if cls is not None:
        resources = _resolve_classified_resources(cursor, organization_id, cls)
        if resources:
            return {
                "kind": "class",
                "id": cls,
                "classification": cls,
                "resource_ids": [r["resource_id"] for r in resources],
                "label": f"{cls} resources ({len(resources)})",
                "items": resources,
                "confidence": "medium",
                "why": f"matched data_classification='{cls}' across {len(resources)} resource(s)",
            }

    # ── 5. Resource-type keyword (key vault, storage, …) ─────────────────
    resource_kind, table = _detect_resource_type(q_low)
    if resource_kind:
        if resource_kind == "subscription":
            # Bare "subscription" with no UUID — ambiguous, skip.
            pass
        elif table is not None:
            resources = _resolve_resources_in_table(
                cursor, organization_id, table, resource_kind,
            )
            if resources:
                return {
                    "kind": "resource",
                    "id": [r["resource_id"] for r in resources],
                    "resource_ids": [r["resource_id"] for r in resources],
                    "label": f"{len(resources)} {resource_kind.replace('_', ' ')}(s)",
                    "items": resources,
                    "confidence": "medium",
                    "why": f"matched resource-type keyword for {resource_kind}",
                }

    # ── 6. Display-name / resource-name substring ────────────────────────
    # Substring match across identities + resource tables. Cheapest after the
    # specific keyword rules so we don't accidentally swallow a category.
    if len(q) >= 3:
        substring = _resolve_substring(cursor, organization_id, q)
        if substring is not None:
            return substring

    return None


def _resolve_literal(
    cursor: Any,
    organization_id: int,
    q: str,
) -> Optional[ResolvedEntity]:
    """Try to match ``q`` as a literal identity_id or resource_id.

    Identities first (UUID-shaped), then resources (slash-prefixed). Returns
    None if neither matches.
    """
    # 1a — identity_id literal
    if _savepoint(cursor, "argus_l3_lit_id"):
        try:
            cursor.execute(
                """
                SELECT i.id, i.identity_id, i.display_name, i.identity_category
                  FROM identities i
                 WHERE i.identity_id = %s
                   AND (%s IS NULL OR i.organization_id = %s)
                 LIMIT 1
                """,
                (q, organization_id, organization_id),
            )
            row = cursor.fetchone()
            _release(cursor, "argus_l3_lit_id")
            if row is not None:
                return {
                    "kind": "identity",
                    "id": _cell(row, 1, "identity_id"),
                    "identity_db_id": _cell(row, 0, "id"),
                    "label": _cell(row, 2, "display_name") or _cell(row, 1, "identity_id"),
                    "category": _cell(row, 3, "identity_category"),
                    "confidence": "high",
                    "why": f"matched identity_id literal '{q}'",
                }
        except Exception as exc:
            logger.debug("argus_l3: literal identity lookup failed: %s", exc)
            _rollback_to(cursor, "argus_l3_lit_id")

    # 1b — resource_id literal across resource tables
    # Match against ANY of the resource tables that carry a resource_id PK.
    for table, kind in (
        ("azure_key_vaults",       "key_vault"),
        ("azure_storage_accounts", "storage_account"),
        ("azure_sql_databases",    "sql_database"),
    ):
        sp = f"argus_l3_lit_{kind}"
        if not _savepoint(cursor, sp):
            continue
        try:
            # azure_sql_databases uses ``database_name``, others use ``name``.
            name_col = "database_name" if table == "azure_sql_databases" else "name"
            cursor.execute(
                f"""
                SELECT resource_id, {name_col} AS rname, subscription_id
                  FROM {table}
                 WHERE resource_id = %s
                   AND (%s IS NULL OR organization_id = %s)
                 LIMIT 1
                """,
                (q, organization_id, organization_id),
            )
            row = cursor.fetchone()
            _release(cursor, sp)
            if row is not None:
                return {
                    "kind": "resource",
                    "resource_kind": kind,
                    "id": _cell(row, 0, "resource_id"),
                    "resource_ids": [_cell(row, 0, "resource_id")],
                    "label": _cell(row, 1, "rname") or _cell(row, 0, "resource_id"),
                    "subscription_id": _cell(row, 2, "subscription_id"),
                    "confidence": "high",
                    "why": f"matched {kind} resource_id literal",
                }
        except Exception as exc:
            logger.debug("argus_l3: literal %s lookup failed: %s", table, exc)
            _rollback_to(cursor, sp)

    return None


def _resolve_ai_agents(
    cursor: Any,
    organization_id: int,
) -> list[dict]:
    """Return all AI-agent identities the org owns (identity_db_id +
    identity_id + display_name). Empty list if the table doesn't exist or no
    rows match.
    """
    sp = "argus_l3_ai_agents"
    if not _savepoint(cursor, sp):
        return []
    try:
        cursor.execute(
            """
            SELECT i.id, i.identity_id, i.display_name, ac.agent_identity_type
              FROM identities i
              JOIN agent_classifications ac ON ac.identity_db_id = i.id
             WHERE ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
               AND (%s IS NULL OR i.organization_id = %s)
            """,
            (organization_id, organization_id),
        )
        rows = cursor.fetchall()
        _release(cursor, sp)
        out = []
        for r in rows:
            out.append({
                "id":              _cell(r, 0, "id"),
                "identity_id":     _cell(r, 1, "identity_id"),
                "display_name":    _cell(r, 2, "display_name"),
                "agent_type":      _cell(r, 3, "agent_identity_type"),
            })
        return out
    except Exception as exc:
        logger.debug("argus_l3: ai-agent lookup failed: %s", exc)
        _rollback_to(cursor, sp)
        return []


def _detect_classification(q_low: str) -> Optional[str]:
    """Map a lowercase query to a canonical classification label, or None."""
    for needle, label in _CLASSIFICATION_KEYWORDS.items():
        if needle in q_low:
            return label
    return None


def _resolve_classified_resources(
    cursor: Any,
    organization_id: int,
    classification: str,
) -> list[dict]:
    """Return resources across all classified tables matching ``classification``.

    We hit each table inside its own savepoint so a missing column (older
    snapshots without classification fields) doesn't poison the txn.
    """
    out: list[dict] = []
    for table, kind in _CLASSIFIED_TABLES:
        sp = f"argus_l3_cls_{kind}"
        if not _savepoint(cursor, sp):
            continue
        try:
            name_col = "database_name" if table == "azure_sql_databases" else "name"
            cursor.execute(
                f"""
                SELECT resource_id, {name_col} AS rname, subscription_id,
                       data_classification
                  FROM {table}
                 WHERE data_classification = %s
                   AND (%s IS NULL OR organization_id = %s)
                """,
                (classification, organization_id, organization_id),
            )
            for r in cursor.fetchall():
                out.append({
                    "resource_id":     _cell(r, 0, "resource_id"),
                    "name":            _cell(r, 1, "rname"),
                    "subscription_id": _cell(r, 2, "subscription_id"),
                    "classification":  _cell(r, 3, "data_classification"),
                    "kind":            kind,
                })
            _release(cursor, sp)
        except Exception as exc:
            logger.debug("argus_l3: classified %s lookup failed: %s", table, exc)
            _rollback_to(cursor, sp)
    return out


def _detect_resource_type(q_low: str) -> tuple[Optional[str], Optional[str]]:
    """Return (resource_kind, table_name) when the query contains a resource
    type keyword. Longest keyword wins so "storage account" beats "storage".
    """
    best: tuple[Optional[str], Optional[str]] = (None, None)
    best_len = 0
    for needle, (kind, table) in _RESOURCE_TYPE_KEYWORDS.items():
        if needle in q_low and len(needle) > best_len:
            best = (kind, table)
            best_len = len(needle)
    return best


def _resolve_resources_in_table(
    cursor: Any,
    organization_id: int,
    table: str,
    resource_kind: str,
) -> list[dict]:
    """Return all resources in ``table`` belonging to the org."""
    sp = f"argus_l3_table_{resource_kind}"
    if not _savepoint(cursor, sp):
        return []
    try:
        name_col = "database_name" if table == "azure_sql_databases" else "name"
        cursor.execute(
            f"""
            SELECT resource_id, {name_col} AS rname, subscription_id
              FROM {table}
             WHERE (%s IS NULL OR organization_id = %s)
            """,
            (organization_id, organization_id),
        )
        rows = cursor.fetchall()
        _release(cursor, sp)
        out = []
        for r in rows:
            out.append({
                "resource_id":     _cell(r, 0, "resource_id"),
                "name":            _cell(r, 1, "rname"),
                "subscription_id": _cell(r, 2, "subscription_id"),
                "kind":            resource_kind,
            })
        return out
    except Exception as exc:
        logger.debug("argus_l3: resource lookup in %s failed: %s", table, exc)
        _rollback_to(cursor, sp)
        return []


def _resolve_substring(
    cursor: Any,
    organization_id: int,
    q: str,
) -> Optional[ResolvedEntity]:
    """Substring match against identities.display_name, resource names. Picks
    the first matching kind in priority order: identity → key vault → storage
    → sql database. Returns the (smallest) set of matches.

    We use ILIKE rather than full-text search — the catalog is small (tens of
    thousands of rows at most) and ILIKE is well-indexed via pg_trgm on most
    snapshots; the helper degrades gracefully when trigram is absent.
    """
    pattern = f"%{q}%"

    # Identities first — they're the most common "by-name" target.
    sp = "argus_l3_sub_ident"
    if _savepoint(cursor, sp):
        try:
            cursor.execute(
                """
                SELECT id, identity_id, display_name, identity_category
                  FROM identities
                 WHERE display_name ILIKE %s
                   AND (%s IS NULL OR organization_id = %s)
                 ORDER BY id DESC
                 LIMIT 25
                """,
                (pattern, organization_id, organization_id),
            )
            rows = cursor.fetchall()
            _release(cursor, sp)
            if rows:
                items = [{
                    "id": _cell(r, 0, "id"),
                    "identity_id": _cell(r, 1, "identity_id"),
                    "display_name": _cell(r, 2, "display_name"),
                    "category": _cell(r, 3, "identity_category"),
                } for r in rows]
                # If the substring picks exactly one identity, it's a
                # high-quality match; otherwise medium.
                conf = "high" if len(items) == 1 else "medium"
                return {
                    "kind": "identity",
                    "id": [i["identity_id"] for i in items] if len(items) > 1 else items[0]["identity_id"],
                    "identity_db_ids": [i["id"] for i in items],
                    "identity_db_id": items[0]["id"] if len(items) == 1 else None,
                    "label": items[0]["display_name"] if len(items) == 1 else f"{len(items)} identities matching '{q}'",
                    "items": items,
                    "confidence": conf,
                    "why": f"matched display_name substring '{q}' on {len(items)} identit{'y' if len(items) == 1 else 'ies'}",
                }
        except Exception as exc:
            logger.debug("argus_l3: substring identity lookup failed: %s", exc)
            _rollback_to(cursor, sp)

    # Resources next — try each table, return on first hit.
    for table, kind in (
        ("azure_key_vaults",       "key_vault"),
        ("azure_storage_accounts", "storage_account"),
        ("azure_sql_databases",    "sql_database"),
    ):
        sp = f"argus_l3_sub_{kind}"
        if not _savepoint(cursor, sp):
            continue
        try:
            name_col = "database_name" if table == "azure_sql_databases" else "name"
            cursor.execute(
                f"""
                SELECT resource_id, {name_col} AS rname, subscription_id
                  FROM {table}
                 WHERE {name_col} ILIKE %s
                   AND (%s IS NULL OR organization_id = %s)
                 LIMIT 25
                """,
                (pattern, organization_id, organization_id),
            )
            rows = cursor.fetchall()
            _release(cursor, sp)
            if rows:
                items = [{
                    "resource_id":     _cell(r, 0, "resource_id"),
                    "name":            _cell(r, 1, "rname"),
                    "subscription_id": _cell(r, 2, "subscription_id"),
                    "kind":            kind,
                } for r in rows]
                conf = "high" if len(items) == 1 else "medium"
                return {
                    "kind": "resource",
                    "resource_kind": kind,
                    "id": [i["resource_id"] for i in items] if len(items) > 1 else items[0]["resource_id"],
                    "resource_ids": [i["resource_id"] for i in items],
                    "label": items[0]["name"] if len(items) == 1 else f"{len(items)} {kind}s matching '{q}'",
                    "items": items,
                    "confidence": conf,
                    "why": f"matched {kind} name substring '{q}'",
                }
        except Exception as exc:
            logger.debug("argus_l3: substring %s lookup failed: %s", table, exc)
            _rollback_to(cursor, sp)

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Persisted-path lookup
# ─────────────────────────────────────────────────────────────────────────────

# Columns we always return on the matched attack_paths row. We avoid SELECT *
# because some snapshots add columns that aren't safe to JSON-serialize raw.
_PATH_COLUMNS = (
    "id, path_id, source_entity_id, source_entity_name, source_entity_type, "
    "path_type, severity, risk_score, description, narrative, impact, "
    "path_length, affected_resource_count, first_detected_at, last_detected_at, "
    "occurrence_count, target_resource_id, target_resource_type, path_nodes, "
    "organization_id, discovery_run_id"
)


def _source_ids_from_resolved(resolved: ResolvedEntity) -> list[str]:
    """Return identity_id literals contained in a resolved source entity, or
    [] when the source isn't an identity (resource-as-source means we'll
    constrain on target instead).
    """
    if not resolved or resolved.get("kind") != "identity":
        return []
    ident = resolved.get("id")
    if isinstance(ident, list):
        return [i for i in ident if i]
    if isinstance(ident, str):
        return [ident]
    return []


def _target_ids_from_resolved(resolved: ResolvedEntity) -> list[str]:
    """Return target_resource_id literals contained in a resolved target."""
    if not resolved:
        return []
    kind = resolved.get("kind")
    if kind == "resource":
        rids = resolved.get("resource_ids") or []
        if not rids and isinstance(resolved.get("id"), str):
            rids = [resolved["id"]]
        return [r for r in rids if r]
    if kind == "class":
        return [r for r in (resolved.get("resource_ids") or []) if r]
    if kind == "subscription":
        # Subscription targets match any path whose target_resource_id starts
        # with /subscriptions/<uuid>/ — handled via LIKE in _find_persisted.
        return []
    return []


def _find_persisted(
    cursor: Any,
    organization_id: int,
    source: Optional[ResolvedEntity],
    target: Optional[ResolvedEntity],
) -> Optional[dict]:
    """Look for the strongest attack_paths row matching the resolved entities.

    Strongest = ORDER BY severity (critical→low), risk_score DESC, last_detected DESC.
    Returns the row as a dict (with path_nodes already decoded) or None.
    """
    conditions: list[str] = []
    params: list[Any] = []

    # organization scope
    conditions.append("ap.organization_id = %s")
    params.append(organization_id)

    src_ids = _source_ids_from_resolved(source)
    if src_ids:
        conditions.append("ap.source_entity_id = ANY(%s)")
        params.append(src_ids)

    tgt_ids = _target_ids_from_resolved(target)
    if tgt_ids:
        conditions.append("ap.target_resource_id = ANY(%s)")
        params.append(tgt_ids)

    # subscription target — LIKE match because attack_paths stores the full
    # resource_id, not the bare subscription GUID.
    if target and target.get("kind") == "subscription":
        sub_uuid = target.get("id")
        if sub_uuid:
            conditions.append(
                "(ap.target_resource_id ILIKE %s OR ap.source_entity_id ILIKE %s)"
            )
            like = f"%/subscriptions/{sub_uuid}%"
            params.extend([like, like])

    where = " AND ".join(conditions)
    sql = f"""
        SELECT {_PATH_COLUMNS}
          FROM attack_paths ap
         WHERE {where}
         ORDER BY
            CASE ap.severity
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                ELSE 5
            END,
            ap.risk_score DESC,
            ap.last_detected_at DESC
         LIMIT 1
    """

    sp = "argus_l3_find_persisted"
    if not _savepoint(cursor, sp):
        return None
    try:
        cursor.execute(sql, tuple(params))
        row = cursor.fetchone()
        _release(cursor, sp)
    except Exception as exc:
        logger.warning("argus_l3: persisted-path lookup failed: %s", exc)
        _rollback_to(cursor, sp)
        return None

    if row is None:
        return None

    out = _path_row_to_dict(row)
    return out


def _path_row_to_dict(row: Any) -> dict:
    """Convert an attack_paths row (tuple or dict cursor) into a JSON-safe dict.

    Mirrors the lightweight normalisation that handlers.get_attack_paths_list
    does: ISO-format timestamps, decode JSON-string path_nodes, stringify
    path_id UUID. We don't run role_metadata enrichment here — that's a UI
    concern handled by ``Database._format_attack_path_row``.
    """
    keys = (
        "id", "path_id", "source_entity_id", "source_entity_name",
        "source_entity_type", "path_type", "severity", "risk_score",
        "description", "narrative", "impact", "path_length",
        "affected_resource_count", "first_detected_at", "last_detected_at",
        "occurrence_count", "target_resource_id", "target_resource_type",
        "path_nodes", "organization_id", "discovery_run_id",
    )

    if isinstance(row, dict):
        out = {k: row.get(k) for k in keys}
    else:
        out = {k: (row[i] if i < len(row) else None) for i, k in enumerate(keys)}

    if out.get("path_id") is not None:
        out["path_id"] = str(out["path_id"])

    for ts in ("first_detected_at", "last_detected_at"):
        v = out.get(ts)
        if v is not None and hasattr(v, "isoformat"):
            out[ts] = v.isoformat()

    # path_nodes may come back as a JSON string when the row came through a
    # raw tuple cursor; normalise to list/dict.
    pn = out.get("path_nodes")
    if isinstance(pn, str):
        try:
            import json
            out["path_nodes"] = json.loads(pn)
        except Exception:
            out["path_nodes"] = []

    return out


# ─────────────────────────────────────────────────────────────────────────────
# Live fallback
# ─────────────────────────────────────────────────────────────────────────────

def _live_fallback(
    cursor: Any,
    organization_id: int,
    source: ResolvedEntity,
    target: Optional[ResolvedEntity],
) -> Optional[dict]:
    """Run :class:`AttackPathEngine.analyze` on the latest run, then pick the
    strongest path whose source matches ``source`` (and optionally whose
    target_resource_id matches ``target``).

    We don't persist the result — this is a read-only investigation. The
    returned dict has the same shape as ``_path_row_to_dict`` so the API
    response is uniform.
    """
    # Locate the latest completed discovery run for this org.
    sp = "argus_l3_latest_run"
    if not _savepoint(cursor, sp):
        return None
    try:
        cursor.execute(
            """
            SELECT MAX(id)
              FROM discovery_runs
             WHERE status IN ('completed', 'partial')
               AND organization_id = %s
            """,
            (organization_id,),
        )
        row = cursor.fetchone()
        _release(cursor, sp)
    except Exception as exc:
        logger.warning("argus_l3: latest-run lookup failed: %s", exc)
        _rollback_to(cursor, sp)
        return None

    run_id = _cell(row, 0, "max") if row is not None else None
    if not run_id:
        return None

    # Import inside the function to keep module-import cost low and avoid
    # circular imports through engines/__init__.py.
    try:
        from app.database import Database
        from app.engines.attack_path_engine import AttackPathEngine
    except Exception as exc:
        logger.warning("argus_l3: cannot import AttackPathEngine: %s", exc)
        return None

    # AttackPathEngine.analyze() expects a Database wrapper, not a bare
    # cursor — we build one against the same org context.
    try:
        db = Database(organization_id=organization_id)
    except Exception as exc:
        logger.warning("argus_l3: Database(organization_id=%s) failed: %s",
                       organization_id, exc)
        return None

    try:
        engine = AttackPathEngine(db)
        paths = engine.analyze(run_id) or []
    except Exception as exc:
        logger.warning("argus_l3: live analyze failed for run %s: %s",
                       run_id, exc)
        paths = []
    finally:
        try:
            db.close()
        except Exception:
            pass

    if not paths:
        return None

    src_ids = set(_source_ids_from_resolved(source))
    tgt_ids = set(_target_ids_from_resolved(target))

    def _matches(p: dict) -> bool:
        if src_ids and p.get("source_entity_id") not in src_ids:
            return False
        if tgt_ids:
            tri = p.get("target_resource_id") or ""
            if tri not in tgt_ids:
                return False
        if target and target.get("kind") == "subscription":
            sub_uuid = (target.get("id") or "").lower()
            if not sub_uuid:
                return False
            tri = (p.get("target_resource_id") or "").lower()
            sei = (p.get("source_entity_id") or "").lower()
            if f"/subscriptions/{sub_uuid}" not in tri and f"/subscriptions/{sub_uuid}" not in sei:
                return False
        return True

    matching = [p for p in paths if _matches(p)]
    if not matching:
        return None

    # Strongest = highest risk_score, then prefer 'critical' severity.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matching.sort(key=lambda p: (
        severity_rank.get((p.get("severity") or "").lower(), 9),
        -int(p.get("risk_score") or 0),
    ))
    best = matching[0]

    # AttackPathEngine returns the path dict already JSON-safe (no datetime
    # values — first/last_detected_at are stamped at persist time). We add
    # placeholders for shape parity with the persisted variant.
    best.setdefault("id", None)
    best.setdefault("path_id", None)
    best.setdefault("first_detected_at", None)
    best.setdefault("last_detected_at", None)
    best.setdefault("occurrence_count", 1)
    best.setdefault("organization_id", organization_id)
    best.setdefault("discovery_run_id", run_id)
    return best


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _confidence_floor(*labels: Optional[str]) -> str:
    """Return the weakest confidence among the supplied labels.

    'low' < 'medium' < 'high'; missing labels are treated as 'low'.
    """
    rank = {"low": 0, "medium": 1, "high": 2}
    score = 2
    for lab in labels:
        score = min(score, rank.get(lab or "low", 0))
    return ("low", "medium", "high")[score]


def investigate_attack_path(
    cursor: Any,
    organization_id: int,
    *,
    source_query: Optional[str],
    target_query: Optional[str],
    prefer_persisted: bool = True,
) -> Optional[dict]:
    """Resolve ``source_query`` / ``target_query`` to graph entities and return
    the strongest matching attack path.

    Args:
        cursor: Open DB cursor (tuple or RealDictCursor — both supported).
        organization_id: JWT org id; required for RLS scoping.
        source_query: Free-text descriptor for the path origin (e.g. ``"ai
            agent"``, ``"john.admin@contoso.com"``, ``"<uuid>"``). ``None``
            means "any source".
        target_query: Free-text descriptor for the path destination (e.g.
            ``"PHI"``, ``"subscription <uuid>"``, ``"keyvault prod-kv"``).
            ``None`` means "any target".
        prefer_persisted: When True (default) we only look at the persisted
            ``attack_paths`` table; if no row matches we return
            ``{found: False, ...}``. When False, we additionally run a live
            :class:`AttackPathEngine.analyze` for the latest completed run
            and select the strongest result — useful for "what-if" /
            on-demand investigations.

    Returns:
        Always returns a dict (never raises on bad input). Shape::

            {
              "found": bool,
              "path": { ... attack_paths row (path_nodes decoded) ... } | None,
              "source_resolved": ResolvedEntity | None,
              "target_resolved": ResolvedEntity | None,
              "resolution_confidence": "high" | "medium" | "low",
              "fallback_used": bool,
              "why": str,
            }
    """
    if organization_id is None:
        # The investigator must always know which tenant to scope to —
        # superadmin callers can pass a synthetic org_id.
        return {
            "found": False,
            "path": None,
            "source_resolved": None,
            "target_resolved": None,
            "resolution_confidence": "low",
            "fallback_used": False,
            "why": "organization_id is required for attack-path investigation",
        }

    if not source_query and not target_query:
        return {
            "found": False,
            "path": None,
            "source_resolved": None,
            "target_resolved": None,
            "resolution_confidence": "low",
            "fallback_used": False,
            "why": "at least one of source_query or target_query is required",
        }

    source_resolved = _resolve_query(cursor, organization_id, source_query) if source_query else None
    target_resolved = _resolve_query(cursor, organization_id, target_query) if target_query else None

    # If a query was supplied but didn't resolve to anything, bail with an
    # explicit reason — UI shows the empty state.
    unresolved_parts = []
    if source_query and source_resolved is None:
        unresolved_parts.append(f"source '{source_query}'")
    if target_query and target_resolved is None:
        unresolved_parts.append(f"target '{target_query}'")
    if unresolved_parts:
        return {
            "found": False,
            "path": None,
            "source_resolved": source_resolved,
            "target_resolved": target_resolved,
            "resolution_confidence": "low",
            "fallback_used": False,
            "why": "could not resolve " + " and ".join(unresolved_parts),
        }

    # ── Persisted lookup ─────────────────────────────────────────────────
    path = _find_persisted(cursor, organization_id, source_resolved, target_resolved)
    fallback_used = False

    # ── Live fallback (opt-in) ───────────────────────────────────────────
    if path is None and not prefer_persisted and source_resolved is not None:
        path = _live_fallback(cursor, organization_id, source_resolved, target_resolved)
        fallback_used = path is not None

    if path is None:
        src_label = source_resolved["label"] if source_resolved else "any source"
        tgt_label = target_resolved["label"] if target_resolved else "any target"
        return {
            "found": False,
            "path": None,
            "source_resolved": source_resolved,
            "target_resolved": target_resolved,
            "resolution_confidence": _confidence_floor(
                source_resolved.get("confidence") if source_resolved else None,
                target_resolved.get("confidence") if target_resolved else None,
            ),
            "fallback_used": False,
            "why": (
                f"resolved {src_label} → {tgt_label}, but no persisted attack path "
                f"connects them"
                + ("" if prefer_persisted else " (live fallback returned no matches)")
            ),
        }

    # ── Found ────────────────────────────────────────────────────────────
    src_label = source_resolved["label"] if source_resolved else "any source"
    tgt_label = target_resolved["label"] if target_resolved else "any target"
    why = (
        f"matched persisted attack path {src_label} → {tgt_label} "
        f"(path_type={path.get('path_type')}, severity={path.get('severity')}, "
        f"risk_score={path.get('risk_score')})"
    )
    if fallback_used:
        why = (
            f"no persisted path matched; live AttackPathEngine returned "
            f"{src_label} → {tgt_label} "
            f"(path_type={path.get('path_type')}, severity={path.get('severity')}, "
            f"risk_score={path.get('risk_score')})"
        )

    return {
        "found": True,
        "path": path,
        "source_resolved": source_resolved,
        "target_resolved": target_resolved,
        "resolution_confidence": _confidence_floor(
            source_resolved.get("confidence") if source_resolved else None,
            target_resolved.get("confidence") if target_resolved else None,
        ),
        "fallback_used": fallback_used,
        "why": why,
    }


__all__ = ["investigate_attack_path"]
