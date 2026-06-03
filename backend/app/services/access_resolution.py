"""
Single source of truth for "does this identity have access to this resource,
and at what level?"

Historically, scope-matching logic was reimplemented ad-hoc in:
  - handlers.py:get_sensitive_access_for_identity
  - blast_radius_engine._load_resources / _enumerate_reachable
  - constants/ai_risk.py:detect_signals

Each implementation had subtle differences (e.g. substring vs. prefix match,
case handling, root-scope coverage, nested resource type handling). This
module is the SSOT — all callers should funnel through `resolve_agent_resource_access`
or `resolve_agent_resource_access_batch`.

Design:
  - Pure scope logic (`_scope_covers`) is testable without a DB.
  - Role → access_level derivation uses `constants/role_metadata.py` first
    (canonical names / tiers), falls back to substring patterns for
    custom or non-catalogued roles.
  - Batch helper uses a single SQL query (no N+1).
"""
from __future__ import annotations

import logging
from typing import Any, Iterable, Literal, Optional, TypedDict

from ..constants.role_metadata import (
    Provider,
    detect_provider,
    get_role_metadata_auto,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Types
# ─────────────────────────────────────────────────────────────────────────────

AccessLevel = Literal["reader", "contributor", "owner"]


class AccessResult(TypedDict):
    access_level: AccessLevel
    role_name: str
    scope: str
    derivation_path: str  # human-readable explanation (e.g. "owner@subscription")


# ─────────────────────────────────────────────────────────────────────────────
# Access-level ordering (used to pick the STRONGEST result)
# ─────────────────────────────────────────────────────────────────────────────

_LEVEL_RANK: dict[str, int] = {
    "reader":      1,
    "contributor": 2,
    "owner":       3,
}

# Derivation specificity — when access levels tie, prefer the more-specific
# scope (resource > resource_group > subscription > root).
_PATH_RANK: dict[str, int] = {
    "exact":          5,
    "nested":         4,
    "resource_group": 3,
    "subscription":   2,
    "management_group": 1,
    "root":           0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Role → access_level (no hardcoded role list beyond fallback substrings)
# ─────────────────────────────────────────────────────────────────────────────

def _level_from_role(role_name: str) -> AccessLevel:
    """Derive owner / contributor / reader from a role name.

    Strategy:
      1. Look up role_metadata (canonical names, tiers).
         - Owner / User Access Administrator / Role Based Access Control
           Administrator → owner (they can grant roles).
         - Anything ending in "Contributor" (or AWS *FullAccess /
           GCP roles/editor / roles/owner) → contributor.
         - Anything ending in "Reader" / containing "ReadOnly" /
           roles/viewer / Security Reader → reader.
      2. Fallback substring patterns for roles not in the catalogue.

    The Provider / tier from role_metadata is the *first* check; substring
    matching is the safety net for custom roles or new built-ins.
    """
    if not role_name:
        return "reader"

    name = role_name.strip()
    name_lower = name.lower()

    # 1) Try role_metadata first — gives canonical name + provider context
    meta = get_role_metadata_auto(name)
    provider = meta.get("provider", Provider.UNKNOWN.value)
    canonical = (meta.get("name") or name)
    canonical_lower = canonical.lower()

    # Owner-equivalent (can-grant-roles or full-control)
    # Azure RBAC: "Owner", "User Access Administrator", "Role Based Access Control Administrator"
    # AWS: "AdministratorAccess", "IAMFullAccess"
    # GCP: "roles/owner", "roles/iam.securityAdmin", "roles/iam.serviceAccountKeyAdmin"
    if provider == Provider.AZURE_RBAC.value:
        if canonical_lower in ("owner", "user access administrator",
                                "role based access control administrator"):
            return "owner"
        if canonical_lower.endswith("contributor") or "administrator" in canonical_lower:
            return "contributor"
        if canonical_lower.endswith("reader") or "secrets user" in canonical_lower:
            return "reader"
    elif provider == Provider.AWS_IAM.value:
        if canonical in ("AdministratorAccess", "IAMFullAccess", "AWSOrganizationsFullAccess"):
            return "owner"
        if "fullaccess" in canonical_lower or "poweruser" in canonical_lower:
            return "contributor"
        if "readonly" in canonical_lower or "audit" in canonical_lower:
            return "reader"
    elif provider == Provider.GCP_IAM.value:
        if canonical_lower in ("roles/owner", "roles/iam.securityadmin",
                                "roles/iam.serviceaccountkeyadmin",
                                "roles/iam.serviceaccountadmin",
                                "roles/iam.serviceaccounttokencreator"):
            return "owner"
        if canonical_lower == "roles/editor" or canonical_lower.endswith(".admin"):
            return "contributor"
        if canonical_lower == "roles/viewer" or ".viewer" in canonical_lower:
            return "reader"

    # 2) Fallback substring patterns (custom roles, new built-ins)
    if name_lower in ("owner", "user access administrator",
                       "role based access control administrator"):
        return "owner"
    if "owner" in name_lower and name_lower != "data owner":
        # "Storage Blob Data Owner" still grants effective full control on data
        return "owner" if name_lower == "owner" else "contributor"
    if (name_lower.endswith("contributor")
            or name_lower.endswith("fullaccess")
            or "administrator" in name_lower
            or "officer" in name_lower
            or name_lower.endswith("editor")
            or name_lower.endswith(".admin")):
        return "contributor"
    if (name_lower.endswith("reader")
            or "readonly" in name_lower
            or name_lower.endswith("viewer")
            or "secrets user" in name_lower
            or name_lower == "reader"):
        return "reader"

    # Default to reader for unknown roles (safe — under-reports access vs.
    # over-reports). Callers can override if they need stricter handling.
    return "reader"


# ─────────────────────────────────────────────────────────────────────────────
# Pure scope-matching (testable without DB)
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(s: Optional[str]) -> str:
    """Normalize an ARM ID / scope for comparison.

    - Lowercase
    - Strip trailing slash
    - Collapse leading slashes (always exactly one, except for root `/`)
    """
    if not s:
        return ""
    out = s.strip().lower()
    if not out:
        return ""
    if out == "/":
        return "/"
    # Strip trailing slash
    while len(out) > 1 and out.endswith("/"):
        out = out[:-1]
    # Ensure exactly one leading slash for ARM-style IDs
    if out.startswith("/"):
        while out.startswith("//"):
            out = out[1:]
    return out


def _scope_covers(scope: Optional[str], resource_id: Optional[str]) -> bool:
    """Does `scope` cover `resource_id` (i.e. would an RBAC assignment at
    `scope` grant access to a resource with ID `resource_id`)?

    Pure function — no DB. Handles:
      - Exact match
      - Root scope ('/')
      - Management group scope ('/providers/Microsoft.Management/managementGroups/...')
        (treated as "covers anything"; caller should filter by tenant)
      - Subscription scope ('/subscriptions/<id>')
      - Resource group scope ('/subscriptions/<id>/resourceGroups/<rg>')
      - Direct resource and nested resource types (Microsoft.Sql/servers/X/databases/Y)
    """
    if not scope or not resource_id:
        return False

    s = _normalize(scope)
    r = _normalize(resource_id)

    if not s or not r:
        return False

    # 1) Exact match
    if s == r:
        return True

    # 2) Root
    if s == "/":
        return True

    # 3) Management group — covers everything below. (Note: in practice
    # cross-tenant filtering happens upstream via discovery_run_id.)
    if s.startswith("/providers/microsoft.management/managementgroups/"):
        return True

    # 4) Prefix-as-path: `r` must start with `s + "/"`.
    # This handles subscription / resource_group / resource / nested-type
    # all correctly because ARM IDs are hierarchical paths.
    if r.startswith(s + "/"):
        return True

    return False


def _derivation_for(scope: Optional[str], resource_id: Optional[str]) -> str:
    """Return a derivation_path label for a scope→resource match.

    Returns one of: 'exact', 'nested', 'resource_group', 'subscription',
    'management_group', 'root', or '' (no match).
    """
    if not scope or not resource_id:
        return ""

    s = _normalize(scope)
    r = _normalize(resource_id)

    if not s or not r:
        return ""

    if s == r:
        return "exact"
    if s == "/":
        return "root"
    if s.startswith("/providers/microsoft.management/managementgroups/"):
        return "management_group"

    if not r.startswith(s + "/"):
        return ""

    # Distinguish subscription vs. resource_group vs. resource (nested type)
    # /subscriptions/<sub>                                  → 2 segments
    # /subscriptions/<sub>/resourceGroups/<rg>              → 4 segments
    # /subscriptions/<sub>/resourceGroups/<rg>/providers/.. → resource
    parts = [p for p in s.split("/") if p]
    if len(parts) == 2 and parts[0] == "subscriptions":
        return "subscription"
    if len(parts) == 4 and parts[0] == "subscriptions" and parts[2] == "resourcegroups":
        return "resource_group"
    # Anything deeper is a (parent) resource scope covering a nested child
    return "nested"


# ─────────────────────────────────────────────────────────────────────────────
# Pick the "strongest" result when multiple assignments match
# ─────────────────────────────────────────────────────────────────────────────

def _pick_strongest(candidates: list[AccessResult]) -> Optional[AccessResult]:
    """Choose the strongest access result.

    Primary key:   access_level rank (owner > contributor > reader)
    Tie-breaker:   derivation specificity (exact > nested > rg > sub > mg > root)
    Final tie:     first one (stable)
    """
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda c: (
            _LEVEL_RANK.get(c["access_level"], 0),
            _PATH_RANK.get(c["derivation_path"], 0),
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Single-identity / single-resource lookup
# ─────────────────────────────────────────────────────────────────────────────

def resolve_agent_resource_access(
    cursor: Any,
    identity_db_id: int,
    resource_id: str,
) -> Optional[AccessResult]:
    """Return the STRONGEST access this identity has to `resource_id`, or None
    if it has no access.

    `cursor` is any DB cursor returning rows as dicts or sequences (the only
    columns used are role_name, scope). Used by:
      - Sensitive-access endpoints
      - Blast radius engine spot-checks
      - AI agent signal detection
    """
    if not identity_db_id or not resource_id:
        return None

    try:
        cursor.execute(
            """
            SELECT role_name, scope
            FROM role_assignments
            WHERE identity_db_id = %s
            """,
            (identity_db_id,),
        )
        rows = cursor.fetchall()
    except Exception as exc:  # pragma: no cover - DB failure
        logger.warning("resolve_agent_resource_access query failed: %s", exc)
        return None

    candidates: list[AccessResult] = []
    for row in rows:
        role_name, scope = _extract_role_scope(row)
        if not _scope_covers(scope, resource_id):
            continue
        candidates.append({
            "access_level":    _level_from_role(role_name),
            "role_name":       role_name,
            "scope":           scope,
            "derivation_path": _derivation_for(scope, resource_id),
        })

    return _pick_strongest(candidates)


# ─────────────────────────────────────────────────────────────────────────────
# Batch helper — single SQL query, no N+1
# ─────────────────────────────────────────────────────────────────────────────

def resolve_agent_resource_access_batch(
    cursor: Any,
    identity_db_ids: Iterable[int],
    resource_ids: Iterable[str],
) -> dict[tuple[int, str], AccessResult]:
    """Resolve access for the cross-product of identities × resources in one
    SQL round-trip.

    Returns a sparse dict keyed by `(identity_db_id, resource_id)` — entries
    are present only when the identity has access; absence means no access.
    """
    ident_list = [int(i) for i in identity_db_ids if i is not None]
    res_list = [r for r in resource_ids if r]

    if not ident_list or not res_list:
        return {}

    try:
        cursor.execute(
            """
            SELECT identity_db_id, role_name, scope
            FROM role_assignments
            WHERE identity_db_id = ANY(%s)
            """,
            (ident_list,),
        )
        rows = cursor.fetchall()
    except Exception as exc:  # pragma: no cover
        logger.warning("resolve_agent_resource_access_batch query failed: %s", exc)
        return {}

    # Group rows by identity for in-Python matching against the resource list.
    # (Doing the scope match in SQL would require a stored function or LATERAL
    # join; in-Python is fast enough for typical fan-out and keeps the matching
    # logic in one place.)
    by_ident: dict[int, list[tuple[str, str]]] = {}
    for row in rows:
        ident, role_name, scope = _extract_ident_role_scope(row)
        if ident is None:
            continue
        by_ident.setdefault(ident, []).append((role_name, scope))

    result: dict[tuple[int, str], AccessResult] = {}
    for ident_id in ident_list:
        ras = by_ident.get(ident_id, [])
        if not ras:
            continue
        for res_id in res_list:
            candidates: list[AccessResult] = []
            for role_name, scope in ras:
                if not _scope_covers(scope, res_id):
                    continue
                candidates.append({
                    "access_level":    _level_from_role(role_name),
                    "role_name":       role_name,
                    "scope":           scope,
                    "derivation_path": _derivation_for(scope, res_id),
                })
            best = _pick_strongest(candidates)
            if best is not None:
                result[(ident_id, res_id)] = best

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Row-extraction helpers — tolerate dict, sequence, or DictRow
# ─────────────────────────────────────────────────────────────────────────────

def _extract_role_scope(row: Any) -> tuple[str, str]:
    """Pull (role_name, scope) from a 2-column DB row."""
    if row is None:
        return "", ""
    if isinstance(row, dict):
        return (row.get("role_name") or "", row.get("scope") or "")
    # Sequence-like (tuple, list, psycopg2 row)
    try:
        return ((row[0] or ""), (row[1] or ""))
    except (IndexError, TypeError, KeyError):
        return "", ""


def _extract_ident_role_scope(row: Any) -> tuple[Optional[int], str, str]:
    """Pull (identity_db_id, role_name, scope) from a 3-column DB row."""
    if row is None:
        return None, "", ""
    if isinstance(row, dict):
        ident = row.get("identity_db_id")
        return (
            int(ident) if ident is not None else None,
            row.get("role_name") or "",
            row.get("scope") or "",
        )
    try:
        ident = row[0]
        return (
            int(ident) if ident is not None else None,
            row[1] or "",
            row[2] or "",
        )
    except (IndexError, TypeError, KeyError, ValueError):
        return None, "", ""


# ─────────────────────────────────────────────────────────────────────────────
# Public exports (for callers that need the pure helpers in tests or
# specialized matching)
# ─────────────────────────────────────────────────────────────────────────────

__all__ = [
    "AccessLevel",
    "AccessResult",
    "resolve_agent_resource_access",
    "resolve_agent_resource_access_batch",
    "_scope_covers",
    "_derivation_for",
    "_level_from_role",
    "_normalize",
]
