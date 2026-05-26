"""
Identity Type Taxonomy — Single Source of Truth

Maps all known identity_type variants (PascalCase, mixed-case, legacy)
to the canonical identity_category values stored in the DB.

Usage:
    from app.constants.identity_types import normalize_identity_category

    category = normalize_identity_category(raw_type)
"""

# ── Canonical identity_category values (snake_case, lowercase) ──────

CAT_SERVICE_PRINCIPAL = 'service_principal'
CAT_MANAGED_IDENTITY_SYSTEM = 'managed_identity_system'
CAT_MANAGED_IDENTITY_USER = 'managed_identity_user'
CAT_HUMAN_USER = 'human_user'
CAT_GUEST = 'guest'

# ── Pill groupings (frontend tab predicates) ────────────────────────

HUMAN_CATEGORIES = frozenset({CAT_HUMAN_USER, CAT_GUEST})

NHI_CATEGORIES = frozenset({
    CAT_SERVICE_PRINCIPAL,
    CAT_MANAGED_IDENTITY_SYSTEM,
    CAT_MANAGED_IDENTITY_USER,
})

MANAGED_IDENTITY_CATEGORIES = frozenset({
    CAT_MANAGED_IDENTITY_SYSTEM,
    CAT_MANAGED_IDENTITY_USER,
})

ALL_CATEGORIES = HUMAN_CATEGORIES | NHI_CATEGORIES

# ── Tab → category set mapping (Identity Explorer tabs) ──────────
# Reused by both frontend pre-filter and backend ?tab= parameter.

TAB_CATEGORIES = {
    'humans': HUMAN_CATEGORIES,
    'nhi': NHI_CATEGORIES,
    # 'all' / 'ai-agents' / 'privileged' / 'graph' — no category filter
}

# ── Raw value → canonical category mapping ──────────────────────────
# Covers: Graph API casing, legacy DB values, frontend URL params,
# CISO Dashboard drill-through values.

_TYPE_ALIAS_MAP: dict[str, str] = {
    # Azure humans
    'user': CAT_HUMAN_USER,
    'human_user': CAT_HUMAN_USER,
    'member': CAT_HUMAN_USER,
    'human user': CAT_HUMAN_USER,
    'human': CAT_HUMAN_USER,
    # Azure guests (subset of humans)
    'guest': CAT_GUEST,
    'guest_user': CAT_GUEST,
    'b2b_user': CAT_GUEST,
    # Azure SPNs
    'service_principal': CAT_SERVICE_PRINCIPAL,
    'serviceprincipal': CAT_SERVICE_PRINCIPAL,
    'service principal': CAT_SERVICE_PRINCIPAL,
    'application': CAT_SERVICE_PRINCIPAL,
    'app': CAT_SERVICE_PRINCIPAL,
    # Azure managed identities
    'managed_identity_system': CAT_MANAGED_IDENTITY_SYSTEM,
    'managed_identity_user': CAT_MANAGED_IDENTITY_USER,
    'managedidentity': CAT_MANAGED_IDENTITY_USER,  # ambiguous — default to user-assigned
    'managed identity': CAT_MANAGED_IDENTITY_USER,
}


def normalize_identity_category(raw=None) -> str:
    """Normalize any raw identity type/category string to canonical form.

    Returns the canonical category or the original value lowered if unknown.
    """
    if not raw:
        return 'unknown'
    key = raw.strip().lower()
    return _TYPE_ALIAS_MAP.get(key, key)
