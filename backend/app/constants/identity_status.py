"""
SSOT Identity Status Constants

Canonical status values used across the entire backend.
All SQL filters, API responses, and serialization MUST use these constants.
The actual status is resolved by engines/status_resolver.py from the `enabled`
boolean column — never from the legacy `status` TEXT column.

Schema truth:
  - identities.enabled  BOOLEAN  (SSOT for active/disabled)
  - identities.deleted_at  TIMESTAMPTZ  (SSOT for deleted)
  - identities.status  TEXT  (LEGACY — do NOT query directly)
"""

# ── Canonical status values ──────────────────────────────────────

STATUS_ACTIVE = 'active'
STATUS_DISABLED = 'disabled'
STATUS_DELETED = 'deleted'
STATUS_UNKNOWN = 'unknown'

ALL_STATUSES = (STATUS_ACTIVE, STATUS_DISABLED, STATUS_DELETED, STATUS_UNKNOWN)

# ── SQL filter fragments (parameterised — no string interpolation) ──

STATUS_SQL = {
    STATUS_ACTIVE: "COALESCE(i.enabled, TRUE) = TRUE",
    STATUS_DISABLED: "i.enabled = FALSE",
    STATUS_DELETED: "i.deleted_at IS NOT NULL",
}

# ── Activity status mapping ──────────────────────────────────────

# "dormant_strict" is a composite filter the frontend sends via URL params.
# It maps to the union of these DB-level activity_status values.
DORMANT_STRICT_STATUSES = ('stale', 'never_used')

# ── Microsoft first-party identification ──────────────────────────
# Used to exclude Microsoft-managed SPNs from orphan classification.
# These identities have no owner by design — they are owned by Microsoft.

MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
MICROSOFT_CORP_TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47"

MICROSOFT_FIRST_PARTY_OWNER_IDS = frozenset({
    MICROSOFT_TENANT_ID,
    MICROSOFT_CORP_TENANT_ID,
})

MICROSOFT_FIRST_PARTY_NAME_PREFIXES = ("Microsoft ", "Agent (", "Windows ")

# ── Display labels (for API responses / frontend) ────────────────

STATUS_DISPLAY = {
    STATUS_ACTIVE:   {'label': 'Active',   'color': '#22c55e'},
    STATUS_DISABLED: {'label': 'Disabled', 'color': '#ef4444'},
    STATUS_DELETED:  {'label': 'Deleted',  'color': '#6b7280'},
    STATUS_UNKNOWN:  {'label': 'Unknown',  'color': '#f59e0b'},
}
