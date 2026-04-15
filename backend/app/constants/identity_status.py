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

# ── Display labels (for API responses / frontend) ────────────────

STATUS_DISPLAY = {
    STATUS_ACTIVE:   {'label': 'Active',   'color': '#22c55e'},
    STATUS_DISABLED: {'label': 'Disabled', 'color': '#ef4444'},
    STATUS_DELETED:  {'label': 'Deleted',  'color': '#6b7280'},
    STATUS_UNKNOWN:  {'label': 'Unknown',  'color': '#f59e0b'},
}
