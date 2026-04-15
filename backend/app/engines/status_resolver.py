"""
Canonical Identity Status Resolver

SINGLE source of truth for identity status computation.
All code paths MUST use resolve_status() — never compute status inline.

Priority:
  1. deleted_at is set → 'deleted'
  2. enabled is False → 'disabled'
  3. enabled is True → 'active'
  4. status column fallback → 'active'/'disabled'/'deleted'
  5. None of the above → 'unknown'
"""


def resolve_status(identity_data: dict) -> str:
    """ONLY code path for identity status. Priority: deleted_at → enabled → status fallback."""
    if identity_data.get('deleted_at') is not None:
        return 'deleted'
    enabled = identity_data.get('enabled')
    if enabled is False:
        return 'disabled'
    if enabled is True:
        return 'active'
    status = identity_data.get('status', '')
    if status in ('active', 'disabled', 'deleted'):
        return status
    return 'unknown'


STATUS_DISPLAY = {
    'active':   {'label': 'Active',   'badge_class': 'bg-green-100 text-green-700'},
    'disabled': {'label': 'Disabled', 'badge_class': 'bg-red-100 text-red-700'},
    'deleted':  {'label': 'Deleted',  'badge_class': 'bg-gray-100 text-gray-500'},
    'unknown':  {'label': 'Unknown',  'badge_class': 'bg-yellow-100 text-yellow-700'},
}
