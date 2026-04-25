"""
FIX1B — Canonical Metric Query Definitions

Single source of truth for all dashboard metric WHERE clauses.
Both dashboard counts and drill-down lists MUST use these definitions.
No independent metric SQL is permitted elsewhere.

Usage:
    # Dashboard count:
    SELECT COUNT(*) FROM identities i WHERE <base_where> AND <metric_where>

    # Drill-down list:
    SELECT * FROM identities i WHERE <base_where> AND <metric_where> LIMIT/OFFSET
"""

# ── Base WHERE clause (all identity queries) ────────────────────────────────

BASE_IDENTITY_WHERE = """
    i.discovery_run_id = ANY(%(run_ids)s)
    AND NOT COALESCE(i.is_microsoft_system, false)
"""

HIDE_DELETED_WHERE = """
    AND i.deleted_at IS NULL
"""

# ── Metric-specific WHERE fragments ─────────────────────────────────────────
# Each is an AND clause appended to BASE_IDENTITY_WHERE.

METRIC_DORMANT = """
    AND i.activity_status IN ('stale', 'never_used')
    AND i.identity_category IN ('human_user', 'guest')
"""

METRIC_DORMANT_NHI = """
    AND i.activity_status IN ('stale', 'never_used')
    AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
"""

METRIC_DORMANT_HUMAN = """
    AND i.activity_status IN ('stale', 'never_used')
    AND i.identity_category = 'human_user'
"""

METRIC_PRIVILEGED = """
    AND COALESCE(i.privilege_tier, 'T3') IN ('T0', 'T1')
"""

METRIC_HIGH_RISK = """
    AND i.risk_level IN ('critical', 'high')
"""

METRIC_CRITICAL = """
    AND i.risk_level = 'critical'
"""

METRIC_OVER_PERMISSIONED = """
    AND (COALESCE(i.risk_score, 0) >= 70 OR i.privilege_tier = 'T0')
"""

# SSOT: governance_service.derive_governance_state() step 1 — owner_count==0 → Orphaned
# This SQL is the bulk-count approximation of the canonical Python derivation.
METRIC_UNOWNED_NHI = """
    AND (i.owner_count = 0 OR i.owner_count IS NULL)
    AND COALESCE(i.identity_category, '') NOT IN ('human_user', 'guest', 'microsoft_internal')
"""

METRIC_CREDENTIAL_EXPIRED = """
    AND i.credential_expiration IS NOT NULL
    AND i.credential_expiration < NOW()
"""

METRIC_CREDENTIAL_EXPIRING = """
    AND i.credential_expiration IS NOT NULL
    AND i.credential_expiration >= NOW()
    AND i.credential_expiration < NOW() + INTERVAL '30 days'
"""

METRIC_CREDENTIAL_HEALTHY = """
    AND i.credential_expiration IS NOT NULL
    AND i.credential_expiration >= NOW() + INTERVAL '30 days'
"""

METRIC_NO_CREDENTIALS = """
    AND (i.credential_count = 0 OR i.credential_count IS NULL)
"""

METRIC_GHOST = """
    AND (i.enabled = FALSE OR i.deleted_at IS NOT NULL)
    AND (
        EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
        OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
    )
"""

METRIC_DORMANT_PRIVILEGED = """
    AND i.identity_category IN ('human_user', 'guest')
    AND (
        -- Tier 1: privilege_tier classified (log-dependent)
        (i.privilege_tier IN ('T0', 'T1')
         AND (i.activity_status IN ('stale', 'never_used')
              OR i.days_since_last_signin > 90))
        OR
        -- Tier 2: privilege_tier NULL (log-independent fallback) —
        -- detect privilege via Owner/Contributor/UAA RBAC roles
        -- or any Entra directory role assignment.
        (i.privilege_tier IS NULL
         AND (i.activity_status IN ('stale', 'never_used')
              OR i.days_since_last_signin > 90)
         AND (
           EXISTS (SELECT 1 FROM role_assignments ra
                   WHERE ra.identity_db_id = i.id
                     AND ra.role_name IN (
                       'Owner', 'Contributor',
                       'User Access Administrator',
                       'Global Administrator'))
           OR EXISTS (SELECT 1 FROM entra_role_assignments era
                      WHERE era.identity_db_id = i.id)
         ))
    )
"""

METRIC_SA_CATEGORIES = "('service_principal', 'managed_identity_system', 'managed_identity_user')"

METRIC_SA_BASE = f"""
    AND i.identity_category IN {METRIC_SA_CATEGORIES}
"""

# ── Registry: maps metric name → WHERE fragment ─────────────────────────────
# Used by both dashboard counts and drill-down filters.

METRIC_REGISTRY = {
    'dormant': METRIC_DORMANT,
    'dormant_nhi': METRIC_DORMANT_NHI,
    'dormant_human': METRIC_DORMANT_HUMAN,
    'privileged': METRIC_PRIVILEGED,
    'high_risk': METRIC_HIGH_RISK,
    'critical': METRIC_CRITICAL,
    'over_permissioned': METRIC_OVER_PERMISSIONED,
    'unowned_nhi': METRIC_UNOWNED_NHI,
    'credential_expired': METRIC_CREDENTIAL_EXPIRED,
    'credential_expiring': METRIC_CREDENTIAL_EXPIRING,
    'credential_healthy': METRIC_CREDENTIAL_HEALTHY,
    'no_credentials': METRIC_NO_CREDENTIALS,
    'ghost': METRIC_GHOST,
    'dormant_privileged': METRIC_DORMANT_PRIVILEGED,
}


def get_metric_count_sql(metric_name: str) -> str:
    """Return full COUNT SQL for a registered metric.

    Usage:
        sql = get_metric_count_sql('dormant')
        cursor.execute(sql, {'run_ids': run_ids})
        count = cursor.fetchone()[0]
    """
    fragment = METRIC_REGISTRY.get(metric_name)
    if not fragment:
        raise ValueError(f"Unknown metric: {metric_name}")
    return f"""
        SELECT COUNT(*)
        FROM identities i
        WHERE {BASE_IDENTITY_WHERE}
        {fragment}
    """


def get_metric_where(metric_name: str) -> str:
    """Return the WHERE fragment for a registered metric (for appending to existing queries)."""
    fragment = METRIC_REGISTRY.get(metric_name)
    if not fragment:
        raise ValueError(f"Unknown metric: {metric_name}")
    return fragment


# ── Snapshot selection alias ─────────────────────────────────────────────────
# Canonical name for the snapshot resolver. All metric endpoints must use this.
# Implementation delegates to _latest_run_ids in handlers.py.

def get_latest_snapshot_ids(cursor, org_id=None, connection_id=None):
    """Canonical snapshot resolver — delegates to _latest_run_ids.

    This is the ONLY function that should determine which discovery run(s)
    represent the 'current' snapshot. No endpoint may compute this independently.
    """
    from app.api.handlers import _latest_run_ids
    return _latest_run_ids(cursor, org_id, connection_id)
