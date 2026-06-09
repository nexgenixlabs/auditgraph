"""
Entra Directory Role Last-Used Inference (Feature E Phase 2 / AG-FEATURE-E-P2)

Attributes auditLogs/directoryAudits events to specific directory role
assignments via CATEGORIES_REQUIRING(role) — a mapping from each
directory role to the audit-log categories that role's permissions
gate.

When a user U has directory role R, and an audit-log event with
initiatedBy.user.id = U.id has category in CATEGORIES_REQUIRING(R),
we attribute that event to U's R assignment as evidence of activity.

Moat compliance (see spec_checklist_agentless_readonly):
  ✓ Agentless: Graph API only
  ✓ Read-only: AuditLog.Read.All + RoleManagement.Read.Directory
  ✓ Architecture-derived: assignment IS the architecture; logs enrich.
    Tenants without P2 land in inference_confidence='unknown' with
    activity buckets NULL — surfaced honestly, not fabricated.

PATENT-ADJACENT: this CATEGORIES_REQUIRING mapping IS the moat. The
naive approach attributes ALL audit events for a user to ALL their
roles (false positives); the cross-product attribution distinguishes
which role is doing the work. No competitor surfaces per-directory-role
last-used inference today.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────
# CATEGORIES_REQUIRING — the cross-product moat
#
# Maps each directory role to the auditLogs/directoryAudits categories
# that the role's permissions gate. Derived from Microsoft docs for
# each role's permission set.
#
# Sources cited per role:
#   - https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
#   - Audit log categories: https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs
#
# 8 most common directory roles in v1. Extend as customers surface gaps.
# ─────────────────────────────────────────────────────────────────────────

# Audit log category strings as they appear in /auditLogs/directoryAudits
# Each value is the literal `category` field on the audit event.
ALL_CATEGORIES = {
    'UserManagement', 'GroupManagement', 'ApplicationManagement', 'Policy',
    'DeviceManagement', 'DirectoryManagement', 'Authentication',
    'Authorization', 'AuthorizationPolicy', 'RoleManagement', 'Other',
    'ResourceManagement', 'Label', 'Identity Protection', 'IdentityProtection',
    'B2C', 'ConditionalAccess',
}

CATEGORIES_REQUIRING: dict[str, set[str]] = {
    # Global Administrator — broadest. Any category counts.
    'Global Administrator': ALL_CATEGORIES,

    # Privileged Role Administrator — manages role assignments + PIM
    'Privileged Role Administrator': {
        'RoleManagement', 'DirectoryManagement', 'Policy',
    },

    # User Administrator — manage users, groups, password resets
    'User Administrator': {
        'UserManagement', 'GroupManagement', 'Authentication',
    },

    # Application Administrator — register apps, manage SPNs
    'Application Administrator': {
        'ApplicationManagement', 'Authorization', 'AuthorizationPolicy',
    },

    # Cloud Application Administrator — like ApplicationAdmin but no on-prem
    'Cloud Application Administrator': {
        'ApplicationManagement', 'Authorization',
    },

    # Conditional Access Administrator — CA + named locations + named policies
    'Conditional Access Administrator': {
        'Policy', 'ConditionalAccess', 'AuthorizationPolicy',
    },

    # Security Administrator — read security alerts + manage CA/Identity Protection
    'Security Administrator': {
        'Policy', 'IdentityProtection', 'Identity Protection',
        'ConditionalAccess', 'RoleManagement',
    },

    # Billing Administrator — purchases + subscriptions. Audit-log signature
    # is thin; we use 'Other' as a baseline because billing changes typically
    # land there or in ResourceManagement
    'Billing Administrator': {
        'Other', 'ResourceManagement',
    },
}


# ─────────────────────────────────────────────────────────────────────────
# Bucketing
# ─────────────────────────────────────────────────────────────────────────

def _activity_bucket(activities_30d: int, activities_90d: int) -> str:
    """Bucket the activity volume — same vocabulary the UI uses."""
    if activities_30d >= 20:                       return 'daily'        # 20+ in 30d ≈ ~daily
    if activities_30d >= 5:                        return 'weekly'       # 5-19 in 30d ≈ weekly
    if activities_90d >= 3:                        return 'monthly'      # 3+ in 90d ≈ monthly
    if activities_90d >= 1:                        return 'rare'         # rare cadence
    return 'dormant'                                                      # zero observed activity


def _dormancy_band(days_since_last: Optional[int]) -> str:
    """Risk band derived from days-since-last activity."""
    if days_since_last is None:                    return 'unknown'
    if days_since_last >= 90:                      return 'high'
    if days_since_last >= 30:                      return 'medium'
    return 'low'


# ─────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────

def compute_entra_role_activity(db, org_id: int,
                                  dormancy_filter: Optional[str] = None
                                  ) -> dict[str, Any]:
    """Org-wide Entra directory role activity rollup.

    Returns:
      {
        'rows':    [...per-(identity, role) records...],
        'findings':[...dormant_directory_role_assignment findings...],
        'summary': {
            'total_assignments': N,
            'by_bucket': {daily: N, weekly: N, ...},
            'by_dormancy': {high: N, medium: N, low: N, unknown: N},
            'total_findings': N,
        },
        'computed_at': ISO,
      }
    """
    now = datetime.now(timezone.utc)
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT
              a.identity_db_id, a.identity_id, i.display_name,
              i.identity_category,
              a.role_name, a.role_template_id,
              a.last_action_at, a.days_since_last_action,
              a.activities_30d, a.activities_90d,
              a.activity_bucket, a.dormancy_band,
              a.inferred_from, a.inference_confidence
            FROM entra_role_activity a
            JOIN identities i ON i.id = a.identity_db_id
            WHERE a.organization_id = %s
              AND i.deleted_at IS NULL
            ORDER BY
              CASE a.dormancy_band
                WHEN 'high' THEN 0 WHEN 'medium' THEN 1
                WHEN 'low'  THEN 2 ELSE 3
              END,
              a.days_since_last_action DESC NULLS LAST,
              i.display_name
        """, (org_id,))
        rows_raw = cursor.fetchall()
    finally:
        cursor.close()

    rows_out: list[dict] = []
    findings_out: list[dict] = []
    by_bucket: dict[str, int] = defaultdict(int)
    by_dormancy: dict[str, int] = defaultdict(int)

    for row in rows_raw:
        (identity_db_id, identity_id, display_name, identity_category,
         role_name, role_template_id, last_action_at, days_since_last_action,
         activities_30d, activities_90d, activity_bucket, dormancy_band,
         inferred_from, inference_confidence) = row

        if dormancy_filter and dormancy_band != dormancy_filter:
            continue

        rows_out.append({
            'identity_db_id':         identity_db_id,
            'identity_id':            identity_id,
            'display_name':           display_name,
            'identity_category':      identity_category,
            'role_name':              role_name,
            'role_template_id':       role_template_id,
            'last_action_at':         last_action_at.isoformat() if last_action_at else None,
            'days_since_last_action': days_since_last_action,
            'activities_30d':         activities_30d,
            'activities_90d':         activities_90d,
            'activity_bucket':        activity_bucket,
            'dormancy_band':          dormancy_band,
            'inferred_from':          inferred_from,
            'inference_confidence':   inference_confidence,
        })
        by_bucket[activity_bucket or 'unknown'] += 1
        by_dormancy[dormancy_band or 'unknown'] += 1

        # Emit finding for high-dormancy privileged assignments
        is_privileged = role_name in CATEGORIES_REQUIRING
        if dormancy_band == 'high' and is_privileged and inference_confidence == 'observed':
            sev = 'critical' if role_name in ('Global Administrator',
                                                'Privileged Role Administrator',
                                                'Security Administrator') else 'high'
            findings_out.append({
                'finding_type': 'dormant_directory_role_assignment',
                'severity': sev,
                'identity_db_id': identity_db_id,
                'identity_id':    identity_id,
                'display_name':   display_name,
                'title': (f"{role_name} assignment with no observed activity "
                          f"in {days_since_last_action}d"),
                'evidence': {
                    'role_name': role_name,
                    'days_since_last_action': days_since_last_action,
                    'activities_90d': activities_90d,
                    'last_action_at': last_action_at.isoformat() if last_action_at else None,
                    'inference_confidence': inference_confidence,
                },
                'recommendation': (
                    f'The {role_name} role assignment has not been exercised in '
                    f'{days_since_last_action} days. Review with the assignment owner — '
                    f'either remove the standing grant, replace with PIM-eligibility '
                    f'(time-bound activation), or document why standing grant is required.'
                ),
            })

    summary = {
        'total_assignments': len(rows_raw),
        'by_bucket': dict(by_bucket),
        'by_dormancy': dict(by_dormancy),
        'total_findings': len(findings_out),
    }
    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings_out.sort(key=lambda f: (sev_rank.get(f['severity'], 99), f['identity_id']))

    return {
        'rows':       rows_out,
        'findings':   findings_out,
        'summary':    summary,
        'computed_at': now.isoformat(),
    }


def populate_entra_role_activity(db, org_id: int, run_id: int) -> int:
    """AG-PILOT-FEATURE-E-WRITER (2026-06-08, ENHANCED 2026-06-09):
    materializes entra_role_activity from entra_role_assignments using
    the per-row last_used_at that _collect_entra_audit_activity has
    already populated via CATEGORIES_REQUIRING cross-product
    attribution.

    Activity bucket / dormancy band logic:
      - If last_used_at IS NULL → bucket='unknown', band='unknown'
        (honest "no telemetry" signal — moat rule)
      - If observed: compute days_since_last_action, derive bucket and
        band per the rules in _activity_bucket / _dormancy_band

    Returns the number of rollup rows written.
    """
    cursor = db.conn.cursor()
    try:
        # Read assignments + the last_used_at that the audit puller
        # already populated. Aggregate when an identity has multiple
        # assignments of the same role at different scopes (rare for
        # Entra; usually tenant-wide).
        cursor.execute("""
            SELECT
              i.id              AS identity_db_id,
              COALESCE(i.identity_id, i.object_id) AS identity_id,
              i.identity_category AS principal_type,
              era.role_name,
              era.role_template_id,
              MAX(era.last_used_at) AS last_used_at,
              MAX(era.last_used_operation) AS last_used_operation
            FROM entra_role_assignments era
            JOIN identities i ON i.id = era.identity_db_id
            WHERE era.organization_id = %s
              AND era.discovery_run_id = %s
              AND COALESCE(i.deleted_at, '1970-01-01'::timestamp) < '1971-01-01'::timestamp
            GROUP BY i.id, i.identity_id, i.object_id, i.identity_category,
                     era.role_name, era.role_template_id
        """, (org_id, run_id))
        rows = cursor.fetchall()
        now = datetime.now(timezone.utc)
        written = 0
        for r in rows:
            (identity_db_id, identity_id, principal_type, role_name,
             role_template_id, last_used_at, last_used_operation) = r

            if last_used_at:
                # Architecture-derived: real attribution from audit logs
                # (or PIM activations) is present
                if last_used_at.tzinfo is None:
                    last_used_at = last_used_at.replace(tzinfo=timezone.utc)
                days_since = max(0, int((now - last_used_at).total_seconds() // 86400))
                # 90-day activity count we don't have without aggregation
                # — leave as 1 to indicate "observed at least once"
                activities_30d = 1 if days_since <= 30 else 0
                activities_90d = 1 if days_since <= 90 else 0
                bucket = _activity_bucket(activities_30d, activities_90d)
                band   = _dormancy_band(days_since)
                inferred_from = 'auditLogs/directoryAudits'
                confidence = 'observed'
            else:
                last_used_at = None
                days_since = None
                activities_30d = 0
                activities_90d = 0
                bucket = 'unknown'
                band = 'unknown'
                inferred_from = 'no_telemetry'
                confidence = 'unknown'

            try:
                cursor.execute("""
                    INSERT INTO entra_role_activity
                        (organization_id, discovery_run_id, identity_db_id, identity_id,
                         role_name, role_template_id, assignment_principal_type,
                         last_action_at, days_since_last_action,
                         activities_30d, activities_90d,
                         activity_bucket, dormancy_band,
                         inferred_from, inference_confidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (organization_id, identity_db_id, role_name)
                    DO UPDATE SET
                        discovery_run_id       = EXCLUDED.discovery_run_id,
                        role_template_id       = EXCLUDED.role_template_id,
                        last_action_at         = EXCLUDED.last_action_at,
                        days_since_last_action = EXCLUDED.days_since_last_action,
                        activities_30d         = EXCLUDED.activities_30d,
                        activities_90d         = EXCLUDED.activities_90d,
                        activity_bucket        = EXCLUDED.activity_bucket,
                        dormancy_band          = EXCLUDED.dormancy_band,
                        inferred_from          = EXCLUDED.inferred_from,
                        inference_confidence   = EXCLUDED.inference_confidence,
                        discovered_at          = NOW()
                """, (
                    org_id, run_id, identity_db_id, identity_id,
                    role_name, role_template_id, principal_type or 'unknown',
                    last_used_at, days_since,
                    activities_30d, activities_90d,
                    bucket, band,
                    inferred_from, confidence,
                ))
                written += 1
            except Exception:
                db._rollback()
        db._commit()
        return written
    finally:
        cursor.close()


__all__ = [
    'CATEGORIES_REQUIRING',
    '_activity_bucket',
    '_dormancy_band',
    'compute_entra_role_activity',
    'populate_entra_role_activity',
]
