"""
Ownership Center (Tier WK3.1) — assign / list / report ownership for NHIs.

The SailPoint-money capability: an Identity Governance team needs a
workflow to:
  - SEE every NHI that has no human owner (unowned inventory)
  - ASSIGN an owner (manager + optional delegate)
  - SET an expiry (when the assignment needs re-certification)
  - SEE pending re-certs, exceptions, and recent activity

This MVP engine ships the inventory + assignment surface. Certification
campaigns + workflow routing land in Week 4.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


def list_unowned_nhis(db, org_id: int, limit: int = 200) -> dict[str, Any]:
    """Every NHI in the tenant that has NO active owner assignment.

    V2 (2026-06-12) — two bug fixes per founder review:
      1. SCOPE TO LATEST DISCOVERY RUN. Without this filter every NHI
         was counted once per historical discovery_run row in the
         identities table — org 10 had 2 runs × 1091 NHIs = 2,182
         double-counts that read as "100% unowned" on the UI.
      2. BROADER "HAS OWNER" CHECK. Prior version only treated an
         NHI as owned when it had an entry in nhi_ownership_assignments
         (our internal attestation ledger). That ignored Entra-side
         signals (owner_display_name from /servicePrincipals/{id}/owners,
         app registration owners, sp_ownership rows). The list and
         summary now agree: an NHI is owned if ANY of these signals fires.
    """
    cursor = db.conn.cursor()
    try:
        # Get the latest completed discovery_run_id for this org. If none,
        # short-circuit to an empty result so we never count cross-run rows.
        cursor.execute("""
            SELECT MAX(id) AS run_id FROM discovery_runs
             WHERE organization_id = %s AND status IN ('completed', 'partial')
        """, (org_id,))
        rrow = cursor.fetchone()
        latest_run_id = (rrow['run_id'] if isinstance(rrow, dict) else (rrow[0] if rrow else None))
        if latest_run_id is None:
            return {
                'items': [], 'total_unowned': 0, 'total_nhis': 0, 'pct_unowned': 0,
                'returned': 0,
                'computed_at': datetime.now(timezone.utc).isoformat(),
            }

        # Shared CTEs: scope to latest run + apply the canonical "owned"
        # predicate so the list and the totals always agree.
        _nhi_base = """
            i.organization_id = %s
            AND i.discovery_run_id = %s
            AND i.deleted_at IS NULL
            AND i.identity_category IN
                ('service_principal','managed_identity_system',
                 'managed_identity_user')
            AND NOT COALESCE(i.is_microsoft_system, false)
        """
        # An NHI is OWNED when ANY of these is true. Used in both list + summary.
        _is_owned = """
            (
                EXISTS (SELECT 1 FROM nhi_ownership_assignments oa
                         WHERE oa.identity_db_id = i.id
                           AND oa.organization_id = i.organization_id
                           AND oa.status = 'active')
                OR COALESCE(i.owner_display_name, '') != ''
                OR COALESCE(i.app_reg_owner_display_name, '') != ''
                OR COALESCE(i.owner_count, 0) > 0
                OR EXISTS (SELECT 1 FROM sp_ownership spo
                            WHERE spo.identity_db_id = i.id
                              AND spo.organization_id = i.organization_id)
            )
        """

        cursor.execute(f"""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   COALESCE(ac.agent_identity_type, i.agent_identity_type) AS agent_type,
                   i.risk_level, i.risk_score
              FROM identities i
              LEFT JOIN agent_classifications ac ON ac.identity_db_id = i.id
             WHERE {_nhi_base}
               AND NOT {_is_owned}
             ORDER BY
               CASE i.risk_level
                 WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                 WHEN 'medium'   THEN 2 WHEN 'low' THEN 3
                 ELSE 4 END,
               i.risk_score DESC NULLS LAST
             LIMIT %s
        """, (org_id, latest_run_id, limit))
        rows = cursor.fetchall()

        cursor.execute(f"""
            SELECT count(*) FROM identities i
             WHERE {_nhi_base}
               AND NOT {_is_owned}
        """, (org_id, latest_run_id))
        r = cursor.fetchone()
        total_unowned = (r['count'] if isinstance(r, dict) else r[0])

        cursor.execute(f"""
            SELECT count(*) FROM identities i
             WHERE {_nhi_base}
        """, (org_id, latest_run_id))
        r = cursor.fetchone()
        total_nhis = (r['count'] if isinstance(r, dict) else r[0])
    finally:
        cursor.close()

    items = []
    for r in rows:
        if isinstance(r, dict):
            items.append({
                'identity_db_id':     r['id'],
                'identity_id':        r['identity_id'],
                'display_name':       r['display_name'] or r['identity_id'],
                'identity_category':  r['identity_category'],
                'agent_type':         r['agent_type'],
                'risk_level':         r['risk_level'],
                'risk_score':         r['risk_score'],
            })
        else:
            items.append({
                'identity_db_id':     r[0],
                'identity_id':        r[1],
                'display_name':       r[2] or r[1],
                'identity_category':  r[3],
                'agent_type':         r[4],
                'risk_level':         r[5],
                'risk_score':         r[6],
            })
    pct = round((total_unowned / total_nhis) * 100) if total_nhis else 0
    return {
        'items':         items,
        'total_unowned': total_unowned,
        'total_nhis':    total_nhis,
        'pct_unowned':   pct,
        'returned':      len(items),
        'computed_at':   datetime.now(timezone.utc).isoformat(),
    }


def list_assignments(db, org_id: int, status: Optional[str] = None,
                      limit: int = 200) -> list[dict]:
    """Active assignments. Optionally filter by status."""
    cursor = db.conn.cursor()
    try:
        where = ['organization_id = %s']
        params: list[Any] = [org_id]
        if status:
            where.append('status = %s')
            params.append(status)
        sql = f"""
            SELECT id, identity_db_id, identity_id, owner_user_id,
                   owner_display_name, owner_email, delegate_user_id,
                   delegate_display_name, status, assignment_reason,
                   expires_at, assigned_by_user_id, assigned_at, updated_at
              FROM nhi_ownership_assignments
             WHERE {' AND '.join(where)}
             ORDER BY updated_at DESC
             LIMIT %s
        """
        cursor.execute(sql, params + [limit])
        rows = cursor.fetchall()
    finally:
        cursor.close()
    return [
        {
            'id': r[0], 'identity_db_id': r[1], 'identity_id': r[2],
            'owner_user_id': r[3], 'owner_display_name': r[4],
            'owner_email': r[5], 'delegate_user_id': r[6],
            'delegate_display_name': r[7], 'status': r[8],
            'assignment_reason': r[9],
            'expires_at': r[10].isoformat() if r[10] else None,
            'assigned_by_user_id': r[11],
            'assigned_at': r[12].isoformat() if r[12] else None,
            'updated_at': r[13].isoformat() if r[13] else None,
        }
        for r in rows
    ]


def assign_owner(db, org_id: int, identity_id: str,
                  owner_display_name: str, owner_email: Optional[str] = None,
                  owner_user_id: Optional[int] = None,
                  delegate_display_name: Optional[str] = None,
                  delegate_user_id: Optional[int] = None,
                  assignment_reason: Optional[str] = None,
                  expires_at: Optional[str] = None,
                  assigned_by_user_id: Optional[int] = None) -> dict[str, Any]:
    """Assign or update an owner for one NHI.

    If there's an active assignment, it's revoked (status='revoked') and a new
    active one is inserted — preserves the audit trail.
    """
    cursor = db.conn.cursor()
    try:
        # Resolve identity_db_id from identity_id (latest run)
        cursor.execute("""
            SELECT id FROM identities
             WHERE organization_id = %s AND identity_id = %s
             ORDER BY discovery_run_id DESC LIMIT 1
        """, (org_id, identity_id))
        row = cursor.fetchone()
        if not row:
            return {'error': 'Identity not found'}
        identity_db_id = row[0]

        # Revoke any existing active assignment
        cursor.execute("""
            UPDATE nhi_ownership_assignments
               SET status = 'revoked', updated_at = NOW()
             WHERE organization_id = %s AND identity_db_id = %s AND status = 'active'
        """, (org_id, identity_db_id))

        # Insert new active assignment
        cursor.execute("""
            INSERT INTO nhi_ownership_assignments
                (organization_id, identity_db_id, identity_id,
                 owner_user_id, owner_display_name, owner_email,
                 delegate_user_id, delegate_display_name,
                 status, assignment_reason, expires_at, assigned_by_user_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s)
            RETURNING id, assigned_at
        """, (org_id, identity_db_id, identity_id,
              owner_user_id, owner_display_name, owner_email,
              delegate_user_id, delegate_display_name,
              assignment_reason, expires_at, assigned_by_user_id))
        new_id, assigned_at = cursor.fetchone()
        db.conn.commit()
        return {
            'id': new_id,
            'identity_db_id': identity_db_id,
            'identity_id': identity_id,
            'owner_display_name': owner_display_name,
            'status': 'active',
            'assigned_at': assigned_at.isoformat() if assigned_at else None,
        }
    finally:
        cursor.close()


def get_ownership_summary(db, org_id: int) -> dict[str, Any]:
    """Headline metrics for the Ownership Center page.

    V2 (2026-06-12) — same two fixes as list_unowned_nhis:
      1. Latest-discovery-run scope (was counting cross-run rows).
      2. Broader "owned" predicate (was counting only attestation-ledger
         rows; Entra-side ownership signals were ignored, so a tenant with
         141 of 143 NHIs having an Entra owner read as "2 owned / 141
         unowned" instead of "141 owned / 2 unowned").
    The list and summary now derive from the same predicate.
    """
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT MAX(id) AS run_id FROM discovery_runs
             WHERE organization_id = %s AND status IN ('completed', 'partial')
        """, (org_id,))
        rrow = cursor.fetchone()
        latest_run_id = (rrow['run_id'] if isinstance(rrow, dict) else (rrow[0] if rrow else None))
        if latest_run_id is None:
            return {
                'total_nhi': 0, 'active_assigned': 0, 'unowned': 0,
                'pct_owned': 0, 'expiring_soon': 0, 'exceptions': 0,
                'computed_at': datetime.now(timezone.utc).isoformat(),
            }

        # Same canonical predicates as list_unowned_nhis.
        cursor.execute("""
            SELECT
                count(*) AS total_nhi,
                count(*) FILTER (
                    WHERE EXISTS (SELECT 1 FROM nhi_ownership_assignments oa
                                   WHERE oa.identity_db_id = i.id
                                     AND oa.organization_id = i.organization_id
                                     AND oa.status = 'active')
                       OR COALESCE(i.owner_display_name, '') != ''
                       OR COALESCE(i.app_reg_owner_display_name, '') != ''
                       OR COALESCE(i.owner_count, 0) > 0
                       OR EXISTS (SELECT 1 FROM sp_ownership spo
                                   WHERE spo.identity_db_id = i.id
                                     AND spo.organization_id = i.organization_id)
                ) AS owned
              FROM identities i
             WHERE i.organization_id = %s
               AND i.discovery_run_id = %s
               AND i.deleted_at IS NULL
               AND i.identity_category IN
                    ('service_principal','managed_identity_system',
                     'managed_identity_user')
               AND NOT COALESCE(i.is_microsoft_system, false)
        """, (org_id, latest_run_id))
        r = cursor.fetchone()
        total_nhi = (r['total_nhi'] if isinstance(r, dict) else r[0])
        owned     = (r['owned']     if isinstance(r, dict) else r[1])

        # Re-cert metrics still come from the ledger (those concepts only
        # exist for attested assignments, not Entra-derived ownership).
        cursor.execute("""
            SELECT count(*)
              FROM nhi_ownership_assignments
             WHERE organization_id = %s AND status = 'active'
               AND expires_at IS NOT NULL
               AND expires_at < NOW() + INTERVAL '30 days'
        """, (org_id,))
        r = cursor.fetchone(); expiring_soon = (r['count'] if isinstance(r, dict) else r[0])

        cursor.execute("""
            SELECT count(*)
              FROM nhi_ownership_assignments
             WHERE organization_id = %s AND status = 'exception'
        """, (org_id,))
        r = cursor.fetchone(); exceptions = (r['count'] if isinstance(r, dict) else r[0])
    finally:
        cursor.close()

    unowned = max(0, total_nhi - owned)
    pct_owned = round((owned / total_nhi) * 100) if total_nhi else 0
    return {
        'total_nhi':       total_nhi,
        'active_assigned': owned,    # now: total signal-derived owned, not just ledger
        'unowned':         unowned,
        'pct_owned':       pct_owned,
        'expiring_soon':   expiring_soon,
        'exceptions':      exceptions,
        'computed_at':     datetime.now(timezone.utc).isoformat(),
    }


__all__ = ['list_unowned_nhis', 'list_assignments', 'assign_owner',
            'get_ownership_summary']
