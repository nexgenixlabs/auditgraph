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

    "Unowned" = either:
      - identities.assigned_human_owner is NULL/empty, AND
      - no active row in nhi_ownership_assignments
    """
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   COALESCE(ac.agent_identity_type, i.agent_identity_type) AS agent_type,
                   i.risk_level, i.risk_score
              FROM identities i
              LEFT JOIN agent_classifications ac ON ac.identity_db_id = i.id
              LEFT JOIN nhi_ownership_assignments a
                    ON a.identity_db_id = i.id
                   AND a.status = 'active'
                   AND a.organization_id = i.organization_id
             WHERE i.organization_id = %s
               AND i.deleted_at IS NULL
               AND i.identity_category IN
                    ('service_principal','managed_identity_system',
                     'managed_identity_user')
               AND NOT COALESCE(i.is_microsoft_system, false)
               AND a.id IS NULL
               AND COALESCE(i.owner_display_name, '') = ''
             ORDER BY
               CASE i.risk_level
                 WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                 WHEN 'medium'   THEN 2 WHEN 'low' THEN 3
                 ELSE 4 END,
               i.risk_score DESC NULLS LAST
             LIMIT %s
        """, (org_id, limit))
        rows = cursor.fetchall()

        cursor.execute("""
            SELECT count(*)
              FROM identities i
              LEFT JOIN nhi_ownership_assignments a
                    ON a.identity_db_id = i.id
                   AND a.status = 'active'
                   AND a.organization_id = i.organization_id
             WHERE i.organization_id = %s
               AND i.deleted_at IS NULL
               AND i.identity_category IN
                    ('service_principal','managed_identity_system',
                     'managed_identity_user')
               AND NOT COALESCE(i.is_microsoft_system, false)
               AND a.id IS NULL
               AND COALESCE(i.owner_display_name, '') = ''
        """, (org_id,))
        r = cursor.fetchone()
        total_unowned = (r['count'] if isinstance(r, dict) else r[0])

        cursor.execute("""
            SELECT count(*) FROM identities
             WHERE organization_id = %s
               AND deleted_at IS NULL
               AND identity_category IN
                    ('service_principal','managed_identity_system',
                     'managed_identity_user')
               AND NOT COALESCE(is_microsoft_system, false)
        """, (org_id,))
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
    """Headline metrics for the Ownership Center page."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT
                count(*) FILTER (
                    WHERE identity_category IN
                         ('service_principal','managed_identity_system','managed_identity_user')
                      AND NOT COALESCE(is_microsoft_system, false)
                      AND deleted_at IS NULL
                ) AS total_nhi
              FROM identities WHERE organization_id = %s
        """, (org_id,))
        r = cursor.fetchone(); total_nhi = (r['total_nhi'] if isinstance(r, dict) else r[0])

        cursor.execute("""
            SELECT count(*)
              FROM nhi_ownership_assignments
             WHERE organization_id = %s AND status = 'active'
        """, (org_id,))
        r = cursor.fetchone(); active_assigned = (r['count'] if isinstance(r, dict) else r[0])

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

    unowned = max(0, total_nhi - active_assigned)
    pct_owned = round((active_assigned / total_nhi) * 100) if total_nhi else 0
    return {
        'total_nhi':       total_nhi,
        'active_assigned': active_assigned,
        'unowned':         unowned,
        'pct_owned':       pct_owned,
        'expiring_soon':   expiring_soon,
        'exceptions':      exceptions,
        'computed_at':     datetime.now(timezone.utc).isoformat(),
    }


__all__ = ['list_unowned_nhis', 'list_assignments', 'assign_owner',
            'get_ownership_summary']
