"""
Remediation Queue DB functions — psycopg2 / RealDictCursor pattern.

All functions accept a Database instance (already RLS-scoped) and org_id.
"""
import logging
from datetime import datetime, timezone

from psycopg2.extras import RealDictCursor

from app.constants.remediation import (
    RemediationStatus,
    VALID_STATUS_TRANSITIONS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DDL — idempotent table creation (matches migration 081)
# ---------------------------------------------------------------------------

_RQ_DDL = """
CREATE TABLE IF NOT EXISTS remediation_queue (
    id              SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    attack_path_id  INTEGER,
    identity_id     BIGINT,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    status          VARCHAR(20) NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','in_progress','resolved','dismissed')),
    assigned_to     TEXT,
    priority_score  NUMERIC(5,2),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    resolution_notes TEXT,
    created_by      TEXT NOT NULL,
    CONSTRAINT uq_remediation_queue_org_attack_path
        UNIQUE (organization_id, attack_path_id)
)
"""

_rq_ensured = False


def _ensure_table(conn):
    global _rq_ensured
    if _rq_ensured:
        return
    cursor = conn.cursor()
    try:
        cursor.execute(_RQ_DDL)
        conn.commit()
        _rq_ensured = True
    except Exception:
        conn.rollback()
        # Check whether the table actually exists before silencing the error
        try:
            cursor2 = conn.cursor()
            cursor2.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_name = 'remediation_queue'"
            )
            _rq_ensured = cursor2.fetchone() is not None
            cursor2.close()
        except Exception:
            conn.rollback()
    finally:
        cursor.close()


# ---------------------------------------------------------------------------
# create_remediation_item
# ---------------------------------------------------------------------------

def create_remediation_item(db, org_id, attack_path_id, identity_id,
                            title, description, severity,
                            priority_score, created_by):
    """Insert a new queue item. Returns existing item with already_exists=True on dupe."""
    _ensure_table(db.conn)
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Check for existing item with same org + attack_path
        if attack_path_id is not None:
            cursor.execute(
                """SELECT rq.*, i.display_name, i.principal_type, i.recommended_action
                   FROM remediation_queue rq
                   LEFT JOIN identities i ON i.id = rq.identity_id
                   WHERE rq.organization_id = %s AND rq.attack_path_id = %s""",
                (org_id, attack_path_id),
            )
            existing = cursor.fetchone()
            if existing:
                row = dict(existing)
                row['already_exists'] = True
                return row

        cursor.execute(
            """INSERT INTO remediation_queue
                   (organization_id, attack_path_id, identity_id, title,
                    description, severity, priority_score, created_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING *""",
            (org_id, attack_path_id, identity_id, title,
             description, severity, priority_score, created_by),
        )
        row = dict(cursor.fetchone())
        db.conn.commit()
        row['already_exists'] = False
        return row
    except Exception:
        db.conn.rollback()
        raise
    finally:
        cursor.close()


# ---------------------------------------------------------------------------
# list_remediation_items
# ---------------------------------------------------------------------------

def list_remediation_items(db, org_id, status=None, severity=None,
                           limit=50, offset=0):
    """Paginated list with identity + attack_path joins."""
    _ensure_table(db.conn)
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        conditions = ["rq.organization_id = %s"]
        params = [org_id]

        if status:
            conditions.append("rq.status = %s")
            params.append(status)
        if severity:
            conditions.append("rq.severity = %s")
            params.append(severity)

        where = " AND ".join(conditions)

        # Count total
        cursor.execute(
            f"SELECT COUNT(*) FROM remediation_queue rq WHERE {where}",
            params,
        )
        total = cursor.fetchone()['count']

        # Fetch rows with joins
        cursor.execute(
            f"""SELECT rq.*,
                       i.display_name   AS identity_display_name,
                       i.principal_type AS identity_principal_type,
                       i.recommended_action AS identity_lineage_verdict,
                       ap.risk_score    AS attack_path_score,
                       ap.description   AS path_summary
                FROM remediation_queue rq
                LEFT JOIN identities i   ON i.id = rq.identity_id
                LEFT JOIN attack_paths ap ON ap.id = rq.attack_path_id
                WHERE {where}
                ORDER BY rq.priority_score DESC NULLS LAST, rq.created_at DESC
                LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
        items = [dict(r) for r in cursor.fetchall()]
        return items, total
    finally:
        cursor.close()


# ---------------------------------------------------------------------------
# get_remediation_item
# ---------------------------------------------------------------------------

def get_remediation_item(db, org_id, item_id):
    """Full detail for a single queue item, or None if not found."""
    _ensure_table(db.conn)
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            """SELECT rq.*,
                      i.display_name   AS identity_display_name,
                      i.principal_type AS identity_principal_type,
                      i.recommended_action AS identity_lineage_verdict,
                      ap.risk_score    AS attack_path_score,
                      ap.severity      AS attack_path_severity,
                      ap.path_type     AS attack_path_type,
                      ap.description   AS path_summary,
                      ap.narrative     AS attack_path_narrative,
                      ap.impact        AS attack_path_impact
               FROM remediation_queue rq
               LEFT JOIN identities i   ON i.id = rq.identity_id
               LEFT JOIN attack_paths ap ON ap.id = rq.attack_path_id
               WHERE rq.organization_id = %s AND rq.id = %s""",
            (org_id, item_id),
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        cursor.close()


# ---------------------------------------------------------------------------
# update_remediation_status
# ---------------------------------------------------------------------------

def update_remediation_status(db, org_id, item_id, new_status,
                              resolution_notes=None, assigned_to=None):
    """Transition status with validation. Raises ValueError on invalid transition."""
    _ensure_table(db.conn)
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Fetch current status
        cursor.execute(
            "SELECT status FROM remediation_queue WHERE organization_id = %s AND id = %s",
            (org_id, item_id),
        )
        row = cursor.fetchone()
        if not row:
            return None

        current = row['status']

        # Validate transition
        allowed = VALID_STATUS_TRANSITIONS.get(RemediationStatus(current), set())
        if RemediationStatus(new_status) not in allowed:
            raise ValueError(
                f"Cannot transition from '{current}' to '{new_status}'. "
                f"Allowed transitions: {', '.join(str(s.value) for s in allowed)}"
            )

        # Build SET clause
        sets = ["status = %s", "updated_at = NOW()"]
        params = [new_status]

        if new_status == RemediationStatus.RESOLVED:
            sets.append("resolved_at = NOW()")
        elif new_status == RemediationStatus.OPEN:
            sets.append("resolved_at = NULL")

        if resolution_notes is not None:
            sets.append("resolution_notes = %s")
            params.append(resolution_notes)

        if assigned_to is not None:
            sets.append("assigned_to = %s")
            params.append(assigned_to)

        params.extend([org_id, item_id])

        cursor.execute(
            f"""UPDATE remediation_queue
                SET {', '.join(sets)}
                WHERE organization_id = %s AND id = %s
                RETURNING *""",
            params,
        )
        updated = cursor.fetchone()
        db.conn.commit()
        return dict(updated) if updated else None
    except ValueError:
        raise
    except Exception:
        db.conn.rollback()
        raise
    finally:
        cursor.close()


# ---------------------------------------------------------------------------
# get_remediation_summary
# ---------------------------------------------------------------------------

def get_remediation_summary(db, org_id):
    """Aggregate counts by status and severity, plus avg resolution time."""
    _ensure_table(db.conn)
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            """SELECT
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE status = 'open')        AS status_open,
                   COUNT(*) FILTER (WHERE status = 'in_progress') AS status_in_progress,
                   COUNT(*) FILTER (WHERE status = 'resolved')    AS status_resolved,
                   COUNT(*) FILTER (WHERE status = 'dismissed')   AS status_dismissed,
                   COUNT(*) FILTER (WHERE severity = 'CRITICAL')  AS sev_critical,
                   COUNT(*) FILTER (WHERE severity = 'HIGH')      AS sev_high,
                   COUNT(*) FILTER (WHERE severity = 'MEDIUM')    AS sev_medium,
                   COUNT(*) FILTER (WHERE severity = 'LOW')       AS sev_low,
                   AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 86400.0)
                       FILTER (WHERE resolved_at IS NOT NULL) AS avg_resolution_days
               FROM remediation_queue
               WHERE organization_id = %s""",
            (org_id,),
        )
        r = cursor.fetchone()
        return {
            'total': r['total'],
            'by_status': {
                'open': r['status_open'],
                'in_progress': r['status_in_progress'],
                'resolved': r['status_resolved'],
                'dismissed': r['status_dismissed'],
            },
            'by_severity': {
                'CRITICAL': r['sev_critical'],
                'HIGH': r['sev_high'],
                'MEDIUM': r['sev_medium'],
                'LOW': r['sev_low'],
            },
            'avg_resolution_days': (
                round(float(r['avg_resolution_days']), 1)
                if r['avg_resolution_days'] is not None else None
            ),
        }
    finally:
        cursor.close()
