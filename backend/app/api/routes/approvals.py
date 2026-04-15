"""
W2-A1: Approval Workflow + W2-A2: Audit Trail API handlers.

Approval lifecycle:  pending → approved → queued → executing → executed
                     pending → rejected
                     pending → cancelled
                     approved → queued → executing → failed → queued (retry)
                     failed → failed_permanent (retry exhausted)

State machine enforced by transition_approval().
"""

import json
import logging
import uuid as _uuid
from datetime import datetime, timezone

import psycopg2
from flask import jsonify, request, g
from psycopg2.extras import RealDictCursor

from app.database import Database
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

ALLOWED_ACTION_TYPES = {
    'remove_role', 'assign_owner', 'disable_identity',
    'revoke_credential', 'scope_reduction', 'enable_pim',
}

REVIEW_ROLES = {'admin', 'owner', 'security_admin', 'auditor'}

# Execution worker fetch order — prevents starvation
# priority 1=high, 3=low so ASC = high first
# risk_reduction_score DESC = highest impact first
# requested_at ASC = FIFO within same priority/score
EXECUTION_ORDER_SQL = """
    ORDER BY priority ASC,
             risk_reduction_score DESC,
             requested_at ASC
"""

# ═══════════════════════════════════════════════════
# STATE MACHINE
# ═══════════════════════════════════════════════════

TERMINAL_STATES = frozenset({
    'executed', 'failed_permanent', 'rejected', 'cancelled', 'rolled_back',
})

ALLOWED_TRANSITIONS = {
    'pending':          {'approved', 'rejected', 'cancelled'},
    'approved':         {'queued', 'executing', 'cancelled'},
    'queued':           {'executing', 'cancelled'},
    'executing':        {'executed', 'failed'},
    'failed':           {'queued', 'failed_permanent'},
    'executed':         {'rolled_back'},
    # Terminal — no outbound transitions
    'failed_permanent': set(),
    'rejected':         set(),
    'cancelled':        set(),
    'rolled_back':      set(),
}

# Columns that transition_approval() auto-sets per target status
_AUTO_TIMESTAMP_MAP = {
    'approved':  'reviewed_at',
    'rejected':  'reviewed_at',
    'queued':    'queued_at',
    'executing': 'execution_started_at',
    'executed':  'execution_completed_at',
    'failed':    'execution_completed_at',
    'rolled_back': 'execution_completed_at',
}


def _org_id():
    user = getattr(g, 'current_user', None)
    if not user:
        return -1
    tid = user.get('organization_id')
    if tid:
        return tid
    if user.get('is_superadmin'):
        return None
    return -1


def _db():
    return Database(organization_id=_org_id())


def _user():
    return getattr(g, 'current_user', None) or {}


def _user_id():
    return _user().get('id')


def _user_role():
    return _user().get('role', 'viewer')


def _generate_request_ref(org_id: int) -> str:
    """Generate unique, collision-resistant request reference."""
    short = str(_uuid.uuid4()).replace('-', '')[:8].upper()
    return f"AR-{org_id}-{short}"


def _format_request(row: dict) -> dict:
    """Format an approval_requests row for JSON response."""
    d = dict(row)
    for ts in ('requested_at', 'reviewed_at', 'created_at', 'updated_at',
               'queued_at', 'execution_started_at', 'execution_completed_at',
               'last_retry_at'):
        if d.get(ts):
            d[ts] = d[ts].isoformat()
    return d


# ═══════════════════════════════════════════════════
# CORE STATE MACHINE
# ═══════════════════════════════════════════════════

def _validate_transition(from_status: str, to_status: str) -> bool:
    """Check whether from_status → to_status is allowed."""
    return to_status in ALLOWED_TRANSITIONS.get(from_status, set())


def transition_approval(db, request_ref: str, org_id: int,
                        to_status: str, **update_fields) -> dict:
    """Atomic, validated state transition. Fetches current status from DB
    — never trusts caller. Raises ValueError on invalid transition.

    WORKER PICKUP PATTERN (Week 3 execution engine):
    To safely pick up a job without double-execution:

        result = transition_approval(
            db=db,
            request_ref=ref,
            org_id=org_id,
            to_status='executing',
            execution_started_by=worker_user_id,
            execution_worker_id=worker_name
        )
        updated = result['row']
        prev = result['previous_status']
        # If ValueError: already picked up by another
        # worker or invalid state — skip this job

    The SELECT FOR UPDATE + atomic UPDATE WHERE
    status=current guarantees only one worker
    transitions the job to executing.
    No additional locking mechanism needed.

    AUDIT CONTRACT: Callers MUST call AuditService after a successful
    transition — this function does NOT write audit records.

    Args:
        db:            Database instance (org-scoped)
        request_ref:   The AR-xxx reference
        org_id:        Organization ID (for WHERE clause)
        to_status:     Target status
        **update_fields: Extra columns to SET (reviewed_by, review_note, etc.)

    Returns:
        dict with keys:
            'row': the updated approval_requests row
            'previous_status': status before transition
            (used for truthful audit before_state)

    Raises:
        ValueError — not found, invalid transition, retry exhausted, concurrent
    """
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # ── 1. Lock the row — SKIP LOCKED avoids deadlocks with concurrent workers ──
    cursor.execute("""
        SELECT status, retry_count, max_retries
        FROM approval_requests
        WHERE request_ref = %s
          AND organization_id = %s
        FOR UPDATE SKIP LOCKED
    """, (request_ref, org_id))
    row = cursor.fetchone()

    if not row:
        cursor.close()
        raise ValueError(
            f"Request {request_ref} is locked by another worker or not found "
            f"for org {org_id}. If locked, retry after a moment.")

    if isinstance(row, dict):
        current_status = row['status']
        retry_count    = row['retry_count'] or 0
        max_retries    = row['max_retries'] or 3
    else:
        current_status = row[0]
        retry_count    = row[1] or 0
        max_retries    = row[2] or 3

    # ── 2. Validate transition ──
    if not _validate_transition(current_status, to_status):
        cursor.close()
        allowed = ALLOWED_TRANSITIONS.get(current_status, set())
        raise ValueError(
            f"Invalid transition: {current_status} → {to_status}. "
            f"Allowed from '{current_status}': {sorted(allowed) or 'none (terminal)'}"
        )

    # ── 3. Retry enforcement — auto-redirect to failed_permanent ──
    if to_status == 'queued' and current_status == 'failed':
        if retry_count >= max_retries:
            # Auto-redirect: don't rely on caller
            to_status = 'failed_permanent'
            update_fields.setdefault(
                'execution_error',
                f'Max retries ({max_retries}) exceeded'
            )
            # Re-validate the redirected transition
            if not _validate_transition(current_status, to_status):
                cursor.close()
                raise ValueError(
                    f"Cannot transition "
                    f"{current_status} → {to_status}")

    # ── 4. Build SET clause ──
    sets = ["status = %s", "updated_at = NOW()"]
    params = [to_status]

    # Auto-timestamp for the target status
    ts_col = _AUTO_TIMESTAMP_MAP.get(to_status)
    if ts_col:
        sets.append(f"{ts_col} = NOW()")

    # Increment retry_count on failed → queued re-queue
    if current_status == 'failed' and to_status == 'queued':
        sets.append("retry_count = COALESCE(retry_count, 0) + 1")
        sets.append("last_retry_at = NOW()")

    # Caller-supplied fields (reviewed_by, review_note, queued_by, etc.)
    safe_cols = {
        'reviewed_by', 'review_note', 'queued_by',
        'execution_eta_minutes', 'projected_score_delta',
        'max_retries', 'execution_error',
    }
    for col, val in update_fields.items():
        if col in safe_cols:
            sets.append(f"{col} = %s")
            params.append(val)

    set_sql = ", ".join(sets)

    # ── 5. Atomic UPDATE with old-status guard ──
    params.extend([org_id, request_ref, current_status])
    cursor.execute(f"""
        UPDATE approval_requests
        SET {set_sql}
        WHERE organization_id = %s
          AND request_ref = %s
          AND status = %s
        RETURNING *
    """, params)
    updated = cursor.fetchone()

    if not updated:
        cursor.close()
        raise ValueError(
            f"Concurrent modification — status already changed from '{current_status}'"
        )

    db.conn.commit()
    cursor.close()
    return {
        'row': dict(updated),
        'previous_status': current_status,
    }


# ═══════════════════════════════════════════════════
# APPROVAL ENDPOINTS
# ═══════════════════════════════════════════════════

def create_approval_request():
    """POST /api/approvals — propose a new remediation for approval."""
    body = request.get_json(silent=True) or {}
    identity_id = body.get('identity_id')
    action_type = body.get('action_type')
    action_payload = body.get('action_payload')
    priority = body.get('priority', 2)
    eta = body.get('execution_eta_minutes')

    if not identity_id:
        return jsonify({'error': 'identity_id is required'}), 400
    if action_type not in ALLOWED_ACTION_TYPES:
        return jsonify({'error': f'action_type must be one of: {sorted(ALLOWED_ACTION_TYPES)}'}), 400
    if not action_payload or not isinstance(action_payload, dict):
        return jsonify({'error': 'action_payload must be a non-empty object'}), 400

    # Normalize field names at ingestion — one contract everywhere
    if action_type == 'remove_role':
        if 'role_assignment_id' in action_payload and 'assignment_id' not in action_payload:
            action_payload = dict(action_payload)
            action_payload['assignment_id'] = action_payload.pop('role_assignment_id')

    if priority not in (1, 2, 3):
        return jsonify({'error': 'priority must be 1, 2, or 3'}), 400

    org_id = _org_id()
    if not org_id or org_id < 0:
        return jsonify({'error': 'Organization context required'}), 403

    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)

        # Verify identity belongs to this org
        cursor.execute(
            "SELECT identity_id, display_name FROM identity_list "
            "WHERE organization_id = %s AND identity_id = %s",
            (org_id, identity_id),
        )
        ident = cursor.fetchone()
        if not ident:
            cursor.close()
            db.close()
            return jsonify({'error': 'Identity not found in this organization'}), 404

        display_name = ident['display_name']
        request_ref = _generate_request_ref(org_id)
        now = datetime.now(timezone.utc)

        # Try to get risk_reduction_score from fix_prioritizer
        risk_reduction = 0.0
        try:
            from app.engines.remediation.fix_prioritizer import FixPrioritizer
            fp = FixPrioritizer()
            fixes = fp.get_top_3_fixes_with_projection(cursor, org_id, identity_id)
            for fix in (fixes or []):
                if fix.get('action_type') == action_type:
                    risk_reduction = fix.get('risk_reduction_score', 0.0)
                    break
        except Exception:
            pass

        # Deterministic payload for idempotency index
        normalized = json.dumps(action_payload, sort_keys=True, separators=(',', ':'))

        # Insert — catch duplicate via partial unique index
        try:
            cursor.execute("""
                INSERT INTO approval_requests (
                    organization_id, request_ref, identity_id,
                    identity_display_name, action_type, action_payload,
                    normalized_payload,
                    risk_reduction_score, status, priority,
                    requested_by, requested_at, execution_eta_minutes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s)
                RETURNING id, request_ref, status, identity_id,
                          identity_display_name, action_type, action_payload,
                          priority, requested_at, risk_reduction_score,
                          execution_eta_minutes
            """, (
                org_id, request_ref, identity_id,
                display_name, action_type, json.dumps(action_payload),
                normalized,
                risk_reduction, priority,
                _user_id(), now, eta,
            ))
            row = cursor.fetchone()
            db.conn.commit()
        except psycopg2.errors.UniqueViolation as dup_err:
            db.conn.rollback()
            if 'idx_approval_no_duplicates' in str(dup_err):
                cursor.execute("""
                    SELECT * FROM approval_requests
                    WHERE organization_id = %s
                      AND identity_id = %s
                      AND action_type = %s
                      AND status = 'pending'
                    LIMIT 1
                """, (org_id, identity_id, action_type))
                existing = cursor.fetchone()
                cursor.close()
                db.close()
                return jsonify({
                    'existing': True,
                    'message': 'Pending approval already exists',
                    'request': _format_request(existing) if existing else None,
                }), 409
            raise

        cursor.close()
        result = _format_request(row)

        # Audit trail
        audit = AuditService.from_request(db, request, _user())
        audit.log(
            event_type='approval.created',
            action='Proposed remediation for approval',
            target_type='identity',
            target_id=identity_id,
            target_display_name=display_name,
            after_state={
                'request_ref': request_ref,
                'action_type': action_type,
                'status': 'pending',
            },
            request=request,
        )

        db.close()
        return jsonify(result), 201

    except Exception as e:
        logger.error("create_approval_request failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def list_approval_requests():
    """GET /api/approvals — list with filtering."""
    status_filter = request.args.get('status', 'pending')
    priority_filter = request.args.get('priority', type=int)
    identity_filter = request.args.get('identity_id')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)

        # Status counts
        cursor.execute(
            "SELECT status, COUNT(*) AS cnt FROM approval_requests "
            "WHERE organization_id = %s GROUP BY status",
            (_org_id(),),
        )
        counts = {r['status']: r['cnt'] for r in cursor.fetchall()}

        # Build filter
        where = ["organization_id = %s"]
        params = [_org_id()]
        if status_filter and status_filter != 'all':
            where.append("status = %s")
            params.append(status_filter)
        if priority_filter:
            where.append("priority = %s")
            params.append(priority_filter)
        if identity_filter:
            where.append("identity_id = %s")
            params.append(identity_filter)

        where_sql = " AND ".join(where)

        # Total for current filter
        cursor.execute(f"SELECT COUNT(*) AS cnt FROM approval_requests WHERE {where_sql}", params)
        total = cursor.fetchone()['cnt']

        # Fetch
        cursor.execute(f"""
            SELECT id, request_ref, identity_id, identity_display_name,
                   action_type, action_payload, risk_reduction_score,
                   status, priority, requested_by, requested_at,
                   reviewed_by, reviewed_at, review_note,
                   execution_eta_minutes, projected_score_delta
            FROM approval_requests
            WHERE {where_sql}
            ORDER BY priority ASC, risk_reduction_score DESC, requested_at ASC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        requests_list = [_format_request(r) for r in rows]

        return jsonify({
            'total': total,
            'pending': counts.get('pending', 0),
            'approved': counts.get('approved', 0),
            'rejected': counts.get('rejected', 0),
            'cancelled': counts.get('cancelled', 0),
            'requests': requests_list,
        })

    except Exception as e:
        logger.error("list_approval_requests failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def get_approval_request(request_ref):
    """GET /api/approvals/<request_ref> — single request detail."""
    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT ar.*, u1.username AS requested_by_name,
                   u2.username AS reviewed_by_name
            FROM approval_requests ar
            LEFT JOIN users u1 ON u1.id = ar.requested_by
            LEFT JOIN users u2 ON u2.id = ar.reviewed_by
            WHERE ar.organization_id = %s AND ar.request_ref = %s
        """, (_org_id(), request_ref))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            db.close()
            return jsonify({'error': 'Approval request not found'}), 404

        result = _format_request(row)

        # Enrich with identity context
        cursor.execute(
            "SELECT risk_score, risk_label, identity_class, lifecycle_state "
            "FROM identity_list WHERE organization_id = %s AND identity_id = %s",
            (_org_id(), row['identity_id']),
        )
        ident = cursor.fetchone()
        if ident:
            result['identity_context'] = dict(ident)

        cursor.close()
        db.close()
        return jsonify(result)

    except Exception as e:
        logger.error("get_approval_request failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def approve_request(request_ref):
    """POST /api/approvals/<ref>/approve — transition pending → approved."""
    body = request.get_json(silent=True) or {}
    note = body.get('note', '')

    user = _user()
    if _user_role() not in REVIEW_ROLES:
        return jsonify({'error': 'Insufficient role to approve requests'}), 403

    org_id = _org_id()
    db = _db()
    try:
        # Self-approval guard (read before locking)
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT requested_by FROM approval_requests "
            "WHERE organization_id = %s AND request_ref = %s",
            (org_id, request_ref),
        )
        pre = cursor.fetchone()
        cursor.close()
        if pre and pre['requested_by'] == _user_id():
            db.close()
            return jsonify({'error': 'Requester cannot approve their own request'}), 403

        t = transition_approval(
            db=db, request_ref=request_ref, org_id=org_id,
            to_status='approved',
            reviewed_by=_user_id(),
            review_note=note,
        )
        updated = t['row']
        prev_status = t['previous_status']

        result = _format_request(updated)

        # Audit trail (AUDIT CONTRACT)
        audit = AuditService.from_request(db, request, user)
        audit.log(
            event_type='approval.approved',
            action=f'Approved: {request_ref}',
            target_type='approval_request',
            target_id=request_ref,
            target_display_name=updated.get('identity_display_name'),
            before_state={'status': prev_status},
            after_state={'status': 'approved', 'reviewed_by': _user_id(), 'note': note},
            request=request,
        )

        db.close()
        return jsonify(result)

    except ValueError as e:
        try:
            db.conn.rollback()
        except Exception:
            pass
        db.close()
        msg = str(e)
        code = 409 if ('not found' in msg or 'Concurrent' in msg or 'Invalid' in msg) else 400
        return jsonify({'error': msg}), code

    except Exception as e:
        logger.error("approve_request failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def reject_request(request_ref):
    """POST /api/approvals/<ref>/reject — transition pending → rejected."""
    body = request.get_json(silent=True) or {}
    note = body.get('note', '')

    user = _user()
    org_id = _org_id()
    db = _db()
    try:
        t = transition_approval(
            db=db, request_ref=request_ref, org_id=org_id,
            to_status='rejected',
            reviewed_by=_user_id(),
            review_note=note,
        )
        updated = t['row']
        prev_status = t['previous_status']

        result = _format_request(updated)

        # Audit trail (AUDIT CONTRACT)
        audit = AuditService.from_request(db, request, user)
        audit.log(
            event_type='approval.rejected',
            action=f'Rejected: {request_ref}',
            target_type='approval_request',
            target_id=request_ref,
            target_display_name=updated.get('identity_display_name'),
            before_state={'status': prev_status},
            after_state={'status': 'rejected', 'reviewed_by': _user_id(), 'note': note},
            request=request,
        )

        db.close()
        return jsonify(result)

    except ValueError as e:
        try:
            db.conn.rollback()
        except Exception:
            pass
        db.close()
        msg = str(e)
        code = 409 if ('not found' in msg or 'Concurrent' in msg or 'Invalid' in msg) else 400
        return jsonify({'error': msg}), code

    except Exception as e:
        logger.error("reject_request failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def cancel_request(request_ref):
    """POST /api/approvals/<ref>/cancel — requester or admin only.
    Cancellable from: pending, approved, queued."""
    user = _user()
    org_id = _org_id()
    db = _db()
    try:
        # Auth check: only requester or admin can cancel
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT requested_by, status FROM approval_requests "
            "WHERE organization_id = %s AND request_ref = %s",
            (org_id, request_ref),
        )
        pre = cursor.fetchone()
        cursor.close()
        if not pre:
            db.close()
            return jsonify({'error': 'Request not found'}), 404
        if pre['requested_by'] != _user_id() and _user_role() not in ('admin', 'owner'):
            db.close()
            return jsonify({'error': 'Only the requester or admin can cancel'}), 403

        t = transition_approval(
            db=db, request_ref=request_ref, org_id=org_id,
            to_status='cancelled',
        )
        updated = t['row']
        prev_status = t['previous_status']

        result = _format_request(updated)

        # Audit trail (AUDIT CONTRACT)
        audit = AuditService.from_request(db, request, user)
        audit.log(
            event_type='approval.cancelled',
            action=f'Cancelled: {request_ref}',
            target_type='approval_request',
            target_id=request_ref,
            target_display_name=updated.get('identity_display_name'),
            before_state={'status': prev_status},
            after_state={'status': 'cancelled'},
            request=request,
        )

        db.close()
        return jsonify(result)

    except ValueError as e:
        try:
            db.conn.rollback()
        except Exception:
            pass
        db.close()
        msg = str(e)
        code = 409 if ('not found' in msg or 'Concurrent' in msg or 'Invalid' in msg) else 400
        return jsonify({'error': msg}), code

    except Exception as e:
        logger.error("cancel_request failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def get_approvals_summary():
    """GET /api/approvals/summary — dashboard summary."""
    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        org_id = _org_id()

        # Pending count
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM approval_requests "
            "WHERE organization_id = %s AND status = 'pending'",
            (org_id,),
        )
        pending = cursor.fetchone()['cnt']

        # High priority pending
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM approval_requests "
            "WHERE organization_id = %s AND status = 'pending' AND priority = 1",
            (org_id,),
        )
        high_priority = cursor.fetchone()['cnt']

        # Approved today
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM approval_requests "
            "WHERE organization_id = %s AND status = 'approved' "
            "AND reviewed_at >= CURRENT_DATE",
            (org_id,),
        )
        approved_today = cursor.fetchone()['cnt']

        # Rejected today
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM approval_requests "
            "WHERE organization_id = %s AND status = 'rejected' "
            "AND reviewed_at >= CURRENT_DATE",
            (org_id,),
        )
        rejected_today = cursor.fetchone()['cnt']

        # Average review time (hours) for reviewed requests
        cursor.execute("""
            SELECT COALESCE(
                AVG(EXTRACT(EPOCH FROM (reviewed_at - requested_at)) / 3600.0),
                0
            ) AS avg_hours
            FROM approval_requests
            WHERE organization_id = %s AND reviewed_at IS NOT NULL
        """, (org_id,))
        avg_hours = round(cursor.fetchone()['avg_hours'], 1)

        # Top pending (5 most urgent)
        cursor.execute("""
            SELECT request_ref, identity_display_name, action_type,
                   risk_reduction_score, requested_at, priority
            FROM approval_requests
            WHERE organization_id = %s AND status = 'pending'
            ORDER BY priority ASC, risk_reduction_score DESC
            LIMIT 5
        """, (org_id,))
        top_pending = []
        for r in cursor.fetchall():
            d = dict(r)
            d['requested_at'] = d['requested_at'].isoformat() if d.get('requested_at') else None
            top_pending.append(d)

        cursor.close()
        db.close()

        return jsonify({
            'pending': pending,
            'approved_today': approved_today,
            'rejected_today': rejected_today,
            'high_priority_pending': high_priority,
            'avg_review_time_hours': avg_hours,
            'top_pending': top_pending,
        })

    except Exception as e:
        logger.error("get_approvals_summary failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


# ═══════════════════════════════════════════════════
# W3 EXECUTION ENDPOINTS
# ═══════════════════════════════════════════════════

def execute_approval_request(request_ref):
    """POST /api/approvals/<ref>/execute — execute an approved request."""
    db = _db()
    org_id = _org_id()
    body = request.get_json(silent=True) or {}
    dry_run = body.get('dry_run', True)

    # Safety: require explicit confirmation for live execution
    if not dry_run:
        if not body.get('confirm_live', False):
            return jsonify({
                'error': 'Live execution requires "confirm_live": true',
                'hint': 'Run dry_run=true first to preview impact',
            }), 400

    try:
        # Get Azure credentials for this org.
        # For live execution: use remediation SP (has write permissions).
        # For dry-run: credential not needed (simulation only).
        # TWO-SP MODEL:
        #   discovery SP  (client_id)            → read-only, never writes
        #   remediation SP (remediation_client_id) → User Access Admin, writes only
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT
                client_id,
                azure_directory_id,
                metadata,
                remediation_client_id,
                remediation_client_secret,
                remediation_tenant_id,
                remediation_enabled
            FROM cloud_connections
            WHERE organization_id = %s
              AND status = 'connected'
              AND cloud = 'azure'
            LIMIT 1
        """, (org_id,))
        conn_row = cursor.fetchone()
        cursor.close()

        credential = None
        if conn_row and not dry_run:
            try:
                from azure.identity import ClientSecretCredential

                # Use remediation SP if configured, else fall back to
                # discovery SP (will likely fail with AuthorizationFailed
                # for write operations — correct behavior)
                rem_enabled = conn_row.get('remediation_enabled', False)
                rem_client_id = conn_row.get('remediation_client_id', '')
                rem_client_secret = conn_row.get(
                    'remediation_client_secret', '')
                rem_tenant_id = conn_row.get(
                    'remediation_tenant_id', '') or                     conn_row['azure_directory_id']

                if rem_enabled and rem_client_id and rem_client_secret:
                    # Remediation SP — has User Access Administrator role
                    credential = ClientSecretCredential(
                        tenant_id=rem_tenant_id,
                        client_id=rem_client_id,
                        client_secret=rem_client_secret,
                    )
                    logger.info(
                        "Using remediation SP for live execution "
                        "(org=%s, client=%s...)",
                        org_id, rem_client_id[:8])
                else:
                    # Fallback to discovery SP (read-only)
                    # This will fail for write operations — expected
                    meta = conn_row.get('metadata') or {}
                    if isinstance(meta, str):
                        meta = json.loads(meta)
                    client_secret = meta.get('client_secret', '')
                    credential = ClientSecretCredential(
                        tenant_id=conn_row['azure_directory_id'],
                        client_id=conn_row['client_id'],
                        client_secret=client_secret,
                    )
                    logger.warning(
                        "Remediation SP not configured for org=%s — "
                        "using discovery SP (write operations will fail)",
                        org_id)
            except Exception as e:
                logger.warning("Azure credential init failed: %s", e)

        from app.engines.execution.executor import ExecutionService
        svc = ExecutionService(
            db=db,
            org_id=org_id,
            credential=credential,
            worker_id='api-worker',
            user_id=_user_id(),
        )

        result = svc.execute_approval(
            request_ref=request_ref,
            dry_run=dry_run,
        )

        db.close()
        status_code = 400 if 'error' in result else 200
        return jsonify(result), status_code

    except Exception as e:
        logger.error("execute_approval_request failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def get_execution_history(request_ref):
    """GET /api/approvals/<ref>/execution-history — list runs for a request."""
    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, execution_mode, action_type, identity_id,
                   worker_id, started_by, started_at, completed_at,
                   duration_ms, outcome, arm_request_id,
                   result_payload, error_code, error_message,
                   rollback_of, can_rollback
            FROM execution_runs
            WHERE organization_id = %s AND approval_ref = %s
            ORDER BY started_at DESC
        """, (_org_id(), request_ref))
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        runs = []
        for r in rows:
            d = dict(r)
            for ts in ('started_at', 'completed_at'):
                if d.get(ts):
                    d[ts] = d[ts].isoformat()
            runs.append(d)

        return jsonify({'runs': runs, 'total': len(runs)})

    except Exception as e:
        logger.error("get_execution_history failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def rollback_execution(request_ref):
    """POST /api/approvals/<ref>/rollback — rollback a successfully executed action."""
    db = _db()
    org_id = _org_id()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)

        # Find latest rollbackable run
        cursor.execute("""
            SELECT id, action_type, action_payload, identity_id,
                   rollback_payload
            FROM execution_runs
            WHERE organization_id = %s
              AND approval_ref = %s
              AND can_rollback = true
              AND outcome = 'success'
            ORDER BY started_at DESC
            LIMIT 1
        """, (org_id, request_ref))
        run = cursor.fetchone()
        if not run:
            cursor.close()
            db.close()
            return jsonify({'error': 'No rollbackable execution found'}), 404

        if not run['rollback_payload']:
            cursor.close()
            db.close()
            return jsonify({'error': 'No rollback payload stored'}), 400

        rollback_payload = run['rollback_payload']
        if isinstance(rollback_payload, str):
            import json as _json
            rollback_payload = _json.loads(rollback_payload)

        # ─────────────────────────────────────────────────
        # EXECUTE THE ARM RESTORE CALL before state change
        # restore_role: PUT /roleAssignments/{id}
        # ─────────────────────────────────────────────────
        arm_error = None
        arm_success = False
        import time as _time
        start_ms = int(_time.time() * 1000)

        action = rollback_payload.get('action', '')
        if action == 'restore_role':
            try:
                # Get remediation credentials
                cred_cursor = db.conn.cursor(
                    cursor_factory=RealDictCursor)
                cred_cursor.execute("""
                    SELECT
                        remediation_client_id,
                        remediation_client_secret,
                        remediation_tenant_id,
                        azure_directory_id,
                        client_id,
                        metadata,
                        remediation_enabled
                    FROM cloud_connections
                    WHERE organization_id = %s
                      AND status = 'connected'
                      AND cloud = 'azure'
                    LIMIT 1
                """, (org_id,))
                conn_row = cred_cursor.fetchone()
                cred_cursor.close()

                if conn_row:
                    from azure.identity import                         ClientSecretCredential
                    from azure.mgmt.authorization import                         AuthorizationManagementClient
                    from azure.mgmt.authorization.models import                         RoleAssignment,                         RoleAssignmentCreateParameters

                    rem_enabled = conn_row.get(
                        'remediation_enabled', False)
                    rem_cid = conn_row.get(
                        'remediation_client_id', '')
                    rem_secret = conn_row.get(
                        'remediation_client_secret', '')
                    rem_tid = conn_row.get(
                        'remediation_tenant_id', '') or                         conn_row['azure_directory_id']

                    if rem_enabled and rem_cid and rem_secret:
                        credential = ClientSecretCredential(
                            tenant_id=rem_tid,
                            client_id=rem_cid,
                            client_secret=rem_secret,
                        )
                    else:
                        meta = conn_row.get('metadata') or {}
                        if isinstance(meta, str):
                            import json as _j
                            meta = _j.loads(meta)
                        credential = ClientSecretCredential(
                            tenant_id=conn_row[
                                'azure_directory_id'],
                            client_id=conn_row['client_id'],
                            client_secret=meta.get(
                                'client_secret', ''),
                        )

                    # Extract subscription from scope
                    scope = rollback_payload.get('scope', '')
                    parts = scope.split('/')
                    sub_id = parts[2]                         if len(parts) > 2 else None
                    assignment_id = rollback_payload.get(
                        'assignment_id', '')
                    identity_id = rollback_payload.get(
                        'identity_id', '')

                    # Extract just the GUID from full path
                    guid = assignment_id.split('/')[-1]                         if '/' in assignment_id else                         assignment_id

                    if sub_id and guid and identity_id:
                        # Need role definition ID for the role
                        # First look up the role definition
                        auth_client =                             AuthorizationManagementClient(
                                credential, sub_id)

                        role_name = rollback_payload.get(
                            'role_name', '')

                        # Find role definition ID
                        role_def_id = None
                        for rd in auth_client                                .role_definitions                                .list(scope=scope):
                            if rd.role_name == role_name:
                                role_def_id = rd.id
                                break

                        if role_def_id:
                            # Restore the role assignment
                            auth_client                                .role_assignments                                .create(
                                    scope=scope,
                                    role_assignment_name=guid,
                                    parameters=                                        RoleAssignmentCreateParameters(
                                            role_definition_id=                                                role_def_id,
                                            principal_id=                                                identity_id,
                                        )
                                )
                            arm_success = True
                            logger.info(
                                "Rollback ARM call succeeded: "
                                "restored %s role for %s",
                                role_name, identity_id)
                        else:
                            arm_error = (
                                f"Role definition '{role_name}'"
                                f" not found at scope {scope}")
                    else:
                        arm_error = (
                            "Missing scope, assignment_id "
                            "or identity_id in rollback_payload")
                else:
                    arm_error = "No connector found for org"

            except Exception as e:
                arm_error = f"ARM restore error: {str(e)}"
                logger.error("Rollback ARM call failed: %s", e)
        else:
            # Non-ARM rollback actions (future: disable→enable etc)
            # Mark as success — caller handles manually
            arm_success = True
            logger.warning(
                "Rollback action '%s' has no ARM handler — "
                "marked successful, verify manually", action)

        duration_ms = int(_time.time() * 1000) - start_ms

        if not arm_success and arm_error:
            return jsonify({
                'error': f'ARM rollback failed: {arm_error}',
                'request_ref': request_ref,
                'rollback_payload': rollback_payload,
            }), 500

        # ─────────────────────────────────────────────────
        # ARM restore succeeded — now update state
        # ─────────────────────────────────────────────────

        # Transition approval to rolled_back
        try:
            t = transition_approval(
                db=db, request_ref=request_ref, org_id=org_id,
                to_status='rolled_back',
            )
            prev_status = t['previous_status']
        except ValueError as e:
            cursor.close()
            db.close()
            return jsonify({'error': str(e)}), 409

        # Record rollback execution run
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO execution_runs (
                organization_id, approval_ref, execution_mode,
                action_type, action_payload, identity_id,
                worker_id, started_by, completed_at,
                duration_ms, outcome, rollback_of, can_rollback
            ) VALUES (
                %s, %s, 'rollback', %s, %s::jsonb, %s,
                'api-worker', %s, NOW(), %s, 'rolled_back',
                %s, false
            ) RETURNING id
        """, (
            org_id, request_ref,
            run['action_type'],
            json.dumps(rollback_payload),
            run['identity_id'],
            _user_id(),
            duration_ms,
            run['id'],
        ))
        rollback_run_id = cursor.fetchone()['id']

        # Mark original run as no longer rollbackable
        cursor.execute(
            "UPDATE execution_runs "
            "SET can_rollback = false WHERE id = %s",
            (run['id'],),
        )
        db.conn.commit()
        cursor.close()

        # Audit
        audit = AuditService(db, org_id, _user_id())
        audit.log(
            event_type='remediation.executed',
            action=f'Rolled back: {request_ref} '
                   f'({rollback_payload.get("action","")})',
            outcome='success',
            target_type='identity',
            target_id=run['identity_id'],
            before_state={'status': prev_status},
            after_state={
                'status': 'rolled_back',
                'rollback_run_id': rollback_run_id,
                'arm_success': arm_success,
            },
        )

        db.close()
        return jsonify({
            'request_ref': request_ref,
            'rollback_run_id': rollback_run_id,
            'original_run_id': run['id'],
            'status': 'rolled_back',
            'arm_success': arm_success,
            'message': f'Restored {rollback_payload.get("role_name","")} '
                       f'role for '
                       f'{run["identity_id"][:16]}...',
            'duration_ms': duration_ms,
        })

    except Exception as e:
        logger.error("rollback_execution failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def get_execution_queue():
    """GET /api/execution/queue — view approved/queued items in execution order."""
    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            SELECT id, request_ref, identity_id, identity_display_name,
                   action_type, action_payload, risk_reduction_score,
                   status, priority, requested_by, requested_at,
                   reviewed_by, reviewed_at
            FROM approval_requests
            WHERE organization_id = %s
              AND status IN ('approved', 'queued')
            {EXECUTION_ORDER_SQL}
            LIMIT 50
            FOR UPDATE SKIP LOCKED
        """, (_org_id(),))
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        return jsonify({
            'requests': [_format_request(r) for r in rows],
            'total': len(rows),
        })

    except Exception as e:
        logger.error("get_execution_queue failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


# ═══════════════════════════════════════════════════
# AUDIT LOG ENDPOINTS
# ═══════════════════════════════════════════════════

def get_audit_log():
    """GET /api/audit-log — paginated audit events."""
    event_type = request.args.get('event_type')
    target_type = request.args.get('target_type')
    target_id = request.args.get('target_id')
    actor_user_id = request.args.get('actor_user_id', type=int)
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        org_id = _org_id()

        where = ["organization_id = %s"]
        params = [org_id]

        if event_type:
            where.append("event_type = %s")
            params.append(event_type)
        if target_type:
            where.append("target_type = %s")
            params.append(target_type)
        if target_id:
            where.append("target_id = %s")
            params.append(target_id)
        if actor_user_id:
            where.append("actor_user_id = %s")
            params.append(actor_user_id)
        if from_date:
            where.append("created_at >= %s")
            params.append(from_date)
        if to_date:
            where.append("created_at <= %s")
            params.append(to_date)

        where_sql = " AND ".join(where)

        cursor.execute(f"SELECT COUNT(*) AS cnt FROM platform_audit_log WHERE {where_sql}", params)
        total = cursor.fetchone()['cnt']

        cursor.execute(f"""
            SELECT id, event_type, actor_user_id, actor_display_name, actor_role,
                   target_type, target_id, target_display_name,
                   action, outcome, before_state, after_state, metadata,
                   ip_address, created_at
            FROM platform_audit_log
            WHERE {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        events = []
        for r in rows:
            d = dict(r)
            d['created_at'] = d['created_at'].isoformat() if d.get('created_at') else None
            events.append(d)

        return jsonify({'total': total, 'events': events})

    except Exception as e:
        logger.error("get_audit_log failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def get_audit_log_for_identity(identity_id):
    """GET /api/audit-log/identity/<identity_id> — all events for an identity."""
    limit = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        org_id = _org_id()

        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM platform_audit_log "
            "WHERE organization_id = %s AND target_id = %s",
            (org_id, identity_id),
        )
        total = cursor.fetchone()['cnt']

        cursor.execute("""
            SELECT id, event_type, actor_display_name, actor_role,
                   action, outcome, after_state, metadata, created_at
            FROM platform_audit_log
            WHERE organization_id = %s AND target_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (org_id, identity_id, limit, offset))
        rows = cursor.fetchall()
        cursor.close()
        db.close()

        events = []
        for r in rows:
            d = dict(r)
            d['created_at'] = d['created_at'].isoformat() if d.get('created_at') else None
            events.append(d)

        return jsonify({'total': total, 'events': events})

    except Exception as e:
        logger.error("get_audit_log_for_identity failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500


def get_audit_log_summary():
    """GET /api/audit-log/summary — aggregate counts."""
    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        org_id = _org_id()

        # Events today
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM platform_audit_log "
            "WHERE organization_id = %s AND created_at >= CURRENT_DATE",
            (org_id,),
        )
        events_today = cursor.fetchone()['cnt']

        # Events this week
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM platform_audit_log "
            "WHERE organization_id = %s AND created_at >= CURRENT_DATE - INTERVAL '7 days'",
            (org_id,),
        )
        events_week = cursor.fetchone()['cnt']

        # Approvals today
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM platform_audit_log "
            "WHERE organization_id = %s AND event_type LIKE 'approval.%%' "
            "AND created_at >= CURRENT_DATE",
            (org_id,),
        )
        approvals_today = cursor.fetchone()['cnt']

        # Logins today
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM platform_audit_log "
            "WHERE organization_id = %s AND event_type = 'user.login' "
            "AND created_at >= CURRENT_DATE",
            (org_id,),
        )
        logins_today = cursor.fetchone()['cnt']

        # Top actors (last 7 days)
        cursor.execute("""
            SELECT actor_display_name, COUNT(*) AS event_count
            FROM platform_audit_log
            WHERE organization_id = %s AND created_at >= CURRENT_DATE - INTERVAL '7 days'
              AND actor_display_name IS NOT NULL
            GROUP BY actor_display_name
            ORDER BY event_count DESC
            LIMIT 5
        """, (org_id,))
        top_actors = [dict(r) for r in cursor.fetchall()]

        # Recent critical (failures)
        cursor.execute("""
            SELECT event_type, action, outcome, actor_display_name, created_at
            FROM platform_audit_log
            WHERE organization_id = %s AND outcome = 'failure'
            ORDER BY created_at DESC
            LIMIT 5
        """, (org_id,))
        recent_critical = []
        for r in cursor.fetchall():
            d = dict(r)
            d['created_at'] = d['created_at'].isoformat() if d.get('created_at') else None
            recent_critical.append(d)

        cursor.close()
        db.close()

        return jsonify({
            'events_today': events_today,
            'events_this_week': events_week,
            'approvals_today': approvals_today,
            'logins_today': logins_today,
            'top_actors': top_actors,
            'recent_critical': recent_critical,
        })

    except Exception as e:
        logger.error("get_audit_log_summary failed: %s", e)
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': 'Internal server error'}), 500
