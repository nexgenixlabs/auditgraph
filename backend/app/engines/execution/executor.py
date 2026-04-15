"""
W3 Execution Service — executes approved remediations safely.
Uses transition_approval() for Phase 1 (job pickup).
Phase 2 (execute + record + finalize) is a single atomic transaction.
"""

import json
import logging
import time

from app.api.routes.approvals import transition_approval
from app.services.audit_service import AuditService
from .action_handlers import get_handler, ActionResult

logger = logging.getLogger(__name__)

BLAST_RADIUS_LIMIT = 50
EXECUTION_TIMEOUT_SECONDS = 30


class ExecutionService:
    """Executes approved remediations safely."""

    def __init__(self, db, org_id: int, credential,
                 worker_id: str = 'api-worker',
                 user_id: int = None):
        self.db = db
        self.org_id = org_id
        self.credential = credential
        self.worker_id = worker_id
        self.user_id = user_id

    def execute_approval(self, request_ref: str,
                         dry_run: bool = True) -> dict:
        """Execute a single approved request.

        Two-phase execution:
          Phase 1: transition_approval() → 'executing' (own commit, atomic pickup)
          Phase 2: handler.execute() + INSERT execution_runs + UPDATE status
                   in a single transaction (both succeed or both roll back)

        Always dry_run=True by default — caller must explicitly
        pass dry_run=False for live execution.
        """
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        try:
            # ── Phase 0: Fetch + validate ──────────────────
            cursor.execute("""
                SELECT * FROM approval_requests
                WHERE request_ref = %s AND organization_id = %s
            """, (request_ref, self.org_id))
            req = cursor.fetchone()
            if not req:
                return {'error': 'Request not found', 'ref': request_ref}
            req = dict(req)

            # Blast radius check (live only)
            blast = req.get('blast_radius_score', 0) or 0
            if blast > BLAST_RADIUS_LIMIT and not dry_run:
                return {
                    'error': 'Blast radius exceeds limit',
                    'blast_radius': blast,
                    'limit': BLAST_RADIUS_LIMIT,
                    'suggestion': 'Run dry_run=true first',
                }

            # ── Phase 1: Acquire job (own transaction) ─────
            # transition_approval() commits internally.
            # If server crashes here: job stays 'executing'.
            # A cleanup job (future) will reset stale executings.
            try:
                t = transition_approval(
                    db=self.db,
                    request_ref=request_ref,
                    org_id=self.org_id,
                    to_status='executing',
                )
                prev_status = t['previous_status']
            except ValueError as e:
                return {'error': str(e), 'ref': request_ref}

            # ── Phase 2: Execute + record (single transaction) ─
            start_ms = int(time.time() * 1000)
            handler = get_handler(
                req['action_type'],
                self.credential,
                dry_run=dry_run,
            )

            try:
                action_result = handler.execute(
                    payload=req['action_payload'] if isinstance(req['action_payload'], dict)
                    else json.loads(req['action_payload']),
                    identity_id=req['identity_id'],
                )
            except Exception as e:
                action_result = ActionResult(
                    success=False,
                    message=str(e),
                    simulated=dry_run,
                )

            duration_ms = int(time.time() * 1000) - start_ms

            # outcome distinguishes dry-run from live:
            #   'simulated' = dry_run (regardless of handler success)
            #   'success'   = live + handler succeeded
            #   'failure'   = live + handler failed
            outcome = 'simulated' if dry_run else (
                'success' if action_result.success else 'failure')

            # Final status: both dry-run and live go to 'executed' on success
            to_status = 'executed' if action_result.success else 'failed'

            try:
                # 2a. INSERT execution_runs (no commit yet)
                cursor.execute("""
                    INSERT INTO execution_runs (
                        organization_id, approval_ref, execution_mode,
                        action_type, action_payload, identity_id,
                        worker_id, started_by, completed_at,
                        duration_ms, outcome, arm_request_id,
                        result_payload, error_message,
                        can_rollback, rollback_payload
                    ) VALUES (
                        %s, %s, %s, %s, %s::jsonb, %s,
                        %s, %s, NOW(), %s, %s, %s,
                        %s::jsonb, %s, %s, %s::jsonb
                    ) RETURNING id
                """, (
                    self.org_id,
                    request_ref,
                    'dry_run' if dry_run else 'live',
                    req['action_type'],
                    json.dumps(req['action_payload'] if isinstance(req['action_payload'], dict)
                               else req['action_payload']),
                    req['identity_id'],
                    self.worker_id,
                    self.user_id,
                    duration_ms,
                    outcome,
                    action_result.arm_request_id,
                    json.dumps(action_result.to_dict()),
                    None if action_result.success else action_result.message,
                    action_result.can_rollback and not dry_run,
                    json.dumps(action_result.rollback_payload)
                    if action_result.rollback_payload else None,
                ))
                run_id = cursor.fetchone()['id']

                # ─────────────────────────────────────────────
                # DIRECT UPDATE — intentional, do not replace
                # with transition_approval() here.
                #
                # Reason: Phase 2 requires INSERT execution_runs
                # and UPDATE approval_requests to be atomic in
                # ONE transaction. transition_approval() commits
                # independently, which would break atomicity.
                #
                # This UPDATE is safe because:
                #   - Status is 'executing' (owned by this worker)
                #   - transition_approval() validated the path
                #     in Phase 1 (approved → executing)
                #   - SKIP LOCKED ensures no other worker holds
                #     this row
                #
                # If you need to change this, read executor.py
                # design notes first.
                # ─────────────────────────────────────────────
                error_msg = None if action_result.success else action_result.message
                cursor.execute("""
                    UPDATE approval_requests
                    SET status = %s,
                        updated_at = NOW(),
                        execution_completed_at = NOW(),
                        execution_error = %s
                    WHERE request_ref = %s
                      AND organization_id = %s
                      AND status = 'executing'
                    RETURNING status
                """, (to_status, error_msg, request_ref, self.org_id))

                if not cursor.fetchone():
                    logger.error(
                        "Final status update failed for %s — "
                        "concurrent modification", request_ref)

                # Single commit: execution_runs + status update
                self.db.conn.commit()

            except Exception as e:
                # Phase 2 failed: rollback both INSERT + UPDATE
                self.db.conn.rollback()
                # Mark as failed in separate transaction
                try:
                    transition_approval(
                        db=self.db,
                        request_ref=request_ref,
                        org_id=self.org_id,
                        to_status='failed',
                        execution_error=str(e),
                    )
                except ValueError:
                    pass
                logger.error("Phase 2 failed for %s: %s", request_ref, e,
                             exc_info=True)
                return {'error': str(e), 'ref': request_ref}

            # ── Audit ─────────────────────────────────────
            audit = AuditService(self.db, self.org_id, self.user_id)
            audit.log(
                event_type='remediation.executed' if action_result.success
                else 'remediation.failed',
                action=(f"{'Simulated' if dry_run else 'Executed'}: "
                        f"{req['action_type']} on "
                        f"{req.get('identity_display_name', req['identity_id'])}"),
                outcome='success' if action_result.success else 'failure',
                target_type='identity',
                target_id=req['identity_id'],
                target_display_name=req.get('identity_display_name'),
                before_state={'status': prev_status},
                after_state={
                    'status': to_status,
                    'execution_run_id': run_id,
                    'dry_run': dry_run,
                    'message': action_result.message,
                },
            )

            return {
                'request_ref': request_ref,
                'execution_run_id': run_id,
                'dry_run': dry_run,
                'outcome': outcome,
                'action_type': req['action_type'],
                'identity_id': req['identity_id'],
                'message': action_result.message,
                'duration_ms': duration_ms,
                'can_rollback': action_result.can_rollback and not dry_run,
                'arm_request_id': action_result.arm_request_id,
            }

        except Exception as e:
            logger.error("Execution error for %s: %s", request_ref, e,
                         exc_info=True)
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return {'error': str(e), 'ref': request_ref}
        finally:
            cursor.close()

    @staticmethod
    def recover_stale_executions(db, stale_threshold_minutes: int = 5) -> int:
        """Reset stale 'executing' jobs back to 'queued'.

        Called from scheduler every 5 minutes. A job is stale if
        status='executing' AND execution_started_at < NOW() - threshold.

        Returns count of recovered jobs.
        """
        cursor = db.conn.cursor()
        try:
            cursor.execute("""
                UPDATE approval_requests
                SET
                  status = CASE
                    WHEN COALESCE(retry_count, 0) + 1 >= COALESCE(max_retries, 3)
                      THEN 'failed_permanent'
                    ELSE 'queued'
                  END,
                  execution_started_at = NULL,
                  execution_worker_id   = NULL,
                  execution_started_by  = NULL,
                  retry_count   = COALESCE(retry_count, 0) + 1,
                  last_retry_at = NOW(),
                  execution_error = CASE
                    WHEN COALESCE(retry_count, 0) + 1 >= COALESCE(max_retries, 3)
                      THEN 'Execution timed out — max retries reached'
                    ELSE 'Recovered from stale execution (>' ||
                         %s::text || ' min timeout)'
                  END,
                  updated_at = NOW()
                WHERE status = 'executing'
                  AND organization_id = current_setting(
                      'app.current_organization_id', true
                  )::integer
                  AND execution_started_at <
                      NOW() - (%s || ' minutes')::interval
                RETURNING
                  request_ref,
                  organization_id,
                  status AS new_status,
                  retry_count,
                  max_retries
            """, (stale_threshold_minutes,
                  str(stale_threshold_minutes)))

            recovered = cursor.fetchall()
            db.conn.commit()

            for row in recovered:
                ref = row[0] if isinstance(row, (tuple, list)) else row['request_ref']
                org = row[1] if isinstance(row, (tuple, list)) else row['organization_id']
                rc = row[2] if isinstance(row, (tuple, list)) else row['retry_count']
                new_status = (row[3] if isinstance(row, (tuple, list))
                              else row.get("new_status", "queued"))
                logger.warning(
                    "Recovered stale job %s (org=%s, retry=%s) → %s",
                    ref, org, rc, new_status)

            return len(recovered)

        except Exception as e:
            try:
                db.conn.rollback()
            except Exception:
                pass
            logger.error("Stale job recovery error: %s", e)
            return 0
        finally:
            cursor.close()
