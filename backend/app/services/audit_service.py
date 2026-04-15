"""
AuditService — Immutable audit trail writer.

Call log() after every significant platform action.
Never raises — audit failures are logged but never block the primary operation.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AuditService:

    EVENT_TYPES = {
        'identity.scan.started',
        'identity.scan.completed',
        'identity.scan.failed',
        'approval.created',
        'approval.approved',
        'approval.rejected',
        'approval.cancelled',
        'remediation.executed',
        'remediation.failed',
        'connector.added',
        'connector.tested',
        'connector.deleted',
        'subscription.activated',
        'subscription.deactivated',
        'user.login',
        'user.logout',
        'user.invited',
        'user.role_changed',
        'export.created',
        'report.generated',
    }

    def __init__(self, db, org_id: int,
                 user_id: int = None,
                 user_display_name: str = None,
                 user_role: str = None):
        self.db = db
        self.org_id = org_id
        self.user_id = user_id
        self.user_display_name = user_display_name
        self.user_role = user_role

    def log(self,
            event_type: str,
            action: str,
            outcome: str = 'success',
            target_type: str = None,
            target_id: str = None,
            target_display_name: str = None,
            before_state: dict = None,
            after_state: dict = None,
            metadata: dict = None,
            request=None) -> bool:
        """Write an audit event. Never raises."""
        try:
            if event_type not in self.EVENT_TYPES:
                logger.warning("Unknown audit event_type: %s", event_type)

            ip = None
            ua = None
            req_id = None
            if request:
                ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                ua = (request.headers.get('User-Agent') or '')[:512]
                req_id = request.headers.get('X-Request-ID')

            # Restore RLS context — may have been cleared by a prior commit
            # (SET LOCAL is transaction-scoped and resets on COMMIT).
            if hasattr(self.db, 'set_organization_context'):
                self.db.set_organization_context(self.org_id)

            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO platform_audit_log (
                    organization_id, event_type,
                    actor_user_id, actor_display_name, actor_role,
                    target_type, target_id, target_display_name,
                    action, outcome,
                    before_state, after_state, metadata,
                    ip_address, user_agent, request_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                self.org_id,
                event_type,
                self.user_id,
                self.user_display_name,
                self.user_role,
                target_type,
                str(target_id) if target_id else None,
                target_display_name,
                action,
                outcome,
                json.dumps(before_state) if before_state else None,
                json.dumps(after_state) if after_state else None,
                json.dumps(metadata) if metadata else None,
                ip, ua, req_id,
            ))
            self.db.conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error("Audit log write failed: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return False

    @classmethod
    def from_request(cls, db, request, current_user: dict):
        """Convenience constructor from Flask request context."""
        return cls(
            db=db,
            org_id=current_user.get('org_id') or current_user.get('organization_id'),
            user_id=current_user.get('id'),
            user_display_name=current_user.get('display_name', current_user.get('username', '')),
            user_role=current_user.get('role', 'viewer'),
        )
