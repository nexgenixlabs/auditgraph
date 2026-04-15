"""
Ghost Identity Detector

Finds disabled or deleted identities that still retain active role assignments.
These "zombie permissions" represent a critical security risk — an attacker
who compromises or re-enables such an account inherits all its roles.

Produces anomalies of type 'ghost_identity' (critical or high severity).
"""
import logging
from typing import Dict, List
from app.database import Database

logger = logging.getLogger(__name__)


class GhostIdentityDetector:
    """Detect disabled/deleted identities with active role assignments."""

    def __init__(self, db: Database):
        self.db = db

    def detect(self, run_id: int) -> List[Dict]:
        """
        Scan identities from the given run for ghost permissions.

        Returns list of anomaly dicts ready for save_anomalies().
        """
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT
                    i.id,
                    i.identity_id,
                    i.display_name,
                    i.enabled,
                    i.status,
                    i.deleted_at,
                    (SELECT COUNT(*) FROM role_assignments ra WHERE ra.identity_db_id = i.id) as rbac_count,
                    (SELECT COUNT(*) FROM entra_role_assignments era WHERE era.identity_db_id = i.id) as entra_count,
                    (SELECT array_agg(DISTINCT ra.role_name) FROM role_assignments ra WHERE ra.identity_db_id = i.id) as rbac_roles,
                    (SELECT array_agg(DISTINCT era.role_name) FROM entra_role_assignments era WHERE era.identity_db_id = i.id) as entra_roles
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND (
                      i.enabled = false
                      OR i.deleted_at IS NOT NULL
                  )
                  AND (
                      EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                      OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                  )
            """, (run_id,))

            anomalies = []
            for row in cursor.fetchall():
                db_id, identity_id, display_name, enabled, status, deleted_at, \
                    rbac_count, entra_count, rbac_roles, entra_roles = row

                total_roles = (rbac_count or 0) + (entra_count or 0)
                all_role_names = []
                if rbac_roles:
                    all_role_names.extend(rbac_roles)
                if entra_roles:
                    all_role_names.extend(entra_roles)

                # Determine account state for description
                if deleted_at is not None:
                    account_state = 'deleted'
                elif enabled is False:
                    account_state = 'disabled'
                else:
                    account_state = status or 'unknown'

                # Critical if has high-privilege roles, high otherwise
                critical_role_names = {
                    'Global Administrator', 'Privileged Role Administrator',
                    'Owner', 'User Access Administrator', 'Contributor',
                    'Application Administrator',
                }
                has_critical = any(r in critical_role_names for r in all_role_names)
                severity = 'critical' if has_critical else 'high'

                anomalies.append({
                    'anomaly_type': 'ghost_identity',
                    'severity': severity,
                    'identity_id': identity_id,
                    'identity_name': display_name,
                    'title': f'Ghost identity: {display_name} ({account_state}) retains {total_roles} role(s)',
                    'description': (
                        f'{display_name} is {account_state} but still has '
                        f'{rbac_count or 0} RBAC and {entra_count or 0} Entra role assignments. '
                        f'Roles: {", ".join(all_role_names[:5])}'
                        f'{"..." if len(all_role_names) > 5 else ""}'
                    ),
                    'details': {
                        'account_state': account_state,
                        'rbac_count': rbac_count or 0,
                        'entra_count': entra_count or 0,
                        'rbac_roles': rbac_roles or [],
                        'entra_roles': entra_roles or [],
                        'risk_score_modifier': 200,
                    },
                })

            if anomalies:
                logger.info(f"Ghost detector: {len(anomalies)} ghost identities found in run #{run_id}")
            return anomalies

        finally:
            cursor.close()
