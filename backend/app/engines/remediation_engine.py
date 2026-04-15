"""Phase 12: Automated Remediation Engine.

Executes remediation actions tied to policy recommendations.
Supports approval workflow and safety guards.
"""

import logging

logger = logging.getLogger(__name__)

# Supported remediation action types
SUPPORTED_ACTIONS = {
    'rotate_service_principal_secret',
    'remove_role_assignment',
    'disable_identity',
    'reduce_identity_privilege',
}

# Recommendation type → default action type mapping
RECOMMENDATION_ACTION_MAP = {
    'service_principal_secret_rotation': 'rotate_service_principal_secret',
    'excess_privilege_identity': 'reduce_identity_privilege',
    'guest_user_privilege_review': 'remove_role_assignment',
    'unused_identity_cleanup': 'disable_identity',
    'service_principal_excess_privilege': 'reduce_identity_privilege',
}


class RemediationEngine:
    """Executes remediation actions against cloud environments."""

    def __init__(self, db):
        self.db = db

    def create_remediation_action(self, recommendation_id, org_id, requested_by=None):
        """Create a remediation action from a policy recommendation.

        Returns the created action dict or None if recommendation not found.
        Determines action_type from the recommendation's type.
        Respects remediation_mode setting (automatic vs approval_required).
        """
        rec = self.db.get_policy_recommendation_by_id(recommendation_id)
        if not rec:
            return None

        action_type = RECOMMENDATION_ACTION_MAP.get(
            rec['recommendation_type'], 'reduce_identity_privilege'
        )

        # Check remediation mode
        remediation_mode = self._get_remediation_mode()
        initial_status = 'pending' if remediation_mode == 'approval_required' else 'approved'

        action = self.db.create_auto_remediation_action(
            org_id=org_id,
            connection_id=rec['cloud_connection_id'],
            recommendation_id=recommendation_id,
            action_type=action_type,
            status=initial_status,
            requested_by=requested_by or 'system',
            metadata={
                'recommendation_type': rec['recommendation_type'],
                'identity_id': rec.get('identity_id'),
                'severity': rec['severity'],
                'description': rec.get('description'),
            },
        )

        # Auto-execute if mode is automatic
        if initial_status == 'approved' and action:
            self.execute_remediation(action['id'])

        return action

    def approve_action(self, action_id, approved_by=None):
        """Approve a pending remediation action."""
        action = self.db.get_auto_remediation_action_by_id(action_id)
        if not action:
            return None
        if action['status'] != 'pending':
            return {'error': f"Cannot approve action in '{action['status']}' status"}

        self.db.update_auto_remediation_action(
            action_id, status='approved', approved_by=approved_by
        )
        return self.db.get_auto_remediation_action_by_id(action_id)

    def execute_remediation(self, action_id):
        """Execute a remediation action.

        Workflow:
        1. Retrieve action and validate status
        2. Run safety guards
        3. Execute cloud API action (simulated)
        4. Update status to completed/failed
        5. Log audit trail
        """
        action = self.db.get_auto_remediation_action_by_id(action_id)
        if not action:
            return {'error': 'Action not found'}

        if action['status'] not in ('approved',):
            return {'error': f"Cannot execute action in '{action['status']}' status"}

        # Mark as executing
        self.db.update_auto_remediation_action(action_id, status='executing')

        try:
            # Safety guard check
            safety_result = self._check_safety_guards(action)
            if not safety_result['safe']:
                self.db.update_auto_remediation_action(
                    action_id, status='failed',
                    result_message=f"Safety guard blocked: {safety_result['reason']}"
                )
                return {'status': 'failed', 'reason': safety_result['reason']}

            # Execute the action (simulated for now)
            result = self._execute_action(action)

            if result['success']:
                self.db.update_auto_remediation_action(
                    action_id, status='completed',
                    result_message=result.get('message', 'Action completed successfully')
                )
                # Update linked recommendation to resolved
                if action.get('recommendation_id'):
                    self.db.update_policy_recommendation_status(
                        action['recommendation_id'], 'resolved'
                    )
                logger.info(f"Remediation action {action_id} completed: {action['action_type']}")
            else:
                self.db.update_auto_remediation_action(
                    action_id, status='failed',
                    result_message=result.get('message', 'Action failed')
                )
                logger.error(f"Remediation action {action_id} failed: {result.get('message')}")

            return result

        except Exception as e:
            self.db.update_auto_remediation_action(
                action_id, status='failed',
                result_message=str(e)
            )
            logger.error(f"Remediation action {action_id} exception: {e}")
            return {'success': False, 'message': str(e)}

    def _get_remediation_mode(self):
        """Get remediation mode from settings."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT value FROM settings WHERE key = 'remediation_mode'"
            )
            row = cursor.fetchone()
            cursor.close()
            return row[0] if row else 'approval_required'
        except Exception:
            return 'approval_required'

    def _check_safety_guards(self, action):
        """Check safety guards before executing remediation.

        Prevents dangerous actions like removing the last Owner.
        """
        metadata = action.get('metadata', {})
        action_type = action['action_type']

        # Guard: Do not remove Owner role if no other admin exists
        if action_type in ('remove_role_assignment', 'reduce_identity_privilege'):
            identity_id = metadata.get('identity_id')
            if identity_id:
                try:
                    owner_count = self._count_owners_for_connection(
                        action['cloud_connection_id']
                    )
                    if owner_count <= 1:
                        return {
                            'safe': False,
                            'reason': 'Cannot remove last Owner — at least one admin must remain',
                        }
                except Exception as e:
                    logger.warning(f"Safety guard check failed: {e}")

        return {'safe': True, 'reason': None}

    def _count_owners_for_connection(self, connection_id):
        """Count identities with Owner role for a connection."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT COUNT(DISTINCT i.identity_id)
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE dr.cloud_connection_id = %s
              AND dr.status = 'completed'
              AND ra.role_name = 'Owner'
              AND i.discovery_run_id = (
                  SELECT id FROM discovery_runs
                  WHERE cloud_connection_id = %s AND status = 'completed'
                  ORDER BY id DESC LIMIT 1
              )
        """, (connection_id, connection_id))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else 0

    def _execute_action(self, action):
        """Execute a cloud remediation action.

        Currently simulated — returns success for all supported action types.
        In production, this would call Azure/AWS/GCP APIs.
        """
        action_type = action['action_type']
        metadata = action.get('metadata', {})

        if action_type not in SUPPORTED_ACTIONS:
            return {
                'success': False,
                'message': f"Unsupported action type: {action_type}",
            }

        # Simulated execution for each action type
        if action_type == 'rotate_service_principal_secret':
            return {
                'success': True,
                'message': f"[Simulated] Rotated secret for {metadata.get('identity_id', 'unknown')}",
                'simulated': True,
            }
        elif action_type == 'remove_role_assignment':
            return {
                'success': True,
                'message': f"[Simulated] Removed role assignment for {metadata.get('identity_id', 'unknown')}",
                'simulated': True,
            }
        elif action_type == 'disable_identity':
            return {
                'success': True,
                'message': f"[Simulated] Disabled identity {metadata.get('identity_id', 'unknown')}",
                'simulated': True,
            }
        elif action_type == 'reduce_identity_privilege':
            return {
                'success': True,
                'message': f"[Simulated] Reduced privileges for {metadata.get('identity_id', 'unknown')}",
                'simulated': True,
            }

        return {'success': False, 'message': 'Unknown action type'}
