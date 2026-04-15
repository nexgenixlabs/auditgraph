"""Phase 24: Autonomous Identity Security Operations.

Evaluates active incidents and generates automated response actions
with safety controls (approval gates, hourly rate limits).
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# Response rules: incident_type → list of response actions
RESPONSE_RULES = {
    'credential_compromise': [
        {
            'action': 'rotate_credential',
            'description': 'Rotate compromised credentials',
            'auto_approve': False,
        },
        {
            'action': 'disable_identity',
            'description': 'Disable identity pending investigation',
            'auto_approve': False,
        },
    ],
    'privilege_escalation_attack': [
        {
            'action': 'remove_privileged_role',
            'description': 'Remove escalated privileged role assignment',
            'auto_approve': False,
        },
    ],
    'lateral_movement': [
        {
            'action': 'disable_identity',
            'description': 'Disable identity involved in lateral movement',
            'auto_approve': False,
        },
    ],
    'resource_exposure': [
        {
            'action': 'revert_policy_change',
            'description': 'Revert policy change that exposed resources',
            'auto_approve': False,
        },
    ],
}

# Maximum automated actions per hour per org (safety limit)
MAX_ACTIONS_PER_HOUR = 10

# Actions that require manual approval (critical actions)
CRITICAL_ACTIONS = {'disable_identity', 'remove_privileged_role'}


class SecurityOrchestrator:
    """Autonomous security response orchestrator."""

    def __init__(self, db):
        self.db = db

    def execute_security_responses(self, org_id):
        """Generate response actions for active incidents.

        Steps:
        1. Load active (open/investigating) incidents
        2. Check hourly rate limit
        3. Evaluate response rules per incident
        4. Create pending response actions
        5. Auto-execute non-critical actions if within limits

        Args:
            org_id: Organization ID

        Returns:
            List of created response actions.
        """
        # 1. Load active incidents
        incidents = self.db.get_attack_incidents(status='open', limit=50)
        investigating = self.db.get_attack_incidents(status='investigating', limit=50)
        active_incidents = incidents + investigating

        if not active_incidents:
            return []

        # 2. Check hourly rate limit
        recent_count = self._get_recent_action_count(org_id)
        remaining_budget = max(0, MAX_ACTIONS_PER_HOUR - recent_count)

        if remaining_budget == 0:
            logger.warning(
                f"Rate limit reached for org {org_id}: "
                f"{recent_count} actions in last hour"
            )
            return []

        # 3-4. Evaluate rules and create actions
        created_actions = []
        for incident in active_incidents:
            if len(created_actions) >= remaining_budget:
                break

            incident_type = incident.get('incident_type', '')
            rules = RESPONSE_RULES.get(incident_type, [])

            for rule in rules:
                if len(created_actions) >= remaining_budget:
                    break

                # Check if action already exists for this incident
                if self._action_exists(incident['id'], rule['action']):
                    continue

                action = {
                    'organization_id': org_id,
                    'incident_id': incident['id'],
                    'identity_id': incident.get('identity_id'),
                    'response_action': rule['action'],
                    'status': 'pending',
                    'metadata': {
                        'description': rule['description'],
                        'incident_type': incident_type,
                        'incident_severity': incident.get('severity', 'medium'),
                        'auto_generated': True,
                        'requires_approval': rule['action'] in CRITICAL_ACTIONS,
                    },
                }

                saved = self.db.save_security_response_action(action)
                if saved:
                    created_actions.append(saved)

        logger.info(
            f"Security orchestrator: {len(created_actions)} action(s) "
            f"created for org {org_id}"
        )
        return created_actions

    def approve_action(self, action_id, approved_by):
        """Approve a pending response action.

        Args:
            action_id: UUID of the action
            approved_by: Username of approver

        Returns:
            Updated action dict or None.
        """
        action = self.db.get_security_response_action(action_id)
        if not action:
            return None
        if action['status'] != 'pending':
            return None

        return self.db.update_security_response_action(
            action_id, 'approved', approved_by=approved_by
        )

    def execute_action(self, action_id):
        """Execute an approved (or non-critical pending) response action.

        Actions are simulated — actual cloud operations would be added
        per-provider in production.

        Args:
            action_id: UUID of the action

        Returns:
            Updated action dict or None.
        """
        action = self.db.get_security_response_action(action_id)
        if not action:
            return None

        # Critical actions must be approved first
        if action['response_action'] in CRITICAL_ACTIONS:
            if action['status'] != 'approved':
                return None
        elif action['status'] not in ('pending', 'approved'):
            return None

        try:
            # Simulate execution (real cloud ops would go here)
            result = self._simulate_action(action)

            updated = self.db.update_security_response_action(
                action_id, 'executed',
                metadata_update={
                    'execution_result': result,
                    'executed_at_detail': datetime.now(timezone.utc).isoformat(),
                }
            )
            return updated
        except Exception as e:
            logger.error(f"Action execution failed for {action_id}: {e}")
            self.db.update_security_response_action(
                action_id, 'failed',
                metadata_update={'error': str(e)}
            )
            return None

    def _simulate_action(self, action):
        """Simulate executing a response action.

        Returns:
            Dict with simulation result.
        """
        action_type = action['response_action']
        identity_id = action.get('identity_id', 'unknown')

        simulations = {
            'rotate_credential': {
                'simulated': True,
                'message': f'Credential rotation queued for {identity_id}',
            },
            'disable_identity': {
                'simulated': True,
                'message': f'Identity {identity_id} marked for disable',
            },
            'remove_privileged_role': {
                'simulated': True,
                'message': f'Privileged role removal queued for {identity_id}',
            },
            'revert_policy_change': {
                'simulated': True,
                'message': f'Policy revert queued for {identity_id}',
            },
        }
        return simulations.get(action_type, {'simulated': True, 'message': 'Unknown action'})

    def _get_recent_action_count(self, org_id):
        """Count actions created in the last hour for rate limiting."""
        try:
            return self.db.get_security_response_action_count_recent(org_id)
        except Exception:
            return 0

    def _action_exists(self, incident_id, response_action):
        """Check if a response action already exists for this incident+action."""
        try:
            existing = self.db.get_security_response_actions(
                incident_id=str(incident_id), limit=100
            )
            return any(
                a['response_action'] == response_action
                and a['status'] in ('pending', 'approved', 'executed')
                for a in existing
            )
        except Exception:
            return False
