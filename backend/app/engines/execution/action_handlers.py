"""
W3 Action Handlers — maps action_type → ARM call.
Each handler is pure: takes payload, returns ActionResult.
"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


class ActionResult:
    """Uniform result from any action handler."""

    def __init__(self, success: bool, message: str,
                 arm_request_id: str = None,
                 can_rollback: bool = False,
                 rollback_payload: dict = None,
                 simulated: bool = False):
        self.success = success
        self.message = message
        self.arm_request_id = arm_request_id
        self.can_rollback = can_rollback
        self.rollback_payload = rollback_payload
        self.simulated = simulated

    def to_dict(self) -> dict:
        return {
            'success': self.success,
            'message': self.message,
            'arm_request_id': self.arm_request_id,
            'can_rollback': self.can_rollback,
            'rollback_payload': self.rollback_payload,
            'simulated': self.simulated,
        }


class ExecutionHandler:
    """Base class for action handlers."""

    def __init__(self, credential, dry_run: bool):
        self.credential = credential
        self.dry_run = dry_run

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        raise NotImplementedError

    def _simulate(self, action_desc: str,
                  can_rollback: bool = True,
                  rollback_payload: dict = None) -> ActionResult:
        return ActionResult(
            success=True,
            message=f"[DRY-RUN] Would: {action_desc}",
            can_rollback=can_rollback,
            rollback_payload=rollback_payload,
            simulated=True,
        )


class RemoveRoleHandler(ExecutionHandler):
    """Removes an Azure RBAC role assignment."""

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        scope = payload.get('scope', '')
        assignment_id = payload.get('assignment_id')
        role_name = payload.get('role_name', '')

        if not assignment_id:
            return ActionResult(
                success=False,
                message="assignment_id required for remove_role")

        rollback = {
            'action': 'restore_role',
            'assignment_id': assignment_id,
            'scope': scope,
            'role_name': role_name,
            'identity_id': identity_id,
        }

        if self.dry_run:
            return self._simulate(
                f"Remove role '{role_name}' from {identity_id} at scope {scope}",
                can_rollback=True,
                rollback_payload=rollback,
            )

        try:
            from azure.mgmt.authorization import AuthorizationManagementClient

            parts = scope.split('/')
            sub_id = parts[2] if len(parts) > 2 else None
            if not sub_id:
                return ActionResult(
                    success=False,
                    message=f"Cannot extract subscription from scope: {scope}")

            client = AuthorizationManagementClient(self.credential, sub_id)
            client.role_assignments.delete_by_id(assignment_id)

            return ActionResult(
                success=True,
                message=f"Removed role '{role_name}' from {identity_id}",
                can_rollback=True,
                rollback_payload=rollback,
            )
        except Exception as e:
            return ActionResult(success=False, message=f"ARM error: {e}")


class AssignOwnerHandler(ExecutionHandler):
    """Assigns an owner to an orphaned identity."""

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        owner_id = payload.get('owner_id')
        owner_upn = payload.get('owner_upn', '')

        if not owner_id:
            return ActionResult(
                success=False,
                message="owner_id required for assign_owner")

        if self.dry_run:
            return self._simulate(
                f"Assign owner {owner_upn} ({owner_id}) to {identity_id}",
                can_rollback=True,
                rollback_payload={
                    'action': 'remove_owner',
                    'owner_id': owner_id,
                    'identity_id': identity_id,
                },
            )

        return ActionResult(
            success=False,
            message="assign_owner live execution not yet implemented — use dry_run=true")


class DisableIdentityHandler(ExecutionHandler):
    """Disables an Entra identity."""

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        reason = payload.get('reason', 'security_remediation')

        if self.dry_run:
            return self._simulate(
                f"Disable identity {identity_id} (reason: {reason})",
                can_rollback=True,
                rollback_payload={
                    'action': 'enable_identity',
                    'identity_id': identity_id,
                },
            )

        return ActionResult(
            success=False,
            message="disable_identity live execution not yet implemented")


class RevokeCredentialHandler(ExecutionHandler):
    """Revokes a credential (secret/certificate)."""

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        cred_id = payload.get('credential_id') or payload.get('cred_id')

        if not cred_id:
            return ActionResult(
                success=False,
                message="credential_id required for revoke_credential")

        if self.dry_run:
            return self._simulate(
                f"Revoke credential {cred_id} for {identity_id}",
                can_rollback=False,
            )

        return ActionResult(
            success=False,
            message="revoke_credential live execution not yet implemented")


class ScopeReductionHandler(ExecutionHandler):
    """Reduces scope of a role assignment."""

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        current_scope = payload.get('current_scope', '')
        target_scope = payload.get('target_scope', '')

        if not current_scope or not target_scope:
            return ActionResult(
                success=False,
                message="current_scope and target_scope required")

        if self.dry_run:
            return self._simulate(
                f"Reduce scope for {identity_id} from {current_scope} to {target_scope}",
                can_rollback=True,
                rollback_payload={
                    'action': 'restore_scope',
                    'identity_id': identity_id,
                    'original_scope': current_scope,
                },
            )

        return ActionResult(
            success=False,
            message="scope_reduction live execution not yet implemented")


class EnablePimHandler(ExecutionHandler):
    """Enables PIM (Privileged Identity Management) for a role."""

    def execute(self, payload: dict, identity_id: str) -> ActionResult:
        role = payload.get('role', '')

        if self.dry_run:
            return self._simulate(
                f"Enable PIM for role '{role}' on {identity_id}",
                can_rollback=True,
                rollback_payload={
                    'action': 'disable_pim',
                    'identity_id': identity_id,
                    'role': role,
                },
            )

        return ActionResult(
            success=False,
            message="enable_pim live execution not yet implemented")


# Registry: action_type → handler class
ACTION_REGISTRY: Dict[str, type] = {
    'remove_role':       RemoveRoleHandler,
    'assign_owner':      AssignOwnerHandler,
    'disable_identity':  DisableIdentityHandler,
    'revoke_credential': RevokeCredentialHandler,
    'scope_reduction':   ScopeReductionHandler,
    'enable_pim':        EnablePimHandler,
}


def get_handler(action_type: str, credential, dry_run: bool) -> ExecutionHandler:
    """Get the handler for an action type."""
    handler_class = ACTION_REGISTRY.get(action_type)
    if not handler_class:
        raise ValueError(
            f"Unknown action_type: {action_type}. "
            f"Registered: {list(ACTION_REGISTRY.keys())}")
    return handler_class(credential, dry_run)
