"""
Remediation Script Generator — AG-20

Generates ready-to-run Azure CLI, PowerShell, and Terraform scripts
populated with real values from the live DB.

AuditGraph NEVER touches the customer's environment directly.
The customer inspects, approves, and runs the script themselves.
"""

import logging
from datetime import datetime, timezone

from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ('azure_cli', 'powershell', 'terraform')

# Role privilege ranking — higher = more privilege
_ROLE_PRIVILEGE_RANK = {
    'owner': 100,
    'user access administrator': 90,
    'contributor': 70,
    'security administrator': 60,
    'key vault administrator': 55,
    'storage blob data owner': 50,
    'storage blob data contributor': 40,
    'reader': 10,
}


def _role_rank(role_name: str) -> int:
    return _ROLE_PRIVILEGE_RANK.get((role_name or '').lower(), 30)


class ScriptGenerator:
    """Generates remediation scripts from live DB data."""

    def __init__(self, db):
        self.db = db

    def generate(self, approval: dict, fmt: str = 'azure_cli') -> str:
        """Generate a remediation script for the given approval request.

        Parameters
        ----------
        approval : dict
            Row from approval_requests (must include identity_id,
            action_type, action_payload, organization_id, pre_fix_score,
            identity_display_name, reviewed_by, reviewed_at, request_ref).
        fmt : str
            One of SUPPORTED_FORMATS.

        Returns
        -------
        str
            The full script text.
        """
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {fmt}. Use one of {SUPPORTED_FORMATS}")

        action_type = (approval.get('action_type') or '').lower()
        identity_id = approval.get('identity_id')
        org_id = approval.get('organization_id')

        # Fetch role assignments from live DB
        roles = self._get_role_assignments(identity_id, org_id)
        if not roles:
            return self._no_roles_script(approval, fmt)

        # Select the target role based on action_type
        payload = approval.get('action_payload') or {}

        if action_type == 'remove_role':
            # If payload specifies an assignment_id, use that
            target_assignment_id = payload.get('assignment_id')
            if target_assignment_id:
                target = next(
                    (r for r in roles if r['assignment_id'] == target_assignment_id),
                    None,
                )
            else:
                # Fall back to highest-privilege role
                target = max(roles, key=lambda r: _role_rank(r['role_name']))
        elif action_type in ('revoke_excessive_role', 'scope_reduction'):
            # Pick the highest-privilege role
            target = max(roles, key=lambda r: _role_rank(r['role_name']))
        else:
            # Default: highest-privilege role
            target = max(roles, key=lambda r: _role_rank(r['role_name']))

        if not target:
            target = max(roles, key=lambda r: _role_rank(r['role_name']))

        ctx = {
            'request_ref': approval.get('request_ref', ''),
            'action_type': approval.get('action_type', ''),
            'display_name': approval.get('identity_display_name', ''),
            'pre_fix_score': approval.get('pre_fix_score', 'N/A'),
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'approver_name': self._resolve_approver(approval.get('reviewed_by')),
            'approved_at': (approval['reviewed_at'].isoformat()
                           if hasattr(approval.get('reviewed_at', ''), 'isoformat')
                           else str(approval.get('reviewed_at', ''))),
            'role_name': target['role_name'],
            'scope': target['scope'],
            'principal_id': target['principal_id'],
            'assignment_id': target['assignment_id'],
            'scope_type': target.get('scope_type', ''),
            'risk_level': target.get('risk_level', ''),
        }

        if action_type == 'scope_reduction':
            return self._scope_reduction_script(ctx, fmt, target, roles)

        return self._remove_role_script(ctx, fmt)

    # ------------------------------------------------------------------
    # Script builders
    # ------------------------------------------------------------------

    def _remove_role_script(self, ctx: dict, fmt: str) -> str:
        if fmt == 'azure_cli':
            return self._remove_role_azure_cli(ctx)
        elif fmt == 'powershell':
            return self._remove_role_powershell(ctx)
        else:
            return self._remove_role_terraform(ctx)

    def _remove_role_azure_cli(self, c: dict) -> str:
        return f"""# AuditGraph Remediation Script — Azure CLI
# Ref: {c['request_ref']}
# Finding: {c['action_type']} for {c['display_name']}
# Risk Score Before: {c['pre_fix_score']}
# Generated: {c['timestamp']}
# Change Ticket Required: YES — attach before execution
# Approved By: {c['approver_name']} at {c['approved_at']}
#
# WHAT THIS DOES:
# Removes the "{c['role_name']}" role assignment for {c['display_name']}
# at scope: {c['scope']}
# Risk level: {c['risk_level']}
#
# HOW TO VERIFY AFTER RUNNING:
# az role assignment list --assignee "{c['principal_id']}" --scope "{c['scope']}"
# (should return empty or reduced list)
#
# HOW TO ROLLBACK (within 24h):
# az role assignment create \\
#   --assignee "{c['principal_id']}" \\
#   --role "{c['role_name']}" \\
#   --scope "{c['scope']}"

az role assignment delete \\
  --ids "{c['assignment_id']}" \\
  --scope "{c['scope']}"
"""

    def _remove_role_powershell(self, c: dict) -> str:
        return f"""# AuditGraph Remediation Script — PowerShell
# Ref: {c['request_ref']}
# Finding: {c['action_type']} for {c['display_name']}
# Risk Score Before: {c['pre_fix_score']}
# Generated: {c['timestamp']}
# Approved By: {c['approver_name']} at {c['approved_at']}

$assignmentId = "{c['assignment_id']}"
$scope = "{c['scope']}"

Remove-AzRoleAssignment `
  -ObjectId "{c['principal_id']}" `
  -RoleDefinitionName "{c['role_name']}" `
  -Scope $scope

# Verify:
Get-AzRoleAssignment -ObjectId "{c['principal_id']}" -Scope $scope
"""

    def _remove_role_terraform(self, c: dict) -> str:
        return f"""# AuditGraph Remediation — Terraform
# Ref: {c['request_ref']}
# Finding: {c['action_type']} for {c['display_name']}
# Generated: {c['timestamp']}
#
# Remove this resource block from your Terraform state:

# resource "azurerm_role_assignment" "to_remove" {{
#   scope                = "{c['scope']}"
#   role_definition_name = "{c['role_name']}"
#   principal_id         = "{c['principal_id']}"
# }}

# Run after removing:
# terraform plan   (verify removal shows in plan)
# terraform apply  (execute)
"""

    def _scope_reduction_script(self, ctx: dict, fmt: str,
                                target: dict, roles: list) -> str:
        """Generate a script that removes a broad-scope role and re-creates
        it at a narrower scope (e.g. subscription → resource group)."""
        # Find the most specific resource-group-scoped role to suggest
        rg_roles = [r for r in roles if r.get('scope_type') == 'resource']
        suggested_scope = rg_roles[0]['scope'].rsplit('/providers/', 1)[0] if rg_roles else ctx['scope']

        if fmt == 'azure_cli':
            return f"""# AuditGraph Remediation Script — Azure CLI (Scope Reduction)
# Ref: {ctx['request_ref']}
# Finding: {ctx['action_type']} for {ctx['display_name']}
# Risk Score Before: {ctx['pre_fix_score']}
# Generated: {ctx['timestamp']}
# Approved By: {ctx['approver_name']} at {ctx['approved_at']}
#
# WHAT THIS DOES:
# 1. Removes the broad "{ctx['role_name']}" role at {ctx['scope_type']} scope
# 2. Re-creates it at a narrower resource-group scope
#
# Step 1: Remove broad assignment
az role assignment delete \\
  --ids "{ctx['assignment_id']}" \\
  --scope "{ctx['scope']}"

# Step 2: Re-create at narrower scope
az role assignment create \\
  --assignee "{ctx['principal_id']}" \\
  --role "{ctx['role_name']}" \\
  --scope "{suggested_scope}"

# Verify:
az role assignment list --assignee "{ctx['principal_id']}" --output table
"""
        elif fmt == 'powershell':
            return f"""# AuditGraph Remediation Script — PowerShell (Scope Reduction)
# Ref: {ctx['request_ref']}
# Finding: {ctx['action_type']} for {ctx['display_name']}
# Risk Score Before: {ctx['pre_fix_score']}
# Generated: {ctx['timestamp']}
# Approved By: {ctx['approver_name']} at {ctx['approved_at']}

# Step 1: Remove broad assignment
Remove-AzRoleAssignment `
  -ObjectId "{ctx['principal_id']}" `
  -RoleDefinitionName "{ctx['role_name']}" `
  -Scope "{ctx['scope']}"

# Step 2: Re-create at narrower scope
New-AzRoleAssignment `
  -ObjectId "{ctx['principal_id']}" `
  -RoleDefinitionName "{ctx['role_name']}" `
  -Scope "{suggested_scope}"

# Verify:
Get-AzRoleAssignment -ObjectId "{ctx['principal_id']}"
"""
        else:
            return f"""# AuditGraph Remediation — Terraform (Scope Reduction)
# Ref: {ctx['request_ref']}
# Finding: {ctx['action_type']} for {ctx['display_name']}
# Generated: {ctx['timestamp']}
#
# Replace broad scope with narrow scope:

# resource "azurerm_role_assignment" "reduced_scope" {{
#   scope                = "{suggested_scope}"
#   role_definition_name = "{ctx['role_name']}"
#   principal_id         = "{ctx['principal_id']}"
# }}

# terraform plan
# terraform apply
"""

    def _no_roles_script(self, approval: dict, fmt: str) -> str:
        return f"""# AuditGraph Remediation Script
# Ref: {approval.get('request_ref', '')}
# No active role assignments found for identity {approval.get('identity_display_name', '')}
# The role may have already been removed or the identity has no RBAC assignments.
# No script action required.
"""

    # ------------------------------------------------------------------
    # DB queries
    # ------------------------------------------------------------------

    def _get_role_assignments(self, identity_id: str, org_id: int) -> list:
        """Fetch live role assignments for the identity."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                SELECT ra.role_name, ra.scope, ra.scope_type, ra.principal_id,
                       ra.assignment_id, ra.risk_level
                FROM role_assignments ra
                JOIN identities i ON ra.identity_db_id = i.id
                WHERE i.identity_id = %s AND ra.organization_id = %s
                ORDER BY ra.created_at DESC
            """, (identity_id, org_id))
            rows = [dict(r) for r in cursor.fetchall()]
            # Deduplicate by assignment_id
            seen = set()
            unique = []
            for r in rows:
                aid = r.get('assignment_id')
                if aid and aid not in seen:
                    seen.add(aid)
                    unique.append(r)
            return unique
        except Exception as e:
            logger.error("_get_role_assignments failed: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return []
        finally:
            cursor.close()

    def _resolve_approver(self, user_id) -> str:
        """Resolve user_id to display name."""
        if not user_id:
            return 'Unknown'
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute(
                "SELECT display_name, username FROM users WHERE id = %s",
                (user_id,),
            )
            row = cursor.fetchone()
            if row:
                return row.get('display_name') or row.get('username') or str(user_id)
            return str(user_id)
        except Exception:
            try:
                self.db.conn.rollback()
            except Exception:
                pass
            return str(user_id)
        finally:
            cursor.close()
