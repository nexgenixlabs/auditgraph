"""
Remediation CLI Generator for orphaned privileged accounts.

Generates Azure CLI, PowerShell, and Graph API commands to disable
orphaned privileged accounts and remove their role assignments.
"""


def generate_remediation_commands(finding_dict):
    """Generate remediation command snippets for an orphaned privileged finding.

    Args:
        finding_dict: Must contain privileged_object_id, privileged_upn, roles, severity.

    Returns:
        dict with azure_cli, powershell, graph_api, and summary keys.
    """
    obj_id = finding_dict.get('privileged_object_id', '<OBJECT_ID>')
    upn = finding_dict.get('privileged_upn', '<UPN>')
    roles = finding_dict.get('roles', [])
    severity = finding_dict.get('severity', 'high')

    azure_cli = _generate_azure_cli(obj_id, upn, roles)
    powershell = _generate_powershell(obj_id, upn, roles)
    graph_api = _generate_graph_api(obj_id, roles)

    role_names = [r.get('role_name', 'Unknown') for r in roles]
    summary = (
        f"{'CRITICAL' if severity == 'critical' else 'HIGH'} — "
        f"Privileged account {upn} has {len(roles)} active role(s) "
        f"({', '.join(role_names[:3])}"
        f"{'...' if len(role_names) > 3 else ''}) "
        f"while the paired regular account is disabled. "
        f"This violates HIPAA §164.312(a)(2)(iii) (termination procedures). "
        f"Recommended: disable the account, revoke sessions, and remove all role assignments."
    )

    return {
        'azure_cli': azure_cli,
        'powershell': powershell,
        'graph_api': graph_api,
        'summary': summary,
    }


def _generate_azure_cli(obj_id, upn, roles):
    """Generate Azure CLI remediation commands."""
    lines = [
        f"# Step 1: Disable the privileged account",
        f"az ad user update --id {obj_id} --account-enabled false",
        f"",
        f"# Step 2: Revoke all active sessions",
        f"az rest --method POST --url 'https://graph.microsoft.com/v1.0/users/{obj_id}/revokeSignInSessions'",
        f"",
        f"# Step 3: Remove role assignments",
    ]
    for r in roles:
        scope = r.get('scope', '')
        role_name = r.get('role_name', 'Unknown')
        scope_type = r.get('scope_type', '')
        if scope_type == 'entra':
            lines.append(f"# Remove Entra role: {role_name}")
            lines.append(f"az rest --method DELETE --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{{ASSIGNMENT_ID}}'")
        else:
            lines.append(f"az role assignment delete --assignee {obj_id} --role \"{role_name}\" --scope \"{scope}\"")
    return '\n'.join(lines)


def _generate_powershell(obj_id, upn, roles):
    """Generate PowerShell / Microsoft Graph remediation commands."""
    lines = [
        f"# Step 1: Disable the privileged account",
        f"Update-MgUser -UserId '{obj_id}' -AccountEnabled:$false",
        f"",
        f"# Step 2: Revoke all active sessions",
        f"Invoke-MgInvalidateUserRefreshToken -UserId '{obj_id}'",
        f"",
        f"# Step 3: Remove role assignments",
    ]
    for r in roles:
        scope = r.get('scope', '')
        role_name = r.get('role_name', 'Unknown')
        scope_type = r.get('scope_type', '')
        if scope_type == 'entra':
            lines.append(f"# Remove Entra role: {role_name}")
            lines.append(f"Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId '{{ASSIGNMENT_ID}}'")
        else:
            lines.append(f"Remove-AzRoleAssignment -ObjectId '{obj_id}' -RoleDefinitionName '{role_name}' -Scope '{scope}'")
    return '\n'.join(lines)


def _generate_graph_api(obj_id, roles):
    """Generate Graph API REST remediation calls."""
    lines = [
        f"# Step 1: Disable the privileged account",
        f"PATCH https://graph.microsoft.com/v1.0/users/{obj_id}",
        f'  Body: {{"accountEnabled": false}}',
        f"",
        f"# Step 2: Revoke all active sessions",
        f"POST https://graph.microsoft.com/v1.0/users/{obj_id}/revokeSignInSessions",
        f"",
        f"# Step 3: Remove role assignments",
    ]
    for r in roles:
        role_name = r.get('role_name', 'Unknown')
        scope_type = r.get('scope_type', '')
        if scope_type == 'entra':
            lines.append(f"# Remove Entra role: {role_name}")
            lines.append(f"DELETE https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{{ASSIGNMENT_ID}}")
        else:
            lines.append(f"# Remove Azure RBAC role: {role_name}")
            lines.append(f"DELETE https://management.azure.com{{SCOPE}}/providers/Microsoft.Authorization/roleAssignments/{{ASSIGNMENT_ID}}?api-version=2022-04-01")
    return '\n'.join(lines)
