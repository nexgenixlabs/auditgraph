"""
Phase 4: Fix Recommendation Engine

Reads from security_findings + attack_paths (SELECT only), correlates per entity,
and produces structured, deduplicated fix recommendations with priority scoring,
step-by-step guidance, Azure CLI commands, and compliance references.

Runs after attack_path_analysis in the scheduler pipeline.
"""

import hashlib
import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def compute_recommendation_fingerprint(entity_id: str, fix_type: str) -> str:
    """Compute a deterministic SHA-256 fingerprint for a fix recommendation.

    Stable across snapshots -- same entity + fix type always produces the same
    hash, enabling cross-run deduplication via UPSERT.
    """
    payload = json.dumps({
        'entity_id': entity_id,
        'fix_type': fix_type,
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


# ──────────────────────────────────────────────────────────────────────
# 15 Recommendation Rule Definitions
# ──────────────────────────────────────────────────────────────────────

RECOMMENDATION_RULES = [
    # 1. remove_role
    {
        'fix_type': 'remove_role',
        'finding_triggers': {'dormant_privileged_identity', 'disabled_account_active_role'},
        'path_triggers': {'direct_escalation', 'lateral_movement'},
        'category': 'access_control',
        'effort': 'low',
        'base_priority': 90,
        'risk_reduction_score': 45,
        'title_template': 'Remove unnecessary role assignments from {entity_name}',
        'description_template': (
            '{entity_name} has privileged role assignments that should be revoked. '
            'Dormant or disabled identities with active roles create a significant attack surface.'
        ),
        'steps': [
            'Identify all active role assignments for the identity in Azure Portal > IAM',
            'Verify the identity is dormant/disabled via Entra ID > Users > sign-in logs',
            'Remove RBAC role assignments: Azure Portal > Subscriptions > IAM > Remove',
            'Remove Entra directory role assignments: Entra ID > Roles > Assignments',
            'Document the removal in your change management system',
            'Monitor for any application breakage over the next 48 hours',
        ],
        'azure_cli': (
            '# Remove RBAC role assignment\n'
            'az role assignment delete --assignee "{entity_id}" --role "Contributor" --scope "/subscriptions/<sub-id>"\n\n'
            '# List remaining assignments\n'
            'az role assignment list --assignee "{entity_id}" --output table'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls'],
            'HIPAA': ['164.312(a)(1) - Access control'],
            'NIST': ['AC-2(3) - Disable inactive accounts'],
            'CIS': ['1.1.1 - Ensure unnecessary roles are removed'],
        },
    },
    # 2. enable_mfa
    {
        'fix_type': 'enable_mfa',
        'finding_triggers': {'user_without_mfa'},
        'path_triggers': set(),
        'category': 'access_control',
        'effort': 'medium',
        'base_priority': 80,
        'risk_reduction_score': 40,
        'title_template': 'Enable MFA for {entity_name}',
        'description_template': (
            '{entity_name} does not have multi-factor authentication enforced. '
            'Accounts without MFA are highly vulnerable to credential theft and phishing attacks.'
        ),
        'steps': [
            'Navigate to Entra ID > Security > Conditional Access',
            'Create or update a CA policy targeting this user or their group',
            'Set Grant control to "Require multifactor authentication"',
            'Set Session controls as appropriate (sign-in frequency)',
            'Enable the policy in report-only mode first to verify impact',
            'Switch to enabled after confirming no disruption',
        ],
        'azure_cli': (
            '# List conditional access policies\n'
            'az rest --method GET --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"\n\n'
            '# Note: CA policy creation requires Graph API or Entra portal'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'CC6.6 - System boundaries'],
            'HIPAA': ['164.312(d) - Person or entity authentication'],
            'NIST': ['IA-2(1) - MFA to privileged accounts', 'IA-2(2) - MFA to non-privileged'],
            'CIS': ['1.1.4 - Ensure MFA is enabled for all users'],
        },
    },
    # 3. rotate_credential
    {
        'fix_type': 'rotate_credential',
        'finding_triggers': {'spn_secret_expired', 'secret_older_180_days'},
        'path_triggers': set(),
        'category': 'credential_hygiene',
        'effort': 'medium',
        'base_priority': 75,
        'risk_reduction_score': 30,
        'title_template': 'Rotate credentials for {entity_name}',
        'description_template': (
            '{entity_name} has expired or aged credentials that need rotation. '
            'Long-lived or expired secrets increase the exposure window if compromised.'
        ),
        'steps': [
            'Identify the application or service using this credential',
            'Generate a new client secret or certificate in Entra ID > App registrations',
            'Update the consuming application/service with the new credential',
            'Verify the application functions correctly with the new credential',
            'Remove the old/expired credential from Entra ID',
            'Set a calendar reminder for the next rotation (90-day cycle recommended)',
        ],
        'azure_cli': (
            '# Add a new client secret (90-day expiry)\n'
            'az ad app credential reset --id "{entity_id}" --years 0 --end-date "$(date -d \'+90 days\' +%Y-%m-%d)"\n\n'
            '# List existing credentials\n'
            'az ad app credential list --id "{entity_id}" --output table'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls'],
            'HIPAA': ['164.312(a)(2)(iv) - Encryption and decryption'],
            'NIST': ['IA-5(1) - Password-based authentication'],
            'CIS': ['1.11 - Ensure secrets are rotated within 90 days'],
        },
    },
    # 4. narrow_scope
    {
        'fix_type': 'narrow_scope',
        'finding_triggers': {'overly_broad_rbac', 'managed_identity_subscription_scope', 'subscription_owner'},
        'path_triggers': {'lateral_movement'},
        'category': 'access_control',
        'effort': 'medium',
        'base_priority': 70,
        'risk_reduction_score': 35,
        'title_template': 'Narrow RBAC scope for {entity_name}',
        'description_template': (
            '{entity_name} has overly broad role assignments at subscription scope. '
            'Broad privileges violate least-privilege and enable lateral movement across resources.'
        ),
        'steps': [
            'Review current role assignments: Azure Portal > Subscriptions > IAM',
            'Identify the minimum resources the identity actually needs access to',
            'Create resource-group-scoped role assignments for required resources',
            'Remove the subscription-level role assignment',
            'Verify application functionality with the narrowed scope',
            'Consider using custom roles with only required permissions',
        ],
        'azure_cli': (
            '# List current assignments at subscription scope\n'
            'az role assignment list --assignee "{entity_id}" --scope "/subscriptions/<sub-id>" --output table\n\n'
            '# Create RG-scoped assignment\n'
            'az role assignment create --assignee "{entity_id}" --role "Contributor" --scope "/subscriptions/<sub-id>/resourceGroups/<rg-name>"\n\n'
            '# Remove subscription-level assignment\n'
            'az role assignment delete --assignee "{entity_id}" --role "Contributor" --scope "/subscriptions/<sub-id>"'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.3 - Role-based access'],
            'HIPAA': ['164.312(a)(1) - Access control', '164.514(d) - Minimum necessary'],
            'NIST': ['AC-6 - Least privilege', 'AC-6(1) - Authorize access to security functions'],
            'CIS': ['1.23 - Ensure custom role is assigned for subscription administration'],
        },
    },
    # 5. disable_public_access
    {
        'fix_type': 'disable_public_access',
        'finding_triggers': {'storage_public_access'},
        'path_triggers': {'sensitive_data_exposure'},
        'category': 'data_protection',
        'effort': 'low',
        'base_priority': 95,
        'risk_reduction_score': 50,
        'title_template': 'Disable public access on {entity_name}',
        'description_template': (
            '{entity_name} has public blob access enabled, allowing anonymous internet access to data. '
            'This is a critical data exposure risk that should be remediated immediately.'
        ),
        'steps': [
            'Navigate to Azure Portal > Storage accounts > {entity_name}',
            'Go to Settings > Configuration',
            'Set "Allow Blob public access" to Disabled',
            'Review and remove any existing public containers',
            'Configure private endpoints for authorized access',
            'Verify applications use SAS tokens or managed identity authentication',
        ],
        'azure_cli': (
            '# Disable public blob access\n'
            'az storage account update --name "{entity_name}" --resource-group "<rg>" --allow-blob-public-access false\n\n'
            '# List public containers\n'
            'az storage container list --account-name "{entity_name}" --query "[?properties.publicAccess!=\'None\']" --output table'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.6 - System boundaries', 'CC6.7 - Restrict data transmission'],
            'HIPAA': ['164.312(e)(1) - Transmission security', '164.312(a)(1) - Access control'],
            'NIST': ['AC-3 - Access enforcement', 'SC-7 - Boundary protection'],
            'CIS': ['3.7 - Ensure public access is not allowed for storage accounts'],
        },
    },
    # 6. enable_purge_protection
    {
        'fix_type': 'enable_purge_protection',
        'finding_triggers': {'kv_no_purge_protection'},
        'path_triggers': set(),
        'category': 'data_protection',
        'effort': 'low',
        'base_priority': 70,
        'risk_reduction_score': 20,
        'title_template': 'Enable purge protection on {entity_name}',
        'description_template': (
            '{entity_name} does not have purge protection enabled. '
            'Without purge protection, deleted secrets can be permanently destroyed without recovery.'
        ),
        'steps': [
            'Navigate to Azure Portal > Key Vaults > {entity_name}',
            'Go to Settings > Properties',
            'Enable "Purge protection" (note: this is irreversible once enabled)',
            'Ensure soft-delete is also enabled (prerequisite for purge protection)',
            'Update any IaC templates to include purge protection',
        ],
        'azure_cli': (
            '# Enable purge protection (irreversible)\n'
            'az keyvault update --name "{entity_name}" --enable-purge-protection true\n\n'
            '# Verify settings\n'
            'az keyvault show --name "{entity_name}" --query "{enableSoftDelete:properties.enableSoftDelete, enablePurgeProtection:properties.enablePurgeProtection}"'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'A1.2 - Recovery mechanisms'],
            'HIPAA': ['164.312(a)(2)(iv) - Encryption and decryption'],
            'NIST': ['SC-28 - Protection of information at rest'],
            'CIS': ['8.5 - Ensure purge protection is enabled for Key Vault'],
        },
    },
    # 7. add_private_endpoint
    {
        'fix_type': 'add_private_endpoint',
        'finding_triggers': {'kv_no_private_endpoint'},
        'path_triggers': set(),
        'category': 'network_security',
        'effort': 'high',
        'base_priority': 60,
        'risk_reduction_score': 25,
        'title_template': 'Add private endpoint to {entity_name}',
        'description_template': (
            '{entity_name} has no private endpoint configured. '
            'Traffic to this resource traverses the public internet, increasing exposure.'
        ),
        'steps': [
            'Identify the VNet and subnet for the private endpoint',
            'Create a private endpoint: Azure Portal > Key Vault > Networking > Private endpoint connections',
            'Configure a private DNS zone for the Key Vault',
            'Update firewall rules to deny public network access',
            'Verify connectivity from authorized VNets',
            'Update application configurations to use the private endpoint FQDN',
        ],
        'azure_cli': (
            '# Create private endpoint\n'
            'az network private-endpoint create --name "{entity_name}-pe" --resource-group "<rg>" '
            '--vnet-name "<vnet>" --subnet "<subnet>" --private-connection-resource-id "<kv-resource-id>" '
            '--group-id vault --connection-name "{entity_name}-conn"\n\n'
            '# Disable public access\n'
            'az keyvault update --name "{entity_name}" --public-network-access Disabled'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.6 - System boundaries'],
            'HIPAA': ['164.312(e)(1) - Transmission security'],
            'NIST': ['SC-7 - Boundary protection', 'SC-8 - Transmission confidentiality'],
            'CIS': ['8.6 - Ensure private endpoints are used for Key Vault'],
        },
    },
    # 8. assign_owner
    {
        'fix_type': 'assign_owner',
        'finding_triggers': {'spn_without_owner'},
        'path_triggers': {'ownership_chain'},
        'category': 'governance',
        'effort': 'low',
        'base_priority': 65,
        'risk_reduction_score': 15,
        'title_template': 'Assign an owner to {entity_name}',
        'description_template': (
            '{entity_name} has no assigned owner. Unowned service principals lack accountability '
            'and may accumulate stale permissions or be exploited without anyone responsible for oversight.'
        ),
        'steps': [
            'Navigate to Entra ID > App registrations > {entity_name}',
            'Go to Owners tab and add an appropriate owner',
            'The owner should be someone responsible for the application',
            'Consider adding a team distribution list as a secondary owner',
            'Document the ownership assignment in your CMDB or service catalog',
        ],
        'azure_cli': (
            '# Add owner to app registration\n'
            'az ad app owner add --id "{entity_id}" --owner-object-id "<owner-object-id>"\n\n'
            '# List current owners\n'
            'az ad app owner list --id "{entity_id}" --output table'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'CC1.3 - Accountability'],
            'HIPAA': ['164.308(a)(3) - Workforce security'],
            'NIST': ['AC-2 - Account management'],
            'CIS': ['1.15 - Ensure service principals have owners'],
        },
    },
    # 9. enable_pim
    {
        'fix_type': 'enable_pim',
        'finding_triggers': {'subscription_owner'},
        'path_triggers': {'direct_escalation', 'pim_escalation'},
        'category': 'access_control',
        'effort': 'medium',
        'base_priority': 85,
        'risk_reduction_score': 40,
        'title_template': 'Enable PIM for privileged access of {entity_name}',
        'description_template': (
            '{entity_name} has standing privileged access that should be converted to just-in-time '
            'activation via Privileged Identity Management (PIM). Standing admin access increases '
            'the blast radius of a compromise.'
        ),
        'steps': [
            'Navigate to Entra ID > Privileged Identity Management',
            'Go to Azure resources or Entra roles (depending on the role type)',
            'Find the role assignment for {entity_name}',
            'Convert from "Active" to "Eligible" assignment',
            'Configure activation requirements (MFA, justification, approval)',
            'Set maximum activation duration (recommended: 4-8 hours)',
        ],
        'azure_cli': (
            '# Note: PIM configuration requires Graph API\n'
            '# List eligible role assignments\n'
            'az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"\n\n'
            '# PIM activation settings are managed via Entra portal or Graph API'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'CC6.3 - Role-based access'],
            'HIPAA': ['164.312(a)(1) - Access control'],
            'NIST': ['AC-2(5) - Inactivity logout', 'AC-6(2) - Non-privileged access for non-security'],
            'CIS': ['1.1.2 - Ensure PIM is used for administrative roles'],
        },
    },
    # 10. restrict_guest
    {
        'fix_type': 'restrict_guest',
        'finding_triggers': {'guest_admin'},
        'path_triggers': {'external_identity_risk'},
        'category': 'access_control',
        'effort': 'low',
        'base_priority': 90,
        'risk_reduction_score': 45,
        'title_template': 'Restrict guest admin privileges for {entity_name}',
        'description_template': (
            '{entity_name} is an external guest user with administrative Entra roles. '
            'Guests with admin access pose significant supply-chain and lateral movement risks.'
        ),
        'steps': [
            'Review the business justification for this guest having admin roles',
            'If unjustified, remove administrative Entra role assignments immediately',
            'If justified, convert the guest to a member user or use B2B direct connect',
            'Apply conditional access policies restricting guest sign-in locations',
            'Enable access reviews for all guest admin assignments',
        ],
        'azure_cli': (
            '# List guest role assignments\n'
            'az ad user show --id "{entity_id}" --query "{{displayName:displayName, userType:userType}}"\n\n'
            '# Remove directory role\n'
            'az rest --method DELETE --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/<assignment-id>"'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'CC6.2 - External access'],
            'HIPAA': ['164.308(a)(4) - Information access management'],
            'NIST': ['AC-17 - Remote access', 'AC-20 - Use of external systems'],
            'CIS': ['1.3 - Ensure guest users are reviewed monthly'],
        },
    },
    # 11. review_sensitive_access
    {
        'fix_type': 'review_sensitive_access',
        'finding_triggers': {'sensitive_data_access'},
        'path_triggers': {'sensitive_data_exposure'},
        'category': 'data_protection',
        'effort': 'medium',
        'base_priority': 65,
        'risk_reduction_score': 25,
        'title_template': 'Review sensitive resource access for {entity_name}',
        'description_template': (
            '{entity_name} has RBAC access to resources classified as containing sensitive data. '
            'Review whether this access is necessary and restrict to minimum required permissions.'
        ),
        'steps': [
            'Identify all classified resources the identity can access',
            'Verify the business need for each access grant',
            'Remove access to resources not required for the identity\'s function',
            'For remaining access, ensure the role provides minimum necessary permissions',
            'Enable diagnostic logging on all sensitive resources',
            'Schedule periodic access reviews for sensitive resource access',
        ],
        'azure_cli': (
            '# List role assignments for the identity\n'
            'az role assignment list --assignee "{entity_id}" --output table\n\n'
            '# Check specific resource access\n'
            'az role assignment list --scope "<resource-id>" --output table'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'CC6.7 - Restrict data transmission'],
            'HIPAA': ['164.514(d) - Minimum necessary', '164.312(a)(1) - Access control'],
            'NIST': ['AC-6 - Least privilege', 'AC-25 - Reference monitor'],
            'CIS': ['1.23 - Ensure custom role is assigned for administration'],
        },
    },
    # 12. audit_ownership_chain
    {
        'fix_type': 'audit_ownership_chain',
        'finding_triggers': set(),
        'path_triggers': {'ownership_chain'},
        'category': 'governance',
        'effort': 'medium',
        'base_priority': 70,
        'risk_reduction_score': 20,
        'title_template': 'Audit ownership chain involving {entity_name}',
        'description_template': (
            '{entity_name} is part of an ownership chain where one identity owns another with '
            'elevated privileges. This creates an indirect escalation path that should be reviewed.'
        ),
        'steps': [
            'Map the full ownership chain from the source identity to the privileged target',
            'Verify that each ownership relationship is intentional and documented',
            'Assess whether the source identity needs to own the target',
            'If ownership is not required, remove the owner relationship',
            'Consider adding additional owners for shared accountability',
            'Document approved ownership chains in your security baseline',
        ],
        'azure_cli': (
            '# List owners of an app registration\n'
            'az ad app owner list --id "{entity_id}" --output table\n\n'
            '# List service principals owned by a user\n'
            'az ad user get-member-objects --id "{entity_id}"'
        ),
        'compliance_refs': {
            'SOC2': ['CC1.3 - Accountability', 'CC6.1 - Logical access controls'],
            'HIPAA': ['164.308(a)(3) - Workforce security'],
            'NIST': ['AC-2 - Account management', 'AC-6(5) - Privileged accounts'],
            'CIS': ['1.15 - Ensure service principals have owners'],
        },
    },
    # 13. harden_pim_policy
    {
        'fix_type': 'harden_pim_policy',
        'finding_triggers': set(),
        'path_triggers': {'pim_escalation'},
        'category': 'access_control',
        'effort': 'low',
        'base_priority': 75,
        'risk_reduction_score': 30,
        'title_template': 'Harden PIM activation policy for {entity_name}',
        'description_template': (
            '{entity_name} is eligible for dangerous PIM roles with potentially weak activation controls. '
            'Strengthening PIM policies reduces the risk of unauthorized privilege escalation.'
        ),
        'steps': [
            'Navigate to Entra ID > PIM > Azure AD roles > Settings',
            'Find the role that {entity_name} is eligible for',
            'Require MFA on activation',
            'Require justification for activation',
            'Enable approval workflow for critical roles (Global Admin, etc.)',
            'Set maximum activation duration to 4 hours or less',
        ],
        'azure_cli': (
            '# List PIM role settings\n'
            'az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"\n\n'
            '# PIM policy configuration requires Graph API or Entra portal'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls'],
            'HIPAA': ['164.312(a)(1) - Access control'],
            'NIST': ['AC-2(5) - Inactivity logout', 'AC-6 - Least privilege'],
            'CIS': ['1.1.2 - Ensure PIM is used for administrative roles'],
        },
    },
    # 14. segment_lateral_movement
    {
        'fix_type': 'segment_lateral_movement',
        'finding_triggers': set(),
        'path_triggers': {'lateral_movement'},
        'category': 'network_security',
        'effort': 'high',
        'base_priority': 70,
        'risk_reduction_score': 35,
        'title_template': 'Segment lateral movement risk for {entity_name}',
        'description_template': (
            '{entity_name} has broad subscription-level RBAC that enables lateral movement across '
            'resource groups and resources. Network segmentation and scope restriction are needed.'
        ),
        'steps': [
            'Review all subscription-level role assignments for the identity',
            'Map which resource groups the identity actually needs access to',
            'Replace subscription-scoped roles with resource-group-scoped assignments',
            'Implement Network Security Groups (NSGs) to limit east-west traffic',
            'Consider Azure Firewall or third-party microsegmentation',
            'Enable Azure Defender for Resource Manager to monitor RBAC changes',
        ],
        'azure_cli': (
            '# List subscription-level assignments\n'
            'az role assignment list --assignee "{entity_id}" --scope "/subscriptions/<sub-id>" --output table\n\n'
            '# Create NSG rule to restrict lateral traffic\n'
            'az network nsg rule create --resource-group "<rg>" --nsg-name "<nsg>" --name "DenyLateral" '
            '--priority 200 --direction Inbound --access Deny --source-address-prefixes "VirtualNetwork" '
            '--destination-port-ranges "*"'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.6 - System boundaries'],
            'HIPAA': ['164.312(e)(1) - Transmission security'],
            'NIST': ['SC-7 - Boundary protection', 'AC-4 - Information flow enforcement'],
            'CIS': ['6.1 - Ensure Network Security Groups are configured'],
        },
    },
    # 15. cleanup_disabled_account
    {
        'fix_type': 'cleanup_disabled_account',
        'finding_triggers': {'disabled_account_active_role'},
        'path_triggers': set(),
        'category': 'governance',
        'effort': 'low',
        'base_priority': 85,
        'risk_reduction_score': 35,
        'title_template': 'Clean up disabled account {entity_name}',
        'description_template': (
            '{entity_name} is disabled but retains active role assignments. '
            'Disabled accounts with active roles are a compliance violation and security risk.'
        ),
        'steps': [
            'Verify the account is disabled in Entra ID > Users',
            'Remove all RBAC role assignments from the account',
            'Remove all Entra directory role assignments',
            'Check for any group memberships that grant implicit access',
            'If the account is no longer needed, schedule deletion per retention policy',
            'Document the cleanup in your offboarding checklist',
        ],
        'azure_cli': (
            '# Check account status\n'
            'az ad user show --id "{entity_id}" --query "{{displayName:displayName, accountEnabled:accountEnabled}}"\n\n'
            '# Remove all role assignments\n'
            'az role assignment delete --assignee "{entity_id}" --yes\n\n'
            '# Delete user (if approved)\n'
            'az ad user delete --id "{entity_id}"'
        ),
        'compliance_refs': {
            'SOC2': ['CC6.1 - Logical access controls', 'CC6.2 - Prior to access'],
            'HIPAA': ['164.312(a)(2)(iii) - Automatic logoff', '164.308(a)(3)(ii)(C) - Termination procedures'],
            'NIST': ['AC-2(3) - Disable inactive accounts', 'PS-4 - Personnel termination'],
            'CIS': ['1.1.6 - Ensure disabled users have no role assignments'],
        },
    },
]

# Build lookup indexes for fast matching
_FINDING_TYPE_TO_RULES = {}
_PATH_TYPE_TO_RULES = {}
for _rule in RECOMMENDATION_RULES:
    for _ft in _rule['finding_triggers']:
        _FINDING_TYPE_TO_RULES.setdefault(_ft, []).append(_rule)
    for _pt in _rule['path_triggers']:
        _PATH_TYPE_TO_RULES.setdefault(_pt, []).append(_rule)

# Severity-to-weight mapping for composite priority scoring
_SEVERITY_WEIGHT = {
    'critical': 40,
    'high': 25,
    'medium': 15,
    'low': 5,
}


class FixRecommendationEngine:
    """Correlate security_findings + attack_paths into unified fix recommendations."""

    def __init__(self, db):
        self.db = db

    def analyze(self, run_id: int) -> List[Dict]:
        """Analyze findings and attack paths for a run, return recommendation dicts.

        Flow:
        1. Load open findings by entity_id
        2. Load attack paths by source_entity_id
        3. Union all entity IDs
        4. Match against 15 rules
        5. Compute composite priority
        6. Return deduplicated list
        """
        # Step 1: Load findings grouped by entity_id
        findings_by_entity = self._load_findings(run_id)

        # Step 2: Load attack paths grouped by source_entity_id
        paths_by_entity = self._load_paths(run_id)

        # Step 3: Union all entity IDs
        all_entity_ids = set(findings_by_entity.keys()) | set(paths_by_entity.keys())
        if not all_entity_ids:
            logger.info(f"Fix recommendations: no findings or paths for run #{run_id}")
            return []

        # Step 4-5: Match rules and build recommendations
        recommendations = []
        seen = set()  # (entity_id, fix_type) dedup

        for entity_id in all_entity_ids:
            entity_findings = findings_by_entity.get(entity_id, [])
            entity_paths = paths_by_entity.get(entity_id, [])

            finding_types = {f['finding_type'] for f in entity_findings}
            path_types = {p['path_type'] for p in entity_paths}

            # Resolve entity name from findings or paths
            entity_name = None
            entity_type = 'identity'
            for f in entity_findings:
                if f.get('title'):
                    # Extract name from title (after last colon)
                    parts = f['title'].rsplit(': ', 1)
                    if len(parts) > 1:
                        entity_name = parts[1]
                entity_type = f.get('entity_type', 'identity')
                break
            if not entity_name:
                for p in entity_paths:
                    entity_name = p.get('source_entity_name')
                    entity_type = p.get('source_entity_type', 'identity')
                    if entity_name:
                        break
            if not entity_name:
                entity_name = entity_id

            # Match rules
            matched_rules = set()
            for ft in finding_types:
                for rule in _FINDING_TYPE_TO_RULES.get(ft, []):
                    matched_rules.add(rule['fix_type'])
            for pt in path_types:
                for rule in _PATH_TYPE_TO_RULES.get(pt, []):
                    matched_rules.add(rule['fix_type'])

            for rule in RECOMMENDATION_RULES:
                if rule['fix_type'] not in matched_rules:
                    continue

                key = (entity_id, rule['fix_type'])
                if key in seen:
                    continue
                seen.add(key)

                # Determine which finding/path types triggered this rule
                linked_finding_types = sorted(finding_types & rule['finding_triggers'])
                linked_path_types = sorted(path_types & rule['path_triggers'])

                # Pick the highest-severity matching finding and path for FK linking
                best_finding = None
                for f in entity_findings:
                    if f['finding_type'] in rule['finding_triggers']:
                        if best_finding is None or f.get('risk_score', 0) > best_finding.get('risk_score', 0):
                            best_finding = f
                best_path = None
                for p in entity_paths:
                    if p['path_type'] in rule['path_triggers']:
                        if best_path is None or p.get('risk_score', 0) > best_path.get('risk_score', 0):
                            best_path = p

                # Compute composite priority:
                #   risk_reduction_score + finding_severity_weight + attack_path_severity_weight
                risk_reduction = rule.get('risk_reduction_score', 0)
                finding_severity_weight = 0
                if best_finding:
                    finding_severity_weight = _SEVERITY_WEIGHT.get(
                        best_finding.get('severity', ''), 0)
                path_severity_weight = 0
                if best_path:
                    path_severity_weight = _SEVERITY_WEIGHT.get(
                        best_path.get('severity', ''), 0)

                priority = min(100, risk_reduction + finding_severity_weight + path_severity_weight)

                rec = {
                    'entity_id': entity_id,
                    'entity_type': entity_type,
                    'entity_name': entity_name,
                    'fix_type': rule['fix_type'],
                    'title': rule['title_template'].format(entity_name=entity_name),
                    'description': rule['description_template'].format(
                        entity_name=entity_name, entity_id=entity_id,
                    ),
                    'fix_category': rule['category'],
                    'priority_score': priority,
                    'risk_reduction_score': risk_reduction,
                    'effort': rule['effort'],
                    'steps': rule['steps'],
                    'azure_cli_commands': rule['azure_cli'].format(
                        entity_id=entity_id, entity_name=entity_name,
                    ),
                    'compliance_refs': rule['compliance_refs'],
                    'linked_finding_types': linked_finding_types,
                    'linked_path_types': linked_path_types,
                    'linked_finding_count': len(linked_finding_types),
                    'linked_path_count': len(linked_path_types),
                    'finding_id': best_finding.get('id') if best_finding else None,
                    'attack_path_id': best_path.get('id') if best_path else None,
                    'recommendation_fingerprint': compute_recommendation_fingerprint(
                        entity_id, rule['fix_type'],
                    ),
                }
                recommendations.append(rec)

        # Sort by priority descending
        recommendations.sort(key=lambda r: r['priority_score'], reverse=True)

        logger.info(
            f"Fix recommendations engine: {len(recommendations)} recommendation(s) "
            f"for run #{run_id} across {len(all_entity_ids)} entities"
        )
        return recommendations

    def _load_findings(self, run_id: int) -> Dict[str, List[Dict]]:
        """Load open security findings grouped by entity_id."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT id, entity_id, entity_type, finding_type, severity, risk_score,
                       title, description
                FROM security_findings
                WHERE discovery_run_id = %s AND status = 'open'
            """, (run_id,))
            cols = [d[0] for d in cursor.description]
            rows = cursor.fetchall()
        finally:
            cursor.close()

        grouped: Dict[str, List[Dict]] = {}
        for row in rows:
            d = dict(zip(cols, row))
            grouped.setdefault(d['entity_id'], []).append(d)
        return grouped

    def _load_paths(self, run_id: int) -> Dict[str, List[Dict]]:
        """Load attack paths grouped by source_entity_id."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT id, source_entity_id, source_entity_name, source_entity_type,
                       path_type, risk_score, severity, description
                FROM attack_paths
                WHERE discovery_run_id = %s
            """, (run_id,))
            cols = [d[0] for d in cursor.description]
            rows = cursor.fetchall()
        finally:
            cursor.close()

        grouped: Dict[str, List[Dict]] = {}
        for row in rows:
            d = dict(zip(cols, row))
            grouped.setdefault(d['source_entity_id'], []).append(d)
        return grouped
