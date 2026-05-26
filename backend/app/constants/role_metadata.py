"""
SSOT for role *metadata* (description, can_do, cannot_do, docs_url, tier).

Complements `app/constants/roles.py` (which is the SSOT for role *names*).
Used wherever the product surfaces "what does this role do?" — attack paths,
identity detail, role lists, risk explanations, exports, etc. Do NOT duplicate
this data in handlers — call `get_role_metadata(provider, role_name)` or
`get_role_metadata_auto(role_name)` instead.

Source of truth per provider:
  - Entra:    https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
  - Azure RBAC: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles
  - AWS IAM:  https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html (+ per-policy doc pages)
  - GCP IAM:  https://cloud.google.com/iam/docs/understanding-roles

When adding a role: cite the official one-line description verbatim where
possible, list 3-5 concrete `can_do` actions, and (most important for auditors)
list the `cannot_do` boundaries — that's where misconceptions usually live.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, TypedDict


# ─────────────────────────────────────────────────────────────────────────────
class Provider(str, Enum):
    ENTRA     = "entra"
    AZURE_RBAC = "azure_rbac"
    AWS_IAM   = "aws_iam"
    GCP_IAM   = "gcp_iam"
    UNKNOWN   = "unknown"


class RoleMeta(TypedDict):
    provider:    str       # Provider value
    name:        str       # canonical role name
    description: str       # one-line, auth-source wording
    can_do:      list[str] # 3-5 concrete capabilities
    cannot_do:   list[str] # 2-4 boundary clarifications
    docs_url:    str       # link to the auth source
    tier:        str       # T0 (critical) / T1 (high) / T2 (medium) / T3 (low) / unknown


_ENTRA_DOCS  = "https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference"
_RBAC_DOCS   = "https://learn.microsoft.com/azure/role-based-access-control/built-in-roles"
_AWS_DOCS    = "https://docs.aws.amazon.com/aws-managed-policy/latest/reference"
_GCP_DOCS    = "https://cloud.google.com/iam/docs/understanding-roles"


def _e(slug: str) -> str: return f"{_ENTRA_DOCS}#{slug}"
def _r(slug: str) -> str: return f"{_RBAC_DOCS}#{slug}"
def _a(name: str) -> str: return f"{_AWS_DOCS}/{name}.html"
def _g() -> str:          return _GCP_DOCS  # GCP doc page covers all basic roles


# ═════════════════════════════════════════════════════════════════════════════
# Entra ID — directory roles
# ═════════════════════════════════════════════════════════════════════════════
_ENTRA: dict[str, RoleMeta] = {
    # ── T0: Critical ────────────────────────────────────────────────────────
    "Global Administrator": {
        "provider": Provider.ENTRA.value, "name": "Global Administrator", "tier": "T0",
        "description": "Can manage all aspects of Microsoft Entra ID and Microsoft services that use Microsoft Entra identities.",
        "can_do": [
            "Read and modify every directory object (users, groups, apps, roles, policies)",
            "Assign any directory role to any principal, including Global Administrator",
            'If "Access management for Azure resources" is enabled, elevate to root of every Azure subscription',
        ],
        "cannot_do": ["Bypass Conditional Access on its own sign-in (still subject to MFA/CA)"],
        "docs_url": _e("global-administrator"),
    },
    "Privileged Role Administrator": {
        "provider": Provider.ENTRA.value, "name": "Privileged Role Administrator", "tier": "T0",
        "description": "Can manage role assignments in Microsoft Entra ID, and all aspects of Privileged Identity Management.",
        "can_do": [
            "Assign ANY Entra directory role to any principal (including Global Administrator)",
            "Manage all PIM settings, eligibility, and activations",
            "Manage Administrative Units and their role assignments",
        ],
        "cannot_do": [
            "Read or modify users, groups, applications, or directory data directly",
            "Reset passwords for any user",
            "Manage Azure RBAC role assignments (separate system)",
        ],
        "docs_url": _e("privileged-role-administrator"),
    },
    "Privileged Authentication Administrator": {
        "provider": Provider.ENTRA.value, "name": "Privileged Authentication Administrator", "tier": "T0",
        "description": "Can access to view, set, and reset authentication method information for any user (admin or non-admin).",
        "can_do": [
            "Reset passwords for ANY user, including Global Administrators",
            "Force re-registration of MFA / passwordless methods for any user",
            "Revoke all sessions for any user",
        ],
        "cannot_do": [
            "Modify directory objects (users, groups, apps) outside of authentication settings",
            "Grant directory roles",
        ],
        "docs_url": _e("privileged-authentication-administrator"),
    },
    "Application Administrator": {
        "provider": Provider.ENTRA.value, "name": "Application Administrator", "tier": "T0",
        "description": "Can create and manage all aspects of app registrations and enterprise apps.",
        "can_do": [
            "Create, update, and delete any app registration in the tenant",
            "Add credentials (secrets / certificates) to ANY service principal",
            "Grant tenant-wide admin consent (in classic mode; restricted in newer tenants)",
            "Manage Application Proxy connectors and on-prem groups",
        ],
        "cannot_do": [
            "Manage user accounts, passwords, groups, or directory roles",
            "Read user mail, calendar, or files",
            "Modify Conditional Access policies",
        ],
        "docs_url": _e("application-administrator"),
    },
    "Cloud Application Administrator": {
        "provider": Provider.ENTRA.value, "name": "Cloud Application Administrator", "tier": "T0",
        "description": "Can create and manage all aspects of app registrations and enterprise apps except App Proxy.",
        "can_do": [
            "Create, update, and delete any app registration in the tenant",
            "Add credentials (secrets / certificates) to ANY service principal",
            "Grant tenant-wide admin consent (in classic mode; restricted in newer tenants)",
        ],
        "cannot_do": [
            "Manage on-prem Application Proxy connectors",
            "Manage user accounts, passwords, groups, or directory roles",
            "Read user mail, calendar, or files",
        ],
        "docs_url": _e("cloud-application-administrator"),
    },
    "Hybrid Identity Administrator": {
        "provider": Provider.ENTRA.value, "name": "Hybrid Identity Administrator", "tier": "T0",
        "description": "Can manage Microsoft Entra Connect, Pass-through Authentication (PTA), Password Hash Sync (PHS), Seamless SSO, and federation settings.",
        "can_do": [
            "Configure / disable Entra Connect, PTA agents, PHS, Seamless SSO",
            "Manage federation trust settings for verified domains",
            "Read sync errors and rerun sync",
        ],
        "cannot_do": [
            "Reset passwords or modify users directly (changes flow from on-prem AD)",
            "Grant directory roles",
        ],
        "docs_url": _e("hybrid-identity-administrator"),
    },
    "Domain Name Administrator": {
        "provider": Provider.ENTRA.value, "name": "Domain Name Administrator", "tier": "T0",
        "description": "Can manage domain names in cloud and on-premises.",
        "can_do": [
            "Add, verify, remove custom domains in the tenant",
            "Federate domains with external IdPs",
        ],
        "cannot_do": [
            "Manage users, groups, apps, or roles",
        ],
        "docs_url": _e("domain-name-administrator"),
    },
    "External Identity Provider Administrator": {
        "provider": Provider.ENTRA.value, "name": "External Identity Provider Administrator", "tier": "T0",
        "description": "Can configure identity providers for use in direct federation.",
        "can_do": [
            "Add, configure, and remove external identity providers (SAML/WS-Fed)",
            "Manage federation settings used for B2B / direct federation",
        ],
        "cannot_do": [
            "Manage users, groups, apps, or directory roles directly",
        ],
        "docs_url": _e("external-identity-provider-administrator"),
    },

    # ── T1: High ────────────────────────────────────────────────────────────
    "User Administrator": {
        "provider": Provider.ENTRA.value, "name": "User Administrator", "tier": "T1",
        "description": "Can manage all aspects of users and groups, including resetting passwords for limited admins.",
        "can_do": [
            "Create, update, and delete non-admin users",
            "Reset passwords for non-admin users and a few helpdesk-tier admin roles (Helpdesk Administrator, Directory Readers, etc.)",
            "Manage all groups (security and Microsoft 365)",
            "Manage user views and access requests",
        ],
        "cannot_do": [
            "Reset passwords or delete users with protected roles (Global Administrator, Privileged Role Administrator, Application Administrator, etc.)",
            "Grant or revoke directory roles",
            "Modify Conditional Access or sign-in policies",
            "Manage apps, SPNs, or licenses",
        ],
        "docs_url": _e("user-administrator"),
    },
    "Exchange Administrator": {
        "provider": Provider.ENTRA.value, "name": "Exchange Administrator", "tier": "T1",
        "description": "Can manage all aspects of the Exchange product.",
        "can_do": [
            "Manage all mailboxes (read access, mailbox permissions, delegation)",
            "Configure transport rules, journaling, and mail flow",
            "Set up forwarding / auto-reply on any mailbox",
            "Manage Microsoft 365 Groups and distribution lists",
        ],
        "cannot_do": [
            "Manage directory users / roles outside Exchange context",
            "Modify Conditional Access or sign-in policies",
            "Manage apps, SPNs, or directory schema",
        ],
        "docs_url": _e("exchange-administrator"),
    },
    "SharePoint Administrator": {
        "provider": Provider.ENTRA.value, "name": "SharePoint Administrator", "tier": "T1",
        "description": "Can manage all aspects of the SharePoint service.",
        "can_do": [
            "Create / delete site collections and OneDrive sites",
            "Assign site collection administrators",
            "Configure tenant-wide sharing and external collaboration settings",
        ],
        "cannot_do": [
            "Read individual document content directly (requires explicit site permissions)",
            "Manage Exchange, Teams, or directory roles",
        ],
        "docs_url": _e("sharepoint-administrator"),
    },
    "Teams Administrator": {
        "provider": Provider.ENTRA.value, "name": "Teams Administrator", "tier": "T1",
        "description": "Can manage the Microsoft Teams service.",
        "can_do": [
            "Manage Teams policies, calling, meetings, messaging",
            "Create / delete Teams and channels",
            "Assign phone numbers and manage voice config",
        ],
        "cannot_do": [
            "Read message content (requires eDiscovery roles)",
            "Manage directory users / roles",
        ],
        "docs_url": _e("teams-administrator"),
    },
    "Security Administrator": {
        "provider": Provider.ENTRA.value, "name": "Security Administrator", "tier": "T1",
        "description": "Can read security information and reports, and manage configuration in Microsoft Entra ID and Microsoft 365.",
        "can_do": [
            "Configure Identity Protection, Conditional Access (read+write), Defender for Cloud Apps",
            "Read all security alerts and reports",
            "Manage sign-in risk and user-risk policies",
        ],
        "cannot_do": [
            "Reset passwords for protected admin accounts",
            "Manage directory users, groups, or apps (read-only on many)",
        ],
        "docs_url": _e("security-administrator"),
    },
    "Conditional Access Administrator": {
        "provider": Provider.ENTRA.value, "name": "Conditional Access Administrator", "tier": "T1",
        "description": "Can manage Conditional Access capabilities.",
        "can_do": [
            "Create, update, and delete Conditional Access policies",
            "Configure named locations and authentication contexts",
        ],
        "cannot_do": [
            "Manage users, groups, apps, or other directory roles",
            "Read sign-in logs (read-only requires Reports Reader / Security Reader)",
        ],
        "docs_url": _e("conditional-access-administrator"),
    },
    "Authentication Administrator": {
        "provider": Provider.ENTRA.value, "name": "Authentication Administrator", "tier": "T1",
        "description": "Can access to view, set, and reset authentication method information for any non-admin user.",
        "can_do": [
            "Reset passwords for non-admin users",
            "Force MFA re-registration for non-admin users",
            "Revoke sessions for non-admin users",
        ],
        "cannot_do": [
            "Reset passwords or auth methods for ANY admin (use Privileged Authentication Administrator)",
            "Manage directory data",
        ],
        "docs_url": _e("authentication-administrator"),
    },
    "Helpdesk Administrator": {
        "provider": Provider.ENTRA.value, "name": "Helpdesk Administrator", "tier": "T1",
        "description": "Can reset passwords for non-administrators and Helpdesk Administrators.",
        "can_do": [
            "Reset passwords for non-admin users and other Helpdesk Administrators",
            "Invalidate refresh tokens for affected users",
            "Read basic company information and user properties",
        ],
        "cannot_do": [
            "Reset passwords for higher-privilege admins (User Admin, Global Admin, etc.)",
            "Create, delete, or modify user accounts",
        ],
        "docs_url": _e("helpdesk-administrator"),
    },

    # ── T2: Medium ──────────────────────────────────────────────────────────
    "Intune Administrator": {
        "provider": Provider.ENTRA.value, "name": "Intune Administrator", "tier": "T2",
        "description": "Can manage all aspects of the Intune product.",
        "can_do": [
            "Manage device compliance and configuration policies",
            "Enroll/wipe devices, deploy apps",
            "Manage Autopilot, app protection, and conditional launch policies",
        ],
        "cannot_do": [
            "Manage directory users or roles directly",
            "Read user mail or files",
        ],
        "docs_url": _e("intune-administrator"),
    },
    "Password Administrator": {
        "provider": Provider.ENTRA.value, "name": "Password Administrator", "tier": "T2",
        "description": "Can reset passwords for non-administrators and Password Administrators.",
        "can_do": [
            "Reset passwords for non-admin users and other Password Administrators",
        ],
        "cannot_do": [
            "Reset passwords for higher-privilege admins",
            "Modify users, groups, or directory data",
        ],
        "docs_url": _e("password-administrator"),
    },
    "Groups Administrator": {
        "provider": Provider.ENTRA.value, "name": "Groups Administrator", "tier": "T2",
        "description": "Members of this role can create/manage groups and group settings like naming and expiration policies.",
        "can_do": [
            "Create, update, delete security and Microsoft 365 groups",
            "Configure tenant-wide group naming / expiration policies",
            "Manage group memberships",
        ],
        "cannot_do": [
            "Manage role-assignable groups unless explicitly granted (Privileged Role Admin needed)",
            "Manage users or directory roles",
        ],
        "docs_url": _e("groups-administrator"),
    },
    "Compliance Administrator": {
        "provider": Provider.ENTRA.value, "name": "Compliance Administrator", "tier": "T2",
        "description": "Can read and manage compliance configuration and reports in Microsoft Entra ID and Microsoft 365.",
        "can_do": [
            "Manage compliance policies in Microsoft Purview",
            "Configure eDiscovery (read+write in some workspaces)",
            "Read sign-in and audit reports",
        ],
        "cannot_do": [
            "Manage directory users / roles / apps",
            "Read mailbox/file content without explicit eDiscovery role assignment",
        ],
        "docs_url": _e("compliance-administrator"),
    },
    "Billing Administrator": {
        "provider": Provider.ENTRA.value, "name": "Billing Administrator", "tier": "T2",
        "description": "Can perform common billing related tasks like updating payment information.",
        "can_do": [
            "Manage subscriptions, purchase services, view invoices",
            "Update billing contact and payment method",
        ],
        "cannot_do": [
            "Manage users, groups, apps, or directory roles",
            "Read non-billing data",
        ],
        "docs_url": _e("billing-administrator"),
    },
    "Directory Writers": {
        "provider": Provider.ENTRA.value, "name": "Directory Writers", "tier": "T2",
        "description": "Can read and write basic directory information. For granting access to applications, not intended for users.",
        "can_do": [
            "Read most directory objects",
            "Update basic user properties (display name, contact info)",
            "Create / update / delete groups and group memberships",
        ],
        "cannot_do": [
            "Create or delete user accounts",
            "Manage roles or sensitive properties",
        ],
        "docs_url": _e("directory-writers"),
    },
    "Azure Information Protection Administrator": {
        "provider": Provider.ENTRA.value, "name": "Azure Information Protection Administrator", "tier": "T2",
        "description": "Can manage all aspects of the Azure Information Protection product.",
        "can_do": [
            "Configure sensitivity labels and label policies",
            "Manage AIP scanner and tracking settings",
        ],
        "cannot_do": [
            "Manage users or directory roles",
            "Read protected content (only configure protection)",
        ],
        "docs_url": _e("azure-information-protection-administrator"),
    },

    # ── T3: Low / read-only ─────────────────────────────────────────────────
    "Directory Readers": {
        "provider": Provider.ENTRA.value, "name": "Directory Readers", "tier": "T3",
        "description": "Can read basic directory information. Commonly used to grant directory read access to applications and guests.",
        "can_do": ["Read most directory objects (users, groups, apps — basic properties)"],
        "cannot_do": ["Modify any directory data", "Read secrets / credentials"],
        "docs_url": _e("directory-readers"),
    },
    "Directory Synchronization Accounts": {
        "provider": Provider.ENTRA.value, "name": "Directory Synchronization Accounts", "tier": "T3",
        "description": "Only used by Microsoft Entra Connect service.",
        "can_do": ["Sync on-prem AD objects to Entra ID"],
        "cannot_do": ["Not intended for use by humans — assignment to a user is a red flag"],
        "docs_url": _e("directory-synchronization-accounts"),
    },
    "Reports Reader": {
        "provider": Provider.ENTRA.value, "name": "Reports Reader", "tier": "T3",
        "description": "Can read sign-in and audit reports.",
        "can_do": ["Read Entra sign-in logs, audit logs, and usage reports"],
        "cannot_do": ["Modify any directory data"],
        "docs_url": _e("reports-reader"),
    },
    "Message Center Reader": {
        "provider": Provider.ENTRA.value, "name": "Message Center Reader", "tier": "T3",
        "description": "Can read messages and updates for their organization in Message Center only.",
        "can_do": ["Read Microsoft 365 Message Center posts"],
        "cannot_do": ["Anything else"],
        "docs_url": _e("message-center-reader"),
    },
    "License Administrator": {
        "provider": Provider.ENTRA.value, "name": "License Administrator", "tier": "T3",
        "description": "Can manage product licenses on users and groups.",
        "can_do": ["Assign / remove user licenses", "Manage license usage location"],
        "cannot_do": ["Manage users, groups, or directory roles"],
        "docs_url": _e("license-administrator"),
    },
    "Service Support Administrator": {
        "provider": Provider.ENTRA.value, "name": "Service Support Administrator", "tier": "T3",
        "description": "Can read service health information and manage support tickets.",
        "can_do": ["Read service health", "Open and manage Microsoft support tickets"],
        "cannot_do": ["Modify directory data"],
        "docs_url": _e("service-support-administrator"),
    },
    "Usage Summary Reports Reader": {
        "provider": Provider.ENTRA.value, "name": "Usage Summary Reports Reader", "tier": "T3",
        "description": "Can see only tenant level aggregates in Microsoft 365 Usage Analytics and Productivity Score.",
        "can_do": ["Read tenant-level usage analytics (aggregated, no user-level)"],
        "cannot_do": ["Read user-level activity data"],
        "docs_url": _e("usage-summary-reports-reader"),
    },
    "Security Reader": {
        "provider": Provider.ENTRA.value, "name": "Security Reader", "tier": "T3",
        "description": "Can read security information and reports in Microsoft Entra ID and Microsoft 365.",
        "can_do": [
            "Read all Identity Protection signals and Conditional Access config",
            "Read security alerts and reports across Microsoft 365",
        ],
        "cannot_do": ["Modify security configuration or remediate alerts"],
        "docs_url": _e("security-reader"),
    },

    # ── Legacy ──────────────────────────────────────────────────────────────
    "Company Administrator": {
        "provider": Provider.ENTRA.value, "name": "Company Administrator", "tier": "T0",
        "description": "Legacy display name for Global Administrator. Same permissions.",
        "can_do": ["See Global Administrator"],
        "cannot_do": ["See Global Administrator"],
        "docs_url": _e("global-administrator"),
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# Azure RBAC — built-in roles
# ═════════════════════════════════════════════════════════════════════════════
_RBAC: dict[str, RoleMeta] = {
    # ── T1: Critical (subscription-level admin) ─────────────────────────────
    "Owner": {
        "provider": Provider.AZURE_RBAC.value, "name": "Owner", "tier": "T1",
        "description": "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
        "can_do": [
            "Read / write / delete every resource in the scope",
            "Assign any Azure RBAC role to any principal at this scope or below",
            "Modify locks and policy at this scope",
        ],
        "cannot_do": [
            "Modify Entra directory objects (users, groups, app registrations) — that's Entra roles",
            "Bypass Azure Policy deny rules",
        ],
        "docs_url": _r("owner"),
    },
    "User Access Administrator": {
        "provider": Provider.AZURE_RBAC.value, "name": "User Access Administrator", "tier": "T1",
        "description": "Lets you manage user access to Azure resources.",
        "can_do": [
            "Assign any Azure RBAC role to any principal at this scope or below",
            'Use the "Access management for Azure resources" toggle (when held at tenant root) to grant self Owner on every subscription',
        ],
        "cannot_do": [
            "Read or modify resource data directly (must assign self the role first)",
            "Modify Entra directory roles",
        ],
        "docs_url": _r("user-access-administrator"),
    },
    "Role Based Access Control Administrator": {
        "provider": Provider.AZURE_RBAC.value, "name": "Role Based Access Control Administrator", "tier": "T1",
        "description": "Manage access to Azure resources by assigning roles using Azure RBAC. Cannot grant access to others.",
        "can_do": [
            "Assign and remove Azure RBAC role assignments at the scope",
            "Read role definitions",
        ],
        "cannot_do": [
            "Assign User Access Administrator or Owner roles",
            "Manage resource data",
        ],
        "docs_url": _r("role-based-access-control-administrator"),
    },

    # ── T2: High ────────────────────────────────────────────────────────────
    "Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Contributor", "tier": "T2",
        "description": "Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC.",
        "can_do": [
            "Read / write / delete every resource in the scope",
            "Modify resource configuration, restart, redeploy",
        ],
        "cannot_do": [
            "Assign Azure RBAC roles (no Microsoft.Authorization/roleAssignments/write)",
            "Modify Entra directory objects",
        ],
        "docs_url": _r("contributor"),
    },
    "Key Vault Administrator": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Administrator", "tier": "T2",
        "description": "Perform all data plane operations on a key vault and all objects in it, including certificates, keys, and secrets.",
        "can_do": [
            "Read, write, and delete keys, secrets, certificates in the vault",
            "Configure vault firewall and data-plane policies",
        ],
        "cannot_do": [
            "Manage role assignments on the vault (needs Owner / User Access Admin)",
            "Modify vault management-plane settings outside data ops",
        ],
        "docs_url": _r("key-vault-administrator"),
    },
    "Storage Blob Data Owner": {
        "provider": Provider.AZURE_RBAC.value, "name": "Storage Blob Data Owner", "tier": "T2",
        "description": "Provides full access to Azure Storage blob containers and data, including assigning POSIX access control.",
        "can_do": [
            "Read, write, delete blob containers and blob data",
            "Set POSIX ACLs (for ADLS Gen2)",
        ],
        "cannot_do": [
            "Manage storage account configuration (use Storage Account Contributor)",
            "Manage Azure RBAC role assignments",
        ],
        "docs_url": _r("storage-blob-data-owner"),
    },
    "Virtual Machine Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Virtual Machine Contributor", "tier": "T2",
        "description": "Lets you manage virtual machines, but not access to them, and not the virtual network or storage account they're connected to.",
        "can_do": [
            "Create, modify, delete VMs in the scope",
            "Reset password / SSH key on managed VMs",
            "Run extensions (including command execution extensions)",
        ],
        "cannot_do": [
            "Manage the VM's vNet or storage account",
            "Sign in to the VM (requires VM Admin/User Login)",
        ],
        "docs_url": _r("virtual-machine-contributor"),
    },
    "Virtual Machine Administrator Login": {
        "provider": Provider.AZURE_RBAC.value, "name": "Virtual Machine Administrator Login", "tier": "T2",
        "description": "View Virtual Machines in the portal and login as administrator.",
        "can_do": ["Sign in to Azure-AD-joined VMs as local administrator"],
        "cannot_do": ["Modify VM configuration"],
        "docs_url": _r("virtual-machine-administrator-login"),
    },
    "Managed Identity Operator": {
        "provider": Provider.AZURE_RBAC.value, "name": "Managed Identity Operator", "tier": "T2",
        "description": "Read and Assign User Assigned Identity.",
        "can_do": ["Read user-assigned managed identities", "Assign UAMIs to resources (VMs, Function Apps, etc.)"],
        "cannot_do": ["Create or delete managed identities (needs Managed Identity Contributor)"],
        "docs_url": _r("managed-identity-operator"),
    },
    "Managed Identity Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Managed Identity Contributor", "tier": "T2",
        "description": "Create, Read, Update, and Delete User Assigned Identity.",
        "can_do": ["Full CRUD on user-assigned managed identities"],
        "cannot_do": ["Assign UAMIs to resources (use Managed Identity Operator)"],
        "docs_url": _r("managed-identity-contributor"),
    },

    # ── T3: Medium (data-plane / service-specific write) ────────────────────
    "Key Vault Secrets Officer": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Secrets Officer", "tier": "T3",
        "description": "Perform any action on the secrets of a key vault, except manage permissions.",
        "can_do": ["Read, write, delete, recover secrets in the vault"],
        "cannot_do": ["Manage keys or certificates", "Manage role assignments"],
        "docs_url": _r("key-vault-secrets-officer"),
    },
    "Key Vault Crypto Officer": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Crypto Officer", "tier": "T3",
        "description": "Perform any action on the keys of a key vault, except manage permissions.",
        "can_do": ["Read, write, delete, rotate keys in the vault", "Perform cryptographic operations (sign, encrypt, decrypt)"],
        "cannot_do": ["Manage secrets or certificates", "Manage role assignments"],
        "docs_url": _r("key-vault-crypto-officer"),
    },
    "Key Vault Certificates Officer": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Certificates Officer", "tier": "T3",
        "description": "Perform any action on the certificates of a key vault, except manage permissions.",
        "can_do": ["Read, write, delete, import certificates"],
        "cannot_do": ["Manage keys or secrets", "Manage role assignments"],
        "docs_url": _r("key-vault-certificates-officer"),
    },
    "Key Vault Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Contributor", "tier": "T3",
        "description": "Lets you manage key vaults, but does not allow you to assign roles in Azure RBAC, and does not allow you to access secrets, keys, or certificates.",
        "can_do": ["Create, update, delete key vaults (management plane)", "Configure firewall, soft-delete, purge-protection"],
        "cannot_do": ["Read data-plane content (keys, secrets, certs)", "Manage role assignments"],
        "docs_url": _r("key-vault-contributor"),
    },
    "Storage Blob Data Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Storage Blob Data Contributor", "tier": "T3",
        "description": "Read, write, and delete Azure Storage containers and blobs.",
        "can_do": ["Read, write, delete blob containers and data"],
        "cannot_do": ["Set POSIX ACLs (use Storage Blob Data Owner)", "Manage storage account config"],
        "docs_url": _r("storage-blob-data-contributor"),
    },
    "Storage Account Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Storage Account Contributor", "tier": "T3",
        "description": "Permits management of storage accounts. Provides access to the account key, which can be used to access data via Shared Key authorization.",
        "can_do": ["Manage storage account config", "Read account keys (full data access via Shared Key)"],
        "cannot_do": ["Assign Azure RBAC roles"],
        "docs_url": _r("storage-account-contributor"),
    },
    "Storage Queue Data Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Storage Queue Data Contributor", "tier": "T3",
        "description": "Read, write, and delete Azure Storage queues and queue messages.",
        "can_do": ["Full data-plane access on queues"],
        "cannot_do": ["Manage queue / account config"],
        "docs_url": _r("storage-queue-data-contributor"),
    },
    "Storage Table Data Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Storage Table Data Contributor", "tier": "T3",
        "description": "Allows for read, write and delete access to Azure Storage tables and entities.",
        "can_do": ["Full data-plane access on tables and entities"],
        "cannot_do": ["Manage table / account config"],
        "docs_url": _r("storage-table-data-contributor"),
    },
    "Network Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Network Contributor", "tier": "T3",
        "description": "Lets you manage networks, but not access to them.",
        "can_do": ["Manage vNets, NSGs, route tables, peerings, firewalls"],
        "cannot_do": ["Access compute resources connected to networks"],
        "docs_url": _r("network-contributor"),
    },
    "SQL DB Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "SQL DB Contributor", "tier": "T3",
        "description": "Lets you manage SQL databases, but not access to them. Also, you can't manage their security-related policies or their parent SQL servers.",
        "can_do": ["Create, update, delete SQL databases (management plane)"],
        "cannot_do": ["Connect to database data (needs separate SQL login)", "Manage parent SQL server"],
        "docs_url": _r("sql-db-contributor"),
    },
    "SQL Server Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "SQL Server Contributor", "tier": "T3",
        "description": "Lets you manage SQL servers and databases, but not access to them, and not their security-related policies.",
        "can_do": ["Create, update, delete SQL servers and their databases"],
        "cannot_do": ["Connect to data", "Manage server security policies"],
        "docs_url": _r("sql-server-contributor"),
    },
    "Logic App Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Logic App Contributor", "tier": "T3",
        "description": "Lets you manage logic apps, but not change access to them.",
        "can_do": ["Create, update, delete logic app definitions", "Read run history and trigger logic apps"],
        "cannot_do": ["Assign roles on the logic app"],
        "docs_url": _r("logic-app-contributor"),
    },
    "Automation Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Automation Contributor", "tier": "T3",
        "description": "Manage Azure Automation resources and other resources using Azure Automation.",
        "can_do": ["Create, update, delete Automation accounts", "Run runbooks", "Manage Run As accounts (legacy)"],
        "cannot_do": ["Assign roles on the Automation account"],
        "docs_url": _r("automation-contributor"),
    },
    "Data Factory Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Data Factory Contributor", "tier": "T3",
        "description": "Create and manage Data Factory, along with child resources within it.",
        "can_do": ["Manage Data Factory pipelines, datasets, linked services", "Trigger pipeline runs"],
        "cannot_do": ["Manage role assignments on the Data Factory"],
        "docs_url": _r("data-factory-contributor"),
    },
    "Monitoring Contributor": {
        "provider": Provider.AZURE_RBAC.value, "name": "Monitoring Contributor", "tier": "T3",
        "description": "Can read all monitoring data and edit monitoring settings.",
        "can_do": ["Read all metrics/logs", "Edit alert rules, action groups, diagnostic settings"],
        "cannot_do": ["Manage workspace role assignments"],
        "docs_url": _r("monitoring-contributor"),
    },

    # ── T4: Low / read-only ─────────────────────────────────────────────────
    "Reader": {
        "provider": Provider.AZURE_RBAC.value, "name": "Reader", "tier": "T4",
        "description": "View all resources, but does not allow you to make any changes.",
        "can_do": ["Read every resource in the scope (configuration, not data)"],
        "cannot_do": ["Modify any resource", "Read data-plane content (mailboxes, blobs, secrets)"],
        "docs_url": _r("reader"),
    },
    "Storage Blob Data Reader": {
        "provider": Provider.AZURE_RBAC.value, "name": "Storage Blob Data Reader", "tier": "T4",
        "description": "Read and list Azure Storage containers and blobs.",
        "can_do": ["Read blob containers and blob data"],
        "cannot_do": ["Write / delete blobs", "Modify storage account config"],
        "docs_url": _r("storage-blob-data-reader"),
    },
    "Key Vault Reader": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Reader", "tier": "T4",
        "description": "Read metadata of key vaults and its certificates, keys, and secrets. Cannot read sensitive values such as secret contents or key material.",
        "can_do": ["List keys / secrets / certificates (metadata only)"],
        "cannot_do": ["Read secret values or key material"],
        "docs_url": _r("key-vault-reader"),
    },
    "Key Vault Secrets User": {
        "provider": Provider.AZURE_RBAC.value, "name": "Key Vault Secrets User", "tier": "T4",
        "description": "Read secret contents.",
        "can_do": ["Read secret values (data-plane GET on secrets)"],
        "cannot_do": ["Write secrets, manage keys/certs"],
        "docs_url": _r("key-vault-secrets-user"),
    },
    "Monitoring Reader": {
        "provider": Provider.AZURE_RBAC.value, "name": "Monitoring Reader", "tier": "T4",
        "description": "Can read all monitoring data (metrics, logs, etc.).",
        "can_do": ["Read all metrics and logs in the scope"],
        "cannot_do": ["Modify alerts or diagnostic settings"],
        "docs_url": _r("monitoring-reader"),
    },
    "Security Reader": {
        "provider": Provider.AZURE_RBAC.value, "name": "Security Reader", "tier": "T4",
        "description": "View permissions for Microsoft Defender for Cloud. Can view recommendations, alerts, security policies, and security states.",
        "can_do": ["Read Defender for Cloud recommendations, alerts, policies, state"],
        "cannot_do": ["Modify security configuration or remediate findings"],
        "docs_url": _r("security-reader"),
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# AWS IAM — common managed policies (treated as "roles" in our domain model)
# ═════════════════════════════════════════════════════════════════════════════
_AWS: dict[str, RoleMeta] = {
    "AdministratorAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AdministratorAccess", "tier": "T1",
        "description": "Provides full access to AWS services and resources.",
        "can_do": ["All actions on all resources, including IAM"],
        "cannot_do": ["Bypass SCPs at the AWS Organizations level"],
        "docs_url": _a("AdministratorAccess"),
    },
    "PowerUserAccess": {
        "provider": Provider.AWS_IAM.value, "name": "PowerUserAccess", "tier": "T2",
        "description": "Provides full access to AWS services and resources, but does not allow management of users and groups.",
        "can_do": ["Full access to all AWS services except IAM management"],
        "cannot_do": ["Create / modify IAM users, groups, roles, policies"],
        "docs_url": _a("PowerUserAccess"),
    },
    "IAMFullAccess": {
        "provider": Provider.AWS_IAM.value, "name": "IAMFullAccess", "tier": "T1",
        "description": "Provides full access to IAM via the AWS Management Console.",
        "can_do": [
            "Create / modify / delete IAM users, groups, roles, policies",
            "Attach AdministratorAccess to self → full account takeover in one step",
        ],
        "cannot_do": ["Manage non-IAM AWS services"],
        "docs_url": _a("IAMFullAccess"),
    },
    "IAMReadOnlyAccess": {
        "provider": Provider.AWS_IAM.value, "name": "IAMReadOnlyAccess", "tier": "T4",
        "description": "Provides read only access to IAM via the AWS Management Console.",
        "can_do": ["Read IAM users, groups, roles, policies, credential reports"],
        "cannot_do": ["Modify IAM", "Manage non-IAM services"],
        "docs_url": _a("IAMReadOnlyAccess"),
    },
    "ReadOnlyAccess": {
        "provider": Provider.AWS_IAM.value, "name": "ReadOnlyAccess", "tier": "T4",
        "description": "Provides read-only access to AWS services and resources.",
        "can_do": ["Read all AWS service metadata and most data-plane reads"],
        "cannot_do": ["Modify any resource"],
        "docs_url": _a("ReadOnlyAccess"),
    },
    "AmazonS3FullAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AmazonS3FullAccess", "tier": "T2",
        "description": "Provides full access to all buckets via the AWS Management Console.",
        "can_do": ["Read, write, delete any S3 bucket and object", "Modify bucket policy and ACLs"],
        "cannot_do": ["Manage non-S3 services"],
        "docs_url": _a("AmazonS3FullAccess"),
    },
    "AmazonS3ReadOnlyAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AmazonS3ReadOnlyAccess", "tier": "T4",
        "description": "Provides read only access to all buckets via the AWS Management Console.",
        "can_do": ["List and read S3 buckets and objects"],
        "cannot_do": ["Write / delete S3 data"],
        "docs_url": _a("AmazonS3ReadOnlyAccess"),
    },
    "AmazonEC2FullAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AmazonEC2FullAccess", "tier": "T2",
        "description": "Provides full access to Amazon EC2 via the AWS Management Console.",
        "can_do": ["Launch / terminate EC2 instances", "Manage EBS, AMIs, security groups, key pairs"],
        "cannot_do": ["Manage IAM or non-EC2 services"],
        "docs_url": _a("AmazonEC2FullAccess"),
    },
    "AWSBillingReadOnlyAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AWSBillingReadOnlyAccess", "tier": "T4",
        "description": "Allows users to view bills on the Billing console.",
        "can_do": ["Read billing data and invoices"],
        "cannot_do": ["Modify billing or any other resources"],
        "docs_url": _a("AWSBillingReadOnlyAccess"),
    },
    "SecurityAudit": {
        "provider": Provider.AWS_IAM.value, "name": "SecurityAudit", "tier": "T4",
        "description": "The security audit template grants access to read security configuration metadata.",
        "can_do": ["Read security-relevant configuration across most AWS services"],
        "cannot_do": ["Modify any resource", "Read data-plane content"],
        "docs_url": _a("SecurityAudit"),
    },
    "AWSCloudShellFullAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AWSCloudShellFullAccess", "tier": "T3",
        "description": "Grants full access to AWS CloudShell and its features.",
        "can_do": ["Launch CloudShell sessions; upload/download files; run AWS CLI"],
        "cannot_do": ["Anything not granted by the user's other policies"],
        "docs_url": _a("AWSCloudShellFullAccess"),
    },
    "AWSOrganizationsFullAccess": {
        "provider": Provider.AWS_IAM.value, "name": "AWSOrganizationsFullAccess", "tier": "T1",
        "description": "Provides full access to AWS Organizations.",
        "can_do": [
            "Create / move / close accounts in the org",
            "Manage SCPs (can bypass own restrictions via policy edit)",
            "Enable / disable AWS services across the org",
        ],
        "cannot_do": ["Resources inside member accounts directly (needs cross-account role)"],
        "docs_url": _a("AWSOrganizationsFullAccess"),
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# GCP IAM — basic + key predefined roles
# ═════════════════════════════════════════════════════════════════════════════
_GCP: dict[str, RoleMeta] = {
    "roles/owner": {
        "provider": Provider.GCP_IAM.value, "name": "roles/owner", "tier": "T1",
        "description": "Full access to most Google Cloud resources. Includes Editor permissions plus the ability to manage roles and billing for a project.",
        "can_do": [
            "All Editor permissions",
            "Manage IAM policy on the project / resource",
            "Set up billing for the project",
        ],
        "cannot_do": ["Bypass Organization Policy constraints"],
        "docs_url": _g(),
    },
    "roles/editor": {
        "provider": Provider.GCP_IAM.value, "name": "roles/editor", "tier": "T2",
        "description": "All viewer permissions, plus permissions for actions that modify state, such as changing existing resources.",
        "can_do": ["Read / write / delete most resources", "Modify resource configuration"],
        "cannot_do": ["Manage IAM policies", "Modify project metadata (billing, org policies)"],
        "docs_url": _g(),
    },
    "roles/viewer": {
        "provider": Provider.GCP_IAM.value, "name": "roles/viewer", "tier": "T4",
        "description": "Permissions for read-only actions that do not affect state, such as viewing (but not modifying) existing resources or data.",
        "can_do": ["Read most resource configuration and data-plane content"],
        "cannot_do": ["Modify any resource"],
        "docs_url": _g(),
    },
    "roles/iam.securityAdmin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/iam.securityAdmin", "tier": "T1",
        "description": "Get and set any IAM policy. Permits granting IAM roles to any principal at any level.",
        "can_do": [
            "Read / write IAM policy on any resource in the scope",
            "Grant self Owner role → project takeover in one step",
        ],
        "cannot_do": ["Modify non-IAM resources directly"],
        "docs_url": _g(),
    },
    "roles/iam.roleAdmin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/iam.roleAdmin", "tier": "T2",
        "description": "Provides access to all custom roles in the project.",
        "can_do": ["Create, update, delete custom IAM roles in the project"],
        "cannot_do": ["Grant or revoke role assignments (needs securityAdmin)"],
        "docs_url": _g(),
    },
    "roles/iam.serviceAccountAdmin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/iam.serviceAccountAdmin", "tier": "T1",
        "description": "Create and manage service accounts.",
        "can_do": [
            "Create, update, delete service accounts in the project",
            "Manage IAM policy on individual service accounts",
        ],
        "cannot_do": ["Mint keys for SAs (needs serviceAccountKeyAdmin)", "Impersonate SAs directly"],
        "docs_url": _g(),
    },
    "roles/iam.serviceAccountKeyAdmin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/iam.serviceAccountKeyAdmin", "tier": "T1",
        "description": "Create and manage (and rotate) service account keys.",
        "can_do": [
            "Mint long-lived keys for ANY service account in the project",
            "Use minted key to impersonate the SA → escalate to that SA's privileges",
        ],
        "cannot_do": ["Create new service accounts", "Modify SA IAM policy"],
        "docs_url": _g(),
    },
    "roles/iam.serviceAccountTokenCreator": {
        "provider": Provider.GCP_IAM.value, "name": "roles/iam.serviceAccountTokenCreator", "tier": "T1",
        "description": "Impersonate service accounts (create OAuth2 access tokens, sign blobs or JWTs, etc.).",
        "can_do": [
            "Mint short-lived OAuth tokens for SAs you hold this role on",
            "Sign blobs / JWTs as the SA",
        ],
        "cannot_do": ["Create or modify service accounts"],
        "docs_url": _g(),
    },
    "roles/storage.admin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/storage.admin", "tier": "T2",
        "description": "Grants full control of buckets and objects.",
        "can_do": ["Read, write, delete all Cloud Storage buckets and objects", "Modify bucket IAM policy"],
        "cannot_do": ["Manage non-Storage resources"],
        "docs_url": _g(),
    },
    "roles/compute.admin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/compute.admin", "tier": "T2",
        "description": "Full control of all Compute Engine resources.",
        "can_do": ["Manage all Compute Engine resources (instances, disks, networks, firewalls)"],
        "cannot_do": ["Manage IAM at project level", "Manage non-Compute services"],
        "docs_url": _g(),
    },
    "roles/cloudkms.admin": {
        "provider": Provider.GCP_IAM.value, "name": "roles/cloudkms.admin", "tier": "T2",
        "description": "Provides access to Cloud KMS resources, except for encrypt/decrypt operations.",
        "can_do": ["Manage key rings, crypto keys, key versions, IAM policy on KMS resources"],
        "cannot_do": ["Perform encrypt/decrypt (separate role: cloudkms.cryptoKeyEncrypterDecrypter)"],
        "docs_url": _g(),
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# Combined lookup + accessors
# ═════════════════════════════════════════════════════════════════════════════

_BY_PROVIDER: dict[str, dict[str, RoleMeta]] = {
    Provider.ENTRA.value:      _ENTRA,
    Provider.AZURE_RBAC.value: _RBAC,
    Provider.AWS_IAM.value:    _AWS,
    Provider.GCP_IAM.value:    _GCP,
}


def _default(role_name: str, provider: str = Provider.UNKNOWN.value) -> RoleMeta:
    return {
        "provider":    provider,
        "name":        role_name,
        "description": "Role definition not catalogued. Consult the cloud provider's IAM documentation for the exact permissions it grants before reasoning about blast radius.",
        "can_do":      [],
        "cannot_do":   [],
        "docs_url":    "",
        "tier":        "unknown",
    }


def get_role_metadata(provider: str | Provider, role_name: str) -> RoleMeta:
    """Look up role metadata for a known provider. Returns a non-claiming
    default if the role isn't catalogued (so callers can render safely)."""
    if not role_name:
        return _default("", provider if isinstance(provider, str) else provider.value)
    pv = provider.value if isinstance(provider, Provider) else provider
    tbl = _BY_PROVIDER.get(pv)
    if tbl is None:
        return _default(role_name, pv)
    return tbl.get(role_name) or _default(role_name, pv)


def detect_provider(role_name: str) -> Provider:
    """Heuristic provider detection from a role name string. Used when the
    caller doesn't know the source cloud (e.g. mixed lists)."""
    if not role_name:
        return Provider.UNKNOWN
    if role_name.startswith("roles/"):
        return Provider.GCP_IAM
    if role_name in _AWS:
        return Provider.AWS_IAM
    if role_name in _ENTRA:
        return Provider.ENTRA
    if role_name in _RBAC:
        return Provider.AZURE_RBAC
    # Tie-break: roles named "Security Reader" exist in both Entra and RBAC. We
    # prefer Entra (directory) since callers can override with explicit provider.
    return Provider.UNKNOWN


def get_role_metadata_auto(role_name: str) -> RoleMeta:
    """Look up role metadata without an explicit provider. Tries detect_provider
    first; if that returns UNKNOWN, scans all providers in order."""
    if not role_name:
        return _default("")
    pv = detect_provider(role_name)
    if pv != Provider.UNKNOWN:
        return get_role_metadata(pv, role_name)
    for prov_value, tbl in _BY_PROVIDER.items():
        if role_name in tbl:
            return tbl[role_name]
    return _default(role_name)


def known_roles(provider: Optional[str | Provider] = None) -> list[str]:
    """Diagnostic: list role names catalogued for a provider (or all)."""
    if provider is None:
        return sorted({r for tbl in _BY_PROVIDER.values() for r in tbl.keys()})
    pv = provider.value if isinstance(provider, Provider) else provider
    return sorted((_BY_PROVIDER.get(pv) or {}).keys())
