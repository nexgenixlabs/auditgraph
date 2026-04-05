"""
SSOT for all privilege role name constants.

Every engine / handler that checks role names MUST import from here.
Do not hard-code role name strings elsewhere in the codebase.

Usage:
    from app.constants.roles import EntraRole, RBACRole
    from app.constants.roles import T0_ENTRA_ROLES_LOWER, ALL_PRIVILEGED_ROLES_LOWER
"""
try:
    from enum import StrEnum
except ImportError:
    from enum import Enum

    class StrEnum(str, Enum):
        """Python 3.9/3.10 backport of StrEnum."""
        pass


# ═══════════════════════════════════════════════════════════════════
# Entra ID Directory Roles
# ═══════════════════════════════════════════════════════════════════

class EntraRole(StrEnum):
    """Azure Entra ID directory roles — canonical Title Case values."""

    # ── T0: Critical (tenant-level admin) ─────────────────────────
    GLOBAL_ADMIN              = "Global Administrator"
    PRIVILEGED_ROLE_ADMIN     = "Privileged Role Administrator"
    PRIVILEGED_AUTH_ADMIN     = "Privileged Authentication Administrator"
    APPLICATION_ADMIN         = "Application Administrator"
    CLOUD_APP_ADMIN           = "Cloud Application Administrator"
    HYBRID_IDENTITY_ADMIN     = "Hybrid Identity Administrator"
    DOMAIN_NAME_ADMIN         = "Domain Name Administrator"
    EXTERNAL_IDP_ADMIN        = "External Identity Provider Administrator"

    # ── T1: High (service-level admin) ────────────────────────────
    USER_ADMIN                = "User Administrator"
    EXCHANGE_ADMIN            = "Exchange Administrator"
    SHAREPOINT_ADMIN          = "SharePoint Administrator"
    TEAMS_ADMIN               = "Teams Administrator"
    SECURITY_ADMIN            = "Security Administrator"
    CONDITIONAL_ACCESS_ADMIN  = "Conditional Access Administrator"
    AUTH_ADMIN                = "Authentication Administrator"
    HELPDESK_ADMIN            = "Helpdesk Administrator"

    # ── T2: Medium ────────────────────────────────────────────────
    INTUNE_ADMIN              = "Intune Administrator"
    PASSWORD_ADMIN            = "Password Administrator"
    GROUPS_ADMIN              = "Groups Administrator"
    COMPLIANCE_ADMIN          = "Compliance Administrator"
    BILLING_ADMIN             = "Billing Administrator"
    DIRECTORY_WRITERS         = "Directory Writers"
    AZURE_INFO_PROTECTION_ADMIN = "Azure Information Protection Administrator"

    # ── T3: Low / read-only ───────────────────────────────────────
    DIRECTORY_READERS         = "Directory Readers"
    DIRECTORY_SYNC_ACCOUNTS   = "Directory Synchronization Accounts"
    REPORTS_READER            = "Reports Reader"
    MESSAGE_CENTER_READER     = "Message Center Reader"
    LICENSE_ADMIN             = "License Administrator"
    SERVICE_SUPPORT_ADMIN     = "Service Support Administrator"
    USAGE_SUMMARY_READER      = "Usage Summary Reports Reader"
    SECURITY_READER           = "Security Reader"

    # ── Legacy alias ──────────────────────────────────────────────
    COMPANY_ADMIN             = "Company Administrator"


# ═══════════════════════════════════════════════════════════════════
# Azure RBAC (ARM) Roles
# ═══════════════════════════════════════════════════════════════════

class RBACRole(StrEnum):
    """Azure RBAC roles — canonical Title Case values."""

    # ── T1: Critical (subscription-level admin) ───────────────────
    OWNER                     = "Owner"
    USER_ACCESS_ADMIN         = "User Access Administrator"
    RBAC_ADMIN                = "Role Based Access Control Administrator"

    # ── T2: High ──────────────────────────────────────────────────
    CONTRIBUTOR               = "Contributor"
    KEY_VAULT_ADMIN           = "Key Vault Administrator"
    STORAGE_BLOB_DATA_OWNER   = "Storage Blob Data Owner"
    VIRTUAL_MACHINE_CONTRIBUTOR = "Virtual Machine Contributor"
    VIRTUAL_MACHINE_ADMIN_LOGIN = "Virtual Machine Administrator Login"
    MANAGED_IDENTITY_OPERATOR = "Managed Identity Operator"
    MANAGED_IDENTITY_CONTRIBUTOR = "Managed Identity Contributor"

    # ── T3: Medium (data-plane / service-specific write) ──────────
    KEY_VAULT_SECRETS_OFFICER = "Key Vault Secrets Officer"
    KEY_VAULT_CRYPTO_OFFICER  = "Key Vault Crypto Officer"
    KEY_VAULT_CERTS_OFFICER   = "Key Vault Certificates Officer"
    KEY_VAULT_CONTRIBUTOR     = "Key Vault Contributor"
    STORAGE_BLOB_DATA_CONTRIBUTOR = "Storage Blob Data Contributor"
    STORAGE_ACCOUNT_CONTRIBUTOR = "Storage Account Contributor"
    STORAGE_QUEUE_DATA_CONTRIBUTOR = "Storage Queue Data Contributor"
    STORAGE_TABLE_DATA_CONTRIBUTOR = "Storage Table Data Contributor"
    NETWORK_CONTRIBUTOR       = "Network Contributor"
    SQL_DB_CONTRIBUTOR        = "SQL DB Contributor"
    SQL_SERVER_CONTRIBUTOR    = "SQL Server Contributor"
    SQL_MANAGED_INSTANCE_CONTRIBUTOR = "SQL Managed Instance Contributor"
    COSMOS_DB_ACCOUNT_READER  = "Cosmos DB Account Reader Role"
    DOCUMENTDB_ACCOUNT_CONTRIBUTOR = "DocumentDB Account Contributor"
    WEB_PLAN_CONTRIBUTOR      = "Web Plan Contributor"
    LOGIC_APP_CONTRIBUTOR     = "Logic App Contributor"
    AUTOMATION_CONTRIBUTOR    = "Automation Contributor"
    DATA_FACTORY_CONTRIBUTOR  = "Data Factory Contributor"
    MONITORING_CONTRIBUTOR    = "Monitoring Contributor"

    # ── T4: Low / read-only ───────────────────────────────────────
    READER                    = "Reader"
    STORAGE_BLOB_DATA_READER  = "Storage Blob Data Reader"
    STORAGE_QUEUE_DATA_MSG_PROCESSOR = "Storage Queue Data Message Processor"
    STORAGE_TABLE_DATA_READER = "Storage Table Data Reader"
    KEY_VAULT_READER          = "Key Vault Reader"
    KEY_VAULT_SECRETS_USER    = "Key Vault Secrets User"
    KEY_VAULT_CERTIFICATE_USER = "Key Vault Certificate User"
    KEY_VAULT_CRYPTO_USER     = "Key Vault Crypto User"
    SQL_DB_READER             = "SQL DB Reader"
    MONITORING_READER         = "Monitoring Reader"
    LOG_ANALYTICS_READER      = "Log Analytics Reader"
    SECURITY_READER           = "Security Reader"
    COST_MANAGEMENT_READER    = "Cost Management Reader"
    BILLING_READER            = "Billing Reader"
    BACKUP_READER             = "Backup Reader"


# ═══════════════════════════════════════════════════════════════════
# Helper
# ═══════════════════════════════════════════════════════════════════

def _lower(s: frozenset[str]) -> frozenset[str]:
    """Return a lowercase copy — for case-insensitive tier matching."""
    return frozenset(r.lower() for r in s)


# ═══════════════════════════════════════════════════════════════════
# AGIRS Tier Frozensets (Entra)
# ═══════════════════════════════════════════════════════════════════

T0_ENTRA_ROLES: frozenset[str] = frozenset({
    EntraRole.GLOBAL_ADMIN, EntraRole.PRIVILEGED_ROLE_ADMIN,
    EntraRole.PRIVILEGED_AUTH_ADMIN, EntraRole.APPLICATION_ADMIN,
    EntraRole.CLOUD_APP_ADMIN, EntraRole.HYBRID_IDENTITY_ADMIN,
    EntraRole.DOMAIN_NAME_ADMIN, EntraRole.EXTERNAL_IDP_ADMIN,
})

T1_ENTRA_ROLES: frozenset[str] = frozenset({
    EntraRole.USER_ADMIN, EntraRole.EXCHANGE_ADMIN,
    EntraRole.SHAREPOINT_ADMIN, EntraRole.TEAMS_ADMIN,
    EntraRole.SECURITY_ADMIN, EntraRole.CONDITIONAL_ACCESS_ADMIN,
    EntraRole.AUTH_ADMIN, EntraRole.HELPDESK_ADMIN,
})


# ═══════════════════════════════════════════════════════════════════
# AGIRS Tier Frozensets (RBAC)
# ═══════════════════════════════════════════════════════════════════

T2_RBAC_ROLES: frozenset[str] = frozenset({
    RBACRole.OWNER, RBACRole.CONTRIBUTOR, RBACRole.USER_ACCESS_ADMIN,
})


# ═══════════════════════════════════════════════════════════════════
# Lowercase variants (SQL LOWER() and .lower() comparisons)
# ═══════════════════════════════════════════════════════════════════

T0_ENTRA_ROLES_LOWER: frozenset[str] = _lower(T0_ENTRA_ROLES)
T1_ENTRA_ROLES_LOWER: frozenset[str] = _lower(T1_ENTRA_ROLES)
T2_RBAC_ROLES_LOWER:  frozenset[str] = _lower(T2_RBAC_ROLES)


# ═══════════════════════════════════════════════════════════════════
# Convenience unions
# ═══════════════════════════════════════════════════════════════════

PRIVILEGED_ENTRA_ROLES:      frozenset[str] = T0_ENTRA_ROLES | T1_ENTRA_ROLES
PRIVILEGED_RBAC_ROLES:       frozenset[str] = T2_RBAC_ROLES
ALL_PRIVILEGED_ROLES:        frozenset[str] = PRIVILEGED_ENTRA_ROLES | PRIVILEGED_RBAC_ROLES
ALL_PRIVILEGED_ROLES_LOWER:  frozenset[str] = _lower(ALL_PRIVILEGED_ROLES)
