"""
AuditGraph shared constants — single source of truth for enums and type strings.

All resource_type, identity_category, and verdict string literals MUST reference
these constants. Do not use raw string literals elsewhere in the codebase.
"""


# ── Compute Resource Types (snake_case convention) ─────────────────
class ComputeResourceType:
    APP_SERVICE = 'app_service'
    FUNCTION = 'function_app'
    VIRTUAL_MACHINE = 'virtual_machine'
    LOGIC_APP = 'logic_app'

    ALL = frozenset({APP_SERVICE, FUNCTION, VIRTUAL_MACHINE, LOGIC_APP})
    WEB_TYPES = frozenset({APP_SERVICE, FUNCTION})  # types with env var scanning


# ── Container / Orchestration Resource Types ───────────────────────
class ContainerResourceType:
    AKS_CLUSTER = 'aks_cluster'
    ACR_REGISTRY = 'acr_registry'


# ── Federated Credential Issuer Types ──────────────────────────────
class FederatedIssuerType:
    AKS = 'aks'
    GITHUB = 'github'
    OTHER = 'other'


# ── Lineage Verdict Types ─────────────────────────────────────────
class Verdict:
    HEALTHY = 'HEALTHY'
    NEEDS_REVIEW = 'NEEDS_REVIEW'
    UNUSED = 'UNUSED'
    STALE = 'STALE'
    AT_RISK = 'AT_RISK'
    ORPHANED = 'ORPHANED'
    GHOST_MSI = 'GHOST_MSI'
    FEDERATED_MISCONFIGURED = 'FEDERATED_MISCONFIGURED'
    # FEDERATED_MISCONFIGURED: Fires when a federated identity credential has an
    # overly-broad subject claim that allows unintended principals to assume this identity.

    # Severity ordering (higher = worse)
    SEVERITY = {
        'HEALTHY': 0,
        'NEEDS_REVIEW': 1,
        'UNUSED': 2,
        'STALE': 3,
        'AT_RISK': 4,
        'ORPHANED': 5,
        'GHOST_MSI': 5,
        'FEDERATED_MISCONFIGURED': 4,
    }


# ── Identity Categories ───────────────────────────────────────────
class IdentityCategory:
    SERVICE_PRINCIPAL = 'service_principal'
    MANAGED_IDENTITY_SYSTEM = 'managed_identity_system'
    MANAGED_IDENTITY_USER = 'managed_identity_user'
    HUMAN_USER = 'human_user'
    GUEST = 'guest'
    MICROSOFT_INTERNAL = 'microsoft_internal'

    NHI_TYPES = frozenset({SERVICE_PRINCIPAL, MANAGED_IDENTITY_SYSTEM, MANAGED_IDENTITY_USER})


# ── Database Server Types ──────────────────────────────────────────
class DatabaseServerType:
    AZURE_SQL = 'azure_sql'
    POSTGRESQL = 'postgresql'
    MYSQL = 'mysql'
    COSMOSDB = 'cosmosdb'

    ALL = frozenset({AZURE_SQL, POSTGRESQL, MYSQL, COSMOSDB})


# ── High-Privilege Database Roles ──────────────────────────────────
HIGH_PRIVILEGE_DB_ROLES = [
    'Owner', 'Contributor',
    'SQL Server Contributor',
    'SQL DB Contributor',
    'DocumentDB Account Contributor',
]


# ── Synthetic Identity Types ──────────────────────────────────────
class IdentityType:
    ACR_ADMIN_ACCOUNT = 'acr_admin_account'
