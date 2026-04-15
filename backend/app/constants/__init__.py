"""
AuditGraph shared constants — single source of truth for enums and type strings.

All resource_type, identity_category, and verdict string literals MUST reference
these constants. Do not use raw string literals elsewhere in the codebase.
"""

# ── Query Safety Limits ──────────────────────────────────────────
MAX_QUERY_ROWS = 500  # Defense-in-depth ceiling for cursor.fetchmany()


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
    PAT_GOVERNANCE_RISK = 'PAT_GOVERNANCE_RISK'
    # PAT_GOVERNANCE_RISK: Fires when a Databricks workspace contains
    # active PATs with no expiry date. These are long-lived credentials
    # that bypass Entra ID token lifecycle governance.

    # Severity ordering (higher = worse)
    SEVERITY = {
        'HEALTHY': 0,
        'NEEDS_REVIEW': 1,
        'UNUSED': 2,
        'STALE': 3,
        'PAT_GOVERNANCE_RISK': 3,
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


# ── High-Privilege Database Roles ──────────────────────────────────
from app.constants.roles import RBACRole  # noqa: E402
HIGH_PRIVILEGE_DB_ROLES = [
    RBACRole.OWNER, RBACRole.CONTRIBUTOR,
    RBACRole.SQL_SERVER_CONTRIBUTOR,
    RBACRole.SQL_DB_CONTRIBUTOR,
    RBACRole.DOCUMENTDB_ACCOUNT_CONTRIBUTOR,
]


# ── Synthetic Identity Types ──────────────────────────────────────
class CredentialRiskSQL:
    """SSOT for credential risk identity filtering — matches AGIRS N4 criteria.

    Two variants:
      NHI_CREDENTIAL_RISK_FILTER   — uses `i.` alias, for WHERE clauses
      NHI_CREDENTIAL_RISK_COUNT_FILTER — no alias, for FILTER (WHERE ...) in aggregate queries
    """
    NHI_CREDENTIAL_RISK_FILTER = """
        AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
        AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
        AND i.credential_count > 0
        AND i.credential_expiration IS NOT NULL
        AND i.credential_expiration < NOW() + INTERVAL '30 days'
    """
    NHI_CREDENTIAL_RISK_COUNT_FILTER = """
        identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
        AND NOT COALESCE(is_microsoft_system, false)
        AND credential_count > 0
        AND credential_expiration IS NOT NULL
        AND credential_expiration < NOW() + INTERVAL '30 days'
    """


# ── Remediation Queue ────────────────────────────────────────────
from app.constants.remediation import (  # noqa: E402
    RemediationStatus, RemediationSeverity, VALID_STATUS_TRANSITIONS,
)


class IdentityType:
    ACR_ADMIN_ACCOUNT = 'acr_admin_account'
    ANALYTICS_SERVICE_PRINCIPAL = 'analytics_service_principal'
