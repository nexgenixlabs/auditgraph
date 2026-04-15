"""
AuditGraph Risk Factor Catalog — V2

Declarative risk factor definitions. Each factor has a unique code,
description, severity, points, and category. The discovery engine
matches identity properties against these factors to produce structured
risk_factors JSONB instead of free-text risk_reasons.

New V2 Thresholds:
  0-199   = LOW
  200-499 = MEDIUM
  500-899 = HIGH
  900+    = CRITICAL
"""

from typing import List, Dict, Optional


# ── Factor definitions ─────────────────────────────────────────────

RISK_FACTOR_CATALOG: Dict[str, Dict] = {
    # ── Entra directory roles ──────────────────────────────────────
    "TENANT_ADMIN_ROLE": {
        "description": "Global Administrator: Full tenant control",
        "severity": "critical",
        "points": 400,
        "category": "entra_role",
    },
    "PRIV_ROLE_ADMIN": {
        "description": "Privileged Role Administrator: Can assign any role",
        "severity": "critical",
        "points": 380,
        "category": "entra_role",
    },
    "APP_ADMIN_ROLE": {
        "description": "Application/Cloud App Administrator: Can manage all apps & SPNs",
        "severity": "high",
        "points": 300,
        "category": "entra_role",
    },
    "USER_ADMIN_ROLE": {
        "description": "User Administrator: Can reset passwords, create users",
        "severity": "high",
        "points": 250,
        "category": "entra_role",
    },
    "SECURITY_ADMIN_ROLE": {
        "description": "Security Administrator: Can modify security policies",
        "severity": "high",
        "points": 250,
        "category": "entra_role",
    },
    "EXCHANGE_ADMIN_ROLE": {
        "description": "Exchange Administrator: Full mailbox access",
        "severity": "medium",
        "points": 200,
        "category": "entra_role",
    },
    "SHAREPOINT_ADMIN_ROLE": {
        "description": "SharePoint Administrator: Full document access",
        "severity": "medium",
        "points": 200,
        "category": "entra_role",
    },

    # ── Azure RBAC roles ───────────────────────────────────────────
    "SUBSCRIPTION_OWNER": {
        "description": "Owner on Subscription: Full control including IAM",
        "severity": "critical",
        "points": 350,
        "category": "rbac_role",
    },
    "UAA_ROLE": {
        "description": "User Access Administrator: Can grant any role to any user",
        "severity": "critical",
        "points": 320,
        "category": "rbac_role",
    },
    "SUBSCRIPTION_CONTRIBUTOR": {
        "description": "Contributor on Subscription: Can create/modify/delete all resources",
        "severity": "high",
        "points": 280,
        "category": "rbac_role",
    },
    "RG_OWNER": {
        "description": "Owner on Resource Group: Can delete all resources, modify access",
        "severity": "high",
        "points": 250,
        "category": "rbac_role",
    },
    "RG_CONTRIBUTOR": {
        "description": "Contributor on Resource Group: Broad resource modification access",
        "severity": "medium",
        "points": 150,
        "category": "rbac_role",
    },
    "RESOURCE_OWNER": {
        "description": "Owner role on individual resource",
        "severity": "medium",
        "points": 120,
        "category": "rbac_role",
    },
    "KEYVAULT_FULL_ACCESS": {
        "description": "Key Vault Admin/Officer: Access to secrets/keys/certificates",
        "severity": "high",
        "points": 250,
        "category": "rbac_role",
    },
    "SCOPED_CONTRIBUTOR": {
        "description": "Scoped contributor role: Limited to specific service resources",
        "severity": "low",
        "points": 60,
        "category": "rbac_role",
    },
    "SCOPED_DATA_CONTRIBUTOR": {
        "description": "Data-plane contributor: Can read/write/delete data within specific service",
        "severity": "medium",
        "points": 100,
        "category": "rbac_role",
    },
    "DB_CONTRIBUTOR": {
        "description": "Database contributor: Can manage database resources",
        "severity": "medium",
        "points": 90,
        "category": "rbac_role",
    },
    "NETWORK_CONTRIBUTOR": {
        "description": "Network Contributor: Can manage network resources and security groups",
        "severity": "medium",
        "points": 120,
        "category": "rbac_role",
    },
    "VM_CONTRIBUTOR": {
        "description": "Virtual Machine Contributor: Can manage VMs but not access or networking",
        "severity": "medium",
        "points": 110,
        "category": "rbac_role",
    },

    # ── API permissions ────────────────────────────────────────────
    "DIRECTORY_RW_API": {
        "description": "Graph API Write Access: Can modify tenant data",
        "severity": "high",
        "points": 300,
        "category": "api_permission",
    },
    "DIRECTORY_READ_ALL_API": {
        "description": "Graph API Read-All Access: Broad data access",
        "severity": "medium",
        "points": 180,
        "category": "api_permission",
    },

    # ── Credential risks ──────────────────────────────────────────
    "SECRET_EXPIRED": {
        "description": "Has expired credentials — unrotated secrets",
        "severity": "high",
        "points": 300,
        "category": "credential",
    },
    "SECRET_EXPIRING_SOON": {
        "description": "Credentials expiring within 30 days",
        "severity": "medium",
        "points": 200,
        "category": "credential",
    },
    "MULTIPLE_ACTIVE_SECRETS": {
        "description": "Multiple active credentials — increased attack surface",
        "severity": "medium",
        "points": 120,
        "category": "credential",
    },

    # ── Usage / activity ──────────────────────────────────────────
    "NEVER_USED": {
        "description": "Never used with active credentials — zombie identity",
        "severity": "medium",
        "points": 200,
        "category": "usage",
    },
    "STALE_GT_90D": {
        "description": "Dormant 90+ days with active credentials",
        "severity": "medium",
        "points": 150,
        "category": "usage",
    },
    "PRIVILEGED_AND_NEVER_USED": {
        "description": "Privileged identity that has never been used",
        "severity": "high",
        "points": 300,
        "category": "usage",
    },

    # ── Trust / external ──────────────────────────────────────────
    "EXTERNAL_PRIVILEGED": {
        "description": "External/guest identity with privileged roles",
        "severity": "high",
        "points": 300,
        "category": "trust",
    },
    "CROSS_TENANT_ADMIN": {
        "description": "Cross-tenant identity with administrative access",
        "severity": "critical",
        "points": 350,
        "category": "trust",
    },

    # ── Structural ────────────────────────────────────────────────
    "ORPHANED_PERMISSIONS": {
        "description": "API permissions without role justification",
        "severity": "medium",
        "points": 100,
        "category": "orphan",
    },
    "ORPHANED_IDENTITY": {
        "description": "No role assignments — potentially orphaned identity",
        "severity": "low",
        "points": 80,
        "category": "orphan",
    },
    "ADMIN_APP_ROLES": {
        "description": "Administrative app role assignments",
        "severity": "medium",
        "points": 200,
        "category": "app_role",
    },
    "STANDARD_APP_ROLES": {
        "description": "Non-admin app role assignments",
        "severity": "low",
        "points": 60,
        "category": "app_role",
    },

    # ── AWS IAM ───────────────────────────────────────────────────
    "AWS_ROOT_USER": {
        "description": "AWS root user account — unrestricted access to all services",
        "severity": "critical",
        "points": 450,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_ADMIN_POLICY": {
        "description": "AdministratorAccess policy attached — full AWS control",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_STAR_POLICY": {
        "description": "Wildcard Action:* / Resource:* policy — unrestricted permissions",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_TRUST_WILDCARD": {
        "description": "Role trust policy allows Principal '*' — any AWS entity can assume",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_IAM_FULL_ACCESS": {
        "description": "IAMFullAccess policy — can create users, roles, and policies",
        "severity": "critical",
        "points": 380,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_CONSOLE_ACCESS_NO_MFA": {
        "description": "Console login enabled without MFA — password-only access",
        "severity": "high",
        "points": 300,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_DANGEROUS_INLINE": {
        "description": "Inline policy with dangerous actions (iam:*, sts:AssumeRole, etc.)",
        "severity": "high",
        "points": 300,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_POWER_USER": {
        "description": "PowerUserAccess policy — full service access except IAM",
        "severity": "high",
        "points": 300,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_CROSS_ACCOUNT_TRUST": {
        "description": "Role trust policy allows cross-account assumption",
        "severity": "high",
        "points": 280,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_NO_MFA": {
        "description": "IAM user with no MFA device configured",
        "severity": "high",
        "points": 250,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_ACCESS_KEY_STALE": {
        "description": "Access key not rotated in 90+ days",
        "severity": "medium",
        "points": 200,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_ACCESS_KEY_NEVER_USED": {
        "description": "Access key created but never used",
        "severity": "medium",
        "points": 180,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_SECURITY_AUDIT": {
        "description": "SecurityAudit policy — read access to security configurations",
        "severity": "medium",
        "points": 150,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_MULTIPLE_ACCESS_KEYS": {
        "description": "Multiple active access keys — increased credential exposure",
        "severity": "medium",
        "points": 120,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_SERVICE_LINKED_ROLE": {
        "description": "AWS service-linked role — managed by AWS service",
        "severity": "low",
        "points": 30,
        "category": "aws_iam",
        "cloud": "aws",
    },

    # ── GCP (placeholder) ─────────────────────────────────────────
    "GCP_ORG_ADMIN": {
        "description": "Organization Administrator role",
        "severity": "critical",
        "points": 400,
        "category": "gcp_iam",
        "cloud": "gcp",
    },
    "GCP_OWNER": {
        "description": "Project Owner role",
        "severity": "critical",
        "points": 350,
        "category": "gcp_iam",
        "cloud": "gcp",
    },
    "GCP_OWNER_ROLE": {
        "description": "Owner role binding on project",
        "severity": "critical",
        "points": 350,
        "category": "gcp_iam",
        "cloud": "gcp",
    },
    "GCP_EDITOR_ROLE": {
        "description": "Editor role binding on project",
        "severity": "high",
        "points": 280,
        "category": "gcp_iam",
        "cloud": "gcp",
    },
    "GCP_PRIVILEGED_ROLE": {
        "description": "Privileged predefined role",
        "severity": "high",
        "points": 250,
        "category": "gcp_iam",
        "cloud": "gcp",
    },
    "GCP_SA_KEY_EXPOSURE": {
        "description": "Service account has user-managed keys",
        "severity": "high",
        "points": 300,
        "category": "gcp_credential",
        "cloud": "gcp",
    },
    "GCP_DISABLED_SA_WITH_KEYS": {
        "description": "Disabled service account still has user-managed keys",
        "severity": "high",
        "points": 250,
        "category": "gcp_credential",
        "cloud": "gcp",
    },
}


def score_to_level_v2(score: int) -> str:
    """Convert a risk score to a risk level using V2 thresholds."""
    if score >= 900:
        return "critical"
    elif score >= 500:
        return "high"
    elif score >= 200:
        return "medium"
    elif score > 0:
        return "low"
    return "info"


def make_factor(code: str, evidence: str = "") -> Dict:
    """
    Create a structured risk factor dict from a catalog code.

    Returns:
        {"code": "...", "description": "...", "severity": "...",
         "points": N, "category": "...", "evidence": "..."}
    """
    entry = RISK_FACTOR_CATALOG.get(code)
    if not entry:
        return {
            "code": code,
            "description": code,
            "severity": "low",
            "points": 0,
            "category": "unknown",
            "evidence": evidence,
        }
    return {
        "code": code,
        "description": entry["description"],
        "severity": entry["severity"],
        "points": entry["points"],
        "category": entry["category"],
        "evidence": evidence,
    }
