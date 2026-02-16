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

    # ── AWS (placeholder) ─────────────────────────────────────────
    "AWS_ADMIN_POLICY": {
        "description": "AdministratorAccess policy attached",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
    },
    "AWS_ROOT_USER": {
        "description": "AWS root user account",
        "severity": "critical",
        "points": 450,
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
