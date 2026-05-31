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

#
# AG-E (2026-05-30): Each factor is now tagged with industry framework refs.
#   cis    — CIS Azure / AWS / GCP Foundations Benchmark control ID(s)
#   mitre  — MITRE ATT&CK Cloud Matrix technique ID(s) — IAM/Cloud sub-matrix
# Mappings target the most-specific applicable control. Sources:
#   CIS Microsoft Azure Foundations Benchmark v2.1 (2024)
#   CIS Amazon Web Services Foundations Benchmark v3.0 (2024)
#   CIS Google Cloud Platform Foundations Benchmark v3.0 (2024)
#   MITRE ATT&CK v15 (October 2024) — Enterprise/Cloud
#
RISK_FACTOR_CATALOG: Dict[str, Dict] = {
    # ── Entra directory roles ──────────────────────────────────────
    "TENANT_ADMIN_ROLE": {
        "description": "Global Administrator: Full tenant control",
        "severity": "critical",
        "points": 400,
        "category": "entra_role",
        "cis": ["CIS Azure 1.23"],   # Limit Global Admin count
        "mitre": ["T1078.004"],      # Valid Accounts: Cloud Accounts
    },
    "PRIV_ROLE_ADMIN": {
        "description": "Privileged Role Administrator: Can assign any role",
        "severity": "critical",
        "points": 380,
        "category": "entra_role",
        "cis": ["CIS Azure 1.23"],
        "mitre": ["T1098.003"],      # Account Manipulation: Additional Cloud Roles
    },
    "APP_ADMIN_ROLE": {
        "description": "Application/Cloud App Administrator: Can manage all apps & SPNs",
        "severity": "high",
        "points": 300,
        "category": "entra_role",
        "cis": ["CIS Azure 1.14"],
        "mitre": ["T1098.001"],      # Additional Cloud Credentials
    },
    "USER_ADMIN_ROLE": {
        "description": "User Administrator: Can reset passwords, create users",
        "severity": "high",
        "points": 250,
        "category": "entra_role",
        "cis": ["CIS Azure 1.23"],
        "mitre": ["T1098.003", "T1556.001"],  # Modify Auth Process: Domain Controller
    },
    "SECURITY_ADMIN_ROLE": {
        "description": "Security Administrator: Can modify security policies",
        "severity": "high",
        "points": 250,
        "category": "entra_role",
        "cis": ["CIS Azure 1.23"],
        "mitre": ["T1562.008"],      # Impair Defenses: Disable/Modify Cloud Logs
    },
    "EXCHANGE_ADMIN_ROLE": {
        "description": "Exchange Administrator: Full mailbox access",
        "severity": "medium",
        "points": 200,
        "category": "entra_role",
        "cis": ["CIS Azure 1.23"],
        "mitre": ["T1114.002"],      # Email Collection: Remote Email Collection
    },
    "SHAREPOINT_ADMIN_ROLE": {
        "description": "SharePoint Administrator: Full document access",
        "severity": "medium",
        "points": 200,
        "category": "entra_role",
        "cis": ["CIS Azure 1.23"],
        "mitre": ["T1213.002"],      # Data from Information Repositories: SharePoint
    },

    # ── Azure RBAC roles ───────────────────────────────────────────
    "SUBSCRIPTION_OWNER": {
        "description": "Owner on Subscription: Full control including IAM",
        "severity": "critical",
        "points": 350,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],   # Custom owner roles
        "mitre": ["T1078.004", "T1098.003"],
    },
    "UAA_ROLE": {
        "description": "User Access Administrator: Can grant any role to any user",
        "severity": "critical",
        "points": 320,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1098.003"],
    },
    "SUBSCRIPTION_CONTRIBUTOR": {
        "description": "Contributor on Subscription: Can create/modify/delete all resources",
        "severity": "high",
        "points": 280,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1078.004"],
    },
    "RG_OWNER": {
        "description": "Owner on Resource Group: Can delete all resources, modify access",
        "severity": "high",
        "points": 250,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1098.003"],
    },
    "RG_CONTRIBUTOR": {
        "description": "Contributor on Resource Group: Broad resource modification access",
        "severity": "medium",
        "points": 150,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1078.004"],
    },
    "RESOURCE_OWNER": {
        "description": "Owner role on individual resource",
        "severity": "medium",
        "points": 120,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1078.004"],
    },
    "KEYVAULT_FULL_ACCESS": {
        "description": "Key Vault Admin/Officer: Access to secrets/keys/certificates",
        "severity": "high",
        "points": 250,
        "category": "rbac_role",
        "cis": ["CIS Azure 8.5"],    # Key Vault — limit admin access
        "mitre": ["T1552.001", "T1555.006"],  # Unsecured Creds / Cloud Secrets Mgmt
    },
    "SCOPED_CONTRIBUTOR": {
        "description": "Scoped contributor role: Limited to specific service resources",
        "severity": "low",
        "points": 60,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1078.004"],
    },
    "SCOPED_DATA_CONTRIBUTOR": {
        "description": "Data-plane contributor: Can read/write/delete data within specific service",
        "severity": "medium",
        "points": 100,
        "category": "rbac_role",
        "cis": ["CIS Azure 1.22"],
        "mitre": ["T1530"],          # Data from Cloud Storage
    },
    "DB_CONTRIBUTOR": {
        "description": "Database contributor: Can manage database resources",
        "severity": "medium",
        "points": 90,
        "category": "rbac_role",
        "cis": ["CIS Azure 4.1"],    # DB security
        "mitre": ["T1213.003"],      # Data from Info Repos: Code Repositories
    },
    "NETWORK_CONTRIBUTOR": {
        "description": "Network Contributor: Can manage network resources and security groups",
        "severity": "medium",
        "points": 120,
        "category": "rbac_role",
        "cis": ["CIS Azure 6.1"],    # Network security
        "mitre": ["T1562.007"],      # Impair Defenses: Disable Cloud Firewall
    },
    "VM_CONTRIBUTOR": {
        "description": "Virtual Machine Contributor: Can manage VMs but not access or networking",
        "severity": "medium",
        "points": 110,
        "category": "rbac_role",
        "cis": ["CIS Azure 7.1"],    # VM security
        "mitre": ["T1578.002"],      # Modify Cloud Compute Infra: Create Cloud Instance
    },

    # ── API permissions ────────────────────────────────────────────
    "DIRECTORY_RW_API": {
        "description": "Graph API Write Access: Can modify tenant data",
        "severity": "high",
        "points": 300,
        "category": "api_permission",
        "cis": ["CIS Azure 1.14"],
        "mitre": ["T1098.003"],
    },
    "DIRECTORY_READ_ALL_API": {
        "description": "Graph API Read-All Access: Broad data access",
        "severity": "medium",
        "points": 180,
        "category": "api_permission",
        "cis": ["CIS Azure 1.14"],
        "mitre": ["T1087.004"],      # Account Discovery: Cloud Account
    },

    # ── Credential risks ──────────────────────────────────────────
    "SECRET_EXPIRED": {
        "description": "Has expired credentials — unrotated secrets",
        "severity": "high",
        "points": 300,
        "category": "credential",
        "cis": ["CIS Azure 1.4"],    # No expired keys
        "mitre": ["T1098.001"],      # Additional Cloud Credentials
    },
    "SECRET_EXPIRING_SOON": {
        "description": "Credentials expiring within 30 days",
        "severity": "medium",
        "points": 200,
        "category": "credential",
        "cis": ["CIS Azure 1.4"],
        "mitre": ["T1098.001"],
    },
    "MULTIPLE_ACTIVE_SECRETS": {
        "description": "Multiple active credentials — increased attack surface",
        "severity": "medium",
        "points": 120,
        "category": "credential",
        "cis": ["CIS Azure 1.4"],
        "mitre": ["T1098.001"],
    },

    # ── Usage / activity ──────────────────────────────────────────
    "NEVER_USED": {
        "description": "Never used with active credentials — zombie identity",
        "severity": "medium",
        "points": 200,
        "category": "usage",
        "cis": ["CIS Azure 1.3"],    # Guest users review / Disable dormant
        "mitre": ["T1078.001"],      # Default/Disabled Accounts
    },
    "STALE_GT_90D": {
        "description": "Dormant 90+ days with active credentials",
        "severity": "medium",
        "points": 150,
        "category": "usage",
        "cis": ["CIS Azure 1.3"],
        "mitre": ["T1078.001"],
    },
    "PRIVILEGED_AND_NEVER_USED": {
        "description": "Privileged identity that has never been used",
        "severity": "high",
        "points": 300,
        "category": "usage",
        "cis": ["CIS Azure 1.3", "CIS Azure 1.23"],
        "mitre": ["T1078.001", "T1078.004"],
    },

    # ── Trust / external ──────────────────────────────────────────
    "EXTERNAL_PRIVILEGED": {
        "description": "External/guest identity with privileged roles",
        "severity": "high",
        "points": 300,
        "category": "trust",
        "cis": ["CIS Azure 1.3"],    # Guest user restrictions
        "mitre": ["T1078.004"],
    },
    "CROSS_TENANT_ADMIN": {
        "description": "Cross-tenant identity with administrative access",
        "severity": "critical",
        "points": 350,
        "category": "trust",
        "cis": ["CIS Azure 1.3"],
        "mitre": ["T1078.004", "T1199"],  # Trusted Relationship
    },

    # ── Structural ────────────────────────────────────────────────
    "ORPHANED_PERMISSIONS": {
        "description": "API permissions without role justification",
        "severity": "medium",
        "points": 100,
        "category": "orphan",
        "cis": ["CIS Azure 1.14"],
        "mitre": ["T1098.001"],
    },
    "ORPHANED_IDENTITY": {
        "description": "No role assignments — potentially orphaned identity",
        "severity": "low",
        "points": 80,
        "category": "orphan",
        "cis": ["CIS Azure 1.3"],
        "mitre": ["T1078.001"],
    },
    "ADMIN_APP_ROLES": {
        "description": "Administrative app role assignments",
        "severity": "medium",
        "points": 200,
        "category": "app_role",
        "cis": ["CIS Azure 1.14"],
        "mitre": ["T1098.003"],
    },
    "STANDARD_APP_ROLES": {
        "description": "Non-admin app role assignments",
        "severity": "low",
        "points": 60,
        "category": "app_role",
        "cis": ["CIS Azure 1.14"],
        "mitre": ["T1078.004"],
    },

    # ── AWS IAM ───────────────────────────────────────────────────
    "AWS_ROOT_USER": {
        "description": "AWS root user account — unrestricted access to all services",
        "severity": "critical",
        "points": 450,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.7"],     # Eliminate use of root user
        "mitre": ["T1078.004"],
    },
    "AWS_ADMIN_POLICY": {
        "description": "AdministratorAccess policy attached — full AWS control",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.16"],    # No full admin via inline / attached
        "mitre": ["T1098.003"],
    },
    "AWS_STAR_POLICY": {
        "description": "Wildcard Action:* / Resource:* policy — unrestricted permissions",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.16"],
        "mitre": ["T1098.003"],
    },
    "AWS_TRUST_WILDCARD": {
        "description": "Role trust policy allows Principal '*' — any AWS entity can assume",
        "severity": "critical",
        "points": 400,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.16"],
        "mitre": ["T1199", "T1078.004"],  # Trusted Relationship + Cloud Account
    },
    "AWS_IAM_FULL_ACCESS": {
        "description": "IAMFullAccess policy — can create users, roles, and policies",
        "severity": "critical",
        "points": 380,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.16"],
        "mitre": ["T1098.003"],
    },
    "AWS_CONSOLE_ACCESS_NO_MFA": {
        "description": "Console login enabled without MFA — password-only access",
        "severity": "high",
        "points": 300,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.10"],    # MFA for all IAM users with console
        "mitre": ["T1078.004"],
    },
    "AWS_DANGEROUS_INLINE": {
        "description": "Inline policy with dangerous actions (iam:*, sts:AssumeRole, etc.)",
        "severity": "high",
        "points": 300,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.15"],    # IAM users receive policies only via groups
        "mitre": ["T1098.003"],
    },
    "AWS_POWER_USER": {
        "description": "PowerUserAccess policy — full service access except IAM",
        "severity": "high",
        "points": 300,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.16"],
        "mitre": ["T1078.004"],
    },
    "AWS_CROSS_ACCOUNT_TRUST": {
        "description": "Role trust policy allows cross-account assumption",
        "severity": "high",
        "points": 280,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.20"],    # IAM Access Analyzer external trust review
        "mitre": ["T1199"],
    },
    "AWS_NO_MFA": {
        "description": "IAM user with no MFA device configured",
        "severity": "high",
        "points": 250,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.10"],
        "mitre": ["T1078.004"],
    },
    "AWS_ACCESS_KEY_STALE": {
        "description": "Access key not rotated in 90+ days",
        "severity": "medium",
        "points": 200,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.14"],    # Rotate access keys every 90 days
        "mitre": ["T1098.001"],
    },
    "AWS_ACCESS_KEY_NEVER_USED": {
        "description": "Access key created but never used",
        "severity": "medium",
        "points": 180,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.12"],    # No credentials unused for 45+ days
        "mitre": ["T1078.001"],
    },
    "AWS_SECURITY_AUDIT": {
        "description": "SecurityAudit policy — read access to security configurations",
        "severity": "medium",
        "points": 150,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.16"],
        "mitre": ["T1087.004"],
    },
    "AWS_MULTIPLE_ACCESS_KEYS": {
        "description": "Multiple active access keys — increased credential exposure",
        "severity": "medium",
        "points": 120,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": ["CIS AWS 1.13"],    # Only one active access key per user
        "mitre": ["T1098.001"],
    },
    "AWS_SERVICE_LINKED_ROLE": {
        "description": "AWS service-linked role — managed by AWS service",
        "severity": "low",
        "points": 30,
        "category": "aws_iam",
        "cloud": "aws",
        "cis": [],
        "mitre": [],
    },

    # ── GCP (placeholder) ─────────────────────────────────────────
    "GCP_ORG_ADMIN": {
        "description": "Organization Administrator role",
        "severity": "critical",
        "points": 400,
        "category": "gcp_iam",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.4"],     # Manage service accounts and keys
        "mitre": ["T1078.004", "T1098.003"],
    },
    "GCP_OWNER": {
        "description": "Project Owner role",
        "severity": "critical",
        "points": 350,
        "category": "gcp_iam",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.5"],     # No primitive Owner role for SAs
        "mitre": ["T1078.004"],
    },
    "GCP_OWNER_ROLE": {
        "description": "Owner role binding on project",
        "severity": "critical",
        "points": 350,
        "category": "gcp_iam",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.5"],
        "mitre": ["T1078.004"],
    },
    "GCP_EDITOR_ROLE": {
        "description": "Editor role binding on project",
        "severity": "high",
        "points": 280,
        "category": "gcp_iam",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.5"],
        "mitre": ["T1078.004"],
    },
    "GCP_PRIVILEGED_ROLE": {
        "description": "Privileged predefined role",
        "severity": "high",
        "points": 250,
        "category": "gcp_iam",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.5"],
        "mitre": ["T1098.003"],
    },
    "GCP_SA_KEY_EXPOSURE": {
        "description": "Service account has user-managed keys",
        "severity": "high",
        "points": 300,
        "category": "gcp_credential",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.4"],     # No user-managed SA keys
        "mitre": ["T1098.001"],
    },
    "GCP_DISABLED_SA_WITH_KEYS": {
        "description": "Disabled service account still has user-managed keys",
        "severity": "high",
        "points": 250,
        "category": "gcp_credential",
        "cloud": "gcp",
        "cis": ["CIS GCP 1.4"],
        "mitre": ["T1078.001", "T1098.001"],
    },
    "GHOST_ACCESS": {
        "description": "Disabled identity retains active RBAC role assignments",
        "severity": "critical",
        "points": 900,
        "category": "governance",
        "cis": ["CIS Azure 1.3"],   # Review dormant + disabled accounts
        "mitre": ["T1078.001"],     # Default/Disabled Accounts
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


# AG-G (2026-05-30): CVSS 3.1-style 0.0–10.0 normalization.
#
# Industry frameworks (CIS, NIST, MITRE ATT&CK) don't define numeric risk
# scores — they define controls and techniques. The closest standardized
# numeric severity is CVSS 3.1 (0.0–10.0, used universally for CVEs). We
# normalize AuditGraph's proprietary additive point totals to that scale
# so auditors and downstream tools (SIEM, GRC) have a recognizable number.
#
# Bucket boundaries match the CVSS 3.1 severity rating definition:
#   0.0          → NONE       (no risk factors)
#   0.1 – 3.9    → LOW        (info / minor)
#   4.0 – 6.9    → MEDIUM
#   7.0 – 8.9    → HIGH
#   9.0 – 10.0   → CRITICAL
#
# Mapping from AuditGraph internal points → CVSS:
#   internal 0          →  0.0
#   internal 1–199      →  0.1–3.9   (low)
#   internal 200–499    →  4.0–6.9   (medium)
#   internal 500–899    →  7.0–8.9   (high)
#   internal ≥ 900      →  9.0–10.0  (critical, capped at 10.0)
# Within each band we linearly interpolate so a +400 factor reads as
# higher CVSS than a +250 factor within the medium bucket.
#
# This is a NORMALIZATION, not a literal CVSS vector — we don't compute
# attack-vector/complexity/etc. base metrics. The label and presentation
# explicitly say "CVSS-aligned 0–10 normalized score" to avoid implying
# we're computing a true CVSS base score.
def points_to_cvss(points: int) -> float:
    """Normalize AuditGraph additive points → CVSS 3.1-aligned 0.0–10.0."""
    if points <= 0:
        return 0.0
    if points >= 900:
        return 10.0
    if points >= 500:
        # 500..899 → 7.0..8.9
        return round(7.0 + (points - 500) / 399.0 * 1.9, 1)
    if points >= 200:
        # 200..499 → 4.0..6.9
        return round(4.0 + (points - 200) / 299.0 * 2.9, 1)
    # 1..199 → 0.1..3.9
    return round(0.1 + (points - 1) / 198.0 * 3.8, 1)


def cvss_to_severity(cvss: float) -> str:
    """CVSS 3.1 severity rating bands (per the official spec)."""
    if cvss == 0.0:
        return "none"
    if cvss < 4.0:
        return "low"
    if cvss < 7.0:
        return "medium"
    if cvss < 9.0:
        return "high"
    return "critical"


def make_factor(code: str, evidence: str = "") -> Dict:
    """
    Create a structured risk factor dict from a catalog code.

    Returns:
        {"code": "...", "description": "...", "severity": "...",
         "points": N, "category": "...", "evidence": "...",
         "cis": [...], "mitre": [...]}

    AG-E: cis + mitre fields enable framework-aligned reporting
    (CIS Azure/AWS/GCP Foundations Benchmark + MITRE ATT&CK Cloud).
    Both default to empty lists so legacy entries without these fields
    don't break the schema.
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
            "cis": [],
            "mitre": [],
        }
    return {
        "code": code,
        "description": entry["description"],
        "severity": entry["severity"],
        "points": entry["points"],
        "category": entry["category"],
        "evidence": evidence,
        "cis": entry.get("cis", []) or [],
        "mitre": entry.get("mitre", []) or [],
        "cvss": points_to_cvss(entry["points"]),  # AG-G: CVSS-aligned 0-10
    }
