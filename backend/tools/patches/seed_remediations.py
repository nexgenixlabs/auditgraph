#!/usr/bin/env python3
"""
Seed 20 remediation playbooks for the Remediation Engine.

Each playbook maps a risk pattern to actionable fix steps with impact/effort scoring
and compliance references.

Run: cd backend && ./venv/bin/python tools/patches/seed_remediations.py
"""
import sys
import json
sys.path.insert(0, '/Users/sangabattula/projects/auditgraph/backend')

from app.database import Database

print("=" * 70)
print("Seeding Remediation Playbooks")
print("=" * 70)

db = Database()
cursor = db.conn.cursor()

# Clear existing playbooks for clean seed
cursor.execute("DELETE FROM remediation_playbooks")
db.conn.commit()

playbooks = [
    # ── Critical Access Control ─────────────────────────────────────────
    {
        "risk_pattern": "Global Administrator",
        "pattern_type": "contains",
        "title": "Remove or scope Global Administrator assignments",
        "description": "Global Administrator grants unrestricted access to the entire Microsoft 365 tenant. This role should only be assigned to break-glass accounts with PIM just-in-time activation.",
        "steps": [
            "Identify all identities with Global Administrator role in Entra ID > Roles and administrators",
            "For each assignment, determine if the identity genuinely requires tenant-wide control",
            "Replace with scoped admin roles (e.g., User Administrator, Exchange Administrator) where possible",
            "For remaining Global Admin needs, enable PIM eligible assignment with 1-hour max activation",
            "Configure approval workflow requiring a second administrator to approve activation",
            "Ensure at least 2 (but no more than 4) break-glass accounts retain emergency Global Admin access",
            "Document business justification for each remaining assignment"
        ],
        "impact": "critical",
        "effort": "medium",
        "priority_score": 98,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.308(a)(3)", "PCI-DSS 7.1", "NIST AC-6"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Owner",
        "pattern_type": "contains",
        "title": "Replace Azure Owner role with scoped RBAC roles",
        "description": "The Owner role grants full control over Azure resources including the ability to assign access to others. Replace with least-privilege roles scoped to specific resource groups.",
        "steps": [
            "List all Owner role assignments: az role assignment list --role Owner",
            "For each assignment, identify the actual permissions the identity uses",
            "Replace subscription-level Owner with resource-group-scoped Contributor where possible",
            "For identities that need to manage access, use User Access Administrator scoped to specific resource groups",
            "Remove the Owner assignment after confirming the replacement role works",
            "Monitor for access denied errors over 7 days to validate the change"
        ],
        "impact": "critical",
        "effort": "medium",
        "priority_score": 95,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.308(a)(4)", "NIST AC-6"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Privileged Role Administrator",
        "pattern_type": "contains",
        "title": "Restrict Privileged Role Administrator to break-glass only",
        "description": "Privileged Role Administrator can assign any Entra ID directory role including Global Administrator. This is functionally equivalent to Global Admin and must be tightly controlled.",
        "steps": [
            "Identify all Privileged Role Administrator assignments in Entra ID",
            "Remove all permanent assignments except break-glass accounts",
            "Enable PIM eligible assignment with 30-minute max activation and approval required",
            "Configure alerts for any PRA role activation",
            "Review PRA activation logs monthly for unauthorized or unusual activations"
        ],
        "impact": "critical",
        "effort": "medium",
        "priority_score": 96,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.308(a)(3)", "NIST AC-6"],
        "category": "access_control"
    },
    {
        "risk_pattern": "User Access Administrator",
        "pattern_type": "contains",
        "title": "Restrict User Access Administrator to JIT/PIM only",
        "description": "User Access Administrator can grant any Azure RBAC role including Owner, creating a privilege escalation path. Must be controlled via just-in-time access.",
        "steps": [
            "List all User Access Administrator assignments at subscription level",
            "Remove permanent assignments and replace with PIM eligible assignments",
            "Scope assignments to specific resource groups where possible",
            "Configure approval workflow for activation",
            "Set maximum activation duration to 2 hours"
        ],
        "impact": "critical",
        "effort": "medium",
        "priority_score": 94,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.308(a)(4)", "NIST AC-2"],
        "category": "access_control"
    },
    {
        "risk_pattern": "no_mfa",
        "pattern_type": "contains",
        "title": "Enable MFA via Conditional Access policy",
        "description": "Identities without MFA enforcement are vulnerable to credential theft attacks. Conditional Access policies should require MFA for all privileged access.",
        "steps": [
            "Navigate to Entra ID > Protection > Conditional Access",
            "Create a new policy targeting All Users (or specific privileged groups)",
            "Set conditions: All cloud apps, Any device platform",
            "Under Grant: Require multifactor authentication",
            "Set session: Sign-in frequency to 1 hour for privileged roles",
            "Enable the policy in Report-only mode for 7 days to identify impact",
            "Switch to Enabled after confirming no business disruption"
        ],
        "impact": "critical",
        "effort": "medium",
        "priority_score": 93,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.312(d)", "PCI-DSS 8.3", "NIST IA-2"],
        "category": "access_control"
    },

    # ── High-Impact Access Control ──────────────────────────────────────
    {
        "risk_pattern": "Exchange Administrator",
        "pattern_type": "contains",
        "title": "Audit mailbox access and scope Exchange Admin permissions",
        "description": "Exchange Administrators can access all mailboxes including those containing sensitive data. Scope this role and enable audit logging.",
        "steps": [
            "Review all Exchange Administrator assignments in Entra ID",
            "Determine if full Exchange Admin is needed or if a scoped role (e.g., Mail Recipients) suffices",
            "Enable mailbox audit logging: Set-OrganizationConfig -AuditDisabled $false",
            "Configure alerts for admin mailbox access in Microsoft Defender",
            "Move to PIM eligible assignment with justification required"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 82,
        "compliance_refs": ["HIPAA 164.312(a)(1)", "SOC2 CC6.3"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Application Administrator",
        "pattern_type": "contains",
        "title": "Review and restrict Application Administrator permissions",
        "description": "Application Administrators can create service principals with high privileges and access application secrets. This role enables credential theft and privilege escalation.",
        "steps": [
            "Audit all Application Administrator assignments",
            "Replace with Cloud Application Administrator where app proxy is not needed",
            "Restrict app registration creation to authorized administrators only",
            "Enable consent workflow to prevent unauthorized OAuth consent grants",
            "Monitor for new app registrations via Entra ID audit logs"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 80,
        "compliance_refs": ["SOC2 CC6.1", "NIST AC-6"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Security Administrator",
        "pattern_type": "contains",
        "title": "Limit Security Administrator to read-only where possible",
        "description": "Security Administrator can modify security settings and disable protections. Most monitoring use cases only need Security Reader.",
        "steps": [
            "Identify all Security Administrator role holders",
            "Determine if Security Reader role provides sufficient access for their needs",
            "Downgrade to Security Reader where write access is not required",
            "For remaining Security Admin needs, enable PIM with approval workflow",
            "Configure alerts for security policy changes"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 78,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.308(a)(1)", "NIST AC-6"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Conditional Access Administrator",
        "pattern_type": "contains",
        "title": "Require approval workflow for CA policy changes",
        "description": "Conditional Access Administrators can disable MFA policies, creating catastrophic security gaps. Changes must require approval.",
        "steps": [
            "Move all permanent CA Admin assignments to PIM eligible",
            "Configure approval workflow requiring Security team sign-off",
            "Set maximum activation duration to 4 hours",
            "Enable change tracking alerts for all CA policy modifications",
            "Implement CA policy backup/restore process before making changes"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 85,
        "compliance_refs": ["SOC2 CC6.1", "NIST AC-6"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Mail.ReadWrite",
        "pattern_type": "contains",
        "title": "Remove Mail.ReadWrite unless business-justified",
        "description": "Mail.ReadWrite Graph API permission allows reading and writing to any mailbox in the organization. This is a high-value target for data exfiltration.",
        "steps": [
            "Identify all service principals with Mail.ReadWrite or Mail.ReadWrite.All",
            "For each, verify there is a documented business need for full mailbox access",
            "Replace with Mail.Read where write access is not needed",
            "Scope to specific mailboxes using application access policies where possible",
            "Revoke permission: Remove-MgServicePrincipalAppRoleAssignment"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 76,
        "compliance_refs": ["HIPAA 164.312(a)(1)", "SOC2 CC6.3"],
        "category": "access_control"
    },
    {
        "risk_pattern": "Files.ReadWrite.All",
        "pattern_type": "contains",
        "title": "Scope file access to specific SharePoint sites",
        "description": "Files.ReadWrite.All grants access to all files in SharePoint and OneDrive. Scope access to specific sites using Sites.Selected permission.",
        "steps": [
            "Identify all service principals with Files.ReadWrite.All",
            "Determine which specific SharePoint sites each SPN needs to access",
            "Replace Files.ReadWrite.All with Sites.Selected permission",
            "Grant site-specific access via SharePoint admin: Add-SPOSiteCollectionAppCatalog",
            "Validate the application still functions correctly with scoped access"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 74,
        "compliance_refs": ["HIPAA 164.312(a)(1)", "SOC2 CC6.3"],
        "category": "access_control"
    },
    {
        "risk_pattern": "excessive_permissions",
        "pattern_type": "contains",
        "title": "Apply least-privilege: remove unused API permissions",
        "description": "Service principals with excessive permissions increase blast radius. Remove unused Graph API permissions following the principle of least privilege.",
        "steps": [
            "Review each permission granted to the service principal in Entra ID > App registrations > API permissions",
            "Cross-reference with application usage logs in Entra ID sign-in logs",
            "Identify permissions that have never been exercised (require Azure AD Premium P2)",
            "Remove unused permissions one at a time, testing the application after each removal",
            "Document the minimum required permission set for the application"
        ],
        "impact": "high",
        "effort": "high",
        "priority_score": 70,
        "compliance_refs": ["SOC2 CC6.1", "NIST AC-6", "PCI-DSS 7.1"],
        "category": "access_control"
    },
    {
        "risk_pattern": "no_conditional_access",
        "pattern_type": "contains",
        "title": "Create CA policies covering all identity types",
        "description": "Identities without Conditional Access coverage bypass MFA, device compliance, and location restrictions. All identities should be covered.",
        "steps": [
            "Review current CA policy scope in Entra ID > Protection > Conditional Access",
            "Identify gaps: check if service principals and workload identities are covered",
            "Create a baseline policy requiring MFA for all users on all cloud apps",
            "Create a separate policy for workload identities restricting IP ranges",
            "Test in Report-only mode for 7 days before enabling"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 72,
        "compliance_refs": ["SOC2 CC6.1", "NIST AC-2", "HIPAA 164.312(d)"],
        "category": "access_control"
    },

    # ── Credential Hygiene ──────────────────────────────────────────────
    {
        "risk_pattern": "expired",
        "pattern_type": "contains",
        "title": "Rotate or remove expired credentials",
        "description": "Expired credentials indicate poor lifecycle management and may signal abandoned service principals that should be decommissioned.",
        "steps": [
            "List all service principals with expired secrets/certificates",
            "For each, determine if the application is still actively used (check sign-in logs)",
            "If unused: disable the service principal and schedule for deletion after 30 days",
            "If active: generate a new secret with maximum 12-month expiry",
            "Store the new secret in Azure Key Vault (never in code or config files)",
            "Update the application configuration to use the new credential",
            "Remove the expired credential from the app registration"
        ],
        "impact": "high",
        "effort": "low",
        "priority_score": 88,
        "compliance_refs": ["SOC2 CC7.2", "HIPAA 164.312(d)", "PCI-DSS 8.1", "NIST IA-5"],
        "category": "credential_hygiene"
    },
    {
        "risk_pattern": "expiring_soon",
        "pattern_type": "contains",
        "title": "Schedule credential rotation before expiry",
        "description": "Credentials expiring within 30 days need proactive rotation to prevent application outages.",
        "steps": [
            "Generate a new secret or certificate before the current one expires",
            "Add the new credential alongside the existing one (dual-credential period)",
            "Update the application to use the new credential",
            "Validate the application works with the new credential for 48 hours",
            "Remove the old credential after confirming the new one is in use",
            "Set a calendar reminder for the next rotation (recommended: every 6 months)"
        ],
        "impact": "medium",
        "effort": "low",
        "priority_score": 75,
        "compliance_refs": ["SOC2 CC7.2", "NIST IA-5"],
        "category": "credential_hygiene"
    },
    {
        "risk_pattern": "stale_credential",
        "pattern_type": "contains",
        "title": "Rotate credentials inactive for 90+ days",
        "description": "Stale credentials may have been compromised without detection. Rotate as a precautionary measure.",
        "steps": [
            "Identify credentials that have not been used in 90+ days via sign-in logs",
            "Determine if the application is still needed",
            "If unneeded: remove the credential and disable the service principal",
            "If needed: rotate the credential immediately as a precaution",
            "Enable credential monitoring to detect future staleness"
        ],
        "impact": "high",
        "effort": "low",
        "priority_score": 73,
        "compliance_refs": ["NIST IA-5", "SOC2 CC7.2"],
        "category": "credential_hygiene"
    },

    # ── Governance ──────────────────────────────────────────────────────
    {
        "risk_pattern": "dormant",
        "pattern_type": "contains",
        "title": "Disable or remove dormant identities",
        "description": "Identities with no sign-in activity for 90+ days are attack surface that provides no business value. Disable or remove them.",
        "steps": [
            "Confirm the identity has no sign-in activity in the last 90 days via Entra ID sign-in logs",
            "Check if the identity is used by automated processes (service principals may authenticate via token, not interactive sign-in)",
            "Contact the application owner to confirm the identity is no longer needed",
            "Disable the identity (do not delete yet): Set-AzureADServicePrincipal -AccountEnabled $false",
            "Wait 30 days to confirm no business impact from disabling",
            "If no impact after 30 days, proceed with deletion"
        ],
        "impact": "high",
        "effort": "low",
        "priority_score": 83,
        "compliance_refs": ["SOC2 CC6.2", "HIPAA 164.308(a)(3)", "NIST AC-2", "PCI-DSS 8.1"],
        "category": "governance"
    },
    {
        "risk_pattern": "never_used",
        "pattern_type": "contains",
        "title": "Review and remove never-used identities",
        "description": "Identities created 30+ days ago with no recorded sign-in are likely orphaned and should be decommissioned.",
        "steps": [
            "Verify the identity was created more than 30 days ago with zero sign-in events",
            "Check if the identity was recently provisioned and may not yet be in use",
            "Contact the creator (if known) to determine if the identity is still needed",
            "If unneeded: disable immediately and schedule deletion in 30 days",
            "If needed but not yet deployed: set a 30-day deadline for activation or removal"
        ],
        "impact": "high",
        "effort": "low",
        "priority_score": 79,
        "compliance_refs": ["SOC2 CC6.2", "NIST AC-2"],
        "category": "governance"
    },
    {
        "risk_pattern": "no_owner",
        "pattern_type": "contains",
        "title": "Assign ownership to unowned service principals",
        "description": "Service principals without designated owners cannot be maintained, rotated, or decommissioned properly. Every SPN must have a human owner.",
        "steps": [
            "List all service principals without owners in Entra ID > Enterprise applications",
            "For each, identify the team or individual that created or manages the application",
            "Assign at least one owner via Entra ID > Enterprise applications > [App] > Owners > Add owner",
            "Assign a secondary owner for redundancy",
            "Configure an alert for service principals created without owners going forward"
        ],
        "impact": "high",
        "effort": "medium",
        "priority_score": 77,
        "compliance_refs": ["SOC2 CC6.3", "NIST CM-8", "PCI-DSS 8.6"],
        "category": "governance"
    },
    {
        "risk_pattern": "multiple_high_privilege",
        "pattern_type": "contains",
        "title": "Separate duties across multiple identities",
        "description": "A single identity holding multiple high-privilege roles violates separation of duties and maximizes blast radius if compromised.",
        "steps": [
            "Identify the identity's full role set across Azure RBAC and Entra ID",
            "Determine which roles can be moved to separate service principals or user accounts",
            "Create purpose-specific service principals for distinct functional areas",
            "Migrate role assignments to the new purpose-specific identities",
            "Remove excess roles from the original identity",
            "Document the role separation and update RACI/ownership records"
        ],
        "impact": "critical",
        "effort": "high",
        "priority_score": 86,
        "compliance_refs": ["SOC2 CC6.1", "HIPAA 164.308(a)(3)", "NIST AC-5"],
        "category": "governance"
    },
]

for pb in playbooks:
    cursor.execute("""
        INSERT INTO remediation_playbooks
        (risk_pattern, pattern_type, title, description, steps,
         impact, effort, priority_score, compliance_refs, category)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        pb["risk_pattern"],
        pb["pattern_type"],
        pb["title"],
        pb["description"],
        json.dumps(pb["steps"]),
        pb["impact"],
        pb["effort"],
        pb["priority_score"],
        json.dumps(pb["compliance_refs"]),
        pb["category"],
    ))

db.conn.commit()
print(f"\nInserted {len(playbooks)} remediation playbooks")

# Verify
cursor.execute("""
    SELECT title, impact, effort, priority_score, category
    FROM remediation_playbooks
    ORDER BY priority_score DESC
""")
print("\nPlaybooks (by priority):")
for r in cursor.fetchall():
    print(f"  [{r[1]:8s}|{r[2]:6s}|P{r[3]:3d}] {r[4]:20s} | {r[0]}")

cursor.execute("SELECT COUNT(*) FROM remediation_playbooks")
total = cursor.fetchone()[0]
print(f"\nTotal playbooks: {total}")

cursor.close()
db.close()
print("\nDone!")
print("=" * 70)
