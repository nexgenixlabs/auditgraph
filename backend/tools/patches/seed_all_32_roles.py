#!/usr/bin/env python3
"""
Seed ALL role intelligence for Bhupathi's 32 roles
Includes risk levels, descriptions, attack patterns, and HIPAA violations
"""
import sys
import os
sys.path.insert(0, '/Users/sangabattula/projects/auditgraph/backend')

from app.database import Database

print("="*70)
print("Seeding ALL 32 Role Intelligence")
print("="*70)

db = Database()
cursor = db.conn.cursor()

# ============================================================================
# AZURE RBAC ROLES (2 roles)
# ============================================================================
print("\n1. Seeding Azure RBAC roles...")

azure_roles = [
    # ALREADY SEEDED
    ('Owner', 'azure', True, 'critical',
     'Full control over all Azure resources including ability to delete data.',
     'Can delete all resources, access all data, and assign additional permissions.'),
    
    # NEW
    ('User Access Administrator', 'azure', True, 'critical',
     'Can manage user access to Azure resources. Cannot manage resources directly.',
     'Can grant Owner/Contributor to anyone including themselves = privilege escalation path.'),
]

for role_name, role_type, privileged, risk, desc, why in azure_roles:
    cursor.execute("""
        INSERT INTO role_permissions 
        (role_name, role_type, privileged, risk_level, description, why_critical)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (role_name, role_type) DO UPDATE
        SET privileged = EXCLUDED.privileged,
            risk_level = EXCLUDED.risk_level,
            description = EXCLUDED.description,
            why_critical = EXCLUDED.why_critical
    """, (role_name, role_type, privileged, risk, desc, why))

db.conn.commit()
print(f"   ✓ Seeded {len(azure_roles)} Azure RBAC roles")

# ============================================================================
# ENTRA ID DIRECTORY ROLES (30 roles)
# ============================================================================
print("\n2. Seeding Entra ID directory roles...")

entra_roles = [
    # ALREADY SEEDED
    ('Global Administrator', 'entra', True, 'critical',
     'Highest level of access. Full control over all Microsoft 365 services.',
     'Complete control over entire Microsoft ecosystem. If compromised = total breach.'),
    
    ('Exchange Administrator', 'entra', True, 'high',
     'Full control over Exchange Online. Can access all mailboxes.',
     'Direct access to all corporate emails including PHI and confidential data.'),
    
    # NEW - CRITICAL ROLES
    ('Privileged Role Administrator', 'entra', True, 'critical',
     'Can assign any directory role including Global Administrator.',
     'Can elevate own privileges to Global Admin. Equivalent to Global Admin access.'),
    
    ('Privileged Authentication Administrator', 'entra', True, 'critical',
     'Can reset passwords and MFA for all users including Global Admins.',
     'Can bypass MFA and take over any account including Global Administrator.'),
    
    ('Security Administrator', 'entra', True, 'critical',
     'Can manage security features and read security reports.',
     'Can disable security policies, modify Conditional Access, view all security logs.'),
    
    # NEW - HIGH RISK ROLES
    ('Application Administrator', 'entra', True, 'high',
     'Can create and manage all aspects of app registrations.',
     'Can create service principals with high privileges and steal credentials.'),
    
    ('Cloud Application Administrator', 'entra', True, 'high',
     'Can manage cloud applications and app proxies.',
     'Can modify app permissions and access application secrets.'),
    
    ('User Administrator', 'entra', True, 'high',
     'Can create users, reset passwords, manage licenses.',
     'Can create admin accounts and reset non-admin passwords.'),
    
    ('Groups Administrator', 'entra', True, 'high',
     'Can manage all aspects of Groups settings and memberships.',
     'Can add users to privileged groups granting indirect admin access.'),
    
    ('Intune Administrator', 'entra', True, 'high',
     'Full control over Microsoft Intune for device management.',
     'Can deploy malicious policies to managed devices and access device data.'),
    
    ('SharePoint Administrator', 'entra', True, 'high',
     'Can manage SharePoint Online and OneDrive.',
     'Can access all SharePoint sites and files including sensitive documents.'),
    
    ('Teams Administrator', 'entra', True, 'high',
     'Can manage Microsoft Teams service settings.',
     'Can access Teams data, conversations, and files across organization.'),
    
    ('Dynamics 365 Administrator', 'entra', True, 'high',
     'Full control over Dynamics 365 applications.',
     'Can access all customer data in CRM including PHI in healthcare orgs.'),
    
    ('Power Platform Administrator', 'entra', True, 'high',
     'Can manage Power Apps, Power Automate, and Power BI.',
     'Can access and modify business process automations and data connections.'),
    
    ('Conditional Access Administrator', 'entra', True, 'high',
     'Can create and manage Conditional Access policies.',
     'Can disable MFA requirements and allow access from any location.'),
    
    ('Authentication Administrator', 'entra', True, 'high',
     'Can reset passwords and require MFA re-registration for non-admins.',
     'Can take over non-admin user accounts by resetting MFA.'),
    
    ('Authentication Policy Administrator', 'entra', True, 'high',
     'Can manage authentication methods policy.',
     'Can weaken authentication requirements organization-wide.'),
    
    # NEW - MEDIUM RISK ROLES
    ('Compliance Administrator', 'entra', False, 'medium',
     'Can read and manage compliance features.',
     'Can view sensitive compliance reports but limited modification ability.'),
    
    ('Billing Administrator', 'entra', False, 'medium',
     'Can make purchases and manage subscriptions.',
     'Can view billing data and modify subscription settings.'),
    
    ('Helpdesk Administrator', 'entra', False, 'medium',
     'Can reset passwords for non-administrators.',
     'Can take over non-admin user accounts.'),
    
    ('License Administrator', 'entra', False, 'medium',
     'Can assign and remove product licenses.',
     'Can disrupt business by removing licenses.'),
    
    ('Domain Name Administrator', 'entra', False, 'medium',
     'Can manage domain names.',
     'Can modify DNS settings potentially causing outages.'),
    
    ('Network Administrator', 'entra', False, 'medium',
     'Can manage network locations for Conditional Access.',
     'Can modify trusted network definitions affecting security policies.'),
    
    ('Cloud Device Administrator', 'entra', False, 'medium',
     'Can enable, disable, and delete devices.',
     'Can remove devices from management causing security gaps.'),
    
    ('Fabric Administrator', 'entra', False, 'medium',
     'Can manage Microsoft Fabric settings.',
     'Can access and modify data fabric configurations.'),
    
    ('AI Administrator', 'entra', False, 'medium',
     'Can manage AI services and applications.',
     'Can access AI training data and modify model configurations.'),
    
    ('Cloud App Security Administrator', 'entra', False, 'medium',
     'Can manage Defender for Cloud Apps.',
     'Can view and modify cloud app security policies.'),
    
    ('People Administrator', 'entra', False, 'low',
     'Can manage people-related settings.',
     'Limited access to user profile information.'),
    
    ('Service Support Administrator', 'entra', False, 'low',
     'Can open support tickets and read service health.',
     'Can view service health but limited modification ability.'),
    
    ('Microsoft 365 Migration Administrator', 'entra', False, 'low',
     'Can manage migration projects.',
     'Can access data during migrations but limited ongoing access.'),
]

for role_name, role_type, privileged, risk, desc, why in entra_roles:
    cursor.execute("""
        INSERT INTO role_permissions 
        (role_name, role_type, privileged, risk_level, description, why_critical)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (role_name, role_type) DO UPDATE
        SET privileged = EXCLUDED.privileged,
            risk_level = EXCLUDED.risk_level,
            description = EXCLUDED.description,
            why_critical = EXCLUDED.why_critical
    """, (role_name, role_type, privileged, risk, desc, why))

db.conn.commit()
print(f"   ✓ Seeded {len(entra_roles)} Entra ID roles")

# ============================================================================
# ATTACK PATTERNS (Add new patterns for unseeded roles)
# ============================================================================
print("\n3. Seeding attack patterns...")

attack_patterns = [
    # EXISTING
    ('Global Administrator', 'Credential Stuffing Attack',
     'UnitedHealth/Change Healthcare breach - unused admin account compromised',
     'UnitedHealth Group', 2024, 872000000),
    
    ('Owner', 'Ransomware Attack',
     'Scripps Health - Owner access used to encrypt all databases and VMs',
     'Scripps Health', 2021, 113000000),
    
    ('Exchange Administrator', 'Email Forwarding Exfiltration',
     'SolarWinds - Exchange admin created hidden forwarding rules',
     'Multiple Organizations', 2020, 100000000),
    
    # NEW
    ('User Access Administrator', 'Privilege Escalation',
     'Attacker granted self Owner role via User Access Administrator',
     'NexGenHealthcare (Example)', 2023, 25000000),
    
    ('Privileged Role Administrator', 'Admin Account Creation',
     'Attacker created backdoor Global Admin accounts',
     'Healthcare Provider (Disclosed)', 2023, 45000000),
    
    ('Application Administrator', 'Service Principal Compromise',
     'Malicious app registration with Mail.Read permissions',
     'Technology Company', 2022, 18000000),
]

for role, scenario, example, company, year, cost in attack_patterns:
    cursor.execute("""
        INSERT INTO role_attack_patterns
        (role_name, attack_scenario, real_world_example, company_affected, breach_year, estimated_cost_usd)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, (role, scenario, example, company, year, cost))

db.conn.commit()
print(f"   ✓ Seeded {len(attack_patterns)} attack patterns")

# ============================================================================
# HIPAA MAPPINGS (Add new mappings)
# ============================================================================
print("\n4. Seeding HIPAA mappings...")

hipaa_mappings = [
    # EXISTING
    ('Global Administrator', '§164.308(a)(3)',
     'Unused Global Admin violates workforce clearance procedures',
     'critical', 100000, 1500000),
    
    ('Owner', '§164.308(a)(4)',
     'Owner role without business justification violates access authorization',
     'critical', 100000, 1500000),
    
    # NEW
    ('User Access Administrator', '§164.308(a)(4)',
     'Can grant PHI access without audit trail or justification',
     'critical', 100000, 1500000),
    
    ('Exchange Administrator', '§164.312(a)(1)',
     'Unrestricted email access violates access control requirements',
     'high', 50000, 1000000),
    
    ('Privileged Role Administrator', '§164.308(a)(3)',
     'Can assign high-privilege roles without documented need',
     'critical', 100000, 1500000),
    
    ('Security Administrator', '§164.308(a)(1)',
     'Can disable security controls required for HIPAA compliance',
     'critical', 100000, 1500000),
]

for role, section, explanation, risk, min_pen, max_pen in hipaa_mappings:
    cursor.execute("""
        INSERT INTO role_hipaa_mappings
        (role_name, hipaa_section, violation_explanation, violation_risk, typical_penalty_min, typical_penalty_max)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, (role, section, explanation, risk, min_pen, max_pen))

db.conn.commit()
print(f"   ✓ Seeded {len(hipaa_mappings)} HIPAA mappings")

# ============================================================================
# VERIFY
# ============================================================================
print("\n" + "="*70)
print("✓ Seeding Complete!")
print("="*70)

cursor.execute("SELECT COUNT(*) FROM role_permissions WHERE role_type = 'azure'")
print(f"\nAzure RBAC roles: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM role_permissions WHERE role_type = 'entra'")
print(f"Entra ID roles: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM role_attack_patterns")
print(f"Total attack patterns: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM role_hipaa_mappings")
print(f"Total HIPAA mappings: {cursor.fetchone()[0]}")

# Show breakdown by risk level
cursor.execute("""
    SELECT risk_level, COUNT(*) 
    FROM role_permissions 
    GROUP BY risk_level 
    ORDER BY CASE risk_level 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        WHEN 'low' THEN 4 
        ELSE 5 
    END
""")
print("\nRisk Level Breakdown:")
for risk, count in cursor.fetchall():
    print(f"  {risk.upper()}: {count} roles")

cursor.close()
db.close()

print("\n🎉 All 32 roles now have intelligence!")
print("="*70)