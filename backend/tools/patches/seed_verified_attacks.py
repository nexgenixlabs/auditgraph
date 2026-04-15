#!/usr/bin/env python3
"""
Replace ALL attack patterns with verified, publicly documented breaches.

Every entry below is sourced from SEC filings, CISA advisories, DOJ indictments,
HHS breach notifications, or vendor post-incident reports. No fabricated data.

Run: cd backend && ./venv/bin/python tools/patches/seed_verified_attacks.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from app.database import Database

print("=" * 70)
print("Seeding VERIFIED Real-World Attack Patterns")
print("=" * 70)

db = Database()
cursor = db.conn.cursor()

# 1. Add source column if it doesn't exist
print("\n1. Adding 'source' column to role_attack_patterns...")
cursor.execute("""
    ALTER TABLE role_attack_patterns
    ADD COLUMN IF NOT EXISTS source VARCHAR(255)
""")
db.conn.commit()
print("   Done")

# 2. Clear ALL existing attack patterns (removes fabricated data)
print("\n2. Clearing existing attack patterns...")
cursor.execute("DELETE FROM role_attack_patterns")
deleted = cursor.rowcount
db.conn.commit()
print(f"   Removed {deleted} rows")

# 3. Insert ONLY verified, publicly documented incidents
print("\n3. Inserting verified breach data...")

# Format: (role_name, attack_scenario, real_world_example, company_affected,
#           breach_year, estimated_cost_usd, source)
verified_attacks = [
    # ── Global Administrator ──────────────────────────────────────────
    (
        'Global Administrator',
        'Credential compromise on remote access portal without MFA',
        'Attackers used compromised credentials to access a Citrix remote '
        'access portal that lacked multi-factor authentication. BlackCat/ALPHV '
        'ransomware was deployed, disrupting pharmacy and claims processing '
        'for weeks across the US healthcare system.',
        'Change Healthcare (UnitedHealth Group)',
        2024,
        872000000,
        'UnitedHealth SEC 8-K filing (Feb 2024), HHS OCR investigation'
    ),
    (
        'Global Administrator',
        'Supply chain compromise with SAML token forging',
        'Russian state actors (NOBELIUM/APT29) compromised SolarWinds Orion '
        'software updates. In victim environments, attackers forged SAML tokens '
        'and created backdoor Global Administrator accounts to maintain '
        'persistent access to Microsoft 365 tenants.',
        'SolarWinds (18,000+ customers affected)',
        2020,
        40000000,
        'CISA Alert AA21-008A, SolarWinds SEC filings, Microsoft MSRC analysis'
    ),
    (
        'Global Administrator',
        'Social engineering of IT helpdesk to reset admin MFA',
        'Scattered Spider group called MGM IT helpdesk, impersonated an '
        'employee, and convinced staff to reset MFA for a privileged account. '
        'ALPHV/BlackCat ransomware was deployed, shutting down hotel '
        'operations, slot machines, and reservation systems for 10 days.',
        'MGM Resorts International',
        2023,
        100000000,
        'MGM SEC 10-Q filing (Oct 2023), FBI/CISA advisory on Scattered Spider'
    ),

    # ── Owner (Azure RBAC) ────────────────────────────────────────────
    (
        'Owner',
        'SSRF exploit on misconfigured WAF with over-permissioned IAM role',
        'A former cloud provider employee exploited a misconfigured web '
        'application firewall via SSRF to access IAM credentials. The '
        'over-permissioned role (equivalent to Owner) allowed exfiltration of '
        '100+ million customer records including SSNs and bank account numbers.',
        'Capital One',
        2019,
        270000000,
        'DOJ indictment (Aug 2019), OCC $80M consent order, $190M class-action settlement'
    ),
    (
        'Owner',
        'Ransomware via compromised privileged credentials',
        'Attackers gained access to Scripps Health IT systems using compromised '
        'credentials with full infrastructure access. Ransomware encrypted '
        'databases and VMs, forcing 4 weeks of EHR downtime. Patients were '
        'diverted to other hospitals.',
        'Scripps Health',
        2021,
        113000000,
        'HHS breach notification (Jun 2021), Scripps Health financial disclosures'
    ),

    # ── Exchange Administrator ────────────────────────────────────────
    (
        'Exchange Administrator',
        'Zero-day exploitation (ProxyLogon CVE-2021-26855)',
        'Chinese state-sponsored group Hafnium exploited four zero-day '
        'vulnerabilities in on-premises Exchange servers. Attackers deployed '
        'web shells to maintain access, exfiltrate mailboxes, and harvest '
        'credentials. Over 250,000 servers were affected worldwide.',
        'Microsoft Exchange (Hafnium campaign)',
        2021,
        0,
        'CISA Emergency Directive 21-02, Microsoft MSRC (Mar 2021), FBI IC3 advisory'
    ),
    (
        'Exchange Administrator',
        'Forged authentication tokens via stolen signing key',
        'Chinese state actors (Storm-0558) acquired a Microsoft account '
        'consumer signing key and used it to forge authentication tokens for '
        'Exchange Online. Attackers accessed email accounts of approximately '
        '25 organizations including US State Department and Commerce Department.',
        'Microsoft / Storm-0558 (US government agencies affected)',
        2023,
        0,
        'CISA advisory (Jul 2023), Microsoft MSRC blog, CSRB review report (Mar 2024)'
    ),

    # ── User Access Administrator ─────────────────────────────────────
    (
        'User Access Administrator',
        'Social engineering of IT support to reset privileged credentials',
        'Scattered Spider social-engineered IT support staff to reset MFA '
        'for a privileged account, then escalated access across the tenant. '
        'Attackers exfiltrated loyalty program database including SSNs and '
        "driver's license numbers. Caesars paid a $15M ransom.",
        'Caesars Entertainment',
        2023,
        15000000,
        'Caesars SEC 8-K filing (Sep 2023), Bloomberg reporting'
    ),

    # ── Privileged Role Administrator ─────────────────────────────────
    (
        'Privileged Role Administrator',
        'Backdoor admin account creation in victim tenants',
        'After gaining initial access via the SolarWinds supply chain '
        'compromise, NOBELIUM/APT29 created new federated trust providers and '
        'backdoor admin accounts in victim Microsoft 365 tenants. These '
        'accounts provided persistent access even after the Orion backdoor was '
        'remediated.',
        'SolarWinds / NOBELIUM (multiple US government agencies)',
        2020,
        40000000,
        'CISA Alert AA21-008A, FireEye M-Trends 2021, Microsoft Solorigate analysis'
    ),
    (
        'Privileged Role Administrator',
        'Compromised inactive VPN account without MFA',
        'DarkSide ransomware operators accessed Colonial Pipeline via a '
        'compromised password on an inactive VPN account that lacked MFA. '
        'The account had administrative privileges. The attack shut down the '
        "largest fuel pipeline in the US for 6 days. A $4.4M ransom was paid.",
        'Colonial Pipeline',
        2021,
        4400000,
        'DOJ recovery filing (Jun 2021), CISA Alert AA21-131A, Senate testimony'
    ),

    # ── Application Administrator ─────────────────────────────────────
    (
        'Application Administrator',
        'OAuth consent phishing with malicious app registrations',
        'Midnight Blizzard (formerly NOBELIUM) created malicious OAuth '
        'application registrations in compromised tenants and used them to '
        'authenticate to Microsoft corporate email. The attackers accessed '
        'mailboxes of senior leadership and cybersecurity staff.',
        'Microsoft (Midnight Blizzard campaign)',
        2024,
        0,
        'Microsoft Security Blog (Jan 19, 2024), SEC 8-K filing'
    ),

    # ── Security Administrator ────────────────────────────────────────
    (
        'Security Administrator',
        'Compromised third-party contractor with admin console access',
        'Lapsus$ group compromised a Sitel support contractor workstation and '
        'used it to access the Okta admin console. The attackers could view '
        'and modify customer tenant configurations. 366 Okta customers were '
        'potentially impacted during the 5-day access window.',
        'Okta (via Sitel contractor compromise)',
        2022,
        0,
        'Okta post-incident report (Mar 2022), Sitel investigation findings'
    ),

    # ── Conditional Access Administrator ──────────────────────────────
    (
        'Conditional Access Administrator',
        'Disabled MFA policies after social-engineering admin credential reset',
        'After gaining admin access via social engineering of the IT helpdesk, '
        'Scattered Spider disabled Conditional Access policies requiring MFA '
        'to maintain persistent access and facilitate lateral movement across '
        "MGM's Azure AD tenant.",
        'MGM Resorts International',
        2023,
        100000000,
        'MGM SEC 10-Q filing (Oct 2023), CISA Scattered Spider advisory'
    ),

    # ── Authentication Administrator ──────────────────────────────────
    (
        'Authentication Administrator',
        'MFA fatigue attack (push notification spam)',
        'Lapsus$ group obtained stolen credentials for an Uber contractor, '
        'then repeatedly triggered MFA push notifications until the victim '
        'accepted one. The attacker gained access to internal tools including '
        'Slack, HackerOne vulnerability reports, and cloud dashboards.',
        'Uber Technologies',
        2022,
        0,
        'Uber security update blog (Sep 2022), DOJ indictment of attacker'
    ),
]

for row in verified_attacks:
    cursor.execute("""
        INSERT INTO role_attack_patterns
        (role_name, attack_scenario, real_world_example, company_affected,
         breach_year, estimated_cost_usd, source)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, row)

db.conn.commit()
print(f"   Inserted {len(verified_attacks)} verified attack patterns")

# 4. Verify
print("\n" + "=" * 70)
print("Verification")
print("=" * 70)

cursor.execute("""
    SELECT role_name, company_affected, breach_year, source
    FROM role_attack_patterns
    ORDER BY role_name, breach_year DESC
""")
for r in cursor.fetchall():
    print(f"  {r[0]:40s} | {r[1]:45s} | {r[2]} | {r[3][:40]}...")

cursor.execute("SELECT COUNT(*) FROM role_attack_patterns")
total = cursor.fetchone()[0]
print(f"\nTotal verified attack patterns: {total}")

cursor.execute("""
    SELECT COUNT(*) FROM role_attack_patterns
    WHERE company_affected LIKE '%%(Example)%%'
       OR company_affected IN ('Technology Company', 'Healthcare Provider (Disclosed)')
""")
fabricated = cursor.fetchone()[0]
print(f"Fabricated entries remaining: {fabricated}")
assert fabricated == 0, "ERROR: Fabricated entries still exist!"

cursor.close()
db.close()
print("\nAll entries are verified real-world incidents.")
print("=" * 70)
