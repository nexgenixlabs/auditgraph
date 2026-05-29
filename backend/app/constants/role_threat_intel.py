"""
AG-166: Curated threat-intelligence knowledge base.

Maps high-risk Azure RBAC / Entra roles (and our internal risk-signal keys) to
REAL, PUBLICLY-DOCUMENTED incidents where the role — or its direct equivalent —
was abused. The point is to turn abstract "this role is risky" into "this exact
capability was exploited in breach X."

Every incident MUST carry a `source_url` to an authoritative public writeup
(vendor threat-intel post, CISA advisory, Wiz/Mandiant research, court filing).
`validate_threat_intel()` enforces this — speculation is rejected.

Used by:
  - AI Investigate drawer (Risk Breakdown → "Real-world precedent" per signal)
  - AI Access "Most Common Roles" (incident count badge)

Architecture-aligned: this is static role intelligence — no telemetry needed.
"""
from __future__ import annotations


# Each incident:
#   id            short stable key
#   name          display name
#   year          incident year (int)
#   summary       1-2 sentence what-happened, focused on the role/capability abused
#   mitre         MITRE ATT&CK technique IDs
#   cve           optional CVE id
#   source_url    REQUIRED — authoritative public source
INCIDENTS: dict[str, dict] = {
    "storm0558_2023": {
        "id": "storm0558_2023",
        "name": "Storm-0558 token forgery",
        "year": 2023,
        "summary": "A stolen Microsoft consumer signing key was used to forge Azure AD "
                   "access tokens and impersonate users across Exchange Online / OWA — "
                   "abusing the trust placed in privileged token-issuing identities.",
        "mitre": ["T1606.002", "T1078.004"],
        "cve": None,
        "source_url": "https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition/",
    },
    "midnight_blizzard_2024": {
        "id": "midnight_blizzard_2024",
        "name": "Midnight Blizzard (NOBELIUM) OAuth app abuse",
        "year": 2024,
        "summary": "Password-spray compromised a legacy test tenant, then a dormant OAuth "
                   "application with elevated 'full_access_as_app' was abused to reach "
                   "corporate mailboxes. Highlights the risk of app/SPN credentials and "
                   "over-scoped application permissions.",
        "mitre": ["T1078.004", "T1098.001", "T1528"],
        "cve": None,
        "source_url": "https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/",
    },
    "solarwinds_2020": {
        "id": "solarwinds_2020",
        "name": "SolarWinds / SUNBURST (Golden SAML)",
        "year": 2020,
        "summary": "After initial supply-chain access, the actor forged SAML tokens and "
                   "ADDED credentials to existing service principals / app registrations "
                   "to gain long-term, high-privilege access to cloud resources.",
        "mitre": ["T1199", "T1098.001", "T1606.002"],
        "cve": None,
        "source_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a",
    },
    "ms_ai_38tb_2023": {
        "id": "ms_ai_38tb_2023",
        "name": "Microsoft AI research 38TB exposure (Wiz)",
        "year": 2023,
        "summary": "An over-permissioned Azure Storage SAS token attached to an AI research "
                   "repo exposed 38TB of internal data, including secrets and backups. "
                   "Direct example of broad storage data access on an AI workload.",
        "mitre": ["T1530"],
        "cve": None,
        "source_url": "https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers",
    },
    "capital_one_2019": {
        "id": "capital_one_2019",
        "name": "Capital One S3 breach",
        "year": 2019,
        "summary": "An SSRF flaw let an attacker retrieve an over-privileged instance role's "
                   "credentials and exfiltrate 100M+ records from object storage — the "
                   "classic 'workload identity with broad data access' failure.",
        "mitre": ["T1530", "T1078.004"],
        "cve": None,
        "source_url": "https://www.capitalone.com/digital/facts2019/",
    },
    "codecov_2021": {
        "id": "codecov_2021",
        "name": "Codecov CI secret exfiltration",
        "year": 2021,
        "summary": "A tampered CI script exfiltrated environment variables — including cloud "
                   "keys and Key Vault / secret-store credentials — from thousands of "
                   "pipelines. Shows the blast radius of secret-read access.",
        "mitre": ["T1552.001", "T1555.006"],
        "cve": None,
        "source_url": "https://about.codecov.io/security-update/",
    },
    "lastpass_2022": {
        "id": "lastpass_2022",
        "name": "LastPass vault exfiltration",
        "year": 2022,
        "summary": "A DevOps engineer's access to a cloud storage / secrets vault was abused "
                   "to exfiltrate encrypted customer vault backups — a real-world case of "
                   "secret-store administrative access being the crown-jewel target.",
        "mitre": ["T1555", "T1530"],
        "cve": None,
        "source_url": "https://blog.lastpass.com/posts/2022/12/notice-of-recent-security-incident",
    },
    "uber_2022": {
        "id": "uber_2022",
        "name": "Uber MFA-fatigue → admin escalation",
        "year": 2022,
        "summary": "After an MFA-fatigue social-engineering bypass, the actor found a "
                   "PowerShell script containing privileged admin credentials and escalated "
                   "to broad management access. Illustrates the danger of broad-privilege roles.",
        "mitre": ["T1078.004", "T1098", "T1621"],
        "cve": None,
        "source_url": "https://www.uber.com/newsroom/security-update/",
    },
    "moveit_clop_2023": {
        "id": "moveit_clop_2023",
        "name": "MOVEit Transfer (CL0P) mass exfiltration",
        "year": 2023,
        "summary": "A zero-day SQL injection let CL0P exfiltrate data at scale from managed "
                   "file-transfer storage across thousands of orgs — underscoring how direct "
                   "data-store write/read access becomes a breach amplifier.",
        "mitre": ["T1190", "T1530"],
        "cve": "CVE-2023-34362",
        "source_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
    },
}


# Map our internal risk-signal keys (from ai_risk.RISK_SIGNALS) → incident ids.
# These are the same keys compute_signal_score() emits, so the drawer can attach
# precedents directly to each fired signal.
SIGNAL_TO_INCIDENTS: dict[str, list[str]] = {
    "broad_owner_role":      ["uber_2022", "solarwinds_2020"],
    "key_vault_admin":       ["codecov_2021", "lastpass_2022"],
    "storage_blob_owner":    ["ms_ai_38tb_2023", "capital_one_2019"],
    "sensitive_data_access": ["moveit_clop_2023", "capital_one_2019"],
    "unrestricted_egress":   ["capital_one_2019"],
    "external_llm_access":   ["ms_ai_38tb_2023"],
    "expired_credential":    ["midnight_blizzard_2024"],
    # no_telemetry / dormant_agent / no_owner have no single canonical breach —
    # intentionally omitted rather than forcing a weak citation.
}


# Map specific role NAMES → incident ids, for the AI Access "Most Common Roles"
# list (which works off role names, not signal keys).
ROLE_TO_INCIDENTS: dict[str, list[str]] = {
    "Owner":                         ["uber_2022", "solarwinds_2020"],
    "Contributor":                   ["uber_2022"],
    "User Access Administrator":     ["solarwinds_2020"],
    "Key Vault Administrator":       ["codecov_2021", "lastpass_2022"],
    "Key Vault Secrets Officer":     ["codecov_2021"],
    "Storage Blob Data Owner":       ["ms_ai_38tb_2023", "capital_one_2019"],
    "Storage Blob Data Contributor": ["ms_ai_38tb_2023"],
    "Storage Account Contributor":   ["capital_one_2019"],
    # Entra
    "Application Administrator":     ["midnight_blizzard_2024", "solarwinds_2020"],
    "Cloud Application Administrator": ["midnight_blizzard_2024"],
    "Global Administrator":          ["storm0558_2023", "solarwinds_2020"],
    "Privileged Role Administrator": ["solarwinds_2020"],
}


def incidents_for_signal(signal_key: str) -> list[dict]:
    """Return full incident dicts for a risk-signal key (drawer Risk Breakdown)."""
    return [INCIDENTS[i] for i in SIGNAL_TO_INCIDENTS.get(signal_key, []) if i in INCIDENTS]


def incidents_for_role(role_name: str) -> list[dict]:
    """Return full incident dicts for a role name (AI Access role list)."""
    return [INCIDENTS[i] for i in ROLE_TO_INCIDENTS.get(role_name, []) if i in INCIDENTS]


def incident_count_for_role(role_name: str) -> int:
    return len(ROLE_TO_INCIDENTS.get(role_name, []))


def validate_threat_intel() -> list[str]:
    """CI guard: every incident must have a non-empty source_url and a name.
    Every signal/role mapping must reference a known incident. Returns a list
    of error strings (empty = valid)."""
    errors: list[str] = []
    for iid, inc in INCIDENTS.items():
        if not inc.get("source_url"):
            errors.append(f"incident {iid} missing source_url")
        if not inc.get("name"):
            errors.append(f"incident {iid} missing name")
        if not str(inc.get("source_url", "")).startswith("https://"):
            errors.append(f"incident {iid} source_url is not https")
    for mapping_name, mapping in (("signal", SIGNAL_TO_INCIDENTS), ("role", ROLE_TO_INCIDENTS)):
        for key, ids in mapping.items():
            for i in ids:
                if i not in INCIDENTS:
                    errors.append(f"{mapping_name} mapping '{key}' references unknown incident '{i}'")
    return errors
