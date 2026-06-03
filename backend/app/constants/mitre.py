"""
MITRE ATT&CK technique enrichment — single source of truth.

This module is the canonical MITRE ATT&CK technique library for AuditGraph.
Every event, finding, attack-path node, drift entry, scorecard row, or activity
record that tags MITRE techniques MUST go through one of:

    - enrich_path_node_with_mitre(node_type, role_name=?, resource_type=?)
        Returns a list[dict] of full technique entries for a given attack-path
        node. Use this when annotating attack_paths / activity_timeline /
        lifecycle_drift events with the techniques being demonstrated.

    - get_technique(technique_id)
        Look up a single technique by ID (e.g. "T1552.001"). Returns the full
        dict or None. Use this when a caller already knows the technique ID
        (e.g. from role_threat_intel INCIDENTS["..."]["mitre"]) and just needs
        the canonical name / tactic / URL for rendering.

Rationale: previously each surface (attack-path renderer, scorecard, activity
timeline, lifecycle drift) carried its own ad-hoc map of technique IDs → names.
That drifted. This module is the single registry — change a name or URL here
and every surface picks it up.

Technique IDs are sourced from existing call-sites (do not invent new ones):
    - backend/app/constants/role_threat_intel.py  (INCIDENTS[*].mitre)
    - backend/app/constants/ai_attack_scenarios.py
    - backend/app/engines/risk_catalog.py

Technique descriptions are short, factual, drawn from publicly-known ATT&CK
technique definitions. Each entry carries a canonical URL of the form
https://attack.mitre.org/techniques/<id-with-slash-not-dot>/ that can be
followed for the authoritative description.

No DB calls. No logger. No I/O. Pure data + pure functions — safe to import
anywhere and trivial to unit test.
"""

from __future__ import annotations

from typing import Optional


# ── Tactics ───────────────────────────────────────────────────────
# Source: https://attack.mitre.org/tactics/enterprise/
TACTICS: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
}


def _attack_url(technique_id: str) -> str:
    """Build the canonical https://attack.mitre.org URL for a technique id.

    "T1552.001"  -> https://attack.mitre.org/techniques/T1552/001/
    "T1530"      -> https://attack.mitre.org/techniques/T1530/
    """
    if "." in technique_id:
        parent, sub = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def _tech(
    technique_id: str,
    name: str,
    tactic_id: str,
    description: str,
) -> dict:
    """Build a canonical technique dict. tactic name is looked up from TACTICS."""
    return {
        "id": technique_id,
        "name": name,
        "tactic": TACTICS[tactic_id],
        "tactic_id": tactic_id,
        "description": description,
        "url": _attack_url(technique_id),
    }


# ── Techniques ────────────────────────────────────────────────────
# Every ID below appears in at least one of role_threat_intel.py,
# ai_attack_scenarios.py, or risk_catalog.py. Adding/removing entries must
# be matched at those call-sites. Descriptions are short paraphrases of the
# public ATT&CK definitions; consult the URL field for the authoritative copy.
MITRE_TECHNIQUES: dict[str, dict] = {
    # https://attack.mitre.org/techniques/T1041/
    "T1041": _tech(
        "T1041",
        "Exfiltration Over C2 Channel",
        "TA0010",
        "Adversaries exfiltrate data over an existing command-and-control "
        "channel, blending exfil traffic with normal C2.",
    ),
    # https://attack.mitre.org/techniques/T1078/001/
    "T1078.001": _tech(
        "T1078.001",
        "Valid Accounts: Default Accounts",
        "TA0001",
        "Use of default or built-in accounts (often dormant or not properly "
        "disabled) to gain or maintain access.",
    ),
    # https://attack.mitre.org/techniques/T1078/004/
    "T1078.004": _tech(
        "T1078.004",
        "Valid Accounts: Cloud Accounts",
        "TA0001",
        "Compromise or abuse of legitimate cloud identities (users, service "
        "principals, managed identities) to access cloud resources.",
    ),
    # https://attack.mitre.org/techniques/T1087/004/
    "T1087.004": _tech(
        "T1087.004",
        "Account Discovery: Cloud Account",
        "TA0007",
        "Enumeration of cloud user, group, and service-principal accounts to "
        "map the identity surface for follow-on attacks.",
    ),
    # https://attack.mitre.org/techniques/T1098/
    "T1098": _tech(
        "T1098",
        "Account Manipulation",
        "TA0003",
        "Modification of an account (credentials, permissions, attributes) to "
        "preserve or escalate access.",
    ),
    # https://attack.mitre.org/techniques/T1098/001/
    "T1098.001": _tech(
        "T1098.001",
        "Account Manipulation: Additional Cloud Credentials",
        "TA0003",
        "Adding a secret, certificate, or federated credential to an existing "
        "cloud identity (commonly a service principal or app registration) to "
        "establish persistence.",
    ),
    # https://attack.mitre.org/techniques/T1098/003/
    "T1098.003": _tech(
        "T1098.003",
        "Account Manipulation: Additional Cloud Roles",
        "TA0003",
        "Assigning additional privileged roles to a controlled identity to "
        "broaden access and persist.",
    ),
    # https://attack.mitre.org/techniques/T1114/002/
    "T1114.002": _tech(
        "T1114.002",
        "Email Collection: Remote Email Collection",
        "TA0009",
        "Collection of mailbox contents from a remote email service (e.g. "
        "Exchange Online) using a privileged identity.",
    ),
    # https://attack.mitre.org/techniques/T1190/
    "T1190": _tech(
        "T1190",
        "Exploit Public-Facing Application",
        "TA0001",
        "Exploitation of a vulnerability in an Internet-exposed application "
        "to gain initial access.",
    ),
    # https://attack.mitre.org/techniques/T1199/
    "T1199": _tech(
        "T1199",
        "Trusted Relationship",
        "TA0001",
        "Abuse of an established trust (supply chain, federation, partner "
        "tenant) to access an otherwise-protected environment.",
    ),
    # https://attack.mitre.org/techniques/T1213/
    "T1213": _tech(
        "T1213",
        "Data from Information Repositories",
        "TA0009",
        "Collection of sensitive data from information repositories such as "
        "wikis, code repos, document stores, and knowledge bases.",
    ),
    # https://attack.mitre.org/techniques/T1213/002/
    "T1213.002": _tech(
        "T1213.002",
        "Data from Information Repositories: SharePoint",
        "TA0009",
        "Collection of data from SharePoint sites and document libraries via "
        "an identity with broad SharePoint access.",
    ),
    # https://attack.mitre.org/techniques/T1213/003/
    "T1213.003": _tech(
        "T1213.003",
        "Data from Information Repositories: Code Repositories",
        "TA0009",
        "Collection of source code, build configs, and embedded secrets from "
        "code-hosting repositories.",
    ),
    # https://attack.mitre.org/techniques/T1528/
    "T1528": _tech(
        "T1528",
        "Steal Application Access Token",
        "TA0006",
        "Theft of OAuth / application access tokens to impersonate apps or "
        "users without needing the original credentials.",
    ),
    # https://attack.mitre.org/techniques/T1530/
    "T1530": _tech(
        "T1530",
        "Data from Cloud Storage",
        "TA0009",
        "Direct access to cloud object/blob storage to read data — typically "
        "via an over-privileged identity or misconfigured access control.",
    ),
    # https://attack.mitre.org/techniques/T1552/001/
    "T1552.001": _tech(
        "T1552.001",
        "Unsecured Credentials: Credentials In Files",
        "TA0006",
        "Discovery of plaintext credentials, keys, or secrets in files such "
        "as scripts, configs, key vaults, or environment variables.",
    ),
    # https://attack.mitre.org/techniques/T1555/
    "T1555": _tech(
        "T1555",
        "Credentials from Password Stores",
        "TA0006",
        "Extraction of credentials from password managers, vaults, or other "
        "secret stores.",
    ),
    # https://attack.mitre.org/techniques/T1555/006/
    "T1555.006": _tech(
        "T1555.006",
        "Credentials from Password Stores: Cloud Secrets Management Stores",
        "TA0006",
        "Extraction of secrets specifically from cloud secret-management "
        "services (e.g. Azure Key Vault, AWS Secrets Manager).",
    ),
    # https://attack.mitre.org/techniques/T1556/001/
    "T1556.001": _tech(
        "T1556.001",
        "Modify Authentication Process: Domain Controller Authentication",
        "TA0005",
        "Modification of authentication mechanisms on a domain controller / "
        "identity provider to bypass or weaken authentication.",
    ),
    # https://attack.mitre.org/techniques/T1562/007/
    "T1562.007": _tech(
        "T1562.007",
        "Impair Defenses: Disable or Modify Cloud Firewall",
        "TA0005",
        "Disabling or modifying cloud network firewall / NSG rules to permit "
        "attacker traffic and evade defenses.",
    ),
    # https://attack.mitre.org/techniques/T1562/008/
    "T1562.008": _tech(
        "T1562.008",
        "Impair Defenses: Disable or Modify Cloud Logs",
        "TA0005",
        "Disabling, deleting, or tampering with cloud audit / diagnostic logs "
        "to hinder detection and forensics.",
    ),
    # https://attack.mitre.org/techniques/T1567/
    "T1567": _tech(
        "T1567",
        "Exfiltration Over Web Service",
        "TA0010",
        "Exfiltration of data to a legitimate, attacker-controlled web "
        "service (cloud storage, SaaS app) to blend with normal traffic.",
    ),
    # https://attack.mitre.org/techniques/T1578/002/
    "T1578.002": _tech(
        "T1578.002",
        "Modify Cloud Compute Infrastructure: Create Cloud Instance",
        "TA0005",
        "Creation of new cloud compute instances to host attacker tooling, "
        "exfiltrate data, or evade existing controls.",
    ),
    # https://attack.mitre.org/techniques/T1606/002/
    "T1606.002": _tech(
        "T1606.002",
        "Forge Web Credentials: SAML Tokens",
        "TA0006",
        "Forgery of SAML authentication tokens (e.g. Golden SAML) using "
        "stolen signing keys to impersonate users at the IdP.",
    ),
    # https://attack.mitre.org/techniques/T1621/
    "T1621": _tech(
        "T1621",
        "Multi-Factor Authentication Request Generation",
        "TA0006",
        "Repeated MFA push prompts (\"MFA fatigue\") to coerce a user into "
        "approving an attacker login.",
    ),
}


# ── Role-name → technique-ID mapping ──────────────────────────────
# Derived from role_threat_intel.py: for each role in ROLE_TO_INCIDENTS, take
# the union of mitre IDs across the cited incidents. We keep this static (no
# import of role_threat_intel) to avoid an import cycle and to make this
# module fully self-contained for unit tests.
ROLE_TO_TECHNIQUES: dict[str, list[str]] = {
    # Azure RBAC — broad-privilege
    "Owner": ["T1078.004", "T1098", "T1621", "T1199", "T1098.001", "T1606.002"],
    "Contributor": ["T1078.004", "T1098", "T1621"],
    "User Access Administrator": ["T1199", "T1098.001", "T1606.002"],
    # Azure RBAC — Key Vault
    "Key Vault Administrator": ["T1552.001", "T1555.006", "T1555", "T1530"],
    "Key Vault Secrets Officer": ["T1552.001", "T1555.006"],
    # Azure RBAC — Storage
    "Storage Blob Data Owner": ["T1530"],
    "Storage Blob Data Contributor": ["T1530"],
    "Storage Account Contributor": ["T1530", "T1078.004"],
    # Entra (Microsoft Graph) directory roles
    "Application Administrator": [
        "T1078.004", "T1098.001", "T1528", "T1199", "T1606.002",
    ],
    "Cloud Application Administrator": ["T1078.004", "T1098.001", "T1528"],
    "Global Administrator": ["T1606.002", "T1078.004", "T1199", "T1098.001"],
    "Privileged Role Administrator": ["T1199", "T1098.001", "T1606.002"],
}


# ── Public API ────────────────────────────────────────────────────
def get_technique(technique_id: Optional[str]) -> Optional[dict]:
    """Look up a single technique by ID.

    Returns the canonical dict ({id, name, tactic, tactic_id, description, url})
    or None if the ID is not registered. None / empty input returns None — never
    raises on bad input.
    """
    if not technique_id:
        return None
    return MITRE_TECHNIQUES.get(technique_id)


def _resolve(ids: list[str]) -> list[dict]:
    """Resolve a list of technique IDs to full dicts, de-duped, order-preserving.

    Unknown IDs are skipped silently — the registry is the source of truth, so
    a caller asking for an unregistered ID gets nothing rather than a fabricated
    entry.
    """
    seen: set[str] = set()
    out: list[dict] = []
    for tid in ids:
        if tid in seen:
            continue
        tech = MITRE_TECHNIQUES.get(tid)
        if tech is None:
            continue
        seen.add(tid)
        out.append(tech)
    return out


def enrich_path_node_with_mitre(
    node_type: str,
    role_name: Optional[str] = None,
    resource_type: Optional[str] = None,
    *,
    has_sensitive_data: bool = False,
    egress_open: bool = False,
) -> list[dict]:
    """Return the MITRE techniques relevant to an attack-path node.

    Args:
        node_type: The kind of node being annotated. Recognized values:
            "managed_identity"   — workload identity (system/user MSI or SPN)
            "service_principal"  — alias for managed_identity for SPNs
            "kv_secret"          — a secret/cert/key inside Key Vault
            "storage_account"    — Azure Storage account (Blob / Data Lake)
            "network_egress"     — an outbound egress path (e.g. NSG / public IP)
            "role_assignment"    — a role binding (use role_name to drive lookup)
        role_name: Optional. When the node represents a role binding, the
            canonical role name (e.g. "Owner", "Key Vault Administrator") used
            to look up techniques via ROLE_TO_TECHNIQUES.
        resource_type: Optional. Reserved for future expansion (e.g. CosmosDB,
            SQL). Currently unused beyond compatibility.
        has_sensitive_data: For storage_account nodes — True if the storage
            account is classified as containing sensitive data. Required for
            T1530 to fire on storage nodes (no fabricated default).
        egress_open: For network_egress nodes — True if egress is unrestricted
            (no NSG, public IP, or private-endpoint-bypass). Required for
            T1041 / T1567 to fire.

    Returns:
        A list of canonical technique dicts (possibly empty). Empty means "no
        MITRE technique is justifiably attached to this node given the inputs"
        — DO NOT substitute a default; callers should render the node without
        a MITRE badge in that case.
    """
    ids: list[str] = []

    nt = (node_type or "").lower().strip()

    # Identity-flavored nodes
    if nt in ("managed_identity", "service_principal"):
        ids.append("T1078.004")

    # Key Vault secret access
    elif nt == "kv_secret":
        ids.append("T1552.001")

    # Storage account — only attach T1530 when sensitive-data classification
    # is set. We never invent a sensitivity verdict.
    elif nt == "storage_account":
        if has_sensitive_data:
            ids.append("T1530")

    # Egress — only attach exfil techniques when egress is actually open.
    elif nt == "network_egress":
        if egress_open:
            ids.append("T1041")
            ids.append("T1567")

    # Role-driven lookup. Applies on any node when a role name is supplied
    # (the role_assignment node-type calls this with role_name set, but it's
    # also legitimate to enrich e.g. an identity node when the role context
    # is known).
    if role_name:
        for tid in ROLE_TO_TECHNIQUES.get(role_name, []):
            ids.append(tid)

    return _resolve(ids)


__all__ = [
    "TACTICS",
    "MITRE_TECHNIQUES",
    "ROLE_TO_TECHNIQUES",
    "get_technique",
    "enrich_path_node_with_mitre",
]
