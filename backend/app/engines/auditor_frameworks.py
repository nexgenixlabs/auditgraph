"""
Auditor Pack framework mappings (2026-05-31, AG-Hero-5).

Each framework defines the controls in scope + how they map back to the
CIS Foundations Benchmark IDs that AuditGraph already tags on every risk
factor (via risk_catalog `cis` field). The output is what a CISO/auditor
needs to copy-paste into their evidence binder:

  Section CC6.6 — Logical Access Restrictions
    Findings (12): [list of identities with risk_factors that map here]

Frameworks covered for v1:
  SOC2 (Trust Services Criteria — CC6 Logical Access focus)
  HIPAA (Security Rule — 164.308 Administrative Safeguards focus)
  PCI DSS v4.0 (Requirement 7 Access Control + Requirement 8 Identification)
  ISO 27001:2022 (A.5 Organizational + A.8 People + A.9 Access Control)
  CIS Azure Foundations v2.1 (direct passthrough of risk_factors CIS tags)

This is NOT a substitute for a full audit — it's a CISO time-saver that
generates the first-pass evidence pack. Auditor still validates. We
explicitly label every output "AuditGraph automated evidence (auditor
review required)" in the PDF.
"""
from __future__ import annotations
from typing import Dict, List


# Each entry: framework_code → [controls]
# Each control: { id, title, description, cis_map: [CIS ids that satisfy this control] }
#
# The cis_map is the bridge — when an identity finding has CIS tag X and X
# appears in a control's cis_map, that finding maps to this control.

AUDITOR_FRAMEWORKS: Dict[str, Dict] = {
    "soc2": {
        "name": "SOC 2 Trust Services Criteria",
        "version": "2017 (TSC)",
        "publisher": "AICPA",
        "scope_note": "Common Criteria CC6 — Logical and Physical Access Controls",
        "controls": [
            {
                "id": "CC6.1",
                "title": "Logical Access Security — Restrict Logical Access",
                "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
                "cis_map": ["CIS Azure 1.22", "CIS Azure 1.23", "CIS Azure 1.14"],
            },
            {
                "id": "CC6.2",
                "title": "User Registration and Authorization",
                "description": "Prior to issuing system credentials, the entity registers and authorizes new internal and external users whose access is administered by the entity.",
                "cis_map": ["CIS Azure 1.3", "CIS Azure 1.4"],
            },
            {
                "id": "CC6.3",
                "title": "Removal of User Access (Provisioning & Deprovisioning)",
                "description": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or system design and changes, giving consideration to the concepts of least privilege and segregation of duties.",
                "cis_map": ["CIS Azure 1.3", "CIS Azure 1.22"],
            },
            {
                "id": "CC6.6",
                "title": "Logical Access — Restrictions on External Access",
                "description": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
                "cis_map": ["CIS Azure 1.3"],
            },
            {
                "id": "CC6.7",
                "title": "Restricted Authorized User Access",
                "description": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal.",
                "cis_map": ["CIS Azure 8.5"],
            },
            {
                "id": "CC6.8",
                "title": "Detection / Prevention of Unauthorized Software",
                "description": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
                "cis_map": ["CIS Azure 1.14"],
            },
        ],
    },

    "hipaa": {
        "name": "HIPAA Security Rule",
        "version": "45 CFR Part 164",
        "publisher": "HHS / OCR",
        "scope_note": "Administrative Safeguards (164.308) focus — workforce access management",
        "controls": [
            {
                "id": "164.308(a)(3)(i)",
                "title": "Workforce Security — Authorization and/or Supervision",
                "description": "Implement procedures for the authorization and/or supervision of workforce members who work with electronic protected health information or in locations where it might be accessed.",
                "cis_map": ["CIS Azure 1.22", "CIS Azure 1.23"],
            },
            {
                "id": "164.308(a)(3)(ii)(C)",
                "title": "Workforce Security — Termination Procedures",
                "description": "Implement procedures for terminating access to electronic protected health information when the employment of a workforce member ends.",
                "cis_map": ["CIS Azure 1.3"],
            },
            {
                "id": "164.308(a)(4)(i)",
                "title": "Information Access Management — Access Authorization",
                "description": "Implement policies and procedures for granting access to electronic protected health information.",
                "cis_map": ["CIS Azure 1.22", "CIS Azure 1.14"],
            },
            {
                "id": "164.308(a)(5)(ii)(C)",
                "title": "Security Awareness and Training — Log-in Monitoring",
                "description": "Procedures for monitoring log-in attempts and reporting discrepancies.",
                "cis_map": ["CIS Azure 1.3"],
            },
            {
                "id": "164.312(a)(2)(i)",
                "title": "Access Control — Unique User Identification",
                "description": "Assign a unique name and/or number for identifying and tracking user identity.",
                "cis_map": ["CIS Azure 1.4"],
            },
            {
                "id": "164.312(d)",
                "title": "Person or Entity Authentication",
                "description": "Implement procedures to verify that a person or entity seeking access is the one claimed.",
                "cis_map": ["CIS Azure 1.4"],
            },
        ],
    },

    "pci": {
        "name": "PCI DSS",
        "version": "v4.0 (March 2022)",
        "publisher": "PCI Security Standards Council",
        "scope_note": "Requirement 7 (Access Control) + Requirement 8 (Identification & Authentication)",
        "controls": [
            {
                "id": "PCI 7.1",
                "title": "Least Privilege Access",
                "description": "Access to system components and data is appropriately defined and assigned per role.",
                "cis_map": ["CIS Azure 1.22"],
            },
            {
                "id": "PCI 7.2",
                "title": "Access Assignment Based on Job Function",
                "description": "Access is assigned based on least privilege necessary to perform job responsibilities.",
                "cis_map": ["CIS Azure 1.22", "CIS Azure 1.23"],
            },
            {
                "id": "PCI 8.2",
                "title": "Unique User ID Before Access",
                "description": "Users are identified and authenticated for all access to system components and cardholder data.",
                "cis_map": ["CIS Azure 1.4"],
            },
            {
                "id": "PCI 8.3",
                "title": "Strong Authentication — MFA",
                "description": "Multi-factor authentication is required for all non-console access and all remote access.",
                "cis_map": ["CIS Azure 1.4"],
            },
            {
                "id": "PCI 8.6",
                "title": "Service Account / System Account Restrictions",
                "description": "Use of application and system accounts and associated authentication factors is managed.",
                "cis_map": ["CIS Azure 1.14", "CIS Azure 1.3"],
            },
        ],
    },

    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "version": "2022",
        "publisher": "ISO/IEC",
        "scope_note": "Annex A.5 Organizational + A.8 Asset Management + A.9 Access Control focus",
        "controls": [
            {
                "id": "A.5.15",
                "title": "Access Control Policy",
                "description": "Rules to control physical and logical access to information and other associated assets.",
                "cis_map": ["CIS Azure 1.22"],
            },
            {
                "id": "A.5.16",
                "title": "Identity Management",
                "description": "Full life cycle of identities is managed.",
                "cis_map": ["CIS Azure 1.3", "CIS Azure 1.4"],
            },
            {
                "id": "A.5.18",
                "title": "Access Rights — Provision, Review, Revoke",
                "description": "Access rights to information and other associated assets are provisioned, reviewed, modified and removed in accordance with the topic-specific policy.",
                "cis_map": ["CIS Azure 1.3", "CIS Azure 1.22"],
            },
            {
                "id": "A.8.2",
                "title": "Privileged Access Rights",
                "description": "Allocation and use of privileged access rights is restricted and managed.",
                "cis_map": ["CIS Azure 1.22", "CIS Azure 1.23"],
            },
            {
                "id": "A.8.3",
                "title": "Information Access Restriction",
                "description": "Access to information and other associated assets is restricted in accordance with the established topic-specific policy.",
                "cis_map": ["CIS Azure 8.5"],
            },
            {
                "id": "A.8.5",
                "title": "Secure Authentication",
                "description": "Secure authentication technologies and procedures are implemented based on access restrictions and the topic-specific policy on access control.",
                "cis_map": ["CIS Azure 1.4"],
            },
        ],
    },

    "cis": {
        "name": "CIS Microsoft Azure Foundations Benchmark",
        "version": "v2.1 (2024)",
        "publisher": "Center for Internet Security",
        "scope_note": "Direct mapping — every identity risk factor carries a CIS control ID natively",
        # CIS controls are 1:1 with the cis tags on factors. Auto-derived
        # from RISK_FACTOR_CATALOG at runtime; no static control list here.
        "controls": None,  # signals auto-build
    },
}


def get_framework(code: str) -> Dict:
    """Get framework definition (raises KeyError if unknown code)."""
    return AUDITOR_FRAMEWORKS[code.lower()]


def map_factor_to_controls(factor_cis_tags: List[str], framework_code: str) -> List[str]:
    """Given a risk factor's CIS tags, return list of control IDs in the
    requested framework that this factor satisfies/violates."""
    fw = AUDITOR_FRAMEWORKS.get(framework_code.lower())
    if not fw or not fw.get("controls"):
        # CIS framework — direct passthrough
        return list(factor_cis_tags or [])
    matches = []
    fcis = set(factor_cis_tags or [])
    for ctrl in fw["controls"]:
        if fcis & set(ctrl.get("cis_map", [])):
            matches.append(ctrl["id"])
    return matches


def list_frameworks() -> List[Dict]:
    """Lightweight list of available frameworks for the UI dropdown."""
    return [
        {"code": k, "name": v["name"], "version": v["version"], "scope_note": v["scope_note"]}
        for k, v in AUDITOR_FRAMEWORKS.items()
    ]
