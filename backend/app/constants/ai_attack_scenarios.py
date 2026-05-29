"""
AI Risk pillar — attack-scenario catalog.

Turns the risk SIGNALS we derive from architecture (ai_risk.py) into named,
MITRE-mapped attack scenarios. A scenario is the *chaining* insight: a single
signal is a finding, but a COMBINATION (e.g. data access + unrestricted egress)
is an exploitable path.

Architecture-aligned: scenarios evaluate against signals already computed from
RBAC + resource config + network posture. No telemetry.

Each scenario fires for an agent when:
  - every key in `requires` is present in the agent's fired signals, AND
  - if `requires_any` is set, at least one of those keys is also present.
"""
from __future__ import annotations


AI_ATTACK_SCENARIOS: dict[str, dict] = {
    "AI_PRIVILEGE_ESCALATION": {
        "id": "AI_PRIVILEGE_ESCALATION",
        "name": "Subscription takeover via over-privileged AI agent",
        "severity": "critical",
        "requires": ["broad_owner_role"],
        "requires_any": [],
        "narrative": "This AI agent holds Owner / Contributor / User Access Administrator at "
                     "subscription scope. A prompt-injection or credential compromise lets an "
                     "attacker exercise that role to control every resource in the subscription — "
                     "including granting themselves persistent access.",
        "mitre": ["T1078.004", "T1098"],
        "prevented_by": "Scope the agent to a resource group with a least-privilege custom role.",
    },
    "AI_SECRET_EXPOSURE": {
        "id": "AI_SECRET_EXPOSURE",
        "name": "Credential theft via Key Vault administrative access",
        "severity": "critical",
        "requires": ["key_vault_admin"],
        "requires_any": [],
        "narrative": "The agent can read or modify every secret in the vault. An attacker who "
                     "hijacks the agent (prompt injection, token theft) exfiltrates the secrets "
                     "and pivots to whatever those credentials unlock — the classic AI-to-lateral-"
                     "movement bridge.",
        "mitre": ["T1555.006", "T1552.001"],
        "prevented_by": "Replace with Key Vault Secrets User scoped to an explicit secret allowlist.",
    },
    "AI_DATA_EXFILTRATION": {
        "id": "AI_DATA_EXFILTRATION",
        "name": "Data exfiltration — direct data access + unrestricted egress",
        "severity": "critical",
        "requires": ["sensitive_data_access", "unrestricted_egress"],
        "requires_any": [],
        "narrative": "The agent has direct read/write access to storage / SQL / Cosmos AND "
                     "unrestricted internet egress. A prompt-injection that coerces the agent to "
                     "read sensitive data and POST it to an attacker endpoint has a complete, "
                     "unmonitored exfiltration path.",
        "mitre": ["T1530", "T1567", "T1041"],
        "prevented_by": "Remove unrestricted egress (Private Endpoint / NSG) and/or downgrade data "
                        "access to read-only through a governed RAG layer.",
    },
    "AI_DATA_EXPOSURE": {
        "id": "AI_DATA_EXPOSURE",
        "name": "Sensitive data reachable by AI agent",
        "severity": "high",
        "requires": [],
        "requires_any": ["sensitive_data_access", "storage_blob_owner"],
        "narrative": "The agent has direct data-plane access to storage that bypasses application-"
                     "layer controls (DLP, masking, row-level security). Even without a confirmed "
                     "egress path, this is the high-value target a prompt-injection attack aims for.",
        "mitre": ["T1530", "T1213"],
        "prevented_by": "Route data access through a governed RAG / vector DB with row-level masking.",
    },
    "AI_UNGOVERNED_PRIVILEGE": {
        "id": "AI_UNGOVERNED_PRIVILEGE",
        "name": "Privileged AI agent with no accountable owner",
        "severity": "high",
        "requires": ["no_owner"],
        "requires_any": ["broad_owner_role", "key_vault_admin", "sensitive_data_access", "storage_blob_owner"],
        "narrative": "This agent holds privileged access but has no human owner. If it is abused, "
                     "there is no accountable party to notice, investigate, or revoke — the "
                     "privilege persists indefinitely as unmanaged attack surface.",
        "mitre": ["T1078.004"],
        "prevented_by": "Assign a human owner and re-attest the agent's privileges.",
    },
    "AI_STALE_CREDENTIAL": {
        "id": "AI_STALE_CREDENTIAL",
        "name": "Stale credential extends attack window",
        "severity": "medium",
        "requires": ["expired_credential"],
        "requires_any": [],
        "narrative": "The agent retains expired credentials. Unrotated secrets extend the window in "
                     "which a stolen credential remains usable and signal broken lifecycle automation.",
        "mitre": ["T1078.004"],
        "prevented_by": "Remove or rotate expired secrets/certificates; automate rotation.",
    },
}

SCENARIO_ORDER = [
    "AI_PRIVILEGE_ESCALATION", "AI_SECRET_EXPOSURE", "AI_DATA_EXFILTRATION",
    "AI_DATA_EXPOSURE", "AI_UNGOVERNED_PRIVILEGE", "AI_STALE_CREDENTIAL",
]

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def evaluate_scenarios(fired_signal_keys: set) -> list[dict]:
    """Return the attack scenarios that apply to an agent given its fired signals."""
    hits = []
    for sid in SCENARIO_ORDER:
        sc = AI_ATTACK_SCENARIOS[sid]
        if not all(k in fired_signal_keys for k in sc["requires"]):
            continue
        if sc["requires_any"] and not any(k in fired_signal_keys for k in sc["requires_any"]):
            continue
        hits.append(sc)
    return hits


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)
