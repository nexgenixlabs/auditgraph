"""
AI Governance policy catalog + evaluation.

Turns the risk SIGNALS we already derive from architecture (see ai_risk.py)
into named, framework-mapped POLICIES with a pass/fail verdict per AI agent.
This is the "are you within policy?" layer — what auditors and CISOs buy.

Architecture-aligned: every policy evaluates against signals derived from the
cloud control plane (RBAC, resource config, network posture). No telemetry.

A policy "fails" for an agent when its bound risk signal fired for that agent.
Because signals are already computed by detect_signals(), evaluation is a cheap
set-membership check — no extra Azure calls.
"""
from __future__ import annotations

from typing import Optional


# Each policy:
#   id            stable key
#   name          human statement of the rule (what SHOULD be true)
#   severity      critical | high | medium | low
#   signal_key    the ai_risk signal whose presence == a violation
#   framework     compliance framework control references
#   rationale     why this policy exists
#   remediation   how to get compliant
AI_GOVERNANCE_POLICIES: dict[str, dict] = {
    "no_broad_privilege": {
        "id": "no_broad_privilege",
        "name": "AI agents must not hold Owner / Contributor / User Access Administrator at subscription scope",
        "severity": "critical",
        "signal_key": "broad_owner_role",
        "framework": ["NIST AC-6 (Least Privilege)", "CIS Azure 1.23", "ISO 27001 A.9.2.3"],
        "rationale": "Subscription-scope ownership gives an autonomous agent full control of every "
                     "resource beneath it, including IAM. A prompt-injected or compromised agent "
                     "with this role can take over the subscription.",
        "remediation": "Replace with a resource-group-scoped Contributor or a custom least-privilege role.",
    },
    "must_have_human_owner": {
        "id": "must_have_human_owner",
        "name": "Every AI agent must have an accountable human owner",
        "severity": "high",
        "signal_key": "no_owner",
        "framework": ["NIST AC-2 (Account Management)", "NIST PM-15", "ISO 27001 A.9.2.1"],
        "rationale": "Ownerless AI identities have no accountable party — remediation stalls, "
                     "lifecycle decisions are never made, and the identity decays into "
                     "unmanaged attack surface.",
        "remediation": "Assign a human owner via the AuditGraph governance workflow.",
    },
    "no_keyvault_admin": {
        "id": "no_keyvault_admin",
        "name": "AI agents must not hold Key Vault Administrator / Secrets Officer",
        "severity": "critical",
        "signal_key": "key_vault_admin",
        "framework": ["NIST SC-12", "NIST IA-5", "CIS Azure 8.x"],
        "rationale": "Administrative secret access lets an agent read or modify every secret in the "
                     "vault — the single most common credential-exfiltration enabler for AI workloads.",
        "remediation": "Use Key Vault Secrets User with an explicit allowlist of required secret names.",
    },
    "no_direct_data_write": {
        "id": "no_direct_data_write",
        "name": "AI agents must not have direct write access to storage / SQL / Cosmos",
        "severity": "high",
        "signal_key": "sensitive_data_access",
        "framework": ["NIST AC-4 (Information Flow)", "NIST SC-28", "ISO 27001 A.8.2.3"],
        "rationale": "Direct data-plane write access bypasses application-layer controls (DLP, masking, "
                     "row-level security) and is a high-blast-radius target for prompt-injection.",
        "remediation": "Route data access through a governed RAG / vector DB with row-level masking; "
                       "downgrade to read-only where possible.",
    },
    "no_unrestricted_egress": {
        "id": "no_unrestricted_egress",
        "name": "AI agents must not have unrestricted internet egress",
        "severity": "medium",
        "signal_key": "unrestricted_egress",
        "framework": ["NIST SC-7 (Boundary Protection)", "CIS Azure 6.x"],
        "rationale": "Unrestricted egress lets an agent call arbitrary external endpoints — the "
                     "exfiltration channel for prompt-injection-driven data theft.",
        "remediation": "Apply NSG egress rules or Private Endpoint; force traffic through a governed proxy.",
    },
    "telemetry_required": {
        "id": "telemetry_required",
        "name": "AI workloads must emit diagnostic telemetry",
        "severity": "medium",
        "signal_key": "no_telemetry",
        "framework": ["NIST AU-2 (Audit Events)", "NIST AU-12", "NIST SI-4"],
        "rationale": "Without telemetry, anomaly detection and post-incident forensics are impossible. "
                     "Note: this is a confirmation gap, not a risk derivation — AuditGraph still derives "
                     "access from architecture regardless.",
        "remediation": "Enable diagnostic settings forwarding to Log Analytics / SIEM.",
    },
    "no_expired_credentials": {
        "id": "no_expired_credentials",
        "name": "AI agents must not retain expired credentials",
        "severity": "medium",
        "signal_key": "expired_credential",
        "framework": ["NIST IA-5 (Authenticator Management)"],
        "rationale": "Unrotated / expired credentials extend the credential-theft window and indicate "
                     "broken lifecycle automation.",
        "remediation": "Remove or rotate expired secrets/certificates; automate rotation.",
    },
}

# Display order for the policy table — critical first
POLICY_ORDER = [
    "no_broad_privilege", "no_keyvault_admin", "no_direct_data_write",
    "must_have_human_owner", "no_unrestricted_egress", "telemetry_required",
    "no_expired_credentials",
]

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def evaluate_agent_policies(
    fired_signal_keys: set,
    *,
    identity_id: Optional[str] = None,
    active_exceptions: Optional[dict] = None,
) -> list[dict]:
    """Given the set of risk-signal keys that fired for an agent, return the
    list of policy violations (one dict per failed policy).

    Args:
        fired_signal_keys: signal keys that fired for this agent.
        identity_id: the agent's identity_id (UUID/external ID), used to look up
            active exceptions.
        active_exceptions: dict keyed by (identity_id, policy_id) → expires_at
            ISO string. When a violation matches an active exception, the
            violation is RETAINED in the list but flagged as suppressed so the
            UI can render the exception inline ("Exception · expires X").
            Callers that need to act on violations (anomalies, alerts) should
            filter out suppressed_by_exception=True themselves.
    """
    violations = []
    excs = active_exceptions or {}
    for pid in POLICY_ORDER:
        pol = AI_GOVERNANCE_POLICIES[pid]
        if pol["signal_key"] in fired_signal_keys:
            exc_key = (identity_id, pid) if identity_id is not None else None
            suppressed = bool(exc_key and exc_key in excs)
            expires_at = excs.get(exc_key) if suppressed else None
            violations.append({
                "policy_id":   pid,
                "name":        pol["name"],
                "severity":    pol["severity"],
                "framework":   pol["framework"],
                "remediation": pol["remediation"],
                "suppressed_by_exception": suppressed,
                "exception_expires_at":    expires_at,
            })
    return violations


def policy_list() -> list[dict]:
    """Ordered policy definitions for display."""
    return [AI_GOVERNANCE_POLICIES[pid] for pid in POLICY_ORDER]


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)
