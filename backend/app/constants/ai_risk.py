"""
AI Identity Risk Constants — Single Source of Truth
====================================================

All AI-specific risk scoring weights, thresholds, signal definitions,
and access-type categorizations live here. Referenced by:
  - Backend API endpoints (ai-agents, permissions, blast-radius)
  - AI risk scoring computations
  - Frontend constants mirror (riskScoring.ts)

Aligned to:
  - CVSS v3.1 severity bands
  - MITRE ATT&CK for Enterprise v14
  - CIS Controls v8
  - NIST SP 800-207 (Zero Trust Architecture)
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════
# CVSS v3.1 Severity Bands (normalized 0-100 score)
# ═══════════════════════════════════════════════════════════════════

SEVERITY_CRITICAL_MIN = 75.0
SEVERITY_HIGH_MIN = 50.0
SEVERITY_MEDIUM_MIN = 25.0
SEVERITY_LOW_MIN = 10.0


def severity_from_score(score: float) -> str:
    """Map a 0-100 risk score to a CVSS v3.1-aligned severity label."""
    if score >= SEVERITY_CRITICAL_MIN:
        return "critical"
    if score >= SEVERITY_HIGH_MIN:
        return "high"
    if score >= SEVERITY_MEDIUM_MIN:
        return "medium"
    if score >= SEVERITY_LOW_MIN:
        return "low"
    return "info"


# ═══════════════════════════════════════════════════════════════════
# AI Agent Risk Score Weights (5-dimension model)
# ═══════════════════════════════════════════════════════════════════
# Final = max(dimensions) * MAX_WEIGHT + mean(dimensions) * MEAN_WEIGHT
# Scaled to 0-100 range.

AI_RISK_MAX_WEIGHT = 0.4
AI_RISK_MEAN_WEIGHT = 0.6
AI_RISK_SCALE = 10.0  # multiply blended 0-10 → 0-100

# Dimension: Model Access
MODEL_ACCESS_WEIGHTS = {
    "owner": 10.0,
    "contributor": 8.0,
    "developer": 6.0,
    "user": 4.0,
    "reader": 2.0,
    "none": 0.0,
}

# Dimension: Key Vault Access
KEY_VAULT_WEIGHTS = {
    "administrator": 10.0,
    "secrets_officer": 9.0,
    "secrets_user": 7.0,
    "reader": 3.0,
    "none": 0.0,
}

# Dimension: Data Access
DATA_ACCESS_WEIGHTS = {
    "owner": 10.0,
    "contributor": 8.0,
    "data_reader_writer": 6.0,
    "data_reader": 4.0,
    "none": 0.0,
}

# Dimension: Telemetry / Monitoring Access
TELEMETRY_WEIGHTS = {
    "full_access": 8.0,
    "contributor": 6.0,
    "reader": 3.0,
    "none": 0.0,
}

# Dimension: Internet Egress (network exposure)
INTERNET_EGRESS_WEIGHTS = {
    "unrestricted": 10.0,
    "restricted": 5.0,
    "blocked": 1.0,
    "unknown": 7.0,  # unknown = assume worst-case minus margin
}

# ═══════════════════════════════════════════════════════════════════
# AI-Specific Access Type Categorization
# ═══════════════════════════════════════════════════════════════════
# Maps Azure RBAC role names to access categories for the AI Agents tab.

MODEL_ACCESS_ROLES = frozenset({
    "Azure AI Administrator",
    "Azure AI Developer",
    "Azure AI Project Manager",
    "Azure AI User",
    "AzureML Data Scientist",
    "Azure ML Data Scientist",
    "AzureML Registry User",
    "Cognitive Services User",
    "Cognitive Services Contributor",
    "Cognitive Services Speech User",
    "OpenAI Contributor",
})

KEY_VAULT_ACCESS_ROLES = frozenset({
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
    "Key Vault Secrets User",
    "Key Vault Reader",
    "Key Vault Certificates Officer",
    "Key Vault Crypto Officer",
    "Key Vault Crypto User",
})

DATA_ACCESS_ROLES = frozenset({
    "Storage Blob Data Owner",
    "Storage Blob Data Contributor",
    "Storage Blob Data Reader",
    "Storage Table Data Contributor",
    "Storage Table Data Reader",
    "Storage Queue Data Contributor",
    "Storage Queue Data Reader",
    "Cosmos DB Account Reader Role",
    "DocumentDB Account Contributor",
    "SQL DB Contributor",
    "SQL Server Contributor",
})

TELEMETRY_ACCESS_ROLES = frozenset({
    "Monitoring Contributor",
    "Monitoring Reader",
    "Log Analytics Contributor",
    "Log Analytics Reader",
    "Application Insights Component Contributor",
})

# Scope substring patterns that indicate internet-facing resources
INTERNET_EGRESS_SCOPE_PATTERNS = [
    "microsoft.network/publicipaddresses",
    "microsoft.network/applicationgateways",
    "microsoft.cdn",
    "microsoft.network/frontdoors",
    "microsoft.apimanagement",
    "microsoft.web/sites",  # App Service (can be external)
]

# ═══════════════════════════════════════════════════════════════════
# Role → Access Level Mapping
# ═══════════════════════════════════════════════════════════════════
# Maps specific roles to their effective access level within each category.

MODEL_ACCESS_ROLE_LEVELS: dict[str, str] = {
    "Azure AI Administrator": "owner",
    "Azure AI Developer": "developer",
    "Azure AI Project Manager": "contributor",
    "Azure AI User": "user",
    "AzureML Data Scientist": "developer",
    "Azure ML Data Scientist": "developer",
    "AzureML Registry User": "reader",
    "Cognitive Services User": "user",
    "Cognitive Services Contributor": "contributor",
    "Cognitive Services Speech User": "user",
    "OpenAI Contributor": "contributor",
}

KEY_VAULT_ROLE_LEVELS: dict[str, str] = {
    "Key Vault Administrator": "administrator",
    "Key Vault Secrets Officer": "secrets_officer",
    "Key Vault Secrets User": "secrets_user",
    "Key Vault Reader": "reader",
    "Key Vault Certificates Officer": "secrets_officer",
    "Key Vault Crypto Officer": "secrets_officer",
    "Key Vault Crypto User": "secrets_user",
}

DATA_ACCESS_ROLE_LEVELS: dict[str, str] = {
    "Storage Blob Data Owner": "owner",
    "Storage Blob Data Contributor": "contributor",
    "Storage Blob Data Reader": "data_reader",
    "Storage Table Data Contributor": "contributor",
    "Storage Table Data Reader": "data_reader",
    "Storage Queue Data Contributor": "contributor",
    "Storage Queue Data Reader": "data_reader",
    "Cosmos DB Account Reader Role": "data_reader",
    "DocumentDB Account Contributor": "contributor",
    "SQL DB Contributor": "contributor",
    "SQL Server Contributor": "owner",
}

TELEMETRY_ROLE_LEVELS: dict[str, str] = {
    "Monitoring Contributor": "contributor",
    "Monitoring Reader": "reader",
    "Log Analytics Contributor": "contributor",
    "Log Analytics Reader": "reader",
    "Application Insights Component Contributor": "contributor",
}

# ═══════════════════════════════════════════════════════════════════
# Broad privilege roles (tenant-wide danger multipliers)
# ═══════════════════════════════════════════════════════════════════

BROAD_PRIVILEGE_ROLES = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Global Administrator",
})

# ═══════════════════════════════════════════════════════════════════
# AI Permission Signals — permission strings that indicate AI usage
# ═══════════════════════════════════════════════════════════════════

AI_PERMISSION_SIGNALS = {
    "AiService.ReadWrite.All": {"confidence": 0.95, "platform": "azure_ai"},
    "CognitiveServices": {"confidence": 0.95, "platform": "azure_cognitive"},
    "Bot.ReadWrite.All": {"confidence": 0.95, "platform": "bot_framework"},
    "MachineLearningServices": {"confidence": 0.90, "platform": "azure_ml"},
}

# ═══════════════════════════════════════════════════════════════════
# AI Platform Labels (for display)
# ═══════════════════════════════════════════════════════════════════

AI_PLATFORM_LABELS: dict[str, str] = {
    "openai": "OpenAI",
    "azure_openai": "Azure OpenAI",
    "azure_ai": "Azure AI",
    "azure_cognitive": "Azure Cognitive",
    "azure_ml": "Azure ML",
    "azure_ai_studio": "Azure AI Studio",
    "anthropic": "Anthropic",
    "copilot_studio": "Copilot Studio",
    "power_virtual_agents": "Power VA",
    "bot_framework": "Bot Framework",
}

# ═══════════════════════════════════════════════════════════════════
# Confidence Thresholds
# ═══════════════════════════════════════════════════════════════════

CONFIDENCE_HIGH = 0.85
CONFIDENCE_MEDIUM = 0.60
CONFIDENCE_LOW = 0.40


def confidence_label(score: float) -> str:
    """Map a 0-1 confidence score to a display label."""
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    if score >= CONFIDENCE_LOW:
        return "low"
    return "minimal"


# ═══════════════════════════════════════════════════════════════════
# MITRE ATT&CK Technique Mapping — AI-specific
# ═══════════════════════════════════════════════════════════════════

AI_MITRE_TECHNIQUES: dict[str, str] = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1528": "Steal Application Access Token",
    "T1550": "Use Alternate Authentication Material",
    "T1556": "Modify Authentication Process",
    "T1199": "Trusted Relationship",
    "T1537": "Transfer Data to Cloud Account",
}

# ═══════════════════════════════════════════════════════════════════
# Remediation Priority Thresholds (aligned with risk_engine.py)
# ═══════════════════════════════════════════════════════════════════

REMEDIATION_P0_THRESHOLD = 75.0  # Critical — fix now
REMEDIATION_P1_THRESHOLD = 50.0  # High — fix this sprint
# Below P1 = P2 — track but don't block


# ═══════════════════════════════════════════════════════════════════
# AI Permissions Page — Assessment Tone Thresholds (AG-162)
# ═══════════════════════════════════════════════════════════════════
# Tone for each metric is derived from "% of total AI agents holding that
# access type." Values are deliberately conservative — these thresholds
# encode the assumption that most AI agents should be minimally privileged.
#
# Each metric entry:
#   healthy_pct_max     — at or below this % = healthy (green)
#   borderline_pct_max  — above healthy, up to here = borderline (amber)
#   above borderline                                = concerning (red)
#   higher_is_better    — True for metrics where MORE coverage is good (e.g. Telemetry)
#   action_prompt       — 1-line guidance shown on the card
#   benchmark           — short industry benchmark / rationale shown as tooltip
#
# Source: AuditGraph AI Security baseline (May 2026); thresholds reviewed
# against CIS Microsoft Azure Foundations Benchmark + Microsoft Zero Trust
# guidance for service principals.

PERMISSION_TONE_THRESHOLDS: dict[str, dict] = {
    "model_access": {
        "healthy_pct_max":    30.0,
        "borderline_pct_max": 50.0,
        "higher_is_better":   False,
        "action_prompt":      "Review whether each agent needs model access",
        "benchmark":          "Healthy if intentional — AI Builder / Cognitive roles are expected for genuine AI workloads",
    },
    "key_vault_access": {
        "healthy_pct_max":    5.0,
        "borderline_pct_max": 15.0,
        "higher_is_better":   False,
        "action_prompt":      "Audit which secrets each agent can read — scope down to specific secrets where possible",
        "benchmark":          "Industry guidance: <5% of AI agents should hold any Key Vault role; Secrets Officer / Admin should be rare",
    },
    "data_access": {
        "healthy_pct_max":    10.0,
        "borderline_pct_max": 25.0,
        "higher_is_better":   False,
        "action_prompt":      "Verify each agent's data scope — prefer Read-only roles over Contributor",
        "benchmark":          "Direct storage access bypasses application-layer controls; review RAG / vector DB alternatives",
    },
    "telemetry": {
        "healthy_pct_max":    100.0,   # higher_is_better — see below
        "borderline_pct_max": 50.0,
        "higher_is_better":   True,
        "action_prompt":      "Enable diagnostic logging on AI workloads without it",
        "benchmark":          "Industry guidance: 100% of AI workloads should emit diagnostics to a SIEM",
    },
    "internet_egress": {
        "healthy_pct_max":    0.0,
        "borderline_pct_max": 5.0,
        "higher_is_better":   False,
        "action_prompt":      "Apply network policy / Private Endpoint to restrict outbound access",
        "benchmark":          "Unrestricted egress allows AI agents to call arbitrary external APIs; should be 0% in regulated environments",
    },
    "broad_privilege": {
        "healthy_pct_max":    0.0,
        "borderline_pct_max": 2.0,
        "higher_is_better":   False,
        "action_prompt":      "Replace Owner / Contributor / UAA with least-privilege scoped roles",
        "benchmark":          "Industry guidance: 0 AI agents should hold Owner, Contributor, or User Access Administrator at subscription scope",
    },
}


def assess_tone(metric_key: str, count: int, total: int) -> dict:
    """Return assessment dict for a single permission metric.

    Output keys: pct, tone (healthy|borderline|concerning|unknown),
    action_prompt, benchmark — used by the AI Permissions page cards.
    """
    cfg = PERMISSION_TONE_THRESHOLDS.get(metric_key)
    pct = round((count / total) * 100, 1) if total > 0 else 0.0
    if not cfg or total == 0:
        return {
            "pct": pct,
            "tone": "unknown",
            "action_prompt": "",
            "benchmark": "",
        }
    if cfg["higher_is_better"]:
        # Invert: high % is healthy, low % is concerning.
        if pct >= 80.0:
            tone = "healthy"
        elif pct >= cfg["borderline_pct_max"]:
            tone = "borderline"
        else:
            tone = "concerning"
    else:
        if pct <= cfg["healthy_pct_max"]:
            tone = "healthy"
        elif pct <= cfg["borderline_pct_max"]:
            tone = "borderline"
        else:
            tone = "concerning"
    return {
        "pct": pct,
        "tone": tone,
        "action_prompt": cfg["action_prompt"],
        "benchmark": cfg["benchmark"],
    }


def _name_list(agents: list[dict], limit: int = 3) -> str:
    """Format a short list of agent display names for findings text.
    Returns "(X)" for 1, "(X, Y)" for 2, "(X, Y, Z, +N more)" for >3.
    """
    if not agents:
        return ""
    names = [a.get("display_name") or a.get("identity_id") or "Unknown" for a in agents[:limit]]
    extra = max(0, len(agents) - limit)
    suffix = f", +{extra} more" if extra else ""
    return f" ({', '.join(names)}{suffix})"


# ═══════════════════════════════════════════════════════════════════
# AG-164: Signal-sum risk scoring (NIST + CVSS v3.1 + MITRE ATT&CK aligned)
# ═══════════════════════════════════════════════════════════════════
# Replaces the dimensional max+mean blend for the AI Inventory's primary risk
# score. Each signal is independently defensible — auditors see exactly which
# control failures contributed and can map to their compliance framework.
#
# Each signal entry:
#   weight       — raw contribution (used for prioritisation and breakdown)
#   title        — 1-line human description
#   rationale    — 1-2 sentence "why this matters"
#   nist         — NIST SP 800-53 control identifiers
#   cvss_vector  — CVSS v3.1 vector string for THIS signal's contribution
#                  (combined CVSS for an agent isn't meaningful; we cite per-signal)
#   mitre        — MITRE ATT&CK / ATLAS technique IDs the signal maps to
#   remediation  — concrete suggested fix
#
# Final per-agent score is CVSS-aligned 0–10. See compute_signal_score().

RISK_SIGNALS: dict[str, dict] = {
    "broad_owner_role": {
        "weight": 150,
        "title": "Holds Owner / Contributor / User Access Administrator on a subscription",
        "rationale": "Subscription-scope ownership grants full management of all resources beneath the scope, including IAM changes. AI agents rarely need this.",
        "nist": ["AC-6 (Least Privilege)", "AC-2 (Account Management)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "mitre": ["T1078.004"],
        "remediation": "Replace with scoped Contributor at the resource-group level, or with custom least-privilege role.",
    },
    "key_vault_admin": {
        "weight": 150,
        "title": "Holds Key Vault Administrator or Secrets Officer",
        "rationale": "Can read, write, or delete any secret in the vault. Single most common credential-exfiltration enabler for AI agents.",
        "nist": ["SC-12 (Cryptographic Key Establishment)", "IA-5 (Authenticator Management)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L",
        "mitre": ["T1555.006", "T1552.001"],
        "remediation": "Use Key Vault Secrets User with an explicit allowlist of secret names.",
    },
    "storage_blob_owner": {
        "weight": 125,
        "title": "Holds Storage Blob Data Owner",
        "rationale": "Full read / write / delete plus ACL management on blob containers. Direct data exfiltration risk that bypasses any application-layer DLP.",
        "nist": ["AC-3 (Access Enforcement)", "MP-2 (Media Access)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "mitre": ["T1530"],
        "remediation": "Restrict to Storage Blob Data Contributor or Reader; remove ACL ownership unless explicitly justified.",
    },
    "sensitive_data_access": {
        "weight": 100,
        "title": "Has direct write access to storage / SQL / Cosmos",
        "rationale": "Bypasses application-layer controls (DLP, masking, row-level security). High blast radius for prompt-injection scenarios that coerce data writes.",
        "nist": ["AC-4 (Information Flow Enforcement)", "SC-28 (Protection of Information at Rest)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N",
        "mitre": ["T1530", "T1213"],
        "remediation": "Route through governed RAG / vector DB with row-level masking; downgrade to read-only where possible.",
    },
    "no_telemetry": {
        "weight": 100,
        "title": "No diagnostic telemetry detected for this AI workload",
        "rationale": "Without sign-in / activity / Graph audit logs, anomaly detection and post-incident forensics are impossible. The agent could be abused for weeks before discovery.",
        "nist": ["AU-2 (Audit Events)", "AU-12 (Audit Generation)", "SI-4 (System Monitoring)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "mitre": ["T1562.008"],
        "remediation": "Enable diagnostic settings forwarding sign-in / audit / activity logs to Log Analytics or SIEM.",
    },
    "unrestricted_egress": {
        "weight": 75,
        "title": "AI workload has unrestricted internet egress",
        "rationale": "Agent can call any external endpoint — adversarial LLMs, attacker-controlled webhooks, exfil destinations. Defends against prompt-injection-driven data exfiltration.",
        "nist": ["SC-7 (Boundary Protection)", "SC-7(4) (External Telecommunications)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "mitre": ["T1567", "T1041"],
        "remediation": "Apply NSG egress rules; use Private Endpoint with allowlist; force traffic through governed forward proxy.",
    },
    "external_llm_access": {
        "weight": 50,
        "title": "AI workload calls a third-party LLM endpoint",
        "rationale": "Prompts and grounding data sent to non-Microsoft / non-AWS provider — review DPA, data residency, and vendor risk.",
        "nist": ["SC-7 (Boundary Protection)", "PM-9 (Risk Management Strategy)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "mitre": ["T1567"],
        "remediation": "Route through Azure OpenAI / Bedrock with vendor DPA + data-residency agreement in place.",
    },
    "expired_credential": {
        "weight": 50,
        "title": "AI agent has expired credentials still attached",
        "rationale": "Unrotated secrets / certificates extend the credential-theft attack window. Indicates broken lifecycle automation.",
        "nist": ["IA-5 (Authenticator Management)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "mitre": ["T1078.004"],
        "remediation": "Remove or rotate expired credentials; automate via App Registration credential rotation policy.",
    },
    "dormant_agent": {
        "weight": 25,
        "title": "AI agent has not signed in for 90+ days but retains permissions",
        "rationale": "Dormant identities are unmonitored attack surface — the longer dormant, the less likely an anomaly will be noticed.",
        "nist": ["AC-2 (Account Management)", "AC-2(3) (Disable Inactive Accounts)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "mitre": ["T1078.004"],
        "remediation": "Disable or re-attest dormant agent ownership; remove role assignments.",
    },
    "no_owner": {
        "weight": 25,
        "title": "AI agent has no human owner assigned",
        "rationale": "No accountable party means remediation requests stall and lifecycle decisions don't get made. Compounds with all other findings.",
        "nist": ["AC-2 (Account Management)", "PM-15 (Contacts with Security Groups)"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "mitre": [],
        "remediation": "Assign a human owner via the AuditGraph governance workflow.",
    },
}


def detect_signals(agent_meta: dict, role_assignments: list[dict],
                   access_levels: dict[str, str]) -> list[dict]:
    """Evaluate which RISK_SIGNALS fire for one AI agent.

    Args:
        agent_meta: dict with keys like display_name, owner_display_name,
                    credential_count, credential_risk, last_sign_in,
                    last_activity_date, ai_telemetry_status (optional)
        role_assignments: list of {role_name, scope, ...} dicts
        access_levels: result of aggregate_access_levels()

    Returns a list of fired signal dicts, each with weight + full metadata.
    """
    import datetime as _dt
    fired = []

    def add(signal_key: str, evidence: str = ''):
        sig = RISK_SIGNALS.get(signal_key)
        if sig:
            fired.append({**sig, 'key': signal_key, 'evidence': evidence})

    role_names = {(ra.get('role_name') or '') for ra in role_assignments}
    sub_scope_roles = [ra for ra in role_assignments
                       if (ra.get('scope') or '').startswith('/subscriptions/')
                       and (ra.get('scope') or '').count('/') == 2]
    # 1) broad_owner_role at subscription scope
    for ra in sub_scope_roles:
        if (ra.get('role_name') or '') in BROAD_PRIVILEGE_ROLES:
            add('broad_owner_role', evidence=f"{ra.get('role_name')} on {ra.get('scope', '')}")
            break

    # 2) key_vault_admin
    kv_admin_roles = {'Key Vault Administrator', 'Key Vault Secrets Officer',
                      'Key Vault Crypto Officer', 'Key Vault Certificates Officer'}
    overlap = role_names & kv_admin_roles
    if overlap:
        add('key_vault_admin', evidence=', '.join(sorted(overlap)))

    # 3) storage_blob_owner
    if 'Storage Blob Data Owner' in role_names:
        add('storage_blob_owner', evidence='Storage Blob Data Owner')

    # 4) sensitive_data_access (write-level on data resources, excludes blob owner already counted)
    write_data_roles = {'Storage Blob Data Contributor', 'Storage File Data SMB Share Contributor',
                        'Storage Table Data Contributor', 'Storage Queue Data Contributor',
                        'Cosmos DB Built-in Data Contributor', 'SQL DB Contributor'}
    write_overlap = role_names & write_data_roles
    if write_overlap and 'storage_blob_owner' not in [s['key'] for s in fired]:
        add('sensitive_data_access', evidence=', '.join(sorted(write_overlap)))

    # 5) no_telemetry — heuristic: no last_sign_in AND no last_activity_date
    has_telem = bool(agent_meta.get('last_sign_in') or agent_meta.get('last_activity_date')
                     or agent_meta.get('last_service_principal_sign_in'))
    explicit_telem = agent_meta.get('ai_telemetry_status')
    if explicit_telem == 'disabled' or (not has_telem and explicit_telem != 'enabled'):
        add('no_telemetry', evidence='No sign-in / activity logs in the lookback window')

    # 6) unrestricted_egress / 7) external_llm_access — from access_levels
    if access_levels.get('internet_egress') == 'unrestricted':
        add('unrestricted_egress', evidence='Role scope includes internet-facing resources')
    # external_llm: heuristic — if platform is anthropic/openai but model_access is model-level
    plat = (agent_meta.get('detected_platform') or '').lower()
    if plat in {'anthropic', 'openai'} or 'openai' in plat:
        add('external_llm_access', evidence=f"detected_platform = {plat or 'unknown'}")

    # 8) expired_credential — credential_risk == 'expired'
    if (agent_meta.get('credential_risk') or '').lower() == 'expired':
        add('expired_credential', evidence='credential_risk = expired')

    # 9) dormant_agent
    last_act = agent_meta.get('last_activity_date') or agent_meta.get('last_sign_in')
    if last_act:
        try:
            last_dt = last_act if isinstance(last_act, _dt.datetime) else _dt.datetime.fromisoformat(str(last_act).replace('Z', '+00:00'))
            if (_dt.datetime.now(last_dt.tzinfo) - last_dt).days >= 90:
                add('dormant_agent', evidence=f"last activity {last_act}")
        except Exception:
            pass

    # 10) no_owner
    if not agent_meta.get('owner_display_name'):
        add('no_owner', evidence='No human owner assigned')

    return fired


def compute_signal_score(fired_signals: list[dict]) -> dict:
    """Convert fired signals into CVSS-aligned 0–10 score + severity + breakdown.

    Stacking rule (enterprise risk philosophy):
      - Highest single signal weight sets the score floor (one critical = critical).
      - Each additional signal adds 0.5, capped at +1.0 above floor.
      - Score is rounded to 1 decimal and capped at 10.0.

    Severity bands match CVSS v3.1:
      9.0–10.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low, 0.0 info.

    Returns:
        {
          'score': float (0–10),
          'severity': 'critical|high|medium|low|info',
          'breakdown': [{key, title, weight, contribution, ...}, ...] sorted by weight desc
        }
    """
    if not fired_signals:
        return {'score': 0.0, 'severity': 'info', 'breakdown': []}

    max_weight = max(s['weight'] for s in fired_signals)

    if   max_weight >= 150: base = 9.0
    elif max_weight >= 125: base = 8.0
    elif max_weight >= 100: base = 7.0
    elif max_weight >= 75:  base = 5.0
    elif max_weight >= 50:  base = 3.0
    elif max_weight >= 25:  base = 1.5
    else:                   base = 0.5

    additional = min(1.0, 0.5 * (len(fired_signals) - 1))
    score = round(min(10.0, base + additional), 1)

    if   score >= 9.0: sev = 'critical'
    elif score >= 7.0: sev = 'high'
    elif score >= 4.0: sev = 'medium'
    elif score >= 0.1: sev = 'low'
    else:              sev = 'info'

    breakdown = sorted(
        [
            {
                'key':          s['key'],
                'title':        s['title'],
                'weight':       s['weight'],
                'rationale':    s['rationale'],
                'nist':         s['nist'],
                'cvss_vector':  s['cvss_vector'],
                'mitre':        s['mitre'],
                'remediation':  s['remediation'],
                'evidence':     s.get('evidence', ''),
            }
            for s in fired_signals
        ],
        key=lambda x: -x['weight'],
    )
    return {'score': score, 'severity': sev, 'breakdown': breakdown}


def synthesize_findings(metrics: dict[str, dict], total_agents: int,
                        overprivileged_agents: list[dict] | int = 0) -> list[str]:
    """Generate 3–5 plain-English findings sentences from live metric data.

    `overprivileged_agents` accepts either an int count (legacy) or a list of
    agent dicts with `display_name` / `identity_id`. When a list is passed,
    the offending agent names are included inline so the user sees WHO, not
    just HOW MANY.

    NO hardcoded text other than the templates — all numbers and severity
    references come from the metrics dict. Used by AI Permissions page.
    """
    if total_agents == 0:
        return ["No AI agents detected in this organization yet. Run a discovery scan to populate this view."]

    # Backward-compat shim
    if isinstance(overprivileged_agents, int):
        op_count = overprivileged_agents
        op_list: list[dict] = []
    else:
        op_count = len(overprivileged_agents)
        op_list = overprivileged_agents

    findings: list[str] = []
    findings.append(
        f"AuditGraph identified {total_agents} AI agent identit{'y' if total_agents == 1 else 'ies'} in your environment."
    )

    concerning = [(k, v) for k, v in metrics.items() if v.get("tone") == "concerning"]
    borderline = [(k, v) for k, v in metrics.items() if v.get("tone") == "borderline"]

    if op_count > 0:
        is_plural = op_count != 1
        names = _name_list(op_list)
        findings.append(
            f"{op_count} agent{'s' if is_plural else ''}{names} "
            f"{'hold' if is_plural else 'holds'} broad privilege roles "
            f"(Owner, Contributor, or User Access Administrator) — industry guidance is 0 in production environments."
        )

    if concerning:
        worst_key, worst = concerning[0]
        cfg = PERMISSION_TONE_THRESHOLDS.get(worst_key, {})
        label = worst_key.replace("_", " ").title()
        if cfg.get("higher_is_better"):
            findings.append(
                f"{label} coverage is only {worst['pct']}% of agents — below the recommended baseline. "
                f"Recommended action: {worst['action_prompt']}."
            )
        else:
            findings.append(
                f"{label} is currently {worst['pct']}% of agents — above the recommended threshold. "
                f"Recommended action: {worst['action_prompt']}."
            )

    if borderline and len(findings) < 4:
        bk, bv = borderline[0]
        label = bk.replace("_", " ").title()
        findings.append(
            f"{label} sits at {bv['pct']}% — within tolerance but worth periodic review."
        )

    if not concerning and not borderline and op_count == 0:
        findings.append("All measured permission categories are within recommended thresholds. Maintain this posture by reviewing new AI agent role grants quarterly.")

    return findings[:5]


# ═══════════════════════════════════════════════════════════════════
# Helper: Classify roles into access categories
# ═══════════════════════════════════════════════════════════════════

def classify_role_access(role_name: str, scope: str | None = None) -> dict[str, str | None]:
    """Classify a single role assignment into AI access categories.

    Returns a dict with keys: model_access, key_vault_access, data_access,
    telemetry, internet_egress — each value is the access level or None.
    """
    result: dict[str, str | None] = {
        "model_access": None,
        "key_vault_access": None,
        "data_access": None,
        "telemetry": None,
        "internet_egress": None,
    }

    if role_name in MODEL_ACCESS_ROLE_LEVELS:
        result["model_access"] = MODEL_ACCESS_ROLE_LEVELS[role_name]
    if role_name in KEY_VAULT_ROLE_LEVELS:
        result["key_vault_access"] = KEY_VAULT_ROLE_LEVELS[role_name]
    if role_name in DATA_ACCESS_ROLE_LEVELS:
        result["data_access"] = DATA_ACCESS_ROLE_LEVELS[role_name]
    if role_name in TELEMETRY_ROLE_LEVELS:
        result["telemetry"] = TELEMETRY_ROLE_LEVELS[role_name]

    # Check scope for internet egress indicators
    if scope:
        scope_lower = scope.lower()
        for pattern in INTERNET_EGRESS_SCOPE_PATTERNS:
            if pattern in scope_lower:
                result["internet_egress"] = "unrestricted"
                break

    # Broad privilege roles grant elevated access across all categories
    if role_name in BROAD_PRIVILEGE_ROLES:
        if result["model_access"] is None:
            result["model_access"] = "contributor"
        if result["key_vault_access"] is None:
            result["key_vault_access"] = "secrets_user"
        if result["data_access"] is None:
            result["data_access"] = "contributor"
        if result["telemetry"] is None:
            result["telemetry"] = "full_access"
        if result["internet_egress"] is None:
            result["internet_egress"] = "unrestricted"

    return result


def aggregate_access_levels(role_assignments: list[dict]) -> dict[str, str]:
    """Aggregate access levels from multiple role assignments.

    Takes the highest access level per category across all roles.
    Returns dict with keys: model_access, key_vault_access, data_access,
    telemetry, internet_egress — each value is the highest level or "none".
    """
    # Track max weight per category
    category_weights = {
        "model_access": ("none", 0.0),
        "key_vault_access": ("none", 0.0),
        "data_access": ("none", 0.0),
        "telemetry": ("none", 0.0),
        "internet_egress": ("none", 0.0),
    }

    weight_maps = {
        "model_access": MODEL_ACCESS_WEIGHTS,
        "key_vault_access": KEY_VAULT_WEIGHTS,
        "data_access": DATA_ACCESS_WEIGHTS,
        "telemetry": TELEMETRY_WEIGHTS,
        "internet_egress": INTERNET_EGRESS_WEIGHTS,
    }

    for ra in role_assignments:
        role_name = ra.get("role_name", "")
        scope = ra.get("scope", "")
        classified = classify_role_access(role_name, scope)

        for cat, level in classified.items():
            if level is not None:
                w = weight_maps[cat].get(level, 0.0)
                if w > category_weights[cat][1]:
                    category_weights[cat] = (level, w)

    return {cat: val[0] for cat, val in category_weights.items()}


def compute_ai_risk_dimensions(access_levels: dict[str, str]) -> dict[str, float]:
    """Compute per-dimension risk scores (0-10) from aggregated access levels.

    Returns dict with keys matching access_levels, values are 0-10 floats.
    """
    weight_maps = {
        "model_access": MODEL_ACCESS_WEIGHTS,
        "key_vault_access": KEY_VAULT_WEIGHTS,
        "data_access": DATA_ACCESS_WEIGHTS,
        "telemetry": TELEMETRY_WEIGHTS,
        "internet_egress": INTERNET_EGRESS_WEIGHTS,
    }
    return {
        cat: weight_maps[cat].get(access_levels.get(cat, "none"), 0.0)
        for cat in weight_maps
    }


def compute_ai_risk_score(dimensions: dict[str, float]) -> float:
    """Compute blended 0-100 AI risk score from dimension scores (0-10 each).

    Formula: (max(dims) * MAX_WEIGHT + mean(dims) * MEAN_WEIGHT) * SCALE
    Aligned with risk_engine.py CVSS v3.1 blend.
    """
    values = list(dimensions.values())
    if not values:
        return 0.0
    from statistics import mean
    blended = (max(values) * AI_RISK_MAX_WEIGHT) + (mean(values) * AI_RISK_MEAN_WEIGHT)
    return round(min(blended * AI_RISK_SCALE, 100.0), 2)
