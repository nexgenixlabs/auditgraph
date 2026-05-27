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
