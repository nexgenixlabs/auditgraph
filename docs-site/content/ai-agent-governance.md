# AI Agent Governance

## Overview

AI Agent Governance is AuditGraph's purpose-built module for discovering, classifying, and securing AI agent service principals (SPNs) across your cloud environment. As organizations deploy AI agents — chatbots, automation workflows, autonomous code generators — the number of non-human identities with elevated permissions grows rapidly. AuditGraph provides continuous visibility into these identities and detects orphaned agents that pose a lateral movement risk.

```
┌─────────────────────────────────────────────────────────────────────┐
│                   AI Agent Governance Pipeline                       │
│                                                                     │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────┐ │
│  │ Discovery │──▶│ Classifier   │──▶│ SP Sign-In   │──▶│ Orphan  │ │
│  │ (Graph    │   │ (Pattern     │   │ Enrichment   │   │Detector │ │
│  │  API)     │   │  Library)    │   │ (Graph API)  │   │(IASM-AG)│ │
│  └──────────┘   └──────────────┘   └──────────────┘   └─────────┘ │
│       │                │                   │                │      │
│       ▼                ▼                   ▼                ▼      │
│  identities    agent_classifi-    last_service_     security_      │
│  table         cations table      principal_        findings       │
│                                   sign_in           (IASM-AG-001) │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Why AI Agent SPNs Are Different

Traditional identity governance focuses on human users and well-known service accounts. AI agent SPNs introduce unique challenges:

| Challenge | Description |
|-----------|-------------|
| **Rapid proliferation** | Teams spin up agent SPNs for experiments and proofs-of-concept, then forget to decommission them |
| **Elevated permissions** | AI agents often require Owner/Contributor roles to provision resources autonomously |
| **Client credential auth** | Agents authenticate via client credentials (client ID + secret/certificate), not interactive login |
| **Invisible activity** | Client credential sign-ins appear in `servicePrincipalSignIns`, NOT in the standard `lastSignInDateTime` field |
| **No human owner** | Agents may outlive the team that created them, becoming orphaned with standing access |
| **Framework diversity** | Agents built on Copilot Studio, Azure OpenAI, LangChain, Semantic Kernel, AutoGen, and custom frameworks each register SPNs differently |

> **Important:** Standard dormancy detection that relies solely on `lastSignInDateTime` will produce **false positives** for AI agents that authenticate exclusively via client credentials. AuditGraph solves this with dual sign-in source detection.

---

## Agent Classification Engine

### How It Works

The classification engine runs during each discovery cycle and examines every service principal to determine if it is an AI agent. Classification uses a pattern library that matches against multiple identity attributes.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Classification Decision Tree                      │
│                                                                     │
│  Service Principal                                                  │
│       │                                                             │
│       ├── Display name matches known patterns?                      │
│       │   (e.g., "Copilot*", "*-openai-*", "*AutoGen*")           │
│       │                                                             │
│       ├── App ID matches known AI platform registrations?           │
│       │   (e.g., Copilot Studio well-known app IDs)                │
│       │                                                             │
│       ├── API permissions include AI service scopes?                │
│       │   (e.g., CognitiveServices.*, OpenAI.*)                    │
│       │                                                             │
│       └── Metadata matches framework signatures?                    │
│           (e.g., LangChain user-agent, SK telemetry tags)          │
│                                                                     │
│  Result: ai_agent | possible_ai_agent | unknown                     │
│  + confidence score (0.0 - 1.0)                                    │
│  + detected platform (copilot_studio, azure_openai, langchain...)  │
└─────────────────────────────────────────────────────────────────────┘
```

### Classification Types

| Type | Description | Confidence |
|------|-------------|------------|
| `ai_agent` | Definitively identified as an AI agent SPN | 0.80 - 1.00 |
| `possible_ai_agent` | Likely an AI agent but not confirmed (heuristic match) | 0.40 - 0.79 |
| `unknown` | Not classified as an AI agent | 0.00 - 0.39 |

### Detected Platforms

The pattern library currently identifies agents from the following platforms:

| Platform | Detection Method |
|----------|-----------------|
| **Copilot Studio** | Well-known app IDs, display name patterns |
| **Azure OpenAI** | API permission scopes, resource naming |
| **Power Automate** | Flow-specific SPN patterns, app ID registry |
| **LangChain** | Display name patterns, permission signatures |
| **Semantic Kernel** | SDK telemetry markers, naming conventions |
| **AutoGen** | Framework-specific SPN naming patterns |
| **Custom** | Generic AI/ML permission patterns |

### Pattern Library

Classification patterns are defined in a versioned JSON configuration that can be reloaded at runtime without restarting the service. Each pattern specifies:

```json
{
  "pattern_id": "copilot_studio_v1",
  "match_type": "display_name",
  "regex": "(?i)(copilot|bot-framework|power-virtual)",
  "platform": "copilot_studio",
  "confidence": 0.95,
  "exclusions": ["copilot-docs-reader"]
}
```

> **Tip:** Administrators can trigger a reclassification of all SPNs via `POST /api/agent-identities/reclassify` or reload the pattern library via `POST /api/agent-patterns/reload` without waiting for the next discovery cycle.

---

## Orphan Detection (IASM-AG-001)

### Finding Definition

The **IASM-AG-001** finding identifies orphaned AI agent SPNs — decommissioned agents whose service principals remain active with elevated permissions.

| Property | Value |
|----------|-------|
| **Finding Code** | IASM-AG-001 |
| **Finding Type** | `orphaned_ai_agent_spn` |
| **Severity** | Critical |
| **Risk Score** | 90 |
| **AGIRS Penalty** | +15 points |
| **Category** | AI Agent Governance |

### Orphan Criteria

An identity is flagged as orphaned when **ALL five** criteria are met:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Orphan Criteria                               │
│                  (ALL must be TRUE to flag)                          │
│                                                                     │
│  1. ✓ Classified as ai_agent or possible_ai_agent                  │
│                                                                     │
│  2. ✓ Inactive for > 30 days (effective last activity)             │
│       OR never signed in via any method                             │
│                                                                     │
│  3. ✓ Still enabled (not disabled in Entra ID)                     │
│                                                                     │
│  4. ✓ Not soft-deleted                                             │
│                                                                     │
│  5. ✓ Holds at least one elevated RBAC role:                       │
│       • Owner                                                       │
│       • Contributor                                                 │
│       • User Access Administrator                                   │
│       • Any custom role with write/modify/delete/manage/admin/      │
│         operator in the name                                        │
└─────────────────────────────────────────────────────────────────────┘
```

> **Note:** The 30-day threshold is defined by the `ORPHAN_INACTIVE_DAYS` constant. Identities inactive for exactly 30 days are NOT flagged — only those exceeding 30 days.

### Auto-Resolution

Open IASM-AG-001 findings are automatically resolved when any of the following conditions are detected during the next discovery cycle:

- The identity has been **deleted** from Entra ID
- The identity has been **disabled**
- The identity has been **reclassified** (no longer an AI agent)
- The identity shows **recent activity** within the 30-day window (via either interactive or service principal sign-in)

---

## Dual Sign-In Source Detection

### The Problem

Azure AD tracks two distinct types of sign-in events in separate data stores:

```
┌─────────────────────────────────────┐    ┌────────────────────────────────┐
│   Interactive / Delegated Logins     │    │  Client Credential Logins      │
│                                     │    │                                │
│  • Human user signs in via browser  │    │  • SPN authenticates via       │
│  • OAuth2 authorization code flow   │    │    client_id + secret/cert     │
│  • Delegated permission flows       │    │  • OAuth2 client credentials   │
│  • Populates:                       │    │    grant flow                  │
│    lastSignInDateTime               │    │  • Machine-to-machine auth     │
│                                     │    │  • Populates:                  │
│  Source: signIns (interactive)      │    │    servicePrincipalSignIns     │
└─────────────────────────────────────┘    └────────────────────────────────┘
```

An AI agent running nightly batch jobs via client credentials will have:

- `lastSignInDateTime` = **NULL** (never performed an interactive login)
- `servicePrincipalSignIns` = **yesterday** (actively authenticating every night)

Without checking both sources, this active agent appears dormant and gets flagged as orphaned — a **false positive** that triggers a critical alert.

### The Solution

AuditGraph computes an **effective last activity** timestamp by taking the most recent sign-in from either source:

```python
# Dual sign-in source logic
interactive_sign_in = identity.last_sign_in           # from lastSignInDateTime
sp_sign_in = classification.last_service_principal_sign_in  # from servicePrincipalSignIns

candidates = [t for t in [interactive_sign_in, sp_sign_in] if t is not None]
effective_last_active = max(candidates) if candidates else None

days_inactive = (now - effective_last_active).days if effective_last_active else 999
```

| Scenario | Interactive Sign-In | SP Sign-In | Effective Last Active | Result |
|----------|-------------------|------------|----------------------|--------|
| Active agent (client creds only) | NULL | 2 days ago | 2 days ago | **Not orphaned** |
| Active agent (interactive only) | 5 days ago | NULL | 5 days ago | **Not orphaned** |
| Active agent (both recent) | 10 days ago | 2 days ago | 2 days ago | **Not orphaned** |
| Dormant agent (both old) | 60 days ago | 40 days ago | 40 days ago | **Orphaned** (40 > 30) |
| Never signed in | NULL | NULL | None | **Orphaned** (999 days) |
| Graph API unavailable | 45 days ago | (error) | 45 days ago | **Orphaned** (graceful degradation) |

### Activity Detection Source

Every finding and API response includes an `activity_detection_source` field that explains which sign-in source determined the dormancy status:

| Source | Meaning |
|--------|---------|
| `service_principal_sign_in` | Most recent activity came from client credential authentication |
| `interactive_sign_in` | Most recent activity came from interactive/delegated login |
| `no_activity_recorded` | No sign-in data available from either source |

---

## Service Principal Sign-In Enrichment

### Pipeline Architecture

The enrichment step runs during the nightly discovery pipeline, **after** agent classification and **before** orphan detection. This ensures the orphan detector has the most current activity data.

```
Discovery Pipeline (per-tenant)
─────────────────────────────────────────────
  ... (identity discovery, risk scoring) ...
       │
       ▼
  agent_classification         ← Classify SPNs as ai_agent / unknown
       │
       ▼
  agent_sp_signin_enrichment   ← Fetch SP sign-in data from Graph API
       │
       ▼
  agent_orphan_detection       ← Detect orphans using effective last active
       │
       ▼
  ... (policy recommendations, remediation) ...
```

### Microsoft Graph API Call

For each classified AI agent SPN, the enrichment step queries the Microsoft Graph audit logs:

```
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
  ?$filter=servicePrincipalId eq '{object_id}'
           and signInEventTypes/any(t: t eq 'servicePrincipal')
  &$orderby=createdDateTime desc
  &$top=1
  &$select=createdDateTime,servicePrincipalId,status
```

> **Note:** This endpoint requires the `AuditLog.Read.All` Microsoft Graph API permission. If this permission is not granted, the enrichment step degrades gracefully — orphan detection falls back to using only `lastSignInDateTime`.

### Rate Limiting and Batch Processing

| Parameter | Value | Configurable |
|-----------|-------|-------------|
| **Batch size** | 50 SPNs per run | `AGENT_ENRICH_BATCH_SIZE` env var |
| **Inter-call delay** | 100ms between Graph API calls | Hardcoded |
| **429 retry** | Exponential backoff, max 3 retries | Hardcoded |
| **Prioritization** | Oldest-enriched SPNs processed first | Automatic |

For organizations with more than 50 AI agent SPNs, the enrichment processes the oldest-enriched identities first, ensuring all agents are eventually enriched across multiple discovery cycles.

### Graceful Degradation

The enrichment step is designed as an **optional enrichment** — it must never block the discovery pipeline:

| Failure Mode | Behavior |
|-------------|----------|
| **403 Forbidden** | Log warning, skip SPN, continue. `AuditLog.Read.All` may not be granted. |
| **404 Not Found** | Return None. SPN has never authenticated via client credentials. |
| **429 Rate Limited** | Retry with backoff (up to 3 attempts). If exhausted, skip SPN. |
| **Network error** | Log error, skip SPN, continue loop. |
| **No Azure connection** | Skip entire enrichment step. Log info message. |
| **Incomplete credentials** | Skip entire enrichment step. Log info message. |

> **Warning:** If the Graph API is completely unavailable, the orphan detector will still function using only `lastSignInDateTime`. This means agents that authenticate exclusively via client credentials may be flagged as orphaned until the enrichment step succeeds on the next cycle. This is a safe default — it is better to over-report (false positive) than to miss a genuinely orphaned agent (false negative).

---

## Data Model

### agent_classifications Table

The `agent_classifications` table stores the classification result for each service principal.

| Column | Type | Description |
|--------|------|-------------|
| `id` | BIGSERIAL | Primary key |
| `identity_db_id` | BIGINT | FK to `identities.id` (CASCADE delete) |
| `identity_id` | TEXT | Azure object ID of the identity |
| `agent_identity_type` | TEXT | `ai_agent`, `possible_ai_agent`, or `unknown` |
| `classification_confidence` | REAL | Confidence score (0.0 - 1.0) |
| `classification_reason` | TEXT | Human-readable explanation of why the classification was assigned |
| `detected_platform` | TEXT | `copilot_studio`, `azure_openai`, `langchain`, `power_automate`, etc. |
| `pattern_version` | TEXT | Version of the pattern library used |
| `last_service_principal_sign_in` | TIMESTAMPTZ | Most recent client credential sign-in (from Graph API enrichment) |
| `agent_penalty_score` | INTEGER | AGIRS penalty applied for orphaned findings (default 0) |
| `agent_penalty_reason` | TEXT | Explanation of the penalty |
| `discovery_run_id` | BIGINT | FK to `discovery_runs.id` |
| `organization_id` | INTEGER | Tenant scoping (RLS enforced) |
| `created_at` | TIMESTAMPTZ | Record creation timestamp |
| `updated_at` | TIMESTAMPTZ | Last modification timestamp |

**Unique constraint:** `(identity_db_id, discovery_run_id)` — one classification per identity per run.

### IASM-AG-001 Finding Payload

When an orphaned agent is detected, the finding's `metadata` JSON contains:

```json
{
  "finding_code": "IASM-AG-001",
  "display_name": "nightly-etl-bot",
  "detected_platform": "azure_openai",
  "days_inactive": 45,
  "rbac_roles": ["Owner", "Contributor"],
  "agirs_penalty": 15,
  "category": "AI Agent Governance",
  "recommended_action": "disable_spn",
  "activity_detection_source": "service_principal_sign_in",
  "last_interactive_sign_in": null,
  "last_service_principal_sign_in": "2025-12-15T03:22:00+00:00",
  "effective_last_active": "2025-12-15T03:22:00+00:00"
}
```

---

## API Reference

### List AI Agent Identities

```
GET /api/agent-identities
```

Returns paginated list of identities classified as AI agents, with classification metadata and activity detection fields.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `per_page` | int | 25 | Items per page (max 100) |
| `sort_by` | string | `agirs_score` | Sort field: `agirs_score`, `last_active`, `display_name` |
| `sort_dir` | string | `desc` | Sort direction: `asc` or `desc` |
| `platform` | string | `all` | Filter by platform: `copilot_studio`, `azure_openai`, `langchain`, `power_automate`, `all` |
| `include_possible` | bool | `false` | Include `possible_ai_agent` in results |

**Response fields (per item):**

| Field | Type | Description |
|-------|------|-------------|
| `identity_id` | string | Azure object ID |
| `display_name` | string | Display name |
| `agent_identity_type` | string | `ai_agent` or `possible_ai_agent` |
| `detected_platform` | string | Detected AI platform |
| `classification_confidence` | float | Confidence score (0.0 - 1.0) |
| `risk_score` | int | Base risk score |
| `risk_score_display` | int | Risk score + AGIRS penalty |
| `agent_penalty_score` | int | AGIRS penalty (0 or 15) |
| `last_sign_in` | ISO date | Interactive sign-in timestamp |
| `last_service_principal_sign_in` | ISO date | Client credential sign-in timestamp |
| `last_interactive_sign_in` | ISO date | Same as `last_sign_in` (explicit alias) |
| `effective_last_active` | ISO date | Most recent of interactive or SP sign-in |
| `activity_detection_source` | string | `service_principal_sign_in`, `interactive_sign_in`, or `no_activity_recorded` |

### Get Agent Identity Count

```
GET /api/agent-identities/count
```

Returns lightweight counts without full identity data. Used for filter badges.

**Response:**

```json
{
  "ai_agent": 12,
  "possible_ai_agent": 5
}
```

### Reclassify Agent Identities

```
POST /api/agent-identities/reclassify
```

**Admin only.** Triggers re-classification of all SPNs using the latest pattern library. Does not wait for the next discovery cycle.

### Reload Pattern Library

```
POST /api/agent-patterns/reload
```

**Admin only.** Reloads the classification pattern library from disk without restarting the service. Useful after updating pattern definitions.

---

## Configuration

### Feature Flag

AI Agent Governance is controlled by the `FEATURE_AI_AGENT_GOVERNANCE` feature flag in `app/config.py`. When disabled, all agent governance endpoints return 404 and the pipeline steps are skipped.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FEATURE_AI_AGENT_GOVERNANCE` | `true` | Enable/disable the entire module |
| `AGENT_ENRICH_BATCH_SIZE` | `50` | Max SPNs to enrich per discovery cycle |

### Required Microsoft Graph Permissions

| Permission | Required For |
|-----------|--------------|
| `Application.Read.All` | Discover service principals and app registrations |
| `AuditLog.Read.All` | Read interactive sign-in logs AND service principal sign-in logs |

> **Important:** If `AuditLog.Read.All` is not granted, the enrichment step will return a 403 and degrade gracefully. However, this means client-credential-only agents will appear dormant. For accurate AI agent governance, ensure this permission is granted to the AuditGraph app registration.

---

## AGIRS Impact

When an IASM-AG-001 finding is active, a **+15 point penalty** is applied to the organization's AGIRS score via the Non-Human Identity Risk Index (NHIRI). The penalty is:

- **Applied** when an orphaned agent finding is created
- **Cleared** when the finding is auto-resolved (agent becomes active, disabled, deleted, or reclassified)
- **Visible** in the `risk_score_display` field on the agent identities API response

```
NHIRI impact:
  Base NHIRI score:  78.0
  AGIRS penalty:    -15.0  (one orphaned agent)
  Adjusted NHIRI:    63.0

  If 3 orphaned agents: -45.0 penalty
  Adjusted NHIRI:    33.0  (critical territory)
```

---

## Remediation Playbook

When an IASM-AG-001 finding is detected, the recommended remediation steps are:

1. **Identify the owning team** — Check the SPN's owner field and app registration metadata
2. **Verify decommission status** — Confirm with the team whether the agent is still in use
3. **Check client credential activity** — Review the `activity_detection_source` field to understand how the agent was last active
4. **Disable the SPN** — If confirmed decommissioned, disable the service principal in Entra ID
5. **Remove elevated roles** — Strip Owner/Contributor/UAA role assignments
6. **Delete if appropriate** — If the agent is permanently retired, delete the SPN and app registration
7. **Document** — Record the decommission in your change management system

> **Tip:** The `effective_last_active` and `activity_detection_source` fields in the finding payload help auditors distinguish between truly orphaned agents and agents that are active but only via client credentials.

---

## Glossary

| Term | Definition |
|------|-----------|
| **AI Agent SPN** | A service principal registered in Entra ID that represents an AI agent (chatbot, automation workflow, autonomous code tool) |
| **Client Credentials** | Authentication using client ID + client secret or certificate, without a human user present |
| **Interactive Sign-In** | Authentication involving a human user (browser login, delegated OAuth flow) |
| **Service Principal Sign-In** | Authentication via client credential grant flow, logged separately from interactive sign-ins |
| **Effective Last Active** | The more recent of `lastSignInDateTime` and `lastServicePrincipalSignIn` |
| **Orphaned Agent** | An AI agent SPN that is inactive, still enabled, and holds elevated permissions |
| **IASM-AG-001** | Finding code for orphaned AI agent SPNs |
| **Pattern Library** | Versioned JSON configuration defining how to classify SPNs as AI agents |
| **Graceful Degradation** | When the Graph API is unavailable, orphan detection falls back to using only interactive sign-in data |
