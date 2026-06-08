# Screen Walkthrough — Threat Connectors

**Route**: `/ai-runtime/threat-connectors` · **Section**: AI Security · **Audience**: Detection engineers, security architects, threat ops

## What this screen answers

> *"I have prompt injection / jailbreak / content-safety detection from a vendor — how do I get those signals into AuditGraph so they show up in posture and risk?"*

This screen is the integration point with partner detection systems. AuditGraph does NOT detect content abuse; partners do. This screen wires those partners in, normalizes their signals, and surfaces the events alongside AuditGraph's identity consequence data.

## What you see on screen

### Top — summary cards (4)

| Card | Counts |
|---|---|
| Total signals (rolling) | Sum across all wired connectors |
| Connectors enabled | How many partners are actively reporting |
| Critical (recent) | Severity = critical signals in current view |
| High (recent) | Severity = high |

### Body — connector grid (one card per partner)

Cards show:

- Partner name + vendor key
- Enabled / disabled state
- Total signals received (lifetime)
- Last signal timestamp

If a partner isn't yet wired, the card is dashed-bordered with an **Add connector** button.

### Filter bar

- Vendor: all · azure_content_filter · bedrock_guardrails · lakera_guard · openai_moderation · nemo_guardrails · custom
- Severity: all · critical · high · medium · low

### Signal feed table

Each row is one received signal:

| Column | Source |
|---|---|
| Severity | normalized from vendor (info/low/medium/high/critical) |
| Vendor | which partner sent it |
| Signal type | normalized type (prompt_injection / jailbreak / data_leakage / toxic_content / pii_in_output / etc.) |
| Title | vendor-friendly headline |
| Agent | which AI identity was affected (when identifiable) |
| Received | ingest timestamp |

Click a row to open the **Signal Detail** modal with the full evidence (vendor's raw filter response, request IDs, etc.).

## Supported partners (built-in adapters)

| Vendor | Adapter behavior |
|---|---|
| **azure_content_filter** | Parses Azure OpenAI content filter results — prompt_injection, jailbreak, hate, sexual, self-harm, indirect_attack |
| **bedrock_guardrails** | Parses AWS Bedrock Guardrails assessments — PROMPT_ATTACK, contentPolicy filters, sensitiveInformationPolicy |
| **lakera_guard** | Parses Lakera /v2/guard responses — prompt_injection, jailbreak, pii, unknown_links, moderated_content |
| **openai_moderation** | Parses OpenAI /v1/moderations response — hate, harassment, sexual, self-harm, violence |
| **nemo_guardrails** | Parses NVIDIA NeMo rail violations (input/output/dialog) |
| **custom** | Pass-through for customer-normalized signals |

Each adapter is a deterministic function from `vendor_payload → list[NormalizedSignal]`. New vendors are added by registering an adapter; no schema change.

## How a connector gets wired

### Step 1 — register the connector

Click an unregistered partner card → **Add connector** → confirm name. Optionally provide a webhook secret. Status flips to enabled.

When you provide a `webhook_secret`, it's stored in the database in a dedicated column (never in JSONB, never returned via GET). Used by AuditGraph to verify HMAC-SHA256 signatures on incoming webhooks (constant-time compare).

### Step 2 — point the partner's webhook at AuditGraph

```
POST https://app.auditgraph.ai/api/ai-security/threat-signals?vendor=<vendor_key>
X-AG-Signature: sha256=<HMAC-SHA256 of body using webhook_secret>
Content-Type: application/json

{<vendor-specific payload>}
```

The body is whatever the vendor normally sends. AuditGraph's adapter parses it.

### Step 3 — events start flowing

Signals appear in the feed table within seconds. Each signal's `identity_db_id` is auto-resolved by joining on `identity_id` string (the agent the vendor reported); if no match, the signal still ingests but with `identity_db_id = null`.

## Security controls on the ingest endpoint

- **Role gate**: only admin / security_admin can POST signals (prevents low-privilege users from fabricating events to manipulate risk scoring).
- **Payload cap**: 256 KB per request (prevents DoS).
- **Rate limit**: 120 signals/minute per (org, vendor). High enough for legitimate detection volume; low enough to catch flood attacks.
- **HMAC verification**: when a webhook_secret is configured, the X-AG-Signature header is required and verified with constant-time compare. Without a secret, the system soft-passes (allows bootstrap).
- **PII strip**: by default, the raw vendor payload (which may contain user prompts and AI completions) is stripped before storage. Only normalized signal metadata is retained. Customers can opt in to full-payload retention via the `threat_signals_retain_partner_payloads` setting (with documented compliance implications).
- **Idempotency**: vendor-provided `external_id` (e.g., Azure's `request_id`, Lakera's `flag_id`) is used to dedup. Same external_id + same vendor + same org = single row.

## How signals integrate with the rest of the platform

Once ingested, signals integrate at three places:

1. **AI Findings catalog** — new finding types like `ai_threat_prompt_injection` are created when signals exceed threshold. Triage in the unified Findings UI.
2. **Trust Score** — the Telemetry dimension can be upgraded from PARTIAL to FULL when active threat coverage is detected.
3. **Abuse Scenarios** — the per-agent Abuse Scenarios card surfaces recent partner signals as additional evidence (e.g., "Prompt Injection severity bumped to critical: 3 confirmed events from Azure Content Filter in last 24h").

## Common questions

**Q: Why doesn't AuditGraph detect prompt injection itself?**
Detection is partner territory — Lakera, Bedrock Guardrails, Azure Content Safety, OpenAI Moderation, NeMo Guardrails all do this well, focus their R&D there, and have low false-positive rates calibrated to their model output. AuditGraph's value is quantifying consequence, not duplicating detection.

**Q: What if I don't use any partner?**
You still get full identity consequence quantification (Multi-Hop XGRAPH, Abuse Scenarios, Findings). You miss the real-time detection layer — which means you find out about prompt injection through architecture posture changes, not through real-time alerts. Recommended to wire at least one partner.

**Q: Can I write my own connector?**
Yes — use `vendor=custom` and normalize on your end. The custom adapter accepts the standardized `NormalizedSignal` shape directly.

**Q: What's the retention period?**
Default is 90 days for signals (configurable via `threat_signals_retention_days`). Connector configurations are kept forever (small data).

## What to do next

1. Identify which partner(s) you already use (or want to evaluate).
2. Register the connector here.
3. Point the partner's webhook at the ingest endpoint with HMAC-signed deliveries.
4. Watch the signal feed populate.
5. Triage any high/critical signals via the AI Findings catalog.

## Related screens

- [AI Findings](#screen-ai-findings) — where ingested signals become triageable findings
- [AI Abuse Scenarios](#screen-ai-abuse-scenarios) — where signals augment consequence scoring
