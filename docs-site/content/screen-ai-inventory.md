# Screen Walkthrough — AI Inventory

**Route**: `/ai-inventory/agents` · **Section**: Identity Security · **Audience**: Security architects, AI platform owners, governance leads

## What this screen answers

> *"What AI is operating in my tenant right now, and which identities are doing it?"*

This is the discovery list — every service principal, managed identity, and human user that AuditGraph has classified as either running an AI workload or having privileged AI configuration access. Rows are sorted by risk; columns surface the dimensions that matter for triage.

## What you see on screen

### Top — KPI cards (filter affordances)

Five cards across the top, each clickable to filter the table below:

| Card | What it counts | Click action |
|---|---|---|
| **AI identities in tenant** | Non-human identities running AI workloads | Clears all filters |
| **Humans with AI access** | Humans who can configure or deploy AI models | Toggles the "AI-Privileged Humans" section open/closed |
| **Avg risk per identity** | Mean risk score across the visible cohort | Sorts table by risk DESC |
| **Can deploy/invoke models** | AI identities with model_deployment-scoped roles (e.g., Cognitive Services Contributor) | Filters to `?filter=model_access` |
| **Can reach secrets** | AI identities with Key Vault read or admin scope | Filters to `?filter=key_vault_access` |

Each card's subtitle is the *business-impact* statement, not the field name. CISO-friendly framing.

### Body — Section A: AI Agent Identities

The main table. Columns:

| Column | Source | Purpose |
|---|---|---|
| Identity | display name + identity_id | The agent |
| AI Service | `agent_classifications.detected_platform` | Which platform was detected (Azure OpenAI, Copilot Studio, Azure ML, etc.) |
| RBAC Roles | first 2 role names + `+N` overflow | What this agent can do at the cloud-resource layer |
| Model | model-deployment role badges | Can it deploy or invoke models? |
| Key Vault | KV role badges | Can it read or admin secrets? |
| Data | classified-data-reachability badges | What PHI/PCI/PII can it reach? |
| Telemetry | sign-in/audit telemetry coverage | Are logs flowing? |
| Egress | outbound network posture | Can it reach the public internet? |
| Risk | composite 0-100 score | Headline figure for triage |

The chip displayed under the count — **"subtype of NHI"** — is intentional. It signals that an AI agent is a non-human identity, not a separate category. This pre-empts the CISO question: *"Are these just service principals?"* Yes — and that's exactly the model AuditGraph uses.

### Body — Section B: AI-Privileged Humans (collapsed by default)

Humans with administrative access over AI systems — Azure AI Developer, Cognitive Services Contributor, Copilot Studio admin, etc. These aren't the AI agents themselves; they're the humans who configure them. Important for ownership and certification campaigns.

Section ships collapsed because most viewers want the agent list first; expanding reveals the human attack surface around the agents.

## How to read the risk score

The score is computed by the per-identity risk engine on every snapshot:

- **Critical (80-100)** — agent has overprivileged scope (Owner/Contributor at subscription) AND no owner AND reaches classified data
- **High (60-79)** — overprivileged OR reaches classified data with no oversight
- **Medium (40-59)** — moderate scope, owner present, telemetry partial
- **Low (0-39)** — least privilege, owner present, telemetry full

Risk is the legacy 0-100 score from the discovery pipeline. The **9-dimensional Trust Score** (see [Identity Trust](#screen-identity-trust)) is the newer headline metric — same agent, more nuanced view across 9 dimensions (Ownership · Secrets · Egress · Telemetry · Oversight · Data Access · Network · Model Exposure · Supply Chain).

## Common questions

**Q: Why is this in Identity Security and not AI Security?**
Because AI agents *are* non-human identities. The Identity Security section is where you go to triage identity-level risk. The AI Security section is for the AI *workload* layer (model registry, supply chain, threat connectors) — that's a different surface.

**Q: How did the platform decide this SPN is an AI agent?**
Click the row to open the drawer; the **Classification** card shows the detection method (pattern matching on display name, app-role catalog match against known AI app IDs, captured Azure OpenAI request emitter) and the confidence (0.0 – 1.0). Anything ≥ 0.85 is treated as a confirmed AI agent; lower confidence marks it as "possible_ai_agent" until confirmed.

**Q: A row is missing. Why?**
Three reasons:
1. The agent was created after the most recent discovery snapshot — wait for the next discovery cycle or click *Trigger Discovery* in Connectors.
2. The agent is `is_microsoft_system=true` (a built-in Microsoft service principal) and is hidden by default.
3. The agent is classified as `unknown` (confidence < 0.50). Adjust the filter to include possible_ai_agents.

**Q: Can I export this?**
Yes — click *Reports & Exports* in the sidebar. Choose CSV for the table view or PDF for the snapshot.

## What to do next (recommended flow)

1. Sort by risk DESC and review the top 5 agents — those are the immediate triage targets.
2. For each critical agent: click into the drawer, review *Trust Score* (9 dims), *Abuse Scenarios* (5 attack scenarios with $ exposure), and *Multi-Hop XGRAPH* (transitive reach).
3. Assign owners for the unowned agents via the [Ownership Center](#screen-ownership-center). 99% unowned is the typical starting state — closing this gap is the single highest-leverage move you can make.
4. Schedule a re-discovery to refresh the snapshot.

## Related screens

- [Identity Trust](#screen-identity-trust) — the 9-dim Trust Score breakdown
- [Multi-Hop XGRAPH](#screen-multi-hop-xgraph) — transitive agent-to-agent reach
- [AI Abuse Scenarios](#screen-ai-abuse-scenarios) — 5 named attack scenarios per agent
- [Ownership Center](#screen-ownership-center) — assign owners to unowned agents
