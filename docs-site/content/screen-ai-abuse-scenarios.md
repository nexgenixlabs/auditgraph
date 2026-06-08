# Screen Walkthrough — AI Abuse Scenarios

**Route**: `/ai-risk` · **Section**: AI Security · **Audience**: Security architects, threat modelers, CISOs

## What this screen answers

> *"If an attacker successfully attacked my AI agents, what specifically would they reach?"*

AuditGraph does NOT detect prompt injection, jailbreaks, or toxic content — that's vendor territory (Lakera, Bedrock Guardrails, Azure Content Safety, OpenAI Moderation). AuditGraph quantifies the **consequence** of those attacks succeeding. This screen lists five named attack scenarios, evaluates each AI agent against each scenario, and produces severity + dollar exposure per (agent × scenario).

The framing is deliberate: **detection is partner territory; impact quantification is our territory**.

## What you see on screen

### Top — summary strip (4 cards)

| Card | Counts |
|---|---|
| Exploitable Agents | of N total, how many have ≥1 active scenario |
| Critical Scenarios | total agent-scenario combinations at severity = critical |
| High Scenarios | severity = high |
| Total Estimated Exposure | sum of dollar bands across all hit scenarios (with MAX dedup per class) |

### Body — five scenario panels

Each panel covers one scenario:

#### 1. Prompt Injection Compromise

> An attacker injects malicious instructions into the agent's prompt context (via a poisoned document, a public web surface scraped by the agent, or an upstream user input). The agent obediently executes the attacker's chosen tool calls.

| Field | Source |
|---|---|
| Threat source | Prompt injection (detected by partners — Lakera, Bedrock Guardrails) |
| MITRE | T1213 (Data from Information Repositories), T1552 (Unsecured Credentials), T1530 (Data from Cloud Storage) |
| Severity logic | Based on what the agent can reach. PHI write reach → critical. PII read → medium. |
| Worst agents (top 5) | Agents with the worst severity for this scenario |
| Dollar exposure | Per-agent breach exposure if compromised this way |

#### 2. Service Principal Credential Theft

> An attacker steals one of the agent's authentication credentials (client secret, certificate, federated token). They authenticate as the agent and act with its privileges.

| Field | Source |
|---|---|
| Threat source | Credential theft (no specific detector — covered by NHI security generally) |
| MITRE | T1552.004 (Private Keys), T1078.004 (Cloud Accounts) |
| Severity logic | Depends on auth surfaces. No discoverable secret = low (good). Multiple secrets / federated = high. |
| Worst agents | Agents with the most exposable auth |

#### 3. Owner Departure / Orphaning

> The human owner of the agent leaves the company or rotates roles. Without backup ownership, the agent becomes orphaned — no one reviews privilege drift, no one accepts risk.

| Field | Source |
|---|---|
| Threat source | Operational — not an attack per se, but the precondition for many attacks |
| MITRE | T1098 (Account Manipulation) |
| Severity logic | Unowned agent = medium baseline. Combined with classified data reach = high. |
| Recommendation | Assign owner via the Ownership Center |

#### 4. Tool Abuse

> An attacker subverts a tool that the agent invokes (e.g., a webbrowser tool that follows an attacker-controlled link, or a code-execution tool that runs attacker-supplied code).

| Field | Source |
|---|---|
| Threat source | Tool exploitation — varies by tool type |
| MITRE | T1199 (Trusted Relationship) |
| Severity logic | Based on the tools the agent has configured and their scope |
| Worst agents | Agents with the most unbounded tools (e.g., webbrowser allowing `*`) |

#### 5. Supply Chain Compromise

> An attacker compromises a component the agent depends on — a fine-tuned model checkpoint, an npm-installed plugin, an external API the agent calls.

| Field | Source |
|---|---|
| Threat source | Supply chain attack (see [AI Supply Chain](#screen-ai-supply-chain)) |
| MITRE | T1199, T1078.004, T1552.004 |
| Severity logic | Based on the agent's supply-chain dependency tree |
| Worst agents | Agents with the most unverified/community plugins or fine-tuned models |

### Per-panel — "Worst Agents" table

Each scenario panel shows the top 5 agents at the worst severity for that scenario. Each row:

- Agent display name + identity_id
- Severity dot + label
- One-line headline ("Owner: Sarah Chen · agent activity last seen 1d ago")
- Dollar mid display

Click any row to open the agent's drawer with all 5 scenarios populated.

### Per-panel — count by severity

The thin bar at the bottom of each panel: `critical: N · high: N · medium: N · low: N`. Tells you how widely this scenario applies.

## How severity is determined

Each scenario has its own severity function. The functions are deterministic and use the same architecture signals available elsewhere on the platform. Pseudocode:

```python
def evaluate_prompt_injection(agent):
    if agent.reaches_phi_write:    return 'critical'
    if agent.reaches_phi_read:     return 'high'
    if agent.reaches_pii_anywhere: return 'medium'
    return 'low'

def evaluate_credential_theft(agent):
    if not agent.has_any_auth_surface:  return 'low'  # honest empty state
    if agent.has_federated_credentials: return 'high'
    return 'medium'
```

The full logic lives in `backend/app/engines/ai/abuse_scenarios.py`. Operators can extend the catalog by adding scenarios to the `SCENARIOS` list and providing a severity function.

## Why we explicitly do NOT detect content

This is intentional positioning. AuditGraph stays in the **identity consequence layer**. Content detection (prompt injection, jailbreak, toxic, hallucination) is partner territory:

| Partner | What they detect |
|---|---|
| Lakera Guard | Prompt injection, jailbreak, PII in output |
| AWS Bedrock Guardrails | Prompt attack, content policy violations |
| Azure OpenAI Content Filters | Hate, violence, sexual, self-harm, prompt injection |
| OpenAI Moderation API | Hate, harassment, sexual, self-harm, violence |
| NVIDIA NeMo Guardrails | Input/output/dialog rail violations |

These partners ingest their signals into AuditGraph via the [Threat Connectors](#screen-threat-connectors) screen. AuditGraph then **quantifies the consequence** of any signal — "this prompt-injection event reached an agent that has $56.52M of PHI exposure" — which is the consequence framing CISOs use to prioritize.

## Common questions

**Q: How does this differ from Multi-Hop XGRAPH?**
Same underlying data (agent reachability), different organizing principle. Multi-Hop is *chains* (Agent A → Agent B → ...). Abuse Scenarios is *threats* (one of 5 named attacks). A given agent may appear in both surfaces.

**Q: Where do the $ numbers come from?**
Same breach-cost factor table as everything else. See [Breach Cost Methodology](#breach-cost-methodology) for the full derivation.

**Q: Why are there exactly 5 scenarios?**
Five was the result of trying to maximize coverage while keeping the list memorable for boards. Each scenario maps to a distinct threat-source category (content, credential, ownership, tool, supply-chain) and a distinct remediation playbook.

**Q: Can I add a 6th scenario?**
Yes — append to the `SCENARIOS` list in `abuse_scenarios.py` and provide a severity function. The UI auto-renders new scenarios.

## What to do next

1. Read the top-line counts. If you have any critical scenario hits, those are immediate triage.
2. Pick a scenario and review the worst-5 agents for that scenario. Fix the conditions that drive the severity — e.g., for credential theft hits, rotate to federated identity; for ownership hits, assign owners.
3. After remediation, re-run discovery — the scenarios re-evaluate automatically.
4. Wire up at least one threat connector (Azure Content Filter or Bedrock Guardrails) to start receiving real-time signals. Open [Threat Connectors](#screen-threat-connectors).

## Related screens

- [Multi-Hop XGRAPH](#screen-multi-hop-xgraph) — same data, chain-organized
- [Threat Connectors](#screen-threat-connectors) — wire up partner detection signals
- [AI Findings](#screen-ai-findings) — unified detector catalog of these and other issues
- [Breach Cost Methodology](#breach-cost-methodology) — $ source
