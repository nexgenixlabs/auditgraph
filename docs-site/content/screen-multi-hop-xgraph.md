# Screen Walkthrough — Multi-Hop XGRAPH

**Route**: `/ai-attack-paths/multi-hop` · **Section**: Graph Intelligence · **Audience**: Security architects, red team, CISOs, threat modelers

## What this screen answers

> *"When a low-privilege agent invokes a higher-privilege agent, what's the transitive blast radius?"*

This is the patent-track screen. Prior-art systems compute single-hop blast radius (identity → resource). This screen computes **multi-hop transitive reach** — Agent A → Agent B → ... → Resource — and quantifies the dollar exposure of each chain. It's the difference between knowing "this agent reaches PHI" and knowing "this agent has *no direct access* but inherits PHI write through a 3-hop invocation chain."

## What you see on screen

### Top — KPI cards (4)

| Card | Meaning |
|---|---|
| **Chains discovered** | Total transitive chains found from the current cohort |
| **Critical chains** | Chains terminating in writeable PHI/PCI or with a weak link in the path |
| **High chains** | Chains terminating in read-only PHI/PCI or write of PII |
| **Deepest chain** | Longest path observed (in hops) |

These numbers update as you change the filters below.

### View toggle: Chains | Graph

Two views of the same data:

- **Chains** — flat list of all chains, severity-sorted, with per-chain dollar bands and weakest-link callouts.
- **Graph** — node-and-edge table view showing every agent and every invocation, indexed by degree (most-invoked agents float to top). Useful for understanding *who is the central hub* in your invocation graph.

### Filter chips

Three filter groups:

- **Class**: all · PHI · PCI · PII · FINANCIAL · HR — terminal data classification of the chain
- **Depth**: ≤2 · ≤3 · ≤4 · ≤5 — maximum hops to traverse

Combine these to ask focused questions: "Show me only chains reaching PHI within 3 hops" → click `PHI` + `≤3`.

### Chain list (the default view)

Each row is one transitive chain. Reading a row left-to-right:

1. **Severity dot + label** — critical / high / medium / low
2. **Depth** — number of edges
3. **Terminal classification** — PHI / PCI / PII / etc.
4. **WRITE** label — present if the terminal access is write-capable (escalates severity)
5. **⚠ weak link** — present if any edge in the chain has shared-secret authentication or inferred confidence
6. **Hop diagram** — e.g., `Gpt4 Inference SP ─H→ Openai Connector SP ─B→ demo-ai-copilot-prod ⇒ PHI`
7. **Dollar band** — mid value highlighted, low–high range, terminal record count

Click any row to open the *Inspect* detail modal.

### Chain detail modal (Inspect →)

When you click a chain, you see the full breakdown:

#### Invocation path
Hop-by-hop breakdown with per-edge details:
- Hop number (0 = source, last = terminal)
- Identity display name
- Edge mechanism (`mcp`, `http`, `service_bus`, `shared_secret`, etc.)
- Invocation name (e.g., `callContactDB`, `forwardInference`)
- Confidence: `observed` (green), `declared` (blue), `inferred` (amber)
- Observation count (how many times this edge was seen in telemetry)

#### Weakest link (if present)
Explanation of why this chain's severity was bumped. Example:

> "Hop 0 uses `shared_secret` (inferred). Shared-secret authentication makes the invocation easy to impersonate. Severity bumped from high → critical."

#### Estimated exposure
Mid-band as the headline, low-high range below, source attribution. Click **ⓘ Methodology** for the full breach-cost derivation (see [Breach Cost Methodology](#breach-cost-methodology)).

#### MITRE ATT&CK
List of technique IDs derived from the mechanisms in the chain. Each mechanism contributes one or more techniques (e.g., `mcp` → T1199 Trusted Relationship; `shared_secret` → T1078.004 Cloud Accounts + T1552 Unsecured Credentials). The terminal classification adds T1530 Data from Cloud Storage. Write capability adds T1565 Data Manipulation.

## How chains are computed

The traversal is a bounded breadth-first search (BFS) from each source agent up to `max_depth` hops. At each visited node, the engine checks if that node has any classified-data reach — if yes, a chain is emitted. The BFS includes:

- **Cycle elimination**: each path maintains its own visited set; no node appears twice in the same chain.
- **Per-(source, target, depth) deduplication**: the same source-to-target chain isn't emitted twice via different paths.
- **Depth-zero suppression**: depth-0 chains (source agent itself reaching data) are NOT emitted — those are single-hop, already covered by prior art. This screen is specifically about depth ≥ 1.

Edges come from one of five sources:

1. **MCP traces** — Model Context Protocol tool-call telemetry
2. **Azure OpenAI logs** — request logs that show agent-to-agent forwarding
3. **AWS Bedrock CloudTrail** — InvokeAgent events
4. **Customer-declared service maps** — YAML/JSON of known dependencies
5. **Inferred shared-credential edges** — two identities sharing a certificate or federated credential

Each edge carries a confidence: `observed` (direct telemetry), `declared` (customer-stated), or `inferred` (heuristic). The confidence affects severity (see below).

## Severity scoring

Two stages.

**Stage 1 — base severity** from the matrix indexed by (terminal classification, write flag):

| Class | write | severity |
|---|---|---|
| PHI / PCI | yes | critical |
| PHI / PCI | no | high |
| PII / FINANCIAL | yes | high |
| PII / FINANCIAL | no | medium |
| HR / SOURCE / CONFIDENTIAL | yes | medium |
| HR / SOURCE / CONFIDENTIAL | no | low |

**Stage 2 — weakest-link bump.** Examine each edge in the chain. If ANY edge has `mechanism = shared_secret` OR `confidence = inferred`, bump severity by one tier (saturating at critical). Tag the chain with `weakest_link` pointing at the first qualifying edge.

The bump is applied at most once per chain (no double-counting). The rationale: a chain is only as strong as its weakest edge. A shared-secret edge in any position means an attacker can pivot through that point cheaply.

## The three-hop demo example

Default demo data includes this chain (the patent-priority example):

```
Gpt4 Inference Service Sp ─http→ Openai Prod Connector Sp ─service_bus→ demo-ai-copilot-prod
   ⇒ write 120,000 PHI records
```

- Base severity: critical (PHI + write)
- Weakest link: none (all edges observed, no shared_secret)
- Final severity: critical
- Dollar band: $48.96M low – **$56.52M mid** – $64.20M high
- MITRE: T1199, T1530, T1565, T1648

Why this matters: `Gpt4 Inference Service Sp` has **no direct PHI access**. A naive single-hop blast radius would conclude "this agent has no risk to patient data." This screen reveals the truth — it has $56.52M of transitive PHI exposure via two hops it didn't authorize for itself.

## Common questions

**Q: How does the platform capture invocation edges?**
The agent_invocations table accepts edges from five sources (above). Customers wire whichever sources they have telemetry for. The demo uses captured MCP traces + declared edges; in production, MCP and Azure OpenAI logs are the most common.

**Q: I see "no chains." What's wrong?**
Two reasons. First, you may have classified data reachability but no observed agent-to-agent edges yet — wire up MCP tracing or declare known dependencies. Second, you may have edges but no terminal data reach — confirm `agent_data_reachability` is populated by the discovery pipeline.

**Q: Can chains span clouds?**
Yes. The schema is cloud-agnostic. An Azure managed identity that has been granted a role via AWS STS produces an inter-cloud edge.

**Q: How does this differ from regular Attack Paths?**
Attack Paths covers the *general* human + NHI attack graph (BloodHound territory). This screen is specifically the *autonomous-agent invocation graph* — Agent A → Agent B chains via MCP / HTTP / event-bus. Different evidence sources, different threat model, different remediation.

## What to do next

1. Sort by severity DESC. Focus on critical chains first.
2. For each chain with a weakest link, fix the weak edge — eliminate the shared secret (rotate to per-identity credentials) or confirm the inferred edge (turn it into observed via telemetry).
3. For each critical write-chain, harden the terminal agent — scope reduction on the high-privilege agent at the end.
4. Re-run after fixes; chain count should drop.

## Related screens

- [AI Abuse Scenarios](#screen-ai-abuse-scenarios) — same data presented as named scenarios
- [Data Reachability](#screen-data-reachability) — what classified data each agent reaches directly
- [AI Inventory](#screen-ai-inventory) — drill into specific agents
- [Breach Cost Methodology](#breach-cost-methodology) — where the $ comes from
