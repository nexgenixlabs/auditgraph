# Screen Walkthrough — AI Supply Chain

**Route**: `/ai-runtime/supply-chain` · **Section**: AI Security · **Audience**: AI platform owners, security architects, supply chain risk leads

## What this screen answers

> *"What models, plugins, vector databases, and external APIs does each of my AI agents depend on — and which of those dependencies are risky?"*

This is the supply chain map for AI. For each AI agent, AuditGraph traces upstream to discover its full dependency tree: model → plugin → vector DB → external API → tool. Each component gets a risk score based on a flag catalog (fine-tuned, unverified-vendor, public-endpoint, etc.). The aggregate per-agent supply chain risk surfaces which agents have the most fragile dependency chains.

## What you see on screen

### Top — summary strip (5 cards by component kind)

Each card is one component kind:

| Kind | What it covers |
|---|---|
| Model | OpenAI / Anthropic / custom models, including fine-tunes |
| Plugin | LangChain / LlamaIndex modules, MCP servers, custom plugins |
| Vector DB | Pinecone / pgvector / Qdrant / Azure Cosmos vector / etc. |
| External API | Salesforce / HuggingFace / customer APIs the agent calls |
| Tool | Browser, code-exec, file-IO, etc. tools the agent has been given |

Each card shows: total count · critical count · high count. Quick visual of where the systemic risk is concentrated.

### Body — left column: agent picker

List of all AI agents that have any supply chain components. Each row shows aggregate risk (0-100) and severity band. Click an agent to load its tree on the right.

### Body — right column: dependency tree

Shows the selected agent's full supply chain:

#### Aggregate risk card (top-right)
The agent's overall supply-chain risk score with severity band.

#### Top risk contributors
Top 3 risk flags driving the aggregate score, with their contribution weights. Example:

> **unbounded_scope** +50 · **mutable_dependency** +40 · **community_plugin** +30

This tells you "the reason this agent's supply chain is risky is mostly that one of its tools has unbounded scope."

#### Component groups (Model / Plugin / Vector DB / External API / Tool)
Each component is one card showing:

- Kind icon (M / P / V / A / T)
- Component name (e.g., `gpt-4o-mini-ft-2024-07-18-ag-v1`)
- Vendor (e.g., `OpenAI` or `community/npm`)
- Version
- Customer-managed badge (if applicable — signals lower risk)
- Risk flags (chips: `fine_tuned`, `community_plugin`, etc.)
- Risk score (0-100)

Components are sorted within each group by risk DESC.

## Risk flag catalog

Each component carries zero or more flags. The flag catalog drives the risk score:

| Flag | Penalty | Meaning |
|---|---|---|
| `cve` | 30 | Known vulnerability against this component |
| `unbounded_scope` | 25 | Tool/plugin has unrestricted scope (e.g., webbrowser with `*` allowed_domains) |
| `unapproved` | 25 | Model not approved via Model Registry |
| `fine_tuned` | 20 | Custom fine-tuned model — needs training-data provenance review |
| `mutable_dependency` | 20 | Component version is not pinned (will auto-update) |
| `public_endpoint` | 20 | Vector DB / API is reachable from the public internet |
| `unverified_vendor` | 20 | Vendor not on the customer's approved list |
| `community_plugin` | 15 | Plugin from a community source (npm, PyPI) without enterprise support |
| `no_pinned_version` | 15 | Version constraint allows minor/major bumps |
| `external_managed` | 10 | Vendor-managed (lower risk than community but higher than customer-managed) |
| `no_scope_audit` | 15 | External API OAuth scopes not audited recently |

Aggregate score = sum of flag penalties, capped at 100. Severity bucket = critical (≥80), high (≥60), medium (≥40), low (<40).

## How components are discovered

The discovery pipeline pulls from:

- **Azure**: Cognitive Services accounts (models), Azure AI Foundry registered models, AKS workload manifests (for plugins), Azure Cosmos vector indices, App Service / Function Apps (for external APIs called)
- **AWS**: Bedrock foundation + custom models, AWS Lambda layers, OpenSearch / Pinecone indices
- **GCP**: Vertex AI models, GKE workload manifests
- **GitHub**: workflow files (npm/pip dependency lists)
- **Customer declarations**: for components not auto-discoverable, declare via the API

Each component's discovery source is shown in its metadata. For customer-declared components, the declaring user + timestamp are recorded for audit.

## Worked example

The demo's `demo-ai-copilot-prod` agent shows:

```
Models (5)
  ├─ gpt-4o (baseline, score=5)              ← safe
  ├─ gpt-4o-mini-ft-2024-07-18-ag-v1 (score=78)   ← fine_tuned, unapproved
  └─ ...

Plugins (3)
  ├─ pinecone-langchain v0.1.5 (score=68)    ← community_plugin, no_pinned_version, mutable
  ├─ webbrowser-langchain v0.0.7 (score=74)  ← community_plugin, unbounded_scope
  └─ pgvector v0.5.1 (score=10)              ← customer-managed, safe

Vector DB (2)
  ├─ Pinecone (us-west) (score=62)           ← public_endpoint, external_managed
  └─ AzurePG.aiag-pg (score=12)              ← customer-managed, private

External API (2)
  ├─ salesforce.com/contacts (score=56)      ← no_scope_audit, mutable
  └─ huggingface.co/datasets (score=72)      ← community, mutable, unverified

Tool (1)
  └─ webBrowser (score=64)                   ← unbounded_scope

Aggregate: 55 (medium)
Top risk: unbounded_scope (+50), mutable_dependency (+40), community_plugin (+30)
```

The narrative reads: *"copilot-prod's biggest supply-chain risk is the webbrowser tool with unbounded scope, plus several mutable community plugins."*

## What to remediate

The recommendation flows from the top risk contributors:

- **`unbounded_scope` (tool)** → set `allowed_domains` to a specific list, not `*`
- **`mutable_dependency` (plugin)** → pin to a specific version (`0.1.5` not `^0.1.0`)
- **`community_plugin`** → migrate to an enterprise-supported equivalent or self-host with security review
- **`fine_tuned` + `unapproved`** → push the model through Model Registry approval
- **`public_endpoint` (vector DB)** → move to a private endpoint
- **`unverified_vendor`** → add to approved vendor list or replace

The same flag categories surface in the [AI Findings](#screen-ai-findings) catalog as named findings, which is where you'd run the remediation workflow.

## Common questions

**Q: How does this differ from cloud CSPM dependency scanning?**
CSPM looks at infrastructure dependencies (NPM packages with CVEs, container base image vulns). This screen looks at AI-specific dependencies (which model, which vector DB, which tool). Same idea, AI-native catalog.

**Q: Can I export the dependency tree?**
Yes — the per-agent supply chain endpoint returns the full tree as JSON. Useful for procurement reviews and SBOM-AI.

**Q: How is "aggregate risk" computed across the tree?**
It's the MAX risk_score of any component in the agent's reachable tree (not the sum). The rationale: a chain is only as weak as its weakest link, and summing would double-count when components share the same flag.

## What to do next

1. Pick the agent with the highest aggregate risk score (top of the agent picker).
2. Look at the top 3 contributing flags. Pick the highest one.
3. Find which component(s) carry that flag in the tree. Remediate them.
4. Re-discover and verify the aggregate dropped.

## Related screens

- [AI Model Registry](#screen-ai-model-registry) — fine-tuned and unapproved models surface here
- [AI Findings](#screen-ai-findings) — same risk catalog as findings
- [AI Inventory](#screen-ai-inventory) — per-agent drilldown
