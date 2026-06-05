# Patent Draft — Multi-Hop XGRAPH Transitive Blast-Radius for AI Agent Identities

**Working title (lawyer to refine):** "System and method for computing transitive blast radius across chains of autonomous agent identities in cloud and SaaS environments"

**Status**: Draft for IP attorney review. NOT a final filing. Per peer review v3/v4 — Year-1 priority patent.

**Authors**: Bhupathi R. Sangabattula, AuditGraph
**Date**: 2026-06-05
**Estimated filing**: Q3 2026 (US provisional, then PCT in 12 months)
**Budget**: $15-20k legal (provisional + drafting)

---

## 1. Field of the invention

Cybersecurity, specifically identity security posture management (ISPM) and non-human identity (NHI) governance — and more specifically the computation of "blast radius" (the privileged-resource scope an attacker would inherit upon compromise) when one or more autonomous AI agent identities can transitively invoke one another via MCP servers, HTTP APIs, function calls, event buses, or shared credentials.

## 2. Background — what's already known

Prior art (specific reference to be expanded by attorney):

| Vendor / paper | What they do | What they don't do |
|---|---|---|
| Wiz, Lacework, Orca | Cloud-resource blast radius | Single hop: identity → resource. No agent-to-agent chains. |
| Astrix, Entro, Token Security | NHI inventory + secret rotation | No transitive reachability; no AI-specific scoring. |
| Lakera, Bedrock Guardrails | Prompt-injection content detection | Detect content; don't quantify resource impact. |
| Microsoft Entra "Insights" | Per-identity privilege graph | Doesn't traverse identity-to-identity invocation edges. |

The gap: no existing system computes the **transitive** identity-to-identity privilege reach that arises when:

- Agent A authenticates as service principal SP_A
- Agent A invokes Agent B via MCP (Model Context Protocol)
- Agent B authenticates as service principal SP_B with KV Admin scope
- A compromise of SP_A (e.g., via prompt injection of Agent A) effectively grants the attacker SP_B's privileges through the invocation chain

This patent claims a deterministic, schema-free method for computing such chains and quantifying their dollar-denominated breach exposure.

## 3. Summary of the invention

A computer-implemented system comprising:

1. An **edge ingestion layer** that captures or accepts evidence of one AI agent identity invoking another. Evidence sources include:
   - Direct telemetry: MCP server logs, AWS Bedrock Agent runtime logs, Azure OpenAI request logs, custom HTTP middleware
   - Declared service maps: customer-declared YAML/JSON of agent-to-agent dependencies
   - Inferred: identities sharing the same shared_secret authenticate as the same SPN, creating an implicit invocation edge

2. A **normalized edge data model** comprising tuples of `(source_identity, target_identity, mechanism, confidence, count, observed_time)` where:
   - `mechanism` is from a fixed catalog: mcp, http, azure_function, webhook, event_grid, shared_secret, service_bus
   - `confidence` is one of: observed (direct evidence), declared (customer-stated), inferred (heuristic)

3. A **bounded breadth-first traversal engine** that, starting from one or more source identities, walks the invocation graph up to a configurable depth limit, with:
   - Per-(source, target) visit deduplication
   - Cycle guards using a per-path visited set
   - Termination on classified-data reach (each visited identity is checked against per-identity reachability tables; chains that reach PHI, PCI, PII, etc. are emitted)

4. A **chain-level severity scoring function** that:
   - Computes a base severity from `(terminal_data_class, is_write_capability)` using a configurable matrix
   - Bumps severity one tier if any edge in the chain has `mechanism = shared_secret` OR `confidence = inferred` ("weakest-link" detection)
   - Maps the chain to MITRE ATT&CK techniques (T1199, T1078.004, T1530, T1565 …)

5. A **breach-exposure quantification** that joins the terminal data classification + record count to industry-standard cost factors (IBM Cost of a Data Breach, Ponemon, Verizon DBIR), producing low/mid/high dollar bands per chain.

## 4. Detailed embodiment — claims (numbered, to be refined by attorney)

**Claim 1.** A computer-implemented method for computing transitive identity-to-identity blast radius in a cloud environment, comprising:
  - (a) receiving a plurality of invocation edges, each edge representing one identity invoking another via a named mechanism;
  - (b) receiving a per-identity data-reachability map indicating, for each identity, the classified data tables and record counts the identity can read or write under its current role assignments;
  - (c) performing a bounded breadth-first traversal of a graph constructed from said edges, beginning at one or more source identities;
  - (d) at each visited identity, emitting a candidate chain if the visited identity has a non-zero entry in the data-reachability map;
  - (e) scoring each chain by:
    (i) selecting a base severity from a matrix indexed by (terminal data class, write flag);
    (ii) detecting any edge in the chain whose mechanism is a shared-secret or whose confidence is inferred, and incrementing severity by one tier;
    (iii) mapping the chain to one or more MITRE ATT&CK technique identifiers based on the mechanism types present;
  - (f) computing a breach-exposure dollar band by joining the terminal data classification and record count to an industry-standard cost-factor table;
  - (g) returning the chains, severity, MITRE mapping, and dollar bands as a structured response.

**Claim 2.** The method of claim 1, wherein at least one of the invocation edges is captured by parsing Model Context Protocol (MCP) tool-call traces.

**Claim 3.** The method of claim 1, wherein at least one of the invocation edges is inferred by detecting that two distinct identity records share the same authentication secret material.

**Claim 4.** The method of claim 1, wherein the breadth-first traversal applies a per-source, per-target deduplication cache so that no chain is emitted more than once even when multiple paths exist between the same source and target.

**Claim 5.** A system comprising one or more processors and memory storing instructions that, when executed, cause the system to perform the method of claim 1.

**Claim 6.** A non-transitory computer-readable medium storing instructions that, when executed, cause one or more processors to perform the method of claim 1.

**Claim 7.** The method of claim 1, further comprising:
  - storing each invocation edge with an idempotency key `(organization_id, source_identity_db_id, target_identity_db_id, via_mechanism)` such that re-ingestion of the same edge from the same evidence source is idempotent.

**Claim 8.** The method of claim 1, wherein the severity bump described in step (e)(ii) is applied only once per chain regardless of how many weak-link edges are present.

**Claim 9.** The method of claim 1, wherein the chain emission is filtered by a query-time classification parameter such that only chains terminating at the specified data class are returned.

**Claim 10.** The method of claim 1, wherein each identity additionally carries metadata indicating whether it is an AI-classified agent, and the chains are tagged with the count of AI-classified hops they contain.

## 5. Drawings (to be produced)

Figure 1 — high-level architecture: edge sources → normalized edge table → BFS engine → scoring → API response.
Figure 2 — example three-hop chain: gpt4-inference → openai-connector → copilot-prod ⇒ 120K PHI records ($56.52M).
Figure 3 — weak-link detection flow: per-edge mechanism check → severity bump.
Figure 4 — UML class diagram of `AgentInvocation`, `NormalizedSignal`, `Chain` data types.
Figure 5 — sample API request/response showing the structured chain output.

## 6. Working example (already implemented in product)

**Setup:** customer tenant with 13 demo AI agents, 10 captured invocation edges including:
- `gpt4-inference-service-sp` → http → `openai-prod-connector-sp`
- `openai-prod-connector-sp` → service_bus → `demo-ai-copilot-prod`
- `demo-ai-copilot-prod` has `agent_data_reachability` entry: PHI, 120,000 records, write=true

**Engine call:** `trace_multihop(org_id, source='gpt4-inference-service-sp', classification='PHI', max_depth=4)`

**Output:**
```json
{
  "chains": [{
    "depth": 2,
    "hops": [
      {"identity_id": "gpt4-inference-service-sp"},
      {"identity_id": "openai-prod-connector-sp"},
      {"identity_id": "demo-ai-copilot-prod"}
    ],
    "edges": [
      {"via_mechanism": "http"},
      {"via_mechanism": "service_bus"}
    ],
    "terminal_classification": "PHI",
    "terminal_records": 120000,
    "is_write": true,
    "severity": "critical",
    "base_severity": "critical",
    "weakest_link": null,
    "mitre_techniques": ["T1199", "T1530", "T1565", "T1648"],
    "dollar_band": {
      "low": 25_000_000, "mid": 56_520_000, "high": 100_440_000,
      "source": "IBM Cost of a Data Breach 2023 — healthcare avg $11/record (low) ... $471/record (high mid)"
    },
    "headline": "Gpt4 Inference Service Sp → Openai Prod Connector Sp → demo-ai-copilot-prod ⇒ write 120,000 PHI records"
  }]
}
```

## 7. Prior art search — to-do for attorney

- USPTO + Google Patents search for: "transitive identity blast radius", "service principal blast radius", "AI agent chain attack", "MCP attack path"
- USPTO classification 726/22, 726/23 (attack-graph computation)
- Comparative review with: SailPoint Identity AI, Microsoft Entra Insights, Wiz blast-radius, Lacework Polygraph
- Confirm no overlapping claims with arXiv papers on graph-based attack-path computation in cloud environments

## 8. Trademark filings (to bundle with patent filing)

- **Identity Security Graph™** (Class 9 — software; Class 42 — SaaS)
- Argus (Class 9, Class 42) — only if conflict-clear; "Argus" is common

## 9. Engineering record (custody-of-invention)

- Initial implementation: 2026-06-04 (commit `fe65b85` in repository `nexgenixlabs/auditgraph`)
- Live demo: dev.app.auditgraph.ai/ai-attack-paths/multi-hop
- Documentation: `docs/AG_FINAL_IA_AND_BRAND_2026_06_05.md` section 8b (future-merge note)
- Validation suite: `/tmp/validate_tier3_1.sh` — 12/12 checks pass

---

**Next action**: send to IP attorney with PDF export of the live demo screen and a one-pager of prior-art differentiation. Estimated 4-6 weeks to provisional filing.
