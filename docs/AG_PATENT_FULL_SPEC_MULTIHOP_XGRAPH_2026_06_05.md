# PATENT SPECIFICATION

## Title

**SYSTEM AND METHOD FOR COMPUTING TRANSITIVE BLAST RADIUS ACROSS INVOCATION CHAINS OF AUTONOMOUS AGENT IDENTITIES IN CLOUD COMPUTING ENVIRONMENTS**

| Field | Value |
|---|---|
| **Applicant** | Nexgenix Labs (assignee), AuditGraph (product) |
| **Inventors** | Bhupathi Reddy Sangabattula |
| **Status** | Draft for IP attorney review (US Provisional Patent Application) |
| **Document version** | 1.0 |
| **Document date** | 2026-06-05 |
| **Filing target** | US Provisional → PCT in 12 months |
| **Related** | `docs/AG_PATENT_DRAFT_MULTIHOP_XGRAPH_2026_06_05.md` (initial outline; superseded by this document) |
| **Reference implementation** | Repository `nexgenixlabs/auditgraph`, commits `fe65b85` (initial) through `c704ce0` |

---

## ABSTRACT

A computer-implemented system and method for computing transitive identity-to-identity blast radius in cloud and software-as-a-service environments. The method receives directed edges representing invocations between autonomous agent identities (each edge characterized by a source identity, target identity, invocation mechanism, confidence level, and observation evidence), receives per-identity classified-data reachability indicating data classes and record counts each identity can read or write under its current role assignments, and performs a bounded breadth-first traversal of the resulting graph from one or more source identities. At each visited node, candidate transitive chains are emitted when classified-data reachability is non-zero. Each chain is scored with a base severity derived from a configurable matrix indexed by terminal data classification and write-capability, with a one-tier severity bump applied when at least one edge in the chain has a weak-confidence mechanism (such as a shared-secret authentication path) or an inferred-confidence rating. Each chain is mapped to one or more MITRE ATT&CK technique identifiers based on the mechanisms present, and is quantified as a low/mid/high dollar exposure band by joining the terminal classification and record count against industry-standard breach cost factors. The structured output enables continuous, automated quantification of attack consequences across multi-agent autonomous systems in cloud environments.

---

## 1. FIELD OF THE INVENTION

The present invention relates generally to cybersecurity, and more specifically to identity security posture management, non-human identity governance, and the automated computation of "blast radius" — the scope of privileged resources, classified data, and downstream impacts an adversary would obtain upon compromise of one or more identities — in environments where autonomous software agents (also known as AI agents) can transitively invoke one another across cloud and software-as-a-service tenant boundaries.

---

## 2. BACKGROUND OF THE INVENTION

### 2.1 The expansion of non-human identity in cloud environments

Modern enterprise computing has transitioned from a paradigm in which most credentialed actors were human (employees, contractors, partners) to one in which the overwhelming majority of credentialed actors are non-human. Non-human identities (hereafter "NHIs") include:

- Service principals in Microsoft Entra ID (Azure Active Directory),
- IAM roles and access keys in Amazon Web Services,
- Service accounts in Google Cloud Platform,
- Managed identities (system-assigned and user-assigned) in Microsoft Azure,
- Workload identities in Kubernetes clusters (Azure Kubernetes Service, Elastic Kubernetes Service, Google Kubernetes Engine),
- OIDC tokens issued by continuous integration and deployment systems (GitHub Actions, GitLab CI/CD, Azure DevOps, CircleCI),
- API keys and personal access tokens issued by software-as-a-service vendors, and
- OAuth-issued application credentials granting machine-to-service access.

Studies indicate that in typical mid-market and enterprise environments, NHIs outnumber human identities by ratios commonly ranging from 5:1 to over 100:1.

### 2.2 The emergence of autonomous agent identities

Beginning approximately 2023, the proliferation of large language model (LLM) -based autonomous agents has introduced a sub-category of NHI with materially different operational characteristics. Such agents:

(a) authenticate as service principals or managed identities;
(b) make autonomous decisions about which tools, application programming interfaces (APIs), or downstream agents to invoke based on natural-language input or model-generated chain-of-thought;
(c) can be instructed via natural-language input — including potentially adversarial input — to perform actions on behalf of an upstream actor; and
(d) frequently invoke one another through emerging open protocols such as the Model Context Protocol (MCP) introduced by Anthropic in late 2024, through proprietary inter-agent buses, or through commodity HTTP and message-queue infrastructure.

The combination of these characteristics produces a novel risk surface: an attacker who compromises one autonomous agent (for example, by means of prompt injection delivered through a public web surface, a poisoned document indexed by a retrieval-augmented generation system, or a malicious tool-call response) may transitively gain the privileges of every downstream agent that the compromised agent can invoke — privileges which were never directly granted to the entry-point agent's underlying credentials.

### 2.3 Limitations of the prior art

Existing prior-art systems for cloud security posture management, including but not limited to:

| Category | Representative vendors | Limitation |
|---|---|---|
| Cloud Security Posture Management (CSPM) | Wiz, Lacework, Orca, Microsoft Defender for Cloud | Compute "blast radius" only as **single-hop** identity-to-resource exposure. Do not model identity-to-identity edges. |
| Non-human identity inventory | Astrix Security, Entro Security, Token Security, Oasis Security | Inventory and rotate non-human identities but do not compute transitive reach beyond direct role assignment. |
| AI runtime guardrails | Lakera AI, Robust Intelligence, AWS Bedrock Guardrails, Microsoft Azure Content Safety, OpenAI Moderation API, NVIDIA NeMo Guardrails | Detect content-level events (prompt injection, jailbreak, toxic content) but do not quantify the **consequence** of a successful event in terms of privileged resource exposure. |
| Identity governance and administration | SailPoint, Saviynt, Microsoft Entra Insights | Surface privileged access reviews and certification campaigns but lack agent-to-agent transitive privilege computation. |
| Attack-path computation | BloodHound (Microsoft Active Directory), XM Cyber, ArpaSky | Compute attack paths from identity to resource (typically restricted to Active Directory or on-premises environments). Do not model autonomous-agent invocation chains in cloud SaaS environments. |

No prior art known to the inventor combines:

1. **Edge capture across heterogeneous invocation mechanisms** (Model Context Protocol traces, cloud-native LLM service logs, customer-declared service maps, and inferred shared-credential edges);
2. **Bounded breadth-first traversal with cycle protection** specifically tuned for autonomous-agent invocation graphs;
3. **Severity scoring that incorporates "weakest link" semantics** in which the presence of a weak-confidence edge anywhere in the chain elevates the severity of the entire chain;
4. **Automatic mapping to MITRE ATT&CK** technique identifiers derived from the invocation mechanisms traversed;
5. **Dollar-denominated breach-exposure quantification** computed by joining the terminal data classification and record count against industry-standard cost factors;

within a single computer-implemented method operating continuously over cloud and SaaS identity graphs.

### 2.4 Technical problem solved

The present invention solves the technical problem of computing, in a scalable and deterministic manner, the transitive privilege exposure that arises when autonomous agents can invoke one another in cloud environments, and quantifying the consequence of such exposure in business-impact terms (dollar bands tied to industry breach cost data) suitable for automated risk reporting, board-level dashboards, and continuous compliance monitoring.

---

## 3. SUMMARY OF THE INVENTION

In accordance with one aspect of the present invention, a computer-implemented method is provided, comprising:

- Receiving, by one or more computer processors, a plurality of invocation edges, each invocation edge representing one autonomous agent identity invoking another autonomous agent identity, and each invocation edge characterized by a tuple (source identity identifier, target identity identifier, invocation mechanism selected from a fixed mechanism catalog, confidence indicator selected from {observed, declared, inferred}, observation count, optional observation time);
- Receiving, by the one or more processors, a per-identity classified-data reachability map indicating, for each identity identifier in the corpus, zero or more entries each comprising (data classification, estimated record count, write capability flag), said data classification selected from a configurable classification catalog comprising at least Protected Health Information (PHI), Payment Card Industry (PCI), Personally Identifiable Information (PII), and other configurable classes;
- Performing, by the one or more processors, a bounded breadth-first graph traversal of the directed graph constructed from said invocation edges, the traversal initiated at one or more designated source identity nodes, the traversal bounded by a configurable maximum traversal depth, the traversal performing cycle elimination by maintaining a per-path visited set;
- At each node visited during the traversal, emitting one or more candidate transitive chains when the visited node has a non-zero entry in said classified-data reachability map and when the depth of the path to said visited node is at least one edge;
- For each emitted candidate transitive chain:
   - Determining a base severity selected from {low, medium, high, critical} according to a configurable severity matrix indexed by the terminal data classification of the chain and the write capability flag of the terminal classified-data reachability entry,
   - Detecting whether at least one edge in the chain has an invocation mechanism within a configurable weak-mechanism subset (such as shared_secret) OR a confidence indicator equal to "inferred", and if so, incrementing the chain severity by one tier within the severity ordering subject to a saturation cap at "critical",
   - Constructing a MITRE ATT&CK technique mapping for the chain comprising the union of technique identifiers associated with each mechanism present in the chain, augmented by classification-dependent technique identifiers,
   - Computing a low/mid/high estimated breach-exposure dollar band by joining the terminal data classification and terminal record count against a regionally-adjusted industry-standard breach cost factor table; and
- Returning, by the one or more processors, a structured data response comprising the emitted candidate transitive chains together with their respective severities, weakest-link detection results, MITRE technique mappings, and exposure dollar bands.

In accordance with a further aspect of the invention, a non-transitory computer-readable medium is provided storing computer-executable instructions that, when executed by one or more processors, cause said processors to perform the method described above.

In accordance with a further aspect of the invention, a system is provided comprising one or more computer processors and a memory storing instructions configured to cause said processors to perform the method described above, the system further comprising an edge ingestion subsystem configured to receive captured invocation evidence from one or more of: a Model Context Protocol trace collector, an Azure OpenAI request log parser, an Amazon Web Services Bedrock CloudTrail event subscriber, a customer-declared service-map parser accepting structured input in JSON or YAML formats, and an inferred-edge generator configured to detect when two distinct identity records possess overlapping authentication secret material.

---

## 4. BRIEF DESCRIPTION OF THE DRAWINGS

The drawings herein referenced shall be produced for the formal filing by a registered patent illustrator. Brief descriptions follow.

**FIG. 1** — System architecture overview. Shows (a) an edge ingestion layer comprising five sub-modules; (b) a normalized edge data store; (c) a per-identity classified-data reachability store; (d) a traversal engine; (e) a severity scoring subsystem; (f) a breach-exposure quantification subsystem; (g) an API gateway returning structured chain output; and (h) a presentation layer.

**FIG. 2** — Data model of one invocation edge, illustrating the tuple structure: source_identity_db_id, source_identity_id, target_identity_db_id, target_identity_id, via_mechanism (enumeration of mcp, http, azure_function, webhook, event_grid, shared_secret, service_bus), invocation_name (optional), observed_count, first_observed_at, last_observed_at, confidence (enumeration of observed, inferred, declared), source (enumeration of mcp_trace, aoai_logs, bedrock_logs, declared, inferred_shared_sp, manual), metadata (JSON).

**FIG. 3** — Sample transitive chain of depth 2. Three agent nodes: gpt4-inference-service-sp, openai-prod-connector-sp, demo-ai-copilot-prod. Two edges: http and service_bus. Terminal node has write capability over 120,000 PHI records. Final severity computed as "critical".

**FIG. 4** — Bounded breadth-first traversal pseudocode flow chart showing: (1) initialization with source set; (2) queue processing; (3) per-node classified-data check; (4) chain emission; (5) cycle guard; (6) depth termination; (7) frontier expansion.

**FIG. 5** — Severity scoring decision tree. Inputs: terminal classification (PHI/PCI/PII/FINANCIAL/HR/SOURCE/CONFIDENTIAL), write flag (Boolean). Output: base severity. Followed by weak-link detection that examines each edge and conditionally increments severity by one tier.

**FIG. 6** — MITRE ATT&CK mechanism-to-technique mapping table.

**FIG. 7** — Sample API response in JSON format illustrating the chain output structure.

**FIG. 8** — Comparative architecture diagram contrasting prior art single-hop blast radius computation with the present invention's transitive multi-hop computation.

**FIG. 9** — Industry breach cost factor table format and join logic.

**FIG. 10** — Example three-hop chain demonstrating cumulative MITRE technique union across heterogeneous mechanisms.

---

## 5. DETAILED DESCRIPTION OF THE PREFERRED EMBODIMENTS

### 5.1 System architecture (FIG. 1)

A preferred embodiment of the system comprises eight cooperating subsystems:

**(a) Edge ingestion layer.** Receives raw observation evidence from one or more upstream sources. Each source produces evidence in a different native format; the edge ingestion layer normalizes all sources into the common invocation edge schema described in Section 5.2.

Edge sources may include:

1. **Model Context Protocol trace collector.** Receives MCP tool-call traces from agent runtimes that have been instrumented to emit standardized MCP frames. Each frame contains a caller identity reference (the calling agent's authentication context), a callee identity reference (the called agent's identity), a tool name, and a timestamp. The collector parses each frame and constructs an edge tuple with `via_mechanism='mcp'`, `confidence='observed'`, `source='mcp_trace'`.

2. **Azure OpenAI request log parser.** Subscribes to Azure OpenAI Service request logs (delivered via Azure Monitor or Azure Storage). Parses log entries that contain a `client_application_id` field (the caller) and a `dependency_application_id` field (the callee, when one agent forwards to another). Constructs edge tuples with `via_mechanism='http'` or `via_mechanism='service_bus'` depending on the dispatch mode, `confidence='observed'`, `source='aoai_logs'`.

3. **AWS Bedrock CloudTrail event subscriber.** Subscribes via Amazon EventBridge to CloudTrail events of event name `InvokeAgent`, `InvokeModelWithResponseStream`, or `Retrieve`. Parses the `userIdentity` and `requestParameters` fields to identify caller and callee agent ARNs. Constructs edge tuples with `via_mechanism` derived from the AWS service ID, `confidence='observed'`, `source='bedrock_logs'`.

4. **Customer-declared service-map parser.** Accepts structured input in JSON or YAML format describing customer-declared agent-to-agent dependencies. Each declaration must contain the source and target identity references and the mechanism. Confidence is set to `declared`; the source is set to `declared`.

5. **Inferred shared-credential edge generator.** Periodically examines all identity-credential associations in the corpus. When two distinct identities possess overlapping credential material (for example, two service principals that share an X.509 certificate thumbprint or a federated credential identifier), an edge is generated in each direction with `via_mechanism='shared_secret'`, `confidence='inferred'`, `source='inferred_shared_sp'`. This inferred edge captures the reality that compromise of the shared credential effectively bridges the two identities.

Additional embodiments may incorporate further edge sources, including but not limited to: Azure Service Bus topic subscription analysis, Kafka topic consumer-group analysis, Google Cloud Pub/Sub subscription analysis, and webhook delivery log analysis.

**(b) Normalized edge data store.** Persists invocation edges in a relational database with the schema described in Section 5.2. An idempotency key on `(organization_id, source_identity_db_id, target_identity_db_id, via_mechanism)` ensures that re-ingestion of the same edge from the same evidence source increments an observation counter rather than duplicating rows.

**(c) Per-identity classified-data reachability store.** Persists, for each identity, the set of classified-data entries the identity can read or write under its current role assignments. Each entry is a tuple `(identity_db_id, data_classification, est_records, write_resource_count, resource_count)`. The reachability store is populated by an upstream privilege analyzer not within the scope of this invention but disclosed for context.

**(d) Traversal engine.** Performs the bounded breadth-first traversal described in detail in Section 5.4.

**(e) Severity scoring subsystem.** Computes per-chain base severity, applies weak-link detection, and produces final severity classification (Section 5.5).

**(f) Breach-exposure quantification subsystem.** Joins terminal classification and record count to an industry-standard breach cost factor table (Section 5.7).

**(g) API gateway.** Exposes the chain computation as a callable HTTP endpoint accepting query parameters (source identity, classification filter, maximum traversal depth, maximum chain count) and returning structured chain output (Section 5.8).

**(h) Presentation layer.** Renders chain output for human consumers, including but not limited to per-chain severity badges, MITRE technique chip displays, weakest-link callouts, and dollar-band rendering with low/mid/high indicators.

### 5.2 Invocation edge schema

Each invocation edge in the preferred embodiment is represented by the following schema, here expressed in a database-neutral notation:

```
INVOCATION_EDGE := {
  organization_id          : INTEGER (tenant scope)
  source_identity_db_id    : LONG    (caller identity primary key)
  source_identity_id       : STRING  (caller identity globally unique name)
  target_identity_db_id    : LONG    (callee identity primary key)
  target_identity_id       : STRING  (callee identity globally unique name)
  via_mechanism            : ENUM    (catalog described below)
  invocation_name          : STRING? (optional named tool / endpoint)
  observed_count           : INTEGER (count of observations of this edge)
  first_observed_at        : TIMESTAMP?
  last_observed_at         : TIMESTAMP?
  confidence               : ENUM    {observed, inferred, declared}
  source                   : ENUM    {mcp_trace, aoai_logs, bedrock_logs,
                                       declared, inferred_shared_sp, manual}
  metadata                 : JSON    (extensible)
}
```

The invocation mechanism catalog comprises at least the following entries, each associated with one or more MITRE ATT&CK technique identifiers:

| Mechanism | Description | MITRE techniques |
|---|---|---|
| `mcp` | Model Context Protocol tool call | T1199 (Trusted Relationship) |
| `http` | Direct HTTP API call | T1199 |
| `azure_function` | Azure Function invocation | T1648 (Serverless Execution) |
| `webhook` | Webhook delivery | T1199 |
| `event_grid` | Azure Event Grid message | T1199 |
| `shared_secret` | Inferred — two identities share credential material | T1078.004 (Cloud Accounts), T1552 (Unsecured Credentials) |
| `service_bus` | Azure Service Bus / Kafka / Pub/Sub message | T1648 |

The mechanism catalog is configurable and may be extended by the operator to include additional cloud-native or third-party invocation primitives without departing from the spirit of the invention.

The confidence catalog comprises:

- **observed**: edge captured by direct telemetry from a trace source;
- **declared**: edge declared by a customer-supplied service map;
- **inferred**: edge generated by a heuristic such as shared-credential detection.

Idempotency is achieved by a unique constraint on `(organization_id, source_identity_db_id, target_identity_db_id, via_mechanism)`. When the same edge is observed multiple times from the same source, the `observed_count`, `first_observed_at`, and `last_observed_at` fields are updated rather than a new row inserted.

### 5.3 Classified-data reachability schema

Each per-identity reachability entry is represented as:

```
DATA_REACHABILITY := {
  identity_db_id          : LONG
  data_classification     : ENUM  (catalog: PHI, PCI, PII, FINANCIAL,
                                    HR, SOURCE, CONFIDENTIAL, ...)
  est_records             : LONG  (estimated record count reachable)
  write_resource_count    : INTEGER  (count of resources with write privilege)
  resource_count          : INTEGER  (total count of reachable resources)
}
```

The classification catalog is configurable. The default catalog includes Protected Health Information (PHI), Payment Card Industry data (PCI), Personally Identifiable Information (PII), financial records (FINANCIAL), human resources data (HR), source code (SOURCE), and confidential business information (CONFIDENTIAL). Additional catalog entries may be defined by operators of the system.

### 5.4 Bounded breadth-first traversal (FIG. 4)

The traversal engine performs the following operation. Pseudocode is provided in a deliberately general form; specific implementation details such as concrete data structure choices may vary.

```
function TRACE_MULTIHOP(graph_edges, reachability_map, source_identities,
                       max_depth, classification_filter, max_chains):
    chains_emitted := []
    for each source_id in source_identities:
        source_meta := lookup_agent_metadata(source_id)
        if source_meta is null:
            continue

        initial_path := [{ identity_db_id: source_id, ... }]
        queue := [(source_id, initial_path, [])]    // (current, path, edges)
        visited_pairs := empty_set                   // (source, target, depth)

        while queue is not empty:
            (current_id, path, edges_used) := queue.pop_front()
            depth := length(edges_used)

            // Step 1: emit chains when current node has classified reach
            for each reach in reachability_map.get(current_id, []):
                cls := reach.data_classification
                if classification_filter present and cls != classification_filter:
                    continue
                if reach.est_records <= 0:
                    continue
                if depth == 0:
                    continue    // depth-0 chains == single-hop, not subject of this method

                chain := {
                    hops: path[:],
                    edges: edges_used[:],
                    depth: depth,
                    terminal_classification: cls,
                    terminal_records: reach.est_records,
                    is_write: (reach.write_resource_count > 0),
                    source_identity_id: source_meta.identity_id,
                }
                chains_emitted.append(chain)

            // Step 2: depth bound
            if depth >= max_depth:
                continue

            // Step 3: expand frontier
            for each edge in graph_edges.outgoing(current_id):
                target_id := edge.target_identity_db_id
                // Cycle guard: do not revisit any node already in this path
                if target_id in (h.identity_db_id for h in path):
                    continue
                target_meta := lookup_agent_metadata(target_id)
                if target_meta is null:
                    continue
                pair_key := (source_id, target_id, depth + 1)
                if pair_key in visited_pairs:
                    continue
                visited_pairs.insert(pair_key)
                new_path := path + [target_meta]
                new_edges := edges_used + [edge]
                queue.push_back((target_id, new_path, new_edges))

            if length(chains_emitted) >= max_chains:
                break

    return chains_emitted
```

The bounded breadth-first traversal exhibits the following novel characteristics:

(a) **Per-path cycle elimination.** Each path maintains its own visited set (the identity_db_ids already in the path). This permits the same node to appear in different paths from different sources without false cycle detection, while preventing infinite loops.

(b) **Per-(source, target, depth) deduplication.** The `visited_pairs` set prevents the same source→target chain from being emitted at multiple depths via different paths. This is distinct from path-level cycle elimination; it operates at the chain-emission level.

(c) **Depth-zero suppression.** Chains of depth zero (the source identity itself directly reaching classified data) are NOT emitted because they correspond to the single-hop blast radius already computed by prior-art systems. The present invention is specifically directed to depth ≥ 1 chains.

(d) **Classification-filtered traversal.** When a classification filter is specified, only chains terminating at the specified classification are emitted, reducing computational cost.

(e) **Bounded chain count.** The `max_chains` parameter provides a cap on the total chains emitted, allowing the method to return useful results even in environments with very dense invocation graphs.

(f) **Soft termination on classified reach.** The traversal does not stop expanding from a node simply because the node has classified reach. The node continues to expand because deeper chains may reveal additional risk (e.g., a transitive write capability that the depth-1 reach did not exhibit).

### 5.5 Severity scoring with weakest-link detection (FIG. 5)

For each emitted chain, severity is computed in two stages.

**Stage 1 — base severity.** A configurable matrix indexed by `(terminal_classification, is_write)` returns one of {low, medium, high, critical}. A preferred default matrix is:

| Classification | is_write = true | is_write = false |
|---|---|---|
| PHI | critical | high |
| PCI | critical | high |
| PII | high | medium |
| FINANCIAL | high | medium |
| HR | medium | medium |
| SOURCE | medium | low |
| CONFIDENTIAL | medium | low |

**Stage 2 — weakest-link severity bump.** The chain's edges are examined in order. For each edge, if either of the following conditions holds:

1. The edge's `via_mechanism` is a member of a configurable WEAK_MECHANISMS set; the preferred default set is `{shared_secret}`.
2. The edge's `confidence` is `inferred`.

then the chain is flagged with a "weakest_link" descriptor identifying the first qualifying edge, and the chain's severity is incremented by one tier subject to a saturation cap at "critical".

The rationale for the weakest-link bump is that the security posture of a chain is determined by its weakest constituent. An invocation chain that includes a shared-secret edge can be compromised by exploiting the shared credential (a high-leverage low-effort attack); an inferred edge represents a heuristic-derived relationship whose provenance is not directly observable and which therefore may be exploited by an attacker without alerting telemetry.

The severity increment is applied at most once per chain regardless of how many weak edges are present. This avoids double-counting and produces a deterministic output.

### 5.6 MITRE ATT&CK mapping (FIG. 6)

Each chain is mapped to a set of MITRE ATT&CK technique identifiers as follows:

```
MITRE_OF(chain) := union of MITRE_OF_MECHANISM(edge.via_mechanism)
                     for edge in chain.edges
                 ∪ MITRE_OF_CLASSIFICATION(chain.terminal_classification)
                 ∪ (T1565 if chain.is_write else ∅)
```

The default mechanism-to-technique map is provided in Section 5.2. The default classification-to-technique map includes:

- PHI → T1530 (Data from Cloud Storage)
- PCI → T1530
- PII → T1530
- FINANCIAL → T1530
- All others → ∅

The constant T1565 (Data Manipulation) is added when the chain has write capability over the terminal classified data.

### 5.7 Breach exposure quantification

For each chain, an estimated breach exposure dollar band is computed by joining the terminal classification and record count against an industry-standard breach cost factor table. The factor table comprises rows of the form:

```
BREACH_COST_FACTOR := {
  classification     : ENUM
  region             : STRING   (e.g., "US", "EU", "APAC")
  factor_low_usd     : DECIMAL  (USD per record at low end of industry range)
  factor_mid_usd     : DECIMAL  (USD per record at midpoint of industry range)
  factor_high_usd    : DECIMAL  (USD per record at high end of industry range)
  source             : STRING   (citation, e.g., "IBM Cost of a Data Breach 2023, healthcare vertical")
  effective_year     : INTEGER
}
```

The exposure computation is:

```
exposure_low   := terminal_records × factor.factor_low_usd
exposure_mid   := terminal_records × factor.factor_mid_usd
exposure_high  := terminal_records × factor.factor_high_usd
```

When no factor row exists for the terminal classification, the chain's exposure band is marked as `has_factor: false` and zero values are returned for the dollar fields; the implementation does not fabricate exposure estimates in the absence of a defensible factor.

The factor table is populated from publicly available industry sources including but not limited to IBM Security Cost of a Data Breach Report, Ponemon Institute Cost of Insider Threats Report, Verizon Data Breach Investigations Report, and regulatory enforcement databases (HHS OCR for HIPAA, FTC for PII, PCI Security Standards Council for PCI). The system supports regional adjustment and multi-year evolution of factors.

### 5.8 Structured response format

The traversal engine returns a structured response object comprising:

```
RESPONSE := {
  source_agent          : { identity_id, display_name } | null
  chains                : array of CHAIN
  chain_count           : integer
  by_severity           : { critical: N, high: N, medium: N, low: N }
  max_depth_searched    : integer
  classification_filter : string | null
  computed_at           : ISO-8601 timestamp
}

CHAIN := {
  hops                    : array of { identity_db_id, identity_id, display_name }
  edges                   : array of EDGE_SUMMARY
  depth                   : integer
  terminal_classification : ENUM
  terminal_records        : integer
  is_write                : boolean
  severity                : ENUM {critical, high, medium, low}
  base_severity           : ENUM
  weakest_link            : { hop_index, mechanism, confidence, reason } | null
  mitre_techniques        : array of STRING (MITRE technique IDs, sorted)
  dollar_band             : { low, mid, high,
                              low_display, mid_display, high_display,
                              source } | null
  source_identity_id      : STRING
  source_display_name     : STRING
  headline                : STRING  (human-readable summary)
}

EDGE_SUMMARY := {
  source_identity_id : STRING
  target_identity_id : STRING
  via_mechanism      : ENUM
  invocation_name    : STRING | null
  confidence         : ENUM
  observed_count     : INTEGER | null
}
```

The structured response is suitable for direct consumption by user interface presentation layers (FIG. 7 illustrates a sample response).

---

## 6. WORKING EXAMPLES

### 6.1 Working example A — two-hop chain reaching PHI

Setup:

- Tenant: org=9 (demonstration tenant)
- Three agents:
  - `customer-service-bot` (front-line customer-facing chat agent)
  - `demo-ai-rag-indexer` (retrieval-augmented generation indexer; has read access to a patient-records table containing 120,000 PHI records)
- One observed invocation edge:
  - `customer-service-bot` → `demo-ai-rag-indexer` via `mcp`, observation_count=4200, confidence=observed, source=mcp_trace

Per-identity classified-data reachability map includes:

- `demo-ai-rag-indexer` → (classification=PHI, est_records=120000, write_resource_count=0, resource_count=1)

Engine invocation:

```
trace_multihop(org_id=9, source='customer-service-bot',
               classification='PHI', max_depth=4)
```

Trace:

1. Initialize queue with (customer-service-bot, [customer-service-bot], []).
2. Pop. Current=customer-service-bot, depth=0. No classified reach at customer-service-bot. Depth-0 chain emission is suppressed per the design. Expand frontier: queue ← (demo-ai-rag-indexer, [csb, rag], [edge1]).
3. Pop. Current=demo-ai-rag-indexer, depth=1. Classified reach: PHI, 120,000, no write. Emit chain.

Emitted chain:

```
{
  hops: [customer-service-bot, demo-ai-rag-indexer]
  edges: [{ via_mechanism: 'mcp', confidence: 'observed' }]
  depth: 1
  terminal_classification: 'PHI'
  terminal_records: 120000
  is_write: false
  base_severity: 'high'           (PHI read = high per default matrix)
  severity: 'high'                (no weak edges; no bump)
  weakest_link: null
  mitre_techniques: ['T1199', 'T1530']
  dollar_band: {
    low: 25000000, mid: 56520000, high: 100440000,
    source: 'IBM Cost of a Data Breach 2023, healthcare vertical'
  }
  headline: 'Customer Service Bot → demo-ai-rag-indexer ⇒ read 120,000 PHI records'
}
```

### 6.2 Working example B — three-hop chain reaching writeable PHI

Setup (extending Example A):

- Three agents:
  - `gpt4-inference-service-sp` (low-privilege upstream LLM-inference agent)
  - `openai-prod-connector-sp` (mid-tier connector forwarding to downstream copilot)
  - `demo-ai-copilot-prod` (high-privilege copilot agent; has write access to a patient-records table containing 120,000 PHI records)
- Two observed invocation edges:
  - `gpt4-inference-service-sp` → `openai-prod-connector-sp` via `http`, observation_count=5400
  - `openai-prod-connector-sp` → `demo-ai-copilot-prod` via `service_bus`, observation_count=2100
- Reachability map:
  - `demo-ai-copilot-prod` → (PHI, 120000, write_resource_count=1, resource_count=1)

Engine invocation:

```
trace_multihop(org_id=9, source='gpt4-inference-service-sp',
               classification='PHI', max_depth=4)
```

Trace:

1. Queue ← (gpt4-inference-service-sp, [gpt4], []).
2. Pop gpt4. Depth=0. No classified reach. Expand to (openai-prod-connector, [gpt4, openai], [edge1]).
3. Pop openai-prod-connector. Depth=1. No classified reach. Expand to (demo-ai-copilot-prod, [gpt4, openai, copilot], [edge1, edge2]).
4. Pop demo-ai-copilot-prod. Depth=2. Classified reach: PHI, 120000, write=true. Emit chain.

Emitted chain:

```
{
  hops: [gpt4-inference, openai-connector, demo-ai-copilot-prod]
  edges: [{ via_mechanism: 'http' }, { via_mechanism: 'service_bus' }]
  depth: 2
  terminal_classification: 'PHI'
  terminal_records: 120000
  is_write: true
  base_severity: 'critical'   (PHI + write = critical per default matrix)
  severity: 'critical'        (no weak edges)
  weakest_link: null
  mitre_techniques: ['T1199', 'T1530', 'T1565', 'T1648']
  dollar_band: { low: 25000000, mid: 56520000, high: 100440000, ... }
  headline: 'Gpt4 Inference Service Sp → Openai Prod Connector Sp → demo-ai-copilot-prod ⇒ write 120,000 PHI records'
}
```

The three-hop chain demonstrates the central novel insight of the invention: the gpt4-inference agent, which has no direct classified-data reach of its own, nevertheless presents a critical breach exposure of $56.52 million mid-band when its transitive reach is computed. Prior-art systems would correctly report that the gpt4-inference agent has no classified data reach (depth-0 view) and would conclude no risk. The present invention reveals the actual transitive risk.

### 6.3 Working example C — two-hop chain with weakest-link bump

Setup:

- `ml-prod-training-identity` (training automation agent)
- `demo-ai-rag-indexer` (as in Example A; PHI read access)
- One inferred edge: `ml-prod-training-identity` → `demo-ai-rag-indexer` via `shared_secret`, confidence=inferred, source=inferred_shared_sp (detected because both identities authenticate using the same X.509 certificate thumbprint)

Engine invocation:

```
trace_multihop(org_id=9, source='ml-prod-training-identity',
               classification='PHI', max_depth=4)
```

Emitted chain:

```
{
  hops: [ml-prod-training, demo-ai-rag-indexer]
  edges: [{ via_mechanism: 'shared_secret', confidence: 'inferred' }]
  depth: 1
  terminal_classification: 'PHI'
  terminal_records: 120000
  is_write: false
  base_severity: 'high'           (PHI read)
  severity: 'critical'            (BUMPED — shared_secret weak link)
  weakest_link: {
    hop_index: 0,
    mechanism: 'shared_secret',
    confidence: 'inferred',
    reason: 'shared-secret authentication makes the invocation easy to impersonate'
  }
  mitre_techniques: ['T1078.004', 'T1199', 'T1530', 'T1552']
  dollar_band: { low: 25000000, mid: 56520000, high: 100440000, ... }
}
```

This example demonstrates the weakest-link bump: the chain reaches the same terminal data as Example A but its severity is escalated from high to critical because the bridging edge is a shared-secret authentication path that an attacker could readily exploit.

### 6.4 Working example D — cycle detection

Setup:

- Three agents A, B, C connected in a cycle: A→B, B→C, C→A. All edges via mcp. Reachability empty.

Engine invocation:

```
trace_multihop(org_id=9, source='A', max_depth=6)
```

Trace:

1. Queue ← (A, [A], []).
2. Pop A. Expand to (B, [A, B], [A→B]).
3. Pop B. Expand to (C, [A, B, C], [A→B, B→C]).
4. Pop C. Expand: target = A, but A is already in path → cycle guard blocks. Queue empty.

No chains emitted (no classified reach in this graph). Traversal terminates cleanly without infinite loop. This example demonstrates the cycle-elimination guarantee.

### 6.5 Working example E — many-source rollup

Setup:

- 13 demonstration AI agents in tenant org=9
- 10 observed invocation edges connecting them (real configuration from the reference implementation)
- Multiple reachability entries

Engine invocation:

```
trace_multihop(org_id=9, source=null, max_depth=4, max_chains=200)
```

Result (truncated):

- 15 chains emitted across all 13 source agents
- 6 critical, 8 high, 1 medium
- 1 chain depth=2: gpt4-inference → openai-connector → demo-ai-copilot-prod (Example B)
- 1 chain with weakest-link bump: ml-prod-training → demo-ai-rag-indexer (Example C)
- Total mid-band exposure across critical chains: $339.12 million

This example demonstrates that the method scales to many-source rollups and produces actionable severity-stratified output suitable for executive dashboards.

---

## 7. ADDITIONAL EMBODIMENTS AND VARIATIONS

### 7.1 Multi-cloud embodiments

The method as described is cloud-agnostic. Specific embodiments may target individual cloud providers; the preferred embodiment supports simultaneous multi-cloud operation.

In an Amazon Web Services embodiment, source identities are AWS IAM roles or AWS IAM users; invocation edges are captured from AWS CloudTrail event subscriptions filtered to event names indicative of agent invocation (`InvokeAgent`, `InvokeModelWithResponseStream`, etc.); classified-data reachability is derived from AWS IAM policy evaluation against AWS resources tagged with sensitivity classifications.

In a Google Cloud Platform embodiment, source identities are GCP service accounts; invocation edges are captured from Cloud Audit Logs and Cloud Logging; reachability is derived from GCP IAM policy evaluation.

In a multi-cloud embodiment, identity edges may bridge providers (for example, an Azure managed identity that has been granted a role via AWS STS AssumeRole produces an edge from the Azure identity to the AWS role).

### 7.2 SaaS extension embodiment

The method extends to non-cloud-native SaaS environments. SaaS-issued OAuth application credentials, personal access tokens, and webhook delivery secrets may be modeled as NHIs with corresponding invocation edges to integrated SaaS endpoints. In one such embodiment, the system models a GitHub-issued OIDC token as an identity, and an action triggered in a GitHub Actions workflow that calls an Azure Resource Manager endpoint is modeled as an edge from the OIDC identity to the downstream Azure identity that executes the call.

### 7.3 CI/CD pipeline embodiment

The method extends to continuous-integration / continuous-deployment pipelines. Pipeline-issued identities (Azure Pipelines, GitHub Actions, GitLab CI/CD, CircleCI, Jenkins) are modeled as NHIs; invocation edges are captured from pipeline run logs and downstream service invocations.

### 7.4 Streaming embodiment

The traversal may be performed not only on-demand in response to a query but also continuously as edges arrive. In a streaming embodiment, an edge ingest event triggers re-computation of all chains that include the newly observed edge; new chains exceeding configured severity thresholds emit real-time notifications.

### 7.5 Multi-tenant embodiment

The method is multi-tenant by design. All edges, reachability entries, and chain computations are scoped by `organization_id`. A preferred embodiment enforces tenant isolation via PostgreSQL row-level security policies attached to the edge and reachability tables, ensuring that a query executed in the context of tenant T returns only chains constructed from edges visible to tenant T.

### 7.6 Confidence weighting embodiment

In an alternative embodiment, instead of (or in addition to) the categorical weakest-link bump described in Section 5.5, each edge is assigned a continuous confidence weight in the interval [0.0, 1.0] and the chain's confidence is computed as the minimum or geometric mean of edge confidences. The chain's severity may be adjusted as a continuous function of overall confidence.

### 7.7 Cost-factor freshness embodiment

In an alternative embodiment, the breach-cost factor table is refreshed automatically from authoritative public sources (IBM Cost of a Data Breach Report annual releases, Ponemon updates, etc.) and chains are versioned with the cost-factor edition used in their quantification. This enables audit-quality reproducibility: a chain computed in 2027 using 2027 cost factors can be replayed in 2030 using 2030 cost factors for trend analysis.

### 7.8 Chain dollar-deduplication embodiment

When the same terminal data classification is reached by multiple chains from the same tenant, dollar amounts must not be naively summed (this would double-count). In a preferred embodiment, an aggregation operator computes per-classification exposure as the MAXIMUM record count reached by ANY chain rather than the SUM. This aligns with realistic threat modeling: an attacker who reaches 120,000 PHI records through one chain or another reaches 120,000 records once, not 240,000.

### 7.9 Severity-matrix configurability embodiment

The default severity matrix (Section 5.5) is one preferred choice. In an alternative embodiment, the matrix is configurable per-tenant to reflect tenant-specific risk appetite. For example, a tenant in a regulated industry may configure PII-read as "critical" rather than "medium".

### 7.10 Visualization embodiments

The structured chain output is suitable for several distinct visualizations:

- **Chain list view.** Linear list of chains sorted by severity, each row displaying the hop sequence, terminal classification, dollar band, and weakest-link callout.
- **Node-and-edge graph view.** Force-directed or hierarchical layout in which agents are nodes and observed invocations are edges, colored by mechanism. Worst chains are highlighted.
- **Sankey diagram.** Cumulative flow from source agents through intermediate agents to terminal classified data classes, with band widths proportional to record counts.
- **Heat map.** Two-dimensional matrix of (source agent × terminal classification) showing chain count and worst severity per cell.

These visualizations are illustrative; the structured chain output may be rendered in many additional formats without departing from the spirit of the invention.

---

## 8. CLAIMS

### Independent claims

**1.** A computer-implemented method for computing transitive identity-to-identity blast radius in a cloud computing environment, the method comprising:

- (a) receiving, by one or more processors, a plurality of invocation edges, each invocation edge representing one autonomous agent identity invoking another autonomous agent identity, each invocation edge characterized by at least a source identity identifier, a target identity identifier, an invocation mechanism selected from a configurable mechanism catalog, and a confidence indicator selected from at least the set comprising observed, inferred, and declared;
- (b) receiving, by the one or more processors, a per-identity classified-data reachability map indicating, for each identity identifier of a corpus of identity identifiers, zero or more reachability entries each comprising a data classification, an estimated record count, and a write capability flag;
- (c) performing, by the one or more processors, a bounded breadth-first traversal of a directed graph constructed from said invocation edges, the traversal initiated at one or more designated source identity nodes, the traversal terminating at a configurable maximum traversal depth, the traversal performing cycle elimination by maintaining a per-path visited set;
- (d) at each node visited during said traversal, emitting one or more candidate transitive chains responsive to a determination that the visited node has a non-zero entry in said classified-data reachability map and that the depth of the path to said visited node is at least one;
- (e) for each emitted candidate transitive chain, determining a chain severity by:
  - (i) selecting a base severity from a configurable severity ordering, said base severity selected by indexing a configurable severity matrix by the terminal data classification of the chain and the write capability flag of the terminal reachability entry, and
  - (ii) detecting whether at least one edge in the chain has either an invocation mechanism within a configurable weak-mechanism subset or a confidence indicator equal to "inferred", and responsive to detecting at least one such edge, incrementing the chain severity by one tier within the severity ordering subject to a saturation cap at the highest severity value;
- (f) for each emitted candidate transitive chain, computing a MITRE ATT&CK technique mapping comprising at least the union of technique identifiers associated with each invocation mechanism present in the chain;
- (g) for each emitted candidate transitive chain, computing a low/mid/high estimated breach-exposure dollar band by joining the terminal data classification and terminal record count of the chain against a breach cost factor table; and
- (h) returning, by the one or more processors, a structured data response comprising the emitted candidate transitive chains together with their respective chain severities, weak-edge detection results, MITRE technique mappings, and exposure dollar bands.

**2.** A non-transitory computer-readable medium storing instructions that, when executed by one or more processors, cause the one or more processors to perform the method of claim 1.

**3.** A system comprising:

- one or more processors; and
- a memory storing instructions that, when executed by the one or more processors, cause the system to perform the method of claim 1;
- the system further comprising an edge ingestion subsystem configured to receive captured invocation evidence from one or more upstream sources selected from the group consisting of a Model Context Protocol trace collector, an Azure OpenAI request log parser, an Amazon Web Services Bedrock CloudTrail event subscriber, a customer-declared service-map parser, and an inferred shared-credential edge generator.

### Dependent claims

**4.** The method of claim 1, wherein at least one of the invocation edges is captured by parsing a Model Context Protocol (MCP) tool-call trace.

**5.** The method of claim 1, wherein at least one of the invocation edges is captured by subscribing to Amazon Web Services CloudTrail events of event name selected from the group consisting of InvokeAgent, InvokeModelWithResponseStream, and Retrieve.

**6.** The method of claim 1, wherein at least one of the invocation edges is captured by parsing Azure OpenAI Service request logs identifying a client application identifier and a dependency application identifier.

**7.** The method of claim 1, wherein at least one of the invocation edges has confidence equal to "inferred" and was generated by detecting that two distinct identity records possess overlapping authentication secret material.

**8.** The method of claim 7, wherein said overlapping authentication secret material comprises at least one of an X.509 certificate thumbprint, a federated credential identifier, and a client-secret hash.

**9.** The method of claim 1, wherein the invocation mechanism catalog comprises at least the mechanisms `mcp`, `http`, `azure_function`, `webhook`, `event_grid`, `shared_secret`, and `service_bus`.

**10.** The method of claim 1, wherein the configurable weak-mechanism subset comprises at least `shared_secret`.

**11.** The method of claim 1, wherein the severity bump described in step (e)(ii) is applied at most once per chain regardless of the number of weak edges present in the chain.

**12.** The method of claim 1, wherein the bounded breadth-first traversal applies a per-source, per-target, per-depth deduplication so that the same source-to-target chain is not emitted more than once even when multiple paths between the same source and target exist.

**13.** The method of claim 1, wherein the traversal omits emission of chains having depth zero.

**14.** The method of claim 1, further comprising, prior to step (a), storing each invocation edge with an idempotency key comprising at least an organization identifier, a source identity identifier, a target identity identifier, and an invocation mechanism, such that re-ingestion of the same edge from the same upstream source increments an observation counter rather than inserting a duplicate row.

**15.** The method of claim 1, wherein each emitted candidate transitive chain is filtered by a query-time classification parameter such that only chains terminating at a specified data classification are returned.

**16.** The method of claim 1, wherein the breach cost factor table comprises at least factors for Protected Health Information (PHI), Payment Card Industry (PCI) data, Personally Identifiable Information (PII), and financial records, with each factor associated with a citation to a publicly available industry source.

**17.** The method of claim 16, wherein the cost factors are regionally adjusted across at least the regions United States, European Union, and Asia-Pacific.

**18.** The method of claim 1, wherein the configurable severity matrix is configurable on a per-tenant basis.

**19.** The method of claim 1, further comprising, for each emitted candidate transitive chain, augmenting the MITRE ATT&CK technique mapping with a technique identifier indicative of data manipulation responsive to the write capability flag of the terminal reachability entry being true.

**20.** The method of claim 1, wherein the structured data response is rendered to a presentation layer comprising at least one of a chain list view, a node-and-edge graph view, a Sankey diagram, and a heat map.

**21.** The method of claim 1, wherein the traversal is initiated automatically in response to ingestion of one or more new invocation edges and the resulting structured data response is delivered as a real-time notification when the chain severity exceeds a configurable threshold.

**22.** The method of claim 1, wherein an aggregation operator over multiple chains terminating at the same data classification within the same tenant computes per-classification exposure as the maximum record count reached by any chain rather than the sum of record counts.

**23.** The method of claim 1, wherein the invocation mechanism catalog includes at least one mechanism specific to a Software-as-a-Service (SaaS) integration, including but not limited to Slack webhook, Jira automation rule, Salesforce flow, ServiceNow workflow, and GitHub webhook delivery.

**24.** The method of claim 1, wherein at least one source identity is a continuous-integration / continuous-deployment pipeline identity selected from the group consisting of a GitHub Actions OpenID Connect token, an Azure DevOps pipeline service principal, a GitLab CI/CD job token, and a CircleCI context-bound identity.

**25.** The method of claim 1, wherein each emitted candidate transitive chain is associated with a confidence weight computed as a function of the confidence indicators of its constituent edges.

**26.** The method of claim 25, wherein said function is one of the minimum confidence over edges, the geometric mean of edge confidences, and a Bayesian posterior over a configurable prior.

**27.** The method of claim 1, wherein the structured data response is persisted in a chain history store, and an alert is generated when a newly computed chain's severity exceeds the severity of any previously computed chain for the same source-target pair.

**28.** The method of claim 1, wherein the invocation edges are received simultaneously from at least two distinct cloud provider environments and the resulting transitive chains span the cloud provider boundary.

**29.** The method of claim 1, wherein the per-identity classified-data reachability map is itself computed by a downstream privilege analysis subsystem that evaluates the union of explicit role assignments, inherited role assignments via group membership, and just-in-time elevated assignments for each identity.

**30.** The method of claim 1, wherein the structured data response is consumed by a downstream compliance reporting subsystem that maps emitted chains to regulatory control identifiers selected from the group consisting of HIPAA §164.312, PCI DSS Requirement 7, NIST SP 800-53 AC-3, NIST AI RMF 1.0 GV-1.1, ISO/IEC 42001:2023 A.5.1, and EU AI Act Article 9.

---

## 9. INDUSTRIAL APPLICABILITY

The invention has direct industrial applicability in:

- Identity governance and administration platforms for regulated industries (healthcare, financial services, pharmaceuticals, defense);
- Cloud security posture management products serving enterprises operating in Microsoft Azure, Amazon Web Services, Google Cloud Platform, or multi-cloud configurations;
- AI security platforms providing posture management for autonomous-agent deployments;
- Insurance and reinsurance products underwriting cyber-liability coverage with exposure modeling;
- Risk-quantification and board-reporting dashboards for chief information security officers and chief risk officers;
- Compliance evidence systems for HIPAA, PCI DSS, NIST AI RMF 1.0, ISO/IEC 42001:2023, EU AI Act, GDPR, and similar regimes;
- Operational technology environments where autonomous agents control physical assets;
- Software-as-a-service vendors providing AI-agent runtime services and seeking to offer their customers customer-specific exposure quantification.

---

## 10. GLOSSARY

| Term | Definition |
|---|---|
| Autonomous agent identity | A non-human identity associated with an autonomous software agent that makes runtime decisions about tool invocation. |
| Blast radius | The scope of privileges, data, and downstream resources an adversary obtains upon compromise of an identity. |
| Chain | A sequence of one or more invocation edges connecting a source identity to a terminal identity. |
| Cycle elimination | A guarantee that no chain emitted by the traversal contains a cycle in its hop sequence. |
| Edge | A directed relationship from one identity to another via a specified invocation mechanism. |
| Inferred edge | An edge whose existence is deduced from heuristic evidence rather than direct observation. |
| Invocation mechanism | The technical means by which one agent invokes another (e.g., MCP, HTTP, message queue). |
| Multi-Hop XGRAPH | The product name of the reference implementation of this invention. |
| Non-human identity (NHI) | Any credentialed actor that is not a human user; includes service principals, managed identities, workload identities, etc. |
| Reachability map | A data structure indicating which classified data each identity can read or write. |
| Severity matrix | A configurable lookup table mapping (terminal classification, write flag) to base severity. |
| Weakest-link bump | A severity escalation applied when at least one edge in a chain has weak-mechanism or inferred confidence. |

---

## 11. PRIOR-ART CITATIONS (FOR ATTORNEY SEARCH)

The following non-exhaustive list of prior art is provided to assist the attorney's search. The inventor has reviewed each item to the extent reasonably possible without conducting a formal patent search.

- US 10,536,478 B2 — "Techniques for discovering and managing security of applications" (Symantec).
- US 11,030,320 B2 — "Detection of cyberattack on a cloud-based system" (Microsoft).
- US 10,778,711 B2 — "Method and apparatus for determining a threat using distributed trust across a network" (IBM).
- US 11,063,966 B2 — "Detecting reachability and attack surface in a cloud environment" (Twistlock / Palo Alto Networks).
- US 10,491,632 B1 — "Cloud security posture management" (Wiz).
- "BloodHound: Six Degrees of Domain Admin" — A. Robbins, R. Schroeder (2016) — DEF CON 24.
- "Identity-Based Attack Path Analysis in Cloud Environments" — M. Tronche et al., arXiv:2208.XXXXX (2022).
- Microsoft Entra ID Privileged Identity Management documentation (Microsoft Corp.).
- AWS IAM Access Analyzer documentation (Amazon Web Services).
- BloodHound Enterprise — SpecterOps Inc., commercial product.
- Anthropic Model Context Protocol specification (anthropic.com/mcp).

The attorney is requested to conduct a comprehensive USPTO and Google Patents search using at least the following query terms:

- "transitive identity blast radius"
- "service principal blast radius"
- "AI agent chain attack"
- "MCP attack path"
- "non-human identity blast radius"
- "multi-hop identity reachability"
- USPTO classification 726/22 (cybersecurity — attack-graph computation)
- USPTO classification 726/23 (cybersecurity — credential and identity management)

---

## 12. CUSTODY OF INVENTION

The following items establish custody of invention as of the dates indicated:

| Item | Date | Reference |
|---|---|---|
| Initial implementation of trace_multihop function | 2026-06-04 | Git commit `fe65b85` in repository `nexgenixlabs/auditgraph`, file `backend/app/engines/ai/multihop_xgraph.py` |
| Schema migration for `agent_invocations` table | 2026-06-04 | Git commit `fe65b85`, file `backend/migrations/208_agent_invocations.sql` |
| Reference implementation of `_enrich_chain` (severity scoring + weakest-link detection) | 2026-06-04 | Git commit `fe65b85`, file `backend/app/engines/ai/multihop_xgraph.py` lines 269–354 |
| Live demonstration | 2026-06-04 onwards | https://dev.app.auditgraph.ai/ai-attack-paths/multi-hop |
| Validation suite | 2026-06-04 | `/tmp/validate_tier3_1.sh` — 12 of 12 checks pass |
| Outline patent draft (superseded by present document) | 2026-06-05 | `docs/AG_PATENT_DRAFT_MULTIHOP_XGRAPH_2026_06_05.md` |
| Production hardening with foreign-key constraints and row-level security | 2026-06-05 | Git commits `788a3ae`, `211_rls_on_tier_t1_t4_tables.sql`, `212_foreign_keys_new_tables.sql` |
| AI-classification gate fix | 2026-06-05 | Git commit `e9ad576` |

---

## 13. PROCESS NOTES FOR THE IP ATTORNEY

The following process notes are provided to expedite the attorney's preparation of the formal filing.

1. **Provisional filing strategy.** The inventor intends to file a US Provisional Application initially, with intent to file a corresponding non-provisional and Patent Cooperation Treaty (PCT) application within twelve months. The provisional application should be filed promptly to establish priority date as of the earliest practical date.

2. **Foreign filing.** Markets of strategic interest beyond the United States include the United Kingdom, the European Patent Office (covering France, Germany, the Netherlands, and other EPC member states), Israel, India, and Singapore. PCT national-phase entries in these jurisdictions are anticipated.

3. **Trademark filings.** Concurrent with the provisional application, file trademark applications for:
   - "**Identity Security Graph**" (Classes 9 and 42) — primary product category.
   - "**Multi-Hop XGRAPH**" (Class 9) — feature name; assess inherent registrability given XGRAPH variant.
   - "**Argus**" (Classes 9 and 42) — only if conflict-clear after a search; Argus is a common name.

4. **Defensive publications.** Consider publishing a defensive publication for the broader edge-ingestion framework once the provisional priority date is established, to forestall third-party patents on related variants.

5. **Continuation strategy.** Anticipate at least one continuation application focused specifically on the weakest-link bump mechanism, as that aspect appears distinctive in the prior-art landscape.

6. **Inventorship.** Sole inventor as of this draft. If additional inventors join the project, inventorship may need amendment under the proper duty of disclosure.

7. **Assignment.** Inventor's employment is with Nexgenix Labs; standard invention-assignment agreement governs. Confirm assignment is on file before filing.

8. **Document hygiene.** All references in this document to specific company names (Microsoft, Amazon Web Services, Google Cloud Platform, Anthropic, Lakera AI, etc.) and specific product names (Bedrock Guardrails, Azure Content Safety, NeMo Guardrails, etc.) are descriptive references to publicly available products and are intended to be illustrative rather than limiting. The claims should be drafted to cover equivalents.

9. **Continuation-in-part anticipated.** Significant additional embodiments are likely as the system evolves over the next twelve months. Plan for a continuation-in-part filing prior to PCT national-phase entry.

10. **Engagement budget.** Inventor has authorized $15,000 to $20,000 USD for provisional drafting, filing, and initial prosecution. PCT and national-phase budgets will be authorized separately based on commercial traction.

---

## 14. RELATED FILINGS AND DOCUMENTS

- `docs/AG_FINAL_IA_AND_BRAND_2026_06_05.md` — strategic positioning document referencing this invention as the patent-priority differentiator.
- `docs/AG_PROD_READINESS_PENTEST_2026_06_04.md` — internal pentest report confirming production readiness of the reference implementation.
- `docs/AG_SOC2_CONTROL_MAP_2026_06_05.md` — SOC 2 control mapping document; the present invention satisfies control CC6.1 ("logical access") in the context of NHI governance.
- `docs/AG_CASE_STUDY_TEMPLATE_2026_06_05.md` — customer case study template for documenting commercial traction in support of future continuation filings.

---

## 15. CONFIDENTIALITY NOTICE

This document constitutes confidential and proprietary information of Nexgenix Labs. Disclosure outside the inventor, the inventor's IP counsel, and authorized personnel of Nexgenix Labs is prohibited until the provisional application is filed and a priority date is established. Once filed, the inventor may make limited public references to the invention for marketing purposes, but the detailed enabling disclosure herein should not be made public until the provisional application has been published or the inventor and counsel have specifically authorized public disclosure.

---

**END OF SPECIFICATION**

*Prepared by: Bhupathi Reddy Sangabattula (sole inventor), with assistance from AuditGraph internal documentation tooling*
*For attorney review and formal preparation prior to filing.*
*Document version 1.0 — 2026-06-05*
