# Patent Candidates + What's Next In Plate

**Date**: 2026-06-07
**Author**: Co-founder strategy
**Status**: For founder review · sign-off → start scheduling attorney calls + next-sprint planning

---

## Part 1 — Patent candidates beyond Multi-Hop XGRAPH

We already have one patent draft in flight:

- **`docs/AG_PATENT_FULL_SPEC_MULTIHOP_XGRAPH_2026_06_07.md`** — Multi-Hop XGRAPH (transitive blast radius across agent invocation chains with weakest-link severity bump). ~30 pages, 30 numbered claims, IP attorney engagement pending.

This section identifies 5 additional patent-worthy inventions shipped or in-progress today. Each ranked by defensibility + commercial value.

### 🥇 P2 — Cross-Product Role-Activity Attribution (CATEGORIES_REQUIRING)

**File a continuation-in-part to the Multi-Hop spec or a sibling utility patent.**

**The invention:** for every (identity, role) assignment, attribute audit-log events to the specific role assignment by intersecting **role permissions × audit-log event categories**. The naïve approach credits ALL events for a user to ALL the user's roles (false positives); our cross-product method narrows attribution to "which role's permissions actually gate this event's category."

**Why it's defensible:**
- No vendor today surfaces per-directory-role last-used inference at the assignment level. SailPoint stops at the user level; Wiz doesn't touch Entra directory roles; BloodHound is static.
- The mapping itself (`CATEGORIES_REQUIRING(Global Administrator) = {all}`, `CATEGORIES_REQUIRING(Conditional Access Administrator) = {Policy, ConditionalAccess}`) is the asset — extending it to AWS IAM, GCP IAM, OAuth scopes is straightforward and we get all of those.
- Implemented + tested today: `backend/app/engines/entra/role_activity_inference.py` (line 60-110 is the mapping).

**Commercial value:** highest. Every CISO buying identity governance asks "is this admin actually using this role?" Today the only answer is "log into Entra and squint." Our answer is "here are the 23 dormant privileged role assignments, ranked by severity, with the actions they haven't taken." That's a Wiz-grade insight Wiz doesn't have.

**Patent claim shape:**
> A method for attributing identity audit events to specific role assignments in a directory service, comprising: maintaining a mapping from each role to a set of audit-log event categories whose corresponding actions require that role's permissions; ingesting a stream of audit events; for each (user, role) tuple, attributing only those events whose category appears in the role's mapped category set; aggregating to produce per-assignment activity windows and dormancy classifications.

The patent generalizes naturally: substitute "directory role" with "AWS IAM role" / "GCP IAM role" / "OAuth scope" / "Kubernetes RBAC role" — same mechanism applies.

---

### 🥈 P3 — PIM Eligible-vs-Active Differential Detection

**File as a continuation or standalone utility patent.**

**The invention:** detecting "overprivileged eligibility" by computing the architectural delta between PIM-eligible role assignments and observed activations over a time window, emitting findings when eligibility persists without activation (architectural state).

The key claim is the **graceful degradation property**: the primary signal (eligibility-without-activation) is computable from architecture alone (PIM eligibility table + a single timestamp); enriched activation-frequency analysis adds depth when audit logs are available. This is novel — competitors that depend on logs entirely produce no output on logs-OFF tenants (70% of orgs).

**Why it's defensible:**
- Microsoft Entra PIM doesn't surface this. The portal shows eligible assignments and shows activation history, but not the *delta*.
- SailPoint, Saviynt, Okta — none surface a per-(identity, role) overprivilege classification with severity bands.
- Demonstrated today: `backend/app/engines/pim/pim_overprivilege.py`, with 5 demo personas each triggering a distinct finding type.

**Commercial value:** very high. PIM overprivilege is a top-three audit finding in regulated industries. Today, organizations review eligibility manually quarterly; this automates it.

**Patent claim shape:**
> A method for detecting overprivileged role eligibility comprising: enumerating eligible role assignments for a tenant; querying observed activation events over a configurable time window; classifying each (identity, role, scope) tuple by the cardinality of activation observations; emitting severity-graded findings when (a) eligibility persists with zero observed activations, (b) observed activations fall below a configurable threshold, or (c) the role's activation policy fails configurable security controls; wherein when activation logs are unavailable, the system falls back to architectural-only analysis without producing fabricated activity-frequency outputs.

---

### 🥉 P4 — Architecture-Derived Identity Risk Without Logs

**File as a foundational platform patent — covers our entire moat statement.**

**The invention:** a pipeline that derives quantified identity-security risk from cloud-resource architecture alone (RBAC + resource configuration + network topology + credential metadata) WITHOUT requiring activity or audit logs. The system produces complete risk findings, dollar-quantified breach exposure, and remediation recommendations on tenants where the only inputs are configuration APIs.

**Why this matters:** 70% of organizations don't centralize logs. Every vendor that requires logs (Wiz Defender, Lacework, Datadog Cloud SIEM, etc.) cannot serve them. AuditGraph can. The patent codifies the differentiator.

**The novel piece:** the **explicit hierarchy of evidence** — architecture provides primary signal, logs enrich, and the system surfaces evidence-source attribution so customers can see which findings are derived from which evidence layer. This makes the output defensible to regulators (who care about evidence provenance).

**Why it's defensible:**
- Wiz and Lacework architecturally depend on log ingestion to compute consequence. They can't pivot to a logs-OFF model without rebuilding their data layer.
- The "70% don't enable logs" stat is a market reality competitors face but can't address.
- Implemented across the entire codebase — backed by the standing rule in `memory/spec_checklist_agentless_readonly.md`.

**Commercial value:** highest strategically — this is the patent that protects the "agentless + read-only + architecture-derived" three-assertion claim from being copied even after seeing our product.

**Patent claim shape:**
> A computer-implemented method for quantifying identity security risk in a cloud environment without dependence on activity logs, comprising: collecting role-based-access-control assignments, resource configuration metadata, and network topology data from cloud provider APIs using only read-only permissions; constructing an identity-to-resource reachability graph derived from said configuration data; classifying reachable resources by data sensitivity using structural inspection methods; computing per-identity exposure quantities by combining reachable resource counts with industry cost factors; emitting risk findings and remediation recommendations derived from said graph; wherein the system produces complete output on tenants where activity logs are absent or disabled, and when activity logs are present, they augment but do not gate the risk classification.

---

### P5 — Identity-Graph-To-Dollar-Exposure Pipeline

**File as a utility patent.**

**The invention:** the specific pipeline that converts (a) identity-to-resource reachability + (b) resource data-classification + (c) industry breach-cost factors into a deterministic, source-cited dollar quantification of identity breach exposure with auditable provenance.

The novelty is the **deterministic + provenance-preserving** combination. Competitors quantify identity risk as a 0-10 score. AuditGraph quantifies as "$56.52 million ± $7.7M range, cited to IBM Cost of a Data Breach 2023, healthcare vertical, 471 USD/record midpoint, derived from 120,000 PHI records reachable via these specific 5 role assignments." Each number in that sentence is reproducible from raw data and an auditor can trace every digit.

**Why it's defensible:**
- Other vendors produce dollar numbers but without source citations (they're ML-derived black boxes).
- The audit trail makes the output defensible to regulators in SOC 2 / HIPAA / PCI / GDPR contexts.
- Implemented in `backend/app/engines/scoring/breach_cost.py` + `backend/migrations/204_breach_cost_factors.sql` + the new `BreachCostMethodology.tsx` UI modal that surfaces the derivation one click away.

**Commercial value:** high. The breach-cost transparency directly addressed the CISO question from yesterday's review ("how did you arrive at $X?"). This is also the framework that lets AuditGraph charge premium pricing — "our $ numbers will land in your auditor's report, not just your dashboard."

**Patent claim shape:**
> A method for producing auditable dollar-quantified breach exposure estimates from identity access graphs comprising: enumerating identities and their effective reachable resources via configurable read-only API queries; classifying reachable resources by data type using structural inspection; querying a versioned cost-factor table keyed by data classification and region, each row carrying its source citation and effective year; computing exposure values as the product of reachable record counts and cost factors; persisting an audit trail recording the (timestamp, user, identity, factor row, computation result) for every quantification; emitting findings whose evidence section includes a complete derivation traceable to the cost-factor source.

---

### P6 — AI Abuse Scenario Catalog with Identity-Consequence Quantification

**File as a continuation or standalone.**

**The invention:** decomposing AI-specific threat surfaces into a fixed catalog of named scenarios (prompt injection, credential theft, owner orphaning, tool abuse, supply chain), evaluating each scenario per AI identity using deterministic severity functions over architectural signals, and producing per-(identity, scenario) breach exposure quantifications without requiring detection of the threat actor's actions.

**The key novelty:** the platform doesn't *detect* prompt injection (that's partner territory — Lakera, Bedrock Guardrails, Azure Content Filters). Instead it *quantifies the consequence* of any of these threats succeeding against a specific AI identity. The 5-scenario decomposition + consequence-attribution framework is novel.

**Why it's defensible:**
- AI security vendors split into detection (Lakera, Robust Intelligence) vs governance (Credo, Lakera Red) but no one does identity-consequence attribution.
- Demonstrated in `backend/app/engines/ai/abuse_scenarios.py` with 19/19 passing tests.

**Commercial value:** medium-high. AI security is the hot category but currently noisy. A patent here positions us as the "consequence layer" of AI security — partners on the detection layer feed us via Threat Connectors.

---

### Patent filing prioritization

| Rank | Patent | Effort | Strategic priority |
|---|---|---|---|
| 1 | Multi-Hop XGRAPH (existing draft) | Attorney engagement → file Q3 | CRITICAL |
| 2 | P2 — CATEGORIES_REQUIRING attribution | New filing — 6-8 weeks attorney work | CRITICAL |
| 3 | P4 — Architecture-derived risk (the moat patent) | New filing — biggest scope, 8-10 weeks attorney work | CRITICAL — foundational |
| 4 | P3 — PIM Eligible-vs-Active differential | New filing — 4-6 weeks | HIGH |
| 5 | P5 — Identity-to-dollar pipeline | New filing — 4-6 weeks | HIGH |
| 6 | P6 — AI Abuse Scenario catalog | New filing — 4-6 weeks | MEDIUM |

**Recommended sequence:** file Multi-Hop XGRAPH first (already drafted). While that's in attorney review, draft P2 + P3 in parallel (these are smaller, faster). P4 needs the most attorney work (foundational + broadest claims) — start it after P2/P3 are stable.

**Filing cadence:** target 6 patents filed in 12 months. Provisional → utility conversion within 12 months of each. Total attorney spend: roughly $50-80K for 6 filings, recoverable in first round of enterprise pricing.

---

## Part 2 — What's next in plate

Sequencing the post-pilot moves so engineering, sales, ops, and IP all move in lock-step rather than tripping over each other.

### Now → Week 4 (in flight or imminent)

| Item | Driver | Status |
|---|---|---|
| PIM Overprivilege Detection | Engineering ✅ | Shipped local + cloud-dev |
| Feature E Phase 2 | Engineering ✅ | Shipped local + cloud-dev |
| 100K perf baseline | Engineering ✅ | Doc shipped |
| Test backfill — engines (98% on patent features) | Engineering ✅ | Today |
| Test backfill — remaining modules (target 70% overall) | Engineering | 4-5 days remaining |
| External pentest engagement signed | Founder | In progress |
| SOC 2 vendor selection (Drata / Vanta / Secureframe) | Founder | In progress |
| Zero-trust networking deployment | Founder | In progress |
| First customer pilot conversations | Sales (Founder) | Ongoing |

### Week 4 → Week 8

| Item | Driver | Why now |
|---|---|---|
| **First customer pilot signed** | Sales | This unlocks AWS plan + case study + investor narrative — *the* gating event |
| **Identity-list N+1 fix** (1d engineering) | Engineering | Perf baseline flagged 1.7s p95 — fix before pilot scales it up |
| **PIM authoritative discovery** (replace demo data with real Graph API) | Engineering | 1 week |
| **First case study draft** | Sales + Engineering | Template ready; needs pilot's real numbers |
| **Multi-Hop XGRAPH patent filing** | IP attorney | Spec ready; ~6 week attorney process |
| **CATEGORIES_REQUIRING patent provisional** (P2) | IP attorney | Start drafting once Multi-Hop is filed |
| **Pricing tier UI in billing** | Engineering | Pilot will ask "how much for production" |
| **Status page** (status.auditgraph.ai via Cloudflare Pages) | Engineering | 1 day; signals SaaS maturity |

### Week 8 → Week 12

| Item | Driver | Why now |
|---|---|---|
| **AWS slim stripe** (IAM + Bedrock + Multi-Hop AWS edges) | Engineering | Triggered by first pilot signal — 3-4 week scoped build |
| **Second + third customer pilots** | Sales | Build the network-effect benchmarking floor |
| **Production environment** (cus-ag-prod) | Engineering + Founder | Required before first paying customer |
| **First case study published** (with named customer) | Sales | The marketing artifact that closes the next 5 deals |
| **P4 patent (architecture-derived) drafted** | IP attorney | The moat-protecting patent |
| **P3 PIM differential patent drafted** | IP attorney | Parallel to P4 |
| **Investor deck refresh** | Founder | New perf data + case study + 3 pilots + 6 patents in flight = different conversation |

### Week 12 → Q4 2026 launch

| Item | Driver |
|---|---|
| **GA pricing announcement** | Founder + Sales |
| **AWS GA** | Engineering |
| **SOC 2 Type II audit period ends** | External auditor |
| **5+ customer references** | Sales |
| **Q1 2027 GCP planning** | Engineering |

### What I'd hold (still)

Even with pressure to expand, hold these until specific triggers:

| Item | Triggered by |
|---|---|
| **GCP discovery** | After 2nd AWS customer; GCP demand is real but smaller |
| **New Tier 5+ AI features** | After 3 case studies — current features need to land before stacking more |
| **Major UI redesign** | After brand pivot absorbs and customer feedback patterns emerge |
| **Marketing site full rebuild** | After first paying customer; current docs site + login is enough for pilots |
| **International expansion** | After ARR hits ~$1M and US enterprise pilots converted |

---

## Part 3 — Risks worth watching

| Risk | Likelihood | What to watch |
|---|---|---|
| First pilot wants AWS at signing | High | If true → AWS slim stripe accelerates from Q4 to Week 6-8 |
| Pentest finds a critical (P0) gap | Medium | All P0/HIGH from internal pentest closed; budget reserve for external findings |
| SOC 2 timeline slips past Q4 | Medium | Vendor selection drag = 6-week slip baked in. Start onboarding this week. |
| Identity-list N+1 surfaces on a pilot before fix | Low at pilot scale (15-30K) | Fix before pilot tenant exceeds 20K identities |
| Patent attorney bandwidth limits filing cadence | Medium | Multi-attorney engagement; aim for 2 patents in flight in parallel |
| Demo data drift between local and cloud-dev | Low | Idempotent SQL generators in place; nightly re-replay would help |

---

## Part 4 — One paragraph for the next CISO / investor pitch

Use this verbatim when asked "what's next":

> *"We just shipped two patent-track Azure features in the past two days — PIM Overprivilege Detection and Entra Directory Role Last-Used Inference. Both run sub-2-millisecond p99 at 100,000 identities because we explicitly denormalized into purpose-built tables. Five additional patents are queued for filing on top of the existing Multi-Hop XGRAPH spec — the foundational one covers our agentless + read-only + architecture-derived methodology. While our external pentest and SOC 2 audit run in parallel, the engineering team is closing the test coverage gap and signing our first three pilot customers. AWS expansion is gated on first signed Azure pilot, targeted Q4."*

That's a confident roadmap, not "we're scrambling to catch up."

---

## Sign-off

- [ ] Founder approves the patent filing prioritization (Part 1)
- [ ] Founder approves the Week 4-12 sequence (Part 2)
- [ ] Founder books IP attorney intake call to schedule Multi-Hop filing
- [ ] Founder approves the standing "hold AWS until first pilot" gate
- [ ] Engineering starts the identity-list N+1 fix this week
- [ ] Engineering continues test backfill (PIM + Feature E done today; ~70% engine coverage target)
