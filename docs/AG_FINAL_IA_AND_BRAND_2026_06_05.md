# AuditGraph — Final Information Architecture + Brand (Peer Review v2)

**Date**: 2026-06-05
**Status**: Founder-approved architecture; ready to execute
**Supersedes**: `AG_PATH_TO_10_10_2026_06_05.md` (the AI/NHI split was wrong)

---

## 1. The fixed mental model

The previous plan made `NHI` and `AI Identity` peer sections. That was wrong because **AI agents ARE NHIs** — they're a sub-type with extra metadata, not a separate category. The right Gartner-aligned taxonomy has only 2 identity branches:

```
Identities
├── Human Identities
│   └── (users, contractors, partners)
└── Non-Human Identities (NHI)
    ├── Service Principals
    ├── Managed Identities (system + user-assigned)
    ├── Workload Identities (AKS pods, GitHub Actions OIDC, Terraform)
    ├── CI/CD Identities (Azure Pipelines, GitLab CI/CD)
    ├── API-based Identities (PATs, OAuth apps, API keys)
    └── AI Agent Identities ◄── a SUBTYPE, not a peer
```

The other thing the platform owns — **AI Runtime / Workload concerns** — isn't an identity category at all:

```
AI Runtime (workload layer, not identity)
├── Model Registry (which models, approval workflow)
├── Supply Chain (model + plugin + vector DB + external API tree)
├── Threat Connectors (Lakera/Bedrock/etc. signal ingestion)
└── AI Findings (catalog of AI-specific detections)
```

These are about **what the AI is doing**, not **who the AI is**.

---

## 2. Brand

| Property | Value |
|---|---|
| **Product** | AuditGraph |
| **Category** | **Identity Security Graph™** |
| **Tagline (homepage)** | **Identity Security for the AI Era** |
| **Longer pitch** | The Identity Security Graph for Humans, NHIs, and AI |
| **One-sentence elevator** | AuditGraph is the Identity Security Graph that continuously maps human, non-human, and AI identities to the data, permissions, and attack paths they can reach. |
| **AI analyst** | Argus (unchanged) |
| **Argus tagline** | Argus sees what your logs miss (unchanged) |

Brand promise = **graph**. Everything in the platform IS a graph:
- Identity Graph
- Access Graph
- AI Graph
- Attack Graph
- Multi-Hop XGRAPH
- Supply Chain Graph

The category name "Identity Security Graph" is unique, defensible, and ties together what the product literally does.

---

## 3. Final sidebar — complete navigation

Every existing page is placed. Every new capability has a slot. AI is the **wedge**, identity is the **platform**.

```
══════════════════════════════════════════════════════════════════════════
  COMMAND CENTER                                       (operational+exec)
──────────────────────────────────────────────────────────────────────────
  ├── Executive Posture           ⭐ KPI roll-up across all identity types
  ├── Board Scorecard             ⭐ CEO/CFO/audit-committee view
  ├── Risk Monitoring
  ├── Drift Analysis
  ├── Findings                    (renamed from "Security Findings" — broader)
  ├── Remediation Plan
  └── Change Control Center

══════════════════════════════════════════════════════════════════════════
  IDENTITY SECURITY                          (the platform — all 3 types)
──────────────────────────────────────────────────────────────────────────
  Each page works for Human / NHI / AI via a type filter at the top.
  ├── Identity Inventory          unified — was Identity Explorer + AI Inventory
  ├── Identity Access             unified — was Access Graph + AI Access
  ├── Identity Trust Score        ⭐ NEW name (was "Risk Score") — 9 dims per type
  ├── Identity Lifecycle          unified — JML for Human + NHI + AI
  ├── Identity Governance         unified — policy + ownership + certification
  └── Ownership Center            ⭐ NEW — the SailPoint money (Gap 1)

══════════════════════════════════════════════════════════════════════════
  IDENTITY TOPOLOGY                                   (graph-based views)
──────────────────────────────────────────────────────────────────────────
  ├── Identity Graph              (relationships)
  ├── Access Graph                (identity → resource)
  ├── Multi-Hop XGRAPH            ⭐ PATENT MOAT (Agent → Agent → Resource)
  ├── Role Optimization
  └── PIM & Just-in-Time

══════════════════════════════════════════════════════════════════════════
  ATTACK SURFACE                              (cross-cutting attack views)
──────────────────────────────────────────────────────────────────────────
  ├── Attack Paths                (general — human + NHI + AI chains)
  ├── Data Reachability           ⭐ "strongest differentiator" per reviewer
  ├── AI Attack Paths             (AI-specific cinematic chain)
  └── Attack Simulator

══════════════════════════════════════════════════════════════════════════
  AI SECURITY                              (AI WORKLOAD — not AI identity)
──────────────────────────────────────────────────────────────────────────
  ├── AI Runtime                  (overview / health)
  ├── Model Registry              (AG-T2.2 — approval workflow)
  ├── AI Supply Chain             (AG-T3.2 — model+plugin+vector+API tree)
  ├── Threat Connectors           (AG-T4 — partner ingest framework)
  ├── AI Findings                 (AG-T2.3 — catalog with workflow)
  └── AI Abuse Scenarios          ⭐ promote AG-T2.1 to its own page

══════════════════════════════════════════════════════════════════════════
  ARGUS                                                 (the AI analyst)
──────────────────────────────────────────────────────────────────────────
  └── Argus Analyst               (spans all identity types + workload)

══════════════════════════════════════════════════════════════════════════
  GOVERNANCE & ASSURANCE                       (compliance + audit + reports)
──────────────────────────────────────────────────────────────────────────
  ├── Compliance Posture
  ├── Compliance Evidence         (NIST AI RMF / ISO 42001 / EU AI Act / SOC2 / HIPAA / PCI)
  ├── Access Reviews
  ├── Activity Timeline
  ├── Peer Benchmarking           ⭐ NEW (network-effect moat — Gap 5)
  └── Reports & Exports

══════════════════════════════════════════════════════════════════════════
  PLATFORM                                                (admin / setup)
──────────────────────────────────────────────────────────────────────────
  ├── Connectors                  (Azure, AWS, GCP, GitHub, Terraform Cloud, …)
  ├── Team Members
  ├── Audit Log
  └── Settings

══════════════════════════════════════════════════════════════════════════
  BILLING                                              (admin only)
──────────────────────────────────────────────────────────────────────────
  ├── Billing Overview
  └── Subscriptions
```

**Total: 9 top-level sections** (was 10 — merged Board + Observability + Evidence → Governance & Assurance and into Command Center).

### Section-by-section rationale

| Section | Rationale |
|---|---|
| **Command Center** | Operational + executive landing. Board Scorecard moved up here because that's where CEOs look. |
| **Identity Security** | The platform. Filter-driven: same page shows Human / NHI / AI. Each row is a per-identity job (inventory → access → trust → lifecycle → governance → ownership). |
| **Identity Topology** | Graph-based analytical surfaces. Multi-Hop XGRAPH lives here because it's a **graph view**, not an attack surface (although it adjacents). |
| **Attack Surface** | Cross-cutting attack analytics. Data Reachability stays here because it answers "what can the worst attacker reach", not "who owns this identity". |
| **AI Security** | The AI **workload** layer. No identities live here — these are about models, plugins, supply chain, threat ingestion, AI-specific findings. |
| **Argus** | Cross-cutting analyst. Promoted top-level because it answers questions across all layers. |
| **Governance & Assurance** | Evidence + audit + benchmarking. Peer Benchmarking lives here because it IS evidence ("12th percentile of healthcare peers"). |
| **Platform / Billing** | Standard SaaS admin. |

---

## 4. Page-level mapping (every URL keeps working)

| Current URL | New section | New label |
|---|---|---|
| `/` | Command Center | Executive Posture |
| `/command-center` | Command Center | Command Center |
| `/dashboard` | Command Center | Risk Monitoring |
| `/drift-analysis` | Command Center | Drift Analysis |
| `/security-findings` | Command Center | Findings |
| `/remediation` | Command Center | Remediation Plan |
| `/remediation-queue` | Command Center | Change Control Center |
| `/board-scorecard` | Command Center | Board Scorecard |
| `/identity-explorer` | Identity Security | Identity Inventory (with type tabs) |
| `/ai-inventory` | Identity Security | Identity Inventory (?type=ai) |
| `/access-graph` | Identity Topology | Access Graph |
| `/identity-graph` | Identity Topology | Identity Graph |
| `/role-mining` | Identity Topology | Role Optimization |
| `/ai-access` | Identity Security | Identity Access (?type=ai) |
| `/ai-risk` | Identity Security | Identity Trust Score (?type=ai) |
| `/ai-lifecycle` | Identity Security | Identity Lifecycle (?type=ai) |
| `/ai-governance` | Identity Security | Identity Governance (?type=ai) |
| `/ownership-center` ⭐ NEW | Identity Security | Ownership Center |
| `/ai-runtime` | AI Security | AI Runtime |
| `/ai-runtime/model-registry` | AI Security | Model Registry |
| `/ai-runtime/supply-chain` | AI Security | AI Supply Chain |
| `/ai-runtime/threat-connectors` | AI Security | Threat Connectors |
| `/ai-findings` | AI Security | AI Findings |
| `/ai-abuse-scenarios` ⭐ NEW page | AI Security | AI Abuse Scenarios |
| `/attack-paths` | Attack Surface | Attack Paths |
| `/ai-risk/attack-paths` | Attack Surface | AI Attack Paths |
| `/ai-attack-paths/multi-hop` | Identity Topology | Multi-Hop XGRAPH |
| `/ai-access/data-reachability` | Attack Surface | Data Reachability |
| `/attack-simulator` | Attack Surface | Attack Simulator |
| `/argus` | Argus | Argus Analyst |
| `/compliance-posture` | Governance & Assurance | Compliance Posture |
| `/compliance` | Governance & Assurance | Compliance Evidence |
| `/access-reviews` | Governance & Assurance | Access Reviews |
| `/ai-runtime/activity` | Governance & Assurance | Activity Timeline |
| `/peer-benchmarking` ⭐ NEW | Governance & Assurance | Peer Benchmarking |
| `/reports` | Governance & Assurance | Reports & Exports |
| `/settings/connections` | Platform | Connectors |
| `/organization/users` | Platform | Team Members |
| `/activity` | Platform | Audit Log |
| `/settings/general` | Platform | Settings |
| `/billing` | Billing | Billing Overview |
| `/subscriptions` | Billing | Subscriptions |

**Zero URL breakage. All renames are label-only.** Anything new gets a fresh URL.

---

## 5. Complete improvement summary — what we're doing and why

### A) Brand & positioning (1 week)

| Change | Why |
|---|---|
| Category: "Identity Security Graph™" | Matches the product literally; no peer competing for this exact phrase |
| Tagline: "Identity Security for the AI Era" | AI is the wedge; identity is the platform |
| Remove all "AI Security" implications of prompt-injection detection | We quantify impact; partners detect content |
| Argus stays | Already on-brand and unique |

### B) Information architecture (1 week)

| Change | Why |
|---|---|
| 9 top-level sections (above) | Clear, non-overlapping, Gartner-aligned |
| Identity Security unifies Human + NHI + AI via type filter | AI is a subtype, not a peer |
| AI Security = workload only (no identities) | Eliminates "wait, isn't an AI agent just an SPN?" buyer question |
| Multi-Hop XGRAPH moves to Identity Topology | It's a graph view, not just an attack surface |

### C) New capabilities (6 weeks)

| Capability | What | Sprint | Effort |
|---|---|---|---|
| **Trust Score (universal)** | Apply existing 9-dim engine to ALL NHIs + design Human dims (MFA, password age, role drift). Rename "Risk Score" → "Trust Score". Add `Trust < 50` filter everywhere. | 1 | 5 days |
| **Executive language pass** | Every KPI converted from architect→CISO ("13 agents" → "7 NHIs can reach PHI · $81.6M exposure · top fix saves $56.5M") | 1 | 5 days |
| **Ownership Center** | Assign / delegate / manager-approval / certification campaigns / exception inbox. SailPoint-tier governance. | 2 | 1.5 weeks |
| **Identity Inventory unification** | One page with Human / NHI / AI tabs, columns adapt by type. AI Inventory becomes a saved view. | 2 | 1 week |
| **Identity Lifecycle unification** | JML for all 3 types. Human JML is new; NHI JML extends current AI Lifecycle. | 3 | 1.5 weeks |
| **Identity Governance unification** | Policy + ownership + certification engine generalized | 3 | 1 week |
| **AI Abuse Scenarios page** | Promote AG-T2.1 from drawer-only to its own page (5 scenarios + org rollup) | 3 | 3 days |
| **Peer Benchmarking** | Anonymized percentile bands per metric × industry × org size. Network-effect moat. | 4 | 1 week |
| **NHI Coverage expansion** | GitHub Actions OIDC, Terraform Cloud, AKS Workload Identities, Azure Pipelines, GitLab CI/CD discovery | 4 | 2 weeks |

### D) Production readiness P1s (2 weeks, can run in parallel)

From `AG_PROD_READINESS_PENTEST_2026_06_04.md`:

| Item | Effort |
|---|---|
| C-3: Test coverage for 7 Tier 1-4 modules | 3 days |
| C-4: PR-gate runs pytest + eslint + migration smoke | 1 day |
| C-6: Default-strip PII from `threat_signals.evidence.raw` | 1 day |
| H-2: HMAC verification on inbound partner webhooks | 1 day |
| H-3: N+1 batching in 2 rollup functions | 1 day |

### E) Defensibility (in parallel — long lead time)

| Item | Effort |
|---|---|
| Patent filing #1: Multi-Hop XGRAPH (Agent → Agent → Resource transitive blast radius) | $15-20k legal + 6 months |
| Patent filing #2: Per-role last-used inference from ARM + auditLogs | $15-20k legal + 6 months |
| Patent filing #3: Cross-cloud identity attack graph composition | $15-20k legal + 6 months |
| External pentest (Trail of Bits / NCC Group) | $25-40k + 4-6 weeks |
| SOC 2 Type II evidence collection | rolling, controls already exist in `compliance` table |
| 3 design partner case studies | depends on customer pilots |

### F) UI/UX polish (2 weeks)

| Item | Effort |
|---|---|
| Progressive scan animation (hero moment) | 3 days |
| Attack-path animation (hero moment) | 3 days |
| Eliminate `alert()` → toast component | 1 day |
| Accessibility pass (ARIA, keyboard nav) | 2 days |
| Mobile-responsive exec view | 3 days |

---

## 6. Sequenced 8-week plan

### Week 1 — Brand + IA pivot (zero risk, fully reversible)

- ✅ New brand: "Identity Security Graph"
- ✅ New tagline: "Identity Security for the AI Era"
- ✅ Sidebar reorg to 9 sections (label + group changes; URLs unchanged)
- ✅ Trust Score rename in UI (Risk Score → Trust Score)
- ✅ Marketing copy sweep removing "we detect prompt injection"

### Week 2 — Trust Score (universal) + Exec language

- Apply 9-dim Trust Score to all NHI types (engine already exists; just unhide for non-AI)
- Design 5-dim Trust Score for humans (MFA, password age, last login, role drift, PIM hygiene)
- Executive language pass: every dashboard KPI rewritten
- "Trust < 50" filter on every list

### Weeks 3-4 — Ownership Center + Inventory unification

- Build Ownership Center (schema + UI)
- Unify Identity Inventory page (Human / NHI / AI tabs)
- Migrate AI Inventory to saved-view of unified inventory

### Weeks 5-6 — Lifecycle + Governance + AI Abuse Scenarios page

- Identity Lifecycle (JML) generalized — Human + NHI
- Identity Governance generalized (policy + cert)
- Promote AI Abuse Scenarios from drawer to dedicated page
- Close C-3 (tests) + C-4 (CI gates) from prod-audit

### Week 7 — Peer Benchmarking + NHI coverage (parallel)

- Peer Benchmarking page + nightly aggregate job
- Begin NHI expansion: GitHub Actions OIDC + Terraform Cloud (first 2 of 5 platforms)
- Close C-6, H-2, H-3

### Week 8 — Polish + defensibility kickoff

- Hero moments: progressive scan + attack-path animations
- Accessibility + mobile + alert() removal
- Engage IP attorney for 3 patent filings
- Engage Trail of Bits / NCC for external pentest
- First case study draft (design partner #1)

---

## 7. Scorecard impact

| Area | Now | Week 1 | Week 4 | Week 8 |
|---|---|---|---|---|
| Product Vision | 9 | 9.5 | 10 | 10 |
| Differentiation | 8.5 | 8.5 | 9.5 | 10 |
| Identity Security Alignment | 9.5 | 10 | 10 | 10 |
| Enterprise Relevance | 9 | 9.5 | 10 | 10 |
| UI/UX | 8 | 8 | 9 | 10 |
| Defensibility | 9 | 9 | 9 | 10 |
| Current Readiness | 8.5 | 9 | 9.5 | 10 |
| **Average** | **8.7** | **9.1** | **9.6** | **10.0** |

---

## 8. Open founder calls

1. **Approve "Identity Security Graph™" as category name?**
2. **Approve "Identity Security for the AI Era" as homepage tagline?**
3. **Approve the 9-section IA above?**
4. **Patent budget: $45-60k (3 filings)?**
5. **External pentest budget: $25-40k?**
6. **Sprint 1 priority within Week 2: Trust Score surfacing first, or Exec language pass first?**

Once you approve #1-3, I'll start Week 1 immediately — it's the lowest-risk highest-impact change (no schema changes, no URL changes, just label + grouping in the sidebar component).
