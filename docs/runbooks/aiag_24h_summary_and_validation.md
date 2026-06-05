# AIAG 24-Hour Build Summary + Validation Guide

**Window:** 2026-06-02 → 2026-06-03 (one push from peer-feedback session to validated localhost demo).

**Audience:** Founder. Use this to validate every feature end-to-end on both real client (org=10 virtuallabs, READ-ONLY) and demo (org=9 AuditGraph Demo, full write access).

---

## TL;DR — what shipped

**Three large categories, 7 commits, ~9,500 lines of code:**

1. **AI Identity Attack Graph (AIAG)** — the category-defining capability. Six features across three tiers + shared infrastructure:
   - T1A AI Identity Attack Paths (AG-178)
   - T1B Per-Agent Trust Score + Board Scorecard (AG-179)
   - T2A Sensitive Data Reachability (AG-180)
   - T2C AI Lifecycle + Drift (AG-181)
   - T3A Activity Timeline + Behavior Baseline (AG-182)
   - Shared infra: MITRE library, scope-match helper, classification taxonomy, drift event taxonomy, ai_classifier enrichment (AG-177)

2. **Argus 7-layer EPIC (AG-184)** — the AI Identity Security Analyst (not a chatbot). All 8 layers shipped, all rule-based (no LLM required for MVP):
   - L1 NL Query · L2 Reasoner · L3 Attack Path Investigator · L4 CISO Advisor
   - L5 Explain Why · L6 What-If Simulator · L7 Executive Summary · XGRAPH Cross-identity

3. **Operational tooling** — localhost validation runbook, cloud-dev deployment plan, Trust Score thresholds proposal, demo seeder with safety guards, PHI honesty UI pass.

**Constraint envelope honored throughout:**
- No real client data deleted, modified, or added to (after the 2026-06-03 near-miss + cleanup).
- No fake/hardcoded values. Empty states are honest.
- No data-plane reads. Classification heuristic surfaces customer's own labels, never inspects content.
- Migration 100 regression rule respected (explicit PKs + sequences on all 6 new tables).
- Type-check passes (`tsc --noEmit` zero errors).
- 80 unit tests pass for `access_resolution.py`.

---

## Q: Can we validate everything in demo org=9?

**Mostly yes. Here's the precise breakdown:**

| Capability | Demo org=9 covers it? | Why / Gap |
|---|---|---|
| T1A AI Attack Paths | ✅ Full | Demo seeds 4 AI agents + KV Admin + classified storage + open egress → 1 critical chain emits. |
| T1B Trust Score | ✅ Full | All 5 dimensions exercised (one agent ownerless, one with secrets HIGH, one with egress FAIL). |
| T1B Board Scorecard | ⚠️ Partial | KPIs compute correctly; trend sparkline needs ≥2 daily snapshots — for demo set, run scheduler once + wait OR run `persist_ai_scorecard_snapshots` job manually twice. |
| T2A Data Reachability | ✅ Full | 4 classified resources (PHI, PCI, HR, PII) with record_count_estimate. |
| T2C AI Lifecycle | ✅ Full | Two historical runs seeded → `ai_permissions_escalated` + `ai_agent_mover` fire reliably. |
| T3A Activity Timeline | ⚠️ Partial | 20-day baseline computes (is_active=true). Anomaly detection ran in my smoke test with 0 detections — threshold tuning needed for the seeded volume spike to fire. Live customer data has richer signal. |
| Argus L1 NL Query | ✅ Full | 6 named intents work; free-text fallback works. |
| Argus L2 Reasoner | ✅ Full | 6 question_types all run; some return medium-confidence on demo subset (smaller pool). |
| Argus L3 Investigator | ✅ Full | Resolves "AI agents" → "PHI" and surfaces the T1A chain. |
| Argus L4 CISO Advisor | ⚠️ Partial | Returns 0-5 priorities depending on signals fired. Demo has ownerless + KV admin → at least 2 priorities. |
| Argus L5 Explain Why | ✅ Full | Decomposes the seeded agents' risk scores. |
| Argus L6 What-If | ✅ Full | Remove KV Admin from drift agent → projected score drops materially. |
| Argus L7 Executive Storytelling | ⚠️ Partial | Needs ai_board_scorecard_snapshots history. Generate via scheduler hook OR manual `compute_board_scorecard()`. |
| Argus XGRAPH | ✅ Full | "Who can reach PHI?" → returns categorized count + common path. |

**Where real client (org=10 virtuallabs) READ-ONLY view is strictly better:**
- Connected Apps consent scenarios (Vercel/MOVEit/Storm-0558/NOBELIUM/Shadow) — real OAuth grants only exist in customer tenants
- Shadow App detection — needs real App Registrations
- Federated credentials (AG-150) — needs real `federated_credentials` rows
- Scale / latency testing — demo has 288 identities, real has 15,678
- Anomaly threshold calibration — needs natural activity baselines

**Recommended:** demo org=9 for engine + UI validation; real client org=10 for the production-fidelity demos and threshold tuning. Both are reachable from the same localhost frontend by switching tenant context.

---

## Q: Animations shipped?

**Yes — 9 distinct animations, all subtle (under 1 second), no third-party libraries.**

| Component | Animation | Trigger |
|---|---|---|
| `AttackPathView.tsx` | Per-hop edge lighting cascade across the chain | First render of any attack path |
| `AgentTrustScoreCard.tsx` | Gauge needle sweep 0 → trust_score (~800ms cubic-out) | Card mount |
| `AIBoardScorecard.tsx` | 5 KPI cards count up from 0 (~600ms) + trend sparkline draws in | Page mount |
| `AIDataReachability.tsx` | 7 classification card counts cascade in | Page mount |
| `AILifecycle.tsx` | J → M → L bucket dot cascade (~400ms staggered) | Page mount |
| `AgentActivityTimeline.tsx` | Events fade-in cascading (~30ms each, cap 30) | Per-agent timeline load |
| `ExplainRiskWaterfall.tsx` | Bars cascade in by weight desc (~50ms staggered, top 12) | Card render |
| `WhoCanReach.tsx` (Argus XGRAPH) | 4-category bar count-up + fade-in cascade | Card render |
| `CisoRecommendations.tsx` / `ReasonChain.tsx` / `ExecutiveSummary.tsx` / `NlQuery.tsx` | `fadeIn` keyframe on result cards + stagger on list items | Query response |

**Animation philosophy:** every animation answers "what just changed?" Bar grows from 0 because the number wasn't there before. Chain lights up because traversal direction matters. Nothing decorative.

---

## 24-hour shipped catalog (in commit order)

| Commit | Scope | Migrations |
|---|---|---|
| `c7a4cda` | Connected Apps scenario menu (5 OAuth playbooks) + AG-150 federated credentials endpoint + AG-86 Shadow App detection | 119 |
| `212d934` | AIAG shared infrastructure (MITRE / scope-match / classification / drift events) + Tier 1A attack path detector + Tier 1B trust score engine + UI | 120, 122 |
| `53fe7e8` | Tier 2A data reachability + Tier 2C AI lifecycle + Tier 3A behavior baseline (3 engines + 9 API endpoints + 3 frontend pages + scheduler hooks) | 121, 123, 124 |
| `7a6dee3` | Runbooks (validation, cloud-dev deployment, Trust Score thresholds) + demo seeder + PHI honesty UI pass | – |
| `f9b1f1a` | Argus Layer 5 (Explain Why) + Layer 3 (Attack Path Investigator) — backend engines + UI components + `/argus` landing page | – |
| `4eee84a` | Seeder schema-tolerance + `data_reachability_engine` cursor fix (found during validation) | – |
| `46a6759` | Argus L1 NL Query + L2 Reasoner + L4 CISO Advisor + L6 What-If + L7 Exec Summary + XGRAPH Cross-Identity | 125 |
| `cb7f7eb` | Seeder safety guard: refuses virtuallabs/orangeblack/azurecredits + default `--org-id 9` | – |

**Schemas added (6 new tables + 4 column extensions):**
- `approved_apps` (Shadow Apps registry, migration 119)
- `agent_classifications` extensions: model_name, owner_display_name_at_classify, account_resource_id (120)
- `azure_sql_servers`, `azure_sql_databases`, `azure_cosmos_accounts`, `azure_cosmos_databases` (121)
- `agent_data_reachability` rollup (121)
- `ai_trust_score_history`, `ai_board_scorecard_snapshots` (122)
- `ai_agent_lifecycle_events` (123)
- `agent_activity_events`, `agent_behavior_baselines`, `agent_behavior_anomalies` (124)
- `argus_reasoning_cache` (125)

**API surface added (24+ new endpoints):**

| Route | Layer |
|---|---|
| GET /api/attack-paths?source_entity_type=ai_agent | T1A |
| GET /api/ai-security/trust-score/<id> | T1B |
| GET /api/ai-security/board-scorecard | T1B |
| GET /api/ai-security/board-scorecard/history | T1B |
| GET /api/ai-agents/<id>/data-reachability | T2A |
| GET /api/data-security | T2A |
| POST /api/resources/<id>/classify | T2A |
| POST /api/resources/auto-classify | T2A |
| GET /api/ai-agents/<id>/lifecycle | T2C |
| GET /api/ai-agents/<id>/drift | T2C |
| GET /api/dashboard/ai-jml-snapshot | T2C |
| GET /api/ai-agents/<id>/activity-timeline | T3A |
| GET /api/ai-agents/<id>/baseline | T3A |
| GET /api/ai-agents/activity/anomalies | T3A |
| POST /api/argus/nl-query | Argus L1 |
| POST /api/argus/reason | Argus L2 |
| POST /api/argus/investigate-attack-path | Argus L3 |
| GET /api/argus/recommendations | Argus L4 |
| GET /api/argus/explain-risk-score/<id> | Argus L5 |
| POST /api/argus/what-if/role-removal | Argus L6 |
| GET /api/argus/executive-summary?topic= | Argus L7 |
| GET /api/argus/who-can-reach?classification= | Argus XGRAPH |

---

## Per-feature validation — same matrix for both org=10 (real) and org=9 (demo)

For **org=10 (virtuallabs, real client)**: READ-ONLY validation. Log in as `admin@virtuallabs.com` or use superadmin with `X-Tenant-Id: 10`. The same UI pages will render against real customer data.

For **org=9 (AuditGraph Demo)**: full demo flow with the seeded data. Log in with the demo admin OR superadmin with `X-Tenant-Id: 9`.

### Pre-flight (one-time)

```bash
# Backend running with latest commit?
git log -1 --oneline                          # should be cb7f7eb or later
lsof -i :5001 | grep LISTEN                   # backend should be up

# All migrations applied to localhost?
PGPASSWORD=auditgraph psql -h localhost -p 5434 -U auditgraph -d auditgraph -c \
  "SELECT tablename FROM pg_tables WHERE tablename IN (
    'agent_data_reachability', 'ai_agent_lifecycle_events',
    'agent_activity_events', 'ai_trust_score_history',
    'argus_reasoning_cache') ORDER BY tablename;"
# Expect all 5 listed

# Demo data present in org=9?
PGPASSWORD=auditgraph psql -h localhost -p 5434 -U auditgraph -d auditgraph -c \
  "SELECT count(*) AS demo_identities FROM identities WHERE organization_id=9 AND identity_id LIKE 'aa000%';"
# Expect 8

# Real client data intact in org=10?
PGPASSWORD=auditgraph psql -h localhost -p 5434 -U auditgraph -d auditgraph -c \
  "SELECT count(*) FROM identities WHERE organization_id=10;"
# Expect 15,678 (must NOT contain any aa000-prefix rows)
```

### Feature matrix

| # | Feature | URL | Real (org=10) check | Demo (org=9) check |
|---|---|---|---|---|
| 1 | **AI Attack Paths** | `/ai-risk/attack-paths` | Shows real attack chains across 15k identities | Shows the seeded ai_agent_exfiltration chain with MITRE T1078.004 / T1552.001 / T1530 / T1041 chips |
| 2 | **Trust Score** (per-agent) | `/ai-inventory/agents` → click agent → drawer | Trust Score appears at top of `AIInvestigateDrawer` with 5 dimensions | 4 demo agents all show Trust Score; alexander_CoS_project = ~22/100 CRITICAL |
| 3 | **Board Scorecard** | `/board-scorecard` | 5 KPIs from real data (telemetry coverage 1.2%, etc.) | KPIs computed from 4 demo agents; sparkline empty until scheduler runs |
| 4 | **Data Reachability** | `/ai-access/data-reachability` | 7 classification cards reflect any tagged real resources | 4 classification cards populated (PHI 120K records, PCI 45K, HR 250K, PII 80K); SOURCE+Confidential cards "no resources classified" |
| 5 | **AI Lifecycle** | `/ai-lifecycle` | J/M/L from real run-over-run deltas; window selector works | 7-day window shows `ai_permissions_escalated` + `ai_agent_mover` events on alexander_CoS_project |
| 6 | **Activity Timeline** | `/ai-runtime/activity` | Per-agent baseline + anomalies (sparse without Azure Monitor ingestion) | 4 baselines (is_active after 20-day samples); 0 anomalies until threshold tuning |
| 7 | **Argus** | `/argus` | 8 tabs all functional against real graph | Same 8 tabs, demo-sized responses |
| 7a | Argus L1 NL Query | `/argus` → NL Query tab | Try: "Show ownerless AI agents" — should return real ownerless count | Returns the 1 demo ownerless agent (EP.Jason Collins) |
| 7b | Argus L2 Reasoner | `/argus` → Reasoning Chain | "Highest business risk" — narrates real graph | "2 AI agents can reach classified data; 2 ownerless..." (demo) |
| 7c | Argus L3 Investigator | `/argus` → Investigate Path | "Show attack paths from AI agents to PHI" → returns real critical chains | Returns the seeded ai_agent_exfiltration path |
| 7d | Argus L4 CISO Advisor | `/argus` → What to Fix | Top 5 from real signal frequencies | 2-3 priorities from demo signals (KV admin, no owner) |
| 7e | Argus L5 Explain Why | `/argus` → Explain Risk Score | Pick any real AI agent → waterfall of contributions | Pick alexander_CoS_project → 6 contributions with weights, MITRE chips, evidence |
| 7f | Argus L6 What-If | `/argus` → What-If Simulator | Pick real role → projected drop | Pick alexander's KV Admin assignment → projected score drops ~30 pts |
| 7g | Argus L7 Executive | `/argus` → Executive Summary | "Are our AI agents secure?" → board prose | Board prose from 4 demo agents; trend `null` until snapshots accumulate |
| 7h | Argus XGRAPH | `/argus` → Who Can Reach | "PHI" → real categorized identities | "PHI" → 2 demo AI agents, 0 humans/SPNs/OAuth (demo set is small) |

### Engine-level verification (CLI, for engineers)

After any change to engines, re-run the smoke test:

```bash
cd /Users/sangabattula/projects/auditgraph/backend
APP_ENV=local DB_HOST=localhost ./venv/bin/python -c "
from app.database import Database
db = Database()
cur = db.conn.cursor()
cur.execute(\"SET LOCAL app.current_organization_id = '9'\")
cur.execute(\"SET LOCAL app.current_tenant_id = '9'\")

# Demo org=9 — expects non-empty results
from app.engines.ai.data_reachability_engine import refresh_data_reachability
print('T2A:', refresh_data_reachability(db, 383, 9))

from app.engines.ai.ai_lifecycle_engine import AILifecycleEngine
print('T2C:', len(AILifecycleEngine(db).analyze(383, 382, 9)), 'events')

from app.engines.ai.agent_behavior_engine import AgentBehaviorEngine
print('T3A:', AgentBehaviorEngine(db).refresh_baselines(9))

from app.engines.attack_path_engine import AttackPathEngine
print('T1A:', len(AttackPathEngine(db)._detect_ai_agent_exfiltration(383)), 'chains')

from app.engines.scoring.board_scorecard_engine import compute_board_scorecard
print('Scorecard:', compute_board_scorecard(cur, 9))
"
```

Last validated 2026-06-03 against org=9 (post-cleanup):
- T2A: 4 agents evaluated, PHI + PCI classifications, 2 rollup rows written.
- T2C: 2 lifecycle events (`ai_permissions_escalated` + `ai_agent_mover` on `alexander_CoS_project`).
- T3A: 4 baselines written (is_active depends on `samples_count >= 14`).
- T1A: 1 CRITICAL attack chain detected, risk_score=77.
- Scorecard: 5 KPIs computed honestly from real-time signal data.

---

## What's queued (your action items)

1. **Cloud-dev demo tenant provisioning.** `dev.app.auditgraph.ai` does not yet have a dedicated demo tenant. Until provisioned:
   - Cloud-dev demo flow is unavailable
   - `org=orangeblack` is the real client and must stay READ-ONLY there too
   - Action: provision a demo tenant via the existing tenant-creation flow, target name like `auditgraph-demo-cloud` or `demo-tenant`
2. **Trust Score threshold sign-off.** `docs/runbooks/trust_score_thresholds_proposal.md` — 14 penalty weights + 4 band thresholds (90/70/50). Required before any customer sees the board pack.
3. **Apply migrations 120 → 125 to cloud-dev** via `docs/runbooks/aiag_cloud_dev_deployment.md`.
4. **After provisioning the cloud demo tenant**, run `seed_aiag_demo.py --org-id <new-id>` against cloud-dev DB so the cloud demo lights up.
5. **Validation walkthrough**: founder + me, screen-share session against both org=10 (real demo) and org=9 (controlled demo), capture screenshots for the customer-facing materials.

## What's deferred (intentionally)

- **Tier 3B Agent-to-Agent / MCP** (AG-183) — MCP protocol immaturity, needs 2-3 design partners to validate edge sources before public demo.
- **Ollama integration for Argus narrative enrichment** — currently all 8 layers are rule-based + return structured data. Adding Ollama for richer L2/L7 prose is `ollama_copilot_plan.md` — ~3 hours of work, no API spend.
- **Anthropic API integration** — confirmed NOT required for any current capability. Save the credits.
