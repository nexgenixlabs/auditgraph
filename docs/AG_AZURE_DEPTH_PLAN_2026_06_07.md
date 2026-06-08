# Azure-Depth Plan — Sprint Q3 2026

**Date**: 2026-06-07
**Status**: Draft for founder final review
**Author**: Co-founder strategy (this is "the plan to widen the moat while pentest + SOC 2 run externally")
**Decision context**: AWS expansion deferred to Q4 2026 — gate is first signed Azure pilot customer. Until then, every engineering minute goes into making Azure unbeatably deep.

---

## 1. Decision summary

### What we ARE doing (next 6 weeks)

1. **PIM Overprivilege Detection** — read-only eligible/active assignment analysis surfacing identities that have privileged eligibility but never exercise it.
2. **Feature E Phase 2 — Entra Directory Role Last-Used Inference** — using auditLogs/directoryAudits to compute per-role last-activity timestamps and surface "dormant privileged role" findings.
3. **Backend test backfill** for Tiers 0-1 modules (everything older than Tier 1-4) to reach 70% statement coverage — SOC 2 evidence + safety net for refactors.
4. **Performance baseline at 100K identities** on cloud-dev with synthetic load — find bottlenecks before a customer does.
5. **Three customer pilot conversations** kicked off in parallel (sales-driven; engineering supports onboarding).

### What we are NOT doing

| Item | Why deferred | Trigger to revisit |
|---|---|---|
| **AWS discovery** (IAM, Bedrock, etc.) | Builds shallow second cloud at cost of Azure depth | First Azure signed pilot OR prospect explicitly conditions deal on AWS |
| **GCP discovery** | Same as AWS, further out | After AWS proves the multi-cloud pattern |
| **New AI features (Tier 5+)** | Tier 1-4 needs to stabilize and start producing customer-attested outcomes | After 3 case studies published |
| **UI redesign / new pages** | Brand pivot just landed; let customers absorb it | Q4 2026 retrospective |

### What runs in parallel (founder + external)

- **External pentest** (Trail of Bits / NCC Group selection + engagement) — founder-driven
- **SOC 2 vendor selection** (Drata / Vanta / Secureframe) — founder-driven
- **Zero-trust networking deployment** — founder-driven
- **Customer pilot pipeline** — sales/founder-driven; engineering supports onboarding

---

## 2. Feature 1 — PIM Overprivilege Detection

### 2.1 What it does

Every identity that has a **PIM-eligible** privileged role assignment gets analyzed against its **actual activation history**. The output is a per-identity overprivilege score with three sub-signals:

1. **Eligible but never activated** — has the role but has never exercised it. Strong candidate for assignment removal.
2. **Eligible but rarely activated** — activates once per quarter or less. Candidate for time-bound assignment instead of standing eligibility.
3. **Eligible AND active** with no MFA requirement on activation — least privilege violation that needs a config tightening, not a role removal.

These map to three new finding types in the Findings catalog (`pim_unused_eligibility`, `pim_low_frequency_activation`, `pim_weak_activation_control`).

### 2.2 Data sources — all read-only

| Source | Permission required | Already have? |
|---|---|---|
| `GET /roleManagement/directory/roleEligibilityScheduleInstances` | `RoleManagement.Read.Directory` | ✅ Yes |
| `GET /roleManagement/directory/roleAssignmentScheduleInstances` | `RoleManagement.Read.Directory` | ✅ Yes |
| `GET /roleManagement/directory/roleEligibilitySchedules` | `RoleManagement.Read.Directory` | ✅ Yes |
| `GET /auditLogs/directoryAudits` (filtered to PIM activation events) | `AuditLog.Read.All` | ✅ Yes (Tier 1-4 reach) |
| `GET /policies/roleManagementPolicies` (activation policy: MFA, approval, justification, max duration) | `Policy.Read.All` | ✅ Yes |

**Moat compliance check:**

- [x] No write permissions requested. Same read-only consent the platform already operates under.
- [x] Works on logs-OFF tenants for the eligible-vs-active delta (the core finding). Activation history simply degrades to "unknown frequency" gracefully.
- [x] No agent deployed. Pure Graph API.
- [x] Architecture-derived for the primary signal. Logs enrich, don't gate.

### 2.3 The P2 nuance (founder's question, addressed)

Audit log dependency: this feature uses **`auditLogs/directoryAudits`**, which requires Entra ID **P2** licensing on the customer tenant. Practical reality:

- Any org >50 employees in our target verticals (healthcare, financial services, regulated AI) almost certainly has P2 — Conditional Access alone is enough to require it.
- P2 audit logs are **centralized** (single Graph endpoint, all customer tenants the same path) — unlike Azure resource diagnostic settings which are per-resource and often scattered.
- Fallback when P2 is missing: the eligible-vs-active delta (the core overprivilege signal) still works. We lose activation-frequency analysis only. Display "frequency: unknown — Entra P2 required" instead of fabricating.

This preserves the moat: we don't *require* logs to produce value. We *enrich* with them when available.

### 2.4 Severity model

```
no MFA on activation        → critical    (most exploitable)
eligible + never activated  → high        (cleanup target)
eligible + rare activation  → medium      (review candidate)
eligible + frequent active  → low         (working as intended)
```

Each finding rolls into the Identity Trust score (Oversight dimension) and surfaces in the Findings catalog with workflow status.

### 2.5 UI — three surfaces

1. **New page** at `/identity-security/pim` — sortable table of all PIM-eligible identities with their overprivilege classification. Filter chips by severity and by role.
2. **Existing AI Inventory / Identity Inventory drawer** — adds a "PIM Activity" tab showing the per-identity eligible roles + activation history.
3. **New findings** in the existing AI Findings + Security Findings catalogs (three finding types from §2.1).

### 2.6 Sprint breakdown — 8 days engineering

| Day | Work |
|---|---|
| 1 | Schema: `pim_eligibility_state` + `pim_activation_observations` tables; migration 215 |
| 2 | Discovery engine: pull all 5 Graph endpoints; persist normalized records |
| 3 | Severity logic: implement the 4-tier classifier; tests for each tier |
| 4 | Findings catalog: 3 new detectors emitting normalized findings |
| 5 | API handlers: `/api/identity-security/pim/overprivilege` + filters |
| 6 | UI: new page + drawer tab |
| 7 | Integration tests + demo data seed |
| 8 | Cloud-dev deploy + verification |

### 2.7 Success criteria

- 5 PIM-eligible demo identities produce ≥3 critical or high findings
- One worked example shows "this identity has eligibility she hasn't activated in 18 months — recommend removal"
- The Identity Trust Oversight dimension reflects PIM hygiene in its score
- No P2-required path crashes on a tenant without P2 — gracefully degrades

---

## 3. Feature 2 — Entra Directory Role Last-Used Inference (Feature E Phase 2)

### 3.1 What it does

For every Entra **directory role** assignment (Global Admin, User Administrator, Application Admin, Exchange Admin, etc.), compute:

1. **`last_admin_action`** — most recent observed action attributable to this role-assignment from auditLogs (e.g., a UserAdmin who last reset a password 23 days ago vs. one who hasn't taken any directory action in 14 months).
2. **`activity_frequency`** — actions per day over the trailing 90 days, bucketed (daily / weekly / monthly / rare / dormant).
3. **`dormancy_risk_band`** — high (>90 days no activity) / medium (30-90) / low (<30).

This is the basis for "dormant privileged role" findings — directory role assignments that haven't been exercised but are still active grants.

### 3.2 Data sources — all read-only

| Source | Permission required | Already have? |
|---|---|---|
| `GET /directoryRoles` + `GET /directoryRoles/{id}/members` | `RoleManagement.Read.Directory` | ✅ Yes |
| `GET /auditLogs/directoryAudits` (filtered by `initiatedBy.user.id` + role-relevant `category`) | `AuditLog.Read.All` | ✅ Yes |
| `GET /reports/credentialUserRegistrationDetails` (optional — MFA registration enrichment) | `Reports.Read.All` | Need to add |

**Moat compliance check:**

- [x] No write permissions. Pure observation.
- [x] Works without logs — gracefully degrades to "unknown — Entra P2 required for activity inference" rather than failing or hiding.
- [x] No agent. Pure Graph API.
- [x] Architecture provides the assignment surface (which identities have which directory roles); audit logs enrich with activity. Same moat-honoring pattern as PIM Overprivilege.

### 3.3 The inference algorithm

The hard part is matching `auditLogs.directoryAudits` events to specific role assignments. Audit log entries don't say "this action was taken under directory role X" — they say "user U did action A". We infer:

```python
for each directory_role_assignment(user U, role R):
    # Find audit events that REQUIRE role R's permissions
    relevant_events = audit_logs.filter(
        initiated_by_user_id = U.id
        AND audit_category in CATEGORIES_REQUIRING(R)
    )
    last_action = max(relevant_events.timestamp) or None
    activity_count_90d = count(relevant_events in last 90 days)
    bucket = bucketize(activity_count_90d)
    dormancy_band = classify_dormancy(last_action)
```

`CATEGORIES_REQUIRING(R)` is a hard-coded mapping derived from the Microsoft docs of role permissions. For example:
- `UserAdministrator` → categories `UserManagement`, `GroupManagement` (when group is owned/member-managed by UserAdmin)
- `ApplicationAdministrator` → `ApplicationManagement`, `Authentication`
- `ConditionalAccessAdministrator` → `Policy`
- `GlobalAdministrator` → all categories (broadest)

This mapping is the actual moat — it's the same insight as Wiz-grade ARM-side last-used inference but applied to Entra directory roles, where no competitor currently does it.

### 3.4 Sprint breakdown — 9 days engineering

| Day | Work |
|---|---|
| 1 | Schema: `entra_role_activity` table with last_action + bucket + dormancy_band; migration 216 |
| 2 | Build the `CATEGORIES_REQUIRING(R)` mapping — research + table |
| 3-4 | Inference engine: pull auditLogs in batches, attribute to assignments, compute buckets |
| 5 | New finding detector: `dormant_directory_role_assignment` |
| 6 | API handler: extend existing identity detail to include activity data |
| 7 | UI: add "Directory Role Activity" section to identity drawer |
| 8 | Tests with synthetic auditLog seed |
| 9 | Cloud-dev deploy + verification |

### 3.5 Success criteria

- A demo Global Administrator with 0 actions in 90 days produces a `dormant_directory_role_assignment` critical finding
- An active User Administrator with recent password-reset events shows "active — last action 3 days ago"
- The Telemetry dimension of Identity Trust upgrades from PARTIAL → FULL on identities where activity inference succeeds
- Gracefully shows "unknown — Entra P2 required" on tenants without log access

---

## 4. Test backfill — running in parallel

### 4.1 Scope

Bring backend test coverage outside Tier 1-4 from the current ~30% to **70% statement coverage**. Auditors will ask for this; it's also the safety net we need to refactor older modules without fear.

Priority order (most-touched first):

1. `access_resolution.py` — already has some tests, fill the gaps
2. `discovery/azure_*.py` — discovery pipeline modules
3. `engines/scoring/*` — risk scorers other than `agent_trust_scorer`
4. `api/handlers.py` — too large, but at least the most-called endpoints (auth, identities, dashboard)
5. `database.py` — connection/RLS handling

### 4.2 Effort — 5 days total, can run during the PIM + Feature E work

This is fill-in work that an engineer can do between integration steps. Doesn't block the headline features.

---

## 5. Performance baseline at scale

### 5.1 Why

We've never tested AuditGraph at 100K identities. Every prospect at the mid-market or larger asks about scale. Failing this question kills deals. Better to find the bottleneck on cloud-dev now than on a customer tenant later.

### 5.2 Plan — 4 days total

| Day | Work |
|---|---|
| 1 | Build a synthetic-scale seeder: generate 100K demo identities + 10× role assignments + multi-hop edges |
| 2 | Apply to a fresh cloud-dev tenant; run discovery; measure per-stage timing |
| 3 | Identify top 3 bottlenecks (likely candidates: the abuse_scenarios N+1, supply chain rollup pre-batching, identity-list endpoint pagination) |
| 4 | Fix the worst one; document the others for backlog |

### 5.3 Output

A scale-test artifact in `docs/`:

> *"AuditGraph cloud-dev verified at 100K identities, 1.2M role assignments, end-to-end discovery in N minutes. Per-page API response p99 under 800ms."*

That sentence goes in the pentest report, the SOC 2 evidence package, and the sales deck.

---

## 6. Customer pilot pipeline — parallel, sales-driven

Engineering doesn't drive this directly, but supports onboarding.

Per the case study template (`docs/AG_CASE_STUDY_TEMPLATE_2026_06_05.md`), the targets are:

1. **Healthcare** — hospital network with 5-50K NHIs, HIPAA lens. PHI dollar exposure is the headline.
2. **Financial Services** — mid-market bank or fintech with SOX/PCI lens.
3. **Tech (AI-native)** — Series B+ SaaS with heavy Azure OpenAI use.

Engineering support per pilot: ~1 day for onboarding + ~2 days for ongoing during pilot window. Three pilots = ~9 engineering days over 6-12 weeks elapsed.

---

## 7. Timeline — 6-week sprint

```
Week 1  ──┬─ PIM Overprivilege days 1-4  ──┬─ Test backfill (background, 1 engineer)
Week 2  ──┤  PIM Overprivilege days 5-8   │
Week 3  ──┤  Feature E days 1-4           │
Week 4  ──┤  Feature E days 5-9           │
Week 5  ──┤  Performance baseline + first pilot onboarding
Week 6  ──┴─ Bug-fix + buffer + sales-deck refresh

In parallel (founder + external):
  • Pentest vendor selection + engagement signed (~weeks 2-4)
  • SOC 2 vendor onboarding + control evidence collection begins
  • Zero-trust networking deployment continues
  • Customer pilot conversations
```

End-of-sprint deliverables:

- ✅ PIM Overprivilege Detection live on cloud-dev with demo data
- ✅ Feature E Phase 2 live on cloud-dev with demo data
- ✅ Test coverage at 70% statements outside Tier 1-4
- ✅ Performance verified at 100K identities, documented
- ✅ Pentest engagement signed
- ✅ SOC 2 vendor onboarded
- ✅ First customer pilot signed (target — depends on sales cycle)

---

## 8. The standing rule — "agentless, read-only, architecture-derived"

A bright-line check for every new feature spec from here forward. Three assertions, signed off before any new schema or discovery code is written:

1. **Agentless**: the feature is implemented entirely via remote cloud-provider APIs. No agent code runs inside the customer environment.
2. **Read-only**: the feature requires only `*.Read.*` permissions. No `*.ReadWrite.*` or `*.All.Write` permissions added.
3. **Architecture-derived**: the feature produces useful output on a tenant with no logs enabled (or degrades gracefully with explicit "unknown" rather than failing).

A spec that violates any of these is a moat deviation and needs explicit founder approval to ship.

This is now codified in the standing memory entry. See `memory/feedback_no_log_dependency.md` (existing) and the new `memory/spec_checklist_agentless_readonly.md` (to be added).

---

## 9. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| PIM Overprivilege depends on Entra P2 audit logs | Low — every target customer has P2 | Eligible-vs-active delta works without P2; graceful degradation message |
| Feature E `CATEGORIES_REQUIRING(R)` mapping is incomplete | Medium | Start with the 8 most common directory roles; expand as customers surface gaps |
| Performance at 100K reveals an unfixable bottleneck | Low | Worst case: document scale limit, position as "up to N identities per tenant"; refactor in Q4 |
| Pentest finds a critical gap | Medium | All P0/HIGH from internal pentest already closed; budget reserve for external findings |
| First customer pilot wants AWS | High eventually | The "one signed pilot" gate is exactly this signal — if AWS is the gate, we revisit Q4 plan |
| SOC 2 vendor selection takes 6+ weeks | Low | Drata/Vanta both have <2 week onboarding documented |

---

## 10. Open questions for founder review

Before kicking off the sprint:

1. **Approve scope of PIM Overprivilege Detection?** Specifically — the 3 finding types (`pim_unused_eligibility`, `pim_low_frequency_activation`, `pim_weak_activation_control`).
2. **Approve scope of Feature E Phase 2?** Specifically — the `CATEGORIES_REQUIRING(R)` mapping approach for 8 most common directory roles, expandable later.
3. **Test backfill priority** — agree with the 5-module priority order above?
4. **Performance test target** — confirm 100K identities is the right milestone (not 10K, not 1M)?
5. **Customer pilot pipeline** — who's owning the sales conversations? Founder solo or does engineering need to do anything beyond support?
6. **AWS gate** — confirm "first signed Azure pilot customer" is the trigger to revisit AWS plan. If yes, we lock the Q4 reassessment.
7. **Approve adding the standing rule** (§8) as a permanent spec checklist?

---

## 11. Bottom line for the next sales / investor conversation

The story this sprint produces:

> *"While our SOC 2 prep + external pentest run in parallel, we're using engineering capacity to extend our Azure depth in two ways no competitor matches today — PIM Overprivilege Detection that identifies privileged eligibility customers carry but never use, and per-directory-role activity inference from Entra audit logs. AWS expansion is gated on our first signed Azure pilot customer, targeted for Q4 2026."*

That sentence answers three CISO questions simultaneously:

1. *"What's your roadmap?"* → Two specific, defensible features they understand.
2. *"How do you compare on multi-cloud?"* → "Azure-first, AWS Q4, gated on customer demand" — disciplined, not over-promising.
3. *"How do you justify your price vs. Wiz / SailPoint?"* → Two capabilities those vendors don't have, with the moat reasoning explicit.

It also produces three concrete artifacts that don't exist today:

- A 100K-identity scale-test result
- 70% test coverage backstop
- Two new patent-track Azure features (PIM Overprivilege + Entra Last-Used) that pair with the existing Multi-Hop XGRAPH patent draft

---

**Status**: ready for founder review. Sign-off → kick off Week 1 Monday.
