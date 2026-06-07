# Pre-Pilot Readiness Checklist

**Date**: 2026-06-07
**Trigger**: Founder confirmed a real pilot client is incoming. Will be enabled one tenant at a time.
**Status**: For founder review · sign-off → start client onboarding
**Discipline**: This is a HARD gate. Don't skip items. Real customer data is a different blast-radius than demo data.

---

## Part 1 — The single most important rule

> **Customer tenants are READ-ONLY everywhere. They are never written to except by the customer's own user actions through their own portal. Demo/test orgs are the only legitimate write target.**

This is already in CLAUDE.md as the "HARD RULE: no org data deletion." For a real pilot the rule extends:

- **No automated writes** to customer data — even for "remediation" suggestions. We surface recommendations; the customer's IAM admin clicks the button in Entra.
- **No demo personas seeded into customer tenant** — `demo-*` identities only appear in `auditgraph-demo` orgs (org=9 local, org=3 cloud-dev, org=N for any new demo orgs).
- **No code in customer tenant** — agentless is non-negotiable. Pure Graph API + ARM API + AWS read-only calls.
- **No log requirement enforced** — the moat is "works without logs"; first pilot must confirm graceful degradation on a tenant without P2 if they don't have it.

If any new code wants to violate this, founder approval required IN WRITING (commit message + memory entry).

---

## Part 2 — Hard gates before client tenant goes live

### 🔴 GATE 1 — Org isolation verified

Before pointing AuditGraph at the client's Azure tenant:

- [ ] Create a fresh organization row for the client (e.g., `org_id=10` or next available). Never re-use a demo org.
- [ ] Confirm the client's Entra tenant ID + subscription IDs are recorded.
- [ ] Cloud connection registered with the client's specific app registration (not a shared service principal).
- [ ] Verify RLS policies block cross-org reads: log in as the client's admin, query GET /api/identities — should return ONLY the client's identities. If you see any `demo-*` identity, RLS is broken.
- [ ] Verify the `_admin_reason` audit trail is producing logs on any cross-org admin operation.

**Smoke test:**
```bash
# Login as client admin (after first SSO setup)
# Query identities — expect ZERO matches for demo-* or perf-*
curl -s -H "Authorization: Bearer $CLIENT_TOKEN" \
  "https://dev.api.auditgraph.ai/api/identities?search=demo-" | jq '.identities | length'
# Expected: 0
```

### 🔴 GATE 2 — Permissions least-privilege confirmed

The app registration used for the client's discovery:

- [ ] Has ONLY these permission scopes granted (read-only):
  - `Directory.Read.All`
  - `RoleManagement.Read.Directory`
  - `Policy.Read.All`
  - `AuditLog.Read.All` (optional — for Feature E + activity)
  - `Application.Read.All`
  - On ARM side: `Reader` role at the subscription scope
- [ ] NO `*.ReadWrite.*` permissions in the consent grant.
- [ ] NO custom roles created in the customer tenant by AuditGraph.
- [ ] Client's IAM admin has reviewed and approved the consent grant in their own portal.

**Smoke test:**
```bash
# In Azure Portal, the app registration's API permissions tab MUST show
# every permission as "Read" or "ReadDirectoryData" etc. — never "ReadWrite".
# Screenshot this for the customer's audit file.
```

### 🔴 GATE 3 — Demo-data isolation confirmed

After standing up the client's org:

- [ ] Verify no `demo-*` identity rows exist in the client's org:
  ```sql
  -- via apply_cloud_migration.py against cloud-dev
  SELECT identity_id FROM identities WHERE organization_id = <CLIENT_ORG_ID> AND identity_id LIKE 'demo-%';
  -- Expected: 0 rows
  ```
- [ ] Verify no `perf-*` or `pim_*demo*` rows either:
  ```sql
  SELECT identity_id FROM identities WHERE organization_id = <CLIENT_ORG_ID> AND identity_id LIKE 'perf-%';
  ```
- [ ] Confirm PIM eligibility tables are empty for the client (will populate from real Graph API on first discovery):
  ```sql
  SELECT COUNT(*) FROM pim_eligibility_state WHERE organization_id = <CLIENT_ORG_ID>;
  -- Expected: 0 (PIM authoritative discovery not yet implemented)
  ```

### 🔴 GATE 4 — Settings tightened

- [ ] Default scheduler interval set to a reasonable cadence (start at daily, never sub-hour for pilot).
- [ ] Email notifications OFF by default — let the client opt in per category.
- [ ] No SOAR playbooks active by default — playbooks can trigger real-feeling alerts; client must opt-in.
- [ ] Threat connector partner integrations OFF — client wires their own if/when they want.
- [ ] Webhook secret generation — if the client wants webhooks for findings, generate a unique per-tenant secret.

### 🔴 GATE 5 — Backup + rollback plan

- [ ] Database backup snapshot taken immediately before adding the client's org.
- [ ] Rollback path documented: if discovery produces unexpected results, how to revert without losing the client's `organizations` row but clearing their `identities` / `role_assignments`.
- [ ] `_admin_reason` annotation present on any DB admin operation that touches client data.

---

## Part 3 — Soft gates (recommended but not blocking)

### 🟡 GATE 6 — Performance pre-check

Before pointing at the client's full tenant:

- [ ] Estimate the client's identity count (ask their IAM lead).
- [ ] If > 20K identities, run the perf seeder at that count in cloud-dev first to confirm endpoints behave.
- [ ] If > 50K identities, prioritize the identity-list N+1 fix BEFORE pointing at client.

### 🟡 GATE 7 — Observability ready

- [ ] Cloud-dev API logs in Log Analytics — confirm queries are flowing.
- [ ] Have a live query saved that filters to the client's org_id for triaging issues.
- [ ] Alert channel (Slack? email?) set up for backend exceptions on the client's tenant.

### 🟡 GATE 8 — Communication channel

- [ ] Dedicated Slack channel or shared email thread with the client's IAM lead.
- [ ] On-call rotation defined (probably just founder + 1 engineer for first pilot).
- [ ] First incident drill — pretend something breaks; can we triage + remediate within an hour?

### 🟡 GATE 9 — Customer artifact ready

- [ ] One-page onboarding doc for the client's IAM admin (consent grant flow, expected API permissions).
- [ ] First report template the client will see at end of week 1 (CISO-friendly format).
- [ ] Customer-specific MSA / DPA agreement signed (legal — not engineering).

### 🟡 GATE 10 — Brand polish

- [ ] If the client wants their logo + name on the login page, the tenant branding fields are populated (`branding.company_name` + `branding.logo_url`).
- [ ] If not, default AuditGraph branding shows.

---

## Part 4 — Onboarding flow (one tenant at a time)

The user said "will enable and test one by one." Here's the proposed sequence:

### Tenant N — Day 0 (kickoff)
1. Sign legal docs (MSA + DPA)
2. Client IAM admin creates the app registration in their Azure tenant per the onboarding doc
3. Client grants the read-only permissions listed in GATE 2
4. Founder + engineering join a 30-min screen-share to verify the consent grant
5. Engineering creates the client's org row in cloud-dev DB (`organizations.id = N`)
6. Engineering creates the `cloud_connections` row pointing at the client's app registration

### Tenant N — Day 0 (smoke)
1. Run first discovery scan against the client's tenant (manual trigger)
2. Watch the logs in real-time
3. Confirm: identities discovered, role assignments populated, no errors
4. If errors: pause, diagnose, do NOT proceed to step 5
5. Once clean discovery: client's admin logs into AuditGraph and sees their data

### Tenant N — Day 1 (first findings)
1. Walk through the Executive Posture page with the client's CISO
2. Show 3 specific findings with dollar exposure
3. Get feedback — what surprised them? What confirmed what they suspected?
4. Capture quotes for the case study

### Tenant N — Week 1 (PIM + Feature E)
1. Enable PIM Overprivilege Detection
2. Enable Feature E (Entra Directory Role Activity)
3. Walk through findings with their IAM lead
4. Identify the top 5 remediation actions
5. Track which ones they actually implement (the case study outcome metric)

### Tenant N — Week 2+ (steady state)
1. Daily discovery
2. Weekly check-in with client's CISO
3. Capture metrics for the case study (findings closed, $ exposure reduced, owner coverage increased)

### Then — Tenant N+1
Same flow, in parallel. Cap at 3 simultaneous pilots until each is in steady-state operation.

---

## Part 5 — Risks specific to the pilot phase

| Risk | Likelihood | Mitigation |
|---|---|---|
| Client's identity count is >50K | Medium | Run perf-seeder at their scale first; have N+1 fix ready |
| Client doesn't have Entra P2 (no audit logs) | Medium | Feature E gracefully degrades; PIM has eligibility fallback. Verify on Day 0 |
| Discovery produces unexpected findings (e.g., 50 critical "owner missing") | High — this is the entire point | Triage with client first; this is normal pilot output, not a bug |
| Client wants AWS too | High | Per AG-AZURE-DEPTH-PLAN, AWS is gated on first pilot signing — if this is the request, accelerate AWS slim stripe to weeks 4-8 |
| Customer-side admin grants the wrong (too-broad) permissions | Medium | The 30-min screen share in Day 0 catches this. Reject and re-grant if anything > read-only present |
| Brand confusion (NexgenixLabs vs AuditGraph) | Low | AdminConsole shows NexgenixLabs; client login shows AuditGraph. Already separated. |

---

## Part 6 — What NOT to do during pilot

Mistakes the team must avoid:

1. **Don't enable scheduled automated remediation.** Even if the client asks. First pilot is about quantifying risk and producing recommendations — never auto-acting on customer config.
2. **Don't push code changes to dev/prod during client business hours** without coordinating. Even a "small fix" can disrupt the client's view at exactly the wrong moment.
3. **Don't show demo data to the client.** When demonstrating PIM/Feature E, use the client's REAL data. The 5 demo personas are for sales pitches, not for active customer relationships.
4. **Don't promise features not yet shipped.** Roadmap items stay roadmap items until they're live.
5. **Don't share findings between customers** (peer benchmarking uses anonymized aggregates per the design — but until 10+ pilots exist, no comparison is shown).
6. **Don't apply hotfixes without testing on cloud-dev first.** Even urgent ones. The local → cloud-dev → main flow is mandatory.
7. **Don't add the client's identities to demo orgs by mistake.** Always verify `org_id` before writing.

---

## Part 7 — Engineering pre-pilot checklist (this week)

These are the must-fix tickets before client tenant goes live:

| Priority | Ticket | Owner | Est | Status |
|---|---|---|---|---|
| 🔴 P0 | Identity-list N+1 fix (target: 1.7s p95 → 250ms) | Engineering | 1 day | TBD |
| 🔴 P0 | Write a "fresh org" provisioning script (creates org + cloud_connection + initial settings, idempotent) | Engineering | 4 hours | TBD |
| 🔴 P0 | Add an `org_id` assertion to every demo seeder (already done for PIM/Feature E — confirm for all others) | Engineering | 2 hours | TBD |
| 🟡 P1 | PIM authoritative discovery (replace demo data with real Graph API) | Engineering | 1 week | TBD |
| 🟡 P1 | Per-tenant settings UI for scheduler interval + email notifications | Engineering | 1 day | TBD |
| 🟡 P1 | Customer-facing onboarding doc (the 1-pager for IAM admins) | Founder + Engineering | 4 hours | TBD |
| 🟢 P2 | Status page (status.auditgraph.ai) | Engineering | 1 day | TBD |
| 🟢 P2 | Per-tenant branding UI (logo upload, company name) | Engineering | 1 day | TBD |

The P0s must land before Day 0. P1s should land by Week 1. P2s by Week 2.

---

## Part 8 — Sign-off

Before the first client tenant goes live:

- [ ] All 5 🔴 hard gates passed
- [ ] At least 3 🟡 soft gates passed (others can be retrofit)
- [ ] All P0 engineering tickets shipped
- [ ] Legal docs signed (MSA + DPA)
- [ ] Client IAM admin has reviewed the consent grant
- [ ] Founder approval recorded in commit message of the org-creation script

If any 🔴 gate is unchecked, **do not proceed**. Address the gap, then re-check.

---

## Bottom line

The platform is technically ready. The discipline going forward is:

- **Demo orgs are write-targets. Customer orgs are read-only.**
- **Three things land before Day 0: identity-list N+1 fix, the org-provisioning script, the customer onboarding doc.**
- **Brand the first interaction carefully.** The client's first 5 minutes in AuditGraph determine the case study tone.

This is a great moment. Let's not burn it with a hotfix that touches the wrong tenant.
