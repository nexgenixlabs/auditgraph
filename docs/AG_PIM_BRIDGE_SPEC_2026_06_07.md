# PIM Authoritative Discovery Bridge — Spec

**Date**: 2026-06-07
**Status**: Phase 1 shipped today (dual-write bridge). Phase 2 spec for follow-up sprint.
**Ticket**: AG-PIM-AUTH-DISCOVERY

## Why this exists

Today's PIM Overprivilege Detection feature reads from `pim_eligibility_state` (new table from migration 215). But the discovery pipeline writes to `pim_eligible_assignments` (older table). Without a bridge, a real customer's first scan would NOT populate the PIM Overprivilege page — it would show "0 eligible assignments" even though their tenant has hundreds.

## Phase 1 (SHIPPED today — quick bridge)

`database.py / save_pim_eligible()` now ALSO writes to `pim_eligibility_state`. Activation-policy fields default to conservative-safe values (require MFA + justification, 8h max activation). Scope mapping handled (directory / subscription / resource_group / resource).

**Result**: a real customer's first scan now populates the PIM Overprivilege page with real eligibility data immediately. The 3 finding types still fire correctly because the engine logic doesn't depend on activation-policy fields being accurate (only on the eligibility itself + activation observations).

**Limitation**: activation-policy data is defaulted, not pulled from Entra. So the `pim_weak_activation_control` finding will NEVER fire on real client data (defaults are safe). The other 2 finding types (`pim_unused_eligibility`, `pim_low_frequency_activation`) work correctly.

## Phase 2 (1 week — full bridge)

To close the gap, three additional discovery streams needed:

### Stream A — Activation Policy ingestion (2 days)

Pull `GET /policies/roleManagementPolicies` per directory role:
- `requires_mfa_on_activation` from `EnablementRule` content
- `requires_approval` from `ApprovalRule` content
- `requires_justification` from `JustificationRule` content
- `max_activation_minutes` from `ExpirationRule` content

Update `pim_eligibility_state` rows with the real values instead of defaults. Then `pim_weak_activation_control` finding fires correctly.

### Stream B — Activation History ingestion (2 days)

Pull `GET /auditLogs/directoryAudits` filtered to PIM activation events. Persist to `pim_activation_observations`:
- `activated_at` from event timestamp
- `activation_duration_minutes` from event details
- `justification` from event message
- `audit_event_id` for idempotency (already constrained)

Then `pim_low_frequency_activation` finding fires with real frequency analysis.

### Stream C — Backfill + ongoing job (1 day)

- On first scan: pull last 90 days of audit log activation events
- On subsequent scans: incremental pull since last `discovered_at`
- Scheduled refresh: daily delta sync

### Stream D — Migration of legacy data (1 day)

One-shot migration: for any existing customer org with `pim_eligible_assignments` rows but empty `pim_eligibility_state`, backfill the new table from the old. Then deprecate the old table in a future cleanup.

### Stream E — Test coverage (1 day)

- Mock the Graph API responses for activation policy + audit log endpoints
- Test that all 3 finding types fire correctly with real-data shapes
- Regression test: dual-write doesn't break existing `pim_eligible_assignments` consumers

## Total Phase 2 effort: 7 days (A+B+C+D+E)

Can split across 2 engineers in parallel: A+B done together (3 days each), C+D+E sequenced after (3 days).

## Validation gate

Before declaring Phase 2 done:
- [ ] On localhost org=9 (demo): all 3 PIM finding types fire as expected
- [ ] On cloud-dev org=3 (demo): all 3 PIM finding types fire
- [ ] On a synthetic Entra tenant with 50 eligible assignments: real Graph API ingest succeeds, fields populated correctly
- [ ] On a tenant WITHOUT P2 (logs OFF): graceful degradation — `pim_unused_eligibility` still fires (architectural signal), `pim_low_frequency_activation` shows "unknown frequency"

## Moat compliance reminder

Per `memory/spec_checklist_agentless_readonly.md`:

- ✅ Agentless — all data from Graph API only
- ✅ Read-only — `RoleManagement.Read.Directory` + `Policy.Read.All` + `AuditLog.Read.All`
- ✅ Architecture-derived — Phase 1 (eligibility) works on logs-OFF tenants; Phase 2 enriches with audit logs but doesn't gate

No new permissions required beyond what's already requested.
