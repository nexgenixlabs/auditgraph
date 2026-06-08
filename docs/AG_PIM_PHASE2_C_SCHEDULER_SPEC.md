# PIM Phase 2 Stream C — Scheduler Delta Sync Spec

**Date**: 2026-06-07
**Status**: Spec only — implementation deferred (1 day estimated)
**Sibling commits**: Streams A (5d053e8), B + D + E (next commit)

## Goal

Keep `pim_eligibility_state` and `pim_activation_observations` continuously fresh between full discovery scans, so the PIM Overprivilege page reflects activity from the last few hours — not just the last discovery cycle.

## Why this matters

Today (post Streams A + B):

| When | Fresh? |
|---|---|
| Full discovery scan (daily by default) | ✅ Yes — eligibility + activations both refreshed |
| Between scans (up to 24h gap) | ❌ Stale — new activations not visible |

For pilot phase this is acceptable. For production at scale, customers expect activation events to surface within ~1 hour of the audit log entry.

## Approach

A new scheduler job: `pim_delta_sync` running every 30-60 minutes per tenant.

For each tenant with PIM data enabled:

1. **Fetch new activations** since `last_pim_sync_at` watermark on the tenant:
   ```
   GET /auditLogs/directoryAudits
       ?$filter=activityDateTime ge {watermark}
              and category eq 'RoleManagement'
              and (activityDisplayName eq 'Add member to role' or
                   activityDisplayName eq 'Add eligible member to role')
       &$top=999
   ```
2. **Parse** each event into a `pim_activation_observations` row using the same parser shape as the discovery code path.
3. **Persist** via the existing `_dual_write_pim_activation_observation` helper — same idempotency guarantees (deterministic synthetic event_id).
4. **Update watermark** to the latest event's `activityDateTime`.
5. **Refresh policies** if any new eligibility detected (covered by the eligibility scheduler — not duplicated here).

## Schema additions needed

One column on `cloud_connections`:

```sql
ALTER TABLE cloud_connections
    ADD COLUMN last_pim_delta_sync_at TIMESTAMPTZ;
```

Defaults to NULL on existing rows → first delta-sync run looks back 90 days
(consistent with the initial backfill window).

## Scheduler hook

`backend/app/scheduler.py` already has `apscheduler` infrastructure. Add:

```python
scheduler.add_job(
    func=pim_delta_sync_all_tenants,
    trigger='interval',
    minutes=int(os.getenv('PIM_DELTA_SYNC_MINUTES', '45')),
    id='pim_delta_sync',
    replace_existing=True,
    max_instances=1,
)
```

The function iterates active cloud_connections, runs the delta pull per tenant, updates the watermark.

## Tests

- Unit: parser + watermark advancement (mock Graph API responses)
- Integration: end-to-end on a synthetic tenant — seed activations after a watermark, verify delta picks them up
- Idempotency: re-run the sync over the same window — no duplicate rows

## Effort

1 day. Code is mostly shaped — the delta query, the watermark update, the scheduler hook. The dual-write target already exists from Stream B.

## What blocks shipping today

Nothing technical — purely session scope. The first pilot doesn't strictly need delta sync since daily discovery captures activations on each cycle. This is a "polish for production scale" item.

## Recommended trigger

Ship this when either:
- First pilot has been running for 30+ days and would benefit from sub-daily freshness
- A second customer signs on and operates at higher activation cadence
- The discovery interval is shortened below 6h (at which point delta sync becomes redundant)
