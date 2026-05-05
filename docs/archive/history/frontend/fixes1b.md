# FIX1B — Metric Source of Truth Refactor

**Date**: 2026-02-28
**Status**: IMPLEMENTED

---

## STEP 1: Metric Registry

### Issue
Dashboard counts and drill-down filters used independent SQL WHERE clauses scattered across handlers.py. No single source of truth for metric definitions — making it easy for dashboard and drill-down to drift apart.

### Fix
Created `backend/app/api/metric_queries.py` — canonical metric query definitions:
- `BASE_IDENTITY_WHERE` — shared base (discovery_run_id + exclude Microsoft first-party)
- 13 metric-specific WHERE fragments: dormant, dormant_nhi, dormant_human, privileged, high_risk, critical, over_permissioned, unowned_nhi, credential_expired, credential_expiring, credential_healthy, no_credentials, ghost
- `METRIC_REGISTRY` — maps metric name → WHERE fragment
- `get_metric_count_sql()` — returns full COUNT SQL for dashboard
- `get_metric_where()` — returns WHERE fragment for drill-down append
- `get_latest_snapshot_ids()` — canonical snapshot resolver alias

### Verified
- `test_metric_registry_has_all_metrics` — all 13 metrics registered
- `test_metric_count_sql_returns_valid_sql` — COUNT SQL has correct structure
- `test_metric_count_sql_rejects_unknown` — raises ValueError for unknown metrics

---

## STEP 2: Dashboard Uses Canonical Queries

### Issue
`get_dashboard_posture()` had inline SQL for credential health (expired, expiring, healthy, no_credentials), dormant count, and no-owner count. These were independent of the drill-down filters.

### Fix
Refactored `get_dashboard_posture()` to use `get_metric_count_sql()` for all 6 metric counts:
- `credential_expired`, `credential_expiring`, `credential_healthy`, `no_credentials`
- `dormant`
- `unowned_nhi`

### Verified
- `test_dashboard_posture_uses_canonical_queries` — all 6 canonical calls present
- `test_no_inline_dormant_sql_in_posture` — no inline `activity_status = 'stale'`
- `test_no_inline_credential_sql_in_posture` — no inline `credential_expiration` filters

---

## STEP 3: Drill-Down Filters Use Canonical Queries

### Issue
`GET /api/identities` had no way to filter by credential status, owner status, or arbitrary metric — drill-down from dashboard cards required manual URL construction with ad-hoc filters.

### Fix
Added 3 new query parameters to `get_identities()`:
- `?credential_status=expired|expiring_soon|healthy|no_credentials` — uses `get_metric_where()` for canonical credential filtering
- `?has_owner=false` — uses `get_metric_where('unowned_nhi')` for unowned NHI drill-down
- `?metric=<name>` — uses `METRIC_REGISTRY` for any registered metric drill-down

### Verified
- `test_identities_has_credential_status_filter`
- `test_identities_has_owner_filter`
- `test_identities_has_metric_filter`
- `test_canonical_definitions_match` — METRIC_DORMANT includes both 'stale' and 'never_used'

---

## STEP 4: Snapshot Selection Centralization

### Issue
All metric endpoints already used `_latest_run_ids()` but there was no canonical alias in metric_queries.py to enforce the pattern.

### Fix
Added `get_latest_snapshot_ids()` in metric_queries.py that delegates to `_latest_run_ids`. This is the canonical name for the snapshot resolver.

### Verified
- `test_get_latest_snapshot_ids_exists`
- `test_get_latest_snapshot_ids_delegates`
- 8 endpoint tests confirming `_latest_run_ids` usage: get_stats, get_dashboard_posture, get_identities, get_identity_summary, get_attack_surface_score, get_spn_stats, get_sa_governance_stats

---

## STEP 5: No Raw Summary Table Reads

### Verified
- `test_stats_does_not_use_discovery_runs_columns_for_counts` — get_stats uses `FROM identities i`
- `test_posture_does_not_read_precomputed` — get_dashboard_posture queries identities table

---

## STEP 6: Hard Parity & Snapshot Lock

### Verified
- `test_parity_dormant_dashboard_vs_drilldown` — dashboard and drill-down share canonical METRIC_DORMANT
- `test_parity_credential_dashboard_vs_drilldown` — dashboard and drill-down share canonical credential metrics
- `test_parity_unowned_dashboard_vs_drilldown` — dashboard and drill-down share canonical METRIC_UNOWNED_NHI
- `test_no_manual_snapshot_in_metric_endpoints` — no `SELECT MAX(id)` in metric functions
- `test_all_metric_endpoints_call_latest_run_ids` — 9 endpoints centralized
- `test_canonical_dormant_is_consistent` — stale + never_used
- `test_canonical_unowned_excludes_humans` — excludes human_user + guest
- `test_canonical_ghost_requires_roles` — checks disabled + active role assignments
- `test_base_where_filters_microsoft` — excludes Microsoft first-party

---

## Files Modified

| File | Changes |
|------|---------|
| `backend/app/api/metric_queries.py` | **New** — 13 canonical metric definitions, METRIC_REGISTRY, get_metric_count_sql(), get_metric_where(), get_latest_snapshot_ids() |
| `backend/app/api/handlers.py` | Refactored get_dashboard_posture() to use canonical queries, added 3 drill-down filters to get_identities() |
| `backend/tests/test_fix1b.py` | **New** — 30 tests |
| `backend/tests/test_fix1a.py` | Updated 2 tests to reflect FIX1B canonical refactor |
| `frontend/fixes1b.md` | **New** — this documentation |

## Verification

- [x] 133/133 tests pass (103 existing + 30 FIX1B)
- [x] All dashboard metric counts use canonical get_metric_count_sql()
- [x] All drill-down filters use canonical get_metric_where()
- [x] No inline metric SQL remains in get_dashboard_posture()
- [x] Snapshot selection centralized via _latest_run_ids across 9 endpoints
- [x] Hard parity confirmed for dormant, credential, and unowned metrics
- [x] No manual MAX(id) snapshot computation in metric endpoints
