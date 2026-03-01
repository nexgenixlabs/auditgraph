# FIX1A — Platform Consistency & Data Integrity Stabilization

**Date**: 2026-02-28
**Status**: IMPLEMENTED

---

## STEP 1: Count Reconciliation

### Issue
Dashboard posture `dormant_count` used `activity_status = 'stale'` (line 5129 in handlers.py), while **every other endpoint** (SA governance, AGIRS, workload identities, identity governance — 15+ locations) used `IN ('stale', 'never_used')`.

### Fix
Changed `get_dashboard_posture()` to use `IN ('stale', 'never_used')` — now all dormant counts are consistent across:
- Dashboard posture card
- SA governance stats
- AGIRS factors
- Identity governance page
- QuickActions widget
- Drill-down filters

### Verified
All endpoints now use the same dormant definition. Two tests confirm:
- `test_dormant_count_uses_stale_and_never_used`
- `test_sa_governance_dormant_matches`

---

## STEP 2: Dummy Subscriptions

### Finding
Seed script (`backend/scripts/seed_performance_data.py`) is a **manual dev tool** only — never auto-invoked from `create_app()` or production code. No cleanup needed.

### Verified
- `test_no_auto_seed_in_create_app` confirms no seed logic in startup

---

## STEP 3: Connector Duplication

### Finding
Only one canonical route exists: `/settings/connections` in Sidebar.tsx + Settings.tsx `ConnectionsTab`. No duplicate `/connectors` route found.

### Verified
- `test_no_duplicate_connector_routes` confirms no `/api/connectors` route

---

## STEP 4: Effective Access (RBAC Hygiene) Data Pipeline

### Issue
Frontend `EffectiveAccessExplorer.tsx` called `GET /api/rbac-hygiene` but only `/summary` and `/findings` sub-endpoints existed. Page showed empty state with "No RBAC hygiene data available."

### Fix
Added `get_rbac_hygiene_combined()` handler and `GET /api/rbac-hygiene` route that returns the `HygieneData` shape the frontend expects:
```
{ overall_score, grade, total_identities, total_findings, rules[], tier_distribution, scope_breakdown, findings[] }
```

### Verified
- `test_rbac_hygiene_base_endpoint_exists`
- `test_rbac_hygiene_combined_handler_exists`

---

## STEP 5: Sensitive Access (Data Security) Data Pipeline

### Issue
Frontend `SensitiveDataAccess.tsx` called `GET /api/data-security` but only `/summary` existed. Page showed "No resource security data available."

### Fix
Added `get_data_security_combined()` handler and `GET /api/data-security` route that returns the `SecurityData` shape the frontend expects:
```
{ overall_score, overall_grade, total_resources, total_findings, components{}, risk_distribution{}, findings[] }
```
Derives component scores and findings from `risk_components` JSONB on storage accounts + key vaults.

### Verified
- `test_data_security_base_endpoint_exists`
- `test_data_security_combined_handler_exists`

---

## STEP 6: Billing Visibility

### Finding
All billing endpoints exist and are correctly wired:
- `GET /api/billing/history` — returns snapshots
- `GET /api/billing/current-estimate` — live estimate
- `GET /api/billing/invoice/<doc_id>/download` — PDF download
- `GET /api/client/invoices` — invoice list

Data appears when billing snapshots have been generated (manual or scheduled).

### Verified
- `test_billing_history_endpoint_exists`
- `test_billing_invoice_download_endpoint_exists`

---

## STEP 7: Organization Logo Upload

### Issues (2 bugs)

**Bug 1 — Auth mismatch**: Client portal logo routes (`/api/clients/<id>/logo`, `/api/tenants/<id>/logo`) used `@require_portal_role('superadmin', 'poweradmin')`. Client portal users have client roles (admin, security_admin), not portal roles — so every upload from Settings was rejected by auth middleware.

**Fix**: Changed to `@require_role('admin')`. Admin portal routes (`/api/organizations/<id>/logo`) still use `@require_portal_role` correctly.

**Bug 2 — Payload mismatch**: Frontend `GeneralTab.tsx` sent `{ logo: reader.result }` (raw data URL), but backend handler expects `{ logo_data: <base64>, content_type: <mime> }`.

**Fix**: Frontend now parses the data URL, extracts base64 data and content_type, sends correct payload.

### Verified
- `test_client_logo_uses_client_role`
- `test_logo_handler_expects_logo_data`
- `test_frontend_logo_sends_correct_payload`

---

## STEP 8: Snapshot Consistency

### Finding
`_latest_run_ids()` (handlers.py:207-269) is the **single canonical function** used by all data-fetching endpoints (~191 call sites). No ad-hoc snapshot resolution logic exists outside this function. All tabs consistently use the same snapshot(s) via this function.

RBAC Hygiene has its own `rbac_hygiene_scans` table — this is by design (separate analysis engine).

### Verified
- `test_latest_run_ids_used_consistently` — confirms 5 major endpoints use `_latest_run_ids`
- `test_no_duplicate_snapshot_logic` — confirms MAX(id) queries are limited to canonical locations

---

## Files Modified

| File | Changes |
|------|---------|
| `backend/app/api/handlers.py` | Fixed dormant count (stale→stale+never_used), added `get_rbac_hygiene_combined()`, added `get_data_security_combined()` |
| `backend/app/main.py` | Added `/api/rbac-hygiene` + `/api/data-security` routes, imported new handlers, fixed client logo routes to `@require_role('admin')` |
| `frontend/src/components/settings/GeneralTab.tsx` | Fixed logo upload payload (parse data URL → logo_data + content_type) |
| `backend/tests/test_fix1a.py` | **New** — 15 tests |
| `frontend/fixes1a.md` | **New** — this documentation |

## Verification

- [x] 103/103 tests pass (65 existing + 23 guardrails + 15 FIX1A)
- [x] Dormant count now consistent across all endpoints (IN stale, never_used)
- [x] No dummy subscriptions seeded in production startup
- [x] No duplicate connector routes
- [x] `/api/rbac-hygiene` base endpoint returns HygieneData shape
- [x] `/api/data-security` base endpoint returns SecurityData shape
- [x] Billing endpoints exist and are wired
- [x] Client logo upload uses correct auth + payload format
- [x] All tabs use `_latest_run_ids()` for snapshot consistency
