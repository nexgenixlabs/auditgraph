# FIX1C — Multi-Connector Canonicalization & Integrity Hardening

## Problem
The cloud_connections system supported multiple connectors per provider per org but lacked critical integrity constraints:
- No cross-org uniqueness (same Azure directory reusable by multiple orgs)
- No FK from cloud_subscriptions → cloud_connections
- Column `azure_directory_id` used for all clouds (misleading)
- `delete_client_connection()` didn't call `track_usage`
- UI rendered a flat list instead of grouping by provider

## Changes

### Stage 1: Migration 023 — `external_id`, Constraints, FK
- Added `external_id` VARCHAR(100) column to `cloud_connections` (cloud-agnostic identifier)
- Backfill from `azure_directory_id` where NULL
- Deduplication of cross-org conflicts (keep earliest per cloud+external_id)
- `uq_org_provider_external` — per-org uniqueness constraint
- `uq_provider_external_global` — global uniqueness (prevents same cloud account across orgs)
- `fk_subscription_connector` — FK from `cloud_subscriptions.cloud_connection_id` → `cloud_connections.id` with CASCADE

### Stage 2: Canonical Connector Service Layer
- New `backend/app/connectors.py` with:
  - `get_connectors(db, org_id, cloud=None)` — all connectors for org
  - `get_connector(db, org_id, cloud, external_id)` — single connector lookup
  - `validate_connector_unique(db, cloud, external_id)` — cross-org uniqueness check
- `create_client_connection()` — validates cross-org uniqueness before INSERT (409 if duplicate)
- `delete_client_connection()` — now calls `track_usage()` after delete

### Stage 3: Frontend Provider-Grouped Rendering
- `ConnectionsTab.tsx` — connections grouped by provider (Azure/AWS/GCP) instead of flat list
- Each provider section has a header with count badge
- Only providers with connections are shown

### Stage 4: Tests
- 13 source-inspection tests in `backend/tests/test_fix1c.py`
- Covers migration DDL, handler logic, RLS, billing, scheduler, service layer, UI

## Files Modified
| File | Action |
|------|--------|
| `backend/app/database.py` | Migration 023 + updated `create_cloud_connection` |
| `backend/app/connectors.py` | **New** — canonical connector service |
| `backend/app/api/handlers.py` | Cross-org validation + track_usage in delete |
| `frontend/src/components/settings/ConnectionsTab.tsx` | Provider-grouped rendering |
| `backend/tests/test_fix1c.py` | **New** — 13 tests |

## Verification
```bash
cd backend && FLASK_ENV=development ./venv/bin/python -m pytest tests/test_fix1c.py -v
```
