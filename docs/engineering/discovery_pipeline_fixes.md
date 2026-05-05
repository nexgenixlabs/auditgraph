# Discovery Pipeline — Post-Mortem & Hardening Guide

**Date:** 2026-03-04
**Scope:** Azure identity discovery end-to-end pipeline
**Environment:** Local Docker Postgres (localhost:5434), APP_ENV=local

---

## 1. Executive Summary

During localhost integration testing of the full onboarding-to-discovery flow, the Azure discovery pipeline failed repeatedly after successfully saving 130 identities. Post-save steps (exposure scoring, resource discovery, app registrations) crashed the entire pipeline due to cascading transaction errors.

Root causes fell into four categories:

| # | Category | Impact | Severity |
|---|----------|--------|----------|
| 1 | RLS context loss on COMMIT/ROLLBACK | All tenant-scoped queries fail after any commit | Critical |
| 2 | Missing error isolation in pipeline stages | Single SQL error aborts remaining 8+ stages | Critical |
| 3 | DDL table creation rollback bug | Tables silently not created despite "OK" log | High |
| 4 | Schema drift between migrations and DDL | Missing columns cause runtime SQL errors | Medium |

All issues are now resolved. The pipeline completes end-to-end: 130 identities, 37 app registrations, 10 storage accounts, 10 key vaults, exposure scores, identity groups — all in ~90 seconds.

---

## 2. What Went Wrong

### 2.1 RLS Context Loss on Transaction Boundaries (Critical)

**Problem:** PostgreSQL `SET LOCAL` is transaction-scoped. Every `COMMIT` or `ROLLBACK` resets `app.current_organization_id` to empty string. Subsequent RLS-protected queries fail with:

```
invalid input syntax for type integer: ""
```

This is because RLS policies cast the session variable to integer:
```sql
USING (organization_id = current_setting('app.current_organization_id', true)::integer)
```

**How it manifested:** The discovery engine opens a `Database(organization_id=2)` connection, sets the RLS context via `SET LOCAL`, then calls `save_identity()` which eventually commits. After the commit, the next query (e.g., `save_role_assignment()`) fails because RLS context is gone.

**Why it wasn't caught earlier:** On Azure dev DB with a single `auditgraph` superuser (BYPASSRLS), RLS policies don't enforce — queries succeed regardless of context. The bug only surfaces with strict RLS enforcement or when `SET LOCAL` is actually used for tenant isolation.

**Fix — `_commit()` and `_rollback()` methods (database.py:496-518):**

```python
def _commit(self):
    """Commit and auto-restore RLS context (SET LOCAL is transaction-scoped)."""
    self.conn.commit()
    if self._organization_id is not None:
        self.set_organization_context(self._organization_id)

def _rollback(self):
    """Rollback and auto-restore RLS context (SET LOCAL is transaction-scoped)."""
    self.conn.rollback()
    if self._organization_id is not None:
        self.set_organization_context(self._organization_id)
```

**Scope of change:** Global replacement across the entire codebase — every `self.conn.commit()` → `self._commit()` and every `self.conn.rollback()` → `self._rollback()` in 14 files:

- `database.py` (246 replacements)
- `handlers.py`, `auth.py`, `main.py`, `scheduler.py`
- `drift_detector.py`, `azure_discovery.py`, `aws_discovery.py`
- `p2_ingestion.py`, `behavioral_engine.py`, `agirs_engine.py`
- `billing/service.py`, `entitlements/service.py`, `entitlements/decorator.py`

### 2.2 Missing Error Isolation in Pipeline Stages (Critical)

**Problem:** The `_async_run_discovery()` method runs 12+ sequential stages. Most stages were NOT wrapped in try/except, meaning a SQL error in any stage would:

1. Put the psycopg2 connection into "aborted transaction" state
2. Every subsequent SQL command fails with: `current transaction is aborted, commands ignored until end of transaction block`
3. The discovery run never reaches `complete_discovery_run()` — stays stuck as `status='running'` forever

**How it manifested:** After saving 130 identities, `_compute_workload_exposure()` failed (missing `permission_id` column). This left the connection in error state. All subsequent steps (resource discovery, app registrations, completion) failed with the "aborted transaction" error.

**Fix — Wrap every pipeline stage in try/except with rollback:**

```
Stage                              | Before | After
───────────────────────────────────┼────────┼──────
P2 telemetry ingestion             | bare   | try/except + rollback
Workload exposure scoring          | bare   | try/except + rollback
Behavioral anomaly detection       | bare   | try/except + rollback
Resource discovery (storage/KV)    | bare   | try/except + rollback (per-resource)
Identity exposure enhancement      | bare   | try/except + rollback
App registration discovery         | bare   | try/except + rollback
CA policy save + coverage          | bare   | try/except + rollback
Microsoft flag sweep               | bare   | try/except + rollback
Complete discovery run              | bare   | try/except + fallback UPDATE
Subscription sync                  | try    | + rollback added
Auto identity groups               | try    | + rollback added
Per-identity metadata save         | partial| single try/except wrapping all sub-saves
```

**Design principle:** Each stage is isolated. A failure in resource discovery does NOT prevent app registration discovery, drift detection, or run completion. The run always completes (even if some stages report warnings).

### 2.3 DDL Table Creation Rollback Bug (High)

**Problem:** `_ensure_azure_storage_accounts_table()` and `_ensure_azure_key_vaults_table()` in database.py had a subtle bug:

```python
# BUG: No commit between CREATE TABLE and ALTER TABLE loop
cursor.execute("CREATE TABLE IF NOT EXISTS azure_storage_accounts (...)")
cursor.execute("CREATE INDEX IF NOT EXISTS ...")
# Loop tries to ADD COLUMN — if col already exists, exception handler calls _rollback()
for col, defn in [...]:
    try:
        cursor.execute(f"ALTER TABLE ... ADD COLUMN {col} {defn}")
    except Exception:
        self._rollback()  # THIS ROLLS BACK THE CREATE TABLE TOO!
self._commit()  # Commits nothing — table was already rolled back
```

The `_rollback()` inside the ADD COLUMN loop rolls back the entire transaction, including the `CREATE TABLE` and `CREATE INDEX` statements. The method returns without error, but the table doesn't exist.

**Fix — Commit after CREATE, per-column commit/rollback:**

```python
cursor.execute("CREATE TABLE IF NOT EXISTS azure_storage_accounts (...)")
cursor.execute("CREATE INDEX IF NOT EXISTS ...")
self._commit()  # Lock in the table creation

for col, defn in [...]:
    try:
        cursor.execute(f"ALTER TABLE ... ADD COLUMN IF NOT EXISTS {col} {defn}")
        self._commit()  # Lock in each column addition
    except Exception:
        self._rollback()  # Only rolls back THIS column attempt
```

### 2.4 Schema Drift — Missing Columns (Medium)

**Problem:** The `_compute_workload_exposure()` method queries `graph_api_permissions` for columns (`permission_id`, `permission_type`) that don't exist in the actual table schema. The table only has `permission_name` and `risk_level`.

This happened because the exposure engine was written against a newer schema definition that was never applied to the migration or DDL methods.

**Fix:** Updated the query to use actual columns:

```python
# Before (broken):
SELECT identity_db_id, permission_id, permission_name, permission_type
FROM graph_api_permissions WHERE ...

# After (fixed):
SELECT identity_db_id, permission_name, risk_level
FROM graph_api_permissions WHERE ...
```

### 2.5 Async Event Loop Conflict (Medium)

**Problem:** `run_discovery()` calls `asyncio.run(self._async_run_discovery())` which creates a new event loop. Inside `_async_run_discovery()`, the app registration step called `asyncio.get_event_loop().run_until_complete(self._discover_app_registrations(...))` — trying to synchronously execute an async function from within an already-running event loop.

```
RuntimeError: This event loop is already running
```

**Fix:** Since `_async_run_discovery()` is already an async method, use `await`:

```python
# Before (broken):
app_regs = asyncio.get_event_loop().run_until_complete(
    self._discover_app_registrations(spn_app_id_map)
)

# After (fixed):
app_regs = await self._discover_app_registrations(spn_app_id_map)
```

---

## 3. Additional Pipeline Improvements

### 3.1 Subscription Auto-Insert on Connection Test

**Problem:** When a user tests an Azure connection, subscriptions are discovered from the Azure API but were NOT persisted to `cloud_subscriptions`. The user had to manually create/activate subscriptions before discovery could run.

**Fix (handlers.py — `test_client_connection()`):**

```python
for s in subs:
    cursor.execute("""
        INSERT INTO cloud_subscriptions
            (organization_id, cloud, account_id, account_name, status, cloud_connection_id)
        VALUES (%s, 'azure', %s, %s, 'discovered', %s)
        ON CONFLICT (organization_id, cloud, account_id) DO UPDATE
            SET account_name = EXCLUDED.account_name,
                cloud_connection_id = EXCLUDED.cloud_connection_id,
                deleted = false
    """, (tid, s['id'], s['name'], connection_id))
```

### 3.2 Auto-Activation Before Discovery

**Problem:** Even with subscriptions in the database, they defaulted to `monitored=false`. Discovery skips unmonitored subscriptions. Users had to manually activate each one.

**Fix (handlers.py — `discover_client_connection()`):**

```python
cursor.execute("""
    UPDATE cloud_subscriptions
    SET monitored = true, status = 'active',
        activated_at = NOW(), activated_by = %s
    WHERE organization_id = %s
      AND cloud_connection_id = %s
      AND monitored = false AND deleted = false
    RETURNING id, account_id
""", (user_id, tid, connection_id))
```

### 3.3 Credential-Based Discovery Toggle

**Problem:** `AZURE_DISCOVERY_ENABLED = not IS_LOCAL` prevented discovery from running on localhost even when valid Azure credentials were present.

**Fix (config.py):**

```python
# Before: AZURE_DISCOVERY_ENABLED = not IS_LOCAL
AZURE_DISCOVERY_ENABLED = bool(os.getenv("AZURE_TENANT_ID") and os.getenv("AZURE_CLIENT_ID"))
```

Discovery is now enabled whenever credentials are present, regardless of environment tier.

---

## 4. Enterprise Deployment Implications

### 4.1 Multi-Tenant RLS Safety

The `_commit()` / `_rollback()` pattern is **mandatory** for any multi-tenant PostgreSQL deployment using `SET LOCAL` for row-level security:

- Every commit/rollback clears the session variable
- Without auto-restore, cross-tenant data leakage or query failures occur
- This applies to ALL code paths, not just discovery — handlers, scheduler, billing, entitlements

**Deployment checklist item:** Verify that no raw `self.conn.commit()` or `self.conn.rollback()` calls exist outside of `_commit()` / `_rollback()`. Run:
```bash
grep -rn "\.conn\.commit\(\)\|\.conn\.rollback\(\)" app/ --include="*.py"
```
Expected: zero results outside of `_commit()` and `_rollback()` method definitions.

### 4.2 Discovery Pipeline Resilience

For enterprise tenants with thousands of identities, partial failures are inevitable:

- Graph API rate limiting causes timeouts on PIM/CA queries
- Missing licenses (e.g., no Azure AD Premium) cause permission errors
- Large tenants hit pagination edge cases

The isolated error handling ensures:
- A PIM discovery failure doesn't prevent identity save
- A resource discovery failure doesn't prevent run completion
- The run always reaches `status='completed'` with a count of what was saved
- Operators can inspect logs for `⚠️` warnings to identify skipped stages

### 4.3 Schema Migration Safety

DDL methods that combine `CREATE TABLE` + `ALTER TABLE ADD COLUMN` must commit between them. Enterprise pattern:

```python
# 1. Create the table
cursor.execute("CREATE TABLE IF NOT EXISTS ...")
self._commit()  # Lock it in

# 2. Add columns individually (idempotent)
for col, defn in new_columns:
    try:
        cursor.execute(f"ALTER TABLE ... ADD COLUMN IF NOT EXISTS {col} {defn}")
        self._commit()
    except Exception:
        self._rollback()  # Only this column fails
```

This prevents:
- Silent table creation failures that pass without error
- DDL deadlocks when multiple gunicorn workers run startup DDL simultaneously
- Schema drift between environments

### 4.4 Onboarding Flow Automation

The subscription auto-insert and auto-activation changes eliminate manual steps from the onboarding flow:

```
Before: Connect → Test → (manually create subs) → (manually activate) → Discover
After:  Connect → Test (auto-inserts subs) → Discover (auto-activates) → Done
```

This reduces onboarding friction for enterprise customers and eliminates a common support ticket category ("discovery found no identities" — because subscriptions weren't activated).

### 4.5 Local Development Parity

The credential-based discovery toggle ensures developers can run the full pipeline locally with Docker Postgres + real Azure credentials, matching production behavior. The safety guard in `config.py` still prevents `APP_ENV=local` from connecting to Azure-hosted databases.

---

## 5. Files Changed

| File | Changes | Lines |
|------|---------|-------|
| `app/database.py` | `_commit()`, `_rollback()` methods; global commit/rollback replacement; DDL table fix | ~300 |
| `app/engines/discovery/azure_discovery.py` | Error isolation for all 12 stages; `permission_id` fix; async `await` fix | ~80 |
| `app/api/handlers.py` | Subscription auto-insert; auto-activation; onboarding stage check | ~40 |
| `app/config.py` | Credential-based discovery toggle | ~3 |
| `app/scheduler.py` | Onboarding stage check update | ~2 |
| 9 other files | Global `conn.commit()` → `_commit()` replacement | ~50 |

---

## 6. Verification

### Test Sequence (localhost)

```bash
# 1. Start Docker Postgres
docker compose up -d auditgraph-postgres

# 2. Start backend
APP_ENV=local ./venv/bin/python -m app.main

# 3. Login as client admin
curl -s -X POST http://localhost:5001/api/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Portal-Context: client' \
  -d '{"username":"azadmin","password":"<password>"}'

# 4. Test connection (auto-inserts subscriptions)
curl -s -X POST http://localhost:5001/api/client/connections/<id>/test \
  -H "Authorization: Bearer <token>"

# 5. Trigger discovery (auto-activates subscriptions)
curl -s -X POST http://localhost:5001/api/client/connections/<id>/discover \
  -H "Authorization: Bearer <token>"

# 6. Verify completion
psql -c "SELECT status, total_identities FROM discovery_runs ORDER BY id DESC LIMIT 1;"
# Expected: status=completed, total_identities=130
```

### Expected Output Markers

```
✓ Saved 130 identities
✓ Computed exposure for 31 SPNs/MIs (0 critical)
✓ Found 10 storage accounts
✓ Found 10 key vaults
✓ Saved 10 storage accounts, 10 key vaults
✓ Identity exposure enhanced + risk history saved for 20 resources
✓ Found 37 app registrations
✓ Saved 37 app registrations
✓ Discovery run completed
✓ Synced 1 subscription(s) to registry
✓ Auto identity groups seeded for organization 2
```

### Warning Markers (Non-Fatal)

Any `⚠️` lines indicate skipped stages — investigate but not blocking:
```
⚠️ P2 telemetry ingestion error: ...    → No P2 license
⚠️ Behavioral anomaly detection error: ... → Expected without P2
⚠️ Sign-in activity requires Premium license → Basic user data used instead
```
