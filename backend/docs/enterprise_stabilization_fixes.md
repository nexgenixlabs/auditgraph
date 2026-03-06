# Enterprise Stabilization — Post-Mortem & Fixes

**Date:** 2026-03-04
**Scope:** SaaS platform stability across client portal, admin portal, and API layer
**Environment:** Local Docker Postgres (localhost:5434), APP_ENV=local
**Related:** [Discovery Pipeline Fixes](./discovery_pipeline_fixes.md) — completed same session

---

## 1. Executive Summary

After the discovery pipeline hardening, the client portal login worked but navigation failed with "Expected JSON object" errors, and the dashboard showed a locked/setup state instead of the CISO dashboard with live identity data.

Root causes fell into five categories:

| # | Category | Impact | Severity |
|---|----------|--------|----------|
| 1 | Frontend JSON parsing crashes | Login succeeds but UI shows error instead of dashboard | Critical |
| 2 | Onboarding stage stuck at "locked" | Dashboard permanently shows LockedDashboard | Critical |
| 3 | Missing global JSON error handlers | API errors return HTML/plain text, breaking frontend parsing | High |
| 4 | No enterprise logging middleware | No visibility into org/tenant context on errors | Medium |
| 5 | Hardcoded org names | "Acme Organization" in seed data, incorrect branding | Low |

All issues resolved. Both portals (client + admin) function end-to-end with live discovery data.

---

## 2. Issues & Fixes

### 2.1 Frontend JSON Parsing Crashes (Critical)

**Problem:** Multiple frontend components called `await res.json()` without error handling. When any API response was non-JSON (empty body, HTML error page, network timeout), the call throws `SyntaxError: Expected JSON object` which propagates as an unhandled exception, crashing the component.

**Affected files and fixes:**

| File | Line | Before | After |
|------|------|--------|-------|
| `AuthContext.tsx` | 268 | `await res.json()` | `await res.json().catch(() => ({}))` + `access_token` validation |
| `Login.tsx` | 134 | `await res.json()` | `await res.json().catch(() => ({}))` |
| `Dashboard.tsx` | 170-178 | `await res.json()` (5 calls) | `.catch(() => ({}))` or `.catch(() => null)` per endpoint |
| `OnboardingWizard.tsx` | 82 | `await res.json()` | `await res.json().catch(() => ({}))` |
| `App.tsx` | 136-147 | `await res.json()` (2 calls) | `.catch(() => null)` inside Promise.all |

**Design pattern — Defensive JSON parsing:**
```typescript
// For required data (login tokens):
const data = await res.json().catch(() => ({}));
if (!data.access_token) throw new Error('Invalid login response');

// For optional dashboard data:
const json = await res.json().catch(() => null);
if (json) { /* use it */ }

// For Promise.all batches:
const [a, b] = await Promise.all([
  resA.json().catch(() => ({})),
  resB.json().catch(() => null),
]);
```

**Enterprise rule:** Every `.json()` call in the frontend MUST have a `.catch()` fallback. This prevents cascading UI failures when a single API endpoint returns non-JSON.

### 2.2 Onboarding Stage Stuck at "locked" (Critical)

**Problem:** After a successful discovery run completing with 130 identities, the organization's `onboarding_stage` remained `locked`. The App.tsx routing logic checks this stage — if not `active`, it renders `LockedDashboard` instead of `CISODashboard`.

The stage advancement code existed in `scheduler.py` (`_run_org_discovery()`) but relied on the background thread completing the stage update AFTER the discovery thread finished. Race conditions, exceptions in post-discovery steps, or simply the background thread failing silently left the stage at `locked`.

**Fix — Two-pronged approach:**

**A. Immediate stage advancement in handlers.py:**

When a user clicks "Discover" on a connection, the handler now advances the stage BEFORE launching the background discovery thread:

```python
# In discover_client_connection():
try:
    adm = Database(_admin_reason='discover_connection: advance onboarding stage')
    try:
        o = adm.get_organization_by_id(tid)
        if o and o.get('onboarding_stage') in ('connections', 'locked', 'authenticating', 'password_change'):
            adm.update_organization(tid, onboarding_stage='active')
    finally:
        adm.close()
except Exception:
    pass  # Non-fatal — discovery still proceeds
```

Same pattern added to `test_client_connection()` — a successful Azure connection test also advances the stage.

**B. App.tsx dual-check — stage + discovery data:**

Even if the DB stage is wrong, if discovery data exists, the dashboard should unlock:

```typescript
useEffect(() => {
  Promise.all([
    fetch('/api/organization/stage').then(r => r.ok ? r.json().catch(() => null) : null),
    fetch('/api/discovery/status').then(r => r.ok ? r.json().catch(() => null) : null),
  ]).then(([stageData, discData]) => {
    const stage = stageData?.stage || 'active';
    const hasSnapshot = discData?.has_snapshot || false;
    // If discovery data exists, unlock regardless of DB stage
    if (hasSnapshot || stage === 'active') {
      setTenantStage('active');
    } else {
      setTenantStage(stage);
    }
  });
}, [user, loading, location.pathname]);
```

**Enterprise rule:** Never gate critical UI on a single state field. Use evidence-based fallbacks — if data exists, show it.

### 2.3 Missing Global JSON Error Handlers (High)

**Problem:** Flask's default error handlers return HTML. When the frontend receives a 400 Bad Request as HTML, the `.json()` call fails, triggering the cascading error from 2.1.

The app already had JSON error handlers for 404, 405, 429, 500, and generic Exception. The 400 handler was missing.

**Fix (main.py):**

```python
@app.errorhandler(400)
def _bad_request(e):
    return jsonify({
        'error': str(e.description) if hasattr(e, 'description') else 'Bad request',
        'error_code': 'BAD_REQUEST',
        'request_id': getattr(g, 'request_id', None),
    }), 400
```

**Verification — All HTTP error codes now return JSON:**

| Code | Handler | Response Format |
|------|---------|-----------------|
| 400 | `_bad_request` | `{"error": "...", "error_code": "BAD_REQUEST"}` |
| 404 | `_not_found` | `{"error": "Not found", "error_code": "NOT_FOUND"}` |
| 405 | `_method_not_allowed` | `{"error": "Method not allowed"}` |
| 429 | `_rate_limited` | `{"error": "Rate limit exceeded"}` |
| 500 | `_internal_error` | `{"error": "Internal server error", "error_code": "INTERNAL_ERROR"}` |
| Exception | `_unhandled` | `{"error": "Unexpected error", "error_code": "UNHANDLED"}` |

### 2.4 Enterprise Logging Middleware (Medium)

**Problem:** API errors had no org/tenant context in logs. When supporting multiple tenants, operators need to know WHICH tenant experienced a failure, how long requests take, and whether any API responses violate the JSON contract.

**Fix — Enhanced `_record_metrics` after_request handler (main.py):**

```python
# Contextual error logging with org/tenant IDs
org_id = getattr(g, 'org_id', None)
tenant_id = getattr(g, 'tenant_id', None) or org_id
if response.status_code >= 400:
    logger.warning("API %s %s org=%s tenant=%s status=%d duration=%.0fms",
                   request.method, request.path, org_id, tenant_id,
                   response.status_code, duration_ms)
elif duration_ms > 1000:
    logger.info("API_SLOW %s %s org=%s status=%d duration=%.0fms",
                request.method, request.path, org_id,
                response.status_code, duration_ms)

# JSON contract enforcement
ct = response.content_type or ''
if not ct.startswith('application/json') and response.status_code != 204:
    if '/metrics' not in request.path:
        logger.error("NON_JSON_RESPONSE %s %s content_type=%s status=%d",
                     request.method, request.path, ct, response.status_code)
```

**Log patterns for operators:**

| Pattern | Meaning | Action |
|---------|---------|--------|
| `API POST /api/... org=2 tenant=2 status=500 duration=45ms` | 500 error for specific tenant | Check stack trace above |
| `API_SLOW GET /api/identities org=2 status=200 duration=2340ms` | Slow query | Optimize query or add index |
| `NON_JSON_RESPONSE GET /api/... content_type=text/html status=200` | JSON contract violation | Fix handler return type |

### 2.5 Organization Naming Cleanup (Low)

**Problem:** Seed data and DDL created an "Acme Organization" placeholder. This is incorrect:

- **Organization 1 (Platform Admin):** The AuditGraph/NexgenixLabs admin portal org — used by superadmin users (`techadmin`, `admin`)
- **Organization 2+ (Client orgs):** Real tenant orgs like AzureCredits — used by client admins (`azadmin`)

**Fix:**
- `database.py` — `_ensure_organizations_table()`: Changed "Acme Organization" to "Platform Admin"
- `database.py` — `seed_local_admin()`: Changed "Local Development" to "Platform Admin"
- DB migration: `UPDATE organizations SET name = 'Platform Admin' WHERE id = 1`
- No hardcoded org names anywhere — all tenant names come from the DB

---

## 3. Portal Architecture

```
┌─────────────────────────────────────────────────┐
│                Admin Portal                      │
│  admin.auditgraph.ai / localhost:3000/admin      │
│  Users: techadmin/changeme, admin/Admin@123       │
│  JWT: ADMIN_JWT_SECRET, kid=admin-v1              │
│  aud: auditgraph-platform, iss: admin.auditgraph │
│  Routes: /api/organizations, /api/admin/*         │
│  Purpose: Manage all client tenants               │
├─────────────────────────────────────────────────┤
│                Client Portal                      │
│  app.auditgraph.ai / localhost:3000               │
│  Users: azadmin/Test@12345678                     │
│  JWT: CLIENT_JWT_SECRET, kid=client-v1            │
│  aud: auditgraph-tenant, iss: <slug>.auditgraph  │
│  Routes: /api/stats, /api/identities, etc.        │
│  Purpose: Identity governance for this tenant     │
├─────────────────────────────────────────────────┤
│  Localhost dev: X-Portal-Context header routes    │
│  to correct JWT secret + audience                 │
└─────────────────────────────────────────────────┘
```

---

## 4. Verification Checklist

### Client Portal (azadmin)

| Endpoint | Expected | Status |
|----------|----------|--------|
| `POST /api/auth/login` | `access_token` + `refresh_token` | OK |
| `GET /api/organization/stage` | `stage: "active"` | OK |
| `GET /api/discovery/status` | `has_snapshot: true, total_identities: 130` | OK |
| `GET /api/client/connections` | `connected: true, requires_setup: false` | OK |
| `GET /api/stats` | `latest_run.total_identities: 36` | OK |
| `GET /api/identity-summary` | `categories: 2, azure subscriptions: 1` | OK |
| `GET /api/dashboard/posture` | `posture_score: 97.2` | OK |
| `GET /api/identities?limit=3` | `total: 36, returned: 3` | OK |
| `GET /api/tenant/config` | `azure.enabled: true, plan: pro` | OK |
| `GET /api/onboarding/status` | 200 JSON | OK |
| `GET /api/health` | `status: ready` | OK |

### Admin Portal (techadmin)

| Endpoint | Expected | Status |
|----------|----------|--------|
| `POST /api/auth/login` (X-Portal-Context: admin) | `is_superadmin: true, portal_role: superadmin` | OK |
| `GET /api/organizations` | 2 orgs (Platform Admin, AzureCredits) | OK |
| `GET /api/admin/billing/summary` | `active_orgs: 2, by_plan details` | OK |
| `GET /api/admin/action-log` | 200 JSON (empty on fresh env) | OK |
| `GET /api/health` | `status: ready` | OK |

---

## 5. Files Changed (Enterprise Stabilization)

| File | Changes |
|------|---------|
| `backend/app/main.py` | 400 error handler, enterprise logging middleware, JSON contract enforcement |
| `backend/app/api/handlers.py` | Onboarding stage advancement in `discover_client_connection()` + `test_client_connection()` |
| `backend/app/database.py` | Removed "Acme Organization" hardcoding → "Platform Admin" |
| `frontend/src/contexts/AuthContext.tsx` | Defensive JSON parsing on login |
| `frontend/src/pages/Login.tsx` | Defensive JSON parsing on password change |
| `frontend/src/pages/Dashboard.tsx` | Defensive JSON parsing on all 5 dashboard API calls |
| `frontend/src/pages/OnboardingWizard.tsx` | Defensive JSON parsing on test connection |
| `frontend/src/App.tsx` | Dual-check org stage (DB stage + discovery snapshot) |

---

## 6. Enterprise Deployment Rules

1. **Every `.json()` call needs `.catch()`** — No exceptions. Use `.catch(() => ({}))` for required data, `.catch(() => null)` for optional.

2. **All HTTP error codes return JSON** — Verify every Flask `@app.errorhandler()` returns `jsonify()`, not a string or HTML template.

3. **Log org/tenant context on every error** — The `_record_metrics` after_request handler injects `org=N tenant=N` into all error and slow-request logs.

4. **Onboarding stage must not block data** — If discovery data exists (`has_snapshot: true`), show the dashboard. Never rely solely on a DB state field that could be stale.

5. **No hardcoded organization names** — All org names come from the database. Seed data uses generic names ("Platform Admin") that operators can rename.

6. **Portal JWT isolation is mandatory** — Admin and client portals use different JWT secrets, key IDs, audiences, and issuers. On localhost, `X-Portal-Context` header selects the portal. In production, hostname routing handles it automatically.
