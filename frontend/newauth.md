# Phase 1A — Auth & Control Plane Isolation Audit + Phase 1B Implementation

**Date**: 2026-02-28
**Scope**: JWT issuance, middleware, role model, cookie/token scoping, admin↔tenant boundary
**Status**: Phase 1A = READ-ONLY audit (below), Phase 1B = IMPLEMENTED (see bottom)

---

## 1. Current Auth Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        SINGLE Flask Backend (app.main)                       │
│                    https://api.auditgraph.ai (port 5000)                     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    auth_middleware() [before_request]                    │ │
│  │                                                                         │ │
│  │  1. PUBLIC_PATHS bypass (login, refresh, health, metrics, SAML, etc.)   │ │
│  │  2. API key auth (X-API-Key / Bearer ag_...)                           │ │
│  │  3. JWT auth (Bearer <token>) → verify_access_token()                  │ │
│  │  4. Superadmin X-Tenant-Id override                                    │ │
│  │  5. Host↔Tenant guard (subdomain slug vs JWT tenant_id)                │ │
│  │  6. Trial expiry check                                                  │ │
│  │                                                                         │ │
│  │  OUTPUT: g.current_user = { id, username, role, tenant_id,             │ │
│  │           is_superadmin, portal_role, ... }                             │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌──────────────────────┐  ┌─────────────────────┐  ┌────────────────────┐  │
│  │  TENANT ROUTES       │  │  ADMIN ROUTES        │  │  SHARED ROUTES     │  │
│  │                      │  │                      │  │                    │  │
│  │  @require_role(...)   │  │  @require_portal_*() │  │  /api/auth/login   │  │
│  │  @require_feature()   │  │  @require_superadmin │  │  /api/auth/refresh │  │
│  │                      │  │                      │  │  /api/auth/me      │  │
│  │  /api/identities     │  │  /api/admin/*        │  │  /api/auth/logout  │  │
│  │  /api/stats           │  │  /api/tenants        │  │                    │  │
│  │  /api/dashboard/*     │  │  /api/clients        │  │                    │  │
│  │  /api/settings        │  │                      │  │                    │  │
│  └──────────────────────┘  └─────────────────────┘  └────────────────────┘  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     SINGLE JWT Issuer & Secret                          │ │
│  │                                                                         │ │
│  │  JWT_SECRET = os.getenv('JWT_SECRET')     # ONE key for everything     │ │
│  │  JWT_ALGORITHM = 'HS256'                                                │ │
│  │  ACCESS_TOKEN_EXPIRY = 24 hours                                        │ │
│  │  REFRESH_TOKEN_EXPIRY = 7 days                                         │ │
│  │                                                                         │ │
│  │  No `iss` claim (no issuer)                                            │ │
│  │  No `aud` claim (no audience)                                          │ │
│  │  No portal-scoped claim (admin vs client not in token)                 │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                      FRONTEND (Single React SPA)                             │
│         app.auditgraph.ai / admin.auditgraph.ai / {slug}.auditgraph.ai       │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    AuthContext (SHARED — one instance)                   │ │
│  │                                                                         │ │
│  │  detectPortal(): hostname starts with 'admin.' OR path starts          │ │
│  │                  with '/admin' → 'admin', else → 'client'              │ │
│  │                                                                         │ │
│  │  tokenKeys('admin'):  admin_access_token, admin_refresh_token          │ │
│  │  tokenKeys('client'): access_token, refresh_token                      │ │
│  │                                                                         │ │
│  │  Storage: localStorage (NOT cookies, NOT sessionStorage)               │ │
│  │  Token attachment: global window.fetch interceptor                     │ │
│  │  Login endpoint: SAME /api/auth/login (portal param differentiates)    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌──────────────────────┐  ┌─────────────────────────────────────────────┐  │
│  │  CLIENT PORTAL       │  │  ADMIN PORTAL                               │  │
│  │                      │  │                                             │  │
│  │  App.tsx → Routes    │  │  AdminConsole.tsx (standalone layout)       │  │
│  │  ProtectedRoute      │  │  Own login form (AdminLogin component)      │  │
│  │  checks: user != null│  │  Checks: portal_role in VALID_PORTAL_ROLES │  │
│  │                      │  │  Own sidebar, own topbar, own route tree    │  │
│  │  Route: /admin/* →   │  │  Mounted at /admin/* or /* on admin.       │  │
│  │  renders AdminConsole│  │  subdomain                                  │  │
│  └──────────────────────┘  └─────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Goal 1 — Same JWT Issuer / Key / Middleware / Role Model?

| Question | Answer | Evidence |
|----------|--------|----------|
| Same JWT signing key? | **YES** — single `JWT_SECRET` env var | `auth.py:16` — one key, no per-portal differentiation |
| Same JWT issuer? | **No issuer at all** — no `iss` claim in token | `auth.py:43-56` — payload has `sub`, `role`, `tenant_id`, `is_superadmin`, `portal_role`, `type` — no `iss` or `aud` |
| Same middleware? | **YES** — single `auth_middleware()` as `before_request` | `main.py:305` — `app.before_request(auth_middleware)`. Every request flows through the same function. |
| Same role model? | **TWO overlapping role systems in ONE token** — `role` (client) + `portal_role` (admin) coexist in the same JWT | `auth.py:46,51` — both `role` and `portal_role` are set in every token |

### Structural Analysis of JWT Claims

```json
{
  "sub": "42",
  "username": "techadmin",
  "role": "admin",              ← CLIENT role (admin/security_admin/compliance/reader)
  "display_name": "Tech Admin",
  "tenant_id": null,            ← null for platform admins
  "tenant_name": null,
  "is_superadmin": true,        ← boolean flag (legacy, predates portal_role)
  "portal_role": "superadmin",  ← PORTAL role (superadmin/poweradmin/billing/reader)
  "force_password_change": false,
  "iat": 1740700000,
  "exp": 1740786400,
  "type": "access"
}
```

**No `iss`, no `aud`, no `portal` scope claim.** The token does not declare which portal it was issued for.

---

## 3. Goal 2 — Authentication Flow Analysis

### 3.1 Shared Auth Libraries

| Component | Shared? | Detail |
|-----------|---------|--------|
| Login endpoint | **YES** | Single `POST /api/auth/login` — `handlers.py:6627` |
| Token generation | **YES** | Single `generate_access_token()` — `auth.py:41` |
| Token verification | **YES** | Single `verify_access_token()` — `auth.py:75-77` |
| Token refresh | **YES** | Single `POST /api/auth/refresh` — `auth.py:60` |
| Role validation | **YES** | Same `auth_middleware()` for all routes |
| Logout | **YES** | Single `POST /api/auth/logout` |

### 3.2 Login Portal Enforcement

The login handler **does differentiate** admin vs client at login time (`handlers.py:6682-6691`):

```python
if portal == 'client':
    # Block admin-portal users from client portal login
    if user.get('is_superadmin') or user.get('portal_role') in (...):
        return 403  "Platform administrators must use the admin portal."
elif portal == 'admin':
    # Block client-only users from admin portal login
    if not user.get('is_superadmin') and portal_role not in (...):
        return 403  "Access denied. This portal is for platform administrators only."
```

**However**: the `portal` parameter comes from the **frontend request body** (`data.get('portal', 'client')`). It is NOT derived from the request origin/host. An attacker can send `{"portal": "admin"}` from any origin.

### 3.3 Token Structural Identity

Admin JWT and tenant JWT are **structurally identical**. The difference is only in the claim VALUES:
- Admin: `portal_role: "superadmin"`, `is_superadmin: true`, `tenant_id: null`
- Tenant: `portal_role: null`, `is_superadmin: false`, `tenant_id: 5`

There is no structural marker (like `aud: "admin"` vs `aud: "client"`) to distinguish them.

---

## 4. Goal 3 — Route Protection Analysis

### 4.1 Admin Route Decorators

All `/api/admin/*` routes and `/api/tenants` routes use portal-scoped decorators:

| Decorator | Check | File |
|-----------|-------|------|
| `@require_portal_access()` | `portal_role in VALID_PORTAL_ROLES or is_superadmin` | `auth.py:278-292` |
| `@require_portal_role('superadmin', 'poweradmin')` | `portal_role in allowed_roles or is_superadmin` | `auth.py:295-309` |
| `@require_superadmin()` | `is_superadmin == True` | `auth.py:263-275` |

### 4.2 Can a Tenant Token Access Admin Endpoints?

**NO** — a tenant user with `role: 'admin'` but `portal_role: null` and `is_superadmin: false`:
- `require_portal_access()` → checks `portal_role in VALID_PORTAL_ROLES` → `null` not in tuple → checks `is_superadmin` → `false` → **403** ✓
- `require_portal_role(...)` → same check → **403** ✓
- `require_superadmin()` → `is_superadmin` is `false` → **403** ✓

**The role name collision (`admin` client role vs portal roles) does NOT cause confusion** because admin routes check `portal_role`/`is_superadmin`, not `role`.

### 4.3 Can an Admin Token Access Tenant Endpoints?

**YES** — an admin token with `portal_role: 'superadmin'` and `role: 'admin'`:
- `require_role('admin')` → checks `user['role'] == 'admin'` → **passes** ✓ (by design — superadmins have client role 'admin')
- All tenant data endpoints pass because superadmins bypass RLS via `Database()` with no tenant context

**This is by design** for cross-tenant management, but means a stolen admin token grants access to ALL tenant data AND admin endpoints.

### 4.4 Missing Origin/Host Enforcement on Admin Routes

**CRITICAL FINDING**: Admin routes (`/api/admin/*`, `/api/tenants`, `/api/clients`) have **no host/origin check**. The `auth_middleware()` host-tenant guard at `auth.py:194` explicitly **exempts** users with `portal_role`:

```python
if not g.current_user.get('is_superadmin') and not g.current_user.get('portal_role'):
    # host guard logic...
```

This means:
- A request from `tenant-a.auditgraph.ai` with an admin JWT can call `/api/admin/tenants` → **succeeds**
- A request from `app.auditgraph.ai` with an admin JWT can call `/api/admin/billing/summary` → **succeeds**
- There is NO enforcement that admin routes are only callable from `admin.auditgraph.ai`

---

## 5. Goal 4 — Cookie & Token Storage Analysis

### 5.1 Storage Mechanism

**No cookies are used.** The entire auth system uses `localStorage`:

| Portal | Access Token Key | Refresh Token Key | File |
|--------|-----------------|-------------------|------|
| Client | `access_token` | `refresh_token` | `AuthContext.tsx:71` |
| Admin | `admin_access_token` | `admin_refresh_token` | `AuthContext.tsx:69` |

Additionally stored:
- `active_tenant_id` — superadmin tenant override (shared across portals)
- `active_tenant_name` — display label for active tenant

### 5.2 Domain Scoping

**localStorage is origin-scoped by the browser** (protocol + hostname + port). This means:

| Origin | localStorage Scope | Isolated? |
|--------|--------------------|-----------|
| `https://admin.auditgraph.ai` | Own scope | ✓ Isolated from tenant subdomains |
| `https://app.auditgraph.ai` | Own scope | ✓ Isolated from admin |
| `https://acme.auditgraph.ai` | Own scope | ✓ Isolated from other tenants |
| `http://localhost:3000` | Single scope | **SHARED** — admin + client share localStorage in dev |

**In production, localStorage provides natural isolation between subdomains.** This is a strength.

### 5.3 Dev Mode Weakness

In development (`localhost:3000`), both admin and client portals run on the same origin. The `tokenKeys()` function differentiates by using `admin_access_token` vs `access_token` keys, which prevents accidental token mixing. However:

- Both tokens exist in the **same localStorage** on localhost
- A malicious script on localhost could read both tokens
- The `active_tenant_id` key is **shared** across portals (not prefixed)

### 5.4 No Cookie Flags (N/A)

Since no cookies are used, there are no `HttpOnly`, `Secure`, `SameSite`, or `Domain` concerns. The tradeoff:
- **Pro**: No CSRF vulnerability (no auto-attached credentials)
- **Con**: Tokens accessible to any JS on the page (XSS = full compromise)

---

## 6. Boundary Weaknesses

### CRITICAL (1)

| ID | Finding | Impact | File:Line |
|----|---------|--------|-----------|
| **C1** | **No `iss`/`aud` claims in JWT — tokens are structurally interchangeable between portals** | A JWT issued during admin portal login is byte-identical in structure to a client portal JWT. There is no cryptographic or structural way to restrict a token to one portal. The backend cannot distinguish "this token was issued for admin use" vs "this token was issued for client use." | `auth.py:43-56` |

### HIGH (4)

| ID | Finding | Impact | File:Line |
|----|---------|--------|-----------|
| **H1** | **Admin API routes have no origin/host enforcement** | Any HTTP client with a valid admin JWT can call `/api/admin/*` from any origin. The host-tenant guard explicitly exempts `portal_role` users. Admin routes are accessible from `tenant-a.auditgraph.ai`, `curl`, or any CORS-exempt client. | `auth.py:194` |
| **H2** | **`portal` parameter in login is client-supplied, not derived from host** | The login handler trusts `data.get('portal', 'client')` to determine whether to allow admin login. An attacker could POST `{"portal": "admin", "username": "...", "password": "..."}` to the login endpoint from any origin to attempt admin authentication. The login handler blocks non-portal users, but the portal parameter itself is not validated against the request origin. | `handlers.py:6633` |
| **H3** | **Single JWT secret for both portals — no key isolation** | Compromise of `JWT_SECRET` allows forging tokens for BOTH admin and tenant portals. No key rotation mechanism exists. No per-portal key separation. | `auth.py:16-18` |
| **H4** | **Admin token grants full tenant data access (by design but high blast radius)** | A superadmin JWT has `role: 'admin'` which passes all `@require_role('admin')` checks AND `is_superadmin: true` which bypasses RLS. A single stolen admin token = full platform compromise (all tenants, all admin functions). | `auth.py:263-275` |

### MEDIUM (5)

| ID | Finding | Impact | File:Line |
|----|---------|--------|-----------|
| **M1** | **Host-tenant guard silently passes on DB errors** | `except Exception: pass` at auth.py:216-217 means database outages disable the cross-subdomain token guard entirely. Tokens become reusable across subdomains during DB failures. | `auth.py:216-217` |
| **M2** | **Refresh tokens not portal-scoped** | A refresh token issued during admin login can be used at `POST /api/auth/refresh` to get new tokens. The refresh endpoint (`handlers.py:6745`) does not check which portal the original token was issued for. A stolen admin refresh token remains valid even if the admin access token expires. | `handlers.py:6745-6762` |
| **M3** | **`active_tenant_id` localStorage key shared across portals (dev mode)** | In production this is isolated by origin, but in dev mode both portals share the same localStorage. The `active_tenant_id` key is not portal-prefixed, meaning admin portal tenant switching can affect client portal requests. | `AuthContext.tsx:82-97` |
| **M4** | **24-hour access token TTL is excessive for admin tokens** | Admin tokens should have shorter TTLs (15-30 min) given their elevated privileges. A stolen admin token provides 24 hours of unrestricted access. | `auth.py:20` |
| **M5** | **No token binding (no fingerprint, no IP lock)** | JWTs have no device fingerprint, IP binding, or browser binding. A token extracted via XSS or MITM works from any client, any IP, any location for the full 24-hour TTL. | `auth.py:43-56` |

### LOW (3)

| ID | Finding | Impact | File:Line |
|----|---------|--------|-----------|
| **L1** | **AdminConsole frontend check is UI-only** | `AdminConsole.tsx:147` checks `if (!user \|\| !hasPortalAccess)` but this is a JS guard. A user who manually navigates to `/admin` sees the admin login form, not the admin console. However, the actual protection is backend-side (`@require_portal_access`), so this is defense-in-depth, not a vulnerability. | `AdminConsole.tsx:147` |
| **L2** | **Login sends `portal` context but token doesn't encode it** | The login handler receives `portal: 'admin'` and enforces access, but the resulting JWT does not contain a `portal` claim. The backend cannot later verify which portal the token was originally issued through. | `handlers.py:6633`, `auth.py:43-56` |
| **L3** | **`isAdminAccessible` allows admin route rendering on localhost** | `App.tsx:190-192` allows `/admin/*` routes to render on localhost without the admin subdomain. This is dev convenience but means any dev-mode user can access the admin UI (backend still blocks unauthorized access). | `App.tsx:190-192` |

---

## 7. Summary Matrix

| Property | admin.auditgraph.ai | {slug}.auditgraph.ai | app.auditgraph.ai |
|----------|---------------------|----------------------|-------------------|
| JWT issuer | None | None | None |
| JWT signing key | `JWT_SECRET` | `JWT_SECRET` | `JWT_SECRET` |
| JWT audience | None | None | None |
| Middleware | `auth_middleware()` | `auth_middleware()` | `auth_middleware()` |
| Login endpoint | `/api/auth/login` | `/api/auth/login` | `/api/auth/login` |
| Token storage keys | `admin_access_token` | `access_token` | `access_token` |
| Host-tenant guard | **Exempted** (portal_role) | **Enforced** | **Skipped** (not a tenant slug) |
| Route protection | `@require_portal_*` | `@require_role` | `@require_role` |
| Cookie domain | N/A (localStorage) | N/A (localStorage) | N/A (localStorage) |
| Token reuse across portals | YES (structurally identical) | Blocked by host guard | N/A |

---

## 8. Recommended Refactor Approach

### Phase A — Quick Wins (1-2 days, no breaking changes)

#### A1. Add `iss` and `aud` claims to JWT
```python
# auth.py generate_access_token():
payload = {
    ...
    'iss': 'auditgraph',
    'aud': 'admin' if user.get('portal_role') else 'client',
}

# auth.py verify_access_token():
# Verify audience matches detected portal
```
**Impact**: Tokens become portal-scoped. An admin token cannot be used on client endpoints and vice versa. Backend can reject mismatched tokens.

#### A2. Validate `portal` against request host in login handler
```python
# handlers.py auth_login():
# Derive portal from request host, not from request body
host = request.host.split(':')[0]
if host.startswith('admin.'):
    portal = 'admin'
else:
    portal = 'client'
# Ignore client-supplied portal parameter
```
**Impact**: Eliminates portal spoofing attack vector.

#### A3. Add host check for admin API routes
```python
# auth.py — new decorator:
def require_admin_origin():
    """Reject admin API calls not from admin.auditgraph.ai."""
    host = request.host.split(':')[0]
    if not host.startswith('admin.') and host not in ('localhost', '127.0.0.1'):
        return jsonify({'error': 'Admin API only accessible from admin portal'}), 403
```
**Impact**: Admin API routes only accessible from admin subdomain.

#### A4. Reduce admin token TTL
```python
ADMIN_TOKEN_EXPIRY = timedelta(minutes=30)
CLIENT_TOKEN_EXPIRY = timedelta(hours=24)
```
**Impact**: Reduces blast radius of stolen admin tokens from 24h to 30min.

### Phase B — Medium-Term Hardening (3-5 days)

#### B1. Separate JWT signing keys per portal
```python
JWT_SECRET_ADMIN = os.getenv('JWT_SECRET_ADMIN')
JWT_SECRET_CLIENT = os.getenv('JWT_SECRET_CLIENT')
```
**Impact**: Compromise of one key doesn't compromise the other portal. Tokens from one portal cannot be forged using the other portal's key.

#### B2. Add token fingerprinting
```python
# Include browser fingerprint hash in JWT
payload['fp'] = hashlib.sha256(request.headers.get('User-Agent', '').encode()).hexdigest()[:16]
# Verify on each request
```
**Impact**: Tokens extracted via network interception cannot be used from a different browser.

#### B3. Portal-scoped refresh tokens
```python
# Store portal context with refresh token
db.save_refresh_token(user['id'], token_hash, expires_at, portal='admin')
# Verify on refresh
if token_record['portal'] != detected_portal:
    return 401
```
**Impact**: Admin refresh tokens only work from admin portal.

#### B4. Fail-closed host-tenant guard
```python
# Replace `except Exception: pass` with fail-closed:
except Exception as e:
    logger.error(f"Host-tenant guard DB error: {e}")
    return jsonify({'error': 'Service temporarily unavailable'}), 503
```

### Phase C — Enterprise-Grade (1-2 weeks)

#### C1. Separate admin API service
- Deploy admin API as a separate container with its own JWT secret
- Admin routes only accessible via internal network or admin subdomain
- Complete blast radius isolation

#### C2. mTLS for admin API
- Require client certificate for admin API access
- Certificate pinned to admin portal's nginx

#### C3. Hardware-backed JWT signing
- Use HSM or Azure Key Vault for JWT signing
- Key never leaves secure boundary

---

## 9. Risk Prioritization

| Priority | Action | Effort | Risk Reduced |
|----------|--------|--------|-------------|
| 1 | A1: Add `aud` claim to JWT | 2hr | C1 (CRITICAL) |
| 2 | A2: Derive portal from host, not body | 1hr | H2 (HIGH) |
| 3 | A4: Reduce admin token TTL to 30min | 30min | M4 (MEDIUM) |
| 4 | A3: Add host check on admin routes | 2hr | H1 (HIGH) |
| 5 | B4: Fail-closed host guard | 1hr | M1 (MEDIUM) |
| 6 | B3: Portal-scoped refresh tokens | 3hr | M2 (MEDIUM) |
| 7 | B1: Separate JWT signing keys | 4hr | H3 (HIGH) |
| 8 | B2: Token fingerprinting | 3hr | M5 (MEDIUM) |

---

# Phase 1B — Full Auth Boundary Refactor (IMPLEMENTED)

**Date**: 2026-02-28
**Status**: IMPLEMENTED — resolves C1, H1, H2, H3, M1, M2, M4

## Changes Implemented

### Backend (`auth.py`)
- **Dual JWT keys**: `ADMIN_JWT_SECRET` + `TENANT_JWT_SECRET` with `JWT_SECRET` fallback (resolves H3)
- **Portal-specific TTLs**: Admin 30min, Tenant 60min (resolves M4)
- **Standard claims**: `iss` (auditgraph-platform / auditgraph-tenant), `aud` (admin.auditgraph.ai / {slug}.auditgraph.ai) (resolves C1)
- **Host-derived portal**: `_derive_portal()` reads Host header; dev mode accepts `X-Portal-Context` (resolves H2)
- **Portal-aware middleware**: Key selected from host → admin tokens verified with `audience='admin.auditgraph.ai'` (resolves H1)
- **API key admin block**: API keys return 403 on admin portal
- **Fail-closed**: Removed `except Exception: pass` catch-all (resolves M1)
- **Host↔Tenant guard replaced**: By cryptographic `aud` verification (stronger)
- **Trial expiry**: Only fires on client portal
- **Dead code removed**: `verify_access_token()`, `get_tenant_id()`, old constants

### Backend (`handlers.py`)
- **`auth_login()`**: Portal derived from `_derive_portal()`, not client body
- **`auth_refresh()`**: Reads `portal` from stored refresh token record (resolves M2)
- **`saml_token_exchange()`**: Hardcodes `portal='client'`, looks up tenant slug
- **`admin_impersonate()`**: New endpoint for admin→tenant impersonation

### Backend (`database.py`)
- **`refresh_tokens.portal`**: New column for portal-scoped refresh tokens

### Frontend (`AuthContext.tsx`)
- **`login()`**: Removed `portal` parameter, sends `X-Portal-Context` header in dev
- **Impersonation**: `impersonate(tenantId)` + `exitImpersonation()` with token backup

### Frontend (`TopBar.tsx`)
- Amber impersonation banner with "Exit Impersonation" button

## New Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_JWT_SECRET` | No* | JWT signing key for admin portal |
| `TENANT_JWT_SECRET` | No* | JWT signing key for tenant portal |

*Falls back to `JWT_SECRET` if not set.

## Security Properties
- Admin token on tenant route → 401 (wrong key/audience)
- Tenant token on admin route → 401 (wrong key/audience)
- Cross-tenant replay → 403 (audience mismatch)
- API key on admin portal → 403
- All JWT errors → 401/403 (fail-closed)

---

# Phase 1C — Auth Hardening Tightening (IMPLEMENTED)

**Date**: 2026-02-28
**Status**: IMPLEMENTED — 14 tests passing

## Changes

### 1. Production JWT_SECRET fallback removed
- `JWT_SECRET` fallback only allowed when `FLASK_ENV=development`
- Production requires explicit `ADMIN_JWT_SECRET` + `TENANT_JWT_SECRET` or startup fails
- Error message differs by environment for clearer debugging

### 2. iss/aud semantics corrected
| Portal | `iss` (origin) | `aud` (audience) |
|--------|---------------|-------------------|
| Admin | `admin.auditgraph.ai` | `auditgraph-platform` |
| Tenant | `{slug}.auditgraph.ai` | `auditgraph-tenant` |

- `iss` = origin domain (who issued the token)
- `aud` = logical audience name (who should consume it)
- Middleware verifies `aud` on decode, then checks `iss` matches host slug for tenant tokens

### 3. Impersonation hardened
- **`impersonated_by`** claim: username of the admin performing impersonation
- **`impersonation_exp`** claim: 15-minute hard cap (Unix timestamp)
- Token `exp` clamped to `impersonation_exp` if shorter than normal TTL
- Middleware rejects tokens where `impersonation_exp` has passed (returns 401)
- **Audit logging**: `impersonation_start` and `impersonation_end` events in `admin_audit_log`
- **`POST /api/admin/impersonate/end`**: New endpoint to log impersonation end
- Frontend `exitImpersonation()` calls end endpoint before restoring admin tokens
- Response includes `expires_in_minutes: 15` for client display

### 4. Refresh token hardening
- Tokens already SHA-256 hashed in DB (Phase 1B)
- Rotate on every refresh: old token revoked, new token issued (Phase 1B)
- **Token reuse detection** (Phase 1C): If a revoked token is presented, ALL tokens for that user are revoked and a warning is logged — prevents stolen token replay

### 5. Host↔tenant_id validation
- After `iss` check, middleware resolves host slug to `tenants.id` via DB lookup
- If `token.tenant_id` does not match the slug's tenant ID → 403 "Token tenant mismatch"
- Superadmins exempt (they operate cross-tenant by design)
- Graceful degradation: DB lookup failure does not block request

### 6. Tests (14 passing)
| Test | Asserts |
|------|---------|
| `test_admin_token_fails_tenant_decode` | Admin token + TENANT_KEY → InvalidTokenError |
| `test_admin_token_wrong_audience_for_tenant` | Admin token + ADMIN_KEY + tenant aud → InvalidAudienceError |
| `test_tenant_token_fails_admin_decode` | Tenant token + ADMIN_KEY → InvalidTokenError |
| `test_tenant_token_wrong_audience_for_admin` | Tenant token + TENANT_KEY + admin aud → InvalidAudienceError |
| `test_admin_token_decodes_with_correct_key` | iss=admin.auditgraph.ai, aud=auditgraph-platform |
| `test_tenant_token_decodes_with_correct_key` | iss=acme.auditgraph.ai, aud=auditgraph-tenant |
| `test_impersonation_has_15min_cap` | impersonation_exp within 15min, exp clamped |
| `test_impersonation_exp_is_respected` | Past impersonation_exp is detectable |
| `test_refresh_token_hash` | SHA-256 hex digest matches |
| `test_admin_token_ttl` | 30-minute TTL |
| `test_tenant_token_ttl` | 60-minute TTL |
| `test_tenant_token_without_slug_uses_app_iss` | iss=app.auditgraph.ai when no slug |
| `test_cross_tenant_token_different_iss` | Different slugs → different iss claims |
| `test_keys_are_distinct` | ADMIN_KEY ≠ TENANT_KEY |

## Environment Variables
| Variable | Dev | Production |
|----------|-----|------------|
| `ADMIN_JWT_SECRET` | Optional (falls back to `JWT_SECRET`) | **Required** |
| `TENANT_JWT_SECRET` | Optional (falls back to `JWT_SECRET`) | **Required** |
| `JWT_SECRET` | Used as fallback when above are missing | **Not accepted** — startup fails |
| `FLASK_ENV` | `development` enables fallback | Any other value or unset = production mode |
