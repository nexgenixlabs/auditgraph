# Section 3 -- Security Architecture

## Overview

AuditGraph's security architecture is designed for multi-tenant SaaS operation where customer data isolation is the highest priority. The platform implements defense-in-depth across authentication, authorization, data isolation, encryption, and operational security.

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                               │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 1: Network Security                                 │   │
│  │ HTTPS/TLS, HSTS, Security Headers, CORS                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 2: Authentication                                   │   │
│  │ JWT (portal-specific keys), OIDC, SAML, API Keys         │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 3: Authorization                                    │   │
│  │ RBAC (8 roles), Portal roles, Feature flags               │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 4: Tenant Isolation                                 │   │
│  │ Row Level Security, Dual DB users, Context verification   │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 5: Data Protection                                  │   │
│  │ Field encryption (Fernet/MultiFernet), Log redaction      │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 6: API Protection                                   │   │
│  │ Rate limiting, Input validation, Size limits, Idempotency │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Layer 7: Operational Safety                               │   │
│  │ Circuit breakers, Retry logic, Security event logging     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Zero Trust Security Model

AuditGraph follows a Zero Trust security model.

Every request is:

- **Authenticated** — via JWT, OIDC, or API key
- **Authorized** — via RBAC and role-based enforcement
- **Explicitly scoped** — to both `organization_id` (tenant) and `cloud_connection_id` (connector)

No implicit trust is granted based on network location or prior access. All data access is continuously validated and constrained at multiple layers, including database-enforced Row Level Security (RLS).

---

## Threat Model Summary

AuditGraph's security architecture is designed to mitigate the following threat scenarios. Each threat has at least two independent mitigations (defense-in-depth).

| Threat | Description | Mitigations |
|--------|------------|-------------|
| **Cross-tenant data access** | Attacker with valid credentials for Tenant A attempts to read Tenant B's data | JWT `organization_id` claim validation, `SET LOCAL` tenant context, RLS policies on 44 tables, `NOBYPASSRLS` database role |
| **Cross-connector data leakage** | User within the same organization accesses data from a connector they should not see | `cloud_connection_id` scoping in `_latest_run_ids()`, frontend `withConnection()` enforcement, NOT NULL foreign key constraints |
| **Credential exposure** | Attacker gains access to the database and attempts to read stored cloud secrets | Fernet encryption (AES-128-CBC + HMAC-SHA256), `enc:` prefix identification, credentials never returned in API responses, log redaction |
| **Token compromise** | Stolen JWT used to authenticate as another user or access another portal | Short-lived access tokens (30/60 min), separate signing keys per portal, refresh token single-use rotation, reuse detection revokes all user tokens |
| **API abuse** | Automated attacks targeting authentication or mutation endpoints | Sliding-window rate limiting, JSON schema validation, input sanitization, request size limits, idempotency keys |
| **External dependency failure** | Cloud provider API outage causes cascading failures in AuditGraph | Circuit breakers (3 independent: Graph API, AWS API, LLM API), exponential backoff retry, heartbeat-based zombie job detection |

**Out-of-scope threats:**

AuditGraph does not protect against threats within the customer's cloud environment itself (e.g., compromised Azure AD admin, lateral movement within AWS). AuditGraph's role is to detect and report these conditions, not to prevent them. See [Best Practices](best-practices.md) for remediation guidance.

---

## Authentication Model

### JWT Tokens

AuditGraph uses JSON Web Tokens for stateless authentication. Two separate signing keys protect the admin and client portals:

| Portal | Secret | Access TTL | Refresh TTL | Audience |
|--------|--------|-----------|-------------|----------|
| Admin Portal | `ADMIN_JWT_SECRET` | 30 minutes | 7 days | `auditgraph-platform` |
| Client Portal | `CLIENT_JWT_SECRET` | 60 minutes | 7 days | `auditgraph-tenant` |

**Token Claims:**

```json
{
  "sub": "42",
  "username": "admin@company.com",
  "role": "admin",
  "display_name": "Jane Admin",
  "org_id": 7,
  "org_name": "Acme Corp",
  "is_superadmin": false,
  "portal_role": null,
  "portal": "client",
  "iss": "acme.auditgraph.ai",
  "aud": "auditgraph-tenant",
  "iat": 1710600000,
  "exp": 1710603600,
  "type": "access",
  "ver": 2
}
```

**Login Flow:**

```
1. Client sends POST /api/auth/login
   { "username": "admin@company.com", "password": "..." }

2. Server validates credentials (bcrypt)
3. Server checks account lockout status
4. Server verifies portal access (admin vs client)
5. Server derives organization from Host header domain
6. Server generates access token + refresh token
7. Refresh token hash (SHA-256) stored in database
8. Server returns:
   { "token": "eyJ...", "refresh_token": "...", "user": {...} }
```

**Refresh Token Security:**

- Raw token returned to client once (never stored server-side)
- SHA-256 hash stored in database
- Reuse detection: if a revoked token is presented, all user tokens are revoked
- 7-day expiry, consumed after single use

### OIDC Login

AuditGraph supports OpenID Connect for enterprise SSO integration.

```
┌──────────┐        ┌──────────────┐        ┌────────────┐
│  Browser  │        │  AuditGraph  │        │    IdP     │
│           │        │   Backend    │        │ (Azure AD, │
│           │        │              │        │  Okta,     │
│           │        │              │        │  Google)   │
└─────┬─────┘        └──────┬───────┘        └──────┬─────┘
      │                     │                       │
      │  1. Click SSO       │                       │
      ├────────────────────►│                       │
      │                     │                       │
      │  2. Redirect to     │                       │
      │     IdP authz URL   │                       │
      │◄────────────────────┤                       │
      │                     │                       │
      │  3. Authenticate    │                       │
      │     at IdP          │                       │
      ├─────────────────────┼──────────────────────►│
      │                     │                       │
      │  4. IdP returns     │                       │
      │     auth code       │                       │
      │◄────────────────────┼───────────────────────┤
      │                     │                       │
      │  5. Send code to    │                       │
      │     AuditGraph      │                       │
      ├────────────────────►│                       │
      │                     │  6. Exchange code      │
      │                     │     for tokens         │
      │                     ├──────────────────────►│
      │                     │                       │
      │                     │  7. Receive ID token   │
      │                     │◄──────────────────────┤
      │                     │                       │
      │                     │  8. Verify ID token    │
      │                     │     via JWKS           │
      │                     ├──────────────────────►│
      │                     │                       │
      │  9. Return JWT      │                       │
      │◄────────────────────┤                       │
      │                     │                       │
```

### JWKS Verification

ID tokens from the IdP are verified using the provider's JSON Web Key Set (JWKS):

1. AuditGraph fetches the IdP's OIDC discovery document
2. Extracts the `jwks_uri` endpoint
3. Creates a `PyJWKClient` for that URI with a **600-second TTL cache**
4. Retrieves the signing key matching the token's `kid` header
5. Verifies the RS256 signature, audience, issuer, and expiration
6. Validates the nonce if one was sent during authorization

**Cache behavior:**
- JWKS clients are cached per `jwks_uri` with a 10-minute TTL
- Within each client, individual keys are cached for 300 seconds
- Cache refresh events are logged at INFO level
- Thread-safe via `threading.Lock()`

**Security posture:**
- Signature verification failure is a hard rejection (no fallback to unverified decode)
- Unverified decode only occurs if the IdP discovery document has no `jwks_uri` (rare edge case)

### SAML SSO

AuditGraph supports SAML 2.0 for enterprise identity providers:

- **Library**: `python3-saml` (OneLogin)
- **Signed assertions required**: `wantAssertionsSigned: True`
- **JIT provisioning**: Users are automatically created on first SAML login
- **Group-to-role mapping**: IdP groups map to AuditGraph roles
- **One-time codes**: SAML ACS endpoint generates a 60-second one-time code exchanged for a JWT

---

## RBAC Role Model

### Client Portal Roles

AuditGraph implements a hierarchical role model. Higher roles inherit all permissions of lower roles.

```
owner
  └── admin
       └── security_admin
            └── security_analyst
                 └── compliance
                      └── reader
```

| Role | Capabilities |
|------|-------------|
| **owner** | Full platform access, billing, organization deletion |
| **admin** | User management, connector management, settings, all read/write operations |
| **security_admin** | Security operations, SOAR, remediation execution, all read operations |
| **security_analyst** | Investigation, anomaly analysis, remediation review, all read operations |
| **compliance** | Compliance frameworks, access reviews, reports, all read operations |
| **reader** | Read-only access to all dashboards, identities, and reports |

### Admin Portal Roles

The admin portal uses a separate role set for platform operators:

| Portal Role | Capabilities |
|-------------|-------------|
| **superadmin** | Full platform access, tenant CRUD, billing, impersonation |
| **poweradmin** | Tenant management, provisioning, user management |
| **billing** | Billing operations, invoice management, plan changes |
| **reader** | Read-only access to all admin dashboards and analytics |

### Role Enforcement

Roles are checked via decorators on route handlers:

```python
@require_role('admin')                         # admin and above only
@require_role('admin', 'security_admin')       # multiple roles allowed
@require_superadmin()                           # superadmin flag required
@require_portal_role('superadmin', 'poweradmin') # specific portal roles
```

---

## Tenant Isolation -- Row Level Security

### Architecture

AuditGraph enforces tenant isolation at the database layer using PostgreSQL Row Level Security. This provides a defense-in-depth guarantee: even if application code has a bug, one tenant cannot access another tenant's data.

```
┌──────────────────────────────────────────────────────────────┐
│  REQUEST FLOW                                                │
│                                                              │
│  1. HTTP Request arrives                                     │
│  2. Auth middleware extracts org_id from JWT                 │
│  3. Database(organization_id=N) called                       │
│     → Connects as auditgraph_app (NOBYPASSRLS)              │
│     → SET LOCAL app.current_organization_id = N              │
│  4. All queries filtered by RLS policy:                      │
│     organization_id = current_setting('app.current_org...')  │
│  5. Connection returned to pool with RESET                   │
└──────────────────────────────────────────────────────────────┘
```

### Dual Database Users

| User | RLS Mode | Purpose |
|------|----------|---------|
| `auditgraph_app` | `NOBYPASSRLS` | Tenant-scoped operations. Every query is filtered. |
| `auditgraph_admin` | `BYPASSRLS` | DDL, migrations, system maintenance, cross-tenant analytics |

### RLS Policy

Every tenant-scoped table has strict policies:

```sql
-- SELECT: only rows for current tenant
CREATE POLICY tenant_strict_sel ON identities
  FOR SELECT USING (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );

-- INSERT: only rows matching current tenant
CREATE POLICY tenant_strict_ins ON identities
  FOR INSERT WITH CHECK (
    organization_id = current_setting('app.current_organization_id', true)::integer
  );
```

### Safety Layers

The RLS implementation has five safety layers:

1. **SET LOCAL** (transaction-scoped): Context auto-resets on COMMIT/ROLLBACK
2. **Explicit RESET on checkout**: Clean slate from previous connection user
3. **Explicit RESET on return**: Belt-and-suspenders before returning to pool
4. **Flask teardown hook**: Catches missed connection closes
5. **Context verification**: Reads back the set value before executing queries

### Admin Guard

In production, the system blocks accidental `Database()` calls (without tenant context) inside request handlers:

```python
# This raises RuntimeError in production:
db = Database()  # No organization_id inside a request

# Must use either:
db = Database(organization_id=g.current_user['org_id'])  # Tenant-scoped
db = Database(_admin_reason='system maintenance')         # Explicit admin bypass
```

---

## API Security Protections

### Rate Limiting

In-memory sliding-window rate limiter protects sensitive endpoints:

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /api/auth/login` | 5 requests | 60 seconds | IP address |
| `POST /api/auth/signup` | 3 requests | 60 seconds | IP address |
| `POST /api/auth/refresh` | 10 requests | 60 seconds | IP address |
| `POST /api/auth/forgot-password` | 3 requests | 300 seconds | IP address |
| `POST /api/auth/reset-password` | 5 requests | 300 seconds | IP address |
| Connector mutations | 20 requests | 60 seconds | IP + path |
| Copilot endpoints | 20 requests | 60 seconds | IP + path |

Rate-limited responses return `429 Too Many Requests` with a `Retry-After` header.

### Input Validation

JSON request bodies are validated against schemas using the `jsonschema` library:

| Schema | Validated Fields | Applied To |
|--------|-----------------|-----------|
| `LOGIN_SCHEMA` | username (required), password (required) | `POST /api/auth/login` |
| `CREATE_CONNECTION_SCHEMA` | label, cloud, credentials | `POST /api/client/connections` |
| `TRIGGER_RUN_SCHEMA` | connection_id, scan_mode | `POST /api/runs/trigger` |
| `COPILOT_CHAT_SCHEMA` | message (max 10,000 chars) | `POST /api/copilot/chat` |
| `CREATE_USER_SCHEMA` | username, password, role | `POST /api/users` |
| `CHANGE_PASSWORD_SCHEMA` | current_password, new_password | `PUT /api/auth/password` |
| `SAVE_SETTINGS_SCHEMA` | key-value pairs | `POST /api/settings` |

Validation errors return `400` with a structured error response:

```json
{
  "error": "Validation error at password: 'password' is a required property",
  "error_code": "VALIDATION_ERROR",
  "field": "password",
  "request_id": "req_abc123"
}
```

### Input Sanitization

A middleware layer scans all JSON request bodies for injection patterns:

- **XSS patterns**: `<script>`, event handlers (`onclick=`), `javascript:` URIs
- **SQL injection**: `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `WAITFOR DELAY`
- **Command injection**: Shell metacharacters in unexpected fields

Scanning is recursive (max depth 20) and skips legitimate paths like `/api/identities/query`.

### Request Size Limits

- **MAX_CONTENT_LENGTH**: 5 MB per request (Flask config)
- **Input sanitizer soft limit**: 10 MB (middleware check)
- Exceeding limits returns `413 Payload Too Large`

### Security Headers

All API responses include:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Enforce HTTPS |
| `Referrer-Policy` | `strict-origin` | Prevent path/query leakage |
| `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'` | XSS and framing protection |
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Prevent caching of sensitive data |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Disable unused browser features |

---

## Encryption Model

### Field-Level Encryption

Sensitive data at rest is encrypted using Fernet symmetric encryption from the `cryptography` library.

**Encrypted fields:**
- Cloud connector credentials (client secrets)
- OIDC client secrets
- Refresh token metadata
- API key secrets

**Encryption format:**

```
Plaintext:  my-secret-value
Encrypted:  enc:gAAAAABk...base64...
                │
                └── "enc:" prefix identifies encrypted values
```

**Gradual migration**: The `decrypt_field()` function handles both encrypted (`enc:` prefixed) and plaintext values transparently. This allows encryption to be adopted incrementally without requiring a bulk migration of existing data.

### Key Rotation Support

AuditGraph supports encryption key rotation using MultiFernet:

```
Environment variable:
  ENCRYPTION_KEYS=NEW_KEY,OLD_KEY_1,OLD_KEY_2

Behavior:
  - Encryption always uses the FIRST (newest) key
  - Decryption tries all keys in order
  - rotate_encrypted_field() re-encrypts with the newest key
```

**Key configuration priority:**

| Priority | Source | Result |
|----------|--------|--------|
| 1 | `ENCRYPTION_KEYS` env var (comma-separated) | MultiFernet with multiple keys |
| 2 | `ENCRYPTION_KEY` env var (single key) | Single Fernet key |
| 3 | `ENCRYPTION_KEY_FILE` path | Read key from file |
| 4 | Development fallback | Ephemeral key (not persistent across restarts) |

### Key Rotation Procedure

```
Step 1: Generate a new Fernet key
  $ python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Step 2: Prepend the new key to ENCRYPTION_KEYS
  ENCRYPTION_KEYS=NEW_KEY,CURRENT_KEY,OLD_KEY

Step 3: Deploy the updated environment variable

Step 4: Rotate existing encrypted values (optional)
  All existing values remain readable via MultiFernet.
  To re-encrypt with the new key, call rotate_encrypted_field()
  on each encrypted value.

Step 5: After confirming all values are rotated, remove old keys
  ENCRYPTION_KEYS=NEW_KEY
```

---

## Secrets Management

### Password Policy

User passwords must meet:

| Requirement | Minimum |
|-------------|---------|
| Length | 12 characters |
| Uppercase | At least 1 |
| Lowercase | At least 1 |
| Digit | At least 1 |
| Special character | At least 1 (`!@#$%^&*()_+-=[]{}` etc.) |
| Not in blocklist | 170 common passwords rejected |

### API Key Security

API keys use the `ag_` prefix format with SHA-256 hashing:

```
Generation:
  1. Generate 32 hex characters: ag_1a2b3c4d...
  2. Hash with SHA-256 for storage
  3. Return raw key to user once (never stored in plaintext)

Authentication:
  1. Client sends X-API-Key header or Bearer ag_... token
  2. Server hashes the provided key
  3. Lookup hash in api_keys table
  4. Check: enabled, not expired, correct organization
  5. Increment usage counter
```

### Log Redaction

Secrets are automatically redacted from log output:

| Pattern | Replacement |
|---------|-------------|
| `password=...` | `password=[REDACTED]` |
| `Bearer eyJ...` | `Bearer [REDACTED]` |
| `ag_1234...` | `[REDACTED_API_KEY]` |
| `client_secret=...` | `client_secret=[REDACTED]` |
| `AccountKey=...` | `AccountKey=[REDACTED]` |

---

## Security Event Logging

AuditGraph produces structured security events for SIEM integration:

| Event Type | Severity | Trigger |
|-----------|----------|---------|
| `LOGIN_SUCCESS` | info | Successful authentication |
| `LOGIN_FAILED` | medium | Failed authentication attempt |
| `ROLE_CHANGED` | medium | User role modification |
| `CONNECTOR_CREATED` | info | New cloud connector added |
| `CONNECTOR_DELETED` | medium | Cloud connector removed |
| `CREDENTIAL_ROTATED` | info | Connector credentials rotated |
| `TENANT_CONTEXT_VIOLATION` | critical | RLS context mismatch detected |
| `RLS_DRIFT_DETECTED` | critical | RLS policy removed from a table |
| `ADMIN_GUARD_BLOCKED` | high | Unauthorized Database() call in request context |
| `POOL_EXHAUSTION` | high | Connection pool capacity reached |
| `SLOW_QUERY` | medium | Query exceeded threshold |
| `AUTH_FAILURE` | high | Token or session validation failure |

**Event structure:**

```json
{
  "event_type": "LOGIN_FAILED",
  "severity": "medium",
  "tenant_id": null,
  "correlation_id": "req_abc123",
  "timestamp": "2026-03-16T14:30:00.000Z",
  "details": {
    "username": "baduser",
    "ip_address": "10.0.0.1",
    "reason": "invalid credentials"
  }
}
```

---

## References

- [Security Features](security-features.md) -- Detailed documentation of all security protections
- [Operations](operations.md) -- Key rotation procedures and monitoring
- [Security Posture](security-posture.md) -- Security maturity assessment
- [API Reference](api-reference.md) -- Authentication endpoints and examples
