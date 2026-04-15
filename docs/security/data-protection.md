# Data Protection and Tenant Isolation

## Overview

This document describes how AuditGraph protects customer data across all layers of the platform. It is intended for security teams evaluating AuditGraph during vendor security reviews, procurement assessments, and compliance audits.

AuditGraph implements a defense-in-depth data protection model. No single layer is relied upon for security — multiple independent controls ensure that a failure at one layer does not expose customer data.

---

## Tenant Isolation

AuditGraph uses a multi-layer tenant isolation model. Every customer organization is a fully isolated tenant, and cross-tenant data access is architecturally prevented at the database layer.

### Isolation Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Request Authentication                             │
│  JWT token contains organization_id claim                    │
│  ↓                                                           │
│  Layer 2: Auth Middleware                                     │
│  Extracts and validates organization_id from token           │
│  ↓                                                           │
│  Layer 3: Tenant Context                                     │
│  SET LOCAL app.current_tenant_id = organization_id           │
│  ↓                                                           │
│  Layer 4: Row Level Security (PostgreSQL)                    │
│  All queries filtered by organization_id automatically       │
│  ↓                                                           │
│  Layer 5: Tenant-Scoped Data Access                          │
│  Only data belonging to the authenticated tenant is returned │
└─────────────────────────────────────────────────────────────┘
```

### Organization-Level Scoping

Every customer is represented by an `organization` record. All customer-owned data is associated with an `organization_id` foreign key. This is the root isolation primitive — no data record can exist without a tenant association.

| Property | Implementation |
|----------|---------------|
| **Tenant identifier** | Integer `organization_id` on all customer tables |
| **Enforcement** | NOT NULL constraint — no record can exist without a tenant |
| **Auto-fill** | Database trigger (`trg_auto_tenant_id`) fills `organization_id` from session context if not explicitly provided |
| **Validation** | Trigger raises an exception if both the provided value and session context are NULL |

### Connector-Level Isolation

Within each organization, cloud connectors provide a second level of scoping. Each connector represents a single cloud boundary (Azure tenant, AWS account, GCP project). Discovery data is always tied to both an organization and a connector.

```
Organization (Acme Corp)
├── Connector 1: Production Azure    → Discovery runs → Identities
├── Connector 2: Development Azure   → Discovery runs → Identities
└── Connector 3: Production AWS      → Discovery runs → Identities
```

Data from one connector never appears in queries for another connector unless explicitly requested by the authenticated user within the same organization.

### Connector Isolation Guarantee

AuditGraph enforces strict connector-level data isolation as a security invariant, not a convenience feature. Every discovery record is scoped by both `organization_id` (tenant boundary) and `cloud_connection_id` (connector boundary). These two foreign keys are required (NOT NULL) on all discovery-related tables.

| Guarantee | Enforcement |
|-----------|------------|
| **No cross-connector queries** | `_latest_run_ids()` filters by both `organization_id` and `cloud_connection_id` before any data is returned |
| **No cross-connector joins** | Discovery runs, identities, role assignments, and resources are always scoped to a single connector |
| **No data aggregation across connectors** | Frontend passes `connection_id` via `withConnection()` on every API call; backend rejects requests without a valid connector scope |
| **Deletion isolation** | Deleting a connector removes only its discovery data. Other connectors within the same organization are unaffected. |

This means a production Azure tenant's identities and entitlements are never visible in queries for a development Azure tenant, even when both belong to the same organization. The isolation boundary is enforced at the database query layer, not the application presentation layer.

### PostgreSQL Row Level Security (RLS)

RLS is the foundational isolation control. Even if application-level authorization is bypassed through a software bug, the database itself prevents cross-tenant access.

**Coverage:** 44 tables with strict RLS policies.

**Policy definition:**

```sql
-- Every SELECT is filtered to the current tenant
CREATE POLICY tenant_strict_sel ON table_name
  FOR SELECT TO auditgraph_app
  USING (organization_id = current_setting('app.current_tenant_id', true)::integer);

-- Every INSERT must match the current tenant
CREATE POLICY tenant_strict_ins ON table_name
  FOR INSERT TO auditgraph_app
  WITH CHECK (organization_id = current_setting('app.current_tenant_id', true)::integer);

-- UPDATE and DELETE follow the same pattern
```

**Key design decisions:**

- Policies are **strict** — there is no fallback for NULL context. If the tenant context is not set, no rows are returned.
- Policies use `current_setting('app.current_tenant_id', true)` which returns NULL (not an error) if unset, causing the comparison to fail safely.
- All 44 customer data tables have SELECT, INSERT, UPDATE, and DELETE policies.

### Dual Database Users

AuditGraph uses two PostgreSQL users with different RLS behavior:

| User | RLS Mode | Purpose | Used By |
|------|----------|---------|---------|
| `auditgraph_app` | `NOBYPASSRLS` | All request-scoped queries are filtered by RLS | API request handlers |
| `auditgraph_admin` | `BYPASSRLS` | Cross-tenant operations (system jobs, DDL, analytics) | Scheduler, migrations, superadmin |

The application user (`auditgraph_app`) **cannot** bypass RLS under any circumstances. Even if an attacker gains access to this database user, they cannot read data across tenants without a valid tenant context.

### Tenant Context Enforcement

Five safety mechanisms ensure the tenant context is always correctly set and never leaks between requests:

| Safety Layer | Mechanism |
|-------------|-----------|
| **SET LOCAL** | Tenant context is transaction-scoped. It cannot persist beyond the current transaction. |
| **Checkout RESET** | The connection pool resets all session state when checking out a connection. |
| **Return RESET** | Session state is cleared again when returning a connection to the pool. |
| **Teardown hook** | Flask's `teardown_appcontext` ensures cleanup runs even if the request handler raises an exception. |
| **Admin guard** | A runtime check blocks `Database()` calls without a tenant context inside request handlers, preventing accidental unscoped queries. |

**Security event:** If a request attempts to query data without a valid tenant context, a `TENANT_CONTEXT_VIOLATION` security event is logged.

---

## Encryption

### Data in Transit

All communication between clients and the AuditGraph API is encrypted using TLS.

| Control | Implementation |
|---------|---------------|
| **Protocol** | TLS 1.3 (minimum) |
| **HSTS** | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` |
| **Certificate** | Azure-managed TLS certificates for all `*.auditgraph.ai` domains |
| **Enforcement** | HTTP requests are automatically redirected to HTTPS |

HSTS enforcement ensures that browsers never attempt an unencrypted connection after the first visit. The `preload` directive submits AuditGraph domains to browser preload lists for protection on first visit.

### Data at Rest

Sensitive fields are encrypted at the application layer before storage using Fernet symmetric encryption.

| Property | Value |
|----------|-------|
| **Algorithm** | AES-128-CBC (encryption) + HMAC-SHA256 (integrity) |
| **Library** | Python `cryptography.fernet.Fernet` |
| **Key size** | 256-bit key (128-bit AES key + 128-bit HMAC key, base64-encoded) |
| **IV** | Random 128-bit IV per encryption operation |
| **Timestamp** | Fernet tokens include a creation timestamp for optional TTL enforcement |

**What is encrypted:**

| Data | Table | Column |
|------|-------|--------|
| Azure client secrets | `cloud_connections` | `client_secret` |
| AWS secret access keys | `cloud_connections` | `aws_secret_access_key` |
| GCP service account keys | `cloud_connections` | `gcp_service_account_key` |
| Connector credentials after rotation | `cloud_connections` | Updated in place |

### Credential Storage

All cloud connector credentials follow a strict storage protocol:

```
1. Credential received via API request (HTTPS)
       ↓
2. Encrypted immediately using Fernet
       ↓
3. Stored in database with "enc:" prefix
       ↓
4. Plaintext discarded from memory
       ↓
5. API responses never return credential values
       ↓
6. Decrypted only at discovery time, used, then discarded
```

**Identification:** Encrypted values carry an `enc:` prefix. This prefix allows the decryption function to distinguish between encrypted and legacy plaintext values during migration.

**Masking:** API responses that return connector metadata (e.g., `GET /api/client/connections`) never include credential values. Connection status and configuration are returned, but secrets are omitted entirely.

---

## Encryption Key Management

### MultiFernet Key Rotation

AuditGraph supports zero-downtime encryption key rotation using Python's `MultiFernet` class.

**How it works:**

```
ENCRYPTION_KEYS = NEW_KEY,OLD_KEY

MultiFernet([Fernet(NEW_KEY), Fernet(OLD_KEY)])

Encrypt: Always uses NEW_KEY (first in list)
Decrypt: Tries NEW_KEY first, falls back to OLD_KEY
```

This allows new data to be encrypted with the current key while old data encrypted with a previous key remains readable.

### Key Configuration

| Variable | Purpose |
|----------|---------|
| `ENCRYPTION_KEY` | Single encryption key (simple mode) |
| `ENCRYPTION_KEYS` | Comma-separated list of keys (rotation mode, newest first) |

When `ENCRYPTION_KEYS` is set, it takes precedence over `ENCRYPTION_KEY`.

### Rotation Procedure

```
Step 1: Generate a new Fernet key
  python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Step 2: Set ENCRYPTION_KEYS with new key first, old key second
  ENCRYPTION_KEYS=NEW_KEY,OLD_KEY

Step 3: Deploy updated environment
  New encryptions use NEW_KEY
  Old encrypted values decrypt via OLD_KEY (MultiFernet fallback)

Step 4: (Optional) Re-encrypt existing values
  Call rotate_encrypted_field() on stored encrypted values

Step 5: After re-encryption is complete, remove old key
  ENCRYPTION_KEYS=NEW_KEY
```

### Backward Compatibility

During rotation, the system operates in a dual-key mode where both keys are active. This ensures:

- No downtime during rotation
- Existing encrypted values remain decryptable
- New encrypted values use the strongest (newest) key
- Old keys can be safely removed after all values are re-encrypted

### Key Isolation

Encryption keys are managed with strict separation from encrypted data:

| Principle | Implementation |
|-----------|---------------|
| **Keys separate from data** | Encryption keys are never stored in the same database as encrypted values |
| **No source code embedding** | Keys are injected via environment variables at deploy time, not committed to version control |
| **Environment-level management** | Production keys are managed through Azure Container Apps secrets and Azure Key Vault |
| **No runtime persistence** | Keys are loaded into memory at application startup and are not written to disk by the application |
| **Rotation without data access** | Key rotation requires only environment variable updates — no direct database access needed |

This separation ensures that database access alone is insufficient to decrypt stored credentials. An attacker would need access to both the database and the deployment environment's secret store.

---

## Authentication and Access Control

### JWT Authentication

AuditGraph uses JSON Web Tokens for stateless authentication with portal-specific signing keys.

| Property | Admin Portal | Client Portal |
|----------|-------------|---------------|
| **Signing key** | `ADMIN_JWT_SECRET` | `CLIENT_JWT_SECRET` |
| **Access token TTL** | 30 minutes | 60 minutes |
| **Refresh token TTL** | 7 days | 7 days |
| **Algorithm** | HS256 | HS256 |
| **Token storage** | Refresh tokens are SHA-256 hashed before database storage | Same |

Separate signing keys ensure that a token issued for the client portal cannot be used to access admin portal endpoints, and vice versa.

### OIDC Login

AuditGraph supports OpenID Connect single sign-on with JWKS-based signature verification.

| Property | Implementation |
|----------|---------------|
| **Algorithm** | RS256 (RSA with SHA-256) |
| **Key source** | IdP JWKS endpoint (auto-discovered) |
| **Cache** | JWKS keys cached for 600 seconds (10 minutes) |
| **Providers** | Azure AD, Okta, Google Workspace |
| **JIT provisioning** | Users are automatically created on first SSO login |
| **Group mapping** | IdP groups map to AuditGraph roles |

### RBAC Role Enforcement

All API endpoints enforce role-based access control through decorator-based authorization.

**Client Portal Roles (8 roles):**

| Role | Access Level |
|------|-------------|
| `owner` | Full organization control including billing and user management |
| `admin` | Full access except billing |
| `security_admin` | Identity management, risk analysis, remediation |
| `compliance` | Compliance dashboards, reports, audit evidence |
| `auditor` | Read access plus remediation actions |
| `analyst` | Read access plus advanced queries |
| `viewer` | Read-only access to all dashboards |
| `reader` | Read-only access to assigned data |

**Admin Portal Roles (4 roles):**

| Role | Access Level |
|------|-------------|
| `superadmin` | Full platform control across all tenants |
| `poweradmin` | Tenant management, user provisioning |
| `billing` | Billing and subscription management |
| `reader` | Read-only platform monitoring |

### Portal Separation

The admin portal (`admin.auditgraph.ai`) and client portal (`app.auditgraph.ai`) are architecturally separated:

- Different JWT signing keys prevent cross-portal token reuse
- Different role hierarchies (4 portal roles vs. 8 client roles)
- Admin portal routes enforce `require_portal_role()` decorators
- Client portal routes enforce `require_role()` decorators
- Subdomain-based routing directs requests to the correct portal

---

## API Security Protections

### Rate Limiting

In-memory sliding window rate limiting protects authentication endpoints from brute-force attacks.

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /api/auth/login` | 5 requests | Per minute |
| `POST /api/auth/refresh` | 10 requests | Per minute |
| `POST /api/auth/signup` | 5 requests | Per minute |
| `POST /api/auth/forgot-password` | 3 requests | Per minute |
| API key authentication | 20 requests | Per minute |

When a rate limit is exceeded, the API returns HTTP 429 with a `Retry-After` header. A `RATE_LIMIT_EXCEEDED` security event is logged.

### JSON Schema Validation

Request bodies are validated against JSON schemas on mutation endpoints.

| Endpoint | Validated Fields |
|----------|-----------------|
| `POST /api/auth/login` | `username` (string, required), `password` (string, required) |
| `POST /api/client/connections` | `cloud` (enum), `label` (string), cloud-specific credential fields |
| `POST /api/runs/trigger` | `connection_id` (integer), `scan_mode` (enum) |
| `POST /api/identities/query` | `groups` (array), `conditions` (array), operators (allowlist) |
| `POST /api/users` | `username` (string), `role` (enum), `password` (string, policy-checked) |

Invalid requests receive HTTP 400 with a structured error describing the validation failure. An `INPUT_VALIDATION_FAILED` security event is logged.

### Request Size Limits

All requests are limited to 5 MB maximum content length. Requests exceeding this limit receive HTTP 413 without processing the body.

### Idempotency Protection

Mutation endpoints support the `Idempotency-Key` header to prevent duplicate operations from network retries.

| Property | Implementation |
|----------|---------------|
| **Header** | `Idempotency-Key: <client-generated-uuid>` |
| **Storage** | In-memory cache with 24-hour TTL |
| **Behavior** | Duplicate requests return the cached response without re-executing the operation |
| **Endpoints** | Connector creation, discovery trigger, and other state-changing operations |

### Input Sanitization

All string inputs are scanned for common injection patterns before processing.

| Attack Vector | Detection |
|---------------|-----------|
| Cross-site scripting (XSS) | `<script>`, `javascript:`, `onerror=`, event handler patterns |
| SQL injection | `'; DROP`, `UNION SELECT`, `OR 1=1`, comment sequences |
| Command injection | Backticks, `$()`, pipe chains, semicolons in shell-sensitive fields |

Requests containing suspicious patterns receive HTTP 400. A `SUSPICIOUS_INPUT` security event is logged with the detected pattern type.

### Security Headers

All API responses include hardened security headers.

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Force HTTPS |
| `Content-Security-Policy` | `default-src 'self'` | Prevent content injection |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disable unnecessary browser APIs |

---

## Audit Logging

### Security Events

AuditGraph records structured security events for all security-relevant operations.

**Storage:** `security_events` table with `organization_id` (RLS-enforced).

**Event types:**

| Event Type | Severity | Trigger |
|-----------|----------|---------|
| `LOGIN_SUCCESS` | Info | Successful authentication |
| `LOGIN_FAILED` | Medium | Failed authentication attempt |
| `ACCOUNT_LOCKOUT` | High | Repeated failed login attempts |
| `RLS_VIOLATION` | Critical | Attempted access without tenant context |
| `TENANT_CONTEXT_VIOLATION` | Critical | Database query without valid tenant scope |
| `RATE_LIMIT_EXCEEDED` | Medium | Request rate limit triggered |
| `INPUT_VALIDATION_FAILED` | Low | Malformed request body |
| `SUSPICIOUS_INPUT` | High | Injection pattern detected in input |
| `SLOW_QUERY` | Low | Database query exceeded threshold |
| `CIRCUIT_BREAKER_OPENED` | High | External API failure threshold reached |
| `CIRCUIT_BREAKER_CLOSED` | Info | External API recovered |
| `ENCRYPTION_ERROR` | Critical | Encryption or decryption failure |

### Structured Event Format

**Production format (JSON):**

```json
{
  "timestamp": "2026-03-16T14:30:00.123Z",
  "level": "WARNING",
  "event_type": "RATE_LIMIT_EXCEEDED",
  "severity": "medium",
  "message": "Rate limit exceeded on /api/auth/login",
  "source_ip": "10.0.0.1",
  "user_id": null,
  "organization_id": 7,
  "details": {
    "endpoint": "/api/auth/login",
    "limit": 5,
    "window_seconds": 60
  }
}
```

Events are output in structured JSON format suitable for ingestion by log aggregation platforms (Splunk, Datadog, Azure Monitor, Elastic).

### Secret Redaction

All log output passes through a redaction filter that prevents accidental secret exposure.

| Pattern | Replacement |
|---------|-------------|
| `password=mysecret` | `password=[REDACTED]` |
| `Bearer eyJhbG...` | `Bearer [REDACTED]` |
| `ag_1234567890abcdef...` | `[REDACTED_API_KEY]` |
| `client_secret=abc123` | `client_secret=[REDACTED]` |
| `AccountKey=base64...` | `AccountKey=[REDACTED]` |

### Anomaly Detection Alerts

Beyond security events, AuditGraph's anomaly detection engine monitors for behavioral anomalies across discovered identities.

| Anomaly Type | Description |
|-------------|-------------|
| `permission_escalation` | Unexpected role assignment addition |
| `risk_score_spike` | Sudden increase in identity risk score |
| `dormant_reactivation` | Previously inactive identity shows activity |
| `credential_surge` | Multiple credentials added in short period |
| `off_hours_pim` | PIM role activation outside business hours |
| `excessive_pim_usage` | Abnormally high PIM activation frequency |
| `impossible_travel` | Sign-in from geographically impossible locations (P2) |
| `auth_failure_burst` | Cluster of authentication failures (P2) |

Anomalies are stored in the `anomalies` table, surfaced in the dashboard, and can trigger SOAR playbooks and Slack/Teams notifications.

### Compliance Evidence Export

Security events and audit logs serve as compliance evidence. Export options include:

| Method | Endpoint | Format |
|--------|----------|--------|
| Activity log | `GET /api/activity?limit=500` | JSON (180-day retention) |
| Security events | `GET /api/system/health` | JSON (event summaries) |
| Anomaly history | `GET /api/anomalies` | JSON (filterable by type, severity) |
| Full audit report | `GET /api/reports/data` | JSON (for PDF generation) |
| Prometheus metrics | `GET /api/metrics` | Prometheus text format |

For automated evidence collection, create a `viewer`-role API key with a scoped expiration. See [Compliance Mapping](../compliance.md) for framework-specific evidence guidance.

---

## Security Architecture Summary

AuditGraph follows a defense-in-depth security model combining multiple independent protection layers. No single control is relied upon for data protection — each layer provides independent security guarantees.

```
┌─────────────────────────────────────────────────────────────────┐
│  EXTERNAL BOUNDARY                                               │
│  TLS 1.3 | HSTS | Security Headers | CORS | Rate Limiting       │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │  AUTHENTICATION                                            │   │
│  │  JWT (dual portal keys) | OIDC (JWKS) | SAML | API Keys   │   │
│  │                                                            │   │
│  │  ┌─────────────────────────────────────────────────────┐  │   │
│  │  │  AUTHORIZATION                                       │  │   │
│  │  │  RBAC (8 client + 4 portal roles) | Feature flags    │  │   │
│  │  │                                                       │  │   │
│  │  │  ┌──────────────────────────────────────────────┐    │  │   │
│  │  │  │  TENANT ISOLATION                             │    │  │   │
│  │  │  │  RLS (44 tables) | Dual DB users | 5 safety   │    │  │   │
│  │  │  │  layers | Admin guard | Context verification  │    │  │   │
│  │  │  │                                               │    │  │   │
│  │  │  │  ┌──────────────────────────────────────┐    │    │  │   │
│  │  │  │  │  DATA PROTECTION                      │    │    │  │   │
│  │  │  │  │  Fernet encryption (AES-128-CBC +     │    │    │  │   │
│  │  │  │  │  HMAC-SHA256) | MultiFernet rotation  │    │    │  │   │
│  │  │  │  │  | Log redaction | Credential masking │    │    │  │   │
│  │  │  │  └──────────────────────────────────────┘    │    │  │   │
│  │  │  └──────────────────────────────────────────────┘    │  │   │
│  │  └─────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                   │
│  OPERATIONAL SAFETY                                               │
│  Circuit breakers | Retry logic | Security event logging          │
│  Anomaly detection | Structured audit trail | Secret redaction    │
└─────────────────────────────────────────────────────────────────┘
```

**Key properties:**

| Property | Guarantee |
|----------|-----------|
| **Tenant isolation** | RLS prevents cross-tenant data access even if application bugs exist |
| **Credential protection** | Secrets are encrypted at rest, masked in responses, redacted in logs |
| **Authentication strength** | Dual portal keys, JWKS-verified SSO, rate-limited login |
| **API hardening** | Validated inputs, size limits, idempotency, injection detection |
| **Auditability** | Structured events for every security-relevant action |
| **Resilience** | Circuit breakers and retry logic prevent cascading failures |

---

## References

- [Security Architecture](../security-architecture.md) -- Full security architecture documentation
- [Security Features](../security-features.md) -- Rate limiting, circuit breakers, encryption details
- [Security Posture](../security-posture.md) -- Platform security maturity assessment
- [Compliance Mapping](../compliance.md) -- Framework mappings and audit evidence
- [Operations](../operations.md) -- Deployment, monitoring, key rotation procedures
- [Data Model](../data-model.md) -- Database schema and RLS implementation
