# Section 8 -- Security Features

## Overview

AuditGraph implements multiple layers of security protections. This section documents each protection, its purpose, and how it works.

---

## Rate Limiting

### Purpose

Rate limiting prevents brute-force attacks against authentication endpoints and protects API availability.

### Implementation

AuditGraph uses an in-memory sliding-window rate limiter. No external dependency (like Redis) is required.

**How it works:**
1. Each request is keyed by `{IP_address}:{endpoint_path}`
2. Request timestamps are stored in an in-memory dictionary
3. When a request arrives, timestamps outside the window are evicted
4. If the count exceeds the threshold, a `429 Too Many Requests` is returned
5. Stale entries are auto-cleaned every 60 seconds

### Rate Limits

| Endpoint | Max Requests | Window | Key |
|----------|-------------|--------|-----|
| `POST /api/auth/login` | 5 | 60 seconds | IP |
| `POST /api/auth/signup` | 3 | 60 seconds | IP |
| `POST /api/auth/refresh` | 10 | 60 seconds | IP |
| `POST /api/auth/forgot-password` | 3 | 300 seconds | IP |
| `POST /api/auth/reset-password` | 5 | 300 seconds | IP |
| Connector mutations (create/update/delete) | 20 | 60 seconds | IP + path |
| Copilot endpoints (chat/query/investigate) | 20 | 60 seconds | IP + path |

### Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 45
Content-Type: application/json

{
  "error": "Rate limit exceeded. Try again in 45 seconds.",
  "retry_after": 45
}
```

---

## JSON Validation

### Purpose

Schema validation prevents malformed or malicious payloads from reaching handler logic.

### Implementation

Request bodies are validated against JSON schemas using the `jsonschema` library. The `@validate_json(SCHEMA)` decorator rejects requests that fail validation before the handler executes.

### Schemas

| Schema | Key Rules |
|--------|-----------|
| `LOGIN_SCHEMA` | `username` and `password` required, no extra fields |
| `CREATE_CONNECTION_SCHEMA` | `label` required, `cloud` must be `azure`/`aws`/`gcp` |
| `TRIGGER_RUN_SCHEMA` | `connection_id` integer, `scan_mode` enum |
| `COPILOT_CHAT_SCHEMA` | `message` required, max 10,000 characters |
| `CREATE_USER_SCHEMA` | `username`, `password`, `role` required |
| `CHANGE_PASSWORD_SCHEMA` | `current_password` and `new_password` required |
| `SAVE_SETTINGS_SCHEMA` | Key-value pairs, values must be string/boolean/integer/null |

### Example: Validation Error

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "admin" }

HTTP/1.1 400 Bad Request
{
  "error": "Validation error at password: 'password' is a required property",
  "error_code": "VALIDATION_ERROR",
  "field": "password",
  "request_id": "req_abc123"
}
```

---

## Idempotency Protection

### Purpose

Idempotency keys prevent duplicate operations when clients retry requests (e.g., due to network timeouts). Without idempotency protection, a retry could create duplicate connectors or trigger duplicate discovery runs.

### Implementation

Clients include an `Idempotency-Key` header with a unique value. The server caches the response for 24 hours. Duplicate requests return the cached response with `X-Idempotent-Replayed: true`.

### Protected Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /api/client/connections` | Prevent duplicate connector creation |
| `POST /api/runs/trigger` | Prevent duplicate discovery runs |

### Example

```http
POST /api/client/connections
Idempotency-Key: idem_abc123def456
Content-Type: application/json

{ "label": "Production Azure", "cloud": "azure", ... }

HTTP/1.1 201 Created
X-Idempotency-Key: idem_abc123def456
X-Idempotent-Replayed: false

{ "id": 42, "label": "Production Azure", ... }
```

Retry the same request:

```http
POST /api/client/connections
Idempotency-Key: idem_abc123def456
Content-Type: application/json

{ "label": "Production Azure", "cloud": "azure", ... }

HTTP/1.1 201 Created
X-Idempotency-Key: idem_abc123def456
X-Idempotent-Replayed: true

{ "id": 42, "label": "Production Azure", ... }
```

The second request returns the cached response without creating a duplicate.

---

## Circuit Breakers

### Purpose

Circuit breakers prevent cascading failures when external APIs (Microsoft Graph, AWS IAM, AI services) are degraded or unavailable. Instead of repeatedly calling a failing API, the circuit breaker "opens" and rejects requests immediately, allowing the system to recover.

### Implementation

```
       Normal                Failures exceed             Recovery timeout
      operation              threshold                    elapsed
         │                      │                          │
    ┌────▼────┐            ┌────▼────┐              ┌─────▼─────┐
    │ CLOSED  │───────────►│  OPEN   │─────────────►│ HALF_OPEN │
    │ (allow) │            │ (block) │              │ (test)    │
    └────▲────┘            └─────────┘              └─────┬─────┘
         │                                                │
         │        Success on test request                 │
         └────────────────────────────────────────────────┘
```

### Configured Breakers

| Breaker | Failure Threshold | Recovery Timeout | Protects |
|---------|-------------------|------------------|----------|
| `graph_api` | 5 consecutive failures | 60 seconds | Microsoft Graph API calls |
| `aws_api` | 5 consecutive failures | 60 seconds | AWS IAM API calls |
| `llm_api` | 3 consecutive failures | 120 seconds | AI/Copilot API calls |

### Behavior

- **CLOSED**: All requests pass through. Failures are counted.
- **OPEN**: All requests are immediately rejected. No API calls are made.
- **HALF_OPEN**: One test request is allowed. Success closes the breaker; failure reopens it.

---

## Retry Logic

### Purpose

Transient failures (network timeouts, 503 errors) should be retried automatically with exponential backoff. Retry logic works alongside circuit breakers.

### Implementation

Uses the `tenacity` library for retry decorators:

| Decorator | Max Attempts | Backoff | Applied To |
|-----------|-------------|---------|------------|
| `retry_graph_api` | 3 | 1-8 seconds exponential | Microsoft Graph API calls |
| `retry_aws_api` | 3 | 1-8 seconds exponential | AWS IAM API calls |
| `retry_llm_api` | 2 | 2-16 seconds exponential | AI/Copilot service calls |

### Resilient Call Pattern

```python
from app.resilience import resilient_call

# Combines circuit breaker check + retry logic:
result = resilient_call('graph_api', requests.get, url, timeout=10)
```

1. Check circuit breaker state
2. If OPEN, raise `CircuitBreakerOpen` immediately
3. If CLOSED/HALF_OPEN, execute the call with retry
4. On success, record success (close breaker if HALF_OPEN)
5. On failure, record failure (open breaker if threshold reached)

---

## Request Size Limits

### Purpose

Prevents denial-of-service via large payloads.

### Configuration

| Limit | Value | Enforcement |
|-------|-------|-------------|
| `MAX_CONTENT_LENGTH` | 5 MB | Flask built-in (returns 413) |
| Input sanitizer soft limit | 10 MB | Middleware (returns 400) |

Exceeding the limit returns:

```http
HTTP/1.1 413 Payload Too Large
{
  "error": "Request entity too large. Maximum 5MB allowed."
}
```

---

## Security Event Logging

### Purpose

Structured security events provide audit trail and SIEM integration for security-relevant actions.

### Event Types

| Event Type | Severity | Trigger |
|-----------|----------|---------|
| `LOGIN_SUCCESS` | info | Successful authentication |
| `LOGIN_FAILED` | medium | Invalid credentials or locked account |
| `ROLE_CHANGED` | medium | User role modification (admin promotion = medium) |
| `CONNECTOR_CREATED` | info | New cloud connector added |
| `CONNECTOR_DELETED` | medium | Cloud connector removed |
| `CREDENTIAL_ROTATED` | info | Connector credentials rotated |
| `TENANT_CONTEXT_VIOLATION` | critical | RLS context mismatch or bypass detected |
| `RLS_DRIFT_DETECTED` | critical | RLS policy removed from a table |
| `ADMIN_GUARD_BLOCKED` | high | Unauthorized admin DB access in request |
| `POOL_EXHAUSTION` | high | Connection pool capacity reached |
| `SLOW_QUERY` | medium | Query exceeded latency threshold |

### Event Format

```json
{
  "event_type": "LOGIN_FAILED",
  "severity": "medium",
  "tenant_id": null,
  "correlation_id": "req_abc123",
  "timestamp": "2026-03-16T14:30:00.000Z",
  "details": {
    "username": "admin@company.com",
    "ip_address": "10.0.0.1",
    "reason": "invalid credentials"
  }
}
```

### Severity-to-Log-Level Mapping

| Severity | Log Level | Response |
|----------|-----------|----------|
| `critical` | CRITICAL | Immediate investigation required |
| `high` | ERROR | Prompt investigation |
| `medium` | WARNING | Review during regular audit |
| `low` / `info` | INFO | Normal operational audit trail |

---

## Encryption

### Purpose

Field-level encryption protects sensitive data at rest in the database.

### What Is Encrypted

| Data | Location |
|------|----------|
| Cloud connector client secrets | `cloud_connections.metadata` JSONB |
| OIDC client secrets | `settings` table |
| Refresh token metadata | In-memory processing |

### Encryption Details

| Property | Value |
|----------|-------|
| Algorithm | Fernet (AES-128-CBC + HMAC-SHA256) |
| Key Size | 256-bit (32 bytes, base64-encoded) |
| Rotation | MultiFernet (multiple keys, newest first) |
| Prefix | `enc:` identifies encrypted values |
| Gradual Migration | `decrypt_field()` handles both encrypted and plaintext |

### Key Rotation

MultiFernet allows zero-downtime key rotation:

```
ENCRYPTION_KEYS=NEW_KEY,OLD_KEY

- Encryption uses NEW_KEY
- Decryption tries NEW_KEY first, then OLD_KEY
- rotate_encrypted_field() re-encrypts with NEW_KEY
```

See [Security Architecture](security-architecture.md) for the full rotation procedure.

---

## Credential Protection

### Password Storage

User passwords are hashed with bcrypt (adaptive cost factor). Plaintext passwords are never stored.

### Credential Masking

Credentials are masked in API responses and logs:

| Context | Behavior |
|---------|----------|
| API responses | Client secrets never included in GET responses |
| Log output | Redaction filter replaces secrets with `[REDACTED]` |
| Database | Encrypted with Fernet before storage |
| Memory | Decrypted only when needed (e.g., discovery execution) |

---

## Input Sanitization

### Purpose

A middleware layer provides defense-in-depth against injection attacks.

### Detection Patterns

| Category | Examples |
|----------|---------|
| **XSS** | `<script>`, `onclick=`, `javascript:`, `<iframe>` |
| **SQL Injection** | `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `SLEEP()` |
| **Command Injection** | Shell metacharacters in unexpected fields |

### Behavior

- Recursively scans all JSON body values (max depth 20)
- Skips exempt paths (webhook callbacks, SAML ACS)
- Skips legitimate SQL-like endpoints (identity query builder)
- Returns `400 Bad Request` on detection
- Logs warning with IP address

---

## Why These Protections Matter

| Protection | Threat Mitigated | Impact if Missing |
|-----------|------------------|-------------------|
| Rate limiting | Brute-force password attacks | Account compromise |
| JSON validation | Malformed payload exploitation | Application errors, potential injection |
| Idempotency | Duplicate operations on retry | Duplicate resources, inconsistent state |
| Circuit breakers | Cascading failure from external APIs | Full platform outage |
| Retry logic | Transient network failures | Failed discovery runs, missed data |
| Size limits | Denial-of-service via large payloads | Memory exhaustion, service crash |
| Security events | Undetected security incidents | Compromised accounts go unnoticed |
| Encryption | Data exposure from database access | Credential theft |
| Key rotation | Long-term key compromise | All encrypted data exposed |
| Input sanitization | XSS, SQL injection, command injection | Data breach, privilege escalation |

---

## References

- [Security Architecture](security-architecture.md) -- Authentication and tenant isolation
- [Operations](operations.md) -- Monitoring and troubleshooting
- [Security Posture](security-posture.md) -- Security maturity assessment
- [API Reference](api-reference.md) -- Security-related API endpoints
