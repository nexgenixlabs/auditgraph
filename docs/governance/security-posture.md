# Section 11 -- Security Posture

## Overview

This section describes the security maturity of the AuditGraph platform itself. While AuditGraph helps customers assess their cloud identity security posture, the platform also maintains its own security controls.

---

## Security Maturity Assessment

AuditGraph's security posture is assessed across four dimensions:

```
┌──────────────────────────────────────────────────────────────┐
│                SECURITY MATURITY SCORECARD                    │
│                                                              │
│  ┌───────────────────────────────────┐                      │
│  │  API Security            ████████ │  Strong               │
│  ├───────────────────────────────────┤                      │
│  │  Data Protection         ████████ │  Strong               │
│  ├───────────────────────────────────┤                      │
│  │  Operational Safety      ████████ │  Strong               │
│  ├───────────────────────────────────┤                      │
│  │  Code Quality            ██████── │  Good                 │
│  └───────────────────────────────────┘                      │
└──────────────────────────────────────────────────────────────┘
```

---

## API Security

API security protects the platform from unauthorized access, injection attacks, and abuse.

| Control | Implementation | Status |
|---------|---------------|--------|
| **Authentication** | JWT with portal-specific signing keys (ADMIN/CLIENT) | Implemented |
| **Token Security** | 30/60-min access TTL, 7-day refresh, SHA-256 hashing, reuse detection | Implemented |
| **OIDC Verification** | RS256 signature verification via JWKS with 600s TTL cache | Implemented |
| **SAML Verification** | Signed assertion requirement via python3-saml | Implemented |
| **RBAC** | 8-role hierarchy (owner→reader) with decorator-based enforcement | Implemented |
| **API Key Auth** | `ag_` prefix, SHA-256 hash storage, usage tracking, expiry support | Implemented |
| **Rate Limiting** | In-memory sliding window on auth endpoints (5-20 req/min) | Implemented |
| **JSON Validation** | Schema validation on 10+ endpoints via jsonschema | Implemented |
| **Input Sanitization** | XSS, SQLi, command injection pattern detection | Implemented |
| **Request Size Limits** | 5 MB max content length | Implemented |
| **Security Headers** | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy | Implemented |
| **CORS** | Configured per-environment with strict origin checking | Implemented |
| **Idempotency** | Header-based dedup on mutation endpoints (24h TTL) | Implemented |
| **Password Policy** | 12+ chars, uppercase, lowercase, digit, special char, blocklist | Implemented |

### How to Interpret

**Strong** means all critical API security controls are in place. The platform protects against the OWASP Top 10 API security risks:

- **Broken Authentication**: JWT verification, rate-limited login, account lockout
- **Broken Object Level Authorization**: RLS enforces tenant isolation at database layer
- **Excessive Data Exposure**: Credentials never returned in API responses
- **Lack of Resources & Rate Limiting**: Rate limits on sensitive endpoints, request size caps
- **Injection**: Input sanitization, parameterized queries, schema validation

---

## Data Protection

Data protection ensures customer data is secure at rest, in transit, and in memory.

| Control | Implementation | Status |
|---------|---------------|--------|
| **Encryption at Rest** | Fernet field-level encryption for credentials and secrets | Implemented |
| **Key Rotation** | MultiFernet support (ENCRYPTION_KEYS, comma-separated) | Implemented |
| **Encryption in Transit** | HTTPS/TLS with HSTS (1-year max-age, includeSubDomains, preload) | Implemented |
| **Tenant Isolation** | PostgreSQL Row Level Security on 44 tables with strict policies | Implemented |
| **Dual DB Users** | auditgraph_app (NOBYPASSRLS) / auditgraph_admin (BYPASSRLS) | Implemented |
| **RLS Safety Layers** | SET LOCAL + checkout RESET + return RESET + teardown hook + verify | Implemented |
| **Log Redaction** | Passwords, tokens, API keys, secrets auto-redacted in all log output | Implemented |
| **Credential Masking** | Client secrets never in API responses, encrypted in DB | Implemented |
| **Snapshot Integrity** | SHA-256 hash + HMAC signature on discovery runs | Implemented |
| **Admin Guard** | Blocks accidental Database() calls without tenant context in requests | Implemented |

### How to Interpret

**Strong** means data protection follows defense-in-depth principles:

1. **Network layer**: TLS everywhere, HSTS enforcement
2. **Application layer**: Encrypted credentials, masked responses, redacted logs
3. **Database layer**: RLS prevents cross-tenant access even if application bugs exist
4. **Process layer**: Admin guard, context verification, safety resets

The most critical control is **Row Level Security**. Even if an application-level authorization check is bypassed, the database itself enforces that queries can only return data for the authenticated tenant.

---

## Operational Safety

Operational safety ensures the platform remains available and resilient under adverse conditions.

| Control | Implementation | Status |
|---------|---------------|--------|
| **Circuit Breakers** | 3 breakers (graph_api, aws_api, llm_api) with threshold/recovery | Implemented |
| **Retry Logic** | Exponential backoff via tenacity (2-3 attempts per service) | Implemented |
| **Health Endpoints** | 6 endpoints (liveness, readiness, detailed, system, SLA, metrics) | Implemented |
| **Security Event Logging** | 12+ structured event types with severity levels | Implemented |
| **Heartbeat Monitoring** | 20-second heartbeats during discovery runs, zombie detection | Implemented |
| **Connection Pooling** | ThreadedConnectionPool with configurable min/max | Implemented |
| **Slow Query Detection** | Configurable threshold (DB_SLOW_QUERY_MS), logged as security events | Implemented |
| **Data Retention** | Automated daily cleanup at 03:00 UTC with configurable retention periods | Implemented |
| **Graceful Degradation** | Circuit breakers prevent cascading failures from external API outages | Implemented |
| **Snapshot Validation** | Post-discovery validation of required and optional components | Implemented |

### How to Interpret

**Strong** means the platform is designed to survive common failure modes:

- **External API outage**: Circuit breakers prevent cascading failures. Discovery for that cloud provider pauses until recovery.
- **Database overload**: Connection pooling limits concurrent connections. Slow queries are detected and logged.
- **Stale data**: Scheduled discovery ensures data freshness. Drift detection catches changes between scans.
- **Runaway processes**: Heartbeat monitoring detects zombie discovery jobs. Runtime limits prevent infinite loops.

---

## Code Quality

Code quality practices ensure the codebase is maintainable, testable, and free of common vulnerabilities.

| Practice | Implementation | Status |
|----------|---------------|--------|
| **Static Analysis** | Bandit configured in pyproject.toml (skips B101/B104) | Configured |
| **Linting** | Ruff configured (E, F, W, I, N, UP, B, C4 rules) | Configured |
| **Type Checking** | MyPy configured with warn_return_any, ignore_missing_imports | Configured |
| **Code Formatting** | Black configured (line-length 100, py39+) | Configured |
| **Unit Tests** | 41 tests covering encryption, validation, rate limiting, circuit breakers, OIDC, security events | Implemented |
| **Parameterized Queries** | All SQL uses %s placeholders via psycopg2 | Implemented |
| **Query Field Allowlist** | QUERY_FIELD_MAP prevents SQL injection in advanced query builder | Implemented |
| **Dependency Scanning** | pip-audit in CI/CD guardrail tests | Configured |

### How to Interpret

**Good** means foundational code quality practices are in place, with room for expansion:

- Static analysis and linting catch common bugs and security issues
- Unit tests cover critical security modules (encryption, auth, rate limiting)
- Parameterized queries prevent SQL injection at the framework level
- Dependency scanning catches known vulnerabilities in third-party packages

**Areas for improvement:**
- Expand test coverage to include integration tests
- Add end-to-end API tests
- Implement continuous security scanning in CI/CD

---

## Compliance Alignment

AuditGraph's security controls align with common enterprise compliance requirements:

| Framework | Relevant Controls |
|-----------|------------------|
| **SOC 2 Type II** | Access controls (RBAC), encryption at rest, audit logging, change detection |
| **ISO 27001** | A.9 Access control, A.10 Cryptography, A.12 Operations security |
| **NIST 800-53** | AC-2 (Account Management), SC-12 (Cryptographic Key), AU-2 (Audit Events) |
| **CIS Controls** | 4.1 (MFA), 5.4 (Restrict Admin Privileges), 6.2 (Centralized Logging) |
| **HIPAA** | Password policy (12+ chars, complexity), encryption, audit trail |

---

## Security Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  EXTERNAL BOUNDARY                                              │
│  TLS 1.3 | HSTS | Security Headers | CORS | Rate Limiting      │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  AUTHENTICATION                                            │  │
│  │  JWT (dual keys) | OIDC (JWKS) | SAML | API Keys         │  │
│  │                                                            │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  AUTHORIZATION                                       │  │  │
│  │  │  RBAC (8 roles) | Portal roles | Feature flags       │  │  │
│  │  │                                                       │  │  │
│  │  │  ┌──────────────────────────────────────────────┐    │  │  │
│  │  │  │  DATA ISOLATION                               │    │  │  │
│  │  │  │  RLS (44 tables) | Dual DB users | Verify     │    │  │  │
│  │  │  │                                               │    │  │  │
│  │  │  │  ┌──────────────────────────────────────┐    │    │  │  │
│  │  │  │  │  DATA PROTECTION                      │    │    │  │  │
│  │  │  │  │  Fernet encryption | Log redaction    │    │    │  │  │
│  │  │  │  │  Credential masking | Key rotation    │    │    │  │  │
│  │  │  │  └──────────────────────────────────────┘    │    │  │  │
│  │  │  └──────────────────────────────────────────────┘    │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## References

- [Security Architecture](security-architecture.md) -- Detailed security design
- [Security Features](security-features.md) -- Feature-level documentation
- [Operations](operations.md) -- Monitoring and operational procedures
- [Best Practices](best-practices.md) -- Customer security recommendations
