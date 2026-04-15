# Security Overview for AuditGraph

## Introduction

AuditGraph is a Cloud Identity Security platform that provides continuous visibility into identity risk across Azure, AWS, and GCP environments. The platform discovers identities, analyzes privilege relationships, computes quantitative risk scores, and helps organizations enforce least privilege and detect identity drift.

AuditGraph is built with a security-first architecture. The platform protects customer data through strict tenant isolation, encrypted credential storage, hardened APIs, and structured security monitoring. This document provides an executive-level summary of the platform's security model for CISOs, security architects, and vendor assessment teams.

For detailed technical documentation, each section below references the relevant deep-dive pages.

---

## Platform Security Model

AuditGraph operates as a read-only observer of customer cloud environments. The platform collects identity and access metadata — it does not read file contents, email, application data, or network traffic, and it does not create, modify, or delete any resources in customer environments.

```
┌───────────────────────────────────────────────────────┐
│            Customer Cloud Environments                 │
│         Azure  /  AWS  /  GCP                          │
└──────────────────────┬────────────────────────────────┘
                       │  Read-only API calls
                       ▼
┌───────────────────────────────────────────────────────┐
│            AuditGraph Connectors                       │
│   Encrypted credentials  |  Per-tenant isolation       │
└──────────────────────┬────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────┐
│            Discovery Engine                            │
│   Identity scanning  |  Entitlement mapping            │
│   Resource inventory  |  Credential tracking           │
└──────────────────────┬────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────┐
│     Identity Graph  +  Risk Engine  +  Compliance      │
│   Access graph construction  |  AGIRS scoring          │
│   Drift detection  |  Anomaly detection                │
└──────────────────────┬────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────┐
│            CISO Dashboard  +  Reports                  │
│   Risk posture  |  Remediation  |  Audit evidence      │
└───────────────────────────────────────────────────────┘
```

**Data collected:** Identity metadata, role assignments, credential expiration dates, resource names, ownership relationships, and sign-in timestamps. See [FAQ](../faq.md) for the complete data collection inventory.

**Data not collected:** File contents, blob data, email, chat messages, application databases, network traffic.

---

## Tenant Isolation

Every customer organization is a fully isolated tenant. Cross-tenant data access is prevented at the database layer through PostgreSQL Row Level Security — even if an application-level authorization check is bypassed.

```
┌───────────────────────────────────────────────────────┐
│  1. Authentication                                     │
│     JWT token validated, organization_id extracted      │
│                          ↓                              │
│  2. Tenant Context Enforcement                         │
│     SET LOCAL app.current_tenant_id = organization_id  │
│                          ↓                              │
│  3. Connector-Level Isolation                          │
│     Cloud connectors scoped to owning organization     │
│                          ↓                              │
│  4. Row Level Security (PostgreSQL)                    │
│     All 44 customer tables filtered automatically      │
│                          ↓                              │
│  5. Database Role Separation                           │
│     App user (NOBYPASSRLS) cannot bypass RLS           │
│                          ↓                              │
│  Tenant-Scoped Data Access                             │
└───────────────────────────────────────────────────────┘
```

| Layer | Protection |
|-------|-----------|
| **Authentication** | JWT tokens carry the tenant identifier. Invalid or missing tokens are rejected before any data access. |
| **Tenant context** | Every database connection sets a transaction-scoped tenant context. Context is automatically cleared on connection return. |
| **Connector isolation** | Cloud connectors belong to a single organization. Discovery data inherits the connector's tenant scope. |
| **Row Level Security** | PostgreSQL enforces `WHERE organization_id = current_tenant` on every query. 44 tables are protected. |
| **Database role separation** | The application user (`NOBYPASSRLS`) cannot disable RLS. Only the system user (`BYPASSRLS`) can access cross-tenant data, and it is restricted to scheduled jobs and migrations. |

All database queries are executed within an enforced tenant context. PostgreSQL Row Level Security ensures that records from other organizations cannot be accessed even if application-level logic fails. The tenant context is transaction-scoped (`SET LOCAL`) and automatically cleared when the database connection is returned to the pool, preventing context leakage between requests.

See [Data Protection and Tenant Isolation](data-protection.md) for the complete isolation model, safety layers, and security event logging.

---

## Encryption and Data Protection

AuditGraph encrypts sensitive data at every stage of its lifecycle.

### Data in Transit

| Control | Implementation |
|---------|---------------|
| **Transport encryption** | TLS 1.3 on all connections |
| **HSTS enforcement** | 1-year max-age with `includeSubDomains` and `preload` directives |
| **Certificate management** | Azure-managed TLS certificates for all `*.auditgraph.ai` domains |

### Data at Rest

| Control | Implementation |
|---------|---------------|
| **Encryption algorithm** | Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) |
| **Scope** | All cloud connector credentials (client secrets, access keys, service account keys) |
| **Identification** | Encrypted values carry an `enc:` prefix to distinguish from plaintext |
| **Access** | Credentials are decrypted only at discovery time, then discarded from memory |

### Credential Protection

- Connector secrets are encrypted immediately on receipt
- API responses never return credential values
- Log output automatically redacts passwords, tokens, API keys, and secrets

### Key Management

| Control | Implementation |
|---------|---------------|
| **Key rotation** | MultiFernet supports multiple active keys for zero-downtime rotation |
| **Configuration** | Keys provided via environment variables (`ENCRYPTION_KEYS`, comma-separated) |
| **Backward compatibility** | Old keys remain active for decryption until all values are re-encrypted |

### Cryptography Summary

| Protection | Implementation |
|-----------|---------------|
| **Data in transit** | TLS 1.3 with HSTS preload |
| **Data at rest** | Fernet symmetric encryption (AES-128-CBC) |
| **Integrity verification** | HMAC-SHA256 on all encrypted values |
| **Key rotation** | MultiFernet with zero-downtime rotation |
| **Log protection** | Automatic redaction of secrets, tokens, and keys |

See [Data Protection and Tenant Isolation](data-protection.md) for encryption details, key rotation procedures, and credential storage protocols.

---

## Authentication and Access Control

AuditGraph provides multiple authentication methods and enforces role-based access control across two separated portals.

```
┌───────────────────────────────────────────────────────┐
│  User Login                                            │
│       ↓                                                │
│  OIDC / SAML SSO  or  Local Authentication             │
│       ↓                                                │
│  JWT Issuance (portal-specific signing key)            │
│       ↓                                                │
│  RBAC Enforcement (decorator-based, per endpoint)      │
│       ↓                                                │
│  Authorized API Access                                 │
└───────────────────────────────────────────────────────┘
```

| Control | Implementation |
|---------|---------------|
| **JWT authentication** | Portal-specific signing keys (admin and client), 30/60-minute access tokens, 7-day refresh tokens |
| **Single sign-on** | OIDC (Azure AD, Okta, Google Workspace) with RS256 JWKS signature verification; SAML 2.0 with signed assertions |
| **RBAC** | 8 client portal roles (owner through reader) and 4 admin portal roles (superadmin through reader) |
| **Portal separation** | Separate signing keys, role hierarchies, and route decorators prevent cross-portal token reuse |
| **API key authentication** | `ag_` prefix keys with SHA-256 hash storage, usage tracking, role scoping, and expiration |

See [Security Architecture](../security-architecture.md) for JWT claims structure, OIDC verification flow, SAML integration, and RBAC role hierarchy.

---

## API Security and Operational Protection

AuditGraph hardens the API layer against common attack vectors.

| Protection | Implementation | Prevents |
|-----------|---------------|----------|
| **Rate limiting** | Sliding window on auth endpoints (5-20 req/min) | Brute-force attacks, credential stuffing |
| **Request validation** | JSON schema validation on mutation endpoints | Malformed input, unexpected data types |
| **Input sanitization** | Pattern detection for XSS, SQLi, command injection | Injection attacks |
| **Idempotency** | `Idempotency-Key` header with 24-hour deduplication | Duplicate operations from network retries |
| **Request size limits** | 5 MB maximum content length | Denial-of-service via payload inflation |
| **Security headers** | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy | Clickjacking, content injection, MIME sniffing |
| **Circuit breakers** | 3 breakers (Graph API, AWS API, LLM API) with threshold and recovery | Cascading failures from external API outages |

These controls address the OWASP API Security Top 10:

| Control | Purpose |
|---------|---------|
| Rate limiting | Prevent API abuse and brute-force attacks |
| Schema validation | Prevent malformed requests and type confusion |
| Input sanitization | Prevent injection attacks (XSS, SQLi, command injection) |
| Idempotency | Prevent duplicate operations from network retries |
| Request size limits | Prevent memory exhaustion and payload-based denial of service |

See [Security Features](../security-features.md) for rate limiting configuration, validation schemas, and circuit breaker state machine details.

---

## Compliance and Governance

AuditGraph maps identity findings to major compliance frameworks and provides continuous posture monitoring rather than point-in-time audits.

| Framework | Coverage |
|-----------|---------|
| **SOC 2 Type II** | Access control, monitoring, encryption, change management |
| **ISO 27001** | Identity management, access rights, cryptography, logging |
| **NIST 800-53 Rev 5** | Account management, least privilege, audit events, risk assessment |
| **NIST CSF 2.0** | Identify, Protect, Detect, Respond, Recover functions |
| **CIS Benchmarks** | 33 checks across Azure, AWS, and GCP (identity, storage, key vault) |
| **Azure Security Benchmark v3** | Identity management, privileged access, data security, logging |
| **AWS Security Best Practices** | IAM user management, credential rotation, policy hygiene |
| **HIPAA / PCI-DSS / SOX** | Access controls, encryption, audit trails, change detection |

AuditGraph computes compliance scores per framework after each discovery scan, enabling security teams to track posture trends and generate audit evidence on demand.

See [Compliance Mapping](../compliance.md) for control-level mapping tables, evidence endpoints, and audit preparation guidance.

---

## Security Monitoring and Audit Logging

AuditGraph records structured security events for every security-relevant operation and provides behavioral monitoring across discovered identities.

**Platform security events** track authentication, authorization, and operational incidents:

```json
{
  "event_type": "LOGIN_FAILED",
  "severity": "medium",
  "organization_id": 7,
  "timestamp": "2026-03-16T18:30:00.000Z",
  "details": {
    "username": "admin@company.com",
    "source_ip": "10.0.0.1",
    "reason": "invalid_password"
  }
}
```

**Identity monitoring** detects behavioral anomalies across customer cloud environments:

| Capability | Description |
|-----------|-------------|
| **Anomaly detection** | 8 detection types including permission escalation, dormant reactivation, and impossible travel |
| **Drift monitoring** | Automatic comparison of consecutive discovery snapshots detecting role, credential, and configuration changes |
| **Security events** | 12+ structured event types (login, RLS violation, rate limit, circuit breaker, slow query) |
| **Audit evidence** | JSON export via API, CSV download from UI, PDF reports, and API key access for automated collection |

Events are output in structured JSON format suitable for ingestion by SIEM platforms (Splunk, Datadog, Azure Monitor, Elastic).

See [Data Protection and Tenant Isolation](data-protection.md) for the complete event type catalog, log redaction rules, and evidence export procedures.

---

## Summary

AuditGraph is built using a defense-in-depth security architecture that protects customer data through multiple independent control layers.

| Security Domain | Key Controls |
|----------------|-------------|
| **Tenant isolation** | PostgreSQL RLS on 44 tables, dual database users, transaction-scoped tenant context |
| **Data protection** | Fernet encryption for credentials, TLS 1.3 in transit, automatic log redaction |
| **Authentication** | JWT with portal-specific keys, OIDC/SAML SSO, JWKS verification, API keys |
| **Authorization** | 8-role client RBAC, 4-role admin RBAC, decorator-based enforcement |
| **API hardening** | Rate limiting, input validation, sanitization, size limits, idempotency |
| **Monitoring** | Structured security events, anomaly detection, drift monitoring, audit export |
| **Compliance** | Continuous scoring against SOC 2, ISO 27001, NIST 800-53, CIS, and 7 additional frameworks |

The platform collects only identity and access metadata through read-only API calls. It does not modify customer cloud environments, store customer application data, or access file contents or network traffic.

For organizations conducting a vendor security assessment, the recommended review path is:

1. [Data Protection and Tenant Isolation](data-protection.md) -- Encryption, RLS, credential storage
2. [Security Architecture](../security-architecture.md) -- Authentication, RBAC, full 7-layer model
3. [Compliance Mapping](../compliance.md) -- Framework control mappings and audit evidence
4. [Security Posture](../security-posture.md) -- Platform self-assessment scorecard
5. [FAQ](../faq.md) -- Data collection scope, SOC 2 status, self-hosting options

---

## References

- [Data Protection and Tenant Isolation](data-protection.md) -- Encryption, RLS, credential storage, key rotation
- [Security Architecture](../security-architecture.md) -- Authentication, RBAC, tenant isolation, API security
- [Security Features](../security-features.md) -- Rate limiting, circuit breakers, security events
- [Security Posture](../security-posture.md) -- Platform security maturity scorecard
- [Compliance Mapping](../compliance.md) -- Framework mappings and audit evidence
- [FAQ](../faq.md) -- Common security and data protection questions
