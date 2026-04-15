# Security FAQ for Vendor Assessments

*Last Updated: March 2026*

## Overview

This page provides concise answers to the security questions most commonly asked during enterprise vendor evaluations. It is designed to help security teams complete questionnaires such as SIG (Standardized Information Gathering), CAIQ (Cloud Security Alliance), SOC 2 vendor reviews, and internal enterprise security assessments.

For detailed technical documentation, each answer references the relevant deep-dive page.

---

## Data Storage

**Where is customer data stored?**

AuditGraph stores identity and access metadata only. It does not store customer application data, file contents, email, or network traffic.

| Property | Implementation |
|----------|---------------|
| **Data scope** | Identity metadata: display names, role assignments, credential expiry dates, ownership relationships, sign-in timestamps |
| **Storage location** | PostgreSQL Flexible Server hosted on Azure (eastus region) |
| **Credential handling** | Cloud connector secrets are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). No plaintext credential storage. |
| **Logical isolation** | Every record is scoped to an `organization_id`. PostgreSQL Row Level Security enforces tenant boundaries at the database layer. |
| **Retention** | Configurable per data type. Defaults: discovery runs 90 days, activity log 180 days, anomalies 180 days. |

Customer cloud resources (virtual machines, storage blobs, databases, application code) are not stored in AuditGraph. The platform stores resource names and configuration metadata for security analysis, not resource contents.

---

## Data Classification

AuditGraph processes **identity and access metadata only**. This data is classified as operational security metadata — it describes who has access to what, not what customers do with that access.

| Classification | Examples | Stored by AuditGraph |
|---------------|----------|---------------------|
| **Identity metadata** | Display names, UPNs, object IDs, account status | Yes |
| **Access metadata** | Role assignments, permission scopes, group memberships | Yes |
| **Credential metadata** | Key IDs, expiration dates, credential types | Yes (values are never stored) |
| **Activity metadata** | Sign-in timestamps, last activity dates | Yes |
| **Application data** | File contents, blob data, database records | No |
| **Communication data** | Email, chat messages, calendar entries | No |
| **Sensitive business data** | Financial records, trade secrets, intellectual property | No |
| **PII beyond identity identifiers** | Social security numbers, health records, payment card data | No |

AuditGraph does not process, transmit, or store customer application data, end-user content, or regulated personal data beyond the identity identifiers necessary for security analysis (display names, email addresses, and object IDs).

---

## Data Residency

**Where is customer data physically located?**

AuditGraph currently stores all customer data in Microsoft Azure (East US region).

| Property | Detail |
|----------|--------|
| **Cloud provider** | Microsoft Azure |
| **Primary region** | East US |
| **Database** | Azure Database for PostgreSQL Flexible Server |
| **Container runtime** | Azure Container Apps |

For enterprise customers with specific regulatory or compliance requirements, regional deployment options (such as EU or APAC regions) can be supported based on customer needs. Data residency, localization, and region-specific compliance requirements can be discussed and configured during the onboarding process.

Contact security@auditgraph.ai to discuss data residency requirements.

---

## Shared Responsibility Model

**Who is responsible for what?**

AuditGraph follows a shared responsibility model that clearly defines security ownership between the platform and its customers.

**AuditGraph is responsible for:**

- Platform infrastructure and application security
- Data encryption and tenant isolation
- API security, authentication, and authorization controls
- Platform availability, monitoring, and incident response

**Customers are responsible for:**

- Secure configuration of cloud connectors (least privilege permissions, credential rotation)
- Identity and access policies within their cloud environments
- Credential rotation and least privilege enforcement for monitored identities
- Monitoring and remediation of identified identity risks

This model ensures clear accountability and aligns with standard cloud security practices (aligned with industry-standard cloud shared responsibility models (AWS, Azure, GCP)).

---

## Data Collected vs. Not Collected

| Collected by AuditGraph | Not Collected by AuditGraph |
|--------------------------|------------------------------|
| Identity display names and IDs | Application data or databases |
| Role assignments (RBAC, Entra, IAM) | File contents or blob data |
| Credential expiration dates and key IDs | Actual secret values or passwords |
| Ownership relationships | Customer business data |
| Sign-in timestamps and activity status | Email or chat messages |
| Resource names and security configuration | Network traffic or packet data |
| Conditional access policy metadata | Source code or application logs |
| PIM eligible assignments and activations | Financial or PII records |

AuditGraph uses read-only API calls exclusively. It does not create, modify, or delete any resources in customer cloud environments. The only exception is the opt-in auto-remediation feature, which requires explicit admin approval and simulates actions by default before execution.

AuditGraph operates in read-only mode by default. It does not create, modify, or delete resources in customer environments unless explicitly enabled via opt-in remediation workflows with administrative approval.

---

## Authentication and SSO

**Does AuditGraph support single sign-on?**

Yes. AuditGraph supports two SSO protocols and multiple enterprise identity providers.

| Protocol | Implementation |
|----------|---------------|
| **OIDC (OpenID Connect)** | RS256 signature verification via JWKS endpoint with 600-second cache. Supports Azure AD, Okta, and Google Workspace. |
| **SAML 2.0** | Signed assertion requirement via python3-saml. Supports any SAML-compliant identity provider. |

**SSO features:**

| Feature | Support |
|---------|---------|
| Just-in-time provisioning | Users are automatically created on first SSO login |
| IdP group-to-role mapping | IdP group memberships map to AuditGraph RBAC roles |
| Force-SSO mode | Disables local password login, requiring all users to authenticate via SSO |
| Per-organization configuration | Each tenant can configure its own SSO provider independently |

**RBAC enforcement:**

All API endpoints enforce role-based access control. The client portal provides 8 roles (owner, admin, security_admin, compliance, auditor, analyst, viewer, reader) and the admin portal provides 4 roles (superadmin, poweradmin, billing, reader). Roles are enforced via decorator-based middleware on every endpoint.

See [Security Architecture](../security-architecture.md) for the complete authentication model and RBAC hierarchy.

### Session Security

| Control | Implementation |
|---------|---------------|
| **Access token lifetime** | 30 minutes (admin portal) / 60 minutes (client portal) |
| **Refresh token lifetime** | 7 days with single-use rotation |
| **Token validation** | Every API request validates JWT signature, expiration, and tenant claims before processing |
| **Invalid token handling** | Expired, malformed, or tampered tokens are immediately rejected with 401 Unauthorized |
| **Portal separation** | Admin and client portals use independent signing keys; tokens from one portal cannot authenticate to the other |

Short-lived access tokens limit the window of exposure if a token is compromised. Refresh tokens are rotated on each use, and previously used refresh tokens are invalidated to prevent replay attacks.

---

## Tenant Isolation

**How are customers isolated from each other?**

AuditGraph enforces tenant isolation through five independent layers. The foundational control is PostgreSQL Row Level Security, which prevents cross-tenant data access at the database layer — even if application-level logic contains a bug.

| Layer | Mechanism | Protection |
|-------|-----------|-----------|
| **1. Authentication** | JWT with `organization_id` claim | Requests without a valid token are rejected before any data access |
| **2. Tenant context** | `SET LOCAL app.current_tenant_id` | Transaction-scoped context that cannot persist or leak between requests |
| **3. Connector isolation** | Connectors scoped to owning org | Discovery data inherits the connector's tenant boundary |
| **4. Row Level Security** | RLS policies on 44 tables | Every SELECT, INSERT, UPDATE, DELETE is filtered by `organization_id` |
| **5. Database role separation** | `auditgraph_app` (NOBYPASSRLS) | The application database user cannot bypass RLS under any circumstances |

**Additional safety mechanisms:**

- Connection pool resets tenant context on both checkout and return
- Flask teardown hook ensures cleanup even if request handlers raise exceptions
- Admin guard blocks unscoped database calls inside request handlers
- `TENANT_CONTEXT_VIOLATION` security events are logged for any attempted unscoped access

See [Data Protection and Tenant Isolation](data-protection.md) for the complete isolation model and safety layer documentation.

---

## Encryption

**How does AuditGraph protect sensitive data?**

### Data in Transit

| Control | Implementation |
|---------|---------------|
| **Transport encryption** | TLS 1.3 on all client-to-API connections |
| **HSTS** | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` |
| **Certificate management** | Azure-managed TLS certificates for all `*.auditgraph.ai` domains |

### Data at Rest

| Control | Implementation |
|---------|---------------|
| **Algorithm** | Fernet symmetric encryption (AES-128-CBC for confidentiality, HMAC-SHA256 for integrity) |
| **Scope** | All cloud connector credentials (Azure client secrets, AWS secret keys, GCP service account keys) |
| **Identification** | Encrypted values carry an `enc:` prefix |
| **Key rotation** | MultiFernet supports multiple active keys for zero-downtime rotation |

### Credential Protection

| Practice | Implementation |
|----------|---------------|
| **Immediate encryption** | Credentials are encrypted on receipt before database storage |
| **No plaintext storage** | Encrypted values only; legacy plaintext detected by absence of `enc:` prefix |
| **No API exposure** | Credential values are never returned in API responses |
| **Minimal decryption** | Secrets are decrypted only at discovery time, used for API calls, then discarded |
| **Log redaction** | Passwords, tokens, API keys, and secrets are automatically redacted from all log output |

AuditGraph never persists decrypted secrets. Credentials are decrypted only in memory during discovery operations, used for short-lived API calls to cloud providers, and immediately discarded. Decrypted values are never written to logs, API responses, or persistent storage.

Encryption keys are managed via environment-secured configuration and are never stored in source code or persisted alongside encrypted data.

See [Data Protection and Tenant Isolation](data-protection.md) for key rotation procedures and the complete credential lifecycle.

---

## API Security

**What protections are implemented on the API layer?**

| Control | Implementation | Threat Mitigated |
|---------|---------------|-----------------|
| **Rate limiting** | Sliding window on authentication endpoints (5-20 requests/minute) | Brute-force attacks, credential stuffing |
| **JSON schema validation** | Request body validation on 10+ mutation endpoints | Malformed input, unexpected data types |
| **Input sanitization** | Pattern detection for XSS, SQL injection, and command injection | Injection attacks |
| **Idempotency keys** | `Idempotency-Key` header with 24-hour deduplication cache | Duplicate operations from network retries |
| **Request size limits** | 5 MB maximum content length | Memory exhaustion, denial-of-service |
| **Security headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Clickjacking, content injection, MIME sniffing |
| **CORS** | Strict origin checking configured per environment | Cross-origin request forgery |
| **Circuit breakers** | 3 independent breakers for external API dependencies | Cascading failures from upstream outages |

**Password policy:** 12+ characters with uppercase, lowercase, digit, and special character requirements. Common passwords are blocked via a built-in blocklist.

See [Security Features](../security-features.md) for rate limiting thresholds, validation schemas, and circuit breaker configuration.

---

## Availability and Reliability

**How does AuditGraph ensure service availability?**

AuditGraph is designed for high availability and operational resilience. The platform architecture supports consistent performance under load and graceful degradation during upstream service disruptions.

**Architectural characteristics:**

| Characteristic | Implementation |
|---------------|---------------|
| **Stateless API services** | Gunicorn workers behind Azure Container Apps support horizontal scaling |
| **Circuit breakers** | 3 independent breakers (Graph API, AWS API, LLM API) prevent cascading failures from external dependencies |
| **Retry logic** | Exponential backoff via tenacity (2-3 attempts per service) for transient failures |
| **Connection pooling** | ThreadedConnectionPool with configurable min/max connections and failover support |
| **Health monitoring** | 6 health endpoints (liveness, readiness, detailed, system, SLA, metrics) with 30-second check intervals |
| **Zombie detection** | 20-second heartbeats during discovery runs detect and recover stalled processes |

**Target service level objectives (SLOs):**

| Metric | Target |
|--------|--------|
| **Uptime** | 99.9% for production environments |
| **API latency (p95)** | < 500ms for identity query endpoints |
| **Discovery completion** | < 10 minutes for deep scans (1,000 identities) |

These controls help ensure consistent performance and resilience under load and during upstream service disruptions.

### Backup and Recovery

AuditGraph implements backup and recovery procedures to ensure data durability and service continuity.

| Control | Implementation |
|---------|---------------|
| **Automated backups** | Daily backups of PostgreSQL databases managed by Azure Flexible Server |
| **Point-in-time recovery** | PITR capabilities allow restoration to any point within the backup retention window |
| **Retention alignment** | Backup retention is aligned with configured data retention policies per data type |
| **Recovery validation** | Recovery procedures are periodically tested to validate data integrity and restoration processes |

See [Operations](../operations.md) for health endpoint details, monitoring configuration, and troubleshooting procedures.

---

## Compliance Frameworks

**Which compliance frameworks does AuditGraph support?**

AuditGraph maps identity findings to the following frameworks and computes compliance scores after each discovery scan:

| Framework | Version | Coverage Area |
|-----------|---------|--------------|
| **SOC 2 Type II** | 2017 | Access control, monitoring, encryption, change management |
| **ISO 27001** | 2022 | Identity management, access rights, cryptography, logging |
| **NIST 800-53** | Rev 5 | Account management, least privilege, audit events, risk assessment |
| **NIST CSF** | 2.0 | Identify, Protect, Detect, Respond, Recover functions |
| **CIS Benchmarks** | v2.0 | 33 checks across Azure, AWS, and GCP |
| **Azure Security Benchmark** | v3 | Identity management, privileged access, data security |
| **AWS Security Best Practices** | Current | IAM hygiene, credential rotation, policy management |
| **HIPAA / PCI-DSS / SOX** | Current | Access controls, encryption, audit trails |

**Continuous compliance monitoring:**

AuditGraph provides continuous identity posture monitoring rather than point-in-time audits. After each discovery scan (default every 12 hours), the platform recomputes compliance scores, evaluates CIS benchmark controls, and updates the compliance dashboard. Security teams can track posture trends over time and generate audit evidence on demand via API or PDF export.

See [Compliance Mapping](../compliance.md) for control-level mapping tables, evidence export endpoints, and audit preparation checklists.

---

## Auditability and Evidence

**How does AuditGraph support audit evidence requirements?**

AuditGraph generates auditable records across every layer of its operation. These records support evidence requirements for SOC 2 Type II, ISO 27001, NIST 800-53, and enterprise internal audit programs.

| Evidence Type | Source | Retention | Export |
|--------------|--------|-----------|--------|
| **Discovery snapshots** | Cryptographically signed (SHA-256 hash + HMAC signature) per discovery run | Configurable (default 90 days) | `GET /api/runs` |
| **Identity drift history** | Side-by-side comparison of consecutive snapshots, tracking role changes, credential additions, and identity lifecycle events | Configurable (default 90 days) | `GET /api/drift/history` |
| **Security events** | 12+ structured event types covering authentication, authorization, tenant context, encryption, and rate limiting | 180 days | `GET /api/activity` |
| **Anomaly detection records** | 8 behavioral anomaly types with severity, affected identity, and resolution tracking | Configurable (default 180 days) | `GET /api/anomalies` |
| **Compliance scores** | Per-framework scores recomputed after each discovery scan | Retained with discovery runs | `GET /api/dashboard/compliance` |
| **Full audit reports** | Comprehensive identity posture data formatted for PDF generation | On demand | `GET /api/reports/data` |

**Snapshot integrity:** Each discovery snapshot includes a SHA-256 hash of its metadata and an HMAC signature using the platform key. This enables tamper detection — if any snapshot data is modified after discovery, the integrity check fails. Integrity can be verified via `GET /api/system/integrity-check`.

**Evidence automation:** Create a `viewer`-role API key with scoped expiration to automate periodic evidence collection for audit preparation.

---

## Security Testing

**How is the platform tested for security vulnerabilities?**

AuditGraph undergoes regular security validation to ensure the integrity of its authentication, authorization, and data protection controls.

**Current security testing practices:**

| Practice | Implementation |
|----------|---------------|
| **Static code analysis** | Bandit (Python security linter) configured in pyproject.toml with targeted rule skips (B101/B104) |
| **Code linting** | Ruff configured with E, F, W, I, N, UP, B, C4 rule sets for code quality and common bug detection |
| **Type checking** | MyPy configured with `warn_return_any` for type safety enforcement |
| **Dependency scanning** | pip-audit in CI/CD guardrail tests to detect known vulnerabilities in third-party packages |
| **Unit tests** | 41 tests covering encryption, input validation, rate limiting, circuit breakers, OIDC verification, and security event generation |
| **Manual security review** | Authentication flows, RBAC enforcement, RLS tenant isolation, and credential handling reviewed on every significant change |

**Roadmap:**

Formal third-party penetration testing and external security assessments are planned as part of upcoming compliance initiatives, including SOC 2 Type II certification. Results will be made available to enterprise customers under NDA upon request.

See [Security Posture](../security-posture.md) for the platform's security maturity self-assessment.

---

## Internal Access Controls

**How does AuditGraph control access to production systems?**

Access to AuditGraph production systems is strictly controlled and follows the principle of least privilege.

| Control | Implementation |
|---------|---------------|
| **Role-based access** | Internal engineers and operators are assigned roles scoped to specific responsibilities |
| **Need-based access** | Production access is granted only when required and revoked when no longer needed |
| **Audit trail** | All administrative actions on production systems are logged and monitored |
| **Periodic review** | Access permissions are reviewed periodically to ensure continued appropriateness |
| **Separation of duties** | Database admin credentials (`BYPASSRLS`) are restricted to system operations and are not used by application code |

This approach reduces the risk of unauthorized access and supports audit and compliance requirements.

---

## Logging and Monitoring

**How does AuditGraph track security events?**

AuditGraph records structured security events for every security-relevant platform operation.

**Security event example:**

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

**Monitoring capabilities:**

| Capability | Description |
|-----------|-------------|
| **Security event logging** | 12+ structured event types covering authentication, authorization, tenant context, rate limiting, encryption, and query performance |
| **Anomaly detection** | 8 behavioral detection types: permission escalation, risk score spike, dormant reactivation, credential surge, off-hours PIM, excessive PIM, impossible travel, auth failure burst |
| **Identity drift monitoring** | Automatic comparison of consecutive discovery snapshots detecting new/removed identities, role changes, and credential modifications |
| **Audit evidence export** | JSON via API, CSV from UI, PDF reports, and dedicated API key access for automated evidence collection |
| **Log redaction** | Automatic redaction of passwords, tokens, API keys, and secrets from all log output |
| **SIEM integration** | Structured JSON format compatible with Splunk, Datadog, Azure Monitor, and Elastic |

Events support forensic investigation, audit reporting, and real-time alerting via Slack and Teams webhook integrations.

See [Data Protection and Tenant Isolation](data-protection.md) for the complete event type catalog and evidence export procedures.

---

## Contact for Security Reviews

For enterprise security reviews, vendor assessment questionnaires, or additional security documentation requests, contact the AuditGraph security team:

**Email:** security@auditgraph.ai

**What to include:**

- Your organization name and contact information
- The questionnaire format (SIG, CAIQ, custom template)
- Specific compliance frameworks or security domains of interest
- Timeline for the assessment

The AuditGraph team provides dedicated support for enterprise security evaluations, including pre-populated questionnaire responses, architecture review sessions, and supplementary documentation.

---

## Vulnerability Disclosure

**How should security vulnerabilities be reported?**

AuditGraph supports responsible vulnerability disclosure. If you discover a security issue, report it directly to the security team.

| Property | Detail |
|----------|--------|
| **Report to** | security@auditgraph.ai |
| **Subject line** | `[SECURITY] Brief description of the issue` |
| **Acknowledgment** | Within 2 business days |
| **Initial assessment** | Within 5 business days |
| **Coordination** | AuditGraph works with reporters to validate findings and agree on disclosure timelines |
| **Recognition** | Reporters are credited (with permission) in release notes |

**What to include in a report:**

- Description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept preferred)
- Affected component or endpoint
- Your preferred contact method for follow-up

**Penetration testing coordination:**

Enterprise customers who wish to conduct penetration testing against their AuditGraph environment should contact security@auditgraph.ai in advance to coordinate testing windows and scope. This ensures testing does not trigger rate limiting or circuit breaker protections that could affect other tenants.

---

## References

- [Security Overview](overview.md) -- Executive-level platform security summary
- [Data Protection and Tenant Isolation](data-protection.md) -- Encryption, RLS, credential storage
- [Security Architecture](../security-architecture.md) -- Authentication, RBAC, full 7-layer model
- [Security Features](../security-features.md) -- Rate limiting, circuit breakers, security events
- [Compliance Mapping](../compliance.md) -- Framework control mappings and audit evidence
- [Security Posture](../security-posture.md) -- Platform security maturity scorecard
- [FAQ](../faq.md) -- General platform questions
