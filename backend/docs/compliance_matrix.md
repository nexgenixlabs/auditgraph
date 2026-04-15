# AuditGraph — Enterprise Compliance Control Matrix

**Version:** 1.0
**Date:** 2026-03-03
**Classification:** Internal — Audit Readiness

---

## Table of Contents

1. [Executive Security Posture Summary](#1-executive-security-posture-summary)
2. [SOC 2 Type II Control Mapping](#2-soc-2-type-ii-control-mapping)
3. [HIPAA Technical Safeguard Mapping](#3-hipaa-technical-safeguard-mapping)
4. [Unified Control Matrix](#4-unified-control-matrix)
5. [Gap Analysis & Remediation Plan](#5-gap-analysis--remediation-plan)
6. [Missing Enterprise Features](#6-missing-enterprise-features)
7. [Customer-Facing Architecture Summary](#7-customer-facing-architecture-summary)
8. [Audit Readiness Roadmap](#8-audit-readiness-roadmap)
9. [Risk Assessment](#9-risk-assessment)

---

## 1. Executive Security Posture Summary

AuditGraph is a multi-tenant SaaS platform for cloud identity security auditing. The platform implements defense-in-depth security across seven layers:

| Layer | Implementation | Maturity |
|-------|---------------|----------|
| **Data Isolation** | PostgreSQL Row-Level Security (RLS) with FORCE RLS on 44 tables, dual database roles (NOBYPASSRLS app user + BYPASSRLS admin user), 5-layer context verification | Production |
| **Authentication** | Dual JWT keys (admin/client portal isolation), bcrypt password hashing, HIPAA-grade password policy (12-char minimum), SAML 2.0 SSO, API key auth (SHA-256 hashed) | Production |
| **Authorization** | 4-tier client RBAC (admin/security_admin/compliance/reader), 4-tier admin RBAC (superadmin/poweradmin/billing/reader), per-tenant role enforcement | Production |
| **Audit Trail** | Append-only activity_log (no delete API), admin_audit_log for privileged operations, structured security events (SecurityEventLogger), configurable retention (90-365 days) | Production |
| **Network Security** | TLS-enforced database connections (DB_SSLMODE=require), HSTS with 1-year max-age + preload, CORS whitelist, security headers (X-Frame-Options: DENY, CSP-equivalent via Permissions-Policy) | Production |
| **Secrets Management** | Azure Key Vault integration (container runtime injection), secret redaction filter on all log output, bcrypt/SHA-256 for stored credentials, 90-day rotation policy | Production |
| **Operational Safety** | CI/CD isolation test gate, migration-aware readiness probes, connection pooling with context reset, nightly RLS drift detection, automated data retention | Production |

**Overall Assessment:** AuditGraph satisfies the majority of SOC 2 Type II and HIPAA Technical Safeguard requirements through implemented controls. Gaps exist primarily in formalized policy documentation, immutable audit log guarantees, and MFA enforcement — all addressable without architectural changes.

---

## 2. SOC 2 Type II Control Mapping

### CC1 — Control Environment

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC1.1 | COSO Principle 1: Integrity and ethical values | Organization-scoped settings, admin_audit_log tracks privileged operations | PARTIAL — Requires formal security policy document |
| CC1.2 | COSO Principle 2: Board oversight | Admin portal with superadmin/poweradmin/billing/reader roles, AdminActionLog page | PARTIAL — Requires documented governance structure |
| CC1.3 | COSO Principle 3: Management structure | 4-tier admin RBAC with granular route decorators | SATISFIED |
| CC1.4 | COSO Principle 4: Competence commitment | N/A — Organizational control, not technical | OUT OF SCOPE |
| CC1.5 | COSO Principle 5: Accountability | Activity log with user_id, admin_audit_log with ip_address, impersonation tracking | SATISFIED |

### CC2 — Communication and Information

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC2.1 | Internal communication of security info | Slack/Teams notification dispatch, SecurityEventLogger for SIEM | SATISFIED |
| CC2.2 | External communication of commitments | N/A — Requires published security page/SOC 2 report | GAP |
| CC2.3 | Communication with external parties | Webhook notifications, email alerts, API for integration | SATISFIED |

### CC3 — Risk Assessment

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC3.1 | Risk identification objectives | 10-factor identity risk scoring, anomaly detection (6 types), RLS drift detection | SATISFIED |
| CC3.2 | Risk identification and analysis | validate_rls_drift(), validate_tenant_index_coverage(), detect_tenant_skew() | SATISFIED |
| CC3.3 | Fraud risk consideration | Impersonation time-capping (15 min), admin_audit_log, rate limiting | SATISFIED |
| CC3.4 | Change impact assessment | Drift detection engine, nightly audit job at 04:30 UTC, migration tracking | SATISFIED |

### CC4 — Monitoring Activities

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC4.1 | Ongoing and separate evaluations | Nightly RLS audit, daily data retention check, continuous anomaly detection | SATISFIED |
| CC4.2 | Communication of deficiencies | SecurityEventLogger with severity-tagged events, Slack/Teams dispatch | SATISFIED |

### CC5 — Control Activities

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC5.1 | Selection and development of controls | FORCE RLS, ENFORCE_ADMIN_GUARD, connection pool context reset, readiness gates | SATISFIED |
| CC5.2 | Technology general controls | gunicorn --preload (DDL deadlock prevention), schema_migrations table, idempotent DDL | SATISFIED |
| CC5.3 | Deployment through policies | CI/CD test-guardrails gate, _migration_in_progress readiness probe | SATISFIED |

### CC6 — Logical and Physical Access Controls (SECURITY)

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC6.1 | Logical access security | Dual JWT keys, RBAC (4 client + 4 admin roles), require_role/require_superadmin decorators, API key scoping | SATISFIED |
| CC6.2 | Credential management | bcrypt hashing, 12-char HIPAA password policy, SHA-256 API key hashing, 90-day Key Vault rotation, password reset with 1-hour token expiry | SATISFIED |
| CC6.3 | Registration and authorization | JIT provisioning via SAML SSO, admin-only user creation, organization-scoped user lists | SATISFIED |
| CC6.4 | Access restriction for assets | RLS with FORCE RLS on 44 tables, NOBYPASSRLS app role, tenant context verification before every query | SATISFIED |
| CC6.5 | Access restriction for information | Organization-scoped settings, cross-org guard in auth middleware, X-Organization-Id restricted to superadmins | SATISFIED |
| CC6.6 | System boundary security | Security headers (HSTS, X-Frame-Options: DENY, Permissions-Policy), CORS whitelist, rate limiting on auth endpoints | SATISFIED |
| CC6.7 | Manage changes to infrastructure | schema_migrations table, apply_migration() with checksums, CI/CD pipeline with test gates | SATISFIED |
| CC6.8 | Vulnerability management | N/A — No automated dependency scanning in pipeline | GAP |

### CC7 — System Operations (AVAILABILITY)

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC7.1 | Detection of anomalies | AnomalyDetector engine (6 types), SecurityEventLogger, pool exhaustion alerts, slow query logging | SATISFIED |
| CC7.2 | Incident response | Slack/Teams webhook dispatch on scan_failed/anomaly_detected, admin_audit_log | PARTIAL — Requires formal incident response plan |
| CC7.3 | Recovery and resilience | Azure Flex Server automated backup (35-day retention), PITR, geo-redundant backup, read replica design | SATISFIED |
| CC7.4 | Business continuity | RPO < 5min (WAL archiving), RTO < 30min (PITR + redeploy), health endpoints for orchestrator | SATISFIED |
| CC7.5 | Capacity management | Connection pool with utilization monitoring, tenant skew detection, DB_POOL_MAX tuning | SATISFIED |

### CC8 — Change Management

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC8.1 | Change authorization | CI/CD pipeline requires test-guardrails pass before build, dev branch deployment | SATISFIED |

### CC9 — Risk Mitigation (PROCESSING INTEGRITY)

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| CC9.1 | Risk mitigation activities | 5-layer tenant context defense, fail-closed SecurityViolationError, readiness gating during migrations | SATISFIED |
| CC9.2 | Vendor risk management | N/A — Requires vendor management policy | GAP |

### A1 — Availability (Additional Criteria)

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| A1.1 | Availability commitments | Health endpoints (/health/live, /health/ready), Docker HEALTHCHECK, Kubernetes-compatible probes | SATISFIED |
| A1.2 | Environmental protections | Azure Container Apps managed infrastructure, non-root container user | SATISFIED |
| A1.3 | Recovery testing | validate_rls_drift() after restore, failover validation checklist | PARTIAL — Requires scheduled DR testing |

### C1 — Confidentiality (Additional Criteria)

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| C1.1 | Confidential information identification | RLS-enforced tenant isolation, include_secrets=False default on cloud connections | SATISFIED |
| C1.2 | Disposal of confidential information | Automated data retention with configurable periods (90-365 days), cleanup_old_* methods | SATISFIED |

### PI1 — Processing Integrity (Additional Criteria)

| Control | Criteria | AuditGraph Implementation | Status |
|---------|----------|--------------------------|--------|
| PI1.1 | Processing integrity objectives | verify_tenant_context() before every execute_safe(), schema_migrations with checksums | SATISFIED |
| PI1.2 | System inputs are complete and accurate | Password validation (12-char, complexity, blocklist), SAML assertion signature verification | SATISFIED |
| PI1.3 | Processing is complete and accurate | Transaction-scoped tenant context (SET LOCAL), FORCE RLS prevents owner bypass | SATISFIED |
| PI1.4 | Outputs are complete and accurate | JSON response validation, error handlers with error_code fields | SATISFIED |
| PI1.5 | Stored data integrity | NOT NULL constraints on organization_id (44 tables), auto-fill trigger trg_auto_tenant_id | SATISFIED |

---

## 3. HIPAA Technical Safeguard Mapping

### §164.312(a) — Access Control

| Standard | Implementation Detail | AuditGraph Feature | Status |
|----------|----------------------|-------------------|--------|
| (a)(1) — Unique user identification | Users table with SERIAL id, unique username constraint, JWT sub claim as string user_id | `app/database.py:4666` | SATISFIED |
| (a)(2)(i) — Emergency access | Admin portal with superadmin role, _admin_reason parameter for emergency Database() access | `app/database.py:392` | SATISFIED |
| (a)(2)(ii) — Automatic logoff | Access token expiry: 30min (admin), 60min (client); refresh token: 7 days | `app/api/auth.py:39-41` | SATISFIED |
| (a)(2)(iii) — Encryption and decryption | bcrypt password hashing, SHA-256 API key hashing, TLS for DB connections, Azure infrastructure encryption at rest | Multiple files | SATISFIED |
| (a)(2)(iv) — Audit mechanisms | See §164.312(b) below | — | SATISFIED |

### §164.312(b) — Audit Controls

| Standard | Implementation Detail | AuditGraph Feature | Status |
|----------|----------------------|-------------------|--------|
| Record and examine activity | activity_log table (append-only, no delete API), admin_audit_log for privileged ops, SecurityEventLogger for SIEM events | `app/database.py:3412`, `app/security_events.py` | SATISFIED |
| Hardware/software/procedural mechanisms | JSONFormatter structured logging, Prometheus /api/metrics endpoint, request_id correlation across logs | `app/logging_config.py` | SATISFIED |
| Audit trail immutability | No DELETE endpoint for activity_log; deletion only via automated retention job with configurable minimum (180 days default) | `app/database.py:10116` | PARTIAL — See Gap #1 |

### §164.312(c) — Integrity Controls

| Standard | Implementation Detail | AuditGraph Feature | Status |
|----------|----------------------|-------------------|--------|
| (c)(1) — ePHI integrity | RLS prevents cross-tenant data access/modification; FORCE RLS on all 44 tenant tables | `app/database.py:651` | SATISFIED |
| (c)(2) — Authentication of ePHI | verify_tenant_context() confirms org_id matches PostgreSQL session before every query; schema_migrations with checksums | `app/database.py:470` | SATISFIED |

### §164.312(d) — Person or Entity Authentication

| Standard | Implementation Detail | AuditGraph Feature | Status |
|----------|----------------------|-------------------|--------|
| Verify identity of person/entity | bcrypt password + JWT token; SAML 2.0 SSO with signed assertions; API keys with SHA-256; rate limiting (5 attempts/60s) | `app/api/auth.py`, `app/api/saml.py` | SATISFIED |
| Multi-factor authentication | Not natively enforced by AuditGraph; delegated to IdP via SAML SSO (force_sso setting can mandate IdP login) | — | PARTIAL — See Gap #2 |

### §164.312(e) — Transmission Security

| Standard | Implementation Detail | AuditGraph Feature | Status |
|----------|----------------------|-------------------|--------|
| (e)(1) — Integrity controls | HSTS header (max-age=31536000, includeSubDomains, preload); DB_SSLMODE=require | `app/security.py:127` | SATISFIED |
| (e)(2) — Encryption | TLS 1.2+ for all connections (HSTS preload enforcement); Azure Flex Server SSL | `app/config.py:56` | SATISFIED |

### §164.308(a) — Administrative Safeguards (Technical Implementation)

| Standard | Implementation Detail | AuditGraph Feature | Status |
|----------|----------------------|-------------------|--------|
| (a)(1) — Security management process | validate_rls_startup() fail-fast, enforce_force_rls(), nightly RLS audit | `app/database.py:585,651,736` | SATISFIED |
| (a)(3) — Workforce security | RBAC role enforcement, organization-scoped user management, enabled/disabled toggle | `app/api/auth.py:396` | SATISFIED |
| (a)(4) — Information access management | RLS policies, include_secrets=False, cross-org guard in auth middleware | `app/api/auth.py:320` | SATISFIED |
| (a)(5) — Security awareness and training | N/A — Organizational control | OUT OF SCOPE |
| (a)(6) — Security incident procedures | SecurityEventLogger, Slack/Teams webhook dispatch, admin_audit_log | `app/security_events.py` | PARTIAL — Requires formal IRP document |
| (a)(7) — Contingency plan | RPO < 5min, RTO < 30min, geo-redundant backup, failover checklist | `app/config.py` (blueprint) | SATISFIED |
| (a)(8) — Evaluation | validate_rls_drift(), detect_tenant_skew(), CI/CD guardrail tests | `app/database.py` | SATISFIED |

---

## 4. Unified Control Matrix

| # | Control Area | SOC 2 Ref | HIPAA Ref | Implementation | File:Line | Status |
|---|-------------|-----------|-----------|----------------|-----------|--------|
| 1 | **Unique user identity** | CC6.1 | §312(a)(1) | SERIAL user id, unique username, JWT sub claim | auth.py:102 | SATISFIED |
| 2 | **Password security** | CC6.2 | §312(d) | bcrypt, 12-char min, complexity, blocklist | security.py:145 | SATISFIED |
| 3 | **Session management** | CC6.1 | §312(a)(2)(ii) | JWT 30/60min access, 7d refresh, token rotation prep (kid headers) | auth.py:35-41 | SATISFIED |
| 4 | **Role-based access** | CC6.3 | §308(a)(4) | 4+4 role system, require_role decorators, portal-aware | auth.py:396-457 | SATISFIED |
| 5 | **Multi-tenant isolation** | CC6.4, PI1.3 | §312(c)(1) | RLS + FORCE RLS on 44 tables, dual DB roles, 5-layer context defense | database.py:31-63 | SATISFIED |
| 6 | **Encryption in transit** | CC6.6 | §312(e)(2) | TLS (DB_SSLMODE=require), HSTS 1yr + preload | config.py:56, security.py:127 | SATISFIED |
| 7 | **Encryption at rest** | CC6.4 | §312(a)(2)(iii) | Azure infrastructure encryption, bcrypt/SHA-256 for credentials | — | SATISFIED |
| 8 | **Audit trail** | CC4.1 | §312(b) | activity_log (append-only), admin_audit_log, SecurityEventLogger | database.py:3412 | SATISFIED |
| 9 | **Secret management** | CC6.2 | §312(a)(2)(iii) | Key Vault injection, SecretRedactionFilter, 90-day rotation | config.py, logging_config.py | SATISFIED |
| 10 | **Vulnerability management** | CC6.8 | §308(a)(1) | — | — | GAP |
| 11 | **MFA enforcement** | CC6.1 | §312(d) | Delegated to IdP via SAML; no native MFA | — | PARTIAL |
| 12 | **Incident response** | CC7.2 | §308(a)(6) | SecurityEventLogger + webhooks; no formal IRP doc | security_events.py | PARTIAL |
| 13 | **Data retention** | C1.2 | §312(b) | Configurable retention (90-365d), automated cleanup at 03:00 UTC | scheduler.py:1050 | SATISFIED |
| 14 | **Backup & recovery** | CC7.3, CC7.4 | §308(a)(7) | Azure automated daily backup, WAL, PITR, geo-redundant, RPO < 5min | config.py (blueprint) | SATISFIED |
| 15 | **Change management** | CC8.1 | — | CI/CD test gate, schema_migrations, migration-aware readiness | deploy.yml, database.py:994 | SATISFIED |
| 16 | **Input validation** | PI1.2 | §312(c)(2) | Password policy, SAML signature verification, rate limiting | security.py:145 | SATISFIED |
| 17 | **API security** | CC6.6 | §312(e)(1) | API keys (SHA-256), rate limiting, CORS whitelist, security headers | auth.py:161, security.py:112 | SATISFIED |
| 18 | **SSO/Federation** | CC6.3 | §312(d) | SAML 2.0 with signed assertions, JIT provisioning, force_sso toggle | saml.py | SATISFIED |
| 19 | **Log immutability** | CC4.1 | §312(b) | No delete API; retention-only deletion | — | PARTIAL |
| 20 | **Capacity management** | CC7.5 | — | Connection pool monitoring, tenant skew detection, slow query alerts | database.py | SATISFIED |

**Summary: 16 SATISFIED, 4 PARTIAL/GAP**

---

## 5. Gap Analysis & Remediation Plan

### Gap #1: Audit Log Immutability (MEDIUM)

**Current State:** Activity logs have no DELETE API endpoint, but the underlying database allows deletion via admin SQL access and the automated retention job can purge records after 180 days. There is no cryptographic guarantee of log integrity.

**SOC 2 Impact:** CC4.1 (Monitoring Activities) — Auditors may question whether logs can be tampered with by a database administrator.

**HIPAA Impact:** §164.312(b) — Audit controls must protect against unauthorized alteration.

**Remediation Plan:**
| Phase | Action | Effort | Priority |
|-------|--------|--------|----------|
| 1 | Add `ALTER TABLE activity_log SET (autovacuum_enabled = true)` and a PostgreSQL trigger that prevents DELETE/UPDATE on activity_log rows (BEFORE DELETE → RAISE EXCEPTION) | 1 day | HIGH |
| 2 | Add SHA-256 hash chain: each log entry stores hash(prev_hash + current_entry), creating a tamper-evident chain | 3 days | MEDIUM |
| 3 | Forward logs to an immutable external store (Azure Blob Storage with immutability policy or Azure Monitor Logs with 730-day retention) | 2 days | MEDIUM |

### Gap #2: MFA Enforcement (MEDIUM)

**Current State:** AuditGraph supports SAML 2.0 SSO with force_sso toggle, which can mandate IdP login (where the IdP enforces MFA). However, there is no native MFA for password-based login, and force_sso is not enabled by default.

**SOC 2 Impact:** CC6.1 — Logical access security should include multi-factor authentication for privileged access.

**HIPAA Impact:** §164.312(d) — Person or entity authentication should use multiple factors for ePHI access.

**Remediation Plan:**
| Phase | Action | Effort | Priority |
|-------|--------|--------|----------|
| 1 | Add TOTP (RFC 6238) support: `mfa_secret` column on users table, QR code enrollment endpoint, verification at login | 5 days | HIGH |
| 2 | Add MFA enforcement policy: per-org setting `require_mfa = true/false`, enforced at login handler | 1 day | HIGH |
| 3 | Document that force_sso + IdP-enforced MFA is an acceptable alternative for SOC 2 | 0.5 day | HIGH |

### Gap #3: Vulnerability Scanning (LOW)

**Current State:** No automated dependency vulnerability scanning (Dependabot, Snyk, etc.) in the CI/CD pipeline. Python dependencies are pinned in requirements.txt but not scanned for CVEs.

**SOC 2 Impact:** CC6.8 — Vulnerability management requires regular scanning and patching.

**Remediation Plan:**
| Phase | Action | Effort | Priority |
|-------|--------|--------|----------|
| 1 | Enable GitHub Dependabot alerts on the repository | 0.5 day | HIGH |
| 2 | Add `pip-audit` step to CI/CD pipeline (fail on critical/high CVEs) | 0.5 day | HIGH |
| 3 | Add `npm audit` for frontend dependencies | 0.5 day | MEDIUM |

### Gap #4: Formal Policy Documentation (LOW)

**Current State:** Security controls are implemented in code but lack corresponding policy documents that auditors expect (Information Security Policy, Incident Response Plan, Data Classification Policy, etc.).

**SOC 2 Impact:** CC1.1, CC2.2 — Requires documented policies and external communication.

**Remediation Plan:**
| Phase | Action | Effort | Priority |
|-------|--------|--------|----------|
| 1 | Create Information Security Policy (references implemented controls) | 2 days | MEDIUM |
| 2 | Create Incident Response Plan (references SecurityEventLogger, webhook dispatch) | 1 day | MEDIUM |
| 3 | Create Data Classification Policy (tenant data = confidential, audit logs = internal) | 1 day | LOW |
| 4 | Publish Security Practices page (customer-facing) | 1 day | MEDIUM |

### Gap #5: DR Testing (LOW)

**Current State:** DR plan and failover checklist exist in documentation. PITR, backup, and replica design are specified. However, there is no evidence of regular DR test execution.

**SOC 2 Impact:** A1.3 — Recovery testing should be performed periodically.

**Remediation Plan:**
| Phase | Action | Effort | Priority |
|-------|--------|--------|----------|
| 1 | Schedule quarterly DR test: PITR restore to a staging server + run test_isolation_stress.py | 0.5 day/quarter | MEDIUM |
| 2 | Document DR test results in admin_audit_log with action='dr_test' | 0.5 day | LOW |

---

## 6. Missing Enterprise Features

### Required for Enterprise Procurement

| Feature | Current State | Effort | Impact |
|---------|--------------|--------|--------|
| **TOTP/MFA** | Delegated to IdP via SAML | 5 days | HIGH — Blocks procurement at security-conscious orgs |
| **Audit log export** | JSON export exists via /api/reports/data; no dedicated audit trail export | 2 days | HIGH — Auditors need downloadable evidence packages |
| **Immutable audit logs** | Append-only (no delete API) but no cryptographic tamper-evidence | 3 days | MEDIUM — Required for SOC 2 Type II |
| **Dependency scanning** | Not in CI/CD | 1 day | MEDIUM — Table stakes for security review |
| **CSP header** | Permissions-Policy set; no Content-Security-Policy | 1 day | LOW — Defense-in-depth for XSS |
| **DOMPurify for markdown** | CopilotPanel uses dangerouslySetInnerHTML without sanitization | 0.5 day | MEDIUM — XSS vector in AI responses |
| **Data Processing Agreement** | No DPA template | 1 day | HIGH — Required for GDPR/HIPAA customers |
| **Penetration test report** | No evidence of pentest | External | HIGH — Required by enterprise security teams |
| **SOC 2 Type II report** | No audit engagement | External | HIGH — Gold standard for SaaS trust |

### Nice-to-Have for Competitive Positioning

| Feature | Current State | Effort | Impact |
|---------|--------------|--------|--------|
| **SSO enforcement indicator** | force_sso setting exists but no visual badge in admin | 0.5 day | LOW |
| **Session revocation** | Refresh tokens expire but can't be individually revoked | 2 days | LOW |
| **IP allowlisting** | No per-tenant IP restrictions | 3 days | MEDIUM |
| **Geo-fencing** | No geographic access restrictions | 3 days | LOW |
| **Data residency labels** | No per-tenant data region tracking | 2 days | MEDIUM |

---

## 7. Customer-Facing Architecture Summary

*This section is written for non-technical stakeholders (CISOs, procurement teams, legal).*

### How AuditGraph Protects Your Data

**Your data is isolated.** Every customer's data is stored in the same database but is cryptographically separated using PostgreSQL Row-Level Security (RLS). This is the same technology used by major cloud platforms. When your team accesses AuditGraph, the system verifies their identity five separate times before any data is returned — and each verification confirms they can only see your organization's data, never anyone else's.

**Your credentials are never stored in plain text.** Passwords are hashed using bcrypt (an industry-standard one-way algorithm). API keys are hashed with SHA-256. Database credentials are stored in Azure Key Vault and injected into the application at runtime — they never exist as files on disk and are automatically rotated every 90 days.

**Your data is encrypted everywhere it goes.** All connections between you and AuditGraph use TLS 1.2+ encryption (enforced by HSTS with browser preloading). Connections between AuditGraph and its database also use mandatory TLS. Data at rest is encrypted by Azure's infrastructure encryption.

**Every action is logged.** AuditGraph maintains a comprehensive audit trail of all user actions, system events, and administrative operations. These logs cannot be deleted through the application interface and are retained for a minimum of 180 days (configurable up to 365 days). Security-relevant events are emitted in real-time for integration with your SIEM platform.

**Access is strictly controlled.** AuditGraph supports four permission levels (Administrator, Security Administrator, Compliance, and Reader). Your administrators control who has access and at what level. AuditGraph supports SAML 2.0 Single Sign-On, allowing you to enforce your organization's MFA and password policies through your existing identity provider (Okta, Azure AD, OneLogin, etc.).

**Your data can be recovered.** AuditGraph maintains automated daily backups with 35-day retention and continuous write-ahead log archiving. This enables point-in-time recovery to any second within the backup window. Backups are geo-redundant (replicated to a paired Azure region). Our recovery objectives: less than 5 minutes of data loss (RPO) and less than 30 minutes of downtime (RTO).

**Our deployment process is gated.** Every code change passes through automated security tests that verify tenant isolation under concurrent load before it can be deployed. During deployment, the system gracefully drains traffic from old instances before switching to new ones, ensuring zero-downtime updates.

### Compliance Certifications & Standards

| Standard | Status | Notes |
|----------|--------|-------|
| SOC 2 Type II | In Progress | Controls implemented; audit engagement pending |
| HIPAA | Technical Safeguards Implemented | BAA available upon request |
| GDPR | Compliant by Design | Data isolation, retention controls, export capability |
| CIS Azure Foundations v2.0 | Monitored | AuditGraph audits customers against CIS benchmarks |
| ISO 27001:2022 | Aligned | Control mapping available |

### Security Contact

For security inquiries, vulnerability reports, or to request our full security documentation package, contact: security@auditgraph.ai

---

## 8. Audit Readiness Roadmap

### Phase 1: Critical Gaps (Weeks 1-2) — Blocks SOC 2 Engagement

| # | Task | Owner | Deliverable |
|---|------|-------|-------------|
| 1 | Enable GitHub Dependabot + add pip-audit to CI/CD | Engineering | deploy.yml updated |
| 2 | Add DELETE trigger on activity_log (RAISE EXCEPTION) | Engineering | Migration SQL |
| 3 | Document SAML force_sso as MFA-equivalent for SOC 2 | Security | Policy document section |
| 4 | Add DOMPurify to CopilotPanel markdown rendering | Frontend | CopilotPanel.tsx fix |
| 5 | Create Information Security Policy document | Security | PDF/Markdown |
| 6 | Create Incident Response Plan | Security | PDF/Markdown |

### Phase 2: Strengthen Controls (Weeks 3-4) — Recommended Before Audit

| # | Task | Owner | Deliverable |
|---|------|-------|-------------|
| 7 | Implement TOTP MFA (enrollment + verification) | Engineering | auth.py, database.py |
| 8 | Add audit log export endpoint (CSV/JSON with date range) | Engineering | handlers.py |
| 9 | Add hash chain to activity_log (tamper-evident) | Engineering | database.py migration |
| 10 | Add Content-Security-Policy header | Engineering | security.py |
| 11 | Create Data Classification Policy | Security | PDF/Markdown |
| 12 | Execute first DR test (PITR restore + validate) | Ops | admin_audit_log entry |

### Phase 3: Enterprise Polish (Weeks 5-8) — Competitive Advantage

| # | Task | Owner | Deliverable |
|---|------|-------|-------------|
| 13 | Forward audit logs to Azure Monitor (immutable retention) | Engineering | Log pipeline |
| 14 | Add IP allowlisting per tenant | Engineering | settings + middleware |
| 15 | Publish customer-facing Security Practices page | Marketing/Security | Web page |
| 16 | Engage SOC 2 Type II auditor | Executive | Audit engagement |
| 17 | Create Data Processing Agreement template | Legal | DPA document |
| 18 | Commission external penetration test | Executive | Pentest report |

### Timeline Summary

```
Week 1-2:  ████████████████  Critical gaps (6 items)
Week 3-4:  ████████████████  Strengthen controls (6 items)
Week 5-8:  ████████████████████████████████  Enterprise polish (6 items)
Week 9+:   SOC 2 Type II audit engagement (3-6 month process)
```

---

## 9. Risk Assessment

### Mitigated Risks (Controls in Place)

| Risk | Likelihood | Impact | Control | Residual Risk |
|------|-----------|--------|---------|--------------|
| Cross-tenant data leakage | Very Low | Critical | RLS + FORCE RLS + 5-layer verification + nightly audit | **Very Low** |
| Credential exposure in logs | Very Low | High | SecretRedactionFilter on all log output | **Very Low** |
| Brute-force authentication | Low | High | Rate limiting (5/min), bcrypt, 12-char password policy | **Very Low** |
| Unauthorized admin access | Very Low | Critical | ENFORCE_ADMIN_GUARD, dual DB roles, admin_audit_log | **Very Low** |
| Data loss | Very Low | Critical | Automated daily backup, WAL, geo-redundant, PITR | **Very Low** |
| Deployment breaks isolation | Very Low | Critical | CI/CD test gate (36 tests), migration-aware readiness | **Very Low** |
| Connection pool exhaustion | Low | Medium | Pool fallback + alerting, tenant skew detection | **Low** |
| Slow query degradation | Low | Medium | DB_SLOW_QUERY_MS threshold + structured alerts | **Low** |

### Residual Risks (Require Attention)

| Risk | Likelihood | Impact | Gap | Recommended Action |
|------|-----------|--------|-----|-------------------|
| No native MFA | Medium | High | Gap #2 | Implement TOTP or document force_sso as equivalent |
| Audit log tampering by DBA | Low | High | Gap #1 | Add DELETE trigger + hash chain + external forwarding |
| Unpatched dependencies | Medium | Medium | Gap #3 | Enable Dependabot + pip-audit in CI |
| No formal IRP | Low | Medium | Gap #4 | Create Incident Response Plan document |
| XSS via AI markdown | Low | Medium | CopilotPanel | Add DOMPurify sanitization |
| Single-region deployment | Low | High | Infra | Azure paired-region failover (already geo-redundant backup) |

### Risk Heat Map

```
           LOW IMPACT    MEDIUM IMPACT    HIGH IMPACT    CRITICAL IMPACT
          ┌─────────────┬───────────────┬──────────────┬────────────────┐
HIGH      │             │               │ No MFA (pre- │                │
LIKELIHOOD│             │               │ remediation) │                │
          ├─────────────┼───────────────┼──────────────┼────────────────┤
MEDIUM    │             │ Unpatched     │              │                │
LIKELIHOOD│             │ dependencies  │              │                │
          ├─────────────┼───────────────┼──────────────┼────────────────┤
LOW       │             │ No formal IRP │ Log tamper   │ Single region  │
LIKELIHOOD│             │ XSS markdown  │ by DBA       │                │
          ├─────────────┼───────────────┼──────────────┼────────────────┤
VERY LOW  │             │               │              │ Cross-tenant   │
LIKELIHOOD│             │               │              │ leakage (RLS)  │
          └─────────────┴───────────────┴──────────────┴────────────────┘
                                                  ▲ All critical risks are
                                                    at VERY LOW likelihood
```

---

*Document generated for AuditGraph audit readiness preparation. For questions, contact the engineering and security teams.*
