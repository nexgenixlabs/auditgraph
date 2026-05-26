# AuditGraph Security Architecture Whitepaper

**Document Classification:** Customer-Facing — Public
**Version:** 1.0
**Date:** March 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Multi-Tenant Isolation Model](#2-multi-tenant-isolation-model)
3. [Audit Log Integrity & Tamper Protection](#3-audit-log-integrity--tamper-protection)
4. [Runtime Enforcement & Admin Guard](#4-runtime-enforcement--admin-guard)
5. [Infrastructure & Secret Management](#5-infrastructure--secret-management)
6. [Monitoring & Incident Response](#6-monitoring--incident-response)
7. [Business Continuity & Disaster Recovery](#7-business-continuity--disaster-recovery)
8. [Compliance Alignment (SOC 2 & HIPAA)](#8-compliance-alignment-soc-2--hipaa)
9. [Secure Development Lifecycle](#9-secure-development-lifecycle)
10. [Why AuditGraph Is Architecturally Secure by Design](#10-why-auditgraph-is-architecturally-secure-by-design)

---

## 1. Executive Summary

Organizations evaluating identity security platforms face a fundamental question: is the tool that audits our security posture itself architecturally secure?

AuditGraph was built to answer that question affirmatively — not through bolt-on controls, but through security enforcement embedded at the database, runtime, and infrastructure layers from day one.

**What AuditGraph protects.** AuditGraph ingests and analyzes identity configurations across Azure AD, AWS IAM, and GCP IAM. It processes sensitive data — role assignments, permission structures, credential metadata, and risk assessments — for organizations that operate under regulatory frameworks including SOC 2, HIPAA, and CIS benchmarks. The platform must meet or exceed the security standards it helps customers enforce.

**How AuditGraph protects it.** Rather than relying on application-layer access checks alone, AuditGraph enforces tenant isolation at the PostgreSQL database engine level using Row-Level Security (RLS) policies on every tenant-scoped table. Every query, every connection, and every administrative operation passes through multiple verification layers before data is returned. Audit trails are cryptographically chained and protected by immutable database triggers. Security events are structured, machine-parseable, and wired to automated alerting.

**Key security metrics at a glance:**

| Metric | Value |
|--------|-------|
| Tenant-isolated database tables | 44 (all with FORCE RLS) |
| Tenant context verification layers | 5 (JWT → header → connection reset → session SET → RLS policy) |
| Structured security event types | 10 (auto-alerting on critical/high) |
| Audit trail integrity | SHA-256 hash chain + immutable trigger |
| Recovery Point Objective (RPO) | < 5 minutes |
| Recovery Time Objective (RTO) | < 30 minutes |
| SOC 2 controls satisfied | 33 of 35 (94%) |
| HIPAA safeguards satisfied | 16 of 18 (89%) |

This whitepaper details each layer of AuditGraph's security architecture, the technical mechanisms that enforce it, and the compliance frameworks it satisfies.

---

## 2. Multi-Tenant Isolation Model

### The Challenge

Multi-tenant SaaS platforms store data for multiple organizations in shared infrastructure. A defect in a single query, a missed filter, or a leaked database connection can expose one customer's data to another. Most platforms address this with application-layer WHERE clauses — a pattern that depends entirely on developers never making a mistake.

AuditGraph takes a fundamentally different approach.

### Database-Enforced Isolation

AuditGraph enforces tenant isolation at the PostgreSQL engine level using Row-Level Security (RLS) — the same mechanism used by Salesforce, Stripe, and other platforms that process sensitive multi-tenant data. This means that even if application code contains a bug that omits a tenant filter, the database itself refuses to return rows belonging to other tenants.

**44 tenant-scoped tables** carry a `tenant_id` column with a NOT NULL constraint. Each table has four strict RLS policies (SELECT, INSERT, UPDATE, DELETE) that compare `tenant_id` against a session-scoped PostgreSQL variable. The database will not return, modify, or accept a row unless the tenant context matches.

**FORCE ROW LEVEL SECURITY** is enabled on all 44 tables. This PostgreSQL directive ensures that RLS policies apply even to the table owner role — eliminating a common bypass vector in standard RLS deployments.

### Five-Layer Context Verification

Before any tenant data is accessed, AuditGraph performs five independent verification steps:

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: JWT Token Validation                               │
│  ─ Signed token contains tenant_id in claims                 │
│  ─ Separate signing keys for admin and client portals        │
├──────────────────────────────────────────────────────────────┤
│  Layer 2: Host-Tenant Header Verification                    │
│  ─ Subdomain slug matched against JWT tenant_id              │
│  ─ Rejects requests where URL tenant ≠ token tenant          │
├──────────────────────────────────────────────────────────────┤
│  Layer 3: Connection Checkout Reset                          │
│  ─ RESET app.current_organization_id on every checkout       │
│  ─ Prevents residual context from a previous request         │
├──────────────────────────────────────────────────────────────┤
│  Layer 4: Transaction-Scoped Session SET                     │
│  ─ SET LOCAL app.current_organization_id = N                 │
│  ─ Scoped to the current transaction only                    │
├──────────────────────────────────────────────────────────────┤
│  Layer 5: RLS Policy Enforcement                             │
│  ─ PostgreSQL evaluates tenant_id = current_setting(...)     │
│  ─ Rows that don't match are invisible to the query          │
└──────────────────────────────────────────────────────────────┘
```

If any layer fails, the request is rejected before data is returned. The system fails closed — a missing or mismatched tenant context produces an error, never a data leak.

### Dual Database Users

AuditGraph uses two PostgreSQL roles with deliberately different privileges:

| Role | Privilege | Used For |
|------|-----------|----------|
| `auditgraph_app` | `NOBYPASSRLS` | All tenant-scoped operations (queries, inserts, updates) |
| `auditgraph_admin` | `BYPASSRLS` | Schema migrations, system health checks, cross-tenant analytics |

Tenant-facing API requests always use the `auditgraph_app` role. The admin role is restricted to system operations that require cross-tenant visibility (e.g., schema migrations, scheduled jobs), and its use is monitored by the Admin Guard (Section 4).

### Auto-Fill Safety Trigger

Every tenant-scoped table has a trigger (`trg_auto_tenant_id`) that fills the `tenant_id` column from the session context if it is not provided by the application. If both the application value and the session context are NULL, the trigger raises an exception and the insert is rejected. This eliminates an entire class of bugs where a developer forgets to set `tenant_id` on a new record.

---

## 3. Audit Log Integrity & Tamper Protection

### Immutable Audit Trail

AuditGraph maintains an append-only `activity_log` table that records every significant operation: logins, data access, configuration changes, administrative actions, and security events. This log is the primary evidence artifact for SOC 2 (CC7.2) and HIPAA (164.312(b)) compliance.

The log is protected by a PostgreSQL trigger (`trg_activity_log_immutable`) that enforces immutability at the database engine level:

- **DELETE operations** are blocked with an exception
- **UPDATE operations** are blocked with an exception
- **Only INSERT** is permitted

This means that even a database administrator with full table ownership cannot silently delete or modify audit entries. The trigger fires before the operation reaches the storage engine, so no partial modification is possible.

### SHA-256 Hash Chain

Each audit log entry includes an `integrity_hash` computed as:

```
integrity_hash = SHA-256( previous_hash || action_type || description || timestamp )
```

This creates a cryptographic chain where each entry's hash depends on its predecessor. If any historical entry is modified — even a single character — every subsequent hash in the chain becomes invalid. An auditor can verify the integrity of the entire audit trail by recomputing the chain from the first entry forward.

This is the same principle used in blockchain and certificate transparency logs, applied to a traditional relational audit trail.

### Authorized Retention Cleanup

When data retention policies require the removal of aged records (configurable per data type, default 365 days for activity logs), the immutable trigger is temporarily disabled under strict controls:

1. A security event is emitted before the trigger is disabled
2. Only records exceeding the configured retention period are deleted
3. The trigger is re-enabled immediately after cleanup
4. A security event is emitted confirming re-enablement

This process runs as an automated daily job at 03:00 UTC and is fully auditable.

### Supplementary Audit Logs

In addition to the primary activity log, AuditGraph maintains:

| Log | Purpose | Retention |
|-----|---------|-----------|
| `admin_audit_log` | All administrative mutations (plan changes, tenant management, billing overrides) | Permanent |
| `billing_events` | Subscription and payment changes | Permanent |
| Structured JSON logs | Application-level request traces with correlation IDs | Azure Log Analytics retention |

---

## 4. Runtime Enforcement & Admin Guard

### The Problem with Trust-Based Security

Most multi-tenant applications rely on developers to correctly scope every database call. A single omitted tenant filter, a debugging session that uses an admin connection, or a background job that forgets to set context — any of these can silently expose cross-tenant data. The defect may go undetected for months because the application "works correctly" from the user's perspective.

AuditGraph addresses this with runtime enforcement that operates independently of developer intent.

### Admin Guard

The Admin Guard monitors database connection creation during HTTP request handling. If code attempts to create an administrative database connection (one that bypasses RLS) while processing a user-facing API request, the operation is blocked and a `ADMIN_GUARD_BLOCKED` security event is emitted.

Administrative connections are permitted only when:
- An explicit `_admin_reason` is provided (e.g., "schema_migration", "system_health_check")
- The operation runs outside of a user request context (e.g., a scheduled job)

This prevents a common vulnerability class where a developer uses an admin connection for convenience during feature development, and that code path reaches production.

### Tenant Context Verification

Before every database query executed through the safe execution path (`execute_safe`), AuditGraph calls `verify_tenant_context()` to confirm:

1. The PostgreSQL session variable `app.current_organization_id` is set
2. The session variable matches the tenant_id that was passed to the Database constructor
3. The variable was not cleared or changed by a previous operation in the same connection

If verification fails, the query is not executed. Instead, a `TENANT_CONTEXT_VIOLATION` security event is emitted with one of three violation types:

- **context_lost** — the session variable was cleared (indicates a connection pool leak)
- **context_mismatch** — the session variable doesn't match expectations (indicates a logic error)
- **context_absent** — no tenant context was set (indicates a missing initialization step)

### Connection Pool Safety

AuditGraph's connection pool implements two additional safeguards:

**Checkout reset.** Every time a connection is checked out from the pool, the tenant context variable is explicitly reset to NULL before it is assigned to the new request. This prevents a scenario where a connection retains context from a previous request due to an error in the return path.

**PgBouncer detection.** If AuditGraph detects that connections are being routed through PgBouncer in session mode (a common database proxy), startup fails with a fatal error. Session-mode PgBouncer can leak `SET LOCAL` variables across transactions, which would compromise RLS enforcement. This guard is automatic and requires no configuration.

---

## 5. Infrastructure & Secret Management

### Deployment Architecture

AuditGraph runs on Azure Container Apps with the following topology:

```
┌─────────────────────────────────────────────────────────────┐
│                       Internet                              │
└───────────────────────────┬─────────────────────────────────┘
                            │ TLS 1.2+
┌───────────────────────────▼─────────────────────────────────┐
│              Azure Container Apps Environment               │
│                                                             │
│  ┌─────────────────────┐    ┌─────────────────────────┐    │
│  │  auditgraph-api     │    │  auditgraph-web         │    │
│  │  (gunicorn, Python) │    │  (nginx:alpine, static) │    │
│  │  Port 5000          │    │  Port 80                │    │
│  └─────────┬───────────┘    └─────────────────────────┘    │
│            │ SSL (DB_SSLMODE=require)                       │
│  ┌─────────▼───────────────────────────────────────────┐   │
│  │  Azure PostgreSQL Flexible Server                   │   │
│  │  ├── FORCE RLS on 44 tables                         │   │
│  │  ├── Continuous WAL archiving                       │   │
│  │  ├── 35-day backup retention                        │   │
│  │  └── Geo-redundant backup storage                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Secret Management

AuditGraph follows a zero-secrets-on-disk architecture:

| Environment | Secret Source | Mechanism |
|-------------|-------------|-----------|
| Production | Azure Key Vault | Container Apps secret references (environment injection) |
| CI/CD | GitHub Actions Secrets | Encrypted at rest, decrypted only during workflow execution |
| Local development | `.env.local` | Localhost-only values; safety guard blocks Azure database URLs |

**The safety guard** is a runtime check that prevents a developer from accidentally connecting to a production database during local development. If `APP_ENV=local` and the database hostname contains `azure.com`, the application crashes with an explicit error message before any connection is established.

### Log Redaction

All log output passes through a `SecretRedactionFilter` that masks sensitive values before they reach any log destination. The filter covers four pattern categories:

- **Credential key-value pairs** — any environment variable or configuration key containing PASSWORD, SECRET, TOKEN, or API_KEY
- **Bearer tokens** — HTTP Authorization headers
- **Azure connection strings** — storage account and service bus connection strings
- **API keys** — AuditGraph's `ag_` prefixed API keys

This ensures that even if a debug log statement inadvertently includes a credential, the value is replaced with `[REDACTED]` before it leaves the application process.

### Network Security Headers

Every HTTP response includes security headers that mitigate common web attack vectors:

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` | Force HTTPS for 1 year |
| X-Frame-Options | `DENY` | Prevent clickjacking |
| X-Content-Type-Options | `nosniff` | Prevent MIME sniffing |
| Content-Security-Policy | Restrictive policy | Prevent XSS |
| Permissions-Policy | Deny camera, microphone, geolocation | Limit browser capabilities |

---

## 6. Monitoring & Incident Response

### Structured Security Telemetry

AuditGraph's `SecurityEventLogger` emits machine-parseable JSON events for 10 defined event types, each with a severity classification and automated routing:

**Critical Events (auto-page on-call):**
- `TENANT_CONTEXT_VIOLATION` — RLS context lost, mismatched, or bypassed
- `RLS_DRIFT_DETECTED` — FORCE RLS or a policy was removed from a table

**High Events (auto-notify via Slack/Teams):**
- `ADMIN_GUARD_BLOCKED` — unauthorized admin database access during a request
- `POOL_EXHAUSTION` — connection pool at capacity, falling back to direct connections
- `AUTH_FAILURE` (burst) — more than 10 failures per minute from a single source

**Medium Events (logged, reviewed in daily triage):**
- `SLOW_QUERY` — query exceeded the configurable threshold (default: 100ms)
- `TENANT_SKEW` — a single tenant consuming more than 25% of database resources
- `AUTH_FAILURE` (individual) — single failed login attempt

**Informational Events (logged for compliance):**
- `AUTH_SUCCESS`, `SECRET_ROTATION`, `MIGRATION_APPLIED`, `STARTUP_VALIDATION`

Every event includes a timestamp (ISO 8601 UTC), correlation ID (linking to the originating HTTP request), affected tenant ID, and a structured details payload. Events are emitted as JSON to container logs, which flow into Azure Log Analytics for querying, alerting, and long-term retention.

### Incident Response Framework

AuditGraph maintains a formal Incident Response Plan with defined timelines:

| Priority | Response Time | Resolution Target | Example |
|----------|--------------|-------------------|---------|
| P1 (Critical) | 15 minutes | 4 hours | Tenant isolation breach |
| P2 (High) | 30 minutes | 8 hours | Auth system failure |
| P3 (Medium) | 2 hours | 24 hours | Performance degradation |
| P4 (Info) | Next business day | 5 business days | Routine operational events |

The escalation path is: On-Call SRE (15 min) → Security Lead (30 min) → CTO (1 hour) → Compliance Officer (if data breach).

Customer notification for data breach scenarios follows a defined protocol: internal assessment within 4 hours, draft notification within 24 hours, customer notification within 48 hours, and HIPAA breach notification within 72 hours if applicable.

### Nightly Security Audit

A scheduled job runs at 04:30 UTC daily to verify that FORCE ROW LEVEL SECURITY remains enabled on all 44 tenant-scoped tables. If any table is found with RLS disabled or FORCE RLS removed, a `RLS_DRIFT_DETECTED` critical event is emitted immediately. This catches configuration drift caused by manual database changes, failed migrations, or infrastructure modifications.

---

## 7. Business Continuity & Disaster Recovery

### Recovery Objectives

| Metric | Target | Mechanism |
|--------|--------|-----------|
| **RPO** (max data loss) | < 5 minutes | Continuous WAL archiving to geo-redundant storage |
| **RTO** (max downtime) | < 30 minutes | PITR restore + container redeployment + DNS propagation |

### Backup Strategy

AuditGraph's PostgreSQL database is protected by three backup mechanisms:

1. **Continuous WAL archiving** — every database transaction is streamed to Azure geo-redundant storage in near-real-time, providing sub-5-minute recovery granularity
2. **Automated daily snapshots** — full database snapshots taken daily by Azure PostgreSQL Flexible Server
3. **35-day retention** — any point within the last 35 days can be used as a recovery target

### Quarterly DR Drills

AuditGraph conducts quarterly disaster recovery drills following a documented procedure:

1. **Baseline capture** — record current tenant counts, identity counts, and the latest audit log entry with its integrity hash
2. **PITR restore** — create a point-in-time clone of the production database to a recovery target
3. **Data validation** — verify tenant counts match, RLS policies are intact, FORCE RLS is enabled on all 44 tables, and the integrity hash chain is valid
4. **Application validation** — deploy the application against the restored database and verify health endpoints respond correctly
5. **Evidence collection** — record RTO measurement, completed validation checklist, and health check responses
6. **Cleanup** — remove temporary DR resources

Each drill produces a signed report documenting actual RPO/RTO measurements, any issues found, and corrective action items. These reports are retained as SOC 2 (A1.2, A1.3) and HIPAA (164.308(a)(7)) compliance evidence.

### Tenant Isolation During Recovery

A restored database retains all RLS policies, FORCE RLS settings, and dual-user role configurations. The DR validation procedure explicitly verifies that all 44 tables have `relrowsecurity = true` and `relforcerowsecurity = true` before the restored instance is declared ready. Tenant isolation is never degraded during a disaster recovery scenario.

---

## 8. Compliance Alignment (SOC 2 & HIPAA)

### SOC 2 Type II

AuditGraph maps 35 controls across the Trust Services Criteria. Current posture: **33 satisfied, 2 partial.**

| Category | Controls | Satisfied | Key Implementation |
|----------|----------|-----------|-------------------|
| Security (CC6) | 12 | 11 | RLS, RBAC, JWT, encryption, dependency scanning |
| Availability (A1) | 4 | 3 | PITR, geo-redundant backup, health probes |
| Confidentiality (C1) | 5 | 5 | Data classification, secret redaction, retention |
| Processing Integrity (PI1) | 4 | 4 | Input validation, hash chain, drift detection |
| Monitoring (CC7) | 5 | 5 | SecurityEventLogger, anomaly detection, audit trail |
| Change Management (CC8) | 3 | 3 | CI/CD gates, dependency scanning, migration tracking |
| Risk Assessment (CC3) | 2 | 2 | 10-factor risk scoring, anomaly detection |

**Partial controls** relate to automated backup verification (currently manual quarterly drills) and formal security awareness training documentation. Both are on the active remediation roadmap.

### HIPAA

AuditGraph maps 18 safeguards across Administrative, Technical, and Organizational categories. Current posture: **16 satisfied, 2 partial.**

| Category | Controls | Satisfied | Key Implementation |
|----------|----------|-----------|-------------------|
| Administrative (164.308) | 6 | 5 | ISP, RBAC, incident response, contingency plan |
| Technical (164.312) | 8 | 7 | Access control, audit controls, encryption, integrity |
| Organizational (164.314) | 4 | 4 | Tenant isolation, data export, retention |

**Notable HIPAA alignment:**
- **164.312(b) Audit Controls** — immutable audit log with SHA-256 hash chain exceeds the standard requirement for hardware or software mechanisms that record activity in systems containing ePHI
- **164.312(a)(1) Access Control** — five-layer tenant verification provides defense-in-depth beyond the standard's access control requirement
- **164.308(a)(7) Contingency Plan** — quarterly DR drills with documented evidence collection directly address the standard's requirement for testing and revision procedures

### Compliance Evidence Artifacts

AuditGraph maintains the following artifacts for audit purposes:

| Artifact | Type | Retention | Purpose |
|----------|------|-----------|---------|
| `activity_log` | Database (immutable) | 365 days | User activity audit trail |
| `admin_audit_log` | Database | Permanent | Privileged operation tracking |
| `integrity_hash` chain | Column | 365 days | Tamper-evidence verification |
| CI/CD pipeline logs | GitHub Actions | 90 days | Change management evidence |
| DR drill reports | Document | Permanent | Business continuity evidence |
| SecurityEventLogger output | Log Analytics | Configurable | Security monitoring evidence |

---

## 9. Secure Development Lifecycle

### Pre-Deployment Gates

Every code change passes through a mandatory CI/CD pipeline before reaching production:

```
Code Push → test-guardrails job ──────────────────────► Build & Deploy
                │                                            │
                ├── pip-audit (dependency CVE scan)           ├── ACR image build
                ├── Isolation stress tests (36+ tests)       │   (tagged with commit SHA)
                └── Production guardrail tests               │
                    ├── FORCE RLS verification                ├── Deploy to Container Apps
                    ├── Admin guard enforcement               │
                    └── Pool management validation            └── Readiness polling
                                                                 (12 × 10s health checks)
```

**If any test fails, the build does not proceed.** There is no manual override.

### Dependency Management

**Automated scanning.** Dependabot monitors Python (pip), JavaScript (npm), and GitHub Actions dependencies on a weekly cadence. Pull requests are automatically created when updates are available.

**Vulnerability detection.** `pip-audit` runs in strict mode during CI, scanning all Python dependencies against the Python Packaging Advisory Database. Builds produce a warning on any known vulnerability with an available fix.

### Secure Coding Patterns

AuditGraph's codebase enforces security through structural patterns rather than developer discipline:

- **`execute_safe()`** — all database queries pass through a single execution method that enforces tenant context verification, slow query detection, and structured error handling. Direct `cursor.execute()` calls are not used in production code paths.
- **`@require_role()` decorators** — every API endpoint is annotated with its required role. Endpoints without a role decorator are blocked by default.
- **`Database(tenant_id=N)` constructor** — the tenant context is set at connection creation time, not per-query. There is no "default" connection that operates without tenant context.
- **Auto-fill triggers** — even if application code omits `tenant_id` on an INSERT, the database trigger fills it from the session context. If both are NULL, the insert fails.

### Migration Safety

Schema migrations are applied through an idempotent migration framework that:
- Tracks applied migrations in a `schema_migrations` table with checksums
- Sets `_migration_in_progress = True` during DDL, causing the readiness probe to return 503 (preventing traffic routing during schema changes)
- Emits `MIGRATION_APPLIED` security events for audit trail
- Uses the admin database user (required for DDL) with explicit `_admin_reason` logging

---

## 10. Why AuditGraph Is Architecturally Secure by Design

### Three Differentiators

**1. Database-enforced isolation, not application-layer filtering.**

Most multi-tenant SaaS platforms rely on WHERE clauses in application code to scope data to the current tenant. This creates a class of vulnerabilities where a single missing filter — in any query, in any code path, by any developer — can expose cross-tenant data. These defects are difficult to detect in code review and may go unnoticed in testing because the application "works correctly" for the test tenant.

AuditGraph enforces isolation at the PostgreSQL engine level. FORCE ROW LEVEL SECURITY ensures that even the table owner role cannot bypass RLS policies. The database will not return rows for a tenant that doesn't match the session context, regardless of what the application code requests. This is a structural guarantee, not a best-practice guideline.

**2. Cryptographic audit trail integrity, not append-only tables.**

Many platforms describe their audit logs as "immutable" because they don't expose a DELETE API endpoint. But a database administrator, a compromised service account, or a SQL injection vulnerability can still modify or delete records directly.

AuditGraph enforces immutability with a PostgreSQL trigger that blocks DELETE and UPDATE operations at the database engine level. The SHA-256 hash chain provides an independent verification mechanism: if any entry in the log is modified after the fact, every subsequent hash becomes invalid. An auditor can verify the integrity of the entire trail by recomputing the chain — no trust in the application is required.

**3. Fail-closed runtime enforcement, not trust-based access control.**

AuditGraph's Admin Guard, tenant context verification, and connection pool reset mechanisms operate independently of developer intent. A developer cannot accidentally create an admin connection during a user request, cannot execute a query without verified tenant context, and cannot check out a pooled connection that retains residual state from a previous tenant.

These are not code review guidelines or static analysis rules. They are runtime enforcement mechanisms that block unsafe operations in real-time and emit security events when they fire.

### Security Is Not a Feature — It Is the Architecture

Identity security posture management platforms process some of the most sensitive data in an organization: who has access to what, which credentials are expiring, which service principals have excessive privileges, and where the blast radius of a compromise would reach.

AuditGraph was designed with the conviction that the tool responsible for auditing an organization's security posture must itself be architecturally sound — not through promises, but through enforcement mechanisms that an auditor can independently verify.

Every query passes through five verification layers. Every audit entry is cryptographically chained to its predecessor. Every connection resets its tenant context on checkout. Every deployment passes through isolation tests before a container image is built.

This is what it means to be secure by design.

---

## Appendix A: Security Architecture Summary

| Layer | Mechanism | Enforcement Level |
|-------|-----------|------------------|
| Authentication | JWT (dual keys, 30/60 min), SAML 2.0 SSO, API keys (SHA-256) | Application |
| Authorization | 4-role client RBAC + 4-role admin RBAC | Application |
| Tenant Isolation | FORCE RLS on 44 tables, dual DB users, 5-layer context verification | Database engine |
| Audit Integrity | Immutable trigger + SHA-256 hash chain | Database engine |
| Secret Protection | Key Vault injection, log redaction (4 pattern categories) | Infrastructure + Application |
| Network | TLS 1.2+, HSTS (1 year), CSP, CORS whitelist | Infrastructure |
| Monitoring | 10 security event types, anomaly detection (6 types) | Application |
| CI/CD | Isolation tests, pip-audit, Dependabot, readiness polling | Pipeline |
| DR | RPO < 5 min (WAL), RTO < 30 min (PITR), quarterly drills | Infrastructure |

## Appendix B: Compliance Quick Reference

| Requirement | AuditGraph Control | Status |
|------------|-------------------|--------|
| SOC 2 CC6.1 — Logical access | JWT + RBAC + API keys + RLS | Satisfied |
| SOC 2 CC6.4 — Access restriction | FORCE RLS + dual DB users + Admin Guard | Satisfied |
| SOC 2 CC7.2 — Monitoring | Immutable audit log + SecurityEventLogger | Satisfied |
| SOC 2 CC8.1 — Change management | CI/CD test gates + dependency scanning | Satisfied |
| SOC 2 A1.2 — DR recovery | PITR + quarterly drills + evidence | Satisfied |
| HIPAA 164.312(a)(1) — Access control | 5-layer tenant verification | Satisfied |
| HIPAA 164.312(b) — Audit controls | Immutable log + hash chain + export | Satisfied |
| HIPAA 164.312(e)(1) — Transmission | TLS 1.2+ / HSTS / DB SSL | Satisfied |
| HIPAA 164.308(a)(6) — Incident response | Formal IR plan with severity matrix | Satisfied |
| HIPAA 164.308(a)(7) — Contingency | DR plan + quarterly testing | Satisfied |

---

*For questions about AuditGraph's security architecture, contact security@auditgraph.ai.*
*For compliance documentation requests or audit questionnaire support, contact compliance@auditgraph.ai.*
