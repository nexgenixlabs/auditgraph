# AuditGraph — Security Marketing Kit

**Version:** 1.0
**Date:** March 2026
**Audience:** Board of Directors, CISOs, Sales Engineering, Marketing
**Source Material:** Security Architecture Whitepaper v1.0, Competitive Positioning v1.0

---

# DELIVERABLE 1: Executive Security Brief (1-Page, Board-Ready)

---

## AuditGraph — Executive Security Brief

### Platform Overview

AuditGraph is a cloud identity security posture management platform that analyzes access configurations across Azure AD, AWS IAM, and GCP IAM. It processes sensitive identity data — role assignments, credential metadata, privilege escalation paths, and blast radius assessments — for organizations operating under SOC 2, HIPAA, and CIS compliance frameworks.

### Security Architecture at a Glance

| Control | AuditGraph Implementation |
|---------|--------------------------|
| **Tenant Isolation** | Database-enforced (PostgreSQL FORCE RLS on 44 tables) — not application-layer WHERE clauses |
| **Audit Trail** | Immutable (database trigger blocks DELETE/UPDATE) + SHA-256 hash chain for independent verification |
| **Runtime Safety** | Fail-closed enforcement — admin connections blocked during user requests, tenant context verified before every query |
| **Deployment Security** | Mandatory isolation test gate in CI/CD — no code deploys without passing 36+ tenant isolation tests |
| **Monitoring** | 10 structured security event types with automated severity routing (15-minute P1 response) |
| **Business Continuity** | RPO < 5 minutes (continuous WAL archiving), RTO < 30 minutes (PITR), quarterly DR drills |

### Compliance Posture

| Framework | Coverage | Status |
|-----------|----------|--------|
| SOC 2 Type II | 33 of 35 controls satisfied | 94% — 2 partial controls on active roadmap |
| HIPAA | 16 of 18 safeguards satisfied | 89% — 2 partial controls on active roadmap |
| CIS Benchmarks | Automated scanning | Storage + Key Vault benchmarks |

### Why This Matters

AuditGraph audits your organization's identity security. If the auditing tool itself is not architecturally secure, the audit results cannot be trusted.

Three properties distinguish AuditGraph's architecture:

1. **A single developer error cannot expose tenant data.** Isolation is enforced by the database engine, not by application code. Even if a query omits a tenant filter, the database returns zero rows — not another customer's data.

2. **Audit trail integrity can be independently verified.** The SHA-256 hash chain allows any auditor to verify the entire trail by recomputing hashes from the first entry forward. No trust in the application is required.

3. **Security controls are enforced, not recommended.** Runtime mechanisms block unsafe operations in real-time. Configuration drift is detected nightly. Deployment is gated on isolation tests with no manual override.

### Key Metrics for Risk Assessment

| Metric | Value |
|--------|-------|
| Tenant-isolated tables | 44 (all FORCE RLS) |
| Context verification layers | 5 independent checks per request |
| Automated security event types | 10 (critical events page on-call within 15 min) |
| Backup retention | 35 days, geo-redundant, continuous WAL |
| DR drill cadence | Quarterly with signed evidence reports |
| Dependency scanning | Every deployment (pip-audit strict mode) + weekly Dependabot |

---

*Full technical detail: Security Architecture Whitepaper (10 pages)*
*Architectural comparison: Competitive Positioning Document (8 pages)*
*Compliance detail: SOC2.md, HIPAA.md, Information Security Policy*

---
---

# DELIVERABLE 2: CISO Security Deep-Dive Deck (15-Slide Outline)

---

## Slide Deck: AuditGraph Security Architecture — CISO Deep-Dive

**Format:** 16:9 presentation
**Duration:** 30-45 minutes
**Audience:** CISO, Security Engineering leads, GRC team

---

### Slide 1 — Title

**AuditGraph Security Architecture**
*How we protect the data that maps your access surface*

- Subtitle: Technical deep-dive for security leadership
- Date, presenter name, version

---

### Slide 2 — The Core Question

**"Is the tool that audits our security posture itself architecturally secure?"**

- Identity security platforms process the most sensitive data in your stack
- Role assignments, credential metadata, privilege paths, blast radius
- If the auditing tool leaks tenant data, the audit itself is compromised
- This deck shows exactly how AuditGraph prevents that

---

### Slide 3 — Architecture Overview (Visual)

**Defense-in-Depth: Four Enforcement Layers**

Diagram showing:
```
Internet (TLS 1.2+)
  → Azure Container Apps
    → Application Layer (JWT, RBAC, Admin Guard)
      → Database Engine (FORCE RLS, 44 tables, dual roles)
        → Audit Layer (immutable trigger, SHA-256 chain)
          → Monitoring (10 event types, automated alerting)
```

Key point: Controls enforced at the database engine level, not just application code.

---

### Slide 4 — Tenant Isolation: The Problem

**Application-Layer Filtering Is Architecturally Fragile**

- Industry standard: WHERE tenant_id = ? in every query
- 500 queries × 0.1% omission rate = 39.4% probability of at least one leak
- Silent failure — application works correctly from the user's perspective
- Invisible to single-tenant test databases

---

### Slide 5 — Tenant Isolation: Our Approach

**Database-Enforced FORCE RLS on Every Table**

| Layer | Mechanism |
|-------|-----------|
| 1 | JWT signed tenant_id |
| 2 | Host-tenant header match |
| 3 | Connection pool checkout RESET |
| 4 | Transaction-scoped SET LOCAL |
| 5 | PostgreSQL RLS policy evaluation |

- 44 tables, FORCE RLS on all
- Dual DB users: app (NOBYPASSRLS) + admin (BYPASSRLS, monitored)
- Auto-fill trigger rejects rows without tenant context
- Failure mode: blocked query + security event (not silent leak)

---

### Slide 6 — Tenant Isolation: Comparison Table

| Dimension | App-Layer Filtering | AuditGraph (FORCE RLS) |
|-----------|--------------------|-----------------------|
| Bypass via app bug | Yes | No |
| Bypass via SQL injection | Yes | No |
| Bypass via admin tool | Yes | No — FORCE applies to table owners |
| Developer discipline required | Every query | Context set once at connection |
| Failure mode | Silent data leak | Blocked query + alert |

---

### Slide 7 — Audit Trail Integrity: The Problem

**"Immutable" Often Means "No Delete Button in the API"**

- Database accepts DELETE and UPDATE without restriction
- DBA, compromised credential, or SQL injection can tamper
- Append-only by convention, not enforcement
- Auditors increasingly asking: "Can I verify this independently?"

---

### Slide 8 — Audit Trail Integrity: Our Approach

**Database Trigger + SHA-256 Hash Chain**

- PostgreSQL trigger blocks DELETE and UPDATE at engine level
- Even table owner cannot silently modify entries
- Each entry: `integrity_hash = SHA-256(prev_hash || action || description || timestamp)`
- Any modification invalidates all subsequent hashes
- Any auditor can recompute and verify — no trust in application required

Retention cleanup: controlled process with trigger disable/re-enable audit trail.

---

### Slide 9 — Runtime Enforcement

**Three Mechanisms That Operate Independently of Developer Intent**

1. **Admin Guard** — blocks admin DB connections during user requests; emits ADMIN_GUARD_BLOCKED event
2. **Tenant Context Verification** — confirms PostgreSQL session variable before every query; emits TENANT_CONTEXT_VIOLATION on failure
3. **Connection Pool Reset** — RESET on every checkout; PgBouncer session-mode detection fails startup

Key point: These are not code review guidelines. They are runtime blocks.

---

### Slide 10 — Monitoring & Incident Response

**10 Structured Security Event Types**

| Severity | Events | Routing |
|----------|--------|---------|
| Critical | TENANT_CONTEXT_VIOLATION, RLS_DRIFT_DETECTED | PagerDuty (15 min) |
| High | ADMIN_GUARD_BLOCKED, POOL_EXHAUSTION, AUTH burst | Slack/Teams (30 min) |
| Medium | SLOW_QUERY, TENANT_SKEW, individual AUTH_FAILURE | Daily triage (2 hr) |
| Info | AUTH_SUCCESS, SECRET_ROTATION, MIGRATION_APPLIED | Log only |

Every event: JSON structured, ISO 8601 timestamp, correlation ID, tenant ID.
Escalation: SRE (15 min) → Security Lead (30 min) → CTO (1 hr).

---

### Slide 11 — CI/CD Security Gate

**Mandatory Pre-Deploy Isolation Testing**

```
Code push → test-guardrails (BLOCKING) → Build → Deploy → Readiness polling
               │
               ├── pip-audit (CVE scan, strict mode)
               ├── 36+ isolation stress tests (multi-tenant, concurrent)
               └── Production guardrails (FORCE RLS, Admin Guard, pool)
```

- No build proceeds until ALL tests pass
- No manual override
- Post-deploy: 12 health checks × 10s + migration-aware readiness probe
- Nightly: FORCE RLS drift audit on all 44 tables (04:30 UTC)

---

### Slide 12 — Business Continuity

**RPO < 5 Minutes | RTO < 30 Minutes**

| Mechanism | Detail |
|-----------|--------|
| Continuous WAL | Every transaction streamed to geo-redundant storage |
| Daily snapshots | Azure PostgreSQL automated full backups |
| 35-day retention | Any second within the window as restore target |
| Quarterly DR drills | PITR restore + full validation + signed evidence |

DR validation confirms: tenant counts match, FORCE RLS intact on 44 tables, hash chain valid, health endpoints responsive. Tenant isolation is never degraded during recovery.

---

### Slide 13 — Compliance Posture

**SOC 2 Type II: 33/35 (94%) | HIPAA: 16/18 (89%)**

| SOC 2 Category | Satisfied |
|---------------|-----------|
| Security (CC6) | 11/12 |
| Availability (A1) | 3/4 |
| Confidentiality (C1) | 5/5 |
| Processing Integrity (PI1) | 4/4 |
| Monitoring (CC7) | 5/5 |
| Change Management (CC8) | 3/3 |

2 partial: automated backup verification + security awareness training — both on roadmap.

Evidence artifacts: immutable activity_log, admin_audit_log, billing_events, integrity_hash chain, CI/CD logs, DR drill reports.

---

### Slide 14 — Architectural Maturity Comparison

| Tier | Isolation | Audit | Runtime | CI/CD |
|------|-----------|-------|---------|-------|
| **Tier 1** (Most SaaS) | WHERE clauses | Append-only API | Code review | Optional tests |
| **Tier 2** (Security SaaS) | RLS (no FORCE) | DB trigger | Linter rules | Mandatory unit tests |
| **Tier 3** (AuditGraph) | FORCE RLS + dual roles + 5-layer verification | Trigger + SHA-256 chain | Runtime enforcement + Admin Guard | Blocking gate + nightly drift audit |

Tier 1: one developer error = exposure.
Tier 3: requires multiple simultaneous infrastructure failures + nightly audit miss.

---

### Slide 15 — Summary & Next Steps

**AuditGraph: Secure by Construction, Not by Convention**

Three architectural guarantees:
1. A single developer error cannot expose tenant data (FORCE RLS)
2. Audit trail integrity is independently verifiable (SHA-256 hash chain)
3. Security controls are enforced at runtime, not recommended in documentation

**Next steps:**
- Request full Security Architecture Whitepaper
- Schedule security engineering walkthrough
- Request compliance evidence package (SOC 2 / HIPAA)
- Contact: security@auditgraph.ai

---
---

# DELIVERABLE 3: Trust Center Content Structure (Web-Ready)

---

## AuditGraph Trust Center — Site Structure

**URL:** trust.auditgraph.ai (or auditgraph.ai/trust)
**Purpose:** Self-service security and compliance information for prospects, customers, and auditors

---

### Page 1: Trust Center Home

**Headline:** Security is not a feature we added. It is the architecture we built.

**Hero section:**
- One-sentence positioning: "AuditGraph enforces tenant isolation at the database engine level, protects audit trails with cryptographic hash chaining, and gates every deployment on mandatory isolation tests."
- Three stat badges:
  - 44 tables with FORCE RLS
  - SHA-256 audit hash chain
  - SOC 2: 94% controls satisfied

**Quick links grid (6 tiles):**
1. Data Isolation
2. Audit & Compliance
3. Infrastructure Security
4. Incident Response
5. Business Continuity
6. Documentation Downloads

---

### Page 2: Data Isolation

**Headline:** Your data is isolated by the database engine, not by application code.

**Content sections:**

**2.1 — How Tenant Isolation Works**
- FORCE RLS on 44 tables (brief explanation for non-technical readers)
- Five-layer verification (visual diagram)
- Dual database roles (app vs admin)
- Fail-closed behavior: missing context = blocked request, not data leak

**2.2 — FAQ**
- "Is my data in a shared database?" → Yes, with database-engine isolation (same approach as Salesforce, Stripe)
- "Can another customer's query return my data?" → No. FORCE RLS is enforced by PostgreSQL, not by our code.
- "Can your engineers access my data?" → Only through the admin role, which is monitored, logged, and restricted to system operations.
- "What happens during a database backup restore?" → RLS policies, FORCE settings, and dual roles are preserved. Our DR procedure verifies this explicitly.

---

### Page 3: Audit & Compliance

**Headline:** Immutable audit trail with cryptographic tamper evidence.

**Content sections:**

**3.1 — Audit Trail Integrity**
- Immutable trigger (blocks DELETE/UPDATE at database level)
- SHA-256 hash chain (each entry linked to predecessor)
- Independent verification: any auditor can recompute and verify
- 365-day retention with controlled cleanup process

**3.2 — Compliance Frameworks**

| Framework | Coverage | Documentation |
|-----------|----------|--------------|
| SOC 2 Type II | 33/35 controls (94%) | Download SOC 2 Control Mapping |
| HIPAA | 16/18 safeguards (89%) | Download HIPAA Safeguard Mapping |
| CIS Benchmarks | Automated scanning | Download CIS Benchmark Report |

**3.3 — Downloadable Documents**
- Security Architecture Whitepaper (PDF)
- SOC 2 Control Mapping (PDF)
- HIPAA Safeguard Mapping (PDF)
- Information Security Policy (PDF)
- MFA Policy (PDF)

**3.4 — FAQ**
- "Can audit log entries be deleted?" → No. A database trigger blocks DELETE and UPDATE. Even administrators cannot modify entries.
- "How can I verify the audit trail hasn't been tampered with?" → Each entry includes a SHA-256 hash linked to the previous entry. Recompute the chain to verify integrity.
- "What compliance evidence can you provide?" → Immutable activity_log exports (CSV/JSON with integrity hashes), admin_audit_log, CI/CD pipeline logs, DR drill reports.

---

### Page 4: Infrastructure Security

**Headline:** Zero secrets on disk. TLS everywhere. Every deploy gated on isolation tests.

**Content sections:**

**4.1 — Deployment Architecture**
- Azure Container Apps (managed ingress, TLS termination)
- Azure PostgreSQL Flexible Server (encrypted at rest, SSL connections)
- Container images tagged with commit SHA for traceability

**4.2 — Secret Management**
- Azure Key Vault injection (secrets never on disk)
- Log redaction: passwords, tokens, API keys, connection strings masked before log emission
- Local dev safety guard: blocks Azure database URLs in local mode

**4.3 — CI/CD Security**
- Mandatory pre-deploy isolation gate (36+ tests)
- pip-audit dependency CVE scanning on every build
- Dependabot automated dependency updates (weekly)
- Post-deploy readiness polling with migration-aware health probe

**4.4 — Network Security**
- TLS 1.2+ for all connections (API and database)
- HSTS with 1-year max-age, includeSubDomains, preload
- Content Security Policy, X-Frame-Options DENY, Permissions-Policy
- CORS restricted to app.auditgraph.ai and admin.auditgraph.ai

---

### Page 5: Incident Response

**Headline:** Automated detection. Defined timelines. Structured escalation.

**Content sections:**

**5.1 — Security Event Monitoring**
- 10 structured event types with severity classification
- Critical events auto-page on-call within 15 minutes
- Every event includes correlation ID for request tracing

**5.2 — Response Timelines**

| Priority | Response | Resolution |
|----------|----------|------------|
| P1 Critical | 15 minutes | 4 hours |
| P2 High | 30 minutes | 8 hours |
| P3 Medium | 2 hours | 24 hours |
| P4 Info | Next business day | 5 business days |

**5.3 — Customer Notification**
- Internal assessment: 4 hours
- Draft notification: 24 hours
- Customer notification: 48 hours
- HIPAA breach filing: 72 hours (if applicable)

**5.4 — Nightly Security Audit**
- FORCE RLS verified on all 44 tables daily at 04:30 UTC
- Drift detected within 24 hours
- Critical alert emitted immediately on any configuration change

---

### Page 6: Business Continuity

**Headline:** RPO under 5 minutes. RTO under 30 minutes. Tested quarterly.

**Content sections:**

**6.1 — Backup & Recovery**

| Mechanism | Detail |
|-----------|--------|
| Continuous WAL archiving | Sub-5-minute recovery granularity |
| Automated daily snapshots | Full database backup |
| 35-day retention | Point-in-time recovery to any second |
| Geo-redundant storage | Replicated to paired Azure region |

**6.2 — DR Drill Program**
- Quarterly cadence (January, April, July, October)
- Full PITR restore + application deployment + validation
- Signed evidence reports retained for compliance
- Validation includes: tenant isolation, hash chain integrity, health endpoints

**6.3 — Isolation During Recovery**
- Restored databases retain all RLS policies and FORCE settings
- DR validation explicitly checks all 44 tables before declaring ready
- Tenant isolation is never degraded during a disaster recovery scenario

---

### Page 7: Documentation Downloads

**Headline:** Download our security documentation.

**Document library table:**

| Document | Description | Format |
|----------|------------|--------|
| Security Architecture Whitepaper | 10-page technical deep-dive | PDF |
| Competitive Positioning | Architectural comparison framework | PDF |
| SOC 2 Control Mapping | 35 controls, implementation evidence | PDF |
| HIPAA Safeguard Mapping | 18 safeguards, implementation evidence | PDF |
| Information Security Policy | 6-section SOC 2 aligned policy | PDF |
| MFA Policy | SSO-delegated MFA architecture | PDF |
| Incident Response Plan | Severity matrix, response timelines | PDF |
| DR Test Procedure | PITR drill steps, validation checklist | PDF |

**Additional resources:**
- Request a security engineering walkthrough: security@auditgraph.ai
- Request audit evidence package: compliance@auditgraph.ai
- Report a security concern: security@auditgraph.ai

---

### Trust Center — Technical Implementation Notes

**Hosting:** Static site at trust.auditgraph.ai (separate subdomain)
**CMS:** Headless CMS or static-site generator (Hugo/Next.js)
**Access:** Public (no login required for documentation access)
**PDF generation:** Convert markdown docs via pandoc or custom pipeline
**Analytics:** Track document downloads for sales intelligence
**Update cadence:** Review quarterly, update after each compliance milestone

---
---

# DELIVERABLE 4: 30-Second Security Positioning Pitch

---

## Sales Demo Security Pitch (30 Seconds)

**Context:** Opening or closing a live product demo. Delivered verbally by an SE or AE. Addresses the unspoken question: "How do I know my data is safe in your platform?"

---

### The Pitch

> "AuditGraph processes your most sensitive identity data — who has access to what across your entire cloud environment. So the platform itself has to be at least as secure as what it's auditing.
>
> Here's what makes our architecture different: tenant isolation is enforced by the database engine, not by application code. Even if our own code had a bug that omitted a tenant filter, the database would return zero rows — not your neighbor's data. That's FORCE Row-Level Security on every one of our 44 tenant-scoped tables.
>
> Our audit trail is cryptographically chained — every entry is linked to the one before it with a SHA-256 hash. An auditor can verify the entire trail independently, without trusting our application.
>
> And every deployment we make passes through 36 mandatory tenant isolation tests before a container image is even built. There's no override. No skip button.
>
> We're at 94% SOC 2 coverage and 89% HIPAA today. We can share the full whitepaper and control mapping after this call."

---

### Key Phrases for Different Audiences

**For CISOs:**
> "Isolation is enforced at the database engine level — a single developer error cannot expose tenant data."

**For Security Engineers:**
> "FORCE RLS on all 44 tables, dual database roles with NOBYPASSRLS for the app user, connection pool checkout reset, and a blocking CI/CD isolation gate with 36+ multi-tenant stress tests."

**For GRC / Compliance:**
> "33 of 35 SOC 2 controls satisfied, immutable audit trail with SHA-256 hash chain that any auditor can independently verify, and quarterly DR drills with signed evidence reports."

**For Procurement / Legal:**
> "We can provide our Security Architecture Whitepaper, SOC 2 control mapping, HIPAA safeguard mapping, Information Security Policy, and Incident Response Plan. All available at our Trust Center."

---

### Objection Responses

**"Do you have SOC 2 certification?"**
> "We've mapped 35 SOC 2 controls and satisfy 33 today — 94%. The two partial controls are on our active roadmap. We can share the full control mapping with implementation evidence for each."

**"Is my data in a shared database?"**
> "Yes, and it's isolated by the database engine using PostgreSQL FORCE Row-Level Security — the same mechanism used by Salesforce and Stripe. Even our own admin role is monitored by a runtime guard that blocks unauthorized access during user requests."

**"How do I know your audit logs haven't been tampered with?"**
> "Each entry includes a SHA-256 hash that chains to the previous entry. A database trigger blocks any DELETE or UPDATE. You can export the trail and recompute the chain independently — no trust in our application required."

**"What happens if there's a data breach?"**
> "We have a formal Incident Response Plan. Critical events auto-page on-call within 15 minutes. Customer notification within 48 hours. HIPAA breach filing within 72 hours if applicable. We can share the full IR plan."

---
---

# Appendix: Document Cross-Reference

| Deliverable | Source Material | Use Case |
|-------------|----------------|----------|
| Executive Security Brief | Whitepaper Sec. 1, Appendix A | Board presentations, executive buy-in |
| CISO Deck Outline | Whitepaper (all sections) + Competitive Positioning | Security leadership briefings, technical evaluations |
| Trust Center Structure | Whitepaper + Competitive Positioning + Compliance docs | Self-service prospect enablement, audit support |
| 30-Second Pitch | Whitepaper Sec. 10 + Competitive Positioning Sec. 8 | Live demos, intro calls, elevator pitch |

| Related Document | Location |
|-----------------|----------|
| Security Architecture Whitepaper | `docs/security_architecture_whitepaper.md` |
| Competitive Positioning | `docs/competitive_positioning.md` |
| SOC 2 Control Mapping | `docs/compliance/SOC2.md` |
| HIPAA Safeguard Mapping | `docs/compliance/HIPAA.md` |
| Information Security Policy | `docs/compliance/information_security_policy.md` |
| MFA Policy | `docs/compliance/mfa_policy.md` |
| Incident Response Plan | `docs/compliance/incident_response_plan.md` |
| DR Test Procedure | `docs/compliance/dr_test_procedure.md` |
| Compliance Matrix | `backend/docs/compliance_matrix.md` |
| CIS Benchmarks | `docs/compliance/CIS.md` |
