# Architectural Security Differentiators in Identity Security Platforms

**Document Classification:** Internal — Sales Engineering & Executive Briefing
**Version:** 1.0
**Date:** March 2026
**Audience:** Enterprise Security Buyers, CISOs, Security Engineering Teams

---

## Table of Contents

1. [Introduction: Why Architecture Matters More Than Feature Lists](#1-introduction-why-architecture-matters-more-than-feature-lists)
2. [Differentiator 1: Database-Enforced Isolation vs Application-Layer Filtering](#2-differentiator-1-database-enforced-isolation-vs-application-layer-filtering)
3. [Differentiator 2: Cryptographic Audit Integrity vs Append-Only Logs](#3-differentiator-2-cryptographic-audit-integrity-vs-append-only-logs)
4. [Differentiator 3: Runtime Enforcement vs Trust-Based Code Discipline](#4-differentiator-3-runtime-enforcement-vs-trust-based-code-discipline)
5. [Differentiator 4: Forced Isolation Testing vs Manual QA](#5-differentiator-4-forced-isolation-testing-vs-manual-qa)
6. [Risk Model: Quantifying Architectural Exposure](#6-risk-model-quantifying-architectural-exposure)
7. [Evaluation Framework for Security Buyers](#7-evaluation-framework-for-security-buyers)
8. [Conclusion](#8-conclusion)

---

## 1. Introduction: Why Architecture Matters More Than Feature Lists

Identity security platforms occupy a uniquely sensitive position in the enterprise stack. They ingest, store, and analyze the data that defines who can access what — role assignments, credential metadata, privilege escalation paths, service principal configurations, and blast radius assessments. A breach of an identity security platform does not just expose data; it exposes the map of an organization's entire access surface.

Despite this, most platform evaluations focus on feature checklists: number of integrations, dashboard capabilities, reporting options. These are important, but they do not answer the question that matters most to a CISO:

**If a developer on the vendor's team writes a bug, can that bug expose my tenant's data to another customer?**

The answer depends entirely on architecture — specifically, where in the technology stack tenant isolation, audit integrity, and access control are enforced. A platform with an impressive feature set but application-layer-only security controls carries fundamentally different risk than one that enforces isolation at the database engine level.

This document examines four architectural dimensions where identity security platforms diverge in maturity, and provides a framework for evaluating those differences during procurement.

---

## 2. Differentiator 1: Database-Enforced Isolation vs Application-Layer Filtering

### The Industry Standard: Application-Layer WHERE Clauses

The majority of multi-tenant SaaS platforms implement tenant isolation by appending `WHERE tenant_id = ?` to database queries in application code. This is straightforward to implement and works correctly when applied consistently.

The problem is consistency. Every query, in every endpoint, in every code path — including background jobs, admin tools, data exports, reporting queries, and migration scripts — must include the correct tenant filter. A single omission, a debug session that uses an unscoped connection, or a new feature that queries a table without the filter creates a cross-tenant data leak.

These defects are particularly dangerous because:
- They are **silent** — the application functions correctly from the current user's perspective
- They are **invisible to automated testing** — tests that run against a single-tenant database will never detect a missing WHERE clause
- They are **difficult to detect in code review** — a reviewer must verify the presence of a filter, not the presence of a bug
- They are **cumulative** — every new query is a new opportunity for the filter to be omitted

### The AuditGraph Approach: Engine-Level Enforcement

AuditGraph enforces tenant isolation at the PostgreSQL engine level using Row-Level Security (RLS). The critical difference is **where** the enforcement occurs:

| Dimension | Application-Layer Filtering | Database-Enforced RLS |
|-----------|---------------------------|----------------------|
| **Enforcement point** | Application code (WHERE clause) | Database engine (policy evaluation) |
| **Bypass via application bug** | Yes — omitted filter exposes data | No — database blocks unscoped queries |
| **Bypass via SQL injection** | Yes — injected query has no filter | No — RLS applies to all queries on the connection |
| **Bypass via admin tool / direct query** | Yes — ad-hoc queries are unfiltered | No — FORCE RLS applies even to table owners |
| **Coverage** | Only queries that include the filter | All queries, all code paths, all tools |
| **Developer discipline required** | Every query must be manually filtered | Context set once at connection creation |
| **Failure mode** | Silent data leak | Blocked query + security event |

AuditGraph applies RLS to **44 tenant-scoped tables** and enables **FORCE ROW LEVEL SECURITY** on every one. The FORCE directive is critical — without it, the database role that owns the table can bypass RLS policies entirely, which is the default PostgreSQL behavior. Many platforms that claim RLS enforcement omit FORCE, leaving a significant bypass vector for admin connections and migration scripts.

### Defense in Depth: Five Verification Layers

Rather than relying on a single enforcement point, AuditGraph verifies tenant context at five independent layers:

```
Layer 1: JWT token validation (signed tenant_id in claims)
Layer 2: Host-tenant header verification (subdomain vs token match)
Layer 3: Connection pool checkout reset (clears residual context)
Layer 4: Transaction-scoped session SET (PostgreSQL variable)
Layer 5: RLS policy evaluation (database engine filter on every row)
```

Each layer is independent. A failure at any layer results in a blocked request, not a degraded security posture. The system fails closed — the default state is "no access," not "full access pending a check."

### Dual Database Roles

AuditGraph separates database access into two roles:

- **Application role** (`NOBYPASSRLS`): Used for all tenant-facing operations. Cannot bypass RLS under any circumstances, even with explicit queries.
- **Admin role** (`BYPASSRLS`): Restricted to schema migrations and system health checks. Its use during HTTP request handling is blocked by the Admin Guard (Section 4) and emits a security event.

This prevents a class of incidents where a developer or ORM uses a connection pool configured with an admin-level role, inadvertently bypassing all tenant isolation.

### What to Ask During Evaluation

When evaluating any identity security platform's tenant isolation:

1. **Is isolation enforced at the database engine level, or in application code?** If application code, every query is a potential exposure point.
2. **Is FORCE ROW LEVEL SECURITY enabled?** Standard RLS without FORCE allows the table owner role to bypass policies.
3. **Does the platform use a single database user or separate roles?** A single role with BYPASSRLS negates all RLS protections.
4. **What happens when tenant context is missing?** A mature architecture blocks the query. An immature one returns unfiltered results.

---

## 3. Differentiator 2: Cryptographic Audit Integrity vs Append-Only Logs

### The Industry Standard: "Immutable" by Convention

Most platforms describe their audit logs as immutable. In practice, this typically means:
- No DELETE endpoint is exposed in the API
- Application code only performs INSERTs
- Log records are retained for a configurable period

This is append-only by convention, not by enforcement. The database layer accepts DELETE and UPDATE operations without restriction. The "immutability" depends on:
- No developer adding a DELETE endpoint in a future release
- No SQL injection vulnerability reaching the audit table
- No database administrator running a manual cleanup
- No compromised service account issuing direct SQL

For SOC 2 (CC4.1, CC7.2) and HIPAA (164.312(b)), auditors must determine whether the audit trail can be trusted as evidence. An audit trail that is "immutable because we don't expose a delete button" provides a different level of assurance than one that is "immutable because the database engine rejects modifications."

### The AuditGraph Approach: Engine-Level Immutability + Cryptographic Verification

AuditGraph enforces audit trail integrity at two independent levels:

**Level 1: Database Trigger Enforcement**

A PostgreSQL trigger (`trg_activity_log_immutable`) fires before any DELETE or UPDATE operation on the audit table. The trigger raises an exception, preventing the operation before it reaches the storage engine. This enforcement is:
- Independent of application code (no API change can bypass it)
- Active against direct SQL access (admin terminals, migration scripts, SQL injection)
- Transparent to auditors (the trigger definition is inspectable in the database schema)

**Level 2: SHA-256 Hash Chain**

Each audit entry includes a cryptographic integrity hash computed as:

```
integrity_hash = SHA-256( previous_entry_hash || action_type || description || timestamp )
```

This produces a verifiable chain where each entry's hash depends on every entry that preceded it. The properties of this chain:

| Property | Mechanism |
|----------|-----------|
| **Tamper detection** | Modifying any entry invalidates all subsequent hashes |
| **Insertion detection** | Inserting a record between two entries breaks the chain |
| **Deletion detection** | Removing a record creates a gap in the chain |
| **Independent verification** | Any party with read access can recompute and verify the chain |
| **No trust required** | Verification depends on SHA-256, not on the application's honesty |

### Comparison Matrix

| Dimension | Append-Only Convention | Database Trigger | Trigger + Hash Chain |
|-----------|----------------------|-----------------|---------------------|
| Protection against API misuse | Yes | Yes | Yes |
| Protection against direct SQL | No | **Yes** | **Yes** |
| Protection against admin tampering | No | **Yes** (raises exception) | **Yes** (detectable even if trigger removed) |
| Independent third-party verification | No | Partial (trigger existence) | **Yes** (recompute chain) |
| SOC 2 CC4.1 evidence strength | Weak | Strong | **Strongest** |
| HIPAA 164.312(b) evidence strength | Weak | Strong | **Strongest** |

### Authorized Retention Cleanup

A legitimate concern with immutable audit logs is compliance with data retention policies. AuditGraph handles this through a controlled process:

1. A security event is emitted documenting the start of authorized cleanup
2. The immutable trigger is temporarily disabled (this operation is itself audited)
3. Only records exceeding the configured retention period are deleted
4. The trigger is re-enabled immediately
5. A security event is emitted confirming re-enablement

This process runs as an automated daily job and creates a clear audit trail of its own execution. An auditor can verify that every trigger disable/re-enable cycle corresponds to a retention cleanup event.

### What to Ask During Evaluation

1. **Can a database administrator delete audit log entries with a direct SQL statement?** If yes, the log is append-only by convention, not by enforcement.
2. **Does the platform provide independent verification of audit trail integrity?** A hash chain or digital signature allows any party to verify the trail without trusting the application.
3. **How does the platform handle data retention against immutable logs?** A mature answer involves a controlled process with its own audit trail. An immature answer is "we don't delete audit logs" (which may conflict with data minimization requirements).

---

## 4. Differentiator 3: Runtime Enforcement vs Trust-Based Code Discipline

### The Industry Standard: Rely on Developers

The prevailing security model in SaaS development is:
- Code reviews catch security defects
- Static analysis tools flag common patterns
- Security training teaches developers best practices
- Penetration testing finds what reviews and tools miss

These are valuable practices. They are also insufficient for a platform that processes identity security data. The gap is not in the tooling — it is in the model. Trust-based security assumes that every developer, in every commit, will follow every security guideline, and that reviewers will catch every deviation. It is a model that depends on humans never making mistakes.

The failure modes are well-documented in post-incident analyses across the industry:
- A developer uses an admin database connection "temporarily" during debugging, and the code reaches production
- A background job iterates across tenants but initializes the database connection outside the loop, retaining the previous tenant's context
- A connection pool returns a connection that retains session state from a previous request
- An ORM generates a query without the expected tenant filter because of a missing model configuration

### The AuditGraph Approach: Enforcement Independent of Developer Intent

AuditGraph implements three runtime enforcement mechanisms that operate regardless of what the developer intends:

**Admin Guard.** If code creates a database connection that bypasses RLS (an admin-level connection) while handling an HTTP request, the operation is blocked at runtime. Not flagged. Not logged for later review. Blocked. A `ADMIN_GUARD_BLOCKED` security event is emitted immediately. The developer must explicitly declare an `_admin_reason` to use the admin connection, and that declaration is auditable.

**Tenant Context Verification.** Before every query executed through the safe execution path, the system verifies that the PostgreSQL session variable matches the expected tenant. If the context was lost (connection pool issue), mismatched (logic error), or never set (initialization failure), the query is not executed. A `TENANT_CONTEXT_VIOLATION` critical security event is emitted with the specific violation type.

**Connection Pool Reset.** Every connection checkout from the pool executes `RESET app.current_organization_id` before the connection is handed to the requesting code. This eliminates residual tenant context from a previous request. Additionally, AuditGraph detects PgBouncer in session mode at startup and refuses to run — session-mode PgBouncer can leak `SET LOCAL` variables across transactions, which would compromise the entire RLS enforcement chain.

### Comparison: Where Defects Are Caught

| Defect Class | Trust-Based (Code Review) | Runtime Enforcement |
|-------------|--------------------------|-------------------|
| Missing tenant filter in query | Caught if reviewer notices | **Caught by RLS policy — query returns no data** |
| Admin connection in request handler | Caught if reviewer notices | **Blocked by Admin Guard — operation rejected** |
| Stale tenant context on pooled connection | Almost never caught in review | **Caught by checkout reset — context cleared** |
| Background job with wrong tenant context | Caught in integration testing (maybe) | **Caught by verify_tenant_context — query rejected** |
| Connection pool proxy leaking state | Never caught in code review | **Caught by PgBouncer detection — startup fails** |

The difference is not that trust-based approaches fail to catch some defects. The difference is that runtime enforcement catches them **at the moment they would cause harm**, not at an earlier stage where the detection depends on human attention.

### What to Ask During Evaluation

1. **What happens if a developer accidentally uses an admin-level database connection in a user-facing endpoint?** A runtime enforcement answer is "the operation is blocked." A trust-based answer is "our code review process would catch that."
2. **How does the platform prevent connection pool state leakage between tenants?** Look for explicit reset-on-checkout behavior, not "we trust the pool library to manage state."
3. **Is there a single execution path for all database queries, or can developers bypass it?** A single `execute_safe()` path with pre-query verification is structurally safer than scattered `cursor.execute()` calls where each developer must remember to verify context.

---

## 5. Differentiator 4: Forced Isolation Testing vs Manual QA

### The Industry Standard: Test What You Build

Most SaaS platforms test tenant isolation through:
- Unit tests that verify WHERE clauses are present
- Integration tests that query the database with a known tenant and verify results
- Periodic penetration testing by an external firm

This approach has three structural weaknesses:

**1. Coverage depends on what developers write.** If a developer adds a new endpoint and forgets to add an isolation test, the endpoint ships without isolation verification. Test coverage is opt-in, not enforced.

**2. Single-tenant test databases miss cross-tenant bugs.** Most test environments contain data for one tenant. A query that returns all rows without a tenant filter passes with flying colors — because all rows belong to the test tenant. The bug is invisible until a second tenant's data exists.

**3. Tests run when developers choose to run them.** If the CI pipeline doesn't mandate isolation tests before deployment, a broken commit can reach production between test runs.

### The AuditGraph Approach: Mandatory Isolation Gate in CI/CD

AuditGraph's deployment pipeline includes a `test-guardrails` job that must pass before any container image is built. This is not a recommended step or a nightly job — it is a blocking gate. No exceptions. No manual override.

The gate includes:

```
test-guardrails (blocking)
├── pip-audit — dependency CVE scan (strict mode)
├── Isolation stress tests (36+ tests)
│   ├── Concurrent multi-tenant queries
│   ├── Connection pool context isolation under load
│   ├── Cross-tenant data access attempts (must return 0 rows)
│   └── Tenant context leak detection on pooled connections
└── Production guardrail tests
    ├── FORCE RLS enabled on all 44 tables
    ├── Admin Guard blocks unscoped admin connections
    └── Pool management returns safe connections
```

**If any test fails, the pipeline stops.** The backend and frontend images are not built, not pushed to the container registry, and not deployed. A developer cannot ship code that breaks tenant isolation, even accidentally.

### Post-Deployment Validation

After deployment, the pipeline performs readiness polling:
- 12 health check attempts at 10-second intervals (120-second timeout)
- Readiness probe returns 503 during active schema migrations (prevents traffic routing to a partially-migrated database)
- Detailed health endpoint verifies database connectivity, RLS configuration, and migration status

### Nightly Drift Detection

Even after deployment passes all gates, AuditGraph runs a nightly audit at 04:30 UTC that verifies FORCE ROW LEVEL SECURITY remains enabled on all 44 tables. This catches drift caused by manual database changes, infrastructure modifications, or backup restoration that may have altered RLS configuration. If drift is detected, a `RLS_DRIFT_DETECTED` critical security event triggers immediate notification.

### Comparison Matrix

| Dimension | Manual QA / Periodic Testing | Mandatory CI/CD Gate + Nightly Audit |
|-----------|------------------------------|-------------------------------------|
| **Test coverage** | Opt-in (depends on developer) | Enforced (36+ isolation tests) |
| **Multi-tenant test data** | Often single-tenant databases | Multi-tenant concurrent stress tests |
| **Deploy without passing tests** | Often possible (skip CI) | **Impossible (blocking gate)** |
| **Post-deploy drift detection** | Not typically implemented | **Nightly FORCE RLS verification** |
| **Dependency vulnerability scanning** | Periodic (quarterly pen test) | **Every deployment (pip-audit --strict)** |
| **Time to detect isolation regression** | Days to weeks (next pen test) | **Minutes (next deploy attempt)** |

### What to Ask During Evaluation

1. **Can an engineer deploy code that hasn't passed tenant isolation tests?** If the CI pipeline allows skipping tests, the gate is advisory, not enforced.
2. **Are isolation tests run against a multi-tenant database, or single-tenant?** Single-tenant test databases cannot detect missing WHERE clauses.
3. **What happens if FORCE RLS is accidentally disabled on a table after deployment?** A nightly drift audit detects this. Without drift detection, the regression persists until the next security review.

---

## 6. Risk Model: Quantifying Architectural Exposure

### The Cross-Tenant Exposure Surface

The risk of a cross-tenant data leak can be modeled as a function of the number of unprotected access paths in the system. Each access path — a database query, an API endpoint, a background job, an admin tool — is a potential exposure point if tenant isolation depends on application-layer enforcement.

**Application-Layer Filtering Model:**

```
Exposure probability per query = P(developer omits filter)
Exposure probability per release = 1 - (1 - P)^N

Where N = number of database queries across all code paths
```

For a platform with 500 distinct queries, even a 0.1% per-query omission rate produces:

```
P(at least one unfiltered query) = 1 - (1 - 0.001)^500 = 39.4%
```

Over multiple releases, the cumulative probability approaches certainty. This is not a reflection of developer quality — it is a mathematical property of a model that requires perfection across every query.

**Database-Enforced RLS Model:**

```
Exposure probability per query = P(RLS policy is disabled on the table)
                               × P(FORCE RLS is disabled)
                               × P(nightly drift audit fails to detect)

= P(RLS disabled) × P(FORCE disabled) × P(audit miss)
```

For a platform with FORCE RLS on all tables and nightly drift auditing:

```
P(exposure) ≈ P(manual schema change) × P(drift undetected for >24h)
```

This is a fundamentally different risk surface. The exposure requires multiple independent failures in infrastructure-level controls, not a single omission in application code.

### Audit Trail Integrity Risk

**Append-Only Convention:**

```
P(trail tampered) = P(SQL injection reaches audit table)
                  + P(compromised DB credentials)
                  + P(insider with DB access)
                  + P(backup restore overwrites entries)
```

Each vector is independent and difficult to eliminate entirely.

**Trigger + Hash Chain:**

```
P(trail tampered undetected) = P(trigger disabled)
                              × P(hash chain not verified)
                              × P(security event suppressed)
```

The hash chain provides an independent verification mechanism that operates even if the trigger is temporarily disabled. An auditor who recomputes the chain from the first entry will detect any modification, regardless of the application's state at the time of tampering.

### Architectural Maturity Tiers

| Tier | Tenant Isolation | Audit Integrity | Runtime Safety | CI/CD Gate | Platforms |
|------|-----------------|----------------|----------------|------------|-----------|
| **Tier 1** | Application WHERE clauses | Append-only API | Code review | Optional tests | Most SaaS platforms |
| **Tier 2** | RLS (without FORCE) | Database trigger | Linter rules | Mandatory unit tests | Security-focused SaaS |
| **Tier 3** | FORCE RLS + dual roles + context verification | Trigger + hash chain | Runtime enforcement + Admin Guard | Blocking isolation gate + drift audit | AuditGraph |

The difference between tiers is not feature count — it is the number of independent failures required for a security incident to occur. Tier 1 requires one developer error. Tier 3 requires multiple infrastructure-level failures occurring simultaneously and remaining undetected through nightly audits.

---

## 7. Evaluation Framework for Security Buyers

### Vendor Assessment Questionnaire

The following questions are designed to surface architectural differences during procurement. They focus on mechanisms, not marketing claims.

#### Tenant Isolation

| # | Question | Strong Answer | Weak Answer |
|---|----------|--------------|-------------|
| 1 | Where is tenant isolation enforced? | Database engine (RLS) | Application code (WHERE clauses) |
| 2 | Is FORCE ROW LEVEL SECURITY enabled? | Yes, on all tenant-scoped tables | "We use RLS" (without FORCE) |
| 3 | How many database roles are used? | Separate app (NOBYPASSRLS) and admin (BYPASSRLS) | Single role for all operations |
| 4 | What happens when tenant context is missing? | Query is blocked, security event emitted | "It depends on the endpoint" |
| 5 | Can a developer bypass isolation in a code path? | No — RLS enforces regardless of code | "Our review process catches that" |

#### Audit Trail

| # | Question | Strong Answer | Weak Answer |
|---|----------|--------------|-------------|
| 6 | Can audit entries be deleted via direct SQL? | No — trigger blocks DELETE | "We don't expose a delete endpoint" |
| 7 | Can integrity be verified independently? | Yes — recompute hash chain | "Our audit log is append-only" |
| 8 | How is data retention handled against immutability? | Controlled process with its own audit trail | "We don't delete audit logs" |

#### Runtime Safety

| # | Question | Strong Answer | Weak Answer |
|---|----------|--------------|-------------|
| 9 | What prevents an admin connection in a user request? | Runtime guard blocks it, emits security event | "Developers know not to do that" |
| 10 | How is connection pool state managed between tenants? | Explicit RESET on every checkout | "The pool library handles that" |
| 11 | Is there a single execution path for all queries? | Yes — `execute_safe()` with pre-query verification | "Developers use the ORM" |

#### CI/CD Security

| # | Question | Strong Answer | Weak Answer |
|---|----------|--------------|-------------|
| 12 | Can code deploy without passing isolation tests? | No — blocking gate, no override | "Tests run nightly" |
| 13 | Are isolation tests multi-tenant? | Yes — concurrent cross-tenant stress tests | "We test with a single tenant" |
| 14 | Is post-deploy isolation drift detected? | Yes — nightly FORCE RLS audit | "We check during pen tests" |
| 15 | Are dependencies scanned for CVEs before deploy? | Yes — pip-audit in strict mode, every build | "We run Dependabot" |

### Scoring Guidance

| Score | Criteria |
|-------|----------|
| **Enterprise-ready** | Database-enforced isolation + cryptographic audit + runtime enforcement + mandatory CI/CD gate |
| **Adequate** | RLS without FORCE + append-only audit + code review discipline + optional CI tests |
| **Insufficient for regulated industries** | Application-layer filtering only + no audit integrity verification + trust-based security model |

---

## 8. Conclusion

Identity security platforms process data that defines an organization's attack surface. The platform's own security architecture is not a secondary consideration — it is a prerequisite for trusting the platform's output.

The four architectural dimensions examined in this document — tenant isolation, audit integrity, runtime enforcement, and isolation testing — represent the difference between platforms that are secure by convention and platforms that are secure by construction.

**Secure by convention** means the platform works correctly when every developer follows every guideline, every code review catches every omission, and no infrastructure change drifts from the expected state. It is a model that works until it doesn't, and the failure is typically silent.

**Secure by construction** means the database engine blocks cross-tenant queries regardless of application code. Audit log modifications are rejected by the storage layer and detectable by cryptographic verification. Admin-level connections are blocked at runtime during user requests. Tenant isolation is tested as a mandatory deployment gate, not an optional quality check. Configuration drift is detected within 24 hours, not during the next penetration test.

For organizations operating under SOC 2, HIPAA, or other regulatory frameworks, the distinction matters. Auditors are increasingly asking not just "do you have controls?" but "where are those controls enforced?" A control that depends on developer discipline is not the same as a control enforced by the database engine, and compliance evidence that requires trusting the application is not the same as evidence that can be independently verified by recomputing a hash chain.

The question for enterprise security buyers is not which platform has the most features. It is which platform's architecture ensures that a single human error cannot compromise tenant isolation, a compromised credential cannot silently tamper with the audit trail, and a missed code review cannot ship a cross-tenant data leak to production.

Architecture is the answer that survives contact with reality.

---

## Appendix: AuditGraph Architecture Summary

| Dimension | Mechanism | Enforcement Level |
|-----------|-----------|------------------|
| Tenant Isolation | FORCE RLS on 44 tables, dual DB roles, 5-layer context verification, auto-fill triggers | Database engine |
| Audit Integrity | Immutable trigger (blocks DELETE/UPDATE) + SHA-256 hash chain | Database engine |
| Runtime Safety | Admin Guard, verify_tenant_context(), connection pool reset, PgBouncer detection | Application runtime |
| CI/CD Security | Blocking isolation gate (36+ tests), pip-audit, Dependabot, readiness polling | Pipeline |
| Drift Detection | Nightly FORCE RLS audit on all 44 tables, critical security event on drift | Scheduled |
| Monitoring | 10 structured security event types, Slack/Teams/PagerDuty routing | Application |
| DR | RPO < 5 min (WAL), RTO < 30 min (PITR), quarterly drills with evidence | Infrastructure |
| Compliance | SOC 2: 33/35 satisfied (94%) — HIPAA: 16/18 satisfied (89%) | Documented |
