# Information Security Policy — AuditGraph

**Version:** 1.0
**Effective Date:** 2026-03-03
**Classification:** Internal — Confidential
**Owner:** Security Engineering
**Review Cadence:** Annual (next review: 2027-03-03)

---

## 1. Executive Summary

This Information Security Policy establishes the security controls, governance framework, and operational procedures that protect AuditGraph's SaaS platform, customer data, and infrastructure. It is aligned to **SOC 2 Type II Trust Services Criteria** and **HIPAA Technical Safeguards**, and references the specific technical controls implemented in the AuditGraph codebase.

AuditGraph is a cloud identity security posture management platform that ingests, analyzes, and reports on customer identity configurations across Azure AD, AWS IAM, and GCP IAM. Given the sensitivity of the identity data processed, this policy enforces defense-in-depth across all layers.

### Compliance Posture Summary

| Framework | Controls Mapped | Status |
|-----------|----------------|--------|
| SOC 2 TSC | 35 controls | 31 satisfied, 4 partial |
| HIPAA | 18 safeguards | 15 satisfied, 3 partial |
| CIS Azure | 12 storage + 10 KV benchmarks | Automated scanning |

---

## 2. Access Control

### 2.1 Authentication

**Control:** CC6.1 (SOC 2), 164.312(d) (HIPAA)

AuditGraph implements layered authentication:

| Mechanism | Implementation | Token Lifetime |
|-----------|---------------|----------------|
| JWT (client portal) | `CLIENT_JWT_SECRET`, PyJWT + bcrypt | 30 min access / 7 day refresh |
| JWT (admin portal) | `ADMIN_JWT_SECRET`, separate key pair | 60 min access / 7 day refresh |
| SAML 2.0 SSO | python3-saml, IdP-delegated MFA | One-time code (60s) → JWT |
| API Keys | `ag_` prefix, SHA-256 hashed in DB | No expiry (admin-revocable) |
| Service Principal | Azure AD certificate/secret | Per-credential expiry |

**Code References:**
- `backend/app/api/auth.py` — JWT issuance, refresh rotation, portal isolation
- `backend/app/api/saml.py` — SAML SP configuration, ACS endpoint
- `backend/app/api/handlers.py` — API key validation, usage tracking

### 2.2 Authorization (RBAC)

**Control:** CC6.3 (SOC 2), 164.312(a)(1) (HIPAA)

Four-role client RBAC:
| Role | Permissions |
|------|------------|
| `admin` | Full CRUD, user management, settings, SSO config |
| `security_admin` | Read + remediation execution, no user management |
| `compliance` | Read + compliance reports, no remediation |
| `reader` | Read-only across all resources |

Four-role admin portal RBAC:
| Role | Permissions |
|------|------------|
| `superadmin` | Full platform control, tenant CRUD, cross-tenant access |
| `poweradmin` | Tenant management, provisioning, no billing |
| `billing` | Billing and subscription management only |
| `reader` | Read-only admin dashboard access |

**Enforcement:** `@require_role()` and `@require_portal_role()` decorators on every endpoint.

### 2.3 Multi-Tenant Isolation

**Control:** CC6.1 (SOC 2), 164.312(a)(1) (HIPAA)

AuditGraph enforces tenant isolation at the database layer using PostgreSQL Row-Level Security:

- **44 tables** have `tenant_id NOT NULL` with strict RLS policies
- **FORCE ROW LEVEL SECURITY** enabled on all tenant-scoped tables
- **Dual database users:** `auditgraph_app` (NOBYPASSRLS) for tenant operations, `auditgraph_admin` (BYPASSRLS) for system/DDL
- **Session context:** `SET app.current_tenant_id = N` before every tenant query
- **Auto-fill trigger:** `trg_auto_tenant_id` fills tenant_id from session context; raises exception if both NULL
- **Drift detection:** Startup validates FORCE RLS is still enabled on all tables

**Code References:**
- `backend/app/database.py` — `Database(tenant_id=N)` sets RLS context
- Migration 017 — strict RLS policies, NOT NULL enforcement, auto-fill triggers
- `backend/app/security_events.py` — `TENANT_CONTEXT_VIOLATION`, `RLS_DRIFT_DETECTED` events

---

## 3. Data Protection

### 3.1 Encryption

**Control:** CC6.7 (SOC 2), 164.312(a)(2)(iv), 164.312(e)(1) (HIPAA)

| Layer | Mechanism |
|-------|-----------|
| In transit (API) | TLS 1.2+ via Azure Container Apps ingress, HSTS headers |
| In transit (DB) | `DB_SSLMODE=require` for Azure PostgreSQL |
| At rest (DB) | Azure-managed encryption (AES-256) on Flexible Server |
| At rest (blobs) | Azure Storage SSE with Microsoft-managed keys |
| Secrets | Environment injection via Container Apps secret references |

**Code References:**
- `backend/app/security.py` — `add_security_headers()` (HSTS, CSP, X-Frame-Options)
- `backend/app/database.py` — SSL mode configuration
- `backend/app/config.py` — Secret injection pattern documentation

### 3.2 Secret Management

**Control:** CC6.1 (SOC 2)

Secrets are never stored in source code or committed `.env` files:
- Production: Azure Container Apps injects secrets as environment variables
- Local dev: `.env.local` with localhost-only values (safety guard blocks Azure URLs)
- CI/CD: GitHub Actions secrets for ACR credentials, Azure service principal
- Logging: `SecretRedactionFilter` masks passwords, Bearer tokens, API keys, connection strings

**Code References:**
- `backend/app/logging_config.py` — `SecretRedactionFilter`, `redact_secrets()`
- `backend/app/config.py` — `SAFETY GUARD` RuntimeError for Azure URLs in local mode

### 3.3 Data Classification

| Classification | Examples | Controls |
|---------------|----------|----------|
| Critical | DB credentials, JWT secrets, API keys | Secret injection, redaction, SHA-256 hashing |
| Confidential | Identity configurations, role assignments, risk scores | RLS isolation, encrypted transit/rest |
| Internal | Activity logs, discovery run metadata | Append-only audit trail, retention policies |
| Public | Health endpoints, API documentation | No authentication required |

---

## 4. Audit & Monitoring

### 4.1 Audit Trail Immutability

**Control:** CC4.1, CC7.2 (SOC 2), 164.312(b) (HIPAA)

The `activity_log` table is protected by a PostgreSQL trigger (`trg_activity_log_immutable`) that:
- **Blocks DELETE** operations (raises exception)
- **Blocks UPDATE** operations (raises exception)
- Only INSERT is permitted
- Authorized retention cleanup temporarily disables the trigger with audit logging

Each activity log entry includes an `integrity_hash` (SHA-256 chain linking to predecessor), providing tamper-evidence.

**Code References:**
- `backend/app/database.py` — `_ensure_activity_log_table()`, `log_activity()` hash chain
- `backend/app/database.py` — `cleanup_old_activity_log()` trigger disable/re-enable

### 4.2 Structured Security Events

**Control:** CC7.2, CC7.3 (SOC 2), 164.312(b) (HIPAA)

`SecurityEventLogger` emits machine-parseable JSON events for 10 event types:

| Event | Severity | Trigger |
|-------|----------|---------|
| `TENANT_CONTEXT_VIOLATION` | Critical | RLS context lost or mismatched |
| `RLS_DRIFT_DETECTED` | Critical | FORCE RLS or policy removed |
| `ADMIN_GUARD_BLOCKED` | High | Unauthorized admin DB access in request |
| `POOL_EXHAUSTION` | High | Connection pool at capacity |
| `SLOW_QUERY` | Medium | Query exceeds threshold |
| `TENANT_SKEW` | Medium | Tenant consuming >25% of resources |
| `AUTH_FAILURE` | Medium | Failed login or expired token |
| `AUTH_SUCCESS` | Info | Successful authentication |
| `SECRET_ROTATION` | Info/High | Credential rotation success/failure |
| `MIGRATION_APPLIED` | Info | Schema migration completed |

**Code Reference:** `backend/app/security_events.py`

### 4.3 Audit Export

Authorized administrators can export audit trails via `GET /api/audit/export`:
- Formats: CSV and JSON
- Filters: date range, action type
- Includes integrity hash chain metadata for verification
- Requires `admin` role

---

## 5. Infrastructure Security

### 5.1 Deployment Architecture

```
Internet → Azure Front Door (WAF) → Container Apps Environment
                                         ├── auditgraph-api (gunicorn, 2 workers)
                                         └── auditgraph-web (nginx:alpine)
                                                ↓
                                     Azure PostgreSQL Flexible Server
                                         (FORCE RLS, encrypted, SSL)
```

### 5.2 Network Security

| Control | Implementation |
|---------|---------------|
| Ingress | Azure Container Apps managed ingress (TLS termination) |
| CORS | Restricted to `app.auditgraph.ai`, `admin.auditgraph.ai` |
| Security headers | HSTS, CSP, X-Content-Type-Options, X-Frame-Options |
| Rate limiting | Per-endpoint throttling on auth endpoints |

### 5.3 CI/CD Security

**Control:** CC8.1 (SOC 2)

The deployment pipeline (`.github/workflows/deploy.yml`) enforces:

1. **Isolation test gate** (`test-guardrails` job) — runs tenant isolation and production guardrail tests; blocks build on failure
2. **Dependency scanning** (`pip-audit`) — scans for known CVEs in Python dependencies
3. **Dependabot** — automated weekly PRs for dependency updates (pip, npm, GitHub Actions)
4. **Readiness polling** — post-deploy health check (12 attempts × 10s) before declaring success
5. **ACR image tagging** — images tagged with commit SHA for traceability

### 5.4 Connection Pool Management

- Pooled connections with configurable `DB_POOL_SIZE` (default: 20)
- Low-water-mark alerting at <10% available connections
- PgBouncer session mode detection (fatal error)
- Tenant skew detection across 6 major tables

---

## 6. Incident Response & Business Continuity

### 6.1 Incident Classification

See: `docs/compliance/incident_response_plan.md`

Security events from `SecurityEventLogger` are classified into 4 severity levels:
- **P1 (Critical):** Tenant isolation breach, RLS drift, data exposure
- **P2 (High):** Admin guard bypass, pool exhaustion, auth system failure
- **P3 (Medium):** Slow queries, tenant skew, individual auth failures
- **P4 (Low/Info):** Successful operations, migrations, rotations

### 6.2 Business Continuity

See: `docs/compliance/dr_test_procedure.md`

| Metric | Target |
|--------|--------|
| RPO (Recovery Point Objective) | < 5 minutes (continuous WAL archiving) |
| RTO (Recovery Time Objective) | < 30 minutes (PITR + redeploy + DNS + validation) |
| Backup frequency | Continuous WAL + daily full snapshot |
| DR drill cadence | Quarterly |

### 6.3 Data Retention

Configurable retention periods per data type:
- Discovery runs: 90 days (default)
- Drift reports: 90 days
- Activity logs: 365 days
- Anomalies: 180 days
- SOAR actions: 180 days
- Notifications: 30 days

Automated cleanup runs daily at 03:00 UTC via scheduler. Immutable audit trigger temporarily disabled with audit trail during authorized cleanup.

---

## Appendix A: Regulatory Cross-Reference

| This Policy Section | SOC 2 TSC | HIPAA |
|--------------------|-----------|-------|
| 2.1 Authentication | CC6.1, CC6.6 | 164.312(d) |
| 2.2 Authorization | CC6.3 | 164.312(a)(1) |
| 2.3 Tenant Isolation | CC6.1 | 164.312(a)(1) |
| 3.1 Encryption | CC6.7 | 164.312(a)(2)(iv), 164.312(e)(1) |
| 3.2 Secret Management | CC6.1 | — |
| 4.1 Audit Immutability | CC4.1, CC7.2 | 164.312(b) |
| 4.2 Security Events | CC7.2, CC7.3 | 164.312(b) |
| 5.3 CI/CD Security | CC8.1 | — |
| 6.1 Incident Response | CC7.3, CC7.4 | 164.308(a)(6) |
| 6.2 Business Continuity | A1.2, A1.3 | 164.308(a)(7) |

## Appendix B: Evidence Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| `activity_log` table | PostgreSQL | Immutable user activity audit trail |
| `admin_audit_log` table | PostgreSQL | Admin mutation tracking |
| `billing_events` table | PostgreSQL | Billing change history |
| `integrity_hash` column | `activity_log` | SHA-256 tamper-evidence chain |
| Structured JSON logs | Container Apps Log Analytics | Security events, request traces |
| `deploy.yml` | GitHub Actions | CI/CD pipeline with test gates |
| `dependabot.yml` | GitHub | Automated dependency updates |
| Migration history | `schema_migrations` table | Schema change tracking |

## Appendix C: Policy Review & Approval

| Role | Responsibility |
|------|---------------|
| Security Engineering | Policy authorship, technical control implementation |
| CTO | Policy approval, exception authorization |
| Compliance Officer | Annual review, audit liaison |
| All Engineers | Policy adherence, incident reporting |

**Revision History:**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-03 | Security Engineering | Initial policy |
