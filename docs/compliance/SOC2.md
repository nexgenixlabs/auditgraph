# SOC 2 Type II Compliance — AuditGraph

**Version:** 2.0
**Last Updated:** 2026-03-03
**Parent Policy:** `information_security_policy.md`

## Compliance Summary

| Category | Controls | Satisfied | Partial | Gap |
|----------|----------|-----------|---------|-----|
| Security (CC6) | 12 | 11 | 1 | 0 |
| Availability (A1) | 4 | 3 | 1 | 0 |
| Confidentiality (C1) | 5 | 5 | 0 | 0 |
| Processing Integrity (PI1) | 4 | 4 | 0 | 0 |
| Monitoring (CC7) | 5 | 5 | 0 | 0 |
| Change Management (CC8) | 3 | 3 | 0 | 0 |
| Risk Assessment (CC3) | 2 | 2 | 0 | 0 |
| **Total** | **35** | **33** | **2** | **0** |

---

## Security (CC6) — Logical & Physical Access

### CC6.1 — Logical Access Security
**Status:** SATISFIED
- JWT authentication with dual portal isolation (admin/client separate secrets)
- RBAC: 4 client roles (admin, security_admin, compliance, reader)
- RBAC: 4 admin portal roles (superadmin, poweradmin, billing, reader)
- API key management: `ag_` prefix, SHA-256 hashed, role-scoped, usage tracking
- Rate limiting on authentication endpoints
- **Evidence:** `auth.py`, `handlers.py` (API key validation), `activity_log`

### CC6.2 — Access Review
**Status:** SATISFIED
- User management UI with role assignment
- API key lifecycle (create/edit/toggle/delete) with admin-only access
- Activity log tracks all role changes and user modifications
- **Evidence:** `activity_log` entries with action_type `user_updated`, `api_key_*`

### CC6.3 — Access Provisioning
**Status:** SATISFIED
- SSO/SAML 2.0 with JIT (Just-In-Time) user provisioning
- IdP group → AuditGraph role mapping
- `force_sso` setting to disable local authentication
- Superadmin impersonation logged to `admin_audit_log`
- **Evidence:** `saml.py`, `sso_auth_codes` table, `mfa_policy.md`

### CC6.4 — Access Restriction to System Components
**Status:** SATISFIED
- Multi-tenant PostgreSQL RLS on 44 tables (FORCE ROW LEVEL SECURITY)
- Dual DB users: `auditgraph_app` (NOBYPASSRLS) / `auditgraph_admin` (BYPASSRLS)
- Host↔Tenant subdomain guard in auth middleware
- Admin guard prevents unauthorized `Database()` in request context
- **Evidence:** Migration 017, `database.py`, `TENANT_CONTEXT_VIOLATION` events

### CC6.5 — Logical Access Removal
**Status:** SATISFIED
- User deletion endpoints (admin-only)
- API key revocation (toggle/delete)
- SSO deprovisioning via IdP (user removed from IdP → no AuditGraph access)
- JWT refresh token rotation (old tokens invalidated)
- **Evidence:** User CRUD handlers, API key handlers

### CC6.6 — Authentication Mechanisms
**Status:** SATISFIED
- Password policy: 12-char minimum, uppercase/lowercase/digit/special, blocklist
- JWT with short-lived access tokens (30/60 min) + refresh rotation (7 day)
- SAML 2.0 SSO with IdP-delegated MFA
- One-time auth codes (60s TTL) for SSO callback
- **Evidence:** `security.py:validate_password()`, `auth.py`, `mfa_policy.md`

### CC6.7 — Encryption
**Status:** SATISFIED
- TLS 1.2+ in transit (Azure Container Apps ingress, HSTS headers)
- DB connections: `DB_SSLMODE=require`
- At rest: Azure-managed AES-256 encryption
- Secrets: Container Apps secret injection, log redaction
- **Evidence:** `security.py:add_security_headers()`, `logging_config.py:SecretRedactionFilter`

### CC6.8 — Malicious Software Prevention
**Status:** SATISFIED
- Dependabot automated dependency updates (pip, npm, GitHub Actions)
- `pip-audit` in CI pipeline — scans for known CVEs before build
- Container images from official bases (python:3.11-slim, nginx:alpine)
- **Evidence:** `.github/dependabot.yml`, `deploy.yml` (pip-audit step)

---

## Availability (A1) — System Availability

### A1.1 — Availability Commitments
**Status:** SATISFIED
- Health endpoints: `/health` (liveness), `/health/ready` (readiness), `/api/health` (detailed)
- Migration-aware readiness probe (returns 503 during DDL)
- Post-deploy health verification in CI/CD pipeline
- **Evidence:** `main.py` health routes, `deploy.yml` readiness polling

### A1.2 — DR Recovery
**Status:** SATISFIED
- RPO < 5 minutes (continuous WAL archiving)
- RTO < 30 minutes (PITR + redeploy)
- Quarterly DR drill procedure documented
- **Evidence:** `dr_test_procedure.md`, `config.py` blueprint

### A1.3 — Backup & Restore
**Status:** PARTIAL
- Azure PostgreSQL automated backups (35-day retention)
- Continuous WAL archiving for point-in-time recovery
- **Gap:** No automated backup verification (manual quarterly drill only)
- **Evidence:** Azure PostgreSQL Flexible Server configuration

---

## Confidentiality (C1)

### C1.1 — Confidential Information Identification
**Status:** SATISFIED
- Data classification in `information_security_policy.md` (Critical/Confidential/Internal/Public)
- Secret redaction in logs (passwords, tokens, API keys, connection strings)
- **Evidence:** `logging_config.py:SecretRedactionFilter`

### C1.2 — Confidential Information Disposal
**Status:** SATISFIED
- Automated data retention with configurable periods per data type
- Daily cleanup job at 03:00 UTC
- Immutable audit trigger temporarily disabled with full audit trail during cleanup
- **Evidence:** `database.py:cleanup_old_*()` methods, retention settings

---

## Monitoring (CC7) — System Monitoring

### CC7.1 — Monitoring Infrastructure
**Status:** SATISFIED
- Structured JSON logging with request correlation (X-Request-ID)
- `SecurityEventLogger` with 10 event types
- Pool utilization monitoring with low-water-mark alerting
- Tenant skew detection across 6 major tables
- **Evidence:** `security_events.py`, `logging_config.py`, `database.py`

### CC7.2 — Monitoring Activities
**Status:** SATISFIED
- `activity_log` table: append-only, immutable (PostgreSQL trigger)
- `admin_audit_log` table: all admin mutations
- `billing_events` table: billing change history
- Anomaly detection engine: 6+ anomaly types
- Integrity hash chain (SHA-256) for tamper-evidence
- **Evidence:** `database.py:log_activity()`, `trg_activity_log_immutable`

### CC7.3 — Anomaly Detection
**Status:** SATISFIED
- AnomalyDetector engine: permission_escalation, risk_score_spike, dormant_reactivation, credential_surge, off_hours_pim, excessive_pim_usage
- Security events classify anomalies by severity
- Dashboard widgets for real-time anomaly visibility
- **Evidence:** Anomaly API endpoints, `security_events.py`

---

## Change Management (CC8)

### CC8.1 — Change Authorization
**Status:** SATISFIED
- GitHub PR workflow required for all code changes
- CI/CD test gate (isolation tests + production guardrails) blocks builds on failure
- Dependabot automates dependency updates with PR review
- `pip-audit` scans for CVEs before image build
- **Evidence:** `deploy.yml`, `dependabot.yml`, `test_production_guardrails.py`

---

## Evidence Artifacts

| Artifact | Type | Retention |
|----------|------|-----------|
| `activity_log` | Database table | 365 days |
| `admin_audit_log` | Database table | Permanent |
| `billing_events` | Database table | Permanent |
| `integrity_hash` chain | Column on activity_log | 365 days |
| GitHub Actions logs | CI/CD | 90 days |
| Container Apps logs | Application | Azure Log Analytics retention |
| `schema_migrations` | Database table | Permanent |
