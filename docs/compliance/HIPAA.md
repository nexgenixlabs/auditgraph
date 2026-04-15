# HIPAA Compliance — AuditGraph

**Version:** 2.0
**Last Updated:** 2026-03-03
**Parent Policy:** `information_security_policy.md`

## Compliance Summary

| Safeguard Category | Controls | Satisfied | Partial |
|-------------------|----------|-----------|---------|
| Administrative (164.308) | 6 | 5 | 1 |
| Technical (164.312) | 8 | 7 | 1 |
| Organizational (164.314) | 4 | 4 | 0 |
| **Total** | **18** | **16** | **2** |

---

## Administrative Safeguards (164.308)

### 164.308(a)(1) — Security Management Process
**Status:** SATISFIED
- Information Security Policy documented (`information_security_policy.md`)
- Risk assessment with heat map (`compliance_matrix.md`)
- Anomaly detection engine (6 types) for ongoing risk identification
- Quarterly DR drills with evidence collection
- **Evidence:** `compliance_matrix.md`, `security_events.py`, `dr_test_procedure.md`

### 164.308(a)(3) — Workforce Security
**Status:** SATISFIED
- RBAC with 4 client roles + 4 admin portal roles
- JIT provisioning via SSO (users created only when IdP authenticates)
- User termination: delete endpoint + SSO deprovisioning
- Role changes logged to `activity_log`
- **Evidence:** `auth.py` RBAC decorators, user CRUD handlers

### 164.308(a)(4) — Information Access Management
**Status:** SATISFIED
- Multi-tenant RLS isolates PHI per tenant (44 tables, FORCE RLS)
- Role-based endpoint access (`@require_role()`)
- API keys scoped to specific roles
- Cross-tenant access requires superadmin + audit trail
- **Evidence:** Migration 017, `database.py`, `admin_audit_log`

### 164.308(a)(5) — Security Awareness & Training
**Status:** PARTIAL
- Technical controls documented in ISP and compliance matrix
- **Gap:** No formal security awareness training program for operators
- **Remediation:** Implement annual security training with completion tracking

### 164.308(a)(6) — Security Incident Procedures
**Status:** SATISFIED
- Incident Response Plan with severity classification (P1-P4)
- SecurityEventLogger maps 10 event types to IR workflow
- Escalation paths with response timelines (15 min to 8 hours)
- Communication protocol for breach notification
- **Evidence:** `incident_response_plan.md`, `security_events.py`

### 164.308(a)(7) — Contingency Plan
**Status:** SATISFIED
- DR plan with RPO < 5 min, RTO < 30 min
- Quarterly PITR drill procedure
- Azure PostgreSQL automated backups (35-day retention)
- Automated data retention with configurable periods
- **Evidence:** `dr_test_procedure.md`, `config.py` blueprint

---

## Technical Safeguards (164.312)

### 164.312(a)(1) — Access Control
**Status:** SATISFIED
- Unique user identification (username + tenant_id)
- Emergency access: superadmin break-glass with audit trail
- Automatic logoff: JWT access token expiration (30/60 min)
- Impersonation hard cap: 15 minutes
- **Evidence:** `auth.py`, `auth_middleware()`

### 164.312(a)(2)(i) — Unique User Identification
**Status:** SATISFIED
- Each user has unique `id` + `username` within tenant scope
- JWT `sub` claim contains user ID
- Activity logs correlate user_id to all actions
- **Evidence:** `users` table, JWT claims in `auth.py`

### 164.312(a)(2)(iii) — Automatic Logoff
**Status:** SATISFIED
- Access token expiry: 30 min (client) / 60 min (admin)
- Refresh token: 7 day rotation
- Impersonation: 15 min hard cap
- Frontend AuthContext auto-refreshes or redirects to login
- **Evidence:** `auth.py` token configuration, `AuthContext.tsx`

### 164.312(a)(2)(iv) — Encryption & Decryption
**Status:** SATISFIED
- TLS 1.2+ for all API communication (Azure Container Apps)
- `DB_SSLMODE=require` for database connections
- Azure-managed AES-256 encryption at rest
- Password hashing: bcrypt with salt
- API keys: SHA-256 one-way hash
- **Evidence:** `security.py`, `database.py`, `auth.py`

### 164.312(b) — Audit Controls
**Status:** SATISFIED
- Immutable `activity_log` with PostgreSQL trigger (blocks DELETE/UPDATE)
- SHA-256 integrity hash chain (tamper-evidence)
- `admin_audit_log` for all privileged operations
- `billing_events` for financial changes
- SecurityEventLogger: 10 structured event types
- Audit export: `GET /api/audit/export` (CSV/JSON with integrity metadata)
- **Evidence:** `database.py`, `security_events.py`, `handlers.py:export_audit_trail()`

### 164.312(c)(1) — Integrity Controls
**Status:** SATISFIED
- RLS prevents cross-tenant data modification
- Auto-fill trigger ensures tenant_id on every row
- Integrity hash chain on activity_log detects tampering
- Drift detection identifies unauthorized configuration changes
- **Evidence:** Migration 017 (RLS), `trg_activity_log_immutable`, drift reports

### 164.312(d) — Person or Entity Authentication
**Status:** SATISFIED
- Multi-factor authentication via IdP (SSO/SAML)
- `force_sso` setting enforces IdP authentication for all users
- MFA policy documented with enforcement checklist
- **Evidence:** `saml.py`, `mfa_policy.md`

### 164.312(e)(1) — Transmission Security
**Status:** PARTIAL
- TLS 1.2+ for all external communication
- HSTS headers with 1-year max-age
- DB connections encrypted (`DB_SSLMODE=require`)
- **Gap:** No TLS certificate pinning for internal service communication
- **Evidence:** `security.py:add_security_headers()`

---

## Organizational Safeguards (164.314)

### 164.314(a) — Business Associate Requirements
**Status:** SATISFIED
- Multi-tenant architecture ensures data isolation
- Tenant configuration includes cloud provider and add-on settings
- Each tenant's data is independently exportable and deletable
- **Evidence:** Tenant CRUD API, data retention controls

### 164.314(b) — Group Health Plan Requirements
**Status:** N/A (SaaS platform, not a group health plan)

---

## PHI Data Flow

```
Customer IdP → SAML SSO → AuditGraph API (TLS) → PostgreSQL (SSL, RLS)
                                                       ↓
                                               Per-tenant isolation
                                               (FORCE ROW LEVEL SECURITY)
                                                       ↓
                                               Encrypted at rest (AES-256)
```

AuditGraph processes identity metadata (usernames, role assignments, risk scores) — not direct PHI. However, for customers in regulated industries (healthcare), this metadata may be considered indirectly identifiable, warranting HIPAA-aligned controls.

## Evidence Artifacts

| HIPAA Requirement | Artifact | Location |
|------------------|----------|----------|
| Access Control | RBAC decorators | `auth.py` |
| Audit Controls | Immutable activity_log | `database.py` |
| Integrity | Hash chain | `activity_log.integrity_hash` |
| Transmission | TLS + HSTS | `security.py` |
| Contingency | DR procedure | `dr_test_procedure.md` |
| Incident Response | IR plan | `incident_response_plan.md` |
| MFA | Policy document | `mfa_policy.md` |
