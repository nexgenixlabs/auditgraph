# HIPAA Compliance — AuditGraph

## Status: Stub (Phase 4B)

## Safeguards Mapped

### Administrative Safeguards (164.308)
- Role-based access control with 4 client roles + 4 portal roles
- Password policy: 12-char minimum, uppercase/lowercase/digit/special, blocklist
- Activity logging for all user actions
- Admin audit trail for privileged operations

### Technical Safeguards (164.312)
- Encryption in transit: HSTS, TLS required (DB_SSLMODE=require)
- Session management: JWT with 15-min access token, refresh rotation
- Audit controls: structured logging with user/org/request correlation
- Automatic logoff: token expiration, impersonation 15-min hard cap

### Organizational Safeguards
- Multi-tenant isolation via PostgreSQL RLS
- Tenant-scoped data access (no cross-tenant leakage)
- Superadmin operations logged to `admin_audit_log`

## Evidence Artifacts
- Password validation: `security.py:validate_password()`
- RLS policies: migration 017 (strict SELECT/INSERT/UPDATE/DELETE)
- Audit logs: `admin_audit_log`, `activity_log`, `billing_events`
- Security headers: `security.py:add_security_headers()`
