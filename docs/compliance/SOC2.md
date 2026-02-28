# SOC 2 Compliance — AuditGraph

## Status: Stub (Phase 4B)

## Controls Mapped

### CC6.1 — Logical Access Security
- JWT authentication with portal isolation (admin vs client)
- Role-based access control (admin/security_admin/compliance/reader)
- API key management with SHA-256 hashing
- Rate limiting on sensitive endpoints

### CC6.3 — Access Provisioning
- SSO/SAML with JIT user provisioning
- Multi-tenant isolation via RLS (Row-Level Security)
- Superadmin impersonation with audit trail

### CC7.2 — Monitoring Activities
- Structured JSON logging with request correlation (X-Request-ID)
- Admin audit log (`admin_audit_log` table)
- Activity log (append-only audit trail)
- Anomaly detection engine (6+ anomaly types)

### CC8.1 — Change Management
- Drift detection with persisted reports
- Billing event tracking (`billing_events` table)
- Discovery run history with full state snapshots

## Evidence Artifacts
- `admin_audit_log` — all admin mutations
- `activity_log` — user activity trail
- `billing_events` — billing change history
- Structured logs — JSON with user_id, organization_id, request_id
