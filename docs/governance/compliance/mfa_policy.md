# Multi-Factor Authentication (MFA) Policy — AuditGraph

**Version:** 1.0
**Effective Date:** 2026-03-03
**Owner:** Security Engineering
**SOC 2 Control:** CC6.1, CC6.6 | **HIPAA:** 164.312(d)

---

## 1. Purpose

This policy establishes multi-factor authentication requirements for all AuditGraph users and administrators. MFA is enforced at the Identity Provider (IdP) layer via SAML SSO federation, ensuring that AuditGraph never processes or stores MFA credentials directly.

## 2. Scope

| User Type | MFA Requirement | Enforcement Mechanism |
|-----------|----------------|----------------------|
| Client portal users (admin, security_admin, compliance, reader) | Required | IdP-enforced via SSO |
| Admin portal users (superadmin, poweradmin, billing, reader) | Required | IdP-enforced via SSO |
| API key access | N/A (key-based) | Key scoped to role, SHA-256 hashed |
| Service accounts (SPN discovery) | N/A (certificate-based) | Azure AD managed identity |

## 3. Architecture — SSO-Delegated MFA

AuditGraph delegates authentication to the customer's SAML 2.0 Identity Provider. The MFA enforcement chain is:

```
User → AuditGraph Login Page → SAML AuthnRequest → IdP (Entra ID / Okta / etc.)
                                                        ↓
                                                   IdP enforces MFA
                                                   (Authenticator app, FIDO2, SMS)
                                                        ↓
                                              SAML Response → AuditGraph ACS
                                                        ↓
                                              One-time auth code → JWT issued
```

### 3.1 `force_sso` Setting

Each tenant has a configurable `sso_force_sso` setting (stored in the `settings` table):

| Setting Value | Behavior |
|---------------|----------|
| `false` (default) | Local username/password login AND SSO login both available |
| `true` | Local login hidden. Only SSO login button shown. All authentication flows through IdP. |

**Implementation reference:**
- Setting key: `sso_force_sso` in `SSO_SETTING_KEYS` (`backend/app/api/saml.py`)
- Checked by: `GET /api/auth/sso-status` → returns `{ force_sso: true/false }`
- Frontend: `Login.tsx` hides username/password form when `force_sso === true`

### 3.2 MFA Enforcement When `force_sso = true`

When SSO is forced:
1. All users MUST authenticate through the configured IdP
2. The IdP's Conditional Access / MFA policies apply to every login
3. AuditGraph has NO local password bypass
4. Emergency break-glass: superadmin can disable `force_sso` via direct DB update

### 3.3 IdP MFA Configuration (Customer Responsibility)

AuditGraph requires that customers configure MFA in their IdP. Recommended policies:

**Azure AD / Entra ID:**
- Conditional Access policy requiring MFA for the AuditGraph Enterprise Application
- Allowed methods: Microsoft Authenticator (push), FIDO2 security keys, certificate-based
- Block legacy authentication protocols

**Okta:**
- MFA policy on the AuditGraph SAML application
- Factor enrollment: Okta Verify, WebAuthn, YubiKey
- Session lifetime: 8 hours max

**Google Workspace:**
- 2-Step Verification enforced for organizational unit
- Allowed methods: Security key, Google Authenticator

## 4. Admin Enforcement Checklist

Before marking a tenant as MFA-compliant:

- [ ] SSO configured and tested (`GET /api/auth/sso-status` returns `sso_configured: true`)
- [ ] `force_sso` enabled (`sso_force_sso = true` in tenant settings)
- [ ] IdP Conditional Access policy requires MFA for AuditGraph app
- [ ] At least one phishing-resistant method enabled (FIDO2, certificate)
- [ ] Legacy authentication blocked in IdP
- [ ] Test: attempt login → redirected to IdP → MFA challenged → returned to AuditGraph
- [ ] Document IdP policy name and configuration in tenant onboarding record

## 5. Local Login Deprecation Path

For tenants still using local authentication (`force_sso = false`):

| Phase | Timeline | Action |
|-------|----------|--------|
| Advisory | Onboarding | Inform tenant that SSO + MFA is required for SOC 2 compliance |
| Warning | 30 days | Activity log shows `auth_provider: local` warnings |
| Enforcement | 60 days | Admin enables `force_sso = true` |
| Lockdown | 90 days | Platform policy auto-enables `force_sso` for all tenants |

## 6. Monitoring & Compliance Evidence

### Security Events (SecurityEventLogger)
- `AUTH_SUCCESS` — logs `auth_provider` (local vs sso), user_id, IP
- `AUTH_FAILURE` — logs failed attempts, reason (invalid_password, expired_token, sso_error)

### Compliance Queries
```sql
-- Tenants without SSO enforcement
SELECT t.name, s.value
FROM tenants t
LEFT JOIN settings s ON s.organization_id = t.id AND s.key = 'sso_force_sso'
WHERE COALESCE(s.value, 'false') != 'true';

-- Users still using local auth (last 30 days)
SELECT u.username, u.auth_provider, MAX(al.created_at) as last_login
FROM users u
JOIN activity_log al ON al.user_id = u.id AND al.action_type = 'auth_login'
WHERE u.auth_provider = 'local'
AND al.created_at > NOW() - INTERVAL '30 days'
GROUP BY u.username, u.auth_provider;
```

### Audit Evidence Artifacts
- `activity_log` entries with `action_type = 'auth_login'` show auth_provider per login
- `settings` table shows `sso_force_sso` state per tenant
- IdP audit logs (customer-provided) confirm MFA challenge completion

## 7. Exceptions

| Exception | Approval Required | Duration |
|-----------|------------------|----------|
| Break-glass superadmin local login | Security Lead + CTO | 24 hours max |
| API key access (no MFA) | Tenant Admin | Permanent (key-scoped) |
| Service principal (certificate auth) | Automated | N/A |

All exceptions must be logged in the `admin_audit_log` with justification.
