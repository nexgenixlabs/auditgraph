# AuditGraph Regression Test Matrix

**Version:** v6.0.0
**Date:** 2026-02-26
**Total API Endpoints:** 220+
**Authentication:** JWT Bearer token (login via `POST /api/auth/login`)

---

## Test Execution Protocol

1. **Pre-requisites:** Backend running on `localhost:5001`, PostgreSQL connected, seed data loaded
2. **Auth:** Login as `nexgenadmin`/`changeme` (admin role, tenant_id=1)
3. **Verify:** Each endpoint returns expected status code and response shape
4. **Regression:** After any code change, re-run all CRITICAL and HIGH priority tests

---

## 1. Health & System (Public)

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 1.1 | GET | `/api/health` | None | 200, `{status, checks}` | CRITICAL |
| 1.2 | GET | `/health` | None | 200, `{status}` | CRITICAL |
| 1.3 | GET | `/api/metrics` | None | 200, Prometheus text | HIGH |
| 1.4 | GET | `/api/system/health` | JWT | 200, `{api, top_endpoints}` | HIGH |
| 1.5 | GET | `/api/system/sla` | JWT | 200, `{uptime_pct, sla_targets}` | MEDIUM |
| 1.6 | GET | `/api/system/resource-integrity` | JWT | 200, integrity report | LOW |
| 1.7 | GET | `/api/system/storage` | JWT | 200, `{tables, total_size}` | MEDIUM |
| 1.8 | POST | `/api/system/cleanup` | JWT (admin) | 200, cleanup results | LOW |
| 1.9 | GET | `/api/system/tenant-isolation` | JWT (admin) | 200, isolation report | HIGH |
| 1.10 | GET | `/api/system/launch-readiness` | JWT (admin) | 200, 51 gates | HIGH |

---

## 2. Authentication & Authorization

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 2.1 | POST | `/api/auth/login` | None | 200, `{access_token, refresh_token}` | CRITICAL |
| 2.2 | POST | `/api/auth/login` (bad creds) | None | 401, `{error}` | CRITICAL |
| 2.3 | POST | `/api/auth/refresh` | Refresh token | 200, `{access_token}` | CRITICAL |
| 2.4 | POST | `/api/auth/logout` | JWT | 200 | HIGH |
| 2.5 | GET | `/api/auth/me` | JWT | 200, `{id, username, role}` | CRITICAL |
| 2.6 | PUT | `/api/auth/password` | JWT | 200 (valid change) | HIGH |
| 2.7 | POST | `/api/auth/forgot-password` | None | 200 | MEDIUM |
| 2.8 | GET | `/api/auth/validate-reset-token` | None | 200, `{valid, email}` | MEDIUM |
| 2.9 | POST | `/api/auth/reset-password` | None | 200 | MEDIUM |
| 2.10 | GET | `/api/auth/password-policy` | None | 200, `{min_length, requirements}` | HIGH |
| 2.11 | GET | `/api/auth/tenants` | None | 200, `{tenants}` | MEDIUM |
| 2.12 | GET | `/api/auth/sso-status` | None | 200, `{sso_enabled}` | MEDIUM |
| 2.13 | GET | `/api/auth/tenant-branding` | None | 200, branding data | LOW |

---

## 3. SSO/SAML

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 3.1 | GET | `/api/auth/saml/metadata` | None | 200, XML | MEDIUM |
| 3.2 | GET | `/api/auth/saml/login` | None | 302, redirect to IdP | MEDIUM |
| 3.3 | POST | `/api/auth/saml/acs` | None (SAML) | 302 | MEDIUM |
| 3.4 | POST | `/api/auth/saml/token` | None | 200, `{access_token}` | MEDIUM |
| 3.5 | GET | `/api/auth/saml/slo` | None | 302 | LOW |
| 3.6 | GET | `/api/settings/sso` | JWT (admin) | 200, SSO config | MEDIUM |
| 3.7 | POST | `/api/settings/sso` | JWT (admin) | 200 | MEDIUM |
| 3.8 | POST | `/api/settings/sso/parse-metadata` | JWT (admin) | 200, parsed IdP data | MEDIUM |

---

## 4. User Management

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 4.1 | GET | `/api/users` | JWT (admin) | 200, `{users}` | HIGH |
| 4.2 | POST | `/api/users` | JWT (admin) | 201, `{user}` | HIGH |
| 4.3 | PUT | `/api/users/<id>` | JWT (admin) | 200 | HIGH |
| 4.4 | DELETE | `/api/users/<id>` | JWT (admin) | 200 | HIGH |
| 4.5 | POST | `/api/users/<id>/reset-password` | JWT (admin) | 200, `{temp_password}` | MEDIUM |
| 4.6 | GET | `/api/portal-users` | JWT (superadmin) | 200, `{users}` | MEDIUM |

---

## 5. API Keys

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 5.1 | GET | `/api/api-keys` | JWT (admin) | 200, `{api_keys}` | HIGH |
| 5.2 | POST | `/api/api-keys` | JWT (admin) | 201, `{api_key, raw_key}` | HIGH |
| 5.3 | PUT | `/api/api-keys/<id>` | JWT (admin) | 200 | MEDIUM |
| 5.4 | DELETE | `/api/api-keys/<id>` | JWT (admin) | 200 | MEDIUM |

---

## 6. Dashboard & Stats

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 6.1 | GET | `/api/stats` | JWT | 200, `{total_identities, risk counts}` | CRITICAL |
| 6.2 | GET | `/api/identity-summary` | JWT | 200, `{categories, monitored_resources}` | CRITICAL |
| 6.3 | GET | `/api/risks` | JWT | 200, `{critical_identities}` | CRITICAL |
| 6.4 | GET | `/api/dashboard/posture` | JWT | 200, posture metrics | HIGH |
| 6.5 | GET | `/api/dashboard/compliance` | JWT | 200, GRC scorecard | HIGH |
| 6.6 | GET | `/api/dashboard/conditional-access` | JWT | 200, CA summary | MEDIUM |
| 6.7 | GET | `/api/dashboard/anomalies` | JWT | 200, top anomalies | MEDIUM |
| 6.8 | GET | `/api/dashboard/role-usage` | JWT | 200, role usage stats | MEDIUM |
| 6.9 | GET | `/api/dashboard/credential-intelligence` | JWT | 200, cred insights | HIGH |
| 6.10 | GET | `/api/dashboard/trust` | JWT | 200, trust data | MEDIUM |
| 6.11 | GET | `/api/dashboard/preferences` | JWT | 200, widget prefs | LOW |
| 6.12 | PUT | `/api/dashboard/preferences` | JWT | 200 | LOW |
| 6.13 | DELETE | `/api/dashboard/preferences` | JWT | 200 | LOW |
| 6.14 | GET | `/api/summary` | JWT | 200 | MEDIUM |
| 6.15 | GET | `/api/dashboard/summary` | JWT | 200 | MEDIUM |
| 6.16 | GET | `/api/identity-risk-summary` | JWT | 200 | MEDIUM |
| 6.17 | GET | `/api/dangerous-identities` | JWT | 200 | MEDIUM |
| 6.18 | GET | `/api/dashboard/identity-correlation` | JWT | 200 | MEDIUM |

---

## 7. Identities

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 7.1 | GET | `/api/identities` | JWT | 200, `{identities, total}` | CRITICAL |
| 7.2 | GET | `/api/identities?limit=100&offset=0` | JWT | 200, paginated | CRITICAL |
| 7.3 | GET | `/api/identities?risk_level=critical` | JWT | 200, filtered | HIGH |
| 7.4 | GET | `/api/identities?identity_category=guest` | JWT | 200, filtered | HIGH |
| 7.5 | GET | `/api/identities?search=admin` | JWT | 200, searched | HIGH |
| 7.6 | GET | `/api/identities/<id>` | JWT | 200, full identity detail | CRITICAL |
| 7.7 | GET | `/api/identities/<id>` (not found) | JWT | 404 | HIGH |
| 7.8 | POST | `/api/identities/query` | JWT | 200, query results | HIGH |
| 7.9 | GET | `/api/identities/query/fields` | JWT | 200, field list | MEDIUM |
| 7.10 | POST | `/api/identities/risk-history/batch` | JWT | 200, batch sparklines | MEDIUM |
| 7.11 | GET | `/api/identities/<id>/anomalies` | JWT | 200 | MEDIUM |
| 7.12 | POST | `/api/identities/<id>/simulate` | JWT | 200, simulation | LOW |
| 7.13 | GET | `/api/identities/<id>/graph-data` | JWT | 200, `{trust, scope, graph}` | HIGH |
| 7.14 | GET | `/api/identities/<id>/lifecycle` | JWT | 200 | MEDIUM |
| 7.15 | GET | `/api/identities/<id>/risk-history` | JWT | 200 | MEDIUM |
| 7.16 | GET | `/api/identities/<id>/pim` | JWT | 200, PIM data | HIGH |
| 7.17 | GET | `/api/identities/<id>/usage` | JWT | 200 | MEDIUM |
| 7.18 | GET | `/api/identities/<id>/remediations` | JWT | 200, matched playbooks | HIGH |
| 7.19 | GET | `/api/identities/<id>/timeline` | JWT | 200, event timeline | MEDIUM |
| 7.20 | GET | `/api/identities/<id>/attack-paths` | JWT | 200, escalation chains | MEDIUM |
| 7.21 | GET | `/api/identities/<id>/effective-access` | JWT | 200, access + CLI cmds | HIGH |
| 7.22 | GET | `/api/identities/<id>/subscriptions` | JWT | 200 | MEDIUM |
| 7.23 | GET | `/api/identities/<id>/sensitive-access` | JWT | 200 | MEDIUM |
| 7.24 | GET | `/api/identities/<id>/groups` | JWT | 200 | LOW |
| 7.25 | POST | `/api/identities/exposure-graph` | JWT | 200 | MEDIUM |

---

## 8. Discovery & Runs

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 8.1 | GET | `/api/runs` | JWT | 200, `{runs}` | HIGH |
| 8.2 | POST | `/api/runs/trigger` | JWT (admin) | 200, `{run_id}` | HIGH |
| 8.3 | GET | `/api/runs/<id>/drift` | JWT | 200, drift report | HIGH |
| 8.4 | GET | `/api/scheduler` | JWT | 200, `{status, next_run}` | MEDIUM |
| 8.5 | GET | `/api/snapshots` | JWT | 200 | LOW |
| 8.6 | GET | `/api/snapshots/state` | JWT | 200 | LOW |
| 8.7 | GET | `/api/snapshots/compare` | JWT | 200 | LOW |

---

## 9. Drift & Changes

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 9.1 | GET | `/api/drift/latest` | JWT | 200, latest drift summary | HIGH |
| 9.2 | GET | `/api/drift/history` | JWT | 200, drift report list | HIGH |

---

## 10. Anomalies

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 10.1 | GET | `/api/anomalies` | JWT | 200, `{anomalies}` | HIGH |
| 10.2 | GET | `/api/anomalies/stats` | JWT | 200, summary stats | HIGH |
| 10.3 | GET | `/api/anomalies/<id>` | JWT | 200, anomaly detail | MEDIUM |
| 10.4 | PATCH | `/api/anomalies/<id>` | JWT (admin) | 200, resolved | MEDIUM |

---

## 11. Resources

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 11.1 | GET | `/api/resources` | JWT | 200, `{resources}` | HIGH |
| 11.2 | GET | `/api/resources/stats` | JWT | 200, counts by type/risk | HIGH |
| 11.3 | GET | `/api/resources/<id>` | JWT | 200, full resource detail | HIGH |
| 11.4 | GET | `/api/resources/<id>/access` | JWT | 200, identity access list | MEDIUM |
| 11.5 | GET | `/api/resources/<id>/findings` | JWT | 200 | MEDIUM |
| 11.6 | GET | `/api/resources/<id>/anomalies` | JWT | 200 | LOW |
| 11.7 | GET | `/api/resources/expiry-summary` | JWT | 200 | MEDIUM |
| 11.8 | GET | `/api/resources/compliance-summary` | JWT | 200 | MEDIUM |
| 11.9 | GET | `/api/resources/classifications` | JWT | 200 | MEDIUM |
| 11.10 | POST | `/api/resources/<id>/classify` | JWT (admin) | 200 | LOW |
| 11.11 | DELETE | `/api/resources/<id>/classify` | JWT (admin) | 200 | LOW |
| 11.12 | POST | `/api/resources/auto-classify` | JWT (admin) | 200 | LOW |
| 11.13 | GET | `/api/resources/<id>/access-map` | JWT | 200 | LOW |
| 11.14 | GET | `/api/data-security/summary` | JWT | 200 | MEDIUM |
| 11.15 | GET | `/api/blast-radius/summary` | JWT | 200 | MEDIUM |

---

## 12. SPNs & Workload Identities

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 12.1 | GET | `/api/spns/stats` | JWT | 200, SPN summary | HIGH |
| 12.2 | GET | `/api/spns` | JWT | 200, SPN list | HIGH |
| 12.3 | GET | `/api/spns/<id>` | JWT | 200, SPN detail | HIGH |
| 12.4 | GET | `/api/app-registrations/stats` | JWT | 200 | MEDIUM |
| 12.5 | GET | `/api/app-registrations` | JWT | 200 | MEDIUM |
| 12.6 | GET | `/api/app-registrations/<id>` | JWT | 200 | MEDIUM |
| 12.7 | GET | `/api/workload-identities/stats` | JWT | 200 | HIGH |
| 12.8 | GET | `/api/workload-identities` | JWT | 200 | HIGH |
| 12.9 | GET | `/api/workload-identities/<id>` | JWT | 200 | MEDIUM |
| 12.10 | GET | `/api/workload-identities/findings` | JWT | 200 | MEDIUM |
| 12.11 | GET | `/api/workload-identities/anomalies/stats` | JWT | 200 | MEDIUM |
| 12.12 | GET | `/api/workload-identities/anomalies` | JWT | 200 | MEDIUM |

---

## 13. Compliance

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 13.1 | GET | `/api/compliance/frameworks` | JWT | 200, framework list | HIGH |
| 13.2 | PATCH | `/api/compliance/frameworks/<id>` | JWT (admin) | 200 | MEDIUM |
| 13.3 | GET | `/api/compliance/gap-analysis` | JWT | 200 | MEDIUM |
| 13.4 | GET | `/api/compliance/trends` | JWT | 200 | MEDIUM |
| 13.5 | GET | `/api/compliance/intelligence` | JWT | 200 | MEDIUM |

---

## 14. Governance & Access Reviews

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 14.1 | GET | `/api/service-accounts/stats` | JWT | 200 | HIGH |
| 14.2 | GET | `/api/service-accounts/governance` | JWT | 200 | HIGH |
| 14.3 | POST | `/api/service-accounts/<id>/attest` | JWT (admin) | 200 | MEDIUM |
| 14.4 | GET | `/api/settings/sa-governance` | JWT | 200 | MEDIUM |
| 14.5 | POST | `/api/settings/sa-governance` | JWT (admin) | 200 | MEDIUM |
| 14.6 | GET | `/api/governance/identities` | JWT | 200 | MEDIUM |
| 14.7 | GET | `/api/governance/stats` | JWT | 200 | MEDIUM |
| 14.8 | GET | `/api/access-reviews` | JWT | 200, campaigns | HIGH |
| 14.9 | POST | `/api/access-reviews` | JWT (admin) | 201, campaign | MEDIUM |
| 14.10 | GET | `/api/access-reviews/<id>` | JWT | 200, detail | MEDIUM |
| 14.11 | PUT | `/api/access-reviews/<id>` | JWT (admin) | 200 | MEDIUM |
| 14.12 | DELETE | `/api/access-reviews/<id>` | JWT (admin) | 200 | LOW |
| 14.13 | PATCH | `/api/access-reviews/<id>/reviews/<id>` | JWT | 200, decision | MEDIUM |
| 14.14 | POST | `/api/access-reviews/<id>/reviews/bulk` | JWT | 200 | MEDIUM |
| 14.15 | GET | `/api/access-reviews/metrics` | JWT | 200 | MEDIUM |

---

## 15. Remediation & SOAR

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 15.1 | GET | `/api/remediation-summary` | JWT | 200 | HIGH |
| 15.2 | POST | `/api/bulk/remediation` | JWT (admin) | 200 | MEDIUM |
| 15.3 | GET | `/api/remediation/queue` | JWT | 200 | MEDIUM |
| 15.4 | POST | `/api/remediation/auto-execute` | JWT (admin) | 200 | LOW |
| 15.5 | POST | `/api/identities/<id>/remediation-execute` | JWT (admin) | 200 | MEDIUM |
| 15.6 | GET | `/api/soar/playbooks` | JWT | 200, `{playbooks}` | HIGH |
| 15.7 | POST | `/api/soar/playbooks` | JWT (admin) | 201 | MEDIUM |
| 15.8 | PUT | `/api/soar/playbooks/<id>` | JWT (admin) | 200 | MEDIUM |
| 15.9 | DELETE | `/api/soar/playbooks/<id>` | JWT (admin) | 200 | MEDIUM |
| 15.10 | POST | `/api/soar/playbooks/<id>/test` | JWT (admin) | 200 | LOW |
| 15.11 | GET | `/api/soar/actions` | JWT | 200, action history | MEDIUM |
| 15.12 | GET | `/api/soar/actions/stats` | JWT | 200 | MEDIUM |
| 15.13 | POST | `/api/soar/execute` | JWT (admin) | 200 | LOW |

---

## 16. Settings & Configuration

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 16.1 | GET | `/api/settings` | JWT | 200, `{settings}` | HIGH |
| 16.2 | POST | `/api/settings` | JWT (admin) | 200 | HIGH |
| 16.3 | POST | `/api/settings/test-email` | JWT (admin) | 200 | LOW |
| 16.4 | POST | `/api/settings/test-connection` | JWT (admin) | 200 | MEDIUM |
| 16.5 | GET | `/api/settings/integrations` | JWT | 200 | MEDIUM |
| 16.6 | POST | `/api/settings/integrations` | JWT (admin) | 200 | MEDIUM |
| 16.7 | POST | `/api/settings/integrations/test` | JWT (admin) | 200 | LOW |

---

## 17. Cloud Connections

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 17.1 | GET | `/api/client/connections` | JWT | 200, `{connections}` | CRITICAL |
| 17.2 | POST | `/api/client/connections` | JWT (admin) | 201 | HIGH |
| 17.3 | PUT | `/api/client/connections/<id>` | JWT (admin) | 200 | MEDIUM |
| 17.4 | DELETE | `/api/client/connections/<id>` | JWT (admin) | 200 | MEDIUM |
| 17.5 | POST | `/api/client/connections/test` | JWT (admin) | 200 | HIGH |
| 17.6 | POST | `/api/client/connections/<id>/discover` | JWT (admin) | 200 | HIGH |
| 17.7 | GET | `/api/tenant/config` | JWT | 200, `{cloud_providers}` | HIGH |

---

## 18. Tenant & Multi-Tenant (Admin Portal)

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 18.1 | GET | `/api/clients` | JWT (portal) | 200, `{tenants}` | HIGH |
| 18.2 | POST | `/api/clients` | JWT (superadmin) | 201, `{tenant}` | HIGH |
| 18.3 | PUT | `/api/clients/<id>` | JWT (portal) | 200 | HIGH |
| 18.4 | DELETE | `/api/clients/<id>` | JWT (superadmin) | 200 | MEDIUM |
| 18.5 | POST | `/api/clients/<id>/provision` | JWT (portal) | 200 | HIGH |
| 18.6 | GET | `/api/analytics/clients` | JWT (portal) | 200 | MEDIUM |
| 18.7 | GET | `/api/analytics/clients/trends` | JWT (portal) | 200 | LOW |
| 18.8 | GET | `/api/analytics/login-sessions` | JWT (portal) | 200 | LOW |

---

## 19. Billing & Subscriptions

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 19.1 | GET | `/api/subscriptions` | JWT | 200 | HIGH |
| 19.2 | GET | `/api/subscriptions/stats` | JWT | 200 | MEDIUM |
| 19.3 | POST | `/api/subscriptions/activate` | JWT (admin) | 200 | HIGH |
| 19.4 | POST | `/api/subscriptions/activate-all` | JWT (admin) | 200 | MEDIUM |
| 19.5 | PUT | `/api/subscriptions/<id>/deactivate` | JWT (admin) | 200 | MEDIUM |
| 19.6 | GET | `/api/subscriptions/distinct` | JWT | 200 | LOW |
| 19.7 | GET | `/api/client/invoices` | JWT | 200, `{invoices}` | HIGH |
| 19.8 | GET | `/api/admin/billing/summary` | JWT (portal) | 200 | MEDIUM |
| 19.9 | GET | `/api/billing/stripe-status` | JWT (admin) | 200 | MEDIUM |
| 19.10 | POST | `/api/billing/stripe-webhook` | None (Stripe sig) | 200 | HIGH |
| 19.11 | POST | `/api/admin/pilot-setup` | JWT (superadmin) | 200 | HIGH |

---

## 20. Scan Schedules (Phase 6)

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 20.1 | GET | `/api/scan-schedules` | JWT (admin) | 200, `{schedules}` | HIGH |
| 20.2 | POST | `/api/scan-schedules` | JWT (admin) | 201 | HIGH |
| 20.3 | PUT | `/api/scan-schedules/<id>` | JWT (admin) | 200 | MEDIUM |
| 20.4 | DELETE | `/api/scan-schedules/<id>` | JWT (admin) | 200 | MEDIUM |

---

## 21. Webhooks & Risk Rules

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 21.1 | GET | `/api/webhooks` | JWT (admin) | 200 | MEDIUM |
| 21.2 | POST | `/api/webhooks` | JWT (admin) | 201 | MEDIUM |
| 21.3 | PUT | `/api/webhooks/<id>` | JWT (admin) | 200 | LOW |
| 21.4 | DELETE | `/api/webhooks/<id>` | JWT (admin) | 200 | LOW |
| 21.5 | POST | `/api/webhooks/<id>/test` | JWT (admin) | 200 | LOW |
| 21.6 | GET | `/api/risk-rules` | JWT | 200 | MEDIUM |
| 21.7 | POST | `/api/risk-rules` | JWT (admin) | 201 | MEDIUM |
| 21.8 | POST | `/api/risk-rules/preview` | JWT (admin) | 200 | LOW |

---

## 22. Reports & Exports

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 22.1 | GET | `/api/reports/data` | JWT | 200, full report JSON | HIGH |
| 22.2 | GET | `/api/export/evidence-zip` | JWT | 200, ZIP | MEDIUM |
| 22.3 | GET | `/api/export/<type>` | JWT | 200, CSV/JSON | MEDIUM |

---

## 23. Trends & Analytics

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 23.1 | GET | `/api/trends` | JWT | 200, trend data | MEDIUM |
| 23.2 | GET | `/api/trends/velocity` | JWT | 200, velocity metrics | MEDIUM |
| 23.3 | GET | `/api/overview/insights` | JWT | 200 | MEDIUM |
| 23.4 | GET | `/api/overview/attack-surface-score` | JWT | 200 | MEDIUM |

---

## 24. Activity & Notifications

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 24.1 | GET | `/api/activity` | JWT | 200, `{activity_log}` | HIGH |
| 24.2 | GET | `/api/activity?limit=50` | JWT | 200, paginated | HIGH |
| 24.3 | GET | `/api/notifications` | JWT | 200 | MEDIUM |
| 24.4 | GET | `/api/notifications/stats` | JWT | 200, unread count | MEDIUM |
| 24.5 | PATCH | `/api/notifications/<id>` | JWT | 200, mark read | LOW |
| 24.6 | POST | `/api/notifications/mark-all-read` | JWT | 200 | LOW |

---

## 25. Role Mining & RBAC

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 25.1 | GET | `/api/role-mining` | JWT | 200 | MEDIUM |
| 25.2 | GET | `/api/rbac-hygiene/summary` | JWT | 200 | MEDIUM |
| 25.3 | GET | `/api/rbac-hygiene/findings` | JWT | 200 | MEDIUM |
| 25.4 | POST | `/api/rbac-hygiene/scan` | JWT (admin) | 200 | LOW |

---

## 26. Saved Views & Groups

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 26.1 | GET | `/api/saved-views` | JWT | 200 | MEDIUM |
| 26.2 | POST | `/api/saved-views` | JWT | 201 | LOW |
| 26.3 | GET | `/api/groups` | JWT | 200 | MEDIUM |
| 26.4 | POST | `/api/groups` | JWT (admin) | 201 | LOW |

---

## 27. AI Copilot

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 27.1 | POST | `/api/copilot/chat` | JWT | 200, AI response | MEDIUM |
| 27.2 | GET | `/api/copilot/conversations` | JWT | 200, history | LOW |
| 27.3 | GET | `/api/copilot/suggestions` | JWT | 200, quick-ask chips | LOW |

---

## 28. Identity Correlation

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 28.1 | GET | `/api/correlation/linked` | JWT | 200 | MEDIUM |
| 28.2 | POST | `/api/correlation/link` | JWT (admin) | 200 | MEDIUM |
| 28.3 | DELETE | `/api/correlation/link/<id>` | JWT (admin) | 200 | LOW |
| 28.4 | GET | `/api/correlation/config` | JWT | 200 | LOW |
| 28.5 | PUT | `/api/correlation/config` | JWT (admin) | 200 | LOW |
| 28.6 | GET | `/api/correlation/accounts` | JWT | 200 | MEDIUM |

---

## 29. Onboarding

| # | Method | Endpoint | Auth | Expected | Priority |
|---|--------|----------|------|----------|----------|
| 29.1 | GET | `/api/onboarding/status` | JWT | 200 | MEDIUM |
| 29.2 | POST | `/api/onboarding/test-connection` | JWT | 200 | MEDIUM |

---

## Security Regression Checks

| # | Test | Expected | Priority |
|---|------|----------|----------|
| S1 | Unauthenticated access to `/api/identities` | 401 | CRITICAL |
| S2 | Viewer role POST to `/api/users` | 403 | CRITICAL |
| S3 | SQL injection in `?search='OR 1=1--` | 200, no injection | CRITICAL |
| S4 | Rate limit: 6 rapid login attempts | 429 on 6th | HIGH |
| S5 | Expired JWT token | 401 | HIGH |
| S6 | Cross-tenant access (wrong tenant_id header) | 403 or empty | CRITICAL |
| S7 | Password below 12 chars rejected | 400 | HIGH |
| S8 | Common password blocked | 400 | HIGH |
| S9 | XSS in display_name field | Sanitized output | HIGH |
| S10 | CORS headers present | Access-Control headers | MEDIUM |

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| CRITICAL | 18 | Must pass on every deploy — auth, data access, core APIs |
| HIGH | 72 | Primary user flows — dashboard, identities, resources, billing |
| MEDIUM | 73 | Secondary features — governance, analytics, notifications |
| LOW | 30 | Edge cases — exports, webhooks, test endpoints |
| Security | 10 | OWASP/auth regression checks |
| **Total** | **203** | |
