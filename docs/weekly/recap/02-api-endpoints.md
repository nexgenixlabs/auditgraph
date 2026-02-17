# AuditGraph API Endpoint Catalog

> Comprehensive catalog of all route registrations in `backend/app/main.py`.
> Source of truth: the `create_app()` function and its `@app.<method>()` decorators.

---

## Statistics

- **Total route decorators**: 198
- **Total unique paths**: ~156 (some paths share handlers via aliases)
- **Total handler functions**: ~180 (imported from `handlers.py` + `auth.py`)
- **Public endpoints**: 15 (no auth required)
- **Role-restricted endpoints** (`@require_role`): 68
- **Portal-restricted endpoints** (`@require_portal_access` / `@require_portal_role` / `@require_superadmin`): 12
- **Auth-only endpoints** (auth middleware, no role decorator): 103

---

## Public Endpoints (No Auth Required)

These paths are either in the `PUBLIC_PATHS` set or matched by prefix rules in `auth_middleware()`.

| Method | Path | Handler | Notes |
|--------|------|---------|-------|
| GET | `/api/health` | `health_check()` | Service health check |
| GET | `/health` | `health_check()` | Alias (same handler, separate decorator) |
| GET | `/api/metrics` | `prometheus_metrics()` | Prometheus-format metrics |
| POST | `/api/auth/login` | `auth_login()` | JWT access + refresh token generation |
| POST | `/api/auth/refresh` | `auth_refresh()` | Refresh token rotation |
| POST | `/api/auth/forgot-password` | `forgot_password_handler()` | Password reset email |
| GET | `/api/auth/validate-reset-token` | `validate_reset_token_handler()` | Check reset token validity |
| POST | `/api/auth/reset-password` | `reset_password_handler()` | Complete password reset |
| GET | `/api/auth/tenant-branding` | `get_tenant_branding()` | Login page branding (logo, colors) |
| GET | `/api/auth/sso-status` | `sso_status()` | SSO configuration check by tenant slug |
| GET | `/api/auth/saml/metadata` | `saml_metadata()` | SP metadata XML for IdP setup |
| GET | `/api/auth/saml/login` | `saml_login()` | Redirect to IdP for authentication |
| POST | `/api/auth/saml/acs` | `saml_acs()` | SAML Assertion Consumer Service |
| POST | `/api/auth/saml/token` | `saml_token_exchange()` | Exchange SSO one-time code for JWT |
| GET | `/api/auth/saml/slo` | `saml_slo()` | Single logout |
| GET | `/api/tenants/by-slug/<slug>` | `get_tenant_by_slug_public()` | Public tenant lookup by URL slug |

---

## Authentication Endpoints

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| POST | `/api/auth/login` | `auth_login()` | Public | Returns access_token + refresh_token |
| POST | `/api/auth/refresh` | `auth_refresh()` | Public | Rotates refresh token |
| POST | `/api/auth/logout` | `auth_logout()` | Auth | Revokes refresh token |
| GET | `/api/auth/me` | `auth_me()` | Auth | Current user profile |
| PUT | `/api/auth/password` | `change_password()` | Auth | Change own password |
| GET | `/api/auth/tenants` | `get_user_tenants_handler()` | Auth | List tenants the user belongs to |
| POST | `/api/auth/forgot-password` | `forgot_password_handler()` | Public | Initiate password reset |
| GET | `/api/auth/validate-reset-token` | `validate_reset_token_handler()` | Public | Validate reset token |
| POST | `/api/auth/reset-password` | `reset_password_handler()` | Public | Complete password reset |
| GET | `/api/auth/tenant-branding` | `get_tenant_branding()` | Public | Login page branding |

---

## User Management (Admin Only)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/users` | `get_users_list()` | `@require_role('admin')` |
| POST | `/api/users` | `create_user_handler()` | `@require_role('admin')` |
| PUT | `/api/users/<int:user_id>` | `update_user_handler()` | `@require_role('admin')` |
| DELETE | `/api/users/<int:user_id>` | `delete_user_handler()` | `@require_role('admin')` |
| POST | `/api/users/<int:user_id>/reset-password` | `admin_reset_user_password()` | `@require_role('admin')` |

---

## Dashboard & Stats (Auth Required)

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/stats` | `get_stats()` | Auth | Latest run summary + previous run |
| GET | `/api/summary` | `get_stats()` | Auth | Alias for `/api/stats` |
| GET | `/api/dashboard/summary` | `get_stats()` | Auth | Alias for `/api/stats` |
| GET | `/api/identity-summary` | `get_identity_summary()` | Auth | Category risk breakdown + monitored resources |
| GET | `/api/dashboard/posture` | `get_dashboard_posture()` | Auth | Credential health, dormant counts, posture score |
| GET | `/api/dashboard/compliance` | `get_dashboard_compliance()` | Auth | GRC compliance scorecard |
| GET | `/api/dashboard/conditional-access` | `get_dashboard_ca_summary()` | Auth | CA policy coverage, MFA enforcement |
| GET | `/api/dashboard/anomalies` | `get_dashboard_anomalies()` | Auth | Top unresolved anomalies widget |
| GET | `/api/dashboard/role-usage` | `get_role_usage_stats()` | Auth | Role usage statistics |
| GET | `/api/dashboard/credential-intelligence` | `get_credential_intelligence()` | Auth | Credential intelligence data |
| GET | `/api/dashboard/trust` | `get_trust_dashboard()` | Auth | Trust posture dashboard |
| GET | `/api/overview/insights` | `get_overview_insights()` | Auth | Tier distribution, action items |
| GET | `/api/overview/attack-surface-score` | `get_attack_surface_score()` | Auth | Attack surface score computation |

---

## Dashboard Preferences

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/dashboard/preferences` | `get_dashboard_preferences_handler()` | Auth |
| PUT | `/api/dashboard/preferences` | `save_dashboard_preferences_handler()` | Auth |
| DELETE | `/api/dashboard/preferences` | `reset_dashboard_preferences_handler()` | Auth |

---

## Identity Endpoints (Auth Required)

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/identities` | `get_identities()` | Auth | Filters: risk_level, identity_category, cloud, search, subscription_id, limit, offset |
| GET | `/api/identities/<identity_id>` | `get_identity_details()` | Auth | Full detail with roles, permissions, trend |
| POST | `/api/identities/query` | `query_identities()` | Auth | Advanced query builder (AND/OR groups) |
| GET | `/api/identities/query/fields` | `get_query_fields()` | Auth | Available fields, operators, value suggestions |
| POST | `/api/identities/risk-history/batch` | `get_batch_risk_history()` | Auth | Batch sparkline data, up to 200 identities |
| POST | `/api/identities/exposure-graph` | `get_exposure_graph()` | Auth | Multi-identity exposure graph |
| GET | `/api/identities/<identity_id>/graph-data` | `get_identity_graph_data()` | Auth | Access graph (executive + technical modes) |
| GET | `/api/identities/<identity_id>/pim` | `get_identity_pim_data()` | Auth | PIM eligible assignments + activations |
| GET | `/api/identities/<identity_id>/usage` | `get_identity_usage()` | Auth | Usage intelligence |
| GET | `/api/identities/<identity_id>/risk-history` | `get_identity_risk_history()` | Auth | Per-identity risk trend sparkline |
| GET | `/api/identities/<identity_id>/lifecycle` | `get_identity_lifecycle()` | Auth | Lifecycle events |
| GET | `/api/identities/<identity_id>/anomalies` | `get_identity_anomalies_handler()` | Auth | Identity-specific anomalies |
| GET | `/api/identities/<identity_id>/remediations` | `get_identity_remediations()` | Auth | Matched remediation playbooks |
| GET | `/api/identities/<identity_id>/remediation-status` | `get_remediation_status()` | Auth | Remediation action statuses |
| POST | `/api/identities/<identity_id>/remediation-action` | `post_remediation_action()` | `@require_role('auditor', 'admin')` | Create remediation action |
| POST | `/api/identities/<path:identity_id>/remediation-execute` | `execute_remediation()` | Auth | Execute auto-remediation action |
| GET | `/api/identities/<identity_id>/groups` | `get_identity_groups_handler()` | Auth | Group membership |
| GET | `/api/identities/<identity_id>/timeline` | `get_identity_timeline()` | Auth | Forensic timeline (5 sources) |
| GET | `/api/identities/<identity_id>/attack-paths` | `get_identity_attack_paths()` | Auth | 5 escalation chain types |
| POST | `/api/identities/<identity_id>/simulate` | `simulate_risk()` | `@require_role('admin', 'security_admin', 'auditor')` | Risk what-if simulation |
| GET | `/api/identities/<path:identity_id>/subscriptions` | `get_identity_subscriptions()` | Auth | Multi-subscription access |

---

## Risks

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/risks` | `get_risks()` | Auth |

---

## Compliance (Role-Restricted)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/compliance/frameworks` | `get_compliance_frameworks_list()` | Auth |
| PATCH | `/api/compliance/frameworks/<int:framework_id>` | `toggle_compliance_framework_handler()` | `@require_role('admin')` |
| GET | `/api/compliance/gap-analysis` | `get_compliance_gap_analysis()` | `@require_role('admin', 'security_admin', 'compliance', 'reader')` |
| GET | `/api/compliance/trends` | `get_compliance_trends_handler()` | `@require_role('admin', 'security_admin', 'compliance', 'reader')` |
| GET | `/api/compliance/intelligence` | `get_compliance_intelligence()` | `@require_role('admin', 'security_admin', 'compliance', 'reader')` |

---

## Discovery Runs & Drift

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/runs` | `get_discovery_runs()` | Auth | List discovery runs |
| POST | `/api/runs/trigger` | `trigger_discovery()` | `@require_role('admin', 'security_admin')` | Manual discovery trigger |
| GET | `/api/runs/<int:run_id>/drift` | `get_drift_report()` | Auth | Full drift report for a run |
| GET | `/api/scheduler` | `get_scheduler_status()` | Auth | Scheduler status + next run time |
| GET | `/api/drift/latest` | `get_latest_drift()` | Auth | Most recent drift report summary |
| GET | `/api/drift/history` | `get_drift_history()` | Auth | Drift report history list |

---

## Trends

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/trends` | `get_trends()` | Auth |
| GET | `/api/trends/velocity` | `get_trends_velocity()` | Auth |

---

## Azure Resources (Role-Restricted)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/resources` | `get_resources()` | `@require_role('compliance', 'reader', 'admin')` |
| GET | `/api/resources/stats` | `get_resource_stats()` | `@require_role('compliance', 'reader', 'admin')` |
| GET | `/api/resources/expiry-summary` | `get_resource_expiry_summary()` | `@require_role('compliance', 'reader', 'admin')` |
| GET | `/api/resources/compliance-summary` | `get_resource_compliance_summary()` | `@require_role('compliance', 'reader', 'admin')` |
| GET | `/api/resources/<path:resource_id>` | `get_resource_detail()` | `@require_role('compliance', 'reader', 'admin')` |
| GET | `/api/resources/<path:resource_id>/access` | `get_resource_access()` | `@require_role('compliance', 'reader', 'admin')` |

---

## SPN Dashboard

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/spns/stats` | `get_spn_stats()` | Auth |
| GET | `/api/spns` | `get_spn_list()` | Auth |
| GET | `/api/spns/<path:identity_id>` | `get_spn_detail()` | Auth |

---

## App Registrations

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/app-registrations/stats` | `get_app_reg_stats()` | Auth |
| GET | `/api/app-registrations` | `get_app_reg_list()` | Auth |
| GET | `/api/app-registrations/<app_id>` | `get_app_reg_detail()` | Auth |

---

## Settings & Configuration

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/settings` | `get_app_settings()` | Auth | All settings + status |
| POST | `/api/settings` | `save_app_settings()` | `@require_role('admin')` | Update settings |
| POST | `/api/settings/test-email` | `test_email()` | `@require_role('admin')` | Send test email |
| POST | `/api/settings/test-connection` | `test_azure_connection()` | `@require_role('admin', 'security_admin')` | Test Azure credentials |
| GET | `/api/settings/sso` | `get_sso_settings()` | `@require_role('admin')` | SSO/SAML configuration |
| POST | `/api/settings/sso` | `save_sso_settings()` | `@require_role('admin')` | Save SSO configuration |
| POST | `/api/settings/sso/parse-metadata` | `parse_sso_metadata()` | `@require_role('admin')` | Parse IdP metadata XML |
| GET | `/api/settings/sa-governance` | `get_sa_governance_settings()` | Auth | SA governance policy settings |
| POST | `/api/settings/sa-governance` | `save_sa_governance_settings()` | `@require_role('admin')` | Save SA governance policy |
| GET | `/api/settings/integrations` | `get_integration_settings()` | `@require_role('admin')` | Slack/Teams webhook config |
| POST | `/api/settings/integrations` | `save_integration_settings()` | `@require_role('admin')` | Save integration config |
| POST | `/api/settings/integrations/test` | `test_integration_webhook()` | `@require_role('admin')` | Test webhook delivery |

---

## Anomaly Detection

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/anomalies` | `get_anomalies_list()` | Auth | Filters: type, severity, identity_id, resolved, run_id |
| GET | `/api/anomalies/stats` | `get_anomaly_stats_handler()` | Auth | Summary: total, unresolved, by_type, by_severity |
| GET | `/api/anomalies/<int:anomaly_id>` | `get_anomaly_detail()` | Auth | Single anomaly detail |
| PATCH | `/api/anomalies/<int:anomaly_id>` | `resolve_anomaly_handler()` | Auth | Resolve anomaly |

---

## SOAR Integration

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/soar/playbooks` | `get_soar_playbooks_list()` | Auth |
| POST | `/api/soar/playbooks` | `create_soar_playbook_handler()` | `@require_role('admin')` |
| PUT | `/api/soar/playbooks/<int:playbook_id>` | `update_soar_playbook_handler()` | `@require_role('admin')` |
| DELETE | `/api/soar/playbooks/<int:playbook_id>` | `delete_soar_playbook_handler()` | `@require_role('admin')` |
| POST | `/api/soar/playbooks/<int:playbook_id>/test` | `test_soar_playbook_handler()` | `@require_role('admin')` |
| GET | `/api/soar/actions` | `get_soar_actions_list()` | Auth |
| GET | `/api/soar/actions/stats` | `get_soar_action_stats_handler()` | Auth |
| POST | `/api/soar/execute` | `execute_soar_action_handler()` | `@require_role('admin', 'security_admin')` |

---

## API Key Management (Admin Only)

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/api-keys` | `get_api_keys_list()` | `@require_role('admin')` | List all API keys |
| POST | `/api/api-keys` | `create_api_key_handler()` | `@require_role('admin')` | Returns raw key once |
| PUT | `/api/api-keys/<int:key_id>` | `update_api_key_handler()` | `@require_role('admin')` | Update name, role, enabled |
| DELETE | `/api/api-keys/<int:key_id>` | `delete_api_key_handler()` | `@require_role('admin')` | Revoke key |

---

## Webhooks (Admin Only for Writes)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/webhooks` | `get_webhooks_list()` | Auth |
| POST | `/api/webhooks` | `create_webhook()` | `@require_role('admin')` |
| PUT | `/api/webhooks/<int:webhook_id>` | `update_webhook()` | `@require_role('admin')` |
| DELETE | `/api/webhooks/<int:webhook_id>` | `delete_webhook()` | `@require_role('admin')` |
| POST | `/api/webhooks/<int:webhook_id>/test` | `test_webhook_endpoint()` | `@require_role('admin')` |
| GET | `/api/webhooks/<int:webhook_id>/deliveries` | `get_webhook_deliveries()` | Auth |

---

## Custom Risk Rules (Admin Only for Writes)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/risk-rules` | `get_risk_rules_list()` | Auth |
| POST | `/api/risk-rules` | `create_risk_rule()` | `@require_role('admin')` |
| PUT | `/api/risk-rules/<int:rule_id>` | `update_risk_rule()` | `@require_role('admin')` |
| DELETE | `/api/risk-rules/<int:rule_id>` | `delete_risk_rule()` | `@require_role('admin')` |
| POST | `/api/risk-rules/preview` | `preview_risk_rule()` | `@require_role('admin')` |

---

## Notifications

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/notifications` | `get_notifications_list()` | Auth |
| GET | `/api/notifications/stats` | `get_notification_stats_handler()` | Auth |
| PATCH | `/api/notifications/<int:notification_id>` | `mark_notification_handler()` | Auth |
| POST | `/api/notifications/mark-all-read` | `mark_all_notifications_read_handler()` | Auth |
| DELETE | `/api/notifications/<int:notification_id>` | `delete_notification_handler()` | Auth |

---

## Export Pipeline

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/export/<export_type>` | `export_data()` | Auth | Dynamic export_type segment (csv, json, etc.) |

---

## Saved Views

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/saved-views` | `get_saved_views_list()` | Auth |
| POST | `/api/saved-views` | `create_saved_view_handler()` | Auth |
| PUT | `/api/saved-views/<int:view_id>` | `update_saved_view_handler()` | Auth |
| DELETE | `/api/saved-views/<int:view_id>` | `delete_saved_view_handler()` | Auth |
| POST | `/api/saved-views/<int:view_id>/default` | `set_default_view_handler()` | Auth |

---

## Access Review Campaigns

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/access-reviews` | `get_access_reviews_list()` | Auth | List campaigns |
| POST | `/api/access-reviews` | `create_access_review()` | `@require_role('admin')` | Create new campaign |
| GET | `/api/access-reviews/metrics` | `get_campaign_metrics_handler()` | Auth | Campaign-level metrics |
| GET | `/api/access-reviews/<int:campaign_id>` | `get_access_review_detail()` | Auth | Campaign detail + review items |
| PUT | `/api/access-reviews/<int:campaign_id>` | `update_access_review()` | `@require_role('admin')` | Update campaign |
| DELETE | `/api/access-reviews/<int:campaign_id>` | `delete_access_review()` | `@require_role('admin')` | Delete campaign |
| PATCH | `/api/access-reviews/<int:campaign_id>/reviews/<int:review_id>` | `update_review_decision()` | `@require_role('auditor', 'admin')` | Approve/deny individual review |
| POST | `/api/access-reviews/<int:campaign_id>/reviews/bulk` | `bulk_review_decisions()` | `@require_role('auditor', 'admin')` | Bulk approve/deny |
| GET | `/api/access-reviews/<int:campaign_id>/audit-log` | `get_campaign_audit_log_handler()` | Auth | Campaign audit trail |

---

## Identity Groups

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/groups` | `get_groups_list()` | Auth |
| POST | `/api/groups` | `create_group_handler()` | `@require_role('auditor', 'admin')` |
| GET | `/api/groups/compare` | `get_group_comparison_handler()` | Auth |
| GET | `/api/groups/<int:group_id>` | `get_group_detail()` | Auth |
| PUT | `/api/groups/<int:group_id>` | `update_group_handler()` | `@require_role('auditor', 'admin')` |
| DELETE | `/api/groups/<int:group_id>` | `delete_group_handler()` | `@require_role('admin')` |
| POST | `/api/groups/<int:group_id>/members` | `add_group_members_handler()` | `@require_role('auditor', 'admin')` |
| DELETE | `/api/groups/<int:group_id>/members` | `remove_group_members_handler()` | `@require_role('auditor', 'admin')` |

---

## Remediation Engine

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/remediation-summary` | `get_remediation_dashboard_summary()` | Auth | Dashboard summary widget |
| GET | `/api/remediation/queue` | `get_remediation_queue_handler()` | Auth | Queued remediation actions |
| POST | `/api/remediation/auto-execute` | `batch_auto_remediate()` | Auth | Batch auto-execute (rejects high-risk) |
| POST | `/api/bulk/remediation` | `post_bulk_remediation()` | `@require_role('auditor', 'admin')` | Bulk remediation operations |

---

## Role Mining

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/role-mining` | `get_role_mining()` | Auth |

---

## Reports

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/reports/data` | `get_report_data()` | Auth |

---

## Activity Log

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/activity` | `get_activity()` | Auth |

---

## Service Account Governance

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/service-accounts/stats` | `get_sa_governance_stats()` | Auth |
| GET | `/api/service-accounts/governance` | `get_sa_governance_list()` | Auth |
| POST | `/api/service-accounts/<identity_id>/attest` | `post_sa_attestation()` | `@require_role('admin', 'security_admin', 'auditor')` |

---

## Identity Governance V2 (Risk-Aware Certification)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/governance/identities` | `get_governance_identities()` | Auth |
| GET | `/api/governance/identities/<identity_id>` | `get_governance_identity_detail()` | Auth |
| POST | `/api/governance/identities/<identity_id>/decide` | `post_governance_decision()` | `@require_role('admin', 'security_admin', 'auditor')` |
| GET | `/api/governance/stats` | `get_governance_stats()` | Auth |

---

## Tenant Management

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/tenants` | `get_tenants_list()` | `@require_portal_access()` | All portal roles |
| POST | `/api/tenants` | `create_tenant_handler()` | `@require_portal_role('superadmin', 'poweradmin')` | Create tenant |
| PUT | `/api/tenants/<int:tenant_id>` | `update_tenant_handler()` | `@require_portal_role('superadmin', 'poweradmin')` | Update tenant |
| DELETE | `/api/tenants/<int:tenant_id>` | `delete_tenant_handler()` | `@require_superadmin()` | Delete tenant (superadmin only) |
| GET | `/api/tenant` | `get_current_tenant_handler()` | Auth | Current user's tenant |
| GET | `/api/tenant/config` | `get_tenant_config()` | Auth | Cloud provider + add-on config |
| GET | `/api/tenant/stage` | `get_tenant_stage()` | Auth | Onboarding stage |
| POST | `/api/tenant/stage` | `update_tenant_stage()` | `@require_role('admin')` | Update onboarding stage |
| GET | `/api/tenants/by-slug/<slug>` | `get_tenant_by_slug_public()` | Public | Tenant lookup by URL slug |
| POST | `/api/tenants/<int:tenant_id>/provision` | `provision_tenant_handler()` | `@require_portal_role('superadmin', 'poweradmin')` | Provision tenant resources |
| POST | `/api/tenants/<int:tenant_id>/logo` | `upload_tenant_logo()` | `@require_portal_role('superadmin', 'poweradmin')` | Upload tenant logo |
| DELETE | `/api/tenants/<int:tenant_id>/logo` | `delete_tenant_logo()` | `@require_portal_role('superadmin', 'poweradmin')` | Delete tenant logo |

---

## Portal Users (Superadmin Only)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/portal-users` | `get_portal_users_list()` | `@require_superadmin()` |

---

## Cross-Tenant Analytics (Portal Access Required)

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/analytics/tenants` | `get_cross_tenant_analytics()` | `@require_portal_access()` |
| GET | `/api/analytics/tenants/trends` | `get_cross_tenant_trends()` | `@require_portal_access()` |
| GET | `/api/analytics/login-sessions` | `get_login_sessions()` | `@require_portal_access()` |

---

## Onboarding Wizard

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/onboarding/status` | `get_onboarding_status()` | Auth |
| POST | `/api/onboarding/test-connection` | `test_azure_connection()` | `@require_role('admin', 'security_admin')` |

---

## Cloud Subscriptions

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/subscriptions` | `get_subscriptions_list()` | Auth |
| GET | `/api/subscriptions/stats` | `get_subscriptions_stats()` | Auth |
| POST | `/api/subscriptions/activate` | `activate_subscription()` | `@require_role('admin', 'security_admin')` |
| PUT | `/api/subscriptions/<int:sub_id>/deactivate` | `deactivate_subscription()` | `@require_role('admin', 'security_admin')` |
| GET | `/api/subscriptions/distinct` | `get_subscriptions_distinct()` | Auth |

---

## System Health & Data Retention

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/system/health` | `get_system_health()` | Auth | API stats, top endpoints, table sizes |
| GET | `/api/system/storage` | `get_storage_stats()` | Auth | Table sizes, row counts, oldest records |
| POST | `/api/system/cleanup` | `run_manual_cleanup()` | Auth | Manual data retention cleanup |

---

## Scan Modes

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/api/scan-modes` | `get_scan_modes()` | Auth |

---

## AI Security Copilot

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| POST | `/api/copilot/chat` | `copilot_chat()` | Auth |
| GET | `/api/copilot/conversations` | `copilot_conversations_list()` | Auth |
| GET | `/api/copilot/suggestions` | `copilot_suggestions()` | Auth |

---

## SSO/SAML (Public + Admin)

| Method | Path | Handler | Auth | Notes |
|--------|------|---------|------|-------|
| GET | `/api/auth/sso-status` | `sso_status()` | Public | Check SSO config by tenant slug |
| GET | `/api/auth/saml/metadata` | `saml_metadata()` | Public | SP metadata XML |
| GET | `/api/auth/saml/login` | `saml_login()` | Public | Redirect to IdP |
| POST | `/api/auth/saml/acs` | `saml_acs()` | Public | Assertion Consumer Service |
| POST | `/api/auth/saml/token` | `saml_token_exchange()` | Public | SSO code to JWT exchange |
| GET | `/api/auth/saml/slo` | `saml_slo()` | Public | Single logout |

---

## Special Route Patterns

### `<path:resource_id>` -- ARM Resource Paths

Used for Azure Resource Manager paths that contain forward slashes (e.g., `/subscriptions/abc/resourceGroups/rg1/providers/...`).

```
GET  /api/resources/<path:resource_id>
GET  /api/resources/<path:resource_id>/access
POST /api/identities/<path:identity_id>/remediation-execute
GET  /api/identities/<path:identity_id>/subscriptions
GET  /api/spns/<path:identity_id>
```

**Important**: Flask's `<path:>` converter strips leading `/`. Handlers must prepend `/` if missing:
```python
if not resource_id.startswith('/'):
    resource_id = '/' + resource_id
```

### `<int:id>` -- Integer Primary Keys

Used for database primary keys (auto-increment integers).

```
PUT/DELETE  /api/users/<int:user_id>
PUT/DELETE  /api/api-keys/<int:key_id>
PUT/DELETE  /api/soar/playbooks/<int:playbook_id>
PUT/DELETE  /api/tenants/<int:tenant_id>
GET/PUT/DELETE  /api/access-reviews/<int:campaign_id>
PATCH  /api/access-reviews/<int:campaign_id>/reviews/<int:review_id>
PUT/DELETE  /api/webhooks/<int:webhook_id>
PUT/DELETE  /api/risk-rules/<int:rule_id>
PUT/DELETE  /api/saved-views/<int:view_id>
GET/PUT/DELETE  /api/groups/<int:group_id>
PATCH/DELETE  /api/notifications/<int:notification_id>
GET/PATCH  /api/anomalies/<int:anomaly_id>
GET  /api/runs/<int:run_id>/drift
PUT  /api/subscriptions/<int:sub_id>/deactivate
PATCH  /api/compliance/frameworks/<int:framework_id>
```

### `<identity_id>` -- Plain String Parameters

Used for UUID-like identity IDs (Entra Object IDs) and other string identifiers.

```
GET  /api/identities/<identity_id>
GET  /api/identities/<identity_id>/graph-data
GET  /api/identities/<identity_id>/pim
GET  /api/identities/<identity_id>/usage
GET  /api/identities/<identity_id>/lifecycle
GET  /api/identities/<identity_id>/risk-history
GET  /api/identities/<identity_id>/anomalies
GET  /api/identities/<identity_id>/remediations
GET  /api/identities/<identity_id>/remediation-status
POST /api/identities/<identity_id>/remediation-action
GET  /api/identities/<identity_id>/groups
GET  /api/identities/<identity_id>/timeline
GET  /api/identities/<identity_id>/attack-paths
POST /api/identities/<identity_id>/simulate
POST /api/service-accounts/<identity_id>/attest
GET  /api/governance/identities/<identity_id>
POST /api/governance/identities/<identity_id>/decide
GET  /api/app-registrations/<app_id>
GET  /api/tenants/by-slug/<slug>
GET  /api/export/<export_type>
```

---

## Auth Decorator Reference

### `@require_role(*roles)`

Client portal role check. Verifies `g.current_user['role']` is in the allowed list.

```python
@require_role('admin')                              # Admin only
@require_role('admin', 'security_admin')            # Admin or Security Admin
@require_role('auditor', 'admin')                   # Auditor or Admin
@require_role('admin', 'security_admin', 'auditor') # Admin, SA, or Auditor
@require_role('compliance', 'reader', 'admin')      # Compliance, Reader, or Admin
@require_role('admin', 'security_admin', 'compliance', 'reader')  # 4 roles
```

**Used on 68 route registrations.**

### `@require_superadmin()`

Superadmin-only access. Checks `g.current_user['is_superadmin'] == True`.

```python
@require_superadmin()  # Used on: DELETE /api/tenants/<id>, GET /api/portal-users
```

**Used on 2 route registrations.**

### `@require_portal_access()`

Any admin portal role. Accepts all 4 `VALID_PORTAL_ROLES` (superadmin, poweradmin, billing, reader) plus `is_superadmin=True` as fallback.

```python
@require_portal_access()  # Used on: GET /api/tenants, GET /api/analytics/*
```

**Used on 4 route registrations.**

### `@require_portal_role(*roles)`

Specific admin portal roles. Falls back to `is_superadmin` for backward compatibility.

```python
@require_portal_role('superadmin', 'poweradmin')  # Used on: POST/PUT /api/tenants, provision, logo
```

**Used on 6 route registrations.**

---

## Auth Middleware Flow

1. **Public path check**: If path is in `PUBLIC_PATHS` set or matches prefix rules (`/api/tenants/by-slug/`, `/api/auth/saml/`, `/api/auth/sso-status`), skip auth.
2. **Non-API path check**: If path does not start with `/api/`, skip auth.
3. **OPTIONS method**: Always allowed (CORS preflight).
4. **API Key auth**: Check `X-API-Key` header or `Bearer ag_...` prefix. Validates key hash in DB.
5. **JWT auth**: Standard `Bearer <token>` header. Decodes and verifies HS256 JWT.
6. **Superadmin override**: If `X-Tenant-Id` header present and user is superadmin, override tenant context.
7. **Role decorators**: Applied after middleware. Return 403 if role mismatch.

---

## Route Registration Summary by HTTP Method

| Method | Count |
|--------|-------|
| GET | 118 |
| POST | 51 |
| PUT | 12 |
| DELETE | 13 |
| PATCH | 4 |
| **Total** | **198** (note: 3 path aliases share the `get_stats()` handler) |
