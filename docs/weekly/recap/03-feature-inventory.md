# AuditGraph Feature Inventory

> Comprehensive catalog of all implemented features, organized by phase.
> Last updated: 2026-02-16

---

## Feature Summary

| Metric | Count |
|--------|-------|
| Phases implemented | 85+ |
| Database tables | 56 |
| API routes (registered) | 198 |
| Frontend pages (.tsx) | 38 |
| Frontend components (.tsx) | 46 |
| Dashboard widgets | 21+ |
| Backend Python modules | 26 |
| Backend total LOC | ~35,000+ |
| Frontend total LOC | ~36,000+ |

---

## Database Table Inventory (56 tables)

### Core Discovery Tables (from migrations)

| Table | Source | Purpose |
|-------|--------|---------|
| `discovery_runs` | Migration 001 | Discovery run metadata (status, timing, counts, tenant_id) |
| `identities` | Migration 001 | Master identity table (display_name, type, risk_score, category, cloud, activity_status, primary_subscription_id, additional_subscription_count) |
| `role_assignments` | Migration 001 | Azure RBAC role assignments per identity |
| `entra_role_assignments` | Migration 001 | Entra (AAD) directory role assignments |
| `identity_roles` | Migration 001 | Legacy role tracking |
| `credentials` | Migration 002 | Secrets, certificates, federated credentials with expiry tracking |
| `graph_api_permissions` | Migration 003 | Microsoft Graph API permission grants (Application vs Delegated) |
| `sp_app_roles` | Migration 004 | Service principal app role assignments |
| `role_permissions` | Migration 005 | Role permission details for intelligence |
| `role_activity_log` | Migration 005 | Role activity tracking |
| `role_attack_patterns` | Migration 005 | Known attack patterns for roles |
| `role_hipaa_mappings` | Migration 005 | HIPAA compliance mappings for roles |
| `sp_ownership` | Migration 007 | Service principal owner relationships |
| `pim_eligible_assignments` | Migration 010 | PIM eligible role assignments (identity_db_id FK) |
| `pim_activations` | Migration 010 | PIM activation history (identity_db_id FK) |
| `ca_policies` | Migration 011 | Conditional Access policies |
| `ca_identity_coverage` | Migration 011 | CA coverage per identity |
| `remediation_playbooks` | Migration 012 | 20 seeded remediation playbooks with pattern matching |
| `drift_reports` | Migration 013 | Persisted drift detection results |
| `settings` | Migration 014 | Key-value configuration store (tenant-scoped) |
| `activity_log` | Migration 015 | Append-only audit trail (user_id, tenant_id) |
| `risk_scores` | Discovery | Historical risk score snapshots |

### Application Tables (from database.py _ensure_* methods)

| Table | Purpose |
|-------|---------|
| `remediation_actions` | Remediation execution tracking (status, log, executed_by) |
| `webhooks` | Webhook endpoint configurations |
| `webhook_deliveries` | Webhook delivery history and retry tracking |
| `custom_risk_rules` | User-defined risk scoring rules |
| `notifications` | In-app notification inbox |
| `users` | User accounts (username, password_hash, role, email, phone, auth_provider, external_id, tenant_id) |
| `refresh_tokens` | JWT refresh token store |
| `sso_auth_codes` | One-time SAML SSO auth codes (60s TTL) |
| `admin_audit_log` | Admin portal audit trail |
| `compliance_frameworks` | Compliance framework definitions (6 frameworks) |
| `compliance_controls` | Individual compliance controls (30 controls) |
| `compliance_root_causes` | Root cause analysis for compliance failures |
| `compliance_snapshots` | Historical compliance score snapshots |
| `azure_storage_accounts` | Azure Storage Account security posture (35 columns) |
| `azure_key_vaults` | Azure Key Vault security posture (37 columns) |
| `app_registrations` | Azure AD app registrations (36 columns, UNIQUE on run_id+app_id) |
| `saved_views` | User-saved identity filter views |
| `access_review_campaigns` | Access review campaign definitions |
| `campaign_reviews` | Individual review decisions within campaigns |
| `campaign_audit_log` | Access review audit trail |
| `identity_groups` | Custom and auto identity groupings |
| `identity_group_members` | Group membership junction table |
| `anomalies` | Detected anomalies (6 types, severity, resolved status) |
| `api_keys` | API key store (SHA-256 hashed, role-scoped) |
| `soar_playbooks` | SOAR automation playbook definitions |
| `soar_actions` | SOAR action execution history |
| `dashboard_preferences` | Per-user dashboard widget layout |
| `tenants` | Multi-tenant definitions (name, slug, plan, license dates) |
| `sa_attestations` | Service account governance attestations |
| `governance_decisions` | NHI governance approval/rejection decisions |
| `copilot_conversations` | AI Copilot conversation history (JSONB messages) |
| `cloud_subscriptions` | Cloud subscription/account inventory |
| `identity_subscription_access` | Identity-to-subscription RBAC junction table |

---

## Phase-by-Phase Feature List

---

### Phase 1: Overview Page

**What it does**: Global risk intelligence landing page with attack surface score (6-pillar weighted scoring), risk drivers, credential snapshot, trust metrics, and 30-day trend comparison.

**Backend components**:
- `handlers.py`: `get_stats()`, `get_overview_insights()`, `get_attack_surface_score()`
- Computes attack surface score from 6 weighted pillars
- Trend comparison against previous discovery run

**Frontend components**:
- `pages/Overview.tsx` (515 lines)
- `components/overview/GlobalRiskCards.tsx` (135 lines) -- top-level risk metric cards
- `components/overview/CategoryRiskGrid.tsx` (155 lines) -- risk breakdown by identity category
- `components/overview/CriticalIdentitiesList.tsx` (137 lines) -- highest-risk identities
- `components/overview/InsightsPanel.tsx` (354 lines) -- AI-generated security insights
- `components/overview/CloudComparison.tsx` (395 lines) -- multi-cloud posture comparison

**API endpoints**:
- `GET /api/stats` -- latest run summary + previous_run for trend
- `GET /api/identity-summary` -- category risk breakdown + monitored_resources
- `GET /api/overview/insights` -- computed security insights
- `GET /api/overview/attack-surface-score` -- 6-pillar weighted score

**DB tables**: `discovery_runs`, `identities`, `risk_scores`

**Known gaps**: Insights are rule-based, not ML-driven. Attack surface score weights are hardcoded.

---

### Phase 2: Dashboard

**What it does**: 6-tab operational dashboard (Exposure & Risk, Credential Intelligence, Trust & Access, Usage & Optimization, Governance & Compliance, Platform & Discovery) with 21+ widgets and 11 parallel API calls on mount.

**Backend components**:
- `handlers.py`: `get_dashboard_posture()`, `get_credential_intelligence()`, `get_dashboard_trust()`, `get_dashboard_compliance()`, `get_dashboard_conditional_access()`, `get_dashboard_role_usage()`, `get_dashboard_anomalies()`

**Frontend components**:
- `pages/Dashboard.tsx` (580 lines) -- main dashboard shell with 6 tabs
- `components/dashboard/PostureScore.tsx` (102 lines) -- overall posture score dial
- `components/dashboard/CredentialHealth.tsx` (63 lines) -- credential expiry summary
- `components/dashboard/CredentialIntelligence.tsx` (145 lines) -- deep credential analytics
- `components/dashboard/TrustAccessPanel.tsx` (206 lines) -- trust and access metrics
- `components/dashboard/QuickActions.tsx` (111 lines) -- action item counts
- `components/dashboard/RiskHeatMap.tsx` (122 lines) -- category x severity heatmap
- `components/dashboard/RiskDonutChart.tsx` (146 lines) -- risk distribution pie
- `components/dashboard/RiskTrendChart.tsx` (159 lines) -- historical risk trend
- `components/dashboard/RiskVelocityChart.tsx` (146 lines) -- inflow/outflow velocity
- `components/dashboard/RoleUsageChart.tsx` (164 lines) -- role usage analytics
- `components/dashboard/ComplianceScorecard.tsx` (180 lines) -- GRC scorecard
- `components/dashboard/ConditionalAccessCard.tsx` (134 lines) -- CA policy summary
- `components/dashboard/AnomalyAlerts.tsx` (125 lines) -- top unresolved anomalies
- `components/dashboard/SOARActivity.tsx` (127 lines) -- SOAR action feed
- `components/dashboard/RecentChanges.tsx` (109 lines) -- latest drift changes
- `components/dashboard/RemediationProgress.tsx` (69 lines) -- remediation status
- `components/dashboard/PlatformHealth.tsx` (84 lines) -- system health badge
- `components/dashboard/CloudContextBanner.tsx` (91 lines) -- cloud connection status
- `components/dashboard/ResourceOverview.tsx` (174 lines) -- resource security summary
- `components/dashboard/ExpiryTracker.tsx` (107 lines) -- KV/cert expiry countdown
- `components/dashboard/ServiceAccountGovernance.tsx` (109 lines) -- SA governance widget
- `components/dashboard/CustomizePanel.tsx` (162 lines) -- widget toggle drawer

**API endpoints**:
- `GET /api/dashboard/posture`
- `GET /api/dashboard/credential-intelligence`
- `GET /api/dashboard/trust`
- `GET /api/dashboard/compliance`
- `GET /api/dashboard/conditional-access`
- `GET /api/dashboard/anomalies`
- `GET /api/dashboard/role-usage`
- `GET /api/dashboard/summary`

**DB tables**: All core tables (aggregated queries)

**Known gaps**: 11 parallel API calls on mount can strain backend under load. No server-side caching layer.

---

### Phase 3: Identities Table

**What it does**: 14-column sortable identity inventory with advanced filtering (risk, category, cloud, subscription, activity, tier, credential status, CA status), saved views, bulk operations, QueryBuilder (simple/advanced mode), and 4 export formats (CSV selected, CSV all, PDF, JSON).

**Backend components**:
- `handlers.py`: `get_identities()`, `query_identities()`, `get_query_fields()`
- `_identity_list_select()` and `_map_identity_row()` shared helpers
- `QUERY_FIELD_MAP` (25 direct columns) + `QUERY_COMPUTED_FIELDS` (3 subqueries) for SQL injection prevention

**Frontend components**:
- `pages/Identities.tsx` (1,571 lines) -- main table page
- `components/QueryBuilder.tsx` (379 lines) -- simple/advanced filter builder
- `components/IdentityDrawer.tsx` (750 lines) -- side panel preview
- `components/graph/ExposureGraph.tsx` (157 lines) -- inline exposure visualization
- `components/Sparkline.tsx` (86 lines) -- inline risk trend sparkline

**API endpoints**:
- `GET /api/identities` -- paginated list (supports `limit`, `offset`, `cloud`, `risk_level`, `identity_category`, `search`)
- `POST /api/identities/query` -- advanced query (AND/OR groups, 28 fields, 10 operators)
- `GET /api/identities/query/fields` -- available fields, operators, value suggestions
- `POST /api/identities/risk-history/batch` -- batch sparkline data

**DB tables**: `identities`, `risk_scores`, `role_assignments`, `credentials`

**Known gaps**: No server-side column sorting (client-side only for visible page). Bulk operations are sequential, not batched.

---

### Phase 4: Identity Detail

**What it does**: 13-tab identity deep dive providing complete security posture for a single identity. Tabs: Overview, Roles, Permissions, Credentials, Ownership, Access Graph, Anomalies, PIM, Compliance, Remediation, Lifecycle, What If (Risk Simulation), Timeline (Forensic View).

**Backend components**:
- `handlers.py`: `get_identity_detail()`, `get_identity_graph_data()`, `get_identity_pim()`, `get_identity_anomalies()`, `get_identity_remediations()`, `get_identity_lifecycle()`, `get_identity_risk_history()`, `get_identity_usage()`, `get_identity_timeline()`, `get_identity_attack_paths()`, `simulate_identity_risk()`

**Frontend components**:
- `pages/IdentityDetail.tsx` (2,883 lines) -- 13-tab layout shell
- `components/graph/AccessGraphTab.tsx` (492 lines) -- dual-mode access graph
- `components/graph/AttackPathView.tsx` (187 lines) -- attack path visualization
- `components/graph/nodes.tsx` (372 lines) -- 13 custom ReactFlow node types

**API endpoints**:
- `GET /api/identities/<id>` -- full detail with roles, permissions, app_roles, owners, trend, evidence
- `GET /api/identities/<id>/graph-data` -- access graph (trust, scope, exposure, pre-computed nodes/edges)
- `GET /api/identities/<id>/pim` -- PIM eligible assignments, activations, overuse metrics
- `GET /api/identities/<id>/anomalies` -- identity-specific anomalies
- `GET /api/identities/<id>/remediations` -- matched remediation playbooks
- `GET /api/identities/<id>/lifecycle` -- lifecycle events
- `GET /api/identities/<id>/risk-history` -- risk score over time
- `GET /api/identities/<id>/usage` -- usage intelligence
- `GET /api/identities/<id>/timeline` -- forensic timeline (5 event sources)
- `GET /api/identities/<id>/attack-paths` -- 5 escalation chain types
- `POST /api/identities/<id>/simulate` -- what-if risk simulation
- `GET /api/identities/<id>/subscriptions` -- multi-subscription access
- `GET /api/identities/<id>/groups` -- group memberships

**DB tables**: All core identity tables + `anomalies`, `pim_*`, `remediation_*`, `risk_scores`

**Known gaps**: IdentityDetail.tsx is 2,883 lines and should be decomposed. 13 sub-API calls on mount.

---

### Phases 5-6: Pagination & Multi-Cloud Foundation

**What it does**: API-level pagination (limit/offset) on identity list endpoints. BaseDiscoveryEngine abstract class defining `discover()` and `test_connection()` interface. AWS and GCP discovery engine stubs.

**Backend components**:
- `engines/discovery/base.py` (43 lines) -- BaseDiscoveryEngine ABC
- `engines/discovery/aws_discovery.py` (114 lines) -- AWSDiscoveryEngine stub (8 privileged IAM policy ARNs defined)
- `engines/discovery/gcp_discovery.py` (112 lines) -- GCPDiscoveryEngine stub (12 privileged GCP roles defined)

**API endpoints**: Pagination params added to `GET /api/identities`, `GET /api/activity`, `GET /api/drift/history`

**DB tables**: No new tables. Added `cloud` column to `identities`.

**Known gaps**: AWS and GCP engines are stubs only -- no actual cloud API integration. No cursor-based pagination (offset can be slow at scale).

---

### Phase 7: Access Graph

**What it does**: Dual-mode (Executive/Technical) ReactFlow-based access visualization. Executive mode shows 3-5 summary nodes (identity, risk_summary, blast_radius, owner, federated_trust). Technical mode shows full ARM tree (Subscription -> Resource Group -> Resource) with Entra directory branch, permissions, and credentials.

**Backend components**:
- `handlers.py`: `get_identity_graph_data()` -- pre-computes node positions server-side
- `scope_hierarchy` computed at line ~1649 drives the ARM tree layout
- Entra branch positioned upper-right, ARM tree below, permissions below that, credentials at bottom, owners/federated in left column

**Frontend components**:
- `components/graph/AccessGraphTab.tsx` (492 lines) -- graph container with mode toggle
- `components/graph/nodes.tsx` (372 lines) -- 13 custom node types: `identity`, `risk_summary`, `blast_radius`, `owner`, `federated_trust`, `role`, `permission`, `credential`, `scope`, `subscription`, `resource_group`, `resource`, `entra_directory`

**API endpoints**:
- `GET /api/identities/<id>/graph-data`

**DB tables**: `role_assignments`, `entra_role_assignments`, `graph_api_permissions`, `credentials`, `sp_ownership`

**Known gaps**: Node positions pre-computed server-side (no client-side auto-layout). Large graphs (100+ nodes) can cause rendering performance issues. @xyflow/react v12 + React 19 requires `!!data.field &&` pattern due to `Record<string, unknown>` typing.

---

### Phase 8: PIM Tracking

**What it does**: Privileged Identity Management discovery and display -- eligible roles, activation history, overuse metrics (activations/month, avg duration, percentage used vs eligible).

**Backend components**:
- `azure_discovery.py`: PIM eligible assignment + activation discovery via Graph API `roleManagement`
- `handlers.py`: `get_identity_pim()`

**Frontend components**: PIM tab in IdentityDetail, PIM badge in Identities table

**API endpoints**:
- `GET /api/identities/<id>/pim`

**DB tables**: `pim_eligible_assignments`, `pim_activations` (both use `identity_db_id` FK keyed by `object_id`)

**Known gaps**: PIM data keyed by `object_id` (not `identity_id`/`app_id`). Requires `RoleManagement.Read.Directory` Graph API permission.

---

### Phase 9: Conditional Access

**What it does**: CA policy discovery, per-identity coverage computation, MFA enforcement tracking, and dashboard card showing weak/missing policies.

**Backend components**:
- `azure_discovery.py`: CA policy discovery via Graph API `Policy.Read.All`
- `handlers.py`: `get_dashboard_conditional_access()`
- Coverage heuristic: all-user enabled policies, check exclusion list

**Frontend components**: ConditionalAccessCard dashboard widget, shield icon in Identities table

**API endpoints**:
- `GET /api/dashboard/conditional-access`

**DB tables**: `ca_policies`, `ca_identity_coverage`

**Known gaps**: Simplified coverage heuristic -- does not evaluate nested group membership or device compliance conditions.

---

### Phase 10: Hierarchical Access Graph

**What it does**: ARM tree layout in technical access graph mode (Subscription -> Resource Group -> Resource) with 4 new node types and Entra directory branch.

**Backend components**: Enhanced `get_identity_graph_data()` with scope hierarchy parsing

**Frontend components**: 4 new ReactFlow node types: `subscription`, `resource_group`, `resource`, `entra_directory`

**Known gaps**: Deep hierarchies (5+ levels) can overflow viewport.

---

### Phase 11: Dashboard Cloud Context

**What it does**: CloudContextBanner widget showing connected cloud providers (Azure/AWS/GCP), connection status, and monitored resource counts per provider.

**Frontend components**: `components/dashboard/CloudContextBanner.tsx` (91 lines)

**API endpoints**: Uses `/api/tenant/config` for cloud connection status

---

### Phase 12: Remediation Engine

**What it does**: 20 seeded remediation playbooks with pattern-matching against identity risk factors. Each playbook has conditions, severity, category, and step-by-step remediation instructions.

**Backend components**:
- `handlers.py`: `get_identity_remediations()` -- matches playbooks to identity risk profile
- Playbooks seeded in `database.py` during schema creation

**Frontend components**: Remediation tab in IdentityDetail

**API endpoints**:
- `GET /api/identities/<id>/remediations`

**DB tables**: `remediation_playbooks`

**Known gaps**: Playbooks are static (seeded). No user-created playbook support via UI (only DB).

---

### Phase 13: Report Generation

**What it does**: 3 PDF report types -- Full Audit (multi-page with cover, exec summary, compliance, top risks, remediation playbook, evidence), Executive Summary (A4 landscape 1-page posture circle), and Compliance report.

**Backend components**:
- `handlers.py`: `get_reports_data()` -- comprehensive JSON aggregation for PDF generation

**Frontend components**:
- `pages/Reports.tsx` (267 lines) -- report type toggle and download
- `utils/pdfGenerator.ts` -- jsPDF + autoTable multi-page report generator
- `utils/spnPdfGenerator.ts` -- SPN-specific privilege report

**API endpoints**:
- `GET /api/reports/data`

**Known gaps**: PDF generated client-side (large datasets can cause browser memory issues). No server-side PDF generation. No scheduled PDF export.

---

### Phase 14: Drift Detection

**What it does**: Run-to-run comparison detecting 5 change types: new identities, removed identities, permission changes, risk score changes, credential changes. Results persisted for historical access.

**Backend components**:
- `engines/drift_detector.py` (439 lines) -- `compare_runs()` method
- `handlers.py`: `get_drift_latest()`, `get_drift_history()`, `get_run_drift()`

**Frontend components**: RecentChanges dashboard widget, DriftHistory page

**API endpoints**:
- `GET /api/drift/latest` -- most recent drift summary
- `GET /api/drift/history` -- drift report history list
- `GET /api/runs/<id>/drift` -- full drift for specific run (persisted or live-computed)

**DB tables**: `drift_reports`

**Known gaps**: Drift detection is purely point-in-time comparison. No continuous streaming drift detection.

---

### Phase 15: Settings & Configuration

**What it does**: Key-value settings store with 13+ UI sections: Organization, Scheduler, Email, Scheduled Reports, Risk Rules, Webhooks, API Keys, SOAR, SSO/SAML, SA Governance, Data Retention, Integrations (Slack/Teams), Cloud Connections.

**Backend components**:
- `handlers.py`: `get_settings()`, `update_settings()`
- `database.py`: settings CRUD with tenant scoping

**Frontend components**:
- `pages/Settings.tsx` (4,327 lines) -- 13 collapsible sections

**API endpoints**:
- `GET /api/settings` -- all settings + status
- `POST /api/settings` -- update settings
- `POST /api/settings/test-email` -- send test email
- `POST /api/settings/test-connection` -- test cloud connection

**DB tables**: `settings`

**Known gaps**: Settings.tsx is 4,327 lines and should be split into section components. No settings import/export. No settings change history.

---

### Phase 16: Drift History

**What it does**: Timeline table with expandable detail views showing 5 collapsible change sections (new/removed/permission/risk/credential changes) per drift report.

**Frontend components**:
- `pages/DriftHistory.tsx` (618 lines)

**API endpoints**: Uses `GET /api/drift/history`

---

### Phase 17: Activity Log

**What it does**: Append-only audit trail recording all system actions (discovery, settings changes, report generation, drift detection, user management, etc.) with action type filtering.

**Backend components**:
- `database.py`: `_ensure_activity_log_table()`, `log_activity()`
- `handlers.py`: `_log()` helper auto-injects user/tenant context

**Frontend components**:
- `pages/ActivityLog.tsx` (257 lines) -- timeline with action type badges and filter buttons

**API endpoints**:
- `GET /api/activity` -- supports `limit`, `offset`, `type` filter

**DB tables**: `activity_log` (user_id, tenant_id, action, description, metadata JSONB)

---

### Phase 18: Scheduled Reports & Email

**What it does**: Email notifications via Microsoft Graph API (primary) or SendGrid (fallback). Test email, identity change reports, and scheduled weekly/monthly report delivery via APScheduler.

**Backend components**:
- `services/email_service.py` (795 lines) -- `send_identity_change_report()`, `send_test_email()`, `send_scheduled_report()`
- `services/sendgrid_service.py` (78 lines) -- SendGrid fallback
- `scheduler.py`: Second APScheduler job for report delivery

**Frontend components**: Section 4 in Settings (weekly/monthly toggle)

**Known gaps**: Email HTML has XSS risk -- identity display names not escaped in templates.

---

### Phases 19-29: Identity Comparison, Bulk Ops, Dark Mode, Webhooks, Custom Risk Rules, Notifications

**What these do**: A collection of platform enhancement features.

#### Identity Comparison (Phase 19)
- **Frontend**: `pages/IdentityComparison.tsx` (603 lines) -- side-by-side identity comparison
- **API**: `GET /api/groups/compare`

#### Dark Mode (Phase 21)
- **Frontend**: `hooks/useTheme.ts` -- system/manual theme toggle
- CSS variables for dark theme

#### Webhooks (Phase 24)
- **Backend**: `services/webhook_service.py` (148 lines) -- 7 event types
- **DB tables**: `webhooks`, `webhook_deliveries`
- **API**: `GET/POST/PUT/DELETE /api/webhooks`, `POST /api/webhooks/<id>/test`, `GET /api/webhooks/<id>/deliveries`
- **Known gaps**: No webhook URL validation (SSRF risk)

#### Custom Risk Rules (Phase 25)
- **Backend**: `engines/risk_rules.py` (176 lines) -- field/operator validation, rule evaluation
- **DB tables**: `custom_risk_rules`
- **API**: `GET/POST/PUT/DELETE /api/risk-rules`, `POST /api/risk-rules/preview`

#### Notifications (Phase 26-30)
- **Backend**: `services/notification_service.py` (197 lines) -- in-app notification creation
- **Frontend**: `pages/NotificationCenter.tsx` (401 lines) -- bell badge, severity/category filters
- **DB tables**: `notifications`
- **API**: `GET /api/notifications`, `GET /api/notifications/stats`, `PATCH /api/notifications/<id>`, `POST /api/notifications/mark-all-read`, `DELETE /api/notifications/<id>`

---

### Phase 31: RBAC & Authentication

**What it does**: JWT authentication (PyJWT + bcrypt), role-based access control with 3 client roles (admin, auditor, viewer -- later extended to admin/security_admin/compliance/reader in Phase 85), Login page, protected routes, user management.

**Backend components**:
- `api/auth.py` (256 lines) -- `auth_login()`, `auth_refresh()`, `auth_logout()`, `auth_me()`, `require_auth()` decorator, `require_role()` decorator
- `database.py`: user CRUD, refresh token management
- Default admin: `admin`/`changeme` (from env `ADMIN_USERNAME`/`ADMIN_PASSWORD`)
- `_users_ensured` class flag prevents repeated DDL

**Frontend components**:
- `pages/Login.tsx` (433 lines) -- login form with SSO button
- `pages/ForgotPassword.tsx` (117 lines)
- `pages/ResetPassword.tsx` (197 lines)
- `contexts/AuthContext.tsx` -- global `window.fetch` interceptor auto-attaches Bearer token, permission booleans

**API endpoints**:
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `PUT /api/auth/password`
- `POST /api/auth/forgot-password`
- `GET /api/auth/validate-reset-token`
- `POST /api/auth/reset-password`
- `GET/POST /api/users`
- `PUT/DELETE /api/users/<id>`
- `POST /api/users/<id>/reset-password`

**DB tables**: `users`, `refresh_tokens`

**Known gaps**: Login deadlock fix required: `auth_login()` must close DB connection BEFORE calling `generate_refresh_token()`. PyJWT `sub` must be string (not int).

---

### Phases 32-38: Compliance, Export, Saved Views, Identity Lifecycle, Access Reviews, Role Mining, Identity Groups

#### Compliance Frameworks (Phase 32)
- **What**: 6 compliance frameworks, 30 controls, metric-based evaluation, gap analysis, trend tracking
- **Backend**: `engines/risk_catalog.py` (276 lines) -- compliance evaluation
- **Frontend**: `pages/Compliance.tsx` (900 lines)
- **DB tables**: `compliance_frameworks`, `compliance_controls`, `compliance_root_causes`, `compliance_snapshots`
- **API**: `GET /api/compliance/frameworks`, `PATCH /api/compliance/frameworks/<id>`, `GET /api/compliance/gap-analysis`, `GET /api/compliance/trends`, `GET /api/compliance/intelligence`

#### Export Pipeline (Phase 33)
- **Frontend**: `pages/Exports.tsx` (204 lines), `utils/exportUtils.ts`
- **API**: `GET /api/export/<export_type>`

#### Saved Views (Phase 34)
- **DB tables**: `saved_views`
- **API**: `GET/POST/PUT/DELETE /api/saved-views`, `POST /api/saved-views/<id>/default`

#### Access Reviews (Phase 36)
- **What**: Campaign system with AI recommendations (approve/revoke/flag/downgrade/convert_pim/rotate_secret), bulk review actions
- **Frontend**: `pages/AccessReviews.tsx` (1,301 lines)
- **DB tables**: `access_review_campaigns`, `campaign_reviews`, `campaign_audit_log`
- **API**: `GET/POST /api/access-reviews`, `GET/PUT/DELETE /api/access-reviews/<id>`, `PATCH /api/access-reviews/<id>/reviews/<id>`, `POST /api/access-reviews/<id>/reviews/bulk`, `GET /api/access-reviews/metrics`, `GET /api/access-reviews/<id>/audit-log`

#### Role Mining (Phase 37)
- **What**: Unused/redundant/orphaned roles, toxic combos, role bundles, assignment method enrichment, multi-source evidence, PIM-aware blast radius
- **Backend**: `engines/role_mining.py` (1,198 lines)
- **Frontend**: `pages/RoleMining.tsx` (790 lines)
- **API**: `GET /api/role-mining`

#### Identity Groups (Phase 38)
- **What**: Custom + auto groups with member management, group comparison
- **Frontend**: `pages/IdentityGroups.tsx` (600 lines)
- **DB tables**: `identity_groups`, `identity_group_members`
- **API**: `GET/POST /api/groups`, `GET /api/groups/compare`, `GET/PUT/DELETE /api/groups/<id>`, `POST/DELETE /api/groups/<id>/members`, `GET /api/identities/<id>/groups`

---

### Phase 39: Advanced Query Builder

**What it does**: POST-based query endpoint with 28 searchable fields, 10 operators (equals, not_equals, contains, not_contains, starts_with, greater_than, less_than, in, not_in, is_null), AND/OR group logic. Simple and advanced mode toggle in Identities page.

**Backend components**:
- `handlers.py`: `query_identities()`, `get_query_fields()`
- `QUERY_FIELD_MAP` (25 direct columns) + `QUERY_COMPUTED_FIELDS` (3 subqueries)
- All fields use `i.` alias for SQL injection prevention

**Frontend components**:
- `components/QueryBuilder.tsx` (379 lines)

**API endpoints**:
- `POST /api/identities/query`
- `GET /api/identities/query/fields`

---

### Phase 40: Anomaly Detection

**What it does**: 6 anomaly detection types running after each discovery scan: permission_escalation, risk_score_spike, dormant_reactivation, credential_surge, off_hours_pim, excessive_pim_usage.

**Backend components**:
- `engines/anomaly_detector.py` (423 lines) -- `AnomalyDetector` with 6 `_detect_*` methods
- `scheduler.py`: runs anomaly detection after drift detection

**Frontend components**: AnomalyAlerts dashboard widget, Anomalies tab in IdentityDetail

**API endpoints**:
- `GET /api/anomalies` -- list (filters: type, severity, identity_id, resolved, run_id)
- `GET /api/anomalies/stats` -- summary (total, unresolved, by_type, by_severity)
- `GET /api/anomalies/<id>` -- single anomaly detail
- `PATCH /api/anomalies/<id>` -- resolve anomaly (admin/auditor)
- `GET /api/identities/<id>/anomalies` -- identity-specific anomalies
- `GET /api/dashboard/anomalies` -- top unresolved for dashboard

**DB tables**: `anomalies`

---

### Phase 41: Risk Trend Analytics

**What it does**: Enhanced trend API with posture_score and avg_risk_score history. Velocity API tracking risk inflow/outflow/retention. Per-identity risk history and batch sparkline data for the identities table.

**Backend components**:
- `handlers.py`: `get_trends()`, `get_trends_velocity()`

**Frontend components**: RiskVelocityChart dashboard widget, Sparkline column in Identities table, Risk Score Trajectory chart in IdentityDetail Overview

**API endpoints**:
- `GET /api/trends`
- `GET /api/trends/velocity`
- `POST /api/identities/risk-history/batch`
- `GET /api/identities/<id>/risk-history`

**DB tables**: `risk_scores`

---

### Phase 42: API Key Management

**What it does**: External API key system with `ag_` prefix, SHA-256 hashed storage, role-scoped access, usage tracking, dual auth support (X-API-Key header or Bearer ag_...).

**Backend components**:
- `api/auth.py`: API key authentication path
- `database.py`: API key CRUD, usage counter increment

**Frontend components**: API Keys section in Settings (create/edit/toggle/delete), one-time key display modal

**API endpoints**:
- `GET /api/api-keys` -- list (admin only)
- `POST /api/api-keys` -- create (returns raw key once)
- `PUT /api/api-keys/<id>` -- update
- `DELETE /api/api-keys/<id>` -- delete

**DB tables**: `api_keys`

---

### Phase 43: SOAR Integration

**What it does**: Security Orchestration, Automation and Response with playbooks, condition matching, cooldown periods, and 4 action types: webhook, create_ticket, send_notification, tag_for_review.

**Backend components**:
- `engines/soar_engine.py` (357 lines) -- `SoarEngine` with `evaluate_triggers()` and 4 `_action_*` methods
- `scheduler.py`: hooks for anomaly and drift triggers

**Frontend components**: SOARActivity dashboard widget, SOAR section in Settings

**API endpoints**:
- `GET/POST /api/soar/playbooks`
- `PUT/DELETE /api/soar/playbooks/<id>`
- `POST /api/soar/playbooks/<id>/test` -- dry-run test with mock event
- `GET /api/soar/actions` -- action history
- `GET /api/soar/actions/stats` -- action stats
- `POST /api/soar/execute` -- manual trigger

**DB tables**: `soar_playbooks`, `soar_actions`

**Known gaps**: SOAR credentials stored in plaintext (ServiceNow/Jira creds in JSONB `action_config`).

---

### Phase 44: Dashboard Customization

**What it does**: Per-user dashboard widget preferences with drag-drop toggle panel. 21 registered widgets with visibility and order persistence.

**Backend components**:
- `database.py`: dashboard preferences CRUD

**Frontend components**:
- `components/dashboard/CustomizePanel.tsx` (162 lines)
- `hooks/useDashboardPreferences.ts`
- `components/dashboard/widgetRegistry.ts`

**API endpoints**:
- `GET /api/dashboard/preferences`
- `PUT /api/dashboard/preferences`
- `DELETE /api/dashboard/preferences`

**DB tables**: `dashboard_preferences`

---

### Phases 45-46: Multi-Tenant Foundation & User Management

**What it does**: Full multi-tenant architecture with tenant table, JWT tenant context (`tenant_id`/`tenant_name`/`is_superadmin`), row-level security via `_tenant_id()` helper on 43 tables, superadmin role, X-Tenant-Id header override, TenantSwitcher in navigation.

**Backend components**:
- `database.py`: `_ensure_tenants_table()`, tenant CRUD, `_tenant_id()` helper
- `api/auth.py`: JWT includes tenant context
- `handlers.py`: `_log()` auto-injects user/tenant into activity log
- `require_superadmin()` decorator

**Frontend components**:
- TenantSwitcher dropdown in TopBar
- Tenant management section in Settings
- `contexts/TenantContext.tsx`

**API endpoints**:
- `GET/POST /api/tenants`
- `PUT/DELETE /api/tenants/<id>`
- `GET /api/tenant` -- current tenant info
- `GET /api/tenant/config` -- cloud provider & add-on config
- `GET /api/auth/tenants` -- user's accessible tenants
- `GET /api/tenants/by-slug/<slug>`

**DB tables**: `tenants`, `admin_audit_log`

---

### Phases 47-51: Cross-Tenant Analytics, Onboarding, Risk Simulation, Search Modal, Compliance Trend

#### Cross-Tenant Analytics (Phase 47)
- **Frontend**: `pages/CrossTenantAnalytics.tsx` (398 lines)
- **API**: `GET /api/analytics/tenants`, `GET /api/analytics/tenants/trends`, `GET /api/analytics/login-sessions`

#### Onboarding Wizard (Phase 48)
- **Frontend**: `pages/OnboardingWizard.tsx` (405 lines) / `pages/admin/AdminOnboarding.tsx` (442 lines) -- 5-step wizard
- **API**: `GET /api/onboarding/status`, `POST /api/onboarding/test-connection`

#### Risk Simulation / What-If (Phase 49)
- **Frontend**: What If tab in IdentityDetail
- **API**: `POST /api/identities/<id>/simulate`

#### Search Modal (Phase 50)
- **Frontend**: `components/SearchModal.tsx` (181 lines) -- Cmd+K debounced search

#### Compliance Trend Tracking (Phase 51)
- **DB tables**: `compliance_snapshots`
- **API**: `GET /api/compliance/trends`

---

### Phase 52: Azure Resource Discovery

**What it does**: Discovery and risk assessment of Azure Storage Accounts and Key Vaults with points-based risk scoring, CIS benchmark compliance, and cross-linking to identities via RBAC scope matching.

**Backend components**:
- `azure_discovery.py`: `StorageManagementClient` + `KeyVaultManagementClient` discovery, `MonitorManagementClient` for diagnostic logging
- `handlers.py`: resource list, stats, detail, access endpoints
- Points-based risk scoring for security posture

**Frontend components**:
- `pages/Resources.tsx` (461 lines) -- resource inventory list
- `pages/ResourceDetail.tsx` (1,089 lines) -- 5 tabs: Overview, Security, Network, Access, Compliance

**API endpoints**:
- `GET /api/resources` -- combined list (filters: resource_type, risk_level, subscription, search)
- `GET /api/resources/stats` -- summary counts by type and risk
- `GET /api/resources/<path:resource_id>` -- full detail
- `GET /api/resources/<path:resource_id>/access` -- identities with RBAC access
- `GET /api/resources/expiry-summary` -- KV expiry summary
- `GET /api/resources/compliance-summary` -- CIS compliance summary

**DB tables**: `azure_storage_accounts` (35 columns), `azure_key_vaults` (37 columns)

**Known gaps**: Flask `<path:resource_id>` strips leading `/` -- handlers must prepend `/` if missing.

---

### Phase 53: SaaS Platform

**What it does**: TenantContext for subdomain/portal detection, AdminConsole standalone layout, tenant-scoped login.

**Frontend components**:
- `contexts/TenantContext.tsx` (subdomain detection)
- `pages/AdminConsole.tsx` (251 lines)

---

### Phase 54: SSO/SAML Integration

**What it does**: SAML 2.0 SSO via python3-saml. Full flow: AuthnRequest -> IdP -> ACS -> one-time code -> JWT. Just-in-time (JIT) user provisioning, IdP group-to-role mapping, per-tenant SSO configuration, force-SSO mode.

**Backend components**:
- `api/saml.py` -- SAML helper module
- `database.py`: SSO auth code management, user JIT provisioning
- Users gain `auth_provider`/`external_id` columns

**Frontend components**:
- `pages/SsoCallback.tsx` (49 lines) -- code exchange callback
- SSO button on Login page
- SSO config section in Settings (IdP metadata parse, role mapping editor, force-SSO toggle)

**API endpoints**:
- `GET /api/auth/sso-status`
- `GET /api/auth/saml/metadata` -- SP metadata XML
- `GET /api/auth/saml/login` -- initiate AuthnRequest
- `POST /api/auth/saml/acs` -- assertion consumer service
- `POST /api/auth/saml/token` -- exchange one-time code for JWT
- `GET /api/auth/saml/slo` -- single logout
- `GET /api/settings/sso` -- SSO configuration
- `POST /api/settings/sso` -- update SSO config
- `POST /api/settings/sso/parse-metadata` -- parse IdP metadata XML

**DB tables**: `sso_auth_codes`

---

### Phase 58: Compliance Auto-Remediation

**What it does**: 5 remediation action types (flag_for_review, create_ticket, disable_identity, remove_role, rotate_credential) with execution tracking. Batch auto-execute rejects high-risk actions.

**Backend components**:
- `handlers.py`: `_execute_remediation()` engine -- real execution for flag_for_review, simulated for Azure ops
- Execution tracking columns: `execution_status`, `execution_log` (JSONB), `executed_at`, `executed_by`

**API endpoints**:
- `POST /api/identities/<id>/remediation-execute` -- execute single action
- `GET /api/remediation/queue` -- pending actions queue
- `POST /api/remediation/auto-execute` -- batch auto-execute
- `GET /api/identities/<id>/remediation-status`
- `POST /api/identities/<id>/remediation-action`
- `GET /api/remediation-summary`
- `POST /api/bulk/remediation`

**DB tables**: `remediation_actions`

**Known gaps**: Azure operations (disable_identity, remove_role, rotate_credential) are simulated, not real.

---

### Phase 63: Service Account Governance

**What it does**: Non-Human Identity (NHI) governance with configurable policies (`sa_gov_*` settings), governance status computation (compliant/needs_attention/non_compliant), attestation workflow.

**Backend components**:
- `database.py`: SA governance stats, attestation CRUD, governance decision tracking
- Governance status computed from policy thresholds

**Frontend components**:
- `pages/ServiceAccountGovernance.tsx` (1,014 lines) -- summary cards, governance table, attestation modal
- `components/dashboard/ServiceAccountGovernance.tsx` (109 lines) -- dashboard widget

**API endpoints**:
- `GET /api/service-accounts/stats`
- `GET /api/service-accounts/governance`
- `POST /api/service-accounts/<identity_id>/attest`
- `GET /api/settings/sa-governance`
- `POST /api/settings/sa-governance`
- `GET /api/governance/identities`
- `GET /api/governance/identities/<identity_id>`
- `POST /api/governance/identities/<identity_id>/decide`
- `GET /api/governance/stats`

**DB tables**: `sa_attestations`, `governance_decisions`

---

### Phase 68: Real-Time Monitoring & Health

**What it does**: MetricsCollector singleton (thread-safe, in-memory), request timing middleware, enhanced health endpoint (DB + scheduler + system), Prometheus-format metrics, system health page with 30s auto-refresh.

**Backend components**:
- `metrics.py` (MetricsCollector) -- `record_request()`, `prometheus_format()`
- Enhanced `/api/health` with DB, scheduler, system checks
- `psutil` for CPU/memory/disk metrics

**Frontend components**:
- `pages/SystemHealth.tsx` (353 lines) -- auto-refresh system dashboard

**API endpoints**:
- `GET /api/health` -- enhanced (DB + scheduler + system status)
- `GET /api/metrics` -- Prometheus format (public)
- `GET /api/system/health` -- API stats, top endpoints, runs, table sizes

**Known gaps**: Metrics not shared across gunicorn workers -- each worker has its own MetricsCollector instance. No external metrics aggregation (Datadog, Grafana).

---

### Phase 69: Resource Security Enhancements

**What it does**: 5 enhancements -- KV item-level expiry tracking (JSONB columns), key rotation compliance, enhanced identity access mapping (RBAC + access policy + over-privilege detection), SAS token audit, expanded CIS compliance (6->12 storage controls, 5->10 KV controls).

**Frontend components**: ExpiryTracker + ResourceOverview dashboard widgets

---

### Phase 70: Admin Console Enhancements

**What it does**: Dedicated admin portal at `/admin` with standalone layout (own top bar, no regular sidebar), delete tenant (type-to-confirm), edit tenant name, AdminBilling placeholder.

**Frontend components**:
- `pages/AdminConsole.tsx` (251 lines) -- layout shell
- `pages/admin/AdminOverview.tsx` (319 lines)
- `pages/admin/AdminTenants.tsx` (882 lines)
- `pages/admin/AdminUsers.tsx` (580 lines)
- `pages/admin/AdminBilling.tsx` (360 lines)
- `pages/admin/AdminMonitoring.tsx` (381 lines)
- `pages/admin/AdminOnboarding.tsx` (442 lines)
- `pages/admin/AdminProfile.tsx` (232 lines)

**Known gaps**: Admin portal has its own auth flow -- if `!user || !isSuperAdmin` shows AdminLogin component. Non-superadmin users get "Access denied".

---

### Phase 71: SPN Dashboard

**What it does**: Dedicated SPN management page with 5 summary cards (custom SPNs, critical/high, expired creds, expiring soon, high blast radius), activity and blast radius breakdowns, advanced filters, hide Microsoft toggle, drill-down panel with risk summary, credentials, RBAC/Entra roles, attacker narrative, auditor questions, and PDF privilege report.

**Backend components**:
- `handlers.py`: `get_spns_stats()`, `get_spns()`, `get_spn_detail()` -- auto-generated `risk_summary` and `recommendations`

**Frontend components**:
- `pages/SPNDashboard.tsx` (871 lines) -- full SPN management
- `utils/spnPdfGenerator.ts` -- privilege report PDF

**API endpoints**:
- `GET /api/spns/stats`
- `GET /api/spns` -- list with blast_radius + critical_roles
- `GET /api/spns/<path:identity_id>` -- full detail

---

### Phase 72: Data Retention & Archival

**What it does**: 6 cleanup methods (discovery_runs, drift_reports, activity_log, anomalies, soar_actions, notifications), `get_storage_stats()` for table sizes, daily scheduler job at 03:00 UTC (`run_data_retention`), 7 retention setting keys.

**Backend components**:
- `database.py`: 6 cleanup methods, `get_storage_stats()`
- `scheduler.py`: daily retention job

**API endpoints**:
- `GET /api/system/storage` -- table sizes, row counts, oldest records
- `POST /api/system/cleanup` -- manual cleanup trigger

**Frontend components**: Retention settings section in Settings, "Retention Settings" link in SystemHealth

---

### Phase 73: Access Source & SAS Audit

**What it does**: RBAC access source classification (direct/resource_group/subscription/management_group), `access_source_breakdown` stats, audit posture bar (AAD Only/Auditable/Partial/Unauditable), diagnostic logging discovery via MonitorManagementClient.

**Backend components**:
- Enhanced resource access mapping with source classification
- `diagnostic_logging_enabled` + `logging_destinations` columns on `azure_storage_accounts`
- CIS 3.14 diagnostic logging compliance check

---

### Phase 74: App Registration Audit

**What it does**: Azure AD app registration discovery and audit with 36-column table, Graph API `applications.get()` with pagination, 10 high-risk permission GUIDs, credential tracking (secrets + certs + expiry flags), owner fetching, SPN cross-linking, 10-factor risk scoring.

**Backend components**:
- `azure_discovery.py`: app registration discovery, `HIGH_RISK_PERMISSION_GUIDS` (10 dangerous MS Graph perms)
- 10-factor risk scoring: ownerless +40, multi-tenant+app-perms +30, expired creds +25, etc.

**Frontend components**:
- `pages/AppRegistrations.tsx` (778 lines) -- 5 stat cards, 4 filters, 8-column table, 480px drill-down panel

**API endpoints**:
- `GET /api/app-registrations/stats`
- `GET /api/app-registrations` -- list with filters + sort + pagination
- `GET /api/app-registrations/<app_id>` -- full detail

**DB tables**: `app_registrations` (36 columns, UNIQUE on run_id + app_id)

---

### Phase 75: Tenant Cloud Config & Dynamic Sidebar

**What it does**: Dynamic sidebar showing only enabled cloud providers, pricing model v3.0 (Azure $199/$799/$1499, AWS $249/$849/$1549, GCP $229/$829/$1529), "Add Cloud Provider" modal, plan badge display.

**Backend components**:
- `database.py`: `get_tenant_config()`
- `handlers.py`: tenant config route

**Frontend components**:
- `components/layout/Sidebar.tsx` (395 lines) -- dynamic cloud sub-groups
- `constants/pricing.ts` -- v3.0 pricing model, `calculateMonthlyTotal()`, `calculateCloudBaseTotal()`, `calculateAddonTotal()`, `ACCOUNT_TIERS`, `ACCOUNT_TIER_LABELS`

**API endpoints**:
- `GET /api/tenant/config`

---

### Phase 76: Admin Portal RBAC

**What it does**: 4 portal roles (superadmin/poweradmin/billing/reader) with `VALID_PORTAL_ROLES` constant, `require_portal_role(*roles)` decorator, granular route decorators per endpoint.

**Backend components**:
- `api/auth.py`: `VALID_PORTAL_ROLES`, `require_portal_role()`, `require_portal_access()`
- `database.py`: `support` -> `poweradmin` DB migration

---

### Phase 77: Admin Portal v3.0

**What it does**: AdminOverview reduced to 2 summary cards, license tracking (`license_activated_at`/`license_expires_at` on tenants), AdminUsers profile side panel with email/phone fields, `trial` as valid plan tier.

**DB tables**: Added columns to `tenants` and `users`

---

### Phase 79: AI Security Copilot

**What it does**: Anthropic Claude-powered security assistant with live posture context gathering, quick-ask suggestion chips, conversation history, and markdown rendering.

**Backend components**:
- `services/copilot_service.py` (205 lines) -- `CopilotService` with `gather_context()`, `get_suggestions()`, `ask()`
- Uses `copilot_api_key` setting for Anthropic API key

**Frontend components**:
- `components/CopilotPanel.tsx` (335 lines) -- slide-out panel with chat bubbles

**API endpoints**:
- `POST /api/copilot/chat`
- `GET /api/copilot/conversations`
- `GET /api/copilot/suggestions`

**DB tables**: `copilot_conversations` (JSONB messages)

**Known gaps**: CopilotPanel uses `dangerouslySetInnerHTML` for markdown rendering (XSS vector).

---

### Phase 80: Identity Timeline / Forensic View

**What it does**: Aggregates 5 event sources (anomalies, risk_scores, pim_activations, soar_actions, remediation_actions) into a unified chronological timeline. Date range and event type filters, CSV export.

**API endpoints**:
- `GET /api/identities/<id>/timeline`

**Frontend components**: Timeline tab (13th tab) in IdentityDetail

---

### Phase 81: Attack Path Analysis

**What it does**: Computes 5 escalation chain types (direct_escalation, ownership_chain, pim_abuse, lateral_movement, credential_exposure) and visualizes them as ReactFlow directed attack graphs.

**Backend components**:
- `handlers.py`: `get_identity_attack_paths()` -- computes escalation chains

**Frontend components**:
- `components/graph/AttackPathView.tsx` (187 lines) -- 3rd mode in AccessGraphTab toggle
- `attack_node` custom ReactFlow node type

**API endpoints**:
- `GET /api/identities/<id>/attack-paths`

---

### Phase 82: Executive Posture Report

**What it does**: A4 landscape 1-page PDF with posture score circle, 2x3 metric grid, and executive summary strip.

**Frontend components**:
- `utils/pdfGenerator.ts`: `generateExecutiveReport()` function
- Reports.tsx gains report type toggle (Full Audit / Executive Summary)

---

### Phase 83: Slack/Teams Notifications

**What it does**: Webhook-based notifications with Slack Block Kit and Microsoft Teams Adaptive Card formatting. 5-minute rate limiting per channel. 6 event toggles (scan_complete, scan_failed, anomaly_detected, drift_detected, etc.).

**Backend components**:
- `services/notification_dispatcher.py` (173 lines) -- `NotificationDispatcher` with `send_slack()`, `send_teams()`, `dispatch()`
- `scheduler.py`: hooks for scan_complete/scan_failed/anomaly_detected/drift_detected

**Frontend components**: Section 13 in Settings (IntegrationsSection) -- webhook URL, eye toggle, 6 event toggles, test button per platform

**API endpoints**:
- `GET /api/settings/integrations`
- `POST /api/settings/integrations`
- `POST /api/settings/integrations/test`

---

### Phase 84: Multi-Subscription Identity Model

**What it does**: Junction table mapping identities to multiple Azure subscriptions with RBAC role and scope tracking. Primary subscription computed via privilege priority (Owner > Contributor > Reader).

**Backend components**:
- `azure_discovery.py`: populates junction table from role_assignments
- `database.py`: `update_identity_subscription_summary()` computes primary subscription
- `handlers.py`: subscription filter queries junction table

**Frontend components**: "+N more" badge in Identities table, subscription filter count text

**API endpoints**:
- `GET /api/identities/<id>/subscriptions`
- `GET /api/subscriptions`
- `GET /api/subscriptions/stats`
- `POST /api/subscriptions/activate`
- `PUT /api/subscriptions/<id>/deactivate`
- `GET /api/subscriptions/distinct`

**DB tables**: `identity_subscription_access`, `cloud_subscriptions`

---

### Phase 85: Client Portal RBAC & Pricing

**What it does**: 4-role client RBAC (admin/security_admin/compliance/reader) with per-role permission booleans (canActivateSubscriptions, canSeePricing, canManageConnections, canManageUsers). Cloud-first sidebar hierarchy (Azure/AWS/GCP expandable nodes with brand colors). Subscription management, credential masking, HIPAA compliance gap warning.

**Frontend components**:
- `pages/Subscriptions.tsx` (197 lines)
- `utils/maskCredential.ts`
- `components/UpgradeGate.tsx` (28 lines)
- Enhanced `contexts/AuthContext.tsx` with permission booleans
- Cloud-first sidebar with recursive rendering and brand colors

**API endpoints**:
- Uses existing subscription and tenant config endpoints

---

## Backend Services Inventory

| Service | File | Lines | Purpose | Key Methods |
|---------|------|-------|---------|-------------|
| EmailService | `services/email_service.py` | 795 | Email via Microsoft Graph API + SendGrid fallback | `send_identity_change_report()`, `send_test_email()`, `send_scheduled_report()` |
| NotificationDispatcher | `services/notification_dispatcher.py` | 173 | Slack Block Kit + Teams Adaptive Card webhooks | `send_slack()`, `send_teams()`, `dispatch()` |
| NotificationService | `services/notification_service.py` | 197 | In-app notification creation and management | `create_notification()`, `get_notifications()` |
| CopilotService | `services/copilot_service.py` | 205 | AI security assistant (Anthropic Claude) | `gather_context()`, `get_suggestions()`, `ask()` |
| WebhookService | `services/webhook_service.py` | 148 | Outbound webhook delivery (7 event types) | `dispatch()`, `deliver()` |
| SendGridService | `services/sendgrid_service.py` | 78 | SendGrid email fallback | `send_email()` |
| AnomalyDetector | `engines/anomaly_detector.py` | 423 | 6 anomaly detection types | `analyze()`, 6 `_detect_*` methods |
| SoarEngine | `engines/soar_engine.py` | 357 | SOAR automation engine | `evaluate_triggers()`, 4 `_action_*` methods |
| DriftDetector | `engines/drift_detector.py` | 439 | Run-to-run drift comparison | `compare_runs()` |
| RiskRuleEngine | `engines/risk_rules.py` | 176 | Custom risk rule evaluation | `evaluate()` |
| RoleMiningEngine | `engines/role_mining.py` | 1,198 | Role optimization analysis | `analyze()` |
| RiskCatalog | `engines/risk_catalog.py` | 276 | Risk category definitions and compliance | `evaluate()` |
| MetricsCollector | `metrics.py` | -- | In-memory request metrics (thread-safe) | `record_request()`, `prometheus_format()` |
| AzureDiscoveryEngine | `engines/discovery/azure_discovery.py` | 2,947 | Azure cloud discovery (12+ steps) | `discover()`, `test_connection()` |
| AWSDiscoveryEngine | `engines/discovery/aws_discovery.py` | 114 | AWS discovery stub | `discover()`, `test_connection()` (stub) |
| GCPDiscoveryEngine | `engines/discovery/gcp_discovery.py` | 112 | GCP discovery stub | `discover()`, `test_connection()` (stub) |
| ActivityTracker | `engines/discovery/activity_tracker.py` | 169 | Identity activity tracking | `track()` |
| CredentialChecker | `engines/discovery/credential_checker.py` | 165 | Credential expiry and risk checks | `check()` |

---

## Azure Discovery Engine Detail

The `AzureDiscoveryEngine` (2,947 lines) performs 13 discovery steps:

| Step | Azure SDK / API | What it discovers |
|------|----------------|-------------------|
| 1 | ARM `SubscriptionClient` | Subscription inventory |
| 2 | ARM `AuthorizationManagementClient` | RBAC role assignments per subscription |
| 3 | Graph `roleManagement` | Entra directory role assignments |
| 4 | Graph `servicePrincipals` | Service principal inventory (with Microsoft filtering) |
| 5 | Graph (per SP) | Credential discovery (secrets, certificates, federated) |
| 6 | Graph `appRoleAssignments` | API permission discovery (Application vs Delegated) |
| 7 | Graph (per SP) | App role assignments |
| 8 | Graph `/servicePrincipals/{id}/owners` | Service principal ownership |
| 9 | Graph `roleManagement/directory/roleEligibilityScheduleInstances` | PIM eligible assignments + activations |
| 10 | Graph `identity/conditionalAccess/policies` | Conditional Access policies |
| 11 | ARM `StorageManagementClient` + `MonitorManagementClient` | Storage accounts + diagnostic logging |
| 12 | ARM `KeyVaultManagementClient` + data plane clients | Key vaults + secrets/keys/certs expiry |
| 13 | Graph `applications` | App registrations (with pagination) |

**Risk scoring**: V2 structured scoring with 7 categories, 0-900+ point scale, severity multipliers per category.

**Required Graph API permissions**: `RoleManagement.Read.Directory` (PIM), `Policy.Read.All` (CA), `AuditLog.Read.All` (activity), `Application.Read.All`, `Directory.Read.All`

---

## Frontend Architecture Summary

### Pages (38 files, ~25,687 LOC)

| Page | File | Lines | Description |
|------|------|-------|-------------|
| Overview | `Overview.tsx` | 515 | Landing page with attack surface score |
| Dashboard | `Dashboard.tsx` | 580 | 6-tab operational dashboard |
| Identities | `Identities.tsx` | 1,571 | 14-column sortable table |
| Identity Detail | `IdentityDetail.tsx` | 2,883 | 13-tab deep dive |
| Settings | `Settings.tsx` | 4,327 | 13+ configuration sections |
| Access Reviews | `AccessReviews.tsx` | 1,301 | Campaign-based access reviews |
| Resources | `Resources.tsx` | 461 | Azure resource inventory |
| Resource Detail | `ResourceDetail.tsx` | 1,089 | 5-tab resource deep dive |
| SA Governance | `ServiceAccountGovernance.tsx` | 1,014 | NHI governance workflow |
| Compliance | `Compliance.tsx` | 900 | 6-framework compliance view |
| SPN Dashboard | `SPNDashboard.tsx` | 871 | SPN management |
| App Registrations | `AppRegistrations.tsx` | 778 | App registration audit |
| Role Mining | `RoleMining.tsx` | 790 | Role optimization |
| Drift History | `DriftHistory.tsx` | 618 | Drift timeline |
| Identity Comparison | `IdentityComparison.tsx` | 603 | Side-by-side comparison |
| Identity Groups | `IdentityGroups.tsx` | 600 | Group management |
| Login | `Login.tsx` | 433 | Authentication |
| Onboarding | `OnboardingWizard.tsx` | 405 | Setup wizard |
| Notification Center | `NotificationCenter.tsx` | 401 | Notification inbox |
| Cross-Tenant | `CrossTenantAnalytics.tsx` | 398 | Multi-tenant analytics |
| System Health | `SystemHealth.tsx` | 353 | Platform monitoring |
| Reports | `Reports.tsx` | 267 | PDF report generation |
| Activity Log | `ActivityLog.tsx` | 257 | Audit trail |
| Admin Console | `AdminConsole.tsx` | 251 | Admin portal shell |
| Exports | `Exports.tsx` | 204 | Data exports |
| Subscriptions | `Subscriptions.tsx` | 197 | Subscription management |
| Admin Tenants | `admin/AdminTenants.tsx` | 882 | Tenant management |
| Admin Users | `admin/AdminUsers.tsx` | 580 | Portal user management |
| Admin Onboarding | `admin/AdminOnboarding.tsx` | 442 | Admin setup wizard |
| Admin Monitoring | `admin/AdminMonitoring.tsx` | 381 | Platform monitoring |
| Admin Billing | `admin/AdminBilling.tsx` | 360 | Revenue analytics |
| Admin Overview | `admin/AdminOverview.tsx` | 319 | Admin dashboard |
| Admin Profile | `admin/AdminProfile.tsx` | 232 | User profile |
| SSO Callback | `SsoCallback.tsx` | 49 | SAML callback handler |
| Forgot Password | `ForgotPassword.tsx` | 117 | Password reset request |
| Reset Password | `ResetPassword.tsx` | 197 | Password reset form |
| Locked Dashboard | `LockedDashboard.tsx` | 49 | Access-gated view |

### Key Frontend Utilities

| File | Lines | Purpose |
|------|-------|---------|
| `utils/pdfGenerator.ts` | -- | Full audit + executive PDF generation (jsPDF + autoTable) |
| `utils/spnPdfGenerator.ts` | -- | SPN privilege report PDF |
| `utils/exportUtils.ts` | -- | CSV/JSON export helpers |
| `utils/maskCredential.ts` | -- | Credential value masking |
| `utils/complianceMapping.ts` | -- | Compliance framework mappings |
| `constants/metrics.ts` | -- | Types, labels, colors, thresholds (single source of truth) |
| `constants/pricing.ts` | -- | v3.0 pricing model, tier definitions |
| `constants/design.ts` | -- | Design system constants |
| `services/api.ts` | -- | API client configuration |
| `hooks/useDashboardPreferences.ts` | -- | Dashboard customization hook |
| `hooks/useTheme.ts` | -- | Dark/light theme management |

---

## Scheduler Jobs

| Job | Schedule | Purpose |
|-----|----------|---------|
| Discovery scan | Configurable interval (default 6h) | Run Azure/AWS/GCP discovery |
| Anomaly detection | After each discovery scan | Detect 6 anomaly types |
| Drift detection | After each discovery scan | Compare current vs previous run |
| SOAR evaluation | After anomaly + drift | Evaluate SOAR playbook triggers |
| Scheduled reports | Weekly/monthly (configurable) | Email report delivery |
| Data retention | Daily at 03:00 UTC | Cleanup old data per retention policies |

---

## Identity Categories

| Category | Description |
|----------|-------------|
| `service_principal` | Azure AD service principal (app identity) |
| `managed_identity_system` | System-assigned managed identity |
| `managed_identity_user` | User-assigned managed identity |
| `human_user` | Human user account |
| `guest` | Guest/external user |
| `microsoft_internal` | Microsoft first-party service principal |

---

## Activity Statuses

| Status | Description |
|--------|-------------|
| `active` | Recently active identity |
| `inactive` | No recent activity (configurable threshold) |
| `stale` | Inactive beyond stale threshold |
| `never_used` | No activity ever recorded |
| `recently_created` | Created within last 7 days |
| `unknown` | Activity data unavailable |

---

## Top Design Gaps

| # | Gap | Severity | Impact |
|---|-----|----------|--------|
| 1 | **No connection pooling** -- each `Database()` = fresh psycopg2 connection | High | Connection exhaustion under load |
| 2 | **handlers.py is 12,940 lines** -- should be split into route-group modules | High | Maintainability, merge conflicts |
| 3 | **database.py is 7,725 lines** -- should be split by domain | High | Maintainability |
| 4 | **No migration framework** -- `_ensure_*` methods + loose SQL files | High | Schema drift between environments |
| 5 | **AWS/GCP not implemented** -- stubs only | Medium | Feature gap for multi-cloud customers |
| 6 | **Settings.tsx is 4,327 lines** -- should be split into section components | Medium | Frontend maintainability |
| 7 | **No API rate limiting** -- beyond Slack/Teams 5-min throttle | Medium | Abuse vector |
| 8 | **Metrics not shared across workers** -- each gunicorn worker has own MetricsCollector | Medium | Inaccurate metrics in production |
| 9 | **SOAR credentials in plaintext** -- ServiceNow/Jira creds in JSONB `action_config` | High | Security risk |
| 10 | **No webhook URL validation** -- SSRF risk in SOAR webhook dispatch | High | Security risk |
| 11 | **Email HTML has XSS risk** -- identity display names not escaped | Medium | Security risk |
| 12 | **Copilot uses dangerouslySetInnerHTML** -- XSS vector in frontend | Medium | Security risk |
| 13 | **Authenticated SPN not visible** -- tenant's own discovery SPN may not appear | Low | Audit gap |
| 14 | **No container non-root user** -- both Dockerfiles run as root | Medium | Security best practice violation |
| 15 | **No Flask error handlers registered** -- no 404, 500, etc. handlers | Low | Poor error UX |
| 16 | **11 parallel API calls on Dashboard mount** -- no server-side aggregation endpoint | Medium | Performance under load |
| 17 | **IdentityDetail.tsx is 2,883 lines** -- 13 tabs in single file | Medium | Frontend maintainability |
| 18 | **No cursor-based pagination** -- offset pagination slows at scale | Low | Performance at scale |
| 19 | **No server-side caching** -- Redis or similar for expensive queries | Medium | Performance under load |
| 20 | **No test suite** -- no unit or integration tests | High | Regression risk |

---

## File Size Summary (Backend)

| File | Lines | Role |
|------|-------|------|
| `api/handlers.py` | 12,940 | All API handler functions |
| `database.py` | 7,725 | Database access layer + schema |
| `engines/discovery/azure_discovery.py` | 2,947 | Azure cloud discovery |
| `main.py` | 1,295 | Flask app factory + route registration |
| `engines/role_mining.py` | 1,198 | Role mining analysis |
| `scheduler.py` | 952 | APScheduler job definitions |
| `services/email_service.py` | 795 | Email service (Graph API) |
| `engines/drift_detector.py` | 439 | Drift detection |
| `engines/discovery/models.py` | 430 | Data models |
| `engines/anomaly_detector.py` | 423 | Anomaly detection |
| `engines/soar_engine.py` | 357 | SOAR automation |
| `engines/risk_catalog.py` | 276 | Risk categories |
| `api/auth.py` | 256 | Authentication + RBAC |
| **Total backend** | **~35,000+** | |

---

## Deployment Architecture

```
                    Internet
                       |
              Azure Container Apps
              (auditgraph-env, eastus)
              Static IP: 13.92.66.67
                    /        \
    auditgraph-web            auditgraph-api
    (nginx:alpine)            (python:3.11-slim)
    app.auditgraph.ai         api.auditgraph.ai
    admin.auditgraph.ai       gunicorn (2 workers, --preload)
         |                          |
    React SPA                 Flask + psycopg2
    (static files)                  |
                          PostgreSQL (Flex Server)
                     auditgraph-db-dev.postgres.database.azure.com
                          (DB_SSLMODE=require)
```

**CI/CD**: `.github/workflows/deploy.yml` builds on ACR (`auditgraphcr.azurecr.io`, linux/amd64) and deploys to Container Apps on push to `main`.

---

*Document generated from codebase analysis on 2026-02-16.*
