# AuditGraph Architecture Reference

**Generated:** 2026-04-08
**Branch:** dev
**Scope:** Complete codebase audit — read-only, no code changes

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Database Schema](#2-database-schema)
3. [Backend Architecture](#3-backend-architecture)
4. [The CISO Summary Endpoint (SSOT)](#4-the-ciso-summary-endpoint-ssot)
5. [Frontend Architecture](#5-frontend-architecture)
6. [Executive Posture Dashboard (SSOT Contract)](#6-executive-posture-dashboard-ssot-contract)
7. [Data Flow Diagrams](#7-data-flow-diagrams)
8. [Known Issues & Fix History](#8-known-issues--fix-history)
9. [Phase Boundaries](#9-phase-boundaries)
10. [SSOT Rules](#10-ssot-rules)

---

## 1. Project Overview

### Repo Structure

```
auditgraph/
├── backend/           Flask API (Python 3.11)
│   ├── app/           Application code (main.py, database.py, handlers.py)
│   │   ├── api/       10 handler modules (handlers.py is 33,792 lines)
│   │   ├── engines/   86 analysis/discovery/risk engine files
│   │   ├── services/  9 external integration services
│   │   ├── ai/        3 AI copilot files
│   │   ├── billing/   3 billing engine files
│   │   ├── middleware/ 3 middleware files
│   │   └── constants/ 5 constant files
│   ├── migrations/    81 SQL migrations + 1 comprehensive schema (100_full_schema.sql)
│   ├── tests/         52 test files
│   └── scripts/       12 utility scripts
├── frontend/          React SPA (TypeScript)
│   └── src/
│       ├── pages/     72 page components
│       ├── components/ 132 shared components
│       ├── contexts/  7 React context providers
│       ├── constants/ 11 constant files
│       ├── hooks/     5 custom hooks
│       ├── services/  2 API service files
│       └── utils/     12 utility files
├── deploy/            Nginx configs (app + admin portal)
├── infra/             Infrastructure as Code
└── docs/              Documentation
```

### Tech Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| **Backend** | Flask (Python 3.11) | 33,792-line handlers.py, 27,518-line database.py |
| **Database** | PostgreSQL 16 | 96 tables, RLS on 44, dual-user isolation |
| **Frontend** | React 19 + TypeScript | 208 TSX + 42 TS files, CRA build |
| **Styling** | Tailwind CSS 3.4 | Dark theme, custom design tokens |
| **Graphs** | @xyflow/react 12 | Identity access graphs, attack paths |
| **Charts** | Recharts 3.7 | Dashboard visualizations |
| **PDF Export** | jsPDF 4.1 + autotable | Full audit + executive reports |
| **Auth** | PyJWT + bcrypt | Dual JWT secrets (admin/client), SAML/SSO |
| **Azure SDK** | azure-identity, azure-mgmt-* | Primary cloud provider |
| **Scheduling** | APScheduler | Discovery, drift, anomaly, retention jobs |
| **AI** | Anthropic Claude API | Security copilot |
| **Deployment** | Azure Container Apps | ACR → gunicorn + nginx:alpine |

### Environment Configuration

| Tier | Backend Port | Frontend Port | Database |
|------|-------------|---------------|----------|
| Local (bare metal) | 5001 | 3000 (CRA dev server) | localhost:5434 |
| Docker Compose | 5000 | 3000 (nginx proxy) | auditgraph-postgres:5432 |
| Production | 8000 (gunicorn) | 3000 (nginx static) | Azure Flex Server |

**Key URLs:**
- Production: `api.auditgraph.ai` / `app.auditgraph.ai` / `admin.auditgraph.ai`
- Dev: `dev.api.auditgraph.ai` / `dev.app.auditgraph.ai` / `dev.admin.auditgraph.ai`
- Demo: `demo.auditgraph.ai`

---

## 2. Database Schema

### 2.1 Table Inventory (96 tables)

**RLS-Protected Tables (44)** — all have `tenant_id NOT NULL`, STRICT policies:

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `identities` | Master identity table | 82 cols, risk_score, activity_status, blast_radius |
| `role_assignments` | Azure RBAC roles | scope, role_name, risk_level |
| `entra_role_assignments` | Entra directory roles | role_name, is_pim_activated |
| `credentials` | Identity credentials | credential_type, expiry, risk_level |
| `graph_api_permissions` | MS Graph permissions | permission_type (Application/Delegated) |
| `pim_eligible_assignments` | PIM eligible roles | role_name, assignment_type |
| `pim_activations` | PIM activation history | activated_at, duration |
| `identity_subscription_access` | Multi-sub access mapping | subscription_id, rbac_role, scope_type |
| `ca_policies` | Conditional Access policies | conditions (JSONB), grant_controls (JSONB) |
| `ca_identity_coverage` | CA coverage per identity | policy_id, is_covered |
| `discovery_runs` | Discovery run metadata | status, started_at, completed_at |
| `drift_reports` | Drift between runs | changes (JSONB), 5 change types |
| `anomalies` | Detected anomalies | type (6 types), severity, resolved |
| `app_registrations` | Azure AD apps | 55 cols, permissions, credential tracking |
| `azure_storage_accounts` | Storage security audit | 48 cols, SAS audit, CIS compliance |
| `azure_key_vaults` | Key vault audit | 48 cols, item-level expiry, compliance |
| `cloud_subscriptions` | Subscription inventory | account_id, status, resource_count |
| `activity_log` | Audit trail | append-only, integrity_hash |
| `users` | Tenant users | role, auth_provider, portal_role |
| `settings` | Key-value config | per-org settings |
| `soar_playbooks` | Automation playbooks | conditions (JSONB), actions (JSONB) |
| `soar_actions` | Automation action log | status, execution_log |
| `remediation_actions` | Remediation tracking | execution_status, executed_at |
| `notifications` | In-app notifications | severity, category, action_items |
| `api_keys` | API key management | key_hash (SHA-256), role, usage |
| `saved_views` | Saved filter views | filters (JSONB), is_default |
| `webhooks` | Webhook configs | url, events, secret |
| `webhook_deliveries` | Webhook delivery log | status_code, response_body |
| `copilot_conversations` | AI chat history | messages (JSONB) |
| `access_review_campaigns` | Access review campaigns | status, scope |
| `campaign_reviews` | Individual review items | decision, reviewer_id |
| `identity_groups` | Identity grouping | group_type, criteria |
| `identity_group_members` | Group membership | identity_id, group_id |
| `sa_attestations` | SA governance attestations | attested_by, expires_at |
| `custom_risk_rules` | Custom risk scoring | conditions (JSONB), score_adjustment |
| `dashboard_preferences` | Widget layout prefs | layout (JSONB) |
| `sso_auth_codes` | One-time SSO codes | code, expires_at (60s TTL) |
| `sp_app_roles` | App role assignments | role_id, role_value |
| `sp_ownership` | SPN ownership | owner_id, owner_type |
| `governance_decisions` | Governance audit log | decision, rationale |
| `role_activity_log` | Role change audit | action, old_role, new_role |
| `campaign_audit_log` | Review campaign audit | action, details |
| `compliance_snapshots` | Point-in-time compliance | score, framework |

**Non-RLS Tables (52)** — system-wide or reference data:

| Table | Purpose |
|-------|---------|
| `organizations` | Org/tenant master (43 cols) — plan, billing, Stripe |
| `cloud_connections` | Cloud provider credentials (org-level) |
| `remediation_playbooks` | Playbook templates (shared) |
| `risk_summary` | Computed risk summaries |
| `schema_migrations` | Migration tracking |
| `platform_settings` | Global platform config |
| `plans` | Subscription plan definitions |
| `compliance_frameworks` | Framework definitions |
| `compliance_controls` | Control definitions |
| `invoices` / `invoice_documents` | Billing records |
| `billing_events` / `billing_audit_log` | Billing audit trail |
| `admin_audit_log` | Admin portal audit trail |
| `workload_signin_events` | P2 sign-in telemetry |
| `workload_activity_stats` | P2 activity aggregation |
| `workload_anomaly_events` | P2 behavioral anomalies |
| `blast_radius_results` | Pre-computed blast radius |
| `fix_recommendations` | Auto-generated fix suggestions |
| `attack_paths` | Pre-computed escalation chains |
| `security_findings` | Aggregated security findings |
| `identity_graph_edges` | Graph edge data |
| `identity_security_posture` | Derived posture scores |
| `refresh_tokens` | JWT refresh tokens |

### 2.2 RLS Security Model

```
┌─────────────────────────────────────────────────────────┐
│  PostgreSQL Row-Level Security (Phase 87)                │
│                                                          │
│  auditgraph_app (NOBYPASSRLS)                           │
│    ├── SET app.current_tenant_id = N                    │
│    ├── All 44 tables: FORCE ROW LEVEL SECURITY          │
│    └── Policy: tenant_id = current_setting(             │
│              'app.current_tenant_id', true)::integer     │
│                                                          │
│  auditgraph_admin (BYPASSRLS)                           │
│    ├── Used for DDL, migrations, system queries          │
│    └── No RLS filtering applied                         │
│                                                          │
│  Auto-fill Trigger (trg_auto_tenant_id):                │
│    ├── On INSERT: fills tenant_id from session context   │
│    └── RAISES exception if both NULL                    │
└─────────────────────────────────────────────────────────┘
```

### 2.3 Primary Foreign Key Chains

```
discovery_runs.id ──┬── identities.discovery_run_id
                    ├── app_registrations.run_id
                    ├── azure_storage_accounts.discovery_run_id
                    ├── azure_key_vaults.discovery_run_id
                    ├── ca_policies.discovery_run_id
                    ├── drift_reports.discovery_run_id
                    ├── anomalies.run_id
                    └── compliance_snapshots.discovery_run_id

identities.id ──────┬── role_assignments.identity_db_id
                    ├── entra_role_assignments.identity_db_id
                    ├── credentials.identity_db_id
                    ├── graph_api_permissions.identity_db_id
                    ├── pim_eligible_assignments.identity_db_id
                    ├── pim_activations.identity_db_id
                    ├── identity_subscription_access.identity_db_id
                    ├── ca_identity_coverage.identity_db_id
                    └── sp_ownership.identity_db_id (15+ child tables)

cloud_connections.id ── cloud_subscriptions.cloud_connection_id

soar_playbooks.id ───── soar_actions.playbook_id

access_review_campaigns.id ──┬── campaign_reviews.campaign_id
                             └── campaign_audit_log.campaign_id
```

**Note:** `identities` has NO `tenant_id` column — tenant scoping is via `discovery_run_id` → `discovery_runs.tenant_id`.

### 2.4 JSONB Document Patterns

| Column | Table | Contents |
|--------|-------|----------|
| `risk_factors` | identities | Risk scoring breakdown |
| `risk_reasons` | identities | Human-readable risk explanations |
| `exposure_components` | identities | Blast radius composition |
| `credential_details` | credentials | Credential metadata |
| `conditions` | ca_policies, soar_playbooks, custom_risk_rules | Rule conditions |
| `grant_controls` | ca_policies | CA enforcement controls |
| `actions` | soar_playbooks | Automation action definitions |
| `changes` | drift_reports | 5-type change diffs |
| `metadata` | activity_log | Audit event details |
| `messages` | copilot_conversations | Chat message history |
| `secret_expiry_items` | azure_key_vaults | Item-level expiry tracking |

---

## 3. Backend Architecture

### 3.1 Entry Point & App Factory

**File:** `backend/app/main.py` (3,981 lines)

```
create_app()
  ├── _validate_startup_secrets()     — Require JWT, DB creds in non-dev
  ├── _run_core_schema()              — Migration 001 (identity_roles)
  ├── _run_full_schema()              — Migration 100 (all tables)
  ├── _run_derived_tables()           — Migrations 070-071 (graph_edges, posture)
  ├── _run_schema_sync()              — Sync columns with baseline
  ├── Configure CORS                  — ALLOWED_ORIGINS env var
  ├── Register auth_middleware        — @app.before_request
  ├── Register rate limiter           — Per-endpoint limits
  ├── Register 534 routes             — Inline in create_app()
  └── Start APScheduler               — Discovery, drift, anomaly, retention jobs
```

### 3.2 Complete API Route Map (534 routes)

| Method | Count | Examples |
|--------|-------|---------|
| **GET** | 320 | `/api/ciso/summary`, `/api/identities`, `/api/stats` |
| **POST** | 147 | `/api/auth/login`, `/api/discovery/run`, `/api/copilot/chat` |
| **PUT** | 34 | `/api/users/<id>`, `/api/admin/tenants/<id>/plan` |
| **DELETE** | 22 | `/api/api-keys/<id>`, `/api/tenants/<id>` |
| **PATCH** | 11 | `/api/anomalies/<id>`, `/api/remediation-queue/<id>` |

**Route Categories:**

| Category | Prefix | Routes | Handler Module |
|----------|--------|--------|---------------|
| Health/System | `/api/health`, `/api/system`, `/api/metrics` | 12 | main.py |
| Auth | `/api/auth/*` | 18 | auth.py |
| CISO Dashboard | `/api/ciso/summary` | 1 | handlers.py |
| Identities | `/api/identities/*` | 25 | handlers.py |
| Dashboard | `/api/dashboard/*` | 12 | handlers.py |
| Risk/Exposure | `/api/risk/*`, `/api/exposure/*` | 8 | handlers.py |
| Anomalies | `/api/anomalies/*` | 4 | handlers.py |
| Drift | `/api/drift/*` | 3 | handlers.py |
| Remediation | `/api/remediation*` | 12 | handlers.py |
| SOAR | `/api/soar/*` | 7 | handlers.py |
| Resources | `/api/resources/*` | 5 | handlers.py |
| SPNs | `/api/spns/*` | 4 | handlers.py |
| App Registrations | `/api/app-registrations/*` | 3 | handlers.py |
| Reports | `/api/reports/*` | 8 | handlers.py |
| Settings | `/api/settings/*` | 10 | handlers.py |
| Users | `/api/users/*` | 5 | handlers.py |
| Notifications | `/api/notifications/*` | 4 | handlers.py |
| Activity | `/api/activity` | 1 | handlers.py |
| Discovery | `/api/discovery/*`, `/api/runs/*` | 8 | handlers.py |
| Compliance | `/api/compliance/*` | 5 | handlers.py |
| Billing | `/api/billing/*`, `/api/client/billing/*` | 10 | handlers.py |
| Admin | `/api/admin/*` | 40+ | handlers.py |
| Security | `/api/security/*` | 35+ | handlers.py |
| AI/Copilot | `/api/copilot/*`, `/api/ai/*` | 10 | handlers.py |
| Graph | `/api/graph/*` | 10 | handlers.py |
| Workload Identities | `/api/workload-identities/*` | 6 | handlers.py |
| Attack Paths | `/api/attack-paths/*` | 5 | handlers.py |
| Blast Radius | `/api/blast-radius/*` | 3 | handlers.py |
| Access Reviews | `/api/access-reviews/*` | 5 | handlers.py |
| SCIM | `/api/scim/v2/*` | 6 | handlers.py |
| Webhooks | `/api/webhooks/*` | 4 | handlers.py |
| Subscriptions | `/api/subscriptions/*` | 6 | handlers.py |

### 3.3 Authentication Flow

```
Request
  │
  ▼
auth_middleware (@app.before_request)
  ├── Skip public paths (/api/auth/login, /api/health, etc.)
  ├── Extract token from:
  │   ├── Cookie: ag_client_access / ag_admin_access
  │   ├── Header: Authorization: Bearer <jwt>
  │   └── Header: X-API-Key: ag_<hex> (or Bearer ag_<hex>)
  ├── Decode JWT with:
  │   ├── ADMIN_JWT_SECRET (admin portal)
  │   └── CLIENT_JWT_SECRET (client portal)
  ├── Derive portal from Host header
  ├── Derive org_slug from subdomain
  ├── Validate issuer/audience match
  ├── Set g.current_user, g.current_org
  └── Database(tenant_id=org_id) for RLS scoping
```

**Roles:**
- **Client portal:** admin, security_admin, compliance, reader
- **Admin portal:** superadmin, poweradmin, billing, reader

### 3.4 Database Class

**File:** `backend/app/database.py` (27,518 lines)

```python
# Tenant-scoped operations (RLS enforced)
db = Database(tenant_id=5)   # → auditgraph_app + SET app.current_tenant_id=5

# Admin operations (RLS bypassed)
db = Database()              # → auditgraph_admin (BYPASSRLS)
```

Key methods: `execute()`, `fetchone()`, `fetchall()`, `get_latest_risk_summaries()`, `get_identities()`, `get_identity()`, `log_activity()`, plus 100+ `_ensure_*_table()` DDL methods.

### 3.5 Engine Layer (86 files)

**Discovery Engines:**

| Engine | File | Purpose |
|--------|------|---------|
| AzureDiscoveryEngine | `engines/discovery/azure_discovery.py` | Full Azure identity/resource discovery |
| AWSDiscoveryEngine | `engines/discovery/aws_discovery.py` | AWS IAM discovery (stub) |
| GCPDiscoveryEngine | `engines/discovery/gcp_discovery.py` | GCP IAM discovery (stub) |
| ActivityTracker | `engines/discovery/activity_tracker.py` | Sign-in activity tracking |
| CredentialChecker | `engines/discovery/credential_checker.py` | Credential expiry/risk |
| AgentPatternLoader | `engines/discovery/agent_pattern_loader.py` | AI agent classification |

**Risk & Scoring Engines:**

| Engine | File | Purpose |
|--------|------|---------|
| RiskSummaryEngine | `engines/risk/risk_summary_engine.py` | 5-phase risk computation |
| AGIRSEngine | `engines/risk/agirs_engine.py` | 4-index AGIRS score (Access, Governance, Identity, Risk) |
| SPNRiskEngine | `engines/risk/spn_risk_engine.py` | SPN-specific risk scoring |
| RiskEvaluator | `engines/risk_evaluator.py` | Per-identity risk evaluation |
| RiskForecaster | `engines/risk_forecaster.py` | Risk trend prediction |

**Analysis Engines:**

| Engine | File | Purpose |
|--------|------|---------|
| AttackPathEngine | `engines/attack_path_engine.py` | 5-type escalation chain computation |
| BlastRadiusEngine | `engines/blast_radius_engine.py` | Blast radius calculation |
| AnomalyDetector | `engines/anomaly_detector.py` | 6-type anomaly detection |
| DriftDetector | `engines/drift_detector.py` | Change detection between runs |
| SecurityFindingsEngine | `engines/security_findings_engine.py` | Aggregated findings |
| IdentityExposureEngine | `engines/identity_exposure_engine.py` | Exposure assessment |
| FixRecommendationEngine | `engines/fix_recommendation_engine.py` | Auto-generated fixes |
| SoarEngine | `engines/soar_engine.py` | SOAR automation |
| RemediationEngine | `engines/remediation_engine.py` | Remediation matching |
| PolicyGenerator | `engines/policy_generator.py` | Least-privilege policy generation |
| RbacHygieneEngine | `engines/rbac_hygiene.py` | RBAC cleanup analysis |

**Telemetry:**

| Engine | File | Purpose |
|--------|------|---------|
| P2Ingestion | `engines/telemetry/p2_ingestion.py` | Entra P2 sign-in log ingestion |
| BehavioralEngine | `engines/telemetry/behavioral_engine.py` | 8-type behavioral anomaly detection |

### 3.6 Service Layer (9 files)

| Service | File | Purpose |
|---------|------|---------|
| EmailService | `services/email_service.py` | SMTP email delivery |
| SlackService | `services/slack_service.py` | Slack Block Kit notifications |
| TeamsService | `services/teams_service.py` | Teams Adaptive Card notifications |
| SAML Helper | `services/saml.py` | SAML/SSO flow |
| NotificationDispatcher | `engines/integration_dispatcher.py` | Multi-channel dispatch with rate limiting |

### 3.7 Scheduler Jobs

| Job | Schedule | What It Does |
|-----|----------|-------------|
| `run_discovery` | Every N hours (configurable) | Full discovery pipeline per tenant |
| `run_drift_detection` | After discovery | Diff against previous run |
| `run_anomaly_detection` | After drift | 6-type anomaly scan |
| `run_data_retention` | Daily 03:00 UTC | Cleanup old runs/logs/reports |
| `run_scheduled_reports` | Weekly/monthly | Email report delivery |

---

## 4. The CISO Summary Endpoint (SSOT)

### 4.1 Route

```
GET /api/ciso/summary
  ├── Auth: Required (any authenticated role)
  ├── Query params: connection_id (optional)
  ├── Response: JSON envelope with status/coverage/confidence
  └── Cache: 30-second TTL per org+connection
```

### 4.2 Handler Architecture

```python
get_ciso_summary()                    # Outer handler (triple-nested error catching)
  └── _ciso_summary_inner()           # Inner handler (6-phase pipeline)
        │
        ├── Phase 1: Isolation context
        │   ├── org_id from g.current_user (mandatory, positive int)
        │   ├── conn_id from query param or default
        │   └── run_ids from _scoped_run_ids(conn_id)
        │
        ├── Phase 2: Cache check (30s TTL)
        │
        ├── Phase 3: Collection (6 sources, each wrapped in try/except)
        │   ├── _collect_risk_summary(db, run_ids, org_id)  → 5 SQL queries
        │   ├── _collect_trends(db, run_ids)                → last 10 runs
        │   ├── _collect_anomalies(db, org_id)              → stats + top 5
        │   ├── _collect_remediation(db, org_id)            → action counts
        │   ├── _collect_drift(db, run_ids)                 → latest drift
        │   └── _collect_spn_stats(db, run_ids)             → SPN breakdown
        │
        ├── Phase 4: Data building (6 builders, safe defaults)
        │   ├── _build_risk_summary_data(raw)
        │   ├── _build_trend_data(raw)
        │   ├── _build_anomaly_data(raw)
        │   ├── _build_remediation_data(raw)
        │   ├── _build_drift_data(raw)
        │   └── _build_spn_data(raw)
        │
        ├── Phase 5: Envelope construction
        │   └── _build_ciso_envelope(data, db, run_ids, org_id)
        │       ├── Status: READY | PARTIAL | DISCOVERY_REQUIRED | ERROR
        │       ├── Coverage: usableSources / totalSources × 100%
        │       ├── Confidence: high (≥85%) | medium (≥50%) | low (<50%)
        │       └── LastUpdated: risk_summary.computed_at → fallback: discovery_runs.completed_at
        │
        └── Phase 6: Validation & caching
```

### 4.3 RiskSummaryEngine.compute()

**File:** `backend/app/engines/risk/risk_summary_engine.py`

```
compute(db, run_ids, org_id)
  │
  ├── Phase 1: Identity risk counts (8 metrics)
  │   ├── total_identities
  │   ├── critical_count, high_count, medium_count, low_count
  │   ├── dormant_count, over_privileged_count
  │   └── external_exposure_count
  │
  ├── Phase 2: AGIRS computation
  │   └── AGIRSEngine.compute() → 4 index scores
  │       ├── access_index (0-100)
  │       ├── governance_index (0-100)
  │       ├── identity_index (0-100)
  │       └── risk_index (0-100)
  │       → agirs_score = weighted average
  │
  ├── Phase 3: Remaining metrics
  │   ├── attack_path_count
  │   ├── resource_count
  │   ├── total_subscriptions (from cloud_subscriptions)
  │   ├── active_subscriptions
  │   └── privileged_role_count
  │
  ├── Phase 4: Pillar deduction model
  │   ├── 7 pillars (100-point scale)
  │   ├── Grade: A (90+), B (80+), C (70+), D (60+), F (<60)
  │   └── posture_score = pillar average
  │
  └── Phase 5: Persist to risk_summary table
      └── computed_at = NOW()
```

### 4.4 Response JSON Shape

```json
{
  "status": "READY",
  "coverage": { "pct": 100, "usableSources": 6, "totalSources": 6 },
  "confidence": { "level": "high", "pct": 100 },
  "lastUpdated": "2026-04-08T12:00:00Z",
  "data": {
    "riskSummary": {
      "totalIdentities": 150,
      "riskDistribution": { "critical": 5, "high": 12, "medium": 30, "low": 103 },
      "exposure": {
        "subscriptions": 3,
        "activeSubscriptions": 3,
        "resources": 47,
        "privilegedRoles": 8
      },
      "agirs": { "score": 72, "grade": "C", "indexes": {...} },
      "postureScore": 68,
      "attackPaths": 4,
      "pillars": [...]
    },
    "trends": [...],
    "anomalies": { "stats": {...}, "top": [...] },
    "remediation": { "pending": 5, "completed": 12, "failed": 1 },
    "drift": { "totalChanges": 3, "breakdown": {...} },
    "spnExposure": { "total": 25, "custom": 18, "byRisk": {...} }
  },
  "gaps": [...],
  "recommendations": [...]
}
```

### 4.5 Subscription Count Trace

```
cloud_subscriptions table
  └── SELECT COUNT(*) WHERE discovery_run_id IN (run_ids)
      └── _collect_risk_summary() → raw['total_subscriptions']
          └── _build_risk_summary_data() → data.riskSummary.exposure.subscriptions
              └── _build_ciso_envelope() → response.data.riskSummary.exposure.subscriptions
                  └── cisoViewModel.ts → vm.monitored.subscriptions
                      └── CISODashboard.tsx → header subtitle render
```

### 4.6 LastUpdated Trace

```
RiskSummaryEngine.compute() → summary['computed_at'] = NOW()
  └── INSERT INTO risk_summary ... computed_at
      └── db.get_latest_risk_summaries() → row['computed_at']
          └── _collect_risk_summary() → raw['computed_at']
              └── _build_ciso_envelope() → response.lastUpdated
                  ├── Primary: risk_summary.computed_at
                  └── Fallback: discovery_runs.completed_at (most recent)
                      └── cisoViewModel.ts → vm.lastUpdated
                          └── CISODashboard.tsx header
```

---

## 5. Frontend Architecture

### 5.1 Entry Point & Provider Stack

```
index.tsx
  └── <App />
      └── ThemeProvider
          └── BrowserRouter
              └── OrganizationProvider
                  └── AuthProvider (global fetch interceptor)
                      └── ConnectionProvider (cloud connection context)
                          └── FeatureFlagProvider
                              └── CopilotProvider
                                  └── Routes (65+ routes)
```

### 5.2 Authentication

**File:** `frontend/src/contexts/AuthContext.tsx`

- Cookie-based auth (httpOnly refresh token server-side)
- Global `window.fetch` interceptor: auto-attaches `credentials: 'include'` + CSRF + `X-Organization-Id` header
- 401 → deduplicated token refresh → retry original request
- Impersonation state from server response

### 5.3 API Client

**File:** `frontend/src/services/apiClient.ts`

```typescript
api.get<T>(url)      // GET /api/...
api.post<T>(url, body)
api.put<T>(url, body)
api.patch<T>(url, body)
api.del<T>(url)
```

Base URL: `/api` (proxied in dev via CRA proxy, full URL in prod via `REACT_APP_API_URL`)

### 5.4 Cloud Connection Context

**File:** `frontend/src/contexts/ConnectionContext.tsx`

- `withConnection(url)` — appends `?connection_id=N` to API URLs when a connection is selected
- Fetches from `GET /api/client/connections` (filtered to `status='connected'`)
- Multi-cloud support: Azure, AWS, GCP

### 5.5 Page Component Inventory (72 pages)

**Core Pages:**

| Page | Route | SSOT Endpoint |
|------|-------|--------------|
| CISODashboard | `/` (home) | `GET /api/ciso/summary` |
| Dashboard | `/dashboard` | Multiple: `/api/stats`, `/api/dashboard/*` |
| Identities | `/identities` | `GET /api/identities` |
| IdentityDetail | `/identities/:id` | `GET /api/identities/:id` + sub-endpoints |
| WorkloadIdentities | `/workload-identities` | `GET /api/workload-identities/stats` |
| SPNDashboard | `/spns` | `GET /api/spns/stats`, `GET /api/spns` |
| AppRegistrations | `/app-registrations` | `GET /api/app-registrations/*` |
| Reports | `/reports` | `GET /api/reports/data` |
| DriftHistory | `/drift` | `GET /api/drift/history` |
| Settings | `/settings` | `GET /api/settings` |
| ActivityLog | `/activity` | `GET /api/activity` |
| SecurityCommandCenter | `/command-center` | `GET /api/security/command-center` |
| AttackPaths | `/attack-paths` | `GET /api/attack-paths` |
| AttackSimulator | `/attack-simulator` | `POST /api/attack/simulate` |
| Compliance | `/compliance` | `GET /api/compliance/*` |
| RemediationCenter | `/remediation` | `GET /api/remediation-queue` |
| AccessReviews | `/access-reviews` | `GET /api/access-reviews` |
| RoleMining | `/role-mining` | `GET /api/role-mining` |
| RbacHygiene | `/rbac-hygiene` | `GET /api/rbac-hygiene/*` |
| AIAgents | `/ai-agents` | `GET /api/agent-identities` |
| DataSecurity | `/data-security` | `GET /api/resources/*` |
| CrossTenantAnalytics | `/analytics` | `GET /api/analytics/*` |

**Admin Pages (under `/admin`):**

| Page | Route | Purpose |
|------|-------|---------|
| AdminOverview | `/admin` | Tenant/user summary cards |
| AdminTenants | `/admin/tenants` | Manage client orgs |
| AdminUsers | `/admin/users` | Manage admin users |
| AdminBilling | `/admin/billing` | MRR/ARR analytics |
| AdminMonitoring | `/admin/monitoring` | System health dashboard |
| AdminPlatformOps | `/admin/platform-ops` | Platform operations |

### 5.6 Component Tree (132 components)

```
components/
├── ciso/             (8) ExecutiveSummaryHero, BlastRadiusSection, ActiveThreats,
│                         BusinessImpact, ActivityDrift, RemediationImpact,
│                         ImmediateRisks, plus helpers
├── dashboard/        (39) PostureScore, CredentialHealth, RiskHeatMap, RiskDonutChart,
│                          ComplianceTab, RiskMonitoringTab, RiskMovementTab,
│                          IdentityContextDrawer, AGIRSBreakdownPanel, AGIRSTrendChart,
│                          BlastRadiusWidget, ExecutiveMetrics, RemediationPriorities,
│                          RiskProjectionPanel, ciso-shared.tsx (ScoreRing, DN, Sparkline)
├── graph/            (5)  AccessGraphTab, nodes.tsx (13 node types), edges.ts
├── identity-detail/  (14) OverviewTab, RolesTab, PermissionsTab, CredentialsTab,
│                          OwnershipTab, ComplianceTab, RemediationTab, TimelineTab,
│                          AttackPathsTab, PIMTab, AnomaliesTab
├── overview/         (8)  ExecutiveSummaryTab, ActionPlanTab, GlobalRiskCards
├── settings/         (12) GeneralTab, ScoringTab, IntegrationsSection, SSOSection
├── lineage/          (9)  IdentityLineageView + helpers
├── layout/           (3)  Sidebar, TopBar
├── ui/               (9)  ActionItemCard, Modal, Toast, Badge
├── shared/           (8)  Reusable presentation components
└── (root)            (22) IdentityDrawer, LineageDetailPanel, CopilotPanel, etc.
```

---

## 6. Executive Posture Dashboard (SSOT Contract)

### 6.1 Single Data Source

The CISO Executive Dashboard (`/` route) fetches from **exactly one endpoint**:

```
GET /api/ciso/summary?connection_id={selected_connection_id}
```

All dashboard tiles, charts, and metrics derive from this single response.

### 6.2 View Model Transform

**File:** `frontend/src/utils/cisoViewModel.ts`

```typescript
mapSummaryToViewModel(json: CISOSummaryResponse): CISOViewModel
```

Pure transformation — no API calls, no React hooks, no side effects.

### 6.3 CISOViewModel Interface

```typescript
interface CISOViewModel {
  // Status
  status: 'READY' | 'PARTIAL' | 'DISCOVERY_REQUIRED' | 'ERROR'
  status_label: string
  status_reason: string

  // Monitored scope
  total_identities: number
  monitored: {
    subscriptions: number
    active_count: number
  }

  // Risk exposure
  risk_exposure: {
    count: number
    pct: number
    level: string
    nav_url: string
  }

  // Top risk drivers (5 types)
  top_risk_drivers: Array<{
    type: 'dormant_privileged' | 'ghost_accounts' | 'orphaned_spns' | 'over_privileged' | 'external_exposure'
    count: number
    severity: string
  }>

  // Blast radius
  blast_radius: {
    identity: { display_name: string, risk_score: number }
    consequences: string[]
  }

  // Actions
  immediate_actions: Array<{
    title: string
    effort: string      // "15m" | "30m" | "20m"
    risk_reduction: number
    urgency: string
  }>

  // Category breakdown
  identity_categories: Record<string, { count: number, pct: number }>

  // Top 10 dangerous identities
  findings: Array<{
    identity_id: string
    display_name: string
    risk_score: number
    category: string
    prefill: object   // Instant drawer load data
  }>

  // Extended data
  trend_history: Array<{ date: string, posture_score: number }>
  anomaly_summary: { total: number, unresolved: number, by_type: object }
  remediation_progress: { pending: number, completed: number, failed: number }
  drift_summary: { total_changes: number, breakdown: object }
  spn_exposure: { total: number, custom: number, by_risk: object }

  // AGIRS
  agirs: { score: number, grade: string, indexes: object }
  posture_score: number
  lastUpdated: string
}
```

### 6.4 Component Tree & VM Field Mapping

```
CISODashboard.tsx
  │
  ├── State machine: LOADING → NOT_CONNECTED → DISCOVERY_REQUIRED → PARTIAL → READY → ERROR
  │
  ├── ROW 1 (120px)
  │   ├── NarrativePanel [col-5]
  │   │   └── Reads: vm.status, vm.risk_exposure, vm.top_risk_drivers[0]
  │   ├── RiskScorePanel [col-4]
  │   │   └── Reads: vm.agirs.score, vm.agirs.grade, vm.trend_history (delta)
  │   └── ConfidencePanel [col-3]
  │       └── Reads: response.confidence.level, response.confidence.pct, response.coverage
  │
  ├── ROW 2 (140px)
  │   ├── BlastRadiusCard [col-3]
  │   │   └── Reads: vm.blast_radius.identity, vm.blast_radius.consequences
  │   ├── AttackPathCard [col-3]
  │   │   └── Reads: vm.findings[0] (top escalation)
  │   ├── IdentityRiskCard [col-3]
  │   │   └── Reads: vm.identity_categories, vm.total_identities
  │   └── RightRail [col-3, row-span-2]
  │       ├── AnomalyWidget
  │       │   └── Reads: vm.anomaly_summary
  │       ├── BusinessImpactWidget
  │       │   └── Reads: vm.blast_radius.consequences
  │       └── DriftWidget
  │           └── Reads: vm.drift_summary
  │
  └── ROW 3 (fill)
      ├── TopActionsPanel [col-5]
      │   └── Reads: vm.immediate_actions (top 3)
      └── ImmediateRisksPanel [col-4]
          └── Reads: vm.top_risk_drivers (top 3)
```

### 6.5 Shared CISO Helpers

**File:** `frontend/src/components/dashboard/ciso-shared.tsx`

| Component | Purpose |
|-----------|---------|
| `ScoreRing` | SVG circular progress (0-100, color-coded) |
| `DN` (DrillableNumber) | Clickable metric → opens IdentityContextDrawer or navigates |
| `Sparkline` | Inline SVG polyline chart |
| `CISOBadge` | Status/severity badge |
| `ProgressBar` | Horizontal progress bar |
| `StatBox` | Metric display box |
| `InsightSentence` | Formatted insight text |
| `SeverityPill` | Critical/High/Medium/Low pill |

---

## 7. Data Flow Diagrams

### 7.1 subscription_count

```
cloud_subscriptions table (populated by Azure discovery)
  │
  ▼
RiskSummaryEngine.compute()
  → SELECT COUNT(DISTINCT account_id) FROM cloud_subscriptions
     WHERE discovery_run_id IN (run_ids)
  → summary['total_subscriptions'] = N
  │
  ▼
_collect_risk_summary(db, run_ids, org_id)
  → raw['total_subscriptions'] = summary['total_subscriptions']
  │
  ▼
_build_risk_summary_data(raw)
  → data['exposure']['subscriptions'] = raw.get('total_subscriptions', 0)
  │
  ▼
Response JSON: data.riskSummary.exposure.subscriptions
  │
  ▼
cisoViewModel.ts: mapSummaryToViewModel()
  → vm.monitored.subscriptions = data.riskSummary.exposure.subscriptions
  │
  ▼
CISODashboard.tsx: header subtitle
  → "{vm.monitored.subscriptions} subscriptions"
```

**Break point for subscriptions=0:** If no discovery has run yet (no rows in `cloud_subscriptions` for the connection's run_ids), the count returns 0. The `_build_risk_summary_data` fallback is `raw.get('total_subscriptions', 0)`. This propagates through to the UI as "0 subscriptions".

### 7.2 last_scan / lastUpdated

```
RiskSummaryEngine.compute()
  → INSERT INTO risk_summary ... computed_at = NOW()
  │
  ▼
db.get_latest_risk_summaries()
  → SELECT computed_at FROM risk_summary ORDER BY computed_at DESC LIMIT 1
  │
  ▼
_collect_risk_summary()
  → raw['computed_at'] = row['computed_at']
  │
  ▼
_build_ciso_envelope()
  → lastUpdated = raw.get('computed_at')
  → IF NULL: fallback to SELECT MAX(completed_at) FROM discovery_runs
  → IF STILL NULL: lastUpdated = None
  │
  ▼
Response JSON: lastUpdated (ISO string or null)
  │
  ▼
cisoViewModel.ts
  → vm.lastUpdated = data.lastUpdated || null
  │
  ▼
CISODashboard.tsx
  → Renders: "Last snapshot: {relative_time}" or "Not observed" if null
```

**Break point for "Not observed":** If no `risk_summary` rows exist AND no completed `discovery_runs` exist, `lastUpdated` is null. The frontend renders "Not observed" (previously "Never", fixed in commit 49ffad6).

### 7.3 posture_score

```
RiskSummaryEngine.compute()
  → Phase 4: Pillar deduction model (7 pillars × 100 points)
  → posture_score = average of pillar scores
  → Persisted to risk_summary.posture_score
  │
  ▼
_collect_risk_summary()
  → raw['posture_score'] = row['posture_score']
  │
  ▼
_build_risk_summary_data()
  → data['postureScore'] = raw.get('posture_score', 0)
  │
  ▼
Response JSON: data.riskSummary.postureScore
  │
  ▼
cisoViewModel.ts
  → vm.posture_score = data.riskSummary.postureScore
  │
  ▼
RiskScorePanel (via ScoreRing SVG)
```

### 7.4 blast_radius

```
identities table → blast_radius column (pre-computed during discovery)
  │
  ▼
_collect_risk_summary()
  → SELECT display_name, risk_score, blast_radius FROM identities
     WHERE discovery_run_id IN (run_ids)
     ORDER BY risk_score DESC LIMIT 1
  → raw['top_identity'] = { display_name, risk_score, blast_radius }
  │
  ▼
_build_risk_summary_data()
  → data['blastRadius'] = raw['top_identity']
  │
  ▼
cisoViewModel.ts
  → vm.blast_radius.identity = { display_name, risk_score }
  → vm.blast_radius.consequences = computed from blast_radius data
  │
  ▼
BlastRadiusCard component
```

### 7.5 identity_count (total_identities)

```
identities table
  │
  ▼
RiskSummaryEngine.compute()
  → SELECT COUNT(*) FROM identities WHERE discovery_run_id IN (run_ids)
  → summary['total_identities'] = N
  │
  ▼
_collect_risk_summary()
  → raw['total_identities']
  │
  ▼
_build_risk_summary_data()
  → data['totalIdentities'] = raw.get('total_identities', 0)
  │
  ▼
Response JSON: data.riskSummary.totalIdentities
  │
  ▼
cisoViewModel.ts
  → vm.total_identities = data.riskSummary.totalIdentities
  → (used as denominator for all percentage calculations)
  │
  ▼
Multiple components: IdentityRiskCard, NarrativePanel, etc.
```

---

## 8. Known Issues & Fix History

| Date | Commit | Issue | Fix |
|------|--------|-------|-----|
| Recent | 49ffad6 | "Last Auth" shows "Never" instead of appropriate text | Changed to "Not observed" |
| Recent | 7313a00 | Numeric identity DB IDs not resolved to UUID in `/identities` | UUID resolution in all endpoints |
| Recent | bbcb39d | CISO dashboard 500 — column name mismatches + RLS rollback | Column alignment + RLS fix |
| Recent | d8db9ca | Cookie `Secure` flag uses wrong env var | Use `APP_ENV` instead of `FLASK_ENV` |
| Recent | ead2f3d | Security audit fixes (#27-#33) | Attack paths, remediation queue, CISO dashboard, lineage overhaul |

### Current Status

- **CISO dashboard:** Functional with 6-source data pipeline, 30s cache, triple error handling
- **subscription_count=0:** Occurs when no discovery has run for the selected connection — expected behavior, shows "0 subscriptions" (not a bug — requires first discovery)
- **lastUpdated="Not observed":** Occurs when no risk_summary or completed discovery_runs exist — fixed wording (was "Never")

---

## 9. Phase Boundaries

### Phase 1 (Current): Identity-First, Azure Primary

- Full Azure identity discovery (Entra ID, RBAC, PIM, CA, Graph API permissions)
- Azure resource discovery (Storage Accounts, Key Vaults)
- App Registration audit
- Risk scoring, anomaly detection, drift detection, SOAR, remediation
- CISO executive dashboard (single SSOT endpoint)
- Admin portal (multi-tenant management, billing)
- AI Security Copilot (Claude API)
- P2 telemetry pipeline (behavioral intelligence)

### Phase 2 (Deferred): Multi-Cloud + Advanced Analytics

- **AWS**: Stub discovery engine exists (`aws_discovery.py`), not production-ready
- **GCP**: Stub discovery engine exists (`gcp_discovery.py`), not production-ready
- Resource scanning expansion (AKS, analytics workspaces)
- Some `/api/security/*` routes return placeholder data (expected, not bugs)
- Some dashboard widgets show "Coming Soon" for AWS/GCP

### Deferred Routes (return placeholder/stub data)

Routes under `/api/security/*` that are primarily for future expansion — they return valid JSON but may contain computed/placeholder data rather than live-discovered data:
- `/api/security/risk-forecast`
- `/api/security/attack-predictions`
- `/api/security/benchmark`
- `/api/security/strategy-advisor`

---

## 10. SSOT Rules (Enforced Going Forward)

### Rule 1: One Endpoint Per Dashboard Page

The CISO Executive Dashboard reads from **exactly one endpoint**: `GET /api/ciso/summary`. All tiles, charts, and metrics derive from this single response. No dashboard tile should make its own API call.

### Rule 2: All Tiles Read from VM Only

Components receive the `CISOViewModel` as props. No component should call `fetch()` or use raw JSON fields. The `mapSummaryToViewModel()` function is the single transformation layer.

### Rule 3: No Hardcoded Fallbacks

- ❌ `subscriptions ?? 0` — masks data pipeline failures
- ❌ `lastUpdated ?? "Never"` — misleading when data hasn't loaded
- ❌ `risk_level ?? "low"` — false reassurance
- ✅ Use null state: show "—" or appropriate empty state
- ✅ Use backend status: `DISCOVERY_REQUIRED` when no data exists

### Rule 4: Null State Shows "—" Not Misleading Zeros

When a metric has no data (no discovery run, no subscriptions, no risk summary):
- Show "—" or "Not observed" — not `0` or `"Never"` or `"low"`
- The backend returns `null` for missing data, not `0`
- The VM should propagate `null` to the component

### Rule 5: subscription_count Always from cloud_subscriptions

Subscription count must come from `cloud_subscriptions` table (populated during discovery), not from `cloud_connections` static config or any hardcoded value. The pipeline:
```
cloud_subscriptions → RiskSummaryEngine → _collect_risk_summary → response → VM → UI
```

### Rule 6: Isolation Integrity

- Every API handler must use `Database(tenant_id=org_id)` for tenant-scoped queries
- `run_ids` must be scoped via `_scoped_run_ids()` with connection validation
- Cross-tenant data access is blocked at the RLS level
- Superadmin bypass only via `Database()` (no tenant_id = admin user)

---

## Appendix: Summary Statistics

| Metric | Count |
|--------|-------|
| **Total database tables** | 96 |
| **RLS-protected tables** | 44 |
| **Total API endpoints** | 534 (320 GET, 147 POST, 34 PUT, 22 DELETE, 11 PATCH) |
| **Frontend pages** | 72 |
| **Frontend components** | 132 |
| **Backend engine files** | 86 |
| **Backend handler lines** | 33,792 |
| **Database.py lines** | 27,518 |
| **Main.py lines** | 3,981 |
| **SQL migrations** | 82 files |
| **Test files** | 52 (backend) + 4 (frontend) |
| **SSOT endpoint** | `GET /api/ciso/summary` |

### Break Point Analysis

| Issue | Layer | Description | Status |
|-------|-------|-------------|--------|
| Subscriptions=0 | DB → Engine | No `cloud_subscriptions` rows when discovery hasn't run | Expected behavior — DISCOVERY_REQUIRED status shown |
| Last scan="Not observed" | DB → Envelope | No `risk_summary.computed_at` and no `discovery_runs.completed_at` | Fixed (was "Never", now "Not observed") |

### Recommended Monitoring

1. **subscription_count**: Alert if subscription_count > 100 per connection (data leak detection already in handler)
2. **active_subscriptions > total_subscriptions**: Logged as ERROR (already implemented)
3. **CISO summary cache misses**: Monitor 30s cache hit rate for performance
4. **Discovery run completion**: Alert if no completed run in 2× scheduled interval

## 11. Latent Risks

### identities table missing cloud_connection_id

The `identities` table currently has no `cloud_connection_id` column. Tenant scoping
is via `discovery_run_id` → `discovery_runs.tenant_id`. This transitive path works
but complicates direct Tier 1 ↔ Tier 2 cross-referencing. Phase 2 plan:

```sql
ALTER TABLE identities ADD cloud_connection_id INTEGER REFERENCES cloud_connections(id);
```

This would enable direct connection-scoped identity queries without joining through
`discovery_runs`, simplifying isolation logic and improving query performance.

### LR-2: handlers.py is 33,000+ lines

**Current state**: Single file contains all API endpoints and supporting functions.

**Risk**: As the codebase grows, merge conflicts, test coverage gaps, and cognitive load
increase. Currently manageable but will become critical around 40k+ lines.

**Phase 2 fix** — split into domain modules:
```
backend/app/api/
  handlers_ciso.py
  handlers_identity.py
  handlers_discovery.py
  handlers_inventory.py
  handlers_shared.py (shared helpers, isolation functions)
```

**Mitigation until Phase 2**: New endpoints go at the top of their domain section
with a clear section comment.

## 12. New Endpoints Registry

| Endpoint | Tier | Purpose | Added |
|----------|------|---------|-------|
| GET /api/inventory/summary | Tier 1 | Connection health + subscription counts. Always available — never blocked by discovery state. | 2026-04-08 |

Available at both `/api/inventory/summary` and `/api/v1/inventory/summary`
(auto-mirrored by `_register_v1_routes()`).

## 13. Tier Violation Register

All known Tier 1/2 mixing violations and their fixes:

| File | Field | Violation | Fix Applied | Date |
|------|-------|-----------|-------------|------|
| `CISODashboard.tsx` | Header subtitle | Tier 2 VM (`vm.last_updated`, `vm.monitored.subscriptions`) used in Tier 1 header slot | `useInventorySummary()` → `inventorySubtitle` | 2026-04-08 |
| `ExecutiveSummaryHero.tsx` | ConfidencePanel subscriptions | `vm.monitored.subscriptions` used without Tier 1 override | `inventorySubscriptions ?? vm.monitored.subscriptions` | 2026-04-08 |

When adding new dashboard components that show last_scan or subscription count:
always use `useInventorySummary()` — never read from CISOViewModel for these fields.

## 14. Phase 3 Identity Engine (A1–E8)

### Overview

The Phase 3 identity engine is a FastAPI application mounted inside the Flask
WSGI process via `a2wsgi` and `Phase3Dispatcher` (see `app/api/phase3_wsgi.py`).
It provides a clean-sheet identity API under `/api/v1/` that replaces the
legacy Flask handler endpoints for identity state, posture scoring, and
what-if simulation.

### Route Map (15 endpoints)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/identities` | Paginated identity list (org-scoped) |
| GET | `/api/v1/identities/{id}` | Full identity state (11 B-blocks) |
| GET | `/api/v1/identities/{id}/roles` | RBAC role assignments |
| GET | `/api/v1/identities/{id}/attack-paths` | Attack path chains |
| GET | `/api/v1/identities/{id}/remediation` | Matched remediation actions |
| POST | `/api/v1/identities/{id}/remediation/{aid}/execute` | Execute remediation |
| GET | `/api/v1/identities/{id}/simulations` | Simulation history |
| POST | `/api/v1/identities/{id}/simulate` | Run what-if simulation |
| GET | `/api/v1/identities/{id}/simulations/{sid}/export` | Export finding artifact |
| GET | `/api/v1/identities/global/{gid}` | Cross-org global identity lookup |
| GET | `/api/v1/posture/score` | Current posture score (5 dimensions) |
| GET | `/api/v1/posture/score/history` | Posture trend (N days) |
| POST | `/api/v1/posture/score/recompute` | Force recompute (rate-limited) |
| GET | `/api/v1/posture/actions` | Top priority remediation actions |
| POST | `/api/v1/posture/simulate/bulk` | Bulk what-if (max 50, rate-limited) |

### Key Components

```
backend/app/
├── api/
│   ├── routes/
│   │   ├── identities.py      FastAPI router (identity endpoints)
│   │   └── posture.py          FastAPI router (posture endpoints)
│   ├── deps.py                 Shared dependencies (auth, DB session)
│   ├── rate_limit.py           In-memory sliding window rate limiter
│   └── phase3_wsgi.py          Flask↔FastAPI bridge (a2wsgi dispatcher)
├── schemas/
│   └── identity.py             Pydantic v2 models (20+ enums, 11 B-blocks)
├── services/
│   ├── identity_state_engine.py  Orchestrator (B01–B09 block assembly)
│   ├── posture_score_engine.py   5-dimension CVSS scoring engine
│   ├── whatif_service.py         What-if simulation (3 types)
│   ├── global_identity_registry.py  F1 cross-cloud UUID registry
│   └── builders/
│       ├── identity_profile_builder.py   B01 profile + B03 ownership + B05 privilege
│       ├── activity_builder.py           B02 activity/lifecycle
│       ├── governance_engine.py          B04 governance classification
│       ├── risk_engine.py                B06 risk scoring (5 factors)
│       ├── attack_path_engine.py         B08 attack path computation
│       ├── identity_blast_radius_engine.py  Blast radius traversal
│       └── enum_aliases.py               SSOT enum alias map (E8)
│   └── phase3_skeleton_writer.py   Legacy→Phase 3 bridge (upserts to skeleton tables)
```

### Tenant Isolation

Every Phase 3 endpoint extracts `organization_id` from the JWT via
`Depends(_current_org_id)`. The org ID is threaded into every SQL query
as a bind parameter — there is no URL-based or header-based org override.
The `test_phase3_org_isolation.py` suite (24 tests) validates this.

### Enum System

Enums use Title case canonical values (`RiskLabel.CRITICAL = "Critical"`)
but accept case-insensitive input via `_CaseInsensitiveMixin._missing_()`.
Legacy discovery values (e.g., `"guest"`, `"managed_identity_system"`) are
mapped via `IDENTITY_TYPE_ALIASES` in `enum_aliases.py`.

### Rate Limiting

Three compute-heavy endpoints are rate-limited per org:
- `POST /score/recompute`: 3 calls / 60s
- `POST /{id}/simulate`: 10 calls / 60s
- `POST /simulate/bulk`: 5 calls / 60s

Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header.

### Contract Sync

`backend/tests/export_api_contract.py` introspects the FastAPI routers and
emits `api_contract.json`. The frontend's `npm run check:contract` compares
the backend's response model fields against the TypeScript interfaces in
`identityEngineApi.ts`. CI should run both to detect drift.

### Sprint History

| Sprint | Scope |
|--------|-------|
| A1 | FastAPI mount, async DB, IdentityStateEngine, B01–B09 blocks |
| E1 | Skeleton writer bridge (legacy discovery → Phase 3 tables) |
| E2 | DataContext/confidence propagation, partial-data states |
| E3 | Attack path engine, blast radius, remediation actions |
| E4 | What-if simulation engine (3 types), simulation history |
| E5 | Global identity registry, cross-org lookup, simulation export |
| E6 | Posture score engine, CISO Dashboard v1, trend chart |
| E7 | Cache-Control fix, what-if UI hardening, bulk simulation |
| E8 | Contract sync, enum audit, org isolation suite, rate limiting |

## 15. Data Tiers — Platform Contract

See `backend/docs/DATA_TIERS.md` for the full tier definitions covering:
- Tier 1 (Inventory): `cloud_connections`, `cloud_subscriptions` — always available
- Tier 2 (Analytics): `identities`, `risk_summary`, etc. — requires completed discovery
- Semantic naming rules (inventory_subscriptions vs subscription_count)
- Isolation rules for both tiers
