# AuditGraph Technical Design Document

**Version:** 2.0
**Last Updated:** 2026-05-08
**Classification:** Internal — Engineering & TPM Reference
**Authors:** Engineering Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Application Architecture](#3-application-architecture)
4. [Database Architecture](#4-database-architecture)
5. [Security Architecture](#5-security-architecture)
6. [Discovery Pipeline](#6-discovery-pipeline)
7. [API Design](#7-api-design)
8. [Frontend Architecture](#8-frontend-architecture)
9. [Infrastructure & Deployment](#9-infrastructure--deployment)
10. [Risk & Scoring Engines](#10-risk--scoring-engines)
11. [Multi-Tenancy & Isolation](#11-multi-tenancy--isolation)
12. [Observability & Operations](#12-observability--operations)
13. [Feature Inventory & Maturity](#13-feature-inventory--maturity)
14. [Technical Debt & Known Gaps](#14-technical-debt--known-gaps)
15. [Appendix](#15-appendix)

---

## 1. Executive Summary

AuditGraph is a cloud identity security platform that discovers, classifies, and governs non-human identities (NHIs) and human users across Azure Entra ID and Azure RBAC. It provides continuous discovery, risk scoring, lineage analysis, drift detection, attack path simulation, and remediation orchestration for enterprise identity posture management.

**Key Metrics (as of 2026-05-08):**

| Metric | Value |
|--------|-------|
| Backend Python modules | 200 files |
| Frontend React components | 214 files (75 pages + 139 components) |
| API endpoints | 160+ |
| Database tables | 154 |
| Database migrations | 114 |
| RLS policies | 525 |
| Database indexes | 565 |
| Analysis engines | 99 |
| Supported cloud | Azure (AWS/GCP schema-ready) |

---

## 2. System Overview

### 2.1 High-Level Architecture

```
                    +------------------+
                    |   Client Browser |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  React Frontend  |  :3000 (dev) / Nginx (prod)
                    |  (TypeScript/    |
                    |   Tailwind CSS)  |
                    +--------+---------+
                             |  REST API
                    +--------v---------+
                    |  Flask + FastAPI  |  :5001 (dev) / Container Apps (prod)
                    |  (Hybrid WSGI/   |
                    |   ASGI Gateway)  |
                    +----+----+----+---+
                         |    |    |
              +----------+    |    +----------+
              |               |               |
     +--------v----+  +------v------+  +------v------+
     | PostgreSQL   |  | APScheduler |  | Azure Graph |
     | 16 (RLS)     |  | (Discovery  |  | API / ARM   |
     | :5434        |  |  Scheduler) |  | SDK         |
     +--------------+  +-------------+  +-------------+
```

### 2.2 Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend | React + TypeScript | 19.2 / 4.9 |
| Styling | Tailwind CSS | 3.4 |
| Graphs | @xyflow/react, Recharts | 12.10, 3.7 |
| API Framework | Flask (primary) + FastAPI (async routes) | 3.0 / 0.104 |
| Database | PostgreSQL | 16 |
| ORM | Direct psycopg2 (not SQLAlchemy ORM) | 2.9 |
| Auth | JWT (HS256) + SAML + OIDC | PyJWT 2.x |
| Cloud SDK | Azure Identity, MS Graph SDK, ARM | Latest |
| Scheduler | APScheduler | 3.x |
| Encryption | Fernet (AES-128 + HMAC) | cryptography |
| Containerization | Docker + Docker Compose | Latest |
| IaC | Azure Bicep | Native |
| CI/CD | GitHub Actions | 3 workflows |
| Reverse Proxy | Nginx | Latest |
| Deployment | Azure Container Apps | Latest |

---

## 3. Application Architecture

### 3.1 Backend Module Structure

```
backend/app/
+-- main.py                    (4,784 lines — Flask app, routes, middleware)
+-- database.py                (21,000+ lines — all DB operations)
+-- scheduler.py               (5,600+ lines — APScheduler jobs, background tasks)
+-- encryption.py              (226 lines — Fernet field-level encryption)
+-- security_events.py         (150 lines — structured security event logging)
+-- api/
|   +-- handlers.py            (39,789 lines — all REST handler implementations)
|   +-- auth.py                (26,472 lines — JWT, RBAC, middleware)
|   +-- validation.py          (176 lines — JSON schema validation)
|   +-- routes.py              (Phase 3 modular route registration)
|   +-- routes/                (5 async route modules: approvals, identities,
|   |                            posture, resources, snapshots)
|   +-- deps.py                (380 lines — FastAPI dependencies, DB sessions)
|   +-- oidc.py                (OIDC integration)
|   +-- saml.py                (SAML SSO)
|   +-- scim.py                (SCIM user provisioning)
|   +-- rate_limit.py          (async rate limiter)
|   +-- integrity.py           (data integrity checks)
|   +-- metric_queries.py      (analytics queries)
+-- engines/                   (99 files — core analysis engines)
|   +-- discovery/             (12 files — Azure/cloud discovery pipelines)
|   +-- analysis/              (7 files — attack paths, blast radius, drift)
|   +-- risk/                  (3 files — AGIRS, SPN risk, risk summary)
|   +-- scoring/               (3 files — CVSS, attack path, posture scoring)
|   +-- remediation/           (7 files — fix catalogue, simulation, priority)
|   +-- correlation/           (4 files — identity correlation, zombie detection)
|   +-- attack_paths/          (2 files — attack path detection)
|   +-- execution/             (2 files — action execution)
|   +-- telemetry/             (3 files — CloudTrail, P2, behavioral)
+-- services/                  (34 files — business logic layer)
|   +-- builders/              (6 files — activity, attack path, governance,
|   |                            risk, blast radius builders)
|   +-- graph/                 (4 files — traversal engine, metrics, policies)
|   +-- email_service.py       (scheduled reports, drift notifications)
|   +-- webhook_service.py     (outbound webhook dispatch)
|   +-- notification_service.py
+-- security/                  (4 files)
|   +-- sql_identifiers.py     (allowlist-based SQL identifier validation)
|   +-- sso_security.py        (SAML hardening, replay prevention)
|   +-- tenant_scope.py        (cross-org guards, org_id decorators)
+-- middleware/                (6 files — input sanitizer, org scope guard)
+-- constants/                 (7 files — AGIRS, activity types, roles)
+-- entitlements/              (6 files — feature gates, plan enforcement)
+-- config/                    (2 files — app config, feature flags)
+-- billing/                   (3 files — billing service)
+-- ai/                        (3 files — copilot gateway)
+-- adapters/                  (2 files — Azure adapter)
```

### 3.2 Request Lifecycle

```
Browser Request
    |
    v
[Nginx / React Dev Proxy] -----> :5001
    |
    v
[Flask before_request hooks]
    |-- auth_middleware()          → JWT validation, org context
    |-- _enforce_demo_write_guard → Block writes on demo orgs
    |-- sanitize_request()        → XSS/SQLi pattern detection
    |-- security_headers()        → CSP, HSTS, X-Frame-Options
    |
    v
[Route Handler] (handlers.py)
    |-- _db()                     → New Database() connection
    |-- SET app.current_organization_id  → RLS context
    |-- Business logic + DB queries
    |-- db.close()
    |
    v
[after_request hooks]
    |-- add_security_headers()
    |-- JSON response formatting
    |
    v
Response to Client
```

### 3.3 Hybrid Flask + FastAPI Architecture

The application uses a **Flask-primary, FastAPI-secondary** pattern:

- **Flask** handles all synchronous routes (160+ endpoints in main.py)
- **FastAPI** handles Phase 3 async routes via an ASGI-to-WSGI bridge (`phase3_wsgi.py`)
- Async routes: approvals, advanced identity queries, posture analytics, resource discovery, snapshot management
- Both frameworks share the same JWT validation and database layer

---

## 4. Database Architecture

### 4.1 Overview

| Property | Value |
|----------|-------|
| Engine | PostgreSQL 16 |
| Port | 5434 (dev), 5432 (prod) |
| Users | `auditgraph` (admin/migrations), `auditgraph_app` (application) |
| Tables | 154 |
| Indexes | 565 |
| RLS Policies | 525 |
| Foreign Keys | 0 (application-managed referential integrity) |
| Total disk | ~500 MB (dev dataset) |

### 4.2 Schema Domain Model

```
+-------------------+     +---------------------+     +------------------+
| organizations     |     | cloud_connections    |     | discovery_runs   |
| (5 orgs)          |<--->| (Azure creds/config) |<--->| (scan history)   |
+-------------------+     +---------------------+     +--------+---------+
                                                               |
                          +------------------------------------+
                          |
              +-----------v-----------+
              |     identities        |
              | (8,238 rows, 32 MB)   |
              | - identity_id (UUID)  |
              | - display_name        |
              | - identity_type       |
              | - risk_level/score    |
              | - activity_status     |
              | - recommended_action  |
              | - workload_origin     |
              +-----------+-----------+
                          |
        +-----------------+------------------+
        |                 |                  |
+-------v------+  +------v-------+  +-------v--------+
| role_         |  | credentials  |  | entra_role_    |
| assignments   |  | (5,849)      |  | assignments    |
| (28,562)      |  +--------------+  | (346 for org10)|
+--------------+                     +----------------+
        |
+-------v---------+     +-------------------+     +------------------+
| identity_graph_  |     | lineage_verdicts  |     | anomalies        |
| edges (35,929)   |     | (6,268)           |     | (46 for org10)   |
+-----------------+      +-------------------+     +------------------+

+------------------+     +-------------------+     +------------------+
| attack_paths     |     | drift_reports     |     | remediation_     |
+-----------------+      | (107, 27 MB)      |     | queue            |
                         +-------------------+     +------------------+
```

### 4.3 Core Table Groups

**Identity & Access (12 tables):**
identities, identity_credentials, identity_subscription_access, identity_list, role_assignments, entra_role_assignments, entra_groups, entra_group_memberships, graph_api_permissions, credentials, federated_credentials, identity_orphan_classifications

**Discovery & Lineage (8 tables):**
discovery_runs, discovery_run_phases, lineage_verdicts, identity_lineage_scores, workload_attributions, identity_reachability, discovered_resources, pipeline_health_metrics

**Risk & Analysis (10 tables):**
identity_risk_scores, risk_findings, spn_exposure_findings, identity_attack_predictions, attack_paths, attack_simulations, security_findings, risk_forecasts, privilege_drift_events, identity_threat_events

**Graph (5 tables):**
graph_nodes, graph_edges, identity_graph_edges, graph_snapshots, graph_visualization_cache

**Governance & Compliance (8 tables):**
compliance_frameworks, compliance_controls, compliance_snapshots, access_review_campaigns, access_reviews, security_advisor_reports, tenant_posture_metrics, conditional_access_policies

**Operational (12 tables):**
organizations, users, cloud_connections, scan_schedules, settings, activity_log, admin_audit_log, notifications, saved_views, soar_playbooks, soar_actions, webhooks

### 4.4 Row-Level Security (RLS) Design

Every tenant-scoped table enforces RLS via PostgreSQL session variable:

```sql
-- Set on every request by Database.set_organization_context()
SET app.current_organization_id = '10';

-- Policy pattern (4 policies per table):
CREATE POLICY org_strict_sel ON {table} FOR SELECT
  USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY org_strict_ins ON {table} FOR INSERT
  WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY org_strict_upd ON {table} FOR UPDATE
  USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY org_strict_del ON {table} FOR DELETE
  USING (organization_id = current_setting('app.current_organization_id', true)::integer);
```

**Key properties:**
- `FORCE ROW LEVEL SECURITY` enabled (applies even to table owner)
- 26 tables have dual-layer RLS (domain-specific + org_strict)
- Auto-insert trigger `fn_auto_organization_id_{table}` populates org_id
- Application user `auditgraph_app` has no DDL permissions
- Migrations run as `auditgraph` (admin user)

### 4.5 Migration Strategy

- 114 migrations in `backend/migrations/` (001-114)
- Idempotent: `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`
- Run by admin user via `scripts/run_migrations.py`
- No ORM-generated migrations (hand-written SQL)
- Schema changes tracked in `schema_migrations` table

### 4.6 Largest Tables by Disk

| Table | Size | Rows | Avg Row |
|-------|------|------|---------|
| entra_group_memberships | 180 MB | 34,389 | 5.4 KB |
| discovered_resources | 47 MB | 19,485 | 2.5 KB |
| notifications | 33 MB | 28,556 | 1.2 KB |
| identities | 32 MB | 8,238 | 4.0 KB |
| drift_reports | 27 MB | 107 | 252 KB |
| spn_exposure_findings | 26 MB | 37,607 | 0.7 KB |

---

## 5. Security Architecture

### 5.1 Authentication

| Method | Implementation | Expiry |
|--------|---------------|--------|
| JWT (Admin) | HS256, `ADMIN_JWT_SECRET` | 30 min |
| JWT (Client) | HS256, `CLIENT_JWT_SECRET` | 60 min |
| Refresh Token | Opaque 48-byte, SHA-256 hashed in DB | 7 days |
| API Key | SHA-256 hashed, `X-API-Key` header | Configurable |
| SAML SSO | Signed + encrypted assertions, replay cache | Per IdP |
| OIDC | Standard flow with JWKS validation | Per provider |
| Cookie Auth | httpOnly, Secure, SameSite=Lax + CSRF double-submit | Session |

### 5.2 Authorization (RBAC)

```
Role Hierarchy: owner > admin > security_admin > compliance > reader > auditor/viewer

Decorators:
  @require_role('admin', 'owner')        — standard RBAC
  @require_superadmin()                  — platform admin only
  @require_portal_access()               — portal role check
  @require_portal_role('poweradmin')     — specific portal roles
```

### 5.3 Encryption

| Layer | Method | Standard |
|-------|--------|----------|
| In Transit | TLS 1.2+ (HSTS enforced) | NIST SP 800-52 |
| At Rest (fields) | Fernet (AES-128-CBC + HMAC-SHA256) | NIST SP 800-111 |
| At Rest (DB) | PostgreSQL TDE (Azure managed) | Azure |
| Passwords | bcrypt, 12 rounds | NIST SP 800-63B |
| Key Rotation | MultiFernet with newest-first key chain | Custom |

**Protected fields:** client_secret, refresh_token, API keys

### 5.4 Input Validation & Injection Prevention

| Attack | Mitigation |
|--------|-----------|
| SQL Injection | Parameterized queries (`%s` placeholders), SQL identifier allowlist |
| XSS | Input sanitization middleware (8 regex patterns), CSP headers |
| CSRF | Double-submit cookie pattern, SameSite=Lax |
| Clickjacking | X-Frame-Options: DENY |
| MIME Sniffing | X-Content-Type-Options: nosniff |
| Information Leak | Referrer-Policy: strict-origin, no stack traces in prod |

### 5.5 Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
Cache-Control: no-store, no-cache, must-revalidate
```

### 5.6 Audit Logging

| Event | Severity | Destination |
|-------|----------|-------------|
| LOGIN_SUCCESS | info | security_events log |
| AUTH_FAILURE | medium | security_events log |
| TENANT_CONTEXT_VIOLATION | critical | security_events + alert |
| RLS_DRIFT_DETECTED | critical | security_events + alert |
| ADMIN_GUARD_BLOCKED | high | security_events |
| All user actions | info | activity_log table |
| Admin operations | info | admin_audit_log table |

### 5.7 Secret Lifecycle

- Azure client secrets decrypted only at point of use (`decrypt_field()`)
- Zeroed immediately after SDK credential initialization (`client_secret = None`)
- 12 explicit zeroing points across scheduler.py (7) and azure_discovery.py (5)
- Background threads use `nonlocal` + `finally` blocks for guaranteed cleanup

---

## 6. Discovery Pipeline

### 6.1 Pipeline Phases

```
Phase 1:  Authenticate → MS Graph SDK + ARM credential setup
Phase 2:  Discover Users → Human users from Entra ID
Phase 3:  Discover SPNs → Service principals + app registrations
Phase 4:  Discover Groups → Entra groups + memberships
Phase 5:  Discover Roles → Entra directory roles + RBAC assignments
Phase 6:  Discover Credentials → Passwords, certificates, federated
Phase 7:  Risk Assessment → AGIRS scoring, CVSS, CIS Controls
Phase 8:  Activity Analysis → Sign-in logs, audit events
Phase 8.5: Workload Inference → Role-based workload type classification
Phase 8.75: Lineage Verdicts → 12-signal lineage assembly
Phase 9:  Save Identities → Persist to DB with all computed fields
Phase 9.5: Lineage Tables → lineage_verdicts, orphan classifications
Phase 9d/e: ARM Bindings → Managed identity resource bindings
Phase 10-39: Post-processing → Drift detection, ghost detection
Phase 40: Anomaly Detection → 7 identity + 6 resource detectors
Phase 89: Cleanup → Archive old runs, prune stale data
```

### 6.2 Lineage Engine (12 Signals)

| Signal | Source | Weight |
|--------|--------|--------|
| Role Topology | Active non-read-only roles | 10-30 |
| App Registration | Owner, service, reply URLs | 0-20 |
| Sign-in Activity | Pattern, recency | -10 to +20 |
| Federated Credential | External pipeline trust | 35 |
| Discovery Connector | AuditGraph's own SPN | 30 |
| ARM/MI Binding | Managed identity host resource | 30 |
| Heuristic Detection | Name/pattern matching | 10-20 |
| API Usage Pattern | Graph API call patterns | 15 |
| Audit Provenance | Created-by metadata | 20 |
| Owned Objects | Platform SPN ownership | 10-25 |
| Tier-aware Inactivity | Privilege level + staleness | -3 to -15 |
| Key Vault Expiry | Certificate/secret expiry | -8 to -15 |

**Verdict outcomes:** HEALTHY, NEEDS_REVIEW, UNUSED, STALE, ORPHANED, AT_RISK, GHOST_MSI

### 6.3 Scheduling

- Managed by APScheduler (CronTrigger)
- Default: every 12 hours per org
- Configurable per-org via `scan_schedules` table
- Background enrichment threads for: owned objects, IP geolocation, sign-in intelligence

---

## 7. API Design

### 7.1 Endpoint Categories

| Category | Count | Auth | Examples |
|----------|-------|------|----------|
| Health/System | 7 | None/Admin | `/health`, `/api/metrics` |
| Authentication | 10 | Public/Token | `/api/auth/login`, `/api/auth/refresh` |
| Identities | 15+ | Client | `/api/identities`, `/api/identities/<id>` |
| Dashboard | 10+ | Client | `/api/dashboard/posture`, `/api/dashboard/compliance` |
| Discovery | 5 | Client | `/api/discovery/run`, `/api/discovery/status` |
| Anomalies | 5 | Client | `/api/anomalies/stats`, `/api/anomalies` |
| SOAR | 7 | Client | `/api/soar/playbooks`, `/api/soar/actions` |
| Remediation | 8+ | Client | `/api/remediation/queue`, `/api/remediation/actions` |
| Reports/Export | 5+ | Client | `/api/export/identities`, `/api/reports` |
| Settings | 5+ | Admin | `/api/settings`, `/api/saved-views` |
| Admin | 25+ | Superadmin | `/api/admin/organizations`, `/api/admin/billing` |

### 7.2 API Conventions

- **Response format:** JSON with consistent `{data, error, error_code, request_id}` envelope
- **Pagination:** `?limit=50&offset=0` (max 200)
- **Filtering:** Query params (`?risk_level=critical&identity_type=service_principal`)
- **Sorting:** `?sort_field=risk_score&sort_dir=desc`
- **Export:** Streaming CSV with chunked transfer encoding
- **Idempotency:** `X-Idempotency-Key` header support for mutating operations
- **Rate limiting:** Per-IP sliding window (auth), per-org (async routes)

---

## 8. Frontend Architecture

### 8.1 Structure

```
frontend/src/
+-- App.tsx                     (Main router — React Router 7)
+-- pages/                      (75 page components)
|   +-- CISODashboard.tsx       (Executive security dashboard)
|   +-- Identities.tsx          (Identity inventory — primary view)
|   +-- IdentityDetail.tsx      (5-tab identity deep dive)
|   +-- Dashboard.tsx           (Operational dashboard)
|   +-- SecurityCommandCenter   (SOC-style command view)
|   +-- Settings.tsx            (Org configuration)
|   +-- OnboardingWizard.tsx    (New tenant setup)
|   +-- [70+ more pages]
+-- components/                 (139 reusable components)
|   +-- ciso/                   (CISO dashboard widgets)
|   +-- dashboard/              (Dashboard subsections)
|   +-- graph/                  (Graph visualization — @xyflow)
|   +-- identity-detail/        (5-tab detail architecture)
|   +-- settings/               (Settings page tabs)
|   +-- layout/                 (Sidebar, TopBar, TrialBanner)
|   +-- ui/                     (Base UI primitives)
+-- contexts/                   (6 React contexts)
|   +-- AuthContext              (JWT state, login/logout)
|   +-- TenantContext            (Org selection)
|   +-- ConnectionContext        (Cloud connection selection)
|   +-- ThemeContext             (Dark/light mode)
|   +-- CopilotContext           (AI assistant state)
|   +-- FeatureFlagContext       (Entitlement-driven UI gates)
+-- services/
|   +-- api.ts                  (API client wrapper)
|   +-- apiClient.ts            (Axios instance with interceptors)
|   +-- identityEngineApi.ts    (Identity-specific API)
+-- utils/                      (Export, formatting, scoring helpers)
+-- constants/                  (Metrics, activity types, roles)
+-- types/                      (TypeScript type definitions)
```

### 8.2 Key Frontend Patterns

- **UI Lock Policy:** Backend/data wiring changes only — no layout/structure modifications
- **Export:** CSV via `IDENTITY_CSV_COLUMNS` constant, risk scores normalized to 0-10
- **Graph visualization:** @xyflow/react for identity graphs, Recharts for charts
- **PDF generation:** jspdf + jspdf-autotable for compliance reports
- **State management:** React Context (no Redux)
- **Routing:** React Router 7 with auth guards

---

## 9. Infrastructure & Deployment

### 9.1 Local Development

```
docker-compose.yml:
  - PostgreSQL 16 (port 5434)
  - Redis (optional)

Backend:  python wsgi.py → Flask on :5001
Frontend: npm start → CRA dev server on :3000 (proxies to :5001)
```

### 9.2 Production (Azure Container Apps)

```
Azure Container Apps (Bicep IaC):
  +-- auditgraph-api     (Flask/Uvicorn backend)
  +-- auditgraph-app     (React SPA + Nginx)
  +-- auditgraph-admin   (Admin portal + Nginx)

Azure Flexible Server:
  +-- PostgreSQL 16 (SSL required, RLS enforced)

GitHub Actions (3 workflows):
  +-- deploy.yml          (Production deployment)
  +-- dev-deploy.yml      (Dev deployment)
  +-- security-scan.yml   (gitleaks, bandit, dependency audit)
```

### 9.3 Environment Tiers

| Tier | Database | Config File | Domain |
|------|----------|------------|--------|
| Local | localhost:5434 | .env.local | localhost:3000 |
| Dev | Azure Flexible Server | .env.dev | dev.auditgraph.ai |
| QA | Azure Flexible Server | .env.qa | qa.auditgraph.ai |
| Staging | Azure Flexible Server | .env.stg | stg.auditgraph.ai |
| Production | Azure Flexible Server | .env.prod | app.auditgraph.ai |

---

## 10. Risk & Scoring Engines

### 10.1 AGIRS (AuditGraph Identity Risk Score)

- Additive risk scoring: raw integer (0-2500+), normalized to 0-10 for display
- Based on CVSS v3.1 base metrics adapted for identity risk
- Inputs: privilege tier, credential health, activity staleness, MFA coverage, role count, blast radius

### 10.2 Risk Levels

| Level | Score Range | Description |
|-------|------------|-------------|
| Critical | 8.0-10.0 | Immediate action required |
| High | 6.0-7.9 | Requires attention within 7 days |
| Medium | 3.0-5.9 | Review within 30 days |
| Low | 1.0-2.9 | Monitor |
| Info | 0.0-0.9 | No action needed |

### 10.3 Anomaly Detection

7 identity detectors + 6 resource detectors run post-discovery:
- Credential surge, risk score spike, ghost identity appearance
- Role assignment anomaly, permission escalation
- Resource configuration drift, policy violation

### 10.4 Compliance Frameworks

- CIS Controls v8 (identity-focused controls)
- NIST SP 800-63B (credential management)
- MITRE ATT&CK v14 (attack path mapping)
- CVSS v3.1 (vulnerability scoring adapted for identities)

---

## 11. Multi-Tenancy & Isolation

### 11.1 Isolation Layers

```
Layer 1: JWT — org_id claim in token, validated on every request
Layer 2: RLS — PostgreSQL row-level security on ALL tenant tables
Layer 3: Application — @requires_org_id decorator, OrgScopedSession interceptor
Layer 4: Connection — Database._poison_connection() on RLS/rollback failures
```

### 11.2 Verified Isolation (Audit 2026-05-08)

| Table | org=10 | org=9 | Cross-Leak |
|-------|--------|-------|------------|
| identities | 5,169 | 280 | None |
| discovery_runs | 8 | 3 | None |
| cloud_connections | 1 | 1 | None |
| entra_role_assignments | 186 | 20 | None |
| credentials | 2,912 | 0 | None |
| anomalies | 46 | 0 | None |

---

## 12. Observability & Operations

### 12.1 Logging

- Structured logging via Python `logging` module
- Security events: `SecurityEventLogger` with severity levels
- Discovery pipeline: phase-level progress logging
- Request tracking: `g.request_id` correlation ID

### 12.2 Health Checks

| Endpoint | Purpose |
|----------|---------|
| `/health` | Basic liveness |
| `/health/live` | Kubernetes liveness probe |
| `/health/ready` | Kubernetes readiness probe (DB check) |
| `/api/system/health` | Detailed system status |
| `/api/system/sla` | SLA metrics |

### 12.3 Operational Runbooks

Located in `docs/engineering/runbooks/`:
- Database migration procedures
- Discovery pipeline troubleshooting
- Incident response playbook

---

## 13. Feature Inventory & Maturity

### 13.1 Production-Ready (Active Data)

| Feature | Tables with Data | Status |
|---------|-----------------|--------|
| Identity Discovery | identities, role_assignments, credentials | Active |
| Risk Scoring (AGIRS) | identity_risk_scores, risk_findings | Active |
| Lineage Analysis | lineage_verdicts, identity_lineage_scores | Active |
| Anomaly Detection | anomalies | Active |
| Drift Detection | drift_reports, privilege_drift_events | Active |
| Graph Visualization | graph_nodes, graph_edges | Active |
| Attack Path Analysis | attack_paths, spn_exposure_findings | Active |
| Notification System | notifications | Active |
| SOAR Orchestration | soar_playbooks, soar_actions | Schema ready |
| Scheduled Reports | report scheduling via settings | Active |

### 13.2 Schema-Ready (Empty Tables)

| Feature | Tables | Status |
|---------|--------|--------|
| Billing & Invoicing | invoices, billing_events, billing_audit_log | Schema only |
| Compliance Frameworks | compliance_frameworks, compliance_controls | Schema only |
| Access Reviews | access_review_campaigns, access_reviews | Schema only |
| PIM Integration | pim_activations, pim_eligible_assignments | Schema only |
| Formal Reporting | reports, report_runs, report_outputs | Schema only |
| Auto-Remediation | auto_remediation_actions | Schema only |

---

## 14. Technical Debt & Known Gaps

### 14.1 Architecture

| Item | Impact | Priority |
|------|--------|----------|
| `handlers.py` is 39,789 lines | Hard to navigate, slow IDE | Medium |
| `database.py` is 21,000+ lines | Same concern | Medium |
| No foreign keys in DB | Orphaned records possible | Low (by design) |
| 97 empty tables | Schema bloat | Low |
| Flask + FastAPI hybrid | Two auth paths to maintain | Low |

### 14.2 Operational

| Item | Impact | Priority |
|------|--------|----------|
| DDL-in-request pattern | Multiple tables had `_ensure_*_table()` running DDL per request; fixed for SOAR, saved_views, lineage_verdicts via migrations 112-114 | Resolved |
| Lineage coverage 18.7% | Genuine for this tenant — depends on ARM bindings, app reg metadata, federated signals | Monitor |
| org=11 never existed | Audit referenced non-existent org; using org=9 as second test org | Resolved |

---

## 15. Appendix

### 15.1 Key File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `backend/app/main.py` | 4,784 | Flask app, routes, middleware |
| `backend/app/api/handlers.py` | 39,789 | All REST handlers |
| `backend/app/api/auth.py` | 26,472 | Authentication & authorization |
| `backend/app/database.py` | 21,000+ | All database operations |
| `backend/app/scheduler.py` | 5,600+ | Discovery scheduling, background tasks |
| `backend/app/engines/discovery/azure_discovery.py` | 10,800+ | Azure discovery pipeline |
| `frontend/src/pages/Identities.tsx` | 1,800+ | Identity inventory page |
| `frontend/src/pages/CISODashboard.tsx` | 2,500+ | Executive dashboard |

### 15.2 Environment Variables (Key)

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` / `ADMIN_JWT_SECRET` / `CLIENT_JWT_SECRET` | Token signing |
| `ENCRYPTION_KEY` / `ENCRYPTION_KEYS` | Fernet field encryption |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | Graph API auth |
| `SENDGRID_API_KEY` | Email delivery |
| `BCRYPT_ROUNDS` | Password hashing cost (default: 12) |
| `ENTITLEMENT_CACHE_TTL` | Feature gate cache (default: 10s) |

### 15.3 Compliance Audit Results (2026-05-08)

```
Discovery Pipeline:    5/5
Security Hardening:    7/7
UI/UX Readiness:       5/5
API Correctness:       3/3
Data Accuracy:         4/4
Onboarding Flow:       4/4
OVERALL:              28/28
```
