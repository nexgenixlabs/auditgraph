# AuditGraph Platform — Codebase Design Document
## Week 11 Review (February 2026)

### 1. Platform Overview
AuditGraph is a multi-tenant SaaS identity security posture management (ISPM) platform for Azure/Entra ID environments. It discovers, analyzes, and remediates identity risks across cloud environments.

- **Frontend**: React 19 + TypeScript, Tailwind CSS, React Router v6, @xyflow/react v12, Recharts, jsPDF
- **Backend**: Python 3.11 Flask, PostgreSQL 16 with Row-Level Security (RLS), APScheduler
- **Cloud SDKs**: Azure Identity, Azure Resource Management, Microsoft Graph API (msgraph-sdk)
- **Deployment**: Azure Container Apps, ACR (linux/amd64), GitHub Actions CI/CD
- **Auth**: JWT (PyJWT) + bcrypt, SAML 2.0 SSO (python3-saml), API Keys (ag_ prefix)

### 2. Architecture Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────┐
│                    FRONTEND (React + TypeScript)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Overview  │ │Dashboard │ │Identities│ │  Admin   │   ...38  │
│  │   Page    │ │ (6 tabs) │ │ (Table)  │ │ Console  │   pages  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────────────────────────────────────────────┐          │
│  │ AuthContext (JWT) │ TenantContext │ TopBar+Sidebar│          │
│  └──────────────────────────────────────────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│                    BACKEND (Flask + Python 3.11)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │  Auth     │ │ Handlers │ │Scheduler │ │ Services │          │
│  │Middleware │ │(~180 fns)│ │(3 jobs)  │ │(Email,   │          │
│  │  (JWT/    │ │ 203      │ │Discovery │ │ SOAR,    │          │
│  │  API Key) │ │ routes   │ │Report    │ │ Copilot, │          │
│  └──────────┘ └──────────┘ │Retention │ │ Notif.)  │          │
│                             └──────────┘ └──────────┘          │
│  ┌──────────────────────────────────────────────────┐          │
│  │ Azure Discovery Engine (ARM + Graph + PIM + CA)  │          │
│  │ Anomaly Detector (6 types) │ SOAR Engine          │          │
│  │ Drift Detector │ Risk Rule Engine │ Role Mining    │          │
│  └──────────────────────────────────────────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│                    DATABASE (PostgreSQL 16)                       │
│  40+ tables │ RLS on 43 tables │ 16 migration files             │
│  7 seed methods │ Tenant isolation via set_config()              │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Key Statistics
- **Backend**: ~25,000 lines of Python across 15+ files
  - `database.py`: 7,725 lines (40+ tables, CRUD, seeds, RLS)
  - `handlers.py`: ~12,940 lines (~180 handler functions)
  - `main.py`: ~500 lines (203 route registrations)
  - `azure_discovery.py`: ~2,500 lines (full Azure discovery engine)
  - `scheduler.py`: ~400 lines (3 scheduled jobs + post-discovery pipeline)
- **Frontend**: ~30,000 lines of TypeScript/React across 80+ files
  - 38+ pages (Overview, Dashboard, Identities, IdentityDetail, Settings, etc.)
  - 20+ dashboard widgets (self-fetching pattern)
  - 13 custom ReactFlow graph node types
  - 3 PDF generators (full audit, executive, SPN privilege)
- **Database**: 40+ tables, 43 with RLS policies, 16 SQL migration files
- **API**: 203 route registrations, ~155 unique paths, ~13 public endpoints
- **Completed Phases**: 85+ feature phases implemented

### 4. Multi-Tenant Architecture
- PostgreSQL RLS (Row-Level Security) on 43 tables
- `set_config('app.current_tenant_id', value, FALSE)` session variable
- JWT includes tenant_id, tenant_name, is_superadmin
- `X-Tenant-Id` header override for superadmins
- `_tenant_id()` helper in handlers extracts tenant context
- NULL tenant context = superadmin bypass (sees all data)

### 5. Authentication Model
- **Client Portal**: JWT with 4 roles (admin, security_admin, compliance, reader)
- **Admin Portal**: 4 portal roles (superadmin, poweradmin, billing, reader)
- **API Keys**: `ag_` prefix + 32 hex chars, SHA-256 hashed, role-scoped
- **SSO/SAML**: python3-saml, JIT user provisioning, IdP group→role mapping
- **Token Flow**: Access token (24h) + Refresh token (7 days, opaque, hashed in DB)

### 6. Discovery Pipeline
1. Scheduler triggers per-tenant discovery (configurable: 6/12/24 hours)
2. Azure Discovery Engine runs: subscriptions → RBAC roles → Entra roles → SPNs → credentials → permissions → app roles → ownership → PIM → CA policies → storage accounts → key vaults → app registrations
3. V2 structured risk scoring (7 categories, 0-900+ points, severity multipliers)
4. Post-discovery pipeline: drift detection → email → SOAR triggers → webhooks → notifications → anomaly detection → compliance snapshots

### 7. Deployment Architecture
- **Backend Container**: `auditgraph-api` on Azure Container Apps (gunicorn, 2 workers, --preload)
- **Frontend Container**: `auditgraph-web` on Azure Container Apps (nginx:alpine, static SPA)
- **Database**: Azure Database for PostgreSQL (Flexible Server, require SSL)
- **CI/CD**: GitHub Actions → ACR build → Container Apps deploy on push to main
- **Domains**: api.auditgraph.ai (backend), app.auditgraph.ai + admin.auditgraph.ai (frontend)

### 8. File Structure Overview

```
auditgraph/
├── backend/
│   ├── app/
│   │   ├── main.py              # Flask app factory, 203 routes
│   │   ├── database.py          # 7725-line DB layer (40+ tables)
│   │   ├── scheduler.py         # APScheduler (3 jobs)
│   │   ├── metrics.py           # MetricsCollector singleton
│   │   ├── wsgi.py              # WSGI entry point
│   │   ├── api/
│   │   │   ├── handlers.py      # ~180 handler functions
│   │   │   ├── auth.py          # JWT middleware + decorators
│   │   │   └── saml.py          # SAML SSO helper
│   │   ├── engines/
│   │   │   ├── discovery/
│   │   │   │   ├── azure_discovery.py  # Full Azure engine
│   │   │   │   ├── aws_discovery.py    # Stub
│   │   │   │   ├── gcp_discovery.py    # Stub
│   │   │   │   ├── base.py             # ABC interface
│   │   │   │   └── models.py           # Identity/Risk models
│   │   │   ├── drift_detector.py
│   │   │   ├── anomaly_detector.py
│   │   │   ├── soar_engine.py
│   │   │   ├── risk_rule_engine.py
│   │   │   ├── risk_catalog.py
│   │   │   └── role_mining_engine.py
│   │   └── services/
│   │       ├── email_service.py
│   │       ├── notification_dispatcher.py
│   │       ├── copilot_service.py
│   │       ├── notification_service.py
│   │       └── webhook_service.py
│   ├── migrations/          # 16 SQL files
│   ├── Dockerfile           # python:3.11-slim + gunicorn
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx          # Router + layout
│   │   ├── pages/           # 38+ page components
│   │   ├── components/      # Shared components
│   │   │   ├── dashboard/   # 20+ widgets
│   │   │   ├── graph/       # ReactFlow (13 node types)
│   │   │   ├── layout/      # TopBar, Sidebar
│   │   │   └── overview/    # Overview sub-components
│   │   ├── contexts/        # AuthContext, TenantContext
│   │   ├── constants/       # metrics.ts, pricing.ts, design.ts
│   │   ├── hooks/           # useTheme, useDashboardPreferences
│   │   └── utils/           # pdfGenerator, exportUtils, etc.
│   ├── Dockerfile           # node:20-alpine → nginx:alpine
│   ├── nginx.prod.conf      # Production nginx (static only)
│   └── nginx.conf           # Dev nginx (with backend proxy)
├── docker-compose.yml       # Local dev compose
└── .github/workflows/
    └── deploy.yml           # CI/CD pipeline
```

### 9. What's Missing / Known Gaps
1. **No connection pooling** — Each Database() opens a fresh psycopg2 connection (no pgBouncer/pool)
2. **No migration framework** — DDL via _ensure_* methods + standalone SQL files (no Alembic)
3. **AWS/GCP discovery** — Stub implementations only (NotImplementedError)
4. **No container non-root user** — Both Dockerfiles run as root
5. **No nginx security headers** — Missing X-Frame-Options, CSP, HSTS in nginx.prod.conf
6. **No rollback strategy** — CI/CD deploys with no automatic rollback on health check failure
7. **No staging environment** — Direct deploy to production on push to main
8. **Large monolithic files** — handlers.py (12,940 lines), database.py (7,725 lines), Settings.tsx (2,000+ lines)
9. **XSS risk in CopilotPanel** — dangerouslySetInnerHTML for markdown rendering
10. **No streaming for Copilot** — Blocking API call, could timeout on long responses
11. **In-memory metrics** — MetricsCollector not shared across gunicorn workers
12. **Email hardcoded addresses** — Default from/to emails are NexgenixLabs-specific
13. **No rate limiting** — No API-level rate limiting (only 5-min throttle on Slack/Teams notifications)
14. **Tenant SPN discovery gap** — Authenticated SPN may not appear in its own tenant's identity list (under investigation)
