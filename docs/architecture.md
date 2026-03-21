# Section 2 -- Architecture

## Platform Architecture

AuditGraph is a multi-tenant SaaS platform with a clear separation between the control plane (organization management, authentication, billing) and the data plane (identity discovery, risk analysis, compliance scoring).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE                                  │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  Admin Portal │  │ Client Portal│  │  API Gateway │  │ Auth      │  │
│  │  (React SPA)  │  │ (React SPA)  │  │  (Flask)     │  │ Service   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └───────────┘  │
│         │                  │                  │                          │
│         └──────────────────┼──────────────────┘                          │
│                            │                                             │
│                     ┌──────▼───────┐                                    │
│                     │   Backend    │                                    │
│                     │   (Flask +   │                                    │
│                     │   Gunicorn)  │                                    │
│                     └──────┬───────┘                                    │
└────────────────────────────┼────────────────────────────────────────────┘
                             │
┌────────────────────────────┼────────────────────────────────────────────┐
│                          DATA PLANE                                     │
│                            │                                            │
│  ┌─────────────────────────▼──────────────────────────────────┐        │
│  │                    Discovery Engine                         │        │
│  │                                                             │        │
│  │  ┌───────────┐    ┌───────────┐    ┌───────────┐          │        │
│  │  │  Azure     │    │  AWS       │    │  GCP       │          │        │
│  │  │  Engine    │    │  Engine    │    │  Engine    │          │        │
│  │  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘          │        │
│  │        │                │                 │                 │        │
│  │  ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐          │        │
│  │  │ Graph API │    │ IAM API   │    │ IAM API   │          │        │
│  │  │ ARM API   │    │ STS API   │    │ CRM API   │          │        │
│  │  └───────────┘    └───────────┘    └───────────┘          │        │
│  └────────────────────────────────────────────────────────────┘        │
│                            │                                            │
│  ┌─────────────────────────▼──────────────────────────────────┐        │
│  │                    Analysis Pipeline                        │        │
│  │                                                             │        │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │        │
│  │  │  Risk     │ │  Drift    │ │ Anomaly  │ │  Attack Path │ │        │
│  │  │  Engine   │ │ Detector  │ │ Detector │ │  Analyzer    │ │        │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘ │        │
│  └────────────────────────────────────────────────────────────┘        │
│                            │                                            │
│  ┌─────────────────────────▼──────────────────────────────────┐        │
│  │                    Data Layer                               │        │
│  │                                                             │        │
│  │  ┌───────────────────────────────────────────────────────┐ │        │
│  │  │  PostgreSQL 15                                         │ │        │
│  │  │  54 tables | Row Level Security | Connection Pooling   │ │        │
│  │  └───────────────────────────────────────────────────────┘ │        │
│  └────────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### Frontend

Two separate React single-page applications serve different audiences:

| Portal | URL | Purpose | Authentication |
|--------|-----|---------|----------------|
| **Client Portal** | `app.auditgraph.ai` | Identity security operations for customers | Client JWT (60-min TTL) |
| **Admin Portal** | `admin.auditgraph.ai` | Platform management for AuditGraph operators | Admin JWT (30-min TTL) |

Both portals are built with React, TypeScript, and Tailwind CSS. They are served as static assets by nginx (Alpine Linux). In production, the API URL is baked into the build at compile time. There is no runtime proxy; the frontend calls the API directly.

### Backend

The backend is a Python Flask application served by Gunicorn with 2 workers and the `--preload` flag. All API endpoints are registered on a single Flask application instance.

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Web Framework** | Flask 3.x | HTTP request handling, routing, middleware |
| **WSGI Server** | Gunicorn | Production-grade process management |
| **Scheduler** | APScheduler | Cron-based discovery runs and maintenance jobs |
| **Database** | PostgreSQL 15 | Primary data store with Row Level Security |
| **ORM** | Raw SQL (psycopg2) | Direct SQL for performance and RLS control |

### Database

PostgreSQL 15 with 54 tables, 44 of which enforce Row Level Security through strict policies. The database uses dual connection users:

- **`auditgraph_app`** (NOBYPASSRLS): Used for all tenant-scoped operations. RLS policies filter every query by `organization_id`.
- **`auditgraph_admin`** (BYPASSRLS): Used for DDL, cross-tenant operations, and system maintenance.

---

## Identity Discovery Pipeline

The discovery pipeline is the core data collection system. It executes per-connector and produces a complete snapshot of identities, entitlements, and resources.

```
┌───────────────────────────────────────────────────────────────┐
│  TRIGGER                                                      │
│  ├── Scheduled (APScheduler, every 12 hours)                  │
│  ├── Manual (POST /api/runs/trigger)                          │
│  └── Continuous (every 5 minutes, per-connection interval)    │
└───────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────┐
│  ORCHESTRATION (Scheduler)                                    │
│                                                               │
│  FOR EACH enabled organization:                               │
│    FOR EACH connected cloud_connection:                        │
│      1. Create snapshot_job (status: running)                 │
│      2. Decrypt connector credentials                         │
│      3. Instantiate cloud-specific engine                     │
│      4. Execute discovery with circuit breaker protection     │
│      5. Complete snapshot_job (status: completed/failed)      │
└───────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────┐
│  CLOUD DISCOVERY (Engine)                                     │
│                                                               │
│  Azure Engine (21 stages):                                    │
│    ┌──────────────────────────────────────────────────┐       │
│    │ 1. Role Assignments (ARM API)                    │       │
│    │ 2. Entra Directory Roles (Graph API)             │       │
│    │ 3. Service Principals (Graph API, paginated)     │       │
│    │ 4. SPN Credentials (secrets, certs, federated)   │       │
│    │ 5. Graph API Permissions (dangerous perm check)  │       │
│    │ 6. Application Roles                             │       │
│    │ 7. Ownership Discovery                           │       │
│    │ 8. PIM Eligible Assignments                      │       │
│    │ 9. Conditional Access Policies                   │       │
│    │ 10. Human Users with Roles                       │       │
│    │ 11. Managed Identities                           │       │
│    │ 12. Risk Calculation                             │       │
│    │ 13. Credential Expiration Check                  │       │
│    │ 14. Activity Status Check                        │       │
│    │ 15. Storage Account Discovery                    │       │
│    │ 16. Key Vault Discovery                          │       │
│    │ 17. App Registration Discovery                   │       │
│    │ 18. P2 Telemetry Ingestion (if enabled)          │       │
│    │ 19. Workload Exposure Scoring                    │       │
│    │ 20. Behavioral Anomaly Detection                 │       │
│    │ 21. Subscription Sync                            │       │
│    └──────────────────────────────────────────────────┘       │
│                                                               │
│  AWS Engine (4 stages):                                       │
│    ┌──────────────────────────────────────────────────┐       │
│    │ 1. IAM Users + Access Keys                       │       │
│    │ 2. IAM Roles + Trust Relationships               │       │
│    │ 3. Policy Analysis (dangerous actions)            │       │
│    │ 4. Activity Tracking (key last-used)              │       │
│    └──────────────────────────────────────────────────┘       │
│                                                               │
│  GCP Engine (4 stages):                                       │
│    ┌──────────────────────────────────────────────────┐       │
│    │ 1. Service Accounts + Keys                       │       │
│    │ 2. IAM Bindings (project-level)                  │       │
│    │ 3. Permission Analysis                           │       │
│    │ 4. Risk Calculation                              │       │
│    └──────────────────────────────────────────────────┘       │
└───────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────┐
│  POST-DISCOVERY PIPELINE                                      │
│                                                               │
│  Executed after each connector discovery completes:           │
│                                                               │
│  1. Drift Detection                                           │
│     Compare current snapshot with previous run                │
│     Detect: new roles, removed roles, credential changes      │
│     Persist drift_report                                      │
│                                                               │
│  2. Anomaly Detection (6 anomaly types)                       │
│     permission_escalation, risk_score_spike,                  │
│     dormant_reactivation, credential_surge,                   │
│     off_hours_pim, excessive_pim_usage                        │
│                                                               │
│  3. Risk Summary Computation (AGIRS)                          │
│     HIRI + NHIRI + GEI → composite AGIRS score                │
│     Persist to risk_summary table                             │
│                                                               │
│  4. Notification Dispatch                                     │
│     Email, Slack, Teams notifications (if configured)         │
│                                                               │
│  5. SOAR Playbook Evaluation                                  │
│     Execute matching playbooks for anomalies and drift        │
└───────────────────────────────────────────────────────────────┘
```

---

## Connector Architecture

Each cloud connector represents a cloud boundary. Connectors are isolated at the database level through the `cloud_connections` table, and every discovery run is linked to exactly one connector.

```
Organization (org_id=7)
│
├── Azure Connector (conn_id=1, azure_directory_id="abc-123")
│   ├── Discovery Run #101 (2026-03-15 00:00)
│   │   ├── 245 identities
│   │   ├── 12 subscriptions
│   │   └── 307 resources
│   └── Discovery Run #108 (2026-03-16 00:00)
│       ├── 248 identities (+3 new, -0 removed)
│       ├── 12 subscriptions
│       └── 312 resources (+5)
│
├── Azure Connector (conn_id=2, azure_directory_id="def-456")
│   └── Discovery Run #102
│       └── 89 identities (separate tenant)
│
├── AWS Connector (conn_id=3, aws_account="123456789012")
│   └── Discovery Run #103
│       └── 34 IAM users + 18 IAM roles
│
└── GCP Connector (conn_id=4, gcp_project="my-project")
    └── Discovery Run #104
        └── 12 service accounts
```

### Connector Isolation Model

Data from different connectors never mixes:

1. **Every `discovery_run`** has a `cloud_connection_id` foreign key
2. **Every `identity`** is linked to a `discovery_run_id`
3. **Queries scope by latest run IDs** per connector using `_latest_run_ids()`
4. **The frontend sends `connection_id`** as a query parameter on every request via the `ConnectionContext`
5. **Row Level Security** enforces organization-level isolation at the database layer

```
┌──────────────────────────────────────────────────────────┐
│  Query Scoping Chain                                     │
│                                                          │
│  Request → Auth Middleware → Set RLS Context (org_id)    │
│         → ConnectionContext → connection_id query param   │
│         → _latest_run_ids(org_id, connection_id)         │
│         → discovery_run_id IN (latest_runs)              │
│         → Identities scoped to specific connector        │
└──────────────────────────────────────────────────────────┘
```

---

## Risk Computation Engine

The risk engine computes scores at two levels: per-identity and per-organization.

### Per-Identity Risk Scoring

Each identity receives a risk score (0-100) based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Privilege Tier | High | T0 identities score higher than T3 |
| Activity Status | High | Stale or never-used identities are riskier |
| Credential Health | Medium | Expired or expiring credentials increase risk |
| Ownership Status | Medium | Ownerless service principals score higher |
| Permission Scope | Medium | Tenant-wide access scores higher than resource-level |
| External Exposure | Low | Guest accounts with privileged roles |

### Organization-Level Scoring (AGIRS)

The AGIRS (AuditGraph Identity Risk Score) is a composite organizational score:

```
AGIRS = 0.40 × HIRI + 0.40 × NHIRI + 0.20 × GEI

Where:
  HIRI  = Human Identity Risk Index (0-100)
  NHIRI = Non-Human Identity Risk Index (0-100)
  GEI   = Governance Effectiveness Index (0-100)
```

See [Risk Scoring Model](risk-scoring.md) for detailed calculations.

---

## Access Graph Model

AuditGraph builds a directed graph for each identity showing its effective access.

### Node Types

The access graph uses 13 node types:

| Node Type | Description |
|-----------|-------------|
| `identity` | The identity being analyzed |
| `risk_summary` | Aggregated risk score and factors |
| `blast_radius` | Impact assessment summary |
| `owner` | Identity that owns this identity |
| `federated_trust` | External trust relationship |
| `role` | Azure RBAC or Entra directory role |
| `permission` | Microsoft Graph API permission |
| `credential` | Secret, certificate, or federated credential |
| `scope` | Generic access scope |
| `subscription` | Azure subscription |
| `resource_group` | Azure resource group |
| `resource` | Specific cloud resource (Key Vault, Storage Account) |
| `entra_directory` | Entra ID directory role scope |

### Graph Modes

The graph supports two visualization modes:

**Executive Mode**: Summarized view showing blast radius, risk factors, and high-level access scope. Designed for security leaders who need quick impact assessment.

**Technical Mode**: Full hierarchical ARM tree showing Identity -> Subscription -> Resource Group -> Resource with role badges at each level. Entra directory roles appear in a separate branch. Designed for engineers and auditors performing detailed access review.

```
Technical Mode Layout:

┌──────────┐
│ Identity  │
└────┬─────┘
     │
     ├────────────────────────────────────────────┐
     │                                            │
     ▼                                            ▼
┌──────────────┐                           ┌──────────────┐
│ Subscription │                           │ Entra Dir    │
│ (prod-sub)   │                           │ (Global      │
│ [Owner]      │                           │  Admin)      │
└──────┬───────┘                           └──────────────┘
       │
       ├──────────────────┐
       ▼                  ▼
┌──────────────┐   ┌──────────────┐
│ Resource Grp │   │ Resource Grp │
│ (prod-rg)    │   │ (data-rg)    │
│ [Contributor]│   └──────┬───────┘
└──────────────┘          │
                          ▼
                   ┌──────────────┐
                   │ Key Vault    │
                   │ (prod-kv)    │
                   │ [Get,List]   │
                   └──────────────┘
```

---

## Data Model

### Core Tables

| Table | Purpose | RLS | Key Columns |
|-------|---------|-----|-------------|
| `organizations` | Tenant/organization registry | No (public) | id, name, slug, plan, enabled |
| `users` | User accounts | Yes | id, username, role, organization_id |
| `cloud_connections` | Cloud connectors | Yes | id, organization_id, cloud, status, metadata |
| `discovery_runs` | Discovery run records | Yes | id, organization_id, cloud_connection_id, status |
| `identities` | Discovered identities | Yes | id, discovery_run_id, identity_id, display_name, risk_score |
| `risk_summary` | AGIRS scores per run | Yes | id, organization_id, agirs_score, hiri_score, nhiri_score, gei_score |
| `drift_reports` | Drift detection results | Yes | id, organization_id, changes (JSONB) |
| `anomalies` | Detected anomalies | Yes | id, organization_id, type, severity, identity_id |
| `remediation_actions` | Remediation tracking | Yes | id, organization_id, status, action_type |

### Key Relationships

```
organizations (1) ──── (*) cloud_connections
cloud_connections (1) ──── (*) discovery_runs
discovery_runs (1) ──── (*) identities
identities (1) ──── (*) pim_eligible_assignments
identities (1) ──── (*) identity_subscription_access
organizations (1) ──── (*) risk_summary
organizations (1) ──── (*) drift_reports
organizations (1) ──── (*) anomalies
```

---

## Scalability

### Connection Pooling

The backend uses `ThreadedConnectionPool` (psycopg2) with configurable pool sizes:

| Pool | Min | Max | Purpose |
|------|-----|-----|---------|
| App Pool | `DB_POOL_MIN` (default 2) | `DB_POOL_MAX` (default 20) | Tenant-scoped queries |
| Admin Pool | 1 | `DB_POOL_MAX / 4` | DDL and cross-tenant operations |

### Discovery Scaling

Discovery runs execute per-connector with heartbeat monitoring. The scheduler detects zombie jobs (stale heartbeats) and enforces runtime limits. Failed jobs are automatically retried.

### Scan Modes

Three scan modes balance thoroughness against speed:

| Mode | Stages | Duration | Use Case |
|------|--------|----------|----------|
| **Quick** | Identities, basic roles | ~1-2 minutes | Rapid check, lightweight |
| **Standard** | + Credentials, permissions | ~3-5 minutes | Recommended daily scan |
| **Deep** | + PIM, CA policies, resources, app registrations | ~5-15 minutes | Full audit |

---

## References

- [Security Architecture](security-architecture.md) -- Authentication, RBAC, and tenant isolation
- [Discovery Engine](discovery-engine.md) -- Detailed discovery pipeline documentation
- [Risk Scoring Model](risk-scoring.md) -- AGIRS calculation methodology
- [Operations](operations.md) -- Deployment and configuration
