# AuditGraph

**Identity Security Graph for Human, Non-Human, and AI Identities.**

Agentless · read-only · architecture-derived.

## Overview

AuditGraph is the Identity Security Graph platform: the only product that maps the full lineage from **Human → Non-Human → AI Agent → Model → Classified Data** in a single graph, derived from your tenant's architecture without write access, agents, or runtime telemetry.

Most identity products see `User → Role → Resource`. AuditGraph sees `Human → SPN → MI → AI Agent → Model → PHI`, all connected, all from architecture. No competitor surfaces the full chain end-to-end today.

### What we replace
- **SailPoint / Saviynt** for human identity governance
- **Microsoft Entra ID Governance** for cross-cloud identity hygiene
- **Astrix / Entro / Oasis** for NHI security (we cover more identity types with less access)
- **AI security tools** for the AI-as-NHI subset

### Key Features

- **Identity Discovery**: Automatically discover all identity types in your Azure tenant
  - Service Principals (customer-owned applications)

### Key Features

- **Identity Discovery**: Automatically discover all identity types in your Azure tenant
  - Service Principals (customer-owned applications)
  - Managed Identities (System-assigned & User-assigned)
  - Human Users with Azure RBAC or Entra ID roles
  - Guest accounts
  - Microsoft Internal services (for visibility)

- **Risk Assessment**: Points-based risk scoring with multiple factors:
  - Azure RBAC role assignments (Owner, Contributor, User Access Administrator)
  - Entra ID directory roles (Global Administrator, Application Administrator)
  - Microsoft Graph API permissions (Mail.ReadWrite, Directory.ReadWrite.All)
  - Credential status, age, and expiration
  - Activity status (dormant identity + active secret = critical)
  - Ownership accountability

- **Privilege Tier Classification**: Identity tiering based on role criticality:
  - **T0 Control Plane** — Global Admin, Privileged Role Admin, tenant-wide Owner
  - **T1 Management Plane** — User Admin, Exchange Admin, subscription Owner/Contributor
  - **T2 Data/App Plane** — Scoped RBAC roles, risky Graph API permissions
  - **T3 Standard** — No privileged roles

- **Trust Relationship Mapping**: Identify who can act as, manage, or escalate an identity:
  - Federated credential trusts (GitHub Actions, Azure AD, Google Cloud, AWS EKS)
  - Ownership edges (who manages this service principal)
  - Role-based trust chains

- **Effective Scope & Blast Radius**: Visualize what an identity can impact:
  - ARM scope hierarchy parsing (subscription > resource group > resource)
  - Entra directory scope analysis
  - Blast radius computation (subscription count, RG count, resource count)

- **Secret Exposure Intelligence**: Credential hygiene beyond count/expiry:
  - Age analysis (never rotated flags for secrets >365 days)
  - Cross-referencing: dormant identity + active secret = critical exposure
  - Privileged identity + long-lived secret = high exposure
  - Federated trust to external CI/CD + privileged roles = high exposure

- **GRC Compliance Scoring**: Framework-level compliance assessment:
  - **SOC 2** — CC6.1 (Logical Access), CC6.3 (Role-Based Access)
  - **HIPAA** — Section 164.312 (Access Controls), violation mappings per role
  - **PCI-DSS** — Requirement 7/8 (Privileged Access Control)
  - **NIST 800-53** — AC-6 (Least Privilege), IA-5 (Authenticator Management)

- **Role Intelligence**: Per-role security context:
  - Real-world attack pattern mappings (company, year, estimated cost)
  - HIPAA violation mappings with penalty ranges
  - Role usage status inference (active, likely unused, orphaned, over-privileged)

- **Interactive Access Graph**: Dual-mode graph visualization per identity:
  - Executive Risk Story — simplified 3-5 node view for stakeholder communication
  - Technical Trust Graph — full relationship graph with all role/scope/credential edges
  - Powered by @xyflow/react with pan/zoom/minimap

- **PIM (Privileged Identity Management) Tracking**: JIT access governance monitoring
  - Eligible role discovery via roleEligibilityScheduleInstances
  - Active activation tracking with justification and ticket integration
  - Overuse metrics: activation frequency, total active hours, always-active pattern detection
  - PIM badge on Identities table, dedicated PIM tab on Identity Detail

- **Conditional Access Monitoring**: Policy coverage and MFA enforcement analysis
  - Automatic policy discovery via Graph API (Policy.Read.All)
  - Per-identity coverage computation (covered / excluded / no coverage)
  - MFA enforcement status per identity
  - Weak policy detection: disabled policies, legacy auth, missing MFA
  - Dashboard widget with coverage percentage and policy risk flags
  - Shield icon on Identities table (green=MFA, yellow=no MFA, red=excluded)

- **Scheduled Discovery & Change Alerts**: Automated monitoring with email notifications
  - Configurable discovery interval (6, 12, or 24 hours)
  - Email alerts when identities are added or removed
  - Summary table showing category changes (Before | After | Change)

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Frontend                               │
│  React 19 + TypeScript + Tailwind CSS + React Router          │
│  @xyflow/react (graph viz) + jsPDF (PDF export)              │
│  Port 3000 → proxies /api to backend :5001                   │
├──────────────────────────────────────────────────────────────┤
│                        Backend                                │
│  Python Flask + Flask-CORS                                    │
│  Microsoft Graph SDK + Azure Identity SDK                     │
│  Port 5001                                                    │
├──────────────────────────────────────────────────────────────┤
│                        Database                               │
│  PostgreSQL — 18 tables                                       │
│  identities, role_assignments, entra_role_assignments,        │
│  credentials, sp_ownership, graph_api_permissions,            │
│  app_role_assignments, discovery_runs, risk_scores, ...       │
└──────────────────────────────────────────────────────────────┘
```

## UI Pages

### Overview (`/`)

- Global Risk Cards — total identities, critical/high/medium counts
- Cloud Comparison — Azure identity breakdown (AWS/GCP ready)
- Privilege Tier Distribution — T0-T3 bar chart with named T0/T1 identities
- Action Items — dormant privileged count, expiring credentials, unowned SPNs
- Recommendations — prioritized items with deep-links to filtered Identities page

### Dashboard (`/dashboard`)

- Posture Score — weighted security posture (0-100) with trend comparison
- Credential Health — valid/expiring/expired donut chart
- Quick Actions — real-time counts for dormant, expiring, unowned
- Risk Heat Map — identity category vs risk level matrix
- Risk Donut Chart — risk level distribution
- GRC Compliance Scorecard — SOC 2, HIPAA, PCI-DSS, NIST 800-53 controls
- Conditional Access Card — policy coverage %, MFA enforcement, weak policy flags

### Identities (`/identities`)

- 14-column sortable table with checkbox selection
- Columns: Name, Type, Category, Cloud, Risk, Entra Roles, RBAC Roles, Graph API, Tier, Secret/Expiry, Created, Last Used, Activity, Compliance
- Filters: risk level, category, search text
- URL-driven filters: `owner_status`, `activity_status`, `privilege_tier` (from recommendation deep-links)
- Dismissible filter chips when URL-driven filters are active
- CSV and PDF export

### Identity Detail (`/identities/:id`)

8-tab layout:

| Tab | Content |
|-----|---------|
| **Overview** | Quick stats, activity status, risk reasons, CA coverage badges |
| **Roles** | Azure RBAC + Entra roles with usage status, risk badges, compliance cross-links |
| **Permissions** | Graph API permissions + app role assignments |
| **Credentials** | Credential count, status, next expiration |
| **Ownership** | Owner listing with primary owner badge |
| **Access Graph** | Dual-mode interactive graph + trust/scope/exposure detail panels (with hover tooltips) |
| **PIM** | Eligible roles, activation history with justification/ticket, overuse metrics |
| **Compliance** | GRC framework relevance, per-role attack patterns, HIPAA violation mappings |

## Identity Categories

| Category | Key | Description |
|----------|-----|-------------|
| Service Principal | `service_principal` | Customer-owned Azure AD applications |
| System Assigned MI | `managed_identity_system` | Managed identities bound to Azure resource lifecycle |
| User Assigned MI | `managed_identity_user` | Standalone managed identities for flexible assignment |
| Human User | `human_user` | Users with Azure RBAC or Entra directory roles |
| Guest | `guest` | External/guest user accounts |
| Microsoft Internal | `microsoft_internal` | Microsoft first-party services (informational) |

## Activity Status

| Status | Meaning | Badge Color |
|--------|---------|-------------|
| `active` | Sign-in within last 30 days | Green — Active |
| `inactive` | Sign-in 30-90 days ago | Yellow — Idle 30-90d |
| `stale` | No sign-in for 90+ days | Red — Stale 90d+ |
| `never_used` | Created >30 days ago, never signed in | Orange — Never Used |
| `recently_created` | Created <30 days ago, no sign-in yet | Blue — New |
| `unknown` | No sign-in data available (requires Azure AD P1/P2) | Gray dash |

## Onboarding a New Tenant / Subscription

Follow these steps to onboard a new Azure tenant or add a subscription for identity discovery.

### Step 1: Create an Azure Service Principal

Register an app in Entra ID (Azure AD) for AuditGraph to read identity data.

```bash
# Create the service principal
az ad sp create-for-rbac --name "AuditGraph-Reader" --role Reader \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

Save the output — you'll need `appId`, `password`, and `tenant`.

### Step 2: Grant Microsoft Graph API Permissions

The service principal needs read-only Graph API permissions. In the Azure Portal:

1. Go to **Entra ID** > **App registrations** > **AuditGraph-Reader**
2. Click **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**
3. Add these permissions:

| Permission | Purpose | Required |
|-----------|---------|----------|
| `Directory.Read.All` | Read all identities, roles, group memberships | Yes |
| `Application.Read.All` | Read service principals, credentials, ownership | Yes |
| `RoleManagement.Read.Directory` | Read Entra role assignments + PIM eligible roles | Yes |
| `Policy.Read.All` | Read Conditional Access policies | Yes |
| `AuditLog.Read.All` | Read sign-in activity (last sign-in timestamps) | Yes |
| `Mail.Send` | Send email change notifications (optional) | No |

4. Click **Grant admin consent** for the tenant

### Step 3: Assign Azure RBAC Reader Role

The service principal needs Reader access on each subscription you want to monitor:

```bash
# Grant Reader on a subscription
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>

# For multiple subscriptions, repeat for each:
az role assignment create \
  --assignee <APP_ID> \
  --role "Reader" \
  --scope /subscriptions/<SECOND_SUBSCRIPTION_ID>
```

> **Note**: AuditGraph discovers RBAC role assignments using `az role assignment list --all`, which returns roles across **all subscriptions** the service principal has access to. To monitor additional subscriptions, just grant Reader on them — no code changes needed.

### Step 4: Configure Environment

Create `backend/.env.local`:

```env
# Azure Service Principal
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=your-primary-subscription-id

# PostgreSQL Database
DB_HOST=your-db-host
DB_PORT=5432
DB_NAME=auditgraph
DB_USER=your-db-user
DB_PASSWORD=your-db-password
DB_SSLMODE=require

# Email Notifications (optional)
EMAIL_FROM=sender@yourdomain.com
EMAIL_TO=security-team@yourdomain.com

# Scheduler Configuration
DISCOVERY_INTERVAL_HOURS=12  # Options: 6, 12, or 24
```

### Step 5: Run Database Migrations

```bash
cd backend

# Run all migrations in order
for f in migrations/*.sql; do
  echo "Running $f..."
  PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
    --set=sslmode=require -f "$f"
done
```

### Step 6: Start AuditGraph

```bash
# Backend (starts scheduler automatically)
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m app.main
# → API at http://localhost:5001
# → Scheduler runs discovery every 12h (configurable)

# Frontend
cd frontend
npm install
npm start
# → UI at http://localhost:3000
```

### Step 7: Trigger First Discovery

Discovery runs automatically on schedule, but you can trigger it immediately:

- **UI**: Click the **"Run Discovery"** button on the Dashboard page
- **API**: `POST http://localhost:5001/api/runs/trigger`
- **CLI**: `curl -X POST http://localhost:5001/api/runs/trigger`

Monitor progress at `GET /api/runs`. After completion, refresh the Dashboard to see discovered identities.

### Adding More Subscriptions

To monitor additional subscriptions after initial setup:

1. Grant the service principal **Reader** access on the new subscription (Step 3)
2. Trigger a new discovery run (Step 7)
3. New RBAC role assignments from the added subscription will appear automatically

No environment variable changes or restarts needed — the discovery engine reads roles across all accessible subscriptions.

### Optional: PIM + Conditional Access

| Feature | License Required | Permission |
|---------|-----------------|------------|
| PIM (Privileged Identity Management) | Azure AD P2 | `RoleManagement.Read.Directory` |
| Conditional Access policies | Azure AD P1+ | `Policy.Read.All` |
| Sign-in activity (last sign-in) | Azure AD P1+ | `AuditLog.Read.All` |

If your tenant doesn't have P2, PIM data will be empty (no errors). If CA policies aren't configured, the CA section will show 0 coverage.

---

## Local Development

### Prerequisites

- Python 3.9+
- Node.js 18+
- PostgreSQL database (Azure Postgres Flexible Server or local)
- Azure Service Principal with read permissions (see Onboarding above)

### Backend Setup

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m app.main
# → API at http://localhost:5001 (scheduler starts automatically)
```

### Frontend Setup

```bash
cd frontend
npm install
npm start
# → UI at http://localhost:3000
```

## API Endpoints

### Health & Summary

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/stats` | Latest run summary statistics |
| `GET /api/identity-summary` | Category-level risk breakdown |
| `GET /api/risks` | Critical and high-risk identities |

### Dashboard

| Endpoint | Description |
|----------|-------------|
| `GET /api/dashboard/posture` | Posture score, credential health, dormant counts, trend |
| `GET /api/dashboard/compliance` | GRC compliance scorecard (SOC 2, HIPAA, PCI-DSS, NIST) |
| `GET /api/dashboard/conditional-access` | CA policy coverage, MFA enforcement, weak policy flags |

### Overview

| Endpoint | Description |
|----------|-------------|
| `GET /api/overview/insights` | Tier distribution, action items, dormant privileged, unowned SPNs |

### Identities

| Endpoint | Description |
|----------|-------------|
| `GET /api/identities` | All identities (supports `limit`, `offset`, `cloud`, `risk_level`, `identity_category`, `search`) |
| `GET /api/identities/:id` | Full detail: roles, permissions, app_roles, owners, role_intelligence |
| `GET /api/identities/:id/graph-data` | Access graph: trust relationships, effective scope, secret exposure, pre-computed graph nodes/edges |
| `GET /api/identities/:id/pim` | PIM eligible assignments, activation history, overuse metrics |

### Discovery & Scheduler

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /api/runs` | GET | List discovery runs (last 50) |
| `POST /api/runs/trigger` | POST | Trigger a manual discovery run (returns 202, runs in background) |
| `GET /api/runs/:id/drift` | GET | Get drift report comparing a run to its predecessor |
| `GET /api/scheduler` | GET | Scheduler status, next run time, interval configuration |

## Project Structure

```
auditgraph/
├── backend/
│   └── app/
│       ├── main.py                          # Flask app factory + route registration
│       ├── database.py                      # PostgreSQL connection pool
│       ├── scheduler.py                     # Scheduled discovery + email alerts
│       ├── api/
│       │   └── handlers.py                  # All API endpoint handlers
│       ├── engines/
│       │   └── discovery/
│       │       ├── base.py                  # BaseDiscoveryEngine interface
│       │       ├── azure_discovery.py       # Azure/Entra ID discovery (production)
│       │       ├── aws_discovery.py         # AWS IAM discovery (stub)
│       │       ├── gcp_discovery.py         # GCP IAM discovery (stub)
│       │       ├── activity_tracker.py      # Sign-in activity analysis
│       │       ├── credential_checker.py    # Credential expiry/health checks
│       │       └── models.py               # Identity data models
│       ├── core/                            # Risk scoring engine, classification
│       ├── db/                              # Database schema setup
│       └── services/                        # Business logic services
├── frontend/
│   └── src/
│       ├── App.tsx                          # Router + Overview page (inline)
│       ├── pages/
│       │   ├── Dashboard.tsx                # Stats, posture, compliance, CA card
│       │   ├── Identities.tsx               # 14-col sortable table + CSV/PDF export
│       │   └── IdentityDetail.tsx           # 8-tab detail layout (with PIM tab)
│       └── components/
│           ├── dashboard/
│           │   ├── PostureScore.tsx          # Posture gauge (0-100)
│           │   ├── CredentialHealth.tsx      # Credential donut chart
│           │   ├── QuickActions.tsx          # Action item counts
│           │   ├── ComplianceScorecard.tsx   # GRC framework scores
│           │   ├── RiskHeatMap.tsx           # Category x risk matrix
│           │   ├── RiskDonutChart.tsx        # Risk distribution chart
│           │   └── ConditionalAccessCard.tsx # CA coverage + weak policy flags
│           ├── overview/
│           │   ├── GlobalRiskCards.tsx       # Total/critical/high/medium counts
│           │   ├── CloudComparison.tsx       # Per-cloud identity breakdown
│           │   ├── CategoryRiskGrid.tsx      # Category-level risk grid
│           │   ├── CriticalIdentitiesList.tsx # Named critical identities
│           │   └── InsightsPanel.tsx         # Tier distribution + recommendations
│           └── graph/
│               ├── AccessGraphTab.tsx        # Graph canvas + trust/scope/exposure panels
│               └── nodes.tsx                 # 8 custom ReactFlow node types
└── docs/
    └── weekly/                              # Sprint documentation
```

## Multi-Cloud Support

| Cloud | Status | Discovery Engine |
|-------|--------|-----------------|
| **Azure** | Production | Full Entra ID + RBAC + Graph API + credential + ownership discovery |
| **AWS** | Stub | `aws_discovery.py` — IAM role/policy discovery placeholder |
| **GCP** | Stub | `gcp_discovery.py` — IAM discovery placeholder |

All engines extend `BaseDiscoveryEngine` with `discover()` and `test_connection()` methods.

## Identity Discovery Rules

| Identity Type | Discovery Rule |
|---------------|----------------|
| Service Principals | All discovered (including orphaned with no roles) |
| User Assigned Managed Identities | All discovered (including orphaned) |
| System Assigned Managed Identities | Only with RBAC roles assigned |
| Human Users | Only with Azure RBAC or Entra ID roles |
| Guest Users | Only with roles assigned |
| Microsoft Internal | All discovered (informational only) |

## Security Considerations

- **Least Privilege**: Use a service principal with minimal read-only permissions for discovery
- **Secrets Management**: Never commit `.env.local` or any secrets to version control
- **Network Security**: Deploy backend behind appropriate network controls
- **Data Classification**: Identity data should be treated as sensitive

## Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Frontend** | React 19, TypeScript, Tailwind CSS, React Router, jsPDF, @xyflow/react |
| **Backend** | Python 3.9+, Flask, Flask-CORS, psycopg2 |
| **Database** | PostgreSQL |
| **Cloud APIs** | Microsoft Graph API, Azure Resource Manager, Azure Identity SDK |
| **Scheduler** | APScheduler (discovery + email alerts) |

## License

Proprietary - All rights reserved.

---

Built with security-first principles for enterprise cloud identity management.
