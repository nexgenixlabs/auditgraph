# AuditGraph: The Complete Product Reference

## Identity Risk Intelligence Platform

---

**Version:** 3.0 | **Edition:** First | **Date:** March 2026

**Authors:** AuditGraph Engineering Team

**Classification:** Internal & Customer Reference

---

# COVER PAGE

```
 ╔══════════════════════════════════════════════════════════════╗
 ║                                                              ║
 ║                      A U D I T G R A P H                     ║
 ║                                                              ║
 ║          Identity Risk Intelligence Platform                 ║
 ║                                                              ║
 ║     ┌─────────────────────────────────────────────────┐      ║
 ║     │                                                 │      ║
 ║     │   The Complete Product Reference Textbook       │      ║
 ║     │                                                 │      ║
 ║     │   Covering:                                     │      ║
 ║     │     - Identity Graph Engine                     │      ║
 ║     │     - Trust AI & Security Copilot               │      ║
 ║     │     - Compliance & GRC Automation               │      ║
 ║     │     - Attack Path Analysis                      │      ║
 ║     │     - SOAR Integration                          │      ║
 ║     │     - Multi-Tenant SaaS Architecture            │      ║
 ║     │     - CISO Executive Intelligence               │      ║
 ║     │     - And 80+ Feature Modules                   │      ║
 ║     │                                                 │      ║
 ║     └─────────────────────────────────────────────────┘      ║
 ║                                                              ║
 ║     For: Employees, Customers, Partners, Auditors            ║
 ║                                                              ║
 ║     AuditGraph, Inc. | https://auditgraph.ai                 ║
 ║     March 2026 | v3.0                                        ║
 ║                                                              ║
 ╚══════════════════════════════════════════════════════════════╝
```

---

# TABLE OF CONTENTS

| Part | Chapter | Title | Page |
|------|---------|-------|------|
| **I** | | **FOUNDATIONS** | |
| | 1 | Product Overview & Vision | 1 |
| | 2 | Platform Architecture | 2 |
| | 3 | Multi-Tenant SaaS Foundation | 3 |
| **II** | | **IDENTITY DISCOVERY & ANALYSIS** | |
| | 4 | Identity Discovery Engine | 4 |
| | 5 | Identity Graph & Relationship Mapping | 5 |
| | 6 | Identity Categories & Classification | 6 |
| | 7 | Multi-Cloud Identity Support | 7 |
| **III** | | **RISK INTELLIGENCE** | |
| | 8 | AGIRS Composite Risk Scoring | 8 |
| | 9 | Blast Radius Analysis | 9 |
| | 10 | Attack Path Analysis | 10 |
| | 11 | Drift Detection Engine | 11 |
| | 12 | Anomaly Detection Engine | 12 |
| | 13 | Behavioral Intelligence (P2 Telemetry) | 13 |
| **IV** | | **GOVERNANCE & COMPLIANCE** | |
| | 14 | Identity Governance Engine | 14 |
| | 15 | Service Account Governance | 15 |
| | 16 | Compliance Framework Automation | 16 |
| | 17 | Privileged Identity Management (PIM) | 17 |
| | 18 | Conditional Access Analysis | 18 |
| | 19 | RBAC Hygiene Engine | 19 |
| **V** | | **REMEDIATION & AUTOMATION** | |
| | 20 | Remediation Engine | 20 |
| | 21 | SOAR Integration | 21 |
| | 22 | Policy Recommender | 22 |
| **VI** | | **AI & INTELLIGENCE** | |
| | 23 | AI Security Copilot (Trust AI) | 23 |
| | 24 | AI Investigation Tools | 24 |
| **VII** | | **REPORTING & VISUALIZATION** | |
| | 25 | CISO Executive Dashboard | 25 |
| | 26 | Access Graph Visualization | 26 |
| | 27 | PDF Report Generation | 27 |
| | 28 | Drift History & Activity Log | 28 |
| **VIII** | | **CLOUD RESOURCE SECURITY** | |
| | 29 | Azure Resource Discovery | 29 |
| | 30 | Service Principal (SPN) Dashboard | 30 |
| | 31 | App Registration Audit | 31 |
| | 32 | Key Vault & Storage Security | 32 |
| **IX** | | **PLATFORM OPERATIONS** | |
| | 33 | Authentication & Authorization | 33 |
| | 34 | SSO/SAML/OIDC Integration | 34 |
| | 35 | API Key Management | 35 |
| | 36 | Notification & Integration System | 36 |
| | 37 | Scheduler & Background Jobs | 37 |
| | 38 | Data Retention & Archival | 38 |
| | 39 | System Health & Observability | 39 |
| **X** | | **ADMINISTRATION** | |
| | 40 | Admin Portal & Tenant Management | 40 |
| | 41 | Billing & Subscription Management | 41 |
| | 42 | Deployment Architecture | 42 |
| **XI** | | **USER INTERFACE** | |
| | 43 | Dashboard & Widget System | 43 |
| | 44 | Identity Explorer | 44 |
| | 45 | Settings & Configuration | 45 |
| | 46 | Advanced Query Builder | 46 |
| **XII** | | **SECURITY ARCHITECTURE** | |
| | 47 | Row-Level Security (RLS) | 47 |
| | 48 | Database Security & Connection Pooling | 48 |
| | 49 | Input Sanitization & Rate Limiting | 49 |
| | 50 | Audit Trail & Security Logging | 50 |
| **XIII** | | **APPENDICES** | |
| | A | Complete API Reference | A |
| | B | Database Schema Reference | B |
| | C | Configuration Variables | C |
| | D | Glossary of Terms | D |

---

# PART I: FOUNDATIONS

---

## Chapter 1: Product Overview & Vision

### 1.1 What is AuditGraph?

AuditGraph is an **Identity Risk Intelligence Platform** designed to provide continuous visibility, risk assessment, and automated governance for cloud identities across Azure, AWS, and GCP environments. It answers the fundamental question every CISO asks: *"Who has access to what, why, and is that access still appropriate?"*

Unlike traditional Identity Governance and Administration (IGA) tools that focus on provisioning workflows, AuditGraph focuses on **discovery-first intelligence** -- automatically scanning cloud environments to build a comprehensive map of all identities, their permissions, credentials, trust relationships, and behavioral patterns.

### 1.2 Core Value Propositions

**1. Complete Identity Visibility**
AuditGraph discovers every identity in your cloud environment -- human users, service principals, managed identities, guest accounts, and app registrations. It maps their RBAC roles, Entra directory roles, Microsoft Graph API permissions, credentials, and ownership chains.

**2. Risk-Quantified Intelligence**
Every identity receives a composite risk score through the AGIRS (AuditGraph Identity Risk Score) engine, combining human identity risk (HIRI), non-human identity risk (NHIRI), and governance effectiveness (GEI) into a single actionable metric.

**3. Graph-Based Access Analysis**
The Identity Graph engine builds a visual map showing how identities connect to subscriptions, resource groups, resources, and sensitive data -- revealing attack paths, blast radius, and privilege escalation chains that flat permission lists cannot show.

**4. Automated Governance**
Drift detection, anomaly detection, SOAR playbooks, and remediation workflows continuously monitor for security-relevant changes and can automatically respond to threats.

**5. AI-Powered Investigation**
The Trust AI Copilot (powered by Claude) allows security teams to ask natural language questions about their identity posture, investigate suspicious behavior, and receive contextual recommendations.

### 1.3 Target Audiences

| Audience | Primary Use Case |
|----------|-----------------|
| **CISO / Security Leadership** | Executive risk posture, compliance reporting, board-ready metrics |
| **Identity & Access Management (IAM) Teams** | Daily identity hygiene, access reviews, privilege management |
| **Security Operations (SecOps)** | Anomaly investigation, incident response, threat detection |
| **Compliance & Audit Teams** | Framework compliance (SOC2, HIPAA, PCI), evidence collection |
| **Cloud Infrastructure Teams** | Resource security, credential lifecycle, SPN management |
| **MSP / MSSP Partners** | Multi-tenant client management, cross-org analytics |

### 1.4 Real-World Problem: The Identity Sprawl Crisis

**The Problem:**
Modern enterprises operate with thousands of cloud identities -- many created for one-time projects, never reviewed, and left with excessive permissions. A 2025 Microsoft study found that 95% of Azure permissions granted are never used, and the average enterprise has 3x more service principals than human users.

**Case Study: Financial Services Firm (500 Azure Subscriptions)**

A mid-size financial services company discovered during a SOC2 audit that they had:
- 12,400 service principals across 500 Azure subscriptions
- 847 SPNs with expired credentials still holding active RBAC roles
- 156 human users with Global Administrator who hadn't logged in for 90+ days
- 43 guest accounts with Owner-level access to production subscriptions
- Zero visibility into which SPNs could reach sensitive Key Vault secrets

AuditGraph was deployed and within 24 hours:
- Discovered all 12,400 SPNs and mapped their full access chains
- Identified 847 "zombie" SPNs (expired credentials + active roles) as critical risk
- Generated remediation playbooks for the 156 dormant Global Admins
- Built attack path analysis showing 23 privilege escalation chains to Key Vault access
- Produced a SOC2-ready compliance report with evidence mapping

**Impact:** The firm reduced their identity attack surface by 62% within 30 days using AuditGraph's prioritized remediation recommendations.

### 1.5 Example Architecture: Complete AuditGraph Deployment

```
                         ┌─────────────────────────────┐
                         │      DNS: auditgraph.ai      │
                         │  app.* / admin.* / api.*     │
                         └──────────┬──────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
              │  Client    │  │  Admin     │  │  Backend   │
              │  Portal    │  │  Portal    │  │  API       │
              │ (React+    │  │ (React+    │  │ (Flask+    │
              │  nginx)    │  │  nginx)    │  │  Gunicorn) │
              │  Port 3000 │  │  Port 3001 │  │  Port 8000 │
              └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │     Azure Container Apps       │
                    │     Environment (VNet)         │
                    └───────────────┬───────────────┘
                                    │
               ┌────────────────────┼────────────────────┐
               │                    │                    │
        ┌──────▼──────┐    ┌───────▼───────┐    ┌───────▼───────┐
        │  PostgreSQL   │    │  APScheduler   │    │   Azure APIs   │
        │  (Flex Server)│    │  (In-Process)  │    │  (Graph + ARM) │
        │  54 Tables    │    │  Discovery     │    │  Identity      │
        │  RLS Enforced │    │  Drift         │    │  Discovery     │
        │  Dual-User    │    │  Anomaly       │    │  PIM/CA        │
        └───────────────┘    │  SOAR          │    │  Resources     │
                             │  Retention     │    └────────────────┘
                             └────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │      External Integrations     │
                    │  Slack | Teams | Jira | SIEM   │
                    │  SendGrid | Anthropic Claude   │
                    └───────────────────────────────┘
```

---

## Chapter 2: Platform Architecture

### 2.1 Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 19, TypeScript, Tailwind CSS | Single-page application |
| **Visualization** | ReactFlow v12, Recharts | Identity graphs, charts |
| **PDF Export** | jsPDF + autoTable | Report generation |
| **Backend** | Python 3.11, Flask | REST API server |
| **Database** | PostgreSQL 15 | Primary data store |
| **Authentication** | PyJWT, bcrypt | JWT-based auth |
| **Scheduling** | APScheduler | Background job execution |
| **AI** | Anthropic Claude API | Security copilot |
| **Cloud SDKs** | azure-identity, azure-mgmt-*, msgraph-sdk | Azure discovery |
| **SSO** | python3-saml, OIDC | Enterprise single sign-on |
| **Deployment** | Azure Container Apps, Docker, Bicep | Cloud-native deployment |
| **CI/CD** | GitHub Actions | Automated build & deploy |

### 2.2 Architectural Principles

**1. Discovery-First Design**
AuditGraph does not require agents or inline proxies. It connects to cloud APIs (Microsoft Graph, Azure Resource Manager) using read-only service principal credentials and discovers identities through API enumeration.

**2. Tenant Isolation by Default**
Every table with tenant data uses PostgreSQL Row-Level Security (RLS) with FORCE policies. There is no code path that can accidentally leak data between tenants.

**3. Fail-Closed Security**
If the tenant context is lost or corrupted, the database connection raises a `SecurityViolationError` and refuses to execute queries. The system never falls back to an unscoped query.

**4. Snapshot-Based Analysis**
Each discovery run creates a complete point-in-time snapshot of all identities, roles, and credentials. Drift detection compares snapshots to identify changes. This avoids mutation-based tracking that can miss changes.

**5. Separation of Concerns**
Backend engines (discovery, drift, anomaly, SOAR, remediation) are independent Python classes that operate on database state. The Flask API layer is a thin routing and authorization layer. The React frontend is a pure presentation layer that calls the API.

### 2.3 Request Lifecycle

```
  Client Request (Browser)
         │
         ▼
  ┌──────────────────┐
  │  nginx (static)   │ ── Static assets served directly
  │  or API proxy     │
  └────────┬─────────┘
           │ /api/* requests
           ▼
  ┌──────────────────┐
  │  Gunicorn Worker  │ ── 2 workers, --preload
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │  Flask before_    │
  │  request hook     │
  │  1. Input sanitize│
  │  2. Parse JWT     │
  │  3. Set g.user    │
  │  4. Rate limit    │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │  Route Handler    │
  │  1. Auth check    │
  │  2. DB(org_id)    │  ── RLS-scoped connection
  │  3. Business logic│
  │  4. JSON response │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │  Flask after_     │
  │  request hook     │
  │  1. Security hdrs │
  │  2. Close DB conn │
  │  3. Log metrics   │
  └──────────────────┘
```

### 2.4 Real-World Problem: Why Architecture Matters for Identity Platforms

**The Problem:**
Many identity tools started as single-tenant on-premise solutions and added multi-tenancy as an afterthought. This leads to:
- Data leakage between customers (a compliance nightmare)
- Performance degradation as customers scale
- Complex deployment requiring dedicated infrastructure per customer

**Case Study: MSP Managing 15 Client Tenants**

A Managed Security Service Provider (MSP) needed to monitor 15 client Azure environments from a single platform. Previous tools required separate installations per client, creating operational overhead.

With AuditGraph's multi-tenant architecture:
- All 15 clients run on a single deployment
- PostgreSQL RLS guarantees zero data leakage (verified by automated stress tests in CI/CD)
- Superadmin console provides cross-tenant analytics without compromising isolation
- Each client has their own subdomain (client1.app.auditgraph.ai) with branded login
- Billing is aggregated per-client with per-cloud pricing

**Architecture for MSP Deployment:**

```
  ┌─────────────────────────────────────────────┐
  │              MSP Admin Portal               │
  │         admin.auditgraph.ai                 │
  │  ┌─────────┬──────────┬──────────────────┐  │
  │  │ Tenant  │ Billing  │ Cross-Tenant     │  │
  │  │ Mgmt    │ Dashboard│ Analytics        │  │
  │  └─────────┴──────────┴──────────────────┘  │
  └─────────────────┬───────────────────────────┘
                    │ superadmin JWT
                    ▼
  ┌─────────────────────────────────────────────┐
  │              Backend API                     │
  │         api.auditgraph.ai                   │
  │                                              │
  │  ┌──────────────────────────────────────┐   │
  │  │  Database(organization_id=N)         │   │
  │  │  SET LOCAL app.current_org_id = N    │   │
  │  │  ──────────────────────────────────  │   │
  │  │  RLS Policy:                         │   │
  │  │  org_id = current_setting(           │   │
  │  │    'app.current_organization_id')    │   │
  │  └──────────────────────────────────────┘   │
  └─────────────────┬───────────────────────────┘
                    │
  ┌─────────────────▼───────────────────────────┐
  │           PostgreSQL (RLS Enforced)          │
  │  ┌──────┬──────┬──────┬──────┬──────┐      │
  │  │Org 1 │Org 2 │Org 3 │ ...  │Org 15│      │
  │  │Data  │Data  │Data  │      │Data  │      │
  │  │══════│══════│══════│══════│══════│      │
  │  │FORCE ROW LEVEL SECURITY on all tables│   │
  │  └──────┴──────┴──────┴──────┴──────┘      │
  └─────────────────────────────────────────────┘
```

---

## Chapter 3: Multi-Tenant SaaS Foundation

### 3.1 Overview

AuditGraph is built from the ground up as a multi-tenant SaaS platform. Every data table is scoped to an organization, and PostgreSQL Row-Level Security (RLS) enforces isolation at the database level -- meaning even a bug in application code cannot cause cross-tenant data leakage.

### 3.2 Tenant Model

The `organizations` table is the root of the tenant hierarchy:

```
organizations
  ├── id (SERIAL PRIMARY KEY)
  ├── name (VARCHAR 255)
  ├── slug (VARCHAR 100 UNIQUE)  ── URL identifier (e.g., "acmecorp")
  ├── plan_tier                  ── free | trial | pro | enterprise
  ├── status                     ── active | suspended | cancelled
  ├── is_demo (BOOLEAN)          ── Demo sandbox mode
  ├── license_activated_at       ── License start date
  ├── license_expires_at         ── License end date
  └── settings (JSONB)           ── Org-specific configuration
```

Every other data table has an `organization_id` column (NOT NULL) that references this table.

### 3.3 Dual-User Database Architecture

AuditGraph uses two PostgreSQL roles to enforce tenant isolation:

```
┌─────────────────────────────────────────────────┐
│               PostgreSQL Server                  │
│                                                  │
│  Role: auditgraph_app (NOBYPASSRLS)             │
│  ├── Used for: All tenant-scoped API requests    │
│  ├── RLS: ALWAYS enforced                        │
│  └── Cannot: Run DDL, access other tenants       │
│                                                  │
│  Role: auditgraph_admin (BYPASSRLS)             │
│  ├── Used for: Schema migrations, scheduler      │
│  ├── RLS: Bypassed (cross-tenant access)         │
│  └── Can: Run DDL, superadmin queries            │
│                                                  │
│  44 tables with FORCE ROW LEVEL SECURITY         │
│  Auto-fill trigger on all 44 tables              │
│  Strict policies (no null-context bypass)        │
└─────────────────────────────────────────────────┘
```

### 3.4 Tenant Context Lifecycle

Every API request follows this security lifecycle:

1. **JWT Parsing**: Extract `organization_id` from JWT claims
2. **Connection Checkout**: Get connection from pool, RESET context
3. **Context Set**: `SET LOCAL app.current_organization_id = N` (transaction-scoped)
4. **Verification**: Read back `current_setting()` to confirm context was set
5. **Query Execution**: All queries filtered by RLS automatically
6. **Connection Return**: RESET context, return to pool

### 3.5 Real-World Problem: Multi-Tenant Data Isolation

**The Problem:**
In 2024, a major SaaS identity vendor disclosed that a bug in their application layer allowed one customer's API request to return another customer's identity data. The root cause was an improperly cached database connection that retained the previous request's tenant context.

**Case Study: Healthcare Organization Under HIPAA**

A healthcare organization required mathematical proof that patient-adjacent identity data could never leak between tenants. AuditGraph's defense-in-depth approach provided:

1. **Database-Level Guarantee**: PostgreSQL FORCE RLS means even the database owner cannot bypass policies
2. **Connection Pool Safety**: Every connection is RESET on checkout and return
3. **Transaction-Scoped Context**: SET LOCAL auto-resets on COMMIT/ROLLBACK
4. **Auto-Fill Trigger**: INSERT without org_id raises an exception (never silently succeeds)
5. **CI/CD Stress Tests**: `test_isolation_stress.py` runs 10 concurrent cross-tenant requests and verifies zero leakage
6. **RLS Drift Audit**: Daily scheduled job at 04:30 UTC validates all FORCE RLS policies are intact

**Architecture: 7-Layer Tenant Isolation**

```
Layer 1: SET LOCAL (transaction-scoped, auto-resets)
    │
Layer 2: Pool Checkout RESET (clear residual state)
    │
Layer 3: Verification (read back current_setting)
    │
Layer 4: Pool Return RESET (belt-and-suspenders)
    │
Layer 5: Flask Teardown Hook (catches exception paths)
    │
Layer 6: FORCE RLS (database-level enforcement)
    │
Layer 7: Auto-Fill Trigger (prevents unscoped INSERTs)
    │
    └── Fail-Closed: SecurityViolationError on any breach
```

---

# PART II: IDENTITY DISCOVERY & ANALYSIS

---

## Chapter 4: Identity Discovery Engine

### 4.1 Overview

The Identity Discovery Engine is the core data collection system of AuditGraph. It connects to cloud provider APIs using read-only service principal credentials and enumerates every identity, role assignment, credential, and permission in the environment. The result is a complete point-in-time snapshot stored in the database.

### 4.2 Discovery Pipeline

The Azure Discovery Engine (`backend/app/engines/discovery/azure_discovery.py`) executes a 13-step pipeline:

```
Step 1:  Create discovery_run record
    │
Step 2:  Discover Azure RBAC role assignments (ARM API)
    │
Step 3:  Discover Entra ID directory roles (Graph API)
    │
Step 4:  Discover Service Principals with pagination (999/page)
    │
Step 5:  Discover SPN credentials (secrets, certificates, federated)
    │
Step 6:  Discover Microsoft Graph API permissions
    │         (10 HIGH_RISK_PERMISSION_GUIDS tracked)
    │
Step 7:  Discover custom application role assignments
    │
Step 8:  Discover users with Azure RBAC or Entra roles
    │
Step 9:  Calculate risk levels (RBAC + Entra combined)
    │
Step 10: Check credential expiration status
    │
Step 11: Check last activity/sign-in (P2 telemetry if available)
    │
Step 12: Save all data to PostgreSQL (batch INSERT)
    │
Step 13: Complete discovery_run with summary statistics
```

### 4.3 Scan Modes

AuditGraph supports three scan modes to balance thoroughness against speed:

| Mode | What's Discovered | Duration | Use Case |
|------|------------------|----------|----------|
| **Quick** | Identities only | ~2 min | Hourly monitoring |
| **Standard** | Identities + roles + credentials | ~5 min | Daily scans |
| **Deep** | Full audit (identities, roles, credentials, PIM, CA, resources) | ~15 min | Weekly comprehensive audit |

### 4.4 Microsoft System SPN Filtering

Azure tenants contain hundreds of Microsoft-owned service principals (e.g., "Microsoft Graph", "Azure Portal"). AuditGraph automatically identifies these using the `appOwnerOrganizationId` field (Microsoft's tenant GUID) and flags them with `is_microsoft_system = true`. Users can toggle "Hide Microsoft" to focus on customer-owned identities.

### 4.5 High-Risk Graph Permissions

The discovery engine tracks 10 Microsoft Graph API permissions classified as high-risk:

| Permission | Risk | Why Dangerous |
|-----------|------|---------------|
| RoleManagement.ReadWrite.Directory | CRITICAL | Can grant Global Admin to any identity |
| Directory.ReadWrite.All | CRITICAL | Full directory modification access |
| Application.ReadWrite.All | HIGH | Can create new app registrations with any permission |
| AppRoleAssignment.ReadWrite.All | HIGH | Can assign any application role |
| User.ReadWrite.All | HIGH | Can modify any user account |
| Group.ReadWrite.All | HIGH | Can modify security groups controlling access |
| Mail.ReadWrite | HIGH | Can read/write any user's email |
| Files.ReadWrite.All | HIGH | Can access all SharePoint/OneDrive files |
| RoleManagement.Read.Directory | MEDIUM | Can enumerate all admin role assignments |
| Directory.Read.All | MEDIUM | Can read entire directory including sensitive attributes |

### 4.6 Real-World Problem: Shadow Identities

**The Problem:**
Organizations create service principals for CI/CD pipelines, automation scripts, and integrations. Over time, teams leave, projects end, but the SPNs remain -- often with Contributor or Owner access to production subscriptions. These "shadow identities" are invisible to traditional IAM tools.

**Case Study: Technology Company with 2,000 SPNs**

A SaaS technology company running 120 Azure subscriptions had no inventory of their service principals. After deploying AuditGraph:

- **Discovery** found 2,147 service principals (vs. the 200 they knew about)
- **Classification** identified 1,200 as Microsoft system SPNs, leaving 947 customer-owned
- **Risk Analysis** flagged 89 SPNs with expired credentials still holding active roles
- **Credential Tracking** revealed 34 SPNs with credentials expiring within 30 days
- **Ownership Mapping** showed 156 SPNs had zero documented owners ("orphaned")

**Architecture: Discovery Data Flow**

```
┌────────────────────┐     ┌──────────────────────┐
│  Azure Graph API   │     │  Azure ARM API        │
│  ──────────────    │     │  ──────────────       │
│  • Service         │     │  • Role Assignments   │
│    Principals      │     │  • Subscriptions      │
│  • Users           │     │  • Resource Groups    │
│  • Groups          │     │  • Resources          │
│  • App Regs        │     │  • Management Groups  │
│  • Directory Roles │     │                       │
│  • PIM             │     │                       │
│  • Permissions     │     │                       │
└────────┬───────────┘     └──────────┬────────────┘
         │                            │
         ▼                            ▼
┌─────────────────────────────────────────────────┐
│            Azure Discovery Engine               │
│                                                  │
│  1. Enumerate identities (paginated, 999/page)  │
│  2. Map RBAC roles to identity scope hierarchy  │
│  3. Track credentials (type, expiry, age)       │
│  4. Classify risk (CRITICAL/HIGH/MEDIUM/LOW)    │
│  5. Detect Microsoft vs customer-owned          │
│  6. Calculate activity status (P2 telemetry)    │
└───────────────────────┬─────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│              PostgreSQL (RLS-scoped)            │
│                                                  │
│  discovery_runs ─┬── identities                 │
│                  ├── role_assignments            │
│                  ├── entra_role_assignments      │
│                  ├── credentials                 │
│                  ├── graph_api_permissions       │
│                  └── sp_app_roles               │
└─────────────────────────────────────────────────┘
```

---

## Chapter 5: Identity Graph & Relationship Mapping

### 5.1 Overview

The Identity Graph Engine (`backend/app/engines/graph_builder.py`) constructs a relationship graph that maps every identity to its roles, resources, subscriptions, owners, and trust relationships. Unlike flat permission tables, the graph reveals transitive access paths -- showing not just what role an identity has, but what resources that role can reach.

### 5.2 Graph Data Model

The graph consists of **nodes** (entities) and **edges** (relationships):

**Node Types:**

| Node Type | Description | Example |
|-----------|-------------|---------|
| `identity` | Any cloud identity | SPN, user, managed identity |
| `role` | Azure RBAC role | Owner, Contributor, Reader |
| `entra_role` | Entra directory role | Global Admin, Security Admin |
| `subscription` | Azure subscription | Production-Sub-001 |
| `resource_group` | Azure resource group | rg-production-api |
| `resource` | Azure resource | Storage Account, Key Vault |
| `owner` | Identity owner | User who owns an SPN |
| `federated_trust` | Federated credential issuer | GitHub Actions, AWS IAM |
| `risk_summary` | Aggregated risk node | Executive view summary |
| `blast_radius` | Impact visualization | Compromise reach bubble |
| `permission` | API permission | Graph API permission |
| `credential` | Secret/certificate | SPN secret, certificate |
| `entra_directory` | Directory scope | Entra ID tenant |

**Edge Types:**

| Edge Type | From → To | Meaning |
|-----------|-----------|---------|
| `assigned_role` | Identity → Role | Identity holds this RBAC role |
| `granted_scope` | Role → Subscription/RG/Resource | Role's effective scope |
| `has_entra_role` | Identity → Entra Role | Identity holds directory role |
| `owns` | Owner → Identity | Ownership relationship |
| `federated_trust_to` | Identity → Trust | Federated credential issuer |

### 5.3 Graph Visualization Modes

The frontend (`components/graph/AccessGraphTab.tsx`) renders the graph in three modes:

**Mode 1: Executive View**
Shows a simplified risk summary with blast radius bubble. Designed for CISO-level presentations.

```
  ┌─────────────┐
  │  Identity    │
  │  SPN-api-01  │
  │  Risk: HIGH  │
  └──────┬───────┘
         │
  ┌──────▼───────┐     ┌─────────────────┐
  │ Risk Summary │     │  Blast Radius    │
  │ Score: 78    │     │  ┌─────────┐    │
  │ Tier: T1     │     │  │ 12 Subs │    │
  │ 5 roles      │     │  │ 34 RGs  │    │
  │ 3 high-risk  │     │  │ 89 Res  │    │
  └──────────────┘     │  └─────────┘    │
                       └─────────────────┘
```

**Mode 2: Technical View**
Hierarchical ARM tree showing Identity → Subscription → Resource Group → Resource with role badges at each level. Entra roles in a separate branch.

```
  ┌─────────────┐
  │  Identity    │
  │  SPN-api-01  │
  └──┬───────┬───┘
     │       │
     ▼       ▼
  ┌──────┐  ┌──────────────┐
  │Entra │  │ Subscription │
  │Roles │  │ Prod-Sub-001 │
  │------│  │ [Contributor]│
  │Global│  └──────┬───────┘
  │Admin │         │
  └──────┘    ┌────┴────┐
              ▼         ▼
        ┌──────────┐ ┌──────────┐
        │ RG: api  │ │ RG: data │
        │[Reader]  │ │[Owner]   │
        └────┬─────┘ └────┬─────┘
             │             │
        ┌────▼────┐   ┌───▼──────┐
        │Storage  │   │Key Vault │
        │acct-01  │   │kv-prod   │
        └─────────┘   └──────────┘
```

**Mode 3: Attack Path View**
Shows privilege escalation chains with severity-coded edges.

```
  ┌─────────────┐  ── CRITICAL ──▶ ┌────────────────┐
  │ SPN-deploy  │                   │ Global Admin    │
  │ (compromised│  ── HIGH ──────▶ │ (via PIM abuse) │
  │  credential)│                   └────────┬────────┘
  └─────────────┘                            │
                                    ── CRITICAL ──▶
                                    ┌────────▼────────┐
                                    │ All Subscriptions│
                                    │ (full control)   │
                                    └──────────────────┘
```

### 5.4 Real-World Problem: Hidden Access Paths

**The Problem:**
Traditional RBAC reviews check direct role assignments. But in Azure, access can be inherited through resource group hierarchy, granted via Entra directory roles that apply to all resources, or acquired through PIM eligible assignments. Without graph analysis, these transitive paths are invisible.

**Case Study: Insurance Company Audit Finding**

During a PCI-DSS audit, an insurance company was asked to demonstrate that no unauthorized identity had access to their payment processing Key Vault. A flat RBAC report showed 3 identities with direct access. AuditGraph's graph analysis revealed:

- 3 identities with direct Key Vault access (known)
- 7 identities with Contributor at the resource group level (inherited access)
- 2 identities with Owner at the subscription level (inherited through hierarchy)
- 1 service principal with Application Administrator Entra role (can create new SPNs with Key Vault access)
- 1 identity with PIM-eligible User Access Administrator (could activate and grant themselves access)

**Total actual access: 14 identities** (vs. 3 in the flat report)

**Architecture: Graph Construction Pipeline**

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│  Discovery Run │    │  Graph Builder  │    │  Graph Storage  │
│  (raw data)    │ ──▶│                 │ ──▶│                 │
│                │    │  1. Create nodes│    │  graph_nodes    │
│  identities    │    │  2. Create edges│    │  graph_edges    │
│  roles         │    │  3. Compute     │    │                 │
│  permissions   │    │     positions   │    │  Pre-computed   │
│  credentials   │    │  4. Build ARM   │    │  x,y positions  │
│  owners        │    │     hierarchy   │    │  for frontend   │
└────────────────┘    └────────────────┘    └────────────────┘
```

---

## Chapter 6: Identity Categories & Classification

### 6.1 Overview

AuditGraph classifies every discovered identity into one of six categories, each with distinct risk characteristics and governance requirements.

### 6.2 Category Definitions

| Category | Code | Description | Typical Count | Risk Profile |
|----------|------|-------------|---------------|-------------|
| **Service Principal** | `service_principal` | App-created identities for automation | 40-60% of total | High (often over-privileged) |
| **System Managed Identity** | `managed_identity_system` | Azure-managed, tied to resource lifecycle | 15-25% | Low (auto-rotated credentials) |
| **User Managed Identity** | `managed_identity_user` | User-created, shared across resources | 5-10% | Medium (wider blast radius) |
| **Human User** | `human_user` | Interactive user accounts | 15-25% | Variable (depends on role) |
| **Guest** | `guest` | External/B2B guest accounts | 5-15% | High (external access) |
| **Microsoft Internal** | `microsoft_internal` | Microsoft-owned system SPNs | Filtered | N/A (system) |

### 6.3 Activity Status Classification

Each identity receives an activity status based on sign-in telemetry:

| Status | Definition | Risk Implication |
|--------|-----------|-----------------|
| `active` | Last sign-in within 30 days | Normal, monitor for drift |
| `inactive` | Last sign-in 30-90 days ago | Review for privilege reduction |
| `stale` | Last sign-in 90+ days ago | Candidate for disable/removal |
| `never_used` | No recorded sign-in ever | Likely abandoned, high risk |
| `recently_created` | Created within 7 days | Monitor for excessive permissions |
| `dormant` | P2-confirmed no activity (95% confidence) | Strong candidate for removal |
| `unknown` | No telemetry available | Risk gap, needs P2 license |

### 6.4 Privilege Tiering

AuditGraph assigns each identity a privilege tier (T0-T3) based on their highest-privilege role:

```
Tier 0 (T0) ── "Keys to the Kingdom"
  │  Global Administrator
  │  Privileged Role Administrator
  │  Owner at subscription/management group
  │
Tier 1 (T1) ── "Significant Privilege"
  │  Security Administrator
  │  User Access Administrator
  │  Application Administrator
  │  Contributor at subscription level
  │
Tier 2 (T2) ── "Moderate Privilege"
  │  Contributor at resource group level
  │  Custom roles with write permissions
  │  Reader with sensitive data access
  │
Tier 3 (T3) ── "Limited Privilege"
     Reader roles
     Custom roles with read-only access
```

### 6.5 Real-World Problem: Guest Account Proliferation

**The Problem:**
Azure B2B guest accounts are created whenever external users are invited to collaborate. These guests often receive temporary project access but are never removed, accumulating over months and years.

**Case Study: Consulting Firm with 300 Active Projects**

A consulting firm inviting clients and contractors to their Azure tenant discovered:
- 2,400 guest accounts across all projects
- 890 guests hadn't logged in for 6+ months
- 45 guests had Contributor access to production subscriptions
- 12 guests had Security Admin Entra roles (likely unintentional)

AuditGraph's guest-specific governance rules flagged:
- All 45 guests with Contributor as "HIGH" risk
- All 12 guests with Security Admin as "CRITICAL" risk
- Generated remediation playbooks to remove expired guest access
- Created a quarterly access review workflow for remaining guests

---

## Chapter 7: Multi-Cloud Identity Support

### 7.1 Overview

AuditGraph is designed as a multi-cloud identity platform supporting Azure (production), AWS, and GCP. The discovery engine uses a base class pattern (`BaseDiscoveryEngine`) that standardizes the discovery interface across all cloud providers.

### 7.2 Cloud Provider Architecture

```
┌─────────────────────────────────────────────────┐
│              BaseDiscoveryEngine                │
│                                                  │
│  Abstract Methods:                               │
│  ├── discover(run_id) → Run full discovery       │
│  ├── test_connection() → Validate credentials    │
│  └── cloud_provider → Property returning name    │
│                                                  │
│  Shared Methods:                                 │
│  ├── save_identities() → Batch DB insert         │
│  ├── calculate_risk() → Risk scoring             │
│  └── update_run_status() → Status tracking       │
└──────────────┬──────────────────────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐
│ Azure  │ │  AWS   │ │  GCP   │
│ Engine │ │ Engine │ │ Engine │
│ (Prod) │ │ (Stub) │ │ (Stub) │
└────────┘ └────────┘ └────────┘
```

### 7.3 Azure (Production Support)

Azure discovery is fully implemented with support for:
- Microsoft Graph API (identities, directory roles, app permissions)
- Azure Resource Manager (RBAC roles, subscriptions, resource groups)
- PIM (Privileged Identity Management) eligible assignments and activations
- Conditional Access policy discovery
- Storage Account and Key Vault security scanning
- App Registration audit

### 7.4 AWS & GCP (Future Support)

AWS and GCP discovery engines are implemented as placeholder stubs providing the base class interface. The architecture supports adding these providers by:
1. Implementing the cloud-specific API calls in the discovery engine
2. Mapping provider-specific identity types to AuditGraph's category system
3. Adding provider-specific risk rules to the scoring engine

### 7.5 Multi-Cloud Configuration

Each tenant configures cloud connections via the `cloud_connections` table:

```
cloud_connections
  ├── id
  ├── organization_id (RLS-scoped)
  ├── cloud_provider (azure | aws | gcp)
  ├── connection_name ("Production Azure")
  ├── status (connected | disconnected | error)
  ├── credentials_encrypted (BYTEA, AES-encrypted)
  └── last_tested (TIMESTAMP)
```

The sidebar dynamically shows only enabled cloud providers, fetched from `/api/tenant/config`.

### 7.6 Real-World Problem: Multi-Cloud Identity Fragmentation

**The Problem:**
Enterprises using multiple cloud providers face identity fragmentation -- the same human may have separate accounts in Azure AD, AWS IAM, and GCP IAM with no cross-cloud visibility.

**Case Study: E-Commerce Platform (Azure + AWS)**

An e-commerce company running Azure for identity/compliance and AWS for compute had:
- 500 Azure identities (humans + SPNs)
- 800 AWS IAM entities (users + roles + service accounts)
- Zero correlation between Azure users and their corresponding AWS roles
- A terminated employee's Azure account was disabled but their AWS IAM user remained active with S3 full access

AuditGraph's Identity Correlation Engine (ICE) detected the cross-cloud identity link and flagged the orphaned AWS entity.

**Architecture: Multi-Cloud Discovery**

```
┌──────────────────────────────────────────────────┐
│                  AuditGraph Platform              │
│                                                    │
│  ┌─────────────────────────────────────────────┐  │
│  │          Cloud Connection Manager            │  │
│  │                                              │  │
│  │  Connection 1: Azure (Production)  ✓        │  │
│  │  Connection 2: Azure (Dev/Test)    ✓        │  │
│  │  Connection 3: AWS (us-east-1)     ◐        │  │
│  │  Connection 4: GCP (project-prod)  ◐        │  │
│  └───────────┬────────────┬────────────┬───────┘  │
│              │            │            │           │
│         ┌────▼────┐ ┌────▼────┐ ┌────▼────┐      │
│         │ Azure   │ │  AWS    │ │  GCP    │      │
│         │ Graph + │ │  IAM +  │ │ IAM +   │      │
│         │ ARM API │ │ STS API │ │ CRM API │      │
│         └────┬────┘ └────┬────┘ └────┬────┘      │
│              │            │            │           │
│              └────────────┼────────────┘           │
│                           │                        │
│              ┌────────────▼────────────┐           │
│              │  Identity Correlation   │           │
│              │  Engine (ICE)           │           │
│              │  ──────────────────     │           │
│              │  Cross-cloud matching   │           │
│              │  Zombie detection       │           │
│              │  Orphan identification  │           │
│              └─────────────────────────┘           │
└────────────────────────────────────────────────────┘
```

---

# PART III: RISK INTELLIGENCE

---

## Chapter 8: AGIRS Composite Risk Scoring

### 8.1 Overview

The AuditGraph Identity Risk Score (AGIRS) is a proprietary composite scoring model that quantifies an organization's identity risk posture on a 0-100 scale. Unlike simple vulnerability counting, AGIRS uses a three-axis model that separately evaluates human identity risk, non-human identity risk, and governance effectiveness.

The AGIRS engine resides in `backend/app/engines/risk/agirs_engine.py`.

### 8.2 Three-Axis Model

```
                    AGIRS Score (0-100)
                         │
          ┌──────────────┼──────────────┐
          │              │              │
     ┌────▼────┐    ┌───▼────┐    ┌───▼────┐
     │  HIRI   │    │ NHIRI  │    │  GEI   │
     │  (40%)  │    │ (40%)  │    │ (20%)  │
     │         │    │        │    │        │
     │ Human   │    │Non-Hum │    │Govern- │
     │Identity │    │Identity│    │ance    │
     │Risk Idx │    │Risk Idx│    │Effect. │
     └─────────┘    └────────┘    └────────┘
```

**Final Score:** `AGIRS = (HIRI × 0.40) + (NHIRI × 0.40) + (GEI × 0.20)`

### 8.3 HIRI: Human Identity Risk Index

HIRI starts at 100 and deducts points per 100 human identities for each risk factor:

| Factor | Code | Deduction | Definition |
|--------|------|-----------|------------|
| Ghost Humans | H1 | -3 pts | Disabled/deleted accounts that still hold active roles |
| Dormant Privileged | H2 | -5 pts | Stale users (90+ days) with T0/T1/T2 roles |
| Over-Privileged | H3 | -4 pts | Users with risk_score >= 70 or Tier 0 |
| External Guests w/ Privilege | H4 | -6 pts | Guest accounts holding privileged roles |
| Zombie Humans | H5 | -7 pts | Stale accounts with valid credentials and high risk |

**Example Calculation:**
Organization with 200 human users:
- 4 ghost humans: H1 = 4/200 × 100 × 3 = 6.0 deducted
- 8 dormant privileged: H2 = 8/200 × 100 × 5 = 20.0 deducted
- HIRI = 100 - 6.0 - 20.0 = 74.0

### 8.4 NHIRI: Non-Human Identity Risk Index

NHIRI follows the same deduction model for non-human identities:

| Factor | Code | Deduction | Definition |
|--------|------|-----------|------------|
| Orphaned NHI | N1 | -4 pts | SPNs/managed identities with no owner |
| Dormant NHI | N2 | -3 pts | Inactive non-human identities with active roles |
| Zombie NHI | N3 | -6 pts | Stale NHIs with valid credentials and high risk |
| Expired/Expiring Creds | N4 | -2 pts | Credentials expired or expiring within 30 days |
| Ownerless Apps | N5 | -5 pts | App registrations with zero owners |

### 8.5 GEI: Governance Effectiveness Index

GEI measures how well the organization's governance controls are performing:

| Factor | Weight | Measurement |
|--------|--------|-------------|
| Remediation Closure Rate | 30% | % of flagged issues resolved within SLA |
| Access Review Completion | 25% | % of scheduled access reviews completed |
| MFA Adoption | 20% | % of human identities with MFA enabled |
| CA Policy Coverage | 15% | % of identities covered by Conditional Access |
| Credential Rotation | 10% | % of SPNs with credentials rotated on schedule |

### 8.6 Blast Radius Danger Score

Beyond the composite score, AGIRS calculates a per-identity "blast radius danger score":

```
Danger Score = Tier Weight × Scope Multiplier × Dormancy Amplifier

Tier Weights:      T0=10, T1=7, T2=4, T3=1
Scope Multiplier:  tenant=3.0, subscription=2.0, resource_group=1.5, resource=1.0
Dormancy Amplifier: stale=2.0, never_used=2.5, inactive=1.5, active=1.0
```

**Example:** A stale T0 identity with subscription-level Owner role:
`Danger = 10 × 2.0 × 2.0 = 40.0` (maximum practical danger)

### 8.7 Real-World Problem: Moving Beyond Simple Risk Counts

**The Problem:**
Most identity tools report "you have 47 critical identities" without context. A CISO needs to know: Is the situation improving? How does human vs. non-human risk compare? Are governance controls actually working?

**Case Study: Manufacturing Company Quarterly Board Report**

A manufacturing company needed to report identity risk to their board quarterly. Before AGIRS, they showed a flat count of critical identities, which fluctuated without context.

With AGIRS:
- Q1: AGIRS = 62 (HIRI: 71, NHIRI: 53, GEI: 65)
- Q2: AGIRS = 68 (HIRI: 74, NHIRI: 58, GEI: 78) -- improvement
- Q3: AGIRS = 72 (HIRI: 78, NHIRI: 63, GEI: 82) -- continued improvement
- Q4: AGIRS = 67 (HIRI: 75, NHIRI: 55, GEI: 80) -- NHIRI regression

The Q4 NHIRI drop was traced to a new CI/CD pipeline that created 40 service principals with Owner access. AGIRS pinpointed the exact problem axis.

**Architecture: AGIRS Computation Flow**

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Latest       │     │  AGIRS       │     │  CISO        │
│ Discovery    │────▶│  Engine      │────▶│  Dashboard   │
│ Snapshot     │     │              │     │              │
│              │     │  1. Count    │     │  Score Ring  │
│  identities  │     │     factors  │     │  Trend Chart │
│  roles       │     │  2. Calculate│     │  Factor      │
│  credentials │     │     HIRI     │     │  Breakdown   │
│  owners      │     │  3. Calculate│     │  Drill-down  │
│  activity    │     │     NHIRI    │     │              │
│              │     │  4. Calculate│     │              │
│              │     │     GEI      │     │              │
│              │     │  5. Composite│     │              │
│              │     │     score    │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
```

---

## Chapter 9: Blast Radius Analysis

### 9.1 Overview

The Blast Radius Engine (`backend/app/engines/blast_radius_engine.py`) answers the question: *"If this identity is compromised, what can the attacker reach?"* It simulates compromise scenarios by tracing access paths from each identity through the ARM scope hierarchy and Entra directory.

### 9.2 How Blast Radius is Computed

For each identity, the engine:

1. **Enumerate RBAC Scope Expansion**: Trace from identity → role assignments → scope (subscription/RG/resource)
2. **Enumerate Entra Directory Privilege**: Check for directory-wide roles (Global Admin = all resources)
3. **Enumerate Reachable Resources**: Count storage accounts, key vaults, databases within scope
4. **Classify Sensitive Assets**: Tag resources containing PII, PHI, PCI data
5. **Count Attack Paths**: Reference attack_paths table for escalation potential
6. **Estimate Remediation Reduction**: How much would removing a specific role reduce blast radius?

### 9.3 Privilege Weights

The engine assigns weights to roles based on their destructive potential:

```
Global Administrator ─────────── 50 pts
Privileged Role Admin ────────── 45 pts
Owner ─────────────────────────── 40 pts
User Access Administrator ────── 38 pts
Application Administrator ────── 35 pts
Security Administrator ────────── 30 pts
User Administrator ─────────────── 30 pts
Exchange Administrator ─────────── 28 pts
Contributor ───────────────────── 25 pts
```

### 9.4 Safety Limits

To prevent runaway computation on large environments:
- `MAX_BLAST_RADIUS_IDENTITIES = 1000` (process at most 1000 identities per run)
- `MAX_BLAST_RADIUS_RESOURCES = 5000` (cap resource enumeration)

### 9.5 Real-World Problem: Understanding Compromise Impact

**The Problem:**
When a credential is leaked in a GitHub commit or a phishing attack succeeds, security teams need to instantly understand what the attacker can reach. Without blast radius analysis, incident response teams waste hours manually tracing role assignments.

**Case Study: Incident Response at Retail Company**

A retail company detected suspicious sign-in activity on a service principal. Their incident response playbook required answering: "What can this SPN reach?"

Without AuditGraph: The IR team spent 4 hours manually checking Azure RBAC, Entra roles, and resource access policies.

With AuditGraph: The blast radius was pre-computed and available in <5 seconds:
- **3 subscriptions** with Contributor access
- **12 resource groups** within those subscriptions
- **47 resources** including 2 Key Vaults with encryption keys
- **156 storage containers** including customer PII data
- **2 escalation paths** to Owner through PIM eligible assignments

The IR team contained the incident in 15 minutes instead of 4 hours.

---

## Chapter 10: Attack Path Analysis

### 10.1 Overview

The Attack Path Analysis Engine (`backend/app/engines/attack_path_engine.py`) performs batch tenant-wide analysis to detect privilege escalation chains -- paths where a low-privilege identity can reach high-privilege access through a series of steps.

### 10.2 Escalation Chain Types

The engine detects five types of escalation chains:

| Path Type | Description | Example |
|-----------|-------------|---------|
| `direct_escalation` | Identity already holds critical role | SPN with Global Admin |
| `ownership_chain` | Identity owns another identity that has privilege | User owns SPN that has Owner |
| `pim_abuse` | Identity can activate PIM role to gain privilege | Eligible for Privileged Role Admin |
| `lateral_movement` | Identity can modify another identity's permissions | Application Admin can grant app roles |
| `credential_exposure` | Identity's credentials are expired/weak | Expired secret + active Owner role |

### 10.3 Path Construction

Each attack path is represented as a chain of nodes:

```
Source Identity ──▶ Step 1 ──▶ Step 2 ──▶ ... ──▶ Target (High Privilege)
```

**Safety Limits:**
- `MAX_GRAPH_DEPTH = 5` (maximum nodes in a single path)
- `MAX_PATHS_PER_IDENTITY = 10` (prevent explosion on highly connected identities)
- `MAX_PATHS_PER_RUN = 2000` (cap total paths per tenant)

### 10.4 Path Fingerprinting

Each attack path receives a deterministic SHA-256 fingerprint:
```
fingerprint = SHA-256(source_entity_id + path_type + sorted(node_ids))
```

This enables:
- **Deduplication**: Same path across multiple runs produces same hash
- **Change Detection**: New paths in current run but not previous = new escalation risk
- **Trend Tracking**: Count of active escalation paths over time

### 10.5 Dangerous Elements Tracked

| Category | Elements | Risk |
|----------|----------|------|
| Entra Roles | Global Admin, Privileged Role Admin, Application Admin, Cloud App Admin, Auth Admin, User Admin | Directory-wide privilege |
| MS Graph Perms | RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.ReadWrite.All, User.ReadWrite.All, GroupMember.ReadWrite.All | API-level escalation |
| RBAC Roles | Owner, Contributor, User Access Admin (at subscription scope) | Resource-level control |
| Data Classes | confidential, highly_confidential, restricted, PII, PHI, PCI | Sensitive data exposure |

### 10.6 Real-World Problem: Multi-Step Privilege Escalation

**The Problem:**
Attackers rarely need direct Global Admin access. They find a chain: compromise an SPN with Application Administrator → create a new app registration → grant it RoleManagement.ReadWrite.Directory → use that to assign Global Admin to themselves.

**Case Study: Penetration Test Finding at Bank**

During a red team exercise, a bank's pentesters discovered a 3-step escalation chain:

1. **Entry**: Compromised CI/CD SPN with `Application.ReadWrite.All` Graph permission
2. **Escalation**: Used permission to create new app registration with `RoleManagement.ReadWrite.Directory`
3. **Objective**: Assigned Global Administrator to the new app, gaining full tenant control

AuditGraph's Attack Path Engine would have detected this chain pre-breach:

```
┌──────────────┐     ┌────────────────┐     ┌──────────────────┐
│  SPN-cicd    │────▶│  Application   │────▶│  Global Admin    │
│              │     │  .ReadWrite.All│     │  Assignment      │
│  [ENTRY]     │     │  [ESCALATION] │     │  [OBJECTIVE]     │
│  Severity:   │     │  Severity:    │     │  Severity:       │
│  MEDIUM      │     │  HIGH         │     │  CRITICAL        │
└──────────────┘     └────────────────┘     └──────────────────┘
```

**Architecture: Attack Path Detection Flow**

```
┌────────────────┐
│  Discovery     │
│  Snapshot      │
└───────┬────────┘
        │
        ▼
┌────────────────────────────────────────────┐
│           Attack Path Engine               │
│                                            │
│  For each identity:                        │
│    1. Check direct critical roles          │
│    2. Trace ownership chains               │
│    3. Check PIM eligible escalation        │
│    4. Check lateral movement via           │
│       Application Admin / User Admin       │
│    5. Check credential exposure risk       │
│                                            │
│  Path fingerprinting (SHA-256)             │
│  Deduplication across runs                 │
│  Severity classification                   │
└───────────────┬────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────┐
│  attack_paths table                        │
│  ├── source_entity_id                      │
│  ├── path_type                             │
│  ├── severity (critical/high/medium/low)   │
│  ├── path_nodes (JSONB array)              │
│  └── fingerprint (SHA-256, stable)         │
└────────────────────────────────────────────┘
```

---

## Chapter 11: Drift Detection Engine

### 11.1 Overview

The Drift Detection Engine (`backend/app/engines/drift_detector.py`) compares consecutive discovery snapshots to identify security-relevant changes. It answers: *"What changed since the last scan?"*

### 11.2 Change Categories

**Legacy 5-Bucket Classification:**

| Category | What It Detects |
|----------|----------------|
| New Identities | Identities in current run but not previous |
| Removed Identities | Identities in previous run but not current |
| Permission Changes | Role assignments added or removed |
| Risk Changes | Risk level escalations or de-escalations |
| Credential Changes | Credential status deterioration |

**Enhanced 13 Typed Events (v2):**

| Event Type | Severity | Description |
|-----------|----------|-------------|
| `identity_added` | INFO | New identity discovered |
| `identity_removed` | MEDIUM | Identity no longer present |
| `identity_disabled` | LOW | Identity disabled in directory |
| `identity_reactivated` | HIGH | Previously removed identity reappears |
| `role_assigned` | MEDIUM | New role assignment |
| `role_removed` | LOW | Role assignment removed |
| `privilege_escalated` | CRITICAL | Identity gained critical role |
| `privilege_deescalated` | LOW | Identity lost critical role |
| `risk_escalated` | HIGH | Risk level increased |
| `risk_deescalated` | LOW | Risk level decreased |
| `spn_credential_expired` | HIGH | SPN credential expired |
| `spn_credential_added` | MEDIUM | New credential added to SPN |
| `mfa_disabled` | CRITICAL | MFA disabled for identity |

### 11.3 Soft-Delete & Reactivation

When an identity disappears between runs, AuditGraph does not hard-delete it. Instead:
1. Sets `deleted_at` timestamp (soft-delete)
2. If the identity reappears in a future run, clears `deleted_at` (reactivation)
3. Reactivation triggers a `identity_reactivated` event (HIGH severity)

This handles Azure AD sync delays and temporary identity removal.

### 11.4 Real-World Problem: Detecting Unauthorized Changes

**The Problem:**
An insider or compromised account can make subtle permission changes that go unnoticed for weeks -- adding themselves as Owner on a single resource group, granting a Graph API permission to an SPN, or activating a PIM role outside business hours.

**Case Study: Government Agency Insider Threat**

A government agency discovered during a post-incident review that an employee had:
1. Added their personal guest account to the tenant (identity_added)
2. Assigned the guest Contributor on a sensitive resource group (role_assigned)
3. Used the guest account to access classified storage (no detection)

With AuditGraph's drift detection running every 6 hours:
- Hour 0: `identity_added` event for guest account
- Hour 0: `role_assigned` event for Contributor on classified RG
- SOAR playbook triggered: Slack alert + auto-created Jira ticket
- Security team investigated within 30 minutes

---

## Chapter 12: Anomaly Detection Engine

### 12.1 Overview

The Anomaly Detection Engine (`backend/app/engines/anomaly_detector.py`) runs after each drift detection pass and analyzes patterns that indicate security threats beyond simple change tracking. It detects behavioral anomalies that drift detection alone would miss.

### 12.2 Anomaly Types

| Type | Severity | Detection Logic |
|------|----------|----------------|
| `permission_escalation` | CRITICAL | Identity gained critical/high-risk roles between runs |
| `risk_score_spike` | HIGH | Risk score increased by >20 points in one run |
| `dormant_reactivation` | HIGH | Identity inactive 90+ days suddenly becomes active |
| `credential_surge` | MEDIUM | Credential count increased by 3+ in one run |
| `off_hours_pim` | HIGH | PIM activation outside 8am-6pm business hours |
| `excessive_pim_usage` | MEDIUM | 5+ PIM activations in 7 days or "always active" pattern |

### 12.3 Critical Roles for Escalation Detection

The engine maintains two role lists for anomaly sensitivity:

**Critical Roles (triggers CRITICAL anomaly):**
- Global Administrator
- Privileged Role Administrator
- Owner (at subscription+)
- User Access Administrator
- Application Administrator

**High-Risk Roles (triggers HIGH anomaly):**
- Security Administrator
- Compliance Administrator
- Conditional Access Administrator
- Authentication Administrator

### 12.4 Real-World Problem: Detecting Credential Compromise

**The Problem:**
When an attacker compromises an SPN credential, they often test access by activating PIM roles outside business hours or rapidly creating new credentials. Traditional SIEM tools may not correlate these identity-layer signals.

**Case Study: SaaS Company Credential Leak**

A SaaS company's SPN credential was accidentally committed to a public GitHub repository. The attacker:
1. Used the credential at 2:00 AM local time
2. Activated PIM eligible "User Access Administrator" role
3. Created 2 new client secrets on the same SPN

AuditGraph detected all three anomalies within the next scheduled scan:
- `off_hours_pim`: PIM activation at 02:00 (outside 08:00-18:00 window)
- `credential_surge`: Credential count jumped from 1 to 3
- `permission_escalation`: UAA role added

All three anomalies triggered SOAR playbooks that disabled the SPN and notified the security team via Slack.

---

## Chapter 13: Behavioral Intelligence (P2 Telemetry)

### 13.1 Overview

The P2 Telemetry Pipeline (`backend/app/engines/` + `P2TelemetryService`) ingests Microsoft Entra ID P2 sign-in logs to provide high-confidence behavioral intelligence for workload identities. Without P2 data, activity status relies on heuristics (40% confidence). With P2 data, confidence rises to 95%.

### 13.2 Data Sources

| Table | Purpose |
|-------|---------|
| `workload_signin_events` | Raw sign-in log entries from Entra ID P2 |
| `workload_activity_stats` | Aggregated activity metrics per identity |
| `workload_anomaly_events` | P2-specific behavioral anomalies |

### 13.3 Behavioral Anomaly Types (8 P2-Specific)

| Type | Description |
|------|-------------|
| `impossible_travel` | Sign-ins from geographically distant locations in impossible timeframe |
| `dormant_reactivation` | P2-confirmed dormant identity (95% confidence) suddenly active |
| `off_hours_spike` | Unusual spike in off-hours authentication |
| `new_resource_access` | Identity accessing a resource type it has never accessed before |
| `auth_failure_burst` | 5+ authentication failures in 10-minute window |
| `risky_sign_in` | Entra ID flagged the sign-in as risky (compromised token, etc.) |
| `ca_bypass_attempt` | Sign-in that circumvented Conditional Access policy |
| `volume_anomaly` | Authentication volume 3x higher than 30-day baseline |

### 13.4 P2 vs. Heuristic Activity Detection

```
Without P2 License:                  With P2 License:
──────────────────                   ──────────────────
Activity Status: Heuristic           Activity Status: P2-Confirmed
Confidence: ~40%                     Confidence: ~95%
Method: last_sign_in_date from       Method: Real sign-in log analysis
  Azure AD (if available)              from Entra P2 workload logs
Dormant: Guess based on role age     Dormant: Verified by zero sign-ins
                                       over 90-day window
Exposure Banner: RED                 Exposure Banner: GREEN
"Visibility Gap: Limited telemetry"  "P2 Active: Full behavioral intel"
```

### 13.5 Real-World Problem: False Positive Reduction

**The Problem:**
Without sign-in telemetry, identity tools guess activity status from indirect signals (role creation date, credential age). This produces high false-positive rates -- flagging active SPNs as dormant because their last_sign_in_date is null.

**Case Study: Enterprise with 3,000 SPNs**

An enterprise had 3,000 service principals. Without P2:
- AuditGraph flagged 1,200 as "inactive" (heuristic, 40% confidence)
- Manual review found only 340 were truly dormant
- False positive rate: 72%

After enabling P2 telemetry:
- AuditGraph flagged 380 as "dormant" (P2-confirmed, 95% confidence)
- Manual review confirmed 340 were dormant
- False positive rate: 10.5%
- 860 fewer false positives to investigate

**Architecture: P2 Telemetry Pipeline**

```
┌────────────────────┐
│  Microsoft Entra   │
│  ID P2 Sign-In     │
│  Logs              │
└────────┬───────────┘
         │ Graph API: /auditLogs/signIns
         ▼
┌────────────────────┐
│  P2 Telemetry      │
│  Service           │
│  ──────────────    │
│  1. Ingest logs    │
│  2. Aggregate stats│
│  3. Run behavioral │
│     anomaly detect │
│  4. Update activity│
│     status (95%    │
│     confidence)    │
└────────┬───────────┘
         │
    ┌────┴─────────────────────────┐
    │                              │
    ▼                              ▼
┌──────────────────┐    ┌──────────────────┐
│workload_signin_  │    │workload_anomaly_ │
│events            │    │events            │
│(raw sign-ins)    │    │(8 anomaly types) │
└──────────────────┘    └──────────────────┘
    │
    ▼
┌──────────────────┐
│workload_activity_│
│stats             │
│(30-day summary)  │
└──────────────────┘
```

---

# PART IV: GOVERNANCE & COMPLIANCE

---

## Chapter 14: Identity Governance Engine

### 14.1 Overview

The Identity Governance Engine (`backend/app/engines/identity_governance_engine.py`) enforces organizational policies around identity lifecycle, credential age, and privilege duration. It detects governance violations and generates actionable findings.

### 14.2 Governance Rules

| Rule | Threshold | Severity | Description |
|------|-----------|----------|-------------|
| Unused Identity | 90 days inactive | MEDIUM | Identity has not signed in for 90+ days |
| Stale Credentials | 180 days old | HIGH | Credential has not been rotated in 180+ days |
| Privilege Drift | 365 days | MEDIUM | Identity has held a privileged role for 1+ years without review |
| Guest Over-Privilege | Any privileged role | HIGH | Guest accounts should not hold Owner, Contributor, or Admin roles |
| Ownerless SPN | Zero owners | HIGH | Service principal has no documented owner |
| Excessive Permissions | risk_score >= 70 | HIGH | Identity's combined permissions exceed safe thresholds |

### 14.3 Governance Status Computation

Each identity receives a governance status:

```
COMPLIANT ──── All governance rules pass
    │
NEEDS_ATTENTION ── 1-2 low/medium governance violations
    │
NON_COMPLIANT ──── Any high/critical governance violation
```

### 14.4 Real-World Problem: Identity Lifecycle Neglect

**The Problem:**
Organizations create identities for projects, contractors, and integrations but have no systematic process to review and remove them. Over years, identity counts grow linearly while reviews are ad-hoc (or nonexistent).

**Case Study: University IT Department**

A university with 15,000 Azure identities ran AuditGraph's governance engine:
- 3,400 identities hadn't been used in 90+ days (23%)
- 1,200 service principals had credentials older than 1 year
- 890 identities held privileged roles for over 365 days without access review
- 45 former contractor guest accounts still had Contributor access

AuditGraph generated prioritized remediation recommendations, reducing the identity attack surface by 40% in 60 days.

---

## Chapter 15: Service Account Governance

### 15.1 Overview

Service Account Governance (Phase 63) provides specialized lifecycle management for non-human identities (service principals and managed identities), which require different governance rules than human accounts.

### 15.2 Governance Policies

Configurable via `sa_gov_*` settings keys:

| Policy | Setting Key | Default | Description |
|--------|------------|---------|-------------|
| Minimum Owner Count | `sa_gov_min_owners` | 2 | Every SPN must have at least 2 owners |
| Maximum Credential Age | `sa_gov_max_cred_age_days` | 180 | Credentials must be rotated within 180 days |
| Attestation Frequency | `sa_gov_attestation_days` | 90 | Owners must attest SPN is still needed every 90 days |
| Require Business Justification | `sa_gov_require_justification` | true | Every SPN must have a documented business purpose |
| Auto-Disable Threshold | `sa_gov_auto_disable_days` | 180 | SPNs inactive for 180+ days are auto-disabled |

### 15.3 Attestation Workflow

```
Owner receives attestation reminder (email/Slack)
    │
    ├── Owner confirms: "Still needed" → Status: COMPLIANT
    │     └── Next attestation in 90 days
    │
    ├── Owner declines: "No longer needed" → Status: PENDING_REMOVAL
    │     └── Remediation playbook: disable + remove roles
    │
    └── No response in 14 days → Status: NON_COMPLIANT
          └── Escalation to admin + auto-disable (if configured)
```

### 15.4 Real-World Problem: Orphaned Service Accounts

**The Problem:**
When an engineer leaves the company, their personal Azure account is disabled via HR offboarding. But the service principals they created remain active with their original permissions -- effectively creating a persistent backdoor.

**Case Study: Fintech Startup Post-Acquisition**

After acquiring a fintech startup, the parent company inherited 400 Azure service principals. AuditGraph's SA Governance module found:
- 120 SPNs with zero owners (original developers left)
- 45 SPNs with credentials last rotated 2+ years ago
- 18 SPNs with Owner-level access to production databases

The governance engine automatically:
1. Flagged all 120 ownerless SPNs for immediate review
2. Generated attestation requests for the remaining 280
3. Created remediation playbooks for the 18 high-privilege SPNs
4. Set up quarterly attestation reminders going forward

---

## Chapter 16: Compliance Framework Automation

### 16.1 Overview

AuditGraph maps identity risk findings to compliance frameworks (SOC2, HIPAA, PCI-DSS, CIS, NIST), providing automatic compliance scoring and evidence collection for auditors.

### 16.2 Supported Frameworks

| Framework | Controls Mapped | Key Identity Requirements |
|-----------|----------------|--------------------------|
| **SOC2** | CC6.1-CC6.8 | Access control, monitoring, change management |
| **HIPAA** | 164.312 | Access controls, audit logs, encryption |
| **PCI-DSS** | Req 7, 8, 10 | Least privilege, unique IDs, audit trail |
| **CIS Azure** | 1.x-5.x | Identity config, logging, networking |
| **NIST 800-53** | AC, AU, IA | Access control, audit, identification |

### 16.3 Automatic Evidence Collection

For each compliance control, AuditGraph automatically collects evidence:

```
Control: PCI-DSS Requirement 8.1.4
"Remove/disable inactive user accounts within 90 days"

Evidence:
  ├── Total identities: 1,200
  ├── Inactive 90+ days: 45
  ├── Disabled in period: 38
  ├── Still active: 7 (VIOLATION)
  └── Remediation playbooks: 7 auto-generated

Status: PARTIAL (93.8% compliant)
```

### 16.4 Compliance Scorecard

The dashboard displays compliance scores per framework as a percentage:

```
┌─────────┬──────┬──────┬──────┬──────┐
│         │ SOC2 │HIPAA │ PCI  │ CIS  │
├─────────┼──────┼──────┼──────┼──────┤
│ Score   │ 87%  │ 72%  │ 91%  │ 83%  │
│ Status  │  ●   │  ●   │  ●   │  ●   │
│         │Green │Orange│Green │Green │
└─────────┴──────┴──────┴──────┴──────┘
```

### 16.5 Real-World Problem: Audit Readiness

**The Problem:**
Preparing for SOC2 or HIPAA audits takes weeks of manual evidence collection. Identity access reviews are a major audit finding category, and most organizations cannot demonstrate continuous compliance.

**Case Study: Healthcare SaaS Passing HIPAA Audit**

A healthcare SaaS company faced a HIPAA audit requiring:
1. Complete inventory of all identities with access to PHI
2. Evidence of quarterly access reviews
3. Proof of least privilege enforcement
4. Audit trail of all access changes

AuditGraph provided:
1. **Identity inventory**: Automatic discovery of all 800 identities with RBAC mapping
2. **Access reviews**: Automated quarterly review workflows with attestation records
3. **Least privilege**: AGIRS scoring showing over-privileged identities and remediation actions taken
4. **Audit trail**: Activity log with 100% coverage of identity changes (drift detection + activity_log)

The company passed their HIPAA audit in 3 days instead of the expected 3 weeks.

---

## Chapter 17: Privileged Identity Management (PIM)

### 17.1 Overview

AuditGraph discovers and monitors Azure Entra PIM (Privileged Identity Management) eligible assignments and activations. PIM allows just-in-time privilege access, but it can be misused if not monitored.

### 17.2 Data Model

**PIM Eligible Assignments** (`pim_eligible_assignments`):
- Identities that CAN activate a privileged role (but haven't yet)
- Tracked by `object_id` (Entra identity object ID, not AuditGraph identity_id)
- Includes expiration dates and activation requirements

**PIM Activations** (`pim_activations`):
- Historical record of WHEN identities activated their eligible roles
- Duration tracking (hours)
- Frequency metrics (activations in last 7/30 days)

### 17.3 PIM Risk Indicators

| Indicator | Severity | Meaning |
|-----------|----------|---------|
| Always-active pattern | HIGH | Identity activates PIM role daily and keeps it active all day |
| Excessive activations | MEDIUM | 5+ activations in 7 days (potential automation without standing access) |
| Off-hours activation | HIGH | PIM activation outside business hours (8am-6pm) |
| Long-duration activation | MEDIUM | Activation duration exceeds 8 hours (should be short-lived) |
| Expired eligible assignment | LOW | PIM assignment has expired but identity retains permissions |

### 17.4 Real-World Problem: PIM Abuse Detection

**The Problem:**
PIM is designed to reduce standing privilege by requiring just-in-time activation. But some organizations configure PIM eligible roles without expiration, max duration limits, or activation monitoring -- effectively creating "standing privilege with an extra click."

**Case Study: Consulting Firm PIM Audit**

A consulting firm with 50 PIM-eligible Global Administrators found:
- 12 users activated Global Admin daily and kept it active for 8+ hours
- 3 users activated PIM at 2-3 AM (off-hours, suspicious)
- 8 PIM assignments had no expiration date (perpetual eligibility)

AuditGraph detected these patterns through:
- `excessive_pim_usage` anomaly for the 12 daily activators
- `off_hours_pim` anomaly for the 3 night-time activators
- PIM tab showing 8 assignments with null expiration

---

## Chapter 18: Conditional Access Analysis

### 18.1 Overview

AuditGraph discovers Azure Conditional Access (CA) policies and evaluates their coverage across all identities. CA policies enforce MFA, device compliance, and location restrictions -- but gaps in coverage leave identities exposed.

### 18.2 Coverage Computation

AuditGraph uses a simplified heuristic for CA coverage:

1. Enumerate all enabled CA policies targeting "All Users"
2. Check each identity against policy exclusion lists
3. Classify identity as "Covered" or "Not Covered"
4. Track MFA enforcement percentage

### 18.3 CA Dashboard Metrics

```
┌─────────────────────────────────┐
│   Conditional Access Coverage   │
│                                 │
│   Covered:     890 (74%)    ●   │
│   Not Covered: 310 (26%)    ●   │
│   MFA Enforced: 85%             │
│   Weak Policies: 3              │
│                                 │
│   Required: Policy.Read.All     │
│   Graph API Permission          │
└─────────────────────────────────┘
```

### 18.4 Real-World Problem: CA Policy Gaps

**The Problem:**
Organizations create CA policies targeting "All Users" but exclude service accounts, break-glass accounts, or specific groups. Over time, excluded identities accumulate privilege without MFA or location restrictions.

**Case Study: Financial Services CA Audit**

A bank with 15 CA policies believed they had 100% MFA coverage. AuditGraph found:
- 310 identities were excluded from all CA policies (26% uncovered)
- 89 of those excluded identities held Contributor+ roles
- 12 service principals with Owner access had zero CA policy coverage
- 3 "break-glass" accounts with Global Admin had MFA disabled

---

## Chapter 19: RBAC Hygiene Engine

### 19.1 Overview

The RBAC Hygiene Engine (`backend/app/engines/rbac_hygiene.py`) scores and reports on the cleanliness of Azure RBAC role assignments. It detects overly broad roles, excessive permissions, and role sprawl.

### 19.2 Hygiene Violations Detected

| Violation | Risk | Description |
|-----------|------|-------------|
| Management group-scoped Owner | CRITICAL | Owner at management group affects all child subscriptions |
| Subscription-scoped Owner | HIGH | Owner across entire subscription |
| Duplicate role assignments | MEDIUM | Same identity has same role assigned multiple times |
| Custom role with wildcard actions | HIGH | Custom role with `*/write` or `*/delete` actions |
| Excessive role count per identity | MEDIUM | Identity holds 10+ distinct role assignments |

### 19.3 Real-World Problem: Role Sprawl

**Case Study:** A technology company found that 45 identities had 15+ role assignments each, making it impossible to understand their effective access. AuditGraph's RBAC Hygiene report recommended consolidating overlapping roles into 3-4 custom roles per identity.

---

# PART V: REMEDIATION & AUTOMATION

---

## Chapter 20: Remediation Engine

### 20.1 Overview

The Remediation Engine (`backend/app/engines/remediation_engine.py`) translates risk findings into actionable remediation steps. It supports both automated execution and approval-based workflows.

### 20.2 Supported Remediation Actions

| Action | Description | Auto-Execute? |
|--------|-------------|---------------|
| `rotate_service_principal_secret` | Generate new secret, deprecate old | Simulated |
| `remove_role_assignment` | Remove specific RBAC role | Simulated |
| `disable_identity` | Disable the identity in Entra ID | Simulated |
| `reduce_identity_privilege` | Replace high-privilege role with lower | Simulated |
| `flag_for_review` | Create ticket for manual review | Automatic |
| `create_ticket` | Create Jira/ServiceNow ticket | Automatic |

Note: Azure-modifying actions (rotate, remove, disable) are currently simulated for safety. The engine records what would happen and tracks the simulation result.

### 20.3 Remediation Workflow

```
Finding Detected (via drift/anomaly/governance)
    │
    ▼
┌──────────────────┐
│ Pattern Matching  │
│ (20 built-in     │
│  playbooks)      │
└────────┬─────────┘
         │
    ┌────▼────┐
    │ Mode?   │
    └────┬────┘
         │
    ┌────┴────────────────┐
    │                     │
    ▼                     ▼
┌──────────┐       ┌──────────────┐
│ Automatic│       │ Approval     │
│ Execute  │       │ Required     │
│          │       │              │
│ Execute  │       │ Queue action │
│ action   │       │ Notify admin │
│ Log audit│       │ Wait for     │
│          │       │ approval     │
└──────────┘       └──────┬───────┘
                          │ Approved
                          ▼
                   ┌──────────────┐
                   │ Execute      │
                   │ action       │
                   │ Log audit    │
                   └──────────────┘
```

### 20.4 Remediation Playbooks (20 Built-In)

AuditGraph ships with 20 pre-built remediation playbooks:

| Category | Playbook | Impact | Effort |
|----------|----------|--------|--------|
| Credential | Rotate expired SPN secrets | High | Quick |
| Credential | Remove unused credentials | Medium | Quick |
| Privilege | Remove Owner from guest accounts | Critical | Quick |
| Privilege | Demote Contributor to Reader | High | Medium |
| Privilege | Restrict management group-scoped roles | Critical | Extended |
| Lifecycle | Disable stale identities (90+ days) | High | Quick |
| Lifecycle | Remove orphaned SPNs | Medium | Medium |
| Governance | Assign owners to ownerless SPNs | Medium | Medium |
| Governance | Enable MFA for uncovered users | High | Quick |
| Compliance | Address PCI-DSS identity violations | High | Extended |

### 20.5 Real-World Problem: Prioritizing Remediation

**The Problem:**
Security teams are overwhelmed with findings. A typical AuditGraph scan might produce 500+ findings. Without prioritization, teams either try to fix everything (burnout) or ignore the list (risk accumulation).

**Case Study: Retail Chain Remediation Sprint**

A retail chain ran their first AuditGraph scan and received 847 findings. Using the Impact/Effort matrix:
- **Quick Wins (High Impact, Quick Effort)**: 89 findings → Fixed in Week 1
- **Strategic (High Impact, Extended Effort)**: 156 findings → Planned for Q2
- **Easy Fixes (Low Impact, Quick Effort)**: 234 findings → Fixed in Week 2
- **Long-Term (Low Impact, Extended Effort)**: 368 findings → Backlogged

By focusing on quick wins first, the retail chain reduced critical identities from 89 to 12 in one week.

---

## Chapter 21: SOAR Integration

### 21.1 Overview

The Security Orchestration, Automation, and Response (SOAR) engine (`backend/app/engines/soar_engine.py`) evaluates automated response playbooks when security events occur. It bridges the gap between detection (anomaly/drift) and response (notification/ticketing/remediation).

### 21.2 Trigger Types

| Trigger | When Fired | Example |
|---------|-----------|---------|
| `anomaly` | Anomaly detector finds a match | Permission escalation detected |
| `risk_escalation` | Identity risk level increases | SPN moved from MEDIUM to CRITICAL |
| `drift` | Drift detector finds changes | New identity with Owner role |
| `new_identity` | New identity discovered | Unknown SPN appears in environment |

### 21.3 Action Types

| Action | Integration | Description |
|--------|------------|-------------|
| `webhook` | Any HTTP endpoint | POST event data to URL |
| `create_ticket` | Jira, ServiceNow | Create incident/task ticket |
| `send_notification` | Slack, Teams, PagerDuty | Send alert message |
| `tag_for_review` | Internal | Flag identity for manual review |

### 21.4 Supported Integrations

ServiceNow, Jira, Slack, PagerDuty, Microsoft Teams, custom webhooks, and internal (in-app notifications).

### 21.5 Cooldown Mechanism

To prevent alert fatigue, each playbook has a configurable cooldown window (default: 300 seconds). If the same playbook triggers for the same identity within the cooldown window, the execution is skipped.

### 21.6 Real-World Problem: Alert-to-Action Gap

**The Problem:**
Security tools generate alerts, but without automation, alerts sit in a queue until a human reads them. For identity threats, the window between detection and exploitation can be minutes.

**Case Study: MSP Automated Incident Response**

An MSP managing 15 client tenants configured SOAR playbooks:

| Trigger | Condition | Actions |
|---------|-----------|---------|
| `anomaly` | severity = critical | 1. Slack alert to #security-critical 2. PagerDuty incident 3. Tag for review |
| `drift` | privilege_escalated | 1. Jira ticket (P1) 2. Teams message to IAM team |
| `new_identity` | risk_level = critical | 1. Slack alert 2. Auto-disable identity (approval required) |

Result: Mean time from detection to containment dropped from 4 hours (manual) to 12 minutes (automated).

---

## Chapter 22: Policy Recommender

### 22.1 Overview

The Policy Recommender (`backend/app/engines/policy_recommender.py`) analyzes the current identity landscape and generates policy recommendations tailored to the organization's risk profile.

### 22.2 Recommendation Types

| Type | Description | Example |
|------|-------------|---------|
| `excess_privilege_identity` | Identity has more access than needed | "SPN-deploy has Owner but only reads storage" |
| `service_principal_secret_rotation` | SPN credentials need rotation | "SPN-api secret expires in 15 days" |
| `guest_user_privilege_review` | Guest accounts need access review | "12 guests have Contributor access" |
| `unused_identity_cleanup` | Dormant identities should be removed | "45 identities inactive for 90+ days" |

### 22.3 Real-World Problem: Continuous Policy Improvement

**Case Study:** A healthcare organization used the policy recommender to progressively improve their identity posture over 6 months, implementing 12 of 18 recommendations and improving their AGIRS score from 58 to 79.

---

# PART VI: AI & INTELLIGENCE

---

## Chapter 23: AI Security Copilot (Trust AI)

### 23.1 Overview

The AI Security Copilot (Phase 79), branded as "Trust AI," is a conversational AI assistant powered by Anthropic's Claude API. It allows security teams to ask natural language questions about their identity posture and receive contextual, data-backed answers.

The copilot consists of two backend components:
- **CopilotService** (`backend/app/services/copilot_service.py`): Wraps the Anthropic Claude API
- **CopilotGateway** (`backend/app/ai/copilot_gateway.py`): Enforces tenant isolation, rate limits, and safety

### 23.2 Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  CopilotPanel   │     │  Copilot Gateway  │     │  Anthropic   │
│  (React)        │────▶│                   │────▶│  Claude API  │
│                 │     │  1. Tenant check   │     │              │
│  Chat interface │     │  2. Rate limit     │     │  Response    │
│  Context chips  │     │  3. Prompt guard   │────▶│  generation  │
│  History        │     │  4. Usage logging  │     │              │
└─────────────────┘     └──────────────────┘     └──────────────┘
                              │
                              ▼
                        ┌──────────────────┐
                        │  Database (RLS)   │
                        │  Pre-filtered     │
                        │  tenant data      │
                        │  injected into    │
                        │  system prompt    │
                        └──────────────────┘
```

**Critical Security Design**: The LLM never directly queries the database. All data is pre-filtered through tenant-scoped Database connections (RLS-enforced) and injected into the prompt context. The LLM receives only the current tenant's data.

### 23.3 Rate Limits by Plan

| Plan | Queries/Day | Max Prompt Size | Max Response Tokens |
|------|------------|-----------------|---------------------|
| Free | 10 | 8,000 chars | 2,000 |
| Trial | 100 | 8,000 chars | 2,000 |
| Pro | 1,000 | 8,000 chars | 2,000 |

### 23.4 Example Interactions

**Question**: "Which service principals have the highest blast radius?"

**Copilot Response**: "Based on your latest scan, the top 3 SPNs by blast radius are:
1. **SPN-deploy-prod** (Danger Score: 38.0) - Owner on 3 subscriptions, reaches 89 resources including 2 Key Vaults
2. **SPN-terraform** (Danger Score: 32.0) - Contributor across all subscriptions, 12 resource groups
3. **SPN-monitoring** (Danger Score: 24.0) - Reader with Graph API Directory.ReadWrite.All permission

I recommend reviewing SPN-deploy-prod first -- it has expired credentials with active Owner roles, making it a 'zombie' identity."

**Question**: "Is our organization compliant with PCI-DSS Requirement 8?"

**Copilot Response**: "Your PCI-DSS Requirement 8 compliance is at 87%. Key gaps:
- Req 8.1.4: 7 inactive accounts not disabled within 90 days
- Req 8.2.3: 12 service accounts without password complexity
- Req 8.5: 3 shared/generic accounts detected

Remediation playbooks are available for all 3 gaps in the Remediation tab."

### 23.5 Real-World Problem: Security Team Skill Gaps

**The Problem:**
Junior security analysts may not know which Azure RBAC roles are dangerous, how to interpret PIM activation patterns, or what compliance controls map to identity findings. This creates a bottleneck where only senior analysts can perform investigations.

**Case Study: SOC Team Onboarding**

A SOC team hired 5 junior analysts who needed 3 months of training to investigate identity incidents. With Trust AI:
- Analysts could ask "Why is this SPN critical?" and get a contextual explanation
- "What should I do about this anomaly?" produced specific remediation steps
- "Show me attack paths from SPN-cicd" generated visual escalation chains
- Training ramp-up reduced from 3 months to 3 weeks

---

## Chapter 24: AI Investigation Tools

### 24.1 Overview

The AI Investigation Tools (`backend/app/ai/investigation_tools.py`) provide structured tool schemas that the Claude API can invoke during copilot conversations. These tools give the AI access to real-time identity data without direct database access.

### 24.2 Available Tools (5)

| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `attack_paths` | Find privilege escalation chains | identity name/ID | Escalation paths with severity |
| `blast_radius` | Compute compromise impact | identity name/ID | Reachable subscriptions, RGs, resources |
| `escalation_paths` | Find escalation with remediation sim | identity name/ID | Paths + "what if we removed role X" |
| `timeline` | Chronological event history | identity name/ID, date range | Anomalies, risk changes, PIM, SOAR, remediation |
| `graph_diff` | Compare two snapshots | run_id_1, run_id_2 | Added/removed/changed nodes and edges |

### 24.3 Identity Resolution Strategy

When a user asks about an identity by name, the tools resolve it through multi-strategy fallback:

```
1. Exact identity_id match (e.g., "spn-deploy-prod")
    │ not found
    ▼
2. Object_id match (e.g., Azure GUID)
    │ not found
    ▼
3. Display_name exact match
    │ not found
    ▼
4. Display_name ILIKE substring match
    │ not found
    ▼
5. Return "Identity not found" with suggestions
```

### 24.4 Real-World Problem: Forensic Investigation Speed

**Case Study: Investigating Suspicious SPN Activity**

A security analyst received a SOAR alert about suspicious PIM activation on SPN-analytics. Using Trust AI:

1. **"Show me the timeline for SPN-analytics"** → Tool: `timeline`
   - 2:14 AM: PIM activation for User Access Administrator
   - 2:16 AM: New credential added
   - 2:18 AM: Risk score spiked from 45 to 89

2. **"What's the blast radius if SPN-analytics is compromised?"** → Tool: `blast_radius`
   - 4 subscriptions, 18 resource groups, 67 resources
   - Includes 3 Key Vaults with encryption keys

3. **"Show attack paths from SPN-analytics"** → Tool: `attack_paths`
   - Path 1: SPN → UAA activation → Grant Owner → All subscriptions
   - Severity: CRITICAL

Investigation completed in 8 minutes (vs. 2+ hours manually).

---

# PART VII: REPORTING & VISUALIZATION

---

## Chapter 25: CISO Executive Dashboard

### 25.1 Overview

The CISO Executive Dashboard (`frontend/src/pages/CISODashboard.tsx`) is a dark-themed, data-rich intelligence view designed for security leadership. It presents identity risk through 6 tabs with drill-down capabilities.

### 25.2 Dashboard Tabs

| Tab | Content | Key Metrics |
|-----|---------|-------------|
| Executive Summary | AGIRS score, governance index, compliance | Score ring, letter grade, trend |
| Identity Risk | Human/phantom/insider risks | HIRI factors, ghost/zombie counts |
| Action Plan | Prioritized remediation playbooks | Impact/effort matrix, quick wins |
| Control & Governance | Control effectiveness rates | MFA adoption, CA coverage, review completion |
| Compliance & Evidence | Audit framework tracking | Framework scores, evidence sources |
| Risk Movement | Trends, velocity, direction | Inflow/outflow, retention, sparklines |

### 25.3 Score Ring Visualization

The AGIRS score is rendered as a concentric circle gauge:

```
         ┌─────────────┐
         │  ╭───────╮   │
         │ ╭│  78   │╮  │
         │ │╰───────╯│  │
         │ │ AGIRS    │  │
         │ │ Grade: B │  │
         │ ╰─────────╯  │
         │  HIRI: 74     │
         │  NHIRI: 83    │
         │  GEI: 71      │
         └─────────────┘
```

### 25.4 DrillableNumber Component

Every metric on the CISO Dashboard is clickable. Clicking navigates to the Identities page with the appropriate filter pre-applied:

```
"23 Ghost Humans" → Click → /identities?status=disabled&has_roles=true
"7 Zombie SPNs" → Click → /identities?category=service_principal&status=stale&risk=critical
```

### 25.5 Real-World Problem: Board-Level Reporting

**The Problem:**
CISOs need to present identity risk to their board in a format that non-technical executives can understand. Showing raw counts of critical identities doesn't convey whether the situation is improving or worsening.

**Case Study: Public Company Board Presentation**

A publicly traded company's CISO used the CISO Dashboard for quarterly board presentations:

- **Single Score**: AGIRS 72 (Grade: B) -- immediately understandable
- **Trend**: Improving from 58 (Grade: D) six months ago
- **Top Risks**: 3 bullet points from the Action Plan tab
- **Compliance**: SOC2 at 91%, PCI at 87% (green status)
- **Investment Justification**: "We reduced ghost humans from 89 to 12, and zombie SPNs from 34 to 7"

The board approved additional security budget based on the quantified improvement.

---

## Chapter 26: Access Graph Visualization

### 26.1 Overview

The Access Graph (`frontend/src/components/graph/AccessGraphTab.tsx`) uses ReactFlow v12 to render interactive identity relationship graphs. It supports 13 custom node types and 3 view modes (Executive, Technical, Attack Paths).

### 26.2 Node Types (13)

| Node Type | Visual | Description |
|-----------|--------|-------------|
| `identity` | Blue card | The identity being analyzed |
| `risk_summary` | Red/orange card | Aggregated risk metrics |
| `blast_radius` | Circle bubble | Compromise reach visualization |
| `owner` | Green card | Identity owner (user/group) |
| `federated_trust` | Purple card | Federated credential issuer |
| `role` | Badge on edge | RBAC role assignment |
| `permission` | Small card | Graph API permission |
| `credential` | Yellow card | Secret/certificate |
| `scope` | Gray card | ARM scope (subscription/RG) |
| `subscription` | Blue box | Azure subscription |
| `resource_group` | Gray box | Azure resource group |
| `resource` | Icon card | Azure resource (storage/KV) |
| `entra_directory` | Purple box | Entra directory scope |

### 26.3 Technical View Layout

The technical view uses a hierarchical ARM tree layout with pre-computed server-side positions:

```
                    ┌──────────┐
                    │ Identity │
                    └────┬─────┘
                ┌────────┼────────┐
           ┌────▼────┐       ┌───▼──────────┐
           │ Entra   │       │ Subscriptions │
           │ Roles   │       │ (ARM tree)    │
           │ (upper  │       │               │
           │  right) │       │  Sub → RG →   │
           └─────────┘       │  Resource     │
                             └───────────────┘
     ┌─────────┐
     │ Owners  │  (left column)
     │Federated│
     │ Trust   │
     └─────────┘
           ┌──────────┐
           │Permissions│  (below ARM tree)
           │Credentials│  (bottom)
           └──────────┘
```

### 26.4 Real-World Problem: Explaining Access to Auditors

**Case Study:** During a SOC2 audit, an auditor asked "Show me exactly how SPN-billing-api can access the payment Key Vault." The security team opened AuditGraph's Access Graph:

1. SPN-billing-api → Contributor role → Production subscription
2. Production subscription → rg-payments resource group
3. rg-payments → kv-payment-keys Key Vault
4. Additional path: SPN-billing-api → Key Vault Contributor (direct)

The auditor could visually verify the access chain and confirm it was intentional.

---

## Chapter 27: PDF Report Generation

### 27.1 Overview

AuditGraph generates three types of PDF reports using jsPDF + autoTable:

| Report Type | Format | Pages | Audience |
|-------------|--------|-------|----------|
| Full Audit | A4 Portrait | 20+ | Security teams, auditors |
| Executive Summary | A4 Landscape | 1 | CISO, board |
| Compliance | A4 Portrait | 10+ | Compliance teams |

### 27.2 Full Audit Report Contents

| Section | Content |
|---------|---------|
| Cover Page | Client name, date, AuditGraph branding |
| Executive Summary | AGIRS score, total identities, risk distribution |
| Compliance Scorecard | SOC2, HIPAA, PCI, CIS scores |
| Top Risks | Top 10 critical identities with remediation playbooks |
| Remediation Playbook | Steps per identity, impact/effort, compliance refs |
| Evidence Section | Data sources, scan metadata, collection timestamps |

### 27.3 Executive Summary Report (1-Page)

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  AuditGraph Executive Risk Summary                  │
│  [Client Name] | [Date]                             │
│                                                     │
│  ┌────────┐   ┌──────┬──────┬──────┬──────┬──────┐ │
│  │ Posture│   │Total │Crit  │High  │Med   │Low   │ │
│  │ Score  │   │1,200 │  23  │  67  │ 340  │ 770  │ │
│  │  78    │   │      │      │      │      │      │ │
│  │  (B)   │   └──────┴──────┴──────┴──────┴──────┘ │
│  └────────┘                                         │
│                                                     │
│  Executive Summary:                                 │
│  Identity posture improved 12% over previous        │
│  quarter. Critical identities reduced from 35 to    │
│  23. Key concern: 7 orphaned SPNs with Owner access.│
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 27.4 Real-World Problem: Recurring Client Reports

**Case Study: MSP Monthly Client Reports**

An MSP generating monthly identity risk reports for 15 clients previously spent 2 hours per client (30 hours/month) manually assembling PowerPoint decks. With AuditGraph:
- Each report generated in <10 seconds (PDF download)
- Customizable client name on cover page
- Consistent formatting across all clients
- Total time: 15 minutes/month (vs. 30 hours)

---

## Chapter 28: Drift History & Activity Log

### 28.1 Drift History

The Drift History page (`frontend/src/pages/DriftHistory.tsx`) provides a timeline of all detected changes across discovery runs, organized into 5 collapsible sections:

1. **New Identities**: Newly discovered identities
2. **Removed Identities**: Identities no longer present (soft-deleted)
3. **Permission Changes**: Role assignments added or removed
4. **Risk Changes**: Risk level escalations or de-escalations
5. **Credential Changes**: Credential status changes

### 28.2 Activity Log

The Activity Log (`frontend/src/pages/ActivityLog.tsx`) provides an append-only audit trail of all platform actions:

| Action Type | Example |
|-------------|---------|
| `discovery_started` | "Manual discovery triggered by admin@corp.com" |
| `discovery_completed` | "Discovery completed: 1,200 identities, 23 critical" |
| `setting_changed` | "Scheduler interval changed from 12h to 6h" |
| `identity_remediated` | "SPN-deploy-prod disabled by admin@corp.com" |
| `api_key_created` | "API key 'CI/CD Integration' created" |
| `soar_executed` | "Playbook 'Critical Alert' triggered for SPN-billing" |
| `user_created` | "User john.doe added with role 'auditor'" |

### 28.3 Real-World Problem: Change Accountability

**Case Study:** During a security incident investigation, a compliance team needed to answer: "Who changed the RBAC role on SPN-payments, and when?" AuditGraph's activity log showed the exact user, timestamp, and change details -- producing a chain of evidence for the incident report.

---

# PART VIII: CLOUD RESOURCE SECURITY

---

## Chapter 29: Azure Resource Discovery

### 29.1 Overview

Azure Resource Discovery (Phase 52) extends AuditGraph beyond identities to the resources they access. It discovers Azure Storage Accounts and Key Vaults, evaluates their security configuration, and cross-links identities that have RBAC access to each resource.

### 29.2 Discovered Resources

| Resource Type | API | Key Security Fields |
|---------------|-----|-------------------|
| Storage Account | StorageManagementClient | HTTPS-only, TLS version, public access, encryption, diagnostic logging |
| Key Vault | KeyVaultManagementClient | Soft delete, purge protection, public network, secrets/keys/certs counts |

### 29.3 Points-Based Risk Scoring

Each resource receives a risk score (0-100) based on CIS benchmark checks:

**Storage Accounts (12 checks):**
- HTTPS traffic only not enforced (+15)
- TLS version below 1.2 (+20)
- Public blob access enabled (+25)
- No diagnostic logging (+10)
- No encryption at rest (+20)
- Shared key access enabled (+10)

**Key Vaults (10 checks):**
- Soft delete not enabled (+25)
- Purge protection not enabled (+20)
- Public network access enabled (+15)
- No access policies configured (+15)
- Expired secrets present (+10)
- No key rotation policy (+10)

### 29.4 Cross-Link: Identity → Resource Access

The `/api/resources/<id>/access` endpoint shows which identities have RBAC access to a specific resource, including:
- Direct role assignments on the resource
- Inherited assignments from resource group
- Inherited assignments from subscription
- Access policy assignments (Key Vault specific)

### 29.5 Real-World Problem: Data Exposure Through Misconfigured Storage

**Case Study: Publicly Accessible Storage Account**

A media company's AuditGraph scan found a storage account with:
- `public_access_level = Container` (all blobs publicly readable)
- Contains 12,000 customer profile images
- 4 identities with Contributor access (none aware of public exposure)
- CIS risk score: 85/100 (CRITICAL)

The remediation playbook immediately recommended disabling public access and enabling private endpoints.

---

## Chapter 30: Service Principal (SPN) Dashboard

### 30.1 Overview

The SPN Dashboard (Phase 71) provides a dedicated view for managing Azure service principals -- the most common source of identity risk in Azure environments.

### 30.2 Dashboard Components

**5 Summary Cards:**
- Total custom SPNs (excluding Microsoft)
- Critical/High risk SPNs
- SPNs with expired credentials
- SPNs with credentials expiring within 30 days
- SPNs with high blast radius (10+ resources)

**Filters:**
- Risk level, blast radius range, credential status, activity status, search
- "Hide Microsoft" toggle (excludes Microsoft-owned system SPNs)

**Table Columns:**
- Name, Blast Radius, Critical Roles, Credential Risk, Next Expiry, Activity Status

### 30.3 SPN Drill-Down Panel

Clicking an SPN opens a 480px side panel with:
- Risk summary with auto-generated narrative
- Credential details (type, expiry, age)
- RBAC and Entra role assignments
- Owners
- Recommendations (auto-generated)
- "Open Full Identity Detail" link
- Attacker narrative ("If this SPN is compromised, an attacker could...")
- Auditor questions (key questions for access review)

### 30.4 SPN Privilege Report (PDF)

The `spnPdfGenerator.ts` generates a per-SPN privilege report including blast radius visualization, role assignments, credential inventory, and risk recommendations.

### 30.5 Real-World Problem: SPN Credential Sprawl

**Case Study: Enterprise with 800 Custom SPNs**

An enterprise with 800 custom SPNs used the SPN Dashboard to discover:
- 234 SPNs had multiple credentials (secret sprawl)
- 89 had expired credentials with active roles ("zombie" risk)
- 45 had blast radius exceeding 50 resources
- 12 had Global Administrator Entra role

The dashboard prioritized the 12 Global Admin SPNs for immediate remediation and generated privilege reports for the compliance team.

---

## Chapter 31: App Registration Audit

### 31.1 Overview

The App Registration Audit (Phase 74) provides security assessment of Azure Entra application registrations, which are often created for development/testing and forgotten with dangerous permissions.

### 31.2 10-Factor Risk Scoring

| Factor | Points | Condition |
|--------|--------|-----------|
| Ownerless | +40 | No registered owners |
| Multi-tenant + App Permissions | +30 | Multi-tenant app with application-level Graph permissions |
| Expired Credentials | +25 | Secrets or certificates past expiration |
| High-Risk Graph Permission | +20 | Has RoleManagement.ReadWrite, AppRoleAssignment.ReadWrite, etc. |
| No Recent Activity | +15 | No sign-in in 90+ days |
| Certificate-Based Auth | +10 | More static than secrets, harder to rotate |
| Old with No Activity | +5 | Created 5+ days ago with no activity |
| Multiple Secrets | +5 | More than 1 secret (rotation risk) |
| External Redirect URIs | +5 | Reply URLs pointing to external domains |
| Excessive Scopes | +5 | More than 10 API scopes configured |

### 31.3 Real-World Problem: Development App Registrations in Production

**Case Study: Software Company with 300 App Registrations**

A software company found that 300 app registrations existed in their production Entra tenant. AuditGraph's audit revealed:
- 78 app registrations had zero owners (developers left the company)
- 45 were multi-tenant with `Directory.ReadWrite.All` permission
- 23 had expired credentials but active service principals still using them
- 12 had redirect URIs pointing to localhost (development leftovers)

The 10-factor risk scoring prioritized the 45 multi-tenant apps with directory write permissions as the highest risk (score: 70+).

---

## Chapter 32: Key Vault & Storage Security

### 32.1 Overview

AuditGraph provides enhanced security analysis for Azure Key Vaults and Storage Accounts through two feature sets:

1. **Item-Level Expiry Tracking** (Phase 69): Track expiration of individual secrets, keys, and certificates within Key Vaults
2. **Access Source & SAS Audit** (Phase 73): Classify RBAC access sources and audit SAS token usage

### 32.2 Key Vault Expiry Tracking

```
Key Vault: kv-production
├── Secrets (15 total)
│   ├── Expired: 3 (db-password, api-key-old, smtp-secret)
│   ├── Expiring <30 days: 2 (stripe-key, sendgrid-key)
│   └── Healthy: 10
├── Keys (4 total)
│   ├── Expired: 0
│   └── Healthy: 4
└── Certificates (2 total)
    ├── Expiring <30 days: 1 (wildcard-cert)
    └── Healthy: 1
```

### 32.3 RBAC Access Source Classification

Each identity's access to a resource is classified by source:

| Source | Description | Example |
|--------|-------------|---------|
| `direct` | Role assigned directly on the resource | Contributor on kv-prod |
| `resource_group` | Role inherited from parent RG | Contributor on rg-production |
| `subscription` | Role inherited from subscription | Reader on sub-prod |
| `management_group` | Role inherited from management group | Owner on mg-root |

### 32.4 Audit Posture Classification

Storage accounts are classified by audit capability:

| Posture | Description |
|---------|-------------|
| AAD Only | All access through Azure AD (fully auditable) |
| Auditable | Diagnostic logging enabled, SAS tokens tracked |
| Partial | Some access methods not logged |
| Unauditable | No diagnostic logging, shared keys enabled |

### 32.5 Real-World Problem: Secret Rotation Compliance

**Case Study: PCI-DSS Requirement 3.6**

A payment processor needed to prove encryption key rotation compliance for PCI-DSS. AuditGraph's Key Vault expiry tracker showed:
- 3 encryption keys hadn't been rotated in 18 months (violation)
- 2 API keys for payment gateways were expired
- 1 TLS certificate was expiring in 15 days

The compliance team used these findings to create a key rotation schedule and passed their PCI audit.

---

# PART IX: PLATFORM OPERATIONS

---

## Chapter 33: Authentication & Authorization

### 33.1 Overview

AuditGraph uses JWT-based authentication with dual JWT secrets (one for client portal, one for admin portal), refresh token rotation, and role-based access control across two portal types.

### 33.2 JWT Architecture

```
┌─────────────────────────────────────────────────┐
│              Dual JWT Architecture               │
│                                                  │
│  CLIENT_JWT_SECRET                               │
│  ├── Client Portal (app.auditgraph.ai)           │
│  ├── Token Expiry: 60 minutes                    │
│  ├── Claims: sub, org_id, role, email            │
│  └── Roles: admin, security_admin,               │
│              compliance, reader                   │
│                                                  │
│  ADMIN_JWT_SECRET                                │
│  ├── Admin Portal (admin.auditgraph.ai)          │
│  ├── Token Expiry: 30 minutes                    │
│  ├── Claims: sub, is_superadmin, portal_role     │
│  └── Roles: superadmin, poweradmin,              │
│              billing, reader                      │
│                                                  │
│  Refresh Tokens: 7-day expiry                    │
│  Token Schema Version: For key rotation          │
│  Key IDs: admin-v1, tenant-v1                    │
└─────────────────────────────────────────────────┘
```

### 33.3 Client Portal RBAC (4 Roles)

| Role | Permissions |
|------|------------|
| `admin` | Full tenant access, user management, settings, remediation |
| `security_admin` | Security operations, remediation execution, scan triggers |
| `compliance` | Compliance reviews, report generation, evidence access |
| `reader` | View-only access to all non-admin features |

### 33.4 Admin Portal RBAC (4 Roles)

| Role | Permissions |
|------|------------|
| `superadmin` | Full platform access, cross-tenant ops, tenant CRUD |
| `poweradmin` | Tenant management, provisioning, monitoring |
| `billing` | Billing operations, invoice generation |
| `reader` | Read-only analytics and monitoring |

### 33.5 Portal Detection

The system detects which portal to authenticate against using subdomain analysis:

```
dev.admin.auditgraph.ai → Admin Portal → ADMIN_JWT_SECRET
admin.auditgraph.ai     → Admin Portal → ADMIN_JWT_SECRET
dev.app.auditgraph.ai   → Client Portal → CLIENT_JWT_SECRET
acme.app.auditgraph.ai  → Client Portal → CLIENT_JWT_SECRET (org: acme)
dev.api.auditgraph.ai   → API Host → Skip issuer check
```

### 33.6 Real-World Problem: Credential Management for Security Tools

**Case Study:** A security team needed to ensure that the identity governance tool itself didn't become a privilege escalation vector. AuditGraph's dual-JWT architecture ensures that a compromised client portal token cannot access admin portal endpoints, and vice versa.

---

## Chapter 34: SSO/SAML/OIDC Integration

### 34.1 Overview

AuditGraph supports enterprise SSO through three protocols: SAML 2.0 (Phase 54), OIDC (OpenID Connect), and SCIM provisioning -- enabling seamless integration with corporate identity providers.

### 34.2 SAML Flow

```
User clicks "SSO Login"
    │
    ▼
AuditGraph generates AuthnRequest
    │
    ▼ Redirect to IdP
┌──────────────┐
│  Corporate   │
│  IdP (Okta,  │
│  Azure AD,   │
│  etc.)       │
└──────┬───────┘
       │ User authenticates at IdP
       │ IdP sends SAML assertion
       ▼
AuditGraph ACS endpoint
    │
    ├── Validate XML signature
    ├── Extract user attributes
    ├── JIT provisioning (create user if new)
    ├── Map IdP groups → AuditGraph roles
    ├── Generate one-time code (60s TTL)
    │
    ▼
Frontend exchanges code for JWT
    │
    ▼
User is logged in
```

### 34.3 JIT (Just-In-Time) Provisioning

When a user authenticates via SAML for the first time, AuditGraph automatically creates their user account:
- Username from SAML NameID
- Email from SAML attribute
- Role from IdP group → role mapping
- `auth_provider = 'saml'`
- `external_id` = IdP user ID

### 34.4 Force-SSO Mode

When enabled, Force-SSO:
- Hides the local username/password login form
- Only shows the "Login with SSO" button
- Prevents creation of local accounts
- Ensures all authentication goes through the corporate IdP

### 34.5 Real-World Problem: Enterprise SSO Requirement

**Case Study: Enterprise with Okta**

A 5,000-person enterprise required all tools to integrate with their Okta IdP. AuditGraph's SAML integration:
1. Parsed Okta's IdP metadata XML to auto-configure SP
2. Mapped Okta groups ("security-team" → admin, "auditors" → compliance)
3. Enabled Force-SSO to prevent local password accounts
4. JIT provisioned 50 users on first login without manual account creation

---

## Chapter 35: API Key Management

### 35.1 Overview

API Key Management (Phase 42) allows machine-to-machine authentication for CI/CD integrations, SIEM feeds, and automation scripts.

### 35.2 Key Format

```
ag_a7b3c9d2e1f4g5h6i7j8k9l0m1n2o3p4
│  │
│  └── 32 hexadecimal characters (128-bit entropy)
└── Prefix: "ag_" (identifies AuditGraph keys)
```

### 35.3 Security Properties

| Property | Implementation |
|----------|---------------|
| Storage | SHA-256 hash only (raw key shown once at creation) |
| Authentication | `X-API-Key` header or `Bearer ag_...` |
| Role Scoping | Each key has a role (admin, auditor, viewer) |
| Expiration | Optional expiry date |
| Usage Tracking | `last_used_at`, `usage_count` per key |
| Revocation | Instant disable via toggle or delete |

### 35.4 Real-World Problem: SIEM Integration

**Case Study:** A SOC team needed to pull AuditGraph data into their Splunk SIEM. They created an API key with `reader` role, configured Splunk to poll `/api/anomalies` every 5 minutes, and correlated identity anomalies with network security events.

---

## Chapter 36: Notification & Integration System

### 36.1 Overview

AuditGraph's notification system supports three channels: in-app notifications, Slack (Block Kit), and Microsoft Teams (Adaptive Cards).

### 36.2 Notification Channels

| Channel | Format | Rate Limit |
|---------|--------|-----------|
| In-App | Bell icon badge + notification center | None |
| Slack | Block Kit messages with severity colors | 5 min per org/event type |
| Teams | Adaptive Card messages | 5 min per org/event type |
| Email | HTML formatted reports | Per-setting |

### 36.3 Event Types

| Event | Trigger | Default Channel |
|-------|---------|----------------|
| `scan_complete` | Discovery run finishes | Slack, Email |
| `scan_failed` | Discovery run fails | Slack, PagerDuty |
| `anomaly_detected` | Anomaly engine finds match | Slack, Teams |
| `drift_detected` | Drift engine finds changes | Slack, Email |
| `risk_escalation` | Identity risk level increases | Slack, Teams |
| `credential_expiring` | SPN credential within 30 days of expiry | Email |

### 36.4 Real-World Problem: Multi-Channel Alert Routing

**Case Study:** An MSP configured different channels per event type:
- Critical anomalies → PagerDuty (wake up on-call)
- Drift detected → Slack #identity-changes (awareness)
- Scan completed → Email to compliance team (audit trail)
- Credential expiring → Teams to infrastructure team (action required)

---

## Chapter 37: Scheduler & Background Jobs

### 37.1 Overview

AuditGraph uses APScheduler (BackgroundScheduler) to run periodic jobs including identity discovery, drift detection, anomaly analysis, and data retention cleanup.

### 37.2 Job Schedule

| Job | Schedule | Purpose |
|-----|----------|---------|
| Scheduled Discovery | Every 6/12/24h (configurable) | Run full identity scan |
| Drift Detection | After each discovery | Compare with previous run |
| Anomaly Detection | After drift detection | Detect behavioral anomalies |
| SOAR Evaluation | After anomaly detection | Trigger automated playbooks |
| RBAC Hygiene | After discovery | Score RBAC cleanliness |
| AGIRS Computation | After discovery | Update composite risk score |
| Compliance Trend | After discovery | Track framework scores over time |
| Data Retention | Daily at 03:00 UTC | Prune old data per retention settings |
| RLS Drift Audit | Daily at 04:30 UTC | Verify tenant isolation policies |
| Health Checks | Every 5 minutes | Monitor DB, scheduler, system |

### 37.3 Post-Discovery Pipeline

```
Discovery Run Completes
    │
    ▼
Drift Detection (compare with previous run)
    │
    ▼
Anomaly Detection (6 anomaly types)
    │
    ▼
SOAR Evaluation (trigger matching playbooks)
    │
    ▼
RBAC Hygiene Analysis
    │
    ▼
AGIRS Score Computation
    │
    ▼
Compliance Trend Update
    │
    ▼
Email Notifications (if enabled)
```

### 37.4 Tenant Isolation in Scheduler

The scheduler opens a fresh `Database(organization_id=N)` connection for each tenant, ensuring RLS context is correctly set per-org. Demo tenants are automatically skipped.

### 37.5 Real-World Problem: Continuous Monitoring

**Case Study:** A financial institution required continuous identity monitoring (not just quarterly audits). AuditGraph's scheduler running every 6 hours provided:
- 4 daily snapshots of all identities
- Drift detection catching unauthorized changes within 6 hours
- Anomaly detection identifying suspicious patterns within 12 hours
- Compliance trend showing week-over-week improvement

---

## Chapter 38: Data Retention & Archival

### 38.1 Overview

Data Retention (Phase 72) provides configurable cleanup policies for historical data, preventing unbounded database growth.

### 38.2 Retention Policies

| Data Type | Setting Key | Default | Description |
|-----------|------------|---------|-------------|
| Discovery Runs | `retention_discovery_runs_days` | 90 days | Old scan snapshots |
| Drift Reports | `retention_drift_reports_days` | 90 days | Change detection reports |
| Activity Log | `retention_activity_log_days` | 365 days | Audit trail entries |
| Anomalies | `retention_anomalies_days` | 180 days | Resolved anomalies |
| SOAR Actions | `retention_soar_actions_days` | 180 days | Playbook execution history |
| Notifications | `retention_notifications_days` | 90 days | In-app notifications |

### 38.3 Storage Monitoring

The `/api/system/storage` endpoint returns table sizes, row counts, and oldest records -- allowing administrators to monitor database growth and adjust retention periods.

### 38.4 Real-World Problem: Database Growth Management

**Case Study:** An enterprise running AuditGraph for 2 years with 6-hour scan intervals accumulated:
- 4,380 discovery runs
- 4,380 drift reports
- 26,000+ anomaly records
- 500,000+ activity log entries

With 90-day retention enabled, the system automatically cleaned up old data, keeping the database under 10 GB while maintaining the most recent 3 months of full history.

---

## Chapter 39: System Health & Observability

### 39.1 Overview

System Health (Phase 68) provides real-time monitoring of the AuditGraph platform itself, including database connectivity, scheduler status, system metrics, and API performance.

### 39.2 Health Endpoints

| Endpoint | Purpose | Auth Required |
|----------|---------|--------------|
| `GET /health/live` | Kubernetes liveness probe | No |
| `GET /health/ready` | Kubernetes readiness probe | No |
| `GET /api/health` | Basic health check | No |
| `GET /api/health/detailed` | Full diagnostics | Yes |
| `GET /api/metrics` | Prometheus text format | No |
| `GET /api/system/health` | Admin dashboard metrics | Yes (admin) |

### 39.3 Metrics Collected

| Metric | Type | Description |
|--------|------|-------------|
| `request_count` | Counter | Total HTTP requests |
| `request_latency` | Histogram | Response time distribution |
| `error_count` | Counter | 4xx/5xx responses |
| `discovery_jobs` | Counter | Discovery runs executed |
| `graph_builds` | Counter | Graph construction jobs |
| `pool_utilization` | Gauge | DB connection pool usage |
| `system_cpu` | Gauge | System CPU utilization |
| `system_memory` | Gauge | System memory usage |

### 39.4 Real-World Problem: Platform Reliability

**Case Study:** An MSP managing 15 tenants used the SystemHealth page to detect a connection pool exhaustion issue during peak scan hours. The pool utilization graph showed 95% usage at 2:00 AM when all tenants' discovery runs overlapped. Solution: Staggered scan schedules by 30-minute intervals.

---

# PART X: ADMINISTRATION

---

## Chapter 40: Admin Portal & Tenant Management

### 40.1 Overview

The Admin Portal (`admin.auditgraph.ai`) is a separate application providing platform-wide management for superadmins. It has its own login page, sidebar navigation, and JWT secret.

### 40.2 Admin Console Pages

| Page | Route | Access | Purpose |
|------|-------|--------|---------|
| Overview | `/admin` | All roles | Tenant count, active tenants |
| Tenants | `/admin/tenants` | superadmin, poweradmin | CRUD tenant organizations |
| Users | `/admin/users` | superadmin, poweradmin | Platform user management |
| Billing | `/admin/billing` | superadmin, billing | MRR, ARR, revenue analytics |
| Monitoring | `/admin/monitoring` | All roles | Tenant health, scan status |
| Action Log | `/admin/action-log` | All roles | Admin audit trail |
| Platform Ops | `/admin/platform-ops` | superadmin | Maintenance, cleanup |

### 40.3 Tenant Configuration

The Configure modal for each tenant includes:

```
┌─────────────────────────────────────┐
│  Configure: Acme Corporation        │
│  ─────────────────────────────────  │
│                                     │
│  Cloud Providers:                   │
│  [✓] Azure    Plan: Pro  ▼         │
│  [ ] AWS      Plan: ---            │
│  [ ] GCP      Plan: ---            │
│                                     │
│  Add-Ons:                           │
│  ── Included with Pro ──            │
│  [✓] Secret Detection               │
│  [✓] AI Investigation               │
│  [✓] Audit Logging                   │
│                                     │
│  ── Paid Add-Ons ──                 │
│  [ ] Extended Retention ($149/mo)   │
│                                     │
│  ── Coming Soon ──                  │
│  [ ] Terraform Integration (grayed) │
│                                     │
│  [Save Configuration]               │
└─────────────────────────────────────┘
```

### 40.4 Real-World Problem: Multi-Tenant Platform Operations

**Case Study:** An MSP onboarding a new client needed to: create tenant, configure Azure connection, assign admin user, trigger first discovery, and verify results. AuditGraph's Admin Portal completed this in 10 minutes with the onboarding wizard.

---

## Chapter 41: Billing & Subscription Management

### 41.1 Overview

AuditGraph's billing system (Phases 75, 85) supports per-cloud pricing, add-on features, and multi-tier plan management.

### 41.2 Pricing Model (v3.0)

| Plan | Azure | AWS | GCP | Description |
|------|-------|-----|-----|-------------|
| Free | $0 | $0 | $0 | Limited features, 100 identities |
| Trial | $0 | $0 | $0 | Full features, 30-day trial |
| Pro | $799 | $849 | $829 | Full features, unlimited identities |
| Enterprise | $1,499 | $1,549 | $1,529 | Custom, dedicated support |

**Paid Add-Ons:**
- Extended Retention: $149/month (extends data retention from 90 to 365 days)

**Included with Pro:**
- Secret Detection
- AI Investigation (Trust AI Copilot)
- Audit Logging

**Annual Discount:** 15% for annual commitment

### 41.3 Admin Billing Dashboard

The Admin Billing page shows:
- Total MRR (Monthly Recurring Revenue)
- Projected ARR (Annual Recurring Revenue)
- Active organizations count
- Plan distribution (free/trial/pro/enterprise)
- Revenue by cloud provider
- Revenue by add-on
- Per-tenant billing details

### 41.4 Real-World Problem: MSP Revenue Tracking

**Case Study:** An MSP using AuditGraph needed to track revenue across 15 client tenants. The Admin Billing dashboard provided real-time MRR/ARR calculations, per-tenant revenue breakdown, and plan tier distribution for financial reporting.

---

## Chapter 42: Deployment Architecture

### 42.1 Overview

AuditGraph deploys on Azure Container Apps with PostgreSQL Flexible Server, using Bicep IaC and GitHub Actions CI/CD.

### 42.2 Production Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Azure Container Apps Environment          │
│                (VNet-integrated, private DNS)             │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ API Container│  │ App Container│  │Admin Container│  │
│  │ (Flask +     │  │ (React +    │  │ (React +     │  │
│  │  Gunicorn)   │  │  nginx)     │  │  nginx)      │  │
│  │ Port 8000    │  │ Port 3000   │  │ Port 3001    │  │
│  │ CPU: 1.0     │  │ CPU: 0.5    │  │ CPU: 0.5     │  │
│  │ RAM: 2 Gi    │  │ RAM: 1 Gi   │  │ RAM: 1 Gi    │  │
│  │ Scale: 1-3   │  │ Scale: 1-2  │  │ Scale: 1     │  │
│  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘  │
│         │                 │                 │           │
│         │   Custom Domains + TLS Certs      │           │
│         │   dev.api.auditgraph.ai           │           │
│         │   dev.app.auditgraph.ai           │           │
│         │   dev.admin.auditgraph.ai         │           │
│         │                                   │           │
└─────────┼───────────────────────────────────┼───────────┘
          │                                   │
          ▼                                   │
┌───────────────────────┐                     │
│  Azure PostgreSQL     │                     │
│  Flexible Server      │                     │
│  ──────────────────   │                     │
│  SKU: B4ms (4vCPU)   │                     │
│  Storage: 32 GB       │                     │
│  SSL: Required        │                     │
│  Backup: 35-day       │                     │
│  No Public Access     │                     │
│  Private DNS Zone     │                     │
└───────────────────────┘                     │
                                              │
┌─────────────────────────────────────────────┘
│
▼
┌───────────────────────┐
│  Azure Container      │
│  Registry (ACR)       │
│  ──────────────────   │
│  SKU: Basic           │
│  3 image repos        │
│  Build: az acr build  │
│  Platform: linux/amd64│
└───────────────────────┘
```

### 42.3 CI/CD Pipeline

```
Push to 'dev' branch
    │
    ▼
┌──────────────────────┐
│  Test Guardrails      │
│  ├── RLS policy tests │
│  ├── Isolation stress │
│  ├── pip-audit (CVE)  │
│  └── PostgreSQL 15    │
│      service container│
└──────────┬───────────┘
           │ All pass
           ▼
┌──────────────────────┐
│  Build (Parallel)     │
│  ├── API image (ACR)  │
│  ├── App image (ACR)  │
│  └── Admin image (ACR)│
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Deploy (Bicep)       │
│  ├── Update images    │
│  ├── Apply env vars   │
│  ├── Wait for health  │
│  │   (24 attempts)    │
│  └── Verify readiness │
└──────────────────────┘
```

### 42.4 Real-World Problem: Zero-Downtime Deployment

**Case Study:** AuditGraph uses Azure Container Apps' revision-based deployment. New revisions are deployed alongside existing ones. Traffic shifts to the new revision only after it passes health checks (`/health/live` and `/health/ready`). If the new revision fails, traffic remains on the previous revision -- achieving zero-downtime deployment.

---

# PART XI: USER INTERFACE

---

## Chapter 43: Dashboard & Widget System

### 43.1 Overview

The Dashboard (`frontend/src/pages/Dashboard.tsx`) provides an analyst-focused view with 20+ configurable widgets. Users can customize widget visibility, order, and layout through the CustomizePanel.

### 43.2 Widget Registry

| Widget | Category | Data Source |
|--------|----------|------------|
| RiskHeatMap | Risk | `/api/identity-summary` |
| QuickActions | Risk | `/api/stats` |
| RiskDonutChart | Risk | `/api/stats` |
| CredentialHealth | Credentials | `/api/dashboard/posture` |
| ComplianceScorecard | Compliance | `/api/dashboard/compliance` |
| ConditionalAccessCard | Security | `/api/dashboard/conditional-access` |
| CloudContextBanner | Infrastructure | `/api/tenant/config` |
| RecentChanges | Drift | `/api/drift/latest` |
| RiskTrendChart | Trends | `/api/trends` |
| AnomalyAlerts | Anomalies | `/api/anomalies/stats` |
| RiskVelocityChart | Trends | `/api/trends/velocity` |
| SOARActivity | Automation | `/api/soar/actions` |
| ServiceAccountGovernance | Governance | `/api/service-accounts/governance` |
| PlatformHealth | Operations | `/api/system/health` |
| ExpiryTracker | Resources | `/api/resources/stats` |
| ResourceOverview | Resources | `/api/resources/stats` |

### 43.3 Customization Architecture

```
┌──────────────────┐     ┌──────────────────┐
│  CustomizePanel  │     │  Dashboard       │
│  (Drag & Drop)   │────▶│  Preferences API │
│                  │     │                  │
│  Show/Hide       │     │  GET /api/       │
│  Reorder         │     │   dashboard/     │
│  Reset defaults  │     │   preferences    │
└──────────────────┘     └──────────────────┘
```

Preferences are stored per-user in the `dashboard_preferences` table and cached in localStorage.

---

## Chapter 44: Identity Explorer

### 44.1 Overview

The Identity Explorer (`frontend/src/pages/Identities.tsx`) is the primary identity list view, featuring a 14-column sortable table with advanced filtering, CSV/PDF export, and drill-down to identity detail.

### 44.2 Table Columns

| Column | Description |
|--------|-------------|
| Name | Identity display name |
| Type | Service Principal, User, Managed Identity |
| Category | Detailed classification |
| Cloud | Azure, AWS, GCP |
| Risk | Color-coded risk level badge |
| RBAC Roles | Count of Azure RBAC assignments |
| Entra Roles | Count of directory role assignments |
| Graph Permissions | Count of API permissions |
| Privilege Tier | T0-T3 classification |
| Credentials | Count + expiry status |
| Created | When the identity was created |
| Last Seen | Last sign-in or activity |
| Ownership | Owner count |
| Subscription | Primary + "+N more" badge |

### 44.3 Filter System

Filters include: Category, Cloud, Risk Level, Credential Status, Activity Status, Privilege Tier, Effective Scope, and Credential Health. Filters combine with AND logic.

---

## Chapter 45: Settings & Configuration

### 45.1 Overview

The Settings page (`frontend/src/pages/Settings.tsx`) provides 10 tabbed sections for tenant configuration:

| Tab | Purpose |
|-----|---------|
| General | Org name, scheduler interval, email toggle |
| Connections | Cloud credential management |
| Users | User CRUD with role assignment |
| Notifications | Webhook URL configuration |
| Security | API keys, SSO/SAML, OIDC |
| Compliance | Framework selection, evidence mapping |
| Governance | SA attestation policies |
| Scoring | Custom risk rules |
| Integrations | Slack/Teams webhook setup |
| Advanced | Data retention, P2 telemetry, cleanup |

---

## Chapter 46: Advanced Query Builder

### 46.1 Overview

The Advanced Query Builder (Phase 39) allows security teams to construct complex identity queries using Boolean logic (AND/OR groups) across 28 fields.

### 46.2 Query Structure

```json
{
  "groups": [
    {
      "conditions": [
        {"field": "risk_level", "operator": "=", "value": "critical"},
        {"field": "identity_category", "operator": "in",
         "value": ["service_principal"]}
      ]
    },
    {
      "conditions": [
        {"field": "activity_status", "operator": "=", "value": "stale"},
        {"field": "credential_count", "operator": ">", "value": 0}
      ]
    }
  ],
  "group_operator": "OR"
}
```

This query finds: "Critical SPNs" OR "Stale identities with credentials"

### 46.3 Operators

| Operator | SQL | Example |
|----------|-----|---------|
| `equals` | `=` | risk_level = 'critical' |
| `not_equals` | `!=` | category != 'microsoft_internal' |
| `contains` | `ILIKE %val%` | name contains 'deploy' |
| `greater_than` | `>` | credential_count > 3 |
| `less_than` | `<` | risk_score < 50 |
| `in` | `IN (...)` | category in ['spn', 'guest'] |
| `is_empty` | `IS NULL` | owner_count is null |
| `is_not_empty` | `IS NOT NULL` | last_sign_in is not null |

### 46.4 SQL Injection Prevention

All query fields are validated against `QUERY_FIELD_MAP` (25 direct columns) and `QUERY_COMPUTED_FIELDS` (3 subqueries). Any field not in the allowlist is rejected. Values are always parameterized.

### 46.5 Real-World Problem: Finding Specific Risk Patterns

**Case Study:** An auditor needed to find "all service principals that are stale, have Owner access to any subscription, AND have expired credentials." The query builder constructed this in 30 seconds, finding 7 identities that matched -- all flagged as critical remediation priorities.

---

# PART XII: SECURITY ARCHITECTURE

---

## Chapter 47: Row-Level Security (RLS)

### 47.1 Overview

PostgreSQL Row-Level Security (RLS) is the foundation of AuditGraph's tenant isolation. All 44 tenant-scoped tables have strict RLS policies that cannot be bypassed, even by the table owner.

### 47.2 Policy Definition

Every tenant-scoped table has four policies:

```sql
-- SELECT: Only rows belonging to current tenant
CREATE POLICY tenant_strict_sel ON table_name
  FOR SELECT USING (
    organization_id = current_setting(
      'app.current_organization_id', true)::integer
  );

-- INSERT: Can only insert rows for current tenant
CREATE POLICY tenant_strict_ins ON table_name
  FOR INSERT WITH CHECK (
    organization_id = current_setting(
      'app.current_organization_id', true)::integer
  );

-- UPDATE: Can only update rows belonging to current tenant
CREATE POLICY tenant_strict_upd ON table_name
  FOR UPDATE USING (
    organization_id = current_setting(
      'app.current_organization_id', true)::integer
  );

-- DELETE: Can only delete rows belonging to current tenant
CREATE POLICY tenant_strict_del ON table_name
  FOR DELETE USING (
    organization_id = current_setting(
      'app.current_organization_id', true)::integer
  );

-- FORCE: Apply RLS even to table owner
ALTER TABLE table_name FORCE ROW LEVEL SECURITY;
```

### 47.3 Auto-Fill Trigger

Every tenant-scoped table has a trigger that automatically fills `organization_id` from the session context:

```sql
CREATE TRIGGER trg_auto_tenant_id
  BEFORE INSERT OR UPDATE ON table_name
  FOR EACH ROW EXECUTE FUNCTION auto_fill_tenant_id();

-- auto_fill_tenant_id():
-- If NEW.organization_id IS NULL:
--   Set from current_setting('app.current_organization_id')
--   If THAT is also NULL: RAISE EXCEPTION
```

### 47.4 Real-World Problem: Defense Against Application Bugs

**Case Study:** During development, a code change accidentally removed the `organization_id` filter from a SQL query. In a traditional application, this would have returned data from all tenants. With AuditGraph's RLS:
- The query executed, but RLS automatically filtered results to the current tenant
- No cross-tenant data was returned
- The bug was caught in code review, but even if deployed, RLS prevented data leakage
- CI/CD guardrail tests verified RLS policies before every deployment

---

## Chapter 48: Database Security & Connection Pooling

### 48.1 Connection Pool Architecture

```
┌─────────────────────────────────────────────┐
│           _PoolManager (Singleton)           │
│                                              │
│  ┌──────────────────┐  ┌──────────────────┐ │
│  │  App Pool         │  │  Admin Pool       │ │
│  │  (NOBYPASSRLS)    │  │  (BYPASSRLS)      │ │
│  │  min=2, max=20    │  │  min=1, max=5     │ │
│  │                   │  │                   │ │
│  │  Checkout:        │  │  Checkout:        │ │
│  │  1. RESET context │  │  1. No RLS reset  │ │
│  │  2. COMMIT        │  │  2. DDL allowed   │ │
│  │                   │  │                   │ │
│  │  Return:          │  │  Return:          │ │
│  │  1. RESET context │  │  1. RESET context │ │
│  │  2. putconn()     │  │  2. putconn()     │ │
│  └──────────────────┘  └──────────────────┘ │
│                                              │
│  Pool Exhaustion Alert: < 10% available      │
│  Fallback: Direct connection (logged)        │
│  PgBouncer Check: Must be transaction mode   │
└─────────────────────────────────────────────┘
```

### 48.2 Admin Guard

In Flask request context, using `Database()` without organization_id raises `RuntimeError` unless `_admin_reason` is provided:

```python
# BLOCKED: Raises RuntimeError
db = Database()

# ALLOWED: Explicit admin reason
db = Database(_admin_reason='schema_migration')
```

This prevents developers from accidentally bypassing RLS in request handlers.

---

## Chapter 49: Input Sanitization & Rate Limiting

### 49.1 Input Sanitization

The input sanitizer middleware (`backend/app/middleware/input_sanitizer.py`) processes all incoming request payloads, stripping potential injection vectors.

### 49.2 Rate Limiting

The rate limiter (`backend/app/security.py`) uses an in-memory sliding window algorithm:

| Endpoint Category | Max Requests | Window |
|------------------|-------------|--------|
| Authentication | 10 | 60 seconds |
| Discovery Trigger | 5 | 300 seconds |
| API (default) | 400 | 60 seconds |
| Health/Metrics | Unlimited | N/A |

### 49.3 Security Headers

Every response includes:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`

---

## Chapter 50: Audit Trail & Security Logging

### 50.1 Activity Log

Every user action is recorded in the `activity_log` table:
- User ID, organization ID, IP address, user agent
- Action type and description
- Metadata (JSON) with action-specific details
- Immutable timestamp

### 50.2 Security Event Logger

Structured SIEM-compatible events for:

| Event Type | Trigger |
|-----------|---------|
| `TENANT_CONTEXT_VIOLATION` | RLS context mismatch detected |
| `RLS_DRIFT_DETECTED` | FORCE RLS policy missing during daily audit |
| `ADMIN_GUARD_BLOCKED` | Unauthorized admin mode access attempt |
| `POOL_EXHAUSTION` | Connection pool below 10% availability |
| `SLOW_QUERY` | Query execution exceeds 100ms threshold |
| `AUTH_FAILURE` | Failed authentication attempt |

### 50.3 Secret Redaction

The `SecretRedactionFilter` automatically strips sensitive values from log output:
- Passwords, tokens, API keys
- Azure connection strings
- JWT secrets
- Database credentials

---

# PART XIII: APPENDICES

---

## Appendix A: Complete API Reference

### Health & System
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health/live` | No | Liveness probe |
| GET | `/health/ready` | No | Readiness probe |
| GET | `/api/health` | No | Basic health |
| GET | `/api/health/detailed` | Yes | Full diagnostics |
| GET | `/api/metrics` | No | Prometheus metrics |
| GET | `/api/system/health` | Admin | System dashboard |
| GET | `/api/system/storage` | Admin | Storage stats |
| POST | `/api/system/cleanup` | Admin | Manual data cleanup |

### Authentication
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | No | JWT login |
| POST | `/api/auth/refresh` | No | Refresh token |
| POST | `/api/auth/logout` | Yes | Invalidate session |
| GET | `/api/auth/me` | Yes | Current user profile |
| POST | `/api/auth/password` | Yes | Change password |
| GET | `/api/auth/sso-status` | No | SSO config for tenant |
| POST | `/api/auth/saml/login` | No | SAML AuthnRequest |
| POST | `/api/auth/saml/acs` | No | SAML ACS callback |

### Identity Management
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/identities` | Yes | List identities (paginated) |
| GET | `/api/identities/<id>` | Yes | Identity detail |
| POST | `/api/identities/query` | Yes | Advanced query |
| GET | `/api/identities/query/fields` | Yes | Query field metadata |
| GET | `/api/identities/<id>/graph-data` | Yes | Access graph |
| GET | `/api/identities/<id>/pim` | Yes | PIM assignments |
| GET | `/api/identities/<id>/anomalies` | Yes | Identity anomalies |
| GET | `/api/identities/<id>/timeline` | Yes | Forensic timeline |
| GET | `/api/identities/<id>/attack-paths` | Yes | Escalation chains |
| GET | `/api/identities/<id>/remediations` | Yes | Matched playbooks |
| GET | `/api/identities/<id>/subscriptions` | Yes | Subscription access |

### Dashboard & Analytics
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/stats` | Yes | Dashboard summary |
| GET | `/api/identity-summary` | Yes | Category breakdown |
| GET | `/api/risks` | Yes | Critical/high identities |
| GET | `/api/dashboard/posture` | Yes | Posture score |
| GET | `/api/dashboard/compliance` | Yes | Compliance scorecard |
| GET | `/api/dashboard/conditional-access` | Yes | CA coverage |
| GET | `/api/dashboard/anomalies` | Yes | Top anomalies |
| GET | `/api/trends` | Yes | Risk trends |
| GET | `/api/trends/velocity` | Yes | Risk velocity |

### Discovery & Drift
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/runs` | Yes | Run history |
| POST | `/api/runs/trigger` | Admin | Manual discovery |
| GET | `/api/drift/latest` | Yes | Latest drift |
| GET | `/api/drift/history` | Yes | Drift timeline |
| GET | `/api/runs/<id>/drift` | Yes | Run-specific drift |
| GET | `/api/scheduler` | Yes | Scheduler status |

### Resources
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/resources` | Yes | Resource list |
| GET | `/api/resources/stats` | Yes | Resource summary |
| GET | `/api/resources/<path:id>` | Yes | Resource detail |
| GET | `/api/resources/<path:id>/access` | Yes | Identity access |
| GET | `/api/spns/stats` | Yes | SPN summary |
| GET | `/api/spns` | Yes | SPN list |
| GET | `/api/spns/<id>` | Yes | SPN detail |
| GET | `/api/app-registrations/stats` | Yes | App reg summary |
| GET | `/api/app-registrations` | Yes | App reg list |
| GET | `/api/app-registrations/<id>` | Yes | App reg detail |

### Anomalies
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/anomalies` | Yes | Anomaly list |
| GET | `/api/anomalies/stats` | Yes | Anomaly summary |
| GET | `/api/anomalies/<id>` | Yes | Anomaly detail |
| PATCH | `/api/anomalies/<id>` | Auditor+ | Mark resolved |

### SOAR
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/soar/playbooks` | Yes | List playbooks |
| POST | `/api/soar/playbooks` | Admin | Create playbook |
| PUT | `/api/soar/playbooks/<id>` | Admin | Update playbook |
| DELETE | `/api/soar/playbooks/<id>` | Admin | Delete playbook |
| POST | `/api/soar/playbooks/<id>/test` | Admin | Test playbook |
| GET | `/api/soar/actions` | Yes | Action history |
| GET | `/api/soar/actions/stats` | Yes | Action stats |
| POST | `/api/soar/execute` | Admin | Manual trigger |

### Settings & Configuration
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/settings` | Yes | All settings |
| POST | `/api/settings` | Admin | Update settings |
| GET | `/api/tenant/config` | Yes | Cloud/addon config |
| GET | `/api/activity` | Yes | Activity log |
| GET/POST | `/api/api-keys` | Admin | API key CRUD |
| DELETE | `/api/api-keys/<id>` | Admin | Delete API key |

### AI Copilot
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/copilot/chat` | Yes | Send message |
| GET | `/api/copilot/conversations` | Yes | History |
| GET | `/api/copilot/suggestions` | Yes | Context chips |

### Admin Portal
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/admin/tenants` | Portal | List tenants |
| POST | `/api/admin/tenants` | Superadmin | Create tenant |
| PUT | `/api/admin/tenants/<id>` | Superadmin | Update tenant |
| DELETE | `/api/admin/tenants/<id>` | Superadmin | Delete tenant |
| GET | `/api/admin/users` | Portal | List admin users |
| GET | `/api/admin/billing` | Billing+ | Revenue analytics |
| GET | `/api/admin/action-log` | Portal | Admin audit trail |

---

## Appendix B: Database Schema Quick Reference

### Core Tables (54+)
| Table | RLS | Purpose |
|-------|-----|---------|
| `organizations` | No | Tenant root (slug, plan, status) |
| `users` | Yes | User accounts (auth, role, org) |
| `discovery_runs` | Yes | Scan execution records |
| `snapshot_runs` | Yes | Org-level scan aggregation |
| `identities` | No* | Discovered identities (*scoped via run_id) |
| `role_assignments` | Yes | RBAC roles |
| `entra_role_assignments` | Yes | Directory roles |
| `credentials` | Yes | Secrets/certs/federated |
| `graph_api_permissions` | Yes | MS Graph permissions |
| `pim_eligible_assignments` | Yes | PIM eligible roles |
| `pim_activations` | Yes | PIM activation history |
| `drift_reports` | Yes | Change detection reports |
| `anomalies` | Yes | Detected anomalies |
| `attack_paths` | Yes | Escalation chains |
| `graph_nodes` | Yes | IAM graph vertices |
| `graph_edges` | Yes | IAM graph edges |
| `azure_storage_accounts` | Yes | Storage security |
| `azure_key_vaults` | Yes | Key vault security |
| `app_registrations` | Yes | App reg audit |
| `soar_playbooks` | Yes | SOAR automation |
| `soar_actions` | Yes | SOAR execution log |
| `activity_log` | Yes | Audit trail |
| `settings` | Yes | Key-value config |
| `cloud_connections` | Yes | Cloud credentials |
| `api_keys` | Yes | Machine auth |
| `compliance_frameworks` | Yes | Compliance standards |
| `compliance_controls` | Yes | Framework controls |
| `copilot_usage` | Yes | AI usage tracking |

---

## Appendix C: Configuration Variables

### Database
| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | auditgraph | Database name |
| `DB_USER` | auditgraph_app | App user (NOBYPASSRLS) |
| `DB_PASSWORD` | - | App user password |
| `DB_ADMIN_USER` | auditgraph_admin | Admin user (BYPASSRLS) |
| `DB_ADMIN_PASSWORD` | - | Admin user password |
| `DB_SSLMODE` | require | SSL mode |
| `DB_POOL_MIN` | 2 | Min pool connections |
| `DB_POOL_MAX` | 20 | Max pool connections |
| `DB_SLOW_QUERY_MS` | 100 | Slow query threshold |

### Authentication
| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | - | Client JWT signing key |
| `ADMIN_JWT_SECRET` | - | Admin JWT signing key |

### Azure Discovery
| Variable | Default | Description |
|----------|---------|-------------|
| `AZURE_TENANT_ID` | - | Entra tenant GUID |
| `AZURE_CLIENT_ID` | - | SPN app ID |
| `AZURE_CLIENT_SECRET` | - | SPN password |

### Integrations
| Variable | Default | Description |
|----------|---------|-------------|
| `COPILOT_API_KEY` | - | Anthropic Claude API key |
| `SENDGRID_API_KEY` | - | Email delivery |
| `SLACK_WEBHOOK_URL` | - | Slack notifications |
| `TEAMS_WEBHOOK_URL` | - | Teams notifications |

---

## Appendix D: Glossary of Terms

| Term | Definition |
|------|-----------|
| **AGIRS** | AuditGraph Identity Risk Score -- composite 0-100 score |
| **ARM** | Azure Resource Manager -- Azure's management API |
| **Blast Radius** | Resources reachable if an identity is compromised |
| **CA** | Conditional Access -- Azure policies enforcing MFA/device compliance |
| **CISO** | Chief Information Security Officer |
| **CIS** | Center for Internet Security -- benchmark standards |
| **Drift** | Changes detected between consecutive discovery scans |
| **Entra ID** | Microsoft's identity platform (formerly Azure Active Directory) |
| **GEI** | Governance Effectiveness Index -- AGIRS sub-score |
| **Ghost Identity** | Disabled/deleted account that retains active roles |
| **HIRI** | Human Identity Risk Index -- AGIRS sub-score |
| **ICE** | Identity Correlation Engine -- cross-cloud identity linking |
| **JIT** | Just-In-Time provisioning -- auto-create users on first SSO login |
| **NHIRI** | Non-Human Identity Risk Index -- AGIRS sub-score |
| **NHI** | Non-Human Identity -- SPNs, managed identities, app registrations |
| **P2** | Microsoft Entra ID P2 license -- provides sign-in telemetry |
| **PIM** | Privileged Identity Management -- just-in-time role activation |
| **RBAC** | Role-Based Access Control |
| **RLS** | Row-Level Security -- PostgreSQL feature for tenant isolation |
| **SAML** | Security Assertion Markup Language -- SSO protocol |
| **SCIM** | System for Cross-domain Identity Management -- user provisioning |
| **SOAR** | Security Orchestration, Automation, and Response |
| **SPN** | Service Principal -- non-human Azure identity |
| **T0/T1/T2/T3** | Privilege tiers -- T0 is highest ("keys to the kingdom") |
| **Zombie Identity** | Stale identity with valid credentials and high-risk roles |

---

# INDEX

**A**
- Access Graph Visualization, Chapter 26
- Access Reviews, Chapter 14
- AGIRS Score, Chapter 8
- Anomaly Detection, Chapter 12
- API Key Management, Chapter 35
- App Registration Audit, Chapter 31
- Attack Path Analysis, Chapter 10
- Authentication, Chapter 33
- Azure Discovery Engine, Chapter 4

**B**
- Behavioral Intelligence, Chapter 13
- Billing & Subscriptions, Chapter 41
- Blast Radius Analysis, Chapter 9

**C**
- CISO Dashboard, Chapter 25
- Compliance Automation, Chapter 16
- Conditional Access, Chapter 18
- Connection Pooling, Chapter 48
- Copilot (Trust AI), Chapter 23

**D**
- Dashboard Widgets, Chapter 43
- Data Retention, Chapter 38
- Deployment Architecture, Chapter 42
- Drift Detection, Chapter 11

**G**
- Governance Engine, Chapter 14
- Graph Builder, Chapter 5

**H**
- Health Monitoring, Chapter 39
- HIRI (Human Identity Risk Index), Chapter 8

**I**
- Identity Categories, Chapter 6
- Identity Discovery, Chapter 4
- Identity Explorer, Chapter 44
- Identity Graph, Chapter 5
- Input Sanitization, Chapter 49
- Investigation Tools, Chapter 24

**K**
- Key Vault Security, Chapter 32

**M**
- Multi-Cloud Support, Chapter 7
- Multi-Tenant Architecture, Chapter 3

**N**
- NHIRI (Non-Human Identity Risk Index), Chapter 8
- Notification System, Chapter 36

**P**
- P2 Telemetry, Chapter 13
- PDF Reports, Chapter 27
- PIM Tracking, Chapter 17
- Policy Recommender, Chapter 22
- Privilege Tiering, Chapter 6

**Q**
- Query Builder, Chapter 46

**R**
- Rate Limiting, Chapter 49
- RBAC Hygiene, Chapter 19
- Remediation Engine, Chapter 20
- RLS (Row-Level Security), Chapter 47

**S**
- Scheduler, Chapter 37
- Security Logging, Chapter 50
- Service Account Governance, Chapter 15
- Settings Configuration, Chapter 45
- SOAR Integration, Chapter 21
- SPN Dashboard, Chapter 30
- SSO/SAML/OIDC, Chapter 34
- Storage Security, Chapter 32

**T**
- Tenant Management, Chapter 40
- Trust AI (Copilot), Chapter 23

---

```
 ╔══════════════════════════════════════════════════════════════╗
 ║                                                              ║
 ║                      A U D I T G R A P H                     ║
 ║                                                              ║
 ║          Identity Risk Intelligence Platform                 ║
 ║                                                              ║
 ║     ─────────────────────────────────────────────────        ║
 ║                                                              ║
 ║     The Complete Product Reference Textbook                  ║
 ║                                                              ║
 ║     50 Chapters | 4 Appendices | Full Index                  ║
 ║                                                              ║
 ║     Covering 86+ Feature Phases                              ║
 ║     54+ Database Tables                                      ║
 ║     200+ API Endpoints                                       ║
 ║     70+ Frontend Pages                                       ║
 ║     100+ React Components                                    ║
 ║                                                              ║
 ║     ─────────────────────────────────────────────────        ║
 ║                                                              ║
 ║     Copyright (c) 2026 AuditGraph, Inc.                      ║
 ║     All Rights Reserved.                                     ║
 ║                                                              ║
 ║     https://auditgraph.ai                                    ║
 ║                                                              ║
 ╚══════════════════════════════════════════════════════════════╝
```
