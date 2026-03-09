# AuditGraph Database Migration Guide

**Version:** 1.0
**Last Updated:** March 2026
**Applies To:** Dev, QA, Staging, Production environments

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [New Environment Setup (Step-by-Step)](#4-new-environment-setup)
5. [Environment Variables Reference](#5-environment-variables-reference)
6. [What Happens at Startup (Auto-Migration)](#6-what-happens-at-startup)
7. [Post-Deploy: Onboarding a Client](#7-post-deploy-onboarding-a-client)
8. [Schema Reference](#8-schema-reference)
9. [RLS (Row Level Security)](#9-rls-row-level-security)
10. [Troubleshooting](#10-troubleshooting)
11. [Environment Matrix](#11-environment-matrix)
12. [Lessons Learned](#12-lessons-learned)

---

## 1. Overview

AuditGraph uses a **self-healing schema** approach. The backend application automatically creates all tables, columns, indexes, RLS policies, and grants on every startup. There is no separate migration tool or manual SQL execution required.

**The deployment process for any new environment is:**

```
1. Provision PostgreSQL server + create database + create two DB roles
2. Deploy the container with correct environment variables
3. App starts → auto-creates all 94 tables, applies RLS, grants permissions
4. Admin logs into admin portal → creates tenant/client
5. Client logs into client portal → adds cloud connection → triggers discovery
6. Done.
```

---

## 2. Architecture

### Dual-User Model

AuditGraph uses two PostgreSQL roles for security isolation:

| Role | Purpose | RLS Behavior | Used For |
|------|---------|-------------|----------|
| `auditgraph_{env}_admin` | DDL, migrations, system ops | BYPASSRLS | Startup DDL, scheduled jobs, seeding |
| `auditgraph_{env}_app` | Tenant-scoped API requests | NOBYPASSRLS | All HTTP request handling |

**Why two users?**
- The app user can NEVER bypass row-level security, even if there's a bug in the application code
- The admin user runs DDL (CREATE TABLE, ALTER TABLE) which requires elevated privileges
- Startup runs as admin, then all requests run as app user

### Connection Pools

Two separate connection pools are maintained at runtime:

- **App Pool:** `DB_POOL_MAX` connections (default 8), used for API requests
- **Admin Pool:** `max(5, DB_POOL_MAX / 4)` connections, used for scheduler jobs and system operations

Each connection is RESET on checkout/return to prevent tenant context leakage.

---

## 3. Prerequisites

### 3.1 PostgreSQL Server

| Requirement | Value |
|-------------|-------|
| **Version** | PostgreSQL 13+ (14+ recommended) |
| **Hosting** | Azure Database for PostgreSQL Flexible Server (recommended) |
| **Extensions** | None required (`gen_random_uuid()` is built-in since PG 13) |
| **SSL** | Required (`DB_SSLMODE=require`) for all non-local environments |

### 3.2 Create Database

```sql
-- Connect as server admin (e.g., agnppgadmin)
CREATE DATABASE auditgraph_{env};  -- e.g., auditgraph_qa, auditgraph_stg, auditgraph_prod
```

### 3.3 Create Two Database Roles

```sql
-- Connect to the new database as server admin

-- 1. Admin role (BYPASSRLS) — for DDL, migrations, system operations
CREATE ROLE auditgraph_{env}_admin WITH LOGIN PASSWORD '<strong-password>' BYPASSRLS;
GRANT ALL PRIVILEGES ON DATABASE auditgraph_{env} TO auditgraph_{env}_admin;
GRANT ALL ON SCHEMA public TO auditgraph_{env}_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO auditgraph_{env}_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO auditgraph_{env}_admin;

-- 2. App role (NOBYPASSRLS) — for tenant-scoped API requests
CREATE ROLE auditgraph_{env}_app WITH LOGIN PASSWORD '<strong-password>' NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO auditgraph_{env}_app;
-- (Table-level grants are applied automatically by the app at startup)
```

**Replace `{env}` with:** `qa`, `stg`, `prod`, etc.

### 3.4 Verify Roles

```sql
SELECT rolname, rolbypassrls FROM pg_roles
WHERE rolname LIKE 'auditgraph_%';
```

Expected:
```
 rolname                    | rolbypassrls
----------------------------+--------------
 auditgraph_qa_admin        | t
 auditgraph_qa_app          | f
```

---

## 4. New Environment Setup (Step-by-Step)

### Step 1: Provision Infrastructure

```bash
# Option A: Azure Bicep (recommended)
# Copy infra/containerapps-dev.bicep → containerapps-{env}.bicep
# Update parameters: environmentName, dbHost, dbName, dbUser, dbAdminUser, corsOrigins

az deployment group create \
  --resource-group {resource-group} \
  --template-file infra/containerapps-{env}.bicep \
  --parameters \
    acrUsername=$ACR_USERNAME \
    acrPassword=$ACR_PASSWORD \
    dbPassword=$DB_PASSWORD \
    dbAdminPassword=$DB_ADMIN_PASSWORD \
    jwtSecret=$JWT_SECRET \
    adminJwtSecret=$ADMIN_JWT_SECRET \
    clientJwtSecret=$CLIENT_JWT_SECRET
```

### Step 2: Set Environment Variables

See [Section 5](#5-environment-variables-reference) for the complete list. The critical ones:

```env
APP_ENV=qa                          # qa, stg, or prod
DB_HOST=<pg-server-fqdn>
DB_NAME=auditgraph_qa
DB_USER=auditgraph_qa_app
DB_PASSWORD=<app-user-password>
DB_ADMIN_USER=auditgraph_qa_admin
DB_ADMIN_PASSWORD=<admin-user-password>
DB_SSLMODE=require
DB_POOL_MAX=8
```

### Step 3: Deploy the Container

```bash
# Build and push to ACR
az acr build --registry auditgraphcr \
  --image auditgraph-api:{env} \
  --platform linux/amd64 \
  --file backend/Dockerfile .

# Deploy (via Bicep, GitHub Actions, or az CLI)
az containerapp update --name auditgraph-api-{env} \
  --resource-group {resource-group} \
  --image auditgraphcr.azurecr.io/auditgraph-api:{env}
```

### Step 4: Verify Startup

```bash
# Health check
curl https://{env}.api.auditgraph.ai/health

# Expected response:
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "migration": "idle",
    "scheduler": "ok",
    "startup": "complete"
  }
}
```

### Step 5: Onboard Client (Admin Portal)

See [Section 7](#7-post-deploy-onboarding-a-client).

---

## 5. Environment Variables Reference

### Required — Database

| Variable | Example (QA) | Description |
|----------|-------------|-------------|
| `DB_HOST` | `eus2-ag-nonprod-pg.postgres.database.azure.com` | PostgreSQL server FQDN |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `auditgraph_qa` | Database name |
| `DB_USER` | `auditgraph_qa_app` | App user (NOBYPASSRLS) |
| `DB_PASSWORD` | `<secret>` | App user password |
| `DB_ADMIN_USER` | `auditgraph_qa_admin` | Admin user (BYPASSRLS) |
| `DB_ADMIN_PASSWORD` | `<secret>` | Admin user password |
| `DB_SSLMODE` | `require` | SSL mode (`require` for Azure, `disable` for localhost) |
| `DB_POOL_MAX` | `8` | Max connections per pool |

### Required — Application

| Variable | Example (QA) | Description |
|----------|-------------|-------------|
| `APP_ENV` | `qa` | Environment tier (`local`, `dev`, `qa`, `stg`, `prod`) |
| `FLASK_ENV` | `production` | Flask mode (always `production` for deployed envs) |
| `JWT_SECRET` | `<secret>` | JWT signing secret (client portal) |
| `ADMIN_JWT_SECRET` | `<secret>` | Admin portal JWT secret |
| `CLIENT_JWT_SECRET` | `<secret>` | Client portal JWT secret |
| `CORS_ORIGINS` | `https://qa.app.auditgraph.ai,...` | Comma-separated allowed origins |
| `ADMIN_PASSWORD` | `<secret>` | Platform admin password (synced on startup) |

### Optional — Azure Discovery (for auto-seeding dev connections)

| Variable | Example | Description |
|----------|---------|-------------|
| `DEV_AZURE_DIRECTORY_ID` | `<tenant-id>` | Auto-seed cloud connection (dev only) |
| `AZURE_TENANT_ID` | `<tenant-id>` | Azure AD tenant for Graph API |
| `AZURE_CLIENT_ID` | `<client-id>` | Service principal for discovery |
| `AZURE_CLIENT_SECRET` | `<secret>` | Service principal secret |

### What NOT to Set

| Variable | Why |
|----------|-----|
| `DEFAULT_ORG_SLUG` | Only for dev; QA/STG/Prod use admin portal onboarding |
| `DEV_TENANT_PASSWORD` | Only for dev auto-seeded user |
| `ALLOW_DEMO` | Set to `false` in prod (demo data is for dev/QA only) |

---

## 6. What Happens at Startup (Auto-Migration)

When the container starts, the backend runs a comprehensive auto-migration sequence. **No manual SQL is needed.**

### Startup Sequence (in order)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CONNECT AS ADMIN USER (BYPASSRLS)                           │
│    └─ Single admin connection for all DDL operations            │
├─────────────────────────────────────────────────────────────────┤
│ 2. CREATE CORE TABLES (Migration 001)                           │
│    └─ discovery_runs, identities, role_assignments,             │
│       identity_roles, etc. (IF NOT EXISTS)                      │
├─────────────────────────────────────────────────────────────────┤
│ 3. CREATE ALL TABLES (Migration 100 — Full Schema)              │
│    └─ 94 CREATE TABLE IF NOT EXISTS statements                  │
│    └─ Covers every table from localhost dump                    │
│    └─ Safe to run repeatedly (IF NOT EXISTS guards)             │
├─────────────────────────────────────────────────────────────────┤
│ 4. ENSURE TABLE EXTENSIONS (35+ _ensure_* methods)              │
│    └─ Adds columns, constraints, indexes to existing tables     │
│    └─ Each method is idempotent (ADD COLUMN IF NOT EXISTS)      │
├─────────────────────────────────────────────────────────────────┤
│ 5. SCHEMA SYNC (sync_schema.py)                                 │
│    └─ Compares current DB schema vs expected schema (CSV)       │
│    └─ Adds any missing columns to match localhost exactly       │
│    └─ Catches any gaps missed by _ensure_* methods              │
├─────────────────────────────────────────────────────────────────┤
│ 6. PERFORMANCE INDEXES                                          │
│    └─ 9 composite indexes for common query patterns             │
│    └─ CREATE INDEX IF NOT EXISTS (safe to repeat)               │
├─────────────────────────────────────────────────────────────────┤
│ 7. CLOSE ADMIN CONNECTION                                       │
├─────────────────────────────────────────────────────────────────┤
│ 8. VALIDATE RLS CONFIGURATION                                   │
│    └─ Verifies DB_USER ≠ DB_ADMIN_USER                         │
│    └─ Verifies app user has NOBYPASSRLS                         │
│    └─ Verifies admin user has BYPASSRLS                         │
│    └─ FAILS FAST if misconfigured                               │
├─────────────────────────────────────────────────────────────────┤
│ 9. ENFORCE FORCE RLS                                            │
│    └─ Finds all tables with organization_id column              │
│    └─ Creates 4 strict RLS policies per table (sel/ins/upd/del) │
│    └─ Enables FORCE ROW LEVEL SECURITY                          │
│    └─ Creates auto-fill trigger for organization_id             │
├─────────────────────────────────────────────────────────────────┤
│ 10. SEED DATA                                                   │
│     └─ ensure_default_admin() — platform admin user             │
│     └─ seed_compliance_frameworks() — 15 frameworks, 200 ctrls  │
│     └─ seed_demo_tenant() — demo org + users + synthetic data   │
│     └─ seed_dev_tenant() — dev only (AzureCredits + azadmin)    │
├─────────────────────────────────────────────────────────────────┤
│ 11. BULK GRANT                                                  │
│     └─ GRANT SELECT,INSERT,UPDATE,DELETE on ALL tables          │
│     └─ GRANT USAGE,SELECT on ALL sequences                      │
│     └─ Per-table with SAVEPOINT (skips unowned tables)          │
│     └─ Sets DEFAULT PRIVILEGES for future tables                │
├─────────────────────────────────────────────────────────────────┤
│ 12. VALIDATE TENANT INDEXES (warning-only)                      │
│     └─ Checks all org_id tables have proper indexes             │
│     └─ Logs warnings but does NOT block startup                 │
├─────────────────────────────────────────────────────────────────┤
│ 13. START SCHEDULER + HEALTH CHECK = READY                      │
└─────────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `backend/migrations/001_create_identity_roles.sql` | Core tables (discovery_runs, identities, roles) |
| `backend/migrations/100_full_schema.sql` | All 94 tables (CREATE TABLE IF NOT EXISTS) |
| `backend/scripts/sync_schema.py` | Column-level schema sync (embedded CSV) |
| `backend/app/main.py` | Startup orchestration (`create_app()`) |
| `backend/app/database.py` | DDL methods, RLS, grants, seeding |

---

## 7. Post-Deploy: Onboarding a Client

Once the environment is deployed and healthy, follow this process:

### Step 1: Admin Portal — Create Tenant

1. Navigate to `https://{env}.admin.auditgraph.ai`
2. Login with platform admin credentials
3. Go to **Tenants** → **Create New Tenant**
4. Fill in:
   - **Name:** Client organization name
   - **Slug:** URL-safe identifier (e.g., `acme-corp`)
   - **Plan:** `pro` (or `trial`, `enterprise`)
5. Save

### Step 2: Admin Portal — Create Client User

1. Go to **Users** → **Create User**
2. Fill in:
   - **Username:** Client admin username
   - **Password:** Strong initial password
   - **Role:** `admin`
   - **Organization:** Select the tenant created above
3. Save

### Step 3: Client Portal — Login & Add Cloud Connection

1. Navigate to `https://{env}.app.auditgraph.ai`
2. Login with the client credentials
3. Go to **Settings** → **Cloud Connections** → **Add Connection**
4. Select **Azure Entra ID**
5. Enter:
   - **Label:** Descriptive name (e.g., "Production Entra ID")
   - **Azure Directory ID:** Client's Azure AD tenant ID
   - **Client ID:** Service principal application ID
   - **Client Secret:** Service principal secret
6. Click **Test Connection** → verify "Connected"
7. Save

### Step 4: Trigger Discovery

1. Go to **Discovery** or the **Dashboard**
2. Click **Run Discovery** (or wait for the scheduled scan)
3. Discovery takes 1-3 minutes for typical tenants
4. Once complete, identities appear in the dashboard

### That's It

No database migrations, no manual SQL, no schema changes. The app handles everything.

---

## 8. Schema Reference

### Table Count: 94

The full schema is defined in `backend/migrations/100_full_schema.sql`.

### Tables by Category

#### Core Identity Tables
| Table | Rows (typical) | Description |
|-------|----------------|-------------|
| `identities` | 50-5000 per tenant | All discovered identities |
| `identity_roles` | 100-10000 | RBAC role assignments per identity |
| `role_assignments` | 100-10000 | ARM scope role assignments |
| `entra_role_assignments` | 10-500 | Entra directory role assignments |
| `credentials` | 50-2000 | SP secrets and certificates |
| `graph_api_permissions` | 50-5000 | Graph API permissions per identity |
| `sp_app_roles` | 10-500 | App role assignments |
| `sp_ownership` | 10-500 | SP/App registration owners |
| `identity_subscription_access` | 50-5000 | Identity↔subscription mapping |

#### Discovery & Runs
| Table | Description |
|-------|-------------|
| `discovery_runs` | Discovery run history with status and counts |
| `cloud_connections` | Azure/AWS/GCP connection credentials |
| `cloud_subscriptions` | Discovered subscriptions per connection |
| `drift_reports` | Change detection between runs |

#### Security & Compliance
| Table | Description |
|-------|-------------|
| `security_findings` | Per-entity security findings |
| `attack_paths` | Computed escalation chains |
| `blast_radius_results` | Impact analysis per identity |
| `fix_recommendations` | Prioritized remediation actions |
| `compliance_frameworks` | Framework definitions (CIS, NIST, etc.) |
| `compliance_controls` | Individual compliance controls |
| `compliance_snapshots` | Point-in-time compliance scores |

#### Platform & Multi-Tenant
| Table | Description |
|-------|-------------|
| `organizations` | Tenant definitions (name, slug, plan) |
| `users` | User accounts with org mapping |
| `settings` | Per-tenant key-value settings |
| `activity_log` | Audit trail of all actions |
| `notifications` | In-app notification inbox |

#### Resources
| Table | Description |
|-------|-------------|
| `azure_storage_accounts` | Discovered storage accounts with security posture |
| `azure_key_vaults` | Discovered key vaults with item-level tracking |
| `app_registrations` | Entra app registrations with exposure scoring |

#### Workload Intelligence (P2 License)
| Table | Description |
|-------|-------------|
| `workload_signin_events` | Sign-in log telemetry |
| `workload_activity_stats` | Aggregated activity statistics |
| `workload_anomaly_events` | Behavioral anomaly detections |

### Tables WITHOUT organization_id (no RLS)

These tables are global/system-level:

| Table | Reason |
|-------|--------|
| `compliance_frameworks` | Shared framework definitions |
| `compliance_controls` | Shared control definitions |
| `compliance_root_causes` | Shared root cause catalog |
| `role_permissions` | Static role metadata |
| `role_attack_patterns` | Static breach examples |
| `role_hipaa_mappings` | Static HIPAA mappings |
| `remediation_playbooks` | Shared playbook templates |
| `plans` | Plan definitions |
| `platform_settings` | Global platform config |
| `schema_migrations` | Migration tracking |
| `pim_activations` | PIM data (scoped by identity_db_id FK) |
| `pim_eligible_assignments` | PIM eligibility (scoped by identity_db_id FK) |
| `refresh_tokens` | Auth tokens (scoped by user_id FK) |

---

## 9. RLS (Row Level Security)

### How It Works

Every table with an `organization_id` column has:

1. **4 strict RLS policies** (SELECT, INSERT, UPDATE, DELETE):
   ```sql
   CREATE POLICY org_strict_sel ON table_name FOR SELECT
     USING (organization_id = current_setting('app.current_organization_id', true)::integer);
   ```

2. **FORCE ROW LEVEL SECURITY** enabled:
   ```sql
   ALTER TABLE table_name FORCE ROW LEVEL SECURITY;
   ```

3. **Auto-fill trigger** on INSERT:
   ```sql
   -- If organization_id is NULL, auto-fills from session context
   -- If both are NULL, raises an exception
   ```

### How Tenant Context Is Set

1. HTTP request arrives → JWT decoded → `organization_id` extracted
2. `Database(organization_id=N)` created → connection from app pool
3. `SET LOCAL app.current_organization_id = 'N'` executed (transaction-scoped)
4. All queries automatically filtered to organization N
5. Connection returned to pool → context RESET

### Admin User Bypasses RLS

The admin user (`BYPASSRLS`) is used for:
- Startup DDL and migrations
- Scheduled discovery jobs (which loop per-tenant)
- System health checks

**Admin connections are NOT used for API requests.**

---

## 10. Troubleshooting

### Startup Fails: "RLS MISCONFIGURATION"

```
RuntimeError: RLS MISCONFIGURATION: DB_USER == DB_ADMIN_USER
```

**Fix:** Set distinct users in environment variables:
```env
DB_USER=auditgraph_qa_app
DB_ADMIN_USER=auditgraph_qa_admin
```

### Startup Fails: "role does not exist"

```
FATAL: role "auditgraph_qa_app" does not exist
```

**Fix:** Create the roles (see [Section 3.3](#33-create-two-database-roles)).

### Tables Exist But Queries Return Empty

**Cause:** RLS filtering everything because `organization_id` is NULL or mismatched.

**Check:**
```sql
-- Verify organization exists
SELECT id, name, slug FROM organizations;

-- Verify user has correct org
SELECT id, username, organization_id FROM users WHERE username = 'clientadmin';

-- Verify discovery run has correct org
SELECT id, organization_id, status FROM discovery_runs ORDER BY id DESC LIMIT 5;
```

### GRANT Failures at Startup (Ownership)

```
WARNING: Bulk GRANT: 90 tables granted, 4 skipped (ownership): ...
```

**Cause:** Some tables were created by the PostgreSQL server admin (`postgres`) instead of the app admin user. These tables can't be GRANTed by the app admin.

**Fix:** Connect as server admin and reassign:
```sql
-- As server admin (e.g., agnppgadmin):
ALTER TABLE custom_risk_rules OWNER TO auditgraph_qa_admin;
ALTER TABLE webhooks OWNER TO auditgraph_qa_admin;
-- Repeat for each skipped table
```

### Discovery Runs But Identities Show 0

**Cause:** Stale snapshot job blocking new discovery.

**Check logs for:**
```
DISCOVERY_SKIPPED connection_id=N — active job ...
```

**Fix:** The app automatically expires stale jobs after 30 minutes. If still stuck:
```sql
UPDATE snapshot_jobs SET status = 'failed'
WHERE status IN ('queued', 'running')
  AND created_at < NOW() - INTERVAL '1 hour';
```

### DDL Error During Request: "must be owner of table"

```
InsufficientPrivilege: must be owner of table compliance_controls
```

**Cause:** A request-time `_ensure_*` method is trying to CREATE INDEX as the app user.

**Not a problem:** The app handles this with `_can_ddl()` guards. If you see this in logs, it's a non-fatal error — the table already exists from startup DDL.

---

## 11. Environment Matrix

| Setting | Dev | QA | Staging | Production |
|---------|-----|-----|---------|------------|
| `APP_ENV` | `dev` | `qa` | `stg` | `prod` |
| `DB_SSLMODE` | `require` | `require` | `require` | `require` |
| `DB_POOL_MAX` | 8 | 10 | 15 | 20 |
| `CORS_ORIGINS` | `dev.app.*,demo.*` | `qa.app.*,qa.admin.*` | `stg.app.*,stg.admin.*` | `app.*,admin.*` |
| Demo Data | Yes (auto-seeded) | Optional | No | No |
| Dev Tenant | Yes (azadmin) | No | No | No |
| `ALLOW_DEMO` | `true` | `true` | `false` | `false` |
| Gunicorn Workers | 2 | 2 | 3 | 4 |
| Replicas | 1-3 | 1-2 | 2-3 | 2-5 |
| Auto-Scaling | 50 concurrent | 50 concurrent | 100 concurrent | 100 concurrent |

### Naming Convention

| Component | Pattern | Example (QA) |
|-----------|---------|-------------|
| Database | `auditgraph_{env}` | `auditgraph_qa` |
| Admin user | `auditgraph_{env}_admin` | `auditgraph_qa_admin` |
| App user | `auditgraph_{env}_app` | `auditgraph_qa_app` |
| API URL | `{env}.api.auditgraph.ai` | `qa.api.auditgraph.ai` |
| Client URL | `{env}.app.auditgraph.ai` | `qa.app.auditgraph.ai` |
| Admin URL | `{env}.admin.auditgraph.ai` | `qa.admin.auditgraph.ai` |
| Container App | `auditgraph-api-{env}` | `auditgraph-api-qa` |
| ACR Image Tag | `{env}` | `qa` |

---

## 12. Lessons Learned

These are critical insights from the dev environment deployment. Follow these to avoid repeating the same issues.

### L1: Never Run Manual SQL Against the Database

The app creates everything at startup. If you run manual DDL (CREATE TABLE, ALTER TABLE), those tables may be owned by the server admin user instead of the app admin user, causing GRANT failures on every subsequent startup.

**Rule:** Let the app handle all schema changes.

### L2: Both DB Users Are Required

If you only set `DB_USER` and not `DB_ADMIN_USER`, the app will fail the RLS validation check and refuse to start. Both users must exist with the correct BYPASSRLS/NOBYPASSRLS flags.

### L3: Localhost and Deployed DBs Are Independent

The localhost database evolves as you run the app locally. The deployed database only gets schema changes via the startup DDL code. They are NOT automatically synchronized.

**What keeps them in sync:** `100_full_schema.sql` (CREATE TABLE IF NOT EXISTS for all 94 tables) + `sync_schema.py` (adds any missing columns). When new tables/columns are added locally, regenerate these files.

### L4: Gunicorn Requires --preload

Without `--preload`, multiple gunicorn workers call `create_app()` simultaneously, causing DDL deadlocks (two workers trying to CREATE TABLE on the same table).

```bash
gunicorn wsgi:app --preload --workers 2 --bind 0.0.0.0:8000
```

### L5: Discovery Requires Cloud Connection First

Identities don't appear until a discovery run completes. A discovery run requires a valid cloud connection with tested credentials. The process is always:

```
Create Tenant → Create User → Login → Add Connection → Test → Discover
```

### L6: Demo Data Is Auto-Seeded

The demo organization with synthetic data is created automatically on startup. It uses `is_demo=true` to prevent real Azure discovery. Demo data includes ~200 identities, roles, credentials, findings, and attack paths.

### L7: Table Ownership Matters

If a table is owned by the PostgreSQL server admin (e.g., `postgres` or `agnppgadmin`), the app admin user cannot:
- GRANT access to the app user
- ALTER TABLE to add columns
- CREATE INDEX on the table
- FORCE ROW LEVEL SECURITY

**Prevention:** Never create tables manually. Let the app do it.

**Fix if it happens:**
```sql
-- As server admin:
ALTER TABLE table_name OWNER TO auditgraph_{env}_admin;
```

### L8: Use Platform linux/amd64 for ACR Builds

Building on Mac (ARM64) and pushing to Azure Container Apps (AMD64) causes exec format errors. Always build with:

```bash
az acr build --platform linux/amd64 ...
```

### L9: Regenerating Schema Files

When you add new tables or columns to the codebase, regenerate the schema files to keep deployed environments in sync:

```bash
# From the project root, with localhost DB running:

# 1. Regenerate full schema SQL
docker exec auditgraph-postgres pg_dump -U postgres -d auditgraph \
  --schema-only --no-owner --no-privileges --no-comments \
  -t '*' --section=pre-data | \
  python3 -c "
import sys, re
sql = sys.stdin.read()
for m in re.finditer(r'CREATE TABLE (\w+) \(([^;]+)\);', sql, re.DOTALL):
    name, body = m.group(1), m.group(2)
    print(f'CREATE TABLE IF NOT EXISTS {name} ({body});')
    print()
" > backend/migrations/100_full_schema.sql

# 2. Regenerate schema sync CSV
docker exec auditgraph-postgres psql -U postgres -d auditgraph -t -A -F'|' \
  -c "SELECT table_name, column_name, data_type, character_maximum_length,
      column_default, is_nullable
      FROM information_schema.columns
      WHERE table_schema = 'public'
      ORDER BY table_name, ordinal_position" \
  > /tmp/schema_export.csv

# Then update the SCHEMA_CSV in backend/scripts/sync_schema.py
```

### L10: JWT Secrets Must Be Unique Per Environment

Never share JWT secrets between environments. If dev and QA share the same `JWT_SECRET`, a token from dev could authenticate against QA.

---

## Appendix A: Quick Reference Card

### New Environment Checklist

- [ ] PostgreSQL server provisioned
- [ ] Database created: `auditgraph_{env}`
- [ ] Admin role created: `auditgraph_{env}_admin` (BYPASSRLS)
- [ ] App role created: `auditgraph_{env}_app` (NOBYPASSRLS)
- [ ] Environment variables set (DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, DB_ADMIN_USER, DB_ADMIN_PASSWORD, DB_SSLMODE, JWT_SECRET, ADMIN_JWT_SECRET, CLIENT_JWT_SECRET, CORS_ORIGINS, APP_ENV)
- [ ] Container deployed with `--preload` flag
- [ ] Health check passes: `GET /health` → `{"status": "ready"}`
- [ ] Admin portal accessible
- [ ] Tenant created via admin portal
- [ ] Client user created via admin portal
- [ ] Client logged in via client portal
- [ ] Cloud connection added and tested
- [ ] Discovery triggered and completed
- [ ] Identities visible in dashboard

### Emergency: Reset a Stuck Environment

```bash
# 1. Check health
curl https://{env}.api.auditgraph.ai/health

# 2. Check logs
az containerapp logs show --name auditgraph-api-{env} \
  --resource-group {rg} --type console --tail 100

# 3. Force restart (re-runs all startup DDL)
az containerapp revision restart --name auditgraph-api-{env} \
  --resource-group {rg} --revision <latest-revision>

# 4. Verify
curl https://{env}.api.auditgraph.ai/health
```
