# AuditGraph DB Migration Runbook

End-to-end procedure for bootstrapping a fresh Azure PostgreSQL Flexible Server with the AuditGraph schema, role configuration, and (optionally) data from a source DB. Distilled from the actual cus-ag-nonprod dev rollout — every step here exists because the previous attempt without it failed.

---

## 0. When to use this runbook

Use this for:
- Standing up a new environment (staging, prod, new region) from scratch
- Recovering a corrupted dev DB
- Migrating data between environments (sandbox → dev, dev → staging, etc.)

Time budget: **3–6 hours** end to end for a clean run. The unknowns are mostly fast (~15 min per phase); the slow parts are image rebuilds (~2–4 min each) and Azure resource provisioning (PG SKU change ~5–10 min, container startup ~30 s per replica).

---

## 1. Prerequisites

### Azure resources (must exist before you start)
- Subscription with quota for: PostgreSQL Flexible Server (General Purpose tier), Container Apps, Container Registry, VNet
- Resource group (e.g. `cus-ag-nonprod-rg`)
- VNet with at least three delegated subnets:
  - `*-app-snet` — for Container Apps env (delegated to `Microsoft.App/environments`)
  - `*-db-snet` — for PostgreSQL (delegated to `Microsoft.DBforPostgreSQL/flexibleServers`)
  - `*-pe-snet` — for private endpoints (storage, ACR, etc.)
- Private DNS zone: `<env>.private.postgres.database.azure.com` linked to the VNet
- PostgreSQL Flexible Server provisioned in `*-db-snet`:
  - **Tier: General Purpose** (NOT Burstable — see §13.1)
  - **SKU: Standard_D2ds_v5** or larger (2+ vCPU, sustained)
  - **Storage: ≥ 128 GB / P10** (gives 500 IOPS; smaller tiers starve discovery scans — see §13.2)
  - Postgres 16
  - Admin login captured (you'll need the password for §3)
- Container Apps environment in `*-app-snet` with VNet integration
- Container Registry (Basic SKU minimum) — admin-enabled OR managed identity wired up
- Log Analytics workspace linked to the Container Apps env

### Local tooling
- `az` CLI (`az login` with permissions to all the above)
- Docker running locally (only needed if your source DB is local)
- `psycopg2-binary` Python package
- Python 3.11+

### Source DB (optional, only if migrating data)
- Connection string to the source DB (PG, any version)
- Read access (a read-only role is sufficient for the dump phase)

---

## 2. Plan the migration

Decide three things up front:

| Decision | Options | Notes |
|---|---|---|
| **DB name** | e.g. `auditgraph_dev` | Match what Terraform/Bicep creates. Code references the DB by env var, so any name works. |
| **Data scope** | Schema only / Schema + selected orgs / Full copy | "Schema + selected orgs" is what we used. Pure schema is simpler if you just need a working environment. |
| **Where to run migration jobs** | Container Apps Job in the same env as the target DB | Required because PG is VNet-only; nothing outside the VNet can reach the private endpoint. |

---

## 3. Create the database + roles

Postgres ships with admin login from server provisioning. We never use it at runtime — instead we create two purpose-built roles:

- **`<env>_admin`** — `BYPASSRLS`, used by migrations + DDL + the app's admin connection pool
- **`<env>_app`** — `NOBYPASSRLS`, used by the app's tenant-scoped connection pool (RLS enforces isolation)
- **Legacy aliases `auditgraph_app` + `auditgraph_admin`** (NOLOGIN group roles) — the backend has hardcoded `GRANT … TO auditgraph_app` in `~12 places`; create the alias roles and `GRANT auditgraph_app TO <env>_app` so inherited privileges work without code changes.

The DB and roles need to exist before anything else. Two paths:

### 3a. If Terraform/Bicep created the DB
Terraform creates the database and sets the server admin password. Capture:
- `DB_HOST` (FQDN)
- `DB_NAME` (e.g. `auditgraph_dev`)
- `SERVER_ADMIN_USER` (usually matches the server name)
- `SERVER_ADMIN_PASSWORD` (from `az postgres flexible-server show`, Key Vault, or Terraform state)

If the password is unknown, reset it once:
```bash
az postgres flexible-server update -g <rg> -n <pg-name> --admin-password "<new-pwd>"
```

### 3b. Run the role setup
This SQL is in `backend/scripts/setup_dev_db_roles.sql` and gets executed inside the Container Apps Job (the `setup-roles` phase). It:
1. Creates `auditgraph_dev_admin` (BYPASSRLS) and `auditgraph_dev_app` (NOBYPASSRLS) with login passwords
2. Grants `ALL PRIVILEGES ON DATABASE auditgraph_dev` to admin
3. Grants `USAGE ON SCHEMA public` to app
4. Creates `auditgraph_app` and `auditgraph_admin` NOLOGIN alias roles
5. Grants the aliases to the real users

**You'll need to edit the DB name in this SQL file if your DB name isn't `auditgraph_dev`.** Search-replace.

---

## 4. Build the migration image

The migration runs inside a Container Apps Job because the PG private endpoint is unreachable from outside the VNet. The image bundles:
- Backend code (for Python `create_app()` DDL)
- All SQL migrations
- `psql` client
- The orchestration script `deploy/migration/run.sh`
- (Optional) `local_cols.json` schema dump from source DB
- (Optional) `sandbox_dump.json` data dump from source DB

### Build context
Stage a minimal context to keep upload fast:
```bash
rm -rf /tmp/migration-build && mkdir -p /tmp/migration-build
rsync -a --exclude='venv' --exclude='__pycache__' --exclude='.pytest_cache' \
  backend/ /tmp/migration-build/backend/
rsync -a scripts/ /tmp/migration-build/scripts/
mkdir -p /tmp/migration-build/deploy/migration/
cp deploy/migration/Dockerfile deploy/migration/run.sh /tmp/migration-build/deploy/migration/
```

### Build via ACR (avoids cross-arch issues on Mac)
```bash
cd /tmp/migration-build && az acr build \
  --registry <acr-name> \
  --image auditgraph-migration:v1 \
  --file deploy/migration/Dockerfile \
  --platform linux/amd64 .
```

Build takes ~2–4 min.

---

## 5. Deploy the migration jobs

Three Container Apps Jobs, all use the same image but different `PHASE` env var.

### setup-roles job (uses server admin creds)
```bash
az containerapp job create \
  --name migration-setup-roles \
  --resource-group <rg> \
  --environment <cae-name> \
  --trigger-type Manual \
  --replica-timeout 600 --replica-retry-limit 0 \
  --parallelism 1 --replica-completion-count 1 \
  --image <acr>.azurecr.io/auditgraph-migration:v1 \
  --cpu 0.5 --memory 1Gi \
  --registry-server <acr>.azurecr.io \
  --registry-username <acr> \
  --registry-password '<acr-pwd>' \
  --secrets 'server-admin-pwd=<server-admin-pwd>' \
  --env-vars \
    PHASE=setup-roles \
    DB_HOST=<pg-fqdn> \
    DB_NAME=auditgraph_dev \
    SERVER_ADMIN_USER=<server-admin-user> \
    SERVER_ADMIN_PASSWORD=secretref:server-admin-pwd
```

### migrate job (uses admin role; bigger replica)
```bash
az containerapp job create \
  --name migration-migrate \
  --resource-group <rg> \
  --environment <cae-name> \
  --trigger-type Manual \
  --replica-timeout 3600 --replica-retry-limit 0 \
  --parallelism 1 --replica-completion-count 1 \
  --image <acr>.azurecr.io/auditgraph-migration:v1 \
  --cpu 1.0 --memory 2Gi \
  --registry-server <acr>.azurecr.io \
  --registry-username <acr> --registry-password '<acr-pwd>' \
  --secrets \
    'db-admin-pwd=<chosen-admin-pwd>' \
    'db-app-pwd=<chosen-app-pwd>' \
  --env-vars \
    PHASE=migrate \
    AG_SKIP_FULL_SCHEMA_DUMP=1 \
    DB_HOST=<pg-fqdn> \
    DB_NAME=auditgraph_dev \
    DB_SSLMODE=require \
    DB_ADMIN_USER=auditgraph_dev_admin \
    DB_ADMIN_PASSWORD=secretref:db-admin-pwd \
    DB_USER=auditgraph_dev_app \
    DB_PASSWORD=secretref:db-app-pwd \
    APP_ENV=dev
```

Critical env vars:
- `AG_SKIP_FULL_SCHEMA_DUMP=1` — skips `100_full_schema.sql` (which is a broken pg_dump missing PRIMARY KEY constraints; see §13.3)
- `DB_USER` and `DB_ADMIN_USER` **must be different** roles — the app's `validate_rls_startup()` aborts if they match

### restore job (uses server admin role; needs `session_replication_role` privilege)
Only create this if you're migrating data from a source DB.

```bash
az containerapp job create \
  --name migration-restore \
  --resource-group <rg> \
  --environment <cae-name> \
  --trigger-type Manual \
  --replica-timeout 1800 --replica-retry-limit 0 \
  --parallelism 1 --replica-completion-count 1 \
  --image <acr>.azurecr.io/auditgraph-migration:v1 \
  --cpu 1.0 --memory 2Gi \
  --registry-server <acr>.azurecr.io \
  --registry-username <acr> --registry-password '<acr-pwd>' \
  --secrets 'cloud-dsn=dbname=auditgraph_dev user=<server-admin-user> password=<server-admin-pwd> host=<pg-fqdn> port=5432 sslmode=require' \
  --env-vars PHASE=restore CLOUD_DSN=secretref:cloud-dsn
```

Restore MUST use the **server admin** (not `auditgraph_dev_admin`) because it calls `SET session_replication_role = 'replica'` to bypass FK validation during bulk load. That setting requires `azure_pg_admin` privileges which only the server admin has.

---

## 6. Execute phases in order

### 6.1 (Optional) reset-db
If you need a clean slate (e.g. previous failed attempt left partial state):
```bash
az containerapp job update -g <rg> -n migration-setup-roles --set-env-vars PHASE=reset-db
az containerapp job start --name migration-setup-roles -g <rg>
```
This drops + recreates the DB. **Destructive — all data lost.**

### 6.2 setup-roles
```bash
az containerapp job update -g <rg> -n migration-setup-roles --set-env-vars PHASE=setup-roles
az containerapp job start --name migration-setup-roles -g <rg>
```
Expected output: 4 roles created (`auditgraph_dev_admin`, `auditgraph_dev_app`, `auditgraph_app`, `auditgraph_admin`) plus grants.

### 6.3 migrate (Python DDL + SQL migrations)
```bash
az containerapp job start --name migration-migrate -g <rg>
```
Watch via `az monitor log-analytics query`. The migrate job:
1. Calls `create_app()` which runs all Python `_ensure_*_table()` methods → creates ~96 tables with proper PKs
2. Runs `enforce_force_rls()` → applies RLS to ~84 tenant tables, creates policies
3. Runs `ensure_app_user_grants()` → SELECT/INSERT/UPDATE/DELETE grants to `auditgraph_dev_app` on all tables
4. Seeds `compliance_frameworks`, default admin user, etc.
5. **Pre-marks** migrations 001-079 as applied (those conflict with Python DDL — see §13.4)
6. Runs SQL migrations 080+ via `run_migrations.py` (with `conn.autocommit = True` so `CREATE INDEX CONCURRENTLY` works)

Total runtime: 5–8 min on a fresh DB.

### 6.4 patch-sql for migrations the migrate job can't handle
Migration 101 uses `CREATE INDEX CONCURRENTLY` and can't run via the standard runner (psycopg2 multi-statement issue — §13.5). Pre-marked as applied; apply the indexes manually later:
```bash
az containerapp job update -g <rg> -n migration-migrate \
  --set-env-vars PHASE=patch-sql PATCH_FROM=101 PATCH_TO=101
az containerapp job start --name migration-migrate -g <rg>
```

### 6.5 sync-schema (additive column sync from source)
**Critical step.** The codebase has accumulated columns that no migration adds (the local sandbox grew them via code edits over years). Without this, scans will fail intermittently with `column "X" does not exist`.

#### First dump locally from source DB:
```bash
LOCAL_DSN="dbname=auditgraph user=... password=... host=localhost port=5434" \
  python3 backend/scripts/sync_schema_columns.py dump --out /tmp/local_cols.json
```

#### Bundle the dump into a new image build (`v2`):
```bash
cp /tmp/local_cols.json /tmp/migration-build/deploy/migration/local_cols.json
# Dockerfile must have: COPY deploy/migration/local_cols.json /data/local_cols.json
cd /tmp/migration-build && az acr build \
  --registry <acr> --image auditgraph-migration:v2 \
  --file deploy/migration/Dockerfile --platform linux/amd64 .
```

#### Run sync (with API offline to avoid lock contention — see §13.6):
```bash
# Scale API down first
LATEST=$(az containerapp revision list -g <rg> -n auditgraph-api --query '[?properties.active==`true`].name | [0]' -o tsv)
az containerapp revision deactivate -g <rg> -n auditgraph-api --revision $LATEST

# Run sync
az containerapp job update -g <rg> -n migration-migrate \
  --image <acr>.azurecr.io/auditgraph-migration:v2 \
  --set-env-vars PHASE=sync-schema
az containerapp job start --name migration-migrate -g <rg>
# Wait for completion (~5–10 min on a quiet DB; can run >30 min if API holds locks)

# Reactivate API
az containerapp revision activate -g <rg> -n auditgraph-api --revision $LATEST
```

Expected output: "Added N columns" where N is typically 50–200 depending on how stale your fresh schema is vs source.

Failures on `v_*` views (ALTER TABLE on views) are benign — skip them.

### 6.6 restore (data migration — optional)
Only if you want data from source.

#### Dump from source locally:
```bash
LOCAL_DSN="..." python3 backend/scripts/migrate_to_cloud_dev.py dump \
  --orgs 1,2,9 --out /tmp/sandbox_dump.json
```

Edit `--orgs` to the IDs you want. The dumper handles 3 categories:
- Global reference tables (compliance_frameworks, role_permissions, etc.) — all rows
- `organizations` — only the requested IDs
- Org-scoped tables — filtered by `organization_id IN (...)`
- Tables linked via `discovery_run_id` — filtered transitively

#### Bundle into new image build (v3):
```bash
cp /tmp/sandbox_dump.json /tmp/migration-build/deploy/migration/sandbox_dump.json
cd /tmp/migration-build && az acr build \
  --registry <acr> --image auditgraph-migration:v3 \
  --file deploy/migration/Dockerfile --platform linux/amd64 .
```

#### Run restore:
```bash
az containerapp job update -g <rg> -n migration-restore \
  --image <acr>.azurecr.io/auditgraph-migration:v3
az containerapp job start --name migration-restore -g <rg>
```

Restore takes 3–6 min for ~50k rows. Expect "ON CONFLICT DO NOTHING" silently dropping duplicate PKs from source (e.g. `sp_ownership.id=16 × 10` in our case).

---

## 7. Verify

```bash
# Connection works
curl https://<api-fqdn>/api/health
# Expect: {"checks":{"database":"ok",...},"status":"ready"}

# Users present
az containerapp job update -g <rg> -n migration-migrate \
  --set-env-vars PHASE=patch-sql PATCH_FROM=999 PATCH_TO=999
# (Where 999 is a SELECT-only SQL like 999_list_users.sql)
az containerapp job start --name migration-migrate -g <rg>

# Login works (replace creds)
curl -X POST https://<api-fqdn>/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"techadmin","password":"changeme"}'
```

---

## 8. Deploy API + frontend containers

Once the DB is ready, deploy the application:

```bash
# API
az containerapp create \
  --name auditgraph-api -g <rg> --environment <cae> \
  --image <acr>.azurecr.io/auditgraph-api:dev \
  --target-port 8000 --ingress external \
  --cpu 2.0 --memory 4Gi --min-replicas 2 --max-replicas 5 \
  --registry-server <acr>.azurecr.io \
  --registry-username <acr> --registry-password '<acr-pwd>' \
  --secrets db-admin-pwd=... db-app-pwd=... \
  --env-vars \
    APP_ENV=dev FLASK_ENV=production \
    DB_HOST=<pg-fqdn> DB_PORT=5432 DB_NAME=auditgraph_dev DB_SSLMODE=require \
    DB_ADMIN_USER=auditgraph_dev_admin DB_ADMIN_PASSWORD=secretref:db-admin-pwd \
    DB_USER=auditgraph_dev_app DB_PASSWORD=secretref:db-app-pwd \
    ALLOWED_ORIGINS=https://dev.app.auditgraph.ai,https://dev.admin.auditgraph.ai,https://dev.api.auditgraph.ai \
    COOKIE_DOMAIN=.auditgraph.ai

# Frontend (app + admin) — same pattern with target-port 3000 and 3001
```

**Critical env vars on API:**
- `ALLOWED_ORIGINS` — comma-separated, MUST include the frontend domains or browser blocks CORS
- `COOKIE_DOMAIN=.auditgraph.ai` — without this, CSRF cookie is scoped to `dev.api.*` only and JS at `dev.app.*` can't read it

---

## 9. Bind custom domains

```bash
# Get the env's verification ID once
VERIFY_ID=$(az containerapp env show -g <rg> -n <cae> \
  --query 'properties.customDomainConfiguration.customDomainVerificationId' -o tsv)
DEFAULT_DOMAIN=$(az containerapp env show -g <rg> -n <cae> \
  --query 'properties.defaultDomain' -o tsv)
```

At your DNS provider (Cloudflare, Route53, etc.), add **per subdomain**:
- TXT record: `asuid.<subdomain>` value = `$VERIFY_ID`
- CNAME record: `<subdomain>` value = `<containerapp-name>.<DEFAULT_DOMAIN>`

Cloudflare specifically: **set CNAME to DNS-only** (gray cloud, not proxied), otherwise Azure's verification fails.

After DNS propagates (1–10 min):
```bash
az containerapp hostname bind -g <rg> -n auditgraph-api \
  --hostname dev.api.auditgraph.ai \
  --environment <cae> --validation-method CNAME
```
Repeat for each subdomain. Azure provisions a free managed cert automatically.

---

## 10. Operational notes

### Restart API after env/secret changes
```bash
LATEST=$(az containerapp revision list -g <rg> -n auditgraph-api \
  --query '[?properties.active==`true`].name | [0]' -o tsv)
az containerapp revision restart -g <rg> -n auditgraph-api --revision $LATEST
```

### Inspect DB state from inside the VNet
Use the existing `migration-migrate` job with `PHASE=patch-sql` and a SELECT-only SQL file (see `999_list_users.sql` as template).

### Reset a forgotten password
Login as `techadmin` to `dev.admin.auditgraph.ai`, navigate to User Management, reset the password. Or via SQL:
```sql
UPDATE users SET password_hash = crypt('newpwd', gen_salt('bf', 10)) WHERE username = 'X';
```
(requires `pgcrypto` extension)

### Pull logs
```bash
WS_ID=$(az monitor log-analytics workspace show -g <rg> -n <law-name> --query customerId -o tsv)
az monitor log-analytics query -w "$WS_ID" --analytics-query \
  "ContainerAppConsoleLogs_CL | where ContainerName_s == 'auditgraph-api' and TimeGenerated > ago(15m) | order by TimeGenerated desc | take 100 | project TimeGenerated, Log_s"
```

---

## 11. Resource sizing (validated for dev workload of ~3k identities)

| Resource | Minimum | Recommended | Notes |
|---|---|---|---|
| PG tier | General Purpose D2ds_v5 | D2ds_v5 or D4ds_v5 | **Burstable B-series will starve under scan load.** Burst credits exhaust in minutes. |
| PG storage | 128 GB / P10 / 500 IOPS | 256 GB / P15 / 1100 IOPS | IOPS scales with disk size; budget for it. |
| PG max_connections | default (429 on D2ds_v5) | default | App pool max = 25 per worker × replicas; default is plenty. |
| API container | 1 CPU / 2 GiB / 1 replica | 2 CPU / 4 GiB / 2–5 replicas | Min 2 replicas keeps scheduler responsive during rolling restarts. |
| Frontend (app, admin) | 0.25 CPU / 0.5 GiB | 0.5 CPU / 1 GiB / 1–2 replicas | Static nginx — cheap. |
| ACR | Basic | Basic | ~$5/mo, sufficient for dev. |

---

## 12. Cost (cus-ag-nonprod baseline, ~May 2026)

| Resource | Monthly cost |
|---|---|
| PG D2ds_v5 (GP) + 128 GB storage | ~$145 |
| Container Apps (Consumption, 24/7) | ~$30–50 |
| Container Registry Basic | ~$5 |
| Log Analytics ingestion + retention (30d) | ~$10–20 |
| Bandwidth | <$5 typically |
| **Total dev** | **~$200/mo** |

Production with HA + larger compute + longer retention runs $400–600/mo.

---

## 13. Known gotchas (the reasons this runbook exists)

### 13.1 Burstable PG is a trap for scans
B-series instances earn CPU credits when idle and spend them under load. A discovery scan runs ~5–8 min of sustained DB activity which exhausts credits and the DB grinds to crawl. **Always use General Purpose tier for environments that run scans.**

### 13.2 PG IOPS is tied to storage size
Premium SSD tier IOPS = `max(120, 3 × storage_gb)`. 32 GB → 120 IOPS (barely usable). 128 GB → 500 IOPS (workable for dev). 256 GB → 1100 IOPS (comfortable). If you skip the sizing check, scans hang for 20+ min on disk I/O.

### 13.3 `100_full_schema.sql` is a broken pg_dump
The file is a `pg_dump --section=pre-data` output that lost its constraints section. Tables created from it have no PRIMARY KEY. Subsequent `CREATE TABLE IF NOT EXISTS` calls skip them (table exists), leaving them PK-less, which then breaks FK creation (e.g. `keyvault_metadata REFERENCES cloud_connections(id)` fails with "no unique constraint").

**Fix:** the `AG_SKIP_FULL_SCHEMA_DUMP=1` env var (gated in `backend/app/main.py:1047`) makes Python skip running this migration. Python DDL's `_ensure_*_table()` methods create the same tables correctly with proper PKs.

### 13.4 SQL migrations 001-079 conflict with current Python DDL
The pre-100 SQL migrations were written when the schema was simpler. The Python DDL has evolved (e.g. `settings(key PK)` → `settings(id PK, UNIQUE(org_id, key))`). Running them fresh against the current Python-DDL'd schema causes ON CONFLICT failures.

**Fix:** The migrate phase's run.sh pre-marks 001-079 as applied. Migrations 080+ are real (they add Phase 3 tables, approval_workflow, execution_engine, etc.) and DO need to run.

### 13.5 `CREATE INDEX CONCURRENTLY` can't run via psycopg2 multi-statement
psycopg2's `cur.execute(multi_statement_sql)` wraps everything in an implicit transaction even when autocommit is True. PostgreSQL rejects `CONCURRENTLY` inside a transaction. Migration 101 hits this.

**Fix:** pre-marked as applied. Apply the indexes manually via raw `psql -f`:
```bash
PGPASSWORD=$ADMIN_PWD psql -h $DB_HOST -U auditgraph_dev_admin -d auditgraph_dev \
  -f /app/backend/migrations/101_identities_org_id_constraints.sql
```
(from inside a Container Apps Job)

### 13.6 `ALTER TABLE` hangs when the API is running
Schema changes need `AccessExclusiveLock` which conflicts with the API's continuous SELECTs. Sync-schema sat for 22 min adding 18 columns then got killed.

**Fix:** deactivate API revisions before running sync-schema. Reactivate after.

### 13.7 `session_replication_role` requires `azure_pg_admin`
The restore phase bypasses FK validation with `SET session_replication_role = 'replica'`. Only the server admin (or roles granted `azure_pg_admin`) can set this. `auditgraph_dev_admin` cannot, even with BYPASSRLS.

**Fix:** restore phase MUST connect as the server admin, not the app admin role.

### 13.8 Cross-origin cookies need both `COOKIE_DOMAIN` and proper SameSite
Without `COOKIE_DOMAIN=.auditgraph.ai`, the CSRF cookie set by `dev.api.*` can't be read by JS on `dev.app.*`. The double-submit CSRF check then fails on every mutating request. Symptom: "CSRF token mismatch" 403 on requests where the Cookie header DOES contain the value (browser ships it, JS just can't read it).

### 13.9 Clear browser cookies after changing `COOKIE_DOMAIN`
Old cookies scoped to `dev.api.*` stay in browser storage even after the server-side `Domain=.auditgraph.ai` change. Users see the new symptom until they clear cookies.

### 13.10 Local sandbox has cross-tenant orphan refs
Years of dev have accumulated rows where e.g. `identity_subscription_access.identity_db_id` points to an identity in a different org. Fresh DBs with proper FKs reject these.

**Fix:** restore uses `INSERT … ON CONFLICT DO NOTHING` + `session_replication_role='replica'` to tolerate. Lose ~0.1% of rows; accept and move on.

### 13.11 Discovery saves identities but UI shows 0
The "X identities discovered" count comes from `identity_list` (a Phase 3 projection table), NOT from the `identities` table where rows actually live. If `identity_list` schema is incomplete (missing columns the writer expects), the writer fails per-identity and `identity_list` stays empty, even though `identities` has thousands of rows.

**Fix:** run `sync-schema` to ensure `identity_list` has all columns the code expects. Most common missing columns: `is_microsoft_system`, `identity_class`.

### 13.12 Scheduler thread keeps container alive past migration completion
`create_app()` starts a background scheduler thread. After run.sh completes the migration step, the script exits — but the scheduler keeps the Python process alive. The container is then killed at `replica-timeout`, marked Failed even though migrations succeeded.

**Mitigation:** check `schema_migrations` table or app logs rather than relying on the job's terminal status. Bump `replica-timeout` to 3600s to be safe.

---

## 14. Troubleshooting cheatsheet

| Symptom | Most likely cause | Fix |
|---|---|---|
| `psql: error: connection ... no pg_hba.conf entry ... no encryption` | psql tried without SSL first | Cosmetic — psql retries with SSL automatically. Set `PGSSLMODE=require` to suppress. |
| `password authentication failed for user X` | Wrong password, or password contains shell-special chars | Reset via `az postgres flexible-server update --admin-password`. |
| `relation "X" does not exist` during scan | Schema drift — table never created in cloud | Run sync-schema after dumping source's schema. |
| `column "X" of relation "Y" does not exist` | Schema drift on column level | Same — run sync-schema. |
| `CREATE INDEX CONCURRENTLY cannot run inside a transaction block` | psycopg2 multi-statement quirk | Mark migration as applied, apply via raw psql. |
| `set_session cannot be used inside a transaction` | Setting autocommit mid-transaction | Set autocommit immediately after `psycopg2.connect()`, before any other call. |
| `permission denied to set parameter "session_replication_role"` | Not server admin | Switch restore phase to use server admin DSN. |
| Sync-schema runs >30 min with no output | API holding ALTER TABLE locks | Deactivate API revisions, re-run sync. |
| API returns 401 with valid creds | Stale browser cookies after cookie-config change | Clear cookies for the apex domain and retry. |
| CORS preflight returns no `Access-Control-Allow-Origin` | `ALLOWED_ORIGINS` env var missing on API | Set it via `az containerapp update --set-env-vars`. |
| Login hangs >2 min | DB connection pool exhausted | Restart API revision; investigate stuck queries via `pg_stat_activity`. |
| "0 identities" after successful scan | `identity_list` write failures | Check logs for `phase3_skeleton_writer: identity_list upsert failed`; sync-schema. |

---

## 15. Reference: phase descriptions

The single `migration-migrate` job runs different work based on `PHASE`:

| PHASE | What it does | Who runs it |
|---|---|---|
| `reset-db` | DROP + CREATE DATABASE (destroys all data) | server admin |
| `setup-roles` | Creates app/admin roles + legacy alias roles + grants | server admin |
| `migrate` | Python DDL + SQL migrations (with skip list 001-079) | app admin |
| `restore` | Loads bundled `sandbox_dump.json` into target | server admin (needs `session_replication_role`) |
| `patch-sql` | Runs a single range of SQL migration files (PATCH_FROM/PATCH_TO) via raw psql | app admin |
| `sync-schema` | Adds missing columns from bundled `local_cols.json` | app admin |
| `all` | setup-roles → migrate → restore | mixed (uses whatever creds are set) |

The script is at `deploy/migration/run.sh`. Each phase is a bash function; routing is a simple `case "$PHASE"` at the end.
