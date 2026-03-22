# AuditGraph Database Migration Guide

## Overview

This document covers how to set up a fresh AuditGraph database on any environment (dev/qa/stg/prod). Each environment is independent with its own organizations, users, and data. The admin portal is the single entry point for client onboarding.

## Environment Model

```
localhost (sandbox)  ─ local Docker DB, auto-seeds AzureCredits + Demo orgs
dev                  ─ Azure Cloud Dev DB, clean — orgs added via dev.admin
qa                   ─ Azure Cloud QA DB, clean — orgs added via qa.admin
stg                  ─ Azure Cloud Stg DB, clean — orgs added via stg.admin
prod                 ─ Azure Cloud Prod DB, clean — orgs added via admin portal
```

Each non-local environment starts with:
- Complete schema (116 tables, 524 indexes, 258 RLS policies, 67 triggers, 982 constraints)
- Reference/seed data (10 global tables, 225 rows)
- 1 organization: Platform Admin
- 1 user: techadmin (superadmin, portal_role=superadmin)
- Zero client data

---

## Variables Reference

All scripts below use these placeholders. Set them once at the top of your terminal session.

```bash
# ── Set these for your target environment ─────────────────────────
export ENV="qa"                                          # dev | qa | stg | prod
export REGION="eastus2"                                  # Azure region
export RG="eus2-ag-nonprod-rg"                           # Resource group
export PG_SERVER="cus-ag-nonprod-pg"                     # Flex Server name (without .postgres.database.azure.com)
export PG_SERVER_ADMIN="auditgraph_${ENV}_eastus2"       # Server admin username (created during server provision)
export PG_SERVER_ADMIN_PW="<server_admin_password>"      # Server admin password
export DB_NAME="auditgraph_${ENV}_eastus2"               # Database name
export ADMIN_USER="auditgraph_${ENV}_admin"              # App admin DB user (BYPASSRLS)
export ADMIN_PW="<strong_password_admin>"                 # App admin DB password
export APP_USER="auditgraph_${ENV}_app"                  # App DB user (NOBYPASSRLS)
export APP_PW="<strong_password_app>"                     # App DB password
export PLATFORM_ADMIN_PW="changeme"                      # techadmin login password
export ACR="auditgraphcr"                                # Azure Container Registry name
export CAE="<container_app_env_name>"                     # Container App Environment name
export CONTAINER_API="auditgraph-api-${ENV}"             # API container app name
export CONTAINER_WEB="auditgraph-web-${ENV}"             # Web (client) container app name
export CONTAINER_ADMIN="auditgraph-admin-${ENV}"         # Admin container app name
export DOMAIN="auditgraph.ai"                            # Base domain
```

---

## Pre-Migration: Section A — Source Machine Setup

Prepare your laptop / CI runner. Run all commands from `backend/` directory.

```bash
cd backend
```

### A.1 — Start Docker & Postgres Container

```bash
# Verify Docker is running
docker ps > /dev/null 2>&1 && echo "OK: Docker running" || echo "FAIL: Start Docker Desktop"

# Start the Postgres container (if not already running)
docker compose up -d postgres

# Verify container is up and DB is accessible
docker exec auditgraph-postgres pg_isready -U auditgraph -d auditgraph \
  && echo "OK: Postgres container ready" \
  || echo "FAIL: Postgres container not ready"
```

### A.2 — Ensure Local DB Is Populated (116 tables)

```bash
# Check table count — should be 116
PGPASSWORD=auditgraph psql -h localhost -p 5434 -U auditgraph -d auditgraph -t \
  -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public';" | tr -d ' '

# If less than 116, start the app once to run all _ensure_* DDL methods:
./venv/bin/python -c "from app.main import create_app; create_app()"
```

### A.3 — Ensure Python Venv Has psycopg2

```bash
./venv/bin/python -c "import psycopg2; print('OK: psycopg2 installed')" 2>/dev/null \
  || ./venv/bin/pip install psycopg2-binary
```

### A.4 — Ensure pg_dump v15 Is Available (via Docker)

```bash
docker exec auditgraph-postgres pg_dump --version
# Expected: pg_dump (PostgreSQL) 15.x
```

### A.5 — Ensure psql Client Is Installed

```bash
psql --version 2>/dev/null \
  && echo "OK: psql installed" \
  || echo "FAIL: Install with 'brew install postgresql@15' (Mac) or 'apt install postgresql-client-15' (Linux)"
```

### A.6 — Ensure Seed Scripts Have Been Run on Local

```bash
# These seed reference data + may ALTER TABLE (adds columns).
# The migration script runs them automatically, but you can pre-run:
./venv/bin/python tools/patches/seed_all_32_roles.py
./venv/bin/python tools/patches/seed_verified_attacks.py
./venv/bin/python tools/patches/seed_remediations.py
```

### A.7 — Verify Source Readiness (all-in-one check)

```bash
echo "── Source Machine Readiness ──"
docker ps > /dev/null 2>&1 && echo "  [OK] Docker running" || echo "  [FAIL] Docker not running"
docker exec auditgraph-postgres pg_isready -U auditgraph -d auditgraph > /dev/null 2>&1 \
  && echo "  [OK] Postgres container" || echo "  [FAIL] Postgres container"
TABLES=$(PGPASSWORD=auditgraph psql -h localhost -p 5434 -U auditgraph -d auditgraph -t \
  -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public';" 2>/dev/null | tr -d ' ')
[ "$TABLES" = "116" ] && echo "  [OK] Local DB: $TABLES tables" || echo "  [FAIL] Local DB: $TABLES tables (expected 116)"
./venv/bin/python -c "import psycopg2" 2>/dev/null \
  && echo "  [OK] psycopg2" || echo "  [FAIL] psycopg2 not installed"
docker exec auditgraph-postgres pg_dump --version > /dev/null 2>&1 \
  && echo "  [OK] pg_dump v15 (Docker)" || echo "  [FAIL] pg_dump"
psql --version > /dev/null 2>&1 \
  && echo "  [OK] psql client" || echo "  [FAIL] psql client not installed"
```

---

## Pre-Migration: Section B — Target Azure Environment (one-time per env)

These steps create the Azure infrastructure. Only run once per environment.

### B.1 — Create Resource Group

```bash
az group create \
  --name $RG \
  --location $REGION \
  --output table
```

### B.2 — Create Azure Flexible Server (PostgreSQL 15)

```bash
az postgres flexible-server create \
  --name $PG_SERVER \
  --resource-group $RG \
  --location $REGION \
  --sku-name Standard_B1ms \
  --storage-size 32 \
  --version 15 \
  --admin-user $PG_SERVER_ADMIN \
  --admin-password "$PG_SERVER_ADMIN_PW" \
  --yes \
  --output table

# Enforce SSL
az postgres flexible-server parameter set \
  --server-name $PG_SERVER \
  --resource-group $RG \
  --name require_secure_transport \
  --value on
```

### B.3 — Create the Database

```bash
az postgres flexible-server db create \
  --server-name $PG_SERVER \
  --resource-group $RG \
  --database-name $DB_NAME \
  --output table
```

### B.4 — Add Temporary Firewall Rule (for migration from your machine)

```bash
MY_IP=$(curl -s ifconfig.me)
echo "Your IP: $MY_IP"

az postgres flexible-server firewall-rule create \
  --server-name $PG_SERVER \
  --resource-group $RG \
  --name allow-migration \
  --start-ip-address $MY_IP \
  --end-ip-address $MY_IP \
  --output table
```

### B.5 — Create DB Users (Admin + App)

```bash
# Connect as server admin
PGPASSWORD="$PG_SERVER_ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${PG_SERVER_ADMIN} sslmode=require" \
  <<SQL

-- Admin user (BYPASSRLS — startup DDL, migrations, superadmin ops)
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${ADMIN_USER}') THEN
    CREATE ROLE ${ADMIN_USER} WITH LOGIN PASSWORD '${ADMIN_PW}' BYPASSRLS;
  END IF;
END \$\$;
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${ADMIN_USER};
GRANT ALL PRIVILEGES ON SCHEMA public TO ${ADMIN_USER};
GRANT CREATE ON SCHEMA public TO ${ADMIN_USER};

-- App user (NOBYPASSRLS — RLS enforced, tenant-scoped requests)
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}') THEN
    CREATE ROLE ${APP_USER} WITH LOGIN PASSWORD '${APP_PW}' NOBYPASSRLS;
  END IF;
END \$\$;
GRANT USAGE ON SCHEMA public TO ${APP_USER};
GRANT CREATE ON SCHEMA public TO ${APP_USER};

-- App user inherits admin ownership (needed for startup DDL guards)
GRANT ${ADMIN_USER} TO ${APP_USER};

-- Verify
SELECT rolname, rolbypassrls, rolsuper
FROM pg_roles
WHERE rolname LIKE 'auditgraph_${ENV}_%';

SQL
```

### B.6 — Verify DB Connectivity from Migration Machine

```bash
PGPASSWORD="$ADMIN_PW" pg_isready \
  -h ${PG_SERVER}.postgres.database.azure.com \
  -p 5432 \
  -U $ADMIN_USER \
  -d $DB_NAME \
  && echo "OK: Can reach target DB" \
  || echo "FAIL: Cannot reach target DB — check firewall rule"
```

### B.7 — Deploy Container Apps (API + Web + Admin)

```bash
# Build and push API image
az acr build \
  --registry $ACR \
  --image ${CONTAINER_API}:latest \
  --platform linux/amd64 \
  --file Dockerfile .

# Build and push Web (client) image
az acr build \
  --registry $ACR \
  --image ${CONTAINER_WEB}:latest \
  --platform linux/amd64 \
  --file ../frontend/Dockerfile ../frontend/ \
  --build-arg REACT_APP_API_URL=https://${ENV}.api.${DOMAIN}

# Build and push Admin image
az acr build \
  --registry $ACR \
  --image ${CONTAINER_ADMIN}:latest \
  --platform linux/amd64 \
  --file ../frontend/Dockerfile.admin ../frontend/ \
  --build-arg REACT_APP_API_URL=https://${ENV}.api.${DOMAIN}

# Create API container app (or update existing)
az containerapp create \
  --name $CONTAINER_API \
  --resource-group $RG \
  --environment $CAE \
  --image ${ACR}.azurecr.io/${CONTAINER_API}:latest \
  --registry-server ${ACR}.azurecr.io \
  --target-port 5000 \
  --ingress external \
  --min-replicas 1 --max-replicas 2 \
  --env-vars \
    APP_ENV="${ENV}" \
    FLASK_ENV="production" \
    PYTHONUNBUFFERED="1" \
    DB_HOST="${PG_SERVER}.postgres.database.azure.com" \
    DB_PORT="5432" \
    DB_NAME="${DB_NAME}" \
    DB_SSLMODE="require" \
    CORS_ORIGINS="https://${ENV}.app.${DOMAIN},https://${ENV}.admin.${DOMAIN}" \
  --secrets \
    db-user="${APP_USER}" \
    db-password="${APP_PW}" \
    db-admin-user="${ADMIN_USER}" \
    db-admin-password="${ADMIN_PW}" \
    admin-password="${PLATFORM_ADMIN_PW}" \
    jwt-secret="$(openssl rand -hex 32)" \
    admin-jwt-secret="$(openssl rand -hex 32)" \
    client-jwt-secret="$(openssl rand -hex 32)" \
  --secret-env-vars \
    DB_USER=db-user \
    DB_PASSWORD=db-password \
    DB_ADMIN_USER=db-admin-user \
    DB_ADMIN_PASSWORD=db-admin-password \
    ADMIN_PASSWORD=admin-password \
    JWT_SECRET=jwt-secret \
    ADMIN_JWT_SECRET=admin-jwt-secret \
    CLIENT_JWT_SECRET=client-jwt-secret

# Create Web (client) container app
az containerapp create \
  --name $CONTAINER_WEB \
  --resource-group $RG \
  --environment $CAE \
  --image ${ACR}.azurecr.io/${CONTAINER_WEB}:latest \
  --registry-server ${ACR}.azurecr.io \
  --target-port 80 \
  --ingress external \
  --min-replicas 1 --max-replicas 1

# Create Admin container app
az containerapp create \
  --name $CONTAINER_ADMIN \
  --resource-group $RG \
  --environment $CAE \
  --image ${ACR}.azurecr.io/${CONTAINER_ADMIN}:latest \
  --registry-server ${ACR}.azurecr.io \
  --target-port 80 \
  --ingress external \
  --min-replicas 1 --max-replicas 1
```

### B.8 — Configure Custom Domains + TLS Certificates

```bash
# Add custom hostnames to each container app
az containerapp hostname add --name $CONTAINER_API   --resource-group $RG --hostname ${ENV}.api.${DOMAIN}
az containerapp hostname add --name $CONTAINER_WEB   --resource-group $RG --hostname ${ENV}.app.${DOMAIN}
az containerapp hostname add --name $CONTAINER_ADMIN --resource-group $RG --hostname ${ENV}.admin.${DOMAIN}

# Before binding certificates, add DNS CNAME records:
#   ${ENV}.api.${DOMAIN}   → CNAME → ${CONTAINER_API}.<cae-default-domain>
#   ${ENV}.app.${DOMAIN}   → CNAME → ${CONTAINER_WEB}.<cae-default-domain>
#   ${ENV}.admin.${DOMAIN} → CNAME → ${CONTAINER_ADMIN}.<cae-default-domain>
#
# Get the default domain:
az containerapp env show --name $CAE --resource-group $RG --query "properties.defaultDomain" -o tsv

# Bind managed certificates (run after DNS propagation, may take up to 20 min)
az containerapp hostname bind --name $CONTAINER_API   --resource-group $RG --hostname ${ENV}.api.${DOMAIN}   --environment $CAE --validation-method CNAME
az containerapp hostname bind --name $CONTAINER_WEB   --resource-group $RG --hostname ${ENV}.app.${DOMAIN}   --environment $CAE --validation-method CNAME
az containerapp hostname bind --name $CONTAINER_ADMIN --resource-group $RG --hostname ${ENV}.admin.${DOMAIN} --environment $CAE --validation-method CNAME
```

### B.9 — Add Environment to Migration Script

```bash
# Append the new env config to migrate_env.py
# (Or manually edit backend/scripts/migrate_env.py and add to the ENVS dict)
cat <<EOF

Add this to ENVS dict in backend/scripts/migrate_env.py:

    "${ENV}": {
        "dsn": (
            "dbname=${DB_NAME} "
            "user=${ADMIN_USER} "
            "password=${ADMIN_PW} "
            "host=${PG_SERVER}.postgres.database.azure.com "
            "port=5432 sslmode=require"
        ),
        "app_user": "${APP_USER}",
        "admin_user": "${ADMIN_USER}",
    },
EOF
```

### B.10 — Verify Target Readiness (all-in-one check)

```bash
echo "── Target Environment Readiness (${ENV}) ──"
az group show --name $RG > /dev/null 2>&1 \
  && echo "  [OK] Resource group: $RG" || echo "  [FAIL] Resource group"
az postgres flexible-server show --name $PG_SERVER --resource-group $RG > /dev/null 2>&1 \
  && echo "  [OK] Flex Server: $PG_SERVER" || echo "  [FAIL] Flex Server"
az postgres flexible-server db show --server-name $PG_SERVER --resource-group $RG --database-name $DB_NAME > /dev/null 2>&1 \
  && echo "  [OK] Database: $DB_NAME" || echo "  [FAIL] Database"
PGPASSWORD="$ADMIN_PW" pg_isready -h ${PG_SERVER}.postgres.database.azure.com -p 5432 -U $ADMIN_USER -d $DB_NAME > /dev/null 2>&1 \
  && echo "  [OK] DB connectivity (admin user)" || echo "  [FAIL] DB connectivity"
PGPASSWORD="$APP_PW" pg_isready -h ${PG_SERVER}.postgres.database.azure.com -p 5432 -U $APP_USER -d $DB_NAME > /dev/null 2>&1 \
  && echo "  [OK] DB connectivity (app user)" || echo "  [FAIL] DB connectivity (app user)"
ROLES=$(PGPASSWORD="$ADMIN_PW" psql "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" -t \
  -c "SELECT COUNT(*) FROM pg_roles WHERE rolname IN ('${ADMIN_USER}','${APP_USER}');" 2>/dev/null | tr -d ' ')
[ "$ROLES" = "2" ] && echo "  [OK] DB users: admin + app" || echo "  [FAIL] DB users (found $ROLES, expected 2)"
az containerapp show --name $CONTAINER_API --resource-group $RG > /dev/null 2>&1 \
  && echo "  [OK] Container App: $CONTAINER_API" || echo "  [FAIL] Container App: $CONTAINER_API"
curl -s -o /dev/null -w "%{http_code}" https://${ENV}.api.${DOMAIN}/api/health 2>/dev/null | grep -q 200 \
  && echo "  [OK] API health: https://${ENV}.api.${DOMAIN}" || echo "  [WARN] API not reachable yet (expected before migration)"
curl -s -o /dev/null -w "%{http_code}" https://${ENV}.app.${DOMAIN}/ 2>/dev/null | grep -q 200 \
  && echo "  [OK] Client portal: https://${ENV}.app.${DOMAIN}" || echo "  [WARN] Client portal not reachable"
curl -s -o /dev/null -w "%{http_code}" https://${ENV}.admin.${DOMAIN}/ 2>/dev/null | grep -q 200 \
  && echo "  [OK] Admin portal: https://${ENV}.admin.${DOMAIN}" || echo "  [WARN] Admin portal not reachable"
grep -q "\"${ENV}\"" scripts/migrate_env.py 2>/dev/null \
  && echo "  [OK] migrate_env.py has '${ENV}' config" || echo "  [FAIL] Add '${ENV}' to ENVS in migrate_env.py"
```

---

## Migration Steps

### Step 1: Run the Migration Script

```bash
cd backend

# Full migration (fresh schema dump from local + reference data)
./venv/bin/python scripts/migrate_env.py --target $ENV

# Re-run with cached schema dump (faster, skips pg_dump)
./venv/bin/python scripts/migrate_env.py --target $ENV --skip-schema-dump
```

**What it does:**

| Phase | Action | Details |
|-------|--------|---------|
| 1 | Dump schema | Runs seed scripts on local, then `pg_dump --schema-only` via Docker |
| 2 | Clean target | DROP all tables, views, sequences, functions on target DB |
| 3 | Load schema | Load DDL via `psql` (116 tables, 524 indexes, 258 RLS policies, 67 triggers) |
| 4 | Copy reference data | 10 global tables, 225 rows (see table below) |
| 5 | Grant permissions | DML to app user, ALL to admin user |
| 6 | Reset sequences | All SERIAL sequences set to MAX(id) + 1 |
| 7 | Verify | Count all schema objects + reference data rows |

### Step 2: Restart the API Container

```bash
# Update to latest image + restart
az containerapp update \
  --name $CONTAINER_API \
  --resource-group $RG \
  --image ${ACR}.azurecr.io/${CONTAINER_API}:latest

# Or restart existing revision (no image change):
az containerapp revision restart \
  --name $CONTAINER_API \
  --resource-group $RG \
  --revision $(az containerapp revision list \
    --name $CONTAINER_API \
    --resource-group $RG \
    --query "[0].name" -o tsv)

# Wait for health
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://${ENV}.api.${DOMAIN}/api/health 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "API is up" && break
  echo "Waiting... ($i, status=$STATUS)"
  sleep 10
done
```

### Step 3: Remove Temp Firewall Rule

```bash
az postgres flexible-server firewall-rule delete \
  --server-name $PG_SERVER \
  --resource-group $RG \
  --name allow-migration --yes
```

---

## Post-Migration Verification

### Automated (built into migration script Phase 7)

The script prints a verification report. All counts should match:

```
Tables:       116
Columns:      1883
Indexes:      524
RLS Policies: 258
Triggers:     67
Sequences:    107
Views:        2
Functions:    67
Constraints:  982
```

### Post-Migration Verification Script

```bash
echo "══════════════════════════════════════════════════════════"
echo "  POST-MIGRATION VERIFICATION — ${ENV}"
echo "══════════════════════════════════════════════════════════"

TARGET_DSN="host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} password=${ADMIN_PW} sslmode=require"

echo ""
echo "── 1. API Health ──"
curl -s https://${ENV}.api.${DOMAIN}/api/health | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'  Status: {d[\"status\"]} | DB: {d[\"checks\"][\"database\"]} | Scheduler: {d[\"checks\"][\"scheduler\"]}')
" 2>/dev/null || echo "  FAIL: API not reachable"

echo ""
echo "── 2. Admin Portal Login ──"
curl -s https://${ENV}.api.${DOMAIN}/api/auth/login \
  -X POST -H "Content-Type: application/json" \
  -H "X-Portal-Context: admin" \
  -H "Origin: https://${ENV}.admin.${DOMAIN}" \
  -d "{\"username\":\"techadmin\",\"password\":\"${PLATFORM_ADMIN_PW}\"}" 2>/dev/null \
  | python3 -c "
import sys,json; d=json.load(sys.stdin)
if 'error' in d: print(f'  FAIL: {d[\"error\"]}')
else:
    u=d['user']
    print(f'  OK: {u[\"username\"]} | superadmin={u[\"is_superadmin\"]} | portal_role={u.get(\"portal_role\")}')
" 2>/dev/null

echo ""
echo "── 3. Portal URLs ──"
echo "  Admin:  $(curl -s -o /dev/null -w '%{http_code}' https://${ENV}.admin.${DOMAIN}/) — https://${ENV}.admin.${DOMAIN}"
echo "  Client: $(curl -s -o /dev/null -w '%{http_code}' https://${ENV}.app.${DOMAIN}/)   — https://${ENV}.app.${DOMAIN}"
echo "  API:    $(curl -s -o /dev/null -w '%{http_code}' https://${ENV}.api.${DOMAIN}/api/health) — https://${ENV}.api.${DOMAIN}"

echo ""
echo "── 4. Database State ──"
PGPASSWORD="$ADMIN_PW" psql "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" -t -c "
SELECT '  Organizations: ' || COUNT(*) FROM organizations
UNION ALL SELECT '  Users:         ' || COUNT(*) FROM users
UNION ALL SELECT '  Identities:    ' || COUNT(*) FROM identities
UNION ALL SELECT '  Connections:   ' || COUNT(*) FROM cloud_connections
UNION ALL SELECT '  Runs:          ' || COUNT(*) FROM discovery_runs;
" 2>/dev/null

echo ""
echo "── 5. Schema Counts ──"
PGPASSWORD="$ADMIN_PW" psql "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" -t -c "
SELECT '  Tables:      ' || COUNT(*) FROM pg_tables WHERE schemaname='public'
UNION ALL SELECT '  Columns:     ' || COUNT(*) FROM information_schema.columns WHERE table_schema='public'
UNION ALL SELECT '  Indexes:     ' || COUNT(*) FROM pg_indexes WHERE schemaname='public'
UNION ALL SELECT '  RLS Policies:' || COUNT(*) FROM pg_policies
UNION ALL SELECT '  Triggers:    ' || COUNT(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid=c.oid JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND NOT t.tgisinternal
UNION ALL SELECT '  Sequences:   ' || COUNT(*) FROM information_schema.sequences WHERE sequence_schema='public'
UNION ALL SELECT '  Views:       ' || COUNT(*) FROM information_schema.views WHERE table_schema='public'
UNION ALL SELECT '  Functions:   ' || COUNT(*) FROM (SELECT DISTINCT routine_name FROM information_schema.routines WHERE routine_schema='public' AND routine_type='FUNCTION') x
UNION ALL SELECT '  Constraints: ' || COUNT(*) FROM information_schema.table_constraints WHERE table_schema='public';
" 2>/dev/null

echo ""
echo "── 6. Reference Data ──"
for tbl in compliance_frameworks compliance_controls compliance_root_causes remediation_playbooks role_permissions role_attack_patterns role_hipaa_mappings platform_settings plans schema_migrations; do
  CNT=$(PGPASSWORD="$ADMIN_PW" psql "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" -t -c "SELECT COUNT(*) FROM $tbl;" 2>/dev/null | tr -d ' ')
  printf "  %-28s %s rows\n" "$tbl" "$CNT"
done

echo ""
echo "══════════════════════════════════════════════════════════"
```

### Expected Post-Migration State

| Check | Expected |
|-------|----------|
| API health | `ready`, database `ok`, scheduler `ok` |
| Admin login | 200, `is_superadmin=true`, `portal_role=superadmin` |
| Organizations | 1 (Platform Admin) |
| Users | 1 (techadmin) |
| Identities | 0 |
| Cloud connections | 0 |
| Discovery runs | 0 |
| Tables | 116 |
| Columns | 1883 |
| Indexes | 524 |
| RLS Policies | 258 |
| Triggers | 67 |
| Sequences | 107 |
| Views | 2 |
| Functions | 67 |
| Constraints | 982 |
| Reference data total | 225 rows |

---

## What App Startup Creates

After migration, the API container startup runs this sequence:

| Step | Function | Runs on | Creates |
|------|----------|---------|---------|
| 1 | `ensure_default_admin()` | ALL envs | techadmin user (superadmin, portal_role=superadmin) in Platform Admin org |
| 2 | `seed_local_admin()` | `local` ONLY | admin user + default org — **SKIPPED on dev/qa/stg/prod** |
| 3 | `seed_dev_tenant()` | `local` ONLY | AzureCredits org + azadmin — **SKIPPED on dev/qa/stg/prod** |
| 4 | `seed_demo_tenant()` | `local` ONLY | Demo org + demo users — **SKIPPED on dev/qa/stg/prod** |
| 5 | `validate_rls_startup()` | ALL envs | Verifies dual-user RLS architecture |
| 6 | FORCE ROW LEVEL SECURITY | ALL envs | Applied on all tenant-scoped tables |
| 7 | Start scheduler | ALL envs | Continuous discovery (5 min), scans (12h), retention (daily) |

**Result on non-local envs:** 1 org (Platform Admin), 1 user (techadmin), 0 clients, 0 identities.

---

## Client Onboarding Flow

After migration + API restart:

```
1. Login to admin portal
   URL:  https://{env}.admin.auditgraph.ai
   User: techadmin / {ADMIN_PASSWORD}

2. Create new organization (tenant)
   Admin Portal → Tenants → + New Tenant
   Fill: name, slug, plan tier (free/trial/pro/enterprise)

3. Create client admin user
   Admin Portal → Tenants → select tenant → Users → + New User
   Fill: username, password, role=admin

4. Client logs in at client portal
   URL:  https://{env}.app.auditgraph.ai
   User: client admin credentials from step 3

5. Client connects cloud provider
   Client Portal → Settings → Connections → + Add Connection
   Select: Azure
   Enter: Azure Directory (Tenant) ID, Client ID, Client Secret
   Click: Test Connection → should show "Connected"

6. Run discovery
   Client Portal → Settings → Manual Scan → Trigger
   OR: wait for scheduler (next scan within 5 minutes for continuous, 12h for full)

7. Dashboard populated
   Identities, roles, credentials, resources discovered
   AGIRS score computed, attack paths analyzed, exposures flagged
   All dashboard widgets show real data
```

---

## Full Wipe & Rebuild

To completely reset any environment back to clean state:

```bash
cd backend

# Step 1: Add firewall rule (if needed)
MY_IP=$(curl -s ifconfig.me)
az postgres flexible-server firewall-rule create \
  --server-name $PG_SERVER --resource-group $RG \
  --name allow-migration \
  --start-ip-address $MY_IP --end-ip-address $MY_IP

# Step 2: Wipe + migrate
./venv/bin/python scripts/migrate_env.py --target $ENV

# Step 3: Restart API container
az containerapp revision restart \
  --name $CONTAINER_API \
  --resource-group $RG \
  --revision $(az containerapp revision list \
    --name $CONTAINER_API \
    --resource-group $RG \
    --query "[0].name" -o tsv)

# Step 4: Wait for health
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://${ENV}.api.${DOMAIN}/api/health 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "API is up" && break
  echo "Waiting... ($i)" && sleep 10
done

# Step 5: Run post-migration verification (section above)

# Step 6: Remove firewall rule
az postgres flexible-server firewall-rule delete \
  --server-name $PG_SERVER --resource-group $RG \
  --name allow-migration --yes
```

**WARNING:** This destroys ALL data (organizations, users, identities, discovery history, settings) on the target environment. Only reference/seed data is preserved.

---

## Seed Scripts (Local Only)

These scripts seed reference data into the LOCAL database. The migration script copies the result to target environments automatically.

| Script | Purpose | Run On |
|--------|---------|--------|
| `tools/patches/seed_all_32_roles.py` | 32 Azure/Entra roles with risk intelligence | Local |
| `tools/patches/seed_verified_attacks.py` | 14 verified real-world breach patterns | Local |
| `tools/patches/seed_remediations.py` | 20 remediation playbooks | Local |
| `scripts/seed_demo_tenant.py` | Demo org with 120+ synthetic identities | Local only |

The migration script auto-runs schema-altering seeds (`seed_all_32_roles.py`, `seed_verified_attacks.py`) before `pg_dump` to ensure the schema dump captures any `ALTER TABLE ADD COLUMN` changes made by these scripts.

---

## Dual-User RLS Architecture

| User | Naming Convention | Purpose | RLS |
|------|------------------|---------|-----|
| Admin | `auditgraph_{env}_admin` | Startup DDL, migrations, superadmin ops | BYPASSRLS |
| App | `auditgraph_{env}_app` | Tenant-scoped HTTP request handlers | NOBYPASSRLS |

- 44 tenant-scoped tables have `organization_id NOT NULL` + strict RLS policies
- Policies use `current_setting('app.current_organization_id', true)::integer`
- App user connections set `SET LOCAL app.current_organization_id = N` per request
- Admin user bypasses RLS entirely (used for cross-tenant admin operations)

---

## Troubleshooting

### "CREATE TABLE IF NOT EXISTS" permission error
```bash
# App user needs CREATE on public schema
PGPASSWORD="$PG_SERVER_ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${PG_SERVER_ADMIN} sslmode=require" \
  -c "GRANT CREATE ON SCHEMA public TO ${APP_USER};"
```

### "must be owner of table" for CREATE INDEX
```bash
# Grant admin role to app user (RLS still enforced — BYPASSRLS is NOT inherited)
PGPASSWORD="$PG_SERVER_ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${PG_SERVER_ADMIN} sslmode=require" \
  -c "GRANT ${ADMIN_USER} TO ${APP_USER};"
```

### Scheduler creates empty discovery runs
The scheduler runs discovery for all `connected` cloud connections. If credentials don't work from the container network, discovery completes with 0 identities.
```bash
# Check cloud_connections status
PGPASSWORD="$ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" \
  -c "SELECT id, organization_id, cloud, status, label FROM cloud_connections;"
```
Fix: ensure the Azure app registration credentials are valid from the container's outbound IP. Required API permissions: `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`.

### techadmin can't login to admin portal
```bash
# Check and fix portal_role
PGPASSWORD="$ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" \
  -c "SELECT username, is_superadmin, portal_role FROM users WHERE username = 'techadmin';"

PGPASSWORD="$ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" \
  -c "UPDATE users SET portal_role = 'superadmin' WHERE username = 'techadmin';"
```

### Tables exist but RLS blocks all data
```bash
# Check RLS policies on a table
PGPASSWORD="$ADMIN_PW" psql \
  "host=${PG_SERVER}.postgres.database.azure.com port=5432 dbname=${DB_NAME} user=${ADMIN_USER} sslmode=require" \
  -c "SELECT tablename, policyname, cmd, qual FROM pg_policies WHERE tablename = 'identities';"
```

### Migration script can't connect to target DB
```bash
# Check firewall rules
az postgres flexible-server firewall-rule list \
  --server-name $PG_SERVER --resource-group $RG --output table

# Add your IP
MY_IP=$(curl -s ifconfig.me)
az postgres flexible-server firewall-rule create \
  --server-name $PG_SERVER --resource-group $RG \
  --name allow-migration \
  --start-ip-address $MY_IP --end-ip-address $MY_IP

# Test connectivity
PGPASSWORD="$ADMIN_PW" pg_isready \
  -h ${PG_SERVER}.postgres.database.azure.com -p 5432 -U $ADMIN_USER -d $DB_NAME
```

### psql version mismatch during Phase 3
```bash
# Check versions
psql --version
docker exec auditgraph-postgres pg_dump --version

# If psql is too old, install v15+
brew install postgresql@15          # Mac
sudo apt install postgresql-client-15  # Linux
```

---

## Reference Data Tables

| Table | Rows | Description |
|-------|------|-------------|
| `compliance_frameworks` | 11 | GRC framework definitions (SOC2, HIPAA, NIST, etc.) |
| `compliance_controls` | 119 | Control requirements per framework |
| `compliance_root_causes` | 7 | Root cause → risk factor mapping |
| `remediation_playbooks` | 20 | Standard remediation playbooks |
| `role_permissions` | 32 | Azure/Entra role intelligence (risk levels, descriptions) |
| `role_attack_patterns` | 14 | Verified real-world breach incidents |
| `role_hipaa_mappings` | 6 | HIPAA violation mappings for key roles |
| `platform_settings` | 8 | Platform-wide configuration |
| `plans` | 4 | Billing plan tiers (free/trial/pro/enterprise) |
| `schema_migrations` | 4 | Migration version tracking |
| **Total** | **225** | |

---

## Dev Environment Quick Reference

| Resource | URL / Value |
|----------|-------------|
| API | `https://dev.api.auditgraph.ai` |
| Admin Portal | `https://dev.admin.auditgraph.ai` |
| Client Portal | `https://dev.app.auditgraph.ai` |
| DB Host | `cus-ag-nonprod-pg.postgres.database.azure.com` |
| DB Name | `auditgraph_dev_eastus2` |
| Admin DB User | `auditgraph_dev_admin` |
| App DB User | `auditgraph_dev_app` |
| Platform Login | `techadmin` / (ADMIN_PASSWORD secret) |
| Resource Group | `eus2-ag-nonprod-rg` |
| Container App | `auditgraph-api-dev` |
| ACR Image | `auditgraphcr.azurecr.io/auditgraph-api-dev:latest` |
