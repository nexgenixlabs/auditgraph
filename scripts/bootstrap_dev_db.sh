#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AuditGraph DEV Database Bootstrap
#
# Validates env vars, tests DB connectivity, runs migrations + DDL,
# seeds the demo tenant, and verifies tables were created.
#
# Usage:
#   ./scripts/bootstrap_dev_db.sh
#
# Required environment variables:
#   DEV_DB_HOST (or DB_HOST)
#   DEV_DB_NAME (or DB_NAME)
#   DEV_DB_USER (or DB_USER)
#   DEV_DB_PASSWORD (or DB_PASSWORD)
#   DEV_DB_ADMIN_USER (or DB_ADMIN_USER)
#   DEV_DB_ADMIN_PASSWORD (or DB_ADMIN_PASSWORD)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "\n\033[1;34m▸ $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓ $*\033[0m"; }
fail() { echo -e "  \033[1;31m✗ $*\033[0m"; exit 1; }

# ── Step 1: Validate Environment Variables ───────────────────────────────────

log "Validating environment variables"

# Support both DEV_ prefixed (CI) and unprefixed (local) var names
export DB_HOST="${DEV_DB_HOST:-${DB_HOST:-}}"
export DB_NAME="${DEV_DB_NAME:-${DB_NAME:-}}"
export DB_USER="${DEV_DB_USER:-${DB_USER:-}}"
export DB_PASSWORD="${DEV_DB_PASSWORD:-${DB_PASSWORD:-}}"
export DB_ADMIN_USER="${DEV_DB_ADMIN_USER:-${DB_ADMIN_USER:-}}"
export DB_ADMIN_PASSWORD="${DEV_DB_ADMIN_PASSWORD:-${DB_ADMIN_PASSWORD:-}}"
export DB_PORT="${DB_PORT:-5432}"
export DB_SSLMODE="${DB_SSLMODE:-require}"

MISSING=()
[[ -z "$DB_HOST" ]]           && MISSING+=("DEV_DB_HOST / DB_HOST")
[[ -z "$DB_NAME" ]]           && MISSING+=("DEV_DB_NAME / DB_NAME")
[[ -z "$DB_USER" ]]           && MISSING+=("DEV_DB_USER / DB_USER")
[[ -z "$DB_PASSWORD" ]]       && MISSING+=("DEV_DB_PASSWORD / DB_PASSWORD")
[[ -z "$DB_ADMIN_USER" ]]     && MISSING+=("DEV_DB_ADMIN_USER / DB_ADMIN_USER")
[[ -z "$DB_ADMIN_PASSWORD" ]] && MISSING+=("DEV_DB_ADMIN_PASSWORD / DB_ADMIN_PASSWORD")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "  Missing environment variables:"
  for v in "${MISSING[@]}"; do
    echo "    - $v"
  done
  fail "Set the missing variables and retry"
fi

ok "DB_HOST=$DB_HOST"
ok "DB_NAME=$DB_NAME"
ok "DB_USER=$DB_USER"
ok "DB_ADMIN_USER=$DB_ADMIN_USER"

# ── Step 2: Test Database Connectivity ───────────────────────────────────────

log "Testing database connectivity"

# Try admin user first (needed for migrations)
if command -v psql &>/dev/null; then
  PGPASSWORD="$DB_ADMIN_PASSWORD" psql \
    -h "$DB_HOST" -p "$DB_PORT" -U "$DB_ADMIN_USER" -d "$DB_NAME" \
    -c "SELECT 1 AS connectivity_check;" \
    --no-psqlrc -q 2>/dev/null \
    && ok "psql connectivity verified (admin user)" \
    || fail "Cannot connect to $DB_HOST/$DB_NAME as $DB_ADMIN_USER"
else
  # Fallback: use Python psycopg2
  python3 -c "
import psycopg2, os
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=int(os.environ['DB_PORT']),
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_ADMIN_USER'],
    password=os.environ['DB_ADMIN_PASSWORD'],
    sslmode=os.environ.get('DB_SSLMODE', 'require'),
    connect_timeout=10
)
cur = conn.cursor()
cur.execute('SELECT 1')
cur.close()
conn.close()
print('  Connection OK')
" && ok "Python connectivity verified (admin user)" \
  || fail "Cannot connect to $DB_HOST/$DB_NAME as $DB_ADMIN_USER"
fi

# ── Step 3: Run SQL Migrations + Python DDL ──────────────────────────────────

log "Running database migrations (SQL + DDL)"

export APP_ENV=dev

python3 "$REPO_ROOT/scripts/run_migrations.py" --include-ddl
ok "Migrations and DDL complete"

# ── Step 4: Seed Demo Tenant ─────────────────────────────────────────────────

log "Seeding demo tenant"

(cd "$REPO_ROOT/backend" && python3 scripts/seed_demo_tenant.py)
ok "Demo tenant seeded"

# ── Step 5: Verify Tables Exist ──────────────────────────────────────────────

log "Verifying database schema"

TABLE_COUNT=$(python3 -c "
import psycopg2, os
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=int(os.environ['DB_PORT']),
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_ADMIN_USER'],
    password=os.environ['DB_ADMIN_PASSWORD'],
    sslmode=os.environ.get('DB_SSLMODE', 'require')
)
cur = conn.cursor()
cur.execute(\"SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'\")
count = cur.fetchone()[0]
cur.close()
conn.close()
print(count)
")

if [[ "$TABLE_COUNT" -eq 0 ]]; then
  fail "No tables found in public schema after migrations"
fi

ok "$TABLE_COUNT tables in public schema"

# Verify key tables exist
KEY_TABLES="organizations users identities discovery_runs settings"
MISSING_TABLES=()

for tbl in $KEY_TABLES; do
  EXISTS=$(python3 -c "
import psycopg2, os
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=int(os.environ['DB_PORT']),
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_ADMIN_USER'],
    password=os.environ['DB_ADMIN_PASSWORD'],
    sslmode=os.environ.get('DB_SSLMODE', 'require')
)
cur = conn.cursor()
cur.execute(\"SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=%s)\", ('$tbl',))
print(cur.fetchone()[0])
cur.close()
conn.close()
")
  if [[ "$EXISTS" == "True" ]]; then
    ok "Table: $tbl"
  else
    MISSING_TABLES+=("$tbl")
  fi
done

if [[ ${#MISSING_TABLES[@]} -gt 0 ]]; then
  echo "  Missing tables: ${MISSING_TABLES[*]}"
  fail "Required tables not found"
fi

# Verify demo organization exists
DEMO_EXISTS=$(python3 -c "
import psycopg2, os
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=int(os.environ['DB_PORT']),
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_ADMIN_USER'],
    password=os.environ['DB_ADMIN_PASSWORD'],
    sslmode=os.environ.get('DB_SSLMODE', 'require')
)
cur = conn.cursor()
cur.execute(\"SELECT COUNT(*) FROM organizations WHERE slug = 'demo' AND is_demo = true\")
print(cur.fetchone()[0])
cur.close()
conn.close()
")

if [[ "$DEMO_EXISTS" -ge 1 ]]; then
  ok "Demo organization verified (slug=demo, is_demo=true)"
else
  fail "Demo organization not found"
fi

echo ""
echo "  ──────────────────────────────────────"
echo "  Database bootstrap complete"
echo "  $TABLE_COUNT tables | demo tenant ready"
echo "  ──────────────────────────────────────"
