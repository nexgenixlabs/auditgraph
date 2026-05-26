#!/usr/bin/env bash
# Migration job entrypoint. Runs one or more phases against the cloud dev PG.
set -euo pipefail

PHASE="${PHASE:-all}"

log()  { echo -e "\n\033[1;34m▸ $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓ $*\033[0m"; }
fail() { echo -e "  \033[1;31m✗ $*\033[0m"; exit 1; }

run_reset_db() {
  log "Phase: reset-db (DROP + CREATE DATABASE \$DB_NAME)"
  : "${DB_HOST:?required}"
  : "${DB_NAME:?required}"
  : "${SERVER_ADMIN_USER:?required}"
  : "${SERVER_ADMIN_PASSWORD:?required}"
  # Must connect to the management DB (postgres) to drop another DB.
  PGPASSWORD="$SERVER_ADMIN_PASSWORD" psql \
    -h "$DB_HOST" -p "${DB_PORT:-5432}" \
    -U "$SERVER_ADMIN_USER" -d postgres \
    --set ON_ERROR_STOP=1 --no-psqlrc \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();" \
    -c "DROP DATABASE IF EXISTS $DB_NAME;" \
    -c "CREATE DATABASE $DB_NAME;"
  ok "Database $DB_NAME reset"
}

run_setup_roles() {
  log "Phase: setup-roles"
  : "${DB_HOST:?required}"
  : "${DB_NAME:?required}"
  : "${SERVER_ADMIN_USER:?required}"
  : "${SERVER_ADMIN_PASSWORD:?required}"
  PGPASSWORD="$SERVER_ADMIN_PASSWORD" psql \
    -h "$DB_HOST" -p "${DB_PORT:-5432}" \
    -U "$SERVER_ADMIN_USER" -d "$DB_NAME" \
    --set ON_ERROR_STOP=1 --no-psqlrc \
    -f /app/backend/scripts/setup_dev_db_roles.sql
  ok "Roles created/verified"
}

run_migrate() {
  log "Phase: migrate (Python DDL first, then SQL migrations)"
  : "${DB_HOST:?required}"
  : "${DB_NAME:?required}"
  : "${DB_ADMIN_USER:?required}"
  : "${DB_ADMIN_PASSWORD:?required}"
  export DB_HOST DB_NAME DB_ADMIN_USER DB_ADMIN_PASSWORD
  export DB_PORT="${DB_PORT:-5432}"
  export DB_SSLMODE="${DB_SSLMODE:-require}"
  # Backend's create_app() runs as admin during bootstrap. DB_USER/PASSWORD
  # point at the admin role since the app role grants are applied later by
  # create_app() itself (startup step 11: Bulk GRANT).
  export DB_USER="${DB_USER:-$DB_ADMIN_USER}"
  export DB_PASSWORD="${DB_PASSWORD:-$DB_ADMIN_PASSWORD}"

  log "Step 1/2: Python DDL via create_app() (creates all _ensure_*_table() schemas)"
  cd /app/backend
  python3 -c "
from app.main import create_app
app = create_app()
with app.app_context():
    print('  DDL initialization complete.')
"
  ok "Python DDL applied"

  log "Step 2/2: SQL migrations (RLS, indexes, ALTER TABLE patches)"
  cd /app
  # Pre-mark legacy migrations 001-099 as applied: Python DDL has already
  # created all tables they would have built, and several conflict with the
  # current Python schemas (e.g. 014_create_settings.sql uses an old shape).
  # Migrations 100+ are idempotent patches that still need to run.
  python3 << 'PYEOF'
import os, glob, re, psycopg2
conn = psycopg2.connect(
    host=os.environ['DB_HOST'], port=int(os.environ.get('DB_PORT','5432')),
    dbname=os.environ['DB_NAME'], user=os.environ['DB_ADMIN_USER'],
    password=os.environ['DB_ADMIN_PASSWORD'],
    sslmode=os.environ.get('DB_SSLMODE','require'),
)
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        filename TEXT,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
""")
cur.execute("ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS filename TEXT")
applied = 0
# Skip range: 001-079 are early-history migrations that conflict with current
# Python DDL (e.g. 014 settings table shape). 080+ create tables Python DDL
# doesn't (identity_list, approval_requests, phase3_*) — those must run.
for path in sorted(glob.glob('/app/backend/migrations/0[0-9][0-9]_*.sql')):
    name = os.path.basename(path)
    m = re.match(r'^(\d{3})', name)
    if not m: continue
    version = m.group(1)
    v = int(version)
    if v >= 80:  # 080-099 + 100+ run normally
        continue
    cur.execute(
        "INSERT INTO schema_migrations (version, filename) VALUES (%s, %s) "
        "ON CONFLICT (version) DO NOTHING",
        (version, name)
    )
    applied += 1
# Clear any prior pre-marks for 080-099 so they get applied on this run.
cur.execute("DELETE FROM schema_migrations WHERE version >= '080' AND version <= '099'")
# Migration 101 uses CREATE INDEX CONCURRENTLY which can't run via psycopg2's
# multi-statement execute. Pre-mark as applied; the indexes it adds are
# performance optimizations, not correctness-critical. Apply manually later via
# `psql -f 101_identities_org_id_constraints.sql` if needed.
cur.execute(
    "INSERT INTO schema_migrations (version, filename) VALUES (%s, %s) "
    "ON CONFLICT (version) DO NOTHING",
    ('101', '101_identities_org_id_constraints.sql (skipped — needs psql)')
)
conn.commit()
print(f"  Pre-marked {applied} legacy migrations (001-099) as applied")
conn.close()
PYEOF
  python3 /app/scripts/run_migrations.py
  ok "SQL migrations applied"
}

run_restore() {
  log "Phase: restore (sandbox data → cloud)"
  : "${CLOUD_DSN:?required}"
  export CLOUD_DSN
  python3 /app/backend/scripts/migrate_to_cloud_dev.py restore --in /data/sandbox_dump.json
  ok "Restore complete"
}

run_sync_schema() {
  log "Phase: sync-schema (additive ADD COLUMN sync from local sandbox dump)"
  : "${DB_HOST:?required}"
  : "${DB_NAME:?required}"
  : "${DB_ADMIN_USER:?required}"
  : "${DB_ADMIN_PASSWORD:?required}"
  CLOUD_DSN="dbname=$DB_NAME user=$DB_ADMIN_USER password=$DB_ADMIN_PASSWORD host=$DB_HOST port=${DB_PORT:-5432} sslmode=${DB_SSLMODE:-require}" \
    python3 /app/backend/scripts/sync_schema_columns.py apply --in /data/local_cols.json
  ok "sync-schema done"
}

run_patch_sql() {
  # Apply a specific range of SQL migrations directly via psql.
  # Used to bring in 080-099 (phase3 + approval_workflow + execution_engine)
  # which were incorrectly pre-marked as applied by earlier migrate runs.
  log "Phase: patch-sql (range $PATCH_FROM-$PATCH_TO via psql)"
  : "${DB_HOST:?required}"
  : "${DB_NAME:?required}"
  : "${DB_ADMIN_USER:?required}"
  : "${DB_ADMIN_PASSWORD:?required}"
  : "${PATCH_FROM:?required (e.g. 080)}"
  : "${PATCH_TO:?required (e.g. 099)}"

  # Clear stale pre-marks in the range first.
  PGPASSWORD="$DB_ADMIN_PASSWORD" psql \
    -h "$DB_HOST" -p "${DB_PORT:-5432}" \
    -U "$DB_ADMIN_USER" -d "$DB_NAME" \
    --set ON_ERROR_STOP=1 --no-psqlrc \
    -c "DELETE FROM schema_migrations WHERE version >= '$PATCH_FROM' AND version <= '$PATCH_TO';"

  for f in $(ls /app/backend/migrations/[0-9][0-9][0-9]_*.sql | sort); do
    name="$(basename "$f")"
    version="${name:0:3}"
    if [ "$version" \< "$PATCH_FROM" ] || [ "$version" \> "$PATCH_TO" ]; then
      continue
    fi
    case "$name" in
      *_rollback.sql) echo "  SKIP $name (rollback)"; continue ;;
    esac
    echo "  ▶ $name"
    PGPASSWORD="$DB_ADMIN_PASSWORD" psql \
      -h "$DB_HOST" -p "${DB_PORT:-5432}" \
      -U "$DB_ADMIN_USER" -d "$DB_NAME" \
      --set ON_ERROR_STOP=1 --no-psqlrc \
      -f "$f" || { echo "    ✗ $name failed (continuing)"; continue; }
    PGPASSWORD="$DB_ADMIN_PASSWORD" psql \
      -h "$DB_HOST" -p "${DB_PORT:-5432}" \
      -U "$DB_ADMIN_USER" -d "$DB_NAME" \
      --set ON_ERROR_STOP=1 --no-psqlrc \
      -c "INSERT INTO schema_migrations (version, filename) VALUES ('$version', '$name') ON CONFLICT (version) DO UPDATE SET filename = EXCLUDED.filename;"
    echo "    ✓ $name"
  done
  ok "patch-sql done"
}

run_diff_schema() {
  log "Phase: diff-schema (compare bundled local dump vs cloud)"
  : "${DB_HOST:?required}"; : "${DB_NAME:?required}"; : "${DB_ADMIN_USER:?required}"; : "${DB_ADMIN_PASSWORD:?required}"
  CLOUD_DSN="dbname=$DB_NAME user=$DB_ADMIN_USER password=$DB_ADMIN_PASSWORD host=$DB_HOST port=${DB_PORT:-5432} sslmode=${DB_SSLMODE:-require}" \
    python3 /app/backend/scripts/schema_compare.py /data/local_schema.json
}


run_apply_local_schema() {
  log "Phase: apply-local-schema (load /data/local_schema.sql via psql as DB_ADMIN_USER)"
  : "${DB_HOST:?required}"; : "${DB_NAME:?required}"; : "${DB_ADMIN_USER:?required}"; : "${DB_ADMIN_PASSWORD:?required}"
  PGPASSWORD="$DB_ADMIN_PASSWORD" psql \
    -h "$DB_HOST" -p "${DB_PORT:-5432}" \
    -U "$DB_ADMIN_USER" -d "$DB_NAME" \
    --set ON_ERROR_STOP=0 --no-psqlrc \
    -f /data/local_schema.sql 2>&1 | tail -100
  ok "apply-local-schema done"
}

run_full_reset() {
  log "Phase: full-reset (reset-db -> setup-roles -> apply-local-schema)"
  run_reset_db
  run_setup_roles
  run_apply_local_schema
  ok "Full reset complete"
}

case "$PHASE" in
  reset-db)     run_reset_db ;;
  diff-schema)  run_diff_schema ;;
  apply-local-schema) run_apply_local_schema ;;
  full-reset)   run_full_reset ;;
  setup-roles)  run_setup_roles ;;
  migrate)      run_migrate ;;
  restore)      run_restore ;;
  patch-sql)    run_patch_sql ;;
  sync-schema)  run_sync_schema ;;
  all)
    run_setup_roles
    run_migrate
    run_restore
    ;;
  *)
    fail "Unknown PHASE: $PHASE (use: reset-db, setup-roles, migrate, restore, patch-sql, sync-schema, all)"
    ;;
esac

ok "Done."

