#!/bin/bash
# ============================================================================
# AuditGraph Backup Restoration Test
# Phase 6 Task 0c: Verify backup + restore pipeline works end-to-end
#
# This script:
#   1. Creates a backup of the current database
#   2. Creates a temporary test database
#   3. Restores the backup to the test database
#   4. Verifies row counts match
#   5. Cleans up the test database
#   6. Reports RTO/RPO metrics
#
# Usage: ./scripts/test_backup_restore.sh
# ============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
BACKUP_DIR="./backups/restore_test"
TEST_DB="auditgraph_restore_test"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-auditgraph}"
DB_USER="${DB_ADMIN_USER:-${DB_USER:-auditgraph_admin}}"
DB_PASSWORD="${DB_ADMIN_PASSWORD:-${DB_PASSWORD:-}}"

export PGPASSWORD="${DB_PASSWORD}"

mkdir -p "${BACKUP_DIR}"

echo "================================================================"
echo "  AuditGraph Backup Restoration Test"
echo "  Timestamp: ${TIMESTAMP}"
echo "================================================================"
echo ""

# ── Step 1: Get source row counts ─────────────────────────────────────────────
echo "[1/6] Counting rows in source database..."
SOURCE_COUNTS=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A -c "
SELECT json_object_agg(table_name, row_count) FROM (
    SELECT schemaname || '.' || relname AS table_name, n_live_tup AS row_count
    FROM pg_stat_user_tables
    WHERE schemaname = 'public'
    ORDER BY relname
) t;
" 2>/dev/null)
echo "  Source counts captured"

# ── Step 2: Create backup ─────────────────────────────────────────────────────
echo "[2/6] Creating backup..."
BACKUP_START=$(date +%s)

pg_dump \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    --no-owner \
    --no-privileges \
    --clean \
    --if-exists \
    2>"${BACKUP_DIR}/backup_${TIMESTAMP}.log" \
    | gzip > "${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gz"

BACKUP_END=$(date +%s)
BACKUP_DURATION=$((BACKUP_END - BACKUP_START))
BACKUP_SIZE=$(du -sh "${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gz" | cut -f1)
echo "  Backup created: ${BACKUP_SIZE} in ${BACKUP_DURATION}s"

# ── Step 3: Create test database ──────────────────────────────────────────────
echo "[3/6] Creating test database '${TEST_DB}'..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c \
    "DROP DATABASE IF EXISTS ${TEST_DB};" 2>/dev/null
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c \
    "CREATE DATABASE ${TEST_DB};" 2>/dev/null
echo "  Test database created"

# ── Step 4: Restore backup ───────────────────────────────────────────────────
echo "[4/6] Restoring backup to '${TEST_DB}'..."
RESTORE_START=$(date +%s)

gunzip -c "${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gz" | \
    psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TEST_DB}" \
    2>"${BACKUP_DIR}/restore_${TIMESTAMP}.log" 1>/dev/null

RESTORE_END=$(date +%s)
RESTORE_DURATION=$((RESTORE_END - RESTORE_START))
echo "  Restore completed in ${RESTORE_DURATION}s"

# ── Step 5: Verify row counts ────────────────────────────────────────────────
echo "[5/6] Verifying restored data..."
RESTORE_COUNTS=$(psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${TEST_DB}" -t -A -c "
SELECT json_object_agg(table_name, row_count) FROM (
    SELECT schemaname || '.' || relname AS table_name, n_live_tup AS row_count
    FROM pg_stat_user_tables
    WHERE schemaname = 'public'
    ORDER BY relname
) t;
" 2>/dev/null)

# Compare key tables
echo "  Row count comparison:"
for table in tenants users identities discovery_runs role_assignments settings \
             activity_log drift_reports cloud_subscriptions invoices; do
    SRC=$(echo "${SOURCE_COUNTS}" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read() or '{}')
print(d.get('public.${table}', 'N/A'))
" 2>/dev/null || echo "N/A")
    DST=$(echo "${RESTORE_COUNTS}" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read() or '{}')
print(d.get('public.${table}', 'N/A'))
" 2>/dev/null || echo "N/A")
    MATCH=""
    if [ "${SRC}" = "${DST}" ]; then
        MATCH="MATCH"
    else
        MATCH="MISMATCH"
    fi
    printf "    %-25s source=%-8s restored=%-8s %s\n" "${table}" "${SRC}" "${DST}" "${MATCH}"
done

# ── Step 6: Cleanup ──────────────────────────────────────────────────────────
echo "[6/6] Cleaning up test database..."
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c \
    "DROP DATABASE IF EXISTS ${TEST_DB};" 2>/dev/null
echo "  Test database dropped"

# ── Summary ──────────────────────────────────────────────────────────────────
TOTAL_DURATION=$((RESTORE_END - BACKUP_START))
echo ""
echo "================================================================"
echo "  BACKUP RESTORATION TEST RESULTS"
echo "================================================================"
echo ""
echo "  Backup size:      ${BACKUP_SIZE}"
echo "  Backup duration:  ${BACKUP_DURATION}s (RPO indicator)"
echo "  Restore duration: ${RESTORE_DURATION}s (RTO indicator)"
echo "  Total duration:   ${TOTAL_DURATION}s"
echo ""
echo "  RPO: Last backup point (scheduled daily at 03:00 UTC)"
echo "       Maximum data loss: ~24 hours"
echo "  RTO: ${RESTORE_DURATION}s restore time + deployment (~5 min)"
echo "       Estimated recovery: < 10 minutes"
echo ""
echo "  Backup file: ${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gz"
echo "  Backup log:  ${BACKUP_DIR}/backup_${TIMESTAMP}.log"
echo "  Restore log: ${BACKUP_DIR}/restore_${TIMESTAMP}.log"
echo "================================================================"
