#!/bin/bash
# ============================================================================
# AuditGraph Database Backup Script
# Phase 5: Backup & Disaster Recovery
#
# Usage:
#   ./scripts/backup.sh                   # Full backup to ./backups/
#   ./scripts/backup.sh /path/to/output   # Full backup to custom dir
#   BACKUP_S3_BUCKET=my-bucket ./scripts/backup.sh  # Upload to S3 after
#
# Requires: pg_dump, gzip, (optional: aws cli for S3 upload)
# ============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="auditgraph_${TIMESTAMP}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Database connection (reads from .env or environment)
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-auditgraph}"
DB_USER="${DB_ADMIN_USER:-${DB_USER:-auditgraph_admin}}"
DB_PASSWORD="${DB_ADMIN_PASSWORD:-${DB_PASSWORD:-}}"

export PGPASSWORD="${DB_PASSWORD}"

# ── Create backup directory ───────────────────────────────────────────────────
mkdir -p "${BACKUP_DIR}"

echo "=== AuditGraph Database Backup ==="
echo "Timestamp:  ${TIMESTAMP}"
echo "Host:       ${DB_HOST}:${DB_PORT}"
echo "Database:   ${DB_NAME}"
echo "Output:     ${BACKUP_DIR}/${BACKUP_NAME}.sql.gz"
echo ""

# ── Full database dump (custom format for parallel restore) ───────────────────
echo "[1/4] Running pg_dump..."
pg_dump \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    --no-owner \
    --no-privileges \
    --clean \
    --if-exists \
    --verbose \
    2>"${BACKUP_DIR}/${BACKUP_NAME}.log" \
    | gzip > "${BACKUP_DIR}/${BACKUP_NAME}.sql.gz"

BACKUP_SIZE=$(du -sh "${BACKUP_DIR}/${BACKUP_NAME}.sql.gz" | cut -f1)
echo "  Backup size: ${BACKUP_SIZE}"

# ── Schema-only backup (for quick reference) ──────────────────────────────────
echo "[2/4] Schema-only backup..."
pg_dump \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    --schema-only \
    --no-owner \
    --no-privileges \
    | gzip > "${BACKUP_DIR}/${BACKUP_NAME}_schema.sql.gz"

# ── Verify backup integrity ──────────────────────────────────────────────────
echo "[3/4] Verifying backup integrity..."
TABLE_COUNT=$(gunzip -c "${BACKUP_DIR}/${BACKUP_NAME}.sql.gz" | grep -c "^CREATE TABLE" || true)
echo "  Tables in backup: ${TABLE_COUNT}"

if [ "${TABLE_COUNT}" -lt 10 ]; then
    echo "  WARNING: Expected 50+ tables, found ${TABLE_COUNT}. Backup may be incomplete."
fi

# ── Upload to S3 (if configured) ─────────────────────────────────────────────
if [ -n "${BACKUP_S3_BUCKET:-}" ]; then
    echo "[4/4] Uploading to S3..."
    aws s3 cp "${BACKUP_DIR}/${BACKUP_NAME}.sql.gz" \
        "s3://${BACKUP_S3_BUCKET}/backups/${BACKUP_NAME}.sql.gz" \
        --storage-class STANDARD_IA
    aws s3 cp "${BACKUP_DIR}/${BACKUP_NAME}_schema.sql.gz" \
        "s3://${BACKUP_S3_BUCKET}/backups/${BACKUP_NAME}_schema.sql.gz" \
        --storage-class STANDARD_IA
    echo "  Uploaded to s3://${BACKUP_S3_BUCKET}/backups/"
else
    echo "[4/4] Skipping S3 upload (BACKUP_S3_BUCKET not set)"
fi

# ── Clean up old backups ─────────────────────────────────────────────────────
echo ""
echo "Cleaning backups older than ${RETENTION_DAYS} days..."
DELETED=$(find "${BACKUP_DIR}" -name "auditgraph_*.sql.gz" -mtime +${RETENTION_DAYS} -delete -print | wc -l)
find "${BACKUP_DIR}" -name "auditgraph_*.log" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
echo "  Removed ${DELETED} old backup files"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Backup Complete ==="
echo "Full backup:   ${BACKUP_DIR}/${BACKUP_NAME}.sql.gz (${BACKUP_SIZE})"
echo "Schema backup: ${BACKUP_DIR}/${BACKUP_NAME}_schema.sql.gz"
echo "Log:           ${BACKUP_DIR}/${BACKUP_NAME}.log"
echo ""
echo "To restore:"
echo "  gunzip -c ${BACKUP_DIR}/${BACKUP_NAME}.sql.gz | psql -h \$DB_HOST -U \$DB_USER -d ${DB_NAME}"
