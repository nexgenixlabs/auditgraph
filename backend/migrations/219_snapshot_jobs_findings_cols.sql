-- AG-PILOT-FIX-TRIGGER-500-PART2 (2026-06-08): missing snapshot_jobs columns
--
-- Real pilot Day 0 bug: POST /api/runs/trigger returned 500 with
--   psycopg2.errors.UndefinedColumn: column "critical_count" does not exist
--
-- Root cause: get_active_snapshot_job() in database.py SELECTs 5 columns
-- (critical_count, high_count, medium_count, low_count, live_findings)
-- that are only added lazily by azure_discovery.py:516 the FIRST time
-- discovery actually runs. Before first discovery, the columns don't
-- exist — so any "Capture Snapshot" click that hits the active-job
-- check (i.e., any click with connection_id in the body) crashes.
--
-- Fix: add these columns properly via migration so they exist from the
-- moment a tenant runs migrations. The lazy ALTER TABLE in
-- azure_discovery.py is now redundant but harmless (IF NOT EXISTS).
--
-- Idempotent: ON CONFLICT-style IF NOT EXISTS, safe to re-run.

\set ON_ERROR_STOP on

BEGIN;

ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS critical_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS high_count     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS medium_count   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS low_count      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS live_findings  JSONB DEFAULT '[]'::JSONB;

COMMIT;
