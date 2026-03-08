-- Migration 038: Enforce cloud_connection_id NOT NULL on discovery_runs
-- Phase 2 of Discovery Isolation & Multi-Tenant Enforcement
--
-- Problem: discovery_runs.cloud_connection_id allows NULL, which means
-- discovery runs can exist without connection context, breaking tenant isolation.
--
-- Strategy:
-- 1. Backfill NULL rows from matching org connection
-- 2. Archive orphaned runs (no matching connection)
-- 3. Backfill remaining NULLs with 0 for NOT NULL constraint
-- 4. Enforce NOT NULL
-- 5. Add composite index for _latest_run_ids query pattern

-- Step 1: Backfill NULL cloud_connection_id from matching org connection
UPDATE discovery_runs dr
SET cloud_connection_id = (
    SELECT c.id FROM cloud_connections c
    WHERE c.organization_id = dr.organization_id
    ORDER BY c.created_at ASC LIMIT 1
)
WHERE dr.cloud_connection_id IS NULL AND dr.organization_id IS NOT NULL;

-- Step 2: Archive orphaned runs (no matching connection)
UPDATE discovery_runs SET status = 'archived'
WHERE cloud_connection_id IS NULL;

-- Step 3: Backfill remaining NULLs with 0 for NOT NULL constraint
UPDATE discovery_runs SET cloud_connection_id = 0
WHERE cloud_connection_id IS NULL;

-- Step 4: Enforce NOT NULL
ALTER TABLE discovery_runs ALTER COLUMN cloud_connection_id SET NOT NULL;

-- Step 5: Composite index for _latest_run_ids query pattern
CREATE INDEX IF NOT EXISTS idx_discovery_runs_conn_status
ON discovery_runs(cloud_connection_id, status, id DESC);
