-- Migration 039: Snapshot Jobs Table
-- Phase 3: Discovery job lifecycle tracking
-- Tracks per-connection discovery progress (queued→running→completed/failed)

-- Create snapshot_jobs table
CREATE TABLE IF NOT EXISTS snapshot_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    discovery_run_id INTEGER,
    scan_mode VARCHAR(20) NOT NULL DEFAULT 'deep',
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    stage VARCHAR(40)
        CHECK (stage IS NULL OR stage IN (
            'discovering_subscriptions', 'discovering_identities',
            'discovering_rbac', 'discovering_resources', 'finalizing'
        )),
    progress INTEGER NOT NULL DEFAULT 0
        CHECK (progress >= 0 AND progress <= 100),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- Partial index for fast concurrency guard (active jobs per connection)
CREATE INDEX IF NOT EXISTS idx_snapshot_jobs_conn_active
ON snapshot_jobs (cloud_connection_id, status)
WHERE status IN ('queued', 'running');

-- Index for listing jobs by org
CREATE INDEX IF NOT EXISTS idx_snapshot_jobs_org_status
ON snapshot_jobs (organization_id, status, created_at DESC);

-- Enable RLS
ALTER TABLE snapshot_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE snapshot_jobs FORCE ROW LEVEL SECURITY;

-- Strict RLS policies
DROP POLICY IF EXISTS sj_strict_sel ON snapshot_jobs;
DROP POLICY IF EXISTS sj_strict_ins ON snapshot_jobs;
DROP POLICY IF EXISTS sj_strict_upd ON snapshot_jobs;
DROP POLICY IF EXISTS sj_strict_del ON snapshot_jobs;

CREATE POLICY sj_strict_sel ON snapshot_jobs FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sj_strict_ins ON snapshot_jobs FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sj_strict_upd ON snapshot_jobs FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sj_strict_del ON snapshot_jobs FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

-- Grant to app user
GRANT SELECT, INSERT, UPDATE ON snapshot_jobs TO auditgraph_app;
