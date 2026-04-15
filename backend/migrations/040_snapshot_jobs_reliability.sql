-- Migration 040: Snapshot Jobs Reliability
-- Phase 4: Heartbeat, retry, metrics, and runtime safety columns

-- Retry tracking
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS max_retries INTEGER NOT NULL DEFAULT 3;

-- Heartbeat for zombie detection
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ;

-- Provenance
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS started_by VARCHAR(50);

-- Discovery metrics
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS identities_discovered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS resources_discovered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS subscriptions_discovered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS duration_seconds INTEGER;

-- Error classification
ALTER TABLE snapshot_jobs ADD COLUMN IF NOT EXISTS error_type VARCHAR(30);

-- Heartbeat index for zombie detection queries
CREATE INDEX IF NOT EXISTS idx_snapshot_jobs_heartbeat
ON snapshot_jobs (last_heartbeat_at);
