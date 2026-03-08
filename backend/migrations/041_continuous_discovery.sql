-- Migration 041: Continuous Discovery — add scheduling columns to cloud_connections
-- Phase 5: Enables per-connection auto-refresh on configurable intervals.
-- Idempotent — safe to run multiple times.

-- Add continuous discovery columns
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'cloud_connections' AND column_name = 'discovery_enabled') THEN
        ALTER TABLE cloud_connections ADD COLUMN discovery_enabled BOOLEAN NOT NULL DEFAULT false;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'cloud_connections' AND column_name = 'discovery_interval_minutes') THEN
        ALTER TABLE cloud_connections ADD COLUMN discovery_interval_minutes INTEGER NOT NULL DEFAULT 360;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'cloud_connections' AND column_name = 'last_snapshot_started_at') THEN
        ALTER TABLE cloud_connections ADD COLUMN last_snapshot_started_at TIMESTAMPTZ;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'cloud_connections' AND column_name = 'last_snapshot_completed_at') THEN
        ALTER TABLE cloud_connections ADD COLUMN last_snapshot_completed_at TIMESTAMPTZ;
    END IF;
END $$;

-- Partial index for efficient due-for-discovery lookups
CREATE INDEX IF NOT EXISTS idx_cloud_conn_discovery_enabled
ON cloud_connections (discovery_enabled, discovery_interval_minutes)
WHERE discovery_enabled = true;
