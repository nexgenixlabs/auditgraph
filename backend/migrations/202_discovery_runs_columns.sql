-- Backfill discovery_runs columns that local sandbox accumulated but cloud DB
-- never received. Code in azure_discovery.py and handlers.py references all 4.

ALTER TABLE discovery_runs
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

ALTER TABLE discovery_runs
    ADD COLUMN IF NOT EXISTS pipeline_health_summary JSONB;

ALTER TABLE discovery_runs
    ADD COLUMN IF NOT EXISTS snapshot_hash VARCHAR(64);

ALTER TABLE discovery_runs
    ADD COLUMN IF NOT EXISTS snapshot_signature VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_discovery_runs_metadata ON discovery_runs USING gin (metadata);
