-- Migration 110: Pipeline Health Metrics
--
-- Tracks per-stage ingestion/persistence metrics for every discovery run.
-- Enables detection of silent pipeline failures (e.g., ON CONFLICT errors,
-- transaction poisoning) by comparing fetched vs persisted counts.
--
-- Health status: healthy / degraded / failed / skipped
-- Degraded: failure_rate > 5% OR persisted << fetched (>20% drop)
-- Failed: stage threw unrecoverable exception OR failure_rate > 50%

CREATE TABLE IF NOT EXISTS pipeline_stage_metrics (
    id BIGSERIAL PRIMARY KEY,
    discovery_run_id BIGINT NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL,
    stage_name TEXT NOT NULL,           -- e.g. 'identity_discovery', 'entra_role_collection'
    stage_order INTEGER NOT NULL DEFAULT 0,

    -- Counters
    records_fetched INTEGER NOT NULL DEFAULT 0,
    records_matched INTEGER NOT NULL DEFAULT 0,
    records_persisted INTEGER NOT NULL DEFAULT 0,
    records_failed INTEGER NOT NULL DEFAULT 0,
    records_skipped INTEGER NOT NULL DEFAULT 0,

    -- Computed
    failure_rate NUMERIC(5,2) DEFAULT 0,  -- (failed / fetched) * 100

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER DEFAULT 0,

    -- Health
    health_status TEXT NOT NULL DEFAULT 'healthy',  -- healthy / degraded / failed / skipped
    degradation_reason TEXT,                        -- human-readable explanation
    error_message TEXT,                             -- exception text (truncated)

    -- Prior run comparison
    prior_run_persisted INTEGER,                    -- previous run same-stage count
    delta_vs_prior NUMERIC(5,2),                    -- % change vs prior run

    -- Metadata
    extra JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT uq_pipeline_stage_run UNIQUE (discovery_run_id, stage_name)
);

-- Indexes for health dashboard queries
CREATE INDEX IF NOT EXISTS idx_psm_org_run
ON pipeline_stage_metrics(organization_id, discovery_run_id DESC);

CREATE INDEX IF NOT EXISTS idx_psm_health_status
ON pipeline_stage_metrics(organization_id, health_status)
WHERE health_status != 'healthy';

-- Attach pipeline_health_summary JSONB to discovery_runs
ALTER TABLE discovery_runs
    ADD COLUMN IF NOT EXISTS pipeline_health_summary JSONB DEFAULT NULL;

-- Comment
COMMENT ON TABLE pipeline_stage_metrics IS
    'Per-stage ingestion metrics for pipeline health monitoring. Detects silent failures.';
