-- Phase 14: Drift Detection & Change Tracking
-- Persists drift comparison results between consecutive discovery runs

CREATE TABLE IF NOT EXISTS drift_reports (
    id SERIAL PRIMARY KEY,
    current_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    previous_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    new_identities_count INTEGER NOT NULL DEFAULT 0,
    removed_identities_count INTEGER NOT NULL DEFAULT 0,
    permission_changes_count INTEGER NOT NULL DEFAULT 0,
    risk_changes_count INTEGER NOT NULL DEFAULT 0,
    credential_changes_count INTEGER NOT NULL DEFAULT 0,
    total_changes INTEGER NOT NULL DEFAULT 0,
    changes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(current_run_id, previous_run_id)
);

CREATE INDEX IF NOT EXISTS idx_drift_reports_current_run ON drift_reports(current_run_id);
CREATE INDEX IF NOT EXISTS idx_drift_reports_created_at ON drift_reports(created_at DESC);
