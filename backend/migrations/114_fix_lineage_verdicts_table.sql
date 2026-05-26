-- Migration 114: Ensure lineage_verdicts table schema is complete.
-- Moves DDL out of _ensure_lineage_verdicts_table() (same pattern as
-- migrations 112/113 for SOAR and saved_views tables).

CREATE TABLE IF NOT EXISTS lineage_verdicts (
    id BIGSERIAL PRIMARY KEY,
    discovery_run_id BIGINT NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL,
    identity_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    verdict VARCHAR(50) NOT NULL,
    confidence_score FLOAT DEFAULT 1.0,
    contributing_factors JSONB,
    previous_verdict VARCHAR(50),
    verdict_changed BOOLEAN DEFAULT FALSE,
    scored_at TIMESTAMPTZ DEFAULT NOW(),
    verdict_source VARCHAR(50) DEFAULT 'lineage_engine'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_lv_identity_run ON lineage_verdicts(identity_id, discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_lv_run_id ON lineage_verdicts(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_lv_identity_id ON lineage_verdicts(identity_id);
CREATE INDEX IF NOT EXISTS idx_lv_verdict ON lineage_verdicts(verdict);
CREATE INDEX IF NOT EXISTS idx_lv_org_id ON lineage_verdicts(organization_id);
CREATE INDEX IF NOT EXISTS idx_lv_changed ON lineage_verdicts(verdict_changed) WHERE verdict_changed = TRUE;
