-- Migration 105: Privilege drift events table
--
-- Stores classified privilege/access changes between discovery runs.
-- Each row = one deterministic drift event derived from snapshot comparison.
-- Queryable per-identity and per-org for summary aggregation.

CREATE TABLE IF NOT EXISTS privilege_drift_events (
    id BIGSERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    identity_id TEXT NOT NULL,
    identity_db_id BIGINT,
    display_name TEXT,
    identity_category TEXT,
    -- Drift classification
    drift_type TEXT NOT NULL,  -- privilege_added, privilege_removed, scope_expanded, scope_reduced, risk_increased, risk_reduced
    role_name TEXT,
    role_type TEXT NOT NULL DEFAULT 'azure',  -- azure, entra
    scope TEXT,
    prior_scope TEXT,          -- for scope_expanded / scope_reduced
    prior_risk_level TEXT,     -- for risk_increased / risk_reduced
    current_risk_level TEXT,
    prior_risk_score INTEGER,
    current_risk_score INTEGER,
    is_privileged BOOLEAN DEFAULT FALSE,
    details JSONB DEFAULT '{}'::jsonb,
    -- Run references
    discovery_run_id BIGINT NOT NULL,
    previous_run_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_priv_drift_org_run
ON privilege_drift_events(organization_id, discovery_run_id);

CREATE INDEX IF NOT EXISTS idx_priv_drift_identity
ON privilege_drift_events(identity_id);

CREATE INDEX IF NOT EXISTS idx_priv_drift_type
ON privilege_drift_events(organization_id, drift_type);
