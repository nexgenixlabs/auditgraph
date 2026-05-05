-- Migration 103: Optimization recommendations with review workflow
--
-- Persists privilege optimization candidates with review state tracking.
-- Each recommendation is keyed by (org, identity, role, type, scope, classification)
-- to enable upsert across discovery runs while preserving review decisions.

CREATE TABLE IF NOT EXISTS optimization_recommendations (
    id BIGSERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    identity_id TEXT NOT NULL,
    identity_db_id BIGINT,
    display_name TEXT,
    identity_category TEXT,
    role_name TEXT NOT NULL,
    role_type TEXT NOT NULL DEFAULT 'azure',
    scope TEXT DEFAULT '/',
    scope_type TEXT,
    -- Optimization classification
    classification TEXT NOT NULL,  -- candidate_remove, candidate_review, insufficient_evidence, potential_scope_narrowing
    reason TEXT,
    advisory TEXT,
    evidence_summary JSONB DEFAULT '{}'::jsonb,
    -- Review workflow
    review_status TEXT NOT NULL DEFAULT 'open',  -- open, accepted, dismissed, deferred
    reviewer TEXT,
    reviewed_at TIMESTAMPTZ,
    review_note TEXT,
    -- Context
    discovery_run_id BIGINT,
    observation_window_days INTEGER DEFAULT 90,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Prevent duplicate recommendations per org/identity/role/classification
    UNIQUE(organization_id, identity_id, role_name, role_type, scope, classification)
);

CREATE INDEX IF NOT EXISTS idx_opt_rec_org_status
ON optimization_recommendations(organization_id, review_status);

CREATE INDEX IF NOT EXISTS idx_opt_rec_identity
ON optimization_recommendations(identity_id);
