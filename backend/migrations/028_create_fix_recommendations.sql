-- Migration 028: Create fix_recommendations table
-- Phase 4: Unified Fix Recommendation Engine
-- Correlates security_findings + attack_paths into structured, deduplicated fix recommendations.

CREATE TABLE IF NOT EXISTS fix_recommendations (
    id SERIAL PRIMARY KEY,
    recommendation_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    entity_type VARCHAR(30) NOT NULL,
    entity_name TEXT,
    fix_type VARCHAR(60) NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    fix_category VARCHAR(40) NOT NULL,
    priority_score INTEGER NOT NULL DEFAULT 0,
    effort VARCHAR(10) NOT NULL DEFAULT 'medium',
    steps JSONB NOT NULL DEFAULT '[]',
    azure_cli_commands TEXT,
    compliance_refs JSONB DEFAULT '{}',
    linked_finding_types JSONB DEFAULT '[]',
    linked_path_types JSONB DEFAULT '[]',
    linked_finding_count INTEGER NOT NULL DEFAULT 0,
    linked_path_count INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    status_changed_by VARCHAR(100),
    status_changed_at TIMESTAMPTZ,
    assigned_to VARCHAR(100),
    recommendation_fingerprint TEXT,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(discovery_run_id, entity_id, fix_type)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_fr_run ON fix_recommendations(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_fr_org ON fix_recommendations(organization_id);
CREATE INDEX IF NOT EXISTS idx_fr_entity ON fix_recommendations(entity_id);
CREATE INDEX IF NOT EXISTS idx_fr_priority ON fix_recommendations(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_fr_status ON fix_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_fr_type ON fix_recommendations(fix_type);
CREATE INDEX IF NOT EXISTS idx_fr_category ON fix_recommendations(fix_category);
CREATE INDEX IF NOT EXISTS idx_fr_created ON fix_recommendations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fr_fingerprint ON fix_recommendations(recommendation_fingerprint);

-- Unique partial index for fingerprint-based UPSERT (one row per fingerprint per org)
CREATE UNIQUE INDEX IF NOT EXISTS idx_fr_org_fingerprint
ON fix_recommendations(organization_id, recommendation_fingerprint)
WHERE recommendation_fingerprint IS NOT NULL;
