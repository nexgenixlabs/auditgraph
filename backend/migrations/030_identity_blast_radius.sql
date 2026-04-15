-- Migration 030: Identity Blast Radius Results
-- Phase 5: Blast Radius Engine
--
-- Stores per-identity blast radius analysis: reachable resources, sensitive assets,
-- privilege escalation paths, risk scoring, and remediation impact.
--
-- Idempotent: uses CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS blast_radius_results (
    id SERIAL PRIMARY KEY,
    result_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    identity_id INTEGER NOT NULL,
    identity_name TEXT,
    identity_type TEXT,
    discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE CASCADE,

    reachable_resource_count INTEGER NOT NULL DEFAULT 0,
    reachable_subscription_count INTEGER NOT NULL DEFAULT 0,
    reachable_resource_group_count INTEGER NOT NULL DEFAULT 0,

    sensitive_resource_count INTEGER NOT NULL DEFAULT 0,
    sensitive_data_types JSONB DEFAULT '[]',

    resource_breakdown JSONB DEFAULT '{}',

    privilege_escalation_paths INTEGER NOT NULL DEFAULT 0,

    risk_domain TEXT NOT NULL DEFAULT 'identity',
    identity_exposure_level TEXT NOT NULL DEFAULT 'LOW',

    blast_radius_reduction INTEGER NOT NULL DEFAULT 0,
    remediation_confidence TEXT,

    risk_score INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(discovery_run_id, identity_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_br_org ON blast_radius_results(organization_id);
CREATE INDEX IF NOT EXISTS idx_br_identity ON blast_radius_results(identity_id);
CREATE INDEX IF NOT EXISTS idx_br_run ON blast_radius_results(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_br_risk_score ON blast_radius_results(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_br_exposure ON blast_radius_results(identity_exposure_level);
CREATE INDEX IF NOT EXISTS idx_br_created ON blast_radius_results(created_at DESC);
