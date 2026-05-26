-- Migration 107: Identity reachability table
--
-- Focused reachability metrics and risk flags per identity per run.
-- Augments blast_radius_results with privileged resource counts,
-- high-value target tracking, and deterministic risk flag computation.
-- One row per identity per discovery run.

CREATE TABLE IF NOT EXISTS identity_reachability (
    id BIGSERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    identity_id TEXT NOT NULL,
    identity_db_id BIGINT NOT NULL,
    display_name TEXT,
    identity_category TEXT,
    -- Reachability metrics
    reachable_resource_count INTEGER NOT NULL DEFAULT 0,
    reachable_privileged_resource_count INTEGER NOT NULL DEFAULT 0,
    subscriptions_reachable INTEGER NOT NULL DEFAULT 0,
    resource_groups_reachable INTEGER NOT NULL DEFAULT 0,
    high_value_targets_reachable INTEGER NOT NULL DEFAULT 0,
    -- Privileged role context
    has_privileged_roles BOOLEAN DEFAULT FALSE,
    privileged_role_names JSONB DEFAULT '[]'::jsonb,
    highest_scope_type TEXT,          -- management_group, subscription, resource_group, resource
    -- Risk flags (deterministic)
    flag_broad_blast_radius BOOLEAN DEFAULT FALSE,
    flag_privileged_wide_reach BOOLEAN DEFAULT FALSE,
    flag_ai_excessive_blast BOOLEAN DEFAULT FALSE,
    flag_dormant_high_blast BOOLEAN DEFAULT FALSE,
    risk_flag_count INTEGER NOT NULL DEFAULT 0,
    risk_flag_details JSONB DEFAULT '[]'::jsonb,
    -- Cross-reference
    blast_radius_risk_score INTEGER DEFAULT 0,
    blast_radius_exposure_level TEXT DEFAULT 'LOW',
    agent_identity_type TEXT,
    activity_status TEXT,
    -- Run context
    discovery_run_id BIGINT NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(identity_db_id, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS idx_ir_org_run
ON identity_reachability(organization_id, discovery_run_id);

CREATE INDEX IF NOT EXISTS idx_ir_identity
ON identity_reachability(identity_db_id);

CREATE INDEX IF NOT EXISTS idx_ir_flags
ON identity_reachability(organization_id, risk_flag_count DESC)
WHERE risk_flag_count > 0;

CREATE INDEX IF NOT EXISTS idx_ir_exposure
ON identity_reachability(organization_id, blast_radius_exposure_level);
