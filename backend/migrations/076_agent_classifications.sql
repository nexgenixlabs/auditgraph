-- Migration 076: AI Agent Governance — agent_identity_type + agent_classifications table
-- Phase 1, Task 1-1
-- Additive only: new nullable column + new table. No existing data modified.
--
-- UP:
--   1. Add agent_identity_type column to identities (nullable, no default)
--   2. Create agent_classifications table for full classification metadata
--
-- DOWN (reverse):
--   DROP TABLE IF EXISTS agent_classifications;
--   ALTER TABLE identities DROP COLUMN IF EXISTS agent_identity_type;

-- 1. Lightweight enum column on identities
-- Values: 'human', 'service_account', 'ai_agent', 'managed_identity',
--         'workload_identity', 'unknown', 'possible_ai_agent'
-- Default: NULL (existing records unaffected until classifier runs)
ALTER TABLE identities ADD COLUMN IF NOT EXISTS agent_identity_type TEXT;

CREATE INDEX IF NOT EXISTS idx_identities_agent_identity_type
    ON identities(agent_identity_type)
    WHERE agent_identity_type IS NOT NULL;

-- 2. Full classification metadata table
CREATE TABLE IF NOT EXISTS agent_classifications (
    id              BIGSERIAL PRIMARY KEY,
    identity_db_id  BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    identity_id     TEXT NOT NULL,               -- denormalized for fast lookup
    agent_identity_type TEXT NOT NULL DEFAULT 'unknown',
    classification_confidence REAL NOT NULL DEFAULT 0.0,
    classification_reason TEXT,                   -- e.g. 'display_name_match: copilot'
    detected_platform TEXT,                       -- e.g. 'copilot_studio', 'azure_openai'
    pattern_version TEXT,                         -- version from ai_agent_patterns.json
    classified_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
    organization_id INTEGER,                      -- tenant scoping
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_db_id, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_classifications_org
    ON agent_classifications(organization_id);
CREATE INDEX IF NOT EXISTS idx_agent_classifications_type
    ON agent_classifications(agent_identity_type);
CREATE INDEX IF NOT EXISTS idx_agent_classifications_platform
    ON agent_classifications(detected_platform);
CREATE INDEX IF NOT EXISTS idx_agent_classifications_identity
    ON agent_classifications(identity_id);
CREATE INDEX IF NOT EXISTS idx_agent_classifications_run
    ON agent_classifications(discovery_run_id);
