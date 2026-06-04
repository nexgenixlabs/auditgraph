-- AG-T3.2: AI Supply Chain dependency graph.
--
-- Two tables:
--   ai_supply_chain_components — nodes (model | plugin | vector_db |
--                                external_api | tool)
--   ai_supply_chain_links      — directed edges (agent → component or
--                                component → component)
--
-- Risk flags per node (jsonb array): 'cve' | 'unverified_vendor' |
--   'public_endpoint' | 'no_pinned_version' | 'mutable_dependency' |
--   'unapproved' | 'fine_tuned' | 'community_plugin'
--
-- Composed risk_score per node 0-100 from the flags (engine computes;
-- column persists last value for fast read).

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS ai_supply_chain_components (
    id                      BIGSERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL,
    discovery_run_id        BIGINT,

    component_kind          TEXT NOT NULL
        CHECK (component_kind IN ('model','plugin','vector_db','external_api','tool')),
    component_name          TEXT NOT NULL,
    vendor                  TEXT,
    version                 TEXT,
    is_managed_by_customer  BOOLEAN NOT NULL DEFAULT FALSE,

    risk_flags              JSONB NOT NULL DEFAULT '[]'::jsonb,
    risk_score              INTEGER NOT NULL DEFAULT 0,

    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ai_supply_chain_components_unique
        UNIQUE (organization_id, component_kind, component_name, vendor, version)
);

CREATE INDEX IF NOT EXISTS idx_ai_sc_components_org_kind
    ON ai_supply_chain_components (organization_id, component_kind);

CREATE TABLE IF NOT EXISTS ai_supply_chain_links (
    id                      BIGSERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL,

    -- Either source_identity_db_id (agent → component) OR
    -- source_component_id (component → component) is set, not both.
    source_identity_db_id   BIGINT,
    source_component_id     BIGINT REFERENCES ai_supply_chain_components(id) ON DELETE CASCADE,
    target_component_id     BIGINT NOT NULL REFERENCES ai_supply_chain_components(id) ON DELETE CASCADE,

    relationship            TEXT NOT NULL
        CHECK (relationship IN ('uses','depends_on','calls','reads_from','writes_to','indexes')),
    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ai_sc_links_exactly_one_source
        CHECK ((source_identity_db_id IS NOT NULL)::int +
               (source_component_id   IS NOT NULL)::int = 1)
);

CREATE INDEX IF NOT EXISTS idx_ai_sc_links_agent
    ON ai_supply_chain_links (organization_id, source_identity_db_id)
    WHERE source_identity_db_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_sc_links_component_src
    ON ai_supply_chain_links (organization_id, source_component_id)
    WHERE source_component_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_sc_links_target
    ON ai_supply_chain_links (organization_id, target_component_id);

-- updated_at trigger on components
CREATE OR REPLACE FUNCTION _ai_sc_components_touch()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ai_sc_components_touch ON ai_supply_chain_components;
CREATE TRIGGER trg_ai_sc_components_touch
    BEFORE UPDATE ON ai_supply_chain_components
    FOR EACH ROW EXECUTE FUNCTION _ai_sc_components_touch();

DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON ai_supply_chain_components TO auditgraph_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON ai_supply_chain_links TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE ai_supply_chain_components_id_seq TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE ai_supply_chain_links_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON ai_supply_chain_components TO auditgraph_admin';
    EXECUTE 'GRANT ALL ON ai_supply_chain_links TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;
