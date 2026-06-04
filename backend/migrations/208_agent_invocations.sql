-- AG-T3.1: Agent invocations graph — Agent A invokes Agent B.
--
-- This is the data model for multi-hop XGRAPH (the patent-worthy
-- agent-to-agent reachability surface). Each row is a directed edge:
-- a source agent invokes a target agent through some mechanism.
--
-- Edge sources (priority order, highest-confidence first):
--   1. 'mcp_trace'         — captured Model Context Protocol tool call
--   2. 'aoai_logs'         — Azure OpenAI request logs with tool annotations
--   3. 'bedrock_logs'      — AWS Bedrock CloudTrail
--   4. 'declared'          — customer-declared via /api/agent-invocations
--   5. 'inferred_shared_sp' — both agents authenticated as same SPN (weak)
--
-- Mechanisms (via_mechanism):
--   mcp           — MCP server call
--   http          — direct HTTP call (REST API)
--   azure_function — Azure Function trigger
--   webhook       — webhook delivery
--   event_grid    — Azure Event Grid
--   shared_secret — both agents share a credential (weak invocation, strong risk)
--   service_bus   — Azure Service Bus topic/queue
--
-- Idempotent: unique on (org, source, target, mechanism) so re-ingestion
-- bumps observed_count rather than duplicating.

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS agent_invocations (
    id                      BIGSERIAL PRIMARY KEY,
    organization_id         INTEGER NOT NULL,
    discovery_run_id        BIGINT,

    source_identity_db_id   BIGINT NOT NULL,
    source_identity_id      TEXT NOT NULL,
    target_identity_db_id   BIGINT NOT NULL,
    target_identity_id      TEXT NOT NULL,

    via_mechanism           TEXT NOT NULL
        CHECK (via_mechanism IN
            ('mcp','http','azure_function','webhook','event_grid','shared_secret','service_bus')),
    invocation_name         TEXT,   -- 'callContactDB' | 'invokeSupportBot' | tool name

    observed_count          INTEGER NOT NULL DEFAULT 1,
    first_observed_at       TIMESTAMPTZ,
    last_observed_at        TIMESTAMPTZ,

    confidence              TEXT NOT NULL DEFAULT 'observed'
        CHECK (confidence IN ('observed','inferred','declared')),
    source                  TEXT NOT NULL DEFAULT 'manual'
        CHECK (source IN ('mcp_trace','aoai_logs','bedrock_logs','declared','inferred_shared_sp','manual')),

    metadata                JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT agent_invocations_unique
        UNIQUE (organization_id, source_identity_db_id, target_identity_db_id, via_mechanism),
    CONSTRAINT agent_invocations_no_self_loop
        CHECK (source_identity_db_id <> target_identity_db_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_invocations_org_source
    ON agent_invocations (organization_id, source_identity_db_id);
CREATE INDEX IF NOT EXISTS idx_agent_invocations_org_target
    ON agent_invocations (organization_id, target_identity_db_id);
CREATE INDEX IF NOT EXISTS idx_agent_invocations_org_mechanism
    ON agent_invocations (organization_id, via_mechanism);

-- updated_at trigger
CREATE OR REPLACE FUNCTION _agent_invocations_touch()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_agent_invocations_touch ON agent_invocations;
CREATE TRIGGER trg_agent_invocations_touch
    BEFORE UPDATE ON agent_invocations
    FOR EACH ROW EXECUTE FUNCTION _agent_invocations_touch();

-- Grants
DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON agent_invocations TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE agent_invocations_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON agent_invocations TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;

\d agent_invocations
