-- AG-181 (Tier 2C): AI Lifecycle + Drift schema
--
-- Per-AI-agent J/M/L event log. Reuses drift_events_ai.py event types.
-- Honors migration 100 regression rule: explicit PK + sequence.

BEGIN;

CREATE TABLE IF NOT EXISTS ai_agent_lifecycle_events (
    id                  BIGSERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL,
    discovery_run_id    BIGINT,
    prev_run_id         BIGINT,
    identity_db_id      BIGINT NOT NULL,
    identity_id         TEXT NOT NULL,
    event_type          TEXT NOT NULL,                 -- model_changed | ai_permissions_escalated | ...
    severity            TEXT NOT NULL DEFAULT 'medium',-- critical / high / medium / low
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    before_snapshot     JSONB,
    after_snapshot      JSONB,
    description         TEXT,
    mitre_techniques    JSONB,                         -- list of T... IDs tagged at event-build time
    resolved            BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at         TIMESTAMPTZ,
    resolved_by         TEXT,                          -- user_id / system
    UNIQUE (organization_id, identity_db_id, discovery_run_id, event_type)
);

CREATE INDEX IF NOT EXISTS idx_aile_org_run   ON ai_agent_lifecycle_events(organization_id, discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_aile_identity  ON ai_agent_lifecycle_events(identity_db_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_aile_severity  ON ai_agent_lifecycle_events(organization_id, severity, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_aile_unres     ON ai_agent_lifecycle_events(organization_id, resolved, occurred_at DESC)
    WHERE resolved = FALSE;

-- RLS policies (Phase 87 strict)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='auditgraph_app') THEN
        ALTER TABLE ai_agent_lifecycle_events ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS tenant_strict_sel ON ai_agent_lifecycle_events;
        DROP POLICY IF EXISTS tenant_strict_ins ON ai_agent_lifecycle_events;
        DROP POLICY IF EXISTS tenant_strict_upd ON ai_agent_lifecycle_events;
        DROP POLICY IF EXISTS tenant_strict_del ON ai_agent_lifecycle_events;
        CREATE POLICY tenant_strict_sel ON ai_agent_lifecycle_events FOR SELECT
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_ins ON ai_agent_lifecycle_events FOR INSERT
            WITH CHECK (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_upd ON ai_agent_lifecycle_events FOR UPDATE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_del ON ai_agent_lifecycle_events FOR DELETE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        GRANT SELECT, INSERT, UPDATE, DELETE ON ai_agent_lifecycle_events TO auditgraph_app;
    END IF;
END $$;

COMMIT;
