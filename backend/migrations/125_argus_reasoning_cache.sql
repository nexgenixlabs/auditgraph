-- AG-186 (Argus Layer 2): Reasoning cache
--
-- Stores the synthesized narratives produced by argus_reasoner.reason_about().
-- One row per (organization, question_hash, latest_run_id) tuple — the
-- cache is invalidated naturally when a new discovery run lands because
-- question_hash is computed off of {question_type, run_id} so a fresh run
-- yields a new hash and the prior row is left in place (audit trail).
--
-- Honors migration 100 regression rule: explicit PK + sequence per table.
-- RLS-strict per Phase 87.

BEGIN;

CREATE TABLE IF NOT EXISTS argus_reasoning_cache (
    id                  BIGSERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL,
    question_hash       TEXT NOT NULL,
    question_type       TEXT NOT NULL,
    response_json       JSONB NOT NULL,
    latest_run_id       BIGINT,
    confidence          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, question_hash)
);

CREATE INDEX IF NOT EXISTS idx_argus_reasoning_cache_org_created
    ON argus_reasoning_cache(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_argus_reasoning_cache_type
    ON argus_reasoning_cache(organization_id, question_type);
CREATE INDEX IF NOT EXISTS idx_argus_reasoning_cache_run
    ON argus_reasoning_cache(organization_id, latest_run_id);

-- RLS policies (Phase 87 strict). Skip if tenancy mode not enabled.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='auditgraph_app') THEN
        ALTER TABLE argus_reasoning_cache ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS tenant_strict_sel ON argus_reasoning_cache;
        DROP POLICY IF EXISTS tenant_strict_ins ON argus_reasoning_cache;
        DROP POLICY IF EXISTS tenant_strict_upd ON argus_reasoning_cache;
        DROP POLICY IF EXISTS tenant_strict_del ON argus_reasoning_cache;
        CREATE POLICY tenant_strict_sel ON argus_reasoning_cache FOR SELECT
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_ins ON argus_reasoning_cache FOR INSERT
            WITH CHECK (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_upd ON argus_reasoning_cache FOR UPDATE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_del ON argus_reasoning_cache FOR DELETE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);

        GRANT SELECT, INSERT, UPDATE, DELETE ON argus_reasoning_cache TO auditgraph_app;
    END IF;
END $$;

COMMIT;
