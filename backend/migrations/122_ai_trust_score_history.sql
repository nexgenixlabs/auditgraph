-- AG-179 (Tier 1B): AI Trust Score history + Board Scorecard snapshots
--
-- Persisted daily snapshots so the board pack shows trend, not just point-in-time.
-- Honors migration 100 regression rule: explicit PK + sequence per table.
-- RLS-strict per Phase 87.

BEGIN;

CREATE TABLE IF NOT EXISTS ai_trust_score_history (
    id                 BIGSERIAL PRIMARY KEY,
    organization_id    INTEGER NOT NULL,
    identity_db_id     BIGINT NOT NULL,
    identity_id        TEXT NOT NULL,
    snapshot_date      DATE NOT NULL,
    trust_score        INTEGER NOT NULL CHECK (trust_score BETWEEN 0 AND 100),
    ownership_grade    TEXT NOT NULL,
    secrets_grade      TEXT NOT NULL,
    egress_grade       TEXT NOT NULL,
    telemetry_grade    TEXT NOT NULL,
    oversight_grade    TEXT NOT NULL,
    policy_violations  INTEGER NOT NULL DEFAULT 0,
    exceptions_active  INTEGER NOT NULL DEFAULT 0,
    raw_evidence       JSONB,
    computed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, identity_db_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_ai_tsh_org_date
    ON ai_trust_score_history(organization_id, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_ai_tsh_identity
    ON ai_trust_score_history(identity_db_id, snapshot_date DESC);

CREATE TABLE IF NOT EXISTS ai_board_scorecard_snapshots (
    id                       BIGSERIAL PRIMARY KEY,
    organization_id          INTEGER NOT NULL,
    snapshot_date            DATE NOT NULL,
    total_agents             INTEGER NOT NULL DEFAULT 0,
    with_owner_pct           NUMERIC(5,2) NOT NULL DEFAULT 0,
    with_telemetry_pct       NUMERIC(5,2) NOT NULL DEFAULT 0,
    private_network_pct      NUMERIC(5,2) NOT NULL DEFAULT 0,
    least_privilege_pct      NUMERIC(5,2) NOT NULL DEFAULT 0,
    policy_compliant_pct     NUMERIC(5,2) NOT NULL DEFAULT 0,
    distribution_strong      INTEGER NOT NULL DEFAULT 0,
    distribution_good        INTEGER NOT NULL DEFAULT 0,
    distribution_elevated    INTEGER NOT NULL DEFAULT 0,
    distribution_critical    INTEGER NOT NULL DEFAULT 0,
    top_10_worst_json        JSONB,
    exceptions_pending       INTEGER NOT NULL DEFAULT 0,
    computed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_ai_bss_org_date
    ON ai_board_scorecard_snapshots(organization_id, snapshot_date DESC);

-- RLS policies (Phase 87 strict). Skip if tenancy mode not enabled.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='auditgraph_app') THEN
        ALTER TABLE ai_trust_score_history ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ai_board_scorecard_snapshots ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS tenant_strict_sel ON ai_trust_score_history;
        DROP POLICY IF EXISTS tenant_strict_ins ON ai_trust_score_history;
        DROP POLICY IF EXISTS tenant_strict_upd ON ai_trust_score_history;
        DROP POLICY IF EXISTS tenant_strict_del ON ai_trust_score_history;
        CREATE POLICY tenant_strict_sel ON ai_trust_score_history FOR SELECT
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_ins ON ai_trust_score_history FOR INSERT
            WITH CHECK (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_upd ON ai_trust_score_history FOR UPDATE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_del ON ai_trust_score_history FOR DELETE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);

        DROP POLICY IF EXISTS tenant_strict_sel ON ai_board_scorecard_snapshots;
        DROP POLICY IF EXISTS tenant_strict_ins ON ai_board_scorecard_snapshots;
        DROP POLICY IF EXISTS tenant_strict_upd ON ai_board_scorecard_snapshots;
        DROP POLICY IF EXISTS tenant_strict_del ON ai_board_scorecard_snapshots;
        CREATE POLICY tenant_strict_sel ON ai_board_scorecard_snapshots FOR SELECT
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_ins ON ai_board_scorecard_snapshots FOR INSERT
            WITH CHECK (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_upd ON ai_board_scorecard_snapshots FOR UPDATE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);
        CREATE POLICY tenant_strict_del ON ai_board_scorecard_snapshots FOR DELETE
            USING (organization_id = current_setting('app.current_tenant_id', true)::integer);

        GRANT SELECT, INSERT, UPDATE, DELETE ON ai_trust_score_history TO auditgraph_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ai_board_scorecard_snapshots TO auditgraph_app;
    END IF;
END $$;

COMMIT;
