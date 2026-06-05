-- AG-182 (Tier 3A): AI Activity Timeline + Behavior Baseline schema
--
-- Tables for the "CrowdStrike for AI Agents" capability. Tier 3A MVP
-- ships the schema + endpoints + UI. The Azure Monitor / ARM Activity
-- Log ingester is a fast-follow (needs adaptive backoff hardening).
--
-- Honors migration 100 regression rule.

BEGIN;

-- ── Per-event activity log ────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_activity_events (
    id                BIGSERIAL PRIMARY KEY,
    organization_id   INTEGER NOT NULL,
    identity_db_id    BIGINT NOT NULL,
    identity_id       TEXT NOT NULL,
    category          TEXT NOT NULL,                  -- model_call | secret_read | data_access | permission_change | auth_event | anomaly
    occurred_at       TIMESTAMPTZ NOT NULL,
    source            TEXT NOT NULL,                  -- azure_monitor | arm_activity_log | graph_audit
    resource_id       TEXT,
    resource_type     TEXT,
    operation_name    TEXT,
    metric_value      DOUBLE PRECISION,               -- records read / tokens / bytes
    severity          TEXT DEFAULT 'info',
    raw_payload       JSONB,
    ingested_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aae_org_time     ON agent_activity_events(organization_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_aae_identity_time ON agent_activity_events(identity_db_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_aae_category     ON agent_activity_events(organization_id, category, occurred_at DESC);

-- ── 14-day rolling baseline per agent ─────────────────────────
CREATE TABLE IF NOT EXISTS agent_behavior_baselines (
    id                          BIGSERIAL PRIMARY KEY,
    organization_id             INTEGER NOT NULL,
    identity_db_id              BIGINT NOT NULL,
    identity_id                 TEXT NOT NULL,
    window_days                 INTEGER NOT NULL DEFAULT 14,
    avg_daily_model_invocations DOUBLE PRECISION,
    p95_daily_model_invocations DOUBLE PRECISION,
    avg_daily_records_read      DOUBLE PRECISION,
    p95_daily_records_read      DOUBLE PRECISION,
    avg_daily_distinct_peers    DOUBLE PRECISION,
    hourly_pattern              JSONB,                 -- 24-hour distribution histogram
    samples_count               INTEGER NOT NULL DEFAULT 0,
    is_active                   BOOLEAN NOT NULL DEFAULT FALSE,    -- true once samples_count >= window_days
    computed_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, identity_db_id)
);

CREATE INDEX IF NOT EXISTS idx_abb_org   ON agent_behavior_baselines(organization_id);

-- ── Anomalies surfaced from baseline comparison ───────────────
CREATE TABLE IF NOT EXISTS agent_behavior_anomalies (
    id              BIGSERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    identity_db_id  BIGINT NOT NULL,
    identity_id     TEXT NOT NULL,
    anomaly_type    TEXT NOT NULL,                    -- volume_spike | new_peer | new_resource | off_hours_break
    severity        TEXT NOT NULL DEFAULT 'medium',
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    baseline_value  DOUBLE PRECISION,
    observed_value  DOUBLE PRECISION,
    delta_pct       DOUBLE PRECISION,
    description     TEXT,
    related_event_ids BIGINT[],
    resolved        BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_aba_org_time  ON agent_behavior_anomalies(organization_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_aba_identity  ON agent_behavior_anomalies(identity_db_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_aba_unres     ON agent_behavior_anomalies(organization_id, resolved, severity)
    WHERE resolved = FALSE;

-- RLS policies (Phase 87 strict)
DO $$
DECLARE
    _tbl TEXT;
    _tables TEXT[] := ARRAY[
        'agent_activity_events',
        'agent_behavior_baselines',
        'agent_behavior_anomalies'
    ];
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='auditgraph_app') THEN
        FOREACH _tbl IN ARRAY _tables LOOP
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_sel ON %I', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_ins ON %I', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_upd ON %I', _tbl);
            EXECUTE format('DROP POLICY IF EXISTS tenant_strict_del ON %I', _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_sel ON %I FOR SELECT '
                'USING (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_ins ON %I FOR INSERT '
                'WITH CHECK (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_upd ON %I FOR UPDATE '
                'USING (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format(
                'CREATE POLICY tenant_strict_del ON %I FOR DELETE '
                'USING (organization_id = current_setting(''app.current_tenant_id'', true)::integer)',
                _tbl);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO auditgraph_app', _tbl);
        END LOOP;
    END IF;
END $$;

COMMIT;
