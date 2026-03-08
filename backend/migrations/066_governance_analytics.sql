-- Migration 066: Identity Governance Analytics
-- Phase 31: Governance posture metrics and trend analysis

-- Table: identity_governance_metrics (org-scoped, with RLS)
CREATE TABLE IF NOT EXISTS identity_governance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    metric_type VARCHAR(60) NOT NULL CHECK (metric_type IN (
        'privilege_drift_rate',
        'stale_credentials_ratio',
        'guest_privilege_ratio',
        'inactive_identity_ratio'
    )),
    metric_value NUMERIC(10, 4) NOT NULL DEFAULT 0,
    sample_size INTEGER NOT NULL DEFAULT 0,
    affected_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    computed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_igm_org ON identity_governance_metrics(organization_id);
CREATE INDEX IF NOT EXISTS idx_igm_connection ON identity_governance_metrics(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_igm_metric_type ON identity_governance_metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_igm_computed_at ON identity_governance_metrics(computed_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_igm_dedup
    ON identity_governance_metrics(cloud_connection_id, metric_type)
    WHERE computed_at = (SELECT MAX(computed_at) FROM identity_governance_metrics igm2
        WHERE igm2.cloud_connection_id = identity_governance_metrics.cloud_connection_id
        AND igm2.metric_type = identity_governance_metrics.metric_type);

ALTER TABLE identity_governance_metrics ENABLE ROW LEVEL SECURITY;

CREATE POLICY igm_strict_sel ON identity_governance_metrics FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igm_strict_ins ON identity_governance_metrics FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igm_strict_upd ON identity_governance_metrics FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igm_strict_del ON identity_governance_metrics FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE ON identity_governance_metrics TO auditgraph_app;


-- Table: identity_governance_trends (org-scoped, with RLS)
CREATE TABLE IF NOT EXISTS identity_governance_trends (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    metric_type VARCHAR(60) NOT NULL CHECK (metric_type IN (
        'privilege_drift_rate',
        'stale_credentials_ratio',
        'guest_privilege_ratio',
        'inactive_identity_ratio'
    )),
    previous_value NUMERIC(10, 4) NOT NULL DEFAULT 0,
    current_value NUMERIC(10, 4) NOT NULL DEFAULT 0,
    change_pct NUMERIC(10, 4) NOT NULL DEFAULT 0,
    trend_direction VARCHAR(20) NOT NULL CHECK (trend_direction IN (
        'increasing', 'stable', 'decreasing'
    )),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    computed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_igt_org ON identity_governance_trends(organization_id);
CREATE INDEX IF NOT EXISTS idx_igt_connection ON identity_governance_trends(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_igt_metric_type ON identity_governance_trends(metric_type);
CREATE INDEX IF NOT EXISTS idx_igt_computed_at ON identity_governance_trends(computed_at DESC);

ALTER TABLE identity_governance_trends ENABLE ROW LEVEL SECURITY;

CREATE POLICY igt_strict_sel ON identity_governance_trends FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igt_strict_ins ON identity_governance_trends FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igt_strict_upd ON identity_governance_trends FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igt_strict_del ON identity_governance_trends FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE ON identity_governance_trends TO auditgraph_app;
