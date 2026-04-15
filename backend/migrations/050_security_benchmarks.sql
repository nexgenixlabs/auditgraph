-- Migration 050: Security Benchmarks
-- Phase 14: Cross-Tenant Security Benchmarking

-- Aggregated benchmarks (NO RLS — system-wide anonymised data)
CREATE TABLE IF NOT EXISTS security_benchmarks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name     VARCHAR(100) NOT NULL,
    metric_value    FLOAT NOT NULL,
    sample_size     INTEGER DEFAULT 0,
    percentile_25   FLOAT,
    percentile_50   FLOAT,
    percentile_75   FLOAT,
    computed_at     TIMESTAMPTZ DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sb_metric ON security_benchmarks(metric_name);

GRANT SELECT ON security_benchmarks TO auditgraph_app;

-- Per-tenant posture metrics (org-scoped with RLS)
CREATE TABLE IF NOT EXISTS tenant_posture_metrics (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    risk_score          FLOAT DEFAULT 0,
    critical_findings   INTEGER DEFAULT 0,
    high_findings       INTEGER DEFAULT 0,
    blast_radius_avg    FLOAT DEFAULT 0,
    nhi_exposure        INTEGER DEFAULT 0,
    escalation_paths    INTEGER DEFAULT 0,
    identity_count      INTEGER DEFAULT 0,
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tpm_org ON tenant_posture_metrics(organization_id);
CREATE INDEX IF NOT EXISTS idx_tpm_created ON tenant_posture_metrics(created_at DESC);

ALTER TABLE tenant_posture_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_posture_metrics FORCE ROW LEVEL SECURITY;

CREATE POLICY tpm_strict_sel ON tenant_posture_metrics FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY tpm_strict_ins ON tenant_posture_metrics FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY tpm_strict_upd ON tenant_posture_metrics FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY tpm_strict_del ON tenant_posture_metrics FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_posture_metrics TO auditgraph_app;
