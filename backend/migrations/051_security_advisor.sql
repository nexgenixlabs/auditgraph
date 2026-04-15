-- Migration 051: Security Advisor Reports
-- Phase 15: AI Security Advisor

CREATE TABLE IF NOT EXISTS security_advisor_reports (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         INTEGER NOT NULL,
    risk_score              FLOAT DEFAULT 0,
    benchmark_percentile    FLOAT DEFAULT 50,
    top_risks               JSONB DEFAULT '[]',
    recommended_actions     JSONB DEFAULT '[]',
    risk_reduction_estimate FLOAT DEFAULT 0,
    metadata                JSONB DEFAULT '{}',
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sar_org ON security_advisor_reports(organization_id);
CREATE INDEX IF NOT EXISTS idx_sar_created ON security_advisor_reports(created_at DESC);

ALTER TABLE security_advisor_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_advisor_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY sar_strict_sel ON security_advisor_reports FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sar_strict_ins ON security_advisor_reports FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sar_strict_upd ON security_advisor_reports FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sar_strict_del ON security_advisor_reports FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON security_advisor_reports TO auditgraph_app;
