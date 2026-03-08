-- Migration 068: Identity Security Command Center
-- Phase 33: Real-time identity security posture tracking

CREATE TABLE IF NOT EXISTS identity_security_posture (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    risk_score FLOAT NOT NULL DEFAULT 0,
    incident_count INTEGER NOT NULL DEFAULT 0,
    prediction_count INTEGER NOT NULL DEFAULT 0,
    governance_violation_count INTEGER NOT NULL DEFAULT 0,
    strategy_recommendation_count INTEGER NOT NULL DEFAULT 0,
    threat_event_count INTEGER NOT NULL DEFAULT 0,
    active_identity_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_isp_org ON identity_security_posture(organization_id);
CREATE INDEX IF NOT EXISTS idx_isp_connection ON identity_security_posture(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_isp_risk ON identity_security_posture(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_isp_created ON identity_security_posture(created_at DESC);

ALTER TABLE identity_security_posture ENABLE ROW LEVEL SECURITY;

CREATE POLICY isp_strict_sel ON identity_security_posture FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY isp_strict_ins ON identity_security_posture FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY isp_strict_upd ON identity_security_posture FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY isp_strict_del ON identity_security_posture FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE ON identity_security_posture TO auditgraph_app;
