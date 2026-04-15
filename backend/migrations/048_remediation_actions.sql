-- Migration 048: Remediation Actions
-- Phase 12: Automated Remediation Engine

CREATE TABLE IF NOT EXISTS auto_remediation_actions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    recommendation_id   UUID NULL,
    action_type         VARCHAR(100) NOT NULL,
    status              VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'executing', 'completed', 'failed')),
    requested_by        VARCHAR(255),
    approved_by         VARCHAR(255),
    executed_at         TIMESTAMPTZ,
    result_message      TEXT,
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ara_org ON auto_remediation_actions(organization_id);
CREATE INDEX IF NOT EXISTS idx_ara_connection ON auto_remediation_actions(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_ara_recommendation ON auto_remediation_actions(recommendation_id);
CREATE INDEX IF NOT EXISTS idx_ara_status ON auto_remediation_actions(status);
CREATE INDEX IF NOT EXISTS idx_ara_type ON auto_remediation_actions(action_type);

ALTER TABLE auto_remediation_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auto_remediation_actions FORCE ROW LEVEL SECURITY;

CREATE POLICY ara_strict_sel ON auto_remediation_actions FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ara_strict_ins ON auto_remediation_actions FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ara_strict_upd ON auto_remediation_actions FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ara_strict_del ON auto_remediation_actions FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON auto_remediation_actions TO auditgraph_app;
