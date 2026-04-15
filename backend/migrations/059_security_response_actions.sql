-- Migration 059: Security Response Actions
-- Phase 24: Autonomous Identity Security Operations

CREATE TABLE IF NOT EXISTS security_response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    incident_id UUID REFERENCES identity_attack_incidents(id),
    identity_id VARCHAR(500),
    response_action VARCHAR(40) NOT NULL CHECK (response_action IN (
        'rotate_credential', 'disable_identity',
        'remove_privileged_role', 'revert_policy_change'
    )),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'approved', 'executed', 'failed', 'rejected'
    )),
    metadata JSONB DEFAULT '{}',
    approved_by VARCHAR(100),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sra_org ON security_response_actions(organization_id);
CREATE INDEX IF NOT EXISTS idx_sra_incident ON security_response_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_sra_identity ON security_response_actions(identity_id);
CREATE INDEX IF NOT EXISTS idx_sra_status ON security_response_actions(status);
CREATE INDEX IF NOT EXISTS idx_sra_action ON security_response_actions(response_action);
CREATE INDEX IF NOT EXISTS idx_sra_created ON security_response_actions(created_at DESC);

ALTER TABLE security_response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_response_actions FORCE ROW LEVEL SECURITY;

CREATE POLICY sra_strict_sel ON security_response_actions FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sra_strict_ins ON security_response_actions FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sra_strict_upd ON security_response_actions FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY sra_strict_del ON security_response_actions FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON security_response_actions TO auditgraph_app;
