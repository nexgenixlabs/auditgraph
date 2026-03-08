-- Migration 058: Identity Attack Replay & Forensics
-- Phase 23: Two tables for attack incident tracking and replay steps

-- Table 1: identity_attack_incidents (org-scoped, RLS-protected)
CREATE TABLE IF NOT EXISTS identity_attack_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    identity_id VARCHAR(500) NOT NULL,
    incident_type VARCHAR(40) NOT NULL CHECK (incident_type IN (
        'privilege_escalation_attack', 'credential_compromise',
        'lateral_movement', 'resource_exposure'
    )),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    summary TEXT,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iai_org ON identity_attack_incidents(organization_id);
CREATE INDEX IF NOT EXISTS idx_iai_identity ON identity_attack_incidents(identity_id);
CREATE INDEX IF NOT EXISTS idx_iai_type ON identity_attack_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_iai_severity ON identity_attack_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_iai_status ON identity_attack_incidents(status);
CREATE INDEX IF NOT EXISTS idx_iai_created ON identity_attack_incidents(created_at DESC);

ALTER TABLE identity_attack_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_attack_incidents FORCE ROW LEVEL SECURITY;

CREATE POLICY iai_strict_sel ON identity_attack_incidents FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iai_strict_ins ON identity_attack_incidents FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iai_strict_upd ON identity_attack_incidents FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iai_strict_del ON identity_attack_incidents FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_attack_incidents TO auditgraph_app;

-- Table 2: identity_attack_replay_steps (linked to incidents via incident_id)
CREATE TABLE IF NOT EXISTS identity_attack_replay_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES identity_attack_incidents(id),
    step_index INTEGER NOT NULL,
    event_type VARCHAR(60) NOT NULL,
    event_time TIMESTAMPTZ,
    description TEXT,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_iars_incident ON identity_attack_replay_steps(incident_id);
CREATE INDEX IF NOT EXISTS idx_iars_step ON identity_attack_replay_steps(incident_id, step_index);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_attack_replay_steps TO auditgraph_app;
