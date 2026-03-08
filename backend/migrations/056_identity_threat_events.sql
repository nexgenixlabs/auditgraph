-- Migration 056: Continuous Identity Threat Detection
-- Phase 20: identity_threat_events table for real-time threat event tracking

-- Table: identity_threat_events (org-scoped, RLS-protected)
CREATE TABLE IF NOT EXISTS identity_threat_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id VARCHAR(500),
    event_type VARCHAR(40) NOT NULL CHECK (event_type IN (
        'privilege_escalation', 'credential_creation',
        'suspicious_login', 'policy_change'
    )),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    description TEXT,
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ite_org ON identity_threat_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_ite_connection ON identity_threat_events(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_ite_identity ON identity_threat_events(identity_id);
CREATE INDEX IF NOT EXISTS idx_ite_event_type ON identity_threat_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ite_severity ON identity_threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_ite_status ON identity_threat_events(status);
CREATE INDEX IF NOT EXISTS idx_ite_created ON identity_threat_events(created_at DESC);

-- RLS
ALTER TABLE identity_threat_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_threat_events FORCE ROW LEVEL SECURITY;

CREATE POLICY ite_strict_sel ON identity_threat_events FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ite_strict_ins ON identity_threat_events FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ite_strict_upd ON identity_threat_events FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ite_strict_del ON identity_threat_events FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_threat_events TO auditgraph_app;
