-- Migration 064: Identity Risk Simulations
-- Phase 29: Identity Risk Simulation Engine

CREATE TABLE IF NOT EXISTS identity_risk_simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER,
    identity_id VARCHAR(500),
    identity_name VARCHAR(500),
    identity_category VARCHAR(100),
    simulation_type VARCHAR(60) NOT NULL CHECK (simulation_type IN (
        'identity_compromise', 'credential_leak', 'privilege_grant'
    )),
    exposed_resources INTEGER DEFAULT 0,
    exposed_identities INTEGER DEFAULT 0,
    escalation_paths INTEGER DEFAULT 0,
    simulation_score FLOAT DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
    impact_summary TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_irs_org ON identity_risk_simulations(organization_id);
CREATE INDEX IF NOT EXISTS idx_irs_identity ON identity_risk_simulations(identity_id);
CREATE INDEX IF NOT EXISTS idx_irs_type ON identity_risk_simulations(simulation_type);
CREATE INDEX IF NOT EXISTS idx_irs_score ON identity_risk_simulations(simulation_score DESC);
CREATE INDEX IF NOT EXISTS idx_irs_created ON identity_risk_simulations(created_at DESC);

-- RLS
ALTER TABLE identity_risk_simulations ENABLE ROW LEVEL SECURITY;

CREATE POLICY irs_strict_sel ON identity_risk_simulations FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY irs_strict_ins ON identity_risk_simulations FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY irs_strict_upd ON identity_risk_simulations FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY irs_strict_del ON identity_risk_simulations FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_risk_simulations TO auditgraph_app;
