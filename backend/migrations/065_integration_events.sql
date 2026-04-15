-- Migration 065: Integration Events
-- Phase 30: Enterprise Security Integrations

CREATE TABLE IF NOT EXISTS integration_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    event_type VARCHAR(60) NOT NULL CHECK (event_type IN (
        'incident', 'threat', 'governance_action', 'risk_prediction'
    )),
    destination VARCHAR(60) NOT NULL CHECK (destination IN (
        'slack', 'jira', 'servicenow', 'siem'
    )),
    payload JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'sent', 'failed', 'skipped'
    )),
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Integration configs table
CREATE TABLE IF NOT EXISTS integration_configs (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    integration_type VARCHAR(60) NOT NULL CHECK (integration_type IN (
        'slack', 'jira', 'servicenow', 'siem'
    )),
    enabled BOOLEAN DEFAULT FALSE,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (organization_id, integration_type)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ie_org ON integration_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_ie_type ON integration_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ie_dest ON integration_events(destination);
CREATE INDEX IF NOT EXISTS idx_ie_status ON integration_events(status);
CREATE INDEX IF NOT EXISTS idx_ie_created ON integration_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ic_org ON integration_configs(organization_id);

-- RLS on integration_events
ALTER TABLE integration_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY ie_strict_sel ON integration_events FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ie_strict_ins ON integration_events FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ie_strict_upd ON integration_events FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ie_strict_del ON integration_events FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

-- RLS on integration_configs
ALTER TABLE integration_configs ENABLE ROW LEVEL SECURITY;

CREATE POLICY ic_strict_sel ON integration_configs FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ic_strict_ins ON integration_configs FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ic_strict_upd ON integration_configs FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ic_strict_del ON integration_configs FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON integration_events TO auditgraph_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON integration_configs TO auditgraph_app;
GRANT USAGE, SELECT ON SEQUENCE integration_configs_id_seq TO auditgraph_app;
