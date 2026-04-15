-- Migration 057: Identity Security Data Lake
-- Phase 21: Three tables for long-term identity activity storage

-- Table 1: identity_activity_events (org-scoped, RLS-protected)
CREATE TABLE IF NOT EXISTS identity_activity_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id VARCHAR(500),
    event_type VARCHAR(40) NOT NULL CHECK (event_type IN (
        'login', 'role_assignment', 'credential_change',
        'policy_update', 'resource_access'
    )),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iae_org ON identity_activity_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_iae_connection ON identity_activity_events(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_iae_identity ON identity_activity_events(identity_id);
CREATE INDEX IF NOT EXISTS idx_iae_event_type ON identity_activity_events(event_type);
CREATE INDEX IF NOT EXISTS idx_iae_created ON identity_activity_events(created_at DESC);

ALTER TABLE identity_activity_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_activity_events FORCE ROW LEVEL SECURITY;

CREATE POLICY iae_strict_sel ON identity_activity_events FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iae_strict_ins ON identity_activity_events FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iae_strict_upd ON identity_activity_events FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iae_strict_del ON identity_activity_events FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_activity_events TO auditgraph_app;

-- Table 2: identity_role_history (org-scoped, RLS-protected)
CREATE TABLE IF NOT EXISTS identity_role_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    identity_id VARCHAR(500) NOT NULL,
    role_name VARCHAR(255) NOT NULL,
    scope VARCHAR(1000),
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_irh_org ON identity_role_history(organization_id);
CREATE INDEX IF NOT EXISTS idx_irh_identity ON identity_role_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_irh_role ON identity_role_history(role_name);
CREATE INDEX IF NOT EXISTS idx_irh_assigned ON identity_role_history(assigned_at DESC);

ALTER TABLE identity_role_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_role_history FORCE ROW LEVEL SECURITY;

CREATE POLICY irh_strict_sel ON identity_role_history FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY irh_strict_ins ON identity_role_history FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY irh_strict_upd ON identity_role_history FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY irh_strict_del ON identity_role_history FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_role_history TO auditgraph_app;

-- Table 3: identity_access_history (org-scoped, RLS-protected)
CREATE TABLE IF NOT EXISTS identity_access_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    identity_id VARCHAR(500) NOT NULL,
    resource_id VARCHAR(1000),
    action VARCHAR(255),
    access_time TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iah_org ON identity_access_history(organization_id);
CREATE INDEX IF NOT EXISTS idx_iah_identity ON identity_access_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_iah_resource ON identity_access_history(resource_id);
CREATE INDEX IF NOT EXISTS idx_iah_access_time ON identity_access_history(access_time DESC);

ALTER TABLE identity_access_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_access_history FORCE ROW LEVEL SECURITY;

CREATE POLICY iah_strict_sel ON identity_access_history FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iah_strict_ins ON identity_access_history FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iah_strict_upd ON identity_access_history FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iah_strict_del ON identity_access_history FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_access_history TO auditgraph_app;
