-- Migration 046: Identity Credentials Inventory
-- Phase 10: Credential tracking for NHI analytics and executive dashboard

CREATE TABLE IF NOT EXISTS identity_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id         TEXT NOT NULL,
    credential_type     VARCHAR(50) NOT NULL CHECK (credential_type IN ('secret', 'certificate', 'key', 'password', 'token')),
    created_at          TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ,
    metadata            JSONB DEFAULT '{}',
    discovered_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ic_org ON identity_credentials(organization_id);
CREATE INDEX IF NOT EXISTS idx_ic_connection ON identity_credentials(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_ic_identity ON identity_credentials(identity_id);
CREATE INDEX IF NOT EXISTS idx_ic_type ON identity_credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_ic_expires ON identity_credentials(expires_at);

-- Dedup: one credential record per connection+identity+type+created_at
CREATE UNIQUE INDEX IF NOT EXISTS idx_ic_dedup
    ON identity_credentials (cloud_connection_id, identity_id, credential_type, COALESCE(created_at, '1970-01-01'::timestamptz));

ALTER TABLE identity_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_credentials FORCE ROW LEVEL SECURITY;

CREATE POLICY ic_strict_sel ON identity_credentials FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ic_strict_ins ON identity_credentials FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ic_strict_upd ON identity_credentials FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ic_strict_del ON identity_credentials FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_credentials TO auditgraph_app;
