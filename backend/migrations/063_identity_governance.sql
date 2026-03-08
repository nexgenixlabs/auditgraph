-- Migration 063: Identity Governance Actions
-- Phase 28: Autonomous Identity Governance

CREATE TABLE IF NOT EXISTS identity_governance_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id VARCHAR(500),
    identity_name VARCHAR(500),
    identity_category VARCHAR(100),
    governance_action VARCHAR(60) NOT NULL CHECK (governance_action IN (
        'downgrade_privileged_role', 'disable_unused_identity',
        'rotate_old_credential', 'remove_guest_privilege'
    )),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'approved', 'executed', 'failed'
    )),
    reason TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_iga_org ON identity_governance_actions(organization_id);
CREATE INDEX IF NOT EXISTS idx_iga_connection ON identity_governance_actions(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_iga_identity ON identity_governance_actions(identity_id);
CREATE INDEX IF NOT EXISTS idx_iga_action ON identity_governance_actions(governance_action);
CREATE INDEX IF NOT EXISTS idx_iga_status ON identity_governance_actions(status);
CREATE INDEX IF NOT EXISTS idx_iga_created ON identity_governance_actions(created_at DESC);

-- Dedup: one pending action per identity per action type per connection
CREATE UNIQUE INDEX IF NOT EXISTS idx_iga_dedup
    ON identity_governance_actions(cloud_connection_id, identity_id, governance_action)
    WHERE status = 'pending';

-- RLS
ALTER TABLE identity_governance_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY iga_strict_sel ON identity_governance_actions FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iga_strict_ins ON identity_governance_actions FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iga_strict_upd ON identity_governance_actions FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY iga_strict_del ON identity_governance_actions FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_governance_actions TO auditgraph_app;
