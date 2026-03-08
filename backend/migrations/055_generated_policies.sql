-- Migration 055: Automated Least-Privilege Policy Generation
-- Phase 19: generated_policies table for storing optimized IAM policies

-- Table: generated_policies (org-scoped, RLS-protected)
CREATE TABLE IF NOT EXISTS generated_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id VARCHAR(500) NOT NULL,
    cloud_provider VARCHAR(20) NOT NULL,
    generated_policy JSONB DEFAULT '{}',
    policy_type VARCHAR(30) NOT NULL CHECK (policy_type IN ('least_privilege', 'role_replacement')),
    confidence_score FLOAT DEFAULT 0.0,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'dismissed')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_gp_org ON generated_policies(organization_id);
CREATE INDEX IF NOT EXISTS idx_gp_connection ON generated_policies(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_gp_identity ON generated_policies(identity_id);
CREATE INDEX IF NOT EXISTS idx_gp_type ON generated_policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_gp_created ON generated_policies(created_at DESC);

-- Partial unique index for dedup (one active policy per identity per type)
CREATE UNIQUE INDEX IF NOT EXISTS idx_gp_dedup
    ON generated_policies(cloud_connection_id, identity_id, policy_type)
    WHERE status = 'pending';

-- RLS
ALTER TABLE generated_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE generated_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY gp_strict_sel ON generated_policies FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gp_strict_ins ON generated_policies FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gp_strict_upd ON generated_policies FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gp_strict_del ON generated_policies FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON generated_policies TO auditgraph_app;
