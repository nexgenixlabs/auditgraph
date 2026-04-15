-- Migration 047: Policy Recommendations
-- Phase 11: IAM Policy Recommendation Engine

CREATE TABLE IF NOT EXISTS policy_recommendations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    finding_id          UUID NULL,
    identity_id         VARCHAR NULL,
    resource_id         VARCHAR NULL,
    recommendation_type VARCHAR(100) NOT NULL,
    severity            VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description         TEXT,
    recommended_action  TEXT,
    confidence_score    INTEGER DEFAULT 80,
    metadata            JSONB DEFAULT '{}',
    status              VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'accepted', 'dismissed', 'resolved')),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pr_org ON policy_recommendations(organization_id);
CREATE INDEX IF NOT EXISTS idx_pr_connection ON policy_recommendations(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_pr_status ON policy_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_pr_severity ON policy_recommendations(severity);
CREATE INDEX IF NOT EXISTS idx_pr_type ON policy_recommendations(recommendation_type);

-- Dedup: one recommendation per connection+type+identity
CREATE UNIQUE INDEX IF NOT EXISTS idx_pr_dedup
    ON policy_recommendations (cloud_connection_id, recommendation_type, COALESCE(identity_id, ''))
    WHERE status IN ('open', 'accepted');

ALTER TABLE policy_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_recommendations FORCE ROW LEVEL SECURITY;

CREATE POLICY pr_strict_sel ON policy_recommendations FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY pr_strict_ins ON policy_recommendations FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY pr_strict_upd ON policy_recommendations FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY pr_strict_del ON policy_recommendations FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON policy_recommendations TO auditgraph_app;
