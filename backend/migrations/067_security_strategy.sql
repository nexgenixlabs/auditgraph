-- Migration 067: AI Security Strategy Advisor
-- Phase 32: Strategic security recommendations

CREATE TABLE IF NOT EXISTS security_strategy_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    recommendation_type VARCHAR(60) NOT NULL CHECK (recommendation_type IN (
        'reduce_privileged_roles',
        'rotate_credentials',
        'remove_unused_identities',
        'limit_guest_privileges'
    )),
    risk_reduction_score FLOAT NOT NULL DEFAULT 0,
    implementation_effort VARCHAR(20) NOT NULL CHECK (implementation_effort IN (
        'low', 'medium', 'high'
    )),
    priority VARCHAR(20) NOT NULL CHECK (priority IN (
        'critical', 'high', 'medium', 'low'
    )),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'implemented', 'dismissed')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ssr_org ON security_strategy_recommendations(organization_id);
CREATE INDEX IF NOT EXISTS idx_ssr_connection ON security_strategy_recommendations(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_ssr_type ON security_strategy_recommendations(recommendation_type);
CREATE INDEX IF NOT EXISTS idx_ssr_priority ON security_strategy_recommendations(priority);
CREATE INDEX IF NOT EXISTS idx_ssr_status ON security_strategy_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_ssr_created ON security_strategy_recommendations(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ssr_dedup
    ON security_strategy_recommendations(cloud_connection_id, recommendation_type)
    WHERE status = 'open';

ALTER TABLE security_strategy_recommendations ENABLE ROW LEVEL SECURITY;

CREATE POLICY ssr_strict_sel ON security_strategy_recommendations FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ssr_strict_ins ON security_strategy_recommendations FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ssr_strict_upd ON security_strategy_recommendations FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ssr_strict_del ON security_strategy_recommendations FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE ON security_strategy_recommendations TO auditgraph_app;
