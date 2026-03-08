-- Migration 062: Identity Graph Intelligence
-- Phase 27: Graph-based IAM structural analysis

CREATE TABLE IF NOT EXISTS identity_graph_insights (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    identity_id VARCHAR(500),
    identity_name VARCHAR(500),
    identity_category VARCHAR(100),
    centrality_score FLOAT DEFAULT 0,
    blast_radius INTEGER DEFAULT 0,
    trust_chain_length INTEGER DEFAULT 0,
    resource_reachability INTEGER DEFAULT 0,
    privilege_concentration FLOAT DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
    insight_summary TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_igi_org ON identity_graph_insights(organization_id);
CREATE INDEX IF NOT EXISTS idx_igi_connection ON identity_graph_insights(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_igi_identity ON identity_graph_insights(identity_id);
CREATE INDEX IF NOT EXISTS idx_igi_risk ON identity_graph_insights(risk_level);
CREATE INDEX IF NOT EXISTS idx_igi_centrality ON identity_graph_insights(centrality_score DESC);
CREATE INDEX IF NOT EXISTS idx_igi_created ON identity_graph_insights(created_at DESC);

-- Dedup: one insight per identity per connection
CREATE UNIQUE INDEX IF NOT EXISTS idx_igi_dedup
    ON identity_graph_insights(cloud_connection_id, identity_id);

-- RLS
ALTER TABLE identity_graph_insights ENABLE ROW LEVEL SECURITY;

CREATE POLICY igi_strict_sel ON identity_graph_insights FOR SELECT
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igi_strict_ins ON identity_graph_insights FOR INSERT
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igi_strict_upd ON identity_graph_insights FOR UPDATE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY igi_strict_del ON identity_graph_insights FOR DELETE
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON identity_graph_insights TO auditgraph_app;
