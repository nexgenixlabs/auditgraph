-- Migration 052: Graph Visualization Cache
-- Phase 16: Identity Attack Graph Visualization

CREATE TABLE IF NOT EXISTS graph_visualization_cache (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    graph_type          VARCHAR(30) NOT NULL CHECK (graph_type IN ('identity_graph', 'attack_path_graph')),
    graph_data          JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gvc_org ON graph_visualization_cache(organization_id);
CREATE INDEX IF NOT EXISTS idx_gvc_connection ON graph_visualization_cache(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_gvc_type ON graph_visualization_cache(graph_type);
CREATE INDEX IF NOT EXISTS idx_gvc_created ON graph_visualization_cache(created_at DESC);

ALTER TABLE graph_visualization_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_visualization_cache FORCE ROW LEVEL SECURITY;

CREATE POLICY gvc_strict_sel ON graph_visualization_cache FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gvc_strict_ins ON graph_visualization_cache FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gvc_strict_upd ON graph_visualization_cache FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gvc_strict_del ON graph_visualization_cache FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON graph_visualization_cache TO auditgraph_app;
