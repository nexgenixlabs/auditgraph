-- Migration 043: IAM Graph Engine — graph_nodes + graph_edges tables
-- Phase 7: Relationship graph for identity access path analysis

-- ── graph_nodes (org-scoped, WITH RLS) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS graph_nodes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    node_type           VARCHAR(50) NOT NULL CHECK (node_type IN ('identity', 'role', 'resource', 'subscription')),
    external_id         VARCHAR(500) NOT NULL,
    display_name        VARCHAR(500),
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gn_org ON graph_nodes(organization_id);
CREATE INDEX IF NOT EXISTS idx_gn_connection ON graph_nodes(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_gn_type ON graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_gn_external ON graph_nodes(external_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gn_dedup ON graph_nodes(cloud_connection_id, node_type, external_id);

ALTER TABLE graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_nodes FORCE ROW LEVEL SECURITY;

CREATE POLICY gn_strict_sel ON graph_nodes FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gn_strict_ins ON graph_nodes FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gn_strict_upd ON graph_nodes FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY gn_strict_del ON graph_nodes FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON graph_nodes TO auditgraph_app;

-- ── graph_edges (org-scoped, WITH RLS) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS graph_edges (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    source_node_id      UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    target_node_id      UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    edge_type           VARCHAR(50) NOT NULL CHECK (edge_type IN ('assigned_role', 'grants_access', 'contains_resource')),
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ge_org ON graph_edges(organization_id);
CREATE INDEX IF NOT EXISTS idx_ge_connection ON graph_edges(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_ge_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_ge_target ON graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_ge_type ON graph_edges(edge_type);

ALTER TABLE graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_edges FORCE ROW LEVEL SECURITY;

CREATE POLICY ge_strict_sel ON graph_edges FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ge_strict_ins ON graph_edges FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ge_strict_upd ON graph_edges FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);
CREATE POLICY ge_strict_del ON graph_edges FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE, DELETE ON graph_edges TO auditgraph_app;
