-- Migration 070: Identity Graph Edges
-- Lightweight edge table for the identity-to-role-to-scope graph.

CREATE TABLE IF NOT EXISTS identity_graph_edges (
    id SERIAL PRIMARY KEY,
    connection_id INT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_graph_conn ON identity_graph_edges(connection_id);
CREATE INDEX IF NOT EXISTS idx_graph_source ON identity_graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_graph_target ON identity_graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_graph_edge_type ON identity_graph_edges(edge_type);
