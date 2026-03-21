-- Migration 072: Add ON DELETE CASCADE FKs from graph_nodes/graph_edges → cloud_connections
-- Ensures graph data is automatically cleaned when a cloud connection is removed.
-- Previously these tables had cloud_connection_id columns but no FK constraint,
-- requiring application-layer cleanup via ConnectionLifecycleService.

BEGIN;

-- graph_nodes → cloud_connections (CASCADE)
ALTER TABLE graph_nodes
    DROP CONSTRAINT IF EXISTS fk_graph_nodes_connection;

ALTER TABLE graph_nodes
    ADD CONSTRAINT fk_graph_nodes_connection
    FOREIGN KEY (cloud_connection_id)
    REFERENCES cloud_connections(id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

-- graph_edges → cloud_connections (CASCADE)
ALTER TABLE graph_edges
    DROP CONSTRAINT IF EXISTS fk_graph_edges_connection;

ALTER TABLE graph_edges
    ADD CONSTRAINT fk_graph_edges_connection
    FOREIGN KEY (cloud_connection_id)
    REFERENCES cloud_connections(id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

-- Track migration
INSERT INTO schema_migrations (version, description, applied_at)
VALUES (72, '072_add_connection_cascade_fk', NOW())
ON CONFLICT DO NOTHING;

COMMIT;
