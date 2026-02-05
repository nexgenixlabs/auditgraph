-- Add Graph API permissions tracking table
CREATE TABLE IF NOT EXISTS graph_api_permissions (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    permission_name TEXT NOT NULL,
    permission_description TEXT,
    resource_name TEXT DEFAULT 'Microsoft Graph',
    risk_level TEXT DEFAULT 'medium',
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(identity_db_id, permission_name)
);

CREATE INDEX IF NOT EXISTS idx_graph_permissions_identity ON graph_api_permissions(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_graph_permissions_risk ON graph_api_permissions(risk_level);
