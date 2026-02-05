-- 003_create_graph_api_permissions.sql

CREATE TABLE IF NOT EXISTS graph_api_permissions (
  id BIGSERIAL PRIMARY KEY,
  identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

  permission_name TEXT NOT NULL,
  permission_description TEXT,
  resource_name TEXT DEFAULT 'Microsoft Graph',
  risk_level TEXT, -- critical | high | medium | low

  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (identity_db_id, permission_name)
);

CREATE INDEX IF NOT EXISTS idx_graph_perms_identity_db_id ON graph_api_permissions(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_graph_perms_risk_level ON graph_api_permissions(risk_level);
CREATE INDEX IF NOT EXISTS idx_graph_perms_permission_name ON graph_api_permissions(permission_name);
