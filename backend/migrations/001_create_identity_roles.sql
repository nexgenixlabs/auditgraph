CREATE TABLE IF NOT EXISTS identity_roles (
  id BIGSERIAL PRIMARY KEY,
  identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL,
  role_type TEXT NOT NULL,              -- 'azure_rbac' | 'entra_directory_role'
  scope TEXT,
  inherited BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_roles_identity_db_id ON identity_roles(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_identity_roles_role_type ON identity_roles(role_type);
CREATE INDEX IF NOT EXISTS idx_identity_roles_role_name ON identity_roles(role_name);
