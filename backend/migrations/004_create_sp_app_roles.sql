-- 004_create_sp_app_roles.sql

CREATE TABLE IF NOT EXISTS sp_app_roles (
  id BIGSERIAL PRIMARY KEY,
  identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

  app_role_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,

  resource_display_name TEXT,
  principal_display_name TEXT,

  created_date_time TIMESTAMPTZ,
  risk_level TEXT, -- critical | high | medium | low

  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (identity_db_id, app_role_id, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_sp_app_roles_identity_db_id ON sp_app_roles(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_sp_app_roles_risk_level ON sp_app_roles(risk_level);
CREATE INDEX IF NOT EXISTS idx_sp_app_roles_resource_name ON sp_app_roles(resource_display_name);
