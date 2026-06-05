-- 116_restore_perm_table_constraints.sql
--
-- AG-DBFIX: migration 100_full_schema.sql defined graph_api_permissions
-- and sp_app_roles WITHOUT primary keys, sequence defaults, or unique
-- constraints. Result: every discovery write to these tables silently
-- failed (NOT NULL on `id` with no default, and ON CONFLICT clauses
-- referencing a UNIQUE constraint that doesn't exist).
--
-- Symptom: Identity Detail > Permissions tab shows "0 Graph API
-- permissions discovered" for every SPN — even the connector itself,
-- which has 10 admin-consented Graph permissions in Azure.
--
-- This migration restores the original schema (per 003_create_graph_api_permissions.sql)
-- without dropping or modifying any existing rows. Fully idempotent — safe
-- to re-run.

BEGIN;

-- ── graph_api_permissions ─────────────────────────────────────────────

CREATE SEQUENCE IF NOT EXISTS graph_api_permissions_id_seq
  AS BIGINT OWNED BY graph_api_permissions.id;

SELECT setval(
  'graph_api_permissions_id_seq',
  COALESCE((SELECT MAX(id) FROM graph_api_permissions), 0) + 1,
  false
);

ALTER TABLE graph_api_permissions
  ALTER COLUMN id SET DEFAULT nextval('graph_api_permissions_id_seq');

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'graph_api_permissions'::regclass AND contype = 'p'
  ) THEN
    ALTER TABLE graph_api_permissions
      ADD CONSTRAINT graph_api_permissions_pkey PRIMARY KEY (id);
  END IF;
END$$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'graph_api_permissions'::regclass
       AND contype = 'u'
       AND conname = 'graph_api_permissions_identity_perm_key'
  ) THEN
    ALTER TABLE graph_api_permissions
      ADD CONSTRAINT graph_api_permissions_identity_perm_key
      UNIQUE (identity_db_id, permission_name);
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_graph_perms_identity_db_id
  ON graph_api_permissions(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_graph_perms_risk_level
  ON graph_api_permissions(risk_level);
CREATE INDEX IF NOT EXISTS idx_graph_perms_permission_name
  ON graph_api_permissions(permission_name);

-- ── sp_app_roles ──────────────────────────────────────────────────────

CREATE SEQUENCE IF NOT EXISTS sp_app_roles_id_seq
  AS BIGINT OWNED BY sp_app_roles.id;

SELECT setval(
  'sp_app_roles_id_seq',
  COALESCE((SELECT MAX(id) FROM sp_app_roles), 0) + 1,
  false
);

ALTER TABLE sp_app_roles
  ALTER COLUMN id SET DEFAULT nextval('sp_app_roles_id_seq');

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'sp_app_roles'::regclass AND contype = 'p'
  ) THEN
    ALTER TABLE sp_app_roles
      ADD CONSTRAINT sp_app_roles_pkey PRIMARY KEY (id);
  END IF;
END$$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'sp_app_roles'::regclass
       AND contype = 'u'
       AND conname = 'sp_app_roles_identity_role_resource_key'
  ) THEN
    ALTER TABLE sp_app_roles
      ADD CONSTRAINT sp_app_roles_identity_role_resource_key
      UNIQUE (identity_db_id, app_role_id, resource_id);
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_sp_app_roles_identity_db_id
  ON sp_app_roles(identity_db_id);

COMMIT;
