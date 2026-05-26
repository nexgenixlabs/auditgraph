-- Migration 102: Add unique index for entra_role_assignments upsert
--
-- Prevents duplicate rows from accumulating across discovery runs.
-- Required for ON CONFLICT clause in save_entra_role_assignment().
-- Also adds last_used_at/last_used_operation columns if missing
-- (previously only added via startup DDL).

ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS last_used_operation TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_entra_roles_upsert
ON entra_role_assignments (identity_db_id, role_definition_id, COALESCE(directory_scope, '/'));
