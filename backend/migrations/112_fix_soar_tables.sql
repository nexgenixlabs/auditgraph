-- Migration 112: Ensure SOAR tables have all required columns and indexes.
-- Moves DDL out of _ensure_soar_tables() (which ran on every request and
-- failed with InsufficientPrivilege for the app user).

-- Tables already exist from prior migrations/startup.  Only add missing
-- columns and indexes idempotently.

-- Columns
ALTER TABLE soar_playbooks ADD COLUMN IF NOT EXISTS organization_id INTEGER;
ALTER TABLE soar_actions   ADD COLUMN IF NOT EXISTS organization_id INTEGER;
ALTER TABLE soar_actions   ADD COLUMN IF NOT EXISTS execution_mode VARCHAR(20) NOT NULL DEFAULT 'simulated';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_trigger  ON soar_playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_enabled  ON soar_playbooks(enabled);
CREATE INDEX IF NOT EXISTS idx_soar_actions_playbook   ON soar_actions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_soar_actions_status     ON soar_actions(status);
CREATE INDEX IF NOT EXISTS idx_soar_actions_created    ON soar_actions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_actions_identity   ON soar_actions(identity_id);
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_org      ON soar_playbooks(organization_id);
CREATE INDEX IF NOT EXISTS idx_soar_actions_org        ON soar_actions(organization_id);
CREATE INDEX IF NOT EXISTS idx_soar_actions_org_created ON soar_actions(organization_id, created_at DESC);
