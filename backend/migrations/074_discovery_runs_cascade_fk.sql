-- Migration 074: Add ON DELETE CASCADE FK from discovery_runs → cloud_connections
-- This is the critical missing FK constraint. When a cloud_connection is deleted,
-- discovery_runs for that connection are automatically cascade-deleted, which in turn
-- cascades to 20+ child tables (identities, role_assignments, risk_summary, etc.).
-- This replaces the need for application-layer deletion of discovery_runs.

BEGIN;

-- Drop if exists (idempotent)
ALTER TABLE discovery_runs
    DROP CONSTRAINT IF EXISTS fk_discovery_runs_connection;

-- Add CASCADE FK
ALTER TABLE discovery_runs
    ADD CONSTRAINT fk_discovery_runs_connection
    FOREIGN KEY (cloud_connection_id)
    REFERENCES cloud_connections(id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;

-- Track migration
INSERT INTO schema_migrations (version, description, applied_at)
VALUES (74, '074_discovery_runs_cascade_fk', NOW())
ON CONFLICT DO NOTHING;

COMMIT;
