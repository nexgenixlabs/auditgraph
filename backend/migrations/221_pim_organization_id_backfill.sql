-- 221_pim_organization_id_backfill.sql
-- 2026-06-12
--
-- Schema parity fix for cloud dev (and any environment that predates the
-- migration that added organization_id to PIM tables).
--
-- Root cause of founder's "115 vs 110 attack paths" delta:
--   Local enrolled tenant has 5 pim_escalation attack paths.
--   Cloud enrolled tenant (same Azure account) has 0.
--   Cause: cloud's pim_eligible_assignments + pim_activations predate
--   the organization_id column. The attack-path PIM detector queries
--   `WHERE organization_id = %s` and silently returns 0 rows.
--
-- Audit also surfaced role_attack_patterns.source missing on cloud.
-- Adding all three columns + a backfill via identity_db_id join.

ALTER TABLE pim_eligible_assignments
  ADD COLUMN IF NOT EXISTS organization_id integer;

ALTER TABLE pim_activations
  ADD COLUMN IF NOT EXISTS organization_id integer;

ALTER TABLE role_attack_patterns
  ADD COLUMN IF NOT EXISTS source text;

-- Backfill organization_id via identity_db_id → identities.organization_id
-- (No-op when target tables are empty, which is the case on cloud today.
-- Idempotent: only updates rows where organization_id IS NULL.)
UPDATE pim_eligible_assignments pea
SET organization_id = i.organization_id
FROM identities i
WHERE pea.identity_db_id = i.id
  AND pea.organization_id IS NULL;

UPDATE pim_activations pa
SET organization_id = i.organization_id
FROM identities i
WHERE pa.identity_db_id = i.id
  AND pa.organization_id IS NULL;

-- Indexes for org-scoped queries (matches the access pattern of
-- attack-paths PIM detector + Ownership Center).
CREATE INDEX IF NOT EXISTS idx_pim_eligible_org
  ON pim_eligible_assignments (organization_id);

CREATE INDEX IF NOT EXISTS idx_pim_activations_org
  ON pim_activations (organization_id);
