-- AG-129: Rollback for 101_identities_org_id_constraints.sql
-- Reverses all Phase A schema changes in dependency order.

BEGIN;

-- ─── Step 5 rollback: Remove consistency trigger ──────────────────────────────
DROP TRIGGER IF EXISTS trg_identities_org_id_consistency ON identities;
DROP FUNCTION IF EXISTS trg_identities_org_consistency();

-- ─── Step 4 rollback: Remove FK ───────────────────────────────────────────────
ALTER TABLE identities
    DROP CONSTRAINT IF EXISTS fk_identities_organization_id;

-- ─── Step 1 rollback: Remove NOT NULL ─────────────────────────────────────────
ALTER TABLE identities
    ALTER COLUMN organization_id DROP NOT NULL;

COMMIT;

-- ─── Steps 2-3 rollback: Remove indexes ──────────────────────────────────────
-- CONCURRENTLY cannot run inside a transaction block.
DROP INDEX CONCURRENTLY IF EXISTS idx_identities_org_id;
DROP INDEX CONCURRENTLY IF EXISTS idx_identities_org_risk;
DROP INDEX CONCURRENTLY IF EXISTS idx_identities_org_run;
