-- AG-129: Eliminate transitive scoping on identities table
-- Phase A: Schema constraints (NOT NULL, indexes, FK, consistency trigger)
--
-- Prerequisites:
--   - All identities.organization_id values are non-NULL (verified: 8129/8129)
--   - Phase Pre-A ensured all INSERT paths supply organization_id
--
-- Performance budget: < 5s on 10k-row table (non-blocking where possible)
-- Rollback: 101_identities_org_id_constraints_rollback.sql

BEGIN;

-- ─── Step 1: NOT NULL constraint ──────────────────────────────────────────────
-- Safe because we verified 0 NULLs exist.
ALTER TABLE identities
    ALTER COLUMN organization_id SET NOT NULL;

COMMIT;

-- ─── Step 2: Index on organization_id ─────────────────────────────────────────
-- CONCURRENTLY cannot run inside a transaction block.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_org_id
    ON identities (organization_id);

-- ─── Step 3: Composite index for hot dashboard queries ────────────────────────
-- Covers: WHERE organization_id = X ORDER BY risk_score DESC / activity_status
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_org_risk
    ON identities (organization_id, risk_score DESC);

-- Covers: WHERE organization_id = X AND discovery_run_id = Y (common join pattern)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identities_org_run
    ON identities (organization_id, discovery_run_id);

-- ─── Step 4: FK to organizations ──────────────────────────────────────────────
-- NOT VALID avoids full table scan + lock; VALIDATE in separate txn.
BEGIN;

ALTER TABLE identities
    ADD CONSTRAINT fk_identities_organization_id
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
    NOT VALID;

COMMIT;

-- Validate the FK (acquires SHARE UPDATE EXCLUSIVE lock, non-blocking for writes)
ALTER TABLE identities
    VALIDATE CONSTRAINT fk_identities_organization_id;

-- ─── Step 5: Consistency trigger ──────────────────────────────────────────────
-- Ensures identities.organization_id matches the organization_id on the
-- referenced discovery_run. Prevents silent data corruption.
BEGIN;

CREATE OR REPLACE FUNCTION trg_identities_org_consistency()
RETURNS TRIGGER AS $$
DECLARE
    run_org_id INTEGER;
BEGIN
    -- Skip check if discovery_run_id is NULL (shouldn't happen, but defensive)
    IF NEW.discovery_run_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT organization_id INTO run_org_id
    FROM discovery_runs
    WHERE id = NEW.discovery_run_id;

    -- If the discovery_run doesn't exist, let FK handle it
    IF run_org_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.organization_id != run_org_id THEN
        RAISE EXCEPTION 'AG-129 consistency violation: identities.organization_id (%) does not match discovery_runs.organization_id (%) for run_id %',
            NEW.organization_id, run_org_id, NEW.discovery_run_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_identities_org_id_consistency
    BEFORE INSERT OR UPDATE OF organization_id, discovery_run_id
    ON identities
    FOR EACH ROW
    EXECUTE FUNCTION trg_identities_org_consistency();

COMMIT;
