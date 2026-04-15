-- Migration 085: Phase 3 identity columns on the identities table
--
-- IdentityProfileBuilder SELECTs columns the legacy identities schema
-- does not expose. Adding them here so the Phase 3 FastAPI build path
-- (GET /api/v1/identities/{id}) can load a profile without raising
-- UndefinedColumn.
--
-- All adds are IF NOT EXISTS and nullable / default-safe so existing
-- rows remain valid. No backfill is performed — the A4 seed script is
-- responsible for populating Phase 3 test fixtures. Production rows
-- stay NULL until the Phase 3 discovery writer is wired up in a
-- later milestone.

BEGIN;

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS global_identity_id   UUID,
    ADD COLUMN IF NOT EXISTS user_principal_name  VARCHAR(500),
    ADD COLUMN IF NOT EXISTS cloud_id             VARCHAR(20),
    ADD COLUMN IF NOT EXISTS is_federated_identity BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS federated_from       VARCHAR(500),
    ADD COLUMN IF NOT EXISTS last_modified_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS discovered_at        TIMESTAMPTZ;

-- Safe single-row lookup for the profile builder hot path.
-- Partial on organization_id NOT NULL to skip the null-org detritus
-- left by the pre-Phase 87 schema.
CREATE INDEX IF NOT EXISTS idx_identities_org_identity_id
    ON identities (organization_id, identity_id)
    WHERE organization_id IS NOT NULL;

COMMIT;
