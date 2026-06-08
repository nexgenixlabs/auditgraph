-- AG-PIM-PHASE2-D (2026-06-07): Legacy PIM data backfill
--
-- One-shot migration: for every existing row in pim_eligible_assignments
-- (the legacy table), insert a corresponding row into pim_eligibility_state
-- (the new table) with conservative-safe defaults for activation-policy
-- fields. Same approach as the Phase 1 bridge writes.
--
-- Idempotent: ON CONFLICT DO NOTHING — safe to re-run. Existing rows in
-- pim_eligibility_state (already populated by the dual-write bridge from
-- Phase 1) are not overwritten.
--
-- Similarly for pim_activations → pim_activation_observations.
--
-- This unblocks tenants that ran discovery BEFORE Phase 1 (commit c7feca8)
-- and have legacy data only. After this migration, the PIM Overprivilege
-- page will populate from their historic discovery data immediately.
--
-- Moat compliance: pure data migration, no schema changes, no permissions
-- changed.

\set ON_ERROR_STOP on

BEGIN;

-- ── 1. Backfill pim_eligibility_state from pim_eligible_assignments ──
WITH legacy_eligible AS (
    SELECT
        i.organization_id,
        i.discovery_run_id,
        pea.identity_db_id,
        i.identity_id,
        pea.role_name,
        pea.role_definition_id,
        COALESCE(pea.directory_scope, '/') AS directory_scope,
        pea.start_datetime,
        pea.end_datetime,
        pea.assignment_type
    FROM pim_eligible_assignments pea
    JOIN identities i ON i.id = pea.identity_db_id
    WHERE i.deleted_at IS NULL
)
INSERT INTO pim_eligibility_state (
    organization_id, discovery_run_id, identity_db_id, identity_id,
    role_name, role_template_id, scope, scope_type,
    assignment_type, eligible_since,
    requires_mfa_on_activation, requires_approval,
    requires_justification, max_activation_minutes
)
SELECT
    le.organization_id,
    le.discovery_run_id,
    le.identity_db_id,
    le.identity_id,
    le.role_name,
    le.role_definition_id,
    le.directory_scope,
    -- Same scope_type derivation as _dual_write_pim_eligibility_state
    CASE
        WHEN le.directory_scope = '/' OR le.directory_scope IS NULL THEN 'directory'
        WHEN le.directory_scope LIKE '/subscriptions/%' AND le.directory_scope NOT LIKE '%/resourceGroups/%' THEN 'subscription'
        WHEN le.directory_scope LIKE '%/resourceGroups/%' AND le.directory_scope NOT LIKE '%/providers/%' THEN 'resource_group'
        WHEN le.directory_scope LIKE '%/providers/%' THEN 'resource'
        ELSE 'other'
    END,
    'eligible',
    le.start_datetime,
    -- Conservative-safe defaults (same as Phase 1 bridge)
    TRUE,    -- requires_mfa_on_activation
    FALSE,   -- requires_approval
    TRUE,    -- requires_justification
    480      -- max_activation_minutes (Azure 8h default)
FROM legacy_eligible le
ON CONFLICT (organization_id, identity_db_id, role_name, scope, assignment_type)
DO NOTHING;

-- ── 2. Backfill pim_activation_observations from pim_activations ──
-- Use a synthetic deterministic audit_event_id (same shape as
-- _dual_write_pim_activation_observation) so idempotent re-runs.
WITH legacy_activations AS (
    SELECT
        i.organization_id,
        pa.identity_db_id,
        i.identity_id,
        pa.role_name,
        pa.role_definition_id,
        COALESCE(pa.directory_scope, '/') AS scope,
        pa.activation_start,
        pa.activation_end,
        pa.justification,
        -- duration in minutes when both end + start known
        CASE
            WHEN pa.activation_start IS NOT NULL AND pa.activation_end IS NOT NULL
            THEN EXTRACT(EPOCH FROM (pa.activation_end - pa.activation_start)) / 60
            ELSE NULL
        END::INTEGER AS duration_minutes
    FROM pim_activations pa
    JOIN identities i ON i.id = pa.identity_db_id
    WHERE pa.activation_start IS NOT NULL
      AND i.deleted_at IS NULL
)
INSERT INTO pim_activation_observations (
    organization_id, identity_db_id, identity_id,
    role_name, role_template_id, scope,
    activated_at, activation_duration_minutes,
    justification, audit_event_id
)
SELECT
    la.organization_id,
    la.identity_db_id,
    la.identity_id,
    la.role_name,
    la.role_definition_id,
    la.scope,
    la.activation_start,
    la.duration_minutes,
    la.justification,
    -- Synthetic deterministic event_id matching _dual_write helper
    'pim-req:' || la.identity_db_id::TEXT
        || ':' || COALESCE(la.role_definition_id, 'unknown')
        || ':' || la.activation_start::TEXT
FROM legacy_activations la
ON CONFLICT (organization_id, audit_event_id) DO NOTHING;

-- ── 3. Report results ──
-- (Postgres NOTICE — visible in psql output but not the application log)
DO $$
DECLARE
    eligibility_rows INTEGER;
    observation_rows INTEGER;
BEGIN
    SELECT COUNT(*) INTO eligibility_rows FROM pim_eligibility_state;
    SELECT COUNT(*) INTO observation_rows FROM pim_activation_observations;
    RAISE NOTICE 'pim_eligibility_state total rows: %', eligibility_rows;
    RAISE NOTICE 'pim_activation_observations total rows: %', observation_rows;
END $$;

COMMIT;
