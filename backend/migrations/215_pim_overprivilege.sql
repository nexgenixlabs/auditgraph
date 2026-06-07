-- AG-PIM-OVERPRIV (2026-06-07): PIM Overprivilege Detection
--
-- Two tables that together feed the PIM Overprivilege engine.
-- All data sourced from read-only Graph API calls. No write to customer
-- config is performed.
--
-- Graph endpoints consumed:
--   GET /roleManagement/directory/roleEligibilityScheduleInstances
--   GET /roleManagement/directory/roleAssignmentScheduleInstances
--   GET /policies/roleManagementPolicies (for MFA/approval requirements)
--   GET /auditLogs/directoryAudits (filtered to PIM activation events)
--
-- Required permission tier: RoleManagement.Read.Directory + AuditLog.Read.All
-- both read-only. See docs/AG_AZURE_DEPTH_PLAN_2026_06_07.md §2.2.

\set ON_ERROR_STOP on

BEGIN;

-- ── 1. pim_eligibility_state — point-in-time snapshot per (identity, role, scope)
CREATE TABLE IF NOT EXISTS pim_eligibility_state (
    id                          BIGSERIAL PRIMARY KEY,
    organization_id             INTEGER NOT NULL,
    discovery_run_id            BIGINT,

    identity_db_id              BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    identity_id                 TEXT NOT NULL,

    role_name                   TEXT NOT NULL,
    role_template_id            TEXT,                       -- Azure built-in role template GUID
    scope                       TEXT NOT NULL,              -- e.g. '/' for directory, or /subscriptions/...
    scope_type                  TEXT NOT NULL,              -- 'directory'|'subscription'|'resource_group'|'resource'

    assignment_type             TEXT NOT NULL
        CHECK (assignment_type IN ('eligible','active','active_via_eligible')),

    eligible_since              TIMESTAMPTZ,
    active_until                TIMESTAMPTZ,                -- for active activations: when does this elevation expire

    -- Activation policy snapshot at discovery time
    requires_mfa_on_activation  BOOLEAN NOT NULL DEFAULT TRUE,
    requires_approval           BOOLEAN NOT NULL DEFAULT FALSE,
    requires_justification      BOOLEAN NOT NULL DEFAULT TRUE,
    max_activation_minutes      INTEGER,                    -- typical: 480 (8h)

    discovered_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pim_eligibility_unique
        UNIQUE (organization_id, identity_db_id, role_name, scope, assignment_type)
);
CREATE INDEX IF NOT EXISTS idx_pim_eligibility_org_identity
    ON pim_eligibility_state (organization_id, identity_db_id);
CREATE INDEX IF NOT EXISTS idx_pim_eligibility_role
    ON pim_eligibility_state (organization_id, role_name);


-- ── 2. pim_activation_observations — rolling observations of when activations
--      actually occurred (sourced from auditLogs/directoryAudits)
CREATE TABLE IF NOT EXISTS pim_activation_observations (
    id                          BIGSERIAL PRIMARY KEY,
    organization_id             INTEGER NOT NULL,

    identity_db_id              BIGINT REFERENCES identities(id) ON DELETE SET NULL,
    identity_id                 TEXT NOT NULL,

    role_name                   TEXT NOT NULL,
    role_template_id            TEXT,
    scope                       TEXT,                       -- nullable: some activations don't carry scope

    activated_at                TIMESTAMPTZ NOT NULL,
    activation_duration_minutes INTEGER,                    -- nullable

    justification               TEXT,
    audit_event_id              TEXT,                       -- Graph audit log entry id (for dedup)

    observed_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pim_observation_unique_event
        UNIQUE (organization_id, audit_event_id)
);
CREATE INDEX IF NOT EXISTS idx_pim_activation_obs_identity_role
    ON pim_activation_observations (organization_id, identity_db_id, role_name, activated_at DESC);


-- ── RLS — strict tenant policies (same pattern as 211)
DO $$
DECLARE
    t TEXT;
    using_clause TEXT := 'organization_id = (current_setting(''app.current_organization_id'', true))::integer';
BEGIN
    FOREACH t IN ARRAY ARRAY['pim_eligibility_state', 'pim_activation_observations'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_sel ON %I', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_ins ON %I', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_upd ON %I', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_strict_del ON %I', t);
        EXECUTE format('CREATE POLICY tenant_strict_sel ON %I FOR SELECT USING (%s)', t, using_clause);
        EXECUTE format('CREATE POLICY tenant_strict_ins ON %I FOR INSERT WITH CHECK (%s)', t, using_clause);
        EXECUTE format('CREATE POLICY tenant_strict_upd ON %I FOR UPDATE USING (%s) WITH CHECK (%s)',
                       t, using_clause, using_clause);
        EXECUTE format('CREATE POLICY tenant_strict_del ON %I FOR DELETE USING (%s)', t, using_clause);
    END LOOP;
END $$;

DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON pim_eligibility_state TO auditgraph_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON pim_activation_observations TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE pim_eligibility_state_id_seq TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE pim_activation_observations_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON pim_eligibility_state TO auditgraph_admin';
    EXECUTE 'GRANT ALL ON pim_activation_observations TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;
