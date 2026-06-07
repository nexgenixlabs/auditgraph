-- AG-FEATURE-E-P2 (2026-06-07): Entra Directory Role Last-Used Inference
--
-- For every (identity, directory_role) assignment, attribute audit-log
-- events to the assignment and compute per-role last-used + activity
-- bucket + dormancy band.
--
-- Source: GET /directoryRoles + /directoryRoles/{id}/members +
--         GET /auditLogs/directoryAudits (filtered by initiatedBy + category)
--
-- Required permission tier: RoleManagement.Read.Directory +
-- AuditLog.Read.All — both READ-ONLY. See moat compliance check in
-- docs/AG_AZURE_DEPTH_PLAN_2026_06_07.md §3.2.
--
-- Moat compliance:
--   ✓ Agentless (pure Graph API)
--   ✓ Read-only (no *.ReadWrite.*)
--   ✓ Architecture-derived (role assignment is the architecture; audit
--     logs enrich. On tenants without P2, last_action_at + activity
--     buckets show NULL and the UI shows "Entra P2 required for
--     inference" instead of failing.)

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS entra_role_activity (
    id                          BIGSERIAL PRIMARY KEY,
    organization_id             INTEGER NOT NULL,
    discovery_run_id            BIGINT,

    identity_db_id              BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    identity_id                 TEXT NOT NULL,

    role_name                   TEXT NOT NULL,                  -- e.g. 'Global Administrator'
    role_template_id            TEXT,
    assignment_principal_type   TEXT,                            -- 'User' | 'Group' | 'ServicePrincipal'

    -- Activity inference (all nullable — degrade gracefully on logs-OFF tenants)
    last_action_at              TIMESTAMPTZ,
    days_since_last_action      INTEGER,
    activities_30d              INTEGER,
    activities_90d              INTEGER,

    activity_bucket             TEXT,                            -- 'daily'|'weekly'|'monthly'|'rare'|'dormant'|'unknown'
    dormancy_band               TEXT,                            -- 'low'|'medium'|'high'|'unknown'

    inferred_from               TEXT NOT NULL DEFAULT 'auditLogs',  -- where the activity counts came from
    inference_confidence        TEXT NOT NULL DEFAULT 'unknown',   -- 'observed'|'unknown' for v1

    discovered_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT entra_role_activity_unique
        UNIQUE (organization_id, identity_db_id, role_name)
);
CREATE INDEX IF NOT EXISTS idx_entra_role_activity_org_identity
    ON entra_role_activity (organization_id, identity_db_id);
CREATE INDEX IF NOT EXISTS idx_entra_role_activity_dormancy
    ON entra_role_activity (organization_id, dormancy_band, days_since_last_action DESC);


-- ── RLS — strict tenant policies (matches migration 211)
DO $$
DECLARE
    using_clause TEXT := 'organization_id = (current_setting(''app.current_organization_id'', true))::integer';
BEGIN
    EXECUTE 'ALTER TABLE entra_role_activity ENABLE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_strict_sel ON entra_role_activity';
    EXECUTE 'DROP POLICY IF EXISTS tenant_strict_ins ON entra_role_activity';
    EXECUTE 'DROP POLICY IF EXISTS tenant_strict_upd ON entra_role_activity';
    EXECUTE 'DROP POLICY IF EXISTS tenant_strict_del ON entra_role_activity';
    EXECUTE format('CREATE POLICY tenant_strict_sel ON entra_role_activity FOR SELECT USING (%s)', using_clause);
    EXECUTE format('CREATE POLICY tenant_strict_ins ON entra_role_activity FOR INSERT WITH CHECK (%s)', using_clause);
    EXECUTE format('CREATE POLICY tenant_strict_upd ON entra_role_activity FOR UPDATE USING (%s) WITH CHECK (%s)', using_clause, using_clause);
    EXECUTE format('CREATE POLICY tenant_strict_del ON entra_role_activity FOR DELETE USING (%s)', using_clause);
END $$;

DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON entra_role_activity TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE entra_role_activity_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON entra_role_activity TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;
