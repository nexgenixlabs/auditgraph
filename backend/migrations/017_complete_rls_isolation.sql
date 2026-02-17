-- ============================================================
-- 017: Complete Tenant Isolation — Fixes gaps in 016
--
-- Problem: Migration 016 created RLS policies but:
--   1. auditgraph_admin has BYPASSRLS → RLS is completely ignored
--   2. Policies have NULL-context bypass → no isolation when context unset
--   3. 11 tables still have NULL tenant_id rows
--
-- Fix:
--   Part A: Create auditgraph_app user WITHOUT BYPASSRLS
--   Part B: Backfill remaining NULL tenant_ids
--   Part C: Enforce NOT NULL on tenant_id
--   Part D: Replace permissive policies with STRICT ones (no NULL bypass)
--   Part E: Add auto-fill trigger as safety net
--   Part F: Verify
--
-- Run: psql $DATABASE_URL -f backend/migrations/017_complete_rls_isolation.sql
-- ============================================================
BEGIN;

-- ============================================================
-- PART A: Create application user WITHOUT BYPASSRLS
-- The app will connect as this user; auditgraph_admin keeps bypass for migrations.
-- ============================================================

-- Create the user (skip if already exists)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditgraph_app') THEN
        CREATE ROLE auditgraph_app WITH LOGIN PASSWORD 'AuditGr@ph2026!app' NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;
        RAISE NOTICE 'Created role auditgraph_app (NOBYPASSRLS)';
    ELSE
        -- Ensure NOBYPASSRLS even if user already exists
        ALTER ROLE auditgraph_app NOBYPASSRLS;
        ALTER ROLE auditgraph_app WITH PASSWORD 'AuditGr@ph2026!app';
        RAISE NOTICE 'Updated role auditgraph_app (NOBYPASSRLS enforced)';
    END IF;
END $$;

-- Grant full access to public schema objects
GRANT USAGE ON SCHEMA public TO auditgraph_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auditgraph_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auditgraph_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO auditgraph_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO auditgraph_app;


-- ============================================================
-- PART B: Backfill remaining NULL tenant_ids
-- Assign all NULL rows to tenant 1 (NexgenixLabs — the original/first tenant).
-- These are legacy rows created before proper tenant scoping.
-- ============================================================

DO $$
DECLARE
    v_default_tenant INTEGER;
    tbl TEXT;
    cnt BIGINT;
BEGIN
    SELECT id INTO v_default_tenant FROM tenants ORDER BY id ASC LIMIT 1;
    IF v_default_tenant IS NULL THEN
        RAISE EXCEPTION 'No tenants found — cannot backfill';
    END IF;

    FOR tbl IN SELECT unnest(ARRAY[
        'access_review_campaigns', 'activity_log', 'anomalies', 'api_keys',
        'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
        'ca_identity_coverage', 'ca_policies', 'campaign_audit_log', 'campaign_reviews',
        'compliance_snapshots', 'copilot_conversations', 'credentials',
        'custom_risk_rules', 'dashboard_preferences', 'discovery_runs', 'drift_reports',
        'entra_role_assignments', 'governance_decisions', 'graph_api_permissions',
        'identities', 'identity_group_members', 'identity_groups', 'identity_roles',
        'identity_subscription_access', 'notifications', 'pim_activations',
        'pim_eligible_assignments', 'remediation_actions', 'role_activity_log',
        'role_assignments', 'sa_attestations', 'saved_views', 'settings',
        'soar_actions', 'soar_playbooks', 'sp_app_roles', 'sp_ownership',
        'sso_auth_codes', 'users', 'webhook_deliveries', 'webhooks'
    ]) LOOP
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = tbl AND column_name = 'tenant_id' AND table_schema = 'public') THEN
            EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id IS NULL', tbl) INTO cnt;
            IF cnt > 0 THEN
                EXECUTE format('UPDATE %I SET tenant_id = $1 WHERE tenant_id IS NULL', tbl) USING v_default_tenant;
                RAISE NOTICE 'Backfilled % NULL rows in %', cnt, tbl;
            END IF;
        END IF;
    END LOOP;
END $$;


-- ============================================================
-- PART C: Enforce NOT NULL on all tenant_id columns
-- (except cloud_subscriptions which is already NOT NULL)
-- ============================================================

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN SELECT unnest(ARRAY[
        'access_review_campaigns', 'activity_log', 'anomalies', 'api_keys',
        'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
        'ca_identity_coverage', 'ca_policies', 'campaign_audit_log', 'campaign_reviews',
        'compliance_snapshots', 'copilot_conversations', 'credentials',
        'custom_risk_rules', 'dashboard_preferences', 'discovery_runs', 'drift_reports',
        'entra_role_assignments', 'governance_decisions', 'graph_api_permissions',
        'identities', 'identity_group_members', 'identity_groups', 'identity_roles',
        'identity_subscription_access', 'notifications', 'pim_activations',
        'pim_eligible_assignments', 'remediation_actions', 'role_activity_log',
        'role_assignments', 'sa_attestations', 'saved_views', 'settings',
        'soar_actions', 'soar_playbooks', 'sp_app_roles', 'sp_ownership',
        'sso_auth_codes', 'users', 'webhook_deliveries', 'webhooks'
    ]) LOOP
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = tbl AND column_name = 'tenant_id'
                   AND is_nullable = 'YES' AND table_schema = 'public') THEN
            EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', tbl);
            RAISE NOTICE 'NOT NULL enforced on %', tbl;
        END IF;
    END LOOP;
END $$;


-- ============================================================
-- PART D: Replace ALL policies with STRICT versions
-- NO null-context bypass. If tenant_id is not set → zero rows.
-- This is the core security fix.
-- ============================================================

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN SELECT unnest(ARRAY[
        'access_review_campaigns', 'activity_log', 'anomalies', 'api_keys',
        'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
        'ca_identity_coverage', 'ca_policies', 'campaign_audit_log', 'campaign_reviews',
        'cloud_subscriptions', 'compliance_snapshots', 'copilot_conversations',
        'credentials', 'custom_risk_rules', 'dashboard_preferences', 'discovery_runs',
        'drift_reports', 'entra_role_assignments', 'governance_decisions',
        'graph_api_permissions', 'identities', 'identity_group_members',
        'identity_groups', 'identity_roles', 'identity_subscription_access',
        'notifications', 'pim_activations', 'pim_eligible_assignments',
        'remediation_actions', 'role_activity_log', 'role_assignments',
        'sa_attestations', 'saved_views', 'settings', 'soar_actions',
        'soar_playbooks', 'sp_app_roles', 'sp_ownership', 'sso_auth_codes',
        'users', 'webhook_deliveries', 'webhooks'
    ]) LOOP
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_name = tbl AND table_schema = 'public') THEN
            RAISE NOTICE 'Skipping % (not found)', tbl;
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = tbl AND column_name = 'tenant_id' AND table_schema = 'public') THEN
            RAISE NOTICE 'Skipping % (no tenant_id)', tbl;
            CONTINUE;
        END IF;

        -- Ensure RLS is on
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

        -- Drop old permissive policies
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_select ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_insert ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_update ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_delete ON %I', tbl);
        -- Also drop any legacy policy names
        EXECUTE format('DROP POLICY IF EXISTS rls_sel ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS rls_ins ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS rls_upd ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS rls_del ON %I', tbl);

        -- Create STRICT policies — NO null bypass
        EXECUTE format(
            'CREATE POLICY tenant_strict_sel ON %I FOR SELECT USING (
                tenant_id = current_setting(''app.current_tenant_id'', true)::integer
            )', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_strict_ins ON %I FOR INSERT WITH CHECK (
                tenant_id = current_setting(''app.current_tenant_id'', true)::integer
            )', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_strict_upd ON %I FOR UPDATE USING (
                tenant_id = current_setting(''app.current_tenant_id'', true)::integer
            )', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_strict_del ON %I FOR DELETE USING (
                tenant_id = current_setting(''app.current_tenant_id'', true)::integer
            )', tbl);

        RAISE NOTICE 'Strict RLS policies on %', tbl;
    END LOOP;
END $$;


-- ============================================================
-- PART E: Auto-fill trigger — safety net for INSERTs
-- If code forgets tenant_id, trigger fills from session variable.
-- If both are NULL, INSERT is rejected.
-- ============================================================

CREATE OR REPLACE FUNCTION auto_set_tenant_id()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.tenant_id IS NULL THEN
        BEGIN
            NEW.tenant_id := current_setting('app.current_tenant_id', true)::integer;
        EXCEPTION WHEN OTHERS THEN
            NULL;
        END;
    END IF;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'tenant_id is required — no tenant context set and no tenant_id provided (table: %)', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN SELECT unnest(ARRAY[
        'access_review_campaigns', 'activity_log', 'anomalies', 'api_keys',
        'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
        'ca_identity_coverage', 'ca_policies', 'campaign_audit_log', 'campaign_reviews',
        'cloud_subscriptions', 'compliance_snapshots', 'copilot_conversations',
        'credentials', 'custom_risk_rules', 'dashboard_preferences', 'discovery_runs',
        'drift_reports', 'entra_role_assignments', 'governance_decisions',
        'graph_api_permissions', 'identities', 'identity_group_members',
        'identity_groups', 'identity_roles', 'identity_subscription_access',
        'notifications', 'pim_activations', 'pim_eligible_assignments',
        'remediation_actions', 'role_activity_log', 'role_assignments',
        'sa_attestations', 'saved_views', 'settings', 'soar_actions',
        'soar_playbooks', 'sp_app_roles', 'sp_ownership', 'sso_auth_codes',
        'users', 'webhook_deliveries', 'webhooks'
    ]) LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables
                   WHERE table_name = tbl AND table_schema = 'public')
        AND EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name = tbl AND column_name = 'tenant_id' AND table_schema = 'public') THEN
            EXECUTE format('DROP TRIGGER IF EXISTS trg_auto_tenant_id ON %I', tbl);
            EXECUTE format(
                'CREATE TRIGGER trg_auto_tenant_id BEFORE INSERT ON %I
                 FOR EACH ROW EXECUTE FUNCTION auto_set_tenant_id()', tbl);
            RAISE NOTICE 'Auto-fill trigger on %', tbl;
        END IF;
    END LOOP;
END $$;


-- ============================================================
-- PART F: Verify
-- ============================================================

-- Check no NULL tenant_ids remain
DO $$
DECLARE
    tbl TEXT;
    cnt BIGINT;
    has_nulls BOOLEAN := FALSE;
BEGIN
    FOR tbl IN SELECT unnest(ARRAY[
        'access_review_campaigns', 'activity_log', 'anomalies', 'api_keys',
        'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
        'ca_identity_coverage', 'ca_policies', 'campaign_audit_log', 'campaign_reviews',
        'compliance_snapshots', 'copilot_conversations', 'credentials',
        'custom_risk_rules', 'dashboard_preferences', 'discovery_runs', 'drift_reports',
        'entra_role_assignments', 'governance_decisions', 'graph_api_permissions',
        'identities', 'identity_group_members', 'identity_groups', 'identity_roles',
        'identity_subscription_access', 'notifications', 'pim_activations',
        'pim_eligible_assignments', 'remediation_actions', 'role_activity_log',
        'role_assignments', 'sa_attestations', 'saved_views', 'settings',
        'soar_actions', 'soar_playbooks', 'sp_app_roles', 'sp_ownership',
        'sso_auth_codes', 'users', 'webhook_deliveries', 'webhooks'
    ]) LOOP
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = tbl AND column_name = 'tenant_id' AND table_schema = 'public') THEN
            EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id IS NULL', tbl) INTO cnt;
            IF cnt > 0 THEN
                RAISE WARNING 'STILL NULL: % has % rows', tbl, cnt;
                has_nulls := TRUE;
            END IF;
        END IF;
    END LOOP;
    IF NOT has_nulls THEN
        RAISE NOTICE 'All tenant_id columns are fully populated';
    END IF;
END $$;

-- Show final RLS status
SELECT c.relname AS tablename,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY c.relname;

-- Show new policies
SELECT tablename, policyname, cmd
FROM pg_policies
WHERE policyname LIKE 'tenant_strict_%'
ORDER BY tablename, cmd;

COMMIT;
