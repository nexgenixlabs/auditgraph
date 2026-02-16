-- ============================================================
-- AuditGraph: Row-Level Security (RLS) Migration
-- Adds tenant_id to all tenant-scoped tables, backfills from
-- parent tables, enables RLS with FORCE, and creates policies.
--
-- SAFE TO RUN MULTIPLE TIMES (idempotent).
-- tenant_id is INTEGER (tenants.id is SERIAL).
--
-- Policy pattern:
--   SELECT/UPDATE/DELETE: allow if no context set OR tenant matches
--   INSERT: allow if no context set OR tenant_id is NULL OR tenant matches
--   This ensures backward compatibility during the migration period.
-- ============================================================

BEGIN;

-- ============================================================
-- STEP 1: Add tenant_id column to all tables that need it
-- ============================================================

-- Core discovery tables (created by initial migrations)
ALTER TABLE identities ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE graph_api_permissions ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE sp_ownership ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE sp_app_roles ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE identity_roles ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE role_activity_log ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE pim_eligible_assignments ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE pim_activations ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE ca_policies ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE ca_identity_coverage ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE drift_reports ADD COLUMN IF NOT EXISTS tenant_id INTEGER;

-- Tables managed by _ensure methods (need tenant_id added)
ALTER TABLE compliance_snapshots ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE soar_playbooks ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE soar_actions ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE identity_groups ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE identity_group_members ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE saved_views ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE dashboard_preferences ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE identity_subscription_access ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE custom_risk_rules ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS tenant_id INTEGER;
ALTER TABLE campaign_audit_log ADD COLUMN IF NOT EXISTS tenant_id INTEGER;

-- ============================================================
-- STEP 2: Backfill tenant_id from parent tables
-- Order matters: parent tables first, then children.
-- ============================================================

-- 2A: Tables with run_id or discovery_run_id → JOIN to discovery_runs
UPDATE identities i SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE i.discovery_run_id = dr.id AND i.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE role_assignments ra SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE ra.run_id = dr.id AND ra.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE entra_role_assignments era SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE era.run_id = dr.id AND era.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE credentials c SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE c.run_id = dr.id AND c.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE graph_api_permissions gap SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE gap.run_id = dr.id AND gap.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE sp_ownership spo SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE spo.run_id = dr.id AND spo.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE sp_app_roles ara SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE ara.run_id = dr.id AND ara.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE identity_roles ir SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE ir.run_id = dr.id AND ir.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE role_activity_log ral SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE ral.run_id = dr.id AND ral.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE ca_policies cp SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE cp.run_id = dr.id AND cp.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE ca_identity_coverage cic SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE cic.run_id = dr.id AND cic.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE drift_reports drf SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE drf.current_run_id = dr.id AND drf.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE compliance_snapshots cs SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE cs.run_id = dr.id AND cs.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE anomalies a SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE a.discovery_run_id = dr.id AND a.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

UPDATE identity_subscription_access isa SET tenant_id = dr.tenant_id
FROM discovery_runs dr WHERE isa.discovery_run_id = dr.id AND isa.tenant_id IS NULL AND dr.tenant_id IS NOT NULL;

-- 2B: Tables with identity_db_id → JOIN to identities (now backfilled)
UPDATE pim_eligible_assignments pea SET tenant_id = i.tenant_id
FROM identities i WHERE pea.identity_db_id = i.id AND pea.tenant_id IS NULL AND i.tenant_id IS NOT NULL;

UPDATE pim_activations pa SET tenant_id = i.tenant_id
FROM identities i WHERE pa.identity_db_id = i.id AND pa.tenant_id IS NULL AND i.tenant_id IS NOT NULL;

-- 2C: Tables with user_id or created_by → JOIN to users
UPDATE soar_playbooks sp SET tenant_id = u.tenant_id
FROM users u WHERE sp.created_by = u.id AND sp.tenant_id IS NULL AND u.tenant_id IS NOT NULL;

UPDATE identity_groups ig SET tenant_id = u.tenant_id
FROM users u WHERE ig.created_by = u.id AND ig.tenant_id IS NULL AND u.tenant_id IS NOT NULL;

UPDATE saved_views sv SET tenant_id = u.tenant_id
FROM users u WHERE sv.user_id = u.id AND sv.tenant_id IS NULL AND u.tenant_id IS NOT NULL;

UPDATE dashboard_preferences dp SET tenant_id = u.tenant_id
FROM users u WHERE dp.user_id = u.id AND dp.tenant_id IS NULL AND u.tenant_id IS NOT NULL;

-- 2D: Tables joining to other backfilled tables
UPDATE soar_actions sa SET tenant_id = sp.tenant_id
FROM soar_playbooks sp WHERE sa.playbook_id = sp.id AND sa.tenant_id IS NULL AND sp.tenant_id IS NOT NULL;

UPDATE identity_group_members igm SET tenant_id = ig.tenant_id
FROM identity_groups ig WHERE igm.group_id = ig.id AND igm.tenant_id IS NULL AND ig.tenant_id IS NOT NULL;

UPDATE campaign_reviews cr SET tenant_id = arc.tenant_id
FROM access_review_campaigns arc WHERE cr.campaign_id = arc.id AND cr.tenant_id IS NULL AND arc.tenant_id IS NOT NULL;

UPDATE campaign_audit_log cal SET tenant_id = arc.tenant_id
FROM access_review_campaigns arc WHERE cal.campaign_id = arc.id AND cal.tenant_id IS NULL AND arc.tenant_id IS NOT NULL;

-- 2E: Tables with no direct FK — best-effort backfill
-- remediation_actions: match via identity_id text to identities
UPDATE remediation_actions rma SET tenant_id = i.tenant_id
FROM identities i WHERE rma.identity_id = i.identity_id AND rma.tenant_id IS NULL AND i.tenant_id IS NOT NULL;

-- webhooks/webhook_deliveries/custom_risk_rules: backfill with tenant 1 if single-tenant
-- (These tables had no tenant FK before; any existing data belongs to the first tenant)
DO $$
DECLARE
    v_count INT;
    v_tenant_id INT;
BEGIN
    SELECT COUNT(*) INTO v_count FROM tenants;
    IF v_count = 1 THEN
        SELECT id INTO v_tenant_id FROM tenants LIMIT 1;
        UPDATE webhooks SET tenant_id = v_tenant_id WHERE tenant_id IS NULL;
        UPDATE webhook_deliveries wd SET tenant_id = w.tenant_id
        FROM webhooks w WHERE wd.webhook_id = w.id AND wd.tenant_id IS NULL AND w.tenant_id IS NOT NULL;
        UPDATE custom_risk_rules SET tenant_id = v_tenant_id WHERE tenant_id IS NULL;
    ELSIF v_count > 1 THEN
        -- Multi-tenant: assign to first tenant (nexgenixlabs) as these are legacy rows
        SELECT id INTO v_tenant_id FROM tenants ORDER BY created_at ASC LIMIT 1;
        UPDATE webhooks SET tenant_id = v_tenant_id WHERE tenant_id IS NULL;
        UPDATE webhook_deliveries wd SET tenant_id = w.tenant_id
        FROM webhooks w WHERE wd.webhook_id = w.id AND wd.tenant_id IS NULL AND w.tenant_id IS NOT NULL;
        UPDATE custom_risk_rules SET tenant_id = v_tenant_id WHERE tenant_id IS NULL;
    END IF;
END $$;

-- ============================================================
-- STEP 3: Create indexes on tenant_id columns
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_identities_tenant ON identities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_tenant ON role_assignments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entra_role_assignments_tenant ON entra_role_assignments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant ON credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_graph_api_permissions_tenant ON graph_api_permissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sp_ownership_tenant ON sp_ownership(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sp_app_roles_tenant ON sp_app_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_identity_roles_tenant ON identity_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_activity_log_tenant ON role_activity_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pim_eligible_tenant ON pim_eligible_assignments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pim_activations_tenant ON pim_activations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ca_policies_tenant ON ca_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ca_identity_coverage_tenant ON ca_identity_coverage(tenant_id);
CREATE INDEX IF NOT EXISTS idx_drift_reports_tenant ON drift_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_compliance_snapshots_tenant ON compliance_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_tenant ON anomalies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_tenant ON soar_playbooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_soar_actions_tenant ON soar_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_identity_groups_tenant ON identity_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_identity_group_members_tenant ON identity_group_members(tenant_id);
CREATE INDEX IF NOT EXISTS idx_saved_views_tenant ON saved_views(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_preferences_tenant ON dashboard_preferences(tenant_id);
CREATE INDEX IF NOT EXISTS idx_isa_tenant ON identity_subscription_access(tenant_id);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_tenant ON remediation_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_custom_risk_rules_tenant ON custom_risk_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaign_reviews_tenant ON campaign_reviews(tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaign_audit_log_tenant ON campaign_audit_log(tenant_id);

-- ============================================================
-- STEP 4: Enable RLS + FORCE on ALL tenant-scoped tables
-- ============================================================

-- Helper macro: For each table we enable RLS, force it, and
-- create 4 policies. The SELECT/UPDATE/DELETE policy uses a
-- NULL-context bypass so superadmin/startup queries work.
-- The INSERT policy additionally allows NULL tenant_id
-- (legacy INSERTs that haven't been updated yet).

-- ── Tables that ALREADY had tenant_id ──

-- discovery_runs
ALTER TABLE discovery_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso_select ON discovery_runs;
DROP POLICY IF EXISTS tenant_iso_insert ON discovery_runs;
DROP POLICY IF EXISTS tenant_iso_update ON discovery_runs;
DROP POLICY IF EXISTS tenant_iso_delete ON discovery_runs;
CREATE POLICY tenant_iso_select ON discovery_runs FOR SELECT USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_insert ON discovery_runs FOR INSERT WITH CHECK (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_update ON discovery_runs FOR UPDATE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_delete ON discovery_runs FOR DELETE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);

-- settings
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso_select ON settings;
DROP POLICY IF EXISTS tenant_iso_insert ON settings;
DROP POLICY IF EXISTS tenant_iso_update ON settings;
DROP POLICY IF EXISTS tenant_iso_delete ON settings;
CREATE POLICY tenant_iso_select ON settings FOR SELECT USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_insert ON settings FOR INSERT WITH CHECK (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_update ON settings FOR UPDATE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_delete ON settings FOR DELETE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);

-- users
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso_select ON users;
DROP POLICY IF EXISTS tenant_iso_insert ON users;
DROP POLICY IF EXISTS tenant_iso_update ON users;
DROP POLICY IF EXISTS tenant_iso_delete ON users;
CREATE POLICY tenant_iso_select ON users FOR SELECT USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_insert ON users FOR INSERT WITH CHECK (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_update ON users FOR UPDATE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_delete ON users FOR DELETE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);

-- activity_log
ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso_select ON activity_log;
DROP POLICY IF EXISTS tenant_iso_insert ON activity_log;
DROP POLICY IF EXISTS tenant_iso_update ON activity_log;
DROP POLICY IF EXISTS tenant_iso_delete ON activity_log;
CREATE POLICY tenant_iso_select ON activity_log FOR SELECT USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_insert ON activity_log FOR INSERT WITH CHECK (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_update ON activity_log FOR UPDATE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);
CREATE POLICY tenant_iso_delete ON activity_log FOR DELETE USING (
    current_setting('app.current_tenant_id', TRUE) IS NULL
    OR tenant_id IS NULL
    OR tenant_id = current_setting('app.current_tenant_id', TRUE)::INTEGER);

-- ── Tables that got tenant_id added in this migration ──
-- Using a DO block to generate policies for all remaining tables

DO $$
DECLARE
    tbl TEXT;
BEGIN
    -- All tenant-scoped tables (both pre-existing and newly added tenant_id)
    FOR tbl IN
        SELECT unnest(ARRAY[
            'identities', 'role_assignments', 'entra_role_assignments',
            'credentials', 'graph_api_permissions', 'sp_ownership',
            'sp_app_roles', 'identity_roles', 'role_activity_log',
            'pim_eligible_assignments', 'pim_activations',
            'ca_policies', 'ca_identity_coverage',
            'drift_reports', 'compliance_snapshots', 'anomalies',
            'soar_playbooks', 'soar_actions',
            'identity_groups', 'identity_group_members',
            'saved_views', 'dashboard_preferences',
            'identity_subscription_access', 'remediation_actions',
            'webhooks', 'webhook_deliveries', 'custom_risk_rules',
            'campaign_reviews', 'campaign_audit_log',
            'notifications', 'api_keys',
            'azure_storage_accounts', 'azure_key_vaults',
            'app_registrations', 'access_review_campaigns',
            'sa_attestations', 'governance_decisions',
            'copilot_conversations', 'cloud_subscriptions',
            'sso_auth_codes'
        ])
    LOOP
        -- Skip if table doesn't exist
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            RAISE NOTICE 'Skipping % (table does not exist)', tbl;
            CONTINUE;
        END IF;

        -- Enable RLS
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

        -- Drop existing policies
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_select ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_insert ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_update ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS tenant_iso_delete ON %I', tbl);

        -- Create policies with NULL-context bypass
        EXECUTE format(
            'CREATE POLICY tenant_iso_select ON %I FOR SELECT USING (
                current_setting(''app.current_tenant_id'', TRUE) IS NULL
                OR tenant_id IS NULL
                OR tenant_id = current_setting(''app.current_tenant_id'', TRUE)::INTEGER)', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_iso_insert ON %I FOR INSERT WITH CHECK (
                current_setting(''app.current_tenant_id'', TRUE) IS NULL
                OR tenant_id IS NULL
                OR tenant_id = current_setting(''app.current_tenant_id'', TRUE)::INTEGER)', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_iso_update ON %I FOR UPDATE USING (
                current_setting(''app.current_tenant_id'', TRUE) IS NULL
                OR tenant_id IS NULL
                OR tenant_id = current_setting(''app.current_tenant_id'', TRUE)::INTEGER)', tbl);
        EXECUTE format(
            'CREATE POLICY tenant_iso_delete ON %I FOR DELETE USING (
                current_setting(''app.current_tenant_id'', TRUE) IS NULL
                OR tenant_id IS NULL
                OR tenant_id = current_setting(''app.current_tenant_id'', TRUE)::INTEGER)', tbl);

        RAISE NOTICE 'RLS enabled on %', tbl;
    END LOOP;
END $$;

-- ============================================================
-- STEP 5: Verify RLS status
-- ============================================================

SELECT tablename, rowsecurity, forcerowsecurity
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;

COMMIT;
