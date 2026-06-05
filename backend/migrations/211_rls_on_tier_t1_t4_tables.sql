-- AG-PROD-HARDENING #1: Enable strict RLS on the 7 new tier 1-4 tables.
--
-- Per CLAUDE.md: "strict RLS on all 44 tables. tenant_strict_sel/ins/upd/del
-- — NO null-context bypass. tenant_id = current_setting('app.current_tenant_id', true)::integer"
--
-- Internal pentest F-003 + prod readiness audit identified these tables
-- as having NO RLS, meaning tenant isolation depends purely on app-code
-- WHERE clauses. This migration adds defense-in-depth.
--
-- Pattern: we set BOTH app.current_organization_id and app.current_tenant_id
-- equal at runtime (see backend/app/database.py), so the policy can use
-- either. We use organization_id for consistency with the recently-added
-- tables in cloud_align_rls_tenant_to_org.sql (082b984).
--
-- Idempotent: ENABLE RLS + CREATE POLICY are wrapped in DO blocks that
-- catch "already exists" cleanly.

\set ON_ERROR_STOP on

BEGIN;

-- Helper: install strict tenant policies on a table that has org_id column
CREATE OR REPLACE FUNCTION _install_tenant_strict_rls(target_table TEXT) RETURNS VOID AS $$
DECLARE
    pol TEXT;
    op  TEXT;
    using_clause TEXT := 'organization_id = (current_setting(''app.current_organization_id'', true))::integer';
BEGIN
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', target_table);

    -- Drop any pre-existing policy of these names so the re-create is clean
    FOREACH pol IN ARRAY ARRAY['tenant_strict_sel','tenant_strict_ins','tenant_strict_upd','tenant_strict_del'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', pol, target_table);
    END LOOP;

    EXECUTE format(
        'CREATE POLICY tenant_strict_sel ON %I FOR SELECT USING (%s)',
        target_table, using_clause);
    EXECUTE format(
        'CREATE POLICY tenant_strict_ins ON %I FOR INSERT WITH CHECK (%s)',
        target_table, using_clause);
    EXECUTE format(
        'CREATE POLICY tenant_strict_upd ON %I FOR UPDATE USING (%s) WITH CHECK (%s)',
        target_table, using_clause, using_clause);
    EXECUTE format(
        'CREATE POLICY tenant_strict_del ON %I FOR DELETE USING (%s)',
        target_table, using_clause);
END $$ LANGUAGE plpgsql;

-- breach_cost_factors is ORG-AGNOSTIC reference data (no organization_id
-- column). Industry-standard cost factors are not tenant-specific; public
-- read is intentional. Writes are admin-only via Postgres role grants.
-- (Intentionally NOT in the strict-RLS list below.)

-- Tables added in tiers 2-4 that need strict tenant RLS
SELECT _install_tenant_strict_rls('ai_model_approvals');          -- 206
SELECT _install_tenant_strict_rls('agent_invocations');           -- 208
SELECT _install_tenant_strict_rls('ai_supply_chain_components');  -- 209
SELECT _install_tenant_strict_rls('ai_supply_chain_links');       -- 209
SELECT _install_tenant_strict_rls('threat_signals');              -- 210
SELECT _install_tenant_strict_rls('threat_connectors');           -- 210

DROP FUNCTION _install_tenant_strict_rls(TEXT);

COMMIT;

\echo ''
\echo '=== RLS status after migration ==='
SELECT tablename,
       CASE WHEN relrowsecurity THEN 'enabled' ELSE 'DISABLED' END AS rls,
       (SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename = t.tablename) AS policy_count
FROM pg_tables t JOIN pg_class c ON c.relname = t.tablename
WHERE t.schemaname='public'
  AND t.tablename IN ('ai_model_approvals',
                       'agent_invocations','ai_supply_chain_components',
                       'ai_supply_chain_links','threat_signals','threat_connectors')
ORDER BY tablename;
