-- Migration 091: Enable RLS on ALL tables with organization_id
--
-- Idempotent — safe to re-run on any environment.
--
-- For every public table that has an organization_id column:
--   1. ENABLE + FORCE ROW LEVEL SECURITY
--   2. Create org_strict_sel/ins/upd/del policies (skipped if they already exist)
--
-- Policy pattern (strict — no null bypass):
--   organization_id = current_setting('app.current_organization_id', true)::integer
--
-- Covers 104 org-scoped tables including users (auth uses admin bypass).
-- Tables with custom-named policies (e.g. agent_cls_sel, ap_org_sel) are left
-- as-is; only the standard org_strict_* set is created where missing.

BEGIN;

DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOR tbl IN
    SELECT t.tablename
    FROM pg_tables t
    WHERE t.schemaname = 'public'
      AND EXISTS (
        SELECT 1
        FROM information_schema.columns c
        WHERE c.table_name = t.tablename
          AND c.column_name = 'organization_id'
          AND c.table_schema = 'public'
      )
    ORDER BY t.tablename
  LOOP
    BEGIN
      -- Enable RLS (idempotent — no-op if already enabled)
      EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
      EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

      -- Create standard policies only if they don't already exist
      IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = tbl
          AND policyname = 'org_strict_sel'
      ) THEN
        EXECUTE format(
          'CREATE POLICY org_strict_sel ON %I FOR SELECT USING (
            organization_id = current_setting(''app.current_organization_id'', true)::integer
          )', tbl);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = tbl
          AND policyname = 'org_strict_ins'
      ) THEN
        EXECUTE format(
          'CREATE POLICY org_strict_ins ON %I FOR INSERT WITH CHECK (
            organization_id = current_setting(''app.current_organization_id'', true)::integer
          )', tbl);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = tbl
          AND policyname = 'org_strict_upd'
      ) THEN
        EXECUTE format(
          'CREATE POLICY org_strict_upd ON %I FOR UPDATE USING (
            organization_id = current_setting(''app.current_organization_id'', true)::integer
          )', tbl);
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = tbl
          AND policyname = 'org_strict_del'
      ) THEN
        EXECUTE format(
          'CREATE POLICY org_strict_del ON %I FOR DELETE USING (
            organization_id = current_setting(''app.current_organization_id'', true)::integer
          )', tbl);
      END IF;

      RAISE NOTICE 'RLS ensured: %', tbl;
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'Skipped %: %', tbl, SQLERRM;
    END;
  END LOOP;
END$$;

-- Verify: zero unprotected org tables
SELECT COUNT(*) as unprotected_org_tables
FROM pg_tables t
WHERE t.schemaname = 'public'
  AND t.rowsecurity = false
  AND EXISTS (
    SELECT 1 FROM information_schema.columns c
    WHERE c.table_name = t.tablename
      AND c.column_name = 'organization_id'
      AND c.table_schema = 'public'
  );
-- Expected: 0

COMMIT;
