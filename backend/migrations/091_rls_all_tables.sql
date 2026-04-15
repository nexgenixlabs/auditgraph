-- Migration 091: Enable RLS on all tables with organization_id
--
-- Two groups:
--   A) 46 tables already have org_strict_* policies but rowsecurity=false
--      → Just ENABLE + FORCE RLS
--   B) 52 tables have no policies at all
--      → CREATE org_strict_sel/ins/upd/del + ENABLE + FORCE RLS
--
-- Uses the same strict pattern already on 46+ tables:
--   organization_id = current_setting('app.current_organization_id', true)::integer
--
-- Excludes: users (global table, auth lookup needs cross-org access)

BEGIN;

DO $$
DECLARE
  tbl TEXT;
BEGIN
  FOR tbl IN
    SELECT t.tablename
    FROM pg_tables t
    WHERE t.schemaname = 'public'
      AND t.rowsecurity = false
      AND t.tablename != 'users'
      AND EXISTS (
        SELECT 1
        FROM information_schema.columns c
        WHERE c.table_name = t.tablename
          AND c.column_name = 'organization_id'
          AND c.table_schema = 'public'
      )
  LOOP
    BEGIN
      -- Enable RLS
      EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
      EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

      -- Create policies only if they don't exist (52 tables need these)
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

      RAISE NOTICE 'RLS enabled: %', tbl;
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'Skipped %: %', tbl, SQLERRM;
    END;
  END LOOP;
END$$;

-- Explicitly keep users table open (auth needs cross-org lookup)
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- Verify: count tables still unprotected
SELECT COUNT(*) as still_unprotected
FROM pg_tables t
WHERE t.schemaname = 'public'
  AND t.rowsecurity = false
  AND t.tablename != 'users'
  AND EXISTS (
    SELECT 1 FROM information_schema.columns c
    WHERE c.table_name = t.tablename
      AND c.column_name = 'organization_id'
      AND c.table_schema = 'public'
  );
-- Expected: 0

COMMIT;
