-- =============================================================================
-- AuditGraph DEV Database — Role Setup Script
-- =============================================================================
-- Target: cus-ag-nonprod-pg.postgres.database.azure.com
-- Database: auditgraph_dev  (created by Terraform; supersedes legacy auditgraph_dev_eastus2)
--
-- Run this ONCE as the server admin (auditgraph_dev_eastus2) before deploying
-- the container. The app will NOT start without both roles.
--
-- Connection (substitute <SERVER_ADMIN_PWD> at run time, do not commit):
--   psql "postgresql://auditgraph_dev_eastus2:<SERVER_ADMIN_PWD>@cus-ag-nonprod-pg.postgres.database.azure.com:5432/auditgraph_dev?sslmode=require"
-- =============================================================================

-- ─── Step 1: Create Admin Role (BYPASSRLS) ──────────────────────────────────
-- Used for: DDL, schema migrations, scheduler jobs, startup health checks
-- The app connects as this user during the 13-step startup sequence.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditgraph_dev_admin') THEN
    CREATE ROLE auditgraph_dev_admin
      WITH LOGIN PASSWORD 'Aud1tGr@phDevAdm1n2026' BYPASSRLS;
    RAISE NOTICE 'Created role: auditgraph_dev_admin (BYPASSRLS)';
  ELSE
    RAISE NOTICE 'Role auditgraph_dev_admin already exists — skipping';
  END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE auditgraph_dev
  TO auditgraph_dev_admin;

GRANT ALL ON SCHEMA public
  TO auditgraph_dev_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO auditgraph_dev_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO auditgraph_dev_admin;

-- ─── Step 2: Create App Role (NOBYPASSRLS) ──────────────────────────────────
-- Used for: All HTTP API requests at runtime (tenant-scoped via RLS)
-- This user can ONLY see data for the tenant set in app.current_organization_id.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditgraph_dev_app') THEN
    CREATE ROLE auditgraph_dev_app
      WITH LOGIN PASSWORD 'Aud1tGr@phDevApp2026' NOBYPASSRLS;
    RAISE NOTICE 'Created role: auditgraph_dev_app (NOBYPASSRLS)';
  ELSE
    RAISE NOTICE 'Role auditgraph_dev_app already exists — skipping';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO auditgraph_dev_app;

-- Note: Table-level grants (SELECT/INSERT/UPDATE/DELETE) are applied
-- automatically by the app at startup Step 11 (Bulk GRANT).
-- Do NOT manually grant table permissions here.

-- ─── Step 2b: Legacy role aliases ───────────────────────────────────────────
-- Backend code has hardcoded "auditgraph_app" / "auditgraph_admin" in some
-- GRANT statements (e.g. database.py:11210 entitlements). Create them as
-- NOLOGIN group roles and grant membership so the real users inherit privs.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditgraph_app') THEN
    CREATE ROLE auditgraph_app NOLOGIN;
    RAISE NOTICE 'Created legacy alias role: auditgraph_app (NOLOGIN)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditgraph_admin') THEN
    CREATE ROLE auditgraph_admin NOLOGIN;
    RAISE NOTICE 'Created legacy alias role: auditgraph_admin (NOLOGIN)';
  END IF;
END
$$;

GRANT auditgraph_app   TO auditgraph_dev_app;
GRANT auditgraph_admin TO auditgraph_dev_admin;

-- ─── Step 3: Verify ─────────────────────────────────────────────────────────
-- Both roles must show correct BYPASSRLS flags.

SELECT rolname, rolbypassrls
FROM pg_roles
WHERE rolname LIKE 'auditgraph_dev_%';

-- Expected output:
--  rolname                  | rolbypassrls
-- --------------------------+--------------
--  auditgraph_dev_admin     | t
--  auditgraph_dev_app       | f
-- (server admin auditgraph_dev_eastus2 is filtered out by the LIKE pattern)

-- ─── Done ────────────────────────────────────────────────────────────────────
-- After verifying both roles, deploy the container.
-- The app will auto-create all 94 tables, enforce RLS, seed tenants.
