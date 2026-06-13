-- 222_pim_eligible_unique_index.sql
-- 2026-06-12
--
-- Cloud discovery run #49 enumerated 145 PIM eligible assignments
-- correctly from Microsoft Graph, but every save_pim FAILED with:
--   "there is no unique or exclusion constraint matching the
--    ON CONFLICT specification"
--
-- database.save_pim_eligible() does:
--   ON CONFLICT (identity_db_id, role_definition_id, directory_scope)
--
-- That requires uq_pim_eligible_identity_role_scope to exist. Migration
-- 221 added the organization_id column but not this index. The runtime
-- helper _ensure_pim_constraints() does try to create it on the first
-- INSERT, but it short-circuits when the connection is tenant-scoped
-- (NOBYPASSRLS app user can't DDL) and sets a class-level "ensured"
-- flag for the lifetime of the worker process — so once discovery
-- (which runs as tenant-scoped) hits this code first, no admin
-- connection will ever retry the DDL.
--
-- Fix: ship the index as a real migration. Adds it explicitly so
-- discovery never depends on opportunistic runtime DDL.

CREATE UNIQUE INDEX IF NOT EXISTS uq_pim_eligible_identity_role_scope
  ON pim_eligible_assignments
    (identity_db_id, role_definition_id, directory_scope);
