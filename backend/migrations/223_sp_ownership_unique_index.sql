-- 223_sp_ownership_unique_index.sql
-- 2026-06-12
--
-- Cloud devpilot post-discovery had sp_ownership = 0 even after 3
-- discovery runs. Cloud logs revealed the same pattern as PIM (mig 222):
--
--   "save_ownership FAILED for <SP name>: there is no unique or
--    exclusion constraint matching the ON CONFLICT specification"
--
-- database.store_ownership() uses:
--   ON CONFLICT (identity_db_id, owner_object_id)
--
-- The runtime helper _ensure_nhi_columns() does try to CREATE this
-- index at first call but short-circuits when the connection is
-- tenant-scoped (NOBYPASSRLS) and caches the no-op flag for the
-- lifetime of the worker. Once discovery hits the code first as a
-- tenant connection, the index never gets created.
--
-- Ship the index as an explicit migration so discovery doesn't depend
-- on opportunistic runtime DDL.

CREATE UNIQUE INDEX IF NOT EXISTS uq_sp_ownership_identity_owner
  ON sp_ownership (identity_db_id, owner_object_id);
