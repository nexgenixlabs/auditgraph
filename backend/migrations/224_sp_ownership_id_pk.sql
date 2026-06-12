-- 224_sp_ownership_id_pk.sql
-- 2026-06-12
--
-- Cloud sp_ownership.id has no SERIAL default + no PK + no sequence.
-- This is the well-documented migration 100 regression — that migration
-- file is missing PKs, UNIQUEs, and id sequence defaults on 40+ tables.
-- Memory note [[regression_migration_100_constraints]] tracks the
-- wider audit; graph_api_permissions + sp_app_roles were fixed in
-- migration 116. Adding sp_ownership to that list.
--
-- After migration 222 (uq index) cloud save_ownership stopped failing
-- on ON CONFLICT but immediately hit:
--   "null value in column 'id' of relation 'sp_ownership'
--    violates not-null constraint"
-- because the INSERT doesn't supply id and there's no DEFAULT.
--
-- Idempotent — uses IF NOT EXISTS / IF EXISTS guards.

-- 1) Ensure the sequence exists.
CREATE SEQUENCE IF NOT EXISTS sp_ownership_id_seq;

-- 2) Bind the sequence as the column DEFAULT.
ALTER TABLE sp_ownership
  ALTER COLUMN id SET DEFAULT nextval('sp_ownership_id_seq');

-- 3) Make the sequence "owned by" the column so dropping the column
--    drops the sequence too.
ALTER SEQUENCE sp_ownership_id_seq OWNED BY sp_ownership.id;

-- 4) Advance the sequence past any existing rows (safe even when 0 rows).
SELECT setval(
  'sp_ownership_id_seq',
  GREATEST(COALESCE((SELECT MAX(id) FROM sp_ownership), 0), 1),
  true
);

-- 5) Reassign ids on any rows that share a value with another row.
--    Cloud has duplicate ids from partial save_ownership inserts that
--    happened before migration 223 (those INSERTs collided on ON
--    CONFLICT before the unique index existed; psycopg2 retried with
--    fresh IDs but a few duplicates slipped through). Locally there
--    are no duplicates so the UPDATE rewrites zero rows.
WITH dup AS (
  SELECT ctid, id,
         ROW_NUMBER() OVER (PARTITION BY id ORDER BY ctid) AS rn
  FROM sp_ownership
)
UPDATE sp_ownership s
SET id = nextval('sp_ownership_id_seq')
FROM dup d
WHERE s.ctid = d.ctid AND d.rn > 1;

-- 6) Add primary key if missing.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'sp_ownership'::regclass AND contype = 'p'
  ) THEN
    ALTER TABLE sp_ownership ADD CONSTRAINT sp_ownership_pkey PRIMARY KEY (id);
  END IF;
END$$;
