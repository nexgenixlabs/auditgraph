-- 118_restore_id_sequences.sql
--
-- AG-DBFIX (continuation of 116/117): migration 117 restored PRIMARY KEYs
-- on ~80 tables, but a subset have `id BIGINT NOT NULL` with NO sequence
-- default — so INSERTs without explicit id values still fail with
-- "null value in column 'id' violates not-null constraint" (verified
-- against role_attack_patterns when running seed_verified_attacks.py).
--
-- This migration creates the missing sequences and binds them as defaults.
-- All ALTERs are idempotent. No rows touched.
--
-- Seven affected tables (the eighth — plans — has id VARCHAR storing
-- 'free'/'trial'/'pro' enum keys, not an auto-increment, so it's
-- excluded):
--   role_activity_log, role_attack_patterns, role_hipaa_mappings,
--   role_permissions, workload_activity_stats, workload_anomaly_events,
--   workload_signin_events.

BEGIN;

DO $$
DECLARE
  tbl text;
  seq text;
BEGIN
  FOR tbl IN SELECT unnest(ARRAY[
    'role_activity_log', 'role_attack_patterns',
    'role_hipaa_mappings', 'role_permissions',
    'workload_activity_stats', 'workload_anomaly_events',
    'workload_signin_events'
  ])
  LOOP
    seq := tbl || '_id_seq';
    EXECUTE format('CREATE SEQUENCE IF NOT EXISTS %I AS BIGINT OWNED BY %I.id', seq, tbl);
    EXECUTE format(
      'SELECT setval(%L, COALESCE((SELECT MAX(id)::bigint FROM %I), 0::bigint) + 1, false)',
      seq, tbl
    );
    EXECUTE format(
      'ALTER TABLE %I ALTER COLUMN id SET DEFAULT nextval(%L)',
      tbl, seq
    );
  END LOOP;
END$$;

COMMIT;
