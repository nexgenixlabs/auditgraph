-- AG-PROD-HARDENING #2: Foreign keys on the new tables that reference
-- identities(id). Prod-readiness audit flagged these as missing FKs.
--
-- Tables affected:
--   agent_invocations.source_identity_db_id
--   agent_invocations.target_identity_db_id
--   threat_signals.identity_db_id
--   ai_supply_chain_links.source_identity_db_id
--
-- ON DELETE CASCADE on source_identity_db_id / target_identity_db_id so
-- removing an identity cleans up its edges and signals automatically.
-- (Same pattern as the existing role_assignments → identities FK.)
--
-- Idempotent: each ALTER is wrapped in IF NOT EXISTS via DO block.

\set ON_ERROR_STOP on

BEGIN;

-- agent_invocations.source / target
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'agent_invocations_source_fk') THEN
        ALTER TABLE agent_invocations
            ADD CONSTRAINT agent_invocations_source_fk
            FOREIGN KEY (source_identity_db_id) REFERENCES identities(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'agent_invocations_target_fk') THEN
        ALTER TABLE agent_invocations
            ADD CONSTRAINT agent_invocations_target_fk
            FOREIGN KEY (target_identity_db_id) REFERENCES identities(id) ON DELETE CASCADE;
    END IF;
END $$;

-- threat_signals.identity_db_id (nullable — signal may pre-date discovery)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'threat_signals_identity_fk') THEN
        ALTER TABLE threat_signals
            ADD CONSTRAINT threat_signals_identity_fk
            FOREIGN KEY (identity_db_id) REFERENCES identities(id) ON DELETE SET NULL;
    END IF;
END $$;

-- ai_supply_chain_links.source_identity_db_id (nullable — could be component-source)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'ai_supply_chain_links_source_identity_fk') THEN
        ALTER TABLE ai_supply_chain_links
            ADD CONSTRAINT ai_supply_chain_links_source_identity_fk
            FOREIGN KEY (source_identity_db_id) REFERENCES identities(id) ON DELETE CASCADE;
    END IF;
END $$;

COMMIT;

\echo ''
\echo '=== Foreign keys after migration ==='
SELECT conrelid::regclass AS table_name, conname AS constraint_name,
       pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE conrelid::regclass::text IN
        ('agent_invocations','threat_signals','ai_supply_chain_links')
  AND contype = 'f'
ORDER BY conrelid::regclass::text, conname;
