-- AG-177 (Shared Infra): agent_classifications enrichment for AI Identity Attack Graph
--
-- Adds 3 columns so lifecycle drift can detect MODEL_CHANGED reliably,
-- scorecard can grade Ownership at-snapshot, attack_paths can label the
-- ai_agent node, and data_reachability has a stable per-agent model identity.
--
-- Idempotent. Honors migration 100 regression rule: explicit PK + sequence
-- on this table is set in 076_agent_classifications.sql; we only ADD COLUMN.

BEGIN;

ALTER TABLE agent_classifications
    ADD COLUMN IF NOT EXISTS model_name TEXT;

ALTER TABLE agent_classifications
    ADD COLUMN IF NOT EXISTS owner_display_name_at_classify TEXT;

ALTER TABLE agent_classifications
    ADD COLUMN IF NOT EXISTS account_resource_id TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_classifications_model
    ON agent_classifications(model_name)
    WHERE model_name IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_classifications_account
    ON agent_classifications(account_resource_id)
    WHERE account_resource_id IS NOT NULL;

COMMIT;
