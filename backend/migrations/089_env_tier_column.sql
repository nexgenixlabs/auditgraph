-- Migration 089: Add env_tier column to identity_list and identity_list_snapshots
--
-- Environment tier classification for identities:
--   platform   — Microsoft 1P service principals
--   production — identities scoped to production resources
--   dev        — lab/test/sandbox identities
--   ci_cd      — CI/CD pipeline identities (GitHub OIDC, etc.)
--   corporate  — human users, guest users
--   unknown    — unclassified (inference engine not yet run)

BEGIN;

ALTER TABLE identity_list
    ADD COLUMN IF NOT EXISTS env_tier VARCHAR(32) NOT NULL DEFAULT 'unknown';

ALTER TABLE identity_list_snapshots
    ADD COLUMN IF NOT EXISTS env_tier VARCHAR(32) NOT NULL DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS ix_identity_list_env_tier
    ON identity_list (organization_id, env_tier);

COMMIT;
