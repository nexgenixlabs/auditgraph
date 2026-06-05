-- AG-86: Approved Apps Registry + Shadow App detection
-- Per-org allowlist of sanctioned applications. Any App Registration / SPN
-- not in this list and matching shadow signatures (unverified, AI-name,
-- high-scope, new) is flagged "Shadow App" by the detection engine.

BEGIN;

CREATE TABLE IF NOT EXISTS approved_apps (
    id               SERIAL PRIMARY KEY,
    organization_id  INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    app_id           VARCHAR(64),                -- Microsoft appId / clientId
    display_name     VARCHAR(255),
    publisher_name   VARCHAR(255),
    app_category     VARCHAR(64) DEFAULT 'general',  -- ai, productivity, dev_tools, security, general, other
    match_kind       VARCHAR(16) NOT NULL DEFAULT 'app_id',  -- app_id | publisher | display_name_prefix
    notes            TEXT,
    -- added_by_user_id intentionally NOT a FK — users.id has no
    -- referenceable PK constraint in this schema (re-added on prod elsewhere).
    added_by_user_id INTEGER,
    is_seeded        BOOLEAN DEFAULT FALSE,      -- TRUE for default-seeded entries
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT approved_apps_match_check CHECK (
        (match_kind = 'app_id' AND app_id IS NOT NULL) OR
        (match_kind = 'publisher' AND publisher_name IS NOT NULL) OR
        (match_kind = 'display_name_prefix' AND display_name IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_approved_apps_org ON approved_apps(organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_approved_apps_org_appid
    ON approved_apps(organization_id, app_id)
    WHERE app_id IS NOT NULL;

-- AG-86: Cached per-identity shadow verdict so the inventory list doesn't
-- pay for the full evaluation on every request. Refreshed by discovery.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS is_shadow_app BOOLEAN DEFAULT FALSE;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS shadow_reasons JSONB;

CREATE INDEX IF NOT EXISTS idx_identities_shadow
    ON identities(organization_id, is_shadow_app)
    WHERE is_shadow_app = TRUE;

COMMIT;
