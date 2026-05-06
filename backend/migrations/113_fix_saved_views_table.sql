-- Migration 113: Ensure saved_views table schema is complete.
-- Moves DDL out of _ensure_saved_views_table() (same pattern as migration 112
-- for SOAR tables).  All statements are idempotent.

CREATE TABLE IF NOT EXISTS saved_views (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    filters JSONB NOT NULL DEFAULT '{}',
    sort_field VARCHAR(50),
    sort_direction VARCHAR(10) DEFAULT 'desc',
    is_default BOOLEAN DEFAULT false,
    is_shared BOOLEAN DEFAULT false,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    organization_id INTEGER
);

CREATE INDEX IF NOT EXISTS idx_saved_views_user ON saved_views(user_id);
CREATE INDEX IF NOT EXISTS idx_saved_views_org ON saved_views(organization_id);
CREATE INDEX IF NOT EXISTS idx_saved_views_org_user ON saved_views(organization_id, user_id);
