-- 007_create_sp_ownership.sql
-- Ownership tracking for service principals and applications
-- Tracks who is responsible for each non-human identity

CREATE TABLE IF NOT EXISTS sp_ownership (
    id BIGSERIAL PRIMARY KEY,
    identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

    -- Owner identity info
    owner_object_id TEXT NOT NULL,
    owner_display_name TEXT,
    owner_upn TEXT,                    -- User Principal Name (email)
    owner_type TEXT DEFAULT 'user',    -- user, servicePrincipal, group

    -- Ownership metadata
    ownership_type TEXT DEFAULT 'application',  -- application, servicePrincipal
    is_primary_owner BOOLEAN DEFAULT FALSE,

    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (identity_db_id, owner_object_id)
);

CREATE INDEX IF NOT EXISTS idx_sp_ownership_identity_db_id ON sp_ownership(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_sp_ownership_owner_object_id ON sp_ownership(owner_object_id);
CREATE INDEX IF NOT EXISTS idx_sp_ownership_owner_upn ON sp_ownership(owner_upn);

-- Add denormalized owner field to identities for quick access
ALTER TABLE identities ADD COLUMN IF NOT EXISTS owner_display_name TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS owner_count INTEGER DEFAULT 0;

COMMENT ON TABLE sp_ownership IS 'Tracks owners of service principals and applications';
COMMENT ON COLUMN sp_ownership.owner_type IS 'Type of owner: user, servicePrincipal, group';
COMMENT ON COLUMN sp_ownership.ownership_type IS 'What is owned: application or servicePrincipal';
COMMENT ON COLUMN sp_ownership.is_primary_owner IS 'First owner discovered, typically the creator';
