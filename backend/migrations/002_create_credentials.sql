-- 002_create_credentials.sql

-- Add identity credential summary columns (used by database.py)
ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS credential_count INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS next_expiry TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS credential_risk TEXT; -- expired, expiring_soon, healthy, unknown

CREATE INDEX IF NOT EXISTS idx_identities_next_expiry ON identities(next_expiry);
CREATE INDEX IF NOT EXISTS idx_identities_credential_risk ON identities(credential_risk);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
  id BIGSERIAL PRIMARY KEY,
  identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

  credential_type TEXT NOT NULL, -- secret | certificate | federated
  key_id TEXT NOT NULL,
  display_name TEXT,

  start_datetime TIMESTAMPTZ,
  end_datetime TIMESTAMPTZ,

  thumbprint TEXT,
  issuer TEXT,
  subject TEXT,

  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (identity_db_id, key_id)
);

CREATE INDEX IF NOT EXISTS idx_credentials_identity_db_id ON credentials(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_credentials_end_datetime ON credentials(end_datetime);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
