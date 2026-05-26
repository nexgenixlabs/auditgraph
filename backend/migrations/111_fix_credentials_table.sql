-- Migration 111: Fix credentials table — missing sequence, PK, unique constraint, indexes
-- Root cause: table was created without BIGSERIAL (no sequence), no PRIMARY KEY, no UNIQUE
-- constraint on (identity_db_id, key_id).  ON CONFLICT in save_credential() silently fails.
-- Also fixes identity_subscription_access.id missing sequence.

-- ═══════════════════════════════════════════════════════════════════
-- 1. credentials table
-- ═══════════════════════════════════════════════════════════════════

-- 1a. Create the sequence and wire it to the id column
CREATE SEQUENCE IF NOT EXISTS credentials_id_seq;
SELECT setval('credentials_id_seq',
              COALESCE((SELECT MAX(id) FROM credentials), 0) + 1, false);
ALTER TABLE credentials ALTER COLUMN id SET DEFAULT nextval('credentials_id_seq');
ALTER SEQUENCE credentials_id_seq OWNED BY credentials.id;

-- 1b. Primary key (skip if already present)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'credentials_pkey' AND conrelid = 'credentials'::regclass
  ) THEN
    ALTER TABLE credentials ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);
  END IF;
END $$;

-- 1c. Unique constraint required by ON CONFLICT (identity_db_id, key_id)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'credentials_identity_db_id_key_id_key'
      AND conrelid = 'credentials'::regclass
  ) THEN
    ALTER TABLE credentials
      ADD CONSTRAINT credentials_identity_db_id_key_id_key
      UNIQUE (identity_db_id, key_id);
  END IF;
END $$;

-- 1d. Indexes (idempotent)
CREATE INDEX IF NOT EXISTS idx_credentials_identity_db_id ON credentials(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_credentials_end_datetime   ON credentials(end_datetime);
CREATE INDEX IF NOT EXISTS idx_credentials_type           ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_org            ON credentials(organization_id);

-- ═══════════════════════════════════════════════════════════════════
-- 2. identity_subscription_access.id — same missing-sequence pattern
-- ═══════════════════════════════════════════════════════════════════
CREATE SEQUENCE IF NOT EXISTS identity_subscription_access_id_seq;
SELECT setval('identity_subscription_access_id_seq',
              COALESCE((SELECT MAX(id) FROM identity_subscription_access), 0) + 1, false);
ALTER TABLE identity_subscription_access
  ALTER COLUMN id SET DEFAULT nextval('identity_subscription_access_id_seq');
ALTER SEQUENCE identity_subscription_access_id_seq
  OWNED BY identity_subscription_access.id;
