-- AG-75: Add access_paths JSONB column to identities table
-- Stores the canonical inclusion reason for each human/guest identity
ALTER TABLE identities ADD COLUMN IF NOT EXISTS access_paths JSONB DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_identities_access_paths ON identities USING GIN (access_paths);
