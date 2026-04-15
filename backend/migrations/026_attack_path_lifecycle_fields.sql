-- 026_attack_path_lifecycle_fields.sql
-- Adds fingerprint and lifecycle tracking to attack_paths table.
-- Idempotent — safe to run multiple times.

-- 1. Fingerprint column for deterministic cross-snapshot deduplication
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS path_fingerprint TEXT;

-- 2. Lifecycle tracking fields
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;

-- 3. Index on fingerprint for fast lookups
CREATE INDEX IF NOT EXISTS idx_ap_fingerprint ON attack_paths(path_fingerprint);

-- 4. Unique partial index for fingerprint-based UPSERT (org-scoped)
CREATE UNIQUE INDEX IF NOT EXISTS idx_ap_org_fingerprint
    ON attack_paths(organization_id, path_fingerprint)
    WHERE path_fingerprint IS NOT NULL;
