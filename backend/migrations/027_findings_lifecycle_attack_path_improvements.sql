-- 027_findings_lifecycle_attack_path_improvements.sql
-- Adds fingerprint and lifecycle tracking to security_findings table,
-- plus last_seen_run_id and affected_resource_count to attack_paths.
-- Idempotent — safe to run multiple times.

-- ──────────────────────────────────────────────────────────────────────
-- 1. security_findings: fingerprint + lifecycle columns
-- ──────────────────────────────────────────────────────────────────────

ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS finding_fingerprint TEXT;
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;

-- Index on fingerprint for fast lookups
CREATE INDEX IF NOT EXISTS idx_sf_fingerprint ON security_findings(finding_fingerprint);

-- Unique partial index for fingerprint-based UPSERT (org-scoped)
CREATE UNIQUE INDEX IF NOT EXISTS idx_sf_org_fingerprint
    ON security_findings(organization_id, finding_fingerprint)
    WHERE finding_fingerprint IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────
-- 2. attack_paths: last_seen_run_id + affected_resource_count
-- ──────────────────────────────────────────────────────────────────────

ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS last_seen_run_id INTEGER;
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS affected_resource_count INTEGER NOT NULL DEFAULT 0;
