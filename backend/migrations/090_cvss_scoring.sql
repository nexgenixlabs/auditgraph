-- Migration 090: CVSS-aligned 5-dimension identity scoring
--
-- Adds per-identity scoring columns to identity_list:
--   severity_score     — final score (0.0–10.0), max(5 dims) * env_multiplier
--   cvss_band          — CRITICAL / HIGH / MEDIUM / LOW / INFO
--   blast_radius_score — dimension 1: scope of compromise impact
--   privilege_score    — dimension 2: least privilege violation
--   dormancy_score     — dimension 3: authentication currency
--   governance_score   — dimension 4: account governance gaps
--   credential_score   — dimension 5: credential hygiene
--   env_multiplier     — environment context amplifier
--   score_computed_at  — timestamp of last scoring run

BEGIN;

-- ── identity_list columns ────────────────────────────────────────────
ALTER TABLE identity_list
    ADD COLUMN IF NOT EXISTS severity_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS cvss_band         VARCHAR(10) NOT NULL DEFAULT 'INFO',
    ADD COLUMN IF NOT EXISTS blast_radius_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS privilege_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS dormancy_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS governance_score  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS credential_score  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS env_multiplier    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS score_computed_at TIMESTAMPTZ;

-- ── identity_list_snapshots (mirror columns for historical queries) ──
ALTER TABLE identity_list_snapshots
    ADD COLUMN IF NOT EXISTS severity_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS cvss_band         VARCHAR(10) NOT NULL DEFAULT 'INFO',
    ADD COLUMN IF NOT EXISTS blast_radius_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS privilege_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS dormancy_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS governance_score  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS credential_score  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS env_multiplier    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS score_computed_at TIMESTAMPTZ;

-- ── Constraint: valid CVSS bands only ────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'cvss_band_check' AND conrelid = 'identity_list'::regclass
    ) THEN
        ALTER TABLE identity_list
            ADD CONSTRAINT cvss_band_check
            CHECK (cvss_band IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO'));
    END IF;
END $$;

-- ── Indexes for filtering / sorting ──────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_identity_cvss_band
    ON identity_list (organization_id, cvss_band);

CREATE INDEX IF NOT EXISTS idx_identity_severity_score
    ON identity_list (organization_id, severity_score DESC);

COMMIT;
