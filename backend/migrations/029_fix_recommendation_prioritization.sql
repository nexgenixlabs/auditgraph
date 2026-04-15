-- Migration 029: Fix Recommendation Prioritization & Traceability
--
-- Adds risk_reduction_score, finding_id, and attack_path_id to fix_recommendations.
--
-- Note: fix_category, effort (implementation_effort), and priority_score already
-- exist from migration 028. This migration only adds the truly new columns.
--
-- Idempotent: uses ADD COLUMN IF NOT EXISTS and CREATE INDEX IF NOT EXISTS.

-- Risk reduction estimate (0-100): how much security risk is removed if this fix is applied
ALTER TABLE fix_recommendations ADD COLUMN IF NOT EXISTS risk_reduction_score INTEGER DEFAULT 0;

-- Direct FK to the specific security finding that triggered this recommendation
ALTER TABLE fix_recommendations ADD COLUMN IF NOT EXISTS finding_id INTEGER;

-- Direct FK to the specific attack path that triggered this recommendation
ALTER TABLE fix_recommendations ADD COLUMN IF NOT EXISTS attack_path_id INTEGER;

-- Indexes for the new FK columns (join performance)
CREATE INDEX IF NOT EXISTS idx_fr_finding_id ON fix_recommendations(finding_id);
CREATE INDEX IF NOT EXISTS idx_fr_attack_path_id ON fix_recommendations(attack_path_id);

-- Index on risk_reduction_score for prioritization queries
CREATE INDEX IF NOT EXISTS idx_fr_risk_reduction ON fix_recommendations(risk_reduction_score DESC);
