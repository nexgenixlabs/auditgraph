-- Migration 104: Add generated_at column to optimization_recommendations
--
-- Tracks when the recommendation was last computed/refreshed by the
-- post-discovery materialization pipeline.  Distinct from updated_at
-- (which changes on review state mutations too) and created_at
-- (which is the initial insert time).

ALTER TABLE optimization_recommendations
ADD COLUMN IF NOT EXISTS generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
