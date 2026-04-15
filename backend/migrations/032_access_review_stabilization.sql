-- Migration 032: Access Review Stabilization
-- Adds risk snapshots, review outcomes, and SLA metrics for Phase 7 reporting.

-- Part 1: Risk snapshot on review_assignments
ALTER TABLE review_assignments ADD COLUMN IF NOT EXISTS risk_snapshot JSONB;

-- Part 2: Review outcome on access_reviews
ALTER TABLE access_reviews ADD COLUMN IF NOT EXISTS review_outcome TEXT;

-- Part 3: Review duration metric on access_reviews
ALTER TABLE access_reviews ADD COLUMN IF NOT EXISTS review_duration_hours INTEGER;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ar_review_outcome ON access_reviews(review_outcome);
CREATE INDEX IF NOT EXISTS idx_ar_review_duration ON access_reviews(review_duration_hours);
