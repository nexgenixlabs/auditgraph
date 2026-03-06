-- Migration 034: Reporting Engine Stabilization
-- Adds generation duration tracking, run-level parameters, and expiration.

ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS generation_duration_ms INTEGER;
ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS parameters JSONB DEFAULT '{}';
ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_rr_expires_at ON report_runs(expires_at);
