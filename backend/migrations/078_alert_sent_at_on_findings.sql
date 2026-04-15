-- Migration 078: Add alert_sent_at to security_findings
--
-- Tracks when an email alert was sent for a finding. Used by the orphan
-- agent alert dedup guard (IASM-AG-001) to prevent duplicate emails on
-- subsequent nightly scans when the same finding is still open.
--
-- NULL = alert not yet sent for this finding row.
-- Non-NULL = alert already sent; skip on subsequent scans.
--
-- When a finding is resolved and the same SPN re-triggers later,
-- the UPSERT creates or reopens a row with alert_sent_at = NULL,
-- so the guard correctly fires the alert once for the new occurrence.
--
-- UP:
ALTER TABLE security_findings
    ADD COLUMN IF NOT EXISTS alert_sent_at TIMESTAMPTZ;

-- DOWN (reverse migration):
-- ALTER TABLE security_findings
--     DROP COLUMN IF EXISTS alert_sent_at;
