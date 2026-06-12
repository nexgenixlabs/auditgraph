-- 220_board_scorecard_per_run_snapshots.sql
-- 2026-06-12
--
-- ai_board_scorecard_snapshots was keyed (organization_id, snapshot_date)
-- so every same-day discovery run UPSERTed the existing row and the
-- 2nd+ scans of the day were thrown away. That meant a 24h-scheduled
-- tenant never saw a trend on day 1, and a 6h-scheduled tenant ran 4
-- scans but only ever had 1 row.
--
-- Switching to per-run snapshots: drop the (org, snapshot_date) unique
-- constraint, add discovery_run_id to disambiguate. Existing seeded
-- rows (org 9 demo history) keep their unique snapshot_date so they
-- still chart correctly; new rows can share a date freely.

ALTER TABLE ai_board_scorecard_snapshots
  DROP CONSTRAINT IF EXISTS ai_board_scorecard_snapshots_organization_id_snapshot_date_key;

ALTER TABLE ai_board_scorecard_snapshots
  ADD COLUMN IF NOT EXISTS discovery_run_id integer;

-- Index for fast trend queries — chronological ordering by computed_at,
-- per org. Replaces the old (org, snapshot_date) lookup pattern.
CREATE INDEX IF NOT EXISTS idx_ai_bss_org_computed
  ON ai_board_scorecard_snapshots (organization_id, computed_at DESC);

-- Optional weak uniqueness on (org, discovery_run_id) — prevents a
-- single run from accidentally writing twice if the snapshot hook
-- fires more than once. NULL discovery_run_id (legacy seeded rows)
-- is allowed multiple times.
CREATE UNIQUE INDEX IF NOT EXISTS ai_board_scorecard_snapshots_org_run_uniq
  ON ai_board_scorecard_snapshots (organization_id, discovery_run_id)
  WHERE discovery_run_id IS NOT NULL;
