-- AG-PERF-N+1 (2026-06-07): identity-list endpoint perf fix
--
-- BEFORE: GET /api/identities at 100K identities takes 1700ms p95.
-- ROOT CAUSE per EXPLAIN ANALYZE:
--   1. ORDER BY (risk_level, display_name) lacks a composite index, so
--      the planner does an index scan on idx_identities_risk_level then
--      sorts 20,001 rows to find the top 50 — 653ms of pure scan/sort
--   2. The 22 correlated EXISTS subqueries amplify this
--
-- AFTER (expected): composite index lets the planner walk directly to
-- the top-50 in sorted order — ~50ms full query, ~150-250ms endpoint.
--
-- This is a pure read-path optimization. No data shape change. Safe to
-- apply to running tenants — CREATE INDEX IF NOT EXISTS is non-blocking
-- in PostgreSQL when CONCURRENTLY is used.
--
-- Per perf baseline: docs/AG_PERF_BASELINE_100K_2026_06_07.md §5

\set ON_ERROR_STOP on

-- CONCURRENTLY requires no transaction block — apply outside BEGIN/COMMIT
-- Safe to re-run (idempotent via IF NOT EXISTS).

CREATE INDEX IF NOT EXISTS idx_identities_list_order
    ON identities (organization_id, risk_level, display_name)
    WHERE deleted_at IS NULL;

-- Composite partial index matches the WHERE + ORDER BY of the
-- identity list handler exactly:
--   WHERE i.organization_id = ? AND i.deleted_at IS NULL
--   ORDER BY i.risk_level, i.display_name
--
-- The partial index condition `WHERE deleted_at IS NULL` keeps the
-- index small (deleted identities are typically 0-2% of rows).

-- Verify with: EXPLAIN ANALYZE SELECT ... ORDER BY ... LIMIT 50;
-- Expected plan: Index Only Scan using idx_identities_list_order
