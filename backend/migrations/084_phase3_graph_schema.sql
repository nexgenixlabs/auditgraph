-- Migration 084: Phase 3 Graph Schema Extensions
-- Extends graph_edges with the 6 columns GraphTraversalEngine requires
-- and introduces identity_snapshots to back DataMode.SNAPSHOT lookups.
--
-- Corrections from the drafted spec:
--   * Filename number bumped from 044 → 084. 044 is taken by
--     044_escalation_rules.sql; the next free slot after
--     083_idx_cloud_subscriptions_conn_org.sql is 084.
--   * identity_snapshots.scan_run_id → discovery_run_id. scan_runs
--     does not exist in this schema; the real run table is
--     discovery_runs (see migration 036, 038, 074).
--   * The graph_edges_edge_type_check CHECK constraint was already
--     widened by migration 053 to include 'escalation_path',
--     'policy_attachment', and 'role_binding'. This migration
--     preserves all 6 legacy values and adds 9 Phase 3 values
--     (15 total) so existing rows stay valid.
--
-- Idempotency: every DDL uses IF NOT EXISTS / IF EXISTS and wraps
-- in a single transaction so a partial failure rolls back cleanly.
-- Re-running the migration against a DB that already has it is a
-- no-op.
--
-- RLS note: graph_edges has FORCE ROW LEVEL SECURITY enabled
-- (see 043_iam_graph.sql). The backfill UPDATE below must run as
-- a BYPASSRLS role (auditgraph_admin) or with
-- app.current_organization_id set. If running via
-- `psql $DATABASE_URL < ...`, make sure $DATABASE_URL points at
-- the admin user, not the app user.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Extend graph_edges with Phase 3 columns
-- ---------------------------------------------------------------------------
ALTER TABLE graph_edges
    ADD COLUMN IF NOT EXISTS source_node_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS target_node_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS usage_confidence VARCHAR(20),
    ADD COLUMN IF NOT EXISTS cloud_provider   VARCHAR(20),
    ADD COLUMN IF NOT EXISTS valid_at         TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS invalidated_at   TIMESTAMPTZ DEFAULT NULL;

-- ---------------------------------------------------------------------------
-- 2. Widen the edge_type CHECK constraint
--    Legacy values (6):   assigned_role, grants_access, contains_resource,
--                         escalation_path, policy_attachment, role_binding
--    Phase 3 values (9):  HAS_ROLE, HAS_PERMISSION, CAN_ACCESS, MEMBER_OF,
--                         OWNS, TRUSTS, DELEGATES_TO, BOUND_TO, PART_OF
-- ---------------------------------------------------------------------------
ALTER TABLE graph_edges
    DROP CONSTRAINT IF EXISTS graph_edges_edge_type_check;

ALTER TABLE graph_edges
    ADD CONSTRAINT graph_edges_edge_type_check
    CHECK (edge_type IN (
        -- Legacy (migrations 043, 053) — preserved for backward compat
        'assigned_role',
        'grants_access',
        'contains_resource',
        'escalation_path',
        'policy_attachment',
        'role_binding',
        -- Phase 3 (EdgeType enum in traversal_policy.py)
        'HAS_ROLE',
        'HAS_PERMISSION',
        'CAN_ACCESS',
        'MEMBER_OF',
        'OWNS',
        'TRUSTS',
        'DELEGATES_TO',
        'BOUND_TO',
        'PART_OF'
    ));

-- ---------------------------------------------------------------------------
-- 3. Backfill existing rows
--    * valid_at ← created_at (so historical rows are "visible" to
--      GraphTraversalEngine's live-mode temporal clause)
--    * source_node_type / target_node_type ← graph_nodes.node_type
--      (co-scoped by organization_id as a defense-in-depth guard
--      against cross-org drift; the FK already enforces 1:1)
--
--    Only rows with NULL valid_at are touched so re-running is
--    idempotent. Rows inserted after this migration get valid_at
--    from the column default.
-- ---------------------------------------------------------------------------
UPDATE graph_edges e
SET
    valid_at = e.created_at,
    source_node_type = (
        SELECT n.node_type
        FROM graph_nodes n
        WHERE n.id = e.source_node_id
          AND n.organization_id = e.organization_id
    ),
    target_node_type = (
        SELECT n.node_type
        FROM graph_nodes n
        WHERE n.id = e.target_node_id
          AND n.organization_id = e.organization_id
    )
WHERE e.valid_at IS NULL;

-- ---------------------------------------------------------------------------
-- 4. Performance indexes for the BFS hot path
--    * idx_graph_edges_source_org:  _fetch_edges_batch per-level fan-out
--      (one query per BFS level, keyed by org + source node, live rows only)
--    * idx_graph_edges_edge_type:   policy-scoped scans over edge types
--      within an org (e.g. "show me every HAS_ROLE edge for org 2")
--    Both are partial on invalidated_at IS NULL — snapshot-mode
--    queries fall back to the existing idx_ge_org/idx_ge_source indexes.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_graph_edges_source_org
    ON graph_edges (organization_id, source_node_id)
    WHERE invalidated_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_graph_edges_edge_type
    ON graph_edges (organization_id, edge_type)
    WHERE invalidated_at IS NULL;

-- ---------------------------------------------------------------------------
-- 5. identity_snapshots — backs DataMode.SNAPSHOT lookups
--    GraphTraversalEngine._resolve_snapshot_date queries this table
--    by its SERIAL `id` PK (`WHERE id = :sid`). The separate
--    snapshot_id INT column is a caller-facing identifier that can
--    be assigned by the snapshot pipeline independently of the
--    auto-increment PK (e.g. stable across DB dump/restore).
--
--    NOTE: discovery_runs(id) is the real run table; the drafted
--    spec referenced scan_runs(id) which does not exist.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_snapshots (
    id                SERIAL PRIMARY KEY,
    snapshot_id       INTEGER NOT NULL,
    organization_id   INTEGER NOT NULL,
    snapshot_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    discovery_run_id  INTEGER REFERENCES discovery_runs(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (snapshot_id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_identity_snapshots_org_date
    ON identity_snapshots (organization_id, snapshot_date DESC);

-- valid_at is the column GraphTraversalEngine._fetch_edges_batch
-- compares snapshot_date against, so we also index snapshot_date
-- for fast PITR lookups. No other access patterns are currently
-- expected — add more indexes when call sites demand them.

COMMIT;
