-- AG-WK7.A: Peer Benchmarking — anonymized percentile-band data moat.
--
-- Per peer review v3/v4: "peer benchmarking page may become more valuable
-- than patents over time." Customers stop scrolling when they see they're
-- in the 12th percentile for AI agent ownership coverage.
--
-- Two tables:
--   peer_benchmark_snapshots — one row per (org, metric, snapshot_date)
--                              with the raw value. NEVER returned to the
--                              client — used only to compute aggregates.
--   peer_benchmark_aggregates — one row per (industry, org_size_band,
--                                metric) with percentile bands. Returned
--                                to all customers in their industry/band.
--
-- Privacy:
--   - Aggregates with n<10 contributing orgs return "Insufficient peers"
--   - Each metric value gets +/- Laplace noise on the percentile
--     boundaries before being written to peer_benchmark_aggregates
--     (epsilon=1.0 — strong privacy for non-sensitive metrics)

\set ON_ERROR_STOP on

BEGIN;

-- 1) Per-org metric snapshots (the raw data — never returned to clients)
CREATE TABLE IF NOT EXISTS peer_benchmark_snapshots (
    id                  BIGSERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL,
    snapshot_date       DATE NOT NULL,
    metric_key          TEXT NOT NULL,
        -- e.g., "ownership_coverage_pct", "nhi_count_per_employee",
        -- "trust_score_avg", "credentials_expired_pct"
    metric_value        NUMERIC(12,4) NOT NULL,

    -- bucketing dimensions (anonymized at aggregate time)
    industry            TEXT,
        -- e.g., "healthcare", "financial_services", "tech", "retail"
    org_size_band       TEXT,
        -- e.g., "smb_under_500", "mid_500_5000", "ent_5000_50000", "mega_50000_plus"

    contributed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT pbs_org_metric_day UNIQUE (organization_id, metric_key, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_pbs_bucket
    ON peer_benchmark_snapshots (industry, org_size_band, metric_key, snapshot_date);


-- 2) Aggregated percentiles per industry+size+metric (returned to clients)
CREATE TABLE IF NOT EXISTS peer_benchmark_aggregates (
    id                  BIGSERIAL PRIMARY KEY,
    snapshot_date       DATE NOT NULL,
    industry            TEXT NOT NULL,
    org_size_band       TEXT NOT NULL,
    metric_key          TEXT NOT NULL,

    n_contributors      INTEGER NOT NULL,        -- count of distinct orgs
    p10                 NUMERIC(12,4),
    p25                 NUMERIC(12,4),
    p50                 NUMERIC(12,4),           -- median
    p75                 NUMERIC(12,4),
    p90                 NUMERIC(12,4),

    -- "Higher is better" — flips the percentile interpretation. For
    -- ownership_coverage_pct, higher=better. For credentials_expired_pct,
    -- lower=better.
    higher_is_better    BOOLEAN NOT NULL DEFAULT TRUE,

    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT pba_bucket_unique
        UNIQUE (snapshot_date, industry, org_size_band, metric_key)
);
CREATE INDEX IF NOT EXISTS idx_pba_lookup
    ON peer_benchmark_aggregates (industry, org_size_band, metric_key, snapshot_date DESC);


-- RLS — snapshots are strict per-org; aggregates are PUBLIC READ for all
-- (anonymized, never reveal individual org values).
ALTER TABLE peer_benchmark_snapshots ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE using_clause TEXT := 'organization_id = (current_setting(''app.current_organization_id'', true))::integer';
BEGIN
    EXECUTE format('DROP POLICY IF EXISTS tenant_strict_sel ON peer_benchmark_snapshots');
    EXECUTE format('DROP POLICY IF EXISTS tenant_strict_ins ON peer_benchmark_snapshots');
    EXECUTE format('DROP POLICY IF EXISTS tenant_strict_upd ON peer_benchmark_snapshots');
    EXECUTE format('DROP POLICY IF EXISTS tenant_strict_del ON peer_benchmark_snapshots');
    EXECUTE format('CREATE POLICY tenant_strict_sel ON peer_benchmark_snapshots FOR SELECT USING (%s)', using_clause);
    EXECUTE format('CREATE POLICY tenant_strict_ins ON peer_benchmark_snapshots FOR INSERT WITH CHECK (%s)', using_clause);
    EXECUTE format('CREATE POLICY tenant_strict_upd ON peer_benchmark_snapshots FOR UPDATE USING (%s) WITH CHECK (%s)', using_clause, using_clause);
    EXECUTE format('CREATE POLICY tenant_strict_del ON peer_benchmark_snapshots FOR DELETE USING (%s)', using_clause);
END $$;

-- Aggregates: anyone with a valid app session can read (no RLS needed —
-- the data is already anonymized + bucketized; protecting it would defeat
-- the purpose).

DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON peer_benchmark_snapshots TO auditgraph_app';
    EXECUTE 'GRANT SELECT ON peer_benchmark_aggregates TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE peer_benchmark_snapshots_id_seq TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE peer_benchmark_aggregates_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON peer_benchmark_snapshots TO auditgraph_admin';
    EXECUTE 'GRANT ALL ON peer_benchmark_aggregates TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;
