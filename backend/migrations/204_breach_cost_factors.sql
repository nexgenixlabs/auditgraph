-- AG-T1.1: Breach cost factors table for risk-in-$ quantification.
--
-- Design notes
-- ────────────
--   * All cost factors live in this table, NEVER hardcoded in Python.
--     Customers can adjust per-record costs via /api/settings later.
--   * Each row carries the public source citation that justifies the number,
--     so a CISO can defend the dashboard figure to their CFO/board.
--   * Pessimistic/optimistic band: lower/upper bound capture the
--     "$50K–$250K per record" headline you see in industry reports without
--     committing to a single false-precision number.
--   * Region-aware: GDPR jurisdictions can override with a row tagged
--     `region='eu'`. The lookup falls back to global if no regional row.
--   * Frozen at effective_date so a snapshot reproduces last quarter's
--     dashboard number even if costs are updated mid-cycle.
--
-- Sources cited (all publicly available, all 2023):
--   - IBM "Cost of a Data Breach Report 2023"
--   - Ponemon "Healthcare Breach 2023" (PHI)
--   - Verizon "Data Breach Investigations Report 2023" (PCI)
--   - GDPR Enforcement Tracker (regulatory penalty band)

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS breach_cost_factors (
    id                    SERIAL PRIMARY KEY,
    data_classification   TEXT        NOT NULL,
    region                TEXT        NOT NULL DEFAULT 'global',
    cost_per_record_low   NUMERIC(12,2) NOT NULL,
    cost_per_record_high  NUMERIC(12,2) NOT NULL,
    cost_per_record_mid   NUMERIC(12,2) NOT NULL,
    regulatory_band_low   NUMERIC(14,2) NOT NULL DEFAULT 0,
    regulatory_band_high  NUMERIC(14,2) NOT NULL DEFAULT 0,
    source                TEXT        NOT NULL,
    source_year           INTEGER     NOT NULL,
    notes                 TEXT,
    effective_date        DATE        NOT NULL,
    superseded_date       DATE,
    is_active             BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT bcf_class_region_active_unique
        UNIQUE (data_classification, region, is_active),
    CONSTRAINT bcf_band_ordered CHECK (cost_per_record_low <= cost_per_record_mid AND cost_per_record_mid <= cost_per_record_high)
);

CREATE INDEX IF NOT EXISTS idx_bcf_class_region_active
    ON breach_cost_factors (data_classification, region) WHERE is_active = TRUE;

INSERT INTO breach_cost_factors
    (data_classification, region,
     cost_per_record_low, cost_per_record_mid, cost_per_record_high,
     regulatory_band_low, regulatory_band_high,
     source, source_year, notes, effective_date)
VALUES
    ('PHI', 'global',
        408, 471, 535,
        100, 1500000,
        'IBM Cost of a Data Breach 2023 — Healthcare; Ponemon Healthcare Breach 2023',
        2023,
        'Healthcare = most expensive sector for 13th consecutive year. HIPAA Tier 4 penalty cap $1.5M/violation/year.',
        '2024-01-01'),
    ('PCI', 'global',
        180, 264, 429,
        5000, 100000,
        'IBM Cost of a Data Breach 2023 — Financial Services; Verizon DBIR 2023',
        2023,
        'PCI DSS non-compliance fines $5K-$100K/month + card brand assessments + reissuance.',
        '2024-01-01'),
    ('PII', 'global',
        148, 165, 183,
        100, 50000,
        'IBM Cost of a Data Breach 2023 — global average',
        2023,
        'Customer/employee personal identifiers. State-level breach notification statutes vary.',
        '2024-01-01'),
    ('PII', 'eu',
        165, 245, 330,
        100000, 20000000,
        'GDPR Enforcement Tracker 2023 — top-decile fines; IBM EU regional avg',
        2023,
        'GDPR Article 83(5): up to €20M or 4% of global turnover. Regulatory band reflects observed enforcement, not the cap.',
        '2024-01-01'),
    ('FINANCIAL', 'global',
        200, 260, 380,
        0, 0,
        'IBM Cost of a Data Breach 2023 — Financial Services',
        2023,
        'Account/transaction data. Excludes PCI cardholder data which is its own class.',
        '2024-01-01'),
    ('HR', 'global',
        100, 135, 175,
        0, 0,
        'IBM Cost of a Data Breach 2023 — internal employee records average',
        2023,
        'Employee records (compensation, performance, SSN). Higher in EU due to GDPR overlap.',
        '2024-01-01'),
    ('SOURCE', 'global',
        25, 75, 200,
        0, 0,
        'estimated — IP exposure not records-based',
        2023,
        'Source code / IP. Per-file conservative estimate; true value depends on whether code is product-differentiating IP.',
        '2024-01-01'),
    ('CONFIDENTIAL', 'global',
        30, 60, 120,
        0, 0,
        'estimated — internal documents, conservative',
        2023,
        'Internal docs (strategy memos, contracts). Varies wildly; this is a floor.',
        '2024-01-01')
ON CONFLICT DO NOTHING;

-- Grant: read access to both app + admin roles
DO $$ BEGIN
    EXECUTE 'GRANT SELECT ON breach_cost_factors TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON breach_cost_factors TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;

\echo ''
\echo '=== Loaded breach cost factors ==='
SELECT data_classification, region,
       cost_per_record_low || '–' || cost_per_record_high AS band,
       source_year, left(source, 50) AS source
FROM breach_cost_factors ORDER BY data_classification, region;
