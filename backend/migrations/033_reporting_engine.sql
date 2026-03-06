-- Migration 033: Reporting Engine
-- Phase 7: Executive security reports and compliance evidence.

-- 1) reports — report definitions / request records
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    report_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    report_type TEXT NOT NULL,
    title TEXT,
    parameters JSONB DEFAULT '{}',
    created_by INTEGER,
    created_by_username VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rpt_org_id ON reports(organization_id);
CREATE INDEX IF NOT EXISTS idx_rpt_report_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_rpt_created_at ON reports(created_at DESC);

-- 2) report_runs — each generation attempt for a report
CREATE TABLE IF NOT EXISTS report_runs (
    id SERIAL PRIMARY KEY,
    run_id UUID NOT NULL DEFAULT gen_random_uuid(),
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    record_count INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    generated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rr_report_id ON report_runs(report_id);
CREATE INDEX IF NOT EXISTS idx_rr_org_id ON report_runs(organization_id);
CREATE INDEX IF NOT EXISTS idx_rr_status ON report_runs(status);

-- 3) report_outputs — exported files (pdf/csv/json)
CREATE TABLE IF NOT EXISTS report_outputs (
    id SERIAL PRIMARY KEY,
    output_id UUID NOT NULL DEFAULT gen_random_uuid(),
    run_id INTEGER NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL,
    format TEXT NOT NULL DEFAULT 'json',
    storage_path TEXT,
    file_size_bytes INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ro_run_id ON report_outputs(run_id);
CREATE INDEX IF NOT EXISTS idx_ro_org_id ON report_outputs(organization_id);
CREATE INDEX IF NOT EXISTS idx_ro_format ON report_outputs(format);
