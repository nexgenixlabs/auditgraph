-- Migration 035: Platform Operations & Health Monitoring
-- Phase 8: Job tracking, tenant health, system metrics, discovery integrity.

-- 1) job_runs — track execution of all background jobs
CREATE TABLE IF NOT EXISTS job_runs (
    id SERIAL,
    job_id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    organization_id INTEGER,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jr_org_id ON job_runs(organization_id);
CREATE INDEX IF NOT EXISTS idx_jr_job_type ON job_runs(job_type);
CREATE INDEX IF NOT EXISTS idx_jr_status ON job_runs(status);
CREATE INDEX IF NOT EXISTS idx_jr_started_at ON job_runs(started_at DESC);

-- 2) tenant_health — operational health per tenant
CREATE TABLE IF NOT EXISTS tenant_health (
    organization_id INTEGER PRIMARY KEY,
    last_discovery_run TIMESTAMPTZ,
    snapshot_age_hours INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    critical_risks INTEGER DEFAULT 0,
    blast_radius_critical INTEGER DEFAULT 0,
    integrity_warning BOOLEAN DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'stale',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_th_status ON tenant_health(status);
CREATE INDEX IF NOT EXISTS idx_th_updated_at ON tenant_health(updated_at DESC);

-- 3) system_health_metrics — global system metrics
CREATE TABLE IF NOT EXISTS system_health_metrics (
    id SERIAL,
    metric_id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shm_metric_name ON system_health_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_shm_recorded_at ON system_health_metrics(recorded_at DESC);

-- 4) discovery_integrity_metrics — per-run discovery counts for drift comparison
CREATE TABLE IF NOT EXISTS discovery_integrity_metrics (
    id SERIAL,
    metric_id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    organization_id INTEGER NOT NULL,
    discovery_run_id INTEGER,
    identities_count INTEGER DEFAULT 0,
    resources_count INTEGER DEFAULT 0,
    role_assignments_count INTEGER DEFAULT 0,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dim_org_id ON discovery_integrity_metrics(organization_id);
CREATE INDEX IF NOT EXISTS idx_dim_run_id ON discovery_integrity_metrics(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_dim_recorded_at ON discovery_integrity_metrics(recorded_at DESC);
