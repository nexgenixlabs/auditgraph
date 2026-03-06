-- Migration 031: Access Review Workflow
-- Phase 6: Compliance-driven access review lifecycle (SOC2, HIPAA, ISO27001, NIST)

-- 1) access_reviews — top-level review campaigns
CREATE TABLE IF NOT EXISTS access_reviews (
    id SERIAL PRIMARY KEY,
    review_id UUID NOT NULL DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    review_type VARCHAR(30) NOT NULL DEFAULT 'manual',       -- manual, periodic, triggered
    scope VARCHAR(30) NOT NULL DEFAULT 'privileged',          -- privileged, all, custom
    status VARCHAR(20) NOT NULL DEFAULT 'open',               -- open, in_progress, completed, cancelled
    created_by VARCHAR(100),
    created_by_user_id INTEGER,
    total_assignments INTEGER NOT NULL DEFAULT 0,
    completed_assignments INTEGER NOT NULL DEFAULT 0,
    approved_count INTEGER NOT NULL DEFAULT 0,
    revoked_count INTEGER NOT NULL DEFAULT 0,
    flagged_count INTEGER NOT NULL DEFAULT 0,
    due_date TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    completed_by VARCHAR(100),
    compliance_frameworks JSONB DEFAULT '[]',                  -- ["SOC2", "HIPAA", "ISO27001", "NIST"]
    settings JSONB DEFAULT '{}',                               -- auto_revoke, reminder_days, etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ar_org_id ON access_reviews(organization_id);
CREATE INDEX IF NOT EXISTS idx_ar_status ON access_reviews(status);
CREATE INDEX IF NOT EXISTS idx_ar_review_type ON access_reviews(review_type);
CREATE INDEX IF NOT EXISTS idx_ar_created_at ON access_reviews(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ar_due_date ON access_reviews(due_date);

-- 2) review_assignments — one per identity-role pair under review
CREATE TABLE IF NOT EXISTS review_assignments (
    id SERIAL PRIMARY KEY,
    assignment_id UUID NOT NULL DEFAULT gen_random_uuid(),
    review_id INTEGER NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL,
    identity_id INTEGER NOT NULL,
    identity_name TEXT,
    identity_type VARCHAR(30),
    role_name TEXT NOT NULL,
    role_type VARCHAR(20) NOT NULL DEFAULT 'rbac',            -- rbac, entra, app_role
    scope TEXT,
    risk_level VARCHAR(20),
    risk_score INTEGER DEFAULT 0,
    blast_radius_score INTEGER DEFAULT 0,
    attack_path_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    reviewer VARCHAR(100),
    reviewer_user_id INTEGER,
    decision VARCHAR(20) NOT NULL DEFAULT 'pending',          -- pending, approved, revoked, flagged
    decision_reason TEXT,
    decision_at TIMESTAMPTZ,
    due_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ra_review_id ON review_assignments(review_id);
CREATE INDEX IF NOT EXISTS idx_ra_org_id ON review_assignments(organization_id);
CREATE INDEX IF NOT EXISTS idx_ra_identity_id ON review_assignments(identity_id);
CREATE INDEX IF NOT EXISTS idx_ra_reviewer ON review_assignments(reviewer);
CREATE INDEX IF NOT EXISTS idx_ra_decision ON review_assignments(decision);
CREATE INDEX IF NOT EXISTS idx_ra_created_at ON review_assignments(created_at DESC);

-- 3) review_evidence — supporting data attached to assignment decisions
CREATE TABLE IF NOT EXISTS review_evidence (
    id SERIAL PRIMARY KEY,
    evidence_id UUID NOT NULL DEFAULT gen_random_uuid(),
    assignment_id INTEGER NOT NULL REFERENCES review_assignments(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL,
    evidence_type VARCHAR(30) NOT NULL,                       -- finding, attack_path, blast_radius, activity_log, manual_note
    source_id TEXT,                                            -- FK to source record
    title TEXT NOT NULL,
    detail JSONB DEFAULT '{}',
    added_by VARCHAR(100),
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_re_assignment_id ON review_evidence(assignment_id);
CREATE INDEX IF NOT EXISTS idx_re_org_id ON review_evidence(organization_id);
CREATE INDEX IF NOT EXISTS idx_re_evidence_type ON review_evidence(evidence_type);
