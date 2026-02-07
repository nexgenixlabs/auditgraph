-- Migration 011: Conditional Access policy tables
-- Tracks CA policies, per-identity coverage, and weak policy detection

CREATE TABLE IF NOT EXISTS ca_policies (
    id SERIAL PRIMARY KEY,
    discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    state TEXT NOT NULL,                -- enabled | disabled | enabledForReportingButNotEnforced
    include_users JSONB DEFAULT '[]',
    exclude_users JSONB DEFAULT '[]',
    include_applications JSONB DEFAULT '[]',
    client_app_types JSONB DEFAULT '[]',
    grant_controls JSONB DEFAULT '{}',
    session_controls JSONB DEFAULT '{}',
    requires_mfa BOOLEAN DEFAULT FALSE,
    targets_all_users BOOLEAN DEFAULT FALSE,
    has_exclusions BOOLEAN DEFAULT FALSE,
    allows_legacy_auth BOOLEAN DEFAULT FALSE,
    modified_datetime TIMESTAMPTZ,
    UNIQUE(discovery_run_id, policy_id)
);

CREATE TABLE IF NOT EXISTS ca_identity_coverage (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    coverage_status TEXT NOT NULL,       -- covered | partial | excluded | no_coverage
    mfa_enforced BOOLEAN DEFAULT FALSE,
    applicable_policy_count INTEGER DEFAULT 0,
    excluded_from_count INTEGER DEFAULT 0,
    risk_flags JSONB DEFAULT '[]',
    UNIQUE(identity_db_id)
);

ALTER TABLE identities ADD COLUMN IF NOT EXISTS ca_coverage_status TEXT;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS ca_mfa_enforced BOOLEAN;
