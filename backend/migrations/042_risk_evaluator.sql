-- Migration 042: Risk Evaluator — risk_rules + risk_findings tables
-- Phase 6: Rules-based risk detection engine

-- ── risk_rules (system-wide, NO RLS) ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS risk_rules (
    id              SERIAL PRIMARY KEY,
    rule_key        VARCHAR(100) UNIQUE NOT NULL,
    rule_name       VARCHAR(255) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    rule_type       VARCHAR(60) NOT NULL CHECK (rule_type IN ('identity', 'credential', 'access', 'configuration', 'compliance', 'behavioral')),
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_rules_enabled ON risk_rules(enabled);

GRANT SELECT ON risk_rules TO auditgraph_app;

-- ── risk_findings (org-scoped, WITH RLS) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS risk_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     INTEGER NOT NULL,
    cloud_connection_id INTEGER NOT NULL,
    rule_id             INTEGER REFERENCES risk_rules(id),
    severity            VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    identity_id         TEXT,
    resource_id         TEXT,
    metadata            JSONB DEFAULT '{}',
    status              VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    detected_at         TIMESTAMPTZ DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    resolved_by         VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_rf_org ON risk_findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_rf_connection ON risk_findings(cloud_connection_id);
CREATE INDEX IF NOT EXISTS idx_rf_rule ON risk_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_rf_severity ON risk_findings(severity);
CREATE INDEX IF NOT EXISTS idx_rf_status ON risk_findings(status);
CREATE INDEX IF NOT EXISTS idx_rf_detected ON risk_findings(detected_at DESC);

-- Dedup: only one open finding per connection+rule+identity+resource
CREATE UNIQUE INDEX IF NOT EXISTS idx_rf_dedup
    ON risk_findings (cloud_connection_id, rule_id, COALESCE(identity_id, ''), COALESCE(resource_id, ''))
    WHERE status = 'open';

-- ── RLS policies ────────────────────────────────────────────────────────────

ALTER TABLE risk_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_findings FORCE ROW LEVEL SECURITY;

CREATE POLICY rf_strict_sel ON risk_findings FOR SELECT TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

CREATE POLICY rf_strict_ins ON risk_findings FOR INSERT TO auditgraph_app
    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);

CREATE POLICY rf_strict_upd ON risk_findings FOR UPDATE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

CREATE POLICY rf_strict_del ON risk_findings FOR DELETE TO auditgraph_app
    USING (organization_id = current_setting('app.current_organization_id', true)::integer);

GRANT SELECT, INSERT, UPDATE ON risk_findings TO auditgraph_app;

-- ── Seed default rules ──────────────────────────────────────────────────────

INSERT INTO risk_rules (rule_key, rule_name, description, severity, rule_type) VALUES
    ('disabled_user_with_role', 'Disabled User with Active Roles', 'Disabled users that still have active role assignments', 'high', 'identity'),
    ('guest_high_privilege', 'Guest with High Privilege', 'Guest users with Owner or Contributor role assignments', 'critical', 'access'),
    ('spn_owner', 'Service Principal with Owner Role', 'Service principals assigned the Owner role', 'critical', 'access'),
    ('expired_spn_secret', 'Expired SPN Credential', 'Service principals with expired credentials', 'high', 'credential'),
    ('spn_secret_expiring', 'SPN Credential Expiring Soon', 'Service principal credentials expiring within 30 days', 'medium', 'credential'),
    ('inactive_privileged', 'Inactive Privileged Identity', 'Inactive or stale identities with Owner/Contributor roles', 'high', 'identity')
ON CONFLICT (rule_key) DO NOTHING;
