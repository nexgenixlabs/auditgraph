-- Phase 12: Remediation Engine
-- Table for mapping risk patterns to actionable remediation playbooks

CREATE TABLE IF NOT EXISTS remediation_playbooks (
    id SERIAL PRIMARY KEY,
    risk_pattern VARCHAR(255) NOT NULL,
    pattern_type VARCHAR(20) DEFAULT 'contains',  -- contains, startswith, exact
    title VARCHAR(255) NOT NULL,
    description TEXT,
    steps JSONB NOT NULL,              -- ["Step 1...", "Step 2..."]
    impact VARCHAR(10) DEFAULT 'high', -- critical, high, medium, low
    effort VARCHAR(10) DEFAULT 'medium', -- low, medium, high
    priority_score INTEGER DEFAULT 50, -- 0-100, higher = do first
    compliance_refs JSONB,             -- ["SOC2 CC6.1", "HIPAA 164.312(a)"]
    category VARCHAR(50),              -- access_control, credential_hygiene, monitoring, governance
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remediation_pattern ON remediation_playbooks(risk_pattern);
CREATE INDEX IF NOT EXISTS idx_remediation_category ON remediation_playbooks(category);
