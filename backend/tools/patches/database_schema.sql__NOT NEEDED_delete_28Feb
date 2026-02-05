-- AuditGraph Database Schema

-- Table 1: Discovery Runs (each execution)
CREATE TABLE IF NOT EXISTS discovery_runs (
    id SERIAL PRIMARY KEY,
    subscription_id VARCHAR(255) NOT NULL,
    subscription_name VARCHAR(255),
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    status VARCHAR(50) NOT NULL, -- running, completed, failed
    total_identities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: Identities (service principals & managed identities)
CREATE TABLE IF NOT EXISTS identities (
    id SERIAL PRIMARY KEY,
    discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE CASCADE,
    identity_id VARCHAR(255) NOT NULL,
    display_name VARCHAR(500) NOT NULL,
    identity_type VARCHAR(50) NOT NULL, -- service_principal, managed_identity
    app_id VARCHAR(255),
    object_id VARCHAR(255),
    created_datetime TIMESTAMP,
    enabled BOOLEAN DEFAULT TRUE,
    is_microsoft_system BOOLEAN DEFAULT FALSE,
    
    -- Risk assessment
    risk_level VARCHAR(50), -- critical, high, medium, low, info
    risk_reasons TEXT[],
    
    -- Credentials
    credential_expiration TIMESTAMP,
    credential_status VARCHAR(50), -- expired, critical, warning, good, unknown
    
    -- Activity
    last_sign_in TIMESTAMP,
    activity_status VARCHAR(50), -- active, inactive, stale, never_used, unknown
    
    -- Metadata
    tags JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Index for fast lookups
    UNIQUE(discovery_run_id, identity_id)
);

-- Table 3: Role Assignments (RBAC permissions)
CREATE TABLE IF NOT EXISTS role_assignments (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER REFERENCES identities(id) ON DELETE CASCADE,
    role_name VARCHAR(255) NOT NULL,
    scope VARCHAR(1000) NOT NULL,
    scope_type VARCHAR(50) NOT NULL, -- subscription, resource_group, resource
    principal_id VARCHAR(255) NOT NULL,
    assignment_id VARCHAR(255),
    created_on TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_identities_run_id ON identities(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_identities_risk_level ON identities(risk_level);
CREATE INDEX IF NOT EXISTS idx_identities_type ON identities(identity_type);
CREATE INDEX IF NOT EXISTS idx_identities_system ON identities(is_microsoft_system);
CREATE INDEX IF NOT EXISTS idx_role_assignments_identity ON role_assignments(identity_db_id);
CREATE INDEX IF NOT EXISTS idx_discovery_runs_status ON discovery_runs(status);
CREATE INDEX IF NOT EXISTS idx_discovery_runs_started ON discovery_runs(started_at DESC);

-- Views for easy querying
CREATE OR REPLACE VIEW v_latest_identities AS
SELECT i.*
FROM identities i
INNER JOIN (
    SELECT MAX(id) as run_id FROM discovery_runs WHERE status = 'completed'
) latest ON i.discovery_run_id = latest.run_id;

CREATE OR REPLACE VIEW v_critical_identities AS
SELECT * FROM v_latest_identities WHERE risk_level = 'critical';

COMMENT ON TABLE discovery_runs IS 'Each discovery execution/run';
COMMENT ON TABLE identities IS 'Discovered Azure identities (SPNs, MIs)';
COMMENT ON TABLE role_assignments IS 'RBAC role assignments for identities';
