-- Migration 071: Identity Security Posture
-- Aggregated posture snapshot per connection, computed from security_findings.

CREATE TABLE IF NOT EXISTS identity_security_posture (
    id SERIAL PRIMARY KEY,
    connection_id INT,
    risk_score INT,
    findings_count INT,
    high_severity INT,
    medium_severity INT,
    low_severity INT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posture_conn ON identity_security_posture(connection_id);
CREATE INDEX IF NOT EXISTS idx_posture_created ON identity_security_posture(created_at DESC);
