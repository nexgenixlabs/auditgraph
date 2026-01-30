-- Add credentials table for SPN credential tracking
-- Created: January 30, 2026
-- Purpose: Track service principal secrets, certificates, and federated credentials

-- Create credentials table
CREATE TABLE credentials (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL CHECK (credential_type IN ('secret', 'certificate', 'federated')),
    key_id TEXT NOT NULL,
    display_name TEXT,
    start_datetime TIMESTAMP,
    end_datetime TIMESTAMP,
    thumbprint TEXT, -- for certificates
    issuer TEXT, -- for federated credentials
    subject TEXT, -- for federated credentials
    discovered_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(identity_db_id, key_id)
);

-- Create indexes for performance
CREATE INDEX idx_credentials_identity ON credentials(identity_db_id);
CREATE INDEX idx_credentials_expiry ON credentials(end_datetime);
CREATE INDEX idx_credentials_type ON credentials(credential_type);

-- Add computed fields to identities table for quick access
ALTER TABLE identities ADD COLUMN credential_count INTEGER DEFAULT 0;
ALTER TABLE identities ADD COLUMN next_expiry TIMESTAMP;
ALTER TABLE identities ADD COLUMN credential_risk TEXT CHECK (credential_risk IN ('expired', 'expiring_soon', 'healthy', 'unknown'));

-- Create indexes on new columns
CREATE INDEX idx_identities_credential_risk ON identities(credential_risk);
CREATE INDEX idx_identities_next_expiry ON identities(next_expiry);
