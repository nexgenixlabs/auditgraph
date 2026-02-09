-- Phase 15: Settings & Configuration
-- Key-value settings table for runtime configuration

CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed defaults
INSERT INTO settings (key, value) VALUES
    ('org_name', 'AuditGraph'),
    ('discovery_interval_hours', '12'),
    ('email_enabled', 'true'),
    ('email_to', ''),
    ('notify_new_identities', 'true'),
    ('notify_removed_identities', 'true'),
    ('notify_permission_changes', 'true'),
    ('notify_risk_changes', 'true'),
    ('notify_credential_changes', 'true')
ON CONFLICT (key) DO NOTHING;
