-- Migration 045: Non-Human Identity Security Rules
-- Phase 9: Seed 5 NHI detection rules into risk_rules

INSERT INTO risk_rules (rule_key, rule_name, description, severity, rule_type) VALUES
    ('spn_secret_without_expiry', 'SPN Secret Without Expiry', 'Service principal secret has no expiration date set', 'critical', 'credential'),
    ('spn_secret_older_than_180_days', 'SPN Secret Older Than 180 Days', 'Service principal secret created more than 180 days ago', 'high', 'credential'),
    ('unused_service_principal', 'Unused Service Principal', 'Service principal with no sign-in activity in 90+ days', 'medium', 'identity'),
    ('spn_owner_role', 'SPN with Owner Role', 'Service principal has Owner role assignment', 'high', 'access'),
    ('managed_identity_high_privilege', 'Managed Identity High Privilege', 'Managed identity has Contributor or Owner role', 'medium', 'access')
ON CONFLICT (rule_key) DO NOTHING;
