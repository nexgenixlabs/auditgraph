-- Migration 044: Privilege Escalation Rules
-- Phase 8: Seed 4 escalation detection rules into risk_rules

INSERT INTO risk_rules (rule_key, rule_name, description, severity, rule_type) VALUES
    ('identity_can_assign_owner', 'Can Assign Owner Role', 'Identity has roleAssignments/write permission enabling Owner assignment', 'critical', 'access'),
    ('service_principal_owner', 'Service Principal with Owner', 'Service principal has Owner role — high-privilege non-human access', 'high', 'access'),
    ('managed_identity_contributor', 'Managed Identity with Contributor', 'Managed identity has Contributor or Owner role', 'medium', 'access'),
    ('identity_can_modify_role_definitions', 'Can Modify Role Definitions', 'Identity has roleDefinitions/write permission enabling custom role creation', 'critical', 'access')
ON CONFLICT (rule_key) DO NOTHING;
