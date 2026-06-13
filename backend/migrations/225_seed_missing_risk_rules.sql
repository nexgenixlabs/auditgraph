-- 225_seed_missing_risk_rules.sql
-- 2026-06-12
--
-- Cloud devpilot was producing 0 risk_findings even after fixing the
-- earlier rollback-cascade bug, even though direct SQL run as the
-- tenant-scoped Database connection found matching identities.
--
-- Root cause (caught by the engine-probe technique — run the engine
-- inline via a one-off container job and inspect what it sees):
--
-- Cloud's risk_rules table was missing 7 of the rule_keys that
-- risk_evaluator's @_register decorators bind to. The EVALUATORS dict
-- registered ['spn_owner', 'disabled_user_with_role', 'guest_high_
-- privilege', 'expired_spn_secret', 'spn_secret_expiring',
-- 'inactive_privileged', ...] but cloud's risk_rules contained only
-- escalation-detector + NHI-analyzer keys + the aws_/gcp_ rules. No
-- overlap with risk_evaluator → 0 findings.
--
-- The corresponding 7 risk_evaluator rules from local org 11 produce
-- 29 findings (spn_owner=1, spn_secret_expiring=16, inactive_
-- privileged=12). After seeding, cloud produces 30 findings (Azure
-- timing drift of +1).
--
-- Idempotent — ON CONFLICT (rule_key) DO NOTHING.

INSERT INTO risk_rules (rule_key, rule_name, description, severity, rule_type, enabled, created_at, updated_at)
VALUES
  ('disabled_user_with_role',     'Disabled User with Active Roles',  'Disabled users that still have active role assignments',                'high',     'identity',  true, NOW(), NOW()),
  ('guest_high_privilege',        'Guest with High Privilege',        'Guest users with Owner or Contributor role assignments',                'critical', 'access',    true, NOW(), NOW()),
  ('spn_owner',                   'Service Principal with Owner Role', 'Service principals assigned the Owner role',                           'critical', 'access',    true, NOW(), NOW()),
  ('expired_spn_secret',          'Expired SPN Credential',           'Service principals with expired credentials',                           'high',     'credential',true, NOW(), NOW()),
  ('spn_secret_expiring',         'SPN Credential Expiring Soon',     'Service principal credentials expiring within 30 days',                 'medium',   'credential',true, NOW(), NOW()),
  ('inactive_privileged',         'Inactive Privileged Identity',     'Inactive or stale identities with Owner/Contributor roles',             'high',     'identity',  true, NOW(), NOW()),
  ('identity_large_blast_radius', 'Large Blast Radius',               'Identity has access to a high number of resources through role assignments', 'high', 'access', true, NOW(), NOW())
ON CONFLICT (rule_key) DO NOTHING;
