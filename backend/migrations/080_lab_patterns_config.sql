-- Lab name patterns — tenant-configurable discovery heuristics
--
-- Priority chain:
--   1. settings.lab_name_patterns (per-tenant, JSON array of strings)
--   2. platform_settings 'lab_name_patterns' (global default)
--   3. Empty list (no lab pattern matching)
--
-- Ops can customise via:
--   INSERT INTO settings (key, value, organization_id)
--   VALUES ('lab_name_patterns', '["aglab-","lab-spn","myorg-lab-"]', 42);

BEGIN;

-- Seed platform-wide default so existing behaviour is preserved
INSERT INTO platform_settings (key, value)
VALUES ('lab_name_patterns',
        '["aglab-","lab-spn","test-spn","-lab-","sandbox-","dev-spn"]')
ON CONFLICT (key) DO NOTHING;

COMMIT;
