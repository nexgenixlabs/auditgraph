-- AIAG cloud-demo supplement: light up JML panel + enable behavioral
-- anomaly analysis on the Executive Posture dashboard for org=3.
--
-- Adds:
--   * 2 joiners (created <30 days ago, risk critical/high, with priv roles)
--   * 2 mover_stale_access anomalies (movers panel)
--   * 2 leavers (ghost identities = enabled=FALSE + role_assignments retained)
--   * settings.p2_telemetry_enabled = 'true' (Anomalies panel goes live)
--
-- Fingerprint: df000-* identities (idempotent).

\set ON_ERROR_STOP on

BEGIN;

SELECT set_config('app.current_organization_id', '3', true);
SELECT set_config('app.current_tenant_id', '3', true);

-- ============================================================
-- 1. JOINERS — 2 new identities created within last 30 days, critical/high
-- ============================================================
INSERT INTO identities
    (organization_id, discovery_run_id, identity_id, display_name,
     identity_type, identity_category, risk_score, risk_level,
     activity_status, last_sign_in, created_datetime, enabled, is_microsoft_system,
     risk_reasons)
VALUES
    (3, 36, 'df000016-d3a0-4000-aaaa-aaaaaaaaa016', 'demo-joiner-fresh-admin',
     'user', 'human_user', 85, 'critical',
     'active', NOW() - INTERVAL '6 hours', NOW() - INTERVAL '7 days', TRUE, FALSE,
     ARRAY['joiner_with_owner', 'new_user_critical_role']),
    (3, 36, 'df000017-d3a0-4000-aaaa-aaaaaaaaa017', 'demo-joiner-new-sp',
     'service_principal', 'service_principal', 78, 'high',
     'active', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '14 days', TRUE, FALSE,
     ARRAY['joiner_with_owner', 'workload_provisioned_with_priv'])
ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
    risk_level = EXCLUDED.risk_level,
    created_datetime = EXCLUDED.created_datetime,
    is_microsoft_system = FALSE;

UPDATE identities SET is_microsoft_system=FALSE
WHERE organization_id=3 AND identity_id IN ('df000016-d3a0-4000-aaaa-aaaaaaaaa016','df000017-d3a0-4000-aaaa-aaaaaaaaa017');

-- Role assignments for the joiners (critical scope = "joiner with Owner")
DO $$
DECLARE _j1 BIGINT; _j2 BIGINT;
        _sub TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111';
BEGIN
    SELECT id INTO _j1 FROM identities WHERE organization_id=3 AND identity_id='df000016-d3a0-4000-aaaa-aaaaaaaaa016';
    SELECT id INTO _j2 FROM identities WHERE organization_id=3 AND identity_id='df000017-d3a0-4000-aaaa-aaaaaaaaa017';

    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, _j1, 'Owner', _sub, 'subscription', 'df000016-d3a0-4000-aaaa-aaaaaaaaa016', gen_random_uuid()::text
    WHERE _j1 IS NOT NULL
    ON CONFLICT DO NOTHING;

    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, _j2, 'Contributor', _sub, 'subscription', 'df000017-d3a0-4000-aaaa-aaaaaaaaa017', gen_random_uuid()::text
    WHERE _j2 IS NOT NULL
    ON CONFLICT DO NOTHING;
END $$;

-- ============================================================
-- 2. MOVERS — mover_stale_access anomalies
-- ============================================================
DELETE FROM anomalies
WHERE organization_id=3 AND anomaly_type='mover_stale_access'
  AND identity_id IN ('df000005-d3a0-4000-aaaa-aaaaaaaaa005','df000013-d3a0-4000-aaaa-aaaaaaaaa013');

INSERT INTO anomalies
    (organization_id, discovery_run_id, anomaly_type, severity, identity_id, identity_name,
     title, description, details, resolved, created_at)
VALUES
    (3, 36, 'mover_stale_access', 'high',
     'df000005-d3a0-4000-aaaa-aaaaaaaaa005', 'demo-dormant-admin-01',
     'Mover retains prior privileged access after department change',
     'demo-dormant-admin-01 moved from Cloud Engineering to Finance Analytics 45 days ago but still holds Owner on subscription. Prior privileged roles should be revoked on department change.',
     '{"prior_department":"Cloud Engineering","new_department":"Finance Analytics","days_since_move":45,"retained_roles":["Owner"]}'::jsonb,
     FALSE, NOW() - INTERVAL '12 hours'),
    (3, 36, 'mover_stale_access', 'medium',
     'df000013-d3a0-4000-aaaa-aaaaaaaaa013', 'demo-ai-priv-human-01',
     'Mover retains AI deployment access after role change',
     'demo-ai-priv-human-01 changed titles from AI Platform Engineer to Product Manager 21 days ago but still has Cognitive Services Contributor on the OpenAI account.',
     '{"prior_title":"AI Platform Engineer","new_title":"Product Manager","days_since_move":21,"retained_roles":["Cognitive Services Contributor"]}'::jsonb,
     FALSE, NOW() - INTERVAL '3 days')
ON CONFLICT DO NOTHING;

-- ============================================================
-- 3. LEAVERS — ghost identities (enabled=FALSE) with retained roles
-- df000007 (demo-ghost-acct-01) was created for this, just need to flip enabled
-- ============================================================
UPDATE identities SET enabled = FALSE
WHERE organization_id=3 AND identity_id='df000007-d3a0-4000-aaaa-aaaaaaaaa007';

-- Add one more clear leaver (terminated SP with role retained)
INSERT INTO identities
    (organization_id, discovery_run_id, identity_id, display_name,
     identity_type, identity_category, risk_score, risk_level,
     activity_status, last_sign_in, created_datetime, enabled, is_microsoft_system,
     risk_reasons)
VALUES
    (3, 36, 'df000018-d3a0-4000-aaaa-aaaaaaaaa018', 'demo-leaver-disabled-sp',
     'service_principal', 'service_principal', 82, 'critical',
     'stale', NOW() - INTERVAL '120 days', NOW() - INTERVAL '720 days', FALSE, FALSE,
     ARRAY['ghost_identity', 'disabled_with_roles_retained'])
ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
    enabled = FALSE,
    is_microsoft_system = FALSE;

UPDATE identities SET is_microsoft_system=FALSE
WHERE organization_id=3 AND identity_id='df000018-d3a0-4000-aaaa-aaaaaaaaa018';

DO $$
DECLARE _l BIGINT;
BEGIN
    SELECT id INTO _l FROM identities WHERE organization_id=3 AND identity_id='df000018-d3a0-4000-aaaa-aaaaaaaaa018';
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, _l, 'Contributor',
           '/subscriptions/11111111-1111-4111-1111-111111111111',
           'subscription', 'df000018-d3a0-4000-aaaa-aaaaaaaaa018', gen_random_uuid()::text
    WHERE _l IS NOT NULL
    ON CONFLICT DO NOTHING;
END $$;

-- ============================================================
-- 4. SETTINGS — enable p2_telemetry (turns Anomalies panel from amber to live)
-- ============================================================
INSERT INTO settings (organization_id, key, value, updated_at)
VALUES (3, 'p2_telemetry_enabled', 'true', NOW())
ON CONFLICT (organization_id, key) DO UPDATE SET value = 'true', updated_at = NOW();

-- ============================================================
-- 5. Recompute total_identities (now 297 — 295 + 2 joiners + 1 leaver - 1 already counted)
-- ============================================================
UPDATE discovery_runs SET total_identities = (
    SELECT count(*) FROM identities WHERE organization_id=3 AND discovery_run_id=36
) WHERE id = 36;

COMMIT;

\echo ''
\echo '=== Joiners (created < 30 days, critical/high) ==='
SELECT identity_id, display_name, risk_level, created_datetime::date FROM identities
WHERE organization_id=3 AND discovery_run_id=36
  AND created_datetime >= NOW() - INTERVAL '30 days'
  AND risk_level IN ('critical','high')
  AND NOT COALESCE(is_microsoft_system, false);

\echo ''
\echo '=== Movers (mover_stale_access) ==='
SELECT identity_id, identity_name, severity FROM anomalies
WHERE organization_id=3 AND anomaly_type='mover_stale_access' AND NOT resolved;

\echo ''
\echo '=== Leavers (enabled=FALSE with role_assignments) ==='
SELECT i.identity_id, i.display_name, i.enabled,
       (SELECT count(*) FROM role_assignments ra WHERE ra.identity_db_id=i.id) AS roles
FROM identities i
WHERE i.organization_id=3 AND i.discovery_run_id=36
  AND i.enabled = FALSE
ORDER BY i.identity_id;

\echo ''
\echo '=== p2_telemetry_enabled ==='
SELECT organization_id, key, value FROM settings WHERE organization_id=3 AND key='p2_telemetry_enabled';

\echo ''
\echo '=== Run 36 ==='
SELECT id, total_identities FROM discovery_runs WHERE id=36;
