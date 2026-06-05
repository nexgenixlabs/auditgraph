-- AIAG Cloud Demo FULL-FEATURE Seed for org_id=3 (auditgraph-demo)
-- Scope: ONLY org_id=3. Never touches any other tenant.
-- Fingerprint prefixes: 'de000*' (existing AI agents) and 'df000*' (new full-feature identities).
-- Idempotent: all 'df000*' rows are deleted + re-inserted on each run.
-- Resources: 'aiag-*' or '/subscriptions/11111111-%' fingerprint.

\set ON_ERROR_STOP on

BEGIN;

-- Pre-flight: refuse if there's no demo connection
DO $$
DECLARE _n INT;
BEGIN
    SELECT count(*) INTO _n FROM cloud_connections WHERE organization_id = 3;
    IF _n = 0 THEN
        RAISE EXCEPTION 'No cloud_connections row for org_id=3 — provision a connection first';
    END IF;
END $$;

-- RLS context (forced-policy tables need both)
SELECT set_config('app.current_organization_id', '3', true);
SELECT set_config('app.current_tenant_id', '3', true);

-- ============================================================
-- CLEANUP: only df000-* fingerprinted rows.
-- de000-* (existing 3 AI agents) preserved.
-- ============================================================
DELETE FROM agent_activity_events       WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM agent_behavior_anomalies    WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM workload_anomaly_events     WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM agent_data_reachability     WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM ai_agent_lifecycle_events   WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM identity_reachability       WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM privilege_drift_events      WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM federated_credentials       WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM pim_eligible_assignments
    WHERE identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'df000%');
DELETE FROM pim_activations
    WHERE identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'df000%');
DELETE FROM role_assignments            WHERE organization_id=3
    AND identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'df000%');
DELETE FROM agent_classifications       WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM identities                  WHERE organization_id=3 AND identity_id LIKE 'df000%';
DELETE FROM attack_paths                WHERE organization_id=3 AND (source_entity_id LIKE 'df000%' OR source_entity_id LIKE 'de000%');
DELETE FROM anomalies                   WHERE organization_id=3 AND (identity_id LIKE 'df000%' OR identity_id LIKE 'de000%');
DELETE FROM consent_grants              WHERE organization_id=3 AND client_app_id LIKE 'df000%';
DELETE FROM compliance_snapshots        WHERE organization_id=3 AND framework_key LIKE 'demo_%';
DELETE FROM ai_agent_lifecycle_events   WHERE organization_id=3 AND identity_id LIKE 'de000%';
DELETE FROM agent_data_reachability     WHERE organization_id=3 AND identity_id LIKE 'de000%';
DELETE FROM identity_reachability       WHERE organization_id=3 AND identity_id LIKE 'de000%';
DELETE FROM privilege_drift_events      WHERE organization_id=3 AND identity_id LIKE 'de000%';
DELETE FROM workload_anomaly_events     WHERE organization_id=3 AND identity_id LIKE 'de000%';
DELETE FROM agent_behavior_anomalies    WHERE organization_id=3 AND identity_id LIKE 'de000%';

-- ============================================================
-- SECTION 1: 12 new identities (df000*) across all gap categories
-- ============================================================
DO $$
DECLARE
    _run_id BIGINT := 36;  -- The visible demo run
BEGIN
    INSERT INTO identities
        (organization_id, discovery_run_id, identity_id, display_name,
         identity_type, identity_category, risk_score, risk_level,
         agent_identity_type, activity_status, last_sign_in, created_datetime,
         credential_expiration, credential_status, enabled, is_microsoft_system,
         risk_reasons)
    VALUES
    -- 04: Over-privileged SP (Subscription Owner) — attack path source
    (3, _run_id, 'df000004-d3a0-4000-aaaa-aaaaaaaaa004', 'demo-overprivileged-sp-01',
     'service_principal', 'service_principal', 95, 'critical',
     NULL, 'active', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '180 days',
     NOW() + INTERVAL '60 days', 'valid', TRUE, FALSE,
     ARRAY['subscription_owner_scope', 'over_privileged']),
    -- 05: Dormant admin (Owner, 95 days no login)
    (3, _run_id, 'df000005-d3a0-4000-aaaa-aaaaaaaaa005', 'demo-dormant-admin-01',
     'user', 'human_user', 88, 'critical',
     NULL, 'dormant', NOW() - INTERVAL '95 days', NOW() - INTERVAL '730 days',
     NULL, NULL, TRUE, FALSE,
     ARRAY['dormant_privileged', 'no_recent_activity']),
    -- 06: Dormant admin (KV Admin, 87 days no login)
    (3, _run_id, 'df000006-d3a0-4000-aaaa-aaaaaaaaa006', 'demo-dormant-admin-02',
     'user', 'human_user', 82, 'critical',
     NULL, 'dormant', NOW() - INTERVAL '87 days', NOW() - INTERVAL '540 days',
     NULL, NULL, TRUE, FALSE,
     ARRAY['dormant_privileged', 'key_vault_admin']),
    -- 07: Ghost account (terminated user, still enabled)
    (3, _run_id, 'df000007-d3a0-4000-aaaa-aaaaaaaaa007', 'demo-ghost-acct-01',
     'user', 'human_user', 70, 'high',
     NULL, 'stale', NOW() - INTERVAL '180 days', NOW() - INTERVAL '900 days',
     NULL, NULL, TRUE, FALSE,
     ARRAY['ghost_account', 'terminated_still_enabled']),
    -- 08: Stale credentials (SP with expired secret)
    (3, _run_id, 'df000008-d3a0-4000-aaaa-aaaaaaaaa008', 'demo-stale-creds-01',
     'service_principal', 'service_principal', 65, 'high',
     NULL, 'active', NOW() - INTERVAL '2 days', NOW() - INTERVAL '270 days',
     NOW() - INTERVAL '30 days', 'expired', TRUE, FALSE,
     ARRAY['expired_credentials', 'credential_rotation_overdue']),
    -- 09: Federated trust (legit GitHub Actions)
    (3, _run_id, 'df000009-d3a0-4000-aaaa-aaaaaaaaa009', 'demo-federated-trust-01',
     'service_principal', 'service_principal', 35, 'low',
     NULL, 'active', NOW() - INTERVAL '6 hours', NOW() - INTERVAL '90 days',
     NULL, 'federated', TRUE, FALSE,
     ARRAY['federated_credential', 'github_actions']),
    -- 10: Federated trust (weak audience match)
    (3, _run_id, 'df000010-d3a0-4000-aaaa-aaaaaaaaa010', 'demo-federated-trust-02',
     'service_principal', 'service_principal', 78, 'high',
     NULL, 'active', NOW() - INTERVAL '12 hours', NOW() - INTERVAL '60 days',
     NULL, 'federated', TRUE, FALSE,
     ARRAY['federated_credential', 'weak_audience_match', 'any_tenant_trust']),
    -- 11: AI multimodal agent (gpt-4o + dall-e + embeddings)
    (3, _run_id, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'demo-ai-multimodal-prod',
     'service_principal', 'service_principal', 78, 'high',
     'ai_agent', 'active', NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '90 days',
     NOW() + INTERVAL '180 days', 'valid', TRUE, FALSE,
     ARRAY['multi_model_usage', 'ai_agent']),
    -- 12: AI fine-tune agent (custom models)
    (3, _run_id, 'df000012-d3a0-4000-aaaa-aaaaaaaaa012', 'demo-ai-finetuner',
     'service_principal', 'service_principal', 68, 'high',
     'ai_agent', 'active', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '75 days',
     NULL, 'valid', TRUE, FALSE,
     ARRAY['ai_agent', 'custom_model_deployment']),
    -- 13: Human with AI deployment access (ai_privileged_human)
    (3, _run_id, 'df000013-d3a0-4000-aaaa-aaaaaaaaa013', 'demo-ai-priv-human-01',
     'user', 'human_user', 72, 'high',
     'ai_privileged_human', 'active', NOW() - INTERVAL '4 hours', NOW() - INTERVAL '365 days',
     NULL, NULL, TRUE, FALSE,
     ARRAY['ai_privileged_human', 'can_deploy_models']),
    -- 14: PIM eligible (Owner, never activated)
    (3, _run_id, 'df000014-d3a0-4000-aaaa-aaaaaaaaa014', 'demo-pim-eligible-01',
     'user', 'human_user', 55, 'medium',
     NULL, 'active', NOW() - INTERVAL '1 day', NOW() - INTERVAL '270 days',
     NULL, NULL, TRUE, FALSE,
     ARRAY['pim_eligible_owner', 'standing_eligible']),
    -- 15: PIM overuse (frequent activations + off-hours)
    (3, _run_id, 'df000015-d3a0-4000-aaaa-aaaaaaaaa015', 'demo-pim-overuse-01',
     'user', 'human_user', 80, 'high',
     NULL, 'active', NOW() - INTERVAL '6 hours', NOW() - INTERVAL '450 days',
     NULL, NULL, TRUE, FALSE,
     ARRAY['pim_overuse', 'off_hours_activation', 'frequent_admin_use'])
    ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        risk_score = EXCLUDED.risk_score,
        risk_level = EXCLUDED.risk_level,
        activity_status = EXCLUDED.activity_status,
        risk_reasons = EXCLUDED.risk_reasons,
        is_microsoft_system = FALSE;

    -- Force is_microsoft_system to FALSE (trigger bug)
    UPDATE identities SET is_microsoft_system = FALSE
    WHERE organization_id = 3 AND (identity_id LIKE 'df000%' OR identity_id LIKE 'de000%');

    RAISE NOTICE '✓ Inserted 12 new df000-* demo identities on run 36';
END $$;

-- ============================================================
-- SECTION 2: agent_classifications for the 3 new AI agents (df0001[1-3])
-- ============================================================
INSERT INTO agent_classifications
    (identity_db_id, identity_id, agent_identity_type, classification_confidence,
     classification_reason, detected_platform, pattern_version, discovery_run_id,
     organization_id, model_name, owner_display_name_at_classify, account_resource_id)
SELECT i.id, i.identity_id,
       CASE i.identity_id
            WHEN 'df000013-d3a0-4000-aaaa-aaaaaaaaa013' THEN 'ai_privileged_human'
            ELSE 'ai_agent'
       END,
       0.93, 'aiag_cloud_demo_full_feature',
       'azure_openai', '1.0.0', 36, 3,
       CASE i.identity_id
            WHEN 'df000011-d3a0-4000-aaaa-aaaaaaaaa011' THEN 'gpt-4o,dall-e-3,text-embedding-3-large'
            WHEN 'df000012-d3a0-4000-aaaa-aaaaaaaaa012' THEN 'gpt-4o-mini-ft-v1,gpt-4o-mini-ft-v2'
            WHEN 'df000013-d3a0-4000-aaaa-aaaaaaaaa013' THEN NULL
            ELSE 'gpt-4o'
       END,
       'AuditGraph Demo Platform Team',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod'
FROM identities i
WHERE i.organization_id = 3
  AND i.identity_id IN ('df000011-d3a0-4000-aaaa-aaaaaaaaa011',
                        'df000012-d3a0-4000-aaaa-aaaaaaaaa012',
                        'df000013-d3a0-4000-aaaa-aaaaaaaaa013')
  AND i.discovery_run_id = 36
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 3: role_assignments — privileged & escalation patterns
-- ============================================================
DO $$
DECLARE
    _sub TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111';
    _kv_phi TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi';
    _kv_secrets TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-secrets';
    _storage_phi TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01';
    _cosmos TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.DocumentDB/databaseAccounts/aiag-cosmos-pii';
    _sql_srv TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Sql/servers/aiag-sql-pci';
    _cog TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod';
BEGIN
    -- df000004: Subscription Owner (over-privileged SP)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Owner', _sub, 'subscription', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000004-d3a0-4000-aaaa-aaaaaaaaa004'
    ON CONFLICT DO NOTHING;

    -- df000005: Owner on subscription (dormant admin)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Owner', _sub, 'subscription', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000005-d3a0-4000-aaaa-aaaaaaaaa005'
    ON CONFLICT DO NOTHING;

    -- df000006: KV Admin (dormant admin)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Key Vault Administrator', _kv_secrets, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000006-d3a0-4000-aaaa-aaaaaaaaa006'
    ON CONFLICT DO NOTHING;

    -- df000007: Reader (ghost account)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Reader', _sub, 'subscription', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000007-d3a0-4000-aaaa-aaaaaaaaa007'
    ON CONFLICT DO NOTHING;

    -- df000008: Storage Blob Data Contributor (stale creds SP)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Storage Blob Data Contributor', _storage_phi, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000008-d3a0-4000-aaaa-aaaaaaaaa008'
    ON CONFLICT DO NOTHING;

    -- df000009: Contributor (federated, legit)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Contributor', _sub || '/resourceGroups/rg-aiag-demo', 'resource_group', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000009-d3a0-4000-aaaa-aaaaaaaaa009'
    ON CONFLICT DO NOTHING;

    -- df000010: Storage Blob Data Owner (federated weak)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Storage Blob Data Owner', _storage_phi, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000010-d3a0-4000-aaaa-aaaaaaaaa010'
    ON CONFLICT DO NOTHING;

    -- df000011: Multi-model AI — Cognitive Services User + Storage Blob Reader + Cosmos Reader
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, ra.rn, ra.sc, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i,
         (VALUES ('Cognitive Services OpenAI User', _cog),
                 ('Storage Blob Data Reader', _storage_phi),
                 ('Cosmos DB Account Reader Role', _cosmos)
         ) AS ra(rn, sc)
    WHERE i.organization_id=3 AND i.identity_id='df000011-d3a0-4000-aaaa-aaaaaaaaa011'
    ON CONFLICT DO NOTHING;

    -- df000012: Fine-tune AI — Cognitive Services Contributor + Storage Contributor
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, ra.rn, ra.sc, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i,
         (VALUES ('Cognitive Services Contributor', _cog),
                 ('Storage Blob Data Contributor', _storage_phi)
         ) AS ra(rn, sc)
    WHERE i.organization_id=3 AND i.identity_id='df000012-d3a0-4000-aaaa-aaaaaaaaa012'
    ON CONFLICT DO NOTHING;

    -- df000013: AI-priv human — Cognitive Services Contributor (can deploy)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Cognitive Services Contributor', _cog, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000013-d3a0-4000-aaaa-aaaaaaaaa013'
    ON CONFLICT DO NOTHING;

    -- df000015: User Administrator (PIM overuse)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Contributor', _sub, 'subscription', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000015-d3a0-4000-aaaa-aaaaaaaaa015'
    ON CONFLICT DO NOTHING;

    RAISE NOTICE '✓ role_assignments seeded for 11 of 12 new identities';
END $$;

-- ============================================================
-- SECTION 4: Additional resources (for attack paths to reach)
-- ============================================================
INSERT INTO azure_key_vaults
    (organization_id, discovery_run_id, subscription_id, resource_id,
     resource_group, name, location, public_network_access,
     default_network_action, private_endpoint_count, secrets_total)
VALUES
    (3, 36, '11111111-1111-4111-1111-111111111111',
     '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-secrets',
     'rg-aiag-demo', 'aiag-vault-secrets', 'eastus', 'Disabled', 'Deny', 1, 28)
ON CONFLICT DO NOTHING;

-- Cosmos PII + SQL PCI resource rows skipped: cloud schema lags local on
-- these tables (missing name/classification columns). Data classification
-- for these targets is encoded directly in agent_data_reachability rows
-- below — the attack path narratives reference resources by ID only.

-- ============================================================
-- SECTION 5: Multi-model AI deployments on aiag-openai-prod
-- ============================================================
DO $$
DECLARE
    _cog_acct TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod';
BEGIN
    INSERT INTO azure_ai_model_deployments
        (organization_id, discovery_run_id, account_resource_id, account_name,
         deployment_name, model_name, model_version, model_format, sku_name, sku_capacity, provisioning_state)
    VALUES
        (3, 36, _cog_acct, 'aiag-openai-prod', 'gpt-4o-prod',           'gpt-4o',                  '2024-11-20', 'OpenAI', 'GlobalStandard', 50,  'Succeeded'),
        (3, 36, _cog_acct, 'aiag-openai-prod', 'gpt-4o-mini',           'gpt-4o-mini',             '2024-07-18', 'OpenAI', 'GlobalStandard', 100, 'Succeeded'),
        (3, 36, _cog_acct, 'aiag-openai-prod', 'embedding-large',       'text-embedding-3-large',  '1',          'OpenAI', 'Standard',       30,  'Succeeded'),
        (3, 36, _cog_acct, 'aiag-openai-prod', 'dalle-3-image',         'dall-e-3',                '3.0',        'OpenAI', 'Standard',       2,   'Succeeded'),
        (3, 36, _cog_acct, 'aiag-openai-prod', 'gpt-4o-mini-ft-v1',     'gpt-4o-mini-ft-2024-07-18-ag-v1', '1', 'OpenAI', 'Standard',       5,   'Succeeded'),
        (3, 36, _cog_acct, 'aiag-openai-prod', 'gpt-4o-mini-ft-v2',     'gpt-4o-mini-ft-2024-07-18-ag-v2', '2', 'OpenAI', 'Standard',       5,   'Succeeded')
    ON CONFLICT DO NOTHING;
    RAISE NOTICE '✓ 6 model deployments on aiag-openai-prod';
END $$;

-- ============================================================
-- SECTION 6: attack_paths (privilege escalation chains)
-- ============================================================
DO $$
DECLARE
    _kv_phi TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi';
    _storage_phi TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01';
    _sub TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111';
    _copilot_id INT;
    _rag_id INT;
    _multi_id INT;
    _opsp_id INT;
    _dorm_id INT;
    _fed_id INT;
BEGIN
    SELECT id INTO _copilot_id FROM identities WHERE organization_id=3 AND identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001';
    SELECT id INTO _rag_id     FROM identities WHERE organization_id=3 AND identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002';
    SELECT id INTO _multi_id   FROM identities WHERE organization_id=3 AND identity_id='df000011-d3a0-4000-aaaa-aaaaaaaaa011';
    SELECT id INTO _opsp_id    FROM identities WHERE organization_id=3 AND identity_id='df000004-d3a0-4000-aaaa-aaaaaaaaa004';
    SELECT id INTO _dorm_id    FROM identities WHERE organization_id=3 AND identity_id='df000005-d3a0-4000-aaaa-aaaaaaaaa005';
    SELECT id INTO _fed_id     FROM identities WHERE organization_id=3 AND identity_id='df000010-d3a0-4000-aaaa-aaaaaaaaa010';

    INSERT INTO attack_paths
        (organization_id, discovery_run_id, source_entity_id, source_entity_name, source_entity_type,
         path_type, risk_score, severity, path_nodes, description, narrative, impact,
         path_fingerprint, target_resource_id, target_resource_type, identity_id,
         highest_role, highest_scope_level, path_risk_score, path_risk_tier,
         has_keyvault_access, has_subscription_scope, has_expired_credentials,
         path_length, affected_resource_count)
    VALUES
    -- 1: AI copilot → KV Admin → secret exfil
    (3, 36, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'demo-ai-copilot-prod', 'ai_agent',
     'ai_agent_secret_exfil', 95, 'critical',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','de000001-d3a0-4000-aaaa-aaaaaaaaa001','name','demo-ai-copilot-prod'),
        jsonb_build_object('type','role','name','Key Vault Administrator'),
        jsonb_build_object('type','resource','id',_kv_phi,'name','aiag-vault-phi'),
        jsonb_build_object('type','data','classification','PHI','records',14)
     ),
     'AI agent demo-ai-copilot-prod has KV Admin on aiag-vault-phi — can read all 14 PHI-classified secrets',
     'demo-ai-copilot-prod is an AI agent with Key Vault Administrator role on the PHI-classified vault. A prompt-injection attack on the agent could exfiltrate all 14 secrets including database passwords and API keys.',
     'Full secret-store compromise · MITRE T1213 (Data from Information Repositories) + T1552 (Unsecured Credentials)',
     'ai_copilot_kv_admin_phi', _kv_phi, 'key_vault', _copilot_id,
     'Key Vault Administrator', 'resource', 95, 'critical', TRUE, FALSE, FALSE, 3, 1),

    -- 2: AI copilot → Storage Blob Owner → PHI exfil
    (3, 36, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'demo-ai-copilot-prod', 'ai_agent',
     'ai_agent_data_exfil', 92, 'critical',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','de000001-d3a0-4000-aaaa-aaaaaaaaa001','name','demo-ai-copilot-prod'),
        jsonb_build_object('type','role','name','Storage Blob Data Owner'),
        jsonb_build_object('type','resource','id',_storage_phi,'name','aiagphiblob01'),
        jsonb_build_object('type','data','classification','PHI','records',120000)
     ),
     'AI agent demo-ai-copilot-prod has Storage Blob Data Owner on PHI storage (120K records)',
     'demo-ai-copilot-prod can read/write any blob in aiagphiblob01, which is tagged PHI with an estimated 120,000 patient records. Compromise of the agent would expose all PHI data.',
     '120K PHI records · MITRE T1530 (Data from Cloud Storage Object)',
     'ai_copilot_blob_owner_phi', _storage_phi, 'storage_account', _copilot_id,
     'Storage Blob Data Owner', 'resource', 92, 'critical', FALSE, FALSE, FALSE, 3, 1),

    -- 3: Over-privileged SP → Subscription Owner
    (3, 36, 'df000004-d3a0-4000-aaaa-aaaaaaaaa004', 'demo-overprivileged-sp-01', 'service_principal',
     'sub_owner_sp', 90, 'critical',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','df000004-d3a0-4000-aaaa-aaaaaaaaa004','name','demo-overprivileged-sp-01'),
        jsonb_build_object('type','role','name','Owner'),
        jsonb_build_object('type','scope','type','subscription','id',_sub)
     ),
     'Service principal demo-overprivileged-sp-01 has Owner on entire subscription',
     'demo-overprivileged-sp-01 is a service principal with Owner permission on the whole subscription. SP compromise would give an attacker full subscription control: create resources, exfiltrate data, pivot to other tenants.',
     'Full subscription compromise · MITRE T1078.004 (Cloud Accounts)',
     'opsp_sub_owner', _sub, 'subscription', _opsp_id,
     'Owner', 'subscription', 90, 'critical', FALSE, TRUE, FALSE, 2, 50),

    -- 4: Dormant admin → Owner role
    (3, 36, 'df000005-d3a0-4000-aaaa-aaaaaaaaa005', 'demo-dormant-admin-01', 'human_user',
     'dormant_privileged', 85, 'critical',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','df000005-d3a0-4000-aaaa-aaaaaaaaa005','name','demo-dormant-admin-01','dormant_days',95),
        jsonb_build_object('type','role','name','Owner'),
        jsonb_build_object('type','scope','type','subscription','id',_sub)
     ),
     'Human demo-dormant-admin-01 is dormant (95 days) but still holds Owner on subscription',
     'demo-dormant-admin-01 has not signed in for 95 days but retains Owner permissions on the subscription. Account takeover via password spray or credential reuse would yield full subscription control with low detection risk (no recent activity baseline).',
     'Stale credential abuse path · MITRE T1078.004',
     'dormant_admin_sub_owner', _sub, 'subscription', _dorm_id,
     'Owner', 'subscription', 85, 'critical', FALSE, TRUE, FALSE, 2, 50),

    -- 5: Federated trust weak → blob owner
    (3, 36, 'df000010-d3a0-4000-aaaa-aaaaaaaaa010', 'demo-federated-trust-02', 'service_principal',
     'weak_federated_trust', 78, 'high',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','df000010-d3a0-4000-aaaa-aaaaaaaaa010','name','demo-federated-trust-02'),
        jsonb_build_object('type','federated_trust','issuer','any-tenant','audience','*'),
        jsonb_build_object('type','role','name','Storage Blob Data Owner'),
        jsonb_build_object('type','resource','id',_storage_phi,'name','aiagphiblob01')
     ),
     'demo-federated-trust-02 has weak federated audience match + Storage Blob Owner on PHI',
     'demo-federated-trust-02 trusts ANY OIDC issuer (audience=*) — an attacker controlling any OIDC IdP can mint tokens for this SP and gain Storage Blob Owner on PHI data.',
     'External IdP compromise → 120K PHI records · MITRE T1199 (Trusted Relationship)',
     'weak_fed_blob_owner', _storage_phi, 'storage_account', _fed_id,
     'Storage Blob Data Owner', 'resource', 78, 'high', FALSE, FALSE, FALSE, 4, 1),

    -- 6: Multimodal AI → multi-data class
    (3, 36, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'demo-ai-multimodal-prod', 'ai_agent',
     'ai_agent_multi_data_class', 75, 'high',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','df000011-d3a0-4000-aaaa-aaaaaaaaa011','name','demo-ai-multimodal-prod'),
        jsonb_build_object('type','role','name','Storage Blob Data Reader+Cosmos DB Reader'),
        jsonb_build_object('type','resource','classes',jsonb_build_array('PHI','PII'))
     ),
     'demo-ai-multimodal-prod reads BOTH PHI (storage) and PII (cosmos)',
     'demo-ai-multimodal-prod has reader access to two data classifications: PHI in aiagphiblob01 (120K) and PII in aiag-cosmos-pii (50K). Cross-classification AI agents create concentrated breach impact.',
     'Multi-class data reachability · MITRE T1530 + T1213',
     'multimodal_multi_class', _storage_phi, 'storage_account', _multi_id,
     'Storage Blob Data Reader', 'resource', 75, 'high', FALSE, FALSE, FALSE, 3, 2),

    -- 7: AI rag indexer → storage reader
    (3, 36, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'demo-ai-rag-indexer', 'ai_agent',
     'ai_agent_data_read', 70, 'high',
     jsonb_build_array(
        jsonb_build_object('type','identity','id','de000002-d3a0-4000-aaaa-aaaaaaaaa002','name','demo-ai-rag-indexer'),
        jsonb_build_object('type','role','name','Storage Blob Data Reader'),
        jsonb_build_object('type','resource','id',_storage_phi,'name','aiagphiblob01')
     ),
     'demo-ai-rag-indexer reads PHI blob storage for RAG indexing',
     'demo-ai-rag-indexer indexes 120K patient records for RAG retrieval. Prompt injection could cause selective PHI disclosure via the model.',
     '120K PHI records readable via RAG · MITRE T1530',
     'rag_blob_reader_phi', _storage_phi, 'storage_account', _rag_id,
     'Storage Blob Data Reader', 'resource', 70, 'high', FALSE, FALSE, FALSE, 3, 1)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE '✓ 7 attack paths seeded';
END $$;

-- ============================================================
-- SECTION 7: consent_grants (OAuth)
-- ============================================================
INSERT INTO consent_grants
    (organization_id, discovery_run_id, grant_type, client_app_id, client_display_name,
     resource_app_id, resource_display_name, scopes, consent_type,
     principal_display_name, created_datetime, expires_at, last_activity_at,
     risk_score, risk_level, high_risk_scopes, age_days, evidence_source,
     publisher_name, publisher_domain, verified_publisher)
VALUES
    -- 1: HIGH-RISK admin-consent app (Mail+Files full access)
    (3, 36, 'application',
     'df00app1-0000-0000-0000-000000000001', 'Productivity Plus',
     '00000003-0000-0000-c000-000000000000', 'Microsoft Graph',
     ARRAY['Mail.ReadWrite','Files.ReadWrite.All','User.Read.All'], 'AllPrincipals',
     NULL, NOW() - INTERVAL '180 days', NULL, NOW() - INTERVAL '2 days',
     85, 'high', ARRAY['Mail.ReadWrite','Files.ReadWrite.All'], 180, 'graph',
     'ProductivityPlus Inc', 'productivityplus.example', FALSE),

    -- 2: CRITICAL admin-consent (Sites.FullControl)
    (3, 36, 'application',
     'df00app2-0000-0000-0000-000000000002', 'DocAnalyzer Cloud',
     '00000003-0000-0000-c000-000000000000', 'Microsoft Graph',
     ARRAY['Sites.FullControl.All','Files.ReadWrite.All'], 'AllPrincipals',
     NULL, NOW() - INTERVAL '90 days', NULL, NOW() - INTERVAL '1 day',
     95, 'critical', ARRAY['Sites.FullControl.All','Files.ReadWrite.All'], 90, 'graph',
     'DocAnalyzer Cloud Ltd', 'docanalyzer.example', FALSE),

    -- 3: HIGH admin consent — ChatBuddy (calendars+mail)
    (3, 36, 'application',
     'df00app3-0000-0000-0000-000000000003', 'ChatBuddy AI',
     '00000003-0000-0000-c000-000000000000', 'Microsoft Graph',
     ARRAY['Calendars.ReadWrite','Mail.Read','User.Read.All'], 'AllPrincipals',
     NULL, NOW() - INTERVAL '45 days', NULL, NOW() - INTERVAL '3 hours',
     78, 'high', ARRAY['Calendars.ReadWrite','Mail.Read'], 45, 'graph',
     'ChatBuddy AI', 'chatbuddy.example', TRUE),

    -- 4: MEDIUM user-consented
    (3, 36, 'delegated',
     'df00app4-0000-0000-0000-000000000004', 'SimpleSurvey Pro',
     '00000003-0000-0000-c000-000000000000', 'Microsoft Graph',
     ARRAY['User.Read','offline_access'], 'Principal',
     'AmandaThompson@auditgraph-demo.onmicrosoft.com', NOW() - INTERVAL '30 days', NULL, NOW() - INTERVAL '6 hours',
     45, 'medium', ARRAY[]::text[], 30, 'graph',
     'SimpleSurvey LLC', 'simplesurvey.example', TRUE),

    -- 5: LOW stale (admin consent, no activity 200+ days)
    (3, 36, 'application',
     'df00app5-0000-0000-0000-000000000005', 'LegacyConnector v1',
     '00000003-0000-0000-c000-000000000000', 'Microsoft Graph',
     ARRAY['Directory.Read.All'], 'AllPrincipals',
     NULL, NOW() - INTERVAL '600 days', NULL, NOW() - INTERVAL '210 days',
     55, 'medium', ARRAY['Directory.Read.All'], 600, 'graph',
     'Legacy Apps Inc', 'legacyapps.example', FALSE)
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 8: anomalies (org-level)
-- ============================================================
INSERT INTO anomalies
    (organization_id, discovery_run_id, anomaly_type, severity, identity_id, identity_name,
     title, description, details, resolved, created_at)
VALUES
    (3, 36, 'permission_escalation', 'critical',
     'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'demo-ai-copilot-prod',
     'AI agent escalated from Reader to KV Administrator',
     'demo-ai-copilot-prod gained Key Vault Administrator role on aiag-vault-phi within the last 24h. Previous role was Reader. This is a 6-tier escalation with no associated change ticket.',
     jsonb_build_object('prior_role','Reader','new_role','Key Vault Administrator','resource','aiag-vault-phi','escalation_tier_delta',6),
     FALSE, NOW() - INTERVAL '8 hours'),

    (3, 36, 'dormant_reactivation', 'high',
     'df000007-d3a0-4000-aaaa-aaaaaaaaa007', 'demo-ghost-acct-01',
     'Dormant account reactivated after 180 days',
     'demo-ghost-acct-01 signed in for the first time in 180+ days. Account is classified as ghost (former employee). HR records indicate termination effective 2025-12-01.',
     jsonb_build_object('dormant_days',180,'classification','ghost','hr_status','terminated'),
     FALSE, NOW() - INTERVAL '4 hours'),

    (3, 36, 'credential_surge', 'high',
     'df000008-d3a0-4000-aaaa-aaaaaaaaa008', 'demo-stale-creds-01',
     '3 new client secrets created in 24h',
     'demo-stale-creds-01 had 3 client secrets created within the last 24 hours. Combined with expired previous secret, this is a credential-stuffing recovery pattern.',
     jsonb_build_object('new_secrets',3,'window_hours',24,'expired_secret_count',1),
     FALSE, NOW() - INTERVAL '12 hours'),

    (3, 36, 'off_hours_pim', 'medium',
     'df000015-d3a0-4000-aaaa-aaaaaaaaa015', 'demo-pim-overuse-01',
     'PIM activation at 03:00 UTC',
     'demo-pim-overuse-01 activated User Administrator at 03:00 UTC outside their normal 09:00-17:00 PT window. Activation was approved by automated policy (no human reviewer).',
     jsonb_build_object('activation_hour_utc',3,'role','User Administrator','approval','automated'),
     FALSE, NOW() - INTERVAL '1 day'),

    (3, 36, 'risk_score_spike', 'high',
     'df000004-d3a0-4000-aaaa-aaaaaaaaa004', 'demo-overprivileged-sp-01',
     'Risk score jumped 30 points in 24h',
     'demo-overprivileged-sp-01 risk score increased from 65 to 95 over the last 24h. Driver: new Owner-scoped assignment on subscription.',
     jsonb_build_object('prior_score',65,'new_score',95,'delta',30,'driver','new_subscription_owner_assignment'),
     FALSE, NOW() - INTERVAL '6 hours'),

    (3, 36, 'ai_volume_spike', 'high',
     'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'demo-ai-copilot-prod',
     'AI agent model calls 5× baseline',
     'demo-ai-copilot-prod made 5,000 model calls in the last 24h vs. 1,000-call baseline. Burst pattern is characteristic of automated abuse or data-exfil via prompt-stuffing.',
     jsonb_build_object('observed',5000,'baseline',1000,'delta_pct',400),
     FALSE, NOW() - INTERVAL '2 hours')
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 9: workload_anomaly_events (AI agent specific)
-- ============================================================
INSERT INTO workload_anomaly_events
    (organization_id, identity_db_id, identity_id, anomaly_type, severity, title, description,
     evidence, baseline, detected_value, discovery_run_id, created_at)
SELECT 3, i.id, i.identity_id, 'volume_spike', 'critical',
       'AI agent call volume 5× baseline',
       'Model call volume for demo-ai-copilot-prod surged from 1,000 calls/day to 5,000 calls/day in the last 24h.',
       jsonb_build_object('window','24h','signal','call_count'),
       jsonb_build_object('mean',1000,'stddev',150),
       jsonb_build_object('observed',5000), 36, NOW() - INTERVAL '2 hours'
FROM identities i WHERE i.organization_id=3 AND i.identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001'
ON CONFLICT DO NOTHING;

INSERT INTO workload_anomaly_events
    (organization_id, identity_db_id, identity_id, anomaly_type, severity, title, description,
     evidence, baseline, detected_value, discovery_run_id, created_at)
SELECT 3, i.id, i.identity_id, 'new_resource_access', 'high',
       'AI agent accessed previously-unseen resource',
       'demo-ai-rag-indexer accessed aiag-cosmos-pii for the first time. Resource was not in the agent baseline access pattern.',
       jsonb_build_object('new_resource','aiag-cosmos-pii','first_access_at',(NOW() - INTERVAL '8 hours')::text),
       jsonb_build_object('resources_accessed_30d',1),
       jsonb_build_object('resources_accessed_today',2), 36, NOW() - INTERVAL '8 hours'
FROM identities i WHERE i.organization_id=3 AND i.identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002'
ON CONFLICT DO NOTHING;

INSERT INTO workload_anomaly_events
    (organization_id, identity_db_id, identity_id, anomaly_type, severity, title, description,
     evidence, baseline, detected_value, discovery_run_id, created_at)
SELECT 3, i.id, i.identity_id, 'model_added', 'medium',
       'New model attached to AI agent',
       'demo-ai-multimodal-prod added dall-e-3 to its model usage. The agent now uses 3 distinct models including a multimodal image generation model.',
       jsonb_build_object('added_model','dall-e-3','category','image_generation'),
       jsonb_build_object('models_in_use',2),
       jsonb_build_object('models_in_use',3), 36, NOW() - INTERVAL '5 days'
FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000011-d3a0-4000-aaaa-aaaaaaaaa011'
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 10: agent_behavior_anomalies
-- ============================================================
INSERT INTO agent_behavior_anomalies
    (organization_id, identity_db_id, identity_id, anomaly_type, severity,
     baseline_value, observed_value, delta_pct, description)
SELECT 3, i.id, i.identity_id, 'volume_spike', 'critical',
       1000.0, 5000.0, 400.0,
       'AI agent inference volume 5× baseline mean over last 24h.'
FROM identities i WHERE i.organization_id=3 AND i.identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001'
ON CONFLICT DO NOTHING;

INSERT INTO agent_behavior_anomalies
    (organization_id, identity_db_id, identity_id, anomaly_type, severity,
     baseline_value, observed_value, delta_pct, description)
SELECT 3, i.id, i.identity_id, 'data_read_burst', 'high',
       250.0, 1200.0, 380.0,
       'Storage read volume 4.8× baseline. New resource (cosmos) added to read pattern.'
FROM identities i WHERE i.organization_id=3 AND i.identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002'
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 11: ai_agent_lifecycle_events
-- ============================================================
DO $$
DECLARE _copilot INT;
        _rag INT;
        _multi INT;
        _ft INT;
BEGIN
    SELECT id INTO _copilot FROM identities WHERE organization_id=3 AND identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001';
    SELECT id INTO _rag     FROM identities WHERE organization_id=3 AND identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002';
    SELECT id INTO _multi   FROM identities WHERE organization_id=3 AND identity_id='df000011-d3a0-4000-aaaa-aaaaaaaaa011';
    SELECT id INTO _ft      FROM identities WHERE organization_id=3 AND identity_id='df000012-d3a0-4000-aaaa-aaaaaaaaa012';

    -- Single-row INSERTs (multi-row VALUES caused "lists must all be same length"
    -- on the cloud psql even though local accepted it — defensive)
    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'created', 'low',
            NOW() - INTERVAL '120 days', NULL,
            '{"agent_type":"ai_agent","model":"gpt-4o"}'::jsonb,
            'AI agent demo-ai-copilot-prod created.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'role_granted', 'medium',
            NOW() - INTERVAL '60 days',
            '{"roles":["Reader"]}'::jsonb,
            '{"roles":["Reader","Storage Blob Data Reader"]}'::jsonb,
            'Storage Blob Data Reader granted.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'privilege_escalation', 'critical',
            NOW() - INTERVAL '8 hours',
            '{"roles":["Reader","Storage Blob Data Reader"]}'::jsonb,
            '{"roles":["Key Vault Administrator","Storage Blob Data Owner"]}'::jsonb,
            'Massive privilege escalation: gained KV Admin + Blob Owner.',
            '["T1078.004","T1098"]'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _rag, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'created', 'low',
            NOW() - INTERVAL '60 days', NULL,
            '{"agent_type":"ai_agent","model":"text-embedding-3-large"}'::jsonb,
            'AI agent demo-ai-rag-indexer created.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _rag, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'role_granted', 'medium',
            NOW() - INTERVAL '30 days', NULL,
            '{"roles":["Storage Blob Data Reader"]}'::jsonb,
            'Storage Blob Data Reader granted on aiagphiblob01.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _multi, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'created', 'low',
            NOW() - INTERVAL '90 days', NULL,
            '{"agent_type":"ai_agent","models":["gpt-4o"]}'::jsonb,
            'Multimodal AI agent created.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _multi, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'model_added', 'medium',
            NOW() - INTERVAL '5 days',
            '{"models":["gpt-4o","text-embedding-3-large"]}'::jsonb,
            '{"models":["gpt-4o","text-embedding-3-large","dall-e-3"]}'::jsonb,
            'Added dall-e-3 multimodal image generation model.',
            '["T1588"]'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _ft, 'df000012-d3a0-4000-aaaa-aaaaaaaaa012', 'created', 'low',
            NOW() - INTERVAL '75 days', NULL,
            '{"agent_type":"ai_agent","purpose":"fine_tuning"}'::jsonb,
            'Fine-tune AI agent created.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _ft, 'df000012-d3a0-4000-aaaa-aaaaaaaaa012', 'custom_model_deployed', 'high',
            NOW() - INTERVAL '20 days',
            '{"custom_models":[]}'::jsonb,
            '{"custom_models":["gpt-4o-mini-ft-v1","gpt-4o-mini-ft-v2"]}'::jsonb,
            'Two custom fine-tuned models deployed.', NULL)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE '✓ 9 AI lifecycle events seeded';
END $$;

-- ============================================================
-- SECTION 12: federated_credentials
-- ============================================================
DO $$
DECLARE _fed1 INT; _fed2 INT;
BEGIN
    SELECT id INTO _fed1 FROM identities WHERE organization_id=3 AND identity_id='df000009-d3a0-4000-aaaa-aaaaaaaaa009';
    SELECT id INTO _fed2 FROM identities WHERE organization_id=3 AND identity_id='df000010-d3a0-4000-aaaa-aaaaaaaaa010';

    INSERT INTO federated_credentials
        (organization_id, identity_db_id, identity_id, discovery_run_id,
         credential_id, name, issuer, subject, audiences, issuer_type, description)
    VALUES
        (3, _fed1, 'df000009-d3a0-4000-aaaa-aaaaaaaaa009', 36,
         'fed-cred-gh-001', 'github-actions-prod',
         'https://token.actions.githubusercontent.com',
         'repo:auditgraph-demo/infra:ref:refs/heads/main',
         jsonb_build_array('api://AzureADTokenExchange'),
         'github_actions',
         'Legitimate GitHub Actions OIDC federation, narrow subject scope (main branch only).'),

        (3, _fed2, 'df000010-d3a0-4000-aaaa-aaaaaaaaa010', 36,
         'fed-cred-weak-001', 'any-tenant-trust',
         'https://sts.example-broker.com',
         '*',
         jsonb_build_array('*'),
         'generic_oidc',
         'WEAK: audience wildcard + subject wildcard allow any OIDC issuer to mint tokens.')
    ON CONFLICT DO NOTHING;

    RAISE NOTICE '✓ 2 federated credentials seeded';
END $$;

-- ============================================================
-- SECTION 13: pim_eligible_assignments + pim_activations
-- ============================================================
DO $$
DECLARE _pim_elig INT; _pim_over INT; _dorm INT;
BEGIN
    SELECT id INTO _pim_elig FROM identities WHERE organization_id=3 AND identity_id='df000014-d3a0-4000-aaaa-aaaaaaaaa014';
    SELECT id INTO _pim_over FROM identities WHERE organization_id=3 AND identity_id='df000015-d3a0-4000-aaaa-aaaaaaaaa015';
    SELECT id INTO _dorm     FROM identities WHERE organization_id=3 AND identity_id='df000005-d3a0-4000-aaaa-aaaaaaaaa005';

    -- PIM SKIPPED on cloud-dev: pim_eligible_assignments / pim_activations
    -- have NO organization_id column on cloud schema, but DO carry a
    -- trg_auto_organization_id trigger that references NEW.organization_id.
    -- Resolving this requires either adding the missing column or dropping
    -- the broken trigger — both are shared-schema changes outside the scope
    -- of a demo seed. Re-enable this section after migration adds the column.
    RAISE NOTICE '⚠ PIM section SKIPPED on cloud (schema mismatch — see comment in SQL)';
    -- _pim_elig, _pim_over, _dorm used below if PIM enabled; harmless when skipped
END $$;

-- ============================================================
-- SECTION 14: privilege_drift_events (T2C lifecycle drift)
-- ============================================================
DO $$
DECLARE _copilot INT; _opsp INT;
BEGIN
    SELECT id INTO _copilot FROM identities WHERE organization_id=3 AND identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001';
    SELECT id INTO _opsp    FROM identities WHERE organization_id=3 AND identity_id='df000004-d3a0-4000-aaaa-aaaaaaaaa004';

    INSERT INTO privilege_drift_events
        (organization_id, identity_id, identity_db_id, display_name, identity_category, drift_type, role_name,
         role_type, scope, prior_scope, prior_risk_level, current_risk_level,
         prior_risk_score, current_risk_score, is_privileged, details,
         discovery_run_id, previous_run_id)
    VALUES
        (3, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', _copilot, 'demo-ai-copilot-prod', 'service_principal',
         'role_added', 'Key Vault Administrator', 'azure',
         '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi',
         NULL, 'low', 'critical', 25, 92, TRUE,
         jsonb_build_object('reason','first appearance','tier_delta',6), 36, 35),

        (3, 'df000004-d3a0-4000-aaaa-aaaaaaaaa004', _opsp, 'demo-overprivileged-sp-01', 'service_principal',
         'scope_widened', 'Owner', 'azure',
         '/subscriptions/11111111-1111-4111-1111-111111111111',
         '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo',
         'high', 'critical', 65, 95, TRUE,
         jsonb_build_object('reason','scope_widened_from_rg_to_subscription'), 36, 35)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE '✓ 2 privilege drift events seeded';
END $$;

-- ============================================================
-- SECTION 15: agent_data_reachability + identity_reachability
-- ============================================================
DO $$
DECLARE _copilot INT; _rag INT; _multi INT; _eval INT;
        _opsp INT; _dorm INT; _fed1 INT; _fed2 INT;
        _pim_over INT; _ai_human INT; _ft INT; _ghost INT;
BEGIN
    SELECT id INTO _copilot  FROM identities WHERE organization_id=3 AND identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001';
    SELECT id INTO _rag      FROM identities WHERE organization_id=3 AND identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002';
    SELECT id INTO _eval     FROM identities WHERE organization_id=3 AND identity_id='de000003-d3a0-4000-aaaa-aaaaaaaaa003';
    SELECT id INTO _multi    FROM identities WHERE organization_id=3 AND identity_id='df000011-d3a0-4000-aaaa-aaaaaaaaa011';
    SELECT id INTO _opsp     FROM identities WHERE organization_id=3 AND identity_id='df000004-d3a0-4000-aaaa-aaaaaaaaa004';
    SELECT id INTO _dorm     FROM identities WHERE organization_id=3 AND identity_id='df000005-d3a0-4000-aaaa-aaaaaaaaa005';
    SELECT id INTO _fed1     FROM identities WHERE organization_id=3 AND identity_id='df000009-d3a0-4000-aaaa-aaaaaaaaa009';
    SELECT id INTO _fed2     FROM identities WHERE organization_id=3 AND identity_id='df000010-d3a0-4000-aaaa-aaaaaaaaa010';
    SELECT id INTO _pim_over FROM identities WHERE organization_id=3 AND identity_id='df000015-d3a0-4000-aaaa-aaaaaaaaa015';
    SELECT id INTO _ai_human FROM identities WHERE organization_id=3 AND identity_id='df000013-d3a0-4000-aaaa-aaaaaaaaa013';
    SELECT id INTO _ft       FROM identities WHERE organization_id=3 AND identity_id='df000012-d3a0-4000-aaaa-aaaaaaaaa012';
    SELECT id INTO _ghost    FROM identities WHERE organization_id=3 AND identity_id='df000007-d3a0-4000-aaaa-aaaaaaaaa007';

    -- agent_data_reachability (data-classification access per AI agent)
    INSERT INTO agent_data_reachability
        (organization_id, discovery_run_id, identity_db_id, identity_id, data_classification,
         resource_count, write_resource_count, est_records, top_resources)
    VALUES
        (3, 36, _copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'PHI',
         1, 1, 120000, jsonb_build_array(jsonb_build_object('name','aiagphiblob01','records',120000,'role','Storage Blob Data Owner'))),
        (3, 36, _rag, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'PHI',
         1, 0, 120000, jsonb_build_array(jsonb_build_object('name','aiagphiblob01','records',120000,'role','Storage Blob Data Reader'))),
        (3, 36, _multi, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'PHI',
         1, 0, 120000, jsonb_build_array(jsonb_build_object('name','aiagphiblob01','records',120000,'role','Storage Blob Data Reader'))),
        (3, 36, _multi, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'PII',
         1, 0, 50000, jsonb_build_array(jsonb_build_object('name','aiag-cosmos-pii','records',50000,'role','Cosmos DB Reader')))
    ON CONFLICT (organization_id, discovery_run_id, identity_db_id, data_classification) DO UPDATE SET
        resource_count = EXCLUDED.resource_count,
        est_records = EXCLUDED.est_records,
        top_resources = EXCLUDED.top_resources;

    -- identity_reachability (per-identity blast radius)
    INSERT INTO identity_reachability
        (organization_id, identity_id, identity_db_id, display_name, identity_category,
         reachable_resource_count, reachable_privileged_resource_count,
         subscriptions_reachable, resource_groups_reachable, high_value_targets_reachable,
         has_privileged_roles, privileged_role_names, highest_scope_type,
         flag_broad_blast_radius, flag_privileged_wide_reach, flag_ai_excessive_blast, flag_dormant_high_blast,
         risk_flag_count, blast_radius_risk_score, blast_radius_exposure_level,
         agent_identity_type, activity_status, discovery_run_id)
    VALUES
        (3, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', _copilot, 'demo-ai-copilot-prod', 'service_principal',
         3, 3, 1, 1, 2, TRUE,
         jsonb_build_array('Key Vault Administrator','Storage Blob Data Owner'),
         'resource', TRUE, TRUE, TRUE, FALSE, 3, 92, 'CRITICAL', 'ai_agent', 'active', 36),
        (3, 'df000004-d3a0-4000-aaaa-aaaaaaaaa004', _opsp, 'demo-overprivileged-sp-01', 'service_principal',
         52, 52, 1, 12, 8, TRUE,
         jsonb_build_array('Owner'),
         'subscription', TRUE, TRUE, FALSE, FALSE, 2, 95, 'CRITICAL', NULL, 'active', 36),
        (3, 'df000005-d3a0-4000-aaaa-aaaaaaaaa005', _dorm, 'demo-dormant-admin-01', 'human_user',
         52, 52, 1, 12, 8, TRUE,
         jsonb_build_array('Owner'),
         'subscription', TRUE, TRUE, FALSE, TRUE, 3, 88, 'CRITICAL', NULL, 'dormant', 36),
        (3, 'df000010-d3a0-4000-aaaa-aaaaaaaaa010', _fed2, 'demo-federated-trust-02', 'service_principal',
         1, 1, 0, 0, 1, FALSE,
         jsonb_build_array('Storage Blob Data Owner'),
         'resource', FALSE, FALSE, FALSE, FALSE, 1, 78, 'HIGH', NULL, 'active', 36),
        (3, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', _multi, 'demo-ai-multimodal-prod', 'service_principal',
         3, 0, 1, 1, 2, FALSE,
         jsonb_build_array('Cognitive Services OpenAI User','Storage Blob Data Reader','Cosmos DB Account Reader Role'),
         'resource', FALSE, FALSE, TRUE, FALSE, 1, 78, 'HIGH', 'ai_agent', 'active', 36),
        (3, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', _rag, 'demo-ai-rag-indexer', 'service_principal',
         1, 0, 0, 0, 1, FALSE,
         jsonb_build_array('Storage Blob Data Reader'),
         'resource', FALSE, FALSE, FALSE, FALSE, 1, 72, 'HIGH', 'ai_agent', 'active', 36),
        (3, 'de000003-d3a0-4000-aaaa-aaaaaaaaa003', _eval, 'demo-ai-eval-bot', 'service_principal',
         1, 0, 0, 0, 0, FALSE,
         jsonb_build_array('Cognitive Services User'),
         'resource', FALSE, FALSE, FALSE, FALSE, 0, 42, 'MEDIUM', 'ai_agent', 'active', 36),
        (3, 'df000007-d3a0-4000-aaaa-aaaaaaaaa007', _ghost, 'demo-ghost-acct-01', 'human_user',
         52, 0, 1, 12, 0, FALSE,
         jsonb_build_array('Reader'),
         'subscription', TRUE, FALSE, FALSE, TRUE, 2, 70, 'HIGH', NULL, 'stale', 36),
        (3, 'df000015-d3a0-4000-aaaa-aaaaaaaaa015', _pim_over, 'demo-pim-overuse-01', 'human_user',
         52, 52, 1, 12, 8, TRUE,
         jsonb_build_array('Contributor','User Administrator (PIM)'),
         'subscription', TRUE, TRUE, FALSE, FALSE, 2, 80, 'HIGH', NULL, 'active', 36),
        (3, 'df000013-d3a0-4000-aaaa-aaaaaaaaa013', _ai_human, 'demo-ai-priv-human-01', 'human_user',
         1, 1, 0, 0, 1, TRUE,
         jsonb_build_array('Cognitive Services Contributor'),
         'resource', FALSE, FALSE, TRUE, FALSE, 1, 72, 'HIGH', 'ai_privileged_human', 'active', 36),
        (3, 'df000012-d3a0-4000-aaaa-aaaaaaaaa012', _ft, 'demo-ai-finetuner', 'service_principal',
         2, 1, 0, 0, 1, FALSE,
         jsonb_build_array('Cognitive Services Contributor','Storage Blob Data Contributor'),
         'resource', FALSE, FALSE, TRUE, FALSE, 1, 68, 'HIGH', 'ai_agent', 'active', 36)
    ON CONFLICT (identity_db_id, discovery_run_id) DO UPDATE SET
        reachable_resource_count = EXCLUDED.reachable_resource_count,
        blast_radius_risk_score = EXCLUDED.blast_radius_risk_score,
        blast_radius_exposure_level = EXCLUDED.blast_radius_exposure_level;

    RAISE NOTICE '✓ reachability rows seeded';
END $$;

-- ============================================================
-- SECTION 16: compliance_snapshots (6 frameworks)
-- ============================================================
INSERT INTO compliance_snapshots
    (organization_id, run_id, framework_key, framework_name, score,
     pass_count, warn_count, fail_count, total_controls, metrics)
VALUES
    (3, 36, 'demo_soc2',  'SOC 2 Type II',      78, 42, 6, 8,  56, jsonb_build_object('top_fail','CC6.6 logical access')),
    (3, 36, 'demo_iso',   'ISO 27001:2022',     82, 65, 4, 8,  77, jsonb_build_object('top_fail','A.9.2.4 secret authentication')),
    (3, 36, 'demo_nist',  'NIST 800-53',        73, 50, 9, 11, 70, jsonb_build_object('top_fail','AC-2 account management')),
    (3, 36, 'demo_pci',   'PCI DSS v4.0',       65, 28, 7, 9,  44, jsonb_build_object('top_fail','7.2 access by need-to-know')),
    (3, 36, 'demo_hipaa', 'HIPAA Security',     71, 16, 3, 4,  23, jsonb_build_object('top_fail','164.312(a) access control')),
    (3, 36, 'demo_cis',   'CIS Azure 2.0',      80, 88, 8, 12, 108, jsonb_build_object('top_fail','3.7 storage public access'))
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 17: Update total_identities on run 36
-- ============================================================
UPDATE discovery_runs SET total_identities = (
    SELECT count(*) FROM identities WHERE organization_id=3 AND discovery_run_id=36
) WHERE id = 36;

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================
\echo ''
\echo '=== Identities (df000-* + de000-*) ==='
SELECT identity_id, display_name, risk_level, activity_status
FROM identities WHERE organization_id=3 AND (identity_id LIKE 'df000%' OR identity_id LIKE 'de000%')
ORDER BY identity_id;

\echo ''
\echo '=== Feature row counts ==='
SELECT 'attack_paths' AS feature, count(*) FROM attack_paths WHERE organization_id=3
UNION ALL SELECT 'consent_grants', count(*) FROM consent_grants WHERE organization_id=3
UNION ALL SELECT 'anomalies', count(*) FROM anomalies WHERE organization_id=3
UNION ALL SELECT 'workload_anomaly_events', count(*) FROM workload_anomaly_events WHERE organization_id=3
UNION ALL SELECT 'agent_behavior_anomalies', count(*) FROM agent_behavior_anomalies WHERE organization_id=3
UNION ALL SELECT 'ai_agent_lifecycle_events', count(*) FROM ai_agent_lifecycle_events WHERE organization_id=3
UNION ALL SELECT 'federated_credentials', count(*) FROM federated_credentials WHERE organization_id=3
UNION ALL SELECT 'pim_eligible_assignments', count(*) FROM pim_eligible_assignments
    WHERE identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'df000%')
UNION ALL SELECT 'pim_activations', count(*) FROM pim_activations
    WHERE identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'df000%')
UNION ALL SELECT 'privilege_drift_events', count(*) FROM privilege_drift_events WHERE organization_id=3
UNION ALL SELECT 'agent_data_reachability', count(*) FROM agent_data_reachability WHERE organization_id=3
UNION ALL SELECT 'identity_reachability', count(*) FROM identity_reachability WHERE organization_id=3
UNION ALL SELECT 'compliance_snapshots', count(*) FROM compliance_snapshots WHERE organization_id=3
UNION ALL SELECT 'azure_ai_model_deployments', count(*) FROM azure_ai_model_deployments WHERE organization_id=3;

\echo ''
\echo '=== Run 36 ==='
SELECT id, total_identities FROM discovery_runs WHERE id=36;
