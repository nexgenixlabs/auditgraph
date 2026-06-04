-- AIAG cloud-demo cleanup: remove `ai_startup_alexander_CoS_project`
-- (poorly-named synthetic) and replace with 3 clearly-demo-branded AI agents
-- that exercise the full AIAG / Argus feature set.
--
-- TARGET: org_id=3 (cloud-dev auditgraph-demo), discovery_run_id=36
--
-- New agents:
--   demo-ai-copilot-prod    CRITICAL  Azure OpenAI + KV Admin + Storage Blob Owner  (hero attack path)
--   demo-ai-rag-indexer     HIGH      Azure OpenAI + Storage Blob Reader on PHI      (data reachability)
--   demo-ai-eval-bot        MEDIUM    Azure OpenAI + Cognitive Services User only    (safe baseline)
--
-- All owned by "AuditGraph Demo Platform Team", clearly synthetic UUIDs (de00000*-d3a0-*).

\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
    _kv_phi      TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi';
    _storage_phi TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01';
    _cog_acct_1  TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod';
    _id_copilot  BIGINT;
    _id_rag      BIGINT;
    _id_eval     BIGINT;
    _bad_id      BIGINT;
BEGIN
    -- STEP 1: REMOVE the misnamed agent across ALL its dependents
    SELECT id INTO _bad_id FROM identities
    WHERE organization_id=3 AND identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001'
    LIMIT 1;

    IF _bad_id IS NOT NULL THEN
        DELETE FROM agent_activity_events     WHERE organization_id=3 AND identity_db_id=_bad_id;
        DELETE FROM role_assignments          WHERE organization_id=3 AND identity_db_id=_bad_id;
    END IF;
    DELETE FROM agent_classifications WHERE organization_id=3 AND identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001';
    DELETE FROM identities            WHERE organization_id=3 AND identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001';
    RAISE NOTICE '✓ Removed ai_startup_alexander_CoS_project (id=%) from org=3', _bad_id;

    -- STEP 2a: demo-ai-copilot-prod  (CRITICAL — KV Admin + Storage Blob Owner)
    INSERT INTO identities
        (organization_id, discovery_run_id, identity_id, display_name,
         identity_type, identity_category, risk_score, risk_level,
         agent_identity_type, activity_status, last_sign_in, created_datetime,
         is_microsoft_system)
    VALUES (3, 36, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'demo-ai-copilot-prod',
            'service_principal', 'service_principal', 92, 'critical',
            'ai_agent', 'active', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '120 days',
            FALSE)
    ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
        agent_identity_type='ai_agent',
        is_microsoft_system=FALSE,
        risk_level='critical',
        risk_score=92,
        display_name='demo-ai-copilot-prod'
    RETURNING id INTO _id_copilot;

    INSERT INTO agent_classifications
        (identity_db_id, identity_id, agent_identity_type, classification_confidence,
         classification_reason, detected_platform, pattern_version, discovery_run_id,
         organization_id, model_name, owner_display_name_at_classify, account_resource_id)
    VALUES (_id_copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'ai_agent', 0.96,
            'demo_seed', 'azure_openai', '1.0.0', 36, 3,
            'gpt-4o', 'AuditGraph Demo Platform Team', _cog_acct_1)
    ON CONFLICT DO NOTHING;

    INSERT INTO role_assignments
        (organization_id, identity_db_id, role_name, scope, scope_type,
         principal_id, assignment_id)
    SELECT 3, _id_copilot, ra.rn, ra.sc, 'resource',
           'de000001-d3a0-4000-aaaa-aaaaaaaaa001', gen_random_uuid()::text
    FROM (VALUES
        ('Key Vault Administrator',          _kv_phi),
        ('Storage Blob Data Owner',          _storage_phi)
    ) AS ra(rn, sc)
    ON CONFLICT DO NOTHING;

    -- STEP 2b: demo-ai-rag-indexer  (HIGH — Storage Blob Reader on PHI)
    INSERT INTO identities
        (organization_id, discovery_run_id, identity_id, display_name,
         identity_type, identity_category, risk_score, risk_level,
         agent_identity_type, activity_status, last_sign_in, created_datetime,
         is_microsoft_system)
    VALUES (3, 36, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'demo-ai-rag-indexer',
            'service_principal', 'service_principal', 72, 'high',
            'ai_agent', 'active', NOW() - INTERVAL '4 hours', NOW() - INTERVAL '60 days',
            FALSE)
    ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
        agent_identity_type='ai_agent',
        is_microsoft_system=FALSE,
        risk_level='high',
        risk_score=72,
        display_name='demo-ai-rag-indexer'
    RETURNING id INTO _id_rag;

    INSERT INTO agent_classifications
        (identity_db_id, identity_id, agent_identity_type, classification_confidence,
         classification_reason, detected_platform, pattern_version, discovery_run_id,
         organization_id, model_name, owner_display_name_at_classify, account_resource_id)
    VALUES (_id_rag, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'ai_agent', 0.91,
            'demo_seed', 'azure_openai', '1.0.0', 36, 3,
            'text-embedding-3-large', 'AuditGraph Demo Platform Team', _cog_acct_1)
    ON CONFLICT DO NOTHING;

    INSERT INTO role_assignments
        (organization_id, identity_db_id, role_name, scope, scope_type,
         principal_id, assignment_id)
    SELECT 3, _id_rag, 'Storage Blob Data Reader', _storage_phi, 'resource',
           'de000002-d3a0-4000-aaaa-aaaaaaaaa002', gen_random_uuid()::text
    ON CONFLICT DO NOTHING;

    -- STEP 2c: demo-ai-eval-bot  (MEDIUM — Cognitive Services User only)
    INSERT INTO identities
        (organization_id, discovery_run_id, identity_id, display_name,
         identity_type, identity_category, risk_score, risk_level,
         agent_identity_type, activity_status, last_sign_in, created_datetime,
         is_microsoft_system)
    VALUES (3, 36, 'de000003-d3a0-4000-aaaa-aaaaaaaaa003', 'demo-ai-eval-bot',
            'service_principal', 'service_principal', 42, 'medium',
            'ai_agent', 'active', NOW() - INTERVAL '6 hours', NOW() - INTERVAL '45 days',
            FALSE)
    ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
        agent_identity_type='ai_agent',
        is_microsoft_system=FALSE,
        risk_level='medium',
        risk_score=42,
        display_name='demo-ai-eval-bot'
    RETURNING id INTO _id_eval;

    INSERT INTO agent_classifications
        (identity_db_id, identity_id, agent_identity_type, classification_confidence,
         classification_reason, detected_platform, pattern_version, discovery_run_id,
         organization_id, model_name, owner_display_name_at_classify, account_resource_id)
    VALUES (_id_eval, 'de000003-d3a0-4000-aaaa-aaaaaaaaa003', 'ai_agent', 0.89,
            'demo_seed', 'azure_openai', '1.0.0', 36, 3,
            'gpt-4o-mini', 'AuditGraph Demo Platform Team', _cog_acct_1)
    ON CONFLICT DO NOTHING;

    INSERT INTO role_assignments
        (organization_id, identity_db_id, role_name, scope, scope_type,
         principal_id, assignment_id)
    SELECT 3, _id_eval, 'Cognitive Services User', _cog_acct_1, 'resource',
           'de000003-d3a0-4000-aaaa-aaaaaaaaa003', gen_random_uuid()::text
    ON CONFLICT DO NOTHING;

    -- STEP 3: Activity events (so behavior baseline + T3A fire)
    INSERT INTO agent_activity_events
        (organization_id, identity_db_id, identity_id, category, occurred_at, source,
         resource_id, resource_type, operation_name, metric_value, severity)
    SELECT 3, _id_copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001',
           'inference', NOW() - (interval '1 day' * gs), 'azure_openai',
           _cog_acct_1, 'cognitive_services', 'completions', 1500.0 + gs*10, 'info'
    FROM generate_series(1, 14) AS gs;

    INSERT INTO agent_activity_events
        (organization_id, identity_db_id, identity_id, category, occurred_at, source,
         resource_id, resource_type, operation_name, metric_value, severity)
    SELECT 3, _id_rag, 'de000002-d3a0-4000-aaaa-aaaaaaaaa002',
           'data_read', NOW() - (interval '1 day' * gs), 'azure_storage',
           _storage_phi, 'storage_account', 'blob_get', 250.0 + gs*5, 'info'
    FROM generate_series(1, 14) AS gs;

    INSERT INTO agent_activity_events
        (organization_id, identity_db_id, identity_id, category, occurred_at, source,
         resource_id, resource_type, operation_name, metric_value, severity)
    SELECT 3, _id_eval, 'de000003-d3a0-4000-aaaa-aaaaaaaaa003',
           'inference', NOW() - (interval '1 day' * gs), 'azure_openai',
           _cog_acct_1, 'cognitive_services', 'completions', 80.0 + gs, 'info'
    FROM generate_series(1, 14) AS gs;

    -- STEP 4: Recompute total_identities on run 36
    UPDATE discovery_runs SET total_identities=(
        SELECT count(*) FROM identities
        WHERE organization_id=3 AND discovery_run_id=36
    )
    WHERE id=36;

    RAISE NOTICE '✓ Added demo-ai-copilot-prod (%) demo-ai-rag-indexer (%) demo-ai-eval-bot (%) to org=3',
        _id_copilot, _id_rag, _id_eval;
END $$;

COMMIT;

\echo ''
\echo '=== Verification: run 36 total_identities ==='
SELECT id, total_identities FROM discovery_runs WHERE id=36;

\echo ''
\echo '=== Verification: bad agent gone ==='
SELECT count(*) AS leftover FROM identities
WHERE organization_id=3 AND identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001';

\echo ''
\echo '=== Verification: 3 demo AI agents present ==='
SELECT i.identity_id, i.display_name, i.risk_level,
       (SELECT count(*) FROM role_assignments WHERE identity_db_id=i.id) AS roles,
       (SELECT count(*) FROM agent_activity_events WHERE identity_db_id=i.id) AS events
FROM identities i
WHERE i.organization_id=3 AND i.identity_id LIKE 'de00000_-d3a0-%'
ORDER BY i.identity_id;

\echo ''
\echo '=== Verification: AI Inventory query (joined to classifications) ==='
SELECT count(*) AS ai_count FROM identities i
JOIN agent_classifications ac ON ac.identity_db_id = i.id
WHERE i.organization_id=3
  AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent', 'ai_privileged_human')
  AND NOT COALESCE(i.is_microsoft_system, false)
  AND i.deleted_at IS NULL;
