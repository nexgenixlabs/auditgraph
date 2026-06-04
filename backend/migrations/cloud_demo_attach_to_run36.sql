-- AIAG cloud-demo fix: attach the AI agent to the original demo run (run 36)
-- so the user sees 280 original demo identities + 1 AI agent = 281 total in
-- the LATEST visible snapshot — not just the 1 AI agent in isolation.
--
-- Strategy:
--   1. INSERT my agent into discovery_run 36 (alongside the existing 280)
--   2. INSERT agent_classifications for it tied to run 36
--   3. INSERT role_assignments (KV Admin + Storage Contributor) for the new
--      identity_db_id so T1A attack-path detector still fires
--   4. UPDATE total_identities on run 36 = 281
--   5. DELETE my synthetic runs 41+42 + all their dependents (cascading)
--
-- This SACRIFICES the lifecycle drift demo (no prev_run with Reader only)
-- in exchange for the user's familiar 280-identity demo state + the AI
-- agent appearing in context. Lifecycle drift will fire naturally on the
-- next discovery cycle.

\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
    _new_id      BIGINT;
    _kv_phi      TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi';
    _storage_phi TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01';
    _cog_acct_1  TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod';
BEGIN
    -- Step 1: Insert my agent into run 36 (idempotent via ON CONFLICT)
    INSERT INTO identities
        (organization_id, discovery_run_id, identity_id, display_name,
         identity_type, identity_category, risk_score, risk_level,
         agent_identity_type, activity_status, last_sign_in, created_datetime,
         is_microsoft_system)
    VALUES (3, 36, 'aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001', 'ai_startup_alexander_CoS_project',
            'service_principal', 'service_principal', 88, 'critical',
            'ai_agent', 'active', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '30 days',
            FALSE)
    ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
        agent_identity_type='ai_agent',
        is_microsoft_system=FALSE
    RETURNING id INTO _new_id;
    RAISE NOTICE 'Agent in run 36 → identity_db_id=%', _new_id;

    -- Belt-and-suspenders: ensure the column stays FALSE
    UPDATE identities SET is_microsoft_system=FALSE
    WHERE organization_id=3 AND identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001'
      AND discovery_run_id=36;

    -- Step 2: agent_classifications for the new row
    INSERT INTO agent_classifications
        (identity_db_id, identity_id, agent_identity_type, classification_confidence,
         classification_reason, detected_platform, pattern_version, discovery_run_id,
         organization_id, model_name, owner_display_name_at_classify, account_resource_id)
    VALUES (_new_id, 'aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001', 'ai_agent', 0.95,
            'aiag_cloud_demo_attach', 'azure_openai', '1.0.0', 36, 3,
            'gpt-4o', 'alexander@example.com', _cog_acct_1)
    ON CONFLICT DO NOTHING;

    -- Step 3: role_assignments — KV Admin + Storage Contributor (current state,
    -- the same escalation the user expects to see on the agent's risk profile)
    INSERT INTO role_assignments
        (organization_id, identity_db_id, role_name, scope, scope_type,
         principal_id, assignment_id)
    SELECT 3, _new_id, ra.rn, ra.sc, 'resource',
           'aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001', gen_random_uuid()::text
    FROM (VALUES
        ('Key Vault Administrator',          _kv_phi),
        ('Storage Blob Data Contributor',    _storage_phi)
    ) AS ra(rn, sc)
    ON CONFLICT DO NOTHING;

    -- Step 4: Recompute total_identities on run 36
    UPDATE discovery_runs SET total_identities=(
        SELECT count(*) FROM identities
        WHERE organization_id=3 AND discovery_run_id=36
    )
    WHERE id=36;

    -- Step 5: Drop my synthetic runs (41 + 42) — they're mine, this is the demo org.
    -- Order matters: dependents first.
    DELETE FROM agent_activity_events     WHERE organization_id=3
        AND identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND discovery_run_id IN (41,42));
    DELETE FROM role_assignments          WHERE organization_id=3
        AND identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND discovery_run_id IN (41,42));
    DELETE FROM agent_classifications     WHERE organization_id=3 AND discovery_run_id IN (41,42);
    DELETE FROM identities                WHERE organization_id=3 AND discovery_run_id IN (41,42);
    -- Resource rows we seeded into 41/42 too
    DELETE FROM azure_ai_model_deployments WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND account_resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_cognitive_services_accounts WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_key_vaults          WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_storage_accounts    WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_sql_databases       WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_sql_servers         WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_cosmos_databases    WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    DELETE FROM azure_cosmos_accounts     WHERE organization_id=3 AND discovery_run_id IN (41,42)
        AND resource_id LIKE '/subscriptions/11111111-%';
    -- Finally the runs themselves
    DELETE FROM discovery_runs WHERE id IN (41, 42) AND organization_id=3;

    -- Add resources to run 36 too (so the AI agent has reachable KV + storage)
    INSERT INTO azure_cognitive_services_accounts
        (organization_id, discovery_run_id, subscription_id, resource_id,
         resource_group, name, kind, public_network_access,
         network_acls_default_action, private_endpoint_count)
    VALUES (3, 36, '11111111-1111-4111-1111-111111111111', _cog_acct_1,
            'rg-aiag-demo', 'aiag-openai-prod', 'OpenAI', 'Disabled', 'Deny', 1)
    ON CONFLICT DO NOTHING;

    INSERT INTO azure_key_vaults
        (organization_id, discovery_run_id, subscription_id, resource_id,
         resource_group, name, location, public_network_access,
         default_network_action, private_endpoint_count, secrets_total)
    VALUES (3, 36, '11111111-1111-4111-1111-111111111111', _kv_phi,
            'rg-aiag-demo', 'aiag-vault-phi', 'eastus', 'Disabled', 'Deny', 1, 14)
    ON CONFLICT DO NOTHING;

    INSERT INTO azure_storage_accounts
        (organization_id, discovery_run_id, subscription_id, resource_id,
         resource_group, name, location, public_blob_access,
         default_network_action, private_endpoint_count,
         data_classification, classification_source, classification_confidence,
         record_count_estimate)
    VALUES (3, 36, '11111111-1111-4111-1111-111111111111', _storage_phi,
            'rg-aiag-demo', 'aiagphiblob01', 'eastus', FALSE, 'Deny', 0,
            'PHI', 'tag', 'high', 120000)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE '✓ Attached AI agent to run 36; dropped runs 41/42';
END $$;

COMMIT;

-- Verification
\echo ''
\echo '=== Verification: run 36 ==='
SELECT id, total_identities, completed_at FROM discovery_runs
WHERE organization_id=3 ORDER BY id DESC LIMIT 5;

\echo ''
\echo '=== Verification: AI agent in run 36 ==='
SELECT i.id, i.identity_id, i.display_name, i.discovery_run_id, i.is_microsoft_system
FROM identities i
WHERE i.organization_id=3 AND i.identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001';

\echo ''
\echo '=== Verification: AI Inventory query ==='
SELECT count(*) FROM identities i
JOIN agent_classifications ac ON ac.identity_db_id = i.id
WHERE i.organization_id=3
  AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent', 'ai_privileged_human')
  AND NOT COALESCE(i.is_microsoft_system, false)
  AND i.deleted_at IS NULL;
