-- AIAG Cloud Demo Seed for org_id=3 (auditgraph-demo) — pure-SQL version
--
-- Idempotent (re-runs delete prior aa000-* fingerprinted rows first).
-- Applied via apply_cloud_migration.py — runs inside VNet.
--
-- Tag VALUES say "classification=PHI" — labels only, NEVER real PHI content.
-- We never read data-plane content.

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

-- RLS context (forced-policy tables use this)
SELECT set_config('app.current_organization_id', '3', true);
SELECT set_config('app.current_tenant_id', '3', true);

-- ============================================================
-- Cleanup: only aa000-* fingerprinted rows (never customer data)
-- ============================================================
DELETE FROM agent_activity_events       WHERE organization_id=3 AND identity_id LIKE 'aa000%';
DELETE FROM agent_data_reachability     WHERE organization_id=3 AND identity_id LIKE 'aa000%';
DELETE FROM ai_agent_lifecycle_events   WHERE organization_id=3 AND identity_id LIKE 'aa000%';
DELETE FROM attack_paths                WHERE organization_id=3 AND source_entity_id LIKE 'aa000%';
DELETE FROM role_assignments            WHERE organization_id=3
   AND identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'aa000%');
DELETE FROM agent_classifications       WHERE organization_id=3 AND identity_id LIKE 'aa000%';
DELETE FROM identities                  WHERE organization_id=3 AND identity_id LIKE 'aa000%';
DELETE FROM azure_ai_model_deployments  WHERE organization_id=3 AND account_resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_cognitive_services_accounts WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_key_vaults            WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_storage_accounts      WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_sql_databases         WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_sql_servers           WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_cosmos_databases      WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';
DELETE FROM azure_cosmos_accounts       WHERE organization_id=3 AND resource_id LIKE '/subscriptions/11111111-%';

-- ============================================================
-- Create 2 discovery runs (prev T-2 days, current NOW)
-- ============================================================
WITH conn AS (SELECT id FROM cloud_connections WHERE organization_id=3 LIMIT 1),
     prev AS (
         INSERT INTO discovery_runs (organization_id, cloud_connection_id, subscription_id,
                                     started_at, completed_at, status)
         SELECT 3, c.id, '11111111-1111-4111-1111-111111111111',
                NOW() - INTERVAL '2 days 15 minutes', NOW() - INTERVAL '2 days', 'completed'
         FROM conn c
         RETURNING id
     ),
     curr AS (
         INSERT INTO discovery_runs (organization_id, cloud_connection_id, subscription_id,
                                     started_at, completed_at, status)
         SELECT 3, c.id, '11111111-1111-4111-1111-111111111111',
                NOW() - INTERVAL '15 minutes', NOW(), 'completed'
         FROM conn c
         RETURNING id
     )
SELECT (SELECT id FROM prev) AS prev_run_id,
       (SELECT id FROM curr) AS curr_run_id \gset

\echo prev_run_id = :prev_run_id
\echo curr_run_id = :curr_run_id

-- ============================================================
-- RESOURCES — seeded into BOTH runs
-- ============================================================
-- Cognitive Services accounts
INSERT INTO azure_cognitive_services_accounts
    (organization_id, discovery_run_id, subscription_id, resource_id,
     resource_group, name, kind, public_network_access,
     network_acls_default_action, private_endpoint_count)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/' || n,
       'rg-aiag-demo', n, k, p, da, pe
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('aiag-openai-prod', 'OpenAI', 'Disabled', 'Deny',  1),
        ('aiag-openai-stg',  'OpenAI', 'Enabled',  'Allow', 0),
        ('aiag-copilot-bot', 'CognitiveServices', 'Disabled', 'Deny', 1)
     ) AS a(n,k,p,da,pe)
ON CONFLICT DO NOTHING;

-- Model deployments
INSERT INTO azure_ai_model_deployments
    (organization_id, discovery_run_id, account_resource_id,
     deployment_name, model_name, model_version, sku_name, sku_capacity)
SELECT 3, r,
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/' || ac,
       d.dn, d.mn, d.mv, 'Standard', d.cap
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('aiag-openai-prod', 'gpt-4o-prod',   'gpt-4o',         '2024-08-06', 100),
        ('aiag-openai-prod', 'gpt-4-prod',    'gpt-4',          '0613',       50),
        ('aiag-openai-stg',  'gpt-4o-stg',    'gpt-4o',         '2024-08-06', 25),
        ('aiag-openai-stg',  'gpt-4o-mini',   'gpt-4o-mini',    '2024-07-18', 100),
        ('aiag-copilot-bot', 'claude-sonnet', 'claude-3-sonnet','20240229',   50),
        ('aiag-copilot-bot', 'embedding-3',   'text-embedding-3-large', '1', 100)
     ) AS d(ac, dn, mn, mv, cap)
ON CONFLICT DO NOTHING;

-- Key Vaults
INSERT INTO azure_key_vaults
    (organization_id, discovery_run_id, subscription_id, resource_id,
     resource_group, name, location, public_network_access,
     default_network_action, private_endpoint_count, secrets_total)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/' || k.n,
       'rg-aiag-demo', k.n, 'eastus', k.pna, k.dna, k.pe, k.s
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('aiag-vault-phi', 'Disabled', 'Deny',  1, 14),
        ('aiag-vault-pci', 'Enabled',  'Allow', 0, 8)
     ) AS k(n, pna, dna, pe, s)
ON CONFLICT DO NOTHING;

-- Storage accounts
INSERT INTO azure_storage_accounts
    (organization_id, discovery_run_id, subscription_id, resource_id,
     resource_group, name, location, public_blob_access,
     default_network_action, private_endpoint_count,
     data_classification, classification_source, classification_confidence,
     record_count_estimate)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/' || s.n,
       'rg-aiag-demo', s.n, 'eastus', s.pba, s.dna, 0,
       s.cl, s.cs, s.cc, s.re
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('aiagphiblob01', FALSE, 'Deny',  'PHI',    'tag',          'high',   120000::bigint),
        ('aiagpci01',     FALSE, 'Deny',  'PCI',    'tag',          'high',   45000::bigint),
        ('aiagsrccode01', FALSE, 'Allow', 'SOURCE', 'name_pattern', 'medium', NULL::bigint),
        ('aiagpublic01',  TRUE,  'Allow', NULL,     NULL,           NULL,     NULL::bigint)
     ) AS s(n, pba, dna, cl, cs, cc, re)
ON CONFLICT DO NOTHING;

-- SQL server + databases
INSERT INTO azure_sql_servers
    (organization_id, discovery_run_id, subscription_id, resource_id,
     resource_group, server_name, location, public_network_access)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Sql/servers/aiag-sql-prod',
       'rg-aiag-demo', 'aiag-sql-prod', 'eastus', 'Enabled'
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r
ON CONFLICT DO NOTHING;

INSERT INTO azure_sql_databases
    (organization_id, discovery_run_id, subscription_id, resource_id,
     server_resource_id, database_name, sku_name, sku_tier, capacity,
     data_classification, classification_source, classification_confidence,
     record_count_estimate)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Sql/servers/aiag-sql-prod/databases/' || d.n,
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Sql/servers/aiag-sql-prod',
       d.n, d.sk, d.st, d.cap, d.cl, d.cs, d.cc, d.re
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('hr-analytics', 'GP_Gen5', 'GeneralPurpose', 4,    'HR', 'tag', 'high', 250000::bigint),
        ('generic-app',  'S0',      NULL::text,       NULL::int, NULL::text, NULL::text, NULL::text, NULL::bigint)
     ) AS d(n, sk, st, cap, cl, cs, cc, re)
ON CONFLICT DO NOTHING;

-- Cosmos
INSERT INTO azure_cosmos_accounts
    (organization_id, discovery_run_id, subscription_id, resource_id,
     resource_group, account_name, location, kind, public_network_access)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.DocumentDB/databaseAccounts/aiag-cosmos-prod',
       'rg-aiag-demo', 'aiag-cosmos-prod', 'eastus', 'GlobalDocumentDB', 'Enabled'
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r
ON CONFLICT DO NOTHING;

INSERT INTO azure_cosmos_databases
    (organization_id, discovery_run_id, subscription_id, resource_id,
     account_resource_id, database_name, api_kind,
     data_classification, classification_source, classification_confidence,
     record_count_estimate)
SELECT 3, r, '11111111-1111-4111-1111-111111111111',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.DocumentDB/databaseAccounts/aiag-cosmos-prod/sqlDatabases/' || d.n,
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.DocumentDB/databaseAccounts/aiag-cosmos-prod',
       d.n, 'sql', d.cl, d.cs, d.cc, d.re
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('customer-pii',   'PII', 'tag', 'high', 80000::bigint),
        ('generic-app-db', NULL::text, NULL::text, NULL::text, NULL::bigint)
     ) AS d(n, cl, cs, cc, re)
ON CONFLICT DO NOTHING;

-- ============================================================
-- IDENTITIES — 1 marquee AI agent in both runs
-- ============================================================
INSERT INTO identities
    (organization_id, discovery_run_id, identity_id, display_name,
     identity_type, identity_category, risk_score, risk_level,
     agent_identity_type, activity_status, last_sign_in, created_datetime,
     is_microsoft_system)
SELECT 3, r, 'aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001', 'ai_startup_alexander_CoS_project',
       'service_principal', 'service_principal', 88, 'critical',
       'ai_agent', 'active', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '30 days', FALSE
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r
ON CONFLICT DO NOTHING;

-- agent_classifications row (with AG-177 enrichment columns)
INSERT INTO agent_classifications
    (identity_db_id, identity_id, agent_identity_type, classification_confidence,
     classification_reason, detected_platform, pattern_version, discovery_run_id,
     organization_id, model_name, owner_display_name_at_classify, account_resource_id)
SELECT i.id, i.identity_id, 'ai_agent', 0.95, 'aiag_cloud_demo_seed',
       'azure_openai', '1.0.0', i.discovery_run_id, 3,
       'gpt-4o', 'alexander@example.com',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod'
FROM identities i
WHERE i.organization_id=3 AND i.identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001'
  AND i.discovery_run_id IN (:prev_run_id::bigint, :curr_run_id::bigint)
ON CONFLICT DO NOTHING;

-- ============================================================
-- ROLE ASSIGNMENTS — escalation pattern across the 2 runs
--   prev run: Reader only (low-priv baseline)
--   curr run: KV Admin + Storage Contributor (the escalation = T2C event)
-- ============================================================
-- Prev run: Reader on the cog svc
INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, 'Reader',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod',
       'resource', i.identity_id, gen_random_uuid()::text
FROM identities i
WHERE i.organization_id=3 AND i.identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001'
  AND i.discovery_run_id = :prev_run_id::bigint
ON CONFLICT DO NOTHING;

-- Curr run: KV Admin + Storage Contributor (the escalation)
INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, ra.rn, ra.sc, 'resource', i.identity_id, gen_random_uuid()::text
FROM identities i,
     (VALUES
        ('Key Vault Administrator',
         '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi'),
        ('Storage Blob Data Contributor',
         '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01')
     ) AS ra(rn, sc)
WHERE i.organization_id=3 AND i.identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001'
  AND i.discovery_run_id = :curr_run_id::bigint
ON CONFLICT DO NOTHING;

-- ============================================================
-- ACTIVITY EVENTS — 20 days of model calls for behavior baseline
-- (last day spikes to 5x → triggers volume_spike anomaly)
-- ============================================================
INSERT INTO agent_activity_events
    (organization_id, identity_db_id, identity_id, category, occurred_at,
     source, operation_name, metric_value, severity)
SELECT 3, i.id, i.identity_id, 'model_call',
       NOW() - ((19 - d.day_offset) || ' days')::interval,
       'azure_monitor', 'POST /chat/completions',
       CASE WHEN d.day_offset = 19 THEN 1000 ELSE 200 END,
       'info'
FROM identities i,
     generate_series(0, 19) AS d(day_offset)
WHERE i.organization_id=3 AND i.identity_id='aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001'
  AND i.discovery_run_id = :curr_run_id::bigint;

COMMIT;
