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
-- Cleanup: aa000-* (legacy fingerprint) AND de000-* (current demo agents)
-- NEVER touches customer data.
-- ============================================================
DELETE FROM agent_activity_events       WHERE organization_id=3 AND (identity_id LIKE 'aa000%' OR identity_id LIKE 'de000%');
DELETE FROM agent_data_reachability     WHERE organization_id=3 AND (identity_id LIKE 'aa000%' OR identity_id LIKE 'de000%');
DELETE FROM ai_agent_lifecycle_events   WHERE organization_id=3 AND (identity_id LIKE 'aa000%' OR identity_id LIKE 'de000%');
DELETE FROM attack_paths                WHERE organization_id=3 AND (source_entity_id LIKE 'aa000%' OR source_entity_id LIKE 'de000%');
DELETE FROM role_assignments            WHERE organization_id=3
   AND identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND (identity_id LIKE 'aa000%' OR identity_id LIKE 'de000%'));
DELETE FROM agent_classifications       WHERE organization_id=3 AND (identity_id LIKE 'aa000%' OR identity_id LIKE 'de000%');
DELETE FROM identities                  WHERE organization_id=3 AND (identity_id LIKE 'aa000%' OR identity_id LIKE 'de000%');
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
-- IDENTITIES — 3 clearly-demo-branded AI agents in both runs
--   demo-ai-copilot-prod  (CRITICAL  KV Admin + Storage Blob Owner)
--   demo-ai-rag-indexer   (HIGH      Storage Blob Reader on PHI)
--   demo-ai-eval-bot      (MEDIUM    Cognitive Services User only)
-- All owned by "AuditGraph Demo Platform Team" — clearly synthetic.
-- ============================================================
INSERT INTO identities
    (organization_id, discovery_run_id, identity_id, display_name,
     identity_type, identity_category, risk_score, risk_level,
     agent_identity_type, activity_status, last_sign_in, created_datetime,
     is_microsoft_system)
SELECT 3, r, agent.id, agent.name,
       'service_principal', 'service_principal', agent.score, agent.level,
       'ai_agent', 'active', NOW() - (agent.signin_h || ' hours')::interval,
       NOW() - (agent.age_d || ' days')::interval, FALSE
FROM unnest(ARRAY[:prev_run_id::bigint, :curr_run_id::bigint]) r,
     (VALUES
        ('de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'demo-ai-copilot-prod', 92, 'critical', 1,   120),
        ('de000002-d3a0-4000-aaaa-aaaaaaaaa002', 'demo-ai-rag-indexer',  72, 'high',     4,    60),
        ('de000003-d3a0-4000-aaaa-aaaaaaaaa003', 'demo-ai-eval-bot',     42, 'medium',   6,    45)
     ) AS agent(id, name, score, level, signin_h, age_d)
ON CONFLICT DO NOTHING;

-- Belt-and-suspenders against the trigger / code path that sometimes
-- flips is_microsoft_system to TRUE on the INSERT path. Demo agents
-- MUST be visible to AI Inventory (filters NOT is_microsoft_system).
UPDATE identities SET is_microsoft_system=FALSE
WHERE organization_id=3 AND identity_id LIKE 'de000%';

-- Backfill total_identities so the snapshot picker shows the correct count.
UPDATE discovery_runs SET total_identities=(
    SELECT count(*) FROM identities
    WHERE organization_id=3 AND discovery_run_id=discovery_runs.id
)
WHERE organization_id=3 AND id IN (:prev_run_id::bigint, :curr_run_id::bigint);

-- agent_classifications row (with AG-177 enrichment columns)
INSERT INTO agent_classifications
    (identity_db_id, identity_id, agent_identity_type, classification_confidence,
     classification_reason, detected_platform, pattern_version, discovery_run_id,
     organization_id, model_name, owner_display_name_at_classify, account_resource_id)
SELECT i.id, i.identity_id, 'ai_agent', 0.93, 'aiag_cloud_demo_seed',
       'azure_openai', '1.0.0', i.discovery_run_id, 3,
       CASE i.identity_id
            WHEN 'de000001-d3a0-4000-aaaa-aaaaaaaaa001' THEN 'gpt-4o'
            WHEN 'de000002-d3a0-4000-aaaa-aaaaaaaaa002' THEN 'text-embedding-3-large'
            ELSE 'gpt-4o-mini'
       END,
       'AuditGraph Demo Platform Team',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod'
FROM identities i
WHERE i.organization_id=3 AND i.identity_id LIKE 'de000%'
  AND i.discovery_run_id IN (:prev_run_id::bigint, :curr_run_id::bigint)
ON CONFLICT DO NOTHING;

-- ============================================================
-- ROLE ASSIGNMENTS — escalation pattern on copilot (T2C lifecycle drift)
--   prev run: copilot=Reader, rag=Reader, eval=Cognitive Services User (low-priv baselines)
--   curr run: copilot=KV Admin + Storage Blob Owner (escalation),
--             rag=Storage Blob Data Reader on PHI (data reachability),
--             eval=Cognitive Services User (unchanged — safe baseline)
-- ============================================================
-- PREV RUN: low-priv baseline for all 3
INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, 'Reader',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod',
       'resource', i.identity_id, gen_random_uuid()::text
FROM identities i
WHERE i.organization_id=3 AND i.identity_id IN ('de000001-d3a0-4000-aaaa-aaaaaaaaa001','de000002-d3a0-4000-aaaa-aaaaaaaaa002')
  AND i.discovery_run_id = :prev_run_id::bigint
ON CONFLICT DO NOTHING;

INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, 'Cognitive Services User',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod',
       'resource', i.identity_id, gen_random_uuid()::text
FROM identities i
WHERE i.organization_id=3 AND i.identity_id='de000003-d3a0-4000-aaaa-aaaaaaaaa003'
  AND i.discovery_run_id = :prev_run_id::bigint
ON CONFLICT DO NOTHING;

-- CURR RUN: copilot escalates to critical scope
INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, ra.rn, ra.sc, 'resource', i.identity_id, gen_random_uuid()::text
FROM identities i,
     (VALUES
        ('Key Vault Administrator',
         '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi'),
        ('Storage Blob Data Owner',
         '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01')
     ) AS ra(rn, sc)
WHERE i.organization_id=3 AND i.identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001'
  AND i.discovery_run_id = :curr_run_id::bigint
ON CONFLICT DO NOTHING;

-- CURR RUN: rag-indexer gains Storage Blob Data Reader on PHI
INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, 'Storage Blob Data Reader',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01',
       'resource', i.identity_id, gen_random_uuid()::text
FROM identities i
WHERE i.organization_id=3 AND i.identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002'
  AND i.discovery_run_id = :curr_run_id::bigint
ON CONFLICT DO NOTHING;

-- CURR RUN: eval-bot keeps Cognitive Services User (safe baseline, no drift)
INSERT INTO role_assignments
    (organization_id, identity_db_id, role_name, scope, scope_type,
     principal_id, assignment_id)
SELECT 3, i.id, 'Cognitive Services User',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod',
       'resource', i.identity_id, gen_random_uuid()::text
FROM identities i
WHERE i.organization_id=3 AND i.identity_id='de000003-d3a0-4000-aaaa-aaaaaaaaa003'
  AND i.discovery_run_id = :curr_run_id::bigint
ON CONFLICT DO NOTHING;

-- ============================================================
-- ACTIVITY EVENTS — 14 days of model calls + storage reads
-- copilot spikes on day 14 → volume_spike anomaly hook
-- ============================================================
INSERT INTO agent_activity_events
    (organization_id, identity_db_id, identity_id, category, occurred_at,
     source, resource_id, resource_type, operation_name, metric_value, severity)
SELECT 3, i.id, i.identity_id, 'inference',
       NOW() - ((14 - d.day_offset) || ' days')::interval,
       'azure_openai',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod',
       'cognitive_services', 'completions',
       CASE WHEN d.day_offset = 14 THEN 5000 ELSE 1000 END, 'info'
FROM identities i, generate_series(0, 14) AS d(day_offset)
WHERE i.organization_id=3 AND i.identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001'
  AND i.discovery_run_id = :curr_run_id::bigint;

INSERT INTO agent_activity_events
    (organization_id, identity_db_id, identity_id, category, occurred_at,
     source, resource_id, resource_type, operation_name, metric_value, severity)
SELECT 3, i.id, i.identity_id, 'data_read',
       NOW() - ((14 - d.day_offset) || ' days')::interval,
       'azure_storage',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01',
       'storage_account', 'blob_get', 250.0 + d.day_offset*5, 'info'
FROM identities i, generate_series(0, 14) AS d(day_offset)
WHERE i.organization_id=3 AND i.identity_id='de000002-d3a0-4000-aaaa-aaaaaaaaa002'
  AND i.discovery_run_id = :curr_run_id::bigint;

INSERT INTO agent_activity_events
    (organization_id, identity_db_id, identity_id, category, occurred_at,
     source, resource_id, resource_type, operation_name, metric_value, severity)
SELECT 3, i.id, i.identity_id, 'inference',
       NOW() - ((14 - d.day_offset) || ' days')::interval,
       'azure_openai',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod',
       'cognitive_services', 'completions', 80.0 + d.day_offset, 'info'
FROM identities i, generate_series(0, 14) AS d(day_offset)
WHERE i.organization_id=3 AND i.identity_id='de000003-d3a0-4000-aaaa-aaaaaaaaa003'
  AND i.discovery_run_id = :curr_run_id::bigint;

COMMIT;
