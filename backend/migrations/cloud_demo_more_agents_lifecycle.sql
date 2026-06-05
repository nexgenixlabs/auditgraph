-- Cloud demo expansion: more AI agents, fresh lifecycle events within
-- the 7-day window, more JML signal.
--
-- Adds 8 new AI agents (df000020 .. df000027) covering varied risk
-- profiles + use cases so AI Inventory / AI Access / Board Scorecard /
-- AI Lifecycle all show meaningful spread.
--
-- Also: rewrites all ai_agent_lifecycle_events to occurred_at within the
-- last 7 days so the AI Lifecycle page (default 7-day window) is non-empty.

\set ON_ERROR_STOP on

BEGIN;

SELECT set_config('app.current_organization_id', '3', true);
SELECT set_config('app.current_tenant_id', '3', true);

-- ============================================================
-- CLEANUP: only df0002* + previous lifecycle events (re-seed fresh)
-- ============================================================
DELETE FROM agent_activity_events       WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM agent_behavior_anomalies    WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM workload_anomaly_events     WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM agent_data_reachability     WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM identity_reachability       WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM role_assignments            WHERE organization_id=3
    AND identity_db_id IN (SELECT id FROM identities WHERE organization_id=3 AND identity_id LIKE 'df0002%');
DELETE FROM agent_classifications       WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM identities                  WHERE organization_id=3 AND identity_id LIKE 'df0002%';
DELETE FROM ai_agent_lifecycle_events   WHERE organization_id=3 AND (identity_id LIKE 'de000%' OR identity_id LIKE 'df000%');

-- ============================================================
-- SECTION 1: 8 new AI identities (df0002*) — varied profiles
-- ============================================================
DO $$
DECLARE _run_id BIGINT := 36;
BEGIN
    INSERT INTO identities
        (organization_id, discovery_run_id, identity_id, display_name,
         identity_type, identity_category, risk_score, risk_level,
         agent_identity_type, activity_status, last_sign_in, created_datetime,
         enabled, is_microsoft_system, risk_reasons)
    VALUES
    -- 20: customer support bot (active, low-risk)
    (3, _run_id, 'df000020-d3a0-4000-aaaa-aaaaaaaaa020', 'demo-ai-customer-support',
     'service_principal', 'service_principal', 32, 'low',
     'ai_agent', 'active', NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '6 days', TRUE, FALSE,
     ARRAY['ai_agent','single_purpose']),
    -- 21: RAG finance (high — reads financial data)
    (3, _run_id, 'df000021-d3a0-4000-aaaa-aaaaaaaaa021', 'demo-ai-rag-finance',
     'service_principal', 'service_principal', 74, 'high',
     'ai_agent', 'active', NOW() - INTERVAL '45 minutes', NOW() - INTERVAL '4 days', TRUE, FALSE,
     ARRAY['ai_agent','reads_financial_data','no_human_owner']),
    -- 22: fraud detector (CRITICAL — Owner + sensitive data write)
    (3, _run_id, 'df000022-d3a0-4000-aaaa-aaaaaaaaa022', 'demo-ai-fraud-detect',
     'service_principal', 'service_principal', 89, 'critical',
     'ai_agent', 'active', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '5 days', TRUE, FALSE,
     ARRAY['ai_agent','overprivileged','autonomous_workflow']),
    -- 23: legal analyzer (high — reads SOURCE classification)
    (3, _run_id, 'df000023-d3a0-4000-aaaa-aaaaaaaaa023', 'demo-ai-legal-analyzer',
     'service_principal', 'service_principal', 67, 'high',
     'ai_agent', 'active', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 days', TRUE, FALSE,
     ARRAY['ai_agent','reads_legal_documents']),
    -- 24: marketing LLM (medium — content generation)
    (3, _run_id, 'df000024-d3a0-4000-aaaa-aaaaaaaaa024', 'demo-ai-marketing-llm',
     'service_principal', 'service_principal', 48, 'medium',
     'ai_agent', 'active', NOW() - INTERVAL '5 hours', NOW() - INTERVAL '2 days', TRUE, FALSE,
     ARRAY['ai_agent','content_generation']),
    -- 25: data pipeline (high — autonomous, no human in loop)
    (3, _run_id, 'df000025-d3a0-4000-aaaa-aaaaaaaaa025', 'demo-ai-data-pipeline',
     'service_principal', 'service_principal', 71, 'high',
     'ai_agent', 'active', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '7 days', TRUE, FALSE,
     ARRAY['ai_agent','autonomous','no_human_oversight']),
    -- 26: hr screener (high — reads HR data, sensitive)
    (3, _run_id, 'df000026-d3a0-4000-aaaa-aaaaaaaaa026', 'demo-ai-hr-screener',
     'service_principal', 'service_principal', 76, 'high',
     'ai_agent', 'active', NOW() - INTERVAL '8 hours', NOW() - INTERVAL '5 days', TRUE, FALSE,
     ARRAY['ai_agent','reads_hr_data','regulated_processing']),
    -- 27: internal copilot (medium — broad reader scope across org)
    (3, _run_id, 'df000027-d3a0-4000-aaaa-aaaaaaaaa027', 'demo-ai-internal-copilot',
     'service_principal', 'service_principal', 58, 'medium',
     'ai_agent', 'active', NOW() - INTERVAL '20 minutes', NOW() - INTERVAL '6 days', TRUE, FALSE,
     ARRAY['ai_agent','broad_reader_scope'])
    ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
        is_microsoft_system = FALSE,
        risk_level = EXCLUDED.risk_level,
        risk_score = EXCLUDED.risk_score;

    UPDATE identities SET is_microsoft_system = FALSE
    WHERE organization_id=3 AND identity_id LIKE 'df0002%';
END $$;

-- ============================================================
-- SECTION 2: agent_classifications for all 8 new agents
-- ============================================================
INSERT INTO agent_classifications
    (identity_db_id, identity_id, agent_identity_type, classification_confidence,
     classification_reason, detected_platform, pattern_version, discovery_run_id,
     organization_id, model_name, owner_display_name_at_classify, account_resource_id)
SELECT i.id, i.identity_id, 'ai_agent', 0.92, 'aiag_cloud_demo_expand',
       'azure_openai', '1.0.0', 36, 3,
       CASE i.identity_id
            WHEN 'df000020-d3a0-4000-aaaa-aaaaaaaaa020' THEN 'gpt-4o-mini'
            WHEN 'df000021-d3a0-4000-aaaa-aaaaaaaaa021' THEN 'text-embedding-3-large'
            WHEN 'df000022-d3a0-4000-aaaa-aaaaaaaaa022' THEN 'gpt-4o'
            WHEN 'df000023-d3a0-4000-aaaa-aaaaaaaaa023' THEN 'gpt-4o-mini-ft-2024-07-18-ag-v1'
            WHEN 'df000024-d3a0-4000-aaaa-aaaaaaaaa024' THEN 'gpt-4o-mini'
            WHEN 'df000025-d3a0-4000-aaaa-aaaaaaaaa025' THEN 'gpt-4o'
            WHEN 'df000026-d3a0-4000-aaaa-aaaaaaaaa026' THEN 'gpt-4o-mini-ft-2024-07-18-ag-v2'
            WHEN 'df000027-d3a0-4000-aaaa-aaaaaaaaa027' THEN 'gpt-4o-mini'
       END,
       'AuditGraph Demo Platform Team',
       '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod'
FROM identities i
WHERE i.organization_id=3 AND i.identity_id LIKE 'df0002%' AND i.discovery_run_id=36
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 3: role_assignments
-- ============================================================
DO $$
DECLARE
    _sub TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111';
    _kv  TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.KeyVault/vaults/aiag-vault-phi';
    _storage TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.Storage/storageAccounts/aiagphiblob01';
    _cog TEXT := '/subscriptions/11111111-1111-4111-1111-111111111111/resourceGroups/rg-aiag-demo/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod';
BEGIN
    -- df000020 customer-support: just cognitive services user (low priv)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Cognitive Services User', _cog, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000020-d3a0-4000-aaaa-aaaaaaaaa020'
    ON CONFLICT DO NOTHING;

    -- df000021 rag-finance: storage reader on PHI (proxy for financial)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, ra.rn, ra.sc, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i, (VALUES ('Storage Blob Data Reader', _storage),
                               ('Cognitive Services OpenAI User', _cog)) AS ra(rn, sc)
    WHERE i.organization_id=3 AND i.identity_id='df000021-d3a0-4000-aaaa-aaaaaaaaa021'
    ON CONFLICT DO NOTHING;

    -- df000022 fraud-detect: Storage Blob Owner + KV Secrets User (critical)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, ra.rn, ra.sc, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i, (VALUES ('Storage Blob Data Owner', _storage),
                               ('Key Vault Secrets User', _kv),
                               ('Cognitive Services OpenAI Contributor', _cog)) AS ra(rn, sc)
    WHERE i.organization_id=3 AND i.identity_id='df000022-d3a0-4000-aaaa-aaaaaaaaa022'
    ON CONFLICT DO NOTHING;

    -- df000023 legal-analyzer: storage reader
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Storage Blob Data Reader', _storage, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000023-d3a0-4000-aaaa-aaaaaaaaa023'
    ON CONFLICT DO NOTHING;

    -- df000024 marketing-llm: cognitive services user only
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Cognitive Services OpenAI User', _cog, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000024-d3a0-4000-aaaa-aaaaaaaaa024'
    ON CONFLICT DO NOTHING;

    -- df000025 data-pipeline: contributor on RG + storage contributor
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, ra.rn, ra.sc, 'resource_group', i.identity_id, gen_random_uuid()::text
    FROM identities i, (VALUES ('Contributor', _sub || '/resourceGroups/rg-aiag-demo'),
                               ('Storage Blob Data Contributor', _storage)) AS ra(rn, sc)
    WHERE i.organization_id=3 AND i.identity_id='df000025-d3a0-4000-aaaa-aaaaaaaaa025'
    ON CONFLICT DO NOTHING;

    -- df000026 hr-screener: storage reader on PHI
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Storage Blob Data Reader', _storage, 'resource', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000026-d3a0-4000-aaaa-aaaaaaaaa026'
    ON CONFLICT DO NOTHING;

    -- df000027 internal-copilot: subscription Reader (broad blast)
    INSERT INTO role_assignments (organization_id, identity_db_id, role_name, scope, scope_type, principal_id, assignment_id)
    SELECT 3, i.id, 'Reader', _sub, 'subscription', i.identity_id, gen_random_uuid()::text
    FROM identities i WHERE i.organization_id=3 AND i.identity_id='df000027-d3a0-4000-aaaa-aaaaaaaaa027'
    ON CONFLICT DO NOTHING;
END $$;

-- ============================================================
-- SECTION 4: agent_data_reachability for the new agents
-- ============================================================
INSERT INTO agent_data_reachability
    (organization_id, discovery_run_id, identity_db_id, identity_id, data_classification,
     resource_count, write_resource_count, est_records, top_resources)
SELECT 3, 36, i.id, i.identity_id, mapping.cls, mapping.rc, mapping.wrc, mapping.recs,
       jsonb_build_array(jsonb_build_object('name','aiagphiblob01','records',mapping.recs,'role',mapping.role))
FROM identities i,
     (VALUES
        ('df000021-d3a0-4000-aaaa-aaaaaaaaa021', 'FINANCIAL', 1, 0, 85000, 'Storage Blob Data Reader'),
        ('df000022-d3a0-4000-aaaa-aaaaaaaaa022', 'PHI',       1, 1, 120000, 'Storage Blob Data Owner'),
        ('df000023-d3a0-4000-aaaa-aaaaaaaaa023', 'SOURCE',    1, 0, 12000,  'Storage Blob Data Reader'),
        ('df000025-d3a0-4000-aaaa-aaaaaaaaa025', 'PHI',       1, 1, 120000, 'Storage Blob Data Contributor'),
        ('df000026-d3a0-4000-aaaa-aaaaaaaaa026', 'HR',        1, 0, 24000,  'Storage Blob Data Reader')
     ) AS mapping(iid, cls, rc, wrc, recs, role)
WHERE i.organization_id=3 AND i.identity_id = mapping.iid
ON CONFLICT (organization_id, discovery_run_id, identity_db_id, data_classification) DO UPDATE SET
    resource_count = EXCLUDED.resource_count,
    est_records = EXCLUDED.est_records;

-- ============================================================
-- SECTION 5: identity_reachability for new agents (blast radius)
-- ============================================================
INSERT INTO identity_reachability
    (organization_id, identity_id, identity_db_id, display_name, identity_category,
     reachable_resource_count, reachable_privileged_resource_count,
     subscriptions_reachable, resource_groups_reachable, high_value_targets_reachable,
     has_privileged_roles, privileged_role_names, highest_scope_type,
     flag_broad_blast_radius, flag_privileged_wide_reach, flag_ai_excessive_blast, flag_dormant_high_blast,
     risk_flag_count, blast_radius_risk_score, blast_radius_exposure_level,
     agent_identity_type, activity_status, discovery_run_id)
SELECT 3, i.identity_id, i.id, i.display_name, i.identity_category,
       m.rrc, m.rprc, m.subs, m.rgs, m.hvt,
       m.has_priv, m.priv_roles::jsonb, m.scope,
       m.broad, m.priv_wide, m.ai_excess, m.dormant_high,
       m.flag_count, m.score, m.exposure,
       'ai_agent', 'active', 36
FROM identities i,
     (VALUES
        ('df000020-d3a0-4000-aaaa-aaaaaaaaa020', 1, 0, 0, 0, 0, FALSE, '["Cognitive Services User"]',                          'resource',     FALSE, FALSE, FALSE, FALSE, 0, 32, 'MEDIUM'),
        ('df000021-d3a0-4000-aaaa-aaaaaaaaa021', 2, 0, 0, 0, 1, FALSE, '["Storage Blob Data Reader","Cognitive Services User"]','resource',     FALSE, FALSE, TRUE,  FALSE, 1, 74, 'HIGH'),
        ('df000022-d3a0-4000-aaaa-aaaaaaaaa022', 3, 3, 0, 0, 2, TRUE,  '["Storage Blob Data Owner","Key Vault Secrets User"]', 'resource',     TRUE,  TRUE,  TRUE,  FALSE, 3, 89, 'CRITICAL'),
        ('df000023-d3a0-4000-aaaa-aaaaaaaaa023', 1, 0, 0, 0, 1, FALSE, '["Storage Blob Data Reader"]',                          'resource',     FALSE, FALSE, FALSE, FALSE, 0, 67, 'HIGH'),
        ('df000024-d3a0-4000-aaaa-aaaaaaaaa024', 1, 0, 0, 0, 0, FALSE, '["Cognitive Services User"]',                          'resource',     FALSE, FALSE, FALSE, FALSE, 0, 48, 'MEDIUM'),
        ('df000025-d3a0-4000-aaaa-aaaaaaaaa025', 5, 1, 0, 1, 1, FALSE, '["Contributor","Storage Blob Data Contributor"]',      'resource_group', TRUE,  FALSE, TRUE,  FALSE, 2, 71, 'HIGH'),
        ('df000026-d3a0-4000-aaaa-aaaaaaaaa026', 1, 0, 0, 0, 1, FALSE, '["Storage Blob Data Reader"]',                          'resource',     FALSE, FALSE, FALSE, FALSE, 0, 76, 'HIGH'),
        ('df000027-d3a0-4000-aaaa-aaaaaaaaa027', 52, 0, 1, 12, 0, FALSE, '["Reader"]',                                          'subscription', TRUE,  FALSE, FALSE, FALSE, 1, 58, 'MEDIUM')
     ) AS m(iid, rrc, rprc, subs, rgs, hvt, has_priv, priv_roles, scope, broad, priv_wide, ai_excess, dormant_high, flag_count, score, exposure)
WHERE i.organization_id=3 AND i.identity_id = m.iid
ON CONFLICT (identity_db_id, discovery_run_id) DO UPDATE SET
    blast_radius_risk_score = EXCLUDED.blast_radius_risk_score,
    blast_radius_exposure_level = EXCLUDED.blast_radius_exposure_level;

-- ============================================================
-- SECTION 6: ALL ai_agent_lifecycle_events within last 7 days
-- ============================================================
DO $$
DECLARE
    _ids RECORD;
BEGIN
    -- Cleanup already done above. Re-seed with fresh timestamps.
    -- Existing 6 demo AI agents get 2-3 events each (created + role_granted ± escalation)
    -- New 8 agents get a 'created' event each
    FOR _ids IN SELECT id, identity_id, display_name FROM identities
                WHERE organization_id=3 AND agent_identity_type='ai_agent'
                  AND (identity_id LIKE 'de000%' OR identity_id LIKE 'df000%')
                  AND discovery_run_id=36
    LOOP
        -- Every agent gets a 'created' event 1-6 days ago
        INSERT INTO ai_agent_lifecycle_events
            (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
             occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
        VALUES (3, 36, _ids.id, _ids.identity_id, 'created', 'low',
                NOW() - (INTERVAL '1 day' * (1 + (random()*5)::int)),
                NULL,
                jsonb_build_object('agent_type','ai_agent','display_name',_ids.display_name),
                'AI agent ' || _ids.display_name || ' created.', NULL)
        ON CONFLICT DO NOTHING;
    END LOOP;
END $$;

-- Specific high-severity events for the headline agents (within last 7 days)
DO $$
DECLARE
    _copilot BIGINT; _multi BIGINT; _ft BIGINT; _fraud BIGINT; _pipeline BIGINT;
BEGIN
    SELECT id INTO _copilot  FROM identities WHERE organization_id=3 AND identity_id='de000001-d3a0-4000-aaaa-aaaaaaaaa001';
    SELECT id INTO _multi    FROM identities WHERE organization_id=3 AND identity_id='df000011-d3a0-4000-aaaa-aaaaaaaaa011';
    SELECT id INTO _ft       FROM identities WHERE organization_id=3 AND identity_id='df000012-d3a0-4000-aaaa-aaaaaaaaa012';
    SELECT id INTO _fraud    FROM identities WHERE organization_id=3 AND identity_id='df000022-d3a0-4000-aaaa-aaaaaaaaa022';
    SELECT id INTO _pipeline FROM identities WHERE organization_id=3 AND identity_id='df000025-d3a0-4000-aaaa-aaaaaaaaa025';

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _copilot, 'de000001-d3a0-4000-aaaa-aaaaaaaaa001', 'privilege_escalation', 'critical',
            NOW() - INTERVAL '6 hours',
            '{"roles":["Reader","Storage Blob Data Reader"]}'::jsonb,
            '{"roles":["Key Vault Administrator","Storage Blob Data Owner"]}'::jsonb,
            'Massive privilege escalation: gained KV Admin + Blob Owner on PHI vault.',
            '["T1078.004","T1098"]'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _multi, 'df000011-d3a0-4000-aaaa-aaaaaaaaa011', 'model_added', 'medium',
            NOW() - INTERVAL '2 days',
            '{"models":["gpt-4o","text-embedding-3-large"]}'::jsonb,
            '{"models":["gpt-4o","text-embedding-3-large","dall-e-3"]}'::jsonb,
            'Added dall-e-3 multimodal image generation model.',
            '["T1588"]'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _ft, 'df000012-d3a0-4000-aaaa-aaaaaaaaa012', 'custom_model_deployed', 'high',
            NOW() - INTERVAL '3 days',
            '{"custom_models":[]}'::jsonb,
            '{"custom_models":["gpt-4o-mini-ft-v1","gpt-4o-mini-ft-v2"]}'::jsonb,
            'Two custom fine-tuned models deployed to aiag-openai-prod.', NULL)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _fraud, 'df000022-d3a0-4000-aaaa-aaaaaaaaa022', 'role_granted', 'critical',
            NOW() - INTERVAL '4 days',
            '{"roles":["Storage Blob Data Reader"]}'::jsonb,
            '{"roles":["Storage Blob Data Owner","Key Vault Secrets User"]}'::jsonb,
            'Agent gained write access to PHI blob storage + KV secrets — privilege escalation.',
            '["T1098"]'::jsonb)
    ON CONFLICT DO NOTHING;

    INSERT INTO ai_agent_lifecycle_events
        (organization_id, discovery_run_id, identity_db_id, identity_id, event_type, severity,
         occurred_at, before_snapshot, after_snapshot, description, mitre_techniques)
    VALUES (3, 36, _pipeline, 'df000025-d3a0-4000-aaaa-aaaaaaaaa025', 'role_granted', 'high',
            NOW() - INTERVAL '5 days',
            '{"roles":[]}'::jsonb,
            '{"roles":["Contributor","Storage Blob Data Contributor"]}'::jsonb,
            'Autonomous pipeline agent granted Contributor on rg-aiag-demo.',
            '["T1098"]'::jsonb)
    ON CONFLICT DO NOTHING;
END $$;

-- ============================================================
-- SECTION 7: more leavers (flip 2 existing identities to disabled)
-- ============================================================
UPDATE identities SET enabled = FALSE
WHERE organization_id=3 AND identity_id IN (
    'df000006-d3a0-4000-aaaa-aaaaaaaaa006',  -- demo-dormant-admin-02 (KV Admin, dormant 87d)
    'df000008-d3a0-4000-aaaa-aaaaaaaaa008'   -- demo-stale-creds-01
);

-- ============================================================
-- SECTION 8: more mover anomalies
-- ============================================================
INSERT INTO anomalies
    (organization_id, discovery_run_id, anomaly_type, severity, identity_id, identity_name,
     title, description, details, resolved, created_at)
VALUES
    (3, 36, 'mover_stale_access', 'high',
     'df000014-d3a0-4000-aaaa-aaaaaaaaa014', 'demo-pim-eligible-01',
     'Mover retains PIM Owner eligibility after team change',
     'demo-pim-eligible-01 moved from Platform Eng to Customer Success 60 days ago. PIM-eligible Owner assignment should have been removed on transfer.',
     '{"prior_team":"Platform Eng","new_team":"Customer Success","days_since_move":60,"retained_pim":["Owner"]}'::jsonb,
     FALSE, NOW() - INTERVAL '2 days'),
    (3, 36, 'mover_stale_access', 'medium',
     'df000004-d3a0-4000-aaaa-aaaaaaaaa004', 'demo-overprivileged-sp-01',
     'Workload moved to different application — owner not updated',
     'demo-overprivileged-sp-01 reassigned to a new application 30 days ago, but the original owner is still listed and retains Subscription Owner role.',
     '{"days_since_reassignment":30,"prior_owner":"former-team@auditgraph-demo","new_owner":"unknown"}'::jsonb,
     FALSE, NOW() - INTERVAL '4 days')
ON CONFLICT DO NOTHING;

-- ============================================================
-- SECTION 9: Recompute total_identities
-- ============================================================
UPDATE discovery_runs SET total_identities = (
    SELECT count(*) FROM identities WHERE organization_id=3 AND discovery_run_id=36
) WHERE id = 36;

COMMIT;

\echo ''
\echo '=== New AI agents ==='
SELECT identity_id, display_name, risk_level FROM identities
WHERE organization_id=3 AND identity_id LIKE 'df0002%' ORDER BY identity_id;

\echo ''
\echo '=== Lifecycle events within 7 days ==='
SELECT count(*) AS within_7d FROM ai_agent_lifecycle_events
WHERE organization_id=3 AND occurred_at >= NOW() - INTERVAL '7 days';

\echo ''
\echo '=== Total run 36 ==='
SELECT id, total_identities FROM discovery_runs WHERE id=36;

\echo ''
\echo '=== Disabled identities (leavers) ==='
SELECT identity_id, display_name FROM identities
WHERE organization_id=3 AND discovery_run_id=36 AND enabled=FALSE ORDER BY identity_id;

\echo ''
\echo '=== Mover anomalies ==='
SELECT count(*) AS movers FROM anomalies
WHERE organization_id=3 AND anomaly_type='mover_stale_access' AND NOT resolved;
