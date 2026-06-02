-- 117_restore_constraints_sweep.sql
--
-- AG-DBFIX (continuation of 116): migration 100_full_schema.sql lost
-- PRIMARY KEYs and UNIQUE constraints across ~80 tables. Migration 116
-- handled graph_api_permissions + sp_app_roles (where INSERTs were
-- silently failing). This sweep restores the rest.
--
-- Why this matters even when INSERTs currently succeed:
--   1. Without PRIMARY KEY (id), duplicate id values are possible — and
--      DO occur (e.g. sp_ownership row id=16 appears 10 times locally).
--   2. Without UNIQUE constraints, ON CONFLICT clauses in upcoming code
--      paths would silently fail the same way graph_api_permissions did.
--   3. Foreign-key references to these tables can never be added.
--   4. CTID-based UPDATEs and replication tools (logical, CDC) misbehave
--      without a PK.
--
-- All ALTERs are idempotent (NOT EXISTS guards) and additive only — no
-- data is dropped, modified, or migrated. Safe to re-run.
--
-- Pre-flight audited against local DB: 80 PK adds are SAFE; 12 UNIQUE
-- adds are SAFE; 1 PK skipped (sp_ownership — duplicate id=16);
-- 2 UNIQUEs skipped (attack_paths, security_findings — duplicate rows
-- accumulated due to the missing constraint). The skipped items are
-- documented at the bottom and require manual review.

BEGIN;

-- Section 1: Restore PRIMARY KEY (id) on 80 tables
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='access_review_campaigns'::regclass AND contype='p') THEN
    ALTER TABLE access_review_campaigns ADD CONSTRAINT access_review_campaigns_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='access_reviews'::regclass AND contype='p') THEN
    ALTER TABLE access_reviews ADD CONSTRAINT access_reviews_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='activity_log'::regclass AND contype='p') THEN
    ALTER TABLE activity_log ADD CONSTRAINT activity_log_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='admin_audit_log'::regclass AND contype='p') THEN
    ALTER TABLE admin_audit_log ADD CONSTRAINT admin_audit_log_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='agirs_scores'::regclass AND contype='p') THEN
    ALTER TABLE agirs_scores ADD CONSTRAINT agirs_scores_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='anomalies'::regclass AND contype='p') THEN
    ALTER TABLE anomalies ADD CONSTRAINT anomalies_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='api_keys'::regclass AND contype='p') THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='app_reg_exposure_findings'::regclass AND contype='p') THEN
    ALTER TABLE app_reg_exposure_findings ADD CONSTRAINT app_reg_exposure_findings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='app_registrations'::regclass AND contype='p') THEN
    ALTER TABLE app_registrations ADD CONSTRAINT app_registrations_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='attack_paths'::regclass AND contype='p') THEN
    ALTER TABLE attack_paths ADD CONSTRAINT attack_paths_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='azure_key_vaults'::regclass AND contype='p') THEN
    ALTER TABLE azure_key_vaults ADD CONSTRAINT azure_key_vaults_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='azure_storage_accounts'::regclass AND contype='p') THEN
    ALTER TABLE azure_storage_accounts ADD CONSTRAINT azure_storage_accounts_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='billing_audit_log'::regclass AND contype='p') THEN
    ALTER TABLE billing_audit_log ADD CONSTRAINT billing_audit_log_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='billing_events'::regclass AND contype='p') THEN
    ALTER TABLE billing_events ADD CONSTRAINT billing_events_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='blast_radius_results'::regclass AND contype='p') THEN
    ALTER TABLE blast_radius_results ADD CONSTRAINT blast_radius_results_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='ca_identity_coverage'::regclass AND contype='p') THEN
    ALTER TABLE ca_identity_coverage ADD CONSTRAINT ca_identity_coverage_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='ca_policies'::regclass AND contype='p') THEN
    ALTER TABLE ca_policies ADD CONSTRAINT ca_policies_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='campaign_audit_log'::regclass AND contype='p') THEN
    ALTER TABLE campaign_audit_log ADD CONSTRAINT campaign_audit_log_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='campaign_reviews'::regclass AND contype='p') THEN
    ALTER TABLE campaign_reviews ADD CONSTRAINT campaign_reviews_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='cloud_connections'::regclass AND contype='p') THEN
    ALTER TABLE cloud_connections ADD CONSTRAINT cloud_connections_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='cloud_subscriptions'::regclass AND contype='p') THEN
    ALTER TABLE cloud_subscriptions ADD CONSTRAINT cloud_subscriptions_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='compliance_controls'::regclass AND contype='p') THEN
    ALTER TABLE compliance_controls ADD CONSTRAINT compliance_controls_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='compliance_frameworks'::regclass AND contype='p') THEN
    ALTER TABLE compliance_frameworks ADD CONSTRAINT compliance_frameworks_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='compliance_root_causes'::regclass AND contype='p') THEN
    ALTER TABLE compliance_root_causes ADD CONSTRAINT compliance_root_causes_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='compliance_snapshots'::regclass AND contype='p') THEN
    ALTER TABLE compliance_snapshots ADD CONSTRAINT compliance_snapshots_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='copilot_conversations'::regclass AND contype='p') THEN
    ALTER TABLE copilot_conversations ADD CONSTRAINT copilot_conversations_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='custom_risk_rules'::regclass AND contype='p') THEN
    ALTER TABLE custom_risk_rules ADD CONSTRAINT custom_risk_rules_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='dashboard_preferences'::regclass AND contype='p') THEN
    ALTER TABLE dashboard_preferences ADD CONSTRAINT dashboard_preferences_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='discovery_integrity_metrics'::regclass AND contype='p') THEN
    ALTER TABLE discovery_integrity_metrics ADD CONSTRAINT discovery_integrity_metrics_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='drift_reports'::regclass AND contype='p') THEN
    ALTER TABLE drift_reports ADD CONSTRAINT drift_reports_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='fix_recommendations'::regclass AND contype='p') THEN
    ALTER TABLE fix_recommendations ADD CONSTRAINT fix_recommendations_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='governance_decisions'::regclass AND contype='p') THEN
    ALTER TABLE governance_decisions ADD CONSTRAINT governance_decisions_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='human_identities'::regclass AND contype='p') THEN
    ALTER TABLE human_identities ADD CONSTRAINT human_identities_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='identity_group_members'::regclass AND contype='p') THEN
    ALTER TABLE identity_group_members ADD CONSTRAINT identity_group_members_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='identity_groups'::regclass AND contype='p') THEN
    ALTER TABLE identity_groups ADD CONSTRAINT identity_groups_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='identity_links'::regclass AND contype='p') THEN
    ALTER TABLE identity_links ADD CONSTRAINT identity_links_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='identity_subscription_access'::regclass AND contype='p') THEN
    ALTER TABLE identity_subscription_access ADD CONSTRAINT identity_subscription_access_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='invoice_documents'::regclass AND contype='p') THEN
    ALTER TABLE invoice_documents ADD CONSTRAINT invoice_documents_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='invoices'::regclass AND contype='p') THEN
    ALTER TABLE invoices ADD CONSTRAINT invoices_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='job_runs'::regclass AND contype='p') THEN
    ALTER TABLE job_runs ADD CONSTRAINT job_runs_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='msp_relationships'::regclass AND contype='p') THEN
    ALTER TABLE msp_relationships ADD CONSTRAINT msp_relationships_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='notifications'::regclass AND contype='p') THEN
    ALTER TABLE notifications ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='organization_billing_snapshots'::regclass AND contype='p') THEN
    ALTER TABLE organization_billing_snapshots ADD CONSTRAINT organization_billing_snapshots_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='organization_entitlements'::regclass AND contype='p') THEN
    ALTER TABLE organization_entitlements ADD CONSTRAINT organization_entitlements_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='organization_usage'::regclass AND contype='p') THEN
    ALTER TABLE organization_usage ADD CONSTRAINT organization_usage_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='organization_usage_counters'::regclass AND contype='p') THEN
    ALTER TABLE organization_usage_counters ADD CONSTRAINT organization_usage_counters_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='orphaned_privileged_findings'::regclass AND contype='p') THEN
    ALTER TABLE orphaned_privileged_findings ADD CONSTRAINT orphaned_privileged_findings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='pim_activations'::regclass AND contype='p') THEN
    ALTER TABLE pim_activations ADD CONSTRAINT pim_activations_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='pim_eligible_assignments'::regclass AND contype='p') THEN
    ALTER TABLE pim_eligible_assignments ADD CONSTRAINT pim_eligible_assignments_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='plans'::regclass AND contype='p') THEN
    ALTER TABLE plans ADD CONSTRAINT plans_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='rbac_hygiene_scans'::regclass AND contype='p') THEN
    ALTER TABLE rbac_hygiene_scans ADD CONSTRAINT rbac_hygiene_scans_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='refresh_tokens'::regclass AND contype='p') THEN
    ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='remediation_actions'::regclass AND contype='p') THEN
    ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='remediation_playbooks'::regclass AND contype='p') THEN
    ALTER TABLE remediation_playbooks ADD CONSTRAINT remediation_playbooks_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='report_outputs'::regclass AND contype='p') THEN
    ALTER TABLE report_outputs ADD CONSTRAINT report_outputs_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='report_runs'::regclass AND contype='p') THEN
    ALTER TABLE report_runs ADD CONSTRAINT report_runs_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='reports'::regclass AND contype='p') THEN
    ALTER TABLE reports ADD CONSTRAINT reports_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='resource_findings'::regclass AND contype='p') THEN
    ALTER TABLE resource_findings ADD CONSTRAINT resource_findings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='resource_risk_history'::regclass AND contype='p') THEN
    ALTER TABLE resource_risk_history ADD CONSTRAINT resource_risk_history_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='review_assignments'::regclass AND contype='p') THEN
    ALTER TABLE review_assignments ADD CONSTRAINT review_assignments_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='review_evidence'::regclass AND contype='p') THEN
    ALTER TABLE review_evidence ADD CONSTRAINT review_evidence_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='role_activity_log'::regclass AND contype='p') THEN
    ALTER TABLE role_activity_log ADD CONSTRAINT role_activity_log_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='role_attack_patterns'::regclass AND contype='p') THEN
    ALTER TABLE role_attack_patterns ADD CONSTRAINT role_attack_patterns_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='role_hipaa_mappings'::regclass AND contype='p') THEN
    ALTER TABLE role_hipaa_mappings ADD CONSTRAINT role_hipaa_mappings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='role_permissions'::regclass AND contype='p') THEN
    ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='sa_attestations'::regclass AND contype='p') THEN
    ALTER TABLE sa_attestations ADD CONSTRAINT sa_attestations_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='saved_views'::regclass AND contype='p') THEN
    ALTER TABLE saved_views ADD CONSTRAINT saved_views_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='scan_schedules'::regclass AND contype='p') THEN
    ALTER TABLE scan_schedules ADD CONSTRAINT scan_schedules_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='security_findings'::regclass AND contype='p') THEN
    ALTER TABLE security_findings ADD CONSTRAINT security_findings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='settings'::regclass AND contype='p') THEN
    ALTER TABLE settings ADD CONSTRAINT settings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='soar_actions'::regclass AND contype='p') THEN
    ALTER TABLE soar_actions ADD CONSTRAINT soar_actions_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='soar_playbooks'::regclass AND contype='p') THEN
    ALTER TABLE soar_playbooks ADD CONSTRAINT soar_playbooks_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='spn_exposure_findings'::regclass AND contype='p') THEN
    ALTER TABLE spn_exposure_findings ADD CONSTRAINT spn_exposure_findings_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='sso_auth_codes'::regclass AND contype='p') THEN
    ALTER TABLE sso_auth_codes ADD CONSTRAINT sso_auth_codes_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='system_health_metrics'::regclass AND contype='p') THEN
    ALTER TABLE system_health_metrics ADD CONSTRAINT system_health_metrics_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='webhook_deliveries'::regclass AND contype='p') THEN
    ALTER TABLE webhook_deliveries ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='webhooks'::regclass AND contype='p') THEN
    ALTER TABLE webhooks ADD CONSTRAINT webhooks_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='workload_activity_stats'::regclass AND contype='p') THEN
    ALTER TABLE workload_activity_stats ADD CONSTRAINT workload_activity_stats_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='workload_anomaly_events'::regclass AND contype='p') THEN
    ALTER TABLE workload_anomaly_events ADD CONSTRAINT workload_anomaly_events_pkey PRIMARY KEY (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='workload_signin_events'::regclass AND contype='p') THEN
    ALTER TABLE workload_signin_events ADD CONSTRAINT workload_signin_events_pkey PRIMARY KEY (id);
  END IF;
END$$;

-- Section 2: Restore UNIQUE constraints (12 safe adds)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='app_registrations'::regclass AND contype='u' AND conname='app_registrations_discovery_run_id_app_id_key') THEN
    ALTER TABLE app_registrations ADD CONSTRAINT app_registrations_discovery_run_id_app_id_key UNIQUE (discovery_run_id, app_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='blast_radius_results'::regclass AND contype='u' AND conname='blast_radius_results_discovery_run_id_identity_id_key') THEN
    ALTER TABLE blast_radius_results ADD CONSTRAINT blast_radius_results_discovery_run_id_identity_id_key UNIQUE (discovery_run_id, identity_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='ca_identity_coverage'::regclass AND contype='u' AND conname='ca_identity_coverage_identity_db_id_key') THEN
    ALTER TABLE ca_identity_coverage ADD CONSTRAINT ca_identity_coverage_identity_db_id_key UNIQUE (identity_db_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='ca_policies'::regclass AND contype='u' AND conname='ca_policies_discovery_run_id_policy_id_key') THEN
    ALTER TABLE ca_policies ADD CONSTRAINT ca_policies_discovery_run_id_policy_id_key UNIQUE (discovery_run_id, policy_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='compliance_snapshots'::regclass AND contype='u' AND conname='compliance_snapshots_run_id_framework_key_key') THEN
    ALTER TABLE compliance_snapshots ADD CONSTRAINT compliance_snapshots_run_id_framework_key_key UNIQUE (run_id, framework_key);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='fix_recommendations'::regclass AND contype='u' AND conname='fix_recommendations_discovery_run_id_entity_id_fix_type_key') THEN
    ALTER TABLE fix_recommendations ADD CONSTRAINT fix_recommendations_discovery_run_id_entity_id_fix_type_key UNIQUE (discovery_run_id, entity_id, fix_type);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='identity_links'::regclass AND contype='u' AND conname='identity_links_organization_id_account_object_id_key') THEN
    ALTER TABLE identity_links ADD CONSTRAINT identity_links_organization_id_account_object_id_key UNIQUE (organization_id, account_object_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='msp_relationships'::regclass AND contype='u' AND conname='msp_relationships_msp_organization_id_client_organizati_key') THEN
    ALTER TABLE msp_relationships ADD CONSTRAINT msp_relationships_msp_organization_id_client_organizati_key UNIQUE (msp_organization_id, client_organization_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='organization_usage_counters'::regclass AND contype='u' AND conname='organization_usage_counters_organization_id_resource_ty_key') THEN
    ALTER TABLE organization_usage_counters ADD CONSTRAINT organization_usage_counters_organization_id_resource_ty_key UNIQUE (organization_id, resource_type);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='plans'::regclass AND contype='u' AND conname='plans_id_key') THEN
    ALTER TABLE plans ADD CONSTRAINT plans_id_key UNIQUE (id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='remediation_actions'::regclass AND contype='u' AND conname='remediation_actions_identity_id_playbook_id_key') THEN
    ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_identity_id_playbook_id_key UNIQUE (identity_id, playbook_id);
  END IF;
END$$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='tenant_health'::regclass AND contype='u' AND conname='tenant_health_organization_id_key') THEN
    ALTER TABLE tenant_health ADD CONSTRAINT tenant_health_organization_id_key UNIQUE (organization_id);
  END IF;
END$$;

COMMIT;

-- ─── Items intentionally NOT included in this sweep ────────────────────
--
-- 1. sp_ownership ADD PRIMARY KEY (id)
--    Blocked: 10 rows share id=16 (likely an older seeder that didn't
--    increment its id counter). Different (identity_db_id, owner_object_id)
--    so the data is real — they just share an id.
--    Fix path (manual):
--      WITH dups AS (
--        SELECT ctid, id, row_number() OVER (PARTITION BY id ORDER BY ctid) AS rn
--          FROM sp_ownership WHERE id IN (SELECT id FROM sp_ownership GROUP BY id HAVING count(*) > 1)
--      ) UPDATE sp_ownership s SET id = nextval('sp_ownership_id_seq')
--          FROM dups d WHERE s.ctid = d.ctid AND d.rn > 1;
--    Then re-run this migration's PK block for sp_ownership.
--
-- 2. attack_paths ADD UNIQUE (discovery_run_id, source_entity_id, path_type, description)
--    Blocked: 5 duplicate groups. Likely the same attack path re-discovered
--    multiple times within a single run because the missing UNIQUE meant
--    the upsert always inserted instead of upserting.
--    Fix path: dedupe to keep newest row per group, then add UNIQUE.
--
-- 3. security_findings ADD UNIQUE (discovery_run_id, entity_id, finding_type)
--    Blocked: 28 duplicate groups. Same root cause as attack_paths.
--    Fix path: same as attack_paths.
--
-- These three items are deliberately surfaced rather than silently
-- patched because dedup requires choosing which row "wins" — that's a
-- decision for the operator, not a migration.
