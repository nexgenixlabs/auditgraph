import pathlib as _pathlib
from dotenv import load_dotenv
# Load backend/.env relative to this file's location so it works
# regardless of CWD (e.g. started from project root vs backend/)
load_dotenv(_pathlib.Path(__file__).resolve().parent.parent / '.env')

from flask import Flask, jsonify, g, request
from flask_cors import CORS
from datetime import datetime
import atexit
import logging
import os
import re
import time
import uuid

from app.config import APP_ENV, IS_DEV, IS_LOCAL, log_startup_banner
from app.logging_config import configure_logging
from app.metrics import MetricsCollector
from app.security import rate_limit, add_security_headers
from app.constants.agirs import PURGE_RATE_LIMIT_REQUESTS, PURGE_RATE_LIMIT_WINDOW_SECONDS
from app.idempotency import idempotent
from app.api.validation import (
    validate_json, LOGIN_SCHEMA, REFRESH_SCHEMA, CREATE_CONNECTION_SCHEMA,
    TRIGGER_RUN_SCHEMA, COPILOT_CHAT_SCHEMA, CREATE_USER_SCHEMA,
    CREATE_WEBHOOK_SCHEMA, SAVE_SETTINGS_SCHEMA, CHANGE_PASSWORD_SCHEMA,
    ROTATE_CREDENTIALS_SCHEMA,
)

from app.api.auth import auth_middleware, require_role, require_superadmin, require_portal_access, require_portal_role, require_feature
from app.api.handlers import (
    _safe_handler,
    get_stats,
    get_identities,
    get_identity_details,
    get_risks,
    get_identity_summary,
    get_dashboard_posture,
    get_dashboard_compliance,
    get_overview_insights,
    get_attack_surface_score,
    get_credential_intelligence,
    get_trust_dashboard,
    get_identity_graph_data,
    get_identity_pim_data,
    get_identity_usage,
    get_exposure_graph,
    get_dashboard_ca_summary,
    get_discovery_runs,
    get_snapshots,
    get_snapshot_state,
    get_snapshot_compare,
    get_drift_report,
    trigger_discovery,
    get_scheduler_status,
    get_identity_remediations,
    get_report_data,
    get_latest_drift,
    get_drift_history,
    get_trends,
    get_app_settings,
    save_app_settings,
    test_email,
    get_activity,
    export_audit_trail,
    get_remediation_status,
    post_remediation_action,
    get_remediation_dashboard_summary,
    get_generated_remediations_handler,
    update_generated_remediation_handler,
    trigger_remediation_generation_handler,
    get_remediation_script_handler,
    post_bulk_remediation,
    get_role_usage_stats,
    get_role_mining,
    get_webhooks_list,
    create_webhook,
    update_webhook,
    delete_webhook,
    test_webhook_endpoint,
    get_webhook_deliveries,
    get_risk_rules_list,
    create_risk_rule,
    update_risk_rule,
    delete_risk_rule,
    preview_risk_rule,
    get_notifications_list,
    get_notification_stats_handler,
    mark_notification_handler,
    mark_all_notifications_read_handler,
    delete_notification_handler,
    auth_login,
    auth_refresh,
    auth_logout,
    auth_me,
    change_password,
    get_users_list,
    create_user_handler,
    update_user_handler,
    delete_user_handler,
    get_compliance_frameworks_list,
    toggle_compliance_framework_handler,
    get_compliance_gap_analysis,
    get_compliance_trends_handler,
    get_compliance_intelligence,
    export_data,
    export_evidence_zip,
    get_saved_views_list,
    create_saved_view_handler,
    update_saved_view_handler,
    delete_saved_view_handler,
    set_default_view_handler,
    get_identity_lifecycle,
    get_groups_list,
    create_group_handler,
    get_group_detail,
    update_group_handler,
    delete_group_handler,
    add_group_members_handler,
    remove_group_members_handler,
    get_group_comparison_handler,
    get_identity_groups_handler,
    query_identities,
    get_query_fields,
    get_anomalies_list,
    get_anomaly_stats_handler,
    get_anomaly_detail,
    resolve_anomaly_handler,
    get_identity_anomalies_handler,
    get_dashboard_anomalies,
    get_trends_velocity,
    get_identity_risk_history,
    get_batch_risk_history,
    get_api_keys_list,
    create_api_key_handler,
    update_api_key_handler,
    delete_api_key_handler,
    get_soar_playbooks_list,
    create_soar_playbook_handler,
    update_soar_playbook_handler,
    delete_soar_playbook_handler,
    test_soar_playbook_handler,
    get_soar_actions_list,
    get_soar_action_stats_handler,
    execute_soar_action_handler,
    get_dashboard_preferences_handler,
    save_dashboard_preferences_handler,
    reset_dashboard_preferences_handler,
    get_organizations_list,
    create_organization_handler,
    update_organization_handler,
    delete_organization_handler,
    bulk_delete_organizations_handler,
    get_current_organization_handler,
    get_cross_org_analytics,
    get_cross_org_trends,
    get_login_sessions,
    get_onboarding_status,
    test_azure_connection,
    simulate_risk,
    get_organization_by_slug_public,
    validate_organization_slug,
    provision_organization_handler,
    reset_client_root_user,
    get_user_organizations_handler,
    sso_status,
    saml_metadata,
    saml_login,
    saml_acs,
    saml_token_exchange,
    saml_slo,
    get_sso_settings,
    save_sso_settings,
    parse_sso_metadata,
    get_sa_governance_stats,
    get_sa_governance_list,
    post_sa_attestation,
    get_sa_governance_settings,
    save_sa_governance_settings,
    get_governance_identities,
    get_governance_identity_detail,
    post_governance_decision,
    get_governance_stats,
    health_check,
    health_live,
    health_ready,
    prometheus_metrics,
    get_system_health,
    get_sla_metrics,
    get_portal_users_list,
    get_spn_stats,
    get_spn_list,
    get_spn_detail,
    get_identity_lineage,
    get_spn_lineage,
    get_storage_stats,
    validate_org_isolation,
    run_manual_cleanup,
    execute_remediation,
    get_remediation_queue_handler,
    batch_auto_remediate,
    get_app_reg_stats,
    get_app_reg_list,
    get_app_reg_detail,
    get_organization_config,
    get_organization_entitlements,
    get_organization_branding,
    get_organization_stage,
    update_organization_stage,
    upload_organization_logo,
    delete_organization_logo,
    get_scan_modes,
    copilot_chat,
    copilot_conversations_list,
    copilot_suggestions,
    get_identity_timeline,
    get_identity_attack_paths,
    get_identity_effective_access,
    get_integration_settings,
    save_integration_settings,
    test_integration_webhook,
    forgot_password_handler,
    validate_reset_token_handler,
    reset_password_handler,
    admin_reset_user_password,
    get_subscriptions_list,
    get_subscriptions_stats,
    activate_subscription,
    activate_all_subscriptions,
    deactivate_subscription,
    reconcile_subscriptions,
    get_subscriptions_distinct,
    get_subscriptions_scope_summary,
    get_identity_subscriptions,
    activate_client_subscription,
    get_discovery_status,
    get_snapshot_job_status,
    get_discovery_history,
    get_discovery_settings,
    update_discovery_settings,
    run_discovery,
    get_admin_organization_billing,
    update_admin_organization_plan,
    update_admin_organization_commitment,
    update_admin_organization_platform_fee,
    update_admin_cloud_rate,
    get_admin_billing_summary,
    get_admin_billing_events,
    get_admin_action_log,
    admin_impersonate,
    admin_end_impersonation,
    get_client_billing_summary,
    get_client_usage_metering,
    get_platform_settings,
    update_platform_settings_handler,
    generate_invoice,
    get_admin_invoices,
    get_admin_invoice,
    update_invoice_status_handler,
    send_invoice_email,
    get_client_invoices,
    get_client_invoice,
    verify_client_invoice,
    verify_admin_invoice,
    get_client_billing_preview,
    get_client_connections,
    get_inventory_summary,
    create_client_connection,
    update_client_connection,
    delete_client_connection,
    purge_client_connection_data,
    cleanup_inactive_connections_handler,
    rotate_connector_credentials,
    check_connector_credential_expiry_handler,
    test_client_connection,
    discover_client_connection,
    get_rbac_hygiene_combined,
    get_rbac_hygiene_summary,
    get_rbac_hygiene_findings,
    run_rbac_hygiene_scan,
    get_rbac_hygiene_history,
    get_workload_stats,
    get_workload_list,
    get_workload_detail,
    get_workload_findings,
    get_workload_anomalies,
    get_workload_anomaly_stats,
    # ICE: Identity Correlation Engine
    get_correlation_linked_identities,
    get_correlation_linked_identity_detail,
    post_correlation_link,
    delete_correlation_link,
    verify_correlation_link,
    get_orphaned_findings_list,
    get_orphaned_finding_detail_handler,
    acknowledge_orphaned_finding,
    remediate_orphaned_finding,
    suppress_orphaned_finding,
    get_correlation_config,
    save_correlation_config,
    get_dashboard_identity_correlation,
    get_correlation_accounts,
    get_identity_risk_summary,
    get_risk_summary,
    get_risk_summary_full,
    get_exposure_summary,
    get_attack_path_count,
    get_dangerous_identities,
    get_sensitive_access_for_identity,
    get_blast_radius_summary,
    platform_integrity_check_handler,
    data_source_map_handler,
    metric_integrity_debug_handler,
    governance_reconciliation_handler,
    # Phase 5: Launch Readiness
    validate_launch_readiness,
    # Phase 6: Scan Schedules, Stripe, Pilot, Password Policy
    get_scan_schedules_list,
    create_scan_schedule_handler,
    update_scan_schedule_handler,
    delete_scan_schedule_handler,
    get_stripe_status,
    stripe_webhook_handler,
    create_stripe_customer_handler,
    create_pilot_organization,
    get_password_policy,
    get_billing_current_estimate,
    get_billing_history_handler,
    get_billing_invoice_download,
    get_billing_status_handler,
    get_msp_billing_aggregate,
    admin_generate_billing_snapshot,
    admin_generate_invoice_document,
    admin_update_msp_relationship,
    verify_snapshot_integrity,
    get_findings_list,
    get_findings_stats_handler,
    get_finding_detail,
    update_finding_status_handler,
    get_risk_findings_list,
    acknowledge_risk_finding,
    resolve_risk_finding,
    get_graph_identity_access,
    get_graph_identity_attack_paths,
    get_nhi_security_findings,
    get_dashboard_summary_handler,
    get_policy_recommendations_handler,
    accept_policy_recommendation,
    dismiss_policy_recommendation,
    execute_remediation_handler,
    approve_remediation_handler,
    get_remediation_actions_handler,
    run_attack_simulation_handler,
    get_attack_simulation_handler,
    get_attack_simulations_list_handler,
    get_security_benchmark_handler,
    get_security_advisor_handler,
    get_risk_forecast_handler,
    get_generated_policy_handler,
    get_generated_policies_list_handler,
    apply_generated_policy_handler,
    dismiss_generated_policy_handler,
    get_threat_events_handler,
    acknowledge_threat_event_handler,
    resolve_threat_event_handler,
    get_identity_history_handler,
    get_activity_events_handler,
    get_attack_incidents_handler,
    get_attack_replay_handler,
    update_incident_status_handler,
    get_response_actions_handler,
    approve_response_action_handler,
    execute_response_action_handler,
    get_attack_predictions_handler,
    get_graph_insights_handler,
    get_governance_actions_handler,
    run_risk_simulation_handler,
    get_risk_simulations_handler,
    get_integration_events_handler,
    configure_integration_handler,
    get_governance_metrics_handler,
    get_governance_trends_handler,
    get_strategy_advisor_handler,
    get_command_center_handler,
    process_copilot_query_handler,
    get_copilot_history_handler,
    get_cloud_risk_summary_handler,
    get_security_overview_handler,
    get_security_findings_handler,
    get_security_findings_summary_handler,
    acknowledge_security_finding_handler,
    resolve_security_finding_handler,
    get_security_dashboard_handler,
    get_graph_visualization_handler,
    get_graph_debug_handler,
    get_identity_graph_handler,
    get_attack_path_graph_handler,
    # Identity Graph Engine
    get_graph_engine_attack_paths,
    get_graph_engine_blast_radius,
    get_graph_engine_escalation_paths,
    # Identity Risk Summary & AI Explanation
    get_identity_risk_summary_detail,
    get_identity_ai_risk_explanation,
    post_ai_attack_path_explanation,
    post_ai_executive_narrative,
    # Phase 91: AI Investigation Assistant
    ai_investigate_assistant_handler,
    # AI Audit Log
    get_ai_audit_log_handler,
    # AI Remediation Planner
    post_ai_remediation_plan,
    # Least Privilege Role Generator
    post_ai_least_privilege_role,
    get_graph_diff_handler,
    get_attack_paths_list,
    get_attack_path_detail,
    get_identity_persisted_attack_paths,
    trigger_attack_path_analysis,
    get_attack_surface_summary,
    get_fix_recommendations_list,
    get_fix_recommendations_stats_handler,
    get_fix_recommendation_detail,
    update_fix_recommendation_status_handler,
    get_identity_fix_recommendations,
    get_blast_radius_list,
    get_blast_radius_detail,
    get_identity_blast_radius,
    p6_create_access_review,
    p6_get_access_reviews,
    p6_get_access_review,
    get_access_review_assignments_handler,
    submit_review_decision_handler,
    get_access_reviews_stats_handler,
    get_identity_access_reviews_handler,
    complete_access_review_handler,
    get_assignment_evidence_handler,
    create_report_handler,
    get_reports_list_handler,
    get_report_detail_handler,
    get_report_runs_handler,
    download_report_handler,
    get_platform_health_handler,
    get_system_jobs_handler,
    get_system_job_detail_handler,
    get_system_tenants_health_handler,
    get_system_tenant_health_detail_handler,
    get_system_metrics_handler,
    # Admin SaaS Operator
    get_admin_alerts_handler,
    acknowledge_alert_handler,
    get_snapshot_runs_handler,
    admin_trigger_tenant_snapshot,
    admin_rebuild_tenant_graph,
    admin_disable_tenant,
    admin_suspend_tenant,
    admin_reset_tenant_discovery,
    admin_flush_cache,
    admin_rebuild_all_graphs,
    agent_patterns_reload,
    get_agent_identities,
    get_agent_identity_count,
    agent_identities_reclassify,
    scan_orphan_agents,
    get_agent_blast_radius,
    get_agent_delegations,
    manage_agent_delegation,
    delete_agent_delegation,
    get_agent_risk_summary,
    admin_restart_workers,
    # Phase 8: Graph Attack Findings & Identity Risk Scores
    get_graph_attack_findings_handler,
    get_graph_attack_finding_detail_handler,
    get_identity_risk_scores_handler,
    run_graph_attack_analysis_handler,
    # Phase 9: Security Posture Command Center
    get_posture_score_handler,
    get_risky_identities_handler,
    get_remediation_priority_handler,
    get_privileged_identities_handler,
    get_security_events_handler,
    # Phase 10: Remediation Workflow
    assign_finding_handler,
    update_finding_status_workflow_handler,
    add_finding_comment_handler,
    get_finding_comments_handler,
    get_remediation_metrics_handler,
    # Phase 11: Security Automation & Integrations
    save_slack_integration_handler,
    save_jira_integration_handler,
    create_jira_ticket_handler,
    get_report_posture_handler,
    get_report_findings_handler,
    get_report_remediation_handler,
    # Phase 12: AI Security Copilot
    copilot_query_handler,
    copilot_security_summary_handler,
    # AI Copilot Investigation Enhancement
    copilot_investigate_handler,
    copilot_graph_query_handler,
    ai_health_handler,
    # Phase 13: Self-Service Signup
    auth_signup,
    auth_verify_email,
    get_plan_limits_handler,
    # Phase 16: Continuous Identity Risk Monitoring
    get_identity_exposures_handler,
    acknowledge_identity_exposure_handler,
    resolve_identity_exposure_handler,
    get_privilege_drift_handler,
    simulate_attack_path_handler,
    # Phase 17: Enterprise Identity Integration
    get_permission_matrix_handler,
    oidc_login,
    oidc_callback,
    get_oidc_settings,
    save_oidc_settings,
    list_invitations_handler,
    create_invitation_handler,
    revoke_invitation_handler,
    validate_invitation_handler,
    accept_invitation_handler,
    # Phase 2A: Entra Group Scanner
    get_entra_groups,
    get_entra_group_stats,
    get_identity_entra_groups,
    # Phase 2A: Resource Identity Links
    # Lineage Verdicts
    get_identity_verdict_history,
    get_dashboard_verdict_changes,
    # Key Vault Access Graph
    get_identity_keyvault_access,
    # Remediation Queue (attack-path driven)
    create_remediation_queue_item,
    list_remediation_queue,
    get_remediation_queue_item_detail,
    patch_remediation_queue_item,
    get_remediation_queue_summary,
    get_ciso_summary,
    recompute_cvss_scores,
    get_identity_top_fixes,
    get_org_remediation_summary,
)
from app.scheduler import start_scheduler, stop_scheduler
from app.middleware.input_sanitizer import sanitize_request

logger = logging.getLogger(__name__)


def _validate_startup_secrets():
    """Fail fast if critical secrets are missing or debug flags leak into production."""
    # ── Block production-hostile flags in non-dev environments ──
    if not IS_DEV:
        hostile = []
        if os.getenv("FLASK_DEBUG"):
            hostile.append("FLASK_DEBUG")
        if os.getenv("FLASK_ENV") == "development":
            hostile.append("FLASK_ENV=development")
        if hostile:
            raise RuntimeError(
                f"Production-hostile config detected: {', '.join(hostile)}. "
                f"These must not be set when APP_ENV={APP_ENV}"
            )

    if IS_DEV:
        return  # Skip secret checks in local/dev

    required = [
        ('ADMIN_JWT_SECRET', 'Admin portal JWT signing'),
        ('CLIENT_JWT_SECRET', 'Client portal JWT signing'),
        ('DB_HOST', 'Database host'),
        ('DB_PASSWORD', 'Database password'),
    ]
    missing = [(name, desc) for name, desc in required if not os.getenv(name)]
    if missing:
        for name, desc in missing:
            logger.critical(f"Missing required secret: {name} ({desc})")
        raise RuntimeError(
            f"Missing {len(missing)} required secret(s): "
            + ', '.join(name for name, _ in missing)
        )


def _run_core_schema(db_init):
    """Run migration 001 SQL to create core tables (discovery_runs, identities, etc.).
    All statements use IF NOT EXISTS so it's safe to run on every startup.
    Also adds organization_id/cloud_connection_id columns needed by later migrations.
    """
    import pathlib
    sql_path = pathlib.Path(__file__).parent.parent / 'migrations' / '001_create_identity_roles.sql'
    if not sql_path.exists():
        logger.warning("Core schema SQL not found at %s", sql_path)
        return
    sql = sql_path.read_text()
    cursor = db_init.conn.cursor()
    cursor.execute(sql)
    db_init._commit()
    # Add columns that later migrations (018) would add
    cursor.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS organization_id INTEGER")
    cursor.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS cloud_connection_id INTEGER")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_org ON discovery_runs(organization_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_connection ON discovery_runs(cloud_connection_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_org_status ON discovery_runs(organization_id, status)")
    db_init._commit()
    cursor.close()


def _run_full_schema(db_init):
    """Run migration 100 SQL to create ALL tables (from localhost pg_dump).
    All statements use CREATE TABLE IF NOT EXISTS — safe to run on every startup.
    This ensures dev DB has every table that localhost has.
    """
    import pathlib
    sql_path = pathlib.Path(__file__).parent.parent / 'migrations' / '100_full_schema.sql'
    if not sql_path.exists():
        logger.warning("Full schema SQL not found at %s", sql_path)
        return
    sql = sql_path.read_text()
    cursor = db_init.conn.cursor()
    cursor.execute(sql)
    db_init._commit()
    cursor.close()
    logger.info("Full schema: all tables ensured (CREATE TABLE IF NOT EXISTS)")


def _run_derived_tables(db_init):
    """Run migrations 070-071 to create derived data tables.
    All statements use CREATE TABLE/INDEX IF NOT EXISTS — safe to run on every startup.
    """
    import pathlib
    migrations_dir = pathlib.Path(__file__).parent.parent / 'migrations'
    for sql_file in ['070_identity_graph_edges.sql', '071_security_posture.sql']:
        sql_path = migrations_dir / sql_file
        if sql_path.exists():
            cursor = db_init.conn.cursor()
            cursor.execute(sql_path.read_text())
            db_init._commit()
            cursor.close()
    logger.info("Derived tables: identity_graph_edges + identity_security_posture ensured")


def _run_schema_sync(conn):
    """Sync ALL table columns to match the expected schema (from localhost dump).

    Uses the sync_schema script which embeds the full localhost schema as a CSV.
    This ensures dev DB has every column that localhost has, without needing
    to maintain manual ALTER TABLE lists.
    """
    import pathlib
    script_path = pathlib.Path(__file__).parent.parent / 'scripts' / 'sync_schema.py'
    if not script_path.exists():
        logger.warning("sync_schema.py not found -- skipping schema sync")
        return

    # Import the sync module
    import importlib.util
    spec = importlib.util.spec_from_file_location("sync_schema", str(script_path))
    sync_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sync_mod)

    # Load expected schema and compare
    sync_mod._load_expected_schema()
    current = sync_mod.get_current_schema(conn)

    changes = sync_mod.compare_schemas(sync_mod.EXPECTED_COLUMNS, current)
    n_missing_tables = len(changes["missing_tables"])
    n_missing_cols = len(changes["missing_columns"])

    if n_missing_tables == 0 and n_missing_cols == 0:
        logger.info("Schema sync: all %s tables, %s columns in sync",
                    len(sync_mod.EXPECTED_COLUMNS),
                    sum(len(c) for c in sync_mod.EXPECTED_COLUMNS.values()))
        return

    if n_missing_tables:
        logger.warning("Schema sync: %s missing tables (will be created by _ensure_* methods)", n_missing_tables)

    if n_missing_cols:
        logger.info("Schema sync: adding %s missing columns...", n_missing_cols)
        sync_mod.apply_changes(conn, changes, dry_run=False)
        logger.info("Schema sync: %s columns added", n_missing_cols)


def create_app():
    # Phase 4A: Structured logging
    configure_logging()

    # Environment diagnostics
    log_startup_banner()

    # Phase 4A: Startup secrets validation
    _validate_startup_secrets()

    # AI Copilot env diagnostic
    logger = logging.getLogger(__name__)
    logger.info("Copilot API key loaded: %s", bool(os.getenv("ANTHROPIC_API_KEY")))
    logger.info("Copilot model: %s", os.getenv("LLM_MODEL", "(default)"))

    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB request size limit

    allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if not allowed_origins:
        raise RuntimeError(
            "ALLOWED_ORIGINS env var is required and must not be empty. "
            "Example: ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173"
        )
    CORS(app, resources={r"/*": {
        "origins": allowed_origins,
        "allow_headers": ["Content-Type", "Authorization", "X-Portal-Context",
                          "X-Organization-Id", "X-API-Key", "Idempotency-Key",
                          "X-CSRF-Token", "X-Tenant-ID"],
        "expose_headers": ["Content-Type", "X-Idempotency-Key", "X-Idempotent-Replayed"],
        "supports_credentials": True,
    }})

    # Authentication middleware (Phase 31)
    app.before_request(auth_middleware)

    # Phase 1 Security Hardening: Input sanitization (XSS/SQLi defense-in-depth)
    app.before_request(sanitize_request)

    # Resolve numeric identity_id URL params to UUID strings.
    # Some frontend links (e.g. CISO dangerous identities) may use DB ids.
    @app.before_request
    def _resolve_identity_param():
        va = request.view_args
        if not va or 'identity_id' not in va:
            return
        raw = va['identity_id']
        try:
            db_id = int(raw)
        except (ValueError, TypeError):
            return  # already a UUID — no resolution needed
        from app.api.handlers import _db, _org_id, _connection_id, _latest_run_ids, _resolve_identity_id
        try:
            db = _db()
            cursor = db.conn.cursor()
            run_ids = _latest_run_ids(cursor, _org_id(), _connection_id())
            if run_ids:
                va['identity_id'] = _resolve_identity_id(cursor, raw, run_ids)
        except Exception:
            pass  # let the handler deal with it

    # Phase 4A: Request ID correlation + Phase 68: Request timing middleware
    @app.before_request
    def _start_timer():
        g.request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
        g._request_start = time.time()

    @app.after_request
    def _record_metrics(response):
        # Phase 4A: Echo request ID in response
        request_id = getattr(g, 'request_id', None)
        if request_id:
            response.headers['X-Request-ID'] = request_id

        start = getattr(g, '_request_start', None)
        if start and request.path.startswith('/api/'):
            duration_ms = (time.time() - start) * 1000
            path = re.sub(r'/[0-9a-f-]{8,}', '/:id', request.path)
            path = re.sub(r'/\d+', '/:id', path)
            MetricsCollector.get().record_request(
                request.method, path, response.status_code, duration_ms)

            # Enterprise logging: tenant/org context per API request
            org_id = getattr(g, 'org_id', None)
            tenant_id = getattr(g, 'tenant_id', None) or org_id
            if response.status_code >= 400:
                logger.warning(
                    "API %s %s org=%s tenant=%s status=%d duration=%.0fms",
                    request.method, path, org_id, tenant_id,
                    response.status_code, duration_ms,
                )
            elif duration_ms > 1000:
                logger.info(
                    "API_SLOW %s %s org=%s status=%d duration=%.0fms",
                    request.method, path, org_id,
                    response.status_code, duration_ms,
                )

            # JSON contract enforcement: warn on non-JSON API responses
            ct = response.content_type or ''
            if not ct.startswith('application/json') and response.status_code != 204:
                # Allow Prometheus metrics and health probes
                if '/metrics' not in request.path:
                    logger.error(
                        "NON_JSON_RESPONSE %s %s content_type=%s status=%d",
                        request.method, path, ct, response.status_code,
                    )
        return response

    # Phase 5: Security headers on all responses
    app.after_request(add_security_headers)

    # ------------------------------------------------------------------
    # Tenant context teardown — CRITICAL for isolation safety
    # ------------------------------------------------------------------
    # Ensures app.current_organization_id is RESET at the end of every
    # request, regardless of success or failure. This prevents context
    # leakage if connections are ever reused (pooling, keep-alive).
    # Defense-in-depth: Database.close() also resets, and we use
    # transaction-scoped context (SET LOCAL), but this teardown hook
    # provides a belt-and-suspenders guarantee.
    @app.teardown_request
    def _reset_tenant_context(exc):
        db_conn = getattr(g, '_tenant_db', None)
        if db_conn is not None:
            try:
                db_conn.reset_organization_context()
                db_conn.close()
            except Exception:
                pass  # Connection may already be closed/errored
            g._tenant_db = None

    # SecurityViolationError handler — returns 403, never exposes internals
    from app.database import SecurityViolationError as _SVE

    @app.errorhandler(_SVE)
    def _security_violation(e):
        request_id = getattr(g, 'request_id', None)
        logger.error(
            "SECURITY_VIOLATION [request_id=%s]: %s", request_id, str(e)
        )
        return jsonify({
            'error': 'Access denied',
            'error_code': 'SECURITY_VIOLATION',
            'request_id': request_id,
        }), 403

    # Phase 4A/4B: Global error boundary with standardized error_code
    @app.errorhandler(400)
    def _bad_request(e):
        return jsonify({
            'error': str(e.description) if hasattr(e, 'description') else 'Bad request',
            'error_code': 'BAD_REQUEST',
            'request_id': getattr(g, 'request_id', None),
        }), 400

    @app.errorhandler(404)
    def _not_found(e):
        return jsonify({
            'error': 'Not found',
            'error_code': 'NOT_FOUND',
            'request_id': getattr(g, 'request_id', None),
        }), 404

    @app.errorhandler(405)
    def _method_not_allowed(e):
        return jsonify({
            'error': 'Method not allowed',
            'error_code': 'METHOD_NOT_ALLOWED',
            'request_id': getattr(g, 'request_id', None),
        }), 405

    @app.errorhandler(413)
    def _payload_too_large(e):
        return jsonify({
            'error': 'Request payload too large (max 5 MB)',
            'error_code': 'PAYLOAD_TOO_LARGE',
            'request_id': getattr(g, 'request_id', None),
        }), 413

    @app.errorhandler(429)
    def _too_many_requests(e):
        return jsonify({
            'error': 'Too many requests',
            'error_code': 'RATE_LIMITED',
            'request_id': getattr(g, 'request_id', None),
        }), 429

    @app.errorhandler(500)
    def _internal_error(e):
        request_id = getattr(g, 'request_id', None)
        logger.exception(f"500 error [request_id={request_id}]")
        return jsonify({
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR',
            'request_id': request_id,
        }), 500

    @app.errorhandler(Exception)
    def _unhandled_exception(e):
        request_id = getattr(g, 'request_id', None)
        logger.exception(f"Unhandled exception [request_id={request_id}]")
        return jsonify({
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR',
            'request_id': request_id,
        }), 500

    # Ensure tables exist at startup (run as admin user for DDL privileges).
    # Each block is independently guarded so one failure doesn't block the rest.
    # Set migration flag so readiness probe returns 503 during DDL.
    from app.database import Database as _DbInit
    _DbInit._migration_in_progress = True
    try:
        _db_init = _DbInit()
    except Exception as e:
        logger.warning("Startup DB connection failed: %s", e)
        _DbInit._migration_in_progress = False
        _db_init = None

    if _db_init:
        # ── Critical tables (must exist for Settings, Connections, etc.) ──
        _startup_ops = [
            ('settings table', lambda: _db_init.conn.cursor().execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id SERIAL PRIMARY KEY,
                    key VARCHAR(255) NOT NULL,
                    value TEXT,
                    organization_id INTEGER NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(organization_id, key)
                )
            """) or _db_init._commit()),
            ('settings index', lambda: _db_init.conn.cursor().execute(
                "CREATE INDEX IF NOT EXISTS idx_settings_org ON settings(organization_id)"
            ) or _db_init._commit()),
            ('core schema (migration 001)', lambda: _run_core_schema(_db_init)),
            ('full schema (migration 100)', lambda: _run_full_schema(_db_init)),
            ('derived tables (070-071)', lambda: _run_derived_tables(_db_init)),
            ('cloud_connections table', lambda: _db_init._ensure_cloud_connections_table()),
            ('cloud_subscriptions table', lambda: _db_init._ensure_cloud_subscriptions_table()),
            ('entitlements tables', lambda: _db_init._ensure_entitlements_tables()),
        ]

        # ── Optional backfill/migration ops (depend on tables that may not exist yet) ──
        _startup_ops += [
            ('identity_subscription_access', lambda: _db_init._ensure_identity_subscription_access_table()),
            ('backfill_microsoft_flag', lambda: _db_init.backfill_microsoft_flag()),
            ('cleanup_microsoft_remediations', lambda: _db_init.cleanup_microsoft_remediations()),
            ('permission_plane_column', lambda: _db_init.ensure_permission_plane_column()),
            ('deleted_at_column', lambda: _db_init.ensure_deleted_at_column()),
            ('identity_lineage_columns', lambda: _db_init.ensure_identity_lineage_columns()),
            ('last_activity_columns', lambda: _db_init.ensure_last_activity_columns()),
            ('spn_exposure', lambda: _db_init._ensure_spn_exposure()),
            ('app_reg_exposure', lambda: _db_init._ensure_app_reg_exposure()),
            ('workload_telemetry', lambda: _db_init._ensure_workload_telemetry_tables()),
            ('security_findings', lambda: _db_init._ensure_security_findings_table()),
            ('attack_paths', lambda: _db_init._ensure_attack_paths_table()),
            ('fix_recommendations', lambda: _db_init._ensure_fix_recommendations_table()),
            ('blast_radius', lambda: _db_init._ensure_blast_radius_table()),
            ('access_reviews', lambda: _db_init._ensure_access_reviews_tables()),
            ('reports', lambda: _db_init._ensure_reports_tables()),
            ('notifications', lambda: _db_init._ensure_notifications_table()),
            ('dashboard_preferences', lambda: _db_init._ensure_dashboard_preferences_table()),
            ('activity_log', lambda: _db_init._ensure_activity_log_table()),
            ('remediation_playbooks', lambda: _db_init._ensure_remediation_playbooks()),
            ('remediation_actions', lambda: _db_init._ensure_remediation_actions_table()),
            ('webhook_tables', lambda: _db_init._ensure_webhook_tables()),
            ('custom_risk_rules', lambda: _db_init._ensure_custom_risk_rules_table()),
            ('anomalies', lambda: _db_init._ensure_anomalies_table()),
            ('api_keys', lambda: _db_init._ensure_api_keys_table()),
            ('soar_tables', lambda: _db_init._ensure_soar_tables()),
            ('saved_views', lambda: _db_init._ensure_saved_views_table()),
            ('identity_groups', lambda: _db_init._ensure_identity_group_tables()),
            ('compliance_tables', lambda: _db_init._ensure_compliance_tables()),
            ('compliance_snapshots', lambda: _db_init._ensure_compliance_snapshots_table()),
            ('organizations', lambda: _db_init._ensure_organizations_table()),
            ('users', lambda: _db_init._ensure_users_table()),
            ('copilot', lambda: _db_init._ensure_copilot_tables()),
            ('ai_audit_log', lambda: _db_init._ensure_ai_audit_log_table()),
            ('sa_attestations', lambda: _db_init._ensure_sa_attestations_table()),
            ('billing_events', lambda: _db_init._ensure_billing_events_table()),
            ('app_registrations', lambda: _db_init._ensure_app_registrations_table()),
            ('agent_classifications', lambda: _db_init._ensure_agent_classifications_table()),
            ('entra_groups', lambda: _db_init._ensure_entra_group_tables()),
            ('associated_resource_columns', lambda: _db_init.ensure_associated_resource_columns()),
            ('lineage_verdicts', lambda: _db_init._ensure_lineage_verdicts_table()),
            ('keyvault_metadata', lambda: _db_init._ensure_keyvault_metadata_table()),
            ('role_assignment_group_cols', lambda: _db_init._ensure_role_assignment_group_cols()),
        ]

        for label, op in _startup_ops:
            try:
                op()
            except Exception as e:
                logger.warning("Startup DDL skipped (%s): %s", label, e)
                try:
                    _db_init._rollback()
                except Exception:
                    pass

        # ICE tables + scan schedules + Stripe columns (independent functions)
        for label, fn in [
            ('orphaned_findings', lambda: __import__('app.database', fromlist=['_ensure_orphaned_findings_table'])._ensure_orphaned_findings_table(_db_init.conn)),
            ('scan_schedules', lambda: __import__('app.database', fromlist=['_ensure_scan_schedules_table'])._ensure_scan_schedules_table(_db_init.conn)),
            ('stripe_columns', lambda: __import__('app.database', fromlist=['_ensure_stripe_columns'])._ensure_stripe_columns(_db_init.conn)),
        ]:
            try:
                fn()
            except Exception as e:
                logger.warning("Startup DDL skipped (%s): %s", label, e)
                try:
                    _db_init._rollback()
                except Exception:
                    pass

        # Schema sync: add any missing columns to match localhost schema
        try:
            _run_schema_sync(_db_init.conn)
        except Exception as e:
            logger.warning("Schema sync error (non-fatal): %s", e)
            try:
                _db_init._rollback()
            except Exception:
                pass

        # Role usage columns (last_used_at for per-role activity tracking)
        try:
            _rc = _db_init.conn.cursor()
            _rc.execute("ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ")
            _rc.execute("ALTER TABLE role_assignments ADD COLUMN IF NOT EXISTS last_used_operation TEXT")
            _rc.execute("ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ")
            _rc.execute("ALTER TABLE entra_role_assignments ADD COLUMN IF NOT EXISTS last_used_operation TEXT")
            _db_init.conn.commit()
            _rc.close()
        except Exception as e:
            logger.warning("Role usage columns DDL skipped: %s", e)
            try:
                _db_init._rollback()
            except Exception:
                pass

        # Performance indexes (each independently guarded)
        _perf_cursor = _db_init.conn.cursor()
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_identities_tenant_run ON identities(tenant_id, discovery_run_id)",
            "CREATE INDEX IF NOT EXISTS idx_identities_tenant_risk ON identities(tenant_id, risk_level)",
            "CREATE INDEX IF NOT EXISTS idx_identities_tenant_cat ON identities(tenant_id, identity_category)",
            "CREATE INDEX IF NOT EXISTS idx_identities_tenant_status ON identities(tenant_id, activity_status)",
            "CREATE INDEX IF NOT EXISTS idx_role_assignments_tenant ON role_assignments(tenant_id, identity_db_id)",
            "CREATE INDEX IF NOT EXISTS idx_drift_tenant_created ON drift_reports(tenant_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sa_tenant_run ON azure_storage_accounts(tenant_id, discovery_run_id)",
            "CREATE INDEX IF NOT EXISTS idx_kv_tenant_run ON azure_key_vaults(tenant_id, discovery_run_id)",
            "CREATE INDEX IF NOT EXISTS idx_activity_tenant_created ON activity_log(tenant_id, created_at DESC)",
        ]:
            try:
                _perf_cursor.execute(idx_sql)
            except Exception:
                _db_init._rollback()
        try:
            _db_init._commit()
        except Exception:
            pass
        _perf_cursor.close()

        # Backfill NULL role_name/scope in generated_remediations
        try:
            _bf_count = _db_init.backfill_generated_remediations_roles()
            if _bf_count > 0:
                logger.info("Backfilled role_name/scope on %s generated_remediations rows", _bf_count)
        except Exception as e:
            logger.warning("Remediation role backfill skipped: %s", e)
            try:
                _db_init._rollback()
            except Exception:
                pass

        _db_init.close()
        _DbInit._migration_in_progress = False

    # -----------------------
    # Health & Monitoring (Phase 68 + Phase 4A)
    # -----------------------
    @app.get("/health/live")
    def health_liveness():
        return health_live()

    @app.get("/health/ready")
    @app.get("/api/health")
    @app.get("/health")
    def health_readiness():
        return health_ready()

    # Backward compat: detailed health_check remains at /api/health
    @app.get("/api/health/detailed")
    def health_detailed():
        return health_check()

    @app.get("/api/metrics")
    @require_role('admin')
    def metrics():
        return prometheus_metrics()

    @app.get("/api/system/health")
    @require_portal_access()
    def system_health():
        return get_system_health()

    @app.get("/api/system/sla")
    @require_portal_access()
    def system_sla():
        return get_sla_metrics()

    @app.get("/api/system/ai-health")
    @require_role('admin')
    def ai_health():
        return ai_health_handler()

    # -----------------------
    # Authentication (Phase 31)
    # -----------------------
    @app.post("/api/auth/login")
    @rate_limit(max_requests=5, window_seconds=60)   # 5 attempts/min per IP
    @validate_json(LOGIN_SCHEMA)
    def login():
        return auth_login()

    @app.post("/api/auth/signup")
    @rate_limit(max_requests=3, window_seconds=60)   # 3 signups/min per IP
    def signup():
        return auth_signup()

    @app.post("/api/auth/verify-email")
    def verify_email():
        return auth_verify_email()

    @app.get("/api/plan/limits")
    @require_role('viewer')
    def plan_limits():
        return get_plan_limits_handler()

    @app.post("/api/auth/refresh")
    @rate_limit(max_requests=10, window_seconds=60)   # 10 refreshes/min per IP
    @validate_json(REFRESH_SCHEMA)
    def refresh():
        return auth_refresh()

    @app.post("/api/auth/logout")
    @require_role('viewer')
    def logout():
        return auth_logout()

    @app.get("/api/auth/me")
    @require_role('viewer')
    def me():
        return auth_me()

    @app.put("/api/auth/password")
    @require_role('viewer')
    @rate_limit(max_requests=5, window_seconds=300)
    @validate_json(CHANGE_PASSWORD_SCHEMA)
    def password_change():
        return change_password()

    # Phase 84: Password reset & account lockout
    @app.post("/api/auth/forgot-password")
    @rate_limit(max_requests=3, window_seconds=300)   # 3 per 5 min per IP
    def forgot_password():
        return forgot_password_handler()

    @app.get("/api/auth/validate-reset-token")
    def validate_reset_token():
        return validate_reset_token_handler()

    @app.post("/api/auth/reset-password")
    @rate_limit(max_requests=5, window_seconds=300)   # 5 per 5 min per IP
    def reset_password():
        return reset_password_handler()

    # -----------------------
    # User Management (Phase 31 - Admin only)
    # -----------------------
    @app.get("/api/users")
    @require_role('admin')
    def users_list():
        return get_users_list()

    @app.post("/api/users")
    @require_role('admin')
    @validate_json(CREATE_USER_SCHEMA)
    def users_create():
        return create_user_handler()

    @app.put("/api/users/<int:user_id>")
    @require_role('admin')
    def users_update(user_id):
        return update_user_handler(user_id)

    @app.delete("/api/users/<int:user_id>")
    @require_role('admin')
    def users_delete(user_id):
        return delete_user_handler(user_id)

    @app.post("/api/users/<int:user_id>/reset-password")
    @require_role('admin')
    def users_reset_password(user_id):
        return admin_reset_user_password(user_id)

    # -----------------------
    # API Key Management (Phase 42 - Admin only)
    # -----------------------
    @app.get("/api/api-keys")
    @require_role('admin')
    def api_keys_list():
        return get_api_keys_list()

    @app.post("/api/api-keys")
    @require_role('admin')
    @require_feature('api_keys')
    def api_keys_create():
        return create_api_key_handler()

    @app.put("/api/api-keys/<int:key_id>")
    @require_role('admin')
    def api_keys_update(key_id):
        return update_api_key_handler(key_id)

    @app.delete("/api/api-keys/<int:key_id>")
    @require_role('admin')
    def api_keys_delete(key_id):
        return delete_api_key_handler(key_id)

    # -----------------------
    # SOAR Integration (Phase 43)
    # -----------------------
    @app.get("/api/soar/playbooks")
    def soar_playbooks_list():
        return get_soar_playbooks_list()

    @app.post("/api/soar/playbooks")
    @require_role('admin')
    @require_feature('soar')
    def soar_playbooks_create():
        return create_soar_playbook_handler()

    @app.put("/api/soar/playbooks/<int:playbook_id>")
    @require_role('admin')
    @require_feature('soar')
    def soar_playbooks_update(playbook_id):
        return update_soar_playbook_handler(playbook_id)

    @app.delete("/api/soar/playbooks/<int:playbook_id>")
    @require_role('admin')
    @require_feature('soar')
    def soar_playbooks_delete(playbook_id):
        return delete_soar_playbook_handler(playbook_id)

    @app.post("/api/soar/playbooks/<int:playbook_id>/test")
    @require_role('admin')
    @require_feature('soar')
    def soar_playbooks_test(playbook_id):
        return test_soar_playbook_handler(playbook_id)

    @app.get("/api/soar/actions")
    def soar_actions_list():
        return get_soar_actions_list()

    @app.get("/api/soar/actions/stats")
    def soar_actions_stats():
        return get_soar_action_stats_handler()

    @app.post("/api/soar/execute")
    @require_role('admin', 'security_admin')
    @require_feature('soar')
    def soar_execute():
        return execute_soar_action_handler()

    # -----------------------
    # Dashboard Preferences (Phase 44)
    # -----------------------
    @app.get("/api/dashboard/preferences")
    def dashboard_preferences_get():
        return get_dashboard_preferences_handler()

    @app.put("/api/dashboard/preferences")
    def dashboard_preferences_save():
        return save_dashboard_preferences_handler()

    @app.delete("/api/dashboard/preferences")
    def dashboard_preferences_reset():
        return reset_dashboard_preferences_handler()

    # -----------------------
    # Organization Management (Phase 2C org rename; was Tenant Management Phase 45/70)
    # -----------------------
    @app.get("/api/organizations")
    @require_portal_access()
    def organizations_list():
        return get_organizations_list()

    @app.post("/api/organizations")
    @require_portal_role('superadmin', 'poweradmin')
    def organizations_create():
        return create_organization_handler()

    @app.put("/api/organizations/<int:organization_id>")
    @require_portal_role('superadmin', 'poweradmin')
    def organizations_update(organization_id):
        return update_organization_handler(organization_id)

    @app.delete("/api/organizations/<int:organization_id>")
    @require_superadmin()
    def organizations_delete(organization_id):
        return delete_organization_handler(organization_id)

    # Backward compat: /api/tenants → /api/organizations
    @app.get("/api/tenants")
    @require_portal_access()
    def tenants_list():
        return get_organizations_list()

    @app.post("/api/tenants")
    @require_portal_role('superadmin', 'poweradmin')
    def tenants_create():
        return create_organization_handler()

    @app.put("/api/tenants/<int:organization_id>")
    @require_portal_role('superadmin', 'poweradmin')
    def tenants_update(organization_id):
        return update_organization_handler(organization_id)

    @app.delete("/api/tenants/<int:organization_id>")
    @require_superadmin()
    def tenants_delete(organization_id):
        return delete_organization_handler(organization_id)

    # -----------------------
    # Client Aliases (backward compat)
    # -----------------------
    @app.get("/api/clients")
    @require_portal_access()
    def clients_list():
        return get_organizations_list()

    @app.post("/api/clients")
    @require_portal_role('superadmin', 'poweradmin')
    def clients_create():
        return create_organization_handler()

    @app.put("/api/clients/<int:organization_id>")
    @require_portal_role('superadmin', 'poweradmin')
    def clients_update(organization_id):
        return update_organization_handler(organization_id)

    @app.delete("/api/clients/<int:organization_id>")
    @require_superadmin()
    def clients_delete(organization_id):
        return delete_organization_handler(organization_id)

    @app.post("/api/admin/organizations/bulk-delete")
    @require_superadmin()
    def admin_bulk_delete_organizations():
        return bulk_delete_organizations_handler()

    # -----------------------
    # Admin Billing API (organization routes + backward compat tenant routes)
    # -----------------------
    @app.get("/api/admin/organizations/<int:organization_id>/billing")
    @require_portal_access()
    def admin_organization_billing(organization_id):
        return get_admin_organization_billing(organization_id)

    @app.put("/api/admin/organizations/<int:organization_id>/plan")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_organization_plan(organization_id):
        return update_admin_organization_plan(organization_id)

    @app.put("/api/admin/organizations/<int:organization_id>/commitment")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_organization_commitment(organization_id):
        return update_admin_organization_commitment(organization_id)

    @app.put("/api/admin/organizations/<int:organization_id>/platform-fee")
    @require_superadmin()
    def admin_organization_platform_fee(organization_id):
        return update_admin_organization_platform_fee(organization_id)

    @app.put("/api/admin/organizations/<int:organization_id>/clouds/<cloud>/rate")
    @require_superadmin()
    def admin_org_cloud_rate(organization_id, cloud):
        return update_admin_cloud_rate(organization_id, cloud)

    # Backward compat: /api/admin/tenants/... billing routes
    @app.get("/api/admin/tenants/<int:organization_id>/billing")
    @require_portal_access()
    def admin_tenant_billing(organization_id):
        return get_admin_organization_billing(organization_id)

    @app.put("/api/admin/tenants/<int:organization_id>/plan")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_tenant_plan(organization_id):
        return update_admin_organization_plan(organization_id)

    @app.put("/api/admin/tenants/<int:organization_id>/commitment")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_tenant_commitment(organization_id):
        return update_admin_organization_commitment(organization_id)

    @app.put("/api/admin/tenants/<int:organization_id>/platform-fee")
    @require_superadmin()
    def admin_tenant_platform_fee(organization_id):
        return update_admin_organization_platform_fee(organization_id)

    @app.put("/api/admin/tenants/<int:organization_id>/clouds/<cloud>/rate")
    @require_superadmin()
    def admin_cloud_rate(organization_id, cloud):
        return update_admin_cloud_rate(organization_id, cloud)

    @app.get("/api/admin/billing/summary")
    @require_portal_access()
    def admin_billing_summary():
        return get_admin_billing_summary()

    @app.get("/api/admin/billing/events")
    @require_portal_access()
    def admin_billing_events():
        return get_admin_billing_events()

    @app.get("/api/admin/action-log")
    @require_portal_access()
    def admin_action_log():
        return get_admin_action_log()

    # ── Admin Alerts & Tenant Operations ──────────────────────────
    @app.get("/api/admin/alerts")
    @require_portal_access()
    def admin_alerts():
        return get_admin_alerts_handler()

    @app.post("/api/admin/alerts/<alert_id>/acknowledge")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_acknowledge_alert(alert_id):
        return acknowledge_alert_handler(alert_id)

    @app.get("/api/admin/snapshot-runs")
    @require_portal_access()
    def admin_snapshot_runs():
        return get_snapshot_runs_handler()

    @app.post("/api/admin/tenants/<int:organization_id>/snapshot")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_tenant_snapshot_route(organization_id):
        return admin_trigger_tenant_snapshot(organization_id)

    @app.post("/api/admin/tenants/<int:organization_id>/rebuild-graph")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_tenant_rebuild_graph(organization_id):
        return admin_rebuild_tenant_graph(organization_id)

    @app.post("/api/admin/tenants/<int:organization_id>/disable")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_tenant_disable(organization_id):
        return admin_disable_tenant(organization_id)

    @app.post("/api/admin/tenants/<int:organization_id>/suspend")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_tenant_suspend(organization_id):
        return admin_suspend_tenant(organization_id)

    @app.post("/api/admin/tenants/<int:organization_id>/reset-discovery")
    @require_portal_role('superadmin')
    def admin_tenant_reset_discovery(organization_id):
        return admin_reset_tenant_discovery(organization_id)

    @app.post("/api/admin/clients/<int:organization_id>/reset-root-user")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_client_reset_root_user(organization_id):
        return reset_client_root_user(organization_id)

    # ── Platform Operations ───────────────────────────────────────
    @app.post("/api/admin/platform/flush-cache")
    @require_portal_role('superadmin')
    def admin_platform_flush_cache():
        return admin_flush_cache()

    @app.post("/api/admin/platform/rebuild-graphs")
    @require_portal_role('superadmin')
    def admin_platform_rebuild_graphs():
        return admin_rebuild_all_graphs()

    @app.post("/api/admin/agent-patterns/reload")
    @require_portal_role('superadmin')
    def admin_agent_patterns_reload():
        return agent_patterns_reload()

    # ── AI Agent Governance endpoints (Phase 1) ──
    @app.get("/api/agent-identities")
    def agent_identities_list():
        return get_agent_identities()

    @app.get("/api/agent-identities/count")
    def agent_identities_count():
        return get_agent_identity_count()

    @app.post("/api/agent-identities/reclassify")
    @require_role('admin')
    def agent_identities_reclassify_route():
        return agent_identities_reclassify()

    @app.get("/api/dashboard/agent-risk-summary")
    def agent_risk_summary_route():
        return get_agent_risk_summary()

    @app.get("/api/agent-identities/<identity_id>/blast-radius")
    def agent_blast_radius_route(identity_id):
        return get_agent_blast_radius(identity_id)

    @app.get("/api/agent-identities/delegations")
    def agent_delegations_list_route():
        return get_agent_delegations()

    @app.post("/api/agent-identities/delegations")
    @require_role('admin')
    def agent_delegations_create_route():
        return manage_agent_delegation()

    @app.delete("/api/agent-identities/delegations")
    @require_role('admin')
    def agent_delegations_delete_route():
        return delete_agent_delegation()

    @app.post("/api/agent-identities/scan-orphans")
    @require_role('admin')
    def agent_identities_scan_orphans_route():
        return scan_orphan_agents()

    @app.post("/api/admin/platform/restart-workers")
    @require_portal_role('superadmin')
    def admin_platform_restart_workers():
        return admin_restart_workers()

    # Phase 1B+1C: Admin impersonation
    @app.post("/api/admin/impersonate")
    @require_portal_role('superadmin', 'poweradmin')
    @rate_limit(max_requests=3, window_seconds=60)
    def admin_impersonate_route():
        return admin_impersonate()

    @app.post("/api/admin/impersonate/end")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_end_impersonation_route():
        return admin_end_impersonation()

    @app.get("/api/client/billing/summary")
    @require_role('admin', 'security_admin')
    def client_billing_summary():
        return get_client_billing_summary()

    @app.get("/api/client/billing/usage")
    @require_role('admin', 'security_admin')
    def client_billing_usage():
        return get_client_usage_metering()

    @app.get("/api/client/billing/preview")
    @require_role('admin', 'security_admin')
    def client_billing_preview():
        return get_client_billing_preview()

    # Admin Billing Client Aliases (backward compat)
    @app.get("/api/admin/clients/<int:organization_id>/billing")
    @require_portal_access()
    def admin_client_billing(organization_id):
        return get_admin_organization_billing(organization_id)

    @app.put("/api/admin/clients/<int:organization_id>/plan")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_client_plan(organization_id):
        return update_admin_organization_plan(organization_id)

    @app.put("/api/admin/clients/<int:organization_id>/commitment")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_client_commitment(organization_id):
        return update_admin_organization_commitment(organization_id)

    @app.put("/api/admin/clients/<int:organization_id>/platform-fee")
    @require_superadmin()
    def admin_client_platform_fee(organization_id):
        return update_admin_organization_platform_fee(organization_id)

    @app.put("/api/admin/clients/<int:organization_id>/clouds/<cloud>/rate")
    @require_superadmin()
    def admin_client_cloud_rate(organization_id, cloud):
        return update_admin_cloud_rate(organization_id, cloud)

    # -----------------------
    # Platform Settings & Invoices
    # -----------------------
    @app.get("/api/admin/platform-settings")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_platform_settings_get():
        return get_platform_settings()

    @app.post("/api/admin/platform-settings")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_platform_settings_update():
        return update_platform_settings_handler()

    @app.post("/api/admin/organizations/<int:organization_id>/invoices")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_generate_org_invoice(organization_id):
        return generate_invoice(organization_id)

    # Backward compat: /api/admin/tenants/<id>/invoices
    @app.post("/api/admin/tenants/<int:organization_id>/invoices")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_generate_invoice(organization_id):
        return generate_invoice(organization_id)

    @app.get("/api/admin/invoices")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_invoices_list():
        return get_admin_invoices()

    @app.get("/api/admin/invoices/<int:invoice_id>")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_invoice_detail(invoice_id):
        return get_admin_invoice(invoice_id)

    @app.patch("/api/admin/invoices/<int:invoice_id>/status")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_invoice_status(invoice_id):
        return update_invoice_status_handler(invoice_id)

    @app.post("/api/admin/invoices/<int:invoice_id>/send")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_invoice_send(invoice_id):
        return send_invoice_email(invoice_id)

    @app.get("/api/admin/invoices/<int:invoice_id>/verify")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_invoice_verify(invoice_id):
        return verify_admin_invoice(invoice_id)

    # Client Invoice Endpoints
    @app.get("/api/client/invoices")
    @require_role('admin', 'security_admin')
    def client_invoices_list():
        return get_client_invoices()

    @app.get("/api/client/invoices/<int:invoice_id>")
    @require_role('admin', 'security_admin')
    def client_invoice_detail(invoice_id):
        return get_client_invoice(invoice_id)

    @app.get("/api/client/invoices/<int:invoice_id>/verify")
    @require_role('admin', 'security_admin')
    def client_invoice_verify(invoice_id):
        return verify_client_invoice(invoice_id)

    # Organization context (current org config, entitlements, branding, stage)
    @app.get("/api/organization")
    def organization_current():
        return get_current_organization_handler()

    @app.get("/api/organization/config")
    def organization_config():
        return get_organization_config()

    @app.get("/api/organization/entitlements")
    def organization_entitlements():
        return get_organization_entitlements()

    @app.get("/api/auth/org-branding")
    def organization_branding():
        return get_organization_branding()

    @app.get("/api/organization/stage")
    def organization_stage_get():
        return get_organization_stage()

    @app.post("/api/organization/stage")
    @require_role('admin')
    def organization_stage_update():
        return update_organization_stage()

    # Backward compat: /api/tenant/... routes
    @app.get("/api/tenant")
    def tenant_current():
        return get_current_organization_handler()

    @app.get("/api/tenant/config")
    def tenant_config():
        return get_organization_config()

    @app.get("/api/tenant/entitlements")
    def tenant_entitlements():
        return get_organization_entitlements()

    @app.get("/api/auth/tenant-branding")
    def tenant_branding():
        return get_organization_branding()

    @app.get("/api/tenant/stage")
    def tenant_stage_get():
        return get_organization_stage()

    @app.post("/api/tenant/stage")
    @require_role('admin')
    def tenant_stage_update():
        return update_organization_stage()

    # Organization by-slug, provisioning, user orgs
    @app.get("/api/organizations/by-slug/<slug>")
    def organization_by_slug(slug):
        return get_organization_by_slug_public(slug)

    @app.post("/api/organizations/<int:organization_id>/provision")
    @require_portal_role('superadmin', 'poweradmin')
    def organizations_provision(organization_id):
        return provision_organization_handler(organization_id)

    @app.get("/api/auth/organizations")
    def auth_organizations():
        return get_user_organizations_handler()

    # Backward compat: /api/tenants/by-slug, /api/clients/by-slug, provision, auth/tenants
    @app.get("/api/tenants/by-slug/<slug>")
    def tenant_by_slug(slug):
        return get_organization_by_slug_public(slug)

    @app.get("/api/clients/by-slug/<slug>")
    def client_by_slug(slug):
        return get_organization_by_slug_public(slug)

    @app.post("/api/tenants/validate-slug")
    @rate_limit(max_requests=5, window_seconds=60)
    def tenants_validate_slug():
        return validate_organization_slug()

    @app.post("/api/tenants/<int:organization_id>/provision")
    @require_portal_role('superadmin', 'poweradmin')
    def tenants_provision(organization_id):
        return provision_organization_handler(organization_id)

    @app.post("/api/clients/<int:organization_id>/provision")
    @require_portal_role('superadmin', 'poweradmin')
    def clients_provision(organization_id):
        return provision_organization_handler(organization_id)

    @app.get("/api/auth/tenants")
    def auth_tenants():
        return get_user_organizations_handler()

    # -----------------------
    # Portal Users (Phase 70 - Superadmin only)
    # -----------------------
    @app.get("/api/portal-users")
    @require_superadmin()
    def portal_users_list():
        return get_portal_users_list()

    # Phase 54: SSO/SAML
    @app.get("/api/auth/sso-status")
    def sso_status_route():
        return sso_status()

    @app.get("/api/auth/saml/metadata")
    def saml_metadata_route():
        return saml_metadata()

    @app.get("/api/auth/saml/login")
    def saml_login_route():
        return saml_login()

    @app.post("/api/auth/saml/acs")
    def saml_acs_route():
        return saml_acs()

    @app.post("/api/auth/saml/token")
    def saml_token_route():
        return saml_token_exchange()

    @app.get("/api/auth/saml/slo")
    def saml_slo_route():
        return saml_slo()

    @app.get("/api/settings/sso")
    @require_role('admin')
    def sso_settings_get():
        return get_sso_settings()

    @app.post("/api/settings/sso")
    @require_role('admin')
    @require_feature('sso')
    def sso_settings_save():
        return save_sso_settings()

    @app.post("/api/settings/sso/parse-metadata")
    @require_role('admin')
    @require_feature('sso')
    def sso_parse_metadata_route():
        return parse_sso_metadata()

    # -----------------------
    # Phase 17: Permission Matrix
    # -----------------------
    @app.get("/api/auth/permissions")
    def permissions_matrix():
        return get_permission_matrix_handler()

    # -----------------------
    # Phase 17: OIDC SSO
    # -----------------------
    @app.get("/api/auth/oidc/login")
    def oidc_login_route():
        return oidc_login()

    @app.get("/api/auth/oidc/callback")
    def oidc_callback_route():
        return oidc_callback()

    @app.get("/api/settings/oidc")
    @require_role('admin')
    def oidc_settings_get():
        return get_oidc_settings()

    @app.post("/api/settings/oidc")
    @require_role('admin')
    @require_feature('oidc')
    def oidc_settings_save():
        return save_oidc_settings()

    # -----------------------
    # Phase 17: SCIM 2.0 Provisioning
    # -----------------------
    from app.api.scim import (
        scim_list_users, scim_create_user, scim_get_user,
        scim_replace_user, scim_patch_user, scim_delete_user,
        scim_service_provider_config, scim_schemas,
    )

    @app.get("/api/scim/v2/Users")
    def scim_users_list():
        return scim_list_users()

    @app.post("/api/scim/v2/Users")
    def scim_users_create():
        return scim_create_user()

    @app.get("/api/scim/v2/Users/<int:user_id>")
    def scim_users_get(user_id):
        return scim_get_user(user_id)

    @app.put("/api/scim/v2/Users/<int:user_id>")
    def scim_users_replace(user_id):
        return scim_replace_user(user_id)

    @app.patch("/api/scim/v2/Users/<int:user_id>")
    def scim_users_patch(user_id):
        return scim_patch_user(user_id)

    @app.delete("/api/scim/v2/Users/<int:user_id>")
    def scim_users_delete(user_id):
        return scim_delete_user(user_id)

    @app.get("/api/scim/v2/ServiceProviderConfig")
    def scim_sp_config():
        return scim_service_provider_config()

    @app.get("/api/scim/v2/Schemas")
    def scim_schemas_route():
        return scim_schemas()

    # -----------------------
    # Phase 17: User Invitations
    # -----------------------
    @app.get("/api/invitations")
    @require_role('admin')
    def invitations_list():
        return list_invitations_handler()

    @app.post("/api/invitations")
    @require_role('admin')
    def invitations_create():
        return create_invitation_handler()

    @app.delete("/api/invitations/<int:invitation_id>")
    @require_role('admin')
    def invitations_revoke(invitation_id):
        return revoke_invitation_handler(invitation_id)

    @app.get("/api/auth/validate-invitation")
    def validate_invitation_route():
        return validate_invitation_handler()

    @app.post("/api/auth/accept-invitation")
    def accept_invitation_route():
        return accept_invitation_handler()

    # -----------------------
    # Service Account Governance (Phase 63)
    # -----------------------
    @app.get("/api/service-accounts/stats")
    def sa_gov_stats_route():
        return get_sa_governance_stats()

    @app.get("/api/service-accounts/governance")
    def sa_gov_list_route():
        return get_sa_governance_list()

    @app.post("/api/service-accounts/<identity_id>/attest")
    @require_role('admin', 'security_admin', 'auditor')
    def sa_gov_attest_route(identity_id):
        return post_sa_attestation(identity_id)

    @app.get("/api/settings/sa-governance")
    def sa_gov_settings_get_route():
        return get_sa_governance_settings()

    @app.post("/api/settings/sa-governance")
    @require_role('admin')
    def sa_gov_settings_save_route():
        return save_sa_governance_settings()

    # -----------------------
    # Identity Governance V2 — Risk-Aware Certification
    # -----------------------
    @app.get("/api/governance/identities")
    def governance_identities_route():
        return get_governance_identities()

    @app.get("/api/governance/identities/<identity_id>")
    def governance_identity_detail_route(identity_id):
        return get_governance_identity_detail(identity_id)

    @app.post("/api/governance/identities/<identity_id>/decide")
    @require_role('admin', 'security_admin', 'auditor')
    def governance_decision_route(identity_id):
        return post_governance_decision(identity_id)

    @app.get("/api/governance/stats")
    def governance_stats_route():
        return get_governance_stats()

    # -----------------------
    # Cross-Organization Analytics (Phase 47 - all portal roles, used by Overview)
    # -----------------------
    @app.get("/api/analytics/organizations")
    @require_portal_access()
    def analytics_organizations():
        return get_cross_org_analytics()

    @app.get("/api/analytics/organizations/trends")
    @require_portal_access()
    def analytics_organizations_trends():
        return get_cross_org_trends()

    # Backward compat: /api/analytics/tenants + /api/analytics/clients
    @app.get("/api/analytics/tenants")
    @require_portal_access()
    def analytics_tenants():
        return get_cross_org_analytics()

    @app.get("/api/analytics/tenants/trends")
    @require_portal_access()
    def analytics_tenants_trends():
        return get_cross_org_trends()

    @app.get("/api/analytics/clients")
    @require_portal_access()
    def analytics_clients():
        return get_cross_org_analytics()

    @app.get("/api/analytics/clients/trends")
    @require_portal_access()
    def analytics_clients_trends():
        return get_cross_org_trends()

    @app.get("/api/analytics/login-sessions")
    @require_portal_access()
    def analytics_login_sessions():
        return get_login_sessions()

    # -----------------------
    # Onboarding Wizard (Phase 48)
    # -----------------------
    @app.get("/api/onboarding/status")
    def onboarding_status():
        return get_onboarding_status()

    @app.post("/api/onboarding/test-connection")
    @require_role('admin', 'security_admin')
    def onboarding_test_connection():
        return test_azure_connection()

    # -----------------------
    # Summary endpoints
    # -----------------------
    @app.get("/api/summary")
    def summary():
        return get_stats()

    # UI expects this - provides category breakdown for dashboard
    @app.get("/api/identity-summary")
    def identity_summary():
        return get_identity_summary()

    # Optional alias
    @app.get("/api/stats")
    def stats_alias():
        return get_stats()

    # -----------------------
    # AGIRS: Identity Risk Summary (Rule 57 SSOT)
    # -----------------------
    @app.get("/api/identity-risk-summary")
    def identity_risk_summary():
        return get_identity_risk_summary()

    @app.get("/api/dangerous-identities")
    def dangerous_identities():
        return get_dangerous_identities()

    # -----------------------
    # Dashboard posture (credential health, trends)
    # -----------------------
    @app.get("/api/dashboard/posture")
    def dashboard_posture():
        return get_dashboard_posture()

    @app.get("/api/dashboard/credential-intelligence")
    def dashboard_credential_intelligence():
        return get_credential_intelligence()

    @app.get("/api/dashboard/trust")
    def dashboard_trust():
        return get_trust_dashboard()

    # -----------------------
    # Dashboard compliance scorecard
    # -----------------------
    @app.get("/api/dashboard/compliance")
    def dashboard_compliance():
        return get_dashboard_compliance()

    # -----------------------
    # Compliance Frameworks (Phase 32)
    # -----------------------
    @app.get("/api/compliance/frameworks")
    def compliance_frameworks():
        return get_compliance_frameworks_list()

    @app.patch("/api/compliance/frameworks/<int:framework_id>")
    @require_role('admin')
    def compliance_frameworks_toggle(framework_id):
        return toggle_compliance_framework_handler(framework_id)

    @app.get("/api/compliance/gap-analysis")
    @require_role('admin', 'security_admin', 'compliance', 'reader')
    def compliance_gap_analysis():
        return get_compliance_gap_analysis()

    @app.get("/api/compliance/trends")
    @require_role('admin', 'security_admin', 'compliance', 'reader')
    def compliance_trends():
        return get_compliance_trends_handler()

    @app.get("/api/compliance/intelligence")
    @require_role('admin', 'security_admin', 'compliance', 'reader')
    def compliance_intelligence():
        return get_compliance_intelligence()

    # -----------------------
    # Overview insights (tier distribution, action items)
    # -----------------------
    @app.get("/api/overview/insights")
    def overview_insights():
        return get_overview_insights()

    @app.get("/api/overview/attack-surface-score")
    def overview_attack_surface():
        return get_attack_surface_score()

    # -----------------------
    # Tier 1: Inventory (always available)
    # Also available at /api/v1/inventory/summary via _register_v1_routes() auto-mirror
    # -----------------------
    @app.get("/api/inventory/summary")
    def inventory_summary():
        return get_inventory_summary()

    # -----------------------
    # CISO Dashboard SSOT
    # -----------------------
    @app.get("/api/ciso/summary")
    def ciso_summary():
        return get_ciso_summary()

    # -----------------------
    # Canonical risk/exposure/attack-path summaries
    # -----------------------
    @app.get("/api/risk/summary")
    def risk_summary():
        return get_risk_summary()

    @app.get("/api/risk/summary/full")
    def risk_summary_full():
        return get_risk_summary_full()

    @app.get("/api/exposure/summary")
    def exposure_summary():
        return get_exposure_summary()

    @app.get("/api/attack-paths/count")
    def attack_paths_count():
        return get_attack_path_count()

    # -----------------------
    # Risks (Dashboard needs it)
    # -----------------------
    @app.get("/api/risks")
    def risks():
        return get_risks()

    # -----------------------
    # Identities
    # -----------------------
    @app.get("/api/identities")
    def identities():
        return get_identities()

    @app.get("/api/identities/<identity_id>")
    def identity_details(identity_id):
        return get_identity_details(identity_id)

    # -----------------------
    # Advanced Query Builder (Phase 39)
    # -----------------------
    @app.post("/api/identities/query")
    @require_feature('advanced_query')
    def identities_query():
        return query_identities()

    @app.get("/api/identities/query/fields")
    def identities_query_fields():
        return get_query_fields()

    @app.post("/api/identities/risk-history/batch")
    def batch_risk_hist():
        return get_batch_risk_history()

    @app.get("/api/identities/<identity_id>/anomalies")
    def identity_anomalies(identity_id):
        return get_identity_anomalies_handler(identity_id)

    # -----------------------
    # Risk Simulation (Phase 49)
    # -----------------------
    @app.post("/api/identities/<identity_id>/simulate")
    @require_role('admin', 'security_admin', 'auditor')
    def identity_simulate(identity_id):
        return simulate_risk(identity_id)

    # -----------------------
    # Identity Access Graph (trust, scope, exposure, visualization)
    # -----------------------
    @app.get("/api/identities/<identity_id>/graph-data")
    def identity_graph_data(identity_id):
        return get_identity_graph_data(identity_id)

    @app.get("/api/identities/<identity_id>/keyvault-access")
    def identity_keyvault_access(identity_id):
        return get_identity_keyvault_access(identity_id)

    # -----------------------
    # Identity Lifecycle (Phase 35)
    # -----------------------
    @app.get("/api/identities/<identity_id>/lifecycle")
    def identity_lifecycle(identity_id):
        return get_identity_lifecycle(identity_id)

    @app.get("/api/identities/<identity_id>/risk-history")
    def identity_risk_hist(identity_id):
        return get_identity_risk_history(identity_id)

    # -----------------------
    # Identity PIM data (eligible roles, activations, overuse)
    # -----------------------
    @app.get("/api/identities/<identity_id>/pim")
    def identity_pim_data(identity_id):
        return get_identity_pim_data(identity_id)

    @app.get("/api/identities/<identity_id>/usage")
    def identity_usage(identity_id):
        return get_identity_usage(identity_id)

    @app.post("/api/identities/exposure-graph")
    def exposure_graph():
        return get_exposure_graph()

    # -----------------------
    # Conditional Access summary
    # -----------------------
    @app.get("/api/dashboard/conditional-access")
    def dashboard_ca():
        return get_dashboard_ca_summary()

    @app.get("/api/dashboard/anomalies")
    def dashboard_anomalies():
        return get_dashboard_anomalies()

    # -----------------------
    # Anomaly Detection (Phase 40)
    # -----------------------
    @app.get("/api/anomalies")
    def anomalies_list():
        return get_anomalies_list()

    @app.get("/api/anomalies/stats")
    def anomalies_stats():
        return get_anomaly_stats_handler()

    @app.get("/api/anomalies/<int:anomaly_id>")
    def anomaly_detail(anomaly_id):
        return get_anomaly_detail(anomaly_id)

    @app.patch("/api/anomalies/<int:anomaly_id>")
    @require_role('admin', 'auditor')
    def anomaly_resolve(anomaly_id):
        return resolve_anomaly_handler(anomaly_id)

    # -----------------------
    # Discovery Runs
    # -----------------------
    @app.get("/api/runs")
    def runs():
        return get_discovery_runs()

    @app.post("/api/runs/trigger")
    @require_role('admin', 'security_admin')
    @rate_limit(max_requests=5, window_seconds=60)   # 5 triggers/min per IP
    @validate_json(TRIGGER_RUN_SCHEMA)
    @idempotent
    def runs_trigger():
        return trigger_discovery()

    @app.get("/api/runs/<int:run_id>/drift")
    def runs_drift(run_id):
        return get_drift_report(run_id)

    # -----------------------
    # Snapshots (point-in-time state) — IMMUTABLE, read-only
    # -----------------------
    @app.get("/api/snapshots")
    def snapshots_list():
        return get_snapshots()

    @app.get("/api/snapshots/state")
    def snapshots_state():
        return get_snapshot_state()

    @app.get("/api/snapshots/compare")
    def snapshots_compare():
        return get_snapshot_compare()

    # Phase 1 Security: Snapshot integrity verification
    @app.get("/api/snapshots/<int:run_id>/verify")
    @require_role('admin', 'security_admin')
    def snapshots_verify(run_id):
        return verify_snapshot_integrity()

    # Gate 29: Snapshot immutability — reject all mutation attempts
    @app.route("/api/snapshots", methods=["DELETE", "PUT", "PATCH"])
    @app.route("/api/snapshots/<path:subpath>", methods=["DELETE", "PUT", "PATCH", "POST"])
    def snapshots_immutable(subpath=None):
        return jsonify({"error": "Snapshots are immutable. Point-in-time audit data cannot be modified or deleted."}), 405

    @app.route("/api/runs/<int:run_id>", methods=["DELETE", "PUT", "PATCH"])
    def runs_immutable(run_id):
        return jsonify({"error": "Discovery runs are immutable audit records. Cannot modify or delete."}), 405

    # -----------------------
    # Scheduler status
    # -----------------------
    @app.get("/api/scheduler")
    def scheduler_status():
        return get_scheduler_status()

    # -----------------------
    # Remediation Engine (Phase 12)
    # -----------------------
    @app.get("/api/identities/<identity_id>/remediations")
    def identity_remediations(identity_id):
        return get_identity_remediations(identity_id)

    # -----------------------
    # Report Generation (Phase 13)
    # -----------------------
    @app.get("/api/reports/data")
    def report_data():
        return get_report_data()

    # -----------------------
    # Drift Detection (Phase 14)
    # -----------------------
    @app.get("/api/drift/latest")
    def drift_latest():
        return get_latest_drift()

    @app.get("/api/drift/history")
    def drift_history():
        return get_drift_history()

    # -----------------------
    # Remediation Action Tracking (Phase 21)
    # -----------------------
    @app.get("/api/identities/<identity_id>/remediation-status")
    def identity_remediation_status(identity_id):
        return get_remediation_status(identity_id)

    @app.post("/api/identities/<identity_id>/remediation-action")
    @require_role('auditor', 'admin')
    def identity_remediation_action(identity_id):
        return post_remediation_action(identity_id)

    @app.get("/api/remediation-summary")
    def remediation_summary():
        return get_remediation_dashboard_summary()

    @app.get("/api/remediation/generated")
    def remediation_generated():
        return get_generated_remediations_handler()

    @app.patch("/api/remediation/generated/<remediation_id>")
    def remediation_generated_update(remediation_id):
        return update_generated_remediation_handler(remediation_id)

    @app.post("/api/remediation/generate")
    def remediation_generate_trigger():
        return trigger_remediation_generation_handler()

    @app.get("/api/remediation/<remediation_id>/script")
    def remediation_script(remediation_id):
        return get_remediation_script_handler(remediation_id)

    # -----------------------
    # Bulk Operations (Phase 25)
    # -----------------------
    @app.post("/api/bulk/remediation")
    @require_role('auditor', 'admin')
    def bulk_remediation():
        return post_bulk_remediation()

    # -----------------------
    # Dashboard Charts (Phase 26)
    # -----------------------
    @app.get("/api/dashboard/role-usage")
    def dashboard_role_usage():
        return get_role_usage_stats()

    # -----------------------
    # Role Mining & Optimization (Phase 37)
    # -----------------------
    @app.get("/api/role-mining")
    def role_mining():
        return get_role_mining()

    # -----------------------
    # RBAC Hygiene (Phase 88 + FIX1A)
    # -----------------------
    @app.get("/api/rbac-hygiene")
    def rbac_hygiene_combined():
        return get_rbac_hygiene_combined()

    @app.get("/api/rbac-hygiene/summary")
    def rbac_hygiene_summary():
        return get_rbac_hygiene_summary()

    @app.get("/api/rbac-hygiene/findings")
    def rbac_hygiene_findings():
        return get_rbac_hygiene_findings()

    @app.post("/api/rbac-hygiene/scan")
    @require_role('admin')
    def rbac_hygiene_scan():
        return run_rbac_hygiene_scan()

    @app.get("/api/rbac-hygiene/history")
    def rbac_hygiene_history():
        return get_rbac_hygiene_history()

    # -----------------------
    # Historical Trends (Phase 20)
    # -----------------------
    @app.get("/api/trends")
    def trends():
        return get_trends()

    @app.get("/api/trends/velocity")
    def trends_vel():
        return get_trends_velocity()

    # -----------------------
    # Settings (Phase 15 - Admin only for writes)
    # -----------------------
    @app.get("/api/settings")
    def app_settings():
        return get_app_settings()

    @app.post("/api/settings")
    @require_role('admin')
    @validate_json(SAVE_SETTINGS_SCHEMA)
    def app_settings_save():
        return save_app_settings()

    @app.post("/api/settings/test-email")
    @require_role('admin')
    def settings_test_email():
        return test_email()

    @app.post("/api/settings/test-connection")
    @require_role('admin', 'security_admin')
    def settings_test_connection():
        return test_azure_connection()

    # -----------------------
    # Cloud Connections (multi-directory / multi-cloud)
    # -----------------------
    @app.get("/api/client/connections")
    def client_connections_list():
        return get_client_connections()

    @app.post("/api/client/connections")
    @require_role('admin', 'security_admin')
    @rate_limit(max_requests=20, window_seconds=60)
    @validate_json(CREATE_CONNECTION_SCHEMA)
    @idempotent
    def client_connections_create():
        return create_client_connection()

    @app.put("/api/client/connections/<int:connection_id>")
    @require_role('admin', 'security_admin')
    @rate_limit(max_requests=20, window_seconds=60)
    def client_connections_update(connection_id):
        return update_client_connection(connection_id)

    @app.delete("/api/client/connections/<int:connection_id>")
    @require_role('admin')
    @rate_limit(max_requests=20, window_seconds=60)
    def client_connections_delete(connection_id):
        return delete_client_connection(connection_id)

    @app.post("/api/client/connections/<int:connection_id>/purge-data")
    @require_role('admin')
    @rate_limit(max_requests=PURGE_RATE_LIMIT_REQUESTS, window_seconds=PURGE_RATE_LIMIT_WINDOW_SECONDS)
    def client_connections_purge_data(connection_id):
        return purge_client_connection_data(connection_id)

    @app.post("/api/admin/cleanup-inactive-connections")
    @require_role('admin')
    def admin_cleanup_inactive():
        return cleanup_inactive_connections_handler()

    @app.post("/api/client/connections/test")
    @require_role('admin', 'security_admin')
    def client_connections_test():
        return test_client_connection()

    @app.post("/api/client/connections/<int:connection_id>/discover")
    @require_role('admin', 'security_admin')
    def client_connections_discover(connection_id):
        return discover_client_connection(connection_id)

    @app.post("/api/connectors/<int:connection_id>/rotate-credentials")
    @require_role('admin', 'security_admin')
    @rate_limit(max_requests=20, window_seconds=60)
    @validate_json(ROTATE_CREDENTIALS_SCHEMA)
    def connector_rotate_credentials(connection_id):
        return rotate_connector_credentials(connection_id)

    @app.get("/api/connectors/expiring-credentials")
    @require_role('admin', 'security_admin')
    def connector_expiring_credentials():
        return check_connector_credential_expiry_handler()

    # -----------------------
    # Webhooks (Phase 28 - Admin only for writes)
    # -----------------------
    @app.get("/api/webhooks")
    def webhooks_list():
        return get_webhooks_list()

    @app.post("/api/webhooks")
    @require_role('admin')
    @validate_json(CREATE_WEBHOOK_SCHEMA)
    def webhooks_create():
        return create_webhook()

    @app.put("/api/webhooks/<int:webhook_id>")
    @require_role('admin')
    def webhooks_update(webhook_id):
        return update_webhook(webhook_id)

    @app.delete("/api/webhooks/<int:webhook_id>")
    @require_role('admin')
    def webhooks_delete(webhook_id):
        return delete_webhook(webhook_id)

    @app.post("/api/webhooks/<int:webhook_id>/test")
    @require_role('admin')
    def webhooks_test(webhook_id):
        return test_webhook_endpoint(webhook_id)

    @app.get("/api/webhooks/<int:webhook_id>/deliveries")
    def webhooks_deliveries(webhook_id):
        return get_webhook_deliveries(webhook_id)

    # -----------------------
    # Custom Risk Rules (Phase 29 - Admin only for writes)
    # -----------------------
    @app.get("/api/risk-rules")
    def risk_rules_list():
        return get_risk_rules_list()

    @app.post("/api/risk-rules")
    @require_role('admin')
    @require_feature('custom_risk_rules')
    def risk_rules_create():
        return create_risk_rule()

    @app.put("/api/risk-rules/<int:rule_id>")
    @require_role('admin')
    @require_feature('custom_risk_rules')
    def risk_rules_update(rule_id):
        return update_risk_rule(rule_id)

    @app.delete("/api/risk-rules/<int:rule_id>")
    @require_role('admin')
    @require_feature('custom_risk_rules')
    def risk_rules_delete(rule_id):
        return delete_risk_rule(rule_id)

    @app.post("/api/risk-rules/preview")
    @require_role('admin')
    def risk_rules_preview():
        return preview_risk_rule()

    # -----------------------
    # Export Pipeline (Phase 33)
    # -----------------------
    @app.get("/api/export/evidence-zip")
    @require_role('admin', 'security_admin', 'compliance')
    @require_feature('compliance_export')
    def export_evidence_zip_route():
        return export_evidence_zip()

    @app.get("/api/export/<export_type>")
    @require_role('admin', 'security_admin', 'compliance')
    @require_feature('compliance_export')
    def export(export_type):
        return export_data(export_type)

    # -----------------------
    # Saved Views (Phase 34)
    # -----------------------
    @app.get("/api/saved-views")
    def saved_views_list():
        return get_saved_views_list()

    @app.post("/api/saved-views")
    def saved_views_create():
        return create_saved_view_handler()

    @app.put("/api/saved-views/<int:view_id>")
    def saved_views_update(view_id):
        return update_saved_view_handler(view_id)

    @app.delete("/api/saved-views/<int:view_id>")
    def saved_views_delete(view_id):
        return delete_saved_view_handler(view_id)

    @app.post("/api/saved-views/<int:view_id>/default")
    def saved_views_set_default(view_id):
        return set_default_view_handler(view_id)

    # -----------------------
    # Access Reviews (Phase 6 — replaces Phase 36 campaigns)
    # -----------------------
    @app.get("/api/access-reviews")
    def access_reviews_list():
        return p6_get_access_reviews()

    @app.post("/api/access-reviews")
    @require_role('admin', 'security_admin')
    def access_reviews_create():
        return p6_create_access_review()

    @app.get("/api/access-reviews/stats")
    def access_reviews_stats():
        return get_access_reviews_stats_handler()

    @app.get("/api/access-reviews/<int:review_id>")
    def access_reviews_detail(review_id):
        return p6_get_access_review(review_id)

    @app.get("/api/access-reviews/<int:review_id>/assignments")
    def access_review_assignments(review_id):
        return get_access_review_assignments_handler(review_id)

    @app.patch("/api/access-reviews/assignments/<int:assignment_id>/decision")
    @require_role('admin', 'security_admin', 'auditor')
    def access_review_decision(assignment_id):
        return submit_review_decision_handler(assignment_id)

    @app.get("/api/access-reviews/assignments/<int:assignment_id>/evidence")
    def access_review_assignment_evidence(assignment_id):
        return get_assignment_evidence_handler(assignment_id)

    @app.patch("/api/access-reviews/<int:review_id>/complete")
    @require_role('admin', 'security_admin')
    def access_review_complete(review_id):
        return complete_access_review_handler(review_id)

    @app.get("/api/identities/<identity_id>/access-reviews")
    def identity_access_reviews(identity_id):
        return get_identity_access_reviews_handler(identity_id)

    # -----------------------
    # Identity Groups (Phase 38)
    # -----------------------
    @app.get("/api/groups")
    def groups_list():
        return get_groups_list()

    @app.post("/api/groups")
    @require_role('auditor', 'admin')
    def groups_create():
        return create_group_handler()

    @app.get("/api/groups/compare")
    def groups_compare():
        return get_group_comparison_handler()

    @app.get("/api/groups/<int:group_id>")
    def groups_detail(group_id):
        return get_group_detail(group_id)

    @app.put("/api/groups/<int:group_id>")
    @require_role('auditor', 'admin')
    def groups_update(group_id):
        return update_group_handler(group_id)

    @app.delete("/api/groups/<int:group_id>")
    @require_role('admin')
    def groups_delete(group_id):
        return delete_group_handler(group_id)

    @app.post("/api/groups/<int:group_id>/members")
    @require_role('auditor', 'admin')
    def groups_add_members(group_id):
        return add_group_members_handler(group_id)

    @app.delete("/api/groups/<int:group_id>/members")
    @require_role('auditor', 'admin')
    def groups_remove_members(group_id):
        return remove_group_members_handler(group_id)

    @app.get("/api/identities/<identity_id>/groups")
    def identity_groups(identity_id):
        return get_identity_groups_handler(identity_id)

    @app.get("/api/identities/<identity_id>/sensitive-access")
    @require_role('compliance', 'reader', 'admin')
    def identity_sensitive_access(identity_id):
        return get_sensitive_access_for_identity(identity_id)

    @app.get("/api/blast-radius/summary")
    @require_role('compliance', 'reader', 'admin')
    def blast_radius_summary():
        return get_blast_radius_summary()

    # -----------------------
    # Activity Log (Phase 17)
    # -----------------------
    @app.get("/api/activity")
    def activity_log():
        return get_activity()

    @app.get("/api/audit/export")
    @require_role('admin')
    def audit_export():
        return export_audit_trail()

    # -----------------------
    # Notifications (Phase 30)
    # -----------------------
    @app.get("/api/notifications")
    def notifications_list():
        return get_notifications_list()

    @app.get("/api/notifications/stats")
    def notifications_stats():
        return get_notification_stats_handler()

    @app.patch("/api/notifications/<int:notification_id>")
    def notifications_mark(notification_id):
        return mark_notification_handler(notification_id)

    @app.post("/api/notifications/mark-all-read")
    def notifications_mark_all():
        return mark_all_notifications_read_handler()

    @app.delete("/api/notifications/<int:notification_id>")
    def notifications_delete(notification_id):
        return delete_notification_handler(notification_id)

    # -----------------------
    # SPN Dashboard (Phase 71)
    # -----------------------
    @app.get("/api/spns/stats")
    def spn_stats():
        return get_spn_stats()

    @app.get("/api/spns")
    def spn_list():
        return get_spn_list()

    @app.get("/api/spns/<path:identity_id>")
    def spn_detail(identity_id):
        return get_spn_detail(identity_id)

    # -----------------------
    # Phase 2A: Entra Group Scanner
    # -----------------------
    @app.get("/api/entra-groups/stats")
    def entra_groups_stats():
        return get_entra_group_stats()

    @app.get("/api/entra-groups")
    def entra_groups_list():
        return get_entra_groups()

    @app.get("/api/identities/<identity_id>/entra-groups")
    def identity_entra_groups(identity_id):
        return get_identity_entra_groups(identity_id)

    # Unified lineage endpoint — single source of truth for all identity lineage data
    @app.get("/api/identities/<identity_id>/lineage")
    def identity_lineage(identity_id):
        return get_identity_lineage(identity_id)

    # Deprecated alias — old SPN lineage route redirects to unified handler
    @app.get("/api/spn/<path:spn_id>/lineage")
    def spn_lineage(spn_id):
        return get_spn_lineage(spn_id)

    # Lineage Verdicts — historical verdict tracking
    @app.get("/api/identities/<identity_id>/verdict-history")
    def identity_verdict_history(identity_id):
        return get_identity_verdict_history(identity_id)

    @app.get("/api/dashboard/verdict-changes")
    def dashboard_verdict_changes():
        return get_dashboard_verdict_changes()

    # Phase 74: App Registration Audit
    @app.get("/api/app-registrations/stats")
    def app_reg_stats():
        return get_app_reg_stats()

    @app.get("/api/app-registrations")
    def app_reg_list():
        return get_app_reg_list()

    @app.get("/api/app-registrations/<app_id>")
    def app_reg_detail(app_id):
        return get_app_reg_detail(app_id)

    # Workload Identity Exposure (Unified)
    @app.get("/api/workload-identities/stats")
    def workload_stats():
        return get_workload_stats()

    @app.get("/api/workload-identities/findings")
    def workload_findings():
        return get_workload_findings()

    @app.get("/api/workload-identities/anomalies/stats")
    def workload_anomaly_stats_route():
        return get_workload_anomaly_stats()

    @app.get("/api/workload-identities/anomalies")
    def workload_anomalies_route():
        return get_workload_anomalies()

    @app.get("/api/workload-identities")
    def workload_list():
        return get_workload_list()

    @app.get("/api/workload-identities/<path:workload_id>")
    def workload_detail(workload_id):
        return get_workload_detail(workload_id)

    # Phase 72: Data Retention
    @app.get("/api/system/storage")
    def system_storage():
        return get_storage_stats()

    @app.post("/api/system/cleanup")
    @require_role('admin')
    def system_cleanup():
        return run_manual_cleanup()

    @app.get("/api/system/org-isolation")
    @require_role('admin')
    def system_org_isolation():
        return validate_org_isolation()

    # Backward compat: /api/system/tenant-isolation
    @app.get("/api/system/tenant-isolation")
    @require_role('admin')
    def system_tenant_isolation():
        return validate_org_isolation()

    @app.get("/api/system/integrity-check")
    @require_role('admin')
    def system_integrity_check():
        return platform_integrity_check_handler()

    @app.get("/api/system/data-source-map")
    @require_role('admin')
    def system_data_source_map():
        return data_source_map_handler()

    @app.get("/api/system/governance-reconciliation")
    @require_role('admin')
    def system_governance_reconciliation():
        return governance_reconciliation_handler()

    @app.get("/api/system/metric-integrity-debug")
    @require_role('admin')
    def system_metric_integrity_debug():
        return metric_integrity_debug_handler()

    @app.get("/api/system/launch-readiness")
    @require_portal_access()
    def system_launch_readiness():
        return validate_launch_readiness()

    # CVSS Identity Scoring
    @app.post("/api/scoring/recompute")
    @require_role('admin')
    def scoring_recompute():
        return recompute_cvss_scores()

    # Fix Prioritizer — per-identity top 3 fixes
    @app.get("/api/identities/<path:identity_id>/fixes")
    @require_role('viewer', 'auditor', 'admin')
    def identity_top_fixes(identity_id):
        return get_identity_top_fixes(identity_id)

    # Canonical recommendation route (W2-R3)
    @app.get("/api/remediation/recommendations/<path:identity_id>")
    @require_role('viewer', 'auditor', 'admin')
    def remediation_recommendations(identity_id):
        return get_identity_top_fixes(identity_id)

    # Org-level recommendations (W2-R3)
    @app.get("/api/remediation/org-summary")
    @require_role('viewer', 'auditor', 'admin')
    def remediation_org_summary():
        return get_org_remediation_summary()

    # Phase 58: Compliance Auto-Remediation
    @app.post("/api/identities/<path:identity_id>/remediation-execute")
    @require_role('admin')
    def remediation_execute(identity_id):
        return execute_remediation(identity_id)

    @app.get("/api/remediation/queue")
    def remediation_queue():
        return get_remediation_queue_handler()

    @app.post("/api/remediation/auto-execute")
    @require_role('admin')
    def remediation_auto_execute():
        return batch_auto_remediate()

    # Organization logo upload/delete
    @app.post("/api/organizations/<int:organization_id>/logo")
    @require_portal_role('superadmin', 'poweradmin')
    def organization_logo_upload(organization_id):
        return upload_organization_logo(organization_id)

    @app.delete("/api/organizations/<int:organization_id>/logo")
    @require_portal_role('superadmin', 'poweradmin')
    def organization_logo_delete(organization_id):
        return delete_organization_logo(organization_id)

    # Backward compat: /api/tenants/<id>/logo + /api/clients/<id>/logo
    # FIX1A: Client portal uses @require_role (not portal_role) since
    # these are called from the client Settings page with client JWT
    @app.post("/api/tenants/<int:organization_id>/logo")
    @require_role('admin')
    def tenant_logo_upload(organization_id):
        return upload_organization_logo(organization_id)

    @app.delete("/api/tenants/<int:organization_id>/logo")
    @require_role('admin')
    def tenant_logo_delete(organization_id):
        return delete_organization_logo(organization_id)

    @app.post("/api/clients/<int:organization_id>/logo")
    @require_role('admin')
    def client_logo_upload(organization_id):
        return upload_organization_logo(organization_id)

    @app.delete("/api/clients/<int:organization_id>/logo")
    @require_role('admin')
    def client_logo_delete(organization_id):
        return delete_organization_logo(organization_id)

    # Phase 78: Scan modes
    @app.get("/api/scan-modes")
    def scan_modes():
        return get_scan_modes()

    # -----------------------
    # Phase 79: AI Security Copilot
    # -----------------------
    @app.post("/api/copilot/chat")
    @require_feature('ai_copilot')
    @rate_limit(max_requests=20, window_seconds=60)
    @validate_json(COPILOT_CHAT_SCHEMA)
    def copilot_chat_route():
        return copilot_chat()

    @app.get("/api/copilot/conversations")
    def copilot_conversations_route():
        return copilot_conversations_list()

    @app.get("/api/copilot/suggestions")
    def copilot_suggestions_route():
        return copilot_suggestions()

    # Phase 12: Context-aware copilot
    @app.post("/api/copilot/query")
    @require_feature('ai_copilot')
    @rate_limit(max_requests=20, window_seconds=60)
    def copilot_query_route():
        return copilot_query_handler()

    @app.get("/api/copilot/security-summary")
    @require_feature('ai_copilot')
    def copilot_security_summary_route():
        return copilot_security_summary_handler()

    # AI Copilot Investigation Enhancement
    @app.post("/api/copilot/investigate")
    @require_feature('ai_copilot')
    @rate_limit(max_requests=20, window_seconds=60)
    def copilot_investigate_route():
        return copilot_investigate_handler()

    @app.post("/api/copilot/graph-query")
    @require_feature('ai_copilot')
    @rate_limit(max_requests=20, window_seconds=60)
    def copilot_graph_query_route():
        return copilot_graph_query_handler()

    # -----------------------
    # Phase 80: Identity Timeline
    # -----------------------
    @app.get("/api/identities/<identity_id>/timeline")
    def identity_timeline(identity_id):
        return get_identity_timeline(identity_id)

    # -----------------------
    # Phase 81: Attack Path Analysis
    # -----------------------
    @app.get("/api/identities/<identity_id>/attack-paths")
    def identity_attack_paths(identity_id):
        return get_identity_attack_paths(identity_id)

    @app.get("/api/identities/<identity_id>/effective-access")
    def identity_effective_access(identity_id):
        return get_identity_effective_access(identity_id)

    # -----------------------
    # Phase 83: Slack/Teams Integrations
    # -----------------------
    @app.get("/api/settings/integrations")
    @require_role('admin')
    def integrations_get():
        return get_integration_settings()

    @app.post("/api/settings/integrations")
    @require_role('admin')
    def integrations_save():
        return save_integration_settings()

    @app.post("/api/settings/integrations/test")
    @require_role('admin')
    def integrations_test():
        return test_integration_webhook()

    # -----------------------
    # Cloud Subscriptions (per-account monitoring)
    # -----------------------
    @app.get("/api/subscriptions")
    def subscriptions_list():
        return get_subscriptions_list()

    @app.get("/api/subscriptions/stats")
    def subscriptions_stats():
        return get_subscriptions_stats()

    @app.post("/api/subscriptions/activate")
    @require_role('admin', 'security_admin')
    def subscriptions_activate():
        return activate_subscription()

    @app.post("/api/subscriptions/activate-all")
    @require_role('admin', 'security_admin')
    def subscriptions_activate_all():
        return activate_all_subscriptions()

    @app.put("/api/subscriptions/<int:sub_id>/deactivate")
    @require_role('admin', 'security_admin')
    def subscriptions_deactivate(sub_id):
        return deactivate_subscription(sub_id)

    @app.post("/api/subscriptions/reconcile")
    @require_role('admin', 'security_admin')
    def subscriptions_reconcile():
        return reconcile_subscriptions()

    @app.get("/api/subscriptions/distinct")
    def subscriptions_distinct():
        return get_subscriptions_distinct()

    @app.get("/api/subscriptions/scope-summary")
    def subscriptions_scope_summary():
        return get_subscriptions_scope_summary()

    @app.get("/api/identities/<path:identity_id>/subscriptions")
    def identity_subscriptions(identity_id):
        return get_identity_subscriptions(identity_id)

    # -----------------------
    # Client Subscription Activation (REST path-param)
    # -----------------------
    @app.post("/api/client/subscriptions/<int:subscription_id>/activate")
    @require_role('admin', 'security_admin')
    def client_subscription_activate(subscription_id):
        return activate_client_subscription(subscription_id)

    # -----------------------
    # Discovery Status & Trigger
    # -----------------------
    @app.get("/api/discovery/status")
    def discovery_status():
        return get_discovery_status()

    @app.post("/api/discovery/run")
    def discovery_run():
        return run_discovery()

    @app.get("/api/discovery/jobs/<int:connection_id>")
    def discovery_job_status(connection_id):
        return get_snapshot_job_status(connection_id)

    @app.get("/api/discovery/history")
    def discovery_history():
        return get_discovery_history()

    @app.get("/api/discovery/settings/<int:connection_id>")
    def discovery_settings_get(connection_id):
        return get_discovery_settings(connection_id)

    @app.put("/api/discovery/settings/<int:connection_id>")
    def discovery_settings_update(connection_id):
        return update_discovery_settings(connection_id)

    # -----------------------
    # Phase 6: Scan Schedules
    # -----------------------
    @app.get("/api/scan-schedules")
    @require_role('admin', 'security_admin')
    def scan_schedules_list():
        return get_scan_schedules_list()

    @app.post("/api/scan-schedules")
    @require_role('admin')
    def scan_schedule_create():
        return create_scan_schedule_handler()

    @app.put("/api/scan-schedules/<int:schedule_id>")
    @require_role('admin')
    def scan_schedule_update(schedule_id):
        return update_scan_schedule_handler(schedule_id)

    @app.delete("/api/scan-schedules/<int:schedule_id>")
    @require_role('admin')
    def scan_schedule_delete(schedule_id):
        return delete_scan_schedule_handler(schedule_id)

    # -----------------------
    # Phase 6: Stripe Billing
    # -----------------------
    @app.get("/api/billing/stripe-status")
    @require_role('admin')
    def billing_stripe_status():
        return get_stripe_status()

    @app.post("/api/billing/stripe-webhook")
    def billing_stripe_webhook():
        return stripe_webhook_handler()

    @app.post("/api/admin/organizations/<int:organization_id>/stripe-customer")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_create_org_stripe_customer(organization_id):
        return create_stripe_customer_handler(organization_id)

    # Backward compat: /api/admin/tenants/<id>/stripe-customer
    @app.post("/api/admin/tenants/<int:organization_id>/stripe-customer")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_create_stripe_customer(organization_id):
        return create_stripe_customer_handler(organization_id)

    # -----------------------
    # Phase 3B: Billing Transparency & Invoice Engine
    # -----------------------
    @app.get("/api/billing/current-estimate")
    @require_role('admin', 'security_admin')
    def billing_current_estimate():
        return get_billing_current_estimate()

    @app.get("/api/billing/history")
    @require_role('admin', 'security_admin')
    def billing_history():
        return get_billing_history_handler()

    @app.get("/api/billing/invoice/<int:doc_id>/download")
    @require_role('admin', 'security_admin')
    def billing_invoice_download(doc_id):
        return get_billing_invoice_download(doc_id)

    @app.get("/api/billing/status")
    @require_role('admin', 'security_admin')
    def billing_status():
        return get_billing_status_handler()

    @app.get("/api/msp/billing/aggregate")
    @require_role('admin', 'security_admin')
    def msp_billing_aggregate():
        return get_msp_billing_aggregate()

    # Admin billing overrides
    @app.post("/api/admin/organizations/<int:organization_id>/billing/snapshot")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    @rate_limit(max_requests=5, window_seconds=60)
    def admin_billing_snapshot(organization_id):
        return admin_generate_billing_snapshot(organization_id)

    @app.post("/api/admin/organizations/<int:organization_id>/billing/invoice-document")
    @require_portal_role('superadmin', 'poweradmin', 'billing')
    def admin_billing_invoice_document(organization_id):
        return admin_generate_invoice_document(organization_id)

    @app.post("/api/admin/msp/relationships")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_msp_relationships():
        return admin_update_msp_relationship()

    # -----------------------
    # Phase 6: Pilot Setup
    # -----------------------
    @app.post("/api/admin/pilot-setup")
    @require_portal_role('superadmin', 'poweradmin')
    def admin_pilot_setup():
        return create_pilot_organization()

    # -----------------------
    # Phase 6: Password Policy
    # -----------------------
    @app.get("/api/auth/password-policy")
    def auth_password_policy():
        return get_password_policy()

    # -----------------------
    # ICE: Identity Correlation Engine
    # -----------------------
    @app.get("/api/correlation/linked")
    def correlation_linked():
        return get_correlation_linked_identities()

    @app.get("/api/correlation/linked/<int:human_id>")
    def correlation_linked_detail(human_id):
        return get_correlation_linked_identity_detail(human_id)

    @app.post("/api/correlation/link")
    @require_role('admin', 'security_admin')
    def correlation_link_create():
        return post_correlation_link()

    @app.delete("/api/correlation/link/<int:link_id>")
    @require_role('admin', 'security_admin')
    def correlation_link_delete(link_id):
        return delete_correlation_link(link_id)

    @app.put("/api/correlation/link/<int:link_id>/verify")
    @require_role('admin', 'security_admin')
    def correlation_link_verify(link_id):
        return verify_correlation_link(link_id)

    @app.get("/api/findings/orphaned-privileged")
    def findings_orphaned():
        return get_orphaned_findings_list()

    @app.get("/api/findings/orphaned-privileged/<int:finding_id>")
    def findings_orphaned_detail(finding_id):
        return get_orphaned_finding_detail_handler(finding_id)

    @app.put("/api/findings/orphaned-privileged/<int:finding_id>/acknowledge")
    @require_role('admin', 'security_admin', 'auditor')
    def findings_orphaned_acknowledge(finding_id):
        return acknowledge_orphaned_finding(finding_id)

    @app.put("/api/findings/orphaned-privileged/<int:finding_id>/remediate")
    @require_role('admin', 'security_admin')
    def findings_orphaned_remediate(finding_id):
        return remediate_orphaned_finding(finding_id)

    @app.put("/api/findings/orphaned-privileged/<int:finding_id>/suppress")
    @require_role('admin', 'security_admin')
    def findings_orphaned_suppress(finding_id):
        return suppress_orphaned_finding(finding_id)

    @app.get("/api/correlation/config")
    def correlation_config_get():
        return get_correlation_config()

    @app.put("/api/correlation/config")
    @require_role('admin')
    def correlation_config_save():
        return save_correlation_config()

    @app.get("/api/dashboard/identity-correlation")
    def dashboard_identity_correlation():
        return get_dashboard_identity_correlation()

    @app.get("/api/correlation/accounts")
    def correlation_accounts():
        return get_correlation_accounts()

    # -----------------------
    # Security Findings (Phase 2)
    # -----------------------
    @app.get("/api/findings")
    def findings_list():
        return get_findings_list()

    @app.get("/api/findings/stats")
    def findings_stats():
        return get_findings_stats_handler()

    @app.get("/api/findings/<int:finding_id>")
    def finding_detail(finding_id):
        return get_finding_detail(finding_id)

    @app.patch("/api/findings/<int:finding_id>/status")
    @require_role('admin', 'security_admin')
    def finding_status_update(finding_id):
        return update_finding_status_handler(finding_id)

    # -----------------------
    # Phase 6: Risk Findings (Rules-Based)
    # -----------------------
    @app.get("/api/risk/findings")
    def risk_findings_list():
        return get_risk_findings_list()

    @app.post("/api/risk/findings/<finding_id>/acknowledge")
    @require_role('admin', 'security_admin')
    def risk_finding_acknowledge(finding_id):
        return acknowledge_risk_finding(finding_id)

    @app.post("/api/risk/findings/<finding_id>/resolve")
    @require_role('admin', 'security_admin')
    def risk_finding_resolve(finding_id):
        return resolve_risk_finding(finding_id)

    # -----------------------
    # Phase 7: IAM Graph Queries
    # -----------------------
    @app.get("/api/graph/identity/<identity_id>/access")
    def graph_identity_access(identity_id):
        return get_graph_identity_access(identity_id)

    # -----------------------
    # Phase 8: Privilege Escalation Paths
    # -----------------------
    @app.get("/api/graph/identity/<identity_id>/attack-paths")
    def graph_identity_attack_paths(identity_id):
        return get_graph_identity_attack_paths(identity_id)

    # -----------------------
    # Phase 9: NHI Security
    # -----------------------
    @app.get("/api/security/nhi")
    def nhi_security():
        return get_nhi_security_findings()

    # -----------------------
    # Phase 10: Executive Dashboard
    # -----------------------
    @app.get("/api/dashboard/summary")
    def dashboard_summary():
        return get_dashboard_summary_handler()

    # -----------------------
    # Phase 11: Policy Recommendations
    # -----------------------
    @app.get("/api/security/recommendations")
    def security_recommendations():
        return _safe_handler(get_policy_recommendations_handler, {'recommendations': [], 'stats': None})

    @app.post("/api/security/recommendations/<rec_id>/accept")
    def security_recommendation_accept(rec_id):
        return accept_policy_recommendation(rec_id)

    @app.post("/api/security/recommendations/<rec_id>/dismiss")
    def security_recommendation_dismiss(rec_id):
        return dismiss_policy_recommendation(rec_id)

    # -----------------------
    # Phase 12: Automated Remediation
    # -----------------------
    @app.post("/api/security/remediation/<recommendation_id>/execute")
    def security_remediation_execute(recommendation_id):
        return execute_remediation_handler(recommendation_id)

    @app.post("/api/security/remediation/<action_id>/approve")
    def remediation_approve(action_id):
        return approve_remediation_handler(action_id)

    @app.get("/api/security/remediation/actions")
    def remediation_actions_list():
        return get_remediation_actions_handler()

    # -----------------------
    # Phase 13: Attack Simulation
    # -----------------------
    @app.post("/api/security/attack-simulation")
    def attack_simulation_run():
        return run_attack_simulation_handler()

    @app.get("/api/security/attack-simulation/<simulation_id>")
    def attack_simulation_detail(simulation_id):
        return get_attack_simulation_handler(simulation_id)

    @app.get("/api/security/attack-simulations")
    def attack_simulations_list():
        return _safe_handler(get_attack_simulations_list_handler, {'simulations': []})

    # -----------------------
    # Phase 14: Security Benchmarking
    # -----------------------
    @app.get("/api/security/benchmark")
    def security_benchmark():
        return _safe_handler(get_security_benchmark_handler, {'error': 'unavailable'})

    # -----------------------
    # Phase 15: AI Security Advisor
    # -----------------------
    @app.get("/api/security/advisor")
    def security_advisor():
        return _safe_handler(get_security_advisor_handler, {'recommendations': []})

    # -----------------------
    # Phase 17: Multi-Cloud Identity Support
    # -----------------------
    # -----------------------
    # Phase 18: Risk Forecasting
    # -----------------------
    @app.get("/api/security/risk-forecast")
    def risk_forecast():
        return _safe_handler(get_risk_forecast_handler, {'forecast': None})

    # -----------------------
    # Phase 19: Least-Privilege Policy Generation
    # -----------------------
    @app.get("/api/security/generated-policy/<identity_id>")
    def generated_policy(identity_id):
        return get_generated_policy_handler(identity_id)

    @app.get("/api/security/generated-policies")
    def generated_policies_list():
        return _safe_handler(get_generated_policies_list_handler, {'policies': [], 'stats': None})

    @app.post("/api/security/generated-policies/<policy_id>/apply")
    def apply_generated_policy(policy_id):
        return apply_generated_policy_handler(policy_id)

    @app.post("/api/security/generated-policies/<policy_id>/dismiss")
    def dismiss_generated_policy(policy_id):
        return dismiss_generated_policy_handler(policy_id)

    # -----------------------
    # Phase 20: Continuous Identity Threat Detection
    # -----------------------
    @app.get("/api/security/threat-events")
    def threat_events():
        return _safe_handler(get_threat_events_handler, {'events': [], 'stats': None})

    @app.post("/api/security/threat-events/<event_id>/acknowledge")
    def acknowledge_threat_event(event_id):
        return acknowledge_threat_event_handler(event_id)

    @app.post("/api/security/threat-events/<event_id>/resolve")
    def resolve_threat_event(event_id):
        return resolve_threat_event_handler(event_id)

    # -----------------------
    # Phase 21: Identity Security Data Lake
    # -----------------------
    @app.get("/api/security/identity-history/<identity_id>")
    def identity_history(identity_id):
        return get_identity_history_handler(identity_id)

    @app.get("/api/security/activity-events")
    def activity_events():
        return _safe_handler(get_activity_events_handler, {'events': []})

    # -----------------------
    # Phase 23: Identity Attack Replay & Forensics
    # -----------------------
    @app.get("/api/security/incidents")
    def attack_incidents():
        return _safe_handler(get_attack_incidents_handler, {'incidents': [], 'stats': None})

    @app.get("/api/security/attack-replay/<incident_id>")
    def attack_replay(incident_id):
        return get_attack_replay_handler(incident_id)

    @app.post("/api/security/incidents/<incident_id>/status")
    def incident_status(incident_id):
        return update_incident_status_handler(incident_id)

    # -----------------------
    # Phase 24: Autonomous Identity Security Operations
    # -----------------------
    @app.get("/api/security/response-actions")
    def response_actions():
        return _safe_handler(get_response_actions_handler, {'actions': [], 'stats': None})

    @app.post("/api/security/response-actions/<action_id>/approve")
    def approve_response_action(action_id):
        return approve_response_action_handler(action_id)

    @app.post("/api/security/response-actions/<action_id>/execute")
    def execute_response_action(action_id):
        return execute_response_action_handler(action_id)

    # -----------------------
    # Phase 26: Identity Attack Prediction
    # -----------------------
    @app.get("/api/security/attack-predictions")
    def attack_predictions():
        return _safe_handler(get_attack_predictions_handler, {'predictions': [], 'stats': None})

    # -----------------------
    # Phase 27: Identity Graph Intelligence
    # -----------------------
    @app.get("/api/security/graph-insights")
    def graph_insights():
        return _safe_handler(get_graph_insights_handler, {'insights': [], 'stats': None})

    # -----------------------
    # Phase 28: Identity Governance
    # -----------------------
    @app.get("/api/security/governance-actions")
    def governance_actions():
        return _safe_handler(get_governance_actions_handler, {'actions': [], 'stats': None})

    # -----------------------
    # Phase 29: Identity Risk Simulation
    # -----------------------
    @app.post("/api/security/risk-simulation")
    def risk_simulation():
        return run_risk_simulation_handler()

    @app.get("/api/security/risk-simulations")
    def risk_simulations_list():
        return _safe_handler(get_risk_simulations_handler, {'simulations': [], 'stats': None})

    # -----------------------
    # Phase 30: Enterprise Security Integrations
    # -----------------------
    @app.get("/api/security/integrations")
    def security_integrations():
        return _safe_handler(get_integration_events_handler, {'events': [], 'stats': None})

    @app.post("/api/security/integrations/configure")
    def configure_integration():
        return configure_integration_handler()

    # -----------------------
    # Phase 31: Governance Analytics
    # -----------------------
    @app.get("/api/security/governance-metrics")
    def governance_metrics():
        return _safe_handler(get_governance_metrics_handler, {'metrics': [], 'stats': None})

    @app.get("/api/security/governance-trends")
    def governance_trends():
        return _safe_handler(get_governance_trends_handler, {'trends': [], 'stats': None})

    # -----------------------
    # Phase 32: Security Strategy Advisor
    # -----------------------
    @app.get("/api/security/strategy-advisor")
    def strategy_advisor():
        return _safe_handler(get_strategy_advisor_handler, {'recommendations': [], 'stats': None})

    # -----------------------
    # Phase 33: Security Command Center
    # -----------------------
    @app.get("/api/security/command-center")
    def command_center():
        return _safe_handler(get_command_center_handler, {'posture': None, 'stats': None})

    # -----------------------
    # Phase 25: AI Security Copilot
    # -----------------------
    @app.post("/api/security/copilot-query")
    def copilot_query():
        return process_copilot_query_handler()

    @app.get("/api/security/copilot-history")
    def copilot_history():
        return get_copilot_history_handler()

    @app.get("/api/security/findings")
    def security_findings_list():
        return get_security_findings_handler()

    @app.get("/api/security/findings/summary")
    def security_findings_summary():
        return get_security_findings_summary_handler()

    @app.post("/api/security/findings/<finding_id>/acknowledge")
    def security_finding_acknowledge(finding_id):
        return acknowledge_security_finding_handler(finding_id)

    @app.post("/api/security/findings/<finding_id>/resolve")
    def security_finding_resolve(finding_id):
        return resolve_security_finding_handler(finding_id)

    @app.get("/api/security/cloud-summary")
    def cloud_risk_summary():
        return get_cloud_risk_summary_handler()

    @app.get("/api/security/overview")
    def security_overview():
        return get_security_overview_handler()

    @app.get("/api/security/dashboard")
    def security_dashboard():
        return get_security_dashboard_handler()

    # -----------------------
    # Phase 16: Graph Visualization
    # -----------------------
    @app.get("/api/graph/debug")
    def graph_debug():
        return get_graph_debug_handler()

    @app.get("/api/graph/visualization")
    def graph_visualization():
        return get_graph_visualization_handler()

    @app.get("/api/graph/identity/<identity_id>")
    def graph_identity(identity_id):
        return get_identity_graph_handler(identity_id)

    @app.get("/api/graph/attack-path/<simulation_id>")
    def graph_attack_path(simulation_id):
        return get_attack_path_graph_handler(simulation_id)

    # -----------------------
    # Attack Path Analysis (Phase 3)
    # -----------------------
    @app.get("/api/attack-paths")
    def attack_paths_list():
        return get_attack_paths_list()

    @app.get("/api/attack-paths/<path_id>")
    def attack_path_detail(path_id):
        return get_attack_path_detail(path_id)

    @app.get("/api/identities/<identity_id>/persisted-attack-paths")
    def identity_persisted_attack_paths(identity_id):
        return get_identity_persisted_attack_paths(identity_id)

    @app.post("/api/attack-paths/analyze")
    def attack_paths_analyze():
        return trigger_attack_path_analysis()

    @app.get("/api/dashboard/attack-surface")
    def dashboard_attack_surface():
        return get_attack_surface_summary()

    # -----------------------
    # Remediation Queue (attack-path driven)
    # -----------------------
    @app.get("/api/remediation-queue/summary")
    def rq_summary():
        return get_remediation_queue_summary()

    @app.get("/api/remediation-queue/<int:item_id>")
    def rq_item_detail(item_id):
        return get_remediation_queue_item_detail(item_id)

    @app.get("/api/remediation-queue")
    def rq_list():
        return list_remediation_queue()

    @app.post("/api/remediation-queue")
    @require_role('admin', 'security_admin', 'auditor')
    def rq_create():
        return create_remediation_queue_item()

    @app.patch("/api/remediation-queue/<int:item_id>")
    @require_role('admin', 'security_admin', 'auditor')
    def rq_patch(item_id):
        return patch_remediation_queue_item(item_id)

    # -----------------------
    # Phase 8: Graph Attack Findings & Identity Risk Scores
    # -----------------------
    @app.get("/api/graph-findings")
    def graph_findings_list():
        return get_graph_attack_findings_handler()

    @app.get("/api/graph-findings/<int:finding_id>")
    def graph_finding_detail(finding_id):
        return get_graph_attack_finding_detail_handler(finding_id)

    @app.get("/api/identity-risk-scores")
    def identity_risk_scores():
        return get_identity_risk_scores_handler()

    @app.post("/api/graph-attack/analyze")
    @require_role('admin', 'security_admin')
    def graph_attack_analyze():
        return run_graph_attack_analysis_handler()

    # -----------------------
    # Identity Graph Engine API
    # -----------------------
    @app.get("/api/graph/attack-paths")
    def graph_engine_attack_paths():
        return get_graph_engine_attack_paths()

    @app.get("/api/graph/blast-radius")
    def graph_engine_blast_radius():
        return get_graph_engine_blast_radius()

    @app.get("/api/graph/escalation-paths")
    def graph_engine_escalation_paths():
        return get_graph_engine_escalation_paths()

    # -----------------------
    # Identity Risk Summary & AI Explanation
    # -----------------------
    @app.get("/api/identities/<identity_id>/risk-summary")
    def identity_risk_summary_detail(identity_id):
        return get_identity_risk_summary_detail(identity_id)

    @app.get("/api/identities/<identity_id>/ai-risk-explanation")
    def identity_ai_risk_explanation(identity_id):
        return get_identity_ai_risk_explanation(identity_id)

    @app.post("/api/ai/explain-attack-path")
    @require_feature('ai_copilot')
    def ai_explain_attack_path():
        return post_ai_attack_path_explanation()

    @app.post("/api/ai/executive-narrative")
    @require_feature('ai_copilot')
    def ai_executive_narrative():
        return post_ai_executive_narrative()

    # -----------------------
    # Phase 91: AI Investigation Assistant
    # -----------------------
    @app.post("/api/ai/investigate-assistant")
    @require_feature('ai_copilot')
    def ai_investigate_assistant():
        return ai_investigate_assistant_handler()

    @app.get("/api/ai/audit-log")
    @require_role('admin')
    def ai_audit_log():
        return get_ai_audit_log_handler()

    @app.post("/api/ai/remediation-plan")
    @require_feature('ai_copilot')
    def ai_remediation_plan():
        return post_ai_remediation_plan()

    @app.post("/api/ai/least-privilege-role")
    @require_feature('ai_copilot')
    def ai_least_privilege_role():
        return post_ai_least_privilege_role()

    @app.get("/api/graph/diff")
    def graph_diff():
        return get_graph_diff_handler()

    # -----------------------
    # Phase 16: Continuous Identity Risk Monitoring
    # -----------------------
    @app.get("/api/identity-exposures")
    def identity_exposures():
        return get_identity_exposures_handler()

    @app.post("/api/identity-exposures/<exposure_id>/acknowledge")
    def identity_exposure_acknowledge(exposure_id):
        return acknowledge_identity_exposure_handler(exposure_id)

    @app.post("/api/identity-exposures/<exposure_id>/resolve")
    def identity_exposure_resolve(exposure_id):
        return resolve_identity_exposure_handler(exposure_id)

    @app.get("/api/privilege-drift")
    def privilege_drift():
        return get_privilege_drift_handler()

    @app.post("/api/attack-path/simulate")
    def attack_path_simulate():
        return simulate_attack_path_handler()

    @app.post("/api/attack/simulate")
    def attack_simulate():
        return simulate_attack_path_handler()

    # -----------------------
    # Phase 9: Security Posture Command Center
    # -----------------------
    @app.get("/api/posture-score")
    def posture_score():
        return get_posture_score_handler()

    @app.get("/api/risky-identities")
    def risky_identities():
        return get_risky_identities_handler()

    @app.get("/api/remediation-priority")
    def remediation_priority():
        return get_remediation_priority_handler()

    @app.get("/api/privileged-identities")
    def privileged_identities():
        return get_privileged_identities_handler()

    @app.get("/api/security-events")
    def security_events():
        return get_security_events_handler()

    # -----------------------
    # Phase 10: Remediation Workflow
    # -----------------------
    @app.post("/api/findings/<finding_id>/assign")
    @require_role('admin', 'security_admin')
    def finding_assign(finding_id):
        return assign_finding_handler(finding_id)

    @app.post("/api/findings/<finding_id>/status")
    @require_role('admin', 'security_admin')
    def finding_status_workflow(finding_id):
        return update_finding_status_workflow_handler(finding_id)

    @app.post("/api/findings/<finding_id>/comments")
    @require_role('admin', 'security_admin', 'auditor')
    def finding_comment_add(finding_id):
        return add_finding_comment_handler(finding_id)

    @app.get("/api/findings/<finding_id>/comments")
    def finding_comments_list(finding_id):
        return get_finding_comments_handler(finding_id)

    @app.get("/api/remediation-metrics")
    def remediation_metrics():
        return get_remediation_metrics_handler()

    # -----------------------
    # Phase 11: Security Automation & Integrations
    # -----------------------
    @app.post("/api/integrations/slack")
    @require_role('admin', 'security_admin')
    def integration_slack():
        return save_slack_integration_handler()

    @app.post("/api/integrations/jira")
    @require_role('admin', 'security_admin')
    def integration_jira():
        return save_jira_integration_handler()

    @app.post("/api/findings/<finding_id>/jira")
    @require_role('admin', 'security_admin')
    def finding_jira_ticket(finding_id):
        return create_jira_ticket_handler(finding_id)

    @app.get("/api/reports/posture")
    def report_posture():
        return get_report_posture_handler()

    @app.get("/api/reports/findings")
    def report_findings():
        return get_report_findings_handler()

    @app.get("/api/reports/remediation")
    def report_remediation():
        return get_report_remediation_handler()

    # -----------------------
    # Fix Recommendations (Phase 4)
    # -----------------------
    @app.get("/api/fix-recommendations")
    def fix_recommendations_list():
        return get_fix_recommendations_list()

    @app.get("/api/fix-recommendations/stats")
    def fix_recommendations_stats():
        return get_fix_recommendations_stats_handler()

    @app.get("/api/fix-recommendations/<int:rec_id>")
    def fix_recommendation_detail(rec_id):
        return get_fix_recommendation_detail(rec_id)

    @app.patch("/api/fix-recommendations/<int:rec_id>/status")
    @require_role('admin', 'security_admin')
    def fix_recommendation_status_update(rec_id):
        return update_fix_recommendation_status_handler(rec_id)

    @app.get("/api/identities/<identity_id>/fix-recommendations")
    def identity_fix_recommendations(identity_id):
        return get_identity_fix_recommendations(identity_id)

    # -----------------------
    # Blast Radius (Phase 5)
    # -----------------------
    @app.get("/api/blast-radius")
    def blast_radius_list():
        return get_blast_radius_list()

    @app.get("/api/blast-radius/<identity_id>")
    def blast_radius_detail(identity_id):
        return get_blast_radius_detail(identity_id)

    @app.get("/api/identities/<identity_id>/blast-radius")
    def identity_blast_radius_detail(identity_id):
        return get_identity_blast_radius(identity_id)

    # -----------------------
    # Reporting Engine (Phase 7)
    # -----------------------
    @app.post("/api/reports")
    @require_role('admin', 'security_admin', 'auditor')
    def reports_create():
        return create_report_handler()

    @app.get("/api/reports")
    def reports_list():
        return get_reports_list_handler()

    @app.get("/api/reports/<int:report_id>")
    def reports_detail(report_id):
        return get_report_detail_handler(report_id)

    @app.get("/api/reports/<int:report_id>/runs")
    def reports_runs(report_id):
        return get_report_runs_handler(report_id)

    @app.get("/api/reports/<int:report_id>/download")
    def reports_download(report_id):
        return download_report_handler(report_id)

    # -----------------------
    # Phase 8: Platform Operations & Health Monitoring
    # -----------------------

    @app.get("/api/platform/health")
    @require_role('admin', 'security_admin')
    def platform_health_overview():
        return get_platform_health_handler()

    @app.get("/api/platform/jobs")
    @require_role('admin', 'security_admin')
    def platform_jobs_list():
        return get_system_jobs_handler()

    @app.get("/api/platform/jobs/<job_id>")
    @require_role('admin', 'security_admin')
    def platform_job_detail(job_id):
        return get_system_job_detail_handler(job_id)

    @app.get("/api/platform/tenants")
    @require_role('admin', 'security_admin')
    def platform_tenants_health():
        return get_system_tenants_health_handler()

    @app.get("/api/platform/tenants/<int:org_id>")
    @require_role('admin', 'security_admin')
    def platform_tenant_health_detail(org_id):
        return get_system_tenant_health_detail_handler(org_id)

    @app.get("/api/platform/metrics")
    @require_role('admin', 'security_admin')
    def platform_metrics():
        return get_system_metrics_handler()

    # ─── W2-A1: Approval Workflow + W2-A2: Audit Trail ──────────────
    from app.api.routes.approvals import (
        create_approval_request,
        list_approval_requests,
        get_approval_request,
        approve_request,
        reject_request,
        cancel_request,
        get_approvals_summary,
        get_audit_log,
        get_audit_log_for_identity,
        get_audit_log_summary,
        execute_approval_request,
        get_execution_history,
        rollback_execution,
        get_execution_queue,
    )

    @app.post("/api/approvals")
    def approvals_create():
        return create_approval_request()

    @app.get("/api/approvals/summary")
    def approvals_summary():
        return get_approvals_summary()

    @app.get("/api/approvals")
    def approvals_list():
        return list_approval_requests()

    @app.get("/api/approvals/<request_ref>")
    def approvals_get(request_ref):
        return get_approval_request(request_ref)

    @app.post("/api/approvals/<request_ref>/approve")
    def approvals_approve(request_ref):
        return approve_request(request_ref)

    @app.post("/api/approvals/<request_ref>/reject")
    def approvals_reject(request_ref):
        return reject_request(request_ref)

    @app.post("/api/approvals/<request_ref>/cancel")
    def approvals_cancel(request_ref):
        return cancel_request(request_ref)

    # ─── W3: Execution Engine ──────────────
    @app.post("/api/approvals/<request_ref>/execute")
    def approvals_execute(request_ref):
        return execute_approval_request(request_ref)

    @app.get("/api/approvals/<request_ref>/execution-history")
    def approvals_exec_history(request_ref):
        return get_execution_history(request_ref)

    @app.post("/api/approvals/<request_ref>/rollback")
    def approvals_rollback(request_ref):
        return rollback_execution(request_ref)

    @app.get("/api/execution/queue")
    def execution_queue():
        return get_execution_queue()

    @app.get("/api/audit-log/summary")
    def audit_log_summary():
        return get_audit_log_summary()

    @app.get("/api/audit-log/identity/<identity_id>")
    def audit_log_identity(identity_id):
        return get_audit_log_for_identity(identity_id)

    @app.get("/api/audit-log")
    def audit_log_list():
        return get_audit_log()

    # -----------------------
    # Start background scheduler (only in main process, not reloader)
    # -----------------------
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_scheduler()
        atexit.register(stop_scheduler)

    # RLS startup validation — fail fast if role config is wrong
    from app.database import Database
    Database.validate_rls_startup()

    # Enterprise isolation: FORCE ROW LEVEL SECURITY on all tenant tables
    Database.enforce_force_rls()

    # Ensure default admin user and compliance frameworks on first startup
    db = Database()
    try:
        db.ensure_default_admin()
        db.seed_local_admin()  # admin user — runs for local + dev
        db.seed_compliance_frameworks()
        db.seed_compliance_root_causes()
        db._migrate_compliance_controls_v2()
        db._migrate_compliance_v3()
        db.deduplicate_auto_groups()

        # Migration 025: Tenant index coverage — create missing org_id indexes
        if db.migrate_025_tenant_indexes():
            logger.info("Migration 025_tenant_indexes applied")

        # Phase 8: Ensure platform operations tables
        db._ensure_platform_ops_tables()

        # Seed tenants: AzureCredits org + azadmin (local/dev), Demo org + demo users (all)
        db.seed_dev_tenant()
        db.seed_demo_tenant()

    finally:
        db.close()

    # Bulk GRANT: ensure app user can access all tables created by admin user
    Database.grant_app_user_access()

    # Validate tenant index coverage (warning-only, does not block startup)
    idx_report = Database.validate_tenant_index_coverage()
    if not idx_report.get('skipped'):
        if idx_report['missing_index']:
            logger.warning(
                "TENANT INDEX GAP: %d tables lack organization_id index: %s",
                len(idx_report['missing_index']),
                ', '.join(idx_report['missing_index']),
            )
        if idx_report['non_leading']:
            logger.warning(
                "TENANT INDEX WARNING: %d tables have non-leading org_id index: %s",
                len(idx_report['non_leading']),
                ', '.join(e['table'] for e in idx_report['non_leading']),
            )
        if idx_report['ok']:
            logger.info(
                "Tenant index coverage OK — %d tables checked, all covered",
                idx_report['tables_checked'],
            )

    # Enable the request-context admin guard now that startup is done.
    # Any Database() call inside a request without _admin_reason will raise
    # RuntimeError (ENFORCE_ADMIN_GUARD=True) or log a warning (False).
    Database._startup_complete = True

    # ── API Versioning: mirror /api/* routes at /api/v1/* ──
    # Existing /api/ routes remain unchanged (backward compatible).
    # New /api/v1/ prefix allows future version evolution.
    _register_v1_routes(app)

    # ── Phase 3 FastAPI mount (A3) ──
    # Mount the Phase 3 FastAPI routers (identities, resources, snapshots)
    # under the Flask WSGI stack via a2wsgi. This installs a dispatcher
    # that delegates matching (method, path) tuples to FastAPI and falls
    # through to Flask for everything else — including every legacy v1
    # mirror created by _register_v1_routes that Phase 3 does not own.
    # See app.api.phase3_wsgi.SHADOWED_ROUTES for the exact shadow set.
    try:
        from app.api.phase3_wsgi import install as install_phase3
        install_phase3(app)
    except Exception:
        logger.exception(
            "Phase 3 FastAPI mount failed — Flask continues without "
            "/api/v1 Phase 3 routes"
        )

    return app


def _register_v1_routes(app):
    """Register /api/v1/ aliases for every existing /api/ route.

    This iterates over all registered URL rules and creates matching
    /api/v1/ rules pointing to the same view functions. Existing
    /api/ routes remain untouched — both prefixes work identically.
    """
    v1_count = 0
    for rule in list(app.url_map.iter_rules()):
        if not rule.rule.startswith('/api/'):
            continue
        if rule.rule.startswith('/api/v1/'):
            continue
        # Skip static/health endpoints that don't need versioning
        if rule.endpoint == 'static':
            continue

        v1_path = '/api/v1/' + rule.rule[5:]   # /api/foo → /api/v1/foo
        v1_endpoint = f"v1_{rule.endpoint}"

        # Extract actual HTTP methods (exclude OPTIONS/HEAD — Flask adds those)
        methods = rule.methods - {'OPTIONS', 'HEAD'}
        if not methods:
            continue

        view_func = app.view_functions.get(rule.endpoint)
        if not view_func:
            continue

        try:
            app.add_url_rule(v1_path, endpoint=v1_endpoint,
                             view_func=view_func, methods=sorted(methods))
            v1_count += 1
        except Exception:
            pass  # Skip duplicates or conflicts silently

    logger = logging.getLogger(__name__)
    logger.info("API v1 routes registered: %d routes mirrored at /api/v1/", v1_count)


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=False)
