from flask import Flask, jsonify, g, request
from flask_cors import CORS
from datetime import datetime
import atexit
import logging
import os
import re
import time
import uuid

from app.logging_config import configure_logging
from app.metrics import MetricsCollector
from app.security import rate_limit, add_security_headers

from app.api.auth import auth_middleware, require_role, require_superadmin, require_portal_access, require_portal_role, require_feature
from app.api.handlers import (
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
    get_remediation_status,
    post_remediation_action,
    get_remediation_dashboard_summary,
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
    get_access_reviews_list,
    create_access_review,
    get_access_review_detail,
    update_access_review,
    delete_access_review,
    update_review_decision,
    bulk_review_decisions,
    get_campaign_metrics_handler,
    get_campaign_audit_log_handler,
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
    get_current_organization_handler,
    get_cross_org_analytics,
    get_cross_org_trends,
    get_login_sessions,
    get_onboarding_status,
    test_azure_connection,
    simulate_risk,
    get_resources,
    get_resource_stats,
    get_resource_detail,
    get_resource_access,
    get_resource_findings,
    get_resource_anomalies,
    get_resource_expiry_summary,
    get_resource_compliance_summary,
    get_data_security_summary,
    get_organization_by_slug_public,
    provision_organization_handler,
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
    check_resource_integrity,
    get_portal_users_list,
    get_spn_stats,
    get_spn_list,
    get_spn_detail,
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
    get_subscriptions_distinct,
    get_identity_subscriptions,
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
    create_client_connection,
    update_client_connection,
    delete_client_connection,
    test_client_connection,
    discover_client_connection,
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
    get_dangerous_identities,
    # Phase 91: Sensitive Data Intelligence
    get_resource_classifications,
    classify_resource,
    declassify_resource,
    auto_classify_resources,
    get_sensitive_access_for_identity,
    get_resource_access_map,
    get_blast_radius_summary,
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
)
from app.scheduler import start_scheduler, stop_scheduler

logger = logging.getLogger(__name__)


def _validate_startup_secrets():
    """Fail fast if critical secrets are missing in production."""
    if os.getenv('FLASK_ENV') == 'development':
        return  # Skip in dev

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


def create_app():
    # Phase 4A: Structured logging
    configure_logging()

    # Phase 4A: Startup secrets validation
    _validate_startup_secrets()

    app = Flask(__name__)
    cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
    CORS(app, resources={r"/*": {"origins": [o.strip() for o in cors_origins]}})

    # Authentication middleware (Phase 31)
    app.before_request(auth_middleware)

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
        return response

    # Phase 5: Security headers on all responses
    app.after_request(add_security_headers)

    # Phase 4A/4B: Global error boundary with standardized error_code
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

    @app.errorhandler(429)
    def _too_many_requests(e):
        return jsonify({
            'error': 'Too many requests',
            'error_code': 'RATE_LIMITED',
            'request_id': getattr(g, 'request_id', None),
        }), 429

    @app.errorhandler(500)
    def _internal_error(e):
        return jsonify({
            'error': 'Internal server error',
            'error_code': 'INTERNAL_ERROR',
            'request_id': getattr(g, 'request_id', None),
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

    # Ensure tables exist at startup (run as admin user for DDL privileges)
    try:
        from app.database import Database as _DbInit
        _db_init = _DbInit()
        _db_init._ensure_identity_subscription_access_table()
        _db_init.backfill_microsoft_flag()
        _db_init.ensure_permission_plane_column()
        _db_init.ensure_deleted_at_column()
        _db_init._ensure_spn_exposure()
        _db_init._ensure_app_reg_exposure()
        _db_init._ensure_workload_telemetry_tables()
        # ICE tables (human_identities, identity_links, orphaned_privileged_findings)
        from app.database import _ensure_orphaned_findings_table
        _ensure_orphaned_findings_table(_db_init.conn)
        # Phase 6: Scan schedules + Stripe columns
        from app.database import _ensure_scan_schedules_table, _ensure_stripe_columns
        _ensure_scan_schedules_table(_db_init.conn)
        _ensure_stripe_columns(_db_init.conn)
        # Phase 3A: Entitlements tables
        _db_init._ensure_entitlements_tables()
        # Phase 6: Performance indexes for scale (500+ identities)
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
                _db_init.conn.rollback()
        _db_init.conn.commit()
        _perf_cursor.close()
        _db_init.close()
    except Exception as e:
        print(f"  ⚠️ Could not ensure tables/backfill: {e}")

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

    @app.get("/api/system/resource-integrity")
    @require_role('admin')
    def resource_integrity():
        return check_resource_integrity()

    # -----------------------
    # Authentication (Phase 31)
    # -----------------------
    @app.post("/api/auth/login")
    @rate_limit(max_requests=5, window_seconds=60)   # 5 attempts/min per IP
    def login():
        return auth_login()

    @app.post("/api/auth/refresh")
    @rate_limit(max_requests=10, window_seconds=60)   # 10 refreshes/min per IP
    def refresh():
        return auth_refresh()

    @app.post("/api/auth/logout")
    def logout():
        return auth_logout()

    @app.get("/api/auth/me")
    def me():
        return auth_me()

    @app.put("/api/auth/password")
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

    @app.get("/api/dashboard/summary")
    def dashboard_summary():
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
    # RBAC Hygiene (Phase 88)
    # -----------------------
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
    def client_connections_create():
        return create_client_connection()

    @app.put("/api/client/connections/<int:connection_id>")
    @require_role('admin', 'security_admin')
    def client_connections_update(connection_id):
        return update_client_connection(connection_id)

    @app.delete("/api/client/connections/<int:connection_id>")
    @require_role('admin')
    def client_connections_delete(connection_id):
        return delete_client_connection(connection_id)

    @app.post("/api/client/connections/test")
    @require_role('admin', 'security_admin')
    def client_connections_test():
        return test_client_connection()

    @app.post("/api/client/connections/<int:connection_id>/discover")
    @require_role('admin', 'security_admin')
    def client_connections_discover(connection_id):
        return discover_client_connection(connection_id)

    # -----------------------
    # Webhooks (Phase 28 - Admin only for writes)
    # -----------------------
    @app.get("/api/webhooks")
    def webhooks_list():
        return get_webhooks_list()

    @app.post("/api/webhooks")
    @require_role('admin')
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
    # Access Review Campaigns (Phase 36)
    # -----------------------
    @app.get("/api/access-reviews")
    def access_reviews_list():
        return get_access_reviews_list()

    @app.post("/api/access-reviews")
    @require_role('admin')
    def access_reviews_create():
        return create_access_review()

    @app.get("/api/access-reviews/<int:campaign_id>")
    def access_reviews_detail(campaign_id):
        return get_access_review_detail(campaign_id)

    @app.put("/api/access-reviews/<int:campaign_id>")
    @require_role('admin')
    def access_reviews_update(campaign_id):
        return update_access_review(campaign_id)

    @app.delete("/api/access-reviews/<int:campaign_id>")
    @require_role('admin')
    def access_reviews_delete(campaign_id):
        return delete_access_review(campaign_id)

    @app.patch("/api/access-reviews/<int:campaign_id>/reviews/<int:review_id>")
    @require_role('auditor', 'admin')
    def review_decision(campaign_id, review_id):
        return update_review_decision(campaign_id, review_id)

    @app.post("/api/access-reviews/<int:campaign_id>/reviews/bulk")
    @require_role('auditor', 'admin')
    def review_bulk_decision(campaign_id):
        return bulk_review_decisions(campaign_id)

    @app.get("/api/access-reviews/metrics")
    def access_reviews_metrics():
        return get_campaign_metrics_handler()

    @app.get("/api/access-reviews/<int:campaign_id>/audit-log")
    def access_reviews_audit_log(campaign_id):
        return get_campaign_audit_log_handler(campaign_id)

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

    # -----------------------
    # Azure Resource Discovery (Phase 52)
    # -----------------------
    @app.get("/api/resources/stats")
    @require_role('compliance', 'reader', 'admin')
    def resources_stats():
        return get_resource_stats()

    @app.get("/api/resources/expiry-summary")
    @require_role('compliance', 'reader', 'admin')
    def resources_expiry_summary():
        return get_resource_expiry_summary()

    @app.get("/api/resources/compliance-summary")
    @require_role('compliance', 'reader', 'admin')
    def resources_compliance_summary():
        return get_resource_compliance_summary()

    @app.get("/api/resources")
    @require_role('compliance', 'reader', 'admin')
    def resources_list():
        return get_resources()

    @app.get("/api/resources/<path:resource_id>")
    @require_role('compliance', 'reader', 'admin')
    def resources_detail(resource_id):
        return get_resource_detail(resource_id)

    @app.get("/api/resources/<path:resource_id>/access")
    @require_role('compliance', 'reader', 'admin')
    def resources_access(resource_id):
        return get_resource_access(resource_id)

    @app.get("/api/resources/<path:resource_id>/findings")
    @require_role('compliance', 'reader', 'admin')
    def resources_findings(resource_id):
        return get_resource_findings(resource_id)

    @app.get("/api/resources/<path:resource_id>/anomalies")
    @require_role('compliance', 'reader', 'admin')
    def resources_anomalies(resource_id):
        return get_resource_anomalies(resource_id)

    @app.get("/api/data-security/summary")
    @require_role('compliance', 'reader', 'admin')
    def data_security_summary():
        return get_data_security_summary()

    # -----------------------
    # Sensitive Data Intelligence (Phase 91)
    # -----------------------
    @app.get("/api/resources/classifications")
    @require_role('compliance', 'reader', 'admin')
    def resource_classifications():
        return get_resource_classifications()

    @app.post("/api/resources/<int:resource_id>/classify")
    @require_role('admin')
    def resource_classify(resource_id):
        return classify_resource(resource_id)

    @app.delete("/api/resources/<int:resource_id>/classify")
    @require_role('admin')
    def resource_declassify(resource_id):
        return declassify_resource(resource_id)

    @app.post("/api/resources/auto-classify")
    @require_role('admin')
    def resource_auto_classify():
        return auto_classify_resources()

    @app.get("/api/identities/<identity_id>/sensitive-access")
    @require_role('compliance', 'reader', 'admin')
    def identity_sensitive_access(identity_id):
        return get_sensitive_access_for_identity(identity_id)

    @app.get("/api/resources/<int:resource_id>/access-map")
    @require_role('compliance', 'reader', 'admin')
    def resource_access_map(resource_id):
        return get_resource_access_map(resource_id)

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

    @app.get("/api/system/launch-readiness")
    @require_portal_access()
    def system_launch_readiness():
        return validate_launch_readiness()

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
    @app.post("/api/tenants/<int:organization_id>/logo")
    @require_portal_role('superadmin', 'poweradmin')
    def tenant_logo_upload(organization_id):
        return upload_organization_logo(organization_id)

    @app.delete("/api/tenants/<int:organization_id>/logo")
    @require_portal_role('superadmin', 'poweradmin')
    def tenant_logo_delete(organization_id):
        return delete_organization_logo(organization_id)

    @app.post("/api/clients/<int:organization_id>/logo")
    @require_portal_role('superadmin', 'poweradmin')
    def client_logo_upload(organization_id):
        return upload_organization_logo(organization_id)

    @app.delete("/api/clients/<int:organization_id>/logo")
    @require_portal_role('superadmin', 'poweradmin')
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
    def copilot_chat_route():
        return copilot_chat()

    @app.get("/api/copilot/conversations")
    def copilot_conversations_route():
        return copilot_conversations_list()

    @app.get("/api/copilot/suggestions")
    def copilot_suggestions_route():
        return copilot_suggestions()

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

    @app.get("/api/subscriptions/distinct")
    def subscriptions_distinct():
        return get_subscriptions_distinct()

    @app.get("/api/identities/<path:identity_id>/subscriptions")
    def identity_subscriptions(identity_id):
        return get_identity_subscriptions(identity_id)

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
    # Start background scheduler (only in main process, not reloader)
    # -----------------------
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_scheduler()
        atexit.register(stop_scheduler)

    # Ensure default admin user and compliance frameworks on first startup
    from app.database import Database
    db = Database()
    try:
        db.ensure_default_admin()
        db.seed_compliance_frameworks()
        db.seed_compliance_root_causes()
        db._migrate_compliance_controls_v2()
        db._migrate_compliance_v3()
        db.deduplicate_auto_groups()
    finally:
        db.close()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
