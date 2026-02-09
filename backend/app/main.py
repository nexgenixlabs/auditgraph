from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime
import atexit

from app.api.auth import auth_middleware, require_role
from app.api.handlers import (
    get_stats,
    get_identities,
    get_identity_details,
    get_risks,
    get_identity_summary,
    get_dashboard_posture,
    get_dashboard_compliance,
    get_overview_insights,
    get_identity_graph_data,
    get_identity_pim_data,
    get_dashboard_ca_summary,
    get_discovery_runs,
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
    get_users_list,
    create_user_handler,
    update_user_handler,
    delete_user_handler,
)
from app.scheduler import start_scheduler, stop_scheduler

def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Authentication middleware (Phase 31)
    app.before_request(auth_middleware)

    # -----------------------
    # Health
    # -----------------------
    @app.get("/api/health")
    @app.get("/health")
    def health():
        return jsonify({
            "service": "AuditGraph API",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        })

    # -----------------------
    # Authentication (Phase 31)
    # -----------------------
    @app.post("/api/auth/login")
    def login():
        return auth_login()

    @app.post("/api/auth/refresh")
    def refresh():
        return auth_refresh()

    @app.post("/api/auth/logout")
    def logout():
        return auth_logout()

    @app.get("/api/auth/me")
    def me():
        return auth_me()

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
    # Dashboard posture (credential health, trends)
    # -----------------------
    @app.get("/api/dashboard/posture")
    def dashboard_posture():
        return get_dashboard_posture()

    # -----------------------
    # Dashboard compliance scorecard
    # -----------------------
    @app.get("/api/dashboard/compliance")
    def dashboard_compliance():
        return get_dashboard_compliance()

    # -----------------------
    # Overview insights (tier distribution, action items)
    # -----------------------
    @app.get("/api/overview/insights")
    def overview_insights():
        return get_overview_insights()

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
    # Identity Access Graph (trust, scope, exposure, visualization)
    # -----------------------
    @app.get("/api/identities/<identity_id>/graph-data")
    def identity_graph_data(identity_id):
        return get_identity_graph_data(identity_id)

    # -----------------------
    # Identity PIM data (eligible roles, activations, overuse)
    # -----------------------
    @app.get("/api/identities/<identity_id>/pim")
    def identity_pim_data(identity_id):
        return get_identity_pim_data(identity_id)

    # -----------------------
    # Conditional Access summary
    # -----------------------
    @app.get("/api/dashboard/conditional-access")
    def dashboard_ca():
        return get_dashboard_ca_summary()

    # -----------------------
    # Discovery Runs
    # -----------------------
    @app.get("/api/runs")
    def runs():
        return get_discovery_runs()

    @app.post("/api/runs/trigger")
    @require_role('admin')
    def runs_trigger():
        return trigger_discovery()

    @app.get("/api/runs/<int:run_id>/drift")
    def runs_drift(run_id):
        return get_drift_report(run_id)

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
    # Historical Trends (Phase 20)
    # -----------------------
    @app.get("/api/trends")
    def trends():
        return get_trends()

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
    def risk_rules_create():
        return create_risk_rule()

    @app.put("/api/risk-rules/<int:rule_id>")
    @require_role('admin')
    def risk_rules_update(rule_id):
        return update_risk_rule(rule_id)

    @app.delete("/api/risk-rules/<int:rule_id>")
    @require_role('admin')
    def risk_rules_delete(rule_id):
        return delete_risk_rule(rule_id)

    @app.post("/api/risk-rules/preview")
    @require_role('admin')
    def risk_rules_preview():
        return preview_risk_rule()

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
    # Start background scheduler (only in main process, not reloader)
    # -----------------------
    import os
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_scheduler()
        atexit.register(stop_scheduler)

    # Ensure default admin user exists on first startup
    from app.database import Database
    db = Database()
    try:
        db.ensure_default_admin()
    finally:
        db.close()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
