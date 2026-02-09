from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime
import atexit

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
)
from app.scheduler import start_scheduler, stop_scheduler

def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

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
    # Historical Trends (Phase 20)
    # -----------------------
    @app.get("/api/trends")
    def trends():
        return get_trends()

    # -----------------------
    # Settings (Phase 15)
    # -----------------------
    @app.get("/api/settings")
    def app_settings():
        return get_app_settings()

    @app.post("/api/settings")
    def app_settings_save():
        return save_app_settings()

    @app.post("/api/settings/test-email")
    def settings_test_email():
        return test_email()

    # -----------------------
    # Activity Log (Phase 17)
    # -----------------------
    @app.get("/api/activity")
    def activity_log():
        return get_activity()

    # -----------------------
    # Start background scheduler (only in main process, not reloader)
    # -----------------------
    import os
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_scheduler()
        atexit.register(stop_scheduler)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
