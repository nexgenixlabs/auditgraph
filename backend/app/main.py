from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime

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
)

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

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
