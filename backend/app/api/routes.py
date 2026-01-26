from flask import Blueprint

from app.api.handlers import (
    health_check,
    get_stats,
    get_identities,
    get_identity_details,
    get_risks,
    get_discovery_runs,
    get_drift_report,
)

api_bp = Blueprint("api", __name__)

# Wire old handlers to new blueprint routes
api_bp.route("/health", methods=["GET"])(health_check)
api_bp.route("/stats", methods=["GET"])(get_stats)
api_bp.route("/identities", methods=["GET"])(get_identities)
api_bp.route("/identities/<identity_id>", methods=["GET"])(get_identity_details)
api_bp.route("/risks", methods=["GET"])(get_risks)
api_bp.route("/runs", methods=["GET"])(get_discovery_runs)
api_bp.route("/drift/<int:run_id>", methods=["GET"])(get_drift_report)
