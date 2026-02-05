"""
AuditGraph API - Route Blueprint (optional)

This module provides a Blueprint-based route registration option.
If you use app.main (explicit routes), you may not need this file.
"""

from flask import Blueprint

from app.api.handlers import (
    health_check,
    get_identities,
    get_identity_details,
    get_risks,
    get_discovery_runs,
    get_drift_report,
    get_stats,
    trigger_discovery,
    get_scheduler_status,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Health
api_bp.get("/health")(health_check)

# Dashboard Summary
api_bp.get("/dashboard/summary")(get_stats)
api_bp.get("/summary")(get_stats)
api_bp.get("/stats")(get_stats)

# Identities
api_bp.get("/identities")(get_identities)
api_bp.get("/identities/<string:identity_id>")(get_identity_details)

# Risks
api_bp.get("/risks")(get_risks)

# Discovery Runs
api_bp.get("/runs")(get_discovery_runs)
api_bp.post("/runs/trigger")(trigger_discovery)
api_bp.get("/runs/<int:run_id>/drift")(get_drift_report)

# Scheduler
api_bp.get("/scheduler")(get_scheduler_status)
