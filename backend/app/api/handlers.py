"""
AuditGraph REST API - Handlers
Provides HTTP endpoint handlers used by the Flask blueprint routes.
"""

from datetime import datetime
from flask import jsonify, request
from dotenv import load_dotenv
import json

from app.database import Database
from app.engines.drift_detector import DriftDetector

# Load env when this module is imported (safe; no DB connection here)
# main.py also loads env, but this makes handlers safe for direct import/tests.
load_dotenv(".env.local")
load_dotenv()


def _db() -> Database:
    """
    Create a DB connection on-demand.
    Prevents DB connections at import time (which breaks tooling/tests).
    """
    return Database()


def _parse_risk_reasons(value):
    """
    risk_reasons in DB may be:
      - None
      - python list (if inserted that way)
      - JSON string '["a","b"]'
      - plain text string
    Normalize to list[str].
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (dict, int, float, bool)):
        return [str(value)]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        # try JSON list
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
                return [str(parsed)]
            except Exception:
                return [s]
        return [s]
    return [str(value)]


def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "service": "AuditGraph API",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


def get_identities():
    """
    Get all identities from the latest discovery run.

    Query params:
        risk_level: Filter by risk level (critical, high, medium, low, info)
        identity_type: Filter by type (user, service_principal, managed_identity, group, unknown)
        search: Filter by display_name contains
    """
    db = _db()
    risk_filter = request.args.get("risk_level")
    type_filter = request.args.get("identity_type")
    search = request.args.get("search")

    cursor = db.conn.cursor()

    cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
    latest_run = cursor.fetchone()[0]

    if not latest_run:
        return jsonify({"error": "No completed discovery runs found"}), 404

    # NOTE:
    # Your current schema does NOT have identity_roles table.
    # We'll return role_count=0 for now; role modeling can be added later.
    query = """
        SELECT
            i.identity_id,
            i.display_name,
            i.identity_type,
            i.risk_level,
            i.credential_status,
            i.credential_expiration,
            i.created_datetime,
            i.activity_status
        FROM identities i
        WHERE i.discovery_run_id = %s
    """
    params = [latest_run]

    if risk_filter:
        query += " AND i.risk_level = %s"
        params.append(risk_filter)

    if type_filter:
        query += " AND i.identity_type = %s"
        params.append(type_filter)

    if search:
        query += " AND LOWER(i.display_name) LIKE %s"
        params.append(f"%{search.lower()}%")

    query += """
        ORDER BY
            CASE i.risk_level
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            i.display_name
    """

    cursor.execute(query, params)
    rows = cursor.fetchall()

    identities = []
    for row in rows:
        identities.append(
            {
                "identity_id": row[0],
                "display_name": row[1],
                "identity_type": row[2],
                "risk_level": row[3],
                "credential_status": row[4] or "Unknown",
                "credential_expiration": row[5],
                "created_datetime": row[6],
                "activity_status": row[7] or "unknown",
                "role_count": 0,  # placeholder until identity_roles table exists
            }
        )

    return jsonify({"run_id": latest_run, "count": len(identities), "identities": identities})


def get_identity_details(identity_id: str):
    """Get detailed info for a single identity (roles, metadata) from latest run."""
    db = _db()
    cursor = db.conn.cursor()

    cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
    latest_run = cursor.fetchone()[0]

    if not latest_run:
        return jsonify({"error": "No completed discovery runs found"}), 404

    # NOTE: your identities table column is last_sign_in (not last_signin_datetime)
    cursor.execute(
        """
        SELECT
            id,
            identity_id,
            display_name,
            identity_type,
            risk_level,
            credential_status,
            credential_expiration,
            created_datetime,
            activity_status,
            last_sign_in,
            risk_reasons,
            object_id,
            app_id,
            enabled,
            is_microsoft_system,
            tags
        FROM identities
        WHERE discovery_run_id = %s AND identity_id = %s
        """,
        (latest_run, identity_id),
    )
    row = cursor.fetchone()

    if not row:
        return jsonify({"error": "Identity not found"}), 404

    # NOTE:
    # identity_roles table doesn't exist in current schema.
    # Return roles=[] for now.
    return jsonify(
        {
            "run_id": latest_run,
            "identity": {
                "identity_id": row[1],
                "display_name": row[2],
                "identity_type": row[3],
                "risk_level": row[4],
                "credential_status": row[5],
                "credential_expiration": row[6],
                "created_datetime": row[7],
                "activity_status": row[8],
                "last_sign_in": row[9],
                "risk_reasons": _parse_risk_reasons(row[10]),
                "object_id": row[11],
                "app_id": row[12],
                "enabled": row[13],
                "is_microsoft_system": row[14],
                "tags": row[15],
            },
            "roles": [],
        }
    )


def get_risks():
    """Return risk items from latest discovery run."""
    db = _db()
    cursor = db.conn.cursor()

    cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
    latest_run = cursor.fetchone()[0]

    if not latest_run:
        return jsonify({"error": "No completed discovery runs found"}), 404

    cursor.execute(
        """
        SELECT
            identity_id, display_name, identity_type, risk_level, risk_reasons
        FROM identities
        WHERE discovery_run_id = %s AND risk_level IN ('critical','high','medium')
        ORDER BY
            CASE risk_level
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                ELSE 4
            END,
            display_name
        """,
        (latest_run,),
    )
    rows = cursor.fetchall()

    return jsonify(
        {
            "run_id": latest_run,
            "count": len(rows),
            "risks": [
                {
                    "identity_id": r[0],
                    "display_name": r[1],
                    "identity_type": r[2],
                    "risk_level": r[3],
                    "risk_reason": _parse_risk_reasons(r[4]),  # keep key for frontend compatibility
                }
                for r in rows
            ],
        }
    )


def get_discovery_runs():
    """List discovery runs."""
    db = _db()
    cursor = db.conn.cursor()

    cursor.execute(
        """
        SELECT id, subscription_id, subscription_name, started_at, completed_at, status
        FROM discovery_runs
        ORDER BY id DESC
        LIMIT 50
        """
    )
    rows = cursor.fetchall()

    return jsonify(
        {
            "count": len(rows),
            "runs": [
                {
                    "id": r[0],
                    "subscription_id": r[1],
                    "subscription_name": r[2],
                    "started_at": r[3].isoformat() if r[3] else None,
                    "completed_at": r[4].isoformat() if r[4] else None,
                    "status": r[5],
                }
                for r in rows
            ],
        }
    )


def get_drift_report(run_id: int):
    """Compute drift report for a given run id."""
    db = _db()
    detector = DriftDetector(db)
    report = detector.generate_drift_report(run_id)
    return jsonify(report)


def get_stats():
    """Dashboard stats (latest run counts)."""
    db = _db()
    cursor = db.conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM discovery_runs")
    total_runs = cursor.fetchone()[0] or 0

    cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
    latest_run = cursor.fetchone()[0]

    latest_summary = None
    if latest_run:
        cursor.execute(
            """
            SELECT
                id,
                completed_at,
                (SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s) AS total_identities,
                (SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s AND risk_level='critical') AS critical_count,
                (SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s AND risk_level='high') AS high_count,
                (SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s AND risk_level='medium') AS medium_count
            FROM discovery_runs
            WHERE id = %s
            """,
            (latest_run, latest_run, latest_run, latest_run, latest_run),
        )

        r = cursor.fetchone()
        latest_summary = {
            "id": r[0],
            "completed_at": r[1].isoformat() if r[1] else None,
            "total_identities": int(r[2] or 0),
            "critical_count": int(r[3] or 0),
            "high_count": int(r[4] or 0),
            "medium_count": int(r[5] or 0),
        }

    return jsonify({"total_discovery_runs": int(total_runs), "latest_run": latest_summary})
