"""
AuditGraph REST API - Handlers

This module contains all HTTP endpoint handler functions for the AuditGraph API.
"""

from datetime import datetime
from flask import jsonify, request
from dotenv import load_dotenv
import json

from app.database import Database
from app.engines.drift_detector import DriftDetector

load_dotenv(".env.local")
load_dotenv()


def _db() -> Database:
    return Database()


def _parse_risk_reasons(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return [value]
    return []


def health_check():
    return jsonify(
        {
            "service": "AuditGraph API",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


def get_stats():
    """
    Dashboard summary statistics for latest completed discovery run.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                completed_at,
                total_identities,
                critical_count,
                high_count,
                medium_count
            FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC
            LIMIT 1
            """
        )
        row = cursor.fetchone()

        cursor.execute("SELECT COUNT(*) FROM discovery_runs")
        total_runs = cursor.fetchone()[0] or 0

        if not row:
            return jsonify({"latest_run": None, "total_discovery_runs": total_runs})

        latest = {
            "id": row[0],
            "completed_at": row[1].isoformat() if row[1] else None,
            "total_identities": row[2] or 0,
            "critical_count": row[3] or 0,
            "high_count": row[4] or 0,
            "medium_count": row[5] or 0,
        }
        return jsonify({"latest_run": latest, "total_discovery_runs": total_runs})

    finally:
        cursor.close()
        db.close()


def get_identities():
    """
    Get all identities from the latest discovery run.

    Query params:
        risk_level: Filter by risk level (critical, high, medium, low, info)
        identity_type: Filter by type (user, service_principal, managed_identity, group, unknown)
        identity_category: Filter by category (e.g., User Assigned Identity)
        search: Filter by display_name contains
    """
    db = _db()
    risk_filter = request.args.get("risk_level")
    type_filter = request.args.get("identity_type")
    category_filter = request.args.get("identity_category")  # ✅ FIXED
    search = request.args.get("search")

    cursor = db.conn.cursor()

    try:
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        latest_run = cursor.fetchone()[0]

        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        query = """
            SELECT
                i.identity_id,
                i.display_name,
                i.identity_type,
                COALESCE(i.identity_category, '') as identity_category,
                i.risk_level,
                i.credential_count,
                i.next_expiry,
                i.credential_risk,
                i.credential_status,
                i.credential_expiration,
                i.created_datetime,
                i.activity_status,
                (
                    SELECT COUNT(*)
                    FROM role_assignments ra
                    WHERE ra.identity_db_id = i.id
                ) + (
                    SELECT COUNT(*)
                    FROM entra_role_assignments era
                    WHERE era.identity_db_id = i.id
                ) as role_count
            FROM identities i
            WHERE i.discovery_run_id = %s
        """
        params = [latest_run]

        if risk_filter:
            query += " AND i.risk_level = %s"
            params.append(risk_filter)

        if category_filter:
            query += " AND COALESCE(i.identity_category, '') = %s"
            params.append(category_filter)
        elif type_filter:
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
                    "identity_category": row[3],
                    "risk_level": row[4] or "info",
                    "credential_count": int(row[5] or 0),
                    "next_expiry": row[6].isoformat() if row[6] else None,
                    "credential_risk": row[7] or "unknown",
                    "credential_status": row[8] or "Unknown",
                    "credential_expiration": row[9].isoformat() if row[9] else None,
                    "created_datetime": row[10].isoformat() if row[10] else None,
                    "activity_status": row[11] or "unknown",
                    "role_count": int(row[12] or 0),
                }
            )

        return jsonify({"count": len(identities), "identities": identities})

    finally:
        cursor.close()
        db.close()


def get_identity_details(identity_id: str):
    """
    Full identity detail view.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, identity_id, display_name, identity_type, identity_category, risk_level,
                   credential_count, credential_risk, credential_status, credential_expiration,
                   created_datetime, activity_status, risk_reasons
            FROM identities
            WHERE identity_id = %s
            ORDER BY discovery_run_id DESC
            LIMIT 1
            """,
            (identity_id,),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Identity not found"}), 404

        identity_db_id = row[0]
        identity = {
            "db_id": identity_db_id,
            "identity_id": row[1],
            "display_name": row[2],
            "identity_type": row[3],
            "identity_category": row[4],
            "risk_level": row[5],
            "credential_count": row[6] or 0,
            "credential_risk": row[7],
            "credential_status": row[8],
            "credential_expiration": row[9].isoformat() if row[9] else None,
            "created_datetime": row[10].isoformat() if row[10] else None,
            "activity_status": row[11],
            "risk_reasons": _parse_risk_reasons(row[12]),
        }

        # ✅ FIXED: clean try/except blocks
        try:
            graph_permissions = db.get_graph_permissions(identity_db_id)
        except Exception as e:
            print(f"Error getting graph permissions: {e}")
            graph_permissions = []

        try:
            app_roles = db.get_app_roles(identity_db_id)
        except Exception as e:
            print(f"Error getting app roles: {e}")
            app_roles = []

        roles = db.get_identity_roles_enriched(identity_db_id)

        return jsonify(
            {
                "identity": identity,
                "roles": roles,
                "graph_permissions": graph_permissions,
                "app_roles": app_roles,
            }
        )

    finally:
        cursor.close()
        db.close()


def get_risks():
    """
    Returns high-risk identities (critical/high) for latest run.
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status='completed'")
        latest_run = cursor.fetchone()[0]
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        cursor.execute(
            """
            SELECT identity_id, display_name, identity_type, identity_category, risk_level, risk_reasons
            FROM identities
            WHERE discovery_run_id = %s
              AND risk_level IN ('critical','high')
            ORDER BY risk_level, display_name
            """,
            (latest_run,),
        )
        rows = cursor.fetchall()

        items = []
        for r in rows:
            items.append(
                {
                    "identity_id": r[0],
                    "display_name": r[1],
                    "identity_type": r[2],
                    "identity_category": r[3],
                    "risk_level": r[4],
                    "risk_reasons": _parse_risk_reasons(r[5]),
                }
            )

        return jsonify({"count": len(items), "items": items})
    finally:
        cursor.close()
        db.close()


def get_discovery_runs():
    db = _db()
    cursor = db.conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, status, started_at, completed_at, total_identities, critical_count, high_count, medium_count
            FROM discovery_runs
            ORDER BY id DESC
            LIMIT 50
            """
        )
        rows = cursor.fetchall()

        runs = []
        for r in rows:
            runs.append(
                {
                    "id": r[0],
                    "status": r[1],
                    "started_at": r[2].isoformat() if r[2] else None,
                    "completed_at": r[3].isoformat() if r[3] else None,
                    "total_identities": r[4] or 0,
                    "critical_count": r[5] or 0,
                    "high_count": r[6] or 0,
                    "medium_count": r[7] or 0,
                }
            )
        return jsonify({"count": len(runs), "runs": runs})
    finally:
        cursor.close()
        db.close()


def get_drift_report(run_id: int):
    detector = DriftDetector()
    report = detector.get_drift_report(run_id)
    return jsonify(report)


def trigger_discovery():
    # Stub (keep existing behavior if you have it elsewhere)
    return jsonify({"status": "not_implemented"}), 501


def get_scheduler_status():
    return jsonify({"scheduler": "unknown"})
