"""
AuditGraph REST API - Handlers

This module contains all HTTP endpoint handler functions for the AuditGraph API.
"""

import os
import time
import bcrypt
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from flask import jsonify, request, g, Response
from dotenv import load_dotenv
import json

from psycopg2.extras import RealDictCursor
from app.database import Database
from app.engines.drift_detector import DriftDetector
from app.api.auth import generate_access_token, generate_refresh_token, hash_refresh_token, VALID_PORTAL_ROLES

load_dotenv(".env.local")
load_dotenv()


def _db() -> Database:
    return Database()


def _tenant_id():
    """Get tenant_id from current authenticated user context."""
    user = getattr(g, 'current_user', None)
    return user.get('tenant_id') if user else None


def _current_user_id():
    """Get the authenticated user's ID (never overridden)."""
    user = getattr(g, 'current_user', None)
    return user.get('id') if user else None


def _log(db, action_type, description, metadata=None):
    """Log activity with auto-injected user/tenant context."""
    user = getattr(g, 'current_user', None)
    uid = user.get('id') if user else None
    tid = user.get('tenant_id') if user else None
    db.log_activity(action_type, description, metadata, user_id=uid, tenant_id=tid)


def _latest_run_query(cursor, tenant_id=None):
    """Get latest completed discovery run ID, optionally scoped by tenant."""
    if tenant_id:
        cursor.execute("SELECT MAX(id) as run_id FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s", (tenant_id,))
    else:
        cursor.execute("SELECT MAX(id) as run_id FROM discovery_runs WHERE status = 'completed'")
    row = cursor.fetchone()
    if not row:
        return None
    # Support both RealDictCursor (dict) and regular cursor (tuple)
    if isinstance(row, dict):
        return row.get('run_id')
    return row[0]


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
        tid = _tenant_id()
        if tid:
            cursor.execute(
                """
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
                FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s
                ORDER BY id DESC LIMIT 1
                """, (tid,)
            )
        else:
            cursor.execute(
                """
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
                FROM discovery_runs WHERE status = 'completed'
                ORDER BY id DESC LIMIT 1
                """
            )
        row = cursor.fetchone()

        if tid:
            cursor.execute("SELECT COUNT(*) FROM discovery_runs WHERE tenant_id = %s", (tid,))
        else:
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

        # Previous run for trend comparison (Pillar 6)
        if tid:
            cursor.execute(
                """
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
                FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s
                ORDER BY id DESC LIMIT 1 OFFSET 1
                """, (tid,)
            )
        else:
            cursor.execute(
                """
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
                FROM discovery_runs WHERE status = 'completed'
                ORDER BY id DESC LIMIT 1 OFFSET 1
                """
            )
        prev_row = cursor.fetchone()
        previous_run = None
        if prev_row:
            previous_run = {
                "id": prev_row[0],
                "completed_at": prev_row[1].isoformat() if prev_row[1] else None,
                "total_identities": prev_row[2] or 0,
                "critical_count": prev_row[3] or 0,
                "high_count": prev_row[4] or 0,
                "medium_count": prev_row[5] or 0,
            }

        return jsonify({
            "latest_run": latest,
            "previous_run": previous_run,
            "total_discovery_runs": total_runs,
        })

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
        cloud: Filter by cloud provider (azure, aws, gcp)
        search: Filter by display_name contains
        limit: Max results to return (default: no limit)
        offset: Skip N results (default: 0)
    """
    db = _db()
    risk_filter = request.args.get("risk_level")
    type_filter = request.args.get("identity_type")
    category_filter = request.args.get("identity_category")
    cloud_filter = request.args.get("cloud")
    search = request.args.get("search")
    limit = request.args.get("limit", type=int)
    offset = request.args.get("offset", default=0, type=int)

    cursor = db.conn.cursor()

    try:
        latest_run = _latest_run_query(cursor, _tenant_id())

        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        query = _identity_list_select() + " WHERE i.discovery_run_id = %s"
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

        if cloud_filter:
            query += " AND COALESCE(i.cloud, 'azure') = %s"
            params.append(cloud_filter.lower())

        if search:
            query += " AND LOWER(i.display_name) LIKE %s"
            params.append(f"%{search.lower()}%")

        subscription_filter = request.args.get("subscription_id")
        if subscription_filter:
            # Check junction table for ANY access (not just primary/discovery subscription)
            query += """ AND (dr_sub.subscription_id = %s
                OR i.identity_id IN (
                    SELECT isa.identity_id FROM identity_subscription_access isa
                    WHERE isa.subscription_id = %s
                ))"""
            params.extend([subscription_filter, subscription_filter])

        # Get total count before pagination
        count_query = f"SELECT COUNT(*) FROM ({query}) sub"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

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

        if limit:
            query += " LIMIT %s OFFSET %s"
            params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        identities = [_map_identity_row(row) for row in rows]

        result = {"count": len(identities), "total": total_count, "identities": identities}
        if limit:
            result["limit"] = limit
            result["offset"] = offset
            result["has_more"] = (offset + len(identities)) < total_count
        return jsonify(result)

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
            SELECT i.id, i.identity_id, i.display_name, i.identity_type, i.identity_category, i.risk_level,
                   i.credential_count, i.credential_risk, i.credential_status, i.credential_expiration,
                   i.created_datetime, i.activity_status, i.risk_reasons,
                   -- Multi-cloud normalized fields
                   COALESCE(i.cloud, 'azure') as cloud,
                   i.identity_type_normalized,
                   i.canonical_name,
                   i.principal_id,
                   i.tenant_or_org_id,
                   COALESCE(i.source_normalized, 'entra') as source,
                   COALESCE(i.is_federated, false) as is_federated,
                   COALESCE(i.status, 'active') as status,
                   i.last_seen_auth,
                   -- Ownership fields
                   i.owner_display_name,
                   COALESCE(i.owner_count, 0) as owner_count,
                   -- Risk scoring fields
                   COALESCE(i.risk_score, 0) as risk_score,
                   COALESCE(i.api_permission_count, 0) as api_permission_count,
                   COALESCE(i.app_role_count, 0) as app_role_count,
                   i.ca_coverage_status,
                   COALESCE(i.ca_mfa_enforced, false) as ca_mfa_enforced,
                   -- Risk V2
                   i.risk_factors,
                   -- Evidence fields (Pillar 5)
                   i.discovery_run_id,
                   dr.completed_at as run_completed_at
            FROM identities i
            LEFT JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE i.identity_id = %s AND dr.tenant_id = %s
            ORDER BY i.discovery_run_id DESC
            LIMIT 1
            """,
            (identity_id, _tenant_id()),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Identity not found"}), 404

        identity_db_id = row[0]
        display_name = row[2] or ''
        identity_type = row[3] or ''
        normalized_category = _normalize_category_key(row[4] or '')

        identity = {
            "db_id": identity_db_id,
            "identity_id": row[1],
            "display_name": display_name,
            "identity_type": identity_type,
            "identity_category": normalized_category,
            "risk_level": row[5],
            "credential_count": row[6] or 0,
            "credential_risk": row[7],
            "credential_status": row[8],
            "credential_expiration": row[9].isoformat() if row[9] else None,
            "created_datetime": row[10].isoformat() if row[10] else None,
            "activity_status": row[11],
            "risk_reasons": _parse_risk_reasons(row[12]),
            # Multi-cloud normalized fields
            "cloud": row[13] or "azure",
            "normalized_identity_type": row[14],
            "canonical_name": row[15],
            "principal_id": row[16],
            "tenant_or_org_id": row[17],
            "source": row[18] or "entra",
            "is_federated": row[19] or False,
            "status": row[20] or "active",
            "last_seen_auth": row[21].isoformat() if row[21] else None,
            # Ownership fields
            "owner_display_name": row[22],
            "owner_count": int(row[23] or 0),
            # Risk scoring fields
            "risk_score": int(row[24] or 0),
            "api_permission_count": int(row[25] or 0),
            "app_role_count": int(row[26] or 0),
            "ca_coverage_status": row[27] or None,
            "ca_mfa_enforced": bool(row[28]) if row[28] is not None else False,
            "risk_factors": row[29] if row[29] else [],
            "discovery_run_id": row[30],
        }

        run_completed_at = row[31].isoformat() if row[31] else None
        current_run_id = row[30]

        # Trend comparison: get this identity's state from the previous run (Pillar 6)
        trend = None
        if current_run_id:
            try:
                tid = _tenant_id()
                if tid:
                    cursor.execute(
                        """
                        SELECT risk_level, risk_score, credential_count, credential_expiration
                        FROM identities
                        WHERE identity_id = %s
                          AND discovery_run_id = (
                              SELECT MAX(id) FROM discovery_runs
                              WHERE status = 'completed' AND id < %s AND tenant_id = %s
                          )
                        LIMIT 1
                        """,
                        (identity_id, current_run_id, tid),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT risk_level, risk_score, credential_count, credential_expiration
                        FROM identities
                        WHERE identity_id = %s
                          AND discovery_run_id = (
                              SELECT MAX(id) FROM discovery_runs
                              WHERE status = 'completed' AND id < %s AND tenant_id = %s
                          )
                        LIMIT 1
                        """,
                        (identity_id, current_run_id, _tenant_id()),
                    )
                prev = cursor.fetchone()
                if prev:
                    trend = {
                        "previous_risk_level": prev[0],
                        "previous_risk_score": int(prev[1] or 0),
                        "risk_direction": (
                            "worsened" if (identity["risk_score"] or 0) > (prev[1] or 0)
                            else "improved" if (identity["risk_score"] or 0) < (prev[1] or 0)
                            else "unchanged"
                        ),
                        "is_new": False,
                    }
                else:
                    # Identity not found in previous run → it's new
                    trend = {
                        "previous_risk_level": None,
                        "previous_risk_score": None,
                        "risk_direction": "new",
                        "is_new": True,
                    }
            except Exception:
                pass

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

        try:
            owners = db.get_ownership(identity_db_id)
        except Exception as e:
            print(f"Error getting owners: {e}")
            owners = []

        roles = db.get_identity_roles_enriched(identity_db_id)

        # Gather compliance and attack intelligence for each role
        role_intelligence = []
        seen_roles = set()
        for role in roles:
            rn = role.get("role_name", "")
            if rn in seen_roles:
                continue
            seen_roles.add(rn)
            try:
                attacks = db.get_role_attack_patterns(rn)
            except Exception:
                attacks = []
            try:
                hipaa = db.get_role_hipaa_violations(rn)
            except Exception:
                hipaa = []
            if attacks or hipaa:
                role_intelligence.append({
                    "role_name": rn,
                    "attack_patterns": attacks,
                    "hipaa_violations": hipaa,
                })

        return jsonify(
            {
                "identity": identity,
                "roles": roles,
                "graph_permissions": graph_permissions,
                "app_roles": app_roles,
                "owners": owners,
                "role_intelligence": role_intelligence,
                "trend": trend,
                "evidence": {
                    "run_id": identity.get("discovery_run_id"),
                    "collected_at": run_completed_at,
                    "sources": {
                        "identity": "Microsoft Graph API /servicePrincipals or /users",
                        "roles_azure": "Azure Resource Manager /roleAssignments",
                        "roles_entra": "Microsoft Graph API /roleManagement/directory",
                        "permissions": "Microsoft Graph API /servicePrincipals/{id}/appRoleAssignments",
                        "credentials": "Microsoft Graph API /applications/{id}/passwordCredentials + keyCredentials",
                        "owners": "Microsoft Graph API /servicePrincipals/{id}/owners",
                        "pim": "Microsoft Graph API /roleManagement/directory/roleEligibilityScheduleInstances",
                        "ca_policies": "Microsoft Graph API /identity/conditionalAccess/policies",
                    },
                },
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
        latest_run = _latest_run_query(cursor, _tenant_id())
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
            display_name = r[1] or ''
            identity_type = r[2] or ''
            normalized_category = _normalize_category_key(r[3] or '')

            items.append(
                {
                    "identity_id": r[0],
                    "display_name": display_name,
                    "identity_type": identity_type,
                    "identity_category": normalized_category,
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
            WHERE tenant_id = %s
            ORDER BY id DESC
            LIMIT 50
            """,
            (_tenant_id(),),
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
    """Get drift report for a specific discovery run."""
    db = _db()
    try:
        # Try persisted report first
        report = db.get_drift_report(run_id)
        if report:
            report['created_at'] = report['created_at'].isoformat() if report.get('created_at') else None
            _log(db,'drift_reviewed', f'Drift report reviewed for run #{run_id}', {
                'run_id': run_id,
                'total_changes': report.get('total_changes', 0),
            })
            return jsonify(report)

        # Fall back to live computation: find the previous run (tenant-scoped)
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE status = 'completed' AND id < %s AND tenant_id = %s
            ORDER BY id DESC
            LIMIT 1
        """, (run_id, _tenant_id()))
        prev_row = cursor.fetchone()
        cursor.close()

        if not prev_row:
            return jsonify({"error": "No previous run to compare against"}), 404

        previous_run_id = prev_row[0]
        detector = DriftDetector(db)
        changes = detector.compare_runs(run_id, previous_run_id)

        # Persist for future use
        db.save_drift_report(run_id, previous_run_id, changes)

        return jsonify({
            "current_run_id": run_id,
            "previous_run_id": previous_run_id,
            "new_identities_count": len(changes.get('new_identities', [])),
            "removed_identities_count": len(changes.get('removed_identities', [])),
            "permission_changes_count": len(changes.get('permission_changes', [])),
            "risk_changes_count": len(changes.get('risk_changes', [])),
            "credential_changes_count": len(changes.get('credential_changes', [])),
            "total_changes": sum(len(v) for v in changes.values()),
            "changes": changes,
        })
    finally:
        db.close()


def get_latest_drift():
    """Get the most recent drift report summary for the dashboard widget."""
    db = _db()
    try:
        report = db.get_latest_drift_report()
        if not report:
            return jsonify({"has_drift_data": False})

        report['created_at'] = report['created_at'].isoformat() if report.get('created_at') else None
        report['has_drift_data'] = True
        return jsonify(report)
    finally:
        db.close()


def get_drift_history():
    """Get drift report history for change timeline."""
    db = _db()
    try:
        limit = request.args.get('limit', 20, type=int)
        reports = db.get_drift_history(limit=limit)

        for r in reports:
            r['created_at'] = r['created_at'].isoformat() if r.get('created_at') else None
            r['run_completed_at'] = r['run_completed_at'].isoformat() if r.get('run_completed_at') else None

        return jsonify({"count": len(reports), "reports": reports})
    finally:
        db.close()


def get_trends():
    """
    Historical trend data: risk counts per discovery run for the last N completed runs.
    Used by frontend sparklines to visualize risk level trends over time.

    Query params:
        limit: Number of runs to return (default 10, max 30)
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        limit = request.args.get('limit', 10, type=int)
        limit = min(max(limit, 2), 30)

        cursor.execute(
            """
            SELECT
                dr.id,
                dr.completed_at,
                dr.total_identities,
                dr.critical_count,
                dr.high_count,
                dr.medium_count,
                dr.low_count,
                COALESCE((
                    SELECT COUNT(*)
                    FROM identities i
                    WHERE i.discovery_run_id = dr.id
                      AND i.activity_status IN ('stale', 'inactive')
                ), 0) as dormant_count,
                CASE WHEN COALESCE(dr.total_identities, 0) > 0
                    THEN ROUND(
                        (COALESCE(dr.total_identities, 0)
                         - COALESCE(dr.critical_count, 0)
                         - COALESCE(dr.high_count, 0)
                         - COALESCE(dr.medium_count, 0)
                        )::numeric / dr.total_identities * 100, 1
                    )
                    ELSE 0
                END as posture_score,
                COALESCE((
                    SELECT ROUND(AVG(COALESCE(i.risk_score, 0))::numeric, 1)
                    FROM identities i
                    WHERE i.discovery_run_id = dr.id
                ), 0) as avg_risk_score
            FROM discovery_runs dr
            WHERE dr.status = 'completed' AND dr.tenant_id = %s
            ORDER BY dr.id DESC
            LIMIT %s
            """,
            (_tenant_id(), limit),
        )
        rows = cursor.fetchall()

        # Reverse to chronological order (oldest first) for sparkline rendering
        runs = []
        for r in reversed(rows):
            runs.append({
                "run_id": r[0],
                "date": r[1].isoformat() if r[1] else None,
                "total": r[2] or 0,
                "critical": r[3] or 0,
                "high": r[4] or 0,
                "medium": r[5] or 0,
                "low": r[6] or 0,
                "dormant": r[7] or 0,
                "posture_score": float(r[8] or 0),
                "avg_risk_score": float(r[9] or 0),
            })

        return jsonify({
            "count": len(runs),
            "runs": runs,
        })

    finally:
        cursor.close()
        db.close()


def get_trends_velocity():
    """GET /api/trends/velocity — risk level inflow/outflow between consecutive runs."""
    db = _db()
    cursor = db.conn.cursor()
    try:
        limit = min(max(request.args.get('limit', 10, type=int), 2), 20)

        cursor.execute("""
            SELECT id, completed_at FROM discovery_runs
            WHERE status = 'completed' AND tenant_id = %s
            ORDER BY id DESC LIMIT %s
        """, (_tenant_id(), limit))
        runs = list(reversed(cursor.fetchall()))

        if len(runs) < 2:
            return jsonify({"transitions": [], "retention": {}})

        LEVELS = ['critical', 'high', 'medium', 'low']
        transitions = []

        for i in range(1, len(runs)):
            prev_run_id = runs[i - 1][0]
            curr_run_id = runs[i][0]
            curr_date = runs[i][1]

            cursor.execute("""
                SELECT
                    COALESCE(prev.risk_level, '__new__') as from_level,
                    COALESCE(curr.risk_level, '__removed__') as to_level,
                    COUNT(*) as cnt
                FROM (
                    SELECT identity_id, risk_level
                    FROM identities WHERE discovery_run_id = %s
                ) prev
                FULL OUTER JOIN (
                    SELECT identity_id, risk_level
                    FROM identities WHERE discovery_run_id = %s
                ) curr ON prev.identity_id = curr.identity_id
                WHERE COALESCE(prev.risk_level, '') != COALESCE(curr.risk_level, '')
                GROUP BY from_level, to_level
            """, (prev_run_id, curr_run_id))

            inflow = {l: 0 for l in LEVELS}
            outflow = {l: 0 for l in LEVELS}

            for from_lvl, to_lvl, cnt in cursor.fetchall():
                if to_lvl in LEVELS:
                    inflow[to_lvl] += cnt
                if from_lvl in LEVELS:
                    outflow[from_lvl] += cnt

            net = {l: inflow[l] - outflow[l] for l in LEVELS}

            transitions.append({
                "run_id": curr_run_id,
                "date": curr_date.isoformat() if curr_date else None,
                "prev_run_id": prev_run_id,
                "inflow": inflow,
                "outflow": outflow,
                "net": net,
            })

        # Retention rates for latest transition
        retention = {}
        if transitions:
            latest = transitions[-1]
            for level in ['critical', 'high']:
                cursor.execute("""
                    SELECT
                        COUNT(*) FILTER (WHERE curr.risk_level = %s) as retained,
                        COUNT(*) as total
                    FROM identities prev
                    JOIN identities curr
                        ON curr.identity_id = prev.identity_id
                        AND curr.discovery_run_id = %s
                    WHERE prev.discovery_run_id = %s
                      AND prev.risk_level = %s
                """, (level, latest["run_id"], latest["prev_run_id"], level))
                row = cursor.fetchone()
                total = row[1] or 0
                retained = row[0] or 0
                retention[level] = {
                    "retained": retained,
                    "total": total,
                    "rate": round(retained / total * 100, 1) if total > 0 else 0,
                }

        return jsonify({"transitions": transitions, "retention": retention})
    finally:
        cursor.close()
        db.close()


def get_identity_risk_history(identity_id):
    """GET /api/identities/<id>/risk-history — compact risk score trajectory for sparkline."""
    db = _db()
    cursor = db.conn.cursor()
    try:
        limit = min(max(request.args.get('limit', 20, type=int), 2), 50)

        cursor.execute("""
            SELECT i.discovery_run_id, dr.completed_at,
                   COALESCE(i.risk_score, 0), i.risk_level
            FROM identities i
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE i.identity_id = %s AND dr.status = 'completed'
            ORDER BY dr.id DESC
            LIMIT %s
        """, (identity_id, limit))
        rows = cursor.fetchall()

        if not rows:
            return jsonify({"identity_id": identity_id, "points": []})

        points = []
        for r in reversed(rows):
            points.append({
                "run_id": r[0],
                "date": r[1].isoformat() if r[1] else None,
                "risk_score": int(r[2]),
                "risk_level": r[3] or "info",
            })

        return jsonify({"identity_id": identity_id, "points": points})
    finally:
        cursor.close()
        db.close()


def get_batch_risk_history():
    """POST /api/identities/risk-history/batch — batch risk score histories for sparklines."""
    db = _db()
    cursor = db.conn.cursor()
    try:
        body = request.get_json(silent=True) or {}
        identity_ids = body.get("identity_ids", [])
        run_limit = min(body.get("limit", 10), 20)

        if not identity_ids or len(identity_ids) > 200:
            return jsonify({"error": "Provide 1-200 identity_ids"}), 400

        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE status = 'completed' AND tenant_id = %s
            ORDER BY id DESC LIMIT %s
        """, (_tenant_id(), run_limit))
        run_ids = [r[0] for r in cursor.fetchall()]

        if not run_ids:
            return jsonify({"histories": {}})

        cursor.execute("""
            SELECT identity_id, discovery_run_id, COALESCE(risk_score, 0)
            FROM identities
            WHERE identity_id = ANY(%s)
              AND discovery_run_id = ANY(%s)
            ORDER BY identity_id, discovery_run_id ASC
        """, (identity_ids, run_ids))

        histories = {}
        for iid, rid, score in cursor.fetchall():
            if iid not in histories:
                histories[iid] = []
            histories[iid].append(int(score))

        return jsonify({"histories": histories})
    finally:
        cursor.close()
        db.close()


def get_app_settings():
    """Return all settings plus connection/scheduler status."""
    db = _db()
    try:
        settings = db.get_settings(tenant_id=_tenant_id())

        # Backfill Azure credentials from env vars if DB settings are empty
        env_creds = {
            'azure_tenant_id': os.getenv('AZURE_TENANT_ID', ''),
            'azure_client_id': os.getenv('AZURE_CLIENT_ID', ''),
            'azure_client_secret': os.getenv('AZURE_CLIENT_SECRET', ''),
        }
        for key, env_val in env_creds.items():
            if not settings.get(key) and env_val:
                settings[key] = env_val

        # Mask secrets for API response
        if settings.get('azure_client_secret'):
            settings['azure_client_secret'] = '********'
        if settings.get('copilot_api_key'):
            settings['copilot_api_key'] = '********'

        # Check Azure credential configuration (env vars OR DB settings)
        azure_configured = all([
            settings.get('azure_tenant_id'),
            settings.get('azure_client_id'),
            settings.get('azure_client_secret'),
        ])

        # Check scheduler state
        from app.scheduler import get_next_run_time, get_next_report_time, scheduler as _sched
        next_run = get_next_run_time()
        next_report = get_next_report_time()

        return jsonify({
            "settings": settings,
            "status": {
                "azure_configured": azure_configured,
                "email_configured": azure_configured,
                "scheduler_running": _sched is not None,
                "next_run": next_run.isoformat() if next_run else None,
                "next_report": next_report.isoformat() if next_report else None,
            }
        })
    finally:
        db.close()


def save_app_settings():
    """Update settings from JSON body. Validates known keys."""
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Expected JSON object"}), 400

    VALID_KEYS = {
        'org_name', 'theme', 'timezone',
        'discovery_interval_hours', 'email_enabled', 'email_to',
        'notify_new_identities', 'notify_removed_identities',
        'notify_permission_changes', 'notify_risk_changes', 'notify_credential_changes',
        'notify_weekly_digest',
        'report_schedule_enabled', 'report_schedule_frequency', 'report_email_to',
        'azure_tenant_id', 'azure_client_id', 'azure_client_secret',
        'aws_access_key_id', 'aws_secret_access_key', 'aws_region',
        'gcp_project_id', 'gcp_service_account_json',
        'onboarding_completed',
        'retention_discovery_days', 'retention_drift_days',
        'retention_activity_days', 'retention_anomalies_days',
        'retention_soar_days', 'retention_notifications_days',
        'retention_enabled',
        'copilot_api_key',
    }
    BOOLEAN_KEYS = {
        'email_enabled', 'notify_new_identities', 'notify_removed_identities',
        'notify_permission_changes', 'notify_risk_changes', 'notify_credential_changes',
        'notify_weekly_digest',
        'report_schedule_enabled', 'onboarding_completed',
        'retention_enabled',
    }

    # Filter to valid keys only
    updates = {}
    errors = []
    for key, value in data.items():
        if key not in VALID_KEYS:
            errors.append(f"Unknown setting: {key}")
            continue

        value = str(value).strip()

        # Skip masked secrets — don't overwrite real secret with mask
        if key in ('azure_client_secret', 'aws_secret_access_key', 'gcp_service_account_json', 'copilot_api_key') and value == '********':
            continue

        if key == 'discovery_interval_hours':
            if value not in ('6', '12', '24'):
                errors.append("discovery_interval_hours must be 6, 12, or 24")
                continue

        if key in BOOLEAN_KEYS:
            if value.lower() not in ('true', 'false'):
                errors.append(f"{key} must be true or false")
                continue
            value = value.lower()

        if key == 'report_schedule_frequency':
            if value not in ('weekly', 'monthly'):
                errors.append("report_schedule_frequency must be weekly or monthly")
                continue

        if key == 'theme':
            if value not in ('light', 'dark', 'system'):
                errors.append("theme must be light, dark, or system")
                continue

        if key in ('email_to', 'report_email_to') and value:
            if '@' not in value:
                errors.append(f"{key} must be a valid email address")
                continue

        if key.startswith('retention_') and key.endswith('_days'):
            try:
                days_val = int(value)
                if days_val < 7 or days_val > 3650:
                    errors.append(f"{key} must be between 7 and 3650 days")
                    continue
            except ValueError:
                errors.append(f"{key} must be a number")
                continue

        updates[key] = value

    if errors:
        return jsonify({"error": "; ".join(errors)}), 400

    db = _db()
    try:
        tid = _tenant_id()
        db.save_settings(updates, tenant_id=tid)

        # Sync org_name to tenant name so it propagates to JWT, TopBar, admin tables
        if 'org_name' in updates and tid:
            new_name = updates['org_name'].strip()
            if new_name:
                db.update_tenant(tid, name=new_name)

        settings = db.get_settings(tenant_id=tid)
        _log(db,'settings_updated', f'Settings updated: {", ".join(updates.keys())}', {
            'updated_keys': list(updates.keys()),
            'values': updates,
        })
        return jsonify({"settings": settings, "updated": list(updates.keys())})
    finally:
        db.close()


def test_email():
    """Send a test email to verify email configuration."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}
        to_email = data.get('email_to', '').strip() or None

        from app.services.email_service import EmailService
        email_service = EmailService()

        if not email_service.credentials_configured:
            return jsonify({"error": "Azure credentials not configured. Email service requires AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET."}), 400

        success = email_service.send_test_email(to_email_override=to_email)

        if success:
            _log(db,'test_email_sent', f'Test email sent to {to_email or "default recipient"}')
            return jsonify({"status": "sent", "message": "Test email sent successfully"})
        else:
            _log(db,'test_email_failed', 'Test email failed to send')
            return jsonify({"error": "Failed to send test email. Check server logs for details."}), 500
    finally:
        db.close()


def trigger_discovery():
    """Trigger a manual discovery run in a background thread."""
    import threading
    from app.scheduler import trigger_manual_discovery

    def _run():
        try:
            trigger_manual_discovery()
        except Exception as e:
            logging.getLogger(__name__).error(f"Manual discovery failed: {e}")

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    db = _db()
    try:
        _log(db,'discovery_triggered', 'Manual discovery run triggered')
    finally:
        db.close()

    return jsonify({"status": "started", "message": "Discovery run triggered. Check /api/runs for progress."}), 202


def get_scheduler_status():
    """Return current scheduler status and next run time."""
    from app.scheduler import get_next_run_time, scheduler as _sched

    next_run = get_next_run_time()
    is_running = _sched is not None

    return jsonify({
        "scheduler": "running" if is_running else "stopped",
        "next_run": next_run.isoformat() if next_run else None,
        "interval_hours": int(os.getenv('DISCOVERY_INTERVAL_HOURS', '12')),
    })


def get_identity_remediations(identity_id: str):
    """
    Get matched remediation playbooks for a specific identity.
    Matches the identity's risk factors against the playbook library.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        # Get identity data
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.risk_level,
                   i.risk_reasons, i.activity_status, i.credential_status,
                   i.credential_risk, COALESCE(i.owner_count, 0) as owner_count,
                   i.ca_coverage_status
            FROM identities i
            WHERE i.identity_id = %s
            ORDER BY i.discovery_run_id DESC
            LIMIT 1
        """, (identity_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Identity not found"}), 404

        identity_db_id = row[0]

        # Get roles
        cursor.execute("""
            SELECT role_name FROM role_assignments WHERE identity_db_id = %s
            UNION ALL
            SELECT role_name FROM entra_role_assignments WHERE identity_db_id = %s
        """, (identity_db_id, identity_db_id))
        roles = [{"role_name": r[0]} for r in cursor.fetchall()]

        identity_data = {
            "risk_reasons": _parse_risk_reasons(row[4]),
            "roles": roles,
            "activity_status": row[5],
            "credential_status": row[6],
            "credential_risk": row[7],
            "owner_count": row[8],
            "ca_coverage_status": row[9],
        }

        result = db.get_identity_remediations(identity_db_id, identity_data)

        return jsonify({
            "identity_id": identity_id,
            "display_name": row[2],
            "risk_level": row[3],
            **result,
        })

    finally:
        cursor.close()
        db.close()


def get_report_data():
    """
    Get comprehensive JSON data for PDF report generation.
    Includes stats, compliance, top risks, and remediation summary.
    """
    db = _db()
    try:
        data = db.get_report_data()
        if data is None:
            return jsonify({"error": "No completed discovery runs found"}), 404
        _log(db,'report_generated', 'Security report data generated', {
            'run_id': data.get('run_id'),
            'total_identities': data.get('stats', {}).get('total_identities', 0),
        })
        return jsonify(data)
    finally:
        db.close()


def get_activity():
    """Get activity log entries with optional filtering, tenant-scoped."""
    db = _db()
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        action_type = request.args.get('type')

        limit = min(limit, 200)

        # Phase 46: Tenant-scoped activity log
        current_user = getattr(g, 'current_user', None)
        is_super = current_user.get('is_superadmin') if current_user else False
        tid = _tenant_id()

        # Superadmins with no override see all; with override see that tenant
        if is_super and not (current_user or {}).get('tenant_id_override'):
            filter_tid = None
        else:
            filter_tid = tid

        entries = db.get_activity_log(limit=limit, offset=offset, action_type=action_type, tenant_id=filter_tid)

        # Exclude admin portal events from client-facing activity log
        if filter_tid is not None:
            entries = [e for e in entries if e.get('action_type') not in ('admin_login', 'admin_logout')]

        for entry in entries:
            entry['created_at'] = entry['created_at'].isoformat() if entry.get('created_at') else None

        return jsonify({
            "count": len(entries),
            "limit": limit,
            "offset": offset,
            "entries": entries,
        })
    except Exception as e:
        return jsonify({"error": str(e), "entries": []}), 500
    finally:
        db.close()


# ============================================================
# Phase 28: Webhook & Alert Integration
# ============================================================

VALID_WEBHOOK_EVENTS = [
    'discovery_completed', 'risk_escalation', 'new_identities',
    'removed_identities', 'permission_changes', 'credential_changes',
    'drift_detected',
]


def get_webhooks_list():
    """GET /api/webhooks — list all webhooks with delivery stats."""
    db = _db()
    try:
        webhooks = db.get_webhooks()
        return jsonify({"webhooks": webhooks, "count": len(webhooks)})
    finally:
        db.close()


def create_webhook():
    """POST /api/webhooks — create a new webhook."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}

        name = str(data.get('name', '')).strip()
        url = str(data.get('url', '')).strip()
        secret = str(data.get('secret', '')).strip() if data.get('secret') else None
        event_types = data.get('event_types', [])
        headers = data.get('headers')

        # Validation
        errors = []
        if not name:
            errors.append("name is required")
        if len(name) > 255:
            errors.append("name must be 255 characters or less")
        if not url:
            errors.append("url is required")
        elif not url.startswith('https://'):
            errors.append("url must start with https://")
        if not event_types or not isinstance(event_types, list):
            errors.append("event_types must be a non-empty list")
        else:
            invalid = [e for e in event_types if e not in VALID_WEBHOOK_EVENTS]
            if invalid:
                errors.append(f"Invalid event types: {', '.join(invalid)}")
        if headers and not isinstance(headers, dict):
            errors.append("headers must be an object")

        # Max 10 webhooks
        existing = db.get_webhooks()
        if len(existing) >= 10:
            errors.append("Maximum of 10 webhooks allowed")

        if errors:
            return jsonify({"error": "; ".join(errors)}), 400

        webhook = db.create_webhook(name, url, secret, event_types, headers)
        _log(db,'webhook_created',
            f'Webhook "{name}" created for events: {", ".join(event_types)}',
            {'webhook_id': webhook['id'], 'url': url, 'event_types': event_types})

        return jsonify(webhook), 201
    finally:
        db.close()


def update_webhook(webhook_id):
    """PUT /api/webhooks/<id> — update a webhook."""
    db = _db()
    try:
        existing = db.get_webhook(webhook_id)
        if not existing:
            return jsonify({"error": "Webhook not found"}), 404

        data = request.get_json(silent=True) or {}
        updates = {}

        if 'name' in data:
            name = str(data['name']).strip()
            if not name:
                return jsonify({"error": "name cannot be empty"}), 400
            updates['name'] = name

        if 'url' in data:
            url = str(data['url']).strip()
            if not url.startswith('https://'):
                return jsonify({"error": "url must start with https://"}), 400
            updates['url'] = url

        if 'secret' in data:
            updates['secret'] = str(data['secret']).strip() if data['secret'] else None

        if 'event_types' in data:
            event_types = data['event_types']
            if not event_types or not isinstance(event_types, list):
                return jsonify({"error": "event_types must be a non-empty list"}), 400
            invalid = [e for e in event_types if e not in VALID_WEBHOOK_EVENTS]
            if invalid:
                return jsonify({"error": f"Invalid event types: {', '.join(invalid)}"}), 400
            updates['event_types'] = event_types

        if 'headers' in data:
            updates['headers'] = data['headers']

        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])

        if not updates:
            return jsonify(existing)

        webhook = db.update_webhook(webhook_id, **updates)
        _log(db,'webhook_updated',
            f'Webhook "{webhook["name"]}" updated: {", ".join(updates.keys())}',
            {'webhook_id': webhook_id, 'updated_fields': list(updates.keys())})

        return jsonify(webhook)
    finally:
        db.close()


def delete_webhook(webhook_id):
    """DELETE /api/webhooks/<id> — delete a webhook."""
    db = _db()
    try:
        existing = db.get_webhook(webhook_id)
        if not existing:
            return jsonify({"error": "Webhook not found"}), 404

        db.delete_webhook(webhook_id)
        _log(db,'webhook_deleted',
            f'Webhook "{existing["name"]}" deleted',
            {'webhook_id': webhook_id, 'url': existing['url']})

        return jsonify({"status": "deleted", "id": webhook_id})
    finally:
        db.close()


def test_webhook_endpoint(webhook_id):
    """POST /api/webhooks/<id>/test — send test payload."""
    db = _db()
    try:
        existing = db.get_webhook(webhook_id)
        if not existing:
            return jsonify({"error": "Webhook not found"}), 404

        from app.services.webhook_service import WebhookService
        service = WebhookService()
        result = service.test_webhook(webhook_id)

        _log(db,'webhook_tested',
            f'Test delivery to webhook "{existing["name"]}": {"success" if result["success"] else "failed"}',
            {'webhook_id': webhook_id, 'success': result['success']})

        if result['success']:
            return jsonify({"status": "delivered", "http_status": result.get('http_status')})
        else:
            return jsonify({"status": "failed", "error": result.get('error'), "http_status": result.get('http_status')}), 502
    finally:
        db.close()


def get_webhook_deliveries(webhook_id):
    """GET /api/webhooks/<id>/deliveries — delivery history."""
    db = _db()
    try:
        existing = db.get_webhook(webhook_id)
        if not existing:
            return jsonify({"error": "Webhook not found"}), 404

        limit = request.args.get('limit', 20, type=int)
        limit = min(limit, 100)
        deliveries = db.get_webhook_deliveries(webhook_id, limit=limit)

        return jsonify({"deliveries": deliveries, "count": len(deliveries)})
    finally:
        db.close()


# ============================================================
# Phase 29: Custom Risk Rule Engine
# ============================================================

VALID_RULE_FIELDS = {
    'identity_category', 'identity_type', 'display_name', 'enabled',
    'activity_status', 'role_count', 'api_permission_count',
    'has_write_permissions', 'has_entra_role', 'has_rbac_role',
    'risk_score', 'credential_status', 'app_role_count',
}

VALID_RULE_OPS = {'eq', 'neq', 'gt', 'lt', 'gte', 'lte', 'in', 'contains'}

VALID_ACTION_TYPES = {'adjust_points', 'force_level'}

VALID_FORCE_LEVELS = {'critical', 'high', 'medium', 'low', 'info'}


# ============================================================
# Phase 39: Advanced Query Builder — Field Allowlist & SQL Engine
# ============================================================

# Maps UI field names to safe SQL column expressions (all use 'i' alias)
QUERY_FIELD_MAP = {
    'display_name':          "i.display_name",
    'identity_type':         "i.identity_type",
    'identity_category':     "COALESCE(i.identity_category, '')",
    'cloud':                 "COALESCE(i.cloud, 'azure')",
    'status':                "COALESCE(i.status, 'active')",
    'enabled':               "COALESCE(i.enabled, true)",
    'is_federated':          "COALESCE(i.is_federated, false)",
    'risk_level':            "i.risk_level",
    'risk_score':            "COALESCE(i.risk_score, 0)",
    'activity_status':       "i.activity_status",
    'created_datetime':      "i.created_datetime",
    'last_sign_in':          "i.last_sign_in",
    'last_seen_auth':        "i.last_seen_auth",
    'credential_count':      "COALESCE(i.credential_count, 0)",
    'credential_status':     "i.credential_status",
    'credential_risk':       "i.credential_risk",
    'credential_expiration': "i.credential_expiration",
    'owner_display_name':    "i.owner_display_name",
    'owner_count':           "COALESCE(i.owner_count, 0)",
    'api_permission_count':  "COALESCE(i.api_permission_count, 0)",
    'app_role_count':        "COALESCE(i.app_role_count, 0)",
    'pim_eligible_count':    "COALESCE(i.pim_eligible_count, 0)",
    'has_permanent_assignment': "COALESCE(i.has_permanent_assignment, false)",
    'ca_coverage_status':    "i.ca_coverage_status",
    'ca_mfa_enforced':       "COALESCE(i.ca_mfa_enforced, false)",
}

# Computed fields that require subqueries
QUERY_COMPUTED_FIELDS = {
    'rbac_role_count': "(SELECT COUNT(*) FROM role_assignments ra WHERE ra.identity_db_id = i.id)",
    'entra_role_count': "(SELECT COUNT(*) FROM entra_role_assignments era WHERE era.identity_db_id = i.id)",
    'privilege_tier': """(CASE
        WHEN EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
            AND LOWER(era.role_name) IN ('global administrator','privileged role administrator',
            'privileged authentication administrator','application administrator',
            'cloud application administrator'))
        THEN 0
        WHEN EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
            AND LOWER(ra.role_name) IN ('owner','user access administrator')
            AND (ra.scope IS NULL OR ra.scope = '/' OR ra.scope LIKE '/subscriptions/%%'
                 AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%'))
        THEN 0
        WHEN EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
            AND LOWER(era.role_name) IN ('user administrator','exchange administrator',
            'sharepoint administrator','teams administrator','conditional access administrator',
            'security administrator'))
        THEN 1
        WHEN EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
            AND LOWER(ra.role_name) IN ('owner','contributor','user access administrator'))
        THEN 1
        WHEN EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id) THEN 2
        WHEN EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id) THEN 2
        ELSE 3
    END)""",
}

QUERY_OPERATORS = {
    'equals':       "{field} = %s",
    'not_equals':   "{field} != %s",
    'contains':     "LOWER(CAST({field} AS TEXT)) LIKE %s",
    'not_contains': "LOWER(CAST({field} AS TEXT)) NOT LIKE %s",
    'greater_than': "{field} > %s",
    'less_than':    "{field} < %s",
    'in':           "{field} = ANY(%s)",
    'not_in':       "{field} != ALL(%s)",
    'is_empty':     "({field} IS NULL OR CAST({field} AS TEXT) = '')",
    'is_not_empty': "({field} IS NOT NULL AND CAST({field} AS TEXT) != '')",
}

QUERY_NUMERIC_FIELDS = {
    'risk_score', 'credential_count', 'owner_count', 'api_permission_count',
    'app_role_count', 'pim_eligible_count', 'rbac_role_count', 'entra_role_count',
    'privilege_tier',
}

QUERY_BOOLEAN_FIELDS = {
    'enabled', 'is_federated', 'has_permanent_assignment', 'ca_mfa_enforced',
}

QUERY_DATE_FIELDS = {
    'created_datetime', 'last_sign_in', 'last_seen_auth', 'credential_expiration',
}


def _build_query_condition(field_name, operator, value):
    """Build a single SQL WHERE condition. Returns (sql_fragment, params)."""
    if field_name in QUERY_FIELD_MAP:
        sql_field = QUERY_FIELD_MAP[field_name]
    elif field_name in QUERY_COMPUTED_FIELDS:
        sql_field = QUERY_COMPUTED_FIELDS[field_name]
    else:
        raise ValueError(f"Unknown field: {field_name}")

    if operator not in QUERY_OPERATORS:
        raise ValueError(f"Unknown operator: {operator}")

    if operator in ('is_empty', 'is_not_empty'):
        return QUERY_OPERATORS[operator].format(field=sql_field), []

    if field_name in QUERY_NUMERIC_FIELDS:
        if operator in ('in', 'not_in'):
            if not isinstance(value, list):
                raise ValueError(f"Operator {operator} requires a list value")
            value = [float(v) for v in value]
        else:
            value = float(value)
    elif field_name in QUERY_BOOLEAN_FIELDS:
        if isinstance(value, str):
            value = value.lower() in ('true', '1', 'yes')
        else:
            value = bool(value)
    elif field_name in QUERY_DATE_FIELDS:
        if operator in ('in', 'not_in'):
            raise ValueError(f"Operator {operator} not supported for date fields")
        value = str(value)

    template = QUERY_OPERATORS[operator]
    sql = template.format(field=sql_field)

    if operator in ('contains', 'not_contains'):
        return sql, [f"%{str(value).lower()}%"]
    elif operator in ('in', 'not_in'):
        if not isinstance(value, list):
            raise ValueError(f"Operator {operator} requires a list value")
        return sql, [value]
    else:
        return sql, [value]


def _build_advanced_query_where(groups):
    """Build WHERE clause from groups of conditions (AND within group, OR between groups)."""
    if not groups:
        return "", []

    or_parts = []
    all_params = []

    for group in groups:
        conditions = group.get('conditions', [])
        if not conditions:
            continue

        and_parts = []
        for cond in conditions:
            field = cond.get('field', '')
            operator = cond.get('operator', 'equals')
            value = cond.get('value')
            sql_fragment, params = _build_query_condition(field, operator, value)
            and_parts.append(sql_fragment)
            all_params.extend(params)

        if and_parts:
            or_parts.append("(" + " AND ".join(and_parts) + ")")

    if not or_parts:
        return "", []

    where_clause = " AND (" + " OR ".join(or_parts) + ")"
    return where_clause, all_params


def _identity_list_select():
    """Returns the SELECT ... FROM portion of the identities list query."""
    return """
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
            ) as rbac_role_count,
            (
                SELECT COUNT(*)
                FROM entra_role_assignments era
                WHERE era.identity_db_id = i.id
            ) as entra_role_count,
            (
                SELECT MAX(ra.risk_level)
                FROM role_assignments ra
                WHERE ra.identity_db_id = i.id
                AND ra.risk_level IS NOT NULL
            ) as rbac_max_risk,
            (
                SELECT MAX(era.risk_level)
                FROM entra_role_assignments era
                WHERE era.identity_db_id = i.id
                AND era.risk_level IS NOT NULL
            ) as entra_max_risk,
            COALESCE(i.cloud, 'azure') as cloud,
            i.identity_type_normalized,
            i.canonical_name,
            i.principal_id,
            i.tenant_or_org_id,
            COALESCE(i.source_normalized, 'entra') as source,
            COALESCE(i.is_federated, false) as is_federated,
            COALESCE(i.status, 'active') as status,
            i.last_seen_auth,
            i.last_sign_in,
            i.owner_display_name,
            COALESCE(i.owner_count, 0) as owner_count,
            COALESCE(i.risk_score, 0) as risk_score,
            COALESCE(i.api_permission_count, 0) as api_permission_count,
            COALESCE(i.app_role_count, 0) as app_role_count,
            (
                SELECT MAX(gp.risk_level)
                FROM graph_api_permissions gp
                WHERE gp.identity_db_id = i.id
                AND gp.risk_level IS NOT NULL
            ) as graph_max_risk,
            i.enabled,
            i.last_sign_in,
            CASE
                WHEN EXISTS (
                    SELECT 1 FROM entra_role_assignments era
                    WHERE era.identity_db_id = i.id
                    AND LOWER(era.role_name) IN (
                        'global administrator', 'privileged role administrator',
                        'privileged authentication administrator',
                        'partner tier2 support', 'security operator',
                        'application administrator', 'cloud application administrator',
                        'hybrid identity administrator',
                        'domain name administrator',
                        'external identity provider administrator'
                    )
                ) THEN 0
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra
                    WHERE ra.identity_db_id = i.id
                    AND LOWER(ra.role_name) IN (
                        'owner', 'user access administrator'
                    )
                    AND (ra.scope IS NULL OR ra.scope = '/' OR ra.scope LIKE '/subscriptions/%%'
                         AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%')
                ) THEN 0
                WHEN EXISTS (
                    SELECT 1 FROM entra_role_assignments era
                    WHERE era.identity_db_id = i.id
                    AND LOWER(era.role_name) IN (
                        'user administrator', 'exchange administrator',
                        'sharepoint administrator', 'teams administrator',
                        'intune administrator', 'conditional access administrator',
                        'authentication administrator',
                        'groups administrator', 'license administrator',
                        'password administrator', 'security administrator',
                        'compliance administrator', 'billing administrator',
                        'dynamics 365 administrator', 'power platform administrator',
                        'azure devops administrator', 'azure information protection administrator',
                        'helpdesk administrator'
                    )
                ) THEN 1
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra
                    WHERE ra.identity_db_id = i.id
                    AND LOWER(ra.role_name) IN (
                        'owner', 'contributor', 'user access administrator'
                    )
                ) THEN 1
                WHEN EXISTS (
                    SELECT 1 FROM entra_role_assignments era
                    WHERE era.identity_db_id = i.id
                ) THEN 2
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra
                    WHERE ra.identity_db_id = i.id
                ) THEN 2
                WHEN EXISTS (
                    SELECT 1 FROM graph_api_permissions gp
                    WHERE gp.identity_db_id = i.id
                    AND gp.risk_level IN ('critical', 'high')
                ) THEN 2
                ELSE 3
            END as privilege_tier,
            COALESCE(i.pim_eligible_count, 0) as pim_eligible_count,
            COALESCE(i.has_permanent_assignment, false) as has_permanent_assignment,
            i.ca_coverage_status,
            COALESCE(i.ca_mfa_enforced, false) as ca_mfa_enforced,
            dr_sub.subscription_id as sub_id,
            dr_sub.subscription_name as sub_name,
            (SELECT isa_p.subscription_id FROM identity_subscription_access isa_p
             WHERE isa_p.identity_db_id = i.id
             ORDER BY CASE
                 WHEN LOWER(isa_p.rbac_role) LIKE '%%owner%%' THEN 4
                 WHEN LOWER(isa_p.rbac_role) LIKE '%%contributor%%' THEN 3
                 WHEN LOWER(isa_p.rbac_role) LIKE '%%admin%%' THEN 3
                 WHEN LOWER(isa_p.rbac_role) LIKE '%%writer%%' THEN 2
                 ELSE 1
             END DESC, isa_p.subscription_name ASC
             LIMIT 1) as primary_subscription_id,
            GREATEST(0, COALESCE((SELECT COUNT(DISTINCT isa_c.subscription_id) - 1
             FROM identity_subscription_access isa_c
             WHERE isa_c.identity_db_id = i.id), 0)) as additional_subscription_count,
            CASE
                WHEN EXISTS (
                    SELECT 1 FROM entra_role_assignments era2
                    WHERE era2.identity_db_id = i.id
                    AND (era2.directory_scope IS NULL OR era2.directory_scope = '/')
                ) THEN 'tenant'
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra2
                    WHERE ra2.identity_db_id = i.id AND ra2.scope_type = 'tenant'
                ) THEN 'tenant'
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra2
                    WHERE ra2.identity_db_id = i.id AND ra2.scope_type = 'subscription'
                ) THEN 'subscription'
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra2
                    WHERE ra2.identity_db_id = i.id AND ra2.scope_type = 'resource_group'
                ) THEN 'resource_group'
                WHEN EXISTS (
                    SELECT 1 FROM role_assignments ra2
                    WHERE ra2.identity_db_id = i.id AND ra2.scope_type = 'resource'
                ) THEN 'resource'
                WHEN EXISTS (
                    SELECT 1 FROM entra_role_assignments era2
                    WHERE era2.identity_db_id = i.id
                ) THEN 'directory'
                ELSE 'none'
            END as effective_scope
        FROM identities i
        LEFT JOIN discovery_runs dr_sub ON dr_sub.id = i.discovery_run_id
    """


def _map_identity_row(row):
    """Maps a raw DB row tuple from _identity_list_select() to the API response dict."""
    display_name = row[1] or ''
    identity_type = row[2] or ''
    raw_category = row[3] or ''
    normalized_category = _normalize_category_key(raw_category)

    return {
        "identity_id": row[0],
        "display_name": display_name,
        "identity_type": identity_type,
        "identity_category": normalized_category,
        "risk_level": row[4] or "info",
        "credential_count": int(row[5] or 0),
        "next_expiry": row[6].isoformat() if row[6] else None,
        "credential_risk": row[7] or "unknown",
        "credential_status": row[8] or "Unknown",
        "credential_expiration": row[9].isoformat() if row[9] else None,
        "created_datetime": row[10].isoformat() if row[10] else None,
        "activity_status": row[11] or "unknown",
        "rbac_role_count": int(row[12] or 0),
        "entra_role_count": int(row[13] or 0),
        "role_count": int(row[12] or 0) + int(row[13] or 0),
        "rbac_max_risk": row[14] or "info",
        "entra_max_risk": row[15] or "info",
        "cloud": row[16] or "azure",
        "normalized_identity_type": row[17],
        "canonical_name": row[18],
        "principal_id": row[19],
        "tenant_or_org_id": row[20],
        "source": row[21] or "entra",
        "is_federated": row[22] or False,
        "status": row[23] or "active",
        "last_seen_auth": row[24].isoformat() if row[24] else None,
        "last_sign_in": row[25].isoformat() if row[25] else None,
        "owner_display_name": row[26],
        "owner_count": int(row[27] or 0),
        "risk_score": int(row[28] or 0),
        "api_permission_count": int(row[29] or 0),
        "app_role_count": int(row[30] or 0),
        "graph_max_risk": row[31] or "info",
        "enabled": row[32] if row[32] is not None else True,
        "last_sign_in": row[33].isoformat() if row[33] else None,
        "privilege_tier": int(row[34]) if row[34] is not None else 3,
        "pim_eligible_count": int(row[35] or 0),
        "has_permanent_assignment": bool(row[36]) if row[36] is not None else False,
        "ca_coverage_status": row[37] or None,
        "ca_mfa_enforced": bool(row[38]) if row[38] is not None else False,
        "subscription_id": row[39] or None,
        "subscription_name": row[40] or None,
        "primary_subscription_id": row[41] or None,
        "additional_subscription_count": int(row[42] or 0),
        "effective_scope": row[43] if len(row) > 43 and row[43] else "none",
        "privileged_level": "privileged" if int(row[34] or 3) == 0 else "elevated" if int(row[34] or 3) == 1 else "standard",
        "credential_health": (
            "none" if int(row[5] or 0) == 0
            else "expired" if (row[7] or "").lower() == "expired"
            else "expiring" if (row[7] or "").lower() == "expiring_soon"
            else "ok"
        ),
    }


def _validate_rule_data(data: dict, db, existing_id=None):
    """Validate risk rule data. Returns list of errors."""
    errors = []

    name = str(data.get('name', '')).strip()
    if not name:
        errors.append("name is required")
    elif len(name) > 255:
        errors.append("name must be 255 characters or less")

    conditions = data.get('conditions')
    if not conditions or not isinstance(conditions, dict):
        errors.append("conditions must be a JSON object")
    else:
        all_conds = conditions.get('all')
        if not all_conds or not isinstance(all_conds, list):
            errors.append("conditions.all must be a non-empty list")
        else:
            for i, cond in enumerate(all_conds):
                if not isinstance(cond, dict):
                    errors.append(f"condition {i}: must be an object")
                    continue
                field = cond.get('field', '')
                if field not in VALID_RULE_FIELDS:
                    errors.append(f"condition {i}: invalid field '{field}'")
                op = cond.get('op', 'eq')
                if op not in VALID_RULE_OPS:
                    errors.append(f"condition {i}: invalid op '{op}'")
                if 'value' not in cond:
                    errors.append(f"condition {i}: value is required")

    action_type = data.get('action_type', 'adjust_points')
    if action_type not in VALID_ACTION_TYPES:
        errors.append(f"action_type must be one of: {', '.join(VALID_ACTION_TYPES)}")

    if action_type == 'force_level':
        force_level = data.get('force_level', '')
        if force_level not in VALID_FORCE_LEVELS:
            errors.append(f"force_level must be one of: {', '.join(VALID_FORCE_LEVELS)}")

    # Max 50 rules
    if not existing_id:
        existing_rules = db.get_custom_risk_rules()
        if len(existing_rules) >= 50:
            errors.append("Maximum of 50 custom risk rules allowed")

    return errors


def get_risk_rules_list():
    """GET /api/risk-rules — list all custom risk rules."""
    db = _db()
    try:
        rules = db.get_custom_risk_rules()
        return jsonify({"rules": rules, "count": len(rules)})
    finally:
        db.close()


def create_risk_rule():
    """POST /api/risk-rules — create a new custom risk rule."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}
        errors = _validate_rule_data(data, db)
        if errors:
            return jsonify({"error": "; ".join(errors)}), 400

        rule = db.create_custom_risk_rule(
            name=str(data['name']).strip(),
            description=str(data.get('description', '')).strip() or None,
            conditions=data['conditions'],
            action_type=data.get('action_type', 'adjust_points'),
            points_adjustment=int(data.get('points_adjustment', 0)),
            force_level=data.get('force_level'),
            reason_text=str(data.get('reason_text', '')).strip() or None,
            priority=int(data.get('priority', 100)),
        )

        _log(db,'risk_rule_created',
            f'Custom risk rule "{rule["name"]}" created',
            {'rule_id': rule['id'], 'action_type': rule['action_type']})

        return jsonify(rule), 201
    finally:
        db.close()


def update_risk_rule(rule_id):
    """PUT /api/risk-rules/<id> — update a custom risk rule."""
    db = _db()
    try:
        existing = db.get_custom_risk_rule(rule_id)
        if not existing:
            return jsonify({"error": "Risk rule not found"}), 404

        data = request.get_json(silent=True) or {}
        updates = {}

        if 'name' in data:
            name = str(data['name']).strip()
            if not name:
                return jsonify({"error": "name cannot be empty"}), 400
            if len(name) > 255:
                return jsonify({"error": "name must be 255 characters or less"}), 400
            updates['name'] = name

        if 'description' in data:
            updates['description'] = str(data['description']).strip() or None

        if 'conditions' in data:
            conditions = data['conditions']
            if not conditions or not isinstance(conditions, dict):
                return jsonify({"error": "conditions must be a JSON object"}), 400
            all_conds = conditions.get('all')
            if not all_conds or not isinstance(all_conds, list):
                return jsonify({"error": "conditions.all must be a non-empty list"}), 400
            for i, cond in enumerate(all_conds):
                if not isinstance(cond, dict):
                    return jsonify({"error": f"condition {i}: must be an object"}), 400
                if cond.get('field', '') not in VALID_RULE_FIELDS:
                    return jsonify({"error": f"condition {i}: invalid field"}), 400
                if cond.get('op', 'eq') not in VALID_RULE_OPS:
                    return jsonify({"error": f"condition {i}: invalid op"}), 400
            updates['conditions'] = conditions

        if 'action_type' in data:
            if data['action_type'] not in VALID_ACTION_TYPES:
                return jsonify({"error": "invalid action_type"}), 400
            updates['action_type'] = data['action_type']

        if 'points_adjustment' in data:
            updates['points_adjustment'] = int(data['points_adjustment'])

        if 'force_level' in data:
            if data['force_level'] and data['force_level'] not in VALID_FORCE_LEVELS:
                return jsonify({"error": "invalid force_level"}), 400
            updates['force_level'] = data['force_level']

        if 'reason_text' in data:
            updates['reason_text'] = str(data['reason_text']).strip() or None

        if 'priority' in data:
            updates['priority'] = int(data['priority'])

        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])

        if not updates:
            return jsonify(existing)

        rule = db.update_custom_risk_rule(rule_id, **updates)
        _log(db,'risk_rule_updated',
            f'Custom risk rule "{rule["name"]}" updated: {", ".join(updates.keys())}',
            {'rule_id': rule_id, 'updated_fields': list(updates.keys())})

        return jsonify(rule)
    finally:
        db.close()


def delete_risk_rule(rule_id):
    """DELETE /api/risk-rules/<id> — delete a custom risk rule."""
    db = _db()
    try:
        existing = db.get_custom_risk_rule(rule_id)
        if not existing:
            return jsonify({"error": "Risk rule not found"}), 404

        db.delete_custom_risk_rule(rule_id)
        _log(db,'risk_rule_deleted',
            f'Custom risk rule "{existing["name"]}" deleted',
            {'rule_id': rule_id})

        return jsonify({"status": "deleted", "id": rule_id})
    finally:
        db.close()


def preview_risk_rule():
    """POST /api/risk-rules/preview — preview which identities a rule would affect."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}

        conditions = data.get('conditions')
        if not conditions or not isinstance(conditions, dict):
            return jsonify({"error": "conditions is required"}), 400

        rule = {
            'id': 0,
            'conditions': conditions,
            'action_type': data.get('action_type', 'adjust_points'),
            'points_adjustment': int(data.get('points_adjustment', 0)),
            'force_level': data.get('force_level'),
            'reason_text': data.get('reason_text', 'Preview'),
            'name': data.get('name', 'Preview Rule'),
        }

        # Get latest run identities
        cursor = db.conn.cursor()
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"affected_count": 0, "affected": []})

        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_type,
                   COALESCE(i.identity_category, '') as identity_category,
                   i.risk_level, i.activity_status,
                   COALESCE(i.enabled, true) as enabled,
                   COALESCE(i.risk_score, 0) as risk_score,
                   (SELECT COUNT(*) FROM role_assignments ra WHERE ra.identity_db_id = i.id) as rbac_count,
                   (SELECT COUNT(*) FROM entra_role_assignments era WHERE era.identity_db_id = i.id) as entra_count,
                   (SELECT COUNT(*) FROM graph_api_permissions gap WHERE gap.identity_db_id = i.id) as perm_count
            FROM identities i
            WHERE i.discovery_run_id = %s
        """, (latest_run,))
        cols = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()

        from app.engines.risk_rules import RiskRuleEngine
        engine = RiskRuleEngine()
        affected = []

        for row in rows:
            identity = dict(zip(cols, row))
            identity['role_count'] = (identity.get('rbac_count', 0) or 0) + (identity.get('entra_count', 0) or 0)
            identity['api_permission_count'] = identity.get('perm_count', 0) or 0
            identity['app_role_count'] = 0
            identity['roles'] = []
            identity['entra_roles'] = []
            identity['_permissions'] = []
            identity['_credentials'] = []

            if engine._matches(identity, rule):
                affected.append({
                    'identity_id': identity['identity_id'],
                    'display_name': identity['display_name'],
                    'identity_category': identity['identity_category'],
                    'risk_level': identity['risk_level'],
                    'risk_score': identity.get('risk_score', 0),
                })

            if len(affected) >= 50:
                break

        return jsonify({"affected_count": len(affected), "affected": affected})
    finally:
        db.close()


# ============================================================
# Phase 30: Notification Center
# ============================================================


def get_notifications_list():
    """GET /api/notifications — list notifications with optional filters."""
    db = _db()
    try:
        limit = min(request.args.get('limit', 50, type=int), 200)
        offset = request.args.get('offset', 0, type=int)
        severity = request.args.get('severity')
        category = request.args.get('category')
        read_param = request.args.get('read')
        read = None
        if read_param == 'true':
            read = True
        elif read_param == 'false':
            read = False

        notifications = db.get_notifications(
            limit=limit, offset=offset, read=read,
            severity=severity, category=category,
            tenant_id=_tenant_id()
        )
        return jsonify({
            "notifications": notifications,
            "count": len(notifications),
            "limit": limit,
            "offset": offset,
        })
    finally:
        db.close()


def get_notification_stats_handler():
    """GET /api/notifications/stats — unread count and breakdowns."""
    db = _db()
    try:
        stats = db.get_notification_stats(tenant_id=_tenant_id())
        return jsonify(stats)
    finally:
        db.close()


def mark_notification_handler(notification_id):
    """PATCH /api/notifications/<id> — mark read or actioned."""
    db = _db()
    try:
        existing = db.get_notification(notification_id)
        if not existing:
            return jsonify({"error": "Notification not found"}), 404

        # Tenant isolation: verify notification belongs to this tenant
        tid = _tenant_id()
        if tid is not None and existing.get('tenant_id') != tid:
            return jsonify({"error": "Notification not found"}), 404

        data = request.get_json(silent=True) or {}

        if data.get('action_type'):
            result = db.action_notification(notification_id, data['action_type'])
        elif data.get('read') is True:
            result = db.mark_notification_read(notification_id)
        else:
            return jsonify({"error": "Provide 'read': true or 'action_type'"}), 400

        return jsonify(result)
    finally:
        db.close()


def mark_all_notifications_read_handler():
    """POST /api/notifications/mark-all-read — bulk mark all as read."""
    db = _db()
    try:
        count = db.mark_all_notifications_read(tenant_id=_tenant_id())
        return jsonify({"status": "ok", "marked_read": count})
    finally:
        db.close()


def delete_notification_handler(notification_id):
    """DELETE /api/notifications/<id> — delete a notification."""
    db = _db()
    try:
        existing = db.get_notification(notification_id)
        if not existing:
            return jsonify({"error": "Notification not found"}), 404

        db.delete_notification(notification_id)
        return jsonify({"status": "deleted", "id": notification_id})
    finally:
        db.close()


def _normalize_category_key(raw_category: str) -> str:
    """
    Normalize category value to canonical snake_case key.
    Handles legacy display names from old database records.
    """
    if not raw_category:
        return 'unknown'

    c = raw_category.lower().strip()

    # Already canonical
    if c in ('service_principal', 'managed_identity_system', 'managed_identity_user',
             'human_user', 'guest', 'microsoft_internal', 'unknown'):
        return c

    # Legacy display name mappings
    if c in ('service principal', 'serviceprincipal'):
        return 'service_principal'
    if c in ('user', 'users', 'human user'):
        return 'human_user'
    if c in ('guest', 'guest user'):
        return 'guest'
    if 'user assigned' in c or 'user-assigned' in c or c == 'managed identity (user)':
        return 'managed_identity_user'
    if 'system assigned' in c or 'system-assigned' in c or c == 'managed identity (system)':
        return 'managed_identity_system'
    if 'microsoft' in c and 'internal' in c:
        return 'microsoft_internal'
    if 'managed identity' in c or 'managed_identity' in c:
        # Default managed identity to system if not specified
        return 'managed_identity_system'

    return 'unknown'


def _is_microsoft_internal_identity(display_name: str, identity_type: str) -> bool:
    """
    Detect if an identity is a Microsoft internal/first-party service.
    Uses display name patterns that reliably indicate Microsoft services.

    This is used at query time to properly categorize existing data that
    wasn't categorized during discovery.

    Args:
        display_name: The identity's display name
        identity_type: The identity type (user, service_principal, etc.)

    Returns:
        True if this is a Microsoft internal service, False otherwise
    """
    if not display_name:
        return False

    # Only apply to service principals
    if identity_type and identity_type.lower() not in ('service_principal', 'serviceprincipal'):
        return False

    name = display_name.lower().strip()

    # Microsoft product/service name patterns
    # These are reliable indicators of Microsoft first-party services
    microsoft_patterns = [
        # Explicit Microsoft branding
        'microsoft ',
        'ms-',
        'ms ',

        # Office 365 / M365
        'office 365',
        'office365',
        'o365',
        'm365 ',

        # Azure services
        'azure ',

        # Specific Microsoft products
        'sharepoint',
        'exchange ',
        'teams ',
        'intune',
        'dynamics ',
        'power bi',
        'powerbi',
        'powerapps',
        'power apps',
        'power platform',
        'onedrive',
        'onenote',
        'outlook',
        'skype',
        'yammer',
        'viva ',
        'cortana',
        'bing',
        'windows ',
        'graph ',

        # Azure AD / Entra
        'aad',
        'entra',
        'active directory',

        # Common Microsoft service patterns
        'substrate',
        'dataverse',
        'common data service',
    ]

    # Check if name starts with or contains Microsoft patterns
    for pattern in microsoft_patterns:
        if name.startswith(pattern) or f' {pattern}' in f' {name}':
            return True

    # Additional specific service names that are Microsoft internal
    microsoft_service_names = [
        'managed service identity',
        'device registration service',
        'billing rp',
        'signup',
        'conferencing virtual assistant',
        'conference auto attendant',
        'connectors',
        'pushchannel',
        'narada notification service',
        'idsproduction',
        'ids-prod',
        'safelinks',
        'sway',
        'ic3 ',
        'ocaas',
        'cap ',
        'cab',
        'oms',
        'pim',
        'spauthevent',
        'subscriptionrp',
        'weveengine',
        'signal b2',
        'privacy management',
        'policy administration',
        'request approvals',
        'group configuration',
        'people profile',
        'meeting migration',
        'media analysis',
        'messaging bot',
        'customer experience',
        'customer service',
        'compliance',
        'sales insights',
        'portfolios',
        'project work',
        'deployment scheduler',
        'deploymentscheduler',
        'configuration manager',
        'cloud licensing',
        'iam ',
        'ip substrate',
        'mcapi',
        'mro ',
        'ppe-',
        'aci api',
        'aciapi',
        # Additional Microsoft services that don't follow common patterns
        'azuresupportcenter',
        'support center',
        'capacitypolicyassignment',
        'capacity policy',
        'centralized deployment',
        'cloudlicensingsystem',
        'ipsubstrate',
        'microsoft.smit',
        '.smit',
        'office shredding',
        'shredding service',
        'officeclientservice',
        'officeservicesmanager',
        'oneprofile',
        'productslifecycle',
        'products lifecycle',
        'projectworkmanagement',
        'salesinsights',
        'virtual visits',
        'windowsupdate',
        'windows update',
        'tenantsearchprocessors',
        'tenant search',
    ]

    for service in microsoft_service_names:
        if service in name:
            return True

    return False


def get_overview_insights():
    """
    Aggregated insights for the Overview page:
    - Privilege tier distribution (T0-T3) with T0/T1 identity names
    - Action items: dormant privileged, expiring credentials, unowned SPNs
    - Lists of dormant privileged identities and unowned SPNs
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        # Privilege tier for each identity
        cursor.execute("""
            SELECT
                i.identity_id,
                i.display_name,
                i.identity_category,
                i.risk_level,
                i.activity_status,
                COALESCE(i.owner_count, 0) as owner_count,
                i.credential_expiration,
                COALESCE(i.cloud, 'azure') as cloud,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM entra_role_assignments era
                        WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'global administrator', 'privileged role administrator',
                            'privileged authentication administrator',
                            'partner tier2 support', 'security operator',
                            'application administrator', 'cloud application administrator',
                            'hybrid identity administrator',
                            'domain name administrator',
                            'external identity provider administrator'
                        )
                    ) THEN 0
                    WHEN EXISTS (
                        SELECT 1 FROM role_assignments ra
                        WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN (
                            'owner', 'user access administrator'
                        )
                        AND (ra.scope IS NULL OR ra.scope = '/' OR ra.scope LIKE '/subscriptions/%%'
                             AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%')
                    ) THEN 0
                    WHEN EXISTS (
                        SELECT 1 FROM entra_role_assignments era
                        WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'user administrator', 'exchange administrator',
                            'sharepoint administrator', 'teams administrator',
                            'intune administrator', 'conditional access administrator',
                            'authentication administrator',
                            'groups administrator', 'license administrator',
                            'password administrator', 'security administrator',
                            'compliance administrator', 'billing administrator',
                            'dynamics 365 administrator', 'power platform administrator',
                            'azure devops administrator', 'azure information protection administrator',
                            'helpdesk administrator'
                        )
                    ) THEN 1
                    WHEN EXISTS (
                        SELECT 1 FROM role_assignments ra
                        WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN (
                            'owner', 'contributor', 'user access administrator'
                        )
                    ) THEN 1
                    WHEN EXISTS (
                        SELECT 1 FROM entra_role_assignments era
                        WHERE era.identity_db_id = i.id
                    ) THEN 2
                    WHEN EXISTS (
                        SELECT 1 FROM role_assignments ra
                        WHERE ra.identity_db_id = i.id
                    ) THEN 2
                    WHEN EXISTS (
                        SELECT 1 FROM graph_api_permissions gp
                        WHERE gp.identity_db_id = i.id
                        AND gp.risk_level IN ('critical', 'high')
                    ) THEN 2
                    ELSE 3
                END as privilege_tier
            FROM identities i
            WHERE i.discovery_run_id = %s
        """, (latest_run,))

        rows = cursor.fetchall()

        tier_counts = {0: 0, 1: 0, 2: 0, 3: 0}
        tier_identities = {0: [], 1: []}  # Only list T0/T1 names
        dormant_privileged = []
        unowned_spns = []
        expiring_creds = 0

        now = datetime.utcnow()

        for r in rows:
            identity_id, display_name, category, risk_level, activity_status, owner_count, cred_exp, cloud, tier = r
            display_name = display_name or ''
            category = _normalize_category_key(category or '')
            tier = int(tier) if tier is not None else 3

            tier_counts[tier] = tier_counts.get(tier, 0) + 1

            identity_stub = {
                "identity_id": identity_id,
                "display_name": display_name,
                "risk_level": risk_level or "info",
                "category": category,
                "cloud": cloud or "azure",
            }

            # Collect T0/T1 names
            if tier <= 1:
                tier_identities[tier].append(identity_stub)

            # Dormant privileged (T0/T1 + stale)
            if tier <= 1 and activity_status in ('stale', 'never_used'):
                dormant_privileged.append({
                    **identity_stub,
                    "tier": tier,
                    "activity_status": activity_status,
                })

            # Expiring credentials (within 30 days)
            if cred_exp:
                try:
                    days_left = (cred_exp - now).days
                    if 0 <= days_left <= 30:
                        expiring_creds += 1
                except Exception:
                    pass

            # Unowned service principals (all risk levels)
            if category == 'service_principal' and (owner_count or 0) == 0:
                unowned_spns.append(identity_stub)

        return jsonify({
            "tier_distribution": {
                "t0": {"count": tier_counts[0], "identities": tier_identities[0]},
                "t1": {"count": tier_counts[1], "identities": tier_identities[1]},
                "t2": {"count": tier_counts[2]},
                "t3": {"count": tier_counts[3]},
            },
            "action_items": {
                "dormant_privileged": len(dormant_privileged),
                "expiring_credentials": expiring_creds,
                "unowned_spns": len(unowned_spns),
            },
            "dormant_privileged": dormant_privileged[:10],
            "unowned_spns": unowned_spns[:10],
        })
    finally:
        cursor.close()
        db.close()


def get_attack_surface_score():
    """
    Compute the 6-pillar Identity Attack Surface Score (0-100).

    Pillars:
      P1 Effective Privilege (30%) — % of identities at T0/T1
      P2 Credential Risk     (20%) — % with expired/expiring creds
      P3 Trust & Federation  (20%) — % guest/external with privileged roles
      P4 Usage Dormancy      (10%) — % stale/never_used
      P5 Ownership Gov       (10%) — % SPNs without owners
      P6 External Exposure   (10%) — % with tenant-wide scope

    Higher score = worse posture (more exposed).
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        cursor.execute("""
            SELECT
                -- totals
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') NOT IN ('microsoft_internal')) as total_excl_msft,

                -- P1: Privilege (T0/T1 via subquery)
                COUNT(*) FILTER (WHERE (
                    EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'global administrator','privileged role administrator',
                            'privileged authentication administrator',
                            'application administrator','cloud application administrator',
                            'hybrid identity administrator','domain name administrator',
                            'external identity provider administrator'
                        ))
                    OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN ('owner','user access administrator')
                        AND (ra.scope IS NULL OR ra.scope = '/' OR (ra.scope LIKE '/subscriptions/%%'
                             AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%')))
                )) as t0_count,

                COUNT(*) FILTER (WHERE (
                    EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'user administrator','exchange administrator',
                            'sharepoint administrator','teams administrator',
                            'security administrator','conditional access administrator',
                            'authentication administrator','helpdesk administrator'
                        ))
                    OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN ('owner','contributor','user access administrator'))
                )) as t0t1_count,

                -- P2: Credential risk
                COUNT(*) FILTER (WHERE credential_count > 0) as has_creds,
                COUNT(*) FILTER (WHERE credential_expiration IS NOT NULL
                    AND credential_expiration < NOW()) as expired_creds,
                COUNT(*) FILTER (WHERE credential_expiration IS NOT NULL
                    AND credential_expiration >= NOW()
                    AND credential_expiration < NOW() + INTERVAL '30 days') as expiring_creds,

                -- P3: Trust (guest/external with roles)
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') = 'guest') as guest_count,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') = 'guest' AND (
                    EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                    OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                )) as guest_with_roles,
                COUNT(*) FILTER (WHERE COALESCE(is_federated, false) = true) as federated_count,

                -- P4: Usage dormancy
                COUNT(*) FILTER (WHERE activity_status IN ('stale', 'never_used')) as dormant_count,

                -- P5: Ownership (SPNs without owners)
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') IN ('service_principal', 'managed_identity_user')
                    AND (owner_count = 0 OR owner_count IS NULL)) as unowned_spns,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') IN ('service_principal', 'managed_identity_user')) as total_spns,

                -- P6: External exposure (tenant-wide scope)
                COUNT(*) FILTER (WHERE (
                    EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND (era.directory_scope IS NULL OR era.directory_scope = '/'))
                    OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND ra.scope_type = 'tenant')
                )) as tenant_scope_count

            FROM identities i
            WHERE i.discovery_run_id = %s
        """, (latest_run,))

        r = cursor.fetchone()
        total = max(r[0] or 1, 1)
        total_excl = max(r[1] or 1, 1)
        t0_count = r[2] or 0
        t0t1_count = r[3] or 0
        has_creds = max(r[4] or 1, 1)
        expired_creds = r[5] or 0
        expiring_creds = r[6] or 0
        guest_count = r[7] or 0
        guest_with_roles = r[8] or 0
        federated_count = r[9] or 0
        dormant_count = r[10] or 0
        unowned_spns = r[11] or 0
        total_spns = max(r[12] or 1, 1)
        tenant_scope = r[13] or 0

        # P1: Effective Privilege — target < 1% at T0
        priv_pct = (t0t1_count / total_excl) * 100
        p1 = min(priv_pct * 10, 100)  # 10% T0/T1 → score 100

        # P2: Credential Risk — expired + expiring as % of those with creds
        cred_risk_pct = ((expired_creds + expiring_creds) / has_creds) * 100
        p2 = min(cred_risk_pct * 2, 100)  # 50% bad creds → score 100

        # P3: Trust & Federation — guest/external with roles
        trust_risk = 0
        if guest_count > 0:
            trust_risk = (guest_with_roles / max(guest_count, 1)) * 60
        trust_risk += min((federated_count / total_excl) * 200, 40)
        p3 = min(trust_risk, 100)

        # P4: Usage Dormancy — stale/never_used identities
        dormant_pct = (dormant_count / total_excl) * 100
        p4 = min(dormant_pct * 2, 100)  # 50% dormant → score 100

        # P5: Ownership Governance — unowned SPNs
        unowned_pct = (unowned_spns / total_spns) * 100
        p5 = min(unowned_pct * 1.5, 100)  # ~67% unowned → score 100

        # P6: External Exposure — tenant-wide scope
        scope_pct = (tenant_scope / total_excl) * 100
        p6 = min(scope_pct * 5, 100)  # 20% tenant-wide → score 100

        # Weighted composite
        score = round(
            p1 * 0.30 + p2 * 0.20 + p3 * 0.20 +
            p4 * 0.10 + p5 * 0.10 + p6 * 0.10, 1
        )

        # Grade thresholds
        if score <= 20:
            grade, severity = 'A', 'low'
        elif score <= 40:
            grade, severity = 'B', 'moderate'
        elif score <= 60:
            grade, severity = 'C', 'high'
        elif score <= 80:
            grade, severity = 'D', 'very_high'
        else:
            grade, severity = 'F', 'critical'

        return jsonify({
            "score": score,
            "grade": grade,
            "severity": severity,
            "pillars": {
                "effective_privilege": {"score": round(p1, 1), "weight": 30, "detail": {"t0": t0_count, "t0t1": t0t1_count, "total": total_excl}},
                "credential_risk": {"score": round(p2, 1), "weight": 20, "detail": {"expired": expired_creds, "expiring": expiring_creds, "with_creds": has_creds}},
                "trust_federation": {"score": round(p3, 1), "weight": 20, "detail": {"guests": guest_count, "guest_with_roles": guest_with_roles, "federated": federated_count}},
                "usage_dormancy": {"score": round(p4, 1), "weight": 10, "detail": {"dormant": dormant_count, "total": total_excl}},
                "ownership_governance": {"score": round(p5, 1), "weight": 10, "detail": {"unowned_spns": unowned_spns, "total_spns": total_spns}},
                "external_exposure": {"score": round(p6, 1), "weight": 10, "detail": {"tenant_scope": tenant_scope, "total": total_excl}},
            },
            "total_identities": r[0] or 0,
        })
    finally:
        cursor.close()
        db.close()


def _compute_compliance_metrics(cursor, latest_run):
    """Compute all compliance metrics from identity posture data."""
    # T0 count
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND (
            EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                AND LOWER(era.role_name) IN (
                    'global administrator', 'privileged role administrator',
                    'privileged authentication administrator',
                    'application administrator', 'cloud application administrator',
                    'hybrid identity administrator'
                ))
            OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                AND LOWER(ra.role_name) IN ('owner', 'user access administrator')
                AND (ra.scope IS NULL OR ra.scope = '/' OR ra.scope LIKE '/subscriptions/%%'
                     AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%'))
        )
    """, (latest_run,))
    t0_count = cursor.fetchone()[0]

    # Dormant privileged
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND i.activity_status IN ('stale', 'never_used')
        AND (
            EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
            OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
        )
    """, (latest_run,))
    dormant_privileged = cursor.fetchone()[0]

    # Expired credentials
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND i.credential_status = 'expired'
    """, (latest_run,))
    expired_credentials = cursor.fetchone()[0]

    # Expiring within 30 days
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND i.credential_expiration IS NOT NULL
        AND i.credential_expiration > NOW()
        AND i.credential_expiration < NOW() + INTERVAL '30 days'
    """, (latest_run,))
    expiring_credentials_30d = cursor.fetchone()[0]

    # Unowned SPNs
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND LOWER(COALESCE(i.identity_category, '')) = 'service_principal'
        AND COALESCE(i.owner_count, 0) = 0
    """, (latest_run,))
    unowned_spns = cursor.fetchone()[0]

    # HIPAA violations
    cursor.execute("""
        SELECT COUNT(DISTINCT rhm.role_name)
        FROM role_hipaa_mappings rhm
        WHERE EXISTS (
            SELECT 1 FROM entra_role_assignments era
            JOIN identities i ON era.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND era.role_name = rhm.role_name
        ) OR EXISTS (
            SELECT 1 FROM role_assignments ra
            JOIN identities i ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND ra.role_name = rhm.role_name
        )
    """, (latest_run, latest_run))
    hipaa_violations = cursor.fetchone()[0]

    # MFA not enforced (identities not covered by any CA policy requiring MFA)
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND COALESCE(i.ca_mfa_enforced, false) = false
        AND LOWER(COALESCE(i.identity_category, '')) IN ('human_user', 'guest')
    """, (latest_run,))
    mfa_not_enforced = cursor.fetchone()[0]

    # Excessive permissions (>5 role assignments)
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND (
            (SELECT COUNT(*) FROM role_assignments ra WHERE ra.identity_db_id = i.id)
            + (SELECT COUNT(*) FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
        ) > 5
    """, (latest_run,))
    excessive_permissions = cursor.fetchone()[0]

    # Stale accounts (inactive > 90 days)
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND i.activity_status IN ('stale', 'never_used')
    """, (latest_run,))
    stale_accounts = cursor.fetchone()[0]

    # No credential rotation (credentials not rotated in 180+ days)
    cursor.execute("""
        SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        AND EXISTS (
            SELECT 1 FROM credentials c WHERE c.identity_db_id = i.id
            AND c.start_datetime IS NOT NULL
            AND c.start_datetime < NOW() - INTERVAL '180 days'
        )
    """, (latest_run,))
    no_credential_rotation = cursor.fetchone()[0]

    return {
        't0_count': t0_count,
        'dormant_privileged': dormant_privileged,
        'expired_credentials': expired_credentials,
        'expiring_credentials_30d': expiring_credentials_30d,
        'unowned_spns': unowned_spns,
        'hipaa_violations': hipaa_violations,
        'mfa_not_enforced': mfa_not_enforced,
        'excessive_permissions': excessive_permissions,
        'stale_accounts': stale_accounts,
        'no_credential_rotation': no_credential_rotation,
    }


def _compute_compliance_evidence(cursor, latest_run, needed_metrics):
    """For each metric in needed_metrics, return up to 50 identities contributing to it."""
    evidence = {}
    _COLS = "i.id, i.identity_id, i.display_name, i.risk_level, COALESCE(i.risk_score,0), COALESCE(i.identity_category,''), i.activity_status"

    def _rows(reason_text):
        return [
            {'id': r[0], 'identity_id': r[1], 'display_name': r[2] or r[1],
             'risk_level': r[3] or 'unknown', 'risk_score': r[4],
             'identity_category': r[5], 'reason': reason_text}
            for r in cursor.fetchall()
        ]

    if 't0_count' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND (
                EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                    AND LOWER(era.role_name) IN (
                        'global administrator', 'privileged role administrator',
                        'privileged authentication administrator',
                        'application administrator', 'cloud application administrator',
                        'hybrid identity administrator'
                    ))
                OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                    AND LOWER(ra.role_name) IN ('owner', 'user access administrator')
                    AND (ra.scope IS NULL OR ra.scope = '/' OR ra.scope LIKE '/subscriptions/%%'
                         AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%'))
            )
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['t0_count'] = _rows("Control Plane (T0) privileged identity")

    if 'dormant_privileged' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND i.activity_status IN ('stale', 'never_used')
            AND (
                EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
            )
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['dormant_privileged'] = _rows("Dormant/stale identity with active role assignments")

    if 'expired_credentials' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND i.credential_status = 'expired'
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['expired_credentials'] = _rows("Expired credentials")

    if 'expiring_credentials_30d' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND i.credential_expiration IS NOT NULL
            AND i.credential_expiration > NOW()
            AND i.credential_expiration < NOW() + INTERVAL '30 days'
            ORDER BY i.credential_expiration ASC LIMIT 50
        """, (latest_run,))
        evidence['expiring_credentials_30d'] = _rows("Credential expires within 30 days")

    if 'unowned_spns' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND LOWER(COALESCE(i.identity_category, '')) = 'service_principal'
            AND COALESCE(i.owner_count, 0) = 0
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['unowned_spns'] = _rows("Service principal without assigned owner")

    if 'hipaa_violations' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i
            WHERE i.discovery_run_id = %s
            AND (
                EXISTS (
                    SELECT 1 FROM entra_role_assignments era
                    JOIN role_hipaa_mappings rhm ON era.role_name = rhm.role_name
                    WHERE era.identity_db_id = i.id
                )
                OR EXISTS (
                    SELECT 1 FROM role_assignments ra
                    JOIN role_hipaa_mappings rhm ON ra.role_name = rhm.role_name
                    WHERE ra.identity_db_id = i.id
                )
            )
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['hipaa_violations'] = _rows("Has roles with HIPAA violation mappings")

    if 'mfa_not_enforced' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND COALESCE(i.ca_mfa_enforced, false) = false
            AND LOWER(COALESCE(i.identity_category, '')) IN ('human_user', 'guest')
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['mfa_not_enforced'] = _rows("Human user without MFA enforcement")

    if 'excessive_permissions' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND (
                (SELECT COUNT(*) FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                + (SELECT COUNT(*) FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
            ) > 5
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['excessive_permissions'] = _rows("Has >5 role assignments")

    if 'stale_accounts' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND i.activity_status IN ('stale', 'never_used')
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['stale_accounts'] = _rows("Stale or never-used account")

    if 'no_credential_rotation' in needed_metrics:
        cursor.execute(f"""
            SELECT {_COLS} FROM identities i WHERE i.discovery_run_id = %s
            AND EXISTS (
                SELECT 1 FROM credentials c WHERE c.identity_db_id = i.id
                AND c.start_datetime IS NOT NULL
                AND c.start_datetime < NOW() - INTERVAL '180 days'
            )
            ORDER BY i.risk_score DESC LIMIT 50
        """, (latest_run,))
        evidence['no_credential_rotation'] = _rows("Credentials not rotated in 180+ days")

    return evidence


_FRAMEWORK_REF_PREFIX = {
    'soc2': 'SOC2', 'hipaa': 'HIPAA', 'pci_dss': 'PCI-DSS',
    'nist_800_53': 'NIST', 'cis_azure': 'CIS', 'iso_27001': 'ISO',
}


def _match_playbooks_to_control(all_playbooks, control_id, framework_key):
    """Filter pre-fetched playbooks whose compliance_refs match this control."""
    prefix = _FRAMEWORK_REF_PREFIX.get(framework_key, '')
    if not prefix:
        return []
    search = f"{prefix} {control_id}"
    matched = []
    for pb in all_playbooks:
        refs = pb.get('compliance_refs') or []
        if any(search in ref for ref in refs):
            matched.append({
                'id': pb['id'], 'title': pb['title'],
                'description': pb.get('description', ''),
                'impact': pb.get('impact', ''), 'effort': pb.get('effort', ''),
            })
    return matched


def _evaluate_control(control, metrics):
    """Evaluate a single control against computed metrics. Returns 'pass', 'warn', or 'fail'."""
    import operator
    ops = {
        '<=': operator.le, '>=': operator.ge, '==': operator.eq,
        '<': operator.lt, '>': operator.gt,
    }
    value = metrics.get(control['metric'], 0)
    pass_op = ops.get(control['pass_operator'])
    if pass_op and pass_op(value, control['pass_value']):
        return 'pass', value
    if control.get('warn_operator') and control.get('warn_value') is not None:
        warn_op = ops.get(control['warn_operator'])
        if warn_op and warn_op(value, control['warn_value']):
            return 'warn', value
    return 'fail', value


def _format_metric_label(metric):
    """Human-readable label for a metric key."""
    labels = {
        't0_count': 'Control Plane (T0) identities',
        'dormant_privileged': 'dormant privileged accounts',
        'expired_credentials': 'expired credentials',
        'expiring_credentials_30d': 'credentials expiring within 30 days',
        'unowned_spns': 'service principals without owners',
        'hipaa_violations': 'roles with HIPAA violation mappings',
        'mfa_not_enforced': 'users without MFA enforced',
        'excessive_permissions': 'identities with excessive permissions',
        'stale_accounts': 'stale/unused accounts',
        'no_credential_rotation': 'credentials not rotated in 180+ days',
    }
    return labels.get(metric, metric)


def get_dashboard_compliance():
    """
    Data-driven compliance scorecard. Loads enabled frameworks and controls from DB,
    evaluates each control against computed identity posture metrics.
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        metrics = _compute_compliance_metrics(cursor, latest_run)
        frameworks = db.get_compliance_frameworks(enabled_only=True)

        scorecard = {}
        for fw in frameworks:
            controls_out = []
            for ctrl in fw['controls']:
                status, value = _evaluate_control(ctrl, metrics)
                label = _format_metric_label(ctrl['metric'])
                if status == 'pass':
                    detail = f"{value} {label} — within limits"
                elif status == 'warn':
                    detail = f"{value} {label} — approaching threshold"
                else:
                    detail = f"{value} {label} — exceeds acceptable limit (target: {ctrl['pass_operator']}{int(ctrl['pass_value'])})"
                controls_out.append({
                    'id': ctrl['control_id'],
                    'name': ctrl['name'],
                    'status': status,
                    'detail': detail,
                    'metric': ctrl['metric'],
                    'value': value,
                    'pass_threshold': f"{ctrl['pass_operator']}{int(ctrl['pass_value'])}",
                    'drilldown_url': ctrl.get('drilldown_url'),
                })

            passes = sum(1 for c in controls_out if c['status'] == 'pass')
            scorecard[fw['key']] = {
                'name': fw['name'],
                'version': fw.get('version'),
                'description': fw.get('description'),
                'controls': controls_out,
                'score': round(passes / len(controls_out) * 100) if controls_out else 0,
                'pass_count': passes,
                'warn_count': sum(1 for c in controls_out if c['status'] == 'warn'),
                'fail_count': sum(1 for c in controls_out if c['status'] == 'fail'),
                'total_controls': len(controls_out),
            }

        return jsonify(scorecard)
    finally:
        cursor.close()
        db.close()


def get_compliance_frameworks_list():
    """GET /api/compliance/frameworks — list all frameworks (enabled and disabled)."""
    db = _db()
    try:
        frameworks = db.get_compliance_frameworks(enabled_only=False)
        return jsonify(frameworks)
    finally:
        db.close()


def toggle_compliance_framework_handler(framework_id):
    """PATCH /api/compliance/frameworks/<id> — toggle enabled state."""
    db = _db()
    try:
        data = request.get_json() or {}
        enabled = data.get('enabled')
        if enabled is None:
            return jsonify({'error': 'Missing "enabled" field'}), 400
        result = db.toggle_compliance_framework(framework_id, bool(enabled))
        if not result:
            return jsonify({'error': 'Framework not found'}), 404
        try:
            _log(db,
                'settings',
                f'Compliance framework "{result["name"]}" {"enabled" if enabled else "disabled"}',
                {'framework_id': framework_id, 'enabled': enabled}
            )
        except Exception:
            pass
        return jsonify(result)
    finally:
        db.close()


def get_compliance_trends_handler():
    """
    GET /api/compliance/trends
    Returns compliance score history per framework across discovery runs.
    Backfills snapshots from existing runs if table is empty.
    """
    fw_filter = request.args.get('framework')
    limit = min(int(request.args.get('limit', 20)), 50)

    db = _db()
    try:
        # Backfill: if no snapshots exist, compute for the last N completed runs
        if db.get_compliance_snapshot_count() == 0:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT id FROM discovery_runs
                WHERE status = 'completed' AND tenant_id = %s
                ORDER BY id DESC LIMIT %s
            """, (_tenant_id(), limit))
            run_ids = [r[0] for r in cursor.fetchall()]
            cursor.close()

            if run_ids:
                frameworks = db.get_compliance_frameworks(enabled_only=True)
                for rid in run_ids:
                    cursor = db.conn.cursor()
                    try:
                        metrics = _compute_compliance_metrics(cursor, rid)
                    except Exception:
                        cursor.close()
                        continue
                    cursor.close()
                    for fw in frameworks:
                        pass_count = 0
                        warn_count = 0
                        for ctrl in fw['controls']:
                            status, _ = _evaluate_control(ctrl, metrics)
                            if status == 'pass':
                                pass_count += 1
                            elif status == 'warn':
                                warn_count += 1
                        total = len(fw['controls'])
                        fail_count = total - pass_count - warn_count
                        score = round(pass_count / total * 100) if total else 0
                        db.save_compliance_snapshot(
                            rid, fw['key'], fw['name'], score,
                            pass_count, warn_count, fail_count, total, metrics
                        )

        runs = db.get_compliance_trends(limit=limit)

        if fw_filter:
            # Filter to single framework, flatten
            filtered = []
            for run in runs:
                fw_data = run['frameworks'].get(fw_filter)
                if fw_data:
                    filtered.append({
                        'run_id': run['run_id'],
                        'date': run['date'],
                        'score': fw_data['score'],
                        'pass_count': fw_data['pass_count'],
                        'warn_count': fw_data['warn_count'],
                        'fail_count': fw_data['fail_count'],
                        'total_controls': fw_data['total_controls'],
                    })
            return jsonify({'runs': filtered, 'count': len(filtered)})

        return jsonify({'runs': runs, 'count': len(runs)})
    finally:
        db.close()


def get_compliance_gap_analysis():
    """
    GET /api/compliance/gap-analysis
    Query params: framework (optional), format (json|csv)
    Returns per-control status with evidence identities and matched remediation playbooks.
    """
    import io as _io
    import csv as _csv
    from datetime import datetime, timezone

    fw_filter = request.args.get('framework')
    out_format = request.args.get('format', 'json')

    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        metrics = _compute_compliance_metrics(cursor, latest_run)
        frameworks = db.get_compliance_frameworks(enabled_only=True)
        if fw_filter:
            frameworks = [fw for fw in frameworks if fw['key'] == fw_filter]

        # Evaluate all controls, collect needed metrics for evidence
        needed_metrics = set()
        fw_results = {}
        for fw in frameworks:
            controls_out = []
            for ctrl in fw['controls']:
                status, value = _evaluate_control(ctrl, metrics)
                label = _format_metric_label(ctrl['metric'])
                if status == 'pass':
                    detail = f"{value} {label} — within limits"
                elif status == 'warn':
                    detail = f"{value} {label} — approaching threshold"
                else:
                    detail = f"{value} {label} — exceeds acceptable limit (target: {ctrl['pass_operator']}{int(ctrl['pass_value'])})"
                if status != 'pass':
                    needed_metrics.add(ctrl['metric'])
                controls_out.append({
                    'control_id': ctrl['control_id'],
                    'name': ctrl['name'],
                    'status': status,
                    'metric': ctrl['metric'],
                    'value': value,
                    'pass_threshold': f"{ctrl['pass_operator']}{int(ctrl['pass_value'])}",
                    'detail': detail,
                    'drilldown_url': ctrl.get('drilldown_url'),
                })
            fw_results[fw['key']] = {'name': fw['name'], 'version': fw.get('version'), 'controls': controls_out}

        # Batch-fetch evidence for non-passing metrics
        evidence = _compute_compliance_evidence(cursor, latest_run, needed_metrics) if needed_metrics else {}

        # Fetch all remediation playbooks once
        cursor.execute("SELECT id, title, description, impact, effort, compliance_refs FROM remediation_playbooks ORDER BY priority_score DESC")
        all_playbooks = []
        for row in cursor.fetchall():
            refs = row[5] if isinstance(row[5], list) else []
            all_playbooks.append({'id': row[0], 'title': row[1], 'description': row[2], 'impact': row[3], 'effort': row[4], 'compliance_refs': refs})

        # Attach evidence + playbooks to non-passing controls, compute scores
        total_controls = 0
        total_passing = 0
        total_warnings = 0
        total_failing = 0
        for fw_key, fw_data in fw_results.items():
            pass_count = 0
            warn_count = 0
            fail_count = 0
            for ctrl in fw_data['controls']:
                total_controls += 1
                if ctrl['status'] == 'pass':
                    pass_count += 1
                    total_passing += 1
                    ctrl['evidence_identities'] = []
                    ctrl['evidence_count'] = 0
                    ctrl['remediation_playbooks'] = []
                else:
                    if ctrl['status'] == 'warn':
                        warn_count += 1
                        total_warnings += 1
                    else:
                        fail_count += 1
                        total_failing += 1
                    ctrl['evidence_identities'] = evidence.get(ctrl['metric'], [])
                    ctrl['evidence_count'] = ctrl['value']
                    ctrl['remediation_playbooks'] = _match_playbooks_to_control(all_playbooks, ctrl['control_id'], fw_key)
            n = len(fw_data['controls'])
            fw_data['score'] = round(pass_count / n * 100) if n else 0
            fw_data['pass_count'] = pass_count
            fw_data['warn_count'] = warn_count
            fw_data['fail_count'] = fail_count
            fw_data['total_controls'] = n

        overall_score = round(total_passing / total_controls * 100) if total_controls else 0

        result = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'run_id': latest_run,
            'overall_score': overall_score,
            'total_controls': total_controls,
            'passing': total_passing,
            'warnings': total_warnings,
            'failing': total_failing,
            'frameworks': fw_results,
        }

        if out_format == 'csv':
            output = _io.StringIO()
            writer = _csv.writer(output)
            writer.writerow(['Framework', 'Control ID', 'Control Name', 'Status',
                             'Metric Value', 'Threshold', 'Evidence Count', 'Evidence Identities'])
            for fw_key, fw_data in fw_results.items():
                for ctrl in fw_data['controls']:
                    names = '; '.join(e['display_name'] for e in ctrl.get('evidence_identities', []))
                    writer.writerow([
                        fw_data['name'], ctrl['control_id'], ctrl['name'],
                        ctrl['status'], ctrl['value'], ctrl['pass_threshold'],
                        ctrl.get('evidence_count', 0), names,
                    ])
            from flask import Response
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=compliance-gap-analysis-{datetime.now().strftime("%Y%m%d")}.csv'}
            )

        return jsonify(result)
    finally:
        cursor.close()
        db.close()


def get_compliance_intelligence():
    """
    GET /api/compliance/intelligence
    Returns risk-weighted compliance scoring, root cause clustering,
    cloud failure counts, top risk drivers, and trend mini.
    """
    from datetime import datetime, timezone
    from psycopg2.extras import RealDictCursor

    SEVERITY_MULT = {'critical': 2.0, 'high': 1.5, 'medium': 1.0, 'low': 0.8}
    SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    db = _db()
    cursor = db.conn.cursor()
    rc_cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        metrics = _compute_compliance_metrics(cursor, latest_run)
        frameworks = db.get_compliance_frameworks(enabled_only=True)

        # Fetch root causes
        rc_cursor.execute("SELECT * FROM compliance_root_causes ORDER BY display_order")
        root_causes_rows = [dict(r) for r in rc_cursor.fetchall()]
        rc_by_id = {rc['id']: rc for rc in root_causes_rows}

        # Evaluate all controls
        total_controls = 0
        total_passing = 0
        total_warnings = 0
        total_failing = 0
        total_weighted_max = 0.0
        total_weighted_pass = 0.0
        cloud_failures = {}
        all_failing_controls = []
        needed_metrics = set()
        fw_results = {}

        for fw in frameworks:
            fw_pass = 0
            fw_warn = 0
            fw_fail = 0
            fw_weighted_max = 0.0
            fw_weighted_pass = 0.0
            controls_out = []

            for ctrl in fw['controls']:
                status, value = _evaluate_control(ctrl, metrics)
                label = _format_metric_label(ctrl['metric'])
                severity = ctrl.get('severity', 'medium')
                weight = ctrl.get('weight', 5)
                cloud = ctrl.get('cloud', 'azure')
                mult = SEVERITY_MULT.get(severity, 1.0)
                w_score = weight * mult

                fw_weighted_max += w_score
                total_weighted_max += w_score

                if status == 'pass':
                    detail = f"{value} {label} — within limits"
                    fw_pass += 1
                    total_passing += 1
                    fw_weighted_pass += w_score
                    total_weighted_pass += w_score
                elif status == 'warn':
                    detail = f"{value} {label} — approaching threshold"
                    fw_warn += 1
                    total_warnings += 1
                    needed_metrics.add(ctrl['metric'])
                else:
                    detail = f"{value} {label} — exceeds acceptable limit (target: {ctrl['pass_operator']}{int(ctrl['pass_value'])})"
                    fw_fail += 1
                    total_failing += 1
                    needed_metrics.add(ctrl['metric'])
                    # Cloud failure tracking
                    cloud_failures[cloud] = cloud_failures.get(cloud, 0) + 1
                    all_failing_controls.append({
                        'control_id': ctrl['control_id'],
                        'name': ctrl['name'],
                        'framework': fw['name'],
                        'framework_key': fw['key'],
                        'severity': severity,
                        'weight': weight,
                        'value': value,
                        'root_cause_id': ctrl.get('root_cause_id'),
                    })

                total_controls += 1
                controls_out.append({
                    'control_id': ctrl['control_id'],
                    'name': ctrl['name'],
                    'status': status,
                    'metric': ctrl['metric'],
                    'value': value,
                    'pass_threshold': f"{ctrl['pass_operator']}{int(ctrl['pass_value'])}",
                    'detail': detail,
                    'drilldown_url': ctrl.get('drilldown_url'),
                    'severity': severity,
                    'weight': weight,
                    'cloud': cloud,
                    'pillar': ctrl.get('pillar'),
                    'root_cause_id': ctrl.get('root_cause_id'),
                })

            n = len(fw['controls'])
            fw_score = round(fw_pass / n * 100) if n else 0
            fw_rw_score = round(fw_weighted_pass / fw_weighted_max * 100) if fw_weighted_max else 0
            fw_results[fw['key']] = {
                'name': fw['name'],
                'version': fw.get('version'),
                'score': fw_score,
                'risk_weighted_score': fw_rw_score,
                'pass_count': fw_pass,
                'warn_count': fw_warn,
                'fail_count': fw_fail,
                'total_controls': n,
                'controls': controls_out,
            }

        overall_score = round(total_passing / total_controls * 100) if total_controls else 0
        risk_weighted_score = round(total_weighted_pass / total_weighted_max * 100) if total_weighted_max else 0

        # Top risk drivers — top 3 failing controls by severity rank then weight DESC
        all_failing_controls.sort(key=lambda c: (SEVERITY_RANK.get(c['severity'], 9), -c['weight']))
        top_risk_drivers = all_failing_controls[:3]

        # Root cause clusters
        rc_clusters = {}
        for ctrl in all_failing_controls:
            rc_id = ctrl.get('root_cause_id')
            if not rc_id or rc_id not in rc_by_id:
                continue
            if rc_id not in rc_clusters:
                rc = rc_by_id[rc_id]
                rc_clusters[rc_id] = {
                    'id': rc_id,
                    'code': rc['code'],
                    'title': rc['title'],
                    'description': rc.get('description'),
                    'category': rc.get('category'),
                    'recommendation': rc.get('recommendation'),
                    'linked_controls': [],
                    'frameworks_impacted': set(),
                    'total_weight': 0,
                    'affected_entities': 0,
                }
            cluster = rc_clusters[rc_id]
            cluster['linked_controls'].append({
                'control_id': ctrl['control_id'],
                'name': ctrl['name'],
                'framework': ctrl['framework'],
                'severity': ctrl['severity'],
            })
            cluster['frameworks_impacted'].add(ctrl['framework_key'])
            cluster['total_weight'] += ctrl['weight']
            cluster['affected_entities'] += ctrl.get('value', 0)

        # Compute impact scores and format
        max_raw = max((c['total_weight'] * len(c['frameworks_impacted']) * max(c['affected_entities'], 1) for c in rc_clusters.values()), default=1)
        root_causes_out = []
        for rc in rc_clusters.values():
            raw = rc['total_weight'] * len(rc['frameworks_impacted']) * max(rc['affected_entities'], 1)
            impact = round(raw / max_raw * 100) if max_raw else 0
            root_causes_out.append({
                'id': rc['id'],
                'code': rc['code'],
                'title': rc['title'],
                'description': rc['description'],
                'category': rc['category'],
                'recommendation': rc['recommendation'],
                'impact_score': impact,
                'linked_controls': rc['linked_controls'],
                'frameworks_impacted': len(rc['frameworks_impacted']),
                'affected_entities': rc['affected_entities'],
            })
        root_causes_out.sort(key=lambda x: -x['impact_score'])

        # Trend mini — last 6 snapshots
        trend_mini = []
        try:
            cursor.execute("""
                SELECT DISTINCT ON (cs.run_id) cs.run_id,
                    dr.completed_at,
                    ROUND(AVG(cs.score) OVER (PARTITION BY cs.run_id)) as overall_score
                FROM compliance_snapshots cs
                JOIN discovery_runs dr ON dr.id = cs.run_id
                ORDER BY cs.run_id DESC
                LIMIT 6
            """)
            for row in cursor.fetchall():
                trend_mini.append({
                    'run_id': row[0],
                    'date': row[1].isoformat() if row[1] else None,
                    'overall_score': int(row[2]) if row[2] else 0,
                })
            trend_mini.reverse()
        except Exception:
            pass

        # Batch-fetch evidence for non-passing controls
        evidence = _compute_compliance_evidence(cursor, latest_run, needed_metrics) if needed_metrics else {}
        # Attach evidence to controls in fw_results
        for fw_key, fw_data in fw_results.items():
            for ctrl in fw_data['controls']:
                if ctrl['status'] == 'pass':
                    ctrl['evidence_identities'] = []
                    ctrl['evidence_count'] = 0
                else:
                    ctrl['evidence_identities'] = evidence.get(ctrl['metric'], [])
                    ctrl['evidence_count'] = ctrl['value']

        return jsonify({
            'overall_score': overall_score,
            'risk_weighted_score': risk_weighted_score,
            'total_controls': total_controls,
            'passing': total_passing,
            'warnings': total_warnings,
            'failing': total_failing,
            'cloud_failures': cloud_failures,
            'top_risk_drivers': top_risk_drivers,
            'frameworks': fw_results,
            'root_causes': root_causes_out,
            'trend_mini': trend_mini,
            'generated_at': datetime.now(timezone.utc).isoformat(),
        })
    finally:
        rc_cursor.close()
        cursor.close()
        db.close()


def get_dashboard_posture():
    """
    Dashboard posture data: credential health, dormant counts, posture score,
    and previous run comparison for trend indicators.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        # Get latest two completed runs for trend comparison (tenant-scoped)
        cursor.execute(
            """
            SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
            FROM discovery_runs
            WHERE status = 'completed' AND tenant_id = %s
            ORDER BY id DESC
            LIMIT 2
            """,
            (_tenant_id(),),
        )
        runs = cursor.fetchall()

        if not runs:
            return jsonify({"error": "No completed discovery runs found"}), 404

        current_run_id = runs[0][0]
        current_run = {
            "id": runs[0][0],
            "completed_at": runs[0][1].isoformat() if runs[0][1] else None,
            "total_identities": runs[0][2] or 0,
            "critical_count": runs[0][3] or 0,
            "high_count": runs[0][4] or 0,
            "medium_count": runs[0][5] or 0,
        }

        previous_run = None
        if len(runs) > 1:
            previous_run = {
                "id": runs[1][0],
                "completed_at": runs[1][1].isoformat() if runs[1][1] else None,
                "total_identities": runs[1][2] or 0,
                "critical_count": runs[1][3] or 0,
                "high_count": runs[1][4] or 0,
                "medium_count": runs[1][5] or 0,
            }

        # Credential health breakdown
        cursor.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE credential_expiration IS NOT NULL
                    AND credential_expiration < NOW()) as expired,
                COUNT(*) FILTER (WHERE credential_expiration IS NOT NULL
                    AND credential_expiration >= NOW()
                    AND credential_expiration < NOW() + INTERVAL '30 days') as expiring_soon,
                COUNT(*) FILTER (WHERE credential_expiration IS NOT NULL
                    AND credential_expiration >= NOW() + INTERVAL '30 days') as healthy,
                COUNT(*) FILTER (WHERE credential_count = 0
                    OR credential_count IS NULL) as no_credentials
            FROM identities
            WHERE discovery_run_id = %s
            """,
            (current_run_id,),
        )
        cred_row = cursor.fetchone()
        credential_health = {
            "expired": cred_row[0] or 0,
            "expiring_soon": cred_row[1] or 0,
            "healthy": cred_row[2] or 0,
            "no_credentials": cred_row[3] or 0,
        }

        # Dormant identities (stale activity)
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM identities
            WHERE discovery_run_id = %s
              AND activity_status = 'stale'
            """,
            (current_run_id,),
        )
        dormant_count = cursor.fetchone()[0] or 0

        # No-owner count
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM identities
            WHERE discovery_run_id = %s
              AND (owner_count = 0 OR owner_count IS NULL)
              AND COALESCE(identity_category, '') NOT IN ('human_user', 'guest', 'microsoft_internal')
            """,
            (current_run_id,),
        )
        no_owner_count = cursor.fetchone()[0] or 0

        # Posture score: % of identities at low/info risk
        total = current_run["total_identities"] or 1
        high_risk = (current_run["critical_count"] + current_run["high_count"]
                     + current_run["medium_count"])
        posture_score = round(((total - high_risk) / total) * 100, 1)

        previous_posture_score = None
        if previous_run:
            prev_total = previous_run["total_identities"] or 1
            prev_high_risk = (previous_run["critical_count"] + previous_run["high_count"]
                              + previous_run["medium_count"])
            previous_posture_score = round(((prev_total - prev_high_risk) / prev_total) * 100, 1)

        return jsonify({
            "current_run": current_run,
            "previous_run": previous_run,
            "posture_score": posture_score,
            "previous_posture_score": previous_posture_score,
            "credential_health": credential_health,
            "dormant_count": dormant_count,
            "no_owner_count": no_owner_count,
            "expiring_credentials_count": credential_health["expiring_soon"],
        })

    finally:
        cursor.close()
        db.close()


def get_trust_dashboard():
    """
    Trust & Federation data for the Dashboard Trust tab.
    Returns: external identity breakdown, trust path summary, cross-tenant access.
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        # External identity breakdown
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') = 'guest') as guests,
                COUNT(*) FILTER (WHERE COALESCE(is_federated, false) = true) as federated,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') = 'guest'
                    AND (EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                         OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id))
                ) as guests_with_roles,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') = 'guest'
                    AND EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'global administrator','privileged role administrator',
                            'application administrator','user administrator','security administrator'
                        ))
                ) as guest_admins,
                COUNT(*) FILTER (WHERE COALESCE(identity_category, '') = 'service_principal'
                    AND COALESCE(service_principal_type, '') = 'Application'
                    AND app_owner_organization_id IS NOT NULL
                    AND app_owner_organization_id != ''
                ) as multi_tenant_apps,
                COUNT(*) FILTER (WHERE tenant_or_org_id IS NOT NULL AND tenant_or_org_id != '') as cross_tenant
            FROM identities i
            WHERE i.discovery_run_id = %s
        """, (latest_run,))
        r = cursor.fetchone()
        external = {
            "total_identities": r[0] or 0,
            "guests": r[1] or 0,
            "federated": r[2] or 0,
            "guests_with_roles": r[3] or 0,
            "guest_admins": r[4] or 0,
            "multi_tenant_apps": r[5] or 0,
            "cross_tenant": r[6] or 0,
        }

        # Top external organizations (by tenant_or_org_id)
        cursor.execute("""
            SELECT tenant_or_org_id, COUNT(*) as cnt,
                   COUNT(*) FILTER (WHERE risk_level IN ('critical', 'high')) as high_risk
            FROM identities
            WHERE discovery_run_id = %s
              AND tenant_or_org_id IS NOT NULL AND tenant_or_org_id != ''
            GROUP BY tenant_or_org_id
            ORDER BY cnt DESC
            LIMIT 10
        """, (latest_run,))
        orgs = [{"org_id": row[0], "identity_count": row[1], "high_risk_count": row[2]} for row in cursor.fetchall()]

        # Guest identities list (top 10 by risk)
        cursor.execute("""
            SELECT identity_id, display_name, risk_level, COALESCE(risk_score, 0),
                   activity_status, tenant_or_org_id
            FROM identities
            WHERE discovery_run_id = %s AND COALESCE(identity_category, '') = 'guest'
            ORDER BY COALESCE(risk_score, 0) DESC
            LIMIT 10
        """, (latest_run,))
        top_guests = [{
            "identity_id": row[0], "display_name": row[1], "risk_level": row[2],
            "risk_score": row[3], "activity_status": row[4], "org_id": row[5],
        } for row in cursor.fetchall()]

        return jsonify({
            "external_summary": external,
            "top_organizations": orgs,
            "top_risk_guests": top_guests,
        })
    finally:
        cursor.close()
        db.close()


def get_credential_intelligence():
    """
    Credential Intelligence data for the Dashboard Credential tab.
    Returns: secret age distribution, auth method breakdown, rotation compliance.
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        # Secret age distribution — buckets by age of oldest credential
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE c.age_days IS NOT NULL AND c.age_days < 30) as age_lt_30,
                COUNT(*) FILTER (WHERE c.age_days >= 30 AND c.age_days < 90) as age_30_90,
                COUNT(*) FILTER (WHERE c.age_days >= 90 AND c.age_days < 180) as age_90_180,
                COUNT(*) FILTER (WHERE c.age_days >= 180 AND c.age_days < 365) as age_180_365,
                COUNT(*) FILTER (WHERE c.age_days >= 365) as age_gt_365
            FROM (
                SELECT i.id,
                    EXTRACT(EPOCH FROM (NOW() - MIN(cr.start_date))) / 86400 as age_days
                FROM identities i
                JOIN credentials cr ON cr.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                GROUP BY i.id
            ) c
        """, (latest_run,))
        age_row = cursor.fetchone()
        secret_age = {
            "<30d": age_row[0] or 0,
            "30-90d": age_row[1] or 0,
            "90-180d": age_row[2] or 0,
            "180-365d": age_row[3] or 0,
            ">365d": age_row[4] or 0,
        }

        # Auth method breakdown — credential types
        cursor.execute("""
            SELECT
                COALESCE(cr.credential_type, 'unknown') as ctype,
                COUNT(DISTINCT cr.identity_db_id) as identity_count
            FROM credentials cr
            JOIN identities i ON i.id = cr.identity_db_id
            WHERE i.discovery_run_id = %s
            GROUP BY ctype
            ORDER BY identity_count DESC
        """, (latest_run,))
        auth_methods = {}
        for row in cursor.fetchall():
            auth_methods[row[0]] = row[1]

        # Rotation compliance — identities with creds needing rotation
        cursor.execute("""
            SELECT
                COUNT(DISTINCT i.id) FILTER (WHERE cr.end_date IS NOT NULL AND cr.end_date < NOW()) as rotation_overdue,
                COUNT(DISTINCT i.id) FILTER (WHERE cr.end_date IS NOT NULL
                    AND cr.end_date >= NOW()
                    AND cr.end_date < NOW() + INTERVAL '30 days') as rotation_soon,
                COUNT(DISTINCT i.id) FILTER (WHERE cr.end_date IS NOT NULL
                    AND cr.end_date >= NOW() + INTERVAL '30 days') as rotation_ok,
                COUNT(DISTINCT i.id) as total_with_creds,
                COUNT(DISTINCT i.id) FILTER (WHERE cr.credential_type = 'password'
                    AND EXTRACT(EPOCH FROM (NOW() - cr.start_date)) / 86400 > 90) as stale_passwords,
                COUNT(DISTINCT i.id) FILTER (WHERE (
                    SELECT COUNT(*) FROM credentials c2
                    WHERE c2.identity_db_id = i.id AND (c2.end_date IS NULL OR c2.end_date > NOW())
                ) > 1) as multi_active
            FROM identities i
            JOIN credentials cr ON cr.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
        """, (latest_run,))
        rot_row = cursor.fetchone()
        rotation = {
            "overdue": rot_row[0] or 0,
            "due_soon": rot_row[1] or 0,
            "compliant": rot_row[2] or 0,
            "total_with_creds": rot_row[3] or 0,
            "stale_passwords": rot_row[4] or 0,
            "multi_active_secrets": rot_row[5] or 0,
        }

        return jsonify({
            "secret_age_distribution": secret_age,
            "auth_method_breakdown": auth_methods,
            "rotation_compliance": rotation,
        })
    finally:
        cursor.close()
        db.close()


def get_identity_summary():
    """
    Get identity counts grouped by category for the dashboard.

    Returns:
        JSON with category breakdown including risk counts per category
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        # Get latest completed discovery run (tenant-scoped)
        cursor.execute("SELECT MAX(id), MAX(completed_at) FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s", (_tenant_id(),))
        row = cursor.fetchone()
        run_id = row[0] if row else None
        completed_at = row[1] if row else None

        if not run_id:
            return jsonify({
                "run_id": None,
                "completed_at": None,
                "categories": {}
            })

        # Get individual identities to properly categorize each one
        # This ensures Microsoft internal detection works correctly
        cursor.execute(
            """
            SELECT
                display_name,
                identity_type,
                COALESCE(identity_category, 'unknown') as category,
                COALESCE(risk_level, 'unknown') as risk
            FROM identities
            WHERE discovery_run_id = %s
            """,
            (run_id,),
        )
        rows = cursor.fetchall()

        # Build category structure with proper Microsoft internal detection
        categories = {}
        for display_name, identity_type, raw_cat, risk in rows:
            # Normalize category key
            cat = _normalize_category_key(raw_cat)

            if cat not in categories:
                categories[cat] = {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                }
            categories[cat]["total"] += 1
            if risk in categories[cat]:
                categories[cat][risk] += 1

        # Count monitored resources per cloud (subscriptions, accounts, projects)
        # Azure: distinct subscription IDs from role_assignments scopes
        cursor.execute("""
            SELECT COUNT(DISTINCT
                CASE
                    WHEN ra.scope LIKE '/subscriptions/%%'
                    THEN SPLIT_PART(ra.scope, '/', 3)
                END
            )
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
              AND ra.scope LIKE '/subscriptions/%%'
        """, (run_id,))
        azure_sub_count = cursor.fetchone()[0] or 0

        # Also get the distinct subscription names/IDs for the detail view
        cursor.execute("""
            SELECT DISTINCT SPLIT_PART(ra.scope, '/', 3) as sub_id
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
              AND ra.scope LIKE '/subscriptions/%%'
            ORDER BY sub_id
        """, (run_id,))
        azure_subs = [r[0] for r in cursor.fetchall() if r[0]]

        return jsonify({
            "run_id": run_id,
            "completed_at": completed_at.isoformat() if completed_at else None,
            "categories": categories,
            "monitored_resources": {
                "azure": {
                    "subscriptions": azure_sub_count,
                    "subscription_ids": azure_subs,
                },
                "aws": {
                    "accounts": 0,
                    "account_ids": [],
                },
                "gcp": {
                    "projects": 0,
                    "project_ids": [],
                },
            }
        })

    finally:
        cursor.close()
        db.close()


# =====================================================================
# Access Graph: Trust, Scope, Secret Exposure, Graph Visualization
# =====================================================================

_ISSUER_LABELS = {
    "token.actions.githubusercontent.com": "GitHub Actions",
    "login.microsoftonline.com": "Azure AD",
    "sts.windows.net": "Azure AD",
    "accounts.google.com": "Google Cloud",
    "oidc.eks.": "AWS EKS",
    "vstoken.dev.azure.com": "Azure DevOps",
}

_RISK_ORDER_GRAPH = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _issuer_label(issuer):
    if not issuer:
        return "Unknown"
    for fragment, label in _ISSUER_LABELS.items():
        if fragment in issuer:
            return label
    parts = issuer.replace("https://", "").replace("http://", "").split("/")
    return parts[0] if parts else issuer


def _max_risk(a, b):
    return a if _RISK_ORDER_GRAPH.get(a, 0) >= _RISK_ORDER_GRAPH.get(b, 0) else b


def _parse_arm_scope(scope):
    parts = scope.strip("/").split("/") if scope else []
    sub_id = rg_name = res_type = res_name = None
    lower_parts = [p.lower() for p in parts]
    if "subscriptions" in lower_parts:
        idx = lower_parts.index("subscriptions")
        if idx + 1 < len(parts):
            sub_id = parts[idx + 1]
    if "resourcegroups" in lower_parts:
        idx = lower_parts.index("resourcegroups")
        if idx + 1 < len(parts):
            rg_name = parts[idx + 1]
    if "providers" in lower_parts:
        idx = lower_parts.index("providers")
        if idx + 2 < len(parts):
            res_type = f"{parts[idx+1]}/{parts[idx+2]}"
            if idx + 3 < len(parts):
                res_name = parts[-1]
    return sub_id, rg_name, res_type, res_name


def _build_scope_label(scope):
    """Build a human-readable label from an ARM scope path."""
    sub_id, rg_name, res_type, res_name = _parse_arm_scope(scope)
    if not sub_id:
        return "Entire Directory" if not scope or scope == "/" else scope
    parts = []
    # Short sub ID (first 8 chars)
    parts.append(f"Sub: {sub_id[:8]}...")
    if rg_name:
        parts.append(f"RG: {rg_name}")
    if res_name:
        # Extract short resource type (e.g. "storageAccounts" from "Microsoft.Storage/storageAccounts")
        short_type = res_type.split("/")[-1] if res_type else ""
        parts.append(f"{short_type}: {res_name}")
    return " / ".join(parts)


def get_identity_graph_data(identity_id):
    """
    Return trust relationships, effective scope, secret exposure analysis,
    and pre-computed graph nodes/edges for dual-mode visualization.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        cursor.execute("""
            SELECT id, identity_id, display_name, identity_category, risk_level,
                   COALESCE(risk_score, 0), activity_status,
                   COALESCE(cloud, 'azure'), COALESCE(owner_count, 0),
                   COALESCE(credential_count, 0)
            FROM identities
            WHERE identity_id = %s
            ORDER BY discovery_run_id DESC LIMIT 1
        """, (identity_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Identity not found"}), 404

        db_id = row[0]
        ident = {
            "identity_id": row[1],
            "display_name": row[2] or "",
            "identity_category": _normalize_category_key(row[3] or ""),
            "risk_level": row[4] or "info",
            "risk_score": int(row[5]),
            "activity_status": row[6] or "unknown",
            "cloud": row[7],
            "owner_count": int(row[8]),
            "credential_count": int(row[9]),
        }

        roles = db.get_identity_roles_enriched(db_id)
        credentials = db.get_identity_credentials(db_id)
        owners = db.get_ownership(db_id)
        graph_perms = db.get_graph_permissions(db_id)
        app_roles = db.get_app_roles(db_id)

        is_dormant = ident["activity_status"] in ("stale", "never_used")
        has_priv_roles = any(r.get("risk_level") in ("critical", "high") for r in roles)

        # ── TRUST RELATIONSHIPS ──────────────────────────────────
        federated_trusts = []
        for c in credentials:
            if c.get("credential_type") == "federated":
                issuer = c.get("issuer") or ""
                label = _issuer_label(issuer)
                risk = "high" if has_priv_roles else "medium"
                reason = f"External identity from {label} can authenticate as this identity"
                if has_priv_roles:
                    reason += " (privileged roles present)"
                federated_trusts.append({
                    "credential_id": c.get("id"),
                    "issuer": issuer,
                    "subject": c.get("subject") or "",
                    "issuer_label": label,
                    "trust_risk": risk,
                    "trust_reason": reason,
                })

        ownership_edges = [{
            "owner_object_id": o.get("owner_object_id"),
            "owner_display_name": o.get("owner_display_name") or "Unknown",
            "owner_upn": o.get("owner_upn"),
            "owner_type": o.get("owner_type", "user"),
            "is_primary_owner": o.get("is_primary_owner", False),
        } for o in owners]

        role_edges = [{
            "role_name": r.get("role_name"),
            "role_type": r.get("role_type", "azure"),
            "scope": r.get("scope") or "",
            "scope_type": r.get("scope_type") or "directory",
            "risk_level": r.get("risk_level") or "low",
            "usage_status": r.get("usage_status") or "unknown",
        } for r in roles]

        trust = {
            "federated_trusts": federated_trusts,
            "ownership_edges": ownership_edges,
            "role_edges": role_edges,
        }

        # ── EFFECTIVE SCOPE ──────────────────────────────────────
        subs = {}
        for r in roles:
            if r.get("role_type") != "azure":
                continue
            scope = r.get("scope") or ""
            sub_id, rg_name, res_type, res_name = _parse_arm_scope(scope)
            if not sub_id:
                continue
            if sub_id not in subs:
                subs[sub_id] = {"subscription_id": sub_id, "resource_groups": {}, "subscription_level_roles": []}
            s = subs[sub_id]
            if rg_name:
                if rg_name not in s["resource_groups"]:
                    s["resource_groups"][rg_name] = {"name": rg_name, "rg_level_roles": [], "resources": {}}
                rg = s["resource_groups"][rg_name]
                if res_type and res_name:
                    # Resource-level role
                    res_key = f"{res_type}:{res_name}"
                    if res_key not in rg["resources"]:
                        rg["resources"][res_key] = {"type": res_type, "name": res_name, "roles": []}
                    if r["role_name"] not in rg["resources"][res_key]["roles"]:
                        rg["resources"][res_key]["roles"].append(r["role_name"])
                else:
                    # RG-level role (no specific resource)
                    if r["role_name"] not in rg["rg_level_roles"]:
                        rg["rg_level_roles"].append(r["role_name"])
            else:
                if r["role_name"] not in s["subscription_level_roles"]:
                    s["subscription_level_roles"].append(r["role_name"])

        scope_hierarchy = []
        total_rgs = 0
        total_resources = 0
        for s in subs.values():
            rgs_out = []
            for rg in s["resource_groups"].values():
                res_list = list(rg["resources"].values())
                total_resources += len(res_list)
                rgs_out.append({
                    "name": rg["name"],
                    "roles": rg["rg_level_roles"],
                    "resources": res_list,
                })
            total_rgs += len(rgs_out)
            scope_hierarchy.append({
                "subscription_id": s["subscription_id"],
                "resource_groups": rgs_out,
                "subscription_level_roles": s["subscription_level_roles"],
            })

        entra_scopes = []
        for r in roles:
            if r.get("role_type") != "entra":
                continue
            ds = r.get("scope") or "/"
            label = "Entire Directory" if ds == "/" else f"Scoped: {ds}"
            entra_scopes.append({
                "role_name": r.get("role_name"),
                "directory_scope": ds,
                "scope_label": label,
                "risk_level": r.get("risk_level") or "low",
            })

        sub_count = len(subs)
        blast_parts = []
        if sub_count:
            blast_parts.append(f"{sub_count} subscription{'s' if sub_count != 1 else ''}")
        if total_rgs:
            blast_parts.append(f"{total_rgs} resource group{'s' if total_rgs != 1 else ''}")
        if total_resources:
            blast_parts.append(f"{total_resources} resource{'s' if total_resources != 1 else ''}")
        if entra_scopes:
            blast_parts.append(f"{len(entra_scopes)} Entra role{'s' if len(entra_scopes) != 1 else ''}")
        blast_label = ", ".join(blast_parts) if blast_parts else "No scoped access"

        effective_scope = {
            "subscription_count": sub_count,
            "resource_group_count": total_rgs,
            "resource_count": total_resources,
            "scope_hierarchy": scope_hierarchy,
            "entra_scopes": entra_scopes,
            "blast_radius_label": blast_label,
        }

        # ── SECRET EXPOSURE ──────────────────────────────────────
        now = datetime.utcnow()
        secret_exposure = []
        for c in credentials:
            flags = []
            risk = "low"
            ctype = c.get("credential_type", "")
            start = c.get("start_datetime")
            end = c.get("end_datetime")
            age_days = None
            days_to_expiry = int(c["days_to_expiry"]) if c.get("days_to_expiry") is not None else None

            if start:
                try:
                    age_days = (now - start).days
                except Exception:
                    pass

            if age_days is not None and age_days > 365:
                flags.append(f"Secret age {age_days} days - never rotated")
                risk = _max_risk(risk, "high")
            elif age_days is not None and age_days > 180:
                flags.append(f"Secret age {age_days} days - rotation recommended")
                risk = _max_risk(risk, "medium")

            if days_to_expiry is not None and days_to_expiry < 0:
                flags.append("Expired credential still present")
                risk = _max_risk(risk, "high")
            elif days_to_expiry is not None and days_to_expiry <= 30:
                flags.append(f"Expires in {days_to_expiry} days")
                risk = _max_risk(risk, "medium")

            if is_dormant and ctype == "secret":
                if not end or (end and end > now):
                    flags.append("Active secret on dormant identity - takeover risk")
                    risk = _max_risk(risk, "critical")

            if has_priv_roles and ctype == "secret":
                flags.append("Secret credential on privileged identity")
                risk = _max_risk(risk, "high")

            if ctype == "federated":
                issuer = c.get("issuer") or ""
                flags.append(f"Federated trust to {_issuer_label(issuer)}")
                if has_priv_roles:
                    flags.append("Identity has privileged roles - lateral movement risk")
                    risk = _max_risk(risk, "high")

            status = c.get("status") or "unknown"
            if ctype == "federated":
                status = "active"

            secret_exposure.append({
                "credential_id": c.get("id"),
                "credential_type": ctype,
                "display_name": c.get("display_name"),
                "age_days": age_days,
                "days_to_expiry": days_to_expiry,
                "status": status,
                "issuer": c.get("issuer"),
                "subject": c.get("subject"),
                "issuer_label": _issuer_label(c.get("issuer") or "") if ctype == "federated" else None,
                "exposure_flags": flags,
                "exposure_risk": risk,
            })

        secret_exposure.sort(key=lambda x: _RISK_ORDER_GRAPH.get(x["exposure_risk"], 0), reverse=True)

        # ── GRAPH PRE-COMPUTATION ────────────────────────────────
        cx, cy = 400, 250

        # Executive mode (3-5 nodes)
        exec_nodes = [{"id": "identity", "type": "identity", "position": {"x": cx, "y": cy},
            "data": {"label": ident["display_name"], "risk_level": ident["risk_level"],
                     "risk_score": ident["risk_score"], "category": ident["identity_category"]}}]
        exec_edges = []

        risk_lines = []
        if has_priv_roles:
            crit_roles = [r["role_name"] for r in roles if r.get("risk_level") == "critical"]
            if crit_roles:
                risk_lines.append(f"Critical roles: {', '.join(crit_roles[:3])}")
        crit_secrets = [s for s in secret_exposure if s["exposure_risk"] in ("critical", "high")]
        if crit_secrets:
            risk_lines.append(f"{len(crit_secrets)} credential exposure{'s' if len(crit_secrets) != 1 else ''}")
        if is_dormant and ident["credential_count"] > 0:
            risk_lines.append("Dormant identity with active credentials")
        high_perms = [p for p in graph_perms if p.get("risk_level") in ("critical", "high")]
        if high_perms:
            risk_lines.append(f"{len(high_perms)} high-risk API permission{'s' if len(high_perms) != 1 else ''}")

        if risk_lines:
            exec_nodes.append({"id": "risk", "type": "risk_summary",
                "position": {"x": cx + 300, "y": cy - 100},
                "data": {"label": risk_lines[0],
                         "detail": "; ".join(risk_lines[1:]) if len(risk_lines) > 1 else "",
                         "risk_level": ident["risk_level"]}})
            exec_edges.append({"id": "e-id-risk", "source": "identity", "target": "risk",
                "label": "top risk", "animated": True, "style": {"stroke": "#ef4444"}})

        if blast_label != "No scoped access":
            exec_nodes.append({"id": "blast", "type": "blast_radius",
                "position": {"x": cx + 300, "y": cy + 100},
                "data": {"label": blast_label}})
            exec_edges.append({"id": "e-id-blast", "source": "identity", "target": "blast",
                "label": "blast radius"})

        if federated_trusts:
            ft = federated_trusts[0]
            fl = ft["issuer_label"]
            if len(federated_trusts) > 1:
                fl += f" (+{len(federated_trusts) - 1} more)"
            exec_nodes.append({"id": "fed", "type": "federated_trust",
                "position": {"x": cx - 300, "y": cy - 100},
                "data": {"label": fl, "subject": ft["subject"], "trust_risk": ft["trust_risk"]}})
            exec_edges.append({"id": "e-fed-id", "source": "fed", "target": "identity",
                "label": "can act as", "animated": True, "style": {"stroke": "#f59e0b"}})

        if ownership_edges:
            primary = next((o for o in ownership_edges if o.get("is_primary_owner")), ownership_edges[0])
            ol = primary["owner_display_name"]
            if len(ownership_edges) > 1:
                ol += f" (+{len(ownership_edges) - 1})"
            exec_nodes.append({"id": "owner", "type": "owner",
                "position": {"x": cx - 300, "y": cy + 100},
                "data": {"label": ol, "owner_type": primary["owner_type"], "upn": primary.get("owner_upn")}})
            exec_edges.append({"id": "e-owner-id", "source": "owner", "target": "identity", "label": "manages"})

        # Technical mode — hierarchical ARM tree layout
        tech_nodes = [{"id": "identity", "type": "identity", "position": {"x": cx, "y": cy},
            "data": {"label": ident["display_name"], "risk_level": ident["risk_level"],
                     "risk_score": ident["risk_score"], "category": ident["identity_category"]}}]
        tech_edges = []

        # Role risk lookup for badge coloring in the tree
        role_risk_map = {}
        for r in role_edges:
            role_risk_map[r["role_name"]] = r.get("risk_level", "low")

        # ── Left column: owners + federated trusts ──
        left_y = 80
        for i, o in enumerate(ownership_edges):
            nid = f"owner-{i}"
            tech_nodes.append({"id": nid, "type": "owner",
                "position": {"x": cx - 350, "y": left_y},
                "data": {"label": o["owner_display_name"], "owner_type": o["owner_type"], "upn": o.get("owner_upn")}})
            tech_edges.append({"id": f"e-{nid}-id", "source": nid, "target": "identity", "label": "manages"})
            left_y += 80

        for i, ft in enumerate(federated_trusts):
            nid = f"fed-{i}"
            tech_nodes.append({"id": nid, "type": "federated_trust",
                "position": {"x": cx - 350, "y": left_y},
                "data": {"label": ft["issuer_label"], "subject": ft["subject"], "trust_risk": ft["trust_risk"]}})
            tech_edges.append({"id": f"e-{nid}-id", "source": nid, "target": "identity",
                "label": "can act as", "animated": True, "style": {"stroke": "#f59e0b"}})
            left_y += 80

        # ── Entra Directory branch (upper-right) ──
        # Roles embedded as data inside the entra_directory node
        right_y = 30
        if entra_scopes:
            entra_roles_data = []
            for es in entra_scopes:
                entra_roles_data.append({
                    "name": es["role_name"],
                    "risk_level": es.get("risk_level", "low"),
                })
            entra_nid = "entra-dir"
            # Height scales with role count
            entra_height = 55 + len(entra_scopes) * 28
            tech_nodes.append({"id": entra_nid, "type": "entra_directory",
                "position": {"x": cx + 280, "y": right_y},
                "data": {"label": "Entra Directory", "count": len(entra_scopes),
                         "roles": entra_roles_data}})
            tech_edges.append({"id": "e-id-entra", "source": "identity", "target": entra_nid,
                "label": "directory roles", "style": {"stroke": "#6366f1"}})
            right_y += entra_height + 20

        # ── ARM hierarchy tree (roles embedded inside each node) ──
        arm_y = max(right_y, 40)

        for si, sub_entry in enumerate(scope_hierarchy):
            sub_nid = f"sub-{si}"
            sub_label = sub_entry["subscription_id"][:12] + "..."
            sub_roles = sub_entry.get("subscription_level_roles", [])
            sub_roles_data = [{"name": rn, "risk_level": role_risk_map.get(rn, "low")} for rn in sub_roles]
            sub_height = 55 + len(sub_roles) * 24
            tech_nodes.append({"id": sub_nid, "type": "subscription",
                "position": {"x": cx + 280, "y": arm_y},
                "data": {"label": sub_label, "full_id": sub_entry["subscription_id"],
                         "roles": sub_roles_data}})
            tech_edges.append({"id": f"e-id-{sub_nid}", "source": "identity", "target": sub_nid,
                "label": "", "style": {"stroke": "#3b82f6"}})
            arm_y += sub_height + 10

            # Resource groups under this subscription
            for rgi, rg in enumerate(sub_entry.get("resource_groups", [])):
                rg_nid = f"sub-{si}-rg-{rgi}"
                rg_roles = rg.get("roles", [])
                rg_roles_data = [{"name": rn, "risk_level": role_risk_map.get(rn, "low")} for rn in rg_roles]
                rg_height = 45 + len(rg_roles) * 24
                tech_nodes.append({"id": rg_nid, "type": "resource_group",
                    "position": {"x": cx + 530, "y": arm_y},
                    "data": {"label": rg["name"], "roles": rg_roles_data}})
                tech_edges.append({"id": f"e-{sub_nid}-{rg_nid}", "source": sub_nid, "target": rg_nid})
                arm_y += rg_height + 10

                # Resources under this RG
                for resi, res in enumerate(rg.get("resources", [])):
                    res_nid = f"sub-{si}-rg-{rgi}-res-{resi}"
                    short_type = res["type"].split("/")[-1] if "/" in res["type"] else res["type"]
                    res_roles = res.get("roles", [])
                    res_roles_data = [{"name": rn, "risk_level": role_risk_map.get(rn, "low")} for rn in res_roles]
                    res_height = 40 + len(res_roles) * 24
                    tech_nodes.append({"id": res_nid, "type": "resource",
                        "position": {"x": cx + 780, "y": arm_y},
                        "data": {"label": res["name"], "resource_type": short_type,
                                 "full_type": res["type"], "roles": res_roles_data}})
                    tech_edges.append({"id": f"e-{rg_nid}-{res_nid}", "source": rg_nid, "target": res_nid})
                    arm_y += res_height + 10

                arm_y += 10  # spacing between RGs

            arm_y += 15  # spacing between subscriptions

        # ── Permissions (Graph API + App Roles) ──
        perm_y = arm_y + 20
        for i, p in enumerate(graph_perms):
            nid = f"perm-{i}"
            tech_nodes.append({"id": nid, "type": "permission",
                "position": {"x": cx + 280, "y": perm_y},
                "data": {"label": p["permission_name"], "permission_type": "graph_api",
                         "resource": p.get("resource_name", "Microsoft Graph"),
                         "risk_level": p.get("risk_level", "info")}})
            tech_edges.append({"id": f"e-id-{nid}", "source": "identity", "target": nid, "label": "has permission"})
            perm_y += 55

        for i, ar in enumerate(app_roles):
            nid = f"approle-{i}"
            tech_nodes.append({"id": nid, "type": "permission",
                "position": {"x": cx + 280, "y": perm_y},
                "data": {"label": ar.get("role_display_name") or ar.get("app_role_id", "App Role"),
                         "permission_type": "app_role",
                         "resource": ar.get("resource_display_name", "Application"),
                         "risk_level": ar.get("risk_level", "info")}})
            tech_edges.append({"id": f"e-id-{nid}", "source": "identity", "target": nid, "label": "app role"})
            perm_y += 55

        # ── Credentials at bottom ──
        bottom_y = max(perm_y, left_y, cy + 200) + 40
        cred_start_x = cx - min(len(secret_exposure), 6) * 65
        for i, c in enumerate(secret_exposure):
            nid = f"cred-{i}"
            tech_nodes.append({"id": nid, "type": "credential",
                "position": {"x": cred_start_x + i * 130, "y": bottom_y},
                "data": {"label": c["display_name"] or c["credential_type"],
                         "credential_type": c["credential_type"], "exposure_risk": c["exposure_risk"],
                         "status": c["status"], "age_days": c.get("age_days"), "days_to_expiry": c.get("days_to_expiry")}})
            tech_edges.append({"id": f"e-id-{nid}", "source": "identity", "target": nid,
                "sourceHandle": "bottom", "label": "holds"})

        graph = {
            "executive_nodes": exec_nodes, "executive_edges": exec_edges,
            "technical_nodes": tech_nodes, "technical_edges": tech_edges,
        }

        return jsonify({
            "identity_id": ident["identity_id"],
            "display_name": ident["display_name"],
            "risk_level": ident["risk_level"],
            "risk_score": ident["risk_score"],
            "trust_relationships": trust,
            "effective_scope": effective_scope,
            "secret_exposure": secret_exposure,
            "graph": graph,
        })

    finally:
        cursor.close()
        db.close()


def get_identity_pim_data(identity_id):
    """
    Get PIM (Privileged Identity Management) data for an identity.
    Returns eligible assignments, activation history, and overuse metrics.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        # Resolve identity_db_id from identity_id (tenant-scoped)
        cursor.execute("""
            SELECT i.id FROM identities i
            JOIN (SELECT MAX(id) as rid FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s) dr
            ON i.discovery_run_id = dr.rid
            WHERE i.identity_id = %s
            LIMIT 1
        """, (_tenant_id(), identity_id))
        row = cursor.fetchone()
        if not row:
            return jsonify({"eligible_assignments": [], "activations": [], "overuse_metrics": {
                "activation_frequency_30d": 0, "always_active_pattern": False, "total_active_hours_30d": 0
            }})

        identity_db_id = row[0]
        pim_data = db.get_pim_data(identity_db_id)

        # Serialize datetimes
        for item in pim_data["eligible_assignments"]:
            for key in ("start_datetime", "end_datetime"):
                if item.get(key) and hasattr(item[key], "isoformat"):
                    item[key] = item[key].isoformat()

        for item in pim_data["activations"]:
            for key in ("activation_start", "activation_end", "created_datetime"):
                if item.get(key) and hasattr(item[key], "isoformat"):
                    item[key] = item[key].isoformat()

        return jsonify(pim_data)

    finally:
        cursor.close()
        db.close()


def get_dashboard_ca_summary():
    """
    Get Conditional Access summary for dashboard.
    Returns policy counts, coverage percentages, and weak policy flags.
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        latest_run = _latest_run_query(cursor, _tenant_id())

        if not latest_run:
            return jsonify({
                "total_policies": 0, "enabled_policies": 0,
                "coverage": {"covered": 0, "excluded": 0, "no_coverage": 0, "coverage_pct": 0},
                "weak_policy_flags": []
            })

        summary = db.get_ca_summary(latest_run)
        return jsonify(summary)

    finally:
        cursor.close()
        db.close()


# ==========================================================================
# Phase 21: Remediation Action Tracking
# ==========================================================================

def get_remediation_status(identity_id: str):
    """Get remediation action statuses for all playbooks for a specific identity."""
    db = _db()
    try:
        actions = db.get_remediation_actions(identity_id)
        return jsonify({
            'identity_id': identity_id,
            'actions': actions,
        })
    finally:
        db.close()


def post_remediation_action(identity_id: str):
    """Create or update a remediation action for an identity."""
    db = _db()
    try:
        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        playbook_id = body.get('playbook_id')
        status = body.get('status')
        notes = body.get('notes')

        if not playbook_id or not status:
            return jsonify({'error': 'playbook_id and status are required'}), 400

        valid_statuses = ('open', 'acknowledged', 'completed', 'skipped')
        if status not in valid_statuses:
            return jsonify({'error': f'status must be one of: {", ".join(valid_statuses)}'}), 400

        result = db.upsert_remediation_action(
            identity_id=identity_id,
            playbook_id=int(playbook_id),
            status=status,
            notes=notes,
        )

        # Serialize timestamps
        for key in ('created_at', 'updated_at'):
            if result.get(key) and hasattr(result[key], 'isoformat'):
                result[key] = result[key].isoformat()

        _log(db,'remediation_updated', f'Remediation status changed to {status}', {
            'identity_id': identity_id,
            'playbook_id': playbook_id,
            'status': status,
        })

        return jsonify(result)
    finally:
        db.close()


def post_bulk_remediation():
    """Apply a remediation status to all matched playbooks for multiple identities."""
    db = _db()
    try:
        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        identity_ids = body.get('identity_ids', [])
        status = body.get('status')
        notes = body.get('notes')

        if not identity_ids or not isinstance(identity_ids, list):
            return jsonify({'error': 'identity_ids must be a non-empty list'}), 400

        if len(identity_ids) > 50:
            return jsonify({'error': 'Maximum 50 identities per bulk action'}), 400

        valid_statuses = ('acknowledged', 'completed', 'skipped')
        if status not in valid_statuses:
            return jsonify({'error': f'status must be one of: {", ".join(valid_statuses)}'}), 400

        result = db.bulk_upsert_remediation_actions(identity_ids, status, notes)

        _log(db,'remediation_updated', f'Bulk {status} applied to {result["identity_count"]} identities ({result["updated_count"]} actions)', {
            'bulk': True,
            'status': status,
            'identity_count': result['identity_count'],
            'updated_count': result['updated_count'],
        })

        return jsonify(result)
    finally:
        db.close()


def get_role_usage_stats():
    """Get role usage_status and risk_level distribution for dashboard chart."""
    db = _db()
    try:
        return jsonify(db.get_role_usage_stats())
    finally:
        db.close()


# ── Phase 58: Compliance Auto-Remediation ─────────────────────────

# Action types that can be auto-executed
REMEDIATION_ACTIONS = {
    'disable_identity': {
        'label': 'Disable Identity',
        'risk': 'high',
        'description': 'Disable the service principal / identity in Entra ID',
        'categories': ['governance'],
        'patterns': ['dormant', 'never_used', 'stale'],
    },
    'flag_for_review': {
        'label': 'Flag for Review',
        'risk': 'low',
        'description': 'Add an internal review flag for manual follow-up',
        'categories': ['governance', 'monitoring', 'access_control', 'credential_hygiene'],
        'patterns': ['*'],
    },
    'create_ticket': {
        'label': 'Create Ticket',
        'risk': 'low',
        'description': 'Create a tracking ticket in the configured ticketing system',
        'categories': ['governance', 'access_control', 'credential_hygiene'],
        'patterns': ['*'],
    },
    'remove_role': {
        'label': 'Remove Role Assignment',
        'risk': 'high',
        'description': 'Remove the specified Azure RBAC or Entra directory role assignment',
        'categories': ['access_control'],
        'patterns': ['global administrator', 'owner', 'privileged', 'user access administrator'],
    },
    'rotate_credential': {
        'label': 'Rotate Credential',
        'risk': 'medium',
        'description': 'Initiate credential rotation (new secret/cert, invalidate old)',
        'categories': ['credential_hygiene'],
        'patterns': ['expired', 'expiring_soon', 'stale_credential'],
    },
}


def _execute_remediation(action_type: str, identity: dict, playbook: dict, db) -> dict:
    """Execute a remediation action. Returns execution log.
    In dev/demo mode, actions are simulated. In production with Azure creds, real API calls would be made."""
    log = {
        'action_type': action_type,
        'identity_id': identity.get('identity_id'),
        'display_name': identity.get('display_name'),
        'playbook_title': playbook.get('title'),
        'timestamp': datetime.utcnow().isoformat(),
    }

    # Check if Azure credentials are configured for real execution
    settings = db.get_settings(tenant_id=_tenant_id())
    azure_configured = all(settings.get(k) for k in ('azure_tenant_id', 'azure_client_id', 'azure_client_secret'))

    if action_type == 'flag_for_review':
        # Internal action — always executes
        log['result'] = 'success'
        log['detail'] = f'Identity flagged for manual review: {playbook.get("title")}'
        log['simulated'] = False
        return log

    if action_type == 'create_ticket':
        # Check if SOAR ticket integration is configured
        log['result'] = 'simulated'
        log['detail'] = f'Ticket creation simulated: [{playbook.get("impact", "").upper()}] {playbook.get("title")} — {identity.get("display_name")}'
        log['simulated'] = True
        return log

    if action_type == 'disable_identity':
        if not azure_configured:
            log['result'] = 'simulated'
            log['detail'] = f'Would disable identity {identity.get("display_name")} (App ID: {identity.get("app_id", "N/A")}). Azure credentials not configured — simulated.'
            log['simulated'] = True
        else:
            log['result'] = 'simulated'
            log['detail'] = f'Identity disable queued for {identity.get("display_name")}. Actual Azure API call requires production approval workflow.'
            log['simulated'] = True
        return log

    if action_type == 'remove_role':
        log['result'] = 'simulated'
        log['detail'] = f'Role removal queued for {identity.get("display_name")}. Requires manual approval before execution.'
        log['simulated'] = True
        return log

    if action_type == 'rotate_credential':
        log['result'] = 'simulated'
        log['detail'] = f'Credential rotation queued for {identity.get("display_name")}. New credential will be generated on approval.'
        log['simulated'] = True
        return log

    log['result'] = 'error'
    log['detail'] = f'Unknown action type: {action_type}'
    return log


def execute_remediation(identity_id: str):
    """Execute a remediation action for an identity/playbook pair."""
    db = _db()
    try:
        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        playbook_id = body.get('playbook_id')
        action_type = body.get('action_type', 'flag_for_review')

        if not playbook_id:
            return jsonify({'error': 'playbook_id is required'}), 400

        if action_type not in REMEDIATION_ACTIONS:
            return jsonify({'error': f'Invalid action_type. Must be one of: {", ".join(REMEDIATION_ACTIONS.keys())}'}), 400

        # Fetch identity
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT identity_id, display_name, identity_category, risk_level,
                   app_id, activity_status
            FROM identities
            WHERE identity_id = %s
            ORDER BY discovery_run_id DESC LIMIT 1
        """, (identity_id,))
        identity = cursor.fetchone()
        cursor.close()

        if not identity:
            return jsonify({'error': 'Identity not found'}), 404

        # Fetch playbook
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM remediation_playbooks WHERE id = %s", (int(playbook_id),))
        playbook = cursor.fetchone()
        cursor.close()

        if not playbook:
            return jsonify({'error': 'Playbook not found'}), 404

        # Execute
        execution_log = _execute_remediation(action_type, dict(identity), dict(playbook), db)
        exec_status = execution_log.get('result', 'error')

        # Record in DB
        user_id = None
        if hasattr(g, 'current_user') and g.current_user:
            user_id = g.current_user.get('id')

        result = db.execute_remediation_action(
            identity_id=identity_id,
            playbook_id=int(playbook_id),
            execution_status=exec_status,
            execution_log=execution_log,
            user_id=user_id,
        )

        # Serialize timestamps
        for key in ('created_at', 'updated_at', 'executed_at'):
            if result.get(key) and hasattr(result[key], 'isoformat'):
                result[key] = result[key].isoformat()

        _log(db, 'remediation_executed', f'Remediation executed: {action_type} on {identity["display_name"]}', {
            'identity_id': identity_id,
            'playbook_id': playbook_id,
            'action_type': action_type,
            'result': exec_status,
            'simulated': execution_log.get('simulated', False),
        })

        return jsonify({
            'action': result,
            'execution_log': execution_log,
        })
    finally:
        db.close()


def get_remediation_queue_handler():
    """Get the pending remediation queue across all identities."""
    db = _db()
    try:
        status_filter = request.args.get('status', 'open')
        impact_filter = request.args.get('impact')
        category_filter = request.args.get('category')
        limit = min(int(request.args.get('limit', '100')), 500)

        queue = db.get_remediation_queue(
            status_filter=status_filter,
            impact_filter=impact_filter,
            category_filter=category_filter,
            limit=limit,
        )

        summary = db.get_remediation_summary()

        return jsonify({
            'queue': queue,
            'summary': summary,
            'available_actions': {k: {'label': v['label'], 'risk': v['risk'], 'description': v['description']}
                                  for k, v in REMEDIATION_ACTIONS.items()},
        })
    finally:
        db.close()


def batch_auto_remediate():
    """Batch execute safe (low-risk) remediations for all open actions matching criteria."""
    db = _db()
    try:
        body = request.get_json() or {}
        action_type = body.get('action_type', 'flag_for_review')
        impact_filter = body.get('impact')
        category_filter = body.get('category')
        max_items = min(int(body.get('max_items', 50)), 200)

        if action_type not in REMEDIATION_ACTIONS:
            return jsonify({'error': f'Invalid action_type'}), 400

        action_def = REMEDIATION_ACTIONS[action_type]
        if action_def['risk'] == 'high':
            return jsonify({'error': 'High-risk actions cannot be batch-executed. Use individual execution with approval.'}), 400

        # Get open remediations
        queue = db.get_remediation_queue(
            status_filter='open',
            impact_filter=impact_filter,
            category_filter=category_filter,
            limit=max_items,
        )

        user_id = None
        if hasattr(g, 'current_user') and g.current_user:
            user_id = g.current_user.get('id')

        results = []
        for item in queue:
            identity = {
                'identity_id': item['identity_id'],
                'display_name': item['display_name'],
                'app_id': '',
                'activity_status': item.get('activity_status', ''),
            }
            playbook = {
                'title': item['playbook_title'],
                'impact': item['impact'],
                'category': item['category'],
            }

            execution_log = _execute_remediation(action_type, identity, playbook, db)
            exec_status = execution_log.get('result', 'error')

            db.execute_remediation_action(
                identity_id=item['identity_id'],
                playbook_id=item['playbook_id'],
                execution_status=exec_status,
                execution_log=execution_log,
                user_id=user_id,
            )

            results.append({
                'identity_id': item['identity_id'],
                'display_name': item['display_name'],
                'playbook_title': item['playbook_title'],
                'result': exec_status,
            })

        _log(db, 'remediation_batch', f'Batch {action_type}: {len(results)} actions executed', {
            'action_type': action_type,
            'count': len(results),
            'impact_filter': impact_filter,
            'category_filter': category_filter,
        })

        return jsonify({
            'executed': len(results),
            'action_type': action_type,
            'results': results,
        })
    finally:
        db.close()


def get_role_mining():
    """GET /api/role-mining — role mining v2: toxic combos, evidence, bundles, blast radius."""
    db = _db()
    try:
        window_days = request.args.get('window_days', 90, type=int)
        window_days = max(7, min(365, window_days))

        from app.engines.role_mining import RoleMiningEngine
        engine = RoleMiningEngine(db, window_days=window_days)
        result = engine.analyze()

        # Backward compat: keep legacy "findings" array for any old consumers
        legacy_findings = []
        for f in result.get('unused_findings', []):
            legacy_findings.append({
                'identity_id': f['identity_id'],
                'identity_name': f['identity_name'],
                'identity_category': f['identity_category'],
                'role_name': f['role_name'],
                'source': f['source'],
                'type': f['finding_type'],
                'risk_level': f['risk_level'],
                'days_since_assigned': f.get('days_since_assigned'),
                'scope': f.get('scope'),
                'recommendation': f['recommendation'],
                'assignment_method': f.get('assignment_method', 'direct'),
            })
        for f in result.get('redundant_findings', []):
            legacy_findings.append({
                'identity_id': f['identity_id'],
                'identity_name': f['identity_name'],
                'identity_category': f['identity_category'],
                'role_name': f['role_name'],
                'source': f['source'],
                'type': 'redundant',
                'risk_level': f.get('risk_level', 'medium'),
                'days_since_assigned': None,
                'scope': f.get('scope'),
                'recommendation': f['recommendation'],
                'assignment_method': f.get('assignment_method', 'direct'),
            })
        for f in result.get('orphaned_findings', []):
            legacy_findings.append({
                'identity_id': f['identity_id'],
                'identity_name': f['identity_name'],
                'identity_category': f['identity_category'],
                'role_name': f['role_name'],
                'source': f['source'],
                'type': 'orphaned',
                'risk_level': f.get('risk_level', 'medium'),
                'days_since_assigned': None,
                'scope': f.get('scope'),
                'recommendation': f['recommendation'],
                'assignment_method': f.get('assignment_method', 'direct'),
            })

        result['findings'] = legacy_findings
        result['role_bundles'] = result.pop('bundles', [])
        return jsonify(result)
    finally:
        db.close()


def get_remediation_dashboard_summary():
    """Get aggregated remediation progress for the dashboard widget."""
    db = _db()
    try:
        summary = db.get_remediation_summary()
        return jsonify(summary)
    finally:
        db.close()


# ================================================================
# Phase 31: Authentication & User Management
# ================================================================

VALID_ROLES = {'admin', 'security_admin', 'compliance', 'reader'}


def auth_login():
    """POST /api/auth/login — authenticate with username/password."""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    tenant_slug = str(data.get('tenant_slug', '')).strip() or None  # Phase 53
    portal = str(data.get('portal', 'client')).strip()  # 'admin' or 'client'

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Phase 68 fix: Close DB connection BEFORE token generation to avoid
    # deadlock between this connection's implicit transaction and the new
    # connection opened by generate_refresh_token() → _ensure_users_table() DDL.
    db = _db()
    try:
        user = db.get_user_by_username(username)

        if not user or not user.get('enabled'):
            try:
                _log(db,'auth_failed', f'Login failed for "{username}": user not found or disabled',
                                {'username': username, 'ip': request.remote_addr})
            except Exception:
                pass
            return jsonify({'error': 'Invalid credentials'}), 401

        # Phase 84: Account lockout check
        locked_until = user.get('locked_until')
        if locked_until:
            if isinstance(locked_until, str):
                locked_until = datetime.fromisoformat(locked_until)
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if locked_until > datetime.now(timezone.utc):
                remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
                return jsonify({
                    'error': 'Account locked',
                    'locked_until': locked_until.isoformat(),
                    'message': f'Too many failed attempts. Try again in {remaining} minutes.'
                }), 423

        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Phase 84: Increment failed login attempts
            try:
                db.increment_failed_login(user['id'])
            except Exception:
                pass
            try:
                _log(db,'auth_failed', f'Login failed for "{username}": wrong password',
                                {'username': username, 'ip': request.remote_addr})
            except Exception:
                pass
            return jsonify({'error': 'Invalid credentials'}), 401

        # Phase 53: Tenant-scoped login enforcement
        if tenant_slug:
            target_tenant = db.get_tenant_by_slug(tenant_slug)
            if not target_tenant:
                return jsonify({'error': 'Organization not found'}), 404
            if not target_tenant.get('enabled'):
                return jsonify({'error': 'Organization is disabled'}), 403
            # Block superadmins from logging into client portals
            if user.get('is_superadmin') and portal == 'client':
                return jsonify({'error': 'Platform administrators must use the admin portal.'}), 403
            if not user.get('is_superadmin') and user.get('tenant_id') != target_tenant['id']:
                return jsonify({'error': 'You do not belong to this organization'}), 403

        # Do all DB writes while connection 1 is still open
        db.update_last_login(user['id'])
        # Phase 84: Reset failed login counter on success
        try:
            db.reset_failed_login(user['id'])
        except Exception:
            pass

        try:
            action_type = 'admin_login' if portal == 'admin' else 'auth_login'
            db.log_activity(action_type, f'User "{username}" logged in ({portal} portal)',
                            {'user_id': user['id'], 'role': user['role'], 'ip': request.remote_addr,
                             'user_agent': request.headers.get('User-Agent', '')[:200],
                             'tenant_name': user.get('tenant_name', ''),
                             'portal': portal},
                            user_id=user['id'], tenant_id=user.get('tenant_id'))
        except Exception:
            pass
    finally:
        db.close()

    # Generate tokens AFTER closing connection 1 (generate_refresh_token opens its own connection)
    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'display_name': user['display_name'],
            'role': user['role'],
            'tenant_id': user.get('tenant_id'),
            'tenant_name': user.get('tenant_name'),
            'is_superadmin': user.get('is_superadmin', False),
            'portal_role': user.get('portal_role'),
            'force_password_change': user.get('force_password_change', False),
        }
    })


def auth_refresh():
    """POST /api/auth/refresh — exchange refresh token for new tokens."""
    data = request.get_json(silent=True) or {}
    raw_refresh = data.get('refresh_token', '')

    if not raw_refresh:
        return jsonify({'error': 'Refresh token required'}), 400

    # Phase 68 fix: Close DB connection BEFORE token generation to avoid deadlock
    # (same pattern as auth_login fix)
    db = _db()
    try:
        token_hash = hash_refresh_token(raw_refresh)
        token_record = db.get_refresh_token(token_hash)

        if not token_record or token_record.get('revoked'):
            return jsonify({'error': 'Invalid refresh token'}), 401

        if token_record['expires_at'].replace(tzinfo=None) < datetime.utcnow():
            return jsonify({'error': 'Refresh token expired'}), 401

        user = db.get_user_by_id(token_record['user_id'])
        if not user or not user.get('enabled'):
            return jsonify({'error': 'User disabled'}), 401

        db.revoke_refresh_token(token_hash)
    finally:
        db.close()

    # Generate tokens AFTER closing connection 1
    access_token = generate_access_token(user)
    new_refresh = generate_refresh_token(user)

    return jsonify({
        'access_token': access_token,
        'refresh_token': new_refresh,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'display_name': user['display_name'],
            'role': user['role'],
            'tenant_id': user.get('tenant_id'),
            'tenant_name': user.get('tenant_name'),
            'is_superadmin': user.get('is_superadmin', False),
            'portal_role': user.get('portal_role'),
            'force_password_change': user.get('force_password_change', False),
        }
    })


def auth_logout():
    """POST /api/auth/logout — revoke refresh token."""
    data = request.get_json(silent=True) or {}
    raw_refresh = data.get('refresh_token', '')
    portal = str(data.get('portal', 'client')).strip()

    db = _db()
    try:
        if raw_refresh:
            db.revoke_refresh_token(hash_refresh_token(raw_refresh))

        user = getattr(g, 'current_user', None)
        if user:
            try:
                action_type = 'admin_logout' if portal == 'admin' else 'auth_logout'
                _log(db, action_type, f'User "{user["username"]}" logged out ({portal} portal)',
                                {'user_id': user['id'], 'portal': portal})
            except Exception:
                pass

        return jsonify({'message': 'Logged out'})
    finally:
        db.close()


def auth_me():
    """GET /api/auth/me — return current authenticated user profile."""
    user = g.current_user
    db = _db()
    try:
        full_user = db.get_user_by_id(user['id'])
        if not full_user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'user': full_user})
    finally:
        db.close()


def change_password():
    """PUT /api/auth/password — change own password."""
    user = g.current_user
    data = request.get_json(silent=True) or {}
    current_password = str(data.get('current_password', ''))
    new_password = str(data.get('new_password', ''))

    if not current_password or not new_password:
        return jsonify({'error': 'Current password and new password are required'}), 400
    if len(new_password) < 12:
        return jsonify({'error': 'New password must be at least 12 characters'}), 400

    db = _db()
    try:
        full_user = db.get_user_by_username(user['username'])
        if not full_user:
            return jsonify({'error': 'User not found'}), 404

        if not bcrypt.checkpw(current_password.encode('utf-8'), full_user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Current password is incorrect'}), 401

        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.update_user(user['id'], password_hash=new_hash)
        # Phase 78: Clear force_password_change after successful password change
        db.set_force_password_change(user['id'], False)

        try:
            _log(db,'password_changed', f'User "{user["username"]}" changed their password',
                            {'user_id': user['id']})
        except Exception:
            pass

        return jsonify({'message': 'Password changed successfully'})
    finally:
        db.close()


def forgot_password_handler():
    """POST /api/auth/forgot-password — initiate password reset (public)."""
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    tenant_slug = str(data.get('tenant_slug', '')).strip() or None

    # Always return success to prevent email enumeration
    success_msg = 'If an account exists with this email, a password reset link has been sent.'

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    db = _db()
    try:
        # Resolve tenant_id from slug if provided
        tenant_id = None
        if tenant_slug:
            tenant = db.get_tenant_by_slug(tenant_slug)
            if tenant:
                tenant_id = tenant['id']

        user = db.get_user_by_email(email, tenant_id=tenant_id)
        if not user:
            return jsonify({'message': success_msg})

        # Rate limit: max 3 reset requests per email per hour
        recent = db.count_recent_reset_requests(email)
        if recent >= 3:
            return jsonify({'message': success_msg})

        # Generate token
        raw_token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(hours=1)

        db.set_password_reset_token(user['id'], token_hash, expires)

        # Build reset URL (log it — email delivery uses existing EmailService if configured)
        reset_url = f"/reset-password?token={raw_token}"
        print(f"[Password Reset] User: {email}, Token: {raw_token}, URL: {reset_url}")

        try:
            _log(db, 'password_reset_requested',
                 f'Password reset requested for "{email}"',
                 {'user_id': user['id'], 'reset_url': reset_url, 'ip': request.remote_addr})
        except Exception:
            pass

        return jsonify({'message': success_msg})
    finally:
        db.close()


def validate_reset_token_handler():
    """GET /api/auth/validate-reset-token — check if a reset token is valid (public)."""
    token = request.args.get('token', '').strip()
    if not token:
        return jsonify({'valid': False}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db = _db()
    try:
        user = db.get_user_by_reset_token(token_hash)
        if not user:
            return jsonify({'valid': False})

        # Mask email: show first 2 chars + *** + domain
        email = user.get('email', '') or ''
        if '@' in email:
            local, domain = email.split('@', 1)
            masked = local[:2] + '***@' + domain
        else:
            masked = '***'

        return jsonify({'valid': True, 'email': masked})
    finally:
        db.close()


def reset_password_handler():
    """POST /api/auth/reset-password — reset password with token (public)."""
    data = request.get_json(silent=True) or {}
    token = str(data.get('token', '')).strip()
    new_password = str(data.get('new_password', ''))

    if not token:
        return jsonify({'error': 'Reset token is required'}), 400
    if not new_password or len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db = _db()
    try:
        user = db.get_user_by_reset_token(token_hash)
        if not user:
            return jsonify({'error': 'Invalid or expired reset token'}), 400

        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.update_user(user['id'], password_hash=new_hash)
        db.clear_password_reset_token(user['id'])
        db.reset_failed_login(user['id'])
        db.set_force_password_change(user['id'], False)

        try:
            _log(db, 'password_reset_completed',
                 f'Password reset completed for user "{user["username"]}"',
                 {'user_id': user['id'], 'ip': request.remote_addr})
        except Exception:
            pass

        return jsonify({'message': 'Password reset successfully. You can now log in with your new password.'})
    finally:
        db.close()


def admin_reset_user_password(user_id):
    """POST /api/users/<id>/reset-password — admin resets a user's password."""
    current_user = getattr(g, 'current_user', None)
    if not current_user:
        return jsonify({'error': 'Authentication required'}), 401

    db = _db()
    try:
        target = db.get_user_by_id(user_id)
        if not target:
            return jsonify({'error': 'User not found'}), 404

        # Generate temporary password
        temp_password = secrets.token_urlsafe(16)
        new_hash = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        db.update_user(user_id, password_hash=new_hash)
        db.set_force_password_change(user_id, True)
        db.reset_failed_login(user_id)
        db.clear_password_reset_token(user_id)

        try:
            db.log_admin_audit(current_user['id'], 'admin_password_reset',
                               target_user_id=user_id,
                               target_tenant_id=target.get('tenant_id'),
                               details={'target_username': target['username']},
                               ip_address=request.remote_addr)
        except Exception:
            pass

        try:
            _log(db, 'admin_password_reset',
                 f'Admin "{current_user["username"]}" reset password for user "{target["username"]}"',
                 {'admin_user_id': current_user['id'], 'target_user_id': user_id})
        except Exception:
            pass

        return jsonify({
            'message': f'Password reset for "{target["username"]}". User will be required to change it on next login.',
            'temp_password': temp_password,
        })
    finally:
        db.close()


def get_users_list():
    """GET /api/users — list users, scoped by tenant."""
    db = _db()
    try:
        current_user = getattr(g, 'current_user', None)
        is_super = current_user.get('is_superadmin') if current_user else False

        if is_super:
            filter_tid = request.args.get('tenant_id', type=int)
        else:
            filter_tid = _tenant_id()
        # Portal users have their own endpoint (/api/portal-users) — always exclude here
        exclude_portal = True

        users = db.get_users(tenant_id=filter_tid, exclude_portal=exclude_portal)
        return jsonify({'users': users})
    finally:
        db.close()


def create_user_handler():
    """POST /api/users — create a new user (admin only)."""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip().lower()
    display_name = str(data.get('display_name', '')).strip()
    password = str(data.get('password', ''))
    role = str(data.get('role', 'viewer')).strip().lower()

    errors = []
    if not username:
        errors.append('username is required')
    elif len(username) < 3:
        errors.append('username must be at least 3 characters')
    elif len(username) > 100:
        errors.append('username must be 100 characters or less')

    if not display_name:
        errors.append('display_name is required')
    elif len(display_name) > 255:
        errors.append('display_name must be 255 characters or less')

    if not password:
        errors.append('password is required')
    elif len(password) < 8:
        errors.append('password must be at least 8 characters')

    if role not in VALID_ROLES:
        errors.append(f'role must be one of: {", ".join(sorted(VALID_ROLES))}')

    if errors:
        return jsonify({'error': '; '.join(errors)}), 400

    db = _db()
    try:
        existing = db.get_user_by_username(username)
        if existing:
            return jsonify({'error': f'Username "{username}" already exists'}), 409

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        current_user = getattr(g, 'current_user', None)
        created_by = current_user['id'] if current_user else None
        # Phase 70: superadmins can set portal_role and is_superadmin on creation
        is_superadmin_flag = False
        portal_role_val = None
        if current_user and current_user.get('is_superadmin'):
            if 'is_superadmin' in data:
                is_superadmin_flag = bool(data['is_superadmin'])
            if 'portal_role' in data and (data['portal_role'] is None or data['portal_role'] in VALID_PORTAL_ROLES):
                portal_role_val = data['portal_role']

        # Portal users (admin console operators) have no tenant — they're platform-level
        if portal_role_val:
            tenant_id = None
        elif current_user and current_user.get('is_superadmin') and 'tenant_id' in data:
            tenant_id = data.get('tenant_id')
        else:
            tenant_id = current_user.get('tenant_id') if current_user else None

        email_val = str(data.get('email', '')).strip() or None
        phone_val = str(data.get('phone', '')).strip() or None
        user = db.create_user(username, hashed, display_name, role, created_by, tenant_id=tenant_id,
                              is_superadmin=is_superadmin_flag, portal_role=portal_role_val,
                              email=email_val, phone=phone_val)

        try:
            _log(db,'user_created', f'User "{username}" created with role "{role}"',
                            {'user_id': user['id'], 'role': role, 'created_by': created_by})
        except Exception:
            pass

        return jsonify({'user': user, 'message': 'User created'}), 201
    finally:
        db.close()


def update_user_handler(user_id):
    """PUT /api/users/<id> — update a user (admin only)."""
    data = request.get_json(silent=True) or {}

    db = _db()
    try:
        existing = db.get_user_by_id(user_id)
        if not existing:
            return jsonify({'error': 'User not found'}), 404

        updates = {}
        errors = []

        if 'display_name' in data:
            dn = str(data['display_name']).strip()
            if not dn:
                errors.append('display_name cannot be empty')
            else:
                updates['display_name'] = dn

        if 'role' in data:
            role = str(data['role']).strip().lower()
            if role not in VALID_ROLES:
                errors.append(f'role must be one of: {", ".join(sorted(VALID_ROLES))}')
            elif existing['role'] == 'admin' and role != 'admin':
                if db.count_admins() <= 1:
                    errors.append('Cannot demote the last admin user')
                else:
                    updates['role'] = role
            else:
                updates['role'] = role

        if 'enabled' in data:
            enabled = bool(data['enabled'])
            if existing['role'] == 'admin' and not enabled:
                if db.count_admins() <= 1:
                    errors.append('Cannot disable the last admin user')
                else:
                    updates['enabled'] = enabled
            else:
                updates['enabled'] = enabled

        if 'password' in data and data['password']:
            pwd = str(data['password'])
            if len(pwd) < 8:
                errors.append('password must be at least 8 characters')
            else:
                updates['password_hash'] = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Phase 46: tenant_id + is_superadmin (superadmin only)
        current_user = getattr(g, 'current_user', None)
        if 'tenant_id' in data:
            if not current_user or not current_user.get('is_superadmin'):
                errors.append('Only superadmins can reassign tenant')
            else:
                updates['tenant_id'] = int(data['tenant_id']) if data['tenant_id'] is not None else None

        if 'is_superadmin' in data:
            if not current_user or not current_user.get('is_superadmin'):
                errors.append('Only superadmins can change superadmin status')
            else:
                updates['is_superadmin'] = bool(data['is_superadmin'])

        # Phase 77: email/phone
        if 'email' in data:
            updates['email'] = str(data['email']).strip() if data['email'] else None
        if 'phone' in data:
            updates['phone'] = str(data['phone']).strip() if data['phone'] else None

        # Phase 70: portal_role (superadmin only)
        if 'portal_role' in data:
            if not current_user or not current_user.get('is_superadmin'):
                errors.append('Only superadmins can change portal_role')
            else:
                pr = data['portal_role']
                if pr is not None and pr not in VALID_PORTAL_ROLES:
                    errors.append(f'portal_role must be null or one of: {", ".join(VALID_PORTAL_ROLES)}')
                else:
                    updates['portal_role'] = pr

        if errors:
            return jsonify({'error': '; '.join(errors)}), 400

        if not updates:
            return jsonify({'user': existing, 'message': 'No changes'})

        user = db.update_user(user_id, **updates)

        if 'password_hash' in updates:
            db.revoke_all_user_tokens(user_id)

        try:
            changed_fields = [k for k in updates if k != 'password_hash']
            if 'password_hash' in updates:
                changed_fields.append('password')
            _log(db,'user_updated', f'User "{existing["username"]}" updated: {", ".join(changed_fields)}',
                            {'user_id': user_id, 'changes': changed_fields})
        except Exception:
            pass

        return jsonify({'user': user, 'message': 'User updated'})
    finally:
        db.close()


def delete_user_handler(user_id):
    """DELETE /api/users/<id> — delete a user (admin only)."""
    db = _db()
    try:
        existing = db.get_user_by_id(user_id)
        if not existing:
            return jsonify({'error': 'User not found'}), 404

        current_user = getattr(g, 'current_user', None)
        if current_user and current_user['id'] == user_id:
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Phase 46: Non-superadmins cannot delete users from another tenant
        if current_user and not current_user.get('is_superadmin'):
            if existing.get('tenant_id') != current_user.get('tenant_id'):
                return jsonify({'error': 'Cannot delete users from another tenant'}), 403

        if existing['role'] == 'admin' and db.count_admins() <= 1:
            return jsonify({'error': 'Cannot delete the last admin user'}), 400

        db.revoke_all_user_tokens(user_id)
        db.delete_user(user_id)

        try:
            _log(db,'user_deleted', f'User "{existing["username"]}" deleted',
                            {'deleted_user_id': user_id, 'deleted_by': current_user['id'] if current_user else None})
        except Exception:
            pass

        return jsonify({'message': f'User "{existing["username"]}" deleted'})
    finally:
        db.close()


# ── Phase 70: Portal Users (Admin Console) ───────────────────────
def get_portal_users_list():
    """GET /api/portal-users — list users with portal_role (superadmin only)."""
    db = _db()
    try:
        users = db.get_portal_users()
        return jsonify({'users': users})
    finally:
        db.close()


# ── Phase 33: Export Pipeline ─────────────────────────────────────

def export_data(export_type):
    """
    GET /api/export/<type>
    Returns structured JSON for client-side CSV/JSON file generation.
    Supported types: identities, compliance, drift, risk-summary
    """
    VALID_TYPES = {'identities', 'compliance', 'drift', 'risk-summary'}
    if export_type not in VALID_TYPES:
        return jsonify({'error': f'Invalid export type. Valid: {", ".join(sorted(VALID_TYPES))}'}), 400

    if export_type == 'identities':
        return _export_identities()
    elif export_type == 'compliance':
        return _export_compliance()
    elif export_type == 'drift':
        return _export_drift()
    elif export_type == 'risk-summary':
        return _export_risk_summary()


def _export_identities():
    """Export all identities (no pagination) with optional filters."""
    db = _db()
    cursor = db.conn.cursor()
    try:
        risk_filter = request.args.get('risk_level')
        category_filter = request.args.get('identity_category')

        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({'error': 'No completed discovery runs found'}), 404

        query = """
            SELECT
                i.identity_id, i.display_name, i.identity_type,
                COALESCE(i.identity_category, '') as identity_category,
                i.risk_level, i.credential_count, i.credential_status,
                i.credential_expiration, i.created_datetime, i.activity_status,
                (SELECT COUNT(*) FROM role_assignments ra WHERE ra.identity_db_id = i.id) as rbac_role_count,
                (SELECT COUNT(*) FROM entra_role_assignments era WHERE era.identity_db_id = i.id) as entra_role_count,
                COALESCE(i.cloud, 'azure') as cloud,
                COALESCE(i.status, 'active') as status,
                i.last_seen_auth,
                i.owner_display_name,
                COALESCE(i.owner_count, 0) as owner_count,
                COALESCE(i.risk_score, 0) as risk_score,
                COALESCE(i.api_permission_count, 0) as api_permission_count,
                COALESCE(i.app_role_count, 0) as app_role_count,
                i.enabled,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'global administrator', 'privileged role administrator',
                            'privileged authentication administrator',
                            'application administrator', 'cloud application administrator',
                            'hybrid identity administrator'
                        )
                    ) THEN 0
                    WHEN EXISTS (
                        SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN ('owner', 'user access administrator')
                        AND (ra.scope IS NULL OR ra.scope = '/' OR ra.scope LIKE '/subscriptions/%%'
                             AND ra.scope NOT LIKE '/subscriptions/%%/resourceGroups/%%')
                    ) THEN 0
                    WHEN EXISTS (
                        SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'user administrator', 'exchange administrator',
                            'sharepoint administrator', 'teams administrator',
                            'security administrator', 'compliance administrator',
                            'conditional access administrator', 'helpdesk administrator'
                        )
                    ) THEN 1
                    WHEN EXISTS (
                        SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN ('owner', 'contributor', 'user access administrator')
                    ) THEN 1
                    WHEN EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id) THEN 2
                    WHEN EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id) THEN 2
                    ELSE 3
                END as privilege_tier,
                i.ca_coverage_status,
                COALESCE(i.ca_mfa_enforced, false) as ca_mfa_enforced,
                i.risk_reasons
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

        query += """
            ORDER BY
                CASE i.risk_level
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                END, i.display_name
        """

        cursor.execute(query, params)
        rows = cursor.fetchall()

        identities = []
        for row in rows:
            identities.append({
                'identity_id': row[0],
                'display_name': row[1] or '',
                'identity_type': row[2] or '',
                'identity_category': _normalize_category_key(row[3] or ''),
                'risk_level': row[4] or 'info',
                'credential_count': int(row[5] or 0),
                'credential_status': row[6] or 'unknown',
                'credential_expiration': row[7].isoformat() if row[7] else None,
                'created_datetime': row[8].isoformat() if row[8] else None,
                'activity_status': row[9] or 'unknown',
                'rbac_role_count': int(row[10] or 0),
                'entra_role_count': int(row[11] or 0),
                'cloud': row[12] or 'azure',
                'status': row[13] or 'active',
                'last_seen_auth': row[14].isoformat() if row[14] else None,
                'owner_display_name': row[15],
                'owner_count': int(row[16] or 0),
                'risk_score': int(row[17] or 0),
                'api_permission_count': int(row[18] or 0),
                'app_role_count': int(row[19] or 0),
                'enabled': row[20] if row[20] is not None else True,
                'privilege_tier': f'T{row[21]}' if row[21] is not None else 'T3',
                'ca_coverage_status': row[22] or None,
                'ca_mfa_enforced': bool(row[23]) if row[23] is not None else False,
                'risk_reasons': row[24] if row[24] else [],
            })

        try:
            _log(db,'export', f'Identities export generated ({len(identities)} records)',
                            {'export_type': 'identities', 'count': len(identities)})
        except Exception:
            pass

        return jsonify({
            'export_type': 'identities',
            'generated_at': datetime.utcnow().isoformat(),
            'run_id': latest_run,
            'total_count': len(identities),
            'filters': {'risk_level': risk_filter, 'identity_category': category_filter},
            'identities': identities,
        })
    finally:
        cursor.close()
        db.close()


def _export_compliance():
    """Export compliance framework evaluations with gap analysis."""
    db = _db()
    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({'error': 'No completed discovery runs found'}), 404

        metrics = _compute_compliance_metrics(cursor, latest_run)
        frameworks = db.get_compliance_frameworks(enabled_only=True)

        scorecard = {}
        all_controls = []
        gap_analysis = []

        for fw in frameworks:
            controls_out = []
            for ctrl in fw['controls']:
                status, value = _evaluate_control(ctrl, metrics)
                label = _format_metric_label(ctrl['metric'])
                if status == 'pass':
                    detail = f"{value} {label} — within limits"
                elif status == 'warn':
                    detail = f"{value} {label} — approaching threshold"
                else:
                    detail = f"{value} {label} — exceeds acceptable limit (target: {ctrl['pass_operator']}{int(ctrl['pass_value'])})"

                ctrl_data = {
                    'id': ctrl['control_id'],
                    'name': ctrl['name'],
                    'status': status,
                    'detail': detail,
                    'metric': ctrl['metric'],
                    'value': value,
                    'pass_threshold': f"{ctrl['pass_operator']}{int(ctrl['pass_value'])}",
                }
                controls_out.append(ctrl_data)

                # Flat record for all_controls and gap_analysis
                flat = {
                    'framework': fw['name'],
                    'framework_key': fw['key'],
                    'control_id': ctrl['control_id'],
                    'control_name': ctrl['name'],
                    'status': status,
                    'current_value': value,
                    'threshold': f"{ctrl['pass_operator']}{int(ctrl['pass_value'])}",
                    'detail': detail,
                }
                all_controls.append(flat)
                if status != 'pass':
                    gap_analysis.append(flat)

            passes = sum(1 for c in controls_out if c['status'] == 'pass')
            scorecard[fw['key']] = {
                'name': fw['name'],
                'version': fw.get('version'),
                'score': round(passes / len(controls_out) * 100) if controls_out else 0,
                'pass_count': passes,
                'warn_count': sum(1 for c in controls_out if c['status'] == 'warn'),
                'fail_count': sum(1 for c in controls_out if c['status'] == 'fail'),
                'total_controls': len(controls_out),
                'controls': controls_out,
            }

        total_controls = sum(fw['total_controls'] for fw in scorecard.values())
        total_passing = sum(fw['pass_count'] for fw in scorecard.values())
        overall_score = round((total_passing / total_controls) * 100) if total_controls > 0 else 0

        try:
            _log(db,'export', f'Compliance export generated ({len(frameworks)} frameworks)',
                            {'export_type': 'compliance', 'frameworks': len(frameworks)})
        except Exception:
            pass

        return jsonify({
            'export_type': 'compliance',
            'generated_at': datetime.utcnow().isoformat(),
            'run_id': latest_run,
            'overall_score': overall_score,
            'raw_metrics': metrics,
            'frameworks': scorecard,
            'all_controls': all_controls,
            'gap_analysis': gap_analysis,
        })
    finally:
        cursor.close()
        db.close()


def _export_drift():
    """Export latest drift report with flattened changes."""
    db = _db()
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s
            ORDER BY id DESC LIMIT 1
        """, (_tenant_id(),))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return jsonify({'error': 'No completed discovery runs found'}), 404

        run_id = row[0]
        report = db.get_drift_report(run_id)
        if not report:
            return jsonify({
                'export_type': 'drift',
                'generated_at': datetime.utcnow().isoformat(),
                'has_data': False,
                'total_changes': 0,
                'changes': [],
            })

        # Flatten all change types into a single list
        flat_changes = []
        changes = report.get('changes') or {}
        if isinstance(changes, str):
            changes = json.loads(changes)

        for item in (changes.get('new_identities') or []):
            flat_changes.append({
                'change_type': 'new_identity',
                'identity_id': item.get('identity_id', ''),
                'display_name': item.get('display_name', ''),
                'detail': f"New {item.get('identity_category', 'identity')} discovered",
                'risk_level': item.get('risk_level', ''),
            })
        for item in (changes.get('removed_identities') or []):
            flat_changes.append({
                'change_type': 'removed_identity',
                'identity_id': item.get('identity_id', ''),
                'display_name': item.get('display_name', ''),
                'detail': 'Identity removed from environment',
                'risk_level': item.get('risk_level', ''),
            })
        for item in (changes.get('permission_changes') or []):
            detail_parts = []
            if item.get('added_roles'):
                detail_parts.append(f"Added: {', '.join(item['added_roles'])}")
            if item.get('removed_roles'):
                detail_parts.append(f"Removed: {', '.join(item['removed_roles'])}")
            flat_changes.append({
                'change_type': 'permission_change',
                'identity_id': item.get('identity_id', ''),
                'display_name': item.get('display_name', ''),
                'detail': '; '.join(detail_parts) if detail_parts else 'Permission change detected',
                'risk_level': item.get('risk_level', ''),
            })
        for item in (changes.get('risk_changes') or []):
            flat_changes.append({
                'change_type': 'risk_change',
                'identity_id': item.get('identity_id', ''),
                'display_name': item.get('display_name', ''),
                'detail': f"{item.get('old_risk', '?')} -> {item.get('new_risk', '?')}",
                'risk_level': item.get('new_risk', ''),
            })
        for item in (changes.get('credential_changes') or []):
            flat_changes.append({
                'change_type': 'credential_change',
                'identity_id': item.get('identity_id', ''),
                'display_name': item.get('display_name', ''),
                'detail': f"{item.get('old_status', '?')} -> {item.get('new_status', '?')}",
                'risk_level': item.get('risk_level', ''),
            })

        try:
            _log(db,'export', f'Drift export generated ({len(flat_changes)} changes)',
                            {'export_type': 'drift', 'run_id': run_id})
        except Exception:
            pass

        return jsonify({
            'export_type': 'drift',
            'generated_at': datetime.utcnow().isoformat(),
            'run_id': run_id,
            'previous_run_id': report.get('previous_run_id'),
            'total_changes': report.get('total_changes', 0),
            'has_data': True,
            'summary': {
                'new_identities': report.get('new_identities_count', 0),
                'removed_identities': report.get('removed_identities_count', 0),
                'permission_changes': report.get('permission_changes_count', 0),
                'risk_changes': report.get('risk_changes_count', 0),
                'credential_changes': report.get('credential_changes_count', 0),
            },
            'changes': flat_changes,
        })
    finally:
        db.close()


def _export_risk_summary():
    """Export executive risk summary for SIEM/GRC integration."""
    db = _db()
    try:
        data = db.get_report_data()
        if data is None:
            return jsonify({'error': 'No completed discovery runs found'}), 404

        top_risks = []
        for tr in data.get('top_risks', []):
            top_risks.append({
                'identity_id': tr.get('identity_id'),
                'display_name': tr.get('display_name'),
                'identity_category': tr.get('identity_category'),
                'risk_level': tr.get('risk_level'),
                'risk_score': tr.get('risk_score'),
                'risk_reasons': tr.get('risk_reasons', []),
                'top_remediation': tr['remediations'][0]['title'] if tr.get('remediations') else None,
            })

        try:
            _log(db,'export', 'Risk summary export generated',
                            {'export_type': 'risk-summary'})
        except Exception:
            pass

        return jsonify({
            'export_type': 'risk-summary',
            'generated_at': datetime.utcnow().isoformat(),
            'run_id': data.get('run_id'),
            'collected_at': data.get('collected_at'),
            'risk_distribution': data.get('stats'),
            'credential_health': data.get('credential_health'),
            'conditional_access': data.get('conditional_access'),
            'top_risks': top_risks,
            'remediation_priorities': data.get('remediation_summary', {}).get('top_priorities', []),
        })
    finally:
        db.close()


# ─── Saved Views (Phase 34) ─────────────────────────────────────────

def get_saved_views_list():
    """GET /api/saved-views — list current user's views + shared views."""
    user = g.current_user
    db = _db()
    try:
        views = db.get_saved_views(user['id'])
        return jsonify({'views': views, 'count': len(views)})
    finally:
        db.close()


def create_saved_view_handler():
    """POST /api/saved-views — create a new saved view."""
    user = g.current_user
    data = request.get_json(silent=True) or {}

    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if len(name) > 100:
        return jsonify({'error': 'Name must be 100 characters or less'}), 400

    filters = data.get('filters', {})
    if not isinstance(filters, dict):
        return jsonify({'error': 'Filters must be an object'}), 400

    db = _db()
    try:
        view = db.create_saved_view(
            user_id=user['id'],
            name=name,
            description=(data.get('description') or '').strip() or None,
            filters=filters,
            sort_field=data.get('sort_field'),
            sort_direction=data.get('sort_direction', 'desc'),
            is_shared=bool(data.get('is_shared', False)) and user['role'] == 'admin',
        )
        try:
            _log(db,'saved_view', f'Created saved view "{name}"',
                            {'view_id': view['id'], 'user': user['username']})
        except Exception:
            pass
        return jsonify(view), 201
    finally:
        db.close()


def update_saved_view_handler(view_id):
    """PUT /api/saved-views/<id> — update an existing saved view."""
    user = g.current_user
    data = request.get_json(silent=True) or {}

    db = _db()
    try:
        existing = db.get_saved_view(view_id)
        if not existing:
            return jsonify({'error': 'View not found'}), 404
        if existing['user_id'] != user['id'] and user['role'] != 'admin':
            return jsonify({'error': 'Not authorized'}), 403

        update_fields = {}
        if 'name' in data:
            name = (data['name'] or '').strip()
            if not name:
                return jsonify({'error': 'Name is required'}), 400
            if len(name) > 100:
                return jsonify({'error': 'Name must be 100 characters or less'}), 400
            update_fields['name'] = name
        if 'description' in data:
            update_fields['description'] = (data['description'] or '').strip() or None
        if 'filters' in data:
            if not isinstance(data['filters'], dict):
                return jsonify({'error': 'Filters must be an object'}), 400
            update_fields['filters'] = data['filters']
        if 'sort_field' in data:
            update_fields['sort_field'] = data['sort_field']
        if 'sort_direction' in data:
            update_fields['sort_direction'] = data['sort_direction']
        if 'is_shared' in data and user['role'] == 'admin':
            update_fields['is_shared'] = bool(data['is_shared'])

        view = db.update_saved_view(view_id, **update_fields)
        try:
            _log(db,'saved_view', f'Updated saved view "{view["name"]}"',
                            {'view_id': view_id, 'user': user['username']})
        except Exception:
            pass
        return jsonify(view)
    finally:
        db.close()


def delete_saved_view_handler(view_id):
    """DELETE /api/saved-views/<id> — delete a saved view."""
    user = g.current_user
    db = _db()
    try:
        existing = db.get_saved_view(view_id)
        if not existing:
            return jsonify({'error': 'View not found'}), 404
        if existing['user_id'] != user['id'] and user['role'] != 'admin':
            return jsonify({'error': 'Not authorized'}), 403

        db.delete_saved_view(view_id)
        try:
            _log(db,'saved_view', f'Deleted saved view "{existing["name"]}"',
                            {'view_id': view_id, 'user': user['username']})
        except Exception:
            pass
        return jsonify({'status': 'deleted', 'id': view_id})
    finally:
        db.close()


def set_default_view_handler(view_id):
    """POST /api/saved-views/<id>/default — set view as user's default."""
    user = g.current_user
    db = _db()
    try:
        view = db.set_default_view(user['id'], view_id)
        if not view:
            return jsonify({'error': 'View not found'}), 404
        return jsonify(view)
    finally:
        db.close()


# ─── Identity Lifecycle (Phase 35) ──────────────────────────────────

_RISK_SEVERITY = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

def _lifecycle_severity_for_risk(level):
    """Map risk level to event severity."""
    if level in ('critical', 'high'):
        return level
    return 'medium'


def _compare_snapshots(prev, curr, timestamp, run_id):
    """Compare two identity snapshots and return lifecycle events."""
    events = []

    def _add(event_type, category, desc, prev_val, curr_val, severity):
        events.append({
            'timestamp': timestamp,
            'run_id': run_id,
            'event_type': event_type,
            'category': category,
            'description': desc,
            'previous_value': str(prev_val) if prev_val is not None else None,
            'current_value': str(curr_val) if curr_val is not None else None,
            'severity': severity,
        })

    # Risk level
    p_risk = (prev.get('risk_level') or 'info').lower()
    c_risk = (curr.get('risk_level') or 'info').lower()
    if p_risk != c_risk:
        p_ord = _RISK_SEVERITY.get(p_risk, 0)
        c_ord = _RISK_SEVERITY.get(c_risk, 0)
        if c_ord > p_ord:
            _add('risk_escalation', 'risk',
                 f'Risk level escalated: {p_risk} \u2192 {c_risk}',
                 p_risk, c_risk, _lifecycle_severity_for_risk(c_risk))
        else:
            _add('risk_deescalation', 'risk',
                 f'Risk level decreased: {p_risk} \u2192 {c_risk}',
                 p_risk, c_risk, 'info')

    # Risk score
    p_score = int(prev.get('risk_score') or 0)
    c_score = int(curr.get('risk_score') or 0)
    delta = c_score - p_score
    if abs(delta) >= 5:
        if delta > 0:
            _add('risk_score_increase', 'risk',
                 f'Risk score increased: {p_score} \u2192 {c_score} (+{delta})',
                 p_score, c_score, 'medium')
        else:
            _add('risk_score_decrease', 'risk',
                 f'Risk score decreased: {p_score} \u2192 {c_score} ({delta})',
                 p_score, c_score, 'info')

    # Enabled
    p_enabled = prev.get('enabled')
    c_enabled = curr.get('enabled')
    if p_enabled is not None and c_enabled is not None and p_enabled != c_enabled:
        if c_enabled:
            _add('enabled_changed', 'lifecycle', 'Identity re-enabled',
                 'disabled', 'enabled', 'high')
        else:
            _add('enabled_changed', 'lifecycle', 'Identity disabled',
                 'enabled', 'disabled', 'medium')

    # Activity status
    p_act = prev.get('activity_status') or 'unknown'
    c_act = curr.get('activity_status') or 'unknown'
    if p_act != c_act:
        sev = 'medium' if c_act in ('stale', 'never_used') else 'info'
        _add('activity_status_changed', 'activity',
             f'Activity status: {p_act} \u2192 {c_act}',
             p_act, c_act, sev)

    # Credential status
    p_cred = prev.get('credential_status') or 'unknown'
    c_cred = curr.get('credential_status') or 'unknown'
    if p_cred != c_cred:
        sev = 'high' if c_cred == 'expired' else ('medium' if c_cred in ('critical', 'warning') else 'info')
        _add('credential_status_changed', 'credential',
             f'Credential status: {p_cred} \u2192 {c_cred}',
             p_cred, c_cred, sev)

    # Credential count
    p_cc = int(prev.get('credential_count') or 0)
    c_cc = int(curr.get('credential_count') or 0)
    if p_cc != c_cc:
        direction = 'added' if c_cc > p_cc else 'removed'
        _add('credential_count_changed', 'credential',
             f'Credentials {direction}: {p_cc} \u2192 {c_cc}',
             p_cc, c_cc, 'medium')

    # API permissions
    p_perm = int(prev.get('api_permission_count') or 0)
    c_perm = int(curr.get('api_permission_count') or 0)
    if p_perm != c_perm:
        sev = 'high' if c_perm > p_perm else 'info'
        direction = 'granted' if c_perm > p_perm else 'revoked'
        _add('permissions_changed', 'access',
             f'API permissions {direction}: {p_perm} \u2192 {c_perm}',
             p_perm, c_perm, sev)

    # Owner
    p_owner = prev.get('owner_display_name') or ''
    c_owner = curr.get('owner_display_name') or ''
    if p_owner != c_owner:
        if not p_owner and c_owner:
            desc = f'Owner assigned: {c_owner}'
        elif p_owner and not c_owner:
            desc = f'Owner removed (was: {p_owner})'
        else:
            desc = f'Owner changed: {p_owner} \u2192 {c_owner}'
        _add('ownership_changed', 'lifecycle', desc, p_owner or None, c_owner or None, 'medium')

    # CA coverage
    p_ca = prev.get('ca_coverage_status') or 'unknown'
    c_ca = curr.get('ca_coverage_status') or 'unknown'
    if p_ca != c_ca:
        sev = 'high' if c_ca in ('no_coverage', 'excluded') else 'info'
        _add('ca_coverage_changed', 'compliance',
             f'CA coverage: {p_ca} \u2192 {c_ca}',
             p_ca, c_ca, sev)

    return events


def get_identity_lifecycle(identity_id):
    """GET /api/identities/<identity_id>/lifecycle — lifecycle timeline."""
    db = _db()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT i.identity_id, i.display_name, i.risk_level, i.risk_score,
                   i.enabled, i.activity_status, i.credential_status, i.credential_count,
                   COALESCE(i.api_permission_count, 0) as api_permission_count,
                   i.owner_display_name, i.ca_coverage_status, i.ca_mfa_enforced,
                   i.created_datetime, i.discovery_run_id,
                   dr.completed_at as run_completed_at
            FROM identities i
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE i.identity_id = %s AND dr.status = 'completed'
            ORDER BY dr.completed_at ASC
        """, (identity_id,))
        snapshots = [dict(r) for r in cursor.fetchall()]
        cursor.close()

        if not snapshots:
            return jsonify({'error': 'Identity not found'}), 404

        events = []
        first = snapshots[0]
        first_ts = first['run_completed_at'].isoformat() if first.get('run_completed_at') else first.get('created_datetime', '')
        if isinstance(first_ts, str):
            pass
        else:
            first_ts = first_ts.isoformat() if first_ts else ''

        # "Created" event
        created_ts = first.get('created_datetime')
        events.append({
            'timestamp': created_ts.isoformat() if created_ts else first_ts,
            'run_id': first.get('discovery_run_id'),
            'event_type': 'identity_created',
            'category': 'lifecycle',
            'description': f'Identity first discovered: {first.get("display_name", identity_id)}',
            'previous_value': None,
            'current_value': (first.get('risk_level') or 'info'),
            'severity': 'info',
        })

        # Summary counters
        summary = {
            'total_runs_observed': len(snapshots),
            'first_seen': first_ts,
            'last_seen': None,
            'risk_changes': 0,
            'credential_events': 0,
            'access_changes': 0,
            'status_changes': 0,
        }

        # Compare consecutive snapshots
        for i in range(1, len(snapshots)):
            prev_snap = snapshots[i - 1]
            curr_snap = snapshots[i]
            ts = curr_snap['run_completed_at']
            ts_str = ts.isoformat() if ts else ''
            run_id = curr_snap.get('discovery_run_id')

            new_events = _compare_snapshots(prev_snap, curr_snap, ts_str, run_id)
            for ev in new_events:
                cat = ev['category']
                if cat == 'risk':
                    summary['risk_changes'] += 1
                elif cat == 'credential':
                    summary['credential_events'] += 1
                elif cat == 'access':
                    summary['access_changes'] += 1
                elif cat in ('lifecycle', 'activity', 'compliance'):
                    summary['status_changes'] += 1
            events.extend(new_events)

        last = snapshots[-1]
        last_ts = last['run_completed_at']
        summary['last_seen'] = last_ts.isoformat() if last_ts else ''

        # Sort events newest-first for display
        events.sort(key=lambda e: e.get('timestamp', ''), reverse=True)

        return jsonify({
            'identity_id': identity_id,
            'display_name': first.get('display_name', identity_id),
            'total_events': len(events),
            'events': events,
            'summary': summary,
        })
    finally:
        db.close()


# ===================================================================
# Access Review Campaigns (Phase 36)
# ===================================================================

def get_access_reviews_list():
    """List all access review campaigns with progress stats."""
    db = _db()
    try:
        status = request.args.get('status')
        campaigns = db.get_campaigns(status=status)
        return jsonify({'campaigns': campaigns})
    finally:
        db.close()


def create_access_review():
    """Create a new access review campaign and populate review items (V2)."""
    db = _db()
    try:
        user = g.current_user
        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        name = (body.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'name is required'}), 400
        if len(name) > 255:
            return jsonify({'error': 'name must be 255 characters or less'}), 400

        description = body.get('description', '')
        deadline = body.get('deadline')
        scope = body.get('scope', {})
        if not isinstance(scope, dict):
            return jsonify({'error': 'scope must be an object'}), 400

        has_criteria = (scope.get('risk_levels') or scope.get('identity_categories')
                        or scope.get('identity_ids'))
        if not has_criteria:
            return jsonify({'error': 'At least one scope criteria is required (risk_levels, identity_categories, or identity_ids)'}), 400

        # V2 fields
        campaign_type = body.get('campaign_type', 'general')
        scope_clouds = body.get('scope_clouds')
        scope_description = body.get('scope_description', '')
        risk_focus = body.get('risk_focus')
        tenant_id = _tenant_id()

        campaign = db.create_campaign(name, description, scope, deadline, user['id'],
                                      campaign_type=campaign_type, scope_clouds=scope_clouds,
                                      scope_description=scope_description, risk_focus=risk_focus,
                                      tenant_id=tenant_id)
        review_count = db.populate_campaign_reviews(campaign['id'], scope, user['id'], deadline=deadline)

        # Audit log
        db.log_campaign_audit(campaign['id'], None, 'campaign_created', user['id'],
                              metadata={'review_count': review_count, 'scope': scope, 'campaign_type': campaign_type})

        _log(db,'campaign_created',
                        f'Access review campaign "{name}" created with {review_count} identities',
                        {'campaign_id': campaign['id'], 'review_count': review_count, 'campaign_type': campaign_type})

        try:
            db.create_notification('access_review', 'access_review', 'info',
                                   f'Campaign "{name}" started',
                                   f'{review_count} identities included for review',
                                   {'campaign_id': campaign['id']}, None, None, None)
        except Exception:
            pass

        campaign = db.get_campaign(campaign['id'])
        return jsonify({'campaign': campaign, 'review_count': review_count}), 201
    finally:
        db.close()


def get_access_review_detail(campaign_id):
    """Get a single campaign with paginated, filtered, sorted review items (V2)."""
    db = _db()
    try:
        campaign = db.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404

        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))
        sort_by = request.args.get('sort_by', 'risk_score')
        sort_dir = request.args.get('sort_dir', 'desc')
        status_filter = request.args.get('status')
        risk_filter = request.args.get('risk_level')
        type_filter = request.args.get('identity_type')
        search = request.args.get('search')

        result = db.get_campaign_reviews_v2(campaign_id, limit=limit, offset=offset,
                                            sort_by=sort_by, sort_dir=sort_dir,
                                            status_filter=status_filter, risk_filter=risk_filter,
                                            type_filter=type_filter, search=search)
        return jsonify({'campaign': campaign, **result})
    finally:
        db.close()


def update_access_review(campaign_id):
    """Update campaign fields or transition status."""
    db = _db()
    try:
        existing = db.get_campaign(campaign_id)
        if not existing:
            return jsonify({'error': 'Campaign not found'}), 404

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        updates = {}
        if 'name' in body:
            updates['name'] = body['name']
        if 'description' in body:
            updates['description'] = body['description']
        if 'deadline' in body:
            updates['deadline'] = body['deadline']

        if 'status' in body:
            new_status = body['status']
            current = existing['status']
            valid_transitions = {
                'active': ['completed'],
                'completed': ['archived'],
            }
            allowed = valid_transitions.get(current, [])
            if new_status not in allowed:
                return jsonify({'error': f'Cannot transition from {current} to {new_status}'}), 400
            updates['status'] = new_status

        db.update_campaign(campaign_id, **updates)
        updated = db.get_campaign(campaign_id)

        if updates.get('status'):
            _log(db,'campaign_status_changed',
                            f'Campaign "{existing["name"]}" status: {existing["status"]} → {updates["status"]}',
                            {'campaign_id': campaign_id, 'old_status': existing['status'],
                             'new_status': updates['status']})
            if updates['status'] == 'completed':
                try:
                    db.create_notification('access_review', 'access_review', 'info',
                                           f'Campaign "{existing["name"]}" completed',
                                           f'{updated.get("completed_reviews", 0)} of {updated.get("total_reviews", 0)} identities reviewed',
                                           {'campaign_id': campaign_id}, None, None, None)
                except Exception:
                    pass

        return jsonify(updated)
    finally:
        db.close()


def delete_access_review(campaign_id):
    """Delete a campaign (only if archived)."""
    db = _db()
    try:
        existing = db.get_campaign(campaign_id)
        if not existing:
            return jsonify({'error': 'Campaign not found'}), 404
        if existing['status'] not in ('archived',):
            return jsonify({'error': 'Only archived campaigns can be deleted'}), 400

        db.delete_campaign(campaign_id)
        _log(db,'campaign_deleted', f'Campaign "{existing["name"]}" deleted',
                        {'campaign_id': campaign_id})
        return jsonify({'status': 'deleted', 'id': campaign_id})
    finally:
        db.close()


def update_review_decision(campaign_id, review_id):
    """Set a decision on a single review item with audit trail."""
    db = _db()
    try:
        user = g.current_user
        campaign = db.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        if campaign['status'] != 'active':
            return jsonify({'error': 'Campaign is not active'}), 400

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        decision = body.get('decision')
        if decision not in ('approve', 'revoke', 'flag', 'downgrade', 'convert_pim', 'rotate_secret'):
            return jsonify({'error': 'decision must be one of: approve, revoke, flag, downgrade, convert_pim, rotate_secret'}), 400

        notes = body.get('notes')

        # Capture old decision for audit
        old_reviews = db.get_campaign_reviews(campaign_id)
        old_decision = None
        for r in old_reviews:
            if r['id'] == review_id:
                old_decision = r.get('decision')
                break

        result = db.update_campaign_review(review_id, decision, notes, user['id'])
        if not result:
            return jsonify({'error': 'Review not found'}), 404

        # Audit log
        db.log_campaign_audit(campaign_id, review_id, 'decision_made', user['id'],
                              old_value=old_decision, new_value=decision,
                              metadata={'identity': result.get('identity_display_name', ''),
                                        'notes': notes, 'reviewer': user['username']})

        _log(db,'review_decided',
                        f'Review decision: {decision} for {result.get("identity_display_name", "")}',
                        {'campaign_id': campaign_id, 'review_id': review_id,
                         'decision': decision, 'reviewer': user['username']})

        return jsonify(result)
    finally:
        db.close()


def bulk_review_decisions(campaign_id):
    """Bulk set decision on multiple review items with audit trail."""
    db = _db()
    try:
        user = g.current_user
        campaign = db.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        if campaign['status'] != 'active':
            return jsonify({'error': 'Campaign is not active'}), 400

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Request body required'}), 400

        review_ids = body.get('review_ids', [])
        if not review_ids or not isinstance(review_ids, list):
            return jsonify({'error': 'review_ids must be a non-empty list'}), 400
        if len(review_ids) > 100:
            return jsonify({'error': 'Maximum 100 reviews per bulk action'}), 400

        decision = body.get('decision')
        if decision not in ('approve', 'revoke', 'flag', 'downgrade', 'convert_pim', 'rotate_secret'):
            return jsonify({'error': 'decision must be one of: approve, revoke, flag, downgrade, convert_pim, rotate_secret'}), 400

        notes = body.get('notes')
        count = db.bulk_update_campaign_reviews(review_ids, decision, notes, user['id'])

        # Audit log for bulk action
        db.log_campaign_audit(campaign_id, None, 'bulk_decision', user['id'],
                              new_value=decision,
                              metadata={'review_ids': review_ids, 'count': count,
                                        'notes': notes, 'reviewer': user['username']})

        _log(db,'review_bulk_decided',
                        f'Bulk {decision}: {count} reviews in campaign "{campaign["name"]}"',
                        {'campaign_id': campaign_id, 'decision': decision,
                         'count': count, 'reviewer': user['username']})

        return jsonify({'updated_count': count})
    finally:
        db.close()


def get_campaign_metrics_handler():
    """Return campaign dashboard KPIs."""
    db = _db()
    try:
        metrics = db.get_campaign_metrics()
        return jsonify(metrics)
    finally:
        db.close()


def get_campaign_audit_log_handler(campaign_id):
    """Return audit trail for a campaign."""
    db = _db()
    try:
        campaign = db.get_campaign(campaign_id)
        if not campaign:
            return jsonify({'error': 'Campaign not found'}), 404
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = int(request.args.get('offset', 0))
        result = db.get_campaign_audit_log(campaign_id, limit=limit, offset=offset)
        return jsonify(result)
    finally:
        db.close()


# ---------------------------------------------------------------
# Identity Groups (Phase 38)
# ---------------------------------------------------------------

def get_groups_list():
    db = _db()
    try:
        groups = db.get_groups()
        return jsonify({'groups': groups})
    finally:
        db.close()


def create_group_handler():
    db = _db()
    try:
        body = request.get_json(force=True)
        name = (body.get('name') or '').strip()
        if not name or len(name) > 255:
            return jsonify({'error': 'name is required (max 255 chars)'}), 400

        user = getattr(g, 'current_user', None) or {}
        data = {
            'name': name,
            'description': body.get('description'),
            'color': body.get('color', '#3B82F6'),
            'group_type': body.get('group_type', 'custom'),
            'auto_criteria': body.get('auto_criteria'),
            'created_by': user.get('id'),
        }
        group = db.create_group(data)
        _log(db,'group_created', f'Created group "{name}"',
                        {'group_id': group['id'], 'user': user.get('username')})
        return jsonify(group), 201
    finally:
        db.close()


def get_group_detail(group_id):
    db = _db()
    try:
        group = db.get_group(group_id)
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify(group)
    finally:
        db.close()


def update_group_handler(group_id):
    db = _db()
    try:
        body = request.get_json(force=True)
        result = db.update_group(group_id, body)
        if not result:
            return jsonify({'error': 'Group not found'}), 404
        return jsonify(result)
    finally:
        db.close()


def delete_group_handler(group_id):
    db = _db()
    try:
        deleted = db.delete_group(group_id)
        if not deleted:
            return jsonify({'error': 'Group not found or is an auto group'}), 400
        _log(db,'group_deleted', f'Deleted group #{group_id}', {'group_id': group_id})
        return jsonify({'deleted': True})
    finally:
        db.close()


def add_group_members_handler(group_id):
    db = _db()
    try:
        body = request.get_json(force=True)
        identity_ids = body.get('identity_ids', [])
        if not identity_ids or not isinstance(identity_ids, list):
            return jsonify({'error': 'identity_ids must be a non-empty list'}), 400

        # Check group exists and is custom
        group = db.get_group(group_id)
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        if group.get('group_type') == 'auto':
            return jsonify({'error': 'Cannot manually add members to auto groups'}), 400

        added = db.add_group_members(group_id, identity_ids)
        return jsonify({'added': added})
    finally:
        db.close()


def remove_group_members_handler(group_id):
    db = _db()
    try:
        body = request.get_json(force=True)
        identity_ids = body.get('identity_ids', [])
        if not identity_ids or not isinstance(identity_ids, list):
            return jsonify({'error': 'identity_ids must be a non-empty list'}), 400

        group = db.get_group(group_id)
        if not group:
            return jsonify({'error': 'Group not found'}), 404
        if group.get('group_type') == 'auto':
            return jsonify({'error': 'Cannot manually remove members from auto groups'}), 400

        removed = db.remove_group_members(group_id, identity_ids)
        return jsonify({'removed': removed})
    finally:
        db.close()


def get_group_comparison_handler():
    db = _db()
    try:
        ids_param = request.args.get('ids', '')
        try:
            group_ids = [int(x.strip()) for x in ids_param.split(',') if x.strip()]
        except ValueError:
            return jsonify({'error': 'ids must be comma-separated integers'}), 400
        if len(group_ids) < 2 or len(group_ids) > 3:
            return jsonify({'error': 'Provide 2-3 group ids'}), 400
        results = db.get_group_comparison(group_ids)
        return jsonify({'groups': results})
    finally:
        db.close()


def get_identity_groups_handler(identity_id):
    db = _db()
    try:
        groups = db.get_identity_groups(identity_id)
        return jsonify({'groups': groups})
    finally:
        db.close()


# ============================================================
# Phase 39: Advanced Query Builder — Endpoints
# ============================================================

QUERY_SORT_ALLOWLIST = {
    'display_name': "i.display_name",
    'identity_type': "i.identity_type",
    'identity_category': "COALESCE(i.identity_category, '')",
    'cloud': "COALESCE(i.cloud, 'azure')",
    'risk_level': """CASE i.risk_level
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2
        WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END""",
    'risk_score': "COALESCE(i.risk_score, 0)",
    'credential_count': "COALESCE(i.credential_count, 0)",
    'owner_count': "COALESCE(i.owner_count, 0)",
    'api_permission_count': "COALESCE(i.api_permission_count, 0)",
    'app_role_count': "COALESCE(i.app_role_count, 0)",
    'created_datetime': "i.created_datetime",
    'last_seen_auth': "i.last_seen_auth",
    'last_sign_in': "i.last_sign_in",
    'activity_status': "i.activity_status",
    'credential_expiration': "i.credential_expiration",
    'pim_eligible_count': "COALESCE(i.pim_eligible_count, 0)",
}


def query_identities():
    """POST /api/identities/query — Advanced query builder endpoint."""
    db = _db()
    data = request.get_json(silent=True) or {}

    groups = data.get('groups', [])
    sort_field = data.get('sort_field', 'risk_level')
    sort_direction = data.get('sort_direction', 'desc')
    limit = data.get('limit')
    offset = data.get('offset', 0)

    # Validate structure
    if not isinstance(groups, list):
        return jsonify({'error': 'groups must be a list'}), 400
    if len(groups) > 10:
        return jsonify({'error': 'Maximum 10 condition groups'}), 400

    for gi, group in enumerate(groups):
        if not isinstance(group, dict):
            return jsonify({'error': f'Group {gi}: must be an object'}), 400
        conditions = group.get('conditions', [])
        if not isinstance(conditions, list):
            return jsonify({'error': f'Group {gi}: conditions must be a list'}), 400
        if len(conditions) > 10:
            return jsonify({'error': f'Group {gi}: maximum 10 conditions per group'}), 400
        for ci, cond in enumerate(conditions):
            if not isinstance(cond, dict):
                return jsonify({'error': f'Group {gi}, condition {ci}: must be an object'}), 400
            field = cond.get('field', '')
            if field not in QUERY_FIELD_MAP and field not in QUERY_COMPUTED_FIELDS:
                return jsonify({'error': f'Group {gi}, condition {ci}: unknown field "{field}"'}), 400
            operator = cond.get('operator', 'equals')
            if operator not in QUERY_OPERATORS:
                return jsonify({'error': f'Group {gi}, condition {ci}: unknown operator "{operator}"'}), 400

    cursor = db.conn.cursor()
    try:
        latest_run = _latest_run_query(cursor, _tenant_id())
        if not latest_run:
            return jsonify({'error': 'No completed discovery runs found'}), 404

        try:
            adv_where, adv_params = _build_advanced_query_where(groups)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        query = _identity_list_select() + " WHERE i.discovery_run_id = %s"
        params = [latest_run]

        query += adv_where
        params.extend(adv_params)

        # Total count
        count_query = f"SELECT COUNT(*) FROM ({query}) sub"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Sort
        sort_dir = "DESC" if sort_direction == 'desc' else "ASC"
        if sort_field in QUERY_SORT_ALLOWLIST:
            query += f" ORDER BY {QUERY_SORT_ALLOWLIST[sort_field]} {sort_dir} NULLS LAST, i.display_name"
        else:
            query += f""" ORDER BY CASE i.risk_level
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END {sort_dir}, i.display_name"""

        # Pagination
        if limit:
            query += " LIMIT %s OFFSET %s"
            params.extend([int(limit), int(offset)])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        identities = [_map_identity_row(row) for row in rows]

        result = {
            'count': len(identities),
            'total': total_count,
            'identities': identities,
            'query': {'groups': groups},
        }
        if limit:
            result['limit'] = limit
            result['offset'] = offset
            result['has_more'] = (int(offset) + len(identities)) < total_count
        return jsonify(result)

    finally:
        cursor.close()
        db.close()


def get_query_fields():
    """GET /api/identities/query/fields — Return queryable field definitions."""
    all_fields = {}
    all_fields.update(QUERY_FIELD_MAP)
    all_fields.update(QUERY_COMPUTED_FIELDS)

    fields = []
    for name in sorted(all_fields.keys()):
        field_type = 'string'
        if name in QUERY_NUMERIC_FIELDS:
            field_type = 'number'
        elif name in QUERY_BOOLEAN_FIELDS:
            field_type = 'boolean'
        elif name in QUERY_DATE_FIELDS:
            field_type = 'date'

        label = name.replace('_', ' ').title()
        fields.append({
            'name': name,
            'type': field_type,
            'label': label,
        })

    suggestions = {
        'risk_level': ['critical', 'high', 'medium', 'low', 'info'],
        'identity_category': ['service_principal', 'managed_identity_system',
                              'managed_identity_user', 'human_user', 'guest'],
        'cloud': ['azure', 'aws', 'gcp'],
        'status': ['active', 'disabled', 'deleted'],
        'activity_status': ['active', 'inactive', 'stale', 'never_used',
                            'recently_created', 'unknown'],
        'credential_status': ['expired', 'critical', 'warning', 'good', 'unknown'],
        'credential_risk': ['expired', 'expiring_soon', 'healthy', 'unknown'],
        'ca_coverage_status': ['covered', 'no_coverage', 'excluded'],
    }

    return jsonify({
        'fields': fields,
        'operators': list(QUERY_OPERATORS.keys()),
        'value_suggestions': suggestions,
    })


# ================================================================
# Phase 40: Anomaly Detection
# ================================================================

def get_anomalies_list():
    """GET /api/anomalies — list anomalies with optional filters."""
    db = _db()
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))
        anomaly_type = request.args.get('type')
        severity = request.args.get('severity')
        identity_id = request.args.get('identity_id')
        run_id = request.args.get('run_id', type=int)
        resolved_param = request.args.get('resolved')
        resolved = None
        if resolved_param is not None:
            resolved = resolved_param.lower() == 'true'

        anomalies = db.get_anomalies(
            limit=limit, offset=offset, anomaly_type=anomaly_type,
            severity=severity, identity_id=identity_id, resolved=resolved,
            run_id=run_id,
        )
        return jsonify({'anomalies': anomalies, 'count': len(anomalies)})
    finally:
        db.close()


def get_anomaly_stats_handler():
    """GET /api/anomalies/stats — anomaly summary stats."""
    db = _db()
    try:
        stats = db.get_anomaly_stats()
        return jsonify(stats)
    finally:
        db.close()


def get_anomaly_detail(anomaly_id):
    """GET /api/anomalies/<id> — single anomaly detail."""
    db = _db()
    try:
        anomaly = db.get_anomaly(anomaly_id)
        if not anomaly:
            return jsonify({'error': 'Anomaly not found'}), 404
        return jsonify(anomaly)
    finally:
        db.close()


def resolve_anomaly_handler(anomaly_id):
    """PATCH /api/anomalies/<id> — resolve or update anomaly (admin/auditor)."""
    user = getattr(g, 'current_user', None)
    if user and user.get('role') == 'viewer':
        return jsonify({'error': 'Not authorized'}), 403

    data = request.get_json(silent=True) or {}
    db = _db()
    try:
        resolved_by = user['username'] if user else data.get('resolved_by')
        result = db.resolve_anomaly(anomaly_id, resolved_by=resolved_by)
        if not result:
            return jsonify({'error': 'Anomaly not found'}), 404
        return jsonify(result)
    finally:
        db.close()


def get_identity_anomalies_handler(identity_id):
    """GET /api/identities/<id>/anomalies — anomalies for a specific identity."""
    db = _db()
    try:
        limit = min(int(request.args.get('limit', 20)), 100)
        anomalies = db.get_identity_anomalies(identity_id, limit=limit)
        return jsonify({'anomalies': anomalies, 'count': len(anomalies)})
    finally:
        db.close()


def get_dashboard_anomalies():
    """GET /api/dashboard/anomalies — top unresolved anomalies for dashboard widget."""
    db = _db()
    try:
        limit = min(int(request.args.get('limit', 5)), 20)
        anomalies = db.get_anomalies_for_dashboard(limit=limit)
        stats = db.get_anomaly_stats()
        return jsonify({
            'anomalies': anomalies,
            'unresolved_count': stats['unresolved'],
        })
    finally:
        db.close()


# ── Phase 42: API Key Management ─────────────────────────────────

def get_api_keys_list():
    """GET /api/api-keys — list all API keys (admin only). Never returns hashes."""
    db = _db()
    try:
        keys = db.get_api_keys()
        return jsonify({'api_keys': keys})
    finally:
        db.close()


def create_api_key_handler():
    """POST /api/api-keys — create a new API key (admin only).
    Returns the full key ONCE in the response."""
    import secrets as _secrets
    import hashlib as _hashlib

    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    description = str(data.get('description', '')).strip()
    role = str(data.get('role', 'viewer')).strip().lower()
    expires_at = data.get('expires_at')

    errors = []
    if not name:
        errors.append('name is required')
    elif len(name) > 255:
        errors.append('name must be 255 characters or less')
    if role not in VALID_ROLES:
        errors.append(f'role must be one of: {", ".join(sorted(VALID_ROLES))}')
    if errors:
        return jsonify({'error': '; '.join(errors)}), 400

    raw_key = 'ag_' + _secrets.token_hex(16)
    key_prefix = raw_key[:8]
    key_hash = _hashlib.sha256(raw_key.encode()).hexdigest()

    current_user = getattr(g, 'current_user', None)
    created_by = current_user['id'] if current_user else None

    db = _db()
    try:
        api_key = db.create_api_key(
            key_prefix=key_prefix,
            key_hash=key_hash,
            name=name,
            description=description or None,
            role=role,
            created_by=created_by,
            expires_at=expires_at,
        )

        try:
            _log(db,'api_key_created',
                f'API key "{name}" created with role "{role}"',
                {'api_key_id': api_key['id'], 'role': role,
                 'created_by': created_by, 'key_prefix': key_prefix})
        except Exception:
            pass

        return jsonify({
            'api_key': api_key,
            'key': raw_key,
            'message': 'API key created. Copy the key now — it will not be shown again.'
        }), 201
    finally:
        db.close()


def update_api_key_handler(key_id):
    """PUT /api/api-keys/<id> — update an API key (admin only)."""
    data = request.get_json(silent=True) or {}
    db = _db()
    try:
        existing = db.get_api_key_by_id(key_id)
        if not existing:
            return jsonify({'error': 'API key not found'}), 404

        updates = {}
        errors = []

        if 'name' in data:
            name = str(data['name']).strip()
            if not name:
                errors.append('name cannot be empty')
            else:
                updates['name'] = name

        if 'description' in data:
            updates['description'] = str(data['description']).strip() or None

        if 'role' in data:
            role = str(data['role']).strip().lower()
            if role not in VALID_ROLES:
                errors.append(f'role must be one of: {", ".join(sorted(VALID_ROLES))}')
            else:
                updates['role'] = role

        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])

        if errors:
            return jsonify({'error': '; '.join(errors)}), 400
        if not updates:
            return jsonify({'api_key': existing, 'message': 'No changes'})

        api_key = db.update_api_key(key_id, **updates)

        try:
            _log(db,'api_key_updated',
                f'API key "{existing["name"]}" updated: {", ".join(updates.keys())}',
                {'api_key_id': key_id, 'changes': list(updates.keys())})
        except Exception:
            pass

        return jsonify({'api_key': api_key, 'message': 'API key updated'})
    finally:
        db.close()


def delete_api_key_handler(key_id):
    """DELETE /api/api-keys/<id> — delete an API key (admin only)."""
    db = _db()
    try:
        existing = db.get_api_key_by_id(key_id)
        if not existing:
            return jsonify({'error': 'API key not found'}), 404

        db.delete_api_key(key_id)

        current_user = getattr(g, 'current_user', None)
        try:
            _log(db,'api_key_deleted',
                f'API key "{existing["name"]}" deleted',
                {'deleted_key_id': key_id,
                 'deleted_by': current_user['id'] if current_user else None})
        except Exception:
            pass

        return jsonify({'message': f'API key "{existing["name"]}" deleted'})
    finally:
        db.close()


# ===================================================================
# Phase 43: SOAR Playbook & Action Handlers
# ===================================================================

_SOAR_TRIGGER_TYPES = {'anomaly', 'risk_escalation', 'drift', 'new_identity'}
_SOAR_ACTION_TYPES = {'webhook', 'create_ticket', 'send_notification', 'tag_for_review'}
_SOAR_INTEGRATIONS = {'servicenow', 'jira', 'slack', 'pagerduty', 'teams', 'custom_webhook', 'internal'}


def get_soar_playbooks_list():
    """GET /api/soar/playbooks — list all SOAR playbooks."""
    db = _db()
    try:
        playbooks = db.get_soar_playbooks()
        return jsonify({'playbooks': playbooks, 'total': len(playbooks)})
    finally:
        db.close()


def create_soar_playbook_handler():
    """POST /api/soar/playbooks — create a SOAR playbook (admin only)."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'name is required'}), 400

        trigger_type = data.get('trigger_type', '')
        if trigger_type not in _SOAR_TRIGGER_TYPES:
            return jsonify({'error': f'Invalid trigger_type. Must be one of: {sorted(_SOAR_TRIGGER_TYPES)}'}), 400

        action_type = data.get('action_type', '')
        if action_type not in _SOAR_ACTION_TYPES:
            return jsonify({'error': f'Invalid action_type. Must be one of: {sorted(_SOAR_ACTION_TYPES)}'}), 400

        integration = data.get('integration', 'internal')
        if integration not in _SOAR_INTEGRATIONS:
            return jsonify({'error': f'Invalid integration. Must be one of: {sorted(_SOAR_INTEGRATIONS)}'}), 400

        # Limit total playbooks
        existing = db.get_soar_playbooks()
        if len(existing) >= 20:
            return jsonify({'error': 'Maximum of 20 SOAR playbooks allowed'}), 400

        current_user = getattr(g, 'current_user', None)
        playbook = db.create_soar_playbook(
            name=name,
            description=data.get('description', ''),
            trigger_type=trigger_type,
            trigger_conditions=data.get('trigger_conditions') or {},
            action_type=action_type,
            action_config=data.get('action_config') or {},
            integration=integration,
            cooldown_minutes=int(data.get('cooldown_minutes', 60)),
            created_by=current_user['username'] if current_user else None,
        )

        try:
            _log(db,'soar_playbook_created',
                f'SOAR playbook "{name}" created ({trigger_type} → {action_type} via {integration})',
                {'playbook_id': playbook['id'], 'trigger_type': trigger_type,
                 'action_type': action_type, 'integration': integration})
        except Exception:
            pass

        return jsonify({'playbook': playbook, 'message': 'Playbook created'}), 201
    finally:
        db.close()


def update_soar_playbook_handler(playbook_id):
    """PUT /api/soar/playbooks/<id> — update a SOAR playbook (admin only)."""
    db = _db()
    try:
        existing = db.get_soar_playbook(playbook_id)
        if not existing:
            return jsonify({'error': 'Playbook not found'}), 404

        data = request.get_json(silent=True) or {}
        updates = {}

        if 'name' in data:
            name = (data['name'] or '').strip()
            if not name:
                return jsonify({'error': 'name cannot be empty'}), 400
            updates['name'] = name
        if 'description' in data:
            updates['description'] = data['description']
        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])
        if 'trigger_type' in data:
            if data['trigger_type'] not in _SOAR_TRIGGER_TYPES:
                return jsonify({'error': f'Invalid trigger_type'}), 400
            updates['trigger_type'] = data['trigger_type']
        if 'trigger_conditions' in data:
            updates['trigger_conditions'] = data['trigger_conditions'] or {}
        if 'action_type' in data:
            if data['action_type'] not in _SOAR_ACTION_TYPES:
                return jsonify({'error': f'Invalid action_type'}), 400
            updates['action_type'] = data['action_type']
        if 'action_config' in data:
            updates['action_config'] = data['action_config'] or {}
        if 'integration' in data:
            if data['integration'] not in _SOAR_INTEGRATIONS:
                return jsonify({'error': f'Invalid integration'}), 400
            updates['integration'] = data['integration']
        if 'cooldown_minutes' in data:
            updates['cooldown_minutes'] = int(data['cooldown_minutes'])

        if not updates:
            return jsonify({'error': 'No valid fields to update'}), 400

        db.update_soar_playbook(playbook_id, **updates)
        playbook = db.get_soar_playbook(playbook_id)

        try:
            _log(db,'soar_playbook_updated',
                f'SOAR playbook "{playbook["name"]}" updated',
                {'playbook_id': playbook_id, 'changes': list(updates.keys())})
        except Exception:
            pass

        return jsonify({'playbook': playbook, 'message': 'Playbook updated'})
    finally:
        db.close()


def delete_soar_playbook_handler(playbook_id):
    """DELETE /api/soar/playbooks/<id> — delete a SOAR playbook (admin only)."""
    db = _db()
    try:
        existing = db.get_soar_playbook(playbook_id)
        if not existing:
            return jsonify({'error': 'Playbook not found'}), 404

        db.delete_soar_playbook(playbook_id)

        try:
            _log(db,'soar_playbook_deleted',
                f'SOAR playbook "{existing["name"]}" deleted',
                {'playbook_id': playbook_id})
        except Exception:
            pass

        return jsonify({'message': f'Playbook "{existing["name"]}" deleted'})
    finally:
        db.close()


def test_soar_playbook_handler(playbook_id):
    """POST /api/soar/playbooks/<id>/test — dry-run test a playbook (admin only)."""
    db = _db()
    try:
        from app.engines.soar_engine import SoarEngine
        engine = SoarEngine(db)
        result = engine.test_playbook(playbook_id)

        if 'error' in result:
            return jsonify(result), 404

        try:
            _log(db,'soar_playbook_tested',
                f'SOAR playbook "{result["playbook_name"]}" tested (would_match={result["would_match"]})',
                {'playbook_id': playbook_id, 'would_match': result['would_match']})
        except Exception:
            pass

        return jsonify(result)
    finally:
        db.close()


def get_soar_actions_list():
    """GET /api/soar/actions — list SOAR action history."""
    db = _db()
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))
        playbook_id = request.args.get('playbook_id')
        status = request.args.get('status')
        identity_id = request.args.get('identity_id')

        if playbook_id:
            playbook_id = int(playbook_id)

        actions = db.get_soar_actions(
            limit=limit, offset=offset,
            playbook_id=playbook_id, status=status,
            identity_id=identity_id,
        )
        return jsonify({'actions': actions, 'total': len(actions), 'limit': limit, 'offset': offset})
    finally:
        db.close()


def get_soar_action_stats_handler():
    """GET /api/soar/actions/stats — SOAR action statistics."""
    db = _db()
    try:
        stats = db.get_soar_action_stats()
        return jsonify(stats)
    finally:
        db.close()


def execute_soar_action_handler():
    """POST /api/soar/execute — manually trigger a SOAR playbook for a specific event."""
    db = _db()
    try:
        from app.engines.soar_engine import SoarEngine, MOCK_EVENTS

        data = request.get_json(silent=True) or {}
        playbook_id = data.get('playbook_id')
        if not playbook_id:
            return jsonify({'error': 'playbook_id is required'}), 400

        playbook = db.get_soar_playbook(int(playbook_id))
        if not playbook:
            return jsonify({'error': 'Playbook not found'}), 404

        if not playbook.get('enabled'):
            return jsonify({'error': 'Playbook is disabled'}), 400

        # Build event from request data or use mock
        event = data.get('event')
        if not event:
            event = dict(MOCK_EVENTS.get(playbook['trigger_type'], {}))
            if data.get('identity_id'):
                event['identity_id'] = data['identity_id']
            if data.get('identity_name'):
                event['identity_name'] = data['identity_name']

        engine = SoarEngine(db)
        try:
            engine._execute_action(playbook, event)
            status = 'success'
        except Exception as e:
            status = 'failed'
            return jsonify({'error': f'Action failed: {str(e)}', 'status': 'failed'}), 500

        try:
            _log(db,'soar_action_manual',
                f'Manual SOAR execution: playbook "{playbook["name"]}" ({playbook["integration"]})',
                {'playbook_id': playbook_id, 'status': status})
        except Exception:
            pass

        return jsonify({'message': 'Action executed', 'status': status, 'playbook_name': playbook['name']})
    finally:
        db.close()


# ===================================================================
# Phase 44: Dashboard Preferences Handlers
# ===================================================================

def get_dashboard_preferences_handler():
    """GET /api/dashboard/preferences — get current user's dashboard layout."""
    user = g.current_user
    db = _db()
    try:
        prefs = db.get_dashboard_preferences(user['id'])
        return jsonify({'preferences': prefs['preferences'] if prefs else None})
    finally:
        db.close()


def save_dashboard_preferences_handler():
    """PUT /api/dashboard/preferences — save/update dashboard layout."""
    user = g.current_user
    data = request.get_json(silent=True) or {}

    widgets = data.get('widgets')
    if widgets is None:
        return jsonify({'error': 'widgets array is required'}), 400
    if not isinstance(widgets, list):
        return jsonify({'error': 'widgets must be an array'}), 400
    if len(widgets) > 30:
        return jsonify({'error': 'Too many widgets (max 30)'}), 400

    for w in widgets:
        if not isinstance(w, dict) or 'id' not in w or 'visible' not in w:
            return jsonify({'error': 'Each widget must have id and visible fields'}), 400

    db = _db()
    try:
        result = db.save_dashboard_preferences(user['id'], {'widgets': widgets})

        try:
            _log(db,'dashboard_preferences',
                f'Dashboard layout updated by {user["username"]}',
                {'user_id': user['id']})
        except Exception:
            pass

        return jsonify({'preferences': result['preferences']})
    finally:
        db.close()


def reset_dashboard_preferences_handler():
    """DELETE /api/dashboard/preferences — reset to default layout."""
    user = g.current_user
    db = _db()
    try:
        db.delete_dashboard_preferences(user['id'])

        try:
            _log(db,'dashboard_preferences',
                f'Dashboard layout reset to default by {user["username"]}',
                {'user_id': user['id']})
        except Exception:
            pass

        return jsonify({'message': 'Dashboard reset to default'})
    finally:
        db.close()


# ===================================================================
# Phase 45: Multi-Tenant Management Handlers
# ===================================================================

def get_tenants_list():
    """GET /api/tenants — list all tenants (superadmin only)."""
    db = _db()
    try:
        tenants = db.get_tenants()
        return jsonify({'tenants': tenants})
    finally:
        db.close()


def create_tenant_handler():
    """POST /api/tenants — create a new tenant (superadmin only)."""
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    slug = str(data.get('slug', '')).strip().lower()
    plan = str(data.get('plan', 'free')).strip().lower()

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if len(name) > 255:
        return jsonify({'error': 'name must be 255 characters or less'}), 400
    if not slug:
        return jsonify({'error': 'slug is required'}), 400
    if not slug.replace('-', '').replace('_', '').isalnum():
        return jsonify({'error': 'slug must be alphanumeric (hyphens and underscores allowed)'}), 400
    if len(slug) > 100:
        return jsonify({'error': 'slug must be 100 characters or less'}), 400
    if plan not in ('free', 'trial', 'pro', 'enterprise'):
        return jsonify({'error': 'plan must be free, trial, pro, or enterprise'}), 400

    # Phase 85: Optional onboarding fields
    primary_cloud = str(data.get('primary_cloud', '')).strip().lower() or None
    industry = str(data.get('industry', '')).strip() or None
    compliance_framework = str(data.get('compliance_framework', '')).strip() or None
    if primary_cloud and primary_cloud not in ('azure', 'aws', 'gcp'):
        return jsonify({'error': 'primary_cloud must be azure, aws, or gcp'}), 400

    db = _db()
    try:
        existing = db.get_tenant_by_slug(slug)
        if existing:
            return jsonify({'error': f'Tenant slug "{slug}" already exists'}), 409

        tenant = db.create_tenant(name, slug, plan,
                                  primary_cloud=primary_cloud,
                                  industry=industry,
                                  compliance_framework=compliance_framework)

        # Set subscription term + auto-compute dates if provided
        term = int(data.get('subscription_term', 0))
        if term in (1, 3, 5):
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            db.update_tenant(tenant['id'],
                             subscription_term=term,
                             license_activated_at=now.isoformat(),
                             license_expires_at=now.replace(year=now.year + term).isoformat())
            tenant = db.get_tenant_by_id(tenant['id'])

        try:
            _log(db,'tenant_created',
                f'Tenant "{name}" created (slug: {slug}, plan: {plan})',
                {'tenant_id': tenant['id'], 'slug': slug, 'plan': plan})
        except Exception:
            pass

        # Phase 84: Optional root user creation during tenant onboarding
        root_username = str(data.get('root_username', '')).strip().lower()
        root_email = str(data.get('root_email', '')).strip().lower()
        root_password = str(data.get('root_password', ''))
        root_user = None

        if root_username and root_password:
            if len(root_username) < 3:
                return jsonify({'error': 'root_username must be at least 3 characters'}), 400
            if len(root_password) < 8:
                return jsonify({'error': 'root_password must be at least 8 characters'}), 400

            existing_user = db.get_user_by_username(root_username)
            if existing_user:
                return jsonify({'error': f'Username "{root_username}" already exists'}), 409

            hashed = bcrypt.hashpw(root_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            current_user = getattr(g, 'current_user', None)
            created_by = current_user['id'] if current_user else None

            root_user = db.create_user(
                root_username, hashed, root_username,
                role='admin', created_by=created_by,
                tenant_id=tenant['id'], is_root_user=True,
                force_password_change=True,
                email=root_email or None
            )

            # Mark tenant as provisioned + set onboarding stage + auto-enable primary cloud
            settings = tenant.get('settings') or {}
            if isinstance(settings, str):
                try:
                    settings = json.loads(settings)
                except Exception:
                    settings = {}
            settings['provisioned'] = True
            settings['provisioned_at'] = datetime.utcnow().isoformat()
            settings['onboarding_stage'] = 'password_change'
            # Auto-enable primary cloud in cloud_providers
            if primary_cloud:
                cp = settings.get('cloud_providers', {})
                cp[primary_cloud] = {'enabled': True, 'plan': plan if plan in ('pro', 'enterprise') else 'pro'}
                settings['cloud_providers'] = cp
            db.update_tenant(tenant['id'], settings=settings)
            tenant = db.get_tenant_by_id(tenant['id'])

            try:
                admin_id = current_user['id'] if current_user else None
                db.log_admin_audit(admin_id, 'tenant_root_user_created',
                                   target_user_id=root_user['id'], target_tenant_id=tenant['id'],
                                   details={'root_username': root_username},
                                   ip_address=request.remote_addr)
            except Exception:
                pass

        result = {'tenant': tenant, 'message': 'Tenant created'}
        if root_user:
            result['root_user'] = {k: v for k, v in root_user.items() if k != 'password_hash'}
        return jsonify(result), 201
    finally:
        db.close()


def update_tenant_handler(tenant_id):
    """PUT /api/tenants/<id> — update tenant details (superadmin only)."""
    data = request.get_json(silent=True) or {}
    db = _db()
    try:
        existing = db.get_tenant_by_id(tenant_id)
        if not existing:
            return jsonify({'error': 'Tenant not found'}), 404

        updates = {}
        if 'name' in data:
            name = str(data['name']).strip()
            if not name or len(name) > 255:
                return jsonify({'error': 'name must be 1-255 characters'}), 400
            updates['name'] = name
        if 'plan' in data:
            plan = str(data['plan']).strip().lower()
            if plan not in ('free', 'trial', 'pro', 'enterprise'):
                return jsonify({'error': 'plan must be free, trial, pro, or enterprise'}), 400
            updates['plan'] = plan
        if 'enabled' in data:
            updates['enabled'] = bool(data['enabled'])
        if 'settings' in data and isinstance(data['settings'], dict):
            updates['settings'] = data['settings']
        if 'license_activated_at' in data:
            updates['license_activated_at'] = data['license_activated_at']
        if 'license_expires_at' in data:
            updates['license_expires_at'] = data['license_expires_at']
        if 'subscription_term' in data:
            term = int(data['subscription_term'])
            if term not in (0, 1, 3, 5):
                return jsonify({'error': 'subscription_term must be 0 (monthly), 1, 3, or 5 years'}), 400
            updates['subscription_term'] = term
            # Auto-compute expiry from activation date + term
            if term > 0:
                activated = data.get('license_activated_at') or existing.get('license_activated_at')
                if activated:
                    from datetime import datetime, timezone
                    act_dt = datetime.fromisoformat(str(activated).replace('Z', '+00:00')) if isinstance(activated, str) else activated
                    updates['license_expires_at'] = act_dt.replace(year=act_dt.year + term).isoformat()
            elif term == 0:
                # Monthly — no fixed expiry
                updates['license_expires_at'] = None
        # Phase 85: Additional tenant metadata fields
        if 'primary_cloud' in data:
            pc = str(data['primary_cloud']).strip().lower()
            if pc and pc not in ('azure', 'aws', 'gcp'):
                return jsonify({'error': 'primary_cloud must be azure, aws, or gcp'}), 400
            updates['primary_cloud'] = pc or None
        if 'industry' in data:
            updates['industry'] = str(data['industry']).strip() or None
        if 'compliance_framework' in data:
            updates['compliance_framework'] = str(data['compliance_framework']).strip() or None
        if 'status' in data:
            st = str(data['status']).strip().lower()
            if st not in ('active', 'trial', 'suspended', 'cancelled'):
                return jsonify({'error': 'status must be active, trial, suspended, or cancelled'}), 400
            updates['status'] = st

        if not updates:
            return jsonify({'tenant': existing, 'message': 'No changes'})

        tenant = db.update_tenant(tenant_id, **updates)
        try:
            _log(db,'tenant_updated',
                f'Tenant "{existing["name"]}" updated: {", ".join(updates.keys())}',
                {'tenant_id': tenant_id, 'updates': list(updates.keys())})
        except Exception:
            pass
        return jsonify({'tenant': tenant, 'message': 'Tenant updated'})
    finally:
        db.close()


def delete_tenant_handler(tenant_id):
    """DELETE /api/tenants/<id> — delete a tenant (superadmin only)."""
    db = _db()
    try:
        existing = db.get_tenant_by_id(tenant_id)
        if not existing:
            return jsonify({'error': 'Tenant not found'}), 404
        if existing.get('slug') == 'default':
            return jsonify({'error': 'Cannot delete the default tenant'}), 400

        try:
            db.delete_tenant(tenant_id)
        except Exception as e:
            logger.error(f"Failed to delete tenant {tenant_id}: {e}")
            return jsonify({'error': f'Failed to delete tenant: {str(e)}'}), 500

        try:
            _log(db,'tenant_deleted',
                f'Tenant "{existing["name"]}" deleted',
                {'tenant_id': tenant_id, 'slug': existing.get('slug')})
        except Exception:
            pass
        return jsonify({'message': f'Tenant "{existing["name"]}" deleted'})
    finally:
        db.close()


def get_current_tenant_handler():
    """GET /api/tenant — get current user's tenant info."""
    tid = _tenant_id()
    if not tid:
        return jsonify({'tenant': None})
    db = _db()
    try:
        tenant = db.get_tenant_by_id(tid)
        return jsonify({'tenant': tenant})
    finally:
        db.close()


def get_tenant_config():
    """GET /api/tenant/config — cloud provider & add-on config for sidebar."""
    tid = _tenant_id()
    if not tid:
        # Superadmin without tenant context — default Azure-only
        return jsonify({
            'cloud_providers': {
                'azure': {'enabled': True, 'plan': 'pro'},
                'aws': {'enabled': False, 'plan': None},
                'gcp': {'enabled': False, 'plan': None},
            },
            'addons': {
                'extended_retention': False,
            },
        })
    db = _db()
    try:
        cfg = db.get_tenant_config(tid)
        if not cfg:
            return jsonify({'error': 'Tenant not found'}), 404
        return jsonify(cfg)
    finally:
        db.close()


# ── Phase 85: Tenant Branding & Onboarding Stage ─────────────────


def get_tenant_branding():
    """GET /api/auth/tenant-branding?slug=<slug> — public branding info for login page."""
    slug = request.args.get('slug', '').strip().lower()
    if not slug:
        return jsonify({'error': 'slug parameter required'}), 400
    db = _db()
    try:
        tenant = db.get_tenant_by_slug(slug)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        settings = tenant.get('settings') or {}
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        return jsonify({
            'company_name': tenant.get('name'),
            'slug': tenant.get('slug'),
            'logo_url': tenant.get('logo_url') or settings.get('logo_url'),
        })
    finally:
        db.close()


def get_tenant_stage():
    """GET /api/tenant/stage — onboarding stage for current tenant."""
    tid = _tenant_id()
    if not tid:
        return jsonify({'stage': 'active', 'primary_cloud': None, 'tenant_name': None})
    db = _db()
    try:
        tenant = db.get_tenant_by_id(tid)
        if not tenant:
            return jsonify({'stage': 'active', 'primary_cloud': None, 'tenant_name': None})
        settings = tenant.get('settings') or {}
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        stage = settings.get('onboarding_stage', 'active')
        return jsonify({
            'stage': stage,
            'primary_cloud': tenant.get('primary_cloud'),
            'tenant_name': tenant.get('name'),
        })
    finally:
        db.close()


def update_tenant_stage():
    """POST /api/tenant/stage — update onboarding stage (admin only)."""
    data = request.get_json(silent=True) or {}
    stage = str(data.get('stage', '')).strip().lower()
    if stage not in ('password_change', 'locked', 'authenticating', 'active'):
        return jsonify({'error': 'stage must be password_change, locked, authenticating, or active'}), 400

    tid = _tenant_id()
    if not tid:
        return jsonify({'error': 'No tenant context'}), 400

    db = _db()
    try:
        tenant = db.get_tenant_by_id(tid)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        settings = tenant.get('settings') or {}
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        settings['onboarding_stage'] = stage
        db.update_tenant(tid, settings=settings)
        try:
            _log(db, 'tenant_stage_updated',
                 f'Onboarding stage changed to "{stage}"',
                 {'tenant_id': tid, 'stage': stage})
        except Exception:
            pass
        return jsonify({'stage': stage, 'message': 'Stage updated'})
    finally:
        db.close()


# ── Phase 47: Cross-Tenant Analytics ─────────────────────────────

def get_cross_tenant_analytics():
    """GET /api/analytics/tenants — per-tenant metrics + global aggregates (superadmin only)."""
    db = _db()
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("""
            WITH latest_runs AS (
                SELECT DISTINCT ON (tenant_id)
                    id, tenant_id, completed_at, total_identities,
                    critical_count, high_count, medium_count, low_count
                FROM discovery_runs
                WHERE status = 'completed'
                ORDER BY tenant_id, id DESC
            ),
            prev_runs AS (
                SELECT DISTINCT ON (tenant_id)
                    tenant_id, total_identities AS prev_total,
                    critical_count AS prev_critical, high_count AS prev_high
                FROM discovery_runs
                WHERE status = 'completed' AND id NOT IN (SELECT id FROM latest_runs)
                ORDER BY tenant_id, id DESC
            ),
            run_counts AS (
                SELECT tenant_id, COUNT(*) AS total_runs
                FROM discovery_runs GROUP BY tenant_id
            ),
            user_counts AS (
                SELECT tenant_id, COUNT(*) AS user_count
                FROM users WHERE tenant_id IS NOT NULL GROUP BY tenant_id
            )
            SELECT
                t.id, t.name, t.slug, t.plan, t.enabled,
                t.settings, t.license_activated_at, t.license_expires_at, t.subscription_term,
                COALESCE(uc.user_count, 0) AS user_count,
                COALESCE(rc.total_runs, 0) AS total_runs,
                lr.completed_at AS last_discovery,
                COALESCE(lr.total_identities, 0) AS total_identities,
                COALESCE(lr.critical_count, 0) AS critical_count,
                COALESCE(lr.high_count, 0) AS high_count,
                COALESCE(lr.medium_count, 0) AS medium_count,
                COALESCE(lr.low_count, 0) AS low_count,
                pr.prev_total, pr.prev_critical, pr.prev_high
            FROM tenants t
            LEFT JOIN latest_runs lr ON lr.tenant_id = t.id
            LEFT JOIN prev_runs pr ON pr.tenant_id = t.id
            LEFT JOIN run_counts rc ON rc.tenant_id = t.id
            LEFT JOIN user_counts uc ON uc.tenant_id = t.id
            ORDER BY t.id
        """)
        rows = [dict(r) for r in cursor.fetchall()]

        # Compute risk score per tenant + serialize timestamps + extract clouds
        for row in rows:
            c = row.get('critical_count') or 0
            h = row.get('high_count') or 0
            m = row.get('medium_count') or 0
            row['risk_score'] = max(0, min(100, 100 - (c * 15 + h * 5 + m * 1)))
            if row.get('last_discovery'):
                row['last_discovery'] = row['last_discovery'].isoformat()
            for ts in ('license_activated_at', 'license_expires_at'):
                if row.get(ts):
                    row[ts] = row[ts].isoformat()
            # Extract enabled clouds from tenant settings JSON
            settings = row.pop('settings', None) or {}
            cp = settings.get('cloud_providers', {})
            row['clouds_enabled'] = [k for k in ('azure', 'aws', 'gcp') if cp.get(k, {}).get('enabled')]

        # Global aggregates
        total_tenants = len(rows)
        active_tenants = sum(1 for r in rows if r.get('total_runs', 0) > 0)
        total_identities = sum(r.get('total_identities', 0) for r in rows)
        total_critical = sum(r.get('critical_count', 0) for r in rows)
        total_high = sum(r.get('high_count', 0) for r in rows)
        scores = [r['risk_score'] for r in rows if r.get('total_runs', 0) > 0]
        avg_risk_score = round(sum(scores) / len(scores)) if scores else 0

        return jsonify({
            'tenants': rows,
            'global': {
                'total_tenants': total_tenants,
                'active_tenants': active_tenants,
                'total_identities': total_identities,
                'total_critical': total_critical,
                'total_high': total_high,
                'avg_risk_score': avg_risk_score,
            },
        })
    finally:
        cursor.close()
        db.close()


def get_cross_tenant_trends():
    """GET /api/analytics/tenants/trends — recent runs per tenant for timeline (superadmin only)."""
    db = _db()
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("""
            SELECT dr.tenant_id, t.name AS tenant_name,
                   dr.id, dr.completed_at, dr.total_identities,
                   dr.critical_count, dr.high_count
            FROM discovery_runs dr
            JOIN tenants t ON t.id = dr.tenant_id
            WHERE dr.status = 'completed'
            ORDER BY dr.tenant_id, dr.completed_at DESC
            LIMIT 100
        """)
        rows = [dict(r) for r in cursor.fetchall()]

        # Group by tenant
        trends: dict = {}
        for row in rows:
            tid = str(row['tenant_id'])
            if tid not in trends:
                trends[tid] = {'tenant_name': row['tenant_name'], 'runs': []}
            if row.get('completed_at'):
                row['completed_at'] = row['completed_at'].isoformat()
            trends[tid]['runs'].append({
                'id': row['id'],
                'completed_at': row['completed_at'],
                'total_identities': row['total_identities'] or 0,
                'critical_count': row['critical_count'] or 0,
                'high_count': row['high_count'] or 0,
            })

        return jsonify({'trends': trends})
    finally:
        cursor.close()
        db.close()


def get_login_sessions():
    """GET /api/analytics/login-sessions — paired login/logout events for governance.
    ?portal=admin|client — filter by portal context (default: all)
    """
    db = _db()
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 200)
        portal_filter = request.args.get('portal', '')  # 'admin', 'client', or '' (all)

        # Determine which action types to include based on portal filter
        if portal_filter == 'admin':
            login_types = ('admin_login',)
            logout_types = ('admin_logout',)
        elif portal_filter == 'client':
            login_types = ('auth_login',)
            logout_types = ('auth_logout',)
        else:
            login_types = ('auth_login', 'admin_login')
            logout_types = ('auth_logout', 'admin_logout')

        all_types = login_types + logout_types

        # Fetch recent login + logout events with user details
        cursor.execute("""
            SELECT a.id, a.action_type, a.description, a.metadata, a.created_at,
                   a.user_id, a.tenant_id,
                   u.username, u.display_name, u.role,
                   t.name AS tenant_name
            FROM activity_log a
            LEFT JOIN users u ON u.id = a.user_id
            LEFT JOIN tenants t ON t.id = a.tenant_id
            WHERE a.action_type = ANY(%s)
            ORDER BY a.created_at DESC
            LIMIT %s
        """, [list(all_types), limit * 3])  # fetch extra to pair logouts with logins
        rows = [dict(r) for r in cursor.fetchall()]

        # Serialize timestamps
        for row in rows:
            if row.get('created_at'):
                row['created_at'] = row['created_at'].isoformat()

        # Build sessions: for each login, find the next logout by the same user
        logins = [r for r in rows if r['action_type'] in login_types]
        logouts = [r for r in rows if r['action_type'] in logout_types]

        # Index logouts by user_id (list, most recent first — already sorted desc)
        logout_map: dict = {}
        for lo in logouts:
            uid = lo.get('user_id')
            if uid not in logout_map:
                logout_map[uid] = []
            logout_map[uid].append(lo)

        sessions = []
        for login in logins[:limit]:
            uid = login.get('user_id')
            meta = login.get('metadata') or {}
            login_time = login['created_at']

            # Find matching logout: first logout by same user AFTER this login
            logout_time = None
            duration_min = None
            if uid in logout_map:
                for lo in reversed(logout_map[uid]):  # oldest first
                    if lo['created_at'] and login_time and lo['created_at'] > login_time:
                        logout_time = lo['created_at']
                        # Calculate duration
                        from datetime import datetime as _dt
                        try:
                            lt = _dt.fromisoformat(login_time.replace('Z', '+00:00'))
                            lot = _dt.fromisoformat(logout_time.replace('Z', '+00:00'))
                            duration_min = round((lot - lt).total_seconds() / 60, 1)
                        except Exception:
                            pass
                        # Remove this logout so it isn't reused
                        logout_map[uid].remove(lo)
                        break

            session_portal = 'admin' if login['action_type'] == 'admin_login' else 'client'
            sessions.append({
                'user_id': uid,
                'username': login.get('username') or '',
                'display_name': login.get('display_name') or login.get('username') or '',
                'role': login.get('role') or meta.get('role', ''),
                'tenant_name': login.get('tenant_name') or meta.get('tenant_name', ''),
                'tenant_id': login.get('tenant_id'),
                'login_at': login_time,
                'logout_at': logout_time,
                'duration_minutes': duration_min,
                'ip_address': meta.get('ip', ''),
                'user_agent': meta.get('user_agent', ''),
                'status': 'ended' if logout_time else 'active',
                'portal': session_portal,
            })

        return jsonify({
            'sessions': sessions,
            'count': len(sessions),
        })
    finally:
        cursor.close()
        db.close()


# ── Phase 48: Onboarding Wizard ─────────────────────────────────

def get_onboarding_status():
    """Check if the current tenant has completed onboarding."""
    db = _db()
    try:
        tid = _tenant_id()
        settings = db.get_settings(tenant_id=tid)
        completed = settings.get('onboarding_completed', 'false') == 'true'
        azure_configured = all([
            settings.get('azure_tenant_id'),
            settings.get('azure_client_id'),
            settings.get('azure_client_secret'),
        ]) or all([
            os.getenv('AZURE_TENANT_ID'),
            os.getenv('AZURE_CLIENT_ID'),
            os.getenv('AZURE_CLIENT_SECRET'),
        ])
        return jsonify({
            'onboarding_completed': completed,
            'azure_configured': azure_configured,
            'has_settings': bool(settings),
        })
    finally:
        db.close()


def test_azure_connection():
    """Test Azure credentials without saving. Returns subscription list on success."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Expected JSON body'}), 400

    azure_tenant_id = (data.get('azure_tenant_id') or '').strip()
    azure_client_id = (data.get('azure_client_id') or '').strip()
    azure_client_secret = (data.get('azure_client_secret') or '').strip()

    if not all([azure_tenant_id, azure_client_id, azure_client_secret]):
        return jsonify({'error': 'All three Azure credential fields are required'}), 400

    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import SubscriptionClient

        credential = ClientSecretCredential(
            tenant_id=azure_tenant_id,
            client_id=azure_client_id,
            client_secret=azure_client_secret,
        )
        sub_client = SubscriptionClient(credential)
        subs = []
        for sub in sub_client.subscriptions.list():
            if sub.state and sub.state.lower() in ('enabled', 'warned'):
                subs.append({
                    'id': sub.subscription_id,
                    'name': sub.display_name or sub.subscription_id,
                })
        return jsonify({
            'status': 'success',
            'subscriptions': subs,
            'message': f'Connected successfully. Found {len(subs)} subscription(s).',
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'message': 'Failed to connect. Check your credentials.',
        }), 400


# ── Phase 49: Identity Risk Simulation ──────────────────────────

def _compute_risk_score(azure_roles, entra_roles, permissions, app_roles, credentials,
                        identity_category=None):
    """Pure-function risk scoring — no DB access. Returns (score, level, reasons)."""
    risk_score = 0
    risk_reasons = []

    # 1. Entra ID directory roles
    for er in entra_roles:
        rn = (er.get('role_name') or '').lower()
        if 'global administrator' in rn:
            risk_score += 100
            risk_reasons.append('Global Administrator: Full tenant control - violates SOC2 least privilege, HIPAA §164.312, PCI-DSS 7')
        elif 'privileged role administrator' in rn:
            risk_score += 90
            risk_reasons.append('Privileged Role Admin: Can assign any role - privilege escalation risk, SOC2 separation of duties')
        elif 'application administrator' in rn or 'cloud application administrator' in rn:
            risk_score += 80
            risk_reasons.append(f"{er.get('role_name','App Admin')}: Can manage all apps/SPNs - HIPAA BAA concerns")
        elif 'user administrator' in rn:
            risk_score += 60
            risk_reasons.append('User Administrator: Can reset passwords, create users - SOC2 access control, PCI-DSS 8.1')
        elif 'security administrator' in rn:
            risk_score += 60
            risk_reasons.append('Security Administrator: Can modify security policies - SOC2 change management')
        elif 'exchange administrator' in rn:
            risk_score += 50
            risk_reasons.append('Exchange Administrator: Full mailbox access - HIPAA ePHI exposure')
        elif 'sharepoint administrator' in rn:
            risk_score += 50
            risk_reasons.append('SharePoint Administrator: Full document access - GDPR Art. 32')

    # 2. Azure RBAC roles
    for role in azure_roles:
        rn = (role.get('role_name') or '').lower()
        st = role.get('scope_type', '')
        if 'owner' in rn:
            if st == 'subscription':
                risk_score += 100
                risk_reasons.append('Owner on Subscription: Full control including IAM - SOC2, PCI-DSS 7.1, HIPAA §164.312(a)(1)')
            elif st == 'resource_group':
                risk_score += 60
                risk_reasons.append('Owner on Resource Group: Can delete all resources, modify access - SOC2 availability')
            else:
                risk_score += 30
                risk_reasons.append(f"Owner role on {st}")
        elif 'contributor' in rn:
            if st == 'subscription':
                risk_score += 80
                risk_reasons.append('Contributor on Subscription: Can create/modify/delete all resources - SOC2, PCI-DSS 7.2')
            elif st == 'resource_group':
                risk_score += 40
                risk_reasons.append('Contributor on Resource Group: Broad resource modification - SOC2 least privilege')
        elif 'user access administrator' in rn:
            risk_score += 70
            risk_reasons.append('User Access Administrator: Can grant any role - privilege escalation, SOC2/PCI-DSS 7.1')
        elif 'key vault' in rn and ('administrator' in rn or 'officer' in rn):
            risk_score += 50
            risk_reasons.append('Key Vault Admin/Officer: Access to secrets/keys - HIPAA §164.312(a)(2)(iv), PCI-DSS 3.5')

    # 3. Graph API permissions
    write_perms = [p for p in permissions
                   if '.write' in (p.get('permission_name') or '').lower()
                   or '.readwrite' in (p.get('permission_name') or '').lower()]
    read_all_perms = [p for p in permissions
                      if ('.read.all' in (p.get('permission_name') or '').lower()
                          or 'readall' in (p.get('permission_name') or '').lower())
                      and p not in write_perms]

    if write_perms:
        risk_score += 60
        risk_reasons.append(f"Graph API Write Access: {len(write_perms)} write permission(s) - SOC2 change management, HIPAA §164.312(c)")
    if read_all_perms and not write_perms:
        risk_score += 40
        risk_reasons.append(f"Graph API Read-All: {len(read_all_perms)} permission(s) - PII/PHI exposure, GDPR Art. 32")

    # 4. Orphaned permissions
    has_roles = len(azure_roles) > 0 or len(entra_roles) > 0
    has_permissions = len(permissions) > 0
    if not has_roles and has_permissions:
        risk_score += 30
        risk_reasons.append('API permissions without role justification (orphaned)')

    # 5. App roles
    admin_app_roles = [ar for ar in app_roles
                       if any(kw in (ar.get('app_role_value') or ar.get('resource_display_name') or '').lower()
                              for kw in ['admin', 'owner', 'full', 'write', 'manage'])]
    if admin_app_roles:
        risk_score += 50
        risk_reasons.append(f"Has {len(admin_app_roles)} administrative app role(s)")
    elif app_roles:
        risk_score += 20
        risk_reasons.append(f"Has {len(app_roles)} app role assignment(s)")

    # 6. Credentials
    has_expired = False
    has_expiring_soon = False
    for cred in credentials:
        end_date = cred.get('end_datetime')
        if end_date:
            from datetime import datetime, timezone
            try:
                if isinstance(end_date, str):
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                else:
                    end_dt = end_date
                now = datetime.now(timezone.utc)
                if end_dt < now:
                    has_expired = True
                elif (end_dt - now).days < 30:
                    has_expiring_soon = True
            except Exception:
                pass
    if has_expired:
        risk_score += 35
        risk_reasons.append('Has expired credentials')
    elif has_expiring_soon:
        risk_score += 15
        risk_reasons.append('Has credentials expiring within 30 days')

    # 7. Orphaned identity (no roles, no perms, no app roles — non-user)
    if not has_roles and not has_permissions and not app_roles:
        if identity_category and identity_category not in ('human_user', 'guest'):
            risk_score += 25
            risk_reasons.append('No role assignments (potentially orphaned identity)')

    # Convert to level
    if risk_score >= 120:
        risk_level = 'critical'
    elif risk_score >= 70:
        risk_level = 'high'
    elif risk_score >= 40:
        risk_level = 'medium'
    elif risk_score > 0:
        risk_level = 'low'
    else:
        risk_level = 'info'
        risk_reasons = ['No elevated privileges detected']

    return risk_score, risk_level, risk_reasons


def simulate_risk(identity_id):
    """POST /api/identities/<id>/simulate — what-if risk simulation."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}
        remove_roles = set(r.lower() for r in (data.get('remove_roles') or []))
        add_roles = data.get('add_roles') or []
        remove_perms = set(p.lower() for p in (data.get('remove_permissions') or []))
        add_perms = data.get('add_permissions') or []

        # Fetch identity
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, identity_id, identity_category, risk_score, risk_level, risk_reasons,
                   credential_status
            FROM identities WHERE identity_id = %s
            ORDER BY discovery_run_id DESC LIMIT 1
        """, (identity_id,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            return jsonify({'error': 'Identity not found'}), 404

        db_id = row['id']
        current_score = row['risk_score'] or 0
        current_level = row['risk_level'] or 'info'
        current_reasons = row['risk_reasons'] if isinstance(row['risk_reasons'], list) else []
        identity_category = row['identity_category']

        # Fetch current data
        roles = db.get_identity_roles_enriched(db_id)
        azure_roles = [r for r in roles if r.get('role_type') == 'azure']
        entra_roles_list = [r for r in roles if r.get('role_type') == 'entra']
        perms = db.get_graph_permissions(db_id)
        app_roles = db.get_app_roles(db_id)

        # Fetch credentials
        cursor.execute("""
            SELECT credential_type, end_datetime FROM credentials WHERE identity_db_id = %s
        """, (db_id,))
        creds = [dict(c) for c in cursor.fetchall()]
        cursor.close()

        # Apply modifications: remove
        sim_azure = [r for r in azure_roles if r.get('role_name', '').lower() not in remove_roles]
        sim_entra = [r for r in entra_roles_list if r.get('role_name', '').lower() not in remove_roles]
        sim_perms = [p for p in perms if (p.get('permission_name') or '').lower() not in remove_perms]
        sim_app_roles = list(app_roles)  # app roles not modified in simulation

        # Apply modifications: add
        for ar in add_roles:
            entry = {'role_name': ar.get('role_name', ''), 'scope_type': ar.get('scope_type', 'subscription')}
            if ar.get('role_type') == 'entra':
                sim_entra.append(entry)
            else:
                sim_azure.append(entry)

        for ap in add_perms:
            sim_perms.append({
                'permission_name': ap.get('permission_name', ''),
                'risk_level': ap.get('risk_level', 'medium'),
            })

        # Compute simulated risk
        sim_score, sim_level, sim_reasons = _compute_risk_score(
            sim_azure, sim_entra, sim_perms, sim_app_roles, creds, identity_category
        )

        delta = sim_score - current_score
        level_change = f"{current_level} \u2192 {sim_level}" if current_level != sim_level else current_level

        # Determine removed and added reasons
        current_set = set(current_reasons)
        sim_set = set(sim_reasons)
        removed_reasons = sorted(current_set - sim_set)
        added_reasons = sorted(sim_set - current_set)

        return jsonify({
            'current': {
                'risk_score': current_score,
                'risk_level': current_level,
                'risk_reasons': current_reasons,
            },
            'simulated': {
                'risk_score': sim_score,
                'risk_level': sim_level,
                'risk_reasons': sim_reasons,
            },
            'delta': delta,
            'level_change': level_change,
            'removed_reasons': removed_reasons,
            'added_reasons': added_reasons,
        })
    finally:
        db.close()


# ─── Phase 52: Azure Resource Discovery ──────────────────────────

def get_resources():
    """GET /api/resources — list storage accounts + key vaults with filters."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        resource_type = request.args.get('resource_type', '')
        risk_level = request.args.get('risk_level', '')
        subscription = request.args.get('subscription', '')
        search = request.args.get('search', '')

        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'resources': [], 'count': 0, 'total': 0})

        # Build UNION ALL of both resource tables
        parts = []
        params = []

        if resource_type != 'key_vault':
            parts.append("""
                SELECT id, resource_id, name, 'storage_account' AS resource_type,
                       location, resource_group, subscription_id, subscription_name,
                       risk_level, risk_score, risk_reasons,
                       jsonb_build_object(
                           'public_blob_access', public_blob_access,
                           'https_only', https_only,
                           'minimum_tls_version', minimum_tls_version,
                           'default_network_action', default_network_action,
                           'customer_managed_keys', customer_managed_keys,
                           'key_rotation_stale', key_rotation_stale,
                           'shared_key_access', shared_key_access,
                           'diagnostic_logging_enabled', diagnostic_logging_enabled,
                           'sas_policy_enabled', sas_policy_enabled
                       ) AS key_config,
                       tags, created_at
                FROM azure_storage_accounts
                WHERE discovery_run_id = %s
            """)
            params.append(run_id)
            if tenant_id:
                parts[-1] += " AND (tenant_id = %s OR tenant_id IS NULL)"
                params.append(tenant_id)

        if resource_type != 'storage_account':
            parts.append("""
                SELECT id, resource_id, name, 'key_vault' AS resource_type,
                       location, resource_group, subscription_id, subscription_name,
                       risk_level, risk_score, risk_reasons,
                       jsonb_build_object(
                           'soft_delete_enabled', soft_delete_enabled,
                           'purge_protection', purge_protection,
                           'enable_rbac_authorization', enable_rbac_authorization,
                           'public_network_access', public_network_access,
                           'secrets_expired', secrets_expired,
                           'keys_expired', keys_expired,
                           'certs_expired', certs_expired
                       ) AS key_config,
                       tags, created_at
                FROM azure_key_vaults
                WHERE discovery_run_id = %s
            """)
            params.append(run_id)
            if tenant_id:
                parts[-1] += " AND (tenant_id = %s OR tenant_id IS NULL)"
                params.append(tenant_id)

        if not parts:
            cursor.close()
            return jsonify({'resources': [], 'count': 0, 'total': 0})

        union_sql = " UNION ALL ".join(parts)

        # Wrap with filters
        where_clauses = []
        filter_params = []
        if risk_level:
            where_clauses.append("r.risk_level = %s")
            filter_params.append(risk_level)
        if subscription:
            where_clauses.append("r.subscription_id = %s")
            filter_params.append(subscription)
        if search:
            where_clauses.append("(r.name ILIKE %s OR r.resource_group ILIKE %s)")
            filter_params.extend([f'%{search}%', f'%{search}%'])

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Count query
        count_sql = f"SELECT COUNT(*) FROM ({union_sql}) r {where_sql}"
        cursor.execute(count_sql, params + filter_params)
        total = cursor.fetchone()['count']

        # Data query
        data_sql = f"""
            SELECT r.* FROM ({union_sql}) r {where_sql}
            ORDER BY r.risk_score DESC, r.name ASC
            LIMIT %s OFFSET %s
        """
        cursor.execute(data_sql, params + filter_params + [limit, offset])
        rows = cursor.fetchall()
        cursor.close()

        resources = []
        for row in rows:
            r = dict(row)
            r['risk_reasons'] = _parse_risk_reasons(r.get('risk_reasons'))
            if isinstance(r.get('tags'), str):
                try:
                    r['tags'] = json.loads(r['tags'])
                except Exception:
                    r['tags'] = {}
            if isinstance(r.get('key_config'), str):
                try:
                    r['key_config'] = json.loads(r['key_config'])
                except Exception:
                    r['key_config'] = {}
            resources.append(r)

        return jsonify({
            'resources': resources,
            'count': len(resources),
            'total': total,
        })
    finally:
        db.close()


def get_resource_stats():
    """GET /api/resources/stats — summary counts for dashboard. Supports ?resource_type= filter."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        resource_type = request.args.get('resource_type', '')
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({
                'total': 0, 'storage_accounts': 0, 'key_vaults': 0,
                'by_risk': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'at_risk': 0,
            })

        tenant_filter = ""
        params = [run_id]
        if tenant_id:
            tenant_filter = " AND (tenant_id = %s OR tenant_id IS NULL)"
            params.append(tenant_id)

        include_sa = resource_type != 'key_vault'
        include_kv = resource_type != 'storage_account'

        zero_risk = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        # Storage account counts
        if include_sa:
            cursor.execute(f"""
                SELECT COUNT(*) as total,
                       COUNT(*) FILTER (WHERE risk_level = 'critical') as critical,
                       COUNT(*) FILTER (WHERE risk_level = 'high') as high,
                       COUNT(*) FILTER (WHERE risk_level = 'medium') as medium,
                       COUNT(*) FILTER (WHERE risk_level = 'low') as low,
                       COUNT(*) FILTER (WHERE risk_level = 'info') as info
                FROM azure_storage_accounts
                WHERE discovery_run_id = %s{tenant_filter}
            """, params)
            sa = dict(cursor.fetchone())
        else:
            sa = dict(zero_risk)

        # Key vault counts
        if include_kv:
            cursor.execute(f"""
                SELECT COUNT(*) as total,
                       COUNT(*) FILTER (WHERE risk_level = 'critical') as critical,
                       COUNT(*) FILTER (WHERE risk_level = 'high') as high,
                       COUNT(*) FILTER (WHERE risk_level = 'medium') as medium,
                       COUNT(*) FILTER (WHERE risk_level = 'low') as low,
                       COUNT(*) FILTER (WHERE risk_level = 'info') as info
                FROM azure_key_vaults
                WHERE discovery_run_id = %s{tenant_filter}
            """, params)
            kv = dict(cursor.fetchone())
        else:
            kv = dict(zero_risk)

        # Rotation compliance & audit posture (storage-only stats)
        rotation_data = None
        audit_posture = None
        if include_sa:
            cursor.execute(f"""
                SELECT COUNT(*) as total,
                       COUNT(*) FILTER (WHERE key_rotation_stale = true) as keys_stale,
                       AVG(GREATEST(
                           EXTRACT(EPOCH FROM (NOW() - key1_created_at)) / 86400,
                           EXTRACT(EPOCH FROM (NOW() - key2_created_at)) / 86400
                       ))::int as avg_key_age_days,
                       COUNT(*) FILTER (WHERE shared_key_access = false) as aad_only,
                       COUNT(*) FILTER (WHERE shared_key_access = true AND diagnostic_logging_enabled = true AND sas_policy_enabled = true) as auditable,
                       COUNT(*) FILTER (WHERE shared_key_access = true AND diagnostic_logging_enabled = true AND (sas_policy_enabled IS NULL OR sas_policy_enabled = false)) as partial,
                       COUNT(*) FILTER (WHERE shared_key_access = true AND (diagnostic_logging_enabled IS NULL OR diagnostic_logging_enabled = false)) as unauditable
                FROM azure_storage_accounts
                WHERE discovery_run_id = %s{tenant_filter}
            """, params)
            rotation_row = dict(cursor.fetchone())
            rotation_data = {
                'total_storage': rotation_row['total'],
                'keys_stale': rotation_row['keys_stale'],
                'avg_key_age_days': rotation_row['avg_key_age_days'] or 0,
            }
            audit_posture = {
                'total': rotation_row['total'],
                'aad_only': rotation_row['aad_only'],
                'auditable': rotation_row['auditable'],
                'partial': rotation_row['partial'],
                'unauditable': rotation_row['unauditable'],
            }

        # Key vault expiry stats (vault-only stat)
        expiry_data = None
        if include_kv:
            cursor.execute(f"""
                SELECT COALESCE(SUM(secrets_total), 0) as total_secrets,
                       COALESCE(SUM(secrets_expired), 0) as expired_secrets,
                       COALESCE(SUM(secrets_expiring_soon), 0) as expiring_secrets,
                       COALESCE(SUM(keys_total), 0) as total_keys,
                       COALESCE(SUM(keys_expired), 0) as expired_keys,
                       COALESCE(SUM(keys_expiring_soon), 0) as expiring_keys,
                       COALESCE(SUM(certs_total), 0) as total_certs,
                       COALESCE(SUM(certs_expired), 0) as expired_certs,
                       COALESCE(SUM(certs_expiring_soon), 0) as expiring_certs
                FROM azure_key_vaults
                WHERE discovery_run_id = %s{tenant_filter}
            """, params)
            expiry_row = dict(cursor.fetchone())
            expiry_data = {
                'secrets': {'total': expiry_row['total_secrets'], 'expired': expiry_row['expired_secrets'], 'expiring_soon': expiry_row['expiring_secrets']},
                'keys': {'total': expiry_row['total_keys'], 'expired': expiry_row['expired_keys'], 'expiring_soon': expiry_row['expiring_keys']},
                'certs': {'total': expiry_row['total_certs'], 'expired': expiry_row['expired_certs'], 'expiring_soon': expiry_row['expiring_certs']},
            }

        cursor.close()

        total = sa['total'] + kv['total']
        by_risk = {
            'critical': sa['critical'] + kv['critical'],
            'high': sa['high'] + kv['high'],
            'medium': sa['medium'] + kv['medium'],
            'low': sa['low'] + kv['low'],
            'info': sa['info'] + kv['info'],
        }

        result = {
            'total': total,
            'storage_accounts': sa['total'],
            'key_vaults': kv['total'],
            'by_risk': by_risk,
            'at_risk': by_risk['critical'] + by_risk['high'],
        }
        if rotation_data is not None:
            result['rotation_compliance'] = rotation_data
        if audit_posture is not None:
            result['audit_posture'] = audit_posture
        if expiry_data is not None:
            result['expiry_summary'] = expiry_data

        return jsonify(result)
    finally:
        db.close()


def get_resource_detail(resource_id):
    """GET /api/resources/<path:resource_id> — full detail for one resource."""
    if not resource_id.startswith('/'):
        resource_id = '/' + resource_id
    db = _db()
    try:
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'error': 'No completed discovery run found'}), 404

        tenant_filter = ""
        params = [run_id, resource_id]
        if tenant_id:
            tenant_filter = " AND (tenant_id = %s OR tenant_id IS NULL)"
            params.append(tenant_id)

        # Try storage account first
        cursor.execute(f"""
            SELECT *, 'storage_account' AS resource_type
            FROM azure_storage_accounts
            WHERE discovery_run_id = %s AND resource_id = %s{tenant_filter}
        """, params)
        row = cursor.fetchone()

        if not row:
            # Try key vault
            cursor.execute(f"""
                SELECT *, 'key_vault' AS resource_type
                FROM azure_key_vaults
                WHERE discovery_run_id = %s AND resource_id = %s{tenant_filter}
            """, params)
            row = cursor.fetchone()

        cursor.close()
        if not row:
            return jsonify({'error': 'Resource not found'}), 404

        resource = dict(row)
        resource['risk_reasons'] = _parse_risk_reasons(resource.get('risk_reasons'))
        # Parse JSONB fields that may come as strings
        for field in ['tags', 'network_rules', 'encryption_details', 'access_policies',
                       'secrets_detail', 'keys_detail', 'certs_detail']:
            if field in resource and isinstance(resource[field], str):
                try:
                    resource[field] = json.loads(resource[field])
                except Exception:
                    pass

        # SAS risk assessment for storage accounts
        if resource.get('resource_type') == 'storage_account':
            factors = []
            recommendations = []
            if resource.get('shared_key_access') is True:
                factors.append('Shared key access is enabled')
                recommendations.append('Disable shared key access and use Azure AD authentication')
            if not resource.get('sas_policy_enabled'):
                factors.append('No SAS expiration policy configured')
                recommendations.append('Configure a SAS expiration policy to limit token lifetimes')
            if resource.get('public_blob_access') is True:
                factors.append('Public blob access is enabled')
                recommendations.append('Disable public blob access unless required')
            if resource.get('key_rotation_stale') is True:
                factors.append('Storage keys have not been rotated in >90 days')
                recommendations.append('Rotate storage account keys every 90 days')
            if resource.get('shared_key_access') is True and not resource.get('diagnostic_logging_enabled'):
                factors.append('No diagnostic logging — shared key/SAS usage is unauditable')
                recommendations.append('Enable diagnostic settings (StorageRead/Write/Delete) to Log Analytics or Event Hub')
            if resource.get('diagnostic_logging_enabled') and resource.get('shared_key_access') is True:
                factors.append('Shared key access enabled with logging — SAS tokens can be generated but usage is tracked')

            level = 'low'
            if len(factors) >= 4:
                level = 'critical'
            elif len(factors) >= 3:
                level = 'high'
            elif len(factors) >= 2:
                level = 'medium'
            elif len(factors) >= 1:
                level = 'medium'

            # Compute auditability status
            has_shared_key = resource.get('shared_key_access') is True
            has_diag = resource.get('diagnostic_logging_enabled') is True
            has_sas_policy = resource.get('sas_policy_enabled') is True
            if not has_shared_key:
                audit_status = 'compliant'
                audit_label = 'Azure AD Only — Fully Auditable'
            elif has_shared_key and has_diag and has_sas_policy:
                audit_status = 'auditable'
                audit_label = 'Shared Key + Logging + SAS Policy — Auditable'
            elif has_shared_key and has_diag:
                audit_status = 'partial'
                audit_label = 'Shared Key + Logging — Partially Auditable (no SAS policy)'
            else:
                audit_status = 'unauditable'
                audit_label = 'Shared Key without Logging — Unauditable'

            resource['sas_risk'] = {
                'level': level,
                'factors': factors,
                'recommendations': recommendations,
                'audit_status': audit_status,
                'audit_label': audit_label,
            }

        return jsonify(resource)
    finally:
        db.close()


def get_resource_access(resource_id):
    """GET /api/resources/<path:resource_id>/access — identities that can access this resource."""
    if not resource_id.startswith('/'):
        resource_id = '/' + resource_id
    db = _db()
    try:
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'resource_id': resource_id, 'rbac_access': [], 'policy_access': [], 'count': 0, 'blast_radius': 0})

        # Note: tenant filtering is already handled via run_id (which belongs to the tenant)
        params = [run_id, resource_id, resource_id]

        # RBAC access
        cursor.execute(f"""
            SELECT i.id, i.display_name, i.identity_category, i.risk_level, i.risk_score,
                   i.object_id,
                   ra.role_name, ra.scope, ra.scope_type
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND (ra.scope = %s OR %s LIKE ra.scope || '/%%')
            ORDER BY i.risk_score DESC, ra.role_name
        """, params)
        rbac_rows = cursor.fetchall()

        OVER_PRIV_ROLES = {'Owner', 'Contributor', 'User Access Administrator'}
        rbac_access = []
        rbac_identity_ids = set()
        for r in rbac_rows:
            entry = dict(r)
            entry['access_type'] = 'rbac'
            entry['over_privileged'] = entry.get('role_name', '') in OVER_PRIV_ROLES and entry.get('scope', '') == resource_id
            # Classify access source by comparing assignment scope to resource_id
            scope = entry.get('scope', '')
            if scope == resource_id:
                entry['access_source'] = 'direct'
                entry['access_source_label'] = 'Direct'
            elif '/resourceGroups/' in scope and '/providers/' not in scope.split('/resourceGroups/')[1]:
                entry['access_source'] = 'resource_group'
                entry['access_source_label'] = 'Inherited (Resource Group)'
            elif scope.startswith('/subscriptions/') and scope.count('/') <= 2:
                entry['access_source'] = 'subscription'
                entry['access_source_label'] = 'Inherited (Subscription)'
            elif '/managementGroups/' in scope:
                entry['access_source'] = 'management_group'
                entry['access_source_label'] = 'Inherited (Management Group)'
            else:
                entry['access_source'] = 'inherited'
                entry['access_source_label'] = 'Inherited'
            rbac_access.append(entry)
            rbac_identity_ids.add(entry['id'])

        # Key Vault access policy cross-reference
        policy_access = []
        kv_params = [run_id, resource_id]
        if tenant_id:
            kv_params.append(tenant_id)
        cursor.execute(f"""
            SELECT access_policies
            FROM azure_key_vaults
            WHERE discovery_run_id = %s AND resource_id = %s
            {'AND (tenant_id = %s OR tenant_id IS NULL)' if tenant_id else ''}
        """, kv_params)
        kv_row = cursor.fetchone()
        policy_identity_ids = set()

        if kv_row and kv_row.get('access_policies'):
            policies = kv_row['access_policies']
            if isinstance(policies, str):
                try:
                    policies = json.loads(policies)
                except Exception:
                    policies = []

            # Collect all object_ids from access policies
            policy_object_ids = [p.get('object_id') for p in policies if p.get('object_id')]
            if policy_object_ids:
                placeholders = ','.join(['%s'] * len(policy_object_ids))
                id_params = [run_id] + policy_object_ids
                cursor.execute(f"""
                    SELECT id, display_name, identity_category, risk_level, risk_score, object_id
                    FROM identities
                    WHERE discovery_run_id = %s AND object_id IN ({placeholders})
                """, id_params)
                identity_map = {r['object_id']: dict(r) for r in cursor.fetchall()}

                for pol in policies:
                    oid = pol.get('object_id', '')
                    identity_info = identity_map.get(oid, {})
                    entry = {
                        'id': identity_info.get('id'),
                        'display_name': identity_info.get('display_name', f'Unknown ({oid[:8]}...)'),
                        'identity_category': identity_info.get('identity_category', 'unknown'),
                        'risk_level': identity_info.get('risk_level', 'unknown'),
                        'risk_score': identity_info.get('risk_score', 0),
                        'object_id': oid,
                        'access_type': 'access_policy',
                        'over_privileged': False,
                        'permissions_summary': pol.get('permissions', {}),
                    }
                    policy_access.append(entry)
                    if identity_info.get('id'):
                        policy_identity_ids.add(identity_info['id'])

        cursor.close()

        blast_radius = len(rbac_identity_ids | policy_identity_ids)
        # Access source breakdown
        source_counts = {}
        for entry in rbac_access:
            src = entry.get('access_source', 'unknown')
            source_counts[src] = source_counts.get(src, 0) + 1
        return jsonify({
            'resource_id': resource_id,
            'rbac_access': rbac_access,
            'policy_access': policy_access,
            'count': len(rbac_access) + len(policy_access),
            'blast_radius': blast_radius,
            'access_source_breakdown': source_counts,
        })
    finally:
        db.close()


def get_resource_expiry_summary():
    """GET /api/resources/expiry-summary — aggregate expiry data across all key vaults."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'secrets': {}, 'keys': {}, 'certs': {}, 'timeline': []})

        tenant_filter = ""
        params = [run_id]
        if tenant_id:
            tenant_filter = " AND (tenant_id = %s OR tenant_id IS NULL)"
            params.append(tenant_id)

        cursor.execute(f"""
            SELECT name, secrets_detail, keys_detail, certs_detail,
                   secrets_total, secrets_expired, secrets_expiring_soon,
                   keys_total, keys_expired, keys_expiring_soon,
                   certs_total, certs_expired, certs_expiring_soon
            FROM azure_key_vaults
            WHERE discovery_run_id = %s{tenant_filter}
        """, params)
        rows = cursor.fetchall()
        cursor.close()

        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        d7 = now + timedelta(days=7)
        d30 = now + timedelta(days=30)
        d90 = now + timedelta(days=90)

        secrets_agg = {'total': 0, 'expired': 0, 'expiring_7d': 0, 'expiring_30d': 0, 'expiring_90d': 0, 'no_expiry': 0}
        keys_agg = {'total': 0, 'expired': 0, 'expiring_7d': 0, 'expiring_30d': 0, 'expiring_90d': 0, 'no_expiry': 0}
        certs_agg = {'total': 0, 'expired': 0, 'expiring_7d': 0, 'expiring_30d': 0, 'expiring_90d': 0, 'no_expiry': 0}
        timeline = []

        def parse_items(items_raw):
            if isinstance(items_raw, str):
                try:
                    return json.loads(items_raw)
                except Exception:
                    return []
            return items_raw or []

        def classify(exp_str, agg, item_name, item_type, vault_name):
            agg['total'] += 1
            if not exp_str:
                agg['no_expiry'] += 1
                return
            try:
                exp = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
            except Exception:
                agg['no_expiry'] += 1
                return
            if exp < now:
                agg['expired'] += 1
            elif exp < d7:
                agg['expiring_7d'] += 1
            elif exp < d30:
                agg['expiring_30d'] += 1
            elif exp < d90:
                agg['expiring_90d'] += 1
            timeline.append({'vault': vault_name, 'item': item_name, 'type': item_type, 'expires_on': exp_str})

        for row in rows:
            vault_name = row['name']
            for s in parse_items(row.get('secrets_detail')):
                classify(s.get('expires_on'), secrets_agg, s.get('name', ''), 'secret', vault_name)
            for k in parse_items(row.get('keys_detail')):
                classify(k.get('expires_on'), keys_agg, k.get('name', ''), 'key', vault_name)
            for c in parse_items(row.get('certs_detail')):
                classify(c.get('expires_on'), certs_agg, c.get('name', ''), 'certificate', vault_name)

        # Sort timeline by expiry (soonest first), filter out no-expiry
        timeline.sort(key=lambda x: x['expires_on'] or '9999')

        return jsonify({
            'secrets': secrets_agg,
            'keys': keys_agg,
            'certs': certs_agg,
            'timeline': timeline[:50],  # Top 50 soonest
        })
    finally:
        db.close()


def get_resource_compliance_summary():
    """GET /api/resources/compliance-summary — aggregate compliance pass/fail across all resources."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'storage': {}, 'key_vault': {}})

        tenant_filter = ""
        params = [run_id]
        if tenant_id:
            tenant_filter = " AND (tenant_id = %s OR tenant_id IS NULL)"
            params.append(tenant_id)

        # Storage compliance
        cursor.execute(f"""
            SELECT COUNT(*) as total,
                   COUNT(*) FILTER (WHERE public_blob_access = false) as public_blob_pass,
                   COUNT(*) FILTER (WHERE https_only = true) as https_pass,
                   COUNT(*) FILTER (WHERE minimum_tls_version = 'TLS1_2') as tls_pass,
                   COUNT(*) FILTER (WHERE customer_managed_keys = true) as cmk_pass,
                   COUNT(*) FILTER (WHERE default_network_action = 'Deny') as network_pass,
                   COUNT(*) FILTER (WHERE shared_key_access = false) as shared_key_pass,
                   COUNT(*) FILTER (WHERE infrastructure_encryption = true) as infra_enc_pass,
                   COUNT(*) FILTER (WHERE allow_cross_tenant_replication = false) as cross_tenant_pass,
                   COUNT(*) FILTER (WHERE key_rotation_stale = false) as rotation_pass,
                   COUNT(*) FILTER (WHERE private_endpoint_count > 0) as private_ep_pass,
                   COUNT(*) FILTER (WHERE sas_policy_enabled = true) as sas_policy_pass,
                   COUNT(*) FILTER (WHERE bypass_settings = 'AzureServices') as bypass_pass
            FROM azure_storage_accounts
            WHERE discovery_run_id = %s{tenant_filter}
        """, params)
        sa_row = dict(cursor.fetchone())
        sa_total = sa_row['total']

        # KV compliance
        cursor.execute(f"""
            SELECT COUNT(*) as total,
                   COUNT(*) FILTER (WHERE soft_delete_enabled = true) as soft_delete_pass,
                   COUNT(*) FILTER (WHERE purge_protection = true) as purge_pass,
                   COUNT(*) FILTER (WHERE enable_rbac_authorization = true) as rbac_pass,
                   COUNT(*) FILTER (WHERE secrets_expired = 0 AND keys_expired = 0 AND certs_expired = 0) as no_expired_pass,
                   COUNT(*) FILTER (WHERE default_network_action = 'Deny') as network_pass,
                   COUNT(*) FILTER (WHERE private_endpoint_count > 0) as private_ep_pass,
                   COUNT(*) FILTER (WHERE soft_delete_retention_days >= 90) as retention_pass
            FROM azure_key_vaults
            WHERE discovery_run_id = %s{tenant_filter}
        """, params)
        kv_row = dict(cursor.fetchone())
        kv_total = kv_row['total']
        cursor.close()

        def pct(passed, total):
            return round(passed / total * 100) if total > 0 else 0

        storage_checks = {
            'public_blob_access': {'passed': sa_row['public_blob_pass'], 'total': sa_total, 'pct': pct(sa_row['public_blob_pass'], sa_total)},
            'https_only': {'passed': sa_row['https_pass'], 'total': sa_total, 'pct': pct(sa_row['https_pass'], sa_total)},
            'tls_1_2': {'passed': sa_row['tls_pass'], 'total': sa_total, 'pct': pct(sa_row['tls_pass'], sa_total)},
            'cmk': {'passed': sa_row['cmk_pass'], 'total': sa_total, 'pct': pct(sa_row['cmk_pass'], sa_total)},
            'network_deny': {'passed': sa_row['network_pass'], 'total': sa_total, 'pct': pct(sa_row['network_pass'], sa_total)},
            'shared_key_disabled': {'passed': sa_row['shared_key_pass'], 'total': sa_total, 'pct': pct(sa_row['shared_key_pass'], sa_total)},
            'infra_encryption': {'passed': sa_row['infra_enc_pass'], 'total': sa_total, 'pct': pct(sa_row['infra_enc_pass'], sa_total)},
            'cross_tenant_disabled': {'passed': sa_row['cross_tenant_pass'], 'total': sa_total, 'pct': pct(sa_row['cross_tenant_pass'], sa_total)},
            'key_rotation': {'passed': sa_row['rotation_pass'], 'total': sa_total, 'pct': pct(sa_row['rotation_pass'], sa_total)},
            'private_endpoints': {'passed': sa_row['private_ep_pass'], 'total': sa_total, 'pct': pct(sa_row['private_ep_pass'], sa_total)},
            'sas_policy': {'passed': sa_row['sas_policy_pass'], 'total': sa_total, 'pct': pct(sa_row['sas_policy_pass'], sa_total)},
            'bypass_limited': {'passed': sa_row['bypass_pass'], 'total': sa_total, 'pct': pct(sa_row['bypass_pass'], sa_total)},
        }
        sa_passed = sum(c['passed'] for c in storage_checks.values())
        sa_total_checks = sa_total * len(storage_checks)

        kv_checks = {
            'soft_delete': {'passed': kv_row['soft_delete_pass'], 'total': kv_total, 'pct': pct(kv_row['soft_delete_pass'], kv_total)},
            'purge_protection': {'passed': kv_row['purge_pass'], 'total': kv_total, 'pct': pct(kv_row['purge_pass'], kv_total)},
            'rbac_auth': {'passed': kv_row['rbac_pass'], 'total': kv_total, 'pct': pct(kv_row['rbac_pass'], kv_total)},
            'no_expired_items': {'passed': kv_row['no_expired_pass'], 'total': kv_total, 'pct': pct(kv_row['no_expired_pass'], kv_total)},
            'network_deny': {'passed': kv_row['network_pass'], 'total': kv_total, 'pct': pct(kv_row['network_pass'], kv_total)},
            'private_endpoints': {'passed': kv_row['private_ep_pass'], 'total': kv_total, 'pct': pct(kv_row['private_ep_pass'], kv_total)},
            'retention_90d': {'passed': kv_row['retention_pass'], 'total': kv_total, 'pct': pct(kv_row['retention_pass'], kv_total)},
        }
        kv_passed = sum(c['passed'] for c in kv_checks.values())
        kv_total_checks = kv_total * len(kv_checks)

        return jsonify({
            'storage': {
                'total_resources': sa_total,
                'total_checks': sa_total_checks,
                'passed': sa_passed,
                'failed': sa_total_checks - sa_passed,
                'score': pct(sa_passed, sa_total_checks),
                'checks': storage_checks,
            },
            'key_vault': {
                'total_resources': kv_total,
                'total_checks': kv_total_checks,
                'passed': kv_passed,
                'failed': kv_total_checks - kv_passed,
                'score': pct(kv_passed, kv_total_checks),
                'checks': kv_checks,
            },
        })
    finally:
        db.close()


# ─── Phase 53: SaaS Platform ─────────────────────────────────────

def get_tenant_by_slug_public(slug):
    """GET /api/tenants/by-slug/<slug> — Public (no auth). Returns limited tenant info."""
    db = _db()
    try:
        tenant = db.get_tenant_by_slug(slug)
        if not tenant:
            return jsonify({'error': 'Organization not found'}), 404
        return jsonify({
            'tenant': {
                'id': tenant['id'],
                'name': tenant['name'],
                'slug': tenant['slug'],
                'plan': tenant.get('plan', 'free'),
                'enabled': tenant.get('enabled', True),
            }
        })
    finally:
        db.close()


def provision_tenant_handler(tenant_id):
    """POST /api/tenants/<id>/provision — Create admin user for a tenant. Superadmin only."""
    data = request.get_json(silent=True) or {}
    admin_username = str(data.get('admin_username', '')).strip().lower()
    admin_display_name = str(data.get('admin_display_name', '')).strip()
    admin_password = str(data.get('admin_password', ''))

    if not admin_username or len(admin_username) < 3:
        return jsonify({'error': 'admin_username must be at least 3 characters'}), 400
    if not admin_display_name:
        return jsonify({'error': 'admin_display_name is required'}), 400
    if not admin_password or len(admin_password) < 12:
        return jsonify({'error': 'admin_password must be at least 12 characters'}), 400

    db = _db()
    try:
        tenant = db.get_tenant_by_id(tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404

        existing = db.get_user_by_username(admin_username)
        if existing:
            return jsonify({'error': f'Username "{admin_username}" already exists'}), 409

        hashed = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        current_user = getattr(g, 'current_user', None)
        created_by = current_user['id'] if current_user else None

        user = db.create_user(admin_username, hashed, admin_display_name, 'admin', created_by, tenant_id=tenant_id, force_password_change=True)

        # Mark tenant as provisioned
        settings = tenant.get('settings') or {}
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        settings['provisioned'] = True
        settings['provisioned_at'] = datetime.utcnow().isoformat()
        db.update_tenant(tenant_id, settings=settings)

        _log(db, 'tenant_provisioned',
             f'Tenant "{tenant["name"]}" provisioned with admin user "{admin_username}"',
             {'tenant_id': tenant_id, 'admin_user_id': user['id']})

        return jsonify({
            'tenant': db.get_tenant_by_id(tenant_id),
            'admin_user': {k: v for k, v in user.items() if k != 'password_hash'},
            'message': f'Tenant provisioned with admin user "{admin_username}"',
        }), 201
    finally:
        db.close()


def get_user_tenants_handler():
    """GET /api/auth/tenants — Return tenants accessible to the current user."""
    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({'error': 'Authentication required'}), 401

    db = _db()
    try:
        if user.get('is_superadmin'):
            all_tenants = db.get_tenants()
            tenants = [
                {'id': t['id'], 'name': t['name'], 'slug': t['slug'], 'plan': t.get('plan', 'free')}
                for t in all_tenants if t.get('enabled', True)
            ]
        else:
            tid = user.get('tenant_id')
            if tid:
                t = db.get_tenant_by_id(tid)
                tenants = [{'id': t['id'], 'name': t['name'], 'slug': t['slug'], 'plan': t.get('plan', 'free')}] if t else []
            else:
                tenants = []
        return jsonify({'tenants': tenants})
    finally:
        db.close()


# ── Phase 54: SSO/SAML Endpoints ───────────────────────────────────────────


def _get_base_url():
    """Derive the base URL from the current Flask request for SAML config."""
    return f"{request.scheme}://{request.host}"


def sso_status():
    """GET /api/auth/sso-status?tenant_slug=X — public endpoint.
    Returns whether SSO is enabled for a tenant."""
    slug = request.args.get('tenant_slug', '').strip()
    if not slug:
        return jsonify({'sso_enabled': False})
    db = _db()
    try:
        tenant = db.get_tenant_by_slug(slug)
        if not tenant or not tenant.get('enabled'):
            return jsonify({'sso_enabled': False})
        enabled = db.get_setting('sso_enabled', 'false', tenant_id=tenant['id'])
        force = db.get_setting('sso_force_sso', 'false', tenant_id=tenant['id'])
        return jsonify({
            'sso_enabled': enabled == 'true',
            'sso_force_sso': force == 'true',
        })
    finally:
        db.close()


def saml_metadata():
    """GET /api/auth/saml/metadata?tenant_slug=X — Return SP metadata XML."""
    from app.api.saml import get_sso_config_for_tenant, get_saml_auth
    slug = request.args.get('tenant_slug', '').strip()
    if not slug:
        return jsonify({'error': 'tenant_slug is required'}), 400
    db = _db()
    try:
        tenant = db.get_tenant_by_slug(slug)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        sso_config = get_sso_config_for_tenant(db, tenant['id'])
        if not sso_config:
            # Return metadata even without full config — admin needs SP info to configure IdP
            sso_config = {
                'sso_idp_entity_id': 'https://placeholder',
                'sso_idp_sso_url': 'https://placeholder',
                'sso_idp_x509_cert': '',
            }
        auth = get_saml_auth(sso_config, request, _get_base_url())
        metadata = auth.get_settings().get_sp_metadata()
        errors = auth.get_settings().validate_metadata(metadata)
        if errors:
            return jsonify({'error': 'Invalid SP metadata', 'details': errors}), 500
        from flask import Response
        return Response(metadata, mimetype='text/xml')
    finally:
        db.close()


def saml_login():
    """GET /api/auth/saml/login?tenant_slug=X — Redirect to IdP."""
    from app.api.saml import get_sso_config_for_tenant, get_saml_auth
    slug = request.args.get('tenant_slug', '').strip()
    if not slug:
        return jsonify({'error': 'tenant_slug is required'}), 400
    db = _db()
    try:
        tenant = db.get_tenant_by_slug(slug)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404
        sso_config = get_sso_config_for_tenant(db, tenant['id'])
        if not sso_config:
            return jsonify({'error': 'SSO is not configured for this organization'}), 400
        auth = get_saml_auth(sso_config, request, _get_base_url())
        sso_url = auth.login(return_to=slug)  # RelayState = tenant slug
        from flask import redirect
        return redirect(sso_url)
    finally:
        db.close()


def saml_acs():
    """POST /api/auth/saml/acs — Assertion Consumer Service callback from IdP."""
    from app.api.saml import (
        get_sso_config_for_tenant, get_saml_auth, extract_saml_attributes, map_saml_role,
    )
    from flask import redirect

    # RelayState carries the tenant slug
    slug = request.form.get('RelayState', '').strip()
    if not slug:
        return jsonify({'error': 'Missing RelayState (tenant slug)'}), 400

    db = _db()
    try:
        tenant = db.get_tenant_by_slug(slug)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404

        sso_config = get_sso_config_for_tenant(db, tenant['id'])
        if not sso_config:
            return jsonify({'error': 'SSO not configured'}), 400

        auth = get_saml_auth(sso_config, request, _get_base_url())
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            return jsonify({'error': 'SAML validation failed', 'details': errors}), 401

        if not auth.is_authenticated():
            return jsonify({'error': 'SAML authentication failed'}), 401

        # Extract user attributes
        attrs = extract_saml_attributes(auth)
        role = map_saml_role(sso_config, attrs['groups'])

        # JIT provision or update user
        user = db.get_user_by_external_id(attrs['name_id'], tenant['id'])

        if not user:
            # Try to link by username/email
            user = db.get_user_by_username(attrs['email'])
            if user and user.get('tenant_id') == tenant['id']:
                # Link existing local account to SSO
                db.update_sso_user(user['id'], external_id=attrs['name_id'])
                user['external_id'] = attrs['name_id']
            else:
                user = None

        if not user:
            # JIT create
            jit_enabled = sso_config.get('sso_jit_enabled', 'true') == 'true'
            if not jit_enabled:
                return jsonify({'error': 'User not found and JIT provisioning is disabled'}), 403
            user = db.create_sso_user(
                username=attrs['email'],
                display_name=attrs['display_name'],
                role=role,
                tenant_id=tenant['id'],
                external_id=attrs['name_id'],
            )
        else:
            # Update display name and role on each login
            db.update_sso_user(
                user['id'],
                display_name=attrs['display_name'],
                role=role,
            )
            user['display_name'] = attrs['display_name']
            user['role'] = role

        if not user.get('enabled', True):
            return jsonify({'error': 'User account is disabled'}), 403

        # Generate one-time auth code
        code = db.create_sso_auth_code(user['id'], tenant['id'])

        # Log the SSO login
        db.log_activity(
            'sso_login',
            f"SSO login: {attrs['email']} via SAML for {tenant['name']}",
            {'tenant_id': tenant['id'], 'external_id': attrs['name_id']},
            user_id=user['id'],
            tenant_id=tenant['id'],
        )

        # Redirect to frontend callback
        return redirect(f"/sso-callback?code={code}")
    finally:
        db.close()


def saml_token_exchange():
    """POST /api/auth/saml/token — Exchange one-time SSO code for JWT tokens."""
    data = request.get_json(silent=True) or {}
    code = str(data.get('code', '')).strip()
    if not code:
        return jsonify({'error': 'Missing code'}), 400

    db = _db()
    try:
        result = db.consume_sso_auth_code(code)
        if not result:
            return jsonify({'error': 'Invalid or expired SSO code'}), 401

        user = db.get_user_by_id(result['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Add tenant_name for token generation
        if user.get('tenant_id') and not user.get('tenant_name'):
            t = db.get_tenant_by_id(user['tenant_id'])
            if t:
                user['tenant_name'] = t['name']

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'display_name': user['display_name'],
                'role': user['role'],
                'tenant_id': user.get('tenant_id'),
                'tenant_name': user.get('tenant_name'),
                'is_superadmin': user.get('is_superadmin', False),
            },
        })
    finally:
        db.close()


def saml_slo():
    """GET /api/auth/saml/slo — SP-initiated Single Logout."""
    from app.api.saml import get_sso_config_for_tenant, get_saml_auth
    from flask import redirect

    user = getattr(g, 'current_user', None)
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    tid = user.get('tenant_id')
    if not tid:
        return jsonify({'error': 'No tenant context'}), 400

    db = _db()
    try:
        sso_config = get_sso_config_for_tenant(db, tid)
        if not sso_config or not sso_config.get('sso_idp_slo_url'):
            return jsonify({'message': 'SLO not configured, logged out locally'})

        auth = get_saml_auth(sso_config, request, _get_base_url())
        slo_url = auth.logout()
        return redirect(slo_url)
    finally:
        db.close()


# ── Phase 54: SSO Settings Endpoints ───────────────────────────────────────


def get_sso_settings():
    """GET /api/settings/sso — Return SSO config for current tenant."""
    from app.api.saml import SSO_SETTING_KEYS
    tid = _tenant_id()
    db = _db()
    try:
        config = {}
        for key in SSO_SETTING_KEYS:
            val = db.get_setting(key, '', tenant_id=tid)
            # Mask the certificate for display (show first/last 20 chars)
            if key == 'sso_idp_x509_cert' and val and len(val) > 50:
                config[key] = val[:20] + '...' + val[-20:]
                config['sso_idp_x509_cert_set'] = True
            else:
                config[key] = val

        # Compute SP info
        base_url = _get_base_url()
        config['sp_entity_id'] = f"{base_url}/api/auth/saml/metadata"
        config['sp_acs_url'] = f"{base_url}/api/auth/saml/acs"
        config['sp_metadata_url'] = f"{base_url}/api/auth/saml/metadata?tenant_slug=default"

        return jsonify(config)
    finally:
        db.close()


def save_sso_settings():
    """POST /api/settings/sso — Save SSO config."""
    from app.api.saml import SSO_SETTING_KEYS
    data = request.get_json(silent=True) or {}
    tid = _tenant_id()

    # Filter to valid SSO keys only
    updates = {}
    for key in SSO_SETTING_KEYS:
        if key in data:
            updates[key] = str(data[key])

    # Validate required fields when enabling SSO
    if updates.get('sso_enabled') == 'true':
        required = ['sso_idp_entity_id', 'sso_idp_sso_url', 'sso_idp_x509_cert']
        db = _db()
        try:
            for field in required:
                val = updates.get(field) or db.get_setting(field, '', tenant_id=tid)
                if not val:
                    return jsonify({'error': f'{field} is required when enabling SSO'}), 400
        finally:
            db.close()

    db = _db()
    try:
        db.save_settings(updates, tenant_id=tid)
        _log(db, 'settings_update', f"SSO settings updated (enabled={updates.get('sso_enabled', 'unchanged')})")
        return jsonify({'message': 'SSO settings saved', 'updated_keys': list(updates.keys())})
    finally:
        db.close()


def parse_sso_metadata():
    """POST /api/settings/sso/parse-metadata — Fetch and parse IdP metadata URL."""
    from app.api.saml import parse_idp_metadata_url
    data = request.get_json(silent=True) or {}
    metadata_url = str(data.get('metadata_url', '')).strip()
    if not metadata_url:
        return jsonify({'error': 'metadata_url is required'}), 400

    try:
        parsed = parse_idp_metadata_url(metadata_url)
        return jsonify(parsed)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# ------------------------------------------------------------------
# Service Account Governance (Phase 63)
# ------------------------------------------------------------------

SA_CATEGORIES = ('service_principal', 'managed_identity_system', 'managed_identity_user')

SA_GOV_DEFAULTS = {
    'sa_gov_max_credential_age_days': '365',
    'sa_gov_attestation_interval_days': '90',
    'sa_gov_dormant_threshold_days': '90',
    'sa_gov_require_owner': 'true',
}


def _load_sa_gov_policies(db, tenant_id=None):
    """Load SA governance policies from settings, with defaults."""
    policies = dict(SA_GOV_DEFAULTS)
    for key in SA_GOV_DEFAULTS:
        val = db.get_setting(key, tenant_id=tenant_id)
        if val is not None:
            policies[key] = val
    return policies


def _compute_governance_status(identity, attestation, policies):
    """Compute governance status and issues for a single service account."""
    issues = []
    now = datetime.utcnow()

    # Check owner requirement
    if policies.get('sa_gov_require_owner') == 'true':
        if (identity.get('owner_count') or 0) == 0:
            issues.append('no_owner')

    # Check credential expiration
    cred_risk = identity.get('credential_risk') or ''
    if cred_risk == 'expired':
        issues.append('credential_expired')
    elif cred_risk == 'expiring_soon':
        issues.append('credential_expiring')

    # Check credential age against policy max
    next_exp = identity.get('next_expiry') or identity.get('credential_expiration')
    if next_exp:
        max_age = int(policies.get('sa_gov_max_credential_age_days', '365'))
        # credential_expiration is the nearest expiry; estimate age from it
        # If the credential was issued for 1yr and expires in 30d, it's ~335d old
        # We approximate: if expiry is in the past or within (max_age) from now,
        # check start_datetime from credentials table; as a simpler heuristic,
        # use credential_risk which already handles expired/expiring
        pass  # Covered by credential_risk checks above

    # Check dormancy
    act_status = identity.get('activity_status') or ''
    if act_status in ('stale', 'never_used'):
        issues.append('dormant')

    # Check attestation
    if attestation is None:
        issues.append('attestation_overdue')
    else:
        next_due = attestation.get('next_due')
        if next_due:
            if hasattr(next_due, 'replace'):
                # It's a datetime
                if next_due.replace(tzinfo=None) < now:
                    issues.append('attestation_overdue')
            elif isinstance(next_due, str):
                try:
                    from dateutil.parser import parse as dtparse
                    if dtparse(next_due).replace(tzinfo=None) < now:
                        issues.append('attestation_overdue')
                except Exception:
                    issues.append('attestation_overdue')

    # Determine overall status
    critical = {'no_owner', 'credential_expired', 'attestation_overdue', 'dormant'}
    if not issues:
        return 'compliant', issues
    elif any(i in critical for i in issues):
        return 'non_compliant', issues
    else:
        return 'needs_attention', issues


def get_sa_governance_stats():
    """GET /api/service-accounts/stats — Governance summary statistics."""
    db = _db()
    cursor = db.conn.cursor()
    tid = _tenant_id()

    try:
        # Get latest run
        run_id = _latest_run_query(cursor, tid)
        if not run_id:
            return jsonify({'error': 'No completed discovery runs'}), 404

        policies = _load_sa_gov_policies(db, tid)

        # Basic counts from identities table
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE COALESCE(owner_count, 0) = 0) as unowned,
                COUNT(*) FILTER (WHERE activity_status IN ('stale', 'never_used')) as dormant,
                COUNT(*) FILTER (WHERE credential_risk = 'expired') as credential_expired,
                COUNT(*) FILTER (WHERE credential_risk = 'expiring_soon') as credential_expiring
            FROM identities
            WHERE discovery_run_id = %s
              AND identity_category IN %s
        """, (run_id, SA_CATEGORIES))
        row = cursor.fetchone()
        total = row[0] or 0
        unowned = row[1] or 0
        dormant = row[2] or 0
        cred_expired = row[3] or 0
        cred_expiring = row[4] or 0

        if total == 0:
            return jsonify({
                'total': 0, 'compliant': 0, 'needs_attention': 0, 'non_compliant': 0,
                'unowned': 0, 'dormant': 0, 'credential_expired': 0,
                'credential_expiring': 0, 'attestation_overdue': 0, 'compliance_rate': 0,
            })

        # Fetch all SA identity_ids and their governance-relevant fields
        from psycopg2.extras import RealDictCursor
        cursor2 = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor2.execute("""
            SELECT identity_id, owner_count, credential_risk, activity_status,
                   credential_expiration, next_expiry
            FROM identities
            WHERE discovery_run_id = %s AND identity_category IN %s
        """, (run_id, SA_CATEGORIES))
        sa_rows = cursor2.fetchall()
        cursor2.close()

        # Batch fetch latest attestations
        sa_ids = [r['identity_id'] for r in sa_rows]
        attestation_map = {}
        if sa_ids:
            cursor3 = db.conn.cursor(cursor_factory=RealDictCursor)
            cursor3.execute("""
                SELECT DISTINCT ON (identity_id) identity_id, status, attested_at, next_due
                FROM sa_attestations
                WHERE identity_id = ANY(%s)
                ORDER BY identity_id, attested_at DESC
            """, (sa_ids,))
            for arow in cursor3.fetchall():
                attestation_map[arow['identity_id']] = dict(arow)
            cursor3.close()

        # Compute governance status for each
        compliant = needs_att = non_comp = att_overdue = 0
        for sa in sa_rows:
            att = attestation_map.get(sa['identity_id'])
            status, issues = _compute_governance_status(dict(sa), att, policies)
            if status == 'compliant':
                compliant += 1
            elif status == 'needs_attention':
                needs_att += 1
            else:
                non_comp += 1
            if 'attestation_overdue' in issues:
                att_overdue += 1

        return jsonify({
            'total': total,
            'compliant': compliant,
            'needs_attention': needs_att,
            'non_compliant': non_comp,
            'unowned': unowned,
            'dormant': dormant,
            'credential_expired': cred_expired,
            'credential_expiring': cred_expiring,
            'attestation_overdue': att_overdue,
            'compliance_rate': round(compliant / total * 100, 1) if total else 0,
        })
    finally:
        db.close()


def get_sa_governance_list():
    """GET /api/service-accounts/governance — SA list with governance overlay."""
    db = _db()
    tid = _tenant_id()

    try:
        from psycopg2.extras import RealDictCursor
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)

        # Get latest run
        if tid:
            cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed' AND tenant_id = %s", (tid,))
        else:
            cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        row = cursor.fetchone()
        run_id = list(row.values())[0] if row else None
        if not run_id:
            return jsonify({'items': [], 'total': 0})

        policies = _load_sa_gov_policies(db, tid)

        # Parse query params
        filter_type = request.args.get('filter', 'all')
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'risk_score')
        sort_dir = request.args.get('sort_dir', 'desc')
        limit = min(int(request.args.get('limit', '50')), 200)
        offset = int(request.args.get('offset', '0'))

        # Build query
        where_clauses = ["i.discovery_run_id = %s", "i.identity_category IN %s"]
        params = [run_id, SA_CATEGORIES]

        if search:
            where_clauses.append("LOWER(i.display_name) LIKE %s")
            params.append(f"%{search.lower()}%")

        if filter_type == 'unowned':
            where_clauses.append("COALESCE(i.owner_count, 0) = 0")
        elif filter_type == 'credential_issues':
            where_clauses.append("i.credential_risk IN ('expired', 'expiring_soon')")
        elif filter_type == 'dormant':
            where_clauses.append("i.activity_status IN ('stale', 'never_used')")

        where_sql = " AND ".join(where_clauses)

        # Allowed sort columns
        sort_map = {
            'display_name': 'i.display_name',
            'identity_category': 'i.identity_category',
            'risk_score': 'COALESCE(i.risk_score, 0)',
            'risk_level': 'i.risk_level',
            'owner_count': 'COALESCE(i.owner_count, 0)',
            'credential_risk': 'i.credential_risk',
            'activity_status': 'i.activity_status',
            'last_sign_in': 'i.last_sign_in',
        }
        order_col = sort_map.get(sort_by, 'COALESCE(i.risk_score, 0)')
        order_dir = 'ASC' if sort_dir.lower() == 'asc' else 'DESC'

        # Count total
        cursor.execute(f"SELECT COUNT(*) as cnt FROM identities i WHERE {where_sql}", params)
        total = cursor.fetchone()['cnt']

        # Fetch page
        cursor.execute(f"""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.risk_level, COALESCE(i.risk_score, 0) as risk_score,
                   COALESCE(i.owner_count, 0) as owner_count, i.owner_display_name,
                   i.credential_risk, i.credential_count, i.credential_expiration,
                   i.next_expiry, i.activity_status, i.last_sign_in, i.created_datetime
            FROM identities i
            WHERE {where_sql}
            ORDER BY {order_col} {order_dir} NULLS LAST
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        rows = [dict(r) for r in cursor.fetchall()]

        if not rows:
            return jsonify({'items': [], 'total': total})

        # Batch fetch latest attestations for this page
        page_ids = [r['identity_id'] for r in rows]
        cursor.execute("""
            SELECT DISTINCT ON (identity_id) identity_id, status as att_status,
                   attested_at, next_due,
                   (SELECT display_name FROM users WHERE id = sa.attested_by) as attester_name
            FROM sa_attestations sa
            WHERE identity_id = ANY(%s)
            ORDER BY identity_id, attested_at DESC
        """, (page_ids,))
        att_map = {}
        for ar in cursor.fetchall():
            att_map[ar['identity_id']] = dict(ar)

        # Filter for needs_attestation (post-query)
        if filter_type == 'needs_attestation':
            filtered = []
            for r in rows:
                att = att_map.get(r['identity_id'])
                _, issues = _compute_governance_status(r, att, policies)
                if 'attestation_overdue' in issues:
                    filtered.append(r)
            rows = filtered
            total = len(rows)  # approximate for this filter

        # Build response items with governance overlay
        items = []
        now = datetime.utcnow()
        for r in rows:
            att = att_map.get(r['identity_id'])
            gov_status, gov_issues = _compute_governance_status(r, att, policies)

            att_status = 'never_attested'
            att_date = None
            next_due = None
            attester = None
            if att:
                att_status = att.get('att_status', 'unknown')
                att_date = att['attested_at'].isoformat() if att.get('attested_at') else None
                nd = att.get('next_due')
                if nd:
                    next_due = nd.isoformat() if hasattr(nd, 'isoformat') else str(nd)
                    if hasattr(nd, 'replace') and nd.replace(tzinfo=None) < now:
                        att_status = 'overdue'
                attester = att.get('attester_name')

            items.append({
                'identity_id': r['identity_id'],
                'identity_db_id': r['id'],
                'display_name': r['display_name'],
                'identity_category': r['identity_category'],
                'governance_status': gov_status,
                'governance_issues': gov_issues,
                'owner_display_name': r['owner_display_name'],
                'owner_count': r['owner_count'],
                'credential_risk': r['credential_risk'],
                'credential_count': r.get('credential_count') or 0,
                'attestation_status': att_status,
                'attestation_date': att_date,
                'next_attestation_due': next_due,
                'attester_name': attester,
                'risk_level': r['risk_level'],
                'risk_score': r['risk_score'],
                'activity_status': r['activity_status'],
                'last_sign_in': r['last_sign_in'].isoformat() if r.get('last_sign_in') else None,
                'created_datetime': r['created_datetime'].isoformat() if r.get('created_datetime') else None,
            })

        return jsonify({'items': items, 'total': total})
    finally:
        db.close()


def post_sa_attestation(identity_id):
    """POST /api/service-accounts/<identity_id>/attest — Submit attestation."""
    db = _db()
    tid = _tenant_id()
    user_id = _current_user_id()

    try:
        data = request.get_json(silent=True) or {}
        status = str(data.get('status', '')).strip()
        justification = str(data.get('justification', '')).strip()

        if status not in ('approved', 'needs_review', 'decommission_requested'):
            return jsonify({'error': 'status must be approved, needs_review, or decommission_requested'}), 400
        if not justification:
            return jsonify({'error': 'justification is required'}), 400

        # Verify identity exists and is a service account
        from psycopg2.extras import RealDictCursor
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, identity_id, display_name, identity_category
            FROM identities
            WHERE identity_id = %s AND identity_category IN %s
            ORDER BY id DESC LIMIT 1
        """, (identity_id, SA_CATEGORIES))
        identity = cursor.fetchone()
        cursor.close()

        if not identity:
            return jsonify({'error': 'Service account not found'}), 404

        policies = _load_sa_gov_policies(db, tid)
        interval = int(policies.get('sa_gov_attestation_interval_days', '90'))

        result = db.create_sa_attestation(
            identity_id=identity_id,
            identity_db_id=identity['id'],
            attested_by=user_id,
            status=status,
            justification=justification,
            interval_days=interval,
            tenant_id=tid,
        )

        _log(db, 'sa_attestation', f"Attested {identity['display_name']}: {status}",
             {'identity_id': identity_id, 'status': status})

        # Serialize datetimes
        for k in ('attested_at', 'next_due', 'created_at'):
            if result.get(k) and hasattr(result[k], 'isoformat'):
                result[k] = result[k].isoformat()

        return jsonify(result), 201
    finally:
        db.close()


def get_sa_governance_settings():
    """GET /api/settings/sa-governance — Return SA governance policy settings."""
    db = _db()
    tid = _tenant_id()
    try:
        policies = _load_sa_gov_policies(db, tid)
        return jsonify({'settings': policies})
    finally:
        db.close()


def save_sa_governance_settings():
    """POST /api/settings/sa-governance — Save SA governance policy settings (admin only)."""
    db = _db()
    tid = _tenant_id()
    try:
        data = request.get_json(silent=True) or {}
        updates = {}

        for key, default in SA_GOV_DEFAULTS.items():
            if key in data:
                val = str(data[key]).strip()
                if key == 'sa_gov_require_owner':
                    if val not in ('true', 'false'):
                        return jsonify({'error': f'{key} must be true or false'}), 400
                else:
                    try:
                        num = int(val)
                        if key == 'sa_gov_max_credential_age_days' and not (1 <= num <= 3650):
                            return jsonify({'error': f'{key} must be 1-3650'}), 400
                        elif key != 'sa_gov_max_credential_age_days' and not (1 <= num <= 365):
                            return jsonify({'error': f'{key} must be 1-365'}), 400
                    except ValueError:
                        return jsonify({'error': f'{key} must be a number'}), 400
                updates[key] = val

        if updates:
            db.save_settings(updates, tenant_id=tid)
            _log(db, 'settings_update', f"SA governance settings updated: {list(updates.keys())}")

        return jsonify({'message': 'SA governance settings saved', 'updated_keys': list(updates.keys())})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Phase 68: Real-Time Monitoring & Health
# ---------------------------------------------------------------------------

def health_check():
    """GET /api/health — Enhanced health check with DB, scheduler, system diagnostics."""
    from app.metrics import MetricsCollector
    checks = {}
    overall = 'healthy'

    # DB connectivity check
    try:
        db = _db()
        t0 = time.time()
        cursor = db.conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_latency = round((time.time() - t0) * 1000, 1)
        cursor.close()
        db.close()
        checks['database'] = {'status': 'healthy', 'latency_ms': db_latency}
    except Exception as e:
        checks['database'] = {'status': 'unhealthy', 'error': str(e)}
        overall = 'degraded'

    # Scheduler check
    try:
        from app.scheduler import scheduler as _sched, get_next_run_time
        sched_running = _sched is not None
        next_run = get_next_run_time()
        checks['scheduler'] = {
            'status': 'running' if sched_running else 'stopped',
            'next_run': next_run.isoformat() if next_run else None,
        }
        if not sched_running:
            overall = 'degraded'
    except Exception:
        checks['scheduler'] = {'status': 'unknown'}

    # System metrics
    checks['system'] = {
        'pid': os.getpid(),
        'uptime_seconds': round(time.time() - MetricsCollector.get().start_time),
    }
    try:
        import psutil
        proc = psutil.Process()
        checks['system']['memory_mb'] = round(proc.memory_info().rss / 1024 / 1024, 1)
        checks['system']['cpu_percent'] = proc.cpu_percent()
    except ImportError:
        pass

    return jsonify({
        'service': 'AuditGraph API',
        'status': overall,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': checks,
    })


def prometheus_metrics():
    """GET /api/metrics — Prometheus text exposition format."""
    from app.metrics import MetricsCollector
    return Response(
        MetricsCollector.get().prometheus_format(),
        mimetype='text/plain; version=0.0.4'
    )


def get_system_health():
    """GET /api/system/health — Detailed health dashboard data."""
    from app.metrics import MetricsCollector
    db = _db()
    try:
        metrics = MetricsCollector.get()
        summary = metrics.get_summary()
        top_endpoints = metrics.get_top_endpoints(10)

        # Latest discovery runs
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, started_at, completed_at, status,
                   total_identities, critical_count, high_count,
                   EXTRACT(EPOCH FROM (completed_at - started_at)) as duration_sec
            FROM discovery_runs
            ORDER BY id DESC LIMIT 10
        """)
        runs = [dict(r) for r in cursor.fetchall()]
        for r in runs:
            for k in ('started_at', 'completed_at'):
                if r.get(k) and hasattr(r[k], 'isoformat'):
                    r[k] = r[k].isoformat()
            if r.get('duration_sec') is not None:
                r['duration_sec'] = round(float(r['duration_sec']), 1)
        cursor.close()

        # Table sizes
        cursor2 = db.conn.cursor()
        cursor2.execute("""
            SELECT relname as table_name,
                   pg_relation_size(oid) as size_bytes
            FROM pg_class
            WHERE relkind = 'r' AND relnamespace = (
                SELECT oid FROM pg_namespace WHERE nspname = 'public'
            )
            ORDER BY pg_relation_size(oid) DESC
            LIMIT 15
        """)
        tables = [{'name': r[0], 'size_bytes': r[1], 'size_mb': round(r[1] / 1024 / 1024, 2)} for r in cursor2.fetchall()]
        cursor2.close()

        return jsonify({
            'api': summary,
            'top_endpoints': top_endpoints,
            'discovery_runs': runs,
            'database': {'tables': tables},
        })
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════
# SPN Dashboard (Phase 71)
# ═══════════════════════════════════════════════════════════════════

SPN_CATEGORIES = ("service_principal", "managed_identity_system", "managed_identity_user")

_DANGEROUS_ROLES_ORDERED = [
    'global administrator', 'privileged role administrator',
    'owner', 'user access administrator',
    'privileged authentication administrator',
    'contributor', 'security administrator',
    'application administrator', 'cloud application administrator',
    'key vault administrator', 'key vault secrets officer',
    'storage blob data owner', 'exchange administrator',
]


def _compute_blast_radius(roles):
    """Compute blast radius: high / medium / low based on role scope."""
    high_roles = {'owner', 'user access administrator', 'contributor'}
    for r in roles:
        rn = (r.get('role_name') or '').lower()
        st = (r.get('scope_type') or '').lower()
        scope = (r.get('scope') or '')
        if st == 'subscription' or (scope == '/' or (scope.startswith('/subscriptions/') and '/resourceGroups/' not in scope)):
            if rn in high_roles:
                return 'high'
    for r in roles:
        rn = (r.get('role_name') or '').lower()
        st = (r.get('scope_type') or '').lower()
        if st == 'resource_group' and rn in {'owner', 'contributor', 'user access administrator'}:
            return 'medium'
    for r in roles:
        if r.get('role_name'):
            return 'low'
    return 'none'


def _extract_critical_roles(roles):
    """Return top 2 most dangerous roles for display."""
    found = []
    for dangerous in _DANGEROUS_ROLES_ORDERED:
        for r in roles:
            rn = (r.get('role_name') or '').lower()
            if rn == dangerous and rn not in [f.lower() for f in found]:
                found.append(r.get('role_name', ''))
                if len(found) >= 2:
                    return found
    return found


def _generate_risk_summary(identity, roles, credentials, entra_roles):
    """Auto-generate risk summary text for an SPN."""
    points = []
    display = identity.get('display_name', 'This SPN')

    # Check for dangerous roles
    dangerous_entra = [r for r in entra_roles if (r.get('role_name') or '').lower() in (
        'global administrator', 'privileged role administrator',
        'privileged authentication administrator')]
    dangerous_rbac = [r for r in roles if (r.get('role_name') or '').lower() in (
        'owner', 'user access administrator') and (
        (r.get('scope_type') or '').lower() == 'subscription' or (r.get('scope') or '') == '/')]
    if dangerous_entra:
        points.append(f"Has Entra directory role: {dangerous_entra[0]['role_name']}")
    if dangerous_rbac:
        scope = dangerous_rbac[0].get('scope', '')
        points.append(f"Has {dangerous_rbac[0]['role_name']} at subscription scope")

    # Credential age / status
    cred_risk = identity.get('credential_risk', 'unknown')
    if cred_risk == 'expired':
        points.append("Has expired credentials (security risk — may indicate abandoned SPN)")
    elif cred_risk == 'expiring_soon':
        points.append("Credentials expiring within 30 days")

    now = datetime.utcnow()
    oldest_secret_days = 0
    for c in credentials:
        if c.get('credential_type') == 'secret' and c.get('start_datetime'):
            start = c['start_datetime']
            if isinstance(start, str):
                try:
                    start = datetime.fromisoformat(start.replace('Z', '+00:00')).replace(tzinfo=None)
                except Exception:
                    continue
            age = (now - start).days
            oldest_secret_days = max(oldest_secret_days, age)
    if oldest_secret_days > 180:
        points.append(f"Uses a {oldest_secret_days}-day-old client secret")
    elif oldest_secret_days > 90:
        points.append(f"Client secret is {oldest_secret_days} days old (consider rotation)")

    # Federated vs secret
    cred_types = set(c.get('credential_type', '') for c in credentials)
    if 'secret' in cred_types and 'federated' not in cred_types:
        points.append("Uses client secret — consider migrating to workload identity federation")

    # Activity / usage
    activity = identity.get('activity_status', 'unknown')
    if activity in ('stale', 'inactive'):
        points.append(f"Activity status is '{activity}' — may be unused")
    elif activity == 'never_used':
        points.append("Has never been used (candidate for removal)")
    elif activity == 'unknown':
        points.append("Usage telemetry unavailable — access risk still exists")

    # Owner
    if identity.get('owner_count', 0) == 0:
        points.append("No registered owner — accountability gap")

    if not points:
        points.append("No significant risk factors identified")

    return points


def _generate_recommendations(identity, roles, credentials, entra_roles):
    """Auto-generate actionable recommendations for an SPN."""
    recs = []
    cred_types = set(c.get('credential_type', '') for c in credentials)

    if 'secret' in cred_types and 'federated' not in cred_types:
        recs.append({
            'priority': 'high',
            'action': 'Migrate to workload identity federation',
            'reason': 'Eliminates need for client secrets entirely'
        })

    cred_risk = identity.get('credential_risk', 'unknown')
    if cred_risk == 'expired':
        recs.append({
            'priority': 'critical',
            'action': 'Remove or rotate expired credentials',
            'reason': 'Expired credentials indicate an abandoned or misconfigured SPN'
        })
    elif cred_risk == 'expiring_soon':
        recs.append({
            'priority': 'high',
            'action': 'Rotate credentials before expiry',
            'reason': 'Credentials will expire within 30 days'
        })

    for r in roles:
        rn = (r.get('role_name') or '').lower()
        st = (r.get('scope_type') or '').lower()
        if rn == 'owner' and st == 'subscription':
            recs.append({
                'priority': 'critical',
                'action': f"Restrict scope — {r['role_name']} at subscription is overprivileged",
                'reason': 'SPNs rarely need Owner. Use Contributor or a custom role with least privilege.'
            })
            break

    for r in entra_roles:
        rn = (r.get('role_name') or '').lower()
        if rn == 'global administrator':
            recs.append({
                'priority': 'critical',
                'action': 'Remove Global Administrator from this SPN',
                'reason': 'No SPN should have Global Admin. Use scoped roles instead.'
            })
            break

    activity = identity.get('activity_status', 'unknown')
    if activity in ('stale', 'never_used'):
        recs.append({
            'priority': 'medium',
            'action': 'Investigate and consider decommissioning',
            'reason': f"SPN appears {activity} — may be a leftover from decommissioned workload"
        })

    if identity.get('owner_count', 0) == 0:
        recs.append({
            'priority': 'medium',
            'action': 'Assign an owner for accountability',
            'reason': 'Unowned SPNs create governance blind spots'
        })

    if not recs:
        recs.append({
            'priority': 'info',
            'action': 'No urgent actions required',
            'reason': 'SPN configuration appears reasonable'
        })

    return recs


def _generate_attacker_narrative(identity, roles, credentials, entra_roles):
    """Generate 'What attackers could do' — plain-language threat scenarios."""
    points = []
    name = identity.get('display_name', 'This SPN')

    # Check for subscription-level Owner/UAA
    for r in roles:
        rn = (r.get('role_name') or '').lower()
        scope = r.get('scope') or ''
        if rn == 'owner' and ('subscriptions' in scope and '/resourceGroups/' not in scope):
            points.append(f"Could create new admin accounts and grant themselves persistent access across the entire subscription")
            break
    for r in roles:
        rn = (r.get('role_name') or '').lower()
        if rn == 'user access administrator':
            points.append("Could escalate privileges by assigning Owner role to attacker-controlled identities")
            break

    # Entra admin
    for r in entra_roles:
        rn = (r.get('role_name') or '').lower()
        if rn == 'global administrator':
            points.append("Could take full control of the Entra tenant — reset passwords, create users, modify all settings")
            break
        if rn in ('application administrator', 'cloud application administrator'):
            points.append("Could create backdoor applications with high-privilege API permissions")
            break

    # Key Vault access
    for r in roles:
        rn = (r.get('role_name') or '').lower()
        if 'key vault' in rn and ('admin' in rn or 'officer' in rn or 'owner' in rn.replace('key vault ', '')):
            points.append("Could exfiltrate secrets, certificates, and encryption keys from Key Vaults")
            break

    # Contributor at subscription
    for r in roles:
        rn = (r.get('role_name') or '').lower()
        st = (r.get('scope_type') or '').lower()
        if rn == 'contributor' and st == 'subscription':
            points.append("Could deploy resources (VMs, storage) for cryptomining or data staging")
            break

    # Credential-based attacks
    cred_types = set(c.get('credential_type', '') for c in credentials)
    if 'secret' in cred_types:
        points.append("Client secret could be extracted from code repos, config files, or environment variables")

    if not points:
        points.append("Limited blast radius — no high-privilege attack paths identified")

    return points


def _generate_auditor_questions(identity, roles, credentials, entra_roles):
    """Generate 'What auditors will question' — compliance-focused probes."""
    questions = []
    name = identity.get('display_name', 'This SPN')

    # Overprivileged roles
    high_roles = [r for r in roles if (r.get('role_name') or '').lower() in ('owner', 'contributor', 'user access administrator')
                  and (r.get('scope_type') or '').lower() == 'subscription']
    if high_roles:
        questions.append(f"Why does '{name}' need {high_roles[0]['role_name']} at subscription scope? Is least privilege applied?")

    # Entra admin roles on SPN
    if entra_roles:
        questions.append(f"Why does a service principal have Entra directory roles? Is this justified by business need?")

    # Credential hygiene
    cred_risk = identity.get('credential_risk', 'unknown')
    if cred_risk == 'expired':
        questions.append("Credentials are expired — is this SPN abandoned? Why hasn't it been decommissioned?")
    elif cred_risk == 'expiring_soon':
        questions.append("Credentials are expiring soon — is there a rotation plan in place?")

    now_str = identity.get('created_datetime', '')
    cred_types = set(c.get('credential_type', '') for c in credentials)
    if 'secret' in cred_types and 'federated' not in cred_types:
        questions.append("Why is a client secret used instead of certificate or workload identity federation?")

    # Activity
    activity = identity.get('activity_status', 'unknown')
    if activity == 'unknown':
        questions.append("How do you prove this SPN is still in use? Sign-in telemetry is unavailable.")
    elif activity in ('stale', 'never_used'):
        questions.append(f"Activity is '{activity}' — can you justify continued access for an unused identity?")

    # Ownership
    if identity.get('owner_count', 0) == 0:
        questions.append("Who is responsible for this SPN? No owner is registered — this is a governance gap.")

    if not questions:
        questions.append("No significant compliance concerns identified for this SPN.")

    return questions


def get_spn_stats():
    """GET /api/spns/stats — SPN dashboard summary cards."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({
                'total': 0, 'custom': 0, 'microsoft': 0,
                'critical': 0, 'high_risk': 0,
                'expired_credentials': 0, 'expiring_soon': 0,
                'by_category': {}, 'by_risk': {},
                'by_activity': {}, 'by_blast_radius': {},
            })

        base = "FROM identities i WHERE i.discovery_run_id = %s AND i.identity_category IN %s"
        cats = SPN_CATEGORIES
        params = [run_id, cats]

        # Total + custom vs microsoft
        cursor.execute(f"""
            SELECT COUNT(*) as total,
                   COUNT(*) FILTER (WHERE NOT COALESCE(i.is_microsoft_system, false)) as custom,
                   COUNT(*) FILTER (WHERE COALESCE(i.is_microsoft_system, false)) as microsoft
            {base}
        """, params)
        counts = dict(cursor.fetchone())

        # By risk level
        cursor.execute(f"""
            SELECT COALESCE(i.risk_level, 'info') as rl, COUNT(*) as c
            {base}
            AND NOT COALESCE(i.is_microsoft_system, false)
            GROUP BY rl
        """, params)
        by_risk = {r['rl']: r['c'] for r in cursor.fetchall()}

        # By category
        cursor.execute(f"""
            SELECT i.identity_category as cat, COUNT(*) as c
            {base}
            AND NOT COALESCE(i.is_microsoft_system, false)
            GROUP BY cat
        """, params)
        by_category = {r['cat']: r['c'] for r in cursor.fetchall()}

        # Credential risk
        cursor.execute(f"""
            SELECT
                COUNT(*) FILTER (WHERE i.credential_risk = 'expired') as expired,
                COUNT(*) FILTER (WHERE i.credential_risk = 'expiring_soon') as expiring_soon,
                COUNT(*) FILTER (WHERE i.credential_count = 0 AND i.identity_category = 'service_principal') as no_credentials
            {base}
            AND NOT COALESCE(i.is_microsoft_system, false)
        """, params)
        cred = dict(cursor.fetchone())

        # Activity status breakdown
        cursor.execute(f"""
            SELECT COALESCE(i.activity_status, 'unknown') as act, COUNT(*) as c
            {base}
            AND NOT COALESCE(i.is_microsoft_system, false)
            GROUP BY act
        """, params)
        by_activity = {r['act']: r['c'] for r in cursor.fetchall()}

        # Blast radius — join role_assignments to compute
        cursor.execute("""
            SELECT i.id,
                   ARRAY_AGG(DISTINCT ra.role_name) FILTER (WHERE ra.role_name IS NOT NULL) as role_names,
                   ARRAY_AGG(DISTINCT ra.scope_type) FILTER (WHERE ra.scope_type IS NOT NULL) as scope_types,
                   ARRAY_AGG(DISTINCT ra.scope) FILTER (WHERE ra.scope IS NOT NULL) as scopes
            FROM identities i
            LEFT JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND i.identity_category IN %s
            AND NOT COALESCE(i.is_microsoft_system, false)
            GROUP BY i.id
        """, params)
        blast_counts = {'high': 0, 'medium': 0, 'low': 0, 'none': 0}
        for row in cursor.fetchall():
            roles_list = []
            role_names = row.get('role_names') or []
            scope_types = row.get('scope_types') or []
            scopes = row.get('scopes') or []
            for rn, st, sc in zip(role_names, scope_types, scopes):
                roles_list.append({'role_name': rn, 'scope_type': st, 'scope': sc})
            br = _compute_blast_radius(roles_list)
            blast_counts[br] = blast_counts.get(br, 0) + 1

        cursor.close()

        return jsonify({
            'total': counts['total'],
            'custom': counts['custom'],
            'microsoft': counts['microsoft'],
            'critical': by_risk.get('critical', 0),
            'high_risk': by_risk.get('high', 0),
            'expired_credentials': cred['expired'],
            'expiring_soon': cred['expiring_soon'],
            'no_credentials': cred['no_credentials'],
            'by_risk': by_risk,
            'by_category': by_category,
            'by_activity': by_activity,
            'by_blast_radius': blast_counts,
        })
    finally:
        db.close()


def get_spn_list():
    """GET /api/spns — SPN list with blast radius + critical roles."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        risk_level = request.args.get('risk_level', '')
        category = request.args.get('category', '')
        cred_filter = request.args.get('credential_filter', '')
        blast = request.args.get('blast_radius', '')
        activity = request.args.get('activity', '')
        search_q = request.args.get('search', '')
        hide_ms = request.args.get('hide_microsoft', 'true').lower() == 'true'
        sort_by = request.args.get('sort', 'risk_score')
        sort_dir = request.args.get('dir', 'desc')

        cursor = db.conn.cursor()
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'spns': [], 'count': 0, 'total': 0})

        # Use existing identity list select
        sql = _identity_list_select()
        where = [" WHERE i.discovery_run_id = %s", " AND i.identity_category IN %s"]
        params = [run_id, SPN_CATEGORIES]

        if hide_ms:
            where.append(" AND NOT COALESCE(i.is_microsoft_system, false)")
        if risk_level:
            where.append(" AND i.risk_level = %s")
            params.append(risk_level)
        if category:
            where.append(" AND i.identity_category = %s")
            params.append(category)
        if cred_filter == 'expired':
            where.append(" AND i.credential_risk = 'expired'")
        elif cred_filter == 'expiring_soon':
            where.append(" AND i.credential_risk = 'expiring_soon'")
        elif cred_filter == 'no_credentials':
            where.append(" AND i.credential_count = 0 AND i.identity_category = 'service_principal'")
        if activity:
            where.append(" AND i.activity_status = %s")
            params.append(activity)
        if search_q:
            where.append(" AND (LOWER(i.display_name) LIKE %s OR LOWER(i.app_id) LIKE %s)")
            like = f"%{search_q.lower()}%"
            params.extend([like, like])

        # Count total
        count_sql = f"SELECT COUNT(*) FROM identities i {''.join(where)}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()[0]

        # Sort
        allowed_sorts = {
            'risk_score': 'i.risk_score', 'display_name': 'i.display_name',
            'credential_risk': 'i.credential_risk', 'next_expiry': 'i.next_expiry',
            'activity_status': 'i.activity_status', 'risk_level': 'i.risk_level',
            'created_datetime': 'i.created_datetime',
        }
        order_col = allowed_sorts.get(sort_by, 'i.risk_score')
        order_dir = 'ASC' if sort_dir == 'asc' else 'DESC'
        order_clause = f" ORDER BY {order_col} {order_dir} NULLS LAST"

        full_sql = sql + ''.join(where) + order_clause + " LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cursor.execute(full_sql, params)
        rows = cursor.fetchall()

        # Map base identity data
        spns = [_map_identity_row(r) for r in rows]

        # Enrich with blast_radius and critical_roles for each SPN
        if spns:
            # Get identity IDs → db IDs mapping
            id_list = [s['identity_id'] for s in spns]
            placeholders = ','.join(['%s'] * len(id_list))
            cursor.execute(f"""
                SELECT i.identity_id, i.id FROM identities i
                WHERE i.discovery_run_id = %s AND i.identity_id IN ({placeholders})
            """, [run_id] + id_list)
            id_map = {}
            for row in cursor.fetchall():
                id_map[row[0]] = row[1]

            if id_map:
                db_ids = list(id_map.values())
                db_placeholders = ','.join(['%s'] * len(db_ids))

                # Fetch roles for all SPNs in one query
                cursor.execute(f"""
                    SELECT identity_db_id, role_name, scope_type, scope
                    FROM role_assignments
                    WHERE identity_db_id IN ({db_placeholders})
                """, db_ids)
                roles_by_id = {}
                for row in cursor.fetchall():
                    roles_by_id.setdefault(row[0], []).append({
                        'role_name': row[1], 'scope_type': row[2], 'scope': row[3]
                    })

                # Fetch entra roles
                cursor.execute(f"""
                    SELECT identity_db_id, role_name
                    FROM entra_role_assignments
                    WHERE identity_db_id IN ({db_placeholders})
                """, db_ids)
                entra_by_id = {}
                for row in cursor.fetchall():
                    entra_by_id.setdefault(row[0], []).append({'role_name': row[1]})

                # Enrich each SPN
                for spn in spns:
                    db_id = id_map.get(spn['identity_id'])
                    rbac_roles = roles_by_id.get(db_id, [])
                    entra_roles = entra_by_id.get(db_id, [])
                    all_roles = rbac_roles + [{'role_name': e['role_name'], 'scope_type': 'directory', 'scope': '/'} for e in entra_roles]
                    spn['blast_radius'] = _compute_blast_radius(rbac_roles)
                    spn['critical_roles'] = _extract_critical_roles(all_roles)

        cursor.close()
        return jsonify({'spns': spns, 'count': len(spns), 'total': total})
    finally:
        db.close()


def get_spn_detail(identity_id):
    """GET /api/spns/<identity_id> — Full SPN detail with risk summary + recommendations."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'error': 'No discovery run found'}), 404

        cursor.execute("""
            SELECT * FROM identities
            WHERE discovery_run_id = %s AND identity_id = %s
        """, (run_id, identity_id))
        identity = cursor.fetchone()
        if not identity:
            cursor.close()
            return jsonify({'error': 'SPN not found'}), 404

        db_id = identity['id']

        # Roles
        cursor.execute("SELECT * FROM role_assignments WHERE identity_db_id = %s", (db_id,))
        roles = [dict(r) for r in cursor.fetchall()]

        # Entra roles
        cursor.execute("SELECT * FROM entra_role_assignments WHERE identity_db_id = %s", (db_id,))
        entra_roles = [dict(r) for r in cursor.fetchall()]

        # Credentials
        cursor.execute("SELECT * FROM credentials WHERE identity_db_id = %s ORDER BY end_datetime ASC", (db_id,))
        credentials = [dict(r) for r in cursor.fetchall()]

        # Permissions
        cursor.execute("SELECT * FROM graph_api_permissions WHERE identity_db_id = %s", (db_id,))
        permissions = [dict(r) for r in cursor.fetchall()]

        # Ownership
        cursor.execute("SELECT * FROM sp_ownership WHERE identity_db_id = %s", (db_id,))
        owners = [dict(r) for r in cursor.fetchall()]

        cursor.close()

        # Serialize timestamps
        for lst in [roles, entra_roles, credentials, permissions, owners]:
            for item in lst:
                for k, v in item.items():
                    if hasattr(v, 'isoformat'):
                        item[k] = v.isoformat()

        identity_dict = dict(identity)
        for k, v in identity_dict.items():
            if hasattr(v, 'isoformat'):
                identity_dict[k] = v.isoformat()

        # Compute SPN-specific fields
        rbac_for_blast = [{'role_name': r.get('role_name'), 'scope_type': r.get('scope_type'), 'scope': r.get('scope')} for r in roles]
        all_for_critical = rbac_for_blast + [{'role_name': e.get('role_name'), 'scope_type': 'directory', 'scope': '/'} for e in entra_roles]

        return jsonify({
            'identity': identity_dict,
            'roles': roles,
            'entra_roles': entra_roles,
            'credentials': credentials,
            'permissions': permissions,
            'owners': owners,
            'blast_radius': _compute_blast_radius(rbac_for_blast),
            'critical_roles': _extract_critical_roles(all_for_critical),
            'risk_summary': _generate_risk_summary(identity_dict, roles, credentials, entra_roles),
            'recommendations': _generate_recommendations(identity_dict, roles, credentials, entra_roles),
            'attacker_narrative': _generate_attacker_narrative(identity_dict, roles, credentials, entra_roles),
            'auditor_questions': _generate_auditor_questions(identity_dict, roles, credentials, entra_roles),
        })
    finally:
        db.close()


# ── Phase 72: Data Retention & Archival ───────────────────────────

def get_storage_stats():
    """Return database storage statistics and retention policy info."""
    db = _db()
    try:
        storage = db.get_storage_stats()
        settings = db.get_settings(tenant_id=_tenant_id())

        retention = {
            'enabled': settings.get('retention_enabled', 'false') == 'true',
            'discovery_days': int(settings.get('retention_discovery_days', '90')),
            'drift_days': int(settings.get('retention_drift_days', '90')),
            'activity_days': int(settings.get('retention_activity_days', '180')),
            'anomalies_days': int(settings.get('retention_anomalies_days', '90')),
            'soar_days': int(settings.get('retention_soar_days', '90')),
            'notifications_days': int(settings.get('retention_notifications_days', '90')),
        }

        return jsonify({
            'storage': storage,
            'retention': retention,
        })
    finally:
        db.close()


# ──────────────────────────────────────────────────────────
# App Registration Audit (Phase 74)
# ──────────────────────────────────────────────────────────

def get_app_reg_stats():
    """GET /api/app-registrations/stats — summary cards."""
    db = _db()
    try:
        db._ensure_app_registrations_table()
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({
                'total': 0, 'by_risk': {}, 'ownerless': 0, 'stale': 0,
                'expired_credentials': 0, 'expiring_soon': 0,
                'multi_tenant': 0, 'third_party': 0, 'by_audience': {},
            })

        base = "FROM app_registrations ar WHERE ar.discovery_run_id = %s"
        params = [run_id]

        cursor.execute(f"SELECT COUNT(*) as total {base}", params)
        total = cursor.fetchone()['total']

        # By risk
        cursor.execute(f"""
            SELECT COALESCE(ar.risk_level, 'info') as rl, COUNT(*) as c
            {base} GROUP BY rl
        """, params)
        by_risk = {r['rl']: r['c'] for r in cursor.fetchall()}

        # Ownerless
        cursor.execute(f"SELECT COUNT(*) as c {base} AND ar.owner_count = 0", params)
        ownerless = cursor.fetchone()['c']

        # Stale (has SPN but SPN is stale/never_used)
        cursor.execute(f"""
            SELECT COUNT(*) as c {base}
            AND ar.has_service_principal = true
            AND ar.spn_activity_status IN ('stale', 'never_used', 'inactive')
        """, params)
        stale = cursor.fetchone()['c']

        # Also count apps with no SPN at all as potentially stale
        cursor.execute(f"SELECT COUNT(*) as c {base} AND ar.has_service_principal = false", params)
        no_spn = cursor.fetchone()['c']

        # Credentials
        cursor.execute(f"""
            SELECT
                COUNT(*) FILTER (WHERE ar.has_expired_credential = true) as expired,
                COUNT(*) FILTER (WHERE ar.has_expiring_soon = true) as expiring_soon
            {base}
        """, params)
        cred_row = dict(cursor.fetchone())

        # Multi-tenant
        cursor.execute(f"""
            SELECT COUNT(*) as c {base}
            AND ar.sign_in_audience IN ('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount')
        """, params)
        multi_tenant = cursor.fetchone()['c']

        # Third-party
        cursor.execute(f"SELECT COUNT(*) as c {base} AND ar.is_third_party = true", params)
        third_party = cursor.fetchone()['c']

        # By audience
        cursor.execute(f"""
            SELECT COALESCE(ar.sign_in_audience, 'Unknown') as aud, COUNT(*) as c
            {base} GROUP BY aud
        """, params)
        by_audience = {r['aud']: r['c'] for r in cursor.fetchall()}

        cursor.close()
        return jsonify({
            'total': total,
            'by_risk': by_risk,
            'ownerless': ownerless,
            'stale': stale,
            'no_spn': no_spn,
            'expired_credentials': cred_row['expired'],
            'expiring_soon': cred_row['expiring_soon'],
            'multi_tenant': multi_tenant,
            'third_party': third_party,
            'by_audience': by_audience,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


def get_app_reg_list():
    """GET /api/app-registrations — paginated list with filters."""
    db = _db()
    try:
        db._ensure_app_registrations_table()
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'items': [], 'total': 0})

        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))
        risk_filter = request.args.get('risk_level', '')
        cred_filter = request.args.get('credential_status', '')
        audience_filter = request.args.get('audience', '')
        search = request.args.get('search', '').strip()
        hide_microsoft = request.args.get('hide_microsoft', 'true').lower() == 'true'
        sort_field = request.args.get('sort', 'risk_score')
        sort_dir = request.args.get('dir', 'desc')

        where = ["ar.discovery_run_id = %s"]
        params: list = [run_id]

        if hide_microsoft:
            where.append("ar.is_third_party = false")
            where.append("ar.app_owner_organization_id != ''")

        if risk_filter:
            where.append("ar.risk_level = %s")
            params.append(risk_filter)
        if cred_filter == 'expired':
            where.append("ar.has_expired_credential = true")
        elif cred_filter == 'expiring':
            where.append("ar.has_expiring_soon = true")
        elif cred_filter == 'healthy':
            where.append("ar.has_expired_credential = false AND ar.has_expiring_soon = false")
        if audience_filter:
            where.append("ar.sign_in_audience = %s")
            params.append(audience_filter)
        if search:
            where.append("ar.display_name ILIKE %s")
            params.append(f'%{search}%')

        where_sql = " AND ".join(where)

        ALLOWED_SORT = {
            'risk_score': 'ar.risk_score',
            'display_name': 'ar.display_name',
            'permission_count': 'ar.permission_count',
            'owner_count': 'ar.owner_count',
            'next_expiry': 'ar.next_expiry',
            'created_datetime': 'ar.created_datetime',
            'application_permission_count': 'ar.application_permission_count',
        }
        order_col = ALLOWED_SORT.get(sort_field, 'ar.risk_score')
        order_dir = 'ASC' if sort_dir.lower() == 'asc' else 'DESC'

        cursor.execute(f"SELECT COUNT(*) as total FROM app_registrations ar WHERE {where_sql}", params)
        total = cursor.fetchone()['total']

        cursor.execute(f"""
            SELECT ar.id, ar.app_id, ar.app_object_id, ar.display_name,
                   ar.risk_level, ar.risk_score,
                   ar.permission_count, ar.application_permission_count,
                   ar.delegated_permission_count, ar.high_risk_permissions,
                   ar.secret_count, ar.certificate_count,
                   ar.next_expiry, ar.has_expired_credential, ar.has_expiring_soon,
                   ar.owner_count, ar.primary_owner,
                   ar.sign_in_audience, ar.is_third_party,
                   ar.has_service_principal, ar.spn_activity_status,
                   ar.created_datetime
            FROM app_registrations ar
            WHERE {where_sql}
            ORDER BY {order_col} {order_dir} NULLS LAST
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        items = [dict(r) for r in cursor.fetchall()]

        # Serialize datetimes
        for item in items:
            for k in ('next_expiry', 'created_datetime'):
                if item.get(k) and hasattr(item[k], 'isoformat'):
                    item[k] = item[k].isoformat()

        cursor.close()
        return jsonify({'items': items, 'total': total})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


def get_app_reg_detail(app_id):
    """GET /api/app-registrations/<app_id> — full detail."""
    db = _db()
    try:
        db._ensure_app_registrations_table()
        tenant_id = _tenant_id()
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        run_id = _latest_run_query(cursor, tenant_id)
        if not run_id:
            cursor.close()
            return jsonify({'error': 'No discovery run'}), 404

        cursor.execute("""
            SELECT * FROM app_registrations ar
            WHERE ar.discovery_run_id = %s AND ar.app_id = %s
        """, (run_id, app_id))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            return jsonify({'error': 'App registration not found'}), 404

        data = dict(row)

        # Serialize datetimes
        for k in ('next_expiry', 'created_datetime', 'spn_last_sign_in', 'created_at'):
            if data.get(k) and hasattr(data[k], 'isoformat'):
                data[k] = data[k].isoformat()

        # Linked SPN info
        linked_spn = None
        if data.get('linked_spn_id'):
            cursor.execute("""
                SELECT id, display_name, identity_category, risk_level, activity_status
                FROM identities WHERE id = %s
            """, (data['linked_spn_id'],))
            spn_row = cursor.fetchone()
            if spn_row:
                linked_spn = dict(spn_row)

        # Generate recommendations
        recommendations = []
        if data.get('owner_count', 0) == 0:
            recommendations.append({
                'priority': 'critical',
                'action': 'Assign an owner to this application',
                'reason': 'Ownerless apps have no accountability for credential rotation or access review.',
            })
        if data.get('has_expired_credential'):
            recommendations.append({
                'priority': 'high',
                'action': 'Remove or rotate expired credentials',
                'reason': 'Expired credentials indicate abandoned lifecycle management.',
            })
        if data.get('has_expiring_soon'):
            recommendations.append({
                'priority': 'high',
                'action': 'Rotate credentials before expiry',
                'reason': 'Credentials expiring soon may cause service disruption.',
            })
        if data.get('application_permission_count', 0) > 5:
            recommendations.append({
                'priority': 'high',
                'action': 'Review and reduce Application-level permissions',
                'reason': f'{data["application_permission_count"]} Application permissions is excessive — apply least-privilege.',
            })
        high_risk_perms = data.get('high_risk_permissions') or []
        if high_risk_perms:
            recommendations.append({
                'priority': 'critical',
                'action': 'Audit high-risk permissions',
                'reason': f'Dangerous permissions: {", ".join(high_risk_perms[:3])}',
            })
        audience = data.get('sign_in_audience', '')
        if audience in ('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount'):
            recommendations.append({
                'priority': 'medium',
                'action': 'Restrict audience to single tenant if possible',
                'reason': 'Multi-tenant apps expand blast radius across organizations.',
            })
        if data.get('has_localhost_redirect'):
            recommendations.append({
                'priority': 'medium',
                'action': 'Remove localhost redirect URIs',
                'reason': 'Localhost URIs suggest dev/test configuration left in production.',
            })
        if data.get('has_http_redirect'):
            recommendations.append({
                'priority': 'medium',
                'action': 'Upgrade redirect URIs to HTTPS',
                'reason': 'Non-HTTPS redirect URIs expose tokens to interception.',
            })
        if not data.get('has_service_principal'):
            recommendations.append({
                'priority': 'info',
                'action': 'Verify if this app registration is still needed',
                'reason': 'No Service Principal means this app has never been consented or used.',
            })

        cursor.close()
        return jsonify({
            'app_registration': data,
            'linked_spn': linked_spn,
            'recommendations': recommendations,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


def run_manual_cleanup():
    """Trigger a manual data cleanup using retention settings."""
    db = _db()
    try:
        settings = db.get_settings(tenant_id=_tenant_id())
        results = {}

        discovery_days = int(settings.get('retention_discovery_days', '90'))
        drift_days = int(settings.get('retention_drift_days', '90'))
        activity_days = int(settings.get('retention_activity_days', '180'))
        anomalies_days = int(settings.get('retention_anomalies_days', '90'))
        soar_days = int(settings.get('retention_soar_days', '90'))
        notif_days = int(settings.get('retention_notifications_days', '90'))

        run_counts = db.cleanup_old_discovery_runs(days=discovery_days)
        results['discovery_runs'] = run_counts.get('discovery_runs', 0)
        results['risk_scores'] = run_counts.get('risk_scores', 0)
        results['drift_reports'] = db.cleanup_old_drift_reports(days=drift_days)
        results['activity_log'] = db.cleanup_old_activity_log(days=activity_days)
        results['anomalies'] = db.cleanup_old_anomalies(days=anomalies_days)
        results['soar_actions'] = db.cleanup_old_soar_actions(days=soar_days)
        results['notifications'] = db.cleanup_old_notifications(days=notif_days)

        total = sum(results.values())
        _log(db, 'data_cleanup', f'Manual cleanup: {total} records deleted', {
            'results': results,
            'retention_settings': {
                'discovery_days': discovery_days,
                'drift_days': drift_days,
                'activity_days': activity_days,
                'anomalies_days': anomalies_days,
                'soar_days': soar_days,
                'notifications_days': notif_days,
            }
        })

        return jsonify({
            'deleted': results,
            'total': total,
        })
    finally:
        db.close()


# ============================================================
# Phase 78: Tenant Logo Upload/Delete
# ============================================================

def upload_tenant_logo(tenant_id):
    """POST /api/tenants/<id>/logo — Upload tenant logo (base64, max 500KB). Superadmin/poweradmin only."""
    data = request.get_json(silent=True) or {}
    logo_data = data.get('logo_data', '')
    content_type = str(data.get('content_type', '')).lower()

    if not logo_data:
        return jsonify({'error': 'logo_data is required (base64-encoded)'}), 400

    valid_types = {'image/png', 'image/jpeg', 'image/svg+xml'}
    if content_type not in valid_types:
        return jsonify({'error': f'Invalid content_type. Must be one of: {", ".join(valid_types)}'}), 400

    # Check size (base64 is ~33% larger than binary, so 500KB binary ≈ 667KB base64)
    import base64
    try:
        raw = base64.b64decode(logo_data)
    except Exception:
        return jsonify({'error': 'Invalid base64 data'}), 400

    if len(raw) > 500 * 1024:
        return jsonify({'error': 'Logo must be under 500KB'}), 400

    logo_url = f'data:{content_type};base64,{logo_data}'

    db = _db()
    try:
        tenant = db.get_tenant_by_id(tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404

        cursor = db.conn.cursor()
        cursor.execute("UPDATE tenants SET logo_url = %s, updated_at = NOW() WHERE id = %s", (logo_url, tenant_id))
        db.conn.commit()
        cursor.close()

        _log(db, 'tenant_logo_uploaded', f'Logo uploaded for tenant "{tenant["name"]}"',
             {'tenant_id': tenant_id})

        return jsonify({'message': 'Logo uploaded', 'logo_url': logo_url})
    finally:
        db.close()


def delete_tenant_logo(tenant_id):
    """DELETE /api/tenants/<id>/logo — Remove tenant logo. Superadmin/poweradmin only."""
    db = _db()
    try:
        tenant = db.get_tenant_by_id(tenant_id)
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 404

        cursor = db.conn.cursor()
        cursor.execute("UPDATE tenants SET logo_url = NULL, updated_at = NOW() WHERE id = %s", (tenant_id,))
        db.conn.commit()
        cursor.close()

        _log(db, 'tenant_logo_deleted', f'Logo removed for tenant "{tenant["name"]}"',
             {'tenant_id': tenant_id})

        return jsonify({'message': 'Logo removed'})
    finally:
        db.close()


# ============================================================
# Phase 78: Scan Modes
# ============================================================

SCAN_MODES = {
    'quick': {
        'label': 'Quick Scan',
        'description': 'Identities only — fastest, ideal for daily monitoring',
        'includes': ['identities'],
        'estimated_minutes': 2,
    },
    'standard': {
        'label': 'Standard Scan',
        'description': 'Identities + roles + credentials — recommended default',
        'includes': ['identities', 'roles', 'credentials'],
        'estimated_minutes': 10,
    },
    'deep': {
        'label': 'Deep Audit',
        'description': 'Full audit: identities, roles, credentials, PIM, CA, resources, app registrations',
        'includes': ['identities', 'roles', 'credentials', 'pim', 'conditional_access', 'resources', 'app_registrations'],
        'estimated_minutes': 30,
    },
}


def get_scan_modes():
    """GET /api/scan-modes — Return available scan mode definitions."""
    return jsonify({'scan_modes': SCAN_MODES})


# ============================================================
# Phase 78: Tier Limits
# ============================================================

TIER_LIMITS = {
    'free': {'max_identities': 50, 'blocked_features': ['soar', 'api_keys', 'advanced_query', 'custom_risk_rules']},
    'trial': {'max_identities': 500, 'trial_days': 14, 'blocked_features': []},
    'pro': {'max_identities': None, 'blocked_features': []},
    'enterprise': {'max_identities': None, 'blocked_features': []},
}


def _check_tier_limits(db, tenant_id):
    """Check if tenant is within tier limits. Returns (ok, error_dict) tuple."""
    tenant = db.get_tenant_by_id(tenant_id)
    if not tenant:
        return True, None

    plan = tenant.get('plan', 'free')
    limits = TIER_LIMITS.get(plan, TIER_LIMITS['free'])

    # Check identity count limit
    if limits.get('max_identities'):
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE dr.tenant_id = %s AND i.discovery_run_id = (
                SELECT id FROM discovery_runs WHERE tenant_id = %s ORDER BY id DESC LIMIT 1
            )
        """, (tenant_id, tenant_id))
        count = cursor.fetchone()[0]
        cursor.close()
        if count >= limits['max_identities']:
            return False, {
                'error': f'{plan.capitalize()} plan is limited to {limits["max_identities"]} identities. Current: {count}.',
                'upgrade_required': True,
                'current_plan': plan,
            }

    # Check trial expiry
    if plan == 'trial' and tenant.get('license_activated_at'):
        from datetime import timedelta
        activated = tenant['license_activated_at']
        if isinstance(activated, str):
            activated = datetime.fromisoformat(activated.replace('Z', '+00:00'))
        if datetime.now(activated.tzinfo if activated.tzinfo else None) > activated + timedelta(days=14):
            return False, {
                'error': 'Trial period has expired. Please upgrade to continue.',
                'upgrade_required': True,
                'current_plan': plan,
            }

    return True, None


# ── Phase 79: AI Security Copilot ──────────────────────────────

def copilot_chat():
    """POST /api/copilot/chat — send a message to the AI copilot."""
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    conversation_id = data.get('conversation_id')

    if not message:
        return jsonify({'error': 'Message is required'}), 400

    db = _db()
    try:
        api_key = db.get_setting('copilot_api_key', '')
        if not api_key:
            return jsonify({
                'error': 'not_configured',
                'response': 'Configure your Anthropic API key in Settings to use the Security Copilot.',
                'conversation_id': None,
                'suggestions': [],
            })

        user_id = _current_user_id()
        tenant_id = _tenant_id()

        # Load or create conversation
        conv = None
        messages_history = []
        if conversation_id:
            conv = db.get_copilot_conversation(conversation_id, user_id)
            if conv:
                messages_history = conv.get('messages', [])

        from app.services.copilot_service import CopilotService
        service = CopilotService(api_key)

        try:
            response_text = service.ask(message, messages_history, db)
        except Exception as e:
            return jsonify({'error': f'AI service error: {str(e)}'}), 502

        # Save conversation
        messages_history.append({'role': 'user', 'content': message})
        messages_history.append({'role': 'assistant', 'content': response_text})

        if conv:
            db.update_copilot_conversation(conversation_id, user_id, messages_history)
        else:
            title = message[:60] + ('...' if len(message) > 60 else '')
            conv = db.create_copilot_conversation(user_id, tenant_id, title, messages_history)
            conversation_id = conv['id']

        suggestions = service.get_suggestions(db)

        return jsonify({
            'response': response_text,
            'conversation_id': conversation_id,
            'suggestions': suggestions,
        })
    finally:
        db.close()


def copilot_conversations_list():
    """GET /api/copilot/conversations — list user's conversations."""
    db = _db()
    try:
        user_id = _current_user_id()
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        convs = db.list_copilot_conversations(user_id, limit, offset)
        return jsonify({'conversations': convs})
    finally:
        db.close()


def copilot_suggestions():
    """GET /api/copilot/suggestions — contextual quick-ask chips."""
    db = _db()
    try:
        api_key = db.get_setting('copilot_api_key', '')
        if not api_key:
            return jsonify({'suggestions': [], 'configured': False})

        from app.services.copilot_service import CopilotService
        service = CopilotService(api_key)
        suggestions = service.get_suggestions(db)
        return jsonify({'suggestions': suggestions, 'configured': True})
    finally:
        db.close()


# ── Identity Dashboard V2: Exposure Graph ──────────────────────

def get_exposure_graph():
    """POST /api/identities/exposure-graph — build exposure graph for up to 50 identities."""
    data = request.get_json() or {}
    identity_ids = data.get('identity_ids', [])
    preset = data.get('preset')

    if not identity_ids and not preset:
        return jsonify({"error": "identity_ids or preset required"}), 400

    db = _db()
    cursor = db.conn.cursor()
    tid = _tenant_id()

    try:
        # If preset, fetch matching identity_ids
        if preset and not identity_ids:
            preset_filters = {
                'privileged': "AND i.privilege_tier = 0",
                'external': "AND i.identity_category = 'guest'",
                'non_human': "AND i.identity_category IN ('service_principal','managed_identity_system','managed_identity_user')",
                'zombie': "AND i.activity_status IN ('stale','never_used')",
                'secret_risk': "AND i.credential_status IN ('expired','expiring_soon')",
            }
            where = preset_filters.get(preset, '')
            cursor.execute(f"""
                SELECT i.identity_id FROM identities i
                JOIN discovery_runs dr ON dr.id = i.discovery_run_id
                WHERE dr.tenant_id = %s {where}
                ORDER BY i.risk_score DESC LIMIT 50
            """, (tid,))
            identity_ids = [r[0] for r in cursor.fetchall()]

        if not identity_ids:
            return jsonify({"nodes": [], "edges": []})

        # Cap at 50
        identity_ids = identity_ids[:50]

        nodes = []
        edges = []
        seen_roles = set()
        seen_scopes = set()

        for idx, iid in enumerate(identity_ids):
            cursor.execute("""
                SELECT i.id, i.identity_id, i.display_name, i.risk_level, i.risk_score,
                       i.identity_category, i.activity_status
                FROM identities i
                JOIN discovery_runs dr ON dr.id = i.discovery_run_id
                WHERE i.identity_id = %s AND dr.tenant_id = %s
                ORDER BY i.discovery_run_id DESC LIMIT 1
            """, (iid, tid))
            row = cursor.fetchone()
            if not row:
                continue

            db_id, identity_id, display_name, risk_level, risk_score, category, activity = row
            node_id = f"id_{identity_id}"

            # Identity node (left column)
            nodes.append({
                "id": node_id,
                "type": "identity",
                "position": {"x": 50, "y": idx * 100},
                "data": {
                    "label": display_name,
                    "risk_level": risk_level or 'info',
                    "risk_score": risk_score or 0,
                    "category": category,
                    "identity_id": identity_id,
                },
            })

            # Get role assignments
            cursor.execute("""
                SELECT role_name, scope_type, scope
                FROM role_assignments WHERE identity_db_id = %s
            """, (db_id,))
            for rn, st, sc in cursor.fetchall():
                role_key = rn
                if role_key not in seen_roles:
                    seen_roles.add(role_key)
                    nodes.append({
                        "id": f"role_{role_key}",
                        "type": "role",
                        "position": {"x": 400, "y": len(seen_roles) * 60},
                        "data": {"label": rn, "role_type": "azure"},
                    })
                edges.append({
                    "id": f"e_{node_id}_{role_key}",
                    "source": node_id,
                    "target": f"role_{role_key}",
                    "label": st or '',
                    "style": {"stroke": "#6366f1"},
                })

                # Scope node
                scope_key = st or 'unknown'
                if scope_key not in seen_scopes:
                    seen_scopes.add(scope_key)
                    nodes.append({
                        "id": f"scope_{scope_key}",
                        "type": "scope",
                        "position": {"x": 750, "y": len(seen_scopes) * 60},
                        "data": {"label": scope_key.replace('_', ' ').title()},
                    })
                edges.append({
                    "id": f"e_role_{role_key}_{scope_key}",
                    "source": f"role_{role_key}",
                    "target": f"scope_{scope_key}",
                    "style": {"stroke": "#94a3b8"},
                })

            # Entra roles
            cursor.execute("""
                SELECT role_name FROM entra_role_assignments WHERE identity_db_id = %s
            """, (db_id,))
            for (rn,) in cursor.fetchall():
                role_key = f"entra_{rn}"
                if role_key not in seen_roles:
                    seen_roles.add(role_key)
                    nodes.append({
                        "id": f"role_{role_key}",
                        "type": "role",
                        "position": {"x": 400, "y": len(seen_roles) * 60},
                        "data": {"label": rn, "role_type": "entra"},
                    })
                edges.append({
                    "id": f"e_{node_id}_{role_key}",
                    "source": node_id,
                    "target": f"role_{role_key}",
                    "label": "entra",
                    "style": {"stroke": "#8b5cf6"},
                })

        return jsonify({"nodes": nodes, "edges": edges, "total_identities": len(identity_ids)})
    finally:
        cursor.close()


# ── Identity Dashboard V2: Usage Intelligence ─────────────────

def get_identity_usage(identity_id):
    """GET /api/identities/<id>/usage — usage intelligence with confidence indicator."""
    db = _db()
    cursor = db.conn.cursor()
    try:
        # Get identity with activity + credential data
        cursor.execute("""
            SELECT i.id, i.activity_status, i.last_seen_auth, i.last_sign_in,
                   i.credential_count, i.credential_status, i.credential_expiration
            FROM identities i
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE i.identity_id = %s AND dr.tenant_id = %s
            ORDER BY i.discovery_run_id DESC LIMIT 1
        """, (identity_id, _tenant_id()))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Identity not found"}), 404

        identity_db_id = row[0]
        activity_status = row[1] or 'unknown'
        last_seen_auth = row[2]
        last_sign_in = row[3]
        last_used = last_seen_auth or last_sign_in

        # Confidence
        confidence = 'low'
        usage_source = 'none'
        if last_used:
            from datetime import datetime, timezone
            try:
                if isinstance(last_used, str):
                    last_dt = datetime.fromisoformat(last_used.replace('Z', '+00:00'))
                else:
                    last_dt = last_used if last_used.tzinfo else last_used.replace(tzinfo=timezone.utc)
                days = (datetime.now(timezone.utc) - last_dt).days
                if days < 90:
                    confidence = 'high'
                    usage_source = 'sign_in_logs'
                else:
                    confidence = 'medium'
                    usage_source = 'sign_in_logs'
            except:
                confidence = 'low'
                usage_source = 'inferred'
        else:
            confidence = 'low'
            usage_source = 'none'

        # Granted vs used: check role usage_status
        cursor.execute("""
            SELECT role_name, 'azure' as role_type, scope_type,
                   COALESCE(usage_status, 'unknown') as usage_status
            FROM role_assignments WHERE identity_db_id = %s
            UNION ALL
            SELECT role_name, 'entra' as role_type, 'directory' as scope_type,
                   COALESCE(usage_status, 'unknown') as usage_status
            FROM entra_role_assignments WHERE identity_db_id = %s
        """, (identity_db_id, identity_db_id))
        all_roles = cursor.fetchall()

        total_roles = len(all_roles)
        definitely_unused = [r for r in all_roles if r[3] == 'definitely_unused']
        used_roles = total_roles - len(definitely_unused)

        # Permissions count
        cursor.execute("SELECT COUNT(*) FROM graph_api_permissions WHERE identity_db_id = %s", (identity_db_id,))
        perm_count = cursor.fetchone()[0] or 0

        return jsonify({
            "identity_id": identity_id,
            "last_used": last_used.isoformat() if hasattr(last_used, 'isoformat') else last_used,
            "usage_source": usage_source,
            "confidence": confidence,
            "activity_status": activity_status,
            "granted_vs_used": {
                "total_roles": total_roles,
                "used_roles": used_roles,
                "never_used_count": len(definitely_unused),
                "never_used_roles": [
                    {"role_name": r[0], "role_type": r[1], "scope_type": r[2]}
                    for r in definitely_unused[:20]
                ],
                "total_permissions": perm_count,
            },
        })
    finally:
        cursor.close()


# ── Phase 80: Identity Timeline / Forensic View ───────────────

def get_identity_timeline(identity_id):
    """GET /api/identities/<id>/timeline — aggregated chronological event feed."""
    db = _db()
    try:
        cursor = db.conn.cursor()
        tid = _tenant_id()

        # Resolve identity DB id
        if tid:
            cursor.execute("""
                SELECT i.id FROM identities i
                JOIN discovery_runs r ON i.discovery_run_id = r.id
                WHERE i.identity_id = %s AND r.tenant_id = %s
                ORDER BY i.discovery_run_id DESC LIMIT 1
            """, (identity_id, tid))
        else:
            cursor.execute("""
                SELECT id FROM identities
                WHERE identity_id = %s ORDER BY discovery_run_id DESC LIMIT 1
            """, (identity_id,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            return jsonify({'events': [], 'total': 0})
        db_id = row[0]

        # Parse filters
        event_types = request.args.get('event_types', '')
        event_types = [t.strip() for t in event_types.split(',') if t.strip()] if event_types else None
        from_date = request.args.get('from')
        to_date = request.args.get('to')
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        events = []

        # 1. Anomalies
        if not event_types or 'anomaly' in event_types:
            try:
                cursor.execute("""
                    SELECT created_at, severity, title, description, type, details
                    FROM anomalies WHERE identity_id = %s ORDER BY created_at DESC LIMIT 50
                """, (identity_id,))
                for r in cursor.fetchall():
                    events.append({
                        'timestamp': r[0].isoformat() if r[0] else None,
                        'event_type': 'anomaly',
                        'severity': r[1],
                        'title': r[2],
                        'description': r[3],
                        'metadata': {'anomaly_type': r[4], 'details': r[5]},
                    })
            except Exception:
                db.conn.rollback()

        # 2. Risk score changes
        if not event_types or 'risk_change' in event_types:
            try:
                cursor.execute("""
                    SELECT recorded_at, risk_score, risk_level
                    FROM risk_scores WHERE identity_id = %s ORDER BY recorded_at DESC LIMIT 50
                """, (identity_id,))
                for r in cursor.fetchall():
                    events.append({
                        'timestamp': r[0].isoformat() if r[0] else None,
                        'event_type': 'risk_change',
                        'severity': r[2] if r[2] in ('critical', 'high') else 'info',
                        'title': f'Risk score: {r[1]}',
                        'description': f'Risk level changed to {r[2]}',
                        'metadata': {'risk_score': r[1], 'risk_level': r[2]},
                    })
            except Exception:
                db.conn.rollback()

        # 3. PIM activations
        if not event_types or 'pim_activation' in event_types:
            try:
                cursor.execute("""
                    SELECT activated_at, role_name, status, justification
                    FROM pim_activations WHERE identity_db_id = %s ORDER BY activated_at DESC LIMIT 50
                """, (db_id,))
                for r in cursor.fetchall():
                    events.append({
                        'timestamp': r[0].isoformat() if r[0] else None,
                        'event_type': 'pim_activation',
                        'severity': 'medium',
                        'title': f'PIM activation: {r[1]}',
                        'description': f'Status: {r[2]}. Justification: {r[3] or "N/A"}',
                        'metadata': {'role_name': r[1], 'status': r[2]},
                    })
            except Exception:
                db.conn.rollback()

        # 4. SOAR actions
        if not event_types or 'soar_action' in event_types:
            try:
                cursor.execute("""
                    SELECT executed_at, action_type, status, result
                    FROM soar_actions WHERE identity_id = %s ORDER BY executed_at DESC LIMIT 50
                """, (identity_id,))
                for r in cursor.fetchall():
                    events.append({
                        'timestamp': r[0].isoformat() if r[0] else None,
                        'event_type': 'soar_action',
                        'severity': 'info',
                        'title': f'SOAR action: {r[1]}',
                        'description': f'Status: {r[2]}',
                        'metadata': {'action_type': r[1], 'status': r[2], 'result': r[3]},
                    })
            except Exception:
                db.conn.rollback()

        # 5. Remediation actions
        if not event_types or 'remediation' in event_types:
            try:
                cursor.execute("""
                    SELECT created_at, action_type, status, notes
                    FROM remediation_actions WHERE identity_id = %s ORDER BY created_at DESC LIMIT 50
                """, (identity_id,))
                for r in cursor.fetchall():
                    events.append({
                        'timestamp': r[0].isoformat() if r[0] else None,
                        'event_type': 'remediation',
                        'severity': 'info',
                        'title': f'Remediation: {r[1]}',
                        'description': f'Status: {r[2]}. {r[3] or ""}',
                        'metadata': {'action_type': r[1], 'status': r[2]},
                    })
            except Exception:
                db.conn.rollback()

        cursor.close()

        # Apply date filters
        if from_date:
            events = [e for e in events if e['timestamp'] and e['timestamp'] >= from_date]
        if to_date:
            events = [e for e in events if e['timestamp'] and e['timestamp'] <= to_date]

        # Sort by timestamp DESC
        events.sort(key=lambda e: e['timestamp'] or '', reverse=True)
        total = len(events)
        events = events[offset:offset + limit]

        return jsonify({'events': events, 'total': total})
    finally:
        db.close()


# ── Phase 81: Attack Path Analysis ─────────────────────────────

DANGEROUS_PERMISSIONS = {
    'RoleManagement.ReadWrite.All', 'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All',
    'GroupMember.ReadWrite.All', 'ServicePrincipalEndpoint.ReadWrite.All',
}

DANGEROUS_ROLES = {
    'Global Administrator', 'Privileged Role Administrator',
    'Application Administrator', 'Cloud Application Administrator',
    'User Administrator', 'Exchange Administrator',
}

def get_identity_attack_paths(identity_id):
    """GET /api/identities/<id>/attack-paths — compute privilege escalation chains."""
    db = _db()
    try:
        cursor = db.conn.cursor()
        tid = _tenant_id()

        # Resolve identity
        if tid:
            cursor.execute("""
                SELECT i.id, i.display_name, i.risk_level, i.risk_score,
                       i.identity_category, i.object_id, i.app_id
                FROM identities i
                JOIN discovery_runs r ON i.discovery_run_id = r.id
                WHERE i.identity_id = %s AND r.tenant_id = %s
                ORDER BY i.discovery_run_id DESC LIMIT 1
            """, (identity_id, tid))
        else:
            cursor.execute("""
                SELECT id, display_name, risk_level, risk_score,
                       identity_category, object_id, app_id
                FROM identities
                WHERE identity_id = %s ORDER BY discovery_run_id DESC LIMIT 1
            """, (identity_id,))
        ident = cursor.fetchone()
        if not ident:
            cursor.close()
            return jsonify({'paths': [], 'summary': {'total_paths': 0, 'critical_paths': 0, 'max_blast_radius': 'none'}})

        db_id, display_name = ident[0], ident[1]
        paths = []

        # 1. Direct escalation: dangerous Graph API permissions
        try:
            cursor.execute("""
                SELECT permission_name, permission_type
                FROM graph_api_permissions
                WHERE identity_db_id = %s AND permission_name = ANY(%s)
            """, (db_id, list(DANGEROUS_PERMISSIONS)))
            dangerous_perms = cursor.fetchall()
            for p in dangerous_perms:
                paths.append({
                    'type': 'direct_escalation',
                    'risk_level': 'critical',
                    'steps': [
                        {'node_type': 'identity', 'node_id': identity_id, 'node_label': display_name, 'description': 'Starting identity'},
                        {'node_type': 'permission', 'node_id': p[0], 'node_label': p[0], 'description': f'{p[1]} permission grants write access'},
                        {'node_type': 'target', 'node_id': 'tenant', 'node_label': 'Tenant-Wide Control', 'description': 'Can escalate to full tenant admin'},
                    ],
                    'impact': f'Direct privilege escalation via {p[0]}',
                    'narrative': f'This identity holds the {p[0]} ({p[1]}) permission, which allows direct escalation to tenant-wide administrative control without any intermediate steps.',
                })
        except Exception:
            db.conn.rollback()

        # 2. Dangerous Entra roles
        try:
            cursor.execute("""
                SELECT role_name, directory_scope
                FROM entra_role_assignments
                WHERE identity_db_id = %s AND role_name = ANY(%s)
            """, (db_id, list(DANGEROUS_ROLES)))
            dangerous_roles = cursor.fetchall()
            for r in dangerous_roles:
                paths.append({
                    'type': 'direct_escalation',
                    'risk_level': 'critical',
                    'steps': [
                        {'node_type': 'identity', 'node_id': identity_id, 'node_label': display_name, 'description': 'Starting identity'},
                        {'node_type': 'role', 'node_id': r[0], 'node_label': r[0], 'description': f'Entra directory role at scope: {r[1] or "/"}'},
                        {'node_type': 'target', 'node_id': 'directory', 'node_label': 'Full Directory Control', 'description': 'Administrative control over all directory objects'},
                    ],
                    'impact': f'{r[0]} grants full directory control',
                    'narrative': f'The {r[0]} role provides administrative authority over the entire Entra ID directory. A compromised identity with this role can create, modify, or delete any directory object.',
                })
        except Exception:
            db.conn.rollback()

        # 3. Ownership chain: identity owns SPNs with privileged roles
        try:
            cursor.execute("""
                SELECT DISTINCT o.identity_id as owned_id, i2.display_name as owned_name, i2.id as owned_db_id
                FROM sp_ownership o
                JOIN identities i2 ON i2.identity_id = o.identity_id AND i2.discovery_run_id = (
                    SELECT MAX(discovery_run_id) FROM identities WHERE identity_id = o.identity_id
                )
                WHERE o.owner_object_id = %s
            """, (ident[5] or ident[6],))  # object_id or app_id
            owned_spns = cursor.fetchall()
            for owned in owned_spns:
                cursor.execute("""
                    SELECT role_name FROM entra_role_assignments
                    WHERE identity_db_id = %s AND role_name = ANY(%s)
                """, (owned[2], list(DANGEROUS_ROLES)))
                priv_roles = cursor.fetchall()
                if priv_roles:
                    paths.append({
                        'type': 'ownership_chain',
                        'risk_level': 'high',
                        'steps': [
                            {'node_type': 'identity', 'node_id': identity_id, 'node_label': display_name, 'description': 'Starting identity (owner)'},
                            {'node_type': 'owned_spn', 'node_id': owned[0], 'node_label': owned[1], 'description': 'Owned service principal'},
                            {'node_type': 'role', 'node_id': priv_roles[0][0], 'node_label': priv_roles[0][0], 'description': 'Privileged role on owned SPN'},
                            {'node_type': 'target', 'node_id': 'directory', 'node_label': 'Directory Control', 'description': 'Escalate via owned SPN credentials'},
                        ],
                        'impact': f'Ownership of {owned[1]} provides indirect {priv_roles[0][0]} access',
                        'narrative': f'This identity owns {owned[1]}, which holds the {priv_roles[0][0]} role. An attacker could create new credentials on the owned SPN and use them to exercise its privileged role.',
                    })
        except Exception:
            db.conn.rollback()

        # 4. PIM abuse: eligible for dangerous roles
        try:
            cursor.execute("""
                SELECT role_name FROM pim_eligible_assignments
                WHERE identity_db_id = %s AND role_name = ANY(%s)
            """, (db_id, list(DANGEROUS_ROLES)))
            pim_roles = cursor.fetchall()
            for pr in pim_roles:
                paths.append({
                    'type': 'pim_abuse',
                    'risk_level': 'high',
                    'steps': [
                        {'node_type': 'identity', 'node_id': identity_id, 'node_label': display_name, 'description': 'Starting identity'},
                        {'node_type': 'pim', 'node_id': pr[0], 'node_label': f'PIM: {pr[0]}', 'description': 'Eligible for privileged role via PIM'},
                        {'node_type': 'target', 'node_id': 'activated_role', 'node_label': pr[0], 'description': 'Activated role grants administrative control'},
                    ],
                    'impact': f'Can activate {pr[0]} via PIM',
                    'narrative': f'This identity is eligible to activate {pr[0]} through Privileged Identity Management. While PIM requires justification, a compromised identity could activate this role and gain administrative control.',
                })
        except Exception:
            db.conn.rollback()

        # 5. Lateral movement: subscription-level Contributor/Owner
        try:
            cursor.execute("""
                SELECT role_name, scope
                FROM role_assignments
                WHERE identity_db_id = %s
                  AND role_name IN ('Owner', 'Contributor')
                  AND (scope ~ '^/subscriptions/[^/]+$' OR scope = '/')
            """, (db_id,))
            sub_roles = cursor.fetchall()
            for sr in sub_roles:
                paths.append({
                    'type': 'lateral_movement',
                    'risk_level': 'medium',
                    'steps': [
                        {'node_type': 'identity', 'node_id': identity_id, 'node_label': display_name, 'description': 'Starting identity'},
                        {'node_type': 'role', 'node_id': sr[0], 'node_label': f'{sr[0]} at {sr[1][:40]}', 'description': f'Subscription-level {sr[0]}'},
                        {'node_type': 'target', 'node_id': sr[1], 'node_label': 'All Subscription Resources', 'description': 'Can modify/delete any resource in subscription'},
                    ],
                    'impact': f'{sr[0]} on subscription grants full resource control',
                    'narrative': f'The {sr[0]} role at subscription scope ({sr[1][:50]}) allows modification or deletion of any resource within the subscription, enabling lateral movement to sensitive workloads.',
                })
        except Exception:
            db.conn.rollback()

        cursor.close()

        # Deduplicate and sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        paths.sort(key=lambda p: severity_order.get(p['risk_level'], 99))
        critical_count = sum(1 for p in paths if p['risk_level'] == 'critical')

        max_blast = 'critical' if critical_count > 0 else ('high' if any(p['risk_level'] == 'high' for p in paths) else 'none')

        return jsonify({
            'paths': paths,
            'summary': {
                'total_paths': len(paths),
                'critical_paths': critical_count,
                'max_blast_radius': max_blast,
            },
        })
    finally:
        db.close()


# ── Phase 83: Slack/Teams Integrations Settings ────────────────

def get_integration_settings():
    """GET /api/settings/integrations — return webhook URLs (masked) + event config."""
    db = _db()
    try:
        slack_url = db.get_setting('slack_webhook_url', '')
        teams_url = db.get_setting('teams_webhook_url', '')
        slack_events = db.get_setting('slack_events', '[]')
        teams_events = db.get_setting('teams_events', '[]')

        def mask_url(url):
            if not url or len(url) < 20:
                return ''
            return url[:15] + '...' + url[-6:]

        return jsonify({
            'slack': {
                'configured': bool(slack_url),
                'webhook_url_masked': mask_url(slack_url),
                'events': json.loads(slack_events) if slack_events else [],
            },
            'teams': {
                'configured': bool(teams_url),
                'webhook_url_masked': mask_url(teams_url),
                'events': json.loads(teams_events) if teams_events else [],
            },
        })
    finally:
        db.close()


def save_integration_settings():
    """POST /api/settings/integrations — save webhook URLs + event config."""
    data = request.get_json(silent=True) or {}
    db = _db()
    try:
        if 'slack_webhook_url' in data:
            db.save_setting('slack_webhook_url', data['slack_webhook_url'])
        if 'teams_webhook_url' in data:
            db.save_setting('teams_webhook_url', data['teams_webhook_url'])
        if 'slack_events' in data:
            db.save_setting('slack_events', json.dumps(data['slack_events']))
        if 'teams_events' in data:
            db.save_setting('teams_events', json.dumps(data['teams_events']))

        _log(db, 'integrations_updated', 'Integration settings updated')
        return jsonify({'success': True})
    finally:
        db.close()


def test_integration_webhook():
    """POST /api/settings/integrations/test — send test message to verify webhook."""
    data = request.get_json(silent=True) or {}
    platform = data.get('platform')
    webhook_url = data.get('webhook_url')

    if not platform or not webhook_url:
        return jsonify({'error': 'platform and webhook_url required'}), 400

    from app.services.notification_dispatcher import NotificationDispatcher
    dispatcher = NotificationDispatcher()

    try:
        if platform == 'slack':
            success = dispatcher.send_slack(webhook_url, {
                'event_type': 'test',
                'title': 'AuditGraph Test Notification',
                'description': 'This is a test message from AuditGraph. If you see this, your Slack integration is working correctly.',
                'severity': 'info',
            })
        elif platform == 'teams':
            success = dispatcher.send_teams(webhook_url, {
                'event_type': 'test',
                'title': 'AuditGraph Test Notification',
                'description': 'This is a test message from AuditGraph. If you see this, your Teams integration is working correctly.',
                'severity': 'info',
            })
        else:
            return jsonify({'error': 'Invalid platform. Use slack or teams.'}), 400

        if success:
            return jsonify({'success': True, 'message': f'Test message sent to {platform}'})
        else:
            return jsonify({'success': False, 'message': f'Failed to send to {platform}. Check the webhook URL.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def check_feature_gate(feature_name):
    """Check if a feature is available for the current tenant's plan."""
    db = _db()
    try:
        tenant_id = _tenant_id()
        if not tenant_id:
            return True, None

        tenant = db.get_tenant_by_id(tenant_id)
        if not tenant:
            return True, None

        plan = tenant.get('plan', 'free')
        limits = TIER_LIMITS.get(plan, TIER_LIMITS['free'])
        blocked = limits.get('blocked_features', [])

        if feature_name in blocked:
            return False, {
                'error': f'{feature_name.replace("_", " ").title()} is not available on the {plan.capitalize()} plan.',
                'upgrade_required': True,
                'current_plan': plan,
            }
        return True, None
    finally:
        db.close()


# ================================================================
# Cloud Subscriptions (per-account monitoring)
# ================================================================

def get_subscriptions_list():
    """GET /api/subscriptions — list cloud subscriptions for current tenant."""
    db = _db()
    try:
        cloud = request.args.get('cloud')
        subs = db.get_cloud_subscriptions(_tenant_id(), cloud=cloud)
        return jsonify({'subscriptions': subs})
    finally:
        db.close()


def get_subscriptions_stats():
    """GET /api/subscriptions/stats — summary counts."""
    db = _db()
    try:
        stats = db.get_subscription_stats(_tenant_id())
        return jsonify(stats)
    finally:
        db.close()


def activate_subscription():
    """POST /api/subscriptions/activate — activate a subscription for monitoring."""
    db = _db()
    try:
        data = request.get_json(silent=True) or {}
        sub_id = data.get('id')
        if not sub_id:
            return jsonify({'error': 'Subscription id is required'}), 400

        user = getattr(g, 'current_user', None)
        user_id = user.get('id') if user else None
        result = db.activate_cloud_subscription(sub_id, user_id)
        if not result:
            return jsonify({'error': 'Subscription not found'}), 404

        _log(db, 'subscription_activated', f"Activated subscription {result.get('account_id')}", {'subscription_id': sub_id})
        return jsonify(result)
    finally:
        db.close()


def deactivate_subscription(sub_id):
    """PUT /api/subscriptions/<id>/deactivate — stop monitoring."""
    db = _db()
    try:
        result = db.deactivate_cloud_subscription(sub_id)
        if not result:
            return jsonify({'error': 'Subscription not found'}), 404

        _log(db, 'subscription_deactivated', f"Deactivated subscription {result.get('account_id')}", {'subscription_id': sub_id})
        return jsonify(result)
    finally:
        db.close()


def get_subscriptions_distinct():
    """GET /api/subscriptions/distinct — distinct subscription_id/name pairs from discovery_runs."""
    db = _db()
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT DISTINCT subscription_id, subscription_name
            FROM discovery_runs
            WHERE tenant_id = %s
              AND subscription_id IS NOT NULL
              AND subscription_id != ''
            ORDER BY subscription_name
        """, (_tenant_id(),))
        rows = cursor.fetchall()
        cursor.close()
        return jsonify({'subscriptions': [{'subscription_id': r[0], 'subscription_name': r[1] or r[0]} for r in rows]})
    except Exception:
        return jsonify({'subscriptions': []})
    finally:
        db.close()


def get_identity_subscriptions(identity_id):
    """GET /api/identities/<identity_id>/subscriptions — all subscription access for an identity."""
    db = _db()
    try:
        # Resolve identity_id to identity_db_id from latest run
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT i.id FROM identities i
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE i.identity_id = %s AND dr.tenant_id = %s
            ORDER BY i.discovery_run_id DESC LIMIT 1
        """, (identity_id, _tenant_id()))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return jsonify({'subscriptions': [], 'count': 0})
        identity_db_id = row[0]
        subs = db.get_identity_subscription_access(identity_db_id)
        # Group by subscription for a cleaner response
        by_sub = {}
        for s in subs:
            sub_id = s['subscription_id']
            if sub_id not in by_sub:
                by_sub[sub_id] = {
                    'subscription_id': sub_id,
                    'subscription_name': s['subscription_name'],
                    'roles': [],
                }
            by_sub[sub_id]['roles'].append({
                'rbac_role': s['rbac_role'],
                'scope': s['scope'],
                'scope_type': s['scope_type'],
                'risk_level': s['risk_level'],
            })
        result = sorted(by_sub.values(), key=lambda x: x['subscription_name'] or '')
        return jsonify({'subscriptions': result, 'count': len(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()
