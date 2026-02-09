"""
AuditGraph REST API - Handlers

This module contains all HTTP endpoint handler functions for the AuditGraph API.
"""

import os
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

        # Previous run for trend comparison (Pillar 6)
        cursor.execute(
            """
            SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
            FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC
            LIMIT 1 OFFSET 1
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
                i.last_sign_in,
                -- Ownership fields
                i.owner_display_name,
                COALESCE(i.owner_count, 0) as owner_count,
                -- Risk scoring fields
                COALESCE(i.risk_score, 0) as risk_score,
                COALESCE(i.api_permission_count, 0) as api_permission_count,
                COALESCE(i.app_role_count, 0) as app_role_count,
                -- Graph API max risk
                (
                    SELECT MAX(gp.risk_level)
                    FROM graph_api_permissions gp
                    WHERE gp.identity_db_id = i.id
                    AND gp.risk_level IS NOT NULL
                ) as graph_max_risk,
                i.enabled,
                i.last_sign_in,
                -- Privilege tier (T0-T3) based on actual role names
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
                COALESCE(i.ca_mfa_enforced, false) as ca_mfa_enforced
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

        if cloud_filter:
            query += " AND COALESCE(i.cloud, 'azure') = %s"
            params.append(cloud_filter.lower())

        if search:
            query += " AND LOWER(i.display_name) LIKE %s"
            params.append(f"%{search.lower()}%")

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

        identities = []
        for row in rows:
            display_name = row[1] or ''
            identity_type = row[2] or ''
            raw_category = row[3] or ''

            # First normalize the category key
            normalized_category = _normalize_category_key(raw_category)

            identities.append(
                {
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
                    # Separate role counts with risk levels
                    "rbac_role_count": int(row[12] or 0),
                    "entra_role_count": int(row[13] or 0),
                    "role_count": int(row[12] or 0) + int(row[13] or 0),
                    "rbac_max_risk": row[14] or "info",
                    "entra_max_risk": row[15] or "info",
                    # Multi-cloud normalized fields
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
                    # Ownership fields
                    "owner_display_name": row[26],
                    "owner_count": int(row[27] or 0),
                    # Risk scoring fields
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
                }
            )

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
                   -- Evidence fields (Pillar 5)
                   i.discovery_run_id,
                   dr.completed_at as run_completed_at
            FROM identities i
            LEFT JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE i.identity_id = %s
            ORDER BY i.discovery_run_id DESC
            LIMIT 1
            """,
            (identity_id,),
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
            "discovery_run_id": row[29],
        }

        run_completed_at = row[30].isoformat() if row[30] else None
        current_run_id = row[29]

        # Trend comparison: get this identity's state from the previous run (Pillar 6)
        trend = None
        if current_run_id:
            try:
                cursor.execute(
                    """
                    SELECT risk_level, risk_score, credential_count, credential_expiration
                    FROM identities
                    WHERE identity_id = %s
                      AND discovery_run_id = (
                          SELECT MAX(id) FROM discovery_runs
                          WHERE status = 'completed' AND id < %s
                      )
                    LIMIT 1
                    """,
                    (identity_id, current_run_id),
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
    """Get drift report for a specific discovery run."""
    db = _db()
    try:
        # Try persisted report first
        report = db.get_drift_report(run_id)
        if report:
            report['created_at'] = report['created_at'].isoformat() if report.get('created_at') else None
            db.log_activity('drift_reviewed', f'Drift report reviewed for run #{run_id}', {
                'run_id': run_id,
                'total_changes': report.get('total_changes', 0),
            })
            return jsonify(report)

        # Fall back to live computation: find the previous run
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE status = 'completed' AND id < %s
            ORDER BY id DESC
            LIMIT 1
        """, (run_id,))
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
                ), 0) as dormant_count
            FROM discovery_runs dr
            WHERE dr.status = 'completed'
            ORDER BY dr.id DESC
            LIMIT %s
            """,
            (limit,),
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
            })

        return jsonify({
            "count": len(runs),
            "runs": runs,
        })

    finally:
        cursor.close()
        db.close()


def get_app_settings():
    """Return all settings plus connection/scheduler status."""
    db = _db()
    try:
        settings = db.get_settings()

        # Check Azure credential configuration
        azure_configured = all([
            os.getenv('AZURE_TENANT_ID'),
            os.getenv('AZURE_CLIENT_ID'),
            os.getenv('AZURE_CLIENT_SECRET'),
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
        'org_name', 'discovery_interval_hours', 'email_enabled', 'email_to',
        'notify_new_identities', 'notify_removed_identities',
        'notify_permission_changes', 'notify_risk_changes', 'notify_credential_changes',
        'report_schedule_enabled', 'report_schedule_frequency', 'report_email_to',
    }
    BOOLEAN_KEYS = {
        'email_enabled', 'notify_new_identities', 'notify_removed_identities',
        'notify_permission_changes', 'notify_risk_changes', 'notify_credential_changes',
        'report_schedule_enabled',
    }

    # Filter to valid keys only
    updates = {}
    errors = []
    for key, value in data.items():
        if key not in VALID_KEYS:
            errors.append(f"Unknown setting: {key}")
            continue

        value = str(value).strip()

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

        if key in ('email_to', 'report_email_to') and value:
            if '@' not in value:
                errors.append(f"{key} must be a valid email address")
                continue

        updates[key] = value

    if errors:
        return jsonify({"error": "; ".join(errors)}), 400

    db = _db()
    try:
        db.save_settings(updates)
        settings = db.get_settings()
        db.log_activity('settings_updated', f'Settings updated: {", ".join(updates.keys())}', {
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
            db.log_activity('test_email_sent', f'Test email sent to {to_email or "default recipient"}')
            return jsonify({"status": "sent", "message": "Test email sent successfully"})
        else:
            db.log_activity('test_email_failed', 'Test email failed to send')
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
        db.log_activity('discovery_triggered', 'Manual discovery run triggered')
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
        db.log_activity('report_generated', 'Security report data generated', {
            'run_id': data.get('run_id'),
            'total_identities': data.get('stats', {}).get('total_identities', 0),
        })
        return jsonify(data)
    finally:
        db.close()


def get_activity():
    """Get activity log entries with optional filtering."""
    db = _db()
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        action_type = request.args.get('type')

        limit = min(limit, 200)

        entries = db.get_activity_log(limit=limit, offset=offset, action_type=action_type)

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
        db.log_activity('webhook_created',
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
        db.log_activity('webhook_updated',
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
        db.log_activity('webhook_deleted',
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

        db.log_activity('webhook_tested',
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
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        latest_run = cursor.fetchone()[0]
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


def get_dashboard_compliance():
    """
    Compliance scorecard: SOC 2, HIPAA, PCI-DSS, NIST 800-53.
    Evaluates pass/warn/fail per control area based on current identity posture.
    """
    db = _db()
    cursor = db.conn.cursor()
    try:
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        latest_run = cursor.fetchone()[0]
        if not latest_run:
            return jsonify({"error": "No completed discovery runs found"}), 404

        # Gather key metrics
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

        # Dormant privileged (T0/T1 with stale/never_used)
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
        expired_creds = cursor.fetchone()[0]

        # Expiring within 30 days
        cursor.execute("""
            SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
            AND i.credential_expiration IS NOT NULL
            AND i.credential_expiration > NOW()
            AND i.credential_expiration < NOW() + INTERVAL '30 days'
        """, (latest_run,))
        expiring_creds = cursor.fetchone()[0]

        # Unowned SPNs
        cursor.execute("""
            SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
            AND LOWER(COALESCE(i.identity_category, '')) = 'service_principal'
            AND COALESCE(i.owner_count, 0) = 0
        """, (latest_run,))
        unowned_spns = cursor.fetchone()[0]

        # Total identities
        cursor.execute("""
            SELECT COUNT(*) FROM identities i WHERE i.discovery_run_id = %s
        """, (latest_run,))
        total = cursor.fetchone()[0]

        # HIPAA violations count
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
        hipaa_roles_with_violations = cursor.fetchone()[0]

        # Build scorecard
        def status(pass_cond, warn_cond):
            if pass_cond:
                return "pass"
            if warn_cond:
                return "warn"
            return "fail"

        scorecard = {
            "soc2": {
                "name": "SOC 2",
                "controls": [
                    {
                        "id": "CC6.1",
                        "name": "Logical Access Controls",
                        "status": status(t0_count <= 2, t0_count <= 5),
                        "detail": f"{t0_count} Control Plane (T0) accounts" + (" — exceeds recommended max of 2" if t0_count > 2 else " — within limits"),
                    },
                    {
                        "id": "CC6.2",
                        "name": "Access Reviews",
                        "status": status(dormant_privileged == 0, dormant_privileged <= 2),
                        "detail": f"{dormant_privileged} dormant privileged account{'s' if dormant_privileged != 1 else ''} need review",
                    },
                    {
                        "id": "CC6.3",
                        "name": "Asset Ownership",
                        "status": status(unowned_spns == 0, unowned_spns <= 3),
                        "detail": f"{unowned_spns} service principal{'s' if unowned_spns != 1 else ''} without owners",
                    },
                    {
                        "id": "CC7.2",
                        "name": "Credential Management",
                        "status": status(expired_creds == 0 and expiring_creds == 0, expired_creds == 0),
                        "detail": f"{expired_creds} expired, {expiring_creds} expiring within 30d",
                    },
                ],
            },
            "hipaa": {
                "name": "HIPAA",
                "controls": [
                    {
                        "id": "§164.312(a)",
                        "name": "Access Control",
                        "status": status(t0_count <= 2, t0_count <= 5),
                        "detail": f"{t0_count} identities with full tenant access",
                    },
                    {
                        "id": "§164.312(d)",
                        "name": "Authentication",
                        "status": status(expired_creds == 0, expiring_creds <= 3),
                        "detail": f"{expired_creds} expired credentials" + (f", {expiring_creds} expiring" if expiring_creds > 0 else ""),
                    },
                    {
                        "id": "§164.308(a)(3)",
                        "name": "Workforce Security",
                        "status": status(dormant_privileged == 0, dormant_privileged <= 2),
                        "detail": f"{dormant_privileged} dormant privileged account{'s' if dormant_privileged != 1 else ''}",
                    },
                    {
                        "id": "§164.312(b)",
                        "name": "Audit Controls",
                        "status": "pass" if hipaa_roles_with_violations == 0 else "warn",
                        "detail": f"{hipaa_roles_with_violations} role{'s' if hipaa_roles_with_violations != 1 else ''} with HIPAA violation mappings in use",
                    },
                ],
            },
            "pci_dss": {
                "name": "PCI-DSS",
                "controls": [
                    {
                        "id": "Req 7.1",
                        "name": "Limit Access",
                        "status": status(t0_count <= 2, t0_count <= 5),
                        "detail": f"{t0_count} accounts with unrestricted access",
                    },
                    {
                        "id": "Req 8.1",
                        "name": "Credential Lifecycle",
                        "status": status(expired_creds == 0 and expiring_creds == 0, expired_creds == 0),
                        "detail": f"{expired_creds} expired, {expiring_creds} expiring credentials",
                    },
                    {
                        "id": "Req 8.6",
                        "name": "Service Account Controls",
                        "status": status(unowned_spns == 0, unowned_spns <= 3),
                        "detail": f"{unowned_spns} unmanaged service account{'s' if unowned_spns != 1 else ''}",
                    },
                ],
            },
            "nist": {
                "name": "NIST 800-53",
                "controls": [
                    {
                        "id": "AC-2",
                        "name": "Account Management",
                        "status": status(dormant_privileged == 0, dormant_privileged <= 2),
                        "detail": f"{dormant_privileged} dormant account{'s' if dormant_privileged != 1 else ''} requiring action",
                    },
                    {
                        "id": "AC-6",
                        "name": "Least Privilege",
                        "status": status(t0_count <= 2, t0_count <= 5),
                        "detail": f"{t0_count} T0 identities (target: ≤2)",
                    },
                    {
                        "id": "IA-5",
                        "name": "Authenticator Management",
                        "status": status(expired_creds == 0, expiring_creds <= 3),
                        "detail": f"{expired_creds + expiring_creds} credential{'s' if (expired_creds + expiring_creds) != 1 else ''} need attention",
                    },
                    {
                        "id": "CM-8",
                        "name": "Asset Inventory",
                        "status": status(unowned_spns == 0, unowned_spns <= 3),
                        "detail": f"{total} identities tracked, {unowned_spns} unowned",
                    },
                ],
            },
        }

        # Compute overall scores per framework
        for fw in scorecard.values():
            controls = fw["controls"]
            passes = sum(1 for c in controls if c["status"] == "pass")
            fw["score"] = round(passes / len(controls) * 100) if controls else 0
            fw["pass_count"] = passes
            fw["total_controls"] = len(controls)

        return jsonify(scorecard)
    finally:
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
        # Get latest two completed runs for trend comparison
        cursor.execute(
            """
            SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
            FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC
            LIMIT 2
            """
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


def get_identity_summary():
    """
    Get identity counts grouped by category for the dashboard.

    Returns:
        JSON with category breakdown including risk counts per category
    """
    db = _db()
    cursor = db.conn.cursor()

    try:
        # Get latest completed discovery run
        cursor.execute("SELECT MAX(id), MAX(completed_at) FROM discovery_runs WHERE status = 'completed'")
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
        # Resolve identity_db_id from identity_id
        cursor.execute("""
            SELECT i.id FROM identities i
            JOIN (SELECT MAX(id) as rid FROM discovery_runs WHERE status = 'completed') dr
            ON i.discovery_run_id = dr.rid
            WHERE i.identity_id = %s
            LIMIT 1
        """, (identity_id,))
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
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        latest_run = cursor.fetchone()[0]

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

        db.log_activity('remediation_updated', f'Remediation status changed to {status}', {
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

        db.log_activity('remediation_updated', f'Bulk {status} applied to {result["identity_count"]} identities ({result["updated_count"]} actions)', {
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


def get_remediation_dashboard_summary():
    """Get aggregated remediation progress for the dashboard widget."""
    db = _db()
    try:
        summary = db.get_remediation_summary()
        return jsonify(summary)
    finally:
        db.close()
