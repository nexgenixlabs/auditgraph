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
                END as privilege_tier
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

            # For service principals, check if it's actually Microsoft internal
            # This handles legacy data that wasn't properly categorized
            if normalized_category == 'service_principal':
                if _is_microsoft_internal_identity(display_name, identity_type):
                    normalized_category = 'microsoft_internal'

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
            SELECT id, identity_id, display_name, identity_type, identity_category, risk_level,
                   credential_count, credential_risk, credential_status, credential_expiration,
                   created_datetime, activity_status, risk_reasons,
                   -- Multi-cloud normalized fields
                   COALESCE(cloud, 'azure') as cloud,
                   identity_type_normalized,
                   canonical_name,
                   principal_id,
                   tenant_or_org_id,
                   COALESCE(source_normalized, 'entra') as source,
                   COALESCE(is_federated, false) as is_federated,
                   COALESCE(status, 'active') as status,
                   last_seen_auth,
                   -- Ownership fields
                   owner_display_name,
                   COALESCE(owner_count, 0) as owner_count,
                   -- Risk scoring fields
                   COALESCE(risk_score, 0) as risk_score,
                   COALESCE(api_permission_count, 0) as api_permission_count,
                   COALESCE(app_role_count, 0) as app_role_count
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
        display_name = row[2] or ''
        identity_type = row[3] or ''
        normalized_category = _normalize_category_key(row[4] or '')

        # For service principals, check if it's actually Microsoft internal
        if normalized_category == 'service_principal':
            if _is_microsoft_internal_identity(display_name, identity_type):
                normalized_category = 'microsoft_internal'

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

            # For service principals, check if it's actually Microsoft internal
            if normalized_category == 'service_principal':
                if _is_microsoft_internal_identity(display_name, identity_type):
                    normalized_category = 'microsoft_internal'

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
    detector = DriftDetector()
    report = detector.get_drift_report(run_id)
    return jsonify(report)


def trigger_discovery():
    # Stub (keep existing behavior if you have it elsewhere)
    return jsonify({"status": "not_implemented"}), 501


def get_scheduler_status():
    return jsonify({"scheduler": "unknown"})


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
        'apple internet accounts',
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

            # Unowned service principals
            if category == 'service_principal' and (owner_count or 0) == 0:
                if risk_level in ('critical', 'high', 'medium'):
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

        return jsonify({
            "current_run": current_run,
            "previous_run": previous_run,
            "posture_score": posture_score,
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

            # For service principals, check if it's actually Microsoft internal
            if cat == 'service_principal':
                if _is_microsoft_internal_identity(display_name, identity_type):
                    cat = 'microsoft_internal'

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

        return jsonify({
            "run_id": run_id,
            "completed_at": completed_at.isoformat() if completed_at else None,
            "categories": categories
        })

    finally:
        cursor.close()
        db.close()
