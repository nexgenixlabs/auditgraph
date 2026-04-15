"""
Identity Graph Builder

Builds lightweight identity→role→scope edges in the identity_graph_edges table
from role_assignments joined with identities for a given cloud connection.

Edge types:
  - assigned_role:      identity → role
  - grants_access:      role → scope (subscription / resource group / resource)
  - contains_resource:  subscription → child scope (resource group / resource)
"""

import logging
import re

logger = logging.getLogger(__name__)

# Pattern to extract subscription ID from ARM scope paths
# e.g. /subscriptions/34780384-6a21-4b79-ac90-1e3976b58a33/resourceGroups/...
_SUB_RE = re.compile(r'^/subscriptions/([^/]+)', re.IGNORECASE)


def _extract_subscription_id(scope: str) -> str:
    """Extract the subscription GUID from an ARM scope path, or return ''."""
    m = _SUB_RE.match(scope or '')
    return f"/subscriptions/{m.group(1)}" if m else ''


def build_identity_graph(connection_id, db):
    """Build identity graph edges for a cloud connection.

    1. Resolve the latest completed discovery run for this connection.
    2. Query role_assignments JOIN identities for that run.
    3. Clear old edges for this connection.
    4. Insert new edges: identity→role, role→scope, subscription→scope.

    Returns dict with edge_count.
    """
    from psycopg2.extras import RealDictCursor

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # Find latest completed run for this connection
    cursor.execute("""
        SELECT id FROM discovery_runs
        WHERE cloud_connection_id = %s AND status = 'completed'
        ORDER BY id DESC LIMIT 1
    """, (connection_id,))
    row = cursor.fetchone()
    run_id = row['id'] if row else None

    if run_id:
        # Fetch role assignments for this specific run
        cursor.execute("""
            SELECT i.identity_id,
                   i.display_name,
                   ra.role_name,
                   ra.scope,
                   ra.scope_type
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        assignments = cursor.fetchall()
    else:
        # Fallback: get ALL role assignments regardless of run
        # (handles dev/migration scenarios where cloud_connection_id isn't set)
        logger.info(f"No run for connection {connection_id}, using org-wide role assignments")
        cursor.execute("""
            SELECT DISTINCT ON (i.identity_id, ra.role_name, ra.scope)
                   i.identity_id,
                   i.display_name,
                   ra.role_name,
                   ra.scope,
                   ra.scope_type
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.is_microsoft_system = FALSE
            ORDER BY i.identity_id, ra.role_name, ra.scope, i.discovery_run_id DESC NULLS LAST
        """)
        assignments = cursor.fetchall()

    if not assignments:
        cursor.close()
        logger.info(f"No role assignments for run #{run_id}, skipping graph edges")
        return {'edge_count': 0}

    # Clear existing edges for this connection
    cursor.execute("DELETE FROM identity_graph_edges WHERE connection_id = %s",
                   (connection_id,))

    edge_count = 0
    seen_edges = set()

    for ra in assignments:
        identity_id = ra['identity_id']
        role_name = ra['role_name'] or 'Unknown Role'
        scope = ra['scope'] or ''
        subscription_id = _extract_subscription_id(scope)

        # Edge 1: identity → role (assigned_role)
        key1 = (identity_id, f"role:{role_name}", 'assigned_role')
        if key1 not in seen_edges:
            seen_edges.add(key1)
            cursor.execute("""
                INSERT INTO identity_graph_edges
                    (connection_id, source_id, target_id, edge_type)
                VALUES (%s, %s, %s, %s)
            """, (connection_id, identity_id, f"role:{role_name}", 'assigned_role'))
            edge_count += 1

        # Edge 2: role → scope (grants_access)
        if scope:
            key2 = (f"role:{role_name}", scope, 'grants_access')
            if key2 not in seen_edges:
                seen_edges.add(key2)
                cursor.execute("""
                    INSERT INTO identity_graph_edges
                        (connection_id, source_id, target_id, edge_type)
                    VALUES (%s, %s, %s, %s)
                """, (connection_id, f"role:{role_name}", scope, 'grants_access'))
                edge_count += 1

        # Edge 3: subscription → scope (contains_resource)
        if subscription_id and scope and subscription_id != scope:
            key3 = (subscription_id, scope, 'contains_resource')
            if key3 not in seen_edges:
                seen_edges.add(key3)
                cursor.execute("""
                    INSERT INTO identity_graph_edges
                        (connection_id, source_id, target_id, edge_type)
                    VALUES (%s, %s, %s, %s)
                """, (connection_id, subscription_id, scope, 'contains_resource'))
                edge_count += 1

    db._commit()
    cursor.close()

    logger.info(f"Identity graph built for connection {connection_id}: "
                f"{edge_count} edges from {len(assignments)} role assignments")

    return {'edge_count': edge_count}
