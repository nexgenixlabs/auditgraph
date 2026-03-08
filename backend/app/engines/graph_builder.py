"""
Phase 7: IAM Graph Engine — Graph Builder

Builds a relationship graph of identities, roles, resources, and subscriptions
from the latest discovery run for a cloud connection. The graph is stored in
graph_nodes and graph_edges tables, enabling access path analysis.
"""

import logging

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds IAM graph nodes and edges from discovered identity data."""

    def __init__(self, db):
        self.db = db

    def build_iam_graph(self, connection_id, org_id):
        """Build the full IAM graph for a cloud connection.

        Clears existing graph data for this connection and rebuilds from
        the latest completed discovery run.

        Returns dict with node_count and edge_count.
        """
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.debug(f"No completed run for connection {connection_id}, skipping graph build")
            return {'node_count': 0, 'edge_count': 0}

        # Clear existing graph for this connection
        self.db.clear_graph(connection_id)

        # Collect data from discovery
        identities = self._get_identities(run_id)
        role_assignments = self._get_role_assignments(run_id)
        subscriptions = self._extract_subscriptions(role_assignments)

        # Build nodes
        node_map = {}  # external_id -> node UUID

        # Identity nodes
        for ident in identities:
            node_id = self.db.create_graph_node(
                org_id=org_id,
                connection_id=connection_id,
                node_type='identity',
                external_id=ident['identity_id'],
                display_name=ident['display_name'],
                metadata={
                    'identity_category': ident.get('identity_category'),
                    'risk_score': ident.get('risk_score'),
                    'activity_status': ident.get('activity_status'),
                },
            )
            if node_id:
                node_map[ident['identity_id']] = node_id

        # Role nodes (deduplicated by role name)
        role_names = set()
        for ra in role_assignments:
            role_name = ra.get('role_name')
            if role_name and role_name not in role_names:
                role_names.add(role_name)
                node_id = self.db.create_graph_node(
                    org_id=org_id,
                    connection_id=connection_id,
                    node_type='role',
                    external_id=f"role:{role_name}",
                    display_name=role_name,
                    metadata={'role_type': 'rbac'},
                )
                if node_id:
                    node_map[f"role:{role_name}"] = node_id

        # Subscription nodes
        for sub_id, sub_name in subscriptions.items():
            node_id = self.db.create_graph_node(
                org_id=org_id,
                connection_id=connection_id,
                node_type='subscription',
                external_id=sub_id,
                display_name=sub_name or sub_id,
                metadata={},
            )
            if node_id:
                node_map[sub_id] = node_id

        # Resource nodes (from role assignment scopes)
        resource_scopes = set()
        for ra in role_assignments:
            scope = ra.get('scope', '')
            if scope and scope not in resource_scopes:
                resource_scopes.add(scope)
                node_id = self.db.create_graph_node(
                    org_id=org_id,
                    connection_id=connection_id,
                    node_type='resource',
                    external_id=scope,
                    display_name=scope.split('/')[-1] if '/' in scope else scope,
                    metadata={'scope': scope},
                )
                if node_id:
                    node_map[scope] = node_id

        # Build edges
        edge_count = 0

        for ra in role_assignments:
            identity_id = ra.get('identity_id')
            role_name = ra.get('role_name')
            scope = ra.get('scope', '')
            subscription_id = ra.get('subscription_id')

            # Edge: Identity → Role (assigned_role)
            src = node_map.get(identity_id)
            tgt = node_map.get(f"role:{role_name}")
            if src and tgt:
                self.db.create_graph_edge(
                    org_id=org_id,
                    connection_id=connection_id,
                    source_node_id=src,
                    target_node_id=tgt,
                    edge_type='assigned_role',
                    metadata={'scope': scope},
                )
                edge_count += 1

            # Edge: Role → Resource (grants_access)
            tgt_resource = node_map.get(scope)
            if tgt and tgt_resource:
                self.db.create_graph_edge(
                    org_id=org_id,
                    connection_id=connection_id,
                    source_node_id=tgt,
                    target_node_id=tgt_resource,
                    edge_type='grants_access',
                    metadata={'role_name': role_name},
                )
                edge_count += 1

            # Edge: Subscription → Resource (contains_resource)
            if subscription_id and scope:
                sub_node = node_map.get(subscription_id)
                if sub_node and tgt_resource and subscription_id != scope:
                    self.db.create_graph_edge(
                        org_id=org_id,
                        connection_id=connection_id,
                        source_node_id=sub_node,
                        target_node_id=tgt_resource,
                        edge_type='contains_resource',
                        metadata={},
                    )
                    edge_count += 1

        node_count = len(node_map)
        logger.info(f"IAM graph built for connection {connection_id}: "
                     f"{node_count} nodes, {edge_count} edges")

        return {'node_count': node_count, 'edge_count': edge_count}

    def _get_latest_run_id(self, connection_id):
        """Get the most recent completed discovery run for a connection."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE cloud_connection_id = %s AND status = 'completed'
            ORDER BY id DESC LIMIT 1
        """, (connection_id,))
        row = cursor.fetchone()
        cursor.close()
        return row['id'] if row else None

    def _get_identities(self, run_id):
        """Get all identities from a discovery run."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, identity_id, display_name, identity_category,
                   risk_score, activity_status
            FROM identities
            WHERE discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

    def _get_role_assignments(self, run_id):
        """Get all role assignments for identities in a discovery run."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT ra.*, i.identity_id
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

    def _extract_subscriptions(self, role_assignments):
        """Extract unique subscription IDs and names from role assignments."""
        subs = {}
        for ra in role_assignments:
            sub_id = ra.get('subscription_id')
            sub_name = ra.get('subscription_name')
            if sub_id and sub_id not in subs:
                subs[sub_id] = sub_name
        return subs
