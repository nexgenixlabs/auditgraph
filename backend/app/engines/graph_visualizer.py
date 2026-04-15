"""Phase 16: Identity Attack Graph Visualization Engine.

Generates graph structures for identity relationships and attack paths,
suitable for frontend visualization with node/edge data.
"""

import logging

logger = logging.getLogger(__name__)

# Maximum nodes to include in a single graph
MAX_NODES = 2000

# Node type display configuration
NODE_TYPES = {
    'identity', 'service_principal', 'managed_identity',
    'role', 'resource', 'subscription',
    'aws_user', 'aws_role', 'gcp_service_account', 'gcp_project',
}

# Edge type configuration
EDGE_TYPES = {
    'assigned_role', 'grants_access', 'contains_resource', 'escalation_path',
    'policy_attachment', 'role_binding',
}

# Identity category to node type mapping
CATEGORY_NODE_TYPE = {
    'human_user': 'identity',
    'guest': 'identity',
    'service_principal': 'service_principal',
    'managed_identity_system': 'managed_identity',
    'managed_identity_user': 'managed_identity',
    'microsoft_internal': 'service_principal',
}


class GraphVisualizer:
    """Generates graph visualization data from IAM graph and attack paths."""

    def __init__(self, db):
        self.db = db

    def generate_identity_graph(self, connection_id, org_id):
        """Generate full IAM identity graph for a cloud connection.

        Steps:
        1. Load graph_nodes for the connection
        2. Load graph_edges for the connection
        3. Build node/edge structure with limits
        4. Store result in visualization cache
        """
        # 1. Load nodes
        nodes = self._load_graph_nodes(connection_id)

        # 2. Load edges
        edges = self._load_graph_edges(connection_id)

        # 3. Build structure with safeguards
        graph_data = self._build_graph_structure(nodes, edges)

        # 4. Cache result
        cached = self._save_to_cache(
            org_id, connection_id, 'identity_graph', graph_data
        )

        graph_data['cache_id'] = str(cached['id']) if cached else None
        return graph_data

    def generate_attack_graph(self, simulation_id, org_id):
        """Generate attack path graph from a simulation.

        Uses attack_sim_paths to build a directed graph showing
        attacker movement from source identity through intermediate
        nodes to target resources.
        """
        # Load simulation and paths
        simulation = self.db.get_attack_simulation_by_id(simulation_id)
        if not simulation:
            return {'error': 'Simulation not found'}

        paths = self._load_attack_paths(simulation_id)
        if not paths:
            return {
                'nodes': [],
                'edges': [],
                'path_count': 0,
                'simulation_id': str(simulation_id),
            }

        # Build attack graph
        nodes = {}
        edges = []

        for path in paths:
            source = path.get('source_identity', '')
            target = path.get('target_resource', '')
            path_nodes = path.get('path_nodes', [])

            # Add source node
            if source and source not in nodes:
                nodes[source] = {
                    'id': source,
                    'label': source,
                    'type': 'identity',
                    'risk_level': path.get('risk_level', 'medium'),
                }

            # Add target node
            if target and target not in nodes:
                nodes[target] = {
                    'id': target,
                    'label': target,
                    'type': 'resource',
                    'risk_level': path.get('risk_level', 'medium'),
                }

            # Add intermediate nodes from path_nodes
            prev_node_id = source
            for i, pn in enumerate(path_nodes):
                node_id = pn if isinstance(pn, str) else pn.get('id', f'{source}_hop_{i}')
                node_label = pn if isinstance(pn, str) else pn.get('label', node_id)
                node_type = 'role' if isinstance(pn, str) else pn.get('type', 'role')

                if node_id not in nodes:
                    nodes[node_id] = {
                        'id': node_id,
                        'label': node_label,
                        'type': node_type,
                        'risk_level': path.get('risk_level', 'medium'),
                    }

                # Edge from previous to this node
                edges.append({
                    'source': prev_node_id,
                    'target': node_id,
                    'type': 'escalation_path',
                    'path_index': path.get('path_index', 0),
                })
                prev_node_id = node_id

            # Final edge to target
            if prev_node_id and target:
                edges.append({
                    'source': prev_node_id,
                    'target': target,
                    'type': 'escalation_path',
                    'path_index': path.get('path_index', 0),
                })

        graph_data = {
            'nodes': list(nodes.values())[:MAX_NODES],
            'edges': edges,
            'path_count': len(paths),
            'simulation_id': str(simulation_id),
            'node_count': min(len(nodes), MAX_NODES),
            'edge_count': len(edges),
            'truncated': len(nodes) > MAX_NODES,
        }

        # Cache the attack graph
        connection_id = simulation.get('cloud_connection_id', 0)
        self._save_to_cache(org_id, connection_id, 'attack_path_graph', graph_data)

        return graph_data

    def generate_identity_neighborhood(self, identity_id, org_id):
        """Generate a neighborhood graph around a specific identity.

        Returns the identity node plus all directly connected nodes
        (roles, resources, subscriptions) and their edges.
        """
        nodes = {}
        edges = []

        # Find the identity in graph_nodes
        identity_node = self._find_identity_node(identity_id)
        if not identity_node:
            return {'nodes': [], 'edges': [], 'center_identity': identity_id}

        node_id = str(identity_node['id'])
        nodes[node_id] = {
            'id': node_id,
            'label': identity_node.get('display_name', identity_id),
            'type': identity_node.get('node_type', 'identity'),
            'external_id': identity_node.get('external_id', ''),
            'metadata': identity_node.get('metadata', {}),
        }

        # Load edges where this node is source or target
        neighbors = self._load_neighbor_edges(identity_node['id'])
        for edge in neighbors:
            src = str(edge['source_node_id'])
            tgt = str(edge['target_node_id'])
            other_id = tgt if src == node_id else src

            # Load the other node
            if other_id not in nodes:
                other_node = self._load_node_by_id(other_id)
                if other_node:
                    nodes[other_id] = {
                        'id': other_id,
                        'label': other_node.get('display_name', other_id),
                        'type': other_node.get('node_type', 'resource'),
                        'external_id': other_node.get('external_id', ''),
                        'metadata': other_node.get('metadata', {}),
                    }

            edges.append({
                'source': src,
                'target': tgt,
                'type': edge.get('edge_type', 'assigned_role'),
            })

        return {
            'nodes': list(nodes.values())[:MAX_NODES],
            'edges': edges,
            'center_identity': identity_id,
            'node_count': len(nodes),
            'edge_count': len(edges),
        }

    # ── Private helpers ────────────────────────────────────────────────

    def _load_graph_nodes(self, connection_id):
        """Load graph nodes for a connection."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM graph_nodes
                WHERE cloud_connection_id = %s
                ORDER BY node_type, display_name
                LIMIT %s
            """, (connection_id, MAX_NODES))
            rows = cursor.fetchall()
            cursor.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _load_graph_edges(self, connection_id):
        """Load graph edges for a connection."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM graph_edges
                WHERE cloud_connection_id = %s
            """, (connection_id,))
            rows = cursor.fetchall()
            cursor.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _load_attack_paths(self, simulation_id):
        """Load attack sim paths for a simulation."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM attack_sim_paths
                WHERE simulation_id = %s
                ORDER BY path_index
            """, (str(simulation_id),))
            rows = cursor.fetchall()
            cursor.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _find_identity_node(self, identity_id):
        """Find a graph node by external_id."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM graph_nodes
                WHERE external_id = %s
                LIMIT 1
            """, (identity_id,))
            row = cursor.fetchone()
            cursor.close()
            return dict(row) if row else None
        except Exception:
            return None

    def _load_neighbor_edges(self, node_id):
        """Load edges connected to a node."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM graph_edges
                WHERE source_node_id = %s OR target_node_id = %s
            """, (str(node_id), str(node_id)))
            rows = cursor.fetchall()
            cursor.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _load_node_by_id(self, node_id):
        """Load a single graph node by id."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM graph_nodes
                WHERE id = %s
            """, (node_id,))
            row = cursor.fetchone()
            cursor.close()
            return dict(row) if row else None
        except Exception:
            return None

    def _build_graph_structure(self, nodes, edges):
        """Build visualization-ready graph structure with limits."""
        # Map node UUIDs to string IDs
        node_list = []
        node_ids = set()

        for n in nodes[:MAX_NODES]:
            nid = str(n['id'])
            node_ids.add(nid)
            node_list.append({
                'id': nid,
                'label': n.get('display_name', n.get('external_id', '')),
                'type': n.get('node_type', 'identity'),
                'external_id': n.get('external_id', ''),
                'metadata': n.get('metadata', {}),
            })

        # Only include edges where both endpoints exist
        edge_list = []
        for e in edges:
            src = str(e['source_node_id'])
            tgt = str(e['target_node_id'])
            if src in node_ids and tgt in node_ids:
                edge_list.append({
                    'source': src,
                    'target': tgt,
                    'type': e.get('edge_type', 'assigned_role'),
                })

        return {
            'nodes': node_list,
            'edges': edge_list,
            'node_count': len(node_list),
            'edge_count': len(edge_list),
            'truncated': len(nodes) > MAX_NODES,
        }

    def _save_to_cache(self, org_id, connection_id, graph_type, graph_data):
        """Save graph data to visualization cache."""
        try:
            return self.db.save_graph_visualization_cache(
                org_id, connection_id, graph_type, graph_data
            )
        except Exception:
            logger.warning("Failed to cache graph visualization")
            return None
