"""Phase 13: Identity Attack Simulation Engine.

Simulates identity compromise scenarios using BFS traversal
through the IAM graph to calculate blast radius and attack paths.
"""

import logging
from collections import deque

logger = logging.getLogger(__name__)

# Performance safeguards
MAX_DEPTH_DEFAULT = 6
MAX_NODES_TRAVERSED = 5000

# Blast radius threshold for generating risk findings
BLAST_RADIUS_THRESHOLD = 10


class AttackSimulator:
    """Simulates identity compromise and calculates blast radius."""

    def __init__(self, db):
        self.db = db

    def simulate_identity_attack(self, connection_id, org_id, identity_id,
                                  max_depth=MAX_DEPTH_DEFAULT,
                                  simulation_type='identity_compromise'):
        """Run an identity compromise simulation.

        Steps:
        1. Verify identity exists in the identities table
        2. Load IAM graph nodes and edges for this connection
        3. If graph is empty, rebuild it via GraphBuilder
        4. BFS traverse from the compromised identity
        5. Detect reachable identities, roles, resources
        6. Calculate blast radius
        7. Store simulation + attack paths
        8. Optionally create risk finding if blast radius exceeds threshold

        Returns the simulation result dict.
        """
        # Step 1: Verify identity exists in identities table
        if not self._identity_exists(identity_id):
            return {'error': 'Identity not present in graph snapshot'}

        # Step 2: Load graph
        nodes, edges = self._load_graph(connection_id)

        # Step 3: If graph is empty, rebuild it
        if not nodes:
            logger.info(f"Graph empty for connection {connection_id}, rebuilding...")
            from app.engines.graph_builder import GraphBuilder
            result = GraphBuilder(self.db).build_iam_graph(connection_id, org_id)
            logger.info(f"Graph rebuild: {result.get('node_count', 0)} nodes, {result.get('edge_count', 0)} edges")
            nodes, edges = self._load_graph(connection_id)
            if not nodes:
                return {'error': 'No IAM graph data available for this connection'}

        # Step 4: Find the starting node
        start_node = self._find_identity_node(nodes, identity_id)
        if not start_node:
            return {'error': 'Identity not present in graph snapshot'}

        # BFS traversal
        traversal = self._bfs_traverse(start_node, nodes, edges, max_depth)

        # Calculate blast radius metrics
        metrics = self._calculate_blast_radius(traversal, nodes)

        # Build attack paths
        paths = self._build_attack_paths(identity_id, traversal, nodes)

        # Store simulation
        simulation = self.db.create_attack_simulation(
            org_id=org_id,
            connection_id=connection_id,
            identity_id=identity_id,
            simulation_type=simulation_type,
            max_depth=max_depth,
            blast_radius=metrics['blast_radius'],
            metadata={
                'reachable_resources': metrics['reachable_resources'],
                'reachable_identities': metrics['reachable_identities'],
                'reachable_subscriptions': metrics['reachable_subscriptions'],
                'nodes_traversed': metrics['nodes_traversed'],
                'max_depth_reached': metrics['max_depth_reached'],
            },
        )

        # Store attack paths
        if simulation and paths:
            self.db.save_attack_sim_paths(simulation['id'], paths)

        # Create risk finding if blast radius exceeds threshold
        if metrics['blast_radius'] >= BLAST_RADIUS_THRESHOLD:
            self._create_blast_radius_finding(
                connection_id, org_id, identity_id, metrics['blast_radius']
            )

        # Build graph visualization data from traversal
        graph_nodes, graph_edges = self._build_graph_data(
            start_node, traversal, nodes, edges
        )

        return {
            'simulation_id': str(simulation['id']) if simulation else None,
            'identity_id': identity_id,
            'simulation_type': simulation_type,
            'blast_radius': metrics['blast_radius'],
            'reachable_resources': metrics['reachable_resources'],
            'reachable_identities': metrics['reachable_identities'],
            'reachable_subscriptions': metrics['reachable_subscriptions'],
            'nodes_traversed': metrics['nodes_traversed'],
            'max_depth_reached': metrics['max_depth_reached'],
            'paths': paths[:50],  # Limit returned paths
            'nodes': graph_nodes[:200],
            'edges': graph_edges[:500],
        }

    def _load_graph(self, connection_id):
        """Load graph nodes and edges for a connection."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT id, node_type, external_id, display_name, metadata
            FROM graph_nodes
            WHERE cloud_connection_id = %s
        """, (connection_id,))
        nodes = {str(r['id']): dict(r) for r in cursor.fetchall()}

        cursor.execute("""
            SELECT id, source_node_id, target_node_id, edge_type, metadata
            FROM graph_edges
            WHERE cloud_connection_id = %s
        """, (connection_id,))
        edges = [dict(r) for r in cursor.fetchall()]
        cursor.close()

        return nodes, edges

    def _identity_exists(self, identity_id):
        """Check if identity exists in the identities table."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT 1 FROM identities WHERE identity_id = %s LIMIT 1",
                (identity_id,)
            )
            exists = cursor.fetchone() is not None
            cursor.close()
            return exists
        except Exception as e:
            logger.warning(f"Failed to check identity existence: {e}")
            return False

    def _find_identity_node(self, nodes, identity_id):
        """Find the graph node matching an identity_id."""
        for node_id, node in nodes.items():
            if node['node_type'] == 'identity' and node['external_id'] == identity_id:
                return node_id
        return None

    def _bfs_traverse(self, start_node_id, nodes, edges, max_depth):
        """BFS traversal through the IAM graph.

        Traversal rules:
        - Follow edges: identity → assigned_role → grants_access → contains_resource → identity
        - Stop when path depth exceeds max_depth
        - Stop when MAX_NODES_TRAVERSED reached (performance safeguard)

        Returns dict of visited node IDs → {depth, parent, edge_type}.
        """
        # Build adjacency list
        adjacency = {}
        for edge in edges:
            src = str(edge['source_node_id'])
            tgt = str(edge['target_node_id'])
            if src not in adjacency:
                adjacency[src] = []
            adjacency[src].append({'target': tgt, 'edge_type': edge['edge_type']})
            # Also traverse reverse for bidirectional reachability
            if tgt not in adjacency:
                adjacency[tgt] = []
            adjacency[tgt].append({'target': src, 'edge_type': edge['edge_type'] + '_reverse'})

        visited = {}
        queue = deque()
        queue.append((start_node_id, 0, None, None))
        visited[start_node_id] = {'depth': 0, 'parent': None, 'edge_type': None}

        nodes_traversed = 0

        while queue:
            if nodes_traversed >= MAX_NODES_TRAVERSED:
                break

            current, depth, parent, edge_type = queue.popleft()
            nodes_traversed += 1

            if depth >= max_depth:
                continue

            for neighbor in adjacency.get(current, []):
                target = neighbor['target']
                if target not in visited:
                    visited[target] = {
                        'depth': depth + 1,
                        'parent': current,
                        'edge_type': neighbor['edge_type'],
                    }
                    queue.append((target, depth + 1, current, neighbor['edge_type']))

        return visited

    def _calculate_blast_radius(self, traversal, nodes):
        """Calculate blast radius metrics from traversal results."""
        reachable_resources = 0
        reachable_identities = 0
        reachable_subscriptions = 0
        max_depth_reached = 0

        for node_id, info in traversal.items():
            node = nodes.get(node_id)
            if not node:
                continue
            node_type = node.get('node_type', '')
            if node_type == 'resource':
                reachable_resources += 1
            elif node_type == 'identity':
                reachable_identities += 1
            elif node_type == 'subscription':
                reachable_subscriptions += 1
            if info['depth'] > max_depth_reached:
                max_depth_reached = info['depth']

        blast_radius = reachable_resources + reachable_identities + reachable_subscriptions

        return {
            'blast_radius': blast_radius,
            'reachable_resources': reachable_resources,
            'reachable_identities': reachable_identities,
            'reachable_subscriptions': reachable_subscriptions,
            'nodes_traversed': len(traversal),
            'max_depth_reached': max_depth_reached,
        }

    def _build_attack_paths(self, source_identity, traversal, nodes):
        """Build attack path records from traversal data."""
        paths = []
        path_index = 0

        for node_id, info in traversal.items():
            node = nodes.get(node_id)
            if not node:
                continue
            # Only record paths to resources and identities (not roles)
            if node.get('node_type') not in ('resource', 'identity', 'subscription'):
                continue
            if info['depth'] == 0:
                continue  # Skip the start node

            # Reconstruct path
            path_nodes = self._reconstruct_path(node_id, traversal, nodes)

            risk_level = 'high' if info['depth'] <= 2 else \
                         'medium' if info['depth'] <= 4 else 'low'

            paths.append({
                'path_index': path_index,
                'source_identity': source_identity,
                'target_resource': node.get('external_id', ''),
                'path_length': info['depth'],
                'path_nodes': path_nodes,
                'risk_level': risk_level,
            })
            path_index += 1

        # Sort by path_length (shortest first)
        paths.sort(key=lambda p: p['path_length'])
        return paths

    def _reconstruct_path(self, end_node_id, traversal, nodes):
        """Reconstruct the path from start to end node."""
        path = []
        current = end_node_id
        while current is not None:
            node = nodes.get(current)
            if node:
                path.append(node.get('display_name') or node.get('external_id', current))
            else:
                path.append(current)
            info = traversal.get(current)
            if info:
                current = info.get('parent')
            else:
                break
        path.reverse()
        return path

    def _build_graph_data(self, start_node_id, traversal, nodes, edges):
        """Build graph nodes/edges for frontend visualization."""
        visited_ids = set(traversal.keys())
        graph_nodes = []
        for node_id in visited_ids:
            node = nodes.get(node_id)
            if not node:
                continue
            info = traversal[node_id]
            graph_nodes.append({
                'id': node_id,
                'label': node.get('display_name') or node.get('external_id', node_id),
                'type': node.get('node_type', 'unknown'),
                'depth': info['depth'],
                'is_start': node_id == start_node_id,
            })

        graph_edges = []
        seen_edges = set()
        for edge in edges:
            src = str(edge['source_node_id'])
            tgt = str(edge['target_node_id'])
            if src in visited_ids and tgt in visited_ids:
                edge_key = (src, tgt)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    graph_edges.append({
                        'source': src,
                        'target': tgt,
                        'label': edge.get('edge_type', ''),
                    })

        return graph_nodes, graph_edges

    def _create_blast_radius_finding(self, connection_id, org_id, identity_id, blast_radius):
        """Create a risk finding for large blast radius."""
        try:
            # Check if risk_rules table has the rule
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT id FROM risk_rules WHERE rule_key = 'identity_large_blast_radius'"
            )
            rule_row = cursor.fetchone()
            if not rule_row:
                cursor.close()
                return

            rule_id = rule_row[0]
            import json as _json
            cursor.execute("""
                INSERT INTO risk_findings
                    (organization_id, cloud_connection_id, rule_id, severity,
                     identity_id, metadata, status)
                VALUES (%s, %s, %s, 'high', %s, %s, 'open')
                ON CONFLICT (cloud_connection_id, rule_id, COALESCE(identity_id, ''), COALESCE(resource_id, ''))
                    WHERE status = 'open'
                DO UPDATE SET detected_at = NOW(), metadata = EXCLUDED.metadata
            """, (org_id, connection_id, rule_id, identity_id,
                  _json.dumps({
                      'blast_radius': blast_radius,
                      'finding_category': 'privilege_escalation',
                      'reason': f'Identity has blast radius of {blast_radius} (threshold: {BLAST_RADIUS_THRESHOLD})',
                  })))
            self.db._commit()
            cursor.close()
        except Exception as e:
            logger.warning(f"Failed to create blast radius finding: {e}")
