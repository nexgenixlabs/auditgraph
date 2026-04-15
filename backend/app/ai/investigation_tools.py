"""AI Investigation Assistant — Tool Schemas & Executor (Phase 91)

Defines 5 tool schemas for Claude's native tool_use and an executor
that runs each tool locally against the DB / GraphAttackEngine.
"""

import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Tool Schemas (Anthropic tool_use format) ──────────────────────────────

INVESTIGATION_TOOLS = [
    {
        "name": "attack_paths",
        "description": (
            "Find privilege escalation and role-chaining attack paths for a specific identity. "
            "Returns paths showing how the identity could escalate privileges."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identity": {
                    "type": "string",
                    "description": "Identity search term: display name, identity_id, or object_id"
                }
            },
            "required": ["identity"]
        }
    },
    {
        "name": "blast_radius",
        "description": (
            "Compute the blast radius for a specific identity — how many subscriptions, "
            "resource groups, resources, and secrets it can reach via its role assignments."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identity": {
                    "type": "string",
                    "description": "Identity search term: display name, identity_id, or object_id"
                }
            },
            "required": ["identity"]
        }
    },
    {
        "name": "escalation_paths",
        "description": (
            "Find escalation paths for an identity and optionally simulate the impact "
            "of removing specific edges (remediation simulation)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identity": {
                    "type": "string",
                    "description": "Identity search term: display name, identity_id, or object_id"
                },
                "include_simulation": {
                    "type": "boolean",
                    "description": "If true, also simulate remediation by removing the highest-risk edge from each path"
                }
            },
            "required": ["identity"]
        }
    },
    {
        "name": "timeline",
        "description": (
            "Retrieve a chronological event timeline for a specific identity, "
            "including anomalies, risk score changes, PIM activations, SOAR actions, "
            "and remediation actions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identity": {
                    "type": "string",
                    "description": "Identity search term: display name, identity_id, or object_id"
                },
                "event_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter to specific event types: anomaly, risk_change, pim_activation, soar_action, remediation"
                },
                "from_date": {
                    "type": "string",
                    "description": "Start date filter (ISO format, e.g. 2025-01-01)"
                },
                "to_date": {
                    "type": "string",
                    "description": "End date filter (ISO format, e.g. 2025-12-31)"
                }
            },
            "required": ["identity"]
        }
    },
    {
        "name": "graph_diff",
        "description": (
            "Compare two graph snapshots to find added/removed/changed nodes and edges. "
            "Defaults to comparing the latest completed run against the previous one."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "run_id_a": {
                    "type": "integer",
                    "description": "First (older) discovery run ID. Defaults to previous completed run."
                },
                "run_id_b": {
                    "type": "integer",
                    "description": "Second (newer) discovery run ID. Defaults to latest completed run."
                }
            },
            "required": []
        }
    },
]


def resolve_identity(cursor, run_ids, search_term):
    """Multi-strategy identity resolution.

    Tries in order: exact identity_id → object_id → display_name exact → ILIKE substring.
    Returns dict with db_id, identity_id, display_name, identity_category or None.
    """
    if not run_ids or not search_term:
        return None

    search_term = search_term.strip()

    # Strategy 1: exact identity_id match
    cursor.execute("""
        SELECT id, identity_id, display_name, identity_category
        FROM identities
        WHERE identity_id = %s AND discovery_run_id = ANY(%s)
        ORDER BY discovery_run_id DESC LIMIT 1
    """, (search_term, run_ids))
    row = cursor.fetchone()
    if row:
        return _row_to_dict(row)

    # Strategy 2: object_id match
    cursor.execute("""
        SELECT id, identity_id, display_name, identity_category
        FROM identities
        WHERE object_id = %s AND discovery_run_id = ANY(%s)
        ORDER BY discovery_run_id DESC LIMIT 1
    """, (search_term, run_ids))
    row = cursor.fetchone()
    if row:
        return _row_to_dict(row)

    # Strategy 3: exact display_name match
    cursor.execute("""
        SELECT id, identity_id, display_name, identity_category
        FROM identities
        WHERE display_name = %s AND discovery_run_id = ANY(%s)
        ORDER BY discovery_run_id DESC LIMIT 1
    """, (search_term, run_ids))
    row = cursor.fetchone()
    if row:
        return _row_to_dict(row)

    # Strategy 4: ILIKE substring match
    cursor.execute("""
        SELECT id, identity_id, display_name, identity_category
        FROM identities
        WHERE display_name ILIKE %s AND discovery_run_id = ANY(%s)
        ORDER BY discovery_run_id DESC LIMIT 1
    """, (f'%{search_term}%', run_ids))
    row = cursor.fetchone()
    if row:
        return _row_to_dict(row)

    return None


def _row_to_dict(row):
    """Convert a tuple row to identity dict."""
    if isinstance(row, dict):
        return {
            'db_id': row.get('id'),
            'identity_id': row.get('identity_id'),
            'display_name': row.get('display_name'),
            'identity_category': row.get('identity_category'),
        }
    return {
        'db_id': row[0],
        'identity_id': row[1],
        'display_name': row[2],
        'identity_category': row[3],
    }


class InvestigationToolExecutor:
    """Executes investigation tools locally against DB and GraphAttackEngine."""

    def __init__(self, db, org_id, run_ids):
        self.db = db
        self.org_id = org_id
        self.run_ids = run_ids
        self._engine = None
        self._graph_built = False

    def execute(self, tool_name, tool_input):
        """Dispatch a tool call to the appropriate internal method."""
        dispatch = {
            'attack_paths': self._exec_attack_paths,
            'blast_radius': self._exec_blast_radius,
            'escalation_paths': self._exec_escalation_paths,
            'timeline': self._exec_timeline,
            'graph_diff': self._exec_graph_diff,
        }
        fn = dispatch.get(tool_name)
        if not fn:
            return {'error': f'Unknown tool: {tool_name}'}
        try:
            return fn(tool_input)
        except Exception as e:
            logger.error("Investigation tool %s failed: %s", tool_name, e, exc_info=True)
            return {'error': f'Tool execution failed: {type(e).__name__}: {e}'}

    def _get_engine(self, run_id):
        """Lazy-build GraphAttackEngine, reused across calls."""
        if self._engine is not None and self._graph_built:
            return self._engine
        try:
            from app.engines.graph_attack_engine import GraphAttackEngine
            self._engine = GraphAttackEngine(self.db)
            self._engine._build_graph(self.org_id, run_id)
            self._graph_built = True
            return self._engine
        except Exception as e:
            logger.error("Failed to build graph engine: %s", e)
            raise

    def _resolve(self, identity_str):
        """Resolve an identity search term to DB identity."""
        cursor = self.db.conn.cursor()
        result = resolve_identity(cursor, self.run_ids, identity_str)
        cursor.close()
        return result

    def _exec_attack_paths(self, params):
        identity_str = params.get('identity', '')
        resolved = self._resolve(identity_str)
        if not resolved:
            return {'error': f'Identity not found: {identity_str}', 'paths': []}

        run_id = self.run_ids[0] if self.run_ids else None
        if not run_id:
            return {'error': 'No completed discovery runs found', 'paths': []}

        engine = self._get_engine(run_id)
        paths = engine.find_escalation_paths(resolved['identity_id'])

        # Cap at 20 paths
        paths = paths[:20]

        return {
            'identity': resolved,
            'path_count': len(paths),
            'paths': paths,
        }

    def _exec_blast_radius(self, params):
        identity_str = params.get('identity', '')
        resolved = self._resolve(identity_str)
        if not resolved:
            return {'error': f'Identity not found: {identity_str}'}

        run_id = self.run_ids[0] if self.run_ids else None
        if not run_id:
            return {'error': 'No completed discovery runs found'}

        engine = self._get_engine(run_id)
        radius = engine.compute_blast_radius(resolved['identity_id'])

        return {
            'identity': resolved,
            'blast_radius': radius,
        }

    def _exec_escalation_paths(self, params):
        identity_str = params.get('identity', '')
        include_simulation = params.get('include_simulation', False)

        resolved = self._resolve(identity_str)
        if not resolved:
            return {'error': f'Identity not found: {identity_str}', 'paths': []}

        run_id = self.run_ids[0] if self.run_ids else None
        if not run_id:
            return {'error': 'No completed discovery runs found', 'paths': []}

        engine = self._get_engine(run_id)
        paths = engine.find_escalation_paths(resolved['identity_id'])
        paths = paths[:20]

        result = {
            'identity': resolved,
            'path_count': len(paths),
            'paths': paths,
        }

        if include_simulation and paths:
            # Simulate removing the highest-risk edge from each path
            edges_to_remove = []
            for p in paths[:5]:  # Simulate top 5 paths
                path_edges = p.get('attack_path_edges', [])
                if path_edges:
                    # Remove the first edge (closest to the identity)
                    edge = path_edges[0]
                    edges_to_remove.append({
                        'source_id': edge.get('source', edge.get('source_id', '')),
                        'target_id': edge.get('target', edge.get('target_id', '')),
                        'edge_type': edge.get('edge_type', edge.get('type', 'ASSIGNED_ROLE')),
                    })
            if edges_to_remove:
                try:
                    simulation = engine.simulate_remediation(resolved['identity_id'], edges_to_remove)
                    result['simulation'] = simulation
                except Exception as e:
                    logger.warning("Remediation simulation failed: %s", e)
                    result['simulation_error'] = str(e)

        return result

    def _exec_timeline(self, params):
        identity_str = params.get('identity', '')
        event_types = params.get('event_types')
        from_date = params.get('from_date')
        to_date = params.get('to_date')

        resolved = self._resolve(identity_str)
        if not resolved:
            return {'error': f'Identity not found: {identity_str}', 'events': []}

        db_id = resolved['db_id']
        identity_id = resolved['identity_id']
        cursor = self.db.conn.cursor()
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
                        'metadata': {'anomaly_type': r[4]},
                    })
            except Exception:
                try:
                    self.db._rollback()
                except Exception:
                    pass

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
                try:
                    self.db._rollback()
                except Exception:
                    pass

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
                try:
                    self.db._rollback()
                except Exception:
                    pass

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
                        'metadata': {'action_type': r[1], 'status': r[2]},
                    })
            except Exception:
                try:
                    self.db._rollback()
                except Exception:
                    pass

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
                try:
                    self.db._rollback()
                except Exception:
                    pass

        cursor.close()

        # Apply date filters
        if from_date:
            events = [e for e in events if e['timestamp'] and e['timestamp'] >= from_date]
        if to_date:
            events = [e for e in events if e['timestamp'] and e['timestamp'] <= to_date]

        # Sort by timestamp DESC, cap at 50
        events.sort(key=lambda e: e['timestamp'] or '', reverse=True)
        events = events[:50]

        return {
            'identity': resolved,
            'event_count': len(events),
            'events': events,
        }

    def _exec_graph_diff(self, params):
        run_id_a = params.get('run_id_a')
        run_id_b = params.get('run_id_b')

        cursor = self.db.conn.cursor()

        # Default to latest and previous runs
        if not run_id_b:
            cursor.execute("""
                SELECT id FROM discovery_runs
                WHERE status = 'completed' AND organization_id = %s
                ORDER BY id DESC LIMIT 1
            """, (self.org_id,))
            row = cursor.fetchone()
            run_id_b = row[0] if row else None

        if not run_id_a and run_id_b:
            cursor.execute("""
                SELECT id FROM discovery_runs
                WHERE status = 'completed' AND organization_id = %s AND id < %s
                ORDER BY id DESC LIMIT 1
            """, (self.org_id, run_id_b))
            row = cursor.fetchone()
            run_id_a = row[0] if row else None

        cursor.close()

        if not run_id_a or not run_id_b:
            return {
                'error': 'Need at least two completed runs to compare',
                'run_id_a': run_id_a,
                'run_id_b': run_id_b,
            }

        diff = self.db.get_graph_diff(self.org_id, run_id_a, run_id_b)

        # Truncate large diffs to fit context window
        for key in ('added_nodes', 'removed_nodes', 'changed_nodes', 'added_edges', 'removed_edges'):
            if key in diff and len(diff[key]) > 100:
                diff[key] = diff[key][:100]
                diff[f'{key}_truncated'] = True

        diff['run_id_a'] = run_id_a
        diff['run_id_b'] = run_id_b
        diff['summary'] = {
            'added_nodes': len(diff.get('added_nodes', [])),
            'removed_nodes': len(diff.get('removed_nodes', [])),
            'changed_nodes': len(diff.get('changed_nodes', [])),
            'added_edges': len(diff.get('added_edges', [])),
            'removed_edges': len(diff.get('removed_edges', [])),
        }

        return diff
