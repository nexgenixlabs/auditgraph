"""
Phase 8: Privilege Escalation Detection

Detects identities that can escalate privileges through IAM relationships
by traversing the graph model and analyzing permissions. Detected escalation
paths are stored as risk findings with escalation_path metadata.
"""

import logging

logger = logging.getLogger(__name__)


class EscalationDetector:
    """Detects privilege escalation paths using graph traversal and permission analysis."""

    def __init__(self, db):
        self.db = db

    def detect_privilege_escalation(self, connection_id, org_id):
        """Run all escalation detection rules for a cloud connection.

        Returns list of escalation findings saved to risk_findings.
        """
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.debug(f"No completed run for connection {connection_id}, skipping escalation detection")
            return []

        # Load escalation rules from risk_rules
        rules = self._get_escalation_rules()

        findings = []
        for rule in rules:
            detector = DETECTORS.get(rule['rule_key'])
            if detector:
                try:
                    rule_findings = detector(self, run_id, connection_id, org_id, rule)
                    findings.extend(rule_findings)
                except Exception as e:
                    logger.error(f"Escalation detector '{rule['rule_key']}' failed: {e}")

        if findings:
            self.db.save_risk_findings(connection_id, org_id, findings)
            logger.info(f"Escalation detection: {len(findings)} finding(s) for connection {connection_id}")
        else:
            logger.debug(f"Escalation detection: no findings for connection {connection_id}")

        return findings

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

    def _get_escalation_rules(self):
        """Get enabled escalation-type risk rules."""
        rules = self.db.get_risk_rules(enabled_only=True)
        return [r for r in rules if r['rule_key'] in DETECTORS]

    def _make_finding(self, rule, identity_id, escalation_path, metadata=None):
        """Build a finding dict with escalation_path in metadata."""
        meta = metadata or {}
        meta['escalation_path'] = escalation_path
        meta['finding_category'] = 'privilege_escalation'
        return {
            'rule_id': rule['id'],
            'severity': rule['severity'],
            'identity_id': identity_id,
            'resource_id': None,
            'metadata': meta,
        }

    def get_identity_escalation_paths(self, identity_external_id):
        """Get all escalation paths for an identity via graph traversal.

        Traverses: identity -> assigned_role -> role -> grants_access -> resource
        and checks for escalation-capable permissions.
        """
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        # Get full access paths through the graph
        cursor.execute("""
            SELECT
                ident.external_id AS identity_id,
                ident.display_name AS identity_name,
                ident.metadata AS identity_metadata,
                role_node.display_name AS role_name,
                e1.metadata AS assignment_metadata,
                res.external_id AS resource_id,
                res.display_name AS resource_name,
                e2.metadata AS access_metadata
            FROM graph_nodes ident
            JOIN graph_edges e1 ON e1.source_node_id = ident.id AND e1.edge_type = 'assigned_role'
            JOIN graph_nodes role_node ON role_node.id = e1.target_node_id
            JOIN graph_edges e2 ON e2.source_node_id = role_node.id AND e2.edge_type = 'grants_access'
            JOIN graph_nodes res ON res.id = e2.target_node_id
            WHERE ident.node_type = 'identity'
              AND ident.external_id = %s
            ORDER BY role_node.display_name
        """, (identity_external_id,))
        paths = [dict(r) for r in cursor.fetchall()]
        cursor.close()

        # Build structured escalation path list
        result = []
        for p in paths:
            path_nodes = [
                p['identity_name'] or p['identity_id'],
                p['role_name'],
                p['resource_name'] or p['resource_id'],
            ]
            result.append({
                'identity': p['identity_id'],
                'identity_name': p['identity_name'],
                'role': p['role_name'],
                'resource': p['resource_id'],
                'resource_name': p['resource_name'],
                'path_nodes': path_nodes,
            })

        return result


# ── Escalation Detector Registry ────────────────────────────────────────────

DETECTORS = {}


def _register(rule_key):
    """Decorator to register an escalation detector for a rule_key."""
    def decorator(fn):
        DETECTORS[rule_key] = fn
        return fn
    return decorator


# ── Rule 1: Identity Can Assign Owner ────────────────────────────────────────

@_register('identity_can_assign_owner')
def _detect_can_assign_owner(self, run_id, connection_id, org_id, rule):
    """Detect identities with Microsoft.Authorization/roleAssignments/write permission.

    These identities can assign any role including Owner, enabling full escalation.
    """
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category,
               ra.role_name, ra.scope
        FROM identities i
        JOIN role_assignments ra ON ra.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
          AND EXISTS (
              SELECT 1 FROM permissions p
              WHERE p.identity_db_id = i.id
                AND p.permission_name LIKE '%%Microsoft.Authorization/roleAssignments/write%%'
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    # Deduplicate by identity
    seen = set()
    findings = []
    for r in rows:
        if r['identity_id'] in seen:
            continue
        seen.add(r['identity_id'])
        escalation_path = [
            r['display_name'] or r['identity_id'],
            'RoleAssignment/write',
            'Owner (potential)',
        ]
        findings.append(self._make_finding(rule, r['identity_id'], escalation_path, {
            'display_name': r['display_name'],
            'identity_category': r['identity_category'],
            'reason': 'Identity can assign Owner role via roleAssignments/write permission',
        }))
    return findings


# ── Rule 2: Service Principal Owner ──────────────────────────────────────────

@_register('service_principal_owner')
def _detect_spn_owner(self, run_id, connection_id, org_id, rule):
    """Detect service principals with Owner role — high-privilege non-human access."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, ra.role_name, ra.scope
        FROM identities i
        JOIN role_assignments ra ON ra.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND ra.role_name = 'Owner'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    seen = set()
    findings = []
    for r in rows:
        if r['identity_id'] in seen:
            continue
        seen.add(r['identity_id'])
        escalation_path = [
            r['display_name'] or r['identity_id'],
            'Owner',
            r['scope'] or 'subscription',
        ]
        findings.append(self._make_finding(rule, r['identity_id'], escalation_path, {
            'display_name': r['display_name'],
            'identity_category': 'service_principal',
            'scope': r['scope'],
            'reason': 'Service principal has Owner role assignment',
        }))
    return findings


# ── Rule 3: Managed Identity Contributor ─────────────────────────────────────

@_register('managed_identity_contributor')
def _detect_mi_contributor(self, run_id, connection_id, org_id, rule):
    """Detect managed identities with Contributor or Owner roles."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category, ra.role_name, ra.scope
        FROM identities i
        JOIN role_assignments ra ON ra.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
          AND i.identity_category IN ('managed_identity_system', 'managed_identity_user')
          AND ra.role_name IN ('Contributor', 'Owner')
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    seen = set()
    findings = []
    for r in rows:
        if r['identity_id'] in seen:
            continue
        seen.add(r['identity_id'])
        escalation_path = [
            r['display_name'] or r['identity_id'],
            r['role_name'],
            r['scope'] or 'subscription',
        ]
        findings.append(self._make_finding(rule, r['identity_id'], escalation_path, {
            'display_name': r['display_name'],
            'identity_category': r['identity_category'],
            'role_name': r['role_name'],
            'scope': r['scope'],
            'reason': f'Managed identity has {r["role_name"]} role assignment',
        }))
    return findings


# ── Rule 4: Identity Can Modify Role Definitions ────────────────────────────

@_register('identity_can_modify_role_definitions')
def _detect_can_modify_roles(self, run_id, connection_id, org_id, rule):
    """Detect identities with Microsoft.Authorization/roleDefinitions/write permission.

    These identities can create or modify custom roles, enabling privilege escalation.
    """
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND EXISTS (
              SELECT 1 FROM permissions p
              WHERE p.identity_db_id = i.id
                AND p.permission_name LIKE '%%Microsoft.Authorization/roleDefinitions/write%%'
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    findings = []
    for r in rows:
        escalation_path = [
            r['display_name'] or r['identity_id'],
            'RoleDefinitions/write',
            'Custom Role (create/modify)',
        ]
        findings.append(self._make_finding(rule, r['identity_id'], escalation_path, {
            'display_name': r['display_name'],
            'identity_category': r['identity_category'],
            'reason': 'Identity can create or modify custom role definitions',
        }))
    return findings
