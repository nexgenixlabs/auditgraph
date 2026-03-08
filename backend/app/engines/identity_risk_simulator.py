"""Phase 29: Identity Risk Simulation Engine.

Simulates identity compromise, credential leak, and privilege grant
scenarios to evaluate security impact — exposed resources, reachable
identities, and privilege escalation paths.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Roles that grant escalation capability
ESCALATION_ROLES = {
    'Owner', 'User Access Administrator',
    'Global Administrator', 'Privileged Role Administrator',
}

# Broad-access privileged roles
HIGH_PRIVILEGE_ROLES = {
    'Owner', 'Contributor', 'User Access Administrator',
    'Global Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'Application Administrator',
}

RISK_THRESHOLDS = {'critical': 80, 'high': 60, 'medium': 40, 'low': 0}

# Simulation type handlers
SIMULATION_TYPES = ('identity_compromise', 'credential_leak', 'privilege_grant')


class IdentityRiskSimulator:
    """Simulates identity compromise scenarios and evaluates blast radius."""

    def __init__(self, db):
        self.db = db

    def run_identity_risk_simulation(self, identity_id, simulation_type, org_id, connection_id=None):
        """Run a risk simulation for a specific identity and scenario type."""
        if simulation_type not in SIMULATION_TYPES:
            raise ValueError(f"Invalid simulation_type: {simulation_type}")

        identity = self._find_identity(identity_id, connection_id)
        if not identity:
            return None

        run_id = identity.get('discovery_run_id')
        db_id = identity.get('id')
        roles = self._load_roles_for_identity(db_id, run_id)

        if simulation_type == 'identity_compromise':
            result = self._simulate_compromise(identity, roles, run_id)
        elif simulation_type == 'credential_leak':
            result = self._simulate_credential_leak(identity, roles, run_id)
        elif simulation_type == 'privilege_grant':
            result = self._simulate_privilege_grant(identity, roles, run_id)
        else:
            result = self._simulate_compromise(identity, roles, run_id)

        score = self._compute_simulation_score(result)
        risk_level = self._classify_risk(score)
        summary = self._generate_impact_summary(identity, simulation_type, result, risk_level)

        sim = {
            'organization_id': org_id,
            'cloud_connection_id': connection_id or identity.get('cloud_connection_id'),
            'identity_id': identity_id,
            'identity_name': identity.get('display_name', ''),
            'identity_category': identity.get('identity_category', ''),
            'simulation_type': simulation_type,
            'exposed_resources': result['exposed_resources'],
            'exposed_identities': result['exposed_identities'],
            'escalation_paths': result['escalation_paths'],
            'simulation_score': round(score, 1),
            'risk_level': risk_level,
            'impact_summary': summary,
            'metadata': {
                'role_count': len(roles),
                'high_priv_roles': result.get('high_priv_roles', []),
                'escalation_roles': result.get('escalation_roles', []),
                'scope_types': result.get('scope_types', {}),
            },
        }

        self.db.save_risk_simulation(org_id, sim)
        return sim

    # ── Simulation Types ─────────────────────────────────────────────────

    def _simulate_compromise(self, identity, roles, run_id):
        """Full identity compromise: all roles and resources accessible."""
        exposed_resources = self._count_exposed_resources(roles)
        exposed_identities = self._count_exposed_identities(roles, run_id)
        escalation_paths = self._count_escalation_paths(roles)
        high_priv = [r['role_name'] for r in roles if r.get('role_name') in HIGH_PRIVILEGE_ROLES]
        esc_roles = [r['role_name'] for r in roles if r.get('role_name') in ESCALATION_ROLES]
        scope_types = self._classify_scopes(roles)

        return {
            'exposed_resources': exposed_resources,
            'exposed_identities': exposed_identities,
            'escalation_paths': escalation_paths,
            'high_priv_roles': list(set(high_priv)),
            'escalation_roles': list(set(esc_roles)),
            'scope_types': scope_types,
        }

    def _simulate_credential_leak(self, identity, roles, run_id):
        """Credential leak: limited to direct role access (no escalation)."""
        exposed_resources = self._count_exposed_resources(roles)
        # Credential leak gives direct access but not escalation capability
        exposed_identities = 0
        escalation_paths = 0
        high_priv = [r['role_name'] for r in roles if r.get('role_name') in HIGH_PRIVILEGE_ROLES]
        scope_types = self._classify_scopes(roles)

        return {
            'exposed_resources': exposed_resources,
            'exposed_identities': exposed_identities,
            'escalation_paths': escalation_paths,
            'high_priv_roles': list(set(high_priv)),
            'escalation_roles': [],
            'scope_types': scope_types,
        }

    def _simulate_privilege_grant(self, identity, roles, run_id):
        """Privilege grant: simulate adding Owner role to identity."""
        # Start with current access
        base = self._simulate_compromise(identity, roles, run_id)

        # Simulate granting Owner at broadest existing scope
        broadest_scope = self._get_broadest_scope(roles)
        if broadest_scope:
            # Count all resources under broadest scope
            additional = self._count_resources_at_scope(broadest_scope, run_id)
            base['exposed_resources'] += additional
            base['escalation_paths'] += 1
            if 'Owner' not in base['high_priv_roles']:
                base['high_priv_roles'].append('Owner')
            if 'Owner' not in base['escalation_roles']:
                base['escalation_roles'].append('Owner')

        return base

    # ── Impact Calculations ──────────────────────────────────────────────

    def _count_exposed_resources(self, roles):
        """Count unique resource scopes accessible."""
        scopes = set()
        for r in roles:
            scope = r.get('scope', '')
            if scope:
                scopes.add(scope)
        return len(scopes)

    def _count_exposed_identities(self, roles, run_id):
        """Count identities that could be affected via escalation roles."""
        has_escalation = any(r.get('role_name') in ESCALATION_ROLES for r in roles)
        if not has_escalation:
            return 0
        cursor = self.db._cursor()
        cursor.execute("SELECT COUNT(*) AS cnt FROM identities WHERE discovery_run_id = %s", (run_id,))
        row = cursor.fetchone()
        cursor.close()
        return int(row['cnt']) if row else 0

    def _count_escalation_paths(self, roles):
        """Count roles that enable privilege escalation."""
        return sum(1 for r in roles if r.get('role_name') in ESCALATION_ROLES)

    def _classify_scopes(self, roles):
        """Classify scopes by type (subscription/rg/resource)."""
        types = {'subscription': 0, 'resource_group': 0, 'resource': 0}
        for r in roles:
            scope = r.get('scope', '')
            parts = scope.strip('/').split('/') if scope else []
            if len(parts) <= 2:
                types['subscription'] += 1
            elif len(parts) <= 4:
                types['resource_group'] += 1
            else:
                types['resource'] += 1
        return types

    def _get_broadest_scope(self, roles):
        """Get the broadest (shortest path) scope from roles."""
        broadest = None
        min_depth = 999
        for r in roles:
            scope = r.get('scope', '')
            if scope:
                depth = len(scope.strip('/').split('/'))
                if depth < min_depth:
                    min_depth = depth
                    broadest = scope
        return broadest

    def _count_resources_at_scope(self, scope, run_id):
        """Count role assignments at or under a scope."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT COUNT(DISTINCT scope) AS cnt FROM role_assignments "
            "WHERE discovery_run_id = %s AND scope LIKE %s",
            (run_id, scope + '%')
        )
        row = cursor.fetchone()
        cursor.close()
        return int(row['cnt']) if row else 0

    # ── Scoring ──────────────────────────────────────────────────────────

    def _compute_simulation_score(self, result):
        """Compute simulation score (0-100) from impact metrics."""
        resource_score = min(result['exposed_resources'] / 20, 1.0) * 40
        identity_score = min(result['exposed_identities'] / 50, 1.0) * 30
        escalation_score = min(result['escalation_paths'] / 3, 1.0) * 30
        return min(resource_score + identity_score + escalation_score, 100)

    def _classify_risk(self, score):
        """Classify risk level from simulation score."""
        for level, threshold in sorted(RISK_THRESHOLDS.items(), key=lambda x: -x[1]):
            if score >= threshold:
                return level
        return 'low'

    def _generate_impact_summary(self, identity, sim_type, result, risk_level):
        """Generate human-readable impact summary."""
        name = identity.get('display_name', identity.get('identity_id', 'Unknown'))
        type_label = sim_type.replace('_', ' ')
        parts = [f"{type_label.title()} simulation for {name}: {risk_level.upper()} impact."]

        if result['exposed_resources'] > 0:
            parts.append(f"Exposed resources: {result['exposed_resources']}.")
        if result['exposed_identities'] > 0:
            parts.append(f"Potentially affected identities: {result['exposed_identities']}.")
        if result['escalation_paths'] > 0:
            parts.append(f"Privilege escalation paths: {result['escalation_paths']}.")
        if result.get('high_priv_roles'):
            parts.append(f"High-privilege roles: {', '.join(result['high_priv_roles'])}.")

        return " ".join(parts)

    # ── Data Loading ─────────────────────────────────────────────────────

    def _find_identity(self, identity_id, connection_id=None):
        """Find identity by identity_id."""
        cursor = self.db._cursor()
        if connection_id:
            cursor.execute(
                "SELECT i.id, i.identity_id, i.display_name, i.identity_category, "
                "i.activity_status, i.credential_status, i.discovery_run_id, "
                "dr.cloud_connection_id "
                "FROM identities i "
                "JOIN discovery_runs dr ON dr.id = i.discovery_run_id "
                "WHERE i.identity_id = %s AND dr.cloud_connection_id = %s "
                "ORDER BY i.discovery_run_id DESC LIMIT 1",
                (identity_id, connection_id)
            )
        else:
            cursor.execute(
                "SELECT i.id, i.identity_id, i.display_name, i.identity_category, "
                "i.activity_status, i.credential_status, i.discovery_run_id, "
                "dr.cloud_connection_id "
                "FROM identities i "
                "JOIN discovery_runs dr ON dr.id = i.discovery_run_id "
                "WHERE i.identity_id = %s "
                "ORDER BY i.discovery_run_id DESC LIMIT 1",
                (identity_id,)
            )
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def _load_roles_for_identity(self, db_id, run_id):
        """Load role assignments for a specific identity."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT role_name, scope FROM role_assignments "
            "WHERE identity_db_id = %s AND discovery_run_id = %s",
            (db_id, run_id)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows
