"""Phase 27: Identity Graph Intelligence Engine.

Computes structural IAM metrics — centrality, blast radius,
trust chain depth, resource reachability, privilege concentration —
to identify high-risk graph hubs and structural weaknesses.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Roles considered high-privilege for centrality weighting
HIGH_PRIVILEGE_ROLES = {
    'Owner', 'Contributor', 'User Access Administrator',
    'Global Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'Application Administrator',
}

# Risk thresholds based on composite graph score
RISK_THRESHOLDS = {
    'critical': 80,
    'high': 60,
    'medium': 40,
    'low': 0,
}


class GraphIntelligenceEngine:
    """Analyzes IAM graph structure to identify high-risk hubs and structural weaknesses."""

    def __init__(self, db):
        self.db = db

    def compute_graph_insights(self, connection_id, org_id):
        """Main entry: compute graph insights for all identities in a connection."""
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.info(f"No completed run for connection {connection_id}")
            return []

        identities = self._load_identities(run_id)
        if not identities:
            logger.info(f"No identities for run {run_id}")
            return []

        role_map = self._load_role_assignments(run_id)
        total_identities = len(identities)
        insights = []

        for identity in identities:
            iid = identity.get('identity_id', '')
            db_id = identity.get('id')
            roles = role_map.get(db_id, [])

            centrality = self._compute_centrality(roles, total_identities)
            blast = self._compute_blast_radius(roles)
            trust_chain = self._compute_trust_chain_length(identity, roles)
            reachability = self._compute_resource_reachability(roles)
            concentration = self._compute_privilege_concentration(roles)

            composite = self._composite_score(centrality, blast, trust_chain, reachability, concentration)
            risk_level = self._classify_risk(composite)
            summary = self._generate_summary(identity, centrality, blast, trust_chain, reachability, concentration, risk_level)

            insights.append({
                'organization_id': org_id,
                'cloud_connection_id': connection_id,
                'identity_id': iid,
                'identity_name': identity.get('display_name', ''),
                'identity_category': identity.get('identity_category', ''),
                'centrality_score': round(centrality, 3),
                'blast_radius': blast,
                'trust_chain_length': trust_chain,
                'resource_reachability': reachability,
                'privilege_concentration': round(concentration, 3),
                'risk_level': risk_level,
                'insight_summary': summary,
                'metadata': {
                    'composite_score': round(composite, 1),
                    'role_count': len(roles),
                    'high_priv_roles': [r['role_name'] for r in roles if r.get('role_name') in HIGH_PRIVILEGE_ROLES],
                },
            })

        if insights:
            self.db.save_graph_insights(connection_id, org_id, insights)
            logger.info(f"Graph intelligence: saved {len(insights)} insights for connection {connection_id}")

        return insights

    # ── Metric Computations ──────────────────────────────────────────────

    def _compute_centrality(self, roles, total_identities):
        """Identity centrality: weighted role count / total identities.
        High-privilege roles count double."""
        if total_identities == 0:
            return 0.0
        weighted = 0
        for r in roles:
            if r.get('role_name') in HIGH_PRIVILEGE_ROLES:
                weighted += 2
            else:
                weighted += 1
        return min(weighted / max(total_identities * 0.1, 1), 1.0)

    def _compute_blast_radius(self, roles):
        """Number of unique scopes (subscriptions, resource groups, resources) reachable."""
        scopes = set()
        for r in roles:
            scope = r.get('scope', '')
            if scope:
                scopes.add(scope)
                # Also count parent scopes
                parts = scope.strip('/').split('/')
                for i in range(2, len(parts) + 1, 2):
                    scopes.add('/' + '/'.join(parts[:i]))
        return len(scopes)

    def _compute_trust_chain_length(self, identity, roles):
        """Trust chain depth: subscription-level=3, RG-level=2, resource-level=1.
        Guests and SPNs add +1 for federated trust."""
        max_depth = 0
        for r in roles:
            scope = r.get('scope', '')
            parts = scope.strip('/').split('/') if scope else []
            if len(parts) <= 2:
                depth = 3  # subscription level
            elif len(parts) <= 4:
                depth = 2  # resource group level
            else:
                depth = 1  # resource level
            max_depth = max(max_depth, depth)

        category = identity.get('identity_category', '')
        if category in ('guest', 'service_principal'):
            max_depth += 1
        return max_depth

    def _compute_resource_reachability(self, roles):
        """Count distinct resource-level scopes accessible."""
        resources = set()
        for r in roles:
            scope = r.get('scope', '')
            parts = scope.strip('/').split('/') if scope else []
            if len(parts) >= 8:
                resources.add(scope)
            elif len(parts) >= 4:
                # RG-level scope means access to all resources within
                resources.add(scope + '/*')
            elif len(parts) >= 2:
                # Subscription-level scope
                resources.add(scope + '/**')
        return len(resources)

    def _compute_privilege_concentration(self, roles):
        """Ratio of high-privilege roles to total roles."""
        if not roles:
            return 0.0
        high_count = sum(1 for r in roles if r.get('role_name') in HIGH_PRIVILEGE_ROLES)
        return high_count / len(roles)

    def _composite_score(self, centrality, blast, trust_chain, reachability, concentration):
        """Weighted composite score (0-100)."""
        return min(100, (
            centrality * 30 +
            min(blast / 20, 1.0) * 25 +
            min(trust_chain / 5, 1.0) * 15 +
            min(reachability / 15, 1.0) * 15 +
            concentration * 15
        ) * 100 / 100)

    def _classify_risk(self, composite_score):
        """Classify risk level from composite score."""
        for level, threshold in sorted(RISK_THRESHOLDS.items(), key=lambda x: -x[1]):
            if composite_score >= threshold:
                return level
        return 'low'

    def _generate_summary(self, identity, centrality, blast, trust_chain, reachability, concentration, risk_level):
        """Generate human-readable insight summary."""
        name = identity.get('display_name', identity.get('identity_id', 'Unknown'))
        parts = [f"{name}: {risk_level.upper()} graph risk."]

        if centrality >= 0.7:
            parts.append(f"High centrality ({centrality:.2f}) — hub identity in the access graph.")
        if blast >= 10:
            parts.append(f"Large blast radius ({blast} scopes) — compromise affects many resources.")
        if trust_chain >= 4:
            parts.append(f"Long trust chain (depth {trust_chain}) — indirect trust path increases exposure.")
        if reachability >= 8:
            parts.append(f"High resource reachability ({reachability} resources) — wide resource access footprint.")
        if concentration >= 0.5:
            parts.append(f"Privilege concentration ({concentration:.0%}) — disproportionate high-privilege roles.")

        return " ".join(parts)

    # ── Data Loading ─────────────────────────────────────────────────────

    def _get_latest_run_id(self, connection_id):
        """Get the latest completed discovery run for a connection."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT id FROM discovery_runs WHERE cloud_connection_id = %s AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (connection_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row['id'] if row else None

    def _load_identities(self, run_id):
        """Load all identities for a discovery run."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT id, identity_id, display_name, identity_category, activity_status "
            "FROM identities WHERE discovery_run_id = %s",
            (run_id,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    def _load_role_assignments(self, run_id):
        """Load role assignments grouped by identity_db_id."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT identity_db_id, role_name, scope FROM role_assignments WHERE discovery_run_id = %s",
            (run_id,)
        )
        role_map = {}
        for row in cursor.fetchall():
            db_id = row['identity_db_id']
            if db_id not in role_map:
                role_map[db_id] = []
            role_map[db_id].append(dict(row))
        cursor.close()
        return role_map
