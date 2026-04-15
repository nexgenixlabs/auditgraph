"""
Phase 32: AI Security Strategy Advisor

Analyzes governance metrics, attack predictions, graph insights, and simulation
results to generate prioritized strategic recommendations that reduce identity
security risk.

4 recommendation types:
  - reduce_privileged_roles: too many identities with Owner/Contributor
  - rotate_credentials: high ratio of stale/expired credentials
  - remove_unused_identities: inactive identities with active role assignments
  - limit_guest_privileges: guests with elevated privileges
"""

import logging

logger = logging.getLogger(__name__)

RECOMMENDATION_TYPES = [
    'reduce_privileged_roles',
    'rotate_credentials',
    'remove_unused_identities',
    'limit_guest_privileges',
]

EFFORT_LEVELS = ('low', 'medium', 'high')
PRIORITY_LEVELS = ('critical', 'high', 'medium', 'low')

# Thresholds for generating recommendations
THRESHOLDS = {
    'privileged_ratio': 0.20,       # >20% identities with privileged roles
    'stale_credential_ratio': 0.15, # >15% identities with stale credentials
    'inactive_ratio': 0.10,         # >10% inactive identities with roles
    'guest_privilege_ratio': 0.05,  # >5% guests with elevated privileges
}


class SecurityStrategyAdvisor:
    """Generate strategic security recommendations from analyzed data."""

    def __init__(self, db):
        self.db = db

    def generate_security_strategy(self, connection_id, org_id):
        """Analyze all security data and generate prioritized recommendations."""
        recommendations = []

        # Step 1: Analyze governance metrics
        gov_recs = self._analyze_governance_metrics(connection_id, org_id)
        recommendations.extend(gov_recs)

        # Step 2: Analyze attack predictions
        pred_recs = self._analyze_attack_predictions(connection_id, org_id)
        recommendations.extend(pred_recs)

        # Step 3: Analyze graph insights
        graph_recs = self._analyze_graph_insights(connection_id, org_id)
        recommendations.extend(graph_recs)

        # Step 4: Analyze simulation results
        sim_recs = self._analyze_simulation_results(connection_id, org_id)
        recommendations.extend(sim_recs)

        # Deduplicate by type — keep highest priority
        deduped = {}
        for rec in recommendations:
            rtype = rec['recommendation_type']
            if rtype not in deduped or self._priority_rank(rec['priority']) > self._priority_rank(deduped[rtype]['priority']):
                deduped[rtype] = rec
        recommendations = list(deduped.values())

        # Sort by priority (critical first), then risk_reduction_score desc
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda r: (priority_order.get(r['priority'], 9), -r['risk_reduction_score']))

        if recommendations:
            self.db.save_strategy_recommendations(connection_id, org_id, recommendations)

        return recommendations

    def _priority_rank(self, priority):
        """Return numeric rank for priority (higher = more important)."""
        return {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(priority, 0)

    def _analyze_governance_metrics(self, connection_id, org_id):
        """Generate recommendations from governance metrics."""
        recs = []
        try:
            metrics = self.db.get_governance_metrics(limit=10, connection_id=connection_id)
            metrics_by_type = {m['metric_type']: m for m in metrics}

            # Check privilege drift rate
            drift = metrics_by_type.get('privilege_drift_rate')
            if drift and float(drift['metric_value']) > THRESHOLDS['privileged_ratio']:
                score = min(float(drift['metric_value']) * 100, 40)
                recs.append({
                    'recommendation_type': 'reduce_privileged_roles',
                    'risk_reduction_score': round(score, 1),
                    'implementation_effort': 'medium',
                    'priority': 'critical' if score > 30 else 'high',
                    'title': 'Reduce privileged service principals and users',
                    'description': f"Privilege drift rate is {float(drift['metric_value'])*100:.1f}%. "
                                   f"{drift['affected_count']} of {drift['sample_size']} identities "
                                   f"have changed role assignments. Review and remove unnecessary privileges.",
                    'metadata': {'source': 'governance_metrics', 'metric_value': float(drift['metric_value'])},
                })

            # Check stale credentials
            stale = metrics_by_type.get('stale_credentials_ratio')
            if stale and float(stale['metric_value']) > THRESHOLDS['stale_credential_ratio']:
                score = min(float(stale['metric_value']) * 80, 35)
                recs.append({
                    'recommendation_type': 'rotate_credentials',
                    'risk_reduction_score': round(score, 1),
                    'implementation_effort': 'low',
                    'priority': 'high' if score > 20 else 'medium',
                    'title': 'Rotate expired and expiring credentials',
                    'description': f"Stale credential ratio is {float(stale['metric_value'])*100:.1f}%. "
                                   f"{stale['affected_count']} identities have expired or expiring credentials. "
                                   f"Rotate these credentials to reduce attack surface.",
                    'metadata': {'source': 'governance_metrics', 'metric_value': float(stale['metric_value'])},
                })

            # Check inactive identities
            inactive = metrics_by_type.get('inactive_identity_ratio')
            if inactive and float(inactive['metric_value']) > THRESHOLDS['inactive_ratio']:
                score = min(float(inactive['metric_value']) * 90, 30)
                recs.append({
                    'recommendation_type': 'remove_unused_identities',
                    'risk_reduction_score': round(score, 1),
                    'implementation_effort': 'low',
                    'priority': 'high' if score > 15 else 'medium',
                    'title': 'Remove or disable unused identities',
                    'description': f"Inactive identity ratio is {float(inactive['metric_value'])*100:.1f}%. "
                                   f"{inactive['affected_count']} identities are inactive >90 days with active roles. "
                                   f"Disable or remove these identities to reduce dormant attack vectors.",
                    'metadata': {'source': 'governance_metrics', 'metric_value': float(inactive['metric_value'])},
                })

            # Check guest privileges
            guest = metrics_by_type.get('guest_privilege_ratio')
            if guest and float(guest['metric_value']) > THRESHOLDS['guest_privilege_ratio']:
                score = min(float(guest['metric_value']) * 120, 25)
                recs.append({
                    'recommendation_type': 'limit_guest_privileges',
                    'risk_reduction_score': round(score, 1),
                    'implementation_effort': 'medium',
                    'priority': 'high' if score > 15 else 'medium',
                    'title': 'Limit guest identity privileges',
                    'description': f"Guest privilege ratio is {float(guest['metric_value'])*100:.1f}%. "
                                   f"{guest['affected_count']} guest identities have elevated privileges. "
                                   f"Restrict guest access to read-only or remove unnecessary role assignments.",
                    'metadata': {'source': 'governance_metrics', 'metric_value': float(guest['metric_value'])},
                })
        except Exception as e:
            logger.warning(f"Governance metrics analysis failed: {e}")
        return recs

    def _analyze_attack_predictions(self, connection_id, org_id):
        """Generate recommendations from attack prediction data."""
        recs = []
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT prediction_type, COUNT(*) as cnt,
                       AVG(confidence_score) as avg_confidence
                FROM attack_predictions
                WHERE confidence_score > 0.7
                GROUP BY prediction_type
                ORDER BY avg_confidence DESC
                LIMIT 5
            """)
            rows = cursor.fetchall()
            cursor.close()

            for row in rows:
                pred_type, count, avg_conf = row
                if count >= 3 and avg_conf > 0.75:
                    recs.append({
                        'recommendation_type': 'reduce_privileged_roles',
                        'risk_reduction_score': round(min(avg_conf * 30, 25), 1),
                        'implementation_effort': 'high',
                        'priority': 'critical' if avg_conf > 0.9 else 'high',
                        'title': f'Address predicted {pred_type.replace("_", " ")} attacks',
                        'description': f"{count} high-confidence attack predictions of type "
                                       f"'{pred_type}' detected (avg confidence: {avg_conf:.0%}). "
                                       f"Reduce privileged roles to minimize attack surface.",
                        'metadata': {'source': 'attack_predictions', 'prediction_type': pred_type,
                                     'count': count, 'avg_confidence': float(avg_conf)},
                    })
        except Exception as e:
            logger.warning(f"Attack prediction analysis failed: {e}")
        return recs

    def _analyze_graph_insights(self, connection_id, org_id):
        """Generate recommendations from identity graph insights."""
        recs = []
        try:
            insights = self.db.get_graph_insights(limit=20, connection_id=connection_id)
            high_centrality = [i for i in insights if float(i.get('centrality_score', 0)) > 0.7]
            high_blast = [i for i in insights if int(i.get('blast_radius', 0)) > 10]

            if len(high_centrality) >= 3:
                score = min(len(high_centrality) * 5, 25)
                recs.append({
                    'recommendation_type': 'reduce_privileged_roles',
                    'risk_reduction_score': round(score, 1),
                    'implementation_effort': 'medium',
                    'priority': 'high',
                    'title': 'Reduce high-centrality identity privileges',
                    'description': f"{len(high_centrality)} identities have high centrality scores (>0.7). "
                                   f"These are critical nodes — compromising one affects many resources. "
                                   f"Apply least-privilege principles.",
                    'metadata': {'source': 'graph_insights', 'high_centrality_count': len(high_centrality)},
                })

            if len(high_blast) >= 2:
                score = min(len(high_blast) * 4, 20)
                recs.append({
                    'recommendation_type': 'reduce_privileged_roles',
                    'risk_reduction_score': round(score, 1),
                    'implementation_effort': 'high',
                    'priority': 'high',
                    'title': 'Limit blast radius of over-privileged identities',
                    'description': f"{len(high_blast)} identities have blast radius >10 resources. "
                                   f"Scope their access to specific resource groups.",
                    'metadata': {'source': 'graph_insights', 'high_blast_count': len(high_blast)},
                })
        except Exception as e:
            logger.warning(f"Graph insights analysis failed: {e}")
        return recs

    def _analyze_simulation_results(self, connection_id, org_id):
        """Generate recommendations from risk simulation data."""
        recs = []
        try:
            simulations = self.db.get_risk_simulations(limit=10)
            high_impact = [s for s in simulations if float(s.get('simulation_score', 0)) > 70]

            if high_impact:
                avg_score = sum(float(s['simulation_score']) for s in high_impact) / len(high_impact)
                recs.append({
                    'recommendation_type': 'rotate_credentials',
                    'risk_reduction_score': round(min(avg_score * 0.3, 20), 1),
                    'implementation_effort': 'low',
                    'priority': 'high' if avg_score > 80 else 'medium',
                    'title': 'Rotate credentials for high-impact simulation targets',
                    'description': f"{len(high_impact)} risk simulations show high impact scores "
                                   f"(avg: {avg_score:.0f}). Rotating credentials reduces exposure.",
                    'metadata': {'source': 'risk_simulations', 'high_impact_count': len(high_impact),
                                 'avg_score': round(avg_score, 1)},
                })
        except Exception as e:
            logger.warning(f"Simulation analysis failed: {e}")
        return recs
