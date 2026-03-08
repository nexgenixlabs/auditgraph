"""
Phase 33: Identity Security Command Center Engine

Computes a real-time composite identity security posture by aggregating:
  - Threat events (open incidents, severity weighting)
  - Attack predictions (high-confidence predictions)
  - Governance violations (pending governance actions)
  - Strategy recommendations (open recommendations)
  - Active identity count

Risk score formula (0-100, lower is better):
  incident_weight * 25 + prediction_weight * 20 +
  governance_weight * 20 + strategy_weight * 15 +
  threat_weight * 20
"""

import logging

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    'critical': 1.0,
    'high': 0.7,
    'medium': 0.4,
    'low': 0.1,
}

RISK_LABELS = {
    (0, 20): 'excellent',
    (20, 40): 'good',
    (40, 60): 'fair',
    (60, 80): 'poor',
    (80, 101): 'critical',
}


class SecurityCommandCenter:
    """Compute real-time identity security posture."""

    def __init__(self, db):
        self.db = db

    def compute_security_posture(self, connection_id, org_id):
        """Aggregate all security signals into a composite posture snapshot."""
        incident_data = self._aggregate_incidents(connection_id)
        prediction_data = self._aggregate_predictions(connection_id)
        governance_data = self._aggregate_governance(connection_id)
        strategy_data = self._aggregate_strategy(connection_id)
        threat_data = self._aggregate_threats(connection_id)
        identity_count = self._count_active_identities(connection_id)

        # Compute composite risk score (0-100)
        risk_score = self._compute_risk_score(
            incident_data, prediction_data, governance_data,
            strategy_data, threat_data, identity_count
        )

        posture = {
            'risk_score': round(risk_score, 1),
            'incident_count': incident_data['count'],
            'prediction_count': prediction_data['count'],
            'governance_violation_count': governance_data['count'],
            'strategy_recommendation_count': strategy_data['count'],
            'threat_event_count': threat_data['count'],
            'active_identity_count': identity_count,
            'metadata': {
                'risk_label': self._risk_label(risk_score),
                'incident_severity': incident_data.get('severity_breakdown', {}),
                'prediction_avg_confidence': prediction_data.get('avg_confidence', 0),
                'governance_by_action': governance_data.get('by_action', {}),
                'strategy_by_priority': strategy_data.get('by_priority', {}),
            },
        }

        self.db.save_security_posture(connection_id, org_id, posture)
        return posture

    def _aggregate_incidents(self, connection_id):
        """Count open incidents by severity."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT severity, COUNT(*) FROM security_incidents
                WHERE status IN ('open', 'investigating')
                GROUP BY severity
            """)
            rows = cursor.fetchall()
        except Exception:
            rows = []
        cursor.close()
        breakdown = {r[0]: r[1] for r in rows}
        total = sum(breakdown.values())
        return {'count': total, 'severity_breakdown': breakdown}

    def _aggregate_predictions(self, connection_id):
        """Count high-confidence attack predictions."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*), COALESCE(AVG(confidence_score), 0)
                FROM attack_predictions
                WHERE confidence_score > 0.5
            """)
            row = cursor.fetchone()
        except Exception:
            row = (0, 0)
        cursor.close()
        return {'count': row[0] or 0, 'avg_confidence': round(float(row[1] or 0), 2)}

    def _aggregate_governance(self, connection_id):
        """Count pending governance violations."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT governance_action, COUNT(*) FROM identity_governance_actions
                WHERE status = 'pending'
                GROUP BY governance_action
            """)
            rows = cursor.fetchall()
        except Exception:
            rows = []
        cursor.close()
        by_action = {r[0]: r[1] for r in rows}
        total = sum(by_action.values())
        return {'count': total, 'by_action': by_action}

    def _aggregate_strategy(self, connection_id):
        """Count open strategy recommendations by priority."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT priority, COUNT(*) FROM security_strategy_recommendations
                WHERE status = 'open'
                GROUP BY priority
            """)
            rows = cursor.fetchall()
        except Exception:
            rows = []
        cursor.close()
        by_priority = {r[0]: r[1] for r in rows}
        total = sum(by_priority.values())
        return {'count': total, 'by_priority': by_priority}

    def _aggregate_threats(self, connection_id):
        """Count open threat events."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM threat_events
                WHERE status IN ('open', 'investigating')
            """)
            row = cursor.fetchone()
        except Exception:
            row = (0,)
        cursor.close()
        return {'count': row[0] or 0}

    def _count_active_identities(self, connection_id):
        """Count identities in latest completed run for this connection."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM identities i
                JOIN discovery_runs dr ON i.discovery_run_id = dr.id
                WHERE dr.cloud_connection_id = %s AND dr.status = 'completed'
                AND dr.id = (SELECT MAX(id) FROM discovery_runs
                             WHERE cloud_connection_id = %s AND status = 'completed')
            """, (connection_id, connection_id))
            row = cursor.fetchone()
        except Exception:
            row = (0,)
        cursor.close()
        return row[0] or 0

    def _compute_risk_score(self, incidents, predictions, governance, strategy, threats, identity_count):
        """Compute composite risk score 0-100 (lower is better)."""
        # Normalize each signal to 0-20 range, then sum
        # Incidents: weighted by severity, max 20
        incident_score = 0
        for sev, count in incidents.get('severity_breakdown', {}).items():
            weight = SEVERITY_WEIGHTS.get(sev, 0.2)
            incident_score += count * weight * 5
        incident_score = min(incident_score, 25)

        # Predictions: based on count and confidence
        pred_count = predictions['count']
        avg_conf = predictions.get('avg_confidence', 0)
        prediction_score = min(pred_count * avg_conf * 4, 20)

        # Governance violations: count-based
        gov_count = governance['count']
        governance_score = min(gov_count * 2, 20)

        # Strategy recommendations: open count
        strat_count = strategy['count']
        strategy_score = min(strat_count * 3, 15)

        # Threats: open count
        threat_count = threats['count']
        threat_score = min(threat_count * 4, 20)

        total = incident_score + prediction_score + governance_score + strategy_score + threat_score
        return min(total, 100)

    def _risk_label(self, score):
        """Return human-readable risk label."""
        for (lo, hi), label in RISK_LABELS.items():
            if lo <= score < hi:
                return label
        return 'critical'
