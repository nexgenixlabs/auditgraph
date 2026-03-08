"""Phase 26: Identity Attack Prediction.

Predicts which identities are most likely to be compromised based on
behavioral patterns, privilege exposure, credential hygiene, anomaly
signals, and attack path reachability.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Risk level thresholds
RISK_THRESHOLDS = {
    'critical': 80,
    'high': 60,
    'medium': 40,
    'low': 0,
}

# Privileged roles that increase attack surface
HIGH_PRIVILEGE_ROLES = {
    'Owner', 'Contributor', 'Global Administrator',
    'Privileged Role Administrator', 'User Access Administrator',
    'Application Administrator', 'Security Administrator',
}

# Score weights for each risk driver
DRIVER_WEIGHTS = {
    'privileged_roles': 25,
    'credential_age': 15,
    'anomaly_frequency': 20,
    'attack_path_exposure': 20,
    'activity_status': 10,
    'credential_count': 10,
}


class AttackPredictor:
    """Predicts identity attack likelihood."""

    def __init__(self, db):
        self.db = db

    def predict_identity_attacks(self, connection_id, org_id):
        """Generate attack predictions for identities in a connection.

        Steps:
        1. Load identity data from latest discovery run
        2. Analyze privilege exposure
        3. Analyze anomaly signals
        4. Analyze attack path exposure
        5. Compute prediction scores
        6. Save prediction records

        Args:
            connection_id: Cloud connection ID
            org_id: Organization ID

        Returns:
            List of prediction dicts.
        """
        # 1. Load identities
        identities = self._load_identities(connection_id)
        if not identities:
            return []

        predictions = []
        for identity in identities:
            identity_id = identity.get('identity_id', '')
            if not identity_id:
                continue

            # 2-4. Analyze risk drivers
            drivers = self._analyze_risk_drivers(identity)

            # 5. Compute prediction score (0-100)
            score = self._compute_prediction_score(drivers)
            risk_level = self._score_to_risk_level(score)
            confidence = self._compute_confidence(drivers)

            # 6. Build recommended actions
            actions = self._generate_recommendations(identity, drivers, risk_level)

            prediction = {
                'organization_id': org_id,
                'identity_id': identity_id,
                'prediction_score': round(score, 1),
                'risk_level': risk_level,
                'risk_drivers': drivers,
                'recommended_actions': actions,
                'confidence': round(confidence, 2),
            }
            predictions.append(prediction)

        # Sort by score descending
        predictions.sort(key=lambda p: p['prediction_score'], reverse=True)

        # Save predictions
        saved = []
        for pred in predictions:
            try:
                result = self.db.save_attack_prediction(pred)
                if result:
                    saved.append(result)
            except Exception as e:
                logger.warning(f"Failed to save prediction for {pred['identity_id']}: {e}")

        logger.info(
            f"Attack predictions for connection {connection_id}: "
            f"{len(saved)} prediction(s), "
            f"{sum(1 for p in saved if p.get('risk_level') in ('critical', 'high'))} high/critical"
        )
        return saved

    def _load_identities(self, connection_id):
        """Load identities from the latest completed discovery run."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       i.risk_level, i.risk_score, i.activity_status,
                       i.credential_status, i.credential_count,
                       i.credential_expiration, i.last_sign_in, i.id as db_id
                FROM identities i
                JOIN discovery_runs dr ON i.discovery_run_id = dr.id
                WHERE dr.cloud_connection_id = %s AND dr.status = 'completed'
                  AND dr.id = (
                      SELECT MAX(id) FROM discovery_runs
                      WHERE cloud_connection_id = %s AND status = 'completed'
                  )
                ORDER BY i.risk_score DESC NULLS LAST
                LIMIT 200
            """, (connection_id, connection_id))
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return rows
        except Exception as e:
            logger.warning(f"Failed to load identities for connection {connection_id}: {e}")
            return []

    def _analyze_risk_drivers(self, identity):
        """Analyze all risk drivers for an identity."""
        drivers = []

        # Driver 1: Privileged role assignments
        priv_score = self._check_privileged_roles(identity)
        if priv_score > 0:
            drivers.append({
                'driver': 'privileged_roles',
                'score': priv_score,
                'detail': 'Identity holds privileged role assignments',
            })

        # Driver 2: Credential age / expiry
        cred_score = self._check_credential_age(identity)
        if cred_score > 0:
            drivers.append({
                'driver': 'credential_age',
                'score': cred_score,
                'detail': f"Credential status: {identity.get('credential_status', 'unknown')}",
            })

        # Driver 3: Anomaly frequency
        anomaly_score = self._check_anomaly_frequency(identity)
        if anomaly_score > 0:
            drivers.append({
                'driver': 'anomaly_frequency',
                'score': anomaly_score,
                'detail': 'Identity has recent anomaly detections',
            })

        # Driver 4: Attack path exposure
        attack_score = self._check_attack_path_exposure(identity)
        if attack_score > 0:
            drivers.append({
                'driver': 'attack_path_exposure',
                'score': attack_score,
                'detail': 'Identity is reachable via attack paths',
            })

        # Driver 5: Activity status
        activity_score = self._check_activity_status(identity)
        if activity_score > 0:
            drivers.append({
                'driver': 'activity_status',
                'score': activity_score,
                'detail': f"Activity: {identity.get('activity_status', 'unknown')}",
            })

        # Driver 6: Credential count
        cred_count_score = self._check_credential_count(identity)
        if cred_count_score > 0:
            drivers.append({
                'driver': 'credential_count',
                'score': cred_count_score,
                'detail': f"Has {identity.get('credential_count', 0)} credential(s)",
            })

        return drivers

    def _check_privileged_roles(self, identity):
        """Check if identity holds privileged roles."""
        try:
            db_id = identity.get('db_id')
            if not db_id:
                return 0
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT role_name FROM role_assignments
                WHERE identity_db_id = %s
            """, (db_id,))
            roles = [r['role_name'] for r in cursor.fetchall()]
            cursor.close()
            priv_count = sum(1 for r in roles if r in HIGH_PRIVILEGE_ROLES)
            if priv_count >= 2:
                return DRIVER_WEIGHTS['privileged_roles']
            elif priv_count == 1:
                return DRIVER_WEIGHTS['privileged_roles'] * 0.6
            return 0
        except Exception:
            return 0

    def _check_credential_age(self, identity):
        """Score based on credential status and expiry."""
        status = identity.get('credential_status', '')
        weight = DRIVER_WEIGHTS['credential_age']
        if status == 'expired':
            return weight
        elif status == 'expiring_soon':
            return weight * 0.7
        elif status == 'active':
            return weight * 0.2
        return 0

    def _check_anomaly_frequency(self, identity):
        """Check anomaly detections for this identity."""
        try:
            identity_id = identity.get('identity_id', '')
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT COUNT(*) as cnt FROM anomalies
                WHERE identity_id = %s AND resolved = false
            """, (identity_id,))
            row = cursor.fetchone()
            cursor.close()
            count = int(row['cnt']) if row else 0
            weight = DRIVER_WEIGHTS['anomaly_frequency']
            if count >= 3:
                return weight
            elif count >= 1:
                return weight * 0.5
            return 0
        except Exception:
            return 0

    def _check_attack_path_exposure(self, identity):
        """Check if identity appears in attack paths."""
        try:
            identity_id = identity.get('identity_id', '')
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT COUNT(*) as cnt FROM identity_attack_incidents
                WHERE identity_id = %s AND status != 'resolved'
            """, (identity_id,))
            row = cursor.fetchone()
            cursor.close()
            count = int(row['cnt']) if row else 0
            weight = DRIVER_WEIGHTS['attack_path_exposure']
            if count >= 2:
                return weight
            elif count >= 1:
                return weight * 0.5
            return 0
        except Exception:
            return 0

    def _check_activity_status(self, identity):
        """Score based on identity activity status."""
        status = identity.get('activity_status', '')
        weight = DRIVER_WEIGHTS['activity_status']
        if status in ('inactive', 'stale'):
            return weight  # dormant + privileged = high risk
        elif status == 'never_used':
            return weight * 0.8
        return 0

    def _check_credential_count(self, identity):
        """Score based on number of credentials."""
        count = identity.get('credential_count', 0) or 0
        weight = DRIVER_WEIGHTS['credential_count']
        if count >= 3:
            return weight
        elif count == 2:
            return weight * 0.5
        return 0

    def _compute_prediction_score(self, drivers):
        """Compute overall prediction score (0-100) from risk drivers."""
        if not drivers:
            return 0
        total = sum(d['score'] for d in drivers)
        return min(total, 100)

    def _score_to_risk_level(self, score):
        """Convert score to risk level."""
        for level, threshold in RISK_THRESHOLDS.items():
            if score >= threshold:
                return level
        return 'low'

    def _compute_confidence(self, drivers):
        """Compute confidence based on how many drivers contributed."""
        if not drivers:
            return 0.0
        active_drivers = len(drivers)
        total_drivers = len(DRIVER_WEIGHTS)
        return min(active_drivers / total_drivers, 1.0)

    def _generate_recommendations(self, identity, drivers, risk_level):
        """Generate recommended actions based on risk drivers."""
        actions = []
        driver_keys = {d['driver'] for d in drivers}

        if 'privileged_roles' in driver_keys:
            actions.append({
                'action': 'Review and reduce privileged role assignments',
                'priority': 'high' if risk_level in ('critical', 'high') else 'medium',
            })

        if 'credential_age' in driver_keys:
            actions.append({
                'action': 'Rotate or renew credentials',
                'priority': 'high',
            })

        if 'anomaly_frequency' in driver_keys:
            actions.append({
                'action': 'Investigate anomalous activity patterns',
                'priority': 'high',
            })

        if 'attack_path_exposure' in driver_keys:
            actions.append({
                'action': 'Remediate attack path vulnerabilities',
                'priority': 'critical' if risk_level == 'critical' else 'high',
            })

        if 'activity_status' in driver_keys:
            status = identity.get('activity_status', '')
            if status in ('inactive', 'stale', 'never_used'):
                actions.append({
                    'action': 'Disable or remove dormant identity',
                    'priority': 'medium',
                })

        if 'credential_count' in driver_keys:
            actions.append({
                'action': 'Consolidate or remove excess credentials',
                'priority': 'medium',
            })

        return actions
