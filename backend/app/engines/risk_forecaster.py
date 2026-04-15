"""Phase 18: Identity Risk Forecasting Engine.

Analyzes historical risk data to predict future risk trends.
Detects growth drivers such as credential aging, privilege escalation,
attack path growth, and NHI exposure increases.
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# Default forecast window in days
DEFAULT_FORECAST_WINDOW = 30

# Valid forecast windows
VALID_WINDOWS = {7, 30, 90}

# Trend thresholds (percentage change)
TREND_INCREASING_THRESHOLD = 5.0   # >5% increase = increasing
TREND_DECREASING_THRESHOLD = -5.0  # <-5% decrease = decreasing

# Driver detection weights
DRIVER_WEIGHTS = {
    'credential_aging': 0.25,
    'privileged_identity_growth': 0.30,
    'attack_path_increase': 0.25,
    'nhi_exposure_increase': 0.20,
}


class RiskForecaster:
    """Predicts future identity risk based on historical trend analysis."""

    def __init__(self, db):
        self.db = db

    def generate_risk_forecast(self, org_id, window_days=DEFAULT_FORECAST_WINDOW):
        """Generate a risk forecast for an organization.

        Steps:
        1. Load historical risk scores
        2. Analyze trend patterns
        3. Detect growth drivers
        4. Compute predicted risk score
        5. Store forecast record

        Args:
            org_id: Organization ID
            window_days: Forecast window (7, 30, or 90 days)

        Returns:
            Forecast dict with current score, predicted score, trend, drivers.
        """
        if window_days not in VALID_WINDOWS:
            window_days = DEFAULT_FORECAST_WINDOW

        # 1. Load historical risk scores
        historical_scores = self._load_historical_scores(org_id)

        # 2. Compute current risk score
        current_score = self._compute_current_risk_score(org_id)

        # 3. Analyze trend
        trend_rate = self._analyze_trend(historical_scores)

        # 4. Detect drivers
        drivers = self._detect_drivers(org_id)

        # 5. Compute predicted score
        predicted_score = self._compute_prediction(
            current_score, trend_rate, window_days, drivers
        )

        # 6. Determine trend direction
        trend_direction = self._classify_trend(current_score, predicted_score)

        # 7. Store forecast
        forecast = {
            'current_risk_score': current_score,
            'predicted_risk_score': predicted_score,
            'trend_direction': trend_direction,
            'forecast_window_days': window_days,
            'drivers': drivers,
        }

        saved = self._save_forecast(org_id, forecast)
        forecast['forecast_id'] = str(saved['id']) if saved else None
        return forecast

    def _load_historical_scores(self, org_id):
        """Load historical risk scores from security advisor reports."""
        try:
            reports = self.db.get_security_advisor_reports(limit=30)
            return [
                {
                    'risk_score': r.get('risk_score', 0),
                    'created_at': r.get('created_at'),
                }
                for r in reports
            ]
        except Exception:
            return []

    def _compute_current_risk_score(self, org_id):
        """Compute current risk score from latest findings."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN rf.severity = 'critical' THEN 10
                             WHEN rf.severity = 'high' THEN 5
                             WHEN rf.severity = 'medium' THEN 2
                             ELSE 0 END) AS risk_score
                FROM risk_findings rf
                WHERE rf.status = 'open'
            """)
            row = cursor.fetchone()
            cursor.close()
            return float(row['risk_score'] or 0) if row else 0.0
        except Exception:
            return 0.0

    def _analyze_trend(self, historical_scores):
        """Analyze risk score trend over time.

        Returns daily rate of change (positive = increasing).
        Uses simple linear regression on available data points.
        """
        if len(historical_scores) < 2:
            return 0.0

        scores = [s['risk_score'] for s in historical_scores if s.get('risk_score') is not None]
        if len(scores) < 2:
            return 0.0

        # Simple: compare most recent to oldest
        n = len(scores)
        newest = scores[0]  # Most recent first
        oldest = scores[-1]

        # Estimate days between data points
        days_span = max(n, 1)

        if oldest == 0:
            return 0.0

        daily_change = (newest - oldest) / days_span
        return daily_change

    def _detect_drivers(self, org_id):
        """Detect factors driving risk changes.

        Analyzes:
        - Credential aging (expired/expiring credentials)
        - Privileged identity growth
        - Attack path count changes
        - NHI exposure indicators
        """
        drivers = []

        # 1. Credential aging
        cred_score = self._check_credential_aging()
        if cred_score > 0:
            drivers.append({
                'factor': 'credential_aging',
                'description': 'Service principal credential aging',
                'impact': round(cred_score * DRIVER_WEIGHTS['credential_aging'], 2),
                'weight': DRIVER_WEIGHTS['credential_aging'],
            })

        # 2. Privileged identity growth
        priv_score = self._check_privileged_growth()
        if priv_score > 0:
            drivers.append({
                'factor': 'privileged_identity_growth',
                'description': 'Increase in privileged identities',
                'impact': round(priv_score * DRIVER_WEIGHTS['privileged_identity_growth'], 2),
                'weight': DRIVER_WEIGHTS['privileged_identity_growth'],
            })

        # 3. Attack path increase
        attack_score = self._check_attack_path_growth()
        if attack_score > 0:
            drivers.append({
                'factor': 'attack_path_increase',
                'description': 'Growth in attack paths',
                'impact': round(attack_score * DRIVER_WEIGHTS['attack_path_increase'], 2),
                'weight': DRIVER_WEIGHTS['attack_path_increase'],
            })

        # 4. NHI exposure increase
        nhi_score = self._check_nhi_exposure()
        if nhi_score > 0:
            drivers.append({
                'factor': 'nhi_exposure_increase',
                'description': 'Increase in NHI exposure',
                'impact': round(nhi_score * DRIVER_WEIGHTS['nhi_exposure_increase'], 2),
                'weight': DRIVER_WEIGHTS['nhi_exposure_increase'],
            })

        return drivers

    def _check_credential_aging(self):
        """Check for credential aging risk."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT COUNT(*) AS cnt FROM risk_findings
                WHERE status = 'open'
                  AND rule_id IN (
                      SELECT id FROM risk_rules
                      WHERE rule_key IN ('expired_spn_secret', 'spn_secret_expiring', 'aws_access_key_stale')
                  )
            """)
            row = cursor.fetchone()
            cursor.close()
            return float(row['cnt'] or 0) if row else 0.0
        except Exception:
            return 0.0

    def _check_privileged_growth(self):
        """Check for privileged identity growth."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT COUNT(*) AS cnt FROM risk_findings
                WHERE status = 'open'
                  AND rule_id IN (
                      SELECT id FROM risk_rules
                      WHERE rule_key IN ('guest_high_privilege', 'spn_owner', 'inactive_privileged',
                                         'aws_user_admin_policy', 'gcp_owner_on_project')
                  )
            """)
            row = cursor.fetchone()
            cursor.close()
            return float(row['cnt'] or 0) if row else 0.0
        except Exception:
            return 0.0

    def _check_attack_path_growth(self):
        """Check for attack path count growth."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT COUNT(*) AS cnt FROM attack_simulations
                WHERE blast_radius >= 10
            """)
            row = cursor.fetchone()
            cursor.close()
            return float(row['cnt'] or 0) if row else 0.0
        except Exception:
            return 0.0

    def _check_nhi_exposure(self):
        """Check for NHI exposure indicators."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT COUNT(*) AS cnt FROM risk_findings
                WHERE status = 'open'
                  AND rule_id IN (
                      SELECT id FROM risk_rules
                      WHERE rule_key IN ('expired_spn_secret', 'spn_secret_expiring', 'gcp_sa_key_exposure')
                  )
            """)
            row = cursor.fetchone()
            cursor.close()
            return float(row['cnt'] or 0) if row else 0.0
        except Exception:
            return 0.0

    def _compute_prediction(self, current_score, trend_rate, window_days, drivers):
        """Compute predicted risk score.

        Prediction = current + (daily_rate × window_days) + driver_impact

        The prediction is bounded to [0, current * 3] to prevent extreme values.
        """
        # Base projection from trend
        trend_projection = trend_rate * window_days

        # Additional impact from drivers
        driver_impact = sum(d.get('impact', 0) for d in drivers)

        predicted = current_score + trend_projection + driver_impact

        # Bound prediction
        predicted = max(0, predicted)
        predicted = min(predicted, max(current_score * 3, 100))

        return round(predicted, 1)

    def _classify_trend(self, current, predicted):
        """Classify the trend direction based on score change."""
        if current == 0:
            return 'stable' if predicted == 0 else 'increasing'

        pct_change = ((predicted - current) / current) * 100

        if pct_change > TREND_INCREASING_THRESHOLD:
            return 'increasing'
        elif pct_change < TREND_DECREASING_THRESHOLD:
            return 'decreasing'
        return 'stable'

    def _save_forecast(self, org_id, forecast):
        """Save forecast to database."""
        try:
            return self.db.save_risk_forecast(
                org_id=org_id,
                forecast_window_days=forecast['forecast_window_days'],
                current_risk_score=forecast['current_risk_score'],
                predicted_risk_score=forecast['predicted_risk_score'],
                trend_direction=forecast['trend_direction'],
                drivers=forecast['drivers'],
            )
        except Exception as e:
            logger.warning(f"Failed to save risk forecast: {e}")
            return None
