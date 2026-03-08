"""
Phase 31: Identity Governance Analytics Engine

Computes governance posture metrics and trend analysis across cloud connections.
Evaluates 4 metric types:
  - privilege_drift_rate: % of identities with role changes exceeding baseline
  - stale_credentials_ratio: % of identities with expired/expiring credentials
  - guest_privilege_ratio: % of guest identities with elevated privileges
  - inactive_identity_ratio: % of identities inactive >90 days with active roles
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

METRIC_TYPES = [
    'privilege_drift_rate',
    'stale_credentials_ratio',
    'guest_privilege_ratio',
    'inactive_identity_ratio',
]

PRIVILEGED_ROLES = ('Owner', 'Contributor', 'User Access Administrator',
                    'Global Administrator', 'Privileged Role Administrator')

RISK_THRESHOLDS = {
    'critical': 0.5,
    'high': 0.3,
    'medium': 0.15,
}


class GovernanceAnalyticsEngine:
    """Compute governance posture metrics and trends for a cloud connection."""

    def __init__(self, db):
        self.db = db

    def compute_governance_metrics(self, connection_id, org_id):
        """Compute all governance metrics for a connection and persist results."""
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.info(f"No completed run for connection {connection_id}, skipping governance analytics")
            return []

        metrics = []
        metrics.append(self._compute_privilege_drift_rate(run_id, connection_id, org_id))
        metrics.append(self._compute_stale_credentials_ratio(run_id, connection_id, org_id))
        metrics.append(self._compute_guest_privilege_ratio(run_id, connection_id, org_id))
        metrics.append(self._compute_inactive_identity_ratio(run_id, connection_id, org_id))

        # Filter out None results
        metrics = [m for m in metrics if m is not None]

        if metrics:
            self.db.save_governance_metrics(connection_id, org_id, metrics)
            # Compute trends after saving current metrics
            trends = self._compute_trends(connection_id, org_id)
            if trends:
                self.db.save_governance_trends(connection_id, org_id, trends)

        return metrics

    def _get_latest_run_id(self, connection_id):
        """Get the latest completed discovery run for this connection."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE cloud_connection_id = %s AND status = 'completed'
            ORDER BY id DESC LIMIT 1
        """, (connection_id,))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None

    def _compute_privilege_drift_rate(self, run_id, connection_id, org_id):
        """Compute % of identities with role assignments that changed vs previous run."""
        cursor = self.db.conn.cursor()
        # Count identities in current run
        cursor.execute("""
            SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s
        """, (run_id,))
        total = cursor.fetchone()[0]
        if total == 0:
            cursor.close()
            return None

        # Count identities with privileged roles
        cursor.execute("""
            SELECT COUNT(DISTINCT i.id) FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            AND ra.role_name IN %s
        """, (run_id, PRIVILEGED_ROLES))
        privileged = cursor.fetchone()[0]

        # Get previous run for comparison
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE cloud_connection_id = %s AND status = 'completed' AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (connection_id, run_id))
        prev_row = cursor.fetchone()
        drift_count = 0
        if prev_row:
            prev_run_id = prev_row[0]
            # Identities whose role count changed between runs
            cursor.execute("""
                SELECT COUNT(*) FROM (
                    SELECT i.identity_id,
                        (SELECT COUNT(*) FROM role_assignments ra
                         JOIN identities i2 ON ra.identity_db_id = i2.id
                         WHERE i2.discovery_run_id = %s AND i2.identity_id = i.identity_id) as curr_roles,
                        (SELECT COUNT(*) FROM role_assignments ra
                         JOIN identities i3 ON ra.identity_db_id = i3.id
                         WHERE i3.discovery_run_id = %s AND i3.identity_id = i.identity_id) as prev_roles
                    FROM identities i WHERE i.discovery_run_id = %s
                ) sub WHERE curr_roles != prev_roles
            """, (run_id, prev_run_id, run_id))
            drift_count = cursor.fetchone()[0]

        cursor.close()
        rate = drift_count / total if total > 0 else 0
        return {
            'metric_type': 'privilege_drift_rate',
            'metric_value': round(rate, 4),
            'sample_size': total,
            'affected_count': drift_count,
            'metadata': {'privileged_count': privileged, 'previous_run_id': prev_row[0] if prev_row else None},
        }

    def _compute_stale_credentials_ratio(self, run_id, connection_id, org_id):
        """Compute % of identities with expired or expiring credentials."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s
        """, (run_id,))
        total = cursor.fetchone()[0]
        if total == 0:
            cursor.close()
            return None

        cursor.execute("""
            SELECT COUNT(*) FROM identities
            WHERE discovery_run_id = %s
            AND (credential_status = 'expired'
                 OR (credential_expiration IS NOT NULL
                     AND credential_expiration < NOW() + INTERVAL '30 days'))
        """, (run_id,))
        stale = cursor.fetchone()[0]
        cursor.close()

        ratio = stale / total if total > 0 else 0
        return {
            'metric_type': 'stale_credentials_ratio',
            'metric_value': round(ratio, 4),
            'sample_size': total,
            'affected_count': stale,
            'metadata': {},
        }

    def _compute_guest_privilege_ratio(self, run_id, connection_id, org_id):
        """Compute % of guest identities with elevated privileges."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM identities
            WHERE discovery_run_id = %s AND identity_category = 'guest'
        """, (run_id,))
        total_guests = cursor.fetchone()[0]
        if total_guests == 0:
            cursor.close()
            return {
                'metric_type': 'guest_privilege_ratio',
                'metric_value': 0,
                'sample_size': 0,
                'affected_count': 0,
                'metadata': {'total_guests': 0},
            }

        cursor.execute("""
            SELECT COUNT(DISTINCT i.id) FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            AND i.identity_category = 'guest'
            AND ra.role_name IN %s
        """, (run_id, PRIVILEGED_ROLES))
        privileged_guests = cursor.fetchone()[0]
        cursor.close()

        ratio = privileged_guests / total_guests if total_guests > 0 else 0
        return {
            'metric_type': 'guest_privilege_ratio',
            'metric_value': round(ratio, 4),
            'sample_size': total_guests,
            'affected_count': privileged_guests,
            'metadata': {'total_guests': total_guests},
        }

    def _compute_inactive_identity_ratio(self, run_id, connection_id, org_id):
        """Compute % of identities inactive >90 days with active role assignments."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s
        """, (run_id,))
        total = cursor.fetchone()[0]
        if total == 0:
            cursor.close()
            return None

        cursor.execute("""
            SELECT COUNT(DISTINCT i.id) FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            AND i.activity_status IN ('inactive', 'stale')
            AND (i.last_sign_in IS NULL OR i.last_sign_in < NOW() - INTERVAL '90 days')
        """, (run_id,))
        inactive = cursor.fetchone()[0]
        cursor.close()

        ratio = inactive / total if total > 0 else 0
        return {
            'metric_type': 'inactive_identity_ratio',
            'metric_value': round(ratio, 4),
            'sample_size': total,
            'affected_count': inactive,
            'metadata': {},
        }

    def _compute_trends(self, connection_id, org_id):
        """Compare current metrics vs previous computation to derive trends."""
        cursor = self.db.conn.cursor()
        trends = []
        for metric_type in METRIC_TYPES:
            cursor.execute("""
                SELECT metric_value, computed_at FROM identity_governance_metrics
                WHERE cloud_connection_id = %s AND metric_type = %s
                ORDER BY computed_at DESC LIMIT 2
            """, (connection_id, metric_type))
            rows = cursor.fetchall()
            if len(rows) < 2:
                continue
            current_val = float(rows[0][0])
            previous_val = float(rows[1][0])
            period_end = rows[0][1]
            period_start = rows[1][1]

            if previous_val == 0:
                change_pct = 100.0 if current_val > 0 else 0.0
            else:
                change_pct = ((current_val - previous_val) / previous_val) * 100.0

            if change_pct > 5:
                direction = 'increasing'
            elif change_pct < -5:
                direction = 'decreasing'
            else:
                direction = 'stable'

            trends.append({
                'metric_type': metric_type,
                'previous_value': round(previous_val, 4),
                'current_value': round(current_val, 4),
                'change_pct': round(change_pct, 4),
                'trend_direction': direction,
                'period_start': period_start,
                'period_end': period_end,
            })
        cursor.close()
        return trends
