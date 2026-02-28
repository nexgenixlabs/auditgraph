"""
Behavioral Anomaly Detection Engine — detects behavioral anomalies
from P2 sign-in telemetry for workload identities.

8 anomaly types detected from workload_signin_events data.
"""

import json
from datetime import datetime, timedelta


class BehavioralAnomalyEngine:
    """Detect behavioral anomalies from workload sign-in telemetry."""

    def __init__(self, db):
        self.db = db

    def detect_anomalies(self, run_id, organization_id):
        """Run all detectors and insert results into workload_anomaly_events."""
        total = 0
        total += self._detect_impossible_travel(run_id, organization_id)
        total += self._detect_dormant_reactivation(run_id, organization_id)
        total += self._detect_off_hours_spike(run_id, organization_id)
        total += self._detect_new_resource_access(run_id, organization_id)
        total += self._detect_auth_failure_burst(run_id, organization_id)
        total += self._detect_risky_sign_in(run_id, organization_id)
        total += self._detect_ca_bypass_attempt(run_id, organization_id)
        total += self._detect_volume_anomaly(run_id, organization_id)
        print(f"  ✓ Behavioral anomaly detection: {total} anomalies found")
        return total

    def _insert_anomaly(self, organization_id, identity_db_id, identity_id, anomaly_type,
                        severity, title, description, evidence, baseline,
                        detected_value, run_id):
        """Insert a single anomaly event."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO workload_anomaly_events
                (organization_id, identity_db_id, identity_id, anomaly_type, severity,
                 title, description, evidence, baseline, detected_value, discovery_run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                organization_id, identity_db_id, identity_id, anomaly_type, severity,
                title, description,
                json.dumps(evidence), json.dumps(baseline), json.dumps(detected_value),
                run_id,
            ))
            self.db.conn.commit()
            return 1
        except Exception as e:
            self.db.conn.rollback()
            print(f"  ⚠️ Failed to insert anomaly: {e}")
            return 0
        finally:
            cursor.close()

    def _detect_impossible_travel(self, run_id, organization_id):
        """Same identity, 2 sign-ins from distant locations within 1 hour."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT DISTINCT ON (a.identity_db_id)
                    a.identity_db_id, a.identity_id,
                    a.location_city AS city_a, a.location_country AS country_a,
                    a.created_datetime AS time_a,
                    b.location_city AS city_b, b.location_country AS country_b,
                    b.created_datetime AS time_b
                FROM workload_signin_events a
                JOIN workload_signin_events b
                    ON a.identity_db_id = b.identity_db_id
                    AND a.id < b.id
                    AND b.created_datetime BETWEEN a.created_datetime AND a.created_datetime + INTERVAL '1 hour'
                    AND a.location_country IS NOT NULL AND b.location_country IS NOT NULL
                    AND a.location_country != b.location_country
                WHERE a.discovery_run_id = %s
            """, (run_id,))
            for row in cursor.fetchall():
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'impossible_travel', 'high',
                    f'Impossible travel: {row[2] or "?"}, {row[3]} → {row[5] or "?"}, {row[6]}',
                    f'Sign-ins from different countries within 1 hour.',
                    {'city_a': row[2], 'country_a': row[3], 'time_a': str(row[4]),
                     'city_b': row[5], 'country_b': row[6], 'time_b': str(row[7])},
                    {}, {}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ Impossible travel detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_dormant_reactivation(self, run_id, organization_id):
        """Identity with 0 sign-ins in previous period suddenly has activity."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT e.identity_db_id, e.identity_id, COUNT(*) AS new_sign_ins
                FROM workload_signin_events e
                JOIN identities i ON i.id = e.identity_db_id
                WHERE e.discovery_run_id = %s
                  AND (i.activity_status IN ('stale', 'never_used')
                       OR i.lifecycle_state IN ('likely_dormant', 'dormant', 'blind'))
                GROUP BY e.identity_db_id, e.identity_id
                HAVING COUNT(*) > 0
            """, (run_id,))
            for row in cursor.fetchall():
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'dormant_reactivation', 'high',
                    f'Dormant identity reactivated — {row[2]} new sign-ins',
                    'Previously inactive workload identity now has sign-in activity.',
                    {'new_sign_ins': row[2]}, {'expected_sign_ins': 0},
                    {'actual_sign_ins': row[2]}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ Dormant reactivation detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_off_hours_spike(self, run_id, organization_id):
        """off_hours_pct > 60% when previous baseline was < 20%."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT s.identity_db_id, s.identity_id, s.off_hours_pct, s.total_sign_ins
                FROM workload_activity_stats s
                WHERE s.discovery_run_id = %s
                  AND s.off_hours_pct > 60
                  AND s.total_sign_ins >= 5
            """, (run_id,))
            for row in cursor.fetchall():
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'off_hours_spike', 'medium',
                    f'Off-hours activity spike: {row[2]:.0f}% of sign-ins outside business hours',
                    'Unusually high off-hours activity for this workload identity.',
                    {'off_hours_pct': float(row[2]), 'total_sign_ins': row[3]},
                    {'expected_off_hours_pct': 20},
                    {'actual_off_hours_pct': float(row[2])}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ Off-hours spike detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_new_resource_access(self, run_id, organization_id):
        """Accessing resource_id never seen before in prior runs."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT e.identity_db_id, e.identity_id,
                       COUNT(DISTINCT e.resource_id) AS new_resources,
                       ARRAY_AGG(DISTINCT e.resource_display_name) AS resource_names
                FROM workload_signin_events e
                WHERE e.discovery_run_id = %s
                  AND e.resource_id IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM workload_signin_events prev
                      WHERE prev.identity_db_id = e.identity_db_id
                        AND prev.resource_id = e.resource_id
                        AND prev.discovery_run_id != %s
                  )
                GROUP BY e.identity_db_id, e.identity_id
                HAVING COUNT(DISTINCT e.resource_id) >= 3
            """, (run_id, run_id))
            for row in cursor.fetchall():
                names = [n for n in (row[3] or []) if n][:5]
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'new_resource_access', 'medium',
                    f'Accessing {row[2]} previously unseen resources',
                    'Identity is accessing resources it has never accessed before.',
                    {'new_resource_count': row[2], 'resource_names': names},
                    {}, {'new_resources': row[2]}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ New resource access detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_auth_failure_burst(self, run_id, organization_id):
        """>10 failed sign-ins within 1 hour."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT identity_db_id, identity_id,
                       COUNT(*) AS failure_count,
                       MIN(created_datetime) AS first_failure,
                       MAX(created_datetime) AS last_failure
                FROM workload_signin_events
                WHERE discovery_run_id = %s
                  AND status = 'failure'
                GROUP BY identity_db_id, identity_id,
                         DATE_TRUNC('hour', created_datetime)
                HAVING COUNT(*) > 10
            """, (run_id,))
            seen = set()
            for row in cursor.fetchall():
                if row[0] in seen:
                    continue
                seen.add(row[0])
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'auth_failure_burst', 'high',
                    f'Authentication failure burst: {row[2]} failures in 1 hour',
                    'Unusually high number of failed sign-in attempts.',
                    {'failure_count': row[2], 'first': str(row[3]), 'last': str(row[4])},
                    {'expected_failures_per_hour': 2},
                    {'actual_failures': row[2]}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ Auth failure burst detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_risky_sign_in(self, run_id, organization_id):
        """MS Graph risk_level = 'high' on sign-in event."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT DISTINCT ON (identity_db_id)
                    identity_db_id, identity_id, risk_level, risk_detail,
                    ip_address, location_city, location_country, created_datetime
                FROM workload_signin_events
                WHERE discovery_run_id = %s
                  AND risk_level = 'high'
            """, (run_id,))
            for row in cursor.fetchall():
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'risky_sign_in', 'critical',
                    'High-risk sign-in detected by Microsoft Identity Protection',
                    f'Risk detail: {row[3] or "none"}. IP: {row[4] or "?"}, Location: {row[5] or "?"}, {row[6] or "?"}.',
                    {'risk_level': row[2], 'risk_detail': row[3], 'ip': row[4],
                     'city': row[5], 'country': row[6], 'time': str(row[7])},
                    {}, {'risk_level': row[2]}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ Risky sign-in detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_ca_bypass_attempt(self, run_id, organization_id):
        """Multiple sign-ins with conditional_access_status = 'notApplied'."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                SELECT identity_db_id, identity_id, COUNT(*) AS bypass_count
                FROM workload_signin_events
                WHERE discovery_run_id = %s
                  AND conditional_access_status = 'notApplied'
                GROUP BY identity_db_id, identity_id
                HAVING COUNT(*) >= 5
            """, (run_id,))
            for row in cursor.fetchall():
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'ca_bypass_attempt', 'high',
                    f'Conditional Access not applied on {row[2]} sign-ins',
                    'Multiple sign-ins without Conditional Access enforcement.',
                    {'bypass_count': row[2]}, {'expected_ca_applied': True},
                    {'ca_not_applied_count': row[2]}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ CA bypass detection error: {e}")
        finally:
            cursor.close()
        return count

    def _detect_volume_anomaly(self, run_id, organization_id):
        """Sign-in volume >3x the 7-day moving average."""
        cursor = self.db.conn.cursor()
        count = 0
        try:
            cursor.execute("""
                WITH current_stats AS (
                    SELECT identity_db_id, identity_id, avg_daily_sign_ins, total_sign_ins
                    FROM workload_activity_stats
                    WHERE discovery_run_id = %s AND total_sign_ins > 10
                ),
                historical AS (
                    SELECT identity_db_id, AVG(avg_daily_sign_ins) AS hist_avg
                    FROM workload_activity_stats
                    WHERE discovery_run_id != %s
                    GROUP BY identity_db_id
                    HAVING AVG(avg_daily_sign_ins) > 0
                )
                SELECT c.identity_db_id, c.identity_id,
                       c.avg_daily_sign_ins AS current_avg,
                       h.hist_avg,
                       c.total_sign_ins
                FROM current_stats c
                JOIN historical h ON h.identity_db_id = c.identity_db_id
                WHERE c.avg_daily_sign_ins > h.hist_avg * 3
            """, (run_id, run_id))
            for row in cursor.fetchall():
                count += self._insert_anomaly(
                    organization_id, row[0], row[1],
                    'volume_anomaly', 'medium',
                    f'Sign-in volume spike: {row[2]:.1f}/day vs {row[3]:.1f}/day baseline',
                    'Sign-in volume exceeds 3x the historical average.',
                    {'current_avg': float(row[2]), 'historical_avg': float(row[3]),
                     'total_sign_ins': row[4]},
                    {'baseline_avg_daily': float(row[3])},
                    {'current_avg_daily': float(row[2])}, run_id,
                )
        except Exception as e:
            print(f"  ⚠️ Volume anomaly detection error: {e}")
        finally:
            cursor.close()
        return count
