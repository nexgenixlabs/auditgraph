"""Phase 20: Continuous Identity Threat Detection Engine.

Detects suspicious identity activity and privilege escalation events
by analyzing recent changes in role assignments, credential lifecycle,
and identity login patterns across cloud connections.
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# Threat event types
EVENT_TYPES = {
    'privilege_escalation',
    'credential_creation',
    'suspicious_login',
    'policy_change',
}

# High-privilege roles that trigger escalation alerts
ESCALATION_ROLES = {
    'Owner', 'Contributor', 'User Access Administrator',
    'Global Administrator', 'Privileged Role Administrator',
    'Security Admin', 'Key Vault Administrator',
}

# Severity mapping for event types
EVENT_SEVERITY = {
    'privilege_escalation': 'critical',
    'credential_creation': 'high',
    'suspicious_login': 'high',
    'policy_change': 'medium',
}


class IdentityThreatDetector:
    """Detects identity-based security threats from discovered data."""

    def __init__(self, db):
        self.db = db

    def detect_identity_threats(self, connection_id, org_id):
        """Detect identity threats for a cloud connection.

        Runs all detection rules and creates threat event records.

        Args:
            connection_id: Cloud connection ID to analyze
            org_id: Organization ID

        Returns:
            List of detected threat events.
        """
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            return []

        events = []

        # Run all detection rules
        events.extend(self._detect_privilege_escalation(run_id, connection_id, org_id))
        events.extend(self._detect_credential_creation(run_id, connection_id, org_id))
        events.extend(self._detect_suspicious_login(run_id, connection_id, org_id))
        events.extend(self._detect_policy_change(run_id, connection_id, org_id))

        # Save detected events
        if events:
            self._save_threat_events(events)

        logger.info(
            f"Threat detection for connection {connection_id}: "
            f"{len(events)} event(s) detected"
        )
        return events

    def _get_latest_run_id(self, connection_id):
        """Get the latest completed discovery run for a connection."""
        try:
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
        except Exception:
            return None

    def _detect_privilege_escalation(self, run_id, connection_id, org_id):
        """Detect identities that recently received high-privilege roles.

        Checks for identities with Owner/Contributor/Global Admin roles
        that have 'recently_created' status or recent sign-in activity.
        """
        events = []
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT DISTINCT i.identity_id, i.display_name, i.identity_category,
                       ra.role_name, ra.scope
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND ra.role_name IN ('Owner', 'Contributor', 'User Access Administrator',
                                       'Global Administrator', 'Privileged Role Administrator',
                                       'Security Admin', 'Key Vault Administrator')
                  AND (i.activity_status = 'recently_created'
                       OR i.identity_category = 'guest')
                ORDER BY i.identity_id
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'privilege_escalation',
                    'severity': 'critical',
                    'description': (
                        f"{row['display_name'] or row['identity_id']} "
                        f"({row['identity_category']}) has {row['role_name']} role"
                    ),
                    'metadata': {
                        'role_name': row['role_name'],
                        'scope': row['scope'],
                        'identity_category': row['identity_category'],
                    },
                })
        except Exception as e:
            logger.warning(f"Privilege escalation detection failed: {e}")

        return events

    def _detect_credential_creation(self, run_id, connection_id, org_id):
        """Detect recently created service account credentials.

        Checks for service principals with new or multiple credentials
        that may indicate unauthorized key creation.
        """
        events = []
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       i.credential_count, i.credential_status
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.identity_category IN ('service_principal', 'managed_identity_user')
                  AND i.credential_count > 2
                ORDER BY i.credential_count DESC
                LIMIT 50
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'credential_creation',
                    'severity': 'high',
                    'description': (
                        f"{row['display_name'] or row['identity_id']} "
                        f"has {row['credential_count']} credentials"
                    ),
                    'metadata': {
                        'credential_count': row['credential_count'],
                        'credential_status': row['credential_status'],
                        'identity_category': row['identity_category'],
                    },
                })
        except Exception as e:
            logger.warning(f"Credential creation detection failed: {e}")

        return events

    def _detect_suspicious_login(self, run_id, connection_id, org_id):
        """Detect suspicious login patterns.

        Checks for identities that were previously inactive/stale
        but now show recent sign-in activity — potential compromise indicators.
        """
        events = []
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       i.activity_status, i.last_sign_in, i.risk_level
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.activity_status IN ('inactive', 'stale')
                  AND i.last_sign_in IS NOT NULL
                  AND i.last_sign_in > NOW() - INTERVAL '7 days'
                ORDER BY i.last_sign_in DESC
                LIMIT 50
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'suspicious_login',
                    'severity': 'high',
                    'description': (
                        f"{row['display_name'] or row['identity_id']} "
                        f"was {row['activity_status']} but signed in recently"
                    ),
                    'metadata': {
                        'activity_status': row['activity_status'],
                        'last_sign_in': row['last_sign_in'].isoformat() if row.get('last_sign_in') else None,
                        'risk_level': row['risk_level'],
                    },
                })
        except Exception as e:
            logger.warning(f"Suspicious login detection failed: {e}")

        return events

    def _detect_policy_change(self, run_id, connection_id, org_id):
        """Detect IAM policy changes.

        Checks for identities with multiple role assignments at different
        scope levels, indicating policy sprawl or changes.
        """
        events = []
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       COUNT(DISTINCT ra.role_name) AS role_count,
                       COUNT(DISTINCT ra.scope_type) AS scope_type_count
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                GROUP BY i.identity_id, i.display_name, i.identity_category
                HAVING COUNT(DISTINCT ra.role_name) > 3
                   AND COUNT(DISTINCT ra.scope_type) > 1
                ORDER BY COUNT(DISTINCT ra.role_name) DESC
                LIMIT 50
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'policy_change',
                    'severity': 'medium',
                    'description': (
                        f"{row['display_name'] or row['identity_id']} "
                        f"has {row['role_count']} roles across "
                        f"{row['scope_type_count']} scope levels"
                    ),
                    'metadata': {
                        'role_count': row['role_count'],
                        'scope_type_count': row['scope_type_count'],
                        'identity_category': row['identity_category'],
                    },
                })
        except Exception as e:
            logger.warning(f"Policy change detection failed: {e}")

        return events

    def _save_threat_events(self, events):
        """Persist detected threat events to the database."""
        try:
            self.db.save_identity_threat_events(events)
        except Exception as e:
            logger.warning(f"Failed to save threat events: {e}")
