"""Phase 21: Identity Activity Ingestion Engine.

Collects identity activity events from discovered data and stores them
in the data lake tables for long-term behavioral analytics and forensic
investigations. Builds role history and access history from current
discovery snapshots.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Activity event types
EVENT_TYPES = {
    'login',
    'role_assignment',
    'credential_change',
    'policy_update',
    'resource_access',
}

# Baseline activity thresholds
BASELINE_LOGIN_DAYS = 90
BASELINE_MIN_EVENTS = 5


class ActivityIngestor:
    """Ingests identity activity into the data lake tables."""

    def __init__(self, db):
        self.db = db

    def ingest_identity_activity(self, connection_id, org_id):
        """Ingest activity data for all identities in a connection.

        Steps:
        1. Get latest discovery run
        2. Ingest login events from identity sign-in data
        3. Ingest role assignment events from role_assignments
        4. Ingest credential change events from credential data
        5. Build role history records
        6. Build access history from RBAC scope data

        Args:
            connection_id: Cloud connection ID
            org_id: Organization ID

        Returns:
            Dict with counts of ingested events by type.
        """
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            return {'total': 0}

        counts = {
            'login': 0,
            'role_assignment': 0,
            'credential_change': 0,
            'resource_access': 0,
            'role_history': 0,
            'access_history': 0,
        }

        # 1. Ingest login events
        counts['login'] = self._ingest_login_events(run_id, connection_id, org_id)

        # 2. Ingest role assignment events
        counts['role_assignment'] = self._ingest_role_events(run_id, connection_id, org_id)

        # 3. Ingest credential change events
        counts['credential_change'] = self._ingest_credential_events(run_id, connection_id, org_id)

        # 4. Build role history
        counts['role_history'] = self._build_role_history(run_id, org_id)

        # 5. Build access history from RBAC scopes
        counts['access_history'] = self._build_access_history(run_id, org_id)

        counts['total'] = sum(counts.values())
        logger.info(
            f"Activity ingestion for connection {connection_id}: "
            f"{counts['total']} records ingested"
        )
        return counts

    def get_identity_history(self, identity_id):
        """Get full activity history for an identity.

        Returns a combined timeline from all three data lake tables.

        Args:
            identity_id: The identity to retrieve history for

        Returns:
            Dict with activity_events, role_history, access_history.
        """
        activity = self._get_activity_events(identity_id)
        roles = self._get_role_history(identity_id)
        access = self._get_access_history(identity_id)
        baseline = self._compute_baseline(identity_id, activity)

        return {
            'identity_id': identity_id,
            'activity_events': activity,
            'role_history': roles,
            'access_history': access,
            'baseline': baseline,
            'total_events': len(activity) + len(roles) + len(access),
        }

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

    def _ingest_login_events(self, run_id, connection_id, org_id):
        """Ingest login events from identity sign-in data."""
        count = 0
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT identity_id, display_name, last_sign_in,
                       activity_status, identity_category
                FROM identities
                WHERE discovery_run_id = %s
                  AND last_sign_in IS NOT NULL
                ORDER BY last_sign_in DESC
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            events = []
            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'login',
                    'metadata': {
                        'display_name': row['display_name'],
                        'last_sign_in': row['last_sign_in'].isoformat() if row.get('last_sign_in') else None,
                        'activity_status': row['activity_status'],
                        'identity_category': row['identity_category'],
                    },
                })

            if events:
                self.db.save_identity_activity_events(events)
                count = len(events)
        except Exception as e:
            logger.warning(f"Login event ingestion failed: {e}")

        return count

    def _ingest_role_events(self, run_id, connection_id, org_id):
        """Ingest role assignment events."""
        count = 0
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, i.display_name,
                       ra.role_name, ra.scope, ra.scope_type, ra.assignment_type
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                ORDER BY i.identity_id
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            events = []
            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'role_assignment',
                    'metadata': {
                        'display_name': row['display_name'],
                        'role_name': row['role_name'],
                        'scope': row['scope'],
                        'scope_type': row.get('scope_type'),
                        'assignment_type': row.get('assignment_type'),
                    },
                })

            if events:
                self.db.save_identity_activity_events(events)
                count = len(events)
        except Exception as e:
            logger.warning(f"Role event ingestion failed: {e}")

        return count

    def _ingest_credential_events(self, run_id, connection_id, org_id):
        """Ingest credential change events."""
        count = 0
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT identity_id, display_name, credential_count,
                       credential_status, credential_expiration,
                       identity_category
                FROM identities
                WHERE discovery_run_id = %s
                  AND credential_count > 0
                ORDER BY identity_id
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            events = []
            for row in rows:
                events.append({
                    'organization_id': org_id,
                    'cloud_connection_id': connection_id,
                    'identity_id': row['identity_id'],
                    'event_type': 'credential_change',
                    'metadata': {
                        'display_name': row['display_name'],
                        'credential_count': row['credential_count'],
                        'credential_status': row['credential_status'],
                        'credential_expiration': row['credential_expiration'].isoformat() if row.get('credential_expiration') else None,
                        'identity_category': row['identity_category'],
                    },
                })

            if events:
                self.db.save_identity_activity_events(events)
                count = len(events)
        except Exception as e:
            logger.warning(f"Credential event ingestion failed: {e}")

        return count

    def _build_role_history(self, run_id, org_id):
        """Build role history records from current role assignments."""
        count = 0
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, ra.role_name, ra.scope
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                ORDER BY i.identity_id, ra.role_name
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            records = []
            for row in rows:
                records.append({
                    'organization_id': org_id,
                    'identity_id': row['identity_id'],
                    'role_name': row['role_name'],
                    'scope': row.get('scope'),
                })

            if records:
                self.db.save_identity_role_history(records)
                count = len(records)
        except Exception as e:
            logger.warning(f"Role history build failed: {e}")

        return count

    def _build_access_history(self, run_id, org_id):
        """Build access history from RBAC scope assignments."""
        count = 0
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT DISTINCT i.identity_id, ra.scope AS resource_id,
                       ra.role_name AS action
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND ra.scope IS NOT NULL
                ORDER BY i.identity_id
            """, (run_id,))
            rows = cursor.fetchall()
            cursor.close()

            records = []
            for row in rows:
                records.append({
                    'organization_id': org_id,
                    'identity_id': row['identity_id'],
                    'resource_id': row['resource_id'],
                    'action': row['action'],
                })

            if records:
                self.db.save_identity_access_history(records)
                count = len(records)
        except Exception as e:
            logger.warning(f"Access history build failed: {e}")

        return count

    def _get_activity_events(self, identity_id):
        """Get activity events for an identity."""
        try:
            events = self.db.get_identity_activity_events(identity_id=identity_id, limit=100)
            return events
        except Exception:
            return []

    def _get_role_history(self, identity_id):
        """Get role history for an identity."""
        try:
            return self.db.get_identity_role_history(identity_id)
        except Exception:
            return []

    def _get_access_history(self, identity_id):
        """Get access history for an identity."""
        try:
            return self.db.get_identity_access_history(identity_id)
        except Exception:
            return []

    def _compute_baseline(self, identity_id, activity_events):
        """Compute behavioral baseline from historical activity.

        Analyzes activity patterns to establish:
        - login_frequency: average logins per week
        - typical_event_types: most common event types
        - event_count: total events in baseline window
        """
        if len(activity_events) < BASELINE_MIN_EVENTS:
            return {
                'status': 'insufficient_data',
                'event_count': len(activity_events),
                'min_required': BASELINE_MIN_EVENTS,
            }

        event_types = {}
        for ev in activity_events:
            et = ev.get('event_type', 'unknown')
            event_types[et] = event_types.get(et, 0) + 1

        # Sort by frequency
        sorted_types = sorted(event_types.items(), key=lambda x: x[1], reverse=True)

        login_count = event_types.get('login', 0)
        weeks = max(BASELINE_LOGIN_DAYS / 7, 1)
        login_frequency = round(login_count / weeks, 2)

        return {
            'status': 'computed',
            'event_count': len(activity_events),
            'login_frequency': login_frequency,
            'typical_event_types': [t[0] for t in sorted_types[:3]],
            'event_distribution': event_types,
        }
