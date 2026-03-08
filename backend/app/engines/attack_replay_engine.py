"""Phase 23: Identity Attack Replay & Forensics Engine.

Reconstructs identity attack timelines by correlating activity events,
threat events, and anomaly data. Generates step-by-step replay sequences
for forensic investigation.
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# Incident type definitions
INCIDENT_TYPES = {
    'privilege_escalation_attack',
    'credential_compromise',
    'lateral_movement',
    'resource_exposure',
}

# Incident detection patterns: sequences of event types that indicate an attack
INCIDENT_PATTERNS = {
    'privilege_escalation_attack': {
        'triggers': ['privilege_escalation'],
        'correlated': ['role_assignment', 'policy_change'],
        'severity': 'critical',
    },
    'credential_compromise': {
        'triggers': ['suspicious_login', 'credential_creation'],
        'correlated': ['credential_change', 'login'],
        'severity': 'critical',
    },
    'lateral_movement': {
        'triggers': ['suspicious_login'],
        'correlated': ['resource_access', 'role_assignment'],
        'severity': 'high',
    },
    'resource_exposure': {
        'triggers': ['policy_change'],
        'correlated': ['resource_access', 'credential_creation'],
        'severity': 'high',
    },
}

# Severity ranking for sorting
SEVERITY_RANK = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
}


class AttackReplayEngine:
    """Reconstructs and replays identity attack sequences."""

    def __init__(self, db):
        self.db = db

    def generate_attack_replay(self, identity_id, org_id):
        """Generate attack replay for an identity.

        Steps:
        1. Collect threat events for identity
        2. Collect activity events for identity
        3. Collect anomaly data for identity
        4. Detect incident patterns
        5. Reconstruct timeline
        6. Generate and store replay steps

        Args:
            identity_id: Identity to analyze
            org_id: Organization ID

        Returns:
            List of detected incidents with replay steps.
        """
        # 1. Collect threat events
        threat_events = self._get_threat_events(identity_id)

        # 2. Collect activity events
        activity_events = self._get_activity_events(identity_id)

        # 3. Collect anomaly data
        anomaly_events = self._get_anomaly_events(identity_id)

        # 4. Merge and sort all events by time
        all_events = self._merge_events(threat_events, activity_events, anomaly_events)

        if not all_events:
            return []

        # 5. Detect incident patterns
        incidents = self._detect_incidents(identity_id, org_id, all_events)

        # 6. Save incidents and replay steps
        saved_incidents = []
        for incident in incidents:
            saved = self._save_incident(incident)
            if saved:
                saved_incidents.append(saved)

        logger.info(
            f"Attack replay for {identity_id}: "
            f"{len(saved_incidents)} incident(s) detected"
        )
        return saved_incidents

    def detect_incidents_for_connection(self, connection_id, org_id):
        """Detect incidents for all identities in a connection.

        Returns:
            List of detected incidents.
        """
        identities = self._get_identities_with_threats(connection_id)
        all_incidents = []

        for identity in identities:
            try:
                incidents = self.generate_attack_replay(
                    identity['identity_id'], org_id
                )
                all_incidents.extend(incidents)
            except Exception as e:
                logger.warning(
                    f"Attack replay failed for {identity.get('identity_id')}: {e}"
                )

        logger.info(
            f"Attack replay for connection {connection_id}: "
            f"{len(all_incidents)} incident(s)"
        )
        return all_incidents

    def get_incident_replay(self, incident_id):
        """Get full replay timeline for an incident.

        Args:
            incident_id: UUID of the incident

        Returns:
            Dict with incident details and ordered replay steps.
        """
        incident = self.db.get_attack_incident(incident_id)
        if not incident:
            return None

        steps = self.db.get_attack_replay_steps(incident_id)

        return {
            'incident': incident,
            'steps': steps,
            'step_count': len(steps),
        }

    def _get_threat_events(self, identity_id):
        """Get threat events for an identity."""
        try:
            events = self.db.get_identity_threat_events(
                status='open', limit=50
            )
            return [
                e for e in events
                if e.get('identity_id') == identity_id
            ]
        except Exception:
            return []

    def _get_activity_events(self, identity_id):
        """Get activity events for an identity."""
        try:
            return self.db.get_identity_activity_events(
                identity_id=identity_id, limit=100
            )
        except Exception:
            return []

    def _get_anomaly_events(self, identity_id):
        """Get anomaly events for an identity."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, identity_id, anomaly_type AS event_type,
                       severity, description, detected_at AS created_at,
                       metadata
                FROM anomalies
                WHERE identity_id = %s
                ORDER BY detected_at DESC LIMIT 50
            """, (identity_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            for row in rows:
                row['id'] = str(row['id'])
                row['source'] = 'anomaly'
                if row.get('created_at'):
                    row['created_at'] = row['created_at'].isoformat()
            return rows
        except Exception:
            return []

    def _merge_events(self, threat_events, activity_events, anomaly_events):
        """Merge and sort all events by time."""
        all_events = []

        for ev in threat_events:
            all_events.append({
                'source': 'threat',
                'event_type': ev.get('event_type', 'unknown'),
                'severity': ev.get('severity', 'medium'),
                'description': ev.get('description', ''),
                'created_at': ev.get('created_at', ''),
                'metadata': ev.get('metadata', {}),
            })

        for ev in activity_events:
            all_events.append({
                'source': 'activity',
                'event_type': ev.get('event_type', 'unknown'),
                'severity': 'low',
                'description': str(ev.get('metadata', {}).get('display_name', '')),
                'created_at': ev.get('created_at', ''),
                'metadata': ev.get('metadata', {}),
            })

        for ev in anomaly_events:
            all_events.append({
                'source': 'anomaly',
                'event_type': ev.get('event_type', 'unknown'),
                'severity': ev.get('severity', 'medium'),
                'description': ev.get('description', ''),
                'created_at': ev.get('created_at', ''),
                'metadata': ev.get('metadata', {}),
            })

        # Sort by created_at descending (most recent first)
        all_events.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return all_events

    def _detect_incidents(self, identity_id, org_id, all_events):
        """Detect incident patterns from merged events."""
        incidents = []
        event_types = {ev['event_type'] for ev in all_events}

        for incident_type, pattern in INCIDENT_PATTERNS.items():
            # Check if any trigger events exist
            trigger_match = any(t in event_types for t in pattern['triggers'])
            if not trigger_match:
                continue

            # Check for correlated events
            correlated_match = any(c in event_types for c in pattern['correlated'])

            if trigger_match and correlated_match:
                # Build replay steps from matching events
                steps = self._build_replay_steps(all_events, pattern)

                # Determine time range
                times = [s['event_time'] for s in steps if s.get('event_time')]
                start_time = min(times) if times else None
                end_time = max(times) if times else None

                incidents.append({
                    'organization_id': org_id,
                    'identity_id': identity_id,
                    'incident_type': incident_type,
                    'severity': pattern['severity'],
                    'start_time': start_time,
                    'end_time': end_time,
                    'summary': self._build_summary(
                        identity_id, incident_type, steps
                    ),
                    'steps': steps,
                })

        # Sort by severity
        incidents.sort(key=lambda x: SEVERITY_RANK.get(x['severity'], 9))
        return incidents

    def _build_replay_steps(self, all_events, pattern):
        """Build ordered replay steps from events matching a pattern."""
        relevant_types = set(pattern['triggers']) | set(pattern['correlated'])
        steps = []
        step_idx = 0

        # Sort events chronologically (oldest first for replay)
        sorted_events = sorted(
            all_events,
            key=lambda x: x.get('created_at', '')
        )

        for ev in sorted_events:
            if ev['event_type'] in relevant_types:
                steps.append({
                    'step_index': step_idx,
                    'event_type': ev['event_type'],
                    'event_time': ev.get('created_at'),
                    'description': ev.get('description', ''),
                    'metadata': ev.get('metadata', {}),
                })
                step_idx += 1

        return steps

    def _build_summary(self, identity_id, incident_type, steps):
        """Build a human-readable incident summary."""
        type_label = incident_type.replace('_', ' ').title()
        step_types = [s['event_type'] for s in steps]
        unique_types = list(dict.fromkeys(step_types))

        return (
            f"{type_label} detected for {identity_id}: "
            f"{len(steps)} event(s) involving {', '.join(unique_types)}"
        )

    def _get_identities_with_threats(self, connection_id):
        """Get identities that have threat events for a connection."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT DISTINCT identity_id
                FROM identity_threat_events
                WHERE cloud_connection_id = %s AND status = 'open'
                  AND identity_id IS NOT NULL
                ORDER BY identity_id
                LIMIT 100
            """, (connection_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return rows
        except Exception:
            return []

    def _save_incident(self, incident):
        """Save incident and its replay steps."""
        try:
            saved_incident = self.db.save_attack_incident(incident)
            if saved_incident and incident.get('steps'):
                self.db.save_attack_replay_steps(
                    str(saved_incident['id']),
                    incident['steps']
                )
            return saved_incident
        except Exception as e:
            logger.warning(f"Failed to save incident: {e}")
            return None
