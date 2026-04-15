"""Phase 30: Enterprise Security Integrations — Integration Dispatcher.

Collects security events (incidents, threats, governance actions, risk predictions)
and dispatches them to configured external systems (Slack, Jira, ServiceNow, SIEM).
"""

import logging
import json
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Event types that can be dispatched
EVENT_TYPES = ('incident', 'threat', 'governance_action', 'risk_prediction')

# Supported destinations
DESTINATIONS = ('slack', 'jira', 'servicenow', 'siem')


class IntegrationDispatcher:
    """Dispatches security events to configured external integrations."""

    def __init__(self, db):
        self.db = db

    def dispatch_integration_events(self, org_id):
        """Collect and dispatch new security events to configured destinations."""
        configs = self.db.get_integration_configs(org_id)
        enabled = [c for c in configs if c.get('enabled')]
        if not enabled:
            logger.debug(f"No enabled integrations for org {org_id}")
            return []

        events = []

        # Collect events from each source
        events.extend(self._collect_incident_events(org_id))
        events.extend(self._collect_threat_events(org_id))
        events.extend(self._collect_governance_events(org_id))
        events.extend(self._collect_prediction_events(org_id))

        dispatched = []
        for event in events:
            for config in enabled:
                dest = config['integration_type']
                result = self._dispatch_to_destination(event, dest, config.get('config', {}), org_id)
                dispatched.append(result)

        if dispatched:
            logger.info(f"Dispatched {len(dispatched)} event(s) for org {org_id}")

        return dispatched

    # ── Event Collectors ─────────────────────────────────────────────────

    def _collect_incident_events(self, org_id):
        """Collect recent open incidents as integration events."""
        try:
            cursor = self.db._cursor()
            cursor.execute(
                "SELECT id, identity_id, incident_type, severity, status "
                "FROM identity_attack_incidents "
                "WHERE status = 'open' "
                "ORDER BY created_at DESC LIMIT 10"
            )
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return [{
                'event_type': 'incident',
                'payload': {
                    'incident_id': str(r.get('id', '')),
                    'identity_id': r.get('identity_id', ''),
                    'incident_type': r.get('incident_type', ''),
                    'severity': r.get('severity', ''),
                    'status': r.get('status', ''),
                },
            } for r in rows]
        except Exception as e:
            logger.warning(f"Failed to collect incident events: {e}")
            return []

    def _collect_threat_events(self, org_id):
        """Collect recent open threat detections."""
        try:
            cursor = self.db._cursor()
            cursor.execute(
                "SELECT id, identity_id, threat_type, severity "
                "FROM identity_threat_events "
                "WHERE status = 'open' "
                "ORDER BY created_at DESC LIMIT 10"
            )
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return [{
                'event_type': 'threat',
                'payload': {
                    'threat_id': str(r.get('id', '')),
                    'identity_id': r.get('identity_id', ''),
                    'threat_type': r.get('threat_type', ''),
                    'severity': r.get('severity', ''),
                },
            } for r in rows]
        except Exception as e:
            logger.warning(f"Failed to collect threat events: {e}")
            return []

    def _collect_governance_events(self, org_id):
        """Collect pending governance actions."""
        try:
            cursor = self.db._cursor()
            cursor.execute(
                "SELECT id, identity_id, identity_name, governance_action, reason "
                "FROM identity_governance_actions "
                "WHERE status = 'pending' "
                "ORDER BY created_at DESC LIMIT 10"
            )
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return [{
                'event_type': 'governance_action',
                'payload': {
                    'action_id': str(r.get('id', '')),
                    'identity_id': r.get('identity_id', ''),
                    'identity_name': r.get('identity_name', ''),
                    'governance_action': r.get('governance_action', ''),
                    'reason': r.get('reason', ''),
                },
            } for r in rows]
        except Exception as e:
            logger.warning(f"Failed to collect governance events: {e}")
            return []

    def _collect_prediction_events(self, org_id):
        """Collect critical/high risk predictions."""
        try:
            cursor = self.db._cursor()
            cursor.execute(
                "SELECT id, identity_id, prediction_score, risk_level "
                "FROM identity_attack_predictions "
                "WHERE risk_level IN ('critical', 'high') "
                "ORDER BY prediction_score DESC LIMIT 10"
            )
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return [{
                'event_type': 'risk_prediction',
                'payload': {
                    'prediction_id': str(r.get('id', '')),
                    'identity_id': r.get('identity_id', ''),
                    'prediction_score': r.get('prediction_score', 0),
                    'risk_level': r.get('risk_level', ''),
                },
            } for r in rows]
        except Exception as e:
            logger.warning(f"Failed to collect prediction events: {e}")
            return []

    # ── Dispatchers ──────────────────────────────────────────────────────

    def _dispatch_to_destination(self, event, destination, config, org_id):
        """Dispatch a single event to a destination. Returns saved event record."""
        payload = event.get('payload', {})
        payload['destination'] = destination
        payload['dispatched_at'] = datetime.now(timezone.utc).isoformat()

        try:
            if destination == 'slack':
                self._send_slack(payload, config)
            elif destination == 'jira':
                self._send_jira(payload, config)
            elif destination == 'servicenow':
                self._send_servicenow(payload, config)
            elif destination == 'siem':
                self._send_siem(payload, config)

            status = 'sent'
            error = None
        except Exception as e:
            status = 'failed'
            error = str(e)
            logger.warning(f"Dispatch to {destination} failed: {e}")

        record = {
            'organization_id': org_id,
            'event_type': event['event_type'],
            'destination': destination,
            'payload': payload,
            'status': status,
            'error_message': error,
        }
        self.db.save_integration_event(org_id, record)
        return record

    def _send_slack(self, payload, config):
        """Send event to Slack webhook. Simulated — logs instead of HTTP call."""
        webhook_url = config.get('webhook_url', '')
        if not webhook_url:
            raise ValueError("Slack webhook_url not configured")
        logger.info(f"[Slack] Would send to {webhook_url}: {payload.get('event_type', 'event')}")

    def _send_jira(self, payload, config):
        """Create Jira ticket. Simulated — logs instead of HTTP call."""
        project_key = config.get('project_key', '')
        if not project_key:
            raise ValueError("Jira project_key not configured")
        logger.info(f"[Jira] Would create ticket in {project_key}: {payload.get('event_type', 'event')}")

    def _send_servicenow(self, payload, config):
        """Create ServiceNow incident. Simulated — logs instead of HTTP call."""
        instance_url = config.get('instance_url', '')
        if not instance_url:
            raise ValueError("ServiceNow instance_url not configured")
        logger.info(f"[ServiceNow] Would create incident at {instance_url}: {payload.get('event_type', 'event')}")

    def _send_siem(self, payload, config):
        """Export event to SIEM. Simulated — logs instead of HTTP call."""
        siem_type = config.get('siem_type', 'splunk')
        endpoint = config.get('endpoint', '')
        if not endpoint:
            raise ValueError("SIEM endpoint not configured")
        logger.info(f"[SIEM/{siem_type}] Would export to {endpoint}: {payload.get('event_type', 'event')}")
