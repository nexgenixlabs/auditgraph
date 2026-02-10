"""
Phase 43: SOAR (Security Orchestration, Automation, and Response) Engine.

Evaluates automated response playbooks when security events occur.
Dispatches actions to integrations (Slack, Teams, PagerDuty, ServiceNow, Jira)
and tracks execution results.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)

VALID_TRIGGER_TYPES = {'anomaly', 'risk_escalation', 'drift', 'new_identity'}
VALID_ACTION_TYPES = {'webhook', 'create_ticket', 'send_notification', 'tag_for_review'}
VALID_INTEGRATIONS = {'servicenow', 'jira', 'slack', 'pagerduty', 'teams', 'custom_webhook', 'internal'}

MOCK_EVENTS = {
    'anomaly': {
        'anomaly_type': 'permission_escalation',
        'severity': 'critical',
        'identity_id': 'mock-identity-001',
        'identity_name': 'Mock Service Principal',
        'description': 'New Global Administrator role detected',
    },
    'risk_escalation': {
        'identity_id': 'mock-identity-002',
        'identity_name': 'Mock User Account',
        'risk_level': 'critical',
        'previous_risk_level': 'medium',
        'risk_score': 95,
    },
    'drift': {
        'total_changes': 5,
        'breakdown': {'new_identities': 1, 'removed_identities': 0,
                      'permission_changes': 2, 'risk_changes': 1, 'credential_changes': 1},
    },
    'new_identity': {
        'identity_id': 'mock-identity-003',
        'identity_name': 'Mock New Service Principal',
        'identity_type': 'ServicePrincipal',
        'identity_category': 'service_principal',
    },
}


class SoarEngine:
    """Evaluates SOAR playbooks and dispatches automated actions."""

    def __init__(self, db):
        self.db = db

    def evaluate_triggers(self, trigger_type, events):
        """
        Main entry point. Query matching playbooks, check cooldowns, execute actions.
        Returns count of actions executed.
        """
        if trigger_type not in VALID_TRIGGER_TYPES:
            logger.warning(f"SOAR: unknown trigger type '{trigger_type}'")
            return 0

        playbooks = self.db.get_enabled_playbooks_by_trigger(trigger_type)
        if not playbooks:
            return 0

        count = 0
        for playbook in playbooks:
            if not self._check_cooldown(playbook):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                if self._matches_conditions(playbook.get('trigger_conditions') or {}, event):
                    try:
                        self._execute_action(playbook, event)
                        count += 1
                    except Exception as e:
                        logger.error(f"SOAR action failed for playbook '{playbook['name']}': {e}")
                    break  # One trigger per playbook per evaluation cycle

        return count

    def _matches_conditions(self, conditions, event):
        """Dict-subset match: all condition keys must match the event data."""
        if not conditions:
            return True
        for key, expected in conditions.items():
            actual = event.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def _check_cooldown(self, playbook):
        """Check if enough time has passed since last trigger."""
        last = playbook.get('last_triggered_at')
        if not last:
            return True
        cooldown = playbook.get('cooldown_minutes', 60)
        if isinstance(last, str):
            try:
                last = datetime.fromisoformat(last)
            except (ValueError, TypeError):
                return True
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > last + timedelta(minutes=cooldown)

    def _execute_action(self, playbook, event):
        """Create action record, dispatch to handler, track result."""
        identity_id = event.get('identity_id')
        anomaly_id = event.get('id') if playbook['trigger_type'] == 'anomaly' else None

        action_id = self.db.create_soar_action(
            playbook_id=playbook['id'],
            identity_id=identity_id,
            anomaly_id=anomaly_id,
            trigger_event=event,
            action_type=playbook['action_type'],
            integration=playbook['integration'],
        )
        self.db.update_soar_action(action_id, 'executing')

        try:
            action_type = playbook['action_type']
            if action_type == 'webhook':
                result = self._action_webhook(playbook, event)
            elif action_type == 'create_ticket':
                result = self._action_create_ticket(playbook, event)
            elif action_type == 'send_notification':
                result = self._action_send_notification(playbook, event)
            elif action_type == 'tag_for_review':
                result = self._action_tag_for_review(playbook, event)
            else:
                result = {'error': f'Unknown action type: {action_type}'}
                self.db.update_soar_action(action_id, 'failed', result)
                return

            self.db.update_soar_action(action_id, 'success', result)
            self.db.update_soar_playbook_triggered(playbook['id'])

            try:
                self.db.log_activity('soar_action_executed',
                    f'SOAR playbook "{playbook["name"]}" executed ({playbook["integration"]})',
                    {'playbook_id': playbook['id'], 'action_id': action_id,
                     'integration': playbook['integration'], 'identity_id': identity_id})
            except Exception:
                pass

        except Exception as e:
            error_result = {'error': str(e)}
            self.db.update_soar_action(action_id, 'failed', error_result)
            try:
                self.db.log_activity('soar_action_failed',
                    f'SOAR playbook "{playbook["name"]}" failed: {str(e)[:200]}',
                    {'playbook_id': playbook['id'], 'action_id': action_id,
                     'integration': playbook['integration'], 'error': str(e)[:500]})
            except Exception:
                pass
            raise

    def _action_webhook(self, playbook, event):
        """Send webhook with integration-specific payload format."""
        config = playbook.get('action_config') or {}
        url = config.get('url', '')
        if not url:
            raise ValueError('Webhook URL not configured in action_config')

        integration = playbook['integration']
        payload = self._build_webhook_payload(integration, playbook, event, config)

        resp = requests.post(url, json=payload, timeout=10,
                             headers={'Content-Type': 'application/json',
                                      'User-Agent': 'AuditGraph-SOAR/1.0'})
        return {
            'http_status': resp.status_code,
            'response': resp.text[:500],
            'success': 200 <= resp.status_code < 300,
        }

    def _build_webhook_payload(self, integration, playbook, event, config):
        """Build integration-specific webhook payload."""
        title = f"[AuditGraph] {playbook['name']}"
        summary = self._event_summary(playbook, event)

        if integration == 'slack':
            return {
                'text': title,
                'blocks': [
                    {'type': 'header', 'text': {'type': 'plain_text', 'text': title}},
                    {'type': 'section', 'text': {'type': 'mrkdwn', 'text': summary}},
                ],
            }
        elif integration == 'teams':
            return {
                '@type': 'MessageCard',
                'summary': title,
                'themeColor': 'FF0000',
                'title': title,
                'sections': [{'text': summary}],
            }
        elif integration == 'pagerduty':
            return {
                'routing_key': config.get('routing_key', ''),
                'event_action': 'trigger',
                'payload': {
                    'summary': summary,
                    'source': 'AuditGraph',
                    'severity': event.get('severity', 'warning'),
                    'custom_details': event,
                },
            }
        else:
            return {
                'event': playbook['trigger_type'],
                'playbook': playbook['name'],
                'integration': integration,
                'data': event,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'AuditGraph',
            }

    def _action_create_ticket(self, playbook, event):
        """Create a ticket in ServiceNow or Jira."""
        config = playbook.get('action_config') or {}
        integration = playbook['integration']
        base_url = config.get('base_url', '')
        if not base_url:
            raise ValueError('base_url not configured in action_config')

        title = f"[AuditGraph] {playbook['name']}"
        description = self._event_summary(playbook, event)

        if integration == 'servicenow':
            url = f"{base_url.rstrip('/')}/api/now/table/incident"
            payload = {
                'short_description': title,
                'description': description,
                'urgency': '1' if event.get('severity') == 'critical' else '2',
                'impact': '2',
                'category': 'Security',
            }
        elif integration == 'jira':
            url = f"{base_url.rstrip('/')}/rest/api/2/issue"
            payload = {
                'fields': {
                    'project': {'key': config.get('project_key', 'SEC')},
                    'summary': title,
                    'description': description,
                    'issuetype': {'name': config.get('issue_type', 'Task')},
                },
            }
        else:
            raise ValueError(f'create_ticket not supported for integration: {integration}')

        headers = {'Content-Type': 'application/json', 'User-Agent': 'AuditGraph-SOAR/1.0'}
        auth = None
        if config.get('username') and config.get('password'):
            auth = (config['username'], config['password'])
        elif config.get('api_token'):
            headers['Authorization'] = f"Bearer {config['api_token']}"

        resp = requests.post(url, json=payload, headers=headers, auth=auth, timeout=15)
        result = {'http_status': resp.status_code, 'response': resp.text[:500]}
        if not (200 <= resp.status_code < 300):
            raise ValueError(f'Ticket creation failed: HTTP {resp.status_code}')
        try:
            body = resp.json()
            result['ticket_id'] = body.get('result', {}).get('number') or body.get('key') or body.get('id')
        except Exception:
            pass
        return result

    def _action_send_notification(self, playbook, event):
        """Create an in-app notification using existing notification infrastructure."""
        severity = event.get('severity', 'medium')
        identity_id = event.get('identity_id')
        identity_name = event.get('identity_name', '')

        self.db.create_notification(
            event_type='soar_automation',
            category='soar',
            severity=severity,
            title=f'SOAR: {playbook["name"]}',
            description=self._event_summary(playbook, event),
            payload={'playbook_id': playbook['id'], 'trigger_type': playbook['trigger_type']},
            related_identity_id=identity_id,
            related_identity_name=identity_name,
        )
        return {'notification_created': True}

    def _action_tag_for_review(self, playbook, event):
        """Tag an identity for remediation review."""
        identity_id = event.get('identity_id')
        if not identity_id:
            return {'skipped': True, 'reason': 'No identity_id in event'}

        # Use the first remediation playbook that exists, or playbook ID 1 as default
        notes = f'Auto-tagged by SOAR playbook: {playbook["name"]}'
        self.db.upsert_remediation_action(
            identity_id=identity_id,
            playbook_id=1,
            status='open',
            notes=notes,
        )
        return {'tagged': True, 'identity_id': identity_id, 'notes': notes}

    def _event_summary(self, playbook, event):
        """Generate a human-readable event summary string."""
        trigger = playbook['trigger_type']
        if trigger == 'anomaly':
            return (f"Anomaly detected: {event.get('anomaly_type', 'unknown')} "
                    f"(severity: {event.get('severity', 'unknown')}) "
                    f"for identity '{event.get('identity_name', event.get('identity_id', 'N/A'))}'")
        elif trigger == 'risk_escalation':
            return (f"Risk escalation: {event.get('identity_name', event.get('identity_id', 'N/A'))} "
                    f"escalated from {event.get('previous_risk_level', '?')} to {event.get('risk_level', '?')} "
                    f"(score: {event.get('risk_score', 'N/A')})")
        elif trigger == 'drift':
            bd = event.get('breakdown', {})
            return (f"Drift detected: {event.get('total_changes', 0)} changes — "
                    f"{bd.get('new_identities', 0)} new, {bd.get('removed_identities', 0)} removed, "
                    f"{bd.get('permission_changes', 0)} permission, {bd.get('risk_changes', 0)} risk")
        elif trigger == 'new_identity':
            return (f"New identity discovered: {event.get('identity_name', event.get('identity_id', 'N/A'))} "
                    f"(type: {event.get('identity_type', 'unknown')}, "
                    f"category: {event.get('identity_category', 'unknown')})")
        return f"SOAR event from playbook '{playbook['name']}'"

    def test_playbook(self, playbook_id):
        """Dry-run test: generate mock event, check condition matching. No execution."""
        playbook = self.db.get_soar_playbook(playbook_id)
        if not playbook:
            return {'error': 'Playbook not found'}

        trigger_type = playbook['trigger_type']
        mock_event = MOCK_EVENTS.get(trigger_type, {})
        conditions = playbook.get('trigger_conditions') or {}
        would_match = self._matches_conditions(conditions, mock_event)
        cooldown_ok = self._check_cooldown(playbook)

        return {
            'playbook_id': playbook_id,
            'playbook_name': playbook['name'],
            'trigger_type': trigger_type,
            'mock_event': mock_event,
            'conditions': conditions,
            'would_match': would_match,
            'cooldown_ok': cooldown_ok,
            'action_type': playbook['action_type'],
            'integration': playbook['integration'],
            'summary': self._event_summary(playbook, mock_event),
        }
