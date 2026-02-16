"""
AuditGraph Notification Dispatcher (Phase 83)

Pushes notifications to Slack and Microsoft Teams channels via webhooks
when security events occur.
"""
import json
import time
import logging
import requests

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    'critical': '#DC2626',
    'high': '#EA580C',
    'medium': '#CA8A04',
    'low': '#16A34A',
    'info': '#2563EB',
}


class NotificationDispatcher:
    """Dispatches notifications to Slack and Teams via webhooks."""

    # In-memory rate limiter: {event_type: last_sent_timestamp}
    _throttle: dict = {}
    THROTTLE_SECONDS = 300  # 5 minutes

    def send_slack(self, webhook_url: str, payload: dict) -> bool:
        """Send a Slack Block Kit message."""
        color = SEVERITY_COLORS.get(payload.get('severity', 'info'), '#2563EB')
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": payload.get('title', 'AuditGraph Alert'), "emoji": True}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": payload.get('description', '')}
            },
        ]

        fields = []
        if payload.get('severity'):
            fields.append({"type": "mrkdwn", "text": f"*Severity:* {payload['severity'].upper()}"})
        if payload.get('event_type'):
            fields.append({"type": "mrkdwn", "text": f"*Event:* {payload['event_type'].replace('_', ' ').title()}"})
        if fields:
            blocks.append({"type": "section", "fields": fields})

        blocks.append({"type": "divider"})
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Sent by AuditGraph Security Platform"}]
        })

        slack_payload = {
            "attachments": [{
                "color": color,
                "blocks": blocks,
            }]
        }

        try:
            resp = requests.post(webhook_url, json=slack_payload, timeout=10)
            if resp.status_code == 200:
                logger.info(f"Slack notification sent: {payload.get('title')}")
                return True
            else:
                logger.warning(f"Slack webhook returned {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Slack webhook error: {e}")
            return False

    def send_teams(self, webhook_url: str, payload: dict) -> bool:
        """Send a Microsoft Teams Adaptive Card message."""
        color = SEVERITY_COLORS.get(payload.get('severity', 'info'), '#2563EB')

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "Container",
                            "style": "emphasis",
                            "items": [{
                                "type": "TextBlock",
                                "text": payload.get('title', 'AuditGraph Alert'),
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": "Attention" if payload.get('severity') in ('critical', 'high') else "Default",
                            }]
                        },
                        {
                            "type": "TextBlock",
                            "text": payload.get('description', ''),
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": (payload.get('severity') or 'info').upper()},
                                {"title": "Event", "value": (payload.get('event_type') or '').replace('_', ' ').title()},
                            ]
                        },
                        {
                            "type": "TextBlock",
                            "text": "Sent by AuditGraph Security Platform",
                            "isSubtle": True,
                            "size": "Small",
                        }
                    ],
                }
            }]
        }

        try:
            resp = requests.post(webhook_url, json=card, timeout=10)
            if resp.status_code in (200, 202):
                logger.info(f"Teams notification sent: {payload.get('title')}")
                return True
            else:
                logger.warning(f"Teams webhook returned {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Teams webhook error: {e}")
            return False

    def _is_throttled(self, event_type: str) -> bool:
        last = self._throttle.get(event_type, 0)
        return (time.time() - last) < self.THROTTLE_SECONDS

    def dispatch(self, event_type: str, event_data: dict, db):
        """Dispatch notifications to configured channels."""
        if self._is_throttled(event_type):
            logger.debug(f"Throttled {event_type} notification")
            return

        try:
            slack_url = db.get_system_setting('slack_webhook_url', '')
            teams_url = db.get_system_setting('teams_webhook_url', '')
            slack_events = json.loads(db.get_system_setting('slack_events', '[]'))
            teams_events = json.loads(db.get_system_setting('teams_events', '[]'))

            payload = {
                'event_type': event_type,
                'title': event_data.get('title', event_type.replace('_', ' ').title()),
                'description': event_data.get('description', ''),
                'severity': event_data.get('severity', 'info'),
            }

            sent = False

            if slack_url and event_type in slack_events:
                self.send_slack(slack_url, payload)
                sent = True

            if teams_url and event_type in teams_events:
                self.send_teams(teams_url, payload)
                sent = True

            if sent:
                self._throttle[event_type] = time.time()

        except Exception as e:
            logger.error(f"Error dispatching {event_type}: {e}")
