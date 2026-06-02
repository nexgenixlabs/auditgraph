"""
Webhook service for AuditGraph alert integration.

Delivers event payloads to configured webhook endpoints (Slack, Teams, Splunk, etc.)
with HMAC-SHA256 signature verification.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)


class WebhookService:
    """Delivers event notifications to registered webhook endpoints."""

    EVENT_TYPES = [
        'discovery_completed',
        'risk_escalation',
        'new_identities',
        'removed_identities',
        'permission_changes',
        'credential_changes',
        'drift_detected',
    ]

    def __init__(self):
        pass  # No DB in __init__ — created per-call to avoid connection issues

    def trigger_event(self, event_type: str, event_data: dict):
        """Find matching webhooks and deliver payload to each."""
        if event_type not in self.EVENT_TYPES:
            logger.warning(f"Unknown webhook event type: {event_type}")
            return

        from app.database import Database
        db = Database()
        try:
            webhooks = db.get_webhooks_for_event(event_type)
            if not webhooks:
                return

            payload = {
                'event': event_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data': event_data,
                'source': 'AuditGraph',
            }

            for wh in webhooks:
                try:
                    delivery_id = db.create_webhook_delivery(wh['id'], event_type, payload)
                    self._deliver(db, wh, delivery_id, payload, event_type)
                except Exception as e:
                    logger.error(f"Webhook delivery failed for #{wh['id']}: {e}")
        except Exception as e:
            logger.error(f"Webhook trigger_event error: {e}")
        finally:
            db.close()

    def _deliver(self, db, webhook: dict, delivery_id: int, payload: dict, event_type: str):
        """POST payload to webhook URL with optional HMAC signature."""
        body = json.dumps(payload, default=str)

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'AuditGraph-Webhook/1.0',
            'X-AuditGraph-Event': event_type,
        }

        # HMAC-SHA256 signature
        if webhook.get('secret'):
            sig = hmac.new(
                webhook['secret'].encode('utf-8'),
                body.encode('utf-8'),
                hashlib.sha256,
            ).hexdigest()
            headers['X-AuditGraph-Signature'] = f'sha256={sig}'

        # Merge custom headers
        if webhook.get('headers') and isinstance(webhook['headers'], dict):
            headers.update(webhook['headers'])

        # AG-102: SSRF guard — re-resolve and re-check the webhook URL
        # right before sending. Catches DNS rebinding attacks against URLs
        # registered before the guard existed, and IP-literal payloads.
        try:
            from app.services.webhook_guard import assert_webhook_safe, WebhookGuardError
            assert_webhook_safe(webhook['url'])
        except WebhookGuardError as ssrf_err:
            db.update_webhook_delivery(
                delivery_id, 'failed', None, f'SSRF guard rejected URL: {ssrf_err}'[:500]
            )
            logger.warning(
                "[AG-102] Webhook #%s blocked by SSRF guard: %s",
                webhook['id'], ssrf_err,
            )
            return

        try:
            resp = requests.post(
                webhook['url'],
                data=body,
                headers=headers,
                timeout=10,
                allow_redirects=False,  # AG-102: don't chase redirects into private IPs
            )
            status = 'delivered' if resp.ok else 'failed'
            db.update_webhook_delivery(
                delivery_id, status, resp.status_code, resp.text[:500]
            )
            if resp.ok:
                logger.info(f"Webhook #{webhook['id']} delivered ({resp.status_code})")
            else:
                logger.warning(f"Webhook #{webhook['id']} failed ({resp.status_code}): {resp.text[:200]}")
        except requests.exceptions.Timeout:
            db.update_webhook_delivery(delivery_id, 'failed', None, 'Connection timed out')
            logger.warning(f"Webhook #{webhook['id']} timed out")
        except Exception as e:
            db.update_webhook_delivery(delivery_id, 'failed', None, str(e)[:500])
            logger.error(f"Webhook #{webhook['id']} error: {e}")

    def test_webhook(self, webhook_id: int) -> dict:
        """Send a test payload to a specific webhook. Returns delivery result."""
        from app.database import Database
        db = Database()
        try:
            webhook = db.get_webhook(webhook_id)
            if not webhook:
                return {'success': False, 'error': 'Webhook not found'}

            payload = {
                'event': 'test',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data': {
                    'message': 'This is a test webhook from AuditGraph.',
                    'webhook_id': webhook_id,
                    'webhook_name': webhook['name'],
                },
                'source': 'AuditGraph',
            }

            delivery_id = db.create_webhook_delivery(webhook_id, 'test', payload)
            self._deliver(db, webhook, delivery_id, payload, 'test')

            # Check delivery result
            deliveries = db.get_webhook_deliveries(webhook_id, limit=1)
            if deliveries and deliveries[0]['status'] == 'delivered':
                return {
                    'success': True,
                    'http_status': deliveries[0].get('http_status'),
                }
            else:
                return {
                    'success': False,
                    'http_status': deliveries[0].get('http_status') if deliveries else None,
                    'error': 'Delivery failed',
                }
        finally:
            db.close()
