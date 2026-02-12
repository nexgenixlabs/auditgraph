"""
SendGrid Email Service

Alternative email delivery provider using SendGrid API.
Used when email_provider setting is set to 'sendgrid'.
"""

import os
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class SendGridEmailService:
    """Send emails via SendGrid API."""

    def __init__(self):
        self.api_key = os.getenv('SENDGRID_API_KEY', '')
        self.from_email = os.getenv('SENDGRID_FROM_EMAIL', 'noreply@auditgraph.ai')
        self.from_name = os.getenv('SENDGRID_FROM_NAME', 'AuditGraph')

    def is_configured(self) -> bool:
        """Check if SendGrid API key is set."""
        return bool(self.api_key)

    def send(self, to_emails: List[str], subject: str, html_content: str, text_content: Optional[str] = None) -> bool:
        """Send an email via SendGrid.

        Returns True on success, False on failure.
        """
        if not self.is_configured():
            logger.warning("SendGrid not configured: SENDGRID_API_KEY not set")
            return False

        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail, Email, To, Content

            sg = SendGridAPIClient(api_key=self.api_key)

            from_email = Email(self.from_email, self.from_name)
            to_list = [To(email) for email in to_emails]

            message = Mail(
                from_email=from_email,
                to_emails=to_list,
                subject=subject,
                html_content=html_content,
            )

            if text_content:
                message.add_content(Content("text/plain", text_content))

            response = sg.send(message)

            if response.status_code in (200, 201, 202):
                logger.info(f"SendGrid email sent successfully to {len(to_emails)} recipient(s)")
                return True
            else:
                logger.error(f"SendGrid returned status {response.status_code}: {response.body}")
                return False

        except ImportError:
            logger.error("sendgrid package not installed. Run: pip install sendgrid")
            return False
        except Exception as e:
            logger.error(f"SendGrid send failed: {e}")
            return False

    def send_test(self, to_email: str) -> bool:
        """Send a test email to verify configuration."""
        return self.send(
            to_emails=[to_email],
            subject="AuditGraph - SendGrid Test Email",
            html_content="<h2>SendGrid Configuration Verified</h2><p>Your SendGrid integration is working correctly.</p>",
            text_content="SendGrid Configuration Verified. Your SendGrid integration is working correctly.",
        )
