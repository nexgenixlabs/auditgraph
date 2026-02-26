"""
AuditGraph Email Notification Service

This module provides email notification capabilities for the AuditGraph system,
specifically for sending identity change reports after scheduled discovery runs.

Features:
    - HTML formatted emails with summary tables
    - Microsoft Graph API for secure email sending (OAuth2)
    - Uses existing Azure service principal credentials
    - Graceful error handling (failures don't crash scheduler)

Usage:
    from app.services.email_service import EmailService

    email_service = EmailService()
    email_service.send_identity_change_report(changes, run_id, prev_run_id, counts)
"""

import os
import logging
import asyncio
from datetime import datetime
from typing import Dict, List
from dotenv import load_dotenv

from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.item.send_mail.send_mail_post_request_body import SendMailPostRequestBody
from msgraph.generated.models.message import Message
from msgraph.generated.models.item_body import ItemBody
from msgraph.generated.models.body_type import BodyType
from msgraph.generated.models.recipient import Recipient
from msgraph.generated.models.email_address import EmailAddress

load_dotenv()

logger = logging.getLogger(__name__)


def get_email_service():
    """Factory: select email service provider based on DB setting.

    Returns an EmailService (Microsoft Graph) or SendGridEmailService
    depending on the 'email_provider' setting. Defaults to Graph.
    """
    try:
        from app.database import Database
        db = Database()
        provider = db.get_system_setting('email_provider', 'graph')
        db.close()
    except Exception:
        provider = 'graph'

    if provider == 'sendgrid':
        try:
            from app.services.sendgrid_service import SendGridEmailService
            return SendGridEmailService()
        except ImportError:
            logger.warning("sendgrid package not installed, falling back to Graph")

    return EmailService()


class EmailService:
    """Email service for AuditGraph notifications using Microsoft Graph API"""

    # Category display names for the report
    CATEGORY_DISPLAY_NAMES = {
        'service_principal': 'Service Principals',
        'managed_identity_system': 'System Managed Identities',
        'managed_identity_user': 'User Managed Identities',
        'human_user': 'Human Users',
        'guest': 'Guest Users',
        'microsoft_internal': 'Microsoft Internal',
        'unknown': 'Unknown',
    }

    def __init__(self):
        """Initialize email service configuration"""
        self.tenant_id = os.getenv('AZURE_TENANT_ID')
        self.client_id = os.getenv('AZURE_CLIENT_ID')
        self.client_secret = os.getenv('AZURE_CLIENT_SECRET')
        self.from_email = os.getenv('EMAIL_FROM', 'bhupathireddys@nexgenixlabs.com')
        self.to_email = os.getenv('EMAIL_TO', 'info@nexgenixlabs.com')

        # Check if credentials are configured
        self.credentials_configured = all([self.tenant_id, self.client_id, self.client_secret])
        if not self.credentials_configured:
            logger.warning("Azure credentials not configured - email service disabled")

    def _create_graph_client(self):
        """Create a fresh Graph client (called per-request to avoid event loop issues)"""
        credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        return GraphServiceClient(
            credentials=credential,
            scopes=['https://graph.microsoft.com/.default']
        )

    def send_identity_change_report(
        self,
        changes: Dict,
        current_run_id: int,
        previous_run_id: int,
        category_counts: Dict[str, Dict[str, int]]
    ) -> bool:
        """
        Send identity change report email via Microsoft Graph API.

        Args:
            changes: Output from DriftDetector.compare_runs()
            current_run_id: Latest discovery run ID
            previous_run_id: Previous discovery run ID
            category_counts: {'before': {...}, 'after': {...}} counts per category

        Returns:
            True if email sent successfully, False otherwise
        """
        new_count = len(changes.get('new_identities', []))
        removed_count = len(changes.get('removed_identities', []))
        perm_count = len(changes.get('permission_changes', []))
        risk_count = len(changes.get('risk_changes', []))
        cred_count = len(changes.get('credential_changes', []))
        total_changes = new_count + removed_count + perm_count + risk_count + cred_count

        # Don't send if no changes
        if total_changes == 0:
            logger.info("No changes - skipping email")
            return True

        subject = f"AuditGraph Alert: {total_changes} Changes Detected (Run #{current_run_id})"

        html_body = self._generate_html_report(
            changes=changes,
            current_run_id=current_run_id,
            previous_run_id=previous_run_id,
            category_counts=category_counts
        )

        # Phase 15: Read email_to from DB settings (fall back to env var)
        to_email = self.to_email
        try:
            from app.database import Database
            db = Database()
            db_email = db.get_system_setting('email_to')
            if db_email and '@' in db_email:
                to_email = db_email
            db.close()
        except Exception:
            pass  # Fall back to env var default

        # Always create a fresh event loop to avoid "Event loop is closed" errors
        # This is necessary because the scheduler runs in a background thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._send_email_graph(subject, html_body, to_email))
        finally:
            loop.close()

    async def _send_email_graph(self, subject: str, html_body: str, to_email: str) -> bool:
        """Send email using Microsoft Graph API"""
        if not self.credentials_configured:
            logger.warning("Azure credentials not configured - skipping email")
            return False

        try:
            # Create fresh Graph client for this request (avoids event loop issues)
            graph_client = self._create_graph_client()

            # Create message
            message = Message(
                subject=subject,
                body=ItemBody(
                    content_type=BodyType.Html,
                    content=html_body
                ),
                to_recipients=[
                    Recipient(
                        email_address=EmailAddress(address=to_email)
                    )
                ]
            )

            # Create request body
            request_body = SendMailPostRequestBody(
                message=message,
                save_to_sent_items=True
            )

            # Send email as the from_email user
            await graph_client.users.by_user_id(self.from_email).send_mail.post(request_body)

            logger.info(f"Identity change report email sent to {to_email} via Microsoft Graph")
            return True

        except Exception as e:
            logger.error(f"Failed to send email via Microsoft Graph: {e}")
            return False

    def _generate_html_report(
        self,
        changes: Dict,
        current_run_id: int,
        previous_run_id: int,
        category_counts: Dict
    ) -> str:
        """Generate complete HTML email body"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        summary_table = self._build_summary_table(category_counts)

        # Only include sections for change types that have data
        new_identities = changes.get('new_identities', [])
        removed_identities = changes.get('removed_identities', [])

        new_section = self._build_identity_section(
            'New Identities',
            new_identities
        ) if new_identities else ''

        removed_section = self._build_identity_section(
            'Removed Identities',
            removed_identities
        ) if removed_identities else ''

        permission_section = self._build_permission_changes_section(
            changes.get('permission_changes', [])
        )
        risk_section = self._build_risk_changes_section(
            changes.get('risk_changes', [])
        )
        credential_section = self._build_credential_changes_section(
            changes.get('credential_changes', [])
        )

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="header">
        <h1>AuditGraph Change Report</h1>
        <p>Discovery Run #{current_run_id} vs #{previous_run_id}</p>
        <p>Generated: {timestamp}</p>
    </div>

    {summary_table}
    {new_section}
    {removed_section}
    {permission_section}
    {risk_section}
    {credential_section}

    <div class="footer">
        <p>This is an automated report from AuditGraph Identity Discovery System.</p>
        <p>NexGenix Labs - Azure Identity Security</p>
    </div>
</body>
</html>
"""
        return html

    def _build_summary_table(self, category_counts: Dict) -> str:
        """Build HTML summary table with before/after/change columns"""
        before = category_counts.get('before', {})
        after = category_counts.get('after', {})

        # Get all categories from both runs
        all_categories = set(before.keys()) | set(after.keys())

        # Define preferred order for categories
        category_order = [
            'service_principal',
            'managed_identity_system',
            'managed_identity_user',
            'human_user',
            'guest',
            'microsoft_internal',
            'unknown',
        ]

        # Sort categories by preferred order, then alphabetically for unknown ones
        sorted_categories = sorted(
            all_categories,
            key=lambda c: (category_order.index(c) if c in category_order else 100, c)
        )

        rows = []
        for category in sorted_categories:
            before_count = before.get(category, 0)
            after_count = after.get(category, 0)
            change = after_count - before_count

            display_name = self.CATEGORY_DISPLAY_NAMES.get(
                category, category.replace('_', ' ').title()
            )

            # Format change with color class
            if change > 0:
                change_html = f'<span class="change-positive">+{change}</span>'
            elif change < 0:
                change_html = f'<span class="change-negative">{change}</span>'
            else:
                change_html = '<span class="change-neutral">0</span>'

            rows.append(f"""
                <tr>
                    <td>{display_name}</td>
                    <td style="text-align: center;">{before_count}</td>
                    <td style="text-align: center;">{after_count}</td>
                    <td style="text-align: center;">{change_html}</td>
                </tr>
            """)

        # Calculate totals
        total_before = sum(before.values())
        total_after = sum(after.values())
        total_change = total_after - total_before

        if total_change > 0:
            total_change_html = f'<span class="change-positive">+{total_change}</span>'
        elif total_change < 0:
            total_change_html = f'<span class="change-negative">{total_change}</span>'
        else:
            total_change_html = '<span class="change-neutral">0</span>'

        rows.append(f"""
            <tr class="total-row">
                <td><strong>Total</strong></td>
                <td style="text-align: center;"><strong>{total_before}</strong></td>
                <td style="text-align: center;"><strong>{total_after}</strong></td>
                <td style="text-align: center;"><strong>{total_change_html}</strong></td>
            </tr>
        """)

        return f"""
    <div class="section">
        <h2 class="section-title">Summary by Category</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th style="text-align: center;">Before</th>
                    <th style="text-align: center;">After</th>
                    <th style="text-align: center;">Change</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
"""

    def _build_identity_section(
        self,
        title: str,
        identities: List[Dict]
    ) -> str:
        """Build HTML section for new or removed identities"""
        if not identities:
            return ''

        items = []
        for identity in identities:
            display_name = identity.get('display_name', 'Unknown')
            identity_type = identity.get('identity_type', 'unknown')
            identity_category = identity.get('identity_category', identity_type)
            risk_level = identity.get('risk_level', 'info') or 'info'

            # Get human-readable category name
            category_display = self.CATEGORY_DISPLAY_NAMES.get(
                identity_category, identity_category.replace('_', ' ').title()
            )

            items.append(f"""
                <div class="identity-item">
                    <strong>{display_name}</strong>
                    <span class="risk-badge risk-{risk_level}">{risk_level.upper()}</span>
                    <br>
                    <span class="identity-meta">Category: {category_display}</span>
                </div>
            """)

        return f"""
    <div class="section">
        <h2 class="section-title">{title} ({len(identities)})</h2>
        <div class="identity-list">
            {''.join(items)}
        </div>
    </div>
"""

    def _build_permission_changes_section(self, changes: List[Dict]) -> str:
        """Build HTML section for permission/role changes."""
        if not changes:
            return ''
        items = []
        for change in changes:
            identity = change.get('identity', {})
            name = identity.get('display_name', 'Unknown')
            added = change.get('added_roles', [])
            removed = change.get('removed_roles', [])
            added_html = ''.join(f'<div class="change-positive">+ {role}</div>' for role in added)
            removed_html = ''.join(f'<div class="change-negative">- {role}</div>' for role in removed)
            items.append(f"""
                <div class="identity-item">
                    <strong>{name}</strong><br>
                    {added_html}{removed_html}
                </div>
            """)
        return f"""
    <div class="section">
        <h2 class="section-title">Permission Changes ({len(changes)})</h2>
        <div class="identity-list">{''.join(items)}</div>
    </div>
"""

    def _build_risk_changes_section(self, changes: List[Dict]) -> str:
        """Build HTML section for risk level changes."""
        if not changes:
            return ''
        items = []
        for change in changes:
            identity = change.get('identity', {})
            name = identity.get('display_name', 'Unknown')
            prev_risk = change.get('previous_risk', '?')
            curr_risk = change.get('current_risk', '?')
            severity = change.get('severity', 'unchanged')
            css_class = 'change-negative' if severity == 'escalation' else 'change-positive'
            arrow = '&uarr;' if severity == 'escalation' else '&darr;'
            items.append(f"""
                <div class="identity-item">
                    <strong>{name}</strong>
                    <span class="{css_class}">{arrow} {prev_risk} &rarr; {curr_risk}</span>
                </div>
            """)
        return f"""
    <div class="section">
        <h2 class="section-title">Risk Level Changes ({len(changes)})</h2>
        <div class="identity-list">{''.join(items)}</div>
    </div>
"""

    def _build_credential_changes_section(self, changes: List[Dict]) -> str:
        """Build HTML section for credential status deterioration."""
        if not changes:
            return ''
        items = []
        for change in changes:
            identity = change.get('identity', {})
            name = identity.get('display_name', 'Unknown')
            prev_status = change.get('previous_status', '?')
            curr_status = change.get('current_status', '?')
            items.append(f"""
                <div class="identity-item">
                    <strong>{name}</strong>
                    <span class="change-negative">{prev_status} &rarr; {curr_status}</span>
                </div>
            """)
        return f"""
    <div class="section">
        <h2 class="section-title">Credential Status Changes ({len(changes)})</h2>
        <div class="identity-list">{''.join(items)}</div>
    </div>
"""

    # ====================================================================
    # Phase 18: Test Email & Scheduled Report
    # ====================================================================

    def send_test_email(self, to_email_override: str = None) -> bool:
        """Send a lightweight test email to verify configuration."""
        to_email = to_email_override or self.to_email
        if not to_email_override:
            try:
                from app.database import Database
                db = Database()
                db_email = db.get_system_setting('email_to')
                if db_email and '@' in db_email:
                    to_email = db_email
                db.close()
            except Exception:
                pass

        subject = "AuditGraph - Email Configuration Test"
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        html_body = f"""
<!DOCTYPE html>
<html>
<head><style>{self._get_css_styles()}</style></head>
<body>
    <div class="header">
        <h1>AuditGraph Email Test</h1>
        <p>Configuration Verification</p>
        <p>{timestamp}</p>
    </div>
    <div class="section">
        <h2 class="section-title">Test Successful</h2>
        <p>This confirms that your AuditGraph email notification configuration is working correctly.</p>
        <p>You will receive change reports at this address when identity changes are detected during scheduled discovery runs.</p>
    </div>
    <div class="footer">
        <p>This is a test email from AuditGraph Identity Discovery System.</p>
        <p>NexGenix Labs - Azure Identity Security</p>
    </div>
</body>
</html>
"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._send_email_graph(subject, html_body, to_email))
        finally:
            loop.close()

    def send_scheduled_report(self) -> bool:
        """Generate and send a scheduled executive summary report email."""
        from app.database import Database
        db = Database()
        try:
            report_data = db.get_report_data()
            if report_data is None:
                logger.info("No completed discovery runs - skipping scheduled report")
                return False

            to_email = db.get_system_setting('report_email_to') or db.get_system_setting('email_to') or self.to_email
            if not to_email or '@' not in to_email:
                logger.warning("No valid report recipient configured")
                return False

            org_name = db.get_system_setting('org_name', 'Your Organization')
            freq = db.get_system_setting('report_schedule_frequency', 'weekly')
        finally:
            db.close()

        stats = report_data.get('stats', {})
        cred = report_data.get('credential_health', {})
        ca = report_data.get('conditional_access', {})
        remediation = report_data.get('remediation_summary', {})
        prev = report_data.get('previous_run')
        collected_at = report_data.get('collected_at', 'N/A')

        subject = f"AuditGraph {freq.capitalize()} Report - {org_name}"
        html_body = self._generate_executive_summary_html(
            stats, cred, ca, remediation, prev, org_name, collected_at
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._send_email_graph(subject, html_body, to_email))
        finally:
            loop.close()

    def send_welcome_email(self, to_email: str, org_name: str, portal_url: str, username: str) -> bool:
        """Send welcome email to newly onboarded tenant admin."""
        if not self.credentials_configured:
            logger.warning("Email credentials not configured - cannot send welcome email")
            return False

        subject = f"Welcome to AuditGraph - {org_name}"
        html_body = f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #0B1220, #1E3A5F); padding: 40px 30px; border-radius: 12px 12px 0 0; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 28px;">Welcome to AuditGraph</h1>
                <p style="color: #94A3B8; margin: 8px 0 0; font-size: 14px;">Identity Risk Operating System</p>
            </div>
            <div style="background: #ffffff; padding: 30px; border: 1px solid #E2E8F0; border-top: none;">
                <p style="color: #334155; font-size: 15px; line-height: 1.6;">Hello,</p>
                <p style="color: #334155; font-size: 15px; line-height: 1.6;">
                    Your organization <strong>{org_name}</strong> has been set up on AuditGraph.
                    You can access your portal and begin configuring your identity security audit.
                </p>
                <div style="background: #F1F5F9; border-radius: 8px; padding: 16px; margin: 20px 0;">
                    <p style="margin: 0 0 8px; font-size: 13px; color: #64748B;"><strong>Portal URL:</strong> <a href="{portal_url}" style="color: #3B82F6;">{portal_url}</a></p>
                    <p style="margin: 0; font-size: 13px; color: #64748B;"><strong>Username:</strong> {username}</p>
                </div>
                <p style="color: #64748B; font-size: 13px;">You will be prompted to change your password on first login.</p>
                <h3 style="color: #1E293B; font-size: 16px; margin-top: 24px;">Getting Started</h3>
                <ol style="color: #334155; font-size: 14px; line-height: 1.8; padding-left: 20px;">
                    <li>Log in and change your password</li>
                    <li>Connect your Azure AD environment</li>
                    <li>Run your first discovery scan</li>
                    <li>Review your identity risk posture</li>
                </ol>
                <div style="text-align: center; margin-top: 24px;">
                    <a href="{portal_url}" style="display: inline-block; padding: 12px 32px; background: #3B82F6; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 14px; font-weight: 600;">
                        Go to Portal
                    </a>
                </div>
            </div>
            <div style="text-align: center; padding: 16px; color: #94A3B8; font-size: 11px;">
                AuditGraph Identity Risk Platform &mdash; <a href="https://auditgraph.ai" style="color: #94A3B8;">auditgraph.ai</a>
            </div>
        </div>
        """

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._send_email_graph(subject, html_body, to_email))
        except Exception as e:
            logger.error(f"Failed to send welcome email: {e}")
            return False
        finally:
            loop.close()

    def _generate_executive_summary_html(
        self, stats: Dict, credential_health: Dict, conditional_access: Dict,
        remediation_summary: Dict, previous_run, org_name: str, collected_at: str
    ) -> str:
        """Generate HTML for the executive summary report email."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        total = stats.get('total_identities', 0)
        critical = stats.get('critical', 0)
        high = stats.get('high', 0)
        medium = stats.get('medium', 0)
        low = stats.get('low', 0)

        def _trend(current, prev_val):
            if prev_val is None:
                return ''
            diff = current - prev_val
            if diff > 0:
                return f'<span class="change-negative">(+{diff})</span>'
            elif diff < 0:
                return f'<span class="change-positive">({diff})</span>'
            return '<span class="change-neutral">(no change)</span>'

        prev_total = previous_run.get('total_identities') if previous_run else None
        prev_critical = previous_run.get('critical') if previous_run else None
        prev_high = previous_run.get('high') if previous_run else None

        expired = credential_health.get('expired', 0)
        expiring = credential_health.get('expiring_soon', 0)
        ca_covered = conditional_access.get('covered', 0) if conditional_access else 0
        ca_total = conditional_access.get('total', 0) if conditional_access else 0
        ca_pct = round(ca_covered / ca_total * 100) if ca_total > 0 else 0
        total_remediations = remediation_summary.get('total_actions', 0) if remediation_summary else 0

        return f"""
<!DOCTYPE html>
<html>
<head><style>{self._get_css_styles()}</style></head>
<body>
    <div class="header">
        <h1>AuditGraph Executive Summary</h1>
        <p>{org_name}</p>
        <p>Data collected: {collected_at} | Report generated: {timestamp}</p>
    </div>

    <div class="section">
        <h2 class="section-title">Identity Risk Overview</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Metric</th>
                    <th style="text-align:center;">Count</th>
                    <th style="text-align:center;">Trend</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Total Identities</td>
                    <td style="text-align:center;">{total}</td>
                    <td style="text-align:center;">{_trend(total, prev_total)}</td>
                </tr>
                <tr>
                    <td><span class="risk-badge risk-critical">CRITICAL</span> Critical Risk</td>
                    <td style="text-align:center;">{critical}</td>
                    <td style="text-align:center;">{_trend(critical, prev_critical)}</td>
                </tr>
                <tr>
                    <td><span class="risk-badge risk-high">HIGH</span> High Risk</td>
                    <td style="text-align:center;">{high}</td>
                    <td style="text-align:center;">{_trend(high, prev_high)}</td>
                </tr>
                <tr>
                    <td>Medium Risk</td>
                    <td style="text-align:center;">{medium}</td>
                    <td style="text-align:center;"></td>
                </tr>
                <tr>
                    <td>Low / Info Risk</td>
                    <td style="text-align:center;">{low}</td>
                    <td style="text-align:center;"></td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Credential Health</h2>
        <p>Expired credentials: <strong class="change-negative">{expired}</strong> |
           Expiring soon: <strong style="color:#e67e22;">{expiring}</strong></p>
    </div>

    <div class="section">
        <h2 class="section-title">Conditional Access Coverage</h2>
        <p>{ca_covered} of {ca_total} identities covered ({ca_pct}%)</p>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Actions</h2>
        <p>{total_remediations} recommended actions across all high/critical identities.</p>
    </div>

    <div class="footer">
        <p>This is an automated scheduled report from AuditGraph.</p>
        <p>NexGenix Labs - Azure Identity Security</p>
    </div>
</body>
</html>
"""

    def _get_css_styles(self) -> str:
        """Return CSS styles for the email"""
        return """
body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
    background: #f5f5f5;
}
.header {
    background: #2c3e50;
    color: white;
    padding: 20px;
    border-radius: 5px 5px 0 0;
}
.header h1 {
    margin: 0 0 10px 0;
    font-size: 24px;
}
.header p {
    margin: 5px 0;
    opacity: 0.9;
}
.section {
    background: white;
    padding: 20px;
    margin: 10px 0;
    border-radius: 5px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
.section-title {
    font-size: 18px;
    color: #2c3e50;
    border-bottom: 2px solid #3498db;
    padding-bottom: 10px;
    margin-top: 0;
}
.summary-table {
    width: 100%;
    border-collapse: collapse;
}
.summary-table th {
    background: #3498db;
    color: white;
    padding: 12px;
    text-align: left;
}
.summary-table td {
    padding: 10px;
    border-bottom: 1px solid #eee;
}
.summary-table .total-row {
    background: #ecf0f1;
}
.change-positive {
    color: #27ae60;
    font-weight: bold;
}
.change-negative {
    color: #e74c3c;
    font-weight: bold;
}
.change-neutral {
    color: #7f8c8d;
}
.identity-list {
    border: 1px solid #eee;
    border-radius: 5px;
}
.identity-item {
    padding: 12px;
    border-bottom: 1px solid #eee;
}
.identity-item:last-child {
    border-bottom: none;
}
.identity-meta {
    color: #7f8c8d;
    font-size: 13px;
}
.risk-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11px;
    margin-left: 10px;
    float: right;
}
.risk-critical {
    background: #e74c3c;
    color: white;
}
.risk-high {
    background: #e67e22;
    color: white;
}
.risk-medium {
    background: #f1c40f;
    color: #333;
}
.risk-low {
    background: #27ae60;
    color: white;
}
.risk-info {
    background: #3498db;
    color: white;
}
.no-items {
    color: #7f8c8d;
    font-style: italic;
}
.footer {
    background: #ecf0f1;
    padding: 15px;
    border-radius: 0 0 5px 5px;
    color: #7f8c8d;
    font-size: 12px;
    text-align: center;
}
"""
