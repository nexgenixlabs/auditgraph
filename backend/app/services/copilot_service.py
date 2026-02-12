"""
AuditGraph AI Security Copilot Service (Phase 79)

Wraps the Anthropic Claude API to answer security questions
using live AuditGraph data as context.
"""
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class CopilotService:
    """AI-powered security assistant using Anthropic Claude API."""

    SYSTEM_PROMPT = """You are AuditGraph Security Copilot, an AI assistant specialized in cloud identity security.
You help security engineers and auditors understand their identity posture by answering questions about:
- Identity risk levels and security posture
- Anomalies and drift detection findings
- Credential health and expiration status
- Privileged access management (PIM)
- Compliance status and gaps
- Remediation recommendations

You ONLY answer questions related to identity security and the AuditGraph platform.
For unrelated questions, politely redirect users to security topics.

When providing answers:
- Be concise and actionable
- Reference specific data when available
- Suggest next steps or investigations
- Use markdown formatting for readability
- Cite specific identity counts and risk levels from the provided context"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = None

    def _get_client(self):
        if self.client is None:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise RuntimeError("anthropic package not installed. Run: pip install anthropic")
        return self.client

    def gather_context(self, db) -> str:
        """Gather current AuditGraph data as context for the AI."""
        context_parts = []

        try:
            cursor = db.conn.cursor()

            # Latest run stats
            cursor.execute("""
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
                FROM discovery_runs WHERE status = 'completed'
                ORDER BY id DESC LIMIT 1
            """)
            run = cursor.fetchone()
            if run:
                context_parts.append(
                    f"Latest scan (Run #{run[0]}): {run[2]} identities — "
                    f"{run[3]} critical, {run[4]} high, {run[5]} medium. "
                    f"Completed: {run[1]}"
                )
                run_id = run[0]
            else:
                context_parts.append("No completed discovery runs found.")
                run_id = None

            # Anomaly stats
            if run_id:
                cursor.execute("""
                    SELECT COUNT(*) as total,
                           COUNT(*) FILTER (WHERE resolved = false) as unresolved,
                           COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                           COUNT(*) FILTER (WHERE severity = 'high') as high
                    FROM anomalies WHERE run_id = %s
                """, (run_id,))
                anom = cursor.fetchone()
                if anom and anom[0] > 0:
                    context_parts.append(
                        f"Anomalies: {anom[0]} total, {anom[1]} unresolved "
                        f"({anom[2]} critical, {anom[3]} high)"
                    )

            # Credential health
            if run_id:
                cursor.execute("""
                    SELECT
                        COUNT(*) FILTER (WHERE credential_status = 'expired') as expired,
                        COUNT(*) FILTER (WHERE credential_status = 'expiring_soon') as expiring,
                        COUNT(*) FILTER (WHERE credential_status = 'healthy') as healthy
                    FROM identities WHERE discovery_run_id = %s
                """, (run_id,))
                creds = cursor.fetchone()
                if creds:
                    context_parts.append(
                        f"Credential health: {creds[0]} expired, {creds[1]} expiring soon, {creds[2]} healthy"
                    )

            # Risk distribution
            if run_id:
                cursor.execute("""
                    SELECT identity_category, COUNT(*) as cnt
                    FROM identities WHERE discovery_run_id = %s
                    GROUP BY identity_category ORDER BY cnt DESC
                """, (run_id,))
                cats = cursor.fetchall()
                if cats:
                    cat_str = ", ".join(f"{c[0]}: {c[1]}" for c in cats)
                    context_parts.append(f"Identity categories: {cat_str}")

            # Recent drift
            cursor.execute("""
                SELECT changes FROM drift_reports ORDER BY id DESC LIMIT 1
            """)
            drift_row = cursor.fetchone()
            if drift_row:
                try:
                    changes = drift_row[0] if isinstance(drift_row[0], dict) else json.loads(drift_row[0])
                    total_drift = sum(len(v) for v in changes.values() if isinstance(v, list))
                    if total_drift > 0:
                        context_parts.append(f"Latest drift: {total_drift} total changes detected")
                except Exception:
                    pass

            cursor.close()
        except Exception as e:
            logger.warning(f"Error gathering copilot context: {e}")
            context_parts.append("(Some context data unavailable)")

        return "\n".join(context_parts)

    def get_suggestions(self, db) -> list:
        """Return contextual quick-ask suggestions based on current posture."""
        suggestions = [
            "What is our current security posture?",
            "Which identities need immediate attention?",
        ]

        try:
            cursor = db.conn.cursor()

            # Check for anomalies
            cursor.execute("SELECT COUNT(*) FROM anomalies WHERE resolved = false")
            unresolved = cursor.fetchone()[0]
            if unresolved > 0:
                suggestions.append(f"Explain the {unresolved} unresolved anomalies")

            # Check for expired credentials
            cursor.execute("""
                SELECT COUNT(*) FROM identities i
                JOIN discovery_runs r ON i.discovery_run_id = r.id
                WHERE r.status = 'completed' AND i.credential_status = 'expired'
                ORDER BY r.id DESC LIMIT 1
            """)
            expired = cursor.fetchone()
            if expired and expired[0] > 0:
                suggestions.append("How do I fix expired credentials?")

            # Check for critical identities
            cursor.execute("""
                SELECT COUNT(*) FROM identities i
                JOIN discovery_runs r ON i.discovery_run_id = r.id
                WHERE r.status = 'completed' AND i.risk_level = 'critical'
                ORDER BY r.id DESC LIMIT 1
            """)
            critical = cursor.fetchone()
            if critical and critical[0] > 0:
                suggestions.append(f"What makes {critical[0]} identities critical risk?")

            cursor.close()
        except Exception:
            pass

        suggestions.append("What remediation steps should we prioritize?")
        return suggestions[:6]

    def ask(self, question: str, conversation_history: list, db) -> str:
        """Send a question to Claude with AuditGraph context."""
        client = self._get_client()
        context = self.gather_context(db)

        messages = []
        for msg in conversation_history[-10:]:  # Keep last 10 messages
            messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })
        messages.append({"role": "user", "content": question})

        system = f"{self.SYSTEM_PROMPT}\n\n--- Current AuditGraph Data ---\n{context}"

        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            system=system,
            messages=messages,
        )

        return response.content[0].text
