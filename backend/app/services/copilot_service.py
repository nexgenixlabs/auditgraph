"""
AuditGraph AI Security Copilot Service (Phase 79 + Phase 12)

Wraps the Anthropic Claude API to answer security questions
using live AuditGraph data as context.

Phase 12 additions:
- explain_attack_path() — rich explanation of a finding's attack chain
- get_remediation_advice() — type-specific remediation guidance
- translate_security_query() — natural language → API mapping
- generate_security_summary() — tenant-wide security summary
"""
import json
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv('LLM_MODEL', 'claude-sonnet-4-5-20250514')


def get_platform_copilot_service():
    """Return a CopilotService using the platform-managed API key, or (None, error_msg)."""
    api_key = os.getenv('ANTHROPIC_API_KEY', '').strip()
    if not api_key:
        return None, 'AI Copilot is not configured by the platform administrator.'
    return CopilotService(api_key), None

# Finding-type specific remediation knowledge
REMEDIATION_KNOWLEDGE = {
    'PRIVILEGE_ESCALATION': {
        'risk': 'An identity can escalate to a higher-privilege role, potentially gaining full tenant control.',
        'steps': [
            'Remove standing privileged role assignments — use PIM (just-in-time) instead',
            'Apply Conditional Access policies requiring MFA for privileged operations',
            'Enable PIM approval workflows for Global Admin and Privileged Role Admin',
            'Review and reduce the scope of custom role definitions',
            'Set up alerts on role assignment changes via Azure Monitor',
        ],
    },
    'KEYVAULT_SECRET_ACCESS': {
        'risk': 'An identity has access to Key Vault secrets, potentially exposing credentials, certificates, or encryption keys.',
        'steps': [
            'Switch Key Vault to RBAC authorization (disable access policies)',
            'Apply least-privilege: use Key Vault Secrets User instead of Contributor',
            'Enable Key Vault diagnostic logging and set up alerts on secret reads',
            'Rotate any secrets that the over-privileged identity could have accessed',
            'Use Managed Identities instead of SPNs with client secrets where possible',
        ],
    },
    'SPN_SECRET_EXPOSURE': {
        'risk': 'A Service Principal has exposed or over-privileged credentials that could be used for unauthorized access.',
        'steps': [
            'Rotate the SPN client secret or certificate immediately',
            'Move to certificate-based authentication (eliminate client secrets)',
            'Reduce the SPN\'s role assignments to minimum required scope',
            'Enable Conditional Access for workload identities (requires Entra P2)',
            'Set up credential expiry monitoring and automated rotation',
        ],
    },
    'ROLE_CHAINING': {
        'risk': 'Multiple role assignments create a chain that, when combined, grants escalated access beyond any single role.',
        'steps': [
            'Audit and consolidate overlapping role assignments',
            'Remove transitive role chains by using single scoped roles',
            'Implement separation-of-duties policies for sensitive operations',
            'Use Access Reviews to periodically validate role necessity',
            'Document and approve all role combinations that cross security boundaries',
        ],
    },
}

# Natural language → API mapping patterns
QUERY_TRANSLATIONS = [
    {'patterns': ['high risk identities', 'critical identities', 'risky identities', 'dangerous identities'],
     'api': 'GET /api/risky-identities', 'description': 'Top risky identities ranked by risk score'},
    {'patterns': ['escalate to owner', 'privilege escalation', 'escalation paths', 'attack paths'],
     'api': 'GET /api/graph-findings?type=PRIVILEGE_ESCALATION', 'description': 'Privilege escalation attack paths'},
    {'patterns': ['keyvault', 'key vault', 'secret access', 'vault secrets'],
     'api': 'GET /api/graph-findings?type=KEYVAULT_SECRET_ACCESS', 'description': 'Key Vault secret access findings'},
    {'patterns': ['spn', 'service principal', 'app registration', 'client secret'],
     'api': 'GET /api/graph-findings?type=SPN_SECRET_EXPOSURE', 'description': 'SPN credential exposure findings'},
    {'patterns': ['posture', 'security score', 'overall security', 'how secure'],
     'api': 'GET /api/posture-score', 'description': 'Current security posture score'},
    {'patterns': ['privileged', 'admin', 'global admin', 'high privilege'],
     'api': 'GET /api/privileged-identities', 'description': 'Privileged identity list'},
    {'patterns': ['remediation', 'fix', 'what to fix', 'priority'],
     'api': 'GET /api/remediation-priority', 'description': 'Prioritized remediation queue'},
    {'patterns': ['open findings', 'unresolved', 'active findings'],
     'api': 'GET /api/graph-findings?status=open', 'description': 'Open attack path findings'},
    {'patterns': ['breached sla', 'sla breach', 'overdue'],
     'api': 'GET /api/graph-findings?status=open', 'description': 'Findings with SLA breaches'},
    {'patterns': ['expired credentials', 'stale credentials', 'credential health'],
     'api': 'GET /api/dashboard/posture', 'description': 'Credential health and posture data'},
    # Graph-oriented investigation patterns
    {'patterns': ['who can access', 'who has access to', 'access to resource'],
     'api': 'GET /api/resources/{id}/access', 'description': 'Identities with access to a specific resource',
     'query_type': 'resource_access'},
    {'patterns': ['show attack paths for', 'attack paths from', 'escalation from'],
     'api': 'GET /api/identities/{id}/attack-paths', 'description': 'Attack path analysis for an identity',
     'query_type': 'attack_paths'},
    {'patterns': ['over-privileged', 'overprivileged', 'excessive permissions', 'too many permissions'],
     'api': 'GET /api/identities?risk_level=critical', 'description': 'Over-privileged identities with excessive permissions',
     'query_type': 'over_privileged'},
    {'patterns': ['dormant accounts with', 'dormant high privilege', 'inactive privileged', 'stale admins'],
     'api': 'GET /api/identities?activity_status=dormant&risk_level=critical', 'description': 'Dormant accounts with high privileges',
     'query_type': 'dormant_privileged'},
    {'patterns': ['lateral movement', 'lateral paths from', 'move laterally'],
     'api': 'GET /api/identities/{id}/attack-paths?type=lateral_movement', 'description': 'Lateral movement paths from an identity',
     'query_type': 'lateral_movement'},
    {'patterns': ['blast radius', 'impact of', 'what can this identity reach'],
     'api': 'GET /api/identities/{id}/attack-paths', 'description': 'Blast radius and reachable resources',
     'query_type': 'blast_radius'},
    {'patterns': ['compliance gaps', 'non-compliant', 'compliance violations', 'failing compliance'],
     'api': 'GET /api/dashboard/compliance', 'description': 'Compliance gaps and violations',
     'query_type': 'compliance_gaps'},
    {'patterns': ['recent anomalies', 'new anomalies', 'latest anomalies', 'anomaly summary'],
     'api': 'GET /api/anomalies?resolved=false', 'description': 'Recent unresolved anomalies',
     'query_type': 'recent_anomalies'},
    {'patterns': ['spn credentials expiring', 'expiring secrets', 'credential expiry'],
     'api': 'GET /api/spns?credential_filter=expiring_soon', 'description': 'Service principals with expiring credentials',
     'query_type': 'spn_expiring'},
    {'patterns': ['owner chain', 'who owns', 'ownership of'],
     'api': 'GET /api/identities/{id}', 'description': 'Identity ownership chain and details',
     'query_type': 'ownership'},
]


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

CRITICAL SECURITY RULES:
1. You ONLY answer questions related to identity security and the AuditGraph platform.
2. You MUST only use the data provided in the context below. Never fabricate data or statistics.
3. You MUST NOT attempt to query databases, call APIs, or access external systems.
4. You MUST NOT reveal internal system details, database schemas, table names, or infrastructure.
5. If the context includes a TENANT BOUNDARY prefix, you MUST only discuss data for that organization.
6. Never reference, compare, or speculate about data from other organizations or tenants.
7. For unrelated questions, politely redirect users to security topics.

When providing answers:
- Be concise and actionable
- Reference specific data when available
- Suggest next steps or investigations
- Use markdown formatting for readability
- Cite specific identity counts and risk levels from the provided context"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY', '')
        self.model = DEFAULT_MODEL
        self.client = None

    def _get_client(self):
        if self.client is None:
            try:
                import anthropic
                self.client = anthropic.Anthropic(
                    api_key=self.api_key,
                    timeout=30.0,
                )
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
            try:
                db._rollback()
            except Exception:
                pass
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
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=messages,
        )

        return response.content[0].text

    # ── Phase 12: Context-aware copilot methods ──────────────────────

    def explain_attack_path(self, finding: dict) -> str:
        """Generate a rich explanation of an attack path finding."""
        client = self._get_client()

        attack_path = finding.get('attack_path') or {}
        nodes = attack_path.get('nodes', [])
        edges = attack_path.get('edges', [])

        path_desc = " → ".join(
            f"{n.get('type', '?')}:{n.get('name', '?')}" for n in nodes
        ) if nodes else "No path data"

        edge_desc = ", ".join(
            f"{e.get('source', '?')} --[{e.get('type', '?')}]--> {e.get('target', '?')}"
            for e in edges
        ) if edges else ""

        knowledge = REMEDIATION_KNOWLEDGE.get(finding.get('finding_type', ''), {})

        prompt = f"""Explain this security attack path finding in clear, actionable terms.

**Finding:** {finding.get('title', 'Unknown')}
**Type:** {finding.get('finding_type', 'Unknown')}
**Severity:** {finding.get('severity', 'unknown')}
**Risk Score:** {finding.get('risk_score', 0)}
**Identity:** {finding.get('identity_name', 'Unknown')} ({finding.get('identity_category', 'unknown')})
**Attack Path:** {path_desc}
**Path Edges:** {edge_desc}
**Description:** {finding.get('description', 'N/A')}
**Known Risk:** {knowledge.get('risk', 'N/A')}

Explain:
1. What this attack path means in practical terms
2. Who/what is at risk and what an attacker could achieve
3. The chain of permissions that enables this path
4. How critical this is relative to typical cloud environments

Use markdown formatting. Be specific to the actual path, not generic."""

        response = client.messages.create(
            model=self.model,
            max_tokens=1500,
            system="You are a cloud security expert explaining attack paths to security engineers. Be specific, concise, and actionable.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def get_remediation_advice(self, finding: dict) -> str:
        """Generate remediation advice for a specific finding."""
        client = self._get_client()
        knowledge = REMEDIATION_KNOWLEDGE.get(finding.get('finding_type', ''), {})

        prompt = f"""Provide specific remediation guidance for this security finding.

**Finding:** {finding.get('title', 'Unknown')}
**Type:** {finding.get('finding_type', 'Unknown')}
**Severity:** {finding.get('severity', 'unknown')}
**Identity:** {finding.get('identity_name', 'Unknown')} ({finding.get('identity_category', 'unknown')})
**Current Remediation Hint:** {finding.get('remediation', 'None')}
**Known Steps:** {json.dumps(knowledge.get('steps', []))}

Provide:
1. Immediate actions (within 24 hours)
2. Short-term fixes (within 1 week)
3. Long-term hardening (ongoing)
4. Verification steps to confirm remediation
5. Azure CLI or PowerShell commands where applicable

Use markdown with numbered steps. Be specific to this finding type."""

        response = client.messages.create(
            model=self.model,
            max_tokens=1500,
            system="You are a cloud security remediation expert. Provide Azure-specific, actionable remediation steps.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def translate_security_query(self, question: str) -> dict:
        """Translate a natural language security question into an API suggestion."""
        question_lower = question.lower()
        for mapping in QUERY_TRANSLATIONS:
            for pattern in mapping['patterns']:
                if pattern in question_lower:
                    return {
                        'matched': True,
                        'api': mapping['api'],
                        'description': mapping['description'],
                        'original_question': question,
                    }
        return {
            'matched': False,
            'api': None,
            'description': 'No direct API match — use the general copilot chat for complex questions.',
            'original_question': question,
        }

    def generate_security_summary(self, context_data: dict) -> str:
        """Generate an AI-powered tenant security summary."""
        client = self._get_client()

        prompt = f"""Generate a concise executive security summary for this cloud tenant.

**Posture Score:** {context_data.get('posture_score', 'N/A')}/100
**Total Identities:** {context_data.get('total_identities', 0)}
**Critical Risk:** {context_data.get('critical_count', 0)}
**High Risk:** {context_data.get('high_count', 0)}
**Open Findings:** {context_data.get('open_findings', 0)}
**Critical Findings:** {context_data.get('critical_findings', 0)}
**SLA Breaches:** {context_data.get('sla_breaches', 0)}
**Privileged Identities:** {context_data.get('privileged_count', 0)}
**Expired Credentials:** {context_data.get('expired_credentials', 0)}
**Attack Paths Detected:** {context_data.get('attack_paths', 0)}
**Recent Anomalies:** {context_data.get('recent_anomalies', 0)}
**Latest Scan:** {context_data.get('last_scan', 'Never')}

Provide:
1. **Overall Assessment** — one-line verdict (Critical/Warning/Moderate/Healthy)
2. **Top 3 Risks** — most urgent security concerns
3. **Recommended Actions** — prioritized next steps (numbered)
4. **Positive Findings** — what's going well

Keep it under 300 words. Use markdown formatting."""

        response = client.messages.create(
            model=self.model,
            max_tokens=1200,
            system="You are a CISO advisor providing executive security summaries. Be direct, specific, and prioritize actionable insights.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def contextual_query(self, question: str, context: str, conversation_history: list = None) -> str:
        """Answer a question with specific finding/identity context."""
        client = self._get_client()

        messages = []
        if conversation_history:
            for msg in conversation_history[-6:]:
                messages.append({"role": msg["role"], "content": msg["content"]})
        messages.append({"role": "user", "content": question})

        system = f"""{self.SYSTEM_PROMPT}

--- Security Context ---
{context}"""

        response = client.messages.create(
            model=self.model,
            max_tokens=1500,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    # ── Investigation methods (AI Copilot Enhancement) ────────────

    def investigate_identity(self, identity_data: dict, question: str = None) -> dict:
        """Structured identity investigation with risk assessment and recommendations."""
        client = self._get_client()

        identity = identity_data.get('identity', {})
        anomalies = identity_data.get('anomalies', [])
        pim = identity_data.get('pim', {})
        attack_paths = identity_data.get('attack_paths', [])
        roles = identity_data.get('roles', [])
        credentials = identity_data.get('credentials', {})

        prompt = f"""Investigate this cloud identity and provide a structured security assessment.

**Identity:** {identity.get('display_name', 'Unknown')} ({identity.get('identity_id', '')})
**Category:** {identity.get('identity_category', 'unknown')}
**Risk Level:** {identity.get('risk_level', 'unknown')} (Score: {identity.get('risk_score', 0)})
**Activity Status:** {identity.get('activity_status', 'unknown')}
**Last Sign-In:** {identity.get('last_sign_in', 'Never')}
**Credential Status:** {credentials.get('status', identity.get('credential_status', 'unknown'))}
**Credential Count:** {credentials.get('count', identity.get('credential_count', 0))}

**Roles ({len(roles)}):** {json.dumps(roles[:10], default=str) if roles else 'None'}
**Anomalies ({len(anomalies)}):** {json.dumps([{{'type': a.get('anomaly_type'), 'severity': a.get('severity'), 'resolved': a.get('resolved')}} for a in anomalies[:5]], default=str) if anomalies else 'None'}
**PIM:** Eligible: {pim.get('eligible_count', 0)}, Active: {pim.get('active_count', 0)}
**Attack Paths ({len(attack_paths)}):** {json.dumps([{{'type': ap.get('path_type'), 'severity': ap.get('severity')}} for ap in attack_paths[:5]], default=str) if attack_paths else 'None'}
**Risk Reasons:** {identity.get('risk_reasons', 'N/A')}

{f'**Specific Question:** {question}' if question else ''}

Provide a structured report with:
1. **Risk Assessment** — overall risk verdict and confidence
2. **Key Findings** — top 3-5 security findings for this identity
3. **Attack Surface** — what an attacker could achieve with this identity
4. **Recommendations** — prioritized actions to reduce risk

Use markdown. Be specific to this identity's data, not generic."""

        response = client.messages.create(
            model=self.model,
            max_tokens=2000,
            system="You are a cloud identity security investigator. Provide thorough, data-driven investigations of identity security posture. Be specific and actionable.",
            messages=[{"role": "user", "content": prompt}],
        )

        report = response.content[0].text
        # Derive severity from identity risk
        risk = identity.get('risk_level', 'medium')
        severity = 'critical' if risk == 'critical' else ('high' if risk == 'high' else 'medium')

        return {
            'report': report,
            'findings': self._extract_findings(report),
            'severity': severity,
            'suggestions': [
                f"Show attack paths for {identity.get('display_name', 'this identity')}",
                f"What credentials does {identity.get('display_name', 'this identity')} have?",
                "What remediation steps should we take?",
                "Compare this identity to similar ones",
            ],
        }

    def investigate_resource(self, resource_data: dict, question: str = None) -> dict:
        """Structured resource investigation with security assessment."""
        client = self._get_client()

        resource = resource_data.get('resource', {})
        access = resource_data.get('access', [])
        compliance = resource_data.get('compliance', {})

        prompt = f"""Investigate this cloud resource and provide a security assessment.

**Resource:** {resource.get('name', 'Unknown')}
**Type:** {resource.get('resource_type', 'unknown')}
**Resource ID:** {resource.get('resource_id', '')}
**Risk Level:** {resource.get('risk_level', 'unknown')} (Score: {resource.get('risk_score', 0)})
**Subscription:** {resource.get('subscription_name', resource.get('subscription_id', 'Unknown'))}

**Security Config:**
- Encryption: {resource.get('encryption_type', 'N/A')}
- Network Access: {resource.get('network_default_action', resource.get('public_network_access', 'N/A'))}
- HTTPS Only: {resource.get('https_only', 'N/A')}
- Soft Delete: {resource.get('soft_delete_enabled', 'N/A')}

**Access:** {len(access)} identities have access
{json.dumps([{{'identity': a.get('display_name', a.get('identity_id')), 'role': a.get('rbac_role'), 'scope': a.get('scope_type')}} for a in access[:10]], default=str) if access else 'No access data'}

**Compliance:** {json.dumps(compliance, default=str) if compliance else 'No compliance data'}

{f'**Specific Question:** {question}' if question else ''}

Provide a structured report with:
1. **Security Assessment** — overall security posture of this resource
2. **Key Findings** — top security concerns
3. **Access Review** — who has access and whether it's appropriate
4. **Recommendations** — prioritized hardening steps

Use markdown. Be specific to this resource."""

        response = client.messages.create(
            model=self.model,
            max_tokens=2000,
            system="You are a cloud resource security analyst. Evaluate resource configurations, access patterns, and compliance status. Provide actionable security recommendations.",
            messages=[{"role": "user", "content": prompt}],
        )

        report = response.content[0].text
        risk = resource.get('risk_level', 'medium')
        severity = 'critical' if risk == 'critical' else ('high' if risk == 'high' else 'medium')

        return {
            'report': report,
            'findings': self._extract_findings(report),
            'severity': severity,
            'suggestions': [
                f"Who can access {resource.get('name', 'this resource')}?",
                "What compliance checks are failing?",
                "How do I harden this resource?",
                "Show network exposure details",
            ],
        }

    def analyze_security_posture(self, posture_data: dict) -> dict:
        """Tenant-wide security posture analysis with prioritized findings."""
        client = self._get_client()

        prompt = f"""Analyze this tenant's overall security posture and provide prioritized action items.

**Posture Score:** {posture_data.get('posture_score', 'N/A')}/100
**Total Identities:** {posture_data.get('total_identities', 0)}
**Risk Distribution:** Critical: {posture_data.get('critical_count', 0)}, High: {posture_data.get('high_count', 0)}, Medium: {posture_data.get('medium_count', 0)}, Low: {posture_data.get('low_count', 0)}

**Top Critical Identities:** {json.dumps(posture_data.get('top_critical', [])[:5], default=str)}

**Credential Health:**
- Expired: {posture_data.get('expired_credentials', 0)}
- Expiring Soon: {posture_data.get('expiring_credentials', 0)}
- Healthy: {posture_data.get('healthy_credentials', 0)}

**Anomalies:** {posture_data.get('unresolved_anomalies', 0)} unresolved ({posture_data.get('critical_anomalies', 0)} critical)
**Compliance Score:** {posture_data.get('compliance_score', 'N/A')}
**SPN Stats:** {posture_data.get('spn_total', 0)} total, {posture_data.get('spn_critical', 0)} critical
**Recent Drift Changes:** {posture_data.get('recent_drift_count', 0)}

Provide:
1. **Executive Summary** — one-paragraph posture assessment
2. **Top 5 Priorities** — most urgent actions ranked by impact
3. **Compliance Gaps** — key compliance issues to address
4. **Risk Trends** — is the posture improving or degrading?
5. **Quick Wins** — low-effort, high-impact improvements

Use markdown. Be specific and data-driven."""

        response = client.messages.create(
            model=self.model,
            max_tokens=2000,
            system="You are a CISO advisor performing a security posture review. Provide strategic, prioritized recommendations based on the data. Focus on what matters most.",
            messages=[{"role": "user", "content": prompt}],
        )

        report = response.content[0].text
        score = posture_data.get('posture_score', 50)
        severity = 'critical' if score < 40 else ('high' if score < 60 else ('medium' if score < 80 else 'low'))

        return {
            'report': report,
            'findings': self._extract_findings(report),
            'severity': severity,
            'suggestions': [
                "What are our biggest compliance gaps?",
                "Which identities need immediate attention?",
                "How do we improve our posture score?",
                "Show risk trends over time",
            ],
        }

    @staticmethod
    def _extract_findings(report: str) -> list:
        """Extract key findings from a markdown report as a list of strings."""
        findings = []
        in_findings = False
        for line in report.split('\n'):
            stripped = line.strip()
            if 'finding' in stripped.lower() or 'priorit' in stripped.lower():
                in_findings = True
                continue
            if in_findings and stripped.startswith(('- ', '* ', '1.', '2.', '3.', '4.', '5.')):
                # Strip markdown list prefix
                text = stripped.lstrip('-*0123456789. ').strip()
                if text:
                    findings.append(text)
            elif in_findings and stripped.startswith('#'):
                in_findings = False
        return findings[:10]
