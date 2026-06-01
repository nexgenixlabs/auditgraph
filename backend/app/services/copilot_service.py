"""
AuditGraph AI Security Copilot Service (Phase 79 + Phase 12)

Wraps the Anthropic Claude API to answer security questions
using live AuditGraph data as context.

Phase 12 additions:
- explain_attack_path() — rich explanation of a finding's attack chain
- get_remediation_advice() — type-specific remediation guidance
- translate_security_query() — natural language → API mapping
- generate_security_summary() — tenant-wide security summary

AG-132: All data-gathering methods enforce org_id (CWE-639, OWASP A01:2021).
"""
import json
import logging
import os
from datetime import datetime

from app.security.tenant_scope import requires_org_id, TenantScopeError

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv('LLM_MODEL', 'claude-sonnet-4-5-20250514')


def get_platform_copilot_service():
    """Return a CopilotService using the platform-managed config, or (None, error_msg).

    AG-Argus-OSS (2026-05-31): honors `COPILOT_PROVIDER=ollama` to allow
    Argus to run on a local open-source LLM without an Anthropic API key.
    See ollama_copilot_plan memory for setup.
    """
    provider = os.getenv('COPILOT_PROVIDER', 'anthropic').lower().strip()
    api_key = os.getenv('ANTHROPIC_API_KEY', '').strip()
    if provider == 'ollama':
        # No API key required — CopilotService routes to OllamaAnthropicAdapter
        # at first request, with helpful errors if the daemon isn't running.
        return CopilotService(api_key or 'ollama-no-key-needed'), None
    if not api_key:
        return None, (
            'AI Copilot is not configured. Set ANTHROPIC_API_KEY for '
            'production, OR COPILOT_PROVIDER=ollama for a local open-source '
            'LLM (see ollama_copilot_plan memory for setup).'
        )
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
            'Enable Conditional Access for workload identities',
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
        # AG-Argus-OSS (2026-05-31): provider routing — 'anthropic' (default,
        # production) or 'ollama' (free local LLM for dev/test/demo). See
        # [[ollama-copilot-plan]] memory for design rationale.
        self.provider = os.getenv('COPILOT_PROVIDER', 'anthropic').lower().strip()

    def _get_client(self):
        """Return an Anthropic-shaped LLM client. Provider determined by
        COPILOT_PROVIDER env var (anthropic | ollama). Both expose the same
        `.messages.create(model, max_tokens, system, messages)` surface so
        all downstream call sites work unchanged."""
        if self.client is None:
            if self.provider == 'ollama':
                # Local Ollama — fail fast with helpful guidance if daemon
                # not running, instead of hanging the user's first prompt.
                from app.services.llm_providers.ollama_adapter import OllamaAnthropicAdapter
                if not OllamaAnthropicAdapter.is_available():
                    raise RuntimeError(
                        "Ollama provider selected (COPILOT_PROVIDER=ollama) but the "
                        "Ollama daemon is not reachable at "
                        f"{os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')}. "
                        "Start it with `ollama serve` (or `brew services start ollama`), "
                        "then pull a model: `ollama pull llama3.1:8b`."
                    )
                self.client = OllamaAnthropicAdapter()
                # Override the Claude model name so call sites' `model=...`
                # arg gets remapped to the configured Ollama model by the
                # adapter's _MessagesAPI.create() — see ollama_adapter.py
                self.model = os.getenv('OLLAMA_MODEL', 'llama3.1:8b')
            else:
                # Default — real Anthropic API
                if not self.api_key:
                    raise RuntimeError(
                        "Anthropic API key not configured. Set ANTHROPIC_API_KEY in "
                        "env, OR switch to local LLM with COPILOT_PROVIDER=ollama "
                        "(see ollama_copilot_plan memory for setup)."
                    )
                try:
                    import anthropic
                    self.client = anthropic.Anthropic(
                        api_key=self.api_key,
                        timeout=30.0,
                        max_retries=2,  # Built-in SDK retry with backoff
                    )
                except ImportError:
                    raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

        # Circuit breaker check — block if LLM API is repeatedly failing
        from app.resilience import get_circuit_breaker, CircuitBreakerOpenError
        cb = get_circuit_breaker('llm_api')
        if not cb.allow_request():
            raise CircuitBreakerOpenError("LLM API circuit breaker is OPEN")
        return self.client

    @requires_org_id
    def gather_context(self, db, *, org_id: int) -> str:
        """Gather current AuditGraph data as context for the AI.

        AG-132: All queries scoped to org_id. No cross-tenant data leaks.
        """
        context_parts = []

        try:
            cursor = db.conn.cursor()

            # Latest run stats — scoped to org
            cursor.execute("""
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count
                FROM discovery_runs
                WHERE status = 'completed' AND organization_id = %s
                ORDER BY id DESC LIMIT 1
            """, (org_id,))
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

            # Anomaly stats — scoped to org
            if run_id:
                cursor.execute("""
                    SELECT COUNT(*) as total,
                           COUNT(*) FILTER (WHERE resolved = false) as unresolved,
                           COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                           COUNT(*) FILTER (WHERE severity = 'high') as high
                    FROM anomalies
                    WHERE run_id = %s AND organization_id = %s
                """, (run_id, org_id))
                anom = cursor.fetchone()
                if anom and anom[0] > 0:
                    context_parts.append(
                        f"Anomalies: {anom[0]} total, {anom[1]} unresolved "
                        f"({anom[2]} critical, {anom[3]} high)"
                    )

            # Credential health — scoped to org
            if run_id:
                cursor.execute("""
                    SELECT
                        COUNT(*) FILTER (WHERE credential_status = 'expired') as expired,
                        COUNT(*) FILTER (WHERE credential_status = 'expiring_soon') as expiring,
                        COUNT(*) FILTER (WHERE credential_status = 'healthy') as healthy
                    FROM identities
                    WHERE discovery_run_id = %s AND organization_id = %s
                """, (run_id, org_id))
                creds = cursor.fetchone()
                if creds:
                    context_parts.append(
                        f"Credential health: {creds[0]} expired, {creds[1]} expiring soon, {creds[2]} healthy"
                    )

            # Risk distribution — scoped to org
            if run_id:
                cursor.execute("""
                    SELECT identity_category, COUNT(*) as cnt
                    FROM identities
                    WHERE discovery_run_id = %s AND organization_id = %s
                    GROUP BY identity_category ORDER BY cnt DESC
                """, (run_id, org_id))
                cats = cursor.fetchall()
                if cats:
                    cat_str = ", ".join(f"{c[0]}: {c[1]}" for c in cats)
                    context_parts.append(f"Identity categories: {cat_str}")

            # Recent drift — scoped to org
            cursor.execute("""
                SELECT changes FROM drift_reports
                WHERE organization_id = %s
                ORDER BY id DESC LIMIT 1
            """, (org_id,))
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
        except TenantScopeError:
            raise
        except Exception as e:
            logger.warning(f"Error gathering copilot context: {e}")
            try:
                db._rollback()
            except Exception:
                pass
            context_parts.append("(Some context data unavailable)")

        # AG-132: Log fingerprint of data passed to LLM for audit trail
        logger.info(
            "copilot_context_gathered",
            extra={
                "event": "copilot_context_gathered",
                "org_id": org_id,
                "context_line_count": len(context_parts),
            },
        )

        return "\n".join(context_parts)

    @requires_org_id
    def get_suggestions(self, db, *, org_id: int) -> list:
        """Return contextual quick-ask suggestions based on current posture.

        AG-132: All queries scoped to org_id. No cross-tenant data leaks.
        """
        suggestions = [
            "What is our current security posture?",
            "Which identities need immediate attention?",
        ]

        try:
            cursor = db.conn.cursor()

            # Check for anomalies — scoped to org
            cursor.execute(
                "SELECT COUNT(*) FROM anomalies WHERE resolved = false AND organization_id = %s",
                (org_id,),
            )
            unresolved = cursor.fetchone()[0]
            if unresolved > 0:
                suggestions.append(f"Explain the {unresolved} unresolved anomalies")

            # Check for expired credentials — scoped to org
            cursor.execute("""
                SELECT COUNT(*) FROM identities i
                JOIN discovery_runs r ON i.discovery_run_id = r.id
                WHERE r.status = 'completed'
                  AND r.organization_id = %s
                  AND i.organization_id = %s
                  AND i.credential_status = 'expired'
            """, (org_id, org_id))
            expired = cursor.fetchone()
            if expired and expired[0] > 0:
                suggestions.append("How do I fix expired credentials?")

            # Check for critical identities — scoped to org
            cursor.execute("""
                SELECT COUNT(*) FROM identities i
                JOIN discovery_runs r ON i.discovery_run_id = r.id
                WHERE r.status = 'completed'
                  AND r.organization_id = %s
                  AND i.organization_id = %s
                  AND i.risk_level = 'critical'
            """, (org_id, org_id))
            critical = cursor.fetchone()
            if critical and critical[0] > 0:
                suggestions.append(f"What makes {critical[0]} identities critical risk?")

            cursor.close()
        except TenantScopeError:
            raise
        except Exception:
            pass

        suggestions.append("What remediation steps should we prioritize?")
        return suggestions[:6]

    @requires_org_id
    def ask(self, question: str, conversation_history: list, db, *, org_id: int) -> str:
        """Send a question to Claude with AuditGraph context.

        AG-132: org_id required; context is scoped to the caller's org.
        """
        client = self._get_client()
        context = self.gather_context(db, org_id=org_id)

        messages = []
        for msg in conversation_history[-10:]:  # Keep last 10 messages
            messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })
        messages.append({"role": "user", "content": question})

        system = f"{self.SYSTEM_PROMPT}\n\n--- Current AuditGraph Data ---\n{context}"

        from app.resilience import get_circuit_breaker
        cb = get_circuit_breaker('llm_api')
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system,
                messages=messages,
            )
            cb.record_success()
            return response.content[0].text
        except Exception:
            cb.record_failure()
            raise

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

    def explain_identity_risk(self, data: dict) -> dict:
        """Generate a structured AI explanation of identity risk.

        Input data keys: identity_name, risk_score, risk_level, risk_drivers[],
                         blast_radius, attack_path_count, last_activity.

        Returns: { summary, drivers[], implications, recommended_action }
        """
        client = self._get_client()

        drivers_text = '\n'.join(f'- {d}' for d in (data.get('risk_drivers') or ['No specific drivers']))

        prompt = f"""Analyze this identity's risk profile and return a JSON object.

**Identity:** {data.get('identity_name', 'Unknown')}
**Risk Score:** {data.get('risk_score', 0)}/100
**Risk Level:** {data.get('risk_level', 'unknown')}
**Risk Drivers:**
{drivers_text}
**Blast Radius Score:** {data.get('blast_radius', 0)}/100
**Attack Path Count:** {data.get('attack_path_count', 0)}
**Last Activity:** {data.get('last_activity', 'Unknown')}

RULES:
1. Only reference the data provided above. Do NOT invent additional facts.
2. Be specific to this identity — not generic security advice.
3. Keep each field concise (2-3 sentences max).

Return ONLY valid JSON with exactly these fields:
{{
  "summary": "A 1-2 sentence risk overview of this specific identity",
  "drivers": ["driver 1 explanation", "driver 2 explanation", ...],
  "implications": "What could happen if this identity is compromised (2-3 sentences)",
  "recommended_action": "The single most impactful remediation action for this identity"
}}"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=800,
                system="You are a cloud identity security analyst. Return ONLY valid JSON. Do not wrap in markdown code blocks. Do not add commentary outside the JSON.",
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            # Strip markdown code fences if present
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3].rstrip()
            result = json.loads(text)
            # Validate required keys
            for key in ('summary', 'drivers', 'implications', 'recommended_action'):
                if key not in result:
                    result[key] = ''
            if not isinstance(result['drivers'], list):
                result['drivers'] = [str(result['drivers'])]
            return result
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI risk explanation parse failed: %s", e)
            # Fallback to raw text if JSON parse fails
            return {
                'summary': f"The identity {data.get('identity_name', 'Unknown')} has a risk score of {data.get('risk_score', 0)}/100 ({data.get('risk_level', 'unknown')}).",
                'drivers': data.get('risk_drivers', []),
                'implications': 'Unable to generate AI analysis. Review the risk drivers manually.',
                'recommended_action': 'Review the identity risk drivers and take appropriate action.',
            }

    def explain_attack_path_chain(self, data: dict) -> dict:
        """Generate a structured AI explanation of a privilege escalation chain.

        Input data keys:
            identity: str — the identity name
            attack_path: list — ordered steps in the escalation chain,
                each with node_type, node_id, node_label, description
            risk_level: str — critical/high/medium/low

        Returns: { explanation, security_impact, recommended_fix }
        """
        client = self._get_client()

        identity = data.get('identity', 'Unknown')
        risk_level = data.get('risk_level', 'unknown')
        path_steps = data.get('attack_path', [])

        # Build step-by-step description from path data
        steps_text = []
        for i, step in enumerate(path_steps, 1):
            if isinstance(step, dict):
                label = step.get('node_label') or step.get('name') or step.get('node_id', '?')
                ntype = step.get('node_type') or step.get('type', '?')
                desc = step.get('description', '')
                line = f"Step {i}: [{ntype}] {label}"
                if desc:
                    line += f" — {desc}"
                steps_text.append(line)
            elif isinstance(step, str):
                steps_text.append(f"Step {i}: {step}")

        chain_desc = '\n'.join(steps_text) if steps_text else 'No path steps provided'

        # Build the arrow chain for quick visual
        arrow_chain = ' -> '.join(
            (s.get('node_label') or s.get('name') or '?') if isinstance(s, dict) else str(s)
            for s in path_steps
        ) if path_steps else 'N/A'

        prompt = f"""Analyze this privilege escalation chain and return a JSON object.

**Identity:** {identity}
**Risk Level:** {risk_level}
**Escalation Chain:** {arrow_chain}

**Detailed Steps:**
{chain_desc}

RULES:
1. ONLY reference the data provided above. Do NOT invent additional facts or assume permissions not listed.
2. Explain each step in the chain and how it enables the next step.
3. Describe the concrete security impact if this path is exploited.
4. Suggest specific remediation to break this chain.
5. Keep each field concise and actionable (3-5 sentences max).

Return ONLY valid JSON with exactly these fields:
{{
  "explanation": "Step-by-step explanation of how the escalation chain works, describing each step and the transition between steps",
  "security_impact": "What an attacker could achieve by exploiting this path — be specific about the blast radius and data at risk",
  "recommended_fix": "The most effective remediation action to break this escalation chain"
}}"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=1000,
                system="You are a cloud identity security analyst specializing in privilege escalation detection. Return ONLY valid JSON. Do not wrap in markdown code blocks.",
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            # Strip markdown code fences if present
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3].rstrip()
            result = json.loads(text)
            # Validate required keys
            for key in ('explanation', 'security_impact', 'recommended_fix'):
                if key not in result:
                    result[key] = ''
            return result
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI attack path explanation parse failed: %s", e)
            return self._fallback_attack_path_explanation(data)

    @staticmethod
    def _fallback_attack_path_explanation(data: dict) -> dict:
        """Deterministic attack path explanation when AI is unavailable."""
        identity = data.get('identity', 'Unknown')
        risk_level = data.get('risk_level', 'unknown')
        path_steps = data.get('attack_path', [])

        # Build explanation from steps
        step_descs = []
        for i, step in enumerate(path_steps, 1):
            if isinstance(step, dict):
                label = step.get('node_label') or step.get('name') or step.get('node_id', '?')
                ntype = step.get('node_type') or step.get('type', '?')
                desc = step.get('description', '')
                step_descs.append(f"Step {i}: The {ntype} '{label}' {desc}." if desc
                                  else f"Step {i}: Involves {ntype} '{label}'.")
            elif isinstance(step, str):
                step_descs.append(f"Step {i}: {step}.")

        explanation = (
            f"The identity '{identity}' participates in a {risk_level} severity "
            f"privilege escalation chain with {len(path_steps)} step(s). "
            + ' '.join(step_descs)
        )

        # Impact based on risk level
        impact_map = {
            'critical': f"If exploited, an attacker starting from '{identity}' could escalate to full administrative control, potentially compromising all tenant resources and data.",
            'high': f"Exploitation could allow an attacker to gain elevated privileges from '{identity}', accessing sensitive resources beyond the identity's intended scope.",
            'medium': f"This path allows privilege elevation from '{identity}', though the target privilege has a limited blast radius.",
        }
        security_impact = impact_map.get(risk_level,
            f"This escalation chain from '{identity}' represents a {risk_level} level security concern.")

        # Fix based on chain length
        if len(path_steps) <= 2:
            fix = "Remove the direct role assignment that enables this single-hop escalation. Consider replacing standing access with PIM just-in-time activation."
        else:
            fix = "Break the escalation chain by removing the intermediate role assignment at the weakest link. Apply least-privilege scoping and enable PIM for privileged roles."

        return {
            'explanation': explanation,
            'security_impact': security_impact,
            'recommended_fix': fix,
        }

    def generate_executive_narrative(self, data: dict) -> dict:
        """Generate an AI executive security narrative for CISO consumption.

        Input data keys:
            agirs_score: int — AuditGraph Identity Risk Score (0-100)
            risk_level: str — overall risk level
            top_risk_drivers: list — key risk driver descriptions
            top_risk_identities: list — names/IDs of highest-risk identities
            recommended_actions: list — prioritized remediation actions
            projected_score: int — projected score after remediation

        Returns: { executive_summary, top_risks[], recommended_actions[], expected_improvement }
        """
        client = self._get_client()

        agirs = data.get('agirs_score', 0)
        risk_level = data.get('risk_level', 'unknown')
        drivers = data.get('top_risk_drivers', [])
        identities = data.get('top_risk_identities', [])
        actions = data.get('recommended_actions', [])
        projected = data.get('projected_score', 0)

        drivers_text = '\n'.join(f'- {d}' for d in drivers) if drivers else '- No specific drivers'
        identities_text = '\n'.join(f'- {i}' for i in identities) if identities else '- None identified'
        actions_text = '\n'.join(f'- {a}' for a in actions) if actions else '- No actions specified'

        prompt = f"""Generate an executive security narrative for a CISO audience and return a JSON object.

**AGIRS Score:** {agirs}/100
**Risk Level:** {risk_level}
**Projected Score After Remediation:** {projected}/100

**Top Risk Drivers:**
{drivers_text}

**Top Risk Identities:**
{identities_text}

**Recommended Actions:**
{actions_text}

RULES:
1. ONLY reference the data provided above. Do NOT invent metrics, counts, or facts not listed.
2. Write for a CISO audience — strategic, concise, no technical jargon.
3. The executive_summary MUST be under 150 words.
4. top_risks should have 2-4 items, each a concise risk statement.
5. recommended_actions should have 2-4 items, each an actionable step.
6. expected_improvement should quantify the score improvement ({agirs} → {projected}).

Return ONLY valid JSON with exactly these fields:
{{
  "executive_summary": "A strategic overview of the organization's identity security posture (under 150 words)",
  "top_risks": ["risk 1", "risk 2", ...],
  "recommended_actions": ["action 1", "action 2", ...],
  "expected_improvement": "Projected impact statement referencing the score improvement"
}}"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=800,
                system="You are a CISO advisor generating executive security narratives. Return ONLY valid JSON. Do not wrap in markdown code blocks. Be concise, strategic, and data-driven. Limit executive_summary to 150 words.",
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3].rstrip()
            result = json.loads(text)
            for key in ('executive_summary', 'top_risks', 'recommended_actions', 'expected_improvement'):
                if key not in result:
                    result[key] = '' if key in ('executive_summary', 'expected_improvement') else []
            if not isinstance(result['top_risks'], list):
                result['top_risks'] = [str(result['top_risks'])]
            if not isinstance(result['recommended_actions'], list):
                result['recommended_actions'] = [str(result['recommended_actions'])]
            return result
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI executive narrative parse failed: %s", e)
            return self._fallback_executive_narrative(data)

    @staticmethod
    def _fallback_executive_narrative(data: dict) -> dict:
        """Deterministic executive narrative when AI is unavailable."""
        agirs = data.get('agirs_score', 0)
        risk_level = data.get('risk_level', 'unknown')
        drivers = data.get('top_risk_drivers', [])
        identities = data.get('top_risk_identities', [])
        actions = data.get('recommended_actions', [])
        projected = data.get('projected_score', 0)

        # Build executive summary
        if agirs < 40:
            posture = "critically exposed"
            urgency = "Immediate executive attention is required."
        elif agirs < 60:
            posture = "elevated risk"
            urgency = "Targeted remediation is recommended within the current quarter."
        elif agirs < 80:
            posture = "moderate risk with improvement opportunities"
            urgency = "Continued monitoring and incremental hardening are advised."
        else:
            posture = "well-managed"
            urgency = "Maintain current controls and review periodically."

        identity_count = len(identities)
        driver_count = len(drivers)
        summary_parts = [
            f"The organization's identity security posture is {posture}, with an AGIRS score of {agirs}/100 ({risk_level}).",
        ]
        if driver_count:
            summary_parts.append(f"Analysis identified {driver_count} key risk driver(s) contributing to the current exposure.")
        if identity_count:
            summary_parts.append(f"{identity_count} high-risk identit{'y requires' if identity_count == 1 else 'ies require'} priority attention.")
        summary_parts.append(urgency)
        if projected > agirs:
            summary_parts.append(f"Implementing recommended actions is projected to improve the score to {projected}/100.")

        # Top risks from drivers
        top_risks = drivers[:4] if drivers else [
            f"Overall posture rated {risk_level} with an AGIRS score of {agirs}/100."
        ]

        # Recommended actions
        rec_actions = actions[:4] if actions else [
            "Review and remediate high-risk identity configurations.",
            "Enforce least-privilege access across privileged roles.",
        ]

        # Expected improvement
        delta = projected - agirs
        if delta > 0:
            improvement = f"Implementing the recommended actions is projected to improve the AGIRS score from {agirs} to {projected} (+{delta} points), moving the posture from {risk_level} toward a stronger security baseline."
        else:
            improvement = f"Current AGIRS score is {agirs}/100. Continue monitoring and enforcing existing controls to maintain posture."

        return {
            'executive_summary': ' '.join(summary_parts),
            'top_risks': top_risks,
            'recommended_actions': rec_actions,
            'expected_improvement': improvement,
        }

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

    # ── Investigation Assistant (Phase 91) ──────────────────────────────

    INVESTIGATION_SYSTEM_PROMPT = (
        "You are AuditGraph Investigation Assistant, a security analyst AI with access to "
        "live identity graph data via tools. You answer security investigation questions by "
        "calling the provided tools to retrieve real data, then synthesize a grounded response.\n\n"
        "RULES:\n"
        "1. You MUST call at least one tool before answering. Never guess or fabricate data.\n"
        "2. Your answer MUST reference ONLY data returned by tools. Cite exact numbers, names, and scores.\n"
        "3. If a tool returns an error (e.g. identity not found), report that clearly — do not improvise.\n"
        "4. When referencing identities, use their display_name and identity_id.\n"
        "5. Format your answer in clear markdown with sections if appropriate.\n"
        "6. At the end, suggest 1-3 follow-up investigation questions the user might ask.\n"
        "7. Keep answers concise — under 500 words.\n"
    )

    def investigate_with_tools(self, question, tools, executor):
        """Multi-turn tool_use investigation loop.

        Args:
            question: User's investigation question
            tools: INVESTIGATION_TOOLS schema list
            executor: InvestigationToolExecutor instance

        Returns:
            dict with answer, evidence[], tools_used[], suggestions[]
        """
        client = self._get_client()
        messages = [{"role": "user", "content": question}]
        evidence = []
        tools_used = []

        max_rounds = 3
        for _round in range(max_rounds):
            response = client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=self.INVESTIGATION_SYSTEM_PROMPT,
                tools=tools,
                messages=messages,
            )

            # Check if Claude wants to use tools
            tool_use_blocks = [b for b in response.content if b.type == 'tool_use']
            text_blocks = [b for b in response.content if b.type == 'text']

            if not tool_use_blocks:
                # No tool calls — Claude is done, extract final answer
                answer = '\n'.join(b.text for b in text_blocks).strip()
                break

            # Process tool calls
            # Add the assistant's full response (with tool_use blocks) to messages
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in tool_use_blocks:
                tool_name = block.name
                tool_input = block.input
                tools_used.append(tool_name)

                logger.info("Investigation tool call: %s(%s)", tool_name, json.dumps(tool_input)[:200])
                result = executor.execute(tool_name, tool_input)

                # Serialize result for evidence tracking
                result_json = json.dumps(result, default=str)
                # Truncate large results for the evidence log
                result_summary = result_json[:2000] if len(result_json) > 2000 else result_json

                evidence.append({
                    'tool': tool_name,
                    'input': tool_input,
                    'result_summary': result_summary,
                })

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_json,
                })

            messages.append({"role": "user", "content": tool_results})
        else:
            # Exhausted max rounds — use whatever text we have
            answer = '\n'.join(b.text for b in text_blocks).strip() if text_blocks else \
                'Investigation completed but no summary was generated. See evidence for raw data.'

        # Extract suggestions from the answer (lines starting with - or * after "follow-up" keyword)
        suggestions = self._extract_suggestions(answer)

        return {
            'answer': answer,
            'evidence': evidence,
            'tools_used': list(set(tools_used)),
            'suggestions': suggestions,
        }

    def generate_remediation_plan(self, data: dict) -> dict:
        """Generate an AI-driven remediation plan that maps risk factors to
        platform-supported remediation actions to reduce the AGIRS score.

        Input data keys:
            agirs_score: int — current AuditGraph Identity Risk Score (0-100)
            top_risk_identities: list of dicts — {name, risk_score, risk_level, risk_drivers[], identity_category, activity_status}
            attack_paths: list of dicts — {identity, risk_level, steps_count, description}
            risk_drivers: list of str — aggregated risk driver strings from the tenant

        Returns:
            {
              "plan_summary": str,
              "projected_score": int,
              "remediation_actions": [
                {
                  "priority": int (1=highest),
                  "action_type": str (one of the 5 platform action types),
                  "title": str,
                  "description": str,
                  "target_identities": [str],
                  "agirs_impact": str (e.g. "HIRI +5", "NHIRI +3"),
                  "effort": "low"|"medium"|"high",
                  "risk": "low"|"medium"|"high",
                  "playbook_category": str
                }, ...
              ]
            }
        """
        client = self._get_client()

        agirs = data.get('agirs_score', 0)
        identities = data.get('top_risk_identities', [])
        attack_paths = data.get('attack_paths', [])
        drivers = data.get('risk_drivers', [])

        # Build identity summary
        id_lines = []
        for ident in identities[:15]:
            name = ident.get('name') or ident.get('identity_name', 'Unknown')
            cat = ident.get('identity_category', '')
            rs = ident.get('risk_score', 0)
            rl = ident.get('risk_level', 'unknown')
            act = ident.get('activity_status', '')
            rd = ', '.join((ident.get('risk_drivers') or [])[:5])
            id_lines.append(f"- {name} ({cat}): score={rs}, level={rl}, status={act}, drivers=[{rd}]")
        identities_text = '\n'.join(id_lines) if id_lines else '- None provided'

        # Build attack path summary
        ap_lines = []
        for ap in attack_paths[:10]:
            ap_lines.append(
                f"- {ap.get('identity', '?')} [{ap.get('risk_level', '?')}]: "
                f"{ap.get('steps_count', '?')} steps — {ap.get('description', 'N/A')}"
            )
        paths_text = '\n'.join(ap_lines) if ap_lines else '- No attack paths'

        # Build risk driver summary
        drivers_text = '\n'.join(f'- {d}' for d in drivers[:20]) if drivers else '- No specific drivers'

        prompt = f"""You are a remediation planner for AuditGraph, an identity security platform.
Given the current AGIRS score and risk data, propose the top remediation actions that would
most effectively reduce risk and improve the AGIRS score.

**Current AGIRS Score:** {agirs}/100 (100 = perfect, lower = more risk)

**AGIRS Score Model:**
- HIRI (Human Identity Risk Index, 40%): penalizes ghost humans (H1), dormant privileged (H2), over-privileged (H3), external guests with privileges (H4)
- NHIRI (Non-Human Identity Risk Index, 40%): penalizes orphaned NHIs (N1), dormant NHIs (N2), zombie NHIs (N3), expired credentials (N4), ownerless high-risk apps (N5)
- GEI (Governance Effectiveness Index, 20%): rewards ownership coverage, PIM adoption, access review completion, monitoring coverage

**Top Risk Identities:**
{identities_text}

**Attack Paths:**
{paths_text}

**Aggregated Risk Drivers:**
{drivers_text}

**PLATFORM-SUPPORTED REMEDIATION ACTION TYPES (you MUST only use these):**
1. flag_for_review — Add internal review flag for manual follow-up (low risk, any category)
2. create_ticket — Create tracking ticket in ticketing system (low risk)
3. disable_identity — Disable the identity in Entra ID (high risk, for dormant/never_used/stale)
4. remove_role — Remove Azure RBAC or Entra directory role assignment (high risk, for over-privileged)
5. rotate_credential — Initiate credential rotation (medium risk, for expired/expiring/stale credentials)

**PLATFORM REMEDIATION CATEGORIES:**
- access_control: over-privileged roles, excessive permissions, missing CA/MFA
- credential_hygiene: expired creds, expiring creds, stale credentials
- governance: dormant identities, never-used, no owner, multiple high privileges

RULES:
1. ONLY reference the data provided above. Do NOT invent identities, scores, or facts.
2. Each action MUST use one of the 5 platform-supported action_type values exactly.
3. Each action MUST map to a playbook_category (access_control, credential_hygiene, or governance).
4. Propose 3-7 actions, ordered by priority (highest impact first).
5. For target_identities, use actual identity names from the data above.
6. agirs_impact should reference which AGIRS sub-score improves (HIRI, NHIRI, or GEI) and estimated points.
7. projected_score should be a realistic estimate of the AGIRS score after all actions are executed.
8. plan_summary should be 2-3 sentences for a security administrator audience.
9. Be specific and actionable — not generic security advice.

Return ONLY valid JSON with exactly these fields:
{{
  "plan_summary": "2-3 sentence overview of the remediation plan",
  "projected_score": <integer 0-100>,
  "remediation_actions": [
    {{
      "priority": 1,
      "action_type": "<one of: flag_for_review, create_ticket, disable_identity, remove_role, rotate_credential>",
      "title": "Short action title",
      "description": "What to do and why it matters (1-2 sentences)",
      "target_identities": ["identity1", "identity2"],
      "agirs_impact": "HIRI +N / NHIRI +N / GEI +N",
      "effort": "low|medium|high",
      "risk": "low|medium|high",
      "playbook_category": "access_control|credential_hygiene|governance"
    }}
  ]
}}"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=(
                    "You are an identity security remediation planner. "
                    "Return ONLY valid JSON. Do not wrap in markdown code blocks. "
                    "Be precise, actionable, and data-driven. "
                    "Every action must use one of the 5 platform-supported action types."
                ),
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3].rstrip()
            result = json.loads(text)
            # Validate required keys
            for key in ('plan_summary', 'projected_score', 'remediation_actions'):
                if key not in result:
                    if key == 'remediation_actions':
                        result[key] = []
                    elif key == 'projected_score':
                        result[key] = agirs
                    else:
                        result[key] = ''
            if not isinstance(result['remediation_actions'], list):
                result['remediation_actions'] = []
            # Validate action types
            valid_types = {'flag_for_review', 'create_ticket', 'disable_identity', 'remove_role', 'rotate_credential'}
            for action in result['remediation_actions']:
                if action.get('action_type') not in valid_types:
                    action['action_type'] = 'flag_for_review'
            return result
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI remediation plan parse failed: %s", e)
            return self._fallback_remediation_plan(data)

    @staticmethod
    def _fallback_remediation_plan(data: dict) -> dict:
        """Deterministic remediation plan when AI is unavailable."""
        agirs = data.get('agirs_score', 0)
        identities = data.get('top_risk_identities', [])
        attack_paths = data.get('attack_paths', [])
        drivers = data.get('risk_drivers', [])

        actions = []
        priority = 1
        targeted = set()

        # Derive drivers set for matching
        all_drivers = set()
        for d in drivers:
            all_drivers.add(d.lower())
        for ident in identities:
            for d in (ident.get('risk_drivers') or []):
                all_drivers.add(d.lower())

        # 1. Over-privileged / Global Admin — remove_role
        priv_identities = [
            i.get('name') or i.get('identity_name', 'Unknown')
            for i in identities
            if any(kw in d.lower() for d in (i.get('risk_drivers') or [])
                   for kw in ('global administrator', 'owner', 'privileged role', 'full tenant'))
        ]
        if priv_identities:
            actions.append({
                'priority': priority,
                'action_type': 'remove_role',
                'title': 'Remove excessive privileged role assignments',
                'description': 'Remove or scope Global Administrator, Owner, and Privileged Role Administrator assignments to reduce blast radius.',
                'target_identities': priv_identities[:5],
                'agirs_impact': f'HIRI +{min(len(priv_identities) * 3, 15)}',
                'effort': 'medium',
                'risk': 'high',
                'playbook_category': 'access_control',
            })
            targeted.update(priv_identities[:5])
            priority += 1

        # 2. Dormant / never-used identities — disable_identity
        dormant_identities = [
            i.get('name') or i.get('identity_name', 'Unknown')
            for i in identities
            if i.get('activity_status') in ('stale', 'never_used', 'dormant', 'inactive')
        ]
        if dormant_identities:
            is_nhi = any(
                i.get('identity_category', '') in ('service_principal', 'managed_identity_system', 'managed_identity_user')
                for i in identities if (i.get('name') or i.get('identity_name')) in dormant_identities
            )
            actions.append({
                'priority': priority,
                'action_type': 'disable_identity',
                'title': 'Disable dormant and no-activity-observed identities',
                'description': 'Disable identities with no recent activity to eliminate standing risk from unused accounts.',
                'target_identities': dormant_identities[:5],
                'agirs_impact': f'{"NHIRI" if is_nhi else "HIRI"} +{min(len(dormant_identities) * 2, 10)}',
                'effort': 'low',
                'risk': 'high',
                'playbook_category': 'governance',
            })
            targeted.update(dormant_identities[:5])
            priority += 1

        # 3. Expired / expiring credentials — rotate_credential
        cred_identities = [
            i.get('name') or i.get('identity_name', 'Unknown')
            for i in identities
            if any(kw in d.lower() for d in (i.get('risk_drivers') or [])
                   for kw in ('expired', 'expiring', 'stale_credential', 'credential'))
        ]
        if cred_identities:
            actions.append({
                'priority': priority,
                'action_type': 'rotate_credential',
                'title': 'Rotate expired and expiring credentials',
                'description': 'Rotate credentials on identities with expired or soon-to-expire secrets to prevent authentication failures and reduce attack surface.',
                'target_identities': cred_identities[:5],
                'agirs_impact': f'NHIRI +{min(len(cred_identities) * 2, 8)}',
                'effort': 'low',
                'risk': 'medium',
                'playbook_category': 'credential_hygiene',
            })
            priority += 1

        # 4. Attack paths — flag_for_review
        if attack_paths:
            ap_identities = list(set(
                ap.get('identity', 'Unknown') for ap in attack_paths
                if ap.get('risk_level') in ('critical', 'high')
            ))[:5]
            if ap_identities:
                actions.append({
                    'priority': priority,
                    'action_type': 'flag_for_review',
                    'title': 'Review identities with active attack paths',
                    'description': f'Flag {len(ap_identities)} identit{"y" if len(ap_identities) == 1 else "ies"} participating in critical/high attack paths for manual security review.',
                    'target_identities': ap_identities,
                    'agirs_impact': 'HIRI +3 / NHIRI +3',
                    'effort': 'low',
                    'risk': 'low',
                    'playbook_category': 'access_control',
                })
                priority += 1

        # 5. Remaining high-risk — create_ticket
        remaining = [
            i.get('name') or i.get('identity_name', 'Unknown')
            for i in identities
            if i.get('risk_level') in ('critical', 'high')
            and (i.get('name') or i.get('identity_name', 'Unknown')) not in targeted
        ]
        if remaining:
            actions.append({
                'priority': priority,
                'action_type': 'create_ticket',
                'title': 'Create tracking tickets for remaining high-risk identities',
                'description': 'Create remediation tickets to track and resolve remaining high-risk identities not covered by automated actions.',
                'target_identities': remaining[:5],
                'agirs_impact': 'GEI +2',
                'effort': 'low',
                'risk': 'low',
                'playbook_category': 'governance',
            })

        # If no actions were generated, add a generic review
        if not actions:
            actions.append({
                'priority': 1,
                'action_type': 'flag_for_review',
                'title': 'Review current identity security posture',
                'description': 'No specific high-priority remediations identified from the provided data. Conduct a manual review of the identity landscape.',
                'target_identities': [],
                'agirs_impact': 'GEI +1',
                'effort': 'low',
                'risk': 'low',
                'playbook_category': 'governance',
            })

        # Estimate projected score
        total_improvement = 0
        for a in actions:
            impact_str = a.get('agirs_impact', '')
            import re
            nums = re.findall(r'\+(\d+)', impact_str)
            total_improvement += sum(int(n) for n in nums)
        projected = min(agirs + total_improvement, 100)

        # Plan summary
        if agirs < 40:
            severity = 'critical'
        elif agirs < 60:
            severity = 'elevated'
        elif agirs < 75:
            severity = 'moderate'
        else:
            severity = 'low'

        plan_summary = (
            f"The organization's AGIRS score of {agirs}/100 indicates {severity} identity risk. "
            f"This plan proposes {len(actions)} remediation action(s) targeting the highest-impact risk factors. "
            f"Full execution is projected to improve the score to approximately {projected}/100."
        )

        return {
            'plan_summary': plan_summary,
            'projected_score': projected,
            'remediation_actions': actions,
        }

    # ── Least Privilege Role Generator ────────────────────────────────────

    # Map of built-in Azure roles → their full ARM action sets.
    # Used to compute privilege_reduction_percent by comparing the original
    # role's action count against the generated custom role's action count.
    BUILTIN_ROLE_ACTION_COUNTS = {
        'Owner': 120, 'Contributor': 95, 'Reader': 25,
        'User Access Administrator': 18,
        'Storage Blob Data Contributor': 12, 'Storage Blob Data Reader': 6,
        'Storage Blob Data Owner': 15,
        'Key Vault Administrator': 22, 'Key Vault Secrets Officer': 10,
        'Key Vault Secrets User': 4, 'Key Vault Certificates Officer': 10,
        'Key Vault Crypto User': 5,
        'Virtual Machine Contributor': 30, 'Network Contributor': 35,
        'SQL DB Contributor': 20,
        'Monitoring Reader': 10, 'Monitoring Contributor': 15,
        'Log Analytics Reader': 8,
        'Security Reader': 12, 'Security Admin': 20,
        'Managed Identity Operator': 6, 'Managed Identity Contributor': 8,
    }

    # Map resource_type keywords → ARM resource provider namespace
    RESOURCE_TYPE_NAMESPACES = {
        'storage': 'Microsoft.Storage',
        'blob': 'Microsoft.Storage',
        'keyvault': 'Microsoft.KeyVault',
        'key vault': 'Microsoft.KeyVault',
        'vm': 'Microsoft.Compute',
        'virtual machine': 'Microsoft.Compute',
        'compute': 'Microsoft.Compute',
        'network': 'Microsoft.Network',
        'sql': 'Microsoft.Sql',
        'database': 'Microsoft.Sql',
        'web': 'Microsoft.Web',
        'app service': 'Microsoft.Web',
        'function': 'Microsoft.Web',
        'container': 'Microsoft.ContainerRegistry',
        'kubernetes': 'Microsoft.ContainerService',
        'aks': 'Microsoft.ContainerService',
        'monitor': 'Microsoft.Insights',
        'log analytics': 'Microsoft.OperationalInsights',
        'cosmos': 'Microsoft.DocumentDB',
        'redis': 'Microsoft.Cache',
        'event hub': 'Microsoft.EventHub',
        'service bus': 'Microsoft.ServiceBus',
    }

    def generate_least_privilege_role(self, data: dict) -> dict:
        """Generate a custom Azure RBAC role JSON scoped to observed actions only.

        Input data keys:
            identity_id: str — Azure object ID
            current_role: str — current built-in role name (e.g., "Contributor")
            observed_actions: list of str — ARM actions actually used (e.g., ["Microsoft.Storage/storageAccounts/read"])
            resource_types: list of str — resource types accessed (e.g., ["storage", "keyvault"])
            resource_scope: str — ARM scope (e.g., "/subscriptions/xxx/resourceGroups/yyy")
            resource_criticality: str — low/medium/high/critical

        Returns:
            {
              "role_definition": { name, description, actions, notActions, assignableScopes },
              "risk_reduction_score": float,
              "privilege_reduction_percent": float,
              "analysis": str
            }
        """
        client = self._get_client()

        identity_id = data.get('identity_id', 'unknown')
        current_role = data.get('current_role', 'Contributor')
        observed = data.get('observed_actions', [])
        resource_types = data.get('resource_types', [])
        scope = data.get('resource_scope', '/')
        criticality = data.get('resource_criticality', 'medium')

        actions_text = '\n'.join(f'- {a}' for a in observed[:60]) if observed else '- No observed actions'
        rtypes_text = ', '.join(resource_types) if resource_types else 'general'

        prompt = f"""Generate a least-privilege custom Azure RBAC role definition for an identity.

**Identity ID:** {identity_id}
**Current Role:** {current_role}
**Resource Types Accessed:** {rtypes_text}
**Resource Scope:** {scope}
**Resource Criticality:** {criticality}

**Observed ARM Actions (from usage logs — the ONLY actions this identity actually needs):**
{actions_text}

RULES:
1. The custom role MUST include ONLY the observed actions listed above. Do NOT add extra actions.
2. NEVER include wildcard actions (e.g., "*/read" or "Microsoft.Storage/*"). Every action must be fully qualified.
3. Scope the role to the narrowest possible level based on the resource_scope provided.
4. The role name must follow the pattern "AuditGraph-Custom-<descriptive>" (e.g., "AuditGraph-Custom-StorageReader").
5. The description must explain what this role replaces and why it's more restrictive.
6. notActions should list dangerous operations explicitly excluded (e.g., "*/delete", "*/write" for read-only roles).
7. assignableScopes must be an array containing ONLY the provided resource_scope.
8. If observed_actions is empty, generate a minimal read-only role for the resource types.

Return ONLY valid JSON with exactly these fields:
{{
  "role_definition": {{
    "name": "AuditGraph-Custom-<descriptive name>",
    "description": "Custom least-privilege role replacing <current_role>. <explanation of scope reduction>.",
    "actions": ["Microsoft.X/y/action1", "Microsoft.X/y/action2"],
    "notActions": ["Microsoft.X/y/delete"],
    "assignableScopes": ["{scope}"]
  }},
  "analysis": "2-3 sentence explanation of why this custom role is safer than the current role and what privileges were removed"
}}"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=1200,
                system=(
                    "You are an Azure RBAC expert generating least-privilege custom role definitions. "
                    "Return ONLY valid JSON. Do not wrap in markdown code blocks. "
                    "Never include wildcard actions. Every action must be a fully qualified ARM action string."
                ),
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            if text.startswith('```'):
                text = text.split('\n', 1)[1] if '\n' in text else text[3:]
            if text.endswith('```'):
                text = text[:-3].rstrip()
            result = json.loads(text)

            # Validate structure
            rd = result.get('role_definition', {})
            for key in ('name', 'description', 'actions', 'notActions', 'assignableScopes'):
                if key not in rd:
                    rd[key] = [] if key in ('actions', 'notActions', 'assignableScopes') else ''
            if not isinstance(rd['actions'], list):
                rd['actions'] = [str(rd['actions'])]
            if not isinstance(rd['notActions'], list):
                rd['notActions'] = []
            if not isinstance(rd['assignableScopes'], list):
                rd['assignableScopes'] = [scope]

            # Strip any wildcard actions the AI might have sneaked in
            rd['actions'] = [a for a in rd['actions'] if '*' not in a]
            if not rd['actions'] and observed:
                rd['actions'] = list(observed)

            result['role_definition'] = rd

            # Compute metrics
            orig_count = self.BUILTIN_ROLE_ACTION_COUNTS.get(current_role, 50)
            new_count = len(rd['actions'])
            result['privilege_reduction_percent'] = round(
                max((orig_count - new_count) / orig_count * 100, 0), 1
            ) if orig_count > 0 else 0.0
            result['risk_reduction_score'] = self._compute_risk_reduction(
                current_role, rd['actions'], criticality
            )

            if 'analysis' not in result:
                result['analysis'] = ''
            return result
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("AI least-privilege role generation failed: %s", e)
            return self._fallback_least_privilege_role(data)

    @staticmethod
    def _compute_risk_reduction(current_role, new_actions, criticality):
        """Compute a 0-100 risk reduction score based on privilege delta."""
        # Higher current role danger = more room for improvement
        role_danger = {
            'Owner': 100, 'Contributor': 80, 'User Access Administrator': 90,
            'Security Admin': 60, 'Key Vault Administrator': 70,
            'Storage Blob Data Owner': 65, 'Virtual Machine Contributor': 55,
            'Network Contributor': 55, 'SQL DB Contributor': 50,
        }
        base_danger = role_danger.get(current_role, 40)

        # Criticality multiplier
        crit_mult = {'critical': 1.3, 'high': 1.1, 'medium': 1.0, 'low': 0.8}
        mult = crit_mult.get(criticality, 1.0)

        # Fewer new actions relative to original = higher reduction
        orig_count = CopilotService.BUILTIN_ROLE_ACTION_COUNTS.get(current_role, 50)
        new_count = len(new_actions)
        if orig_count <= 0:
            ratio = 0
        else:
            ratio = max(orig_count - new_count, 0) / orig_count

        # Score = danger * reduction_ratio * criticality_mult, capped at 100
        score = min(base_danger * ratio * mult, 100)
        return round(score, 1)

    @staticmethod
    def _fallback_least_privilege_role(data: dict) -> dict:
        """Deterministic custom role generation when AI is unavailable."""
        identity_id = data.get('identity_id', 'unknown')
        current_role = data.get('current_role', 'Contributor')
        observed = data.get('observed_actions', [])
        resource_types = data.get('resource_types', [])
        scope = data.get('resource_scope', '/')
        criticality = data.get('resource_criticality', 'medium')

        # Build descriptive name from resource types
        if resource_types:
            primary = resource_types[0].replace(' ', '').title()
        elif observed:
            # Extract resource provider from first observed action
            parts = observed[0].split('/')
            primary = parts[1] if len(parts) >= 2 else 'General'
        else:
            primary = 'General'

        # Determine if read-only or read-write from observed actions
        has_write = any(
            '/write' in a.lower() or '/delete' in a.lower() or '/action' in a.lower()
            for a in observed
        )
        access_label = 'ReadWrite' if has_write else 'Reader'
        role_name = f'AuditGraph-Custom-{primary}{access_label}'

        # Use observed actions directly, or generate minimal read actions
        if observed:
            actions = [a for a in observed if '*' not in a]
        else:
            # Generate read-only actions from resource types
            actions = []
            ns_map = CopilotService.RESOURCE_TYPE_NAMESPACES
            for rt in resource_types:
                ns = ns_map.get(rt.lower())
                if ns:
                    actions.append(f'{ns}/*/read')
            if not actions:
                actions = ['Microsoft.Resources/subscriptions/resourceGroups/read']
            # Remove wildcards — expand to specific read actions
            expanded = []
            for a in actions:
                if '*' in a:
                    ns = a.split('/')[0] + '/' + a.split('/')[1] if '/' in a else a
                    # Don't include wildcards — the rule says never
                    pass
                else:
                    expanded.append(a)
            actions = expanded if expanded else [
                'Microsoft.Resources/subscriptions/resourceGroups/read'
            ]

        # Build notActions: exclude dangerous ops not in observed set
        not_actions = []
        if not has_write:
            not_actions = [
                'Microsoft.Authorization/roleAssignments/write',
                'Microsoft.Authorization/roleAssignments/delete',
            ]

        description = (
            f'Custom least-privilege role replacing {current_role} for identity {identity_id[:12]}. '
            f'Scoped to {len(actions)} observed action(s) on {", ".join(resource_types) if resource_types else "general resources"}, '
            f'eliminating all unused privileges from the original role.'
        )

        role_def = {
            'name': role_name,
            'description': description,
            'actions': actions,
            'notActions': not_actions,
            'assignableScopes': [scope],
        }

        # Compute metrics
        orig_count = CopilotService.BUILTIN_ROLE_ACTION_COUNTS.get(current_role, 50)
        new_count = len(actions)
        priv_reduction = round(
            max((orig_count - new_count) / orig_count * 100, 0), 1
        ) if orig_count > 0 else 0.0

        risk_reduction = CopilotService._compute_risk_reduction(
            current_role, actions, criticality
        )

        analysis = (
            f"The current '{current_role}' role grants approximately {orig_count} actions. "
            f"This custom role restricts access to only {new_count} observed action(s), "
            f"a {priv_reduction}% privilege reduction. "
            f"{'High-criticality resources benefit most from this scoping.' if criticality in ('critical', 'high') else 'This scoping follows the principle of least privilege.'}"
        )

        return {
            'role_definition': role_def,
            'risk_reduction_score': risk_reduction,
            'privilege_reduction_percent': priv_reduction,
            'analysis': analysis,
        }

    @staticmethod
    def _extract_suggestions(answer):
        """Extract follow-up question suggestions from the answer text."""
        suggestions = []
        lines = answer.split('\n')
        in_suggestions = False
        for line in lines:
            stripped = line.strip()
            lower = stripped.lower()
            if 'follow-up' in lower or 'follow up' in lower or 'next' in lower and 'question' in lower:
                in_suggestions = True
                continue
            if in_suggestions and stripped.startswith(('- ', '* ', '1.', '2.', '3.')):
                text = stripped.lstrip('-*0123456789. ').strip()
                # Remove surrounding quotes if present
                if text.startswith('"') and text.endswith('"'):
                    text = text[1:-1]
                if text:
                    suggestions.append(text)
        return suggestions[:3]

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
