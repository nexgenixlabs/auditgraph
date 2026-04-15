"""Phase 25: AI Security Copilot.

Processes natural language security queries by matching intent,
retrieving relevant security data, and generating structured responses.
"""

import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Query intent patterns: regex → intent key
QUERY_PATTERNS = [
    (re.compile(r'(dangerous|risky|high.risk|critical)\s*(identit|user|account)', re.I), 'risk_ranking'),
    (re.compile(r'(risk|danger)\s*(rank|score|level|top)', re.I), 'risk_ranking'),
    (re.compile(r'(top|worst|most).*(risk|danger)', re.I), 'risk_ranking'),
    (re.compile(r'(predict|likely.*(compromis|attack)|forecast.attack|attack.predict)', re.I), 'attack_prediction'),
    (re.compile(r'(incident|attack|breach|compromise)', re.I), 'incident_investigation'),
    (re.compile(r'(replay|timeline|forensic)', re.I), 'incident_investigation'),
    (re.compile(r'(anomal|unusual|suspicious|abnormal)', re.I), 'anomaly_analysis'),
    (re.compile(r'(remediat|fix|action|respond|mitigat)', re.I), 'remediation_advice'),
    (re.compile(r'(policy|privilege|least.privilege|over.privilege)', re.I), 'policy_review'),
    (re.compile(r'(posture|score|trend|improvement|progress)', re.I), 'posture_trends'),
    (re.compile(r'(threat|detect|event)', re.I), 'threat_summary'),
    (re.compile(r'(response|orchestrat|automat)', re.I), 'response_status'),
    (re.compile(r'(graph.*(intel|insight|hub|central)|central|blast.radius|trust.chain|structural)', re.I), 'graph_intelligence'),
    (re.compile(r'(governance|violat|drift|unused.identit|stale.cred|guest.priv)', re.I), 'identity_governance'),
    (re.compile(r'(simulat|what.if|what.happens|impact.*compromis|scenario)', re.I), 'risk_simulation'),
    (re.compile(r'(integrat|slack|jira|servicenow|siem|dispatch|notify|ticket)', re.I), 'integration_status'),
    (re.compile(r'(governance.*(metric|analytic|posture|trend)|metric.*trend|posture.*chang)', re.I), 'governance_analytics'),
    (re.compile(r'(strateg|reduce.*risk.*fast|security.*guidance|priorit.*recommend|risk.*reduction)', re.I), 'security_strategy'),
    (re.compile(r'(command.center|security.posture|overall.*risk|current.*posture|identity.*security.*status)', re.I), 'command_center'),
    (re.compile(r'(predict|compromise|likely|forecast.attack|attack.predict)', re.I), 'attack_prediction'),
]

# Default intent when no pattern matches
DEFAULT_INTENT = 'general_summary'


class SecurityCopilot:
    """AI Security Copilot for natural language security queries."""

    def __init__(self, db):
        self.db = db

    def process_copilot_query(self, query, org_id, user_id=None):
        """Process a natural language security query.

        Steps:
        1. Parse query to determine intent
        2. Retrieve relevant security data
        3. Generate structured response
        4. Save query and response

        Args:
            query: Natural language query string
            org_id: Organization ID for data scoping
            user_id: Optional user ID for audit trail

        Returns:
            Dict with response, intent, data, and suggestions.
        """
        # 1. Parse intent
        intent = self._parse_intent(query)

        # 2. Retrieve data based on intent
        data = self._retrieve_data(intent)

        # 3. Generate response
        response = self._generate_response(intent, query, data)

        # 4. Save query
        self._save_query(org_id, user_id, query, response['answer'], {
            'intent': intent,
            'data_keys': list(data.keys()),
        })

        return response

    def _parse_intent(self, query):
        """Parse natural language query to determine intent."""
        for pattern, intent in QUERY_PATTERNS:
            if pattern.search(query):
                return intent
        return DEFAULT_INTENT

    def _retrieve_data(self, intent):
        """Retrieve relevant security data based on intent."""
        retrievers = {
            'risk_ranking': self._get_risk_ranking_data,
            'incident_investigation': self._get_incident_data,
            'anomaly_analysis': self._get_anomaly_data,
            'remediation_advice': self._get_remediation_data,
            'policy_review': self._get_policy_data,
            'posture_trends': self._get_posture_data,
            'threat_summary': self._get_threat_data,
            'response_status': self._get_response_data,
            'attack_prediction': self._get_prediction_data,
            'graph_intelligence': self._get_graph_intelligence_data,
            'identity_governance': self._get_governance_data,
            'risk_simulation': self._get_simulation_data,
            'integration_status': self._get_integration_data,
            'governance_analytics': self._get_governance_analytics_data,
            'security_strategy': self._get_security_strategy_data,
            'command_center': self._get_command_center_data,
            'general_summary': self._get_general_summary,
        }
        retriever = retrievers.get(intent, self._get_general_summary)
        try:
            return retriever()
        except Exception as e:
            logger.warning(f"Data retrieval failed for intent {intent}: {e}")
            return {}

    def _generate_response(self, intent, query, data):
        """Generate a structured response based on intent and data."""
        generators = {
            'risk_ranking': self._respond_risk_ranking,
            'incident_investigation': self._respond_incidents,
            'anomaly_analysis': self._respond_anomalies,
            'remediation_advice': self._respond_remediation,
            'policy_review': self._respond_policy,
            'posture_trends': self._respond_posture,
            'threat_summary': self._respond_threats,
            'response_status': self._respond_response_status,
            'attack_prediction': self._respond_predictions,
            'graph_intelligence': self._respond_graph_intelligence,
            'identity_governance': self._respond_governance,
            'risk_simulation': self._respond_simulation,
            'integration_status': self._respond_integrations,
            'governance_analytics': self._respond_governance_analytics,
            'security_strategy': self._respond_security_strategy,
            'command_center': self._respond_command_center,
            'general_summary': self._respond_general,
        }
        generator = generators.get(intent, self._respond_general)
        return generator(query, data)

    # ── Data Retrievers ────────────────────────────────────────────────

    def _get_risk_ranking_data(self):
        """Get high-risk identities."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.risk_level, i.risk_score,
                       i.identity_category, i.activity_status
                FROM identities i
                JOIN discovery_runs dr ON i.discovery_run_id = dr.id
                WHERE dr.status = 'completed'
                  AND dr.id = (SELECT MAX(id) FROM discovery_runs WHERE status = 'completed')
                  AND i.risk_level IN ('critical', 'high')
                ORDER BY i.risk_score DESC NULLS LAST
                LIMIT 10
            """)
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return {'identities': rows, 'count': len(rows)}
        except Exception:
            return {'identities': [], 'count': 0}

    def _get_incident_data(self):
        """Get recent attack incidents."""
        try:
            incidents = self.db.get_attack_incidents(status='open', limit=10)
            stats = self.db.get_attack_incidents_stats()
            return {'incidents': incidents, 'stats': stats}
        except Exception:
            return {'incidents': [], 'stats': {}}

    def _get_anomaly_data(self):
        """Get recent anomalies."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT anomaly_type, severity, COUNT(*) as count
                FROM anomalies
                WHERE resolved = false
                GROUP BY anomaly_type, severity
                ORDER BY COUNT(*) DESC LIMIT 10
            """)
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return {'anomalies': rows}
        except Exception:
            return {'anomalies': []}

    def _get_remediation_data(self):
        """Get pending remediation recommendations."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM security_response_actions
                GROUP BY status
            """)
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return {'actions': rows}
        except Exception:
            return {'actions': []}

    def _get_policy_data(self):
        """Get generated policy recommendations."""
        try:
            policies = self.db.get_generated_policies(status='pending', limit=10)
            stats = self.db.get_generated_policies_stats()
            return {'policies': policies, 'stats': stats}
        except Exception:
            return {'policies': [], 'stats': {}}

    def _get_posture_data(self):
        """Get security posture trends."""
        try:
            forecast = self.db.get_latest_risk_forecast()
            return {'forecast': forecast}
        except Exception:
            return {'forecast': None}

    def _get_threat_data(self):
        """Get threat event summary."""
        try:
            events = self.db.get_identity_threat_events(status='open', limit=10)
            stats = self.db.get_identity_threat_events_stats()
            return {'events': events, 'stats': stats}
        except Exception:
            return {'events': [], 'stats': {}}

    def _get_response_data(self):
        """Get response action status."""
        try:
            actions = self.db.get_security_response_actions(limit=10)
            stats = self.db.get_security_response_actions_stats()
            return {'actions': actions, 'stats': stats}
        except Exception:
            return {'actions': [], 'stats': {}}

    def _get_prediction_data(self):
        """Get attack predictions."""
        try:
            predictions = self.db.get_attack_predictions(limit=10)
            stats = self.db.get_attack_predictions_stats()
            return {'predictions': predictions, 'stats': stats}
        except Exception:
            return {'predictions': [], 'stats': {}}

    def _get_general_summary(self):
        """Get general security summary data."""
        data = {}
        try:
            data['incidents'] = self.db.get_attack_incidents_stats()
        except Exception:
            data['incidents'] = {}
        try:
            data['threats'] = self.db.get_identity_threat_events_stats()
        except Exception:
            data['threats'] = {}
        try:
            data['responses'] = self.db.get_security_response_actions_stats()
        except Exception:
            data['responses'] = {}
        return data

    # ── Response Generators ────────────────────────────────────────────

    def _respond_risk_ranking(self, query, data):
        identities = data.get('identities', [])
        count = data.get('count', 0)
        if not identities:
            answer = "No high-risk identities found in the current discovery run."
        else:
            lines = [f"Found {count} high-risk identities:"]
            for i, ident in enumerate(identities[:5], 1):
                name = ident.get('display_name') or ident.get('identity_id', 'Unknown')
                risk = ident.get('risk_level', 'unknown')
                score = ident.get('risk_score', 'N/A')
                lines.append(f"  {i}. {name} — {risk} (score: {score})")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'risk_ranking',
            'data': data,
            'suggestions': [
                'Show me incident details',
                'What remediation actions are recommended?',
                'Show security posture trends',
            ],
        }

    def _respond_incidents(self, query, data):
        incidents = data.get('incidents', [])
        stats = data.get('stats', {})
        total = stats.get('total', 0)
        open_count = stats.get('open', 0)
        if not incidents:
            answer = "No open incidents detected."
        else:
            lines = [f"{open_count} open incident(s) out of {total} total:"]
            for inc in incidents[:5]:
                itype = inc.get('incident_type', 'unknown').replace('_', ' ')
                sev = inc.get('severity', 'unknown')
                lines.append(f"  - {itype} ({sev}): {inc.get('summary', 'No summary')}")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'incident_investigation',
            'data': data,
            'suggestions': [
                'Which identities are most at risk?',
                'What automated responses are available?',
                'Show anomaly analysis',
            ],
        }

    def _respond_anomalies(self, query, data):
        anomalies = data.get('anomalies', [])
        if not anomalies:
            answer = "No unresolved anomalies found."
        else:
            lines = ["Unresolved anomalies by type:"]
            for a in anomalies:
                lines.append(f"  - {a.get('anomaly_type', 'unknown')} ({a.get('severity', '?')}): {a.get('count', 0)} occurrence(s)")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'anomaly_analysis',
            'data': data,
            'suggestions': [
                'Show incident details',
                'Which identities are most dangerous?',
                'What remediation is recommended?',
            ],
        }

    def _respond_remediation(self, query, data):
        actions = data.get('actions', [])
        if not actions:
            answer = "No pending remediation actions."
        else:
            lines = ["Response action status:"]
            for a in actions:
                lines.append(f"  - {a.get('status', 'unknown')}: {a.get('count', 0)} action(s)")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'remediation_advice',
            'data': data,
            'suggestions': [
                'Show high-risk identities',
                'What incidents are open?',
                'Show policy recommendations',
            ],
        }

    def _respond_policy(self, query, data):
        policies = data.get('policies', [])
        stats = data.get('stats', {})
        pending = stats.get('pending', 0)
        if not policies:
            answer = "No pending policy recommendations."
        else:
            lines = [f"{pending} pending least-privilege policy recommendation(s):"]
            for p in policies[:5]:
                identity = p.get('identity_id', 'Unknown')
                ptype = p.get('policy_type', 'unknown').replace('_', ' ')
                conf = p.get('confidence_score', 0)
                lines.append(f"  - {identity}: {ptype} (confidence: {conf:.0%})")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'policy_review',
            'data': data,
            'suggestions': [
                'Which identities are most at risk?',
                'Show incident timeline',
                'What automated responses exist?',
            ],
        }

    def _respond_posture(self, query, data):
        forecast = data.get('forecast')
        if not forecast:
            answer = "No security posture forecast data available."
        else:
            current = forecast.get('current_risk_score', 'N/A')
            predicted = forecast.get('predicted_risk_score', 'N/A')
            direction = forecast.get('trend_direction', 'stable')
            answer = (
                f"Security posture: current risk score {current}, "
                f"predicted {predicted} (trend: {direction})."
            )
        return {
            'answer': answer,
            'intent': 'posture_trends',
            'data': data,
            'suggestions': [
                'Show high-risk identities',
                'What remediation actions are pending?',
                'Show open incidents',
            ],
        }

    def _respond_threats(self, query, data):
        events = data.get('events', [])
        stats = data.get('stats', {})
        open_count = stats.get('open', 0)
        if not events:
            answer = "No open threat events detected."
        else:
            lines = [f"{open_count} open threat event(s):"]
            for ev in events[:5]:
                etype = ev.get('event_type', 'unknown').replace('_', ' ')
                sev = ev.get('severity', 'unknown')
                lines.append(f"  - {etype} ({sev}): {ev.get('description', '')[:80]}")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'threat_summary',
            'data': data,
            'suggestions': [
                'Show incident replay timeline',
                'Which identities are most dangerous?',
                'What automated responses are available?',
            ],
        }

    def _respond_response_status(self, query, data):
        actions = data.get('actions', [])
        stats = data.get('stats', {})
        if not stats:
            answer = "No response action data available."
        else:
            answer = (
                f"Response actions: {stats.get('total', 0)} total, "
                f"{stats.get('pending', 0)} pending, "
                f"{stats.get('executed', 0)} executed, "
                f"{stats.get('failed', 0)} failed."
            )
        return {
            'answer': answer,
            'intent': 'response_status',
            'data': data,
            'suggestions': [
                'Show open incidents',
                'Show high-risk identities',
                'Show anomaly analysis',
            ],
        }

    def _respond_predictions(self, query, data):
        predictions = data.get('predictions', [])
        stats = data.get('stats', {})
        if not predictions:
            answer = "No attack predictions available."
        else:
            lines = [
                f"Attack predictions: {stats.get('total', 0)} identities analyzed, "
                f"{stats.get('critical', 0)} critical, {stats.get('high', 0)} high risk:"
            ]
            for p in predictions[:5]:
                identity = p.get('identity_id', 'Unknown')
                risk = p.get('risk_level', 'unknown')
                score = p.get('prediction_score', 0)
                drivers = [d.get('driver', '') for d in p.get('risk_drivers', [])]
                lines.append(f"  - {identity}: {risk} (score: {score}) — {', '.join(drivers)}")
            answer = "\n".join(lines)
        return {
            'answer': answer,
            'intent': 'attack_prediction',
            'data': data,
            'suggestions': [
                'Show high-risk identities',
                'What remediation actions are recommended?',
                'Show open incidents',
            ],
        }

    def _get_graph_intelligence_data(self):
        """Retrieve graph intelligence insights data."""
        insights = self.db.get_graph_insights(limit=10)
        stats = self.db.get_graph_insights_stats()
        return {'insights': insights, 'stats': stats}

    def _respond_graph_intelligence(self, query, data):
        """Generate response for graph intelligence queries."""
        stats = data.get('stats', {})
        insights = data.get('insights', [])
        parts = [f"Graph Intelligence: {stats.get('total', 0)} identities analyzed."]
        parts.append(f"  Critical: {stats.get('critical', 0)}, High: {stats.get('high', 0)}, "
                     f"Medium: {stats.get('medium', 0)}, Low: {stats.get('low', 0)}")
        parts.append(f"  Avg centrality: {stats.get('avg_centrality', 0):.3f}, "
                     f"Avg blast radius: {stats.get('avg_blast_radius', 0):.1f}")
        if insights:
            parts.append("\nTop graph hubs:")
            for i in insights[:5]:
                parts.append(f"  - {i.get('identity_name', i.get('identity_id', '?'))}: "
                             f"centrality {i.get('centrality_score', 0):.2f}, "
                             f"blast radius {i.get('blast_radius', 0)}, "
                             f"risk {i.get('risk_level', 'unknown')}")
        answer = "\n".join(parts) if len(parts) > 1 else "No graph intelligence data available."
        return {
            'answer': answer,
            'intent': 'graph_intelligence',
            'data': data,
            'suggestions': [
                'Which identities have the highest centrality?',
                'Show trust chain analysis',
                'What is the average blast radius?',
            ],
        }

    def _get_governance_data(self):
        """Retrieve identity governance actions data."""
        actions = self.db.get_governance_actions(limit=10, status='pending')
        stats = self.db.get_governance_actions_stats()
        return {'actions': actions, 'stats': stats}

    def _respond_governance(self, query, data):
        """Generate response for identity governance queries."""
        stats = data.get('stats', {})
        actions = data.get('actions', [])
        by_action = stats.get('by_action', {})
        parts = [f"Governance Actions: {stats.get('total', 0)} total, {stats.get('pending', 0)} pending."]
        if by_action:
            parts.append(f"  Privilege drift: {by_action.get('privilege_drift', 0)}, "
                         f"Unused identities: {by_action.get('unused_identity', 0)}, "
                         f"Stale credentials: {by_action.get('stale_credential', 0)}, "
                         f"Guest privilege: {by_action.get('guest_privilege', 0)}")
        if actions:
            parts.append("\nPending governance actions:")
            for a in actions[:5]:
                parts.append(f"  - {a.get('identity_name', a.get('identity_id', '?'))}: "
                             f"{a.get('governance_action', '').replace('_', ' ')} — {a.get('reason', '')[:80]}")
        answer = "\n".join(parts) if len(parts) > 1 else "No governance violations detected."
        return {
            'answer': answer,
            'intent': 'identity_governance',
            'data': data,
            'suggestions': [
                'Which identities violate governance policies?',
                'Show unused identities',
                'Show stale credential actions',
            ],
        }

    def _get_simulation_data(self):
        """Retrieve risk simulation data."""
        simulations = self.db.get_risk_simulations(limit=10)
        stats = self.db.get_risk_simulations_stats()
        return {'simulations': simulations, 'stats': stats}

    def _respond_simulation(self, query, data):
        """Generate response for risk simulation queries."""
        stats = data.get('stats', {})
        sims = data.get('simulations', [])
        parts = [f"Risk Simulations: {stats.get('total', 0)} completed."]
        parts.append(f"  Critical: {stats.get('critical', 0)}, High: {stats.get('high', 0)}, "
                     f"Avg score: {stats.get('avg_score', 0):.1f}")
        if sims:
            parts.append("\nRecent simulations:")
            for s in sims[:5]:
                parts.append(f"  - {s.get('identity_name', s.get('identity_id', '?'))}: "
                             f"{s.get('simulation_type', '').replace('_', ' ')} — "
                             f"score {s.get('simulation_score', 0):.0f}, "
                             f"{s.get('exposed_resources', 0)} resources exposed")
        answer = "\n".join(parts) if len(parts) > 1 else "No risk simulations have been run yet."
        return {
            'answer': answer,
            'intent': 'risk_simulation',
            'data': data,
            'suggestions': [
                'What happens if automation-spn is compromised?',
                'Simulate credential leak for admin-spn',
                'Show recent simulation results',
            ],
        }

    def _get_integration_data(self):
        """Retrieve integration events and config data."""
        events = self.db.get_integration_events(limit=10)
        stats = self.db.get_integration_events_stats()
        configs = self.db.get_integration_configs()
        return {'events': events, 'stats': stats, 'configs': configs}

    def _respond_integrations(self, query, data):
        """Generate response for integration status queries."""
        stats = data.get('stats', {})
        configs = data.get('configs', [])
        by_dest = stats.get('by_destination', {})
        parts = [f"Integration Events: {stats.get('total', 0)} total, "
                 f"{stats.get('sent', 0)} sent, {stats.get('failed', 0)} failed."]
        if by_dest:
            parts.append(f"  Slack: {by_dest.get('slack', 0)}, Jira: {by_dest.get('jira', 0)}, "
                         f"ServiceNow: {by_dest.get('servicenow', 0)}, SIEM: {by_dest.get('siem', 0)}")
        if configs:
            enabled = [c['integration_type'] for c in configs if c.get('enabled')]
            disabled = [c['integration_type'] for c in configs if not c.get('enabled')]
            if enabled:
                parts.append(f"  Enabled: {', '.join(enabled)}")
            if disabled:
                parts.append(f"  Disabled: {', '.join(disabled)}")
        else:
            parts.append("  No integrations configured yet.")
        answer = "\n".join(parts)
        return {
            'answer': answer,
            'intent': 'integration_status',
            'data': data,
            'suggestions': [
                'Show integration event history',
                'Which integrations are configured?',
                'How many events failed to dispatch?',
            ],
        }

    def _get_governance_analytics_data(self):
        """Retrieve governance analytics metrics and trends."""
        metrics = self.db.get_governance_metrics(limit=20)
        metrics_stats = self.db.get_governance_metrics_stats()
        trends = self.db.get_governance_trends(limit=20)
        trends_stats = self.db.get_governance_trends_stats()
        return {'metrics': metrics, 'metrics_stats': metrics_stats,
                'trends': trends, 'trends_stats': trends_stats}

    def _respond_governance_analytics(self, query, data):
        """Generate response for governance analytics queries."""
        metrics_stats = data.get('metrics_stats', {})
        trends_stats = data.get('trends_stats', {})
        by_type = metrics_stats.get('by_type', {})
        parts = [f"Governance Analytics: {metrics_stats.get('total_metrics', 0)} metric types tracked."]
        for mtype, info in by_type.items():
            label = mtype.replace('_', ' ').title()
            pct = info.get('value', 0) * 100
            parts.append(f"  {label}: {pct:.1f}% ({info.get('affected_count', 0)}/{info.get('sample_size', 0)})")
        trend_by_type = trends_stats.get('by_type', {})
        if trend_by_type:
            parts.append(f"Trends: {trends_stats.get('increasing', 0)} increasing, "
                         f"{trends_stats.get('stable', 0)} stable, "
                         f"{trends_stats.get('decreasing', 0)} decreasing")
        answer = "\n".join(parts) if len(parts) > 1 else "No governance metrics computed yet."
        return {
            'answer': answer,
            'intent': 'governance_analytics',
            'data': data,
            'suggestions': [
                'What is our privilege drift rate?',
                'Show stale credentials ratio trend',
                'How is guest privilege ratio changing?',
            ],
        }

    def _get_security_strategy_data(self):
        """Retrieve security strategy recommendations."""
        recommendations = self.db.get_strategy_recommendations(limit=20, status='open')
        stats = self.db.get_strategy_recommendations_stats()
        return {'recommendations': recommendations, 'stats': stats}

    def _respond_security_strategy(self, query, data):
        """Generate response for security strategy queries."""
        stats = data.get('stats', {})
        recs = data.get('recommendations', [])
        parts = [f"Security Strategy: {stats.get('open', 0)} open recommendations "
                 f"({stats.get('critical', 0)} critical, {stats.get('high', 0)} high). "
                 f"Avg risk reduction: {stats.get('avg_risk_reduction', 0):.1f}%."]
        for rec in recs[:5]:
            effort = rec.get('implementation_effort', 'unknown')
            score = rec.get('risk_reduction_score', 0)
            if hasattr(score, '__float__'):
                score = float(score)
            parts.append(f"  [{rec.get('priority', 'medium').upper()}] {rec.get('title', 'N/A')} "
                         f"(risk reduction: {score:.1f}%, effort: {effort})")
        answer = "\n".join(parts) if len(parts) > 1 else "No strategy recommendations generated yet."
        return {
            'answer': answer,
            'intent': 'security_strategy',
            'data': data,
            'suggestions': [
                'How can we reduce identity risk fastest?',
                'Show critical strategy recommendations',
                'What is the easiest risk reduction action?',
            ],
        }

    def _get_command_center_data(self):
        """Retrieve security posture data for command center."""
        latest = self.db.get_security_posture_latest()
        stats = self.db.get_security_posture_stats()
        return {'posture': latest, 'stats': stats}

    def _respond_command_center(self, query, data):
        """Generate response for command center / security posture queries."""
        posture = data.get('posture')
        stats = data.get('stats', {})
        if not posture:
            return {
                'answer': 'No security posture data available yet. Run a discovery scan to generate posture metrics.',
                'intent': 'command_center',
                'data': data,
                'suggestions': ['Show open incidents', 'What governance violations exist?', 'Show strategy recommendations'],
            }
        risk_score = posture.get('risk_score', 0)
        metadata = posture.get('metadata', {})
        risk_label = metadata.get('risk_label', 'unknown')
        parts = [f"Identity Security Posture: {risk_score}/100 ({risk_label.upper()})"]
        parts.append(f"  Incidents: {posture.get('incident_count', 0)}")
        parts.append(f"  Attack Predictions: {posture.get('prediction_count', 0)}")
        parts.append(f"  Governance Violations: {posture.get('governance_violation_count', 0)}")
        parts.append(f"  Strategy Recommendations: {posture.get('strategy_recommendation_count', 0)}")
        parts.append(f"  Active Identities: {posture.get('active_identity_count', 0)}")
        answer = "\n".join(parts)
        return {
            'answer': answer,
            'intent': 'command_center',
            'data': data,
            'suggestions': [
                'How can we reduce our risk score?',
                'Show critical incidents',
                'What governance actions are pending?',
            ],
        }

    def _respond_general(self, query, data):
        parts = ["Security overview:"]
        incidents = data.get('incidents', {})
        if incidents:
            parts.append(f"  Incidents: {incidents.get('total', 0)} total, {incidents.get('open', 0)} open")
        threats = data.get('threats', {})
        if threats:
            parts.append(f"  Threats: {threats.get('total', 0)} total, {threats.get('open', 0)} open")
        responses = data.get('responses', {})
        if responses:
            parts.append(f"  Response actions: {responses.get('total', 0)} total, {responses.get('pending', 0)} pending")
        answer = "\n".join(parts) if len(parts) > 1 else "No security data available yet."
        return {
            'answer': answer,
            'intent': 'general_summary',
            'data': data,
            'suggestions': [
                'Which identities are most dangerous?',
                'Show open incidents',
                'What is the security posture trend?',
            ],
        }

    # ── Persistence ────────────────────────────────────────────────────

    def _save_query(self, org_id, user_id, query, response, context):
        """Save query and response for audit trail."""
        try:
            self.db.save_copilot_query(org_id, user_id, query, response, context)
        except Exception as e:
            logger.warning(f"Failed to save copilot query: {e}")

    def get_query_history(self, org_id, limit=20):
        """Get recent copilot query history."""
        try:
            return self.db.get_copilot_queries(limit=limit)
        except Exception:
            return []
