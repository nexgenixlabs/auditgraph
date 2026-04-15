"""Phase 15: AI Security Advisor Engine.

Analyzes risk findings, attack simulation results, policy recommendations,
and benchmark metrics to produce prioritized remediation strategies that
maximize security improvement with minimal operational impact.
"""

import logging

logger = logging.getLogger(__name__)

# Impact weights for remediation action types
ACTION_IMPACT = {
    'rotate_service_principal_secret': 0.6,
    'remove_role_assignment': 0.9,
    'disable_identity': 0.7,
    'reduce_identity_privilege': 0.8,
}

# Severity multipliers for prioritization
SEVERITY_MULTIPLIER = {
    'critical': 4.0,
    'high': 3.0,
    'medium': 2.0,
    'low': 1.0,
    'info': 0.5,
}

# Risk reduction estimates per action type (percentage)
RISK_REDUCTION_ESTIMATES = {
    'excess_privilege_identity': 15.0,
    'service_principal_secret_rotation': 10.0,
    'guest_user_privilege_review': 8.0,
    'unused_identity_cleanup': 12.0,
    'service_principal_excess_privilege': 15.0,
}


class SecurityAdvisor:
    """AI-driven security advisor that prioritizes remediation actions."""

    def __init__(self, db):
        self.db = db

    def generate_security_advisor_report(self, org_id):
        """Generate a comprehensive security advisor report.

        Steps:
        1. Load risk findings
        2. Load attack simulation results
        3. Load policy recommendations
        4. Analyze benchmark percentile
        5. Rank remediation actions by priority score
        6. Estimate risk reduction
        7. Store advisor report
        """
        # 1. Load risk findings
        risk_findings = self._load_risk_findings()

        # 2. Load attack simulation results
        simulations = self._load_simulations()

        # 3. Load policy recommendations
        recommendations = self._load_recommendations()

        # 4. Analyze benchmark percentile
        benchmark = self._load_benchmark(org_id)

        # 5. Compute current risk score
        risk_score = self._compute_risk_score(risk_findings)

        # 6. Rank remediation actions
        ranked_actions = self._rank_remediation_actions(recommendations)

        # 7. Identify top risks
        top_risks = self._identify_top_risks(risk_findings, simulations)

        # 8. Estimate risk reduction
        risk_reduction = self._estimate_risk_reduction(ranked_actions, risk_score)

        # 9. Build report
        report = {
            'risk_score': risk_score,
            'benchmark_percentile': benchmark.get('percentile', 50),
            'top_risks': top_risks[:10],
            'recommended_actions': ranked_actions[:10],
            'risk_reduction_estimate': risk_reduction,
        }

        # 10. Store report
        saved = self.db.save_security_advisor_report(
            org_id=org_id,
            risk_score=risk_score,
            benchmark_percentile=benchmark.get('percentile', 50),
            top_risks=top_risks[:10],
            recommended_actions=ranked_actions[:10],
            risk_reduction_estimate=risk_reduction,
            metadata={
                'total_findings': len(risk_findings),
                'total_recommendations': len(recommendations),
                'total_simulations': len(simulations),
            },
        )

        report['report_id'] = str(saved['id']) if saved else None
        return report

    def _load_risk_findings(self):
        """Load open risk findings."""
        try:
            return self.db.get_risk_findings(status='open', limit=500)
        except Exception:
            return []

    def _load_simulations(self):
        """Load recent attack simulations."""
        try:
            return self.db.get_attack_simulations(limit=50)
        except Exception:
            return []

    def _load_recommendations(self):
        """Load open policy recommendations."""
        try:
            return self.db.get_policy_recommendations(status='open', limit=500)
        except Exception:
            return []

    def _load_benchmark(self, org_id):
        """Load benchmark comparison for the tenant."""
        try:
            from app.engines.benchmark_engine import BenchmarkEngine
            engine = BenchmarkEngine(self.db)
            return engine.get_tenant_benchmark_comparison(org_id)
        except Exception:
            return {'percentile': 50}

    def _compute_risk_score(self, findings):
        """Compute risk score from findings: critical*10 + high*5 + medium*2."""
        score = 0
        for f in findings:
            sev = f.get('severity', 'info')
            if sev == 'critical':
                score += 10
            elif sev == 'high':
                score += 5
            elif sev == 'medium':
                score += 2
        return score

    def _rank_remediation_actions(self, recommendations):
        """Rank remediation actions by priority score.

        Priority = impact_score × confidence_score × severity_multiplier

        Returns list of action dicts sorted by priority (highest first).
        """
        ranked = []
        for rec in recommendations:
            rec_type = rec.get('recommendation_type', '')
            severity = rec.get('severity', 'medium')
            confidence = rec.get('confidence_score', 80) / 100.0

            impact = ACTION_IMPACT.get(
                rec_type.replace('_review', '').replace('_cleanup', '_identity'),
                0.5
            )
            sev_mult = SEVERITY_MULTIPLIER.get(severity, 1.0)

            priority_score = impact * confidence * sev_mult

            ranked.append({
                'recommendation_id': str(rec.get('id', '')),
                'recommendation_type': rec_type,
                'severity': severity,
                'description': rec.get('description', ''),
                'recommended_action': rec.get('recommended_action', ''),
                'identity_id': rec.get('identity_id'),
                'priority_score': round(priority_score, 2),
                'impact': impact,
                'confidence': confidence,
            })

        ranked.sort(key=lambda x: x['priority_score'], reverse=True)
        return ranked

    def _identify_top_risks(self, findings, simulations):
        """Identify the most impactful risks."""
        risks = []

        # Add high-severity findings
        for f in findings:
            if f.get('severity') in ('critical', 'high'):
                risks.append({
                    'type': 'finding',
                    'severity': f.get('severity'),
                    'description': f.get('rule_name', f.get('metadata', {}).get('reason', 'Unknown risk')),
                    'identity_id': f.get('identity_id'),
                    'impact_score': SEVERITY_MULTIPLIER.get(f.get('severity', 'medium'), 1.0),
                })

        # Add high blast radius simulations
        for sim in simulations:
            if sim.get('blast_radius', 0) >= 10:
                risks.append({
                    'type': 'blast_radius',
                    'severity': 'high',
                    'description': f"Identity {sim.get('identity_id', 'unknown')} has blast radius of {sim.get('blast_radius', 0)}",
                    'identity_id': sim.get('identity_id'),
                    'impact_score': min(sim.get('blast_radius', 0) / 5.0, 5.0),
                })

        risks.sort(key=lambda x: x.get('impact_score', 0), reverse=True)
        return risks

    def _estimate_risk_reduction(self, ranked_actions, current_risk_score):
        """Estimate potential risk score reduction from executing top actions.

        Uses per-action-type reduction estimates to calculate cumulative
        percentage reduction if top recommended actions are implemented.
        """
        if current_risk_score == 0:
            return 0.0

        total_reduction_pct = 0.0
        for action in ranked_actions[:5]:  # Top 5 actions
            rec_type = action.get('recommendation_type', '')
            reduction = RISK_REDUCTION_ESTIMATES.get(rec_type, 5.0)
            total_reduction_pct += reduction

        # Cap at 80% reduction
        total_reduction_pct = min(total_reduction_pct, 80.0)
        return round(total_reduction_pct, 1)
