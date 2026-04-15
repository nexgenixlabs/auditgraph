"""
DriftIntelligenceEngine — Orchestrator for drift security intelligence.

Runs all 5 enrichment engines in order, each wrapped in try/except
to ensure partial failure doesn't block the pipeline.
"""

import logging

from app.engines.analysis.drift_severity import DriftSeverityEngine
from app.engines.analysis.privilege_escalation import PrivilegeEscalationDetector
from app.engines.analysis.blast_radius import BlastRadiusCalculator
from app.engines.analysis.attack_path_detection import AttackPathDetector
from app.engines.analysis.identity_resurrection import IdentityResurrectionDetector

logger = logging.getLogger(__name__)

SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _max_severity(events: list) -> str:
    """Return the highest severity across all events."""
    best = 'low'
    for e in events:
        sev = e.get('severity', 'medium')
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best, 0):
            best = sev
    return best


class DriftIntelligenceEngine:
    """Orchestrates all drift intelligence enrichment engines."""

    def __init__(self, db):
        self.db = db

    def enrich(self, events: list, current_run_id: int, previous_run_id: int) -> dict:
        """Run all enrichment engines and return enriched events + summary.

        Args:
            events: List of drift event dicts (mutated in-place)
            current_run_id: Current discovery run ID
            previous_run_id: Previous discovery run ID

        Returns:
            Dict with 'events', 'max_severity', and count fields
        """
        # 1. Severity classification (pure logic, no DB)
        try:
            DriftSeverityEngine().enrich(events)
        except Exception as e:
            logger.warning(f"DriftSeverityEngine failed: {e}")

        # 2. Privilege escalation detection (pure logic, no DB)
        try:
            PrivilegeEscalationDetector().enrich(events)
        except Exception as e:
            logger.warning(f"PrivilegeEscalationDetector failed: {e}")

        # 3. Blast radius correlation (DB query)
        try:
            BlastRadiusCalculator(self.db).enrich(events, current_run_id)
        except Exception as e:
            logger.warning(f"BlastRadiusCalculator failed: {e}")

        # 4. Attack path detection (DB query)
        try:
            AttackPathDetector(self.db).enrich(events, current_run_id, previous_run_id)
        except Exception as e:
            logger.warning(f"AttackPathDetector failed: {e}")

        # 5. Identity resurrection detection (DB query)
        try:
            IdentityResurrectionDetector(self.db).enrich(events, current_run_id)
        except Exception as e:
            logger.warning(f"IdentityResurrectionDetector failed: {e}")

        # Compute summary
        priv_esc_count = sum(
            1 for e in events
            if e.get('details', {}).get('privilege_escalation', {}).get('detected')
        )
        attack_path_count = sum(
            1 for e in events if e.get('event_type') == 'attack_path_created'
        )
        resurrection_count = sum(
            1 for e in events if e.get('event_type') == 'identity_resurrection'
        )

        return {
            'events': events,
            'max_severity': _max_severity(events),
            'privilege_escalation_count': priv_esc_count,
            'attack_path_created_count': attack_path_count,
            'identity_resurrection_count': resurrection_count,
        }
