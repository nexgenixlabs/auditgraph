"""
Drift Security Intelligence Layer

Post-detection enrichment engines that add severity classification,
privilege escalation detection, blast radius correlation, attack path
comparison, and identity resurrection detection to drift events.
"""

from app.engines.analysis.drift_intelligence_engine import DriftIntelligenceEngine

__all__ = ['DriftIntelligenceEngine']
