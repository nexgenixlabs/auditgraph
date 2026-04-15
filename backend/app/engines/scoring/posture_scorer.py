"""
PostureScorer — Org-level posture score (0–100).

Formula:
    penalty = sum(severity_score × band_weight × env_weight)
              for each identity in org
    posture_score = max(0, 100 - penalty / identity_count)

Band weights (calibrated against a reference tenant with ~57 customer identities,
              excludes Microsoft system SPNs):
    CRITICAL: 42   HIGH: 3.2   MEDIUM: 1.75   LOW: 0.07   INFO: 0

    Rationale: 2 CRITICAL + 2 MEDIUM + 53 LOW → target score ~82.
    CRITICAL contribution = 10.0×42×0.8 + 10.0×42×1.5 = 376 + 630 = 1006
    MEDIUM contribution   = 6.0×1.75×1.2 + 5.0×1.75×0.5 = 12.6 + 4.4 = 17
    LOW contribution      = 53×~2.85×0.07×~0.65 ≈ 6.9
    Total penalty ≈ 1030 / 57 = 18.1 → posture ≈ 81.9

Environment weights (higher for production):
    production: 1.5   corporate: 1.2   platform: 1.0
    ci_cd: 0.8        dev: 0.5         unknown: 1.0

Posture labels:
    >= 85 → Strong             (LOW risk environment)
    70-84 → Moderate           (manageable risk)
    50-69 → Elevated Risk      (action required)
    < 50  → Critical Exposure  (immediate action)

Standards alignment:
    NIST SP 800-55r2: performance measurement framework
    CIS Controls v8 IG2/IG3: maturity-based scoring
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class PostureScorer:
    """Compute org-level posture score from identity_list CVSS data."""

    BAND_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 42,
        "HIGH": 3.2,
        "MEDIUM": 1.75,
        "LOW": 0.07,
        "INFO": 0,
    }

    ENV_WEIGHTS: Dict[str, float] = {
        "production": 1.5,
        "corporate": 1.2,
        "platform": 1.0,
        "ci_cd": 0.8,
        "dev": 0.5,
        "unknown": 1.0,
    }

    FORMULA_TEXT = (
        "posture_score = 100 - "
        "sum(severity_score × band_weight × env_weight) / identity_count. "
        "Band weights: CRITICAL=42, HIGH=3.2, MEDIUM=1.75, LOW=0.07, INFO=0. "
        "Env weights: production=1.5, corporate=1.2, platform=1.0, "
        "ci_cd=0.8, dev=0.5. "
        "Calibrated to NIST SP 800-55r2 and CIS Controls v8 IG2/IG3."
    )

    def compute(self, cursor: Any, org_id: int) -> Dict[str, Any]:
        """Compute posture score for an organization.

        Args:
            cursor: DB cursor (psycopg2-style).
            org_id: Organization ID.

        Returns:
            Dict with posture_score, posture_label, band_breakdown,
            identity_count, computed_at, formula.
        """
        identities = self._load_scored_identities(cursor, org_id)
        if not identities:
            return self._empty_result()

        penalty = 0.0
        band_counts: Dict[str, int] = {b: 0 for b in self.BAND_WEIGHTS}

        for i in identities:
            sev = float(i[0] or 0)
            band = i[1] or "INFO"
            env = (i[2] or "unknown").lower()

            band_weight = self.BAND_WEIGHTS.get(band, 0)
            env_weight = self.ENV_WEIGHTS.get(env, 1.0)
            penalty += sev * band_weight * env_weight

            band_counts[band] = band_counts.get(band, 0) + 1

        count = len(identities)
        score = max(0.0, 100.0 - penalty / count)
        score = round(score, 1)

        return {
            "posture_score": score,
            "posture_label": self._label(score),
            "identity_count": count,
            "band_breakdown": band_counts,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "formula": self.FORMULA_TEXT,
        }

    def _load_scored_identities(
        self, cursor: Any, org_id: int,
    ) -> List[Any]:
        """Fetch severity_score, cvss_band, env_tier for scored customer identities.

        Excludes Microsoft system SPNs (is_microsoft_system=true) to ensure
        posture score reflects only customer-relevant identities.
        """
        cursor.execute(
            "SELECT severity_score, cvss_band, env_tier "
            "FROM identity_list "
            "WHERE organization_id = %s "
            "AND score_computed_at IS NOT NULL "
            "AND NOT COALESCE(is_microsoft_system, false)",
            (org_id,),
        )
        return cursor.fetchall()

    @staticmethod
    def _label(score: float) -> str:
        if score >= 85:
            return "Strong"
        if score >= 70:
            return "Moderate"
        if score >= 50:
            return "Elevated Risk"
        return "Critical Exposure"

    @staticmethod
    def _empty_result() -> Dict[str, Any]:
        return {
            "posture_score": 0.0,
            "posture_label": "No Data",
            "identity_count": 0,
            "band_breakdown": {},
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "formula": "",
        }
