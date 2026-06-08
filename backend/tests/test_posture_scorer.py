"""Tests for app/engines/scoring/posture_scorer.py — org-level posture
score (0-100) from per-identity CVSS data.

Validates the band-weight × env-weight × severity formula plus the label
buckets. Uses a FakeCursor to avoid the DB dependency.
"""
from __future__ import annotations

from app.engines.scoring.posture_scorer import PostureScorer


class _FakeCursor:
    """psycopg2-style cursor stub returning a fixed result set."""
    def __init__(self, rows):
        self._rows = rows
    def execute(self, query, params=None):
        pass
    def fetchall(self):
        return self._rows


# ──────────────────────────────────────────────────────────────────────
# Empty result
# ──────────────────────────────────────────────────────────────────────

def test_empty_identities_returns_zero_score():
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor([]), org_id=99)

    assert result['posture_score'] == 0.0
    assert result['posture_label'] == 'No Data'
    assert result['identity_count'] == 0


# ──────────────────────────────────────────────────────────────────────
# Label buckets
# ──────────────────────────────────────────────────────────────────────

def test_label_strong_at_85():
    assert PostureScorer._label(85.0) == 'Strong'
    assert PostureScorer._label(95.0) == 'Strong'

def test_label_moderate_70_to_84():
    assert PostureScorer._label(70.0) == 'Moderate'
    assert PostureScorer._label(84.9) == 'Moderate'

def test_label_elevated_50_to_69():
    assert PostureScorer._label(50.0) == 'Elevated Risk'
    assert PostureScorer._label(69.9) == 'Elevated Risk'

def test_label_critical_under_50():
    assert PostureScorer._label(49.9) == 'Critical Exposure'
    assert PostureScorer._label(0.0) == 'Critical Exposure'


# ──────────────────────────────────────────────────────────────────────
# Penalty computation
# ──────────────────────────────────────────────────────────────────────

def test_all_info_band_means_perfect_score():
    """INFO band has weight 0 → no penalty → score 100."""
    rows = [(5.0, 'INFO', 'production')] * 10
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    assert result['posture_score'] == 100.0
    assert result['posture_label'] == 'Strong'

def test_single_critical_identity_in_production_lowers_score_dramatically():
    """One CRITICAL in production: penalty = 10×42×1.5 = 630 / 1 identity → score 0."""
    rows = [(10.0, 'CRITICAL', 'production')]
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    assert result['posture_score'] == 0.0
    assert result['posture_label'] == 'Critical Exposure'

def test_env_weight_production_higher_than_dev():
    """Same severity + band, dev environment gets less penalty (lighter weight)."""
    rows_prod = [(5.0, 'MEDIUM', 'production')] * 10
    rows_dev = [(5.0, 'MEDIUM', 'dev')] * 10
    scorer = PostureScorer()
    score_prod = scorer.compute(_FakeCursor(rows_prod), org_id=99)['posture_score']
    score_dev = scorer.compute(_FakeCursor(rows_dev), org_id=99)['posture_score']
    assert score_dev > score_prod, "dev env should have higher posture (less penalty)"

def test_band_breakdown_counts_correctly():
    rows = [(5.0, 'CRITICAL', 'production'),
            (5.0, 'HIGH',     'production'),
            (5.0, 'HIGH',     'corporate'),
            (5.0, 'MEDIUM',   'dev'),
            (5.0, 'LOW',      'unknown')]
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    assert result['band_breakdown']['CRITICAL'] == 1
    assert result['band_breakdown']['HIGH'] == 2
    assert result['band_breakdown']['MEDIUM'] == 1
    assert result['band_breakdown']['LOW'] == 1

def test_unknown_env_treated_as_unknown_weight():
    """Bad env strings fall back to weight 1.0 (unknown)."""
    rows = [(5.0, 'MEDIUM', 'invalid_environment')]
    scorer = PostureScorer()
    # Doesn't crash; produces a number
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    assert 0 <= result['posture_score'] <= 100

def test_unknown_band_does_not_crash():
    """Bad band strings shouldn't crash. They contribute 0 weight (defensive)."""
    rows = [(5.0, 'BOGUS_BAND', 'production')]
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    # BOGUS_BAND → weight 0 → no penalty
    assert result['posture_score'] == 100.0

def test_none_values_dont_crash():
    """Defensive: rows with None for severity/band/env should be tolerated."""
    rows = [(None, None, None), (5.0, 'MEDIUM', 'production')]
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    assert 0 <= result['posture_score'] <= 100

def test_calibration_target_matches_reference_tenant():
    """Per the docstring, 2 CRITICAL + 2 MEDIUM + 53 LOW should give ~82.

    Mix:
      - 1 CRITICAL @ corporate (sev 10):   10 × 42 × 1.2 = 504
      - 1 CRITICAL @ production (sev 10):  10 × 42 × 1.5 = 630
      - 1 MEDIUM @ corporate (sev 6):       6 × 1.75 × 1.2 = 12.6
      - 1 MEDIUM @ dev (sev 5):             5 × 1.75 × 0.5 = 4.375
      - 53 LOW @ mixed envs (sev 2.85, avg env weight ~0.65):
                                            53 × 2.85 × 0.07 × 0.65 ≈ 6.9
      Total penalty ≈ 1158 / 57 = ~20.3 → score ~80
    """
    rows = (
        [(10.0, 'CRITICAL', 'corporate')] +
        [(10.0, 'CRITICAL', 'production')] +
        [(6.0,  'MEDIUM',   'corporate')] +
        [(5.0,  'MEDIUM',   'dev')] +
        [(2.85, 'LOW', 'production')] * 18 +
        [(2.85, 'LOW', 'corporate')] * 18 +
        [(2.85, 'LOW', 'dev')] * 17
    )
    scorer = PostureScorer()
    result = scorer.compute(_FakeCursor(rows), org_id=99)
    # Allow a tolerance around the docstring's ~82 target
    assert 60 <= result['posture_score'] <= 90, \
        f"calibration drift: got {result['posture_score']}, expected ~80"


# ──────────────────────────────────────────────────────────────────────
# Static helpers + formula text
# ──────────────────────────────────────────────────────────────────────

def test_formula_text_includes_band_weights():
    """The formula text shown in UI must mention the band weights."""
    assert 'CRITICAL=42' in PostureScorer.FORMULA_TEXT
    assert 'HIGH=3.2' in PostureScorer.FORMULA_TEXT

def test_formula_text_includes_compliance_calibration():
    """Mentions NIST + CIS for audit defensibility."""
    text = PostureScorer.FORMULA_TEXT
    assert 'NIST' in text
    assert 'CIS' in text
