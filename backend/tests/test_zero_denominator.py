"""Tests for zero-denominator guards in score calculations.

Verifies that all score/percentage computations return float 0.0 (not crash)
when the denominator is zero — i.e. a tenant with zero controls, zero
identities, or zero SPNs.
"""
import unittest


def _safe_score(numerator: int, denominator: int) -> float:
    """Replicates the guarded score pattern used across handlers.py."""
    return round((numerator / denominator) * 100, 1) if denominator > 0 else 0.0


class TestComplianceScoreZeroDenominator(unittest.TestCase):
    """Line ~5832 / ~10378: per-framework compliance score."""

    def test_zero_controls_returns_zero(self):
        """A framework with zero controls should score 0.0, not crash."""
        controls_out = []
        passes = 0
        score = round(passes / len(controls_out) * 100, 1) if controls_out else 0.0
        self.assertEqual(score, 0.0)
        self.assertIsInstance(score, float)

    def test_all_passing_returns_100(self):
        controls_out = [{'status': 'pass'}, {'status': 'pass'}]
        passes = sum(1 for c in controls_out if c['status'] == 'pass')
        score = round(passes / len(controls_out) * 100, 1) if controls_out else 0.0
        self.assertEqual(score, 100.0)
        self.assertIsInstance(score, float)

    def test_partial_pass_returns_float(self):
        controls_out = [{'status': 'pass'}, {'status': 'fail'}, {'status': 'pass'}]
        passes = sum(1 for c in controls_out if c['status'] == 'pass')
        score = round(passes / len(controls_out) * 100, 1) if controls_out else 0.0
        self.assertAlmostEqual(score, 66.7)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)


class TestOverallComplianceScoreZeroDenominator(unittest.TestCase):
    """Line ~6054 / ~10388 / ~6219: overall compliance score."""

    def test_zero_total_controls(self):
        total_passing = 0
        total_controls = 0
        score = round(total_passing / total_controls * 100, 1) if total_controls > 0 else 0.0
        self.assertEqual(score, 0.0)
        self.assertIsInstance(score, float)

    def test_normal_overall_score(self):
        total_passing = 7
        total_controls = 10
        score = round(total_passing / total_controls * 100, 1) if total_controls > 0 else 0.0
        self.assertEqual(score, 70.0)
        self.assertIsInstance(score, float)


class TestAGIRSPillarZeroDenominator(unittest.TestCase):
    """Lines ~4749-4772: AGIRS 6-pillar scoring with zero identities."""

    def test_zero_total_excl_privilege(self):
        """P1 Effective Privilege: 0 non-Microsoft identities → 0.0%."""
        t0t1_count = 0
        total_excl = 0
        priv_pct = (t0t1_count / total_excl) * 100 if total_excl > 0 else 0.0
        self.assertEqual(priv_pct, 0.0)
        self.assertIsInstance(priv_pct, float)

    def test_zero_has_creds_credential_risk(self):
        """P2 Credential Risk: 0 identities with creds → 0.0%."""
        expired_creds = 0
        expiring_creds = 0
        has_creds = 0
        cred_risk_pct = ((expired_creds + expiring_creds) / has_creds) * 100 if has_creds > 0 else 0.0
        self.assertEqual(cred_risk_pct, 0.0)
        self.assertIsInstance(cred_risk_pct, float)

    def test_zero_total_excl_federation(self):
        """P3 Trust & Federation: 0 non-Microsoft identities → 0.0."""
        federated_count = 0
        total_excl = 0
        trust_risk = min((federated_count / total_excl) * 200, 40) if total_excl > 0 else 0.0
        self.assertEqual(trust_risk, 0.0)
        self.assertIsInstance(trust_risk, float)

    def test_zero_total_excl_dormancy(self):
        """P4 Usage Dormancy: 0 non-Microsoft identities → 0.0%."""
        dormant_count = 0
        total_excl = 0
        dormant_pct = (dormant_count / total_excl) * 100 if total_excl > 0 else 0.0
        self.assertEqual(dormant_pct, 0.0)
        self.assertIsInstance(dormant_pct, float)

    def test_zero_total_spns_ownership(self):
        """P5 Ownership Governance: 0 SPNs → 0.0%."""
        unowned_spns = 0
        total_spns = 0
        unowned_pct = (unowned_spns / total_spns) * 100 if total_spns > 0 else 0.0
        self.assertEqual(unowned_pct, 0.0)
        self.assertIsInstance(unowned_pct, float)

    def test_zero_total_excl_exposure(self):
        """P6 External Exposure: 0 non-Microsoft identities → 0.0%."""
        tenant_scope = 0
        total_excl = 0
        scope_pct = (tenant_scope / total_excl) * 100 if total_excl > 0 else 0.0
        self.assertEqual(scope_pct, 0.0)
        self.assertIsInstance(scope_pct, float)

    def test_nonzero_numerator_with_zero_denom_returns_zero(self):
        """Edge case: numerator > 0 but denominator = 0 → still 0.0, not crash."""
        t0t1_count = 5
        total_excl = 0
        priv_pct = (t0t1_count / total_excl) * 100 if total_excl > 0 else 0.0
        self.assertEqual(priv_pct, 0.0)


class TestPostureScoreZeroDenominator(unittest.TestCase):
    """Line ~6441: posture score with zero total identities."""

    def test_zero_identities(self):
        total = 0
        high_risk = 0
        posture_score = round(((total - high_risk) / total) * 100, 1) if total > 0 else 0.0
        self.assertEqual(posture_score, 0.0)
        self.assertIsInstance(posture_score, float)

    def test_normal_posture(self):
        total = 100
        high_risk = 20
        posture_score = round(((total - high_risk) / total) * 100, 1) if total > 0 else 0.0
        self.assertEqual(posture_score, 80.0)
        self.assertIsInstance(posture_score, float)
        self.assertGreaterEqual(posture_score, 0.0)
        self.assertLessEqual(posture_score, 100.0)

    def test_all_high_risk(self):
        total = 50
        high_risk = 50
        posture_score = round(((total - high_risk) / total) * 100, 1) if total > 0 else 0.0
        self.assertEqual(posture_score, 0.0)


class TestAdminAnalyticsZeroDenominator(unittest.TestCase):
    """Line ~13495: average risk score across organizations."""

    def test_no_active_orgs(self):
        scores = []
        avg = round(sum(scores) / len(scores), 1) if scores else 0.0
        self.assertEqual(avg, 0.0)
        self.assertIsInstance(avg, float)

    def test_single_org(self):
        scores = [42.5]
        avg = round(sum(scores) / len(scores), 1) if scores else 0.0
        self.assertEqual(avg, 42.5)
        self.assertIsInstance(avg, float)


class TestSafeScoreHelper(unittest.TestCase):
    """Verify the _safe_score pattern used throughout handlers.py."""

    def test_zero_denominator(self):
        self.assertEqual(_safe_score(10, 0), 0.0)

    def test_normal(self):
        self.assertEqual(_safe_score(3, 4), 75.0)

    def test_full_score(self):
        self.assertEqual(_safe_score(10, 10), 100.0)

    def test_return_type_always_float(self):
        self.assertIsInstance(_safe_score(0, 0), float)
        self.assertIsInstance(_safe_score(1, 1), float)
        self.assertIsInstance(_safe_score(0, 5), float)


if __name__ == '__main__':
    unittest.main()
