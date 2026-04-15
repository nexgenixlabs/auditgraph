"""Tests for CISO summary SSOT API — readiness logic, coverage, cache, resilience.

Covers:
  1. No data → DISCOVERY_REQUIRED
  2. Partial data → PARTIAL with correct coverage
  3. Full data → READY
  4. Empty responses don't count as usable
  5. Cache invalidation clears entries
  6. Gap prioritization returns highest-priority gap
  7. Error envelope has valid shape
  8. Data builders never crash on bad input
  9. _safe_collect isolates failures
"""
import time
import unittest

# Import pure functions under test
from app.api.handlers import (
    _has_real_data,
    _count_usable_sources,
    _build_ciso_envelope,
    _ciso_cache_get,
    _ciso_cache_set,
    _ciso_cache_invalidate,
    _ciso_empty_envelope,
    _ciso_system_error_envelope,
    _safe_collect,
    _build_risk_summary_data,
    _build_trends_data,
    _build_anomaly_data,
    _build_remediation_data,
    _build_drift_data,
    _build_spn_data,
    _GAP_PRIORITY,
)


# ── Fixtures ──────────────────────────────────────────────────

def _empty_sources():
    """All sources present but with no meaningful data."""
    return {
        'risk': {},
        'trends': {},
        'anomalies': {},
        'remediation': {},
        'drift': {},
        'spn': {},
    }


def _full_sources():
    """All sources with real, usable data."""
    return {
        'risk': {'latest': {'total_identities': 57}},
        'trends': {'runs': [{'run_id': 1}, {'run_id': 2}]},
        'anomalies': {'unresolved': 3, 'top_anomalies': [{'id': 1}]},
        'remediation': {'total': 28, 'open': 5, 'completed': 23},
        'drift': {'total_changes': 12},
        'spn': {'total_custom': 240},
    }


def _partial_sources():
    """Risk and trends available, other sources empty."""
    return {
        'risk': {'latest': {'total_identities': 10}},
        'trends': {'runs': [{'run_id': 1}]},
        'anomalies': {},
        'remediation': {},
        'drift': {},
        'spn': {},
    }


# ── _has_real_data ────────────────────────────────────────────

class TestHasRealData(unittest.TestCase):
    def test_empty_sources_no_real_data(self):
        self.assertFalse(_has_real_data(_empty_sources()))

    def test_all_none_sources(self):
        self.assertFalse(_has_real_data({
            'risk': None, 'trends': None, 'anomalies': None,
            'remediation': None, 'drift': None, 'spn': None,
        }))

    def test_risk_with_identities_is_real(self):
        sources = _empty_sources()
        sources['risk'] = {'latest': {'total_identities': 1}}
        self.assertTrue(_has_real_data(sources))

    def test_risk_with_zero_identities_not_real(self):
        sources = _empty_sources()
        sources['risk'] = {'latest': {'total_identities': 0}}
        self.assertFalse(_has_real_data(sources))

    def test_remediation_with_total_is_real(self):
        sources = _empty_sources()
        sources['remediation'] = {'total': 5}
        self.assertTrue(_has_real_data(sources))

    def test_trends_with_runs_is_real(self):
        sources = _empty_sources()
        sources['trends'] = {'runs': [{'run_id': 1}]}
        self.assertTrue(_has_real_data(sources))

    def test_trends_with_empty_runs_not_real(self):
        sources = _empty_sources()
        sources['trends'] = {'runs': []}
        self.assertFalse(_has_real_data(sources))

    def test_full_sources_is_real(self):
        self.assertTrue(_has_real_data(_full_sources()))

    def test_completely_empty_dict(self):
        self.assertFalse(_has_real_data({}))


# ── _count_usable_sources ────────────────────────────────────

class TestCountUsableSources(unittest.TestCase):
    def test_empty_sources_zero_usable(self):
        usable, total = _count_usable_sources(_empty_sources())
        self.assertEqual(usable, 0)
        self.assertEqual(total, 6)

    def test_full_sources_all_usable(self):
        usable, total = _count_usable_sources(_full_sources())
        self.assertEqual(usable, 6)
        self.assertEqual(total, 6)

    def test_partial_sources_correct_count(self):
        usable, total = _count_usable_sources(_partial_sources())
        self.assertEqual(usable, 2)  # risk + trends
        self.assertEqual(total, 6)

    def test_anomalies_unresolved_counts(self):
        sources = _empty_sources()
        sources['anomalies'] = {'unresolved': 1}
        usable, _ = _count_usable_sources(sources)
        self.assertEqual(usable, 1)

    def test_anomalies_top_list_counts(self):
        sources = _empty_sources()
        sources['anomalies'] = {'unresolved': 0, 'top_anomalies': [{'id': 1}]}
        usable, _ = _count_usable_sources(sources)
        self.assertEqual(usable, 1)

    def test_drift_with_zero_changes_not_usable(self):
        sources = _empty_sources()
        sources['drift'] = {'total_changes': 0}
        usable, _ = _count_usable_sources(sources)
        self.assertEqual(usable, 0)

    def test_spn_with_zero_custom_not_usable(self):
        sources = _empty_sources()
        sources['spn'] = {'total_custom': 0}
        usable, _ = _count_usable_sources(sources)
        self.assertEqual(usable, 0)

    def test_none_sources_zero_usable(self):
        sources = {
            'risk': None, 'trends': None, 'anomalies': None,
            'remediation': None, 'drift': None, 'spn': None,
        }
        usable, total = _count_usable_sources(sources)
        self.assertEqual(usable, 0)
        self.assertEqual(total, 6)


# ── _build_ciso_envelope ──────────────────────────────────────

class TestBuildCISOEnvelope(unittest.TestCase):
    def test_no_run_ids_discovery_required(self):
        result = _build_ciso_envelope(_full_sources(), [], {}, run_ids=[])
        self.assertEqual(result['status'], 'DISCOVERY_REQUIRED')
        self.assertFalse(result['ready'])

    def test_empty_data_discovery_required(self):
        """Even with run_ids, if no source has real data → DISCOVERY_REQUIRED."""
        result = _build_ciso_envelope(_empty_sources(), [], {}, run_ids=[1, 2])
        self.assertEqual(result['status'], 'DISCOVERY_REQUIRED')
        self.assertFalse(result['ready'])
        self.assertEqual(result['coverage'], 0)

    def test_full_data_ready(self):
        sources = _full_sources()
        result = _build_ciso_envelope(sources, [], {}, run_ids=[1, 2])
        self.assertEqual(result['status'], 'READY')
        self.assertTrue(result['ready'])
        self.assertEqual(result['coverage'], 100)
        self.assertEqual(result['confidence'], 'high')

    def test_partial_data_partial_status(self):
        sources = _partial_sources()
        result = _build_ciso_envelope(sources, [], {}, run_ids=[1])
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertTrue(result['ready'])
        self.assertEqual(result['usableSources'], 2)
        self.assertEqual(result['totalSources'], 6)
        self.assertLess(result['coverage'], 100)

    def test_confidence_levels(self):
        """Coverage >= 85 → high, >= 50 → medium, < 50 → low."""
        # Full → high
        result = _build_ciso_envelope(_full_sources(), [], {}, run_ids=[1])
        self.assertEqual(result['confidence'], 'high')

        # 2/6 → 33% → low
        result = _build_ciso_envelope(_partial_sources(), [], {}, run_ids=[1])
        self.assertEqual(result['confidence'], 'low')

    def test_primary_gap_prioritization(self):
        """Should pick highest-priority gap from the list."""
        gaps = ['SPN_UNAVAILABLE', 'ANOMALY_DISABLED', 'DRIFT_NOT_ENABLED']
        result = _build_ciso_envelope(_partial_sources(), gaps, {}, run_ids=[1])
        self.assertEqual(result['primaryGap'], 'ANOMALY_DISABLED')

    def test_primary_gap_none_when_no_gaps(self):
        result = _build_ciso_envelope(_full_sources(), [], {}, run_ids=[1])
        self.assertIsNone(result['primaryGap'])

    def test_primary_gap_single(self):
        gaps = ['DRIFT_NEEDS_SECOND_SCAN']
        result = _build_ciso_envelope(_partial_sources(), gaps, {}, run_ids=[1])
        self.assertEqual(result['primaryGap'], 'DRIFT_NEEDS_SECOND_SCAN')

    def test_envelope_contains_required_fields(self):
        result = _build_ciso_envelope(_full_sources(), [], {'key': 'val'}, run_ids=[1])
        for field in ('status', 'ready', 'coverage', 'confidence', 'data', 'gaps',
                      'primaryGap', 'usableSources', 'totalSources'):
            self.assertIn(field, result, f"Missing field: {field}")

    def test_data_passthrough(self):
        """Envelope should pass through the data dict unchanged."""
        data = {'riskSummary': {'latest': {}}, 'trends': {'runs': []}}
        result = _build_ciso_envelope(_full_sources(), [], data, run_ids=[1])
        self.assertEqual(result['data'], data)


# ── Cache Helpers ─────────────────────────────────────────────

class TestCISOCache(unittest.TestCase):
    def setUp(self):
        _ciso_cache_invalidate()  # clear before each test

    def test_cache_miss_returns_none(self):
        self.assertIsNone(_ciso_cache_get(1, 1))

    def test_cache_hit_returns_data(self):
        _ciso_cache_set(1, 1, {'status': 'READY'})
        result = _ciso_cache_get(1, 1)
        self.assertIsNotNone(result)
        self.assertEqual(result['status'], 'READY')

    def test_cache_invalidate_specific_org(self):
        _ciso_cache_set(1, 1, {'status': 'READY'})
        _ciso_cache_set(2, 1, {'status': 'PARTIAL'})
        _ciso_cache_invalidate(org_id=1)
        self.assertIsNone(_ciso_cache_get(1, 1))
        self.assertIsNotNone(_ciso_cache_get(2, 1))

    def test_cache_invalidate_all(self):
        _ciso_cache_set(1, 1, {'status': 'READY'})
        _ciso_cache_set(2, 1, {'status': 'PARTIAL'})
        _ciso_cache_invalidate()
        self.assertIsNone(_ciso_cache_get(1, 1))
        self.assertIsNone(_ciso_cache_get(2, 1))

    def test_different_conn_ids_independent(self):
        _ciso_cache_set(1, 1, {'conn': 1})
        _ciso_cache_set(1, 2, {'conn': 2})
        self.assertEqual(_ciso_cache_get(1, 1)['conn'], 1)
        self.assertEqual(_ciso_cache_get(1, 2)['conn'], 2)


# ── Gap Priority Order ───────────────────────────────────────

class TestGapPriority(unittest.TestCase):
    def test_risk_summary_is_highest(self):
        self.assertEqual(_GAP_PRIORITY[0], 'RISK_SUMMARY_FAILED')

    def test_all_gaps_in_priority_list(self):
        expected = {
            'RISK_SUMMARY_FAILED', 'ANOMALY_DISABLED', 'DRIFT_NOT_ENABLED',
            'DRIFT_NEEDS_SECOND_SCAN', 'REMEDIATION_UNAVAILABLE', 'SPN_UNAVAILABLE',
        }
        self.assertEqual(set(_GAP_PRIORITY), expected)


# ── Empty Envelope (no data — DISCOVERY_REQUIRED) ─────────────

class TestEmptyEnvelope(unittest.TestCase):
    def test_has_valid_shape(self):
        result = _ciso_empty_envelope()
        for field in ('status', 'coverage', 'data', 'gaps',
                      'primaryGap', 'usableSources', 'totalSources'):
            self.assertIn(field, result, f"Empty envelope missing '{field}'")

    def test_status_is_discovery_required(self):
        """Empty data → DISCOVERY_REQUIRED, not ERROR."""
        result = _ciso_empty_envelope()
        self.assertEqual(result['status'], 'DISCOVERY_REQUIRED')

    def test_usable_sources_zero(self):
        result = _ciso_empty_envelope()
        self.assertEqual(result['usableSources'], 0)
        self.assertEqual(result['totalSources'], 6)
        self.assertEqual(result['coverage'], 0)

    def test_data_sub_objects_all_unavailable(self):
        result = _ciso_empty_envelope()
        for key in ('trends', 'anomalies', 'remediation', 'drift', 'spn'):
            self.assertFalse(result['data'][key]['available'],
                             f"data.{key} should not be available in empty envelope")
        self.assertIsNone(result['data']['riskSummary'])


# ── System Error Envelope (real failures — ERROR) ─────────────

class TestSystemErrorEnvelope(unittest.TestCase):
    def test_has_valid_shape(self):
        result = _ciso_system_error_envelope()
        for field in ('status', 'coverage', 'data', 'gaps',
                      'primaryGap', 'usableSources', 'totalSources'):
            self.assertIn(field, result, f"System error envelope missing '{field}'")

    def test_status_is_error(self):
        """System crash → ERROR, not DISCOVERY_REQUIRED."""
        result = _ciso_system_error_envelope()
        self.assertEqual(result['status'], 'ERROR')

    def test_custom_reason(self):
        result = _ciso_system_error_envelope("DB connection failed")
        self.assertEqual(result['primaryGap'], "DB connection failed")

    def test_default_reason(self):
        result = _ciso_system_error_envelope()
        self.assertEqual(result['primaryGap'], "System error retrieving security data")

    def test_data_sub_objects_all_unavailable(self):
        result = _ciso_system_error_envelope()
        for key in ('trends', 'anomalies', 'remediation', 'drift', 'spn'):
            self.assertFalse(result['data'][key]['available'])
        self.assertIsNone(result['data']['riskSummary'])

    def test_empty_vs_error_status_differs(self):
        """The two envelopes must return DIFFERENT statuses."""
        empty = _ciso_empty_envelope()
        error = _ciso_system_error_envelope()
        self.assertEqual(empty['status'], 'DISCOVERY_REQUIRED')
        self.assertEqual(error['status'], 'ERROR')
        self.assertNotEqual(empty['status'], error['status'])


# ── _safe_collect ─────────────────────────────────────────────

class TestSafeCollect(unittest.TestCase):
    def test_returns_result_on_success(self):
        def ok():
            return {'value': 42}
        self.assertEqual(_safe_collect(ok, 'test')['value'], 42)

    def test_returns_none_on_exception(self):
        def fail():
            raise RuntimeError("boom")
        self.assertIsNone(_safe_collect(fail, 'test'))

    def test_passes_args(self):
        def add(a, b):
            return a + b
        self.assertEqual(_safe_collect(add, 'test', 3, 7), 10)

    def test_catches_all_exceptions(self):
        def bad():
            raise KeyError("missing")
        self.assertIsNone(_safe_collect(bad, 'test'))


# ── Data Builders (resilience) ────────────────────────────────

class TestDataBuilders(unittest.TestCase):
    """Data builders must NEVER crash — always return safe defaults."""

    def test_risk_summary_none_on_no_data(self):
        self.assertIsNone(_build_risk_summary_data({}))

    def test_risk_summary_none_on_none_sources(self):
        self.assertIsNone(_build_risk_summary_data({'risk': None}))

    def test_risk_summary_with_valid_data(self):
        sources = {'risk': {
            'latest': {'total_identities': 10, 'agirs_score': 75, 'agirs_tier': 'C'},
            'previous': None,
        }}
        result = _build_risk_summary_data(sources)
        self.assertIsNotNone(result)
        self.assertEqual(result['identity_counts']['total'], 10)
        self.assertEqual(result['agirs']['score'], 75)

    def test_trends_unavailable_on_empty(self):
        result = _build_trends_data({})
        self.assertFalse(result['available'])

    def test_trends_unavailable_on_none(self):
        result = _build_trends_data({'trends': None})
        self.assertFalse(result['available'])

    def test_trends_available_with_runs(self):
        result = _build_trends_data({'trends': {'runs': [
            {'posture_score': 70, 'date': '2026-01-01'},
            {'posture_score': 80, 'date': '2026-01-02'},
        ]}})
        self.assertTrue(result['available'])
        self.assertEqual(len(result['postureScores']), 2)

    def test_anomaly_unavailable_on_none(self):
        self.assertFalse(_build_anomaly_data({'anomalies': None})['available'])

    def test_anomaly_available_with_data(self):
        result = _build_anomaly_data({'anomalies': {'unresolved': 2, 'by_severity': {}, 'top_anomalies': []}})
        self.assertTrue(result['available'])
        self.assertEqual(result['unresolved'], 2)

    def test_remediation_unavailable_on_none(self):
        self.assertFalse(_build_remediation_data({'remediation': None})['available'])

    def test_drift_unavailable_on_none(self):
        self.assertFalse(_build_drift_data({'drift': None})['available'])

    def test_spn_unavailable_on_none(self):
        self.assertFalse(_build_spn_data({'spn': None})['available'])

    def test_all_builders_survive_corrupt_data(self):
        """All builders should return safe defaults when sources contain garbage."""
        corrupt = {'risk': 'not_a_dict', 'trends': 123, 'anomalies': [],
                    'remediation': True, 'drift': 'bad', 'spn': [1, 2]}
        # None of these should raise
        _build_risk_summary_data(corrupt)
        self.assertFalse(_build_trends_data(corrupt)['available'])
        self.assertFalse(_build_anomaly_data(corrupt)['available'])
        self.assertFalse(_build_remediation_data(corrupt)['available'])
        self.assertFalse(_build_drift_data(corrupt)['available'])
        self.assertFalse(_build_spn_data(corrupt)['available'])


if __name__ == '__main__':
    unittest.main()
