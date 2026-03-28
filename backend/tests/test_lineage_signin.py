"""
Sign-in Activity Pattern Classification — unit tests for _classify_signin_pattern().

Verifies:
  1. No sign-in data at all → never_used
  2. Only non-interactive → machine_only
  3. Only delegated → human_delegated_only
  4. Both within 7 days → hybrid_concurrent + shared_human_machine_identity flag
  5. Both, delegated more recent → hybrid_delegated_recent
  6. Both, non-interactive more recent → hybrid_noninteractive_recent
  7. Stale identity (> 365 days) → stale_over_1_year flag
  8. Dormant identity (90-365 days) → dormant_over_90_days flag
  9. days_since_last_signin computed correctly
 10. human_delegated_only → unexpected_interactive_usage flag
"""
import os
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


# ── Helpers ─────────────────────────────────────────────────────────

def _build_engine():
    """Create an AzureDiscoveryEngine with mocked dependencies."""
    with patch('app.engines.discovery.azure_discovery.ClientSecretCredential') as MockCred, \
         patch('app.engines.discovery.azure_discovery.GraphServiceClient'), \
         patch('app.engines.discovery.azure_discovery.SubscriptionClient'), \
         patch('app.engines.discovery.azure_discovery.Database'):

        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = 'fake-bearer-token'
        mock_cred.get_token = MagicMock(return_value=mock_token)
        MockCred.return_value = mock_cred

        from app.engines.discovery.azure_discovery import AzureDiscoveryEngine

        engine = AzureDiscoveryEngine.__new__(AzureDiscoveryEngine)
        engine.credential = mock_cred
        engine.azure_directory_id = '00000000-0000-0000-0000-000000000001'
        return engine


def _iso(dt: datetime) -> str:
    """Format datetime as ISO-8601 string with Z suffix."""
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


# ── Tests ───────────────────────────────────────────────────────────

class TestSigninPatternClassification:
    """Tests for _classify_signin_pattern()."""

    def test_no_signin_data_returns_never_used(self):
        """Empty signin data → never_used pattern + never_authenticated flag."""
        engine = _build_engine()
        result = engine._classify_signin_pattern({})
        assert result['signin_pattern'] == 'never_used'
        assert 'never_authenticated' in result['signin_risk_flags']
        assert result['last_delegated_signin'] is None
        assert result['last_noninteractive_signin'] is None
        assert result['days_since_last_signin'] is None

    def test_machine_only_from_noninteractive_only(self):
        """Only non-interactive sign-in → machine_only."""
        engine = _build_engine()
        result = engine._classify_signin_pattern({
            'lastNonInteractiveSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=5)),
        })
        assert result['signin_pattern'] == 'machine_only'
        assert 'unexpected_interactive_usage' not in result['signin_risk_flags']

    def test_human_delegated_only(self):
        """Only delegated sign-in → human_delegated_only + unexpected_interactive_usage."""
        engine = _build_engine()
        result = engine._classify_signin_pattern({
            'lastDelegatedSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=2)),
        })
        assert result['signin_pattern'] == 'human_delegated_only'
        assert 'unexpected_interactive_usage' in result['signin_risk_flags']

    def test_hybrid_concurrent_within_7_days(self):
        """Both sign-in types within 7 days → hybrid_concurrent + shared_human_machine_identity."""
        engine = _build_engine()
        now = datetime.now(timezone.utc)
        result = engine._classify_signin_pattern({
            'lastDelegatedSignInDateTime': _iso(now - timedelta(days=3)),
            'lastNonInteractiveSignInDateTime': _iso(now - timedelta(days=5)),
        })
        assert result['signin_pattern'] == 'hybrid_concurrent'
        assert 'shared_human_machine_identity' in result['signin_risk_flags']

    def test_hybrid_delegated_recent(self):
        """Delegated is more recent (gap > 7 days) → hybrid_delegated_recent."""
        engine = _build_engine()
        now = datetime.now(timezone.utc)
        result = engine._classify_signin_pattern({
            'lastDelegatedSignInDateTime': _iso(now - timedelta(days=5)),
            'lastNonInteractiveSignInDateTime': _iso(now - timedelta(days=30)),
        })
        assert result['signin_pattern'] == 'hybrid_delegated_recent'

    def test_hybrid_noninteractive_recent(self):
        """Non-interactive is more recent (gap > 7 days) → hybrid_noninteractive_recent."""
        engine = _build_engine()
        now = datetime.now(timezone.utc)
        result = engine._classify_signin_pattern({
            'lastDelegatedSignInDateTime': _iso(now - timedelta(days=30)),
            'lastNonInteractiveSignInDateTime': _iso(now - timedelta(days=5)),
        })
        assert result['signin_pattern'] == 'hybrid_noninteractive_recent'

    def test_stale_over_1_year_flag(self):
        """Last sign-in > 365 days ago → stale_over_1_year flag."""
        engine = _build_engine()
        result = engine._classify_signin_pattern({
            'lastNonInteractiveSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=400)),
            'lastSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=400)),
        })
        assert 'stale_over_1_year' in result['signin_risk_flags']
        assert 'dormant_over_90_days' not in result['signin_risk_flags']

    def test_dormant_over_90_days_flag(self):
        """Last sign-in 91-365 days ago → dormant_over_90_days flag."""
        engine = _build_engine()
        result = engine._classify_signin_pattern({
            'lastNonInteractiveSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=120)),
            'lastSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=120)),
        })
        assert 'dormant_over_90_days' in result['signin_risk_flags']
        assert 'stale_over_1_year' not in result['signin_risk_flags']

    def test_days_since_last_signin_computed(self):
        """days_since_last_signin should reflect the most recent sign-in across all types."""
        engine = _build_engine()
        now = datetime.now(timezone.utc)
        result = engine._classify_signin_pattern({
            'lastDelegatedSignInDateTime': _iso(now - timedelta(days=10)),
            'lastNonInteractiveSignInDateTime': _iso(now - timedelta(days=50)),
            'lastSignInDateTime': _iso(now - timedelta(days=10)),
        })
        assert result['days_since_last_signin'] is not None
        # Should be close to 10 (allow 1 day tolerance for test execution)
        assert 9 <= result['days_since_last_signin'] <= 11

    def test_unexpected_interactive_usage_flag(self):
        """human_delegated_only pattern should flag unexpected_interactive_usage
        (service principals should not have interactive sign-ins)."""
        engine = _build_engine()
        result = engine._classify_signin_pattern({
            'lastDelegatedSignInDateTime': _iso(datetime.now(timezone.utc) - timedelta(days=1)),
        })
        assert result['signin_pattern'] == 'human_delegated_only'
        assert 'unexpected_interactive_usage' in result['signin_risk_flags']
        assert 'shared_human_machine_identity' not in result['signin_risk_flags']
