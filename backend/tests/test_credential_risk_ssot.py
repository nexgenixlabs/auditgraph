"""
SSOT tests for CredentialRiskSQL constant.

Verifies that all credential-risk SQL paths reference the shared constant
instead of inlining divergent criteria.
"""
import inspect
import textwrap
import pytest

from app.constants import CredentialRiskSQL


# ── 1. Constant contains all required criteria ──────────────────────

class TestCredentialRiskConstant:
    def test_nhi_filter_has_identity_category(self):
        filt = CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER
        assert "service_principal" in filt
        assert "managed_identity_system" in filt
        assert "managed_identity_user" in filt

    def test_nhi_filter_has_credential_count(self):
        assert "credential_count > 0" in CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER

    def test_nhi_filter_has_credential_expiration(self):
        assert "credential_expiration" in CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER
        assert "credential_expiration < NOW() + INTERVAL '30 days'" in CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER

    def test_nhi_filter_excludes_microsoft(self):
        assert "is_microsoft_system" in CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER

    def test_count_filter_has_all_criteria(self):
        filt = CredentialRiskSQL.NHI_CREDENTIAL_RISK_COUNT_FILTER
        assert "service_principal" in filt
        assert "credential_count > 0" in filt
        assert "credential_expiration < NOW() + INTERVAL '30 days'" in filt
        assert "is_microsoft_system" in filt

    def test_count_filter_has_no_table_alias(self):
        """Count filter is used inside FILTER(WHERE ...) — no i. prefix."""
        filt = CredentialRiskSQL.NHI_CREDENTIAL_RISK_COUNT_FILTER
        assert "i.identity_category" not in filt
        assert "i.credential_count" not in filt


# ── 2. AGIRS N4 uses the constant ───────────────────────────────────

class TestAgirs:
    def test_n4_uses_constant(self):
        from app.engines.risk import agirs_engine
        src = inspect.getsource(agirs_engine)
        assert "CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER" in src, \
            "AGIRS N4 must use CredentialRiskSQL.NHI_CREDENTIAL_RISK_FILTER"

    def test_n4_no_inline_credential_expiration(self):
        """The engine should NOT have its own inline '30 days' logic anymore."""
        from app.engines.risk import agirs_engine
        src = inspect.getsource(agirs_engine)
        # The constant string itself will appear in the source, so look for
        # a raw inline query that is NOT the constant reference
        lines = src.split('\n')
        for line in lines:
            if "INTERVAL '30 days'" in line and 'CredentialRiskSQL' not in line and 'class ' not in line and '"""' not in line:
                # Allow the line if it's inside a docstring or comment
                stripped = line.strip()
                if not stripped.startswith('#') and not stripped.startswith('"') and not stripped.startswith("'"):
                    pytest.fail(f"Found inline 30-day credential SQL not using constant: {line.strip()}")


# ── 3. Live fallback uses the constant (no next_expiry) ─────────────

class TestLiveFallback:
    def test_live_fallback_uses_constant(self):
        from app.api import handlers
        src = inspect.getsource(handlers)
        assert "CredentialRiskSQL.NHI_CREDENTIAL_RISK_COUNT_FILTER" in src, \
            "Live fallback must use CredentialRiskSQL.NHI_CREDENTIAL_RISK_COUNT_FILTER"

    def test_live_fallback_no_next_expiry_for_nhi_expired(self):
        """The old bug used next_expiry instead of credential_expiration."""
        from app.api import handlers
        src = inspect.getsource(handlers.get_risk_summary_full)
        # next_expiry should NOT appear in the NHI expired credential counting
        # (it may still appear elsewhere for SPN filters etc.)
        assert "next_expiry IS NOT NULL AND next_expiry < NOW()" not in src, \
            "Live fallback should not use next_expiry for NHI credential risk counting"


# ── 4. Attack surface includes nhi_credential_risk_count ─────────────

class TestAttackSurface:
    def test_attack_surface_has_nhi_count(self):
        from app.api import handlers
        src = inspect.getsource(handlers.get_attack_surface_score)
        assert "nhi_credential_risk_count" in src


# ── 5. Pillar filter uses the constant ───────────────────────────────

class TestPillarFilter:
    def test_pillar_filter_uses_constant(self):
        from app.api import handlers
        src = inspect.getsource(handlers._get_pillar_filter_sql)
        assert "CredentialRiskSQL" in src, \
            "Pillar drill-down filter must use CredentialRiskSQL constant"
