"""
AG-94: Tests for tenant_scope module — @requires_org_id, @cross_org, tenant table registry.

CWE-639, CWE-284, OWASP A01:2021 — Broken Access Control
"""
import inspect
import logging
import pytest
from unittest.mock import MagicMock, patch

from app.security.tenant_scope import (
    TenantScopeError,
    requires_org_id,
    cross_org,
    tenant_tables,
    is_tenant_table,
    invalidate_cache,
    _validate_org_id,
    _BASELINE_TENANT_TABLES,
)


# ── @requires_org_id tests ─────────────────────────────────────────────

class TestRequiresOrgId:
    """Test the @requires_org_id decorator enforcement."""

    def test_raises_on_missing_org_id_kwarg(self):
        """Calling without org_id raises TenantScopeError."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        with pytest.raises(TenantScopeError, match="missing required keyword argument"):
            method(None)

    def test_raises_on_none_org_id(self):
        """org_id=None raises TenantScopeError."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        with pytest.raises(TenantScopeError, match="received None"):
            method(None, org_id=None)

    def test_raises_on_zero_org_id(self):
        """org_id=0 raises TenantScopeError."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        with pytest.raises(TenantScopeError, match="org_id > 0"):
            method(None, org_id=0)

    def test_raises_on_negative_org_id(self):
        """org_id=-1 raises TenantScopeError."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        with pytest.raises(TenantScopeError, match="org_id > 0"):
            method(None, org_id=-1)

    def test_raises_on_non_int_org_id(self):
        """org_id='2' (string) raises TenantScopeError."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        with pytest.raises(TenantScopeError, match="to be int"):
            method(None, org_id="2")

    def test_raises_on_float_org_id(self):
        """org_id=2.0 (float) raises TenantScopeError."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        with pytest.raises(TenantScopeError, match="to be int"):
            method(None, org_id=2.0)

    def test_passes_with_valid_org_id(self):
        """Valid positive int org_id passes through."""
        @requires_org_id
        def method(self, *, org_id: int):
            return org_id

        assert method(None, org_id=2) == 2
        assert method(None, org_id=999) == 999

    def test_fails_at_decoration_if_no_org_id_param(self):
        """@requires_org_id on a function without org_id param fails at import."""
        with pytest.raises(TypeError, match="must have an 'org_id' parameter"):
            @requires_org_id
            def bad_method(self):
                pass

    def test_fails_at_decoration_if_org_id_not_keyword_only(self):
        """@requires_org_id on a function with positional org_id fails at import."""
        with pytest.raises(TypeError, match="must be keyword-only"):
            @requires_org_id
            def bad_method(self, org_id: int):
                pass

    def test_fails_at_decoration_if_org_id_has_default(self):
        """@requires_org_id on a function with default org_id fails at import."""
        with pytest.raises(TypeError, match="must not have a default value"):
            @requires_org_id
            def bad_method(self, *, org_id: int = None):
                pass

    def test_preserves_function_name(self):
        """Wrapper preserves __name__ and __qualname__."""
        @requires_org_id
        def my_method(self, *, org_id: int):
            pass

        assert my_method.__name__ == "my_method"

    def test_exception_type_is_not_generic(self):
        """TenantScopeError is NOT a ValueError or generic exception."""
        assert not issubclass(TenantScopeError, ValueError)
        assert issubclass(TenantScopeError, Exception)


# ── @cross_org tests ───────────────────────────────────────���───────────

class TestCrossOrg:
    """Test the @cross_org decorator for legitimate cross-tenant operations."""

    def test_fails_without_reason(self):
        """@cross_org without reason fails at import."""
        with pytest.raises(TypeError, match="non-empty 'reason'"):
            @cross_org(reason="", audit_event="test")
            def bad():
                pass

    def test_fails_without_audit_event(self):
        """@cross_org without audit_event fails at import."""
        with pytest.raises(TypeError, match="non-empty 'audit_event'"):
            @cross_org(reason="test reason", audit_event="")
            def bad():
                pass

    def test_emits_audit_log(self, caplog):
        """@cross_org emits structured audit log entry per call."""
        @cross_org(reason="test analytics", audit_event="test_cross_org")
        def admin_method():
            return 42

        with caplog.at_level(logging.INFO):
            result = admin_method()

        assert result == 42
        assert "cross_org_access" in caplog.text
        assert "test analytics" in caplog.text

    def test_preserves_cross_org_attributes(self):
        """Decorated function has _cross_org_reason and _cross_org_audit_event."""
        @cross_org(reason="billing rollup", audit_event="billing_query")
        def admin_billing():
            pass

        assert admin_billing._cross_org_reason == "billing rollup"
        assert admin_billing._cross_org_audit_event == "billing_query"

    def test_allows_call_without_org_id(self):
        """@cross_org methods can be called without org_id."""
        @cross_org(reason="platform stats", audit_event="platform_stats")
        def global_count():
            return 100

        assert global_count() == 100


# ── Tenant table registry tests ────────────────────────────────────────

class TestTenantTableRegistry:
    """Test tenant table classification."""

    def test_baseline_includes_known_tables(self):
        """Baseline includes all known tenant-scoped tables."""
        assert 'discovery_runs' in _BASELINE_TENANT_TABLES
        assert 'anomalies' in _BASELINE_TENANT_TABLES
        assert 'settings' in _BASELINE_TENANT_TABLES
        assert 'soar_actions' in _BASELINE_TENANT_TABLES
        assert 'snapshot_jobs' in _BASELINE_TENANT_TABLES

    def test_baseline_excludes_non_tenant_tables(self):
        """Baseline does NOT include non-tenant tables."""
        assert 'users' not in _BASELINE_TENANT_TABLES
        assert 'tenants' not in _BASELINE_TENANT_TABLES

    def test_baseline_includes_identities(self):
        """AG-132: identities has organization_id — must be in baseline."""
        assert 'identities' in _BASELINE_TENANT_TABLES

    def test_is_tenant_table_uses_baseline_without_conn(self):
        """is_tenant_table falls back to baseline when no DB connection."""
        invalidate_cache()
        assert is_tenant_table('discovery_runs')
        assert is_tenant_table('anomalies')
        assert not is_tenant_table('users')
        assert not is_tenant_table('nonexistent_table')

    def test_invalidate_cache_clears(self):
        """invalidate_cache() resets the cache."""
        invalidate_cache()
        # After invalidation, should still work via baseline
        tables = tenant_tables()
        assert len(tables) > 0

    def test_baseline_has_expected_count(self):
        """Baseline has at least 44 tables (the canonical RLS-protected set)."""
        assert len(_BASELINE_TENANT_TABLES) >= 44


# ── _validate_org_id standalone tests ──────────────────────────────────

class TestValidateOrgId:
    """Test the standalone _validate_org_id function."""

    def test_none_raises(self):
        with pytest.raises(TenantScopeError):
            _validate_org_id(None, "test_func")

    def test_zero_raises(self):
        with pytest.raises(TenantScopeError):
            _validate_org_id(0, "test_func")

    def test_negative_raises(self):
        with pytest.raises(TenantScopeError):
            _validate_org_id(-5, "test_func")

    def test_string_raises(self):
        with pytest.raises(TenantScopeError):
            _validate_org_id("3", "test_func")

    def test_valid_passes(self):
        # Should not raise
        _validate_org_id(1, "test_func")
        _validate_org_id(999, "test_func")

    def test_logs_warning_on_violation(self, caplog):
        """Violations emit structured WARN log."""
        with caplog.at_level(logging.WARNING):
            with pytest.raises(TenantScopeError):
                _validate_org_id(None, "test_func")
        assert "tenant_scope_violation" in caplog.text
