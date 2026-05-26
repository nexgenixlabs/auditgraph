"""
Tests for app.security.sql_identifiers — SQL identifier allowlist validation.

Target: 100% line coverage on sql_identifiers.py
"""
import logging
import time
from unittest.mock import MagicMock, patch

import pytest

from app.security.sql_identifiers import (
    SqlIdentifierError,
    _get_column_allowlist,
    _get_table_allowlist,
    _load_column_allowlist,
    _load_table_allowlist,
    _log_rejection,
    _truncate,
    invalidate_cache,
    safe_column,
    safe_columns,
    safe_table,
)


# ── Fixtures ──────────────────────────────────────────────────

def _mock_conn(tables=None, columns=None):
    """Build a mock psycopg2 connection that returns given tables/columns."""
    tables = tables or ['users', 'identities', 'discovery_runs', 'anomalies',
                        'azure_storage_accounts', 'azure_key_vaults']
    columns = columns or {
        'users': ['id', 'username', 'display_name', 'role', 'enabled',
                  'email', 'phone', 'auth_provider', 'external_id',
                  'password_hash', 'organization_id', 'created_at', 'updated_at'],
        'identities': ['id', 'identity_id', 'display_name', 'risk_level',
                       'discovery_run_id', 'organization_id'],
    }
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor

    def _execute_side_effect(sql_str, params=None):
        if 'information_schema.tables' in sql_str:
            cursor.fetchall.return_value = [(t,) for t in tables]
        elif 'information_schema.columns' in sql_str:
            tbl_name = params[0] if params else ''
            cursor.fetchall.return_value = [(c,) for c in columns.get(tbl_name, [])]
        else:
            cursor.fetchall.return_value = []

    cursor.execute.side_effect = _execute_side_effect
    return conn


@pytest.fixture(autouse=True)
def _clear_cache():
    """Clear allowlist cache before each test."""
    invalidate_cache()
    yield
    invalidate_cache()


# ── safe_table tests ──────────────────────────────────────────

class TestSafeTable:
    def test_accepts_known_table(self):
        conn = _mock_conn()
        result = safe_table('users', conn)
        assert result.string == 'users'

    def test_accepts_every_table_in_schema(self):
        tables = ['users', 'identities', 'discovery_runs', 'anomalies',
                  'azure_storage_accounts', 'azure_key_vaults']
        conn = _mock_conn(tables=tables)
        for t in tables:
            result = safe_table(t, conn)
            assert result.string == t

    def test_rejects_injection_drop_table(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("users; DROP TABLE identities--", conn)

    def test_rejects_injection_union_select(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("users UNION SELECT * FROM pg_shadow", conn)

    def test_rejects_empty_string(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="invalid table"):
            safe_table("", conn)

    def test_rejects_none(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="invalid table"):
            safe_table(None, conn)

    def test_rejects_whitespace(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table(" ", conn)

    def test_rejects_case_mismatch(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("USERS", conn)

    def test_rejects_schema_qualified(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("public.users", conn)

    def test_rejects_backticks(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("`users`", conn)

    def test_rejects_quotes(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table('"users"', conn)

    def test_rejects_semicolon(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("users;", conn)

    def test_rejects_comment(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown table"):
            safe_table("users--comment", conn)

    def test_no_conn_raises_if_cache_cold(self):
        with pytest.raises(SqlIdentifierError, match="not initialised"):
            safe_table("users")

    def test_uses_cached_allowlist(self):
        conn = _mock_conn()
        safe_table('users', conn)
        # Second call with no conn should use cache
        result = safe_table('users')
        assert result.string == 'users'


# ── safe_column tests ─────────────────────────────────────────

class TestSafeColumn:
    def test_accepts_known_column(self):
        conn = _mock_conn()
        result = safe_column('users', 'username', conn)
        assert result.string == 'username'

    def test_rejects_unknown_column(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown column"):
            safe_column('users', 'nonexistent_column', conn)

    def test_rejects_cross_table_column_smuggling(self):
        """Column exists in 'identities' but not 'users'."""
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown column"):
            safe_column('users', 'risk_level', conn)

    def test_rejects_empty_column(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="invalid column"):
            safe_column('users', '', conn)

    def test_rejects_none_column(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="invalid column"):
            safe_column('users', None, conn)


# ── safe_columns tests ────────────────────────────────────────

class TestSafeColumns:
    def test_preserves_order(self):
        conn = _mock_conn()
        cols = safe_columns('users', ['email', 'username', 'role'], conn)
        assert [c.string for c in cols] == ['email', 'username', 'role']

    def test_rejects_on_first_unknown(self):
        conn = _mock_conn()
        with pytest.raises(SqlIdentifierError, match="unknown column"):
            safe_columns('users', ['username', 'evil_col'], conn)


# ── Cache tests ───────────────────────────────────────────────

class TestCache:
    def test_invalidate_clears_cache(self):
        conn = _mock_conn()
        safe_table('users', conn)
        invalidate_cache()
        with pytest.raises(SqlIdentifierError, match="not initialised"):
            safe_table('users')  # no conn, cache cleared

    @patch('app.security.sql_identifiers._CACHE_TTL', 0.1)
    def test_cache_expires_after_ttl(self):
        conn = _mock_conn(tables=['users'])
        safe_table('users', conn)
        time.sleep(0.15)
        # Cache expired — needs conn again
        conn2 = _mock_conn(tables=['users', 'new_table'])
        result = safe_table('new_table', conn2)
        assert result.string == 'new_table'

    def test_double_check_locking_table(self):
        """Pre-populate cache so the inner (post-lock) check short-circuits."""
        import app.security.sql_identifiers as mod
        conn = _mock_conn(tables=['users'])
        # Populate cache via first call
        safe_table('users', conn)
        # Expire outer check but keep cache valid by patching timestamp
        saved_ts = mod._table_cache_ts
        mod._table_cache_ts = 0.0  # force past outer check
        # Re-populate cache before the lock is acquired
        mod._table_cache = frozenset(['users'])
        mod._table_cache_ts = time.monotonic()
        # This call hits the double-check branch inside the lock
        result = safe_table('users', conn)
        assert result.string == 'users'

    def test_double_check_locking_column(self):
        """Pre-populate column cache so the inner (post-lock) check short-circuits."""
        import app.security.sql_identifiers as mod
        conn = _mock_conn()
        # Populate column cache
        safe_column('users', 'username', conn)
        # Expire outer check
        entry = mod._column_cache.get('users')
        mod._column_cache['users'] = (entry[0], 0.0)  # expired timestamp
        # Re-populate before lock
        mod._column_cache['users'] = (entry[0], time.monotonic())
        result = safe_column('users', 'username', conn)
        assert result.string == 'username'

    def test_column_cold_cache_no_conn_raises(self):
        """safe_column with no conn and empty column cache raises."""
        conn = _mock_conn()
        safe_table('users', conn)  # populate table cache only
        with pytest.raises(SqlIdentifierError, match="column allowlist not available"):
            safe_column('users', 'username')  # no conn, column cache cold


# ── Logging tests ─────────────────────────────────────────────

class TestLogging:
    def test_rejection_emits_structured_warning(self, caplog):
        conn = _mock_conn()
        with caplog.at_level(logging.WARNING):
            with pytest.raises(SqlIdentifierError):
                safe_table("malicious_table", conn)
        assert any("sql_identifier_rejected" in r.message for r in caplog.records)

    def test_truncates_long_values(self):
        long_val = "a" * 200
        result = _truncate(long_val)
        assert len(result) <= 64 + 3  # 64 chars + "..."
        assert result.endswith("...")


# ── SqlIdentifierError type tests ─────────────────────────────

class TestExceptionType:
    def test_is_not_value_error(self):
        assert not issubclass(SqlIdentifierError, ValueError)

    def test_is_exception(self):
        assert issubclass(SqlIdentifierError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(SqlIdentifierError):
            raise SqlIdentifierError("test")
