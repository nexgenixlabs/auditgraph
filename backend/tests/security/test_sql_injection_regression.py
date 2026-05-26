"""
Regression tests for AG-93: SQL identifier injection fix.

Each test verifies a specific file that was patched from f-string SQL
to psycopg2.sql.SQL() + sql.Identifier() composition. If someone reverts
a fix, these tests will catch it.
"""
from typing import Optional

import pytest


# ── Regression tests for each fixed file ───────────────────────

class TestHandlersRegression:
    """Verify handlers.py uses psycopg2.sql for dynamic table names."""

    def test_imports_psycopg2_sql(self):
        with open('app/api/handlers.py', 'r') as f:
            source = f.read()
        assert 'from psycopg2 import sql as psycopg2_sql' in source

    def test_imports_safe_table(self):
        with open('app/api/handlers.py', 'r') as f:
            source = f.read()
        assert 'safe_table as _safe_tbl' in source

    def test_uses_safe_tbl_for_resource_counts(self):
        with open('app/api/handlers.py', 'r') as f:
            source = f.read()
        assert '_safe_tbl(table, cursor.connection)' in source or \
               '_safe_tbl(tbl, exp_cursor.connection)' in source


class TestDatabaseRegression:
    """Verify database.py uses psycopg2.sql for critical operations."""

    def test_imports_psycopg2_sql(self):
        with open('app/database.py', 'r') as f:
            source = f.read()
        assert 'from psycopg2 import sql as psycopg2_sql' in source

    def test_delete_organization_uses_sql_identifier(self):
        """_safe_del / _critical_del should use psycopg2_sql.Identifier."""
        with open('app/database.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql.SQL("DELETE FROM {tbl} WHERE ")' in source

    def test_update_user_uses_sql_identifier(self):
        """update_user SET clause should use psycopg2_sql.Identifier for columns."""
        with open('app/database.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql.SQL("{col} = %s").format(col=psycopg2_sql.Identifier(k))' in source

    def test_get_storage_stats_uses_sql_identifier(self):
        with open('app/database.py', 'r') as f:
            source = f.read()
        # Should use psycopg2_sql.Identifier for table names in storage stats
        assert 'psycopg2_sql.Identifier(table)' in source

    def test_verify_rls_enforcement_uses_sql_composition(self):
        with open('app/database.py', 'r') as f:
            source = f.read()
        # RLS DDL should use psycopg2_sql.SQL + Identifier
        assert 'psycopg2_sql.SQL("DROP POLICY IF EXISTS {pol} ON {tbl}")' in source


class TestConnectionLifecycleRegression:
    """Verify connection_lifecycle.py uses safe SQL."""

    def test_imports_psycopg2_sql(self):
        with open('app/services/connection_lifecycle.py', 'r') as f:
            source = f.read()
        assert 'from psycopg2 import sql as psycopg2_sql' in source

    def test_delete_uses_sql_identifier(self):
        with open('app/services/connection_lifecycle.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql.SQL("DELETE FROM {tbl} WHERE cloud_connection_id = %s")' in source

    def test_select_uses_sql_identifier(self):
        with open('app/services/connection_lifecycle.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql.SQL("SELECT COUNT(*) FROM {tbl} WHERE cloud_connection_id = %s")' in source


class TestRiskSummaryEngineRegression:
    """Verify risk_summary_engine.py uses safe SQL."""

    def test_imports_psycopg2_sql(self):
        with open('app/engines/risk/risk_summary_engine.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql' in source

    def test_uses_sql_identifier(self):
        with open('app/engines/risk/risk_summary_engine.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql.Identifier' in source


class TestIntegrityRegression:
    """Verify integrity.py uses safe SQL."""

    def test_imports_psycopg2_sql(self):
        with open('app/api/integrity.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql' in source


class TestScimRegression:
    """Verify scim.py PATCH uses allowlisted columns."""

    def test_imports_psycopg2_sql(self):
        with open('app/api/scim.py', 'r') as f:
            source = f.read()
        assert 'psycopg2_sql' in source

    def test_has_column_allowlist(self):
        with open('app/api/scim.py', 'r') as f:
            source = f.read()
        assert '_scim_cols' in source


# ── Lint script self-test ──────────────────────────────────────

class TestLintScript:
    """Verify the lint script itself detects violations correctly."""

    def test_detects_from_interpolation(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        bad = tmp_path / "bad.py"
        bad.write_text('def f():\n    cursor.execute(f"SELECT * FROM {table}")\n')
        violations = check_file(str(bad))
        assert len(violations) == 1

    def test_allows_parameterized_where(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        safe = tmp_path / "safe.py"
        safe.write_text('def f():\n    cursor.execute(f"SELECT * FROM users WHERE {where}", params)\n')
        violations = check_file(str(safe))
        assert len(violations) == 0

    def test_detects_update_set_interpolation(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        bad = tmp_path / "bad_set.py"
        bad.write_text('def f():\n    cursor.execute(f"UPDATE users SET {cols} WHERE id = %s")\n')
        violations = check_file(str(bad))
        assert len(violations) == 1

    def test_detects_alter_table_interpolation(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        bad = tmp_path / "bad_ddl.py"
        bad.write_text('def f():\n    cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN x INT")\n')
        violations = check_file(str(bad))
        assert len(violations) == 1

    def test_noqa_suppresses(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        safe = tmp_path / "noqa.py"
        safe.write_text('def f():\n    cursor.execute(f"SELECT * FROM {table}")  # noqa: NO-FSTRING-SQL\n')
        violations = check_file(str(safe))
        assert len(violations) == 0

    def test_noqa_on_line_before_suppresses(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        safe = tmp_path / "noqa_before.py"
        safe.write_text('def f():\n    # noqa: NO-FSTRING-SQL — DDL migration\n    cursor.execute(f"SELECT * FROM {table}")\n')
        violations = check_file(str(safe))
        assert len(violations) == 0

    def test_strict_mode_catches_all(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        src = tmp_path / "strict.py"
        src.write_text('def f():\n    cursor.execute(f"SELECT * FROM users WHERE {where}")\n')
        violations = check_file(str(src), strict=True)
        assert len(violations) == 1

    def test_non_execute_fstring_not_flagged(self, tmp_path):
        from scripts.lint_no_fstring_sql import check_file
        safe = tmp_path / "log.py"
        safe.write_text('def f():\n    logger.info(f"SELECT * FROM {table}")\n')
        violations = check_file(str(safe))
        assert len(violations) == 0
