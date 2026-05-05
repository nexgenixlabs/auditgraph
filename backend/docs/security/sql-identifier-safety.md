# SQL Identifier Safety — AG-93

**CWE-89 | OWASP A03:2021 | CVSS 9.8**

## Threat Model

Dynamic SQL identifiers (table names, column names) cannot be parameterized with `%s` —
psycopg2 only parameterizes VALUES. Any f-string interpolation in an identifier position
is a SQL injection vector:

```python
# DANGEROUS — table name from user input
cursor.execute(f"SELECT * FROM {table_name} WHERE id = %s", (id,))
```

An attacker controlling `table_name` can inject arbitrary SQL:
`table_name = "users; DROP TABLE identities--"`

## Solution: Schema-Derived Allowlists

All dynamic identifiers go through `app.security.sql_identifiers`:

```python
from psycopg2 import sql
from app.security.sql_identifiers import safe_table, safe_column

# SAFE — validated against live schema, composed with sql.Identifier
cursor.execute(
    sql.SQL("SELECT COUNT(*) FROM {tbl} WHERE org_id = %s")
       .format(tbl=safe_table(table_name, conn)),
    (org_id,),
)
```

### How it works

1. `safe_table(name, conn)` loads all public table names from `information_schema.tables`
2. Validates `name` is in the allowlist (exact match, case-sensitive)
3. Returns `psycopg2.sql.Identifier(name)` — safe for SQL composition
4. Rejects with `SqlIdentifierError` (not `ValueError`) on failure
5. Cache with 60s TTL (configurable via `SQL_IDENT_CACHE_TTL_SEC` env var)
6. Thread-safe with double-check locking

### Column validation

```python
safe_column('users', 'username', conn)  # OK
safe_column('users', 'evil_col', conn)  # SqlIdentifierError
```

## Fixed Call Sites (10 sites, 7 files)

| File | Site | Original Pattern | Fix |
|------|------|-----------------|-----|
| handlers.py | get_identity_summary | `f"SELECT COUNT(*) FROM {table}"` | `sql.SQL().format(tbl=safe_table())` |
| handlers.py | CISO resource counts | same | same |
| database.py | _safe_del/_critical_del | `f"DELETE FROM {table} WHERE {where}"` | `sql.SQL().format(tbl=sql.Identifier())` |
| database.py | update_user SET | `f"UPDATE users SET {set_parts}"` | Column allowlist + `sql.Identifier(k)` |
| database.py | get_storage_stats | `f"SELECT COUNT(*) FROM {table}"` | `sql.SQL().format(tbl=sql.Identifier())` |
| database.py | verify_rls_enforcement | `f'CREATE POLICY ... ON "{table}"'` | Full `sql.SQL().format()` composition |
| connection_lifecycle.py | cleanup/purge/assert (3) | `f"DELETE FROM {table}"` | `sql.SQL().format(tbl=sql.Identifier())` |
| risk_summary_engine.py | resource counts | `f"SELECT COUNT(*) FROM {table}"` | `sql.SQL().format(tbl=sql.Identifier())` |
| integrity.py | integrity checks | `f"SELECT COUNT(*) FROM {table}"` | `sql.SQL().format(tbl=sql.Identifier())` |
| scim.py | SCIM PATCH | `f"UPDATE users SET {set_parts}"` | Column allowlist + `sql.Identifier()` |

## Remaining DDL Sites (75 baselined)

75 existing f-string SQL sites are in the baseline (`.sql-lint-baseline.json`).
All are verified safe — they iterate over hardcoded table name lists in DDL/migration code.
No user input reaches any of them. They are tracked to prevent regression.

## Regression Guard

### Lint Script

```bash
# Check for new violations (baseline filters known-safe ones)
python3 scripts/lint_no_fstring_sql.py --baseline .sql-lint-baseline.json $(find app -name '*.py')

# Full audit (strict mode flags ALL f-string SQL)
python3 scripts/lint_no_fstring_sql.py --strict $(find app -name '*.py')

# Update baseline after intentionally adding safe DDL
python3 scripts/lint_no_fstring_sql.py --update-baseline .sql-lint-baseline.json $(find app -name '*.py')
```

### Inline Suppression

```python
cursor.execute(f"ALTER TABLE {tbl} ...")  # noqa: NO-FSTRING-SQL — DDL migration
```

### Tests

- `tests/security/test_sql_identifiers.py` — 32 tests, 98% coverage on `sql_identifiers.py`
- `tests/security/test_sql_injection_regression.py` — 24 tests verifying each fixed site + lint script

```bash
pytest tests/security/ -v
```

## Rules for New Code

1. **Never** use f-strings for table/column names in `cursor.execute()`
2. **Always** use `safe_table()` / `safe_column()` + `psycopg2.sql.SQL().format()`
3. **For DDL with hardcoded lists**: use `psycopg2.sql.Identifier()` directly, or add `# noqa: NO-FSTRING-SQL` with justification
4. **Composed WHERE clauses** with parameterized values and hardcoded table names are acceptable
5. **Never** catch `SqlIdentifierError` in generic exception handlers — it's a security signal
