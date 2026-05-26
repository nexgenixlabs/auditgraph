"""
Centralised SQL identifier safety — SSOT for all dynamic table/column references.

All runtime SQL that interpolates table or column names MUST go through
safe_table() / safe_column(). These validate against a live schema allowlist
loaded from information_schema and reject anything unknown.

Pattern:
    from app.security.sql_identifiers import safe_table, safe_column
    from psycopg2 import sql

    cursor.execute(
        sql.SQL("SELECT COUNT(*) FROM {tbl} WHERE org_id = %s")
           .format(tbl=safe_table(name, conn)),
        (org_id,),
    )

See docs/security/sql-identifier-safety.md for full threat model.
"""

import logging
import os
import threading
import time
from typing import FrozenSet, Iterable, Optional

from psycopg2 import sql

logger = logging.getLogger(__name__)

_CACHE_TTL = max(5, int(os.environ.get('SQL_IDENT_CACHE_TTL_SEC', '60')))
_MAX_LOG_VALUE_LEN = 64


class SqlIdentifierError(Exception):
    """Raised when an SQL identifier fails allowlist validation.

    This is a security exception — it MUST NOT be caught by generic
    Exception handlers. Callers should return 400/422 to the client
    with a safe error code, never exposing SQL text or the rejected value.
    """


# ── Allowlist cache ──────────────────────────────────────────

_lock = threading.Lock()
_table_cache: Optional[FrozenSet[str]] = None
_table_cache_ts: float = 0.0
_column_cache: dict[str, tuple[FrozenSet[str], float]] = {}


def _load_table_allowlist(conn) -> FrozenSet[str]:
    """Load public table names from information_schema."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
    )
    names = frozenset(r[0] for r in cursor.fetchall())
    cursor.close()
    return names


def _load_column_allowlist(conn, table: str) -> FrozenSet[str]:
    """Load column names for a specific table from information_schema."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = %s",
        (table,),
    )
    names = frozenset(r[0] for r in cursor.fetchall())
    cursor.close()
    return names


def _get_table_allowlist(conn) -> FrozenSet[str]:
    global _table_cache, _table_cache_ts
    now = time.monotonic()
    if _table_cache is not None and (now - _table_cache_ts) < _CACHE_TTL:
        return _table_cache
    with _lock:
        # Double-check after acquiring lock
        if _table_cache is not None and (time.monotonic() - _table_cache_ts) < _CACHE_TTL:
            return _table_cache
        _table_cache = _load_table_allowlist(conn)
        _table_cache_ts = time.monotonic()
        return _table_cache


def _get_column_allowlist(conn, table: str) -> FrozenSet[str]:
    now = time.monotonic()
    entry = _column_cache.get(table)
    if entry is not None and (now - entry[1]) < _CACHE_TTL:
        return entry[0]
    with _lock:
        entry = _column_cache.get(table)
        if entry is not None and (time.monotonic() - entry[1]) < _CACHE_TTL:
            return entry[0]
        cols = _load_column_allowlist(conn, table)
        _column_cache[table] = (cols, time.monotonic())
        return cols


def invalidate_cache():
    """Clear all cached allowlists. Call after schema migrations."""
    global _table_cache, _table_cache_ts, _column_cache
    with _lock:
        _table_cache = None
        _table_cache_ts = 0.0
        _column_cache.clear()


# ── Validators ───────────────────────────────────────────────

def _truncate(value: str) -> str:
    if len(value) <= _MAX_LOG_VALUE_LEN:
        return value
    return value[:_MAX_LOG_VALUE_LEN] + '...'


def _log_rejection(kind: str, value: str):
    import traceback
    frames = traceback.extract_stack(limit=5)
    caller = f"{frames[-3].filename}:{frames[-3].lineno}" if len(frames) >= 3 else "unknown"
    logger.warning(
        "sql_identifier_rejected",
        extra={
            "event": "sql_identifier_rejected",
            "kind": kind,
            "value": _truncate(value),
            "caller": caller,
        },
    )


def safe_table(name: str, conn=None) -> sql.Identifier:
    """Validate table name against schema allowlist and return sql.Identifier.

    Args:
        name: Table name to validate.
        conn: psycopg2 connection for allowlist lookup. If None, uses
              the cached allowlist (fails if cache is cold).

    Raises:
        SqlIdentifierError: If the name is not in the allowlist.
    """
    if not isinstance(name, str) or not name:
        _log_rejection("table", repr(name))
        raise SqlIdentifierError("invalid table identifier")

    allowlist = _get_table_allowlist(conn) if conn else _table_cache
    if allowlist is None:
        raise SqlIdentifierError("table allowlist not initialised — provide a connection")

    if name not in allowlist:
        _log_rejection("table", name)
        raise SqlIdentifierError(f"unknown table: {_truncate(name)!r}")

    return sql.Identifier(name)


def safe_column(table: str, name: str, conn=None) -> sql.Identifier:
    """Validate column name against the target table's schema allowlist.

    Args:
        table: Table the column belongs to (must pass safe_table first).
        name: Column name to validate.
        conn: psycopg2 connection for allowlist lookup.

    Raises:
        SqlIdentifierError: If the column is not in the target table.
    """
    if not isinstance(name, str) or not name:
        _log_rejection("column", repr(name))
        raise SqlIdentifierError("invalid column identifier")

    allowlist = _get_column_allowlist(conn, table) if conn else _column_cache.get(table, (frozenset(), 0))[0]
    if not allowlist:
        raise SqlIdentifierError(f"column allowlist not available for table {_truncate(table)!r}")

    if name not in allowlist:
        _log_rejection("column", f"{table}.{name}")
        raise SqlIdentifierError(f"unknown column: {_truncate(table)}.{_truncate(name)!r}")

    return sql.Identifier(name)


def safe_columns(table: str, names: Iterable[str], conn=None) -> list[sql.Identifier]:
    """Validate multiple column names, preserving order.

    Raises SqlIdentifierError on the first unknown column.
    """
    return [safe_column(table, n, conn) for n in names]
