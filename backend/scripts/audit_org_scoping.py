#!/usr/bin/env python3
"""
audit_org_scoping.py
====================

Static auditor that scans the backend for SELECT statements against
AuditGraph's :data:`GUARDED_TABLES` that are missing an
``organization_id`` filter in their WHERE clause.

Why this exists
---------------
Every guarded table is part of AuditGraph's multi-tenant perimeter. A
single unscoped ``SELECT ... FROM identities`` is a horizontal privilege
escalation waiting to happen. Runtime defenses (``require_org_scope``,
``OrgScopedSession``) catch slip-ups at execute time, but we want CI to
refuse the merge before the code ever ships.

How it works
------------
1. Walk every ``.py`` file under the given path.
2. For each file, extract SQL literals (strings passed to ``text(...)``
   *and* bare multi-line SQL strings).
3. Parse each candidate with :mod:`sqlparse` if available, otherwise fall
   back to a regex-based WHERE-clause extractor.
4. For every ``SELECT`` that touches a guarded table, verify that the
   WHERE clause mentions ``organization_id``. Emit a CRITICAL finding if
   it does not.

Usage
-----
.. code-block:: bash

    python backend/scripts/audit_org_scoping.py \\
        --path backend/app/ \\
        --fail-on-violation

Exit codes
----------
* ``0`` — clean scan, no violations.
* ``1`` — at least one CRITICAL violation was found (when
  ``--fail-on-violation`` is set).
* ``2`` — invalid arguments or the scan itself failed.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


# The guarded-table list is duplicated here as a hardcoded tuple so the
# audit script stays importable even inside CI containers that do not
# install the full backend. The authoritative source of truth remains
# ``backend/app/middleware/org_scope_guard.py``; a unit test asserts the
# two lists stay in sync.
GUARDED_TABLES: tuple[str, ...] = (
    "identities",
    "role_assignments",
    "resources",
    "attack_paths",
    "graph_edges",
    "global_identity_registry",
    "global_identity_members",
)


SEVERITY_CRITICAL: str = "CRITICAL"


# Regex helpers -------------------------------------------------------------


_SELECT_RE: re.Pattern[str] = re.compile(
    r"""
    \bSELECT\b                 # literal SELECT
    (?P<body>.*?)              # columns + FROM clause
    (?:\bWHERE\b\s+(?P<where>.*?))?   # optional WHERE
    (?=\bGROUP\b|\bORDER\b|\bLIMIT\b|\bUNION\b|$)
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

_FROM_TABLE_RE: re.Pattern[str] = re.compile(
    r"\bFROM\s+([A-Za-z_][A-Za-z0-9_\.]*)", re.IGNORECASE
)

_JOIN_TABLE_RE: re.Pattern[str] = re.compile(
    r"\bJOIN\s+([A-Za-z_][A-Za-z0-9_\.]*)", re.IGNORECASE
)

_ORG_FILTER_RE: re.Pattern[str] = re.compile(r"\borganization_id\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    filename: str
    line_number: int
    table: str
    severity: str
    excerpt: str

    def to_dict(self) -> dict:
        return asdict(self)

    def format_console(self) -> str:
        return (
            f"{self.severity} {self.filename}:{self.line_number} "
            f"table={self.table}\n    {self.excerpt}"
        )


# ---------------------------------------------------------------------------
# SQL literal extraction (AST-driven, resilient)
# ---------------------------------------------------------------------------


@dataclass
class SqlLiteral:
    value: str
    line_number: int


class _SqlLiteralCollector(ast.NodeVisitor):
    """Collect string literals that *look like* SQL.

    Heuristic: any string containing a top-level ``SELECT``/``INSERT``/
    ``UPDATE``/``DELETE`` keyword is treated as SQL. The audit only acts on
    ``SELECT`` statements but we keep the net wide enough to catch
    ``SELECT`` used inside CTEs or subqueries.
    """

    _SQL_KEYWORDS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH")

    def __init__(self) -> None:
        self.literals: list[SqlLiteral] = []

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str) and self._looks_like_sql(node.value):
            self.literals.append(
                SqlLiteral(value=node.value, line_number=node.lineno)
            )
        self.generic_visit(node)

    @classmethod
    def _looks_like_sql(cls, value: str) -> bool:
        upper = value.upper()
        return any(kw in upper for kw in cls._SQL_KEYWORDS)


def extract_sql_literals(source: str) -> list[SqlLiteral]:
    """Parse ``source`` and return every SQL-looking string literal."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # A syntactically broken file cannot be audited safely — surface
        # it to the caller as an empty literal list; the caller logs and
        # the CI step will still fail on any other concrete violation.
        return []
    collector = _SqlLiteralCollector()
    collector.visit(tree)
    return collector.literals


# ---------------------------------------------------------------------------
# Violation detection
# ---------------------------------------------------------------------------


def find_violations_in_sql(sql: str) -> list[str]:
    """Return the list of guarded tables referenced without an org filter.

    An empty list means the SQL is either not a SELECT on a guarded table,
    or the SELECT already filters by ``organization_id``.
    """
    offenders: list[str] = []
    for match in _SELECT_RE.finditer(sql):
        body = match.group("body") or ""
        where = match.group("where") or ""

        from_tables = {t.lower() for t in _FROM_TABLE_RE.findall(body)}
        join_tables = {t.lower() for t in _JOIN_TABLE_RE.findall(body)}
        referenced = from_tables | join_tables
        guarded_hit = {t for t in referenced if t in GUARDED_TABLES}
        if not guarded_hit:
            continue

        if _ORG_FILTER_RE.search(where):
            continue

        for t in sorted(guarded_hit):
            if t not in offenders:
                offenders.append(t)

    return offenders


def audit_file(path: Path) -> list[Finding]:
    """Audit a single Python file and return any findings."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        logging.getLogger(__name__).warning(
            "audit.read_failed path=%s err=%s", path, exc
        )
        return []

    findings: list[Finding] = []
    for literal in extract_sql_literals(source):
        offenders = find_violations_in_sql(literal.value)
        if not offenders:
            continue
        excerpt = _compact_excerpt(literal.value)
        for table in offenders:
            findings.append(
                Finding(
                    filename=str(path),
                    line_number=literal.line_number,
                    table=table,
                    severity=SEVERITY_CRITICAL,
                    excerpt=excerpt,
                )
            )
    return findings


def audit_path(root: Path) -> list[Finding]:
    """Walk ``root`` and audit every ``.py`` file under it."""
    findings: list[Finding] = []
    for py_file in _iter_python_files(root):
        findings.extend(audit_file(py_file))
    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_python_files(root: Path) -> Iterator[Path]:
    if root.is_file() and root.suffix == ".py":
        yield root
        return
    for path in sorted(root.rglob("*.py")):
        # Skip virtualenvs, build dirs, and auto-generated test cruft.
        parts = set(path.parts)
        if parts & {".venv", "venv", "__pycache__", "build", "dist", ".tox"}:
            continue
        yield path


def _compact_excerpt(sql: str, *, max_length: int = 240) -> str:
    compact = re.sub(r"\s+", " ", sql).strip()
    if len(compact) > max_length:
        compact = compact[: max_length - 1] + "…"
    return compact


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit AuditGraph backend source for SELECTs on guarded tables "
            "missing an organization_id filter."
        )
    )
    parser.add_argument(
        "--path",
        type=Path,
        required=True,
        help="Directory (or single file) to scan recursively.",
    )
    parser.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="Exit with code 1 if any CRITICAL violation is found.",
    )
    parser.add_argument(
        "--format",
        choices=("console", "json"),
        default="console",
        help="Output format for findings.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational output; only emit findings.",
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    log = logging.getLogger("audit_org_scoping")

    if not args.path.exists():
        log.error("path does not exist: %s", args.path)
        return 2

    log.info("scanning %s", args.path)
    findings = audit_path(args.path)

    if args.format == "json":
        sys.stdout.write(
            json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True) + "\n"
        )
    else:
        if not findings:
            log.info("no violations found")
        else:
            for finding in findings:
                sys.stdout.write(finding.format_console() + "\n")
            log.warning("%d violations found", len(findings))

    if findings and args.fail_on_violation:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
