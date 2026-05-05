#!/usr/bin/env python3
"""
AST-based lint: reject f-string SQL IDENTIFIER interpolation in cursor.execute() calls.

Detects f-strings where a variable is interpolated in an SQL identifier position
(table name, column name) — the actual injection risk vector. Patterns detected:

  - FROM {var}          — dynamic table in SELECT
  - JOIN {var}          — dynamic table in JOIN
  - UPDATE {var}        — dynamic table in UPDATE
  - DELETE FROM {var}   — dynamic table in DELETE
  - INTO {var}          — dynamic table in INSERT
  - TABLE {var}         — dynamic table in ALTER/CREATE/DROP
  - ON {var}            — dynamic table in policy/index
  - SET {var}           — dynamic column list in UPDATE
  - TRIGGER {var}       — dynamic trigger name

Composed WHERE clauses with parameterized values (e.g., f"SELECT ... FROM users
WHERE {where}") are NOT flagged because the table name is a literal and all values
use %s parameterization. These are safe by construction.

Respects inline suppression (on the f-string line OR the line before):
    cursor.execute(f"ALTER TABLE {tbl} ...")  # noqa: NO-FSTRING-SQL — DDL migration
    # noqa: NO-FSTRING-SQL — DDL migration with hardcoded list
    cursor.execute(f\"\"\"ALTER TABLE {tbl} ...\"\"\")

Exit code 0 = pass, 1 = violations found.

Run modes:
  --strict              Flag ALL f-string SQL (for full audit)
  --baseline <file>     Exclude known-safe violations recorded in baseline file
  --update-baseline <f> Scan and write current violations to baseline file, then exit 0
  (default)             Flag only identifier-position interpolation
"""

import ast
import hashlib
import json
import sys
import re

# Patterns where interpolation is in an IDENTIFIER position (dangerous)
IDENT_PATTERNS = re.compile(
    r'(?:FROM|JOIN|UPDATE|INTO|TABLE|ON|TRIGGER|INDEX|SEQUENCE|POLICY)\s*$',
    re.IGNORECASE,
)

# Also flag SET clause interpolation (dynamic column names)
SET_PATTERN = re.compile(r'\bSET\s*$', re.IGNORECASE)

SQL_KEYWORDS = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT)\b',
    re.IGNORECASE,
)

EXECUTE_METHODS = {'execute', 'executemany'}
NOQA_PATTERN = re.compile(r'#\s*noqa:\s*NO-FSTRING-SQL')


def _interpolation_in_ident_position(node: ast.JoinedStr) -> bool:
    """Check if any interpolation follows a SQL identifier keyword."""
    values = node.values
    for i, val in enumerate(values):
        if isinstance(val, ast.FormattedValue):
            # Check preceding literal for identifier-position keyword
            if i > 0:
                prev = values[i - 1]
                if isinstance(prev, ast.Constant) and isinstance(prev.value, str):
                    text = prev.value.rstrip()
                    if IDENT_PATTERNS.search(text) or SET_PATTERN.search(text):
                        return True
    return False


def _has_sql_keyword_in_fstring(node: ast.JoinedStr) -> bool:
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if SQL_KEYWORDS.search(value.value):
                return True
    return False


def _is_execute_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in EXECUTE_METHODS:
        return True
    return False


def _has_interpolation(node: ast.JoinedStr) -> bool:
    return any(isinstance(v, ast.FormattedValue) for v in node.values)


def _violation_key(filepath: str, snippet: str) -> str:
    """Content-based key for baseline matching (line-number independent)."""
    content = f"{filepath}:{snippet.strip()}"
    return hashlib.md5(content.encode()).hexdigest()


def check_file(filepath: str, strict: bool = False) -> list[tuple[int, str]]:
    """Return list of (line_number, snippet) violations."""
    try:
        with open(filepath, 'r') as f:
            source = f.read()
            lines = source.splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_execute_call(node):
            continue
        if not node.args:
            continue

        first_arg = node.args[0]

        if isinstance(first_arg, ast.JoinedStr):
            if not _has_sql_keyword_in_fstring(first_arg):
                continue
            if not _has_interpolation(first_arg):
                continue

            if strict or _interpolation_in_ident_position(first_arg):
                line_no = first_arg.lineno
                if line_no <= len(lines):
                    line_text = lines[line_no - 1]
                    if NOQA_PATTERN.search(line_text):
                        continue
                    # Also check line before for noqa (multi-line f-strings)
                    if line_no >= 2 and NOQA_PATTERN.search(lines[line_no - 2]):
                        continue
                snippet = lines[line_no - 1].strip()[:80] if line_no <= len(lines) else ''
                violations.append((line_no, snippet))

    return violations


def _load_baseline(path: str) -> set[str]:
    """Load baseline file (JSON list of content hashes)."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return set(data.get('known_safe', []))
    except (OSError, json.JSONDecodeError):
        return set()


def main():
    strict = '--strict' in sys.argv
    baseline_path = None
    update_baseline_path = None
    args = sys.argv[1:]

    # Parse --baseline and --update-baseline flags
    filtered_args = []
    i = 0
    while i < len(args):
        if args[i] == '--baseline' and i + 1 < len(args):
            baseline_path = args[i + 1]
            i += 2
        elif args[i] == '--update-baseline' and i + 1 < len(args):
            update_baseline_path = args[i + 1]
            i += 2
        else:
            filtered_args.append(args[i])
            i += 1

    files = [a for a in filtered_args if not a.startswith('--')]
    if not files:
        print("Usage: lint_no_fstring_sql.py [--strict] [--baseline <file>] [--update-baseline <file>] <file1.py> [file2.py ...]")
        sys.exit(0)

    # Load baseline if provided
    baseline = _load_baseline(baseline_path) if baseline_path else set()

    all_violations = []
    for filepath in files:
        violations = check_file(filepath, strict=strict)
        for line_no, snippet in violations:
            key = _violation_key(filepath, snippet)
            all_violations.append((filepath, line_no, snippet, key))

    # Update baseline mode: write all current violations and exit 0
    if update_baseline_path:
        keys = sorted(set(v[3] for v in all_violations))
        with open(update_baseline_path, 'w') as f:
            json.dump({
                'description': 'Known-safe f-string SQL violations (hardcoded table lists, DDL migrations)',
                'count': len(keys),
                'known_safe': keys,
            }, f, indent=2)
        print(f"Baseline updated: {len(keys)} known-safe violations written to {update_baseline_path}")
        sys.exit(0)

    # Filter out baselined violations
    new_violations = [(fp, ln, sn, k) for fp, ln, sn, k in all_violations if k not in baseline]

    for filepath, line_no, snippet, _ in new_violations:
        print(f"{filepath}:{line_no}: f-string SQL identifier interpolation: {snippet}")

    if new_violations:
        print(f"\n{len(new_violations)} f-string SQL identifier violation(s) found.")
        if baseline:
            print(f"({len(all_violations) - len(new_violations)} baselined violations skipped)")
        sys.exit(1)
    else:
        if baseline:
            print(f"Clean. ({len(all_violations)} baselined violations skipped)")
        sys.exit(0)


if __name__ == '__main__':
    main()
