#!/usr/bin/env python3
"""
AG-94: Static lint — detect SQL queries on tenant-scoped tables missing organization_id filter.

Walks Python AST to find cursor.execute()/executemany() calls, extracts SQL strings,
checks if they reference tenant-scoped tables, and verifies organization_id appears
in the WHERE clause (or JOIN condition).

Usage:
    python scripts/lint_tenant_scope.py                    # scan all backend Python files
    python scripts/lint_tenant_scope.py app/database.py    # scan specific file
    python scripts/lint_tenant_scope.py --baseline         # generate baseline file

Inline suppress: # noqa: TENANT-SCOPE — reason: <text>

Exit codes:
    0 — no violations (or all in baseline)
    1 — violations found
"""

import ast
import json
import os
import re
import sys

# Tenant-scoped tables (canonical list from integrity.py)
TENANT_TABLES = {
    'activity_log', 'agirs_scores', 'anomalies', 'api_keys',
    'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
    'cloud_connections', 'compliance_framework_config', 'compliance_snapshots',
    'copilot_conversations', 'credentials',
    'dashboard_preferences', 'discovery_runs', 'discovery_stage_log',
    'drift_reports', 'entra_role_assignments',
    'graph_api_permissions', 'graph_attack_findings', 'graph_edges',
    'identities',
    'identity_exposures', 'identity_groups', 'identity_group_members',
    'identity_subscription_access',
    'job_runs', 'notifications',
    'pim_activations', 'pim_eligible_assignments', 'posture_scores',
    'remediation_actions', 'remediation_playbooks',
    'risk_rules', 'risk_scores', 'risk_summary',
    'role_assignments',
    'sa_attestations', 'saved_views', 'scan_schedules',
    'security_findings', 'settings', 'snapshot_jobs', 'snapshot_runs',
    'soar_actions', 'soar_playbooks',
    'sp_app_roles', 'webhooks',
    'workload_activity_stats', 'workload_anomaly_events', 'workload_signin_events',
}

# Regex to extract table names from SQL FROM/JOIN/INTO/UPDATE clauses
TABLE_REF_RE = re.compile(
    r'\b(?:FROM|JOIN|INTO|UPDATE)\s+([a-z_][a-z0-9_]*)',
    re.IGNORECASE
)

# Regex to check for organization_id in WHERE/AND/ON clause
ORG_FILTER_RE = re.compile(
    r'organization_id\s*=',
    re.IGNORECASE
)

# noqa suppress pattern
NOQA_RE = re.compile(r'#\s*noqa:\s*TENANT-SCOPE')


def extract_sql_string(node):
    """Try to extract a SQL string from an AST node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        # f-string — try to extract the constant parts
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append('__EXPR__')
        return ''.join(parts)
    return None


def find_sql_calls(tree, source_lines):
    """Find cursor.execute()/executemany() calls and extract SQL + line number."""
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Match cursor.execute or cursor.executemany
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ('execute', 'executemany'):
            if node.args:
                sql_str = extract_sql_string(node.args[0])
                if sql_str:
                    # Check for noqa suppress on the same line
                    line_no = node.lineno
                    if line_no <= len(source_lines):
                        line_text = source_lines[line_no - 1]
                        if NOQA_RE.search(line_text):
                            continue
                    results.append((line_no, sql_str))
    return results


def check_sql(sql_str):
    """Check if SQL references tenant tables without organization_id filter.

    Returns list of (table_name, issue) tuples.
    """
    issues = []
    tables_found = TABLE_REF_RE.findall(sql_str)
    tenant_tables_used = [t.lower() for t in tables_found if t.lower() in TENANT_TABLES]

    if not tenant_tables_used:
        return issues

    has_org_filter = bool(ORG_FILTER_RE.search(sql_str))

    if not has_org_filter:
        for table in set(tenant_tables_used):
            issues.append((table, 'missing organization_id filter'))

    return issues


def get_function_name(tree, line_no):
    """Find the enclosing function name for a given line number."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, 'end_lineno'):
                if node.lineno <= line_no <= (node.end_lineno or node.lineno + 1000):
                    return node.name
            elif node.lineno <= line_no:
                return node.name
    return '<module>'


def scan_file(filepath, baseline=None):
    """Scan a Python file for tenant-scope violations.

    Returns list of (file, line, function, table, issue) tuples.
    """
    violations = []
    baseline = baseline or set()

    try:
        with open(filepath, 'r') as f:
            source = f.read()
            source_lines = source.split('\n')
    except (IOError, UnicodeDecodeError):
        return violations

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return violations

    sql_calls = find_sql_calls(tree, source_lines)

    for line_no, sql_str in sql_calls:
        issues = check_sql(sql_str)
        for table, issue in issues:
            func_name = get_function_name(tree, line_no)
            key = f"{filepath}:{line_no}:{func_name}:{table}"
            if key not in baseline:
                violations.append((filepath, line_no, func_name, table, issue))

    return violations


def load_baseline(path):
    """Load baseline file (JSON list of suppressed violation keys)."""
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        data = json.load(f)
    return set(data)


def main():
    baseline_path = os.path.join(os.path.dirname(__file__), '..', '.sql-lint-baseline.json')
    generate_baseline = '--baseline' in sys.argv

    # Determine files to scan
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if args:
        files = args
    else:
        # Scan all Python files in backend/app/
        app_dir = os.path.join(os.path.dirname(__file__), '..', 'app')
        files = []
        for root, dirs, filenames in os.walk(app_dir):
            for fn in filenames:
                if fn.endswith('.py'):
                    files.append(os.path.join(root, fn))

    baseline = load_baseline(baseline_path) if not generate_baseline else set()

    all_violations = []
    for filepath in sorted(files):
        violations = scan_file(filepath, baseline)
        all_violations.extend(violations)

    if generate_baseline:
        keys = []
        for v in all_violations:
            filepath, line_no, func_name, table, issue = v
            keys.append(f"{filepath}:{line_no}:{func_name}:{table}")
        with open(baseline_path, 'w') as f:
            json.dump(sorted(keys), f, indent=2)
        print(f"Baseline written: {len(keys)} entries → {baseline_path}")
        return 0

    if all_violations:
        print(f"\n{'='*72}")
        print(f"TENANT-SCOPE VIOLATIONS: {len(all_violations)} found")
        print(f"{'='*72}\n")
        for filepath, line_no, func_name, table, issue in all_violations:
            rel_path = os.path.relpath(filepath)
            print(f"  {rel_path}:{line_no} [{func_name}] table={table}: {issue}")
        print(f"\n{'='*72}")
        print("Fix: Add WHERE organization_id = %s (or suppress with # noqa: TENANT-SCOPE)")
        print(f"{'='*72}\n")
        return 1
    else:
        print("tenant-scope lint: OK (no violations)")
        return 0


if __name__ == '__main__':
    sys.exit(main())
