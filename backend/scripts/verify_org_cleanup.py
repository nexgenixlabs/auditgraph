#!/usr/bin/env python3
"""
Script 2: Deep-verify an org is fully removed, clean orphans, restart services.

Usage:
  python scripts/verify_org_cleanup.py --org-id 11
  python scripts/verify_org_cleanup.py --org-id 11 --restart
  python scripts/verify_org_cleanup.py --org-id 11 --restart --no-prompt

Run AFTER nuke_org.py to confirm nothing leaked.
"""

import argparse
import os
import signal
import subprocess
import sys
import time

import psycopg2

try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env.local')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass


def get_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=int(os.environ.get('DB_PORT', '5434')),
        dbname=os.environ.get('DB_NAME', 'auditgraph'),
        user=os.environ.get('DB_ADMIN_USER', os.environ.get('DB_USER', 'auditgraph')),
        password=os.environ.get('DB_ADMIN_PASSWORD', os.environ.get('DB_PASSWORD', 'auditgraph')),
        sslmode=os.environ.get('DB_SSLMODE', 'prefer'),
    )


def table_exists(cur, name):
    cur.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=%s",
        (name,),
    )
    return cur.fetchone() is not None


def col_exists(cur, table, col):
    cur.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
        (table, col),
    )
    return cur.fetchone() is not None


# ── Every possible org-scoped column pattern ──
ORG_COLUMNS = ['organization_id', 'org_id', 'target_organization_id']

# FK-based tables (no direct org column)
FK_TABLES = [
    ('pim_activations',          'identity_db_id', 'identities'),
    ('pim_eligible_assignments', 'identity_db_id', 'identities'),
    ('graph_snapshots',          'discovery_run_id', 'discovery_runs'),
]

# Orphan checks: (child_table, child_col, parent_table, parent_col)
ORPHAN_CHECKS = [
    ('role_assignments',          'identity_db_id', 'identities', 'id'),
    ('entra_role_assignments',    'identity_db_id', 'identities', 'id'),
    ('credentials',               'identity_db_id', 'identities', 'id'),
    ('sp_app_roles',              'identity_db_id', 'identities', 'id'),
    ('sp_ownership',              'identity_db_id', 'identities', 'id'),
    ('graph_api_permissions',     'identity_db_id', 'identities', 'id'),
    ('agent_classifications',     'identity_db_id', 'identities', 'id'),
    ('lineage_verdicts',          'identity_id',    'identities', 'id'),
    ('identity_subscription_access', 'identity_db_id', 'identities', 'id'),
    ('entra_group_memberships',   'group_db_id',    'entra_groups', 'id'),
    ('identities',                'discovery_run_id', 'discovery_runs', 'id'),
    ('pim_activations',           'identity_db_id', 'identities', 'id'),
    ('pim_eligible_assignments',  'identity_db_id', 'identities', 'id'),
    ('graph_snapshots',           'discovery_run_id', 'discovery_runs', 'id'),
    ('drift_reports',             'run_id',         'discovery_runs', 'id'),
]


def scan_all_tables(cur, org_id):
    """Scan every public table for any row belonging to this org. Returns list of (table, col, count)."""
    leaks = []

    # Get all public tables
    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
    all_tables = [r[0] for r in cur.fetchall()]

    for tbl in all_tables:
        for org_col in ORG_COLUMNS:
            if col_exists(cur, tbl, org_col):
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}" WHERE "{org_col}" = %s', (org_id,))
                cnt = cur.fetchone()[0]
                if cnt > 0:
                    leaks.append((tbl, org_col, cnt))

    # FK-based tables
    for child, child_col, parent in FK_TABLES:
        if not table_exists(cur, child) or not table_exists(cur, parent):
            continue
        if not col_exists(cur, child, child_col):
            continue
        cur.execute(
            f'SELECT COUNT(*) FROM "{child}" WHERE "{child_col}" IN '
            f'(SELECT id FROM "{parent}" WHERE organization_id = %s)',
            (org_id,),
        )
        cnt = cur.fetchone()[0]
        if cnt > 0:
            leaks.append((child, f'{child_col}→{parent}', cnt))

    return leaks


def scan_orphans(cur):
    """Find orphaned rows across all FK relationships. Returns list of (child, col, parent, count)."""
    orphans = []
    for child, child_col, parent, parent_col in ORPHAN_CHECKS:
        if not table_exists(cur, child) or not table_exists(cur, parent):
            continue
        if not col_exists(cur, child, child_col):
            continue
        cur.execute(f"""
            SELECT COUNT(*) FROM "{child}" c
            WHERE c."{child_col}" IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM "{parent}" p WHERE p."{parent_col}" = c."{child_col}")
        """)
        cnt = cur.fetchone()[0]
        if cnt > 0:
            orphans.append((child, child_col, parent, cnt))
    return orphans


def clean_orphans(conn, cur, orphans):
    """Delete orphaned rows. Returns total cleaned."""
    total = 0
    for child, child_col, parent, cnt in orphans:
        cur.execute(f"""
            DELETE FROM "{child}"
            WHERE "{child_col}" IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM "{parent}" p WHERE p.id = "{child}"."{child_col}")
        """)
        deleted = cur.rowcount
        if deleted > 0:
            print(f'    Cleaned {deleted} orphans from {child}')
            total += deleted
    if total > 0:
        conn.commit()
    return total


def check_sequences(cur, org_id):
    """Check if any sequence names suggest org-specific data (informational)."""
    # Not usually an issue but check refresh_tokens for the deleted users
    if table_exists(cur, 'refresh_tokens'):
        cur.execute("""
            SELECT COUNT(*) FROM refresh_tokens rt
            WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = rt.user_id)
        """)
        cnt = cur.fetchone()[0]
        if cnt > 0:
            return [('refresh_tokens', 'orphaned (no user)', cnt)]
    return []


def find_process(name_pattern):
    """Find PIDs matching a pattern."""
    try:
        result = subprocess.run(
            ['pgrep', '-f', name_pattern],
            capture_output=True, text=True, timeout=5,
        )
        return [int(p) for p in result.stdout.strip().split('\n') if p.strip()]
    except Exception:
        return []


def kill_process(name_pattern, label):
    """Kill processes matching pattern. Returns True if any were killed."""
    pids = find_process(name_pattern)
    # Filter out our own PID
    pids = [p for p in pids if p != os.getpid()]
    if not pids:
        print(f'    {label}: not running')
        return False
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            print(f'    {label}: killed PID {pid}')
        except ProcessLookupError:
            pass
    time.sleep(1)
    return True


def start_backend():
    """Start Flask backend on port 5001."""
    backend_dir = os.path.join(os.path.dirname(__file__), '..')
    env = os.environ.copy()
    env['FLASK_APP'] = 'app.main'
    env['FLASK_ENV'] = 'development'
    log_path = '/tmp/flask_fresh.log'
    log_file = open(log_path, 'w')
    proc = subprocess.Popen(
        [sys.executable, '-m', 'flask', 'run', '--port', '5001'],
        cwd=backend_dir,
        env=env,
        stdout=log_file,
        stderr=log_file,
    )
    print(f'    Backend started: PID {proc.pid}, log → {log_path}')
    return proc


def start_frontend():
    """Start frontend dev server."""
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'frontend')
    if not os.path.isdir(frontend_dir):
        print(f'    Frontend dir not found: {frontend_dir}')
        return None
    log_path = '/tmp/frontend_fresh.log'
    log_file = open(log_path, 'w')
    proc = subprocess.Popen(
        ['npm', 'start'],
        cwd=frontend_dir,
        stdout=log_file,
        stderr=log_file,
    )
    print(f'    Frontend started: PID {proc.pid}, log → {log_path}')
    return proc


def wait_for_health(port, timeout=30):
    """Wait for a health endpoint to respond."""
    import urllib.request
    url = f'http://localhost:{port}/health'
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            resp = urllib.request.urlopen(url, timeout=3)
            if resp.status == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def main():
    parser = argparse.ArgumentParser(description='Verify org cleanup and optionally restart services.')
    parser.add_argument('--org-id', type=int, required=True, help='Organization ID to verify')
    parser.add_argument('--restart', action='store_true', help='Restart backend and frontend after verification')
    parser.add_argument('--no-prompt', action='store_true', help='Skip confirmation for restart')
    parser.add_argument('--clean-orphans', action='store_true', help='Auto-clean any orphaned records found')
    parser.add_argument('--fix', action='store_true', help='Auto-fix all issues: delete leaked rows, orphans, stale tokens')
    args = parser.parse_args()

    org_id = args.org_id
    issues = 0

    conn = get_connection()
    conn.autocommit = True
    cur = conn.cursor()

    # ══════════════════════════════════════════
    # CHECK 1: Org record itself
    # ══════════════════════════════════════════
    print(f'\n  ══════════════════════════════════════════')
    print(f'  CHECK 1 — Organization record (id={org_id})')
    print(f'  ══════════════════════════════════════════')
    cur.execute("SELECT id, name FROM organizations WHERE id = %s", (org_id,))
    org = cur.fetchone()
    if org:
        print(f'    FAIL: Organization "{org[1]}" (id={org[0]}) still exists!')
        print(f'    Run: python scripts/nuke_org.py --org-id {org_id}')
        issues += 1
    else:
        print(f'    PASS: Organization id={org_id} not found in organizations table.')

    # ══════════════════════════════════════════
    # CHECK 2: Deep scan all tables
    # ══════════════════════════════════════════
    print(f'\n  ══════════════════════════════════════════')
    print(f'  CHECK 2 — Deep scan all tables for org={org_id}')
    print(f'  ══════════════════════════════════════════')
    leaks = scan_all_tables(cur, org_id)
    if leaks:
        for tbl, col, cnt in leaks:
            print(f'    LEAK: {tbl}.{col} → {cnt} rows')
            issues += cnt
        print(f'\n    Total leaked rows: {sum(c for _, _, c in leaks)}')

        if args.fix:
            print('\n    Fixing leaked rows...')
            conn.autocommit = False
            fix_cur = conn.cursor()
            fixed = 0
            for tbl, col, cnt in leaks:
                # col may be 'child_col→parent' for FK tables; handle both
                if '→' in col:
                    child_col, parent = col.split('→')
                    fix_cur.execute(
                        f'DELETE FROM "{tbl}" WHERE "{child_col}" IN '
                        f'(SELECT id FROM "{parent}" WHERE organization_id = %s)',
                        (org_id,),
                    )
                else:
                    fix_cur.execute(f'DELETE FROM "{tbl}" WHERE "{col}" = %s', (org_id,))
                deleted = fix_cur.rowcount
                if deleted > 0:
                    print(f'    Deleted {deleted} rows from {tbl}')
                    fixed += deleted
            conn.commit()
            conn.autocommit = True
            cur = conn.cursor()
            print(f'    Fixed {fixed} leaked rows.')
            issues -= fixed
    else:
        print(f'    PASS: Zero rows found for org={org_id} across all tables.')

    # ══════════════════════════════════════════
    # CHECK 3: Orphan scan (global, not org-specific)
    # ══════════════════════════════════════════
    print(f'\n  ══════════════════════════════════════════')
    print(f'  CHECK 3 — Orphan scan (global FK integrity)')
    print(f'  ══════════════════════════════════════════')
    orphans = scan_orphans(cur)
    if orphans:
        for child, child_col, parent, cnt in orphans:
            print(f'    ORPHAN: {child}.{child_col} → {parent}: {cnt} rows')
        issues += sum(c for _, _, _, c in orphans)

        if args.clean_orphans or args.fix:
            print('\n    Cleaning orphans...')
            conn.autocommit = False
            cleaned = clean_orphans(conn, cur, orphans)
            conn.autocommit = True
            cur = conn.cursor()
            print(f'    Cleaned {cleaned} orphaned rows.')
            issues -= cleaned
        else:
            print(f'\n    Re-run with --clean-orphans or --fix to auto-clean.')
    else:
        print(f'    PASS: No orphaned records found.')

    # ══════════════════════════════════════════
    # CHECK 4: Stale refresh tokens
    # ══════════════════════════════════════════
    print(f'\n  ══════════════════════════════════════════')
    print(f'  CHECK 4 — Stale refresh tokens')
    print(f'  ══════════════════════════════════════════')
    seq_issues = check_sequences(cur, org_id)
    if seq_issues:
        for tbl, desc, cnt in seq_issues:
            print(f'    STALE: {tbl}: {cnt} {desc}')
        issues += sum(c for _, _, c in seq_issues)

        if args.fix:
            print('    Cleaning stale tokens...')
            conn.autocommit = False
            fix_cur = conn.cursor()
            fix_cur.execute("""
                DELETE FROM refresh_tokens
                WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = refresh_tokens.user_id)
            """)
            cleaned = fix_cur.rowcount
            conn.commit()
            conn.autocommit = True
            cur = conn.cursor()
            print(f'    Cleaned {cleaned} stale tokens.')
            issues -= cleaned
    else:
        print(f'    PASS: No stale tokens.')

    # ══════════════════════════════════════════
    # CHECK 5: Views referencing org
    # ══════════════════════════════════════════
    print(f'\n  ══════════════════════════════════════════')
    print(f'  CHECK 5 — Materialized views / caches')
    print(f'  ══════════════════════════════════════════')
    views_checked = 0
    for view_name in ['v_critical_identities', 'v_latest_identities']:
        if table_exists(cur, view_name):
            if col_exists(cur, view_name, 'organization_id'):
                cur.execute(f'SELECT COUNT(*) FROM "{view_name}" WHERE organization_id = %s', (org_id,))
                cnt = cur.fetchone()[0]
                if cnt > 0:
                    print(f'    STALE VIEW: {view_name} has {cnt} rows for org={org_id}')
                    issues += cnt
                else:
                    views_checked += 1
    if views_checked > 0 or not any(table_exists(cur, v) for v in ['v_critical_identities', 'v_latest_identities']):
        print(f'    PASS: Views clean.')

    conn.close()

    # ══════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════
    print(f'\n  ══════════════════════════════════════════')
    print(f'  RESULT')
    print(f'  ══════════════════════════════════════════')
    if issues == 0:
        print(f'    ✓ CLEAN — org={org_id} fully removed. Zero remnants.')
    else:
        print(f'    ✗ {issues} issues found. See details above.')
        if not args.restart:
            sys.exit(1)

    # ══════════════════════════════════════════
    # RESTART (optional)
    # ══════════════════════════════════════════
    if not args.restart:
        print(f'\n  To restart services, re-run with --restart.\n')
        return

    print(f'\n  ══════════════════════════════════════════')
    print(f'  RESTART — Backend & Frontend')
    print(f'  ══════════════════════════════════════════')

    if not args.no_prompt:
        print(f'  This will kill and restart Flask (port 5001) and npm (port 3000).')
        print(f'  Continue? [y/N] ', end='', flush=True)
        if input().strip().lower() != 'y':
            print('  Skipped.\n')
            return

    # Kill existing
    print('\n  Stopping services...')
    kill_process('flask run --port 5001', 'Backend (Flask)')
    kill_process('react-scripts start', 'Frontend (React)')
    kill_process('node.*react-scripts', 'Frontend (Node)')
    time.sleep(2)

    # Start fresh
    print('\n  Starting services...')
    start_backend()

    # Wait for backend health
    print('    Waiting for backend health...')
    if wait_for_health(5001, timeout=30):
        print('    Backend healthy.')
    else:
        print('    WARNING: Backend health check timed out (30s).')

    start_frontend()
    time.sleep(3)

    print(f"""
  ══════════════════════════════════════════
  READY FOR FRESH ENROLLMENT
  ══════════════════════════════════════════

  Services restarted. Before re-enrolling:

  1. Clear browser:
     - Open DevTools → Application → Clear Storage
     - Or: Cmd+Shift+Delete → clear cookies + localStorage
       for localhost:3000

  2. Hard refresh: Cmd+Shift+R

  3. Enroll fresh via:
     Settings → Connectors → Add Connection
""")


if __name__ == '__main__':
    main()
