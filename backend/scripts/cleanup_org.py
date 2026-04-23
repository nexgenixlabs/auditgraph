#!/usr/bin/env python3
"""
Cleanup script to remove ALL data for a given organization.

Usage:
  python scripts/cleanup_org.py --org-id 8
  python scripts/cleanup_org.py --org-id 8 --dry-run
  python scripts/cleanup_org.py --org-id 8 --force

Requires: psycopg2, python-dotenv
DB credentials from ENV or .env.local (never hardcoded).
"""

import argparse
import os
import sys
import time

import psycopg2
from psycopg2.extras import RealDictCursor

# ---------------------------------------------------------------------------
# Load env
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env.local')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass  # dotenv optional — use env vars directly

# ---------------------------------------------------------------------------
# All org-scoped tables in safe FK-respecting delete order.
#
# Tuple: (table_name, org_column)
#   org_column = 'organization_id'  → WHERE organization_id = %s
#   org_column = 'target_organization_id' → WHERE target_organization_id = %s
#   org_column = 'org_id'           → WHERE org_id = %s
#   org_column = '@id'              → WHERE id = %s  (organizations table)
#
# Order: deepest FK children first, parents last.
# Many tables CASCADE from discovery_runs → identities, but we delete
# explicitly to show exact counts and avoid relying on CASCADE ordering.
# ---------------------------------------------------------------------------
DELETE_ORDER = [
    # ── Phase 1: Leaf tables (no children reference them) ──
    ('admin_audit_log',             'target_organization_id'),
    ('billing_audit_log',           'organization_id'),
    ('billing_events',              'organization_id'),
    ('campaign_audit_log',          'organization_id'),
    ('platform_audit_log',          'organization_id'),
    ('activity_log',                'organization_id'),
    ('notifications',               'organization_id'),
    ('copilot_conversations',       'organization_id'),
    ('copilot_queries',             'organization_id'),
    ('copilot_usage',               'org_id'),
    ('dashboard_preferences',       'organization_id'),
    ('api_keys',                    'organization_id'),
    ('settings',                    'organization_id'),
    ('sso_auth_codes',              'organization_id'),
    ('webhook_deliveries',          'organization_id'),
    ('webhooks',                    'organization_id'),
    ('saved_views',                 'organization_id'),
    ('custom_risk_rules',           'organization_id'),
    ('invoice_documents',           'organization_id'),
    ('invoices',                    'organization_id'),
    ('organization_billing_snapshots', 'organization_id'),
    ('organization_entitlements',   'organization_id'),
    ('organization_usage',          'organization_id'),
    ('organization_usage_counters', 'organization_id'),
    ('idempotency_keys',           'organization_id'),
    ('scan_schedules',              'organization_id'),
    ('tenant_health',               'organization_id'),
    ('tenant_posture_metrics',      'organization_id'),
    ('tenant_posture_scores',       'organization_id'),

    # ── Phase 2: Workload / telemetry tables ──
    ('workload_anomaly_events',     'organization_id'),
    ('workload_activity_stats',     'organization_id'),
    ('workload_signin_events',      'organization_id'),

    # ── Phase 3: SOAR & remediation action tables ──
    ('security_response_actions',   'organization_id'),
    ('soar_actions',                'organization_id'),
    ('soar_playbooks',              'organization_id'),
    ('auto_remediation_actions',    'organization_id'),
    ('remediation_actions',         'organization_id'),
    ('generated_remediations',      'organization_id'),
    ('fix_recommendations',         'organization_id'),

    # ── Phase 4: Anomaly / findings / analysis tables ──
    ('anomalies',                   'organization_id'),
    ('snapshot_alerts',             'organization_id'),
    ('finding_comments',            'organization_id'),
    ('risk_findings',               'organization_id'),
    ('resource_findings',           'organization_id'),
    ('spn_exposure_findings',       'organization_id'),
    ('app_reg_exposure_findings',   'organization_id'),
    ('orphaned_privileged_findings','organization_id'),
    ('graph_attack_findings',       'organization_id'),
    ('security_findings',           'organization_id'),
    ('security_events',             'organization_id'),
    ('identity_threat_events',      'organization_id'),
    ('identity_attack_incidents',   'organization_id'),
    ('identity_attack_predictions', 'organization_id'),
    ('attack_simulations',          'organization_id'),
    ('risk_forecasts',              'organization_id'),
    ('policy_recommendations',      'organization_id'),
    ('generated_policies',          'organization_id'),
    ('security_advisor_reports',    'organization_id'),

    # ── Phase 5: Compliance & governance ──
    ('review_evidence',             'organization_id'),
    ('review_assignments',          'organization_id'),
    ('campaign_reviews',            'organization_id'),
    ('governance_decisions',        'organization_id'),
    ('compliance_snapshots',        'organization_id'),
    ('access_reviews',              'organization_id'),
    ('access_review_campaigns',     'organization_id'),
    ('sa_attestations',             'organization_id'),
    ('approval_requests',           'organization_id'),

    # ── Phase 6: Reports ──
    ('report_outputs',              'organization_id'),
    ('report_runs',                 'organization_id'),
    ('reports',                     'organization_id'),

    # ── Phase 7: Graph & attack path tables ──
    ('graph_visualization_cache',   'organization_id'),
    ('graph_attack_findings',       'organization_id'),
    ('graph_edges',                 'organization_id'),
    ('graph_nodes',                 'organization_id'),
    ('attack_paths',                'organization_id'),
    ('blast_radius_results',        'organization_id'),

    # ── Phase 8: Identity-linked tables ──
    ('agent_delegations',           'organization_id'),
    ('agent_classifications',       'organization_id'),
    ('identity_access_history',     'organization_id'),
    ('identity_activity_events',    'organization_id'),
    ('identity_credentials',        'organization_id'),
    ('identity_group_members',      'organization_id'),
    ('identity_groups',             'organization_id'),
    ('identity_links',              'organization_id'),
    ('identity_risk_scores',        'organization_id'),
    ('identity_role_history',       'organization_id'),
    ('identity_subscription_access','organization_id'),
    ('risk_score_history',          'organization_id'),
    ('risk_summary',                'organization_id'),
    ('role_activity_log',           'organization_id'),
    ('ca_identity_coverage',        'organization_id'),
    ('agirs_scores',                'organization_id'),
    ('ai_audit_log',                'organization_id'),
    ('rbac_hygiene_scans',          'organization_id'),

    # ── Phase 9: Role / credential / permission tables ──
    ('sp_app_roles',                'organization_id'),
    ('sp_ownership',                'organization_id'),
    ('graph_api_permissions',       'organization_id'),
    ('role_assignments',            'organization_id'),
    ('entra_role_assignments',      'organization_id'),
    ('identity_roles',              'organization_id'),
    ('credentials',                 'organization_id'),
    ('pim_activations',             '@fk:identity_db_id:identities'),
    ('pim_eligible_assignments',    '@fk:identity_db_id:identities'),
    ('lineage_verdicts',            'organization_id'),

    # ── Phase 10: Group tables ──
    ('entra_group_memberships',     'organization_id'),
    ('entra_groups',                'organization_id'),

    # ── Phase 11: Resource tables ──
    ('resource_risk_history',       'organization_id'),
    ('azure_storage_accounts',      'organization_id'),
    ('azure_key_vaults',            'organization_id'),
    ('app_registrations',           'organization_id'),

    # ── Phase 12: Snapshot & drift ──
    ('snapshot_jobs',               'organization_id'),
    ('snapshot_runs',               'organization_id'),
    ('drift_reports',               'organization_id'),
    ('identity_list',               'organization_id'),
    ('human_identities',            'organization_id'),
    ('discovery_integrity_metrics', 'organization_id'),
    ('graph_snapshots',             '@fk:discovery_run_id:discovery_runs'),

    # ── Phase 13: CA policies ──
    ('ca_policies',                 'organization_id'),

    # ── Phase 14: Identities (CASCADE children already deleted above) ──
    ('identities',                  'organization_id'),

    # ── Phase 15: Discovery runs ──
    ('execution_runs',              'organization_id'),
    ('job_runs',                    'organization_id'),
    ('discovery_runs',              'organization_id'),

    # ── Phase 16: Cloud infrastructure ──
    ('cloud_subscriptions',         'organization_id'),
    ('cloud_connections',           'organization_id'),

    # ── Phase 17: Users ──
    ('users',                       'organization_id'),

    # ── Phase 18: Organization itself ──
    ('organizations',               '@id'),
]


def get_connection():
    """Connect to the database using env vars."""
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=int(os.environ.get('DB_PORT', '5434')),
        dbname=os.environ.get('DB_NAME', 'auditgraph'),
        user=os.environ.get('DB_ADMIN_USER', os.environ.get('DB_USER', 'auditgraph')),
        password=os.environ.get('DB_ADMIN_PASSWORD', os.environ.get('DB_PASSWORD', 'auditgraph')),
        sslmode=os.environ.get('DB_SSLMODE', 'prefer'),
    )


def table_exists(cursor, table_name):
    """Check if a table exists in the public schema."""
    cursor.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name = %s",
        (table_name,),
    )
    return cursor.fetchone() is not None


def column_exists(cursor, table_name, column_name):
    """Check if a column exists on a table."""
    cursor.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = %s AND column_name = %s",
        (table_name, column_name),
    )
    return cursor.fetchone() is not None


def resolve_org_column(org_column):
    """Parse org_column spec into (mode, col, parent_table).

    '@id'                          → ('direct', 'id', None)
    'organization_id'              → ('direct', 'organization_id', None)
    '@fk:child_col:parent_table'   → ('fk', 'child_col', 'parent_table')
    """
    if org_column == '@id':
        return ('direct', 'id', None)
    if org_column.startswith('@fk:'):
        parts = org_column.split(':')
        return ('fk', parts[1], parts[2])
    return ('direct', org_column, None)


def count_rows(cursor, table_name, org_column, org_id):
    """Count rows for an org in a table. Returns None if table/column doesn't exist."""
    if not table_exists(cursor, table_name):
        return None
    mode, col, parent_table = resolve_org_column(org_column)
    if not column_exists(cursor, table_name, col):
        return None

    if mode == 'fk':
        # FK chain: child.col IN (SELECT id FROM parent WHERE organization_id = %s)
        if not table_exists(cursor, parent_table):
            return None
        cursor.execute(
            f'SELECT COUNT(*) FROM "{table_name}" '
            f'WHERE "{col}" IN (SELECT id FROM "{parent_table}" WHERE organization_id = %s)',
            (org_id,),
        )
    else:
        cursor.execute(
            f'SELECT COUNT(*) FROM "{table_name}" WHERE "{col}" = %s',
            (org_id,),
        )
    return cursor.fetchone()[0]


def get_org_name(cursor, org_id):
    """Fetch the organization name. Returns None if not found."""
    cursor.execute("SELECT name FROM organizations WHERE id = %s", (org_id,))
    row = cursor.fetchone()
    return row[0] if row else None


def print_summary(counts, org_id, org_name):
    """Print the summary table of what will be deleted."""
    # Filter to tables that exist and have rows
    all_tables = [(t, c) for t, c in counts if c is not None]
    max_name = max(len(t) for t, _ in all_tables) if all_tables else 30
    max_name = max(max_name, 25)

    print()
    print(f'  {"Table":<{max_name}}   Count')
    print(f'  {"─" * max_name}   {"─" * 8}')
    for tbl, cnt in all_tables:
        marker = '' if cnt == 0 else ' ◀'
        print(f'  {tbl:<{max_name}}   {cnt:>6}{marker}')

    total = sum(c for _, c in all_tables)
    existing = sum(1 for _, c in all_tables if c > 0)
    skipped = sum(1 for t, c in counts if c is None)

    print(f'  {"─" * max_name}   {"─" * 8}')
    print(f'  {"TOTAL":<{max_name}}   {total:>6}')
    print()
    print(f'  Tables with data: {existing}')
    if skipped:
        print(f'  Tables not found (skipped): {skipped}')
    print(f'  Total rows to delete: {total}')
    print()
    print(f'  WARNING: This will permanently delete')
    print(f'  org "{org_name}" (id={org_id}) and ALL its data.')
    print(f'  This cannot be undone.')
    print()
    return total


def delete_all(conn, org_id, org_name):
    """Delete all org data in one transaction. Returns (deleted_counts, elapsed)."""
    t0 = time.time()
    cursor = conn.cursor()
    deleted = []

    # Disable immutability triggers that block DELETE on audit tables
    immutable_triggers = []
    for audit_table in ('activity_log', 'admin_audit_log', 'billing_audit_log',
                        'campaign_audit_log', 'platform_audit_log', 'billing_events'):
        if not table_exists(cursor, audit_table):
            continue
        cursor.execute("""
            SELECT tgname FROM pg_trigger
            WHERE tgrelid = %s::regclass AND tgenabled != 'D'
            AND tgname LIKE '%%immutable%%'
        """, (audit_table,))
        for row in cursor.fetchall():
            trigger_name = row[0]
            cursor.execute(f'ALTER TABLE "{audit_table}" DISABLE TRIGGER "{trigger_name}"')
            immutable_triggers.append((audit_table, trigger_name))
            print(f'    Disabled trigger {trigger_name} on {audit_table}')

    for table_name, org_column in DELETE_ORDER:
        if not table_exists(cursor, table_name):
            continue

        mode, col, parent_table = resolve_org_column(org_column)
        if not column_exists(cursor, table_name, col):
            continue

        if mode == 'fk':
            if not table_exists(cursor, parent_table):
                continue
            cursor.execute(
                f'DELETE FROM "{table_name}" '
                f'WHERE "{col}" IN (SELECT id FROM "{parent_table}" WHERE organization_id = %s)',
                (org_id,),
            )
        else:
            cursor.execute(
                f'DELETE FROM "{table_name}" WHERE "{col}" = %s',
                (org_id,),
            )
        count = cursor.rowcount
        if count > 0:
            deleted.append((table_name, count))
            print(f'    Deleted {count:>6} rows from {table_name}')

    # Re-enable immutability triggers
    for audit_table, trigger_name in immutable_triggers:
        cursor.execute(f'ALTER TABLE "{audit_table}" ENABLE TRIGGER "{trigger_name}"')
        print(f'    Re-enabled trigger {trigger_name} on {audit_table}')

    conn.commit()
    elapsed = time.time() - t0
    return deleted, elapsed


def verify_clean(cursor, org_id):
    """Verify nothing remains for this org. Returns list of (table, count) with remaining rows."""
    remaining = []
    for table_name, org_column in DELETE_ORDER:
        cnt = count_rows(cursor, table_name, org_column, org_id)
        if cnt is None:
            continue
        if cnt > 0:
            remaining.append((table_name, cnt))
            print(f'    WARNING  {table_name}: {cnt} rows remain')
        else:
            print(f'    OK  {table_name}: 0')
    return remaining


def check_orphans(cursor):
    """Check for orphaned records after deletion."""
    orphan_checks = [
        (
            'role_assignments',
            'identity_db_id',
            'identities',
            'id',
        ),
        (
            'agent_classifications',
            'identity_db_id',
            'identities',
            'id',
        ),
        (
            'entra_role_assignments',
            'identity_db_id',
            'identities',
            'id',
        ),
        (
            'credentials',
            'identity_db_id',
            'identities',
            'id',
        ),
        (
            'entra_group_memberships',
            'group_db_id',
            'entra_groups',
            'id',
        ),
        (
            'lineage_verdicts',
            'identity_id',
            'identities',
            'id',
        ),
        (
            'identities',
            'discovery_run_id',
            'discovery_runs',
            'id',
        ),
    ]

    total_orphans = 0
    for child_table, child_col, parent_table, parent_col in orphan_checks:
        if not table_exists(cursor, child_table) or not table_exists(cursor, parent_table):
            continue

        # Check column exists
        cursor.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = %s",
            (child_table, child_col),
        )
        if not cursor.fetchone():
            continue

        cursor.execute(f"""
            SELECT COUNT(*) FROM "{child_table}" c
            WHERE c."{child_col}" IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM "{parent_table}" p WHERE p."{parent_col}" = c."{child_col}"
            )
        """)
        cnt = cursor.fetchone()[0]
        if cnt > 0:
            print(f'    ORPHANED: {child_table}.{child_col} → {parent_table}: {cnt} rows')
            total_orphans += cnt
        else:
            print(f'    OK  {child_table}.{child_col} → {parent_table}: 0 orphans')

    return total_orphans


def clean_orphans(conn, cursor):
    """Delete any orphaned records found."""
    orphan_deletes = [
        ('role_assignments', 'identity_db_id', 'identities', 'id'),
        ('agent_classifications', 'identity_db_id', 'identities', 'id'),
        ('entra_role_assignments', 'identity_db_id', 'identities', 'id'),
        ('credentials', 'identity_db_id', 'identities', 'id'),
        ('entra_group_memberships', 'group_db_id', 'entra_groups', 'id'),
        ('lineage_verdicts', 'identity_id', 'identities', 'id'),
    ]
    total = 0
    for child_table, child_col, parent_table, parent_col in orphan_deletes:
        if not table_exists(cursor, child_table) or not table_exists(cursor, parent_table):
            continue
        cursor.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = %s",
            (child_table, child_col),
        )
        if not cursor.fetchone():
            continue
        cursor.execute(f"""
            DELETE FROM "{child_table}" c
            USING (
                SELECT c2.id FROM "{child_table}" c2
                WHERE c2."{child_col}" IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1 FROM "{parent_table}" p WHERE p."{parent_col}" = c2."{child_col}"
                )
            ) orphans
            WHERE c.id = orphans.id
        """)
        cnt = cursor.rowcount
        if cnt > 0:
            print(f'    Cleaned {cnt} orphans from {child_table}')
            total += cnt
    if total > 0:
        conn.commit()
    return total


def main():
    parser = argparse.ArgumentParser(
        description='Remove ALL data for a given organization.',
        epilog='Example: python scripts/cleanup_org.py --org-id 8',
    )
    parser.add_argument('--org-id', type=int, required=True, help='Organization ID to clean up')
    parser.add_argument('--dry-run', action='store_true', help='Show counts only, no deletion')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    args = parser.parse_args()

    org_id = args.org_id
    t_start = time.time()

    # ── Connect ──
    try:
        conn = get_connection()
        conn.autocommit = True  # read phase; switched to False for delete
    except Exception as e:
        print(f'ERROR: Cannot connect to database: {e}', file=sys.stderr)
        sys.exit(1)

    cursor = conn.cursor()

    # ── Verify org exists ──
    org_name = get_org_name(cursor, org_id)
    if not org_name:
        print(f'ERROR: Organization id={org_id} not found.', file=sys.stderr)
        conn.close()
        sys.exit(1)

    print(f'\n  Organization: "{org_name}" (id={org_id})')

    # ── Step 1: Count everything ──
    print('\n══════════════════════════════════════════')
    print('  STEP 1 — Inventory')
    print('══════════════════════════════════════════')
    counts = []
    for table_name, org_column in DELETE_ORDER:
        cnt = count_rows(cursor, table_name, org_column, org_id)
        counts.append((table_name, cnt))

    total = print_summary(counts, org_id, org_name)

    if total == 0:
        print('  Nothing to delete. Org has no data.')
        conn.close()
        sys.exit(0)

    if args.dry_run:
        print('  --dry-run: No changes made.')
        conn.close()
        sys.exit(0)

    # ── Confirm ──
    if not args.force:
        print(f'  Type the org name to confirm deletion: ', end='', flush=True)
        confirm = input().strip()
        if confirm != org_name:
            print(f'  Aborted. You typed "{confirm}", expected "{org_name}".')
            conn.close()
            sys.exit(1)

    # ── Step 2: Delete ──
    print('\n══════════════════════════════════════════')
    print('  STEP 2 — Deleting data')
    print('══════════════════════════════════════════')
    conn.autocommit = False  # wrap deletes in one transaction
    try:
        deleted, elapsed = delete_all(conn, org_id, org_name)
        total_deleted = sum(c for _, c in deleted)
        print(f'\n    Deleted {total_deleted} rows across {len(deleted)} tables in {elapsed:.1f}s')
    except Exception as e:
        print(f'\n  ERROR during deletion: {e}', file=sys.stderr)
        print('  Rolling back all changes...', file=sys.stderr)
        conn.rollback()
        conn.close()
        sys.exit(1)

    # ── Step 3: Verify ──
    conn.autocommit = True  # read-only phase
    cursor = conn.cursor()  # fresh cursor after commit
    print('\n══════════════════════════════════════════')
    print('  STEP 3 — Verify cleanup')
    print('══════════════════════════════════════════')
    remaining = verify_clean(cursor, org_id)
    if remaining:
        print(f'\n    WARNING: {len(remaining)} tables still have data!')
        for tbl, cnt in remaining:
            print(f'      {tbl}: {cnt} rows')
    else:
        print(f'\n    All tables clean.')

    # ── Step 4: Check orphans ──
    print('\n══════════════════════════════════════════')
    print('  STEP 4 — Check for orphaned records')
    print('══════════════════════════════════════════')
    orphan_count = check_orphans(cursor)
    if orphan_count > 0:
        print(f'\n    Found {orphan_count} orphaned records. Cleaning...')
        cleaned = clean_orphans(conn, cursor)
        print(f'    Cleaned {cleaned} orphaned records.')
    else:
        print(f'\n    No orphaned records found.')

    # ── Step 5: Post-cleanup reminder ──
    total_elapsed = time.time() - t_start
    print('\n══════════════════════════════════════════')
    print('  STEP 5 — Post-cleanup')
    print('══════════════════════════════════════════')
    print(f"""
  Database cleanup complete in {total_elapsed:.1f}s.

  Before re-enrolling, also clear:
  1. Browser: clear cookies + localStorage
     for localhost:3000
  2. Backend: restart Flask to clear
     any in-memory caches
     (cd backend && source venv/bin/activate
      ENV_FILE=.env.local python wsgi.py)
  3. Frontend: hard refresh (Cmd+Shift+R)

  Then enroll the org fresh via:
  Settings > Connectors > Add Connection
""")

    conn.close()
    sys.exit(0)


if __name__ == '__main__':
    main()
