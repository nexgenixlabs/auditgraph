#!/usr/bin/env python3
"""
Script 1: Find and delete an organization and ALL its data.

Usage:
  python scripts/nuke_org.py                        # List all orgs
  python scripts/nuke_org.py --org-id 11             # Delete org 11
  python scripts/nuke_org.py --org-name glory        # Find org by name
  python scripts/nuke_org.py --org-id 11 --dry-run   # Preview only
  python scripts/nuke_org.py --org-id 11 --force      # Skip confirmation

After deletion, run:
  python scripts/verify_org_cleanup.py --org-id 11
"""

import argparse
import os
import sys
import time

import psycopg2

# ---------------------------------------------------------------------------
# Env
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env.local')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass


# ---------------------------------------------------------------------------
# EVERY org-scoped table, in safe FK-respecting delete order.
# Covers all 154 public tables as of May 2026.
#
# Format: (table_name, column_spec)
#   'organization_id'              → DELETE WHERE organization_id = %s
#   'target_organization_id'       → DELETE WHERE target_organization_id = %s
#   'org_id'                       → DELETE WHERE org_id = %s
#   'tenant_id'                    → DELETE WHERE tenant_id = %s
#   '@id'                          → DELETE WHERE id = %s (the org table itself)
#   '@fk:col:parent_table'         → DELETE WHERE col IN (SELECT id FROM parent WHERE organization_id = %s)
# ---------------------------------------------------------------------------
DELETE_ORDER = [
    # ── Phase 1: Audit / log tables ──
    ('admin_audit_log',              'target_organization_id'),
    ('billing_audit_log',            'organization_id'),
    ('billing_events',               'organization_id'),
    ('campaign_audit_log',           'organization_id'),
    ('platform_audit_log',           'organization_id'),
    ('activity_log',                 'organization_id'),
    ('ai_audit_log',                 'organization_id'),
    ('role_activity_log',            'organization_id'),
    ('notifications',                'organization_id'),

    # ── Phase 2: User-facing config / keys ──
    ('copilot_conversations',        'organization_id'),
    ('copilot_queries',              'organization_id'),
    ('copilot_usage',                'org_id'),
    ('dashboard_preferences',        'organization_id'),
    ('api_keys',                     'organization_id'),
    ('settings',                     'organization_id'),
    ('sso_auth_codes',               'organization_id'),
    ('saved_views',                  'organization_id'),
    ('custom_risk_rules',            'organization_id'),
    ('scan_schedules',               'organization_id'),

    # ── Phase 3: Webhooks ──
    ('webhook_deliveries',           'organization_id'),
    ('webhooks',                     'organization_id'),

    # ── Phase 4: Billing ──
    ('invoice_documents',            'organization_id'),
    ('invoices',                     'organization_id'),
    ('organization_billing_snapshots', 'organization_id'),
    ('organization_entitlements',    'organization_id'),
    ('organization_usage',           'organization_id'),
    ('organization_usage_counters',  'organization_id'),
    ('idempotency_keys',             'organization_id'),

    # ── Phase 5: Tenant health / posture ──
    ('tenant_health',                'organization_id'),
    ('tenant_posture_metrics',       'organization_id'),
    ('tenant_posture_scores',        'organization_id'),
    ('pipeline_stage_metrics',       'organization_id'),

    # ── Phase 6: Workload telemetry ──
    ('workload_anomaly_events',      'organization_id'),
    ('workload_activity_stats',      'organization_id'),
    ('workload_signin_events',       'organization_id'),
    ('workload_attributions',        'organization_id'),

    # ── Phase 7: SOAR & remediation ──
    ('security_response_actions',    'organization_id'),
    ('soar_actions',                 'organization_id'),
    ('soar_playbooks',               'organization_id'),
    ('auto_remediation_actions',     'organization_id'),
    ('remediation_actions',          'organization_id'),
    ('remediation_queue',            'organization_id'),
    ('generated_remediations',       'organization_id'),
    ('fix_recommendations',          'organization_id'),
    ('optimization_recommendations', 'organization_id'),

    # ── Phase 8: Anomalies / findings / analysis ──
    ('anomalies',                    'organization_id'),
    ('snapshot_alerts',              'organization_id'),
    ('finding_comments',             'organization_id'),
    ('risk_findings',                'organization_id'),
    ('resource_findings',            'organization_id'),
    ('spn_exposure_findings',        'organization_id'),
    ('app_reg_exposure_findings',    'organization_id'),
    ('orphaned_privileged_findings', 'organization_id'),
    ('graph_attack_findings',        'organization_id'),
    ('security_findings',            'organization_id'),
    ('security_events',              'organization_id'),
    ('identity_threat_events',       'organization_id'),
    ('identity_attack_incidents',    'organization_id'),
    ('identity_attack_predictions',  'organization_id'),
    ('attack_simulations',           'organization_id'),
    ('risk_forecasts',               'organization_id'),
    ('policy_recommendations',       'organization_id'),
    ('generated_policies',           'organization_id'),
    ('security_advisor_reports',     'organization_id'),
    ('privilege_drift_events',       'organization_id'),

    # ── Phase 9: Compliance & governance ──
    ('review_evidence',              'organization_id'),
    ('review_assignments',           'organization_id'),
    ('campaign_reviews',             'organization_id'),
    ('governance_decisions',         'organization_id'),
    ('compliance_snapshots',         'organization_id'),
    ('access_reviews',               'organization_id'),
    ('access_review_campaigns',      'organization_id'),
    ('sa_attestations',              'organization_id'),
    ('approval_requests',            'organization_id'),

    # ── Phase 10: Reports ──
    ('report_outputs',               'organization_id'),
    ('report_runs',                  'organization_id'),
    ('reports',                      'organization_id'),

    # ── Phase 11: Graph & attack path ──
    ('graph_visualization_cache',    'organization_id'),
    ('graph_edges',                  'organization_id'),
    ('graph_nodes',                  'organization_id'),
    ('attack_paths',                 'organization_id'),
    ('blast_radius_results',         'organization_id'),

    # ── Phase 12: Identity-linked tables ──
    ('agent_delegations',            'organization_id'),
    ('agent_classifications',        'organization_id'),
    ('identity_access_history',      'organization_id'),
    ('identity_activity_events',     'organization_id'),
    ('identity_arm_connections',     'organization_id'),
    ('identity_credentials',         'organization_id'),
    ('identity_exposures',           'organization_id'),
    ('identity_group_members',       'organization_id'),
    ('identity_groups',              'organization_id'),
    ('identity_links',               'organization_id'),
    ('identity_reachability',        'organization_id'),
    ('identity_risk_scores',         'organization_id'),
    ('identity_role_history',        'organization_id'),
    ('identity_subscription_access', 'organization_id'),
    ('risk_score_history',           'organization_id'),
    ('risk_summary',                 'organization_id'),
    ('ca_identity_coverage',         'organization_id'),
    ('agirs_scores',                 'organization_id'),
    ('rbac_hygiene_scans',           'organization_id'),

    # ── Phase 13: Role / credential / permission tables ──
    ('sp_app_roles',                 'organization_id'),
    ('sp_ownership',                 'organization_id'),
    ('graph_api_permissions',        'organization_id'),
    ('connector_permissions',        'organization_id'),
    ('role_assignments',             'organization_id'),
    ('entra_role_assignments',       'organization_id'),
    ('identity_roles',               'organization_id'),
    ('credentials',                  'organization_id'),
    ('federated_credentials',        'organization_id'),
    ('pim_activations',              '@fk:identity_db_id:identities'),
    ('pim_eligible_assignments',     '@fk:identity_db_id:identities'),
    ('lineage_verdicts',             'organization_id'),

    # ── Phase 14: Group tables ──
    ('entra_group_memberships',      'organization_id'),
    ('entra_groups',                 'organization_id'),

    # ── Phase 15: Resource tables ──
    ('resource_risk_history',        'organization_id'),
    ('discovered_resources',         'organization_id'),
    ('azure_storage_accounts',       'organization_id'),
    ('azure_key_vaults',             'organization_id'),
    ('app_registrations',            'organization_id'),

    # ── Phase 16: Snapshot & drift ──
    ('snapshot_jobs',                'organization_id'),
    ('snapshot_runs',                'organization_id'),
    ('drift_reports',                'organization_id'),
    ('identity_list',                'organization_id'),
    ('human_identities',             'organization_id'),
    ('discovery_integrity_metrics',  'organization_id'),
    ('graph_snapshots',              '@fk:discovery_run_id:discovery_runs'),

    # ── Phase 17: CA policies ──
    ('ca_policies',                  'organization_id'),

    # ── Phase 18: Identities ──
    ('identities',                   'organization_id'),

    # ── Phase 19: Discovery / execution runs ──
    ('execution_runs',               'organization_id'),
    ('job_runs',                     'organization_id'),
    ('discovery_runs',               'organization_id'),

    # ── Phase 20: Cloud infrastructure ──
    ('cloud_subscriptions',          'organization_id'),
    ('cloud_connections',            'organization_id'),

    # ── Phase 21: Users ──
    ('users',                        'organization_id'),

    # ── Phase 22: Organization itself (LAST) ──
    ('organizations',                '@id'),
]


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


def resolve(spec):
    """Parse column spec → (mode, column, parent_table)."""
    if spec == '@id':
        return ('direct', 'id', None)
    if spec.startswith('@fk:'):
        _, col, parent = spec.split(':')
        return ('fk', col, parent)
    return ('direct', spec, None)


def count_for_org(cur, table, spec, org_id):
    if not table_exists(cur, table):
        return None
    mode, col, parent = resolve(spec)
    if not col_exists(cur, table, col):
        return None
    if mode == 'fk':
        if not table_exists(cur, parent):
            return None
        cur.execute(
            f'SELECT COUNT(*) FROM "{table}" WHERE "{col}" IN '
            f'(SELECT id FROM "{parent}" WHERE organization_id = %s)',
            (org_id,),
        )
    else:
        cur.execute(f'SELECT COUNT(*) FROM "{table}" WHERE "{col}" = %s', (org_id,))
    return cur.fetchone()[0]


def list_orgs(cur):
    cur.execute("""
        SELECT o.id, o.name,
               (SELECT COUNT(*) FROM users u WHERE u.organization_id = o.id) as user_cnt,
               (SELECT COUNT(*) FROM discovery_runs d WHERE d.organization_id = o.id) as run_cnt,
               (SELECT COUNT(*) FROM identities i WHERE i.organization_id = o.id) as identity_cnt,
               (SELECT MAX(d.completed_at) FROM discovery_runs d
                WHERE d.organization_id = o.id AND d.status = 'completed') as last_scan
        FROM organizations o
        ORDER BY o.id
    """)
    rows = cur.fetchall()
    if not rows:
        print('\n  No organizations found.\n')
        return

    print(f'\n  {"ID":>4}  {"Name":<25}  {"Users":>5}  {"Runs":>5}  {"Identities":>10}  Last Scan')
    print(f'  {"─"*4}  {"─"*25}  {"─"*5}  {"─"*5}  {"─"*10}  {"─"*20}')
    for r in rows:
        last = str(r[5])[:19] if r[5] else '—'
        print(f'  {r[0]:>4}  {r[1]:<25}  {r[2]:>5}  {r[3]:>5}  {r[4]:>10}  {last}')
    print()


def find_org_by_name(cur, name):
    cur.execute(
        "SELECT id, name FROM organizations WHERE LOWER(name) LIKE %s ORDER BY id",
        (f'%{name.lower()}%',),
    )
    return cur.fetchall()


def main():
    parser = argparse.ArgumentParser(description='Find and delete an organization.')
    parser.add_argument('--org-id', type=int, help='Organization ID to delete')
    parser.add_argument('--org-name', type=str, help='Search org by name (partial match)')
    parser.add_argument('--dry-run', action='store_true', help='Preview only — no deletion')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    parser.add_argument('--list', action='store_true', help='List all organizations')
    args = parser.parse_args()

    conn = get_connection()
    conn.autocommit = True
    cur = conn.cursor()

    # ── List mode ──
    if args.list or (not args.org_id and not args.org_name):
        list_orgs(cur)
        if not args.org_id and not args.org_name:
            print('  Usage: python scripts/nuke_org.py --org-id <ID>')
            print('         python scripts/nuke_org.py --org-name <name>\n')
        conn.close()
        return

    # ── Find by name ──
    if args.org_name and not args.org_id:
        matches = find_org_by_name(cur, args.org_name)
        if not matches:
            print(f'\n  No org matching "{args.org_name}".\n')
            conn.close()
            sys.exit(1)
        if len(matches) > 1:
            print(f'\n  Multiple matches for "{args.org_name}":')
            for oid, oname in matches:
                print(f'    id={oid}  name="{oname}"')
            print(f'\n  Re-run with --org-id <ID>.\n')
            conn.close()
            sys.exit(1)
        args.org_id = matches[0][0]
        print(f'\n  Matched: id={matches[0][0]} name="{matches[0][1]}"')

    org_id = args.org_id

    # ── Verify org exists ──
    cur.execute("SELECT name FROM organizations WHERE id = %s", (org_id,))
    row = cur.fetchone()
    if not row:
        print(f'\n  ERROR: Organization id={org_id} not found.')
        print(f'  (It may already be deleted. Run verify_org_cleanup.py to check for remnants.)\n')
        conn.close()
        sys.exit(1)

    org_name = row[0]
    print(f'\n  Organization: "{org_name}" (id={org_id})')

    # ── Inventory ──
    print('\n  ══════════════════════════════════════════')
    print('  STEP 1 — Inventory')
    print('  ══════════════════════════════════════════')
    counts = []
    total = 0
    tables_with_data = 0
    for tbl, spec in DELETE_ORDER:
        cnt = count_for_org(cur, tbl, spec, org_id)
        counts.append((tbl, cnt))
        if cnt is not None and cnt > 0:
            total += cnt
            tables_with_data += 1
            print(f'    {tbl:<45} {cnt:>6} rows')

    print(f'\n    Total: {total} rows across {tables_with_data} tables')

    if total == 0:
        print('\n  Nothing to delete. Org is empty.\n')
        conn.close()
        return

    if args.dry_run:
        print('\n  --dry-run: No changes made.\n')
        conn.close()
        return

    # ── Confirm ──
    if not args.force:
        print(f'\n  ⚠ This will PERMANENTLY delete org "{org_name}" (id={org_id}) and ALL data.')
        print(f'  Type the org name to confirm: ', end='', flush=True)
        confirm = input().strip()
        if confirm.lower() != org_name.lower():
            print(f'  Aborted. Expected "{org_name}", got "{confirm}".\n')
            conn.close()
            sys.exit(1)

    # ── Delete ──
    print('\n  ══════════════════════════════════════════')
    print('  STEP 2 — Deleting')
    print('  ══════════════════════════════════════════')
    conn.autocommit = False
    t0 = time.time()

    try:
        # Disable immutable audit triggers
        for audit_tbl in ('activity_log', 'admin_audit_log', 'billing_audit_log',
                          'campaign_audit_log', 'platform_audit_log', 'billing_events'):
            if not table_exists(cur, audit_tbl):
                continue
            cur.execute("""
                SELECT tgname FROM pg_trigger
                WHERE tgrelid = %s::regclass AND tgenabled != 'D'
                AND tgname LIKE '%%immutable%%'
            """, (audit_tbl,))
            for trig_row in cur.fetchall():
                cur.execute(f'ALTER TABLE "{audit_tbl}" DISABLE TRIGGER "{trig_row[0]}"')

        deleted_total = 0
        for tbl, spec in DELETE_ORDER:
            if not table_exists(cur, tbl):
                continue
            mode, col, parent = resolve(spec)
            if not col_exists(cur, tbl, col):
                continue

            if mode == 'fk':
                if not table_exists(cur, parent):
                    continue
                cur.execute(
                    f'DELETE FROM "{tbl}" WHERE "{col}" IN '
                    f'(SELECT id FROM "{parent}" WHERE organization_id = %s)',
                    (org_id,),
                )
            else:
                cur.execute(f'DELETE FROM "{tbl}" WHERE "{col}" = %s', (org_id,))

            cnt = cur.rowcount
            if cnt > 0:
                print(f'    Deleted {cnt:>6} from {tbl}')
                deleted_total += cnt

        # Re-enable triggers
        for audit_tbl in ('activity_log', 'admin_audit_log', 'billing_audit_log',
                          'campaign_audit_log', 'platform_audit_log', 'billing_events'):
            if not table_exists(cur, audit_tbl):
                continue
            cur.execute("""
                SELECT tgname FROM pg_trigger
                WHERE tgrelid = %s::regclass AND tgenabled = 'D'
                AND tgname LIKE '%%immutable%%'
            """, (audit_tbl,))
            for trig_row in cur.fetchall():
                cur.execute(f'ALTER TABLE "{audit_tbl}" ENABLE TRIGGER "{trig_row[0]}"')

        conn.commit()
        elapsed = time.time() - t0
        print(f'\n    Done. {deleted_total} rows deleted in {elapsed:.1f}s')

    except Exception as e:
        print(f'\n  ERROR: {e}')
        print('  Rolling back — no data was deleted.')
        conn.rollback()
        conn.close()
        sys.exit(1)

    # ── Quick verify ──
    conn.autocommit = True
    cur = conn.cursor()
    print('\n  ══════════════════════════════════════════')
    print('  STEP 3 — Quick verify')
    print('  ══════════════════════════════════════════')
    remaining = 0
    for tbl, spec in DELETE_ORDER:
        cnt = count_for_org(cur, tbl, spec, org_id)
        if cnt and cnt > 0:
            print(f'    WARNING: {tbl} still has {cnt} rows')
            remaining += cnt
    if remaining == 0:
        print('    All clean.')
    else:
        print(f'\n    {remaining} rows remain! Run verify_org_cleanup.py for deep scan.')

    print(f'\n  Next step:')
    print(f'    python scripts/verify_org_cleanup.py --org-id {org_id}\n')
    conn.close()


if __name__ == '__main__':
    main()
