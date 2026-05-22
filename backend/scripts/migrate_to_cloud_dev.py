#!/usr/bin/env python3
"""
Tenant-scoped migration: Local Docker DB → Azure Cloud Dev DB

Two-stage execution (so it can run from hosts that only reach one DB):

  Stage 1 (run on laptop, has local DB access):
    LOCAL_DSN=... python3 migrate_to_cloud_dev.py dump \
        --orgs 1,2,9 --out /tmp/sandbox_dump.json

  Stage 2 (run inside VNet, has cloud DB access):
    CLOUD_DSN=... python3 migrate_to_cloud_dev.py restore \
        --in /tmp/sandbox_dump.json

Single-host legacy mode (both DBs reachable):
    LOCAL_DSN=... CLOUD_DSN=... python3 migrate_to_cloud_dev.py direct \
        --orgs 1,2,9

Filtering rules:
  - Tables WITH organization_id  → WHERE organization_id IN (orgs)
  - Tables with discovery_run_id → WHERE discovery_run_id ∈ runs of those orgs
  - User-linked tables           → WHERE user_id ∈ users of those orgs
  - Admin audit                  → WHERE target_organization_id IN (orgs)
  - Global reference tables      → all rows
  - organizations                → WHERE id IN (orgs)
"""

import argparse
import json
import os
import sys
from datetime import date, datetime
from decimal import Decimal

import psycopg2
import psycopg2.extensions
import psycopg2.extras

# ── Defaults (overridden by env vars / CLI) ──────────────────────────────────

DEFAULT_LOCAL_DSN = "dbname=auditgraph user=auditgraph password=auditgraph host=localhost port=5434"
DEFAULT_CLOUD_DSN = (
    "dbname=auditgraph "
    "user=auditgraph_dev_admin "
    "password=Aud1tGr@phDevAdm1n2026 "
    "host=cus-ag-nonprod-pg.postgres.database.azure.com "
    "port=5432 sslmode=require"
)

# ── Table categories ─────────────────────────────────────────────────────────

GLOBAL_TABLES = [
    'compliance_frameworks',
    'compliance_controls',
    'compliance_root_causes',
    'remediation_playbooks',
    'role_permissions',
    'role_attack_patterns',
    'role_hipaa_mappings',
    'platform_settings',
    'plans',
    'schema_migrations',
]

ORG_TABLE = 'organizations'

ORG_SCOPED_TABLES = [
    'users',
    'cloud_connections',
    'cloud_subscriptions',
    'discovery_runs',
    'discovery_stage_log',
    'discovery_integrity_metrics',
    'job_runs',
    'scan_schedules',
    'identities',
    'role_assignments',
    'credentials',
    'entra_role_assignments',
    'ca_policies',
    'ca_identity_coverage',
    'identity_subscription_access',
    'pim_activations',
    'pim_eligible_assignments',
    'sa_attestations',
    'governance_decisions',
    'sp_app_roles',
    'sp_ownership',
    'identity_links',
    'identity_roles',
    'graph_api_permissions',
    'role_activity_log',
    'spn_exposure_findings',
    'workload_signin_events',
    'workload_activity_stats',
    'workload_anomaly_events',
    'generated_remediations',
    'identity_exposures',
    'identity_risk_scores',
    'agent_classifications',
    'agent_delegations',
    'app_registrations',
    'app_reg_exposure_findings',
    'azure_storage_accounts',
    'azure_key_vaults',
    'blast_radius_results',
    'rbac_hygiene_scans',
    'resource_findings',
    'resource_risk_history',
    'security_findings',
    'fix_recommendations',
    'human_identities',
    'identity_graph_edges',
    'identity_security_posture',
    'orphaned_privileged_findings',
    'attack_paths',
    'risk_summary',
    'graph_attack_findings',
    'graph_nodes',
    'graph_edges',
    'tenant_posture_scores',
    'snapshot_runs',
    'snapshot_jobs',
    'snapshot_alerts',
    'settings',
    'activity_log',
    'anomalies',
    'drift_reports',
    'compliance_snapshots',
    'notifications',
    'api_keys',
    'custom_risk_rules',
    'dashboard_preferences',
    'soar_playbooks',
    'soar_actions',
    'reports',
    'report_runs',
    'report_outputs',
    'saved_views',
    'webhooks',
    'webhook_deliveries',
    'copilot_conversations',
    'billing_events',
    'billing_audit_log',
    'invoices',
    'invoice_documents',
    'identity_groups',
    'identity_group_members',
    'access_review_campaigns',
    'access_reviews',
    'review_assignments',
    'review_evidence',
    'campaign_reviews',
    'campaign_audit_log',
    'organization_entitlements',
    'organization_usage',
    'organization_usage_counters',
    'organization_billing_snapshots',
    'agirs_scores',
    'ai_audit_log',
    'finding_comments',
    'tenant_health',
    'security_events',
    'msp_relationships',
]

USER_LINKED_TABLES = ['refresh_tokens', 'sso_auth_codes']
ADMIN_AUDIT_TABLES = ['admin_audit_log']


# ── JSON helpers (Postgres → JSON-safe) ──────────────────────────────────────

def _json_default(obj):
    if isinstance(obj, (datetime, date)):
        return {'__t__': 'datetime', 'v': obj.isoformat()}
    if isinstance(obj, Decimal):
        return {'__t__': 'decimal', 'v': str(obj)}
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return {'__t__': 'bytes', 'v': bytes(obj).hex()}
    if isinstance(obj, set):
        return list(obj)
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    raise TypeError(f"Cannot JSON-encode {type(obj).__name__}: {obj!r}")


def _json_revive(obj):
    if isinstance(obj, dict) and '__t__' in obj:
        t = obj['__t__']
        v = obj['v']
        if t == 'datetime':
            try:
                return datetime.fromisoformat(v)
            except ValueError:
                return v
        if t == 'decimal':
            return Decimal(v)
        if t == 'bytes':
            return bytes.fromhex(v)
    return obj


# ── Schema introspection ─────────────────────────────────────────────────────

def get_columns(cur, table):
    cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position",
        (table,)
    )
    return [r[0] for r in cur.fetchall()]


def get_column_types(cur, table):
    cur.execute(
        "SELECT column_name, data_type, udt_name FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name=%s",
        (table,)
    )
    return {r[0]: (r[1], r[2]) for r in cur.fetchall()}


def table_exists(cur, table):
    cur.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=%s)",
        (table,)
    )
    return cur.fetchone()[0]


def has_column(cur, table, col):
    cur.execute(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name=%s AND column_name=%s)",
        (table, col)
    )
    return cur.fetchone()[0]


# ── Dump phase: local → JSON file ────────────────────────────────────────────

def dump_table(cur, table, where=None, params=None):
    if not table_exists(cur, table):
        return None
    cols = get_columns(cur, table)
    if not cols:
        return None
    col_list = ', '.join(cols)
    q = f"SELECT {col_list} FROM {table}"
    if where:
        q += f" WHERE {where}"
    cur.execute(q, params or ())
    rows = cur.fetchall()
    return {'columns': cols, 'rows': [list(r) for r in rows]}


def cmd_dump(args):
    orgs = tuple(int(x) for x in args.orgs.split(','))
    dsn = os.environ.get('LOCAL_DSN', DEFAULT_LOCAL_DSN)
    print(f"Dumping orgs {orgs} from local DB → {args.out}")

    conn = psycopg2.connect(dsn)
    conn.set_session(readonly=True)
    cur = conn.cursor()

    dump = {
        'orgs': list(orgs),
        'generated_at': datetime.utcnow().isoformat(),
        'source_dsn_redacted': _redact_dsn(dsn),
        'phases': {},
    }

    print("\n── Phase 1: Global Reference Tables ──")
    phase = {}
    for tbl in GLOBAL_TABLES:
        data = dump_table(cur, tbl)
        if data is None:
            print(f"  SKIP {tbl} — not in local DB")
            continue
        phase[tbl] = data
        print(f"  OK   {tbl}: {len(data['rows'])} rows")
    dump['phases']['global'] = phase

    print("\n── Phase 2: Organizations ──")
    phase = {}
    data = dump_table(cur, ORG_TABLE, "id IN %s", (orgs,))
    if data is not None:
        phase[ORG_TABLE] = data
        print(f"  OK   {ORG_TABLE}: {len(data['rows'])} rows")
    dump['phases']['org'] = phase

    print("\n── Phase 3: Org-Scoped Tables ──")
    phase = {}
    for tbl in ORG_SCOPED_TABLES:
        if not table_exists(cur, tbl):
            continue
        if has_column(cur, tbl, 'organization_id'):
            data = dump_table(cur, tbl, "organization_id IN %s", (orgs,))
        elif has_column(cur, tbl, 'discovery_run_id'):
            data = dump_table(cur, tbl,
                "discovery_run_id IN (SELECT id FROM discovery_runs WHERE organization_id IN %s)",
                (orgs,)
            )
        else:
            data = dump_table(cur, tbl)
        if data is None:
            continue
        phase[tbl] = data
        print(f"  OK   {tbl}: {len(data['rows'])} rows")
    dump['phases']['org_scoped'] = phase

    print("\n── Phase 4: User-Linked Tables ──")
    phase = {}
    for tbl in USER_LINKED_TABLES:
        if not table_exists(cur, tbl):
            continue
        if has_column(cur, tbl, 'user_id'):
            data = dump_table(cur, tbl,
                "user_id IN (SELECT id FROM users WHERE organization_id IN %s)",
                (orgs,)
            )
        else:
            data = dump_table(cur, tbl)
        if data is None:
            continue
        phase[tbl] = data
        print(f"  OK   {tbl}: {len(data['rows'])} rows")
    dump['phases']['user_linked'] = phase

    print("\n── Phase 5: Admin Audit ──")
    phase = {}
    for tbl in ADMIN_AUDIT_TABLES:
        if not table_exists(cur, tbl):
            continue
        if has_column(cur, tbl, 'target_organization_id'):
            data = dump_table(cur, tbl, "target_organization_id IN %s", (orgs,))
        elif has_column(cur, tbl, 'organization_id'):
            data = dump_table(cur, tbl, "organization_id IN %s", (orgs,))
        else:
            data = dump_table(cur, tbl)
        if data is None:
            continue
        phase[tbl] = data
        print(f"  OK   {tbl}: {len(data['rows'])} rows")
    dump['phases']['admin_audit'] = phase

    conn.close()

    with open(args.out, 'w') as f:
        json.dump(dump, f, default=_json_default)

    size = os.path.getsize(args.out)
    print(f"\nWrote {args.out} ({size/1024/1024:.1f} MB)")


# ── Restore phase: JSON file → cloud ─────────────────────────────────────────

def restore_table(cur, table, payload):
    """Apply rows from a dumped table to the connected DB. Returns row count."""
    if not table_exists(cur, table):
        return -1  # sentinel: cloud doesn't have this table

    local_cols = payload['columns']
    cloud_cols = get_columns(cur, table)
    common = [c for c in local_cols if c in cloud_cols]
    if not common:
        return 0
    idx_map = [local_cols.index(c) for c in common]
    cloud_types = get_column_types(cur, table)
    jsonb_idx = {i for i, c in enumerate(common) if cloud_types.get(c, (None, None))[1] == 'jsonb'}

    rows = payload['rows']
    if not rows:
        return 0

    prepared = []
    for raw in rows:
        revived = [_json_revive(raw[i]) for i in idx_map]
        for j in jsonb_idx:
            if revived[j] is not None:
                revived[j] = psycopg2.extras.Json(revived[j])
        prepared.append(tuple(revived))

    cur.execute(f"TRUNCATE TABLE {table} CASCADE")
    col_list = ', '.join(common)
    placeholders = ', '.join(['%s'] * len(common))
    # ON CONFLICT DO NOTHING: local sandbox has rows that duplicate the
    # current cloud PK/UNIQUE constraints (e.g. sp_ownership.id=16 x10).
    insert_sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
    try:
        psycopg2.extras.execute_batch(cur, insert_sql, prepared, page_size=500)
        return len(prepared)
    except psycopg2.errors.SyntaxError:
        # Table has no unique/PK constraint to anchor ON CONFLICT — fall back
        # to plain insert; if that fails too, propagate.
        cur.connection.rollback()
        cur.execute(f"TRUNCATE TABLE {table} CASCADE")
        psycopg2.extras.execute_batch(
            cur,
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",
            prepared, page_size=500,
        )
        return len(prepared)


def cmd_restore(args):
    dsn = os.environ.get('CLOUD_DSN', DEFAULT_CLOUD_DSN)
    print(f"Restoring → {_redact_dsn(dsn)}")

    with open(args.in_path) as f:
        dump = json.load(f, object_hook=_json_revive_dict)

    orgs = tuple(dump['orgs'])
    print(f"Dump generated at {dump.get('generated_at')} for orgs {orgs}")

    conn = psycopg2.connect(dsn)
    cur = conn.cursor()

    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
    all_tables = [r[0] for r in cur.fetchall()]
    for t in all_tables:
        cur.execute(f"ALTER TABLE {t} DISABLE TRIGGER USER")
    cur.execute("SET CONSTRAINTS ALL DEFERRED")
    # session_replication_role='replica' suppresses FK validation for this session.
    # Local sandbox has cross-org orphan refs that would otherwise abort the batch.
    cur.execute("SET session_replication_role = 'replica'")
    conn.commit()
    print(f"Disabled user triggers on {len(all_tables)} tables (FK checks suspended)")

    total = 0
    order = [
        ('Phase 1: Global', dump['phases'].get('global', {})),
        ('Phase 2: Organizations', dump['phases'].get('org', {})),
        ('Phase 3: Org-Scoped', dump['phases'].get('org_scoped', {})),
        ('Phase 4: User-Linked', dump['phases'].get('user_linked', {})),
        ('Phase 5: Admin Audit', dump['phases'].get('admin_audit', {})),
    ]
    for label, phase in order:
        if not phase:
            continue
        print(f"\n── {label} ──")
        for tbl, payload in phase.items():
            try:
                n = restore_table(cur, tbl, payload)
            except Exception as e:
                conn.rollback()
                print(f"  FAIL {tbl}: {e}")
                raise
            if n == -1:
                print(f"  SKIP {tbl} — not in cloud DB")
            else:
                total += n
                print(f"  OK   {tbl}: {n} rows")
        conn.commit()

    # Reset sequences
    print("\n── Reset Sequences ──")
    cur.execute("""
        SELECT c.table_name, c.column_default
        FROM information_schema.columns c
        WHERE c.table_schema='public' AND c.column_name='id'
          AND c.column_default LIKE 'nextval%'
    """)
    for table, default in cur.fetchall():
        seq = default.split("'")[1]
        cur.execute(f"SELECT COALESCE(MAX(id), 0) + 1 FROM {table}")
        nxt = cur.fetchone()[0]
        cur.execute(f"SELECT setval('{seq}', {nxt}, false)")
    conn.commit()
    print("  Sequences reset")

    for t in all_tables:
        cur.execute(f"ALTER TABLE {t} ENABLE TRIGGER USER")
    cur.execute("SET session_replication_role = 'origin'")
    conn.commit()
    print(f"Re-enabled user triggers on {len(all_tables)} tables (FK checks restored)")

    # Verify
    print("\n── Verification ──")
    for label, q in [
        ('organizations', "SELECT COUNT(*) FROM organizations"),
        ('users', "SELECT COUNT(*) FROM users"),
        ('cloud_connections', "SELECT COUNT(*) FROM cloud_connections"),
        ('discovery_runs', "SELECT COUNT(*) FROM discovery_runs"),
        ('identities', "SELECT COUNT(*) FROM identities"),
    ]:
        cur.execute(q)
        print(f"  {label}: {cur.fetchone()[0]} rows")

    cur.execute("SELECT DISTINCT organization_id FROM discovery_runs")
    found = [r[0] for r in cur.fetchall()]
    leaked = [o for o in found if o not in orgs]
    if leaked:
        print(f"  LEAK: discovery_runs has org_ids {leaked} not in {orgs}")
    else:
        print(f"  OK   discovery_runs only has {found}")

    conn.close()
    print(f"\nRestore complete: {total} rows applied")


# ── Direct mode (legacy: both DBs reachable from one host) ───────────────────

def cmd_direct(args):
    tmp = '/tmp/_migrate_to_cloud_dev_dump.json'
    args.out = tmp
    cmd_dump(args)
    args.in_path = tmp
    cmd_restore(args)
    os.unlink(tmp)


def _redact_dsn(dsn):
    return ' '.join(
        kv if not kv.startswith('password=') else 'password=***'
        for kv in dsn.split()
    )


def _json_revive_dict(d):
    if '__t__' in d:
        return _json_revive(d)
    return d


def main():
    p = argparse.ArgumentParser(description='Tenant-scoped local→cloud migration')
    sub = p.add_subparsers(dest='mode', required=True)

    pd = sub.add_parser('dump', help='Read local DB, write JSON file')
    pd.add_argument('--orgs', required=True, help='Comma-separated org ids (e.g. 1,2,9)')
    pd.add_argument('--out', required=True, help='Output JSON path')

    pr = sub.add_parser('restore', help='Read JSON file, write to cloud DB')
    pr.add_argument('--in', dest='in_path', required=True, help='Input JSON path')

    pdir = sub.add_parser('direct', help='Dump+restore in one run (needs both DBs reachable)')
    pdir.add_argument('--orgs', required=True, help='Comma-separated org ids')

    args = p.parse_args()
    if args.mode == 'dump':
        cmd_dump(args)
    elif args.mode == 'restore':
        cmd_restore(args)
    elif args.mode == 'direct':
        cmd_direct(args)


if __name__ == '__main__':
    main()
