#!/usr/bin/env python3
"""
Generate synthetic identities + role assignments at scale into a dedicated
perf-test org, then time the key API endpoints.

Designed to answer: "Can AuditGraph handle N identities?" with concrete
p50/p95 numbers for the next sales/investor conversation.

Usage:
  ./perf_seed_at_scale.py --org-id 99 --count 10000
  ./perf_seed_at_scale.py --org-id 99 --count 100000

The org-id MUST be a dedicated perf-test org. Defaults to 99. Will create
the org row + cloud_connection + discovery_run if missing.

DO NOT point at org=9 or org=3 (demo orgs) or any real customer org.

Composition (matches realistic enterprise distribution):
  60% service principals
  20% managed identities
  15% human users
   5% AI agents (subset of NHIs)

10x role assignments (~600K rows at 60K identities, 1M at 100K)
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras

NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc)

# Identity composition
COMPOSITION = [
    ('service_principal',         0.60),
    ('managed_identity_system',   0.15),
    ('managed_identity_user',     0.05),
    ('human_user',                0.15),
    ('guest',                     0.04),
    ('microsoft_internal',        0.01),
]

ROLES_BY_SCOPE = [
    ('Owner',                'subscription'),
    ('Contributor',          'subscription'),
    ('Reader',               'subscription'),
    ('Contributor',          'resource_group'),
    ('Reader',               'resource_group'),
    ('Key Vault Secrets User','resource'),
    ('Storage Blob Data Reader','resource'),
    ('Cognitive Services User','resource'),
]
ROLES_PER_IDENTITY_AVG = 10

# Subscription/RG/resource scope strings (~50 distinct subscriptions for realism)
N_SUBS = 50
SUBS = [f'/subscriptions/{i:08x}-aaaa-bbbb-cccc-{i:012x}' for i in range(N_SUBS)]


def ensure_perf_org(cursor, org_id: int):
    """Ensure the perf-test org + cloud_connection + discovery_run exist."""
    cursor.execute("SELECT 1 FROM organizations WHERE id = %s", (org_id,))
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO organizations (id, name, slug, plan, status, created_at)
            VALUES (%s, %s, %s, 'perf_test', 'active', NOW())
            ON CONFLICT (id) DO NOTHING
        """, (org_id, f'Perf Test Org {org_id}', f'perf-test-{org_id}'))
        print(f"  created organization id={org_id}", file=sys.stderr)

    cursor.execute("SELECT id FROM cloud_connections WHERE organization_id = %s LIMIT 1", (org_id,))
    row = cursor.fetchone()
    if not row:
        cursor.execute("""
            INSERT INTO cloud_connections
                (organization_id, cloud, connection_type, label, status, created_at)
            VALUES (%s, 'azure', 'service_principal', 'perf-test', 'connected', NOW())
            RETURNING id
        """, (org_id,))
        cc_id = cursor.fetchone()[0]
        print(f"  created cloud_connection id={cc_id}", file=sys.stderr)
    else:
        cc_id = row[0]

    cursor.execute("SELECT id FROM discovery_runs WHERE organization_id = %s ORDER BY id DESC LIMIT 1", (org_id,))
    row = cursor.fetchone()
    if row:
        return row[0]
    cursor.execute("""
        INSERT INTO discovery_runs (organization_id, cloud_connection_id, subscription_id,
                                     started_at, completed_at, status)
        VALUES (%s, %s, %s, NOW(), NOW(), 'completed') RETURNING id
    """, (org_id, cc_id, 'perf-test-sub-00000001'))
    return cursor.fetchone()[0]


def category_for_index(i: int) -> str:
    """Deterministic category based on a per-identity cumulative weight."""
    h = (i * 2654435761) % 1000   # cheap hash → [0, 1000)
    norm = h / 1000.0
    cum = 0.0
    for cat, w in COMPOSITION:
        cum += w
        if norm < cum: return cat
    return 'service_principal'


def seed_identities(cursor, org_id: int, run_id: int, count: int, batch_size: int = 5000) -> int:
    """Bulk insert N synthetic identities. Returns count inserted."""
    inserted = 0
    t0 = time.perf_counter()
    for batch_start in range(0, count, batch_size):
        rows = []
        for i in range(batch_start, min(batch_start + batch_size, count)):
            cat = category_for_index(i)
            risk_score = (i * 7919) % 100
            risk_level = 'critical' if risk_score >= 80 else 'high' if risk_score >= 60 else 'medium' if risk_score >= 40 else 'low'
            ident_id = f'perf-{org_id}-{cat}-{i:06d}'
            display = f'perf {cat} #{i}'
            itype = 'service_principal' if 'principal' in cat else 'managed_identity' if 'managed' in cat else 'user'
            rows.append((
                org_id, ident_id, display, cat, itype, 'azure',
                run_id, None,                                       # discovery_run_id, deleted_at
                risk_level, None, None, True, 'active'              # risk_level, owner, owner_status, enabled, activity
            ))
        psycopg2.extras.execute_batch(cursor, """
            INSERT INTO identities (organization_id, identity_id, display_name, identity_category,
                                     identity_type, source, discovery_run_id, deleted_at,
                                     risk_level, owner_display_name, owner_status, enabled, activity_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, rows, page_size=500)
        inserted += len(rows)
        if batch_start % (batch_size * 5) == 0:
            elapsed = time.perf_counter() - t0
            rate = inserted / elapsed if elapsed > 0 else 0
            print(f"  identities: {inserted}/{count}  ({rate:.0f}/sec)", file=sys.stderr)
    return inserted


def seed_role_assignments(cursor, org_id: int, run_id: int, identity_count: int,
                            avg_per_identity: int = ROLES_PER_IDENTITY_AVG,
                            batch_size: int = 10000) -> int:
    """For each identity, insert ~avg_per_identity role assignments."""
    # Load identity_ids → identity_db_ids map once
    cursor.execute("SELECT id, identity_id FROM identities WHERE organization_id = %s", (org_id,))
    id_map = cursor.fetchall()
    if not id_map:
        return 0
    rng = random.Random(42)
    total = 0
    rows: list[tuple] = []
    t0 = time.perf_counter()
    for db_id, ident_id in id_map:
        n_roles = max(1, int(rng.gauss(avg_per_identity, 3)))
        for _ in range(n_roles):
            role, scope_type = rng.choice(ROLES_BY_SCOPE)
            sub = rng.choice(SUBS)
            if scope_type == 'subscription':
                scope = sub
            elif scope_type == 'resource_group':
                scope = f'{sub}/resourceGroups/rg-{rng.randint(1, 30):03d}'
            else:
                scope = f'{sub}/resourceGroups/rg-{rng.randint(1, 30):03d}/providers/Microsoft.Storage/storageAccounts/sa{rng.randint(1, 100):04d}'
            rows.append((
                org_id, db_id, ident_id,
                role, scope, scope_type,
                'ServicePrincipal',
            ))
            if len(rows) >= batch_size:
                _flush_role_batch(cursor, rows)
                total += len(rows)
                rows.clear()
                if total % 50000 == 0:
                    elapsed = time.perf_counter() - t0
                    rate = total / elapsed if elapsed > 0 else 0
                    print(f"  role_assignments: {total}  ({rate:.0f}/sec)", file=sys.stderr)
    if rows:
        _flush_role_batch(cursor, rows)
        total += len(rows)
    return total


def _flush_role_batch(cursor, rows: list[tuple]):
    psycopg2.extras.execute_batch(cursor, """
        INSERT INTO role_assignments
            (organization_id, identity_db_id, principal_id,
             role_name, scope, scope_type, principal_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, rows, page_size=500)


def cleanup_perf_org(cursor, org_id: int):
    """Remove all perf-test data for clean re-seed. Tenant-isolated."""
    print(f"  cleaning prior perf data for org={org_id}…", file=sys.stderr)
    for tbl in ['role_assignments', 'pim_eligibility_state',
                 'pim_activation_observations', 'entra_role_activity']:
        try:
            cursor.execute(f"DELETE FROM {tbl} WHERE organization_id = %s", (org_id,))
        except psycopg2.errors.UndefinedTable:
            pass
    cursor.execute("DELETE FROM identities WHERE organization_id = %s", (org_id,))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--org-id', type=int, default=99, help='dedicated perf-test org (default: 99)')
    ap.add_argument('--count', type=int, default=10000, help='identity count to generate')
    ap.add_argument('--clean', action='store_true', help='delete existing perf data first')
    ap.add_argument('--db-host', default=os.getenv('DB_HOST', 'localhost'))
    ap.add_argument('--db-port', type=int, default=int(os.getenv('DB_PORT', '5434')))
    ap.add_argument('--db-name', default=os.getenv('DB_NAME', 'auditgraph'))
    ap.add_argument('--db-user', default=os.getenv('DB_ADMIN_USER', 'auditgraph'))
    ap.add_argument('--db-password', default=os.getenv('DB_ADMIN_PASSWORD', 'auditgraph'))
    ap.add_argument('--db-sslmode', default=os.getenv('DB_SSLMODE', 'disable'))
    args = ap.parse_args()

    if args.org_id in (1, 2, 3, 9):
        sys.exit(f"refusing to seed perf data into reserved org={args.org_id}")

    conn = psycopg2.connect(
        host=args.db_host, port=args.db_port, dbname=args.db_name,
        user=args.db_user, password=args.db_password, sslmode=args.db_sslmode,
    )
    cursor = conn.cursor()
    try:
        if args.clean:
            cleanup_perf_org(cursor, args.org_id)
            conn.commit()
        run_id = ensure_perf_org(cursor, args.org_id)
        conn.commit()
        print(f"  org={args.org_id}  discovery_run_id={run_id}", file=sys.stderr)

        t = time.perf_counter()
        n_identities = seed_identities(cursor, args.org_id, run_id, args.count)
        conn.commit()
        d_identities = time.perf_counter() - t

        t = time.perf_counter()
        n_roles = seed_role_assignments(cursor, args.org_id, run_id, args.count)
        conn.commit()
        d_roles = time.perf_counter() - t

        print(f"\n  done.", file=sys.stderr)
        print(f"  identities:       {n_identities:>8d}   {d_identities:6.1f}s   ({n_identities/d_identities:.0f}/sec)", file=sys.stderr)
        print(f"  role_assignments: {n_roles:>8d}   {d_roles:6.1f}s   ({n_roles/d_roles:.0f}/sec)", file=sys.stderr)
        print(f"  org_id={args.org_id}", file=sys.stderr)
    finally:
        cursor.close(); conn.close()


if __name__ == '__main__':
    main()
