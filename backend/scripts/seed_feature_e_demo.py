#!/usr/bin/env python3
"""
Seed Feature E Phase 2 demo personas — Entra Directory Role Activity.

3 personas, each demonstrating a different dormancy state:

  demo-feat-e-dormant-ga       → Global Administrator, dormant 120d → CRITICAL
  demo-feat-e-active-userAdmin → User Administrator,   active 3d ago → healthy
  demo-feat-e-recent-ca        → Conditional Access Admin, edit 14d ago → healthy

Idempotent. Safe to re-run.

Usage:
  ./seed_feature_e_demo.py --org-id 9              # local
  ./seed_feature_e_demo.py --org-id 3              # cloud-dev (via apply_cloud_migration)
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

import psycopg2

NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc)

PERSONAS = [
    {
        'identity_id':   'demo-feat-e-dormant-ga@auditgraph-demo.com',
        'display_name':  'Dormant Global Admin (Feature E demo)',
        'role_name':     'Global Administrator',
        'role_template_id': '62e90394-69f5-4237-9190-012177145e10',
        'assignment_principal_type': 'User',
        'last_action_at':         NOW - timedelta(days=120),       # 120d dormant
        'days_since_last_action': 120,
        'activities_30d':         0,
        'activities_90d':         0,
        'activity_bucket':        'dormant',
        'dormancy_band':          'high',
        'inferred_from':          'auditLogs',
        'inference_confidence':   'observed',
        'story': 'Global Admin standing grant with 0 actions observed in 120 days — CRITICAL dormant_directory_role_assignment finding',
    },
    {
        'identity_id':   'demo-feat-e-active-userAdmin@auditgraph-demo.com',
        'display_name':  'Active User Admin (Feature E demo)',
        'role_name':     'User Administrator',
        'role_template_id': 'fe930be7-5e62-47db-91af-98c3a49a38b1',
        'assignment_principal_type': 'User',
        'last_action_at':         NOW - timedelta(days=3),         # 3d ago
        'days_since_last_action': 3,
        'activities_30d':         28,                                # daily-ish
        'activities_90d':         84,
        'activity_bucket':        'daily',
        'dormancy_band':          'low',
        'inferred_from':          'auditLogs',
        'inference_confidence':   'observed',
        'story': 'Active User Admin with healthy daily activity pattern — no finding (healthy)',
    },
    {
        'identity_id':   'demo-feat-e-recent-ca@auditgraph-demo.com',
        'display_name':  'Recent Conditional Access Admin (Feature E demo)',
        'role_name':     'Conditional Access Administrator',
        'role_template_id': 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
        'assignment_principal_type': 'User',
        'last_action_at':         NOW - timedelta(days=14),        # 14d ago
        'days_since_last_action': 14,
        'activities_30d':         3,                                 # rare
        'activities_90d':         5,
        'activity_bucket':        'monthly',
        'dormancy_band':          'low',
        'inferred_from':          'auditLogs',
        'inference_confidence':   'observed',
        'story': 'CA Admin with monthly cadence — active and healthy',
    },
]


def get_or_create_identity(cursor, org_id: int, persona: dict, discovery_run_id: int) -> int:
    cursor.execute("""
        SELECT id FROM identities
         WHERE organization_id = %s AND identity_id = %s
         ORDER BY discovery_run_id DESC LIMIT 1
    """, (org_id, persona['identity_id']))
    row = cursor.fetchone()
    if row:
        return row[0]

    cursor.execute("""
        INSERT INTO identities
            (organization_id, identity_id, display_name, identity_category,
             identity_type, source, discovery_run_id, deleted_at,
             risk_level, owner_display_name, owner_status, enabled, activity_status)
        VALUES (%s, %s, %s, 'human_user',
                'human_user', 'entra_id', %s, NULL,
                'high', 'AuditGraph Demo Platform Team', 'resolved', TRUE, 'active')
        RETURNING id
    """, (org_id, persona['identity_id'], persona['display_name'], discovery_run_id))
    return cursor.fetchone()[0]


def latest_discovery_run(cursor, org_id: int) -> int:
    cursor.execute("""
        SELECT id FROM discovery_runs
         WHERE organization_id = %s ORDER BY id DESC LIMIT 1
    """, (org_id,))
    row = cursor.fetchone()
    if not row:
        raise RuntimeError(f"org {org_id} has no discovery_runs — seed cannot proceed")
    return row[0]


def seed(cursor, org_id: int, identity_db_id: int, persona: dict, discovery_run_id: int):
    cursor.execute("""
        INSERT INTO entra_role_activity
            (organization_id, discovery_run_id, identity_db_id, identity_id,
             role_name, role_template_id, assignment_principal_type,
             last_action_at, days_since_last_action,
             activities_30d, activities_90d,
             activity_bucket, dormancy_band,
             inferred_from, inference_confidence)
        VALUES (%s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (organization_id, identity_db_id, role_name)
        DO UPDATE SET
            last_action_at         = EXCLUDED.last_action_at,
            days_since_last_action = EXCLUDED.days_since_last_action,
            activities_30d         = EXCLUDED.activities_30d,
            activities_90d         = EXCLUDED.activities_90d,
            activity_bucket        = EXCLUDED.activity_bucket,
            dormancy_band          = EXCLUDED.dormancy_band,
            inferred_from          = EXCLUDED.inferred_from,
            inference_confidence   = EXCLUDED.inference_confidence,
            discovered_at          = NOW()
    """, (org_id, discovery_run_id, identity_db_id, persona['identity_id'],
          persona['role_name'], persona['role_template_id'],
          persona['assignment_principal_type'],
          persona['last_action_at'], persona['days_since_last_action'],
          persona['activities_30d'], persona['activities_90d'],
          persona['activity_bucket'], persona['dormancy_band'],
          persona['inferred_from'], persona['inference_confidence']))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--org-id', type=int, required=True)
    ap.add_argument('--db-host', default=os.getenv('DB_HOST', 'localhost'))
    ap.add_argument('--db-port', type=int, default=int(os.getenv('DB_PORT', '5434')))
    ap.add_argument('--db-name', default=os.getenv('DB_NAME', 'auditgraph'))
    ap.add_argument('--db-user', default=os.getenv('DB_ADMIN_USER', 'auditgraph'))
    ap.add_argument('--db-password', default=os.getenv('DB_ADMIN_PASSWORD', 'auditgraph'))
    ap.add_argument('--db-sslmode', default=os.getenv('DB_SSLMODE', 'disable'))
    args = ap.parse_args()

    # AG-PILOT-SAFETY (2026-06-07): demo-org allowlist guard
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _demo_safety import assert_safe_demo_org
    assert_safe_demo_org(args.org_id, script_name='seed_feature_e_demo.py')

    conn = psycopg2.connect(
        host=args.db_host, port=args.db_port, dbname=args.db_name,
        user=args.db_user, password=args.db_password, sslmode=args.db_sslmode,
    )
    cursor = conn.cursor()
    try:
        run_id = latest_discovery_run(cursor, args.org_id)
        print(f"  using discovery_run_id={run_id}", file=sys.stderr)
        for p in PERSONAS:
            identity_db_id = get_or_create_identity(cursor, args.org_id, p, run_id)
            seed(cursor, args.org_id, identity_db_id, p, run_id)
            print(f"  ✓ {p['identity_id']:50}  role={p['role_name']:35}  "
                  f"band={p['dormancy_band']}  days_since={p['days_since_last_action']}",
                  file=sys.stderr)
        conn.commit()
        print(f"\n  Seeded {len(PERSONAS)} Feature E demo personas for org={args.org_id}",
              file=sys.stderr)
    finally:
        cursor.close(); conn.close()


if __name__ == '__main__':
    main()
