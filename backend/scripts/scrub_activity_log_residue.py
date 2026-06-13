#!/usr/bin/env python3
"""scrub_activity_log_residue.py — pre-pilot data-integrity sweep (2026-06-11).

Cleans two classes of audit-log residue that leak across tenants when an org
is deleted outside of nuke_org.py and a future org gets the same id:

  1. ORPHAN ROWS — organization_id points to an org row that no longer exists.
     Pure dead data; was kept alive only by the SOC2 immutability trigger.

  2. ID-RECYCLED ROWS — organization_id matches a live org, but the row's
     created_at predates that org's created_at. These belonged to a prior
     occupant of the same id and now leak into the new tenant's activity feed.

Uses the same retention-job pattern as nuke_org.py: temporarily disables the
trg_activity_log_immutable trigger, performs the deletes, re-enables.
Records the sweep in admin_audit_log for SOC2 evidence.

Usage:
  python3 scripts/scrub_activity_log_residue.py            # dry-run (default)
  python3 scripts/scrub_activity_log_residue.py --apply    # actually delete
"""
import argparse
import os
import sys

import psycopg2


def get_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=int(os.environ.get('DB_PORT', '5434')),
        dbname=os.environ.get('DB_NAME', 'auditgraph'),
        user=os.environ.get('DB_ADMIN_USER', os.environ.get('DB_USER', 'auditgraph')),
        password=os.environ.get('DB_ADMIN_PASSWORD', os.environ.get('DB_PASSWORD', 'auditgraph')),
        sslmode=os.environ.get('DB_SSLMODE', 'prefer'),
    )


# Tables that carry organization_id + benefit from this sweep
TARGET_TABLES = ['activity_log', 'security_events']

# Audit tables whose immutability triggers must be temporarily disabled
IMMUTABLE_TABLES = ['activity_log']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true',
                    help='Actually delete (default is dry-run).')
    args = ap.parse_args()

    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()

    print('  ══════════════════════════════════════════')
    print('  Activity-log residue sweep (2026-06-11)')
    print('  ══════════════════════════════════════════')
    print(f'  Mode: {"APPLY" if args.apply else "DRY-RUN"}')
    print()

    orphan_counts = {}
    recycled_counts = {}
    for tbl in TARGET_TABLES:
        cur.execute(
            f"SELECT COUNT(*) FROM {tbl} "
            "WHERE organization_id IS NOT NULL "
            "AND organization_id NOT IN (SELECT id FROM organizations)"
        )
        orphan_counts[tbl] = cur.fetchone()[0]
        cur.execute(
            f"SELECT COUNT(*) FROM {tbl} a "
            "WHERE EXISTS (SELECT 1 FROM organizations o "
            "WHERE o.id = a.organization_id AND a.created_at < o.created_at)"
        )
        recycled_counts[tbl] = cur.fetchone()[0]
        print(f'    {tbl}: {orphan_counts[tbl]} orphan + {recycled_counts[tbl]} id-recycled')

    total = sum(orphan_counts.values()) + sum(recycled_counts.values())
    if total == 0:
        print()
        print('    Already clean. Nothing to do.')
        return

    if not args.apply:
        print()
        print('    Re-run with --apply to delete.')
        return

    try:
        # Record the sweep for SOC2 evidence.
        # 2026-06-12 — admin_audit_log columns are: admin_user_id, action,
        # target_user_id, target_organization_id, details, ip_address.
        # There is no actor_username column; the actor goes into details JSON.
        import json as _json
        cur.execute(
            """INSERT INTO admin_audit_log
               (target_organization_id, action, details, created_at)
               VALUES (1, 'activity_log_retention_sweep', %s::jsonb, NOW())""",
            (_json.dumps({
                "reason": "orphan + id-recycled scrub",
                "script": "scrub_activity_log_residue.py",
                "actor_username": os.environ.get('USER', 'unknown'),
            }),)
        )

        # Disable immutability triggers
        for tbl in IMMUTABLE_TABLES:
            cur.execute(
                """SELECT tgname FROM pg_trigger
                   WHERE tgrelid = %s::regclass AND tgenabled != 'D'
                   AND tgname LIKE '%%immutable%%'""",
                (tbl,)
            )
            for (trig,) in cur.fetchall():
                cur.execute(f'ALTER TABLE "{tbl}" DISABLE TRIGGER "{trig}"')

        # Delete orphans + recycled
        for tbl in TARGET_TABLES:
            cur.execute(
                f"DELETE FROM {tbl} "
                "WHERE organization_id IS NOT NULL "
                "AND organization_id NOT IN (SELECT id FROM organizations)"
            )
            d1 = cur.rowcount
            cur.execute(
                f"DELETE FROM {tbl} a USING organizations o "
                "WHERE a.organization_id = o.id "
                "AND a.created_at < o.created_at"
            )
            d2 = cur.rowcount
            print(f'    {tbl}: deleted {d1} orphan + {d2} recycled')

        # Re-enable triggers
        for tbl in IMMUTABLE_TABLES:
            cur.execute(
                """SELECT tgname FROM pg_trigger
                   WHERE tgrelid = %s::regclass AND tgenabled = 'D'
                   AND tgname LIKE '%%immutable%%'""",
                (tbl,)
            )
            for (trig,) in cur.fetchall():
                cur.execute(f'ALTER TABLE "{tbl}" ENABLE TRIGGER "{trig}"')

        conn.commit()
        print()
        print('    Done. Audit-log immutability re-enabled.')
    except Exception as e:
        conn.rollback()
        print(f'    FAILED, rolled back: {e}')
        sys.exit(1)
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    main()
