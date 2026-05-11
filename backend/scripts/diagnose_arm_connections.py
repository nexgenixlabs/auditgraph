#!/usr/bin/env python3
"""
ARM Connection Pipeline Diagnostic Script

Diagnoses why "Last 3 Connections" shows "Discovery pending" after a scan
by checking all failure points in the ARM data pipeline.

Usage:
    cd /Users/sangabattula/projects/auditgraph/backend
    source venv/bin/activate
    python scripts/diagnose_arm_connections.py --org_id 2
"""

import argparse
import os
import re
import sys

import psycopg2
import psycopg2.extras


DB_CONFIG = {
    "host": "localhost",
    "port": 5434,
    "dbname": "auditgraph",
    "user": "auditgraph",
    "password": "auditgraph",
}

REQUIRED_TABLES = ["identity_arm_connections", "arm_activity_events", "identities"]

ARM_SEARCH_PATTERNS = [
    r"INSERT\s+INTO\s+identity_arm_connections",
    r"INSERT\s+INTO\s+arm_activity_events",
    r"arm_connection",
    r"source_ip",
    r"last_connection",
]

BACKEND_APP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"
)


def connect():
    return psycopg2.connect(**DB_CONFIG)


def check_1_table_existence(cursor):
    """Verify required tables exist in the DB schema."""
    print("\n[CHECK 1] Table Existence")
    try:
        cursor.execute(
            """
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name IN %s
            """,
            (tuple(REQUIRED_TABLES),),
        )
        found = {row[0] for row in cursor.fetchall()}
        for t in REQUIRED_TABLES:
            if t in found:
                print(f"  \u2705 {t:<30s} \u2014 exists")
            else:
                print(f"  \u274c {t:<30s} \u2014 MISSING")
        return found
    except Exception as e:
        print(f"  [CHECK 1] ERROR: {e}")
        return set()


def check_2_raw_row_counts(cursor, existing_tables):
    """Raw row counts for ARM tables (no joins)."""
    print("\n[CHECK 2] Raw Row Counts")
    counts = {}
    for t in ["identity_arm_connections", "arm_activity_events"]:
        if t not in existing_tables:
            print(f"  {t:<30s}: SKIPPED (table missing)")
            counts[t] = None
            continue
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {t}")  # noqa: S608 — diagnostic script, table name from constant
            cnt = cursor.fetchone()[0]
            flag = " \u2190 pipeline not writing" if cnt == 0 else ""
            print(f"  {t:<30s}: {cnt} rows{flag}")
            counts[t] = cnt
        except Exception as e:
            print(f"  {t:<30s}: ERROR \u2014 {e}")
            cursor.connection.rollback()
            counts[t] = None
    return counts


def check_3_join_integrity(cursor, existing_tables):
    """Check if identity_db_id in identity_arm_connections matches identities.id."""
    print("\n[CHECK 3] Join Integrity")
    if "identity_arm_connections" not in existing_tables:
        print("  SKIPPED \u2014 identity_arm_connections table missing")
        return
    try:
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(i.id) AS joined_ok
            FROM identity_arm_connections ae
            LEFT JOIN identities i ON i.id = ae.identity_db_id
            """
        )
        row = cursor.fetchone()
        total, joined_ok = row[0], row[1]
        failed = total - joined_ok
        print(f"  Total ARM rows    : {total}")
        print(f"  Joined OK         : {joined_ok}")
        if failed == 0:
            print(f"  Join FAILED       : {failed}  \u2705")
        else:
            print(
                f"  Join FAILED       : {failed}  \u274c  identity_db_id does not match identities.id"
            )
    except Exception as e:
        print(f"  [CHECK 3] ERROR: {e}")
        cursor.connection.rollback()


def check_4_org_scope(cursor, org_id, existing_tables):
    """Check which org_ids have ARM data vs the requested org_id."""
    print("\n[CHECK 4] Org Scope")
    if "identity_arm_connections" not in existing_tables:
        print("  SKIPPED \u2014 identity_arm_connections table missing")
        return
    try:
        cursor.execute(
            """
            SELECT
                i.organization_id,
                COUNT(*) AS arm_rows
            FROM identity_arm_connections ae
            JOIN identities i ON i.id = ae.identity_db_id
            GROUP BY i.organization_id
            ORDER BY arm_rows DESC
            """
        )
        rows = cursor.fetchall()
        print(f"  Requested org_id : {org_id}")
        if not rows:
            print("  No ARM data for ANY org \u274c")
        else:
            print("  Orgs with ARM data:")
            found_requested = False
            for r in rows:
                oid, cnt = r[0], r[1]
                marker = ""
                if oid == org_id:
                    found_requested = True
                    if cnt == 0:
                        marker = " \u2190 your org has none \u274c"
                elif cnt > 0:
                    marker = " \u2190 data exists but for DIFFERENT org"
                print(f"    org_id={oid}  \u2192  {cnt} rows{marker}")
            if not found_requested:
                print(
                    f"  DIAGNOSIS: No ARM rows joined to org_id={org_id} at all \u274c"
                )
    except Exception as e:
        print(f"  [CHECK 4] ERROR: {e}")
        cursor.connection.rollback()


def check_5_arm_scan_completed(cursor, org_id, existing_tables):
    """Simulate the backend EXISTS query for arm_scan_completed."""
    print("\n[CHECK 5] arm_scan_completed Query Result")
    if "identity_arm_connections" not in existing_tables:
        print("  SKIPPED \u2014 identity_arm_connections table missing")
        return
    try:
        cursor.execute(
            """
            SELECT EXISTS(
                SELECT 1 FROM identity_arm_connections ae
                JOIN identities i ON i.id = ae.identity_db_id
                WHERE i.organization_id = %s
            ) AS arm_scan_completed
            """,
            (org_id,),
        )
        result = cursor.fetchone()[0]
        status = "\u2705" if result else "\u274c"
        print(f"  org_id={org_id}  \u2192  arm_scan_completed = {str(result).upper()}  {status}")
        if not result:
            print(
                '  This is why the UI shows "Discovery pending" even after scan'
            )
    except Exception as e:
        print(f"  [CHECK 5] ERROR: {e}")
        cursor.connection.rollback()


def check_6_collector_discovery():
    """Scan backend Python source for ARM write targets."""
    print("\n[CHECK 6] ARM Collector Discovery")
    compiled = [(p, re.compile(p, re.IGNORECASE)) for p in ARM_SEARCH_PATTERNS]
    hits = []  # list of (filepath_relative, line_no, pattern, line_text)

    for dirpath, _dirnames, filenames in os.walk(BACKEND_APP_DIR):
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, os.path.dirname(BACKEND_APP_DIR))
            try:
                with open(fpath, "r", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        for label, rx in compiled:
                            if rx.search(line):
                                hits.append((rel, lineno, label, line.rstrip()))
            except Exception:
                continue

    if hits:
        # Group by pattern
        by_pattern = {}
        for rel, lineno, pattern, text in hits:
            by_pattern.setdefault(pattern, []).append((rel, lineno, text))
        for pattern, matches in by_pattern.items():
            print(f"  Pattern: {pattern}")
            for rel, lineno, text in matches:
                print(f"    {rel}  line {lineno}")
            print()
    else:
        print(
            "  \u274c No ARM-related INSERT or reference found in any .py file"
        )
        print(
            "     ARM data is NEVER written by the pipeline \u2014 table is always empty"
        )


def print_diagnosis(existing_tables, counts):
    """Print root cause summary based on all checks."""
    print()
    print("\u2550" * 54)
    print("  ARM CONNECTION PIPELINE \u2014 ROOT CAUSE DIAGNOSIS")
    print("\u2550" * 54)

    issues = []

    iac_count = counts.get("identity_arm_connections")
    if iac_count is not None and iac_count == 0:
        issues.append(
            "ISSUE: Pipeline never wrote to identity_arm_connections\n"
            "  \u2192 FIX: Find actual write target from CHECK 6 and\n"
            "         update check_arm_scan_completed() query to match"
        )

    if "identity_arm_connections" not in existing_tables:
        issues.append(
            "ISSUE: identity_arm_connections table does not exist\n"
            "  \u2192 FIX: Run schema migration or ensure _ensure_identity_arm_connections_table() is called"
        )

    if not issues:
        issues.append(
            "No obvious pipeline break detected from row counts.\n"
            "  Review CHECK 3 (join integrity) and CHECK 4 (org scope) above\n"
            "  for org-mismatch or FK issues."
        )

    for issue in issues:
        print(f"\n  {issue}")

    print()
    print("\u2550" * 54)
    print("  RECOMMENDED NEXT STEP:")
    if iac_count is not None and iac_count == 0:
        print(
            "  Run a discovery scan with ARM activity collection enabled,\n"
            "  then re-run this diagnostic to confirm rows appear."
        )
    else:
        print(
            "  Verify the scan's org_id matches the org_id you're querying\n"
            "  in the UI (CHECK 4 shows which orgs have data)."
        )
    print("\u2550" * 54)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Diagnose ARM connection pipeline failures"
    )
    parser.add_argument("--org_id", type=int, default=2, help="Organization ID to check (default: 2)")
    args = parser.parse_args()

    print(f"ARM Connection Pipeline Diagnostics  (org_id={args.org_id})")
    print("=" * 54)

    try:
        conn = connect()
    except Exception as e:
        print(f"\n\u274c Cannot connect to database: {e}")
        sys.exit(1)

    cursor = conn.cursor()

    try:
        existing = check_1_table_existence(cursor)
        counts = check_2_raw_row_counts(cursor, existing)
        check_3_join_integrity(cursor, existing)
        check_4_org_scope(cursor, args.org_id, existing)
        check_5_arm_scan_completed(cursor, args.org_id, existing)
        check_6_collector_discovery()
        print_diagnosis(existing, counts)
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
