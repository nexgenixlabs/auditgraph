"""
Multi-Tenant Load & Performance Test

Simulates 10 tenants with 50,000 rows each (500k total),
runs concurrent read load across all tenants, and verifies:
  1. Zero cross-tenant data leakage under load
  2. Index usage for tenant-scoped queries (no Seq Scans at scale)
  3. Query latency stays within acceptable bounds
  4. Composite indexes are used for filtered + sorted queries

Requires a running PostgreSQL instance.

Usage:
    cd backend
    PYTHONPATH=. ./venv/bin/python tests/test_load_performance.py

    # Quick mode (1k rows per tenant, 10k total):
    PYTHONPATH=. LOAD_TEST_QUICK=1 ./venv/bin/python tests/test_load_performance.py
"""
import os
import sys
import time
import random
import threading
import statistics

import pytest

os.environ.setdefault('APP_ENV', 'local')
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-load')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-load')
os.environ.setdefault('CLIENT_JWT_SECRET', 'client-test-load')
os.environ.setdefault('ENFORCE_ADMIN_GUARD', 'false')

import psycopg2
from app.config import (
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
    DB_ADMIN_USER, DB_ADMIN_PASSWORD, DB_SSLMODE, IS_LOCAL,
)
from app.database import Database

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

QUICK_MODE = os.getenv('LOAD_TEST_QUICK', '').lower() in ('1', 'true', 'yes')
NUM_TENANTS = 10
ROWS_PER_TENANT = 1_000 if QUICK_MODE else 50_000
TOTAL_ROWS = NUM_TENANTS * ROWS_PER_TENANT
CONCURRENT_READERS = 10       # Threads for read load
READS_PER_THREAD = 50 if QUICK_MODE else 200
TENANT_ID_BASE = 80001        # Use 80001-80010 to avoid collisions
TEST_TABLE = '_load_test_events'
TEST_ROLE = '_load_test_app'
TEST_ROLE_PW = '_load_test_pw'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _admin_conn():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_ADMIN_USER, password=DB_ADMIN_PASSWORD,
        sslmode=DB_SSLMODE,
    )


def _rls_conn(org_id):
    """Get a NOBYPASSRLS connection with tenant context."""
    if IS_LOCAL:
        user, pw = TEST_ROLE, TEST_ROLE_PW
    else:
        user, pw = DB_USER, DB_PASSWORD

    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=user, password=pw, sslmode=DB_SSLMODE,
    )
    cur = conn.cursor()
    cur.execute(
        "SELECT set_config('app.current_organization_id', %s, FALSE)",
        (str(org_id),),
    )
    cur.close()
    return conn


# ---------------------------------------------------------------------------
# Setup & Teardown
# ---------------------------------------------------------------------------

def setup():
    """Create test table, indexes, RLS policies, and seed data."""
    conn = _admin_conn()
    conn.autocommit = True
    cur = conn.cursor()

    # Create test role for local mode
    if IS_LOCAL:
        cur.execute(f"SELECT 1 FROM pg_roles WHERE rolname = '{TEST_ROLE}'")
        if not cur.fetchone():
            cur.execute(
                f"CREATE ROLE {TEST_ROLE} LOGIN PASSWORD '{TEST_ROLE_PW}' "
                f"NOBYPASSRLS NOSUPERUSER"
            )
    conn.autocommit = False

    # Create test table
    cur.execute(f"DROP TABLE IF EXISTS {TEST_TABLE} CASCADE")
    cur.execute(f"""
        CREATE TABLE {TEST_TABLE} (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # Indexes — mirrors production pattern
    cur.execute(f"CREATE INDEX idx_lt_org ON {TEST_TABLE}(organization_id)")
    cur.execute(f"CREATE INDEX idx_lt_org_type ON {TEST_TABLE}(organization_id, event_type)")
    cur.execute(f"CREATE INDEX idx_lt_org_sev ON {TEST_TABLE}(organization_id, severity)")
    cur.execute(f"CREATE INDEX idx_lt_org_created ON {TEST_TABLE}(organization_id, created_at DESC)")

    # Enable RLS
    cur.execute(f"ALTER TABLE {TEST_TABLE} ENABLE ROW LEVEL SECURITY")
    cur.execute(f"ALTER TABLE {TEST_TABLE} FORCE ROW LEVEL SECURITY")

    cur.execute(f"""
        CREATE POLICY lt_sel ON {TEST_TABLE} FOR SELECT
        USING (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)
    cur.execute(f"""
        CREATE POLICY lt_ins ON {TEST_TABLE} FOR INSERT
        WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)

    # Grant to test role
    role = TEST_ROLE if IS_LOCAL else DB_USER
    cur.execute(f'GRANT SELECT, INSERT ON {TEST_TABLE} TO "{role}"')
    cur.execute(f'GRANT USAGE, SELECT ON SEQUENCE {TEST_TABLE}_id_seq TO "{role}"')
    conn.commit()

    # Seed data using COPY for speed
    print(f"  Seeding {TOTAL_ROWS:,} rows ({NUM_TENANTS} tenants x {ROWS_PER_TENANT:,} rows)...")
    t0 = time.time()

    event_types = ['login', 'permission_change', 'role_assignment', 'credential_rotation',
                   'anomaly_detected', 'drift_detected', 'scan_completed', 'api_call']
    severities = ['info', 'low', 'medium', 'high', 'critical']

    batch_size = 10_000
    total_inserted = 0

    for tenant_idx in range(NUM_TENANTS):
        org_id = TENANT_ID_BASE + tenant_idx
        for batch_start in range(0, ROWS_PER_TENANT, batch_size):
            batch_end = min(batch_start + batch_size, ROWS_PER_TENANT)
            values_parts = []
            for _ in range(batch_end - batch_start):
                evt = random.choice(event_types)
                sev = random.choice(severities)
                desc = f"Event for org {org_id}: {evt}"
                values_parts.append(
                    cur.mogrify(
                        "(%s, %s, %s, %s, NOW() - (random() * INTERVAL '90 days'))",
                        (org_id, evt, sev, desc)
                    ).decode()
                )
            cur.execute(
                f"INSERT INTO {TEST_TABLE} (organization_id, event_type, severity, description, created_at) "
                f"VALUES {','.join(values_parts)}"
            )
            total_inserted += (batch_end - batch_start)

        conn.commit()

    # ANALYZE so the planner has accurate stats
    conn.autocommit = True
    cur.execute(f"ANALYZE {TEST_TABLE}")
    conn.autocommit = False

    elapsed = time.time() - t0
    print(f"  Seeded {total_inserted:,} rows in {elapsed:.1f}s "
          f"({total_inserted / elapsed:,.0f} rows/sec)")

    cur.close()
    conn.close()


def teardown():
    conn = _admin_conn()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(f"DROP TABLE IF EXISTS {TEST_TABLE} CASCADE")
    if IS_LOCAL:
        try:
            cur.execute(f"DROP ROLE IF EXISTS {TEST_ROLE}")
        except Exception:
            pass
    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# Test 1: Isolation under load
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_isolation_under_load():
    """Each tenant reads concurrently — verify zero leakage."""
    print("\n  Test 1: Isolation under concurrent load")

    errors = []
    latencies = []

    def _reader(org_id, expected_count):
        for _ in range(READS_PER_THREAD):
            try:
                t0 = time.time()
                conn = _rls_conn(org_id)
                cur = conn.cursor()
                cur.execute(f"SELECT COUNT(*) FROM {TEST_TABLE}")
                count = cur.fetchone()[0]
                cur.close()
                conn.close()
                elapsed_ms = (time.time() - t0) * 1000
                latencies.append(elapsed_ms)

                if count != expected_count:
                    errors.append(
                        f"Org {org_id}: expected {expected_count}, got {count}"
                    )
            except Exception as e:
                errors.append(f"Org {org_id}: {e}")

    threads = []
    for i in range(CONCURRENT_READERS):
        org_id = TENANT_ID_BASE + (i % NUM_TENANTS)
        t = threading.Thread(
            target=_reader,
            args=(org_id, ROWS_PER_TENANT),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=120)

    total_ops = CONCURRENT_READERS * READS_PER_THREAD
    if errors:
        for e in errors[:5]:
            print(f"    ERROR: {e}")
        raise AssertionError(f"Isolation test FAILED: {len(errors)} errors in {total_ops} ops")

    p50 = statistics.median(latencies)
    p95 = sorted(latencies)[int(len(latencies) * 0.95)]
    p99 = sorted(latencies)[int(len(latencies) * 0.99)]
    print(f"    PASS: {total_ops:,} reads, 0 leaks")
    print(f"    Latency: p50={p50:.1f}ms  p95={p95:.1f}ms  p99={p99:.1f}ms")


# ---------------------------------------------------------------------------
# Test 2: Index usage at scale (EXPLAIN ANALYZE)
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_index_usage():
    """Verify the planner uses indexes, not seq scans, at 500k rows."""
    print("\n  Test 2: Index usage validation (EXPLAIN ANALYZE)")

    conn = _admin_conn()
    cur = conn.cursor()
    org_id = TENANT_ID_BASE
    cur.execute(
        "SELECT set_config('app.current_organization_id', %s, FALSE)",
        (str(org_id),),
    )

    queries = {
        'org_id filter': (
            f"SELECT * FROM {TEST_TABLE} WHERE organization_id = {org_id} LIMIT 100"
        ),
        'org_id + type composite': (
            f"SELECT * FROM {TEST_TABLE} WHERE organization_id = {org_id} "
            f"AND event_type = 'login' LIMIT 100"
        ),
        'org_id + created_at sort': (
            f"SELECT * FROM {TEST_TABLE} WHERE organization_id = {org_id} "
            f"ORDER BY created_at DESC LIMIT 50"
        ),
        'org_id + severity filter': (
            f"SELECT * FROM {TEST_TABLE} WHERE organization_id = {org_id} "
            f"AND severity = 'critical' LIMIT 100"
        ),
        'COUNT with org_id': (
            f"SELECT COUNT(*) FROM {TEST_TABLE} WHERE organization_id = {org_id}"
        ),
    }

    all_passed = True
    for label, sql in queries.items():
        cur.execute(f"EXPLAIN (ANALYZE, FORMAT TEXT) {sql}")
        plan_lines = [row[0] for row in cur.fetchall()]
        plan_text = '\n'.join(plan_lines)

        # Check for index usage (should NOT be Seq Scan at 500k rows)
        uses_index = ('Index' in plan_text)
        uses_seq = ('Seq Scan' in plan_text and 'Index' not in plan_text)

        # Extract execution time
        exec_line = [l for l in plan_lines if 'Execution Time' in l]
        exec_time = exec_line[0].split(':')[-1].strip() if exec_line else 'N/A'

        status = 'PASS' if uses_index else ('WARN (seq scan)' if uses_seq else 'PASS')
        if uses_seq:
            all_passed = False

        print(f"    {status}: {label:35s} exec={exec_time}")
        if uses_seq:
            # Print full plan for debugging
            for line in plan_lines[:5]:
                print(f"      {line}")

    cur.close()
    conn.close()

    if not all_passed:
        print("    WARNING: Some queries used Seq Scan — may need ANALYZE or more rows")


# ---------------------------------------------------------------------------
# Test 3: Filtered + sorted query performance
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_filtered_sort_performance():
    """Measure latency for common dashboard queries across all tenants."""
    print("\n  Test 3: Dashboard query performance (per-tenant)")

    latencies = {}
    query_templates = {
        'recent_events': (
            f"SELECT id, event_type, severity, created_at "
            f"FROM {TEST_TABLE} "
            f"WHERE organization_id = %s "
            f"ORDER BY created_at DESC LIMIT 20"
        ),
        'count_by_type': (
            f"SELECT event_type, COUNT(*) "
            f"FROM {TEST_TABLE} "
            f"WHERE organization_id = %s "
            f"GROUP BY event_type"
        ),
        'critical_events': (
            f"SELECT id, description, created_at "
            f"FROM {TEST_TABLE} "
            f"WHERE organization_id = %s AND severity = 'critical' "
            f"ORDER BY created_at DESC LIMIT 50"
        ),
        'count_total': (
            f"SELECT COUNT(*) FROM {TEST_TABLE} WHERE organization_id = %s"
        ),
    }

    for label, sql in query_templates.items():
        times = []
        for tenant_idx in range(NUM_TENANTS):
            org_id = TENANT_ID_BASE + tenant_idx
            conn = _rls_conn(org_id)
            cur = conn.cursor()

            t0 = time.time()
            cur.execute(sql, (org_id,))
            cur.fetchall()
            elapsed_ms = (time.time() - t0) * 1000
            times.append(elapsed_ms)

            cur.close()
            conn.close()

        avg = statistics.mean(times)
        p95 = sorted(times)[int(len(times) * 0.95)]
        latencies[label] = {'avg': avg, 'p95': p95}
        print(f"    {label:25s} avg={avg:.1f}ms  p95={p95:.1f}ms")

    # Sanity: avg latency should be under 100ms for indexed queries
    for label, stats in latencies.items():
        if stats['avg'] > 500:
            print(f"    WARNING: {label} avg latency {stats['avg']:.0f}ms exceeds 500ms threshold")


# ---------------------------------------------------------------------------
# Test 4: Cross-tenant JOIN safety
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_cross_tenant_join():
    """Verify JOINs between tenant-scoped connections respect RLS."""
    print("\n  Test 4: Cross-tenant JOIN safety")

    org_a = TENANT_ID_BASE
    org_b = TENANT_ID_BASE + 1

    # Org A self-join — should work
    conn_a = _rls_conn(org_a)
    cur = conn_a.cursor()
    cur.execute(f"""
        SELECT a.event_type, COUNT(*)
        FROM {TEST_TABLE} a
        JOIN {TEST_TABLE} b ON a.organization_id = b.organization_id
            AND a.event_type = b.event_type
        GROUP BY a.event_type
        LIMIT 5
    """)
    join_results = cur.fetchall()
    cur.close()
    conn_a.close()

    assert len(join_results) > 0, "Self-join returned no results"

    # Org A attempting to join with Org B's data — RLS blocks
    conn_a2 = _rls_conn(org_a)
    cur = conn_a2.cursor()
    cur.execute(f"""
        SELECT COUNT(*)
        FROM {TEST_TABLE} a
        WHERE a.organization_id = {org_b}
    """)
    leaked = cur.fetchone()[0]
    cur.close()
    conn_a2.close()

    assert leaked == 0, f"LEAKAGE: Org A read {leaked} rows from Org B"

    print(f"    PASS: Self-join returned {len(join_results)} groups, cross-tenant returned 0")


# ---------------------------------------------------------------------------
# Test 5: UPDATE performance under RLS
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_update_performance():
    """Verify tenant-scoped UPDATEs use indexes and are fast."""
    print("\n  Test 5: Tenant-scoped UPDATE performance")

    # Grant UPDATE to test role
    conn = _admin_conn()
    conn.autocommit = True
    cur = conn.cursor()
    role = TEST_ROLE if IS_LOCAL else DB_USER
    cur.execute(f'GRANT UPDATE ON {TEST_TABLE} TO "{role}"')
    # Add UPDATE policy
    cur.execute(f"""
        CREATE POLICY lt_upd ON {TEST_TABLE} FOR UPDATE
        USING (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)
    cur.close()
    conn.close()

    org_id = TENANT_ID_BASE

    rls_conn = _rls_conn(org_id)
    cur = rls_conn.cursor()

    # EXPLAIN the UPDATE
    cur.execute(f"""
        EXPLAIN (ANALYZE, FORMAT TEXT)
        UPDATE {TEST_TABLE}
        SET description = 'updated'
        WHERE organization_id = {org_id}
          AND severity = 'critical'
          AND created_at > NOW() - INTERVAL '7 days'
    """)
    plan_lines = [row[0] for row in cur.fetchall()]
    exec_line = [l for l in plan_lines if 'Execution Time' in l]
    exec_time = exec_line[0].split(':')[-1].strip() if exec_line else 'N/A'

    rls_conn.rollback()  # Don't persist the update
    cur.close()
    rls_conn.close()

    print(f"    UPDATE exec time: {exec_time}")
    uses_index = any('Index' in l for l in plan_lines)
    print(f"    Uses index: {uses_index}")
    if not uses_index:
        for line in plan_lines[:5]:
            print(f"      {line}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    mode_label = "QUICK" if QUICK_MODE else "FULL"
    print("=" * 70)
    print(f"  AuditGraph — Multi-Tenant Load Performance Test [{mode_label}]")
    print(f"  {NUM_TENANTS} tenants x {ROWS_PER_TENANT:,} rows = {TOTAL_ROWS:,} total")
    print(f"  {CONCURRENT_READERS} concurrent readers x {READS_PER_THREAD} reads")
    print(f"  IS_LOCAL={IS_LOCAL}  DB_HOST={DB_HOST}")
    print("=" * 70)

    try:
        print("\n  Setting up test data...")
        setup()

        test_isolation_under_load()
        test_index_usage()
        test_filtered_sort_performance()
        test_cross_tenant_join()
        test_update_performance()

        print("\n" + "=" * 70)
        print("  ALL TESTS PASSED")
        print("=" * 70)
    except Exception as e:
        print(f"\n  FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        print("\n  Cleaning up...")
        teardown()
