"""
Connection Pool Throughput Benchmark

Measures connection pool performance under concurrent multi-tenant load:
  1. Pool vs. direct connection throughput comparison
  2. Connection saturation behavior (what happens when pool is exhausted)
  3. p50/p95/p99 latency under sustained load
  4. Tenant isolation correctness under pool pressure
  5. Pool checkout/return overhead measurement

Requires a running PostgreSQL instance.

Usage:
    cd backend
    PYTHONPATH=. ./venv/bin/python tests/test_throughput_benchmark.py

    # Quick mode (fewer operations):
    PYTHONPATH=. BENCH_QUICK=1 ./venv/bin/python tests/test_throughput_benchmark.py
"""
import os
import sys
import time
import random
import threading
import statistics
from collections import defaultdict

os.environ.setdefault('APP_ENV', 'local')
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-bench')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-bench')
os.environ.setdefault('CLIENT_JWT_SECRET', 'client-test-bench')
os.environ.setdefault('ENFORCE_ADMIN_GUARD', 'false')
os.environ.setdefault('DB_POOL_ENABLED', 'true')
os.environ.setdefault('DB_POOL_MIN', '2')
os.environ.setdefault('DB_POOL_MAX', '20')

import psycopg2
from app.config import (
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
    DB_ADMIN_USER, DB_ADMIN_PASSWORD, DB_SSLMODE, IS_LOCAL,
    DB_POOL_ENABLED, DB_POOL_MIN, DB_POOL_MAX,
)
from app.database import Database, _PoolManager, SecurityViolationError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

QUICK_MODE = os.getenv('BENCH_QUICK', '').lower() in ('1', 'true', 'yes')
NUM_TENANTS = 5
ROWS_PER_TENANT = 500 if QUICK_MODE else 5_000
CONCURRENT_WORKERS = 20 if QUICK_MODE else 100
OPS_PER_WORKER = 20 if QUICK_MODE else 100
TENANT_ID_BASE = 90001  # Use 90001-90005 to avoid collisions
TEST_TABLE = '_bench_events'
TEST_ROLE = '_bench_test_app'
TEST_ROLE_PW = '_bench_test_pw'


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

def _admin_conn():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_ADMIN_USER, password=DB_ADMIN_PASSWORD,
        sslmode=DB_SSLMODE,
    )


def _rls_conn(org_id):
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


def _setup():
    """Create test role, table, RLS, and seed data."""
    conn = _admin_conn()
    conn.autocommit = True
    cur = conn.cursor()

    if IS_LOCAL:
        cur.execute(f"SELECT 1 FROM pg_roles WHERE rolname = '{TEST_ROLE}'")
        if not cur.fetchone():
            cur.execute(
                f"CREATE ROLE {TEST_ROLE} LOGIN PASSWORD '{TEST_ROLE_PW}' "
                f"NOBYPASSRLS NOSUPERUSER"
            )

    conn.autocommit = False

    # Organizations
    for i in range(NUM_TENANTS):
        tid = TENANT_ID_BASE + i
        cur.execute("""
            INSERT INTO organizations (id, name, slug)
            VALUES (%s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (tid, f'Bench Org {i}', f'bench-{i}'))

    # Test table
    cur.execute(f"DROP TABLE IF EXISTS {TEST_TABLE} CASCADE")
    cur.execute(f"""
        CREATE TABLE {TEST_TABLE} (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            payload TEXT
        )
    """)
    cur.execute(f"CREATE INDEX idx_{TEST_TABLE}_org ON {TEST_TABLE}(organization_id)")
    cur.execute(f"ALTER TABLE {TEST_TABLE} ENABLE ROW LEVEL SECURITY")
    cur.execute(f"ALTER TABLE {TEST_TABLE} FORCE ROW LEVEL SECURITY")
    cur.execute(f"""
        CREATE POLICY bench_sel ON {TEST_TABLE} FOR SELECT
        USING (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)
    cur.execute(f"""
        CREATE POLICY bench_ins ON {TEST_TABLE} FOR INSERT
        WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)

    # Seed data
    event_types = ['login', 'access', 'modify', 'delete', 'create']
    severities = ['low', 'medium', 'high', 'critical']

    for tenant_idx in range(NUM_TENANTS):
        tid = TENANT_ID_BASE + tenant_idx
        batch = []
        for j in range(ROWS_PER_TENANT):
            batch.append((
                tid,
                random.choice(event_types),
                random.choice(severities),
                f'payload_{j}',
            ))
        # Batch insert (1000 at a time)
        for start in range(0, len(batch), 1000):
            chunk = batch[start:start + 1000]
            args_str = ','.join(
                cur.mogrify("(%s,%s,%s,%s)", row).decode() for row in chunk
            )
            cur.execute(f"INSERT INTO {TEST_TABLE} (organization_id, event_type, severity, payload) VALUES {args_str}")

    # Grant to test role
    role = TEST_ROLE if IS_LOCAL else DB_USER
    cur.execute(f'GRANT SELECT, INSERT ON {TEST_TABLE} TO "{role}"')
    cur.execute(f'GRANT USAGE, SELECT ON SEQUENCE {TEST_TABLE}_id_seq TO "{role}"')

    conn.commit()
    cur.close()
    conn.close()

    total = NUM_TENANTS * ROWS_PER_TENANT
    print(f"  Setup complete: {NUM_TENANTS} tenants × {ROWS_PER_TENANT:,} rows = {total:,} total")


def _teardown():
    conn = _admin_conn()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(f"DROP TABLE IF EXISTS {TEST_TABLE} CASCADE")
    for i in range(NUM_TENANTS):
        cur.execute("DELETE FROM organizations WHERE id = %s", (TENANT_ID_BASE + i,))
    if IS_LOCAL:
        try:
            cur.execute(f"DROP ROLE IF EXISTS {TEST_ROLE}")
        except Exception:
            pass
    cur.close()
    conn.close()


def _percentile(data, pct):
    """Calculate percentile from sorted data."""
    if not data:
        return 0
    data_sorted = sorted(data)
    idx = int(len(data_sorted) * pct / 100)
    idx = min(idx, len(data_sorted) - 1)
    return data_sorted[idx]


# ---------------------------------------------------------------------------
# Benchmark 1: Pool throughput under concurrent load
# ---------------------------------------------------------------------------

def bench_pool_throughput():
    """Measure p50/p95/p99 latency with pooled connections under high concurrency."""
    latencies = []
    errors = []
    leaks = []
    lock = threading.Lock()

    def _worker(worker_id):
        tid = TENANT_ID_BASE + (worker_id % NUM_TENANTS)
        for op in range(OPS_PER_WORKER):
            t0 = time.monotonic()
            try:
                db = Database(organization_id=tid)
                cursor = db.conn.cursor()
                cursor.execute(
                    f"SELECT COUNT(*) FROM {TEST_TABLE} WHERE severity = %s",
                    ('high',),
                )
                count = cursor.fetchone()[0]
                cursor.close()

                # Verify tenant context was set correctly
                cursor2 = db.conn.cursor()
                cursor2.execute("SELECT current_setting('app.current_organization_id', true)")
                ctx_val = cursor2.fetchone()[0]
                cursor2.close()
                db.close()

                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    latencies.append(elapsed)
                    if ctx_val != str(tid):
                        leaks.append(f"Worker {worker_id} op {op}: context={ctx_val}, expected {tid}")

            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    errors.append(f"Worker {worker_id} op {op}: {e}")
                    latencies.append(elapsed)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(CONCURRENT_WORKERS)]
    t_start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    wall_time = time.monotonic() - t_start

    total_ops = CONCURRENT_WORKERS * OPS_PER_WORKER
    ops_per_sec = total_ops / wall_time if wall_time > 0 else 0

    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)

    pool_stats = _PoolManager.stats()

    print(f"\n  Pool throughput ({CONCURRENT_WORKERS} workers × {OPS_PER_WORKER} ops):")
    print(f"    Total ops:    {total_ops:,}")
    print(f"    Wall time:    {wall_time:.1f}s")
    print(f"    Throughput:   {ops_per_sec:.0f} ops/sec")
    print(f"    Latency p50:  {p50:.1f}ms")
    print(f"    Latency p95:  {p95:.1f}ms")
    print(f"    Latency p99:  {p99:.1f}ms")
    print(f"    Errors:       {len(errors)}")
    print(f"    Leaks:        {len(leaks)}")
    print(f"    Pool config:  enabled={pool_stats.get('enabled')}")
    if 'app' in pool_stats:
        print(f"    Pool app:     active={pool_stats['app']['active']}, max={pool_stats['app']['max']}")

    if leaks:
        for leak in leaks[:3]:
            print(f"    LEAK: {leak}")
        raise AssertionError(f"TENANT LEAKAGE: {len(leaks)} isolation failures")

    if len(errors) > total_ops * 0.05:
        print(f"    First errors:")
        for e in errors[:5]:
            print(f"      {e}")
        raise AssertionError(f"Too many errors: {len(errors)}/{total_ops}")

    print("  PASS: bench_pool_throughput")
    return {
        'ops': total_ops, 'wall_time': wall_time, 'ops_per_sec': ops_per_sec,
        'p50': p50, 'p95': p95, 'p99': p99,
        'errors': len(errors), 'leaks': len(leaks),
    }


# ---------------------------------------------------------------------------
# Benchmark 2: Direct connection throughput (baseline comparison)
# ---------------------------------------------------------------------------

def bench_direct_throughput():
    """Measure throughput with direct (non-pooled) connections for comparison."""
    latencies = []
    errors = []
    lock = threading.Lock()
    # Use fewer workers for direct — each opens a new connection
    workers = min(CONCURRENT_WORKERS, 20)
    ops = min(OPS_PER_WORKER, 20)

    def _worker(worker_id):
        tid = TENANT_ID_BASE + (worker_id % NUM_TENANTS)
        for op in range(ops):
            t0 = time.monotonic()
            try:
                conn = _rls_conn(tid)
                cur = conn.cursor()
                cur.execute(
                    f"SELECT COUNT(*) FROM {TEST_TABLE} WHERE severity = %s",
                    ('high',),
                )
                cur.fetchone()
                cur.close()
                conn.close()
                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    latencies.append(elapsed)
            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    errors.append(str(e))
                    latencies.append(elapsed)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(workers)]
    t_start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    wall_time = time.monotonic() - t_start

    total_ops = workers * ops
    ops_per_sec = total_ops / wall_time if wall_time > 0 else 0

    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)

    print(f"\n  Direct connection baseline ({workers} workers × {ops} ops):")
    print(f"    Total ops:    {total_ops:,}")
    print(f"    Wall time:    {wall_time:.1f}s")
    print(f"    Throughput:   {ops_per_sec:.0f} ops/sec")
    print(f"    Latency p50:  {p50:.1f}ms")
    print(f"    Latency p95:  {p95:.1f}ms")
    print(f"    Latency p99:  {p99:.1f}ms")
    print(f"    Errors:       {len(errors)}")
    print("  PASS: bench_direct_throughput")
    return {
        'ops': total_ops, 'wall_time': wall_time, 'ops_per_sec': ops_per_sec,
        'p50': p50, 'p95': p95, 'p99': p99, 'errors': len(errors),
    }


# ---------------------------------------------------------------------------
# Benchmark 3: Pool saturation test
# ---------------------------------------------------------------------------

def bench_pool_saturation():
    """Push more concurrent workers than pool max to test overflow behavior."""
    # Use 2x pool max workers to force pool exhaustion
    pool_max = DB_POOL_MAX
    workers = pool_max * 2
    ops = 10 if QUICK_MODE else 30
    latencies = []
    fallback_count = [0]
    errors = []
    lock = threading.Lock()

    def _worker(worker_id):
        tid = TENANT_ID_BASE + (worker_id % NUM_TENANTS)
        for op in range(ops):
            t0 = time.monotonic()
            try:
                db = Database(organization_id=tid)
                # Check if this came from pool or direct
                if not db._from_pool:
                    with lock:
                        fallback_count[0] += 1
                cursor = db.conn.cursor()
                cursor.execute(f"SELECT 1")
                cursor.fetchone()
                cursor.close()
                db.close()
                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    latencies.append(elapsed)
            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    errors.append(str(e))
                    latencies.append(elapsed)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(workers)]
    t_start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    wall_time = time.monotonic() - t_start

    total_ops = workers * ops
    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)

    print(f"\n  Pool saturation ({workers} workers > {pool_max} pool max, {ops} ops each):")
    print(f"    Total ops:      {total_ops:,}")
    print(f"    Wall time:      {wall_time:.1f}s")
    print(f"    Latency p50:    {p50:.1f}ms")
    print(f"    Latency p95:    {p95:.1f}ms")
    print(f"    Latency p99:    {p99:.1f}ms")
    print(f"    Pool fallbacks: {fallback_count[0]} (direct connections when pool full)")
    print(f"    Errors:         {len(errors)}")

    # All ops should succeed even under saturation
    if len(errors) > total_ops * 0.1:
        raise AssertionError(f"Too many errors under saturation: {len(errors)}/{total_ops}")

    print("  PASS: bench_pool_saturation")


# ---------------------------------------------------------------------------
# Benchmark 4: Pool checkout/return overhead
# ---------------------------------------------------------------------------

def bench_pool_overhead():
    """Measure raw checkout + query + return cycle to isolate pool overhead."""
    iterations = 200 if QUICK_MODE else 1000
    latencies_pool = []
    latencies_query = []

    tid = TENANT_ID_BASE

    for _ in range(iterations):
        t0 = time.monotonic()
        db = Database(organization_id=tid)
        t1 = time.monotonic()

        cursor = db.conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        t2 = time.monotonic()

        db.close()
        t3 = time.monotonic()

        # Pool overhead = checkout + context set + close/return
        pool_overhead_ms = ((t1 - t0) + (t3 - t2)) * 1000
        query_ms = (t2 - t1) * 1000

        latencies_pool.append(pool_overhead_ms)
        latencies_query.append(query_ms)

    pool_p50 = _percentile(latencies_pool, 50)
    pool_p95 = _percentile(latencies_pool, 95)
    query_p50 = _percentile(latencies_query, 50)
    query_p95 = _percentile(latencies_query, 95)
    overhead_pct = (pool_p50 / (pool_p50 + query_p50) * 100) if (pool_p50 + query_p50) > 0 else 0

    print(f"\n  Pool overhead measurement ({iterations} iterations, sequential):")
    print(f"    Pool overhead p50: {pool_p50:.2f}ms  (checkout + context + return)")
    print(f"    Pool overhead p95: {pool_p95:.2f}ms")
    print(f"    Query only p50:    {query_p50:.2f}ms  (SELECT 1)")
    print(f"    Query only p95:    {query_p95:.2f}ms")
    print(f"    Overhead ratio:    {overhead_pct:.1f}% of total cycle time")
    print("  PASS: bench_pool_overhead")


# ---------------------------------------------------------------------------
# Benchmark 5: Mixed read/write workload
# ---------------------------------------------------------------------------

def bench_mixed_workload():
    """Simulate realistic mixed workload: 80% reads, 20% writes."""
    latencies = defaultdict(list)
    errors = []
    leaks = []
    lock = threading.Lock()
    workers = min(CONCURRENT_WORKERS, 50)
    ops = OPS_PER_WORKER

    def _worker(worker_id):
        tid = TENANT_ID_BASE + (worker_id % NUM_TENANTS)
        for op in range(ops):
            is_write = random.random() < 0.2
            op_type = 'write' if is_write else 'read'
            t0 = time.monotonic()
            try:
                db = Database(organization_id=tid)
                cursor = db.conn.cursor()
                if is_write:
                    cursor.execute(
                        f"INSERT INTO {TEST_TABLE} (organization_id, event_type, severity, payload) "
                        f"VALUES (%s, %s, %s, %s)",
                        (tid, 'benchmark', 'low', f'worker_{worker_id}_op_{op}'),
                    )
                    db.conn.commit()
                else:
                    cursor.execute(
                        f"SELECT event_type, COUNT(*) FROM {TEST_TABLE} "
                        f"GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 5"
                    )
                    rows = cursor.fetchall()
                cursor.close()
                db.close()

                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    latencies[op_type].append(elapsed)
            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                with lock:
                    errors.append(f"{op_type} worker {worker_id}: {e}")
                    latencies[op_type].append(elapsed)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(workers)]
    t_start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    wall_time = time.monotonic() - t_start

    total_ops = workers * ops
    total_reads = len(latencies['read'])
    total_writes = len(latencies['write'])

    print(f"\n  Mixed workload ({workers} workers × {ops} ops, 80/20 read/write):")
    print(f"    Total ops:     {total_ops:,} ({total_reads} reads, {total_writes} writes)")
    print(f"    Wall time:     {wall_time:.1f}s")
    print(f"    Throughput:    {total_ops / wall_time:.0f} ops/sec")
    for op_type in ('read', 'write'):
        data = latencies[op_type]
        if data:
            print(f"    {op_type.capitalize()} p50: {_percentile(data, 50):.1f}ms  "
                  f"p95: {_percentile(data, 95):.1f}ms  "
                  f"p99: {_percentile(data, 99):.1f}ms")
    print(f"    Errors:        {len(errors)}")

    if len(errors) > total_ops * 0.05:
        for e in errors[:5]:
            print(f"      {e}")
        raise AssertionError(f"Too many errors: {len(errors)}/{total_ops}")

    print("  PASS: bench_mixed_workload")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 70)
    print("  AuditGraph — Connection Pool Throughput Benchmark")
    print(f"  IS_LOCAL={IS_LOCAL}  POOL_ENABLED={DB_POOL_ENABLED}")
    print(f"  POOL_MIN={DB_POOL_MIN}  POOL_MAX={DB_POOL_MAX}")
    print(f"  MODE={'QUICK' if QUICK_MODE else 'FULL'}")
    print(f"  Workers={CONCURRENT_WORKERS}  Ops/worker={OPS_PER_WORKER}")
    print("=" * 70)

    _setup()

    benchmarks = [
        ("Pool Overhead", bench_pool_overhead),
        ("Pool Throughput", bench_pool_throughput),
        ("Direct Baseline", bench_direct_throughput),
        ("Pool Saturation", bench_pool_saturation),
        ("Mixed Workload", bench_mixed_workload),
    ]

    passed = 0
    failed = 0
    results = {}

    for name, fn in benchmarks:
        print(f"\n--- {name} ---")
        try:
            result = fn()
            if result:
                results[name] = result
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {name}: {e}")

    # Summary comparison
    if 'Pool Throughput' in results and 'Direct Baseline' in results:
        pool = results['Pool Throughput']
        direct = results['Direct Baseline']
        speedup = pool['ops_per_sec'] / direct['ops_per_sec'] if direct['ops_per_sec'] > 0 else 0
        latency_improvement = (1 - pool['p50'] / direct['p50']) * 100 if direct['p50'] > 0 else 0
        print(f"\n--- Pool vs Direct Comparison ---")
        print(f"    Throughput:  {pool['ops_per_sec']:.0f} vs {direct['ops_per_sec']:.0f} ops/sec ({speedup:.1f}x)")
        print(f"    Latency p50: {pool['p50']:.1f}ms vs {direct['p50']:.1f}ms ({latency_improvement:+.0f}%)")
        print(f"    Latency p95: {pool['p95']:.1f}ms vs {direct['p95']:.1f}ms")

    _teardown()

    print()
    print("=" * 70)
    print(f"  Results: {passed} passed, {failed} failed, {len(benchmarks)} total")
    print("=" * 70)

    sys.exit(1 if failed > 0 else 0)
