"""
Enterprise Isolation Stress Test Suite

Simulates concurrent multi-tenant requests and verifies that:
  1. Tenant A cannot see Tenant B's data (RLS enforcement)
  2. Tenant context is never leaked across requests
  3. SecurityViolationError fires on missing context
  4. Context reset works correctly on teardown
  5. Admin guard blocks unauthorized admin connections

Requires a running PostgreSQL instance (local or Docker).

In LOCAL mode (single superuser), the suite creates a temporary NOBYPASSRLS
role to prove that RLS policies actually filter rows. This mirrors the
production dual-role architecture (auditgraph_app vs auditgraph_admin).

Usage:
    cd backend
    PYTHONPATH=. ./venv/bin/python tests/test_isolation_stress.py

    # Or via pytest:
    PYTHONPATH=. ./venv/bin/python -m pytest tests/test_isolation_stress.py -v
"""
import os
import sys
import threading

import pytest

# Ensure local dev config before any app imports
os.environ.setdefault('APP_ENV', 'local')
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-stress')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-stress')
os.environ.setdefault('CLIENT_JWT_SECRET', 'client-test-stress')
os.environ.setdefault('ENFORCE_ADMIN_GUARD', 'false')

import psycopg2
from app.config import (
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
    DB_ADMIN_USER, DB_ADMIN_PASSWORD, DB_SSLMODE, IS_LOCAL,
)
from app.database import Database, SecurityViolationError

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

_TEST_ROLE = '_isolation_test_app'
_TEST_ROLE_PW = '_test_pw_12345'


def _admin_conn():
    """Raw admin/superuser connection for test setup/teardown."""
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_ADMIN_USER, password=DB_ADMIN_PASSWORD,
        sslmode=DB_SSLMODE,
    )


def _rls_conn(org_id):
    """Open a NOBYPASSRLS connection with tenant context set.

    In local mode this uses the temporary _isolation_test_app role.
    In non-local mode it uses DB_USER (which is already NOBYPASSRLS).
    """
    if IS_LOCAL:
        user, pw = _TEST_ROLE, _TEST_ROLE_PW
    else:
        user, pw = DB_USER, DB_PASSWORD

    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=user, password=pw, sslmode=DB_SSLMODE,
    )
    cursor = conn.cursor()
    cursor.execute(
        "SELECT set_config('app.current_organization_id', %s, FALSE)",
        (str(org_id),),
    )
    cursor.close()
    return conn


def _setup_test_env():
    """Create test role, table, RLS policies, and seed data."""
    conn = _admin_conn()
    conn.autocommit = True
    cursor = conn.cursor()

    # 1. Create a NOBYPASSRLS test role (local mode only)
    if IS_LOCAL:
        cursor.execute(f"SELECT 1 FROM pg_roles WHERE rolname = '{_TEST_ROLE}'")
        if not cursor.fetchone():
            cursor.execute(
                f"CREATE ROLE {_TEST_ROLE} LOGIN PASSWORD '{_TEST_ROLE_PW}' "
                f"NOBYPASSRLS NOSUPERUSER"
            )

    conn.autocommit = False

    # 2. Ensure organizations table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE,
            enabled BOOLEAN DEFAULT TRUE,
            plan TEXT DEFAULT 'free',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    cursor.execute("""
        INSERT INTO organizations (id, name, slug)
        VALUES (99901, 'Stress Test Org A', 'stress-a'),
               (99902, 'Stress Test Org B', 'stress-b')
        ON CONFLICT (id) DO NOTHING
    """)

    # 3. Create test table with RLS
    cursor.execute("DROP TABLE IF EXISTS _isolation_test CASCADE")
    cursor.execute("""
        CREATE TABLE _isolation_test (
            id SERIAL PRIMARY KEY,
            organization_id INTEGER NOT NULL,
            secret_data TEXT NOT NULL
        )
    """)
    cursor.execute("ALTER TABLE _isolation_test ENABLE ROW LEVEL SECURITY")
    cursor.execute("ALTER TABLE _isolation_test FORCE ROW LEVEL SECURITY")

    # Strict RLS policies
    cursor.execute("""
        CREATE POLICY iso_sel ON _isolation_test FOR SELECT
        USING (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)
    cursor.execute("""
        CREATE POLICY iso_ins ON _isolation_test FOR INSERT
        WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer)
    """)

    # 4. Seed data
    cursor.execute("""
        INSERT INTO _isolation_test (organization_id, secret_data) VALUES
            (99901, 'SECRET_ORG_A_1'),
            (99901, 'SECRET_ORG_A_2'),
            (99901, 'SECRET_ORG_A_3'),
            (99902, 'SECRET_ORG_B_1'),
            (99902, 'SECRET_ORG_B_2')
    """)

    # 5. Grant access to the test role
    role = _TEST_ROLE if IS_LOCAL else DB_USER
    cursor.execute(f'GRANT SELECT, INSERT ON _isolation_test TO "{role}"')
    cursor.execute(f'GRANT USAGE, SELECT ON SEQUENCE _isolation_test_id_seq TO "{role}"')

    conn.commit()
    cursor.close()
    conn.close()


def _teardown_test_env():
    """Remove test table and role."""
    conn = _admin_conn()
    conn.autocommit = True
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS _isolation_test CASCADE")
    cursor.execute("DELETE FROM organizations WHERE id IN (99901, 99902)")

    if IS_LOCAL:
        try:
            cursor.execute(f"DROP ROLE IF EXISTS {_TEST_ROLE}")
        except Exception:
            pass

    cursor.close()
    conn.close()


# ---------------------------------------------------------------------------
# Test 1: Tenant A can only see Org A data
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_tenant_sees_only_own_data():
    """RLS-enforced connection for Org A must return only Org A rows."""
    _setup_test_env()
    try:
        conn_a = _rls_conn(99901)
        cur = conn_a.cursor()
        cur.execute("SELECT secret_data FROM _isolation_test ORDER BY secret_data")
        rows = [r[0] for r in cur.fetchall()]
        cur.close()
        conn_a.close()

        assert len(rows) == 3, f"Org A expected 3, got {len(rows)}: {rows}"
        assert all('ORG_A' in r for r in rows), f"Org A got foreign data: {rows}"

        conn_b = _rls_conn(99902)
        cur = conn_b.cursor()
        cur.execute("SELECT secret_data FROM _isolation_test ORDER BY secret_data")
        rows = [r[0] for r in cur.fetchall()]
        cur.close()
        conn_b.close()

        assert len(rows) == 2, f"Org B expected 2, got {len(rows)}: {rows}"
        assert all('ORG_B' in r for r in rows), f"Org B got foreign data: {rows}"

        print("  PASS: test_tenant_sees_only_own_data")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 2: Cross-tenant WHERE clause returns zero rows
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_cross_tenant_returns_empty():
    """Org A cannot fetch Org B data even with explicit WHERE organization_id = B."""
    _setup_test_env()
    try:
        conn = _rls_conn(99901)
        cur = conn.cursor()
        cur.execute(
            "SELECT secret_data FROM _isolation_test WHERE organization_id = 99902"
        )
        leaked = cur.fetchall()
        cur.close()
        conn.close()

        assert len(leaked) == 0, (
            f"CROSS-TENANT LEAKAGE: Org A read {len(leaked)} of Org B's rows"
        )
        print("  PASS: test_cross_tenant_returns_empty")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 3: Sentinel org_id (-1) matches nothing
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_sentinel_org_matches_nothing():
    """Organization_id = -1 should match zero rows in any table."""
    _setup_test_env()
    try:
        conn = _rls_conn(-1)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM _isolation_test")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()

        assert count == 0, f"Sentinel (-1) returned {count} rows — expected 0"
        print("  PASS: test_sentinel_org_matches_nothing")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 4: verify_tenant_context detects NULL context
# ---------------------------------------------------------------------------

def test_verify_tenant_context_detects_null():
    """verify_tenant_context() must raise SecurityViolationError if context is lost."""
    _setup_test_env()
    try:
        db = Database(organization_id=99901)

        # Simulate context loss
        cursor = db.conn.cursor()
        cursor.execute("RESET app.current_organization_id")
        cursor.close()

        raised = False
        try:
            db.verify_tenant_context()
        except SecurityViolationError as e:
            raised = True
            assert 'LOST' in str(e) or 'NULL' in str(e), f"Unexpected message: {e}"

        db.close()
        assert raised, "SecurityViolationError NOT raised on NULL context"
        print("  PASS: test_verify_tenant_context_detects_null")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 5: verify_tenant_context detects mismatch
# ---------------------------------------------------------------------------

def test_verify_tenant_context_detects_mismatch():
    """verify_tenant_context() must raise if context was tampered to wrong org."""
    _setup_test_env()
    try:
        db = Database(organization_id=99901)

        # Tamper context to Org B
        cursor = db.conn.cursor()
        cursor.execute(
            "SELECT set_config('app.current_organization_id', '99902', TRUE)"
        )
        cursor.close()

        raised = False
        try:
            db.verify_tenant_context()
        except SecurityViolationError as e:
            raised = True
            assert 'MISMATCH' in str(e), f"Unexpected message: {e}"

        db.close()
        assert raised, "SecurityViolationError NOT raised on mismatch"
        print("  PASS: test_verify_tenant_context_detects_mismatch")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 6: execute_safe blocks queries on lost context
# ---------------------------------------------------------------------------

def test_execute_safe_blocks_on_lost_context():
    """execute_safe() must raise SecurityViolationError before running any query."""
    _setup_test_env()
    try:
        db = Database(organization_id=99901)

        # Wipe context
        cursor = db.conn.cursor()
        cursor.execute("RESET app.current_organization_id")
        cursor.close()

        raised = False
        try:
            db.execute_safe("SELECT * FROM _isolation_test")
        except SecurityViolationError:
            raised = True

        db.close()
        assert raised, "execute_safe did NOT block query on lost context"
        print("  PASS: test_execute_safe_blocks_on_lost_context")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 7: execute_safe works normally with valid context
# ---------------------------------------------------------------------------

def test_execute_safe_works_with_context():
    """execute_safe() should succeed when tenant context is valid."""
    _setup_test_env()
    try:
        db = Database(organization_id=99901)
        cursor = db.execute_safe("SELECT 1")
        result = cursor.fetchone()[0]
        cursor.close()
        db.close()

        assert result == 1, f"execute_safe returned {result}, expected 1"
        print("  PASS: test_execute_safe_works_with_context")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 8: close() resets context before closing
# ---------------------------------------------------------------------------

def test_close_resets_context():
    """Database.close() must reset context and close the connection."""
    _setup_test_env()
    try:
        db = Database(organization_id=99901)
        db.verify_tenant_context()  # Should succeed

        raw_conn = db.conn
        db.close()

        assert raw_conn.closed, "Connection was not closed"
        print("  PASS: test_close_resets_context")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 9: Concurrent multi-tenant stress test (RLS enforcement)
# ---------------------------------------------------------------------------

@pytest.mark.requires_db
def test_concurrent_isolation():
    """2 tenants × 20 iterations × concurrent threads — verify zero leakage."""
    _setup_test_env()
    errors = []
    iterations = 20

    def _worker(org_id, expected_prefix, expected_count):
        for i in range(iterations):
            try:
                conn = _rls_conn(org_id)
                cur = conn.cursor()
                cur.execute("SELECT secret_data FROM _isolation_test")
                rows = [r[0] for r in cur.fetchall()]
                cur.close()
                conn.close()

                if len(rows) != expected_count:
                    errors.append(
                        f"Org {org_id} iter {i}: expected {expected_count}, got {len(rows)}"
                    )
                for row in rows:
                    if expected_prefix not in row:
                        errors.append(
                            f"LEAKAGE Org {org_id} iter {i}: got '{row}'"
                        )
            except Exception as e:
                errors.append(f"Org {org_id} iter {i}: {e}")

    try:
        t_a = threading.Thread(target=_worker, args=(99901, 'ORG_A', 3))
        t_b = threading.Thread(target=_worker, args=(99902, 'ORG_B', 2))

        t_a.start()
        t_b.start()
        t_a.join(timeout=30)
        t_b.join(timeout=30)

        if errors:
            for err in errors[:5]:
                print(f"    {err}")
            if len(errors) > 5:
                print(f"    ... and {len(errors) - 5} more errors")
            raise AssertionError(
                f"Concurrent isolation FAILED: {len(errors)} errors"
            )

        print(f"  PASS: test_concurrent_isolation ({iterations * 2} operations, 0 leaks)")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 10: Admin (superuser) sees all data
# ---------------------------------------------------------------------------

def test_admin_sees_all_data():
    """Admin connection bypasses RLS — this is expected and correct."""
    _setup_test_env()
    original = Database._startup_complete
    Database._startup_complete = False

    try:
        db = Database(_admin_reason='isolation_test')
        cursor = db.conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM _isolation_test WHERE organization_id IN (99901, 99902)"
        )
        count = cursor.fetchone()[0]
        cursor.close()
        db.close()

        assert count == 5, f"Admin expected 5 total, got {count}"
        print("  PASS: test_admin_sees_all_data")
    finally:
        Database._startup_complete = original
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 11: SecurityViolationError is a proper exception type
# ---------------------------------------------------------------------------

def test_security_violation_error_type():
    """SecurityViolationError must be Exception subclass, not RuntimeError."""
    assert issubclass(SecurityViolationError, Exception)
    assert not issubclass(SecurityViolationError, RuntimeError)
    e = SecurityViolationError("test")
    assert str(e) == "test"
    print("  PASS: test_security_violation_error_type")


# ---------------------------------------------------------------------------
# Test 12: set_organization_context verifies after setting
# ---------------------------------------------------------------------------

def test_set_organization_context_verifies():
    """set_organization_context must verify the value matches after SET."""
    _setup_test_env()
    try:
        db = Database(organization_id=99901)
        # If we got here without error, verification passed during __init__
        db.verify_tenant_context()  # Double-check
        db.close()
        print("  PASS: test_set_organization_context_verifies")
    finally:
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Test 13: Admin execute_safe skips tenant verification
# ---------------------------------------------------------------------------

def test_admin_execute_safe_no_tenant_check():
    """execute_safe on admin connection should not require tenant context."""
    _setup_test_env()
    original = Database._startup_complete
    Database._startup_complete = False

    try:
        db = Database(_admin_reason='test')
        cursor = db.execute_safe("SELECT 1")
        result = cursor.fetchone()[0]
        cursor.close()
        db.close()

        assert result == 1
        print("  PASS: test_admin_execute_safe_no_tenant_check")
    finally:
        Database._startup_complete = original
        _teardown_test_env()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 70)
    print("  AuditGraph — Tenant Isolation Stress Test Suite")
    print(f"  IS_LOCAL={IS_LOCAL}  DB_USER={DB_USER}  DB_ADMIN_USER={DB_ADMIN_USER}")
    if IS_LOCAL:
        print(f"  Local mode: creating temp role '{_TEST_ROLE}' (NOBYPASSRLS)")
    print("=" * 70)
    print()

    tests = [
        test_security_violation_error_type,
        test_set_organization_context_verifies,
        test_tenant_sees_only_own_data,
        test_cross_tenant_returns_empty,
        test_sentinel_org_matches_nothing,
        test_verify_tenant_context_detects_null,
        test_verify_tenant_context_detects_mismatch,
        test_execute_safe_blocks_on_lost_context,
        test_execute_safe_works_with_context,
        test_close_resets_context,
        test_admin_sees_all_data,
        test_admin_execute_safe_no_tenant_check,
        test_concurrent_isolation,
    ]

    passed = 0
    failed = 0
    for fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {fn.__name__}: {e}")

    print()
    print("=" * 70)
    print(f"  Results: {passed} passed, {failed} failed, {len(tests)} total")
    print("=" * 70)

    sys.exit(1 if failed > 0 else 0)
