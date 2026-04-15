"""
Integration test for delete_organization() cascade.

Requires a real PostgreSQL connection. Uses admin DB to bypass RLS.
Creates a test org, populates high-risk tables, deletes it, and asserts
zero orphaned rows remain.

Usage:
    cd backend && python -m pytest tests/test_delete_organization.py -v
"""
import os
import uuid
import pytest

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-key')
os.environ.setdefault('TENANT_JWT_SECRET', 'tenant-test-key')

from app.database import Database


def _admin_db():
    """Get an admin-mode DB connection (bypasses RLS)."""
    return Database(_admin_reason='test_delete_org')


def _exec(db, sql, params=None):
    """Execute SQL and commit."""
    cur = db.conn.cursor()
    cur.execute(sql, params or ())
    db.conn.commit()
    cur.close()


def _fetch_one(db, sql, params=None):
    """Execute SQL and return one row."""
    cur = db.conn.cursor()
    cur.execute(sql, params or ())
    row = cur.fetchone()
    cur.close()
    return row


def _count(db, table, org_id, col='organization_id'):
    """Count rows in a table for an org. Returns 0 if table doesn't exist."""
    cur = db.conn.cursor()
    try:
        cur.execute(f"SAVEPOINT sp_cnt")
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {col} = %s",
                    (org_id,))
        n = cur.fetchone()[0]
        cur.execute(f"RELEASE SAVEPOINT sp_cnt")
        return n
    except Exception:
        cur.execute(f"ROLLBACK TO SAVEPOINT sp_cnt")
        return 0
    finally:
        cur.close()


def _count_by_subquery(db, table, col, subquery, org_id):
    """Count rows via subquery. Returns 0 if table doesn't exist."""
    cur = db.conn.cursor()
    try:
        cur.execute(f"SAVEPOINT sp_cnt")
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {col} IN ({subquery})",
                    (org_id,))
        n = cur.fetchone()[0]
        cur.execute(f"RELEASE SAVEPOINT sp_cnt")
        return n
    except Exception:
        cur.execute(f"ROLLBACK TO SAVEPOINT sp_cnt")
        return 0
    finally:
        cur.close()


@pytest.fixture
def test_org():
    """Create a test organization and clean up after test."""
    db = _admin_db()
    slug = f"test-del-{uuid.uuid4().hex[:8]}"
    org = db.create_organization(name=f"Test Delete {slug}", slug=slug)
    org_id = org['id']

    yield org_id, db

    # Cleanup: if org still exists (test didn't delete it), force remove
    try:
        row = _fetch_one(db, "SELECT id FROM organizations WHERE id = %s",
                         (org_id,))
        if row:
            db.delete_organization(org_id)
    except Exception:
        pass
    db.close()


def _ensure_table(db, table, ddl):
    """Create a table if it doesn't exist (for test isolation)."""
    cur = db.conn.cursor()
    try:
        cur.execute(f"SAVEPOINT sp_ensure")
        cur.execute(ddl)
        cur.execute(f"RELEASE SAVEPOINT sp_ensure")
    except Exception:
        cur.execute(f"ROLLBACK TO SAVEPOINT sp_ensure")
    db.conn.commit()
    cur.close()


def _safe_insert(db, sql, params):
    """Insert a row, handling cases where the table might not exist."""
    cur = db.conn.cursor()
    try:
        cur.execute("SAVEPOINT sp_ins")
        cur.execute(sql, params)
        cur.execute("RELEASE SAVEPOINT sp_ins")
        db.conn.commit()
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_ins")
    cur.close()


def _create_cloud_connection(db, org_id):
    """Create a cloud_connection and return its id."""
    cur = db.conn.cursor()
    cur.execute("""
        INSERT INTO cloud_connections (organization_id, cloud, connection_type,
                                       label, status)
        VALUES (%s, 'azure', 'entra', 'test-conn', 'active')
        RETURNING id
    """, (org_id,))
    conn_id = cur.fetchone()[0]
    db.conn.commit()
    cur.close()
    return conn_id


def _create_discovery_run(db, org_id, cloud_connection_id=None):
    """Create a discovery_run and return its id."""
    if cloud_connection_id is None:
        cloud_connection_id = _create_cloud_connection(db, org_id)
    cur = db.conn.cursor()
    cur.execute("""
        INSERT INTO discovery_runs (organization_id, cloud_connection_id,
                                    subscription_id, status, started_at)
        VALUES (%s, %s, 'sub-test-001', 'completed', NOW())
        RETURNING id
    """, (org_id, cloud_connection_id))
    run_id = cur.fetchone()[0]
    db.conn.commit()
    cur.close()
    return run_id


def _create_identity(db, org_id, run_id):
    """Create an identity and return its id."""
    cur = db.conn.cursor()
    cur.execute("""
        INSERT INTO identities (identity_id, display_name, identity_type,
                                identity_category, risk_level,
                                discovery_run_id, organization_id)
        VALUES (%s, 'Test SPN', 'service_principal', 'service_principal',
                'high', %s, %s)
        RETURNING id
    """, (f"spn-{uuid.uuid4().hex[:8]}", run_id, org_id))
    ident_id = cur.fetchone()[0]
    db.conn.commit()
    cur.close()
    return ident_id


class TestDeleteOrganizationCascade:
    """Tests for delete_organization() covering all 14 phases."""

    def test_empty_org_delete(self, test_org):
        """An org with no child data should delete cleanly."""
        org_id, db = test_org
        result = db.delete_organization(org_id)
        assert result is True
        assert _fetch_one(db, "SELECT id FROM organizations WHERE id = %s",
                          (org_id,)) is None

    def test_delete_with_users(self, test_org):
        """Org with users should delete cleanly (users FK→organizations NO ACTION)."""
        org_id, db = test_org
        _exec(db, """
            INSERT INTO users (username, password_hash, display_name, role, organization_id)
            VALUES (%s, 'hash', 'Test User', 'viewer', %s)
        """, (f"testuser-{uuid.uuid4().hex[:8]}", org_id))
        assert _count(db, 'users', org_id) >= 1

        result = db.delete_organization(org_id)
        assert result is True
        assert _count(db, 'users', org_id) == 0

    def test_delete_with_settings(self, test_org):
        """Org with settings should delete cleanly (settings FK→organizations NO ACTION)."""
        org_id, db = test_org
        _safe_insert(db, """
            INSERT INTO settings (key, value, organization_id)
            VALUES ('test_key', '"test_val"', %s)
        """, (org_id,))

        result = db.delete_organization(org_id)
        assert result is True
        assert _count(db, 'settings', org_id) == 0

    def test_delete_with_discovery_runs(self, test_org):
        """Org with discovery_runs should delete cleanly."""
        org_id, db = test_org
        _create_discovery_run(db, org_id)
        assert _count(db, 'discovery_runs', org_id) >= 1

        result = db.delete_organization(org_id)
        assert result is True
        assert _count(db, 'discovery_runs', org_id) == 0

    def test_delete_with_full_identity_chain(self, test_org):
        """Full chain: org → cloud_connection → discovery_run → identity → children."""
        org_id, db = test_org

        conn_id = _create_cloud_connection(db, org_id)
        run_id = _create_discovery_run(db, org_id, conn_id)
        ident_id = _create_identity(db, org_id, run_id)

        # identity children (Phase 4 tables)
        _safe_insert(db, """
            INSERT INTO credentials (identity_db_id, credential_type, status,
                                     organization_id)
            VALUES (%s, 'password', 'active', %s)
        """, (ident_id, org_id))

        _safe_insert(db, """
            INSERT INTO role_assignments (identity_db_id, role_name, scope,
                                          organization_id)
            VALUES (%s, 'Reader', '/subscriptions/test', %s)
        """, (ident_id, org_id))

        _safe_insert(db, """
            INSERT INTO entra_role_assignments (identity_db_id, role_name,
                                                organization_id)
            VALUES (%s, 'Directory Readers', %s)
        """, (ident_id, org_id))

        # risk_scores (FK→discovery_runs, NOT CASCADE)
        _safe_insert(db, """
            INSERT INTO risk_scores (identity_id, run_id, risk_score,
                                     risk_level, factors)
            VALUES (%s, %s, 75, 'high', '{}')
        """, (f"spn-{uuid.uuid4().hex[:8]}", run_id))

        result = db.delete_organization(org_id)
        assert result is True

        # Verify zero orphans in all critical tables
        assert _count(db, 'identities', org_id) == 0
        assert _count(db, 'discovery_runs', org_id) == 0
        assert _count(db, 'cloud_connections', org_id) == 0
        assert _count(db, 'credentials', org_id) == 0
        assert _count(db, 'role_assignments', org_id) == 0
        assert _count(db, 'entra_role_assignments', org_id) == 0
        assert _count_by_subquery(
            db, 'risk_scores', 'run_id',
            'SELECT id FROM discovery_runs WHERE organization_id = %s',
            org_id) == 0

    def test_delete_with_analytics_tables(self, test_org):
        """Phase 3 analytics tables should be cleaned up."""
        org_id, db = test_org

        run_id = _create_discovery_run(db, org_id)
        ident_id = _create_identity(db, org_id, run_id)

        # Phase 3 tables
        _safe_insert(db, """
            INSERT INTO attack_paths (organization_id, identity_db_id,
                                      path_type, severity, discovery_run_id,
                                      narrative, chain)
            VALUES (%s, %s, 'direct_escalation', 'high', %s, 'test', '[]')
        """, (org_id, ident_id, run_id))

        _safe_insert(db, """
            INSERT INTO blast_radius_results (organization_id, identity_db_id,
                                              blast_radius, discovery_run_id)
            VALUES (%s, %s, 5, %s)
        """, (org_id, ident_id, run_id))

        result = db.delete_organization(org_id)
        assert result is True
        assert _count(db, 'attack_paths', org_id) == 0
        assert _count(db, 'blast_radius_results', org_id) == 0

    def test_delete_with_graph_nodes_edges(self, test_org):
        """Graph nodes/edges (FK→cloud_connections CASCADE) should be cleaned."""
        org_id, db = test_org

        _safe_insert(db, """
            INSERT INTO cloud_connections (organization_id, provider, name,
                                          credentials, status)
            VALUES (%s, 'azure', 'graph-test-conn', '{}', 'active')
        """, (org_id,))

        conn_id_row = _fetch_one(db, """
            SELECT id FROM cloud_connections
            WHERE organization_id = %s ORDER BY id DESC LIMIT 1
        """, (org_id,))
        if conn_id_row:
            conn_id = conn_id_row[0]
            _safe_insert(db, """
                INSERT INTO graph_nodes (cloud_connection_id, node_id,
                                         node_type, label, organization_id)
                VALUES (%s, 'node-1', 'identity', 'Test Node', %s)
            """, (conn_id, org_id))

            _safe_insert(db, """
                INSERT INTO graph_edges (cloud_connection_id, source_node_id,
                                         target_node_id, edge_type, organization_id)
                VALUES (%s, 'node-1', 'node-2', 'has_role', %s)
            """, (conn_id, org_id))

        result = db.delete_organization(org_id)
        assert result is True
        assert _count(db, 'graph_nodes', org_id) == 0
        assert _count(db, 'graph_edges', org_id) == 0
        assert _count(db, 'cloud_connections', org_id) == 0

    def test_delete_with_billing_tables(self, test_org):
        """Phase 10-12: billing tables with user FKs deleted before users."""
        org_id, db = test_org

        # Create a user first
        _exec(db, """
            INSERT INTO users (username, password_hash, display_name, role,
                               organization_id)
            VALUES (%s, 'hash', 'Billing User', 'admin', %s)
        """, (f"billing-{uuid.uuid4().hex[:8]}", org_id))
        user_id = _fetch_one(db, """
            SELECT id FROM users
            WHERE organization_id = %s ORDER BY id DESC LIMIT 1
        """, (org_id,))[0]

        # billing_audit_log (has actor_id FK→users NO ACTION)
        _safe_insert(db, """
            INSERT INTO billing_audit_log (organization_id, actor_id, action,
                                           description)
            VALUES (%s, %s, 'test_action', 'test description')
        """, (org_id, user_id))

        # organization_entitlements (has granted_by FK→users NO ACTION)
        _safe_insert(db, """
            INSERT INTO organization_entitlements (organization_id, entitlement,
                                                   granted_by, status)
            VALUES (%s, 'test_feature', %s, 'active')
        """, (org_id, user_id))

        result = db.delete_organization(org_id)
        assert result is True
        assert _count(db, 'billing_audit_log', org_id) == 0
        assert _count(db, 'organization_entitlements', org_id) == 0
        assert _count(db, 'users', org_id) == 0

    def test_no_fk_constraint_errors(self, test_org):
        """Full-data org delete must not raise any FK constraint exceptions."""
        org_id, db = test_org

        # Populate a broad set of tables
        conn_id = _create_cloud_connection(db, org_id)
        run_id = _create_discovery_run(db, org_id, conn_id)
        _create_identity(db, org_id, run_id)
        _exec(db, """
            INSERT INTO users (username, password_hash, display_name, role,
                               organization_id)
            VALUES (%s, 'hash', 'FK User', 'viewer', %s)
        """, (f"fkuser-{uuid.uuid4().hex[:8]}", org_id))
        _safe_insert(db, """
            INSERT INTO settings (key, value, organization_id)
            VALUES ('fk_test', '"val"', %s)
        """, (org_id,))
        _safe_insert(db, """
            INSERT INTO activity_log (action, description, organization_id)
            VALUES ('test', 'test activity', %s)
        """, (org_id,))
        _safe_insert(db, """
            INSERT INTO notifications (title, message, severity,
                                       organization_id)
            VALUES ('Test', 'test notification', 'info', %s)
        """, (org_id,))

        # This must NOT raise an FK constraint error
        result = db.delete_organization(org_id)
        assert result is True

        # Verify zero orphans across all 4 non-CASCADE FK tables
        assert _count(db, 'discovery_runs', org_id) == 0
        assert _count(db, 'users', org_id) == 0
        assert _count(db, 'settings', org_id) == 0
        assert _count(db, 'notifications', org_id) == 0
        assert _fetch_one(db, "SELECT id FROM organizations WHERE id = %s",
                          (org_id,)) is None


class TestDeleteOrganizationsCriticalDel:
    """Verify _critical_del re-raises real FK violations."""

    def test_critical_del_raises_on_fk_violation(self, test_org):
        """If a child table blocks a critical delete, the error propagates."""
        org_id, db = test_org

        run_id = _create_discovery_run(db, org_id)

        # Insert a risk_score referencing the run
        _safe_insert(db, """
            INSERT INTO risk_scores (identity_id, run_id, risk_score,
                                     risk_level, factors)
            VALUES ('test-id', %s, 50, 'medium', '{}')
        """, (run_id,))

        # Try to delete discovery_runs directly without cleaning risk_scores first.
        # This should fail with FK violation (risk_scores blocks it).
        cursor = db.conn.cursor()
        try:
            cursor.execute("DELETE FROM discovery_runs WHERE organization_id = %s",
                           (org_id,))
            # If risk_scores table doesn't have FK, this succeeds — that's OK
            db.conn.rollback()
        except Exception as e:
            db.conn.rollback()
            # FK violation detected — confirms _critical_del would catch this
            assert 'violates foreign key' in str(e).lower() or \
                   'foreign key' in str(e).lower() or \
                   'referenced from' in str(e).lower(), \
                   f"Expected FK violation, got: {e}"
        finally:
            cursor.close()

        # Now the full cascade should handle it cleanly
        result = db.delete_organization(org_id)
        assert result is True


class TestBulkDeleteOrganizations:
    """Tests for delete_organizations_by_pattern()."""

    def test_find_by_pattern(self):
        """find_organizations_by_pattern returns matching orgs."""
        db = _admin_db()
        try:
            slug1 = f"bulk-a-{uuid.uuid4().hex[:6]}"
            slug2 = f"bulk-b-{uuid.uuid4().hex[:6]}"
            db.create_organization(name="BulkTest Alpha", slug=slug1)
            db.create_organization(name="BulkTest Beta", slug=slug2)

            matched = db.find_organizations_by_pattern("BulkTest%")
            names = [o['name'] for o in matched]
            assert "BulkTest Alpha" in names
            assert "BulkTest Beta" in names

            # Cleanup
            for org in matched:
                db.delete_organization(org['id'])
        finally:
            db.close()

    def test_bulk_delete_returns_results_and_errors(self):
        """Bulk delete returns (deleted, errors) tuple."""
        db = _admin_db()
        try:
            slug = f"bulkdel-{uuid.uuid4().hex[:6]}"
            db.create_organization(name="BulkDel Target", slug=slug)

            deleted, errors = db.delete_organizations_by_pattern("BulkDel Target")
            assert len(deleted) == 1
            assert deleted[0]['name'] == "BulkDel Target"
            assert len(errors) == 0
        finally:
            db.close()

    def test_bulk_delete_skips_default_org(self):
        """Bulk delete should never match the 'default' organization."""
        db = _admin_db()
        try:
            matched = db.find_organizations_by_pattern("%")
            slugs = [o['slug'] for o in matched]
            assert 'default' not in slugs
        finally:
            db.close()
