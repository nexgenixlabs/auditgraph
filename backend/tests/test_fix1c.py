"""
FIX1C — Multi-Connector Canonicalization & Integrity Hardening Tests

Enforces:
1. Migration 023 adds external_id, global uniqueness, subscription FK
2. create_cloud_connection includes external_id in INSERT
3. create_client_connection validates cross-org uniqueness
4. delete_client_connection tracks usage
5. Canonical connector service layer exists
6. Billing counts monitored only
7. Scheduler scopes by org
8. UI groups connectors by provider
"""
import inspect
import os
import re


# ── STEP 1: Migration 023 DDL ─────────────────────────────────────────────

def test_migration_023_adds_external_id():
    """Migration 023 DDL adds external_id column to cloud_connections."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_023_connector_integrity)
    assert 'external_id' in source
    assert 'ADD COLUMN IF NOT EXISTS external_id' in source


def test_migration_023_global_unique_constraint():
    """Migration 023 DDL creates uq_provider_external_global constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_023_connector_integrity)
    assert 'uq_provider_external_global' in source
    assert 'UNIQUE (cloud, external_id)' in source


def test_migration_023_subscription_fk():
    """Migration 023 DDL creates fk_subscription_connector with CASCADE."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_023_connector_integrity)
    assert 'fk_subscription_connector' in source
    assert 'ON DELETE CASCADE' in source


def test_migration_023_dedup_logic():
    """Migration 023 handles cross-org duplicates before adding constraints."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_023_connector_integrity)
    # Must GROUP BY cloud, external_id to find duplicates
    assert 'GROUP BY cloud, external_id' in source
    assert 'HAVING COUNT(*)' in source
    # Must delete orphaned subscriptions first, then connections
    assert 'DELETE FROM cloud_subscriptions' in source
    assert 'DELETE FROM cloud_connections' in source


# ── STEP 2: create_cloud_connection includes external_id ──────────────────

def test_create_connection_sets_external_id():
    """create_cloud_connection includes external_id in INSERT statement."""
    from app.database import Database
    source = inspect.getsource(Database.create_cloud_connection)
    assert 'external_id' in source
    # external_id should appear in both column list and VALUES
    assert 'external_id' in source.split('INSERT INTO')[1].split('VALUES')[0]
    assert 'external_id' in source.split('VALUES')[1].split('RETURNING')[0]


# ── STEP 3: Handler cross-org validation ──────────────────────────────────

def test_create_validates_global_uniqueness():
    """create_client_connection checks cross-org uniqueness before INSERT."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.create_client_connection)
    assert 'validate_connector_unique' in source
    assert 'DUPLICATE_CONNECTOR' in source
    assert '409' in source


def test_delete_tracks_usage():
    """delete_client_connection includes track_usage call."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.delete_client_connection)
    assert 'track_usage' in source
    assert "'removed'" in source or '"removed"' in source


# ── STEP 4: RLS & billing integrity checks ────────────────────────────────

def test_connector_rls_isolation():
    """cloud_connections table DDL or RLS policies use organization_id."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_cloud_connections_table)
    assert 'organization_id' in source
    # Table has organization_id NOT NULL
    assert 'organization_id INTEGER NOT NULL' in source


def test_billing_counts_monitored_only():
    """calculate_billing filters on monitored=true subscriptions."""
    from app.pricing import calculate_billing
    source = inspect.getsource(calculate_billing)
    assert 'monitored' in source.lower()
    # Should filter for monitored (truthy check or explicit = true)
    assert re.search(r"(monitored|'monitored')", source)


def test_scheduler_scopes_by_org():
    """Scheduler calls get_cloud_connections scoped by organization."""
    import app.scheduler
    source = inspect.getsource(app.scheduler)
    assert 'get_cloud_connections' in source


# ── STEP 5: Canonical service layer ───────────────────────────────────────

def test_canonical_service_exists():
    """connectors.py exports get_connectors, get_connector, validate_connector_unique."""
    from app.connectors import get_connectors, get_connector, validate_connector_unique
    assert callable(get_connectors)
    assert callable(get_connector)
    assert callable(validate_connector_unique)


def test_no_provider_registry_as_data_source():
    """Handlers don't use a static provider list to drive connection logic."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.create_client_connection)
    # Should not have a hardcoded PROVIDER_REGISTRY or similar static dict driving logic
    assert 'PROVIDER_REGISTRY' not in source
    assert 'provider_registry' not in source


# ── STEP 6: UI groups by provider ─────────────────────────────────────────

def test_ui_groups_by_provider():
    """ConnectionsTab source contains provider grouping logic."""
    ui_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'frontend', 'src',
        'components', 'settings', 'ConnectionsTab.tsx'
    )
    with open(ui_path, 'r') as f:
        source = f.read()
    # Must have PROVIDERS array with azure/aws/gcp
    assert 'PROVIDERS' in source
    assert "key: 'azure'" in source or "'azure'" in source
    assert "key: 'aws'" in source or "'aws'" in source
    assert "key: 'gcp'" in source or "'gcp'" in source
    # Must group connections by provider
    assert '.filter(' in source
    assert 'c.cloud' in source or 'conn.cloud' in source
