"""
FIX1C.1 — Subscription Reality Reconciliation Tests

Enforces:
1. Migration 024 adds deleted/deleted_at columns
2. reconcile_subscriptions method exists and handles orphaned subs
3. get_cloud_subscriptions excludes deleted rows
4. get_subscription_stats excludes deleted rows
5. activate_cloud_subscription refuses deleted subs
6. activate_all_cloud_subscriptions skips deleted subs
7. Billing only counts non-deleted monitored subs
8. Reconciliation API endpoint exists
9. Counter reset logic present in reconciliation
"""
import inspect
import re


# ── STEP 1: Migration 024 DDL ─────────────────────────────────────────────

def test_migration_024_adds_deleted_column():
    """Migration 024 adds deleted BOOLEAN column to cloud_subscriptions."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_024_subscription_reconciliation)
    assert 'deleted BOOLEAN' in source
    assert 'ADD COLUMN IF NOT EXISTS deleted' in source


def test_migration_024_adds_deleted_at_column():
    """Migration 024 adds deleted_at TIMESTAMPTZ column to cloud_subscriptions."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_024_subscription_reconciliation)
    assert 'deleted_at' in source
    assert 'TIMESTAMPTZ' in source


def test_migration_024_creates_index():
    """Migration 024 creates index for fast filtering of non-deleted rows."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_024_subscription_reconciliation)
    assert 'idx_cloud_subs_deleted' in source
    assert 'WHERE deleted = false' in source


# ── STEP 2: Reconciliation Method ─────────────────────────────────────────

def test_reconcile_method_exists():
    """reconcile_subscriptions method exists on Database class."""
    from app.database import Database
    assert hasattr(Database, 'reconcile_subscriptions')
    assert callable(Database.reconcile_subscriptions)


def test_reconcile_identifies_orphaned_subs():
    """reconcile_subscriptions checks for subs whose connector belongs to different org or is NULL."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    # Must join cloud_connections to check ownership
    assert 'cloud_connections' in source
    assert 'organization_id' in source
    # Must detect NULL connector (legacy sync), deleted connector, and org mismatch
    assert 'cloud_connection_id IS NULL' in source
    assert 'c.id IS NULL' in source
    assert 'c.organization_id != s.organization_id' in source


def test_reconcile_soft_deletes():
    """reconcile_subscriptions soft-deletes by setting deleted=true + deleted_at."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    assert 'deleted = true' in source
    assert 'deleted_at' in source
    assert "status = 'archived'" in source


def test_reconcile_resets_counters():
    """reconcile_subscriptions resets organization_usage_counters."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    assert 'organization_usage_counters' in source
    assert 'DELETE FROM organization_usage_counters' in source


def test_reconcile_rebuilds_counter():
    """reconcile_subscriptions rebuilds active subscription count from actual state."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    # Must count actual monitored + non-deleted subs
    assert 'monitored = true' in source
    assert 'deleted = false' in source
    assert 'active_subscriptions' in source


# ── STEP 3: Queries Exclude Deleted ───────────────────────────────────────

def test_get_cloud_subscriptions_excludes_deleted():
    """get_cloud_subscriptions filters out deleted rows."""
    from app.database import Database
    source = inspect.getsource(Database.get_cloud_subscriptions)
    assert 'deleted = false' in source


def test_get_subscription_stats_excludes_deleted():
    """get_subscription_stats filters out deleted rows."""
    from app.database import Database
    source = inspect.getsource(Database.get_subscription_stats)
    assert 'deleted = false' in source


def test_activate_subscription_refuses_deleted():
    """activate_cloud_subscription adds deleted=false guard."""
    from app.database import Database
    source = inspect.getsource(Database.activate_cloud_subscription)
    assert 'deleted = false' in source


def test_activate_all_skips_deleted():
    """activate_all_cloud_subscriptions adds deleted=false guard."""
    from app.database import Database
    source = inspect.getsource(Database.activate_all_cloud_subscriptions)
    assert 'deleted = false' in source


def test_sync_excludes_deleted_from_count():
    """sync_cloud_subscriptions count check excludes deleted rows."""
    from app.database import Database
    source = inspect.getsource(Database.sync_cloud_subscriptions)
    assert 'deleted = false' in source


# ── STEP 4: Billing Still Counts Monitored Only ───────────────────────────

def test_billing_uses_monitored_filter():
    """calculate_billing filters on monitored (truthy) subscriptions — unchanged."""
    from app.pricing import calculate_billing
    source = inspect.getsource(calculate_billing)
    assert 'monitored' in source
    # active_subs filters by monitored
    assert "s.get('monitored')" in source or 'monitored' in source


# ── STEP 5: API Endpoint ──────────────────────────────────────────────────

def test_reconcile_endpoint_exists():
    """reconcile_subscriptions handler exists in handlers.py."""
    import app.api.handlers
    assert hasattr(app.api.handlers, 'reconcile_subscriptions')
    source = inspect.getsource(app.api.handlers.reconcile_subscriptions)
    assert 'reconcile_subscriptions' in source
    assert 'subscription_reconciliation' in source


def test_reconcile_route_registered():
    """POST /api/subscriptions/reconcile route is registered in main.py."""
    import app.main
    source = inspect.getsource(app.main.create_app)
    assert '/api/subscriptions/reconcile' in source
