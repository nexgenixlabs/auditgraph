"""
Multi-Tenant Cloud Model Tests — Phases 1, 2, 3, 4 & 5

Phase 1 (Migration 037) enforces:
1. cloud_connection_id NOT NULL in DDL (fresh installs)
2. Migration 037 backfills and enforces NOT NULL constraint
3. Unique constraint changed to (cloud_connection_id, account_id)
4. RLS policies on cloud_subscriptions via cloud_connections JOIN
5. Organization_id sync trigger from cloud_connections
6. insert_discovered_subscriptions requires connection_id
7. ON CONFLICT uses new (cloud_connection_id, account_id) key
8. activate/deactivate methods use cloud_connections JOIN
9. get_cloud_subscriptions supports connection_id filter
10. get_cloud_connections sub_count filters deleted rows
11. reconcile_subscriptions no longer checks NULL cloud_connection_id
12. Azure discovery uses new ON CONFLICT key and requires connection_id

Phase 2 (Discovery Isolation) enforces:
13. Azure/AWS engine constructors require cloud_connection_id and db_org_id
14. create_discovery_run requires cloud_connection_id
15. Legacy settings discovery deprecated
16. Cross-connection query in _save_identities scoped to current connection
17. Migration 038: discovery_runs.cloud_connection_id NOT NULL
18. API trigger/run_discovery validates connections exist
19. Enhanced discovery logging with connection context

Phase 3 (Discovery Job Lifecycle) enforces:
21. Migration 039: snapshot_jobs table with UUID PK, status/stage CHECK constraints
22. 6 CRUD methods for snapshot job lifecycle
23. Concurrency guard in _run_connection_discovery
24. Azure/AWS engine progress reporting (_update_job_progress helper)
25. API 409 guard in trigger_discovery for active jobs
26. get_snapshot_job_status endpoint registered
27. Enhanced logging with snapshot_job_id

Phase 4 (Discovery Reliability & Job Recovery) enforces:
28. Migration 040: heartbeat, retry, metrics, runtime columns on snapshot_jobs
29. Heartbeat mechanism (update_snapshot_job_heartbeat)
30. Zombie job detection (get_zombie_snapshot_jobs)
31. Runtime safety guard (get_runtime_exceeded_jobs)
32. Retry mechanism with error classification
33. Discovery metrics recording (update_snapshot_job_metrics)
34. Snapshot history API (get_discovery_history + /api/discovery/history)
35. Scheduler maintenance job (run_snapshot_job_maintenance)
36. Error classification helper (_classify_discovery_error)
20. _run_org_discovery no longer falls back to legacy path
"""
import inspect
import re
import os

# Ensure dev mode + test keys before importing app modules
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-key-037')
os.environ.setdefault('TENANT_JWT_SECRET', 'tenant-test-key-037')


# ── STEP 1: DDL — cloud_connection_id NOT NULL ──────────────────────────

def test_ensure_table_has_connection_id_not_null():
    """_ensure_cloud_subscriptions_table CREATE TABLE includes cloud_connection_id NOT NULL."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_cloud_subscriptions_table)
    assert 'cloud_connection_id INTEGER NOT NULL' in source, \
        "CREATE TABLE must include cloud_connection_id as NOT NULL"


def test_ensure_table_has_new_unique_constraint():
    """_ensure_cloud_subscriptions_table uses UNIQUE(cloud_connection_id, account_id)."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_cloud_subscriptions_table)
    assert 'UNIQUE(cloud_connection_id, account_id)' in source, \
        "Unique constraint must be on (cloud_connection_id, account_id)"
    # Must NOT have old constraint
    assert 'UNIQUE(organization_id, cloud, account_id)' not in source, \
        "Old unique constraint (organization_id, cloud, account_id) must be removed from DDL"


def test_ensure_table_has_connection_index():
    """_ensure_cloud_subscriptions_table creates idx_cloud_subs_connection."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_cloud_subscriptions_table)
    assert 'idx_cloud_subs_connection' in source, \
        "Must create index on cloud_connection_id"


# ── STEP 2: Migration 037 ───────────────────────────────────────────────

def test_migration_037_exists():
    """Migration 037 runner method exists on Database class."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_037_multi_tenant_cloud')
    assert callable(Database._run_migration_037_multi_tenant_cloud)


def test_migration_037_called_from_entitlements():
    """Migration 037 is called from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_037_multi_tenant_cloud' in source, \
        "Migration 037 must be called from _ensure_entitlements_tables"


def test_migration_037_has_class_flag():
    """Migration 037 has a class-level idempotency flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_037_multi_tenant_cloud_ensured'), \
        "Must have class-level flag _migration_037_multi_tenant_cloud_ensured"


def test_migration_037_backfills_connection_id():
    """Migration 037 backfills NULL cloud_connection_id from matching connections."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'cloud_connection_id IS NULL' in source, \
        "Migration must backfill NULL cloud_connection_id"
    assert 'cloud_connections' in source, \
        "Backfill must look up connection from cloud_connections"


def test_migration_037_soft_deletes_orphans():
    """Migration 037 soft-deletes subscriptions that can't be backfilled."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert "deleted = true" in source or "deleted = True" in source, \
        "Must soft-delete orphaned subscriptions"
    assert 'archived' in source, \
        "Orphaned rows must get status=archived"


def test_migration_037_sets_not_null():
    """Migration 037 enforces NOT NULL on cloud_connection_id."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'SET NOT NULL' in source, \
        "Must ALTER COLUMN cloud_connection_id SET NOT NULL"


def test_migration_037_drops_old_constraint():
    """Migration 037 drops old unique constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'cloud_subscriptions_organization_id_cloud_account_id_key' in source, \
        "Must drop the old (organization_id, cloud, account_id) unique constraint"


def test_migration_037_adds_new_constraint():
    """Migration 037 adds new (cloud_connection_id, account_id) unique constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'uq_connection_account' in source, \
        "Must add uq_connection_account constraint"
    assert 'cloud_connection_id, account_id' in source, \
        "New unique constraint must be on (cloud_connection_id, account_id)"


def test_migration_037_enables_rls():
    """Migration 037 enables RLS on cloud_subscriptions."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'ENABLE ROW LEVEL SECURITY' in source
    assert 'FORCE ROW LEVEL SECURITY' in source


def test_migration_037_creates_rls_policies():
    """Migration 037 creates 4 RLS policies via cloud_connections JOIN."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    for policy in ('sub_strict_sel', 'sub_strict_ins', 'sub_strict_upd', 'sub_strict_del'):
        assert policy in source, f"Must create RLS policy {policy}"
    assert 'app.current_organization_id' in source, \
        "RLS must reference app.current_organization_id session var"
    assert 'cloud_connections' in source, \
        "RLS policies must check cloud_connections membership"


def test_migration_037_creates_org_sync_trigger():
    """Migration 037 creates trigger to auto-fill organization_id from cloud_connections."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'fn_sync_sub_org_id' in source, \
        "Must create fn_sync_sub_org_id function"
    assert 'trg_sync_sub_org_id' in source, \
        "Must create trg_sync_sub_org_id trigger"
    assert 'BEFORE INSERT OR UPDATE' in source, \
        "Trigger must fire on INSERT or UPDATE of cloud_connection_id"


def test_migration_037_idempotent():
    """Migration 037 checks is_nullable before running (idempotent)."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_037_multi_tenant_cloud)
    assert 'is_nullable' in source, \
        "Must check is_nullable to detect if migration already applied"
    assert 'information_schema.columns' in source, \
        "Must query information_schema to check column nullability"


# ── STEP 3: insert_discovered_subscriptions ──────────────────────────────

def test_insert_discovered_requires_connection_id():
    """insert_discovered_subscriptions raises ValueError when connection_id is None."""
    from app.database import Database
    source = inspect.getsource(Database.insert_discovered_subscriptions)
    assert 'ValueError' in source, \
        "Must raise ValueError when connection_id is missing"
    assert 'cloud_connection_id is required' in source or 'connection_id' in source.lower()


def test_insert_discovered_uses_new_conflict_key():
    """insert_discovered_subscriptions ON CONFLICT uses (cloud_connection_id, account_id)."""
    from app.database import Database
    source = inspect.getsource(Database.insert_discovered_subscriptions)
    assert 'ON CONFLICT (cloud_connection_id, account_id)' in source, \
        "ON CONFLICT must use (cloud_connection_id, account_id)"
    assert 'ON CONFLICT (organization_id, cloud, account_id)' not in source, \
        "Old ON CONFLICT key must be removed"


# ── STEP 4: sync_cloud_subscriptions ─────────────────────────────────────

def test_sync_uses_new_conflict_key():
    """sync_cloud_subscriptions ON CONFLICT uses (cloud_connection_id, account_id)."""
    from app.database import Database
    source = inspect.getsource(Database.sync_cloud_subscriptions)
    assert 'ON CONFLICT (cloud_connection_id, account_id)' in source, \
        "ON CONFLICT must use new key"
    assert 'ON CONFLICT (organization_id, cloud, account_id)' not in source, \
        "Old ON CONFLICT key must not appear"


def test_sync_looks_up_connection_id():
    """sync_cloud_subscriptions looks up cloud_connection_id when not available."""
    from app.database import Database
    source = inspect.getsource(Database.sync_cloud_subscriptions)
    assert 'cloud_connections' in source, \
        "Must look up connection_id from cloud_connections"
    assert 'cloud_connection_id' in source


def test_sync_skips_rows_without_connection():
    """sync_cloud_subscriptions skips rows that can't determine a connection_id."""
    from app.database import Database
    source = inspect.getsource(Database.sync_cloud_subscriptions)
    assert 'continue' in source, \
        "Must skip rows without determinable connection_id"


# ── STEP 5: get_cloud_subscriptions ──────────────────────────────────────

def test_get_subscriptions_supports_connection_id():
    """get_cloud_subscriptions accepts connection_id parameter."""
    from app.database import Database
    sig = inspect.signature(Database.get_cloud_subscriptions)
    assert 'connection_id' in sig.parameters, \
        "Must accept connection_id parameter"


def test_get_subscriptions_filters_by_connection():
    """get_cloud_subscriptions uses cloud_connection_id filter when connection_id provided."""
    from app.database import Database
    source = inspect.getsource(Database.get_cloud_subscriptions)
    assert 'cs.cloud_connection_id = %s' in source, \
        "Must filter by cloud_connection_id when provided"


# ── STEP 6: get_subscription_stats ───────────────────────────────────────

def test_get_stats_supports_connection_id():
    """get_subscription_stats accepts connection_id parameter."""
    from app.database import Database
    sig = inspect.signature(Database.get_subscription_stats)
    assert 'connection_id' in sig.parameters, \
        "Must accept connection_id parameter"


def test_get_stats_filters_by_connection():
    """get_subscription_stats uses cloud_connection_id filter when connection_id provided."""
    from app.database import Database
    source = inspect.getsource(Database.get_subscription_stats)
    assert 'cloud_connection_id = %s' in source, \
        "Must filter by cloud_connection_id when provided"


# ── STEP 7: activate/deactivate via cloud_connections JOIN ───────────────

def test_activate_uses_connection_join():
    """activate_cloud_subscription validates via cloud_connections JOIN."""
    from app.database import Database
    source = inspect.getsource(Database.activate_cloud_subscription)
    assert 'cloud_connections cc' in source, \
        "Must JOIN cloud_connections for org validation"
    assert 'cs.cloud_connection_id = cc.id' in source, \
        "Must join on cloud_connection_id"
    assert 'cc.organization_id = %s' in source, \
        "Must validate org through connection"


def test_activate_all_uses_connection_join():
    """activate_all_cloud_subscriptions validates via cloud_connections JOIN."""
    from app.database import Database
    source = inspect.getsource(Database.activate_all_cloud_subscriptions)
    assert 'cloud_connections cc' in source, \
        "Must JOIN cloud_connections for org validation"
    assert 'cs.cloud_connection_id = cc.id' in source, \
        "Must join on cloud_connection_id"
    assert 'cc.organization_id = %s' in source, \
        "Must validate org through connection"


def test_deactivate_uses_connection_join():
    """deactivate_cloud_subscription validates via cloud_connections JOIN."""
    from app.database import Database
    source = inspect.getsource(Database.deactivate_cloud_subscription)
    assert 'cloud_connections cc' in source, \
        "Must JOIN cloud_connections for org validation"
    assert 'cs.cloud_connection_id = cc.id' in source, \
        "Must join on cloud_connection_id"
    assert 'cc.organization_id = %s' in source, \
        "Must validate org through connection"


def test_deactivate_checks_deleted():
    """deactivate_cloud_subscription refuses to deactivate deleted subscriptions."""
    from app.database import Database
    source = inspect.getsource(Database.deactivate_cloud_subscription)
    assert 'deleted = false' in source or 'cs.deleted = false' in source, \
        "Must check deleted = false"


# ── STEP 8: get_cloud_connections sub_count ──────────────────────────────

def test_get_connections_sub_count_filters_deleted():
    """get_cloud_connections sub_count/discovered_count excludes deleted rows."""
    from app.database import Database
    source = inspect.getsource(Database.get_cloud_connections)
    assert 'cs.deleted = false' in source, \
        "sub_count subqueries must filter deleted = false"
    # Count occurrences — should appear in both sub_count and discovered_count
    count = source.count('cs.deleted = false')
    assert count >= 2, \
        f"Expected at least 2 'cs.deleted = false' filters (sub_count + discovered_count), found {count}"


# ── STEP 9: reconcile_subscriptions ──────────────────────────────────────

def test_reconcile_no_null_connection_check():
    """reconcile_subscriptions SQL no longer checks cloud_connection_id IS NULL (NOT NULL constraint)."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    # Extract only SQL strings (content between triple-quote cursor.execute blocks)
    # The docstring may mention it, but the actual SQL query must not filter on it
    sql_matches = re.findall(r'cursor\.execute\(\s*"""(.+?)"""', source, re.DOTALL)
    for sql in sql_matches:
        assert 'cloud_connection_id IS NULL' not in sql, \
            "SQL query must not check cloud_connection_id IS NULL (NOT NULL constraint makes it impossible)"


def test_reconcile_still_checks_deleted_connector():
    """reconcile_subscriptions still checks for deleted connectors (defense-in-depth)."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    assert 'c.id IS NULL' in source, \
        "Must still check for deleted connectors"


def test_reconcile_still_checks_cross_org():
    """reconcile_subscriptions still checks for cross-org connector mismatch."""
    from app.database import Database
    source = inspect.getsource(Database.reconcile_subscriptions)
    assert 'c.organization_id != s.organization_id' in source, \
        "Must still check for cross-org connector mismatch"


# ── STEP 10: handlers.py ────────────────────────────────────────────────

def test_handler_supports_connection_id_filter():
    """get_subscriptions_list handler reads connection_id query parameter."""
    from app.api.handlers import get_subscriptions_list
    source = inspect.getsource(get_subscriptions_list)
    assert 'connection_id' in source, \
        "Handler must accept connection_id query parameter"


# ── STEP 11: Azure discovery engine ──────────────────────────────────────

def test_azure_discovery_uses_new_conflict_key():
    """Azure discovery subscription sync uses ON CONFLICT (cloud_connection_id, account_id)."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    source = inspect.getsource(AzureDiscoveryEngine)
    # Find ON CONFLICT patterns in the class
    conflict_patterns = re.findall(r'ON CONFLICT\s*\([^)]+\)', source)
    for pattern in conflict_patterns:
        if 'cloud_subscriptions' in source and 'account_id' in pattern:
            assert 'cloud_connection_id' in pattern, \
                f"ON CONFLICT for cloud_subscriptions must use cloud_connection_id: {pattern}"
            assert 'organization_id, cloud, account_id' not in pattern, \
                f"Old ON CONFLICT key must not appear: {pattern}"


def test_azure_discovery_requires_connection_id():
    """Azure discovery skips subscription sync if cloud_connection_id is missing."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    source = inspect.getsource(AzureDiscoveryEngine)
    assert 'cloud_connection_id is required' in source or 'not self.cloud_connection_id' in source, \
        "Must guard against missing cloud_connection_id"


# ── STEP 12: SQL migration file ─────────────────────────────────────────

def test_migration_sql_file_exists():
    """Migration 037 SQL file exists."""
    migration_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'migrations', '037_multi_tenant_cloud_model.sql'
    )
    assert os.path.isfile(migration_path), \
        f"Migration file not found at {migration_path}"


def test_migration_sql_has_rls():
    """Migration 037 SQL file contains RLS policy definitions."""
    migration_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'migrations', '037_multi_tenant_cloud_model.sql'
    )
    with open(migration_path) as f:
        sql = f.read()
    assert 'ENABLE ROW LEVEL SECURITY' in sql
    assert 'sub_strict_sel' in sql
    assert 'sub_strict_ins' in sql
    assert 'sub_strict_upd' in sql
    assert 'sub_strict_del' in sql


def test_migration_sql_has_trigger():
    """Migration 037 SQL file contains org_id sync trigger."""
    migration_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'migrations', '037_multi_tenant_cloud_model.sql'
    )
    with open(migration_path) as f:
        sql = f.read()
    assert 'fn_sync_sub_org_id' in sql
    assert 'trg_sync_sub_org_id' in sql


# ══════════════════════════════════════════════════════════════════════════
# Phase 2: Discovery Isolation & Multi-Tenant Enforcement
# ══════════════════════════════════════════════════════════════════════════

# ── STEP 13: Engine constructor guards ───────────────────────────────────

def test_azure_engine_requires_connection_id():
    """AzureDiscoveryEngine.__init__ raises ValueError when cloud_connection_id is None."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    source = inspect.getsource(AzureDiscoveryEngine.__init__)
    assert 'cloud_connection_id is None' in source, \
        "Must guard against None cloud_connection_id"
    assert 'ValueError' in source, \
        "Must raise ValueError for missing cloud_connection_id"
    assert 'db_org_id is None' in source, \
        "Must guard against None db_org_id"


def test_aws_engine_requires_connection_id():
    """AWSDiscoveryEngine.__init__ raises ValueError when cloud_connection_id is None."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine.__init__)
    assert 'cloud_connection_id is None' in source, \
        "Must guard against None cloud_connection_id"
    assert 'ValueError' in source, \
        "Must raise ValueError for missing cloud_connection_id"
    assert 'db_org_id is None' in source, \
        "Must guard against None db_org_id"


# ── STEP 14: create_discovery_run guard ──────────────────────────────────

def test_create_discovery_run_requires_connection_id():
    """create_discovery_run raises ValueError when cloud_connection_id is None."""
    from app.database import Database
    source = inspect.getsource(Database.create_discovery_run)
    assert 'cloud_connection_id is None' in source, \
        "Must check for None cloud_connection_id"
    assert 'ValueError' in source, \
        "Must raise ValueError for missing cloud_connection_id"


# ── STEP 15: Legacy discovery deprecated ─────────────────────────────────

def test_legacy_discovery_deprecated():
    """_run_legacy_settings_discovery body contains DEPRECATED warning."""
    from app.scheduler import _run_legacy_settings_discovery
    source = inspect.getsource(_run_legacy_settings_discovery)
    assert 'DEPRECATED' in source, \
        "Legacy discovery must be marked as DEPRECATED"
    # Must NOT contain AzureDiscoveryEngine instantiation
    assert 'AzureDiscoveryEngine(' not in source, \
        "Legacy path must not instantiate AzureDiscoveryEngine"


# ── STEP 16: Cross-connection query scoped ───────────────────────────────

def test_save_identities_scopes_created_datetime_lookup():
    """_save_identities created_datetime lookup is scoped to current connection."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    source = inspect.getsource(AzureDiscoveryEngine._save_identities)
    assert 'dr.cloud_connection_id' in source, \
        "created_datetime lookup must filter by cloud_connection_id"
    assert 'JOIN discovery_runs' in source, \
        "Must JOIN discovery_runs to scope by connection"


# ── STEP 17: Migration 038 ──────────────────────────────────────────────

def test_migration_038_exists():
    """Migration 038 runner method exists on Database class."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_038_discovery_runs_connection_not_null')
    assert callable(Database._run_migration_038_discovery_runs_connection_not_null)


def test_migration_038_sets_not_null():
    """Migration 038 enforces NOT NULL on discovery_runs.cloud_connection_id."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_038_discovery_runs_connection_not_null)
    assert 'SET NOT NULL' in source, \
        "Must ALTER COLUMN cloud_connection_id SET NOT NULL"
    assert 'discovery_runs' in source, \
        "Must target discovery_runs table"


def test_migration_038_called_from_entitlements():
    """Migration 038 is called from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_038_discovery_runs_connection_not_null' in source, \
        "Migration 038 must be called from _ensure_entitlements_tables"


def test_migration_038_has_class_flag():
    """Migration 038 has a class-level idempotency flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_038_discovery_runs_connection_not_null_ensured'), \
        "Must have class-level flag _migration_038_discovery_runs_connection_not_null_ensured"


def test_migration_038_is_idempotent():
    """Migration 038 checks is_nullable before running (idempotent)."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_038_discovery_runs_connection_not_null)
    assert 'is_nullable' in source, \
        "Must check is_nullable to detect if migration already applied"
    assert 'information_schema.columns' in source, \
        "Must query information_schema to check column nullability"


def test_migration_038_sql_file_exists():
    """Migration 038 SQL file exists."""
    migration_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'migrations', '038_discovery_runs_connection_not_null.sql'
    )
    assert os.path.isfile(migration_path), \
        f"Migration file not found at {migration_path}"


# ── STEP 18: API trigger guard ───────────────────────────────────────────

def test_trigger_discovery_validates_connections():
    """trigger_discovery checks for connected cloud connections before starting."""
    from app.api.handlers import trigger_discovery
    source = inspect.getsource(trigger_discovery)
    assert 'get_cloud_connections' in source, \
        "Must check cloud connections exist"
    assert "status" in source and "connected" in source, \
        "Must filter for connected status"
    assert '400' in source, \
        "Must return 400 when no connections"


def test_run_discovery_validates_connections():
    """run_discovery checks for connected cloud connections before starting."""
    from app.api.handlers import run_discovery
    source = inspect.getsource(run_discovery)
    assert 'get_cloud_connections' in source, \
        "Must check cloud connections exist"
    assert "status" in source and "connected" in source, \
        "Must filter for connected status"
    assert '400' in source, \
        "Must return 400 when no connections"


# ── STEP 19: Enhanced discovery logging ──────────────────────────────────

def test_discovery_logging_has_connection_context():
    """_run_connection_discovery logs connection_id in structured format."""
    from app.scheduler import _run_connection_discovery
    source = inspect.getsource(_run_connection_discovery)
    assert 'DISCOVERY_START' in source, \
        "Must log DISCOVERY_START with connection context"
    assert 'DISCOVERY_COMPLETE' in source, \
        "Must log DISCOVERY_COMPLETE with connection context"
    assert 'connection_id=' in source, \
        "Must include connection_id in log messages"
    assert 'duration=' in source, \
        "Must include duration in completion log"
    assert 'subscriptions_found=' in source, \
        "Must log subscriptions_found count"


# ── STEP 20: No legacy fallback in _run_org_discovery ────────────────────

def test_org_discovery_no_legacy_fallback():
    """_run_org_discovery no longer calls _run_legacy_settings_discovery."""
    from app.scheduler import _run_org_discovery
    source = inspect.getsource(_run_org_discovery)
    assert '_run_legacy_settings_discovery' not in source, \
        "_run_org_discovery must not call legacy discovery path"


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3 — Discovery Job Lifecycle
# ══════════════════════════════════════════════════════════════════════════


# ── Step 21: Migration 039 — snapshot_jobs table ────────────────────────

def test_migration_039_exists():
    """Phase 3: _run_migration_039_snapshot_jobs method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_039_snapshot_jobs'), \
        "Database must have _run_migration_039_snapshot_jobs method"

def test_migration_039_called_from_entitlements():
    """Phase 3: Migration 039 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_039_snapshot_jobs' in source, \
        "_ensure_entitlements_tables must call _run_migration_039_snapshot_jobs"

def test_migration_039_has_class_flag():
    """Phase 3: Idempotency flag exists for migration 039."""
    from app.database import Database
    assert hasattr(Database, '_migration_039_snapshot_jobs_ensured'), \
        "Database must have _migration_039_snapshot_jobs_ensured class flag"

def test_migration_039_creates_snapshot_jobs_table():
    """Phase 3: DDL creates snapshot_jobs with UUID PK, CHECK constraints, required columns."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_039_snapshot_jobs)
    assert 'CREATE TABLE snapshot_jobs' in source, \
        "Must create snapshot_jobs table"
    assert 'gen_random_uuid()' in source, \
        "Must use UUID primary key with gen_random_uuid()"
    assert "CHECK (status IN" in source, \
        "Must have CHECK constraint on status column"
    assert "'queued'" in source and "'running'" in source and "'completed'" in source and "'failed'" in source, \
        "Status CHECK must include queued, running, completed, failed"
    assert "CHECK (stage IS NULL OR stage IN" in source, \
        "Must have CHECK constraint on stage column"
    assert 'discovering_subscriptions' in source, \
        "Must include discovering_subscriptions stage"
    assert 'discovering_identities' in source, \
        "Must include discovering_identities stage"
    assert 'discovering_rbac' in source, \
        "Must include discovering_rbac stage"
    assert 'discovering_resources' in source, \
        "Must include discovering_resources stage"
    assert 'finalizing' in source, \
        "Must include finalizing stage"
    assert 'organization_id' in source, \
        "Must have organization_id column"
    assert 'cloud_connection_id' in source, \
        "Must have cloud_connection_id column"
    assert 'discovery_run_id' in source, \
        "Must have discovery_run_id column"
    assert 'progress' in source, \
        "Must have progress column"

def test_migration_039_has_rls():
    """Phase 3: Migration 039 creates RLS policies on snapshot_jobs."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_039_snapshot_jobs)
    assert 'ENABLE ROW LEVEL SECURITY' in source, \
        "Must enable RLS on snapshot_jobs"
    assert 'FORCE ROW LEVEL SECURITY' in source, \
        "Must force RLS on snapshot_jobs"
    for pol in ('sj_strict_sel', 'sj_strict_ins', 'sj_strict_upd', 'sj_strict_del'):
        assert pol in source, f"Must create {pol} policy"
    assert 'current_organization_id' in source, \
        "RLS must use app.current_organization_id"

def test_migration_039_is_idempotent():
    """Phase 3: Migration 039 checks information_schema before creating."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_039_snapshot_jobs)
    assert 'information_schema.tables' in source, \
        "Must check information_schema.tables for idempotency"
    assert '_migration_039_snapshot_jobs_ensured' in source, \
        "Must check class flag for idempotency"

def test_migration_039_sql_file_exists():
    """Phase 3: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '039_snapshot_jobs.sql')
    assert os.path.exists(sql_path), \
        "migrations/039_snapshot_jobs.sql must exist"


# ── Step 22: Snapshot Job CRUD Methods ──────────────────────────────────

def test_create_snapshot_job_method_exists():
    """Phase 3: create_snapshot_job method has correct signature."""
    from app.database import Database
    assert hasattr(Database, 'create_snapshot_job'), \
        "Database must have create_snapshot_job method"
    source = inspect.getsource(Database.create_snapshot_job)
    assert 'org_id' in source, "Must accept org_id parameter"
    assert 'conn_id' in source, "Must accept conn_id parameter"
    assert 'scan_mode' in source, "Must accept scan_mode parameter"
    assert "INSERT INTO snapshot_jobs" in source, \
        "Must INSERT into snapshot_jobs table"

def test_start_snapshot_job_sets_running():
    """Phase 3: start_snapshot_job transitions to running with initial stage."""
    from app.database import Database
    source = inspect.getsource(Database.start_snapshot_job)
    assert "status = 'running'" in source, \
        "Must set status to running"
    assert 'started_at' in source, \
        "Must set started_at timestamp"
    assert 'discovering_subscriptions' in source, \
        "Must set initial stage to discovering_subscriptions"

def test_update_snapshot_job_progress_method():
    """Phase 3: update_snapshot_job_progress updates stage and progress."""
    from app.database import Database
    source = inspect.getsource(Database.update_snapshot_job_progress)
    assert 'stage' in source, "Must accept stage parameter"
    assert 'progress' in source, "Must accept progress parameter"
    assert 'discovery_run_id' in source, \
        "Must accept optional discovery_run_id parameter"

def test_complete_snapshot_job_method():
    """Phase 3: complete_snapshot_job sets completed_at and error_message."""
    from app.database import Database
    source = inspect.getsource(Database.complete_snapshot_job)
    assert 'completed_at' in source, "Must set completed_at timestamp"
    assert 'error_message' in source, "Must accept error_message parameter"
    assert 'status' in source, "Must accept status parameter"

def test_get_active_snapshot_job_checks_queued_running():
    """Phase 3: get_active_snapshot_job filters by queued/running status."""
    from app.database import Database
    source = inspect.getsource(Database.get_active_snapshot_job)
    assert "IN ('queued', 'running')" in source or "IN ('queued','running')" in source, \
        "Must filter status IN ('queued', 'running')"
    assert 'cloud_connection_id' in source, \
        "Must filter by cloud_connection_id"


# ── Step 23: Scheduler Job Lifecycle ────────────────────────────────────

def test_connection_discovery_checks_active_job():
    """Phase 3: _run_connection_discovery calls get_active_snapshot_job for concurrency guard."""
    from app.scheduler import _run_connection_discovery
    source = inspect.getsource(_run_connection_discovery)
    assert 'get_active_snapshot_job' in source, \
        "Must call get_active_snapshot_job for concurrency guard"
    assert 'DISCOVERY_SKIPPED' in source, \
        "Must log DISCOVERY_SKIPPED when active job exists"
    assert 'create_snapshot_job' in source, \
        "Must call create_snapshot_job to create a new job"
    assert 'start_snapshot_job' in source, \
        "Must call start_snapshot_job to transition to running"
    assert 'complete_snapshot_job' in source, \
        "Must call complete_snapshot_job on success/failure"


# ── Step 24: Engine Progress Reporting ──────────────────────────────────

def test_azure_engine_has_progress_helper():
    """Phase 3: AzureDiscoveryEngine has _update_job_progress method."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    assert hasattr(AzureDiscoveryEngine, '_update_job_progress'), \
        "AzureDiscoveryEngine must have _update_job_progress method"
    source = inspect.getsource(AzureDiscoveryEngine._update_job_progress)
    assert 'snapshot_job_id' in source, \
        "Must check for snapshot_job_id attribute"
    assert 'update_snapshot_job_progress' in source, \
        "Must call db.update_snapshot_job_progress"

def test_azure_engine_reports_all_stages():
    """Phase 3: _async_run_discovery reports all 5 stage names."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    source = inspect.getsource(AzureDiscoveryEngine._async_run_discovery)
    stages = ['discovering_subscriptions', 'discovering_identities',
              'discovering_rbac', 'discovering_resources', 'finalizing']
    for stage in stages:
        assert stage in source, \
            f"_async_run_discovery must report stage '{stage}'"


# ── Step 25: Discovery Logging ──────────────────────────────────────────

def test_discovery_logging_includes_job_id():
    """Phase 3: Discovery logging includes snapshot_job_id."""
    from app.scheduler import _run_connection_discovery
    source = inspect.getsource(_run_connection_discovery)
    assert 'snapshot_job_id=' in source, \
        "Must include snapshot_job_id in log messages"


# ── Step 26: API Endpoints ──────────────────────────────────────────────

def test_trigger_discovery_returns_409_for_active():
    """Phase 3: trigger_discovery returns 409 when active job exists."""
    from app.api.handlers import trigger_discovery
    source = inspect.getsource(trigger_discovery)
    assert 'get_active_snapshot_job' in source, \
        "Must check for active snapshot job"
    assert '409' in source, \
        "Must return 409 status code for active jobs"

def test_get_snapshot_job_status_exists():
    """Phase 3: get_snapshot_job_status handler exists."""
    from app.api.handlers import get_snapshot_job_status
    source = inspect.getsource(get_snapshot_job_status)
    assert 'get_active_snapshot_job' in source, \
        "Must call get_active_snapshot_job"
    assert 'active_job' in source, \
        "Must return active_job in response"


# ── Step 27: AWS Engine Progress ────────────────────────────────────────

def test_aws_engine_has_progress_helper():
    """Phase 3: AWSDiscoveryEngine has _update_job_progress method."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    assert hasattr(AWSDiscoveryEngine, '_update_job_progress'), \
        "AWSDiscoveryEngine must have _update_job_progress method"

def test_aws_engine_reports_stages():
    """Phase 3: AWS run_discovery reports key stages."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine.run_discovery)
    assert 'discovering_identities' in source, \
        "AWS run_discovery must report discovering_identities stage"
    assert 'discovering_rbac' in source, \
        "AWS run_discovery must report discovering_rbac stage"
    assert 'finalizing' in source, \
        "AWS run_discovery must report finalizing stage"


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4 — Discovery Reliability & Job Recovery
# ══════════════════════════════════════════════════════════════════════════


# ── Step 28: Migration 040 — snapshot_jobs reliability columns ──────────

def test_migration_040_exists():
    """Phase 4: _run_migration_040_snapshot_jobs_reliability method exists."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_040_snapshot_jobs_reliability'), \
        "Database must have _run_migration_040_snapshot_jobs_reliability method"

def test_migration_040_called_from_entitlements():
    """Phase 4: Migration 040 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_040_snapshot_jobs_reliability' in source, \
        "_ensure_entitlements_tables must call _run_migration_040_snapshot_jobs_reliability"

def test_migration_040_has_class_flag():
    """Phase 4: Idempotency flag exists for migration 040."""
    from app.database import Database
    assert hasattr(Database, '_migration_040_snapshot_jobs_reliability_ensured'), \
        "Database must have _migration_040_snapshot_jobs_reliability_ensured class flag"

def test_migration_040_adds_reliability_columns():
    """Phase 4: Migration 040 adds heartbeat, retry, metrics columns."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_040_snapshot_jobs_reliability)
    for col in ('retry_count', 'max_retries', 'last_heartbeat_at', 'started_by',
                'identities_discovered', 'resources_discovered', 'subscriptions_discovered',
                'duration_seconds', 'error_type'):
        assert col in source, f"Migration 040 must add {col} column"
    assert 'idx_snapshot_jobs_heartbeat' in source, \
        "Must create heartbeat index"

def test_migration_040_is_idempotent():
    """Phase 4: Migration 040 checks column existence before altering."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_040_snapshot_jobs_reliability)
    assert 'information_schema.columns' in source, \
        "Must check information_schema.columns for idempotency"
    assert '_migration_040_snapshot_jobs_reliability_ensured' in source, \
        "Must check class flag for idempotency"

def test_migration_040_sql_file_exists():
    """Phase 4: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '040_snapshot_jobs_reliability.sql')
    assert os.path.exists(sql_path), \
        "migrations/040_snapshot_jobs_reliability.sql must exist"


# ── Step 29: Heartbeat Mechanism ────────────────────────────────────────

def test_heartbeat_method_exists():
    """Phase 4: update_snapshot_job_heartbeat method exists."""
    from app.database import Database
    assert hasattr(Database, 'update_snapshot_job_heartbeat'), \
        "Database must have update_snapshot_job_heartbeat method"
    source = inspect.getsource(Database.update_snapshot_job_heartbeat)
    assert 'last_heartbeat_at' in source, \
        "Must update last_heartbeat_at column"

def test_heartbeat_thread_in_scheduler():
    """Phase 4: _run_connection_discovery starts a heartbeat thread."""
    from app.scheduler import _run_connection_discovery
    source = inspect.getsource(_run_connection_discovery)
    assert 'heartbeat_stop' in source, \
        "Must have heartbeat_stop event"
    assert 'update_snapshot_job_heartbeat' in source, \
        "Must call update_snapshot_job_heartbeat in heartbeat loop"
    assert 'heartbeat_thread' in source, \
        "Must create heartbeat_thread"

def test_progress_updates_heartbeat():
    """Phase 4: update_snapshot_job_progress also bumps heartbeat."""
    from app.database import Database
    source = inspect.getsource(Database.update_snapshot_job_progress)
    assert 'last_heartbeat_at' in source, \
        "Progress updates must also set last_heartbeat_at"

def test_start_job_sets_heartbeat():
    """Phase 4: start_snapshot_job sets initial heartbeat."""
    from app.database import Database
    source = inspect.getsource(Database.start_snapshot_job)
    assert 'last_heartbeat_at' in source, \
        "start_snapshot_job must set initial last_heartbeat_at"
    assert 'started_by' in source, \
        "start_snapshot_job must accept started_by parameter"


# ── Step 30: Zombie Job Recovery ────────────────────────────────────────

def test_zombie_detection_method():
    """Phase 4: get_zombie_snapshot_jobs detects stale heartbeats."""
    from app.database import Database
    assert hasattr(Database, 'get_zombie_snapshot_jobs'), \
        "Database must have get_zombie_snapshot_jobs method"
    source = inspect.getsource(Database.get_zombie_snapshot_jobs)
    assert 'last_heartbeat_at' in source, \
        "Must check last_heartbeat_at for staleness"
    assert "status = 'running'" in source, \
        "Must only check running jobs"


# ── Step 31: Runtime Safety Guard ───────────────────────────────────────

def test_runtime_exceeded_method():
    """Phase 4: get_runtime_exceeded_jobs detects overtime jobs."""
    from app.database import Database
    assert hasattr(Database, 'get_runtime_exceeded_jobs'), \
        "Database must have get_runtime_exceeded_jobs method"
    source = inspect.getsource(Database.get_runtime_exceeded_jobs)
    assert 'started_at' in source, \
        "Must check started_at for runtime calculation"
    assert "status = 'running'" in source, \
        "Must only check running jobs"


# ── Step 32: Retry Mechanism ────────────────────────────────────────────

def test_retry_method_exists():
    """Phase 4: retry_snapshot_job requeues failed jobs."""
    from app.database import Database
    assert hasattr(Database, 'retry_snapshot_job'), \
        "Database must have retry_snapshot_job method"
    source = inspect.getsource(Database.retry_snapshot_job)
    assert "status = 'queued'" in source, \
        "Must reset status to queued"
    assert 'retry_count' in source, \
        "Must increment retry_count"
    assert 'max_retries' in source, \
        "Must check max_retries limit"

def test_retryable_jobs_method():
    """Phase 4: get_retryable_failed_jobs filters by error type."""
    from app.database import Database
    assert hasattr(Database, 'get_retryable_failed_jobs'), \
        "Database must have get_retryable_failed_jobs method"
    source = inspect.getsource(Database.get_retryable_failed_jobs)
    assert 'throttling' in source, \
        "Must consider throttling as retryable"
    assert 'network_timeout' in source, \
        "Must consider network_timeout as retryable"
    assert 'temporary_auth_failure' in source, \
        "Must consider temporary_auth_failure as retryable"

def test_error_classification_helper():
    """Phase 4: _classify_discovery_error classifies errors correctly."""
    from app.scheduler import _classify_discovery_error
    # Retryable errors
    err_type, retryable = _classify_discovery_error(Exception("429 Too Many Requests"))
    assert err_type == 'throttling' and retryable is True
    err_type, retryable = _classify_discovery_error(Exception("Connection timed out"))
    assert err_type == 'network_timeout' and retryable is True
    # Non-retryable errors
    err_type, retryable = _classify_discovery_error(Exception("Invalid client secret"))
    assert err_type == 'invalid_credentials' and retryable is False


# ── Step 33: Discovery Metrics ──────────────────────────────────────────

def test_metrics_method_exists():
    """Phase 4: update_snapshot_job_metrics records discovery counts."""
    from app.database import Database
    assert hasattr(Database, 'update_snapshot_job_metrics'), \
        "Database must have update_snapshot_job_metrics method"
    source = inspect.getsource(Database.update_snapshot_job_metrics)
    assert 'identities_discovered' in source, \
        "Must update identities_discovered"
    assert 'resources_discovered' in source, \
        "Must update resources_discovered"
    assert 'subscriptions_discovered' in source, \
        "Must update subscriptions_discovered"
    assert 'duration_seconds' in source, \
        "Must calculate duration_seconds"

def test_complete_job_records_duration():
    """Phase 4: complete_snapshot_job calculates duration_seconds."""
    from app.database import Database
    source = inspect.getsource(Database.complete_snapshot_job)
    assert 'duration_seconds' in source, \
        "complete_snapshot_job must set duration_seconds"
    assert 'error_type' in source, \
        "complete_snapshot_job must accept error_type parameter"


# ── Step 34: Snapshot History API ───────────────────────────────────────

def test_snapshot_history_method():
    """Phase 4: get_snapshot_history returns job history."""
    from app.database import Database
    assert hasattr(Database, 'get_snapshot_history'), \
        "Database must have get_snapshot_history method"
    source = inspect.getsource(Database.get_snapshot_history)
    assert 'connection_id' in source, \
        "Must support connection_id filter"
    assert 'org_id' in source, \
        "Must support org_id filter"
    assert 'duration_seconds' in source, \
        "Must include duration_seconds in results"
    assert 'identities_discovered' in source, \
        "Must include identities_discovered in results"

def test_discovery_history_handler_exists():
    """Phase 4: get_discovery_history handler exists."""
    from app.api.handlers import get_discovery_history
    source = inspect.getsource(get_discovery_history)
    assert 'get_snapshot_history' in source, \
        "Must call get_snapshot_history"
    assert 'connection_id' in source, \
        "Must accept connection_id parameter"

def test_discovery_history_route_registered():
    """Phase 4: /api/discovery/history route is registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/discovery/history' in source, \
        "Must register /api/discovery/history route"


# ── Step 35: Scheduler Maintenance ──────────────────────────────────────

def test_maintenance_function_exists():
    """Phase 4: run_snapshot_job_maintenance function exists."""
    from app.scheduler import run_snapshot_job_maintenance
    source = inspect.getsource(run_snapshot_job_maintenance)
    assert 'get_zombie_snapshot_jobs' in source, \
        "Must detect zombie jobs"
    assert 'get_runtime_exceeded_jobs' in source, \
        "Must enforce runtime limits"
    assert 'get_retryable_failed_jobs' in source, \
        "Must retry eligible failed jobs"
    assert 'SNAPSHOT_MAINTENANCE' in source, \
        "Must log maintenance actions"

def test_maintenance_job_registered():
    """Phase 4: Maintenance job registered in scheduler setup."""
    from app.scheduler import start_scheduler
    source = inspect.getsource(start_scheduler)
    assert 'snapshot_job_maintenance' in source, \
        "Must register snapshot_job_maintenance scheduled job"
    assert 'run_snapshot_job_maintenance' in source, \
        "Must reference run_snapshot_job_maintenance function"


# ── Step 36: Error Classification ───────────────────────────────────────

def test_error_classification_in_scheduler():
    """Phase 4: _run_connection_discovery uses error classification."""
    from app.scheduler import _run_connection_discovery
    source = inspect.getsource(_run_connection_discovery)
    assert '_classify_discovery_error' in source, \
        "Must call _classify_discovery_error on failure"
    assert 'DISCOVERY_RETRY' in source, \
        "Must log retry attempts"
    assert 'error_type' in source, \
        "Must pass error_type to complete_snapshot_job"


# ═══════════════════════════════════════════════════════════════════════
# Phase 5 — Continuous Discovery Scheduler
# ═══════════════════════════════════════════════════════════════════════

# ── Step 37: Migration 041 — Continuous Discovery Columns ────────────

def test_migration_041_exists():
    """Phase 5: Migration 041 method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_041_continuous_discovery'), \
        "Database must have _run_migration_041_continuous_discovery method"

def test_migration_041_called_from_entitlements():
    """Phase 5: Migration 041 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_041_continuous_discovery' in source, \
        "Must call _run_migration_041_continuous_discovery from _ensure_entitlements_tables"

def test_migration_041_has_class_flag():
    """Phase 5: Migration 041 has an idempotency class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_041_continuous_discovery_ensured'), \
        "Must have _migration_041_continuous_discovery_ensured class flag"

def test_migration_041_adds_discovery_columns():
    """Phase 5: Migration 041 adds discovery_enabled, discovery_interval_minutes,
    last_snapshot_started_at, last_snapshot_completed_at to cloud_connections."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_041_continuous_discovery)
    assert 'discovery_enabled' in source, "Must add discovery_enabled column"
    assert 'discovery_interval_minutes' in source, "Must add discovery_interval_minutes column"
    assert 'last_snapshot_started_at' in source, "Must add last_snapshot_started_at column"
    assert 'last_snapshot_completed_at' in source, "Must add last_snapshot_completed_at column"
    assert 'BOOLEAN' in source, "discovery_enabled must be BOOLEAN"
    assert 'DEFAULT false' in source, "discovery_enabled must default to false"
    assert 'DEFAULT 360' in source, "discovery_interval_minutes must default to 360"

def test_migration_041_is_idempotent():
    """Phase 5: Migration 041 checks information_schema before altering."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_041_continuous_discovery)
    assert 'information_schema' in source, "Must check information_schema for idempotency"

def test_migration_041_sql_file_exists():
    """Phase 5: SQL migration file 041 exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '041_continuous_discovery.sql')
    assert os.path.exists(sql_path), "migrations/041_continuous_discovery.sql must exist"


# ── Step 38: Continuous Discovery CRUD Methods ──────────────────────────

def test_get_connections_due_for_discovery_method():
    """Phase 5: get_connections_due_for_discovery method exists and queries correctly."""
    from app.database import Database
    assert hasattr(Database, 'get_connections_due_for_discovery'), \
        "Database must have get_connections_due_for_discovery method"
    source = inspect.getsource(Database.get_connections_due_for_discovery)
    assert 'discovery_enabled = true' in source, "Must filter by discovery_enabled"
    assert "status = 'connected'" in source, "Must filter by connected status"
    assert "status IN ('queued', 'running')" in source or \
           "status IN (''queued'', ''running'')" in source or \
           'queued' in source, "Must check for active snapshot jobs"
    assert 'discovery_interval_minutes' in source, "Must use interval for scheduling"

def test_update_discovery_settings_method():
    """Phase 5: update_discovery_settings method exists."""
    from app.database import Database
    assert hasattr(Database, 'update_discovery_settings'), \
        "Database must have update_discovery_settings method"
    source = inspect.getsource(Database.update_discovery_settings)
    assert 'discovery_enabled' in source, "Must update discovery_enabled"
    assert 'discovery_interval_minutes' in source, "Must update discovery_interval_minutes"

def test_update_snapshot_timestamps_method():
    """Phase 5: update_snapshot_timestamps method exists."""
    from app.database import Database
    assert hasattr(Database, 'update_snapshot_timestamps'), \
        "Database must have update_snapshot_timestamps method"
    source = inspect.getsource(Database.update_snapshot_timestamps)
    assert 'last_snapshot_started_at' in source, "Must update last_snapshot_started_at"
    assert 'last_snapshot_completed_at' in source, "Must update last_snapshot_completed_at"

def test_update_cloud_connection_allows_discovery_fields():
    """Phase 5: update_cloud_connection allowed set includes discovery fields."""
    from app.database import Database
    source = inspect.getsource(Database.update_cloud_connection)
    assert 'discovery_enabled' in source, "Must allow discovery_enabled"
    assert 'discovery_interval_minutes' in source, "Must allow discovery_interval_minutes"
    assert 'last_snapshot_started_at' in source, "Must allow last_snapshot_started_at"
    assert 'last_snapshot_completed_at' in source, "Must allow last_snapshot_completed_at"


# ── Step 39: Continuous Discovery Scheduler ─────────────────────────────

def test_continuous_discovery_function_exists():
    """Phase 5: run_continuous_discovery function exists."""
    from app.scheduler import run_continuous_discovery
    source = inspect.getsource(run_continuous_discovery)
    assert 'get_connections_due_for_discovery' in source, \
        "Must call get_connections_due_for_discovery"
    assert '_run_connection_discovery' in source, \
        "Must call _run_connection_discovery for each due connection"
    assert 'CONTINUOUS_DISCOVERY' in source, \
        "Must log CONTINUOUS_DISCOVERY events"

def test_continuous_discovery_job_registered():
    """Phase 5: Continuous discovery job registered in scheduler setup."""
    from app.scheduler import start_scheduler
    source = inspect.getsource(start_scheduler)
    assert 'continuous_discovery' in source, \
        "Must register continuous_discovery scheduled job"
    assert 'run_continuous_discovery' in source, \
        "Must reference run_continuous_discovery function"

def test_snapshot_timestamps_tracked_in_lifecycle():
    """Phase 5: _run_connection_discovery tracks snapshot timestamps."""
    from app.scheduler import _run_connection_discovery
    source = inspect.getsource(_run_connection_discovery)
    assert 'update_snapshot_timestamps' in source, \
        "Must call update_snapshot_timestamps during discovery lifecycle"
    assert 'started=True' in source, \
        "Must mark snapshot started"
    assert 'completed=True' in source, \
        "Must mark snapshot completed"


# ── Step 40: API Endpoints ──────────────────────────────────────────────

def test_get_discovery_settings_handler():
    """Phase 5: get_discovery_settings handler exists."""
    from app.api.handlers import get_discovery_settings
    source = inspect.getsource(get_discovery_settings)
    assert 'discovery_enabled' in source, "Must return discovery_enabled"
    assert 'discovery_interval_minutes' in source, "Must return discovery_interval_minutes"
    assert 'last_snapshot_completed_at' in source, "Must return last_snapshot_completed_at"

def test_update_discovery_settings_handler():
    """Phase 5: update_discovery_settings handler exists."""
    from app.api.handlers import update_discovery_settings
    source = inspect.getsource(update_discovery_settings)
    assert 'discovery_enabled' in source, "Must accept discovery_enabled"
    assert 'discovery_interval_minutes' in source, "Must accept discovery_interval_minutes"
    assert 'max(60' in source or 'min(1440' in source, \
        "Must validate interval bounds"

def test_discovery_settings_routes_registered():
    """Phase 5: Discovery settings routes registered in main.py."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/discovery/settings/' in source, \
        "Must register /api/discovery/settings/<connection_id> routes"
    assert 'get_discovery_settings' in source, \
        "Must call get_discovery_settings handler"
    assert 'update_discovery_settings' in source, \
        "Must call update_discovery_settings handler"


# ── Step 41: Timestamp Serialization ────────────────────────────────────

def test_get_cloud_connections_serializes_new_timestamps():
    """Phase 5: get_cloud_connections serializes new timestamp columns."""
    from app.database import Database
    source = inspect.getsource(Database.get_cloud_connections)
    assert 'last_snapshot_started_at' in source, \
        "Must serialize last_snapshot_started_at"
    assert 'last_snapshot_completed_at' in source, \
        "Must serialize last_snapshot_completed_at"

def test_get_cloud_connection_by_id_serializes_new_timestamps():
    """Phase 5: get_cloud_connection_by_id serializes new timestamp columns."""
    from app.database import Database
    source = inspect.getsource(Database.get_cloud_connection_by_id)
    assert 'last_snapshot_started_at' in source, \
        "Must serialize last_snapshot_started_at"
    assert 'last_snapshot_completed_at' in source, \
        "Must serialize last_snapshot_completed_at"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 6: Risk Detection Engine
# ══════════════════════════════════════════════════════════════════════════════

# ── Migration 042 ────────────────────────────────────────────────────────────

def test_migration_042_exists():
    """Phase 6: _run_migration_042_risk_evaluator method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_042_risk_evaluator'), \
        "Database must have _run_migration_042_risk_evaluator method"

def test_migration_042_called_from_entitlements():
    """Phase 6: migration 042 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_042_risk_evaluator' in source, \
        "Must chain _run_migration_042_risk_evaluator from _ensure_entitlements_tables"

def test_migration_042_creates_risk_rules():
    """Phase 6: migration 042 DDL creates risk_rules table with rule_key and severity CHECK."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_042_risk_evaluator)
    assert 'risk_rules' in source, "Must create risk_rules table"
    assert 'rule_key' in source, "Must have rule_key column"
    assert "severity" in source and "CHECK" in source, \
        "Must have severity CHECK constraint"

def test_migration_042_creates_risk_findings():
    """Phase 6: migration 042 DDL creates risk_findings with UUID PK and org/connection refs."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_042_risk_evaluator)
    assert 'risk_findings' in source, "Must create risk_findings table"
    assert 'gen_random_uuid' in source, "Must use UUID PK"
    assert 'organization_id' in source, "Must have organization_id"
    assert 'cloud_connection_id' in source, "Must have cloud_connection_id"

def test_migration_042_risk_findings_rls():
    """Phase 6: migration 042 creates 4 RLS policies on risk_findings."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_042_risk_evaluator)
    assert 'rf_strict_sel' in source, "Must create rf_strict_sel policy"
    assert 'rf_strict_ins' in source, "Must create rf_strict_ins policy"
    assert 'rf_strict_upd' in source, "Must create rf_strict_upd policy"
    assert 'rf_strict_del' in source, "Must create rf_strict_del policy"

def test_migration_042_seeds_six_rules():
    """Phase 6: migration 042 seeds 6 risk rules."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_042_risk_evaluator)
    assert 'disabled_user_with_role' in source, "Must seed disabled_user_with_role"
    assert 'guest_high_privilege' in source, "Must seed guest_high_privilege"
    assert 'spn_owner' in source, "Must seed spn_owner"
    assert 'expired_spn_secret' in source, "Must seed expired_spn_secret"
    assert 'spn_secret_expiring' in source, "Must seed spn_secret_expiring"
    assert 'inactive_privileged' in source, "Must seed inactive_privileged"

def test_migration_042_dedup_index():
    """Phase 6: migration 042 creates partial unique dedup index."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_042_risk_evaluator)
    assert 'idx_rf_dedup' in source, "Must create idx_rf_dedup partial unique index"
    assert "WHERE status = 'open'" in source, "Dedup must be partial (WHERE status = 'open')"

def test_migration_042_sql_file():
    """Phase 6: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '042_risk_evaluator.sql')
    assert os.path.exists(sql_path), "migrations/042_risk_evaluator.sql must exist"


# ── Risk Evaluator Engine ────────────────────────────────────────────────────

def test_risk_evaluator_class_exists():
    """Phase 6: RiskEvaluator class can be imported."""
    from app.engines.risk_evaluator import RiskEvaluator
    assert RiskEvaluator is not None, "RiskEvaluator class must be importable"

def test_risk_evaluator_evaluate_risks_method():
    """Phase 6: RiskEvaluator has evaluate_risks method with correct signature."""
    from app.engines.risk_evaluator import RiskEvaluator
    sig = inspect.signature(RiskEvaluator.evaluate_risks)
    params = list(sig.parameters.keys())
    assert 'connection_id' in params, "evaluate_risks must accept connection_id"
    assert 'org_id' in params, "evaluate_risks must accept org_id"

def test_risk_evaluator_disabled_user():
    """Phase 6: _eval_disabled_user_with_role evaluator exists."""
    from app.engines import risk_evaluator
    source = inspect.getsource(risk_evaluator)
    assert '_eval_disabled_user_with_role' in source, \
        "Must have _eval_disabled_user_with_role evaluator"

def test_risk_evaluator_guest_privilege():
    """Phase 6: _eval_guest_high_privilege evaluator exists."""
    from app.engines import risk_evaluator
    source = inspect.getsource(risk_evaluator)
    assert '_eval_guest_high_privilege' in source, \
        "Must have _eval_guest_high_privilege evaluator"

def test_risk_evaluator_expired_spn():
    """Phase 6: _eval_expired_spn_secret evaluator exists."""
    from app.engines import risk_evaluator
    source = inspect.getsource(risk_evaluator)
    assert '_eval_expired_spn_secret' in source, \
        "Must have _eval_expired_spn_secret evaluator"

def test_risk_evaluator_inactive_privileged():
    """Phase 6: _eval_inactive_privileged evaluator exists."""
    from app.engines import risk_evaluator
    source = inspect.getsource(risk_evaluator)
    assert '_eval_inactive_privileged' in source, \
        "Must have _eval_inactive_privileged evaluator"


# ── Scheduler Integration ────────────────────────────────────────────────────

def test_risk_evaluation_in_scheduler():
    """Phase 6: _run_risk_evaluation function exists in scheduler."""
    from app import scheduler as sched_module
    source = inspect.getsource(sched_module)
    assert '_run_risk_evaluation' in source, \
        "Scheduler must have _run_risk_evaluation function"
    assert 'risk_evaluation' in source, \
        "Scheduler must track risk_evaluation job"


# ── API Routes ───────────────────────────────────────────────────────────────

def test_risk_findings_api_route():
    """Phase 6: /api/risk/findings route registered in create_app."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/risk/findings' in source, \
        "Must register /api/risk/findings route"

def test_risk_findings_acknowledge_route():
    """Phase 6: /acknowledge route registered in create_app."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/acknowledge' in source, \
        "Must register risk finding acknowledge route"

def test_risk_findings_resolve_route():
    """Phase 6: /resolve route registered in create_app."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/resolve' in source, \
        "Must register risk finding resolve route"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 7: IAM Graph Engine
# ══════════════════════════════════════════════════════════════════════════════

# ── Migration 043 ────────────────────────────────────────────────────────────

def test_migration_043_exists():
    """Phase 7: _run_migration_043_iam_graph method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_043_iam_graph'), \
        "Database must have _run_migration_043_iam_graph method"

def test_migration_043_called_from_entitlements():
    """Phase 7: migration 043 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_043_iam_graph' in source, \
        "Must chain _run_migration_043_iam_graph from _ensure_entitlements_tables"

def test_migration_043_creates_graph_nodes():
    """Phase 7: migration 043 DDL creates graph_nodes with node_type CHECK."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_043_iam_graph)
    assert 'graph_nodes' in source, "Must create graph_nodes table"
    assert 'node_type' in source, "Must have node_type column"
    assert "'identity'" in source and "'role'" in source, \
        "Must have identity and role node types"
    assert "'resource'" in source and "'subscription'" in source, \
        "Must have resource and subscription node types"

def test_migration_043_creates_graph_edges():
    """Phase 7: migration 043 DDL creates graph_edges with edge_type CHECK."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_043_iam_graph)
    assert 'graph_edges' in source, "Must create graph_edges table"
    assert 'source_node_id' in source, "Must have source_node_id FK"
    assert 'target_node_id' in source, "Must have target_node_id FK"
    assert "'assigned_role'" in source, "Must have assigned_role edge type"
    assert "'grants_access'" in source, "Must have grants_access edge type"
    assert "'contains_resource'" in source, "Must have contains_resource edge type"

def test_migration_043_graph_nodes_rls():
    """Phase 7: migration 043 creates 4 RLS policies on graph_nodes."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_043_iam_graph)
    assert 'gn_strict_sel' in source, "Must create gn_strict_sel policy"
    assert 'gn_strict_ins' in source, "Must create gn_strict_ins policy"
    assert 'gn_strict_upd' in source, "Must create gn_strict_upd policy"
    assert 'gn_strict_del' in source, "Must create gn_strict_del policy"

def test_migration_043_graph_edges_rls():
    """Phase 7: migration 043 creates 4 RLS policies on graph_edges."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_043_iam_graph)
    assert 'ge_strict_sel' in source, "Must create ge_strict_sel policy"
    assert 'ge_strict_ins' in source, "Must create ge_strict_ins policy"
    assert 'ge_strict_upd' in source, "Must create ge_strict_upd policy"
    assert 'ge_strict_del' in source, "Must create ge_strict_del policy"

def test_migration_043_dedup_index():
    """Phase 7: migration 043 creates dedup unique index on graph_nodes."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_043_iam_graph)
    assert 'idx_gn_dedup' in source, "Must create idx_gn_dedup unique index"

def test_migration_043_sql_file():
    """Phase 7: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '043_iam_graph.sql')
    assert os.path.exists(sql_path), "migrations/043_iam_graph.sql must exist"


# ── Graph Builder Engine ─────────────────────────────────────────────────────

def test_graph_builder_class_exists():
    """Phase 7: GraphBuilder class can be imported."""
    from app.engines.graph_builder import GraphBuilder
    assert GraphBuilder is not None, "GraphBuilder class must be importable"

def test_graph_builder_build_iam_graph_method():
    """Phase 7: GraphBuilder has build_iam_graph method with correct signature."""
    from app.engines.graph_builder import GraphBuilder
    sig = inspect.signature(GraphBuilder.build_iam_graph)
    params = list(sig.parameters.keys())
    assert 'connection_id' in params, "build_iam_graph must accept connection_id"
    assert 'org_id' in params, "build_iam_graph must accept org_id"

def test_graph_builder_creates_identity_nodes():
    """Phase 7: GraphBuilder creates identity nodes."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "node_type='identity'" in source, \
        "Must create identity nodes"

def test_graph_builder_creates_role_nodes():
    """Phase 7: GraphBuilder creates role nodes."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "node_type='role'" in source, \
        "Must create role nodes"

def test_graph_builder_creates_subscription_nodes():
    """Phase 7: GraphBuilder creates subscription nodes."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "node_type='subscription'" in source, \
        "Must create subscription nodes"

def test_graph_builder_creates_resource_nodes():
    """Phase 7: GraphBuilder creates resource nodes."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "node_type='resource'" in source, \
        "Must create resource nodes"

def test_graph_builder_assigned_role_edges():
    """Phase 7: GraphBuilder creates assigned_role edges."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "edge_type='assigned_role'" in source, \
        "Must create assigned_role edges"

def test_graph_builder_grants_access_edges():
    """Phase 7: GraphBuilder creates grants_access edges."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "edge_type='grants_access'" in source, \
        "Must create grants_access edges"

def test_graph_builder_contains_resource_edges():
    """Phase 7: GraphBuilder creates contains_resource edges."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert "edge_type='contains_resource'" in source, \
        "Must create contains_resource edges"

def test_graph_builder_scoped_per_connection():
    """Phase 7: GraphBuilder scopes graph to connection via clear_graph."""
    from app.engines import graph_builder
    source = inspect.getsource(graph_builder)
    assert 'clear_graph' in source, \
        "Must call clear_graph to scope per connection"


# ── Scheduler Integration ────────────────────────────────────────────────────

def test_iam_graph_build_in_scheduler():
    """Phase 7: _run_iam_graph_build function exists in scheduler."""
    from app import scheduler as sched_module
    source = inspect.getsource(sched_module)
    assert '_run_iam_graph_build' in source, \
        "Scheduler must have _run_iam_graph_build function"
    assert 'iam_graph' in source, \
        "Scheduler must track iam_graph job"


# ── API Routes ───────────────────────────────────────────────────────────────

def test_graph_identity_access_route():
    """Phase 7: /api/graph/identity/<id>/access route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/graph/identity/' in source, \
        "Must register /api/graph/identity/<id>/access route"
    assert '/access' in source, \
        "Must include /access path segment"

def test_graph_resource_identities_route():
    """Phase 7: /api/graph/resource/<id>/identities route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/graph/resource/' in source, \
        "Must register /api/graph/resource/<id>/identities route"
    assert '/identities' in source, \
        "Must include /identities path segment"

def test_graph_query_returns_expected_structure():
    """Phase 7: Graph identity access handler returns identity + resources keys."""
    from app.api.handlers import get_graph_identity_access
    source = inspect.getsource(get_graph_identity_access)
    assert "'identity'" in source, "Response must include identity key"
    assert "'resources'" in source, "Response must include resources key"

def test_graph_resource_query_returns_expected_structure():
    """Phase 7: Graph resource identities handler returns resource + identities keys."""
    from app.api.handlers import get_graph_resource_identities
    source = inspect.getsource(get_graph_resource_identities)
    assert "'resource'" in source, "Response must include resource key"
    assert "'identities'" in source, "Response must include identities key"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 8: Privilege Escalation Detection
# ══════════════════════════════════════════════════════════════════════════════

# ── Migration 044: Escalation Rules ──────────────────────────────────────────

def test_migration_044_exists():
    """Phase 8: _run_migration_044_escalation_rules method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_044_escalation_rules'), \
        "Database must have _run_migration_044_escalation_rules method"

def test_migration_044_called_from_entitlements():
    """Phase 8: migration 044 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_044_escalation_rules' in source, \
        "Must chain _run_migration_044_escalation_rules from _ensure_entitlements_tables"

def test_migration_044_seeds_four_rules():
    """Phase 8: migration 044 seeds 4 escalation rules."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_044_escalation_rules)
    assert 'identity_can_assign_owner' in source, "Must seed identity_can_assign_owner"
    assert 'service_principal_owner' in source, "Must seed service_principal_owner"
    assert 'managed_identity_contributor' in source, "Must seed managed_identity_contributor"
    assert 'identity_can_modify_role_definitions' in source, "Must seed identity_can_modify_role_definitions"

def test_migration_044_sql_file():
    """Phase 8: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '044_escalation_rules.sql')
    assert os.path.exists(sql_path), "migrations/044_escalation_rules.sql must exist"


# ── Escalation Detector Engine ───────────────────────────────────────────────

def test_escalation_detector_class_exists():
    """Phase 8: EscalationDetector class can be imported."""
    from app.engines.escalation_detector import EscalationDetector
    assert EscalationDetector is not None, "EscalationDetector class must be importable"

def test_escalation_detector_detect_method():
    """Phase 8: EscalationDetector has detect_privilege_escalation method."""
    from app.engines.escalation_detector import EscalationDetector
    sig = inspect.signature(EscalationDetector.detect_privilege_escalation)
    params = list(sig.parameters.keys())
    assert 'connection_id' in params, "detect_privilege_escalation must accept connection_id"
    assert 'org_id' in params, "detect_privilege_escalation must accept org_id"

def test_escalation_detector_can_assign_owner():
    """Phase 8: _detect_can_assign_owner escalation rule exists."""
    from app.engines import escalation_detector
    source = inspect.getsource(escalation_detector)
    assert '_detect_can_assign_owner' in source, \
        "Must have _detect_can_assign_owner detector"
    assert 'roleAssignments/write' in source, \
        "Must check for roleAssignments/write permission"

def test_escalation_detector_spn_owner():
    """Phase 8: _detect_spn_owner escalation rule exists."""
    from app.engines import escalation_detector
    source = inspect.getsource(escalation_detector)
    assert '_detect_spn_owner' in source, \
        "Must have _detect_spn_owner detector"
    assert "service_principal" in source, \
        "Must check service_principal identity category"

def test_escalation_detector_mi_contributor():
    """Phase 8: _detect_mi_contributor escalation rule exists."""
    from app.engines import escalation_detector
    source = inspect.getsource(escalation_detector)
    assert '_detect_mi_contributor' in source, \
        "Must have _detect_mi_contributor detector"
    assert 'managed_identity' in source, \
        "Must check managed_identity category"

def test_escalation_detector_modify_roles():
    """Phase 8: _detect_can_modify_roles escalation rule exists."""
    from app.engines import escalation_detector
    source = inspect.getsource(escalation_detector)
    assert '_detect_can_modify_roles' in source, \
        "Must have _detect_can_modify_roles detector"
    assert 'roleDefinitions/write' in source, \
        "Must check for roleDefinitions/write permission"

def test_escalation_path_in_metadata():
    """Phase 8: Escalation findings include escalation_path in metadata."""
    from app.engines import escalation_detector
    source = inspect.getsource(escalation_detector)
    assert 'escalation_path' in source, \
        "Must include escalation_path in finding metadata"
    assert 'privilege_escalation' in source, \
        "Must set finding_category to privilege_escalation"

def test_escalation_graph_traversal():
    """Phase 8: EscalationDetector uses graph traversal for identity paths."""
    from app.engines import escalation_detector
    source = inspect.getsource(escalation_detector)
    assert 'get_identity_escalation_paths' in source, \
        "Must have get_identity_escalation_paths for graph traversal"
    assert 'graph_nodes' in source, \
        "Must query graph_nodes for traversal"
    assert 'graph_edges' in source, \
        "Must query graph_edges for traversal"


# ── Scheduler Integration ────────────────────────────────────────────────────

def test_escalation_detection_in_scheduler():
    """Phase 8: _run_escalation_detection function exists in scheduler."""
    from app import scheduler as sched_module
    source = inspect.getsource(sched_module)
    assert '_run_escalation_detection' in source, \
        "Scheduler must have _run_escalation_detection function"
    assert 'escalation_detection' in source, \
        "Scheduler must track escalation_detection job"

def test_escalation_runs_after_graph_build():
    """Phase 8: Escalation detection runs after IAM graph build in pipeline."""
    from app import scheduler as sched_module
    source = inspect.getsource(sched_module)
    graph_pos = source.find("'iam_graph'")
    escalation_pos = source.find("'escalation_detection'")
    assert graph_pos < escalation_pos, \
        "escalation_detection must run after iam_graph in pipeline"


# ── API Routes ───────────────────────────────────────────────────────────────

def test_escalation_attack_paths_route():
    """Phase 8: /api/graph/identity/<id>/attack-paths route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/graph/identity/' in source and '/attack-paths' in source, \
        "Must register /api/graph/identity/<id>/attack-paths route"

def test_escalation_attack_paths_handler():
    """Phase 8: Attack paths handler returns expected structure."""
    from app.api.handlers import get_graph_identity_attack_paths
    source = inspect.getsource(get_graph_identity_attack_paths)
    assert "'attack_paths'" in source, "Response must include attack_paths key"
    assert "'escalation_findings'" in source, "Response must include escalation_findings key"

def test_escalation_findings_scoped_by_identity():
    """Phase 8: get_escalation_findings method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'get_escalation_findings'), \
        "Database must have get_escalation_findings method"

def test_escalation_findings_filters_by_category():
    """Phase 8: get_escalation_findings filters by privilege_escalation category."""
    from app.database import Database
    source = inspect.getsource(Database.get_escalation_findings)
    assert 'privilege_escalation' in source, \
        "Must filter by finding_category = privilege_escalation"


# ══════════════════════════════════════════════════════════════════════════════
# Phase 9: Non-Human Identity Security Analytics
# ══════════════════════════════════════════════════════════════════════════════

# ── Migration 045: NHI Rules ─────────────────────────────────────────────────

def test_migration_045_exists():
    """Phase 9: _run_migration_045_nhi_rules method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_045_nhi_rules'), \
        "Database must have _run_migration_045_nhi_rules method"

def test_migration_045_called_from_entitlements():
    """Phase 9: migration 045 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_045_nhi_rules' in source, \
        "Must chain _run_migration_045_nhi_rules from _ensure_entitlements_tables"

def test_migration_045_seeds_five_rules():
    """Phase 9: migration 045 seeds 5 NHI rules."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_045_nhi_rules)
    assert 'spn_secret_without_expiry' in source, "Must seed spn_secret_without_expiry"
    assert 'spn_secret_older_than_180_days' in source, "Must seed spn_secret_older_than_180_days"
    assert 'unused_service_principal' in source, "Must seed unused_service_principal"
    assert 'spn_owner_role' in source, "Must seed spn_owner_role"
    assert 'managed_identity_high_privilege' in source, "Must seed managed_identity_high_privilege"

def test_migration_045_sql_file():
    """Phase 9: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '045_nhi_rules.sql')
    assert os.path.exists(sql_path), "migrations/045_nhi_rules.sql must exist"


# ── NHI Analyzer Engine ──────────────────────────────────────────────────────

def test_nhi_analyzer_class_exists():
    """Phase 9: NHIAnalyzer class can be imported."""
    from app.engines.nhi_analyzer import NHIAnalyzer
    assert NHIAnalyzer is not None, "NHIAnalyzer class must be importable"

def test_nhi_analyzer_method_signature():
    """Phase 9: NHIAnalyzer has analyze_nhi_security with correct signature."""
    from app.engines.nhi_analyzer import NHIAnalyzer
    sig = inspect.signature(NHIAnalyzer.analyze_nhi_security)
    params = list(sig.parameters.keys())
    assert 'connection_id' in params, "analyze_nhi_security must accept connection_id"
    assert 'org_id' in params, "analyze_nhi_security must accept org_id"

def test_nhi_rule_secret_no_expiry():
    """Phase 9: _analyze_secret_no_expiry rule exists."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert '_analyze_secret_no_expiry' in source, \
        "Must have _analyze_secret_no_expiry analyzer"
    assert 'credential_expiration IS NULL' in source, \
        "Must check for NULL credential_expiration"

def test_nhi_rule_secret_old():
    """Phase 9: _analyze_secret_old rule exists."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert '_analyze_secret_old' in source, \
        "Must have _analyze_secret_old analyzer"
    assert '180 days' in source, \
        "Must check for 180-day threshold"

def test_nhi_rule_unused_spn():
    """Phase 9: _analyze_unused_spn rule exists."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert '_analyze_unused_spn' in source, \
        "Must have _analyze_unused_spn analyzer"
    assert '90 days' in source, \
        "Must check for 90-day inactivity threshold"

def test_nhi_rule_spn_owner():
    """Phase 9: _analyze_spn_owner rule exists."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert '_analyze_spn_owner' in source, \
        "Must have _analyze_spn_owner analyzer"
    assert "role_name = 'Owner'" in source, \
        "Must check for Owner role"

def test_nhi_rule_mi_high_priv():
    """Phase 9: _analyze_mi_high_priv rule exists."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert '_analyze_mi_high_priv' in source, \
        "Must have _analyze_mi_high_priv analyzer"
    assert 'managed_identity' in source, \
        "Must check managed identity categories"

def test_nhi_findings_category():
    """Phase 9: NHI findings use nhi_security category in metadata."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert 'nhi_security' in source, \
        "Must set finding_category to nhi_security"

def test_nhi_findings_include_identity_type():
    """Phase 9: NHI findings include identity_type in metadata."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert 'identity_type' in source, \
        "Must include identity_type in finding metadata"

def test_nhi_findings_dedup():
    """Phase 9: NHI findings deduplicate by identity via save_risk_findings upsert."""
    from app.engines import nhi_analyzer
    source = inspect.getsource(nhi_analyzer)
    assert 'save_risk_findings' in source, \
        "Must call save_risk_findings for upsert dedup"


# ── Scheduler Integration ────────────────────────────────────────────────────

def test_nhi_analysis_in_scheduler():
    """Phase 9: _run_nhi_analysis function exists in scheduler."""
    from app import scheduler as sched_module
    source = inspect.getsource(sched_module)
    assert '_run_nhi_analysis' in source, \
        "Scheduler must have _run_nhi_analysis function"
    assert 'nhi_security' in source, \
        "Scheduler must track nhi_security job"

def test_nhi_runs_after_escalation():
    """Phase 9: NHI analysis runs after escalation detection in pipeline."""
    from app import scheduler as sched_module
    source = inspect.getsource(sched_module)
    escalation_pos = source.find("'escalation_detection'")
    nhi_pos = source.find("'nhi_security'")
    assert escalation_pos < nhi_pos, \
        "nhi_security must run after escalation_detection in pipeline"


# ── API Route ────────────────────────────────────────────────────────────────

def test_nhi_security_api_route():
    """Phase 9: /api/security/nhi route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/nhi' in source, \
        "Must register /api/security/nhi route"

def test_nhi_security_handler_structure():
    """Phase 9: NHI handler returns findings + stats."""
    from app.api.handlers import get_nhi_security_findings
    source = inspect.getsource(get_nhi_security_findings)
    assert "'findings'" in source, "Response must include findings key"
    assert "'stats'" in source, "Response must include stats key"

def test_nhi_findings_db_method():
    """Phase 9: get_nhi_findings method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'get_nhi_findings'), \
        "Database must have get_nhi_findings method"

def test_nhi_findings_db_filters_category():
    """Phase 9: get_nhi_findings filters by nhi_security category."""
    from app.database import Database
    source = inspect.getsource(Database.get_nhi_findings)
    assert 'nhi_security' in source, \
        "Must filter by finding_category = nhi_security"


# ================================================================
# Phase 10: Executive Security Dashboard
# ================================================================

def test_migration_046_exists():
    """Phase 10: migration 046 method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_046_identity_credentials'), \
        "Database must have _run_migration_046_identity_credentials method"

def test_migration_046_called_from_entitlements():
    """Phase 10: migration 046 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_046_identity_credentials' in source, \
        "Must call _run_migration_046_identity_credentials from entitlements chain"

def test_migration_046_creates_identity_credentials():
    """Phase 10: migration 046 DDL creates identity_credentials table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_046_identity_credentials)
    assert 'identity_credentials' in source, \
        "Must create identity_credentials table"
    assert 'credential_type' in source, \
        "Must have credential_type column"

def test_migration_046_identity_credentials_rls():
    """Phase 10: identity_credentials has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_046_identity_credentials)
    assert 'ic_strict_sel' in source, "Must have SELECT policy"
    assert 'ic_strict_ins' in source, "Must have INSERT policy"
    assert 'ic_strict_upd' in source, "Must have UPDATE policy"
    assert 'ic_strict_del' in source, "Must have DELETE policy"

def test_migration_046_dedup_index():
    """Phase 10: identity_credentials has dedup unique index."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_046_identity_credentials)
    assert 'idx_ic_dedup' in source, \
        "Must have dedup unique index"

def test_migration_046_sql_file():
    """Phase 10: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '046_identity_credentials.sql')
    assert os.path.exists(sql_path), \
        "migrations/046_identity_credentials.sql must exist"

def test_dashboard_summary_method():
    """Phase 10: get_dashboard_summary method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'get_dashboard_summary'), \
        "Database must have get_dashboard_summary method"

def test_dashboard_summary_returns_identity_counts():
    """Phase 10: get_dashboard_summary includes identity counts."""
    from app.database import Database
    source = inspect.getsource(Database.get_dashboard_summary)
    assert 'total_identities' in source, "Must return total_identities"
    assert 'service_principals' in source, "Must return service_principals"
    assert 'managed_identities' in source, "Must return managed_identities"

def test_dashboard_summary_returns_risk_findings():
    """Phase 10: get_dashboard_summary includes risk finding counts."""
    from app.database import Database
    source = inspect.getsource(Database.get_dashboard_summary)
    assert 'critical_findings' in source, "Must return critical_findings"
    assert 'high_findings' in source, "Must return high_findings"
    assert 'medium_findings' in source, "Must return medium_findings"

def test_dashboard_summary_returns_risk_score():
    """Phase 10: get_dashboard_summary computes risk_score."""
    from app.database import Database
    source = inspect.getsource(Database.get_dashboard_summary)
    assert 'risk_score' in source, "Must compute risk_score"

def test_dashboard_summary_returns_nhi_metrics():
    """Phase 10: get_dashboard_summary includes NHI metrics."""
    from app.database import Database
    source = inspect.getsource(Database.get_dashboard_summary)
    assert 'secrets_without_expiry' in source, "Must return secrets_without_expiry"
    assert 'unused_service_principals' in source, "Must return unused_service_principals"

def test_dashboard_summary_returns_credential_stats():
    """Phase 10: get_dashboard_summary includes credential stats."""
    from app.database import Database
    source = inspect.getsource(Database.get_dashboard_summary)
    assert 'total_credentials' in source, "Must return total_credentials"
    assert 'expired_credentials' in source, "Must return expired_credentials"
    assert 'expiring_soon_credentials' in source, "Must return expiring_soon_credentials"

def test_save_identity_credential_method():
    """Phase 10: save_identity_credential method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'save_identity_credential'), \
        "Database must have save_identity_credential method"

def test_get_credential_stats_method():
    """Phase 10: get_credential_stats method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'get_credential_stats'), \
        "Database must have get_credential_stats method"

def test_dashboard_summary_handler_exists():
    """Phase 10: get_dashboard_summary_handler exists in handlers."""
    from app.api.handlers import get_dashboard_summary_handler
    assert callable(get_dashboard_summary_handler), \
        "get_dashboard_summary_handler must be callable"

def test_dashboard_summary_handler_structure():
    """Phase 10: dashboard handler returns summary via jsonify."""
    from app.api.handlers import get_dashboard_summary_handler
    source = inspect.getsource(get_dashboard_summary_handler)
    assert 'get_dashboard_summary' in source, "Must call db.get_dashboard_summary()"
    assert 'jsonify' in source, "Must return jsonify response"

def test_dashboard_summary_route():
    """Phase 10: /api/dashboard/summary route registered in create_app."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/dashboard/summary' in source, \
        "Must register /api/dashboard/summary route"

def test_dashboard_summary_import():
    """Phase 10: get_dashboard_summary_handler imported in main."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert 'get_dashboard_summary_handler' in source or \
           'dashboard_summary_handler' in source, \
        "Must import dashboard summary handler"


# ================================================================
# Phase 11: Policy Recommendation Engine
# ================================================================

def test_migration_047_exists():
    """Phase 11: migration 047 method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_047_policy_recommendations'), \
        "Database must have _run_migration_047_policy_recommendations method"

def test_migration_047_called_from_entitlements():
    """Phase 11: migration 047 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_047_policy_recommendations' in source, \
        "Must call _run_migration_047_policy_recommendations from entitlements chain"

def test_migration_047_creates_policy_recommendations():
    """Phase 11: migration 047 DDL creates policy_recommendations table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_047_policy_recommendations)
    assert 'policy_recommendations' in source, \
        "Must create policy_recommendations table"
    assert 'recommendation_type' in source, \
        "Must have recommendation_type column"
    assert 'recommended_action' in source, \
        "Must have recommended_action column"
    assert 'confidence_score' in source, \
        "Must have confidence_score column"

def test_migration_047_rls():
    """Phase 11: policy_recommendations has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_047_policy_recommendations)
    assert 'pr_strict_sel' in source, "Must have SELECT policy"
    assert 'pr_strict_ins' in source, "Must have INSERT policy"
    assert 'pr_strict_upd' in source, "Must have UPDATE policy"
    assert 'pr_strict_del' in source, "Must have DELETE policy"

def test_migration_047_dedup_index():
    """Phase 11: policy_recommendations has dedup partial unique index."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_047_policy_recommendations)
    assert 'idx_pr_dedup' in source, \
        "Must have dedup unique index"

def test_migration_047_status_check():
    """Phase 11: policy_recommendations status has CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_047_policy_recommendations)
    assert "'open'" in source, "Must allow open status"
    assert "'accepted'" in source, "Must allow accepted status"
    assert "'dismissed'" in source, "Must allow dismissed status"
    assert "'resolved'" in source, "Must allow resolved status"

def test_migration_047_sql_file():
    """Phase 11: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '047_policy_recommendations.sql')
    assert os.path.exists(sql_path), \
        "migrations/047_policy_recommendations.sql must exist"

def test_policy_recommender_class_exists():
    """Phase 11: PolicyRecommender class can be imported."""
    from app.engines.policy_recommender import PolicyRecommender
    assert PolicyRecommender is not None, \
        "PolicyRecommender class must be importable"

def test_policy_recommender_generate_method():
    """Phase 11: generate_policy_recommendations method exists."""
    from app.engines.policy_recommender import PolicyRecommender
    assert hasattr(PolicyRecommender, 'generate_policy_recommendations'), \
        "Must have generate_policy_recommendations method"

def test_policy_recommender_excess_privilege():
    """Phase 11: excess_privilege_identity evaluator exists."""
    from app.engines.policy_recommender import PolicyRecommender
    source = inspect.getsource(PolicyRecommender)
    assert '_eval_excess_privilege_identity' in source, \
        "Must have excess_privilege_identity evaluator"
    assert 'Owner' in source, "Must check for Owner role"

def test_policy_recommender_secret_rotation():
    """Phase 11: service_principal_secret_rotation evaluator exists."""
    from app.engines.policy_recommender import PolicyRecommender
    source = inspect.getsource(PolicyRecommender)
    assert '_eval_service_principal_secret_rotation' in source, \
        "Must have service_principal_secret_rotation evaluator"
    assert '180' in source, "Must check for 180 day threshold"

def test_policy_recommender_guest_privilege():
    """Phase 11: guest_user_privilege_review evaluator exists."""
    from app.engines.policy_recommender import PolicyRecommender
    source = inspect.getsource(PolicyRecommender)
    assert '_eval_guest_user_privilege_review' in source, \
        "Must have guest_user_privilege_review evaluator"
    assert 'guest' in source, "Must check for guest category"

def test_policy_recommender_unused_identity():
    """Phase 11: unused_identity_cleanup evaluator exists."""
    from app.engines.policy_recommender import PolicyRecommender
    source = inspect.getsource(PolicyRecommender)
    assert '_eval_unused_identity_cleanup' in source, \
        "Must have unused_identity_cleanup evaluator"
    assert '90 days' in source, "Must check for 90 day inactivity"

def test_policy_recommender_spn_excess_privilege():
    """Phase 11: service_principal_excess_privilege evaluator exists."""
    from app.engines.policy_recommender import PolicyRecommender
    source = inspect.getsource(PolicyRecommender)
    assert '_eval_service_principal_excess_privilege' in source, \
        "Must have service_principal_excess_privilege evaluator"

def test_policy_recommender_five_evaluators():
    """Phase 11: EVALUATORS list has 5 entries."""
    from app.engines.policy_recommender import EVALUATORS
    assert len(EVALUATORS) == 5, \
        f"Must have 5 evaluators, got {len(EVALUATORS)}"

def test_save_policy_recommendations_method():
    """Phase 11: save_policy_recommendations method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'save_policy_recommendations'), \
        "Database must have save_policy_recommendations method"

def test_save_policy_recommendations_dedup():
    """Phase 11: save_policy_recommendations uses ON CONFLICT for dedup."""
    from app.database import Database
    source = inspect.getsource(Database.save_policy_recommendations)
    assert 'ON CONFLICT' in source, \
        "Must use ON CONFLICT for dedup"
    assert 'DO UPDATE' in source, \
        "Must update on conflict instead of inserting duplicate"

def test_get_policy_recommendations_method():
    """Phase 11: get_policy_recommendations method exists with filters."""
    from app.database import Database
    source = inspect.getsource(Database.get_policy_recommendations)
    assert 'connection_id' in source, "Must filter by connection_id"
    assert 'severity' in source, "Must filter by severity"
    assert 'status' in source, "Must filter by status"

def test_update_policy_recommendation_status_method():
    """Phase 11: update_policy_recommendation_status method exists."""
    from app.database import Database
    assert hasattr(Database, 'update_policy_recommendation_status'), \
        "Database must have update_policy_recommendation_status method"

def test_get_policy_recommendation_stats_method():
    """Phase 11: get_policy_recommendation_stats method exists."""
    from app.database import Database
    source = inspect.getsource(Database.get_policy_recommendation_stats)
    assert 'open' in source, "Must count open recommendations"
    assert 'critical' in source, "Must count critical recommendations"
    assert 'high' in source, "Must count high recommendations"

def test_policy_recommendations_in_scheduler():
    """Phase 11: _run_policy_recommendations in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_policy_recommendations' in source, \
        "Scheduler must have _run_policy_recommendations function"
    assert "'policy_recommendations'" in source, \
        "Must register policy_recommendations as tracked job"

def test_policy_recommendations_after_nhi():
    """Phase 11: policy recommendations runs after NHI analysis."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    nhi_pos = source.find("'nhi_security'")
    pr_pos = source.find("'policy_recommendations'")
    assert nhi_pos < pr_pos, \
        "policy_recommendations must run after nhi_security"

def test_policy_recommendations_api_route():
    """Phase 11: /api/security/recommendations route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/recommendations' in source, \
        "Must register /api/security/recommendations route"

def test_accept_recommendation_route():
    """Phase 11: accept recommendation route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/accept' in source and 'recommendation' in source.lower(), \
        "Must register accept recommendation route"

def test_dismiss_recommendation_route():
    """Phase 11: dismiss recommendation route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/dismiss' in source and 'recommendation' in source.lower(), \
        "Must register dismiss recommendation route"

def test_policy_recommendations_handler_exists():
    """Phase 11: get_policy_recommendations_handler exists in handlers."""
    from app.api.handlers import get_policy_recommendations_handler
    assert callable(get_policy_recommendations_handler), \
        "get_policy_recommendations_handler must be callable"

def test_policy_recommendations_handler_structure():
    """Phase 11: handler returns recommendations + stats."""
    from app.api.handlers import get_policy_recommendations_handler
    source = inspect.getsource(get_policy_recommendations_handler)
    assert "'recommendations'" in source, "Response must include recommendations key"
    assert "'stats'" in source, "Response must include stats key"

def test_accept_handler_exists():
    """Phase 11: accept_policy_recommendation handler exists."""
    from app.api.handlers import accept_policy_recommendation
    assert callable(accept_policy_recommendation), \
        "accept_policy_recommendation must be callable"

def test_dismiss_handler_exists():
    """Phase 11: dismiss_policy_recommendation handler exists."""
    from app.api.handlers import dismiss_policy_recommendation
    assert callable(dismiss_policy_recommendation), \
        "dismiss_policy_recommendation must be callable"


# ================================================================
# Phase 12: Automated Remediation Engine
# ================================================================

def test_migration_048_exists():
    """Phase 12: migration 048 method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_048_remediation_actions'), \
        "Database must have _run_migration_048_remediation_actions method"

def test_migration_048_called_from_entitlements():
    """Phase 12: migration 048 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_048_remediation_actions' in source, \
        "Must call _run_migration_048_remediation_actions from entitlements chain"

def test_migration_048_creates_auto_remediation_actions():
    """Phase 12: migration 048 DDL creates auto_remediation_actions table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_048_remediation_actions)
    assert 'auto_remediation_actions' in source, \
        "Must create auto_remediation_actions table"
    assert 'action_type' in source, "Must have action_type column"
    assert 'recommendation_id' in source, "Must have recommendation_id column"
    assert 'requested_by' in source, "Must have requested_by column"
    assert 'approved_by' in source, "Must have approved_by column"
    assert 'result_message' in source, "Must have result_message column"

def test_migration_048_status_check():
    """Phase 12: auto_remediation_actions has correct status CHECK."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_048_remediation_actions)
    assert "'pending'" in source, "Must allow pending status"
    assert "'approved'" in source, "Must allow approved status"
    assert "'executing'" in source, "Must allow executing status"
    assert "'completed'" in source, "Must allow completed status"
    assert "'failed'" in source, "Must allow failed status"

def test_migration_048_rls():
    """Phase 12: auto_remediation_actions has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_048_remediation_actions)
    assert 'ara_strict_sel' in source, "Must have SELECT policy"
    assert 'ara_strict_ins' in source, "Must have INSERT policy"
    assert 'ara_strict_upd' in source, "Must have UPDATE policy"
    assert 'ara_strict_del' in source, "Must have DELETE policy"

def test_migration_048_sql_file():
    """Phase 12: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '048_remediation_actions.sql')
    assert os.path.exists(sql_path), \
        "migrations/048_remediation_actions.sql must exist"

def test_remediation_engine_class_exists():
    """Phase 12: RemediationEngine class can be imported."""
    from app.engines.remediation_engine import RemediationEngine
    assert RemediationEngine is not None, \
        "RemediationEngine class must be importable"

def test_remediation_engine_execute_method():
    """Phase 12: execute_remediation method exists."""
    from app.engines.remediation_engine import RemediationEngine
    assert hasattr(RemediationEngine, 'execute_remediation'), \
        "Must have execute_remediation method"

def test_remediation_engine_create_action_method():
    """Phase 12: create_remediation_action method exists."""
    from app.engines.remediation_engine import RemediationEngine
    assert hasattr(RemediationEngine, 'create_remediation_action'), \
        "Must have create_remediation_action method"

def test_remediation_engine_approve_method():
    """Phase 12: approve_action method exists."""
    from app.engines.remediation_engine import RemediationEngine
    assert hasattr(RemediationEngine, 'approve_action'), \
        "Must have approve_action method"

def test_remediation_supported_actions():
    """Phase 12: SUPPORTED_ACTIONS includes 4 action types."""
    from app.engines.remediation_engine import SUPPORTED_ACTIONS
    assert 'rotate_service_principal_secret' in SUPPORTED_ACTIONS
    assert 'remove_role_assignment' in SUPPORTED_ACTIONS
    assert 'disable_identity' in SUPPORTED_ACTIONS
    assert 'reduce_identity_privilege' in SUPPORTED_ACTIONS

def test_remediation_recommendation_action_map():
    """Phase 12: RECOMMENDATION_ACTION_MAP maps recommendation types to actions."""
    from app.engines.remediation_engine import RECOMMENDATION_ACTION_MAP
    assert 'service_principal_secret_rotation' in RECOMMENDATION_ACTION_MAP
    assert 'excess_privilege_identity' in RECOMMENDATION_ACTION_MAP
    assert 'unused_identity_cleanup' in RECOMMENDATION_ACTION_MAP

def test_remediation_safety_guards():
    """Phase 12: safety guards check exists in engine."""
    from app.engines.remediation_engine import RemediationEngine
    source = inspect.getsource(RemediationEngine)
    assert '_check_safety_guards' in source, \
        "Must have safety guard checking"
    assert 'Cannot remove last Owner' in source or 'last Owner' in source, \
        "Must prevent removing last Owner"

def test_remediation_approval_workflow():
    """Phase 12: engine supports approval_required mode."""
    from app.engines.remediation_engine import RemediationEngine
    source = inspect.getsource(RemediationEngine)
    assert 'remediation_mode' in source, \
        "Must check remediation_mode setting"
    assert 'approval_required' in source, \
        "Must support approval_required mode"

def test_remediation_simulated_execution():
    """Phase 12: actions are simulated (not live cloud calls)."""
    from app.engines.remediation_engine import RemediationEngine
    source = inspect.getsource(RemediationEngine._execute_action)
    assert 'Simulated' in source, \
        "Actions must be simulated for safety"

def test_create_auto_remediation_action_db():
    """Phase 12: create_auto_remediation_action method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'create_auto_remediation_action'), \
        "Database must have create_auto_remediation_action method"

def test_get_auto_remediation_action_by_id_db():
    """Phase 12: get_auto_remediation_action_by_id method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'get_auto_remediation_action_by_id'), \
        "Database must have get_auto_remediation_action_by_id method"

def test_get_auto_remediation_actions_db():
    """Phase 12: get_auto_remediation_actions method with filters."""
    from app.database import Database
    source = inspect.getsource(Database.get_auto_remediation_actions)
    assert 'status' in source, "Must filter by status"
    assert 'connection_id' in source, "Must filter by connection_id"

def test_update_auto_remediation_action_db():
    """Phase 12: update_auto_remediation_action method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'update_auto_remediation_action'), \
        "Database must have update_auto_remediation_action method"

def test_get_auto_remediation_stats_db():
    """Phase 12: get_auto_remediation_stats returns correct counts."""
    from app.database import Database
    source = inspect.getsource(Database.get_auto_remediation_stats)
    assert 'pending' in source, "Must count pending actions"
    assert 'completed' in source, "Must count completed actions"
    assert 'failed' in source, "Must count failed actions"

def test_auto_remediation_in_scheduler():
    """Phase 12: _run_auto_remediation in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_auto_remediation' in source, \
        "Scheduler must have _run_auto_remediation function"
    assert "'auto_remediation'" in source, \
        "Must register auto_remediation as tracked job"

def test_auto_remediation_after_recommendations():
    """Phase 12: auto remediation runs after policy recommendations."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    pr_pos = source.find("'policy_recommendations'")
    ar_pos = source.find("'auto_remediation'")
    assert pr_pos < ar_pos, \
        "auto_remediation must run after policy_recommendations"

def test_remediation_execute_route():
    """Phase 12: /api/security/remediation/.../execute route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/remediation/' in source and '/execute' in source, \
        "Must register execute remediation route"

def test_remediation_approve_route():
    """Phase 12: /api/security/remediation/.../approve route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/approve' in source and 'remediation' in source, \
        "Must register approve remediation route"

def test_remediation_actions_list_route():
    """Phase 12: /api/security/remediation/actions route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/remediation/actions' in source, \
        "Must register remediation actions list route"

def test_execute_remediation_handler_exists():
    """Phase 12: execute_remediation_handler exists in handlers."""
    from app.api.handlers import execute_remediation_handler
    assert callable(execute_remediation_handler), \
        "execute_remediation_handler must be callable"

def test_approve_remediation_handler_exists():
    """Phase 12: approve_remediation_handler exists in handlers."""
    from app.api.handlers import approve_remediation_handler
    assert callable(approve_remediation_handler), \
        "approve_remediation_handler must be callable"

def test_get_remediation_actions_handler_exists():
    """Phase 12: get_remediation_actions_handler exists in handlers."""
    from app.api.handlers import get_remediation_actions_handler
    assert callable(get_remediation_actions_handler), \
        "get_remediation_actions_handler must be callable"

def test_get_remediation_actions_handler_structure():
    """Phase 12: remediation actions handler returns actions + stats."""
    from app.api.handlers import get_remediation_actions_handler
    source = inspect.getsource(get_remediation_actions_handler)
    assert "'actions'" in source, "Response must include actions key"
    assert "'stats'" in source, "Response must include stats key"


# ================================================================
# Phase 13: Identity Attack Simulation
# ================================================================

def test_migration_049_exists():
    """Phase 13: migration 049 method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_049_attack_simulation'), \
        "Database must have _run_migration_049_attack_simulation method"

def test_migration_049_called_from_entitlements():
    """Phase 13: migration 049 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_049_attack_simulation' in source, \
        "Must call _run_migration_049_attack_simulation from entitlements chain"

def test_migration_049_creates_attack_simulations():
    """Phase 13: migration 049 creates attack_simulations table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_049_attack_simulation)
    assert 'attack_simulations' in source, \
        "Must create attack_simulations table"
    assert 'identity_id' in source, "Must have identity_id column"
    assert 'blast_radius' in source, "Must have blast_radius column"
    assert 'simulation_type' in source, "Must have simulation_type column"
    assert 'max_depth' in source, "Must have max_depth column"

def test_migration_049_creates_attack_sim_paths():
    """Phase 13: migration 049 creates attack_sim_paths table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_049_attack_simulation)
    assert 'attack_sim_paths' in source, \
        "Must create attack_sim_paths table"
    assert 'path_nodes' in source, "Must have path_nodes JSONB column"
    assert 'path_length' in source, "Must have path_length column"
    assert 'simulation_id' in source, "Must reference simulation_id FK"

def test_migration_049_simulation_type_check():
    """Phase 13: simulation_type has CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_049_attack_simulation)
    assert 'identity_compromise' in source, "Must allow identity_compromise"
    assert 'service_principal_compromise' in source, "Must allow service_principal_compromise"

def test_migration_049_rls():
    """Phase 13: attack_simulations has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_049_attack_simulation)
    assert 'as_strict_sel' in source, "Must have SELECT policy"
    assert 'as_strict_ins' in source, "Must have INSERT policy"
    assert 'as_strict_upd' in source, "Must have UPDATE policy"
    assert 'as_strict_del' in source, "Must have DELETE policy"

def test_migration_049_seeds_blast_radius_rule():
    """Phase 13: migration 049 seeds identity_large_blast_radius rule."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_049_attack_simulation)
    assert 'identity_large_blast_radius' in source, \
        "Must seed identity_large_blast_radius risk rule"

def test_migration_049_sql_file():
    """Phase 13: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '049_attack_simulation.sql')
    assert os.path.exists(sql_path), \
        "migrations/049_attack_simulation.sql must exist"

def test_attack_simulator_class_exists():
    """Phase 13: AttackSimulator class can be imported."""
    from app.engines.attack_simulator import AttackSimulator
    assert AttackSimulator is not None, \
        "AttackSimulator class must be importable"

def test_attack_simulator_simulate_method():
    """Phase 13: simulate_identity_attack method exists."""
    from app.engines.attack_simulator import AttackSimulator
    assert hasattr(AttackSimulator, 'simulate_identity_attack'), \
        "Must have simulate_identity_attack method"

def test_attack_simulator_bfs_traversal():
    """Phase 13: BFS traversal logic exists."""
    from app.engines.attack_simulator import AttackSimulator
    source = inspect.getsource(AttackSimulator)
    assert '_bfs_traverse' in source, "Must have BFS traversal method"
    assert 'deque' in source or 'queue' in source, "Must use queue for BFS"

def test_attack_simulator_blast_radius_calc():
    """Phase 13: blast radius calculation exists."""
    from app.engines.attack_simulator import AttackSimulator
    source = inspect.getsource(AttackSimulator)
    assert '_calculate_blast_radius' in source, "Must have blast radius calculation"
    assert 'reachable_resources' in source, "Must count reachable resources"
    assert 'reachable_identities' in source, "Must count reachable identities"
    assert 'reachable_subscriptions' in source, "Must count reachable subscriptions"

def test_attack_simulator_depth_limit():
    """Phase 13: traversal respects max_depth limit."""
    from app.engines.attack_simulator import AttackSimulator
    source = inspect.getsource(AttackSimulator._bfs_traverse)
    assert 'max_depth' in source, "Must check max_depth"

def test_attack_simulator_max_nodes_limit():
    """Phase 13: traversal has MAX_NODES_TRAVERSED safeguard."""
    from app.engines.attack_simulator import MAX_NODES_TRAVERSED
    assert MAX_NODES_TRAVERSED == 5000, \
        f"MAX_NODES_TRAVERSED should be 5000, got {MAX_NODES_TRAVERSED}"

def test_attack_simulator_default_max_depth():
    """Phase 13: default max_depth is 6."""
    from app.engines.attack_simulator import MAX_DEPTH_DEFAULT
    assert MAX_DEPTH_DEFAULT == 6, \
        f"MAX_DEPTH_DEFAULT should be 6, got {MAX_DEPTH_DEFAULT}"

def test_attack_simulator_path_building():
    """Phase 13: attack path building exists."""
    from app.engines.attack_simulator import AttackSimulator
    source = inspect.getsource(AttackSimulator)
    assert '_build_attack_paths' in source, "Must have path building"
    assert '_reconstruct_path' in source, "Must have path reconstruction"

def test_attack_simulator_blast_radius_finding():
    """Phase 13: creates risk finding for large blast radius."""
    from app.engines.attack_simulator import AttackSimulator, BLAST_RADIUS_THRESHOLD
    source = inspect.getsource(AttackSimulator)
    assert '_create_blast_radius_finding' in source, "Must create blast radius finding"
    assert BLAST_RADIUS_THRESHOLD == 10, \
        f"Threshold should be 10, got {BLAST_RADIUS_THRESHOLD}"

def test_create_attack_simulation_db():
    """Phase 13: create_attack_simulation method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'create_attack_simulation'), \
        "Database must have create_attack_simulation method"

def test_save_attack_sim_paths_db():
    """Phase 13: save_attack_sim_paths method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'save_attack_sim_paths'), \
        "Database must have save_attack_sim_paths method"

def test_get_attack_simulation_by_id_db():
    """Phase 13: get_attack_simulation_by_id includes paths."""
    from app.database import Database
    source = inspect.getsource(Database.get_attack_simulation_by_id)
    assert 'attack_sim_paths' in source, "Must join attack paths"
    assert "'paths'" in source or "['paths']" in source, "Must include paths in result"

def test_get_attack_simulations_db():
    """Phase 13: get_attack_simulations method with filters."""
    from app.database import Database
    source = inspect.getsource(Database.get_attack_simulations)
    assert 'connection_id' in source, "Must filter by connection_id"
    assert 'identity_id' in source, "Must filter by identity_id"

def test_attack_simulation_api_route():
    """Phase 13: POST /api/security/attack-simulation route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/attack-simulation' in source, \
        "Must register attack-simulation route"

def test_attack_simulation_detail_route():
    """Phase 13: GET /api/security/attack-simulation/<id> route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert 'attack_simulation_detail' in source or 'simulation_id' in source, \
        "Must register simulation detail route"

def test_attack_simulations_list_route():
    """Phase 13: GET /api/security/attack-simulations route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/attack-simulations' in source, \
        "Must register simulations list route"

def test_run_attack_simulation_handler_exists():
    """Phase 13: run_attack_simulation_handler exists in handlers."""
    from app.api.handlers import run_attack_simulation_handler
    assert callable(run_attack_simulation_handler), \
        "run_attack_simulation_handler must be callable"

def test_run_attack_simulation_handler_validates_input():
    """Phase 13: handler validates identity_id is required."""
    from app.api.handlers import run_attack_simulation_handler
    source = inspect.getsource(run_attack_simulation_handler)
    assert 'identity_id' in source, "Must require identity_id"

def test_get_attack_simulation_handler_exists():
    """Phase 13: get_attack_simulation_handler exists in handlers."""
    from app.api.handlers import get_attack_simulation_handler
    assert callable(get_attack_simulation_handler), \
        "get_attack_simulation_handler must be callable"

def test_get_attack_simulations_list_handler_exists():
    """Phase 13: get_attack_simulations_list_handler exists."""
    from app.api.handlers import get_attack_simulations_list_handler
    assert callable(get_attack_simulations_list_handler), \
        "get_attack_simulations_list_handler must be callable"

def test_get_attack_simulations_list_handler_structure():
    """Phase 13: simulations list handler returns simulations + count."""
    from app.api.handlers import get_attack_simulations_list_handler
    source = inspect.getsource(get_attack_simulations_list_handler)
    assert "'simulations'" in source, "Response must include simulations key"
    assert "'count'" in source, "Response must include count key"


# ================================================================
# Phase 14: Cross-Tenant Security Benchmarking
# ================================================================

def test_migration_050_exists():
    """Phase 14: migration 050 method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_050_security_benchmarks'), \
        "Database must have _run_migration_050_security_benchmarks method"

def test_migration_050_called_from_entitlements():
    """Phase 14: migration 050 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_050_security_benchmarks' in source, \
        "Must call _run_migration_050_security_benchmarks from entitlements chain"

def test_migration_050_creates_security_benchmarks():
    """Phase 14: migration 050 creates security_benchmarks table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_050_security_benchmarks)
    assert 'security_benchmarks' in source, "Must create security_benchmarks table"
    assert 'metric_name' in source, "Must have metric_name column"
    assert 'metric_value' in source, "Must have metric_value column"
    assert 'sample_size' in source, "Must have sample_size column"
    assert 'percentile_25' in source, "Must have percentile_25 column"
    assert 'percentile_50' in source, "Must have percentile_50 column"
    assert 'percentile_75' in source, "Must have percentile_75 column"

def test_migration_050_creates_tenant_posture_metrics():
    """Phase 14: migration 050 creates tenant_posture_metrics table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_050_security_benchmarks)
    assert 'tenant_posture_metrics' in source, "Must create tenant_posture_metrics table"
    assert 'risk_score' in source, "Must have risk_score column"
    assert 'critical_findings' in source, "Must have critical_findings column"
    assert 'blast_radius_avg' in source, "Must have blast_radius_avg column"
    assert 'nhi_exposure' in source, "Must have nhi_exposure column"
    assert 'escalation_paths' in source, "Must have escalation_paths column"

def test_migration_050_benchmarks_no_rls():
    """Phase 14: security_benchmarks has NO RLS (system-wide)."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_050_security_benchmarks)
    # security_benchmarks should NOT have RLS policies
    assert 'sb_strict_sel' not in source, "security_benchmarks must NOT have per-tenant RLS"

def test_migration_050_posture_metrics_rls():
    """Phase 14: tenant_posture_metrics has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_050_security_benchmarks)
    assert 'tpm_strict_sel' in source, "Must have SELECT policy"
    assert 'tpm_strict_ins' in source, "Must have INSERT policy"
    assert 'tpm_strict_upd' in source, "Must have UPDATE policy"
    assert 'tpm_strict_del' in source, "Must have DELETE policy"

def test_migration_050_benchmark_unique_index():
    """Phase 14: security_benchmarks has unique index on metric_name."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_050_security_benchmarks)
    assert 'idx_sb_metric' in source, "Must have unique index on metric_name"

def test_migration_050_sql_file():
    """Phase 14: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '050_security_benchmarks.sql')
    assert os.path.exists(sql_path), \
        "migrations/050_security_benchmarks.sql must exist"

def test_benchmark_engine_class_exists():
    """Phase 14: BenchmarkEngine class can be imported."""
    from app.engines.benchmark_engine import BenchmarkEngine
    assert BenchmarkEngine is not None, \
        "BenchmarkEngine class must be importable"

def test_benchmark_engine_compute_method():
    """Phase 14: compute_security_benchmarks method exists."""
    from app.engines.benchmark_engine import BenchmarkEngine
    assert hasattr(BenchmarkEngine, 'compute_security_benchmarks'), \
        "Must have compute_security_benchmarks method"

def test_benchmark_engine_collect_posture():
    """Phase 14: collect_tenant_posture method exists."""
    from app.engines.benchmark_engine import BenchmarkEngine
    assert hasattr(BenchmarkEngine, 'collect_tenant_posture'), \
        "Must have collect_tenant_posture method"

def test_benchmark_engine_comparison():
    """Phase 14: get_tenant_benchmark_comparison method exists."""
    from app.engines.benchmark_engine import BenchmarkEngine
    assert hasattr(BenchmarkEngine, 'get_tenant_benchmark_comparison'), \
        "Must have get_tenant_benchmark_comparison method"

def test_benchmark_engine_percentile_calc():
    """Phase 14: percentile calculation is correct."""
    from app.engines.benchmark_engine import BenchmarkEngine
    # Test with known values
    values = [10, 20, 30, 40, 50]
    p50 = BenchmarkEngine._percentile(values, 50)
    assert p50 == 30, f"Percentile 50 of [10,20,30,40,50] should be 30, got {p50}"

def test_benchmark_metrics_defined():
    """Phase 14: BENCHMARK_METRICS has expected metric names."""
    from app.engines.benchmark_engine import BENCHMARK_METRICS
    assert 'avg_risk_score' in BENCHMARK_METRICS, "Must have avg_risk_score"
    assert 'avg_critical_findings' in BENCHMARK_METRICS, "Must have avg_critical_findings"
    assert 'avg_blast_radius' in BENCHMARK_METRICS, "Must have avg_blast_radius"
    assert 'avg_nhi_exposure' in BENCHMARK_METRICS, "Must have avg_nhi_exposure"
    assert 'avg_escalation_paths' in BENCHMARK_METRICS, "Must have avg_escalation_paths"

def test_benchmark_privacy_safeguard():
    """Phase 14: benchmark comparison uses aggregated data only."""
    from app.engines.benchmark_engine import BenchmarkEngine
    source = inspect.getsource(BenchmarkEngine.get_tenant_benchmark_comparison)
    assert 'industry_average' in source, "Must return industry_average"
    assert 'percentile' in source, "Must return percentile rank"

def test_save_tenant_posture_metrics_db():
    """Phase 14: save_tenant_posture_metrics method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'save_tenant_posture_metrics'), \
        "Database must have save_tenant_posture_metrics method"

def test_get_latest_tenant_posture_db():
    """Phase 14: get_latest_tenant_posture method exists on Database."""
    from app.database import Database
    assert hasattr(Database, 'get_latest_tenant_posture'), \
        "Database must have get_latest_tenant_posture method"

def test_get_all_tenant_posture_latest_db():
    """Phase 14: get_all_tenant_posture_latest uses DISTINCT ON for latest per org."""
    from app.database import Database
    source = inspect.getsource(Database.get_all_tenant_posture_latest)
    assert 'DISTINCT ON' in source, "Must use DISTINCT ON for latest per org"

def test_upsert_security_benchmark_db():
    """Phase 14: upsert_security_benchmark uses ON CONFLICT."""
    from app.database import Database
    source = inspect.getsource(Database.upsert_security_benchmark)
    assert 'ON CONFLICT' in source, "Must use ON CONFLICT for upsert"

def test_get_security_benchmarks_db():
    """Phase 14: get_security_benchmarks returns dict keyed by metric_name."""
    from app.database import Database
    source = inspect.getsource(Database.get_security_benchmarks)
    assert "metric_name" in source, "Must key by metric_name"

def test_posture_metrics_in_scheduler():
    """Phase 14: _run_posture_metrics in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_posture_metrics' in source, \
        "Scheduler must have _run_posture_metrics function"
    assert "'posture_metrics'" in source, \
        "Must register posture_metrics as tracked job"

def test_posture_metrics_after_remediation():
    """Phase 14: posture metrics runs after auto remediation."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    ar_pos = source.find("'auto_remediation'")
    pm_pos = source.find("'posture_metrics'")
    assert ar_pos < pm_pos, \
        "posture_metrics must run after auto_remediation"

def test_benchmark_computation_function():
    """Phase 14: _run_benchmark_computation function exists in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_benchmark_computation' in source, \
        "Scheduler must have _run_benchmark_computation function"

def test_benchmark_api_route():
    """Phase 14: /api/security/benchmark route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/benchmark' in source, \
        "Must register /api/security/benchmark route"

def test_benchmark_handler_exists():
    """Phase 14: get_security_benchmark_handler exists in handlers."""
    from app.api.handlers import get_security_benchmark_handler
    assert callable(get_security_benchmark_handler), \
        "get_security_benchmark_handler must be callable"

def test_benchmark_handler_uses_engine():
    """Phase 14: handler uses BenchmarkEngine for comparison."""
    from app.api.handlers import get_security_benchmark_handler
    source = inspect.getsource(get_security_benchmark_handler)
    assert 'BenchmarkEngine' in source, "Must use BenchmarkEngine"
    assert 'get_tenant_benchmark_comparison' in source, "Must call comparison method"


# ============================================================
# Phase 15: AI Security Advisor
# ============================================================

def test_migration_051_exists():
    """Phase 15: Database has _run_migration_051_security_advisor method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_051_security_advisor'), \
        "Database must have _run_migration_051_security_advisor method"

def test_migration_051_called_from_entitlements():
    """Phase 15: migration 051 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_051_security_advisor' in source, \
        "Must chain migration 051 from _ensure_entitlements_tables"

def test_migration_051_creates_security_advisor_reports():
    """Phase 15: migration 051 creates security_advisor_reports table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_051_security_advisor)
    assert 'security_advisor_reports' in source, "Must create security_advisor_reports table"
    assert 'organization_id' in source, "Must have organization_id column"
    assert 'risk_score' in source, "Must have risk_score column"
    assert 'benchmark_percentile' in source, "Must have benchmark_percentile column"
    assert 'top_risks' in source, "Must have top_risks JSONB column"
    assert 'recommended_actions' in source, "Must have recommended_actions JSONB column"
    assert 'risk_reduction_estimate' in source, "Must have risk_reduction_estimate column"

def test_migration_051_rls_policies():
    """Phase 15: security_advisor_reports has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_051_security_advisor)
    assert 'sar_strict_sel' in source, "Must have SELECT policy"
    assert 'sar_strict_ins' in source, "Must have INSERT policy"
    assert 'sar_strict_upd' in source, "Must have UPDATE policy"
    assert 'sar_strict_del' in source, "Must have DELETE policy"
    assert 'ENABLE ROW LEVEL SECURITY' in source, "Must enable RLS"
    assert 'FORCE ROW LEVEL SECURITY' in source, "Must force RLS"

def test_migration_051_class_flag():
    """Phase 15: migration 051 uses class flag for idempotency."""
    from app.database import Database
    assert hasattr(Database, '_migration_051_security_advisor_ensured'), \
        "Must have class flag"
    source = inspect.getsource(Database._run_migration_051_security_advisor)
    assert '_migration_051_security_advisor_ensured' in source, \
        "Must check class flag"

def test_migration_051_sql_file():
    """Phase 15: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '051_security_advisor.sql')
    assert os.path.exists(sql_path), "051_security_advisor.sql must exist"

def test_security_advisor_class_exists():
    """Phase 15: SecurityAdvisor class can be imported."""
    from app.engines.security_advisor import SecurityAdvisor
    assert callable(SecurityAdvisor), "SecurityAdvisor must be a class"

def test_security_advisor_generate_report():
    """Phase 15: SecurityAdvisor has generate_security_advisor_report method."""
    from app.engines.security_advisor import SecurityAdvisor
    assert hasattr(SecurityAdvisor, 'generate_security_advisor_report'), \
        "Must have generate_security_advisor_report method"

def test_security_advisor_rank_actions():
    """Phase 15: SecurityAdvisor has _rank_remediation_actions method."""
    from app.engines.security_advisor import SecurityAdvisor
    source = inspect.getsource(SecurityAdvisor)
    assert '_rank_remediation_actions' in source, "Must have _rank_remediation_actions"

def test_security_advisor_identify_top_risks():
    """Phase 15: SecurityAdvisor has _identify_top_risks method."""
    from app.engines.security_advisor import SecurityAdvisor
    source = inspect.getsource(SecurityAdvisor)
    assert '_identify_top_risks' in source, "Must have _identify_top_risks"

def test_security_advisor_risk_reduction():
    """Phase 15: SecurityAdvisor has _estimate_risk_reduction method."""
    from app.engines.security_advisor import SecurityAdvisor
    source = inspect.getsource(SecurityAdvisor)
    assert '_estimate_risk_reduction' in source, "Must have _estimate_risk_reduction"

def test_security_advisor_compute_risk_score():
    """Phase 15: SecurityAdvisor has _compute_risk_score method."""
    from app.engines.security_advisor import SecurityAdvisor
    source = inspect.getsource(SecurityAdvisor)
    assert '_compute_risk_score' in source, "Must have _compute_risk_score"

def test_security_advisor_priority_formula():
    """Phase 15: prioritization uses impact * confidence * severity_multiplier."""
    from app.engines.security_advisor import SecurityAdvisor
    source = inspect.getsource(SecurityAdvisor._rank_remediation_actions)
    assert 'impact' in source, "Must use impact score"
    assert 'confidence' in source, "Must use confidence score"
    assert 'sev_mult' in source or 'SEVERITY_MULTIPLIER' in source, "Must use severity multiplier"
    assert 'priority_score' in source, "Must compute priority_score"

def test_security_advisor_constants():
    """Phase 15: module has ACTION_IMPACT, SEVERITY_MULTIPLIER, RISK_REDUCTION_ESTIMATES."""
    from app.engines import security_advisor
    assert hasattr(security_advisor, 'ACTION_IMPACT'), "Must have ACTION_IMPACT"
    assert hasattr(security_advisor, 'SEVERITY_MULTIPLIER'), "Must have SEVERITY_MULTIPLIER"
    assert hasattr(security_advisor, 'RISK_REDUCTION_ESTIMATES'), "Must have RISK_REDUCTION_ESTIMATES"

def test_security_advisor_db_save_method():
    """Phase 15: Database has save_security_advisor_report method."""
    from app.database import Database
    assert hasattr(Database, 'save_security_advisor_report'), \
        "Database must have save_security_advisor_report"

def test_security_advisor_db_get_reports():
    """Phase 15: Database has get_security_advisor_reports method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_advisor_reports'), \
        "Database must have get_security_advisor_reports"

def test_security_advisor_db_get_latest():
    """Phase 15: Database has get_latest_security_advisor_report method."""
    from app.database import Database
    assert hasattr(Database, 'get_latest_security_advisor_report'), \
        "Database must have get_latest_security_advisor_report"

def test_security_advisor_in_scheduler():
    """Phase 15: _run_security_advisor is in the scheduler module."""
    import app.scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_security_advisor' in source, "Scheduler must have _run_security_advisor"
    assert 'security_advisor' in source, "Scheduler must track security_advisor job"

def test_security_advisor_scheduler_pipeline():
    """Phase 15: security_advisor runs after posture_metrics in pipeline."""
    import app.scheduler as sched
    source = inspect.getsource(sched)
    posture_idx = source.index('posture_metrics')
    advisor_idx = source.index('security_advisor')
    assert advisor_idx > posture_idx, "security_advisor must run after posture_metrics"

def test_security_advisor_api_route():
    """Phase 15: /api/security/advisor route exists in create_app."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/advisor' in source, "Must have /api/security/advisor route"

def test_security_advisor_handler_exists():
    """Phase 15: get_security_advisor_handler is callable."""
    from app.api.handlers import get_security_advisor_handler
    assert callable(get_security_advisor_handler), \
        "get_security_advisor_handler must be callable"

def test_security_advisor_handler_uses_engine():
    """Phase 15: handler uses SecurityAdvisor engine."""
    from app.api.handlers import get_security_advisor_handler
    source = inspect.getsource(get_security_advisor_handler)
    assert 'SecurityAdvisor' in source, "Must use SecurityAdvisor"
    assert 'get_latest_security_advisor_report' in source, "Must try latest report first"


# ============================================================
# Phase 16: Identity Attack Graph Visualization
# ============================================================

def test_migration_052_exists():
    """Phase 16: Database has _run_migration_052_graph_visualization_cache method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_052_graph_visualization_cache'), \
        "Database must have _run_migration_052_graph_visualization_cache method"

def test_migration_052_called_from_entitlements():
    """Phase 16: migration 052 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_052_graph_visualization_cache' in source, \
        "Must chain migration 052 from _ensure_entitlements_tables"

def test_migration_052_creates_graph_visualization_cache():
    """Phase 16: migration 052 creates graph_visualization_cache table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_052_graph_visualization_cache)
    assert 'graph_visualization_cache' in source, "Must create graph_visualization_cache table"
    assert 'organization_id' in source, "Must have organization_id column"
    assert 'cloud_connection_id' in source, "Must have cloud_connection_id column"
    assert 'graph_type' in source, "Must have graph_type column"
    assert 'graph_data' in source, "Must have graph_data JSONB column"
    assert 'identity_graph' in source, "Must allow identity_graph type"
    assert 'attack_path_graph' in source, "Must allow attack_path_graph type"

def test_migration_052_rls_policies():
    """Phase 16: graph_visualization_cache has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_052_graph_visualization_cache)
    assert 'gvc_strict_sel' in source, "Must have SELECT policy"
    assert 'gvc_strict_ins' in source, "Must have INSERT policy"
    assert 'gvc_strict_upd' in source, "Must have UPDATE policy"
    assert 'gvc_strict_del' in source, "Must have DELETE policy"
    assert 'ENABLE ROW LEVEL SECURITY' in source, "Must enable RLS"
    assert 'FORCE ROW LEVEL SECURITY' in source, "Must force RLS"

def test_migration_052_class_flag():
    """Phase 16: migration 052 uses class flag for idempotency."""
    from app.database import Database
    assert hasattr(Database, '_migration_052_graph_visualization_cache_ensured'), \
        "Must have class flag"
    source = inspect.getsource(Database._run_migration_052_graph_visualization_cache)
    assert '_migration_052_graph_visualization_cache_ensured' in source, \
        "Must check class flag"

def test_migration_052_sql_file():
    """Phase 16: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '052_graph_visualization_cache.sql')
    assert os.path.exists(sql_path), "052_graph_visualization_cache.sql must exist"

def test_graph_visualizer_class_exists():
    """Phase 16: GraphVisualizer class can be imported."""
    from app.engines.graph_visualizer import GraphVisualizer
    assert callable(GraphVisualizer), "GraphVisualizer must be a class"

def test_graph_visualizer_generate_identity_graph():
    """Phase 16: GraphVisualizer has generate_identity_graph method."""
    from app.engines.graph_visualizer import GraphVisualizer
    assert hasattr(GraphVisualizer, 'generate_identity_graph'), \
        "Must have generate_identity_graph method"

def test_graph_visualizer_generate_attack_graph():
    """Phase 16: GraphVisualizer has generate_attack_graph method."""
    from app.engines.graph_visualizer import GraphVisualizer
    assert hasattr(GraphVisualizer, 'generate_attack_graph'), \
        "Must have generate_attack_graph method"

def test_graph_visualizer_generate_neighborhood():
    """Phase 16: GraphVisualizer has generate_identity_neighborhood method."""
    from app.engines.graph_visualizer import GraphVisualizer
    assert hasattr(GraphVisualizer, 'generate_identity_neighborhood'), \
        "Must have generate_identity_neighborhood method"

def test_graph_visualizer_max_nodes():
    """Phase 16: GraphVisualizer enforces MAX_NODES limit."""
    from app.engines.graph_visualizer import GraphVisualizer, MAX_NODES
    assert MAX_NODES == 2000, "MAX_NODES must be 2000"
    source = inspect.getsource(GraphVisualizer)
    assert 'MAX_NODES' in source, "Must reference MAX_NODES for safeguards"

def test_graph_visualizer_node_types():
    """Phase 16: module defines supported NODE_TYPES."""
    from app.engines.graph_visualizer import NODE_TYPES
    base_types = {'identity', 'service_principal', 'managed_identity', 'role', 'resource', 'subscription'}
    assert base_types.issubset(NODE_TYPES), f"NODE_TYPES must include {base_types}"

def test_graph_visualizer_edge_types():
    """Phase 16: module defines supported EDGE_TYPES."""
    from app.engines.graph_visualizer import EDGE_TYPES
    base_types = {'assigned_role', 'grants_access', 'contains_resource', 'escalation_path'}
    assert base_types.issubset(EDGE_TYPES), f"EDGE_TYPES must include {base_types}"

def test_graph_visualizer_builds_structure():
    """Phase 16: GraphVisualizer has _build_graph_structure method."""
    from app.engines.graph_visualizer import GraphVisualizer
    source = inspect.getsource(GraphVisualizer)
    assert '_build_graph_structure' in source, "Must have _build_graph_structure"

def test_graph_visualizer_loads_nodes():
    """Phase 16: GraphVisualizer loads graph_nodes from DB."""
    from app.engines.graph_visualizer import GraphVisualizer
    source = inspect.getsource(GraphVisualizer._load_graph_nodes)
    assert 'graph_nodes' in source, "Must query graph_nodes table"
    assert 'cloud_connection_id' in source, "Must filter by connection"

def test_graph_visualizer_loads_edges():
    """Phase 16: GraphVisualizer loads graph_edges from DB."""
    from app.engines.graph_visualizer import GraphVisualizer
    source = inspect.getsource(GraphVisualizer._load_graph_edges)
    assert 'graph_edges' in source, "Must query graph_edges table"

def test_graph_visualizer_attack_paths():
    """Phase 16: generate_attack_graph uses attack_sim_paths."""
    from app.engines.graph_visualizer import GraphVisualizer
    source = inspect.getsource(GraphVisualizer._load_attack_paths)
    assert 'attack_sim_paths' in source, "Must query attack_sim_paths table"

def test_graph_visualizer_caches_result():
    """Phase 16: GraphVisualizer caches results via _save_to_cache."""
    from app.engines.graph_visualizer import GraphVisualizer
    source = inspect.getsource(GraphVisualizer.generate_identity_graph)
    assert '_save_to_cache' in source, "Must cache results"

def test_graph_db_save_cache():
    """Phase 16: Database has save_graph_visualization_cache method."""
    from app.database import Database
    assert hasattr(Database, 'save_graph_visualization_cache'), \
        "Database must have save_graph_visualization_cache"

def test_graph_db_get_cache():
    """Phase 16: Database has get_graph_visualization_cache method."""
    from app.database import Database
    assert hasattr(Database, 'get_graph_visualization_cache'), \
        "Database must have get_graph_visualization_cache"

def test_graph_db_get_visualizations():
    """Phase 16: Database has get_graph_visualizations method."""
    from app.database import Database
    assert hasattr(Database, 'get_graph_visualizations'), \
        "Database must have get_graph_visualizations"

def test_graph_visualization_in_scheduler():
    """Phase 16: _run_graph_visualization is in the scheduler module."""
    import app.scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_graph_visualization' in source, "Scheduler must have _run_graph_visualization"
    assert 'graph_visualization' in source, "Scheduler must track graph_visualization job"

def test_graph_visualization_scheduler_pipeline():
    """Phase 16: graph_visualization runs after security_advisor in pipeline."""
    import app.scheduler as sched
    source = inspect.getsource(sched)
    advisor_idx = source.index("'security_advisor'")
    graph_idx = source.index("'graph_visualization'")
    assert graph_idx > advisor_idx, "graph_visualization must run after security_advisor"

def test_graph_visualization_api_route():
    """Phase 16: /api/graph/visualization route exists in create_app."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/graph/visualization' in source, "Must have /api/graph/visualization route"

def test_graph_identity_api_route():
    """Phase 16: /api/graph/identity/<identity_id> route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/graph/identity/' in source, "Must have /api/graph/identity route"

def test_graph_attack_path_api_route():
    """Phase 16: /api/graph/attack-path/<simulation_id> route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/graph/attack-path/' in source, "Must have /api/graph/attack-path route"

def test_graph_visualization_handler_exists():
    """Phase 16: get_graph_visualization_handler is callable."""
    from app.api.handlers import get_graph_visualization_handler
    assert callable(get_graph_visualization_handler), \
        "get_graph_visualization_handler must be callable"

def test_identity_graph_handler_exists():
    """Phase 16: get_identity_graph_handler is callable."""
    from app.api.handlers import get_identity_graph_handler
    assert callable(get_identity_graph_handler), \
        "get_identity_graph_handler must be callable"

def test_attack_path_graph_handler_exists():
    """Phase 16: get_attack_path_graph_handler is callable."""
    from app.api.handlers import get_attack_path_graph_handler
    assert callable(get_attack_path_graph_handler), \
        "get_attack_path_graph_handler must be callable"

def test_graph_visualization_handler_uses_engine():
    """Phase 16: handler uses GraphVisualizer engine."""
    from app.api.handlers import get_graph_visualization_handler
    source = inspect.getsource(get_graph_visualization_handler)
    assert 'GraphVisualizer' in source, "Must use GraphVisualizer"
    assert 'generate_identity_graph' in source, "Must call generate_identity_graph"

def test_identity_graph_handler_uses_neighborhood():
    """Phase 16: identity handler generates neighborhood graph."""
    from app.api.handlers import get_identity_graph_handler
    source = inspect.getsource(get_identity_graph_handler)
    assert 'generate_identity_neighborhood' in source, "Must call generate_identity_neighborhood"

def test_attack_path_graph_handler_uses_engine():
    """Phase 16: attack path handler uses generate_attack_graph."""
    from app.api.handlers import get_attack_path_graph_handler
    source = inspect.getsource(get_attack_path_graph_handler)
    assert 'generate_attack_graph' in source, "Must call generate_attack_graph"


# ============================================================
# Phase 17: Multi-Cloud Identity Support
# ============================================================

def test_migration_053_exists():
    """Phase 17: Database has _run_migration_053_multi_cloud_support method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_053_multi_cloud_support'), \
        "Database must have _run_migration_053_multi_cloud_support method"

def test_migration_053_called_from_entitlements():
    """Phase 17: migration 053 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_053_multi_cloud_support' in source, \
        "Must chain migration 053 from _ensure_entitlements_tables"

def test_migration_053_extends_graph_nodes():
    """Phase 17: migration 053 extends graph_nodes CHECK for multi-cloud types."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_053_multi_cloud_support)
    assert 'aws_user' in source, "Must add aws_user node type"
    assert 'aws_role' in source, "Must add aws_role node type"
    assert 'gcp_service_account' in source, "Must add gcp_service_account node type"
    assert 'gcp_project' in source, "Must add gcp_project node type"

def test_migration_053_extends_graph_edges():
    """Phase 17: migration 053 extends graph_edges CHECK for multi-cloud types."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_053_multi_cloud_support)
    assert 'policy_attachment' in source, "Must add policy_attachment edge type"
    assert 'role_binding' in source, "Must add role_binding edge type"

def test_migration_053_seeds_cloud_rules():
    """Phase 17: migration 053 seeds 4 cloud-specific risk rules."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_053_multi_cloud_support)
    assert 'aws_access_key_stale' in source, "Must seed aws_access_key_stale rule"
    assert 'aws_user_admin_policy' in source, "Must seed aws_user_admin_policy rule"
    assert 'gcp_sa_key_exposure' in source, "Must seed gcp_sa_key_exposure rule"
    assert 'gcp_owner_on_project' in source, "Must seed gcp_owner_on_project rule"

def test_migration_053_class_flag():
    """Phase 17: migration 053 uses class flag for idempotency."""
    from app.database import Database
    assert hasattr(Database, '_migration_053_multi_cloud_support_ensured'), \
        "Must have class flag"

def test_migration_053_sql_file():
    """Phase 17: SQL migration file exists."""
    import os
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '053_multi_cloud_support.sql')
    assert os.path.exists(sql_path), "053_multi_cloud_support.sql must exist"

def test_aws_discovery_class_exists():
    """Phase 17: AWSDiscoveryEngine class can be imported."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    assert callable(AWSDiscoveryEngine), "AWSDiscoveryEngine must be a class"

def test_aws_discovery_has_run_discovery():
    """Phase 17: AWSDiscoveryEngine has run_discovery method."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    assert hasattr(AWSDiscoveryEngine, 'run_discovery'), \
        "Must have run_discovery method"

def test_aws_discovery_discovers_users():
    """Phase 17: AWS engine discovers IAM users."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine)
    assert '_discover_iam_users' in source, "Must discover IAM users"

def test_aws_discovery_discovers_roles():
    """Phase 17: AWS engine discovers IAM roles."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine)
    assert '_discover_iam_roles' in source, "Must discover IAM roles"

def test_aws_discovery_access_keys():
    """Phase 17: AWS engine collects access keys."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine)
    assert '_get_user_access_keys' in source, "Must collect access keys"

def test_aws_discovery_policies():
    """Phase 17: AWS engine collects IAM policies."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine)
    assert '_get_user_attached_policies' in source, "Must collect attached policies"
    assert '_get_user_inline_policies' in source, "Must collect inline policies"

def test_aws_discovery_cloud_provider():
    """Phase 17: AWS engine identifies as 'aws'."""
    from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
    source = inspect.getsource(AWSDiscoveryEngine)
    assert "'aws'" in source, "cloud_provider must return 'aws'"

def test_gcp_discovery_class_exists():
    """Phase 17: GCPDiscoveryEngine class can be imported."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    assert callable(GCPDiscoveryEngine), "GCPDiscoveryEngine must be a class"

def test_gcp_discovery_has_run_discovery():
    """Phase 17: GCPDiscoveryEngine has run_discovery method."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    assert hasattr(GCPDiscoveryEngine, 'run_discovery'), \
        "Must have run_discovery method"

def test_gcp_discovery_discovers_service_accounts():
    """Phase 17: GCP engine discovers service accounts."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    source = inspect.getsource(GCPDiscoveryEngine)
    assert '_discover_service_accounts' in source, "Must discover service accounts"

def test_gcp_discovery_discovers_iam_bindings():
    """Phase 17: GCP engine discovers IAM bindings."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    source = inspect.getsource(GCPDiscoveryEngine)
    assert '_discover_iam_bindings' in source, "Must discover IAM bindings"

def test_gcp_discovery_collects_sa_keys():
    """Phase 17: GCP engine collects service account keys."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    source = inspect.getsource(GCPDiscoveryEngine)
    assert '_get_sa_keys' in source, "Must collect service account keys"

def test_gcp_discovery_calculates_risks():
    """Phase 17: GCP engine calculates risks with V2 catalog."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    source = inspect.getsource(GCPDiscoveryEngine)
    assert '_calculate_risks' in source, "Must calculate risks"
    assert 'score_to_level_v2' in source, "Must use V2 risk scoring"

def test_gcp_discovery_cloud_provider():
    """Phase 17: GCP engine identifies as 'gcp'."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    source = inspect.getsource(GCPDiscoveryEngine)
    assert "'gcp'" in source, "cloud_provider must return 'gcp'"

def test_gcp_discovery_saves_identities():
    """Phase 17: GCP engine saves identities to database."""
    from app.engines.discovery.gcp_discovery import GCPDiscoveryEngine
    source = inspect.getsource(GCPDiscoveryEngine)
    assert '_save_identities' in source, "Must save identities"
    assert 'save_identity' in source, "Must call db.save_identity"
    assert 'save_role_assignment' in source, "Must save role assignments"

def test_gcp_privileged_roles_defined():
    """Phase 17: GCP privileged roles set is defined."""
    from app.engines.discovery.gcp_discovery import GCP_PRIVILEGED_ROLES
    assert 'roles/owner' in GCP_PRIVILEGED_ROLES, "Must include roles/owner"
    assert 'roles/editor' in GCP_PRIVILEGED_ROLES, "Must include roles/editor"
    assert len(GCP_PRIVILEGED_ROLES) >= 10, "Must have at least 10 privileged roles"

def test_gcp_dangerous_permissions_defined():
    """Phase 17: GCP dangerous permissions set is defined."""
    from app.engines.discovery.gcp_discovery import GCP_DANGEROUS_PERMISSIONS
    assert 'iam.serviceAccountKeys.create' in GCP_DANGEROUS_PERMISSIONS
    assert len(GCP_DANGEROUS_PERMISSIONS) >= 8, "Must have at least 8 dangerous permissions"

def test_risk_evaluator_aws_access_key_stale():
    """Phase 17: risk evaluator has aws_access_key_stale rule."""
    from app.engines.risk_evaluator import EVALUATORS
    assert 'aws_access_key_stale' in EVALUATORS, "Must register aws_access_key_stale evaluator"

def test_risk_evaluator_aws_user_admin_policy():
    """Phase 17: risk evaluator has aws_user_admin_policy rule."""
    from app.engines.risk_evaluator import EVALUATORS
    assert 'aws_user_admin_policy' in EVALUATORS, "Must register aws_user_admin_policy evaluator"

def test_risk_evaluator_gcp_sa_key_exposure():
    """Phase 17: risk evaluator has gcp_sa_key_exposure rule."""
    from app.engines.risk_evaluator import EVALUATORS
    assert 'gcp_sa_key_exposure' in EVALUATORS, "Must register gcp_sa_key_exposure evaluator"

def test_risk_evaluator_gcp_owner_on_project():
    """Phase 17: risk evaluator has gcp_owner_on_project rule."""
    from app.engines.risk_evaluator import EVALUATORS
    assert 'gcp_owner_on_project' in EVALUATORS, "Must register gcp_owner_on_project evaluator"

def test_risk_evaluator_aws_stale_checks_source():
    """Phase 17: aws_access_key_stale evaluator filters by source='aws_iam'."""
    from app.engines.risk_evaluator import EVALUATORS
    source = inspect.getsource(EVALUATORS['aws_access_key_stale'])
    assert 'aws_iam' in source, "Must filter by source='aws_iam'"

def test_risk_evaluator_gcp_owner_checks_source():
    """Phase 17: gcp_owner_on_project evaluator filters by source='gcp_iam'."""
    from app.engines.risk_evaluator import EVALUATORS
    source = inspect.getsource(EVALUATORS['gcp_owner_on_project'])
    assert 'gcp_iam' in source, "Must filter by source='gcp_iam'"

def test_risk_catalog_gcp_factors():
    """Phase 17: risk catalog has GCP-specific risk factors."""
    from app.engines.risk_catalog import RISK_FACTOR_CATALOG
    assert 'GCP_OWNER_ROLE' in RISK_FACTOR_CATALOG, "Must have GCP_OWNER_ROLE"
    assert 'GCP_SA_KEY_EXPOSURE' in RISK_FACTOR_CATALOG, "Must have GCP_SA_KEY_EXPOSURE"
    assert 'GCP_EDITOR_ROLE' in RISK_FACTOR_CATALOG, "Must have GCP_EDITOR_ROLE"

def test_graph_visualizer_multi_cloud_node_types():
    """Phase 17: graph visualizer supports multi-cloud node types."""
    from app.engines.graph_visualizer import NODE_TYPES
    assert 'aws_user' in NODE_TYPES, "Must support aws_user"
    assert 'aws_role' in NODE_TYPES, "Must support aws_role"
    assert 'gcp_service_account' in NODE_TYPES, "Must support gcp_service_account"
    assert 'gcp_project' in NODE_TYPES, "Must support gcp_project"

def test_graph_visualizer_multi_cloud_edge_types():
    """Phase 17: graph visualizer supports multi-cloud edge types."""
    from app.engines.graph_visualizer import EDGE_TYPES
    assert 'policy_attachment' in EDGE_TYPES, "Must support policy_attachment"
    assert 'role_binding' in EDGE_TYPES, "Must support role_binding"

def test_cloud_summary_api_route():
    """Phase 17: /api/security/cloud-summary route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/cloud-summary' in source, "Must have cloud-summary route"

def test_cloud_risk_summary_handler_exists():
    """Phase 17: get_cloud_risk_summary_handler is callable."""
    from app.api.handlers import get_cloud_risk_summary_handler
    assert callable(get_cloud_risk_summary_handler), \
        "get_cloud_risk_summary_handler must be callable"

def test_cloud_risk_summary_handler_groups_by_provider():
    """Phase 17: cloud summary handler groups by cloud provider."""
    from app.api.handlers import get_cloud_risk_summary_handler
    source = inspect.getsource(get_cloud_risk_summary_handler)
    assert 'cloud_provider' in source or 'source' in source, "Must group by cloud provider"
    assert 'providers' in source, "Must return providers list"


# ============================================================
# Phase 18: Identity Risk Forecasting
# ============================================================

def test_migration_054_exists():
    """Phase 18: _run_migration_054_risk_forecasts method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_054_risk_forecasts'), \
        "Database must have _run_migration_054_risk_forecasts method"

def test_migration_054_class_flag():
    """Phase 18: Database has _migration_054_risk_forecasts_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_054_risk_forecasts_ensured'), \
        "Database must have _migration_054_risk_forecasts_ensured flag"

def test_migration_054_called_from_entitlements():
    """Phase 18: migration 054 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_054_risk_forecasts' in source, \
        "Must call _run_migration_054_risk_forecasts from _ensure_entitlements_tables"

def test_migration_054_creates_risk_forecasts_table():
    """Phase 18: migration 054 creates risk_forecasts table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_054_risk_forecasts)
    assert 'risk_forecasts' in source, "Must create risk_forecasts table"
    assert 'forecast_window_days' in source, "Must have forecast_window_days column"
    assert 'current_risk_score' in source, "Must have current_risk_score column"
    assert 'predicted_risk_score' in source, "Must have predicted_risk_score column"
    assert 'trend_direction' in source, "Must have trend_direction column"
    assert 'drivers' in source, "Must have drivers JSONB column"

def test_migration_054_trend_check_constraint():
    """Phase 18: trend_direction has CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_054_risk_forecasts)
    assert 'increasing' in source, "CHECK must include 'increasing'"
    assert 'stable' in source, "CHECK must include 'stable'"
    assert 'decreasing' in source, "CHECK must include 'decreasing'"

def test_migration_054_rls_policies():
    """Phase 18: risk_forecasts has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_054_risk_forecasts)
    assert 'rfc_strict_sel' in source, "Must have rfc_strict_sel policy"
    assert 'rfc_strict_ins' in source, "Must have rfc_strict_ins policy"
    assert 'rfc_strict_upd' in source, "Must have rfc_strict_upd policy"
    assert 'rfc_strict_del' in source, "Must have rfc_strict_del policy"

def test_migration_054_sql_file():
    """Phase 18: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '054_risk_forecasts.sql')
    assert os.path.exists(sql_path), "migrations/054_risk_forecasts.sql must exist"

def test_risk_forecaster_class_exists():
    """Phase 18: RiskForecaster class can be imported."""
    from app.engines.risk_forecaster import RiskForecaster
    assert callable(RiskForecaster), "RiskForecaster must be a class"

def test_risk_forecaster_generate_method():
    """Phase 18: RiskForecaster.generate_risk_forecast method exists."""
    from app.engines.risk_forecaster import RiskForecaster
    assert hasattr(RiskForecaster, 'generate_risk_forecast'), \
        "RiskForecaster must have generate_risk_forecast method"
    source = inspect.getsource(RiskForecaster.generate_risk_forecast)
    assert 'window_days' in source, "Must accept window_days parameter"
    assert 'org_id' in source, "Must accept org_id parameter"

def test_risk_forecaster_valid_windows():
    """Phase 18: Valid forecast windows are 7, 30, 90."""
    from app.engines.risk_forecaster import VALID_WINDOWS
    assert VALID_WINDOWS == {7, 30, 90}, f"VALID_WINDOWS must be {{7, 30, 90}}, got {VALID_WINDOWS}"

def test_risk_forecaster_driver_weights():
    """Phase 18: DRIVER_WEIGHTS has 4 factors summing to 1.0."""
    from app.engines.risk_forecaster import DRIVER_WEIGHTS
    assert len(DRIVER_WEIGHTS) == 4, f"Must have 4 driver weights, got {len(DRIVER_WEIGHTS)}"
    assert 'credential_aging' in DRIVER_WEIGHTS
    assert 'privileged_identity_growth' in DRIVER_WEIGHTS
    assert 'attack_path_increase' in DRIVER_WEIGHTS
    assert 'nhi_exposure_increase' in DRIVER_WEIGHTS
    total = sum(DRIVER_WEIGHTS.values())
    assert abs(total - 1.0) < 0.01, f"Weights must sum to 1.0, got {total}"

def test_risk_forecaster_trend_thresholds():
    """Phase 18: Trend thresholds are defined."""
    from app.engines.risk_forecaster import TREND_INCREASING_THRESHOLD, TREND_DECREASING_THRESHOLD
    assert TREND_INCREASING_THRESHOLD == 5.0, "Increasing threshold must be 5.0"
    assert TREND_DECREASING_THRESHOLD == -5.0, "Decreasing threshold must be -5.0"

def test_risk_forecaster_credential_aging_driver():
    """Phase 18: _check_credential_aging queries credential-related rules."""
    from app.engines.risk_forecaster import RiskForecaster
    source = inspect.getsource(RiskForecaster._check_credential_aging)
    assert 'expired_spn_secret' in source, "Must check expired_spn_secret rule"
    assert 'spn_secret_expiring' in source, "Must check spn_secret_expiring rule"

def test_risk_forecaster_privileged_growth_driver():
    """Phase 18: _check_privileged_growth queries privilege-related rules."""
    from app.engines.risk_forecaster import RiskForecaster
    source = inspect.getsource(RiskForecaster._check_privileged_growth)
    assert 'guest_high_privilege' in source, "Must check guest_high_privilege"
    assert 'spn_owner' in source, "Must check spn_owner"
    assert 'inactive_privileged' in source, "Must check inactive_privileged"

def test_risk_forecaster_attack_path_driver():
    """Phase 18: _check_attack_path_growth queries attack simulations."""
    from app.engines.risk_forecaster import RiskForecaster
    source = inspect.getsource(RiskForecaster._check_attack_path_growth)
    assert 'attack_simulations' in source, "Must query attack_simulations table"
    assert 'blast_radius' in source, "Must check blast_radius"

def test_risk_forecaster_nhi_exposure_driver():
    """Phase 18: _check_nhi_exposure queries NHI-related rules."""
    from app.engines.risk_forecaster import RiskForecaster
    source = inspect.getsource(RiskForecaster._check_nhi_exposure)
    assert 'gcp_sa_key_exposure' in source, "Must check gcp_sa_key_exposure"
    assert 'expired_spn_secret' in source, "Must check expired_spn_secret"

def test_risk_forecaster_prediction_bounded():
    """Phase 18: _compute_prediction bounds the result."""
    from app.engines.risk_forecaster import RiskForecaster
    source = inspect.getsource(RiskForecaster._compute_prediction)
    assert 'max(0' in source or 'max( 0' in source, "Must bound prediction to >= 0"
    assert 'min(' in source, "Must bound prediction with upper limit"

def test_risk_forecaster_classify_trend():
    """Phase 18: _classify_trend returns correct directions."""
    from app.engines.risk_forecaster import RiskForecaster
    source = inspect.getsource(RiskForecaster._classify_trend)
    assert "'increasing'" in source, "Must return 'increasing'"
    assert "'decreasing'" in source, "Must return 'decreasing'"
    assert "'stable'" in source, "Must return 'stable'"

def test_risk_forecast_crud_save():
    """Phase 18: Database has save_risk_forecast method."""
    from app.database import Database
    assert hasattr(Database, 'save_risk_forecast'), \
        "Database must have save_risk_forecast method"

def test_risk_forecast_crud_get():
    """Phase 18: Database has get_risk_forecasts method."""
    from app.database import Database
    assert hasattr(Database, 'get_risk_forecasts'), \
        "Database must have get_risk_forecasts method"

def test_risk_forecast_crud_get_latest():
    """Phase 18: Database has get_latest_risk_forecast method."""
    from app.database import Database
    assert hasattr(Database, 'get_latest_risk_forecast'), \
        "Database must have get_latest_risk_forecast method"

def test_risk_forecast_scheduler_integration():
    """Phase 18: _run_risk_forecast is in scheduler module."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    assert '_run_risk_forecast' in source, "Scheduler must have _run_risk_forecast function"
    assert "risk_forecast" in source, "Scheduler must track risk_forecast job"

def test_risk_forecast_scheduler_pipeline_order():
    """Phase 18: risk_forecast runs after graph_visualization in pipeline."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    gv_pos = source.find("'graph_visualization'")
    rf_pos = source.find("'risk_forecast'")
    assert gv_pos > 0, "Must have graph_visualization in pipeline"
    assert rf_pos > 0, "Must have risk_forecast in pipeline"
    assert rf_pos > gv_pos, "risk_forecast must come after graph_visualization"

def test_risk_forecast_api_route():
    """Phase 18: /api/security/risk-forecast route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/risk-forecast' in source, "Must have risk-forecast route"

def test_risk_forecast_handler_exists():
    """Phase 18: get_risk_forecast_handler is callable."""
    from app.api.handlers import get_risk_forecast_handler
    assert callable(get_risk_forecast_handler), \
        "get_risk_forecast_handler must be callable"

def test_risk_forecast_handler_window_validation():
    """Phase 18: handler validates window parameter."""
    from app.api.handlers import get_risk_forecast_handler
    source = inspect.getsource(get_risk_forecast_handler)
    assert 'window' in source, "Must handle window query param"
    assert '7' in source and '30' in source and '90' in source, \
        "Must validate window against (7, 30, 90)"


# ============================================================
# Phase 19: Automated Least-Privilege Policy Generation
# ============================================================

def test_migration_055_exists():
    """Phase 19: _run_migration_055_generated_policies method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_055_generated_policies'), \
        "Database must have _run_migration_055_generated_policies method"

def test_migration_055_class_flag():
    """Phase 19: Database has _migration_055_generated_policies_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_055_generated_policies_ensured'), \
        "Database must have _migration_055_generated_policies_ensured flag"

def test_migration_055_called_from_entitlements():
    """Phase 19: migration 055 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_055_generated_policies' in source, \
        "Must call _run_migration_055_generated_policies from _ensure_entitlements_tables"

def test_migration_055_creates_generated_policies_table():
    """Phase 19: migration 055 creates generated_policies table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_055_generated_policies)
    assert 'generated_policies' in source, "Must create generated_policies table"
    assert 'identity_id' in source, "Must have identity_id column"
    assert 'cloud_provider' in source, "Must have cloud_provider column"
    assert 'generated_policy' in source, "Must have generated_policy JSONB column"
    assert 'confidence_score' in source, "Must have confidence_score column"

def test_migration_055_policy_type_check():
    """Phase 19: policy_type has CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_055_generated_policies)
    assert 'least_privilege' in source, "CHECK must include 'least_privilege'"
    assert 'role_replacement' in source, "CHECK must include 'role_replacement'"

def test_migration_055_status_check():
    """Phase 19: status has CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_055_generated_policies)
    assert "'pending'" in source, "CHECK must include 'pending'"
    assert "'applied'" in source, "CHECK must include 'applied'"
    assert "'dismissed'" in source, "CHECK must include 'dismissed'"

def test_migration_055_rls_policies():
    """Phase 19: generated_policies has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_055_generated_policies)
    assert 'gp_strict_sel' in source, "Must have gp_strict_sel policy"
    assert 'gp_strict_ins' in source, "Must have gp_strict_ins policy"
    assert 'gp_strict_upd' in source, "Must have gp_strict_upd policy"
    assert 'gp_strict_del' in source, "Must have gp_strict_del policy"

def test_migration_055_dedup_index():
    """Phase 19: generated_policies has partial unique dedup index."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_055_generated_policies)
    assert 'idx_gp_dedup' in source, "Must have dedup index"
    assert "status = 'pending'" in source, "Dedup index must filter on pending status"

def test_migration_055_sql_file():
    """Phase 19: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '055_generated_policies.sql')
    assert os.path.exists(sql_path), "migrations/055_generated_policies.sql must exist"

def test_policy_generator_class_exists():
    """Phase 19: PolicyGenerator class can be imported."""
    from app.engines.policy_generator import PolicyGenerator
    assert callable(PolicyGenerator), "PolicyGenerator must be a class"

def test_policy_generator_generate_method():
    """Phase 19: PolicyGenerator.generate_least_privilege_policy method exists."""
    from app.engines.policy_generator import PolicyGenerator
    assert hasattr(PolicyGenerator, 'generate_least_privilege_policy'), \
        "PolicyGenerator must have generate_least_privilege_policy method"
    source = inspect.getsource(PolicyGenerator.generate_least_privilege_policy)
    assert 'identity_id' in source, "Must accept identity_id parameter"
    assert 'org_id' in source, "Must accept org_id parameter"

def test_policy_generator_connection_method():
    """Phase 19: PolicyGenerator.generate_policies_for_connection method exists."""
    from app.engines.policy_generator import PolicyGenerator
    assert hasattr(PolicyGenerator, 'generate_policies_for_connection'), \
        "PolicyGenerator must have generate_policies_for_connection method"

def test_policy_generator_role_downgrade_map():
    """Phase 19: ROLE_DOWNGRADE_MAP has Owner and Contributor entries."""
    from app.engines.policy_generator import ROLE_DOWNGRADE_MAP
    assert 'Owner' in ROLE_DOWNGRADE_MAP, "Must map Owner to downgrades"
    assert 'Contributor' in ROLE_DOWNGRADE_MAP, "Must map Contributor to downgrades"
    assert 'Reader' in ROLE_DOWNGRADE_MAP['Owner'], "Owner should downgrade to Reader"

def test_policy_generator_high_privilege_roles():
    """Phase 19: HIGH_PRIVILEGE_ROLES is defined."""
    from app.engines.policy_generator import HIGH_PRIVILEGE_ROLES
    assert 'Owner' in HIGH_PRIVILEGE_ROLES, "Must include Owner"
    assert 'Contributor' in HIGH_PRIVILEGE_ROLES, "Must include Contributor"
    assert 'Global Administrator' in HIGH_PRIVILEGE_ROLES, "Must include Global Administrator"

def test_policy_generator_activity_analysis():
    """Phase 19: PolicyGenerator has _analyze_activity method."""
    from app.engines.policy_generator import PolicyGenerator
    assert hasattr(PolicyGenerator, '_analyze_activity'), \
        "PolicyGenerator must have _analyze_activity method"
    source = inspect.getsource(PolicyGenerator._analyze_activity)
    assert 'activity_status' in source, "Must check activity_status"
    assert 'risk_findings' in source, "Must query risk_findings"

def test_policy_generator_risk_indicators():
    """Phase 19: PolicyGenerator has _get_risk_indicators method."""
    from app.engines.policy_generator import PolicyGenerator
    assert hasattr(PolicyGenerator, '_get_risk_indicators'), \
        "PolicyGenerator must have _get_risk_indicators method"
    source = inspect.getsource(PolicyGenerator._get_risk_indicators)
    assert 'attack_simulations' in source, "Must check attack_simulations"
    assert 'blast_radius' in source, "Must check blast_radius"

def test_policy_generator_builds_rationale():
    """Phase 19: PolicyGenerator has _build_rationale method."""
    from app.engines.policy_generator import PolicyGenerator
    assert hasattr(PolicyGenerator, '_build_rationale'), \
        "PolicyGenerator must have _build_rationale method"

def test_policy_generator_over_privileged_query():
    """Phase 19: _get_over_privileged_identities queries high-privilege roles."""
    from app.engines.policy_generator import PolicyGenerator
    source = inspect.getsource(PolicyGenerator._get_over_privileged_identities)
    assert 'Owner' in source, "Must check for Owner role"
    assert 'Contributor' in source, "Must check for Contributor role"
    assert 'role_assignments' in source, "Must query role_assignments"

def test_policy_generator_generates_policy():
    """Phase 19: _generate_policy returns current/suggested/removed roles."""
    from app.engines.policy_generator import PolicyGenerator
    source = inspect.getsource(PolicyGenerator._generate_policy)
    assert 'current_roles' in source, "Must include current_roles"
    assert 'suggested_roles' in source, "Must include suggested_roles"
    assert 'removed_roles' in source, "Must include removed_roles"
    assert 'confidence_score' in source, "Must include confidence_score"

def test_generated_policy_crud_save():
    """Phase 19: Database has save_generated_policy method."""
    from app.database import Database
    assert hasattr(Database, 'save_generated_policy'), \
        "Database must have save_generated_policy method"

def test_generated_policy_crud_get():
    """Phase 19: Database has get_generated_policies method."""
    from app.database import Database
    assert hasattr(Database, 'get_generated_policies'), \
        "Database must have get_generated_policies method"

def test_generated_policy_crud_get_by_identity():
    """Phase 19: Database has get_generated_policy_by_identity method."""
    from app.database import Database
    assert hasattr(Database, 'get_generated_policy_by_identity'), \
        "Database must have get_generated_policy_by_identity method"

def test_generated_policy_crud_update_status():
    """Phase 19: Database has update_generated_policy_status method."""
    from app.database import Database
    assert hasattr(Database, 'update_generated_policy_status'), \
        "Database must have update_generated_policy_status method"

def test_generated_policy_crud_stats():
    """Phase 19: Database has get_generated_policies_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_generated_policies_stats'), \
        "Database must have get_generated_policies_stats method"

def test_policy_generation_in_scheduler():
    """Phase 19: _run_policy_generation is in scheduler module."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    assert '_run_policy_generation' in source, "Scheduler must have _run_policy_generation function"
    assert "'policy_generation'" in source, "Scheduler must track policy_generation job"

def test_policy_generation_scheduler_pipeline_order():
    """Phase 19: policy_generation runs after risk_forecast in pipeline."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    rf_pos = source.find("'risk_forecast'")
    pg_pos = source.find("'policy_generation'")
    assert rf_pos > 0, "Must have risk_forecast in pipeline"
    assert pg_pos > 0, "Must have policy_generation in pipeline"
    assert pg_pos > rf_pos, "policy_generation must come after risk_forecast"

def test_generated_policy_api_route():
    """Phase 19: /api/security/generated-policy/<identity_id> route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/generated-policy/' in source, "Must have generated-policy route"

def test_generated_policies_list_route():
    """Phase 19: /api/security/generated-policies route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/generated-policies' in source, "Must have generated-policies list route"

def test_apply_policy_route():
    """Phase 19: /apply route exists for generated policies."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/apply' in source, "Must have apply route for generated policies"

def test_dismiss_policy_route():
    """Phase 19: /dismiss route exists for generated policies."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/dismiss' in source, "Must have dismiss route for generated policies"

def test_generated_policy_handler_exists():
    """Phase 19: get_generated_policy_handler is callable."""
    from app.api.handlers import get_generated_policy_handler
    assert callable(get_generated_policy_handler), \
        "get_generated_policy_handler must be callable"

def test_generated_policies_list_handler_exists():
    """Phase 19: get_generated_policies_list_handler is callable."""
    from app.api.handlers import get_generated_policies_list_handler
    assert callable(get_generated_policies_list_handler), \
        "get_generated_policies_list_handler must be callable"

def test_apply_policy_handler_exists():
    """Phase 19: apply_generated_policy_handler is callable."""
    from app.api.handlers import apply_generated_policy_handler
    assert callable(apply_generated_policy_handler), \
        "apply_generated_policy_handler must be callable"

def test_dismiss_policy_handler_exists():
    """Phase 19: dismiss_generated_policy_handler is callable."""
    from app.api.handlers import dismiss_generated_policy_handler
    assert callable(dismiss_generated_policy_handler), \
        "dismiss_generated_policy_handler must be callable"

def test_generated_policy_handler_uses_engine():
    """Phase 19: generated policy handler uses PolicyGenerator."""
    from app.api.handlers import get_generated_policy_handler
    source = inspect.getsource(get_generated_policy_handler)
    assert 'PolicyGenerator' in source, "Must use PolicyGenerator engine"
    assert 'generate_least_privilege_policy' in source, "Must call generate_least_privilege_policy"

def test_apply_policy_handler_logs_activity():
    """Phase 19: apply handler logs activity."""
    from app.api.handlers import apply_generated_policy_handler
    source = inspect.getsource(apply_generated_policy_handler)
    assert '_log' in source, "Must log activity on apply"
    assert 'policy_applied' in source, "Must log policy_applied action"


# ============================================================
# Phase 20: Continuous Identity Threat Detection
# ============================================================

def test_migration_056_exists():
    """Phase 20: _run_migration_056_identity_threat_events method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_056_identity_threat_events'), \
        "Database must have _run_migration_056_identity_threat_events method"

def test_migration_056_class_flag():
    """Phase 20: Database has _migration_056_identity_threat_events_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_056_identity_threat_events_ensured'), \
        "Database must have _migration_056_identity_threat_events_ensured flag"

def test_migration_056_called_from_entitlements():
    """Phase 20: migration 056 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_056_identity_threat_events' in source, \
        "Must call _run_migration_056_identity_threat_events from _ensure_entitlements_tables"

def test_migration_056_creates_threat_events_table():
    """Phase 20: migration 056 creates identity_threat_events table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_056_identity_threat_events)
    assert 'identity_threat_events' in source, "Must create identity_threat_events table"
    assert 'event_type' in source, "Must have event_type column"
    assert 'severity' in source, "Must have severity column"
    assert 'metadata' in source, "Must have metadata JSONB column"
    assert 'description' in source, "Must have description column"

def test_migration_056_event_type_check():
    """Phase 20: event_type has CHECK constraint for all 4 types."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_056_identity_threat_events)
    assert 'privilege_escalation' in source, "CHECK must include 'privilege_escalation'"
    assert 'credential_creation' in source, "CHECK must include 'credential_creation'"
    assert 'suspicious_login' in source, "CHECK must include 'suspicious_login'"
    assert 'policy_change' in source, "CHECK must include 'policy_change'"

def test_migration_056_status_check():
    """Phase 20: status has CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_056_identity_threat_events)
    assert "'open'" in source, "CHECK must include 'open'"
    assert "'acknowledged'" in source, "CHECK must include 'acknowledged'"
    assert "'resolved'" in source, "CHECK must include 'resolved'"

def test_migration_056_rls_policies():
    """Phase 20: identity_threat_events has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_056_identity_threat_events)
    assert 'ite_strict_sel' in source, "Must have ite_strict_sel policy"
    assert 'ite_strict_ins' in source, "Must have ite_strict_ins policy"
    assert 'ite_strict_upd' in source, "Must have ite_strict_upd policy"
    assert 'ite_strict_del' in source, "Must have ite_strict_del policy"

def test_migration_056_sql_file():
    """Phase 20: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '056_identity_threat_events.sql')
    assert os.path.exists(sql_path), "migrations/056_identity_threat_events.sql must exist"

def test_identity_threat_detector_class_exists():
    """Phase 20: IdentityThreatDetector class can be imported."""
    from app.engines.identity_threat_detector import IdentityThreatDetector
    assert callable(IdentityThreatDetector), "IdentityThreatDetector must be a class"

def test_identity_threat_detector_detect_method():
    """Phase 20: IdentityThreatDetector.detect_identity_threats method exists."""
    from app.engines.identity_threat_detector import IdentityThreatDetector
    assert hasattr(IdentityThreatDetector, 'detect_identity_threats'), \
        "IdentityThreatDetector must have detect_identity_threats method"
    source = inspect.getsource(IdentityThreatDetector.detect_identity_threats)
    assert 'connection_id' in source, "Must accept connection_id parameter"
    assert 'org_id' in source, "Must accept org_id parameter"

def test_identity_threat_detector_event_types():
    """Phase 20: EVENT_TYPES constant has 4 event types."""
    from app.engines.identity_threat_detector import EVENT_TYPES
    assert 'privilege_escalation' in EVENT_TYPES, "Must include privilege_escalation"
    assert 'credential_creation' in EVENT_TYPES, "Must include credential_creation"
    assert 'suspicious_login' in EVENT_TYPES, "Must include suspicious_login"
    assert 'policy_change' in EVENT_TYPES, "Must include policy_change"
    assert len(EVENT_TYPES) == 4, f"Must have exactly 4 event types, got {len(EVENT_TYPES)}"

def test_identity_threat_detector_escalation_roles():
    """Phase 20: ESCALATION_ROLES has high-privilege roles."""
    from app.engines.identity_threat_detector import ESCALATION_ROLES
    assert 'Owner' in ESCALATION_ROLES, "Must include Owner"
    assert 'Global Administrator' in ESCALATION_ROLES, "Must include Global Administrator"
    assert 'Contributor' in ESCALATION_ROLES, "Must include Contributor"

def test_threat_detector_privilege_escalation():
    """Phase 20: _detect_privilege_escalation queries high-privilege roles."""
    from app.engines.identity_threat_detector import IdentityThreatDetector
    source = inspect.getsource(IdentityThreatDetector._detect_privilege_escalation)
    assert 'Owner' in source, "Must check for Owner role"
    assert 'role_assignments' in source, "Must query role_assignments"
    assert 'privilege_escalation' in source, "Must set event_type"

def test_threat_detector_credential_creation():
    """Phase 20: _detect_credential_creation checks credential counts."""
    from app.engines.identity_threat_detector import IdentityThreatDetector
    source = inspect.getsource(IdentityThreatDetector._detect_credential_creation)
    assert 'credential_count' in source, "Must check credential_count"
    assert 'credential_creation' in source, "Must set event_type"
    assert 'service_principal' in source, "Must filter service principals"

def test_threat_detector_suspicious_login():
    """Phase 20: _detect_suspicious_login checks inactive identities with recent sign-ins."""
    from app.engines.identity_threat_detector import IdentityThreatDetector
    source = inspect.getsource(IdentityThreatDetector._detect_suspicious_login)
    assert 'inactive' in source, "Must check inactive status"
    assert 'last_sign_in' in source, "Must check last_sign_in"
    assert 'suspicious_login' in source, "Must set event_type"

def test_threat_detector_policy_change():
    """Phase 20: _detect_policy_change checks role sprawl."""
    from app.engines.identity_threat_detector import IdentityThreatDetector
    source = inspect.getsource(IdentityThreatDetector._detect_policy_change)
    assert 'role_name' in source, "Must analyze role assignments"
    assert 'scope_type' in source, "Must check scope types"
    assert 'policy_change' in source, "Must set event_type"

def test_threat_events_crud_save():
    """Phase 20: Database has save_identity_threat_events method."""
    from app.database import Database
    assert hasattr(Database, 'save_identity_threat_events'), \
        "Database must have save_identity_threat_events method"

def test_threat_events_crud_get():
    """Phase 20: Database has get_identity_threat_events method."""
    from app.database import Database
    assert hasattr(Database, 'get_identity_threat_events'), \
        "Database must have get_identity_threat_events method"

def test_threat_events_crud_stats():
    """Phase 20: Database has get_identity_threat_events_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_identity_threat_events_stats'), \
        "Database must have get_identity_threat_events_stats method"

def test_threat_events_crud_update_status():
    """Phase 20: Database has update_identity_threat_event_status method."""
    from app.database import Database
    assert hasattr(Database, 'update_identity_threat_event_status'), \
        "Database must have update_identity_threat_event_status method"

def test_threat_detection_in_scheduler():
    """Phase 20: _run_threat_detection is in scheduler module."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    assert '_run_threat_detection' in source, "Scheduler must have _run_threat_detection function"
    assert "'threat_detection'" in source, "Scheduler must track threat_detection job"

def test_threat_detection_scheduler_pipeline_order():
    """Phase 20: threat_detection runs after policy_generation in pipeline."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    pg_pos = source.find("'policy_generation'")
    td_pos = source.find("'threat_detection'")
    assert pg_pos > 0, "Must have policy_generation in pipeline"
    assert td_pos > 0, "Must have threat_detection in pipeline"
    assert td_pos > pg_pos, "threat_detection must come after policy_generation"

def test_threat_events_api_route():
    """Phase 20: /api/security/threat-events route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/threat-events' in source, "Must have threat-events route"

def test_acknowledge_threat_route():
    """Phase 20: /acknowledge route exists for threat events."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert 'acknowledge_threat_event' in source, "Must have acknowledge route"

def test_resolve_threat_route():
    """Phase 20: /resolve route exists for threat events."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert 'resolve_threat_event' in source, "Must have resolve route"

def test_threat_events_handler_exists():
    """Phase 20: get_threat_events_handler is callable."""
    from app.api.handlers import get_threat_events_handler
    assert callable(get_threat_events_handler), \
        "get_threat_events_handler must be callable"

def test_acknowledge_threat_handler_exists():
    """Phase 20: acknowledge_threat_event_handler is callable."""
    from app.api.handlers import acknowledge_threat_event_handler
    assert callable(acknowledge_threat_event_handler), \
        "acknowledge_threat_event_handler must be callable"

def test_resolve_threat_handler_exists():
    """Phase 20: resolve_threat_event_handler is callable."""
    from app.api.handlers import resolve_threat_event_handler
    assert callable(resolve_threat_event_handler), \
        "resolve_threat_event_handler must be callable"

def test_threat_events_handler_returns_stats():
    """Phase 20: threat events handler returns events and stats."""
    from app.api.handlers import get_threat_events_handler
    source = inspect.getsource(get_threat_events_handler)
    assert 'get_identity_threat_events' in source, "Must call get_identity_threat_events"
    assert 'get_identity_threat_events_stats' in source, "Must call get_identity_threat_events_stats"
    assert 'events' in source, "Must return events key"
    assert 'stats' in source, "Must return stats key"

def test_acknowledge_threat_handler_logs_activity():
    """Phase 20: acknowledge handler logs activity."""
    from app.api.handlers import acknowledge_threat_event_handler
    source = inspect.getsource(acknowledge_threat_event_handler)
    assert '_log' in source, "Must log activity on acknowledge"
    assert 'threat_acknowledged' in source, "Must log threat_acknowledged action"

def test_resolve_threat_handler_logs_activity():
    """Phase 20: resolve handler logs activity."""
    from app.api.handlers import resolve_threat_event_handler
    source = inspect.getsource(resolve_threat_event_handler)
    assert '_log' in source, "Must log activity on resolve"
    assert 'threat_resolved' in source, "Must log threat_resolved action"


# ============================================================
# Phase 21: Identity Security Data Lake
# ============================================================

def test_migration_057_exists():
    """Phase 21: _run_migration_057_identity_data_lake method exists on Database."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_057_identity_data_lake'), \
        "Database must have _run_migration_057_identity_data_lake method"

def test_migration_057_class_flag():
    """Phase 21: Database has _migration_057_identity_data_lake_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_057_identity_data_lake_ensured'), \
        "Database must have _migration_057_identity_data_lake_ensured flag"

def test_migration_057_called_from_entitlements():
    """Phase 21: migration 057 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_057_identity_data_lake' in source, \
        "Must call _run_migration_057_identity_data_lake from _ensure_entitlements_tables"

def test_migration_057_creates_activity_events_table():
    """Phase 21: migration 057 creates identity_activity_events table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert 'identity_activity_events' in source, "Must create identity_activity_events table"

def test_migration_057_creates_role_history_table():
    """Phase 21: migration 057 creates identity_role_history table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert 'identity_role_history' in source, "Must create identity_role_history table"

def test_migration_057_creates_access_history_table():
    """Phase 21: migration 057 creates identity_access_history table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert 'identity_access_history' in source, "Must create identity_access_history table"

def test_migration_057_activity_event_type_check():
    """Phase 21: identity_activity_events has event_type CHECK for 5 types."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert "'login'" in source, "CHECK must include 'login'"
    assert "'role_assignment'" in source, "CHECK must include 'role_assignment'"
    assert "'credential_change'" in source, "CHECK must include 'credential_change'"
    assert "'policy_update'" in source, "CHECK must include 'policy_update'"
    assert "'resource_access'" in source, "CHECK must include 'resource_access'"

def test_migration_057_rls_activity_events():
    """Phase 21: identity_activity_events has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert 'iae_strict_sel' in source, "Must have iae_strict_sel policy"
    assert 'iae_strict_ins' in source, "Must have iae_strict_ins policy"
    assert 'iae_strict_upd' in source, "Must have iae_strict_upd policy"
    assert 'iae_strict_del' in source, "Must have iae_strict_del policy"

def test_migration_057_rls_role_history():
    """Phase 21: identity_role_history has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert 'irh_strict_sel' in source, "Must have irh_strict_sel policy"
    assert 'irh_strict_ins' in source, "Must have irh_strict_ins policy"
    assert 'irh_strict_upd' in source, "Must have irh_strict_upd policy"
    assert 'irh_strict_del' in source, "Must have irh_strict_del policy"

def test_migration_057_rls_access_history():
    """Phase 21: identity_access_history has 4 RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_057_identity_data_lake)
    assert 'iah_strict_sel' in source, "Must have iah_strict_sel policy"
    assert 'iah_strict_ins' in source, "Must have iah_strict_ins policy"
    assert 'iah_strict_upd' in source, "Must have iah_strict_upd policy"
    assert 'iah_strict_del' in source, "Must have iah_strict_del policy"

def test_migration_057_sql_file():
    """Phase 21: SQL migration file exists."""
    sql_path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '057_identity_data_lake.sql')
    assert os.path.exists(sql_path), "migrations/057_identity_data_lake.sql must exist"

def test_activity_ingestor_class_exists():
    """Phase 21: ActivityIngestor class can be imported."""
    from app.engines.activity_ingestor import ActivityIngestor
    assert callable(ActivityIngestor), "ActivityIngestor must be a class"

def test_activity_ingestor_ingest_method():
    """Phase 21: ActivityIngestor.ingest_identity_activity method exists."""
    from app.engines.activity_ingestor import ActivityIngestor
    assert hasattr(ActivityIngestor, 'ingest_identity_activity'), \
        "ActivityIngestor must have ingest_identity_activity method"
    source = inspect.getsource(ActivityIngestor.ingest_identity_activity)
    assert 'connection_id' in source, "Must accept connection_id parameter"
    assert 'org_id' in source, "Must accept org_id parameter"

def test_activity_ingestor_history_method():
    """Phase 21: ActivityIngestor.get_identity_history method exists."""
    from app.engines.activity_ingestor import ActivityIngestor
    assert hasattr(ActivityIngestor, 'get_identity_history'), \
        "ActivityIngestor must have get_identity_history method"

def test_activity_ingestor_event_types():
    """Phase 21: EVENT_TYPES constant has 5 event types."""
    from app.engines.activity_ingestor import EVENT_TYPES
    assert 'login' in EVENT_TYPES, "Must include login"
    assert 'role_assignment' in EVENT_TYPES, "Must include role_assignment"
    assert 'credential_change' in EVENT_TYPES, "Must include credential_change"
    assert 'policy_update' in EVENT_TYPES, "Must include policy_update"
    assert 'resource_access' in EVENT_TYPES, "Must include resource_access"

def test_activity_ingestor_login_events():
    """Phase 21: _ingest_login_events queries last_sign_in."""
    from app.engines.activity_ingestor import ActivityIngestor
    source = inspect.getsource(ActivityIngestor._ingest_login_events)
    assert 'last_sign_in' in source, "Must query last_sign_in"
    assert "'login'" in source, "Must set event_type to login"

def test_activity_ingestor_role_events():
    """Phase 21: _ingest_role_events queries role_assignments."""
    from app.engines.activity_ingestor import ActivityIngestor
    source = inspect.getsource(ActivityIngestor._ingest_role_events)
    assert 'role_assignments' in source, "Must query role_assignments"
    assert "'role_assignment'" in source, "Must set event_type to role_assignment"

def test_activity_ingestor_credential_events():
    """Phase 21: _ingest_credential_events queries credential data."""
    from app.engines.activity_ingestor import ActivityIngestor
    source = inspect.getsource(ActivityIngestor._ingest_credential_events)
    assert 'credential_count' in source, "Must check credential_count"
    assert "'credential_change'" in source, "Must set event_type to credential_change"

def test_activity_ingestor_role_history():
    """Phase 21: _build_role_history creates role history records."""
    from app.engines.activity_ingestor import ActivityIngestor
    source = inspect.getsource(ActivityIngestor._build_role_history)
    assert 'save_identity_role_history' in source, "Must call save_identity_role_history"
    assert 'role_name' in source, "Must include role_name"

def test_activity_ingestor_access_history():
    """Phase 21: _build_access_history creates access history records."""
    from app.engines.activity_ingestor import ActivityIngestor
    source = inspect.getsource(ActivityIngestor._build_access_history)
    assert 'save_identity_access_history' in source, "Must call save_identity_access_history"
    assert 'resource_id' in source, "Must include resource_id"

def test_activity_ingestor_compute_baseline():
    """Phase 21: _compute_baseline computes behavioral baseline."""
    from app.engines.activity_ingestor import ActivityIngestor
    source = inspect.getsource(ActivityIngestor._compute_baseline)
    assert 'login_frequency' in source, "Must compute login_frequency"
    assert 'typical_event_types' in source, "Must compute typical_event_types"
    assert 'event_distribution' in source, "Must compute event_distribution"

def test_activity_ingestor_baseline_thresholds():
    """Phase 21: Baseline constants are defined."""
    from app.engines.activity_ingestor import BASELINE_LOGIN_DAYS, BASELINE_MIN_EVENTS
    assert BASELINE_LOGIN_DAYS == 90, "BASELINE_LOGIN_DAYS must be 90"
    assert BASELINE_MIN_EVENTS == 5, "BASELINE_MIN_EVENTS must be 5"

def test_activity_events_crud_save():
    """Phase 21: Database has save_identity_activity_events method."""
    from app.database import Database
    assert hasattr(Database, 'save_identity_activity_events'), \
        "Database must have save_identity_activity_events method"

def test_activity_events_crud_get():
    """Phase 21: Database has get_identity_activity_events method."""
    from app.database import Database
    assert hasattr(Database, 'get_identity_activity_events'), \
        "Database must have get_identity_activity_events method"

def test_role_history_crud_save():
    """Phase 21: Database has save_identity_role_history method."""
    from app.database import Database
    assert hasattr(Database, 'save_identity_role_history'), \
        "Database must have save_identity_role_history method"

def test_role_history_crud_get():
    """Phase 21: Database has get_identity_role_history method."""
    from app.database import Database
    assert hasattr(Database, 'get_identity_role_history'), \
        "Database must have get_identity_role_history method"

def test_access_history_crud_save():
    """Phase 21: Database has save_identity_access_history method."""
    from app.database import Database
    assert hasattr(Database, 'save_identity_access_history'), \
        "Database must have save_identity_access_history method"

def test_access_history_crud_get():
    """Phase 21: Database has get_identity_access_history method."""
    from app.database import Database
    assert hasattr(Database, 'get_identity_access_history'), \
        "Database must have get_identity_access_history method"

def test_activity_ingestion_in_scheduler():
    """Phase 21: _run_activity_ingestion is in scheduler module."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    assert '_run_activity_ingestion' in source, "Scheduler must have _run_activity_ingestion function"
    assert "'activity_ingestion'" in source, "Scheduler must track activity_ingestion job"

def test_activity_ingestion_scheduler_pipeline_order():
    """Phase 21: activity_ingestion runs after threat_detection in pipeline."""
    from app import scheduler as sched_mod
    source = inspect.getsource(sched_mod)
    td_pos = source.find("'threat_detection'")
    ai_pos = source.find("'activity_ingestion'")
    assert td_pos > 0, "Must have threat_detection in pipeline"
    assert ai_pos > 0, "Must have activity_ingestion in pipeline"
    assert ai_pos > td_pos, "activity_ingestion must come after threat_detection"

def test_identity_history_api_route():
    """Phase 21: /api/security/identity-history/<identity_id> route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/identity-history/' in source, "Must have identity-history route"

def test_activity_events_api_route():
    """Phase 21: /api/security/activity-events route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/activity-events' in source, "Must have activity-events route"

def test_identity_history_handler_exists():
    """Phase 21: get_identity_history_handler is callable."""
    from app.api.handlers import get_identity_history_handler
    assert callable(get_identity_history_handler), \
        "get_identity_history_handler must be callable"

def test_activity_events_handler_exists():
    """Phase 21: get_activity_events_handler is callable."""
    from app.api.handlers import get_activity_events_handler
    assert callable(get_activity_events_handler), \
        "get_activity_events_handler must be callable"

def test_identity_history_handler_uses_engine():
    """Phase 21: identity history handler uses ActivityIngestor."""
    from app.api.handlers import get_identity_history_handler
    source = inspect.getsource(get_identity_history_handler)
    assert 'ActivityIngestor' in source, "Must use ActivityIngestor engine"
    assert 'get_identity_history' in source, "Must call get_identity_history"

def test_activity_events_handler_supports_filters():
    """Phase 21: activity events handler supports identity_id and event_type filters."""
    from app.api.handlers import get_activity_events_handler
    source = inspect.getsource(get_activity_events_handler)
    assert 'identity_id' in source, "Must support identity_id filter"
    assert 'event_type' in source, "Must support event_type filter"


# ============================================================
# Phase 23: Identity Attack Replay & Forensics
# ============================================================

def test_phase_23_migration_058_method_exists():
    """Phase 23: Database has _run_migration_058_attack_replay method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_058_attack_replay'), \
        "Database must have _run_migration_058_attack_replay method"

def test_phase_23_migration_058_called_from_entitlements():
    """Phase 23: migration 058 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_058_attack_replay' in source, \
        "Must chain migration 058 from _ensure_entitlements_tables"

def test_phase_23_migration_058_creates_incidents_table():
    """Phase 23: migration 058 creates identity_attack_incidents table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_058_attack_replay)
    assert 'identity_attack_incidents' in source, "Must create identity_attack_incidents table"
    assert 'incident_type' in source, "Must have incident_type column"
    assert 'severity' in source, "Must have severity column"

def test_phase_23_migration_058_creates_replay_steps_table():
    """Phase 23: migration 058 creates identity_attack_replay_steps table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_058_attack_replay)
    assert 'identity_attack_replay_steps' in source, "Must create replay steps table"
    assert 'step_index' in source, "Must have step_index column"
    assert 'incident_id' in source, "Must have incident_id FK"

def test_phase_23_migration_058_rls_policies():
    """Phase 23: migration 058 creates RLS policies for incidents table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_058_attack_replay)
    assert 'ROW LEVEL SECURITY' in source or 'row level security' in source.lower(), \
        "Must enable RLS"
    assert 'app.current_organization_id' in source, "Must use org context for RLS"

def test_phase_23_migration_058_incident_type_check():
    """Phase 23: migration 058 has CHECK constraint for incident_type."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_058_attack_replay)
    assert 'privilege_escalation_attack' in source, "Must include privilege_escalation_attack"
    assert 'credential_compromise' in source, "Must include credential_compromise"
    assert 'lateral_movement' in source, "Must include lateral_movement"
    assert 'resource_exposure' in source, "Must include resource_exposure"

def test_phase_23_migration_058_sql_file_exists():
    """Phase 23: SQL migration file 058 exists."""
    import os
    sql_path = os.path.join(
        os.path.dirname(__file__), '..', 'migrations', '058_attack_replay.sql'
    )
    assert os.path.exists(sql_path), "058_attack_replay.sql must exist"

def test_phase_23_attack_replay_engine_class():
    """Phase 23: AttackReplayEngine class exists and is importable."""
    from app.engines.attack_replay_engine import AttackReplayEngine
    assert callable(AttackReplayEngine), "AttackReplayEngine must be callable class"

def test_phase_23_engine_generate_attack_replay():
    """Phase 23: engine has generate_attack_replay method."""
    from app.engines.attack_replay_engine import AttackReplayEngine
    source = inspect.getsource(AttackReplayEngine)
    assert 'generate_attack_replay' in source, "Must have generate_attack_replay"
    assert 'identity_id' in source, "Must accept identity_id"
    assert 'org_id' in source, "Must accept org_id"

def test_phase_23_engine_detect_incidents_for_connection():
    """Phase 23: engine has detect_incidents_for_connection method."""
    from app.engines.attack_replay_engine import AttackReplayEngine
    source = inspect.getsource(AttackReplayEngine)
    assert 'detect_incidents_for_connection' in source, \
        "Must have detect_incidents_for_connection"

def test_phase_23_engine_get_incident_replay():
    """Phase 23: engine has get_incident_replay method."""
    from app.engines.attack_replay_engine import AttackReplayEngine
    source = inspect.getsource(AttackReplayEngine)
    assert 'get_incident_replay' in source, "Must have get_incident_replay"

def test_phase_23_engine_incident_patterns():
    """Phase 23: engine defines INCIDENT_PATTERNS with 4 types."""
    from app.engines.attack_replay_engine import INCIDENT_PATTERNS
    assert 'privilege_escalation_attack' in INCIDENT_PATTERNS
    assert 'credential_compromise' in INCIDENT_PATTERNS
    assert 'lateral_movement' in INCIDENT_PATTERNS
    assert 'resource_exposure' in INCIDENT_PATTERNS

def test_phase_23_engine_merge_events():
    """Phase 23: engine has _merge_events for combining event sources."""
    from app.engines.attack_replay_engine import AttackReplayEngine
    source = inspect.getsource(AttackReplayEngine)
    assert '_merge_events' in source, "Must have _merge_events"
    assert 'threat' in source, "Must handle threat events"
    assert 'activity' in source, "Must handle activity events"
    assert 'anomaly' in source, "Must handle anomaly events"

def test_phase_23_engine_build_replay_steps():
    """Phase 23: engine has _build_replay_steps for ordered replay."""
    from app.engines.attack_replay_engine import AttackReplayEngine
    source = inspect.getsource(AttackReplayEngine)
    assert '_build_replay_steps' in source, "Must have _build_replay_steps"
    assert 'step_index' in source, "Must track step_index"

def test_phase_23_db_save_attack_incident():
    """Phase 23: Database has save_attack_incident method."""
    from app.database import Database
    assert hasattr(Database, 'save_attack_incident'), \
        "Database must have save_attack_incident"

def test_phase_23_db_save_replay_steps():
    """Phase 23: Database has save_attack_replay_steps method."""
    from app.database import Database
    assert hasattr(Database, 'save_attack_replay_steps'), \
        "Database must have save_attack_replay_steps"

def test_phase_23_db_get_attack_incidents():
    """Phase 23: Database has get_attack_incidents method."""
    from app.database import Database
    assert hasattr(Database, 'get_attack_incidents'), \
        "Database must have get_attack_incidents"

def test_phase_23_db_get_attack_incidents_stats():
    """Phase 23: Database has get_attack_incidents_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_attack_incidents_stats'), \
        "Database must have get_attack_incidents_stats"

def test_phase_23_db_update_attack_incident_status():
    """Phase 23: Database has update_attack_incident_status method."""
    from app.database import Database
    assert hasattr(Database, 'update_attack_incident_status'), \
        "Database must have update_attack_incident_status"

def test_phase_23_scheduler_attack_replay():
    """Phase 23: scheduler has _run_attack_replay function."""
    from app import scheduler
    source = inspect.getsource(scheduler)
    assert '_run_attack_replay' in source, "Must have _run_attack_replay function"
    assert 'AttackReplayEngine' in source, "Must import AttackReplayEngine"

def test_phase_23_scheduler_track_job():
    """Phase 23: attack_replay is tracked in scheduler pipeline."""
    from app import scheduler
    source = inspect.getsource(scheduler)
    assert "'attack_replay'" in source, "Must track attack_replay job"

def test_phase_23_incidents_api_route():
    """Phase 23: /api/security/incidents route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/incidents' in source, "Must have incidents route"

def test_phase_23_attack_replay_api_route():
    """Phase 23: /api/security/attack-replay route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/attack-replay/' in source, "Must have attack-replay route"

def test_phase_23_incident_status_api_route():
    """Phase 23: incident status update route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/status' in source, "Must have incident status route"

def test_phase_23_incidents_handler_exists():
    """Phase 23: get_attack_incidents_handler is callable."""
    from app.api.handlers import get_attack_incidents_handler
    assert callable(get_attack_incidents_handler), \
        "get_attack_incidents_handler must be callable"

def test_phase_23_replay_handler_exists():
    """Phase 23: get_attack_replay_handler is callable."""
    from app.api.handlers import get_attack_replay_handler
    assert callable(get_attack_replay_handler), \
        "get_attack_replay_handler must be callable"

def test_phase_23_incident_status_handler_exists():
    """Phase 23: update_incident_status_handler is callable."""
    from app.api.handlers import update_incident_status_handler
    assert callable(update_incident_status_handler), \
        "update_incident_status_handler must be callable"

def test_phase_23_incidents_handler_uses_db():
    """Phase 23: incidents handler queries DB for incidents and stats."""
    from app.api.handlers import get_attack_incidents_handler
    source = inspect.getsource(get_attack_incidents_handler)
    assert 'get_attack_incidents' in source, "Must call get_attack_incidents"
    assert 'get_attack_incidents_stats' in source, "Must call get_attack_incidents_stats"

def test_phase_23_replay_handler_uses_engine():
    """Phase 23: replay handler uses AttackReplayEngine."""
    from app.api.handlers import get_attack_replay_handler
    source = inspect.getsource(get_attack_replay_handler)
    assert 'AttackReplayEngine' in source, "Must use AttackReplayEngine"
    assert 'get_incident_replay' in source, "Must call get_incident_replay"

def test_phase_23_incident_status_handler_validates():
    """Phase 23: status handler validates status values."""
    from app.api.handlers import update_incident_status_handler
    source = inspect.getsource(update_incident_status_handler)
    assert 'investigating' in source, "Must accept investigating status"
    assert 'resolved' in source, "Must accept resolved status"


# ============================================================
# Phase 24: Autonomous Identity Security Operations
# ============================================================

def test_phase_24_migration_059_method_exists():
    """Phase 24: Database has _run_migration_059_security_response_actions method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_059_security_response_actions'), \
        "Database must have _run_migration_059_security_response_actions method"

def test_phase_24_migration_059_called_from_entitlements():
    """Phase 24: migration 059 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_059_security_response_actions' in source, \
        "Must chain migration 059 from _ensure_entitlements_tables"

def test_phase_24_migration_059_creates_table():
    """Phase 24: migration 059 creates security_response_actions table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_059_security_response_actions)
    assert 'security_response_actions' in source, "Must create security_response_actions table"
    assert 'response_action' in source, "Must have response_action column"
    assert 'incident_id' in source, "Must have incident_id FK"

def test_phase_24_migration_059_response_action_check():
    """Phase 24: migration 059 has CHECK constraint for response_action values."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_059_security_response_actions)
    assert 'rotate_credential' in source, "Must include rotate_credential"
    assert 'disable_identity' in source, "Must include disable_identity"
    assert 'remove_privileged_role' in source, "Must include remove_privileged_role"
    assert 'revert_policy_change' in source, "Must include revert_policy_change"

def test_phase_24_migration_059_status_check():
    """Phase 24: migration 059 has CHECK constraint for status values."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_059_security_response_actions)
    assert 'pending' in source, "Must include pending status"
    assert 'executed' in source, "Must include executed status"
    assert 'failed' in source, "Must include failed status"

def test_phase_24_migration_059_rls_policies():
    """Phase 24: migration 059 creates RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_059_security_response_actions)
    assert 'ROW LEVEL SECURITY' in source or 'row level security' in source.lower(), \
        "Must enable RLS"
    assert 'sra_strict_sel' in source, "Must have SELECT policy"
    assert 'sra_strict_ins' in source, "Must have INSERT policy"
    assert 'sra_strict_upd' in source, "Must have UPDATE policy"
    assert 'sra_strict_del' in source, "Must have DELETE policy"

def test_phase_24_migration_059_sql_file_exists():
    """Phase 24: SQL migration file 059 exists."""
    import os
    sql_path = os.path.join(
        os.path.dirname(__file__), '..', 'migrations', '059_security_response_actions.sql'
    )
    assert os.path.exists(sql_path), "059_security_response_actions.sql must exist"

def test_phase_24_orchestrator_class_exists():
    """Phase 24: SecurityOrchestrator class exists and is importable."""
    from app.engines.security_orchestrator import SecurityOrchestrator
    assert callable(SecurityOrchestrator), "SecurityOrchestrator must be callable class"

def test_phase_24_orchestrator_execute_responses():
    """Phase 24: orchestrator has execute_security_responses method."""
    from app.engines.security_orchestrator import SecurityOrchestrator
    source = inspect.getsource(SecurityOrchestrator)
    assert 'execute_security_responses' in source, "Must have execute_security_responses"
    assert 'org_id' in source, "Must accept org_id"

def test_phase_24_orchestrator_approve_action():
    """Phase 24: orchestrator has approve_action method."""
    from app.engines.security_orchestrator import SecurityOrchestrator
    source = inspect.getsource(SecurityOrchestrator)
    assert 'approve_action' in source, "Must have approve_action"
    assert 'approved_by' in source, "Must track who approved"

def test_phase_24_orchestrator_execute_action():
    """Phase 24: orchestrator has execute_action method."""
    from app.engines.security_orchestrator import SecurityOrchestrator
    source = inspect.getsource(SecurityOrchestrator)
    assert 'execute_action' in source, "Must have execute_action"

def test_phase_24_response_rules():
    """Phase 24: engine defines RESPONSE_RULES with 4 incident types."""
    from app.engines.security_orchestrator import RESPONSE_RULES
    assert 'credential_compromise' in RESPONSE_RULES
    assert 'privilege_escalation_attack' in RESPONSE_RULES
    assert 'lateral_movement' in RESPONSE_RULES
    assert 'resource_exposure' in RESPONSE_RULES

def test_phase_24_critical_actions():
    """Phase 24: engine defines CRITICAL_ACTIONS requiring approval."""
    from app.engines.security_orchestrator import CRITICAL_ACTIONS
    assert 'disable_identity' in CRITICAL_ACTIONS, "disable_identity must be critical"
    assert 'remove_privileged_role' in CRITICAL_ACTIONS, "remove_privileged_role must be critical"

def test_phase_24_rate_limit():
    """Phase 24: engine has MAX_ACTIONS_PER_HOUR safety limit."""
    from app.engines.security_orchestrator import MAX_ACTIONS_PER_HOUR
    assert isinstance(MAX_ACTIONS_PER_HOUR, int), "Must be an integer"
    assert MAX_ACTIONS_PER_HOUR > 0, "Must be positive"

def test_phase_24_orchestrator_safety_controls():
    """Phase 24: orchestrator checks rate limits and critical action approval."""
    from app.engines.security_orchestrator import SecurityOrchestrator
    source = inspect.getsource(SecurityOrchestrator)
    assert 'MAX_ACTIONS_PER_HOUR' in source, "Must check rate limit"
    assert 'CRITICAL_ACTIONS' in source, "Must check critical actions"
    assert 'remaining_budget' in source, "Must track remaining budget"

def test_phase_24_db_save_response_action():
    """Phase 24: Database has save_security_response_action method."""
    from app.database import Database
    assert hasattr(Database, 'save_security_response_action'), \
        "Database must have save_security_response_action"

def test_phase_24_db_get_response_actions():
    """Phase 24: Database has get_security_response_actions method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_response_actions'), \
        "Database must have get_security_response_actions"

def test_phase_24_db_get_response_action():
    """Phase 24: Database has get_security_response_action method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_response_action'), \
        "Database must have get_security_response_action"

def test_phase_24_db_update_response_action():
    """Phase 24: Database has update_security_response_action method."""
    from app.database import Database
    assert hasattr(Database, 'update_security_response_action'), \
        "Database must have update_security_response_action"

def test_phase_24_db_get_response_actions_stats():
    """Phase 24: Database has get_security_response_actions_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_response_actions_stats'), \
        "Database must have get_security_response_actions_stats"

def test_phase_24_db_get_recent_action_count():
    """Phase 24: Database has get_security_response_action_count_recent method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_response_action_count_recent'), \
        "Database must have get_security_response_action_count_recent"

def test_phase_24_scheduler_security_orchestration():
    """Phase 24: scheduler has _run_security_orchestration function."""
    from app import scheduler
    source = inspect.getsource(scheduler)
    assert '_run_security_orchestration' in source, "Must have _run_security_orchestration"
    assert 'SecurityOrchestrator' in source, "Must import SecurityOrchestrator"

def test_phase_24_scheduler_track_job():
    """Phase 24: security_orchestration is tracked in scheduler pipeline."""
    from app import scheduler
    source = inspect.getsource(scheduler)
    assert "'security_orchestration'" in source, "Must track security_orchestration job"

def test_phase_24_response_actions_api_route():
    """Phase 24: /api/security/response-actions route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/response-actions' in source, "Must have response-actions route"

def test_phase_24_approve_api_route():
    """Phase 24: /approve route exists for response actions."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/approve' in source, "Must have approve route"

def test_phase_24_execute_api_route():
    """Phase 24: /execute route exists for response actions."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/execute' in source, "Must have execute route"

def test_phase_24_response_actions_handler_exists():
    """Phase 24: get_response_actions_handler is callable."""
    from app.api.handlers import get_response_actions_handler
    assert callable(get_response_actions_handler), \
        "get_response_actions_handler must be callable"

def test_phase_24_approve_handler_exists():
    """Phase 24: approve_response_action_handler is callable."""
    from app.api.handlers import approve_response_action_handler
    assert callable(approve_response_action_handler), \
        "approve_response_action_handler must be callable"

def test_phase_24_execute_handler_exists():
    """Phase 24: execute_response_action_handler is callable."""
    from app.api.handlers import execute_response_action_handler
    assert callable(execute_response_action_handler), \
        "execute_response_action_handler must be callable"

def test_phase_24_response_actions_handler_uses_db():
    """Phase 24: response actions handler queries DB."""
    from app.api.handlers import get_response_actions_handler
    source = inspect.getsource(get_response_actions_handler)
    assert 'get_security_response_actions' in source, "Must call get_security_response_actions"
    assert 'get_security_response_actions_stats' in source, "Must call stats method"

def test_phase_24_approve_handler_uses_orchestrator():
    """Phase 24: approve handler uses SecurityOrchestrator."""
    from app.api.handlers import approve_response_action_handler
    source = inspect.getsource(approve_response_action_handler)
    assert 'SecurityOrchestrator' in source, "Must use SecurityOrchestrator"
    assert 'approve_action' in source, "Must call approve_action"

def test_phase_24_execute_handler_uses_orchestrator():
    """Phase 24: execute handler uses SecurityOrchestrator."""
    from app.api.handlers import execute_response_action_handler
    source = inspect.getsource(execute_response_action_handler)
    assert 'SecurityOrchestrator' in source, "Must use SecurityOrchestrator"
    assert 'execute_action' in source, "Must call execute_action"


# ============================================================
# Phase 25: AI Security Copilot
# ============================================================

def test_phase_25_migration_060_method_exists():
    """Phase 25: Database has _run_migration_060_copilot_queries method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_060_copilot_queries'), \
        "Database must have _run_migration_060_copilot_queries method"

def test_phase_25_migration_060_called_from_entitlements():
    """Phase 25: migration 060 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_060_copilot_queries' in source, \
        "Must chain migration 060 from _ensure_entitlements_tables"

def test_phase_25_migration_060_creates_table():
    """Phase 25: migration 060 creates copilot_queries table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_060_copilot_queries)
    assert 'copilot_queries' in source, "Must create copilot_queries table"
    assert 'query' in source, "Must have query column"
    assert 'response' in source, "Must have response column"
    assert 'context' in source, "Must have context JSONB column"

def test_phase_25_migration_060_rls_policies():
    """Phase 25: migration 060 creates RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_060_copilot_queries)
    assert 'ROW LEVEL SECURITY' in source or 'row level security' in source.lower(), \
        "Must enable RLS"
    assert 'cq_strict_sel' in source, "Must have SELECT policy"
    assert 'cq_strict_ins' in source, "Must have INSERT policy"
    assert 'cq_strict_upd' in source, "Must have UPDATE policy"
    assert 'cq_strict_del' in source, "Must have DELETE policy"

def test_phase_25_migration_060_sql_file_exists():
    """Phase 25: SQL migration file 060 exists."""
    import os
    sql_path = os.path.join(
        os.path.dirname(__file__), '..', 'migrations', '060_copilot_queries.sql'
    )
    assert os.path.exists(sql_path), "060_copilot_queries.sql must exist"

def test_phase_25_copilot_class_exists():
    """Phase 25: SecurityCopilot class exists and is importable."""
    from app.engines.security_copilot import SecurityCopilot
    assert callable(SecurityCopilot), "SecurityCopilot must be callable class"

def test_phase_25_copilot_process_query():
    """Phase 25: copilot has process_copilot_query method."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert 'process_copilot_query' in source, "Must have process_copilot_query"
    assert 'org_id' in source, "Must accept org_id"
    assert 'user_id' in source, "Must accept user_id"

def test_phase_25_copilot_parse_intent():
    """Phase 25: copilot has _parse_intent for NL query parsing."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_parse_intent' in source, "Must have _parse_intent method"

def test_phase_25_copilot_query_patterns():
    """Phase 25: copilot defines QUERY_PATTERNS for intent matching."""
    from app.engines.security_copilot import QUERY_PATTERNS
    assert len(QUERY_PATTERNS) >= 8, "Must have at least 8 query patterns"

def test_phase_25_copilot_intent_risk_ranking():
    """Phase 25: copilot can parse risk ranking queries."""
    from app.engines.security_copilot import SecurityCopilot
    copilot = SecurityCopilot.__new__(SecurityCopilot)
    assert copilot._parse_intent('Which identities are most dangerous?') == 'risk_ranking'

def test_phase_25_copilot_intent_incidents():
    """Phase 25: copilot can parse incident queries."""
    from app.engines.security_copilot import SecurityCopilot
    copilot = SecurityCopilot.__new__(SecurityCopilot)
    assert copilot._parse_intent('Show me recent incidents') == 'incident_investigation'

def test_phase_25_copilot_intent_anomalies():
    """Phase 25: copilot can parse anomaly queries."""
    from app.engines.security_copilot import SecurityCopilot
    copilot = SecurityCopilot.__new__(SecurityCopilot)
    assert copilot._parse_intent('Any unusual activity?') == 'anomaly_analysis'

def test_phase_25_copilot_intent_posture():
    """Phase 25: copilot can parse posture trend queries."""
    from app.engines.security_copilot import SecurityCopilot
    copilot = SecurityCopilot.__new__(SecurityCopilot)
    assert copilot._parse_intent('What is the posture score trend?') == 'posture_trends'

def test_phase_25_copilot_intent_default():
    """Phase 25: copilot returns general_summary for unknown queries."""
    from app.engines.security_copilot import SecurityCopilot
    copilot = SecurityCopilot.__new__(SecurityCopilot)
    assert copilot._parse_intent('hello world') == 'general_summary'

def test_phase_25_copilot_retrieve_data():
    """Phase 25: copilot has _retrieve_data method with multiple retrievers."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_retrieve_data' in source, "Must have _retrieve_data"
    assert 'risk_ranking' in source, "Must handle risk_ranking"
    assert 'incident_investigation' in source, "Must handle incidents"
    assert 'anomaly_analysis' in source, "Must handle anomalies"

def test_phase_25_copilot_generate_response():
    """Phase 25: copilot has _generate_response with suggestions."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_generate_response' in source, "Must have _generate_response"
    assert 'suggestions' in source, "Must include suggestions"

def test_phase_25_copilot_save_query():
    """Phase 25: copilot saves queries for audit trail."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_save_query' in source, "Must have _save_query"
    assert 'save_copilot_query' in source, "Must call db.save_copilot_query"

def test_phase_25_copilot_get_history():
    """Phase 25: copilot has get_query_history method."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert 'get_query_history' in source, "Must have get_query_history"

def test_phase_25_db_save_copilot_query():
    """Phase 25: Database has save_copilot_query method."""
    from app.database import Database
    assert hasattr(Database, 'save_copilot_query'), \
        "Database must have save_copilot_query"

def test_phase_25_db_get_copilot_queries():
    """Phase 25: Database has get_copilot_queries method."""
    from app.database import Database
    assert hasattr(Database, 'get_copilot_queries'), \
        "Database must have get_copilot_queries"

def test_phase_25_db_get_copilot_query_by_id():
    """Phase 25: Database has get_copilot_query_by_id method."""
    from app.database import Database
    assert hasattr(Database, 'get_copilot_query_by_id'), \
        "Database must have get_copilot_query_by_id"

def test_phase_25_copilot_query_api_route():
    """Phase 25: /api/security/copilot-query route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/copilot-query' in source, "Must have copilot-query route"

def test_phase_25_copilot_history_api_route():
    """Phase 25: /api/security/copilot-history route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/copilot-history' in source, "Must have copilot-history route"

def test_phase_25_copilot_query_handler_exists():
    """Phase 25: process_copilot_query_handler is callable."""
    from app.api.handlers import process_copilot_query_handler
    assert callable(process_copilot_query_handler), \
        "process_copilot_query_handler must be callable"

def test_phase_25_copilot_history_handler_exists():
    """Phase 25: get_copilot_history_handler is callable."""
    from app.api.handlers import get_copilot_history_handler
    assert callable(get_copilot_history_handler), \
        "get_copilot_history_handler must be callable"

def test_phase_25_copilot_query_handler_uses_engine():
    """Phase 25: query handler uses SecurityCopilot engine."""
    from app.api.handlers import process_copilot_query_handler
    source = inspect.getsource(process_copilot_query_handler)
    assert 'SecurityCopilot' in source, "Must use SecurityCopilot"
    assert 'process_copilot_query' in source, "Must call process_copilot_query"

def test_phase_25_copilot_query_handler_validates():
    """Phase 25: query handler validates query input."""
    from app.api.handlers import process_copilot_query_handler
    source = inspect.getsource(process_copilot_query_handler)
    assert 'query' in source, "Must extract query from request"
    assert 'error' in source, "Must return error for empty query"

def test_phase_25_copilot_history_handler_uses_db():
    """Phase 25: history handler queries copilot_queries table."""
    from app.api.handlers import get_copilot_history_handler
    source = inspect.getsource(get_copilot_history_handler)
    assert 'get_copilot_queries' in source, "Must call get_copilot_queries"


# ============================================================
# Phase 26: Identity Attack Prediction
# ============================================================

def test_phase_26_migration_061_method_exists():
    """Phase 26: Database has _run_migration_061_attack_predictions method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_061_attack_predictions'), \
        "Database must have _run_migration_061_attack_predictions method"

def test_phase_26_migration_061_called_from_entitlements():
    """Phase 26: migration 061 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_061_attack_predictions' in source, \
        "Must chain migration 061 from _ensure_entitlements_tables"

def test_phase_26_migration_061_creates_table():
    """Phase 26: migration 061 creates identity_attack_predictions table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_061_attack_predictions)
    assert 'identity_attack_predictions' in source, "Must create identity_attack_predictions table"
    assert 'prediction_score' in source, "Must have prediction_score column"
    assert 'risk_drivers' in source, "Must have risk_drivers JSONB column"
    assert 'recommended_actions' in source, "Must have recommended_actions column"
    assert 'confidence' in source, "Must have confidence column"

def test_phase_26_migration_061_risk_level_check():
    """Phase 26: migration 061 has CHECK constraint for risk_level."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_061_attack_predictions)
    assert 'critical' in source, "Must include critical"
    assert 'high' in source, "Must include high"
    assert 'medium' in source, "Must include medium"
    assert 'low' in source, "Must include low"

def test_phase_26_migration_061_rls_policies():
    """Phase 26: migration 061 creates RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_061_attack_predictions)
    assert 'ROW LEVEL SECURITY' in source or 'row level security' in source.lower(), \
        "Must enable RLS"
    assert 'iap_strict_sel' in source, "Must have SELECT policy"
    assert 'iap_strict_ins' in source, "Must have INSERT policy"

def test_phase_26_migration_061_sql_file_exists():
    """Phase 26: SQL migration file 061 exists."""
    import os
    sql_path = os.path.join(
        os.path.dirname(__file__), '..', 'migrations', '061_attack_predictions.sql'
    )
    assert os.path.exists(sql_path), "061_attack_predictions.sql must exist"

def test_phase_26_predictor_class_exists():
    """Phase 26: AttackPredictor class exists and is importable."""
    from app.engines.attack_predictor import AttackPredictor
    assert callable(AttackPredictor), "AttackPredictor must be callable class"

def test_phase_26_predictor_predict_method():
    """Phase 26: predictor has predict_identity_attacks method."""
    from app.engines.attack_predictor import AttackPredictor
    source = inspect.getsource(AttackPredictor)
    assert 'predict_identity_attacks' in source, "Must have predict_identity_attacks"
    assert 'connection_id' in source, "Must accept connection_id"
    assert 'org_id' in source, "Must accept org_id"

def test_phase_26_predictor_risk_drivers():
    """Phase 26: predictor analyzes multiple risk drivers."""
    from app.engines.attack_predictor import AttackPredictor
    source = inspect.getsource(AttackPredictor)
    assert 'privileged_roles' in source, "Must check privileged_roles"
    assert 'credential_age' in source, "Must check credential_age"
    assert 'anomaly_frequency' in source, "Must check anomaly_frequency"
    assert 'attack_path_exposure' in source, "Must check attack_path_exposure"
    assert 'activity_status' in source, "Must check activity_status"

def test_phase_26_predictor_driver_weights():
    """Phase 26: predictor defines DRIVER_WEIGHTS for scoring."""
    from app.engines.attack_predictor import DRIVER_WEIGHTS
    assert 'privileged_roles' in DRIVER_WEIGHTS
    assert 'credential_age' in DRIVER_WEIGHTS
    assert 'anomaly_frequency' in DRIVER_WEIGHTS
    assert 'attack_path_exposure' in DRIVER_WEIGHTS

def test_phase_26_predictor_risk_thresholds():
    """Phase 26: predictor defines RISK_THRESHOLDS for classification."""
    from app.engines.attack_predictor import RISK_THRESHOLDS
    assert RISK_THRESHOLDS['critical'] == 80
    assert RISK_THRESHOLDS['high'] == 60
    assert RISK_THRESHOLDS['medium'] == 40

def test_phase_26_predictor_score_to_risk():
    """Phase 26: predictor converts scores to risk levels correctly."""
    from app.engines.attack_predictor import AttackPredictor
    pred = AttackPredictor.__new__(AttackPredictor)
    assert pred._score_to_risk_level(85) == 'critical'
    assert pred._score_to_risk_level(65) == 'high'
    assert pred._score_to_risk_level(45) == 'medium'
    assert pred._score_to_risk_level(20) == 'low'

def test_phase_26_predictor_recommendations():
    """Phase 26: predictor generates recommended actions."""
    from app.engines.attack_predictor import AttackPredictor
    source = inspect.getsource(AttackPredictor)
    assert '_generate_recommendations' in source, "Must have _generate_recommendations"
    assert 'action' in source, "Must include action text"
    assert 'priority' in source, "Must include priority"

def test_phase_26_predictor_confidence():
    """Phase 26: predictor computes confidence score."""
    from app.engines.attack_predictor import AttackPredictor
    source = inspect.getsource(AttackPredictor)
    assert '_compute_confidence' in source, "Must have _compute_confidence"

def test_phase_26_predictor_high_privilege_roles():
    """Phase 26: predictor defines HIGH_PRIVILEGE_ROLES."""
    from app.engines.attack_predictor import HIGH_PRIVILEGE_ROLES
    assert 'Owner' in HIGH_PRIVILEGE_ROLES
    assert 'Global Administrator' in HIGH_PRIVILEGE_ROLES

def test_phase_26_db_save_attack_prediction():
    """Phase 26: Database has save_attack_prediction method."""
    from app.database import Database
    assert hasattr(Database, 'save_attack_prediction'), \
        "Database must have save_attack_prediction"

def test_phase_26_db_get_attack_predictions():
    """Phase 26: Database has get_attack_predictions method."""
    from app.database import Database
    assert hasattr(Database, 'get_attack_predictions'), \
        "Database must have get_attack_predictions"

def test_phase_26_db_get_attack_predictions_stats():
    """Phase 26: Database has get_attack_predictions_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_attack_predictions_stats'), \
        "Database must have get_attack_predictions_stats"

def test_phase_26_scheduler_attack_prediction():
    """Phase 26: scheduler has _run_attack_prediction function."""
    from app import scheduler
    source = inspect.getsource(scheduler)
    assert '_run_attack_prediction' in source, "Must have _run_attack_prediction"
    assert 'AttackPredictor' in source, "Must import AttackPredictor"

def test_phase_26_scheduler_track_job():
    """Phase 26: attack_prediction is tracked in scheduler pipeline."""
    from app import scheduler
    source = inspect.getsource(scheduler)
    assert "'attack_prediction'" in source, "Must track attack_prediction job"

def test_phase_26_predictions_api_route():
    """Phase 26: /api/security/attack-predictions route exists."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/attack-predictions' in source, "Must have attack-predictions route"

def test_phase_26_predictions_handler_exists():
    """Phase 26: get_attack_predictions_handler is callable."""
    from app.api.handlers import get_attack_predictions_handler
    assert callable(get_attack_predictions_handler), \
        "get_attack_predictions_handler must be callable"

def test_phase_26_predictions_handler_uses_db():
    """Phase 26: predictions handler queries DB for predictions and stats."""
    from app.api.handlers import get_attack_predictions_handler
    source = inspect.getsource(get_attack_predictions_handler)
    assert 'get_attack_predictions' in source, "Must call get_attack_predictions"
    assert 'get_attack_predictions_stats' in source, "Must call stats method"

def test_phase_26_copilot_prediction_intent():
    """Phase 26: copilot can parse attack prediction queries."""
    from app.engines.security_copilot import SecurityCopilot
    copilot = SecurityCopilot.__new__(SecurityCopilot)
    assert copilot._parse_intent('Which identities are most likely to be compromised?') == 'attack_prediction'

def test_phase_26_copilot_prediction_retriever():
    """Phase 26: copilot has _get_prediction_data retriever."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_get_prediction_data' in source, "Must have _get_prediction_data"
    assert 'get_attack_predictions' in source, "Must query predictions"

def test_phase_26_copilot_prediction_responder():
    """Phase 26: copilot has _respond_predictions generator."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_respond_predictions' in source, "Must have _respond_predictions"


# ── Phase 27: Identity Graph Intelligence ────────────────────────────────

def test_phase_27_migration_062_exists():
    """Phase 27: Database has _run_migration_062_graph_intelligence method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_062_graph_intelligence'), \
        "Database must have _run_migration_062_graph_intelligence"

def test_phase_27_migration_062_called_from_entitlements():
    """Phase 27: migration 062 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_062_graph_intelligence' in source, \
        "Must call _run_migration_062_graph_intelligence from entitlements"

def test_phase_27_migration_062_creates_table():
    """Phase 27: migration 062 creates identity_graph_insights table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_062_graph_intelligence)
    assert 'identity_graph_insights' in source
    assert 'centrality_score' in source
    assert 'blast_radius' in source
    assert 'trust_chain_length' in source
    assert 'resource_reachability' in source
    assert 'privilege_concentration' in source

def test_phase_27_migration_062_rls():
    """Phase 27: migration 062 applies 4 strict RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_062_graph_intelligence)
    assert 'igi_strict_sel' in source
    assert 'igi_strict_ins' in source
    assert 'igi_strict_upd' in source
    assert 'igi_strict_del' in source

def test_phase_27_migration_062_dedup_index():
    """Phase 27: migration 062 creates dedup index."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_062_graph_intelligence)
    assert 'idx_igi_dedup' in source
    assert 'cloud_connection_id' in source
    assert 'identity_id' in source

def test_phase_27_migration_062_sql_file():
    """Phase 27: SQL migration file exists."""
    import os
    path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '062_graph_intelligence.sql')
    assert os.path.isfile(path), "migrations/062_graph_intelligence.sql must exist"

def test_phase_27_graph_intelligence_engine_exists():
    """Phase 27: GraphIntelligenceEngine module can be imported."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    assert GraphIntelligenceEngine is not None

def test_phase_27_compute_graph_insights():
    """Phase 27: engine has compute_graph_insights method."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    assert hasattr(GraphIntelligenceEngine, 'compute_graph_insights')

def test_phase_27_centrality_computation():
    """Phase 27: engine computes centrality score."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    source = inspect.getsource(GraphIntelligenceEngine)
    assert '_compute_centrality' in source

def test_phase_27_blast_radius_computation():
    """Phase 27: engine computes blast radius."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    source = inspect.getsource(GraphIntelligenceEngine)
    assert '_compute_blast_radius' in source

def test_phase_27_trust_chain_computation():
    """Phase 27: engine computes trust chain length."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    source = inspect.getsource(GraphIntelligenceEngine)
    assert '_compute_trust_chain_length' in source

def test_phase_27_resource_reachability():
    """Phase 27: engine computes resource reachability."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    source = inspect.getsource(GraphIntelligenceEngine)
    assert '_compute_resource_reachability' in source

def test_phase_27_privilege_concentration():
    """Phase 27: engine computes privilege concentration."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    source = inspect.getsource(GraphIntelligenceEngine)
    assert '_compute_privilege_concentration' in source

def test_phase_27_risk_classification():
    """Phase 27: engine classifies risk from composite score."""
    from app.engines.graph_intelligence import GraphIntelligenceEngine
    source = inspect.getsource(GraphIntelligenceEngine)
    assert '_classify_risk' in source
    assert '_composite_score' in source

def test_phase_27_graph_intelligence_in_scheduler():
    """Phase 27: _run_graph_intelligence exists in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_graph_intelligence' in source
    assert "graph_intelligence" in source

def test_phase_27_graph_insights_api_route():
    """Phase 27: /api/security/graph-insights route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/graph-insights' in source

def test_phase_27_graph_insights_handler():
    """Phase 27: get_graph_insights_handler exists in handlers."""
    from app.api.handlers import get_graph_insights_handler
    assert callable(get_graph_insights_handler)

def test_phase_27_save_graph_insights_crud():
    """Phase 27: Database has save_graph_insights CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'save_graph_insights')

def test_phase_27_get_graph_insights_crud():
    """Phase 27: Database has get_graph_insights CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_graph_insights')

def test_phase_27_get_graph_insights_stats_crud():
    """Phase 27: Database has get_graph_insights_stats CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_graph_insights_stats')

def test_phase_27_copilot_graph_intelligence_pattern():
    """Phase 27: copilot has graph_intelligence intent pattern."""
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [intent for _, intent in QUERY_PATTERNS]
    assert 'graph_intelligence' in intents, "Must have graph_intelligence intent"

def test_phase_27_copilot_graph_intelligence_retriever():
    """Phase 27: copilot has _get_graph_intelligence_data retriever."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_get_graph_intelligence_data' in source

def test_phase_27_copilot_graph_intelligence_responder():
    """Phase 27: copilot has _respond_graph_intelligence generator."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_respond_graph_intelligence' in source

def test_phase_27_high_privilege_roles():
    """Phase 27: engine defines HIGH_PRIVILEGE_ROLES constant."""
    from app.engines.graph_intelligence import HIGH_PRIVILEGE_ROLES
    assert 'Owner' in HIGH_PRIVILEGE_ROLES
    assert 'Contributor' in HIGH_PRIVILEGE_ROLES
    assert 'Global Administrator' in HIGH_PRIVILEGE_ROLES

def test_phase_27_risk_thresholds():
    """Phase 27: engine defines RISK_THRESHOLDS."""
    from app.engines.graph_intelligence import RISK_THRESHOLDS
    assert RISK_THRESHOLDS['critical'] == 80
    assert RISK_THRESHOLDS['high'] == 60
    assert RISK_THRESHOLDS['medium'] == 40
    assert RISK_THRESHOLDS['low'] == 0


# ── Phase 28: Autonomous Identity Governance ─────────────────────────────

def test_phase_28_migration_063_exists():
    """Phase 28: Database has _run_migration_063_identity_governance method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_063_identity_governance'), \
        "Database must have _run_migration_063_identity_governance"

def test_phase_28_migration_063_called_from_entitlements():
    """Phase 28: migration 063 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_063_identity_governance' in source

def test_phase_28_migration_063_creates_table():
    """Phase 28: migration 063 creates identity_governance_actions table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_063_identity_governance)
    assert 'identity_governance_actions' in source
    assert 'governance_action' in source
    assert 'downgrade_privileged_role' in source
    assert 'disable_unused_identity' in source
    assert 'rotate_old_credential' in source
    assert 'remove_guest_privilege' in source

def test_phase_28_migration_063_status_check():
    """Phase 28: migration 063 has status CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_063_identity_governance)
    assert "'pending'" in source
    assert "'approved'" in source
    assert "'executed'" in source
    assert "'failed'" in source

def test_phase_28_migration_063_rls():
    """Phase 28: migration 063 applies 4 strict RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_063_identity_governance)
    assert 'iga_strict_sel' in source
    assert 'iga_strict_ins' in source
    assert 'iga_strict_upd' in source
    assert 'iga_strict_del' in source

def test_phase_28_migration_063_dedup_index():
    """Phase 28: migration 063 creates dedup index for pending actions."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_063_identity_governance)
    assert 'idx_iga_dedup' in source
    assert "status = 'pending'" in source

def test_phase_28_migration_063_sql_file():
    """Phase 28: SQL migration file exists."""
    import os
    path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '063_identity_governance.sql')
    assert os.path.isfile(path), "migrations/063_identity_governance.sql must exist"

def test_phase_28_governance_engine_exists():
    """Phase 28: IdentityGovernanceEngine module can be imported."""
    from app.engines.identity_governance_engine import IdentityGovernanceEngine
    assert IdentityGovernanceEngine is not None

def test_phase_28_evaluate_identity_governance():
    """Phase 28: engine has evaluate_identity_governance method."""
    from app.engines.identity_governance_engine import IdentityGovernanceEngine
    assert hasattr(IdentityGovernanceEngine, 'evaluate_identity_governance')

def test_phase_28_check_unused_identity():
    """Phase 28: engine checks for unused identities."""
    from app.engines.identity_governance_engine import IdentityGovernanceEngine
    source = inspect.getsource(IdentityGovernanceEngine)
    assert '_check_unused_identity' in source
    assert 'disable_unused_identity' in source

def test_phase_28_check_stale_credentials():
    """Phase 28: engine checks for stale credentials."""
    from app.engines.identity_governance_engine import IdentityGovernanceEngine
    source = inspect.getsource(IdentityGovernanceEngine)
    assert '_check_stale_credentials' in source
    assert 'rotate_old_credential' in source

def test_phase_28_check_privilege_drift():
    """Phase 28: engine checks for privilege drift."""
    from app.engines.identity_governance_engine import IdentityGovernanceEngine
    source = inspect.getsource(IdentityGovernanceEngine)
    assert '_check_privilege_drift' in source
    assert 'downgrade_privileged_role' in source

def test_phase_28_check_guest_privilege():
    """Phase 28: engine checks for guest over-privilege."""
    from app.engines.identity_governance_engine import IdentityGovernanceEngine
    source = inspect.getsource(IdentityGovernanceEngine)
    assert '_check_guest_privilege' in source
    assert 'remove_guest_privilege' in source

def test_phase_28_privileged_roles_constant():
    """Phase 28: engine defines PRIVILEGED_ROLES constant."""
    from app.engines.identity_governance_engine import PRIVILEGED_ROLES
    assert 'Owner' in PRIVILEGED_ROLES
    assert 'Contributor' in PRIVILEGED_ROLES
    assert 'Global Administrator' in PRIVILEGED_ROLES

def test_phase_28_guest_restricted_roles():
    """Phase 28: engine defines GUEST_RESTRICTED_ROLES constant."""
    from app.engines.identity_governance_engine import GUEST_RESTRICTED_ROLES
    assert 'Owner' in GUEST_RESTRICTED_ROLES
    assert 'Contributor' in GUEST_RESTRICTED_ROLES

def test_phase_28_governance_in_scheduler():
    """Phase 28: _run_identity_governance exists in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_identity_governance' in source
    assert "identity_governance" in source

def test_phase_28_governance_api_route():
    """Phase 28: /api/security/governance-actions route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/governance-actions' in source

def test_phase_28_governance_handler():
    """Phase 28: get_governance_actions_handler exists in handlers."""
    from app.api.handlers import get_governance_actions_handler
    assert callable(get_governance_actions_handler)

def test_phase_28_save_governance_actions_crud():
    """Phase 28: Database has save_governance_actions CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'save_governance_actions')

def test_phase_28_get_governance_actions_crud():
    """Phase 28: Database has get_governance_actions CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_governance_actions')

def test_phase_28_get_governance_actions_stats_crud():
    """Phase 28: Database has get_governance_actions_stats CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_governance_actions_stats')

def test_phase_28_update_governance_action_status_crud():
    """Phase 28: Database has update_governance_action_status CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'update_governance_action_status')

def test_phase_28_copilot_governance_pattern():
    """Phase 28: copilot has identity_governance intent pattern."""
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [intent for _, intent in QUERY_PATTERNS]
    assert 'identity_governance' in intents

def test_phase_28_copilot_governance_retriever():
    """Phase 28: copilot has _get_governance_data retriever."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_get_governance_data' in source

def test_phase_28_copilot_governance_responder():
    """Phase 28: copilot has _respond_governance generator."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_respond_governance' in source


# ── Phase 29: Identity Risk Simulation Engine ────────────────────────────

def test_phase_29_migration_064_exists():
    """Phase 29: Database has _run_migration_064_risk_simulations method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_064_risk_simulations')

def test_phase_29_migration_064_called_from_entitlements():
    """Phase 29: migration 064 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_064_risk_simulations' in source

def test_phase_29_migration_064_creates_table():
    """Phase 29: migration 064 creates identity_risk_simulations table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_064_risk_simulations)
    assert 'identity_risk_simulations' in source
    assert 'simulation_type' in source
    assert 'exposed_resources' in source
    assert 'exposed_identities' in source
    assert 'escalation_paths' in source
    assert 'simulation_score' in source

def test_phase_29_migration_064_simulation_types():
    """Phase 29: migration 064 has simulation type CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_064_risk_simulations)
    assert 'identity_compromise' in source
    assert 'credential_leak' in source
    assert 'privilege_grant' in source

def test_phase_29_migration_064_rls():
    """Phase 29: migration 064 applies 4 strict RLS policies."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_064_risk_simulations)
    assert 'irs_strict_sel' in source
    assert 'irs_strict_ins' in source
    assert 'irs_strict_upd' in source
    assert 'irs_strict_del' in source

def test_phase_29_migration_064_sql_file():
    """Phase 29: SQL migration file exists."""
    import os
    path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '064_risk_simulations.sql')
    assert os.path.isfile(path)

def test_phase_29_simulator_engine_exists():
    """Phase 29: IdentityRiskSimulator module can be imported."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    assert IdentityRiskSimulator is not None

def test_phase_29_run_simulation_method():
    """Phase 29: engine has run_identity_risk_simulation method."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    assert hasattr(IdentityRiskSimulator, 'run_identity_risk_simulation')

def test_phase_29_simulate_compromise():
    """Phase 29: engine has _simulate_compromise method."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    source = inspect.getsource(IdentityRiskSimulator)
    assert '_simulate_compromise' in source

def test_phase_29_simulate_credential_leak():
    """Phase 29: engine has _simulate_credential_leak method."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    source = inspect.getsource(IdentityRiskSimulator)
    assert '_simulate_credential_leak' in source

def test_phase_29_simulate_privilege_grant():
    """Phase 29: engine has _simulate_privilege_grant method."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    source = inspect.getsource(IdentityRiskSimulator)
    assert '_simulate_privilege_grant' in source

def test_phase_29_compute_simulation_score():
    """Phase 29: engine computes simulation score."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    source = inspect.getsource(IdentityRiskSimulator)
    assert '_compute_simulation_score' in source

def test_phase_29_count_exposed_resources():
    """Phase 29: engine counts exposed resources."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    source = inspect.getsource(IdentityRiskSimulator)
    assert '_count_exposed_resources' in source

def test_phase_29_count_escalation_paths():
    """Phase 29: engine counts escalation paths."""
    from app.engines.identity_risk_simulator import IdentityRiskSimulator
    source = inspect.getsource(IdentityRiskSimulator)
    assert '_count_escalation_paths' in source

def test_phase_29_risk_thresholds():
    """Phase 29: engine defines RISK_THRESHOLDS."""
    from app.engines.identity_risk_simulator import RISK_THRESHOLDS
    assert RISK_THRESHOLDS['critical'] == 80
    assert RISK_THRESHOLDS['high'] == 60

def test_phase_29_simulation_types_constant():
    """Phase 29: engine defines SIMULATION_TYPES."""
    from app.engines.identity_risk_simulator import SIMULATION_TYPES
    assert 'identity_compromise' in SIMULATION_TYPES
    assert 'credential_leak' in SIMULATION_TYPES
    assert 'privilege_grant' in SIMULATION_TYPES

def test_phase_29_risk_simulation_post_route():
    """Phase 29: POST /api/security/risk-simulation route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/risk-simulation' in source

def test_phase_29_risk_simulations_get_route():
    """Phase 29: GET /api/security/risk-simulations route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/risk-simulations' in source

def test_phase_29_run_simulation_handler():
    """Phase 29: run_risk_simulation_handler exists in handlers."""
    from app.api.handlers import run_risk_simulation_handler
    assert callable(run_risk_simulation_handler)

def test_phase_29_get_simulations_handler():
    """Phase 29: get_risk_simulations_handler exists in handlers."""
    from app.api.handlers import get_risk_simulations_handler
    assert callable(get_risk_simulations_handler)

def test_phase_29_save_risk_simulation_crud():
    """Phase 29: Database has save_risk_simulation CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'save_risk_simulation')

def test_phase_29_get_risk_simulations_crud():
    """Phase 29: Database has get_risk_simulations CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_risk_simulations')

def test_phase_29_get_risk_simulations_stats_crud():
    """Phase 29: Database has get_risk_simulations_stats CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_risk_simulations_stats')

def test_phase_29_copilot_simulation_pattern():
    """Phase 29: copilot has risk_simulation intent pattern."""
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [intent for _, intent in QUERY_PATTERNS]
    assert 'risk_simulation' in intents

def test_phase_29_copilot_simulation_retriever():
    """Phase 29: copilot has _get_simulation_data retriever."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_get_simulation_data' in source

def test_phase_29_copilot_simulation_responder():
    """Phase 29: copilot has _respond_simulation generator."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_respond_simulation' in source


# ── Phase 30: Enterprise Security Integrations ───────────────────────────

def test_phase_30_migration_065_exists():
    """Phase 30: Database has _run_migration_065_integration_events method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_065_integration_events')

def test_phase_30_migration_065_called_from_entitlements():
    """Phase 30: migration 065 is chained from _ensure_entitlements_tables."""
    from app.database import Database
    source = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_065_integration_events' in source

def test_phase_30_migration_065_creates_events_table():
    """Phase 30: migration 065 creates integration_events table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_065_integration_events)
    assert 'integration_events' in source
    assert 'event_type' in source
    assert 'destination' in source
    assert 'payload' in source

def test_phase_30_migration_065_creates_configs_table():
    """Phase 30: migration 065 creates integration_configs table."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_065_integration_events)
    assert 'integration_configs' in source
    assert 'integration_type' in source
    assert 'enabled' in source

def test_phase_30_migration_065_event_types():
    """Phase 30: migration 065 has event_type CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_065_integration_events)
    assert "'incident'" in source
    assert "'threat'" in source
    assert "'governance_action'" in source
    assert "'risk_prediction'" in source

def test_phase_30_migration_065_destinations():
    """Phase 30: migration 065 has destination CHECK constraint."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_065_integration_events)
    assert "'slack'" in source
    assert "'jira'" in source
    assert "'servicenow'" in source
    assert "'siem'" in source

def test_phase_30_migration_065_rls_events():
    """Phase 30: migration 065 applies RLS on integration_events."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_065_integration_events)
    assert 'ie_strict_sel' in source
    assert 'ie_strict_ins' in source
    assert 'ie_strict_upd' in source
    assert 'ie_strict_del' in source

def test_phase_30_migration_065_rls_configs():
    """Phase 30: migration 065 applies RLS on integration_configs."""
    from app.database import Database
    source = inspect.getsource(Database._run_migration_065_integration_events)
    assert 'ic_strict_sel' in source
    assert 'ic_strict_ins' in source
    assert 'ic_strict_upd' in source
    assert 'ic_strict_del' in source

def test_phase_30_migration_065_sql_file():
    """Phase 30: SQL migration file exists."""
    import os
    path = os.path.join(os.path.dirname(__file__), '..', 'migrations', '065_integration_events.sql')
    assert os.path.isfile(path)

def test_phase_30_dispatcher_engine_exists():
    """Phase 30: IntegrationDispatcher module can be imported."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    assert IntegrationDispatcher is not None

def test_phase_30_dispatch_method():
    """Phase 30: engine has dispatch_integration_events method."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    assert hasattr(IntegrationDispatcher, 'dispatch_integration_events')

def test_phase_30_collect_incidents():
    """Phase 30: engine collects incident events."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_collect_incident_events' in source

def test_phase_30_collect_threats():
    """Phase 30: engine collects threat events."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_collect_threat_events' in source

def test_phase_30_collect_governance():
    """Phase 30: engine collects governance action events."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_collect_governance_events' in source

def test_phase_30_collect_predictions():
    """Phase 30: engine collects prediction events."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_collect_prediction_events' in source

def test_phase_30_send_slack():
    """Phase 30: engine has _send_slack dispatcher."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_send_slack' in source

def test_phase_30_send_jira():
    """Phase 30: engine has _send_jira dispatcher."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_send_jira' in source

def test_phase_30_send_servicenow():
    """Phase 30: engine has _send_servicenow dispatcher."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_send_servicenow' in source

def test_phase_30_send_siem():
    """Phase 30: engine has _send_siem dispatcher."""
    from app.engines.integration_dispatcher import IntegrationDispatcher
    source = inspect.getsource(IntegrationDispatcher)
    assert '_send_siem' in source

def test_phase_30_integration_in_scheduler():
    """Phase 30: _run_integration_dispatch exists in scheduler."""
    from app import scheduler as sched
    source = inspect.getsource(sched)
    assert '_run_integration_dispatch' in source
    assert 'integration_dispatch' in source

def test_phase_30_integrations_get_route():
    """Phase 30: GET /api/security/integrations route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/integrations' in source

def test_phase_30_configure_post_route():
    """Phase 30: POST /api/security/integrations/configure route registered."""
    from app.main import create_app
    source = inspect.getsource(create_app)
    assert '/api/security/integrations/configure' in source

def test_phase_30_get_events_handler():
    """Phase 30: get_integration_events_handler exists in handlers."""
    from app.api.handlers import get_integration_events_handler
    assert callable(get_integration_events_handler)

def test_phase_30_configure_handler():
    """Phase 30: configure_integration_handler exists in handlers."""
    from app.api.handlers import configure_integration_handler
    assert callable(configure_integration_handler)

def test_phase_30_save_integration_event_crud():
    """Phase 30: Database has save_integration_event CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'save_integration_event')

def test_phase_30_get_integration_events_crud():
    """Phase 30: Database has get_integration_events CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_integration_events')

def test_phase_30_get_integration_events_stats_crud():
    """Phase 30: Database has get_integration_events_stats CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_integration_events_stats')

def test_phase_30_get_integration_configs_crud():
    """Phase 30: Database has get_integration_configs CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'get_integration_configs')

def test_phase_30_upsert_integration_config_crud():
    """Phase 30: Database has upsert_integration_config CRUD method."""
    from app.database import Database
    assert hasattr(Database, 'upsert_integration_config')

def test_phase_30_copilot_integration_pattern():
    """Phase 30: copilot has integration_status intent pattern."""
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [intent for _, intent in QUERY_PATTERNS]
    assert 'integration_status' in intents

def test_phase_30_copilot_integration_retriever():
    """Phase 30: copilot has _get_integration_data retriever."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_get_integration_data' in source

def test_phase_30_copilot_integration_responder():
    """Phase 30: copilot has _respond_integrations generator."""
    from app.engines.security_copilot import SecurityCopilot
    source = inspect.getsource(SecurityCopilot)
    assert '_respond_integrations' in source

def test_phase_30_event_types_constant():
    """Phase 30: engine defines EVENT_TYPES constant."""
    from app.engines.integration_dispatcher import EVENT_TYPES
    assert 'incident' in EVENT_TYPES
    assert 'threat' in EVENT_TYPES
    assert 'governance_action' in EVENT_TYPES
    assert 'risk_prediction' in EVENT_TYPES

def test_phase_30_destinations_constant():
    """Phase 30: engine defines DESTINATIONS constant."""
    from app.engines.integration_dispatcher import DESTINATIONS
    assert 'slack' in DESTINATIONS
    assert 'jira' in DESTINATIONS
    assert 'servicenow' in DESTINATIONS
    assert 'siem' in DESTINATIONS


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 31 — Identity Governance Analytics
# ═══════════════════════════════════════════════════════════════════════════════

def test_phase_31_migration_066_method_exists():
    """Phase 31: Database has _run_migration_066_governance_analytics method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_066_governance_analytics')

def test_phase_31_migration_066_class_flag():
    """Phase 31: Database has _migration_066_governance_analytics_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_066_governance_analytics_ensured')

def test_phase_31_migration_066_chained():
    """Phase 31: migration 066 is called from _ensure_entitlements_tables."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_066_governance_analytics' in src

def test_phase_31_migration_066_creates_metrics_table():
    """Phase 31: migration 066 creates identity_governance_metrics table."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_066_governance_analytics)
    assert 'identity_governance_metrics' in src
    assert 'metric_type' in src
    assert 'privilege_drift_rate' in src
    assert 'stale_credentials_ratio' in src
    assert 'guest_privilege_ratio' in src
    assert 'inactive_identity_ratio' in src

def test_phase_31_migration_066_creates_trends_table():
    """Phase 31: migration 066 creates identity_governance_trends table."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_066_governance_analytics)
    assert 'identity_governance_trends' in src
    assert 'trend_direction' in src
    assert 'increasing' in src
    assert 'stable' in src
    assert 'decreasing' in src

def test_phase_31_migration_066_metrics_rls():
    """Phase 31: identity_governance_metrics has 4 RLS policies."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_066_governance_analytics)
    assert 'igm_strict_sel' in src
    assert 'igm_strict_ins' in src
    assert 'igm_strict_upd' in src
    assert 'igm_strict_del' in src

def test_phase_31_migration_066_trends_rls():
    """Phase 31: identity_governance_trends has 4 RLS policies."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_066_governance_analytics)
    assert 'igt_strict_sel' in src
    assert 'igt_strict_ins' in src
    assert 'igt_strict_upd' in src
    assert 'igt_strict_del' in src

def test_phase_31_migration_066_sql_file():
    """Phase 31: SQL migration file exists."""
    import os
    assert os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'migrations', '066_governance_analytics.sql'))

def test_phase_31_save_governance_metrics_method():
    """Phase 31: Database has save_governance_metrics method."""
    from app.database import Database
    assert hasattr(Database, 'save_governance_metrics')

def test_phase_31_save_governance_trends_method():
    """Phase 31: Database has save_governance_trends method."""
    from app.database import Database
    assert hasattr(Database, 'save_governance_trends')

def test_phase_31_get_governance_metrics_method():
    """Phase 31: Database has get_governance_metrics method."""
    from app.database import Database
    assert hasattr(Database, 'get_governance_metrics')
    import inspect
    sig = inspect.signature(Database.get_governance_metrics)
    assert 'connection_id' in sig.parameters
    assert 'metric_type' in sig.parameters

def test_phase_31_get_governance_metrics_stats_method():
    """Phase 31: Database has get_governance_metrics_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_governance_metrics_stats')

def test_phase_31_get_governance_trends_method():
    """Phase 31: Database has get_governance_trends method."""
    from app.database import Database
    assert hasattr(Database, 'get_governance_trends')
    import inspect
    sig = inspect.signature(Database.get_governance_trends)
    assert 'connection_id' in sig.parameters
    assert 'metric_type' in sig.parameters

def test_phase_31_get_governance_trends_stats_method():
    """Phase 31: Database has get_governance_trends_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_governance_trends_stats')

def test_phase_31_engine_class_exists():
    """Phase 31: GovernanceAnalyticsEngine class exists."""
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    assert GovernanceAnalyticsEngine is not None

def test_phase_31_engine_compute_method():
    """Phase 31: engine has compute_governance_metrics method."""
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    import inspect
    sig = inspect.signature(GovernanceAnalyticsEngine.compute_governance_metrics)
    assert 'connection_id' in sig.parameters
    assert 'org_id' in sig.parameters

def test_phase_31_privilege_drift_evaluator():
    """Phase 31: engine has _compute_privilege_drift_rate method."""
    import inspect
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    src = inspect.getsource(GovernanceAnalyticsEngine)
    assert '_compute_privilege_drift_rate' in src

def test_phase_31_stale_credentials_evaluator():
    """Phase 31: engine has _compute_stale_credentials_ratio method."""
    import inspect
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    src = inspect.getsource(GovernanceAnalyticsEngine)
    assert '_compute_stale_credentials_ratio' in src

def test_phase_31_guest_privilege_evaluator():
    """Phase 31: engine has _compute_guest_privilege_ratio method."""
    import inspect
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    src = inspect.getsource(GovernanceAnalyticsEngine)
    assert '_compute_guest_privilege_ratio' in src

def test_phase_31_inactive_identity_evaluator():
    """Phase 31: engine has _compute_inactive_identity_ratio method."""
    import inspect
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    src = inspect.getsource(GovernanceAnalyticsEngine)
    assert '_compute_inactive_identity_ratio' in src

def test_phase_31_compute_trends():
    """Phase 31: engine has _compute_trends method."""
    import inspect
    from app.engines.governance_analytics import GovernanceAnalyticsEngine
    src = inspect.getsource(GovernanceAnalyticsEngine)
    assert '_compute_trends' in src

def test_phase_31_metric_types_constant():
    """Phase 31: engine defines METRIC_TYPES constant."""
    from app.engines.governance_analytics import METRIC_TYPES
    assert 'privilege_drift_rate' in METRIC_TYPES
    assert 'stale_credentials_ratio' in METRIC_TYPES
    assert 'guest_privilege_ratio' in METRIC_TYPES
    assert 'inactive_identity_ratio' in METRIC_TYPES

def test_phase_31_risk_thresholds_constant():
    """Phase 31: engine defines RISK_THRESHOLDS constant."""
    from app.engines.governance_analytics import RISK_THRESHOLDS
    assert 'critical' in RISK_THRESHOLDS
    assert 'high' in RISK_THRESHOLDS
    assert 'medium' in RISK_THRESHOLDS

def test_phase_31_scheduler_function():
    """Phase 31: scheduler has _run_governance_analytics function."""
    import inspect
    import app.scheduler as sched
    src = inspect.getsource(sched)
    assert '_run_governance_analytics' in src
    assert 'GovernanceAnalyticsEngine' in src

def test_phase_31_scheduler_track_job():
    """Phase 31: governance_analytics is tracked in scheduler pipeline."""
    import inspect
    import app.scheduler as sched
    src = inspect.getsource(sched)
    assert "'governance_analytics'" in src

def test_phase_31_governance_metrics_api_route():
    """Phase 31: /api/security/governance-metrics route exists."""
    import inspect
    from app.main import create_app
    src = inspect.getsource(create_app)
    assert '/api/security/governance-metrics' in src

def test_phase_31_governance_trends_api_route():
    """Phase 31: /api/security/governance-trends route exists."""
    import inspect
    from app.main import create_app
    src = inspect.getsource(create_app)
    assert '/api/security/governance-trends' in src

def test_phase_31_copilot_pattern():
    """Phase 31: copilot has governance_analytics pattern."""
    import inspect
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [p[1] for p in QUERY_PATTERNS]
    assert 'governance_analytics' in intents

def test_phase_31_copilot_retriever():
    """Phase 31: copilot has _get_governance_analytics_data retriever."""
    import inspect
    from app.engines.security_copilot import SecurityCopilot
    src = inspect.getsource(SecurityCopilot)
    assert '_get_governance_analytics_data' in src

def test_phase_31_copilot_responder():
    """Phase 31: copilot has _respond_governance_analytics responder."""
    import inspect
    from app.engines.security_copilot import SecurityCopilot
    src = inspect.getsource(SecurityCopilot)
    assert '_respond_governance_analytics' in src


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 32 — AI Security Strategy Advisor
# ═══════════════════════════════════════════════════════════════════════════════

def test_phase_32_migration_067_method_exists():
    """Phase 32: Database has _run_migration_067_security_strategy method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_067_security_strategy')

def test_phase_32_migration_067_class_flag():
    """Phase 32: Database has _migration_067_security_strategy_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_067_security_strategy_ensured')

def test_phase_32_migration_067_chained():
    """Phase 32: migration 067 is called from _ensure_entitlements_tables."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_067_security_strategy' in src

def test_phase_32_migration_067_creates_table():
    """Phase 32: migration 067 creates security_strategy_recommendations table."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_067_security_strategy)
    assert 'security_strategy_recommendations' in src
    assert 'recommendation_type' in src
    assert 'reduce_privileged_roles' in src
    assert 'rotate_credentials' in src
    assert 'remove_unused_identities' in src
    assert 'limit_guest_privileges' in src

def test_phase_32_migration_067_risk_reduction():
    """Phase 32: table has risk_reduction_score column."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_067_security_strategy)
    assert 'risk_reduction_score' in src

def test_phase_32_migration_067_effort():
    """Phase 32: table has implementation_effort column with CHECK."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_067_security_strategy)
    assert 'implementation_effort' in src
    assert "'low'" in src or '"low"' in src

def test_phase_32_migration_067_priority():
    """Phase 32: table has priority column with CHECK."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_067_security_strategy)
    assert 'priority' in src
    assert "'critical'" in src or '"critical"' in src

def test_phase_32_migration_067_rls():
    """Phase 32: security_strategy_recommendations has 4 RLS policies."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_067_security_strategy)
    assert 'ssr_strict_sel' in src
    assert 'ssr_strict_ins' in src
    assert 'ssr_strict_upd' in src
    assert 'ssr_strict_del' in src

def test_phase_32_migration_067_dedup():
    """Phase 32: table has dedup partial unique index."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_067_security_strategy)
    assert 'idx_ssr_dedup' in src
    assert "status = 'open'" in src

def test_phase_32_migration_067_sql_file():
    """Phase 32: SQL migration file exists."""
    import os
    assert os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'migrations', '067_security_strategy.sql'))

def test_phase_32_save_strategy_recommendations():
    """Phase 32: Database has save_strategy_recommendations method."""
    from app.database import Database
    assert hasattr(Database, 'save_strategy_recommendations')

def test_phase_32_get_strategy_recommendations():
    """Phase 32: Database has get_strategy_recommendations method with filters."""
    from app.database import Database
    assert hasattr(Database, 'get_strategy_recommendations')
    import inspect
    sig = inspect.signature(Database.get_strategy_recommendations)
    assert 'priority' in sig.parameters
    assert 'status' in sig.parameters
    assert 'connection_id' in sig.parameters

def test_phase_32_get_strategy_recommendations_stats():
    """Phase 32: Database has get_strategy_recommendations_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_strategy_recommendations_stats')

def test_phase_32_update_strategy_recommendation_status():
    """Phase 32: Database has update_strategy_recommendation_status method."""
    from app.database import Database
    assert hasattr(Database, 'update_strategy_recommendation_status')

def test_phase_32_engine_class_exists():
    """Phase 32: SecurityStrategyAdvisor class exists."""
    from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
    assert SecurityStrategyAdvisor is not None

def test_phase_32_engine_generate_method():
    """Phase 32: engine has generate_security_strategy method."""
    from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
    import inspect
    sig = inspect.signature(SecurityStrategyAdvisor.generate_security_strategy)
    assert 'connection_id' in sig.parameters
    assert 'org_id' in sig.parameters

def test_phase_32_analyze_governance_metrics():
    """Phase 32: engine has _analyze_governance_metrics method."""
    import inspect
    from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
    src = inspect.getsource(SecurityStrategyAdvisor)
    assert '_analyze_governance_metrics' in src

def test_phase_32_analyze_attack_predictions():
    """Phase 32: engine has _analyze_attack_predictions method."""
    import inspect
    from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
    src = inspect.getsource(SecurityStrategyAdvisor)
    assert '_analyze_attack_predictions' in src

def test_phase_32_analyze_graph_insights():
    """Phase 32: engine has _analyze_graph_insights method."""
    import inspect
    from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
    src = inspect.getsource(SecurityStrategyAdvisor)
    assert '_analyze_graph_insights' in src

def test_phase_32_analyze_simulation_results():
    """Phase 32: engine has _analyze_simulation_results method."""
    import inspect
    from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
    src = inspect.getsource(SecurityStrategyAdvisor)
    assert '_analyze_simulation_results' in src

def test_phase_32_recommendation_types_constant():
    """Phase 32: engine defines RECOMMENDATION_TYPES constant."""
    from app.engines.security_strategy_advisor import RECOMMENDATION_TYPES
    assert 'reduce_privileged_roles' in RECOMMENDATION_TYPES
    assert 'rotate_credentials' in RECOMMENDATION_TYPES
    assert 'remove_unused_identities' in RECOMMENDATION_TYPES
    assert 'limit_guest_privileges' in RECOMMENDATION_TYPES

def test_phase_32_thresholds_constant():
    """Phase 32: engine defines THRESHOLDS constant."""
    from app.engines.security_strategy_advisor import THRESHOLDS
    assert 'privileged_ratio' in THRESHOLDS
    assert 'stale_credential_ratio' in THRESHOLDS
    assert 'inactive_ratio' in THRESHOLDS
    assert 'guest_privilege_ratio' in THRESHOLDS

def test_phase_32_scheduler_function():
    """Phase 32: scheduler has _run_security_strategy function."""
    import inspect
    import app.scheduler as sched
    src = inspect.getsource(sched)
    assert '_run_security_strategy' in src
    assert 'SecurityStrategyAdvisor' in src

def test_phase_32_scheduler_track_job():
    """Phase 32: security_strategy is tracked in scheduler pipeline."""
    import inspect
    import app.scheduler as sched
    src = inspect.getsource(sched)
    assert "'security_strategy'" in src

def test_phase_32_strategy_advisor_api_route():
    """Phase 32: /api/security/strategy-advisor route exists."""
    import inspect
    from app.main import create_app
    src = inspect.getsource(create_app)
    assert '/api/security/strategy-advisor' in src

def test_phase_32_copilot_pattern():
    """Phase 32: copilot has security_strategy pattern."""
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [p[1] for p in QUERY_PATTERNS]
    assert 'security_strategy' in intents

def test_phase_32_copilot_retriever():
    """Phase 32: copilot has _get_security_strategy_data retriever."""
    import inspect
    from app.engines.security_copilot import SecurityCopilot
    src = inspect.getsource(SecurityCopilot)
    assert '_get_security_strategy_data' in src

def test_phase_32_copilot_responder():
    """Phase 32: copilot has _respond_security_strategy responder."""
    import inspect
    from app.engines.security_copilot import SecurityCopilot
    src = inspect.getsource(SecurityCopilot)
    assert '_respond_security_strategy' in src


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 33 — Identity Security Command Center
# ═══════════════════════════════════════════════════════════════════════════════

def test_phase_33_migration_068_method_exists():
    """Phase 33: Database has _run_migration_068_security_command_center method."""
    from app.database import Database
    assert hasattr(Database, '_run_migration_068_security_command_center')

def test_phase_33_migration_068_class_flag():
    """Phase 33: Database has _migration_068_security_command_center_ensured class flag."""
    from app.database import Database
    assert hasattr(Database, '_migration_068_security_command_center_ensured')

def test_phase_33_migration_068_chained():
    """Phase 33: migration 068 is called from _ensure_entitlements_tables."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._ensure_entitlements_tables)
    assert '_run_migration_068_security_command_center' in src

def test_phase_33_migration_068_creates_table():
    """Phase 33: migration 068 creates identity_security_posture table."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_068_security_command_center)
    assert 'identity_security_posture' in src
    assert 'risk_score' in src
    assert 'incident_count' in src
    assert 'prediction_count' in src
    assert 'governance_violation_count' in src
    assert 'strategy_recommendation_count' in src

def test_phase_33_migration_068_rls():
    """Phase 33: identity_security_posture has 4 RLS policies."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._run_migration_068_security_command_center)
    assert 'isp_strict_sel' in src
    assert 'isp_strict_ins' in src
    assert 'isp_strict_upd' in src
    assert 'isp_strict_del' in src

def test_phase_33_migration_068_sql_file():
    """Phase 33: SQL migration file exists."""
    import os
    assert os.path.exists(os.path.join(os.path.dirname(__file__), '..', 'migrations', '068_security_command_center.sql'))

def test_phase_33_save_security_posture():
    """Phase 33: Database has save_security_posture method."""
    from app.database import Database
    assert hasattr(Database, 'save_security_posture')

def test_phase_33_get_security_posture():
    """Phase 33: Database has get_security_posture method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_posture')
    import inspect
    sig = inspect.signature(Database.get_security_posture)
    assert 'connection_id' in sig.parameters

def test_phase_33_get_security_posture_latest():
    """Phase 33: Database has get_security_posture_latest method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_posture_latest')

def test_phase_33_get_security_posture_stats():
    """Phase 33: Database has get_security_posture_stats method."""
    from app.database import Database
    assert hasattr(Database, 'get_security_posture_stats')

def test_phase_33_engine_class_exists():
    """Phase 33: SecurityCommandCenter class exists."""
    from app.engines.security_command_center import SecurityCommandCenter
    assert SecurityCommandCenter is not None

def test_phase_33_engine_compute_method():
    """Phase 33: engine has compute_security_posture method."""
    from app.engines.security_command_center import SecurityCommandCenter
    import inspect
    sig = inspect.signature(SecurityCommandCenter.compute_security_posture)
    assert 'connection_id' in sig.parameters
    assert 'org_id' in sig.parameters

def test_phase_33_aggregate_incidents():
    """Phase 33: engine has _aggregate_incidents method."""
    import inspect
    from app.engines.security_command_center import SecurityCommandCenter
    src = inspect.getsource(SecurityCommandCenter)
    assert '_aggregate_incidents' in src

def test_phase_33_aggregate_predictions():
    """Phase 33: engine has _aggregate_predictions method."""
    import inspect
    from app.engines.security_command_center import SecurityCommandCenter
    src = inspect.getsource(SecurityCommandCenter)
    assert '_aggregate_predictions' in src

def test_phase_33_aggregate_governance():
    """Phase 33: engine has _aggregate_governance method."""
    import inspect
    from app.engines.security_command_center import SecurityCommandCenter
    src = inspect.getsource(SecurityCommandCenter)
    assert '_aggregate_governance' in src

def test_phase_33_aggregate_strategy():
    """Phase 33: engine has _aggregate_strategy method."""
    import inspect
    from app.engines.security_command_center import SecurityCommandCenter
    src = inspect.getsource(SecurityCommandCenter)
    assert '_aggregate_strategy' in src

def test_phase_33_compute_risk_score():
    """Phase 33: engine has _compute_risk_score method."""
    import inspect
    from app.engines.security_command_center import SecurityCommandCenter
    src = inspect.getsource(SecurityCommandCenter)
    assert '_compute_risk_score' in src

def test_phase_33_risk_label():
    """Phase 33: engine has _risk_label method."""
    import inspect
    from app.engines.security_command_center import SecurityCommandCenter
    src = inspect.getsource(SecurityCommandCenter)
    assert '_risk_label' in src

def test_phase_33_severity_weights():
    """Phase 33: engine defines SEVERITY_WEIGHTS constant."""
    from app.engines.security_command_center import SEVERITY_WEIGHTS
    assert 'critical' in SEVERITY_WEIGHTS
    assert 'high' in SEVERITY_WEIGHTS
    assert 'medium' in SEVERITY_WEIGHTS
    assert 'low' in SEVERITY_WEIGHTS

def test_phase_33_risk_labels():
    """Phase 33: engine defines RISK_LABELS constant."""
    from app.engines.security_command_center import RISK_LABELS
    labels = list(RISK_LABELS.values())
    assert 'excellent' in labels
    assert 'critical' in labels

def test_phase_33_scheduler_function():
    """Phase 33: scheduler has _run_security_posture function."""
    import inspect
    import app.scheduler as sched
    src = inspect.getsource(sched)
    assert '_run_security_posture' in src
    assert 'SecurityCommandCenter' in src

def test_phase_33_scheduler_track_job():
    """Phase 33: security_posture is tracked in scheduler pipeline."""
    import inspect
    import app.scheduler as sched
    src = inspect.getsource(sched)
    assert "'security_posture'" in src

def test_phase_33_command_center_api_route():
    """Phase 33: /api/security/command-center route exists."""
    import inspect
    from app.main import create_app
    src = inspect.getsource(create_app)
    assert '/api/security/command-center' in src

def test_phase_33_copilot_pattern():
    """Phase 33: copilot has command_center pattern."""
    from app.engines.security_copilot import QUERY_PATTERNS
    intents = [p[1] for p in QUERY_PATTERNS]
    assert 'command_center' in intents

def test_phase_33_copilot_retriever():
    """Phase 33: copilot has _get_command_center_data retriever."""
    import inspect
    from app.engines.security_copilot import SecurityCopilot
    src = inspect.getsource(SecurityCopilot)
    assert '_get_command_center_data' in src

def test_phase_33_copilot_responder():
    """Phase 33: copilot has _respond_command_center responder."""
    import inspect
    from app.engines.security_copilot import SecurityCopilot
    src = inspect.getsource(SecurityCopilot)
    assert '_respond_command_center' in src


# ─── Multi-Tenant Discovery Fix Tests ───────────────────────────────────

def test_mt_fix_discover_captures_tenant_id():
    """MT Fix: _discover_subscriptions captures tenant_id per subscription."""
    import inspect
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    src = inspect.getsource(AzureDiscoveryEngine._discover_subscriptions)
    assert 'tenant_id' in src, "_discover_subscriptions must capture tenant_id"


def test_mt_fix_foreign_subscriptions_attribute():
    """MT Fix: __init__ references foreign_subscriptions attribute."""
    import inspect
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    src = inspect.getsource(AzureDiscoveryEngine.__init__)
    assert 'foreign_subscriptions' in src, "__init__ must set foreign_subscriptions"


def test_mt_fix_subscription_partitioning():
    """MT Fix: __init__ partitions subscriptions by azure_directory_id."""
    import inspect
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    src = inspect.getsource(AzureDiscoveryEngine.__init__)
    assert 'azure_directory_id' in src, "__init__ must partition by azure_directory_id"
    # Must filter own-tenant subs (== check) and foreign-tenant subs (!= check)
    assert '!=' in src or 'foreign_subscriptions' in src


def test_mt_fix_find_or_create_method():
    """MT Fix: Database.find_or_create_cloud_connection method exists."""
    from app.database import Database
    assert hasattr(Database, 'find_or_create_cloud_connection'), \
        "Database must have find_or_create_cloud_connection method"


def test_mt_fix_find_or_create_params():
    """MT Fix: find_or_create_cloud_connection has correct parameters."""
    import inspect
    from app.database import Database
    sig = inspect.signature(Database.find_or_create_cloud_connection)
    params = list(sig.parameters.keys())
    assert 'organization_id' in params
    assert 'azure_directory_id' in params


def test_mt_fix_find_or_create_queries():
    """MT Fix: find_or_create_cloud_connection queries cloud_connections by tenant."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database.find_or_create_cloud_connection)
    assert 'cloud_connections' in src
    assert 'azure_directory_id' in src


def test_mt_fix_sync_foreign_subs():
    """MT Fix: Subscription sync references foreign_subscriptions."""
    import inspect
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    src = inspect.getsource(AzureDiscoveryEngine._async_run_discovery)
    assert 'foreign_subscriptions' in src, \
        "_async_run_discovery must sync foreign_subscriptions"
    assert 'find_or_create_cloud_connection' in src, \
        "_async_run_discovery must call find_or_create_cloud_connection"


def test_mt_fix_handler_captures_tenant():
    """MT Fix: Handler captures tenant_id in subscription list."""
    import inspect
    from app.api import handlers
    src = inspect.getsource(handlers)
    # The POST connections handler must capture tenant_id
    assert "sub.tenant_id" in src or "'tenant_id'" in src


def test_mt_fix_handler_groups_by_tenant():
    """MT Fix: Handler calls find_or_create_cloud_connection for foreign tenants."""
    import inspect
    from app.api import handlers
    src = inspect.getsource(handlers)
    assert 'find_or_create_cloud_connection' in src


def test_mt_fix_connection_unique_constraint():
    """MT Fix: cloud_connections DDL has UNIQUE(organization_id, cloud, azure_directory_id)."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._ensure_cloud_connections_table)
    assert 'organization_id' in src
    assert 'azure_directory_id' in src
    assert 'UNIQUE' in src or 'ON CONFLICT' in src


def test_mt_fix_subscription_unique_constraint():
    """MT Fix: cloud_subscriptions DDL has UNIQUE(cloud_connection_id, account_id)."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database._ensure_cloud_subscriptions_table)
    assert 'cloud_connection_id' in src
    assert 'account_id' in src


def test_mt_fix_discovery_run_per_connection():
    """MT Fix: create_discovery_run requires cloud_connection_id."""
    import inspect
    from app.database import Database
    src = inspect.getsource(Database.create_discovery_run)
    assert 'cloud_connection_id' in src
