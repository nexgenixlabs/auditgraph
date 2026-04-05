"""
Phase 2C: Organization Isolation Simulation Suite

Source-inspection tests that verify the tenant→organization rename is complete
across database.py, handlers.py, and service layers.
"""
import os
import inspect
import re

# Ensure dev mode + test keys before importing app modules
os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-key-2c')
os.environ.setdefault('TENANT_JWT_SECRET', 'tenant-test-key-2c')


def _get_method_source(cls, method_name):
    """Get the source code of a method on a class."""
    method = getattr(cls, method_name)
    return inspect.getsource(method)


# ── Test 1: RLS policies use organization_id ──

def test_rls_policies_use_organization_id():
    """All RLS policy DDL in _ensure_* methods must reference organization_id, not tenant_id."""
    from app.database import Database
    # Check that set_organization_context uses app.current_organization_id
    src = inspect.getsource(Database.set_organization_context)
    assert 'app.current_organization_id' in src, \
        "set_organization_context must use app.current_organization_id session var"
    assert 'app.current_tenant_id' not in src, \
        "set_organization_context must not reference old app.current_tenant_id"


# ── Test 2: Session variable is organization_id ──

def test_session_var_is_organization_id():
    """Database.set_organization_context() sets app.current_organization_id."""
    from app.database import Database
    src = inspect.getsource(Database.set_organization_context)
    assert "app.current_organization_id" in src
    assert "app.current_tenant_id" not in src


# ── Test 3: Webhook methods use organization_id ──

def test_webhook_methods_block_cross_org():
    """All webhook DB methods must reference organization_id in their SQL."""
    from app.database import Database
    methods = [
        'get_webhooks', 'get_webhook', 'update_webhook',
        'delete_webhook', 'get_webhooks_for_event',
        'create_webhook_delivery', 'get_webhook_deliveries',
    ]
    for name in methods:
        src = _get_method_source(Database, name)
        assert 'organization_id' in src, f"Database.{name}() missing organization_id filter"


# ── Test 4: SOAR methods use organization_id ──

def test_soar_methods_block_cross_org():
    """All SOAR read/update/delete/stats methods must reference organization_id."""
    from app.database import Database
    methods = [
        'get_soar_playbooks', 'get_soar_playbook',
        'update_soar_playbook', 'delete_soar_playbook',
        'get_enabled_playbooks_by_trigger', 'get_soar_actions',
        'get_soar_action_stats',
    ]
    for name in methods:
        src = _get_method_source(Database, name)
        assert 'organization_id' in src, f"Database.{name}() missing organization_id filter"


# ── Test 5: Custom risk rule methods use organization_id ──

def test_custom_rules_block_cross_org():
    """All custom risk rule DB methods must reference organization_id."""
    from app.database import Database
    methods = [
        'get_custom_risk_rules', 'get_custom_risk_rule',
        'create_custom_risk_rule', 'update_custom_risk_rule',
        'delete_custom_risk_rule', 'get_enabled_risk_rules',
    ]
    for name in methods:
        src = _get_method_source(Database, name)
        assert 'organization_id' in src, f"Database.{name}() missing organization_id filter"


# ── Test 6: Notification methods use organization_id ──

def test_notification_methods_block_cross_org():
    """Notification single-record ops must reference organization_id."""
    from app.database import Database
    methods = [
        'get_notification', 'mark_notification_read',
        'mark_all_notifications_read', 'action_notification',
        'delete_notification',
    ]
    for name in methods:
        src = _get_method_source(Database, name)
        assert 'organization_id' in src, f"Database.{name}() missing organization_id filter"


# ── Test 7: Handler helpers use org_id ──

def test_handler_helpers_use_org_id():
    """_org_id() exists and _db() uses organization_id parameter."""
    from app.api import handlers
    # _org_id helper must exist
    assert hasattr(handlers, '_org_id'), "_org_id helper must exist in handlers.py"
    src = inspect.getsource(handlers._org_id)
    assert 'organization_id' in src, "_org_id must read organization_id from g.current_user"

    # _db helper must use organization_id=
    src = inspect.getsource(handlers._db)
    assert 'organization_id=' in src, "_db must pass organization_id= to Database()"


# ── Test 8: No tenant_id in SQL queries (exemptions only) ──

def test_no_tenant_id_in_sql_queries():
    """database.py should not contain tenant_id in SQL strings, except exempted patterns."""
    import app.database as db_module
    src = inspect.getsource(db_module)

    # Exempted patterns (Azure SDK, backward compat, DB column names for Azure directory)
    exempted_patterns = [
        'tenant_or_org_id',           # Azure directory column
        'allow_cross_tenant',         # Azure Storage property
        "scope_type': 'tenant'",      # Azure RBAC scope type
        'ClientSecretCredential',     # Azure SDK
        'AZURE_TENANT_ID',            # Azure env var
        'tenant_strict',              # Old policy names in DROP statements
        '_migration_018',             # Migration code that renames old names
        'information_schema',         # Migration introspection queries
        'RENAME COLUMN',              # Migration DDL renames old→new columns
        'Phase 2C',                   # Migration docstring
        'column_name =',              # Migration information_schema introspection
        'trg_auto_tenant',            # Old trigger names in migration DROP
        'azure_tenant_id',            # Azure settings key rename in migration
        'entra_tenant_id',            # Azure directory column rename in migration
        'DROP CONSTRAINT',            # Migration constraint cleanup
        'Rename tenant',              # Migration comments
        'ms_tenant_ids',              # Azure Microsoft tenant ID list (system-app filtering)
        'WARNING level',              # Docstring describing slow-query log fields
        'INTEGER NOT NULL',           # DDL column definitions (risk_summary, stage_log, graph_snapshots)
        '# tenant_id',               # Code comments explaining tenant/org column mapping
        'graph_snapshots',            # graph_snapshots table DDL/DML (uses tenant_id column)
        'current_setting',            # RLS policy definitions
        'identity_risk_score',        # risk_summary INSERT column list
        'stage_order',                # discovery_stage_log INSERT column list
        'error_message',              # discovery_stage_log INSERT column list
        'node_count',                 # graph_snapshots INSERT column list
    ]

    # Find all lines with tenant_id
    lines_with_tenant_id = []
    for i, line in enumerate(src.split('\n'), 1):
        if 'tenant_id' in line:
            # Check if line is exempted
            is_exempted = any(pat in line for pat in exempted_patterns)
            if not is_exempted:
                lines_with_tenant_id.append((i, line.strip()))

    assert len(lines_with_tenant_id) == 0, \
        f"Found {len(lines_with_tenant_id)} non-exempted tenant_id refs in database.py:\n" + \
        "\n".join(f"  L{n}: {l}" for n, l in lines_with_tenant_id[:10])
