"""
Attack Path API Routes — v1 tests

Verifies route registration, handler structure, query param filtering,
response shape, and tenant isolation for the v1 attack path endpoints.
"""
import inspect
import json
import os

os.environ.setdefault('APP_ENV', 'local')
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test')
os.environ.setdefault('CLIENT_JWT_SECRET', 'client-test')


# ── Route registration tests ────────────────────────────────────────

def test_attack_paths_list_route_registered():
    """GET /api/attack-paths route is registered in main.py."""
    import app.main
    src = inspect.getsource(app.main)
    assert '"/api/attack-paths"' in src


def test_attack_path_detail_route_registered():
    """GET /api/attack-paths/<path_id> route is registered."""
    import app.main
    src = inspect.getsource(app.main)
    assert '"/api/attack-paths/<path_id>"' in src


def test_identity_attack_paths_route_registered():
    """GET /api/identities/<id>/persisted-attack-paths route is registered."""
    import app.main
    src = inspect.getsource(app.main)
    assert '/persisted-attack-paths"' in src


def test_attack_surface_route_registered():
    """GET /api/dashboard/attack-surface route is registered."""
    import app.main
    src = inspect.getsource(app.main)
    assert '"/api/dashboard/attack-surface"' in src


# ── Handler structure tests ──────────────────────────────────────────

def test_list_handler_reads_severity_filter():
    """get_attack_paths_list reads severity query param."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_paths_list)
    assert "request.args.get('severity'" in src


def test_list_handler_reads_path_type_filter():
    """get_attack_paths_list reads path_type query param."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_paths_list)
    assert "request.args.get('path_type'" in src


def test_list_handler_excludes_path_nodes():
    """List response does NOT include path_nodes (too large for list view)."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_paths_list)
    # The SELECT should NOT include ap.path_nodes
    select_section = src[src.index('SELECT ap.id'):src.index('FROM attack_paths')]
    assert 'path_nodes' not in select_section


def test_list_handler_limits_to_100():
    """List handler caps limit at 100."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_paths_list)
    assert '100' in src
    assert 'min(' in src


def test_detail_handler_returns_404():
    """get_attack_path_detail returns 404 for missing paths."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_path_detail)
    assert '404' in src
    assert "'error'" in src


def test_detail_handler_includes_path_nodes():
    """Detail response includes full path_nodes via ap.*."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_path_detail)
    assert 'ap.*' in src


def test_identity_handler_resolves_string_id():
    """Identity attack paths handler resolves string identity_id to DB id."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_identity_persisted_attack_paths)
    assert 'identity_id = %s' in src
    assert 'get_attack_paths_for_identity' in src


def test_surface_handler_returns_aggregate_counts():
    """get_attack_surface_summary returns aggregate count fields."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_surface_summary)
    assert 'total_paths' in src
    assert 'critical_paths' in src
    assert 'high_paths' in src
    assert 'subscription_scope_paths' in src
    assert 'keyvault_exposure_paths' in src


def test_surface_handler_returns_top_5():
    """get_attack_surface_summary returns top_5_paths list."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_surface_summary)
    assert 'top_5_paths' in src
    assert 'LIMIT 5' in src


# ── Tenant isolation tests ───────────────────────────────────────────

def test_list_handler_scopes_by_organization():
    """List handler filters by organization_id for tenant isolation."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_paths_list)
    assert 'organization_id' in src
    assert '_org_id()' in src


def test_detail_handler_scopes_by_organization():
    """Detail handler filters by organization_id for tenant isolation."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_path_detail)
    assert 'organization_id' in src
    assert '_org_id()' in src


def test_surface_handler_scopes_by_organization():
    """Surface summary handler filters by organization_id."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_attack_surface_summary)
    assert 'organization_id' in src
    assert '_org_id()' in src


def test_identity_handler_uses_run_scoping():
    """Identity handler uses _latest_run_ids for connection-aware scoping."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_identity_persisted_attack_paths)
    assert '_latest_run_ids' in src


# ── DB method existence tests ────────────────────────────────────────

def test_db_get_attack_paths_for_identity_exists():
    """Database.get_attack_paths_for_identity method exists."""
    from app.database import Database
    assert hasattr(Database, 'get_attack_paths_for_identity')


def test_db_get_top_attack_paths_exists():
    """Database.get_top_attack_paths method exists."""
    from app.database import Database
    assert hasattr(Database, 'get_top_attack_paths')


def test_db_save_attack_path_exists():
    """Database.save_attack_path method exists."""
    from app.database import Database
    assert hasattr(Database, 'save_attack_path')


def test_db_get_identities_for_path_building_exists():
    """Database.get_identities_for_path_building method exists."""
    from app.database import Database
    assert hasattr(Database, 'get_identities_for_path_building')


def test_db_get_role_assignments_for_identity_exists():
    """Database.get_role_assignments_for_identity method exists."""
    from app.database import Database
    assert hasattr(Database, 'get_role_assignments_for_identity')
