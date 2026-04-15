"""
FIX1A — Platform Consistency & Data Integrity Stabilization Tests

Tests count reconciliation, endpoint availability, logo upload auth,
snapshot consistency, and connector route uniqueness.
"""
import inspect
import os


# ── STEP 1: Count Reconciliation ────────────────────────────────────────────

def test_dormant_count_uses_stale_and_never_used():
    """Dashboard posture dormant count includes both 'stale' and 'never_used' (via canonical query)."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_dashboard_posture)
    # FIX1B moved inline SQL to canonical metric_queries — now uses get_metric_count_sql('dormant')
    assert "get_metric_count_sql('dormant')" in source
    # Canonical definition must include both stale and never_used
    from app.api.metric_queries import METRIC_DORMANT
    assert "'stale'" in METRIC_DORMANT
    assert "'never_used'" in METRIC_DORMANT


def test_sa_governance_dormant_matches():
    """SA governance dormant uses same definition as dashboard (both via canonical queries)."""
    import app.api.handlers
    posture_src = inspect.getsource(app.api.handlers.get_dashboard_posture)
    sa_src = inspect.getsource(app.api.handlers.get_sa_governance_stats)
    # Dashboard uses canonical metric query
    assert "get_metric_count_sql('dormant')" in posture_src
    # SA governance still uses inline (or canonical) — both share METRIC_DORMANT definition
    assert "IN ('stale', 'never_used')" in sa_src or "get_metric_count_sql('dormant')" in sa_src


# ── STEP 2: Dummy Subscriptions ────────────────────────────────────────────

def test_no_auto_seed_in_create_app():
    """create_app() does not auto-insert dummy subscriptions."""
    import app.main
    source = inspect.getsource(app.main.create_app)
    assert 'seed_cloud_subscriptions' not in source
    assert 'seed_performance' not in source


# ── STEP 3: Connector Routes ───────────────────────────────────────────────

def test_no_duplicate_connector_routes():
    """Only /api/client/connections routes exist — no /api/connectors duplicate."""
    import app.main
    source = inspect.getsource(app.main)
    assert '/api/client/connections' in source
    # No separate /api/connectors route
    assert '"/api/connectors"' not in source


# ── STEP 4: Effective Access (RBAC Hygiene) ─────────────────────────────────

def test_rbac_hygiene_base_endpoint_exists():
    """GET /api/rbac-hygiene base endpoint is registered."""
    import app.main
    source = inspect.getsource(app.main)
    assert '"/api/rbac-hygiene"' in source or "'/api/rbac-hygiene'" in source


def test_rbac_hygiene_combined_handler_exists():
    """get_rbac_hygiene_combined handler returns HygieneData shape."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_rbac_hygiene_combined)
    assert 'overall_score' in source
    assert 'total_findings' in source
    assert 'findings' in source
    assert 'rules' in source
    assert 'tier_distribution' in source


# ── STEP 6: Billing Visibility ──────────────────────────────────────────────

def test_billing_history_endpoint_exists():
    """GET /api/billing/history endpoint is registered."""
    import app.main
    source = inspect.getsource(app.main)
    assert '/api/billing/history' in source


def test_billing_invoice_download_endpoint_exists():
    """GET /api/billing/invoice/<id>/download endpoint is registered."""
    import app.main
    source = inspect.getsource(app.main)
    assert '/api/billing/invoice/' in source
    assert 'download' in source


# ── STEP 7: Logo Upload ────────────────────────────────────────────────────

def test_client_logo_uses_client_role():
    """Client logo route uses @require_role, not @require_portal_role."""
    import app.main
    source = inspect.getsource(app.main)
    # Find the client logo route definition
    idx = source.index('/api/clients/<int:organization_id>/logo")')
    # Look at the 200 chars before and after for the decorator
    context = source[max(0, idx - 200):idx + 200]
    assert "require_role('admin')" in context
    assert 'require_portal_role' not in context


def test_logo_handler_expects_logo_data():
    """Backend logo handler reads logo_data and content_type fields."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.upload_organization_logo)
    assert "logo_data" in source
    assert "content_type" in source


def test_frontend_logo_sends_correct_payload():
    """Frontend GeneralTab sends logo_data + content_type (not raw data URL)."""
    frontend_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'frontend', 'src',
        'components', 'settings', 'GeneralTab.tsx'
    )
    with open(os.path.normpath(frontend_path)) as f:
        source = f.read()
    assert 'logo_data' in source
    assert 'content_type' in source
    # Should NOT send raw { logo: ... } anymore
    assert '{ logo: reader.result }' not in source


# ── STEP 8: Snapshot Consistency ────────────────────────────────────────────

def test_latest_run_ids_used_consistently():
    """_latest_run_ids is used across major endpoint handlers."""
    import app.api.handlers
    # Check key endpoints all call _latest_run_ids
    for fn_name in ['get_stats', 'get_dashboard_posture', 'get_identity_summary',
                     'get_sa_governance_stats']:
        fn = getattr(app.api.handlers, fn_name)
        source = inspect.getsource(fn)
        assert '_latest_run_ids' in source, f'{fn_name} does not use _latest_run_ids'


def test_no_duplicate_snapshot_logic():
    """No ad-hoc 'SELECT MAX(id) FROM discovery_runs' outside _latest_run_ids."""
    import app.api.handlers
    # _latest_run_ids contains MAX(id), but other functions should call it, not replicate it
    source = inspect.getsource(app.api.handlers)
    # Count occurrences of MAX(id) pattern in handlers
    # _latest_run_ids has 2 (connection_id + fallback paths), get_snapshots has 2 (snapshot-specific)
    count = source.count("SELECT MAX(id)")
    assert count <= 5, f'Found {count} MAX(id) queries — snapshot logic may be duplicated'
