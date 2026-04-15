"""
FIX1B — Metric Source of Truth Refactor Tests

Enforces:
1. All metrics have canonical definitions in metric_queries.py
2. Dashboard counts use canonical queries
3. Drill-down filters use canonical queries
4. Snapshot selection is centralized via _latest_run_ids
5. No independent metric WHERE clauses exist
"""
import inspect
import re


# ── STEP 1: Metric Registry Completeness ────────────────────────────────────

def test_metric_registry_has_all_metrics():
    """All key metrics are registered in METRIC_REGISTRY."""
    from app.api.metric_queries import METRIC_REGISTRY

    required = [
        'dormant', 'dormant_nhi', 'dormant_human',
        'privileged', 'high_risk', 'critical',
        'over_permissioned', 'unowned_nhi',
        'credential_expired', 'credential_expiring',
        'credential_healthy', 'no_credentials',
        'ghost',
    ]
    for metric in required:
        assert metric in METRIC_REGISTRY, f"Missing metric: {metric}"


def test_metric_count_sql_returns_valid_sql():
    """get_metric_count_sql returns valid SELECT COUNT SQL."""
    from app.api.metric_queries import get_metric_count_sql

    for metric_name in ['dormant', 'credential_expired', 'unowned_nhi', 'ghost']:
        sql = get_metric_count_sql(metric_name)
        assert 'SELECT COUNT(*)' in sql
        assert 'FROM identities i' in sql
        assert 'discovery_run_id' in sql
        assert 'is_microsoft_system' in sql


def test_metric_count_sql_rejects_unknown():
    """get_metric_count_sql raises ValueError for unknown metric."""
    from app.api.metric_queries import get_metric_count_sql
    import pytest
    with pytest.raises(ValueError, match='Unknown metric'):
        get_metric_count_sql('nonexistent_metric')


# ── STEP 2: Dashboard Uses Canonical Queries ────────────────────────────────

def test_dashboard_posture_uses_canonical_queries():
    """get_dashboard_posture uses get_metric_count_sql for all counts."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_dashboard_posture)
    assert 'get_metric_count_sql' in source
    # Should use canonical queries for these metrics:
    assert "get_metric_count_sql('credential_expired')" in source
    assert "get_metric_count_sql('credential_expiring')" in source
    assert "get_metric_count_sql('credential_healthy')" in source
    assert "get_metric_count_sql('no_credentials')" in source
    assert "get_metric_count_sql('dormant')" in source
    assert "get_metric_count_sql('unowned_nhi')" in source


def test_no_inline_dormant_sql_in_posture():
    """get_dashboard_posture has no inline dormant SQL — uses canonical only."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_dashboard_posture)
    # Should NOT have the old inline pattern
    assert "activity_status = 'stale'" not in source
    assert "activity_status IN ('stale'" not in source


def test_no_inline_credential_sql_in_posture():
    """get_dashboard_posture has no inline credential expiration SQL."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_dashboard_posture)
    # Should NOT have inline credential_expiration filter
    assert 'credential_expiration < NOW()' not in source
    assert 'credential_expiration >= NOW()' not in source


# ── STEP 2b: Drill-Down Filters Use Canonical Queries ───────────────────────

def test_identities_has_credential_status_filter():
    """GET /api/identities supports credential_status filter."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_identities)
    assert 'credential_status' in source
    assert 'get_metric_where' in source


def test_identities_has_owner_filter():
    """GET /api/identities supports has_owner filter."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_identities)
    assert 'has_owner' in source
    assert "get_metric_where('unowned_nhi')" in source


def test_identities_has_metric_filter():
    """GET /api/identities supports direct metric filter."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_identities)
    assert "metric_filter" in source
    assert "METRIC_REGISTRY" in source


def test_canonical_definitions_match():
    """Canonical metric SQL for dormant matches between dashboard and drill-down."""
    from app.api.metric_queries import METRIC_DORMANT
    # The canonical definition must include both stale and never_used
    assert "'stale'" in METRIC_DORMANT
    assert "'never_used'" in METRIC_DORMANT


# ── STEP 3: Snapshot Selection Centralization ───────────────────────────────

def test_get_latest_snapshot_ids_exists():
    """Canonical get_latest_snapshot_ids function exists in metric_queries."""
    from app.api.metric_queries import get_latest_snapshot_ids
    assert callable(get_latest_snapshot_ids)


def test_get_latest_snapshot_ids_delegates():
    """get_latest_snapshot_ids delegates to _latest_run_ids."""
    from app.api.metric_queries import get_latest_snapshot_ids
    source = inspect.getsource(get_latest_snapshot_ids)
    assert '_latest_run_ids' in source


def test_dashboard_posture_uses_latest_run_ids():
    """get_dashboard_posture uses _latest_run_ids for snapshot selection."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_dashboard_posture)
    assert '_latest_run_ids' in source


def test_stats_uses_latest_run_ids():
    """get_stats uses _latest_run_ids for snapshot selection."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_stats)
    assert '_latest_run_ids' in source


def test_identities_uses_latest_run_ids():
    """get_identities uses _latest_run_ids for snapshot selection."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_identities)
    assert '_latest_run_ids' in source


def test_identity_summary_uses_latest_run_ids():
    """get_identity_summary uses _latest_run_ids."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_identity_summary)
    assert '_latest_run_ids' in source


def test_attack_surface_uses_latest_run_ids():
    """get_attack_surface_score uses _latest_run_ids."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_attack_surface_score)
    assert '_latest_run_ids' in source


def test_spn_stats_uses_latest_run_ids():
    """get_spn_stats uses _latest_run_ids."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_spn_stats)
    assert '_latest_run_ids' in source


def test_sa_governance_uses_latest_run_ids():
    """get_sa_governance_stats uses _latest_run_ids."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_sa_governance_stats)
    assert '_latest_run_ids' in source


# ── STEP 4: No Raw Summary Table Reads ──────────────────────────────────────

def test_stats_does_not_use_discovery_runs_columns_for_counts():
    """get_stats computes counts live from identities, not from precomputed discovery_runs columns."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_stats)
    # Must use COUNT/SUM on identities table, not read total_identities from discovery_runs
    assert 'FROM identities i' in source


def test_posture_does_not_read_precomputed():
    """get_dashboard_posture does not read precomputed columns from discovery_runs."""
    import app.api.handlers
    source = inspect.getsource(app.api.handlers.get_dashboard_posture)
    # Should use COUNT from identities, not discovery_runs.total_identities
    lines = source.split('\n')
    # Check it queries identities table for counts
    assert any('FROM identities i' in line for line in lines)


# ── STEP 5: Hard Parity Tests ──────────────────────────────────────────────
# These verify that dashboard and drill-down share the SAME WHERE clauses
# by checking source code references to canonical metric_queries.

def test_parity_dormant_dashboard_vs_drilldown():
    """Dashboard dormant count and drill-down use same canonical definition."""
    from app.api.metric_queries import METRIC_DORMANT
    import app.api.handlers

    # Dashboard posture uses get_metric_count_sql('dormant') which uses METRIC_DORMANT
    posture_src = inspect.getsource(app.api.handlers.get_dashboard_posture)
    assert "get_metric_count_sql('dormant')" in posture_src

    # Drill-down: identities endpoint can use metric=dormant or activity_status=stale,never_used
    identities_src = inspect.getsource(app.api.handlers.get_identities)
    assert 'metric_filter' in identities_src  # Supports ?metric=dormant
    assert 'activity_status' in identities_src  # Also supports direct filter


def test_parity_credential_dashboard_vs_drilldown():
    """Dashboard credential counts and drill-down use same canonical definition."""
    import app.api.handlers

    posture_src = inspect.getsource(app.api.handlers.get_dashboard_posture)
    identities_src = inspect.getsource(app.api.handlers.get_identities)

    # Dashboard uses canonical queries
    assert "get_metric_count_sql('credential_expired')" in posture_src
    assert "get_metric_count_sql('credential_expiring')" in posture_src

    # Drill-down supports credential_status filter
    assert 'credential_status' in identities_src
    assert 'get_metric_where' in identities_src


def test_parity_unowned_dashboard_vs_drilldown():
    """Dashboard unowned count and drill-down use same canonical definition."""
    import app.api.handlers

    posture_src = inspect.getsource(app.api.handlers.get_dashboard_posture)
    identities_src = inspect.getsource(app.api.handlers.get_identities)

    assert "get_metric_count_sql('unowned_nhi')" in posture_src
    assert "get_metric_where('unowned_nhi')" in identities_src


# ── STEP 6: Snapshot Lock Test ──────────────────────────────────────────────

def test_no_manual_snapshot_in_metric_endpoints():
    """No metric endpoint computes snapshot via raw MAX(id) — all use _latest_run_ids."""
    import app.api.handlers

    # These dashboard/metric functions must NOT contain SELECT MAX(id) FROM discovery_runs
    metric_functions = [
        'get_dashboard_posture',
        'get_identity_summary',
        'get_trust_dashboard',
        'get_credential_intelligence',
        'get_sa_governance_stats',
        'get_spn_stats',
    ]
    for fn_name in metric_functions:
        fn = getattr(app.api.handlers, fn_name)
        source = inspect.getsource(fn)
        assert 'SELECT MAX(id)' not in source, \
            f'{fn_name} computes snapshot manually — must use _latest_run_ids'


def test_all_metric_endpoints_call_latest_run_ids():
    """All major metric endpoints call _latest_run_ids."""
    import app.api.handlers

    endpoints = [
        'get_stats', 'get_dashboard_posture', 'get_identity_summary',
        'get_attack_surface_score', 'get_trust_dashboard',
        'get_credential_intelligence', 'get_sa_governance_stats',
        'get_spn_stats', 'get_identities',
    ]
    for fn_name in endpoints:
        fn = getattr(app.api.handlers, fn_name)
        source = inspect.getsource(fn)
        assert '_latest_run_ids' in source, \
            f'{fn_name} does not call _latest_run_ids — snapshot selection not centralized'


# ── Metric WHERE clause consistency ─────────────────────────────────────────

def test_canonical_dormant_is_consistent():
    """Canonical METRIC_DORMANT includes stale AND never_used."""
    from app.api.metric_queries import METRIC_DORMANT
    assert 'stale' in METRIC_DORMANT
    assert 'never_used' in METRIC_DORMANT


def test_canonical_unowned_excludes_humans():
    """Canonical METRIC_UNOWNED_NHI excludes human_user and guest."""
    from app.api.metric_queries import METRIC_UNOWNED_NHI
    assert 'human_user' in METRIC_UNOWNED_NHI
    assert 'guest' in METRIC_UNOWNED_NHI
    assert 'owner_count' in METRIC_UNOWNED_NHI


def test_canonical_ghost_requires_roles():
    """Canonical METRIC_GHOST checks disabled AND has active role assignments."""
    from app.api.metric_queries import METRIC_GHOST
    assert 'enabled = FALSE' in METRIC_GHOST
    assert 'role_assignments' in METRIC_GHOST
    assert 'entra_role_assignments' in METRIC_GHOST


def test_base_where_filters_microsoft():
    """BASE_IDENTITY_WHERE excludes Microsoft first-party."""
    from app.api.metric_queries import BASE_IDENTITY_WHERE
    assert 'is_microsoft_system' in BASE_IDENTITY_WHERE
    assert 'discovery_run_id' in BASE_IDENTITY_WHERE
