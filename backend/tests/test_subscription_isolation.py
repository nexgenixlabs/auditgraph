"""
Subscription Isolation Tests

Source-inspection tests that verify all identity-fetching endpoints enforce the
activated-subscription filter (ACTIVATED_SUB_FILTER_SQL / _apply_sub_filter / _monitored_sub_ids).

This ensures identities from discovered-only (non-monitored) subscriptions are never
leaked into views, maintaining billing and data-boundary integrity.
"""
import os
import re
import inspect

# Ensure dev mode + test keys before importing app modules
os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-key-sub')
os.environ.setdefault('TENANT_JWT_SECRET', 'tenant-test-key-sub')


# ── Test 1: Constant exists with correct structure ──

def test_activated_sub_filter_sql_constant():
    """ACTIVATED_SUB_FILTER_SQL must exist and reference identity_subscription_access."""
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    assert 'identity_subscription_access' in ACTIVATED_SUB_FILTER_SQL
    assert 'isa_m.subscription_id = ANY' in ACTIVATED_SUB_FILTER_SQL
    # Must include Entra-only fallback (NOT EXISTS branch)
    assert 'NOT EXISTS' in ACTIVATED_SUB_FILTER_SQL


# ── Test 2: _monitored_sub_ids helper exists ──

def test_monitored_sub_ids_helper_exists():
    """_monitored_sub_ids helper must exist and query cloud_subscriptions."""
    from app.api import handlers
    assert hasattr(handlers, '_monitored_sub_ids'), \
        "_monitored_sub_ids helper is missing from handlers"
    src = inspect.getsource(handlers._monitored_sub_ids)
    assert 'cloud_subscriptions' in src
    assert 'monitored = true' in src
    assert 'deleted = false' in src


# ── Test 3: _apply_sub_filter helper exists ──

def test_apply_sub_filter_helper_exists():
    """_apply_sub_filter helper must exist and use _monitored_sub_ids."""
    from app.api import handlers
    assert hasattr(handlers, '_apply_sub_filter'), \
        "_apply_sub_filter helper is missing from handlers"
    src = inspect.getsource(handlers._apply_sub_filter)
    assert '_monitored_sub_ids' in src
    assert 'ACTIVATED_SUB_FILTER_SQL' in src


# ── Test 4: All identity-fetching endpoints enforce the filter ──

def test_identity_queries_enforce_subscription_filter():
    """Every identity-fetching endpoint must include activated-subscription filtering."""
    from app.api import handlers

    endpoints = [
        'get_identities',
        'get_identity_details',
        'get_risks',
        'get_stats',
        'get_identity_summary',
        'query_identities',
        'get_identity_graph_data',
        'get_identity_timeline',
        'get_identity_attack_paths',
        'get_spn_stats',
        'get_spn_list',
        'get_spn_detail',
    ]
    for fn_name in endpoints:
        fn = getattr(handlers, fn_name)
        fn_src = inspect.getsource(fn)
        has_filter = (
            '_apply_sub_filter' in fn_src
            or '_monitored_sub_ids' in fn_src
            or 'ACTIVATED_SUB_FILTER_SQL' in fn_src
            or 'sub_filter_sql' in fn_src
        )
        assert has_filter, \
            f"{fn_name}() does NOT enforce activated-subscription filtering"


# ── Test 5: Old opt-in activated_only filter removed from get_identities ──

def test_activated_only_opt_in_removed():
    """get_identities() should no longer use the old opt-in activated_only query param."""
    from app.api import handlers
    fn_src = inspect.getsource(handlers.get_identities)
    assert 'activated_only' not in fn_src, \
        "get_identities() still has the old opt-in activated_only filter — it should be always-on via _apply_sub_filter"


# ── Test 6: Filter preserves Entra-only identities (NOT EXISTS branch) ──

def test_filter_sql_allows_entra_only():
    """ACTIVATED_SUB_FILTER_SQL must include a NOT EXISTS branch for Entra-only identities."""
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    assert 'EXISTS' in ACTIVATED_SUB_FILTER_SQL
    lines = ACTIVATED_SUB_FILTER_SQL.strip().split('\n')
    exists_count = sum(1 for line in lines if 'EXISTS' in line)
    assert exists_count >= 2, \
        "Filter must have both EXISTS (monitored) and NOT EXISTS (Entra-only) branches"


# ── Test 7: Three-way OR filter logic ──

def test_filter_has_three_way_or_logic():
    """ACTIVATED_SUB_FILTER_SQL must have three OR branches:
    (A) EXISTS in monitored subs, (B) NOT EXISTS in org subs (Entra-only),
    (C) managed identity associated_subscription_id path.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL

    # Case A: EXISTS with monitored sub list
    assert 'isa_m.subscription_id = ANY' in sql, "Missing Case A: EXISTS in monitored subs"

    # Case B: NOT EXISTS joining to cloud_subscriptions (org-scoped, not bare NOT EXISTS)
    assert 'cloud_subscriptions' in sql, \
        "Case B must JOIN to cloud_subscriptions to scope by org — bare NOT EXISTS drops identities in non-monitored subs"
    assert 'cs_n.organization_id' in sql, \
        "Case B must filter cloud_subscriptions by organization_id"

    # Case C: managed identity fallback via associated_subscription_id
    assert 'associated_subscription_id' in sql, \
        "Missing Case C: managed identity associated_subscription_id fallback"


# ── Test 8: NOT EXISTS branch scopes to org's discovered subs ──

def test_not_exists_scoped_to_org():
    """The NOT EXISTS (Entra-only) branch must JOIN to cloud_subscriptions filtered
    by organization_id — NOT a bare 'NOT EXISTS (isa)' which incorrectly drops
    identities that have subscription access only in non-monitored subs.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL

    # Extract the NOT EXISTS clause — it must reference cloud_subscriptions
    not_exists_idx = sql.index('NOT EXISTS')
    after_not_exists = sql[not_exists_idx:]
    # The NOT EXISTS subquery must join to cloud_subscriptions
    assert 'cloud_subscriptions' in after_not_exists, \
        "NOT EXISTS must JOIN cloud_subscriptions, not just check identity_subscription_access alone"
    assert 'organization_id' in after_not_exists, \
        "NOT EXISTS must scope cloud_subscriptions to organization_id"
    assert 'deleted = false' in after_not_exists, \
        "NOT EXISTS should exclude soft-deleted cloud_subscriptions"


# ── Test 9: _apply_sub_filter passes 3 params (mon_subs, org_id, mon_subs) ──

def test_apply_sub_filter_passes_three_params():
    """_apply_sub_filter must extend params with [mon_subs, org_id, mon_subs]."""
    from app.api import handlers
    src = inspect.getsource(handlers._apply_sub_filter)
    # Must use extend (not append) to add multiple params
    assert 'params.extend' in src, \
        "_apply_sub_filter must use params.extend to pass 3 params for the 3-way OR filter"
    # Should NOT use params.append(mon_subs) — that only passes 1 param
    assert 'params.append(mon_subs)' not in src, \
        "_apply_sub_filter must not use append(mon_subs) — the filter needs 3 params"


# ── Test 10: Simulated filter logic — identity with NO role assignments is included ──

def test_entra_only_identity_included():
    """An identity with zero entries in identity_subscription_access must pass the
    filter (Entra-only path, Case B). The NOT EXISTS subquery finds no rows in
    isa JOIN cloud_subscriptions, so NOT EXISTS evaluates to TRUE.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL

    # The filter has 3 OR branches. An identity with zero isa entries means:
    # - Case A (EXISTS isa with monitored sub): FALSE (no isa rows)
    # - Case B (NOT EXISTS isa JOIN cloud_subs): TRUE (no isa rows to join)
    # - Case C (associated_subscription_id): FALSE if null
    # Result: TRUE → identity included ✓
    sql = ACTIVATED_SUB_FILTER_SQL
    assert 'OR NOT EXISTS' in sql.replace('\n', ' ').replace('  ', ' '), \
        "Filter must include OR NOT EXISTS branch for Entra-only identities"


# ── Test 11: Simulated filter logic — identity with roles ONLY in non-monitored subs ──

def test_identity_only_in_non_monitored_excluded():
    """An identity whose only subscription access is to non-monitored (but discovered)
    subs SHOULD be excluded. The filter logic:
    - Case A: EXISTS(isa where sub in monitored) → FALSE
    - Case B: NOT EXISTS(isa JOIN cloud_subs where org=X) → FALSE (has isa rows that join to org's cloud_subs)
    - Case C: associated_subscription_id in monitored → FALSE (null or not monitored)
    → All three FALSE → excluded ✓
    """
    # This is a logic verification test — the SQL structure enforces this behavior
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL

    # Case B's JOIN to cloud_subscriptions means isa entries for org's subs
    # (including non-monitored) will make NOT EXISTS false, correctly excluding
    # identities that belong exclusively to non-monitored discovered subs.
    assert 'JOIN cloud_subscriptions' in sql, \
        "NOT EXISTS must JOIN cloud_subscriptions to distinguish org-scoped from Entra-only"


# ── Test 12: Simulated filter logic — identity with roles in monitored sub is included ──

def test_identity_in_monitored_sub_included():
    """An identity with at least one isa entry in a monitored sub passes via Case A.
    This is the primary path — EXISTS(isa where sub = ANY(mon_subs)) → TRUE.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    assert 'isa_m.subscription_id = ANY(%s)' in ACTIVATED_SUB_FILTER_SQL, \
        "Case A must check isa.subscription_id = ANY(monitored_sub_ids)"


# ── Test 13: Managed identity path (Case C) via associated_subscription_id ──

def test_managed_identity_path_included():
    """A managed identity whose associated_subscription_id matches a monitored
    sub must pass the filter via Case C, even if it has no isa entries.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL
    # Case C: i.associated_subscription_id = ANY(mon_subs)
    assert 'associated_subscription_id IS NOT NULL' in sql, \
        "Case C must guard with IS NOT NULL"
    assert 'associated_subscription_id = ANY(%s)' in sql, \
        "Case C must check associated_subscription_id against monitored sub list"


# ── Test 14: Filter param count matches SQL placeholders ──

def test_filter_param_count():
    """ACTIVATED_SUB_FILTER_SQL must have exactly 3 %s placeholders
    (mon_subs, org_id, mon_subs) to match _apply_sub_filter's extend call.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    placeholder_count = ACTIVATED_SUB_FILTER_SQL.count('%s')
    assert placeholder_count == 3, \
        f"Expected 3 %%s placeholders in filter, got {placeholder_count}"
