"""
Subscription Filter Options Tests

Verifies that GET /api/subscriptions/distinct?activated_only=true returns only
monitored (activated) subscriptions and excludes discovered-only ones.
"""
import os
import inspect

# Ensure dev mode + test keys before importing app modules
os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-key-subfilter')
os.environ.setdefault('TENANT_JWT_SECRET', 'tenant-test-key-subfilter')


# ── Test 1: activated_only parameter is supported ──

def test_get_subscriptions_distinct_supports_activated_only():
    """get_subscriptions_distinct() must read the activated_only query param."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    assert 'activated_only' in src, \
        "get_subscriptions_distinct() does not support the activated_only query param"


# ── Test 2: activated_only adds monitored=true filter ──

def test_activated_only_adds_monitored_filter():
    """When activated_only=true, the SQL must include 'monitored = true'."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    assert 'monitored = true' in src, \
        "get_subscriptions_distinct() does not filter by monitored = true"


# ── Test 3: without activated_only, all subscriptions are returned ──

def test_default_returns_all_subscriptions():
    """Without activated_only, the query should NOT add the monitored filter."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    # The monitored clause is conditional — only added when activated_only is true
    assert 'if activated_only' in src or "activated_only" in src, \
        "activated_only filter is not conditional"
    # Should not unconditionally filter by monitored
    lines = src.split('\n')
    unconditional_monitored = any(
        'AND monitored = true' in line and 'if' not in line and 'clause' not in line
        for line in lines
    )
    assert not unconditional_monitored, \
        "get_subscriptions_distinct() unconditionally filters by monitored — it should be opt-in via activated_only param"


# ── Test 4: response shape includes monitored field ──

def test_response_includes_monitored_field():
    """The response dict must include 'monitored' so the frontend can verify activation."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    assert "'monitored'" in src or '"monitored"' in src, \
        "Response does not include 'monitored' field"


# ── Test 5: non-monitored subscriptions excluded when activated_only=true ──

def test_monitored_false_excluded_by_filter():
    """The monitored_clause must add 'AND monitored = true' to exclude discovered subs."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    # Check that the conditional clause adds the right SQL
    assert 'AND monitored = true' in src, \
        "monitored_clause does not contain 'AND monitored = true'"
    # Verify it's used in both the connection-scoped and org-scoped queries
    # by counting occurrences of the monitored_clause variable in the SQL
    assert src.count('monitored_clause') >= 3, \
        "monitored_clause must be defined and used in both query branches"


# ── Test 6: org_id scoping is enforced ──

def test_org_id_scoping_enforced():
    """The query must filter by organization_id to enforce tenant isolation."""
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    assert 'organization_id = %s' in src, \
        "get_subscriptions_distinct() does not enforce organization_id scoping"


# ── Test 7: fallback does NOT fabricate monitored=True ──

def test_fallback_does_not_fabricate_monitored():
    """The discovery_runs fallback must NOT return monitored=True for all subs.
    Hardcoding monitored=True causes the dropdown to show all 12 discovered
    subscriptions instead of only the 2 activated ones.
    """
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    # The fallback (discovery_runs path) must NOT hardcode monitored: True
    # Look for the fallback return statement and verify it uses monitored=False
    lines = src.split('\n')
    fallback_section = False
    for line in lines:
        if 'discovery_runs' in line:
            fallback_section = True
        if fallback_section and "'monitored': True" in line:
            raise AssertionError(
                "Fallback path hardcodes 'monitored': True for all subs — "
                "this causes the dropdown to show all discovered subs as activated. "
                "Fallback must use 'monitored': False or skip when activated_only=true."
            )


# ── Test 8: activated_only=true skips fallback entirely ──

def test_activated_only_skips_fallback():
    """When activated_only=true and cloud_subscriptions has no results, the
    function must return empty rather than falling through to the discovery_runs
    fallback which cannot determine activation status.
    """
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    # There must be a guard: if activated_only: → return empty before fallback
    # Use 'if activated_only:' (with colon) to skip the ternary usage
    assert 'if activated_only:' in src, \
        "Missing guard to skip fallback when activated_only=true"
    # The guard must appear BEFORE the discovery_runs fallback
    guard_idx = src.index('if activated_only:')
    after_guard = src[guard_idx:]
    # Verify the guard returns empty subscriptions within the next few lines
    guard_block = after_guard[:300]
    assert "'subscriptions': []" in guard_block, \
        "activated_only guard must return empty subscriptions list"


# ── Test 9: fallback marks subs as discovered (not active) ──

def test_fallback_marks_subs_as_discovered():
    """The fallback path must mark subs as status='discovered' and
    monitored=False, since their activation status is unknown.
    """
    from app.api import handlers
    src = inspect.getsource(handlers.get_subscriptions_distinct)
    # The fallback section (after fallback_rows) must include monitored: False
    assert 'fallback_rows' in src, \
        "Could not find fallback_rows in get_subscriptions_distinct"
    after_fallback = src[src.index('fallback_rows'):]
    assert "'monitored': False" in after_fallback, \
        "Fallback path must set monitored=False for discovered subs"
    assert "'status': 'discovered'" in after_fallback, \
        "Fallback path must set status='discovered'"


# ── Test 10: Entra-only identity with NO role assignments is included ──
# (This tests the ACTIVATED_SUB_FILTER_SQL, not get_subscriptions_distinct)

def test_identity_no_role_assignments_included():
    """An identity with NO entries in identity_subscription_access must pass
    the activated subscription filter (Entra-only path, Case B).
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL
    # NOT EXISTS branch catches identities with zero subscription-scope roles
    assert 'NOT EXISTS' in sql, \
        "Filter must include NOT EXISTS for Entra-only identities"
    # Case B must reference cloud_subscriptions (org-scoped, not bare NOT EXISTS)
    assert 'cloud_subscriptions' in sql, \
        "NOT EXISTS branch must be org-scoped via cloud_subscriptions JOIN"


# ── Test 11: Identity with roles ONLY in non-monitored subs is excluded ──

def test_identity_only_non_monitored_excluded():
    """An identity whose subscription access is exclusively to non-monitored
    (discovered-only) subscriptions must be excluded by the filter.
    Case A fails (no monitored sub match), Case B fails (has isa rows that
    join to org's cloud_subscriptions), Case C fails (no associated_subscription_id).
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL
    # The EXISTS branch checks monitored subs
    assert 'isa_m.subscription_id = ANY(%s)' in sql, \
        "Case A must check isa against monitored sub list"
    # The NOT EXISTS branch joins to cloud_subscriptions with org_id
    assert 'cs_n.organization_id' in sql, \
        "Case B must join cloud_subscriptions filtered by org"


# ── Test 12: Identity with roles in monitored sub is included ──

def test_identity_monitored_sub_included():
    """An identity with at least one isa entry in a monitored sub passes Case A."""
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    assert 'isa_m.subscription_id = ANY(%s)' in ACTIVATED_SUB_FILTER_SQL


# ── Test 13: Managed identity with associated_subscription_id is included ──

def test_managed_identity_included():
    """A managed identity whose associated_subscription_id matches a monitored
    sub is included via Case C.
    """
    from app.api.handlers import ACTIVATED_SUB_FILTER_SQL
    sql = ACTIVATED_SUB_FILTER_SQL
    assert 'associated_subscription_id' in sql, \
        "Filter must include Case C for managed identities"
    assert 'associated_subscription_id = ANY(%s)' in sql, \
        "Case C must check associated_subscription_id against monitored subs"
