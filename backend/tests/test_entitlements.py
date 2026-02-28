"""Phase 3A + 3A.1: Organization Entitlement Engine tests.

Source-inspection + mock-based (no live DB required).
"""

import inspect
import re
import time
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone, timedelta

import pytest


# ── Test 1: Free plan denied paid feature ──────────────────────────────────

def test_trial_org_denied_paid_feature():
    """Free plan org should be denied soar_automation."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()  # Clear cache

    mock_db = MagicMock()
    # No per-org override
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor
    # Org is on free plan
    mock_db.get_organization_by_id.return_value = {'plan': 'free'}

    allowed, err = is_feature_enabled(mock_db, 1, 'soar_automation')
    assert allowed is False
    assert err is not None
    assert err['upgrade_required'] is True
    assert err['current_plan'] == 'free'


# ── Test 2: Paid plan allowed ──────────────────────────────────────────────

def test_paid_org_allowed():
    """Pro plan org should be allowed soar_automation."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor
    mock_db.get_organization_by_id.return_value = {'plan': 'pro'}

    allowed, err = is_feature_enabled(mock_db, 1, 'soar_automation')
    assert allowed is True
    assert err is None


# ── Test 3: Subscription limit enforcement ─────────────────────────────────

def test_subscription_limit_enforcement():
    """Free plan limited to 1 active subscription."""
    from app.entitlements.service import enforce_subscription_limit

    mock_db = MagicMock()
    mock_db.get_organization_by_id.return_value = {'plan': 'free', 'subscription_limit': None}

    # No counter row → falls back to live COUNT
    # First cursor call returns None (no counter), second returns count of 1
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = [None, (1,)]
    mock_db.conn.cursor.return_value = mock_cursor

    allowed, err_msg = enforce_subscription_limit(mock_db, 1)
    assert allowed is False
    assert 'Free plan' in err_msg


# ── Test 4: Expired trial denial ───────────────────────────────────────────

def test_expired_trial_denial():
    """Trial org with past trial_expires_at should be denied."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor

    past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    mock_db.get_organization_by_id.return_value = {
        'plan': 'trial',
        'trial_expires_at': past_date,
    }

    allowed, err = is_feature_enabled(mock_db, 1, 'soar_automation')
    assert allowed is False
    assert 'trial has expired' in err['error'].lower()


# ── Test 5: Superadmin bypass ──────────────────────────────────────────────

def test_superadmin_bypass():
    """require_entitlement decorator source should contain is_superadmin bypass."""
    from app.entitlements.decorator import require_entitlement

    source = inspect.getsource(require_entitlement)
    assert 'is_superadmin' in source, "Decorator must check is_superadmin for bypass"


# ── Test 6: Per-org override ──────────────────────────────────────────────

def test_per_org_override():
    """Per-org entitlement grant should override plan block."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    # Per-org override: enabled=True, no expiry
    mock_cursor.fetchone.return_value = (True, None)
    mock_db.conn.cursor.return_value = mock_cursor
    # Org is on free plan (would normally block)
    mock_db.get_organization_by_id.return_value = {'plan': 'free'}

    allowed, err = is_feature_enabled(mock_db, 1, 'soar_automation')
    assert allowed is True
    assert err is None


# ── Test 7: Feature registry completeness ──────────────────────────────────

def test_feature_registry_completeness():
    """All FEATURES keys should be non-empty strings with valid plans."""
    from app.entitlements.registry import FEATURES

    assert len(FEATURES) > 0, "FEATURES registry must not be empty"
    for key, defn in FEATURES.items():
        assert isinstance(key, str) and len(key) > 0, f"Key must be non-empty string: {key}"
        assert 'plans' in defn, f"Feature {key} missing 'plans'"
        assert isinstance(defn['plans'], list), f"Feature {key} plans must be a list"
        assert len(defn['plans']) > 0, f"Feature {key} plans must be non-empty"


# ── Test 8: SOAR routes protected ─────────────────────────────────────────

def test_soar_routes_protected():
    """All SOAR write routes in main.py must have @require_feature or @require_entitlement."""
    import os
    main_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'main.py')
    with open(main_path) as f:
        source = f.read()

    # Find all SOAR route definitions (POST/PUT/DELETE)
    soar_route_pattern = r'@app\.(post|put|delete)\(["\']\/api\/soar\/.*?["\']\)'
    routes = re.finditer(soar_route_pattern, source)

    for match in routes:
        # Get context: the decorators between this route and the next def
        start = match.start()
        # Find the def line after this route
        def_match = re.search(r'\n\s+def \w+', source[start:])
        if def_match:
            block = source[start:start + def_match.end()]
            assert 'require_feature' in block or 'require_entitlement' in block, \
                f"SOAR route at {match.group()} missing feature gate"


# ════════════════════════════════════════════════════════════════════════════
# Phase 3A.1 tests
# ════════════════════════════════════════════════════════════════════════════

# ── Test 9: Suspended org blocked globally ─────────────────────────────────

def test_suspended_org_blocked_globally():
    """auth_middleware source must check plan_status for suspended/cancelled."""
    import os
    auth_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'api', 'auth.py')
    with open(auth_path) as f:
        source = f.read()

    assert 'plan_status' in source, "auth_middleware must check plan_status"
    assert "'suspended'" in source or '"suspended"' in source, "Must check for suspended status"
    assert "'cancelled'" in source or '"cancelled"' in source, "Must check for cancelled status"
    assert 'account_blocked' in source, "Must return account_blocked flag"


# ── Test 10: Counter increments on activation ──────────────────────────────

def test_counter_increments_on_activation():
    """track_usage with action='activated' should call _update_counter with delta +1."""
    from app.entitlements.service import track_usage

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_db.conn.cursor.return_value = mock_cursor

    track_usage(mock_db, 42, 'subscription', 'sub-123', 'activated')

    # Should have at least 2 execute calls: INSERT into usage + UPSERT into counters
    calls = mock_cursor.execute.call_args_list
    assert len(calls) >= 2, f"Expected at least 2 execute calls, got {len(calls)}"

    # Second execute should be the counter UPSERT with delta=1
    counter_sql = calls[1][0][0]
    assert 'organization_usage_counters' in counter_sql
    counter_params = calls[1][0][1]
    # Params: (org_id, resource_type, delta, delta)
    assert counter_params[0] == 42  # organization_id
    assert counter_params[1] == 'active_subscriptions'  # resource_type
    assert counter_params[2] == 1   # delta for INSERT
    assert counter_params[3] == 1   # delta for UPDATE


# ── Test 11: Counter decrements on deactivation ───────────────────────────

def test_counter_decrements_on_deactivation():
    """track_usage with action='deactivated' should call _update_counter with delta -1."""
    from app.entitlements.service import track_usage

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_db.conn.cursor.return_value = mock_cursor

    track_usage(mock_db, 42, 'subscription', 'sub-123', 'deactivated')

    calls = mock_cursor.execute.call_args_list
    assert len(calls) >= 2

    counter_params = calls[1][0][1]
    assert counter_params[2] == -1  # delta for INSERT
    assert counter_params[3] == -1  # delta for UPDATE


# ── Test 12: allow_overage allows but logs ─────────────────────────────────

def test_allow_overage_allows_but_logs():
    """enforcement_mode='allow_overage' should allow blocked features."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor
    mock_db.get_organization_by_id.return_value = {
        'plan': 'free',
        'enforcement_mode': 'allow_overage',
    }

    allowed, err = is_feature_enabled(mock_db, 99, 'soar_automation')
    assert allowed is True
    assert err is None


# ── Test 13: monitor_only allows without block ─────────────────────────────

def test_monitor_only_allows_without_block():
    """enforcement_mode='monitor_only' should allow blocked features."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor
    mock_db.get_organization_by_id.return_value = {
        'plan': 'free',
        'enforcement_mode': 'monitor_only',
    }

    allowed, err = is_feature_enabled(mock_db, 98, 'soar_automation')
    assert allowed is True
    assert err is None


# ── Test 14: Cache hit avoids duplicate DB query ──────────────────────────

def test_cache_hit_avoids_duplicate_db_query():
    """Second call to is_feature_enabled should use cache, not hit DB again."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor
    mock_db.get_organization_by_id.return_value = {'plan': 'pro'}

    # First call — hits DB
    allowed1, _ = is_feature_enabled(mock_db, 200, 'api_keys')
    assert allowed1 is True
    first_call_count = mock_db.conn.cursor.call_count

    # Second call — should use cache, no new cursor calls
    allowed2, _ = is_feature_enabled(mock_db, 200, 'api_keys')
    assert allowed2 is True
    assert mock_db.conn.cursor.call_count == first_call_count, \
        "Cache hit should not create new DB cursor"


# ── Test 15: Cache invalidation works ─────────────────────────────────────

def test_cache_invalidation_works():
    """After invalidation, is_feature_enabled should hit DB again."""
    from app.entitlements.service import is_feature_enabled, invalidate_entitlement_cache
    invalidate_entitlement_cache()

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None
    mock_db.conn.cursor.return_value = mock_cursor
    mock_db.get_organization_by_id.return_value = {'plan': 'pro'}

    # First call — hits DB
    is_feature_enabled(mock_db, 201, 'sso')
    first_call_count = mock_db.conn.cursor.call_count

    # Invalidate
    invalidate_entitlement_cache(org_id=201)

    # Third call — should hit DB again
    is_feature_enabled(mock_db, 201, 'sso')
    assert mock_db.conn.cursor.call_count > first_call_count, \
        "After invalidation, DB should be queried again"


# ── Test 16: Superadmin bypass logging ────────────────────────────────────

def test_superadmin_bypass_logging():
    """require_entitlement decorator should log superadmin bypass events."""
    from app.entitlements.decorator import require_entitlement

    source = inspect.getsource(require_entitlement)
    assert 'entitlement_bypass' in source, "Decorator must log superadmin bypass with 'entitlement_bypass'"
    assert 'logger.info' in source or 'logger.warning' in source, "Must use logger for bypass audit"
