"""Phase 3A: Organization Entitlement Engine tests.

Source-inspection + mock-based (no live DB required).
"""

import inspect
import re
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

import pytest


# ── Test 1: Free plan denied paid feature ──────────────────────────────────

def test_trial_org_denied_paid_feature():
    """Free plan org should be denied soar_automation."""
    from app.entitlements.service import is_feature_enabled

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
    from app.entitlements.service import is_feature_enabled

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

    # Simulate 1 active subscription already
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (1,)
    mock_db.conn.cursor.return_value = mock_cursor

    allowed, err_msg = enforce_subscription_limit(mock_db, 1)
    assert allowed is False
    assert 'Free plan' in err_msg


# ── Test 4: Expired trial denial ───────────────────────────────────────────

def test_expired_trial_denial():
    """Trial org with past trial_expires_at should be denied."""
    from app.entitlements.service import is_feature_enabled

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
    from app.entitlements.service import is_feature_enabled

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
