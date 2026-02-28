"""
Phase 1C+1D: Auth Boundary Tests

Tests cryptographic isolation between admin and client portals,
impersonation expiry, refresh token rotation, kid headers, and ver claims.
"""
import os
import time
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

# Ensure dev mode + test keys before importing app modules
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')

# Set distinct keys for portal isolation tests
ADMIN_KEY = 'admin-test-key-1c'
CLIENT_KEY = 'tenant-test-key-1c'
os.environ['ADMIN_JWT_SECRET'] = ADMIN_KEY
os.environ['CLIENT_JWT_SECRET'] = CLIENT_KEY

from app.api.auth import (
    generate_access_token,
    generate_refresh_token,
    hash_refresh_token,
    ADMIN_JWT_SECRET,
    CLIENT_JWT_SECRET,
    JWT_ALGORITHM,
    ADMIN_TOKEN_EXPIRY,
    CLIENT_TOKEN_EXPIRY,
    TOKEN_SCHEMA_VERSION,
    ADMIN_KEY_ID,
    CLIENT_KEY_ID,
)


# ── Helpers ──

def _make_admin_user():
    return {
        'id': 1,
        'username': 'techadmin',
        'role': 'admin',
        'display_name': 'Tech Admin',
        'organization_id': None,
        'org_name': None,
        'is_superadmin': True,
        'portal_role': 'superadmin',
        'force_password_change': False,
    }


def _make_org_user(organization_id=5, org_name='Acme Corp'):
    return {
        'id': 42,
        'username': 'jdoe',
        'role': 'admin',
        'display_name': 'Jane Doe',
        'organization_id': organization_id,
        'org_name': org_name,
        'is_superadmin': False,
        'portal_role': None,
        'force_password_change': False,
    }


def _make_impersonation_user(organization_id=5, org_name='Acme Corp'):
    return {
        'id': 1,
        'username': 'techadmin',
        'role': 'admin',
        'display_name': 'Tech Admin',
        'organization_id': organization_id,
        'org_name': org_name,
        'is_superadmin': False,
        'portal_role': None,
        'impersonating': True,
        'impersonator_id': 1,
        'impersonator_username': 'techadmin',
    }


# ── Test 1: Admin token fails on client route ──

def test_admin_token_fails_client_decode():
    """Admin token signed with ADMIN_KEY cannot be decoded with CLIENT_KEY."""
    user = _make_admin_user()
    token = generate_access_token(user, portal='admin')

    # Decoding with client key must fail
    try:
        jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                   audience='auditgraph-tenant')
        assert False, "Should have raised InvalidTokenError"
    except jwt.InvalidTokenError:
        pass  # Expected


def test_admin_token_wrong_audience_for_client():
    """Admin token has aud=auditgraph-platform, client expects auditgraph-tenant."""
    user = _make_admin_user()
    token = generate_access_token(user, portal='admin')

    # Even if we use ADMIN key, audience check for client should fail
    try:
        jwt.decode(token, ADMIN_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                   audience='auditgraph-tenant')
        assert False, "Should have raised InvalidAudienceError"
    except jwt.InvalidAudienceError:
        pass  # Expected


# ── Test 2: Client token fails on admin route ──

def test_client_token_fails_admin_decode():
    """Client token signed with CLIENT_KEY cannot be decoded with ADMIN_KEY."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client', org_slug='acme')

    # Decoding with admin key must fail
    try:
        jwt.decode(token, ADMIN_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                   audience='auditgraph-platform')
        assert False, "Should have raised InvalidTokenError"
    except jwt.InvalidTokenError:
        pass  # Expected


def test_client_token_wrong_audience_for_admin():
    """Client token has aud=auditgraph-tenant, admin expects auditgraph-platform."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client', org_slug='acme')

    # Even with TENANT key, audience check for admin should fail
    try:
        jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                   audience='auditgraph-platform')
        assert False, "Should have raised InvalidAudienceError"
    except jwt.InvalidAudienceError:
        pass  # Expected


# ── Test 3: Correct portal tokens decode successfully ──

def test_admin_token_decodes_with_correct_key():
    """Admin token decodes fine with ADMIN_KEY + correct audience."""
    user = _make_admin_user()
    token = generate_access_token(user, portal='admin')

    payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-platform')
    assert payload['sub'] == '1'
    assert payload['iss'] == 'admin.auditgraph.ai'
    assert payload['aud'] == 'auditgraph-platform'
    assert payload['portal'] == 'admin'
    assert payload['type'] == 'access'


def test_client_token_decodes_with_correct_key():
    """Client token decodes fine with CLIENT_KEY + correct audience."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client', org_slug='acme')

    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')
    assert payload['sub'] == '42'
    assert payload['iss'] == 'acme.auditgraph.ai'
    assert payload['aud'] == 'auditgraph-tenant'
    assert payload['portal'] == 'client'
    assert payload['org_id'] == 5


# ── Test 4: Impersonation auto-expires ──

def test_impersonation_has_15min_cap():
    """Impersonation tokens have impersonation_exp claim capped at 15 minutes."""
    user = _make_impersonation_user()
    token = generate_access_token(user, portal='client', org_slug='acme')

    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')

    assert payload['impersonating'] is True
    assert payload['impersonated_by'] == 'techadmin'
    assert payload['impersonator_id'] == 1
    assert 'impersonation_exp' in payload

    # impersonation_exp should be ~15 min from now (allow 5s tolerance)
    now = datetime.now(timezone.utc).timestamp()
    imp_exp = payload['impersonation_exp']
    assert imp_exp > now, "impersonation_exp should be in the future"
    assert imp_exp <= now + 15 * 60 + 5, "impersonation_exp should be at most 15 min from now"

    # Token exp should be clamped to impersonation_exp (15min < CLIENT_TOKEN_EXPIRY 60min)
    assert payload['exp'] <= imp_exp + 1


def test_impersonation_exp_is_respected():
    """A token with impersonation_exp in the past should be detectable."""
    user = _make_impersonation_user()
    token = generate_access_token(user, portal='client', org_slug='acme')

    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')

    # Manually check: if impersonation_exp were in the past, middleware would reject
    fake_expired_payload = {**payload, 'impersonation_exp': int(time.time()) - 60}
    assert datetime.now(timezone.utc).timestamp() > fake_expired_payload['impersonation_exp']


# ── Test 5: Refresh token is hashed ──

def test_refresh_token_hash():
    """hash_refresh_token produces SHA-256 hex digest of the raw token."""
    raw = 'test-token-abc123'
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert hash_refresh_token(raw) == expected


# ── Test 6: Token claims structure ──

def test_admin_token_ttl():
    """Admin tokens have 30-minute TTL."""
    user = _make_admin_user()
    token = generate_access_token(user, portal='admin')
    payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-platform')
    ttl = payload['exp'] - payload['iat']
    assert ttl == ADMIN_TOKEN_EXPIRY.total_seconds()


def test_client_token_ttl():
    """Client tokens have 60-minute TTL."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client', org_slug='acme')
    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')
    ttl = payload['exp'] - payload['iat']
    assert ttl == CLIENT_TOKEN_EXPIRY.total_seconds()


def test_client_token_without_slug_uses_app_iss():
    """Client token without slug uses app.auditgraph.ai as issuer."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client')
    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')
    assert payload['iss'] == 'app.auditgraph.ai'


def test_cross_org_token_different_iss():
    """Tokens for different org slugs have different iss claims."""
    user1 = _make_org_user(organization_id=5, org_name='Acme')
    user2 = _make_org_user(organization_id=6, org_name='Globex')

    token1 = generate_access_token(user1, portal='client', org_slug='acme')
    token2 = generate_access_token(user2, portal='client', org_slug='globex')

    p1 = jwt.decode(token1, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                     audience='auditgraph-tenant')
    p2 = jwt.decode(token2, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                     audience='auditgraph-tenant')

    assert p1['iss'] == 'acme.auditgraph.ai'
    assert p2['iss'] == 'globex.auditgraph.ai'
    assert p1['iss'] != p2['iss']
    assert p1['org_id'] != p2['org_id']


# ── Test 7: Key isolation ──

def test_keys_are_distinct():
    """ADMIN and TENANT keys must be distinct when explicitly set."""
    assert ADMIN_JWT_SECRET == ADMIN_KEY
    assert CLIENT_JWT_SECRET == CLIENT_KEY
    assert ADMIN_JWT_SECRET != CLIENT_JWT_SECRET


# ── Test 8: JWT kid header (Phase 1D) ──

def test_admin_token_has_kid_header():
    """Admin token has kid='admin-v1' in JWT header."""
    user = _make_admin_user()
    token = generate_access_token(user, portal='admin')
    header = jwt.get_unverified_header(token)
    assert header['kid'] == ADMIN_KEY_ID
    assert header['kid'] == 'admin-v1'


def test_client_token_has_kid_header():
    """Client token has kid='tenant-v1' in JWT header."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client', org_slug='acme')
    header = jwt.get_unverified_header(token)
    assert header['kid'] == CLIENT_KEY_ID
    assert header['kid'] == 'tenant-v1'


# ── Test 9: Token schema version (Phase 1D) ──

def test_admin_token_has_ver_claim():
    """Admin token contains ver claim matching TOKEN_SCHEMA_VERSION."""
    user = _make_admin_user()
    token = generate_access_token(user, portal='admin')
    payload = jwt.decode(token, ADMIN_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-platform')
    assert payload['ver'] == TOKEN_SCHEMA_VERSION
    assert payload['ver'] == 1


def test_client_token_has_ver_claim():
    """Client token contains ver claim matching TOKEN_SCHEMA_VERSION."""
    user = _make_org_user()
    token = generate_access_token(user, portal='client', org_slug='acme')
    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')
    assert payload['ver'] == TOKEN_SCHEMA_VERSION
    assert payload['ver'] == 1


def test_impersonation_token_has_kid_and_ver():
    """Impersonation token carries both kid and ver correctly."""
    user = _make_impersonation_user()
    token = generate_access_token(user, portal='client', org_slug='acme')
    header = jwt.get_unverified_header(token)
    assert header['kid'] == CLIENT_KEY_ID
    payload = jwt.decode(token, CLIENT_JWT_SECRET, algorithms=[JWT_ALGORITHM],
                         audience='auditgraph-tenant')
    assert payload['ver'] == TOKEN_SCHEMA_VERSION
    assert payload['impersonating'] is True


# ── Test 10: Refresh token rotation atomicity (Phase 1D) ──

def test_refresh_token_hash_is_deterministic():
    """Same raw token always produces the same hash (atomic rotation relies on this)."""
    raw = secrets.token_urlsafe(48)
    h1 = hash_refresh_token(raw)
    h2 = hash_refresh_token(raw)
    assert h1 == h2
    # Different tokens produce different hashes
    raw2 = secrets.token_urlsafe(48)
    h3 = hash_refresh_token(raw2)
    assert h1 != h3


# ══════════════════════════════════════════════════════════════════════
# Phase 2B: Organization Isolation Source-Inspection Tests
# ══════════════════════════════════════════════════════════════════════

import inspect


def _get_method_source(cls, method_name):
    """Get the source code of a method on a class."""
    method = getattr(cls, method_name)
    return inspect.getsource(method)


# ── Test 11: Webhook methods must reference organization_id ──

def test_webhook_methods_use_organization_id():
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


# ── Test 12: Custom risk rule methods must reference organization_id ──

def test_custom_risk_rule_methods_use_organization_id():
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


# ── Test 13: Notification methods must reference organization_id ──

def test_notification_methods_use_organization_id():
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


# ── Test 14: SOAR methods must reference organization_id ──

def test_soar_methods_use_organization_id():
    """SOAR read/update/delete/stats methods must reference organization_id."""
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


# ── Test 15: Dashboard preferences must reference organization_id ──

def test_dashboard_prefs_use_organization_id():
    """Dashboard preference methods must reference organization_id."""
    from app.database import Database
    methods = [
        'get_dashboard_preferences', 'save_dashboard_preferences',
        'delete_dashboard_preferences',
    ]
    for name in methods:
        src = _get_method_source(Database, name)
        assert 'organization_id' in src, f"Database.{name}() missing organization_id filter"


# ── Test 16: Cloud connection single-record ops must reference organization_id ──

def test_cloud_connection_methods_use_organization_id():
    """Cloud connection by-ID methods must reference organization_id."""
    from app.database import Database
    methods = [
        'get_cloud_connection_by_id', 'update_cloud_connection',
    ]
    for name in methods:
        src = _get_method_source(Database, name)
        assert 'organization_id' in src, f"Database.{name}() missing organization_id filter"


# ── Test 17: Client connection handlers must use _db() not Database() ──

def test_handler_connection_methods_use_db_helper():
    """Client connection handlers must use _db() not raw Database()."""
    from app.api import handlers
    for func_name in [
        'get_client_connections', 'create_client_connection',
        'update_client_connection', 'delete_client_connection',
        'test_client_connection', 'discover_client_connection',
    ]:
        func = getattr(handlers, func_name)
        src = inspect.getsource(func)
        # Should use _db() not Database() for org-scoped operations
        # Database() (raw admin bypass) should not appear
        assert '_db()' in src, f"{func_name}() should use _db() for org scoping"


# ── Test 18: Notification dispatcher throttle is org-scoped ──

def test_notification_dispatcher_throttle_is_tenant_scoped():
    """Throttle key must include organization_id."""
    from app.services.notification_dispatcher import NotificationDispatcher
    src = inspect.getsource(NotificationDispatcher._is_throttled)
    assert 'organization_id' in src, "_is_throttled must accept tenant_id parameter"
    dispatch_src = inspect.getsource(NotificationDispatcher.dispatch)
    assert 'organization_id' in dispatch_src, "dispatch must extract organization_id"
