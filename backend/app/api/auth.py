"""
Phase 31 + Phase 1B–1D: JWT Authentication Middleware & Helpers
- Dual JWT signing keys (admin vs client portal)
- Host-derived portal detection
- iss/aud standard claims
- Portal-aware middleware with cryptographic isolation
- Phase 1D: kid header, ver claim, fail-closed slug lookup
"""
from __future__ import annotations
import os
import jwt
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g
from app.database import Database

logger = logging.getLogger(__name__)

# Phase 1B+1C: Dual JWT keys — fallback to JWT_SECRET only in development
_is_dev = os.getenv('FLASK_ENV') == 'development'
_jwt_fallback = os.getenv('JWT_SECRET') if _is_dev else None
ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET') or _jwt_fallback
CLIENT_JWT_SECRET = os.getenv('CLIENT_JWT_SECRET') or _jwt_fallback
if not ADMIN_JWT_SECRET or not CLIENT_JWT_SECRET:
    if _is_dev:
        raise RuntimeError("FATAL: ADMIN_JWT_SECRET + CLIENT_JWT_SECRET (or JWT_SECRET) required.")
    raise RuntimeError("FATAL: ADMIN_JWT_SECRET and CLIENT_JWT_SECRET are required in production.")
JWT_ALGORITHM = 'HS256'

# Phase 1D: Token schema version and key IDs for key rotation prep
TOKEN_SCHEMA_VERSION = 1
ADMIN_KEY_ID = 'admin-v1'
CLIENT_KEY_ID = 'tenant-v1'

# Phase 1B: Portal-specific TTLs
ADMIN_TOKEN_EXPIRY = timedelta(minutes=30)
CLIENT_TOKEN_EXPIRY = timedelta(minutes=60)
REFRESH_TOKEN_EXPIRY = timedelta(days=7)

# Phase 76: Valid portal roles for admin console access
VALID_PORTAL_ROLES = ('superadmin', 'poweradmin', 'billing', 'reader')

PUBLIC_PATHS = {
    '/api/auth/login',
    '/api/auth/refresh',
    '/api/health',
    '/health',
    '/api/metrics',
    '/api/auth/forgot-password',
    '/api/auth/reset-password',
    '/api/auth/validate-reset-token',
    '/api/auth/org-branding',
    '/api/auth/tenant-branding',  # backward compat
    '/api/auth/password-policy',
    '/api/billing/stripe-webhook',
}


# ── Phase 1B: Host-derived portal detection ──

def _derive_portal() -> str:
    """Derive portal from Host header. admin.* -> 'admin', else -> 'client'."""
    host = request.host.split(':')[0]
    if host.startswith('admin.') or host == 'admin':
        return 'admin'
    # Dev mode: accept X-Portal-Context header when no subdomain routing
    if os.getenv('FLASK_ENV') == 'development' or host in ('localhost', '127.0.0.1'):
        override = request.headers.get('X-Portal-Context', '')
        if override in ('admin', 'client'):
            return override
    return 'client'


def _derive_org_slug() -> str | None:
    """Extract organization slug from subdomain. aglabs.auditgraph.ai -> 'aglabs'."""
    host = request.host.split(':')[0]
    parts = host.split('.')
    if len(parts) >= 3 and parts[0] not in ('app', 'api', 'admin', 'www'):
        return parts[0]
    return None


# ── Token generation ──

def generate_access_token(user: dict, portal: str = 'client', org_slug: str | None = None) -> str:
    """Generate a JWT access token with portal-specific key, iss, aud, and TTL.
    Phase 1C: iss = origin domain, aud = logical audience."""
    if portal == 'admin':
        iss = 'admin.auditgraph.ai'
        aud = 'auditgraph-platform'
        secret = ADMIN_JWT_SECRET
        expiry = ADMIN_TOKEN_EXPIRY
    else:
        iss = f'{org_slug}.auditgraph.ai' if org_slug else 'app.auditgraph.ai'
        aud = 'auditgraph-tenant'
        secret = CLIENT_JWT_SECRET
        expiry = CLIENT_TOKEN_EXPIRY

    payload = {
        'sub': str(user['id']),
        'username': user['username'],
        'role': user['role'],
        'display_name': user['display_name'],
        # Phase 2C: Emit both new + old JWT claims for backward compat
        'org_id': user.get('organization_id'),
        'org_name': user.get('org_name'),
        'tenant_id': user.get('organization_id'),   # backward compat
        'tenant_name': user.get('org_name'),         # backward compat
        'is_superadmin': user.get('is_superadmin', False),
        'portal_role': user.get('portal_role'),
        'force_password_change': user.get('force_password_change', False),
        'portal': portal,
        'iss': iss,
        'aud': aud,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + expiry,
        'type': 'access',
        'ver': TOKEN_SCHEMA_VERSION,
    }

    # Phase 1C: Impersonation claims with 15-min hard cap
    if user.get('impersonating'):
        payload['impersonating'] = True
        payload['impersonator_id'] = user['impersonator_id']
        payload['impersonator_username'] = user['impersonator_username']
        payload['impersonated_by'] = user['impersonator_username']
        imp_exp = datetime.now(timezone.utc) + timedelta(minutes=15)
        # Clamp token exp to impersonation_exp if shorter
        if imp_exp < payload['exp']:
            payload['exp'] = imp_exp
        payload['impersonation_exp'] = int(imp_exp.timestamp())

    # Phase 1D: kid header for key rotation prep
    kid = ADMIN_KEY_ID if portal == 'admin' else CLIENT_KEY_ID
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM, headers={'kid': kid})


def generate_refresh_token(user: dict, portal: str = 'client') -> str:
    """Generate an opaque refresh token, store SHA-256 hash in DB with portal context."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    db = Database()
    try:
        expires_at = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY
        db.save_refresh_token(user['id'], token_hash, expires_at, portal=portal)
    finally:
        db.close()

    return raw_token


def hash_refresh_token(raw_token: str) -> str:
    """Hash a raw refresh token for DB lookup."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _authenticate_api_key(raw_key: str):
    """Validate an API key and set g.current_user. Returns None on success, error tuple on failure."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db = Database()
    try:
        row = db.get_api_key_by_hash(key_hash)
        if not row:
            return jsonify({'error': 'Invalid API key'}), 401
        if not row['enabled']:
            return jsonify({'error': 'API key is disabled'}), 401
        if row.get('expires_at') and datetime.now(timezone.utc) > row['expires_at']:
            return jsonify({'error': 'API key has expired'}), 401

        db.increment_api_key_usage(row['id'])

        # Look up creator's organization info
        creator_org_id = None
        creator_org_name = None
        if row['created_by']:
            creator = db.get_user_by_id(row['created_by'])
            if creator:
                creator_org_id = creator.get('organization_id')
                creator_org_name = creator.get('org_name')

        g.current_user = {
            'id': row['created_by'] or 0,
            'username': f'api-key:{row["key_prefix"]}',
            'role': row['role'],
            'display_name': f'API Key: {row["name"]}',
            'api_key_id': row['id'],
            'organization_id': creator_org_id,
            'org_name': creator_org_name,
            'is_superadmin': False,
        }
    finally:
        db.close()
    return None


def auth_middleware():
    """Flask before_request hook. Sets g.current_user or returns 401.
    Phase 1B: Portal-aware with cryptographic key isolation."""
    if request.path in PUBLIC_PATHS:
        return None

    # Phase 53: Public organization lookup by slug (no auth required)
    if (request.path.startswith('/api/organizations/by-slug/') or
        request.path.startswith('/api/tenants/by-slug/') or
        request.path.startswith('/api/clients/by-slug/')):
        return None

    # Phase 54: SAML SSO public endpoints
    if request.path.startswith('/api/auth/saml/') or request.path == '/api/auth/sso-status':
        return None

    if not request.path.startswith('/api/'):
        return None

    if request.method == 'OPTIONS':
        return None

    # Phase 1B: Derive portal from host header
    portal = _derive_portal()

    # Phase 42: Check for API key auth before JWT
    api_key = request.headers.get('X-API-Key', '')
    auth_header = request.headers.get('Authorization', '')

    # Also detect API key in Bearer header (ag_ prefix)
    if not api_key and auth_header.startswith('Bearer ag_'):
        api_key = auth_header[7:]

    if api_key:
        result = _authenticate_api_key(api_key)
        if result is not None:
            return result
        # Phase 1B: API keys blocked on admin portal
        if portal == 'admin':
            return jsonify({'error': 'API keys cannot access admin portal'}), 403
        g.current_user['portal'] = 'client'
    else:
        # Standard JWT auth with portal-specific key
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401

        token = auth_header[7:]
        secret = ADMIN_JWT_SECRET if portal == 'admin' else CLIENT_JWT_SECRET

        try:
            # Phase 1C: aud = logical audience name (not domain)
            if portal == 'admin':
                payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM],
                                     audience='auditgraph-platform')
            else:
                payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM],
                                     audience='auditgraph-tenant')
                # Phase 1C: Verify iss matches host slug (iss = origin domain)
                token_iss = payload.get('iss', '')
                host_slug = _derive_org_slug()
                if host_slug and token_iss != f'{host_slug}.auditgraph.ai':
                    return jsonify({'error': 'Token issuer mismatch'}), 403
                # Phase 1C+1D: Verify token org_id matches resolved slug's organization
                # Phase 1D: Superadmins no longer exempt — cross-org only via impersonation
                if host_slug:
                    token_tid = payload.get('org_id') or payload.get('tenant_id')
                    if token_tid is not None:
                        try:
                            _db = Database()
                            _cur = _db.conn.cursor()
                            _cur.execute("SELECT id FROM organizations WHERE slug = %s", (host_slug,))
                            _row = _cur.fetchone()
                            _cur.close()
                            _db.close()
                            if _row and _row[0] != token_tid:
                                return jsonify({'error': 'Token organization mismatch'}), 403
                        except Exception as e:
                            # Phase 1D: Fail-closed — slug lookup failure blocks request
                            logger.error(f"Organization slug lookup failed for slug={host_slug}: {e}")
                            return jsonify({'error': 'Organization verification failed'}), 500

            if payload.get('type') != 'access':
                return jsonify({'error': 'Invalid token type'}), 401

            # Phase 1D: Verify token schema version
            if payload.get('ver') != TOKEN_SCHEMA_VERSION:
                return jsonify({'error': 'Unsupported token version'}), 401

            g.current_user = {
                'id': int(payload['sub']),
                'username': payload['username'],
                'role': payload['role'],
                'display_name': payload['display_name'],
                # Phase 2C: Read org_id first, fall back to tenant_id for backward compat
                'organization_id': payload.get('org_id') or payload.get('tenant_id'),
                'org_name': payload.get('org_name') or payload.get('tenant_name'),
                'is_superadmin': payload.get('is_superadmin', False),
                'portal_role': payload.get('portal_role'),
                'portal': portal,
            }

            # Carry impersonation claims + enforce impersonation_exp
            if payload.get('impersonating'):
                imp_exp = payload.get('impersonation_exp')
                if imp_exp and datetime.now(timezone.utc).timestamp() > imp_exp:
                    return jsonify({'error': 'Impersonation session expired'}), 401
                g.current_user['impersonating'] = True
                g.current_user['impersonator_id'] = payload.get('impersonator_id')
                g.current_user['impersonator_username'] = payload.get('impersonator_username')
                g.current_user['impersonated_by'] = payload.get('impersonated_by')

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidAudienceError:
            return jsonify({'error': 'Token not valid for this portal'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        # NO except Exception: pass — fail-closed

    # Phase 46: Superadmin org override via X-Organization-Id header (accepts X-Tenant-Id for backward compat)
    override_oid = request.headers.get('X-Organization-Id') or request.headers.get('X-Tenant-Id')
    if override_oid and g.current_user.get('is_superadmin'):
        try:
            g.current_user['organization_id'] = int(override_oid)
            g.current_user['org_id_override'] = True
            # Phase 1D: Log cross-org admin actions
            logger.info(f"Superadmin cross-org override: user_id={g.current_user['id']} -> organization_id={override_oid}")
            try:
                _log_db = Database()
                _log_cur = _log_db.conn.cursor()
                _log_cur.execute(
                    """INSERT INTO activity_log (action, description, user_id, organization_id, metadata, created_at)
                       VALUES (%s, %s, %s, %s, %s, NOW())""",
                    ('cross_org_admin_action',
                     f'Superadmin {g.current_user["username"]} overrode org context to organization_id={override_oid}',
                     g.current_user['id'],
                     int(override_oid),
                     '{}')
                )
                _log_db.conn.commit()
                _log_cur.close()
                _log_db.close()
            except Exception as e:
                logger.warning(f"Failed to log cross-org admin action: {e}")
        except (ValueError, TypeError):
            pass

    # Phase 3A.1: Global plan_status enforcement — suspended/cancelled orgs blocked
    if not g.current_user.get('is_superadmin'):
        _ps_org_id = g.current_user.get('organization_id')
        if _ps_org_id:
            try:
                _ps_db = Database()
                _ps_cur = _ps_db.conn.cursor()
                _ps_cur.execute("SELECT plan_status FROM organizations WHERE id = %s", (_ps_org_id,))
                _ps_row = _ps_cur.fetchone()
                _ps_cur.close()
                _ps_db.close()
                if _ps_row and _ps_row[0] in ('suspended', 'cancelled'):
                    return jsonify({
                        'error': f'Organization account is {_ps_row[0]}. Contact support to restore access.',
                        'plan_status': _ps_row[0],
                        'account_blocked': True,
                    }), 403
            except Exception:
                pass  # Don't block on lookup failure

    # Phase 23: Trial expiry check — only fires on client portal
    if portal == 'client' and not g.current_user.get('is_superadmin') and not g.current_user.get('portal_role'):
        org_id = g.current_user.get('organization_id')
        if org_id:
            try:
                tdb = Database()
                tcur = tdb.conn.cursor()
                tcur.execute("SELECT plan, license_activated_at FROM organizations WHERE id = %s", (org_id,))
                trow = tcur.fetchone()
                tcur.close()
                tdb.close()
                if trow and trow[0] == 'trial' and trow[1]:
                    activated = trow[1]
                    if isinstance(activated, str):
                        activated = datetime.fromisoformat(activated.replace('Z', '+00:00'))
                    tz = activated.tzinfo if activated.tzinfo else None
                    if datetime.now(tz) > activated + timedelta(days=14):
                        return jsonify({
                            'error': 'Trial period has expired. Please upgrade to continue.',
                            'upgrade_required': True,
                            'current_plan': 'trial',
                            'trial_expired': True,
                        }), 403
            except Exception:
                pass  # Don't block on lookup failure

    return None


def require_role(*allowed_roles):
    """Decorator for handlers that require specific roles."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            if user['role'] not in allowed_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_superadmin():
    """Decorator for handlers that require superadmin access."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            if not user.get('is_superadmin'):
                return jsonify({'error': 'Superadmin access required'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_portal_access():
    """Decorator for handlers that require any portal access.
    Accepts all VALID_PORTAL_ROLES plus is_superadmin=True as fallback."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            portal_role = user.get('portal_role')
            if portal_role not in VALID_PORTAL_ROLES and not user.get('is_superadmin'):
                return jsonify({'error': 'Portal access required'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_portal_role(*allowed_roles):
    """Decorator for handlers that require specific portal roles.
    Falls back to is_superadmin for backward compat."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            portal_role = user.get('portal_role')
            if portal_role in allowed_roles or user.get('is_superadmin'):
                return f(*args, **kwargs)
            return jsonify({'error': 'Insufficient portal permissions'}), 403
        return wrapper
    return decorator


def require_feature(feature_name):
    """Decorator that gates a route behind a plan feature.
    Backward-compat alias — delegates to the entitlements engine."""
    from app.entitlements.decorator import require_entitlement
    return require_entitlement(feature_name)
