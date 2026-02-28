"""
Phase 31 + Phase 1B: JWT Authentication Middleware & Helpers
- Dual JWT signing keys (admin vs tenant portal)
- Host-derived portal detection
- iss/aud standard claims
- Portal-aware middleware with cryptographic isolation
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

# Phase 1B: Dual JWT keys with legacy fallback for zero-downtime migration
ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET') or os.getenv('JWT_SECRET')
TENANT_JWT_SECRET = os.getenv('TENANT_JWT_SECRET') or os.getenv('JWT_SECRET')
if not ADMIN_JWT_SECRET or not TENANT_JWT_SECRET:
    raise RuntimeError("FATAL: ADMIN_JWT_SECRET + TENANT_JWT_SECRET (or JWT_SECRET) required.")
JWT_ALGORITHM = 'HS256'

# Phase 1B: Portal-specific TTLs
ADMIN_TOKEN_EXPIRY = timedelta(minutes=30)
TENANT_TOKEN_EXPIRY = timedelta(minutes=60)
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
    '/api/auth/tenant-branding',
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


def _derive_tenant_slug() -> str | None:
    """Extract tenant slug from subdomain. aglabs.auditgraph.ai -> 'aglabs'."""
    host = request.host.split(':')[0]
    parts = host.split('.')
    if len(parts) >= 3 and parts[0] not in ('app', 'api', 'admin', 'www'):
        return parts[0]
    return None


# ── Token generation ──

def generate_access_token(user: dict, portal: str = 'client', tenant_slug: str | None = None) -> str:
    """Generate a JWT access token with portal-specific key, iss, aud, and TTL."""
    if portal == 'admin':
        iss = 'auditgraph-platform'
        aud = 'admin.auditgraph.ai'
        secret = ADMIN_JWT_SECRET
        expiry = ADMIN_TOKEN_EXPIRY
    else:
        iss = 'auditgraph-tenant'
        aud = f'{tenant_slug}.auditgraph.ai' if tenant_slug else 'app.auditgraph.ai'
        secret = TENANT_JWT_SECRET
        expiry = TENANT_TOKEN_EXPIRY

    payload = {
        'sub': str(user['id']),
        'username': user['username'],
        'role': user['role'],
        'display_name': user['display_name'],
        'tenant_id': user.get('tenant_id'),
        'tenant_name': user.get('tenant_name'),
        'is_superadmin': user.get('is_superadmin', False),
        'portal_role': user.get('portal_role'),
        'force_password_change': user.get('force_password_change', False),
        'portal': portal,
        'iss': iss,
        'aud': aud,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + expiry,
        'type': 'access',
    }

    # Impersonation claims
    if user.get('impersonating'):
        payload['impersonating'] = True
        payload['impersonator_id'] = user['impersonator_id']
        payload['impersonator_username'] = user['impersonator_username']

    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


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

        # Look up creator's tenant info
        creator_tenant_id = None
        creator_tenant_name = None
        if row['created_by']:
            creator = db.get_user_by_id(row['created_by'])
            if creator:
                creator_tenant_id = creator.get('tenant_id')
                creator_tenant_name = creator.get('tenant_name')

        g.current_user = {
            'id': row['created_by'] or 0,
            'username': f'api-key:{row["key_prefix"]}',
            'role': row['role'],
            'display_name': f'API Key: {row["name"]}',
            'api_key_id': row['id'],
            'tenant_id': creator_tenant_id,
            'tenant_name': creator_tenant_name,
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

    # Phase 53: Public tenant lookup by slug (no auth required)
    if request.path.startswith('/api/tenants/by-slug/') or request.path.startswith('/api/clients/by-slug/'):
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
        secret = ADMIN_JWT_SECRET if portal == 'admin' else TENANT_JWT_SECRET

        try:
            if portal == 'admin':
                payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM],
                                     audience='admin.auditgraph.ai')
            else:
                payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM],
                                     options={'verify_aud': False})
                # Verify aud matches host slug if present
                token_aud = payload.get('aud', '')
                host_slug = _derive_tenant_slug()
                if host_slug and token_aud != f'{host_slug}.auditgraph.ai':
                    return jsonify({'error': 'Token audience mismatch'}), 403

            if payload.get('type') != 'access':
                return jsonify({'error': 'Invalid token type'}), 401

            g.current_user = {
                'id': int(payload['sub']),
                'username': payload['username'],
                'role': payload['role'],
                'display_name': payload['display_name'],
                'tenant_id': payload.get('tenant_id'),
                'tenant_name': payload.get('tenant_name'),
                'is_superadmin': payload.get('is_superadmin', False),
                'portal_role': payload.get('portal_role'),
                'portal': portal,
            }

            # Carry impersonation claims
            if payload.get('impersonating'):
                g.current_user['impersonating'] = True
                g.current_user['impersonator_id'] = payload.get('impersonator_id')
                g.current_user['impersonator_username'] = payload.get('impersonator_username')

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidAudienceError:
            return jsonify({'error': 'Token not valid for this portal'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        # NO except Exception: pass — fail-closed

    # Phase 46: Superadmin tenant override via X-Tenant-Id header
    override_tid = request.headers.get('X-Tenant-Id')
    if override_tid and g.current_user.get('is_superadmin'):
        try:
            g.current_user['tenant_id'] = int(override_tid)
            g.current_user['tenant_id_override'] = True
        except (ValueError, TypeError):
            pass

    # Phase 23: Trial expiry check — only fires on client portal
    if portal == 'client' and not g.current_user.get('is_superadmin') and not g.current_user.get('portal_role'):
        tenant_id = g.current_user.get('tenant_id')
        if tenant_id:
            try:
                tdb = Database()
                tcur = tdb.conn.cursor()
                tcur.execute("SELECT plan, license_activated_at FROM tenants WHERE id = %s", (tenant_id,))
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
    Superadmins bypass all gates. Logs entitlement_blocked to activity_log."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            # Superadmins bypass all feature gates
            if user.get('is_superadmin'):
                return f(*args, **kwargs)
            # Lazy import to avoid circular dependency (auth <- handlers)
            from app.api.handlers import check_feature_gate
            allowed, err = check_feature_gate(feature_name)
            if not allowed:
                # Log the blocked attempt
                try:
                    db = Database()
                    cursor = db.conn.cursor()
                    cursor.execute(
                        """INSERT INTO activity_log (action, description, user_id, tenant_id, metadata, created_at)
                           VALUES (%s, %s, %s, %s, %s, NOW())""",
                        ('entitlement_blocked',
                         f'Feature "{feature_name}" blocked for {err.get("current_plan", "free")} plan',
                         user.get('id'),
                         user.get('tenant_id'),
                         '{}')
                    )
                    db.conn.commit()
                    cursor.close()
                    db.close()
                except Exception:
                    pass
                return jsonify(err), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
