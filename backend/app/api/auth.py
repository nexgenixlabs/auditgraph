"""
Phase 31: JWT Authentication Middleware & Helpers
"""
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

JWT_SECRET = os.getenv('JWT_SECRET', 'auditgraph-dev-secret-change-in-production')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRY = timedelta(hours=24)
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
}


def generate_access_token(user: dict) -> str:
    """Generate a JWT access token containing user_id, username, role, tenant."""
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
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRY,
        'type': 'access',
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def generate_refresh_token(user: dict) -> str:
    """Generate an opaque refresh token, store SHA-256 hash in DB."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    db = Database()
    try:
        expires_at = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY
        db.save_refresh_token(user['id'], token_hash, expires_at)
    finally:
        db.close()

    return raw_token


def verify_access_token(token: str) -> dict:
    """Verify and decode JWT access token. Raises on invalid/expired."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


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
    """Flask before_request hook. Sets g.current_user or returns 401."""
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
        # Fall through to X-Tenant-Id override below
    else:
        # Standard JWT auth
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401

        token = auth_header[7:]
        try:
            payload = verify_access_token(token)
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
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

    # Phase 46: Superadmin tenant override via X-Tenant-Id header
    override_tid = request.headers.get('X-Tenant-Id')
    if override_tid and g.current_user.get('is_superadmin'):
        try:
            g.current_user['tenant_id'] = int(override_tid)
            g.current_user['tenant_id_override'] = True
        except (ValueError, TypeError):
            pass

    # Phase 87: Host↔Tenant guard — prevent cross-subdomain token reuse
    # If request comes from a tenant subdomain (e.g., aglabs.auditgraph.ai),
    # verify the JWT's tenant matches that subdomain.
    # Superadmins bypass (they legitimately access all tenants).
    if not g.current_user.get('is_superadmin') and not g.current_user.get('portal_role'):
        host = request.host.split(':')[0]  # strip port
        parts = host.split('.')
        # Only enforce for subdomain patterns like <slug>.auditgraph.ai
        if len(parts) >= 3 and parts[-2] in ('auditgraph',):
            host_slug = parts[0]
            # Skip for common non-tenant subdomains
            if host_slug not in ('app', 'api', 'admin', 'www', 'localhost'):
                user_tenant_name = (g.current_user.get('tenant_name') or '').lower().replace(' ', '')
                # Look up slug from DB if needed
                try:
                    db = Database()
                    cursor = db.conn.cursor()
                    cursor.execute("SELECT id, slug FROM tenants WHERE slug = %s", (host_slug,))
                    tenant_row = cursor.fetchone()
                    cursor.close()
                    db.close()
                    if tenant_row:
                        host_tenant_id = tenant_row[0]
                        jwt_tenant_id = g.current_user.get('tenant_id')
                        if jwt_tenant_id and jwt_tenant_id != host_tenant_id:
                            return jsonify({'error': 'Token does not match this tenant'}), 403
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


def get_tenant_id():
    """Get tenant_id from the current authenticated user context."""
    user = getattr(g, 'current_user', None)
    return user.get('tenant_id') if user else None
