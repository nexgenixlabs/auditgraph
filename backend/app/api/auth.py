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

PUBLIC_PATHS = {
    '/api/auth/login',
    '/api/auth/refresh',
    '/api/health',
    '/health',
}


def generate_access_token(user: dict) -> str:
    """Generate a JWT access token containing user_id, username, role."""
    payload = {
        'sub': str(user['id']),
        'username': user['username'],
        'role': user['role'],
        'display_name': user['display_name'],
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


def auth_middleware():
    """Flask before_request hook. Sets g.current_user or returns 401."""
    if request.path in PUBLIC_PATHS:
        return None

    if not request.path.startswith('/api/'):
        return None

    if request.method == 'OPTIONS':
        return None

    auth_header = request.headers.get('Authorization', '')
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
        }
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

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
