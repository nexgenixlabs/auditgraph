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

# Phase 1B+1C: Dual JWT keys — fallback to JWT_SECRET only in development.
# AG-97: even in production a shared JWT_SECRET fallback collapsed the
# dual-portal isolation when the env had only JWT_SECRET set (a common
# dev-to-prod CI/CD leak). Now: (a) fallback is strictly local/dev,
# (b) production REQUIRES both explicit secrets, (c) production enforces
# they are DIFFERENT, (d) minimum 32-byte entropy enforced on both.
_is_dev = os.getenv('APP_ENV', 'local') in ('local', 'dev') or os.getenv('FLASK_ENV') == 'development'
_jwt_fallback = os.getenv('JWT_SECRET') if _is_dev else None
ADMIN_JWT_SECRET = os.getenv('ADMIN_JWT_SECRET') or _jwt_fallback
CLIENT_JWT_SECRET = os.getenv('CLIENT_JWT_SECRET') or _jwt_fallback
if not ADMIN_JWT_SECRET or not CLIENT_JWT_SECRET:
    if _is_dev:
        raise RuntimeError("FATAL: ADMIN_JWT_SECRET + CLIENT_JWT_SECRET (or JWT_SECRET) required.")
    raise RuntimeError("FATAL: ADMIN_JWT_SECRET and CLIENT_JWT_SECRET are required in production.")

# AG-97: secret hygiene — minimum 32-byte entropy + production isolation.
_WEAK_SECRETS = {'secret', 'changeme', 'password', 'jwt_secret', 'dev', 'test'}
for _label, _val in (('ADMIN_JWT_SECRET', ADMIN_JWT_SECRET), ('CLIENT_JWT_SECRET', CLIENT_JWT_SECRET)):
    if len(_val) < 32:
        if _is_dev:
            logger.warning(
                "[AG-97] %s is only %d bytes (production requires ≥ 32). "
                "This is acceptable for local dev but will fail to start in prod.",
                _label, len(_val))
        else:
            raise RuntimeError(
                f"FATAL: {_label} must be at least 32 bytes in production "
                f"(current length: {len(_val)})."
            )
    if _val.lower() in _WEAK_SECRETS:
        raise RuntimeError(f"FATAL: {_label} matches a well-known weak value ({_val!r}).")
if not _is_dev and ADMIN_JWT_SECRET == CLIENT_JWT_SECRET:
    raise RuntimeError(
        "FATAL: ADMIN_JWT_SECRET and CLIENT_JWT_SECRET must be DIFFERENT in production. "
        "A shared secret collapses the dual-portal isolation — a client-portal token "
        "would validate on the admin portal (privilege escalation)."
    )
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
    '/api/auth/signup',
    '/api/auth/verify-email',
    '/api/auth/accept-invitation',
    '/api/auth/validate-invitation',
    '/api/tenant/config',
    '/api/tenants/validate-slug',
}


# ── AG-99: per-superadmin cross-org override rate limit (in-process). ──
# A 1-hour rolling window keyed by user_id. Default cap: 60 switches/hour
# (enough for a busy support session, low enough that a stolen token
# can't sweep thousands of tenants). Override via env CROSS_ORG_RATE_LIMIT.
from collections import deque
_CROSS_ORG_BUCKETS: dict[int, deque] = {}
_CROSS_ORG_LIMIT = int(os.getenv('CROSS_ORG_RATE_LIMIT', '60'))
_CROSS_ORG_WINDOW_S = 3600


def _superadmin_org_override_allowed(user_id: int) -> bool:
    """True if the superadmin is under the per-hour cross-org switch cap."""
    now = datetime.now(timezone.utc).timestamp()
    bucket = _CROSS_ORG_BUCKETS.setdefault(user_id, deque())
    # Evict stale entries
    while bucket and (now - bucket[0]) > _CROSS_ORG_WINDOW_S:
        bucket.popleft()
    if len(bucket) >= _CROSS_ORG_LIMIT:
        return False
    bucket.append(now)
    return True


# ── Phase 1B: Host-derived portal detection ──

def _derive_portal() -> str:
    """Derive portal from Host header. Supports multi-level subdomains (dev.admin.*).

    AG-98: hardening — the dev-mode fallback that trusted X-Portal-Context
    based on host=localhost/127.0.0.1 OR FLASK_ENV=development was a
    privilege-escalation footgun. If either of those signals leaked to a
    production container (misconfigured Dockerfile ENV, CI/CD override),
    any unauthenticated request could set X-Portal-Context: admin and
    force admin JWT key selection.

    Fix: use the SAME `_is_dev` constant resolved at module import time
    from the strictly-controlled APP_ENV env var (see AG-97). Host-based
    bypass removed entirely. FLASK_ENV ignored — only APP_ENV in
    ('local', 'dev') enables the dev-mode header trust.
    """
    host = request.host.split(':')[0]
    parts = host.split('.')
    if 'admin' in parts:
        return 'admin'
    # Accept X-Portal-Context header with Origin cross-validation (cross-origin API calls)
    portal_header = request.headers.get('X-Portal-Context', '')
    if portal_header == 'admin':
        origin = request.headers.get('Origin', '') or request.headers.get('Referer', '')
        if 'admin' in origin.lower():
            return 'admin'
    # AG-98: dev-mode fallback uses APP_ENV ONLY. No more host-based bypass.
    if _is_dev and portal_header in ('admin', 'client'):
        return portal_header
    return 'client'


def _derive_org_slug() -> str | None:
    """Extract organization slug from subdomain. aglabs.auditgraph.ai -> 'aglabs'.

    Multi-level subdomains like dev.api.auditgraph.ai are API hosts, not tenant
    portals — return None so the middleware skips the issuer check.
    """
    host = request.host.split(':')[0]
    parts = host.split('.')
    # Skip infrastructure hosts: if 'api' appears anywhere it's a backend endpoint
    reserved = ('app', 'api', 'admin', 'www', 'dev', 'staging')
    if 'api' in parts:
        return None
    # {slug}.auditgraph.ai — direct tenant subdomain
    if len(parts) == 3 and parts[0] not in reserved:
        return parts[0]
    # {env}.{portal}.auditgraph.ai — env-prefixed portal, not a slug
    if len(parts) >= 4:
        return None
    return None


def _resolve_login_org_slug() -> str | None:
    """Resolve organization slug from Origin header for login-time tenant isolation.

    Domain patterns:
      demo.auditgraph.ai       → 'demo'        (slug = subdomain)
      client1.auditgraph.ai    → 'client1'      (slug = subdomain)
      dev.app.auditgraph.ai    → DEFAULT_ORG_SLUG env var (env-prefixed portal)
      localhost:3000            → None           (no restriction in local dev)
    """
    origin = request.headers.get('Origin', '') or ''
    if not origin:
        return None
    try:
        from urllib.parse import urlparse
        host = (urlparse(origin).hostname or '').lower()
    except Exception:
        return None
    if host in ('localhost', '127.0.0.1'):
        return None
    if not host.endswith('.auditgraph.ai'):
        return None
    parts = host.split('.')
    # {slug}.auditgraph.ai → slug (e.g. demo.auditgraph.ai → 'demo')
    if len(parts) == 3:
        subdomain = parts[0]
        if subdomain not in ('app', 'api', 'admin', 'www'):
            return subdomain
    # {env}.app.auditgraph.ai → use DEFAULT_ORG_SLUG (e.g. dev.app.auditgraph.ai)
    if len(parts) == 4 and parts[1] == 'app':
        return os.getenv('DEFAULT_ORG_SLUG')
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
        'is_demo': bool(user.get('is_demo', False)),
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

    db = Database(_admin_reason='generate_refresh_token: save token hash')
    try:
        expires_at = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY
        db.save_refresh_token(user['id'], token_hash, expires_at, portal=portal)
    finally:
        db.close()

    return raw_token


def hash_refresh_token(raw_token: str) -> str:
    """Hash a raw refresh token for DB lookup."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


# ── Phase S1: httpOnly cookie auth ──

COOKIE_DOMAIN = os.getenv('COOKIE_DOMAIN', None)  # .auditgraph.ai in prod, None for localhost
_IS_SECURE_COOKIE = os.getenv('APP_ENV', 'local') not in ('local', 'dev')


def _cookie_name(portal: str, token_type: str) -> str:
    """Portal-specific cookie name: ag_admin_access, ag_client_refresh, etc."""
    return f'ag_{portal}_{token_type}'


def set_auth_cookies(response, access_token: str, refresh_token: str, portal: str):
    """Set httpOnly auth cookies + CSRF double-submit cookie on a Flask response."""
    access_ttl = int(ADMIN_TOKEN_EXPIRY.total_seconds()) if portal == 'admin' else int(CLIENT_TOKEN_EXPIRY.total_seconds())
    response.set_cookie(
        _cookie_name(portal, 'access'),
        value=access_token,
        httponly=True,
        secure=_IS_SECURE_COOKIE,
        samesite='Lax',
        max_age=access_ttl,
        path='/',
        domain=COOKIE_DOMAIN,
    )
    response.set_cookie(
        _cookie_name(portal, 'refresh'),
        value=refresh_token,
        httponly=True,
        secure=_IS_SECURE_COOKIE,
        samesite='Lax',
        max_age=int(REFRESH_TOKEN_EXPIRY.total_seconds()),
        path='/api/auth/',
        domain=COOKIE_DOMAIN,
    )
    # CSRF double-submit cookie (readable by JS — NOT httpOnly)
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        'csrf_token',
        value=csrf,
        httponly=False,
        secure=_IS_SECURE_COOKIE,
        samesite='Lax',
        max_age=int(REFRESH_TOKEN_EXPIRY.total_seconds()),
        path='/',
        domain=COOKIE_DOMAIN,
    )


def clear_auth_cookies(response, portal: str):
    """Clear auth cookies on logout."""
    for token_type in ('access', 'refresh'):
        response.delete_cookie(
            _cookie_name(portal, token_type),
            path='/' if token_type == 'access' else '/api/auth/',
            domain=COOKIE_DOMAIN,
        )
    response.delete_cookie('csrf_token', path='/', domain=COOKIE_DOMAIN)


def _authenticate_api_key(raw_key: str):
    """Validate an API key and set g.current_user. Returns None on success, error tuple on failure."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db = Database(_admin_reason='api_key_auth: validate key hash')
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

    # Phase 17: OIDC public endpoints
    if request.path.startswith('/api/auth/oidc/'):
        return None

    # Phase 17: SCIM endpoints (use their own bearer token auth)
    if request.path.startswith('/api/scim/'):
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

    # Phase S1: Fall back to httpOnly cookie if no Authorization header and no API key
    _cookie_auth = False
    if not api_key and not auth_header:
        cookie_token = request.cookies.get(_cookie_name(portal, 'access'))
        if cookie_token:
            auth_header = f'Bearer {cookie_token}'
            _cookie_auth = True
            # CSRF double-submit validation for cookie-based auth on mutating methods
            if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
                csrf_header = request.headers.get('X-CSRF-Token', '')
                csrf_cookie = request.cookies.get('csrf_token', '')
                if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
                    return jsonify({'error': 'CSRF token mismatch'}), 403

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
                            _db = Database(_admin_reason='auth_middleware: host-slug guard')
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
                'is_demo': payload.get('is_demo', False),
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
    # AG-99: every cross-org access must:
    #   1. Write to the TARGET org's activity_log (not just the app log) so
    #      the customer sees an audit trail in their own UI.
    #   2. Carry actor identity — user_id, username, source IP — in the
    #      activity_log metadata so an external auditor can trace it.
    #   3. Honor an in-process rate limit (default 60/hour per superadmin)
    #      so a compromised superadmin token can't sweep through every
    #      tenant in seconds.
    override_oid = request.headers.get('X-Organization-Id') or request.headers.get('X-Tenant-Id')
    if override_oid and g.current_user.get('is_superadmin'):
        try:
            target_oid = int(override_oid)
            # AG-99: rate limit cross-org switches. In-process counter is
            # fine for single-worker dev and reasonable for multi-worker
            # production where each worker enforces its own quota (the
            # blast radius is still bounded). For true cross-worker
            # enforcement, use Redis — wired in a follow-on.
            if _superadmin_org_override_allowed(g.current_user['id']):
                g.current_user['organization_id'] = target_oid
                g.current_user['org_id_override'] = True
                _actor_ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '')
                logger.info(
                    "[AG-99] Superadmin cross-org override: user_id=%s username=%s ip=%s -> organization_id=%s",
                    g.current_user['id'], g.current_user.get('username'), _actor_ip, target_oid,
                )
                try:
                    _log_db = Database(_admin_reason='auth_middleware: log cross-org action')
                    _log_cur = _log_db.conn.cursor()
                    import json as _json
                    _meta = _json.dumps({
                        'actor_user_id': g.current_user['id'],
                        'actor_username': g.current_user.get('username'),
                        'actor_ip': _actor_ip,
                        'actor_user_agent': request.headers.get('User-Agent', '')[:200],
                        'request_path': request.path,
                        'request_method': request.method,
                        'override_source_header': (
                            'X-Organization-Id' if request.headers.get('X-Organization-Id') else 'X-Tenant-Id'
                        ),
                    })
                    _log_cur.execute(
                        """INSERT INTO activity_log (action, description, user_id, organization_id, metadata, created_at)
                           VALUES (%s, %s, %s, %s, %s, NOW())""",
                        ('cross_org_admin_action',
                         f'Superadmin {g.current_user["username"]} accessed this tenant via org context override',
                         g.current_user['id'],
                         target_oid,  # TARGET org — customer sees it in their activity log
                         _meta),
                    )
                    _log_db._commit()
                    _log_cur.close()
                    _log_db.close()
                except Exception as e:
                    logger.warning(f"[AG-99] Failed to log cross-org admin action: {e}")
            else:
                logger.warning(
                    "[AG-99] Cross-org override RATE LIMITED for superadmin user_id=%s "
                    "(too many tenant switches in the last hour)", g.current_user['id'])
                return jsonify({
                    'error': 'Cross-org override rate limit exceeded for this superadmin. '
                             'Wait before switching tenants again.',
                    'code': 'cross_org_rate_limit',
                }), 429
        except (ValueError, TypeError):
            pass

    # Phase 3A.1: Per-request principal liveness + plan_status enforcement.
    # A stateless JWT stays valid until expiry, so without this a deleted or
    # disabled user (or a user whose org was deleted) keeps full access on an
    # active session. Verify the principal still exists + is enabled and the org
    # still exists, and block suspended/cancelled orgs — in one lookup that this
    # block already performed for plan_status. Fail-open on DB error so a
    # transient blip can't mass-logout everyone. (Superadmins/demo exempt.)
    if not g.current_user.get('is_superadmin') and not g.current_user.get('is_demo'):
        _uid = g.current_user.get('id')
        if _uid:
            _live_row = None
            _live_ok = False
            try:
                _ps_db = Database(_admin_reason='auth_middleware: principal liveness + plan_status')
                _ps_cur = _ps_db.conn.cursor()
                _ps_cur.execute(
                    """SELECT u.enabled, u.organization_id, o.id, o.plan_status
                       FROM users u
                       LEFT JOIN organizations o ON o.id = u.organization_id
                       WHERE u.id = %s""",
                    (_uid,),
                )
                _live_row = _ps_cur.fetchone()
                _ps_cur.close()
                _ps_db.close()
                _live_ok = True
            except Exception:
                pass  # fail-open: don't block on lookup failure
            if _live_ok:
                if _live_row is None:
                    return jsonify({'error': 'Session invalid — account no longer exists',
                                    'session_invalid': True}), 401
                _enabled, _u_org, _o_id, _plan = _live_row
                if not _enabled:
                    return jsonify({'error': 'Session invalid — account disabled',
                                    'session_invalid': True}), 401
                if _u_org and _o_id is None:
                    return jsonify({'error': 'Session invalid — organization no longer exists',
                                    'session_invalid': True}), 401
                if _plan in ('suspended', 'cancelled'):
                    return jsonify({
                        'error': f'Organization account is {_plan}. Contact support to restore access.',
                        'plan_status': _plan,
                        'account_blocked': True,
                    }), 403

    # Phase 23: Trial expiry check — only fires on client portal
    if portal == 'client' and not g.current_user.get('is_superadmin') and not g.current_user.get('portal_role'):
        org_id = g.current_user.get('organization_id')
        if org_id:
            try:
                tdb = Database(_admin_reason='auth_middleware: license check')
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


# Phase 1 Security Hardening: Role hierarchy — higher roles inherit lower permissions
# owner > admin > security_admin > compliance > reader
ROLE_HIERARCHY = {
    'owner': {'owner', 'admin', 'security_admin', 'security_analyst', 'compliance', 'reader', 'auditor', 'viewer'},
    'admin': {'admin', 'security_admin', 'security_analyst', 'compliance', 'reader', 'auditor', 'viewer'},
    'security_admin': {'security_admin', 'security_analyst', 'compliance', 'reader', 'auditor', 'viewer'},
    'security_analyst': {'security_analyst', 'compliance', 'reader', 'viewer'},
    'compliance': {'compliance', 'reader', 'viewer'},
    'reader': {'reader', 'viewer'},
    # Backward compat aliases
    'auditor': {'auditor', 'viewer', 'reader'},
    'viewer': {'viewer', 'reader'},
}


def require_role(*allowed_roles):
    """Decorator for handlers that require specific roles.
    Uses role hierarchy: owner inherits admin, admin inherits security_admin, etc."""
    allowed_set = set(allowed_roles)

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            user_role = user['role']
            # Direct match
            if user_role in allowed_set:
                return f(*args, **kwargs)
            # Hierarchy check: user's role inherits allowed roles
            inherited = ROLE_HIERARCHY.get(user_role, {user_role})
            if inherited & allowed_set:
                return f(*args, **kwargs)
            return jsonify({'error': 'Insufficient permissions'}), 403
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
