"""
AuditGraph security primitives.

Phase 5: Security Hardening — Rate Limiting & Security Headers
Phase AG-93: SQL Identifier Safety (sql_identifiers submodule)

In-memory rate limiter for auth endpoints.
Thread-safe, no external dependency (no Redis required).
Auto-evicts stale entries every 60 seconds.
"""
import os
import time
import threading
import logging
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger(__name__)


class RateLimiter:
    """In-memory sliding-window rate limiter keyed by IP address."""

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._buckets: dict[str, list[float]] = {}
        self._last_cleanup = time.time()

    @classmethod
    def get(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _cleanup(self):
        """Remove stale entries older than 5 minutes."""
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        cutoff = now - 300
        stale = [k for k, v in self._buckets.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._buckets[k]
        self._last_cleanup = now

    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Check if key has exceeded max_requests in the last window_seconds.

        Returns True if rate limited, False if allowed.
        Also records the current request timestamp.
        """
        now = time.time()
        self._cleanup()

        if key not in self._buckets:
            self._buckets[key] = []

        cutoff = now - window_seconds
        # Remove old timestamps outside the window
        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

        if len(self._buckets[key]) >= max_requests:
            return True

        self._buckets[key].append(now)
        return False

    def get_retry_after(self, key: str, window_seconds: int) -> int:
        """Get seconds until the oldest entry expires from the window."""
        timestamps = self._buckets.get(key, [])
        if not timestamps:
            return 0
        oldest_in_window = timestamps[0]
        return max(1, int(window_seconds - (time.time() - oldest_in_window)) + 1)


def rate_limit(max_requests: int = 5, window_seconds: int = 60, key_func=None):
    """Decorator to rate-limit a Flask route.

    Args:
        max_requests: Maximum requests allowed in the window.
        window_seconds: Window duration in seconds.
        key_func: Optional function(request) → str for custom key.
                  Defaults to client IP address.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            limiter = RateLimiter.get()
            if key_func:
                key = key_func(request)
            else:
                key = f"{request.remote_addr}:{request.path}"

            if limiter.is_rate_limited(key, max_requests, window_seconds):
                retry_after = limiter.get_retry_after(key, window_seconds)
                logger.warning(
                    f"Rate limited: {key} ({max_requests}/{window_seconds}s)")
                response = jsonify({
                    'error': 'Too many requests. Please try again later.',
                    'retry_after': retry_after,
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response

            return f(*args, **kwargs)
        return wrapper
    return decorator


def add_security_headers(response):
    """Add security headers to every response.

    Called as Flask after_request handler.
    """
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Clickjacking protection
    response.headers['X-Frame-Options'] = 'DENY'

    # XSS filter (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Strict Transport Security (1 year, include subdomains)
    response.headers['Strict-Transport-Security'] = \
        'max-age=31536000; includeSubDomains; preload'

    # Referrer policy — strict-origin prevents leaking path/query to cross-origin
    response.headers['Referrer-Policy'] = 'strict-origin'

    # Permissions policy (disable unused browser features)
    response.headers['Permissions-Policy'] = \
        'geolocation=(), camera=(), microphone=()'

    # Content Security Policy (Phase 1 Security Hardening)
    # AG-114: unsafe-inline only in development (2,787 inline style= in frontend)
    _is_dev = os.environ.get('APP_ENV', 'production') == 'local'
    _style_src = "'self' 'unsafe-inline'" if _is_dev else "'self'"
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        f"style-src {_style_src}; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # Cache control for API responses
    # Skip for Phase 3 FastAPI routes — they set their own Cache-Control headers
    if response.content_type and 'application/json' in response.content_type:
        from flask import request as _req
        if not _req.path.startswith('/api/v1/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            response.headers['Pragma'] = 'no-cache'

    return response


# ── Password Policy ──────────────────────────────────────────────────────────

MIN_PASSWORD_LENGTH = 12   # HIPAA-compliant minimum (Phase 6 upgrade)
MAX_PASSWORD_LENGTH = 128

# Common passwords blocklist — all lowercase, >= 12 chars to match MIN_PASSWORD_LENGTH.
# validate_password() calls password.lower() before checking membership.
BLOCKED_PASSWORDS = {
    # Common password + number/symbol patterns
    'password1234', 'password123!', 'password12345', 'password1234!',
    'password!234', 'passwordpass', 'password1111', 'password2024',
    'password2025', 'password2026', 'passw0rd1234', 'p@ssword1234',
    'p@ssw0rd1234',
    # Admin / system patterns
    'admin1234567', 'admin12345!!', 'admin2024!!!', 'admin2025!!!',
    'administrator', 'rootpassword', 'root12345678', 'sysadmin1234',
    'superadmin12', 'testpassword', 'test12345678', 'guest1234567',
    'guestguest12',
    # Welcome / generic
    'welcome12345', 'welcome2024!', 'welcome2025!', 'welcome1234!',
    'changeme1234', 'changeme123!', 'letmein12345', 'letmein1234!',
    'pleaseletme1', 'openthegate1',
    # Simple word + padding
    'qwerty123456', 'qwertyuiop12', 'qwerty12345!', 'asdfghjkl123',
    'zxcvbnm12345', '1qaz2wsx3edc', 'qazwsx123456', '123qwe456rty',
    # Sequential / repeating
    '123456789abc', 'abc123456789', '1234567890ab', 'abcdefgh1234',
    'aaaaaaaaaaaa', '111111111111', '000000000000', '123456789012',
    '987654321012', 'abcdefghijkl', 'zzzzzzzzzzzz', 'qqqqqqqqqqqq',
    # Names + numbers
    'michael12345', 'charlie12345', 'jessica12345', 'jennifer1234',
    'andrew123456', 'daniel123456', 'jordan123456', 'thomas123456',
    'robert123456', 'joseph123456', 'ashley123456', 'joshua123456',
    # Pop culture / animals
    'monkey123456', 'dragon123456', 'shadow123456', 'master123456',
    'superman1234', 'batman123456', 'starwars1234', 'pokemon12345',
    'princess1234', 'sunshine1234', 'football1234', 'baseball1234',
    'soccer123456', 'hockey123456', 'harley123456', 'hunter123456',
    'ranger123456', 'mustang12345', 'cookie123456', 'chocolate123',
    # Affection / sentiment
    'iloveyou1234', 'iloveyou123!', 'trustno1pass', 'trustno11234',
    'letmein!!!!!', 'loveyou12345',
    # Security / infosec terms (ironic weak passwords)
    'security1234', 'secure123456', 'firewall1234', 'network12345',
    'cybersecure1', 'infosec12345', 'hacker123456', 'exploit12345',
    'pentest12345', 'defender1234', 'antivirus123', 'encrypted123',
    'vulnerability', 'scanner12345',
    # Year patterns
    'summer202400', 'summer202500', 'winter202400', 'winter202500',
    'spring202400', 'spring202500', 'autumn202400',
    # Company / product specific
    'auditgraph12', 'auditgraph!!', 'nexgenix1234', 'nexgenix123!',
    'auditgraph23', 'microsoft123', 'azure1234567', 'google123456',
    # Keyboard walks
    '1qazxsw23edc', 'zaq12wsx3edc', '!qaz2wsx#edc', 'qweasdzxc123',
    # Common IT / default patterns
    'default12345', 'temp12345678', 'temporary123', 'initial12345',
    'firstlogin12', 'resetme12345', 'newpassword1', 'newuser12345',
    'setup1234567', 'install12345', 'configconfig',
    # Misc common >= 12 chars
    'trustno1!!!!', 'letmeinletme', 'opensesame12', 'abracadabra1',
    'supermansuper', 'dragondragon', 'mastermaster', 'shadowshadow',
}


def validate_password(password: str) -> tuple:
    """Validate password meets HIPAA-grade security policy.

    Requirements:
    - 12-128 characters (HIPAA minimum)
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    - Not in common password blocklist

    Returns (valid: bool, error_message: str | None)
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Password must be at least {MIN_PASSWORD_LENGTH} characters.'
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f'Password must be at most {MAX_PASSWORD_LENGTH} characters.'
    if not any(c.isupper() for c in password):
        return False, 'Password must contain at least one uppercase letter.'
    if not any(c.islower() for c in password):
        return False, 'Password must contain at least one lowercase letter.'
    if not any(c.isdigit() for c in password):
        return False, 'Password must contain at least one digit.'
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in password):
        return False, 'Password must contain at least one special character.'
    if password.lower() in BLOCKED_PASSWORDS:
        return False, 'This password is too common. Please choose a stronger password.'
    return True, None
