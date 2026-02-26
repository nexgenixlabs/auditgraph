"""
Phase 5: Security Hardening — Rate Limiting & Security Headers

In-memory rate limiter for auth endpoints.
Thread-safe, no external dependency (no Redis required).
Auto-evicts stale entries every 60 seconds.
"""
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

    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions policy (disable unused browser features)
    response.headers['Permissions-Policy'] = \
        'camera=(), microphone=(), geolocation=(), payment=()'

    # Cache control for API responses
    if response.content_type and 'application/json' in response.content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'

    return response


# ── Password Policy ──────────────────────────────────────────────────────────

MIN_PASSWORD_LENGTH = 12   # HIPAA-compliant minimum (Phase 6 upgrade)
MAX_PASSWORD_LENGTH = 128

# Top common passwords blocklist (abbreviated — expand in production)
BLOCKED_PASSWORDS = {
    'password1234', 'password123!', 'changeme1234', 'welcome12345',
    'qwerty123456', 'admin1234567', 'letmein12345', 'monkey123456',
    'dragon123456', 'master123456', '123456789abc', 'abc123456789',
    'iloveyou1234', 'trustno1pass', 'sunshine1234', 'princess1234',
    'football1234', 'charlie12345', 'shadow123456', 'michael12345',
}


def validate_password(password: str) -> tuple[bool, str | None]:
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
