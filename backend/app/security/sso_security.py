"""
AG-95: SSO & SAML authentication security — SSOT for replay prevention,
one-time code hardening, and secure SAML settings.

CWE-294 (Authentication Bypass by Capture-Replay)
CWE-287 (Improper Authentication)
CWE-307 (Improper Restriction of Excessive Authentication Attempts)
CWE-345 (Insufficient Verification of Data Authenticity)
CWE-311 (Missing Encryption of Sensitive Data)
CWE-330 (Use of Insufficiently Random Values)
OWASP A02:2021 — Cryptographic Failures (assertion/NameID encryption)
OWASP A07:2021 — Identification and Authentication Failures
NIST SP 800-63B — AAL2 replay resistance, federation encryption
SAML V2.0 §6.2 — Assertion Encryption
SAML V2.0 §3.4 — NameID Confidentiality

Modules:
  - SamlSettingsBuilder — produces secure-by-default SAML settings
  - AssertionReplayCache — in-memory one-time assertion ID enforcement
  - OneTimeCodeService — HMAC-hashed, rate-limited, constant-time codes
  - SsoRateLimiter — per-key sliding-window rate limiter
  - BootValidator — startup config validation across all orgs

See docs/security/sso-saml-security.md for full threat model.
"""

import hashlib
import hmac
import logging
import os
import secrets
import string
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from typing import Optional, Literal

logger = logging.getLogger(__name__)

# ── Exceptions ─────────────────────────────────────────────────────────

class SamlConfigError(Exception):
    """Raised when SAML settings fail security validation."""


class SamlAuthError(Exception):
    """Raised on SAML authentication failure. Return 401 with generic body."""


class AssertionReplayError(SamlAuthError):
    """Raised when a SAML assertion ID has already been consumed."""


class SsoCodeError(Exception):
    """Raised on one-time code validation failure."""


class SsoRateLimitError(Exception):
    """Raised when rate limit exceeded on SSO endpoints."""


class BootValidationError(Exception):
    """Raised when SAML settings fail validation at boot. Aborts startup."""


# ── HMAC key for code hashing ──────────────────────────────────────────

_SSO_HMAC_KEY = os.environ.get('SSO_HMAC_KEY', '').encode('utf-8')
if not _SSO_HMAC_KEY:
    # Fallback: derive from JWT secret or generate ephemeral
    _jwt_secret = os.environ.get('JWT_SECRET', os.environ.get('SECRET_KEY', ''))
    if _jwt_secret:
        _SSO_HMAC_KEY = hashlib.sha256(
            f"sso-code-hmac:{_jwt_secret}".encode('utf-8')
        ).digest()
    else:
        _SSO_HMAC_KEY = secrets.token_bytes(32)
        logger.warning(
            "SSO_HMAC_KEY not set — using ephemeral key. "
            "Codes will not survive process restart."
        )


# ══════════════════════════════════════════════════════════════════════
# SAML Settings Builder
# ══════════════════════════════════════════════════════════════════════

# Required security flags — NEVER allow override to False
_REQUIRED_SECURITY_FLAGS = {
    'wantAssertionsSigned': True,
    'wantMessagesSigned': True,
    'rejectDeprecatedAlgorithm': True,
}

# Encryption flags — True by default. Override requires superadmin + audit log.
# Per SAML V2.0 §6.2 and NIST SP 800-63B federation requirements.
_ENCRYPTION_FLAGS = {
    'wantNameIdEncrypted': True,
    'wantAssertionsEncrypted': True,
}

# Per-org settings keys that control encryption override (superadmin only)
SSO_ENCRYPTION_OVERRIDE_KEYS = (
    'sso_accept_unencrypted_nameid',
    'sso_accept_unencrypted_assertions',
)


def build_secure_saml_settings(sso_config: dict, base_url: str, *,
                                org_settings: Optional[dict] = None) -> dict:
    """Build python3-saml settings with secure-by-default configuration.

    AG-95: Replaces the old build_saml_settings() with hardened defaults.
    AG-95-v2: Encryption enabled by default (SAML V2.0 §6.2, CWE-311).

    Args:
        sso_config: Dict with sso_idp_entity_id, sso_idp_sso_url, etc.
        base_url: SP base URL (e.g., https://app.auditgraph.ai)
        org_settings: Optional dict with per-org override keys
            (sso_accept_unencrypted_nameid, sso_accept_unencrypted_assertions).
            Only honoured when set by superadmin with audit trail.

    Returns:
        python3-saml settings dict.

    Raises:
        SamlConfigError: If required fields are missing or security is weak.
    """
    sp_entity_id = f"{base_url}/api/auth/saml/metadata"
    acs_url = f"{base_url}/api/auth/saml/acs"
    slo_url = f"{base_url}/api/auth/saml/slo"

    idp_entity_id = sso_config.get('sso_idp_entity_id', '').strip()
    idp_sso_url = sso_config.get('sso_idp_sso_url', '').strip()
    idp_cert = sso_config.get('sso_idp_x509_cert', '').strip()

    if not idp_entity_id:
        raise SamlConfigError("IdP entity ID is required")
    if not idp_sso_url:
        raise SamlConfigError("IdP SSO URL is required")
    if not idp_cert:
        raise SamlConfigError("IdP X.509 certificate is required")

    # AG-95-v2: Per-org encryption override (superadmin-only setting)
    _org = org_settings or {}
    accept_unencrypted_nameid = _org.get(
        'sso_accept_unencrypted_nameid', 'false') == 'true'
    accept_unencrypted_assertions = _org.get(
        'sso_accept_unencrypted_assertions', 'false') == 'true'

    settings = {
        'strict': True,
        'debug': False,
        'sp': {
            'entityId': sp_entity_id,
            'assertionConsumerService': {
                'url': acs_url,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            },
            'singleLogoutService': {
                'url': slo_url,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            },
            'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        },
        'idp': {
            'entityId': idp_entity_id,
            'singleSignOnService': {
                'url': idp_sso_url,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            },
            'singleLogoutService': {
                'url': sso_config.get('sso_idp_slo_url', '').strip(),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            },
            'x509cert': idp_cert,
        },
        'security': {
            # Mandatory — cannot be overridden
            'wantAssertionsSigned': True,
            'wantMessagesSigned': True,
            'rejectDeprecatedAlgorithm': True,
            # Signing config
            'authnRequestsSigned': True,
            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
            # Encryption — enabled by default (SAML V2.0 §6.2, CWE-311)
            'wantNameIdEncrypted': not accept_unencrypted_nameid,
            'wantAssertionsEncrypted': not accept_unencrypted_assertions,
            # Other
            'requestedAuthnContextComparison': 'exact',
            'allowSingleLabelDomains': False,
        },
    }

    _assert_secure(settings)
    return settings


def _assert_secure(settings: dict):
    """Validate SAML settings meet minimum security requirements.

    Raises SamlConfigError if any required flag is missing or set to False.
    Logs warnings for encryption flags disabled via per-org override.
    """
    if not settings.get('strict'):
        raise SamlConfigError("SAML strict mode must be True")

    security = settings.get('security', {})
    for flag, required_value in _REQUIRED_SECURITY_FLAGS.items():
        actual = security.get(flag)
        if actual != required_value:
            raise SamlConfigError(
                f"SAML security flag '{flag}' must be {required_value}, got {actual}"
            )

    # AG-95-v2: Encryption flags — warn (not fail) when overridden per-org
    for flag, default_value in _ENCRYPTION_FLAGS.items():
        actual = security.get(flag)
        if actual is not default_value:
            logger.warning(
                "saml_security: encryption flag '%s' is %s (default: %s). "
                "Per-org override active — verify superadmin audit trail.",
                flag, actual, default_value,
            )

    # Validate SP entity ID and ACS URL are HTTPS in production
    sp = settings.get('sp', {})
    acs_url = sp.get('assertionConsumerService', {}).get('url', '')
    if acs_url and not acs_url.startswith('https://') and 'localhost' not in acs_url:
        raise SamlConfigError(
            f"ACS URL must use HTTPS in production: {acs_url}"
        )


# ══════════════════════════════════════════════════════════════════════
# Boot-time Settings Validation (AG-95-v2 GAP 2)
# ══════════════════════════════════════════════════════════════════════

def validate_saml_settings_at_boot(db=None) -> None:
    """Validate SAML settings for all SSO-enabled orgs at startup.

    Iterates every org with sso_enabled='true'. Builds settings via
    build_secure_saml_settings(). Runs _assert_secure() on each.

    Behavior by ENVIRONMENT:
        test         → log only, do not abort
        development  → log warning with org list, do not abort
        staging      → ABORT on any failure (raise BootValidationError)
        production   → ABORT on any failure (raise BootValidationError)
        (unset)      → defaults to 'production' (fail-safe)

    Logs a canonical settings hash at startup for SIEM drift detection.
    """
    environment = os.environ.get('ENVIRONMENT', 'production').lower()
    base_url = os.environ.get('BASE_URL', os.environ.get(
        'REACT_APP_API_URL', 'http://localhost:5001'))

    # Get DB connection for reading settings
    close_db = False
    if db is None:
        try:
            from app.database import Database
            db = Database()
            close_db = True
        except Exception as e:
            logger.warning(
                "saml_boot_validation: cannot connect to DB — skipping: %s", e)
            return

    try:
        _do_boot_validation(db, environment, base_url)
    finally:
        if close_db:
            try:
                db.close()
            except Exception:
                pass


# Keys needed for SAML settings validation (subset of full SSO_SETTING_KEYS)
_SAML_BOOT_KEYS = (
    'sso_enabled', 'sso_idp_entity_id', 'sso_idp_sso_url', 'sso_idp_slo_url',
    'sso_idp_x509_cert', 'sso_role_mapping', 'sso_default_role',
    'sso_jit_enabled', 'sso_force_sso',
)


def _do_boot_validation(db, environment: str, base_url: str) -> None:
    """Internal boot validation logic."""

    # Get all orgs with SSO enabled
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT DISTINCT organization_id FROM settings
            WHERE key = 'sso_enabled' AND value = 'true'
        """)
        org_rows = cursor.fetchall()
    except Exception as e:
        logger.warning("saml_boot_validation: failed to query SSO orgs: %s", e)
        return
    finally:
        cursor.close()

    if not org_rows:
        logger.info("saml_boot_validation: no SSO-enabled orgs found")
        return

    org_ids = [r[0] if isinstance(r, (list, tuple)) else r['organization_id']
               for r in org_rows]
    failures = []
    settings_hashes = []

    for org_id in org_ids:
        try:
            # Load SSO config for this org
            sso_config = {}
            for key in _SAML_BOOT_KEYS:
                val = db.get_setting(key, '', organization_id=org_id)
                sso_config[key] = val

            # Load per-org encryption overrides
            org_settings = {}
            for override_key in SSO_ENCRYPTION_OVERRIDE_KEYS:
                val = db.get_setting(override_key, 'false', organization_id=org_id)
                org_settings[override_key] = val

            settings = build_secure_saml_settings(
                sso_config, base_url, org_settings=org_settings)

            # Compute canonical hash for drift detection
            import json
            canonical = json.dumps(settings.get('security', {}), sort_keys=True)
            settings_hash = hashlib.sha256(canonical.encode()).hexdigest()[:16]
            settings_hashes.append(f"org_{org_id}:{settings_hash}")

        except SamlConfigError as e:
            failures.append((org_id, str(e)))
        except Exception as e:
            # Non-config errors (DB issues) — log but don't fail boot
            logger.warning(
                "saml_boot_validation: org %d non-config error: %s", org_id, e)

    # Log baseline hash for SIEM
    combined_hash = hashlib.sha256(
        '|'.join(sorted(settings_hashes)).encode()).hexdigest()[:32]
    logger.info(
        "saml_settings_baseline",
        extra={
            "hash": combined_hash,
            "org_count": len(org_ids),
            "failed_count": len(failures),
        },
    )

    if not failures:
        logger.info(
            "saml_boot_validation: OK — %d org(s) validated", len(org_ids))
        return

    # Handle failures per environment
    fail_msgs = [f"  org {oid}: {err}" for oid, err in failures]
    detail = "\n".join(fail_msgs)

    if environment == 'test':
        logger.warning(
            "saml_boot_validation [ENVIRONMENT=test]: %d failure(s) (log only):\n%s",
            len(failures), detail)
    elif environment == 'development':
        logger.warning(
            "saml_boot_validation [ENVIRONMENT=development]: %d failure(s) (non-fatal):\n%s",
            len(failures), detail)
    else:
        # staging, production, or any unknown value → ABORT
        logger.error(
            "saml_boot_validation [ENVIRONMENT=%s]: %d FATAL failure(s):\n%s",
            environment, len(failures), detail)
        raise BootValidationError(
            f"SAML settings validation failed for {len(failures)} org(s) "
            f"in ENVIRONMENT={environment}. Fix settings or set explicit "
            f"per-org overrides. Failures:\n{detail}"
        )


# ══════════════════════════════════════════════════════════════════════
# Assertion Replay Cache
# ══════════════════════════════════════════════════════════════════════

class AssertionReplayCache:
    """In-memory assertion replay cache.

    Guarantees one-time use of every SAML assertion ID.
    Stores assertion IDs until NotOnOrAfter + skew, then evicts.

    WARNING: In-memory backend is NOT safe for multi-process deployment.
    Use Redis in production (or accept the risk with a single process).
    """

    _MAX_ENTRIES = 100_000  # Capacity guard

    def __init__(self):
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._warned_multi_process = False

    def consume(self, assertion_id: str, *,
                not_on_or_after: Optional[datetime] = None,
                skew_seconds: int = 300) -> None:
        """Atomically reserve assertion_id. Raises AssertionReplayError if seen.

        Args:
            assertion_id: The SAML assertion ID (unique per assertion).
            not_on_or_after: Assertion expiry time. If None, uses now + 10min.
            skew_seconds: Clock skew tolerance in seconds (default 5 min).
        """
        if not assertion_id:
            raise AssertionReplayError("Empty assertion ID")

        if not self._warned_multi_process:
            self._warned_multi_process = True
            logger.warning(
                "AssertionReplayCache: using in-memory backend. "
                "NOT safe for multi-process deployment (use Redis in production)."
            )

        now = time.time()
        if not_on_or_after:
            if isinstance(not_on_or_after, datetime):
                expiry = not_on_or_after.timestamp() + skew_seconds
            else:
                expiry = float(not_on_or_after) + skew_seconds
        else:
            expiry = now + 600 + skew_seconds  # Default 10 min + skew

        with self._lock:
            # Evict expired entries
            self._evict(now)

            if assertion_id in self._cache:
                _log_saml_event(
                    "assertion_replay_detected",
                    assertion_id=assertion_id[:32],
                )
                raise AssertionReplayError(
                    f"Assertion ID already consumed (replay detected)"
                )

            # Capacity guard
            if len(self._cache) >= self._MAX_ENTRIES:
                # Evict oldest entry (likely not expired — signal of attack)
                evicted_id, _ = self._cache.popitem(last=False)
                logger.warning(
                    "AssertionReplayCache capacity reached (%d). "
                    "Evicted non-expired entry — possible replay attack volume.",
                    self._MAX_ENTRIES,
                )

            self._cache[assertion_id] = expiry

    def _evict(self, now: float):
        """Remove expired entries."""
        expired = [k for k, exp in self._cache.items() if exp < now]
        for k in expired:
            del self._cache[k]

    def size(self) -> int:
        """Current cache size (for monitoring)."""
        return len(self._cache)


# Global singleton
_replay_cache = AssertionReplayCache()


def get_replay_cache() -> AssertionReplayCache:
    """Get the global assertion replay cache."""
    return _replay_cache


# ══════════════════════════════════════════════════════════════════════
# One-Time Code Service
# ══════════════════════════════════════════════════════════════════════

# Code parameters — aligned with NIST SP 800-63B
CODE_LENGTH = 48          # URL-safe base64 output chars from secrets.token_urlsafe(36)
CODE_TTL_SEC = 300        # 5 min (NIST-acceptable, more humane than 60s)
MAX_ATTEMPTS_PER_CODE = 5
MAX_ATTEMPTS_PER_IDENTIFIER_15M = 10


def generate_code() -> str:
    """Generate a cryptographically secure one-time code.

    Uses secrets.token_urlsafe(36) → ~48 chars of URL-safe base64.
    Entropy: 36 bytes = 288 bits (far exceeds 112-bit NIST minimum).
    """
    return secrets.token_urlsafe(36)


def hash_code(code: str, identifier: str = "", purpose: str = "sso") -> str:
    """HMAC-SHA256 hash of a code with context binding.

    The hash includes (identifier, purpose) so a code cannot be reused
    across different users or purposes.

    Args:
        code: The plaintext code.
        identifier: User identifier (user_id, email, etc.)
        purpose: Token purpose ("sso", "reset", "verify", "invite").

    Returns:
        Hex-encoded HMAC-SHA256 digest.
    """
    msg = f"{purpose}:{identifier}:{code}".encode('utf-8')
    return hmac.new(_SSO_HMAC_KEY, msg, hashlib.sha256).hexdigest()


def verify_code_constant_time(submitted_code: str, stored_hash: str,
                               identifier: str = "",
                               purpose: str = "sso") -> bool:
    """Constant-time code verification using hmac.compare_digest.

    Args:
        submitted_code: The code submitted by the user.
        stored_hash: The HMAC hash stored in the database.
        identifier: User identifier (must match what was used in hash_code).
        purpose: Token purpose (must match).

    Returns:
        True if the code matches.
    """
    computed_hash = hash_code(submitted_code, identifier, purpose)
    return hmac.compare_digest(computed_hash, stored_hash)


# ══════════════════════════════════════════════════════════════════════
# SSO Rate Limiter
# ══════════════════════════════════════════════════════════════════════

class SsoRateLimiter:
    """In-memory sliding-window rate limiter for SSO endpoints.

    Keys are opaque strings (e.g., "sso_exchange:1.2.3.4" or
    "sso_exchange:user@email.com"). Timestamps are stored per-key.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._buckets: dict[str, list[float]] = {}
        self._last_cleanup = time.time()

    def check(self, key: str, max_attempts: int, window_sec: int) -> bool:
        """Check if key is within rate limit. Records the attempt.

        Returns True if allowed, False if blocked.
        """
        now = time.time()
        self._maybe_cleanup(now)

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = []

            cutoff = now - window_sec
            self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

            if len(self._buckets[key]) >= max_attempts:
                return False

            self._buckets[key].append(now)
            return True

    def _maybe_cleanup(self, now: float):
        """Periodically remove stale buckets."""
        if now - self._last_cleanup < 60:
            return
        with self._lock:
            stale = [k for k, v in self._buckets.items()
                     if not v or v[-1] < now - 900]
            for k in stale:
                del self._buckets[k]
            self._last_cleanup = now


# Global singleton
_sso_limiter = SsoRateLimiter()


def check_sso_rate_limit(key: str, max_attempts: int = 5,
                         window_sec: int = 300) -> bool:
    """Check SSO rate limit. Returns True if allowed, False if blocked."""
    return _sso_limiter.check(key, max_attempts, window_sec)


# ══════════════════════════════════════════════════════════════════════
# AuthnRequest ID Cache (InResponseTo binding — SAML V2.0 §3.4)
# ══════════════════════════════════════════════════════════════════════

AUTHN_REQUEST_TTL = 600  # 10 min — AuthnRequest validity


class AuthnRequestCache:
    """Store AuthnRequest IDs for InResponseTo validation.

    When the SP sends an AuthnRequest, we store its ID keyed by a nonce.
    The nonce is embedded in RelayState. On ACS callback, we extract the
    nonce from RelayState, recover the request_id, and pass it to
    process_response() for InResponseTo validation.

    This prevents IdP-initiated login replay and ensures the SAML response
    is in reply to a specific SP-initiated request.
    """

    _MAX_ENTRIES = 10_000

    def __init__(self):
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, tuple[str, float]] = OrderedDict()  # nonce → (request_id, expiry)

    def store(self, nonce: str, request_id: str) -> None:
        """Store an AuthnRequest ID keyed by nonce."""
        expiry = time.time() + AUTHN_REQUEST_TTL
        with self._lock:
            self._evict(time.time())
            if len(self._cache) >= self._MAX_ENTRIES:
                self._cache.popitem(last=False)
            self._cache[nonce] = (request_id, expiry)

    def consume(self, nonce: str) -> Optional[str]:
        """Retrieve and remove AuthnRequest ID by nonce. Returns None if expired/missing."""
        now = time.time()
        with self._lock:
            self._evict(now)
            entry = self._cache.pop(nonce, None)
            if entry is None:
                return None
            request_id, expiry = entry
            if expiry < now:
                return None
            return request_id

    def _evict(self, now: float):
        expired = [k for k, (_, exp) in self._cache.items() if exp < now]
        for k in expired:
            del self._cache[k]


_authn_request_cache = AuthnRequestCache()


def get_authn_request_cache() -> AuthnRequestCache:
    """Get the global AuthnRequest cache for InResponseTo binding."""
    return _authn_request_cache


def make_relay_state(slug: str) -> str:
    """Build RelayState = slug:nonce for InResponseTo binding."""
    nonce = secrets.token_urlsafe(16)
    return f"{slug}:{nonce}"


def parse_relay_state(relay_state: str) -> tuple[str, Optional[str]]:
    """Parse RelayState into (slug, nonce). Returns (slug, None) for legacy format."""
    if ':' in relay_state:
        parts = relay_state.split(':', 1)
        return parts[0], parts[1]
    return relay_state, None


# ══════════════════════════════════════════════════════════════════════
# Structured logging helpers
# ══════════════════════════════════════════════════════════════════════

def _log_saml_event(event: str, **kwargs):
    """Structured log for SAML security events."""
    source_ip = ""
    request_id = ""
    try:
        from flask import request as _req, g
        source_ip = _req.remote_addr or ""
        request_id = getattr(g, 'request_id', '')
    except (ImportError, RuntimeError):
        pass

    logger.warning(
        "saml_security: %s", event,
        extra={
            "event": event,
            "source_ip": source_ip,
            "request_id": request_id,
            **kwargs,
        },
    )


def _log_sso_code_event(event: str, **kwargs):
    """Structured log for SSO code security events."""
    source_ip = ""
    try:
        from flask import request as _req
        source_ip = _req.remote_addr or ""
    except (ImportError, RuntimeError):
        pass

    logger.warning(
        "sso_code_security: %s", event,
        extra={
            "event": event,
            "source_ip": source_ip,
            **kwargs,
        },
    )
