"""
Field-Level Encryption — Fernet symmetric encryption for sensitive data at rest.

Encrypts: cloud connector credentials, refresh tokens, client secrets.
Key source: ENCRYPTION_KEY env var (base64-encoded 32-byte key) or Azure Key Vault.

Usage:
    from app.encryption import encrypt_field, decrypt_field

    encrypted = encrypt_field("my-secret-value")
    plaintext = decrypt_field(encrypted)

Encrypted values are prefixed with 'enc:' to distinguish from plaintext.
This allows gradual migration — decrypt_field handles both encrypted and
plaintext values transparently.
"""
import base64
import logging
import os

from cryptography.fernet import Fernet, MultiFernet, InvalidToken

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

_fernet_instance = None
_key_loaded = False


def _load_key():
    """Load or generate the Fernet encryption key(s).

    Priority:
    1. ENCRYPTION_KEYS env var (comma-separated, newest first) → MultiFernet
    2. ENCRYPTION_KEY env var (single key) → Fernet (backward compatible)
    3. ENCRYPTION_KEY_FILE path to key file → Fernet
    4. Generate ephemeral key (development only — logs warning)

    When ENCRYPTION_KEYS is set, MultiFernet is used:
      - Encryption always uses the FIRST (newest) key
      - Decryption tries all keys in order (supports rotation)
      - Format: NEW_KEY,OLD_KEY_1,OLD_KEY_2
    """
    global _fernet_instance, _key_loaded

    if _key_loaded:
        return _fernet_instance

    # Check for multi-key rotation support first
    multi_keys = os.getenv('ENCRYPTION_KEYS')
    if multi_keys:
        keys = [k.strip() for k in multi_keys.split(',') if k.strip()]
        if keys:
            try:
                fernets = [Fernet(k.encode() if isinstance(k, str) else k) for k in keys]
                _fernet_instance = MultiFernet(fernets)
                _key_loaded = True
                logger.info("Field encryption initialized with %d key(s) (MultiFernet)", len(keys))
                return _fernet_instance
            except Exception as e:
                logger.error("Invalid ENCRYPTION_KEYS: %s", e)
                _fernet_instance = None
                _key_loaded = True
                return None

    # Single key — backward compatible
    key = os.getenv('ENCRYPTION_KEY')

    if not key:
        key_file = os.getenv('ENCRYPTION_KEY_FILE')
        if key_file and os.path.exists(key_file):
            with open(key_file, 'r') as f:
                key = f.read().strip()
            logger.info("Encryption key loaded from file: %s", key_file)

    if not key:
        # Development fallback — generate ephemeral key
        if os.getenv('FLASK_ENV') == 'development':
            key = Fernet.generate_key().decode()
            logger.warning(
                "ENCRYPTION_KEY not set — using ephemeral key. "
                "Encrypted data will NOT survive restarts. "
                "Set ENCRYPTION_KEY env var for production."
            )
        else:
            logger.error(
                "ENCRYPTION_KEY not set in production. "
                "Field encryption is DISABLED. Set ENCRYPTION_KEY env var."
            )
            _key_loaded = True
            _fernet_instance = None
            return None

    try:
        _fernet_instance = Fernet(key.encode() if isinstance(key, str) else key)
        _key_loaded = True
        logger.info("Field encryption initialized")
    except Exception as e:
        logger.error("Invalid ENCRYPTION_KEY: %s", e)
        _fernet_instance = None
        _key_loaded = True

    return _fernet_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ENCRYPTED_PREFIX = 'enc:'


class EncryptionUnavailableError(RuntimeError):
    """Raised when a secret must be encrypted (production) but no key is configured.

    Fail-closed: we refuse to persist a credential in plaintext rather than
    silently degrading. Surfaces as a 5xx at the save path so the misconfig is
    loud instead of leaking secrets at rest.
    """


def _encryption_required() -> bool:
    """True in real deployments, where plaintext-at-rest is never acceptable.

    Mirrors _load_key()'s dev carve-out: only FLASK_ENV=development gets the
    ephemeral-key fallback, so anything explicitly production-like must encrypt.
    Local dev (FLASK_ENV unset/development) is left untouched.
    """
    return (os.getenv('FLASK_ENV', '').lower() == 'production'
            or os.getenv('APP_ENV', '').lower() in ('production', 'prod'))


def encrypt_field(plaintext):
    """Encrypt a string value. Returns 'enc:<base64>'.

    Args:
        plaintext: String value to encrypt. None/empty values pass through unchanged.

    Returns:
        Encrypted string prefixed with 'enc:'.

    Raises:
        EncryptionUnavailableError: in production when no key is configured —
        we will not store the secret in plaintext.
    """
    if not plaintext or not isinstance(plaintext, str):
        return plaintext

    # Already encrypted
    if plaintext.startswith(ENCRYPTED_PREFIX):
        return plaintext

    fernet = _load_key()
    if fernet is None:
        if _encryption_required():
            raise EncryptionUnavailableError(
                "ENCRYPTION_KEY is not configured; refusing to store a secret in "
                "plaintext. Set ENCRYPTION_KEY (a Fernet key) on the API."
            )
        return plaintext

    try:
        encrypted = fernet.encrypt(plaintext.encode('utf-8'))
        return ENCRYPTED_PREFIX + encrypted.decode('utf-8')
    except Exception as e:
        logger.error("Encryption failed: %s", e)
        if _encryption_required():
            raise EncryptionUnavailableError(f"Encryption failed: {e}") from e
        return plaintext


def decrypt_field(value):
    """Decrypt a field value. Handles both encrypted ('enc:...') and plaintext values.

    Args:
        value: Encrypted or plaintext string. None/empty values pass through.

    Returns:
        Decrypted plaintext string.
    """
    if not value or not isinstance(value, str):
        return value

    # Not encrypted — return as-is (allows gradual migration)
    if not value.startswith(ENCRYPTED_PREFIX):
        return value

    fernet = _load_key()
    if fernet is None:
        logger.warning("Cannot decrypt: encryption key not available")
        return value

    try:
        token = value[len(ENCRYPTED_PREFIX):].encode('utf-8')
        return fernet.decrypt(token).decode('utf-8')
    except InvalidToken:
        logger.error("Decryption failed: invalid token (key mismatch or corrupted data)")
        return value
    except Exception as e:
        logger.error("Decryption failed: %s", e)
        return value


def is_encrypted(value):
    """Check if a value is encrypted (has 'enc:' prefix)."""
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def encryption_available():
    """Check if encryption is configured and available."""
    return _load_key() is not None


def rotate_encrypted_field(value):
    """Re-encrypt a value with the current (newest) key.

    Use during key rotation to migrate data encrypted with an old key.
    MultiFernet.rotate() decrypts with any known key, then re-encrypts
    with the first (newest) key.

    Args:
        value: Encrypted string with 'enc:' prefix. Non-encrypted values
               pass through unchanged.

    Returns:
        Re-encrypted string with 'enc:' prefix, or original value if
        rotation is not possible.
    """
    if not value or not isinstance(value, str):
        return value

    if not value.startswith(ENCRYPTED_PREFIX):
        return value

    fernet = _load_key()
    if fernet is None:
        logger.warning("Cannot rotate: encryption key not available")
        return value

    if not isinstance(fernet, MultiFernet):
        # Single key — nothing to rotate
        return value

    try:
        token = value[len(ENCRYPTED_PREFIX):].encode('utf-8')
        rotated = fernet.rotate(token)
        return ENCRYPTED_PREFIX + rotated.decode('utf-8')
    except InvalidToken:
        logger.error("Key rotation failed: invalid token (no known key can decrypt)")
        return value
    except Exception as e:
        logger.error("Key rotation failed: %s", e)
        return value
