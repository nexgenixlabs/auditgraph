"""
Phase 1 Security Hardening: Snapshot Integrity

Provides hash computation and signature verification for discovery run
snapshots, ensuring immutability and tamper detection.

Integrity model:
    snapshot_hash = SHA-256(run_id | subscription_id | started_at |
                           completed_at | total_identities | critical_count |
                           high_count | medium_count | low_count |
                           organization_id)

    snapshot_signature = HMAC-SHA-256(snapshot_hash, signing_key)

The signing key is derived from CLIENT_JWT_SECRET to avoid introducing
a new secret. In production, a dedicated signing key from Key Vault
can be configured via SNAPSHOT_SIGNING_KEY env var.

Database enforcement:
    - Migration adds snapshot_hash + snapshot_signature columns
    - Trigger prevents UPDATE on completed runs (immutability)
    - verify_snapshot() re-computes hash and compares
"""

import hashlib
import hmac
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Signing key: dedicated key or fallback to CLIENT_JWT_SECRET
_SIGNING_KEY: Optional[bytes] = None


def _get_signing_key() -> bytes:
    """Get the snapshot signing key (lazy, cached)."""
    global _SIGNING_KEY
    if _SIGNING_KEY is None:
        key_str = os.getenv('SNAPSHOT_SIGNING_KEY') or os.getenv('CLIENT_JWT_SECRET', '')
        _SIGNING_KEY = key_str.encode('utf-8')
    return _SIGNING_KEY


def compute_snapshot_hash(run: dict) -> str:
    """Compute SHA-256 hash of a discovery run's immutable fields.

    Args:
        run: dict with keys: id, subscription_id, started_at, completed_at,
             total_identities, critical_count, high_count, medium_count,
             low_count, organization_id

    Returns:
        Hex-encoded SHA-256 hash string (64 chars)
    """
    canonical = '|'.join([
        str(run.get('id', '')),
        str(run.get('subscription_id', '')),
        str(run.get('started_at', '')),
        str(run.get('completed_at', '')),
        str(run.get('total_identities', '')),
        str(run.get('critical_count', '')),
        str(run.get('high_count', '')),
        str(run.get('medium_count', '')),
        str(run.get('low_count', '')),
        str(run.get('organization_id', '')),
    ])
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def compute_snapshot_signature(snapshot_hash: str) -> str:
    """Compute HMAC-SHA-256 signature over the snapshot hash.

    Args:
        snapshot_hash: Hex-encoded SHA-256 hash from compute_snapshot_hash()

    Returns:
        Hex-encoded HMAC-SHA-256 signature (64 chars)
    """
    key = _get_signing_key()
    return hmac.new(key, snapshot_hash.encode('utf-8'), hashlib.sha256).hexdigest()


def sign_snapshot(run: dict) -> tuple[str, str]:
    """Compute hash and signature for a discovery run.

    Returns:
        (snapshot_hash, snapshot_signature) tuple
    """
    h = compute_snapshot_hash(run)
    s = compute_snapshot_signature(h)
    return h, s


def verify_snapshot(run: dict) -> dict:
    """Verify the integrity of a discovery run snapshot.

    Args:
        run: dict with all discovery_run fields including snapshot_hash
             and snapshot_signature

    Returns:
        dict with: valid (bool), hash_match (bool), signature_match (bool),
                   expected_hash, stored_hash, error (str|None)
    """
    stored_hash = run.get('snapshot_hash')
    stored_sig = run.get('snapshot_signature')

    if not stored_hash:
        return {
            'valid': False,
            'hash_match': False,
            'signature_match': False,
            'error': 'No snapshot_hash stored — run predates integrity enforcement',
        }

    expected_hash = compute_snapshot_hash(run)
    hash_match = hmac.compare_digest(stored_hash, expected_hash)

    signature_match = False
    if stored_sig:
        expected_sig = compute_snapshot_signature(expected_hash)
        signature_match = hmac.compare_digest(stored_sig, expected_sig)

    valid = hash_match and (signature_match if stored_sig else True)

    result = {
        'valid': valid,
        'hash_match': hash_match,
        'signature_match': signature_match,
        'expected_hash': expected_hash,
        'stored_hash': stored_hash,
    }

    if not hash_match:
        result['error'] = 'Snapshot hash mismatch — data may have been tampered with'
        logger.warning(
            "Snapshot integrity violation: run_id=%s expected=%s stored=%s",
            run.get('id'), expected_hash, stored_hash,
        )
    elif stored_sig and not signature_match:
        result['error'] = 'Snapshot signature mismatch — signing key may have changed'

    return result
