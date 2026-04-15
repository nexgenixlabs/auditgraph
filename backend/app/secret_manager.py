"""
Phase 1 Security Hardening: Secrets Management Abstraction

Provides a unified interface for secret retrieval that works across
all environments:

    local/dev  → Environment variables (loaded from .env files via config.py)
    stg/prod   → Azure Key Vault (via DefaultAzureCredential)

Usage:
    from app.secret_manager import get_secret

    db_password = get_secret('DB_PASSWORD')
    jwt_key = get_secret('ADMIN_JWT_SECRET')

The Azure Key Vault client is lazily initialized on first use.
If Key Vault is not configured (no AZURE_KEY_VAULT_URL), all calls
fall back to environment variables — this is the expected behavior
for local development.

IMPORTANT: This module supplements the container-runtime secret injection
documented in config.py. For most secrets, the container runtime injects
Key Vault values as env vars automatically. This module provides programmatic
access for cases where runtime injection is insufficient (e.g., rotated
secrets that need refresh without restart).
"""

import os
import logging
import time
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ── In-memory cache for Key Vault lookups ────────────────────────────
_CACHE_TTL_SECONDS = 300  # 5-minute TTL

_cache: dict[str, tuple[str, float]] = {}  # name → (value, expires_at)
_cache_lock = threading.Lock()


def _cache_get(name: str) -> Optional[str]:
    """Return cached value if present and not expired."""
    with _cache_lock:
        entry = _cache.get(name)
        if entry and entry[1] > time.time():
            return entry[0]
        if entry:
            del _cache[name]
    return None


def _cache_set(name: str, value: str):
    """Store a value in cache with TTL."""
    with _cache_lock:
        _cache[name] = (value, time.time() + _CACHE_TTL_SECONDS)


# Map env var names to Key Vault secret names
_ENV_TO_KV_MAP = {
    'DB_PASSWORD': 'db-password',
    'DB_ADMIN_PASSWORD': 'db-admin-password',
    'ADMIN_JWT_SECRET': 'admin-jwt-secret',
    'CLIENT_JWT_SECRET': 'client-jwt-secret',
    'AZURE_CLIENT_SECRET': 'azure-client-secret',
    'COPILOT_API_KEY': 'copilot-api-key',
    'STRIPE_SECRET_KEY': 'stripe-secret-key',
    'SLACK_WEBHOOK_URL': 'slack-webhook-url',
    'TEAMS_WEBHOOK_URL': 'teams-webhook-url',
    'SENDGRID_API_KEY': 'sendgrid-api-key',
}

# Lazy-initialized Key Vault client
_kv_client = None
_kv_lock = threading.Lock()
_kv_init_attempted = False


def _get_kv_client():
    """Lazily initialize Azure Key Vault SecretClient.
    Returns None if Key Vault is not configured or SDK is unavailable."""
    global _kv_client, _kv_init_attempted

    if _kv_init_attempted:
        return _kv_client

    with _kv_lock:
        if _kv_init_attempted:
            return _kv_client

        _kv_init_attempted = True
        vault_url = os.getenv('AZURE_KEY_VAULT_URL')

        if not vault_url:
            logger.debug("AZURE_KEY_VAULT_URL not set — secrets will use env vars only")
            return None

        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient

            credential = DefaultAzureCredential()
            _kv_client = SecretClient(vault_url=vault_url, credential=credential)
            logger.info("Azure Key Vault client initialized: %s", vault_url)
        except ImportError:
            logger.warning(
                "azure-identity or azure-keyvault-secrets not installed — "
                "falling back to env vars"
            )
        except Exception as e:
            logger.error("Failed to initialize Key Vault client: %s", e)

        return _kv_client


def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieve a secret by env var name.

    Resolution order:
        1. Environment variable (always checked first — container-runtime injection)
        2. Azure Key Vault (if configured and env var is empty)
        3. Default value

    Args:
        name: Environment variable name (e.g., 'DB_PASSWORD')
        default: Fallback value if secret not found anywhere

    Returns:
        Secret value, or default if not found.
    """
    # 1. Environment variable (highest priority — container runtime injects here)
    value = os.getenv(name)
    if value:
        return value

    # 2. In-memory cache (avoids repeated Key Vault round-trips)
    cached = _cache_get(name)
    if cached is not None:
        return cached

    # 3. Azure Key Vault
    kv_name = _ENV_TO_KV_MAP.get(name)
    if kv_name:
        client = _get_kv_client()
        if client:
            try:
                secret = client.get_secret(kv_name)
                if secret and secret.value:
                    _cache_set(name, secret.value)
                    return secret.value
            except Exception as e:
                logger.warning("Key Vault lookup failed for %s: %s", kv_name, e)

    # 4. Default
    return default


def list_secret_names() -> list[str]:
    """Return the list of known secret names (for health checks / diagnostics).
    Never returns actual secret values."""
    return sorted(_ENV_TO_KV_MAP.keys())


def check_secrets_health() -> dict:
    """Check which secrets are available (without exposing values).
    Returns a dict of {name: 'configured' | 'missing'} for health endpoints."""
    result = {}
    for env_name in sorted(_ENV_TO_KV_MAP.keys()):
        value = os.getenv(env_name)
        result[env_name] = 'configured' if value else 'missing'
    return result
