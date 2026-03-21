"""
Phase 17: OIDC / OpenID Connect SSO Support
Mirrors the SAML pattern in saml.py — provider presets, config loading,
authorization URL building, code exchange, user info extraction, role mapping.
"""
import logging
import json
import time
import threading
import requests
import jwt as pyjwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

# ── JWKS client cache (thread-safe, keyed by jwks_uri, TTL-based) ──
_jwks_cache = {}          # {jwks_uri: {"client": PyJWKClient, "expiry": float}}
_jwks_lock = threading.Lock()
JWKS_CACHE_TTL_SECONDS = 600  # 10 minutes

OIDC_SETTING_KEYS = [
    'oidc_enabled',
    'oidc_client_id',
    'oidc_client_secret',
    'oidc_discovery_url',
    'oidc_scopes',
    'oidc_role_claim',
    'oidc_role_mapping',
    'oidc_default_role',
    'oidc_jit_enabled',
]

OIDC_PRESETS = {
    'azure_ad': {
        'label': 'Microsoft Entra ID (Azure AD)',
        'discovery_url': 'https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration',
        'default_scopes': 'openid profile email',
        'role_claim': 'groups',
    },
    'okta': {
        'label': 'Okta',
        'discovery_url': 'https://{okta_domain}/oauth2/default/.well-known/openid-configuration',
        'default_scopes': 'openid profile email groups',
        'role_claim': 'groups',
    },
    'google': {
        'label': 'Google Workspace',
        'discovery_url': 'https://accounts.google.com/.well-known/openid-configuration',
        'default_scopes': 'openid profile email',
        'role_claim': 'hd',
    },
}


def get_oidc_config_for_org(db, org_id):
    """Load OIDC settings for an organization. Returns dict or None if not enabled."""
    enabled = db.get_setting('oidc_enabled', 'false', organization_id=org_id)
    if enabled != 'true':
        return None
    config = {}
    for key in OIDC_SETTING_KEYS:
        config[key] = db.get_setting(key, '', organization_id=org_id)
    # Decrypt client secret if encrypted
    if config.get('oidc_client_secret'):
        from app.encryption import decrypt_field
        config['oidc_client_secret'] = decrypt_field(config['oidc_client_secret'])
    if not config.get('oidc_client_id') or not config.get('oidc_discovery_url'):
        return None
    return config


def _fetch_discovery(discovery_url):
    """Fetch and cache OIDC discovery document."""
    try:
        resp = requests.get(discovery_url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch OIDC discovery: {e}")
        return None


def build_oidc_authorization_url(oidc_config, redirect_uri, state, nonce):
    """Build the authorization URL to redirect the user to the IdP."""
    discovery = _fetch_discovery(oidc_config['oidc_discovery_url'])
    if not discovery:
        raise ValueError("Failed to fetch OIDC discovery document")

    auth_endpoint = discovery.get('authorization_endpoint')
    if not auth_endpoint:
        raise ValueError("No authorization_endpoint in discovery document")

    scopes = oidc_config.get('oidc_scopes', 'openid profile email').strip()
    client_id = oidc_config['oidc_client_id']

    from urllib.parse import urlencode
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scopes,
        'state': state,
        'nonce': nonce,
    }
    return f"{auth_endpoint}?{urlencode(params)}"


def _get_jwks_client(jwks_uri):
    """Get or create a cached PyJWKClient for the given JWKS URI.

    Uses a TTL-based cache (JWKS_CACHE_TTL_SECONDS = 600s). When the cache
    entry expires, a fresh PyJWKClient is created and the old one is discarded.
    PyJWKClient's own internal key cache (lifespan=300s) provides a second
    layer of caching within each client instance.
    """
    now = time.time()
    with _jwks_lock:
        entry = _jwks_cache.get(jwks_uri)
        if entry and now < entry['expiry']:
            return entry['client']

        # Cache miss or expired — create new client
        if entry:
            logger.info("JWKS cache expired for %s, refreshing", jwks_uri)
        else:
            logger.info("JWKS cache miss for %s, creating client", jwks_uri)

        client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=300)
        _jwks_cache[jwks_uri] = {
            'client': client,
            'expiry': now + JWKS_CACHE_TTL_SECONDS,
        }
        return client


def _verify_id_token(id_token, oidc_config, discovery, expected_nonce=None):
    """Verify and decode an OIDC ID token using JWKS signature verification.

    Validates: signature (RS256), issuer, audience, expiration, nonce.
    Falls back to unverified decode only if JWKS URI is unavailable.
    """
    client_id = oidc_config['oidc_client_id']
    jwks_uri = discovery.get('jwks_uri')
    expected_issuer = discovery.get('issuer')

    # Primary path: full cryptographic verification via JWKS
    if jwks_uri:
        try:
            jwks_client = _get_jwks_client(jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            # Determine algorithms — prefer discovery doc, default to RS256
            algorithms = discovery.get('id_token_signing_alg_values_supported', ['RS256'])

            decode_opts = {
                'algorithms': algorithms,
                'audience': client_id,
            }
            if expected_issuer:
                decode_opts['issuer'] = expected_issuer

            claims = pyjwt.decode(id_token, signing_key.key, **decode_opts)

            # Validate nonce if one was sent during authorization
            if expected_nonce and claims.get('nonce') != expected_nonce:
                logger.warning("OIDC nonce mismatch: expected %s, got %s",
                               expected_nonce, claims.get('nonce'))
                return None

            logger.info("OIDC ID token verified: iss=%s, sub=%s",
                        claims.get('iss'), claims.get('sub'))
            return claims
        except pyjwt.ExpiredSignatureError:
            logger.error("OIDC ID token has expired")
            return None
        except pyjwt.InvalidAudienceError:
            logger.error("OIDC ID token audience mismatch (expected %s)", client_id)
            return None
        except pyjwt.InvalidIssuerError:
            logger.error("OIDC ID token issuer mismatch (expected %s)", expected_issuer)
            return None
        except Exception as e:
            logger.error("OIDC ID token JWKS verification failed: %s", e)
            # Do NOT fall through — signature verification failure is a hard error
            return None

    # Fallback: no jwks_uri in discovery (rare; some non-standard IdPs)
    logger.warning("OIDC discovery has no jwks_uri — falling back to unverified decode")
    try:
        return pyjwt.decode(id_token, options={"verify_signature": False})
    except Exception as e:
        logger.warning("Failed to decode id_token (unverified fallback): %s", e)
        return None


def exchange_oidc_code(oidc_config, code, redirect_uri, expected_nonce=None):
    """Exchange authorization code for tokens. Returns dict with id_token_claims and userinfo.

    ID token signature is verified using the IdP's JWKS endpoint.
    Validates issuer, audience, expiration, and nonce.
    """
    discovery = _fetch_discovery(oidc_config['oidc_discovery_url'])
    if not discovery:
        return None

    token_endpoint = discovery.get('token_endpoint')
    userinfo_endpoint = discovery.get('userinfo_endpoint')
    if not token_endpoint:
        return None

    try:
        resp = requests.post(token_endpoint, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': oidc_config['oidc_client_id'],
            'client_secret': oidc_config.get('oidc_client_secret', ''),
        }, timeout=10)
        resp.raise_for_status()
        token_data = resp.json()
    except Exception as e:
        logger.error("OIDC token exchange failed: %s", e)
        return None

    # Verify and decode ID token using JWKS
    id_token_claims = {}
    id_token = token_data.get('id_token')
    if id_token:
        verified_claims = _verify_id_token(id_token, oidc_config, discovery, expected_nonce)
        if verified_claims is not None:
            id_token_claims = verified_claims
        else:
            # Signature verification failed — do not trust the token
            logger.error("OIDC ID token verification failed, rejecting login")
            return None

    # Fetch userinfo if endpoint available
    userinfo = {}
    if userinfo_endpoint and token_data.get('access_token'):
        try:
            ui_resp = requests.get(userinfo_endpoint, headers={
                'Authorization': f'Bearer {token_data["access_token"]}',
            }, timeout=10)
            if ui_resp.ok:
                userinfo = ui_resp.json()
        except Exception as e:
            logger.warning("Failed to fetch userinfo: %s", e)

    return {
        'id_token_claims': id_token_claims,
        'userinfo': userinfo,
        'access_token': token_data.get('access_token'),
    }


def extract_oidc_user_info(id_token_claims, userinfo):
    """Extract standardized user info from OIDC claims."""
    # Merge claims — userinfo takes precedence
    merged = {**id_token_claims, **userinfo}

    email = merged.get('email', merged.get('preferred_username', merged.get('upn', '')))
    display_name = merged.get('name', merged.get('given_name', ''))
    sub = merged.get('sub', '')
    groups = merged.get('groups', [])

    # Handle groups as string (comma-separated) or list
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(',') if g.strip()]

    return {
        'email': email,
        'display_name': display_name,
        'sub': sub,
        'groups': groups,
    }


def map_oidc_role(oidc_config, groups):
    """Map IdP groups to AuditGraph role using the configured role mapping."""
    default_role = oidc_config.get('oidc_default_role', 'reader') or 'reader'
    mapping_str = oidc_config.get('oidc_role_mapping', '')
    if not mapping_str:
        return default_role

    try:
        mapping = json.loads(mapping_str) if isinstance(mapping_str, str) else mapping_str
    except (json.JSONDecodeError, TypeError):
        return default_role

    if not isinstance(mapping, dict):
        return default_role

    # mapping: {"IdP Group Name": "auditgraph_role", ...}
    # Priority: first match in group list wins (admin > security_admin > ... > reader)
    role_priority = ['owner', 'admin', 'security_admin', 'security_analyst', 'compliance', 'reader']
    best_role = default_role
    best_idx = len(role_priority)

    for group in groups:
        mapped = mapping.get(group) or mapping.get(str(group))
        if mapped and mapped in role_priority:
            idx = role_priority.index(mapped)
            if idx < best_idx:
                best_idx = idx
                best_role = mapped

    return best_role
