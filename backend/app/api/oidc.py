"""
Phase 17: OIDC / OpenID Connect SSO Support
Mirrors the SAML pattern in saml.py — provider presets, config loading,
authorization URL building, code exchange, user info extraction, role mapping.
"""
import logging
import json
import requests

logger = logging.getLogger(__name__)

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


def exchange_oidc_code(oidc_config, code, redirect_uri):
    """Exchange authorization code for tokens. Returns dict with id_token_claims and userinfo."""
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
        logger.error(f"OIDC token exchange failed: {e}")
        return None

    # Decode ID token (without verification — the token endpoint is trusted)
    id_token_claims = {}
    id_token = token_data.get('id_token')
    if id_token:
        try:
            import jwt as pyjwt
            id_token_claims = pyjwt.decode(id_token, options={"verify_signature": False})
        except Exception as e:
            logger.warning(f"Failed to decode id_token: {e}")

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
            logger.warning(f"Failed to fetch userinfo: {e}")

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
