"""
Phase 54: SAML 2.0 SSO Helper Module

Wraps python3-saml (OneLogin) for AuditGraph's tenant-scoped SSO.
"""
import json
import urllib.parse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser


SSO_SETTING_KEYS = (
    'sso_enabled', 'sso_idp_entity_id', 'sso_idp_sso_url', 'sso_idp_slo_url',
    'sso_idp_x509_cert', 'sso_role_mapping', 'sso_default_role',
    'sso_jit_enabled', 'sso_force_sso',
)

# Standard SAML attribute URIs for common claims
ATTR_EMAIL = [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'email', 'Email', 'mail',
]
ATTR_DISPLAY_NAME = [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    'http://schemas.xmlsoap.org/claims/CommonName',
    'displayName', 'display_name', 'name',
]
ATTR_GROUPS = [
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    'http://schemas.xmlsoap.org/claims/Group',
    'groups', 'memberOf', 'Group',
]


def get_sso_config_for_org(db, organization_id):
    """Load SSO settings from the settings table for an organization. Returns dict or None."""
    config = {}
    for key in SSO_SETTING_KEYS:
        val = db.get_setting(key, '', organization_id=organization_id)
        config[key] = val
    if config.get('sso_enabled') != 'true':
        return None
    return config


def build_saml_settings(sso_config, base_url):
    """Transform DB SSO config into python3-saml settings dict."""
    sp_entity_id = f"{base_url}/api/auth/saml/metadata"
    acs_url = f"{base_url}/api/auth/saml/acs"
    slo_url = f"{base_url}/api/auth/saml/slo"

    return {
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
            'entityId': sso_config.get('sso_idp_entity_id', ''),
            'singleSignOnService': {
                'url': sso_config.get('sso_idp_sso_url', ''),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            },
            'singleLogoutService': {
                'url': sso_config.get('sso_idp_slo_url', ''),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            },
            'x509cert': sso_config.get('sso_idp_x509_cert', ''),
        },
        'security': {
            'authnRequestsSigned': True,
            'wantAssertionsSigned': True,
            'wantNameIdEncrypted': False,
        },
    }


def prepare_flask_request(flask_request):
    """Convert Flask request to dict expected by python3-saml."""
    url_data = urllib.parse.urlparse(flask_request.url)
    return {
        'https': 'on' if flask_request.scheme == 'https' else 'off',
        'http_host': flask_request.host,
        'server_port': url_data.port or (443 if flask_request.scheme == 'https' else 80),
        'script_name': flask_request.path,
        'get_data': flask_request.args.copy(),
        'post_data': flask_request.form.copy(),
    }


def get_saml_auth(sso_config, flask_request, base_url):
    """Build a OneLogin_Saml2_Auth from config + request."""
    settings = build_saml_settings(sso_config, base_url)
    req = prepare_flask_request(flask_request)
    return OneLogin_Saml2_Auth(req, settings)


def parse_idp_metadata_url(url):
    """Fetch and parse IdP metadata URL, return extracted config fields."""
    try:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse_remote(url)
        idp = parsed.get('idp', {})
        return {
            'idp_entity_id': idp.get('entityId', ''),
            'idp_sso_url': idp.get('singleSignOnService', {}).get('url', ''),
            'idp_slo_url': idp.get('singleLogoutService', {}).get('url', ''),
            'idp_x509_cert': idp.get('x509cert', ''),
        }
    except Exception as e:
        raise ValueError(f"Failed to parse IdP metadata: {str(e)}")


def extract_saml_attributes(auth):
    """Extract user attributes from a validated SAML assertion."""
    attrs = auth.get_attributes()
    name_id = auth.get_nameid()

    email = name_id  # NameID is typically email
    display_name = ''
    groups = []

    for key in ATTR_EMAIL:
        if key in attrs and attrs[key]:
            email = attrs[key][0]
            break

    for key in ATTR_DISPLAY_NAME:
        if key in attrs and attrs[key]:
            display_name = attrs[key][0]
            break

    for key in ATTR_GROUPS:
        if key in attrs and attrs[key]:
            groups = attrs[key]
            break

    return {
        'name_id': name_id,
        'email': email,
        'display_name': display_name or email.split('@')[0] if email else 'SSO User',
        'groups': groups,
    }


ROLE_PRIORITY = {'admin': 3, 'auditor': 2, 'viewer': 1}


def map_saml_role(sso_config, saml_groups):
    """Map IdP group claims to AuditGraph role using highest-priority match."""
    try:
        role_mapping = json.loads(sso_config.get('sso_role_mapping', '{}'))
    except (json.JSONDecodeError, TypeError):
        role_mapping = {}

    default_role = sso_config.get('sso_default_role', 'viewer')
    if default_role not in ROLE_PRIORITY:
        default_role = 'viewer'

    best_role = default_role
    best_priority = ROLE_PRIORITY.get(default_role, 0)

    for group in saml_groups:
        mapped = role_mapping.get(group)
        if mapped and ROLE_PRIORITY.get(mapped, 0) > best_priority:
            best_role = mapped
            best_priority = ROLE_PRIORITY[mapped]

    return best_role
