"""
SPN Discovery — unit tests for _discover_service_principals().

Verifies:
  1. SPNs with zero role assignments ARE returned (full-tenant discovery)
  2. Pagination via @odata.nextLink is followed
  3. Microsoft system apps are flagged with is_microsoft_system=True
  4. System-assigned managed identities are excluded
  5. User-assigned managed identities are kept
"""
import os
import json
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


# ── Helpers ─────────────────────────────────────────────────────────

MICROSOFT_TENANT_ID = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
CUSTOMER_TENANT_ID = '00000000-0000-0000-0000-000000000001'


def _make_sp(app_id, display_name, sp_type='Application',
             owner_org=None, alt_names=None, enabled=True):
    """Build a minimal SPN dict as returned by Graph API JSON."""
    return {
        'id': f'obj-{app_id}',
        'appId': app_id,
        'displayName': display_name,
        'accountEnabled': enabled,
        'createdDateTime': '2025-01-01T00:00:00Z',
        'servicePrincipalType': sp_type,
        'alternativeNames': alt_names or [],
        'appOwnerOrganizationId': owner_org,
        'publisherName': None,
        'signInActivity': None,
        'servicePrincipalNames': [f'api://{app_id}'],
        'tags': [],
        'passwordCredentials': [],
        'keyCredentials': [],
    }


def _build_engine():
    """Create an AzureDiscoveryEngine with mocked dependencies."""
    with patch('app.engines.discovery.azure_discovery.ClientSecretCredential') as MockCred, \
         patch('app.engines.discovery.azure_discovery.GraphServiceClient'), \
         patch('app.engines.discovery.azure_discovery.SubscriptionClient'), \
         patch('app.engines.discovery.azure_discovery.Database'):

        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = 'fake-bearer-token'
        mock_cred.get_token.return_value = mock_token
        MockCred.return_value = mock_cred

        from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
        engine = AzureDiscoveryEngine(
            azure_directory_id=CUSTOMER_TENANT_ID,
            client_id='test-client-id',
            client_secret='test-client-secret',
            db_org_id=1,
            cloud_connection_id=1,
        )
        # Ensure credential mock is used for get_token
        engine.credential = mock_cred
        return engine


class _FakeResponse:
    """Simulates an aiohttp response."""

    def __init__(self, json_data, status=200):
        self._json_data = json_data
        self.status = status

    async def json(self):
        return self._json_data

    async def text(self):
        return json.dumps(self._json_data)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class _FakeSession:
    """Simulates an aiohttp.ClientSession with pre-loaded pages."""

    def __init__(self, pages):
        self._pages = list(pages)
        self._call_idx = 0

    def get(self, url, **kwargs):
        if self._call_idx < len(self._pages):
            resp = self._pages[self._call_idx]
            self._call_idx += 1
            return _FakeResponse(resp)
        return _FakeResponse({'value': []})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


# ── Tests ───────────────────────────────────────────────────────────

class TestSPNDiscoveryPagination:
    """Verify @odata.nextLink pagination returns all SPNs."""

    def test_follows_nextlink(self):
        engine = _build_engine()

        page1 = {
            'value': [_make_sp('aaa', 'SPN-Page1', owner_org=CUSTOMER_TENANT_ID)],
            '@odata.nextLink': 'https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=page2',
        }
        page2 = {
            'value': [_make_sp('bbb', 'SPN-Page2', owner_org=CUSTOMER_TENANT_ID)],
        }

        with patch('aiohttp.ClientSession', return_value=_FakeSession([page1, page2])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        names = [r['display_name'] for r in result]
        assert 'SPN-Page1' in names
        assert 'SPN-Page2' in names
        assert len(result) == 2


class TestSPNDiscoveryNoRoleFilter:
    """Verify SPNs are returned regardless of role assignments."""

    def test_spn_without_roles_is_returned(self):
        engine = _build_engine()

        sp_no_roles = _make_sp('no-roles-app', 'NoRolesSPN', owner_org=CUSTOMER_TENANT_ID)

        page = {'value': [sp_no_roles]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        assert len(result) == 1
        assert result[0]['display_name'] == 'NoRolesSPN'
        assert result[0]['is_microsoft_system'] is False


class TestSPNDiscoveryMicrosoftFiltering:
    """Verify Microsoft system apps are flagged."""

    def test_microsoft_app_flagged(self):
        engine = _build_engine()

        ms_sp = _make_sp('ms-app-1', 'Microsoft Graph', owner_org=MICROSOFT_TENANT_ID)
        customer_sp = _make_sp('cust-app-1', 'My App', owner_org=CUSTOMER_TENANT_ID)

        page = {'value': [ms_sp, customer_sp]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        ms_result = [r for r in result if r['display_name'] == 'Microsoft Graph']
        cust_result = [r for r in result if r['display_name'] == 'My App']

        assert len(ms_result) == 1
        assert ms_result[0]['is_microsoft_system'] is True

        assert len(cust_result) == 1
        assert cust_result[0]['is_microsoft_system'] is False


class TestSPNDiscoveryManagedIdentities:
    """Verify SAMI exclusion and UAMI inclusion."""

    def test_system_assigned_mi_included_for_lineage(self):
        """SAMIs are now included (not excluded) for lineage mapping.
        They should be categorized as managed_identity_system."""
        engine = _build_engine()

        sami = _make_sp(
            'sami-app', 'my-vm-sami',
            sp_type='ManagedIdentity',
            alt_names=['isExplicit=True', '/subscriptions/.../providers/Microsoft.Compute/virtualMachines/my-vm'],
        )

        page = {'value': [sami]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        assert len(result) == 1
        assert result[0]['identity_category'] == 'managed_identity_system'
        assert result[0]['is_microsoft_system'] is False

    def test_user_assigned_mi_included(self):
        engine = _build_engine()

        uami = _make_sp(
            'uami-app', 'my-uami',
            sp_type='ManagedIdentity',
            alt_names=['isExplicit=True', '/subscriptions/.../providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-uami'],
        )

        page = {'value': [uami]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        assert len(result) == 1
        assert result[0]['identity_category'] == 'managed_identity_user'
        assert result[0]['is_microsoft_system'] is False


class TestSPNDiscoveryFields:
    """Verify new fields (servicePrincipalNames, tags, credentials) are captured."""

    def test_new_fields_present(self):
        engine = _build_engine()

        sp = _make_sp('field-test', 'FieldTestSPN', owner_org=CUSTOMER_TENANT_ID)
        sp['servicePrincipalNames'] = ['api://field-test', 'https://myapp.example.com']
        sp['tags'] = ['WindowsAzureActiveDirectoryIntegratedApp']
        sp['passwordCredentials'] = [{'keyId': 'k1', 'displayName': 'secret1'}]
        sp['keyCredentials'] = [{'keyId': 'k2', 'type': 'AsymmetricX509Cert'}]

        page = {'value': [sp]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        assert len(result) == 1
        r = result[0]
        assert r['service_principal_names'] == ['api://field-test', 'https://myapp.example.com']
        assert r['tags'] == ['WindowsAzureActiveDirectoryIntegratedApp']
        assert len(r['password_credentials']) == 1
        assert len(r['key_credentials']) == 1


class TestDiscoveryConnectorSPN:
    """Verify the discovery connector's own SPN is included and flagged."""

    def test_connector_spn_is_returned_and_flagged(self):
        """SPN whose app_id matches the engine's client_id must be present
        with is_discovery_connector=True and is_microsoft_system=False."""
        engine = _build_engine()

        # The engine's client_id is 'test-client-id' (set in _build_engine)
        connector_sp = _make_sp(
            'test-client-id', 'AuditGraph Discovery Connector',
            owner_org=CUSTOMER_TENANT_ID,
        )
        other_sp = _make_sp(
            'other-app', 'Some Other App',
            owner_org=CUSTOMER_TENANT_ID,
        )

        page = {'value': [connector_sp, other_sp]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        assert len(result) == 2

        conn = [r for r in result if r['app_id'] == 'test-client-id']
        assert len(conn) == 1
        assert conn[0]['is_discovery_connector'] is True
        assert conn[0]['is_microsoft_system'] is False

        other = [r for r in result if r['app_id'] == 'other-app']
        assert len(other) == 1
        assert other[0]['is_discovery_connector'] is False

    def test_connector_spn_not_flagged_as_microsoft_even_with_keyword_name(self):
        """Even if the connector SPN's display name contains Microsoft keywords
        (like 'discovery', 'connector', 'audit'), it must NOT be flagged as
        is_microsoft_system because is_discovery_connector takes precedence."""
        engine = _build_engine()

        # Name contains 'discovery', 'connector', 'audit' — all Microsoft keywords
        connector_sp = _make_sp(
            'test-client-id', 'AuditGraph Discovery Connector Service',
            owner_org=None,  # No owner org — would normally fall to keyword check
        )

        page = {'value': [connector_sp]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_service_principals()
            )

        assert len(result) == 1
        assert result[0]['is_discovery_connector'] is True
        assert result[0]['is_microsoft_system'] is False
        assert result[0]['identity_category'] == 'service_principal'


class _FakeRoutedSession:
    """Simulates an aiohttp session that routes by URL pattern.

    app_pages: sequential pages for /v1.0/applications listing.
    owner_responses: dict mapping object_id → owner response JSON.
    """

    def __init__(self, app_pages, owner_responses=None):
        self._app_pages = list(app_pages)
        self._app_idx = 0
        self._owner_responses = owner_responses or {}

    def get(self, url, **kwargs):
        if '/owners' in url:
            # Extract object_id from URL: /applications/{obj_id}/owners
            parts = url.split('/applications/')
            if len(parts) > 1:
                obj_id = parts[1].split('/owners')[0]
                if obj_id in self._owner_responses:
                    return _FakeResponse(self._owner_responses[obj_id])
            return _FakeResponse({'value': []})
        # App listing page
        if self._app_idx < len(self._app_pages):
            resp = self._app_pages[self._app_idx]
            self._app_idx += 1
            return _FakeResponse(resp)
        return _FakeResponse({'value': []})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class TestAppRegistrationLineage:
    """Verify SPN→App Registration lineage enrichment."""

    def test_fetch_app_registration_map(self):
        """_fetch_app_registration_map returns appId→object lookup with metadata."""
        engine = _build_engine()

        page = {
            'value': [
                {'id': 'app-obj-1', 'appId': 'aaa', 'displayName': 'App One',
                 'appOwnerOrganizationId': CUSTOMER_TENANT_ID,
                 'publisherDomain': 'contoso.com', 'signInAudience': 'AzureADMyOrg'},
                {'id': 'app-obj-2', 'appId': 'bbb', 'displayName': 'App Two',
                 'appOwnerOrganizationId': None,
                 'publisherDomain': 'partner.com', 'signInAudience': 'AzureADMultipleOrgs'},
            ],
        }

        owner_responses = {
            'app-obj-1': {'value': [{'id': 'user-1', 'displayName': 'Alice Admin', 'userPrincipalName': 'alice@contoso.com'}]},
            'app-obj-2': {'value': []},  # No owner
        }

        with patch('aiohttp.ClientSession', return_value=_FakeRoutedSession([page], owner_responses)):
            result = asyncio.get_event_loop().run_until_complete(
                engine._fetch_app_registration_map()
            )

        assert len(result) == 2
        assert result['aaa']['object_id'] == 'app-obj-1'
        assert result['aaa']['display_name'] == 'App One'
        assert result['aaa']['publisher_domain'] == 'contoso.com'
        assert result['aaa']['sign_in_audience'] == 'AzureADMyOrg'
        assert result['aaa']['owner_display_name'] == 'Alice Admin'
        assert result['aaa']['owner_id'] == 'user-1'
        assert result['bbb']['object_id'] == 'app-obj-2'
        assert result['bbb']['owner_display_name'] is None

    def test_fetch_app_registration_map_pagination(self):
        """Pagination follows @odata.nextLink for applications."""
        engine = _build_engine()

        page1 = {
            'value': [{'id': 'obj-1', 'appId': 'a1', 'displayName': 'A1', 'appOwnerOrganizationId': None,
                        'publisherDomain': None, 'signInAudience': None}],
            '@odata.nextLink': 'https://graph.microsoft.com/v1.0/applications?$skiptoken=p2',
        }
        page2 = {
            'value': [{'id': 'obj-2', 'appId': 'a2', 'displayName': 'A2',
                        'appOwnerOrganizationId': None, 'publisherDomain': None, 'signInAudience': None}],
        }

        with patch('aiohttp.ClientSession', return_value=_FakeRoutedSession([page1, page2])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._fetch_app_registration_map()
            )

        assert len(result) == 2
        assert 'a1' in result
        assert 'a2' in result

    def test_enrich_spns_links_to_app_registration(self):
        """SPNs of type Application with matching appId get lineage fields set."""
        engine = _build_engine()

        spns = [
            {
                'app_id': 'aaa',
                'display_name': 'My SPN',
                'service_principal_type': 'Application',
                'identity_category': 'service_principal',
            },
            {
                'app_id': 'zzz',
                'display_name': 'No App Reg SPN',
                'service_principal_type': 'Application',
                'identity_category': 'service_principal',
            },
        ]

        app_map = {
            'aaa': {
                'object_id': 'app-obj-aaa',
                'display_name': 'My App Registration',
                'app_owner_organization_id': CUSTOMER_TENANT_ID,
                'publisher_domain': 'contoso.com',
                'sign_in_audience': 'AzureADMyOrg',
                'owner_display_name': 'Alice Admin',
                'owner_id': 'user-alice',
            },
        }

        engine._enrich_spns_with_app_registrations(spns, app_map)

        # SPN with matching app reg
        assert spns[0]['app_registration_object_id'] == 'app-obj-aaa'
        assert spns[0]['app_registration_name'] == 'My App Registration'
        assert spns[0]['is_external_app'] is False
        assert spns[0]['app_reg_publisher_domain'] == 'contoso.com'
        assert spns[0]['app_reg_sign_in_audience'] == 'AzureADMyOrg'
        assert spns[0]['app_reg_owner_display_name'] == 'Alice Admin'
        assert spns[0]['app_reg_owner_id'] == 'user-alice'

        # SPN without matching app reg — fields not set
        assert 'app_registration_object_id' not in spns[1]

    def test_enrich_spns_marks_external_app(self):
        """SPNs with appOwnerOrganizationId != tenant are marked external."""
        engine = _build_engine()

        spns = [
            {
                'app_id': 'ext-app',
                'display_name': 'External SPN',
                'service_principal_type': 'Application',
                'identity_category': 'service_principal',
            },
        ]

        app_map = {
            'ext-app': {
                'object_id': 'app-obj-ext',
                'display_name': 'Third Party App',
                'app_owner_organization_id': 'some-other-tenant-id',
                'publisher_domain': 'external.com',
                'sign_in_audience': 'AzureADMultipleOrgs',
                'owner_display_name': None,
                'owner_id': None,
            },
        }

        engine._enrich_spns_with_app_registrations(spns, app_map)

        assert spns[0]['app_registration_object_id'] == 'app-obj-ext'
        assert spns[0]['app_registration_name'] == 'Third Party App'
        assert spns[0]['is_external_app'] is True

    def test_all_application_type_spns_have_lineage_after_enrichment(self):
        """Post-sync assertion: every SPN of type Application with a matching
        app registration must have a non-null app_registration_object_id."""
        engine = _build_engine()

        # 5 SPNs, all type Application, all with app registrations
        spns = [
            {'app_id': f'app-{i}', 'display_name': f'SPN {i}',
             'service_principal_type': 'Application', 'identity_category': 'service_principal'}
            for i in range(5)
        ]

        app_map = {
            f'app-{i}': {
                'object_id': f'app-obj-{i}',
                'display_name': f'App Reg {i}',
                'app_owner_organization_id': CUSTOMER_TENANT_ID,
                'publisher_domain': 'contoso.com',
                'sign_in_audience': 'AzureADMyOrg',
                'owner_display_name': f'Owner {i}',
                'owner_id': f'owner-{i}',
            }
            for i in range(5)
        }

        engine._enrich_spns_with_app_registrations(spns, app_map)

        for sp in spns:
            assert sp.get('app_registration_object_id') is not None, \
                f"SPN {sp['display_name']} missing app_registration_object_id"

    def test_app_reg_owner_fetched(self):
        """Owner display name is populated from Graph /owners endpoint."""
        engine = _build_engine()

        page = {
            'value': [
                {'id': 'app-obj-1', 'appId': 'owned-app', 'displayName': 'Owned App',
                 'appOwnerOrganizationId': CUSTOMER_TENANT_ID,
                 'publisherDomain': 'contoso.com', 'signInAudience': 'AzureADMyOrg'},
            ],
        }
        owner_responses = {
            'app-obj-1': {'value': [{'id': 'user-bob', 'displayName': 'Bob Smith', 'userPrincipalName': 'bob@contoso.com'}]},
        }

        with patch('aiohttp.ClientSession', return_value=_FakeRoutedSession([page], owner_responses)):
            result = asyncio.get_event_loop().run_until_complete(
                engine._fetch_app_registration_map()
            )

        assert result['owned-app']['owner_display_name'] == 'Bob Smith'
        assert result['owned-app']['owner_id'] == 'user-bob'

    def test_publisher_domain_populated(self):
        """Publisher domain is populated from Graph API for tenant-owned apps."""
        engine = _build_engine()

        page = {
            'value': [
                {'id': 'app-obj-1', 'appId': 'my-app', 'displayName': 'My App',
                 'appOwnerOrganizationId': CUSTOMER_TENANT_ID,
                 'publisherDomain': 'auditgraphbynexgenix.onmicrosoft.com',
                 'signInAudience': 'AzureADMyOrg'},
            ],
        }

        with patch('aiohttp.ClientSession', return_value=_FakeRoutedSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._fetch_app_registration_map()
            )

        assert result['my-app']['publisher_domain'] == 'auditgraphbynexgenix.onmicrosoft.com'
        assert result['my-app']['sign_in_audience'] == 'AzureADMyOrg'

    def test_external_app_has_no_owner(self):
        """External apps (cross-tenant) should have owner fields as None
        since the owners API won't return cross-tenant owners."""
        engine = _build_engine()

        spns = [
            {
                'app_id': 'ext-app',
                'display_name': 'External SPN',
                'service_principal_type': 'Application',
                'identity_category': 'service_principal',
            },
        ]

        app_map = {
            'ext-app': {
                'object_id': 'app-obj-ext',
                'display_name': 'Third Party App',
                'app_owner_organization_id': 'other-tenant-id',
                'publisher_domain': 'thirdparty.com',
                'sign_in_audience': 'AzureADMultipleOrgs',
                'owner_display_name': None,
                'owner_id': None,
            },
        }

        engine._enrich_spns_with_app_registrations(spns, app_map)

        assert spns[0]['is_external_app'] is True
        assert spns[0]['app_reg_owner_display_name'] is None
        assert spns[0]['app_reg_owner_id'] is None
        assert spns[0]['app_reg_publisher_domain'] == 'thirdparty.com'
