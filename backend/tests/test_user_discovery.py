"""
User Discovery — unit tests for _discover_users().

Verifies:
  1. ALL users returned regardless of role assignments
  2. Pagination via @odata.nextLink is followed
  3. All userType values (Member, Guest, ExternalMember) are included
  4. signInActivity fallback works when P2 is unavailable
  5. User count in result matches total from Graph API pages
"""
import os
import json
import asyncio
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


CUSTOMER_TENANT_ID = '00000000-0000-0000-0000-000000000001'


def _make_user(uid, display_name, upn, user_type='Member', enabled=True):
    """Build a minimal user dict as returned by Graph API JSON."""
    return {
        'id': uid,
        'displayName': display_name,
        'userPrincipalName': upn,
        'accountEnabled': enabled,
        'createdDateTime': '2025-01-01T00:00:00Z',
        'userType': user_type,
        'employeeId': None,
        'department': None,
        'jobTitle': None,
        'signInActivity': None,
        'onPremisesSyncEnabled': None,
        'mail': upn,
        'assignedLicenses': [],
    }


def _build_engine():
    """Create an AzureDiscoveryEngine with mocked dependencies."""
    with patch('app.engines.discovery.azure_discovery.ClientSecretCredential') as MockCred, \
         patch('app.engines.discovery.azure_discovery.GraphServiceClient') as MockGraph, \
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

class TestUserDiscoveryNoRoleGate:
    """Users WITHOUT role assignments must still be returned."""

    def test_user_without_roles_is_returned(self):
        engine = _build_engine()

        user = _make_user('user-no-roles', 'No Roles User', 'noroles@contoso.com')
        page = {'value': [user]}

        # Empty set = no principal has roles
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users(set())
            )

        assert len(result) == 1
        assert result[0]['display_name'] == 'No Roles User'
        assert result[0]['identity_category'] == 'human_user'

    def test_users_with_and_without_roles(self):
        engine = _build_engine()

        users = [
            _make_user('user-with-role', 'Admin User', 'admin@contoso.com'),
            _make_user('user-no-role', 'Regular User', 'regular@contoso.com'),
            _make_user('user-no-role-2', 'Another User', 'another@contoso.com'),
        ]
        page = {'value': users}

        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users({'user-with-role'})
            )

        assert len(result) == 3
        names = {r['display_name'] for r in result}
        assert names == {'Admin User', 'Regular User', 'Another User'}


class TestUserDiscoveryPagination:
    """Verify @odata.nextLink pagination returns all users."""

    def test_follows_nextlink(self):
        engine = _build_engine()

        page1 = {
            'value': [_make_user('u1', 'User1', 'u1@contoso.com')],
            '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=page2',
        }
        page2 = {
            'value': [_make_user('u2', 'User2', 'u2@contoso.com')],
            '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=page3',
        }
        page3 = {
            'value': [_make_user('u3', 'User3', 'u3@contoso.com')],
        }

        with patch('aiohttp.ClientSession', return_value=_FakeSession([page1, page2, page3])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users(set())
            )

        assert len(result) == 3
        assert {r['identity_id'] for r in result} == {'u1', 'u2', 'u3'}

    def test_user_count_matches_graph_total(self):
        """Result count must equal the sum of users across all pages."""
        engine = _build_engine()

        # Simulate 25 users across 3 pages (10 + 10 + 5)
        page1_users = [_make_user(f'u{i}', f'User{i}', f'u{i}@contoso.com') for i in range(10)]
        page2_users = [_make_user(f'u{i}', f'User{i}', f'u{i}@contoso.com') for i in range(10, 20)]
        page3_users = [_make_user(f'u{i}', f'User{i}', f'u{i}@contoso.com') for i in range(20, 25)]

        pages = [
            {'value': page1_users, '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=p2'},
            {'value': page2_users, '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=p3'},
            {'value': page3_users},
        ]

        with patch('aiohttp.ClientSession', return_value=_FakeSession(pages)):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users(set())
            )

        graph_total = len(page1_users) + len(page2_users) + len(page3_users)
        assert len(result) == graph_total == 25


class TestUserDiscoveryUserTypes:
    """All userType values must be included."""

    def test_member_guest_externalmember_all_included(self):
        engine = _build_engine()

        users = [
            _make_user('member1', 'Member User', 'member@contoso.com', user_type='Member'),
            _make_user('guest1', 'Guest User', 'guest@external.com', user_type='Guest'),
            _make_user('ext1', 'External Member', 'ext@partner.com', user_type='ExternalMember'),
        ]
        page = {'value': users}

        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users(set())
            )

        assert len(result) == 3

        member = [r for r in result if r['identity_id'] == 'member1'][0]
        assert member['identity_category'] == 'human_user'
        assert member['is_federated'] is False

        guest = [r for r in result if r['identity_id'] == 'guest1'][0]
        assert guest['identity_category'] == 'guest'
        assert guest['is_federated'] is True

        ext = [r for r in result if r['identity_id'] == 'ext1'][0]
        assert ext['identity_category'] == 'guest'
        assert ext['is_federated'] is True


class TestUserDiscoverySignInFallback:
    """When signInActivity returns 403, the method retries without it."""

    def test_retries_without_sign_in_activity(self):
        engine = _build_engine()

        user = _make_user('u1', 'User1', 'u1@contoso.com')
        # Remove signInActivity from the user dict to simulate no-P2 response
        del user['signInActivity']

        # First call returns 403 with signInActivity error, second succeeds
        error_response = {'error': {'code': 'Authorization_RequestDenied', 'message': 'signInActivity requires P2'}}
        success_page = {'value': [user]}

        call_count = {'n': 0}
        original_pages = [error_response, success_page]
        statuses = [403, 200]

        class _FakeSessionWithError:
            def __init__(self):
                self._idx = 0

            def get(self, url, **kwargs):
                idx = self._idx
                self._idx += 1
                if idx < len(original_pages):
                    return _FakeResponse(original_pages[idx], status=statuses[idx])
                return _FakeResponse({'value': []})

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        with patch('aiohttp.ClientSession', return_value=_FakeSessionWithError()):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users(set())
            )

        assert len(result) == 1
        assert result[0]['display_name'] == 'User1'


class TestUserDiscoveryFields:
    """New fields (onPremisesSyncEnabled, mail, assignedLicenses) are captured."""

    def test_new_fields_present(self):
        engine = _build_engine()

        user = _make_user('u1', 'User1', 'u1@contoso.com')
        user['onPremisesSyncEnabled'] = True
        user['mail'] = 'user1@contoso.com'
        user['assignedLicenses'] = [{'skuId': 'sku-123'}]

        page = {'value': [user]}
        with patch('aiohttp.ClientSession', return_value=_FakeSession([page])):
            result = asyncio.get_event_loop().run_until_complete(
                engine._discover_users(set())
            )

        assert len(result) == 1
        r = result[0]
        assert r['on_premises_sync_enabled'] is True
        assert r['mail'] == 'user1@contoso.com'
        assert len(r['assigned_licenses']) == 1
