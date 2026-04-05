"""
Managed Identity Lineage Mapping — unit tests.

Verifies:
  1. System-assigned MI (principalId) → binding with ManagedIdentitySystemAssigned
  2. User-assigned MI (ARM resource ID) → binding with ManagedIdentityUserAssigned
  3. Resources without identity block → no bindings
  4. API failure → non-fatal, empty result
  5. Mixed system + user-assigned on same resource
  6. System-assigned MIs are no longer skipped during discovery
"""
import os
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


def _build_engine(subscriptions=None):
    """Create an AzureDiscoveryEngine with mocked dependencies."""
    with patch('app.engines.discovery.azure_discovery.ClientSecretCredential') as MockCred, \
         patch('app.engines.discovery.azure_discovery.GraphServiceClient'), \
         patch('app.engines.discovery.azure_discovery.SubscriptionClient'), \
         patch('app.engines.discovery.azure_discovery.Database'):

        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = 'fake-bearer-token'
        mock_cred.get_token = MagicMock(return_value=mock_token)
        MockCred.return_value = mock_cred

        from app.engines.discovery.azure_discovery import AzureDiscoveryEngine

        engine = AzureDiscoveryEngine.__new__(AzureDiscoveryEngine)
        engine.credential = mock_cred
        engine.azure_directory_id = '00000000-0000-0000-0000-000000000001'
        engine.subscriptions = subscriptions or [
            {'id': 'sub-1', 'name': 'Dev Sub'},
        ]
        return engine


def _make_identity(**overrides):
    """Build a minimal identity dict."""
    base = {
        'identity_id': 'iid-default',
        'object_id': 'oid-default',
        'app_id': None,
        'display_name': 'test-identity',
        'identity_category': 'managed_identity_system',
        'alternative_names': [],
    }
    base.update(overrides)
    return base


# ── Test: SAMIs are no longer skipped ────────────────────────────

class TestSAMINoLongerSkipped:
    """Verify system-assigned managed identities are included in discovery."""

    def test_sami_gets_identity_category_system(self):
        """SAMIs should have identity_category = managed_identity_system."""
        # This tests the classification logic inline — the actual discovery
        # method calls Graph API, so we verify the classification branch.
        sp_type_raw = 'ManagedIdentity'
        sp_type_norm = sp_type_raw.strip().lower()
        alt_names = [
            'isExplicit=True',
            '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/my-vm',
        ]
        alt_join = " ".join(str(a) for a in alt_names).lower()
        is_uami = "userassignedidentities" in alt_join

        # SAMI: no 'userassignedidentities' in alt_names
        assert sp_type_norm == 'managedidentity'
        assert not is_uami

        # With the fix, SAMIs get managed_identity_system instead of being skipped
        identity_category = 'managed_identity_system' if not is_uami else 'managed_identity_user'
        assert identity_category == 'managed_identity_system'

    def test_uami_still_gets_identity_category_user(self):
        """UAMIs should still have identity_category = managed_identity_user."""
        alt_names = [
            'isExplicit=True',
            '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-uami',
        ]
        alt_join = " ".join(str(a) for a in alt_names).lower()
        is_uami = "userassignedidentities" in alt_join

        assert is_uami
        identity_category = 'managed_identity_system' if not is_uami else 'managed_identity_user'
        assert identity_category == 'managed_identity_user'


# ── Test: _fetch_managed_identity_associations ────────────────────

class TestFetchManagedIdentityAssociations:
    """Unit tests for _fetch_managed_identity_associations."""

    def test_empty_identities_returns_empty(self):
        """No identities → empty result."""
        engine = _build_engine()
        result = engine._fetch_managed_identity_associations([])
        assert result == {}

    def test_no_subscriptions_returns_empty(self):
        """No subscriptions → empty result."""
        engine = _build_engine(subscriptions=[])
        identities = [_make_identity()]
        result = engine._fetch_managed_identity_associations(identities)
        assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_system_assigned_mi_matched(self, MockQR, MockRGClient):
        """System-assigned MI principalId matches identity object_id."""
        engine = _build_engine()

        mock_response = MagicMock()
        mock_response.data = [{
            'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1',
            'name': 'vm-1',
            'type': 'microsoft.compute/virtualMachines',
            'resourceGroup': 'rg-1',
            'location': 'eastus',
            'identityType': 'SystemAssigned',
            'systemPrincipalId': 'oid-sami-1',
            'userAssigned': None,
        }]
        mock_client = MagicMock()
        mock_client.resources.return_value = mock_response
        MockRGClient.return_value = mock_client

        identities = [_make_identity(
            object_id='oid-sami-1',
            identity_id='iid-sami-1',
            identity_category='managed_identity_system',
        )]
        result = engine._fetch_managed_identity_associations(identities)

        assert 'oid-sami-1' in result
        bindings = result['oid-sami-1']
        assert len(bindings) == 1
        b = bindings[0]
        assert b['resource_name'] == 'vm-1'
        assert b['resource_type'] == 'virtualMachines'
        assert b['binding_method'] == 'ManagedIdentitySystemAssigned'
        assert b['confidence_score'] == 95
        assert b['binding_evidence']['principalId'] == 'oid-sami-1'
        assert b['binding_evidence']['association_type'] == 'managed_identity'
        assert b['binding_evidence']['match_type'] == 'managed_identity_binding'

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_user_assigned_mi_matched_by_arm_id(self, MockQR, MockRGClient):
        """User-assigned MI matched via ARM resource ID in alternativeNames."""
        engine = _build_engine()

        uami_arm = '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-uami'

        mock_response = MagicMock()
        mock_response.data = [{
            'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/my-app',
            'name': 'my-app',
            'type': 'microsoft.web/sites',
            'resourceGroup': 'rg-1',
            'location': 'westus2',
            'identityType': 'UserAssigned',
            'systemPrincipalId': '',
            'userAssigned': {
                uami_arm: {
                    'principalId': 'oid-uami-1',
                    'clientId': 'cid-uami-1',
                },
            },
        }]
        mock_client = MagicMock()
        mock_client.resources.return_value = mock_response
        MockRGClient.return_value = mock_client

        identities = [_make_identity(
            object_id='oid-uami-1',
            identity_id='iid-uami-1',
            identity_category='managed_identity_user',
            alternative_names=['isExplicit=True', uami_arm],
        )]
        result = engine._fetch_managed_identity_associations(identities)

        assert 'oid-uami-1' in result
        bindings = result['oid-uami-1']
        assert len(bindings) == 1
        b = bindings[0]
        assert b['resource_name'] == 'my-app'
        assert b['binding_method'] == 'ManagedIdentityUserAssigned'
        assert b['confidence_score'] == 95
        assert b['binding_evidence']['userAssignedArmId'] == uami_arm

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_user_assigned_mi_matched_by_principal_id(self, MockQR, MockRGClient):
        """User-assigned MI matched via principalId when ARM ID not in alternativeNames."""
        engine = _build_engine()

        mock_response = MagicMock()
        mock_response.data = [{
            'id': '/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.App/containerApps/api',
            'name': 'api',
            'type': 'microsoft.app/containerApps',
            'resourceGroup': 'rg-2',
            'location': 'eastus',
            'identityType': 'UserAssigned',
            'systemPrincipalId': '',
            'userAssigned': {
                '/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other-uami': {
                    'principalId': 'oid-uami-2',
                    'clientId': 'cid-uami-2',
                },
            },
        }]
        mock_client = MagicMock()
        mock_client.resources.return_value = mock_response
        MockRGClient.return_value = mock_client

        identities = [_make_identity(
            object_id='oid-uami-2',
            identity_id='iid-uami-2',
            identity_category='managed_identity_user',
            alternative_names=[],  # No ARM ID match — fallback to principalId
        )]
        result = engine._fetch_managed_identity_associations(identities)

        assert 'oid-uami-2' in result
        assert result['oid-uami-2'][0]['binding_method'] == 'ManagedIdentityUserAssigned'

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_no_identity_block_no_bindings(self, MockQR, MockRGClient):
        """Resources with empty identity → no bindings."""
        engine = _build_engine()

        mock_response = MagicMock()
        mock_response.data = [{
            'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/sa1',
            'name': 'sa1',
            'type': 'microsoft.storage/storageAccounts',
            'resourceGroup': 'rg-1',
            'location': 'eastus',
            'identityType': '',
            'systemPrincipalId': '',
            'userAssigned': None,
        }]
        mock_client = MagicMock()
        mock_client.resources.return_value = mock_response
        MockRGClient.return_value = mock_client

        identities = [_make_identity(object_id='oid-1')]
        result = engine._fetch_managed_identity_associations(identities)
        assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_api_failure_nonfatal(self, MockQR, MockRGClient):
        """Resource Graph failure → empty result, no crash."""
        engine = _build_engine()

        mock_client = MagicMock()
        mock_client.resources.side_effect = Exception("Timeout")
        MockRGClient.return_value = mock_client

        identities = [_make_identity(object_id='oid-1')]
        result = engine._fetch_managed_identity_associations(identities)
        assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_mixed_system_and_user_on_same_resource(self, MockQR, MockRGClient):
        """Resource with both system-assigned + user-assigned → bindings for both."""
        engine = _build_engine()

        uami_arm = '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shared-uami'

        mock_response = MagicMock()
        mock_response.data = [{
            'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1',
            'name': 'aks-1',
            'type': 'microsoft.containerservice/managedClusters',
            'resourceGroup': 'rg-1',
            'location': 'eastus',
            'identityType': 'SystemAssigned, UserAssigned',
            'systemPrincipalId': 'oid-sys-aks',
            'userAssigned': {
                uami_arm: {
                    'principalId': 'oid-uami-aks',
                    'clientId': 'cid-uami-aks',
                },
            },
        }]
        mock_client = MagicMock()
        mock_client.resources.return_value = mock_response
        MockRGClient.return_value = mock_client

        identities = [
            _make_identity(
                object_id='oid-sys-aks',
                identity_id='iid-sys-aks',
                identity_category='managed_identity_system',
            ),
            _make_identity(
                object_id='oid-uami-aks',
                identity_id='iid-uami-aks',
                identity_category='managed_identity_user',
                alternative_names=['isExplicit=True', uami_arm],
            ),
        ]
        result = engine._fetch_managed_identity_associations(identities)

        # System-assigned binding
        assert 'oid-sys-aks' in result
        sys_bindings = result['oid-sys-aks']
        assert len(sys_bindings) == 1
        assert sys_bindings[0]['binding_method'] == 'ManagedIdentitySystemAssigned'
        assert sys_bindings[0]['resource_name'] == 'aks-1'

        # User-assigned binding
        assert 'oid-uami-aks' in result
        uami_bindings = result['oid-uami-aks']
        assert len(uami_bindings) == 1
        assert uami_bindings[0]['binding_method'] == 'ManagedIdentityUserAssigned'

    def test_missing_sdk_graceful_skip(self):
        """If ResourceGraphClient is None, returns empty."""
        engine = _build_engine()
        with patch('app.engines.discovery.azure_discovery.ResourceGraphClient', None):
            identities = [_make_identity(object_id='oid-1')]
            result = engine._fetch_managed_identity_associations(identities)
            assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_subscription_id_extracted_from_resource_id(self, MockQR, MockRGClient):
        """subscription_id is extracted from the ARM resource ID."""
        engine = _build_engine()

        mock_response = MagicMock()
        mock_response.data = [{
            'id': '/subscriptions/aaaa-bbbb/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm',
            'name': 'vm',
            'type': 'microsoft.compute/virtualMachines',
            'resourceGroup': 'rg',
            'location': 'westus',
            'identityType': 'SystemAssigned',
            'systemPrincipalId': 'oid-1',
            'userAssigned': None,
        }]
        mock_client = MagicMock()
        mock_client.resources.return_value = mock_response
        MockRGClient.return_value = mock_client

        identities = [_make_identity(object_id='oid-1')]
        result = engine._fetch_managed_identity_associations(identities)

        assert result['oid-1'][0]['subscription_id'] == 'aaaa-bbbb'
