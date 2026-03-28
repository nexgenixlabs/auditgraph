"""
ARM Resource Graph Scanner — unit tests.

Verifies:
  1. _fetch_arm_resource_associations batches appIds correctly
  2. KQL queries match resources → bindings returned
  3. Empty app_ids → empty result
  4. Missing azure-mgmt-resourcegraph → graceful skip
  5. API failures → non-fatal, empty result
"""
import os
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
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


class TestFetchArmResourceAssociations:
    """Unit tests for _fetch_arm_resource_associations."""

    def test_empty_spns_returns_empty(self):
        """No service principals → empty result."""
        engine = _build_engine()
        result = engine._fetch_arm_resource_associations([])
        assert result == {}

    def test_no_subscriptions_returns_empty(self):
        """No subscriptions → empty result."""
        engine = _build_engine(subscriptions=[])
        spns = [{'app_id': 'aid-1', 'identity_id': 'iid-1',
                 'identity_category': 'service_principal'}]
        result = engine._fetch_arm_resource_associations(spns)
        assert result == {}

    def test_non_spn_identities_skipped(self):
        """Human users and guests should not be scanned."""
        engine = _build_engine()
        spns = [
            {'app_id': 'aid-1', 'identity_id': 'iid-1',
             'identity_category': 'human_user'},
            {'app_id': 'aid-2', 'identity_id': 'iid-2',
             'identity_category': 'guest'},
        ]
        with patch('app.engines.discovery.azure_discovery.ResourceGraphClient'):
            result = engine._fetch_arm_resource_associations(spns)
        assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_appservice_match_returns_binding(self, MockQueryRequest, MockRGClient):
        """AppService with matching appId → binding returned."""
        engine = _build_engine()

        # Mock Resource Graph response
        mock_response = MagicMock()
        mock_response.data = [
            {
                'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/my-app',
                'name': 'my-app',
                'resourceGroup': 'rg-1',
                'location': 'eastus',
                'settingKey': 'AZURE_CLIENT_ID',
                'matchedValue': 'aid-1',
            }
        ]
        mock_client_instance = MagicMock()
        mock_client_instance.resources.return_value = mock_response
        MockRGClient.return_value = mock_client_instance

        spns = [{'app_id': 'aid-1', 'identity_id': 'iid-1',
                 'identity_category': 'service_principal'}]
        result = engine._fetch_arm_resource_associations(spns)

        assert 'aid-1' in result
        bindings = result['aid-1']
        # At least one binding from AppService query
        app_svc = [b for b in bindings if b['resource_type'] == 'AppService']
        assert len(app_svc) >= 1
        assert app_svc[0]['resource_name'] == 'my-app'
        assert app_svc[0]['confidence_score'] == 90
        assert app_svc[0]['binding_method'] == 'HardcodedClientId'

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_no_matches_returns_empty(self, MockQueryRequest, MockRGClient):
        """No Resource Graph matches → empty result."""
        engine = _build_engine()

        mock_response = MagicMock()
        mock_response.data = []
        mock_client_instance = MagicMock()
        mock_client_instance.resources.return_value = mock_response
        MockRGClient.return_value = mock_client_instance

        spns = [{'app_id': 'aid-1', 'identity_id': 'iid-1',
                 'identity_category': 'service_principal'}]
        result = engine._fetch_arm_resource_associations(spns)
        assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_api_failure_nonfatal(self, MockQueryRequest, MockRGClient):
        """Resource Graph API failure → non-fatal, empty result."""
        engine = _build_engine()

        mock_client_instance = MagicMock()
        mock_client_instance.resources.side_effect = Exception("429 Too Many Requests")
        MockRGClient.return_value = mock_client_instance

        spns = [{'app_id': 'aid-1', 'identity_id': 'iid-1',
                 'identity_category': 'service_principal'}]
        result = engine._fetch_arm_resource_associations(spns)
        assert result == {}

    def test_missing_sdk_graceful_skip(self):
        """If ResourceGraphClient is None, returns empty."""
        engine = _build_engine()

        with patch('app.engines.discovery.azure_discovery.ResourceGraphClient', None):
            spns = [{'app_id': 'aid-1', 'identity_id': 'iid-1',
                     'identity_category': 'service_principal'}]
            result = engine._fetch_arm_resource_associations(spns)
            assert result == {}

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_multiple_spns_batched(self, MockQueryRequest, MockRGClient):
        """Multiple SPNs get batched together in KQL queries."""
        engine = _build_engine()

        # Track how many times resources() is called
        call_count = {'n': 0}
        mock_response = MagicMock()
        mock_response.data = []

        def mock_resources(*args, **kwargs):
            call_count['n'] += 1
            return mock_response

        mock_client_instance = MagicMock()
        mock_client_instance.resources.side_effect = mock_resources
        MockRGClient.return_value = mock_client_instance

        spns = [
            {'app_id': f'aid-{i}', 'identity_id': f'iid-{i}',
             'identity_category': 'service_principal'}
            for i in range(5)
        ]
        engine._fetch_arm_resource_associations(spns)

        # 5 SPNs < batch size 50 → 1 batch × 4 queries = 4 calls
        assert call_count['n'] == 4

    @patch('app.engines.discovery.azure_discovery.ResourceGraphClient')
    @patch('app.engines.discovery.azure_discovery.QueryRequest')
    def test_container_app_match(self, MockQueryRequest, MockRGClient):
        """ContainerApp with matching appId → binding returned."""
        engine = _build_engine()

        call_n = {'n': 0}

        def mock_resources(*args, **kwargs):
            call_n['n'] += 1
            resp = MagicMock()
            # 3rd query is ContainerApp
            if call_n['n'] == 3:
                resp.data = [{
                    'id': '/subscriptions/sub-1/resourceGroups/rg-2/providers/Microsoft.App/containerApps/api',
                    'name': 'api',
                    'resourceGroup': 'rg-2',
                    'location': 'westus2',
                    'envKey': 'AZURE_CLIENT_ID',
                    'matchedValue': 'aid-1',
                }]
            else:
                resp.data = []
            return resp

        mock_client_instance = MagicMock()
        mock_client_instance.resources.side_effect = mock_resources
        MockRGClient.return_value = mock_client_instance

        spns = [{'app_id': 'aid-1', 'identity_id': 'iid-1',
                 'identity_category': 'service_principal'}]
        result = engine._fetch_arm_resource_associations(spns)

        assert 'aid-1' in result
        ca_bindings = [b for b in result['aid-1'] if b['resource_type'] == 'ContainerApp']
        assert len(ca_bindings) == 1
        assert ca_bindings[0]['confidence_score'] == 85
        assert ca_bindings[0]['resource_name'] == 'api'
