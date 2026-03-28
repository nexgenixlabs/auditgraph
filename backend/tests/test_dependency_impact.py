"""
Dependency Impact Analysis — unit tests for _compute_dependency_impact().

Verifies:
  1. No bindings, no write roles → none_detected
  2. No bindings, has write roles → none_detected with warning
  3. AppService binding → high impact
  4. FunctionApp binding → high impact
  5. ContainerApp binding → high impact
  6. StorageAccount binding → medium impact
  7. Reader-only roles downgrade to low (unless high-impact resource)
  8. Mixed resources → highest impact wins
  9. Impact statement includes resource names
  10. Multiple high-impact resources listed in statement
"""
import os
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


def _build_engine():
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
        return engine


class TestComputeDependencyImpact:
    """Unit tests for _compute_dependency_impact."""

    def test_no_bindings_no_write_roles(self):
        """No bindings + no write roles → none_detected."""
        engine = _build_engine()
        result = engine._compute_dependency_impact([], [])
        assert result['dependency_impact'] == 'none_detected'
        assert result['dependency_impact_resources'] == []
        assert 'No resource bindings' in result['deletion_impact_statement']

    def test_no_bindings_reader_only(self):
        """No bindings + only reader roles → none_detected, no warning."""
        engine = _build_engine()
        roles = [{'role_name': 'Reader'}]
        result = engine._compute_dependency_impact([], roles)
        assert result['dependency_impact'] == 'none_detected'
        assert 'No resource bindings' in result['deletion_impact_statement']

    def test_no_bindings_has_write_roles(self):
        """No bindings + write roles → none_detected with warning."""
        engine = _build_engine()
        roles = [{'role_name': 'Contributor'}]
        result = engine._compute_dependency_impact([], roles)
        assert result['dependency_impact'] == 'none_detected'
        assert 'write/contribute roles' in result['deletion_impact_statement']

    def test_appservice_binding_high_impact(self):
        """AppService binding → high impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'AppService',
            'resource_name': 'my-webapp',
            'resource_group': 'rg-prod',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'
        assert len(result['dependency_impact_resources']) == 1
        assert result['dependency_impact_resources'][0]['impact_level'] == 'high'

    def test_functionapp_binding_high_impact(self):
        """FunctionApp binding → high impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'FunctionApp',
            'resource_name': 'my-func',
            'resource_group': 'rg-dev',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'

    def test_containerapp_binding_high_impact(self):
        """ContainerApp binding → high impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'ContainerApp',
            'resource_name': 'api-container',
            'resource_group': 'rg-prod',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'

    def test_virtualmachines_high_impact(self):
        """virtualMachines binding → high impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'virtualMachines',
            'resource_name': 'vm-prod-01',
            'resource_group': 'rg-infra',
            'binding_method': 'ManagedIdentitySystemAssigned',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'

    def test_storage_account_medium_impact(self):
        """StorageAccounts binding → medium impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'storageAccounts',
            'resource_name': 'mystorage01',
            'resource_group': 'rg-data',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'medium'
        assert result['dependency_impact_resources'][0]['impact_level'] == 'medium'

    def test_keyvault_medium_impact(self):
        """KeyVault binding → medium impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'keyVaults',
            'resource_name': 'kv-prod',
            'resource_group': 'rg-security',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'medium'

    def test_unknown_resource_low_impact(self):
        """Unknown resource type → low impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'SomeOtherResource',
            'resource_name': 'other-res',
            'resource_group': 'rg-misc',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'low'

    def test_reader_only_downgrades_to_low(self):
        """Reader-only roles + medium binding → downgraded to low."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'storageAccounts',
            'resource_name': 'mystorage',
            'resource_group': 'rg-1',
            'binding_method': 'HardcodedClientId',
        }]
        roles = [{'role_name': 'Reader'}, {'role_name': 'Monitoring Reader'}]
        result = engine._compute_dependency_impact(bindings, roles)
        assert result['dependency_impact'] == 'low'

    def test_reader_only_does_not_downgrade_high(self):
        """Reader-only roles + high-impact resource → stays high."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'AppService',
            'resource_name': 'webapp-prod',
            'resource_group': 'rg-prod',
            'binding_method': 'HardcodedClientId',
        }]
        roles = [{'role_name': 'Reader'}]
        result = engine._compute_dependency_impact(bindings, roles)
        assert result['dependency_impact'] == 'high'

    def test_mixed_resources_highest_wins(self):
        """Mix of high + low resources → overall impact = high."""
        engine = _build_engine()
        bindings = [
            {
                'resource_type': 'SomeOtherResource',
                'resource_name': 'misc-1',
                'resource_group': 'rg-1',
                'binding_method': 'HardcodedClientId',
            },
            {
                'resource_type': 'AppService',
                'resource_name': 'webapp-prod',
                'resource_group': 'rg-prod',
                'binding_method': 'HardcodedClientId',
            },
        ]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'
        assert len(result['dependency_impact_resources']) == 2

    def test_impact_statement_includes_resource_names(self):
        """Impact statement should list resource names for high-impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'AppService',
            'resource_name': 'critical-api',
            'resource_group': 'rg-prod',
            'binding_method': 'HardcodedClientId',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert 'critical-api' in result['deletion_impact_statement']
        assert 'CRITICAL' in result['deletion_impact_statement']

    def test_multiple_high_impact_resources_in_statement(self):
        """Multiple high-impact resources all listed in statement."""
        engine = _build_engine()
        bindings = [
            {
                'resource_type': 'AppService',
                'resource_name': 'webapp-1',
                'resource_group': 'rg-1',
                'binding_method': 'HardcodedClientId',
            },
            {
                'resource_type': 'FunctionApp',
                'resource_name': 'func-2',
                'resource_group': 'rg-2',
                'binding_method': 'HardcodedClientId',
            },
            {
                'resource_type': 'ContainerApp',
                'resource_name': 'container-3',
                'resource_group': 'rg-3',
                'binding_method': 'HardcodedClientId',
            },
        ]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'
        stmt = result['deletion_impact_statement']
        assert 'webapp-1' in stmt
        assert 'func-2' in stmt
        assert 'container-3' in stmt

    def test_medium_impact_statement(self):
        """Medium impact gets summary-style statement."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'storageAccounts',
            'resource_name': 'storage-01',
            'resource_group': 'rg-data',
            'binding_method': 'HardcodedClientId',
        }]
        roles = [{'role_name': 'Contributor'}]
        result = engine._compute_dependency_impact(bindings, roles)
        assert result['dependency_impact'] == 'medium'
        assert 'may be affected' in result['deletion_impact_statement']

    def test_managedclusters_aks_high_impact(self):
        """managedClusters (AKS) binding → high impact."""
        engine = _build_engine()
        bindings = [{
            'resource_type': 'managedClusters',
            'resource_name': 'aks-prod',
            'resource_group': 'rg-k8s',
            'binding_method': 'ManagedIdentitySystemAssigned',
        }]
        result = engine._compute_dependency_impact(bindings, [])
        assert result['dependency_impact'] == 'high'
