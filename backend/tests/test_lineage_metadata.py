"""
App Registration Metadata Mining — unit tests for _extract_app_reg_signals().

Verifies:
  1. replyUrl hostname extraction (App Service, Container App, Static Web App)
  2. localhost URLs ignored
  3. Empty reply URLs → None
  4. requiredResourceAccess API detection (Graph, legacy AD Graph)
  5. workload_type upgrade when unknown
  6. workload_type NOT overridden when already classified
  7. notes + description concatenation
  8. Multiple reply URLs — all public extracted
"""
import os
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


# ── Helpers ─────────────────────────────────────────────────────────

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


# ── Tests ───────────────────────────────────────────────────────────

class TestAppRegSignalExtraction:
    """Tests for _extract_app_reg_signals()."""

    def test_reply_url_extracts_azurewebsites_hostname(self):
        """App Service replyUrl → likely_service = app name, type = app_service."""
        engine = _build_engine()
        app = {'replyUrls': ['https://billing-api.azurewebsites.net/auth/callback']}
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        assert result['app_reg_likely_service'] == 'billing-api'
        assert result['app_reg_likely_service_type'] == 'app_service'

    def test_reply_url_extracts_container_app(self):
        """Container App replyUrl → likely_service_type = container_app."""
        engine = _build_engine()
        app = {'replyUrls': ['https://myapp.nicegrassfield.azurecontainerapps.io']}
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        assert result['app_reg_likely_service_type'] == 'container_app'

    def test_localhost_reply_url_ignored(self):
        """localhost URLs excluded from public hostnames; App Service still detected."""
        engine = _build_engine()
        app = {'replyUrls': ['http://localhost:3000', 'https://app.azurewebsites.net']}
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        hostnames = result['app_reg_reply_url_hostnames'] or []
        assert 'localhost' not in hostnames
        assert result['app_reg_likely_service'] == 'app'

    def test_empty_reply_urls_returns_none(self):
        """No reply URLs → likely_service and hostnames are None."""
        engine = _build_engine()
        app = {'replyUrls': []}
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        assert result['app_reg_likely_service'] is None
        assert result['app_reg_reply_url_hostnames'] is None

    def test_graph_api_detected_in_required_access(self):
        """Microsoft Graph resourceAppId → 'microsoft_graph' in required_apis."""
        engine = _build_engine()
        app = {
            'requiredResourceAccess': [{
                'resourceAppId': '00000003-0000-0000-c000-000000000000',
                'resourceAccess': [{'id': 'abc', 'type': 'Role'}],
            }],
        }
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        assert result['app_reg_required_apis'] == ['microsoft_graph']

    def test_legacy_ad_graph_detected(self):
        """Legacy Azure AD Graph resourceAppId detected."""
        engine = _build_engine()
        app = {
            'requiredResourceAccess': [{
                'resourceAppId': '00000002-0000-0000-c000-000000000000',
            }],
        }
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        assert 'azure_ad_graph_legacy' in result['app_reg_required_apis']

    def test_workload_type_updated_when_unknown(self):
        """When workload_type is 'unknown' and replyUrl points to App Service,
        the enrichment should upgrade workload_type to 'web_workload'."""
        engine = _build_engine()

        # Simulate an SPN identity dict after role inference → unknown
        sp = {
            'app_id': 'test-app-id',
            'identity_category': 'service_principal',
            'workload_type': 'unknown',
            'workload_confidence': 0,
            'role_pattern_matched': 'none',
        }

        app_reg = {
            'object_id': 'obj-1',
            'display_name': 'TestApp',
            'app_owner_organization_id': engine.azure_directory_id,
            'publisher_domain': 'contoso.com',
            'sign_in_audience': 'AzureADMyOrg',
            'owner_display_name': None,
            'owner_id': None,
            'replyUrls': ['https://myapp.azurewebsites.net/auth'],
            'identifierUris': None,
            'notes': None,
            'description': None,
            'web': None,
            'requiredResourceAccess': None,
        }

        # Call enrichment method
        engine._enrich_spns_with_app_registrations([sp], {'test-app-id': app_reg})

        assert sp['workload_type'] == 'web_workload'
        assert sp['workload_confidence'] >= 20

    def test_workload_type_not_overridden_when_classified(self):
        """When workload_type is already set (e.g. 'container_workload'),
        metadata should NOT override it."""
        engine = _build_engine()

        sp = {
            'app_id': 'test-app-id',
            'identity_category': 'service_principal',
            'workload_type': 'container_workload',
            'workload_confidence': 60,
            'role_pattern_matched': 'container_workload',
        }

        app_reg = {
            'object_id': 'obj-1',
            'display_name': 'TestApp',
            'app_owner_organization_id': engine.azure_directory_id,
            'publisher_domain': 'contoso.com',
            'sign_in_audience': 'AzureADMyOrg',
            'owner_display_name': None,
            'owner_id': None,
            'replyUrls': ['https://myapp.azurewebsites.net/auth'],
            'identifierUris': None,
            'notes': None,
            'description': None,
            'web': None,
            'requiredResourceAccess': None,
        }

        engine._enrich_spns_with_app_registrations([sp], {'test-app-id': app_reg})

        assert sp['workload_type'] == 'container_workload'
        assert sp['workload_confidence'] == 60

    def test_notes_and_description_concatenated(self):
        """Both notes and description are concatenated into app_reg_notes."""
        engine = _build_engine()
        app = {
            'notes': 'Billing service',
            'description': 'Used by finance team',
        }
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        assert result['app_reg_notes'] == 'Billing service Used by finance team'

    def test_multiple_reply_urls_all_extracted(self):
        """Multiple public URLs extracted; localhost excluded from count."""
        engine = _build_engine()
        app = {
            'replyUrls': [
                'https://app1.azurewebsites.net/callback',
                'https://app2.example.com/auth',
                'http://localhost:8080/callback',
            ],
        }
        result = engine._extract_app_reg_signals(app, tenant_domain='contoso.com')
        hostnames = result['app_reg_reply_url_hostnames'] or []
        assert len(hostnames) == 2
        assert 'app1.azurewebsites.net' in hostnames
        assert 'app2.example.com' in hostnames
