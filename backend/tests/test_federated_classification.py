"""
Federated Credential Classification — unit tests.

Verifies:
  1. GitHub Actions OIDC issuer → github_actions type, repo extracted from subject
  2. AKS/Kubernetes issuer → aks_workload type, namespace/sa extracted
  3. External/unknown issuer → external_federation fallback
  4. Federated credential boosts verdict score by +35
  5. Edge cases: empty issuer, empty subject, no colon in subject
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


# ── Helpers ─────────────────────────────────────────────────────────

def _get_classifier():
    """Import the static classifier method."""
    with patch('app.engines.discovery.azure_discovery.ClientSecretCredential'), \
         patch('app.engines.discovery.azure_discovery.GraphServiceClient'), \
         patch('app.engines.discovery.azure_discovery.SubscriptionClient'), \
         patch('app.engines.discovery.azure_discovery.Database'):
        from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
        return AzureDiscoveryEngine._classify_federated_credential


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


def _make_identity(**overrides):
    """Build a minimal identity dict with defaults for verdict assembly."""
    base = {
        'identity_id': 'spn-test-001',
        'display_name': 'Test SPN',
        'identity_category': 'service_principal',
        'role_count': 0,
        'workload_type': 'unknown',
        'workload_confidence': 0,
        'app_registration_object_id': None,
        'app_reg_owner_display_name': None,
        'app_reg_likely_service': None,
        'app_reg_reply_url_hostnames': None,
        'app_registration_name': None,
        'is_external_app': False,
        'is_discovery_connector': False,
        'signin_pattern': None,
        'days_since_last_signin': None,
        'last_sign_in': None,
        'workload_risk_flags': [],
        'federated_workload_type': None,
        'federated_workload_name': None,
    }
    base.update(overrides)
    return base


# ── Classification Tests ────────────────────────────────────────────

class TestClassifyFederatedCredential:
    """Unit tests for _classify_federated_credential static method."""

    def test_github_actions_with_ref(self):
        """GitHub Actions OIDC with ref subject → repo extracted."""
        classify = _get_classifier()
        result = classify(
            'https://token.actions.githubusercontent.com',
            'repo:contoso/my-app:ref:refs/heads/main'
        )
        assert result['federated_workload_type'] == 'github_actions'
        assert result['federated_workload_name'] == 'contoso/my-app'

    def test_github_actions_with_environment(self):
        """GitHub Actions OIDC with environment subject → repo extracted."""
        classify = _get_classifier()
        result = classify(
            'https://token.actions.githubusercontent.com',
            'repo:org/deploy-pipeline:environment:production'
        )
        assert result['federated_workload_type'] == 'github_actions'
        assert result['federated_workload_name'] == 'org/deploy-pipeline'

    def test_github_actions_bare_repo(self):
        """GitHub Actions subject with no colon after repo name."""
        classify = _get_classifier()
        result = classify(
            'https://token.actions.githubusercontent.com',
            'repo:myorg/myrepo'
        )
        assert result['federated_workload_type'] == 'github_actions'
        assert result['federated_workload_name'] == 'myorg/myrepo'

    def test_github_actions_non_repo_subject(self):
        """GitHub Actions with non-standard subject (no repo: prefix)."""
        classify = _get_classifier()
        result = classify(
            'https://token.actions.githubusercontent.com',
            'some-other-subject'
        )
        assert result['federated_workload_type'] == 'github_actions'
        assert result['federated_workload_name'] == 'some-other-subject'

    def test_aks_kubernetes_issuer(self):
        """AKS with kubernetes in issuer → aks_workload."""
        classify = _get_classifier()
        result = classify(
            'https://oidc.prod-aks.azure.com/tenant-id/kubernetes',
            'system:serviceaccount:kube-system:my-controller'
        )
        assert result['federated_workload_type'] == 'aks_workload'
        assert result['federated_workload_name'] == 'kube-system/my-controller'

    def test_aks_serviceaccount_in_subject_only(self):
        """Subject contains system:serviceaccount but issuer doesn't say kubernetes."""
        classify = _get_classifier()
        result = classify(
            'https://some-custom-oidc.example.com',
            'system:serviceaccount:app-ns:web-api'
        )
        assert result['federated_workload_type'] == 'aks_workload'
        assert result['federated_workload_name'] == 'app-ns/web-api'

    def test_eks_kubernetes_issuer(self):
        """EKS OIDC with kubernetes in issuer path."""
        classify = _get_classifier()
        result = classify(
            'https://oidc.eks.us-east-1.amazonaws.com/id/ABC123/kubernetes',
            'system:serviceaccount:monitoring:prometheus'
        )
        assert result['federated_workload_type'] == 'aks_workload'
        assert result['federated_workload_name'] == 'monitoring/prometheus'

    def test_external_federation_google(self):
        """Google Cloud issuer → external_federation."""
        classify = _get_classifier()
        result = classify(
            'https://accounts.google.com',
            'projects/123456/locations/global/workloadIdentityPools/pool-1'
        )
        assert result['federated_workload_type'] == 'external_federation'
        assert result['federated_workload_name'] == 'accounts.google.com'

    def test_external_federation_custom(self):
        """Unknown issuer → external_federation with host extracted."""
        classify = _get_classifier()
        result = classify(
            'https://login.partner.microsoftonline.cn/tenant-id/v2.0',
            'some-audience'
        )
        assert result['federated_workload_type'] == 'external_federation'
        assert result['federated_workload_name'] == 'login.partner.microsoftonline.cn'

    def test_empty_issuer_and_subject(self):
        """Both empty → external_federation with 'unknown' name."""
        classify = _get_classifier()
        result = classify('', '')
        assert result['federated_workload_type'] == 'external_federation'
        assert result['federated_workload_name'] == 'unknown'

    def test_none_issuer_and_subject(self):
        """Both None → external_federation with 'unknown' name."""
        classify = _get_classifier()
        result = classify(None, None)
        assert result['federated_workload_type'] == 'external_federation'
        assert result['federated_workload_name'] == 'unknown'


# ── Verdict Integration Tests ───────────────────────────────────────

class TestFederatedVerdictSignal:
    """Verify federated credential adds +35 to verdict score."""

    def test_federated_adds_35_to_score(self):
        """Identity with only federated_workload_type → score includes +35."""
        engine = _build_engine()
        identity = _make_identity(
            federated_workload_type='github_actions',
            federated_workload_name='contoso/deploy',
        )
        verdict = engine._assemble_lineage_verdict(identity)

        assert verdict['verdict_score'] == 35
        fed_signals = [s for s in verdict['verdict_signals']
                       if s['source'] == 'federated_credential']
        assert len(fed_signals) == 1
        assert fed_signals[0]['weight'] == 35
        assert 'github_actions' in fed_signals[0]['detail']

    def test_federated_plus_roles_reaches_high_confidence(self):
        """Federated (35) + role topology (30) = 65 → high confidence."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='ci_cd_pipeline',
            workload_confidence=80,
            federated_workload_type='github_actions',
            federated_workload_name='contoso/deploy',
        )
        verdict = engine._assemble_lineage_verdict(identity)

        assert verdict['verdict_score'] == 65  # 30 (role) + 35 (fed)
        assert verdict['verdict_confidence'] == 'high'

    def test_no_federated_no_signal(self):
        """Identity without federated → no federated signal in verdict."""
        engine = _build_engine()
        identity = _make_identity()
        verdict = engine._assemble_lineage_verdict(identity)

        fed_signals = [s for s in verdict['verdict_signals']
                       if s['source'] == 'federated_credential']
        assert len(fed_signals) == 0

    def test_federated_sets_origin_when_no_other_source(self):
        """Federated credential used as origin when no app_reg or reply_urls."""
        engine = _build_engine()
        identity = _make_identity(
            federated_workload_type='aks_workload',
            federated_workload_name='kube-system/my-controller',
        )
        verdict = engine._assemble_lineage_verdict(identity)

        assert verdict['workload_origin_source'] == 'federated_credential'
        assert 'Aks Workload' in verdict['workload_origin']
        assert 'kube-system/my-controller' in verdict['workload_origin']
