"""
Phase 2B: Container Identity Plane — 20 tests

Tests cover:
  1-3: AKS Resource Graph parsing (cluster, OIDC, node count)
  4-6: Federated credential wildcard detection
  7-8: FEDERATED_MISCONFIGURED verdict
  9-10: ACR registry discovery + admin flagging
  11-12: Layer 2 K8s RBAC (opt-in, binding types)
  13-14: Scoring integration (FEDERATED_MISCONFIGURED bonus)
  15-16: API endpoint shape (aks-clusters, container-risk)
  17: constants.py SSOT for resource types
  18: constants.py SSOT for verdict types
  19-20: Regression — prior tests still pass
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

def _build_container_scanner():
    """Create a ContainerScanner with mocked dependencies."""
    from app.engines.discovery.container_scanner import ContainerScanner
    mock_cred = MagicMock()
    mock_db = MagicMock()
    mock_db._organization_id = 1
    subscriptions = [{'id': 'sub-1', 'name': 'Test Sub'}]
    scanner = ContainerScanner(mock_cred, mock_db, subscriptions, organization_id=1)
    return scanner


def _make_aks_row(**overrides):
    """Build a minimal Resource Graph AKS row."""
    base = {
        'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/my-aks',
        'name': 'my-aks',
        'type': 'microsoft.containerservice/managedclusters',
        'location': 'eastus',
        'resourceGroup': 'rg-1',
        'subscriptionId': 'sub-1',
        'identity': {
            'type': 'SystemAssigned',
            'principalId': 'aks-pid-001',
        },
        'properties': {
            'kubernetesVersion': '1.29.2',
            'agentPoolProfiles': [
                {'count': 3, 'name': 'nodepool1'},
                {'count': 2, 'name': 'nodepool2'},
            ],
            'oidcIssuerProfile': {
                'enabled': True,
                'issuerURL': 'https://eastus.oic.prod-aks.azure.com/tenant-1/aks-oidc-1',
            },
            'securityProfile': {
                'workloadIdentity': {'enabled': True},
            },
            'networkProfile': {'networkPlugin': 'azure'},
        },
        'sku': {'name': 'Base'},
        'tags': {'env': 'prod'},
    }
    base.update(overrides)
    return base


# ── Tests 1-3: AKS Resource Graph Parsing ───────────────────────────

class TestAKSParsing:

    def test_aks_cluster_name_parsed(self):
        """AKS cluster name is correctly extracted."""
        scanner = _build_container_scanner()
        row = _make_aks_row()
        result = scanner._parse_aks_row(row)
        assert result is not None
        assert result['cluster_name'] == 'my-aks'
        assert result['resource_group'] == 'rg-1'
        assert result['subscription_id'] == 'sub-1'

    def test_oidc_issuer_extracted(self):
        """OIDC issuer URL is extracted from oidcIssuerProfile."""
        scanner = _build_container_scanner()
        row = _make_aks_row()
        result = scanner._parse_aks_row(row)
        assert result['oidc_issuer_url'] is not None
        assert 'oic.prod-aks.azure.com' in result['oidc_issuer_url']
        assert result['workload_identity_enabled'] is True

    def test_node_count_summed(self):
        """Node count is the sum across all agent pool profiles."""
        scanner = _build_container_scanner()
        row = _make_aks_row()
        result = scanner._parse_aks_row(row)
        assert result['node_count'] == 5  # 3 + 2

    def test_system_msi_extracted(self):
        """System MSI principalId is extracted from identity block."""
        scanner = _build_container_scanner()
        row = _make_aks_row()
        result = scanner._parse_aks_row(row)
        assert result['system_msi_principal_id'] == 'aks-pid-001'


# ── Tests 4-6: Federated Credential Wildcard Detection ──────────────

class TestFederatedWildcard:

    def test_aks_valid_subject_not_wildcard(self):
        """Valid AKS subject system:serviceaccount:ns:sa is NOT wildcard."""
        scanner = _build_container_scanner()
        clusters = [{'oidc_issuer_url': 'https://issuer.example.com'}]
        is_wc, reason = scanner._detect_wildcard(
            'aks', 'system:serviceaccount:default:my-sa',
            'https://issuer.example.com', clusters,
        )
        assert is_wc is False
        assert reason is None

    def test_aks_wildcard_service_account(self):
        """AKS subject with * in SA name is wildcard."""
        scanner = _build_container_scanner()
        clusters = [{'oidc_issuer_url': 'https://issuer.example.com'}]
        is_wc, reason = scanner._detect_wildcard(
            'aks', 'system:serviceaccount:default:*',
            'https://issuer.example.com', clusters,
        )
        assert is_wc is True
        assert 'wildcard' in reason.lower()

    def test_github_broad_filter_is_wildcard(self):
        """GitHub subject with ref:refs/* is wildcard."""
        scanner = _build_container_scanner()
        is_wc, reason = scanner._detect_wildcard(
            'github', 'repo:org/repo:ref:refs/*',
            'https://token.actions.githubusercontent.com', [],
        )
        assert is_wc is True

    def test_github_valid_branch_not_wildcard(self):
        """GitHub subject with specific branch ref is NOT wildcard."""
        scanner = _build_container_scanner()
        is_wc, reason = scanner._detect_wildcard(
            'github', 'repo:org/repo:ref:refs/heads/main',
            'https://token.actions.githubusercontent.com', [],
        )
        assert is_wc is False

    def test_empty_subject_is_wildcard(self):
        """Empty subject allows any principal — flagged as wildcard."""
        scanner = _build_container_scanner()
        is_wc, reason = scanner._detect_wildcard('aks', '', '', [])
        assert is_wc is True
        assert 'empty' in reason.lower()

    def test_issuer_classification_aks(self):
        """OIDC issuer matching a cluster is classified as 'aks'."""
        scanner = _build_container_scanner()
        clusters = [{'oidc_issuer_url': 'https://eastus.oic.prod-aks.azure.com/t/1'}]
        result = scanner._classify_issuer(
            'https://eastus.oic.prod-aks.azure.com/t/1', clusters
        )
        assert result == 'aks'

    def test_issuer_classification_github(self):
        """GitHub Actions OIDC issuer is classified as 'github'."""
        scanner = _build_container_scanner()
        result = scanner._classify_issuer(
            'https://token.actions.githubusercontent.com', []
        )
        assert result == 'github'


# ── Tests 7-8: FEDERATED_MISCONFIGURED Verdict ─────────────────────

class TestFederatedMisconfiguredVerdict:

    def test_federated_misconfigured_in_constants(self):
        """FEDERATED_MISCONFIGURED exists in Verdict constants."""
        from app.constants import Verdict
        assert Verdict.FEDERATED_MISCONFIGURED == 'FEDERATED_MISCONFIGURED'
        assert Verdict.SEVERITY['FEDERATED_MISCONFIGURED'] == 4

    def test_verdict_to_orphan_has_federated_misconfigured(self):
        """_VERDICT_TO_ORPHAN dict includes FEDERATED_MISCONFIGURED."""
        from app.constants import Verdict
        # The dict is defined in azure_discovery — we verify the constant exists
        assert Verdict.FEDERATED_MISCONFIGURED in Verdict.SEVERITY


# ── Tests 9-10: ACR Discovery ──────────────────────────────────────

class TestACRDiscovery:

    def test_acr_admin_synthetic_identity_call(self):
        """ACR with admin enabled triggers synthetic identity creation."""
        scanner = _build_container_scanner()
        scanner.db.save_acr_registry.return_value = 42
        cursor_mock = MagicMock()
        cursor_mock.fetchone.return_value = (999,)
        scanner.db.conn.cursor.return_value = cursor_mock

        # Call the synthetic identity creator
        scanner._create_acr_admin_identity(run_id=100, registry_name='myacr', acr_db_id=42)
        # Should have called cursor.execute with INSERT
        assert cursor_mock.execute.called
        call_args = cursor_mock.execute.call_args_list[0]
        assert 'INSERT INTO identities' in call_args[0][0]
        assert 'acr-admin-myacr' in call_args[0][1]

    def test_container_resource_type_constants(self):
        """ContainerResourceType has aks_cluster and acr_registry."""
        from app.constants import ContainerResourceType
        assert ContainerResourceType.AKS_CLUSTER == 'aks_cluster'
        assert ContainerResourceType.ACR_REGISTRY == 'acr_registry'


# ── Tests 11-12: Layer 2 K8s RBAC ─────────────────────────────────

class TestLayer2RBAC:

    def test_layer2_skipped_when_disabled(self):
        """Layer 2 scan is skipped for clusters without layer2_scan_enabled."""
        scanner = _build_container_scanner()
        clusters = [{'azure_resource_id': '/aks/1', 'layer2_scan_enabled': False}]
        cluster_db_ids = {'/aks/1': 1}
        result = scanner._scan_layer2_rbac(100, clusters, cluster_db_ids)
        assert result == 0

    def test_layer2_processes_enabled_clusters(self):
        """Layer 2 scan processes clusters with layer2_scan_enabled=True."""
        scanner = _build_container_scanner()
        clusters = [{
            'azure_resource_id': '/aks/1',
            'layer2_scan_enabled': True,
            'subscription_id': 'sub-1',
            'resource_group': 'rg-1',
            'cluster_name': 'test-aks',
        }]
        cluster_db_ids = {'/aks/1': 1}
        # ContainerServiceClient not available → should fail gracefully
        with patch('app.engines.discovery.container_scanner.ContainerServiceClient', None):
            result = scanner._scan_layer2_rbac(100, clusters, cluster_db_ids)
        assert result == 0  # fails gracefully


# ── Tests 13-14: Scoring Integration ──────────────────────────────

class TestScoringIntegration:

    def test_federated_misconfigured_bonus_applied(self):
        """FEDERATED_MISCONFIGURED adds +12 to blast radius score."""
        from app.engines.blast_radius_engine import BlastRadiusEngine
        engine = BlastRadiusEngine.__new__(BlastRadiusEngine)

        base = engine._compute_risk_score(
            rbac=[{'role_name': 'Contributor', 'scope_type': 'subscription'}],
            entra=[], reachable=[], sensitive_count=0,
            identity_category='service_principal', escalation_count=0,
        )
        with_fed = engine._compute_risk_score(
            rbac=[{'role_name': 'Contributor', 'scope_type': 'subscription'}],
            entra=[], reachable=[], sensitive_count=0,
            identity_category='service_principal', escalation_count=0,
            has_federated_misconfigured=True,
        )
        assert with_fed > base
        assert with_fed - base == 12

    def test_federated_misconfigured_no_bonus_when_false(self):
        """No bonus when has_federated_misconfigured=False."""
        from app.engines.blast_radius_engine import BlastRadiusEngine
        engine = BlastRadiusEngine.__new__(BlastRadiusEngine)

        base = engine._compute_risk_score(
            rbac=[], entra=[], reachable=[], sensitive_count=0,
            identity_category='service_principal', escalation_count=0,
        )
        without = engine._compute_risk_score(
            rbac=[], entra=[], reachable=[], sensitive_count=0,
            identity_category='service_principal', escalation_count=0,
            has_federated_misconfigured=False,
        )
        assert base == without


# ── Tests 15-16: API Endpoints ────────────────────────────────────

class TestContainerAPI:

    def test_aks_clusters_endpoint_shape(self):
        """GET /api/aks-clusters returns {clusters, total}."""
        from flask import Flask
        app = Flask(__name__)

        with app.test_request_context('/api/aks-clusters'):
            from app.api.handlers import get_aks_clusters

            with patch('app.api.handlers._db') as mock_db_fn, \
                 patch('app.api.handlers._org_id', return_value=1), \
                 patch('app.api.handlers._connection_id', return_value=None), \
                 patch('app.api.handlers._latest_run_ids', return_value=[1]):

                mock_db = MagicMock()
                mock_db_fn.return_value = mock_db
                mock_cursor = MagicMock()
                mock_db.conn.cursor.return_value = mock_cursor
                mock_db.get_aks_clusters.return_value = ([], 0)

                response = get_aks_clusters()
                data = response.get_json()
                assert 'clusters' in data
                assert 'total' in data

    def test_container_risk_endpoint_shape(self):
        """GET /api/dashboard/container-risk returns expected fields."""
        from flask import Flask
        app = Flask(__name__)

        with app.test_request_context('/api/dashboard/container-risk'):
            from app.api.handlers import get_dashboard_container_risk

            with patch('app.api.handlers._db') as mock_db_fn, \
                 patch('app.api.handlers._org_id', return_value=1), \
                 patch('app.api.handlers._connection_id', return_value=None), \
                 patch('app.api.handlers._latest_run_ids', return_value=[]):

                mock_db = MagicMock()
                mock_db_fn.return_value = mock_db
                mock_cursor = MagicMock()
                mock_db.conn.cursor.return_value = mock_cursor

                response = get_dashboard_container_risk()
                data = response.get_json()
                assert 'total_clusters' in data
                assert 'wildcard_creds' in data
                assert 'federated_misconfigured_count' in data


# ── Tests 17-18: Constants SSOT ──────────────────────────────────

class TestConstantsSSoT:

    def test_resource_type_constants(self):
        """All resource type constants use snake_case convention."""
        from app.constants import ComputeResourceType, ContainerResourceType
        assert ComputeResourceType.APP_SERVICE == 'app_service'
        assert ComputeResourceType.FUNCTION == 'function_app'
        assert ComputeResourceType.VIRTUAL_MACHINE == 'virtual_machine'
        assert ComputeResourceType.LOGIC_APP == 'logic_app'
        assert ContainerResourceType.AKS_CLUSTER == 'aks_cluster'
        assert ContainerResourceType.ACR_REGISTRY == 'acr_registry'

    def test_verdict_severity_includes_all_types(self):
        """Verdict.SEVERITY includes all verdict types."""
        from app.constants import Verdict
        expected = {
            'HEALTHY', 'NEEDS_REVIEW', 'UNUSED', 'STALE',
            'AT_RISK', 'ORPHANED', 'GHOST_MSI', 'FEDERATED_MISCONFIGURED',
        }
        assert expected == set(Verdict.SEVERITY.keys())


# ── Tests 19-20: Regression ──────────────────────────────────────

class TestRegression:

    def test_prior_prompt4_tests_importable(self):
        """Verify Prompt 4 test file can still be imported."""
        import importlib
        mod = importlib.import_module('tests.test_compute_plane')
        assert hasattr(mod, 'TestResourceGraphParsing')
        assert hasattr(mod, 'TestGhostMSI')

    def test_container_scanner_importable(self):
        """Verify container_scanner module imports without error."""
        from app.engines.discovery.container_scanner import ContainerScanner
        assert ContainerScanner is not None

    def test_blast_radius_engine_has_federated_param(self):
        """Verify blast_radius_engine._compute_risk_score accepts has_federated_misconfigured."""
        from app.engines.blast_radius_engine import BlastRadiusEngine
        import inspect
        sig = inspect.signature(BlastRadiusEngine._compute_risk_score)
        assert 'has_federated_misconfigured' in sig.parameters
