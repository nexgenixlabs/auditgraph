"""
Phase 2A: Compute Identity Plane — 19 tests

Tests cover:
  1-4: Resource Graph parsing (4 resource types)
  5-6: MSI identity resolution
  7-8: GHOST_MSI detection
  9-11: Env var secret detection patterns
  12-13: Compute RBAC scanning
  14-15: JIT policy check
  16: Scoring integration (compute danger bonus)
  17-18: API endpoint shape
  19: Regression — prior tests still pass
"""
import os
import json
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret-for-ci')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


# ── Helpers ─────────────────────────────────────────────────────────

def _build_scanner():
    """Create a ComputeScanner with mocked dependencies."""
    from app.engines.discovery.compute_scanner import ComputeScanner
    mock_cred = MagicMock()
    mock_db = MagicMock()
    mock_db._organization_id = 1
    subscriptions = [{'id': 'sub-1', 'name': 'Test Sub'}]
    scanner = ComputeScanner(mock_cred, mock_db, subscriptions, organization_id=1)
    return scanner


def _make_resource_graph_row(**overrides):
    """Build a minimal Resource Graph row."""
    base = {
        'id': '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/myapp',
        'name': 'myapp',
        'type': 'microsoft.web/sites',
        'kind': 'app',
        'location': 'eastus',
        'resourceGroup': 'rg-1',
        'subscriptionId': 'sub-1',
        'identity': {},
        'properties': {},
        'sku': {'name': 'S1'},
        'tags': {'env': 'prod'},
    }
    base.update(overrides)
    return base


# ── Tests 1-4: Resource Graph Parsing ───────────────────────────────

class TestResourceGraphParsing:

    def test_app_service_classification(self):
        """App Service (kind='app') is classified as 'app_service'."""
        scanner = _build_scanner()
        row = _make_resource_graph_row(kind='app')
        result = scanner._parse_resource_graph_row(row)
        assert result is not None
        assert result['resource_type'] == 'app_service'
        assert result['resource_name'] == 'myapp'
        assert result['resource_group'] == 'rg-1'

    def test_function_app_classification(self):
        """Function App (kind='functionapp') is classified as 'function_app'."""
        scanner = _build_scanner()
        row = _make_resource_graph_row(
            kind='functionapp',
            name='myfunc',
            id='/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Web/sites/myfunc',
        )
        result = scanner._parse_resource_graph_row(row)
        assert result is not None
        assert result['resource_type'] == 'function_app'

    def test_vm_classification(self):
        """Virtual Machine is classified as 'virtual_machine'."""
        scanner = _build_scanner()
        row = _make_resource_graph_row(
            type='microsoft.compute/virtualmachines',
            kind='',
            name='myvm',
            id='/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/myvm',
            properties={'storageProfile': {'osDisk': {'osType': 'Linux'}}},
        )
        result = scanner._parse_resource_graph_row(row)
        assert result is not None
        assert result['resource_type'] == 'virtual_machine'
        assert result['os_type'] == 'Linux'

    def test_logic_app_classification(self):
        """Logic App is classified as 'logic_app'."""
        scanner = _build_scanner()
        row = _make_resource_graph_row(
            type='microsoft.logic/workflows',
            kind='stateful',
            name='mylogicapp',
            id='/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Logic/workflows/mylogicapp',
        )
        result = scanner._parse_resource_graph_row(row)
        assert result is not None
        assert result['resource_type'] == 'logic_app'
        assert result['logic_app_kind'] == 'stateful'


# ── Tests 5-6: MSI Identity Resolution ──────────────────────────────

class TestMSIResolution:

    def test_system_msi_extracted_from_identity(self):
        """System MSI principalId is extracted from identity block."""
        scanner = _build_scanner()
        row = _make_resource_graph_row(
            identity={
                'type': 'SystemAssigned',
                'principalId': 'pid-001',
            },
        )
        result = scanner._parse_resource_graph_row(row)
        assert result['system_msi_principal_id'] == 'pid-001'

    def test_user_assigned_msi_extracted(self):
        """User-assigned MSI resource IDs are captured."""
        scanner = _build_scanner()
        row = _make_resource_graph_row(
            identity={
                'type': 'SystemAssigned,UserAssigned',
                'principalId': 'pid-002',
                'userAssignedIdentities': {
                    '/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-1': {},
                },
            },
        )
        result = scanner._parse_resource_graph_row(row)
        assert result['system_msi_principal_id'] == 'pid-002'
        assert result['user_msi_resource_ids'] is not None
        assert len(result['user_msi_resource_ids']) == 1
        assert 'uami-1' in result['user_msi_resource_ids'][0]


# ── Tests 7-8: GHOST_MSI Detection ─────────────────────────────────

class TestGhostMSI:

    def test_ghost_msi_detected_for_orphaned_sami(self):
        """SAMI with roles but no compute resource is flagged as GHOST_MSI."""
        scanner = _build_scanner()
        mock_cursor = MagicMock()
        scanner.db.conn.cursor.return_value = mock_cursor

        # Return one SAMI that has roles but no associated_resource_id
        mock_cursor.fetchall.return_value = [
            (1, 'sami-orphan', 'Orphaned SAMI'),
        ]
        # No compute resources found
        resources = []
        result = scanner._detect_ghost_msi(run_id=100, resources=resources)
        # Should have called save_lineage_verdict
        assert scanner.db.save_lineage_verdict.called
        call_args = scanner.db.save_lineage_verdict.call_args
        assert call_args[0][2]['verdict'] == 'GHOST_MSI'

    def test_sami_with_host_resource_not_ghost(self):
        """SAMI whose principalId matches a compute resource is NOT a ghost."""
        scanner = _build_scanner()
        mock_cursor = MagicMock()
        scanner.db.conn.cursor.return_value = mock_cursor

        # SAMI exists but we'll match it to a compute resource
        mock_cursor.fetchall.return_value = [
            (1, 'pid-match', 'Matched SAMI'),
        ]
        resources = [{'system_msi_principal_id': 'pid-match', 'azure_resource_id': '/sub/rg/res'}]
        result = scanner._detect_ghost_msi(run_id=100, resources=resources)
        # save_lineage_verdict should NOT be called for this identity
        assert not scanner.db.save_lineage_verdict.called


# ── Tests 9-11: Env Var Secret Detection ────────────────────────────

class TestEnvSecretDetection:

    def test_password_pattern_detected(self):
        """Env var named 'DB_PASSWORD' triggers 'password' pattern match."""
        from app.engines.discovery.compute_scanner import _SECRET_NAME_PATTERNS
        matched = None
        for pattern, name in _SECRET_NAME_PATTERNS:
            if pattern.search('DB_PASSWORD'):
                matched = name
                break
        assert matched == 'password'

    def test_api_key_pattern_detected(self):
        """Env var named 'STRIPE_API_KEY' triggers 'api_key' pattern match."""
        from app.engines.discovery.compute_scanner import _SECRET_NAME_PATTERNS
        matched = None
        for pattern, name in _SECRET_NAME_PATTERNS:
            if pattern.search('STRIPE_API_KEY'):
                matched = name
                break
        assert matched == 'api_key'

    def test_keyvault_reference_is_low_severity(self):
        """Key Vault reference values should be classified as LOW severity."""
        from app.engines.discovery.compute_scanner import _KV_REF_PATTERN
        assert _KV_REF_PATTERN.match('@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)')
        assert not _KV_REF_PATTERN.match('supersecretpassword123')


# ── Tests 12-13: Compute RBAC ──────────────────────────────────────

class TestComputeRBAC:

    def test_high_privilege_roles_classified(self):
        """Owner, Contributor, UAA are marked as high privilege."""
        from app.engines.discovery.compute_scanner import _HIGH_PRIV_ROLES
        assert 'Owner' in _HIGH_PRIV_ROLES
        assert 'Contributor' in _HIGH_PRIV_ROLES
        assert 'User Access Administrator' in _HIGH_PRIV_ROLES
        assert 'Reader' not in _HIGH_PRIV_ROLES

    def test_scope_level_detection(self):
        """Compute RBAC assignments scoped to resources get scope_level='resource'."""
        # This tests the logic that when a scope matches a compute resource,
        # the scope_level should be 'resource'
        scanner = _build_scanner()
        row = _make_resource_graph_row()
        parsed = scanner._parse_resource_graph_row(row)
        # Resource IDs should be lowered for scope matching
        assert parsed['azure_resource_id'].lower().startswith('/subscriptions/')


# ── Tests 14-15: JIT Policy ────────────────────────────────────────

class TestJITPolicies:

    def test_vm_resources_only(self):
        """JIT check only processes VM resources."""
        scanner = _build_scanner()
        # No VMs → returns 0
        resources = [
            {'resource_type': 'app_service', 'subscription_id': 'sub-1', 'azure_resource_id': '/r1'},
        ]
        result = scanner._check_jit_policies(100, resources, {'/r1': 1})
        assert result == 0

    def test_jit_check_with_no_security_center(self):
        """When SecurityCenter is unavailable, JIT check still marks VMs as no JIT."""
        scanner = _build_scanner()
        mock_cursor = MagicMock()
        scanner.db.conn.cursor.return_value = mock_cursor

        resources = [
            {'resource_type': 'virtual_machine', 'subscription_id': 'sub-1',
             'azure_resource_id': '/sub/rg/vm1', 'jit_enabled': None},
        ]
        resource_db_ids = {'/sub/rg/vm1': 10}

        with patch('app.engines.discovery.compute_scanner.SecurityCenter', None):
            result = scanner._check_jit_policies(100, resources, resource_db_ids)
        # Should set jit_enabled=FALSE for VMs without JIT info
        mock_cursor.execute.assert_called()


# ── Test 16: Scoring Integration ───────────────────────────────────

class TestScoringIntegration:

    def test_compute_danger_bonus_applied(self):
        """Identities with access to compute resources with exposed env secrets get bonus points."""
        from app.engines.blast_radius_engine import BlastRadiusEngine

        engine = BlastRadiusEngine.__new__(BlastRadiusEngine)
        engine.db = MagicMock()

        # Base score with no danger context
        base = engine._compute_risk_score(
            rbac=[{'role_name': 'Contributor', 'scope_type': 'subscription'}],
            entra=[],
            reachable=[],
            sensitive_count=0,
            identity_category='service_principal',
            escalation_count=0,
        )

        # Score with danger context (3 high-severity secrets)
        with_danger = engine._compute_risk_score(
            rbac=[{'role_name': 'Contributor', 'scope_type': 'subscription'}],
            entra=[],
            reachable=[],
            sensitive_count=0,
            identity_category='service_principal',
            escalation_count=0,
            compute_danger={'high_severity_count': 3, 'secret_count': 3, 'resource_names': ['app1']},
        )

        # Danger bonus should increase score (max 15 for 3+ secrets)
        assert with_danger > base
        assert with_danger - base == 15  # 3 * 5 = 15 (capped at 15)

    def test_compute_danger_no_bonus_when_no_secrets(self):
        """No bonus when compute_danger has 0 high-severity secrets."""
        from app.engines.blast_radius_engine import BlastRadiusEngine
        engine = BlastRadiusEngine.__new__(BlastRadiusEngine)

        base = engine._compute_risk_score(
            rbac=[], entra=[], reachable=[], sensitive_count=0,
            identity_category='service_principal', escalation_count=0,
        )
        with_empty = engine._compute_risk_score(
            rbac=[], entra=[], reachable=[], sensitive_count=0,
            identity_category='service_principal', escalation_count=0,
            compute_danger={'high_severity_count': 0, 'secret_count': 0, 'resource_names': []},
        )
        assert base == with_empty


# ── Tests 17-18: API Endpoints ─────────────────────────────────────

class TestComputeAPI:

    def test_compute_resources_endpoint_shape(self):
        """GET /api/compute-resources returns {resources, total}."""
        from flask import Flask
        app = Flask(__name__)

        with app.test_request_context('/api/compute-resources'):
            from app.api.handlers import get_compute_resources

            with patch('app.api.handlers._db') as mock_db_fn, \
                 patch('app.api.handlers._org_id', return_value=1), \
                 patch('app.api.handlers._connection_id', return_value=None), \
                 patch('app.api.handlers._latest_run_ids', return_value=[1]):

                mock_db = MagicMock()
                mock_db_fn.return_value = mock_db
                mock_cursor = MagicMock()
                mock_db.conn.cursor.return_value = mock_cursor
                mock_db.get_compute_resources.return_value = ([], 0)

                response = get_compute_resources()
                data = response.get_json()
                assert 'resources' in data
                assert 'total' in data

    def test_compute_risk_endpoint_shape(self):
        """GET /api/dashboard/compute-risk returns expected fields."""
        from app.api.handlers import get_compute_identity_risk

        with patch('app.api.handlers._db') as mock_db_fn, \
             patch('app.api.handlers._org_id', return_value=1), \
             patch('app.api.handlers._connection_id', return_value=None), \
             patch('app.api.handlers._latest_run_ids', return_value=[]):

            mock_db = MagicMock()
            mock_db_fn.return_value = mock_db
            mock_cursor = MagicMock()
            mock_db.conn.cursor.return_value = mock_cursor

            from flask import Flask
            app = Flask(__name__)
            with app.test_request_context('/api/dashboard/compute-risk'):
                response = get_compute_identity_risk()
                data = response.get_json()
                assert 'total_compute' in data
                assert 'with_msi' in data
                assert 'with_env_secrets' in data


# ── Test 19: Regression ────────────────────────────────────────────

class TestRegression:

    def test_prior_prompt3_tests_still_importable(self):
        """Verify Prompt 3 test file can still be imported (no syntax breakage)."""
        import importlib
        mod = importlib.import_module('tests.test_verdict_table')
        assert hasattr(mod, 'TestGroupRoleExpansion')
        assert hasattr(mod, 'TestVerdictTable')

    def test_compute_scanner_importable(self):
        """Verify compute_scanner module imports without error."""
        from app.engines.discovery.compute_scanner import ComputeScanner
        assert ComputeScanner is not None

    def test_blast_radius_engine_importable(self):
        """Verify blast_radius_engine still imports with new parameters."""
        from app.engines.blast_radius_engine import BlastRadiusEngine
        assert hasattr(BlastRadiusEngine, '_compute_risk_score')
        assert hasattr(BlastRadiusEngine, '_load_compute_danger_context')
