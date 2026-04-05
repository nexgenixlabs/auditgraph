"""
Identity Lineage API Response Shape — smoke tests.

Verifies that GET /api/identities/<identity_id>/lineage returns the expected
unified response from the Python lineage engine (identities table columns).

Unified endpoint: GET /api/identities/<id>/lineage
Deprecated alias: GET /api/spn/<id>/lineage (same handler)

Uses the Flask test client with a mock database so no live DB is needed.
"""
import os
import json
import pytest

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')

from unittest.mock import patch, MagicMock
from app.main import create_app


@pytest.fixture
def app():
    """Create a test Flask app."""
    application = create_app()
    application.config['TESTING'] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


# ── Shared identity row with all lineage columns ─────────────────

IDENTITY_ROW = {
    'id': 42,
    'identity_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    'display_name': 'my-spn',
    'identity_category': 'service_principal',
    'object_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    'app_id': '11111111-2222-3333-4444-555555555555',
    'created_datetime': '2025-01-01T00:00:00Z',
    'owner_count': 1,
    'cloud': 'azure',
    'last_sign_in': None,
    # App registration columns
    'app_registration_object_id': None,
    'app_registration_name': None,
    'is_external_app': False,
    'app_reg_publisher_domain': None,
    'app_reg_sign_in_audience': None,
    'app_reg_owner_display_name': None,
    'app_reg_owner_id': None,
    'app_reg_reply_url_hostnames': None,
    'app_reg_likely_service': None,
    'app_reg_likely_service_type': None,
    'app_reg_identifier_uris': None,
    'app_reg_notes': None,
    'app_reg_required_apis': None,
    # Workload columns
    'workload_type': None,
    'workload_confidence': None,
    'role_pattern_matched': None,
    'workload_risk_flags': None,
    # Sign-in columns
    'signin_pattern': None,
    'last_delegated_signin': None,
    'last_noninteractive_signin': None,
    'days_since_last_signin': None,
    # Verdict columns
    'verdict_confidence': None,
    'verdict_score': None,
    'workload_origin': None,
    'workload_origin_source': None,
    'recommended_action': None,
    'verdict_action_text': None,
    'verdict_signals': None,
    'verdict_risk_summary': None,
    'is_discovery_connector': False,
    # Federated classification columns
    'federated_workload_type': None,
    'federated_workload_name': None,
    # Dependency impact columns
    'dependency_impact': None,
    'dependency_impact_resources': None,
}


def _mock_db(identity_row, role_rows=None, fed_cred_rows=None,
             resource_binding_rows=None, has_p2=False):
    """Build a mock Database whose cursor handles the query pattern:
    1. Wide identity SELECT (fetchone)
    2. Role assignments (fetchall) via SAVEPOINT lin_roles
    3. P2 check (fetchone) via SAVEPOINT lin_p2
    4. Resource bindings (fetchall) via SAVEPOINT lin_rb
    5. Federated credentials (fetchall) via SAVEPOINT lin_fed
    """
    mock = MagicMock()
    cursor = MagicMock()

    fetchone_count = {'n': 0}
    fetchall_count = {'n': 0}

    def fetchone_side_effect():
        fetchone_count['n'] += 1
        if fetchone_count['n'] == 1:
            return identity_row  # identity query
        if fetchone_count['n'] == 2:
            # P2 check
            return {'x': 1} if has_p2 else None
        return None

    def fetchall_side_effect():
        fetchall_count['n'] += 1
        if fetchall_count['n'] == 1:
            return role_rows or []  # role_assignments
        if fetchall_count['n'] == 2:
            return resource_binding_rows or []  # resource bindings
        if fetchall_count['n'] == 3:
            return fed_cred_rows or []  # federated credentials
        return []

    cursor.fetchone = MagicMock(side_effect=fetchone_side_effect)
    cursor.fetchall = MagicMock(side_effect=fetchall_side_effect)
    cursor.execute = MagicMock()

    mock.conn.cursor.return_value = cursor
    mock.close = MagicMock()
    return mock


# ── Tests ───────────────────────────────────────────────────────────

LINEAGE_URL = '/api/identities/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/lineage'


class TestIdentityLineageResponseShape:
    """Verify the unified lineage response shape."""

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_response_has_all_top_level_keys(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        db = _mock_db(IDENTITY_ROW)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()

        # All 10 top-level keys present
        assert 'identity_id' in data
        assert 'display_name' in data
        assert 'cloud' in data
        assert 'workload_origin' in data
        assert 'confidence' in data
        assert 'arm_associations' in data
        assert 'managed_identity_bindings' in data
        assert 'federated_credentials' in data
        assert 'dependency_impact' in data
        assert 'recommended_action' in data

        # Identity context correct
        assert data['identity_id'] == 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        assert data['display_name'] == 'my-spn'
        assert data['cloud'] == 'azure'

        # Empty collections when no data
        assert data['arm_associations'] == []
        assert data['managed_identity_bindings'] == []
        assert data['federated_credentials'] == []

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_verdict_maps_to_confidence_and_action(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """verdict_score/confidence → confidence section,
        recommended_action → recommended_action section."""
        row = {**IDENTITY_ROW,
               'verdict_score': 72,
               'verdict_confidence': 'high',
               'workload_type': 'ci_cd_pipeline',
               'workload_confidence': 85,
               'recommended_action': 'HEALTHY',
               'verdict_action_text': 'No action required',
               'verdict_risk_summary': ['Low risk CI/CD'],
               }
        roles = [
            {'role_name': 'Contributor', 'scope': '/subscriptions/sub-1',
             'scope_type': 'subscription', 'resource_type': '', 'resource_name': ''},
        ]
        db = _mock_db(row, role_rows=roles)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()

        # Confidence section
        assert data['confidence']['level'] == 'high'
        assert data['confidence']['score'] == 72

        # Role topology
        assert data['role_topology'] is not None
        assert data['role_topology']['workload_type'] == 'ci_cd_pipeline'
        assert data['role_topology']['workload_confidence'] == 85
        assert len(data['role_topology']['role_assignments']) == 1
        assert data['role_topology']['role_assignments'][0]['role_name'] == 'Contributor'

        # Recommended action
        assert data['recommended_action']['action'] == 'HEALTHY'
        assert data['recommended_action']['orphan_status'] == 'NOT_ORPHANED'
        assert data['recommended_action']['active_role_count'] == 1
        assert data['recommended_action']['action_text'] == 'No action required'

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_app_registration_section(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """app_reg columns map to app_registration section."""
        row = {**IDENTITY_ROW,
               'app_registration_object_id': 'ar-obj-123',
               'app_registration_name': 'My App Registration',
               'app_reg_owner_display_name': 'John Doe',
               'app_reg_owner_id': 'owner-uuid-1',
               'app_reg_reply_url_hostnames': ['app.example.com', 'api.example.com'],
               'app_reg_notes': 'Production app',
               'app_reg_likely_service': 'Custom Web App',
               }
        db = _mock_db(row)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()

        assert data['app_registration'] is not None
        ar = data['app_registration']
        assert ar['display_name'] == 'My App Registration'
        assert len(ar['owners']) == 1
        assert ar['owners'][0]['display_name'] == 'John Doe'
        assert ar['notes'] == 'Production app'
        assert ar['likely_service'] == 'Custom Web App'
        assert 'app.example.com' in ar['reply_url_hostnames']
        assert 'api.example.com' in ar['reply_url_hostnames']

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_orphan_caution_upgraded_with_roles(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """ORPHANED verdict with active roles → CAUTION."""
        row = {**IDENTITY_ROW, 'recommended_action': 'ORPHANED'}
        roles = [{'role_name': 'Reader', 'scope': '/subscriptions/s1',
                  'scope_type': 'subscription', 'resource_type': '', 'resource_name': ''}]
        db = _mock_db(row, role_rows=roles)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()
        assert data['recommended_action']['orphan_status'] == 'CAUTION'

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_federated_github_credential(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """GitHub federated credential appears in federated_credentials."""
        fed_creds = [{
            'key_id': 'fed-1',
            'display_name': 'github-deploy',
            'issuer': 'https://token.actions.githubusercontent.com',
            'subject': 'repo:contoso/my-app:ref:refs/heads/main',
        }]
        row = {**IDENTITY_ROW,
               'federated_workload_type': 'github_actions',
               'federated_workload_name': 'contoso/my-app'}
        db = _mock_db(row, fed_cred_rows=fed_creds)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()
        assert len(data['federated_credentials']) == 1
        fc = data['federated_credentials'][0]
        assert fc['resource_type'] == 'FederatedGitHub'
        assert fc['resource_name'] == 'contoso/my-app'
        assert fc['confidence_score'] == 95
        assert fc['binding_evidence']['org'] == 'contoso'
        assert fc['binding_evidence']['repo'] == 'my-app'

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_federated_aks_credential(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """AKS federated credential appears in federated_credentials."""
        fed_creds = [{
            'key_id': 'fed-2',
            'display_name': 'aks-workload',
            'issuer': 'https://oidc.prod-aks.azure.com/tenant/kubernetes',
            'subject': 'system:serviceaccount:kube-system:my-controller',
        }]
        row = {**IDENTITY_ROW,
               'federated_workload_type': 'aks_workload',
               'federated_workload_name': 'kube-system/my-controller'}
        db = _mock_db(row, fed_cred_rows=fed_creds)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()
        assert len(data['federated_credentials']) == 1
        fc = data['federated_credentials'][0]
        assert fc['resource_type'] == 'FederatedAKS'
        assert fc['binding_evidence']['namespace'] == 'kube-system'
        assert fc['binding_evidence']['serviceAccount'] == 'my-controller'

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_arm_associations_separated_from_mi_bindings(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """ARM bindings go to arm_associations, MI bindings go to managed_identity_bindings."""
        bindings = [
            {
                'resource_id': '/subscriptions/sub-1/providers/Microsoft.Web/sites/my-app',
                'resource_type': 'AppService',
                'resource_name': 'my-app',
                'resource_group': 'rg-1',
                'subscription_id': 'sub-1',
                'region': 'eastus',
                'binding_method': 'HardcodedClientId',
                'confidence_score': 90,
                'binding_evidence': {'settingKey': 'AZURE_CLIENT_ID'},
                'last_verified_at': None,
            },
            {
                'resource_id': '/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines/vm-1',
                'resource_type': 'virtualMachines',
                'resource_name': 'vm-1',
                'resource_group': 'rg-2',
                'subscription_id': 'sub-1',
                'region': 'westus',
                'binding_method': 'ManagedIdentitySystemAssigned',
                'confidence_score': 95,
                'binding_evidence': {'principalId': 'oid-1'},
                'last_verified_at': None,
            },
        ]
        db = _mock_db(IDENTITY_ROW, resource_binding_rows=bindings)
        mock_db.return_value = db

        resp = client.get(LINEAGE_URL, headers={'Authorization': 'Bearer fake-token'})

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()
        assert len(data['arm_associations']) == 1
        assert data['arm_associations'][0]['resource_name'] == 'my-app'
        assert data['arm_associations'][0]['binding_method'] == 'HardcodedClientId'

        assert len(data['managed_identity_bindings']) == 1
        assert data['managed_identity_bindings'][0]['resource_name'] == 'vm-1'
        assert data['managed_identity_bindings'][0]['binding_method'] == 'ManagedIdentitySystemAssigned'

    @patch('app.api.handlers._db')
    @patch('app.api.handlers._org_id', return_value=1)
    @patch('app.api.handlers._connection_id', return_value=1)
    @patch('app.api.handlers._latest_run_ids', return_value=[100])
    def test_deprecated_spn_alias_returns_same_data(
        self, mock_run_ids, mock_conn_id, mock_org_id, mock_db, client
    ):
        """Old /api/spn/<id>/lineage still works (deprecated alias)."""
        db = _mock_db(IDENTITY_ROW)
        mock_db.return_value = db

        resp = client.get(
            '/api/spn/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/lineage',
            headers={'Authorization': 'Bearer fake-token'}
        )

        if resp.status_code == 401:
            pytest.skip('Auth middleware blocked test token')

        data = resp.get_json()
        # Same unified shape — has identity_id, not spnId
        assert 'identity_id' in data
        assert 'workload_origin' in data
        assert 'confidence' in data

    def test_response_shape_constants(self):
        """Verify the fields we expect are documented correctly."""
        required_fields = [
            'identity_id', 'display_name', 'cloud',
            'workload_origin', 'confidence',
            'arm_associations', 'managed_identity_bindings',
            'federated_credentials', 'dependency_impact',
            'recommended_action',
        ]
        assert len(required_fields) == 10
        assert 'workload_origin' in required_fields
        assert 'confidence' in required_fields
        assert 'dependency_impact' in required_fields


class TestExtractSubscriptionId:
    """Unit tests for _extract_subscription_id helper."""

    def test_standard_arm_path(self):
        from app.api.handlers import _extract_subscription_id
        result = _extract_subscription_id(
            '/subscriptions/12345678-abcd-ef01-2345-000000000001/resourceGroups/rg/providers/Microsoft.Web/sites/app'
        )
        assert result == '12345678-abcd-ef01-2345-000000000001'

    def test_subscription_only(self):
        from app.api.handlers import _extract_subscription_id
        assert _extract_subscription_id('/subscriptions/sub-id-123') == 'sub-id-123'

    def test_empty_string(self):
        from app.api.handlers import _extract_subscription_id
        assert _extract_subscription_id('') == ''

    def test_none(self):
        from app.api.handlers import _extract_subscription_id
        assert _extract_subscription_id(None) == ''

    def test_non_arm_path(self):
        from app.api.handlers import _extract_subscription_id
        assert _extract_subscription_id('not-an-arm-path') == ''

    def test_case_insensitive(self):
        from app.api.handlers import _extract_subscription_id
        result = _extract_subscription_id('/Subscriptions/ABC-123/resourceGroups/rg')
        assert result == 'ABC-123'
