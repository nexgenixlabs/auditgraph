"""
Attack Path Builder — unit tests

Tests the AttackPathBuilder engine, scope parsing helpers,
and end-to-end path construction with mock DB data.
"""
import os

os.environ.setdefault('APP_ENV', 'local')
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('JWT_SECRET', 'test-secret')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test')
os.environ.setdefault('CLIENT_JWT_SECRET', 'client-test')

from app.engines.attack_paths.attack_path_builder import (
    AttackPathBuilder,
    _parse_scope_level,
    _format_scope_label,
    _format_blast_label,
    _extract_vault_name,
)


# ── _parse_scope_level tests ──────────────────────────────────────────

def test_parse_scope_level_subscription():
    scope = '/subscriptions/abc-123'
    assert _parse_scope_level(scope) == 'subscription'


def test_parse_scope_level_resource_group():
    scope = '/subscriptions/abc-123/resourceGroups/rg-prod'
    assert _parse_scope_level(scope) == 'resource_group'


def test_parse_scope_level_resource():
    scope = '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1'
    assert _parse_scope_level(scope) == 'resource'


def test_parse_scope_level_directory():
    # Entra role — no /subscriptions/ prefix
    scope = '/providers/Microsoft.Authorization'
    assert _parse_scope_level(scope) == 'directory'


def test_parse_scope_level_empty():
    assert _parse_scope_level('') == 'directory'
    assert _parse_scope_level(None) == 'directory'


# ── _format_scope_label tests ────────────────────────────────────────

def test_format_scope_label_subscription():
    scope = '/subscriptions/abcdef12-3456-7890-abcd-ef1234567890'
    label = _format_scope_label(scope, 'subscription')
    assert label == 'Subscription: abcdef12...'


def test_format_scope_label_resource_group():
    scope = '/subscriptions/abc/resourceGroups/rg-production'
    label = _format_scope_label(scope, 'resource_group')
    assert label == 'Resource Group: rg-production'


def test_format_scope_label_resource():
    scope = '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa-prod'
    label = _format_scope_label(scope, 'resource')
    assert label == 'sa-prod'


def test_format_scope_label_directory():
    label = _format_scope_label('', 'directory')
    assert label == 'Entra Directory'


# ── _format_blast_label tests ────────────────────────────────────────

def test_format_blast_label_subscription():
    label = _format_blast_label('subscription')
    assert 'resource groups and resources' in label


def test_format_blast_label_resource_group():
    label = _format_blast_label('resource_group')
    assert 'resources in this resource group' in label


def test_format_blast_label_resource():
    label = _format_blast_label('resource')
    assert 'specific resource' in label


def test_format_blast_label_directory():
    label = _format_blast_label('directory')
    assert 'Entra directory' in label


# ── _extract_vault_name tests ────────────────────────────────────────

def test_extract_vault_name_from_arm_id():
    scope = '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-prod-01'
    assert _extract_vault_name(scope) == 'kv-prod-01'


def test_extract_vault_name_empty():
    assert _extract_vault_name('/subscriptions/abc') == ''
    assert _extract_vault_name('') == ''


# ── Mock DB for integration tests ────────────────────────────────────

class MockDB:
    """Minimal mock of Database for path builder tests."""

    def __init__(self, identities=None, role_assignments=None,
                 keyvault_items=None, saved_paths=None):
        self._identities = identities or []
        self._role_assignments = role_assignments or {}
        self._keyvault_items = keyvault_items or []
        self.saved_paths = saved_paths if saved_paths is not None else []

    def get_identities_for_path_building(self, connection_id):
        return self._identities

    def get_role_assignments_for_identity(self, identity_db_id):
        return self._role_assignments.get(identity_db_id, [])

    def get_keyvault_items_by_scope(self, scope_prefix):
        return self._keyvault_items

    def save_attack_path(self, path_dict):
        self.saved_paths.append(path_dict)
        return path_dict


# ── Integration: SPN with subscription Owner → CRITICAL path ─────────

def test_spn_subscription_owner_creates_critical_path():
    db = MockDB(
        identities=[{
            'id': 1,
            'identity_id': 'spn-abc-123',
            'display_name': 'svc-etl',
            'identity_type': 'service_principal',
            'verdict': 'ORPHANED',
            'agirs_score': 82,
            'owner_count': 0,
            'credential_status': 'valid',
            'credentials_expired': False,
        }],
        role_assignments={
            1: [{
                'role_name': 'Owner',
                'role_definition_name': 'Owner',
                'scope': '/subscriptions/abc-def-123',
                'scope_type': 'subscription',
            }],
        },
    )

    builder = AttackPathBuilder()
    count = builder.build_paths_for_connection(1, db)

    assert count == 1
    path = db.saved_paths[0]
    assert path['has_subscription_scope'] is True
    assert path['path_risk_tier'] == 'CRITICAL'
    assert path['highest_scope_level'] == 'subscription'
    assert path['highest_role'] == 'Owner'
    assert path['has_no_owner'] is True

    # Verify node chain
    nodes = path['path_nodes']
    assert nodes[0]['type'] == 'identity'
    assert nodes[1]['type'] == 'role'
    assert nodes[1]['label'] == 'Owner'
    assert nodes[2]['type'] == 'scope'
    assert nodes[3]['type'] == 'blast_boundary'


# ── Integration: KV Secrets User + 2 critical items ──────────────────

def test_kv_tier_with_critical_items():
    db = MockDB(
        identities=[{
            'id': 2,
            'identity_id': 'spn-kv-reader',
            'display_name': 'svc-keyvault',
            'identity_type': 'service_principal',
            'verdict': 'AT_RISK',
            'agirs_score': 55,
            'owner_count': 1,
            'credential_status': 'valid',
            'credentials_expired': False,
        }],
        role_assignments={
            2: [{
                'role_name': 'Key Vault Secrets User',
                'role_definition_name': 'Key Vault Secrets User',
                'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-prod',
                'scope_type': 'resource',
            }],
        },
        keyvault_items=[
            {'item_name': 'db-password', 'item_type': 'secret',
             'expiry_risk_tier': 'CRITICAL', 'days_until_expiry': 5,
             'vault_name': 'kv-prod', 'vault_resource_id': '/sub/rg/kv'},
            {'item_name': 'api-key', 'item_type': 'secret',
             'expiry_risk_tier': 'CRITICAL', 'days_until_expiry': 10,
             'vault_name': 'kv-prod', 'vault_resource_id': '/sub/rg/kv'},
            {'item_name': 'cert-1', 'item_type': 'certificate',
             'expiry_risk_tier': 'WARNING', 'days_until_expiry': 30,
             'vault_name': 'kv-prod', 'vault_resource_id': '/sub/rg/kv'},
        ],
    )

    builder = AttackPathBuilder()
    count = builder.build_paths_for_connection(1, db)

    assert count == 1
    path = db.saved_paths[0]
    assert path['has_keyvault_access'] is True
    assert path['keyvault_critical_items'] == 2

    # Should have keyvault node as 5th element
    nodes = path['path_nodes']
    assert len(nodes) == 5
    kv_node = nodes[4]
    assert kv_node['type'] == 'keyvault'
    assert kv_node['vault_name'] == 'kv-prod'
    assert kv_node['critical_items'] == 2
    assert len(kv_node['items']) == 3


# ── Integration: 2 different role/scope combos → 2 paths ─────────────

def test_multiple_role_scope_combos():
    db = MockDB(
        identities=[{
            'id': 3,
            'identity_id': 'spn-multi',
            'display_name': 'svc-multi',
            'identity_type': 'service_principal',
            'verdict': 'HEALTHY',
            'agirs_score': 30,
            'owner_count': 1,
            'credential_status': 'valid',
            'credentials_expired': False,
        }],
        role_assignments={
            3: [
                {
                    'role_name': 'Owner',
                    'role_definition_name': 'Owner',
                    'scope': '/subscriptions/sub-1',
                    'scope_type': 'subscription',
                },
                {
                    'role_name': 'Reader',
                    'role_definition_name': 'Reader',
                    'scope': '/subscriptions/sub-1/resourceGroups/rg-dev',
                    'scope_type': 'resource_group',
                },
            ],
        },
    )

    builder = AttackPathBuilder()
    count = builder.build_paths_for_connection(1, db)

    assert count == 2
    tiers = {p['highest_role'] for p in db.saved_paths}
    assert 'Owner' in tiers
    assert 'Reader' in tiers


# ── Integration: no role assignments → 0 paths ───────────────────────

def test_no_role_assignments_no_paths():
    db = MockDB(
        identities=[{
            'id': 4,
            'identity_id': 'spn-idle',
            'display_name': 'svc-idle',
            'identity_type': 'service_principal',
            'verdict': 'UNUSED',
            'agirs_score': 10,
            'owner_count': 0,
            'credential_status': 'expired',
            'credentials_expired': True,
        }],
        role_assignments={4: []},
    )

    builder = AttackPathBuilder()
    count = builder.build_paths_for_connection(1, db)

    assert count == 0
    assert len(db.saved_paths) == 0
