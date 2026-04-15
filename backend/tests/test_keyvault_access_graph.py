"""Tests for Key Vault access graph API handler.

Covers:
  - Correct vault + items extraction from role assignments
  - CRITICAL-tier items highlighted in response
  - Empty response for identities with no KV roles
  - Org/connection scoping via run_ids
"""
import json
import pytest
from unittest.mock import patch, MagicMock

from app.api.handlers import get_identity_keyvault_access


# ── Helpers ────────────────────────────────────────────────────

def _mock_flask_context(identity_id, role_assignments, kv_items_by_vault=None):
    """Set up mocks for Flask request context + DB for get_identity_keyvault_access."""
    kv_items_by_vault = kv_items_by_vault or {}

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_db.conn.cursor.return_value = mock_cursor

    # First query: fetch role_assignments for identity
    mock_cursor.fetchone.return_value = (role_assignments,) if role_assignments else None

    def get_kv_items(vault_id):
        return kv_items_by_vault.get(vault_id, [])

    mock_db.get_keyvault_items_for_vault.side_effect = get_kv_items

    return mock_db, mock_cursor


# ── Test: correct vault + items ───────────────────────────────

@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_returns_vault_with_items(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Identity with KV role assignment returns vault + items."""
    ra = [
        {
            'role_definition_name': 'Key Vault Secrets Officer',
            'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/prod-vault',
        },
    ]
    vault_id = '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/prod-vault'
    items = [
        {'item_type': 'secret', 'item_name': 'db-password', 'enabled': True,
         'days_until_expiry': 5, 'expiry_risk_tier': 'CRITICAL'},
        {'item_type': 'key', 'item_name': 'signing-key', 'enabled': True,
         'days_until_expiry': 60, 'expiry_risk_tier': 'INFO'},
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-1', ra, {vault_id: items})
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-1')

    assert len(result['vaults']) == 1
    vault = result['vaults'][0]
    assert vault['vault_name'] == 'prod-vault'
    assert len(vault['items']) == 2
    assert vault['items'][0]['item_name'] == 'db-password'
    assert 'Key Vault Secrets Officer' in vault['roles']


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_critical_tier_items_present(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """CRITICAL-tier items are correctly returned in vault response."""
    ra = [
        {
            'role_definition_name': 'Reader',
            'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1',
        },
    ]
    vault_id = '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1'
    items = [
        {'item_type': 'secret', 'item_name': 'expired-secret', 'enabled': True,
         'days_until_expiry': -3, 'expiry_risk_tier': 'CRITICAL'},
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-2', ra, {vault_id: items})
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-2')

    assert result['vaults'][0]['items'][0]['expiry_risk_tier'] == 'CRITICAL'
    assert result['vaults'][0]['items'][0]['days_until_expiry'] == -3


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_empty_when_no_kv_roles(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Identity with no KV-scoped roles returns empty vaults list."""
    ra = [
        {
            'role_definition_name': 'Reader',
            'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1',
        },
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-3', ra)
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-3')

    assert result['vaults'] == []


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_empty_when_identity_not_found(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Identity not found returns empty vaults list."""
    mock_db, mock_cursor = _mock_flask_context('nonexistent', None)
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('nonexistent')

    assert result['vaults'] == []


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_multiple_vaults(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Identity with roles on multiple vaults returns all vaults."""
    ra = [
        {
            'role_definition_name': 'Key Vault Secrets Officer',
            'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/vault-a',
        },
        {
            'role_definition_name': 'Key Vault Reader',
            'scope': '/subscriptions/abc/resourceGroups/rg2/providers/Microsoft.KeyVault/vaults/vault-b',
        },
    ]
    vault_a = '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/vault-a'
    vault_b = '/subscriptions/abc/resourceGroups/rg2/providers/Microsoft.KeyVault/vaults/vault-b'
    items_a = [
        {'item_type': 'secret', 'item_name': 'secret-a', 'enabled': True,
         'days_until_expiry': 10, 'expiry_risk_tier': 'CRITICAL'},
    ]
    items_b = [
        {'item_type': 'certificate', 'item_name': 'cert-b', 'enabled': True,
         'days_until_expiry': 120, 'expiry_risk_tier': 'HEALTHY'},
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-4', ra, {vault_a: items_a, vault_b: items_b})
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-4')

    assert len(result['vaults']) == 2
    vault_names = {v['vault_name'] for v in result['vaults']}
    assert vault_names == {'vault-a', 'vault-b'}


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_multiple_roles_on_same_vault(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Multiple roles on the same vault are aggregated."""
    ra = [
        {
            'role_definition_name': 'Key Vault Secrets Officer',
            'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1',
        },
        {
            'role_definition_name': 'Reader',
            'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1',
        },
    ]
    vault_id = '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1'
    items = [
        {'item_type': 'secret', 'item_name': 'secret-1', 'enabled': True,
         'days_until_expiry': None, 'expiry_risk_tier': 'NONE'},
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-5', ra, {vault_id: items})
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-5')

    assert len(result['vaults']) == 1
    assert sorted(result['vaults'][0]['roles']) == ['Key Vault Secrets Officer', 'Reader']


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_nested_kv_scope_detected(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Scope deeper than vault level (e.g. /keys/mykey) still detects the vault."""
    ra = [
        {
            'role_definition_name': 'Contributor',
            'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1/keys/mykey',
        },
    ]
    vault_id = '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1'
    items = [
        {'item_type': 'key', 'item_name': 'mykey', 'enabled': True,
         'days_until_expiry': 25, 'expiry_risk_tier': 'WARNING'},
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-6', ra, {vault_id: items})
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-6')

    assert len(result['vaults']) == 1
    assert result['vaults'][0]['vault_name'] == 'kv1'


@patch('app.api.handlers._apply_sub_filter', lambda q, p, *a: (q, p))
@patch('app.api.handlers._connection_id', return_value=1)
@patch('app.api.handlers._org_id', return_value=1)
@patch('app.api.handlers._latest_run_ids', return_value=[100])
@patch('app.api.handlers._db')
def test_date_serialization(mock_db_fn, mock_run_ids, mock_org, mock_conn):
    """Datetime objects in KV items are serialized to ISO strings."""
    from datetime import datetime, timezone
    ra = [
        {
            'role_definition_name': 'Reader',
            'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1',
        },
    ]
    vault_id = '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1'
    expires = datetime(2025, 6, 15, tzinfo=timezone.utc)
    items = [
        {'item_type': 'secret', 'item_name': 's1', 'enabled': True,
         'expires_on': expires,
         'days_until_expiry': 30, 'expiry_risk_tier': 'WARNING'},
    ]

    mock_db, mock_cursor = _mock_flask_context('spn-7', ra, {vault_id: items})
    mock_db_fn.return_value = mock_db

    with patch('app.api.handlers.jsonify', side_effect=lambda x: x):
        result = get_identity_keyvault_access('spn-7')

    assert isinstance(result['vaults'][0]['items'][0]['expires_on'], str)
    assert '2025-06-15' in result['vaults'][0]['items'][0]['expires_on']
