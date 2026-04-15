"""Tests for classify_role_privilege_tier in the AGIRS engine."""
import pytest
from app.engines.risk.agirs_engine import classify_role_privilege_tier


# ── Exact-match HIGH roles ─────────────────────────────────────────

def test_owner_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Owner', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_contributor_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Contributor', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_user_access_administrator_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'User Access Administrator', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_storage_blob_data_owner_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Storage Blob Data Owner', 'scope': '/subscriptions/abc/resourceGroups/rg1'}) == 'HIGH'


def test_managed_identity_operator_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Managed Identity Operator', 'scope': '/subscriptions/abc'}) == 'HIGH'


# ── Exact-match MEDIUM roles ──────────────────────────────────────

def test_reader_is_medium():
    assert classify_role_privilege_tier({'role_definition_name': 'Reader', 'scope': '/subscriptions/abc'}) == 'MEDIUM'


def test_kv_secrets_user_is_medium():
    """Key Vault Secrets User is MEDIUM when scope is NOT a Key Vault resource."""
    assert classify_role_privilege_tier({'role_definition_name': 'Key Vault Secrets User', 'scope': '/subscriptions/abc'}) == 'MEDIUM'


def test_security_reader_is_medium():
    assert classify_role_privilege_tier({'role_definition_name': 'Security Reader', 'scope': '/subscriptions/abc'}) == 'MEDIUM'


# ── KEY_VAULT scope override ──────────────────────────────────────

def test_any_role_on_keyvault_scope_is_keyvault():
    """Any role scoped to a Key Vault resource returns KEY_VAULT."""
    assert classify_role_privilege_tier({
        'role_definition_name': 'Reader',
        'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/my-vault',
    }) == 'KEY_VAULT'


def test_kv_secrets_user_on_keyvault_scope_is_keyvault():
    """KEY_VAULT scope wins over MEDIUM role name."""
    assert classify_role_privilege_tier({
        'role_definition_name': 'Key Vault Secrets User',
        'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/prod-kv',
    }) == 'KEY_VAULT'


def test_owner_on_keyvault_scope_is_keyvault():
    """KEY_VAULT scope wins over HIGH role name."""
    assert classify_role_privilege_tier({
        'role_definition_name': 'Owner',
        'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1',
    }) == 'KEY_VAULT'


# ── Suffix matching for custom roles ──────────────────────────────

def test_custom_administrator_suffix_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Custom Network Administrator', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_custom_contributor_suffix_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Custom Data Contributor', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_custom_datawriter_suffix_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Custom DataWriter', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_custom_officer_suffix_is_high():
    assert classify_role_privilege_tier({'role_definition_name': 'Custom Compliance Officer', 'scope': '/subscriptions/abc'}) == 'HIGH'


def test_custom_viewer_suffix_is_medium():
    assert classify_role_privilege_tier({'role_definition_name': 'Custom Viewer', 'scope': '/subscriptions/abc'}) == 'MEDIUM'


def test_custom_datareader_suffix_is_medium():
    assert classify_role_privilege_tier({'role_definition_name': 'Custom DataReader', 'scope': '/subscriptions/abc'}) == 'MEDIUM'


def test_custom_user_suffix_is_medium():
    assert classify_role_privilege_tier({'role_definition_name': 'Blob Storage User', 'scope': '/subscriptions/abc'}) == 'MEDIUM'


# ── Unknown / LOW roles ───────────────────────────────────────────

def test_unknown_role_is_low():
    assert classify_role_privilege_tier({'role_definition_name': 'Totally Custom Role', 'scope': '/subscriptions/abc'}) == 'LOW'


def test_empty_role_name_is_low():
    assert classify_role_privilege_tier({'scope': '/subscriptions/abc'}) == 'LOW'


def test_empty_dict_is_low():
    assert classify_role_privilege_tier({}) == 'LOW'


def test_none_values_is_low():
    assert classify_role_privilege_tier({'role_definition_name': None, 'scope': None}) == 'LOW'
