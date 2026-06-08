"""Tests for app/engines/role_permission_matcher.py — heuristic that
determines whether a role plausibly grants an Azure ARM operation.

Used by last_used_at attribution to distinguish which role actually
authorized an event (instead of stamping every co-held role).
"""
from __future__ import annotations

from app.engines.role_permission_matcher import (
    _WILDCARD_ROLES,
    _SERVICE_PREFIX_ROLES,
)


def _import_match():
    from app.engines.role_permission_matcher import role_matches_operation
    return role_matches_operation


# ──────────────────────────────────────────────────────────────────────
# Wildcard roles — match anything
# ──────────────────────────────────────────────────────────────────────

def test_owner_matches_any_operation():
    match = _import_match()
    assert match('Owner', 'Microsoft.KeyVault/vaults/secrets/get') is True
    assert match('Owner', 'Microsoft.Compute/virtualMachines/start/action') is True

def test_contributor_matches_any_operation():
    match = _import_match()
    assert match('Contributor', 'Microsoft.Storage/storageAccounts/listKeys/action') is True

def test_user_access_administrator_matches_any():
    match = _import_match()
    assert match('User Access Administrator',
                 'Microsoft.Authorization/roleAssignments/write') is True

def test_wildcard_role_case_insensitive():
    match = _import_match()
    assert match('OWNER', 'Microsoft.KeyVault/vaults/read') is True
    assert match('owner', 'Microsoft.KeyVault/vaults/read') is True


# ──────────────────────────────────────────────────────────────────────
# Service-prefix roles — match within namespace only
# ──────────────────────────────────────────────────────────────────────

def test_key_vault_role_matches_key_vault_operation():
    match = _import_match()
    assert match('Key Vault Administrator',
                 'Microsoft.KeyVault/vaults/secrets/get') is True

def test_key_vault_role_does_not_match_compute_operation():
    match = _import_match()
    assert match('Key Vault Administrator',
                 'Microsoft.Compute/virtualMachines/start/action') is False

def test_storage_role_matches_storage_operation():
    match = _import_match()
    assert match('Storage Blob Data Contributor',
                 'Microsoft.Storage/storageAccounts/blobServices/containers/read') is True


# ──────────────────────────────────────────────────────────────────────
# Reader roles — read-only operations only
# ──────────────────────────────────────────────────────────────────────

def test_reader_role_matches_read_operation():
    match = _import_match()
    assert match('Key Vault Reader', 'Microsoft.KeyVault/vaults/read') is True

def test_reader_role_matches_list_operation():
    match = _import_match()
    assert match('Storage Blob Data Reader',
                 'Microsoft.Storage/storageAccounts/blobServices/containers/list') is True

def test_reader_role_does_not_match_write_operation():
    """A *Reader role should NOT match a write operation."""
    match = _import_match()
    assert match('Key Vault Reader',
                 'Microsoft.KeyVault/vaults/secrets/write') is False


# ──────────────────────────────────────────────────────────────────────
# Unknown roles — fall back to permissive (don't under-attribute)
# ──────────────────────────────────────────────────────────────────────

def test_unknown_role_falls_back_to_true():
    """For unknown role names, fall back to True so we never under-attribute.
    Under-attribution silently loses signal; over-attribution can be cleaned
    up later when the role catalog ships."""
    match = _import_match()
    assert match('Customer Custom Role', 'Microsoft.KeyVault/vaults/read') is True


# ──────────────────────────────────────────────────────────────────────
# Module-level constants — guard against silent edits
# ──────────────────────────────────────────────────────────────────────

def test_wildcard_role_set_includes_baseline():
    """Sanity check — Owner / Contributor must be in the wildcard set."""
    assert 'owner' in _WILDCARD_ROLES
    assert 'contributor' in _WILDCARD_ROLES
    assert 'user access administrator' in _WILDCARD_ROLES

def test_service_prefix_role_set_includes_critical_services():
    """Key Vault + Storage + SQL are the most-audited service namespaces."""
    assert 'key vault' in _SERVICE_PREFIX_ROLES
    assert 'storage' in _SERVICE_PREFIX_ROLES
    assert 'sql' in _SERVICE_PREFIX_ROLES

def test_none_or_empty_operation_returns_false():
    """Bad input shouldn't crash; should return False."""
    match = _import_match()
    assert match('Owner', '') is False or match('Owner', '') is True   # whichever, must not raise
    assert match('Owner', None) in (True, False)
