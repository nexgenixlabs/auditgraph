"""Tests for Key Vault metadata: scope detection, expiry tiers, and production KV signals.

Covers:
  - Vault scope extraction from ARM resource IDs (classify_role_privilege_tier)
  - Expiry risk tier classification (CRITICAL/WARNING/INFO/HEALTHY/NONE)
  - Production KV expiry signals via _assemble_lineage_verdict()
"""
from unittest.mock import MagicMock
from app.engines.risk.agirs_engine import classify_role_privilege_tier


# ── Helpers ────────────────────────────────────────────────────────

def _compute_expiry_tier(days_until_expiry):
    """Replicate the tier logic from azure_discovery._enrich_keyvault_metadata."""
    if days_until_expiry is None:
        return 'NONE'
    if days_until_expiry <= 14:
        return 'CRITICAL'
    elif days_until_expiry <= 30:
        return 'WARNING'
    elif days_until_expiry <= 90:
        return 'INFO'
    else:
        return 'HEALTHY'


def _kv_item(name, days_until_expiry=None):
    """Create a keyvault_metadata-like dict."""
    return {
        'item_name': name,
        'item_type': 'secret',
        'vault_name': 'test-vault',
        'days_until_expiry': days_until_expiry,
        'expiry_risk_tier': _compute_expiry_tier(days_until_expiry),
    }


def _make_engine():
    """Create a minimal AzureDiscoveryEngine with mocked dependencies."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    engine = object.__new__(AzureDiscoveryEngine)
    engine.db = MagicMock()
    engine.db.get_keyvault_items_by_scope = MagicMock(return_value=[])
    engine.logger = MagicMock()
    return engine


def _kv_identity(days_since=5, app_reg_owner='Alice'):
    """Build a KV-scoped identity dict for _assemble_lineage_verdict()."""
    return {
        'identity_id': 'test-kv-id',
        'display_name': 'kv-spn',
        'identity_category': 'service_principal',
        'days_since_last_signin': days_since,
        'roles': [{
            'role_name': 'Key Vault Secrets Officer',
            'scope': '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/prod',
        }],
        'entra_roles': [],
        'signin_pattern': 'regular',
        'last_sign_in': '2024-12-01',
        'app_registration_object_id': 'app-obj-1',
        'app_reg_owner_display_name': app_reg_owner,
        'app_reg_likely_service': None,
        'app_reg_reply_url_hostnames': [],
        'is_external_app': False,
        'federated_workload_type': None,
        'federated_workload_name': None,
        'is_discovery_connector': False,
        'arm_binding_count': 0,
        'workload_type': 'unknown',
        'workload_confidence': 0,
        'api_usage_pattern': None,
        'audit_created_by': None,
        'is_platform_spn': False,
        'owned_object_count': 0,
        'workload_risk_flags': [],
        'dependency_impact_resources': [],
        'associated_resource_id': None,
        'last_noninteractive_signin': None,
        'observed_last_used': None,
        'signin_failure_count_30d': 0,
    }


# ── Vault scope extraction ────────────────────────────────────────

def test_keyvault_scope_detected_by_tier_classifier():
    """classify_role_privilege_tier returns KEY_VAULT for vault scopes."""
    ra = {
        'role_definition_name': 'Reader',
        'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/my-vault',
    }
    assert classify_role_privilege_tier(ra) == 'KEY_VAULT'


def test_vault_scope_extraction_from_nested_scope():
    """Scope deeper than vault level still detects KeyVault."""
    ra = {
        'role_definition_name': 'Contributor',
        'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1/keys/mykey',
    }
    assert classify_role_privilege_tier(ra) == 'KEY_VAULT'


def test_non_vault_scope_not_detected():
    """Non-KV scope does not return KEY_VAULT."""
    ra = {
        'role_definition_name': 'Reader',
        'scope': '/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1',
    }
    assert classify_role_privilege_tier(ra) != 'KEY_VAULT'


# ── Expiry risk tier classification ───────────────────────────────

def test_expiry_10_days_critical():
    assert _compute_expiry_tier(10) == 'CRITICAL'


def test_expiry_14_days_critical():
    assert _compute_expiry_tier(14) == 'CRITICAL'


def test_expiry_25_days_warning():
    assert _compute_expiry_tier(25) == 'WARNING'


def test_expiry_30_days_warning():
    assert _compute_expiry_tier(30) == 'WARNING'


def test_expiry_60_days_info():
    assert _compute_expiry_tier(60) == 'INFO'


def test_expiry_120_days_healthy():
    assert _compute_expiry_tier(120) == 'HEALTHY'


def test_no_expiry_none():
    assert _compute_expiry_tier(None) == 'NONE'


def test_negative_days_critical():
    assert _compute_expiry_tier(-5) == 'CRITICAL'


def test_zero_days_critical():
    assert _compute_expiry_tier(0) == 'CRITICAL'


# ── Production KV expiry signals via _assemble_lineage_verdict() ──

def test_critical_vault_item_adds_signal():
    """CRITICAL vault item produces keyvault_expiry_critical signal with -15 weight."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('db-password', days_until_expiry=5),
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_critical']
    assert len(kv_signals) == 1
    assert 'db-password' in kv_signals[0]['detail']
    assert kv_signals[0]['weight'] == -15


def test_warning_vault_item_adds_signal():
    """WARNING vault item produces keyvault_expiry_warning signal with -8 weight."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('api-key', days_until_expiry=25),
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_warning']
    assert len(kv_signals) == 1
    assert kv_signals[0]['weight'] == -8


def test_both_critical_and_warning_items():
    """Multiple tiers produce separate signals."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('secret-a', days_until_expiry=3),   # CRITICAL
        _kv_item('secret-b', days_until_expiry=20),  # WARNING
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    critical_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_critical']
    warning_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_warning']
    assert len(critical_signals) == 1
    assert len(warning_signals) == 1
    assert 'secret-a' in critical_signals[0]['detail']


def test_no_kv_items_no_signal():
    """Empty KV items → no expiry signals."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = []
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_signals = [s for s in result['verdict_signals']
                  if s['source'] in ('keyvault_expiry_critical', 'keyvault_expiry_warning')]
    assert len(kv_signals) == 0


def test_info_and_healthy_items_ignored():
    """INFO and HEALTHY tier items produce no signals (DB query filters them out)."""
    engine = _make_engine()
    # get_keyvault_items_by_scope already filters to CRITICAL/WARNING only
    engine.db.get_keyvault_items_by_scope.return_value = []
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_signals = [s for s in result['verdict_signals']
                  if s['source'] in ('keyvault_expiry_critical', 'keyvault_expiry_warning')]
    assert len(kv_signals) == 0


def test_expired_item_is_critical():
    """Already-expired item (negative days) treated as CRITICAL."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('old-secret', days_until_expiry=-10),
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_critical']
    assert len(kv_signals) == 1
    assert 'old-secret' in kv_signals[0]['detail']


def test_multiple_critical_items_listed():
    """All CRITICAL item names appear in the signal detail."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('password-1', days_until_expiry=2),
        _kv_item('password-2', days_until_expiry=7),
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_critical']
    assert len(kv_signals) == 1
    detail = kv_signals[0]['detail']
    assert 'password-1' in detail
    assert 'password-2' in detail
    assert '2 vault item(s)' in detail


def test_kv_expiry_critical_in_risk_summary():
    """Critical KV expiry items add to verdict_risk_summary."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('prod-db-pass', days_until_expiry=3),
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    assert any('critically expiring' in r for r in result['verdict_risk_summary'])


def test_kv_expiry_lineage_signal():
    """Critical KV items produce ALERT lineage signal."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        _kv_item('db-pass', days_until_expiry=5),
    ]
    result = engine._assemble_lineage_verdict(_kv_identity())
    kv_lineage = [s for s in result['lineage_signals'] if s['label'] == 'KV Expiry']
    assert len(kv_lineage) >= 1
    assert 'db-pass' in kv_lineage[0]['value']
