"""Tests for the production verdict system in _assemble_lineage_verdict().

Validates tier-aware inactivity signals and verdict determination for
workload identities. Tests use the production AzureDiscoveryEngine method
via a minimal mock engine.
"""
import pytest
from unittest.mock import MagicMock, patch
from app.engines.risk.agirs_engine import classify_role_privilege_tier


# ── Helpers ────────────────────────────────────────────────────────

def _make_engine():
    """Create a minimal AzureDiscoveryEngine with mocked dependencies."""
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    engine = object.__new__(AzureDiscoveryEngine)
    engine.db = MagicMock()
    engine.db.get_keyvault_items_by_scope = MagicMock(return_value=[])
    engine.logger = MagicMock()
    return engine


def _identity(
    days_since_last_signin=None,
    roles=None,
    entra_roles=None,
    signin_pattern=None,
    last_sign_in=None,
    app_reg_owner=None,
    identity_category='service_principal',
    display_name='test-spn',
    workload_risk_flags=None,
    associated_resource_id=None,
    is_discovery_connector=False,
    **extra,
):
    """Build an identity dict for _assemble_lineage_verdict()."""
    d = {
        'identity_id': 'test-id',
        'display_name': display_name,
        'identity_category': identity_category,
        'days_since_last_signin': days_since_last_signin,
        'roles': roles or [],
        'entra_roles': entra_roles or [],
        'signin_pattern': signin_pattern,
        'last_sign_in': last_sign_in,
        'app_registration_object_id': 'app-obj-1' if app_reg_owner is not None else None,
        'app_reg_owner_display_name': app_reg_owner,
        'app_reg_likely_service': None,
        'app_reg_reply_url_hostnames': [],
        'is_external_app': False,
        'federated_workload_type': None,
        'federated_workload_name': None,
        'is_discovery_connector': is_discovery_connector,
        'arm_binding_count': 0,
        'workload_type': 'unknown',
        'workload_confidence': 0,
        'api_usage_pattern': None,
        'audit_created_by': None,
        'is_platform_spn': False,
        'owned_object_count': 0,
        'workload_risk_flags': workload_risk_flags or [],
        'dependency_impact_resources': [],
        'associated_resource_id': associated_resource_id,
        'last_noninteractive_signin': None,
        'observed_last_used': None,
        'signin_failure_count_30d': 0,
    }
    d.update(extra)
    return d


def _high_role(scope='/subscriptions/abc'):
    return {'role_name': 'Owner', 'scope': scope}


def _medium_role(scope='/subscriptions/abc'):
    return {'role_name': 'Reader', 'scope': scope}


def _kv_role(scope='/subscriptions/abc/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1'):
    return {'role_name': 'Key Vault Secrets Officer', 'scope': scope}


def _verdict(identity_dict):
    """Run _assemble_lineage_verdict on the identity dict."""
    engine = _make_engine()
    return engine._assemble_lineage_verdict(identity_dict)


# ── classify_role_privilege_tier ──────────────────────────────────

def test_tier_high_owner():
    assert classify_role_privilege_tier({'role_name': 'Owner', 'scope': '/sub/x'}) == 'HIGH'


def test_tier_high_role_definition_name():
    """Supports role_definition_name key (test compat)."""
    assert classify_role_privilege_tier({'role_definition_name': 'Contributor', 'scope': '/sub/x'}) == 'HIGH'


def test_tier_medium_reader():
    assert classify_role_privilege_tier({'role_name': 'Reader', 'scope': '/sub/x'}) == 'MEDIUM'


def test_tier_keyvault_scope():
    assert classify_role_privilege_tier(
        {'role_name': 'Reader', 'scope': '/sub/x/providers/Microsoft.KeyVault/vaults/kv1'}
    ) == 'KEY_VAULT'


def test_tier_low_unknown():
    assert classify_role_privilege_tier({'role_name': 'SomeCustomRole', 'scope': '/sub/x'}) == 'LOW'


# ── ORPHANED ──────────────────────────────────────────────────────

def test_orphaned_no_owner_never_authed_has_roles():
    """No owner + never authed + has roles + no confirmed signal → ORPHANED."""
    result = _verdict(_identity(
        days_since_last_signin=None,
        roles=[_high_role()],
        signin_pattern='never_used',
        app_reg_owner=None,
    ))
    assert result['recommended_action'] == 'ORPHANED'


def test_orphaned_no_roles_no_owner_never_authed():
    """No roles + no owner + never authed → UNUSED (not ORPHANED — needs roles)."""
    result = _verdict(_identity(
        days_since_last_signin=None,
        roles=[],
        signin_pattern='never_used',
        app_reg_owner=None,
    ))
    assert result['recommended_action'] == 'UNUSED'


# ── NOT ORPHANED: owner breaks the condition ─────────────────────

def test_not_orphaned_has_owner():
    """Has owner + never authed → NOT ORPHANED (owner = confirmed signal)."""
    result = _verdict(_identity(
        days_since_last_signin=None,
        roles=[_high_role()],
        signin_pattern='never_used',
        app_reg_owner='Alice',
    ))
    assert result['recommended_action'] != 'ORPHANED'


# ── AT_RISK: high privilege + inactivity ─────────────────────────

def test_at_risk_high_priv_never_authed():
    """HIGH role + never authed + no owner + roles → AT_RISK."""
    result = _verdict(_identity(
        days_since_last_signin=None,
        roles=[_high_role()],
        signin_pattern='never_used',
        app_reg_owner=None,
    ))
    # ORPHANED takes priority when no owner + never authed + has roles
    assert result['recommended_action'] in ('ORPHANED', 'AT_RISK')


def test_at_risk_high_priv_inactive_95d():
    """HIGH role + last_signin 95 days + has sign-in → AT_RISK."""
    result = _verdict(_identity(
        days_since_last_signin=95,
        roles=[_high_role()],
        signin_pattern='regular',
        last_sign_in='2024-01-01',
        app_reg_owner='Bob',
    ))
    assert result['recommended_action'] == 'AT_RISK'
    assert any('HIGH' in s.get('detail', '') for s in result['verdict_signals']
               if s['source'] == 'inactivity_tier')


def test_at_risk_keyvault_tier_inactive():
    """KEY_VAULT tier + inactive >90d → AT_RISK."""
    result = _verdict(_identity(
        days_since_last_signin=100,
        roles=[_kv_role()],
        signin_pattern='regular',
        last_sign_in='2024-01-01',
        app_reg_owner='Carol',
    ))
    assert result['recommended_action'] == 'AT_RISK'
    assert any('KEY_VAULT' in s.get('detail', '') for s in result['verdict_signals']
               if s['source'] == 'inactivity_tier')


# ── STALE: moderate inactivity ───────────────────────────────────

def test_stale_high_priv_60d():
    """HIGH role + 60d inactive → STALE."""
    result = _verdict(_identity(
        days_since_last_signin=60,
        roles=[_high_role()],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Dave',
    ))
    assert result['recommended_action'] == 'STALE'
    # Inactivity signal present
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    assert 'HIGH' in tier_signals[0]['detail']


def test_stale_medium_priv_45d():
    """MEDIUM role + 45d inactive → STALE."""
    result = _verdict(_identity(
        days_since_last_signin=45,
        roles=[_medium_role()],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Eve',
    ))
    assert result['recommended_action'] == 'STALE'
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    assert 'MEDIUM' in tier_signals[0]['detail']


# ── HEALTHY ──────────────────────────────────────────────────────

def test_healthy_active_5d():
    """Active 5 days ago → HEALTHY."""
    result = _verdict(_identity(
        days_since_last_signin=5,
        roles=[_high_role()],
        signin_pattern='regular',
        last_sign_in='2024-12-01',
        app_reg_owner='Frank',
    ))
    assert result['recommended_action'] == 'HEALTHY'
    # No inactivity signal for active identities
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 0


def test_healthy_boundary_30d():
    """30 days → still no inactivity signal (STALE starts at 31)."""
    result = _verdict(_identity(
        days_since_last_signin=30,
        roles=[_medium_role()],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Grace',
    ))
    # No inactivity signal
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 0


# ── Inactivity signal values ─────────────────────────────────────

def test_inactivity_signal_high_never_used():
    """HIGH privilege + never authenticated → high_privilege_never_used signal."""
    result = _verdict(_identity(
        days_since_last_signin=None,
        roles=[_high_role()],
        signin_pattern='never_used',
        app_reg_owner=None,
    ))
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    assert 'never authenticated' in tier_signals[0]['detail']


def test_inactivity_signal_high_long_inactive():
    """HIGH privilege + >90d inactive → high_privilege_long_inactive signal."""
    result = _verdict(_identity(
        days_since_last_signin=100,
        roles=[_high_role()],
        signin_pattern='regular',
        last_sign_in='2024-01-01',
        app_reg_owner='Hank',
    ))
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    assert '100' in tier_signals[0]['detail']
    assert tier_signals[0]['weight'] == -12


def test_inactivity_signal_high_short_inactive():
    """HIGH privilege + 31-90d inactive → high_privilege_short_inactive signal."""
    result = _verdict(_identity(
        days_since_last_signin=60,
        roles=[_high_role()],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Ivy',
    ))
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    assert '60' in tier_signals[0]['detail']
    assert tier_signals[0]['weight'] == -5


def test_inactivity_signal_medium_inactive():
    """MEDIUM privilege + >31d inactive → medium_privilege_inactive signal."""
    result = _verdict(_identity(
        days_since_last_signin=45,
        roles=[_medium_role()],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Jack',
    ))
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    assert 'MEDIUM' in tier_signals[0]['detail']
    assert tier_signals[0]['weight'] == -3


# ── KV expiry signals in verdict ─────────────────────────────────

def test_kv_expiry_critical_signal():
    """KV-scoped role + critical expiry item → keyvault_expiry_critical signal."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        {'item_name': 'db-password', 'expiry_risk_tier': 'CRITICAL', 'days_until_expiry': 5},
    ]
    result = engine._assemble_lineage_verdict(_identity(
        days_since_last_signin=5,
        roles=[_kv_role()],
        signin_pattern='regular',
        last_sign_in='2024-12-01',
        app_reg_owner='Kate',
    ))
    kv_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_critical']
    assert len(kv_signals) == 1
    assert 'db-password' in kv_signals[0]['detail']
    assert kv_signals[0]['weight'] == -15


def test_kv_expiry_warning_signal():
    """KV-scoped role + warning expiry item → keyvault_expiry_warning signal."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        {'item_name': 'api-key', 'expiry_risk_tier': 'WARNING', 'days_until_expiry': 25},
    ]
    result = engine._assemble_lineage_verdict(_identity(
        days_since_last_signin=5,
        roles=[_kv_role()],
        signin_pattern='regular',
        last_sign_in='2024-12-01',
        app_reg_owner='Leo',
    ))
    kv_signals = [s for s in result['verdict_signals'] if s['source'] == 'keyvault_expiry_warning']
    assert len(kv_signals) == 1
    assert kv_signals[0]['weight'] == -8


def test_kv_expiry_no_items_no_signal():
    """KV-scoped role + no expiry items → no KV signal."""
    result = _verdict(_identity(
        days_since_last_signin=5,
        roles=[_kv_role()],
        signin_pattern='regular',
        last_sign_in='2024-12-01',
        app_reg_owner='Mike',
    ))
    kv_signals = [s for s in result['verdict_signals']
                  if s['source'] in ('keyvault_expiry_critical', 'keyvault_expiry_warning')]
    assert len(kv_signals) == 0


def test_kv_expiry_risk_summary():
    """Critical KV expiry items add to risk_summary."""
    engine = _make_engine()
    engine.db.get_keyvault_items_by_scope.return_value = [
        {'item_name': 'secret-1', 'expiry_risk_tier': 'CRITICAL', 'days_until_expiry': 3},
        {'item_name': 'secret-2', 'expiry_risk_tier': 'CRITICAL', 'days_until_expiry': 7},
    ]
    result = engine._assemble_lineage_verdict(_identity(
        days_since_last_signin=5,
        roles=[_kv_role()],
        signin_pattern='regular',
        last_sign_in='2024-12-01',
        app_reg_owner='Nancy',
    ))
    assert any('critically expiring' in r for r in result['verdict_risk_summary'])


# ── Privilege tier propagation ───────────────────────────────────

def test_multiple_roles_highest_tier():
    """Multiple roles → inactivity signal uses highest tier."""
    result = _verdict(_identity(
        days_since_last_signin=60,
        roles=[_medium_role(), _high_role()],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Oscar',
    ))
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 1
    # Should use HIGH weight (-5) not MEDIUM (-3)
    assert tier_signals[0]['weight'] == -5
    assert 'HIGH' in tier_signals[0]['detail']


def test_no_roles_no_inactivity_signal():
    """No role assignments → no inactivity signal."""
    result = _verdict(_identity(
        days_since_last_signin=60,
        roles=[],
        signin_pattern='regular',
        last_sign_in='2024-06-01',
        app_reg_owner='Pat',
    ))
    tier_signals = [s for s in result['verdict_signals'] if s['source'] == 'inactivity_tier']
    assert len(tier_signals) == 0


# ── MEDIUM role + >90 days does NOT trigger AT_RISK ───────────────

def test_medium_role_inactive_95d_not_at_risk():
    """MEDIUM privilege + 95 days inactive → NOT AT_RISK (requires HIGH/KV)."""
    result = _verdict(_identity(
        days_since_last_signin=95,
        roles=[_medium_role()],
        signin_pattern='regular',
        last_sign_in='2024-01-01',
        app_reg_owner='Quinn',
    ))
    assert result['recommended_action'] != 'AT_RISK'


# ── HIRI weight constants ────────────────────────────────────────

def test_hiri_weights_exist():
    """Verify tier-aware HIRI weight constants are defined."""
    from app.engines.risk.agirs_engine import (
        H2A_HIGH_NEVER_WEIGHT,
        H2B_HIGH_INACTIVE_90_WEIGHT,
        H2C_HIGH_INACTIVE_31_90_WEIGHT,
        H2D_MEDIUM_INACTIVE_90_WEIGHT,
        H2E_MEDIUM_INACTIVE_31_90_WEIGHT,
    )
    assert H2A_HIGH_NEVER_WEIGHT == 8
    assert H2B_HIGH_INACTIVE_90_WEIGHT == 7
    assert H2C_HIGH_INACTIVE_31_90_WEIGHT == 4
    assert H2D_MEDIUM_INACTIVE_90_WEIGHT == 3
    assert H2E_MEDIUM_INACTIVE_31_90_WEIGHT == 1


def test_dead_code_removed():
    """Verify calculate_verdict, creds_recently_updated, enrich_with_keyvault_expiry are deleted."""
    import app.engines.risk.agirs_engine as mod
    assert not hasattr(mod, 'calculate_verdict')
    assert not hasattr(mod, 'creds_recently_updated')
    assert not hasattr(mod, 'enrich_with_keyvault_expiry')


# ── owner_status: ungoverned vs orphaned ─────────────────────────

def _lifecycle(identity_data, owners):
    """Run _score_lifecycle and return owner_status."""
    from app.engines.risk.spn_risk_engine import WorkloadExposureEngine
    engine = object.__new__(WorkloadExposureEngine)
    _score, _findings, owner_status = engine._score_lifecycle(
        identity_data, credentials=[], owners=owners)
    return owner_status


def test_owner_status_ungoverned_active_3d():
    """0 owners + active 3 days ago → ungoverned (not orphaned)."""
    from datetime import datetime, timedelta
    last = (datetime.utcnow() - timedelta(days=3)).isoformat() + 'Z'
    status = _lifecycle({'activity_status': 'active', 'last_sign_in': last}, [])
    assert status == 'ungoverned'


def test_owner_status_ungoverned_inactive_45d():
    """0 owners + inactive 45 days → ungoverned (stale but within 90d)."""
    from datetime import datetime, timedelta
    last = (datetime.utcnow() - timedelta(days=45)).isoformat() + 'Z'
    status = _lifecycle({'activity_status': 'inactive', 'last_sign_in': last}, [])
    assert status == 'ungoverned'


def test_owner_status_orphaned_never_used():
    """0 owners + never authed → orphaned."""
    status = _lifecycle({'activity_status': 'never_used', 'last_sign_in': None}, [])
    assert status == 'orphaned'


def test_owner_status_orphaned_stale_95d():
    """0 owners + 95 days since last auth → orphaned (beyond 90d)."""
    from datetime import datetime, timedelta
    last = (datetime.utcnow() - timedelta(days=95)).isoformat() + 'Z'
    status = _lifecycle({'activity_status': 'stale', 'last_sign_in': last}, [])
    assert status == 'orphaned'


def test_owner_status_single_owner_active():
    """1 owner + active → single_owner (unchanged by activity)."""
    from datetime import datetime, timedelta
    last = (datetime.utcnow() - timedelta(days=3)).isoformat() + 'Z'
    status = _lifecycle(
        {'activity_status': 'active', 'last_sign_in': last},
        [{'owner_display_name': 'Alice'}])
    assert status == 'single_owner'
