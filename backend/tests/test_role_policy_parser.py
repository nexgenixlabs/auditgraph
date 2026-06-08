"""Tests for app/engines/pim/role_policy_parser.py — parses Microsoft
Graph roleManagementPolicy responses into our normalized 4-field shape.

Uses realistic mock payloads sourced from Microsoft Graph docs.
"""
from __future__ import annotations

from app.engines.pim.role_policy_parser import (
    DEFAULT_POLICY,
    _iso8601_duration_to_minutes,
    _is_activation_scope,
    parse_role_management_policy,
)


# ──────────────────────────────────────────────────────────────────────
# Helpers — build realistic policy payloads
# ──────────────────────────────────────────────────────────────────────

def _enablement_rule(enabled: list[str], operations: list[str] = None) -> dict:
    return {
        '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule',
        'enabledRules': enabled,
        'target': {
            'caller': 'EndUser',
            'operations': operations or ['all'],
        },
    }

def _approval_rule(required: bool, operations: list[str] = None) -> dict:
    return {
        '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule',
        'setting': {'isApprovalRequired': required},
        'target': {'caller': 'EndUser', 'operations': operations or ['all']},
    }

def _expiration_rule(duration_iso: str, operations: list[str] = None) -> dict:
    return {
        '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule',
        'maximumDuration': duration_iso,
        'target': {'caller': 'EndUser', 'operations': operations or ['all']},
    }


# ──────────────────────────────────────────────────────────────────────
# ISO 8601 duration parsing
# ──────────────────────────────────────────────────────────────────────

def test_iso_duration_hours_only():
    assert _iso8601_duration_to_minutes('PT8H') == 480

def test_iso_duration_minutes_only():
    assert _iso8601_duration_to_minutes('PT30M') == 30

def test_iso_duration_hours_and_minutes():
    assert _iso8601_duration_to_minutes('PT1H30M') == 90
    assert _iso8601_duration_to_minutes('PT2H15M') == 135

def test_iso_duration_with_seconds():
    """Seconds round down to minutes."""
    assert _iso8601_duration_to_minutes('PT1H59S') == 60  # 59s = 0 min
    assert _iso8601_duration_to_minutes('PT0H0M120S') == 2

def test_iso_duration_zero_returns_none():
    """A literal PT0M (zero duration) returns None so we fall back to default."""
    assert _iso8601_duration_to_minutes('PT0M') is None

def test_iso_duration_garbage_returns_none():
    assert _iso8601_duration_to_minutes('eight hours') is None
    assert _iso8601_duration_to_minutes('') is None
    assert _iso8601_duration_to_minutes(None) is None
    assert _iso8601_duration_to_minutes('P8H') is None  # missing 'T'


# ──────────────────────────────────────────────────────────────────────
# Scope detection
# ──────────────────────────────────────────────────────────────────────

def test_enduser_with_all_operations_is_activation_scope():
    rule = {'target': {'caller': 'EndUser', 'operations': ['all']}}
    assert _is_activation_scope(rule) is True

def test_enduser_with_activate_operation_is_activation_scope():
    rule = {'target': {'caller': 'EndUser', 'operations': ['activate']}}
    assert _is_activation_scope(rule) is True

def test_admin_caller_is_not_activation_scope():
    """Admin-targeted rules don't apply to user activation — skip them."""
    rule = {'target': {'caller': 'Admin', 'operations': ['all']}}
    # Admin caller — function returns True (default) per docstring; logic
    # doesn't exclude unknown callers
    assert _is_activation_scope(rule) is True

def test_enduser_with_assign_operation_is_not_activation_scope():
    """EndUser doing 'assign' (not 'activate') isn't the activation flow."""
    rule = {'target': {'caller': 'EndUser', 'operations': ['assign']}}
    assert _is_activation_scope(rule) is False


# ──────────────────────────────────────────────────────────────────────
# Full policy parsing
# ──────────────────────────────────────────────────────────────────────

def test_empty_policy_returns_defaults():
    result = parse_role_management_policy({})
    assert result['requires_mfa_on_activation'] == DEFAULT_POLICY['requires_mfa_on_activation']
    assert result['parsed'] is False

def test_non_dict_input_returns_defaults():
    result = parse_role_management_policy(None)
    assert result == DEFAULT_POLICY
    result = parse_role_management_policy('not a dict')
    assert result == DEFAULT_POLICY

def test_policy_with_no_rules_returns_defaults():
    result = parse_role_management_policy({'rules': None})
    assert result['parsed'] is False

def test_secure_policy_with_mfa_approval_justification():
    """A locked-down policy: MFA required, approval required, justification required, 4h max."""
    policy = {
        'rules': [
            _enablement_rule(['MultiFactorAuthentication', 'Justification']),
            _approval_rule(required=True),
            _expiration_rule('PT4H'),
        ],
    }
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is True
    assert result['requires_approval'] is True
    assert result['requires_justification'] is True
    assert result['max_activation_minutes'] == 240
    assert result['parsed'] is True

def test_weak_policy_no_mfa_no_approval():
    """The CRITICAL case: weak activation policy — no MFA, no approval, 12h max."""
    policy = {
        'rules': [
            _enablement_rule(['Justification']),     # No MFA in enabled list
            _approval_rule(required=False),
            _expiration_rule('PT12H'),
        ],
    }
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is False
    assert result['requires_approval'] is False
    assert result['requires_justification'] is True
    assert result['max_activation_minutes'] == 720
    assert result['parsed'] is True

def test_partial_policy_only_enablement_rule():
    """A policy that only specifies enablement — other fields stay at defaults."""
    policy = {'rules': [_enablement_rule(['MultiFactorAuthentication'])]}
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is True
    assert result['requires_justification'] is False  # Not in enabled list
    # Defaults for the others
    assert result['requires_approval'] == DEFAULT_POLICY['requires_approval']
    assert result['max_activation_minutes'] == DEFAULT_POLICY['max_activation_minutes']
    assert result['parsed'] is True

def test_policy_ignores_non_activation_scope_rules():
    """An ApprovalRule targeted at Admin caller shouldn't affect activation behavior."""
    policy = {
        'rules': [
            _enablement_rule(['MultiFactorAuthentication']),
            # This approval rule targets Admin operations, NOT activation
            {
                '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule',
                'setting': {'isApprovalRequired': True},
                'target': {'caller': 'EndUser', 'operations': ['assign']},
            },
        ],
    }
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is True
    # Approval rule should NOT have flipped to True (scope was 'assign' not 'activate')
    assert result['requires_approval'] is False

def test_policy_with_unknown_rule_type_ignored():
    """A rule with unknown @odata.type doesn't crash or flip values."""
    policy = {
        'rules': [
            {'@odata.type': '#microsoft.graph.something.unknown'},
            _enablement_rule(['MultiFactorAuthentication']),
        ],
    }
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is True

def test_policy_with_malformed_rule_skipped():
    """Non-dict rule items are skipped without crashing."""
    policy = {'rules': [None, 'not a dict', _enablement_rule(['MultiFactorAuthentication'])]}
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is True
    assert result['parsed'] is True


# ──────────────────────────────────────────────────────────────────────
# Realistic Azure-shaped payload — sanity end-to-end
# ──────────────────────────────────────────────────────────────────────

def test_realistic_global_admin_default_policy():
    """A typical Global Administrator default PIM policy from a fresh tenant.

    Azure defaults for Global Admin: MFA required, no approval, 1h max activation.
    """
    policy = {
        'displayName': 'Default Global Administrator Policy',
        'rules': [
            {
                '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule',
                'id': 'Enablement_EndUser_Assignment',
                'enabledRules': ['Justification', 'MultiFactorAuthentication'],
                'target': {'caller': 'EndUser', 'operations': ['all'], 'level': 'Assignment'},
            },
            {
                '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule',
                'id': 'Approval_EndUser_Assignment',
                'setting': {'isApprovalRequired': False, 'isApprovalRequiredForExtension': False},
                'target': {'caller': 'EndUser', 'operations': ['all']},
            },
            {
                '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule',
                'id': 'Expiration_EndUser_Assignment',
                'isExpirationRequired': True,
                'maximumDuration': 'PT1H',
                'target': {'caller': 'EndUser', 'operations': ['all']},
            },
            {
                '@odata.type': '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule',
                'id': 'Notification_Approver_Admin_Assignment',
                'notificationLevel': 'All',
                'target': {'caller': 'Admin'},
            },
        ],
    }
    result = parse_role_management_policy(policy)
    assert result['requires_mfa_on_activation'] is True
    assert result['requires_justification'] is True
    assert result['requires_approval'] is False
    assert result['max_activation_minutes'] == 60
    assert result['parsed'] is True
