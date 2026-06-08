"""
PIM activation policy parser (AG-PIM-PHASE2-A, 2026-06-07)

Parses Microsoft Graph /policies/roleManagementPolicies responses into the
fields the pim_eligibility_state table tracks for the PIM Overprivilege
Detection engine.

Graph schema reference:
  https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicy

A roleManagementPolicy has a list of rules, each of which has a specific
@odata.type identifying what it controls:

  RoleManagementPolicyEnablementRule       — what must be enabled at activation
                                              (MultiFactorAuthentication / Justification / Ticketing)
  RoleManagementPolicyApprovalRule         — approval requirement + approver list
  RoleManagementPolicyExpirationRule       — max activation duration (PT8H, etc.)
  RoleManagementPolicyNotificationRule     — who gets notified (not relevant for our scoring)
  RoleManagementPolicyAuthenticationContextRule  — Conditional Access scope check

We extract only the 4 fields our engine cares about:
  - requires_mfa_on_activation  (boolean)
  - requires_approval           (boolean)
  - requires_justification      (boolean)
  - max_activation_minutes      (int, derived from ISO 8601 duration)

Moat compliance (per spec_checklist_agentless_readonly):
  ✓ Pure parser — no I/O, no API calls. Safe.
  ✓ Read-only — this code never writes to customer config.
  ✓ Architecture-derived — the policy IS the architecture; we just inspect.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Conservative-safe defaults match what the Phase 1 bridge writes today.
# When a policy doesn't surface a field, we keep the safe default rather
# than fabricate a value.
DEFAULT_POLICY: dict[str, Any] = {
    'requires_mfa_on_activation': True,
    'requires_approval':          False,
    'requires_justification':     True,
    'max_activation_minutes':     480,    # Azure default: 8h
    'parsed':                     False,  # signals "no real policy data parsed"
}


def parse_role_management_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Parse a single roleManagementPolicy + its rules into our normalized shape.

    Args:
        policy: dict from `GET /policies/roleManagementPolicies/{id}?$expand=rules`.
                Must contain a `rules` array. If missing, returns DEFAULT_POLICY.

    Returns:
        Dict with the 4 normalized fields + `parsed: True` indicating real
        values were extracted from the policy. On any structural anomaly
        the function falls back to DEFAULT_POLICY with `parsed: False`.
    """
    if not isinstance(policy, dict):
        return dict(DEFAULT_POLICY)

    rules = policy.get('rules') or []
    if not isinstance(rules, list):
        return dict(DEFAULT_POLICY)

    result = dict(DEFAULT_POLICY)
    matched_any = False   # flip to True only if we matched a known rule type

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        rule_type = rule.get('@odata.type') or rule.get('odata.type') or ''

        # ── Enablement rules (MFA / Justification / Ticketing) ──
        if 'EnablementRule' in rule_type:
            enabled = rule.get('enabledRules') or []
            if isinstance(enabled, list):
                matched_any = True
                if 'MultiFactorAuthentication' in enabled:
                    result['requires_mfa_on_activation'] = True
                else:
                    # Only flip to False if this is an "EndUser_Assignment"
                    # scoped enablement rule (the activation enablement set).
                    if _is_activation_scope(rule):
                        result['requires_mfa_on_activation'] = False

                result['requires_justification'] = 'Justification' in enabled

        # ── Approval rule ──
        elif 'ApprovalRule' in rule_type:
            if _is_activation_scope(rule):
                setting = rule.get('setting') or {}
                if isinstance(setting, dict):
                    matched_any = True
                    result['requires_approval'] = bool(setting.get('isApprovalRequired'))

        # ── Expiration rule ──
        elif 'ExpirationRule' in rule_type:
            if _is_activation_scope(rule):
                max_dur = rule.get('maximumDuration') or rule.get('maxDuration')
                parsed_min = _iso8601_duration_to_minutes(max_dur)
                if parsed_min is not None:
                    matched_any = True
                    result['max_activation_minutes'] = parsed_min

    result['parsed'] = matched_any
    return result


def _is_activation_scope(rule: dict[str, Any]) -> bool:
    """Determine whether a rule applies to the activation flow.

    Microsoft Graph encodes scope via the `target` field. We want rules
    whose target.caller == 'EndUser' AND target.operations contains
    'all' or 'activate' — those are the rules that govern when a user
    activates an eligible assignment.
    """
    target = rule.get('target') or {}
    if not isinstance(target, dict):
        return True   # default to applying — safer than missing a rule

    caller = (target.get('caller') or '').lower()
    operations = target.get('operations') or []
    if not isinstance(operations, list):
        operations = []
    operations_lc = [str(op).lower() for op in operations]

    # Activation flow: EndUser doing 'all' or 'activate'
    if caller == 'enduser':
        if 'all' in operations_lc or 'activate' in operations_lc:
            return True
        # An EndUser target without specific operations also applies broadly
        if not operations_lc:
            return True
        return False

    # Unknown caller — default to True (don't silently skip a rule)
    return True


# Matches ISO 8601 durations like PT8H, PT30M, PT1H30M, PT2H15M etc.
# Doesn't try to handle Y/M/D — PIM activation durations are always hours/minutes.
_ISO_DURATION_RE = re.compile(r'^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$')


def _iso8601_duration_to_minutes(s: Optional[str]) -> Optional[int]:
    """Convert ISO 8601 duration string (e.g. 'PT8H', 'PT1H30M') to integer minutes.

    Returns None on parse failure — caller falls back to the existing value.
    """
    if not s or not isinstance(s, str):
        return None
    m = _ISO_DURATION_RE.match(s.strip())
    if not m:
        return None
    hours = int(m.group(1)) if m.group(1) else 0
    minutes = int(m.group(2)) if m.group(2) else 0
    seconds = int(m.group(3)) if m.group(3) else 0
    total = hours * 60 + minutes + (seconds // 60)
    return total if total > 0 else None


__all__ = [
    'parse_role_management_policy',
    'DEFAULT_POLICY',
]
