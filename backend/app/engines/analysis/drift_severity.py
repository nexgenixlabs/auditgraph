"""
DriftSeverityEngine — Rule-based severity classifier for drift events.

Inspects each event's event_type and details to override the default severity
when a more specific rule applies. Only upgrades severity, never downgrades.
"""
from __future__ import annotations

import logging
from app.constants.roles import EntraRole, RBACRole, _lower

logger = logging.getLogger(__name__)

SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

# Roles that always warrant critical severity when assigned
CRITICAL_ROLES = _lower(frozenset({
    EntraRole.GLOBAL_ADMIN, EntraRole.COMPANY_ADMIN,
    EntraRole.PRIVILEGED_ROLE_ADMIN, EntraRole.SECURITY_ADMIN,
}))

# Key Vault access roles that warrant critical severity
KEY_VAULT_CRITICAL_ROLES = _lower(frozenset({
    RBACRole.KEY_VAULT_SECRETS_OFFICER, RBACRole.KEY_VAULT_SECRETS_USER,
    RBACRole.KEY_VAULT_ADMIN, RBACRole.KEY_VAULT_CRYPTO_OFFICER,
    RBACRole.KEY_VAULT_CERTS_OFFICER,
}))

# Roles that warrant high severity when assigned
HIGH_ROLES = _lower(frozenset({
    RBACRole.CONTRIBUTOR, RBACRole.USER_ACCESS_ADMIN,
}))


def _role_names_lower(details: dict, key: str) -> list:
    """Extract role names from details, handling both string lists and role signature format."""
    raw = details.get(key, [])
    if not isinstance(raw, list):
        return []
    result = []
    for r in raw:
        if isinstance(r, str):
            # Role signatures are "RoleName:scope_type:/scope/path"
            result.append(r.split(':')[0].strip().lower())
        elif isinstance(r, dict):
            result.append((r.get('role_name') or r.get('name') or '').lower())
    return result


def _check_severity(event: dict) -> str | None:
    """Return upgraded severity or None if no rule matches."""
    et = event.get('event_type', '')
    details = event.get('details', {})
    current = event.get('severity', 'medium')

    # Attack path created is always critical
    if et == 'attack_path_created':
        return 'critical'

    # Identity resurrection is always high
    if et == 'identity_resurrection':
        return 'high'

    # Role assignment / privilege escalation events
    if et in ('role_assigned', 'privilege_escalated', 'identity_added'):
        added = _role_names_lower(details, 'added_roles')
        role_name = (details.get('role_name') or '').lower()
        all_roles = added + ([role_name] if role_name else [])

        # Check critical roles
        for r in all_roles:
            if r in CRITICAL_ROLES:
                return 'critical'
            if r in KEY_VAULT_CRITICAL_ROLES:
                return 'critical'
            if r == 'owner' and details.get('scope_type') in ('subscription', 'management_group'):
                return 'critical'

        # Check high roles
        for r in all_roles:
            if r in HIGH_ROLES:
                return 'high' if SEVERITY_RANK.get(current, 0) < SEVERITY_RANK['high'] else None

        # SPN created with RBAC roles
        if et == 'identity_added' and details.get('identity_category') == 'service_principal':
            if added:
                return 'high' if SEVERITY_RANK.get(current, 0) < SEVERITY_RANK['high'] else None
            return 'medium' if SEVERITY_RANK.get(current, 0) < SEVERITY_RANK['medium'] else None

        # Write access detection
        for r in all_roles:
            if 'contributor' in r or 'writer' in r or 'owner' in r:
                return 'high' if SEVERITY_RANK.get(current, 0) < SEVERITY_RANK['high'] else None

    # Reader role granted
    if et == 'role_assigned':
        added = _role_names_lower(details, 'added_roles')
        for r in added:
            if 'reader' in r and SEVERITY_RANK.get(current, 0) < SEVERITY_RANK['medium']:
                return 'medium'

    # Metadata/tag/description changes
    if et in ('owner_changed', 'microsoft_spn_modified'):
        return 'low' if SEVERITY_RANK.get(current, 0) <= SEVERITY_RANK['low'] else None

    return None


class DriftSeverityEngine:
    """Enriches drift events with refined severity classification."""

    def enrich(self, events: list) -> list:
        """Mutate events in-place with upgraded severity. Returns the list."""
        upgraded = 0
        for event in events:
            new_sev = _check_severity(event)
            if new_sev and SEVERITY_RANK.get(new_sev, 0) > SEVERITY_RANK.get(event.get('severity', 'medium'), 0):
                event.setdefault('details', {})['original_severity'] = event.get('severity')
                event['severity'] = new_sev
                upgraded += 1

        if upgraded:
            logger.info(f"DriftSeverityEngine: upgraded {upgraded} event(s)")
        return events
