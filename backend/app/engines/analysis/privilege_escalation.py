"""
PrivilegeEscalationDetector — Detects privilege escalation in drift events.

Compares previous vs new roles using numeric ranking and annotates events
with escalation metadata.
"""

import logging

logger = logging.getLogger(__name__)

ROLE_PRIVILEGE_RANK = {
    'reader': 1,
    'monitoring reader': 1,
    'log analytics reader': 1,
    'backup reader': 1,
    'cost management reader': 1,
    'contributor': 2,
    'storage blob data contributor': 2,
    'network contributor': 2,
    'virtual machine contributor': 2,
    'sql db contributor': 2,
    'key vault contributor': 2,
    'owner': 3,
    'user access administrator': 3,
    'application administrator': 4,
    'cloud application administrator': 4,
    'privileged role administrator': 4,
    'security administrator': 4,
    'exchange administrator': 4,
    'intune administrator': 4,
    'global administrator': 5,
    'company administrator': 5,
}


def _extract_role_name(sig: str) -> str:
    """Extract role name from a role signature like 'RoleName:scope_type:/scope'."""
    if isinstance(sig, dict):
        return (sig.get('role_name') or sig.get('name') or '').strip().lower()
    return sig.split(':')[0].strip().lower() if isinstance(sig, str) else ''


def _max_rank(roles: list) -> tuple:
    """Return (max_rank, role_name) for a list of role strings/dicts."""
    best_rank = 0
    best_role = ''
    for r in roles:
        name = _extract_role_name(r)
        rank = ROLE_PRIVILEGE_RANK.get(name, 0)
        if rank > best_rank:
            best_rank = rank
            best_role = name
    return best_rank, best_role


class PrivilegeEscalationDetector:
    """Enriches drift events with privilege escalation detection."""

    def enrich(self, events: list) -> list:
        """Mutate events in-place with privilege escalation data. Returns the list."""
        detected = 0
        for event in events:
            et = event.get('event_type', '')
            if et not in ('role_assigned', 'privilege_escalated', 'identity_reactivated'):
                continue

            details = event.get('details', {})
            added = details.get('added_roles', [])
            removed = details.get('removed_roles', [])

            if not added:
                continue

            new_rank, highest_new = _max_rank(added)
            prev_rank, prev_role = _max_rank(removed) if removed else (0, '')

            if new_rank <= 0:
                continue

            delta = new_rank - prev_rank
            if delta > 0:
                details['privilege_escalation'] = {
                    'detected': True,
                    'previous_rank': prev_rank,
                    'new_rank': new_rank,
                    'escalation_delta': delta,
                    'highest_new_role': highest_new.title(),
                    'previous_role': prev_role.title() if prev_role else None,
                }
                detected += 1
            elif new_rank > 0:
                # Same or lower rank — still annotate for context
                details['privilege_escalation'] = {
                    'detected': False,
                    'previous_rank': prev_rank,
                    'new_rank': new_rank,
                    'escalation_delta': delta,
                    'highest_new_role': highest_new.title(),
                    'previous_role': prev_role.title() if prev_role else None,
                }

        if detected:
            logger.info(f"PrivilegeEscalationDetector: {detected} escalation(s) detected")
        return events
