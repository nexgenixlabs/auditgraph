"""
Enhanced Drift Event Taxonomy

Defines 20 typed drift events with severity classification,
a builder function, and backward-compatible legacy format converter.
"""
from datetime import datetime
from typing import Dict, List, Optional


class DriftEventType:
    """Constants for the 13 drift event types."""
    IDENTITY_ADDED = 'identity_added'
    IDENTITY_REMOVED = 'identity_removed'
    IDENTITY_DISABLED = 'identity_disabled'
    IDENTITY_REACTIVATED = 'identity_reactivated'
    ROLE_ASSIGNED = 'role_assigned'
    ROLE_REMOVED = 'role_removed'
    PRIVILEGE_ESCALATED = 'privilege_escalated'
    PRIVILEGE_DEESCALATED = 'privilege_deescalated'
    RISK_ESCALATED = 'risk_escalated'
    RISK_DEESCALATED = 'risk_deescalated'
    SPN_CREDENTIAL_EXPIRED = 'spn_credential_expired'
    SPN_CREDENTIAL_ADDED = 'spn_credential_added'
    MFA_DISABLED = 'mfa_disabled'
    OWNER_CHANGED = 'owner_changed'
    MICROSOFT_SPN_MODIFIED = 'microsoft_spn_modified'
    CLASSIFICATION_ADDED = 'classification_added'
    CLASSIFICATION_REMOVED = 'classification_removed'
    CLASSIFICATION_CHANGED = 'classification_changed'
    ATTACK_PATH_CREATED = 'attack_path_created'
    IDENTITY_RESURRECTION = 'identity_resurrection'


EVENT_SEVERITY: Dict[str, str] = {
    DriftEventType.IDENTITY_ADDED: 'medium',
    DriftEventType.IDENTITY_REMOVED: 'medium',
    DriftEventType.IDENTITY_DISABLED: 'low',
    DriftEventType.IDENTITY_REACTIVATED: 'high',
    DriftEventType.ROLE_ASSIGNED: 'high',
    DriftEventType.ROLE_REMOVED: 'low',
    DriftEventType.PRIVILEGE_ESCALATED: 'critical',
    DriftEventType.PRIVILEGE_DEESCALATED: 'low',
    DriftEventType.RISK_ESCALATED: 'high',
    DriftEventType.RISK_DEESCALATED: 'low',
    DriftEventType.SPN_CREDENTIAL_EXPIRED: 'medium',
    DriftEventType.SPN_CREDENTIAL_ADDED: 'medium',
    DriftEventType.MFA_DISABLED: 'critical',
    DriftEventType.OWNER_CHANGED: 'medium',
    DriftEventType.MICROSOFT_SPN_MODIFIED: 'low',
    DriftEventType.CLASSIFICATION_ADDED: 'medium',
    DriftEventType.CLASSIFICATION_REMOVED: 'high',
    DriftEventType.CLASSIFICATION_CHANGED: 'medium',
    DriftEventType.ATTACK_PATH_CREATED: 'critical',
    DriftEventType.IDENTITY_RESURRECTION: 'high',
}

# Maps typed events to legacy 5-bucket keys for backward compatibility
EVENT_TO_LEGACY_BUCKET: Dict[str, str] = {
    DriftEventType.IDENTITY_ADDED: 'new_identities',
    DriftEventType.IDENTITY_REMOVED: 'removed_identities',
    DriftEventType.IDENTITY_DISABLED: 'removed_identities',
    DriftEventType.IDENTITY_REACTIVATED: 'new_identities',
    DriftEventType.ROLE_ASSIGNED: 'permission_changes',
    DriftEventType.ROLE_REMOVED: 'permission_changes',
    DriftEventType.PRIVILEGE_ESCALATED: 'permission_changes',
    DriftEventType.PRIVILEGE_DEESCALATED: 'permission_changes',
    DriftEventType.RISK_ESCALATED: 'risk_changes',
    DriftEventType.RISK_DEESCALATED: 'risk_changes',
    DriftEventType.SPN_CREDENTIAL_EXPIRED: 'credential_changes',
    DriftEventType.SPN_CREDENTIAL_ADDED: 'credential_changes',
    DriftEventType.MFA_DISABLED: 'risk_changes',
    DriftEventType.OWNER_CHANGED: 'permission_changes',
    DriftEventType.MICROSOFT_SPN_MODIFIED: 'risk_changes',
    DriftEventType.CLASSIFICATION_ADDED: 'classification_changes',
    DriftEventType.CLASSIFICATION_REMOVED: 'classification_changes',
    DriftEventType.CLASSIFICATION_CHANGED: 'classification_changes',
    DriftEventType.ATTACK_PATH_CREATED: 'risk_changes',
    DriftEventType.IDENTITY_RESURRECTION: 'new_identities',
}


def build_event(
    event_type: str,
    identity_id: str,
    display_name: str,
    description: str,
    details: Optional[Dict] = None,
) -> Dict:
    """Build a typed drift event dict."""
    return {
        'event_type': event_type,
        'severity': EVENT_SEVERITY.get(event_type, 'medium'),
        'identity_id': identity_id,
        'display_name': display_name,
        'description': description,
        'details': details or {},
        'timestamp': datetime.utcnow().isoformat(),
    }


def events_to_legacy_format(events: List[Dict]) -> Dict:
    """
    Convert typed events list to the legacy 5-bucket dict format.
    Used for backward compatibility with email, webhooks, SOAR, etc.
    """
    legacy: Dict[str, List] = {
        'new_identities': [],
        'removed_identities': [],
        'permission_changes': [],
        'risk_changes': [],
        'credential_changes': [],
    }

    for event in events:
        bucket = EVENT_TO_LEGACY_BUCKET.get(event.get('event_type', ''))
        if not bucket:
            continue

        et = event['event_type']
        details = event.get('details', {})

        if bucket == 'new_identities':
            legacy[bucket].append({
                'identity_id': event['identity_id'],
                'display_name': event['display_name'],
                'identity_type': details.get('identity_type', ''),
                'identity_category': details.get('identity_category', ''),
                'risk_level': details.get('risk_level', 'info'),
                'credential_status': details.get('credential_status', ''),
                'change_reason': event.get('description', ''),
            })
        elif bucket == 'removed_identities':
            legacy[bucket].append({
                'identity_id': event['identity_id'],
                'display_name': event['display_name'],
                'identity_type': details.get('identity_type', ''),
                'identity_category': details.get('identity_category', ''),
                'risk_level': details.get('risk_level', 'info'),
                'credential_status': details.get('credential_status', ''),
                'change_reason': event.get('description', ''),
            })
        elif bucket == 'permission_changes':
            legacy[bucket].append({
                'identity': {
                    'identity_id': event['identity_id'],
                    'display_name': event['display_name'],
                    'risk_level': details.get('risk_level', 'info'),
                },
                'added_roles': details.get('added_roles', []),
                'removed_roles': details.get('removed_roles', []),
                'change_reason': event.get('description', ''),
            })
        elif bucket == 'risk_changes':
            legacy[bucket].append({
                'identity': {
                    'identity_id': event['identity_id'],
                    'display_name': event['display_name'],
                    'risk_level': details.get('current_risk', 'info'),
                },
                'previous_risk': details.get('previous_risk', 'info'),
                'current_risk': details.get('current_risk', 'info'),
                'previous_score': details.get('previous_score', 0),
                'current_score': details.get('current_score', 0),
                'severity': details.get('severity', 'unchanged'),
                'change_reason': event.get('description', ''),
            })
        elif bucket == 'credential_changes':
            legacy[bucket].append({
                'identity': {
                    'identity_id': event['identity_id'],
                    'display_name': event['display_name'],
                    'risk_level': details.get('risk_level', 'info'),
                },
                'previous_status': details.get('previous_status', ''),
                'current_status': details.get('current_status', ''),
                'change_reason': event.get('description', ''),
            })

    return legacy
