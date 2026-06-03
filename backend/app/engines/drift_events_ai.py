"""
AI Drift Event Taxonomy — Extension to drift_events.py

This module ADDS AI/agent-specific drift event types on top of the base
``DriftEventType`` taxonomy defined in ``drift_events.py``. It does NOT modify
or replace that module — the two are composed at registration time inside a
``DriftDetector`` subclass that merges the two type/severity/bucket dicts.

Composition pattern (in a DriftDetector subclass):

    from .drift_events import (
        DriftEventType, EVENT_SEVERITY, EVENT_TO_LEGACY_BUCKET,
    )
    from .drift_events_ai import (
        AIDriftEventType, AI_EVENT_SEVERITY, AI_EVENT_TO_LEGACY_BUCKET,
        ALL_AI_EVENT_TYPES,
    )

    MERGED_SEVERITY = {**EVENT_SEVERITY, **AI_EVENT_SEVERITY}
    MERGED_BUCKETS = {**EVENT_TO_LEGACY_BUCKET, **AI_EVENT_TO_LEGACY_BUCKET}

Both event families share the same legacy 5-bucket projection
(``new_identities`` / ``removed_identities`` / ``permission_changes`` /
``risk_changes`` / ``credential_changes``) so the existing drift UI, email
templates, webhooks, and SOAR triggers keep working without changes.

The builder ``build_ai_drift_event`` mirrors the shape of ``build_event`` in
``drift_events.py`` and adds a few AI-specific top-level fields
(``run_id``, ``organization_id``, ``before``, ``after``) that downstream AI
posture reporting consumes.

No hardcoded thresholds. No synthetic event generation. Pure constants and
dict builders.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional


class AIDriftEventType:
    """Constants for AI/agent-specific drift event types.

    Composes with ``DriftEventType`` from ``drift_events.py``. Both classes
    are merged at registration time inside the DriftDetector subclass that
    owns AI-aware diffing.
    """
    # AI deployment / model changes
    MODEL_CHANGED = 'ai_model_changed'
    MODEL_VERSION_BUMPED = 'ai_model_version_bumped'
    DEPLOYMENT_ADDED = 'ai_deployment_added'
    DEPLOYMENT_REMOVED = 'ai_deployment_removed'
    CAPACITY_EXPANDED = 'ai_capacity_expanded'

    # AI identity / permission posture
    AI_PERMISSIONS_ESCALATED = 'ai_permissions_escalated'
    AI_OWNER_CHANGED = 'ai_owner_changed'

    # AI agent lifecycle (joiner / mover / leaver applied to autonomous agents)
    AI_AGENT_JOINER = 'ai_agent_joiner'
    AI_AGENT_MOVER = 'ai_agent_mover'
    AI_AGENT_LEAVER = 'ai_agent_leaver'


AI_EVENT_SEVERITY: Dict[str, str] = {
    AIDriftEventType.MODEL_CHANGED: 'high',
    AIDriftEventType.MODEL_VERSION_BUMPED: 'medium',
    AIDriftEventType.DEPLOYMENT_ADDED: 'medium',
    AIDriftEventType.DEPLOYMENT_REMOVED: 'low',
    AIDriftEventType.CAPACITY_EXPANDED: 'medium',
    AIDriftEventType.AI_PERMISSIONS_ESCALATED: 'critical',
    AIDriftEventType.AI_OWNER_CHANGED: 'high',
    AIDriftEventType.AI_AGENT_JOINER: 'medium',
    AIDriftEventType.AI_AGENT_MOVER: 'high',
    AIDriftEventType.AI_AGENT_LEAVER: 'low',
}


# Project each AI event onto one of the legacy 5 buckets used by drift UI,
# email, webhooks, and SOAR. Reuse — do not introduce new buckets.
AI_EVENT_TO_LEGACY_BUCKET: Dict[str, str] = {
    # Model / deployment / capacity changes describe the capability surface
    # of the AI identity — bucket them as classification changes.
    AIDriftEventType.MODEL_CHANGED: 'classification_changes',
    AIDriftEventType.MODEL_VERSION_BUMPED: 'classification_changes',
    AIDriftEventType.DEPLOYMENT_ADDED: 'classification_changes',
    AIDriftEventType.DEPLOYMENT_REMOVED: 'classification_changes',
    AIDriftEventType.CAPACITY_EXPANDED: 'classification_changes',

    # Permission + ownership shifts map to the permission bucket.
    AIDriftEventType.AI_PERMISSIONS_ESCALATED: 'permission_changes',
    AIDriftEventType.AI_OWNER_CHANGED: 'permission_changes',

    # Agent lifecycle mirrors human JML — joiners are new identities,
    # movers are permission changes, leavers are risk changes (so a
    # decommissioned agent still surfaces in the risk feed for follow-up).
    AIDriftEventType.AI_AGENT_JOINER: 'new_identities',
    AIDriftEventType.AI_AGENT_MOVER: 'permission_changes',
    AIDriftEventType.AI_AGENT_LEAVER: 'risk_changes',
}


ALL_AI_EVENT_TYPES: List[str] = [
    AIDriftEventType.MODEL_CHANGED,
    AIDriftEventType.MODEL_VERSION_BUMPED,
    AIDriftEventType.DEPLOYMENT_ADDED,
    AIDriftEventType.DEPLOYMENT_REMOVED,
    AIDriftEventType.CAPACITY_EXPANDED,
    AIDriftEventType.AI_PERMISSIONS_ESCALATED,
    AIDriftEventType.AI_OWNER_CHANGED,
    AIDriftEventType.AI_AGENT_JOINER,
    AIDriftEventType.AI_AGENT_MOVER,
    AIDriftEventType.AI_AGENT_LEAVER,
]


def build_ai_drift_event(
    event_type: str,
    identity_id: str,
    run_id: Optional[Any],
    before: Optional[Dict[str, Any]],
    after: Optional[Dict[str, Any]],
    organization_id: Optional[Any],
    display_name: str = '',
    description: str = '',
    details: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Build a typed AI drift event dict.

    Shape mirrors ``build_event`` in ``drift_events.py`` (event_type, severity,
    identity_id, display_name, description, details, timestamp) and adds the
    AI-specific top-level fields needed by the AI posture pipeline:

    - ``run_id`` — discovery run that produced this event
    - ``organization_id`` — tenant scope (called ``organization_id`` here to
      match the AI pipeline's terminology; equivalent to tenant_id)
    - ``before`` — snapshot of the relevant fields prior to the change
    - ``after`` — snapshot of the relevant fields after the change

    Severity is looked up from ``AI_EVENT_SEVERITY`` (falls back to 'medium'
    so unknown event types don't raise — matching the base builder).

    Any extra ``**kwargs`` are merged into ``details`` (not the top level),
    so callers can attach context like ``model_name``, ``deployment_name``,
    ``capacity_before``/``capacity_after`` without bloating the envelope.
    """
    merged_details: Dict[str, Any] = dict(details or {})
    if kwargs:
        merged_details.update(kwargs)

    return {
        'event_type': event_type,
        'severity': AI_EVENT_SEVERITY.get(event_type, 'medium'),
        'identity_id': identity_id,
        'display_name': display_name,
        'description': description,
        'details': merged_details,
        'run_id': run_id,
        'organization_id': organization_id,
        'before': before or {},
        'after': after or {},
        'timestamp': datetime.utcnow().isoformat(),
    }
