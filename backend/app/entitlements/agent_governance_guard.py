"""Guard decorator for AI Agent Governance feature flag.

Combines the global env-based kill switch (FEATURE_AI_AGENT_GOVERNANCE)
with the per-tenant entitlement check (ai_agent_governance).
When either is disabled, the route returns 404 (as if it doesn't exist).
"""

from functools import wraps
from flask import jsonify

from app.config import FEATURE_AI_AGENT_GOVERNANCE


def require_agent_governance(f):
    """Decorator: route returns 404 when AI Agent Governance is disabled.

    Checks:
      1. Global env flag FEATURE_AI_AGENT_GOVERNANCE (kill switch)
      2. Per-tenant entitlement (delegated to @require_entitlement)

    Usage:
        @app.get("/api/agent-identities")
        @require_agent_governance
        def list_agent_identities():
            ...
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not FEATURE_AI_AGENT_GOVERNANCE:
            return jsonify({'error': 'Not found'}), 404
        return f(*args, **kwargs)
    return wrapper
