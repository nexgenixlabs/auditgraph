"""Organization Entitlement Engine — centralized feature gating & usage tracking."""

from app.entitlements.registry import FEATURES, PLAN_DEFAULTS
from app.entitlements.service import (
    is_feature_enabled,
    enforce_subscription_limit,
    get_org_entitlements,
    track_usage,
)
from app.entitlements.decorator import require_entitlement

__all__ = [
    'FEATURES',
    'PLAN_DEFAULTS',
    'is_feature_enabled',
    'enforce_subscription_limit',
    'get_org_entitlements',
    'track_usage',
    'require_entitlement',
]
