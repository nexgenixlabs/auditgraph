"""Core entitlement logic — feature checks, subscription limits, usage tracking."""

import json
import logging
import threading
import time
from datetime import datetime, timezone

from app.entitlements.registry import FEATURES, FEATURE_ALIASES, PLAN_DEFAULTS

logger = logging.getLogger(__name__)

# ── In-memory entitlement cache (TTL = 60s) ────────────────────────────────

_cache_lock = threading.Lock()
_cache = {}       # key: (org_id, feature_key) → {'result': (bool, err_or_None), 'expires': float}
_CACHE_TTL = 60   # seconds


def _cache_get(org_id, feature_key):
    """Return cached (allowed, err) or None if miss/expired."""
    key = (org_id, feature_key)
    with _cache_lock:
        entry = _cache.get(key)
        if entry and entry['expires'] > time.monotonic():
            return entry['result']
        # Expired — remove
        _cache.pop(key, None)
    return None


def _cache_set(org_id, feature_key, result):
    """Store result in cache with TTL."""
    key = (org_id, feature_key)
    with _cache_lock:
        _cache[key] = {'result': result, 'expires': time.monotonic() + _CACHE_TTL}


def invalidate_entitlement_cache(org_id=None, feature_key=None):
    """Invalidate cache entries. Called on entitlement writes.

    - org_id + feature_key: invalidate single entry
    - org_id only: invalidate all entries for that org
    - neither: flush entire cache
    """
    with _cache_lock:
        if org_id is None:
            _cache.clear()
            return
        if feature_key:
            _cache.pop((org_id, feature_key), None)
        else:
            keys_to_remove = [k for k in _cache if k[0] == org_id]
            for k in keys_to_remove:
                del _cache[k]


# ── Helpers ─────────────────────────────────────────────────────────────────

def _resolve_feature_key(feature_key):
    """Resolve aliases to canonical feature key."""
    return FEATURE_ALIASES.get(feature_key, feature_key)


# ── Core feature check ─────────────────────────────────────────────────────

def is_feature_enabled(db, organization_id, feature_key):
    """Check if a feature is enabled for an organization.

    Returns (allowed: bool, error_dict_or_None).
    Check order: cache → per-org override → plan default → trial expiry.
    """
    feature_key = _resolve_feature_key(feature_key)

    # Check cache first
    cached = _cache_get(organization_id, feature_key)
    if cached is not None:
        return cached

    result = _is_feature_enabled_uncached(db, organization_id, feature_key)
    _cache_set(organization_id, feature_key, result)
    return result


def _is_feature_enabled_uncached(db, organization_id, feature_key):
    """Actual feature check (no cache)."""
    # 1. Check per-org override in organization_entitlements
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT enabled, expires_at FROM organization_entitlements
            WHERE organization_id = %s AND feature_key = %s
        """, (organization_id, feature_key))
        row = cursor.fetchone()
        cursor.close()

        if row is not None:
            enabled, expires_at = row
            # Check expiry
            if expires_at and expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                return False, {
                    'error': f'Entitlement for {feature_key.replace("_", " ").title()} has expired.',
                    'upgrade_required': True,
                    'current_plan': 'expired_override',
                }
            return (enabled, None) if enabled else (False, {
                'error': f'{feature_key.replace("_", " ").title()} is disabled for this organization.',
                'upgrade_required': True,
                'current_plan': 'override_disabled',
            })
    except Exception:
        pass  # Table may not exist yet; fall through to plan check

    # 2. Look up organization plan
    org = db.get_organization_by_id(organization_id)
    if not org:
        return True, None  # Unknown org — allow (fail open)

    plan = org.get('plan', 'free')
    enforcement_mode = org.get('enforcement_mode', 'strict')

    # 3. Check trial expiry
    if plan == 'trial':
        trial_expires = org.get('trial_expires_at')
        if trial_expires:
            if isinstance(trial_expires, str):
                try:
                    trial_expires = datetime.fromisoformat(trial_expires.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    trial_expires = None
            if trial_expires and trial_expires.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                return False, {
                    'error': 'Your trial has expired. Upgrade to Pro to continue using this feature.',
                    'upgrade_required': True,
                    'current_plan': 'trial_expired',
                }

    # 4. Check plan includes feature
    feature_def = FEATURES.get(feature_key)
    if feature_def is None:
        return True, None  # Unknown feature — allow (fail open)

    if plan in feature_def['plans']:
        return True, None

    # Feature not in plan — apply enforcement_mode
    err = {
        'error': f'{feature_key.replace("_", " ").title()} is not available on the {plan.capitalize()} plan.',
        'upgrade_required': True,
        'current_plan': plan,
    }

    if enforcement_mode == 'monitor_only':
        logger.warning(f"[monitor_only] Feature {feature_key} used by org {organization_id} on {plan} plan")
        return True, None  # Allow but logged

    if enforcement_mode == 'allow_overage':
        logger.warning(f"[allow_overage] Feature {feature_key} used by org {organization_id} on {plan} plan")
        return True, None  # Allow but logged (caller may track overage)

    # strict (default)
    return False, err


# ── Subscription limit enforcement ─────────────────────────────────────────

def enforce_subscription_limit(db, organization_id):
    """Check if organization can activate another subscription.

    Returns (allowed: bool, error_msg_or_None).
    Reads from organization_usage_counters first, falls back to live COUNT.
    Respects enforcement_mode.
    """
    org = db.get_organization_by_id(organization_id)
    if not org:
        return True, None

    plan = org.get('plan', 'free')
    enforcement_mode = org.get('enforcement_mode', 'strict')

    # Per-org override
    max_subs = org.get('subscription_limit')

    # Fall back to plan default
    if max_subs is None:
        plan_limits = PLAN_DEFAULTS.get(plan, PLAN_DEFAULTS.get('pro', {}))
        max_subs = plan_limits.get('max_subscriptions')

    if max_subs is None:
        return True, None  # Unlimited

    # Read from counters table first, fall back to live COUNT
    active_count = _get_counter(db, organization_id, 'active_subscriptions')
    if active_count is None:
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM cloud_subscriptions
                WHERE organization_id = %s AND monitored = true
            """, (organization_id,))
            active_count = cursor.fetchone()[0]
            cursor.close()
        except Exception:
            return True, None  # Can't count — allow

    if active_count >= max_subs:
        if enforcement_mode == 'monitor_only':
            logger.warning(f"[monitor_only] Subscription limit ({active_count}/{max_subs}) exceeded for org {organization_id}")
            return True, None

        if enforcement_mode == 'allow_overage':
            logger.warning(f"[allow_overage] Subscription limit ({active_count}/{max_subs}) exceeded for org {organization_id}")
            return True, None

        # strict
        if plan == 'free':
            return False, f'Free plan is limited to {max_subs} active subscription. Upgrade to Pro to monitor more.'
        elif plan == 'trial':
            return False, f'Trial plan is limited to {max_subs} active subscriptions. Upgrade to Pro for unlimited.'
        else:
            return False, f'Subscription limit of {max_subs} active subscriptions reached.'

    return True, None


# ── Counter helpers ─────────────────────────────────────────────────────────

def _get_counter(db, organization_id, resource_type):
    """Read current_count from organization_usage_counters. Returns int or None."""
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT current_count FROM organization_usage_counters
            WHERE organization_id = %s AND resource_type = %s
        """, (organization_id, resource_type))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None
    except Exception:
        return None


def _update_counter(db, organization_id, resource_type, delta):
    """Atomically increment/decrement a usage counter via UPSERT."""
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            INSERT INTO organization_usage_counters (organization_id, resource_type, current_count, updated_at)
            VALUES (%s, %s, GREATEST(0, %s), NOW())
            ON CONFLICT (organization_id, resource_type)
            DO UPDATE SET current_count = GREATEST(0, organization_usage_counters.current_count + %s),
                          updated_at = NOW()
        """, (organization_id, resource_type, delta, delta))
        db._commit()
        cursor.close()
    except Exception:
        try:
            db._rollback()
        except Exception:
            pass


# ── Org entitlements summary ────────────────────────────────────────────────

def get_org_entitlements(db, organization_id):
    """Return full entitlement summary for an organization."""
    org = db.get_organization_by_id(organization_id)
    if not org:
        return None

    plan = org.get('plan', 'free')
    plan_limits = PLAN_DEFAULTS.get(plan, PLAN_DEFAULTS.get('pro', {}))

    # Check each feature
    features = {}
    for key in FEATURES:
        enabled, err = is_feature_enabled(db, organization_id, key)
        features[key] = {
            'enabled': enabled,
            'reason': err.get('error') if err else None,
        }

    return {
        'organization_id': organization_id,
        'plan': plan,
        'plan_type': org.get('plan_type', 'self_serve'),
        'plan_status': org.get('plan_status', 'active'),
        'enforcement_mode': org.get('enforcement_mode', 'strict'),
        'limits': {
            'max_subscriptions': org.get('subscription_limit') or plan_limits.get('max_subscriptions'),
            'max_identities': plan_limits.get('max_identities'),
        },
        'features': features,
    }


# ── Usage tracking ──────────────────────────────────────────────────────────

def track_usage(db, organization_id, resource_type, resource_id, action, metadata=None):
    """Record a usage event in organization_usage and update counters atomically."""
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            INSERT INTO organization_usage (organization_id, resource_type, resource_id, action, metadata)
            VALUES (%s, %s, %s, %s, %s)
        """, (organization_id, resource_type, resource_id, action, json.dumps(metadata or {})))
        db._commit()
        cursor.close()
    except Exception:
        try:
            db._rollback()
        except Exception:
            pass

    # Update counters for activation/deactivation actions
    counter_type = _action_to_counter_type(resource_type, action)
    if counter_type:
        delta = 1 if action in ('activated', 'added') else -1
        _update_counter(db, organization_id, counter_type, delta)


def _action_to_counter_type(resource_type, action):
    """Map resource_type + action to a counter resource_type, or None if not tracked."""
    if resource_type == 'subscription' and action in ('activated', 'deactivated'):
        return 'active_subscriptions'
    if resource_type == 'connection' and action in ('added', 'removed'):
        return 'active_connections'
    return None
