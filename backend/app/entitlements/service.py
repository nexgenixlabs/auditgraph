"""Core entitlement logic — feature checks, subscription limits, usage tracking."""

from datetime import datetime, timezone

from app.entitlements.registry import FEATURES, FEATURE_ALIASES, PLAN_DEFAULTS


def _resolve_feature_key(feature_key):
    """Resolve aliases to canonical feature key."""
    return FEATURE_ALIASES.get(feature_key, feature_key)


def is_feature_enabled(db, organization_id, feature_key):
    """Check if a feature is enabled for an organization.

    Returns (allowed: bool, error_dict_or_None).
    Check order: per-org override → plan default → trial expiry.
    """
    feature_key = _resolve_feature_key(feature_key)

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

    return False, {
        'error': f'{feature_key.replace("_", " ").title()} is not available on the {plan.capitalize()} plan.',
        'upgrade_required': True,
        'current_plan': plan,
    }


def enforce_subscription_limit(db, organization_id):
    """Check if organization can activate another subscription.

    Returns (allowed: bool, error_msg_or_None).
    Checks per-org subscription_limit override, then plan default.
    """
    org = db.get_organization_by_id(organization_id)
    if not org:
        return True, None

    plan = org.get('plan', 'free')

    # Per-org override
    max_subs = org.get('subscription_limit')

    # Fall back to plan default
    if max_subs is None:
        plan_limits = PLAN_DEFAULTS.get(plan, PLAN_DEFAULTS.get('pro', {}))
        max_subs = plan_limits.get('max_subscriptions')

    if max_subs is None:
        return True, None  # Unlimited

    # Count active subscriptions
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
        if plan == 'free':
            return False, f'Free plan is limited to {max_subs} active subscription. Upgrade to Pro to monitor more.'
        elif plan == 'trial':
            return False, f'Trial plan is limited to {max_subs} active subscriptions. Upgrade to Pro for unlimited.'
        else:
            return False, f'Subscription limit of {max_subs} active subscriptions reached.'

    return True, None


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
        'limits': {
            'max_subscriptions': org.get('subscription_limit') or plan_limits.get('max_subscriptions'),
            'max_identities': plan_limits.get('max_identities'),
        },
        'features': features,
    }


def track_usage(db, organization_id, resource_type, resource_id, action, metadata=None):
    """Record a usage event in organization_usage."""
    try:
        import json
        cursor = db.conn.cursor()
        cursor.execute("""
            INSERT INTO organization_usage (organization_id, resource_type, resource_id, action, metadata)
            VALUES (%s, %s, %s, %s, %s)
        """, (organization_id, resource_type, resource_id, action, json.dumps(metadata or {})))
        db.conn.commit()
        cursor.close()
    except Exception:
        try:
            db.conn.rollback()
        except Exception:
            pass
