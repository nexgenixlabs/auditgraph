"""Central feature + plan definitions for the entitlement engine."""

# Features gated by plan tier.  Key = feature_key used in @require_entitlement / @require_feature.
# 'plans' lists which plan tiers include the feature by default.
FEATURES = {
    'soar_automation':    {'plans': ['trial', 'pro']},
    'api_keys':           {'plans': ['trial', 'pro']},
    'advanced_query':     {'plans': ['trial', 'pro']},
    'custom_risk_rules':  {'plans': ['trial', 'pro']},
    'ai_copilot':         {'plans': ['trial', 'pro']},
    'scheduled_reports':  {'plans': ['trial', 'pro']},
    'compliance_export':  {'plans': ['trial', 'pro']},
    'sso':                {'plans': ['trial', 'pro']},
    'oidc':               {'plans': ['trial', 'pro']},
    'scim':               {'plans': ['pro']},
}

# Backward-compat aliases: old feature_name → canonical feature_key
FEATURE_ALIASES = {
    'soar': 'soar_automation',
}

# Default resource limits per plan tier.
# None = unlimited.
PLAN_DEFAULTS = {
    'free':       {'max_subscriptions': 1,  'max_identities': 50},
    'trial':      {'max_subscriptions': 5,  'max_identities': 500},
    'pro':        {'max_subscriptions': None, 'max_identities': None},
}
