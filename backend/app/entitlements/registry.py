"""Central feature + plan definitions for the entitlement engine."""

# Features gated by plan tier.  Key = feature_key used in @require_entitlement / @require_feature.
# 'plans' lists which plan tiers include the feature by default.
FEATURES = {
    'soar_automation':    {'plans': ['trial', 'pro', 'enterprise']},
    'api_keys':           {'plans': ['trial', 'pro', 'enterprise']},
    'advanced_query':     {'plans': ['trial', 'pro', 'enterprise']},
    'custom_risk_rules':  {'plans': ['trial', 'pro', 'enterprise']},
    'ai_copilot':         {'plans': ['trial', 'pro', 'enterprise']},
    'scheduled_reports':  {'plans': ['trial', 'pro', 'enterprise']},
    'compliance_export':  {'plans': ['trial', 'pro', 'enterprise']},
    'sso':                {'plans': ['trial', 'pro', 'enterprise']},
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
    'enterprise': {'max_subscriptions': None, 'max_identities': None},
}
