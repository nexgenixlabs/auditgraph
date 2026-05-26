"""Authoritative billing constants — single source of truth.

All monetary values in integer cents to avoid floating-point issues.
"""

PRICING_VERSION = '2026-03-01'

# Platform base fee (cents/month) — charged to all paid plans
PLATFORM_FEE_CENTS = 50_000  # $500/month

# Per-subscription rate (cents/month) — cloud-agnostic
SUBSCRIPTION_RATE_CENTS = 6_900  # $69/month per monitored subscription

# Plan-specific platform fee overrides
PLAN_PLATFORM_FEES = {
    'free': 0,
    'trial': 0,           # Waived during trial (full fee shown in UI)
    'pro': 50_000,         # $500/month
}

# Per-cloud rate overrides (defaults to SUBSCRIPTION_RATE_CENTS if not listed)
CLOUD_SUB_RATES = {
    'azure': 6_900,
    'aws': 6_900,
    'gcp': 6_900,
}

# Commitment discounts (term_years -> fraction off)
COMMITMENT_DISCOUNTS = {0: 0.0, 1: 0.15, 3: 0.25, 5: 0.35}

# Plan limits
PLAN_LIMITS = {
    'free': {'max_active_subs': 2, 'max_identities': 500},
    'trial': {'max_active_subs': None, 'max_identities': None},
    'pro': {'max_active_subs': None, 'max_identities': None},
    'enterprise': {'max_active_subs': None, 'max_identities': None},
}
