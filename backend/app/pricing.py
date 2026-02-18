"""
AuditGraph Billing Engine — Pure pricing logic (no DB access).

All monetary values are in integer cents to avoid floating-point issues.
"""

# ── Platform fees by account plan (cents/month) ─────────────────────────────
PLATFORM_FEES = {
    'free': 0,
    'trial': 0,
    'pro': 20_000,        # $200/mo
    'enterprise': 50_000,  # $500/mo
}

# ── Default per-subscription rates by cloud (cents/month) ───────────────────
DEFAULT_SUB_RATES = {
    'azure': 6_900,   # $69/mo
    'aws': 7_900,     # $79/mo
    'gcp': 7_400,     # $74/mo
}

# ── Commitment discounts (term_years → fraction off) ────────────────────────
COMMITMENT_DISCOUNTS = {
    0: 0.0,
    1: 0.15,
    3: 0.25,
    5: 0.35,
}

# ── Plan limits ─────────────────────────────────────────────────────────────
PLAN_LIMITS = {
    'free': {'max_active_subs': 1, 'max_identities': 50},
    'trial': {'max_active_subs': 5, 'max_identities': 500},
    'pro': {'max_active_subs': None, 'max_identities': None},
    'enterprise': {'max_active_subs': None, 'max_identities': None},
}


def get_default_platform_fee(plan: str) -> int:
    """Return default platform fee in cents for a plan tier."""
    return PLATFORM_FEES.get(plan, PLATFORM_FEES['pro'])


def get_default_sub_rate(cloud: str) -> int:
    """Return default per-subscription rate in cents for a cloud provider."""
    return DEFAULT_SUB_RATES.get(cloud, DEFAULT_SUB_RATES['azure'])


def calculate_billing(tenant_dict: dict, subscription_list: list) -> dict:
    """Compute full billing breakdown for a tenant.

    Args:
        tenant_dict: tenant row with plan, platform_fee_cents, discount_pct,
                     subscription_term fields.
        subscription_list: list of cloud_subscription rows with cloud,
                          monitored, rate_cents fields.

    Returns dict with:
        platform_fee_cents, subscription_total_cents, gross_monthly_cents,
        discount_pct, net_monthly_cents, projected_arr_cents,
        active_count, subscriptions_by_cloud, line_items
    """
    plan = tenant_dict.get('plan', 'free')
    platform_fee = tenant_dict.get('platform_fee_cents', get_default_platform_fee(plan))
    discount_pct = float(tenant_dict.get('discount_pct', 0))

    # Only count monitored (active) subscriptions
    active_subs = [s for s in subscription_list if s.get('monitored')]
    active_count = len(active_subs)

    # Per-cloud breakdown
    by_cloud = {}
    line_items = []
    sub_total = 0

    for sub in active_subs:
        cloud = sub.get('cloud', 'azure')
        rate = sub.get('rate_cents', get_default_sub_rate(cloud))
        sub_total += rate

        if cloud not in by_cloud:
            by_cloud[cloud] = {'count': 0, 'revenue_cents': 0}
        by_cloud[cloud]['count'] += 1
        by_cloud[cloud]['revenue_cents'] += rate

    # Build line items
    if platform_fee > 0:
        line_items.append({
            'label': 'Platform Fee',
            'amount_cents': platform_fee,
            'type': 'platform',
        })

    for cloud, info in sorted(by_cloud.items()):
        line_items.append({
            'label': f'{cloud.upper()} Subscriptions ({info["count"]})',
            'amount_cents': info['revenue_cents'],
            'type': 'subscriptions',
            'cloud': cloud,
            'count': info['count'],
        })

    gross = platform_fee + sub_total

    # Apply discount
    if discount_pct > 0:
        discount_amount = int(gross * discount_pct / 100)
        net = gross - discount_amount
        line_items.append({
            'label': f'Commitment Discount ({discount_pct}%)',
            'amount_cents': -discount_amount,
            'type': 'discount',
        })
    else:
        net = gross

    return {
        'platform_fee_cents': platform_fee,
        'subscription_total_cents': sub_total,
        'gross_monthly_cents': gross,
        'discount_pct': discount_pct,
        'net_monthly_cents': net,
        'projected_arr_cents': net * 12,
        'active_count': active_count,
        'subscriptions_by_cloud': by_cloud,
        'line_items': line_items,
    }


def calculate_invoice(tenant_dict: dict, subscription_list: list) -> dict:
    """Compute full invoice breakdown for a tenant including tax.

    Wraps calculate_billing() and adds tax computation based on tenant config.

    Returns dict with all calculate_billing() fields plus:
        subtotal_cents, tax_label, tax_rate, tax_amount_cents, total_cents,
        and tax line item appended to line_items.
    """
    billing = calculate_billing(tenant_dict, subscription_list)

    tax_rate = float(tenant_dict.get('tax_rate', 0))
    tax_exempt = tenant_dict.get('tax_exempt', False)
    tax_label = tenant_dict.get('tax_label', 'Tax')

    subtotal = billing['net_monthly_cents']

    if tax_exempt or tax_rate <= 0:
        tax_amount = 0
    else:
        tax_amount = int(subtotal * tax_rate / 100)

    total = subtotal + tax_amount

    line_items = list(billing['line_items'])
    if tax_amount > 0:
        line_items.append({
            'label': f'{tax_label} ({tax_rate}%)',
            'amount_cents': tax_amount,
            'type': 'tax',
        })

    return {
        **billing,
        'subtotal_cents': subtotal,
        'tax_label': tax_label,
        'tax_rate': tax_rate,
        'tax_amount_cents': tax_amount,
        'total_cents': total,
        'line_items': line_items,
    }


def can_activate_subscription(tenant_dict: dict, current_active_count: int):
    """Check if a tenant can activate another subscription.

    Returns (allowed: bool, error_msg: str|None)
    """
    plan = tenant_dict.get('plan', 'free')
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS['pro'])
    max_subs = limits.get('max_active_subs')

    if max_subs is not None and current_active_count >= max_subs:
        if plan == 'free':
            return False, f'Free plan is limited to {max_subs} active subscription. Upgrade to Pro to monitor more.'
        elif plan == 'trial':
            return False, f'Trial plan is limited to {max_subs} active subscriptions. Upgrade to Pro for unlimited.'
        else:
            return False, f'Plan limit of {max_subs} active subscriptions reached.'

    return True, None
