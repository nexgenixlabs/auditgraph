"""
AuditGraph Billing Engine — Pure pricing logic (no DB access).

All monetary values are in integer cents to avoid floating-point issues.
"""

import hashlib
import json

from app.billing.config import (
    PRICING_VERSION,
    PLATFORM_FEE_CENTS,
    PLAN_PLATFORM_FEES,
    CLOUD_SUB_RATES,
    COMMITMENT_DISCOUNTS,
    PLAN_LIMITS,
)


def compute_invoice_hash(invoice_data: dict) -> str:
    """Compute SHA-256 hash of immutable invoice financial fields.

    Uses canonical JSON (sort_keys, compact separators) for deterministic output.
    Excludes mutable fields (status, paid_at, voided_at, notes).
    """
    canonical = json.dumps({
        'invoice_number': invoice_data['invoice_number'],
        'tenant_id': invoice_data['tenant_id'],
        'period_start': str(invoice_data['period_start']),
        'period_end': str(invoice_data['period_end']),
        'subtotal_cents': invoice_data['subtotal_cents'],
        'tax_amount_cents': invoice_data['tax_amount_cents'],
        'discount_cents': invoice_data['discount_cents'],
        'total_cents': invoice_data['total_cents'],
        'line_items': invoice_data['line_items'],
        'seller_snapshot': invoice_data['seller_snapshot'],
        'buyer_snapshot': invoice_data['buyer_snapshot'],
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

# ── Backward-compatible aliases (imported from billing.config) ───────────────
PLATFORM_FEES = PLAN_PLATFORM_FEES
DEFAULT_SUB_RATES = CLOUD_SUB_RATES


def get_default_platform_fee(plan: str) -> int:
    """Return default platform fee in cents for a plan tier."""
    return PLAN_PLATFORM_FEES.get(plan, PLAN_PLATFORM_FEES['pro'])


def get_real_platform_fee(plan: str) -> int:
    """Return the REAL platform fee (ignoring trial waiver).

    Trial plans show $500 as their real fee but waive it.
    """
    if plan == 'trial':
        return PLATFORM_FEE_CENTS  # $500 — full fee, waived at billing time
    return PLAN_PLATFORM_FEES.get(plan, PLAN_PLATFORM_FEES['pro'])


def get_default_sub_rate(cloud: str) -> int:
    """Return default per-subscription rate in cents for a cloud provider."""
    return CLOUD_SUB_RATES.get(cloud, CLOUD_SUB_RATES['azure'])


def calculate_billing(tenant_dict: dict, subscription_list: list) -> dict:
    """Compute full billing breakdown for a tenant.

    Args:
        tenant_dict: tenant row with plan, platform_fee_cents, discount_pct,
                     subscription_term fields.
        subscription_list: list of cloud_subscription rows with cloud,
                          monitored, rate_cents fields.

    Returns dict with:
        platform_fee_cents, platform_fee_waiver_cents, trial_active,
        subscription_total_cents, gross_monthly_cents,
        discount_pct, net_monthly_cents, projected_arr_cents,
        active_count, subscriptions_by_cloud, line_items
    """
    plan = tenant_dict.get('plan', 'free')
    is_trial = (plan == 'trial')

    # Platform fee: always show the REAL fee (even for trial)
    # For trial: use the full $500 fee (will be waived below)
    # For other plans: use org override or plan default
    if is_trial:
        platform_fee = get_real_platform_fee('trial')
    else:
        platform_fee = tenant_dict.get('platform_fee_cents', get_default_platform_fee(plan))

    # Trial waiver: full platform fee waived during trial
    waiver = platform_fee if is_trial else 0

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

    # Trial waiver line item (negative, cancels platform fee)
    if waiver > 0:
        line_items.append({
            'label': 'Trial Waiver \u2014 Platform Fee',
            'amount_cents': -waiver,
            'type': 'trial_waiver',
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

    # Subtract trial waiver before discount
    effective_gross = gross - waiver

    # Apply discount on post-waiver amount
    if discount_pct > 0:
        discount_amount = int(effective_gross * discount_pct / 100)
        net = effective_gross - discount_amount
        line_items.append({
            'label': f'Commitment Discount ({discount_pct}%)',
            'amount_cents': -discount_amount,
            'type': 'discount',
        })
    else:
        net = effective_gross

    return {
        'platform_fee_cents': platform_fee,
        'platform_fee_waiver_cents': waiver,
        'trial_active': is_trial,
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
