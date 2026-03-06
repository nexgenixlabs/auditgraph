"""Billing Transparency Engine — snapshots, estimates, invoices, MSP aggregation.

All monetary values are in integer cents to avoid floating-point issues.
Uses app.pricing for core calculation; this module adds persistence + PDF.
"""

import json
import logging
from datetime import date, datetime, timezone, timedelta

from app.pricing import calculate_billing, calculate_invoice
from app.billing.config import PRICING_VERSION, PLAN_PLATFORM_FEES, CLOUD_SUB_RATES

logger = logging.getLogger(__name__)


def _build_unit_prices(org):
    """Build a snapshot of current unit prices for audit trail."""
    plan = org.get('plan', 'free')
    return {
        'platform_fee_cents': org.get('platform_fee_cents', PLAN_PLATFORM_FEES.get(plan, 0)),
        'sub_rates': dict(CLOUD_SUB_RATES),
        'discount_pct': float(org.get('discount_pct', 0)),
    }


def log_billing_audit(db, organization_id, action, actor_id=None, details=None):
    """Write an entry to billing_audit_log."""
    try:
        cursor = db.conn.cursor()
        cursor.execute("""
            INSERT INTO billing_audit_log (organization_id, action, actor_id, details)
            VALUES (%s, %s, %s, %s)
        """, (organization_id, action, actor_id, json.dumps(details or {})))
        db._commit()
        cursor.close()
    except Exception:
        try:
            db._rollback()
        except Exception:
            pass


def calculate_monthly_snapshot(db, organization_id, period_start=None, period_end=None):
    """Compute a billing snapshot for one organization.

    Args:
        db: Database instance (admin connection, BYPASSRLS).
        organization_id: Org to snapshot.
        period_start/end: Date objects. Defaults to previous calendar month.

    Returns dict with all billing fields + breakdown, ready for DB insert.
    """
    org = db.get_organization_by_id(organization_id)
    if not org:
        return None

    # Default to previous calendar month
    if not period_start or not period_end:
        today = date.today()
        first_of_month = today.replace(day=1)
        period_end = first_of_month - timedelta(days=1)
        period_start = period_end.replace(day=1)

    subs = db.get_cloud_subscriptions(organization_id)
    invoice_data = calculate_invoice(org, subs)

    active_subs = [s for s in subs if s.get('monitored')]

    discount_cents = abs(sum(
        li['amount_cents'] for li in invoice_data['line_items'] if li.get('type') == 'discount'
    ))

    return {
        'organization_id': organization_id,
        'period_start': period_start,
        'period_end': period_end,
        'plan': org.get('plan', 'free'),
        'platform_fee_cents': invoice_data['platform_fee_cents'],
        'subscription_total_cents': invoice_data['subscription_total_cents'],
        'gross_cents': invoice_data['gross_monthly_cents'],
        'discount_pct': float(org.get('discount_pct', 0)),
        'discount_cents': discount_cents,
        'net_cents': invoice_data['net_monthly_cents'],
        'tax_rate': float(invoice_data.get('tax_rate', 0)),
        'tax_cents': invoice_data.get('tax_amount_cents', 0),
        'total_cents': invoice_data.get('total_cents', invoice_data['net_monthly_cents']),
        'active_subscriptions': len(active_subs),
        'pricing_version': PRICING_VERSION,
        'unit_prices': _build_unit_prices(org),
        'breakdown': {
            'subscriptions_by_cloud': invoice_data.get('subscriptions_by_cloud', {}),
            'line_items': invoice_data['line_items'],
        },
    }


def store_billing_snapshot(db, snapshot, force=False):
    """Persist a billing snapshot to organization_billing_snapshots.

    Uses INSERT ... ON CONFLICT DO NOTHING by default (snapshot is immutable once created).
    If force=True, overwrites existing snapshot (admin override).
    Returns the stored/existing row as dict, or None if conflict and not forced.
    """
    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    if force:
        # Admin override — UPSERT
        cursor.execute("""
            INSERT INTO organization_billing_snapshots
                (organization_id, period_start, period_end, plan,
                 platform_fee_cents, subscription_total_cents, gross_cents,
                 discount_pct, discount_cents, net_cents,
                 tax_rate, tax_cents, total_cents,
                 active_subscriptions, pricing_version, unit_prices, breakdown)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (organization_id, period_start)
            DO UPDATE SET
                period_end = EXCLUDED.period_end,
                plan = EXCLUDED.plan,
                platform_fee_cents = EXCLUDED.platform_fee_cents,
                subscription_total_cents = EXCLUDED.subscription_total_cents,
                gross_cents = EXCLUDED.gross_cents,
                discount_pct = EXCLUDED.discount_pct,
                discount_cents = EXCLUDED.discount_cents,
                net_cents = EXCLUDED.net_cents,
                tax_rate = EXCLUDED.tax_rate,
                tax_cents = EXCLUDED.tax_cents,
                total_cents = EXCLUDED.total_cents,
                active_subscriptions = EXCLUDED.active_subscriptions,
                pricing_version = EXCLUDED.pricing_version,
                unit_prices = EXCLUDED.unit_prices,
                breakdown = EXCLUDED.breakdown,
                created_at = NOW()
            RETURNING *
        """, _snapshot_params(snapshot))
    else:
        # Default — DO NOTHING on conflict (snapshot is immutable)
        cursor.execute("""
            INSERT INTO organization_billing_snapshots
                (organization_id, period_start, period_end, plan,
                 platform_fee_cents, subscription_total_cents, gross_cents,
                 discount_pct, discount_cents, net_cents,
                 tax_rate, tax_cents, total_cents,
                 active_subscriptions, pricing_version, unit_prices, breakdown)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (organization_id, period_start) DO NOTHING
            RETURNING *
        """, _snapshot_params(snapshot))

    row = cursor.fetchone()
    db._commit()

    if row is None and not force:
        # Conflict — return existing row
        cursor.execute("""
            SELECT * FROM organization_billing_snapshots
            WHERE organization_id = %s AND period_start = %s
        """, (snapshot['organization_id'], snapshot['period_start']))
        row = cursor.fetchone()

    cursor.close()

    if not row:
        return None

    result = dict(row)
    for k in ('period_start', 'period_end', 'created_at'):
        if result.get(k):
            result[k] = result[k].isoformat() if hasattr(result[k], 'isoformat') else str(result[k])
    for k in ('discount_pct', 'tax_rate'):
        if result.get(k) is not None:
            result[k] = float(result[k])
    return result


def _snapshot_params(snapshot):
    """Build param tuple for snapshot INSERT."""
    return (
        snapshot['organization_id'],
        snapshot['period_start'],
        snapshot['period_end'],
        snapshot['plan'],
        snapshot['platform_fee_cents'],
        snapshot['subscription_total_cents'],
        snapshot['gross_cents'],
        snapshot['discount_pct'],
        snapshot['discount_cents'],
        snapshot['net_cents'],
        snapshot['tax_rate'],
        snapshot['tax_cents'],
        snapshot['total_cents'],
        snapshot['active_subscriptions'],
        snapshot.get('pricing_version', PRICING_VERSION),
        json.dumps(snapshot.get('unit_prices', {})),
        json.dumps(snapshot['breakdown']),
    )


def get_current_estimated_bill(db, organization_id):
    """Compute the current month's estimated bill (live, not persisted).

    Returns the same shape as a snapshot but for the current partial month.
    """
    today = date.today()
    period_start = today.replace(day=1)
    # End of current month
    if today.month == 12:
        period_end = date(today.year + 1, 1, 1) - timedelta(days=1)
    else:
        period_end = date(today.year, today.month + 1, 1) - timedelta(days=1)

    snapshot = calculate_monthly_snapshot(db, organization_id, period_start, period_end)
    if snapshot:
        snapshot['is_estimate'] = True
        snapshot['estimated_at'] = datetime.now(timezone.utc).isoformat()
    return snapshot


def get_billing_history(db, organization_id, limit=12):
    """Fetch historical billing snapshots for an organization."""
    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT * FROM organization_billing_snapshots
        WHERE organization_id = %s
        ORDER BY period_start DESC
        LIMIT %s
    """, (organization_id, limit))
    rows = [dict(r) for r in cursor.fetchall()]
    cursor.close()
    for row in rows:
        for k in ('period_start', 'period_end', 'created_at'):
            if row.get(k):
                row[k] = row[k].isoformat() if hasattr(row[k], 'isoformat') else str(row[k])
        for k in ('discount_pct', 'tax_rate'):
            if row.get(k) is not None:
                row[k] = float(row[k])
    return rows


def get_billing_status(db, organization_id):
    """Return billing health summary for the organization."""
    from psycopg2.extras import RealDictCursor
    org = db.get_organization_by_id(organization_id)
    if not org:
        return None

    # Latest snapshot
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT id, period_start, period_end, total_cents, pricing_version, created_at
        FROM organization_billing_snapshots
        WHERE organization_id = %s
        ORDER BY period_start DESC LIMIT 1
    """, (organization_id,))
    latest_snapshot = cursor.fetchone()

    # Count invoice documents
    cursor.execute("""
        SELECT COUNT(*) as doc_count FROM invoice_documents WHERE organization_id = %s
    """, (organization_id,))
    doc_count = cursor.fetchone()['doc_count']

    # Count audit log entries
    cursor.execute("""
        SELECT COUNT(*) as audit_count FROM billing_audit_log WHERE organization_id = %s
    """, (organization_id,))
    audit_count = cursor.fetchone()['audit_count']

    cursor.close()

    result = {
        'organization_id': organization_id,
        'plan': org.get('plan', 'free'),
        'plan_status': org.get('plan_status', 'active'),
        'enforcement_mode': org.get('enforcement_mode', 'strict'),
        'current_pricing_version': PRICING_VERSION,
        'invoice_document_count': doc_count,
        'billing_audit_entries': audit_count,
        'latest_snapshot': None,
    }

    if latest_snapshot:
        snap = dict(latest_snapshot)
        for k in ('period_start', 'period_end', 'created_at'):
            if snap.get(k):
                snap[k] = snap[k].isoformat() if hasattr(snap[k], 'isoformat') else str(snap[k])
        result['latest_snapshot'] = snap

    return result


def generate_invoice_pdf(db, organization_id, snapshot_id=None, invoice_id=None, generated_by=None):
    """Generate a simple text-based invoice document and store in invoice_documents.

    Returns the document record dict (without file_data for response size).
    """
    from psycopg2.extras import RealDictCursor

    org = db.get_organization_by_id(organization_id)
    if not org:
        return None

    # Load snapshot or compute live
    snapshot = None
    if snapshot_id:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM organization_billing_snapshots WHERE id = %s AND organization_id = %s",
                        (snapshot_id, organization_id))
        snapshot = cursor.fetchone()
        cursor.close()
        if snapshot:
            snapshot = dict(snapshot)

    if not snapshot:
        snapshot = get_current_estimated_bill(db, organization_id)

    if not snapshot:
        return None

    # Build simple text invoice content
    org_name = org.get('billing_company') or org.get('name', 'Unknown')
    period = f"{snapshot.get('period_start', 'N/A')} to {snapshot.get('period_end', 'N/A')}"
    lines = [
        f"INVOICE — {org_name}",
        f"Period: {period}",
        f"Plan: {snapshot.get('plan', 'N/A')}",
        f"Pricing Version: {snapshot.get('pricing_version', PRICING_VERSION)}",
        "",
        "Line Items:",
    ]
    breakdown = snapshot.get('breakdown', {})
    if isinstance(breakdown, str):
        breakdown = json.loads(breakdown)
    for li in breakdown.get('line_items', []):
        amount = li.get('amount_cents', 0) / 100
        lines.append(f"  {li.get('label', 'Item')}: ${amount:,.2f}")

    lines.extend([
        "",
        f"Subtotal: ${snapshot.get('net_cents', 0) / 100:,.2f}",
        f"Tax: ${snapshot.get('tax_cents', 0) / 100:,.2f}",
        f"Total: ${snapshot.get('total_cents', 0) / 100:,.2f}",
    ])

    content = "\n".join(lines)
    file_data = content.encode('utf-8')
    file_name = f"invoice_{organization_id}_{snapshot.get('period_start', 'current')}.txt"

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        INSERT INTO invoice_documents
            (organization_id, invoice_id, snapshot_id, document_type, file_name,
             content_type, file_data, file_size, generated_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, organization_id, invoice_id, snapshot_id, document_type,
                  file_name, content_type, file_size, generated_by, generated_at, immutable
    """, (
        organization_id,
        invoice_id,
        snapshot_id if isinstance(snapshot_id, int) else snapshot.get('id'),
        'invoice',
        file_name,
        'text/plain',
        file_data,
        len(file_data),
        generated_by,
    ))
    doc = dict(cursor.fetchone())
    db._commit()
    cursor.close()

    if doc.get('generated_at'):
        doc['generated_at'] = doc['generated_at'].isoformat()

    # Audit log
    log_billing_audit(db, organization_id, 'invoice_document_generated',
                      actor_id=generated_by,
                      details={'document_id': doc.get('id'), 'file_name': file_name})

    return doc


def get_msp_aggregate_bill(db, msp_organization_id):
    """Compute aggregate billing across all MSP client organizations.

    Returns:
        dict with msp summary, per-client breakdown, and totals.
    """
    from psycopg2.extras import RealDictCursor

    # Get MSP org
    msp_org = db.get_organization_by_id(msp_organization_id)
    if not msp_org:
        return None

    # Get MSP client relationships
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT mr.*, o.name AS client_name, o.plan AS client_plan
        FROM msp_relationships mr
        JOIN organizations o ON o.id = mr.client_organization_id
        WHERE mr.msp_organization_id = %s AND mr.status = 'active'
        ORDER BY o.name
    """, (msp_organization_id,))
    relationships = [dict(r) for r in cursor.fetchall()]
    cursor.close()

    # Compute per-client billing
    clients = []
    total_gross = 0
    total_net = 0
    total_margin = 0

    for rel in relationships:
        client_id = rel['client_organization_id']
        client_estimate = get_current_estimated_bill(db, client_id)
        if not client_estimate:
            continue

        margin_pct = float(rel.get('margin_pct', 0))
        client_net = client_estimate.get('net_cents', 0)
        margin_cents = int(client_net * margin_pct / 100) if margin_pct > 0 else 0

        clients.append({
            'organization_id': client_id,
            'name': rel.get('client_name', ''),
            'plan': rel.get('client_plan', ''),
            'net_cents': client_net,
            'margin_pct': margin_pct,
            'margin_cents': margin_cents,
            'total_with_margin': client_net + margin_cents,
            'active_subscriptions': client_estimate.get('active_subscriptions', 0),
        })
        total_gross += client_net
        total_net += client_net + margin_cents
        total_margin += margin_cents

    return {
        'msp_organization_id': msp_organization_id,
        'msp_name': msp_org.get('name', ''),
        'client_count': len(clients),
        'clients': clients,
        'total_client_gross_cents': total_gross,
        'total_margin_cents': total_margin,
        'total_net_cents': total_net,
        'computed_at': datetime.now(timezone.utc).isoformat(),
    }
