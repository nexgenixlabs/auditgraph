"""Phase 3B: Billing Transparency & Invoice Engine tests.

Mock-based + source inspection (no live DB required).
"""

import json
import re
from unittest.mock import MagicMock, patch
from datetime import date, datetime, timezone, timedelta
from decimal import Decimal

import pytest


# ── Helper: mock org dict ─────────────────────────────────────────────────

def _mock_org(plan='pro', discount_pct=0, platform_fee_cents=20000, **kwargs):
    return {
        'id': 1,
        'name': 'Test Org',
        'plan': plan,
        'plan_type': 'self_serve',
        'discount_pct': discount_pct,
        'platform_fee_cents': platform_fee_cents,
        'tax_rate': 0,
        'tax_exempt': False,
        'tax_label': 'Tax',
        'billing_company': 'Test Corp',
        **kwargs,
    }


def _mock_subs(count=3, cloud='azure', rate_cents=6900):
    return [
        {'id': i, 'cloud': cloud, 'monitored': True, 'rate_cents': rate_cents}
        for i in range(1, count + 1)
    ]


# ── Test 1: Snapshot calculation correct ───────────────────────────────────

def test_snapshot_calculation_correct():
    """calculate_monthly_snapshot should produce correct totals."""
    from app.billing.service import calculate_monthly_snapshot

    mock_db = MagicMock()
    mock_db.get_organization_by_id.return_value = _mock_org(plan='pro', platform_fee_cents=20000)
    mock_db.get_cloud_subscriptions.return_value = _mock_subs(count=3, rate_cents=6900)

    snapshot = calculate_monthly_snapshot(mock_db, 1)
    assert snapshot is not None
    assert snapshot['plan'] == 'pro'
    assert snapshot['platform_fee_cents'] == 20000
    assert snapshot['subscription_total_cents'] == 6900 * 3  # 20700
    assert snapshot['gross_cents'] == 20000 + 20700  # 40700
    assert snapshot['net_cents'] == 40700  # No discount
    assert snapshot['active_subscriptions'] == 3
    assert 'breakdown' in snapshot
    assert 'line_items' in snapshot['breakdown']


# ── Test 2: Discount applied correctly ─────────────────────────────────────

def test_discount_applied():
    """Discount percentage should reduce net_cents."""
    from app.billing.service import calculate_monthly_snapshot

    mock_db = MagicMock()
    mock_db.get_organization_by_id.return_value = _mock_org(
        plan='enterprise', platform_fee_cents=50000, discount_pct=15
    )
    mock_db.get_cloud_subscriptions.return_value = _mock_subs(count=2, rate_cents=7900)

    snapshot = calculate_monthly_snapshot(mock_db, 1)
    gross = 50000 + (7900 * 2)  # 65800
    expected_discount = int(gross * 15 / 100)  # 9870
    expected_net = gross - expected_discount  # 55930

    assert snapshot['gross_cents'] == gross
    assert snapshot['discount_cents'] == expected_discount
    assert snapshot['net_cents'] == expected_net


# ── Test 3: MSP aggregate correct ─────────────────────────────────────────

def test_msp_aggregate_correct():
    """get_msp_aggregate_bill should sum across all MSP clients with margin."""
    from app.billing.service import get_msp_aggregate_bill

    mock_db = MagicMock()
    # MSP org
    mock_db.get_organization_by_id.side_effect = lambda oid: {
        10: {'id': 10, 'name': 'MSP Corp', 'plan': 'enterprise'},
        20: {'id': 20, 'name': 'Client A', 'plan': 'pro', 'platform_fee_cents': 20000,
             'discount_pct': 0, 'tax_rate': 0, 'tax_exempt': False, 'tax_label': 'Tax'},
        30: {'id': 30, 'name': 'Client B', 'plan': 'pro', 'platform_fee_cents': 20000,
             'discount_pct': 0, 'tax_rate': 0, 'tax_exempt': False, 'tax_label': 'Tax'},
    }.get(oid)

    # Mock subscriptions per client
    mock_db.get_cloud_subscriptions.side_effect = lambda oid: (
        _mock_subs(count=2, rate_cents=6900) if oid == 20
        else _mock_subs(count=1, rate_cents=7900) if oid == 30
        else []
    )

    # MSP relationships
    from psycopg2.extras import RealDictCursor
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        {'client_organization_id': 20, 'client_name': 'Client A', 'client_plan': 'pro',
         'margin_pct': Decimal('10.00'), 'msp_organization_id': 10, 'status': 'active'},
        {'client_organization_id': 30, 'client_name': 'Client B', 'client_plan': 'pro',
         'margin_pct': Decimal('15.00'), 'msp_organization_id': 10, 'status': 'active'},
    ]
    mock_db.conn.cursor.return_value = mock_cursor

    result = get_msp_aggregate_bill(mock_db, 10)
    assert result is not None
    assert result['msp_organization_id'] == 10
    assert result['client_count'] == 2
    assert len(result['clients']) == 2
    assert result['total_client_gross_cents'] > 0
    assert result['total_margin_cents'] > 0
    assert result['total_net_cents'] == result['total_client_gross_cents'] + result['total_margin_cents']


# ── Test 4: Invoice immutable after generation ─────────────────────────────

def test_invoice_immutable_after_generation():
    """invoice_documents.immutable should default to true in schema."""
    import os
    db_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'database.py')
    with open(db_path) as f:
        source = f.read()

    # Check CREATE TABLE statement for invoice_documents has immutable BOOLEAN DEFAULT true
    assert 'invoice_documents' in source
    assert 'immutable BOOLEAN NOT NULL DEFAULT true' in source


# ── Test 5: Billing routes registered ──────────────────────────────────────

def test_billing_routes_registered():
    """All Phase 3B billing routes must be registered in main.py."""
    import os
    main_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'main.py')
    with open(main_path) as f:
        source = f.read()

    required_routes = [
        '/api/billing/current-estimate',
        '/api/billing/history',
        '/api/billing/invoice/',
        '/api/msp/billing/aggregate',
        '/api/admin/organizations/',  # admin snapshot + invoice-document
    ]
    for route in required_routes:
        assert route in source, f"Route {route} not found in main.py"


# ── Test 6: Scheduler job registered ──────────────────────────────────────

def test_scheduler_job_registered():
    """Monthly billing snapshot job should be registered in scheduler.py."""
    import os
    sched_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'scheduler.py')
    with open(sched_path) as f:
        source = f.read()

    assert 'monthly_billing_snapshots' in source
    assert 'run_monthly_billing_snapshots' in source
    assert 'day=1' in source  # Runs on 1st of month


# ── Test 7: store_billing_snapshot UPSERT ──────────────────────────────────

def test_store_billing_snapshot_upsert():
    """store_billing_snapshot should use ON CONFLICT for idempotent insert."""
    import os
    service_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'billing', 'service.py')
    with open(service_path) as f:
        source = f.read()

    assert 'ON CONFLICT' in source, "store_billing_snapshot must use UPSERT"
    assert 'organization_id, period_start' in source, "UPSERT key must be (org_id, period_start)"


# ── Test 8: Migration 021 creates all 3 tables ────────────────────────────

def test_migration_021_creates_tables():
    """Migration 021 must create billing_snapshots, msp_relationships, invoice_documents."""
    import os
    db_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'database.py')
    with open(db_path) as f:
        source = f.read()

    assert 'organization_billing_snapshots' in source
    assert 'msp_relationships' in source
    assert 'invoice_documents' in source
    assert '_migration_021_ensured' in source
