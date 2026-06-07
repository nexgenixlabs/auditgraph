"""
Tests for app/engines/entra/role_activity_inference.py — Feature E Phase 2.

Validates the bucketing functions + the dormant-role finding emitter against
synthetic rows. Uses an in-process FakeDB.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.engines.entra.role_activity_inference import (
    CATEGORIES_REQUIRING,
    _activity_bucket,
    _dormancy_band,
    compute_entra_role_activity,
)

NOW = datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────────
# Categories mapping — the patent-track moat
# ──────────────────────────────────────────────────────────────────────

def test_categories_mapping_covers_8_required_roles():
    """At least these 8 most common directory roles must have category attribution."""
    required = [
        'Global Administrator',
        'Privileged Role Administrator',
        'User Administrator',
        'Application Administrator',
        'Cloud Application Administrator',
        'Conditional Access Administrator',
        'Security Administrator',
        'Billing Administrator',
    ]
    for r in required:
        assert r in CATEGORIES_REQUIRING, f"{r} missing from CATEGORIES_REQUIRING"
        assert len(CATEGORIES_REQUIRING[r]) > 0, f"{r} has empty category set"


def test_global_admin_covers_all_categories():
    """Global Admin has broadest reach — must include UserManagement at minimum."""
    cats = CATEGORIES_REQUIRING['Global Administrator']
    for must in ['UserManagement', 'GroupManagement', 'ApplicationManagement',
                 'Policy', 'RoleManagement']:
        assert must in cats, f"GA must include {must}"


def test_conditional_access_admin_covers_ca_specific_categories():
    """CA Admin must cover ConditionalAccess at minimum."""
    cats = CATEGORIES_REQUIRING['Conditional Access Administrator']
    assert 'ConditionalAccess' in cats or 'Policy' in cats


# ──────────────────────────────────────────────────────────────────────
# Bucketing functions
# ──────────────────────────────────────────────────────────────────────

def test_activity_bucket_daily():
    assert _activity_bucket(28, 84) == 'daily'

def test_activity_bucket_weekly():
    assert _activity_bucket(10, 30) == 'weekly'

def test_activity_bucket_monthly():
    assert _activity_bucket(2, 5) == 'monthly'

def test_activity_bucket_rare():
    assert _activity_bucket(0, 1) == 'rare'

def test_activity_bucket_dormant_for_zero():
    assert _activity_bucket(0, 0) == 'dormant'

def test_dormancy_band_high_at_90_days():
    assert _dormancy_band(90) == 'high'
    assert _dormancy_band(120) == 'high'

def test_dormancy_band_medium_30_to_89():
    assert _dormancy_band(30) == 'medium'
    assert _dormancy_band(89) == 'medium'

def test_dormancy_band_low_under_30():
    assert _dormancy_band(0) == 'low'
    assert _dormancy_band(29) == 'low'

def test_dormancy_band_unknown_for_none():
    """None = no audit data → unknown band, not fabricated."""
    assert _dormancy_band(None) == 'unknown'


# ──────────────────────────────────────────────────────────────────────
# End-to-end with FakeDB
# ──────────────────────────────────────────────────────────────────────

class _FakeCursor:
    def __init__(self, rows): self._rows = rows
    def execute(self, *a, **k): pass
    def fetchall(self): return self._rows
    def close(self): pass

class _FakeConn:
    def __init__(self, cursor): self._cursor = cursor
    def cursor(self): return self._cursor

class _FakeDB:
    def __init__(self, rows): self.conn = _FakeConn(_FakeCursor(rows))


def _row(identity_db_id, identity_id, display_name, role_name,
         days_since_last, activities_30d, activities_90d, bucket, band,
         confidence='observed'):
    last_action = NOW - timedelta(days=days_since_last) if days_since_last is not None else None
    return (
        identity_db_id, identity_id, display_name, 'human_user',
        role_name, '00000000-template',
        last_action, days_since_last,
        activities_30d, activities_90d,
        bucket, band,
        'auditLogs', confidence,
    )


def test_dormant_global_admin_produces_critical_finding():
    rows = [_row(1, 'dormant-ga', 'Dormant GA', 'Global Administrator',
                  days_since_last=120, activities_30d=0, activities_90d=0,
                  bucket='dormant', band='high')]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99)

    assert out['summary']['total_assignments'] == 1
    assert out['summary']['total_findings'] == 1
    f = out['findings'][0]
    assert f['finding_type'] == 'dormant_directory_role_assignment'
    assert f['severity'] == 'critical'   # GA is in the critical-severity list
    assert f['evidence']['days_since_last_action'] == 120


def test_active_user_admin_produces_no_finding():
    """Daily-bucket User Admin with low dormancy → no finding."""
    rows = [_row(2, 'active-ua', 'Active UA', 'User Administrator',
                  days_since_last=3, activities_30d=28, activities_90d=84,
                  bucket='daily', band='low')]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99)

    assert out['summary']['total_findings'] == 0


def test_dormancy_filter_excludes_other_bands():
    rows = [
        _row(1, 'dormant-ga', 'GA', 'Global Administrator',
             120, 0, 0, 'dormant', 'high'),
        _row(2, 'active-ua', 'UA', 'User Administrator',
             3, 28, 84, 'daily', 'low'),
    ]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99,
                                        dormancy_filter='high')
    assert len(out['rows']) == 1
    assert out['rows'][0]['dormancy_band'] == 'high'


def test_dormant_non_privileged_role_does_not_produce_finding():
    """Roles outside CATEGORIES_REQUIRING (custom roles, unknowns) don't fire findings."""
    rows = [_row(1, 'custom-1', 'Custom Role User', 'Some Custom Role',
                  days_since_last=120, activities_30d=0, activities_90d=0,
                  bucket='dormant', band='high')]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99)

    # Row appears in the rollup but no finding — we only flag KNOWN privileged roles
    assert out['summary']['total_assignments'] == 1
    assert out['summary']['total_findings'] == 0


def test_dormant_role_with_unknown_confidence_does_not_fire():
    """When inference_confidence='unknown' (P2-less tenant), no finding fires.

    This is the moat compliance check — we don't fabricate findings on
    tenants where we can't actually observe activity.
    """
    rows = [_row(1, 'unsure-ga', 'GA', 'Global Administrator',
                  days_since_last=120, activities_30d=0, activities_90d=0,
                  bucket='dormant', band='high',
                  confidence='unknown')]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99)

    assert out['summary']['total_findings'] == 0


def test_findings_sorted_critical_first():
    rows = [
        _row(1, 'b-app', 'B App', 'Application Administrator',  # high
             120, 0, 0, 'dormant', 'high'),
        _row(2, 'a-ga', 'A GA', 'Global Administrator',          # critical
             120, 0, 0, 'dormant', 'high'),
    ]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99)
    assert out['findings'][0]['severity'] == 'critical'


def test_summary_buckets_count_correctly():
    rows = [
        _row(1, 'ga',  'GA',  'Global Administrator',     120, 0, 0,  'dormant', 'high'),
        _row(2, 'ua',  'UA',  'User Administrator',        3,  28,84, 'daily',   'low'),
        _row(3, 'ca',  'CA',  'Conditional Access Administrator',
             14, 3, 5, 'monthly', 'low'),
    ]
    out = compute_entra_role_activity(_FakeDB(rows), org_id=99)

    assert out['summary']['total_assignments'] == 3
    assert out['summary']['by_dormancy']['high'] == 1
    assert out['summary']['by_dormancy']['low'] == 2
    assert out['summary']['by_bucket']['dormant'] == 1
    assert out['summary']['by_bucket']['daily'] == 1
    assert out['summary']['by_bucket']['monthly'] == 1
