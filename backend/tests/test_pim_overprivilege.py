"""
Tests for app/engines/pim/pim_overprivilege.py — the PIM Overprivilege
Detection engine shipped 2026-06-07.

Validates the deterministic finding-emission logic against synthetic
input rows that map cleanly to each of the 3 finding types:
  - pim_unused_eligibility
  - pim_low_frequency_activation
  - pim_weak_activation_control
plus a healthy persona that must produce NO findings.

Uses an in-process FakeDB (no Postgres needed) so the tests run in CI
without external services.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from app.engines.pim.pim_overprivilege import (
    CRITICAL_ROLES,
    compute_pim_overprivilege,
    _severity_low_freq,
    _severity_unused,
    _severity_weak_mfa,
)


NOW = datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────────
# Fake DB stub matching what compute_pim_overprivilege calls
# ──────────────────────────────────────────────────────────────────────

class _FakeCursor:
    def __init__(self, eligibility_rows, activation_rows):
        self._eligibility = eligibility_rows
        self._activations = activation_rows
        self._last_query_kind = None

    def execute(self, query, params=None):
        if 'pim_eligibility_state' in query:
            self._last_query_kind = 'eligibility'
        elif 'pim_activation_observations' in query:
            self._last_query_kind = 'activations'

    def fetchall(self):
        if self._last_query_kind == 'eligibility':
            return self._eligibility
        if self._last_query_kind == 'activations':
            return self._activations
        return []

    def close(self):
        pass


class _FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
    def cursor(self):
        return self._cursor


class _FakeDB:
    def __init__(self, eligibility_rows, activation_rows):
        self.conn = _FakeConn(_FakeCursor(eligibility_rows, activation_rows))


def _eligibility_row(identity_db_id, identity_id, display_name, role_name,
                      assignment_type='eligible', eligible_days_ago=200,
                      requires_mfa=True, requires_approval=False,
                      requires_justification=True, max_activation_minutes=480,
                      scope='/', scope_type='directory'):
    """Build a tuple matching what compute_pim_overprivilege() unpacks."""
    eligible_since = NOW - timedelta(days=eligible_days_ago)
    return (
        identity_db_id, identity_id, display_name,
        role_name, '00000000-template-id',
        scope, scope_type,
        assignment_type, eligible_since,
        requires_mfa, requires_approval,
        requires_justification, max_activation_minutes,
        'human_user',
    )


def _activation_row(identity_db_id, role_name, days_ago, scope=None):
    activated_at = NOW - timedelta(days=days_ago)
    return (identity_db_id, role_name, scope, activated_at)


# ──────────────────────────────────────────────────────────────────────
# Severity matrix tests
# ──────────────────────────────────────────────────────────────────────

def test_severity_unused_critical_role_long_dormancy_is_critical():
    assert _severity_unused('Global Administrator', 400) == 'critical'

def test_severity_unused_critical_role_short_dormancy_is_high():
    assert _severity_unused('Global Administrator', 200) == 'high'

def test_severity_unused_non_critical_role_is_lower():
    assert _severity_unused('Some Custom Role', 100) == 'medium'

def test_severity_low_freq_critical_zero_activations():
    assert _severity_low_freq('Global Administrator', 0) == 'high'

def test_severity_low_freq_non_critical_some_activations():
    assert _severity_low_freq('Some Custom Role', 1) == 'low'

def test_severity_weak_mfa_critical_role():
    assert _severity_weak_mfa('Security Administrator') == 'critical'

def test_critical_roles_includes_expected_set():
    # Sanity: the moat depends on this list being comprehensive
    for r in ['Global Administrator', 'Security Administrator',
              'User Administrator', 'Privileged Role Administrator']:
        assert r in CRITICAL_ROLES, f"{r} missing from CRITICAL_ROLES"


# ──────────────────────────────────────────────────────────────────────
# End-to-end: feed the engine synthetic rows, assert classifier output
# ──────────────────────────────────────────────────────────────────────

def test_unused_eligibility_finding_for_dormant_global_admin():
    """Eligible for 400 days, never activated → critical pim_unused_eligibility."""
    rows = [_eligibility_row(1, 'dormant-ga', 'Dormant GA',
                              'Global Administrator', eligible_days_ago=400)]
    activations = []
    db = _FakeDB(rows, activations)
    out = compute_pim_overprivilege(db, org_id=99)

    assert out['summary']['total_eligible_assignments'] == 1
    assert out['summary']['total_findings'] == 1

    finding = out['findings'][0]
    assert finding['finding_type'] == 'pim_unused_eligibility'
    assert finding['severity'] == 'critical'
    assert finding['identity_id'] == 'dormant-ga'
    assert 'never activated' in finding['title'].lower()


def test_low_frequency_finding_with_one_old_activation():
    """One activation 95d ago, no recent → pim_low_frequency_activation."""
    rows = [_eligibility_row(2, 'rare-ua', 'Rare UA',
                              'User Administrator', eligible_days_ago=200)]
    activations = [_activation_row(2, 'User Administrator', days_ago=95)]
    db = _FakeDB(rows, activations)
    out = compute_pim_overprivilege(db, org_id=99)

    assert out['summary']['total_findings'] == 1
    finding = out['findings'][0]
    assert finding['finding_type'] == 'pim_low_frequency_activation'
    assert finding['severity'] in ('high', 'medium')
    assert finding['evidence']['activations_90d'] == 0  # 95d is outside 90d window
    assert finding['evidence']['days_since_last'] == 95


def test_weak_activation_control_finding_for_critical_role_without_mfa():
    """Active Security Admin with no-MFA activation policy → critical finding.

    To isolate the weak-MFA finding from the low-frequency finding, seed
    enough activations (>= LOW_FREQUENCY_THRESHOLD=2 within 90 days) so the
    low-freq detector stays silent and only the MFA detector fires.
    """
    rows = [_eligibility_row(3, 'weak-sec', 'Weak Sec',
                              'Security Administrator',
                              eligible_days_ago=180,
                              requires_mfa=False)]
    activations = [
        _activation_row(3, 'Security Administrator', days_ago=7),
        _activation_row(3, 'Security Administrator', days_ago=30),
        _activation_row(3, 'Security Administrator', days_ago=60),
    ]
    db = _FakeDB(rows, activations)
    out = compute_pim_overprivilege(db, org_id=99)

    assert out['summary']['total_findings'] == 1
    finding = out['findings'][0]
    assert finding['finding_type'] == 'pim_weak_activation_control'
    assert finding['severity'] == 'critical'
    assert finding['evidence']['requires_mfa_on_activation'] is False


def test_healthy_active_admin_produces_no_finding():
    """5 recent activations + MFA required → no finding."""
    rows = [_eligibility_row(4, 'active-app', 'Active App',
                              'Application Administrator',
                              eligible_days_ago=300,
                              requires_mfa=True, requires_approval=True)]
    activations = [_activation_row(4, 'Application Administrator', days_ago=d)
                   for d in (2, 9, 16, 23, 30)]
    db = _FakeDB(rows, activations)
    out = compute_pim_overprivilege(db, org_id=99)

    assert out['summary']['total_findings'] == 0
    assert out['identities'][0]['classification'] == 'healthy_active'


def test_weak_mfa_compounds_with_other_findings():
    """An eligible role can produce BOTH a low-frequency + weak-MFA finding."""
    rows = [_eligibility_row(5, 'weak-rare', 'Weak Rare User Admin',
                              'User Administrator',
                              eligible_days_ago=200,
                              requires_mfa=False)]
    activations = [_activation_row(5, 'User Administrator', days_ago=120)]
    db = _FakeDB(rows, activations)
    out = compute_pim_overprivilege(db, org_id=99)

    types = {f['finding_type'] for f in out['findings']}
    assert 'pim_low_frequency_activation' in types
    assert 'pim_weak_activation_control' in types


def test_severity_filter_works():
    """severity_filter=high excludes critical findings."""
    rows = [
        _eligibility_row(1, 'ga', 'GA', 'Global Administrator',
                         eligible_days_ago=400),                  # critical
        _eligibility_row(2, 'ua', 'UA', 'User Administrator',
                         eligible_days_ago=200),                  # high (no activations)
    ]
    db = _FakeDB(rows, [])
    out = compute_pim_overprivilege(db, org_id=99, severity_filter='high')

    assert all(f['severity'] == 'high' for f in out['findings'])


def test_identity_filter_works():
    """identity_filter substring matches identity_id or display_name."""
    rows = [
        _eligibility_row(1, 'global-admin-1', 'GA One', 'Global Administrator',
                         eligible_days_ago=400),
        _eligibility_row(2, 'user-admin-1', 'UA One', 'User Administrator',
                         eligible_days_ago=400),
    ]
    db = _FakeDB(rows, [])
    out = compute_pim_overprivilege(db, org_id=99, identity_filter='user-admin')

    assert len(out['identities']) == 1
    assert out['identities'][0]['identity_id'] == 'user-admin-1'


def test_findings_are_severity_sorted():
    """Critical findings come before high; ties broken by identity_id."""
    rows = [
        _eligibility_row(1, 'b-ua', 'B UA', 'User Administrator',
                         eligible_days_ago=200),                  # high
        _eligibility_row(2, 'a-ga', 'A GA', 'Global Administrator',
                         eligible_days_ago=400),                  # critical
    ]
    db = _FakeDB(rows, [])
    out = compute_pim_overprivilege(db, org_id=99)

    assert out['findings'][0]['severity'] == 'critical'
    assert out['findings'][1]['severity'] == 'high'


def test_summary_counts_match_findings():
    """summary.by_finding_type + by_severity reconcile with findings list."""
    rows = [
        _eligibility_row(1, 'dormant-ga', 'GA', 'Global Administrator',
                         eligible_days_ago=400),
        _eligibility_row(2, 'weak-sec', 'Sec', 'Security Administrator',
                         eligible_days_ago=100, requires_mfa=False),
    ]
    activations = [_activation_row(2, 'Security Administrator', days_ago=7)]
    db = _FakeDB(rows, activations)
    out = compute_pim_overprivilege(db, org_id=99)

    assert sum(out['summary']['by_finding_type'].values()) == out['summary']['total_findings']
    assert sum(out['summary']['by_severity'].values()) == out['summary']['total_findings']
