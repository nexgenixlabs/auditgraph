"""Integration tests for PIM Phase 2 dual-write paths.

Tests the contract between (a) discovery code passing data into
save_pim_eligible / save_pim_activation and (b) the new pim_eligibility_state
+ pim_activation_observations tables being populated correctly.

These tests use a FakeCursor — no Postgres required — so they run
deterministically in CI alongside the existing unit tests.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


# ──────────────────────────────────────────────────────────────────────
# Fake cursor + DB for testing the dual-write functions in isolation
# ──────────────────────────────────────────────────────────────────────

class _FakeCursor:
    """Records executed SQL + remembers fetchone() responses for assertions."""

    def __init__(self, identity_lookup_response=None):
        self.executed = []   # list of (sql, params) tuples
        self._identity_lookup_response = identity_lookup_response
        self._last_was_identity_lookup = False

    def execute(self, sql, params=None):
        self.executed.append((sql.strip(), params))
        self._last_was_identity_lookup = (
            'SELECT organization_id' in sql and 'FROM identities' in sql
        )

    def fetchone(self):
        if self._last_was_identity_lookup:
            return self._identity_lookup_response
        return None

    def close(self):
        pass


class _FakeDB:
    """Stub Database object with just enough surface for the dual-write helpers."""

    def __init__(self, cursor):
        self.conn = type('C', (), {'cursor': lambda self_inner: cursor})()


# ──────────────────────────────────────────────────────────────────────
# Stream A — eligibility dual-write with policy fields
# ──────────────────────────────────────────────────────────────────────

def test_dual_write_eligibility_uses_real_policy_values_when_provided():
    """When discovery passes parsed policy values, they reach pim_eligibility_state."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=(99, 'test-id', 42))
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_eligibility_state(
        fake_db, cursor, identity_db_id=100,
        data={
            'role_name': 'Security Administrator',
            'role_definition_id': 'role-def-id',
            'directory_scope': '/',
            'start_datetime': '2025-12-01T00:00:00+00:00',
            # ← Phase 2 fields ←
            'requires_mfa_on_activation': False,
            'requires_approval': True,
            'requires_justification': False,
            'max_activation_minutes': 720,
        },
    )

    # Find the INSERT into pim_eligibility_state
    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_eligibility_state' in sql
    ]
    assert len(insert_calls) == 1, "expected exactly 1 INSERT into pim_eligibility_state"
    sql, params = insert_calls[0]
    # params positions per the INSERT in database.py
    # (organization_id, discovery_run_id, identity_db_id, identity_id,
    #  role_name, role_template_id, scope, scope_type,
    #  eligible_since, requires_mfa, requires_approval,
    #  requires_justification, max_activation_minutes)
    assert params[0] == 99
    assert params[2] == 100
    assert params[4] == 'Security Administrator'
    # Policy values
    assert params[9] is False    # requires_mfa_on_activation
    assert params[10] is True    # requires_approval
    assert params[11] is False   # requires_justification
    assert params[12] == 720     # max_activation_minutes


def test_dual_write_eligibility_falls_back_to_safe_defaults_when_no_policy():
    """When discovery hasn't merged policy fields, Phase 1 safe defaults apply."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=(99, 'test-id', 42))
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_eligibility_state(
        fake_db, cursor, identity_db_id=100,
        data={
            'role_name': 'Application Administrator',
            'role_definition_id': 'role-def-id-app-admin',
            'directory_scope': '/',
            # No policy fields → defaults kick in
        },
    )

    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_eligibility_state' in sql
    ]
    assert len(insert_calls) == 1
    params = insert_calls[0][1]
    # Phase 1 safe defaults
    assert params[9] is True     # requires_mfa_on_activation (safe)
    assert params[10] is False   # requires_approval (default)
    assert params[11] is True    # requires_justification (safe)
    assert params[12] == 480     # max_activation_minutes (Azure 8h default)


def test_dual_write_eligibility_skips_when_identity_not_found():
    """Defensive: if the identity lookup fails, no INSERT runs."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=None)   # identity not found
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_eligibility_state(
        fake_db, cursor, identity_db_id=999, data={'role_name': 'Anything'},
    )
    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_eligibility_state' in sql
    ]
    assert len(insert_calls) == 0, "expected no INSERT when identity not found"


def test_dual_write_eligibility_scope_type_derivation():
    """scope_type derives correctly from directory_scope string."""
    from app.database import Database

    cases = [
        ('/',                                                                              'directory'),
        ('/subscriptions/abc-123',                                                          'subscription'),
        ('/subscriptions/abc-123/resourceGroups/rg-1',                                      'resource_group'),
        ('/subscriptions/abc-123/resourceGroups/rg-1/providers/Microsoft.Storage/sa1',      'resource'),
        ('/some/weird/scope',                                                               'other'),
    ]
    for scope, expected_type in cases:
        cursor = _FakeCursor(identity_lookup_response=(99, 'id', 42))
        fake_db = _FakeDB(cursor)
        Database._dual_write_pim_eligibility_state(
            fake_db, cursor, identity_db_id=100,
            data={'role_name': 'x', 'role_definition_id': 'x', 'directory_scope': scope},
        )
        params = next(p for s, p in cursor.executed if 'INSERT INTO pim_eligibility_state' in s)
        assert params[7] == expected_type, f"scope={scope!r} expected {expected_type!r}, got {params[7]!r}"


# ──────────────────────────────────────────────────────────────────────
# Stream B — activation observation dual-write
# ──────────────────────────────────────────────────────────────────────

def test_dual_write_activation_observation_skips_without_timestamp():
    """No activation_start AND no created_datetime → skip (no useful observation)."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=(99, 'test-id'))
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_activation_observation(
        fake_db, cursor, identity_db_id=100, data={'role_name': 'x'},
    )
    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_activation_observations' in sql
    ]
    assert len(insert_calls) == 0


def test_dual_write_activation_observation_uses_activation_start():
    """When activation_start is present, the row gets persisted."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=(99, 'test-id'))
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_activation_observation(
        fake_db, cursor, identity_db_id=100,
        data={
            'role_name': 'Security Administrator',
            'role_definition_id': 'role-sec-admin',
            'directory_scope': '/',
            'activation_start': '2026-06-01T10:00:00+00:00',
            'activation_end':   '2026-06-01T11:30:00+00:00',
            'justification':    'Investigating sign-in anomaly',
        },
    )
    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_activation_observations' in sql
    ]
    assert len(insert_calls) == 1
    params = insert_calls[0][1]
    # (org_id, identity_db_id, identity_id, role_name, role_template_id, scope,
    #  activated_at, activation_duration_minutes, justification, audit_event_id)
    assert params[0] == 99
    assert params[1] == 100
    assert params[3] == 'Security Administrator'
    assert params[6] == '2026-06-01T10:00:00+00:00'
    assert params[7] == 90       # 1h30m = 90 minutes
    assert params[8] == 'Investigating sign-in anomaly'
    # audit_event_id is the deterministic synthetic key
    assert params[9].startswith('pim-req:100:role-sec-admin:')


def test_dual_write_activation_observation_falls_back_to_created_datetime():
    """When activation_start is missing but created_datetime is present, use it."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=(99, 'test-id'))
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_activation_observation(
        fake_db, cursor, identity_db_id=100,
        data={
            'role_name': 'User Administrator',
            'role_definition_id': 'role-user-admin',
            'directory_scope': '/',
            # No activation_start
            'created_datetime': '2026-05-15T08:00:00+00:00',
        },
    )
    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_activation_observations' in sql
    ]
    assert len(insert_calls) == 1
    params = insert_calls[0][1]
    assert params[6] == '2026-05-15T08:00:00+00:00'
    assert params[7] is None     # no duration without end time


def test_dual_write_activation_observation_event_id_is_deterministic():
    """Same input data produces same audit_event_id (idempotent re-scans)."""
    from app.database import Database

    def _run():
        cursor = _FakeCursor(identity_lookup_response=(99, 'test-id'))
        fake_db = _FakeDB(cursor)
        Database._dual_write_pim_activation_observation(
            fake_db, cursor, identity_db_id=100,
            data={
                'role_name': 'GA',
                'role_definition_id': 'ga-def',
                'activation_start': '2026-06-01T00:00:00+00:00',
            },
        )
        params = next(
            p for s, p in cursor.executed
            if 'INSERT INTO pim_activation_observations' in s
        )
        return params[9]   # event_id

    assert _run() == _run(), "same input must produce same event_id"


def test_dual_write_activation_observation_skips_when_identity_not_found():
    """Defensive: identity lookup fails → no INSERT."""
    from app.database import Database

    cursor = _FakeCursor(identity_lookup_response=None)
    fake_db = _FakeDB(cursor)
    Database._dual_write_pim_activation_observation(
        fake_db, cursor, identity_db_id=999,
        data={'activation_start': '2026-06-01T00:00:00+00:00'},
    )
    insert_calls = [
        (sql, params) for sql, params in cursor.executed
        if 'INSERT INTO pim_activation_observations' in sql
    ]
    assert len(insert_calls) == 0
