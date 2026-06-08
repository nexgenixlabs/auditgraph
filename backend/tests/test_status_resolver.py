"""Tests for app/engines/status_resolver.py — the canonical identity status
resolver. Single source of truth for identity status computation.

Goal: 100% coverage of this small + frequently-called module.
"""
from __future__ import annotations

from app.engines.status_resolver import resolve_status


def test_deleted_at_set_returns_deleted():
    assert resolve_status({'deleted_at': '2026-01-01T00:00:00Z'}) == 'deleted'

def test_deleted_at_set_overrides_enabled_true():
    """Priority: deleted_at wins over enabled."""
    assert resolve_status({'deleted_at': '2026-01-01T00:00:00Z',
                            'enabled': True}) == 'deleted'

def test_enabled_false_returns_disabled():
    assert resolve_status({'enabled': False}) == 'disabled'

def test_enabled_true_returns_active():
    assert resolve_status({'enabled': True}) == 'active'

def test_enabled_true_overrides_status_column():
    """Priority: enabled bool wins over status string fallback."""
    assert resolve_status({'enabled': True, 'status': 'disabled'}) == 'active'

def test_status_fallback_active():
    """When enabled is None and status column says 'active', use it."""
    assert resolve_status({'status': 'active'}) == 'active'

def test_status_fallback_disabled():
    assert resolve_status({'status': 'disabled'}) == 'disabled'

def test_status_fallback_deleted_string():
    assert resolve_status({'status': 'deleted'}) == 'deleted'

def test_unknown_status_returns_unknown():
    """Status string outside the allow-list → unknown, not the raw value."""
    assert resolve_status({'status': 'pending'}) == 'unknown'

def test_empty_dict_returns_unknown():
    assert resolve_status({}) == 'unknown'

def test_missing_all_signals_returns_unknown():
    """deleted_at is None, enabled is None, status is None or missing."""
    assert resolve_status({'deleted_at': None, 'enabled': None}) == 'unknown'

def test_deleted_at_none_explicit():
    """Explicit None for deleted_at + enabled=True → active."""
    assert resolve_status({'deleted_at': None, 'enabled': True}) == 'active'
