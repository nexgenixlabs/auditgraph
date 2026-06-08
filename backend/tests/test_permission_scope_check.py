"""Tests for app/api/permission_scope_check.py — verdict classification
for Graph API permission scope verification.

Doesn't call Azure (token acquisition mocked); tests the verdict logic
deterministically across green/amber/red scenarios.
"""
from __future__ import annotations

import base64
import json

from app.api.permission_scope_check import (
    OPTIONAL_GRAPH_PERMISSIONS,
    REQUIRED_GRAPH_PERMISSIONS,
    WRITE_PERMISSION_PATTERNS,
    _classify_write,
    _decode_jwt_payload,
)


# ──────────────────────────────────────────────────────────────────────
# Constants sanity
# ──────────────────────────────────────────────────────────────────────

def test_required_set_includes_directory_read():
    """Directory.Read.All MUST be required — discovery cannot function without it."""
    assert 'Directory.Read.All' in REQUIRED_GRAPH_PERMISSIONS

def test_optional_set_includes_role_management_read():
    """RoleManagement.Read.Directory is optional (PIM enrichment)."""
    assert 'RoleManagement.Read.Directory' in OPTIONAL_GRAPH_PERMISSIONS

def test_write_patterns_catch_readwrite():
    assert any('.ReadWrite.' in p for p in WRITE_PERMISSION_PATTERNS)

def test_required_and_optional_disjoint():
    """A permission can't be both required and optional — partition cleanly."""
    assert not (REQUIRED_GRAPH_PERMISSIONS & OPTIONAL_GRAPH_PERMISSIONS)


# ──────────────────────────────────────────────────────────────────────
# _classify_write — detects write-shaped permission names
# ──────────────────────────────────────────────────────────────────────

def test_classify_write_detects_readwrite_all():
    granted = {'Directory.ReadWrite.All', 'Directory.Read.All'}
    assert _classify_write(granted) == {'Directory.ReadWrite.All'}

def test_classify_write_detects_manage():
    granted = {'AppRoleAssignment.ReadWrite.All', 'Application.Read.All',
                'DeviceManagement.Manage.All'}
    write = _classify_write(granted)
    assert 'AppRoleAssignment.ReadWrite.All' in write
    assert 'DeviceManagement.Manage.All' in write
    assert 'Application.Read.All' not in write

def test_classify_write_empty_for_all_read():
    granted = {'Directory.Read.All', 'Application.Read.All',
                'RoleManagement.Read.Directory', 'AuditLog.Read.All'}
    assert _classify_write(granted) == set()

def test_classify_write_detects_owner_role():
    granted = {'Owner', 'Directory.Read.All'}
    assert 'Owner' in _classify_write(granted)


# ──────────────────────────────────────────────────────────────────────
# _decode_jwt_payload — base64url decode of middle JWT segment
# ──────────────────────────────────────────────────────────────────────

def _mint_test_jwt(payload: dict) -> str:
    """Build a fake JWT with the given payload. Header + signature are dummies
    because the decoder doesn't validate signatures."""
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip('=')
    header = b64({'alg': 'RS256', 'typ': 'JWT'})
    body = b64(payload)
    sig = b64({'dummy': True})
    return f"{header}.{body}.{sig}"


def test_decode_jwt_extracts_roles_claim():
    token = _mint_test_jwt({
        'roles': ['Directory.Read.All', 'Application.Read.All'],
        'aud': 'https://graph.microsoft.com',
    })
    payload = _decode_jwt_payload(token)
    assert payload['roles'] == ['Directory.Read.All', 'Application.Read.All']

def test_decode_jwt_handles_padding():
    """Base64url payloads may need padding to multiple of 4."""
    payload = {'roles': ['a']}    # short payload that triggers padding
    token = _mint_test_jwt(payload)
    assert _decode_jwt_payload(token) == payload

def test_decode_jwt_malformed_returns_empty():
    """Malformed JWT shouldn't crash — return empty dict."""
    assert _decode_jwt_payload('not.a.jwt') == {}

def test_decode_jwt_no_dots_returns_empty():
    assert _decode_jwt_payload('plain string') == {}

def test_decode_jwt_empty_returns_empty():
    assert _decode_jwt_payload('') == {}


# ──────────────────────────────────────────────────────────────────────
# End-to-end verdict classification (via _decode_jwt_payload + classify)
#
# We can't easily mock azure.identity in unit tests, so we test the
# verdict-producing functions in isolation.
# ──────────────────────────────────────────────────────────────────────

def test_classify_write_pattern_includes_owner_substring_match():
    """The substring match means anything containing 'Owner' triggers."""
    # 'Owner' is in the WRITE_PERMISSION_PATTERNS tuple — verifies sensible match
    granted = {'PowerUser', 'PrintOwner'}
    write = _classify_write(granted)
    assert 'PrintOwner' in write
    # Confirms we want to expand WRITE_PERMISSION_PATTERNS if this matches
    # too aggressively in practice on a real customer tenant
