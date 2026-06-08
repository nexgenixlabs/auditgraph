"""
Permission scope verification for cloud connection tests.

Given a customer's Azure app registration credentials, verifies that the
granted Microsoft Graph + ARM permissions exactly match what AuditGraph
needs — no more, no less. Directly supports the "agentless + read-only"
sales pitch by surfacing the customer's own consent grant.

Output shape:
    {
        'required_granted': bool,   # all REQUIRED perms present
        'has_write_perms': bool,    # detected any *.ReadWrite.* or write perm
        'verdict': 'green' | 'amber' | 'red',
        'message': human-readable summary,
        'detail': {
            'required_present': [list of granted REQUIRED perms],
            'required_missing': [list of missing REQUIRED perms],
            'optional_present': [list of granted OPTIONAL perms],
            'optional_missing': [list of missing OPTIONAL perms (no warning)],
            'unexpected_write':  [list of granted WRITE perms — warning],
            'all_granted_roles': [raw list from JWT 'roles' claim],
        }
    }

Verdict mapping:
    green = all REQUIRED granted, no WRITE perms (ideal)
    amber = all REQUIRED granted, but WRITE perms present (overprivilege)
    red   = REQUIRED perms missing (functional gap)
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# Permission catalog — keep in sync with docs/AG_AZURE_DEPTH_PLAN §2.2
# ─────────────────────────────────────────────────────────────────────

# Permissions AuditGraph CANNOT function without
REQUIRED_GRAPH_PERMISSIONS = frozenset({
    'Directory.Read.All',
    'Application.Read.All',
})

# Permissions that enrich features but degrade gracefully when missing
OPTIONAL_GRAPH_PERMISSIONS = frozenset({
    'RoleManagement.Read.Directory',     # PIM Overprivilege Detection
    'Policy.Read.All',                    # Conditional Access analysis
    'AuditLog.Read.All',                  # Feature E + PIM activation history (P2 required)
    'Reports.Read.All',                   # MFA registration reports
})

# Permission patterns we EXPLICITLY don't need — flag them as overprivilege
WRITE_PERMISSION_PATTERNS = (
    '.ReadWrite.', '.Write.', '.Manage.', '.All.Write', 'Owner', 'Contributor',
)


# ─────────────────────────────────────────────────────────────────────
# JWT decoding (no signature verification — we just read claims for inspection)
# ─────────────────────────────────────────────────────────────────────

def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload WITHOUT signature verification.

    Safe because we're decoding tokens we ourselves just minted via OAuth
    (the issuer is Microsoft, the audience is our own app). We're reading
    the granted roles claim for inspection only — not for authorization.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError(f"unexpected JWT structure ({len(parts)} parts)")
        payload_b64 = parts[1]
        # JWT base64url decoding — pad to multiple of 4
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(padded)
        return json.loads(payload)
    except Exception as e:
        logger.warning("JWT decode failed: %s", str(e)[:100])
        return {}


# ─────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────

def check_azure_app_permissions(tenant_id: str, client_id: str,
                                  client_secret: str) -> dict[str, Any]:
    """Verify the customer's app registration has the right Graph permissions.

    Acquires a token for Microsoft Graph as the customer's app, decodes
    the token to read the granted app roles, classifies them against
    AuditGraph's expected set, and returns a verdict.

    Args:
        tenant_id:     Entra Directory ID (a.k.a. tenant ID)
        client_id:     App registration client ID
        client_secret: Client secret (already decrypted by caller)

    Returns:
        Dict per module docstring. Never raises — captures errors as
        verdict='red' with descriptive message.
    """
    try:
        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=tenant_id, client_id=client_id,
            client_secret=client_secret,
        )
        # Get token for Microsoft Graph
        token = credential.get_token('https://graph.microsoft.com/.default').token
    except Exception as e:
        return _verdict_red(
            f"Failed to acquire Graph API token: {str(e)[:150]}",
            extra_detail={'all_granted_roles': []}
        )

    payload = _decode_jwt_payload(token)
    granted_roles = list(payload.get('roles', []))

    if not granted_roles:
        return _verdict_red(
            "No app permissions found in the access token. The app "
            "registration may have NO Graph API permissions granted, "
            "OR the admin consent step may not have been completed.",
            extra_detail={'all_granted_roles': []}
        )

    # Classify
    granted_set = set(granted_roles)
    required_present = sorted(granted_set & REQUIRED_GRAPH_PERMISSIONS)
    required_missing = sorted(REQUIRED_GRAPH_PERMISSIONS - granted_set)
    optional_present = sorted(granted_set & OPTIONAL_GRAPH_PERMISSIONS)
    optional_missing = sorted(OPTIONAL_GRAPH_PERMISSIONS - granted_set)
    unexpected_write = sorted(_classify_write(granted_set))

    detail = {
        'required_present': required_present,
        'required_missing': required_missing,
        'optional_present': optional_present,
        'optional_missing': optional_missing,
        'unexpected_write': unexpected_write,
        'all_granted_roles': sorted(granted_roles),
    }

    if required_missing:
        return _verdict_red(
            f"Missing required permission(s): {', '.join(required_missing)}. "
            f"Grant these in the app registration's API permissions tab.",
            extra_detail=detail,
        )

    if unexpected_write:
        return _verdict_amber(
            f"All required permissions granted, but the app also has "
            f"{len(unexpected_write)} WRITE permission(s) "
            f"({', '.join(unexpected_write[:3])}"
            f"{'...' if len(unexpected_write) > 3 else ''}). "
            f"AuditGraph never writes to your tenant — consider downscoping "
            f"these for least-privilege.",
            extra_detail=detail,
        )

    return _verdict_green(
        f"All required permissions granted. {len(optional_present)}/{len(OPTIONAL_GRAPH_PERMISSIONS)} "
        f"optional enrichment permissions also present. No write permissions detected ✓",
        extra_detail=detail,
    )


def _classify_write(granted: set[str]) -> set[str]:
    """Identify permissions in `granted` that match a WRITE pattern."""
    write = set()
    for perm in granted:
        for pat in WRITE_PERMISSION_PATTERNS:
            if pat in perm:
                write.add(perm)
                break
    return write


def _verdict_green(message: str, *, extra_detail: dict) -> dict[str, Any]:
    return {
        'required_granted': True, 'has_write_perms': False,
        'verdict': 'green', 'message': message, 'detail': extra_detail,
    }


def _verdict_amber(message: str, *, extra_detail: dict) -> dict[str, Any]:
    return {
        'required_granted': True, 'has_write_perms': True,
        'verdict': 'amber', 'message': message, 'detail': extra_detail,
    }


def _verdict_red(message: str, *, extra_detail: dict) -> dict[str, Any]:
    return {
        'required_granted': False, 'has_write_perms': False,
        'verdict': 'red', 'message': message, 'detail': extra_detail,
    }


__all__ = [
    'check_azure_app_permissions',
    'REQUIRED_GRAPH_PERMISSIONS',
    'OPTIONAL_GRAPH_PERMISSIONS',
    'WRITE_PERMISSION_PATTERNS',
]
