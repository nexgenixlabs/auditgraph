"""
Enum Alias Map — Single Source of Truth
========================================

Consolidates all ``_safe_enum`` and ``_safe_identity_type`` logic that was
previously scattered across ``identity_profile_builder.py`` and
``identities.py``. Every builder and route handler should import the
helpers below instead of defining inline ``_safe_enum()`` copies.

The definitive audit (E8 Part 2) confirmed the following DB-to-enum
mappings. Any value NOT listed here that reaches a ``_safe_enum`` call
is a latent 500 — add its alias here if a new writer begins emitting it.

Enum Case Convention
--------------------
Some enums use Title case canonical values (``RiskLabel.CRITICAL = "Critical"``)
while DB rows, query params, and legacy writers may emit lowercase
(``"critical"``). These enums carry ``_CaseInsensitiveMixin`` in
``schemas/identity.py`` so that ``RiskLabel("critical")`` resolves to
``RiskLabel.CRITICAL`` without needing explicit aliases.

Identity Type Aliases
---------------------
Legacy discovery engine (``azure_discovery.py``) writes
``identity_category`` values that differ from Phase 3 ``IdentityType``.
The ``IDENTITY_TYPE_ALIASES`` dict maps every known legacy value to
its Phase 3 canonical member.

Definitive Value Map
--------------------
+------------------------+---------------------------------------------+
| Enum                   | DB / API values (all accepted)              |
+========================+=============================================+
| IdentityType           | human_user, guest_user, service_principal,  |
|                        | managed_identity, app_registration, ai_agent|
|                        | *aliases*: user, guest, servicePrincipal,   |
|                        | managed_identity_system,                    |
|                        | managed_identity_user, microsoft_internal   |
+------------------------+---------------------------------------------+
| CloudProvider          | azure, aws, gcp                             |
+------------------------+---------------------------------------------+
| RiskLabel              | Critical, High, Medium, Low, Info           |
|                        | (case-insensitive via _CaseInsensitiveMixin)|
+------------------------+---------------------------------------------+
| GovernanceClassification| Governed, Ungoverned, Orphaned,            |
|                        | PolicyViolation                             |
|                        | (case/underscore-insensitive via _missing_) |
+------------------------+---------------------------------------------+
| LifecycleState         | Active, Dormant, Provisioned, Disabled,     |
|                        | Expired                                     |
|                        | (case-insensitive via _CaseInsensitiveMixin)|
+------------------------+---------------------------------------------+
| PrivilegeLevel         | highly_privileged, privileged, standard     |
+------------------------+---------------------------------------------+
| IdentitySource         | azure_ad, aws_iam, gcp_iam                  |
+------------------------+---------------------------------------------+
| IdentityStatus         | Active, Disabled, Expired, Provisioned      |
|                        | (case-insensitive via _CaseInsensitiveMixin)|
+------------------------+---------------------------------------------+
| Confidence             | high, medium, low, inferred, none           |
+------------------------+---------------------------------------------+
| BuilderDataSource      | none, partial, full, stale                  |
+------------------------+---------------------------------------------+
| ScopeBreadth           | tenant_wide, subscription, resource_group,  |
|                        | resource                                    |
+------------------------+---------------------------------------------+
| OwnerQuality           | active_owner, inactive_owner, no_owner      |
+------------------------+---------------------------------------------+
| RotationStatus         | current, expiring_soon, expired,            |
|                        | no_credentials                              |
+------------------------+---------------------------------------------+
| RoleSource             | azure_rbac, aws_iam, aws_scp, gcp_iam,     |
|                        | gcp_org_policy                              |
+------------------------+---------------------------------------------+
| ResourceType           | key_vault, storage, database, secret,       |
|                        | iam_system, certificate_store               |
+------------------------+---------------------------------------------+
| SensitivityLevel       | Critical, High, Medium, Low                 |
|                        | (case-insensitive via _CaseInsensitiveMixin)|
+------------------------+---------------------------------------------+
| SimulationType (Literal)| ROLE_REMOVAL, PRIVILEGE_REDUCTION,          |
|                        | OWNERSHIP_ASSIGNMENT                        |
+------------------------+---------------------------------------------+
"""

from __future__ import annotations

import logging
from typing import TypeVar

from app.schemas.identity import (
    CloudProvider,
    Confidence,
    GovernanceClassification,
    IdentitySource,
    IdentityStatus,
    IdentityType,
    LifecycleState,
    PrivilegeLevel,
    RiskLabel,
    ScopeBreadth,
)


logger = logging.getLogger(__name__)

_T = TypeVar("_T")


# ---------------------------------------------------------------------------
# Identity type alias map  (legacy identity_category → Phase 3 IdentityType)
# ---------------------------------------------------------------------------

IDENTITY_TYPE_ALIASES: dict[str, IdentityType] = {
    # Graph API / legacy discovery values
    "user":                     IdentityType.HUMAN_USER,
    "guest":                    IdentityType.GUEST_USER,
    "servicePrincipal":         IdentityType.SERVICE_PRINCIPAL,
    "managed_identity_system":  IdentityType.MANAGED_IDENTITY,
    "managed_identity_user":    IdentityType.MANAGED_IDENTITY,
    "microsoft_internal":       IdentityType.SERVICE_PRINCIPAL,
}


# ---------------------------------------------------------------------------
# Consolidated safe-enum helpers
# ---------------------------------------------------------------------------


def safe_enum(enum_cls: type[_T], raw: object, default: _T) -> _T:
    """Return ``enum_cls(raw)`` or *default* if *raw* is not a valid member.

    Works with any ``(str, Enum)`` class. Enums that carry
    ``_CaseInsensitiveMixin`` will resolve case-insensitive matches
    automatically via their ``_missing_`` classmethod.
    """
    try:
        return enum_cls(raw)  # type: ignore[call-arg]
    except (ValueError, KeyError):
        logger.warning("enum_aliases: unknown %s value %r, defaulting to %s",
                       getattr(enum_cls, "__name__", enum_cls), raw, default)
        return default


def safe_identity_type(raw: str) -> IdentityType:
    """Resolve ``identity_type`` with alias fallback.

    Tries the canonical enum first, then checks ``IDENTITY_TYPE_ALIASES``
    for legacy discovery values. Falls back to ``SERVICE_PRINCIPAL`` if
    no match is found.
    """
    try:
        return IdentityType(raw)
    except (ValueError, KeyError):
        alias = IDENTITY_TYPE_ALIASES.get(raw)
        if alias is not None:
            return alias
        logger.warning(
            "enum_aliases: unknown identity_type %r, "
            "defaulting to SERVICE_PRINCIPAL",
            raw,
        )
        return IdentityType.SERVICE_PRINCIPAL


__all__ = [
    "IDENTITY_TYPE_ALIASES",
    "safe_enum",
    "safe_identity_type",
]
