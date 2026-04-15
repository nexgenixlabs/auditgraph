"""
Fix Catalogue — Canonical definitions of remediation fix types.

Each fix type defines:
  - Applicable identity types
  - Execution safety level
  - Effort estimate
  - Framework badges (standards compliance impact)

Standards alignment:
  - CIS Controls v8  (§5.2, §5.3, §5.4)
  - NIST SP 800-207   (§2.1 blast radius, §3.3 least privilege)
  - NIST SP 800-63B   (credential rotation)
  - SOC 2 CC6.1/CC6.3 (access governance)
  - PCI-DSS 7.1       (role-based access control)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ── Enums ────────────────────────────────────────────────────────────

class FixType(str, Enum):
    ESTABLISH_OWNERSHIP = "ESTABLISH_OWNERSHIP"
    REVOKE_EXCESSIVE_ROLE = "REVOKE_EXCESSIVE_ROLE"
    REDUCE_SCOPE = "REDUCE_SCOPE"
    ROTATE_CREDENTIALS = "ROTATE_CREDENTIALS"
    ENABLE_PIM = "ENABLE_PIM"


class ExecutionSafety(str, Enum):
    SAFE = "Safe"
    CAUTION = "Caution"
    REQUIRES_MANUAL_REVIEW = "Requires Manual Review"


# ── Fix definition ───────────────────────────────────────────────────

@dataclass
class FixDefinition:
    """Static metadata for a fix type. No runtime state."""
    fix_type: FixType
    verb: str
    title: str
    execution_safety: str
    effort_minutes: int
    framework_badges: List[str] = field(default_factory=list)
    applicable_types: List[str] = field(default_factory=list)


# ── Catalogue ────────────────────────────────────────────────────────

FIX_CATALOGUE = {
    FixType.ESTABLISH_OWNERSHIP: FixDefinition(
        fix_type=FixType.ESTABLISH_OWNERSHIP,
        verb="ESTABLISH",
        title="Establish ownership for unowned identities",
        execution_safety=ExecutionSafety.SAFE.value,
        effort_minutes=15,
        framework_badges=["CIS v8 5.3", "SOC 2 CC6.1"],
        applicable_types=[
            "human_user", "service_principal",
            "managed_identity", "guest",
        ],
    ),
    FixType.REVOKE_EXCESSIVE_ROLE: FixDefinition(
        fix_type=FixType.REVOKE_EXCESSIVE_ROLE,
        verb="REVOKE",
        title="Revoke excessive privilege roles",
        execution_safety=ExecutionSafety.CAUTION.value,
        effort_minutes=30,
        framework_badges=["NIST 800-207", "PCI-DSS 7.1", "SOC 2"],
        applicable_types=[
            "human_user", "service_principal", "managed_identity",
        ],
    ),
    FixType.REDUCE_SCOPE: FixDefinition(
        fix_type=FixType.REDUCE_SCOPE,
        verb="REDUCE",
        title="Reduce role assignment scope",
        execution_safety=ExecutionSafety.CAUTION.value,
        effort_minutes=30,
        framework_badges=["NIST 800-207", "CIS v8 5.4"],
        applicable_types=[
            "service_principal", "managed_identity",
        ],
    ),
    FixType.ROTATE_CREDENTIALS: FixDefinition(
        fix_type=FixType.ROTATE_CREDENTIALS,
        verb="ROTATE",
        title="Rotate stale credentials",
        execution_safety=ExecutionSafety.CAUTION.value,
        effort_minutes=20,
        framework_badges=["CIS v8 5.2", "NIST 800-63B"],
        applicable_types=[
            "service_principal", "managed_identity",
        ],
    ),
    FixType.ENABLE_PIM: FixDefinition(
        fix_type=FixType.ENABLE_PIM,
        verb="ENABLE",
        title="Enable PIM for privileged roles",
        execution_safety=ExecutionSafety.SAFE.value,
        effort_minutes=60,
        framework_badges=["CIS v8 5.4", "SOC 2 CC6.3"],
        applicable_types=["human_user"],
    ),
}


# ── Privileged role names (shared by simulator + prioritizer) ────────

EXCESSIVE_ROLES = frozenset([
    "owner", "contributor", "user access administrator",
    "user access admin", "global administrator",
    "privileged role administrator",
])

WIDE_SCOPE_LEVELS = frozenset([
    "subscription", "management_group", "managementgroup", "tenant_wide",
])

NHI_TYPES = frozenset([
    "service_principal", "application", "managed_identity",
    "managed_identity_system", "managed_identity_user",
])
