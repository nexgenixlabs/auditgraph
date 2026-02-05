"""AuditGraph discovery engine package.

This package contains the production runtime modules used by the discovery scheduler.
Developer patch scripts must live under backend/tools/ (not imported at runtime).
"""

from .azure_discovery import AzureDiscoveryEngine
from .models import (
    DiscoveryResult,
    Identity,
    IdentityCategory,
    IdentityType,
    RiskLevel,
    RoleAssignment,
)

__all__ = [
    "AzureDiscoveryEngine",
    "DiscoveryResult",
    "Identity",
    "IdentityCategory",
    "IdentityType",
    "RiskLevel",
    "RoleAssignment",
]
