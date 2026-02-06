"""AuditGraph discovery engine package.

This package contains the production runtime modules used by the discovery scheduler.
Developer patch scripts must live under backend/tools/ (not imported at runtime).

Supported cloud providers:
    - Azure (production): AzureDiscoveryEngine
    - AWS (placeholder): AWSDiscoveryEngine
    - GCP (placeholder): GCPDiscoveryEngine
"""

from .azure_discovery import AzureDiscoveryEngine
from .aws_discovery import AWSDiscoveryEngine
from .gcp_discovery import GCPDiscoveryEngine
from .base import BaseDiscoveryEngine
from .models import (
    DiscoveryResult,
    Identity,
    IdentityCategory,
    IdentityType,
    RiskLevel,
    RoleAssignment,
)

__all__ = [
    "BaseDiscoveryEngine",
    "AzureDiscoveryEngine",
    "AWSDiscoveryEngine",
    "GCPDiscoveryEngine",
    "DiscoveryResult",
    "Identity",
    "IdentityCategory",
    "IdentityType",
    "RiskLevel",
    "RoleAssignment",
]
