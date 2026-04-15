"""AuditGraph discovery engine package.

This package contains the production runtime modules used by the discovery scheduler.
Developer patch scripts must live under backend/tools/ (not imported at runtime).

Cloud engine imports are gated by APP_ENV to avoid hard dependencies on
cloud SDKs (azure-*, boto3, google-cloud-*) in local development.

Supported cloud providers:
    - Azure (production): AzureDiscoveryEngine
    - AWS (production):   AWSDiscoveryEngine
    - GCP (placeholder):  GCPDiscoveryEngine
"""

from app.config import AZURE_DISCOVERY_ENABLED, AWS_DISCOVERY_ENABLED, GCP_DISCOVERY_ENABLED

if AZURE_DISCOVERY_ENABLED:
    from .azure_discovery import AzureDiscoveryEngine
else:
    AzureDiscoveryEngine = None

if AWS_DISCOVERY_ENABLED:
    from .aws_discovery import AWSDiscoveryEngine
else:
    AWSDiscoveryEngine = None

if GCP_DISCOVERY_ENABLED:
    from .gcp_discovery import GCPDiscoveryEngine
else:
    GCPDiscoveryEngine = None

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
    "DiscoveryResult",
    "Identity",
    "IdentityCategory",
    "IdentityType",
    "RiskLevel",
    "RoleAssignment",
]

if AZURE_DISCOVERY_ENABLED:
    __all__.append("AzureDiscoveryEngine")
if AWS_DISCOVERY_ENABLED:
    __all__.append("AWSDiscoveryEngine")
if GCP_DISCOVERY_ENABLED:
    __all__.append("GCPDiscoveryEngine")
