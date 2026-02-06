"""
Base discovery engine interface for multi-cloud support.

All cloud-specific engines (Azure, AWS, GCP) should inherit from this base class
to ensure a consistent discovery interface.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from .models import DiscoveryResult


class BaseDiscoveryEngine(ABC):
    """Abstract base class for cloud identity discovery engines."""

    @property
    @abstractmethod
    def cloud_provider(self) -> str:
        """Return the cloud provider identifier (azure, aws, gcp)."""
        ...

    @abstractmethod
    def discover(self, run_id: int) -> DiscoveryResult:
        """
        Run identity discovery for this cloud provider.

        Args:
            run_id: The discovery run ID to associate results with.

        Returns:
            DiscoveryResult containing discovered identities and metadata.
        """
        ...

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connectivity to the cloud provider.

        Returns:
            True if connection is successful, False otherwise.
        """
        ...
