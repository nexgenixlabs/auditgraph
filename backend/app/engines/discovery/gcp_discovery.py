"""
GCP IAM Discovery Engine (Placeholder)

Discovers IAM members, service accounts, and roles from Google Cloud.
This is a foundation stub for future GCP integration.

Required credentials:
    - GOOGLE_APPLICATION_CREDENTIALS (path to service account JSON)
    - GCP_PROJECT_ID

Required IAM permissions:
    - resourcemanager.projects.getIamPolicy
    - iam.serviceAccounts.list
    - iam.serviceAccountKeys.list
    - iam.roles.list
"""

import os
from .base import BaseDiscoveryEngine
from .models import DiscoveryResult


class GCPDiscoveryEngine(BaseDiscoveryEngine):
    """Google Cloud IAM identity discovery engine."""

    @property
    def cloud_provider(self) -> str:
        return "gcp"

    def __init__(self):
        self.credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        self.project_id = os.getenv("GCP_PROJECT_ID")

    def test_connection(self) -> bool:
        """Test GCP IAM connectivity."""
        if not self.credentials_path or not self.project_id:
            return False
        # TODO: Implement google-cloud-iam client check
        return False

    def discover(self, run_id: int) -> DiscoveryResult:
        """
        Discover GCP IAM identities.

        Future implementation will discover:
        - Service accounts (with key rotation status)
        - IAM members (users, groups, domains)
        - Custom roles (with permission analysis)
        - Workload identity bindings
        """
        raise NotImplementedError(
            "GCP discovery is not yet implemented. "
            "Configure GOOGLE_APPLICATION_CREDENTIALS and GCP_PROJECT_ID "
            "environment variables and install google-cloud-iam to enable."
        )
