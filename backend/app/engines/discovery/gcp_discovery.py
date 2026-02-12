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
from .models import DiscoveryResult, CloudIdentity, CloudRole, CloudCredential


# GCP privileged predefined roles
GCP_PRIVILEGED_ROLES = {
    'roles/owner',
    'roles/editor',
    'roles/iam.securityAdmin',
    'roles/iam.serviceAccountAdmin',
    'roles/iam.serviceAccountKeyAdmin',
    'roles/iam.organizationRoleAdmin',
    'roles/resourcemanager.organizationAdmin',
    'roles/resourcemanager.projectIamAdmin',
    'roles/cloudkms.admin',
    'roles/secretmanager.admin',
    'roles/compute.admin',
    'roles/storage.admin',
}

# GCP dangerous permissions
GCP_DANGEROUS_PERMISSIONS = {
    'iam.serviceAccountKeys.create',
    'iam.serviceAccounts.actAs',
    'iam.serviceAccounts.getAccessToken',
    'iam.serviceAccounts.signBlob',
    'iam.serviceAccounts.implicitDelegation',
    'resourcemanager.projects.setIamPolicy',
    'resourcemanager.organizations.setIamPolicy',
    'cloudkms.cryptoKeys.setIamPolicy',
    'storage.buckets.setIamPolicy',
    'compute.instances.setServiceAccount',
}


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

    def _normalize_service_account(self, sa_data: dict) -> CloudIdentity:
        """Convert GCP service account data to normalized CloudIdentity."""
        return CloudIdentity(
            provider='gcp',
            identity_type='service_account',
            display_name=sa_data.get('displayName', ''),
            external_id=sa_data.get('email', ''),
        )

    def _normalize_iam_member(self, member: str, role: str) -> CloudIdentity:
        """Convert GCP IAM binding member to normalized CloudIdentity."""
        # member format: user:email, serviceAccount:email, group:email
        parts = member.split(':', 1)
        member_type = parts[0] if len(parts) > 1 else 'unknown'
        member_id = parts[1] if len(parts) > 1 else member
        return CloudIdentity(
            provider='gcp',
            identity_type=member_type,
            display_name=member_id,
            external_id=member,
        )

    def _is_privileged_role(self, role: str) -> bool:
        """Check if a GCP role is considered privileged."""
        return role in GCP_PRIVILEGED_ROLES
