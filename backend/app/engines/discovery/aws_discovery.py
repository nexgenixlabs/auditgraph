"""
AWS IAM Discovery Engine (Placeholder)

Discovers IAM users, roles, policies, and service accounts from AWS.
This is a foundation stub for future AWS integration.

Required AWS credentials:
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - AWS_REGION (default: us-east-1)

Required IAM permissions:
    - iam:ListUsers
    - iam:ListRoles
    - iam:ListPolicies
    - iam:GetUser
    - iam:GetRole
    - iam:ListAttachedUserPolicies
    - iam:ListAttachedRolePolicies
    - iam:GetAccessKeyLastUsed
"""

import os
from .base import BaseDiscoveryEngine
from .models import DiscoveryResult


class AWSDiscoveryEngine(BaseDiscoveryEngine):
    """AWS IAM identity discovery engine."""

    @property
    def cloud_provider(self) -> str:
        return "aws"

    def __init__(self):
        self.access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region = os.getenv("AWS_REGION", "us-east-1")

    def test_connection(self) -> bool:
        """Test AWS IAM connectivity."""
        if not self.access_key or not self.secret_key:
            return False
        # TODO: Implement boto3 STS get-caller-identity check
        return False

    def discover(self, run_id: int) -> DiscoveryResult:
        """
        Discover AWS IAM identities.

        Future implementation will discover:
        - IAM Users (with access keys, MFA status)
        - IAM Roles (with trust policies, attached policies)
        - Service-linked roles
        - IAM policies (with permission analysis)
        """
        raise NotImplementedError(
            "AWS discovery is not yet implemented. "
            "Configure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY "
            "environment variables and install boto3 to enable."
        )
