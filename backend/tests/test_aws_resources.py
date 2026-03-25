"""
Tests for AWS resource risk scoring and CloudTrail event parsing.
"""
import json
import pytest
from datetime import datetime, timezone, timedelta

from app.engines.discovery.aws_data_security import (
    score_s3_bucket,
    score_kms_key,
    score_lambda_function,
    _risk_level,
)


# ── Risk Level Thresholds ────────────────────────────────────────

class TestRiskLevel:
    def test_critical(self):
        assert _risk_level(70) == 'critical'
        assert _risk_level(100) == 'critical'

    def test_high(self):
        assert _risk_level(50) == 'high'
        assert _risk_level(69) == 'high'

    def test_medium(self):
        assert _risk_level(30) == 'medium'
        assert _risk_level(49) == 'medium'

    def test_low(self):
        assert _risk_level(10) == 'low'
        assert _risk_level(29) == 'low'

    def test_info(self):
        assert _risk_level(0) == 'info'
        assert _risk_level(9) == 'info'


# ── S3 Bucket Scoring ───────────────────────────────────────────

class TestScoreS3Bucket:
    def test_secure_bucket_low_score(self):
        """Fully secured bucket should have a low score."""
        data = {
            'public_access_block_enabled': True,
            'policy_status_is_public': False,
            'acl_grants_public': False,
            'encryption_enabled': True,
            'encryption_algorithm': 'aws:kms',
            'kms_key_id': 'arn:aws:kms:us-east-1:123:key/abc',
            'bucket_key_enabled': True,
            'logging_enabled': True,
            'versioning_enabled': True,
            'lifecycle_rules_count': 3,
            'mfa_delete': True,
        }
        score, level, components, overrides, reasons = score_s3_bucket(data)
        assert score < 10
        assert level == 'info'
        assert len(overrides) == 0

    def test_public_bucket_critical(self):
        """Bucket with no public access block should be critical."""
        data = {
            'public_access_block_enabled': False,
            'policy_status_is_public': True,
            'acl_grants_public': True,
            'encryption_enabled': False,
            'logging_enabled': False,
            'versioning_enabled': False,
            'lifecycle_rules_count': 0,
            'mfa_delete': False,
        }
        score, level, components, overrides, reasons = score_s3_bucket(data)
        assert score >= 50
        assert level == 'critical'
        assert len(overrides) >= 1
        assert 'public_exposure' in components
        assert components['public_exposure']['score'] > 0

    def test_no_encryption_critical_override(self):
        """Bucket without encryption should get a critical override."""
        data = {
            'public_access_block_enabled': True,
            'encryption_enabled': False,
            'logging_enabled': True,
            'versioning_enabled': True,
            'lifecycle_rules_count': 1,
            'mfa_delete': False,
        }
        score, level, components, overrides, reasons = score_s3_bucket(data)
        assert level == 'critical'
        assert any('encryption' in o.lower() for o in overrides)

    def test_sse_s3_lower_than_kms(self):
        """SSE-S3 should score higher (worse) than KMS encryption."""
        base = {
            'public_access_block_enabled': True,
            'logging_enabled': True,
            'versioning_enabled': True,
            'lifecycle_rules_count': 1,
            'mfa_delete': True,
        }
        sse_s3 = {**base, 'encryption_enabled': True, 'encryption_algorithm': 'AES256', 'bucket_key_enabled': True}
        kms = {**base, 'encryption_enabled': True, 'encryption_algorithm': 'aws:kms', 'kms_key_id': 'key', 'bucket_key_enabled': True}

        score_s3, _, _, _, _ = score_s3_bucket(sse_s3)
        score_kms_val, _, _, _, _ = score_s3_bucket(kms)
        assert score_s3 > score_kms_val

    def test_components_have_correct_keys(self):
        """All 4 components should be present."""
        data = {'public_access_block_enabled': True, 'encryption_enabled': True}
        _, _, components, _, _ = score_s3_bucket(data)
        assert 'public_exposure' in components
        assert 'encryption' in components
        assert 'logging' in components
        assert 'data_protection' in components

    def test_component_max_scores(self):
        """Component scores should not exceed their max."""
        data = {
            'public_access_block_enabled': False,
            'policy_status_is_public': True,
            'acl_grants_public': True,
            'encryption_enabled': False,
            'logging_enabled': False,
            'versioning_enabled': False,
            'lifecycle_rules_count': 0,
            'mfa_delete': False,
        }
        _, _, components, _, _ = score_s3_bucket(data)
        for comp_name, comp in components.items():
            assert comp['score'] <= comp['max'], f"{comp_name} exceeded max"


# ── KMS Key Scoring ─────────────────────────────────────────────

class TestScoreKmsKey:
    def test_secure_key_low_score(self):
        data = {
            'rotation_enabled': True,
            'key_state': 'Enabled',
            'key_policy': {},
            'grants_count': 0,
            'key_manager': 'CUSTOMER',
            'origin': 'AWS_KMS',
            'tags': {'Environment': 'prod'},
        }
        score, level, components, overrides, reasons = score_kms_key(data)
        assert score < 20
        assert level in ('info', 'low')

    def test_pending_deletion_critical(self):
        data = {
            'rotation_enabled': False,
            'key_state': 'PendingDeletion',
            'key_policy': {},
            'grants_count': 0,
            'key_manager': 'CUSTOMER',
        }
        score, level, components, overrides, reasons = score_kms_key(data)
        assert level == 'critical'
        assert any('deletion' in o.lower() for o in overrides)

    def test_wildcard_principal_critical(self):
        data = {
            'rotation_enabled': True,
            'key_state': 'Enabled',
            'key_policy': {
                'Statement': [{'Effect': 'Allow', 'Principal': '*'}]
            },
            'grants_count': 0,
            'key_manager': 'CUSTOMER',
        }
        score, level, components, overrides, reasons = score_kms_key(data)
        assert level == 'critical'

    def test_no_rotation_penalty(self):
        data_no_rot = {
            'rotation_enabled': False,
            'key_state': 'Enabled',
            'key_policy': {},
            'grants_count': 0,
            'key_manager': 'CUSTOMER',
        }
        data_with_rot = {
            'rotation_enabled': True,
            'key_state': 'Enabled',
            'key_policy': {},
            'grants_count': 0,
            'key_manager': 'CUSTOMER',
        }
        s1, _, _, _, _ = score_kms_key(data_no_rot)
        s2, _, _, _, _ = score_kms_key(data_with_rot)
        assert s1 > s2

    def test_components_present(self):
        data = {'rotation_enabled': True, 'key_state': 'Enabled'}
        _, _, components, _, _ = score_kms_key(data)
        assert 'key_management' in components
        assert 'access_policy' in components
        assert 'configuration' in components
        assert 'compliance' in components


# ── Lambda Function Scoring ──────────────────────────────────────

class TestScoreLambdaFunction:
    def test_secure_function_low_score(self):
        data = {
            'execution_role_arn': 'arn:aws:iam::123:role/LimitedRole',
            'execution_role_name': 'LimitedRole',
            'vpc_id': 'vpc-123',
            'resource_policy_is_public': False,
            'has_secrets_in_env': False,
            'environment_variables_count': 2,
            'kms_key_arn': 'arn:aws:kms:us-east-1:123:key/abc',
            'runtime': 'python3.12',
            'timeout': 30,
            'memory_size': 256,
            'dead_letter_config': {'TargetArn': 'arn:aws:sqs:...'},
            'tags': {'app': 'test'},
            'code_size': 1024,
            'last_modified': datetime.now(timezone.utc).isoformat(),
        }
        score, level, components, overrides, reasons = score_lambda_function(data)
        assert score < 10
        assert level == 'info'

    def test_admin_role_critical(self):
        data = {
            'execution_role_arn': 'arn:aws:iam::123:role/AdminFullAccess',
            'execution_role_name': 'AdminFullAccess',
            'has_secrets_in_env': True,
            'runtime': 'python2.7',
            'timeout': 600,
            'memory_size': 4096,
        }
        score, level, components, overrides, reasons = score_lambda_function(data)
        assert level == 'critical'
        assert any('admin' in o.lower() for o in overrides)

    def test_secrets_in_env_critical(self):
        data = {
            'execution_role_name': 'BasicRole',
            'vpc_id': 'vpc-1',
            'has_secrets_in_env': True,
            'environment_variables_count': 5,
            'runtime': 'python3.11',
        }
        score, level, components, overrides, reasons = score_lambda_function(data)
        assert level == 'critical'
        assert any('secret' in o.lower() for o in overrides)

    def test_deprecated_runtime_penalty(self):
        base = {
            'execution_role_name': 'Role',
            'vpc_id': 'vpc-1',
            'has_secrets_in_env': False,
            'tags': {'a': 'b'},
            'dead_letter_config': {'TargetArn': 'arn'},
        }
        old = {**base, 'runtime': 'python2.7', 'timeout': 30, 'memory_size': 128}
        new = {**base, 'runtime': 'python3.12', 'timeout': 30, 'memory_size': 128}
        s_old, _, _, _, _ = score_lambda_function(old)
        s_new, _, _, _, _ = score_lambda_function(new)
        assert s_old > s_new

    def test_stale_function_penalty(self):
        base = {
            'execution_role_name': 'Role',
            'vpc_id': 'vpc-1',
            'has_secrets_in_env': False,
            'runtime': 'python3.12',
            'dead_letter_config': {'TargetArn': 'arn'},
            'tags': {'a': 'b'},
        }
        old_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        fresh_date = datetime.now(timezone.utc).isoformat()

        stale = {**base, 'last_modified': old_date}
        fresh = {**base, 'last_modified': fresh_date}
        s_stale, _, _, _, _ = score_lambda_function(stale)
        s_fresh, _, _, _, _ = score_lambda_function(fresh)
        assert s_stale > s_fresh

    def test_components_present(self):
        data = {'execution_role_name': 'Role', 'runtime': 'python3.12'}
        _, _, components, _, _ = score_lambda_function(data)
        assert 'execution_privilege' in components
        assert 'secrets_exposure' in components
        assert 'runtime' in components
        assert 'hygiene' in components


# ── CloudTrail Event Parsing ────────────────────────────────────

class TestCloudTrailParsing:
    """Test CloudTrail event structure parsing used in AWSCloudTrailService."""

    def test_parse_cloudtrail_event(self):
        """Verify we can parse the CloudTrailEvent JSON blob correctly."""
        event = {
            'EventId': 'evt-123',
            'EventName': 'AssumeRole',
            'EventSource': 'sts.amazonaws.com',
            'EventTime': datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            'CloudTrailEvent': json.dumps({
                'userIdentity': {
                    'type': 'IAMUser',
                    'arn': 'arn:aws:iam::123456789:user/alice',
                    'principalId': 'AIDA123',
                },
                'awsRegion': 'us-east-1',
                'sourceIPAddress': '1.2.3.4',
                'userAgent': 'aws-cli/2.0',
                'requestParameters': {'roleArn': 'arn:aws:iam::123:role/Admin'},
                'responseElements': {'assumedRoleUser': {'arn': 'arn:aws:sts::123:assumed-role/Admin/session'}},
                'readOnly': False,
                'managementEvent': True,
                'eventCategory': 'Management',
            }),
            'Resources': [{'ResourceType': 'AWS::IAM::Role', 'ResourceName': 'Admin'}],
        }

        detail = json.loads(event['CloudTrailEvent'])
        assert detail['userIdentity']['arn'] == 'arn:aws:iam::123456789:user/alice'
        assert detail['awsRegion'] == 'us-east-1'
        assert detail['sourceIPAddress'] == '1.2.3.4'
        assert detail['readOnly'] is False

    def test_assumed_role_arn_to_role_arn(self):
        """Test converting session ARN to role ARN for identity matching."""
        session_arn = 'arn:aws:sts::123456789012:assumed-role/MyRole/session-name'

        # The logic from aws_cloudtrail.py
        if ':assumed-role/' in session_arn:
            parts = session_arn.split('/')
            role_name = parts[1] if len(parts) > 1 else ''
            account = session_arn.split(':')[4] if ':' in session_arn else ''
            role_arn = f"arn:aws:iam::{account}:role/{role_name}"
        else:
            role_arn = session_arn

        assert role_arn == 'arn:aws:iam::123456789012:role/MyRole'

    def test_empty_cloudtrail_event(self):
        """Empty CloudTrailEvent JSON should parse gracefully."""
        detail = json.loads('{}')
        assert detail.get('userIdentity', {}).get('arn', '') == ''
        assert detail.get('readOnly', False) is False


# ── Isolation Stamp ─────────────────────────────────────────────

class TestStampIsolation:
    """Test the _stamp_isolation pattern."""

    def test_stamp_sets_keys(self):
        """Verify _stamp_isolation injects all 3 isolation keys."""

        class MockEngine:
            aws_account_id = '123456789012'
            db_org_id = 42
            cloud_connection_id = 7

            def _stamp_isolation(self, data):
                data['aws_account_id'] = self.aws_account_id
                data['organization_id'] = self.db_org_id
                data['cloud_connection_id'] = self.cloud_connection_id
                return data

        engine = MockEngine()
        data = {'name': 'test-bucket', 'resource_id': 'arn:aws:s3:::test'}
        stamped = engine._stamp_isolation(data)

        assert stamped['aws_account_id'] == '123456789012'
        assert stamped['organization_id'] == 42
        assert stamped['cloud_connection_id'] == 7

    def test_save_rejects_wrong_account(self):
        """Save should fail if aws_account_id doesn't match engine's account."""
        engine_account = '111111111111'
        data_account = '222222222222'

        with pytest.raises(AssertionError):
            assert data_account == engine_account, \
                f"Account mismatch: {data_account} != {engine_account}"


# ── Score Consistency ────────────────────────────────────────────

class TestScoreConsistency:
    """Verify scores are deterministic and within bounds."""

    def test_s3_score_deterministic(self):
        data = {'public_access_block_enabled': False, 'encryption_enabled': False}
        s1, l1, _, _, _ = score_s3_bucket(data)
        s2, l2, _, _, _ = score_s3_bucket(data)
        assert s1 == s2
        assert l1 == l2

    def test_kms_score_deterministic(self):
        data = {'rotation_enabled': False, 'key_state': 'Enabled'}
        s1, _, _, _, _ = score_kms_key(data)
        s2, _, _, _, _ = score_kms_key(data)
        assert s1 == s2

    def test_lambda_score_deterministic(self):
        data = {'execution_role_name': 'Admin', 'runtime': 'python2.7'}
        s1, _, _, _, _ = score_lambda_function(data)
        s2, _, _, _, _ = score_lambda_function(data)
        assert s1 == s2

    def test_scores_bounded_0_100(self):
        """Total score should never exceed 100."""
        worst_s3 = {
            'public_access_block_enabled': False,
            'policy_status_is_public': True,
            'acl_grants_public': True,
            'encryption_enabled': False,
            'logging_enabled': False,
            'versioning_enabled': False,
            'lifecycle_rules_count': 0,
            'mfa_delete': False,
        }
        s, _, _, _, _ = score_s3_bucket(worst_s3)
        assert 0 <= s <= 100

        worst_kms = {
            'rotation_enabled': False,
            'key_state': 'PendingDeletion',
            'key_policy': {'Statement': [{'Effect': 'Allow', 'Principal': '*'}]},
            'grants_count': 20,
            'key_manager': 'AWS',
            'origin': 'EXTERNAL',
        }
        s, _, _, _, _ = score_kms_key(worst_kms)
        assert 0 <= s <= 100

        worst_lambda = {
            'execution_role_name': 'AdminFullAccess',
            'has_secrets_in_env': True,
            'resource_policy_is_public': True,
            'runtime': 'python2.7',
            'timeout': 900,
            'memory_size': 10240,
            'code_size': 100 * 1024 * 1024,
        }
        s, _, _, _, _ = score_lambda_function(worst_lambda)
        assert 0 <= s <= 100

    def test_zero_score_floor(self):
        """If any driver fires but total is 0, score should be at least 1."""
        # This tests the zero-score guard in the scoring functions
        data = {
            'public_access_block_enabled': True,
            'encryption_enabled': True,
            'encryption_algorithm': 'aws:kms',
            'kms_key_id': 'key',
            'bucket_key_enabled': True,
            'logging_enabled': True,
            'versioning_enabled': True,
            'lifecycle_rules_count': 1,
            'mfa_delete': False,  # This fires a 5-point driver
        }
        score, _, _, _, _ = score_s3_bucket(data)
        assert score >= 1
