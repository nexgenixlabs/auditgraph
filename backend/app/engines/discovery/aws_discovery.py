"""
AWS IAM Discovery Engine

Discovers IAM users, roles, policies, and trust relationships from AWS.
Calculates risk scores using the V2 risk catalog and stores results in
the same identities table used by Azure discovery.

Also discovers AWS resources (S3, KMS, Lambda), Organizations accounts,
and CloudTrail events when feature flags are enabled.

Required IAM permissions:
    - iam:ListUsers, iam:GetUser, iam:ListAccessKeys, iam:GetAccessKeyLastUsed
    - iam:ListMFADevices, iam:GetLoginProfile
    - iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy
    - iam:ListGroupsForUser
    - iam:ListRoles, iam:GetRole
    - iam:ListAttachedRolePolicies, iam:ListRolePolicies, iam:GetRolePolicy
    - sts:GetCallerIdentity
    Optional (feature-flagged):
    - s3:ListBuckets, s3:GetBucket*, s3:GetEncryptionConfiguration
    - kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus, kms:GetKeyPolicy, kms:ListGrants
    - lambda:ListFunctions, lambda:GetPolicy
    - organizations:DescribeOrganization, organizations:ListAccounts
    - cloudtrail:LookupEvents
"""

import json
import logging
import re
from datetime import datetime, timezone, timedelta

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.database import Database
from app.engines.risk_catalog import RISK_FACTOR_CATALOG, make_factor, score_to_level_v2
from app.engines.discovery.aws_data_security import score_s3_bucket, score_kms_key, score_lambda_function

logger = logging.getLogger(__name__)

# AWS managed policy ARNs that map to specific risk factors
POLICY_RISK_MAP = {
    'arn:aws:iam::aws:policy/AdministratorAccess': 'AWS_ADMIN_POLICY',
    'arn:aws:iam::aws:policy/IAMFullAccess': 'AWS_IAM_FULL_ACCESS',
    'arn:aws:iam::aws:policy/PowerUserAccess': 'AWS_POWER_USER',
    'arn:aws:iam::aws:policy/SecurityAudit': 'AWS_SECURITY_AUDIT',
}

# Inline policy actions considered dangerous
DANGEROUS_ACTIONS = {
    '*', 'iam:*', 'iam:CreateUser', 'iam:AttachUserPolicy',
    'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy',
    'iam:CreateAccessKey', 'iam:PassRole', 'sts:AssumeRole',
    'organizations:*', 'kms:*', 'secretsmanager:GetSecretValue',
}


class AWSDiscoveryEngine:
    """AWS IAM identity discovery engine with full risk scoring."""

    @property
    def cloud_provider(self) -> str:
        return "aws"

    def __init__(self, access_key_id: str, secret_access_key: str,
                 region: str = 'us-east-1', db_org_id: int = None,
                 cloud_connection_id: int = None):
        if cloud_connection_id is None:
            raise ValueError("cloud_connection_id is required for discovery")
        if db_org_id is None:
            raise ValueError("db_org_id is required for discovery")

        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.db_org_id = db_org_id
        self.cloud_connection_id = cloud_connection_id

        self._retry_config = Config(retries={'max_attempts': 5, 'mode': 'adaptive'})
        self._session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region,
        )
        self.iam = self._session.client('iam', config=self._retry_config)
        self.sts = self._session.client('sts', config=self._retry_config)

        # Resolve account ID
        caller = self.sts.get_caller_identity()
        self.aws_account_id = caller['Account']

        self.db = Database(organization_id=db_org_id)
        self._identities = []

    def _update_job_progress(self, stage, progress, discovery_run_id=None):
        """Report progress to snapshot_jobs. Non-fatal on failure."""
        job_id = getattr(self, 'snapshot_job_id', None)
        if not job_id:
            return
        try:
            self.db.update_snapshot_job_progress(job_id, stage, progress, discovery_run_id)
        except Exception as e:
            logger.warning(f"  (job progress update failed: {e})")

    def test_connection(self) -> bool:
        """Test AWS connectivity via STS."""
        try:
            resp = self.sts.get_caller_identity()
            return bool(resp.get('Account'))
        except Exception:
            return False

    def run_discovery(self):
        """Main discovery entry point."""
        logger.info(f"AWS Discovery starting for account {self.aws_account_id}")

        run_id = self.db.create_discovery_run(
            subscription_id=self.aws_account_id,
            subscription_name=f'AWS Account {self.aws_account_id}',
            organization_id=self.db_org_id,
            cloud_connection_id=self.cloud_connection_id,
        )
        logger.info(f"  Created discovery run #{run_id}")
        self._update_job_progress('discovering_identities', 20, discovery_run_id=run_id)

        try:
            self._discover_iam_users()
            logger.info(f"  Discovered {sum(1 for i in self._identities if i.get('identity_category') == 'iam_user')} IAM users")

            self._discover_iam_roles()
            logger.info(f"  Discovered {sum(1 for i in self._identities if i.get('identity_category') in ('iam_role', 'iam_service_linked_role'))} IAM roles")
            self._update_job_progress('discovering_rbac', 60)

            self._calculate_risks()
            self._check_activity()

            counts = self._save_identities(run_id)
            self._update_job_progress('finalizing', 90)

            self.db.complete_discovery_run(
                run_id=run_id,
                total_identities=counts['total'],
                critical_count=counts['critical'],
                high_count=counts['high'],
                medium_count=counts['medium'],
                low_count=counts['low'],
            )

            self._sync_aws_account()

            # Feature-flagged: AWS resource scanning (S3/KMS/Lambda)
            try:
                if self.db.get_setting('aws_resource_scanning_enabled', 'false', self.db_org_id) == 'true':
                    self._discover_and_save_resources(run_id)
            except Exception as e:
                logger.warning(f"  AWS resource scanning failed (non-fatal): {e}")

            # Feature-flagged: AWS Organizations enumeration
            try:
                if self.db.get_setting('aws_organizations_enabled', 'false', self.db_org_id) == 'true':
                    self._discover_organizations()
            except Exception as e:
                logger.warning(f"  AWS Organizations discovery failed (non-fatal): {e}")

            # Feature-flagged: CloudTrail event ingestion
            try:
                if self.db.get_setting('aws_cloudtrail_enabled', 'false', self.db_org_id) == 'true':
                    self._ingest_cloudtrail(run_id)
            except Exception as e:
                logger.warning(f"  CloudTrail ingestion failed (non-fatal): {e}")

            # DEPRECATED: TS lineage subprocess disabled.
            # Lineage engine unified under Python to ensure consistency.
            # try:
            #     if self.db.get_setting('aws_lineage_enabled', 'false', self.db_org_id) == 'true':
            #         self._run_identity_lineage()
            # except Exception as e:
            #     logger.warning(f"  AWS Identity Lineage scan failed (non-fatal): {e}")

            logger.info(f"  AWS Discovery completed: {counts['total']} identities "
                        f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']} L:{counts['low']})")
        except Exception as e:
            logger.error(f"  AWS Discovery failed: {e}", exc_info=True)
            try:
                cursor = self.db.conn.cursor()
                cursor.execute(
                    "UPDATE discovery_runs SET status='failed', completed_at=%s WHERE id=%s",
                    (datetime.utcnow(), run_id))
                self.db._commit()
                cursor.close()
            except Exception:
                pass
            raise
        finally:
            self.db.close()

    # ── IAM User Discovery ───────────────────────────────────────────

    def _discover_iam_users(self):
        """Discover all IAM users with access keys, MFA, policies, groups."""
        paginator = self.iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                username = user['UserName']
                arn = user['Arn']
                created = user.get('CreateDate')

                identity = {
                    'identity_id': arn,
                    'display_name': username,
                    'identity_type': 'iam_user',
                    'identity_category': 'iam_user',
                    'source': 'aws_iam',
                    'cloud': 'aws',
                    'principal_id': arn,
                    'tenant_or_org_id': self.aws_account_id,
                    'created_datetime': created.isoformat() if created else None,
                    'enabled': True,
                    'is_microsoft_system': False,
                    'tags': {
                        'aws_account_id': self.aws_account_id,
                        'arn': arn,
                        'path': user.get('Path', '/'),
                    },
                    # Temporary fields (stripped before save)
                    '_username': username,
                    '_access_keys': self._get_user_access_keys(username),
                    '_mfa_devices': self._get_user_mfa_devices(username),
                    '_attached_policies': self._get_user_attached_policies(username),
                    '_inline_policies': self._get_user_inline_policies(username),
                    '_groups': self._get_user_groups(username),
                    '_console_access': self._check_console_access(username),
                    '_password_last_used': user.get('PasswordLastUsed'),
                }

                # Enrich tags with key metadata
                active_keys = [k for k in identity['_access_keys'] if k['Status'] == 'Active']
                identity['tags']['mfa_enabled'] = len(identity['_mfa_devices']) > 0
                identity['tags']['access_key_count'] = len(active_keys)
                identity['tags']['groups'] = [g['GroupName'] for g in identity['_groups']]
                identity['tags']['has_console_access'] = identity['_console_access']

                self._identities.append(identity)

    def _get_user_access_keys(self, username):
        """Get access keys with last-used info."""
        keys = []
        try:
            resp = self.iam.list_access_keys(UserName=username)
            for key in resp.get('AccessKeyMetadata', []):
                key_info = dict(key)
                try:
                    usage = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    key_info['LastUsedDate'] = usage.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                except ClientError:
                    key_info['LastUsedDate'] = None
                keys.append(key_info)
        except ClientError as e:
            logger.debug(f"  Could not list access keys for {username}: {e}")
        return keys

    def _get_user_mfa_devices(self, username):
        try:
            resp = self.iam.list_mfa_devices(UserName=username)
            return resp.get('MFADevices', [])
        except ClientError:
            return []

    def _get_user_attached_policies(self, username):
        policies = []
        try:
            paginator = self.iam.get_paginator('list_attached_user_policies')
            for page in paginator.paginate(UserName=username):
                policies.extend(page.get('AttachedPolicies', []))
        except ClientError:
            pass
        return policies

    def _get_user_inline_policies(self, username):
        """Get inline policy names and their documents."""
        policies = []
        try:
            paginator = self.iam.get_paginator('list_user_policies')
            for page in paginator.paginate(UserName=username):
                for name in page.get('PolicyNames', []):
                    try:
                        doc = self.iam.get_user_policy(
                            UserName=username, PolicyName=name)
                        policies.append({
                            'PolicyName': name,
                            'PolicyDocument': doc.get('PolicyDocument', {}),
                        })
                    except ClientError:
                        policies.append({'PolicyName': name, 'PolicyDocument': {}})
        except ClientError:
            pass
        return policies

    def _get_user_groups(self, username):
        try:
            resp = self.iam.list_groups_for_user(UserName=username)
            return resp.get('Groups', [])
        except ClientError:
            return []

    def _check_console_access(self, username):
        """Check if user has a login profile (console password)."""
        try:
            self.iam.get_login_profile(UserName=username)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return False
            return False

    # ── IAM Role Discovery ───────────────────────────────────────────

    def _discover_iam_roles(self):
        """Discover all IAM roles with attached policies and trust analysis."""
        paginator = self.iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                rolename = role['RoleName']
                arn = role['Arn']
                path = role.get('Path', '/')
                created = role.get('CreateDate')
                is_service_linked = path.startswith('/aws-service-role/')

                trust_doc = role.get('AssumeRolePolicyDocument', {})
                trust_analysis = self._analyze_trust_policy(trust_doc)

                category = 'iam_service_linked_role' if is_service_linked else 'iam_role'

                identity = {
                    'identity_id': arn,
                    'display_name': rolename,
                    'identity_type': category,
                    'identity_category': category,
                    'source': 'aws_iam',
                    'cloud': 'aws',
                    'principal_id': arn,
                    'tenant_or_org_id': self.aws_account_id,
                    'created_datetime': created.isoformat() if created else None,
                    'enabled': True,
                    'is_microsoft_system': False,
                    'tags': {
                        'aws_account_id': self.aws_account_id,
                        'arn': arn,
                        'path': path,
                        'is_service_linked': is_service_linked,
                        'trust_principals': trust_analysis.get('principals', []),
                        'is_cross_account': trust_analysis.get('is_cross_account', False),
                        'is_wildcard_trust': trust_analysis.get('is_wildcard', False),
                        'trusted_services': trust_analysis.get('services', []),
                        'is_federated': trust_analysis.get('is_federated', False),
                    },
                    '_rolename': rolename,
                    '_attached_policies': self._get_role_attached_policies(rolename),
                    '_inline_policies': self._get_role_inline_policies(rolename),
                    '_trust_analysis': trust_analysis,
                    '_role_last_used': role.get('RoleLastUsed', {}),
                }

                self._identities.append(identity)

    def _get_role_attached_policies(self, rolename):
        policies = []
        try:
            paginator = self.iam.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=rolename):
                policies.extend(page.get('AttachedPolicies', []))
        except ClientError:
            pass
        return policies

    def _get_role_inline_policies(self, rolename):
        policies = []
        try:
            paginator = self.iam.get_paginator('list_role_policies')
            for page in paginator.paginate(RoleName=rolename):
                for name in page.get('PolicyNames', []):
                    try:
                        doc = self.iam.get_role_policy(
                            RoleName=rolename, PolicyName=name)
                        policies.append({
                            'PolicyName': name,
                            'PolicyDocument': doc.get('PolicyDocument', {}),
                        })
                    except ClientError:
                        policies.append({'PolicyName': name, 'PolicyDocument': {}})
        except ClientError:
            pass
        return policies

    def _analyze_trust_policy(self, trust_doc):
        """Parse AssumeRolePolicyDocument to detect trust patterns."""
        result = {
            'principals': [],
            'services': [],
            'is_cross_account': False,
            'is_wildcard': False,
            'is_federated': False,
        }

        if isinstance(trust_doc, str):
            try:
                trust_doc = json.loads(trust_doc)
            except (json.JSONDecodeError, TypeError):
                return result

        for stmt in trust_doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue

            principal = stmt.get('Principal', {})
            if isinstance(principal, str):
                if principal == '*':
                    result['is_wildcard'] = True
                    result['principals'].append('*')
                continue

            # AWS principals (accounts, roles, users)
            aws_principals = principal.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                if p == '*':
                    result['is_wildcard'] = True
                result['principals'].append(p)
                # Cross-account if principal contains a different account ID
                if ':' in p:
                    parts = p.split(':')
                    if len(parts) >= 5:
                        acct = parts[4]
                        if acct and acct != self.aws_account_id and acct != '*':
                            result['is_cross_account'] = True

            # Service principals
            services = principal.get('Service', [])
            if isinstance(services, str):
                services = [services]
            result['services'].extend(services)

            # Federated principals
            federated = principal.get('Federated', [])
            if isinstance(federated, str):
                federated = [federated]
            if federated:
                result['is_federated'] = True
                result['principals'].extend(federated)

        return result

    # ── Risk Calculation ─────────────────────────────────────────────

    def _calculate_risks(self):
        """Apply V2 risk catalog scoring to all discovered identities."""
        for identity in self._identities:
            factors = []
            category = identity.get('identity_category')

            # Service-linked role — low baseline
            if category == 'iam_service_linked_role':
                factors.append(make_factor('AWS_SERVICE_LINKED_ROLE',
                                           f"Service-linked role: {identity['display_name']}"))

            # Managed policy risks
            for policy in identity.get('_attached_policies', []):
                arn = policy.get('PolicyArn', '')
                code = POLICY_RISK_MAP.get(arn)
                if code:
                    factors.append(make_factor(code, f"Policy: {policy.get('PolicyName', arn)}"))

            # Inline policy risks — check for dangerous actions
            for policy in identity.get('_inline_policies', []):
                doc = policy.get('PolicyDocument', {})
                dangerous_found = self._check_dangerous_actions(doc)
                if dangerous_found:
                    factors.append(make_factor('AWS_DANGEROUS_INLINE',
                                               f"Inline policy '{policy['PolicyName']}' has: {', '.join(dangerous_found)}"))

                # Check for Action:* Resource:*
                if self._has_star_policy(doc):
                    factors.append(make_factor('AWS_STAR_POLICY',
                                               f"Inline policy '{policy['PolicyName']}' grants Action:*/Resource:*"))

            # Trust policy risks (roles only)
            trust = identity.get('_trust_analysis', {})
            if trust.get('is_wildcard'):
                factors.append(make_factor('AWS_TRUST_WILDCARD',
                                           "Trust policy allows Principal '*'"))
            if trust.get('is_cross_account'):
                factors.append(make_factor('AWS_CROSS_ACCOUNT_TRUST',
                                           f"Cross-account trust: {trust.get('principals', [])}"))

            # IAM user-specific risks
            if category == 'iam_user':
                access_keys = identity.get('_access_keys', [])
                active_keys = [k for k in access_keys if k.get('Status') == 'Active']
                mfa_devices = identity.get('_mfa_devices', [])
                has_console = identity.get('_console_access', False)

                # No MFA
                if not mfa_devices:
                    factors.append(make_factor('AWS_NO_MFA',
                                               f"No MFA device for user {identity['display_name']}"))

                # Console access without MFA
                if has_console and not mfa_devices:
                    factors.append(make_factor('AWS_CONSOLE_ACCESS_NO_MFA',
                                               "Console login enabled without MFA"))

                # Multiple active access keys
                if len(active_keys) > 1:
                    factors.append(make_factor('AWS_MULTIPLE_ACCESS_KEYS',
                                               f"{len(active_keys)} active access keys"))

                # Stale / never-used access keys
                now = datetime.now(timezone.utc)
                for key in active_keys:
                    created = key.get('CreateDate')
                    last_used = key.get('LastUsedDate')
                    key_id = key.get('AccessKeyId', 'unknown')

                    if last_used is None:
                        factors.append(make_factor('AWS_ACCESS_KEY_NEVER_USED',
                                                   f"Key {key_id} created but never used"))
                    elif created:
                        if isinstance(created, datetime):
                            age = (now - created.replace(tzinfo=timezone.utc)).days
                        else:
                            age = 0
                        if age > 90:
                            factors.append(make_factor('AWS_ACCESS_KEY_STALE',
                                                       f"Key {key_id} is {age} days old"))

            # Calculate total score
            total_score = sum(f['points'] for f in factors)
            risk_level = score_to_level_v2(total_score)

            identity['risk_score'] = total_score
            identity['risk_level'] = risk_level
            identity['risk_factors'] = factors
            identity['risk_reasons'] = [f['description'] for f in factors]

    def _check_dangerous_actions(self, policy_doc):
        """Check if a policy document contains dangerous actions."""
        found = set()
        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action in DANGEROUS_ACTIONS:
                    found.add(action)
        return found

    def _has_star_policy(self, policy_doc):
        """Check if policy has Action:* with Resource:*."""
        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if '*' in actions and '*' in resources:
                return True
        return False

    # ── Activity Status ──────────────────────────────────────────────

    def _check_activity(self):
        """Determine activity status from password/key/role last-used."""
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=90)

        for identity in self._identities:
            category = identity.get('identity_category')
            last_used = None

            if category == 'iam_user':
                # Check PasswordLastUsed
                pwd_used = identity.get('_password_last_used')
                if pwd_used and isinstance(pwd_used, datetime):
                    last_used = pwd_used.replace(tzinfo=timezone.utc)

                # Check access key last used
                for key in identity.get('_access_keys', []):
                    key_used = key.get('LastUsedDate')
                    if key_used and isinstance(key_used, datetime):
                        key_used = key_used.replace(tzinfo=timezone.utc)
                        if last_used is None or key_used > last_used:
                            last_used = key_used
            else:
                # IAM roles — use RoleLastUsed
                role_last = identity.get('_role_last_used', {})
                used_date = role_last.get('LastUsedDate')
                if used_date and isinstance(used_date, datetime):
                    last_used = used_date.replace(tzinfo=timezone.utc)

            if last_used:
                identity['last_sign_in'] = last_used.isoformat()
                if last_used < stale_threshold:
                    identity['activity_status'] = 'stale'
                else:
                    identity['activity_status'] = 'active'
            else:
                identity['last_sign_in'] = None
                identity['activity_status'] = 'never_used'

    # ── Save to Database ─────────────────────────────────────────────

    def _save_identities(self, run_id):
        """Save all discovered identities to the database."""
        counts = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        # Phase 23: Enforce identity count limit based on organization plan
        if self.db_org_id:
            try:
                from app.api.handlers import TIER_LIMITS
                cursor = self.db.conn.cursor()
                cursor.execute("SELECT plan FROM organizations WHERE id = %s", (self.db_org_id,))
                row = cursor.fetchone()
                cursor.close()
                if row:
                    plan = row[0] or 'free'
                    limits = TIER_LIMITS.get(plan, TIER_LIMITS['free'])
                    max_ids = limits.get('max_identities')
                    if max_ids and len(self._identities) > max_ids:
                        logger.warning(f"Organization {self.db_org_id} ({plan} plan): truncating {len(self._identities)} identities to {max_ids}")
                        self._identities = self._identities[:max_ids]
            except Exception as e:
                logger.error(f"Entitlement check failed, proceeding without limit: {e}")

        for identity in self._identities:
            # Cross-account bleed prevention
            acct = identity.get('tags', {}).get('aws_account_id')
            if acct and acct != self.aws_account_id:
                logger.warning(f"  Skipping identity {identity['display_name']} — "
                               f"account {acct} != {self.aws_account_id}")
                continue

            # Strip temporary fields before save
            save_data = {k: v for k, v in identity.items() if not k.startswith('_')}

            # Set credential status from access keys (for users)
            if identity.get('identity_category') == 'iam_user':
                active_keys = [k for k in identity.get('_access_keys', [])
                               if k.get('Status') == 'Active']
                if active_keys:
                    save_data['credential_status'] = 'active'
                else:
                    save_data['credential_status'] = 'none'

            identity_db_id = self.db.save_identity(run_id, save_data)

            # Save policies as role_assignments for UI compatibility
            for policy in identity.get('_attached_policies', []):
                arn = policy.get('PolicyArn', '')
                name = policy.get('PolicyName', arn)
                self.db.save_role_assignment(identity_db_id, {
                    'role_name': name,
                    'scope': f'arn:aws:iam::{self.aws_account_id}:policy',
                    'scope_type': 'account',
                    'principal_id': identity.get('principal_id', ''),
                    'assignment_id': arn,
                    'role_type': 'aws_managed_policy',
                    'risk_level': identity.get('risk_level', 'info'),
                })

            # Save inline policies as role_assignments
            for policy in identity.get('_inline_policies', []):
                name = policy.get('PolicyName', 'inline')
                self.db.save_role_assignment(identity_db_id, {
                    'role_name': f'[inline] {name}',
                    'scope': f'arn:aws:iam::{self.aws_account_id}:inline',
                    'scope_type': 'account',
                    'principal_id': identity.get('principal_id', ''),
                    'assignment_id': f'inline:{name}',
                    'role_type': 'aws_inline_policy',
                    'risk_level': identity.get('risk_level', 'info'),
                })

            level = identity.get('risk_level', 'info')
            counts['total'] += 1
            if level == 'critical':
                counts['critical'] += 1
            elif level == 'high':
                counts['high'] += 1
            elif level == 'medium':
                counts['medium'] += 1
            elif level == 'low':
                counts['low'] += 1

        return counts

    def _run_identity_lineage(self):
        """DEPRECATED: TS lineage subprocess removed.
        Lineage engine unified under Python to ensure consistency.
        Python discovery engine is the single source of truth.
        The TS services/lineage/aws/* files are retained as Phase 2 reference only.
        """
        pass

    def _sync_aws_account(self):
        """Ensure the AWS account is tracked in cloud_subscriptions."""
        try:
            self.db.insert_discovered_subscriptions(
                organization_id=self.db_org_id,
                cloud='aws',
                connection_id=self.cloud_connection_id,
                subs_list=[{
                    'id': self.aws_account_id,
                    'name': f'AWS Account {self.aws_account_id}',
                }],
            )
        except Exception as e:
            logger.warning(f"  Failed to sync AWS account to cloud_subscriptions: {e}")

    # ── Lazy boto3 Clients ────────────────────────────────────────

    _extra_clients = {}

    def _get_client(self, service_name):
        """Create boto3 client on demand. Returns None on permission error."""
        if service_name in self._extra_clients:
            return self._extra_clients[service_name]
        try:
            client = self._session.client(service_name, config=self._retry_config)
            self._extra_clients[service_name] = client
            return client
        except Exception as e:
            logger.warning(f"  Cannot create {service_name} client: {e}")
            return None

    def _stamp_isolation(self, data):
        """Inject isolation keys into every resource/event dict before save."""
        data['aws_account_id'] = self.aws_account_id
        data['organization_id'] = self.db_org_id
        data['cloud_connection_id'] = self.cloud_connection_id
        return data

    # ── S3 Bucket Discovery ──────────────────────────────────────

    SECRET_PATTERNS = re.compile(
        r'(password|secret|key|token|api.?key|access.?key|credential)',
        re.IGNORECASE
    )

    def _discover_s3_buckets(self, run_id):
        """Discover all S3 buckets with security configuration."""
        s3 = self._get_client('s3')
        if not s3:
            return 0
        count = 0
        try:
            resp = s3.list_buckets()
        except ClientError as e:
            logger.warning(f"  s3:ListBuckets failed: {e}")
            return 0

        for bucket in resp.get('Buckets', []):
            name = bucket['BucketName']
            try:
                data = {
                    'resource_id': f'arn:aws:s3:::{name}',
                    'name': name,
                    'region': self._get_bucket_region(s3, name),
                }

                # Public access block
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    conf = pab.get('PublicAccessBlockConfiguration', {})
                    data['block_public_acls'] = conf.get('BlockPublicAcls', False)
                    data['block_public_policy'] = conf.get('BlockPublicPolicy', False)
                    data['public_access_block_enabled'] = (
                        conf.get('BlockPublicAcls', False) and
                        conf.get('BlockPublicPolicy', False) and
                        conf.get('IgnorePublicAcls', False) and
                        conf.get('RestrictPublicBuckets', False)
                    )
                except ClientError:
                    data['public_access_block_enabled'] = False

                # Encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    if rules:
                        sse = rules[0].get('ApplyServerSideEncryptionByDefault', {})
                        data['encryption_enabled'] = True
                        data['encryption_algorithm'] = sse.get('SSEAlgorithm', '')
                        data['kms_key_id'] = sse.get('KMSMasterKeyID')
                        data['bucket_key_enabled'] = rules[0].get('BucketKeyEnabled', False)
                    else:
                        data['encryption_enabled'] = False
                except ClientError:
                    data['encryption_enabled'] = False

                # Versioning
                try:
                    ver = s3.get_bucket_versioning(Bucket=name)
                    data['versioning_enabled'] = ver.get('Status') == 'Enabled'
                    data['mfa_delete'] = ver.get('MFADelete') == 'Enabled'
                except ClientError:
                    pass

                # Logging
                try:
                    log = s3.get_bucket_logging(Bucket=name)
                    le = log.get('LoggingEnabled')
                    data['logging_enabled'] = le is not None
                    data['logging_target_bucket'] = le.get('TargetBucket') if le else None
                except ClientError:
                    pass

                # Policy status (public check)
                try:
                    ps = s3.get_bucket_policy_status(Bucket=name)
                    data['policy_status_is_public'] = ps.get('PolicyStatus', {}).get('IsPublic', False)
                except ClientError:
                    data['policy_status_is_public'] = False

                # ACL (public check)
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    grants = acl.get('Grants', [])
                    data['acl_grants_public'] = any(
                        g.get('Grantee', {}).get('URI', '') in (
                            'http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
                        )
                        for g in grants
                    )
                except ClientError:
                    data['acl_grants_public'] = False

                # Lifecycle
                try:
                    lc = s3.get_bucket_lifecycle_configuration(Bucket=name)
                    data['lifecycle_rules_count'] = len(lc.get('Rules', []))
                except ClientError:
                    data['lifecycle_rules_count'] = 0

                # Stamp isolation keys
                self._stamp_isolation(data)

                # Score
                total, level, components, overrides, reasons = score_s3_bucket(data)
                data['risk_score'] = total
                data['risk_level'] = level
                data['risk_components'] = components
                data['critical_overrides'] = overrides
                data['risk_reasons'] = reasons

                # Validate isolation before save
                assert data['aws_account_id'] == self.aws_account_id, \
                    f"Account mismatch: {data['aws_account_id']} != {self.aws_account_id}"

                self.db.save_s3_bucket(run_id, data)
                count += 1
            except Exception as e:
                logger.warning(f"  Error processing S3 bucket {name}: {e}")

        logger.info(f"  Discovered {count} S3 buckets")
        return count

    def _get_bucket_region(self, s3, bucket_name):
        """Get the region for a bucket."""
        try:
            loc = s3.get_bucket_location(Bucket=bucket_name)
            region = loc.get('LocationConstraint')
            return region or 'us-east-1'  # None means us-east-1
        except ClientError:
            return self.region

    # ── KMS Key Discovery ────────────────────────────────────────

    def _discover_kms_keys(self, run_id):
        """Discover all KMS customer-managed keys with security configuration."""
        kms = self._get_client('kms')
        if not kms:
            return 0
        count = 0

        try:
            paginator = kms.get_paginator('list_keys')
        except ClientError as e:
            logger.warning(f"  kms:ListKeys failed: {e}")
            return 0

        for page in paginator.paginate():
            for key_entry in page.get('Keys', []):
                key_id = key_entry['KeyId']
                key_arn = key_entry['KeyArn']
                try:
                    # Describe key
                    desc = kms.describe_key(KeyId=key_id)
                    meta = desc.get('KeyMetadata', {})

                    data = {
                        'resource_id': key_arn,
                        'name': meta.get('Description') or key_id,
                        'key_id': key_id,
                        'region': self.region,
                        'key_state': meta.get('KeyState'),
                        'key_usage': meta.get('KeyUsage'),
                        'key_spec': meta.get('KeySpec') or meta.get('CustomerMasterKeySpec'),
                        'key_manager': meta.get('KeyManager'),
                        'origin': meta.get('Origin'),
                        'multi_region': meta.get('MultiRegion', False),
                        'multi_region_config': meta.get('MultiRegionConfiguration', {}),
                    }

                    # Rotation status (only for customer-managed symmetric keys)
                    try:
                        rot = kms.get_key_rotation_status(KeyId=key_id)
                        data['rotation_enabled'] = rot.get('KeyRotationEnabled', False)
                    except ClientError:
                        data['rotation_enabled'] = False

                    # Key policy
                    try:
                        pol = kms.get_key_policy(KeyId=key_id, PolicyName='default')
                        policy_str = pol.get('Policy', '{}')
                        data['key_policy'] = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
                    except (ClientError, json.JSONDecodeError):
                        data['key_policy'] = {}

                    # Grants count
                    try:
                        grants = kms.list_grants(KeyId=key_id)
                        data['grants_count'] = len(grants.get('Grants', []))
                    except ClientError:
                        data['grants_count'] = 0

                    # Tags
                    try:
                        tags_resp = kms.list_resource_tags(KeyId=key_id)
                        data['tags'] = {t['TagKey']: t['TagValue'] for t in tags_resp.get('Tags', [])}
                    except ClientError:
                        data['tags'] = {}

                    # Stamp isolation keys
                    self._stamp_isolation(data)

                    # Score
                    total, level, components, overrides, reasons = score_kms_key(data)
                    data['risk_score'] = total
                    data['risk_level'] = level
                    data['risk_components'] = components
                    data['critical_overrides'] = overrides
                    data['risk_reasons'] = reasons

                    # Validate isolation before save
                    assert data['aws_account_id'] == self.aws_account_id

                    self.db.save_kms_key(run_id, data)
                    count += 1
                except Exception as e:
                    logger.warning(f"  Error processing KMS key {key_id}: {e}")

        logger.info(f"  Discovered {count} KMS keys")
        return count

    # ── Lambda Function Discovery ────────────────────────────────

    def _discover_lambda_functions(self, run_id):
        """Discover all Lambda functions with security configuration."""
        lam = self._get_client('lambda')
        if not lam:
            return 0
        count = 0

        try:
            paginator = lam.get_paginator('list_functions')
        except ClientError as e:
            logger.warning(f"  lambda:ListFunctions failed: {e}")
            return 0

        for page in paginator.paginate():
            for func in page.get('Functions', []):
                name = func['FunctionName']
                arn = func['FunctionArn']
                try:
                    role_arn = func.get('Role', '')
                    role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn

                    vpc_config = func.get('VpcConfig', {})
                    env_vars = func.get('Environment', {}).get('Variables', {})
                    env_count = len(env_vars)

                    # Check for secrets in environment variables
                    has_secrets = any(
                        self.SECRET_PATTERNS.search(k)
                        for k in env_vars.keys()
                    )

                    data = {
                        'resource_id': arn,
                        'name': name,
                        'region': self.region,
                        'runtime': func.get('Runtime'),
                        'handler': func.get('Handler'),
                        'timeout': func.get('Timeout', 3),
                        'memory_size': func.get('MemorySize', 128),
                        'code_size': func.get('CodeSize', 0),
                        'last_modified': func.get('LastModified'),
                        'execution_role_arn': role_arn,
                        'execution_role_name': role_name,
                        'vpc_id': vpc_config.get('VpcId'),
                        'subnet_ids': vpc_config.get('SubnetIds', []),
                        'security_group_ids': vpc_config.get('SecurityGroupIds', []),
                        'environment_variables_count': env_count,
                        'has_secrets_in_env': has_secrets,
                        'kms_key_arn': func.get('KMSKeyArn'),
                        'dead_letter_config': func.get('DeadLetterConfig'),
                    }

                    # Resource policy (public invocation check)
                    try:
                        pol = lam.get_policy(FunctionName=name)
                        policy_doc = json.loads(pol.get('Policy', '{}'))
                        data['resource_policy'] = policy_doc
                        # Check for public invoke
                        data['resource_policy_is_public'] = any(
                            stmt.get('Principal') == '*' or
                            (isinstance(stmt.get('Principal'), dict) and
                             stmt['Principal'].get('AWS') == '*')
                            for stmt in policy_doc.get('Statement', [])
                            if stmt.get('Effect') == 'Allow'
                        )
                    except ClientError:
                        data['resource_policy'] = {}
                        data['resource_policy_is_public'] = False

                    # Tags
                    try:
                        data['tags'] = func.get('Tags', {}) or {}
                    except Exception:
                        data['tags'] = {}

                    # Stamp isolation keys
                    self._stamp_isolation(data)

                    # Score
                    total, level, components, overrides, reasons = score_lambda_function(data)
                    data['risk_score'] = total
                    data['risk_level'] = level
                    data['risk_components'] = components
                    data['critical_overrides'] = overrides
                    data['risk_reasons'] = reasons

                    # Validate isolation before save
                    assert data['aws_account_id'] == self.aws_account_id

                    self.db.save_lambda_function(run_id, data)
                    count += 1
                except Exception as e:
                    logger.warning(f"  Error processing Lambda function {name}: {e}")

        logger.info(f"  Discovered {count} Lambda functions")
        return count

    # ── Resource Discovery Orchestrator ──────────────────────────

    def _discover_and_save_resources(self, run_id):
        """Discover S3, KMS, and Lambda resources — called from run_discovery."""
        logger.info("  Starting AWS resource discovery...")
        s3_count = self._discover_s3_buckets(run_id)
        kms_count = self._discover_kms_keys(run_id)
        lambda_count = self._discover_lambda_functions(run_id)
        logger.info(f"  AWS resources: {s3_count} S3, {kms_count} KMS, {lambda_count} Lambda")

    # ── Organizations Discovery ──────────────────────────────────

    def _discover_organizations(self):
        """Discover AWS Organization member accounts and save as cloud_subscriptions."""
        org_client = self._get_client('organizations')
        if not org_client:
            return

        try:
            org_client.describe_organization()
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'AWSOrganizationsNotInUseException':
                logger.info("  AWS Organizations not in use — skipping")
                return
            logger.warning(f"  organizations:DescribeOrganization failed: {e}")
            return

        accounts = []
        try:
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                for acct in page.get('Accounts', []):
                    if acct.get('Status') == 'ACTIVE':
                        accounts.append({
                            'id': acct['Id'],
                            'name': acct.get('Name', f"AWS Account {acct['Id']}"),
                        })
        except ClientError as e:
            logger.warning(f"  organizations:ListAccounts failed: {e}")
            return

        if accounts:
            inserted = self.db.insert_discovered_subscriptions(
                organization_id=self.db_org_id,
                cloud='aws',
                connection_id=self.cloud_connection_id,
                subs_list=accounts,
            )
            logger.info(f"  Discovered {len(accounts)} org accounts, inserted/updated {inserted}")

    # ── CloudTrail Ingestion ─────────────────────────────────────

    def _ingest_cloudtrail(self, run_id):
        """Ingest CloudTrail events using AWSCloudTrailService."""
        from app.engines.telemetry.aws_cloudtrail import AWSCloudTrailService

        lookback = int(self.db.get_setting(
            'aws_cloudtrail_lookback_days', '7', self.db_org_id))

        svc = AWSCloudTrailService(
            session=self._session,
            db=self.db,
            aws_account_id=self.aws_account_id,
        )
        count = svc.ingest_events(
            run_id=run_id,
            organization_id=self.db_org_id,
            cloud_connection_id=self.cloud_connection_id,
            lookback_days=lookback,
        )
        if count > 0:
            svc.backfill_last_activity(run_id)
        logger.info(f"  CloudTrail: ingested {count} events")
