"""
GCP IAM Discovery Engine

Discovers service accounts, IAM bindings, roles, and projects from Google Cloud.
Calculates risk scores using the V2 risk catalog and stores results in
the same identities table used by Azure/AWS discovery.

Required credentials:
    - GCP service account JSON credentials (passed as parameter or env var)

Required IAM permissions:
    - resourcemanager.projects.getIamPolicy
    - iam.serviceAccounts.list
    - iam.serviceAccountKeys.list
    - iam.roles.list
"""

import json
import logging
from datetime import datetime, timezone, timedelta

from app.database import Database
from app.engines.risk_catalog import RISK_FACTOR_CATALOG, make_factor, score_to_level_v2

logger = logging.getLogger(__name__)

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


class GCPDiscoveryEngine:
    """Google Cloud IAM identity discovery engine."""

    @property
    def cloud_provider(self) -> str:
        return "gcp"

    def __init__(self, credentials_json: str, project_id: str,
                 db_org_id: int = None, cloud_connection_id: int = None):
        if cloud_connection_id is None:
            raise ValueError("cloud_connection_id is required for discovery")
        if db_org_id is None:
            raise ValueError("db_org_id is required for discovery")

        self.credentials_json = credentials_json
        self.project_id = project_id
        self.db_org_id = db_org_id
        self.cloud_connection_id = cloud_connection_id
        self.db = Database(organization_id=db_org_id)
        self._identities = []

        # Initialize GCP clients
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            creds_dict = json.loads(credentials_json) if isinstance(credentials_json, str) else credentials_json
            credentials = service_account.Credentials.from_service_account_info(
                creds_dict,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
            self.iam_service = build('iam', 'v1', credentials=credentials)
            self.crm_service = build('cloudresourcemanager', 'v1', credentials=credentials)
        except ImportError:
            logger.warning("google-cloud libraries not installed; GCP discovery will fail at runtime")
            self.iam_service = None
            self.crm_service = None
        except Exception as e:
            logger.error(f"Failed to initialize GCP clients: {e}")
            self.iam_service = None
            self.crm_service = None

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
        """Test GCP connectivity by listing projects."""
        try:
            if not self.crm_service:
                return False
            result = self.crm_service.projects().get(projectId=self.project_id).execute()
            return bool(result.get('projectId'))
        except Exception:
            return False

    def run_discovery(self):
        """Main discovery entry point."""
        logger.info(f"GCP Discovery starting for project {self.project_id}")

        run_id = self.db.create_discovery_run(
            subscription_id=self.project_id,
            subscription_name=f'GCP Project {self.project_id}',
            organization_id=self.db_org_id,
            cloud_connection_id=self.cloud_connection_id,
        )
        logger.info(f"  Created discovery run #{run_id}")
        self._update_job_progress('discovering_identities', 20, discovery_run_id=run_id)

        try:
            self._discover_service_accounts()
            logger.info(f"  Discovered {len([i for i in self._identities if i.get('identity_category') == 'gcp_service_account'])} service accounts")

            self._discover_iam_bindings()
            logger.info(f"  Discovered {len([i for i in self._identities if i.get('identity_category') != 'gcp_service_account'])} IAM members")
            self._update_job_progress('discovering_rbac', 60)

            self._calculate_risks()

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

            self._sync_gcp_project()

            logger.info(f"  GCP Discovery completed: {counts['total']} identities "
                        f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']} L:{counts['low']})")
        except Exception as e:
            logger.error(f"  GCP Discovery failed: {e}", exc_info=True)
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

    # ── Service Account Discovery ──────────────────────────────────────

    def _discover_service_accounts(self):
        """Discover all service accounts in the project."""
        if not self.iam_service:
            return
        try:
            name = f'projects/{self.project_id}'
            request = self.iam_service.projects().serviceAccounts().list(name=name)
            while request is not None:
                response = request.execute()
                for sa in response.get('accounts', []):
                    email = sa.get('email', '')
                    display_name = sa.get('displayName', email)

                    # Get keys for this service account
                    keys = self._get_sa_keys(sa.get('name', ''))
                    user_managed_keys = [k for k in keys
                                         if k.get('keyType') == 'USER_MANAGED']

                    identity = {
                        'identity_id': email,
                        'display_name': display_name,
                        'identity_type': 'gcp_service_account',
                        'identity_category': 'gcp_service_account',
                        'source': 'gcp_iam',
                        'cloud': 'gcp',
                        'principal_id': email,
                        'tenant_or_org_id': self.project_id,
                        'created_datetime': None,
                        'enabled': not sa.get('disabled', False),
                        'is_microsoft_system': False,
                        'tags': {
                            'project_id': self.project_id,
                            'email': email,
                            'unique_id': sa.get('uniqueId', ''),
                            'oauth2_client_id': sa.get('oauth2ClientId', ''),
                            'user_managed_key_count': len(user_managed_keys),
                            'disabled': sa.get('disabled', False),
                        },
                        '_sa_keys': keys,
                        '_user_managed_keys': user_managed_keys,
                    }

                    self._identities.append(identity)

                request = self.iam_service.projects().serviceAccounts().list_next(
                    previous_request=request, previous_response=response)
        except Exception as e:
            logger.error(f"Failed to discover service accounts: {e}")

    def _get_sa_keys(self, sa_name):
        """Get service account keys."""
        try:
            response = self.iam_service.projects().serviceAccounts().keys().list(
                name=sa_name, keyTypes=['USER_MANAGED', 'SYSTEM_MANAGED']
            ).execute()
            return response.get('keys', [])
        except Exception:
            return []

    # ── IAM Binding Discovery ──────────────────────────────────────────

    def _discover_iam_bindings(self):
        """Discover IAM policy bindings on the project."""
        if not self.crm_service:
            return
        try:
            policy = self.crm_service.projects().getIamPolicy(
                resource=self.project_id, body={}
            ).execute()

            # Track seen members to avoid duplicates
            seen_members = {i['identity_id'] for i in self._identities}

            for binding in policy.get('bindings', []):
                role = binding.get('role', '')
                for member in binding.get('members', []):
                    if member in seen_members:
                        # Already discovered as service account — just add role
                        for identity in self._identities:
                            if identity['identity_id'] == member:
                                identity.setdefault('_iam_roles', []).append(role)
                                break
                        continue

                    # Parse member type
                    parts = member.split(':', 1)
                    member_type = parts[0] if len(parts) > 1 else 'unknown'
                    member_id = parts[1] if len(parts) > 1 else member

                    category = 'gcp_user' if member_type == 'user' else \
                               'gcp_group' if member_type == 'group' else \
                               'gcp_service_account' if member_type == 'serviceAccount' else \
                               'gcp_domain' if member_type == 'domain' else 'gcp_member'

                    identity = {
                        'identity_id': member,
                        'display_name': member_id,
                        'identity_type': member_type,
                        'identity_category': category,
                        'source': 'gcp_iam',
                        'cloud': 'gcp',
                        'principal_id': member,
                        'tenant_or_org_id': self.project_id,
                        'created_datetime': None,
                        'enabled': True,
                        'is_microsoft_system': False,
                        'tags': {
                            'project_id': self.project_id,
                            'member_type': member_type,
                        },
                        '_iam_roles': [role],
                    }

                    self._identities.append(identity)
                    seen_members.add(member)

        except Exception as e:
            logger.error(f"Failed to discover IAM bindings: {e}")

    # ── Risk Calculation ────────────────────────────────────────────────

    def _calculate_risks(self):
        """Apply V2 risk catalog scoring to all discovered identities."""
        for identity in self._identities:
            factors = []

            # Service account key exposure
            user_keys = identity.get('_user_managed_keys', [])
            if user_keys:
                factors.append(make_factor('GCP_SA_KEY_EXPOSURE',
                                           f"Service account has {len(user_keys)} user-managed key(s)"))

            # Check IAM role bindings for privilege
            iam_roles = identity.get('_iam_roles', [])
            for role in iam_roles:
                if role == 'roles/owner':
                    factors.append(make_factor('GCP_OWNER_ROLE',
                                               f"Owner role on project {self.project_id}"))
                elif role == 'roles/editor':
                    factors.append(make_factor('GCP_EDITOR_ROLE',
                                               f"Editor role on project {self.project_id}"))
                elif role in GCP_PRIVILEGED_ROLES:
                    factors.append(make_factor('GCP_PRIVILEGED_ROLE',
                                               f"Privileged role: {role}"))

            # Disabled service account with keys
            if identity.get('tags', {}).get('disabled') and user_keys:
                factors.append(make_factor('GCP_DISABLED_SA_WITH_KEYS',
                                           "Disabled service account still has user-managed keys"))

            # Calculate total score
            total_score = sum(f['points'] for f in factors)
            risk_level = score_to_level_v2(total_score)

            identity['risk_score'] = total_score
            identity['risk_level'] = risk_level
            identity['risk_factors'] = factors
            identity['risk_reasons'] = [f['description'] for f in factors]

    # ── Save to Database ────────────────────────────────────────────────

    def _save_identities(self, run_id):
        """Save all discovered identities to the database."""
        counts = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for identity in self._identities:
            # Strip temporary fields before save
            save_data = {k: v for k, v in identity.items() if not k.startswith('_')}

            identity_db_id = self.db.save_identity(run_id, save_data)

            # Save IAM role bindings as role_assignments
            for role in identity.get('_iam_roles', []):
                self.db.save_role_assignment(identity_db_id, {
                    'role_name': role,
                    'scope': f'projects/{self.project_id}',
                    'scope_type': 'project',
                    'principal_id': identity.get('principal_id', ''),
                    'assignment_id': f'{role}:{identity["identity_id"]}',
                    'role_type': 'gcp_iam_binding',
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

    def _sync_gcp_project(self):
        """Ensure the GCP project is tracked in cloud_subscriptions."""
        try:
            self.db.insert_discovered_subscriptions(
                organization_id=self.db_org_id,
                cloud='gcp',
                connection_id=self.cloud_connection_id,
                subs_list=[{
                    'id': self.project_id,
                    'name': f'GCP Project {self.project_id}',
                }],
            )
        except Exception as e:
            logger.warning(f"  Failed to sync GCP project to cloud_subscriptions: {e}")

    def _is_privileged_role(self, role: str) -> bool:
        """Check if a GCP role is considered privileged."""
        return role in GCP_PRIVILEGED_ROLES
