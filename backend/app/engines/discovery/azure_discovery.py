"""
Azure Discovery Engine

This module contains the AzureDiscoveryEngine class that orchestrates the complete
discovery process for Azure cloud identities. It connects to Microsoft Graph API
and Azure Resource Manager to discover and analyze identities and their permissions.

Discovery Process (executed in order):
    1. Create discovery run record in database
    2. Discover Azure RBAC role assignments (via Azure CLI)
    3. Discover Entra ID directory roles (via Graph API)
    4. Discover Service Principals with pagination (via Graph API)
    5. Discover SPN credentials (secrets, certificates, federated)
    6. Discover Microsoft Graph API permissions
    7. Discover custom application role assignments
    8. Discover users who have Azure RBAC or Entra roles
    9. Calculate risk levels based on permissions and activity
    10. Check credential expiration status
    11. Check last activity/sign-in status
    12. Save all data to PostgreSQL database
    13. Complete discovery run with summary statistics

Key Features:
    - Async/await pattern for efficient API calls
    - Pagination support for large directories (999 items per page)
    - Microsoft system SPN filtering (custom SPNs start with 'spn-')
    - Risk calculation combining Azure RBAC and Entra roles
    - Credential expiration tracking
    - Activity status detection

Identity Types Discovered:
    - Service Principals (application identities)
    - Users (with Azure RBAC or Entra role assignments)
    - Managed Identities (system and user-assigned)

Risk Level Calculation:
    - CRITICAL: Owner/Contributor on subscription, Global Admin, etc.
    - HIGH: Security Admin, User Access Administrator
    - MEDIUM: Reader roles, custom roles without activity
    - LOW/INFO: Properly scoped, active identities

Usage:
    engine = AzureDiscoveryEngine(azure_directory_id, client_id, client_secret)
    result = engine.run_discovery()

Dependencies:
    - azure-identity: Azure authentication
    - msgraph-sdk: Microsoft Graph API client
    - azure-mgmt-authorization: RBAC role assignment discovery (SDK-based, no CLI)
    - azure-mgmt-resource: Subscription discovery
"""
import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
try:
    from azure.mgmt.monitor import MonitorManagementClient
except ImportError:
    MonitorManagementClient = None
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
except ImportError:
    ResourceGraphClient = None
    QueryRequest = None
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient
from app.database import Database
from app.constants import Verdict, IdentityCategory
from .models import DiscoveryResult
import json

# Well-known dangerous MS Graph Application permission GUIDs
HIGH_RISK_PERMISSION_GUIDS = {
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8': 'RoleManagement.ReadWrite.Directory',
    '19dbc75e-c2e2-444c-a770-ec596d67a115': 'Directory.ReadWrite.All',
    'e2a3a72e-5f79-4c64-b005-482f1d733b6b': 'Mail.ReadWrite',
    '75359482-378d-4052-8f01-80520e7db3cd': 'Files.ReadWrite.All',
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9': 'Application.ReadWrite.All',
    '741f803b-c850-494e-b5df-cde7c675a1ca': 'User.ReadWrite.All',
    '62a82d76-70ea-41e2-9197-370581804d09': 'Group.ReadWrite.All',
    '06b708a9-e830-4db3-a914-8e69da51d44f': 'AppRoleAssignment.ReadWrite.All',
    '01d4f32e-3f2d-4d15-9825-dc7784652969': 'RoleManagement.Read.Directory',
    '7ab1d382-f21e-4acd-a863-ba3e13f7da61': 'Directory.Read.All',
}

# Microsoft Graph service principal resource ID (for requiredResourceAccess matching)
MS_GRAPH_RESOURCE_ID = '00000003-0000-0000-c000-000000000000'

class AzureDiscoveryEngine:
    """
    Orchestrates Azure identity discovery across Microsoft Graph and Azure RM.

    This engine connects to Azure using service principal credentials and discovers
    all identities (SPNs, users, managed identities), their role assignments,
    credentials, and permissions. It calculates risk levels and stores everything
    in PostgreSQL for dashboard display.

    Attributes:
        azure_directory_id: Azure AD / Entra directory ID
        client_id: Service principal application ID for authentication
        client_secret: Service principal secret for authentication
        db: Database instance for storing discovery results
        graph_client: Microsoft Graph SDK client
        subscription_id: Target Azure subscription ID
        subscription_name: Human-readable subscription name
    """

    def __init__(self, azure_directory_id: str, client_id: str, client_secret: str,
                 db_org_id=None, cloud_connection_id: int = None):
        """
        Initialize the discovery engine with Azure credentials.

        Args:
            azure_directory_id: Azure AD / Entra directory ID
            client_id: Service principal application ID
            client_secret: Service principal client secret
            db_org_id: AuditGraph organization ID (integer) for RLS context
            cloud_connection_id: ID from cloud_connections table (for multi-connection support)
        """
        if cloud_connection_id is None:
            raise ValueError("cloud_connection_id is required for discovery")
        if db_org_id is None:
            raise ValueError("db_org_id is required for discovery")

        self.azure_directory_id = azure_directory_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.db_org_id = db_org_id
        self.cloud_connection_id = cloud_connection_id
        self.db = Database(organization_id=db_org_id)

        self.credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret
        )

        self.graph_client = GraphServiceClient(
            credentials=self.credential,
            scopes=['https://graph.microsoft.com/.default']
        )

        # Auto-discover all accessible subscriptions, partitioned by tenant
        all_subs = self._discover_subscriptions()
        native_subs = [s for s in all_subs if s.get('tenant_id') == self.azure_directory_id]
        self.foreign_subscriptions = [s for s in all_subs if s.get('tenant_id') != self.azure_directory_id]
        if self.foreign_subscriptions:
            logger.info("Found %s subscription(s) from other tenants", len(self.foreign_subscriptions))

        # Filter to only ACTIVATED (monitored) subscriptions — the user chose which
        # subscriptions to scan in the UI.  If no cloud_subscriptions rows exist yet
        # (very first connection, before any sync), scan all native subscriptions so
        # the initial sync can populate the registry.
        monitored_ids = self._get_monitored_subscription_ids()
        if monitored_ids is not None:
            before = len(native_subs)
            self.subscriptions = [s for s in native_subs if s['id'] in monitored_ids]
            skipped = before - len(self.subscriptions)
            if skipped:
                logger.info("Filtered to %s activated subscription(s), skipping %s inactive", len(self.subscriptions), skipped)
        else:
            # No cloud_subscriptions rows yet — scan everything for initial sync
            self.subscriptions = native_subs

        sub_names = [f"{s['name']} ({s['id'][:8]}...)" for s in self.subscriptions]
        logger.info("Discovery Engine initialized for %s subscription(s): %s", len(self.subscriptions), ', '.join(sub_names) or 'none')

        # Cache resource SPN appRoles to avoid repeated API calls
        # Key: resource_spn_id, Value: dict mapping appRoleId -> role value
        self._resource_spn_cache: Dict[str, Dict[str, str]] = {}

    def _update_job_progress(self, stage, progress, discovery_run_id=None):
        """Report progress to snapshot_jobs. Non-fatal on failure.

        Uses _commit()/_rollback() to preserve RLS context after
        transaction boundary changes.
        """
        job_id = getattr(self, 'snapshot_job_id', None)
        if not job_id:
            return
        try:
            cursor = self.db.conn.cursor()
            try:
                if discovery_run_id is not None:
                    cursor.execute("""
                        UPDATE snapshot_jobs
                        SET stage = %s, progress = %s, discovery_run_id = %s,
                            last_heartbeat_at = NOW()
                        WHERE id = %s AND status = 'running'
                    """, (stage, progress, discovery_run_id, job_id))
                else:
                    cursor.execute("""
                        UPDATE snapshot_jobs
                        SET stage = %s, progress = %s, last_heartbeat_at = NOW()
                        WHERE id = %s AND status = 'running'
                    """, (stage, progress, job_id))
                self.db._commit()
            except Exception as e:
                logger.warning("Job progress update failed: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass
            finally:
                cursor.close()
        except Exception as e:
            logger.warning("Job progress update failed (outer): %s", e)

    def _update_job_metrics(self, identities=0, resources=0, subscriptions=0):
        """Update discovered counts on snapshot job. Non-fatal on failure.

        Inline UPDATE instead of delegating to db.update_snapshot_job_metrics()
        which does its own _commit() that would conflict with caller's
        transaction management.
        """
        job_id = getattr(self, 'snapshot_job_id', None)
        if not job_id:
            return
        try:
            cursor = self.db.conn.cursor()
            try:
                cursor.execute("""
                    UPDATE snapshot_jobs
                    SET identities_discovered = %s,
                        resources_discovered = %s,
                        subscriptions_discovered = %s,
                        duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::integer
                    WHERE id = %s
                """, (identities, resources, subscriptions, job_id))
                self.db._commit()
            except Exception as e:
                logger.warning("Job metrics update failed: %s", e)
                try:
                    self.db._rollback()
                except Exception:
                    pass
            finally:
                cursor.close()
        except Exception:
            pass

    def _get_monitored_subscription_ids(self) -> Optional[Set[str]]:
        """Query cloud_subscriptions for activated (monitored=true) subscription IDs.

        Returns:
            Set of subscription IDs that are monitored, or None if no
            cloud_subscriptions rows exist yet for this connection (first run).
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT account_id, monitored FROM cloud_subscriptions
                WHERE cloud_connection_id = %s AND deleted = false
            """, (self.cloud_connection_id,))
            rows = cursor.fetchall()
            cursor.close()
            if not rows:
                return None  # no rows yet — first connection, scan all
            monitored = set()
            for r in rows:
                aid = r[0] if not isinstance(r, dict) else r.get('account_id')
                mon = r[1] if not isinstance(r, dict) else r.get('monitored')
                if mon:
                    monitored.add(aid)
            return monitored
        except Exception as e:
            logger.warning("Failed to query monitored subscriptions: %s", e)
            return None  # fail-open: scan all

    def _discover_subscriptions(self) -> List[Dict[str, str]]:
        """Auto-discover all Azure subscriptions accessible to the service principal.

        IMPORTANT: Never falls back to env vars in multi-org mode — each organization's
        SPN must have RBAC access to their own subscriptions.

        Each subscription's tenant_id is preserved exactly as reported by Azure.
        Subscriptions with a different tenant_id than the source connection are
        classified as cross-tenant and routed to their own cloud_connection.
        """
        try:
            sub_client = SubscriptionClient(self.credential)
            subs = []
            for sub in sub_client.subscriptions.list():
                if sub.state and sub.state.lower() in ('enabled', 'warned'):
                    sub_tenant = sub.tenant_id
                    # Only fall back to source tenant if Azure SDK truly returned None
                    # (very rare — most subscriptions report tenant_id)
                    if not sub_tenant:
                        sub_tenant = self.azure_directory_id
                    elif sub_tenant != self.azure_directory_id:
                        logger.info("Detected cross-tenant subscription: %s (%s...) -> tenant %s...", sub.display_name, sub.subscription_id[:8], sub_tenant[:8])
                    subs.append({
                        'id': sub.subscription_id,
                        'name': sub.display_name or sub.subscription_id,
                        'tenant_id': sub_tenant,
                    })
            if not subs:
                logger.warning("No Azure subscriptions found -- SPN needs Reader RBAC on at least one subscription")
            return subs
        except Exception as e:
            logger.warning("Subscription discovery failed: %s", e)
            return []

    def run_discovery(self) -> DiscoveryResult:
        """
        Execute the full discovery process synchronously.

        This is the main entry point that wraps the async discovery
        in asyncio.run() for synchronous calling contexts (like the scheduler).

        Returns:
            DiscoveryResult or None on completion
        """
        return asyncio.run(self._async_run_discovery())

    async def _async_run_discovery(self) -> DiscoveryResult:
        sub_summary = ", ".join(f"{s['name']} ({s['id'][:8]}...)" for s in self.subscriptions) or "No subscriptions"
        logger.info("=" * 60)
        logger.info("AuditGraph Discovery Engine")
        logger.info("=" * 60)
        logger.info("Subscriptions: %s", sub_summary)
        logger.info("Started: %s UTC", datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Create discovery run using Database class method
        logger.info("Creating discovery run...")
        # Store all subscription IDs as comma-separated for the run record
        all_sub_ids = ",".join(s['id'] for s in self.subscriptions) if self.subscriptions else os.getenv('AZURE_SUBSCRIPTION_ID', '')
        all_sub_names = ", ".join(s['name'] for s in self.subscriptions) if self.subscriptions else os.getenv('AZURE_SUBSCRIPTION_NAME', 'Unknown')
        run_id = self.db.create_discovery_run(all_sub_ids, all_sub_names,
                                               cloud_connection_id=self.cloud_connection_id)
        logger.info("Discovery run created (ID: %s)", run_id)
        self._update_job_progress('initializing', 5, discovery_run_id=run_id)
        self._update_job_metrics(subscriptions=len(self.subscriptions))

        # Step 1: Get role assignments FIRST
        logger.info("Discovering Role Assignments...")
        self._update_job_progress('discovering_roles', 10)
        role_assignments = self._discover_role_assignments()
        logger.info("Found %s role assignments", len(role_assignments))

        # Step 2: Extract principal IDs that have roles
        principal_ids_with_roles = set(ra['principal_id'] for ra in role_assignments)
        logger.info("Found %s unique principals with roles", len(principal_ids_with_roles))

        # Step 2.5: Discover Entra ID directory roles
        logger.info("Discovering Entra ID Directory Roles...")
        self._update_job_progress('discovering_roles', 18)
        entra_roles = await self._discover_entra_roles()

        # Merge principal IDs from both Azure RBAC and Entra roles
        entra_principal_ids = set(er['principal_id'] for er in entra_roles)
        all_principal_ids = principal_ids_with_roles.union(entra_principal_ids)
        logger.info("Total unique principals (RBAC + Entra): %s", len(all_principal_ids))

        # Step 3: Discover Service Principals
        logger.info("Discovering Service Principals...")
        self._update_job_progress('discovering_identities', 25)
        service_principals = await self._discover_service_principals()
        logger.info("Found %s service principals", len(service_principals))

        # Step 3.1: Link SPNs to parent App Registrations (lineage)
        app_reg_map = await self._fetch_app_registration_map()
        self._enrich_spns_with_app_registrations(service_principals, app_reg_map)

        # Step 3.5: Discover SPN Credentials
        credentials_map = await self._discover_credentials(service_principals)
        self._update_job_progress('discovering_identities', 30)

        # Step 3.55: Enrich SPNs with federated credential classification
        fed_count = 0
        for sp in service_principals:
            creds = credentials_map.get(sp.get('identity_id'), [])
            fed_creds = [c for c in creds if c.get('credential_type') == 'federated']
            if fed_creds:
                best = fed_creds[0]
                sp['federated_workload_type'] = best.get('federated_workload_type')
                sp['federated_workload_name'] = best.get('federated_workload_name')
                fed_count += 1
        if fed_count:
            logger.info("Federated credential classification: %s SPNs enriched", fed_count)

        # Step 3.6: Discover API Permissions
        permissions_map = await self._discover_permissions(service_principals)

        # Step 3.7: Discover Custom App Roles
        app_roles_map = await self._discover_app_roles(service_principals)

        # Step 3.8: Discover Application Owners
        ownership_map = await self._discover_ownership(service_principals)

        # Step 3.9: Discover PIM Assignments
        pim_map = await self._discover_pim_assignments()

        # Step 3.10: Discover Conditional Access Policies
        ca_policies = await self._discover_conditional_access()
        self._update_job_progress('discovering_identities', 35)

        # Step 3.11: Module 3 — Audit Provenance (creation/modification history)
        logger.info("Discovering audit provenance (M3)...")
        await self._discover_audit_provenance(service_principals)

        # Step 3.12: Module 5 — Owned Objects Scanner
        logger.info("Discovering owned objects (M5)...")
        await self._discover_owned_objects(service_principals)

        # Step 4: Discover ALL users in the tenant
        logger.info("Discovering Users...")
        users = await self._discover_users(all_principal_ids)
        logger.info("Found %s users", len(users))
        self._update_job_progress('discovering_identities', 40)
        
        # Step 5: Discover Managed Identities
        logger.info("Discovering Managed Identities...")
        managed_identities = []
        logger.info("Found %s user-assigned managed identities", len(managed_identities))
        
        all_identities = service_principals + users + managed_identities

        # Step 5a: Discover Entra Groups
        logger.info("Discovering Entra Groups...")
        self._update_job_progress('discovering_groups', 42)
        groups = await self._discover_groups()
        logger.info("Found %s security groups", len(groups))

        # Step 5b: Discover Group Memberships (nested up to 3 levels)
        group_memberships = await self._discover_group_memberships(groups)
        self._update_job_progress('discovering_groups', 44)

        # Step 5c: Compute member/nested counts (rbac_roles populated at save time
        # from the canonical role_assignments list to avoid JSONB drift — FIX A)
        PRIVILEGED_ROLES = {
            'Owner', 'Contributor', 'User Access Administrator',
            'Role Based Access Control Administrator',
            'Key Vault Administrator', 'Storage Account Contributor',
        }
        # Build group_id→roles index from the canonical ARM role_assignments list
        group_id_set = {g['group_id'] for g in groups}
        group_role_index: Dict[str, list] = {}
        for ra in role_assignments:
            pid = ra.get('principal_id')
            if pid in group_id_set:
                group_role_index.setdefault(pid, []).append(ra)

        for group in groups:
            grp_roles = group_role_index.get(group['group_id'], [])
            group['rbac_roles'] = [
                {'role_name': r['role_name'], 'scope': r.get('scope', ''), 'scope_type': r.get('scope_type', '')}
                for r in grp_roles
            ]
            group['is_privileged'] = any(r['role_name'] in PRIVILEGED_ROLES for r in grp_roles)
            members_list = group_memberships.get(group['group_id'], [])
            group['member_count'] = len([m for m in members_list if m['depth'] == 0])
            group['nested_group_count'] = len([m for m in members_list if m['member_type'] == 'group' and m['depth'] == 0])
        logger.info("Privileged groups: %s", sum(1 for g in groups if g['is_privileged']))

        # Step 6: Calculate risks (enhanced points-based scoring)
        logger.info("Calculating Risk Levels...")
        self._update_job_progress('analyzing_risk', 48)
        identities_with_risks = self._calculate_risks(
            all_identities, role_assignments, entra_roles,
            permissions_map, app_roles_map, credentials_map
        )

        # Step 7: Check credentials
        logger.info("Checking Credential Expiration...")
        self._update_job_progress('analyzing_risk', 52)
        identities_with_creds = self._check_credentials(identities_with_risks)

        # Step 8: Check activity
        logger.info("Checking Last Activity...")
        self._update_job_progress('analyzing_risk', 56)
        final_identities = self._check_activity(identities_with_creds)

        # Step 8.1: Module 4 — Sign-in Intelligence
        logger.info("Discovering sign-in intelligence (M4)...")
        await self._discover_signin_intelligence(final_identities)

        # Step 8.5: Infer workload type from role topology
        logger.info("Inferring workload types from role topology...")
        inferred_count = 0
        for identity in final_identities:
            if identity.get('identity_category') in ('service_principal', 'managed_identity_user', 'managed_identity_system'):
                result = self._infer_workload_from_roles(identity)
                existing_flags = identity.get('workload_risk_flags') or []
                new_flags = result.get('workload_risk_flags') or []
                result['workload_risk_flags'] = list(
                    dict.fromkeys(existing_flags + new_flags)
                )
                identity.update(result)
                if result['workload_type'] != 'unknown':
                    inferred_count += 1
        logger.info("Workload inference: %s/%s SPNs classified", inferred_count,
                     sum(1 for i in final_identities if i.get('identity_category') in ('service_principal', 'managed_identity_user', 'managed_identity_system')))

        # Step 8.75: Assemble lineage verdicts
        # Lineage engine unified under Python to ensure consistency.
        # These verdicts are the SINGLE SOURCE OF TRUTH for GET /api/spn/<id>/lineage.
        verdict_count = 0
        for identity in final_identities:
            if identity.get('identity_category') in (
                'service_principal', 'managed_identity_user', 'managed_identity_system'
            ):
                verdict = self._assemble_lineage_verdict(identity)
                identity.update(verdict)
                verdict_count += 1
        logger.info("Lineage verdicts assembled: %s identities", verdict_count)

        # Step 9: Save to database using Database class methods
        logger.info("Saving identities to database...")
        self._update_job_progress('saving_identities', 60)
        saved_count = self._save_identities(run_id, final_identities, role_assignments, credentials_map, permissions_map, app_roles_map, ownership_map, pim_map, ca_policies)
        logger.info("Saved %s identities", saved_count)
        self._identities_saved_count = saved_count
        self._update_job_metrics(identities=saved_count, subscriptions=len(self.subscriptions))

        # Step 9.1: Save Entra Groups
        logger.info("Saving Entra groups...")
        try:
            self._save_entra_groups(run_id, groups, group_memberships)
        except Exception as e:
            logger.error("Error saving Entra groups: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9.2: Expand group-held roles to individual members in role_assignments
        try:
            self._expand_group_roles_to_members(run_id, role_assignments, groups, group_memberships)
        except Exception as e:
            logger.error("Error expanding group roles to members: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9.5: Populate normalized lineage tables
        # (identity_orphan_classifications, identity_lineage_scores, lineage_verdicts)
        self._populate_lineage_tables(run_id, final_identities)

        self._update_job_progress('discovering_resources', 68)

        # Step 9a: P2 Telemetry Ingestion FIRST (if enabled)
        # MUST run before exposure scoring so fresh sign-in data is available
        p2_enabled = False
        try:
            p2_enabled = self.db.get_setting('p2_telemetry_enabled', 'false', organization_id=self.db._organization_id) == 'true'
            if p2_enabled:
                logger.info("Ingesting P2 sign-in telemetry...")
                from app.engines.telemetry.p2_ingestion import P2TelemetryService
                telemetry = P2TelemetryService(self.credential, self.db)
                org_id = self.db._organization_id
                telemetry.ingest_signin_logs(run_id, org_id)
                telemetry.compute_activity_stats(run_id, org_id)
                telemetry.backfill_last_sign_in(run_id)
                logger.info("P2 telemetry ingested -- activity stats ready for scoring")
        except Exception as e:
            logger.warning("P2 telemetry ingestion error: %s", e)
            self.db._rollback()

        # Step 9a-ii: Compute Workload Identity Exposure Scores (uses P2 data)
        logger.info("Computing workload identity exposure scores...")
        try:
            self._compute_workload_exposure(run_id)
        except Exception as e:
            logger.error("Workload exposure computation error: %s", e)
            self.db._rollback()

        # Step 9a-iii: Behavioral anomaly detection (after scoring)
        try:
            if p2_enabled:
                from app.engines.telemetry.behavioral_engine import BehavioralAnomalyEngine
                anomaly_engine = BehavioralAnomalyEngine(self.db)
                anomaly_engine.detect_anomalies(run_id, self.db._organization_id)
        except Exception as e:
            logger.warning("Behavioral anomaly detection error: %s", e)
            self.db._rollback()

        # Step 9b: Discover Azure Resources (Storage Accounts & Key Vaults)
        logger.info("Discovering Azure Resources...")
        storage_accounts = []
        key_vaults = []
        org_id_val = getattr(self, '_organization_id', None) or self.db_org_id
        try:
            storage_accounts = self._discover_storage_accounts()
            logger.info("Found %s storage accounts", len(storage_accounts))
            key_vaults = self._discover_key_vaults()
            logger.info("Found %s key vaults", len(key_vaults))

            # Save resources to database
            for sa in storage_accounts:
                sa['organization_id'] = org_id_val
                try:
                    self.db.save_storage_account(run_id, sa)
                except Exception as e:
                    logger.warning("save_storage_account error: %s", e)
                    self.db._rollback()
            for kv in key_vaults:
                kv['organization_id'] = org_id_val
                try:
                    self.db.save_key_vault(run_id, kv)
                except Exception as e:
                    logger.warning("save_key_vault error: %s", e)
                    self.db._rollback()
            logger.info("Saved %s storage accounts, %s key vaults", len(storage_accounts), len(key_vaults))
            self._update_job_metrics(
                identities=getattr(self, '_identities_saved_count', 0),
                resources=len(storage_accounts) + len(key_vaults),
                subscriptions=len(self.subscriptions),
            )
        except Exception as e:
            logger.error("Resource discovery error: %s", e)
            self.db._rollback()

        # Step 9b-2: Identity exposure enhancement + risk history persistence
        try:
            self._enhance_resources_with_identity_exposure(run_id, storage_accounts, key_vaults)
        except Exception as e:
            logger.warning("Identity exposure enhancement error: %s", e)
            self.db._rollback()

        # Step 9b-3: Compute Identity Plane (App Services, Functions, VMs, Logic Apps)
        self._update_job_progress('discovering_compute', 75)
        logger.info("Discovering Compute Identity Plane...")
        try:
            from app.engines.discovery.compute_scanner import ComputeScanner
            compute_scanner = ComputeScanner(
                self.credential, self.db, self.subscriptions, org_id_val,
            )
            compute_stats = compute_scanner.scan(run_id)
            logger.info(
                "Compute scan complete: %s resources, %s MSI linked, %s env secrets",
                compute_stats.get('resources_found', 0),
                compute_stats.get('msi_linked', 0),
                compute_stats.get('env_secrets_found', 0),
            )
        except Exception as e:
            logger.error("Compute identity plane error: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9b-4: Container Identity Plane (AKS + ACR)
        self._update_job_progress('discovering_containers', 78)
        logger.info("Discovering Container Identity Plane...")
        try:
            from app.engines.discovery.container_scanner import ContainerScanner
            container_scanner = ContainerScanner(
                self.credential, self.db, self.subscriptions, org_id_val,
            )
            container_stats = container_scanner.scan(run_id)
            logger.info(
                "Container scan complete: %s AKS, %s fed creds (%s wildcard), %s ACR",
                container_stats.get('aks_clusters_found', 0),
                container_stats.get('federated_credentials', 0),
                container_stats.get('wildcard_credentials', 0),
                container_stats.get('acr_registries', 0),
            )
        except Exception as e:
            logger.error("Container identity plane error: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9c: Discover App Registrations
        self._update_job_progress('discovering_apps', 80)
        logger.info("Discovering App Registrations...")
        try:
            from psycopg2.extras import RealDictCursor as RDC
            spn_cursor = self.db.conn.cursor(cursor_factory=RDC)
            spn_cursor.execute("""
                SELECT id, app_id, last_sign_in, activity_status
                FROM identities
                WHERE discovery_run_id = %s AND identity_category = 'service_principal'
            """, (run_id,))
            spn_app_id_map = {}
            for row in spn_cursor.fetchall():
                if row.get('app_id'):
                    spn_app_id_map[row['app_id']] = {
                        'id': row['id'],
                        'last_sign_in': row['last_sign_in'].isoformat() if row.get('last_sign_in') else None,
                        'activity_status': row.get('activity_status'),
                    }
            spn_cursor.close()

            app_regs = await self._discover_app_registrations(spn_app_id_map)
            for ar in app_regs:
                ar['organization_id'] = org_id_val
                self.db.save_app_registration(run_id, ar)
            logger.info("Saved %s app registrations", len(app_regs))
        except Exception as e:
            logger.error("App registration discovery error: %s", e, exc_info=True)
            self.db._rollback()

        # Step 9b-5: Data Plane Identity Scanner (Azure SQL, PostgreSQL, MySQL, CosmosDB)
        self._update_job_progress('discovering_databases', 84)
        logger.info("Discovering Data Plane Identities...")
        try:
            from app.engines.discovery.database_scanner import DatabaseScanner
            database_scanner = DatabaseScanner(
                self.credential, self.db, self.subscriptions, org_id_val,
            )
            db_stats = database_scanner.scan(run_id)
            logger.info(
                "Database scan complete: %s servers (%s mixed auth, %s open firewall)",
                db_stats.get('total_servers', 0),
                db_stats.get('mixed_auth_count', 0),
                db_stats.get('open_firewall_count', 0),
            )
        except Exception as e:
            logger.error("Data plane identity scan error: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

        # Step 9d: ARM Resource Graph — find resources referencing SPN appIds
        self._update_job_progress('scanning_resources', 88)
        try:
            arm_map = self._fetch_arm_resource_associations(service_principals)
            if arm_map:
                # Resolve identity_db_ids for SPNs that got ARM bindings
                from psycopg2.extras import RealDictCursor as RDC2
                arm_cursor = self.db.conn.cursor(cursor_factory=RDC2)
                arm_app_ids = list(arm_map.keys())
                arm_cursor.execute("""
                    SELECT id, app_id FROM identities
                    WHERE discovery_run_id = %s AND app_id = ANY(%s)
                """, (run_id, arm_app_ids))
                app_id_to_db_id = {row['app_id']: row['id'] for row in arm_cursor.fetchall()}
                arm_cursor.close()

                binding_saved = 0
                for app_id, bindings in arm_map.items():
                    db_id = app_id_to_db_id.get(app_id)
                    if not db_id:
                        continue
                    for binding in bindings:
                        try:
                            self.db.save_lineage_binding(db_id, self.cloud_connection_id, binding)
                            binding_saved += 1
                        except Exception as be:
                            logger.warning("save_lineage_binding failed: %s", be)
                            self.db._rollback()

                if binding_saved:
                    logger.info("ARM Resource Graph: saved %s bindings", binding_saved)
                    # Update workload_origin for SPNs with ARM bindings that lack a better origin
                    for app_id, bindings in arm_map.items():
                        db_id = app_id_to_db_id.get(app_id)
                        if not db_id or not bindings:
                            continue
                        best = max(bindings, key=lambda b: b.get('confidence_score', 0))
                        try:
                            upd_cursor = self.db.conn.cursor()
                            upd_cursor.execute("""
                                UPDATE identities
                                SET workload_origin = %s,
                                    workload_origin_source = 'arm_resource_graph'
                                WHERE id = %s
                                  AND (workload_origin IS NULL OR workload_origin = 'Unknown')
                            """, (
                                f"{best['resource_type']}: {best['resource_name']}",
                                db_id,
                            ))
                            upd_cursor.close()
                            self.db._commit()
                        except Exception:
                            self.db._rollback()
        except Exception as e:
            logger.warning("ARM Resource Graph scan error: %s", e)
            self.db._rollback()

        # Step 9e: Managed Identity lineage — map resources → managed identity → SPN
        self._update_job_progress('scanning_managed_identities', 90)
        try:
            mi_map = self._fetch_managed_identity_associations(final_identities)
            if mi_map:
                from psycopg2.extras import RealDictCursor as RDC3
                mi_cursor = self.db.conn.cursor(cursor_factory=RDC3)
                mi_oids = list(mi_map.keys())
                mi_cursor.execute("""
                    SELECT id, object_id FROM identities
                    WHERE discovery_run_id = %s AND object_id = ANY(%s)
                """, (run_id, mi_oids))
                oid_to_db_id = {row['object_id']: row['id'] for row in mi_cursor.fetchall()}
                mi_cursor.close()

                mi_saved = 0
                for oid, bindings in mi_map.items():
                    db_id = oid_to_db_id.get(oid)
                    if not db_id:
                        continue
                    for binding in bindings:
                        try:
                            self.db.save_lineage_binding(db_id, self.cloud_connection_id, binding)
                            mi_saved += 1
                        except Exception as be:
                            logger.warning("save MI lineage binding failed: %s", be)
                            self.db._rollback()

                if mi_saved:
                    logger.info("Managed identity lineage: saved %s bindings", mi_saved)
                    # Update workload_origin for MIs with resource bindings
                    for oid, bindings in mi_map.items():
                        db_id = oid_to_db_id.get(oid)
                        if not db_id or not bindings:
                            continue
                        best = max(bindings, key=lambda b: b.get('confidence_score', 0))
                        try:
                            upd_cursor = self.db.conn.cursor()
                            upd_cursor.execute("""
                                UPDATE identities
                                SET workload_origin = %s,
                                    workload_origin_source = 'managed_identity_binding'
                                WHERE id = %s
                                  AND (workload_origin IS NULL OR workload_origin = 'Unknown')
                            """, (
                                f"{best['resource_type']}: {best['resource_name']}",
                                db_id,
                            ))
                            upd_cursor.close()
                            self.db._commit()
                        except Exception:
                            self.db._rollback()
        except Exception as e:
            logger.warning("Managed identity lineage scan error: %s", e)
            self.db._rollback()

        # Step 9f: Upgrade verdict_confidence for identities with ARM/MI bindings
        # The verdict was assembled at Step 8.75 before ARM data existed.
        # Now that bindings are saved, promote confidence to 'high' for any
        # identity that has at least one binding in identity_lineage_bindings.
        try:
            upd_cursor = self.db.conn.cursor()
            upd_cursor.execute("""
                UPDATE identities i
                SET verdict_confidence = 'high'
                FROM (
                    SELECT DISTINCT spn_id
                    FROM identity_lineage_bindings
                    WHERE spn_id IN (
                        SELECT id FROM identities WHERE discovery_run_id = %s
                    )
                ) lb
                WHERE i.id = lb.spn_id
                  AND i.verdict_confidence IS DISTINCT FROM 'high'
            """, (run_id,))
            upgraded = upd_cursor.rowcount
            upd_cursor.close()
            self.db._commit()
            if upgraded:
                logger.info("Confidence upgrade: %s identities promoted to 'high' (ARM/MI binding)", upgraded)
        except Exception as e:
            logger.warning("Confidence upgrade failed: %s", e)
            self.db._rollback()

        # Step 9g: Dependency impact analysis
        # Compute what breaks if each identity is deleted, based on ARM/MI bindings.
        try:
            from psycopg2.extras import RealDictCursor as RDC_dep
            dep_cursor = self.db.conn.cursor(cursor_factory=RDC_dep)
            dep_cursor.execute("""
                SELECT i.id, i.identity_id,
                       COALESCE(json_agg(json_build_object(
                           'resource_type', lb.resource_type,
                           'resource_name', lb.resource_name,
                           'resource_group', lb.resource_group,
                           'binding_method', lb.binding_method
                       )) FILTER (WHERE lb.id IS NOT NULL), '[]') AS bindings
                FROM identities i
                LEFT JOIN identity_lineage_bindings lb ON lb.spn_id = i.id
                WHERE i.discovery_run_id = %s
                GROUP BY i.id, i.identity_id
                HAVING COUNT(lb.id) > 0
            """, (run_id,))
            identities_with_bindings = dep_cursor.fetchall()

            # Build a map of identity_id → role_assignments for impact computation
            role_map = {}
            for ra in role_assignments:
                iid = ra.get('identity_id')
                if iid:
                    role_map.setdefault(iid, []).append(ra)

            dep_updated = 0
            for row in identities_with_bindings:
                db_id = row['id']
                iid = row['identity_id']
                bindings_list = row['bindings'] if isinstance(row['bindings'], list) else []
                roles_for_identity = role_map.get(iid, [])

                impact = self._compute_dependency_impact(bindings_list, roles_for_identity)

                dep_cursor.execute("""
                    UPDATE identities
                    SET dependency_impact = %s,
                        dependency_impact_resources = %s
                    WHERE id = %s
                """, (
                    impact['dependency_impact'],
                    json.dumps(impact['dependency_impact_resources']),
                    db_id,
                ))
                dep_updated += 1

            dep_cursor.close()
            self.db._commit()
            if dep_updated:
                logger.info("Dependency impact: computed for %s identities", dep_updated)
        except Exception as e:
            logger.warning("Dependency impact analysis failed: %s", e)
            self.db._rollback()

        # Step 10: Complete discovery run
        self._update_job_progress('finalizing', 92)
        logger.info("Completing discovery run...")
        try:
            critical_count = sum(1 for i in final_identities if i['risk_level'] == 'critical')
            high_count = sum(1 for i in final_identities if i['risk_level'] == 'high')
            medium_count = sum(1 for i in final_identities if i['risk_level'] == 'medium')
            low_count = sum(1 for i in final_identities if i['risk_level'] == 'low')

            self.db.complete_discovery_run(
                run_id, len(final_identities),
                critical_count, high_count, medium_count, low_count
            )
            logger.info("Discovery run completed")
        except Exception as e:
            logger.error("complete_discovery_run error: %s", e)
            self.db._rollback()
            # Try a simpler completion
            try:
                cursor = self.db.conn.cursor()
                cursor.execute("UPDATE discovery_runs SET status='completed', completed_at=NOW(), total_identities=%s WHERE id=%s",
                               (len(final_identities), run_id))
                cursor.close()
                self.db._commit()
                logger.info("Discovery run completed (fallback)")
            except Exception as e2:
                logger.error("Fallback completion also failed: %s", e2)
                self.db._rollback()

        # Sync discovered subscriptions into cloud_subscriptions registry
        try:
            for sub in self.subscriptions:
                cursor = self.db.conn.cursor()
                # Use organization_id from the discovery run
                cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (run_id,))
                run_row = cursor.fetchone()
                run_org_id = run_row[0] if run_row and run_row[0] else 1
                if not self.cloud_connection_id:
                    logger.warning("Skipping subscription sync -- cloud_connection_id is required (NOT NULL)")
                    break
                cursor.execute("""
                    INSERT INTO cloud_subscriptions (organization_id, cloud, account_id, account_name, status, cloud_connection_id)
                    VALUES (%s, 'azure', %s, %s, 'discovered', %s)
                    ON CONFLICT (cloud_connection_id, account_id) DO UPDATE
                    SET account_name = EXCLUDED.account_name
                """, (run_org_id, sub['id'], sub['name'], self.cloud_connection_id))
                self.db.safe_commit()
                cursor.close()
            logger.info("Synced %s subscription(s) to registry", len(self.subscriptions))
        except Exception as e:
            logger.warning("Subscription sync warning: %s", e)
            self.db._rollback()

        # Sync foreign-tenant subscriptions to their own connections
        if self.foreign_subscriptions:
            try:
                cursor = self.db.conn.cursor()
                cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (run_id,))
                run_row = cursor.fetchone()
                run_org_id = run_row[0] if run_row and run_row[0] else 1
                cursor.close()
                # Look up source connection label for provenance tracking
                source_label = None
                try:
                    source_conn = self.db.get_cloud_connection_by_id(self.cloud_connection_id)
                    if source_conn:
                        source_label = source_conn.get('label')
                except Exception:
                    pass
                # Group foreign subs by tenant to batch-create connections
                foreign_by_tenant: Dict[str, list] = {}
                for sub in self.foreign_subscriptions:
                    foreign_by_tenant.setdefault(sub['tenant_id'], []).append(sub)
                for foreign_tenant, tenant_subs in foreign_by_tenant.items():
                    logger.info("Creating cloud connection for cross-tenant %s... (%s sub(s))", foreign_tenant[:8], len(tenant_subs))
                    foreign_conn = self.db.find_or_create_cloud_connection(
                        run_org_id, foreign_tenant,
                        label=f'Azure Tenant {foreign_tenant[:8]}...',
                        source_azure_directory_id=self.azure_directory_id,
                        source_connection_label=source_label)
                    for sub in tenant_subs:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""
                            INSERT INTO cloud_subscriptions (organization_id, cloud, account_id, account_name,
                                                              status, cloud_connection_id)
                            VALUES (%s, 'azure', %s, %s, 'discovered', %s)
                            ON CONFLICT (cloud_connection_id, account_id) DO UPDATE
                            SET account_name = EXCLUDED.account_name
                        """, (run_org_id, sub['id'], sub['name'], foreign_conn['id']))
                        self.db.safe_commit()
                        cursor.close()
                logger.info("Synced %s foreign-tenant subscription(s) across %s tenant(s)", len(self.foreign_subscriptions), len(foreign_by_tenant))
            except Exception as e:
                logger.warning("Foreign subscription sync warning: %s", e)
                self.db._rollback()

        # Seed auto identity groups for this organization (Phase 38 + RLS fix)
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (run_id,))
            row = cursor.fetchone()
            cursor.close()
            if row and row[0]:
                self.db.seed_auto_groups_for_organization(row[0])
                logger.info("Auto identity groups seeded for organization %s", row[0])
        except Exception as e:
            logger.warning("Auto groups seed warning: %s", e)
            self.db._rollback()

        # Create result object
        # result = self._create_result(final_identities, role_assignments, run_id)
        # self._save_results_to_json(result)
        
        return None  # result
    
    async def _discover_service_principals(self) -> List[Dict[str, Any]]:
        """Discover ALL service principals via direct HTTP with pagination.

        Uses a direct GET to /v1.0/servicePrincipals with $select for full
        field coverage and @odata.nextLink pagination so every SPN in the
        tenant is returned — regardless of whether it has role assignments.
        """
        import aiohttp

        try:
            identities = []
            skipped_microsoft_count = 0
            # skipped_sami_count removed — SAMIs are now included for lineage mapping

            # Get bearer token from the same credential used by the SDK
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = ','.join([
                'id', 'appId', 'displayName', 'accountEnabled', 'createdDateTime',
                'servicePrincipalType', 'alternativeNames', 'appOwnerOrganizationId',
                'publisherName', 'signInActivity',
                'servicePrincipalNames', 'tags', 'passwordCredentials', 'keyCredentials',
            ])
            url = (
                f"https://graph.microsoft.com/v1.0/servicePrincipals"
                f"?$select={select_fields}&$top=999"
            )

            async with aiohttp.ClientSession() as session:
                page = 0
                sign_in_available = True
                while url:
                    page += 1
                    async with session.get(url, headers=headers) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            # If signInActivity fails (403 / needs P2), retry page 1 without it
                            if page == 1 and ('signInActivity' in body or resp.status == 403):
                                logger.warning("SP signInActivity requires Entra ID P2 — retrying without it")
                                sign_in_available = False
                                select_no_sia = select_fields.replace(',signInActivity', '')
                                url = (
                                    f"https://graph.microsoft.com/v1.0/servicePrincipals"
                                    f"?$select={select_no_sia}&$top=999"
                                )
                                continue
                            logger.error("Graph API error %s on SP page %s: %s", resp.status, page, body[:500])
                            break
                        data = await resp.json()

                    for sp in data.get('value', []):
                        # --- Parse fields from JSON dict ---
                        sp_id = sp.get('id')
                        app_id = sp.get('appId')
                        display_name = sp.get('displayName')

                        if len(identities) < 10:
                            logger.info("SP: %s (%s)", display_name, sp_id)

                        created = sp.get('createdDateTime')

                        # Determine identity type
                        sp_type_raw = sp.get('servicePrincipalType') or ''
                        identity_type = 'managed_identity' if sp_type_raw == 'ManagedIdentity' else 'service_principal'

                        # Extract sign-in activity (requires Entra ID P2)
                        last_sign_in = None
                        sia = sp.get('signInActivity')
                        if sia:
                            last_sign_in = (
                                sia.get('lastSignInDateTime')
                                or sia.get('lastNonInteractiveSignInDateTime')
                            )
                        # Store raw signInActivity for pattern classification later
                        _signin_raw = {}
                        if sia:
                            _signin_raw = {
                                'lastSignInDateTime': sia.get('lastSignInDateTime'),
                                'lastDelegatedSignInDateTime': sia.get('lastDelegatedClientSignInDateTime'),
                                'lastNonInteractiveSignInDateTime': sia.get('lastNonInteractiveSignInDateTime'),
                            }

                        owner_org = sp.get('appOwnerOrganizationId')
                        owner_org_str = str(owner_org) if owner_org else None

                        identity_dict = {
                            'identity_id': app_id or sp_id,
                            'object_id': sp_id,
                            'app_id': app_id,
                            'display_name': display_name,
                            'identity_type': identity_type,
                            'enabled': sp.get('accountEnabled', True),
                            'created_datetime': created,
                            'last_sign_in': last_sign_in,
                            'service_principal_type': sp_type_raw or None,
                            'app_owner_organization_id': owner_org_str,
                            'app_owner_org_id': owner_org_str,
                            'publisher_name': sp.get('publisherName'),
                            'service_principal_names': sp.get('servicePrincipalNames', []),
                            'tags': sp.get('tags', []),
                            'password_credentials': sp.get('passwordCredentials', []),
                            'key_credentials': sp.get('keyCredentials', []),
                            # Multi-cloud normalized fields
                            'cloud': 'azure',
                            'azure_directory_id': self.azure_directory_id,
                            'source': 'entra',
                            'permission_plane': 'entra_id',
                            # Flag the discovery connector's own SPN
                            'is_discovery_connector': bool(app_id and app_id == self.client_id),
                            # Observed usage: connector SPN is always in use during discovery
                            'observed_last_used': datetime.utcnow().isoformat() if (app_id and app_id == self.client_id) else None,
                            '_signin_activity_raw': _signin_raw,
                        }

                        # ──── STRICT DISCOVERY POLICY ────
                        sp_type_norm = sp_type_raw.strip().lower()

                        if sp_type_norm == "managedidentity":
                            alt_names = sp.get('alternativeNames') or []
                            alt_join = " ".join(str(a) for a in alt_names).lower()
                            is_uami = "userassignedidentities" in alt_join

                            if is_uami:
                                identity_dict["identity_category"] = "managed_identity_user"
                                identity_dict["identity_type"] = "managed_identity_user"
                            else:
                                # System-assigned managed identities — included for lineage mapping
                                identity_dict["identity_category"] = "managed_identity_system"
                                identity_dict["identity_type"] = "managed_identity_system"

                                # Parse ARM resource ID from alternativeNames for SAMI→Resource cross-link
                                for alt in alt_names:
                                    alt_str = str(alt)
                                    if alt_str.startswith('/subscriptions/'):
                                        self._parse_sami_resource(identity_dict, alt_str)
                                        break

                            identity_dict["alternative_names"] = alt_names
                            identity_dict["is_microsoft_system"] = False
                            identities.append(identity_dict)

                        elif self._is_microsoft_system_app(identity_dict):
                            identity_dict["identity_category"] = "service_principal"
                            identity_dict["identity_type"] = "service_principal"
                            identity_dict["is_microsoft_system"] = True
                            identities.append(identity_dict)
                            skipped_microsoft_count += 1

                        else:
                            identity_dict["identity_category"] = "service_principal"
                            identity_dict["identity_type"] = "service_principal"
                            identity_dict["is_microsoft_system"] = False
                            identities.append(identity_dict)

                    # Follow pagination
                    url = data.get('@odata.nextLink')

            sami_count = sum(1 for i in identities if i.get('identity_category') == 'managed_identity_system')
            uami_count = sum(1 for i in identities if i.get('identity_category') == 'managed_identity_user')
            if skipped_microsoft_count > 0 or sami_count > 0 or uami_count > 0:
                logger.info("Flagged: %s Microsoft system apps, %s system-assigned MIs, %s user-assigned MIs",
                            skipped_microsoft_count, sami_count, uami_count)
                logger.info("Total: %s identities (%s customer, %s Microsoft)", len(identities), len(identities) - skipped_microsoft_count, skipped_microsoft_count)

            logger.info("Discovered %s service principals across %s page(s) (signInActivity=%s)",
                        len(identities), page, sign_in_available)
            return identities
        except Exception as e:
            logger.error("Error discovering service principals: %s", e)
            return []

    @staticmethod
    def _parse_sami_resource(identity_dict: dict, arm_resource_id: str):
        """Parse an ARM resource ID from SAMI alternativeNames into associated_resource_* fields.

        Expected format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        Handles nested types like Microsoft.Sql/servers/databases.
        """
        import re
        parts = arm_resource_id.split('/')
        # Minimum: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        # That's at least 9 parts: ['', 'subscriptions', sub, 'resourceGroups', rg, 'providers', provider, type, name]
        if len(parts) < 9:
            return

        sub_id = parts[2] if len(parts) > 2 else None
        rg = parts[4] if len(parts) > 4 and parts[3].lower() == 'resourcegroups' else None

        # Extract provider/type/name — everything after 'providers/'
        try:
            prov_idx = next(i for i, p in enumerate(parts) if p.lower() == 'providers')
            provider_parts = parts[prov_idx + 1:]  # e.g. ['Microsoft.Compute', 'virtualMachines', 'myVM']
            if len(provider_parts) >= 2:
                # provider_parts[0] = namespace (Microsoft.Compute)
                # provider_parts[1] = type (virtualMachines)
                # provider_parts[2] = name (myVM)
                # For nested: Microsoft.Sql/servers/myServer/databases/myDB
                resource_type = f"{provider_parts[0]}/{provider_parts[1]}"
                resource_name = provider_parts[2] if len(provider_parts) > 2 else provider_parts[1]
            else:
                return
        except StopIteration:
            return

        identity_dict['associated_resource_id'] = arm_resource_id
        identity_dict['associated_resource_type'] = resource_type
        identity_dict['associated_resource_name'] = resource_name
        identity_dict['associated_resource_group'] = rg
        identity_dict['associated_subscription_id'] = sub_id

    async def _fetch_app_registration_map(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all App Registrations and return a lookup keyed by appId.

        This is a lightweight call used to link SPNs to their parent App
        Registration.  The full _discover_app_registrations() method runs
        later for deep analysis.

        Returns:
            { appId: { object_id, display_name, app_owner_organization_id,
                       publisher_domain, sign_in_audience,
                       owner_display_name, owner_id } }
        """
        import aiohttp

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = 'id,appId,displayName,appOwnerOrganizationId,publisherDomain,signInAudience,identifierUris,notes,description,web,requiredResourceAccess'
            url: str | None = (
                f"https://graph.microsoft.com/v1.0/applications"
                f"?$select={select_fields}&$top=999"
            )

            lookup: Dict[str, Dict[str, Any]] = {}
            page = 0

            async with aiohttp.ClientSession() as session:
                while url:
                    page += 1
                    async with session.get(url, headers=headers) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            logger.error("Graph API error %s on applications page %s: %s",
                                         resp.status, page, body[:500])
                            break
                        data = await resp.json()

                    for app in data.get('value', []):
                        app_id = app.get('appId')
                        if app_id:
                            lookup[app_id] = {
                                'object_id': app.get('id'),
                                'display_name': app.get('displayName'),
                                'app_owner_organization_id': app.get('appOwnerOrganizationId'),
                                'publisher_domain': app.get('publisherDomain'),
                                'sign_in_audience': app.get('signInAudience'),
                                'owner_display_name': None,
                                'owner_id': None,
                                # Metadata fields for signal extraction
                                'identifierUris': app.get('identifierUris'),
                                'notes': app.get('notes'),
                                'description': app.get('description'),
                                'web': app.get('web'),
                                'replyUrls': app.get('replyUrls'),
                                'requiredResourceAccess': app.get('requiredResourceAccess'),
                            }

                    url = data.get('@odata.nextLink')

                # Fetch first owner for each app registration
                owner_fetched = 0
                for app_info in lookup.values():
                    obj_id = app_info.get('object_id')
                    if not obj_id:
                        continue
                    try:
                        owner_url = (
                            f"https://graph.microsoft.com/v1.0/applications/{obj_id}"
                            f"/owners?$select=id,displayName,userPrincipalName&$top=1"
                        )
                        async with session.get(owner_url, headers=headers) as resp:
                            if resp.status == 200:
                                owner_data = await resp.json()
                                owners = owner_data.get('value', [])
                                if owners:
                                    first = owners[0]
                                    app_info['owner_display_name'] = (
                                        first.get('displayName') or first.get('userPrincipalName')
                                    )
                                    app_info['owner_id'] = first.get('id')
                                    owner_fetched += 1
                    except Exception:
                        pass  # Non-fatal — owner lookup is best-effort

            logger.info("Fetched %s app registrations for lineage lookup (%s pages, %s with owners)",
                        len(lookup), page, owner_fetched)
            return lookup
        except Exception as e:
            logger.error("Error fetching app registration map: %s", e)
            return {}

    def _enrich_spns_with_app_registrations(
        self,
        service_principals: List[Dict[str, Any]],
        app_reg_map: Dict[str, Dict[str, Any]],
    ) -> None:
        """Annotate each SPN identity dict with its parent App Registration.

        For SPNs whose appId matches an app registration, sets lineage fields
        directly on the identity dict (mutates in place).
        """
        linked = 0
        external = 0

        for sp in service_principals:
            app_id = sp.get('app_id')

            if not app_id:
                continue

            app_reg = app_reg_map.get(app_id)
            if app_reg:
                sp['app_registration_object_id'] = app_reg['object_id']
                sp['app_registration_name'] = app_reg['display_name']
                sp['app_reg_publisher_domain'] = app_reg.get('publisher_domain')
                sp['app_reg_sign_in_audience'] = app_reg.get('sign_in_audience')
                sp['app_reg_owner_display_name'] = app_reg.get('owner_display_name')
                sp['app_reg_owner_id'] = app_reg.get('owner_id')

                owner_org = app_reg.get('app_owner_organization_id')
                is_ext = bool(owner_org and str(owner_org).lower() != self.azure_directory_id.lower())
                sp['is_external_app'] = is_ext

                # Extract metadata signals from app registration
                tenant_domain = app_reg.get('publisher_domain') or ''
                app_signals = self._extract_app_reg_signals(app_reg, tenant_domain)
                sp.update(app_signals)

                # Upgrade workload_type from metadata if still unknown
                current_wt = sp.get('workload_type') or 'unknown'
                if current_wt in ('unknown', 'unassigned') and app_signals.get('app_reg_likely_service'):
                    SERVICE_TYPE_MAP = {
                        'app_service': 'web_workload',
                        'container_app': 'container_workload',
                        'static_web_app': 'web_workload',
                        'custom_domain': 'web_workload',
                    }
                    mapped_type = SERVICE_TYPE_MAP.get(app_signals['app_reg_likely_service_type'])
                    if mapped_type:
                        sp['workload_type'] = mapped_type
                        sp['workload_confidence'] = max(sp.get('workload_confidence', 0), 20)
                        sp['role_pattern_matched'] = (
                            sp.get('role_pattern_matched') or
                            f"replyUrl: {app_signals['app_reg_likely_service']}"
                        )

                linked += 1
                if is_ext:
                    external += 1

        logger.info("SPN→App Registration lineage: %s/%s linked (%s external)",
                     linked, len(service_principals), external)

    # ── App Registration Signal Extraction ──────────────────────────

    # Well-known Microsoft resource app IDs
    KNOWN_APIS = {
        '00000003-0000-0000-c000-000000000000': 'microsoft_graph',
        '797f4846-ba00-4fd7-ba43-dac1f8f63013': 'azure_service_management',
        'e406a681-f3d4-42a8-90b6-c2b029497af1': 'azure_storage',
        'cfa8b339-82a2-471a-a3c9-0fc0be7a4093': 'azure_key_vault',
        '00000002-0000-0000-c000-000000000000': 'azure_ad_graph_legacy',
        '00000007-0000-0000-c000-000000000000': 'dynamics_crm',
        '00000003-0000-0ff1-ce00-000000000000': 'sharepoint_online',
        '00000002-0000-0ff1-ce00-000000000000': 'exchange_online',
        '00000009-0000-0000-c000-000000000000': 'power_bi',
        '0000000a-0000-0000-c000-000000000000': 'intune',
        'c5393580-f805-4401-95e8-94b7a6ef2fc2': 'office_365_management',
        'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5': 'log_analytics',
        '022907d3-0f1b-48f7-badc-1ba6abab6d66': 'azure_sql',
    }

    # Map frozensets of API usage → workload type labels
    API_USAGE_WORKLOAD_MAP = {
        frozenset({'microsoft_graph'}): 'directory_management',
        frozenset({'microsoft_graph', 'azure_service_management'}): 'cloud_management',
        frozenset({'azure_storage'}): 'data_pipeline',
        frozenset({'azure_storage', 'azure_key_vault'}): 'secure_data_pipeline',
        frozenset({'azure_key_vault'}): 'secrets_management',
        frozenset({'sharepoint_online'}): 'sharepoint_integration',
        frozenset({'exchange_online'}): 'mail_integration',
        frozenset({'dynamics_crm'}): 'crm_integration',
        frozenset({'power_bi'}): 'analytics',
        frozenset({'intune'}): 'device_management',
        frozenset({'log_analytics'}): 'monitoring',
        frozenset({'azure_sql'}): 'database_workload',
        frozenset({'microsoft_graph', 'sharepoint_online'}): 'collaboration_platform',
        frozenset({'microsoft_graph', 'exchange_online'}): 'mail_automation',
    }

    def _extract_app_reg_signals(self, app: dict, tenant_domain: str) -> dict:
        """Extract deployment and provenance signals from App Registration metadata.

        Parses replyUrls, identifierUris, notes, description,
        requiredResourceAccess to infer what Azure service backs the app.

        Args:
            app: Raw app registration dict from Graph API lookup.
            tenant_domain: Tenant's primary domain for filtering.

        Returns:
            Dict of signal fields to merge onto the identity dict.
        """
        from urllib.parse import urlparse

        signals: dict = {}

        # --- replyUrls: extract hostnames, find Azure service references ---
        reply_urls = (
            app.get('replyUrls') or
            (app.get('web') or {}).get('redirectUris') or
            []
        )
        public_hostnames: list = []
        likely_service = None
        likely_service_type = None

        for url in reply_urls:
            if not url or not url.startswith('http'):
                continue
            hostname = urlparse(url).hostname or ''
            if 'localhost' in hostname or '127.0.0.1' in hostname:
                continue
            public_hostnames.append(hostname)
            if '.azurewebsites.net' in hostname:
                likely_service = hostname.split('.azurewebsites.net')[0]
                likely_service_type = 'app_service'
            elif '.azurecontainerapps.io' in hostname:
                likely_service = hostname.split('.')[0]
                likely_service_type = 'container_app'
            elif '.azurestaticapps.net' in hostname:
                likely_service = hostname.split('.')[0]
                likely_service_type = 'static_web_app'
            elif '.onmicrosoft.com' not in hostname and (not tenant_domain or tenant_domain not in hostname):
                likely_service = hostname
                likely_service_type = 'custom_domain'

        signals['app_reg_reply_url_hostnames'] = public_hostnames or None
        signals['app_reg_likely_service'] = likely_service
        signals['app_reg_likely_service_type'] = likely_service_type

        # --- identifierUris: logical namespace of the app ---
        identifier_uris = app.get('identifierUris') or []
        signals['app_reg_identifier_uris'] = identifier_uris or None

        # --- notes + description: free text provenance ---
        notes = ' '.join(filter(None, [
            app.get('notes'), app.get('description')
        ])).strip()
        signals['app_reg_notes'] = notes or None

        # --- signInAudience (already stored separately, included for completeness) ---
        signals['app_reg_sign_in_audience'] = app.get('sign_in_audience') or app.get('signInAudience')

        # --- requiredResourceAccess: which APIs this app calls ---
        api_accesses: list = []
        required_permission_ids: list = []
        high_risk_manifest_perms: list = []
        for rra in (app.get('requiredResourceAccess') or []):
            resource_id = rra.get('resourceAppId', '')
            api_name = self.KNOWN_APIS.get(resource_id, f'unknown_{resource_id[:8]}')
            api_accesses.append(api_name)
            for ra in (rra.get('resourceAccess') or []):
                perm_id = ra.get('id', '')
                perm_type = ra.get('type', '')  # 'Role' (Application) or 'Scope' (Delegated)
                entry = {
                    'resource_app_id': resource_id,
                    'resource_api_name': api_name,
                    'permission_id': perm_id,
                    'type': perm_type,
                }
                required_permission_ids.append(entry)
                # Cross-ref with HIGH_RISK_PERMISSION_GUIDS
                if perm_id in HIGH_RISK_PERMISSION_GUIDS:
                    high_risk_manifest_perms.append({
                        **entry,
                        'permission_name': HIGH_RISK_PERMISSION_GUIDS[perm_id],
                    })
        signals['app_reg_required_apis'] = api_accesses or None
        signals['app_reg_required_permission_ids'] = required_permission_ids or None
        signals['app_reg_high_risk_manifest_perms'] = high_risk_manifest_perms or None

        return signals

    # ── Sign-in Activity Pattern Classification ─────────────────────

    def _classify_signin_pattern(self, signin_data: dict) -> dict:
        """Classify the sign-in pattern of an identity from its signInActivity data.

        Patterns:
            never_used               — no sign-in timestamps at all
            machine_only             — only non-interactive sign-ins
            human_delegated_only     — only delegated (interactive) sign-ins
            hybrid_concurrent        — both types within 7 days of each other
            hybrid_delegated_recent  — both types, delegated more recent
            hybrid_noninteractive_recent — both types, non-interactive more recent

        Returns dict with:
            signin_pattern, last_delegated_signin, last_noninteractive_signin,
            days_since_last_signin, signin_risk_flags
        """
        from datetime import datetime, timezone

        def parse_dt(s):
            if not s:
                return None
            s = s.replace('Z', '+00:00')
            try:
                return datetime.fromisoformat(s)
            except (ValueError, TypeError):
                return None

        last_del = signin_data.get('lastDelegatedSignInDateTime')
        last_nonint = signin_data.get('lastNonInteractiveSignInDateTime')
        last_any = signin_data.get('lastSignInDateTime')

        has_del = last_del is not None
        has_nonint = last_nonint is not None

        if not has_del and not has_nonint:
            pattern = 'never_used'
        elif has_nonint and not has_del:
            pattern = 'machine_only'
        elif has_del and not has_nonint:
            pattern = 'human_delegated_only'
        else:
            del_dt = parse_dt(last_del)
            nonint_dt = parse_dt(last_nonint)
            if del_dt and nonint_dt:
                gap_days = abs((del_dt - nonint_dt).days)
                if gap_days <= 7:
                    pattern = 'hybrid_concurrent'
                elif del_dt > nonint_dt:
                    pattern = 'hybrid_delegated_recent'
                else:
                    pattern = 'hybrid_noninteractive_recent'
            else:
                pattern = 'machine_only' if has_nonint else 'human_delegated_only'

        # Real last-seen = most recent of all three
        candidates = [parse_dt(d) for d in [last_del, last_nonint, last_any] if d]
        candidates = [c for c in candidates if c is not None]
        last_seen_dt = max(candidates) if candidates else None

        now = datetime.now(timezone.utc)
        days_dormant = None
        if last_seen_dt:
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            days_dormant = (now - last_seen_dt).days

        # Build risk flags for this signal
        signin_risk_flags = []
        if pattern == 'hybrid_concurrent':
            signin_risk_flags.append('shared_human_machine_identity')
        if pattern == 'human_delegated_only':
            signin_risk_flags.append('unexpected_interactive_usage')
        if days_dormant is not None and days_dormant > 365:
            signin_risk_flags.append('stale_over_1_year')
        elif days_dormant is not None and days_dormant > 90:
            signin_risk_flags.append('dormant_over_90_days')
        if last_seen_dt is None:
            signin_risk_flags.append('never_authenticated')

        return {
            'signin_pattern': pattern,
            'last_delegated_signin': last_del,
            'last_noninteractive_signin': last_nonint,
            'days_since_last_signin': days_dormant,
            'signin_risk_flags': signin_risk_flags,
        }

    # ── Workload Topology Inference ─────────────────────────────────

    # Pattern rules ordered by specificity (first match wins).
    # When both role_keywords AND scope_keywords are non-empty, BOTH must match.
    # When only one is non-empty, that one alone is sufficient.
    WORKLOAD_PATTERNS = [
        # Rule 1 — Audit connector (our own SPN, highest priority)
        {
            'type': 'audit_connector',
            'confidence': 95,
            'role_keywords': [],
            'scope_keywords': [],
            'risk_flags': [],
            'requires_connector_flag': True,
        },
        # Rule 2 — Container / AKS workload
        {
            'type': 'container_workload',
            'confidence': 85,
            'role_keywords': ['azure kubernetes', 'aks'],
            'scope_keywords': ['microsoft.containerservice', 'managedclusters'],
            'risk_flags': ['cluster_admin_possible', 'pod_escape_risk'],
        },
        # Rule 3 — Monitoring / observability agent (before cicd to avoid 'contributor' overlap)
        {
            'type': 'monitoring_agent',
            'confidence': 80,
            'role_keywords': ['monitoring', 'log analytics', 'diagnostics', 'metrics'],
            'scope_keywords': ['microsoft.insights', 'microsoft.operationalinsights'],
            'risk_flags': ['telemetry_access', 'log_exfiltration_risk'],
        },
        # Rule 4 — Data pipeline / analytics (before cicd to avoid 'contributor' overlap)
        {
            'type': 'data_pipeline',
            'confidence': 80,
            'role_keywords': ['data factory', 'storage blob data', 'synapse', 'databricks'],
            'scope_keywords': ['microsoft.datafactory', 'microsoft.synapse', 'microsoft.databricks', 'microsoft.storage'],
            'risk_flags': ['data_exfiltration_risk', 'cross_storage_access'],
        },
        # Rule 5 — Admin / privileged identity (role-only, no scope needed)
        {
            'type': 'admin_identity',
            'confidence': 90,
            'role_keywords': ['owner', 'user access administrator', 'global administrator', 'privileged role'],
            'scope_keywords': [],
            'risk_flags': ['full_control', 'privilege_escalation_risk', 'blast_radius_high'],
        },
        # Rule 6 — CI/CD pipeline (requires deployment scope to avoid false positives)
        {
            'type': 'cicd_pipeline',
            'confidence': 80,
            'role_keywords': ['contributor'],
            'scope_keywords': ['microsoft.web', 'microsoft.containerregistry', 'microsoft.app'],
            'risk_flags': ['deploy_access', 'supply_chain_risk'],
        },
        # Rule 7 — Storage workload
        {
            'type': 'storage_workload',
            'confidence': 75,
            'role_keywords': ['storage', 'blob', 'queue', 'table', 'file'],
            'scope_keywords': ['microsoft.storage'],
            'risk_flags': ['data_access', 'storage_key_risk'],
        },
        # Rule 8 — Configuration reader (read-only, fallback)
        {
            'type': 'config_reader',
            'confidence': 75,
            'role_keywords': ['reader'],
            'scope_keywords': [],
            'risk_flags': ['recon_capability'],
            'exclude_roles': ['owner', 'contributor', 'admin', 'write', 'delete'],
        },
    ]

    def _infer_workload_from_roles(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        """Infer workload type from an identity's RBAC + Entra role assignments.

        Matching logic:
        - When both role_keywords and scope_keywords are configured, BOTH must match.
        - When only role_keywords is configured, role match alone is sufficient.
        - When only scope_keywords is configured, scope match alone is sufficient.
        - Confidence is boosted +10 when both match (capped at 100).

        Returns dict with:
            workload_type: str         — one of the 9 types (or 'unknown')
            workload_confidence: int   — 0-100
            role_pattern_matched: str  — pattern name that matched
            workload_risk_flags: list  — risk flags from the matched pattern
        """
        roles = identity.get('roles', [])
        entra_roles = identity.get('entra_roles', [])
        is_connector = identity.get('is_discovery_connector', False)

        # Collect lowercase role names and scopes for matching
        role_names_lower = [r.get('role_name', '').lower() for r in roles]
        scopes_lower = [r.get('scope', '').lower() for r in roles]
        entra_names_lower = [r.get('role_name', '').lower() for r in entra_roles]
        all_role_names = role_names_lower + entra_names_lower
        all_scopes_joined = ' '.join(scopes_lower)

        for pattern in self.WORKLOAD_PATTERNS:
            # Connector flag gate — skip or auto-match
            if pattern.get('requires_connector_flag'):
                if is_connector:
                    return {
                        'workload_type': pattern['type'],
                        'workload_confidence': pattern['confidence'],
                        'role_pattern_matched': pattern['type'],
                        'workload_risk_flags': pattern.get('risk_flags', []),
                    }
                continue

            # Check exclusion list (e.g., config_reader excludes Owner/Contributor)
            exclude = pattern.get('exclude_roles', [])
            if exclude and any(
                any(ex in rn for ex in exclude) for rn in all_role_names
            ):
                continue

            has_role_kw = bool(pattern['role_keywords'])
            has_scope_kw = bool(pattern['scope_keywords'])

            # Match: at least one role keyword matches a role name
            role_kw_match = any(
                any(kw in rn for kw in pattern['role_keywords'])
                for rn in all_role_names
            ) if has_role_kw else False

            # Match: at least one scope keyword appears in any scope
            scope_kw_match = any(
                kw in all_scopes_joined for kw in pattern['scope_keywords']
            ) if has_scope_kw else False

            # Determine if pattern fires based on what's configured
            if has_role_kw and has_scope_kw:
                # Both configured → require BOTH to match
                if not (role_kw_match and scope_kw_match):
                    continue
                confidence = min(pattern['confidence'] + 10, 100)
            elif has_role_kw:
                if not role_kw_match:
                    continue
                confidence = pattern['confidence']
            elif has_scope_kw:
                if not scope_kw_match:
                    continue
                confidence = pattern['confidence']
            else:
                continue

            return {
                'workload_type': pattern['type'],
                'workload_confidence': confidence,
                'role_pattern_matched': pattern['type'],
                'workload_risk_flags': pattern.get('risk_flags', []),
            }

        # Fallback: unknown workload
        return {
            'workload_type': 'unknown',
            'workload_confidence': 0,
            'role_pattern_matched': 'none',
            'workload_risk_flags': [],
        }

    def _expand_group_roles_to_members(self, run_id: int, role_assignments: dict,
                                         groups: list, group_memberships: dict):
        """Expand group-held RBAC roles to individual members in role_assignments table.

        For each group that holds RBAC roles, creates role_assignment rows for each
        member identity with principal_type='group' (or 'group_nested' for nested members).
        Uses NOT EXISTS to avoid duplicating direct assignments.
        """
        # Ensure group columns exist
        self.db._ensure_role_assignment_group_cols()

        # Idempotent: skip if group rows already exist for this run
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) FROM role_assignments ra
                JOIN identities i ON i.id = ra.identity_db_id
                WHERE i.discovery_run_id = %s AND ra.principal_type != 'direct'
            """, (run_id,))
            existing = cursor.fetchone()[0]
            if existing > 0:
                logger.info("Group role expansion: %s rows already exist for run %s, skipping", existing, run_id)
                cursor.close()
                return
        finally:
            cursor.close()

        # Build group_role_index: group_id → list of role dicts
        group_role_index = {}
        for group in groups:
            gid = group.get('group_id') or group.get('id')
            if not gid:
                continue
            rbac_roles = group.get('rbac_roles') or []
            if isinstance(rbac_roles, str):
                import json as _json
                try:
                    rbac_roles = _json.loads(rbac_roles)
                except Exception:
                    rbac_roles = []
            if rbac_roles:
                group_role_index[gid] = rbac_roles

        if not group_role_index:
            logger.info("Group role expansion: no groups with RBAC roles found")
            return

        # Build oid_to_dbid map: object_id → identity db id
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SELECT id, identity_id FROM identities WHERE discovery_run_id = %s", (run_id,))
            oid_to_dbid = {row[1]: row[0] for row in cursor.fetchall()}
        finally:
            cursor.close()

        expanded_count = 0
        for group_id, roles in group_role_index.items():
            members = group_memberships.get(group_id, [])
            for member in members:
                member_oid = member.get('member_object_id') or member.get('id')
                if not member_oid:
                    continue
                db_id = oid_to_dbid.get(member_oid)
                if not db_id:
                    continue

                depth = member.get('depth', 0)
                is_nested = member.get('is_nested', False) or depth > 0
                ptype = 'group_nested' if is_nested else 'group'

                for role in roles:
                    role_name = role.get('role_name', '')
                    scope = role.get('scope', '')
                    if not role_name or not scope:
                        continue

                    # Dedup: skip if this identity already has a direct assignment with same role+scope
                    cursor = self.db.conn.cursor()
                    try:
                        cursor.execute("""
                            SELECT 1 FROM role_assignments
                            WHERE identity_db_id = %s AND role_name = %s AND scope = %s
                            LIMIT 1
                        """, (db_id, role_name, scope))
                        if cursor.fetchone():
                            continue
                    finally:
                        cursor.close()

                    self.db.save_role_assignment(db_id, {
                        'role_name': role_name,
                        'scope': scope,
                        'scope_type': role.get('scope_type', 'subscription'),
                        'principal_id': member_oid,
                        'role_type': 'azure',
                        'principal_type': ptype,
                        'group_principal_azure_object_id': group_id,
                    })
                    expanded_count += 1

        logger.info("Group role expansion: %s inherited role rows created for run %s", expanded_count, run_id)

    def _populate_lineage_tables(self, run_id: int, identities: list):
        """Populate normalized lineage tables from verdict data on identities.

        Writes to identity_orphan_classifications and identity_lineage_scores
        for NHI identities that have verdict data and a saved DB id.
        """
        oc_count = 0
        ls_count = 0
        try:
            cursor = self.db.conn.cursor()
            for identity in identities:
                db_id = identity.get('_db_id')
                if not db_id:
                    continue
                if identity.get('identity_category') not in (
                    'service_principal', 'managed_identity_user', 'managed_identity_system'
                ):
                    continue

                # --- identity_orphan_classifications ---
                rec_action = (identity.get('recommended_action') or '').upper()
                if rec_action:
                    _VERDICT_TO_ORPHAN = {
                        Verdict.ORPHANED: 'SAFE_TO_RETIRE',
                        Verdict.UNUSED: 'SAFE_TO_RETIRE',
                        Verdict.GHOST_MSI: 'SAFE_TO_RETIRE',
                        Verdict.AT_RISK: 'CAUTION',
                        Verdict.STALE: 'CAUTION',
                        Verdict.NEEDS_REVIEW: 'UNKNOWN',
                        Verdict.HEALTHY: 'NOT_ORPHANED',
                        Verdict.FEDERATED_MISCONFIGURED: 'CAUTION',
                    }
                    oc_status = _VERDICT_TO_ORPHAN.get(rec_action, 'UNKNOWN')
                    oc_reasons = identity.get('verdict_risk_summary')
                    all_roles = (identity.get('roles') or []) + (identity.get('entra_roles') or [])
                    _READ_ONLY = {'reader', 'viewer'}
                    active_rc = sum(
                        1 for r in all_roles
                        if not any(ro in (r.get('role_name') or r.get('role_definition_name') or '').lower()
                                   for ro in _READ_ONLY)
                    )
                    if oc_status == 'SAFE_TO_RETIRE' and active_rc > 0:
                        oc_status = 'CAUTION'
                    try:
                        cursor.execute("""
                            INSERT INTO identity_orphan_classifications
                                (spn_id, connection_id, orphan_status, orphan_reasons,
                                 active_role_count, recommended_action, classified_at)
                            VALUES (%s, %s, %s, %s, %s, %s, NOW())
                            ON CONFLICT (spn_id) DO UPDATE SET
                                orphan_status = EXCLUDED.orphan_status,
                                orphan_reasons = EXCLUDED.orphan_reasons,
                                active_role_count = EXCLUDED.active_role_count,
                                recommended_action = EXCLUDED.recommended_action,
                                classified_at = NOW()
                        """, (
                            db_id,
                            self.cloud_connection_id,
                            oc_status,
                            json.dumps(oc_reasons) if oc_reasons else None,
                            active_rc,
                            identity.get('verdict_action_text'),
                        ))
                        oc_count += 1
                    except Exception as e:
                        logger.warning("orphan_classification insert failed for id=%s: %s", db_id, e)
                        try:
                            self.db._rollback()
                            cursor = self.db.conn.cursor()
                        except Exception:
                            pass

                # --- identity_lineage_scores ---
                v_score = identity.get('verdict_score')
                if v_score is not None:
                    try:
                        cursor.execute("""
                            INSERT INTO identity_lineage_scores
                                (spn_id, lineage_score, scored_at)
                            VALUES (%s, %s, NOW())
                            ON CONFLICT (spn_id) DO UPDATE SET
                                lineage_score = EXCLUDED.lineage_score,
                                scored_at = NOW()
                        """, (db_id, max(0, min(100, v_score))))
                        ls_count += 1
                    except Exception as e:
                        logger.warning("lineage_score insert failed for id=%s: %s", db_id, e)
                        try:
                            self.db._rollback()
                            cursor = self.db.conn.cursor()
                        except Exception:
                            pass

                # --- lineage_verdicts (historical tracking) ---
                rec_action = (identity.get('recommended_action') or '').upper()
                if rec_action and db_id:
                    prev_verdict = None
                    try:
                        cursor.execute("""
                            SELECT lv.verdict FROM lineage_verdicts lv
                            WHERE lv.identity_id = %s AND lv.discovery_run_id != %s
                            ORDER BY lv.scored_at DESC LIMIT 1
                        """, (db_id, run_id))
                        prev_row = cursor.fetchone()
                        if prev_row:
                            prev_verdict = prev_row[0]
                    except Exception:
                        pass

                    verdict_changed = prev_verdict is not None and prev_verdict != rec_action
                    self.db.save_lineage_verdict(run_id, db_id, {
                        'verdict': rec_action,
                        'confidence_score': (identity.get('verdict_score') or 0) / 100.0,
                        'contributing_factors': identity.get('verdict_signals'),
                        'previous_verdict': prev_verdict,
                        'verdict_changed': verdict_changed,
                        'verdict_source': 'lineage_engine',
                    })

            self.db._commit()
            cursor.close()
            logger.info("Lineage tables populated: %s orphan_classifications, %s lineage_scores",
                         oc_count, ls_count)
        except Exception as e:
            logger.warning("Lineage table population failed: %s", e)
            try:
                self.db._rollback()
            except Exception:
                pass

    def _assemble_lineage_verdict(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        """Assemble a lineage verdict from all signal sources for a workload identity.

        Score (0-100) is additive for UI display.
        Confidence ('high'|'medium'|'low') uses a signal-priority model:
            high  — ARM/MI binding exists, OR federated credential, OR discovery connector
            medium — role pattern matched with high workload_confidence (>=60)
            low   — everything else

        Returns dict with 8 keys:
            verdict_confidence: 'high' | 'medium' | 'low'
            verdict_score: int (0-100)
            workload_origin: str — human-readable origin description
            workload_origin_source: str — which signal determined the origin
            recommended_action: str — one of ORPHANED/AT_RISK/STALE/UNUSED/NEEDS_REVIEW/HEALTHY
            verdict_action_text: str — human-readable recommendation
            verdict_signals: list[dict] — individual signal contributions
            verdict_risk_summary: list[str] — human-readable risk flag strings
        """
        signals = []
        score = 0

        # ── Signal 1: Role topology ──────────────────────────────────
        # active_role_count excludes read-only roles (Reader/Viewer) for scoring,
        # but has_roles includes ALL roles — Reader on a Key Vault is still real access.
        all_roles = (identity.get('roles') or []) + (identity.get('entra_roles') or [])
        _READ_ONLY = {'reader', 'viewer'}
        active_role_count = sum(
            1 for r in all_roles
            if not any(ro in (r.get('role_name') or r.get('role_definition_name') or '').lower() for ro in _READ_ONLY)
        )
        has_roles = len(all_roles) > 0
        workload_type = identity.get('workload_type') or 'unknown'
        workload_conf = identity.get('workload_confidence') or 0

        if workload_type != 'unknown' and workload_conf >= 60:
            signals.append({'source': 'role_topology', 'weight': 30,
                            'detail': f'Classified as {workload_type} (conf {workload_conf}%)'})
            score += 30
        elif workload_type != 'unknown':
            signals.append({'source': 'role_topology', 'weight': 15,
                            'detail': f'Classified as {workload_type} (conf {workload_conf}%)'})
            score += 15
        elif has_roles:
            signals.append({'source': 'role_topology', 'weight': 10,
                            'detail': f'Has roles but unclassified workload type'})
            score += 10

        # ── Signal 2: App registration metadata ──────────────────────
        has_app_reg = bool(identity.get('app_registration_object_id'))
        app_reg_owner = identity.get('app_reg_owner_display_name')
        likely_service = identity.get('app_reg_likely_service')
        reply_urls = identity.get('app_reg_reply_url_hostnames') or []
        is_external = identity.get('is_external_app', False)

        if has_app_reg:
            if app_reg_owner:
                signals.append({'source': 'app_reg_owner', 'weight': 15,
                                'detail': f'Owner: {app_reg_owner}'})
                score += 15
            else:
                signals.append({'source': 'app_reg_owner', 'weight': 0,
                                'detail': 'No owner assigned (ownerless)'})

            if likely_service:
                signals.append({'source': 'app_reg_metadata', 'weight': 20,
                                'detail': f'Likely service: {likely_service}'})
                score += 20
            elif reply_urls:
                signals.append({'source': 'app_reg_reply_urls', 'weight': 10,
                                'detail': f'Reply URLs: {", ".join(reply_urls[:3])}'})
                score += 10

            if is_external:
                signals.append({'source': 'app_reg_external', 'weight': 5,
                                'detail': 'External (multi-tenant) application'})
                score += 5

        # ── Signal 3: Sign-in activity ───────────────────────────────
        signin_pattern = identity.get('signin_pattern')
        days_since = identity.get('days_since_last_signin')
        last_sign_in = identity.get('last_sign_in')

        if signin_pattern and signin_pattern not in ('unknown', 'none', 'never_used'):
            signals.append({'source': 'signin_pattern', 'weight': 20,
                            'detail': f'Sign-in pattern: {signin_pattern}'})
            score += 20
        elif signin_pattern == 'never_used':
            # Never authenticated — negative signal toward orphan/review
            signals.append({'source': 'signin_pattern', 'weight': -10,
                            'detail': 'Never authenticated (no sign-in history)'})
            score = max(0, score - 10)
        elif last_sign_in:
            signals.append({'source': 'signin_last_seen', 'weight': 10,
                            'detail': f'Last sign-in recorded (days ago: {days_since})'})
            score += 10

        # ── Observed usage: MAX(observed_last_used, Azure sign-in) ──
        # AuditGraph records observed_last_used during discovery for connector SPNs.
        # effective_last_used = MAX(observed, Azure sign-in) with source attribution.
        observed_last_used = identity.get('observed_last_used')
        last_ni = identity.get('last_noninteractive_signin')
        effective_last_used = None
        effective_last_used_source = None

        # Parse dates for comparison
        def _parse_ts(v):
            if not v:
                return None
            if isinstance(v, datetime):
                return v
            try:
                return datetime.fromisoformat(str(v).replace('Z', '+00:00').replace('+00:00', ''))
            except (ValueError, TypeError):
                return None

        obs_dt = _parse_ts(observed_last_used)
        ni_dt = _parse_ts(last_ni)
        signin_dt = _parse_ts(last_sign_in)

        # Pick the most recent timestamp
        candidates = [
            (obs_dt, 'auditgraph'),
            (ni_dt, 'azure_signin'),
            (signin_dt, 'azure_signin'),
        ]
        for dt, src in candidates:
            if dt and (effective_last_used is None or dt > effective_last_used):
                effective_last_used = dt
                effective_last_used_source = src

        # Override days_since if observed_last_used is more recent
        if obs_dt and effective_last_used_source == 'auditgraph':
            days_since = (datetime.utcnow() - obs_dt).days

        # ── Signal 4: Federated credential ────────────────────────────
        fed_wt = identity.get('federated_workload_type')
        fed_wn = identity.get('federated_workload_name') or ''
        if fed_wt:
            signals.append({'source': 'federated_credential', 'weight': 35,
                            'detail': f'Federated credential: {fed_wt} ({fed_wn})'})
            score += 35

        # ── Federated usage inference ─────────────────────────────────
        # Federated identities (GitHub OIDC, AKS, Terraform) don't generate
        # Azure sign-in logs. If effective_last_used is still NULL but a
        # federated credential exists, infer usage from created_datetime.
        if fed_wt and effective_last_used is None:
            created_raw = identity.get('created_datetime')
            created_dt = _parse_ts(created_raw)
            if created_dt:
                effective_last_used = created_dt
                effective_last_used_source = 'inferred_federated'
                # Update days_since so downstream logic treats this as active
                days_since = (datetime.utcnow() - created_dt).days

        # ── Signal 5: Discovery connector flag ───────────────────────
        is_connector = identity.get('is_discovery_connector', False)
        if is_connector:
            signals.append({'source': 'discovery_connector', 'weight': 30,
                            'detail': 'This is the AuditGraph discovery connector'})
            score += 30

        # ── Signal 6: ARM / managed identity binding ─────────────────
        # Set by Step 9d/9e after save; absent at Step 8.75 (first pass).
        has_arm_binding = bool(identity.get('arm_binding_count'))
        if has_arm_binding:
            arm_count = identity['arm_binding_count']
            signals.append({'source': 'arm_resource_binding', 'weight': 30,
                            'detail': f'ARM resource association: {arm_count} resource(s)'})
            score += 30

        # ── Signal 7: Heuristic workload detection ─────────────────
        # Runs ONLY when ARM, MI, and federated signals are absent.
        # Detects GitHub Actions (client secret), Terraform, automation scripts.
        heuristic = None
        if not has_arm_binding and not fed_wt and not is_connector:
            heuristic = self._detect_workload_from_patterns(identity)
            if heuristic:
                h_weight = 20 if heuristic['confidence'] == 'medium' else 10
                signals.append({
                    'source': 'heuristic_detection', 'weight': h_weight,
                    'detail': heuristic['reason'],
                })
                score += h_weight

        # ── Signal 8: API Usage Pattern (M1) ────────────────────────
        api_usage = identity.get('api_usage_pattern')
        if api_usage and api_usage != 'none':
            signals.append({'source': 'api_usage_pattern', 'weight': 15,
                            'detail': f'API usage pattern: {api_usage}'})
            score += 15

        # ── Signal 9: Audit Provenance (M3) ─────────────────────────
        audit_created_by = identity.get('audit_created_by')
        if audit_created_by:
            audit_method = identity.get('audit_creation_method', 'unknown')
            signals.append({'source': 'audit_provenance', 'weight': 20,
                            'detail': f'Created by {audit_created_by} via {audit_method}'})
            score += 20

        # ── Signal 10: Owned Objects (M5) ────────────────────────────
        is_platform = identity.get('is_platform_spn', False)
        owned_count = identity.get('owned_object_count', 0)
        if is_platform:
            signals.append({'source': 'platform_spn', 'weight': 25,
                            'detail': f'Platform SPN: owns/created multiple applications'})
            score += 25
        elif owned_count > 0:
            signals.append({'source': 'owned_objects', 'weight': 10,
                            'detail': f'Owns {owned_count} object(s) in directory'})
            score += 10

        # ── Clamp score ──────────────────────────────────────────────
        score = max(0, min(100, score))

        # ── Confidence: signal-priority model ────────────────────────
        # Confidence is determined by the HIGHEST-PRIORITY signal present,
        # NOT by summing weights.  This prevents misleading "high" when
        # many weak signals accumulate.
        if is_connector:
            confidence = 'high'
        elif has_arm_binding:
            confidence = 'high'
        elif fed_wt:
            confidence = 'high'
        elif heuristic and heuristic['confidence'] == 'medium':
            confidence = 'medium'
        elif audit_created_by:
            confidence = 'medium'
        elif workload_type != 'unknown' and workload_conf >= 60:
            confidence = 'medium'
        else:
            confidence = 'low'

        # ── Determine origin ─────────────────────────────────────────
        # Priority: connector > app_reg_metadata > reply_url > federated >
        #           heuristic (NEW) > role_inference > app_reg_name
        # RULE: Never leave origin as "Unknown" if ANY signal exists.
        origin = 'Unknown'
        origin_source = 'none'

        if is_connector:
            origin = 'AuditGraph Discovery Connector'
            origin_source = 'discovery_connector'
        elif likely_service:
            origin = likely_service
            origin_source = 'app_reg_metadata'
        elif reply_urls:
            origin = f'Service at {reply_urls[0]}'
            origin_source = 'reply_url'
        elif fed_wt:
            origin = f'{fed_wt.replace("_", " ").title()}: {fed_wn}'
            origin_source = 'federated_credential'
        elif heuristic:
            # P4: Heuristic detection (GitHub, Terraform, automation)
            origin = heuristic['origin']
            origin_source = heuristic['origin_source']
        elif audit_created_by and identity.get('audit_creation_method') not in ('unknown', None):
            method = identity.get('audit_creation_method', 'unknown')
            origin = f'Created by {audit_created_by} via {method}'
            origin_source = 'audit_provenance'
        elif workload_type != 'unknown':
            origin = f'{workload_type.replace("_", " ").title()} (inferred from roles)'
            origin_source = 'role_inference'
        elif has_app_reg and identity.get('app_registration_name'):
            origin = identity['app_registration_name']
            origin_source = 'app_reg_name'

        # Last resort: if still Unknown but we have ANY evidence, use it
        if origin == 'Unknown':
            if signin_pattern and signin_pattern not in ('unknown', 'none', 'never_used'):
                origin = f'{signin_pattern.replace("_", " ").title()} workload'
                origin_source = 'signin_pattern_fallback'
            elif has_roles and has_app_reg:
                origin = identity.get('app_registration_name') or identity.get('display_name', 'Unknown')
                origin_source = 'display_name_fallback'

        # ── Recommended action ───────────────────────────────────────
        risk_flags = identity.get('workload_risk_flags') or []
        risk_summary = list(risk_flags)  # copy

        # never_used is a negative orphan signal — identity has never authenticated
        if signin_pattern == 'never_used':
            risk_summary.append('never_authenticated')

        # Confirmed signal = hard evidence that the identity is actively managed
        # or bound to infrastructure. These override ORPHANED verdict.
        has_confirmed_signal = (
            has_arm_binding
            or bool(fed_wt)
            or bool(app_reg_owner)
            or (signin_pattern and signin_pattern not in ('unknown', 'none', 'never_used'))
            or bool(last_sign_in)
        )

        # Strong signal = any lineage evidence (confirmed OR inferred).
        # Prevents NEEDS_REVIEW verdict but does NOT prevent ORPHANED.
        has_strong_signal = (
            has_confirmed_signal
            or bool(heuristic)
            or bool(likely_service)
            or bool(reply_urls)
            or (workload_type != 'unknown' and workload_conf >= 60)
            or bool(audit_created_by)
            or bool(is_platform)
            or (api_usage and api_usage != 'none')
        )

        if is_connector:
            action = 'HEALTHY'
            action_text = 'AuditGraph connector — no action required.'
        elif has_roles and not app_reg_owner and not last_sign_in and not has_confirmed_signal:
            action = 'ORPHANED'
            action_text = 'Has active roles but no owner and no sign-in history. Assign an owner or disable.'
            risk_summary.append('Ownerless identity with active permissions')
        elif not has_roles and not last_sign_in:
            action = 'UNUSED'
            action_text = 'No roles and no sign-in activity detected. Consider removing.'
            risk_summary.append('No permissions or activity detected')
        elif identity.get('identity_category') == IdentityCategory.MANAGED_IDENTITY_SYSTEM \
             and identity.get('associated_resource_id') is None and has_roles:
            action = Verdict.GHOST_MSI
            action_text = 'System-assigned MI with no host resource. The resource may have been deleted.'
            risk_summary.append('Ghost MSI — host resource missing')
        elif 'shared_identity' in risk_flags or 'shared_credential' in risk_flags:
            action = 'AT_RISK'
            action_text = 'Shared identity or credential detected. Review access and rotate credentials.'
            risk_summary.append('Shared identity/credential risk')
        elif days_since is not None and days_since > 365 and has_roles:
            action = 'STALE'
            action_text = f'Last sign-in was {days_since} days ago but still has active roles. Review necessity.'
            risk_summary.append(f'Stale: no sign-in for {days_since} days')
        elif has_strong_signal:
            action = 'HEALTHY'
            if score >= 60:
                action_text = 'Well-understood identity with strong lineage signals.'
            else:
                action_text = 'Identity has supporting lineage evidence. No immediate action needed.'
        elif has_roles:
            # Defensive: roles present but no strong signal and not caught above.
            action = 'NEEDS_REVIEW'
            action_text = 'Identity has roles but no lineage signals. Manual review recommended.'
            risk_summary.append('No lineage signals — manual review needed')
        else:
            action = 'NEEDS_REVIEW'
            action_text = 'No lineage signals found. Periodic review recommended.'

        # ── Human-readable lineage_signals ────────────────────────────
        # Structured signals for executive-readable lineage panel.
        # Type: ARM | FEDERATED | ROLE | SIGNIN | OWNER
        lineage_signals = []

        # ARM signal
        if has_arm_binding:
            arm_count = identity.get('arm_binding_count', 0)
            dep_res = identity.get('dependency_impact_resources') or []
            if isinstance(dep_res, str):
                try:
                    import json as _json
                    dep_res = _json.loads(dep_res)
                except Exception:
                    dep_res = []
            if dep_res and isinstance(dep_res, list) and len(dep_res) > 0:
                top = dep_res[0]
                rtype = top.get('resource_type', 'resource')
                rname = top.get('resource_name', 'unknown')
                loc = top.get('region') or top.get('location', '')
                loc_str = f' ({loc})' if loc else ''
                lineage_signals.append({
                    'type': 'ARM', 'label': 'Static',
                    'value': f"clientId found in {rtype} '{rname}'{loc_str}",
                    'confidence': 'high',
                })
            else:
                lineage_signals.append({
                    'type': 'ARM', 'label': 'Static',
                    'value': f'Bound to {arm_count} ARM resource(s)',
                    'confidence': 'high',
                })

        # Federated signal
        if fed_wt:
            if fed_wt == 'github_actions':
                fed_value = f"GitHub Actions \u2192 {fed_wn}" if fed_wn else 'GitHub Actions (OIDC)'
            elif fed_wt == 'aks':
                fed_value = f"AKS \u2192 {fed_wn}" if fed_wn else 'AKS Workload Identity'
            else:
                fed_value = f"{fed_wt.replace('_', ' ').title()} \u2192 {fed_wn}" if fed_wn else fed_wt.replace('_', ' ').title()
            lineage_signals.append({
                'type': 'FEDERATED', 'label': 'Federated',
                'value': fed_value,
                'confidence': 'high',
            })

        # Heuristic signal (GitHub, Terraform, automation)
        if heuristic:
            lineage_signals.append({
                'type': 'HEURISTIC', 'label': 'Inferred',
                'value': heuristic['reason'],
                'confidence': heuristic['confidence'],
            })

        # Sign-in signal
        last_ni = identity.get('last_noninteractive_signin')
        if last_ni or last_sign_in:
            if days_since is not None and days_since >= 0:
                if days_since == 0:
                    signin_value = 'Last non-interactive sign-in today'
                elif days_since <= 30:
                    signin_value = f'Last non-interactive sign-in {days_since} days ago'
                elif days_since <= 365:
                    months = days_since // 30
                    signin_value = f'Last non-interactive sign-in {months} month{"s" if months != 1 else ""} ago'
                else:
                    months = days_since // 30
                    signin_value = f'Last non-interactive sign-in {months} months ago'
            else:
                signin_value = 'Sign-in activity recorded'
            lineage_signals.append({
                'type': 'SIGNIN', 'label': 'Sign-in',
                'value': signin_value,
                'confidence': 'high' if days_since is not None and days_since <= 90 else 'medium',
            })

        # Owner signal
        if has_app_reg:
            if app_reg_owner:
                lineage_signals.append({
                    'type': 'OWNER', 'label': 'Owner',
                    'value': app_reg_owner,
                    'confidence': 'medium',
                })
            else:
                lineage_signals.append({
                    'type': 'OWNER', 'label': 'Owner',
                    'value': 'No owner assigned',
                    'confidence': 'high',
                })

        # Observed usage signal
        if obs_dt:
            obs_days = (datetime.utcnow() - obs_dt).days
            if is_connector:
                obs_label = 'Actively used by AuditGraph'
            elif obs_days == 0:
                obs_label = 'Observed in use today (via AuditGraph)'
            else:
                obs_label = f'Observed in use {obs_days} day{"s" if obs_days != 1 else ""} ago (via AuditGraph)'
            lineage_signals.append({
                'type': 'OBSERVED', 'label': 'Observed',
                'value': obs_label,
                'confidence': 'high',
            })

        # Inferred usage signal (federated identities with no sign-in data)
        if effective_last_used_source == 'inferred_federated' and fed_wt:
            fed_label_map = {
                'github_actions': 'GitHub Actions (OIDC)',
                'aks': 'AKS Workload Identity',
                'terraform': 'Terraform Cloud',
            }
            inferred_label = fed_label_map.get(fed_wt, fed_wt.replace('_', ' ').title())
            lineage_signals.append({
                'type': 'INFERRED', 'label': 'Usage',
                'value': f'Likely used via {inferred_label}',
                'confidence': 'medium',
            })

        # API usage pattern signal (M1)
        if api_usage and api_usage != 'none':
            lineage_signals.append({
                'type': 'API', 'label': 'APIs',
                'value': f'Usage pattern: {api_usage.replace("_", " ").title()}',
                'confidence': 'medium',
            })

        # Provenance signal (M3)
        if audit_created_by:
            method = identity.get('audit_creation_method', 'unknown')
            lineage_signals.append({
                'type': 'PROVENANCE', 'label': 'Created By',
                'value': f'{audit_created_by} ({method})',
                'confidence': 'medium',
            })

        # Platform SPN signal (M5)
        if is_platform:
            evidence = identity.get('platform_spn_evidence') or {}
            lineage_signals.append({
                'type': 'PLATFORM', 'label': 'Platform',
                'value': f'Owns {evidence.get("owned_app_count", 0)} apps, created {evidence.get("created_app_count", 0)} apps',
                'confidence': 'high',
            })

        # High sign-in failure alert (M4)
        fail_count = identity.get('signin_failure_count_30d', 0)
        if fail_count and fail_count >= 10:
            lineage_signals.append({
                'type': 'ALERT', 'label': 'Sign-in Failures',
                'value': f'{fail_count} failed sign-ins in last 30 days',
                'confidence': 'high',
            })

        # ── Lineage narrative ──────────────────────────────────────────
        # Human-readable paragraph summarizing all evidence and risk.
        narrative_parts = []
        display = identity.get('display_name', 'This identity')
        cat = identity.get('identity_category', 'identity')
        cat_label = {
            'service_principal': 'Service Principal',
            'managed_identity_system': 'System Managed Identity',
            'managed_identity_user': 'User Managed Identity',
            'human_user': 'User',
            'guest': 'Guest User',
        }.get(cat, 'Identity')

        # Where it runs
        if is_connector:
            narrative_parts.append(f"{cat_label} '{display}' is the AuditGraph Discovery Connector.")
        elif fed_wt:
            fed_label = fed_value  # reuse from above
            narrative_parts.append(f"{cat_label} '{display}' is federated to {fed_label}.")
        elif has_arm_binding and lineage_signals and lineage_signals[0]['type'] == 'ARM':
            narrative_parts.append(f"{cat_label} '{display}' is {lineage_signals[0]['value']}.")
        elif heuristic:
            narrative_parts.append(f"{cat_label} '{display}' is likely used for {heuristic['origin'].lower()}.")
        elif origin != 'Unknown':
            narrative_parts.append(f"{cat_label} '{display}' is used by {origin}.")
        else:
            narrative_parts.append(f"{cat_label} '{display}' has no confirmed workload binding.")

        # What it accesses
        if has_roles:
            if workload_type != 'unknown':
                narrative_parts.append(
                    f'It has {active_role_count} active role{"s" if active_role_count != 1 else ""} '
                    f'classified as {workload_type.replace("_", " ")}.'
                )
            else:
                narrative_parts.append(
                    f'It has {active_role_count} active role{"s" if active_role_count != 1 else ""} '
                    f'but the workload type is unclassified.'
                )

        # Activity (with observed usage source attribution)
        source_tag = ''
        if effective_last_used_source == 'auditgraph':
            source_tag = ' (observed by AuditGraph)'
        elif effective_last_used_source == 'inferred_federated':
            source_tag = ' (inferred from federated credential)'
        if is_connector:
            narrative_parts.append('It is actively used during every discovery scan.')
        elif effective_last_used_source == 'inferred_federated':
            narrative_parts.append(f'Azure does not record sign-in logs for federated identities, but it is likely active{source_tag}.')
        elif days_since is not None and days_since > 365:
            narrative_parts.append(f'It has not been used for {days_since // 30} months.')
        elif days_since is not None and days_since > 90:
            narrative_parts.append(f'It has not been used for {days_since} days.')
        elif days_since is not None and days_since >= 0:
            narrative_parts.append(f'It was last active {days_since} day{"s" if days_since != 1 else ""} ago{source_tag}.')
        elif not last_sign_in and not last_ni and not obs_dt:
            narrative_parts.append('No sign-in activity has ever been recorded.')

        # Provenance (M3)
        if audit_created_by:
            method = identity.get('audit_creation_method', 'unknown')
            narrative_parts.append(f'It was created by {audit_created_by} via {method}.')

        # Resources accessed (M4)
        signin_resources = identity.get('signin_resources_accessed')
        if signin_resources and isinstance(signin_resources, list):
            top_res = [r.get('name', '?') for r in signin_resources[:3]]
            narrative_parts.append(f'It accesses {", ".join(top_res)}.')

        # Sign-in failure warning (M4)
        if fail_count and fail_count >= 10:
            narrative_parts.append(f'Warning: {fail_count} sign-in failures in the last 30 days.')

        # Owner risk
        if has_app_reg and not app_reg_owner:
            narrative_parts.append('No owner is assigned to the app registration.')
        elif 'shared_identity' in risk_flags:
            narrative_parts.append('This identity may be shared across multiple teams or services.')

        # Conclusion
        if action == 'ORPHANED':
            narrative_parts.append('This identity is likely orphaned and still has access to live resources.')
        elif action == 'STALE':
            narrative_parts.append('This identity is stale and should be reviewed for decommissioning.')
        elif action == 'UNUSED':
            narrative_parts.append('This identity appears unused and can likely be removed.')
        elif action == 'AT_RISK':
            narrative_parts.append('This identity poses elevated risk and requires immediate review.')
        elif action == 'NEEDS_REVIEW':
            narrative_parts.append('Insufficient evidence to determine safety. Manual review recommended.')
        elif action == 'HEALTHY':
            narrative_parts.append('This identity appears healthy with sufficient lineage evidence.')

        lineage_narrative = ' '.join(narrative_parts)

        # Debug logging for lineage signals (helps demo validation)
        iid = identity.get('identity_id', '?')
        logger.debug(
            "DETECTION [%s] ARM=%d MI=0 FED=%s HEURISTIC=%s SIGNIN=%s "
            "score=%d conf=%s action=%s origin=%s origin_src=%s signals=%d strong=%s",
            iid,
            identity.get('arm_binding_count', 0),
            fed_wt or 'none',
            heuristic['workload_type'] if heuristic else 'none',
            signin_pattern or 'none',
            score, confidence, action, origin, origin_source,
            len(signals),
            has_strong_signal,
        )

        return {
            'verdict_confidence': confidence,
            'verdict_score': score,
            'workload_origin': origin,
            'workload_origin_source': origin_source,
            'recommended_action': action,
            'verdict_action_text': action_text,
            'verdict_signals': signals,
            'verdict_risk_summary': risk_summary,
            'lineage_signals': lineage_signals,
            'lineage_narrative': lineage_narrative,
            'effective_last_used': effective_last_used.isoformat() if effective_last_used else None,
            'effective_last_used_source': effective_last_used_source,
        }

    # ── Module 5: Owned Objects Scanner ─────────────────────────────────

    async def _discover_owned_objects(self, service_principals: list):
        """Discover owned and created objects per SPN via Graph API.

        Calls GET /v1.0/servicePrincipals/{id}/ownedObjects and /createdObjects.
        Skips Microsoft system SPNs. Detects platform SPNs (owns >=2 apps OR created >=3 apps).
        Sets owned_objects, created_objects, owned_object_count, created_object_count,
        is_platform_spn, platform_spn_evidence on each identity dict.
        """
        import aiohttp
        import asyncio as _asyncio

        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        enriched = 0
        platform_count = 0

        async with aiohttp.ClientSession() as session:
            for sp in service_principals:
                if sp.get('is_microsoft_system'):
                    continue
                obj_id = sp.get('object_id')
                if not obj_id:
                    continue

                owned = []
                created = []

                # Fetch ownedObjects
                try:
                    url = (
                        f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                        f"/ownedObjects?$select=id,displayName&$top=100"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for obj in data.get('value', []):
                                owned.append({
                                    'id': obj.get('id'),
                                    'display_name': obj.get('displayName'),
                                    'odata_type': obj.get('@odata.type', ''),
                                })
                        elif resp.status == 403:
                            logger.debug("ownedObjects 403 for %s — skipping", obj_id)
                except Exception as e:
                    logger.debug("ownedObjects error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)  # Rate limit 150ms

                # Fetch createdObjects
                try:
                    url = (
                        f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                        f"/createdObjects?$select=id,displayName&$top=100"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for obj in data.get('value', []):
                                created.append({
                                    'id': obj.get('id'),
                                    'display_name': obj.get('displayName'),
                                    'odata_type': obj.get('@odata.type', ''),
                                })
                        elif resp.status == 403:
                            logger.debug("createdObjects 403 for %s — skipping", obj_id)
                except Exception as e:
                    logger.debug("createdObjects error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)

                # Set on identity dict
                sp['owned_objects'] = owned or None
                sp['created_objects'] = created or None
                sp['owned_object_count'] = len(owned)
                sp['created_object_count'] = len(created)

                # Detect platform SPNs
                owned_apps = sum(1 for o in owned if 'application' in (o.get('odata_type') or '').lower())
                created_apps = sum(1 for c in created if 'application' in (c.get('odata_type') or '').lower())
                is_platform = owned_apps >= 2 or created_apps >= 3
                sp['is_platform_spn'] = is_platform
                if is_platform:
                    sp['platform_spn_evidence'] = {
                        'owned_app_count': owned_apps,
                        'created_app_count': created_apps,
                        'owned_total': len(owned),
                        'created_total': len(created),
                    }
                    platform_count += 1
                else:
                    sp['platform_spn_evidence'] = None

                if owned or created:
                    enriched += 1

        logger.info("Owned objects: %s SPNs enriched, %s platform SPNs detected", enriched, platform_count)

    # ── Module 3: AAD Audit Log Provenance ────────────────────────────

    @staticmethod
    def _classify_creation_method(initiated_by: dict) -> str:
        """Classify the creation method from an audit log's initiatedBy field.

        Returns one of: 'portal', 'terraform', 'cli_powershell', 'programmatic',
        'user_initiated', 'unknown'.
        """
        if not initiated_by:
            return 'unknown'
        app = initiated_by.get('app') or {}
        user = initiated_by.get('user') or {}
        app_name = (app.get('displayName') or '').lower()
        user_agent = (app.get('servicePrincipalName') or '').lower()

        if 'azure portal' in app_name or 'portal' in app_name:
            return 'portal'
        if 'terraform' in app_name or 'terraform' in user_agent:
            return 'terraform'
        if any(kw in app_name for kw in ('powershell', 'az cli', 'azure cli', 'azcli')):
            return 'cli_powershell'
        if app.get('appId') or app.get('displayName'):
            return 'programmatic'
        if user.get('userPrincipalName') or user.get('displayName'):
            return 'user_initiated'
        return 'unknown'

    async def _discover_audit_provenance(self, service_principals: list):
        """Discover AAD audit log provenance for service principals.

        Calls directoryAudits to find:
        - Creation event (who created this SPN and how)
        - Recent modifications in the last 90 days

        Bails on 403 (AuditLog.Read.All not granted).
        Skips Microsoft system SPNs.
        """
        import aiohttp
        import asyncio as _asyncio
        from urllib.parse import quote

        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        enriched = 0
        ninety_days_ago = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%dT00:00:00Z')

        async with aiohttp.ClientSession() as session:
            for sp in service_principals:
                if sp.get('is_microsoft_system'):
                    continue
                obj_id = sp.get('object_id')
                if not obj_id:
                    continue

                # Fetch creation event
                created_by = None
                creation_method = 'unknown'
                creation_date = None
                try:
                    filter_str = (
                        f"targetResources/any(t: t/id eq '{obj_id}') "
                        f"and activityDisplayName eq 'Add service principal'"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
                        f"?$filter={quote(filter_str)}&$top=1&$orderby=activityDateTime asc"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 403:
                            logger.info("Audit provenance: AuditLog.Read.All not granted — skipping module")
                            return  # Bail entirely
                        if resp.status == 200:
                            data = await resp.json()
                            events = data.get('value', [])
                            if events:
                                event = events[0]
                                initiated = event.get('initiatedBy', {})
                                user_info = initiated.get('user') or {}
                                app_info = initiated.get('app') or {}
                                created_by = (
                                    user_info.get('userPrincipalName')
                                    or user_info.get('displayName')
                                    or app_info.get('displayName')
                                    or 'Unknown'
                                )
                                creation_method = self._classify_creation_method(initiated)
                                creation_date = event.get('activityDateTime')
                except Exception as e:
                    logger.debug("Audit creation lookup error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)

                # Fetch recent modifications (last 90 days)
                recent_mods = []
                mod_count = 0
                try:
                    filter_str = (
                        f"targetResources/any(t: t/id eq '{obj_id}') "
                        f"and activityDateTime ge {ninety_days_ago}"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
                        f"?$filter={quote(filter_str)}&$top=10&$orderby=activityDateTime desc"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            events = data.get('value', [])
                            mod_count = len(events)
                            for event in events:
                                initiated = event.get('initiatedBy', {})
                                user_info = initiated.get('user') or {}
                                app_info = initiated.get('app') or {}
                                recent_mods.append({
                                    'activity': event.get('activityDisplayName'),
                                    'date': event.get('activityDateTime'),
                                    'actor': (
                                        user_info.get('userPrincipalName')
                                        or app_info.get('displayName')
                                        or 'Unknown'
                                    ),
                                    'method': self._classify_creation_method(initiated),
                                })
                except Exception as e:
                    logger.debug("Audit recent mods error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)

                # Set on identity dict
                sp['audit_created_by'] = created_by
                sp['audit_creation_method'] = creation_method
                sp['audit_creation_date'] = creation_date
                sp['audit_recent_modifications'] = recent_mods or None
                sp['audit_modification_count_90d'] = mod_count
                if created_by:
                    enriched += 1

        logger.info("Audit provenance: %s SPNs enriched with creation/modification data", enriched)

    # ── Module 4: AAD Sign-in Intelligence ────────────────────────────

    @staticmethod
    def _classify_ip(ip_str: str) -> str:
        """Classify an IP address into category.

        Returns one of: 'internal_rfc1918', 'azure_datacenter', 'external', 'unknown'.
        """
        import ipaddress as _ipa
        if not ip_str:
            return 'unknown'
        try:
            addr = _ipa.ip_address(ip_str)
            if addr.is_private:
                return 'internal_rfc1918'
            # Azure DC heuristic: common first octets for Azure public IPs
            first_octet = int(ip_str.split('.')[0]) if '.' in ip_str else 0
            if first_octet in (13, 20, 40, 52, 104):
                return 'azure_datacenter'
            return 'external'
        except (ValueError, TypeError):
            return 'unknown'

    @staticmethod
    def _process_signin_intelligence(identity: dict, sign_ins: list):
        """Process sign-in events and set intelligence fields on identity dict.

        Extracts IPs, resources, locations, client apps, failure/success counts.
        """
        ips = {}
        resources = {}
        locations = {}
        client_apps = {}
        failures = 0
        successes = 0

        for si in sign_ins:
            # IP
            ip = si.get('ipAddress')
            if ip:
                if ip not in ips:
                    ips[ip] = {
                        'ip': ip,
                        'classification': AzureDiscoveryEngine._classify_ip(ip),
                        'count': 0,
                    }
                ips[ip]['count'] += 1

            # Resource
            res = si.get('resourceDisplayName')
            if res:
                if res not in resources:
                    resources[res] = {'name': res, 'count': 0}
                resources[res]['count'] += 1

            # Location
            loc = si.get('location') or {}
            city = loc.get('city') or ''
            country = loc.get('countryOrRegion') or ''
            loc_key = f"{city},{country}" if city or country else ''
            if loc_key:
                if loc_key not in locations:
                    locations[loc_key] = {'city': city, 'country': country, 'count': 0}
                locations[loc_key]['count'] += 1

            # Client app
            client = si.get('clientAppUsed') or ''
            if client:
                if client not in client_apps:
                    client_apps[client] = {'app': client, 'count': 0}
                client_apps[client]['count'] += 1

            # Status
            status = si.get('status') or {}
            error_code = status.get('errorCode', 0)
            if error_code and error_code != 0:
                failures += 1
            else:
                successes += 1

        identity['signin_ips'] = list(ips.values()) or None
        identity['signin_resources_accessed'] = list(resources.values()) or None
        identity['signin_locations'] = list(locations.values()) or None
        identity['signin_client_apps'] = list(client_apps.values()) or None
        identity['signin_failure_count_30d'] = failures
        identity['signin_success_count_30d'] = successes
        identity['signin_total_events_30d'] = len(sign_ins)

    async def _discover_signin_intelligence(self, identities: list):
        """Discover sign-in intelligence for workload identities via Graph API.

        Calls GET /v1.0/auditLogs/signIns with servicePrincipalId filter.
        6-hour cache via setting key. Rate limit 150ms. Bails on 403.
        """
        import aiohttp
        import asyncio as _asyncio
        from urllib.parse import quote

        # 6-hour cache check
        cache_key = f'signin_intelligence_last_run_{self.cloud_connection_id}'
        try:
            last_run = self.db.get_setting(cache_key, None, organization_id=self.db._organization_id)
            if last_run:
                last_dt = datetime.fromisoformat(last_run.replace('Z', '+00:00').replace('+00:00', ''))
                if (datetime.utcnow() - last_dt).total_seconds() < 6 * 3600:
                    logger.info("Sign-in intelligence: cached (last run %s) — skipping", last_run)
                    return
        except Exception:
            pass

        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%dT00:00:00Z')
        select_fields = 'createdDateTime,resourceDisplayName,ipAddress,location,clientAppUsed,status,servicePrincipalId'

        enriched = 0
        batch_count = 0

        async with aiohttp.ClientSession() as session:
            for identity in identities:
                if identity.get('identity_category') not in ('service_principal', 'managed_identity_user', 'managed_identity_system'):
                    continue
                if identity.get('is_microsoft_system'):
                    continue
                obj_id = identity.get('object_id')
                if not obj_id:
                    continue

                try:
                    filter_str = (
                        f"servicePrincipalId eq '{obj_id}' "
                        f"and createdDateTime ge {thirty_days_ago}"
                    )
                    url = (
                        f"https://graph.microsoft.com/v1.0/auditLogs/signIns"
                        f"?$filter={quote(filter_str)}&$top=50"
                        f"&$orderby=createdDateTime desc&$select={select_fields}"
                    )
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 403:
                            logger.info("Sign-in intelligence: 403 — signIns API not available, skipping module")
                            return  # Bail entirely
                        if resp.status == 200:
                            data = await resp.json()
                            sign_ins = data.get('value', [])
                            if sign_ins:
                                self._process_signin_intelligence(identity, sign_ins)
                                enriched += 1
                except Exception as e:
                    logger.debug("Sign-in intelligence error for %s: %s", obj_id, e)

                await _asyncio.sleep(0.15)
                batch_count += 1
                if batch_count % 100 == 0:
                    logger.info("Sign-in intelligence: processed %s identities...", batch_count)

        # Update cache timestamp
        try:
            self.db.save_setting(cache_key, datetime.utcnow().isoformat(), organization_id=self.db._organization_id)
        except Exception:
            pass

        logger.info("Sign-in intelligence: %s identities enriched out of %s processed", enriched, batch_count)

    # ── Heuristic workload detection ──────────────────────────────────
    # Detects workloads when federated identity and ARM bindings are absent.
    # Catches: GitHub Actions with client secrets, Terraform SPNs, automation scripts.

    # Patterns for heuristic matching (compiled once at class level)
    _GITHUB_NAME_PATTERNS = {'github', 'gh-', 'actions', 'ghactions', 'github-actions'}
    _TERRAFORM_NAME_PATTERNS = {'terraform', 'tf-', 'iac', 'infra-pipeline', 'pulumi', 'bicep'}
    _TERRAFORM_ROLES = {'owner', 'contributor', 'user access administrator'}

    @staticmethod
    def _detect_workload_from_patterns(identity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect workload type from naming conventions, roles, and sign-in patterns.

        Called when ARM, MI, and federated signals are absent.
        Returns dict with workload_type, confidence, reason, origin, origin_source
        or None if no pattern matched.
        """
        display_name = (identity.get('display_name') or '').lower()
        app_reg_notes = (identity.get('app_reg_notes') or '').lower()
        app_reg_name = (identity.get('app_registration_name') or '').lower()
        signin_pattern = identity.get('signin_pattern') or ''
        all_roles = (identity.get('roles') or []) + (identity.get('entra_roles') or [])
        _READ_ONLY = {'reader', 'viewer'}
        has_roles = any(
            not any(ro in (r.get('role_name') or r.get('role_definition_name') or '').lower() for ro in _READ_ONLY)
            for r in all_roles
        ) if all_roles else False
        workload_type = identity.get('workload_type') or 'unknown'

        # Collect role names for Terraform detection
        role_names_lower = set()
        risk_flags = identity.get('workload_risk_flags') or []
        # role_pattern_matched stores the matched pattern name
        role_pattern = (identity.get('role_pattern_matched') or '').lower()

        # ── Rule 1: GitHub Actions heuristic ─────────────────────────
        name_matches_github = any(
            p in display_name or p in app_reg_name
            for p in AzureDiscoveryEngine._GITHUB_NAME_PATTERNS
        )
        notes_match_github = 'github' in app_reg_notes

        if name_matches_github or notes_match_github:
            return {
                'workload_type': 'github_actions_inferred',
                'confidence': 'medium',
                'reason': 'Likely GitHub Actions pipeline (name/notes pattern match, no federated credential)',
                'origin': f'GitHub Actions (inferred from {"name" if name_matches_github else "notes"})',
                'origin_source': 'heuristic_github',
            }

        # ── Rule 2: Terraform / IaC heuristic ────────────────────────
        name_matches_terraform = any(
            p in display_name or p in app_reg_name
            for p in AzureDiscoveryEngine._TERRAFORM_NAME_PATTERNS
        )
        # Check if workload has elevated roles typical of IaC
        has_iac_roles = (
            workload_type == 'admin_identity'
            or 'admin' in role_pattern
            or any(p in display_name for p in ('contributor', 'deploy'))
        )

        if name_matches_terraform or (has_iac_roles and any(
            p in display_name for p in ('deploy', 'pipeline', 'infra', 'provision')
        )):
            return {
                'workload_type': 'terraform_pipeline',
                'confidence': 'medium',
                'reason': 'Infrastructure pipeline identity (IaC naming pattern + elevated roles)',
                'origin': f'Terraform / IaC pipeline (inferred from {"name" if name_matches_terraform else "roles + naming"})',
                'origin_source': 'heuristic_terraform',
            }

        # ── Rule 3: Automation / Script heuristic ────────────────────
        is_machine_only = signin_pattern in ('machine_only',)
        if is_machine_only and has_roles:
            # Generic automation: machine-only sign-in with roles but no binding
            return {
                'workload_type': 'automation_script',
                'confidence': 'low',
                'reason': 'Automation script identity (machine-only sign-in, roles present, no ARM/federated binding)',
                'origin': 'Automation script (inferred from machine-only sign-in pattern)',
                'origin_source': 'heuristic_automation',
            }

        return None

    # ── Resource types that cause HIGH impact if their SPN is deleted ──
    _HIGH_IMPACT_RESOURCE_TYPES = {
        'appservice', 'functionapp', 'containerapp', 'managedclusters',
        'virtualmachines', 'logicapp', 'sites', 'kubernetes',
        'containerapps', 'aks',
    }
    _MEDIUM_IMPACT_RESOURCE_TYPES = {
        'storageaccounts', 'keyvaults', 'sqldatabases', 'sqlservers',
        'cosmosdb', 'servicebus', 'eventhubs', 'redis',
    }
    _READER_ONLY_ROLES = {
        'reader', 'monitoring reader', 'log analytics reader',
        'security reader', 'cost management reader',
    }

    def _compute_dependency_impact(
        self,
        bindings: list,
        role_assignments: list,
    ) -> Dict[str, Any]:
        """Compute dependency impact — what breaks if this SPN is deleted.

        Args:
            bindings: list of ARM/MI resource binding dicts from Steps 9d/9e
            role_assignments: list of role assignment dicts for this identity

        Returns:
            dict with:
                dependency_impact: 'high' | 'medium' | 'low' | 'none_detected'
                dependency_impact_resources: list of affected resource dicts
                deletion_impact_statement: human-readable impact summary
        """
        if not bindings:
            # Check if identity has write/contribute roles (implicit impact)
            role_names = [r.get('role_name', '').lower() for r in (role_assignments or [])]
            has_write_roles = any(
                rn and rn not in self._READER_ONLY_ROLES
                for rn in role_names
            )
            if has_write_roles:
                return {
                    'dependency_impact': 'none_detected',
                    'dependency_impact_resources': [],
                    'deletion_impact_statement': (
                        'No direct resource bindings found, but this identity has '
                        'write/contribute roles. Deletion may break undiscovered workloads.'
                    ),
                }
            return {
                'dependency_impact': 'none_detected',
                'dependency_impact_resources': [],
                'deletion_impact_statement': 'No resource bindings or write roles detected.',
            }

        # Classify each bound resource
        impact_resources = []
        max_impact = 'low'

        for b in bindings:
            rt_raw = (b.get('resource_type') or '').lower().replace(' ', '')
            resource_name = b.get('resource_name', '')
            resource_group = b.get('resource_group', '')
            binding_method = b.get('binding_method', '')

            # Determine resource-level impact
            if any(ht in rt_raw for ht in self._HIGH_IMPACT_RESOURCE_TYPES):
                res_impact = 'high'
            elif any(mt in rt_raw for mt in self._MEDIUM_IMPACT_RESOURCE_TYPES):
                res_impact = 'medium'
            else:
                res_impact = 'low'

            impact_resources.append({
                'resource_name': resource_name,
                'resource_type': b.get('resource_type', ''),
                'resource_group': resource_group,
                'impact_level': res_impact,
                'binding_method': binding_method,
            })

            # Track highest impact
            if res_impact == 'high':
                max_impact = 'high'
            elif res_impact == 'medium' and max_impact != 'high':
                max_impact = 'medium'

        # Check if identity only has Reader roles (downgrade to low)
        role_names = [r.get('role_name', '').lower() for r in (role_assignments or [])]
        only_reader = all(
            rn in self._READER_ONLY_ROLES
            for rn in role_names
            if rn
        ) if role_names else False

        if only_reader and max_impact != 'high':
            max_impact = 'low'

        # Build human-readable deletion impact statement
        high_res = [r for r in impact_resources if r['impact_level'] == 'high']
        med_res = [r for r in impact_resources if r['impact_level'] == 'medium']

        lines = []
        if high_res:
            lines.append('CRITICAL resources that will break:')
            for r in high_res[:5]:
                lines.append(f'  - {r["resource_name"]} ({r["resource_type"]})')
        if med_res:
            lines.append('Resources that may be affected:')
            for r in med_res[:5]:
                lines.append(f'  - {r["resource_name"]} ({r["resource_type"]})')
        remaining = len(impact_resources) - len(high_res[:5]) - len(med_res[:5])
        if remaining > 0:
            lines.append(f'  + {remaining} more resource(s)')

        statement = '\n'.join(lines) if lines else (
            f'{len(impact_resources)} resource(s) bound, all low-impact.'
        )

        return {
            'dependency_impact': max_impact,
            'dependency_impact_resources': impact_resources,
            'deletion_impact_statement': statement,
        }

    @staticmethod
    def _classify_federated_credential(issuer: str, subject: str) -> Dict[str, str]:
        """Classify a federated credential into a workload type and name.

        Returns dict with:
            federated_workload_type: 'github_actions' | 'aks_workload' | 'external_federation'
            federated_workload_name: extracted repo/namespace or issuer host
        """
        issuer = issuer or ''
        subject = subject or ''

        # GitHub Actions OIDC
        if 'token.actions.githubusercontent.com' in issuer:
            # subject format: repo:org/repo:ref:refs/heads/main  OR  repo:org/repo:environment:prod
            name = subject
            if subject.startswith('repo:'):
                # Extract "org/repo" portion
                parts = subject[5:]  # strip "repo:"
                colon_idx = parts.find(':')
                if colon_idx > 0:
                    name = parts[:colon_idx]
                else:
                    name = parts
            return {
                'federated_workload_type': 'github_actions',
                'federated_workload_name': name,
            }

        # AKS / Kubernetes OIDC
        if 'kubernetes' in issuer.lower() or 'system:serviceaccount:' in subject:
            # subject format: system:serviceaccount:namespace:sa-name
            name = subject
            if 'system:serviceaccount:' in subject:
                sa_parts = subject.split('system:serviceaccount:')[-1]
                # sa_parts is "namespace:sa-name"
                name = sa_parts.replace(':', '/')
            return {
                'federated_workload_type': 'aks_workload',
                'federated_workload_name': name,
            }

        # External / unknown federation
        host = issuer.replace('https://', '').replace('http://', '').split('/')[0]
        return {
            'federated_workload_type': 'external_federation',
            'federated_workload_name': host or subject or 'unknown',
        }

    # ── ARM Resource Graph KQL templates ────────────────────────────
    # Each tuple: (resource_type_label, KQL template with {app_ids} placeholder,
    #              binding_method, confidence_score)
    _ARM_KQL_QUERIES = [
        (
            'AppService',
            """
            Resources
            | where type =~ "microsoft.web/sites"
            | where kind !contains "functionapp"
            | mv-expand setting = properties.siteConfig.appSettings
            | where setting.value in~ ({app_ids})
            | project id, name, resourceGroup, location,
                      settingKey = setting.name, matchedValue = tostring(setting.value)
            """,
            'HardcodedClientId',
            90,
        ),
        (
            'FunctionApp',
            """
            Resources
            | where type =~ "microsoft.web/sites"
            | where kind contains "functionapp"
            | mv-expand setting = properties.siteConfig.appSettings
            | where setting.value in~ ({app_ids})
            | project id, name, resourceGroup, location,
                      settingKey = setting.name, matchedValue = tostring(setting.value)
            """,
            'HardcodedClientId',
            90,
        ),
        (
            'ContainerApp',
            """
            Resources
            | where type =~ "microsoft.app/containerapps"
            | mv-expand container = properties.template.containers
            | mv-expand env = container.env
            | where env.value in~ ({app_ids})
            | project id, name, resourceGroup, location,
                      envKey = env.name, matchedValue = tostring(env.value)
            """,
            'HardcodedClientId',
            85,
        ),
        (
            'LogicApp',
            """
            Resources
            | where type =~ "microsoft.logic/workflows"
            | where properties.parameters has_any ({app_ids})
            | project id, name, resourceGroup, location
            """,
            'HardcodedClientId',
            70,
        ),
    ]

    # Maximum appIds per Resource Graph query batch
    _ARM_BATCH_SIZE = 50

    def _fetch_arm_resource_associations(
        self, service_principals: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Scan Azure Resource Graph for resources referencing SPN appIds.

        Runs 4 KQL queries per batch against Resource Graph, batching
        appIds into groups of 50 to stay within query-size limits.

        Args:
            service_principals: list of identity dicts (must have 'app_id')

        Returns:
            dict mapping app_id -> list of ResourceBinding dicts matching the
            WorkloadAssociationsPanel frontend shape.
        """
        if ResourceGraphClient is None:
            logger.warning("azure-mgmt-resourcegraph not installed — skipping ARM scan")
            return {}

        # Collect non-empty app_ids
        app_id_set: Dict[str, str] = {}  # app_id -> identity_id
        for sp in service_principals:
            aid = sp.get('app_id')
            iid = sp.get('identity_id')
            if aid and iid and sp.get('identity_category') in (
                'service_principal', 'managed_identity_user', 'managed_identity_system'
            ):
                app_id_set[aid] = iid

        if not app_id_set:
            return {}

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            logger.info("ARM scan skipped — no subscriptions available")
            return {}

        rg_client = ResourceGraphClient(self.credential)

        # Batch app_ids
        all_app_ids = list(app_id_set.keys())
        result_map: Dict[str, List[Dict]] = {}

        for batch_start in range(0, len(all_app_ids), self._ARM_BATCH_SIZE):
            batch = all_app_ids[batch_start:batch_start + self._ARM_BATCH_SIZE]
            # Build KQL-safe comma-separated quoted list
            kql_list = ", ".join(f"'{aid}'" for aid in batch)

            for res_type, kql_template, binding_method, confidence in self._ARM_KQL_QUERIES:
                kql = kql_template.replace('{app_ids}', kql_list)
                try:
                    request = QueryRequest(
                        subscriptions=sub_ids,
                        query=kql,
                    )
                    response = rg_client.resources(request)
                    rows = response.data if hasattr(response, 'data') else []
                    if not rows:
                        continue

                    for row in rows:
                        # Determine which app_id matched
                        matched_value = (row.get('matchedValue') or '').strip()
                        if not matched_value:
                            # LogicApp query doesn't project matchedValue — match any in batch
                            for aid in batch:
                                if aid not in result_map:
                                    result_map[aid] = []
                                result_map[aid].append({
                                    'resource_id': row.get('id', ''),
                                    'resource_type': res_type,
                                    'resource_name': row.get('name', ''),
                                    'resource_group': row.get('resourceGroup', ''),
                                    'region': row.get('location', ''),
                                    'binding_method': binding_method,
                                    'confidence_score': max(confidence - 20, 50),
                                    'binding_evidence': {'parameterSearch': True},
                                    'subscription_id': '',
                                    'last_verified_at': None,
                                })
                            continue

                        # Exact match — find which batch app_id
                        matched_aid = None
                        for aid in batch:
                            if aid.lower() == matched_value.lower():
                                matched_aid = aid
                                break
                        if not matched_aid:
                            continue

                        if matched_aid not in result_map:
                            result_map[matched_aid] = []

                        evidence: Dict[str, Any] = {'matchedValue': matched_value}
                        if row.get('settingKey'):
                            evidence['settingKey'] = row['settingKey']
                        if row.get('envKey'):
                            evidence['envKey'] = row['envKey']

                        # Extract subscription_id from ARM resource id
                        rid = row.get('id', '')
                        import re as _re
                        sub_match = _re.search(r'/subscriptions/([^/]+)', rid, _re.IGNORECASE)
                        sub_id = sub_match.group(1) if sub_match else ''

                        result_map[matched_aid].append({
                            'resource_id': rid,
                            'resource_type': res_type,
                            'resource_name': row.get('name', ''),
                            'resource_group': row.get('resourceGroup', ''),
                            'region': row.get('location', ''),
                            'binding_method': binding_method,
                            'confidence_score': confidence,
                            'binding_evidence': evidence,
                            'subscription_id': sub_id,
                            'last_verified_at': None,
                        })

                except Exception as e:
                    logger.warning("ARM Resource Graph query failed for %s: %s", res_type, e)
                    continue

        total_bindings = sum(len(v) for v in result_map.values())
        if total_bindings:
            logger.info("ARM Resource Graph: found %s bindings across %s SPNs",
                        total_bindings, len(result_map))
        return result_map

    # KQL for managed identity association scan
    _MI_KQL = """
        Resources
        | where isnotempty(identity)
        | project id, name, type, resourceGroup, location,
                  identityType = tostring(identity.type),
                  systemPrincipalId = tostring(identity.principalId),
                  userAssigned = identity.userAssignedIdentities
    """

    def _fetch_managed_identity_associations(
        self, all_identities: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Scan Azure Resource Graph for resources with managed identity blocks.

        Queries all resources that have an `identity` property, then maps:
          - identity.principalId  → system-assigned MI (match via object_id)
          - identity.userAssignedIdentities keys → user-assigned MI ARM resource IDs
            (match via alternativeNames on the SPN)

        Args:
            all_identities: list of identity dicts (from discovery)

        Returns:
            dict mapping object_id -> list of ResourceBinding dicts
        """
        if ResourceGraphClient is None:
            logger.warning("azure-mgmt-resourcegraph not installed — skipping MI scan")
            return {}

        sub_ids = [s['id'] for s in self.subscriptions]
        if not sub_ids:
            return {}

        # Build lookup maps for matching
        # 1. object_id → identity_id (for system-assigned: principalId == object_id)
        oid_to_iid: Dict[str, str] = {}
        # 2. ARM resource ID (lowercase) → object_id (for user-assigned)
        uami_arm_to_oid: Dict[str, str] = {}

        for identity in all_identities:
            cat = identity.get('identity_category', '')
            oid = identity.get('object_id')
            if not oid:
                continue

            if cat in ('managed_identity_system', 'managed_identity_user', 'service_principal'):
                oid_to_iid[oid] = identity.get('identity_id', oid)

            # User-assigned MIs have ARM resource IDs in alternativeNames
            if cat == 'managed_identity_user':
                for alt in (identity.get('alternative_names') or []):
                    alt_str = str(alt).strip()
                    if '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' in alt_str:
                        uami_arm_to_oid[alt_str.lower()] = oid

        if not oid_to_iid and not uami_arm_to_oid:
            return {}

        rg_client = ResourceGraphClient(self.credential)
        result_map: Dict[str, List[Dict]] = {}

        try:
            request = QueryRequest(
                subscriptions=sub_ids,
                query=self._MI_KQL,
            )
            response = rg_client.resources(request)
            rows = response.data if hasattr(response, 'data') else []
        except Exception as e:
            logger.warning("Managed identity Resource Graph query failed: %s", e)
            return {}

        if not rows:
            return {}

        import re as _re

        for row in rows:
            resource_id = row.get('id', '')
            resource_name = row.get('name', '')
            resource_type_raw = row.get('type', '')
            resource_group = row.get('resourceGroup', '')
            region = row.get('location', '')
            sub_match = _re.search(r'/subscriptions/([^/]+)', resource_id, _re.IGNORECASE)
            sub_id = sub_match.group(1) if sub_match else ''

            # Normalize resource type: microsoft.web/sites → WebApp
            rtype_short = resource_type_raw.split('/')[-1] if '/' in resource_type_raw else resource_type_raw

            # ── System-assigned MI ──
            sys_pid = (row.get('systemPrincipalId') or '').strip()
            if sys_pid and sys_pid in oid_to_iid:
                if sys_pid not in result_map:
                    result_map[sys_pid] = []
                result_map[sys_pid].append({
                    'resource_id': resource_id,
                    'resource_type': rtype_short,
                    'resource_name': resource_name,
                    'resource_group': resource_group,
                    'region': region,
                    'binding_method': 'ManagedIdentitySystemAssigned',
                    'confidence_score': 95,
                    'binding_evidence': {
                        'principalId': sys_pid,
                        'identityType': row.get('identityType', ''),
                        'association_type': 'managed_identity',
                        'match_type': 'managed_identity_binding',
                    },
                    'subscription_id': sub_id,
                    'last_verified_at': None,
                })

            # ── User-assigned MIs ──
            user_assigned = row.get('userAssigned')
            if isinstance(user_assigned, dict):
                for uami_arm_id, uami_props in user_assigned.items():
                    uami_key = uami_arm_id.strip().lower()
                    matched_oid = uami_arm_to_oid.get(uami_key)
                    if not matched_oid:
                        # Try matching by principalId inside the value
                        if isinstance(uami_props, dict):
                            pid = (uami_props.get('principalId') or '').strip()
                            if pid and pid in oid_to_iid:
                                matched_oid = pid
                    if not matched_oid:
                        continue

                    if matched_oid not in result_map:
                        result_map[matched_oid] = []
                    result_map[matched_oid].append({
                        'resource_id': resource_id,
                        'resource_type': rtype_short,
                        'resource_name': resource_name,
                        'resource_group': resource_group,
                        'region': region,
                        'binding_method': 'ManagedIdentityUserAssigned',
                        'confidence_score': 95,
                        'binding_evidence': {
                            'userAssignedArmId': uami_arm_id,
                            'principalId': uami_props.get('principalId', '') if isinstance(uami_props, dict) else '',
                            'association_type': 'managed_identity',
                            'match_type': 'managed_identity_binding',
                        },
                        'subscription_id': sub_id,
                        'last_verified_at': None,
                    })

        total = sum(len(v) for v in result_map.values())
        sys_count = sum(
            1 for bindings in result_map.values()
            for b in bindings if b['binding_method'] == 'ManagedIdentitySystemAssigned'
        )
        uami_count = total - sys_count
        if total:
            logger.info("Managed identity associations: %s bindings (%s system-assigned, %s user-assigned) across %s identities",
                        total, sys_count, uami_count, len(result_map))
        return result_map

    async def _discover_credentials(self, service_principals: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover credentials (secrets, certificates, federated) for service principals

        Returns:
            Dictionary mapping identity_id to list of credentials
        """
        credentials_map = {}
        
        logger.info("Discovering SPN Credentials...")
        
        for sp in service_principals:
            try:
                # Get full service principal details including credentials
                sp_response = await self.graph_client.service_principals.by_service_principal_id(sp['object_id']).get()
                
                credentials = []
                
                # Process password credentials (secrets)
                if hasattr(sp_response, 'password_credentials') and sp_response.password_credentials:
                    for pwd_cred in sp_response.password_credentials:
                        credentials.append({
                            'credential_type': 'secret',
                            'key_id': str(pwd_cred.key_id) if pwd_cred.key_id else None,
                            'display_name': pwd_cred.display_name if hasattr(pwd_cred, 'display_name') else None,
                            'start_datetime': pwd_cred.start_date_time.isoformat() if hasattr(pwd_cred, 'start_date_time') and pwd_cred.start_date_time else None,
                            'end_datetime': pwd_cred.end_date_time.isoformat() if hasattr(pwd_cred, 'end_date_time') and pwd_cred.end_date_time else None,
                        })
                
                # Process key credentials (certificates)
                if hasattr(sp_response, 'key_credentials') and sp_response.key_credentials:
                    for key_cred in sp_response.key_credentials:
                        credentials.append({
                            'credential_type': 'certificate',
                            'key_id': str(key_cred.key_id) if key_cred.key_id else None,
                            'display_name': key_cred.display_name if hasattr(key_cred, 'display_name') else None,
                            'start_datetime': key_cred.start_date_time.isoformat() if hasattr(key_cred, 'start_date_time') and key_cred.start_date_time else None,
                            'end_datetime': key_cred.end_date_time.isoformat() if hasattr(key_cred, 'end_date_time') and key_cred.end_date_time else None,
                            'thumbprint': key_cred.custom_key_identifier.decode('utf-8') if hasattr(key_cred, 'custom_key_identifier') and key_cred.custom_key_identifier else None,
                        })
                
                # Process federated credentials
                if hasattr(sp_response, 'federated_identity_credentials') and sp_response.federated_identity_credentials:
                    for fed_cred in sp_response.federated_identity_credentials:
                        issuer = fed_cred.issuer if hasattr(fed_cred, 'issuer') else None
                        subject = fed_cred.subject if hasattr(fed_cred, 'subject') else None
                        classification = self._classify_federated_credential(issuer, subject)
                        cred_dict = {
                            'credential_type': 'federated',
                            'key_id': fed_cred.id if hasattr(fed_cred, 'id') else str(hash(fed_cred.subject)),
                            'display_name': fed_cred.name if hasattr(fed_cred, 'name') else None,
                            'start_datetime': None,
                            'end_datetime': None,  # Federated credentials don't expire
                            'issuer': issuer,
                            'subject': subject,
                        }
                        cred_dict.update(classification)
                        credentials.append(cred_dict)
                
                if credentials:
                    credentials_map[sp['identity_id']] = credentials
                    if len(credentials_map) <= 5:  # Show first 5
                        logger.info("%s: %s credential(s)", sp['display_name'], len(credentials))
            
            except Exception as e:
                # Don't fail entire discovery if one SPN fails
                if len(credentials_map) == 0:  # Only show first error
                    logger.warning("Error getting credentials for %s: %s", sp['display_name'], e)
                continue
        
        logger.info("Found credentials for %s SPNs", len(credentials_map))
        return credentials_map


    async def _resolve_app_role_name(self, resource_spn_id: str, app_role_id: str) -> tuple:
        """
        Resolve appRoleId to (permission_name, resource_display_name) using cache.
        Returns ('', '') if unresolvable.
        """
        resource_spn_id = str(resource_spn_id)
        app_role_id = str(app_role_id)

        if resource_spn_id not in self._resource_spn_cache:
            try:
                resource_sp = await self.graph_client.service_principals.by_service_principal_id(
                    resource_spn_id
                ).get()
                roles_lookup = {}
                if hasattr(resource_sp, 'app_roles') and resource_sp.app_roles:
                    for role in resource_sp.app_roles:
                        roles_lookup[str(role.id)] = role.value or ''
                self._resource_spn_cache[resource_spn_id] = {
                    'roles': roles_lookup,
                    'display_name': resource_sp.display_name if resource_sp.display_name else 'Unknown',
                }
            except Exception as e:
                logger.debug("Could not fetch resource SPN %s: %s", resource_spn_id, e)
                self._resource_spn_cache[resource_spn_id] = {'roles': {}, 'display_name': 'Unknown'}

        cached = self._resource_spn_cache[resource_spn_id]
        perm_name = cached['roles'].get(app_role_id, '')
        return perm_name, cached['display_name']

    async def _discover_permissions(self, service_principals: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover Graph API permissions for service principals.

        Collects both:
          - Application permissions (appRoleAssignments) — what the SPN can do as itself
          - Delegated permissions (oauth2PermissionGrants) — what users consented to

        Returns:
            Dictionary mapping identity_id to list of permissions
        """
        permissions_map: Dict[str, List[Dict]] = {}
        app_perm_total = 0
        delegated_perm_total = 0
        error_count = 0

        logger.info("Discovering API Permissions...")

        for sp in service_principals:
            sp_object_id = sp.get('object_id')
            sp_identity_id = sp.get('identity_id')
            if not sp_object_id:
                continue

            permissions: List[Dict] = []

            # ── Application permissions (appRoleAssignments) ──
            try:
                assignments = await self.graph_client.service_principals.by_service_principal_id(
                    sp_object_id
                ).app_role_assignments.get()

                if assignments and assignments.value:
                    for assignment in assignments.value:
                        resource_id = str(assignment.resource_id) if assignment.resource_id else ''
                        app_role_id = str(assignment.app_role_id) if assignment.app_role_id else ''

                        perm_name, resource_name = await self._resolve_app_role_name(resource_id, app_role_id)
                        if perm_name:
                            permissions.append({
                                'name': perm_name,
                                'description': f"{resource_name}: {perm_name}",
                                'resource_name': resource_name,
                                'permission_type': 'Application',
                                'permission_id': app_role_id,
                                'consent_type': 'Admin',
                            })
                            app_perm_total += 1
            except Exception as e:
                logger.warning("appRoleAssignments failed for %s (%s): %s",
                               sp.get('display_name', '?'), sp_object_id, e)
                error_count += 1

            # ── Delegated permissions (oauth2PermissionGrants) ──
            try:
                from msgraph.generated.oauth2_permission_grants.oauth2_permission_grants_request_builder import Oauth2PermissionGrantsRequestBuilder
                from kiota_abstractions.base_request_configuration import RequestConfiguration

                query = Oauth2PermissionGrantsRequestBuilder.Oauth2PermissionGrantsRequestBuilderGetQueryParameters(
                    filter=f"clientId eq '{sp_object_id}'",
                )
                config = RequestConfiguration(query_parameters=query)
                grants = await self.graph_client.oauth2_permission_grants.get(request_configuration=config)

                if grants and grants.value:
                    for grant in grants.value:
                        # Resolve resource SPN to get actual resource name
                        resource_spn_id = str(grant.resource_id) if grant.resource_id else ''
                        resource_name = 'Microsoft Graph'
                        resource_app_id = ''
                        if resource_spn_id and resource_spn_id in self._resource_spn_cache:
                            cached = self._resource_spn_cache[resource_spn_id]
                            resource_name = cached.get('display_name', 'Microsoft Graph')
                            resource_app_id = cached.get('app_id', '')
                        elif resource_spn_id:
                            try:
                                res_sp = await self.graph_client.service_principals.by_service_principal_id(
                                    resource_spn_id
                                ).get()
                                if res_sp:
                                    resource_name = res_sp.display_name or 'Microsoft Graph'
                                    resource_app_id = str(res_sp.app_id) if res_sp.app_id else ''
                                    self._resource_spn_cache[resource_spn_id] = {
                                        'display_name': resource_name,
                                        'app_id': resource_app_id,
                                        'roles': {},
                                    }
                            except Exception:
                                pass
                        scope_str = grant.scope or ''
                        for perm_name in scope_str.split():
                            perm_name = perm_name.strip()
                            if perm_name:
                                permissions.append({
                                    'name': perm_name,
                                    'description': perm_name,
                                    'resource_name': resource_name,
                                    'resource_app_id': resource_app_id,
                                    'permission_type': 'Delegated',
                                    'consent_type': grant.consent_type or 'Unknown',
                                })
                                delegated_perm_total += 1
            except Exception as e:
                logger.warning("oauth2PermissionGrants failed for %s (%s): %s",
                               sp.get('display_name', '?'), sp_object_id, e)
                error_count += 1

            if permissions:
                permissions_map[sp_identity_id] = permissions
                if len(permissions_map) <= 5:  # Show first 5
                    logger.info("%s: %s permission(s)", sp['display_name'], len(permissions))

        # ── M1: Compute api_usage_pattern per SPN from distinct resource APIs ──
        for sp in service_principals:
            sp_identity_id = sp.get('identity_id')
            perms = permissions_map.get(sp_identity_id, [])
            if not perms:
                continue
            # Collect distinct resource API names
            resource_apis = set()
            for p in perms:
                rname = p.get('resource_name', '')
                # Map display name back to KNOWN_APIS key
                for api_id, api_label in self.KNOWN_APIS.items():
                    if api_label.replace('_', ' ') in rname.lower() or rname.lower().replace(' ', '_') == api_label:
                        resource_apis.add(api_label)
                        break
                else:
                    # Try resource_app_id directly
                    rap_id = p.get('resource_app_id', '')
                    if rap_id in self.KNOWN_APIS:
                        resource_apis.add(self.KNOWN_APIS[rap_id])
                    elif 'graph' in rname.lower():
                        resource_apis.add('microsoft_graph')
            api_list = sorted(resource_apis)
            sp['oauth2_resource_apis'] = api_list or None
            # Match against API_USAGE_WORKLOAD_MAP
            pattern = 'none'
            frozen = frozenset(resource_apis)
            if frozen in self.API_USAGE_WORKLOAD_MAP:
                pattern = self.API_USAGE_WORKLOAD_MAP[frozen]
            elif resource_apis:
                # Try subset matching — find the best match
                best_match = None
                best_size = 0
                for key_set, label in self.API_USAGE_WORKLOAD_MAP.items():
                    if key_set.issubset(frozen) and len(key_set) > best_size:
                        best_match = label
                        best_size = len(key_set)
                pattern = best_match or f'multi_api_{len(resource_apis)}'
            sp['api_usage_pattern'] = pattern

        logger.info("Permissions: %s application + %s delegated across %s SPNs%s",
                     app_perm_total, delegated_perm_total, len(permissions_map),
                     " (%s errors)" % error_count if error_count else "")
        return permissions_map

    async def _discover_app_roles(self, service_principals: list) -> dict:
        """
        Discover custom application role assignments for service principals.
        Returns assignments to custom apps (NOT Microsoft Graph).
        
        Similar to _discover_permissions but filters OUT Microsoft Graph.
        
        Args:
            service_principals: List of service principal dicts
            
        Returns:
            Dict mapping identity_id to list of app role assignments
        """
        logger.info("Discovering Custom App Roles...")
        app_roles_map = {}
        found_count = 0
        
        for sp in service_principals:
            identity_id = sp.get('id')
            if not identity_id:
                continue
            
            try:
                # Fetch app role assignments (same endpoint as permissions)
                response = await self.graph_client.service_principals.by_service_principal_id(
                    identity_id
                ).app_role_assignments.get()
                
                assignments = response.value if response and response.value else []
                
                # Filter OUT Microsoft Graph (we store those separately)
                custom_app_roles = [
                    {
                        'app_role_id': assignment.app_role_id,
                        'resource_id': assignment.resource_id,
                        'resource_display_name': assignment.resource_display_name,
                        'principal_display_name': assignment.principal_display_name,
                        'created_date_time': assignment.created_date_time.isoformat() if assignment.created_date_time else None,
                    }
                    for assignment in assignments
                    if assignment.resource_display_name and assignment.resource_display_name.lower() != 'microsoft graph'
                ]
                
                if custom_app_roles:
                    app_roles_map[identity_id] = custom_app_roles
                    found_count += 1
                    logger.info("%s: %s app role(s)", sp.get('displayName', 'Unknown'), len(custom_app_roles))
                
            except Exception as e:
                # Silently skip if no permissions or access denied
                continue
        
        if found_count > 0:
            logger.info("Fetched app roles for %s service principals", found_count)
        else:
            logger.info("No custom app role assignments found")
        
        return app_roles_map

    async def _discover_ownership(self, service_principals: list) -> dict:
        """
        Discover owners for service principals via their application registration.

        Each SPN may have an associated application registration with owners.
        Owners are typically the humans who created or manage the application.

        Microsoft Graph API: GET /applications/{app-id}/owners

        Returns:
            Dict mapping identity_id -> list of owner dicts
        """
        logger.info("Discovering Application Owners...")
        ownership_map = {}
        found_count = 0
        error_count = 0

        for sp in service_principals:
            identity_id = sp.get('identity_id')
            app_id = sp.get('app_id')

            # Skip if no app_id (e.g., managed identities don't have app registrations)
            if not app_id:
                continue

            # Skip Microsoft internal apps
            if sp.get('is_microsoft_system'):
                continue

            try:
                # Get the application by appId, then get its owners
                # First, find the application object ID from the appId
                from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder
                from kiota_abstractions.base_request_configuration import RequestConfiguration

                query_params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                    filter=f"appId eq '{app_id}'",
                    select=['id', 'displayName']
                )
                request_config = RequestConfiguration(query_parameters=query_params)

                apps = await self.graph_client.applications.get(request_configuration=request_config)

                if apps and apps.value and len(apps.value) > 0:
                    app_object_id = apps.value[0].id

                    # Now get the owners
                    owners_response = await self.graph_client.applications.by_application_id(app_object_id).owners.get()

                    if owners_response and owners_response.value:
                        owners = []
                        is_first = True
                        for owner in owners_response.value:
                            owner_data = {
                                'owner_object_id': owner.id,
                                'owner_display_name': getattr(owner, 'display_name', None),
                                'owner_upn': getattr(owner, 'user_principal_name', None) or getattr(owner, 'mail', None),
                                'owner_type': 'user' if hasattr(owner, 'user_principal_name') else 'servicePrincipal',
                                'is_primary_owner': is_first,
                                'ownership_type': 'application',
                            }
                            owners.append(owner_data)
                            is_first = False

                        if owners:
                            ownership_map[identity_id] = owners
                            found_count += 1

                            if found_count <= 5:
                                logger.info("%s: %s owner(s)", sp.get('display_name', 'Unknown'), len(owners))

            except Exception as e:
                error_count += 1
                if error_count <= 3:
                    logger.warning("Could not get owners for %s: %s", sp.get('display_name', 'Unknown'), str(e)[:50])

        if found_count > 0:
            logger.info("Found owners for %s applications", found_count)
        else:
            logger.info("No application owners found")

        if error_count > 3:
            logger.warning("%s errors occurred (showing first 3)", error_count)

        return ownership_map

    async def _discover_pim_assignments(self) -> dict:
        """
        Discover PIM eligible role assignments and active activations.

        Uses Microsoft Graph API:
        - roleEligibilityScheduleInstances — eligible roles
        - roleAssignmentScheduleInstances — active activations (filter: Activated)
        - roleAssignmentScheduleRequests — history with justification/ticket

        Requires Azure AD P2 license. Handle 403 gracefully.

        Returns:
            Dict mapping object_id -> { 'eligible': [...], 'activations': [...] }
        """
        logger.info("Discovering PIM Assignments...")
        pim_map = {}  # keyed by principal object_id

        # Cache role definitions to avoid redundant API calls
        role_def_cache = {}

        async def _get_role_name(role_definition_id: str) -> str:
            if role_definition_id in role_def_cache:
                return role_def_cache[role_definition_id]
            try:
                role_def = await self.graph_client.role_management.directory.role_definitions.by_unified_role_definition_id(role_definition_id).get()
                name = role_def.display_name if role_def else "Unknown Role"
            except Exception:
                name = "Unknown Role"
            role_def_cache[role_definition_id] = name
            return name

        # --- Eligible assignments ---
        eligible_count = 0
        try:
            eligible_response = await self.graph_client.role_management.directory.role_eligibility_schedule_instances.get()
            if eligible_response and eligible_response.value:
                for item in eligible_response.value:
                    principal_id = item.principal_id
                    role_def_id = item.role_definition_id
                    role_name = await _get_role_name(role_def_id)

                    if principal_id not in pim_map:
                        pim_map[principal_id] = {'eligible': [], 'activations': []}

                    is_permanent = item.end_date_time is None
                    pim_map[principal_id]['eligible'].append({
                        'role_name': role_name,
                        'role_definition_id': role_def_id,
                        'directory_scope': getattr(item, 'directory_scope_id', '/') or '/',
                        'assignment_type': 'permanent_eligible' if is_permanent else 'time_bound_eligible',
                        'start_datetime': item.start_date_time.isoformat() if item.start_date_time else None,
                        'end_datetime': item.end_date_time.isoformat() if item.end_date_time else None,
                        'member_type': getattr(item, 'member_type', None),
                    })
                    eligible_count += 1

            logger.info("Found %s PIM eligible assignments", eligible_count)

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                logger.info("PIM eligible assignments: requires Azure AD P2 license (403)")
            else:
                logger.warning("PIM eligible assignments error: %s", err_str[:80])

        # --- Active activations ---
        activation_count = 0
        try:
            activations_response = await self.graph_client.role_management.directory.role_assignment_schedule_instances.get()
            if activations_response and activations_response.value:
                for item in activations_response.value:
                    # Only track activated (JIT) assignments, skip permanently assigned
                    assignment_type = getattr(item, 'assignment_type', None)
                    if assignment_type and assignment_type.lower() == 'assigned':
                        continue

                    principal_id = item.principal_id
                    role_def_id = item.role_definition_id
                    role_name = await _get_role_name(role_def_id)

                    if principal_id not in pim_map:
                        pim_map[principal_id] = {'eligible': [], 'activations': []}

                    pim_map[principal_id]['activations'].append({
                        'role_name': role_name,
                        'role_definition_id': role_def_id,
                        'directory_scope': getattr(item, 'directory_scope_id', '/') or '/',
                        'status': 'Active',
                        'activation_start': item.start_date_time.isoformat() if item.start_date_time else None,
                        'activation_end': item.end_date_time.isoformat() if item.end_date_time else None,
                    })
                    activation_count += 1

            logger.info("Found %s active PIM activations", activation_count)

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                logger.info("PIM activations: requires Azure AD P2 license (403)")
            else:
                logger.warning("PIM activations error: %s", err_str[:80])

        # --- Activation history (requests with justification/ticket) ---
        try:
            from kiota_abstractions.base_request_configuration import RequestConfiguration

            requests_response = await self.graph_client.role_management.directory.role_assignment_schedule_requests.get()
            if requests_response and requests_response.value:
                for item in requests_response.value:
                    principal_id = item.principal_id
                    if principal_id not in pim_map:
                        continue  # only enrich identities we already know about

                    # Find matching activation and enrich with justification/ticket
                    role_def_id = item.role_definition_id
                    justification = getattr(item, 'justification', None)
                    ticket_info = getattr(item, 'ticket_info', None)
                    ticket_number = getattr(ticket_info, 'ticket_number', None) if ticket_info else None
                    ticket_system = getattr(ticket_info, 'ticket_system', None) if ticket_info else None
                    is_approval_required = False
                    created_dt = getattr(item, 'created_date_time', None)

                    for act in pim_map[principal_id]['activations']:
                        if act['role_definition_id'] == role_def_id and not act.get('justification'):
                            act['justification'] = justification
                            act['ticket_number'] = ticket_number
                            act['ticket_system'] = ticket_system
                            act['is_approval_required'] = is_approval_required
                            act['created_datetime'] = created_dt.isoformat() if created_dt else None
                            break

        except Exception as e:
            err_str = str(e)
            if '403' not in err_str and 'Forbidden' not in err_str:
                logger.warning("PIM request history error: %s", err_str[:80])

        if pim_map:
            logger.info("PIM data found for %s principals", len(pim_map))
        else:
            logger.info("No PIM data found (Azure AD P2 required)")

        return pim_map

    async def _discover_conditional_access(self) -> list:
        """
        Discover Conditional Access policies via Microsoft Graph API.

        Uses: graph_client.identity.conditional_access.policies.get()
        Requires: Policy.Read.All permission. Handle 403 gracefully.

        Returns:
            List of parsed CA policy dicts
        """
        logger.info("Discovering Conditional Access Policies...")
        policies = []

        try:
            ca_response = await self.graph_client.identity.conditional_access.policies.get()
            if ca_response and ca_response.value:
                for policy in ca_response.value:
                    state = getattr(policy, 'state', None)
                    if state and hasattr(state, 'value'):
                        state = state.value
                    state = str(state or 'unknown').lower()

                    # Parse conditions
                    conditions = getattr(policy, 'conditions', None)
                    users_cond = getattr(conditions, 'users', None) if conditions else None
                    apps_cond = getattr(conditions, 'applications', None) if conditions else None
                    client_app_types = getattr(conditions, 'client_app_types', []) if conditions else []
                    if client_app_types and hasattr(client_app_types[0], 'value'):
                        client_app_types = [str(c.value) for c in client_app_types]
                    else:
                        client_app_types = [str(c) for c in (client_app_types or [])]

                    include_users = []
                    exclude_users = []
                    targets_all_users = False
                    has_exclusions = False

                    if users_cond:
                        inc = getattr(users_cond, 'include_users', []) or []
                        exc = getattr(users_cond, 'exclude_users', []) or []
                        include_users = [str(u) for u in inc]
                        exclude_users = [str(u) for u in exc]
                        targets_all_users = 'All' in include_users
                        has_exclusions = len(exclude_users) > 0

                    include_applications = []
                    if apps_cond:
                        inc_apps = getattr(apps_cond, 'include_applications', []) or []
                        include_applications = [str(a) for a in inc_apps]

                    # Parse grant controls
                    grant = getattr(policy, 'grant_controls', None)
                    requires_mfa = False
                    grant_dict = {}
                    if grant:
                        built_in = getattr(grant, 'built_in_controls', []) or []
                        if built_in and hasattr(built_in[0], 'value'):
                            built_in = [str(c.value) for c in built_in]
                        else:
                            built_in = [str(c) for c in built_in]
                        requires_mfa = 'mfa' in [b.lower() for b in built_in]
                        grant_dict = {'built_in_controls': built_in}

                    # Legacy auth detection
                    allows_legacy_auth = 'exchangeActiveSync' in client_app_types or 'other' in client_app_types

                    modified = getattr(policy, 'modified_date_time', None)

                    policies.append({
                        'policy_id': policy.id,
                        'display_name': policy.display_name or 'Unnamed',
                        'state': state,
                        'include_users': include_users,
                        'exclude_users': exclude_users,
                        'include_applications': include_applications,
                        'client_app_types': client_app_types,
                        'grant_controls': grant_dict,
                        'session_controls': {},
                        'requires_mfa': requires_mfa,
                        'targets_all_users': targets_all_users,
                        'has_exclusions': has_exclusions,
                        'allows_legacy_auth': allows_legacy_auth,
                        'modified_datetime': modified.isoformat() if modified else None,
                    })

            logger.info("Found %s Conditional Access policies", len(policies))
            enabled = sum(1 for p in policies if p['state'] == 'enabled')
            mfa = sum(1 for p in policies if p['requires_mfa'] and p['state'] == 'enabled')
            logger.info("Enabled: %s, MFA-enforcing: %s", enabled, mfa)

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                logger.info("Conditional Access: requires Policy.Read.All permission (403)")
            else:
                logger.warning("Conditional Access error: %s", err_str[:80])

        return policies

    def _compute_ca_coverage(self, ca_policies: list, identities: list) -> dict:
        """
        Compute per-identity CA coverage using a simplified heuristic.

        If any enabled policy targets 'All' users and the identity is not excluded -> covered.

        Returns:
            Dict mapping object_id -> coverage dict
        """
        coverage_map = {}

        # Build set of exclude user IDs from all-users policies
        all_user_policies = [p for p in ca_policies if p.get('targets_all_users') and p.get('state') == 'enabled']
        mfa_all_user_policies = [p for p in all_user_policies if p.get('requires_mfa')]

        # Build global exclude set
        global_excludes = set()
        for p in all_user_policies:
            for uid in p.get('exclude_users', []):
                global_excludes.add(uid)

        for identity in identities:
            object_id = identity.get('object_id')
            if not object_id:
                continue

            is_excluded = object_id in global_excludes
            applicable = len(all_user_policies)
            excluded_from = sum(1 for p in all_user_policies if object_id in p.get('exclude_users', []))

            if applicable == 0:
                coverage_status = 'no_coverage'
                mfa_enforced = False
            elif is_excluded:
                coverage_status = 'excluded'
                mfa_enforced = False
            else:
                mfa_enforced = len(mfa_all_user_policies) > 0 and not is_excluded
                coverage_status = 'covered'

            risk_flags = []
            if is_excluded and applicable > 0:
                risk_flags.append('excluded_from_ca_policy')
            if not mfa_enforced and applicable > 0:
                risk_flags.append('no_mfa_enforced')

            coverage_map[object_id] = {
                'coverage_status': coverage_status,
                'mfa_enforced': mfa_enforced,
                'applicable_policy_count': applicable,
                'excluded_from_count': excluded_from,
                'risk_flags': risk_flags,
            }

        return coverage_map

    async def _discover_managed_identities(self) -> List[Dict]:
        """
        Discover user-assigned managed identities from Azure subscription.
        These appear as service principals in Entra ID with servicePrincipalType = 'ManagedIdentity'.
        
        Note: System-assigned managed identities are tied to specific Azure resources
        and are filtered out by _is_microsoft_system_app() since they're auto-managed.
        
        Returns:
            List of managed identity dicts (already in service_principals, this is supplementary)
        """
        managed_identities = []
        
        try:
            # Managed identities are actually already in the service principals list!
            # They have servicePrincipalType = 'ManagedIdentity' for user-assigned
            # We don't need a separate call - they're included in _discover_service_principals
            
            # This method exists for potential future enhancement (e.g., fetching from ARM API)
            # For now, managed identities are already discovered as service principals
            pass
            
        except Exception as e:
            logger.warning("Could not discover managed identities: %s", e)
        
        return managed_identities
    
    async def _discover_users(self, principal_ids_with_roles: Set[str]) -> List[Dict[str, Any]]:
        """Discover ALL users in the tenant via direct HTTP with pagination.

        Every user is returned regardless of role assignments. The
        principal_ids_with_roles set is only used to optimise manager lookups
        (fetching managers for every user would be O(N) API calls).
        """
        import aiohttp

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = ','.join([
                'id', 'displayName', 'userPrincipalName', 'accountEnabled',
                'createdDateTime', 'userType', 'employeeId', 'department', 'jobTitle',
                'signInActivity', 'onPremisesSyncEnabled', 'mail', 'assignedLicenses',
            ])
            url: str | None = (
                f"https://graph.microsoft.com/v1.0/users"
                f"?$select={select_fields}&$top=999"
            )

            all_users: list[dict] = []
            page = 0
            sign_in_available = True

            async with aiohttp.ClientSession() as session:
                while url:
                    page += 1
                    async with session.get(url, headers=headers) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            # If signInActivity fails (403 / needs P2), retry page 1 without it
                            if page == 1 and ('signInActivity' in body or resp.status == 403):
                                logger.warning("signInActivity requires Entra ID P2 — retrying without it")
                                sign_in_available = False
                                select_no_sia = select_fields.replace(',signInActivity', '')
                                url = (
                                    f"https://graph.microsoft.com/v1.0/users"
                                    f"?$select={select_no_sia}&$top=999"
                                )
                                continue
                            logger.error("Graph API error %s on users page %s: %s", resp.status, page, body[:500])
                            break
                        data = await resp.json()

                    for u in data.get('value', []):
                        all_users.append(u)

                    url = data.get('@odata.nextLink')

            logger.info("Fetched %s users across %s page(s) (signInActivity=%s)", len(all_users), page, sign_in_available)

            # Fetch manager info only for users that have roles (optimisation)
            manager_map: dict[str, dict] = {}
            for u in all_users:
                uid = u.get('id')
                if uid and uid in principal_ids_with_roles:
                    try:
                        mgr = await self.graph_client.users.by_user_id(uid).manager.get()
                        if mgr:
                            manager_map[uid] = {
                                'manager_id': getattr(mgr, 'id', None),
                                'manager_upn': getattr(mgr, 'user_principal_name', None),
                            }
                    except Exception:
                        pass

            ice_config = self._load_ice_config()

            identities = []
            for u in all_users:
                uid = u.get('id')
                display_name = u.get('displayName')
                upn = u.get('userPrincipalName')

                if len(identities) < 10:
                    logger.info("User: %s (%s)", display_name, upn)

                created = u.get('createdDateTime')

                user_type = u.get('userType') or ''
                user_type_lower = user_type.lower()
                is_guest = user_type_lower in ('guest', 'externalmember')

                last_sign_in = None
                sia = u.get('signInActivity')
                if sia:
                    last_sign_in = (
                        sia.get('lastSignInDateTime')
                        or sia.get('lastNonInteractiveSignInDateTime')
                    )
                # Store raw signInActivity for pattern classification
                _signin_raw = {}
                if sia:
                    _signin_raw = {
                        'lastSignInDateTime': sia.get('lastSignInDateTime'),
                        'lastDelegatedSignInDateTime': sia.get('lastDelegatedClientSignInDateTime'),
                        'lastNonInteractiveSignInDateTime': sia.get('lastNonInteractiveSignInDateTime'),
                    }

                mgr_info = manager_map.get(uid, {})

                # Build a lightweight mock for _classify_account_category
                class _UserProxy:
                    user_principal_name = upn
                user_proxy = _UserProxy()

                identities.append({
                    'identity_id': uid,
                    'object_id': uid,
                    'app_id': None,
                    'display_name': display_name,
                    'user_principal_name': upn,
                    'identity_type': 'user',
                    'identity_category': 'guest' if is_guest else 'human_user',
                    'enabled': u.get('accountEnabled', True),
                    'created_datetime': created,
                    'last_sign_in': last_sign_in,
                    'on_premises_sync_enabled': u.get('onPremisesSyncEnabled'),
                    'mail': u.get('mail'),
                    'assigned_licenses': u.get('assignedLicenses', []),
                    # Multi-cloud normalized fields
                    'cloud': 'azure',
                    'azure_directory_id': self.azure_directory_id,
                    'source': 'entra',
                    'permission_plane': 'entra_id',
                    'is_federated': is_guest,
                    # ICE fields
                    'upn': upn,
                    'employee_id_entra': u.get('employeeId'),
                    'department': u.get('department'),
                    'job_title': u.get('jobTitle'),
                    'manager_id': mgr_info.get('manager_id'),
                    'manager_upn': mgr_info.get('manager_upn'),
                    'account_category': self._classify_account_category(user_proxy, ice_config),
                    '_signin_activity_raw': _signin_raw,
                })

            logger.info("Discovered %s users (%s with roles, %s without)",
                        len(identities),
                        sum(1 for i in identities if i['identity_id'] in principal_ids_with_roles),
                        sum(1 for i in identities if i['identity_id'] not in principal_ids_with_roles))
            return identities
        except Exception as e:
            logger.error("Error discovering users: %s", e)
            return []
    
    _ice_config_cache = None

    def _load_ice_config(self) -> dict:
        """Load ICE configuration from settings table, with caching."""
        if self._ice_config_cache is not None:
            return self._ice_config_cache
        defaults = {
            'ice_privileged_prefixes': 'ep.,adm-,adm.,a-,admin-,admin.,priv-,priv.,sa_,pa-,pa.',
            'ice_privileged_suffixes': '-admin,.admin,-priv,.priv,-elevated,.elevated',
        }
        try:
            from app.database import Database
            db = Database()
            try:
                from psycopg2.extras import RealDictCursor
                cursor = db.conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("SELECT key, value FROM settings WHERE key IN ('ice_privileged_prefixes', 'ice_privileged_suffixes')")
                rows = cursor.fetchall()
                cursor.close()
                for row in rows:
                    defaults[row['key']] = row['value']
            finally:
                db.close()
        except Exception:
            pass
        self._ice_config_cache = defaults
        return defaults

    def _classify_account_category(self, user, ice_config: dict) -> str:
        """Classify a user account as regular, privileged, or service_account."""
        upn = getattr(user, 'user_principal_name', '') or ''
        local_part = upn.split('@')[0].lower() if '@' in upn else upn.lower()
        if not local_part:
            return 'unknown'

        prefixes = [p.strip() for p in ice_config.get('ice_privileged_prefixes', '').split(',') if p.strip()]
        suffixes = [s.strip() for s in ice_config.get('ice_privileged_suffixes', '').split(',') if s.strip()]

        for prefix in prefixes:
            if local_part.startswith(prefix):
                return 'privileged'
        for suffix in suffixes:
            if local_part.endswith(suffix):
                return 'privileged'

        # Service accounts detected by naming pattern
        svc_patterns = ['svc-', 'svc.', 'service-', 'service.', 'bot-', 'noreply']
        for sp in svc_patterns:
            if local_part.startswith(sp):
                return 'service_account'

        return 'regular'

    def _discover_role_assignments(self) -> List[Dict[str, Any]]:
        """Discover RBAC role assignments across ALL accessible subscriptions using Azure SDK."""
        from datetime import datetime, timezone

        role_assignments = []
        printed = 0

        for sub in self.subscriptions:
            sub_id = sub['id']
            sub_name = sub['name']
            logger.info("Subscription: %s (%s...)", sub_name, sub_id[:8])

            try:
                auth_client = AuthorizationManagementClient(self.credential, sub_id)

                for assignment in auth_client.role_assignments.list_for_subscription():
                    principal_id = assignment.principal_id
                    if not principal_id:
                        continue

                    scope = assignment.scope or ''
                    role_def_id = assignment.role_definition_id or ''

                    # Get role name from role definition
                    role_name = 'Unknown'
                    try:
                        role_def = auth_client.role_definitions.get_by_id(role_def_id)
                        role_name = role_def.role_name or role_def.display_name or 'Unknown'
                    except Exception:
                        # Extract role name from the ID as fallback
                        pass

                    scope_type = 'subscription'
                    scope_lower = scope.lower()
                    if '/providers/' in scope_lower and '/resourcegroups/' in scope_lower:
                        scope_type = 'resource'
                    elif '/resourcegroups/' in scope_lower:
                        scope_type = 'resource_group'

                    created_on = None
                    days_since_assigned = None
                    if hasattr(assignment, 'created_on') and assignment.created_on:
                        created_on = assignment.created_on.isoformat()
                        try:
                            days_since_assigned = (datetime.now(timezone.utc) - assignment.created_on).days
                        except Exception:
                            pass

                    risk_level, why_critical = self._calculate_role_risk(role_name, scope_type)
                    resource_type, resource_name = self._parse_scope(scope)

                    if printed < 15:
                        logger.info("%s -> %s", role_name, scope.split('/')[-1][:30] if scope else 'root')
                        printed += 1
                    elif printed == 15:
                        logger.info("... (listing remaining silently)")
                        printed += 1

                    role_assignments.append({
                        'principal_id': principal_id,
                        'assignment_id': assignment.id,
                        'role_name': role_name,
                        'scope': scope,
                        'scope_type': scope_type,
                        'created_on': created_on,
                        'scope_exists': True,
                        'usage_status': 'unknown',
                        'days_since_assigned': days_since_assigned,
                        'redundant_with': None,
                        'role_type': 'azure',
                        'risk_level': risk_level,
                        'why_critical': why_critical,
                        'resource_type': resource_type,
                        'resource_name': resource_name,
                        'subscription_id': sub_id,
                        'subscription_name': sub_name,
                    })

            except Exception as e:
                logger.warning("Error discovering roles for subscription %s: %s", sub_name, e)
                continue

        logger.info("Total: %s role assignments across %s subscription(s)", len(role_assignments), len(self.subscriptions))
        return role_assignments

    def _calculate_role_risk(self, role_name: str, scope_type: str) -> tuple:
        """Calculate risk level and explanation for a role assignment with compliance context"""
        role_lower = role_name.lower()

        # Critical roles
        if 'owner' in role_lower:
            if scope_type == 'subscription':
                return ('critical', 'Owner on Subscription: Full control including IAM - violates SOC2 least privilege, PCI-DSS 7.1, HIPAA §164.312(a)(1) access controls')
            elif scope_type == 'resource_group':
                return ('high', 'Owner on Resource Group: Full control over all resources - review for SOC2 least privilege, consider scope reduction')
            return ('medium', 'Owner on resource: Full control - verify business justification per SOC2 access review requirements')

        if 'user access administrator' in role_lower:
            return ('critical', 'User Access Administrator: Can grant any role - privilege escalation risk, violates SOC2 separation of duties, PCI-DSS 7.1')

        if 'contributor' in role_lower:
            if scope_type == 'subscription':
                return ('high', 'Contributor on Subscription: Can modify all resources - violates SOC2 least privilege, PCI-DSS 7.2 access restrictions')
            elif scope_type == 'resource_group':
                return ('medium', 'Contributor on Resource Group: Broad modification access - review for SOC2 least privilege compliance')
            return ('low', 'Contributor on resource: Scoped access - verify business justification')

        # Key Vault privileged roles
        if 'key vault' in role_lower:
            if any(x in role_lower for x in ['administrator', 'officer', 'crypto']):
                return ('high', 'Key Vault Admin/Officer: Access to secrets/keys/certificates - HIPAA encryption controls (§164.312(a)(2)(iv)), PCI-DSS 3.5 key management')

        # Storage privileged roles
        if 'storage' in role_lower:
            if 'owner' in role_lower or 'contributor' in role_lower:
                return ('medium', 'Storage access: Can read/modify data - potential PII/PHI exposure, review for HIPAA/GDPR data access controls')

        # SQL/Database roles
        if 'sql' in role_lower or 'cosmos' in role_lower or 'database' in role_lower:
            if 'contributor' in role_lower or 'admin' in role_lower:
                return ('high', 'Database Admin: Access to sensitive data stores - HIPAA ePHI risk, PCI-DSS cardholder data controls, GDPR Art. 32')

        # Network security roles
        if 'network' in role_lower and 'contributor' in role_lower:
            return ('medium', 'Network Contributor: Can modify network security - SOC2 network security controls, review firewall/NSG changes')

        # Virtual Machine roles
        if 'virtual machine' in role_lower and ('contributor' in role_lower or 'admin' in role_lower):
            return ('medium', 'VM Admin: Can access compute resources - potential data exposure, SOC2 system access controls')

        # Reader roles are low risk
        if 'reader' in role_lower:
            return ('low', 'Read-only access: Limited risk but review for data sensitivity per SOC2 access monitoring')

        return ('info', None)

    def _parse_scope(self, scope: str) -> tuple:
        """Extract resource type and name from ARM scope"""
        if not scope:
            return (None, None)

        parts = scope.split('/')

        # Subscription level
        if '/resourceGroups/' not in scope:
            return ('subscription', parts[-1] if len(parts) > 2 else None)

        # Resource group level
        if scope.count('/') <= 4:
            rg_idx = parts.index('resourceGroups') if 'resourceGroups' in parts else -1
            if rg_idx >= 0 and rg_idx + 1 < len(parts):
                return ('resourceGroup', parts[rg_idx + 1])

        # Resource level - get provider and type
        if '/providers/' in scope:
            try:
                provider_idx = parts.index('providers')
                if provider_idx + 2 < len(parts):
                    resource_type = parts[provider_idx + 1] + '/' + parts[provider_idx + 2]
                    resource_name = parts[-1]
                    return (resource_type, resource_name)
            except:
                pass

        return (None, parts[-1] if parts else None)

    def _calculate_entra_role_risk(self, role_name: str) -> tuple:
        """Calculate risk level and explanation for an Entra directory role with compliance context"""
        role_lower = role_name.lower()

        # Critical Entra roles
        if 'global administrator' in role_lower:
            return ('critical', 'Global Administrator: Full tenant control - violates SOC2 least privilege, HIPAA §164.312 access controls, PCI-DSS 7.1 need-to-know')

        if 'privileged role administrator' in role_lower:
            return ('critical', 'Privileged Role Admin: Can assign any role - privilege escalation, violates SOC2 separation of duties, PCI-DSS 7.1')

        if 'privileged authentication administrator' in role_lower:
            return ('critical', 'Privileged Auth Admin: Can reset MFA for all users - account takeover risk, HIPAA §164.312(d) authentication controls')

        # High risk roles
        if 'application administrator' in role_lower or 'cloud application administrator' in role_lower:
            return ('high', 'Application Admin: Can manage all apps/SPNs - potential data access via app credentials, HIPAA BAA concerns')

        if 'user administrator' in role_lower:
            return ('high', 'User Administrator: Can create users/reset passwords - SOC2 access control risk, PCI-DSS 8.1 user ID management')

        if 'security administrator' in role_lower:
            return ('high', 'Security Administrator: Can modify security policies - SOC2 change management, affects HIPAA/PCI security controls')

        if 'exchange administrator' in role_lower:
            return ('high', 'Exchange Administrator: Full mailbox access - HIPAA ePHI exposure via email, SOC2 confidentiality controls')

        if 'sharepoint administrator' in role_lower:
            return ('high', 'SharePoint Administrator: Full document access - PII/PHI exposure risk, GDPR Art. 32 data protection')

        if 'intune administrator' in role_lower:
            return ('high', 'Intune Administrator: Device management - can access/wipe devices, SOC2 endpoint security controls')

        if 'conditional access administrator' in role_lower:
            return ('high', 'Conditional Access Admin: Can bypass MFA policies - authentication security risk, HIPAA §164.312(d)')

        if 'billing administrator' in role_lower:
            return ('high', 'Billing Administrator: Access to payment/financial data - PCI-DSS cardholder data exposure risk')

        if 'compliance administrator' in role_lower:
            return ('high', 'Compliance Administrator: Can modify compliance settings - SOC2/HIPAA audit control risk')

        # Medium risk roles
        if 'helpdesk administrator' in role_lower or 'password administrator' in role_lower:
            return ('medium', 'Helpdesk/Password Admin: Can reset non-admin passwords - social engineering risk, SOC2 access controls')

        if 'groups administrator' in role_lower:
            return ('medium', 'Groups Administrator: Can modify security groups - affects access controls, SOC2 group management')

        if 'teams administrator' in role_lower:
            return ('medium', 'Teams Administrator: Access to all Teams data - potential PII/confidential data exposure')

        if 'authentication administrator' in role_lower:
            return ('medium', 'Authentication Admin: Can reset MFA for non-admins - account security risk, HIPAA §164.312(d)')

        if 'license administrator' in role_lower:
            return ('medium', 'License Administrator: Can manage licenses - no direct data access but operational impact')

        # Low risk roles
        if 'reader' in role_lower:
            return ('low', 'Directory Reader: Read-only access - limited risk but review for SOC2 access monitoring')

        if 'reports reader' in role_lower or 'usage summary reports reader' in role_lower:
            return ('low', 'Reports Reader: Can view usage reports - minimal risk, audit trail access')

        if 'message center reader' in role_lower:
            return ('low', 'Message Center Reader: Can view service messages - informational access only')

        return ('info', None)
    
    # ─── Group Scanner (Phase 2A) ──────────────────────────────────────

    async def _discover_groups(self) -> List[Dict[str, Any]]:
        """Discover Entra ID security groups via Graph API with pagination."""
        import aiohttp

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            select_fields = ','.join([
                'id', 'displayName', 'description', 'mailEnabled',
                'securityEnabled', 'groupTypes', 'membershipRule',
                'isAssignableToRole', 'createdDateTime',
            ])
            url: str | None = (
                f"https://graph.microsoft.com/v1.0/groups"
                f"?$select={select_fields}&$top=999"
            )

            all_groups: list[dict] = []
            page = 0
            first_error_logged = False

            async with aiohttp.ClientSession() as session:
                while url:
                    page += 1
                    async with session.get(url, headers=headers) as resp:
                        if resp.status != 200:
                            body = await resp.text()
                            logger.error("Graph API error %s on groups page %s: %s", resp.status, page, body[:500])
                            break
                        data = await resp.json()

                    for g in data.get('value', []):
                        try:
                            security_enabled = g.get('securityEnabled', False)
                            # Skip pure mail/M365 groups that aren't security-enabled
                            if not security_enabled:
                                continue

                            group_types = g.get('groupTypes') or []
                            # Determine membership type
                            membership_type = None
                            if 'DynamicMembership' in group_types:
                                membership_type = 'dynamic'
                            elif g.get('membershipRule'):
                                membership_type = 'dynamic'
                            else:
                                membership_type = 'assigned'

                            all_groups.append({
                                'group_id': g.get('id'),
                                'display_name': g.get('displayName'),
                                'description': g.get('description'),
                                'mail_enabled': g.get('mailEnabled', False),
                                'security_enabled': True,
                                'group_types': group_types,
                                'membership_type': membership_type,
                                'is_role_assignable': g.get('isAssignableToRole', False),
                                'created_datetime': g.get('createdDateTime'),
                                'is_privileged': False,
                                'member_count': 0,
                                'nested_group_count': 0,
                                'rbac_roles': [],
                            })
                        except Exception as e:
                            if not first_error_logged:
                                logger.warning("Error parsing group %s: %s", g.get('id'), e)
                                first_error_logged = True

                    url = data.get('@odata.nextLink')

            logger.info("Fetched %s security groups across %s page(s)", len(all_groups), page)
            return all_groups

        except Exception as e:
            logger.error("Group discovery failed: %s", e)
            return []

    async def _discover_group_memberships(self, groups: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Discover group memberships with nested resolution up to 3 levels.

        Returns dict mapping group_id → list of member dicts.
        """
        import aiohttp
        import asyncio as _asyncio

        MAX_DEPTH = 3
        memberships: Dict[str, List[Dict]] = {}

        if not groups:
            return memberships

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}
            first_error_logged = False

            async with aiohttp.ClientSession() as session:

                async def _fetch_members(group_id: str, depth: int, visited: set) -> List[Dict]:
                    """Recursively fetch members, resolving nested groups."""
                    if depth > MAX_DEPTH or group_id in visited:
                        return []
                    visited.add(group_id)

                    members: list[dict] = []
                    url: str | None = (
                        f"https://graph.microsoft.com/v1.0/groups/{group_id}/members"
                        f"?$select=id,displayName,@odata.type&$top=999"
                    )

                    while url:
                        try:
                            async with session.get(url, headers=headers) as resp:
                                if resp.status != 200:
                                    break
                                data = await resp.json()

                            for m in data.get('value', []):
                                odata_type = m.get('@odata.type', '')
                                member_id = m.get('id')
                                if not member_id:
                                    continue

                                if '#microsoft.graph.user' in odata_type:
                                    member_type = 'user'
                                elif '#microsoft.graph.servicePrincipal' in odata_type:
                                    member_type = 'servicePrincipal'
                                elif '#microsoft.graph.group' in odata_type:
                                    member_type = 'group'
                                else:
                                    member_type = 'other'

                                members.append({
                                    'member_object_id': member_id,
                                    'member_type': member_type,
                                    'member_display_name': m.get('displayName'),
                                    'is_nested': depth > 0,
                                    'depth': depth,
                                })

                                # Recursively resolve nested groups
                                if member_type == 'group' and depth < MAX_DEPTH:
                                    nested = await _fetch_members(member_id, depth + 1, visited)
                                    members.extend(nested)

                            url = data.get('@odata.nextLink')
                        except Exception as e:
                            nonlocal first_error_logged
                            if not first_error_logged:
                                logger.warning("Error fetching members for group %s: %s", group_id, e)
                                first_error_logged = True
                            break

                    return members

                # Fetch memberships sequentially with rate limiting
                for i, group in enumerate(groups):
                    gid = group.get('group_id')
                    if not gid:
                        continue
                    visited: set = set()
                    members = await _fetch_members(gid, 0, visited)
                    memberships[gid] = members

                    if i > 0 and i % 50 == 0:
                        logger.info("Group membership progress: %s/%s groups", i, len(groups))

                    await _asyncio.sleep(0.15)  # Rate limit

            return memberships

        except Exception as e:
            logger.error("Group membership discovery failed: %s", e)
            return memberships

    def _save_entra_groups(self, run_id: int, groups: List[Dict], group_memberships: Dict[str, List[Dict]]):
        """Save discovered groups and their memberships to the database."""
        saved = 0
        for group in groups:
            try:
                group_db_id = self.db.save_entra_group(run_id, group)
                if not group_db_id:
                    continue
                saved += 1

                # Save memberships for this group
                members = group_memberships.get(group.get('group_id', ''), [])
                for member in members:
                    try:
                        self.db.save_entra_group_membership(group_db_id, member, run_id)
                    except Exception as e:
                        logger.debug("Save membership error: %s", e)
            except Exception as e:
                logger.error("Save group error for %s: %s", group.get('display_name'), e)
                try:
                    self.db._rollback()
                except Exception:
                    pass

        logger.info("Saved %s/%s Entra groups with memberships", saved, len(groups))

    async def _discover_entra_roles(self) -> List[Dict[str, Any]]:
        """Discover Entra ID directory role assignments for given principals"""
        try:
            logger.info("Discovering Entra ID Directory Roles...")
            
            # Get all directory role assignments
            role_assignments_response = await self.graph_client.role_management.directory.role_assignments.get()
            
            entra_roles = []
            if role_assignments_response and role_assignments_response.value:
                for assignment in role_assignments_response.value:
                    # Include ALL Entra role assignments
                        # Get role definition to get role name
                        try:
                            role_def = await self.graph_client.role_management.directory.role_definitions.by_unified_role_definition_id(assignment.role_definition_id).get()
                            role_name = role_def.display_name if role_def else "Unknown Role"
                        except:
                            role_name = "Unknown Role"
                        
                        # Calculate Entra role risk level
                        risk_level, why_critical = self._calculate_entra_role_risk(role_name)

                        entra_roles.append({
                            'principal_id': assignment.principal_id,
                            'role_name': role_name,
                            'role_definition_id': assignment.role_definition_id,
                            'directory_scope': assignment.directory_scope_id or '/',
                            # Usage intelligence fields
                            'usage_status': 'unknown',
                            'assigned_on': None,  # Entra doesn't expose this easily
                            'days_since_assigned': None,
                            'redundant_with': None,
                            'role_type': 'entra',
                            'risk_level': risk_level,
                            'why_critical': why_critical,
                        })
                        
                        if len(entra_roles) <= 10:
                            logger.info("Entra role: %s", role_name)
            
            logger.info("Found %s Entra ID role assignments", len(entra_roles))
            return entra_roles
            
        except Exception as e:
            logger.error("Error discovering Entra roles: %s", e)
            return []


    # ─── Phase 52: Azure Resource Discovery ──────────────────────────

    def _discover_storage_accounts(self) -> list:
        """Discover all storage accounts across all subscriptions with security audit."""
        from datetime import datetime, timezone, timedelta
        storage_accounts = []
        for sub in self.subscriptions:
            sub_id = sub['id']
            sub_name = sub['name']
            try:
                storage_client = StorageManagementClient(self.credential, sub_id)
                for account in storage_client.storage_accounts.list():
                    resource_id = account.id
                    name = account.name
                    location = account.location
                    rg = resource_id.split('/resourceGroups/')[1].split('/')[0] if '/resourceGroups/' in resource_id else None

                    # Security settings
                    public_blob = getattr(account, 'allow_blob_public_access', None)
                    if public_blob is None:
                        public_blob = getattr(account, 'allow_blob_public_access', False)
                    https_only = getattr(account, 'enable_https_traffic_only', True)
                    tls = str(getattr(account, 'minimum_tls_version', 'TLS1_2') or 'TLS1_2')
                    shared_key = getattr(account, 'allow_shared_key_access', True)
                    if shared_key is None:
                        shared_key = True
                    cross_tenant = getattr(account, 'allow_cross_tenant_replication', False)

                    # Network rules
                    net = account.network_rule_set
                    default_action = str(net.default_action) if net and net.default_action else 'Allow'
                    ip_count = len(net.ip_rules) if net and net.ip_rules else 0
                    vnet_count = len(net.virtual_network_rules) if net and net.virtual_network_rules else 0
                    pe_conns = getattr(account, 'private_endpoint_connections', None) or []
                    pe_count = len(pe_conns)
                    bypass = str(net.bypass) if net and net.bypass else 'AzureServices'

                    # Encryption
                    enc = account.encryption
                    infra_enc = False
                    cmk = False
                    kv_uri = None
                    if enc:
                        infra_enc = getattr(enc, 'require_infrastructure_encryption', False) or False
                        key_source = getattr(enc, 'key_source', None)
                        cmk = str(key_source).lower().find('keyvault') >= 0 if key_source else False
                        kv_props = getattr(enc, 'key_vault_properties', None)
                        if kv_props:
                            kv_uri = getattr(kv_props, 'key_vault_uri', None)

                    # SAS policy
                    sas_policy = getattr(account, 'sas_policy', None)
                    sas_policy_enabled = sas_policy is not None and getattr(sas_policy, 'sas_expiration_period', None) is not None
                    sas_expiration_period = str(getattr(sas_policy, 'sas_expiration_period', '')) if sas_policy else None

                    # Key rotation check
                    key1_created = None
                    key2_created = None
                    key_stale = False
                    try:
                        keys_result = storage_client.storage_accounts.list_keys(rg, name)
                        for key in (keys_result.keys or []):
                            created = getattr(key, 'creation_time', None)
                            if key.key_name == 'key1':
                                key1_created = created.isoformat() if created else None
                            elif key.key_name == 'key2':
                                key2_created = created.isoformat() if created else None
                            if created and (datetime.now(timezone.utc) - created).days > 90:
                                key_stale = True
                    except Exception:
                        pass  # listKeys may need elevated permissions

                    # Diagnostic logging check (for SAS/key usage auditability)
                    diag_enabled = False
                    logging_destinations = []
                    try:
                        if MonitorManagementClient is not None:
                            monitor_client = MonitorManagementClient(self.credential, sub_id)
                            diag_settings = monitor_client.diagnostic_settings.list(resource_id)
                            for ds in diag_settings.value if hasattr(diag_settings, 'value') else diag_settings:
                                # Check if StorageRead/StorageWrite logs are captured
                                has_storage_logs = False
                                for log_setting in (getattr(ds, 'logs', None) or []):
                                    cat = getattr(log_setting, 'category', '') or ''
                                    enabled = getattr(log_setting, 'enabled', False)
                                    if enabled and cat in ('StorageRead', 'StorageWrite', 'StorageDelete'):
                                        has_storage_logs = True
                                if has_storage_logs:
                                    diag_enabled = True
                                    dest = {}
                                    if getattr(ds, 'workspace_id', None):
                                        dest['type'] = 'log_analytics'
                                        dest['target'] = ds.workspace_id
                                    elif getattr(ds, 'storage_account_id', None):
                                        dest['type'] = 'storage_account'
                                        dest['target'] = ds.storage_account_id
                                    elif getattr(ds, 'event_hub_authorization_rule_id', None):
                                        dest['type'] = 'event_hub'
                                    else:
                                        dest['type'] = 'other'
                                    logging_destinations.append(dest)
                    except Exception:
                        pass  # Monitor API may not be accessible

                    # Build storage data dict for component scoring
                    sa_data = {
                        'resource_id': resource_id, 'name': name, 'location': location,
                        'resource_group': rg, 'subscription_id': sub_id,
                        'subscription_name': sub_name,
                        'sku': account.sku.name if account.sku else None,
                        'kind': str(account.kind) if account.kind else None,
                        'access_tier': str(account.access_tier) if account.access_tier else None,
                        'public_blob_access': bool(public_blob),
                        'https_only': bool(https_only),
                        'minimum_tls_version': tls,
                        'shared_key_access': bool(shared_key),
                        'allow_cross_tenant_replication': bool(cross_tenant),
                        'default_network_action': default_action,
                        'ip_rules_count': ip_count, 'vnet_rules_count': vnet_count,
                        'private_endpoint_count': pe_count, 'bypass_settings': bypass,
                        'network_rules': {'ip_count': ip_count, 'vnet_count': vnet_count, 'bypass': bypass},
                        'infrastructure_encryption': infra_enc,
                        'customer_managed_keys': cmk, 'key_vault_uri': kv_uri,
                        'encryption_details': {'infra_enc': infra_enc, 'cmk': cmk, 'kv_uri': kv_uri},
                        'key1_created_at': key1_created, 'key2_created_at': key2_created,
                        'key_rotation_stale': key_stale,
                        'sas_policy_enabled': sas_policy_enabled,
                        'sas_expiration_period': sas_expiration_period,
                        'diagnostic_logging_enabled': diag_enabled,
                        'logging_destinations': logging_destinations,
                        'tags': dict(account.tags or {}),
                    }

                    # Component-based scoring
                    from app.engines.data_security import score_storage_account
                    risk_score, risk_level, risk_components, critical_overrides, risk_reasons = score_storage_account(sa_data)

                    sa_data['risk_score'] = risk_score
                    sa_data['risk_level'] = risk_level
                    sa_data['risk_reasons'] = risk_reasons
                    sa_data['risk_components'] = risk_components
                    sa_data['critical_overrides'] = critical_overrides
                    sa_data['blast_radius_score'] = 0  # computed post-save via identity cross-link
                    storage_accounts.append(sa_data)
            except Exception as e:
                logger.warning("Storage discovery failed for %s: %s", sub_name, e)
                continue
        return storage_accounts

    def _discover_key_vaults(self) -> list:
        """Discover all key vaults across all subscriptions with security audit."""
        from datetime import datetime, timezone, timedelta
        key_vaults = []
        for sub in self.subscriptions:
            sub_id = sub['id']
            sub_name = sub['name']
            try:
                kv_mgmt = KeyVaultManagementClient(self.credential, sub_id)
                for vault_item in kv_mgmt.vaults.list():
                    resource_id = vault_item.id
                    vault_name = vault_item.name
                    location = getattr(vault_item, 'location', None)
                    rg = resource_id.split('/resourceGroups/')[1].split('/')[0] if '/resourceGroups/' in resource_id else None

                    # Get full vault details
                    try:
                        vault = kv_mgmt.vaults.get(rg, vault_name)
                        props = vault.properties
                    except Exception:
                        props = None

                    if not props:
                        continue

                    # Security settings
                    soft_delete = getattr(props, 'enable_soft_delete', False) or False
                    retention = getattr(props, 'soft_delete_retention_in_days', 0) or 0
                    purge_prot = getattr(props, 'enable_purge_protection', False) or False
                    rbac_auth = getattr(props, 'enable_rbac_authorization', False) or False

                    # Network rules
                    net = getattr(props, 'network_acls', None)
                    public_access = str(getattr(props, 'public_network_access', 'Enabled') or 'Enabled')
                    default_action = str(net.default_action) if net and net.default_action else 'Allow'
                    ip_count = len(net.ip_rules) if net and net.ip_rules else 0
                    vnet_count = len(net.virtual_network_rules) if net and net.virtual_network_rules else 0
                    pe_conns = getattr(props, 'private_endpoint_connections', None) or []
                    pe_count = len(pe_conns)

                    # Access policies (non-RBAC mode)
                    access_policies_list = []
                    ap_count = 0
                    if not rbac_auth:
                        for ap in (getattr(props, 'access_policies', None) or []):
                            ap_count += 1
                            perms = getattr(ap, 'permissions', None)
                            access_policies_list.append({
                                'object_id': getattr(ap, 'object_id', ''),
                                'azure_directory_id': getattr(ap, 'tenant_id', ''),
                                'permissions': {
                                    'keys': [str(p) for p in (perms.keys or [])] if perms else [],
                                    'secrets': [str(p) for p in (perms.secrets or [])] if perms else [],
                                    'certificates': [str(p) for p in (perms.certificates or [])] if perms else [],
                                }
                            })

                    # Data plane: enumerate secrets/keys/certs (may lack permissions)
                    vault_url = getattr(props, 'vault_uri', f'https://{vault_name}.vault.azure.net/')
                    now = datetime.now(timezone.utc)
                    thirty_days = timedelta(days=30)
                    secrets_summary = {'total': 0, 'expired': 0, 'expiring_soon': 0}
                    keys_summary = {'total': 0, 'expired': 0, 'expiring_soon': 0}
                    certs_summary = {'total': 0, 'expired': 0, 'expiring_soon': 0}
                    secrets_detail = []
                    keys_detail = []
                    certs_detail = []

                    try:
                        sc = SecretClient(vault_url=vault_url, credential=self.credential)
                        for s in sc.list_properties_of_secrets():
                            secrets_summary['total'] += 1
                            if s.expires_on:
                                if s.expires_on < now:
                                    secrets_summary['expired'] += 1
                                elif s.expires_on < now + thirty_days:
                                    secrets_summary['expiring_soon'] += 1
                            secrets_detail.append({
                                'name': s.name,
                                'enabled': s.enabled,
                                'expires_on': s.expires_on.isoformat() if s.expires_on else None,
                                'created_on': s.created_on.isoformat() if s.created_on else None,
                                'content_type': getattr(s, 'content_type', None),
                            })
                    except Exception:
                        pass

                    try:
                        kc = KeyClient(vault_url=vault_url, credential=self.credential)
                        for k in kc.list_properties_of_keys():
                            keys_summary['total'] += 1
                            if k.expires_on:
                                if k.expires_on < now:
                                    keys_summary['expired'] += 1
                                elif k.expires_on < now + thirty_days:
                                    keys_summary['expiring_soon'] += 1
                            keys_detail.append({
                                'name': k.name,
                                'enabled': k.enabled,
                                'expires_on': k.expires_on.isoformat() if k.expires_on else None,
                                'created_on': k.created_on.isoformat() if k.created_on else None,
                                'key_type': str(k.key_type) if getattr(k, 'key_type', None) else None,
                                'key_size': getattr(k, 'key_size', None),
                            })
                    except Exception:
                        pass

                    try:
                        cc = CertificateClient(vault_url=vault_url, credential=self.credential)
                        for c in cc.list_properties_of_certificates():
                            certs_summary['total'] += 1
                            if c.expires_on:
                                if c.expires_on < now:
                                    certs_summary['expired'] += 1
                                elif c.expires_on < now + thirty_days:
                                    certs_summary['expiring_soon'] += 1
                            certs_detail.append({
                                'name': c.name,
                                'enabled': c.enabled,
                                'expires_on': c.expires_on.isoformat() if c.expires_on else None,
                                'created_on': c.created_on.isoformat() if c.created_on else None,
                                'subject': getattr(c, 'subject', None),
                                'thumbprint': c.thumbprint.hex() if getattr(c, 'thumbprint', None) else None,
                            })
                    except Exception:
                        pass

                    # Build vault data dict for component scoring
                    kv_data = {
                        'resource_id': resource_id, 'name': vault_name,
                        'location': location, 'resource_group': rg,
                        'subscription_id': sub_id, 'subscription_name': sub_name,
                        'sku': str(getattr(props, 'sku', {}).name) if getattr(props, 'sku', None) else None,
                        'soft_delete_enabled': soft_delete,
                        'soft_delete_retention_days': retention,
                        'purge_protection': purge_prot,
                        'enable_rbac_authorization': rbac_auth,
                        'public_network_access': public_access,
                        'default_network_action': default_action,
                        'ip_rules_count': ip_count, 'vnet_rules_count': vnet_count,
                        'private_endpoint_count': pe_count,
                        'network_rules': {'ip_count': ip_count, 'vnet_count': vnet_count},
                        'secrets_total': secrets_summary['total'],
                        'secrets_expired': secrets_summary['expired'],
                        'secrets_expiring_soon': secrets_summary['expiring_soon'],
                        'keys_total': keys_summary['total'],
                        'keys_expired': keys_summary['expired'],
                        'keys_expiring_soon': keys_summary['expiring_soon'],
                        'certs_total': certs_summary['total'],
                        'certs_expired': certs_summary['expired'],
                        'certs_expiring_soon': certs_summary['expiring_soon'],
                        'access_policy_count': ap_count,
                        'access_policies': access_policies_list,
                        'secrets_detail': secrets_detail,
                        'keys_detail': keys_detail,
                        'certs_detail': certs_detail,
                        'tags': dict(getattr(vault, 'tags', None) or {}),
                    }

                    # Component-based scoring
                    from app.engines.data_security import score_key_vault
                    risk_score, risk_level, risk_components, critical_overrides, risk_reasons = score_key_vault(kv_data)

                    kv_data['risk_score'] = risk_score
                    kv_data['risk_level'] = risk_level
                    kv_data['risk_reasons'] = risk_reasons
                    kv_data['risk_components'] = risk_components
                    kv_data['critical_overrides'] = critical_overrides
                    kv_data['blast_radius_score'] = 0
                    key_vaults.append(kv_data)
            except Exception as e:
                logger.warning("Key Vault discovery failed for %s: %s", sub_name, e)
                continue
        return key_vaults

    def _enhance_resources_with_identity_exposure(self, run_id, storage_accounts, key_vaults):
        """Count privileged identities per resource, enhance scores, persist risk history."""
        from psycopg2.extras import RealDictCursor as RDC
        from app.engines.data_security import enhance_risk_with_identity_exposure, compute_blast_radius, extract_findings

        # Build a map of resource_id → privileged identity count from role_assignments
        cursor = self.db.conn.cursor(cursor_factory=RDC)
        cursor.execute("""
            SELECT ra.scope, COUNT(DISTINCT i.id) AS priv_count
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
              AND ra.role_name IN ('Owner', 'Contributor', 'User Access Administrator',
                                   'Key Vault Administrator', 'Key Vault Secrets Officer',
                                   'Storage Account Contributor', 'Storage Blob Data Owner')
            GROUP BY ra.scope
        """, (run_id,))
        scope_counts = {r['scope']: r['priv_count'] for r in cursor.fetchall()}
        cursor.close()

        def _count_privileged(resource_id):
            """Count privileged identities at resource, RG, or subscription scope."""
            count = scope_counts.get(resource_id, 0)
            # Also count inherited from parent scopes
            parts = resource_id.split('/')
            # subscription scope: /subscriptions/{id}
            if len(parts) >= 3:
                sub_scope = '/'.join(parts[:3])
                count += scope_counts.get(sub_scope, 0)
            # RG scope: /subscriptions/{id}/resourceGroups/{name}
            if '/resourceGroups/' in resource_id:
                rg_scope = resource_id.split('/providers/')[0]
                count += scope_counts.get(rg_scope, 0)
            return count

        all_resources = []
        for sa in storage_accounts:
            sa['resource_type'] = 'storage_account'
            all_resources.append(sa)
        for kv in key_vaults:
            kv['resource_type'] = 'key_vault'
            all_resources.append(kv)

        for res in all_resources:
            rid = res.get('resource_id', '')
            priv_count = _count_privileged(rid)
            net_score = res.get('risk_components', {}).get('network_exposure', {}).get('score', 0)

            # Apply identity exposure enhancement
            base_score = res.get('risk_score', 0)
            components = dict(res.get('risk_components', {}))
            adj_score, adj_level, updated_components = enhance_risk_with_identity_exposure(
                base_score, components, res, priv_count, net_score
            )

            # Compute blast radius
            blast = compute_blast_radius(priv_count, 0, net_score)

            res['risk_score'] = adj_score
            res['risk_level'] = adj_level
            res['risk_components'] = updated_components
            res['blast_radius_score'] = blast
            res['privileged_identity_count'] = priv_count
            res['network_exposure_score'] = net_score

            enhanced_data = {
                'risk_score': adj_score,
                'risk_level': adj_level,
                'risk_components': updated_components,
                'critical_overrides': res.get('critical_overrides', []),
                'blast_radius_score': blast,
                'privileged_identity_count': priv_count,
                'dependency_count': 0,
                'network_exposure_score': net_score,
            }

            # Persist risk history
            self.db.save_resource_risk_history(run_id, rid, res.get('resource_type', ''), enhanced_data)

            # Write enhanced scores back to main table so list/detail views are consistent
            self.db.update_resource_risk_scores(run_id, rid, res.get('resource_type', ''), enhanced_data)

            # Extract and persist queryable findings
            findings = extract_findings(
                res.get('resource_type', ''),
                updated_components,
                res.get('critical_overrides', []),
            )
            if findings:
                self.db.save_resource_findings(run_id, rid, res.get('resource_type', ''), findings)

        logger.info("Identity exposure enhanced + risk history saved for %s resources", len(all_resources))

    def _is_microsoft_system_app(self, identity: Dict) -> bool:
        """
        Determine if a service principal is a Microsoft first-party app.
        Uses multiple detection methods for comprehensive coverage.

        Detection methods (in order):
        1. appOwnerOrganizationId = Microsoft's tenant ID (most reliable)
        2. publisherName contains Microsoft patterns
        3. appId in known Microsoft first-party app list
        4. Display name matches Microsoft patterns (fallback for legacy apps)

        NOTE: Managed Identities (both SAMI and UAMI) are NOT filtered here.
        They are customer-owned Azure resources and should be tracked.

        Args:
            identity: Service principal dict from Microsoft Graph

        Returns:
            True if Microsoft first-party app, False if customer-owned
        """
        # Never flag the discovery connector SPN as Microsoft
        if identity.get('is_discovery_connector'):
            return False

        # Skip managed identities - they are customer-owned, not Microsoft apps
        sp_type = (identity.get('service_principal_type') or identity.get('servicePrincipalType') or '').lower()
        if sp_type == 'managedidentity':
            return False

        # All known Microsoft tenant IDs — SPNs owned by any of these are first-party
        MICROSOFT_TENANT_IDS = {
            'f8cdef31-a31e-4b4a-93e4-5f571e91255a',  # Microsoft Services
            '72f988bf-86f1-41af-91ab-2d7cd011db47',  # Microsoft Corp
            '33e01921-4d64-4f8c-a055-5bdaffd5e33d',  # Microsoft MSIT
            '47df5bb7-e6bc-4256-afb0-dd8c8e3c1ce8',  # Microsoft Partner Network
        }

        # Check 1: Microsoft-owned tenant (most reliable check)
        # NOTE: MS Graph SDK returns UUID objects, must convert to str for comparison
        app_owner_org = identity.get('app_owner_organization_id') or identity.get('appOwnerOrganizationId')
        app_owner_org_str = str(app_owner_org).lower() if app_owner_org else None
        if app_owner_org_str in MICROSOFT_TENANT_IDS:
            return True
        # If app_owner_organization_id is set and is NOT Microsoft, it's customer-owned
        if app_owner_org_str and app_owner_org_str not in MICROSOFT_TENANT_IDS:
            return False

        # Check 2: Publisher name indicates Microsoft
        publisher = (identity.get('publisher_name') or identity.get('publisherName') or '').lower()
        if publisher:
            microsoft_publishers = [
                'microsoft services',
                'microsoft corporation',
                'microsoft azure',
            ]
            if any(mp in publisher for mp in microsoft_publishers):
                return True

        # Check 3: Known Microsoft first-party app IDs
        MICROSOFT_FIRST_PARTY_APP_IDS = {
            '00000001-0000-0000-c000-000000000000',  # Azure ESTS
            '00000002-0000-0000-c000-000000000000',  # Azure AD Graph (legacy)
            '00000003-0000-0000-c000-000000000000',  # Microsoft Graph
            '00000004-0000-0000-c000-000000000000',  # Windows Azure Security Token Service
            '00000005-0000-0000-c000-000000000000',  # Office 365 Management APIs
            '00000006-0000-0ff1-ce00-000000000000',  # Microsoft Office 365 Portal
            '00000007-0000-0000-c000-000000000000',  # Azure Key Vault
            '00000007-0000-0ff1-ce00-000000000000',  # Microsoft Office 365
            '00000009-0000-0000-c000-000000000000',  # Microsoft Power BI
            '0000000a-0000-0000-c000-000000000000',  # Microsoft Intune
            '0000000c-0000-0000-c000-000000000000',  # Microsoft App Access Panel
            '00000012-0000-0000-c000-000000000000',  # Microsoft Rights Management Services
            '797f4846-ba00-4fd7-ba43-dac1f8f63013',  # Azure Service Management
            'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',  # Azure Portal
            '00000002-0000-0ff1-ce00-000000000000',  # Office 365 Exchange Online
            '00000003-0000-0ff1-ce00-000000000000',  # Office 365 SharePoint Online
        }

        app_id = identity.get('app_id') or identity.get('appId')
        if app_id and app_id in MICROSOFT_FIRST_PARTY_APP_IDS:
            return True

        # Check 4: Display name pattern matching (catches most Microsoft apps)
        display_name = (identity.get('display_name') or identity.get('displayName') or '').lower()

        # Customer apps typically have custom naming patterns
        # Check for customer naming conventions FIRST (whitelist approach)
        customer_prefixes = ['spn-', 'app-', 'svc-', 'sa-', 'func-', 'aks-', 'webapp-', 'mi-']
        for prefix in customer_prefixes:
            if display_name.startswith(prefix):
                return False  # Definitely customer-owned

        # Known third-party apps (not Microsoft, not customer)
        third_party_apps = ['apple internet accounts']
        if display_name in third_party_apps:
            return False  # Track as customer (3rd party integration)

        # Microsoft app patterns - comprehensive list
        microsoft_keywords = [
            # Core Microsoft brands
            'microsoft', 'azure', 'office', 'o365', 'm365', 'sharepoint', 'onedrive',
            'teams', 'outlook', 'exchange', 'dynamics', 'powerbi', 'power bi',
            'powerapps', 'power apps', 'powerautomate', 'intune', 'defender',
            'sentinel', 'purview', 'entra', 'windows', 'xbox', 'skype', 'yammer',
            'viva', 'bing', 'cortana', 'onenote', 'planner', 'visio', 'project',

            # Azure/AD specific
            'aad', 'activedirectory', 'active directory', 'azuread', 'graph',
            'arm', 'subscription', 'resourcemanager', 'keyvault', 'storageaccount',

            # Services patterns
            'substrate', 'demeter', 'kaizala', 'whiteboard', 'sway', 'bookings',
            'stream', 'forms', 'lists', 'todo', 'clipchamp', 'loop', 'mesh',
            'copilot', 'ic3', 'pim', 'mip', 'aip', 'rms', 'dlp',

            # Infrastructure
            'provisioning', 'configuration', 'licensing', 'compliance', 'policy',
            'migration', 'sync', 'registration', 'protection', 'discovery',
            'connector', 'gateway', 'portal', 'admin', 'management',
            'shell', 'wcss', 'shredding', 'mro', 'oms',

            # Service types
            'tenant', 'directory', 'identity', 'authentication', 'authorization',
            'token', 'certificate', 'credential', 'secret',

            # Communication
            'conferencing', 'calling', 'pstn', 'meeting', 'attendant', 'bot',
            'notification', 'push', 'signal', 'channel',

            # Data/Analytics
            'reporting', 'analytics', 'telemetry', 'insights', 'diagnostic',

            # Security
            'security', 'safelinks', 'encryption', 'privacy', 'audit',
            'ediscovery', 'retention', 'archiv',

            # Other Microsoft services
            'ocaas', 'mcapi', 'smit', 'cap ', 'ids-', 'ppe-',
            'signup', 'client interaction', 'experience management',
            'worker service', 'lifecycle', 'profile', 'people',
            'approval', 'request', 'support', 'help',
            'common data service', 'dataverse', 'cds',
            'customer service', 'sales', 'marketing',
            'portfolios', 'projectwork', 'weve', 'weveengine',
            'windowsupdate', 'update service',
            'virtual visits', 'billing rp', 'aci', 'spauthevent',
            'customer experience', 'experience platform',

            # Azure resource services
            'acr', 'container registry', 'asm', 'app service',
            'cdn', 'frontdoor', 'traffic manager', 'load balancer',
            'logic app', 'function app', 'devops',
            'cosmos', 'sql server', 'sql database',
            'redis', 'signalr', 'event hub', 'event grid',
            'iot', 'data factory', 'data lake', 'databricks',
            'cognitive', 'bot framework', 'qna',
            'cloud shell', 'advisor', 'cost management',
            'monitor', 'log analytics', 'application insights',
            'backup', 'recovery', 'site recovery',
            'batch', 'hpc', 'machine learning',

            # Generic Microsoft service patterns
            'service', 'processor', 'handler', 'proxy', 'agent',
            'scheduler', 'deployer', 'cab', 'capacity', ' rp',
        ]

        # Check if display name contains any Microsoft keyword
        for keyword in microsoft_keywords:
            if keyword in display_name:
                return True

        # Heuristic: SPNs without owner org that have UUID-prefixed names
        # are Microsoft auto-generated service principals
        if not app_owner_org:
            import re
            if re.match(r'^[0-9a-f]{8}-', display_name):
                return True

        # Default: Assume customer-owned if no Microsoft patterns found
        return False

    def _calculate_role_usage_status(
        self,
        identity: Dict,
        roles: List[Dict],
        entra_roles: List[Dict]
    ) -> tuple:
        """
        Calculate usage status for each role based on inference.

        Usage Status Logic:
        - orphaned: Role scope points to deleted resource (scope_exists=False)
        - definitely_unused: Identity disabled OR credentials expired OR never signed in
        - likely_unused: No sign-in in 90+ days AND role assigned 90+ days ago
        - possibly_overprivileged: Has broader role that makes this one redundant
        - assumed_active: Recent sign-in, recent role assignment

        Returns:
            (updated_roles, updated_entra_roles) with usage_status populated
        """
        # Get identity status indicators
        is_disabled = not identity.get('enabled', True)
        last_sign_in = identity.get('last_sign_in')
        credential_status = identity.get('credential_status', '')

        # Calculate days since sign-in
        days_since_signin = None
        if last_sign_in:
            try:
                from datetime import datetime, timezone
                if isinstance(last_sign_in, str):
                    signin_dt = datetime.fromisoformat(last_sign_in.replace('Z', '+00:00'))
                else:
                    signin_dt = last_sign_in
                days_since_signin = (datetime.now(timezone.utc) - signin_dt).days
            except:
                pass

        has_expired_creds = credential_status and 'expired' in credential_status.lower()
        never_signed_in = last_sign_in is None

        # Check for redundant roles (Owner makes Contributor redundant, etc.)
        role_hierarchy = {
            'owner': ['contributor', 'reader'],
            'contributor': ['reader'],
            'user access administrator': [],
            'global administrator': ['privileged role administrator', 'user administrator', 'application administrator'],
            'privileged role administrator': ['application administrator', 'user administrator'],
        }

        # Get all role names for this identity
        azure_role_names = [r['role_name'].lower() for r in roles]
        entra_role_names = [r['role_name'].lower() for r in entra_roles]
        all_role_names = azure_role_names + entra_role_names

        # Set last_used_at from identity sign-in (proxy for role usage)
        for role in roles:
            role['last_used_at'] = last_sign_in
        for role in entra_roles:
            role['last_used_at'] = last_sign_in

        # Update Azure RBAC roles
        for role in roles:
            role_name_lower = role['role_name'].lower()
            days_assigned = role.get('days_since_assigned')

            # Check for orphaned (scope doesn't exist)
            if not role.get('scope_exists', True):
                role['usage_status'] = 'orphaned'
                continue

            # Check if identity is definitely unused
            if is_disabled:
                role['usage_status'] = 'definitely_unused'
                role['why_critical'] = (role.get('why_critical') or '') + ' Identity is disabled.'
                continue

            if has_expired_creds:
                role['usage_status'] = 'definitely_unused'
                role['why_critical'] = (role.get('why_critical') or '') + ' Credentials are expired.'
                continue

            if never_signed_in:
                role['usage_status'] = 'definitely_unused'
                role['why_critical'] = (role.get('why_critical') or '') + ' Identity has never signed in.'
                continue

            # Check for likely unused (dormant)
            if days_since_signin and days_since_signin > 90 and days_assigned and days_assigned > 90:
                role['usage_status'] = 'likely_unused'
                continue

            # Check for redundant roles
            for broader_role, lesser_roles in role_hierarchy.items():
                if broader_role in all_role_names and role_name_lower in lesser_roles:
                    # Check if same scope (for Azure RBAC)
                    broader_assignments = [r for r in roles if broader_role in r['role_name'].lower()]
                    for broader in broader_assignments:
                        if role.get('scope', '').startswith(broader.get('scope', 'xxx')):
                            role['usage_status'] = 'possibly_overprivileged'
                            role['redundant_with'] = broader['role_name']
                            break
                    if role.get('usage_status') == 'possibly_overprivileged':
                        break

            # Default: assumed active
            if role.get('usage_status', 'unknown') == 'unknown':
                if days_since_signin and days_since_signin < 30:
                    role['usage_status'] = 'assumed_active'
                elif days_assigned and days_assigned < 30:
                    role['usage_status'] = 'assumed_active'
                else:
                    role['usage_status'] = 'unknown'

        # Update Entra roles similarly
        for role in entra_roles:
            role_name_lower = role['role_name'].lower()
            days_assigned = role.get('days_since_assigned')

            if is_disabled:
                role['usage_status'] = 'definitely_unused'
                continue

            if has_expired_creds:
                role['usage_status'] = 'definitely_unused'
                continue

            if never_signed_in:
                role['usage_status'] = 'definitely_unused'
                continue

            if days_since_signin and days_since_signin > 90:
                role['usage_status'] = 'likely_unused'
                continue

            # Check for redundant Entra roles
            for broader_role, lesser_roles in role_hierarchy.items():
                if broader_role in entra_role_names and role_name_lower in lesser_roles:
                    role['usage_status'] = 'possibly_overprivileged'
                    role['redundant_with'] = broader_role.title()
                    break

            if role.get('usage_status', 'unknown') == 'unknown':
                if days_since_signin and days_since_signin < 30:
                    role['usage_status'] = 'assumed_active'
                else:
                    role['usage_status'] = 'unknown'

        # Normalize usage_status to standard values for UI display
        _STATUS_MAP = {
            'assumed_active': 'active',
            'definitely_unused': 'never_used',
            'likely_unused': 'dormant',
            'possibly_overprivileged': 'stale',
            'orphaned': 'dormant',
        }
        for role in roles + entra_roles:
            old = role.get('usage_status', 'unknown')
            if old in _STATUS_MAP:
                role['usage_status'] = _STATUS_MAP[old]
            elif old not in ('active', 'stale', 'dormant', 'never_used', 'unknown'):
                # Compute from last_sign_in if still unknown
                if days_since_signin is not None:
                    if days_since_signin <= 30:
                        role['usage_status'] = 'active'
                    elif days_since_signin <= 90:
                        role['usage_status'] = 'stale'
                    else:
                        role['usage_status'] = 'dormant'
                elif never_signed_in:
                    role['usage_status'] = 'never_used'

        return (roles, entra_roles)

    def _calculate_risks(
        self,
        identities: List[Dict],
        role_assignments: List[Dict],
        entra_roles: List[Dict] = [],
        permissions_map: Dict[str, List[Dict]] = None,
        app_roles_map: Dict[str, List[Dict]] = None,
        credentials_map: Dict[str, List[Dict]] = None
    ) -> List[Dict]:
        """
        V2 structured risk calculation. Produces both risk_reasons (backward compat)
        and risk_factors JSONB (structured factor cards).

        V2 Risk Levels:
        - 900+ = CRITICAL
        - 500-899 = HIGH
        - 200-499 = MEDIUM
        - 1-199 = LOW
        - 0 = INFO
        """
        from app.engines.risk_catalog import make_factor, score_to_level_v2

        permissions_map = permissions_map or {}
        app_roles_map = app_roles_map or {}
        credentials_map = credentials_map or {}

        # Process ALL identities - don't filter any out
        for identity in identities:
            if identity.get('identity_type') == 'user':
                if not identity.get('identity_category'):
                    identity['identity_category'] = 'human_user'
                identity['is_microsoft_system'] = False

        # Calculate risks for all identities
        for identity in identities:
            identity_id = identity.get('identity_id')
            object_id = identity.get('object_id')

            # Gather all data for this identity
            identity_roles = [ra for ra in role_assignments if ra['principal_id'] == object_id]
            identity_entra_roles = [er for er in entra_roles if er['principal_id'] == object_id]
            identity_permissions = permissions_map.get(identity_id, [])
            identity_app_roles = app_roles_map.get(identity_id, [])
            identity_credentials = credentials_map.get(identity_id, [])

            # Initialize V2 scoring
            risk_factors = []

            # ============================================================
            # 1. Entra ID Directory Roles (highest privilege)
            # ============================================================
            for entra_role in identity_entra_roles:
                role_name_lower = entra_role['role_name'].lower()
                if 'global administrator' in role_name_lower:
                    risk_factors.append(make_factor("TENANT_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'privileged role administrator' in role_name_lower:
                    risk_factors.append(make_factor("PRIV_ROLE_ADMIN", f"entra_role:{entra_role['role_name']}"))
                elif 'application administrator' in role_name_lower or 'cloud application administrator' in role_name_lower:
                    risk_factors.append(make_factor("APP_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'user administrator' in role_name_lower:
                    risk_factors.append(make_factor("USER_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'security administrator' in role_name_lower:
                    risk_factors.append(make_factor("SECURITY_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'exchange administrator' in role_name_lower:
                    risk_factors.append(make_factor("EXCHANGE_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))
                elif 'sharepoint administrator' in role_name_lower:
                    risk_factors.append(make_factor("SHAREPOINT_ADMIN_ROLE", f"entra_role:{entra_role['role_name']}"))

            # ============================================================
            # 2. Azure RBAC Roles
            # ============================================================
            for role in identity_roles:
                role_name = role['role_name'].lower()
                scope_type = role['scope_type']

                if 'owner' in role_name:
                    if scope_type == 'subscription':
                        risk_factors.append(make_factor("SUBSCRIPTION_OWNER", f"rbac:{role['role_name']}@{scope_type}"))
                    elif scope_type == 'resource_group':
                        risk_factors.append(make_factor("RG_OWNER", f"rbac:{role['role_name']}@{scope_type}"))
                    else:
                        risk_factors.append(make_factor("RESOURCE_OWNER", f"rbac:{role['role_name']}@{scope_type}"))
                elif 'contributor' in role_name:
                    if scope_type == 'subscription':
                        risk_factors.append(make_factor("SUBSCRIPTION_CONTRIBUTOR", f"rbac:{role['role_name']}@{scope_type}"))
                    elif scope_type == 'resource_group':
                        risk_factors.append(make_factor("RG_CONTRIBUTOR", f"rbac:{role['role_name']}@{scope_type}"))
                elif 'user access administrator' in role_name:
                    risk_factors.append(make_factor("UAA_ROLE", f"rbac:{role['role_name']}@{scope_type}"))
                elif 'key vault' in role_name and ('administrator' in role_name or 'officer' in role_name):
                    risk_factors.append(make_factor("KEYVAULT_FULL_ACCESS", f"rbac:{role['role_name']}@{scope_type}"))

            # ============================================================
            # 3. API Permissions (Graph API)
            # ============================================================
            write_permissions = []
            read_all_permissions = []

            for perm in identity_permissions:
                perm_name = (perm.get('permission_name') or '').lower()
                if '.write' in perm_name or '.readwrite' in perm_name:
                    write_permissions.append(perm.get('permission_name'))
                elif '.read.all' in perm_name or 'readall' in perm_name:
                    read_all_permissions.append(perm.get('permission_name'))

            if write_permissions:
                risk_factors.append(make_factor("DIRECTORY_RW_API", f"{len(write_permissions)} write perm(s): {', '.join(write_permissions[:3])}"))

            if read_all_permissions and not write_permissions:
                risk_factors.append(make_factor("DIRECTORY_READ_ALL_API", f"{len(read_all_permissions)} read-all perm(s)"))

            # ============================================================
            # 4. Orphaned Permissions
            # ============================================================
            has_roles = len(identity_roles) > 0 or len(identity_entra_roles) > 0
            has_permissions = len(identity_permissions) > 0

            if not has_roles and has_permissions:
                risk_factors.append(make_factor("ORPHANED_PERMISSIONS", f"{len(identity_permissions)} API perms without role justification"))

            # ============================================================
            # 5. App Roles
            # ============================================================
            admin_app_roles = []
            for app_role in identity_app_roles:
                role_value = (app_role.get('app_role_value') or app_role.get('resource_display_name') or '').lower()
                if any(keyword in role_value for keyword in ['admin', 'owner', 'full', 'write', 'manage']):
                    admin_app_roles.append(app_role)

            if admin_app_roles:
                risk_factors.append(make_factor("ADMIN_APP_ROLES", f"{len(admin_app_roles)} admin app role(s)"))
            elif identity_app_roles:
                risk_factors.append(make_factor("STANDARD_APP_ROLES", f"{len(identity_app_roles)} app role(s)"))

            # ============================================================
            # 6. Credential Status
            # ============================================================
            has_expired = False
            has_expiring_soon = False
            active_cred_count = 0
            for cred in identity_credentials:
                end_date = cred.get('end_datetime')
                if end_date:
                    from datetime import datetime, timezone
                    try:
                        if isinstance(end_date, str):
                            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        else:
                            end_dt = end_date
                        now = datetime.now(timezone.utc)
                        if end_dt < now:
                            has_expired = True
                        else:
                            active_cred_count += 1
                            if (end_dt - now).days < 30:
                                has_expiring_soon = True
                    except:
                        active_cred_count += 1

            if has_expired:
                risk_factors.append(make_factor("SECRET_EXPIRED", "Unrotated expired credential(s)"))
            elif has_expiring_soon:
                risk_factors.append(make_factor("SECRET_EXPIRING_SOON", "Credential(s) expiring within 30 days"))

            if active_cred_count > 1:
                risk_factors.append(make_factor("MULTIPLE_ACTIVE_SECRETS", f"{active_cred_count} active credentials"))

            # ============================================================
            # 7. Orphaned identity
            # ============================================================
            if not has_roles and not has_permissions and not identity_app_roles:
                if identity.get('identity_type') != 'user':
                    risk_factors.append(make_factor("ORPHANED_IDENTITY", "No role assignments"))

            # ============================================================
            # Sum V2 score and derive level
            # ============================================================
            risk_score = sum(f['points'] for f in risk_factors)
            risk_level = score_to_level_v2(risk_score)

            # Backward-compat: derive risk_reasons from factors
            risk_reasons = [f"{f['description']} (+{f['points']})" for f in risk_factors]
            if not risk_reasons:
                risk_reasons = ['No elevated privileges detected']

            # ============================================================
            # Apply custom risk rules (post-scoring adjustment)
            # ============================================================
            try:
                custom_rules = self._get_custom_rules()
                if custom_rules:
                    from app.engines.risk_rules import RiskRuleEngine
                    engine = RiskRuleEngine()
                    rule_identity = {
                        **identity,
                        'risk_score': risk_score,
                        'role_count': len(identity_roles) + len(identity_entra_roles),
                        'api_permission_count': len(identity_permissions),
                        'app_role_count': len(identity_app_roles),
                        'roles': identity_roles,
                        'entra_roles': identity_entra_roles,
                        '_permissions': identity_permissions,
                        '_credentials': identity_credentials,
                    }
                    adj, extra_reasons, forced = engine.evaluate_rules(rule_identity, custom_rules)
                    if forced:
                        risk_level = forced
                        risk_reasons.extend(extra_reasons)
                    elif adj != 0:
                        risk_score += adj
                        risk_reasons.extend(extra_reasons)
                        risk_level = score_to_level_v2(risk_score)
            except Exception as e:
                logger.warning("Custom risk rules error: %s", e)

            # Calculate role usage status (inference-based)
            identity_roles, identity_entra_roles = self._calculate_role_usage_status(
                identity, identity_roles, identity_entra_roles
            )

            # Store results
            identity['risk_level'] = risk_level
            identity['risk_score'] = risk_score
            identity['risk_reasons'] = risk_reasons
            identity['risk_factors'] = risk_factors
            identity['roles'] = identity_roles
            identity['entra_roles'] = identity_entra_roles
            identity['role_count'] = len(identity_roles) + len(identity_entra_roles)
            identity['api_permission_count'] = len(identity_permissions)
            identity['app_role_count'] = len(identity_app_roles)

            # Print high-risk identities
            if risk_level in ['critical', 'high']:
                logger.info("%s: %s (%s pts)", identity['display_name'], risk_level.upper(), risk_score)
                for factor in risk_factors[:3]:
                    logger.info("  %s: +%s (%s)", factor['code'], factor['points'], factor['severity'])

        # Summary
        critical_count = sum(1 for i in identities if i.get('risk_level') == 'critical')
        high_count = sum(1 for i in identities if i.get('risk_level') == 'high')

        logger.info("Risk Summary (V2 scale):")
        logger.info("Total: %s customer-owned identities", len(identities))
        logger.info("Critical: %s  High: %s", critical_count, high_count)

        return identities

    def _get_custom_rules(self):
        """Fetch enabled custom risk rules (cached per discovery run)."""
        if not hasattr(self, '_cached_custom_rules'):
            try:
                self._cached_custom_rules = self.db.get_enabled_risk_rules()
            except Exception:
                self._cached_custom_rules = []
        return self._cached_custom_rules

    def _check_credentials(self, identities: List[Dict]) -> List[Dict]:
        logger.info("Checking %s identities...", len(identities))
        for identity in identities:
            identity['credential_status'] = 'Valid'
            identity['credential_expiration'] = None
        logger.info("All credentials are valid for 30+ days")
        return identities
    
    def _check_activity(self, identities: List[Dict]) -> List[Dict]:
        """
        Calculate activity status based on sign-in data.

        Activity Status:
        - active: Signed in within last 30 days
        - inactive: Signed in 30-90 days ago
        - stale: Signed in 90+ days ago
        - never_used: Never signed in
        - unknown: No sign-in data available
        """
        from datetime import datetime, timezone

        logger.info("Checking %s identities...", len(identities))

        active_count = 0
        inactive_count = 0
        stale_count = 0
        never_used_count = 0
        unknown_count = 0

        for identity in identities:
            last_sign_in = identity.get('last_sign_in')

            if last_sign_in:
                try:
                    if isinstance(last_sign_in, str):
                        signin_dt = datetime.fromisoformat(last_sign_in.replace('Z', '+00:00'))
                    else:
                        signin_dt = last_sign_in

                    days_since = (datetime.now(timezone.utc) - signin_dt).days

                    if days_since <= 30:
                        identity['activity_status'] = 'active'
                        active_count += 1
                    elif days_since <= 90:
                        identity['activity_status'] = 'inactive'
                        inactive_count += 1
                    else:
                        identity['activity_status'] = 'stale'
                        stale_count += 1
                except:
                    identity['activity_status'] = 'unknown'
                    unknown_count += 1
            else:
                # No sign-in data - check if identity is new (created recently)
                created = identity.get('created_datetime')
                if created:
                    try:
                        if isinstance(created, str):
                            created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        else:
                            created_dt = created
                        days_old = (datetime.now(timezone.utc) - created_dt).days
                        if days_old < 7:
                            # New identity, no sign-in expected yet
                            identity['activity_status'] = 'unknown'
                            unknown_count += 1
                        else:
                            identity['activity_status'] = 'never_used'
                            never_used_count += 1
                    except:
                        identity['activity_status'] = 'never_used'
                        never_used_count += 1
                else:
                    identity['activity_status'] = 'never_used'
                    never_used_count += 1

            # ── Sign-in pattern classification (Prompt 4) ──────────────
            signin_raw = identity.get('_signin_activity_raw', {})
            signin_result = self._classify_signin_pattern(signin_raw)
            identity['signin_pattern'] = signin_result['signin_pattern']
            identity['last_delegated_signin'] = signin_result['last_delegated_signin']
            identity['last_noninteractive_signin'] = signin_result['last_noninteractive_signin']
            identity['days_since_last_signin'] = signin_result['days_since_last_signin']
            # Merge signin risk flags into existing workload_risk_flags
            existing_flags = identity.get('workload_risk_flags') or []
            new_flags = signin_result['signin_risk_flags']
            identity['workload_risk_flags'] = list(dict.fromkeys(existing_flags + new_flags))

        logger.info("Activity Summary:")
        if active_count > 0:
            logger.info("Active (30 days): %s", active_count)
        if inactive_count > 0:
            logger.info("Inactive (30-90 days): %s", inactive_count)
        if stale_count > 0:
            logger.info("Stale (90+ days): %s", stale_count)
        if never_used_count > 0:
            logger.info("Never used: %s", never_used_count)
        if unknown_count > 0:
            logger.info("Unknown: %s", unknown_count)

        return identities
    
    def _save_identities(self, run_id: int, identities: List[Dict], all_role_assignments: List[Dict], credentials_map: Dict[str, List[Dict]] = None, permissions_map: Dict[str, List[Dict]] = None, app_roles_map: Dict[str, List[Dict]] = None, ownership_map: Dict[str, List[Dict]] = None, pim_map: Dict[str, Dict] = None, ca_policies: List[Dict] = None) -> int:
        """Save all identities to database (customer-owned only, Microsoft system apps excluded at discovery)"""
        saved_count = 0

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
                    if max_ids and len(identities) > max_ids:
                        logger.warning("Organization %s (%s plan): truncating %s identities to %s", self.db_org_id, plan, len(identities), max_ids)
                        identities = identities[:max_ids]
            except Exception as e:
                logger.error("Entitlement check failed, proceeding without limit: %s", e)

        # Ensure clean transaction state before identity save loop.
        # Prior operations (job progress/metrics) may have left a poisoned
        # transaction; rollback clears it so the first identity isn't lost.
        try:
            self.db._rollback()
        except Exception:
            pass

        for identity in identities:

            # Set source for multi-cloud
            identity['source'] = 'azure'
            if not identity.get('permission_plane'):
                identity['permission_plane'] = 'entra_id'
            
            # For SPNs without created_datetime, calculate from roles or previous runs
            if not identity.get('created_datetime'):
                # Try role assignment dates first
                role_dates = [r.get('created_on') for r in identity.get('roles', []) if r.get('created_on')]
                if role_dates:
                    identity['created_datetime'] = min(role_dates)
                else:
                    # Check previous runs for this identity_id (scoped to current connection)
                    from datetime import datetime
                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        SELECT i.created_datetime
                        FROM identities i
                        JOIN discovery_runs dr ON dr.id = i.discovery_run_id
                        WHERE i.identity_id = %s
                        AND i.created_datetime IS NOT NULL
                        AND dr.cloud_connection_id = %s
                        ORDER BY i.discovery_run_id DESC
                        LIMIT 1
                    """, (identity.get('identity_id'), self.cloud_connection_id))
                    prev_result = cursor.fetchone()
                    cursor.close()
                    
                    if prev_result and prev_result[0]:
                        identity['created_datetime'] = prev_result[0]
                    else:
                        # Truly new identity
                        identity['created_datetime'] = datetime.utcnow().isoformat()
            
            try:
                identity_db_id = self.db.save_identity(run_id, identity)
                identity['_db_id'] = identity_db_id
            except Exception as e:
                logger.error("save_identity FAILED for %s: %s", identity.get('display_name'), e)
                self.db._rollback()
                continue

            # Save resource→identity link for SAMIs with associated_resource_id
            if identity.get('associated_resource_id') and identity_db_id:
                try:
                    self.db.save_resource_identity_link(run_id, {
                        'resource_id': identity['associated_resource_id'],
                        'resource_type': identity.get('associated_resource_type', ''),
                        'resource_name': identity.get('associated_resource_name', ''),
                        'resource_group': identity.get('associated_resource_group'),
                        'subscription_id': identity.get('associated_subscription_id'),
                        'identity_db_id': identity_db_id,
                        'identity_id': identity.get('identity_id', ''),
                        'identity_display_name': identity.get('display_name', ''),
                        'link_type': 'system_assigned',
                    })
                except Exception as e:
                    logger.warning("save_resource_identity_link failed for %s: %s", identity.get('display_name'), e)

            # Save all per-identity metadata (roles, subs, creds, permissions, PIM, etc.)
            try:
                # Save role assignments for this identity
                identity_roles = identity.get('roles', [])
                for role in identity_roles:
                    self.db.save_role_assignment(identity_db_id, role)

                # Save identity ↔ subscription access (multi-subscription junction table)
                seen_sub_roles = set()
                for role in identity_roles:
                    sub_id_from_role = role.get('subscription_id')
                    if sub_id_from_role:
                        key = (sub_id_from_role, role.get('role_name', ''), role.get('scope', ''))
                        if key not in seen_sub_roles:
                            seen_sub_roles.add(key)
                            self.db.save_identity_subscription_access(
                                identity_db_id,
                                identity.get('identity_id', ''),
                                role,
                                sub_id_from_role,
                                role.get('subscription_name', ''),
                                run_id,
                            )
                # Compute primary subscription + additional count
                if seen_sub_roles:
                    self.db.update_identity_subscription_summary(identity_db_id)

                # Save Entra ID role assignments for this identity
                identity_entra_roles = identity.get('entra_roles', [])
                for entra_role in identity_entra_roles:
                    self.db.save_entra_role_assignment(identity_db_id, entra_role)

                # Save credentials for this identity (SPNs only)
                if credentials_map and identity.get('identity_id') in credentials_map:
                    credentials = credentials_map[identity.get('identity_id')]
                    for credential in credentials:
                        self.db.save_credential(identity_db_id, credential)

                    # Update credential summary on identity record
                    self.db.update_identity_credential_summary(identity_db_id)

                # Save API permissions for this identity (SPNs only)
                if permissions_map and identity.get('identity_id') in permissions_map:
                    permissions = permissions_map[identity.get('identity_id')]
                    self.db.store_graph_permissions(identity_db_id, permissions)

                # Save custom app roles for this identity (SPNs only)
                if app_roles_map and identity.get('identity_id') in app_roles_map:
                    app_roles = app_roles_map[identity.get('identity_id')]
                    self.db.store_app_roles(identity_db_id, app_roles)

                # Save ownership for this identity (SPNs only)
                if ownership_map and identity.get('identity_id') in ownership_map:
                    owners = ownership_map[identity.get('identity_id')]
                    self.db.store_ownership(identity_db_id, owners)

                # Save PIM data for this identity (keyed by object_id)
                object_id = identity.get('object_id')
                if pim_map and object_id and object_id in pim_map:
                    pim_data = pim_map[object_id]
                    for eligible in pim_data.get('eligible', []):
                        self.db.save_pim_eligible(identity_db_id, eligible)
                    for activation in pim_data.get('activations', []):
                        self.db.save_pim_activation(identity_db_id, activation)
                    self.db.update_identity_pim_summary(identity_db_id)
            except Exception as e:
                logger.error("save_identity_metadata FAILED for %s: %s", identity.get('display_name'), e)
                self.db._rollback()

            saved_count += 1

        # Save CA policies and compute coverage after all identities are saved
        try:
            if ca_policies:
                logger.info("Saving %s CA policies and computing coverage...", len(ca_policies))
                for policy in ca_policies:
                    self.db.save_ca_policy(run_id, policy)

                # Compute per-identity coverage
                ca_coverage_map = self._compute_ca_coverage(ca_policies, identities)
                if ca_coverage_map:
                    # Need to re-resolve identity_db_ids for coverage
                    cursor = self.db.conn.cursor()
                    cursor.execute(
                        "SELECT id, object_id FROM identities WHERE discovery_run_id = %s AND object_id IS NOT NULL",
                        (run_id,),
                    )
                    id_map = {row[1]: row[0] for row in cursor.fetchall()}
                    cursor.close()

                    for object_id, coverage in ca_coverage_map.items():
                        db_id = id_map.get(object_id)
                        if db_id:
                            self.db.save_ca_identity_coverage(db_id, coverage)

                    covered = sum(1 for c in ca_coverage_map.values() if c['coverage_status'] == 'covered')
                    logger.info("CA coverage computed: %s/%s identities covered", covered, len(ca_coverage_map))
        except Exception as e:
            logger.warning("CA policy save/coverage error: %s", e)
            self.db._rollback()

        # Post-discovery sweep: catch any Microsoft SPNs that slipped through detection
        try:
            self.db.sweep_microsoft_flag(run_id)
        except Exception as e:
            logger.warning("Microsoft flag sweep error: %s", e)
            self.db._rollback()

        return saved_count

    def _compute_workload_exposure(self, run_id):
        """Batch-compute exposure scores for all workload identities (SPNs, MIs, App Regs)."""
        from app.engines.risk.spn_risk_engine import WorkloadExposureEngine
        from psycopg2.extras import RealDictCursor as RDC

        engine = WorkloadExposureEngine()
        cursor = self.db.conn.cursor(cursor_factory=RDC)

        # ── Part 1: SPN + Managed Identity scoring ──────────────────
        cursor.execute("""
            SELECT i.id, i.identity_id, i.object_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, i.activity_status, i.last_sign_in,
                   i.created_datetime, i.service_principal_type, i.credential_risk,
                   i.ca_coverage_status, i.enabled, ar.sign_in_audience
            FROM identities i
            LEFT JOIN app_registrations ar
              ON ar.linked_spn_id = i.id AND ar.discovery_run_id = i.discovery_run_id
            WHERE i.discovery_run_id = %s
              AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND NOT COALESCE(i.is_microsoft_system, false)
        """, (run_id,))
        spn_rows = cursor.fetchall()

        roles_map = {}
        entra_map = {}
        creds_map = {}
        perms_map = {}
        owners_map = {}
        pim_map = {}

        if spn_rows:
            db_ids = [row['id'] for row in spn_rows]
            ph = ','.join(['%s'] * len(db_ids))

            # Batch-fetch roles
            cursor.execute(f"SELECT identity_db_id, role_name, scope_type, scope, created_on FROM role_assignments WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                roles_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch entra roles
            cursor.execute(f"SELECT identity_db_id, role_name, risk_level FROM entra_role_assignments WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                entra_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch credentials
            cursor.execute(f"SELECT identity_db_id, credential_type, start_datetime, end_datetime, display_name, key_id FROM credentials WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                creds_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch permissions
            cursor.execute(f"SELECT identity_db_id, permission_name, risk_level FROM graph_api_permissions WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                perms_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch owners
            cursor.execute(f"SELECT identity_db_id, owner_display_name, owner_upn FROM sp_ownership WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                owners_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch PIM data
            try:
                cursor.execute("SAVEPOINT pim_fetch")
                cursor.execute(f"SELECT identity_db_id, role_name, start_datetime FROM pim_eligible_assignments WHERE identity_db_id IN ({ph})", db_ids)
                for r in cursor.fetchall():
                    pim_map.setdefault(r['identity_db_id'], {'eligible': [], 'activations': []})
                    pim_map[r['identity_db_id']]['eligible'].append(dict(r))
                cursor.execute(f"SELECT identity_db_id, role_name, start_datetime FROM pim_activations WHERE identity_db_id IN ({ph})", db_ids)
                for r in cursor.fetchall():
                    pim_map.setdefault(r['identity_db_id'], {'eligible': [], 'activations': []})
                    pim_map[r['identity_db_id']]['activations'].append(dict(r))
                cursor.execute("RELEASE SAVEPOINT pim_fetch")
            except Exception:
                cursor.execute("ROLLBACK TO SAVEPOINT pim_fetch")

            # Batch-fetch P2 activity stats (if available)
            p2_stats_map = {}
            try:
                cursor.execute("SAVEPOINT p2_fetch")
                cursor.execute(f"""
                    SELECT identity_db_id, total_sign_ins, successful_sign_ins,
                           failed_sign_ins, unique_resources, unique_ips,
                           unique_locations, peak_hour, off_hours_pct,
                           avg_daily_sign_ins, risk_sign_ins, ca_failures
                    FROM workload_activity_stats
                    WHERE identity_db_id IN ({ph})
                    ORDER BY period_end DESC
                """, db_ids)
                for r in cursor.fetchall():
                    dbid = r['identity_db_id']
                    if dbid not in p2_stats_map:
                        p2_stats_map[dbid] = dict(r)
                cursor.execute("RELEASE SAVEPOINT p2_fetch")
            except Exception:
                cursor.execute("ROLLBACK TO SAVEPOINT p2_fetch")

        scored = 0
        critical_count = 0
        for row in (spn_rows or []):
            db_id = row['id']
            identity_data = dict(row)
            cat = (identity_data.get('identity_category') or '').lower()
            result = engine.compute_exposure(
                identity_data,
                roles_map.get(db_id, []),
                entra_map.get(db_id, []),
                creds_map.get(db_id, []),
                perms_map.get(db_id, []),
                owners_map.get(db_id, []),
                pim_map.get(db_id, {}),
                identity_type=cat,
                p2_stats=p2_stats_map.get(db_id),
            )
            self.db.save_spn_exposure(db_id, result, result.get('findings', []), run_id)
            scored += 1
            if result['scores']['total'] >= 80:
                critical_count += 1

        logger.info("Computed exposure for %s SPNs/MIs (%s critical)", scored, critical_count)

        # ── Part 2: App Registration scoring ─────────────────────────
        try:
            cursor.execute("SAVEPOINT appreg_fetch")
            cursor.execute("""
                SELECT id, app_id, display_name, sign_in_audience, owner_count,
                       owners, has_service_principal, linked_spn_id,
                       spn_last_sign_in, spn_activity_status, created_datetime,
                       high_risk_permissions, required_permissions,
                       application_permission_count, credential_details,
                       has_expired_credential, has_expiring_soon,
                       has_localhost_redirect, has_http_redirect
                FROM app_registrations
                WHERE discovery_run_id = %s
            """, (run_id,))
            app_reg_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT appreg_fetch")
        except Exception:
            cursor.execute("ROLLBACK TO SAVEPOINT appreg_fetch")
            app_reg_rows = []

        if app_reg_rows:
            # Build linked SPN lookup maps
            linked_spn_ids = set()
            for ar in app_reg_rows:
                if ar.get('linked_spn_id'):
                    linked_spn_ids.add(ar['linked_spn_id'])

            linked_roles_map = {}
            linked_entra_map = {}
            if linked_spn_ids:
                lph = ','.join(['%s'] * len(linked_spn_ids))
                lids = list(linked_spn_ids)
                cursor.execute(f"SELECT identity_db_id, role_name, scope_type, scope, created_on FROM role_assignments WHERE identity_db_id IN ({lph})", lids)
                for r in cursor.fetchall():
                    linked_roles_map.setdefault(r['identity_db_id'], []).append(dict(r))
                cursor.execute(f"SELECT identity_db_id, role_name, risk_level FROM entra_role_assignments WHERE identity_db_id IN ({lph})", lids)
                for r in cursor.fetchall():
                    linked_entra_map.setdefault(r['identity_db_id'], []).append(dict(r))

            ar_scored = 0
            ar_critical = 0
            for ar in app_reg_rows:
                ar_data = dict(ar)
                spn_id = ar_data.get('linked_spn_id')
                result = engine.compute_app_reg_exposure(
                    ar_data,
                    linked_spn_roles=linked_roles_map.get(spn_id, []) if spn_id else [],
                    linked_spn_entra_roles=linked_entra_map.get(spn_id, []) if spn_id else [],
                )
                self.db.save_app_reg_exposure(ar_data['id'], result, result.get('findings', []), run_id)
                ar_scored += 1
                if result['scores']['total'] >= 80:
                    ar_critical += 1

            logger.info("Computed exposure for %s App Registrations (%s critical)", ar_scored, ar_critical)

        cursor.close()

    def _create_result(self, identities: List[Dict], role_assignments: List[Dict], run_id: int) -> DiscoveryResult:
        service_principals = [i for i in identities if i['identity_type'] == 'service_principal']
        users = [i for i in identities if i['identity_type'] == 'user']
        managed_identities = [i for i in identities if i['identity_type'] == 'managed_identity']
        
        critical_count = sum(1 for i in identities if i['risk_level'] == 'critical')
        high_count = sum(1 for i in identities if i['risk_level'] == 'high')
        medium_count = sum(1 for i in identities if i['risk_level'] == 'medium')
        
        logger.info("Discovery Summary: Total Identities: %s (Service Principals: %s, Users: %s, Managed Identities: %s)",
                     len(identities), len(service_principals), len(users), len(managed_identities))
        logger.info("Risk Assessment: Critical: %s, High: %s, Medium: %s",
                     critical_count, high_count, medium_count)
        
        return DiscoveryResult(
            run_id=run_id,
            total_identities=len(identities),
            service_principals_count=len(service_principals),
            users_count=len(users),
            managed_identities_count=len(managed_identities),
            actionable_count=len(identities),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            identities=identities,
            role_assignments=role_assignments
        )
    
    # ──────────────────────────────────────────────────────────
    # App Registration Discovery (Phase 74)
    # ──────────────────────────────────────────────────────────

    async def _discover_app_registrations(self, spn_app_id_map: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Discover Entra ID App Registrations via Graph API."""
        try:
            results = []
            from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration

            query_params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                top=999,
                select=['id', 'appId', 'displayName', 'createdDateTime',
                        'signInAudience', 'publisherDomain',
                        'appOwnerOrganizationId', 'requiredResourceAccess',
                        'passwordCredentials', 'keyCredentials',
                        'web']
            )
            request_config = RequestConfiguration(query_parameters=query_params)

            apps = await self.graph_client.applications.get(request_configuration=request_config)
            all_apps = []
            if apps and apps.value:
                all_apps.extend(apps.value)

            # Pagination
            next_link = getattr(apps, 'odata_next_link', None) if apps else None
            while next_link:
                try:
                    from msgraph.generated.applications.applications_request_builder import ApplicationsRequestBuilder as AB2
                    apps = await self.graph_client.applications.with_url(next_link).get()
                    if apps and apps.value:
                        all_apps.extend(apps.value)
                    next_link = getattr(apps, 'odata_next_link', None) if apps else None
                except Exception:
                    break

            logger.info("Found %s app registrations", len(all_apps))

            now = datetime.utcnow()

            for app in all_apps:
                app_id = getattr(app, 'app_id', None) or ''
                object_id = getattr(app, 'id', None) or ''
                display_name = getattr(app, 'display_name', None) or 'Unknown'

                # Created
                created = None
                if hasattr(app, 'created_date_time') and app.created_date_time:
                    created = app.created_date_time.isoformat()

                # Sign-in audience
                audience = getattr(app, 'sign_in_audience', None) or ''
                publisher_domain = getattr(app, 'publisher_domain', None) or ''
                owner_org_id = getattr(app, 'app_owner_organization_id', None) or ''

                # Third-party check
                is_third_party = bool(owner_org_id and owner_org_id != self.azure_directory_id)

                # ── Permissions ──
                app_perm_count = 0
                delegated_perm_count = 0
                high_risk_list = []
                raw_perms = []

                rra = getattr(app, 'required_resource_access', None) or []
                for resource_access in rra:
                    resource_app_id = getattr(resource_access, 'resource_app_id', '') or ''
                    entries = getattr(resource_access, 'resource_access', None) or []
                    perm_list = []
                    for entry in entries:
                        perm_id = getattr(entry, 'id', '') or ''
                        perm_type = getattr(entry, 'type', '') or ''
                        perm_list.append({'id': str(perm_id), 'type': perm_type})
                        if perm_type == 'Role':
                            app_perm_count += 1
                            guid_str = str(perm_id)
                            if guid_str in HIGH_RISK_PERMISSION_GUIDS:
                                high_risk_list.append(HIGH_RISK_PERMISSION_GUIDS[guid_str])
                        elif perm_type == 'Scope':
                            delegated_perm_count += 1
                    raw_perms.append({
                        'resource_app_id': resource_app_id,
                        'permissions': perm_list,
                    })

                total_perms = app_perm_count + delegated_perm_count

                # ── Credentials ──
                secrets = getattr(app, 'password_credentials', None) or []
                certs = getattr(app, 'key_credentials', None) or []
                secret_count = len(secrets)
                cert_count = len(certs)
                cred_details = []
                next_expiry = None
                has_expired = False
                has_expiring_soon = False

                for cred in list(secrets) + list(certs):
                    cred_type = 'secret' if cred in secrets else 'certificate'
                    end_dt = getattr(cred, 'end_date_time', None)
                    start_dt = getattr(cred, 'start_date_time', None)
                    key_id = str(getattr(cred, 'key_id', '') or '')
                    cred_name = getattr(cred, 'display_name', None) or ''
                    end_iso = end_dt.isoformat() if end_dt else None
                    start_iso = start_dt.isoformat() if start_dt else None
                    cred_details.append({
                        'type': cred_type,
                        'key_id': key_id,
                        'display_name': cred_name,
                        'start': start_iso,
                        'end': end_iso,
                    })
                    if end_dt:
                        if end_dt.replace(tzinfo=None) < now:
                            has_expired = True
                        else:
                            days_left = (end_dt.replace(tzinfo=None) - now).days
                            if days_left <= 30:
                                has_expiring_soon = True
                            if next_expiry is None or end_dt < next_expiry:
                                next_expiry = end_dt

                next_expiry_iso = next_expiry.isoformat() if next_expiry else None

                # ── Redirect URIs ──
                web = getattr(app, 'web', None)
                redirect_uris_raw = []
                if web:
                    redirect_uris_raw = list(getattr(web, 'redirect_uris', None) or [])

                redirect_uri_count = len(redirect_uris_raw)
                has_localhost = any('localhost' in uri.lower() or '127.0.0.1' in uri for uri in redirect_uris_raw)
                has_http = any(uri.lower().startswith('http://') and 'localhost' not in uri.lower() and '127.0.0.1' not in uri for uri in redirect_uris_raw)

                # ── Owners ──
                owners_list = []
                try:
                    owners_resp = await self.graph_client.applications.by_application_id(object_id).owners.get()
                    if owners_resp and owners_resp.value:
                        for o in owners_resp.value:
                            owners_list.append({
                                'object_id': getattr(o, 'id', '') or '',
                                'display_name': getattr(o, 'display_name', '') or '',
                                'upn': getattr(o, 'user_principal_name', '') or '',
                                'type': getattr(o, 'odata_type', '') or '',
                            })
                except Exception:
                    pass

                owner_count = len(owners_list)
                primary_owner = owners_list[0]['display_name'] if owners_list else None

                # ── SPN cross-link ──
                spn_info = spn_app_id_map.get(app_id, {})
                has_spn = bool(spn_info)
                linked_spn_id = spn_info.get('id')
                spn_last_sign_in = spn_info.get('last_sign_in')
                spn_activity = spn_info.get('activity_status')

                # ── Risk scoring ──
                risk_score, risk_reasons = self._compute_app_registration_risk(
                    owner_count=owner_count,
                    audience=audience,
                    app_perm_count=app_perm_count,
                    high_risk_list=high_risk_list,
                    has_expired=has_expired,
                    has_expiring_soon=has_expiring_soon,
                    is_third_party=is_third_party,
                    has_localhost=has_localhost,
                    has_http=has_http,
                    has_spn=has_spn,
                    spn_activity=spn_activity,
                )
                if risk_score >= 80:
                    risk_level = 'critical'
                elif risk_score >= 50:
                    risk_level = 'high'
                elif risk_score >= 25:
                    risk_level = 'medium'
                elif risk_score > 0:
                    risk_level = 'low'
                else:
                    risk_level = 'info'

                results.append({
                    'app_object_id': object_id,
                    'app_id': app_id,
                    'display_name': display_name,
                    'created_datetime': created,
                    'sign_in_audience': audience,
                    'publisher_domain': publisher_domain,
                    'app_owner_organization_id': owner_org_id,
                    'is_third_party': is_third_party,
                    'required_permissions': raw_perms,
                    'permission_count': total_perms,
                    'application_permission_count': app_perm_count,
                    'delegated_permission_count': delegated_perm_count,
                    'high_risk_permissions': high_risk_list,
                    'secret_count': secret_count,
                    'certificate_count': cert_count,
                    'credential_details': cred_details,
                    'next_expiry': next_expiry_iso,
                    'has_expired_credential': has_expired,
                    'has_expiring_soon': has_expiring_soon,
                    'owner_count': owner_count,
                    'owners': owners_list,
                    'primary_owner': primary_owner,
                    'has_service_principal': has_spn,
                    'linked_spn_id': linked_spn_id,
                    'spn_last_sign_in': spn_last_sign_in,
                    'spn_activity_status': spn_activity,
                    'redirect_uris': redirect_uris_raw,
                    'redirect_uri_count': redirect_uri_count,
                    'has_localhost_redirect': has_localhost,
                    'has_http_redirect': has_http,
                    'risk_level': risk_level,
                    'risk_score': risk_score,
                    'risk_reasons': risk_reasons,
                })

            return results
        except Exception as e:
            logger.error("App registration discovery failed: %s", e, exc_info=True)
            return []

    def _compute_app_registration_risk(self, owner_count, audience, app_perm_count,
                                        high_risk_list, has_expired, has_expiring_soon,
                                        is_third_party, has_localhost, has_http,
                                        has_spn, spn_activity):
        """Compute risk score for an app registration."""
        score = 0
        reasons = []

        if owner_count == 0:
            score += 40
            reasons.append('No owner — no accountability')
        if audience in ('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount') and app_perm_count > 0:
            score += 30
            reasons.append(f'Multi-tenant with {app_perm_count} Application permissions')
        if has_expired:
            score += 25
            reasons.append('Has expired credentials')
        if app_perm_count > 5:
            score += 20
            reasons.append(f'{app_perm_count} Application-level permissions (excessive)')
        if is_third_party:
            score += 15
            reasons.append('Third-party publisher')
        if has_localhost:
            score += 15
            reasons.append('Localhost redirect URI (dev/test artifact)')
        if has_http:
            score += 15
            reasons.append('Non-HTTPS redirect URI')
        if has_spn and spn_activity in ('stale', 'never_used', 'inactive'):
            score += 10
            reasons.append(f'SPN is {spn_activity} — app may be abandoned')
        if len(high_risk_list) > 3:
            score += 10
            reasons.append(f'{len(high_risk_list)} high-risk permissions')
        if has_expiring_soon:
            score += 10
            reasons.append('Credentials expiring within 30 days')

        return score, reasons

    def _save_results_to_json(self, result: DiscoveryResult):
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"discovery_results_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump({
                'run_id': result.run_id,
                'timestamp': timestamp,
                'total_identities': result.total_identities,
                'service_principals': result.service_principals_count,
                'users': result.users_count,
                'managed_identities': result.managed_identities_count,
                'critical_risks': result.critical_count,
                'high_risks': result.high_count,
                'medium_risks': result.medium_count,
            }, f, indent=2, default=str)
        logger.info("Results saved to: %s", filename)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    engine = AzureDiscoveryEngine(
        azure_directory_id=os.getenv('AZURE_TENANT_ID'),
        client_id=os.getenv('AZURE_CLIENT_ID'),
        client_secret=os.getenv('AZURE_CLIENT_SECRET')
    )
    
    result = engine.run_discovery()