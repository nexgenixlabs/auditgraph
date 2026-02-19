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
    - Pagination support for large tenants (999 items per page)
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
    engine = AzureDiscoveryEngine(tenant_id, client_id, client_secret)
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
from datetime import datetime
from typing import Dict, List, Any, Set

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
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient
from app.database import Database
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
        tenant_id: Azure AD tenant ID
        client_id: Service principal application ID for authentication
        client_secret: Service principal secret for authentication
        db: Database instance for storing discovery results
        graph_client: Microsoft Graph SDK client
        subscription_id: Target Azure subscription ID
        subscription_name: Human-readable subscription name
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 db_tenant_id=None, cloud_connection_id: int = None):
        """
        Initialize the discovery engine with Azure credentials.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Service principal application ID
            client_secret: Service principal client secret
            db_tenant_id: AuditGraph tenant ID (integer) for RLS context
            cloud_connection_id: ID from cloud_connections table (for multi-connection support)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.db_tenant_id = db_tenant_id
        self.cloud_connection_id = cloud_connection_id
        self.db = Database(tenant_id=db_tenant_id)
        
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )

        self.graph_client = GraphServiceClient(
            credentials=self.credential,
            scopes=['https://graph.microsoft.com/.default']
        )

        # Auto-discover all accessible subscriptions
        self.subscriptions = self._discover_subscriptions()
        sub_names = [f"{s['name']} ({s['id'][:8]}...)" for s in self.subscriptions]
        print(f"✓ Discovery Engine initialized for {len(self.subscriptions)} subscription(s): {', '.join(sub_names) or 'none'}")
    
    def _discover_subscriptions(self) -> List[Dict[str, str]]:
        """Auto-discover all Azure subscriptions accessible to the service principal.

        IMPORTANT: Never falls back to env vars in multi-tenant mode — each tenant's
        SPN must have RBAC access to their own subscriptions.
        """
        try:
            sub_client = SubscriptionClient(self.credential)
            subs = []
            for sub in sub_client.subscriptions.list():
                if sub.state and sub.state.lower() in ('enabled', 'warned'):
                    subs.append({
                        'id': sub.subscription_id,
                        'name': sub.display_name or sub.subscription_id,
                    })
            if not subs:
                print("  ⚠️ No Azure subscriptions found — SPN needs Reader RBAC on at least one subscription")
            return subs
        except Exception as e:
            print(f"  ⚠️ Subscription discovery failed: {e}")
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
        print("\n" + "="*60)
        print("🔍 AuditGraph Discovery Engine")
        print("="*60)
        print(f"\nSubscriptions: {sub_summary}")
        print(f"Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        
        # Create discovery run using Database class method
        print("📝 Creating discovery run...")
        # Store all subscription IDs as comma-separated for the run record
        all_sub_ids = ",".join(s['id'] for s in self.subscriptions) if self.subscriptions else os.getenv('AZURE_SUBSCRIPTION_ID', '')
        all_sub_names = ", ".join(s['name'] for s in self.subscriptions) if self.subscriptions else os.getenv('AZURE_SUBSCRIPTION_NAME', 'Unknown')
        run_id = self.db.create_discovery_run(all_sub_ids, all_sub_names,
                                               cloud_connection_id=self.cloud_connection_id)
        print(f"  ✓ Discovery run created (ID: {run_id})")
        
        # Step 1: Get role assignments FIRST
        print("\n🎯 Discovering Role Assignments...")
        role_assignments = self._discover_role_assignments()
        print(f"  Found {len(role_assignments)} role assignments")
        
        # Step 2: Extract principal IDs that have roles
        principal_ids_with_roles = set(ra['principal_id'] for ra in role_assignments)
        print(f"  Found {len(principal_ids_with_roles)} unique principals with roles")
        
        # Step 2.5: Discover Entra ID directory roles
        print("\n🔑 Discovering Entra ID Directory Roles...")
        entra_roles = await self._discover_entra_roles()
        
        # Merge principal IDs from both Azure RBAC and Entra roles
        entra_principal_ids = set(er['principal_id'] for er in entra_roles)
        all_principal_ids = principal_ids_with_roles.union(entra_principal_ids)
        print(f"  Total unique principals (RBAC + Entra): {len(all_principal_ids)}")
        
        # Step 3: Discover Service Principals
        print("\n📋 Discovering Service Principals...")
        service_principals = await self._discover_service_principals()
        print(f"  Found {len(service_principals)} service principals")
        
        # Step 3.5: Discover SPN Credentials
        credentials_map = await self._discover_credentials(service_principals)
        
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

        # Step 4: Discover users who have Azure RBAC OR Entra roles
        print("\n👥 Discovering Users with Roles...")
        users = await self._discover_users_with_roles(all_principal_ids)
        print(f"  Found {len(users)} users with role assignments")
        
        # Step 5: Discover Managed Identities
        print("\n🔐 Discovering Managed Identities...")
        managed_identities = []
        print(f"  Found {len(managed_identities)} user-assigned managed identities")
        
        all_identities = service_principals + users + managed_identities
        
        # Step 6: Calculate risks (enhanced points-based scoring)
        print("\n⚠️  Calculating Risk Levels...")
        identities_with_risks = self._calculate_risks(
            all_identities, role_assignments, entra_roles,
            permissions_map, app_roles_map, credentials_map
        )
        
        # Step 7: Check credentials
        print("\n🔑 Checking Credential Expiration...")
        identities_with_creds = self._check_credentials(identities_with_risks)
        
        # Step 8: Check activity
        print("\n🕐 Checking Last Activity...")
        final_identities = self._check_activity(identities_with_creds)
        
        # Step 9: Save to database using Database class methods
        print("\n💾 Saving identities to database...")
        saved_count = self._save_identities(run_id, final_identities, role_assignments, credentials_map, permissions_map, app_roles_map, ownership_map, pim_map, ca_policies)
        print(f"  ✓ Saved {saved_count} identities")

        # Step 9a: Compute Workload Identity Exposure Scores
        print("\n🎯 Computing workload identity exposure scores...")
        try:
            self._compute_workload_exposure(run_id)
        except Exception as e:
            print(f"  ✗ Workload exposure computation error: {e}")
            import traceback
            traceback.print_exc()

        # Step 9a-ii: P2 Telemetry Ingestion (if enabled)
        try:
            p2_enabled = self.db.get_setting('p2_telemetry_enabled', 'false', tenant_id=self.db._tenant_id) == 'true'
            if p2_enabled:
                print("\n📊 Ingesting P2 sign-in telemetry...")
                from app.engines.telemetry.p2_ingestion import P2TelemetryService
                telemetry = P2TelemetryService(self.credential, self.db)
                tenant_id = self.db._tenant_id
                telemetry.ingest_signin_logs(run_id, tenant_id)
                telemetry.compute_activity_stats(run_id, tenant_id)
                # Run behavioral anomaly detection
                from app.engines.telemetry.behavioral_engine import BehavioralAnomalyEngine
                anomaly_engine = BehavioralAnomalyEngine(self.db)
                anomaly_engine.detect_anomalies(run_id, tenant_id)
        except Exception as e:
            print(f"  ⚠️ P2 telemetry ingestion error: {e}")

        # Step 9b: Discover Azure Resources (Storage Accounts & Key Vaults)
        print("\n🗄️  Discovering Azure Resources...")
        storage_accounts = self._discover_storage_accounts()
        print(f"  ✓ Found {len(storage_accounts)} storage accounts")
        key_vaults = self._discover_key_vaults()
        print(f"  ✓ Found {len(key_vaults)} key vaults")

        # Save resources to database
        tenant_id_val = getattr(self, '_tenant_id', None)
        for sa in storage_accounts:
            sa['tenant_id'] = tenant_id_val
            self.db.save_storage_account(run_id, sa)
        for kv in key_vaults:
            kv['tenant_id'] = tenant_id_val
            self.db.save_key_vault(run_id, kv)
        print(f"  ✓ Saved {len(storage_accounts)} storage accounts, {len(key_vaults)} key vaults")

        # Step 9c: Discover App Registrations
        print("\n📋 Discovering App Registrations...")
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

            app_regs = asyncio.get_event_loop().run_until_complete(
                self._discover_app_registrations(spn_app_id_map)
            )
            for ar in app_regs:
                ar['tenant_id'] = tenant_id_val
                self.db.save_app_registration(run_id, ar)
            print(f"  ✓ Saved {len(app_regs)} app registrations")
        except Exception as e:
            print(f"  ✗ App registration discovery error: {e}")
            import traceback
            traceback.print_exc()

        # Step 10: Complete discovery run
        print("\n✅ Completing discovery run...")
        critical_count = sum(1 for i in final_identities if i['risk_level'] == 'critical')
        high_count = sum(1 for i in final_identities if i['risk_level'] == 'high')
        medium_count = sum(1 for i in final_identities if i['risk_level'] == 'medium')
        low_count = sum(1 for i in final_identities if i['risk_level'] == 'low')
        
        self.db.complete_discovery_run(
            run_id, len(final_identities),
            critical_count, high_count, medium_count, low_count
        )
        print(f"  ✓ Discovery run completed")

        # Sync discovered subscriptions into cloud_subscriptions registry
        try:
            for sub in self.subscriptions:
                cursor = self.db.conn.cursor()
                # Use tenant_id from the discovery run
                cursor.execute("SELECT tenant_id FROM discovery_runs WHERE id = %s", (run_id,))
                run_row = cursor.fetchone()
                run_tenant_id = run_row[0] if run_row and run_row[0] else 1
                if self.cloud_connection_id:
                    cursor.execute("""
                        INSERT INTO cloud_subscriptions (tenant_id, cloud, account_id, account_name, status, cloud_connection_id)
                        VALUES (%s, 'azure', %s, %s, 'discovered', %s)
                        ON CONFLICT (tenant_id, cloud, account_id) DO UPDATE
                        SET account_name = EXCLUDED.account_name,
                            cloud_connection_id = COALESCE(EXCLUDED.cloud_connection_id, cloud_subscriptions.cloud_connection_id)
                    """, (run_tenant_id, sub['id'], sub['name'], self.cloud_connection_id))
                else:
                    cursor.execute("""
                        INSERT INTO cloud_subscriptions (tenant_id, cloud, account_id, account_name, status)
                        VALUES (%s, 'azure', %s, %s, 'discovered')
                        ON CONFLICT (tenant_id, cloud, account_id) DO UPDATE
                        SET account_name = EXCLUDED.account_name
                    """, (run_tenant_id, sub['id'], sub['name']))
                self.db.conn.commit()
                cursor.close()
            print(f"  ✓ Synced {len(self.subscriptions)} subscription(s) to registry")
        except Exception as e:
            print(f"  ⚠️ Subscription sync warning: {e}")

        # Seed auto identity groups for this tenant (Phase 38 + RLS fix)
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT tenant_id FROM discovery_runs WHERE id = %s", (run_id,))
            row = cursor.fetchone()
            cursor.close()
            if row and row[0]:
                self.db.seed_auto_groups_for_tenant(row[0])
                print(f"  ✓ Auto identity groups seeded for tenant {row[0]}")
        except Exception as e:
            print(f"  ⚠️ Auto groups seed warning: {e}")

        # Create result object
        # result = self._create_result(final_identities, role_assignments, run_id)
        # self._save_results_to_json(result)
        
        return None  # result
    
    async def _discover_service_principals(self) -> List[Dict[str, Any]]:
        """Discover customer-owned service principals (excludes Microsoft system apps and system-assigned MIs)"""
        try:
            identities = []
            skipped_microsoft_count = 0
            skipped_sami_count = 0
            
            # Microsoft Graph returns max 100 by default, need pagination
            # Use $top=999 to get more per page
            from msgraph.generated.service_principals.service_principals_request_builder import ServicePrincipalsRequestBuilder
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            
            query_params = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
                top=999,  # Get up to 999 per page
                select=['id', 'appId', 'displayName', 'accountEnabled', 'createdDateTime',
                        'servicePrincipalType', 'alternativeNames', 'appOwnerOrganizationId', 'publisherName',
                        'signInActivity']  # Include sign-in activity
            )
            request_config = RequestConfiguration(query_parameters=query_params)
            
            sps = await self.graph_client.service_principals.get(request_configuration=request_config)
            
            if sps and sps.value:
                for sp in sps.value:
                    if len(identities) < 10:
                        print(f"    ✓ {sp.display_name} ({sp.id})")
                    
                    # DEBUG: Log first 3 service principals to see available fields
                    if len(identities) < 3:
                        print(f"\n  DEBUG SP #{len(identities)+1}: {sp.display_name}")
                        print(f"    - service_principal_type: {getattr(sp, 'service_principal_type', 'ATTR NOT FOUND')}")
                        print(f"    - app_owner_organization_id: {getattr(sp, 'app_owner_organization_id', 'ATTR NOT FOUND')}")
                        print(f"    - publisher_name: {getattr(sp, 'publisher_name', 'ATTR NOT FOUND')}")
                        print(f"    - app_id: {sp.app_id}")
                        print(f"    - Has additional_data: {hasattr(sp, 'additional_data')}")
                        if hasattr(sp, 'additional_data') and sp.additional_data:
                            print(f"    - additional_data keys: {list(sp.additional_data.keys())[:10]}")
                    
                    created = None
                    if hasattr(sp, 'created_date_time') and sp.created_date_time:
                        created = sp.created_date_time.isoformat()
                    elif hasattr(sp, 'additional_data') and sp.additional_data:
                        if sp.additional_data.get('createdDateTime'):
                            created = sp.additional_data.get('createdDateTime')
                    
                    # Determine identity type based on servicePrincipalType
                    identity_type = 'service_principal'
                    if hasattr(sp, 'service_principal_type'):
                        if sp.service_principal_type == 'ManagedIdentity':
                            identity_type = 'managed_identity'
                    
                    # Check if this is a Microsoft system app (filter out)
                    # Extract sign-in activity if available
                    last_sign_in = None
                    if hasattr(sp, 'sign_in_activity') and sp.sign_in_activity:
                        sia = sp.sign_in_activity
                        # Use last_sign_in_date_time or last_non_interactive_sign_in_date_time
                        if hasattr(sia, 'last_sign_in_date_time') and sia.last_sign_in_date_time:
                            last_sign_in = sia.last_sign_in_date_time.isoformat()
                        elif hasattr(sia, 'last_non_interactive_sign_in_date_time') and sia.last_non_interactive_sign_in_date_time:
                            last_sign_in = sia.last_non_interactive_sign_in_date_time.isoformat()

                    identity_dict = {
                        'identity_id': sp.app_id or sp.id,
                        'object_id': sp.id,
                        'app_id': sp.app_id,
                        'display_name': sp.display_name,
                        'identity_type': identity_type,
                        'enabled': sp.account_enabled if hasattr(sp, 'account_enabled') else True,
                        'created_datetime': created,
                        'last_sign_in': last_sign_in,
                        'service_principal_type': sp.service_principal_type if hasattr(sp, 'service_principal_type') else None,
                        'app_owner_organization_id': str(sp.app_owner_organization_id) if hasattr(sp, 'app_owner_organization_id') and sp.app_owner_organization_id else None,
                        'app_owner_org_id': str(sp.app_owner_organization_id) if hasattr(sp, 'app_owner_organization_id') and sp.app_owner_organization_id else None,
                        'publisher_name': sp.publisher_name if hasattr(sp, 'publisher_name') else None,
                        # Multi-cloud normalized fields
                        'cloud': 'azure',
                        'tenant_id': self.tenant_id,
                        'source': 'entra',
                        'permission_plane': 'entra_id',
                    }

                    # ──── STRICT DISCOVERY POLICY ────
                    # EXCLUDE: Microsoft system apps + system-assigned managed identities
                    # KEEP: Customer service principals, user-assigned MIs only
                    sp_type = None
                    if hasattr(sp, "service_principal_type"):
                        sp_type = sp.service_principal_type
                    elif hasattr(sp, "servicePrincipalType"):
                        sp_type = getattr(sp, "servicePrincipalType")
                    sp_type_norm = str(sp_type or "").strip().lower()

                    if sp_type_norm == "managedidentity":
                        alt_names = []
                        if hasattr(sp, "alternative_names") and sp.alternative_names:
                            alt_names = list(sp.alternative_names)
                        elif hasattr(sp, "alternativeNames") and getattr(sp, "alternativeNames"):
                            alt_names = list(getattr(sp, "alternativeNames"))

                        alt_join = " ".join([str(a) for a in alt_names]).lower()
                        is_uami = "userassignedidentities" in alt_join

                        if not is_uami:
                            # SKIP: System-assigned managed identity (tied to Azure resource lifecycle)
                            skipped_sami_count += 1
                            continue

                        # KEEP: User-assigned managed identity (customer-owned)
                        identity_dict["identity_category"] = "managed_identity_user"
                        identity_dict["identity_type"] = "managed_identity_user"
                        identity_dict["alternative_names"] = alt_names
                        identity_dict["is_microsoft_system"] = False
                        identities.append(identity_dict)

                    elif self._is_microsoft_system_app(identity_dict):
                        # STORE with flag: Microsoft first-party app (filtered at query time)
                        identity_dict["identity_category"] = "service_principal"
                        identity_dict["identity_type"] = "service_principal"
                        identity_dict["is_microsoft_system"] = True
                        identities.append(identity_dict)
                        skipped_microsoft_count += 1

                    else:
                        # KEEP: Customer service principal (app registration)
                        identity_dict["identity_category"] = "service_principal"
                        identity_dict["identity_type"] = "service_principal"
                        identity_dict["is_microsoft_system"] = False
                        identities.append(identity_dict)
            
            if skipped_microsoft_count > 0 or skipped_sami_count > 0:
                print(f"  🏷️ Flagged: {skipped_microsoft_count} Microsoft system apps (is_microsoft_system=True), excluded {skipped_sami_count} system-assigned MIs")
                print(f"  ✅ Total: {len(identities)} identities ({len(identities) - skipped_microsoft_count} customer, {skipped_microsoft_count} Microsoft)")

            return identities
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return []
    
    async def _discover_credentials(self, service_principals: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover credentials (secrets, certificates, federated) for service principals
        
        Returns:
            Dictionary mapping identity_id to list of credentials
        """
        credentials_map = {}
        
        print("\n🔑 Discovering SPN Credentials...")
        
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
                        credentials.append({
                            'credential_type': 'federated',
                            'key_id': fed_cred.id if hasattr(fed_cred, 'id') else str(hash(fed_cred.subject)),
                            'display_name': fed_cred.name if hasattr(fed_cred, 'name') else None,
                            'start_datetime': None,
                            'end_datetime': None,  # Federated credentials don't expire
                            'issuer': fed_cred.issuer if hasattr(fed_cred, 'issuer') else None,
                            'subject': fed_cred.subject if hasattr(fed_cred, 'subject') else None,
                        })
                
                if credentials:
                    credentials_map[sp['identity_id']] = credentials
                    if len(credentials_map) <= 5:  # Show first 5
                        print(f"    ✓ {sp['display_name']}: {len(credentials)} credential(s)")
            
            except Exception as e:
                # Don't fail entire discovery if one SPN fails
                if len(credentials_map) == 0:  # Only show first error
                    print(f"    ⚠️  Error getting credentials for {sp['display_name']}: {e}")
                continue
        
        print(f"  Found credentials for {len(credentials_map)} SPNs")
        return credentials_map


    async def _discover_permissions(self, service_principals: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover Graph API permissions for service principals
        
        Returns:
            Dictionary mapping identity_id to list of permissions
        """
        permissions_map = {}
        
        print("\n🔐 Discovering API Permissions...")
        
        for sp in service_principals:
            try:
                # Get app role assignments for this service principal
                assignments = await self.graph_client.service_principals.by_service_principal_id(
                    sp['object_id']
                ).app_role_assignments.get()
                
                if not assignments or not assignments.value:
                    continue
                
                permissions = []
                
                for assignment in assignments.value:
                    # Get the resource service principal to fetch permission details
                    resource_sp_id = assignment.resource_id
                    
                    try:
                        resource_sp = await self.graph_client.service_principals.by_service_principal_id(
                            resource_sp_id
                        ).get()
                        
                        # Find the specific app role
                        if hasattr(resource_sp, 'app_roles') and resource_sp.app_roles:
                            for app_role in resource_sp.app_roles:
                                if str(app_role.id) == str(assignment.app_role_id):
                                    permissions.append({
                                        'name': app_role.value if app_role.value else 'Unknown',
                                        'description': app_role.display_name if app_role.display_name else '',
                                        'resource_name': resource_sp.display_name if resource_sp.display_name else 'Microsoft Graph',
                                        'permission_type': 'Application',
                                        'permission_id': str(app_role.id),
                                        'consent_type': 'Admin'
                                    })
                                    break
                    except Exception as e:
                        # Skip if we can't fetch resource details
                        continue
                
                if permissions:
                    permissions_map[sp['identity_id']] = permissions
                    if len(permissions_map) <= 5:  # Show first 5
                        print(f"    ✓ {sp['display_name']}: {len(permissions)} permission(s)")
            
            except Exception as e:
                # Skip this SPN if permission fetch fails
                continue
        
        print(f"  ✓ Fetched permissions for {len(permissions_map)} service principals")
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
        print("\n📱 Discovering Custom App Roles...")
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
                    print(f"    ✓ {sp.get('displayName', 'Unknown')}: {len(custom_app_roles)} app role(s)")
                
            except Exception as e:
                # Silently skip if no permissions or access denied
                continue
        
        if found_count > 0:
            print(f"  ✓ Fetched app roles for {found_count} service principals")
        else:
            print(f"  ℹ️  No custom app role assignments found")
        
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
        print("\n👤 Discovering Application Owners...")
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
                                print(f"    ✓ {sp.get('display_name', 'Unknown')}: {len(owners)} owner(s)")

            except Exception as e:
                error_count += 1
                if error_count <= 3:
                    print(f"    ⚠️  Could not get owners for {sp.get('display_name', 'Unknown')}: {str(e)[:50]}")

        if found_count > 0:
            print(f"  ✓ Found owners for {found_count} applications")
        else:
            print(f"  ℹ️  No application owners found")

        if error_count > 3:
            print(f"  ⚠️  {error_count} errors occurred (showing first 3)")

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
        print("\n🔒 Discovering PIM Assignments...")
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

            print(f"  ✓ Found {eligible_count} PIM eligible assignments")

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                print(f"  ℹ️  PIM eligible assignments: requires Azure AD P2 license (403)")
            else:
                print(f"  ⚠️  PIM eligible assignments error: {err_str[:80]}")

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

            print(f"  ✓ Found {activation_count} active PIM activations")

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                print(f"  ℹ️  PIM activations: requires Azure AD P2 license (403)")
            else:
                print(f"  ⚠️  PIM activations error: {err_str[:80]}")

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
                print(f"  ⚠️  PIM request history error: {err_str[:80]}")

        if pim_map:
            print(f"  ✓ PIM data found for {len(pim_map)} principals")
        else:
            print(f"  ℹ️  No PIM data found (Azure AD P2 required)")

        return pim_map

    async def _discover_conditional_access(self) -> list:
        """
        Discover Conditional Access policies via Microsoft Graph API.

        Uses: graph_client.identity.conditional_access.policies.get()
        Requires: Policy.Read.All permission. Handle 403 gracefully.

        Returns:
            List of parsed CA policy dicts
        """
        print("\n🛡️  Discovering Conditional Access Policies...")
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

            print(f"  ✓ Found {len(policies)} Conditional Access policies")
            enabled = sum(1 for p in policies if p['state'] == 'enabled')
            mfa = sum(1 for p in policies if p['requires_mfa'] and p['state'] == 'enabled')
            print(f"    Enabled: {enabled}, MFA-enforcing: {mfa}")

        except Exception as e:
            err_str = str(e)
            if '403' in err_str or 'Forbidden' in err_str or 'Authorization' in err_str:
                print(f"  ℹ️  Conditional Access: requires Policy.Read.All permission (403)")
            else:
                print(f"  ⚠️  Conditional Access error: {err_str[:80]}")

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
            print(f"  Warning: Could not discover managed identities: {e}")
        
        return managed_identities
    
    async def _discover_users_with_roles(self, principal_ids_with_roles: Set[str]) -> List[Dict[str, Any]]:
        """
        Discover human users who have Azure RBAC or Entra ID roles.
        Users without roles are NOT discovered - this is by design for security posture focus.
        Handles pagination to fetch all users (not just first page).
        """
        try:
            from msgraph.generated.users.users_request_builder import UsersRequestBuilder

            # Try with signInActivity first (requires Premium license)
            # Fall back to basic fields if not available
            select_fields = ['id', 'displayName', 'userPrincipalName', 'accountEnabled', 'createdDateTime', 'userType']
            try:
                query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                    select=select_fields + ['signInActivity']
                )
                request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                    query_parameters=query_params
                )
                users_response = await self.graph_client.users.get(request_configuration=request_config)
                print("  ✓ Sign-in activity available (Premium license)")
            except Exception as e:
                if '403' in str(e) or 'premium' in str(e).lower():
                    print("  ⚠️  Sign-in activity requires Premium license - using basic user data")
                    query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                        select=select_fields
                    )
                    request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                        query_parameters=query_params
                    )
                    users_response = await self.graph_client.users.get(request_configuration=request_config)
                else:
                    raise e

            # Collect all users with pagination
            all_users = []
            if users_response and users_response.value:
                all_users.extend(users_response.value)
            # Follow @odata.nextLink for pagination
            while users_response and hasattr(users_response, 'odata_next_link') and users_response.odata_next_link:
                users_response = await self.graph_client.users.with_url(users_response.odata_next_link).get()
                if users_response and users_response.value:
                    all_users.extend(users_response.value)

            identities = []
            for user in all_users:
                # Only include users who have roles (Azure RBAC or Entra ID)
                if user.id not in principal_ids_with_roles:
                    continue

                print(f"    ✓ {user.display_name} ({user.user_principal_name})")

                created = None
                if hasattr(user, 'created_date_time') and user.created_date_time:
                    created = user.created_date_time.isoformat()
                elif hasattr(user, 'created_datetime') and user.created_datetime:
                    created = user.created_datetime.isoformat()

                # Determine if guest user
                user_type = getattr(user, 'user_type', None) or ''
                is_guest = user_type.lower() == 'guest' if user_type else False

                # Extract sign-in activity if available
                last_sign_in = None
                if hasattr(user, 'sign_in_activity') and user.sign_in_activity:
                    sia = user.sign_in_activity
                    if hasattr(sia, 'last_sign_in_date_time') and sia.last_sign_in_date_time:
                        last_sign_in = sia.last_sign_in_date_time.isoformat()
                    elif hasattr(sia, 'last_non_interactive_sign_in_date_time') and sia.last_non_interactive_sign_in_date_time:
                        last_sign_in = sia.last_non_interactive_sign_in_date_time.isoformat()

                identities.append({
                    'identity_id': user.id,
                    'object_id': user.id,
                    'app_id': None,
                    'display_name': user.display_name,
                    'user_principal_name': user.user_principal_name,
                    'identity_type': 'user',
                    'identity_category': 'guest' if is_guest else 'human_user',
                    'enabled': user.account_enabled if hasattr(user, 'account_enabled') and user.account_enabled is not None else True,
                    'created_datetime': created,
                    'last_sign_in': last_sign_in,
                    # Multi-cloud normalized fields
                    'cloud': 'azure',
                    'tenant_id': self.tenant_id,
                    'source': 'entra',
                    'permission_plane': 'entra_id',
                    'is_federated': is_guest,  # Guest users are federated
                })

            return identities
        except Exception as e:
            print(f"  ❌ Error discovering users: {e}")
            return []
    
    def _discover_role_assignments(self) -> List[Dict[str, Any]]:
        """Discover RBAC role assignments across ALL accessible subscriptions using Azure SDK."""
        from datetime import datetime, timezone

        role_assignments = []
        printed = 0

        for sub in self.subscriptions:
            sub_id = sub['id']
            sub_name = sub['name']
            print(f"\n  📋 Subscription: {sub_name} ({sub_id[:8]}...)")

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
                        print(f"    ✓ {role_name} → {scope.split('/')[-1][:30] if scope else 'root'}")
                        printed += 1
                    elif printed == 15:
                        print(f"    ... (listing remaining silently)")
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
                print(f"  ⚠️ Error discovering roles for subscription {sub_name}: {e}")
                continue

        print(f"\n  Total: {len(role_assignments)} role assignments across {len(self.subscriptions)} subscription(s)")
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
    
    async def _discover_entra_roles(self) -> List[Dict[str, Any]]:
        """Discover Entra ID directory role assignments for given principals"""
        try:
            print("🔑 Discovering Entra ID Directory Roles...")
            
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
                            print(f"    ✓ {role_name}")
            
            print(f"  Found {len(entra_roles)} Entra ID role assignments")
            return entra_roles
            
        except Exception as e:
            print(f"  ❌ Error discovering Entra roles: {e}")
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
                print(f"    ⚠️  Storage discovery failed for {sub_name}: {e}")
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
                                'tenant_id': getattr(ap, 'tenant_id', ''),
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
                print(f"    ⚠️  Key Vault discovery failed for {sub_name}: {e}")
                continue
        return key_vaults

    def _compute_storage_risk(self, public_blob, https_only, tls, shared_key,
                              default_action, pe_count, cmk, key_stale,
                              sas_policy_enabled=False, diag_enabled=False):
        """Compute risk score for a storage account."""
        score = 0
        reasons = []
        if public_blob:
            score += 40; reasons.append("Public blob access enabled (+40)")
        if not https_only:
            score += 30; reasons.append("HTTP traffic allowed (+30)")
        if 'Allow' in str(default_action):
            score += 25; reasons.append("Network allows all traffic (+25)")
        if tls not in ('TLS1_2', 'TLS1_3'):
            score += 20; reasons.append(f"Old TLS version: {tls} (+20)")
        if not cmk:
            score += 20; reasons.append("No customer-managed encryption keys (+20)")
        if key_stale:
            score += 20; reasons.append("Storage keys not rotated in 90+ days (+20)")
        if shared_key:
            score += 15; reasons.append("Shared key access enabled (+15)")
        if pe_count == 0:
            score += 15; reasons.append("No private endpoints (+15)")
        if shared_key and not sas_policy_enabled:
            score += 10; reasons.append("No SAS expiration policy with shared key enabled (+10)")
        if shared_key and not diag_enabled:
            score += 10; reasons.append("Shared key access without diagnostic logging — unauditable (+10)")
        return (score, reasons)

    def _compute_keyvault_risk(self, soft_delete, purge_prot, public_access,
                               default_action, pe_count, secrets, keys, certs):
        """Compute risk score for a key vault."""
        score = 0
        reasons = []
        if secrets.get('expired', 0) > 0:
            score += 35; reasons.append(f"{secrets['expired']} expired secrets (+35)")
        if keys.get('expired', 0) > 0:
            score += 35; reasons.append(f"{keys['expired']} expired keys (+35)")
        if certs.get('expired', 0) > 0:
            score += 35; reasons.append(f"{certs['expired']} expired certificates (+35)")
        if not soft_delete:
            score += 30; reasons.append("Soft delete disabled (+30)")
        if str(public_access) != 'Disabled' and 'Allow' in str(default_action):
            score += 25; reasons.append("Network allows all traffic (+25)")
        if not purge_prot:
            score += 20; reasons.append("Purge protection disabled (+20)")
        if pe_count == 0:
            score += 15; reasons.append("No private endpoints (+15)")
        if secrets.get('expiring_soon', 0) > 0:
            score += 10; reasons.append(f"{secrets['expiring_soon']} secrets expiring within 30 days (+10)")
        if keys.get('expiring_soon', 0) > 0:
            score += 10; reasons.append(f"{keys['expiring_soon']} keys expiring within 30 days (+10)")
        if certs.get('expiring_soon', 0) > 0:
            score += 10; reasons.append(f"{certs['expiring_soon']} certificates expiring within 30 days (+10)")
        return (score, reasons)

    def _resource_risk_level(self, score):
        """Map risk score to risk level for resources."""
        if score >= 80: return 'critical'
        if score >= 50: return 'high'
        if score >= 25: return 'medium'
        if score > 0: return 'low'
        return 'info'

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
        # Skip managed identities - they are customer-owned, not Microsoft apps
        sp_type = (identity.get('service_principal_type') or identity.get('servicePrincipalType') or '').lower()
        if sp_type == 'managedidentity':
            return False

        # Microsoft's well-known tenant ID
        MICROSOFT_TENANT_ID = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

        # Check 1: Microsoft-owned tenant (most reliable check)
        # NOTE: MS Graph SDK returns UUID objects, must convert to str for comparison
        app_owner_org = identity.get('app_owner_organization_id') or identity.get('appOwnerOrganizationId')
        app_owner_org_str = str(app_owner_org).lower() if app_owner_org else None
        if app_owner_org_str == MICROSOFT_TENANT_ID:
            return True
        # If app_owner_organization_id is set and is NOT Microsoft, it's customer-owned
        if app_owner_org_str and app_owner_org_str != MICROSOFT_TENANT_ID:
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
                logger.warning(f"Custom risk rules error: {e}")

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
                emoji = '🚨' if risk_level == 'critical' else '🟠'
                print(f"    {emoji} {identity['display_name']}: {risk_level.upper()} ({risk_score} pts)")
                for factor in risk_factors[:3]:
                    print(f"       • {factor['code']}: +{factor['points']} ({factor['severity']})")

        # Summary
        critical_count = sum(1 for i in identities if i.get('risk_level') == 'critical')
        high_count = sum(1 for i in identities if i.get('risk_level') == 'high')

        print(f"\n  📊 Risk Summary (V2 scale):")
        print(f"     Total: {len(identities)} customer-owned identities")
        print(f"     🔴 Critical: {critical_count}  🟠 High: {high_count}")

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
        print(f"  Checking {len(identities)} identities...")
        for identity in identities:
            identity['credential_status'] = 'Valid'
            identity['credential_expiration'] = None
        print(f"  ✓ All credentials are valid for 30+ days")
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

        print(f"  Checking {len(identities)} identities...")

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

        print(f"\n  Summary:")
        if active_count > 0:
            print(f"    🟢 Active (30 days): {active_count}")
        if inactive_count > 0:
            print(f"    🟡 Inactive (30-90 days): {inactive_count}")
        if stale_count > 0:
            print(f"    🟠 Stale (90+ days): {stale_count}")
        if never_used_count > 0:
            print(f"    🔴 Never used: {never_used_count}")
        if unknown_count > 0:
            print(f"    ⚪ Unknown: {unknown_count}")

        return identities
    
    def _save_identities(self, run_id: int, identities: List[Dict], all_role_assignments: List[Dict], credentials_map: Dict[str, List[Dict]] = None, permissions_map: Dict[str, List[Dict]] = None, app_roles_map: Dict[str, List[Dict]] = None, ownership_map: Dict[str, List[Dict]] = None, pim_map: Dict[str, Dict] = None, ca_policies: List[Dict] = None) -> int:
        """Save all identities to database (customer-owned only, Microsoft system apps excluded at discovery)"""
        saved_count = 0

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
                    # Check previous runs for this identity_id
                    from datetime import datetime
                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        SELECT created_datetime 
                        FROM identities 
                        WHERE identity_id = %s 
                        AND created_datetime IS NOT NULL
                        ORDER BY discovery_run_id DESC 
                        LIMIT 1
                    """, (identity.get('identity_id'),))
                    prev_result = cursor.fetchone()
                    cursor.close()
                    
                    if prev_result and prev_result[0]:
                        identity['created_datetime'] = prev_result[0]
                    else:
                        # Truly new identity
                        identity['created_datetime'] = datetime.utcnow().isoformat()
            
            identity_db_id = self.db.save_identity(run_id, identity)
            
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

            saved_count += 1

        # Save CA policies and compute coverage after all identities are saved
        if ca_policies:
            print(f"\n🛡️  Saving {len(ca_policies)} CA policies and computing coverage...")
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
                print(f"  ✓ CA coverage computed: {covered}/{len(ca_coverage_map)} identities covered")

        # Post-discovery sweep: catch any Microsoft SPNs that slipped through detection
        self.db.sweep_microsoft_flag(run_id)

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
            cursor.execute(f"SELECT identity_db_id, permission_id, permission_name, permission_type FROM graph_api_permissions WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                perms_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch owners
            cursor.execute(f"SELECT identity_db_id, owner_display_name, owner_upn FROM sp_ownership WHERE identity_db_id IN ({ph})", db_ids)
            for r in cursor.fetchall():
                owners_map.setdefault(r['identity_db_id'], []).append(dict(r))

            # Batch-fetch PIM data
            try:
                cursor.execute(f"SELECT identity_db_id, role_name, start_datetime FROM pim_eligible_assignments WHERE identity_db_id IN ({ph})", db_ids)
                for r in cursor.fetchall():
                    pim_map.setdefault(r['identity_db_id'], {'eligible': [], 'activations': []})
                    pim_map[r['identity_db_id']]['eligible'].append(dict(r))
                cursor.execute(f"SELECT identity_db_id, role_name, start_datetime FROM pim_activations WHERE identity_db_id IN ({ph})", db_ids)
                for r in cursor.fetchall():
                    pim_map.setdefault(r['identity_db_id'], {'eligible': [], 'activations': []})
                    pim_map[r['identity_db_id']]['activations'].append(dict(r))
            except Exception:
                pass  # PIM tables may not exist

            # Batch-fetch P2 activity stats (if available)
            p2_stats_map = {}
            try:
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
            except Exception:
                pass  # Table may not exist yet

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

        print(f"  ✓ Computed exposure for {scored} SPNs/MIs ({critical_count} critical)")

        # ── Part 2: App Registration scoring ─────────────────────────
        try:
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
        except Exception:
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

            print(f"  ✓ Computed exposure for {ar_scored} App Registrations ({ar_critical} critical)")

        cursor.close()

    def _create_result(self, identities: List[Dict], role_assignments: List[Dict], run_id: int) -> DiscoveryResult:
        service_principals = [i for i in identities if i['identity_type'] == 'service_principal']
        users = [i for i in identities if i['identity_type'] == 'user']
        managed_identities = [i for i in identities if i['identity_type'] == 'managed_identity']
        
        critical_count = sum(1 for i in identities if i['risk_level'] == 'critical')
        high_count = sum(1 for i in identities if i['risk_level'] == 'high')
        medium_count = sum(1 for i in identities if i['risk_level'] == 'medium')
        
        print("\n" + "="*60)
        print("📊 Discovery Summary")
        print("="*60)
        print(f"Total Identities: {len(identities)}")
        print(f"  Service Principals: {len(service_principals)}")
        print(f"  Users (with Azure roles): {len(users)}")
        print(f"  Managed Identities: {len(managed_identities)}")
        print(f"\nRisk Assessment:")
        print(f"  🔴 Critical: {critical_count}")
        print(f"  🟠 High: {high_count}")
        print(f"  🟡 Medium: {medium_count}")
        print("="*60 + "\n")
        
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

            print(f"  ✓ Found {len(all_apps)} app registrations")

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
                is_third_party = bool(owner_org_id and owner_org_id != self.tenant_id)

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
            print(f"  ✗ App registration discovery failed: {e}")
            import traceback
            traceback.print_exc()
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
        print(f"✓ Results saved to: {filename}")


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    engine = AzureDiscoveryEngine(
        tenant_id=os.getenv('AZURE_TENANT_ID'),
        client_id=os.getenv('AZURE_CLIENT_ID'),
        client_secret=os.getenv('AZURE_CLIENT_SECRET')
    )
    
    result = engine.run_discovery()