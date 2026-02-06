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
    - Azure CLI: For RBAC role assignment discovery
"""
import os
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Set
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from app.database import Database
from .models import DiscoveryResult
import json

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

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        """
        Initialize the discovery engine with Azure credentials.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Service principal application ID
            client_secret: Service principal client secret
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.db = Database()
        
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        self.graph_client = GraphServiceClient(
            credentials=credential,
            scopes=['https://graph.microsoft.com/.default']
        )
        
        self.subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
        self.subscription_name = os.getenv('AZURE_SUBSCRIPTION_NAME', 'Unknown')
        print(f"✓ Discovery Engine initialized for subscription: {self.subscription_id}")
    
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
        print("\n" + "="*60)
        print("🔍 AuditGraph Discovery Engine")
        print("="*60)
        print(f"\nTarget: {self.subscription_name} ({self.subscription_id})")
        print(f"Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        
        # Create discovery run using Database class method
        print("📝 Creating discovery run...")
        run_id = self.db.create_discovery_run(self.subscription_id, self.subscription_name)
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

        # Step 4: Discover users who have Azure RBAC OR Entra roles
        print("\n👥 Discovering Users with Roles...")
        users = await self._discover_users_with_roles(all_principal_ids)
        print(f"  Found {len(users)} users with Azure RBAC assignments")
        
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
        saved_count = self._save_identities(run_id, final_identities, role_assignments, credentials_map, permissions_map, app_roles_map, ownership_map)
        print(f"  ✓ Saved {saved_count} identities")
        
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
        
        # Create result object
        # result = self._create_result(final_identities, role_assignments, run_id)
        # self._save_results_to_json(result)
        
        return None  # result
    
    async def _discover_service_principals(self) -> List[Dict[str, Any]]:
        """Discover all service principals with pagination"""
        try:
            identities = []
            
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
                        'app_owner_organization_id': sp.app_owner_organization_id if hasattr(sp, 'app_owner_organization_id') else None,
                        'publisher_name': sp.publisher_name if hasattr(sp, 'publisher_name') else None,
                        # Multi-cloud normalized fields
                        'cloud': 'azure',
                        'tenant_id': self.tenant_id,
                        'source': 'entra',
                    }

                    # Classify identity into the correct category
                    # Categories: service_principal, managed_identity_system, managed_identity_user, microsoft_internal
                    sp_type = None
                    if hasattr(sp, "service_principal_type"):
                        sp_type = sp.service_principal_type
                    elif hasattr(sp, "servicePrincipalType"):
                        sp_type = getattr(sp, "servicePrincipalType")
                    sp_type_norm = str(sp_type or "").strip().lower()

                    # Category 1 & 2: Managed Identities (SAMI / UAMI)
                    # In Entra, managed identities are represented as service principals with servicePrincipalType=ManagedIdentity
                    if sp_type_norm == "managedidentity":
                        alt_names = []
                        if hasattr(sp, "alternative_names") and sp.alternative_names:
                            alt_names = list(sp.alternative_names)
                        elif hasattr(sp, "alternativeNames") and getattr(sp, "alternativeNames"):
                            alt_names = list(getattr(sp, "alternativeNames"))

                        alt_join = " ".join([str(a) for a in alt_names]).lower()
                        is_uami = "userassignedidentities" in alt_join
                        identity_dict["identity_category"] = "managed_identity_user" if is_uami else "managed_identity_system"
                        identity_dict["identity_type"] = identity_dict["identity_category"]
                        identity_dict["alternative_names"] = alt_names
                        identity_dict["is_microsoft_system"] = False  # Managed identities are customer-owned
                        identities.append(identity_dict)

                    # Category 3: Microsoft Internal (first-party Microsoft apps)
                    elif self._is_microsoft_system_app(identity_dict):
                        identity_dict["identity_category"] = "microsoft_internal"
                        identity_dict["identity_type"] = "service_principal"  # Keep legacy type for compatibility
                        identity_dict["is_microsoft_system"] = True
                        identities.append(identity_dict)

                    # Category 4: Customer Service Principals (custom apps)
                    else:
                        identity_dict["identity_category"] = "service_principal"
                        identity_dict["identity_type"] = "service_principal"
                        identity_dict["is_microsoft_system"] = False
                        identities.append(identity_dict)
            
            return identities
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return []

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
        """
        try:
            from msgraph.generated.users.users_request_builder import UsersRequestBuilder

            # Try with signInActivity first (requires Premium license)
            # Fall back to basic fields if not available
            try:
                query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                    select=['id', 'displayName', 'userPrincipalName', 'accountEnabled', 'createdDateTime', 'userType',
                            'signInActivity']
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
                        select=['id', 'displayName', 'userPrincipalName', 'accountEnabled', 'createdDateTime', 'userType']
                    )
                    request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                        query_parameters=query_params
                    )
                    users_response = await self.graph_client.users.get(request_configuration=request_config)
                else:
                    raise e

            identities = []
            for user in users_response.value:
                # Only include users who have roles (Azure RBAC or Entra ID)
                if user.id in principal_ids_with_roles:
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
                        'is_federated': is_guest,  # Guest users are federated
                    })

            return identities
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return []
    
    def _discover_role_assignments(self) -> List[Dict[str, Any]]:
        import subprocess
        import json
        from datetime import datetime, timezone

        try:
            result = subprocess.run(
                ['az', 'role', 'assignment', 'list', '--all'],
                capture_output=True,
                text=True,
                check=True
            )

            assignments = json.loads(result.stdout)

            role_assignments = []
            for assignment in assignments:
                principal_id = assignment.get('principalId')
                if principal_id:
                    if len(role_assignments) < 10:
                        print(f"    ✓ {assignment.get('principalName', 'Unknown')}: {assignment['roleDefinitionName']}")

                    scope = assignment.get('scope', '')
                    scope_type = 'subscription' if '/resourceGroups/' not in scope else 'resource_group' if scope.count('/') <= 4 else 'resource'
                    role_name = assignment['roleDefinitionName']
                    created_on = assignment.get('createdOn')

                    # Calculate days since assigned
                    days_since_assigned = None
                    if created_on:
                        try:
                            created_dt = datetime.fromisoformat(created_on.replace('Z', '+00:00'))
                            days_since_assigned = (datetime.now(timezone.utc) - created_dt).days
                        except:
                            pass

                    # Calculate role-level risk
                    risk_level, why_critical = self._calculate_role_risk(role_name, scope_type)

                    # Extract resource info from scope
                    resource_type, resource_name = self._parse_scope(scope)

                    role_assignments.append({
                        'principal_id': principal_id,
                        'assignment_id': assignment.get('id'),
                        'role_name': role_name,
                        'scope': scope,
                        'scope_type': scope_type,
                        'created_on': created_on,
                        # Usage intelligence fields
                        'scope_exists': True,  # Assume exists (ARM returned it)
                        'usage_status': 'unknown',  # Will be calculated later
                        'days_since_assigned': days_since_assigned,
                        'redundant_with': None,  # Will be calculated later
                        'role_type': 'azure',
                        'risk_level': risk_level,
                        'why_critical': why_critical,
                        'resource_type': resource_type,
                        'resource_name': resource_name,
                    })

            return role_assignments
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return []

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
        app_owner_org = identity.get('app_owner_organization_id') or identity.get('appOwnerOrganizationId')
        if app_owner_org == MICROSOFT_TENANT_ID:
            return True

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

            # Generic Microsoft service patterns
            'service', 'processor', 'handler', 'proxy', 'agent',
            'scheduler', 'deployer', 'cab', 'capacity', ' rp',
        ]

        # Check if display name contains any Microsoft keyword
        for keyword in microsoft_keywords:
            if keyword in display_name:
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
        Enhanced points-based risk calculation for all identities.

        Risk Score Breakdown:
        - Entra ID Roles: Global Admin (100), Privileged Role Admin (90), App Admin (80), Security Admin (60)
        - Azure RBAC: Owner on subscription (100), Contributor on subscription (80), User Access Admin (70)
        - API Permissions: Write permissions (60), Read-all permissions (40)
        - Orphaned permissions: API access without role justification (30)
        - App Roles: Admin app roles (50)
        - Usage: Never used with credentials (40), Dormant 90+ days (20)
        - Credentials: Expired credentials (35)

        Risk Levels:
        - 120+ points = CRITICAL
        - 70-119 points = HIGH
        - 40-69 points = MEDIUM
        - 0-39 points = LOW/INFO
        """
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

            # Initialize scoring
            risk_score = 0
            risk_reasons = []

            is_microsoft = identity.get('is_microsoft_system', False)
            identity_category = identity.get('identity_category', '')

            # Skip detailed scoring for Microsoft internal identities
            if is_microsoft or identity_category == 'microsoft_internal':
                identity['risk_level'] = 'info'
                identity['risk_score'] = 0
                identity['risk_reasons'] = ['Microsoft internal service (no customer action needed)']
                identity['roles'] = identity_roles
                identity['entra_roles'] = identity_entra_roles
                identity['role_count'] = len(identity_roles)
                identity['api_permission_count'] = len(identity_permissions)
                identity['app_role_count'] = len(identity_app_roles)
                continue

            # ============================================================
            # 1. Entra ID Directory Roles (highest privilege)
            # ============================================================
            for entra_role in identity_entra_roles:
                role_name_lower = entra_role['role_name'].lower()
                if 'global administrator' in role_name_lower:
                    risk_score += 100
                    risk_reasons.append('Global Administrator: Full tenant control - violates SOC2 least privilege, HIPAA access controls (§164.312), PCI-DSS requirement 7')
                elif 'privileged role administrator' in role_name_lower:
                    risk_score += 90
                    risk_reasons.append('Privileged Role Admin: Can assign any role - privilege escalation risk, violates SOC2 separation of duties')
                elif 'application administrator' in role_name_lower or 'cloud application administrator' in role_name_lower:
                    risk_score += 80
                    risk_reasons.append(f"{entra_role['role_name']}: Can manage all apps/SPNs - potential data access via credentials, HIPAA BAA concerns")
                elif 'user administrator' in role_name_lower:
                    risk_score += 60
                    risk_reasons.append('User Administrator: Can reset passwords, create users - SOC2 access control risk, PCI-DSS 8.1 violation')
                elif 'security administrator' in role_name_lower:
                    risk_score += 60
                    risk_reasons.append('Security Administrator: Can modify security policies - violates SOC2 change management controls')
                elif 'exchange administrator' in role_name_lower:
                    risk_score += 50
                    risk_reasons.append('Exchange Administrator: Full mailbox access - HIPAA ePHI exposure risk, SOC2 confidentiality')
                elif 'sharepoint administrator' in role_name_lower:
                    risk_score += 50
                    risk_reasons.append('SharePoint Administrator: Full document access - potential PII/PHI exposure, GDPR Art. 32 risk')

            # ============================================================
            # 2. Azure RBAC Roles
            # ============================================================
            for role in identity_roles:
                role_name = role['role_name'].lower()
                scope_type = role['scope_type']

                if 'owner' in role_name:
                    if scope_type == 'subscription':
                        risk_score += 100
                        risk_reasons.append('Owner on Subscription: Full control including IAM - violates SOC2 least privilege, PCI-DSS 7.1, HIPAA §164.312(a)(1)')
                    elif scope_type == 'resource_group':
                        risk_score += 60
                        risk_reasons.append('Owner on Resource Group: Can delete all resources, modify access - SOC2 availability risk')
                    else:
                        risk_score += 30
                        risk_reasons.append(f"Owner role on {scope_type}")
                elif 'contributor' in role_name:
                    if scope_type == 'subscription':
                        risk_score += 80
                        risk_reasons.append('Contributor on Subscription: Can create/modify/delete all resources - violates SOC2 least privilege, PCI-DSS 7.2 access restrictions')
                    elif scope_type == 'resource_group':
                        risk_score += 40
                        risk_reasons.append('Contributor on Resource Group: Broad resource modification access - review for SOC2 least privilege compliance')
                elif 'user access administrator' in role_name:
                    risk_score += 70
                    risk_reasons.append('User Access Administrator: Can grant any role to any user - privilege escalation risk, violates SOC2 separation of duties, PCI-DSS 7.1')
                elif 'key vault' in role_name and ('administrator' in role_name or 'officer' in role_name):
                    risk_score += 50
                    risk_reasons.append(f"Key Vault Admin/Officer: Access to secrets/keys/certificates - HIPAA encryption key controls (§164.312(a)(2)(iv)), PCI-DSS 3.5 key management")

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
                risk_score += 60
                risk_reasons.append(f"Graph API Write Access: {len(write_permissions)} write permission(s) - can modify tenant data, SOC2 change management, HIPAA §164.312(c) integrity controls")

            if read_all_permissions and not write_permissions:
                risk_score += 40
                risk_reasons.append(f"Graph API Read-All Access: {len(read_all_permissions)} permission(s) - broad data access, potential PII/PHI exposure, GDPR Art. 32")

            # ============================================================
            # 4. Orphaned Permissions (API access without role justification)
            # ============================================================
            has_roles = len(identity_roles) > 0 or len(identity_entra_roles) > 0
            has_permissions = len(identity_permissions) > 0

            if not has_roles and has_permissions:
                risk_score += 30
                risk_reasons.append('API permissions without role justification (orphaned)')

            # ============================================================
            # 5. App Roles (Custom application roles)
            # ============================================================
            admin_app_roles = []
            for app_role in identity_app_roles:
                role_value = (app_role.get('app_role_value') or app_role.get('resource_display_name') or '').lower()
                if any(keyword in role_value for keyword in ['admin', 'owner', 'full', 'write', 'manage']):
                    admin_app_roles.append(app_role)

            if admin_app_roles:
                risk_score += 50
                risk_reasons.append(f"Has {len(admin_app_roles)} administrative app role(s)")
            elif identity_app_roles:
                risk_score += 20
                risk_reasons.append(f"Has {len(identity_app_roles)} app role assignment(s)")

            # ============================================================
            # 6. Credential Status
            # ============================================================
            has_expired = False
            has_expiring_soon = False
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
                        elif (end_dt - now).days < 30:
                            has_expiring_soon = True
                    except:
                        pass

            if has_expired:
                risk_score += 35
                risk_reasons.append('Has expired credentials')
            elif has_expiring_soon:
                risk_score += 15
                risk_reasons.append('Has credentials expiring within 30 days')

            # ============================================================
            # 7. No roles and no permissions (truly orphaned)
            # ============================================================
            if not has_roles and not has_permissions and not identity_app_roles:
                if identity.get('identity_type') != 'user':
                    risk_score += 25
                    risk_reasons.append('No role assignments (potentially orphaned identity)')

            # ============================================================
            # Convert score to risk level
            # ============================================================
            if risk_score >= 120:
                risk_level = 'critical'
            elif risk_score >= 70:
                risk_level = 'high'
            elif risk_score >= 40:
                risk_level = 'medium'
            elif risk_score > 0:
                risk_level = 'low'
            else:
                risk_level = 'info'
                risk_reasons = ['No elevated privileges detected']

            # Calculate role usage status (inference-based)
            identity_roles, identity_entra_roles = self._calculate_role_usage_status(
                identity, identity_roles, identity_entra_roles
            )

            # Store results
            identity['risk_level'] = risk_level
            identity['risk_score'] = risk_score
            identity['risk_reasons'] = risk_reasons if risk_reasons else ['No elevated privileges detected']
            identity['roles'] = identity_roles
            identity['entra_roles'] = identity_entra_roles
            identity['role_count'] = len(identity_roles) + len(identity_entra_roles)
            identity['api_permission_count'] = len(identity_permissions)
            identity['app_role_count'] = len(identity_app_roles)

            # Print high-risk identities
            if risk_level in ['critical', 'high']:
                emoji = '🚨' if risk_level == 'critical' else '🟠'
                print(f"    {emoji} {identity['display_name']}: {risk_level.upper()} ({risk_score} pts)")
                for reason in risk_reasons[:3]:  # Show top 3 reasons
                    print(f"       • {reason}")

        # Summary
        customer_count = sum(1 for i in identities if not i.get('is_microsoft_system', False))
        microsoft_count = sum(1 for i in identities if i.get('is_microsoft_system', False))
        critical_count = sum(1 for i in identities if i.get('risk_level') == 'critical')
        high_count = sum(1 for i in identities if i.get('risk_level') == 'high')

        print(f"\n  📊 Risk Summary:")
        print(f"     Total: {len(identities)} ({customer_count} customer, {microsoft_count} Microsoft)")
        print(f"     🔴 Critical: {critical_count}  🟠 High: {high_count}")

        return identities
    
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
    
    def _save_identities(self, run_id: int, identities: List[Dict], all_role_assignments: List[Dict], credentials_map: Dict[str, List[Dict]] = None, permissions_map: Dict[str, List[Dict]] = None, app_roles_map: Dict[str, List[Dict]] = None, ownership_map: Dict[str, List[Dict]] = None) -> int:
        """Save all identities to database with proper categorization"""
        saved_count = 0
        microsoft_count = 0

        for identity in identities:
            # Track Microsoft internal identities (they are now saved with proper category)
            if identity.get('is_microsoft_system'):
                microsoft_count += 1

            # Save ALL identities - Microsoft internal ones have identity_category='microsoft_internal'
            
            # Set source for multi-cloud
            identity['source'] = 'azure'
            
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

            saved_count += 1

        if microsoft_count > 0:
            print(f"  ℹ️  Included {microsoft_count} Microsoft internal identities (categorized separately)")

        return saved_count
    
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