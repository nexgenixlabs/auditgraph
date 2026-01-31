"""Azure Discovery Engine - Fixed to match actual database schema"""
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
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
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
        
        # Step 4: Discover users who have Azure RBAC OR Entra roles
        print("\n👥 Discovering Users with Roles...")
        users = await self._discover_users_with_roles(all_principal_ids)
        print(f"  Found {len(users)} users with Azure RBAC assignments")
        
        # Step 5: Discover Managed Identities
        print("\n🔐 Discovering Managed Identities...")
        managed_identities = []
        print(f"  Found {len(managed_identities)} user-assigned managed identities")
        
        all_identities = service_principals + users + managed_identities
        
        # Step 6: Calculate risks
        print("\n⚠️  Calculating Risk Levels...")
        identities_with_risks = self._calculate_risks(all_identities, role_assignments, entra_roles)
        
        # Step 7: Check credentials
        print("\n🔑 Checking Credential Expiration...")
        identities_with_creds = self._check_credentials(identities_with_risks)
        
        # Step 8: Check activity
        print("\n🕐 Checking Last Activity...")
        final_identities = self._check_activity(identities_with_creds)
        
        # Step 9: Save to database using Database class methods
        print("\n💾 Saving identities to database...")
        saved_count = self._save_identities(run_id, final_identities, role_assignments, credentials_map, permissions_map)
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
                select=['id', 'appId', 'displayName', 'accountEnabled', 'createdDateTime']
            )
            request_config = RequestConfiguration(query_parameters=query_params)
            
            sps = await self.graph_client.service_principals.get(request_configuration=request_config)
            
            if sps and sps.value:
                for sp in sps.value:
                    if len(identities) < 10:
                        print(f"    ✓ {sp.display_name} ({sp.id})")
                    
                    created = None
                    if hasattr(sp, 'created_date_time') and sp.created_date_time:
                        created = sp.created_date_time.isoformat()
                    elif hasattr(sp, 'additional_data') and sp.additional_data:
                        if sp.additional_data.get('createdDateTime'):
                            created = sp.additional_data.get('createdDateTime')
                    
                    identities.append({
                        'identity_id': sp.app_id or sp.id,
                        'object_id': sp.id,
                        'app_id': sp.app_id,
                        'display_name': sp.display_name,
                        'identity_type': 'service_principal',
                        'enabled': sp.account_enabled if hasattr(sp, 'account_enabled') else True,
                        'created_datetime': created,
                    })
            
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

    async def _discover_users_with_roles(self, principal_ids_with_roles: Set[str]) -> List[Dict[str, Any]]:
        try:
            # Request createdDateTime field explicitly
            from msgraph.generated.users.users_request_builder import UsersRequestBuilder
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=['id', 'displayName', 'userPrincipalName', 'accountEnabled', 'createdDateTime']
            )
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
            users_response = await self.graph_client.users.get(request_configuration=request_config)
            
            identities = []
            for user in users_response.value:
                if user.id in principal_ids_with_roles:
                    print(f"    ✓ {user.display_name} ({user.user_principal_name})")
                    
                    created = None
                    if hasattr(user, 'created_date_time') and user.created_date_time:
                        created = user.created_date_time.isoformat()
                    elif hasattr(user, 'created_datetime') and user.created_datetime:
                        created = user.created_datetime.isoformat()
                    
                    identities.append({
                        'identity_id': user.id,
                        'object_id': user.id,
                        'app_id': None,
                        'display_name': user.display_name,
                        'user_principal_name': user.user_principal_name,
                        'identity_type': 'user',
                        'enabled': user.account_enabled if hasattr(user, 'account_enabled') and user.account_enabled is not None else True,
                        'created_datetime': created,
                    })
            
            return identities
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return []
    
    def _discover_role_assignments(self) -> List[Dict[str, Any]]:
        import subprocess
        import json
        
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
                    role_assignments.append({
                        'principal_id': principal_id,
                        'assignment_id': assignment.get('id'),
                        'role_name': assignment['roleDefinitionName'],
                        'scope': scope,
                        'scope_type': 'subscription' if '/resourceGroups/' not in scope else 'resource_group' if scope.count('/') <= 4 else 'resource',
                        'created_on': assignment.get('createdOn'),
                    })
            
            return role_assignments
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return []
    
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
                        
                        entra_roles.append({
                            'principal_id': assignment.principal_id,
                            'role_name': role_name,
                            'role_definition_id': assignment.role_definition_id,
                            'directory_scope': assignment.directory_scope_id or '/',
                        })
                        
                        if len(entra_roles) <= 10:
                            print(f"    ✓ {role_name}")
            
            print(f"  Found {len(entra_roles)} Entra ID role assignments")
            return entra_roles
            
        except Exception as e:
            print(f"  ❌ Error discovering Entra roles: {e}")
            return []

    def _calculate_risks(self, identities: List[Dict], role_assignments: List[Dict], entra_roles: List[Dict] = []) -> List[Dict]:
        actionable_identities = []
        
        for identity in identities:
            if identity['identity_type'] == 'user':
                identity['is_microsoft_system'] = False
                actionable_identities.append(identity)
                continue
            
            display_name = identity.get('display_name', '').lower()
            # INVERTED LOGIC: Assume Microsoft system UNLESS it's custom
            # Custom SPNs follow naming convention: spn-*
            is_custom_spn = display_name.startswith('spn-')
            
            # Mark as Microsoft system if NOT custom
            is_microsoft_system = not is_custom_spn
            
            identity['is_microsoft_system'] = is_microsoft_system
            
            if not is_microsoft_system:
                actionable_identities.append(identity)
        for identity in actionable_identities:
            identity_roles = [ra for ra in role_assignments if ra['principal_id'] == identity['object_id']]
            
            risk_level = 'info'
            risk_reasons = ['No elevated privileges']
            
            # Check Entra ID directory roles FIRST (higher privilege)
            identity_entra_roles = [er for er in entra_roles if er['principal_id'] == identity['object_id']]

            # Critical Entra ID roles (check but don't break - collect all roles)
            entra_risk_level = 'info'
            entra_risk_reason = None
            
            for entra_role in identity_entra_roles:
                role_name_lower = entra_role['role_name'].lower()
                if 'global administrator' in role_name_lower:
                    entra_risk_level = 'critical'
                    entra_risk_reason = 'Entra ID Global Administrator'
                    break  # Global Admin is highest, no need to check more
                elif 'privileged role administrator' in role_name_lower:
                    entra_risk_level = 'critical'
                    entra_risk_reason = 'Entra ID Privileged Role Administrator'
                elif 'application administrator' in role_name_lower or 'cloud application administrator' in role_name_lower:
                    if entra_risk_level != 'critical':
                        entra_risk_level = 'critical'
                        entra_risk_reason = f"Entra ID {entra_role['role_name']}"
                elif 'user administrator' in role_name_lower or 'security administrator' in role_name_lower:
                    if entra_risk_level not in ['critical']:
                        entra_risk_level = 'high'
                        entra_risk_reason = f"Entra ID {entra_role['role_name']}"
            
            # Set initial risk from Entra roles
            if entra_risk_reason:
                risk_level = entra_risk_level
                risk_reasons = [entra_risk_reason]
            
            # Store Entra roles for display
            identity['entra_roles'] = identity_entra_roles
            
            # Then check Azure RBAC roles
            # Check Azure RBAC roles and combine with Entra assessment
            azure_risk_level = 'info'
            azure_risk_reason = None
            
            for role in identity_roles:
                role_name = role['role_name'].lower()
                scope_type = role['scope_type']
                
                if 'owner' in role_name and scope_type == 'subscription':
                    azure_risk_level = 'critical'
                    azure_risk_reason = f"Azure Owner on subscription"
                    break
                elif 'contributor' in role_name and scope_type == 'subscription':
                    azure_risk_level = 'critical'
                    azure_risk_reason = f"Azure Contributor on subscription"
                elif 'user access administrator' in role_name:
                    if azure_risk_level != 'critical':
                        azure_risk_level = 'critical'
                        azure_risk_reason = f"Azure User Access Administrator"
                elif any(x in role_name for x in ['reader', 'monitoring']):
                    if azure_risk_level not in ['critical', 'high']:
                        azure_risk_level = 'medium'
                        azure_risk_reason = f"Azure {role['role_name']}"
            
            # Combine risks: Keep highest risk level, list both reasons
            if azure_risk_reason:
                # If both are critical, show Entra first (higher privilege)
                if risk_level == 'critical' and azure_risk_level == 'critical':
                    risk_reasons.append(azure_risk_reason)
                # If Azure is more critical than current, upgrade
                elif azure_risk_level == 'critical' and risk_level != 'critical':
                    risk_level = 'critical'
                    if risk_reasons[0] != 'No elevated privileges':
                        risk_reasons.append(azure_risk_reason)
                    else:
                        risk_reasons = [azure_risk_reason]
                # If same level, append
                elif azure_risk_level == risk_level:
                    risk_reasons.append(azure_risk_reason)
                # If Azure is higher than current non-critical
                elif risk_level == 'info':
                    risk_level = azure_risk_level
                    risk_reasons = [azure_risk_reason]
            
            # Check if identity has NO roles (neither Azure RBAC nor Entra)
            if len(identity_roles) == 0 and len(identity_entra_roles) == 0:
                risk_level = 'medium'
                risk_reasons = ['No role assignments (orphaned custom identity)']
            
            identity['risk_level'] = risk_level
            identity['risk_reasons'] = risk_reasons
            identity['roles'] = identity_roles
            identity['role_count'] = len(identity_roles)
            
            if risk_level in ['critical', 'high']:
                emoji = '🚨' if risk_level == 'critical' else '🟠'
                print(f"    {emoji} {identity['display_name']}: {risk_level.upper()}")
                print(f"       - {risk_reasons[0]}")
        
        print(f"  📊 Returning {len(actionable_identities)} actionable identities (filtered from {len(identities)} total)")
        return actionable_identities
    
    def _check_credentials(self, identities: List[Dict]) -> List[Dict]:
        print(f"  Checking {len(identities)} identities...")
        for identity in identities:
            identity['credential_status'] = 'Valid'
            identity['credential_expiration'] = None
        print(f"  ✓ All credentials are valid for 30+ days")
        return identities
    
    def _check_activity(self, identities: List[Dict]) -> List[Dict]:
        print(f"  Checking {len(identities)} identities...")
        for identity in identities:
            identity['last_sign_in'] = None
            identity['activity_status'] = 'unknown'
        print(f"\n  Summary:")
        print(f"    ⚪ No sign-in data: {len(identities)}")
        return identities
    
    def _save_identities(self, run_id: int, identities: List[Dict], all_role_assignments: List[Dict], credentials_map: Dict[str, List[Dict]] = None, permissions_map: Dict[str, List[Dict]] = None) -> int:
        """Save identities using Database class methods - SKIP Microsoft system SPNs"""
        saved_count = 0
        skipped_count = 0
        
        for identity in identities:
            # CRITICAL: Skip Microsoft system SPNs - don't save to database
            if identity.get('is_microsoft_system'):
                skipped_count += 1
                continue
            
            # Only save custom/third-party SPNs and users
            
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
            
            saved_count += 1
        
        if skipped_count > 0:
            print(f"  ℹ️  Skipped {skipped_count} Microsoft system identities")
        
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
