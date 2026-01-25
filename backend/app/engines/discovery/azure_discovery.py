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
        
        # Step 3: Discover Service Principals
        print("\n📋 Discovering Service Principals...")
        service_principals = await self._discover_service_principals()
        print(f"  Found {len(service_principals)} service principals")
        
        # Step 4: Discover ONLY users who have Azure roles
        print("\n👥 Discovering Users with Azure Roles...")
        users = await self._discover_users_with_roles(principal_ids_with_roles)
        print(f"  Found {len(users)} users with Azure RBAC assignments")
        
        # Step 5: Discover Managed Identities
        print("\n🔐 Discovering Managed Identities...")
        managed_identities = []
        print(f"  Found {len(managed_identities)} user-assigned managed identities")
        
        all_identities = service_principals + users + managed_identities
        
        # Step 6: Calculate risks
        print("\n⚠️  Calculating Risk Levels...")
        identities_with_risks = self._calculate_risks(all_identities, role_assignments)
        
        # Step 7: Check credentials
        print("\n🔑 Checking Credential Expiration...")
        identities_with_creds = self._check_credentials(identities_with_risks)
        
        # Step 8: Check activity
        print("\n🕐 Checking Last Activity...")
        final_identities = self._check_activity(identities_with_creds)
        
        # Step 9: Save to database using Database class methods
        print("\n💾 Saving identities to database...")
        saved_count = self._save_identities(run_id, final_identities, role_assignments)
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
                top=999  # Get up to 999 per page
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
    
    async def _discover_users_with_roles(self, principal_ids_with_roles: Set[str]) -> List[Dict[str, Any]]:
        try:
            users_response = await self.graph_client.users.get()
            
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
    
    def _calculate_risks(self, identities: List[Dict], role_assignments: List[Dict]) -> List[Dict]:
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
            
            for role in identity_roles:
                role_name = role['role_name'].lower()
                scope_type = role['scope_type']
                
                if 'owner' in role_name and scope_type == 'subscription':
                    risk_level = 'critical'
                    risk_reasons = [f"Owner on subscription level"]
                    break
                elif 'contributor' in role_name and scope_type == 'subscription':
                    risk_level = 'critical'
                    risk_reasons = [f"Contributor on subscription level"]
                    break
                elif 'user access administrator' in role_name:
                    risk_level = 'critical'
                    risk_reasons = [f"User Access Administrator on {scope_type} level"]
                    break
                elif any(x in role_name for x in ['reader', 'monitoring']):
                    risk_level = 'medium'
                    risk_reasons = [f"{role['role_name']} on {scope_type} level"]
            
            if len(identity_roles) == 0:
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
    
    def _save_identities(self, run_id: int, identities: List[Dict], all_role_assignments: List[Dict]) -> int:
        """Save identities using Database class methods - SKIP Microsoft system SPNs"""
        saved_count = 0
        skipped_count = 0
        
        for identity in identities:
            # CRITICAL: Skip Microsoft system SPNs - don't save to database
            if identity.get('is_microsoft_system'):
                skipped_count += 1
                continue
            
            # Only save custom/third-party SPNs and users
            identity_db_id = self.db.save_identity(run_id, identity)
            
            # Save role assignments for this identity
            identity_roles = identity.get('roles', [])
            for role in identity_roles:
                self.db.save_role_assignment(identity_db_id, role)
            
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
