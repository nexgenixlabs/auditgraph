"""
Azure Discovery Engine
"""
import os
from datetime import datetime
from typing import List, Dict, Optional
from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.resource import SubscriptionClient
import requests

from .models import Identity, IdentityType, RoleAssignment, DiscoveryResult, RiskLevel


class AzureDiscoveryEngine:
    """Discovers identities and permissions across Azure"""
    
    def __init__(self, tenant_id=None, client_id=None, client_secret=None, subscription_id=None):
        self.tenant_id = tenant_id or os.getenv('AZURE_TENANT_ID')
        self.client_id = client_id or os.getenv('AZURE_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('AZURE_CLIENT_SECRET')
        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        
        if not all([self.tenant_id, self.client_id, self.client_secret, self.subscription_id]):
            raise ValueError("Missing Azure credentials")
        
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        
        self.auth_client = AuthorizationManagementClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )
        
        self.msi_client = ManagedServiceIdentityClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )
        
        self.sub_client = SubscriptionClient(credential=self.credential)
        
        print(f"✓ Discovery Engine initialized for subscription: {self.subscription_id}")
    
    def get_subscription_info(self) -> Dict:
        """Get subscription information"""
        try:
            sub = self.sub_client.subscriptions.get(self.subscription_id)
            return {'id': sub.subscription_id, 'name': sub.display_name, 'state': sub.state}
        except Exception as e:
            return {'id': self.subscription_id, 'name': 'Unknown', 'state': 'Unknown'}
    
    def discover_service_principals(self) -> List[Identity]:
        """Discover all service principals"""
        print("\n📋 Discovering Service Principals...")
        identities = []
        
        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {'Authorization': f'Bearer {token.token}', 'Content-Type': 'application/json'}
            url = "https://graph.microsoft.com/v1.0/servicePrincipals"
            params = {'$select': 'id,appId,displayName,createdDateTime', '$top': 999}
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                spns = response.json().get('value', [])
                print(f"  Found {len(spns)} service principals")
                
                for spn in spns:
                    identity = Identity(
                        id=spn.get('id'),
                        display_name=spn.get('displayName', 'Unknown'),
                        identity_type=IdentityType.SERVICE_PRINCIPAL,
                        app_id=spn.get('appId'),
                        object_id=spn.get('id'),
                        created_datetime=self._parse_datetime(spn.get('createdDateTime'))
                    )
                    identities.append(identity)
                    print(f"    ✓ {identity.display_name}")
            else:
                print(f"  ✗ Error: {response.status_code}")
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
        
        return identities
    
    def discover_managed_identities(self) -> List[Identity]:
        """Discover managed identities"""
        print("\n🔐 Discovering Managed Identities...")
        identities = []
        
        try:
            user_identities = list(self.msi_client.user_assigned_identities.list_by_subscription())
            print(f"  Found {len(user_identities)} user-assigned managed identities")
            
            for mi in user_identities:
                identity = Identity(
                    id=mi.id,
                    display_name=mi.name,
                    identity_type=IdentityType.MANAGED_IDENTITY_USER,
                    object_id=mi.principal_id,
                    associated_resource_id=mi.id
                )
                identities.append(identity)
                print(f"    ✓ {identity.display_name}")
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
        
        return identities
    
    def discover_role_assignments(self, identities: List[Identity]) -> None:
        """Discover RBAC role assignments"""
        print("\n🎯 Discovering Role Assignments...")
        
        try:
            assignments = list(self.auth_client.role_assignments.list_for_subscription())
            print(f"  Found {len(assignments)} role assignments")
            
            identity_map = {identity.object_id: identity for identity in identities if identity.object_id}
            
            for assignment in assignments:
                principal_id = assignment.principal_id
                
                if principal_id in identity_map:
                    try:
                        role_def = self.auth_client.role_definitions.get_by_id(assignment.role_definition_id)
                        role_name = role_def.role_name
                    except:
                        role_name = "Unknown"
                    
                    scope = assignment.scope
                    if '/subscriptions/' in scope and scope.count('/') == 2:
                        scope_type = 'subscription'
                    elif '/resourceGroups/' in scope:
                        scope_type = 'resource_group'
                    else:
                        scope_type = 'resource'
                    
                    role = RoleAssignment(
                        role_name=role_name,
                        scope=scope,
                        scope_type=scope_type,
                        principal_id=principal_id,
                        principal_type=assignment.principal_type,
                        assignment_id=assignment.id,
                        created_on=assignment.created_on
                    )
                    
                    identity_map[principal_id].add_role_assignment(role)
                    print(f"    ✓ {identity_map[principal_id].display_name}: {role_name} on {scope_type}")
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
    
    def run_discovery(self) -> DiscoveryResult:
        """Run complete discovery"""
        print("\n" + "="*60)
        print("🔍 AuditGraph Discovery Engine")
        print("="*60)
        
        sub_info = self.get_subscription_info()
        result = DiscoveryResult(
            subscription_id=sub_info['id'],
            subscription_name=sub_info['name'],
            discovered_at=datetime.utcnow()
        )
        
        print(f"\nTarget: {sub_info['name']} ({sub_info['id']})")
        
        all_identities = []
        all_identities.extend(self.discover_service_principals())
        all_identities.extend(self.discover_managed_identities())
        self.discover_role_assignments(all_identities)
        
        print("\n⚠️  Calculating Risk Levels...")
        for identity in all_identities:
            identity.calculate_risk()
            result.add_identity(identity)
            
            if identity.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                print(f"    🚨 {identity.display_name}: {identity.risk_level.value.upper()}")
                for reason in identity.risk_reasons:
                    print(f"       - {reason}")
        
        print("\n" + "="*60)
        print("📊 Discovery Summary")
        print("="*60)
        summary = result.get_summary()
        stats = summary['statistics']
        print(f"Total Identities: {stats['total_identities']}")
        print(f"  Service Principals: {stats['service_principals']}")
        print(f"  Managed Identities: {stats['managed_identities']}")
        print(f"\nRisk Assessment:")
        print(f"  🔴 Critical: {stats['critical_risks']}")
        print(f"  🟠 High: {stats['high_risks']}")
        print(f"  🟡 Medium: {stats['medium_risks']}")
        print("="*60 + "\n")
        
        return result
    
    @staticmethod
    def _parse_datetime(dt_string: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime"""
        if not dt_string:
            return None
        try:
            return datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        except:
            return None
