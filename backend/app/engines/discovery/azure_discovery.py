"""
Azure Discovery Engine
Discovers all identities (service principals, managed identities) and their permissions
"""
import os
from datetime import datetime
from typing import List, Dict, Optional
from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.resource import SubscriptionClient
import requests

from .models import (
    Identity, 
    IdentityType, 
    RoleAssignment, 
    DiscoveryResult,
    RiskLevel
)


class AzureDiscoveryEngine:
    """
    Discovers identities and permissions across Azure subscriptions
    """
    
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        subscription_id: Optional[str] = None
    ):
        """
        Initialize the discovery engine with Azure credentials
        
        Args:
            tenant_id: Azure AD Tenant ID
            client_id: Service Principal Client ID
            client_secret: Service Principal Secret
            subscription_id: Azure Subscription ID
        """
        # Get credentials from parameters or environment variables
        self.tenant_id = tenant_id or os.getenv('AZURE_TENANT_ID')
        self.client_id = client_id or os.getenv('AZURE_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('AZURE_CLIENT_SECRET')
        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        
        # Validate credentials
        if not all([self.tenant_id, self.client_id, self.client_secret, self.subscription_id]):
            raise ValueError(
                "Missing Azure credentials. Please provide tenant_id, client_id, "
                "client_secret, and subscription_id or set environment variables."
            )
        
        # Create credential
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
        
        # Initialize Azure clients
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
            return {
                'id': sub.subscription_id,
                'name': sub.display_name,
                'state': sub.state
            }
        except Exception as e:
            print(f"✗ Error getting subscription info: {str(e)}")
            return {
                'id': self.subscription_id,
                'name': 'Unknown',
                'state': 'Unknown'
            }
    
    def discover_service_principals(self) -> List[Identity]:
        """
        Discover all service principals using Microsoft Graph API
        """
        print("\n📋 Discovering Service Principals...")
        
        identities = []
        
        try:
            # Get access token for Microsoft Graph
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            # Query service principals
            url = "https://graph.microsoft.com/v1.0/servicePrincipals"
            params = {
                '$select': 'id,appId,displayName,createdDateTime',
                '$top': 999
            }
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                spns = data.get('value', [])
                
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
                    print(f"    ✓ {identity.display_name} ({identity.app_id})")
            else:
                print(f"  ✗ Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"  ✗ Error discovering service principals: {str(e)}")
        
        return identities
    
    def discover_managed_identities(self) -> List[Identity]:
        """
        Discover all managed identities in the subscription
        """
        print("\n🔐 Discovering Managed Identities...")
        
        identities = []
        
        try:
            # Get user-assigned managed identities
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
            print(f"  ✗ Error discovering managed identities: {str(e)}")
        
        # Note: System-assigned managed identities are discovered through resources
        # We'll add that in a future enhancement
        
        return identities
    
    def discover_role_assignments(self, identities: List[Identity]) -> None:
        """
        Discover all RBAC role assignments for the identities
        """
        print("\n🎯 Discovering Role Assignments...")
        
        try:
            # Get all role assignments in the subscription
            assignments = list(self.auth_client.role_assignments.list_for_subscription())
            
            print(f"  Found {len(assignments)} role assignments")
            
            # Create a map of principal_id to identity
            identity_map = {
                identity.object_id: identity 
                for identity in identities 
                if identity.object_id
            }
            
            # Process each assignment
            for assignment in assignments:
                principal_id = assignment.principal_id
                
                if principal_id in identity_map:
                    # Get role definition
                    try:
                        role_def = self.auth_client.role_definitions.get_by_id(
                            assignment.role_definition_id
                        )
                        role_name = role_def.role_name
                    except:
                        role_name = "Unknown"
                    
                    # Determine scope type
                    scope = assignment.scope
                    if '/subscriptions/' in scope and scope.count('/') == 2:
                        scope_type = 'subscription'
                    elif '/resourceGroups/' in scope:
                        scope_type = 'resource_group'
                    else:
                        scope_type = 'resource'
                    
                    # Create role assignment
                    role = RoleAssignment(
                        role_name=role_name,
                        scope=scope,
                        scope_type=scope_type,
                        principal_id=principal_id,
                        principal_type=assignment.principal_type,
                        assignment_id=assignment.id,
                        created_on=assignment.created_on
                    )
                    
                    # Add to identity
                    identity_map[principal_id].add_role_assignment(role)
                    
                    print(f"    ✓ {identity_map[principal_id].display_name}: {role_name} on {scope_type}")
                    
        except Exception as e:
            print(f"  ✗ Error discovering role assignments: {str(e)}")
    
    def run_discovery(self) -> DiscoveryResult:
        """
        Run complete discovery process
        
        Returns:
            DiscoveryResult with all discovered identities
        """
        print("\n" + "="*60)
        print("🔍 AuditGraph Discovery Engine")
        print("="*60)
        
        # Get subscription info
        sub_info = self.get_subscription_info()
        
        # Create result object
        result = DiscoveryResult(
            subscription_id=sub_info['id'],
            subscription_name=sub_info['name'],
            discovered_at=datetime.utcnow()
        )
        
        print(f"\nTarget: {sub_info['name']} ({sub_info['id']})")
        print(f"Started: {result.discovered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Discover identities
        all_identities = []
        
        # 1. Discover service principals
        spns = self.discover_service_principals()
        all_identities.extend(spns)
        
        # 2. Discover managed identities
        mis = self.discover_managed_identities()
        all_identities.extend(mis)
        
        # 3. Discover role assignments
        self.discover_role_assignments(all_identities)
        
        # 4. Calculate risk for each identity
        print("\n⚠️  Calculating Risk Levels...")
        for identity in all_identities:
            identity.calculate_risk()
            result.add_identity(identity)
            
            if identity.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                print(f"    🚨 {identity.display_name}: {identity.risk_level.value.upper()}")
                for reason in identity.risk_reasons:
                    print(f"       - {reason}")
        
        # Print summary
        print("\n" + "="*60)
        print("📊 Discovery Summary")
        print("="*60)
        summary = result.get_summary()
        stats = summary['statistics']
        print(f"Total Identities: {stats['total_identities']}")
        print(f"  Service Principals: {stats['service_principals']}")
        print(f"    - Microsoft System: {stats.get('microsoft_system_spns', 0)} (filtered from risk calc)")
        print(f"    - Custom/Third-party: {stats.get('custom_spns', 0)}")
        print(f"  Managed Identities: {stats['managed_identities']}")
        print(f"\nRisk Assessment:")
        print(f"  🔴 Critical: {stats['critical_risks']}")
        print(f"  🟠 High: {stats['high_risks']}")
        print(f"  🟡 Medium: {stats['medium_risks']} (actionable findings only)")
        print("="*60 + "\n")
        
        return result
    
    @staticmethod
    def _parse_datetime(dt_string: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string"""
        if not dt_string:
            return None
        try:
            return datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        except:
            return None


def main():
    """
    Main function to run discovery from command line
    """
    # Initialize engine (uses environment variables)
    engine = AzureDiscoveryEngine()
    
    # Run discovery
    result = engine.run_discovery()
    
    # Export results to JSON
    import json
    output_file = f"discovery_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)
    
    print(f"✓ Results saved to: {output_file}")


if __name__ == '__main__':
    main()