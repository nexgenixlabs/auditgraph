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
from .credential_checker import CredentialChecker
from .activity_tracker import ActivityTracker
from app.database import Database


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
        
        # Initialize credential checker
        self.credential_checker = CredentialChecker(self.credential)
        
        # Initialize activity tracker
        self.activity_tracker = ActivityTracker(self.credential)
        
        # Initialize database
        self.db = Database()
        
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
    
    def check_credentials(self, identities: List[Identity]) -> None:
        """
        Check credential expiration for service principals
        """
        print("\n🔑 Checking Credential Expiration...")
        
        # Only check custom SPNs (not Microsoft system SPNs)
        custom_spns = [
            i for i in identities 
            if i.identity_type == IdentityType.SERVICE_PRINCIPAL 
            and not i.is_microsoft_system
        ]
        
        print(f"  Checking {len(custom_spns)} custom service principals...")
        
        expired_count = 0
        critical_count = 0
        warning_count = 0
        
        for identity in custom_spns:
            # Get the application ID from the service principal
            app_id = identity.app_id  # This is the appId
            
            # Check expiration
            expiration_date = self.credential_checker.check_credential_expiration(app_id)
            status = self.credential_checker.get_expiration_status(expiration_date)
            
            # Store in identity object
            identity.credential_expiration = expiration_date
            identity.credential_status = status
            
            # Print alerts for problematic credentials
            if status == "expired":
                print(f"  ❌ {identity.display_name}: EXPIRED")
                expired_count += 1
            elif status == "critical":
                days = (expiration_date - datetime.utcnow()).days
                print(f"  🔴 {identity.display_name}: Expires in {days} days")
                critical_count += 1
            elif status == "warning":
                days = (expiration_date - datetime.utcnow()).days
                print(f"  🟡 {identity.display_name}: Expires in {days} days")
                warning_count += 1
        
        # Summary
        if expired_count == 0 and critical_count == 0 and warning_count == 0:
            print(f"  ✓ All credentials are valid for 30+ days")
        else:
            print(f"\n  Summary:")
            if expired_count > 0:
                print(f"    ❌ Expired: {expired_count}")
            if critical_count > 0:
                print(f"    🔴 Critical (< 7 days): {critical_count}")
            if warning_count > 0:
                print(f"    🟡 Warning (< 30 days): {warning_count}")
    
    def check_activity(self, identities: List[Identity]) -> None:
        """
        Check last activity for service principals
        """
        print("\n🕐 Checking Last Activity...")
        
        # Only check custom SPNs (not Microsoft system SPNs)
        custom_spns = [
            i for i in identities 
            if i.identity_type == IdentityType.SERVICE_PRINCIPAL 
            and not i.is_microsoft_system
        ]
        
        print(f"  Checking {len(custom_spns)} custom service principals...")
        
        never_used_count = 0
        stale_count = 0
        inactive_count = 0
        active_count = 0
        unknown_count = 0
        
        for identity in custom_spns:
            # Get last sign-in
            last_sign_in = self.activity_tracker.get_last_sign_in(identity.app_id)
            status = self.activity_tracker.get_activity_status(last_sign_in, identity.created_datetime)
            
            # Store in identity object
            identity.last_sign_in = last_sign_in
            identity.activity_status = status
            
            # Print alerts for problematic activity
            if status == "never_used":
                days_old = (datetime.utcnow() - identity.created_datetime).days if identity.created_datetime else 0
                print(f"  🔴 {identity.display_name}: Never used (created {days_old} days ago)")
                never_used_count += 1
            elif status == "stale":
                days_ago = (datetime.utcnow() - last_sign_in).days
                print(f"  🟠 {identity.display_name}: Stale (last used {days_ago} days ago)")
                stale_count += 1
            elif status == "inactive":
                days_ago = (datetime.utcnow() - last_sign_in).days
                print(f"  🟡 {identity.display_name}: Inactive (last used {days_ago} days ago)")
                inactive_count += 1
            elif status == "active":
                if last_sign_in:
                    hours_ago = (datetime.utcnow() - last_sign_in).total_seconds() / 3600
                    if hours_ago < 24:
                        print(f"  🟢 {identity.display_name}: Active (last used {int(hours_ago)} hours ago)")
                    else:
                        days_ago = int(hours_ago / 24)
                        print(f"  🟢 {identity.display_name}: Active (last used {days_ago} days ago)")
                active_count += 1
            elif status == "unknown":
                unknown_count += 1
        
        # Summary
        print(f"\n  Summary:")
        if never_used_count > 0:
            print(f"    🔴 Never used: {never_used_count}")
        if stale_count > 0:
            print(f"    🟠 Stale (90+ days): {stale_count}")
        if inactive_count > 0:
            print(f"    🟡 Inactive (30-90 days): {inactive_count}")
        if active_count > 0:
            print(f"    🟢 Active (< 30 days): {active_count}")
        if unknown_count > 0:
            print(f"    ⚪ No sign-in data (90+ days or never used): {unknown_count}")
    
    def save_to_database(self, result) -> int:
        """
        Save discovery results to PostgreSQL database
        
        Returns:
            discovery_run_id
        """
        print("\n💾 Saving to database...")
        
        # Create discovery run
        run_id = self.db.create_discovery_run(
            subscription_id=self.subscription_id,
            subscription_name=result.subscription_name
        )
        print(f"  ✓ Discovery run created (ID: {run_id})")
        
        # Count risk levels
        risk_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Save each identity
        saved_count = 0
        for identity in result.identities:
            # Only save non-Microsoft system identities (the actionable ones)
            if identity.is_microsoft_system:
                continue
            
            # Prepare identity data
            identity_data = {
                'identity_id': identity.id,
                'display_name': identity.display_name,
                'identity_type': identity.identity_type.value,
                'app_id': identity.app_id,
                'object_id': identity.object_id,
                'created_datetime': identity.created_datetime,
                'enabled': identity.enabled,
                'is_microsoft_system': identity.is_microsoft_system,
                'risk_level': identity.risk_level.value if identity.risk_level else None,
                'risk_reasons': identity.risk_reasons,
                'credential_expiration': identity.credential_expiration,
                'credential_status': identity.credential_status,
                'last_sign_in': identity.last_sign_in,
                'activity_status': identity.activity_status,
                'tags': identity.tags
            }
            
            # Save identity
            identity_db_id = self.db.save_identity(run_id, identity_data)
            
            # Count risk levels
            if identity.risk_level:
                risk_level = identity.risk_level.value.lower()
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1
            
            # Save role assignments
            for role in identity.role_assignments:
                role_data = {
                    'role_name': role.role_name,
                    'scope': role.scope,
                    'scope_type': role.scope_type,
                    'principal_id': role.principal_id,
                    'assignment_id': role.assignment_id,
                    'created_on': role.created_on
                }
                self.db.save_role_assignment(identity_db_id, role_data)
            
            saved_count += 1
        
        print(f"  ✓ Saved {saved_count} identities")
        print(f"  ✓ Saved {sum(len(i.role_assignments) for i in result.identities if not i.is_microsoft_system)} role assignments")
        
        # Complete the discovery run
        self.db.complete_discovery_run(
            run_id=run_id,
            total_identities=saved_count,
            critical_count=risk_counts['critical'],
            high_count=risk_counts['high'],
            medium_count=risk_counts['medium'],
            low_count=risk_counts['low']
        )
        print(f"  ✓ Discovery run completed")
        
        return run_id
    
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
        
        # Check credential expiration (after risk calculation)
        self.check_credentials(all_identities)
        
        # Check last activity
        self.check_activity(all_identities)
        
        # Save to database
        self.save_to_database(result)
        
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