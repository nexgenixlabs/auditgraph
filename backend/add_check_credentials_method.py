"""Add check_credentials method to azure_discovery.py"""

with open('app/engines/discovery/azure_discovery.py', 'r') as f:
    lines = f.readlines()

# The method to insert
check_credentials_method = '''    def check_credentials(self, identities: List[Identity]) -> None:
        """
        Check credential expiration for service principals
        """
        print("\\n🔑 Checking Credential Expiration...")
        
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
            print(f"\\n  Summary:")
            if expired_count > 0:
                print(f"    ❌ Expired: {expired_count}")
            if critical_count > 0:
                print(f"    🔴 Critical (< 7 days): {critical_count}")
            if warning_count > 0:
                print(f"    🟡 Warning (< 30 days): {warning_count}")
    
'''

# Find line 244 (run_discovery method) and insert before it
for i, line in enumerate(lines):
    if i == 243:  # Line 244 is index 243 (0-based)
        lines.insert(i, check_credentials_method)
        break

# Write back
with open('app/engines/discovery/azure_discovery.py', 'w') as f:
    f.writelines(lines)

print("✓ Added check_credentials method before run_discovery")
