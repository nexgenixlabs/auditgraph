"""Add check_credentials call in run_discovery method"""

with open('app/engines/discovery/azure_discovery.py', 'r') as f:
    content = f.read()

# Find the section after risk calculation and before summary
old_section = """            if identity.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                print(f"    🚨 {identity.display_name}: {identity.risk_level.value.upper()}")
                for reason in identity.risk_reasons:
                    print(f"       - {reason}")
        
        # Print summary"""

new_section = """            if identity.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                print(f"    🚨 {identity.display_name}: {identity.risk_level.value.upper()}")
                for reason in identity.risk_reasons:
                    print(f"       - {reason}")
        
        # Check credential expiration (after risk calculation)
        self.check_credentials(all_identities)
        
        # Print summary"""

content = content.replace(old_section, new_section)

with open('app/engines/discovery/azure_discovery.py', 'w') as f:
    f.write(content)

print("✓ Added check_credentials call in run_discovery method")
