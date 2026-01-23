"""Add CredentialChecker initialization to __init__ method"""

with open('app/engines/discovery/azure_discovery.py', 'r') as f:
    content = f.read()

# Find where msi_client is initialized and add credential_checker after it
old_section = """        self.msi_client = ManagedServiceIdentityClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )"""

new_section = """        self.msi_client = ManagedServiceIdentityClient(
            credential=self.credential,
            subscription_id=self.subscription_id
        )
        
        # Initialize credential checker
        self.credential_checker = CredentialChecker(self.credential)"""

content = content.replace(old_section, new_section)

with open('app/engines/discovery/azure_discovery.py', 'w') as f:
    f.write(content)

print("✓ Added CredentialChecker initialization in __init__")
