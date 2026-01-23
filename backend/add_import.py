"""Add CredentialChecker import to azure_discovery.py"""

with open('app/engines/discovery/azure_discovery.py', 'r') as f:
    content = f.read()

# Find the models import section and add our import after it
old_import = """from .models import (
    Identity, 
    IdentityType, 
    RoleAssignment, 
    DiscoveryResult,
    RiskLevel
)"""

new_import = """from .models import (
    Identity, 
    IdentityType, 
    RoleAssignment, 
    DiscoveryResult,
    RiskLevel
)
from .credential_checker import CredentialChecker"""

content = content.replace(old_import, new_import)

with open('app/engines/discovery/azure_discovery.py', 'w') as f:
    f.write(content)

print("✓ Added CredentialChecker import to azure_discovery.py")
