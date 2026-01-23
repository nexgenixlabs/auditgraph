"""Update credential fields in models.py"""

with open('app/engines/discovery/models.py', 'r') as f:
    content = f.read()

# Replace the old field names with new ones
old_fields = """    # For service principals
    credential_expires: Optional[datetime] = None
    has_expired_credentials: bool = False"""

new_fields = """    # For service principals
    credential_expiration: Optional[datetime] = None
    credential_status: str = "unknown"  # unknown, good, warning, critical, expired"""

content = content.replace(old_fields, new_fields)

with open('app/engines/discovery/models.py', 'w') as f:
    f.write(content)

print("✓ Updated credential fields in models.py")
print("  - credential_expires → credential_expiration")
print("  - has_expired_credentials → credential_status")
