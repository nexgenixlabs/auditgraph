"""Fix old field name references in models.py"""

with open('app/engines/discovery/models.py', 'r') as f:
    content = f.read()

# Replace the old field reference in calculate_risk method
content = content.replace(
    "        if self.has_expired_credentials:",
    "        if self.credential_status == 'expired':"
)

# Replace the old field in the to_dict method
content = content.replace(
    "            'has_expired_credentials': self.has_expired_credentials,",
    "            'credential_status': self.credential_status,"
)

# Also update credential_expires to credential_expiration in to_dict if it exists
content = content.replace(
    "            'credential_expires': self.credential_expires,",
    "            'credential_expiration': self.credential_expiration.isoformat() if self.credential_expiration else None,"
)

with open('app/engines/discovery/models.py', 'w') as f:
    f.write(content)

print("✓ Fixed old field references in models.py")
print("  - has_expired_credentials → credential_status")
print("  - Updated to_dict method")
