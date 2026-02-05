#!/usr/bin/env python3
"""
Update handlers.py to return app_roles in identity details
"""

with open('handlers.py', 'r') as f:
    content = f.read()

# Check if already added
if 'app_roles = db.get_app_roles' in content:
    print("⚠️  App roles already in API handler!")
    exit(0)

# Find where to add (after get_graph_permissions call)
old_code = '''    # Get graph API permissions
    graph_permissions = db.get_graph_permissions(identity_db_id)'''

new_code = '''    # Get graph API permissions
    graph_permissions = db.get_graph_permissions(identity_db_id)
    
    # Get custom app roles
    app_roles = db.get_app_roles(identity_db_id)'''

if old_code in content:
    content = content.replace(old_code, new_code)
    print("✅ Added get_app_roles call to handler")
else:
    print("⚠️  Could not find exact pattern, trying line-by-line...")
    # Try to find just the get_graph_permissions line
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'graph_permissions = db.get_graph_permissions' in line:
            # Insert after this line
            lines.insert(i + 1, '    ')
            lines.insert(i + 2, '    # Get custom app roles')
            lines.insert(i + 3, '    app_roles = db.get_app_roles(identity_db_id)')
            content = '\n'.join(lines)
            print("✅ Added get_app_roles call to handler (line insert method)")
            break

# Add app_roles to response
if "'graph_permissions': graph_permissions," in content:
    old_return = "'graph_permissions': graph_permissions,"
    new_return = "'graph_permissions': graph_permissions,\n        'app_roles': app_roles,"
    
    content = content.replace(old_return, new_return)
    print("✅ Added app_roles to API response")
elif "'graph_permissions': graph_permissions" in content:
    # Without trailing comma
    old_return = "'graph_permissions': graph_permissions"
    new_return = "'graph_permissions': graph_permissions,\n        'app_roles': app_roles"
    
    content = content.replace(old_return, new_return)
    print("✅ Added app_roles to API response (no comma version)")
else:
    print("⚠️  Could not find response dict to update")

# Write back
with open('handlers.py', 'w') as f:
    f.write(content)

print("\n🎉 API handler updated to return app_roles!")
