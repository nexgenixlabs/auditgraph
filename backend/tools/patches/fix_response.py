#!/usr/bin/env python3
"""
Add app_roles to the return jsonify response
"""

with open('handlers.py', 'r') as f:
    content = f.read()

# Find and update the response dict
old_response = '''    return jsonify(
        {
            "run_id": latest_run,
            "identity": identity,
            "roles": roles,
            "graph_permissions": graph_permissions,
        }
    )'''

new_response = '''    return jsonify(
        {
            "run_id": latest_run,
            "identity": identity,
            "roles": roles,
            "graph_permissions": graph_permissions,
            "app_roles": app_roles,
        }
    )'''

if old_response in content:
    content = content.replace(old_response, new_response)
    
    with open('handlers.py', 'w') as f:
        f.write(content)
    
    print("✅ Added app_roles to API response dict!")
else:
    print("❌ Could not find exact response dict pattern")
    exit(1)
