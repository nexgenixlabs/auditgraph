#!/usr/bin/env python3
"""
Add app roles storage and retrieval functions to database.py
"""

with open('database.py', 'r') as f:
    lines = f.readlines()

# Check if functions already exist
content = ''.join(lines)
if 'def store_app_roles' in content:
    print("⚠️  App roles functions already exist!")
    exit(0)

# Find line 332 (get_graph_permissions) and insert BEFORE it
insert_line = None
for i, line in enumerate(lines):
    if 'def get_graph_permissions(self, identity_db_id: int)' in line:
        insert_line = i
        break

if insert_line is None:
    print("❌ Could not find get_graph_permissions")
    exit(1)

# New functions to insert
new_functions = '''    def store_app_roles(self, identity_db_id: int, app_roles: list):
        """
        Store custom application role assignments for a service principal
        (excludes Microsoft Graph permissions which go to graph_api_permissions)
        
        Args:
            identity_db_id: Database ID of the identity
            app_roles: List of app role assignment dicts from Microsoft Graph
        """
        if not app_roles:
            return
        
        cursor = self.conn.cursor()
        
        for role in app_roles:
            # Calculate risk based on role name/resource
            risk_level = self._calculate_app_role_risk(role)
            
            try:
                cursor.execute("""
                    INSERT INTO sp_app_roles (
                        identity_db_id,
                        app_role_id,
                        resource_id,
                        resource_display_name,
                        principal_display_name,
                        created_date_time,
                        risk_level
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (identity_db_id, app_role_id, resource_id) 
                    DO UPDATE SET
                        resource_display_name = EXCLUDED.resource_display_name,
                        risk_level = EXCLUDED.risk_level,
                        discovered_at = CURRENT_TIMESTAMP
                """, (
                    identity_db_id,
                    role.get('app_role_id'),
                    role.get('resource_id'),
                    role.get('resource_display_name'),
                    role.get('principal_display_name'),
                    role.get('created_date_time'),
                    risk_level
                ))
            except Exception as e:
                print(f"Error storing app role: {e}")
                continue
        
        self.conn.commit()
        cursor.close()
    
    def get_app_roles(self, identity_db_id: int) -> list:
        """
        Retrieve custom app role assignments for an identity
        
        Args:
            identity_db_id: Database ID of the identity
            
        Returns:
            List of app role dicts with risk levels
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                app_role_id,
                resource_id,
                resource_display_name,
                principal_display_name,
                created_date_time,
                risk_level
            FROM sp_app_roles
            WHERE identity_db_id = %s
            ORDER BY risk_level DESC, resource_display_name
        """, (identity_db_id,))
        
        rows = cursor.fetchall()
        cursor.close()
        
        app_roles = []
        for row in rows:
            app_roles.append({
                'app_role_id': row[0],
                'resource_id': row[1],
                'resource_display_name': row[2],
                'principal_display_name': row[3],
                'created_date_time': row[4].isoformat() if row[4] else None,
                'risk_level': row[5]
            })
        
        return app_roles
    
    def _calculate_app_role_risk(self, role: dict) -> str:
        """
        Calculate risk level for a custom app role assignment
        
        Args:
            role: App role assignment dict
            
        Returns:
            Risk level: 'critical', 'high', 'medium', or 'low'
        """
        resource_name = (role.get('resource_display_name') or '').lower()
        
        # High-risk applications (customize based on your environment)
        high_risk_apps = [
            'prod', 'production', 'finance', 'payroll', 
            'hr', 'admin', 'security', 'compliance'
        ]
        
        # Check if resource name contains high-risk keywords
        for keyword in high_risk_apps:
            if keyword in resource_name:
                return 'high'
        
        # Default to medium for custom app roles
        return 'medium'

'''

# Insert the new functions before get_graph_permissions
lines.insert(insert_line, new_functions)

# Write back
with open('database.py', 'w') as f:
    f.writelines(lines)

print("✅ Added app roles functions to database.py!")
print(f"   Inserted at line {insert_line}")
print("   - store_app_roles()")
print("   - get_app_roles()")
print("   - _calculate_app_role_risk()")
