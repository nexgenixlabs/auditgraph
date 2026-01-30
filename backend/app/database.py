"""
Database connection and operations for AuditGraph
"""
import os
import json
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()


class Database:
    """PostgreSQL database handler"""
    
    def __init__(self):
        """Initialize database connection"""
        self.conn = None
        self.connect()
    
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(
                host=os.getenv('DB_HOST'),
                port=os.getenv('DB_PORT'),
                database=os.getenv('DB_NAME'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                sslmode='require'
            )
            print("✓ Connected to database")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            raise
    
    def create_discovery_run(self, subscription_id: str, subscription_name: str) -> int:
        """
        Create a new discovery run record
        
        Returns:
            discovery_run_id
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO discovery_runs (
                subscription_id, subscription_name, started_at, status
            ) VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (subscription_id, subscription_name, datetime.utcnow(), 'running'))
        
        run_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        
        return run_id
    
    def complete_discovery_run(
        self, 
        run_id: int, 
        total_identities: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int
    ):
        """Mark discovery run as completed with summary stats"""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE discovery_runs
            SET completed_at = %s,
                status = %s,
                total_identities = %s,
                critical_count = %s,
                high_count = %s,
                medium_count = %s,
                low_count = %s
            WHERE id = %s
        """, (
            datetime.utcnow(), 'completed',
            total_identities, critical_count, high_count, medium_count, low_count,
            run_id
        ))
        self.conn.commit()
        cursor.close()
    
    def save_identity(self, run_id: int, identity_data: Dict) -> int:
        """
        Save an identity to the database
        
        Returns:
            identity database ID
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO identities (
                discovery_run_id, identity_id, display_name, identity_type,
                app_id, object_id, created_datetime, enabled, is_microsoft_system,
                risk_level, risk_reasons,
                credential_expiration, credential_status,
                last_sign_in, activity_status,
                tags, source
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING id
        """, (
            run_id,
            identity_data.get('identity_id'),
            identity_data.get('display_name'),
            identity_data.get('identity_type'),
            identity_data.get('app_id'),
            identity_data.get('object_id'),
            identity_data.get('created_datetime'),
            identity_data.get('enabled', True),
            identity_data.get('is_microsoft_system', False),
            identity_data.get('risk_level'),
            identity_data.get('risk_reasons', []),
            identity_data.get('credential_expiration'),
            identity_data.get('credential_status'),
            identity_data.get('last_sign_in'),
            identity_data.get('activity_status'),
            json.dumps(identity_data.get('tags', {})),
            identity_data.get('source', 'azure')
        ))
        
        identity_db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        
        return identity_db_id
    
    def save_role_assignment(self, identity_db_id: int, role_data: Dict):
        """Save a role assignment to the database"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO role_assignments (
                identity_db_id, role_name, scope, scope_type,
                principal_id, assignment_id, created_on
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            identity_db_id,
            role_data.get('role_name'),
            role_data.get('scope'),
            role_data.get('scope_type'),
            role_data.get('principal_id'),
            role_data.get('assignment_id'),
            role_data.get('created_on')
        ))
        self.conn.commit()
        cursor.close()

    def save_entra_role_assignment(self, identity_db_id: int, entra_role_data: Dict):
        """Save an Entra ID directory role assignment to the database"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO entra_role_assignments (
                identity_db_id, role_name, role_definition_id, directory_scope
            ) VALUES (%s, %s, %s, %s)
        """, (
            identity_db_id,
            entra_role_data.get('role_name'),
            entra_role_data.get('role_definition_id'),
            entra_role_data.get('directory_scope')
        ))
        self.conn.commit()
        cursor.close()

    
    def get_latest_discovery_run(self) -> Optional[Dict]:
        """Get the most recent completed discovery run"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
        """)
        result = cursor.fetchone()
        cursor.close()
        return dict(result) if result else None
    
    # ========================================================================
    # WEEK 6: Role Intelligence Methods
    # ========================================================================
    
    def get_identity_roles_enriched(self, identity_db_id: int) -> List[Dict]:
        """
        Get all role assignments for an identity with intelligence data
        
        Returns:
            List of roles with intelligence (risk level, descriptions, etc.)
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        # Get Azure RBAC roles with intelligence
        cursor.execute("""
            SELECT 
                'azure' as role_type,
                ra.role_name,
                ra.scope,
                ra.scope_type,
                ra.created_on,
                rp.privileged,
                rp.risk_level,
                rp.description,
                rp.why_critical,
                ral.last_activity_date,
                ral.days_since_last_use
            FROM role_assignments ra
            LEFT JOIN role_permissions rp 
                ON rp.role_name = ra.role_name AND rp.role_type = 'azure'
            LEFT JOIN role_activity_log ral 
                ON ral.identity_db_id = ra.identity_db_id 
                AND ral.role_name = ra.role_name
            WHERE ra.identity_db_id = %s
        """, (identity_db_id,))
        
        azure_roles = [dict(row) for row in cursor.fetchall()]
        
        # Get Entra roles with intelligence
        cursor.execute("""
            SELECT 
                'entra' as role_type,
                era.role_name,
                era.directory_scope as scope,
                'directory' as scope_type,
                NULL as created_on,
                rp.privileged,
                rp.risk_level,
                rp.description,
                rp.why_critical,
                ral.last_activity_date,
                ral.days_since_last_use
            FROM entra_role_assignments era
            LEFT JOIN role_permissions rp 
                ON rp.role_name = era.role_name AND rp.role_type = 'entra'
            LEFT JOIN role_activity_log ral 
                ON ral.identity_db_id = era.identity_db_id 
                AND ral.role_name = era.role_name
            WHERE era.identity_db_id = %s
        """, (identity_db_id,))
        
        entra_roles = [dict(row) for row in cursor.fetchall()]
        
        cursor.close()
        
        # Combine and return
        return azure_roles + entra_roles
    
    def get_role_attack_patterns(self, role_name: str) -> List[Dict]:
        """Get attack patterns for a specific role"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT 
                attack_scenario,
                real_world_example,
                company_affected,
                breach_year,
                estimated_cost_usd
            FROM role_attack_patterns
            WHERE role_name = %s
            ORDER BY breach_year DESC
        """, (role_name,))
        
        patterns = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return patterns
    
    def get_role_hipaa_violations(self, role_name: str) -> List[Dict]:
        """Get HIPAA violations for a specific role"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT 
                hipaa_section,
                violation_explanation,
                violation_risk,
                typical_penalty_min,
                typical_penalty_max
            FROM role_hipaa_mappings
            WHERE role_name = %s
            ORDER BY 
                CASE violation_risk
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END
        """, (role_name,))
        
        violations = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return violations

    # ========================================================================
    # WEEK 6: Role Intelligence Methods
    # ========================================================================
    


    def store_graph_permissions(self, identity_db_id: int, permissions: list):
        """Store Graph API permissions for an identity"""
        cursor = self.conn.cursor()
        
        for perm in permissions:
            perm_name = perm.get('name', 'Unknown')
            perm_desc = perm.get('description', '')
            
            # Simple risk classification
            risk = 'medium'
            if any(x in perm_name.lower() for x in ['write', 'readwrite', 'all']):
                risk = 'high'
            if any(x in perm_name.lower() for x in ['mail', 'files', 'directory.readwrite']):
                risk = 'critical'
            
            cursor.execute("""
                INSERT INTO graph_api_permissions 
                (identity_db_id, permission_name, permission_description, risk_level)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (identity_db_id, permission_name) DO UPDATE
                SET permission_description = EXCLUDED.permission_description,
                    risk_level = EXCLUDED.risk_level,
                    discovered_at = CURRENT_TIMESTAMP
            """, (identity_db_id, perm_name, perm_desc, risk))
        
        self.conn.commit()
        cursor.close()

    def get_graph_permissions(self, identity_db_id: int) -> list:
        """Get Graph API permissions for an identity"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT permission_name, permission_description, resource_name, risk_level
            FROM graph_api_permissions
            WHERE identity_db_id = %s
            ORDER BY 
                CASE risk_level 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    ELSE 4 
                END,
                permission_name
        """, (identity_db_id,))
        
        permissions = []
        for row in cursor.fetchall():
            permissions.append({
                'permission_name': row[0],
                'permission_description': row[1],
                'resource_name': row[2],
                'risk_level': row[3]
            })
        
        cursor.close()
        return permissions

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

    # ========================================================================
    # WEEK 9: Credential Management Methods
    # ========================================================================
    
    def save_credential(self, identity_db_id: int, credential: Dict) -> int:
        """
        Save a credential (secret, certificate, or federated) for an identity
        
        Args:
            identity_db_id: Database ID of the identity
            credential: Dictionary with credential details
                - credential_type: 'secret', 'certificate', or 'federated'
                - key_id: Unique identifier
                - display_name: Optional name
                - start_datetime: When credential becomes valid
                - end_datetime: When credential expires
                - thumbprint: For certificates
                - issuer: For federated credentials
                - subject: For federated credentials
        
        Returns:
            credential_id: Database ID of saved credential
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO credentials (
                identity_db_id, credential_type, key_id, display_name,
                start_datetime, end_datetime, thumbprint, issuer, subject
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (identity_db_id, key_id) 
            DO UPDATE SET
                display_name = EXCLUDED.display_name,
                start_datetime = EXCLUDED.start_datetime,
                end_datetime = EXCLUDED.end_datetime,
                thumbprint = EXCLUDED.thumbprint,
                issuer = EXCLUDED.issuer,
                subject = EXCLUDED.subject,
                discovered_at = NOW()
            RETURNING id
        """, (
            identity_db_id,
            credential['credential_type'],
            credential['key_id'],
            credential.get('display_name'),
            credential.get('start_datetime'),
            credential.get('end_datetime'),
            credential.get('thumbprint'),
            credential.get('issuer'),
            credential.get('subject')
        ))
        
        credential_id = cursor.fetchone()[0]
        cursor.close()
        self.conn.commit()
        
        return credential_id
    
    def update_identity_credential_summary(self, identity_db_id: int):
        """
        Update credential_count, next_expiry, and credential_risk on identity
        
        This should be called after saving all credentials for an identity
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            WITH credential_summary AS (
                SELECT 
                    COUNT(*) as count,
                    MIN(end_datetime) as earliest_expiry,
                    CASE 
                        WHEN MIN(end_datetime) < NOW() THEN 'expired'
                        WHEN MIN(end_datetime) < NOW() + INTERVAL '30 days' THEN 'expiring_soon'
                        WHEN MIN(end_datetime) IS NULL THEN 'unknown'
                        ELSE 'healthy'
                    END as risk
                FROM credentials
                WHERE identity_db_id = %s
            )
            UPDATE identities
            SET 
                credential_count = credential_summary.count,
                next_expiry = credential_summary.earliest_expiry,
                credential_risk = credential_summary.risk
            FROM credential_summary
            WHERE identities.id = %s
        """, (identity_db_id, identity_db_id))
        
        cursor.close()
        self.conn.commit()
    
    def get_identity_credentials(self, identity_db_id: int) -> List[Dict]:
        """
        Get all credentials for an identity
        
        Returns:
            List of credential dictionaries with computed fields
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                id,
                credential_type,
                key_id,
                display_name,
                start_datetime,
                end_datetime,
                thumbprint,
                issuer,
                subject,
                discovered_at,
                CASE 
                    WHEN end_datetime < NOW() THEN 'expired'
                    WHEN end_datetime < NOW() + INTERVAL '30 days' THEN 'expiring_soon'
                    WHEN end_datetime < NOW() + INTERVAL '90 days' THEN 'healthy'
                    ELSE 'healthy'
                END as status,
                EXTRACT(DAY FROM (end_datetime - NOW())) as days_to_expiry
            FROM credentials
            WHERE identity_db_id = %s
            ORDER BY end_datetime ASC NULLS LAST
        """, (identity_db_id,))
        
        credentials = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        
        return credentials
