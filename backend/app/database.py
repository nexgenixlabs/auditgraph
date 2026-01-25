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
                tags
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
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
            json.dumps(identity_data.get('tags', {}))
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
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")
