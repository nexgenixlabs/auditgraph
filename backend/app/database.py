"""
AuditGraph Database Operations Layer

This module provides the Database class that handles all PostgreSQL database
interactions for AuditGraph. It serves as the data access layer between the
application logic and the PostgreSQL database.

Key Responsibilities:
    - Manage PostgreSQL connections with SSL enabled
    - CRUD operations for discovery runs, identities, and role assignments
    - Store and retrieve Entra ID directory roles
    - Manage SPN credentials (secrets, certificates, federated)
    - Store Microsoft Graph API permissions
    - Store custom application role assignments
    - Provide role intelligence data (attack patterns, HIPAA violations)

Database Tables Managed:
    - discovery_runs: Track each discovery execution
    - identities: Store discovered Azure/Entra identities
    - role_assignments: Azure RBAC role assignments
    - entra_role_assignments: Entra ID directory roles
    - credentials: SPN credential tracking (secrets, certs, federated)
    - graph_api_permissions: Microsoft Graph API permissions
    - sp_app_roles: Custom application role assignments
    - role_permissions: Role metadata and intelligence
    - role_attack_patterns: Real-world breach examples
    - role_hipaa_mappings: HIPAA compliance violation mappings
"""
import os
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
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                database=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                sslmode="require",
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
        cursor.execute(
            """
            INSERT INTO discovery_runs (
                subscription_id, subscription_name, started_at, status
            ) VALUES (%s, %s, %s, %s)
            RETURNING id
        """,
            (subscription_id, subscription_name, datetime.utcnow(), "running"),
        )

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
        low_count: int,
    ):
        """Mark discovery run as completed with summary stats"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE discovery_runs
            SET completed_at = %s,
                status = %s,
                total_identities = %s,
                critical_count = %s,
                high_count = %s,
                medium_count = %s,
                low_count = %s
            WHERE id = %s
        """,
            (
                datetime.utcnow(),
                "completed",
                total_identities,
                critical_count,
                high_count,
                medium_count,
                low_count,
                run_id,
            ),
        )
        self.conn.commit()
        cursor.close()

    def save_identity(self, run_id: int, identity_data: Dict) -> int:
        """
        Save an identity to the database (UPSERT)

        Returns:
            identity database ID
        """
        cursor = self.conn.cursor()

        # Normalize JSON fields
        tags_json = json.dumps(identity_data.get("tags", {}) or {})

        # Calculate normalized fields for multi-cloud support
        identity_type_normalized = self._get_normalized_type(identity_data)
        is_federated = identity_data.get("is_federated", False) or identity_data.get("identity_category") == "guest"
        status = "active" if identity_data.get("enabled", True) else "disabled"

        cursor.execute(
            """
            INSERT INTO identities (
                discovery_run_id,
                identity_id,
                display_name,
                source,
                identity_type,
                identity_category,

                app_id,
                object_id,

                service_principal_type,

                created_datetime,
                enabled,
                is_microsoft_system,

                risk_level,
                risk_score,
                risk_reasons,

                credential_expiration,
                credential_status,

                api_permission_count,
                app_role_count,

                last_sign_in,
                activity_status,

                tags,

                -- Multi-cloud normalized fields
                cloud,
                identity_type_normalized,
                canonical_name,
                principal_id,
                tenant_or_org_id,
                source_normalized,
                is_federated,
                status,
                last_seen_auth
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s,
                %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s,
                %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (discovery_run_id, identity_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                source = EXCLUDED.source,
                identity_type = EXCLUDED.identity_type,
                identity_category = EXCLUDED.identity_category,

                app_id = EXCLUDED.app_id,
                object_id = EXCLUDED.object_id,

                service_principal_type = EXCLUDED.service_principal_type,

                created_datetime = EXCLUDED.created_datetime,
                enabled = EXCLUDED.enabled,
                is_microsoft_system = EXCLUDED.is_microsoft_system,

                risk_level = EXCLUDED.risk_level,
                risk_score = EXCLUDED.risk_score,
                risk_reasons = EXCLUDED.risk_reasons,

                credential_expiration = EXCLUDED.credential_expiration,
                credential_status = EXCLUDED.credential_status,

                api_permission_count = EXCLUDED.api_permission_count,
                app_role_count = EXCLUDED.app_role_count,

                last_sign_in = EXCLUDED.last_sign_in,
                activity_status = EXCLUDED.activity_status,

                tags = EXCLUDED.tags,

                -- Multi-cloud normalized fields
                cloud = EXCLUDED.cloud,
                identity_type_normalized = EXCLUDED.identity_type_normalized,
                canonical_name = EXCLUDED.canonical_name,
                principal_id = EXCLUDED.principal_id,
                tenant_or_org_id = EXCLUDED.tenant_or_org_id,
                source_normalized = EXCLUDED.source_normalized,
                is_federated = EXCLUDED.is_federated,
                status = EXCLUDED.status,
                last_seen_auth = EXCLUDED.last_seen_auth,

                created_at = NOW()
            RETURNING id
        """,
            (
                run_id,
                identity_data.get("identity_id"),
                identity_data.get("display_name"),
                identity_data.get("source", "azure"),

                # legacy type (keep)
                identity_data.get("identity_type", "service_principal"),

                # normalized category
                identity_data.get("identity_category", "service_principal"),

                identity_data.get("app_id"),
                identity_data.get("object_id"),

                identity_data.get("service_principal_type"),

                identity_data.get("created_datetime"),
                identity_data.get("enabled", True),
                identity_data.get("is_microsoft_system", False),

                identity_data.get("risk_level"),
                identity_data.get("risk_score", 0),
                identity_data.get("risk_reasons", []),

                identity_data.get("credential_expiration"),
                identity_data.get("credential_status"),

                identity_data.get("api_permission_count", 0),
                identity_data.get("app_role_count", 0),

                identity_data.get("last_sign_in"),
                identity_data.get("activity_status"),

                tags_json,

                # Multi-cloud normalized fields
                identity_data.get("cloud", "azure"),
                identity_type_normalized,
                identity_data.get("display_name"),  # canonical_name = display_name
                identity_data.get("object_id"),  # principal_id = object_id for Azure
                identity_data.get("tenant_id"),  # tenant_or_org_id
                identity_data.get("source", "entra"),  # source_normalized
                is_federated,
                status,
                identity_data.get("last_sign_in"),  # last_seen_auth = last_sign_in
            ),
        )

        identity_db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()

        return identity_db_id

    def _get_normalized_type(self, identity_data: Dict) -> str:
        """
        Map identity_category to normalized identity_type for multi-cloud support

        Mapping:
            service_principal -> app
            managed_identity_system -> workload
            managed_identity_user -> workload
            human_user -> human
            guest -> human
            microsoft_internal -> system
        """
        mapping = {
            "service_principal": "app",
            "managed_identity_system": "workload",
            "managed_identity_user": "workload",
            "human_user": "human",
            "guest": "human",
            "microsoft_internal": "system",
        }
        category = identity_data.get("identity_category", "")
        return mapping.get(category, "app")

    def save_role_assignment(self, identity_db_id: int, role_data: Dict):
        """Save a role assignment to the database with usage intelligence"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO role_assignments (
                identity_db_id, role_name, scope, scope_type,
                principal_id, assignment_id, created_on,
                -- Usage intelligence fields
                scope_exists, usage_status, days_since_assigned,
                redundant_with, role_type, risk_level, why_critical,
                resource_type, resource_name
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
            (
                identity_db_id,
                role_data.get("role_name"),
                role_data.get("scope"),
                role_data.get("scope_type"),
                role_data.get("principal_id"),
                role_data.get("assignment_id"),
                role_data.get("created_on"),
                # Usage intelligence fields
                role_data.get("scope_exists", True),
                role_data.get("usage_status", "unknown"),
                role_data.get("days_since_assigned"),
                role_data.get("redundant_with"),
                role_data.get("role_type", "azure"),
                role_data.get("risk_level"),
                role_data.get("why_critical"),
                role_data.get("resource_type"),
                role_data.get("resource_name"),
            ),
        )
        self.conn.commit()
        cursor.close()

    def save_entra_role_assignment(self, identity_db_id: int, entra_role_data: Dict):
        """Save an Entra ID directory role assignment to the database with usage intelligence"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO entra_role_assignments (
                identity_db_id, role_name, role_definition_id, directory_scope,
                -- Usage intelligence fields
                usage_status, assigned_on, days_since_assigned,
                redundant_with, role_type, risk_level, why_critical
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
            (
                identity_db_id,
                entra_role_data.get("role_name"),
                entra_role_data.get("role_definition_id"),
                entra_role_data.get("directory_scope"),
                # Usage intelligence fields
                entra_role_data.get("usage_status", "unknown"),
                entra_role_data.get("assigned_on"),
                entra_role_data.get("days_since_assigned"),
                entra_role_data.get("redundant_with"),
                entra_role_data.get("role_type", "entra"),
                entra_role_data.get("risk_level"),
                entra_role_data.get("why_critical"),
            ),
        )
        self.conn.commit()
        cursor.close()

    def get_latest_discovery_run(self) -> Optional[Dict]:
        """Get the most recent completed discovery run"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            """
            SELECT * FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 1
        """
        )
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
            List of roles with intelligence (risk level, descriptions, usage status, etc.)
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Get Azure RBAC roles with intelligence and usage status
        cursor.execute(
            """
            SELECT
                COALESCE(ra.role_type, 'azure') as role_type,
                ra.role_name,
                ra.scope,
                ra.scope_type,
                ra.created_on,
                rp.privileged,
                COALESCE(ra.risk_level, rp.risk_level) as risk_level,
                rp.description,
                COALESCE(ra.why_critical, rp.why_critical) as why_critical,
                ral.last_activity_date,
                ral.days_since_last_use,
                -- Usage intelligence fields
                COALESCE(ra.scope_exists, true) as scope_exists,
                COALESCE(ra.usage_status, 'unknown') as usage_status,
                ra.days_since_assigned,
                ra.redundant_with,
                ra.resource_type,
                ra.resource_name
            FROM role_assignments ra
            LEFT JOIN role_permissions rp
                ON rp.role_name = ra.role_name AND rp.role_type = 'azure'
            LEFT JOIN role_activity_log ral
                ON ral.identity_db_id = ra.identity_db_id
                AND ral.role_name = ra.role_name
            WHERE ra.identity_db_id = %s
        """,
            (identity_db_id,),
        )

        azure_roles = [dict(row) for row in cursor.fetchall()]

        # Get Entra roles with intelligence and usage status
        cursor.execute(
            """
            SELECT
                COALESCE(era.role_type, 'entra') as role_type,
                era.role_name,
                era.directory_scope as scope,
                'directory' as scope_type,
                era.assigned_on as created_on,
                rp.privileged,
                COALESCE(era.risk_level, rp.risk_level) as risk_level,
                rp.description,
                COALESCE(era.why_critical, rp.why_critical) as why_critical,
                ral.last_activity_date,
                ral.days_since_last_use,
                -- Usage intelligence fields
                true as scope_exists,
                COALESCE(era.usage_status, 'unknown') as usage_status,
                era.days_since_assigned,
                era.redundant_with,
                NULL as resource_type,
                NULL as resource_name
            FROM entra_role_assignments era
            LEFT JOIN role_permissions rp
                ON rp.role_name = era.role_name AND rp.role_type = 'entra'
            LEFT JOIN role_activity_log ral
                ON ral.identity_db_id = era.identity_db_id
                AND ral.role_name = era.role_name
            WHERE era.identity_db_id = %s
        """,
            (identity_db_id,),
        )

        entra_roles = [dict(row) for row in cursor.fetchall()]

        cursor.close()

        # Combine and return
        return azure_roles + entra_roles

    def get_role_attack_patterns(self, role_name: str) -> List[Dict]:
        """Get attack patterns for a specific role"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            """
            SELECT
                attack_scenario,
                real_world_example,
                company_affected,
                breach_year,
                estimated_cost_usd
            FROM role_attack_patterns
            WHERE role_name = %s
            ORDER BY breach_year DESC
        """,
            (role_name,),
        )

        patterns = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return patterns

    def get_role_hipaa_violations(self, role_name: str) -> List[Dict]:
        """Get HIPAA violations for a specific role"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            """
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
        """,
            (role_name,),
        )

        violations = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return violations

    def store_graph_permissions(self, identity_db_id: int, permissions: list):
        """Store Graph API permissions for an identity"""
        cursor = self.conn.cursor()

        for perm in permissions:
            perm_name = perm.get("name", "Unknown")
            perm_desc = perm.get("description", "")

            # Simple risk classification
            risk = "medium"
            if any(x in perm_name.lower() for x in ["write", "readwrite", "all"]):
                risk = "high"
            if any(x in perm_name.lower() for x in ["mail", "files", "directory.readwrite"]):
                risk = "critical"

            cursor.execute(
                """
                INSERT INTO graph_api_permissions
                (identity_db_id, permission_name, permission_description, risk_level)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (identity_db_id, permission_name) DO UPDATE
                SET permission_description = EXCLUDED.permission_description,
                    risk_level = EXCLUDED.risk_level,
                    discovered_at = CURRENT_TIMESTAMP
            """,
                (identity_db_id, perm_name, perm_desc, risk),
            )

        self.conn.commit()
        cursor.close()

    def store_app_roles(self, identity_db_id: int, app_roles: list):
        """
        Store custom application role assignments for a service principal
        (excludes Microsoft Graph permissions which go to graph_api_permissions)
        """
        if not app_roles:
            return

        cursor = self.conn.cursor()

        for role in app_roles:
            # Calculate risk based on role name/resource
            risk_level = self._calculate_app_role_risk(role)

            try:
                cursor.execute(
                    """
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
                """,
                    (
                        identity_db_id,
                        role.get("app_role_id"),
                        role.get("resource_id"),
                        role.get("resource_display_name"),
                        role.get("principal_display_name"),
                        role.get("created_date_time"),
                        risk_level,
                    ),
                )
            except Exception as e:
                print(f"Error storing app role: {e}")
                continue

        self.conn.commit()
        cursor.close()

    def get_app_roles(self, identity_db_id: int) -> list:
        """Retrieve custom app role assignments for an identity"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
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
        """,
            (identity_db_id,),
        )

        rows = cursor.fetchall()
        cursor.close()

        app_roles = []
        for row in rows:
            app_roles.append(
                {
                    "app_role_id": row[0],
                    "resource_id": row[1],
                    "resource_display_name": row[2],
                    "principal_display_name": row[3],
                    "created_date_time": row[4].isoformat() if row[4] else None,
                    "risk_level": row[5],
                }
            )

        return app_roles

    def _calculate_app_role_risk(self, role: dict) -> str:
        """Calculate risk level for a custom app role assignment"""
        resource_name = (role.get("resource_display_name") or "").lower()

        high_risk_apps = [
            "prod",
            "production",
            "finance",
            "payroll",
            "hr",
            "admin",
            "security",
            "compliance",
        ]

        for keyword in high_risk_apps:
            if keyword in resource_name:
                return "high"

        return "medium"

    def get_graph_permissions(self, identity_db_id: int) -> list:
        """Get Graph API permissions for an identity"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
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
        """,
            (identity_db_id,),
        )

        permissions = []
        for row in cursor.fetchall():
            permissions.append(
                {
                    "permission_name": row[0],
                    "permission_description": row[1],
                    "resource_name": row[2],
                    "risk_level": row[3],
                }
            )

        cursor.close()
        return permissions

    # ========================================================================
    # Ownership Management Methods
    # ========================================================================

    def store_ownership(self, identity_db_id: int, owners: list):
        """
        Store ownership information for a service principal.
        Updates the sp_ownership table and denormalized fields on identities.
        """
        if not owners:
            return

        cursor = self.conn.cursor()

        for owner in owners:
            cursor.execute(
                """
                INSERT INTO sp_ownership (
                    identity_db_id,
                    owner_object_id,
                    owner_display_name,
                    owner_upn,
                    owner_type,
                    ownership_type,
                    is_primary_owner
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (identity_db_id, owner_object_id)
                DO UPDATE SET
                    owner_display_name = EXCLUDED.owner_display_name,
                    owner_upn = EXCLUDED.owner_upn,
                    owner_type = EXCLUDED.owner_type,
                    is_primary_owner = EXCLUDED.is_primary_owner,
                    discovered_at = NOW()
            """,
                (
                    identity_db_id,
                    owner.get("owner_object_id"),
                    owner.get("owner_display_name"),
                    owner.get("owner_upn"),
                    owner.get("owner_type", "user"),
                    owner.get("ownership_type", "application"),
                    owner.get("is_primary_owner", False),
                ),
            )

        # Update denormalized owner fields on identity
        primary_owner = next((o for o in owners if o.get("is_primary_owner")), owners[0] if owners else None)
        if primary_owner:
            cursor.execute(
                """
                UPDATE identities
                SET owner_display_name = %s,
                    owner_count = %s
                WHERE id = %s
            """,
                (
                    primary_owner.get("owner_display_name") or primary_owner.get("owner_upn"),
                    len(owners),
                    identity_db_id,
                ),
            )

        cursor.close()
        self.conn.commit()

    def get_ownership(self, identity_db_id: int) -> list:
        """Get owners for an identity"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT
                owner_object_id,
                owner_display_name,
                owner_upn,
                owner_type,
                ownership_type,
                is_primary_owner
            FROM sp_ownership
            WHERE identity_db_id = %s
            ORDER BY is_primary_owner DESC, owner_display_name
        """,
            (identity_db_id,),
        )

        owners = []
        for row in cursor.fetchall():
            owners.append(
                {
                    "owner_object_id": row[0],
                    "owner_display_name": row[1],
                    "owner_upn": row[2],
                    "owner_type": row[3],
                    "ownership_type": row[4],
                    "is_primary_owner": row[5],
                }
            )

        cursor.close()
        return owners

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
        """
        cursor = self.conn.cursor()

        cursor.execute(
            """
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
        """,
            (
                identity_db_id,
                credential["credential_type"],
                credential["key_id"],
                credential.get("display_name"),
                credential.get("start_datetime"),
                credential.get("end_datetime"),
                credential.get("thumbprint"),
                credential.get("issuer"),
                credential.get("subject"),
            ),
        )

        credential_id = cursor.fetchone()[0]
        cursor.close()
        self.conn.commit()

        return credential_id

    def update_identity_credential_summary(self, identity_db_id: int):
        """
        Update credential_count, next_expiry, and credential_risk on identity

        NOTE: Requires identities table to include:
          - credential_count
          - next_expiry
          - credential_risk
        """
        cursor = self.conn.cursor()

        cursor.execute(
            """
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
        """,
            (identity_db_id, identity_db_id),
        )

        cursor.close()
        self.conn.commit()

    def get_identity_credentials(self, identity_db_id: int) -> List[Dict]:
        """Get all credentials for an identity"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute(
            """
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
        """,
            (identity_db_id,),
        )

        credentials = [dict(row) for row in cursor.fetchall()]
        cursor.close()

        return credentials
