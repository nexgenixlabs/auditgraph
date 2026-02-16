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
                sslmode=os.getenv("DB_SSLMODE", "require"),
            )
            print("✓ Connected to database")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            raise

    def create_discovery_run(self, subscription_id: str, subscription_name: str, tenant_id=None) -> int:
        """
        Create a new discovery run record

        Returns:
            discovery_run_id
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO discovery_runs (
                subscription_id, subscription_name, started_at, status, tenant_id
            ) VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """,
            (subscription_id, subscription_name, datetime.utcnow(), "running", tenant_id),
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

    _risk_factors_col_ensured = False

    def save_identity(self, run_id: int, identity_data: Dict) -> int:
        """
        Save an identity to the database (UPSERT)

        Returns:
            identity database ID
        """
        cursor = self.conn.cursor()

        # Ensure risk_factors JSONB column exists (V2 risk engine)
        if not Database._risk_factors_col_ensured:
            try:
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS risk_factors JSONB DEFAULT '[]'::jsonb")
                self.conn.commit()
            except Exception:
                self.conn.rollback()
            Database._risk_factors_col_ensured = True

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
                risk_factors,

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
                %s, %s, %s, %s,
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
                risk_factors = EXCLUDED.risk_factors,

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
                json.dumps(identity_data.get("risk_factors", [])),

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
                estimated_cost_usd,
                source
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

    # ========================================================================
    # PIM (Privileged Identity Management) Methods
    # ========================================================================

    def save_pim_eligible(self, identity_db_id: int, data: Dict):
        """UPSERT a PIM eligible role assignment"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO pim_eligible_assignments (
                identity_db_id, role_name, role_definition_id, directory_scope,
                assignment_type, start_datetime, end_datetime, member_type
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (identity_db_id, role_definition_id, directory_scope)
            DO UPDATE SET
                role_name = EXCLUDED.role_name,
                assignment_type = EXCLUDED.assignment_type,
                start_datetime = EXCLUDED.start_datetime,
                end_datetime = EXCLUDED.end_datetime,
                member_type = EXCLUDED.member_type,
                discovered_at = NOW()
        """,
            (
                identity_db_id,
                data.get("role_name"),
                data.get("role_definition_id"),
                data.get("directory_scope", "/"),
                data.get("assignment_type", "eligible"),
                data.get("start_datetime"),
                data.get("end_datetime"),
                data.get("member_type"),
            ),
        )
        self.conn.commit()
        cursor.close()

    def save_pim_activation(self, identity_db_id: int, data: Dict):
        """INSERT a PIM activation record"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO pim_activations (
                identity_db_id, role_name, role_definition_id, directory_scope,
                status, activation_start, activation_end,
                justification, ticket_number, ticket_system,
                is_approval_required, created_datetime
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
            (
                identity_db_id,
                data.get("role_name"),
                data.get("role_definition_id"),
                data.get("directory_scope", "/"),
                data.get("status"),
                data.get("activation_start"),
                data.get("activation_end"),
                data.get("justification"),
                data.get("ticket_number"),
                data.get("ticket_system"),
                data.get("is_approval_required", False),
                data.get("created_datetime"),
            ),
        )
        self.conn.commit()
        cursor.close()

    def update_identity_pim_summary(self, identity_db_id: int):
        """Update denormalized PIM counts on identities table"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            WITH pim_summary AS (
                SELECT
                    COUNT(*) as eligible_count,
                    COUNT(*) FILTER (WHERE end_datetime IS NULL) > 0 as has_permanent
                FROM pim_eligible_assignments
                WHERE identity_db_id = %s
            ),
            active_summary AS (
                SELECT COUNT(*) as active_count
                FROM pim_activations
                WHERE identity_db_id = %s AND status = 'Active'
            )
            UPDATE identities
            SET pim_eligible_count = pim_summary.eligible_count,
                pim_active_count = active_summary.active_count,
                has_permanent_assignment = pim_summary.has_permanent
            FROM pim_summary, active_summary
            WHERE identities.id = %s
        """,
            (identity_db_id, identity_db_id, identity_db_id),
        )
        self.conn.commit()
        cursor.close()

    def get_pim_data(self, identity_db_id: int) -> Dict:
        """Get PIM eligible assignments, activations, and overuse metrics"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Eligible assignments
        cursor.execute(
            """
            SELECT role_name, role_definition_id, directory_scope,
                   assignment_type, start_datetime, end_datetime, member_type
            FROM pim_eligible_assignments
            WHERE identity_db_id = %s
            ORDER BY role_name
        """,
            (identity_db_id,),
        )
        eligible = [dict(row) for row in cursor.fetchall()]

        # Activations
        cursor.execute(
            """
            SELECT role_name, role_definition_id, directory_scope,
                   status, activation_start, activation_end,
                   justification, ticket_number, ticket_system,
                   is_approval_required, created_datetime
            FROM pim_activations
            WHERE identity_db_id = %s
            ORDER BY created_datetime DESC NULLS LAST
        """,
            (identity_db_id,),
        )
        activations = [dict(row) for row in cursor.fetchall()]

        # Overuse metrics: activations in last 30 days
        cursor.execute(
            """
            SELECT
                COUNT(*) as activation_frequency_30d,
                COALESCE(SUM(
                    EXTRACT(EPOCH FROM (
                        LEAST(activation_end, NOW()) - activation_start
                    )) / 3600.0
                ), 0) as total_active_hours_30d
            FROM pim_activations
            WHERE identity_db_id = %s
              AND activation_start >= NOW() - INTERVAL '30 days'
        """,
            (identity_db_id,),
        )
        metrics_row = cursor.fetchone()

        freq = int(metrics_row["activation_frequency_30d"]) if metrics_row else 0
        hours = float(metrics_row["total_active_hours_30d"]) if metrics_row else 0.0
        # 30 days * 24 hours = 720 hours; >80% = 576 hours
        always_active = hours > 576

        cursor.close()

        return {
            "eligible_assignments": eligible,
            "activations": activations,
            "overuse_metrics": {
                "activation_frequency_30d": freq,
                "always_active_pattern": always_active,
                "total_active_hours_30d": round(hours, 1),
            },
        }

    # ========================================================================
    # Conditional Access Methods
    # ========================================================================

    def save_ca_policy(self, run_id: int, policy: Dict):
        """UPSERT a Conditional Access policy"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO ca_policies (
                discovery_run_id, policy_id, display_name, state,
                include_users, exclude_users, include_applications,
                client_app_types, grant_controls, session_controls,
                requires_mfa, targets_all_users, has_exclusions,
                allows_legacy_auth, modified_datetime
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (discovery_run_id, policy_id)
            DO UPDATE SET
                display_name = EXCLUDED.display_name,
                state = EXCLUDED.state,
                include_users = EXCLUDED.include_users,
                exclude_users = EXCLUDED.exclude_users,
                include_applications = EXCLUDED.include_applications,
                client_app_types = EXCLUDED.client_app_types,
                grant_controls = EXCLUDED.grant_controls,
                session_controls = EXCLUDED.session_controls,
                requires_mfa = EXCLUDED.requires_mfa,
                targets_all_users = EXCLUDED.targets_all_users,
                has_exclusions = EXCLUDED.has_exclusions,
                allows_legacy_auth = EXCLUDED.allows_legacy_auth,
                modified_datetime = EXCLUDED.modified_datetime
        """,
            (
                run_id,
                policy.get("policy_id"),
                policy.get("display_name"),
                policy.get("state"),
                json.dumps(policy.get("include_users", [])),
                json.dumps(policy.get("exclude_users", [])),
                json.dumps(policy.get("include_applications", [])),
                json.dumps(policy.get("client_app_types", [])),
                json.dumps(policy.get("grant_controls", {})),
                json.dumps(policy.get("session_controls", {})),
                policy.get("requires_mfa", False),
                policy.get("targets_all_users", False),
                policy.get("has_exclusions", False),
                policy.get("allows_legacy_auth", False),
                policy.get("modified_datetime"),
            ),
        )
        self.conn.commit()
        cursor.close()

    def save_ca_identity_coverage(self, identity_db_id: int, coverage: Dict):
        """UPSERT CA coverage for an identity"""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO ca_identity_coverage (
                identity_db_id, coverage_status, mfa_enforced,
                applicable_policy_count, excluded_from_count, risk_flags
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (identity_db_id)
            DO UPDATE SET
                coverage_status = EXCLUDED.coverage_status,
                mfa_enforced = EXCLUDED.mfa_enforced,
                applicable_policy_count = EXCLUDED.applicable_policy_count,
                excluded_from_count = EXCLUDED.excluded_from_count,
                risk_flags = EXCLUDED.risk_flags
        """,
            (
                identity_db_id,
                coverage.get("coverage_status", "no_coverage"),
                coverage.get("mfa_enforced", False),
                coverage.get("applicable_policy_count", 0),
                coverage.get("excluded_from_count", 0),
                json.dumps(coverage.get("risk_flags", [])),
            ),
        )
        # Also update denormalized fields on identity
        cursor.execute(
            """
            UPDATE identities
            SET ca_coverage_status = %s, ca_mfa_enforced = %s
            WHERE id = %s
        """,
            (
                coverage.get("coverage_status", "no_coverage"),
                coverage.get("mfa_enforced", False),
                identity_db_id,
            ),
        )
        self.conn.commit()
        cursor.close()

    def get_ca_summary(self, run_id: int) -> Dict:
        """Get CA summary for dashboard"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Policy counts
        cursor.execute(
            """
            SELECT
                COUNT(*) as total_policies,
                COUNT(*) FILTER (WHERE state = 'enabled') as enabled_policies,
                COUNT(*) FILTER (WHERE state = 'disabled') as disabled_policies,
                COUNT(*) FILTER (WHERE requires_mfa AND state = 'enabled') as mfa_policies
            FROM ca_policies
            WHERE discovery_run_id = %s
        """,
            (run_id,),
        )
        policy_row = cursor.fetchone() or {}

        # Coverage counts
        cursor.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE ca_coverage_status = 'covered') as covered,
                COUNT(*) FILTER (WHERE ca_coverage_status = 'partial') as partial,
                COUNT(*) FILTER (WHERE ca_coverage_status = 'excluded') as excluded,
                COUNT(*) FILTER (WHERE ca_coverage_status = 'no_coverage' OR ca_coverage_status IS NULL) as no_coverage,
                COUNT(*) as total
            FROM identities
            WHERE discovery_run_id = %s
        """,
            (run_id,),
        )
        cov_row = cursor.fetchone() or {}

        total = int(cov_row.get("total", 0)) or 1
        covered = int(cov_row.get("covered", 0))
        coverage_pct = round((covered / total) * 100, 1) if total > 0 else 0

        # Weak policy flags
        weak_flags = []
        cursor.execute(
            """
            SELECT COUNT(*) as cnt FROM ca_policies
            WHERE discovery_run_id = %s AND state = 'enabled'
            AND targets_all_users = true AND requires_mfa = false
        """,
            (run_id,),
        )
        no_mfa_row = cursor.fetchone()
        if no_mfa_row and int(no_mfa_row["cnt"]) > 0:
            weak_flags.append({"flag": "no_mfa_for_all_users", "count": int(no_mfa_row["cnt"]), "severity": "critical"})

        cursor.execute(
            "SELECT COUNT(*) as cnt FROM ca_policies WHERE discovery_run_id = %s AND state = 'disabled'",
            (run_id,),
        )
        disabled_row = cursor.fetchone()
        if disabled_row and int(disabled_row["cnt"]) > 0:
            weak_flags.append({"flag": "ca_policy_disabled", "count": int(disabled_row["cnt"]), "severity": "high"})

        cursor.execute(
            "SELECT COUNT(*) as cnt FROM ca_policies WHERE discovery_run_id = %s AND allows_legacy_auth = true AND state = 'enabled'",
            (run_id,),
        )
        legacy_row = cursor.fetchone()
        if legacy_row and int(legacy_row["cnt"]) > 0:
            weak_flags.append({"flag": "legacy_auth_enabled", "count": int(legacy_row["cnt"]), "severity": "high"})

        cursor.close()

        return {
            "total_policies": int(policy_row.get("total_policies", 0)),
            "enabled_policies": int(policy_row.get("enabled_policies", 0)),
            "disabled_policies": int(policy_row.get("disabled_policies", 0)),
            "mfa_policies": int(policy_row.get("mfa_policies", 0)),
            "coverage": {
                "covered": covered,
                "partial": int(cov_row.get("partial", 0)),
                "excluded": int(cov_row.get("excluded", 0)),
                "no_coverage": int(cov_row.get("no_coverage", 0)),
                "coverage_pct": coverage_pct,
            },
            "weak_policy_flags": weak_flags,
        }

    # ========================================================================
    # Remediation Engine Methods
    # ========================================================================

    def _ensure_remediation_playbooks(self):
        """Create remediation_playbooks table and seed default playbooks if empty."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_playbooks (
                id SERIAL PRIMARY KEY,
                risk_pattern VARCHAR(255) NOT NULL,
                pattern_type VARCHAR(20) DEFAULT 'contains',
                title VARCHAR(255) NOT NULL,
                description TEXT,
                steps JSONB NOT NULL,
                impact VARCHAR(10) DEFAULT 'high',
                effort VARCHAR(10) DEFAULT 'medium',
                priority_score INTEGER DEFAULT 50,
                compliance_refs JSONB,
                category VARCHAR(50),
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        self.conn.commit()

        # Check if empty — seed if so
        cursor.execute("SELECT COUNT(*) FROM remediation_playbooks")
        count = cursor.fetchone()[0]
        if count == 0:
            playbooks = [
                ("Global Administrator", "contains", "Remove or scope Global Administrator assignments",
                 "Global Administrator grants unrestricted access to the entire Microsoft 365 tenant. This role should only be assigned to break-glass accounts with PIM just-in-time activation.",
                 json.dumps(["Identify all identities with Global Administrator role","Determine if the identity genuinely requires tenant-wide control","Replace with scoped admin roles where possible","Enable PIM eligible assignment with 1-hour max activation","Configure approval workflow requiring a second administrator","Ensure 2-4 break-glass accounts retain emergency access","Document business justification for each remaining assignment"]),
                 "critical","medium",98,json.dumps(["SOC2 CC6.1","HIPAA 164.308(a)(3)","PCI-DSS 7.1","NIST AC-6"]),"access_control"),
                ("Owner", "contains", "Replace Azure Owner role with scoped RBAC roles",
                 "The Owner role grants full control over Azure resources including the ability to assign access to others.",
                 json.dumps(["List all Owner role assignments","Identify actual permissions used","Replace with resource-group-scoped Contributor","Use User Access Administrator for access management","Remove Owner assignment after confirming replacement","Monitor for access denied errors over 7 days"]),
                 "critical","medium",95,json.dumps(["SOC2 CC6.1","HIPAA 164.308(a)(4)","NIST AC-6"]),"access_control"),
                ("Privileged Role Administrator", "contains", "Restrict Privileged Role Administrator to break-glass only",
                 "Privileged Role Administrator can assign any Entra ID directory role including Global Administrator.",
                 json.dumps(["Identify all PRA assignments","Remove all permanent assignments except break-glass","Enable PIM with 30-minute max activation and approval","Configure alerts for role activation","Review activation logs monthly"]),
                 "critical","medium",96,json.dumps(["SOC2 CC6.1","HIPAA 164.308(a)(3)","NIST AC-6"]),"access_control"),
                ("User Access Administrator", "contains", "Restrict User Access Administrator to JIT/PIM only",
                 "User Access Administrator can grant any Azure RBAC role including Owner, creating a privilege escalation path.",
                 json.dumps(["List all assignments at subscription level","Replace permanent with PIM eligible","Scope to specific resource groups","Configure approval workflow","Set max activation to 2 hours"]),
                 "critical","medium",94,json.dumps(["SOC2 CC6.1","HIPAA 164.308(a)(4)","NIST AC-2"]),"access_control"),
                ("no_mfa", "contains", "Enable MFA via Conditional Access policy",
                 "Identities without MFA enforcement are vulnerable to credential theft attacks.",
                 json.dumps(["Navigate to Entra ID > Protection > Conditional Access","Create policy targeting All Users","Set conditions: All cloud apps","Under Grant: Require MFA","Set sign-in frequency to 1 hour for privileged roles","Test in Report-only mode for 7 days","Switch to Enabled after confirming no disruption"]),
                 "critical","medium",93,json.dumps(["SOC2 CC6.1","HIPAA 164.312(d)","PCI-DSS 8.3","NIST IA-2"]),"access_control"),
                ("Exchange Administrator", "contains", "Audit mailbox access and scope Exchange Admin permissions",
                 "Exchange Administrators can access all mailboxes including those containing sensitive data.",
                 json.dumps(["Review all Exchange Administrator assignments","Determine if scoped role suffices","Enable mailbox audit logging","Configure alerts for admin mailbox access","Move to PIM eligible with justification"]),
                 "high","medium",82,json.dumps(["HIPAA 164.312(a)(1)","SOC2 CC6.3"]),"access_control"),
                ("Application Administrator", "contains", "Review and restrict Application Administrator permissions",
                 "Application Administrators can create service principals with high privileges and access application secrets.",
                 json.dumps(["Audit all assignments","Replace with Cloud Application Administrator where possible","Restrict app registration creation","Enable consent workflow","Monitor for new app registrations"]),
                 "high","medium",80,json.dumps(["SOC2 CC6.1","NIST AC-6"]),"access_control"),
                ("Security Administrator", "contains", "Limit Security Administrator to read-only where possible",
                 "Security Administrator can modify security settings and disable protections.",
                 json.dumps(["Identify all role holders","Determine if Security Reader suffices","Downgrade where write access not required","Enable PIM with approval for remaining","Configure alerts for security policy changes"]),
                 "high","medium",78,json.dumps(["SOC2 CC6.1","HIPAA 164.308(a)(1)","NIST AC-6"]),"access_control"),
                ("Conditional Access Administrator", "contains", "Require approval workflow for CA policy changes",
                 "Conditional Access Administrators can disable MFA policies, creating catastrophic security gaps.",
                 json.dumps(["Move all permanent assignments to PIM eligible","Configure approval workflow requiring Security team sign-off","Set max activation to 4 hours","Enable change tracking alerts","Implement CA policy backup/restore process"]),
                 "high","medium",85,json.dumps(["SOC2 CC6.1","NIST AC-6"]),"access_control"),
                ("Mail.ReadWrite", "contains", "Remove Mail.ReadWrite unless business-justified",
                 "Mail.ReadWrite Graph API permission allows reading and writing to any mailbox in the organization.",
                 json.dumps(["Identify all SPNs with Mail.ReadWrite","Verify documented business need","Replace with Mail.Read where possible","Scope to specific mailboxes","Revoke unnecessary permissions"]),
                 "high","medium",76,json.dumps(["HIPAA 164.312(a)(1)","SOC2 CC6.3"]),"access_control"),
                ("Files.ReadWrite.All", "contains", "Scope file access to specific SharePoint sites",
                 "Files.ReadWrite.All grants access to all files in SharePoint and OneDrive.",
                 json.dumps(["Identify all SPNs with Files.ReadWrite.All","Determine specific SharePoint sites needed","Replace with Sites.Selected permission","Grant site-specific access","Validate application still functions"]),
                 "high","medium",74,json.dumps(["HIPAA 164.312(a)(1)","SOC2 CC6.3"]),"access_control"),
                ("excessive_permissions", "contains", "Apply least-privilege: remove unused API permissions",
                 "Service principals with excessive permissions increase blast radius.",
                 json.dumps(["Review each permission in App registrations","Cross-reference with usage logs","Identify unused permissions","Remove one at a time, testing after each","Document minimum required permissions"]),
                 "high","high",70,json.dumps(["SOC2 CC6.1","NIST AC-6","PCI-DSS 7.1"]),"access_control"),
                ("no_conditional_access", "contains", "Create CA policies covering all identity types",
                 "Identities without Conditional Access coverage bypass MFA, device compliance, and location restrictions.",
                 json.dumps(["Review current CA policy scope","Identify gaps for service principals and workload identities","Create baseline MFA policy for all users","Create separate policy for workload identities","Test in Report-only mode for 7 days"]),
                 "high","medium",72,json.dumps(["SOC2 CC6.1","NIST AC-2","HIPAA 164.312(d)"]),"access_control"),
                ("expired", "contains", "Rotate or remove expired credentials",
                 "Expired credentials indicate poor lifecycle management and may signal abandoned service principals.",
                 json.dumps(["List all SPNs with expired secrets/certificates","Check sign-in logs for activity","Disable unused SPNs, schedule deletion after 30 days","Generate new secret with max 12-month expiry for active SPNs","Store in Azure Key Vault","Update application configuration","Remove expired credential"]),
                 "high","low",88,json.dumps(["SOC2 CC7.2","HIPAA 164.312(d)","PCI-DSS 8.1","NIST IA-5"]),"credential_hygiene"),
                ("expiring_soon", "contains", "Schedule credential rotation before expiry",
                 "Credentials expiring within 30 days need proactive rotation to prevent application outages.",
                 json.dumps(["Generate new secret or certificate","Add alongside existing credential","Update application to use new credential","Validate for 48 hours","Remove old credential","Set calendar reminder for next rotation"]),
                 "medium","low",75,json.dumps(["SOC2 CC7.2","NIST IA-5"]),"credential_hygiene"),
                ("stale_credential", "contains", "Rotate credentials inactive for 90+ days",
                 "Stale credentials may have been compromised without detection.",
                 json.dumps(["Identify credentials not used in 90+ days","Determine if application still needed","Remove credential and disable SPN if unneeded","Rotate credential immediately if needed","Enable credential monitoring"]),
                 "high","low",73,json.dumps(["NIST IA-5","SOC2 CC7.2"]),"credential_hygiene"),
                ("dormant", "contains", "Disable or remove dormant identities",
                 "Identities with no sign-in activity for 90+ days are attack surface with no business value.",
                 json.dumps(["Confirm no sign-in activity in last 90 days","Check for automated process usage","Contact application owner","Disable the identity","Wait 30 days to confirm no impact","Delete if no impact"]),
                 "high","low",83,json.dumps(["SOC2 CC6.2","HIPAA 164.308(a)(3)","NIST AC-2","PCI-DSS 8.1"]),"governance"),
                ("never_used", "contains", "Review and remove never-used identities",
                 "Identities created 30+ days ago with no recorded sign-in are likely orphaned.",
                 json.dumps(["Verify created 30+ days ago with zero sign-ins","Check if recently provisioned","Contact creator to determine if still needed","Disable if unneeded, schedule deletion in 30 days","Set 30-day deadline for activation if needed"]),
                 "high","low",79,json.dumps(["SOC2 CC6.2","NIST AC-2"]),"governance"),
                ("no_owner", "contains", "Assign ownership to unowned service principals",
                 "Service principals without designated owners cannot be maintained, rotated, or decommissioned properly.",
                 json.dumps(["List all SPNs without owners","Identify managing team or individual","Assign at least one owner","Assign secondary owner for redundancy","Configure alerts for SPNs created without owners"]),
                 "high","medium",77,json.dumps(["SOC2 CC6.3","NIST CM-8","PCI-DSS 8.6"]),"governance"),
                ("multiple_high_privilege", "contains", "Separate duties across multiple identities",
                 "A single identity holding multiple high-privilege roles violates separation of duties.",
                 json.dumps(["Identify full role set across Azure RBAC and Entra ID","Determine which roles can be separated","Create purpose-specific service principals","Migrate role assignments","Remove excess roles from original identity","Document role separation"]),
                 "critical","high",86,json.dumps(["SOC2 CC6.1","HIPAA 164.308(a)(3)","NIST AC-5"]),"governance"),
            ]
            for pb in playbooks:
                cursor.execute("""
                    INSERT INTO remediation_playbooks
                    (risk_pattern, pattern_type, title, description, steps, impact, effort, priority_score, compliance_refs, category)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, pb)
            self.conn.commit()
            print(f"Seeded {len(playbooks)} remediation playbooks")
        cursor.close()

    def get_identity_remediations(self, identity_db_id: int, identity_data: Dict) -> Dict:
        """
        Match an identity's risk factors against remediation playbooks.

        Args:
            identity_db_id: The database ID of the identity
            identity_data: Dict with risk_reasons, roles, activity_status, etc.

        Returns:
            Dict with remediations list and summary
        """
        self._ensure_remediation_playbooks()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Get all playbooks
        cursor.execute("""
            SELECT id, risk_pattern, pattern_type, title, description,
                   steps, impact, effort, priority_score, compliance_refs, category
            FROM remediation_playbooks
            ORDER BY priority_score DESC
        """)
        playbooks = [dict(row) for row in cursor.fetchall()]

        # Build the searchable text from identity risk factors
        risk_reasons = identity_data.get("risk_reasons", [])
        if isinstance(risk_reasons, str):
            try:
                risk_reasons = json.loads(risk_reasons)
            except Exception:
                risk_reasons = [risk_reasons]

        # Get role names
        roles = identity_data.get("roles", [])
        role_names = [r.get("role_name", "") for r in roles] if roles else []

        activity_status = identity_data.get("activity_status", "")
        credential_status = identity_data.get("credential_status", "")
        credential_risk = identity_data.get("credential_risk", "")
        owner_count = identity_data.get("owner_count", 0)
        ca_coverage = identity_data.get("ca_coverage_status", "")

        # Build search corpus
        search_texts = []
        search_texts.extend([r.lower() for r in risk_reasons if isinstance(r, str)])
        search_texts.extend([r.lower() for r in role_names])
        if activity_status:
            search_texts.append(activity_status.lower())
        if credential_status:
            search_texts.append(credential_status.lower())
        if credential_risk:
            search_texts.append(credential_risk.lower())
        if owner_count == 0:
            search_texts.append("no_owner")
        if ca_coverage in ("no_coverage", None, ""):
            search_texts.append("no_conditional_access")
            search_texts.append("no_mfa")

        # Check for multiple high privilege roles
        high_priv_roles = [r for r in role_names if r.lower() in (
            'global administrator', 'owner', 'privileged role administrator',
            'user access administrator', 'exchange administrator',
            'application administrator', 'security administrator'
        )]
        if len(high_priv_roles) >= 2:
            search_texts.append("multiple_high_privilege")

        search_corpus = " ".join(search_texts)

        # Match playbooks
        matched = []
        for pb in playbooks:
            pattern = pb["risk_pattern"].lower()
            ptype = pb["pattern_type"]
            match_found = False
            matched_reason = ""

            if ptype == "exact":
                for text in search_texts:
                    if text == pattern:
                        match_found = True
                        matched_reason = text
                        break
            elif ptype == "startswith":
                for text in search_texts:
                    if text.startswith(pattern):
                        match_found = True
                        matched_reason = text
                        break
            else:  # contains (default)
                for text in search_texts:
                    if pattern in text:
                        match_found = True
                        matched_reason = text
                        break

            if match_found:
                steps = pb["steps"]
                if isinstance(steps, str):
                    try:
                        steps = json.loads(steps)
                    except Exception:
                        steps = [steps]

                compliance_refs = pb["compliance_refs"]
                if isinstance(compliance_refs, str):
                    try:
                        compliance_refs = json.loads(compliance_refs)
                    except Exception:
                        compliance_refs = []

                matched.append({
                    "id": pb["id"],
                    "title": pb["title"],
                    "description": pb["description"],
                    "steps": steps,
                    "impact": pb["impact"],
                    "effort": pb["effort"],
                    "priority_score": pb["priority_score"],
                    "compliance_refs": compliance_refs or [],
                    "category": pb["category"],
                    "matched_reason": matched_reason,
                })

        cursor.close()

        critical_actions = len([m for m in matched if m["impact"] == "critical"])
        quick_wins = len([m for m in matched if m["effort"] == "low"])

        return {
            "remediations": matched,
            "summary": {
                "total": len(matched),
                "critical_actions": critical_actions,
                "quick_wins": quick_wins,
            }
        }

    def get_report_data(self) -> Dict:
        """
        Get comprehensive data for PDF report generation.
        Returns stats, posture, compliance, top risks, and remediation summary.
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Get latest run
        cursor.execute("""
            SELECT id, completed_at, total_identities, critical_count, high_count, medium_count, low_count
            FROM discovery_runs WHERE status = 'completed'
            ORDER BY id DESC LIMIT 1
        """)
        run = cursor.fetchone()
        if not run:
            cursor.close()
            return None

        run_id = run["id"]

        # Previous run for trend
        cursor.execute("""
            SELECT id, total_identities, critical_count, high_count, medium_count
            FROM discovery_runs WHERE status = 'completed'
            ORDER BY id DESC LIMIT 1 OFFSET 1
        """)
        prev_run = cursor.fetchone()

        # Top 20 critical/high identities
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, i.risk_reasons,
                   i.activity_status, i.credential_status, i.owner_display_name,
                   COALESCE(i.owner_count, 0) as owner_count,
                   i.ca_coverage_status
            FROM identities i
            WHERE i.discovery_run_id = %s AND i.risk_level IN ('critical', 'high')
            ORDER BY
                CASE i.risk_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                COALESCE(i.risk_score, 0) DESC
            LIMIT 20
        """, (run_id,))
        top_risks_rows = [dict(r) for r in cursor.fetchall()]

        # Get roles for each top risk identity for remediation matching
        top_risks = []
        for identity_row in top_risks_rows:
            db_id = identity_row["id"]
            # Get roles
            cursor.execute("""
                SELECT role_name FROM role_assignments WHERE identity_db_id = %s
                UNION ALL
                SELECT role_name FROM entra_role_assignments WHERE identity_db_id = %s
            """, (db_id, db_id))
            roles = [{"role_name": r["role_name"]} for r in cursor.fetchall()]

            risk_reasons = identity_row.get("risk_reasons", [])
            if isinstance(risk_reasons, str):
                try:
                    risk_reasons = json.loads(risk_reasons)
                except Exception:
                    risk_reasons = []

            identity_data = {
                "risk_reasons": risk_reasons,
                "roles": roles,
                "activity_status": identity_row.get("activity_status"),
                "credential_status": identity_row.get("credential_status"),
                "owner_count": identity_row.get("owner_count", 0),
                "ca_coverage_status": identity_row.get("ca_coverage_status"),
            }
            remediations = self.get_identity_remediations(db_id, identity_data)

            top_risks.append({
                "identity_id": identity_row["identity_id"],
                "display_name": identity_row["display_name"],
                "identity_category": identity_row["identity_category"],
                "risk_level": identity_row["risk_level"],
                "risk_score": identity_row.get("risk_score", 0),
                "risk_reasons": risk_reasons,
                "remediations": remediations["remediations"][:3],  # Top 3 per identity
            })

        # Aggregate remediation summary
        all_remediations = {}
        for tr in top_risks:
            for rem in tr.get("remediations", []):
                rid = rem["id"]
                if rid not in all_remediations:
                    all_remediations[rid] = {**rem, "affected_identities": 0}
                all_remediations[rid]["affected_identities"] += 1

        remediation_list = sorted(all_remediations.values(), key=lambda x: -x["priority_score"])

        by_category = {}
        by_impact = {}
        for r in remediation_list:
            cat = r.get("category", "other")
            by_category[cat] = by_category.get(cat, 0) + 1
            imp = r.get("impact", "medium")
            by_impact[imp] = by_impact.get(imp, 0) + 1

        quick_wins = [r for r in remediation_list if r.get("effort") == "low"]

        # Credential health
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE credential_risk = 'expired') as expired,
                COUNT(*) FILTER (WHERE credential_risk = 'expiring_soon') as expiring_soon,
                COUNT(*) FILTER (WHERE credential_risk = 'healthy') as healthy,
                COUNT(*) FILTER (WHERE credential_risk IS NULL OR credential_risk = 'unknown') as unknown
            FROM identities WHERE discovery_run_id = %s
        """, (run_id,))
        cred_row = cursor.fetchone() or {}

        # CA coverage
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE ca_coverage_status = 'covered') as covered,
                COUNT(*) FILTER (WHERE ca_coverage_status = 'no_coverage' OR ca_coverage_status IS NULL) as not_covered,
                COUNT(*) as total
            FROM identities WHERE discovery_run_id = %s
        """, (run_id,))
        ca_row = cursor.fetchone() or {}

        cursor.close()

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "run_id": run_id,
            "collected_at": run["completed_at"].isoformat() if run.get("completed_at") else None,
            "stats": {
                "total_identities": run.get("total_identities", 0),
                "critical": run.get("critical_count", 0),
                "high": run.get("high_count", 0),
                "medium": run.get("medium_count", 0),
                "low": run.get("low_count", 0),
            },
            "previous_run": {
                "total_identities": prev_run["total_identities"] if prev_run else None,
                "critical": prev_run["critical_count"] if prev_run else None,
                "high": prev_run["high_count"] if prev_run else None,
            } if prev_run else None,
            "credential_health": {
                "expired": int(cred_row.get("expired", 0)),
                "expiring_soon": int(cred_row.get("expiring_soon", 0)),
                "healthy": int(cred_row.get("healthy", 0)),
                "unknown": int(cred_row.get("unknown", 0)),
            },
            "conditional_access": {
                "covered": int(ca_row.get("covered", 0)),
                "not_covered": int(ca_row.get("not_covered", 0)),
                "total": int(ca_row.get("total", 0)),
            },
            "top_risks": top_risks,
            "remediation_summary": {
                "total_actions": len(remediation_list),
                "by_category": by_category,
                "by_impact": by_impact,
                "quick_wins": quick_wins[:5],
                "top_priorities": remediation_list[:10],
            },
            "evidence": {
                "sources": {
                    "identity": "Microsoft Graph API /servicePrincipals or /users",
                    "roles_azure": "Azure Resource Manager /roleAssignments",
                    "roles_entra": "Microsoft Graph API /roleManagement/directory",
                    "permissions": "Microsoft Graph API /servicePrincipals/{id}/appRoleAssignments",
                    "credentials": "Microsoft Graph API /applications/{id}/passwordCredentials + keyCredentials",
                    "owners": "Microsoft Graph API /servicePrincipals/{id}/owners",
                    "pim": "Microsoft Graph API /roleManagement/directory/roleEligibilityScheduleInstances",
                    "ca_policies": "Microsoft Graph API /identity/conditionalAccess/policies",
                },
            },
        }

    # ========================================================================
    # Phase 14: Drift Detection & Change Tracking
    # ========================================================================

    def save_drift_report(self, current_run_id: int, previous_run_id: int, changes: Dict) -> int:
        """Persist a drift comparison result. Returns drift_report ID."""
        cursor = self.conn.cursor()

        new_count = len(changes.get('new_identities', []))
        removed_count = len(changes.get('removed_identities', []))
        perm_count = len(changes.get('permission_changes', []))
        risk_count = len(changes.get('risk_changes', []))
        cred_count = len(changes.get('credential_changes', []))
        total = new_count + removed_count + perm_count + risk_count + cred_count

        cursor.execute("""
            INSERT INTO drift_reports (
                current_run_id, previous_run_id,
                new_identities_count, removed_identities_count,
                permission_changes_count, risk_changes_count,
                credential_changes_count, total_changes,
                changes
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (current_run_id, previous_run_id) DO UPDATE SET
                new_identities_count = EXCLUDED.new_identities_count,
                removed_identities_count = EXCLUDED.removed_identities_count,
                permission_changes_count = EXCLUDED.permission_changes_count,
                risk_changes_count = EXCLUDED.risk_changes_count,
                credential_changes_count = EXCLUDED.credential_changes_count,
                total_changes = EXCLUDED.total_changes,
                changes = EXCLUDED.changes,
                created_at = NOW()
            RETURNING id
        """, (
            current_run_id, previous_run_id,
            new_count, removed_count, perm_count, risk_count, cred_count, total,
            json.dumps(changes, default=str)
        ))

        report_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return report_id

    def get_drift_report(self, run_id: int) -> Optional[Dict]:
        """Get the drift report where current_run_id = run_id. Returns None if not found."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, current_run_id, previous_run_id,
                   new_identities_count, removed_identities_count,
                   permission_changes_count, risk_changes_count,
                   credential_changes_count, total_changes,
                   changes, created_at
            FROM drift_reports
            WHERE current_run_id = %s
        """, (run_id,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def get_latest_drift_report(self) -> Optional[Dict]:
        """Get the most recent drift report summary (no full changes JSONB)."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, current_run_id, previous_run_id,
                   new_identities_count, removed_identities_count,
                   permission_changes_count, risk_changes_count,
                   credential_changes_count, total_changes,
                   created_at
            FROM drift_reports
            ORDER BY created_at DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def get_drift_history(self, limit: int = 20) -> List[Dict]:
        """Get drift report summaries ordered by most recent."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT dr.id, dr.current_run_id, dr.previous_run_id,
                   dr.new_identities_count, dr.removed_identities_count,
                   dr.permission_changes_count, dr.risk_changes_count,
                   dr.credential_changes_count, dr.total_changes,
                   dr.created_at,
                   r.completed_at as run_completed_at
            FROM drift_reports dr
            JOIN discovery_runs r ON r.id = dr.current_run_id
            ORDER BY dr.created_at DESC
            LIMIT %s
        """, (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    # ========================================================================
    # Phase 15: Settings & Configuration
    # ========================================================================

    def get_settings(self, tenant_id=None) -> Dict[str, str]:
        """Returns all settings as a key-value dict, optionally scoped by tenant."""
        cursor = self.conn.cursor()
        if tenant_id is not None:
            cursor.execute("SELECT key, value FROM settings WHERE tenant_id = %s ORDER BY key", (tenant_id,))
        else:
            cursor.execute("SELECT key, value FROM settings ORDER BY key")
        result = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.close()
        return result

    def get_setting(self, key: str, default: Optional[str] = None, tenant_id=None) -> Optional[str]:
        """Returns a single setting value, or default if not found."""
        cursor = self.conn.cursor()
        if tenant_id is not None:
            cursor.execute("SELECT value FROM settings WHERE key = %s AND tenant_id = %s", (key, tenant_id))
        else:
            cursor.execute("SELECT value FROM settings WHERE key = %s", (key,))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else default

    def save_settings(self, settings_dict: Dict[str, str], tenant_id=None) -> None:
        """Upsert multiple settings in one call, optionally scoped by tenant."""
        cursor = self.conn.cursor()
        for key, value in settings_dict.items():
            if tenant_id is not None:
                cursor.execute("""
                    INSERT INTO settings (key, value, tenant_id, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (tenant_id, key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = NOW()
                """, (key, value, tenant_id))
            else:
                # No tenant context — ON CONFLICT won't match NULLs, so DELETE+INSERT
                cursor.execute("DELETE FROM settings WHERE key = %s AND tenant_id IS NULL", (key,))
                cursor.execute("INSERT INTO settings (key, value, updated_at) VALUES (%s, %s, NOW())", (key, value))
        self.conn.commit()
        cursor.close()

    # ========================================================================
    # Phase 17: Activity Log & Audit Trail
    # ========================================================================

    def _ensure_activity_log_table(self):
        """Create activity_log table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id SERIAL PRIMARY KEY,
                action_type VARCHAR(50) NOT NULL,
                description TEXT NOT NULL,
                metadata JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_action_type ON activity_log(action_type)")
        # Phase 46: Add user_id and tenant_id columns
        cursor.execute("ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS user_id INTEGER")
        cursor.execute("ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS tenant_id INTEGER")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_tenant_id ON activity_log(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id)")
        self.conn.commit()
        cursor.close()

    def log_activity(self, action_type: str, description: str, metadata: dict = None,
                     user_id: int = None, tenant_id: int = None):
        """Append an entry to the activity log. Never raises — errors are logged only."""
        try:
            self._ensure_activity_log_table()
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO activity_log (action_type, description, metadata, user_id, tenant_id, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (
                action_type,
                description,
                json.dumps(metadata) if metadata else None,
                user_id,
                tenant_id,
            ))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            print(f"Warning: Failed to log activity: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass

    def get_activity_log(self, limit: int = 50, offset: int = 0,
                         action_type: str = None, tenant_id: int = None) -> list:
        """Get activity log entries, most recent first. Optionally filtered by tenant."""
        self._ensure_activity_log_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        query = """
            SELECT a.id, a.action_type, a.description, a.metadata, a.created_at,
                   a.user_id, a.tenant_id,
                   u.username AS user_username, u.display_name AS user_display_name
            FROM activity_log a
            LEFT JOIN users u ON u.id = a.user_id
        """
        conditions: list = []
        params: list = []

        if action_type:
            conditions.append("a.action_type = %s")
            params.append(action_type)
        if tenant_id is not None:
            conditions.append("a.tenant_id = %s")
            params.append(tenant_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

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

    # ========================================================================
    # Phase 21: Remediation Action Tracking
    # ========================================================================

    def _ensure_remediation_actions_table(self):
        """Create remediation_actions table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id SERIAL PRIMARY KEY,
                identity_id TEXT NOT NULL,
                playbook_id INTEGER NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'open',
                notes TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(identity_id, playbook_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_actions_identity ON remediation_actions(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_actions_status ON remediation_actions(status)")
        # Phase 58: execution tracking columns
        for col, typedef in [
            ('execution_status', "VARCHAR(20) DEFAULT NULL"),
            ('execution_log', "JSONB DEFAULT NULL"),
            ('executed_at', "TIMESTAMPTZ DEFAULT NULL"),
            ('executed_by', "INTEGER DEFAULT NULL"),
        ]:
            try:
                cursor.execute(f"ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS {col} {typedef}")
            except Exception:
                self.conn.rollback()
        self.conn.commit()
        cursor.close()

    def upsert_remediation_action(self, identity_id: str, playbook_id: int, status: str, notes: str = None):
        """Create or update a remediation action for an identity/playbook pair."""
        self._ensure_remediation_actions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO remediation_actions (identity_id, playbook_id, status, notes, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (identity_id, playbook_id) DO UPDATE SET
                status = EXCLUDED.status,
                notes = EXCLUDED.notes,
                updated_at = NOW()
            RETURNING id, identity_id, playbook_id, status, notes, created_at, updated_at
        """, (identity_id, playbook_id, status, notes))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        return row

    def bulk_upsert_remediation_actions(self, identity_ids, status, notes=None):
        """
        Apply a remediation status to all matched playbooks for multiple identities.
        For each identity: fetch matched playbooks, then upsert actions.
        Returns { updated_count, identity_count, errors }.
        """
        self._ensure_remediation_actions_table()
        self._ensure_remediation_playbooks()
        updated_count = 0
        identity_count = 0
        errors = []

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        for identity_id in identity_ids:
            try:
                # Fetch identity data (latest run)
                cursor.execute("""
                    SELECT i.id, i.identity_id, i.display_name, i.risk_level,
                           i.risk_reasons, i.activity_status, i.credential_status,
                           i.credential_risk, COALESCE(i.owner_count, 0) as owner_count,
                           i.ca_coverage_status
                    FROM identities i
                    WHERE i.identity_id = %s
                    ORDER BY i.discovery_run_id DESC
                    LIMIT 1
                """, (identity_id,))
                row = cursor.fetchone()
                if not row:
                    continue

                identity_db_id = row['id']

                # Get roles
                cursor.execute("""
                    SELECT role_name FROM role_assignments WHERE identity_db_id = %s
                    UNION ALL
                    SELECT role_name FROM entra_role_assignments WHERE identity_db_id = %s
                """, (identity_db_id, identity_db_id))
                roles = [{"role_name": r['role_name']} for r in cursor.fetchall()]

                # Parse risk_reasons
                risk_reasons = row['risk_reasons']
                if isinstance(risk_reasons, str):
                    import json as _json
                    try:
                        risk_reasons = _json.loads(risk_reasons)
                    except Exception:
                        risk_reasons = []
                elif not isinstance(risk_reasons, list):
                    risk_reasons = []

                identity_data = {
                    "risk_reasons": risk_reasons,
                    "roles": roles,
                    "activity_status": row['activity_status'],
                    "credential_status": row['credential_status'],
                    "credential_risk": row['credential_risk'],
                    "owner_count": row['owner_count'],
                    "ca_coverage_status": row['ca_coverage_status'],
                }

                # Get matched playbooks
                result = self.get_identity_remediations(identity_db_id, identity_data)
                matched = result.get('remediations', [])

                if not matched:
                    continue

                identity_count += 1

                # Upsert action for each matched playbook
                for pb in matched:
                    cursor.execute("""
                        INSERT INTO remediation_actions (identity_id, playbook_id, status, notes, updated_at)
                        VALUES (%s, %s, %s, %s, NOW())
                        ON CONFLICT (identity_id, playbook_id) DO UPDATE SET
                            status = EXCLUDED.status,
                            notes = EXCLUDED.notes,
                            updated_at = NOW()
                    """, (identity_id, pb['id'], status, notes))
                    updated_count += 1

            except Exception as e:
                errors.append({"identity_id": identity_id, "error": str(e)[:100]})

        self.conn.commit()
        cursor.close()

        return {
            "updated_count": updated_count,
            "identity_count": identity_count,
            "errors": errors,
        }

    def get_remediation_actions(self, identity_id: str):
        """Get all remediation action statuses for an identity."""
        self._ensure_remediation_actions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT playbook_id, status, notes, updated_at,
                   execution_status, execution_log, executed_at
            FROM remediation_actions
            WHERE identity_id = %s
        """, (identity_id,))
        rows = cursor.fetchall()
        cursor.close()
        result = {}
        for row in rows:
            result[row['playbook_id']] = {
                'status': row['status'],
                'notes': row['notes'],
                'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None,
                'execution_status': row.get('execution_status'),
                'execution_log': row.get('execution_log'),
                'executed_at': row['executed_at'].isoformat() if row.get('executed_at') else None,
            }
        return result

    def get_remediation_summary(self):
        """Get aggregated remediation action status counts across all identities."""
        self._ensure_remediation_actions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'open') as open,
                COUNT(*) FILTER (WHERE status = 'acknowledged') as acknowledged,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'skipped') as skipped,
                COUNT(*) as total
            FROM remediation_actions
        """)
        row = cursor.fetchone()
        cursor.close()

        total = int(row['total']) if row else 0
        completed = int(row['completed']) if row else 0
        completion_pct = round((completed / total) * 100, 1) if total > 0 else 0

        return {
            'open': int(row['open']) if row else 0,
            'acknowledged': int(row['acknowledged']) if row else 0,
            'completed': completed,
            'skipped': int(row['skipped']) if row else 0,
            'total': total,
            'completion_pct': completion_pct,
        }

    # ── Phase 58: Compliance Auto-Remediation ──────────────────────────

    def execute_remediation_action(self, identity_id: str, playbook_id: int,
                                    execution_status: str, execution_log: dict,
                                    user_id: int = None) -> dict:
        """Record a remediation execution (simulated or real)."""
        self._ensure_remediation_actions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO remediation_actions
                (identity_id, playbook_id, status, execution_status, execution_log, executed_at, executed_by, updated_at)
            VALUES (%s, %s, 'completed', %s, %s, NOW(), %s, NOW())
            ON CONFLICT (identity_id, playbook_id) DO UPDATE SET
                status = 'completed',
                execution_status = EXCLUDED.execution_status,
                execution_log = EXCLUDED.execution_log,
                executed_at = NOW(),
                executed_by = EXCLUDED.executed_by,
                updated_at = NOW()
            RETURNING *
        """, (identity_id, playbook_id, execution_status, json.dumps(execution_log), user_id))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        return row

    def get_remediation_queue(self, status_filter=None, impact_filter=None,
                               category_filter=None, limit=100):
        """Get pending remediations across all identities with playbook + identity info."""
        self._ensure_remediation_actions_table()
        self._ensure_remediation_playbooks()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        sql = """
            SELECT i.identity_id, i.display_name, i.risk_level, i.risk_score,
                   i.identity_category, i.activity_status,
                   rp.id as playbook_id, rp.title as playbook_title,
                   rp.impact, rp.effort, rp.category, rp.priority_score,
                   ra.status as action_status, ra.execution_status,
                   ra.executed_at, ra.updated_at
            FROM remediation_actions ra
            JOIN identities i ON i.identity_id = ra.identity_id
                AND i.discovery_run_id = (SELECT MAX(discovery_run_id) FROM identities)
            JOIN remediation_playbooks rp ON rp.id = ra.playbook_id
            WHERE 1=1
        """
        params = []

        if status_filter:
            sql += " AND ra.status = %s"
            params.append(status_filter)
        if impact_filter:
            sql += " AND rp.impact = %s"
            params.append(impact_filter)
        if category_filter:
            sql += " AND rp.category = %s"
            params.append(category_filter)

        sql += " ORDER BY rp.priority_score DESC, rp.impact ASC LIMIT %s"
        params.append(limit)

        cursor.execute(sql, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()

        for r in rows:
            for ts in ('executed_at', 'updated_at'):
                if r.get(ts) and hasattr(r[ts], 'isoformat'):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_role_usage_stats(self):
        """Aggregate usage_status and risk_level counts across all role assignments from latest run."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT MAX(discovery_run_id) FROM identities")
        row = cursor.fetchone()
        latest_run = row['max'] if row else None
        if not latest_run:
            cursor.close()
            return {'statuses': {}, 'by_risk': {}, 'total': 0}

        # Count by usage_status (RBAC + Entra combined)
        cursor.execute("""
            SELECT COALESCE(r.usage_status, 'unknown') as status, COUNT(*) as count
            FROM role_assignments r
            JOIN identities i ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY COALESCE(r.usage_status, 'unknown')
            UNION ALL
            SELECT COALESCE(e.usage_status, 'unknown') as status, COUNT(*) as count
            FROM entra_role_assignments e
            JOIN identities i ON e.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY COALESCE(e.usage_status, 'unknown')
        """, (latest_run, latest_run))
        rows = cursor.fetchall()
        merged = {}
        for r in rows:
            merged[r['status']] = merged.get(r['status'], 0) + r['count']
        total = sum(merged.values())

        # Count by risk_level
        cursor.execute("""
            SELECT COALESCE(r.risk_level, 'unknown') as risk, COUNT(*) as count
            FROM role_assignments r
            JOIN identities i ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY COALESCE(r.risk_level, 'unknown')
            UNION ALL
            SELECT COALESCE(e.risk_level, 'unknown') as risk, COUNT(*) as count
            FROM entra_role_assignments e
            JOIN identities i ON e.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY COALESCE(e.risk_level, 'unknown')
        """, (latest_run, latest_run))
        risk_rows = cursor.fetchall()
        risk_merged = {}
        for r in risk_rows:
            risk_merged[r['risk']] = risk_merged.get(r['risk'], 0) + r['count']

        cursor.close()
        return {'statuses': merged, 'by_risk': risk_merged, 'total': total}

    # ========================================================================
    # Role Mining & Optimization (Phase 37)
    # ========================================================================

    @staticmethod
    def _role_mining_recommendation(finding_type, role_name, redundant_with):
        if finding_type == 'definitely_unused':
            return f'Remove "{role_name}" — confirmed unused'
        elif finding_type == 'likely_unused':
            return f'Review and likely remove "{role_name}" — appears unused'
        elif finding_type == 'redundant':
            return f'Remove "{role_name}" — superseded by "{redundant_with}"'
        elif finding_type == 'orphaned':
            return f'Remove "{role_name}" — target resource no longer exists'
        elif finding_type == 'overprivileged':
            return f'Review "{role_name}" — high-privilege role with low usage signals'
        return f'Review "{role_name}"'

    def get_role_mining_data(self) -> dict:
        """Compute role mining & optimization insights from latest discovery run."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("SELECT MAX(discovery_run_id) as max FROM identities")
        row = cursor.fetchone()
        latest_run = row['max'] if row else None
        if not latest_run:
            cursor.close()
            return {
                'summary': {'total_roles': 0, 'unused': 0, 'redundant': 0, 'orphaned': 0, 'overprivileged': 0, 'optimization_pct': 0},
                'findings': [], 'role_frequency': [], 'role_bundles': [],
            }

        # Findings: UNION ALL across categories
        cursor.execute("""
            -- UNUSED (RBAC)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   r.role_name, 'azure' as source, r.usage_status as finding_type,
                   COALESCE(r.risk_level,'unknown') as risk_level, r.days_since_assigned,
                   r.redundant_with, r.scope
            FROM role_assignments r JOIN identities i ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND r.usage_status IN ('definitely_unused','likely_unused')
            UNION ALL
            -- UNUSED (Entra)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   e.role_name, 'entra' as source, e.usage_status as finding_type,
                   COALESCE(e.risk_level,'unknown') as risk_level, e.days_since_assigned,
                   e.redundant_with, e.directory_scope as scope
            FROM entra_role_assignments e JOIN identities i ON e.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND e.usage_status IN ('definitely_unused','likely_unused')
            UNION ALL
            -- REDUNDANT (RBAC)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   r.role_name, 'azure' as source, 'redundant' as finding_type,
                   COALESCE(r.risk_level,'unknown') as risk_level, r.days_since_assigned,
                   r.redundant_with, r.scope
            FROM role_assignments r JOIN identities i ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND r.redundant_with IS NOT NULL
              AND COALESCE(r.usage_status,'unknown') NOT IN ('definitely_unused','likely_unused')
            UNION ALL
            -- REDUNDANT (Entra)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   e.role_name, 'entra' as source, 'redundant' as finding_type,
                   COALESCE(e.risk_level,'unknown') as risk_level, e.days_since_assigned,
                   e.redundant_with, e.directory_scope as scope
            FROM entra_role_assignments e JOIN identities i ON e.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND e.redundant_with IS NOT NULL
              AND COALESCE(e.usage_status,'unknown') NOT IN ('definitely_unused','likely_unused')
            UNION ALL
            -- ORPHANED (RBAC only)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   r.role_name, 'azure' as source, 'orphaned' as finding_type,
                   COALESCE(r.risk_level,'unknown') as risk_level, r.days_since_assigned,
                   r.redundant_with, r.scope
            FROM role_assignments r JOIN identities i ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND r.scope_exists = false
              AND COALESCE(r.usage_status,'unknown') NOT IN ('definitely_unused','likely_unused')
              AND r.redundant_with IS NULL
            UNION ALL
            -- OVERPRIVILEGED (RBAC)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   r.role_name, 'azure' as source, 'overprivileged' as finding_type,
                   COALESCE(r.risk_level,'unknown') as risk_level, r.days_since_assigned,
                   r.redundant_with, r.scope
            FROM role_assignments r JOIN identities i ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND r.risk_level IN ('critical','high')
              AND COALESCE(r.usage_status,'unknown') NOT IN ('assumed_active','definitely_unused','likely_unused')
              AND COALESCE(r.scope_exists, true) = true AND r.redundant_with IS NULL
            UNION ALL
            -- OVERPRIVILEGED (Entra)
            SELECT i.identity_id, i.display_name, COALESCE(i.identity_category,'') as identity_category,
                   e.role_name, 'entra' as source, 'overprivileged' as finding_type,
                   COALESCE(e.risk_level,'unknown') as risk_level, e.days_since_assigned,
                   e.redundant_with, e.directory_scope as scope
            FROM entra_role_assignments e JOIN identities i ON e.identity_db_id = i.id
            WHERE i.discovery_run_id = %s AND e.risk_level IN ('critical','high')
              AND COALESCE(e.usage_status,'unknown') NOT IN ('assumed_active','definitely_unused','likely_unused')
              AND e.redundant_with IS NULL
        """, (latest_run,) * 7)
        findings_raw = cursor.fetchall()

        findings = []
        for f in findings_raw:
            findings.append({
                'identity_id': f['identity_id'],
                'identity_name': f['display_name'],
                'identity_category': f['identity_category'],
                'role_name': f['role_name'],
                'source': f['source'],
                'type': f['finding_type'],
                'risk_level': f['risk_level'],
                'days_since_assigned': f['days_since_assigned'],
                'scope': f['scope'],
                'recommendation': self._role_mining_recommendation(f['finding_type'], f['role_name'], f.get('redundant_with')),
            })

        # Role frequency: top 10
        cursor.execute("""
            SELECT role_name, source, COUNT(*) as assignment_count FROM (
                SELECT r.role_name, 'azure' as source FROM role_assignments r
                JOIN identities i ON r.identity_db_id = i.id WHERE i.discovery_run_id = %s
                UNION ALL
                SELECT e.role_name, 'entra' as source FROM entra_role_assignments e
                JOIN identities i ON e.identity_db_id = i.id WHERE i.discovery_run_id = %s
            ) combined GROUP BY role_name, source ORDER BY assignment_count DESC LIMIT 10
        """, (latest_run, latest_run))
        role_frequency = [dict(r) for r in cursor.fetchall()]

        # Total roles
        cursor.execute("""
            SELECT (
                SELECT COUNT(*) FROM role_assignments r JOIN identities i ON r.identity_db_id = i.id WHERE i.discovery_run_id = %s
            ) + (
                SELECT COUNT(*) FROM entra_role_assignments e JOIN identities i ON e.identity_db_id = i.id WHERE i.discovery_run_id = %s
            ) as total
        """, (latest_run, latest_run))
        total_roles = cursor.fetchone()['total']

        # Role bundles: co-assigned pairs
        cursor.execute("""
            WITH identity_roles AS (
                SELECT r.identity_db_id, r.role_name FROM role_assignments r
                JOIN identities i ON r.identity_db_id = i.id WHERE i.discovery_run_id = %s
                UNION ALL
                SELECT e.identity_db_id, e.role_name FROM entra_role_assignments e
                JOIN identities i ON e.identity_db_id = i.id WHERE i.discovery_run_id = %s
            )
            SELECT a.role_name as role_a, b.role_name as role_b, COUNT(DISTINCT a.identity_db_id) as co_count
            FROM identity_roles a JOIN identity_roles b
              ON a.identity_db_id = b.identity_db_id AND a.role_name < b.role_name
            GROUP BY a.role_name, b.role_name HAVING COUNT(DISTINCT a.identity_db_id) >= 2
            ORDER BY co_count DESC LIMIT 10
        """, (latest_run, latest_run))
        role_bundles = [dict(r) for r in cursor.fetchall()]

        cursor.close()

        unused = sum(1 for f in findings if f['type'] in ('definitely_unused', 'likely_unused'))
        redundant = sum(1 for f in findings if f['type'] == 'redundant')
        orphaned = sum(1 for f in findings if f['type'] == 'orphaned')
        overprivileged = sum(1 for f in findings if f['type'] == 'overprivileged')
        actionable = unused + redundant + orphaned + overprivileged
        optimization_pct = round(actionable / total_roles * 100) if total_roles > 0 else 0

        return {
            'summary': {
                'total_roles': total_roles, 'unused': unused, 'redundant': redundant,
                'orphaned': orphaned, 'overprivileged': overprivileged, 'optimization_pct': optimization_pct,
            },
            'findings': findings,
            'role_frequency': role_frequency,
            'role_bundles': role_bundles,
        }

    # ========================================================================
    # Phase 28: Webhook & Alert Integration
    # ========================================================================

    def _ensure_webhook_tables(self):
        """Create webhooks and webhook_deliveries tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                url TEXT NOT NULL,
                secret VARCHAR(255),
                event_types TEXT[] NOT NULL DEFAULT '{}',
                headers JSONB,
                enabled BOOLEAN DEFAULT true,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id SERIAL PRIMARY KEY,
                webhook_id INTEGER REFERENCES webhooks(id) ON DELETE CASCADE,
                event_type VARCHAR(50) NOT NULL,
                payload JSONB NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                http_status INTEGER,
                response_body TEXT,
                attempts INTEGER DEFAULT 0,
                next_retry_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                delivered_at TIMESTAMPTZ
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id)")
        self.conn.commit()
        cursor.close()

    def get_webhooks(self) -> list:
        """Get all webhooks with recent delivery stats."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT w.*,
                   (SELECT COUNT(*) FROM webhook_deliveries d WHERE d.webhook_id = w.id) as total_deliveries,
                   (SELECT COUNT(*) FROM webhook_deliveries d WHERE d.webhook_id = w.id AND d.status = 'delivered') as successful_deliveries,
                   (SELECT MAX(d.delivered_at) FROM webhook_deliveries d WHERE d.webhook_id = w.id AND d.status = 'delivered') as last_delivered_at
            FROM webhooks w
            ORDER BY w.created_at DESC
        """)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            r['created_at'] = r['created_at'].isoformat() if r.get('created_at') else None
            r['updated_at'] = r['updated_at'].isoformat() if r.get('updated_at') else None
            r['last_delivered_at'] = r['last_delivered_at'].isoformat() if r.get('last_delivered_at') else None
        return rows

    def get_webhook(self, webhook_id: int) -> dict:
        """Get a single webhook by ID."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM webhooks WHERE id = %s", (webhook_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    def create_webhook(self, name: str, url: str, secret: str, event_types: list, headers: dict = None) -> dict:
        """Create a new webhook configuration."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO webhooks (name, url, secret, event_types, headers, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            RETURNING *
        """, (name, url, secret or None, event_types, json.dumps(headers) if headers else None))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        row['created_at'] = row['created_at'].isoformat() if row.get('created_at') else None
        row['updated_at'] = row['updated_at'].isoformat() if row.get('updated_at') else None
        return row

    def update_webhook(self, webhook_id: int, **fields) -> dict:
        """Update specific fields on a webhook."""
        self._ensure_webhook_tables()
        allowed = {'name', 'url', 'secret', 'event_types', 'headers', 'enabled'}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_webhook(webhook_id)

        set_parts = []
        params = []
        for key, val in updates.items():
            if key == 'headers':
                set_parts.append(f"{key} = %s")
                params.append(json.dumps(val) if val else None)
            else:
                set_parts.append(f"{key} = %s")
                params.append(val)
        set_parts.append("updated_at = NOW()")
        params.append(webhook_id)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE webhooks SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    def delete_webhook(self, webhook_id: int) -> bool:
        """Delete a webhook and its delivery history (CASCADE)."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM webhooks WHERE id = %s", (webhook_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def get_webhooks_for_event(self, event_type: str) -> list:
        """Get all enabled webhooks that subscribe to a specific event type."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM webhooks
            WHERE enabled = true AND %s = ANY(event_types)
        """, (event_type,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    def create_webhook_delivery(self, webhook_id: int, event_type: str, payload: dict) -> int:
        """Create a webhook delivery record."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status, created_at)
            VALUES (%s, %s, %s, 'pending', NOW())
            RETURNING id
        """, (webhook_id, event_type, json.dumps(payload)))
        delivery_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return delivery_id

    def update_webhook_delivery(self, delivery_id: int, status: str, http_status: int = None, response_body: str = None):
        """Update delivery status after attempt."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE webhook_deliveries
            SET status = %s, http_status = %s, response_body = %s,
                attempts = attempts + 1,
                delivered_at = CASE WHEN %s = 'delivered' THEN NOW() ELSE delivered_at END
            WHERE id = %s
        """, (status, http_status, response_body, status, delivery_id))
        self.conn.commit()
        cursor.close()

    def get_webhook_deliveries(self, webhook_id: int, limit: int = 20) -> list:
        """Get recent deliveries for a webhook."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, event_type, status, http_status, attempts, created_at, delivered_at
            FROM webhook_deliveries
            WHERE webhook_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (webhook_id, limit))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            r['created_at'] = r['created_at'].isoformat() if r.get('created_at') else None
            r['delivered_at'] = r['delivered_at'].isoformat() if r.get('delivered_at') else None
        return rows

    # ========================================================================
    # Phase 29: Custom Risk Rule Engine
    # ========================================================================

    def _ensure_custom_risk_rules_table(self):
        """Create custom_risk_rules table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS custom_risk_rules (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                conditions JSONB NOT NULL,
                action_type VARCHAR(20) NOT NULL DEFAULT 'adjust_points',
                points_adjustment INTEGER DEFAULT 0,
                force_level VARCHAR(20),
                reason_text TEXT,
                enabled BOOLEAN DEFAULT true,
                priority INTEGER DEFAULT 100,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        self.conn.commit()
        cursor.close()

    def get_custom_risk_rules(self) -> list:
        """Get all custom risk rules ordered by priority."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM custom_risk_rules ORDER BY priority, id")
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            r['created_at'] = r['created_at'].isoformat() if r.get('created_at') else None
            r['updated_at'] = r['updated_at'].isoformat() if r.get('updated_at') else None
        return rows

    def get_custom_risk_rule(self, rule_id: int) -> dict:
        """Get a single custom risk rule by ID."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM custom_risk_rules WHERE id = %s", (rule_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    def create_custom_risk_rule(self, name, description, conditions, action_type,
                                 points_adjustment, force_level, reason_text, priority) -> dict:
        """Create a new custom risk rule."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO custom_risk_rules
                (name, description, conditions, action_type, points_adjustment, force_level, reason_text, priority, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            RETURNING *
        """, (name, description, json.dumps(conditions), action_type,
              points_adjustment or 0, force_level, reason_text, priority or 100))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        row['created_at'] = row['created_at'].isoformat() if row.get('created_at') else None
        row['updated_at'] = row['updated_at'].isoformat() if row.get('updated_at') else None
        return row

    def update_custom_risk_rule(self, rule_id: int, **fields) -> dict:
        """Update specific fields on a custom risk rule."""
        self._ensure_custom_risk_rules_table()
        allowed = {'name', 'description', 'conditions', 'action_type', 'points_adjustment',
                   'force_level', 'reason_text', 'enabled', 'priority'}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_custom_risk_rule(rule_id)

        set_parts = []
        params = []
        for key, val in updates.items():
            if key == 'conditions':
                set_parts.append(f"{key} = %s")
                params.append(json.dumps(val) if isinstance(val, (dict, list)) else val)
            else:
                set_parts.append(f"{key} = %s")
                params.append(val)
        set_parts.append("updated_at = NOW()")
        params.append(rule_id)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE custom_risk_rules SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    def delete_custom_risk_rule(self, rule_id: int) -> bool:
        """Delete a custom risk rule."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM custom_risk_rules WHERE id = %s", (rule_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def get_enabled_risk_rules(self) -> list:
        """Get only enabled custom risk rules, ordered by priority."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM custom_risk_rules WHERE enabled = true ORDER BY priority, id")
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    # ================================================================
    # Phase 30: Notifications
    # ================================================================

    def _ensure_notifications_table(self):
        """Create notifications table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                event_type VARCHAR(50) NOT NULL,
                category VARCHAR(30) NOT NULL,
                severity VARCHAR(20) NOT NULL DEFAULT 'info',
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                payload JSONB,
                related_identity_id TEXT,
                related_identity_name VARCHAR(255),
                related_run_id INTEGER,
                read BOOLEAN DEFAULT false,
                read_at TIMESTAMPTZ,
                actioned BOOLEAN DEFAULT false,
                action_type VARCHAR(50),
                action_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_read_created ON notifications(read, created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_severity ON notifications(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_category ON notifications(category)")
        cursor.execute("ALTER TABLE notifications ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_tenant ON notifications(tenant_id)")
        self.conn.commit()
        cursor.close()

    def get_notifications(self, limit=50, offset=0, read=None, severity=None, category=None, tenant_id=None) -> list:
        """Get notifications with optional filters."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        conditions = []
        params = []
        if tenant_id is not None:
            conditions.append("tenant_id = %s")
            params.append(tenant_id)
        if read is not None:
            conditions.append("read = %s")
            params.append(read)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if category:
            conditions.append("category = %s")
            params.append(category)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])
        cursor.execute(f"""
            SELECT * FROM notifications {where}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts_field in ('created_at', 'read_at', 'action_at'):
                if r.get(ts_field):
                    r[ts_field] = r[ts_field].isoformat()
        return rows

    def get_notification(self, notification_id: int) -> dict:
        """Get a single notification by ID."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM notifications WHERE id = %s", (notification_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts_field in ('created_at', 'read_at', 'action_at'):
            if result.get(ts_field):
                result[ts_field] = result[ts_field].isoformat()
        return result

    def get_notification_stats(self, tenant_id=None) -> dict:
        """Get notification statistics (unread count, by severity, by category)."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        tenant_filter = ""
        tenant_params: list = []
        if tenant_id is not None:
            tenant_filter = " AND tenant_id = %s"
            tenant_params = [tenant_id]
        cursor.execute(f"SELECT COUNT(*) as total FROM notifications WHERE true{tenant_filter}", tenant_params)
        total = cursor.fetchone()['total']
        cursor.execute(f"SELECT COUNT(*) as unread FROM notifications WHERE read = false{tenant_filter}", tenant_params)
        unread = cursor.fetchone()['unread']
        cursor.execute(f"SELECT severity, COUNT(*) as cnt FROM notifications WHERE read = false{tenant_filter} GROUP BY severity", tenant_params)
        by_severity = {r['severity']: r['cnt'] for r in cursor.fetchall()}
        cursor.execute(f"SELECT category, COUNT(*) as cnt FROM notifications WHERE read = false{tenant_filter} GROUP BY category", tenant_params)
        by_category = {r['category']: r['cnt'] for r in cursor.fetchall()}
        cursor.close()
        return {'total': total, 'unread': unread, 'by_severity': by_severity, 'by_category': by_category}

    def create_notification(self, event_type, category, severity, title, description,
                            payload=None, related_identity_id=None, related_identity_name=None,
                            related_run_id=None, tenant_id=None) -> dict:
        """Create a new notification."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO notifications
                (event_type, category, severity, title, description, payload,
                 related_identity_id, related_identity_name, related_run_id, tenant_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (event_type, category, severity, title, description,
              json.dumps(payload) if payload else None,
              related_identity_id, related_identity_name, related_run_id, tenant_id))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts_field in ('created_at', 'read_at', 'action_at'):
            if row.get(ts_field):
                row[ts_field] = row[ts_field].isoformat()
        return row

    def mark_notification_read(self, notification_id: int) -> dict:
        """Mark a notification as read."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE notifications SET read = true, read_at = NOW()
            WHERE id = %s RETURNING *
        """, (notification_id,))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts_field in ('created_at', 'read_at', 'action_at'):
            if result.get(ts_field):
                result[ts_field] = result[ts_field].isoformat()
        return result

    def mark_all_notifications_read(self, tenant_id=None) -> int:
        """Mark all unread notifications as read. Returns count updated."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor()
        if tenant_id is not None:
            cursor.execute("UPDATE notifications SET read = true, read_at = NOW() WHERE read = false AND tenant_id = %s", (tenant_id,))
        else:
            cursor.execute("UPDATE notifications SET read = true, read_at = NOW() WHERE read = false")
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    def action_notification(self, notification_id: int, action_type: str) -> dict:
        """Mark a notification as actioned (acknowledged/dismissed)."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE notifications SET actioned = true, action_type = %s, action_at = NOW(),
                   read = true, read_at = COALESCE(read_at, NOW())
            WHERE id = %s RETURNING *
        """, (action_type, notification_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts_field in ('created_at', 'read_at', 'action_at'):
            if result.get(ts_field):
                result[ts_field] = result[ts_field].isoformat()
        return result

    def delete_notification(self, notification_id: int) -> bool:
        """Delete a single notification."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM notifications WHERE id = %s", (notification_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def cleanup_old_notifications(self, days=90) -> int:
        """Delete notifications older than N days."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM notifications WHERE created_at < NOW() - INTERVAL '%s days'", (days,))
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    # ================================================================
    # Phase 31: Authentication & RBAC
    # ================================================================

    _users_ensured = False

    def _ensure_users_table(self):
        """Create users and refresh_tokens tables if they don't exist."""
        if Database._users_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                display_name VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'viewer',
                enabled BOOLEAN DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                last_login_at TIMESTAMPTZ,
                created_by INTEGER,
                tenant_id INTEGER,
                is_superadmin BOOLEAN DEFAULT false
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(255) NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                revoked BOOLEAN DEFAULT false
            )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)")
        # Phase 54: SSO columns
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20) DEFAULT 'local'")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id VARCHAR(500)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id)")
        # Phase 54: SSO one-time auth codes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sso_auth_codes (
                id SERIAL PRIMARY KEY,
                code VARCHAR(128) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tenant_id INTEGER,
                used BOOLEAN DEFAULT false,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sso_codes_code ON sso_auth_codes(code)")
        # Phase 78: force_password_change column
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN DEFAULT false")
        # Phase 78: Role migration — auditor→reader, viewer→compliance
        cursor.execute("UPDATE users SET role = 'reader' WHERE role = 'auditor'")
        cursor.execute("UPDATE users SET role = 'compliance' WHERE role = 'viewer'")
        # Phase 84: Root user, password reset, account lockout columns
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_root_user BOOLEAN DEFAULT false")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token TEXT")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMPTZ")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ")
        # Phase 84: Admin audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id SERIAL PRIMARY KEY,
                admin_user_id INTEGER,
                action TEXT NOT NULL,
                target_user_id INTEGER,
                target_tenant_id INTEGER,
                details JSONB DEFAULT '{}',
                ip_address TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_target_user ON admin_audit_log(target_user_id)")
        self.conn.commit()
        cursor.close()
        # Ensure tenants table + migration (adds tenant_id/is_superadmin to users if needed)
        self._ensure_tenants_table()
        Database._users_ensured = True

    def create_user(self, username, password_hash, display_name, role='compliance', created_by=None, tenant_id=None, is_superadmin=False, portal_role=None, email=None, phone=None, force_password_change=False, is_root_user=False):
        """Create a new user. Returns user dict (without password_hash)."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO users (username, password_hash, display_name, role, created_by, tenant_id, is_superadmin, portal_role, email, phone, force_password_change, is_root_user)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, username, display_name, role, enabled, created_at, updated_at, last_login_at, created_by, tenant_id, is_superadmin, portal_role, email, phone, force_password_change, is_root_user
        """, (username, password_hash, display_name, role, created_by, tenant_id, is_superadmin, portal_role, email, phone, force_password_change, is_root_user))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def get_user_by_username(self, username):
        """Get user by username. Returns full dict INCLUDING password_hash (for auth)."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.*, t.name AS tenant_name, t.slug AS tenant_slug
            FROM users u
            LEFT JOIN tenants t ON t.id = u.tenant_id
            WHERE u.username = %s
        """, (username,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def get_user_by_id(self, user_id):
        """Get user by ID. Returns user dict WITHOUT password_hash."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.id, u.username, u.display_name, u.role, u.enabled,
                   u.created_at, u.updated_at, u.last_login_at, u.created_by,
                   u.tenant_id, u.is_superadmin, u.portal_role,
                   u.email, u.phone, u.force_password_change,
                   t.name AS tenant_name, t.slug AS tenant_slug
            FROM users u
            LEFT JOIN tenants t ON t.id = u.tenant_id
            WHERE u.id = %s
        """, (user_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def set_force_password_change(self, user_id, value=True):
        """Set or clear force_password_change flag for a user."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("UPDATE users SET force_password_change = %s WHERE id = %s", (value, user_id))
        self.conn.commit()
        cursor.close()

    def get_users(self, tenant_id=None, exclude_portal=False):
        """Get all users. Returns list of user dicts WITHOUT password_hash."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = """
            SELECT u.id, u.username, u.display_name, u.role, u.enabled,
                   u.created_at, u.updated_at, u.last_login_at, u.created_by,
                   u.tenant_id, u.is_superadmin, u.portal_role,
                   t.name AS tenant_name
            FROM users u
            LEFT JOIN tenants t ON t.id = u.tenant_id
        """
        params = []
        conditions = []
        if tenant_id is not None:
            conditions.append("u.tenant_id = %s")
            params.append(tenant_id)
        if exclude_portal:
            conditions.append("u.portal_role IS NULL")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY u.id"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for row in rows:
            for ts in ('created_at', 'updated_at', 'last_login_at'):
                if row.get(ts):
                    row[ts] = row[ts].isoformat()
        return rows

    def get_portal_users(self):
        """Get all users with portal_role set (superadmin, poweradmin, billing, or reader)."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.id, u.username, u.display_name, u.role, u.enabled,
                   u.created_at, u.updated_at, u.last_login_at, u.created_by,
                   u.tenant_id, u.is_superadmin, u.portal_role,
                   u.email, u.phone,
                   t.name AS tenant_name
            FROM users u
            LEFT JOIN tenants t ON t.id = u.tenant_id
            WHERE u.portal_role IS NOT NULL
            ORDER BY u.portal_role DESC, u.id
        """)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for row in rows:
            for ts in ('created_at', 'updated_at', 'last_login_at'):
                if row.get(ts):
                    row[ts] = row[ts].isoformat()
        return rows

    def update_user(self, user_id, **kwargs):
        """Update user fields. Allowed: display_name, role, enabled, password_hash, tenant_id, is_superadmin, portal_role, email, phone."""
        self._ensure_users_table()
        allowed = {'display_name', 'role', 'enabled', 'password_hash', 'tenant_id', 'is_superadmin', 'portal_role', 'email', 'phone'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_user_by_id(user_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            params.append(v)
        set_parts.append("updated_at = NOW()")
        params.append(user_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE users SET {', '.join(set_parts)}
            WHERE id = %s
            RETURNING id, username, display_name, role, enabled, created_at, updated_at, last_login_at, created_by, tenant_id, is_superadmin, portal_role, email, phone
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def delete_user(self, user_id):
        """Delete user. Returns True if deleted."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def count_admins(self):
        """Count active admin users."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = true")
        count = cursor.fetchone()[0]
        cursor.close()
        return count

    def update_last_login(self, user_id):
        """Update last_login_at timestamp."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s", (user_id,))
        self.conn.commit()
        cursor.close()

    def save_refresh_token(self, user_id, token_hash, expires_at):
        """Save a hashed refresh token."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, token_hash, expires_at))
        self.conn.commit()
        cursor.close()

    def get_refresh_token(self, token_hash):
        """Look up a refresh token by its hash."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM refresh_tokens WHERE token_hash = %s", (token_hash,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def revoke_refresh_token(self, token_hash):
        """Mark a refresh token as revoked."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("UPDATE refresh_tokens SET revoked = true WHERE token_hash = %s", (token_hash,))
        self.conn.commit()
        cursor.close()

    def revoke_all_user_tokens(self, user_id):
        """Revoke all refresh tokens for a user."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("UPDATE refresh_tokens SET revoked = true WHERE user_id = %s AND revoked = false", (user_id,))
        self.conn.commit()
        cursor.close()

    # --------------------------------------------------
    # Phase 84: Password reset & account lockout methods
    # --------------------------------------------------

    def get_user_by_email(self, email, tenant_id=None):
        """Lookup user by email (for forgot password). Returns full dict INCLUDING password_hash."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if tenant_id is not None:
            cursor.execute("""
                SELECT u.*, t.name AS tenant_name, t.slug AS tenant_slug
                FROM users u LEFT JOIN tenants t ON t.id = u.tenant_id
                WHERE LOWER(u.email) = LOWER(%s) AND u.tenant_id = %s AND u.enabled = true
            """, (email, tenant_id))
        else:
            cursor.execute("""
                SELECT u.*, t.name AS tenant_name, t.slug AS tenant_slug
                FROM users u LEFT JOIN tenants t ON t.id = u.tenant_id
                WHERE LOWER(u.email) = LOWER(%s) AND u.enabled = true
            """, (email,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def get_user_by_reset_token(self, token_hash):
        """Lookup user by hashed password reset token. Returns None if expired."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.*, t.name AS tenant_name, t.slug AS tenant_slug
            FROM users u LEFT JOIN tenants t ON t.id = u.tenant_id
            WHERE u.password_reset_token = %s
              AND u.password_reset_expires > NOW()
              AND u.enabled = true
        """, (token_hash,))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def set_password_reset_token(self, user_id, token_hash, expires):
        """Store hashed reset token and expiry on a user."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE users SET password_reset_token = %s, password_reset_expires = %s
            WHERE id = %s
        """, (token_hash, expires, user_id))
        self.conn.commit()
        cursor.close()

    def clear_password_reset_token(self, user_id):
        """Null out reset token/expiry after use."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE users SET password_reset_token = NULL, password_reset_expires = NULL
            WHERE id = %s
        """, (user_id,))
        self.conn.commit()
        cursor.close()

    def increment_failed_login(self, user_id):
        """Increment failed_login_attempts. Lock account for 15 min after 5 failures."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE users SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1
            WHERE id = %s
            RETURNING failed_login_attempts
        """, (user_id,))
        row = cursor.fetchone()
        attempts = row['failed_login_attempts'] if row else 0
        if attempts >= 5:
            cursor.execute("""
                UPDATE users SET locked_until = NOW() + INTERVAL '15 minutes'
                WHERE id = %s
            """, (user_id,))
        self.conn.commit()
        cursor.close()
        return attempts

    def reset_failed_login(self, user_id):
        """Reset failed attempts to 0 and clear locked_until."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE users SET failed_login_attempts = 0, locked_until = NULL
            WHERE id = %s
        """, (user_id,))
        self.conn.commit()
        cursor.close()

    def count_recent_reset_requests(self, email, hours=1):
        """Count how many reset tokens were created for this email in the last N hours."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM users
            WHERE LOWER(email) = LOWER(%s)
              AND password_reset_expires IS NOT NULL
              AND password_reset_expires > NOW() - INTERVAL '%s hours'
        """, (email, hours))
        count = cursor.fetchone()[0]
        cursor.close()
        return count

    def log_admin_audit(self, admin_user_id, action, target_user_id=None, target_tenant_id=None, details=None, ip_address=None):
        """Insert into admin_audit_log."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO admin_audit_log (admin_user_id, action, target_user_id, target_tenant_id, details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (admin_user_id, action, target_user_id, target_tenant_id, json.dumps(details or {}), ip_address))
        self.conn.commit()
        cursor.close()

    def ensure_default_admin(self):
        """Create default admin user if no users exist."""
        import bcrypt as bcrypt_lib
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        cursor.close()
        if count == 0:
            # Get default tenant_id
            default_tenant_id = None
            try:
                cursor2 = self.conn.cursor()
                cursor2.execute("SELECT id FROM tenants ORDER BY id LIMIT 1")
                row = cursor2.fetchone()
                default_tenant_id = row[0] if row else None
                cursor2.close()
            except Exception:
                pass
            username = os.getenv('ADMIN_USERNAME', 'techadmin')
            password = os.getenv('ADMIN_PASSWORD', 'changeme')
            hashed = bcrypt_lib.hashpw(password.encode('utf-8'), bcrypt_lib.gensalt()).decode('utf-8')
            self.create_user(username, hashed, 'Administrator', 'admin', tenant_id=default_tenant_id)
            # Promote to superadmin
            try:
                cursor3 = self.conn.cursor()
                cursor3.execute("UPDATE users SET is_superadmin = true WHERE username = %s", (username,))
                self.conn.commit()
                cursor3.close()
            except Exception:
                pass
            try:
                self.log_activity('auth', f'Default admin user "{username}" created on first startup', {'username': username})
            except Exception:
                pass

    # ── Phase 32: Compliance Frameworks ──────────────────────────────

    def _ensure_compliance_tables(self):
        """Create compliance_frameworks and compliance_controls tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_frameworks (
                id SERIAL PRIMARY KEY,
                key VARCHAR(50) UNIQUE NOT NULL,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                version VARCHAR(50),
                enabled BOOLEAN DEFAULT true,
                display_order INT DEFAULT 100,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_controls (
                id SERIAL PRIMARY KEY,
                framework_id INTEGER NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
                control_id VARCHAR(50) NOT NULL,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                metric VARCHAR(50) NOT NULL,
                pass_operator VARCHAR(10) NOT NULL,
                pass_value NUMERIC NOT NULL,
                warn_operator VARCHAR(10),
                warn_value NUMERIC,
                drilldown_url VARCHAR(255),
                display_order INT DEFAULT 100,
                UNIQUE(framework_id, control_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework ON compliance_controls(framework_id)")
        # V2 columns
        cursor.execute("ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS severity VARCHAR(20) DEFAULT 'medium'")
        cursor.execute("ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS weight INTEGER DEFAULT 5")
        cursor.execute("ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS cloud VARCHAR(20) DEFAULT 'azure'")
        cursor.execute("ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS pillar VARCHAR(50)")
        cursor.execute("ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS root_cause_id INTEGER")
        # Root causes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_root_causes (
                id SERIAL PRIMARY KEY,
                code VARCHAR(50) UNIQUE NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                category VARCHAR(50),
                recommendation TEXT,
                display_order INT DEFAULT 100
            )
        """)
        self.conn.commit()
        cursor.close()

    def get_compliance_frameworks(self, enabled_only=False):
        """Return all frameworks with their controls."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = "SELECT * FROM compliance_frameworks"
        if enabled_only:
            query += " WHERE enabled = true"
        query += " ORDER BY display_order, id"
        cursor.execute(query)
        frameworks = [dict(r) for r in cursor.fetchall()]

        for fw in frameworks:
            cursor.execute(
                "SELECT * FROM compliance_controls WHERE framework_id = %s ORDER BY display_order, id",
                (fw['id'],)
            )
            fw['controls'] = [dict(r) for r in cursor.fetchall()]
            if fw.get('created_at'):
                fw['created_at'] = fw['created_at'].isoformat()
            # Convert Decimal to float for JSON serialization
            for ctrl in fw['controls']:
                for k in ('pass_value', 'warn_value'):
                    if ctrl.get(k) is not None:
                        ctrl[k] = float(ctrl[k])

        cursor.close()
        return frameworks

    def get_compliance_framework(self, framework_id):
        """Return a single framework with controls."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM compliance_frameworks WHERE id = %s", (framework_id,))
        fw = cursor.fetchone()
        if not fw:
            cursor.close()
            return None
        fw = dict(fw)
        cursor.execute(
            "SELECT * FROM compliance_controls WHERE framework_id = %s ORDER BY display_order, id",
            (fw['id'],)
        )
        fw['controls'] = [dict(r) for r in cursor.fetchall()]
        if fw.get('created_at'):
            fw['created_at'] = fw['created_at'].isoformat()
        for ctrl in fw['controls']:
            for k in ('pass_value', 'warn_value'):
                if ctrl.get(k) is not None:
                    ctrl[k] = float(ctrl[k])
        cursor.close()
        return fw

    def toggle_compliance_framework(self, framework_id, enabled):
        """Enable or disable a compliance framework."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "UPDATE compliance_frameworks SET enabled = %s WHERE id = %s RETURNING id, key, name, enabled",
            (enabled, framework_id)
        )
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return dict(row) if row else None

    # ── Phase 51: Compliance Snapshots (Trend Tracking) ─────────────

    def _ensure_compliance_snapshots_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_snapshots (
                id SERIAL PRIMARY KEY,
                run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
                framework_key VARCHAR(50) NOT NULL,
                framework_name VARCHAR(100) NOT NULL,
                score INTEGER NOT NULL,
                pass_count INTEGER NOT NULL DEFAULT 0,
                warn_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                total_controls INTEGER NOT NULL DEFAULT 0,
                metrics JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(run_id, framework_key)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_compliance_snapshots_run ON compliance_snapshots(run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_compliance_snapshots_fw ON compliance_snapshots(framework_key)")
        self.conn.commit()
        cursor.close()

    def save_compliance_snapshot(self, run_id, framework_key, framework_name, score, pass_count, warn_count, fail_count, total_controls, metrics):
        """Save or upsert a compliance snapshot for a run+framework."""
        self._ensure_compliance_snapshots_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO compliance_snapshots (run_id, framework_key, framework_name, score, pass_count, warn_count, fail_count, total_controls, metrics)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id, framework_key) DO UPDATE SET
                score = EXCLUDED.score, pass_count = EXCLUDED.pass_count,
                warn_count = EXCLUDED.warn_count, fail_count = EXCLUDED.fail_count,
                total_controls = EXCLUDED.total_controls, metrics = EXCLUDED.metrics
            RETURNING id
        """, (run_id, framework_key, framework_name, score, pass_count, warn_count, fail_count, total_controls, json.dumps(metrics)))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return row[0] if row else None

    def get_compliance_trends(self, limit=20):
        """Return compliance snapshots grouped by run, ordered chronologically."""
        self._ensure_compliance_snapshots_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT cs.run_id, dr.completed_at, cs.framework_key, cs.framework_name,
                   cs.score, cs.pass_count, cs.warn_count, cs.fail_count, cs.total_controls
            FROM compliance_snapshots cs
            JOIN discovery_runs dr ON cs.run_id = dr.id
            WHERE dr.status = 'completed'
            AND cs.run_id IN (
                SELECT DISTINCT run_id FROM compliance_snapshots
                ORDER BY run_id DESC LIMIT %s
            )
            ORDER BY cs.run_id ASC, cs.framework_key
        """, (limit,))
        rows = cursor.fetchall()
        cursor.close()

        runs_map = {}
        for r in rows:
            rid = r[0]
            if rid not in runs_map:
                runs_map[rid] = {'run_id': rid, 'date': r[1].isoformat() if r[1] else None, 'frameworks': {}}
            runs_map[rid]['frameworks'][r[2]] = {
                'name': r[3], 'score': r[4], 'pass_count': r[5],
                'warn_count': r[6], 'fail_count': r[7], 'total_controls': r[8],
            }
        # Compute overall score per run
        for run in runs_map.values():
            total_pass = sum(fw['pass_count'] for fw in run['frameworks'].values())
            total_ctrls = sum(fw['total_controls'] for fw in run['frameworks'].values())
            run['overall_score'] = round(total_pass / total_ctrls * 100) if total_ctrls else 0
        return list(runs_map.values())

    def get_compliance_snapshot_count(self):
        """Return total number of compliance snapshots (for backfill check)."""
        self._ensure_compliance_snapshots_table()
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM compliance_snapshots")
        count = cursor.fetchone()[0]
        cursor.close()
        return count

    # ─── Phase 52: Azure Resource Discovery ──────────────────────────

    def _ensure_azure_storage_accounts_table(self):
        """Create azure_storage_accounts table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS azure_storage_accounts (
                id SERIAL PRIMARY KEY,
                discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
                resource_id TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT,
                resource_group TEXT,
                subscription_id TEXT,
                subscription_name TEXT,
                sku TEXT,
                kind TEXT,
                access_tier TEXT,
                public_blob_access BOOLEAN DEFAULT FALSE,
                https_only BOOLEAN DEFAULT TRUE,
                minimum_tls_version TEXT DEFAULT 'TLS1_2',
                shared_key_access BOOLEAN DEFAULT TRUE,
                allow_cross_tenant_replication BOOLEAN DEFAULT FALSE,
                default_network_action TEXT DEFAULT 'Allow',
                ip_rules_count INTEGER DEFAULT 0,
                vnet_rules_count INTEGER DEFAULT 0,
                private_endpoint_count INTEGER DEFAULT 0,
                bypass_settings TEXT,
                network_rules JSONB DEFAULT '{}',
                infrastructure_encryption BOOLEAN DEFAULT FALSE,
                customer_managed_keys BOOLEAN DEFAULT FALSE,
                key_vault_uri TEXT,
                encryption_details JSONB DEFAULT '{}',
                key1_created_at TIMESTAMPTZ,
                key2_created_at TIMESTAMPTZ,
                key_rotation_stale BOOLEAN DEFAULT FALSE,
                sas_policy_enabled BOOLEAN,
                sas_expiration_period TEXT,
                risk_level TEXT DEFAULT 'info',
                risk_score INTEGER DEFAULT 0,
                risk_reasons JSONB DEFAULT '[]',
                tags JSONB DEFAULT '{}',
                tenant_id INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(discovery_run_id, resource_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_run ON azure_storage_accounts(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_risk ON azure_storage_accounts(risk_level)")
        # Add columns if upgrading from older schema
        for col, defn in [
            ('sas_policy_enabled', 'BOOLEAN'),
            ('sas_expiration_period', 'TEXT'),
            ('diagnostic_logging_enabled', 'BOOLEAN'),
            ('logging_destinations', 'JSONB DEFAULT \'[]\''),
        ]:
            try:
                cursor.execute(f"ALTER TABLE azure_storage_accounts ADD COLUMN {col} {defn}")
            except Exception:
                self.conn.rollback()
        self.conn.commit()
        cursor.close()

    def _ensure_azure_key_vaults_table(self):
        """Create azure_key_vaults table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS azure_key_vaults (
                id SERIAL PRIMARY KEY,
                discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
                resource_id TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT,
                resource_group TEXT,
                subscription_id TEXT,
                subscription_name TEXT,
                sku TEXT,
                soft_delete_enabled BOOLEAN DEFAULT FALSE,
                soft_delete_retention_days INTEGER DEFAULT 0,
                purge_protection BOOLEAN DEFAULT FALSE,
                enable_rbac_authorization BOOLEAN DEFAULT FALSE,
                public_network_access TEXT DEFAULT 'Enabled',
                default_network_action TEXT DEFAULT 'Allow',
                ip_rules_count INTEGER DEFAULT 0,
                vnet_rules_count INTEGER DEFAULT 0,
                private_endpoint_count INTEGER DEFAULT 0,
                network_rules JSONB DEFAULT '{}',
                secrets_total INTEGER DEFAULT 0,
                secrets_expired INTEGER DEFAULT 0,
                secrets_expiring_soon INTEGER DEFAULT 0,
                keys_total INTEGER DEFAULT 0,
                keys_expired INTEGER DEFAULT 0,
                keys_expiring_soon INTEGER DEFAULT 0,
                certs_total INTEGER DEFAULT 0,
                certs_expired INTEGER DEFAULT 0,
                certs_expiring_soon INTEGER DEFAULT 0,
                access_policy_count INTEGER DEFAULT 0,
                access_policies JSONB DEFAULT '[]',
                secrets_detail JSONB DEFAULT '[]',
                keys_detail JSONB DEFAULT '[]',
                certs_detail JSONB DEFAULT '[]',
                risk_level TEXT DEFAULT 'info',
                risk_score INTEGER DEFAULT 0,
                risk_reasons JSONB DEFAULT '[]',
                tags JSONB DEFAULT '{}',
                tenant_id INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(discovery_run_id, resource_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kv_run ON azure_key_vaults(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kv_risk ON azure_key_vaults(risk_level)")
        # Add columns if upgrading from older schema
        for col in ['secrets_detail', 'keys_detail', 'certs_detail']:
            try:
                cursor.execute(f"ALTER TABLE azure_key_vaults ADD COLUMN {col} JSONB DEFAULT '[]'")
            except Exception:
                self.conn.rollback()
        self.conn.commit()
        cursor.close()

    def save_storage_account(self, run_id, data):
        """Save or update a storage account (UPSERT)."""
        self._ensure_azure_storage_accounts_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO azure_storage_accounts (
                discovery_run_id, resource_id, name, location, resource_group,
                subscription_id, subscription_name, sku, kind, access_tier,
                public_blob_access, https_only, minimum_tls_version,
                shared_key_access, allow_cross_tenant_replication,
                default_network_action, ip_rules_count, vnet_rules_count,
                private_endpoint_count, bypass_settings, network_rules,
                infrastructure_encryption, customer_managed_keys, key_vault_uri,
                encryption_details, key1_created_at, key2_created_at,
                key_rotation_stale, sas_policy_enabled, sas_expiration_period,
                risk_level, risk_score, risk_reasons,
                tags, tenant_id
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s
            )
            ON CONFLICT (discovery_run_id, resource_id) DO UPDATE SET
                name=EXCLUDED.name, location=EXCLUDED.location,
                resource_group=EXCLUDED.resource_group,
                subscription_id=EXCLUDED.subscription_id,
                subscription_name=EXCLUDED.subscription_name,
                sku=EXCLUDED.sku, kind=EXCLUDED.kind, access_tier=EXCLUDED.access_tier,
                public_blob_access=EXCLUDED.public_blob_access,
                https_only=EXCLUDED.https_only,
                minimum_tls_version=EXCLUDED.minimum_tls_version,
                shared_key_access=EXCLUDED.shared_key_access,
                allow_cross_tenant_replication=EXCLUDED.allow_cross_tenant_replication,
                default_network_action=EXCLUDED.default_network_action,
                ip_rules_count=EXCLUDED.ip_rules_count,
                vnet_rules_count=EXCLUDED.vnet_rules_count,
                private_endpoint_count=EXCLUDED.private_endpoint_count,
                bypass_settings=EXCLUDED.bypass_settings,
                network_rules=EXCLUDED.network_rules,
                infrastructure_encryption=EXCLUDED.infrastructure_encryption,
                customer_managed_keys=EXCLUDED.customer_managed_keys,
                key_vault_uri=EXCLUDED.key_vault_uri,
                encryption_details=EXCLUDED.encryption_details,
                key1_created_at=EXCLUDED.key1_created_at,
                key2_created_at=EXCLUDED.key2_created_at,
                key_rotation_stale=EXCLUDED.key_rotation_stale,
                sas_policy_enabled=EXCLUDED.sas_policy_enabled,
                sas_expiration_period=EXCLUDED.sas_expiration_period,
                risk_level=EXCLUDED.risk_level, risk_score=EXCLUDED.risk_score,
                risk_reasons=EXCLUDED.risk_reasons, tags=EXCLUDED.tags,
                created_at=NOW()
            RETURNING id
        """, (
            run_id, data.get('resource_id'), data.get('name'), data.get('location'),
            data.get('resource_group'), data.get('subscription_id'),
            data.get('subscription_name'), data.get('sku'), data.get('kind'),
            data.get('access_tier'), data.get('public_blob_access', False),
            data.get('https_only', True), data.get('minimum_tls_version', 'TLS1_2'),
            data.get('shared_key_access', True),
            data.get('allow_cross_tenant_replication', False),
            data.get('default_network_action', 'Allow'),
            data.get('ip_rules_count', 0), data.get('vnet_rules_count', 0),
            data.get('private_endpoint_count', 0), data.get('bypass_settings'),
            json.dumps(data.get('network_rules', {})),
            data.get('infrastructure_encryption', False),
            data.get('customer_managed_keys', False), data.get('key_vault_uri'),
            json.dumps(data.get('encryption_details', {})),
            data.get('key1_created_at'), data.get('key2_created_at'),
            data.get('key_rotation_stale', False),
            data.get('sas_policy_enabled'),
            data.get('sas_expiration_period'),
            data.get('risk_level', 'info'), data.get('risk_score', 0),
            json.dumps(data.get('risk_reasons', [])),
            json.dumps(data.get('tags', {})), data.get('tenant_id')
        ))
        db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return db_id

    def save_key_vault(self, run_id, data):
        """Save or update a key vault (UPSERT)."""
        self._ensure_azure_key_vaults_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO azure_key_vaults (
                discovery_run_id, resource_id, name, location, resource_group,
                subscription_id, subscription_name, sku,
                soft_delete_enabled, soft_delete_retention_days,
                purge_protection, enable_rbac_authorization,
                public_network_access, default_network_action,
                ip_rules_count, vnet_rules_count, private_endpoint_count,
                network_rules, secrets_total, secrets_expired, secrets_expiring_soon,
                keys_total, keys_expired, keys_expiring_soon,
                certs_total, certs_expired, certs_expiring_soon,
                access_policy_count, access_policies,
                secrets_detail, keys_detail, certs_detail,
                risk_level, risk_score, risk_reasons, tags, tenant_id
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s
            )
            ON CONFLICT (discovery_run_id, resource_id) DO UPDATE SET
                name=EXCLUDED.name, location=EXCLUDED.location,
                resource_group=EXCLUDED.resource_group,
                subscription_id=EXCLUDED.subscription_id,
                subscription_name=EXCLUDED.subscription_name, sku=EXCLUDED.sku,
                soft_delete_enabled=EXCLUDED.soft_delete_enabled,
                soft_delete_retention_days=EXCLUDED.soft_delete_retention_days,
                purge_protection=EXCLUDED.purge_protection,
                enable_rbac_authorization=EXCLUDED.enable_rbac_authorization,
                public_network_access=EXCLUDED.public_network_access,
                default_network_action=EXCLUDED.default_network_action,
                ip_rules_count=EXCLUDED.ip_rules_count,
                vnet_rules_count=EXCLUDED.vnet_rules_count,
                private_endpoint_count=EXCLUDED.private_endpoint_count,
                network_rules=EXCLUDED.network_rules,
                secrets_total=EXCLUDED.secrets_total,
                secrets_expired=EXCLUDED.secrets_expired,
                secrets_expiring_soon=EXCLUDED.secrets_expiring_soon,
                keys_total=EXCLUDED.keys_total, keys_expired=EXCLUDED.keys_expired,
                keys_expiring_soon=EXCLUDED.keys_expiring_soon,
                certs_total=EXCLUDED.certs_total, certs_expired=EXCLUDED.certs_expired,
                certs_expiring_soon=EXCLUDED.certs_expiring_soon,
                access_policy_count=EXCLUDED.access_policy_count,
                access_policies=EXCLUDED.access_policies,
                secrets_detail=EXCLUDED.secrets_detail,
                keys_detail=EXCLUDED.keys_detail,
                certs_detail=EXCLUDED.certs_detail,
                risk_level=EXCLUDED.risk_level, risk_score=EXCLUDED.risk_score,
                risk_reasons=EXCLUDED.risk_reasons, tags=EXCLUDED.tags,
                created_at=NOW()
            RETURNING id
        """, (
            run_id, data.get('resource_id'), data.get('name'), data.get('location'),
            data.get('resource_group'), data.get('subscription_id'),
            data.get('subscription_name'), data.get('sku'),
            data.get('soft_delete_enabled', False),
            data.get('soft_delete_retention_days', 0),
            data.get('purge_protection', False),
            data.get('enable_rbac_authorization', False),
            data.get('public_network_access', 'Enabled'),
            data.get('default_network_action', 'Allow'),
            data.get('ip_rules_count', 0), data.get('vnet_rules_count', 0),
            data.get('private_endpoint_count', 0),
            json.dumps(data.get('network_rules', {})),
            data.get('secrets_total', 0), data.get('secrets_expired', 0),
            data.get('secrets_expiring_soon', 0),
            data.get('keys_total', 0), data.get('keys_expired', 0),
            data.get('keys_expiring_soon', 0),
            data.get('certs_total', 0), data.get('certs_expired', 0),
            data.get('certs_expiring_soon', 0),
            data.get('access_policy_count', 0),
            json.dumps(data.get('access_policies', [])),
            json.dumps(data.get('secrets_detail', [])),
            json.dumps(data.get('keys_detail', [])),
            json.dumps(data.get('certs_detail', [])),
            data.get('risk_level', 'info'), data.get('risk_score', 0),
            json.dumps(data.get('risk_reasons', [])),
            json.dumps(data.get('tags', {})), data.get('tenant_id')
        ))
        db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return db_id

    # ──────────────────────────────────────────────────────────
    # App Registrations (Phase 74)
    # ──────────────────────────────────────────────────────────

    def _ensure_app_registrations_table(self):
        """Create app_registrations table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_registrations (
                id SERIAL PRIMARY KEY,
                discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
                app_object_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_datetime TIMESTAMPTZ,
                sign_in_audience TEXT,
                publisher_domain TEXT,
                app_owner_organization_id TEXT,
                is_third_party BOOLEAN DEFAULT FALSE,
                required_permissions JSONB DEFAULT '[]',
                permission_count INTEGER DEFAULT 0,
                application_permission_count INTEGER DEFAULT 0,
                delegated_permission_count INTEGER DEFAULT 0,
                high_risk_permissions TEXT[] DEFAULT '{}',
                secret_count INTEGER DEFAULT 0,
                certificate_count INTEGER DEFAULT 0,
                credential_details JSONB DEFAULT '[]',
                next_expiry TIMESTAMPTZ,
                has_expired_credential BOOLEAN DEFAULT FALSE,
                has_expiring_soon BOOLEAN DEFAULT FALSE,
                owner_count INTEGER DEFAULT 0,
                owners JSONB DEFAULT '[]',
                primary_owner TEXT,
                has_service_principal BOOLEAN DEFAULT FALSE,
                linked_spn_id INTEGER,
                spn_last_sign_in TIMESTAMPTZ,
                spn_activity_status TEXT,
                redirect_uris JSONB DEFAULT '[]',
                redirect_uri_count INTEGER DEFAULT 0,
                has_localhost_redirect BOOLEAN DEFAULT FALSE,
                has_http_redirect BOOLEAN DEFAULT FALSE,
                risk_level TEXT DEFAULT 'info',
                risk_score INTEGER DEFAULT 0,
                risk_reasons JSONB DEFAULT '[]',
                approval_status TEXT DEFAULT 'unknown',
                tenant_id INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(discovery_run_id, app_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_appreg_run ON app_registrations(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_appreg_risk ON app_registrations(risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_appreg_appid ON app_registrations(app_id)")
        self.conn.commit()
        cursor.close()

    def save_app_registration(self, run_id, data):
        """Save or update an app registration (UPSERT)."""
        self._ensure_app_registrations_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO app_registrations (
                discovery_run_id, app_object_id, app_id, display_name,
                created_datetime, sign_in_audience, publisher_domain,
                app_owner_organization_id, is_third_party,
                required_permissions, permission_count,
                application_permission_count, delegated_permission_count,
                high_risk_permissions,
                secret_count, certificate_count, credential_details,
                next_expiry, has_expired_credential, has_expiring_soon,
                owner_count, owners, primary_owner,
                has_service_principal, linked_spn_id,
                spn_last_sign_in, spn_activity_status,
                redirect_uris, redirect_uri_count,
                has_localhost_redirect, has_http_redirect,
                risk_level, risk_score, risk_reasons,
                approval_status, tenant_id
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s
            )
            ON CONFLICT (discovery_run_id, app_id) DO UPDATE SET
                app_object_id=EXCLUDED.app_object_id,
                display_name=EXCLUDED.display_name,
                created_datetime=EXCLUDED.created_datetime,
                sign_in_audience=EXCLUDED.sign_in_audience,
                publisher_domain=EXCLUDED.publisher_domain,
                app_owner_organization_id=EXCLUDED.app_owner_organization_id,
                is_third_party=EXCLUDED.is_third_party,
                required_permissions=EXCLUDED.required_permissions,
                permission_count=EXCLUDED.permission_count,
                application_permission_count=EXCLUDED.application_permission_count,
                delegated_permission_count=EXCLUDED.delegated_permission_count,
                high_risk_permissions=EXCLUDED.high_risk_permissions,
                secret_count=EXCLUDED.secret_count,
                certificate_count=EXCLUDED.certificate_count,
                credential_details=EXCLUDED.credential_details,
                next_expiry=EXCLUDED.next_expiry,
                has_expired_credential=EXCLUDED.has_expired_credential,
                has_expiring_soon=EXCLUDED.has_expiring_soon,
                owner_count=EXCLUDED.owner_count,
                owners=EXCLUDED.owners,
                primary_owner=EXCLUDED.primary_owner,
                has_service_principal=EXCLUDED.has_service_principal,
                linked_spn_id=EXCLUDED.linked_spn_id,
                spn_last_sign_in=EXCLUDED.spn_last_sign_in,
                spn_activity_status=EXCLUDED.spn_activity_status,
                redirect_uris=EXCLUDED.redirect_uris,
                redirect_uri_count=EXCLUDED.redirect_uri_count,
                has_localhost_redirect=EXCLUDED.has_localhost_redirect,
                has_http_redirect=EXCLUDED.has_http_redirect,
                risk_level=EXCLUDED.risk_level,
                risk_score=EXCLUDED.risk_score,
                risk_reasons=EXCLUDED.risk_reasons,
                approval_status=EXCLUDED.approval_status,
                created_at=NOW()
            RETURNING id
        """, (
            run_id, data.get('app_object_id'), data.get('app_id'),
            data.get('display_name'), data.get('created_datetime'),
            data.get('sign_in_audience'), data.get('publisher_domain'),
            data.get('app_owner_organization_id'),
            data.get('is_third_party', False),
            json.dumps(data.get('required_permissions', [])),
            data.get('permission_count', 0),
            data.get('application_permission_count', 0),
            data.get('delegated_permission_count', 0),
            data.get('high_risk_permissions', []),
            data.get('secret_count', 0),
            data.get('certificate_count', 0),
            json.dumps(data.get('credential_details', [])),
            data.get('next_expiry'),
            data.get('has_expired_credential', False),
            data.get('has_expiring_soon', False),
            data.get('owner_count', 0),
            json.dumps(data.get('owners', [])),
            data.get('primary_owner'),
            data.get('has_service_principal', False),
            data.get('linked_spn_id'),
            data.get('spn_last_sign_in'),
            data.get('spn_activity_status'),
            json.dumps(data.get('redirect_uris', [])),
            data.get('redirect_uri_count', 0),
            data.get('has_localhost_redirect', False),
            data.get('has_http_redirect', False),
            data.get('risk_level', 'info'),
            data.get('risk_score', 0),
            json.dumps(data.get('risk_reasons', [])),
            data.get('approval_status', 'unknown'),
            data.get('tenant_id'),
        ))
        db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return db_id

    def seed_compliance_frameworks(self):
        """Insert default 6 frameworks if the table is empty."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM compliance_frameworks")
        count = cursor.fetchone()[0]
        if count > 0:
            cursor.close()
            return

        frameworks = [
            {
                'key': 'soc2', 'name': 'SOC 2 (Type II)',
                'description': 'Service Organization Control 2 — Trust Services Criteria for security, availability, processing integrity, confidentiality, and privacy.',
                'version': 'Type II', 'display_order': 10,
                'controls': [
                    ('CC6.1', 'Logical Access Controls', 't0_count', '<=', 2, '<=', 5, '/identities?privilege_tier=T0'),
                    ('CC6.2', 'Credential Management', 'expired_credentials', '==', 0, None, None, '/identities?credential_status=expired'),
                    ('CC6.3', 'Service Account Governance', 'unowned_spns', '==', 0, '<=', 3, '/identities?identity_category=service_principal&has_owner=false'),
                    ('CC7.2', 'System Monitoring', 'dormant_privileged', '==', 0, '<=', 2, '/identities?activity_status=stale&has_roles=true'),
                    ('CC8.1', 'Change Management', 'excessive_permissions', '==', 0, '<=', 3, '/identities?excessive_permissions=true'),
                ]
            },
            {
                'key': 'hipaa', 'name': 'HIPAA',
                'description': 'Health Insurance Portability and Accountability Act — Security Rule safeguards for electronic protected health information (ePHI).',
                'version': '§164', 'display_order': 20,
                'controls': [
                    ('§164.312(a)', 'Access Control', 't0_count', '<=', 2, '<=', 5, '/identities?privilege_tier=T0'),
                    ('§164.312(d)', 'Authentication', 'expired_credentials', '==', 0, None, None, '/identities?credential_status=expired'),
                    ('§164.308(a)(3)', 'Workforce Security', 'hipaa_violations', '==', 0, '<=', 2, '/identities?hipaa_violation=true'),
                    ('§164.308(a)(4)', 'Information Access', 'dormant_privileged', '==', 0, '<=', 2, '/identities?activity_status=stale&has_roles=true'),
                    ('§164.312(c)', 'Integrity Controls', 'excessive_permissions', '==', 0, '<=', 5, '/identities?excessive_permissions=true'),
                ]
            },
            {
                'key': 'pci_dss', 'name': 'PCI-DSS',
                'description': 'Payment Card Industry Data Security Standard — requirements for organizations handling cardholder data.',
                'version': 'v4.0', 'display_order': 30,
                'controls': [
                    ('7.1', 'Limit Access', 't0_count', '<=', 2, '<=', 5, '/identities?privilege_tier=T0'),
                    ('7.2.1', 'Credential Lifecycle', 'expired_credentials', '==', 0, None, None, '/identities?credential_status=expired'),
                    ('8.3.6', 'MFA for Admin', 'mfa_not_enforced', '==', 0, '<=', 2, '/identities?mfa_enforced=false'),
                    ('8.6', 'Service Account Controls', 'unowned_spns', '==', 0, '<=', 3, '/identities?identity_category=service_principal&has_owner=false'),
                ]
            },
            {
                'key': 'nist_800_53', 'name': 'NIST 800-53',
                'description': 'Security and Privacy Controls for Information Systems and Organizations — comprehensive catalog of security controls.',
                'version': 'Rev 5', 'display_order': 40,
                'controls': [
                    ('AC-2', 'Account Management', 'stale_accounts', '==', 0, '<=', 3, '/identities?activity_status=stale'),
                    ('AC-6', 'Least Privilege', 't0_count', '<=', 2, '<=', 5, '/identities?privilege_tier=T0'),
                    ('IA-5', 'Authenticator Management', 'expired_credentials', '==', 0, None, None, '/identities?credential_status=expired'),
                    ('AC-17', 'Remote Access', 'mfa_not_enforced', '==', 0, '<=', 2, '/identities?mfa_enforced=false'),
                    ('AU-6', 'Audit Review', 'dormant_privileged', '==', 0, '<=', 2, '/identities?activity_status=stale&has_roles=true'),
                ]
            },
            {
                'key': 'cis_azure', 'name': 'CIS Azure Foundations',
                'description': 'CIS Microsoft Azure Foundations Benchmark — prescriptive guidance for establishing a secure baseline configuration.',
                'version': 'v2.0', 'display_order': 50,
                'controls': [
                    ('1.1', 'Limit Global Admins', 't0_count', '<=', 2, '<=', 5, '/identities?privilege_tier=T0'),
                    ('1.2', 'Unused Credentials', 'stale_accounts', '==', 0, '<=', 3, '/identities?activity_status=stale'),
                    ('1.3', 'MFA Enforcement', 'mfa_not_enforced', '==', 0, '<=', 2, '/identities?mfa_enforced=false'),
                    ('1.4', 'Guest Account Review', 'dormant_privileged', '==', 0, '<=', 2, '/identities?activity_status=stale&has_roles=true'),
                    ('1.5', 'Service Principal Hygiene', 'unowned_spns', '==', 0, '<=', 3, '/identities?identity_category=service_principal&has_owner=false'),
                ]
            },
            {
                'key': 'iso_27001', 'name': 'ISO 27001:2022',
                'description': 'International standard for information security management systems (ISMS) — Annex A controls.',
                'version': '2022', 'display_order': 60,
                'controls': [
                    ('A.5.15', 'Access Control', 't0_count', '<=', 2, '<=', 5, '/identities?privilege_tier=T0'),
                    ('A.5.16', 'Identity Management', 'stale_accounts', '==', 0, '<=', 3, '/identities?activity_status=stale'),
                    ('A.5.17', 'Authentication', 'expired_credentials', '==', 0, None, None, '/identities?credential_status=expired'),
                    ('A.8.2', 'Privileged Access', 'excessive_permissions', '==', 0, '<=', 5, '/identities?excessive_permissions=true'),
                    ('A.8.5', 'Secure Authentication', 'mfa_not_enforced', '==', 0, '<=', 2, '/identities?mfa_enforced=false'),
                ]
            },
        ]

        for i, fw in enumerate(frameworks):
            cursor.execute("""
                INSERT INTO compliance_frameworks (key, name, description, version, display_order)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (fw['key'], fw['name'], fw['description'], fw['version'], fw['display_order']))
            fw_id = cursor.fetchone()[0]

            for j, ctrl in enumerate(fw['controls']):
                control_id, name, metric, pass_op, pass_val, warn_op, warn_val, drilldown = ctrl
                cursor.execute("""
                    INSERT INTO compliance_controls
                        (framework_id, control_id, name, metric, pass_operator, pass_value,
                         warn_operator, warn_value, drilldown_url, display_order)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (fw_id, control_id, name, metric, pass_op, pass_val, warn_op, warn_val, drilldown, (j + 1) * 10))

        self.conn.commit()
        cursor.close()

    def seed_compliance_root_causes(self):
        """Insert 7 root causes if the table is empty."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM compliance_root_causes")
        if cursor.fetchone()[0] > 0:
            cursor.close()
            return
        causes = [
            ('excessive_standing_privilege', 'Excessive Standing Privileges',
             'Identities hold persistent high-privilege roles without time-bound elevation, expanding blast radius.',
             'privilege', 'Implement PIM/JIT for all T0 roles; enforce least-privilege baseline.', 10),
            ('credential_lifecycle_gaps', 'Credential Lifecycle Gaps',
             'Expired, unrotated, or long-lived credentials create persistent attack surface.',
             'credential', 'Enforce 90-day credential rotation; alert on expiring creds at 30 days.', 20),
            ('orphaned_identities', 'Orphaned & Ownerless Identities',
             'Service principals and app registrations without owners lack accountability and review.',
             'governance', 'Assign owners to all SPNs; enforce attestation cycles.', 30),
            ('dormant_access_accumulation', 'Dormant Access Accumulation',
             'Stale accounts retain active role assignments, creating latent privilege risk.',
             'usage', 'Revoke roles from accounts inactive >90 days; automate access reviews.', 40),
            ('weak_authentication', 'Weak Authentication Controls',
             'Users without MFA or conditional-access coverage are vulnerable to credential theft.',
             'authentication', 'Enforce MFA for all human users; close CA policy gaps.', 50),
            ('excessive_permissions_spread', 'Excessive Permission Spread',
             'Identities accumulate roles beyond operational need, violating least privilege.',
             'privilege', 'Cap role assignments per identity; run role-mining to consolidate.', 60),
            ('external_trust_exposure', 'External Trust Exposure',
             'Guest accounts and multi-tenant apps extend trust boundaries beyond the organization.',
             'trust', 'Review guest accounts quarterly; restrict multi-tenant app registrations.', 70),
        ]
        for code, title, desc, cat, rec, order in causes:
            cursor.execute("""
                INSERT INTO compliance_root_causes (code, title, description, category, recommendation, display_order)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (code, title, desc, cat, rec, order))
        self.conn.commit()
        cursor.close()

    def _migrate_compliance_controls_v2(self):
        """Idempotently update controls with severity, weight, pillar, root_cause_id."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor()
        # Build root_cause code → id map
        cursor.execute("SELECT id, code FROM compliance_root_causes")
        rc_map = {row[1]: row[0] for row in cursor.fetchall()}
        if not rc_map:
            cursor.close()
            return

        # Check if migration already ran (any control has non-null pillar)
        cursor.execute("SELECT COUNT(*) FROM compliance_controls WHERE pillar IS NOT NULL")
        if cursor.fetchone()[0] > 0:
            cursor.close()
            return

        # Map (framework_key, control_id) → (severity, weight, pillar, root_cause_code)
        mappings = {
            # SOC2
            ('soc2', 'CC6.1'): ('critical', 9, 'privilege', 'excessive_standing_privilege'),
            ('soc2', 'CC6.2'): ('high', 7, 'credential', 'credential_lifecycle_gaps'),
            ('soc2', 'CC6.3'): ('high', 7, 'governance', 'orphaned_identities'),
            ('soc2', 'CC7.2'): ('medium', 6, 'usage', 'dormant_access_accumulation'),
            ('soc2', 'CC8.1'): ('high', 7, 'privilege', 'excessive_permissions_spread'),
            # HIPAA
            ('hipaa', '§164.312(a)'): ('critical', 9, 'privilege', 'excessive_standing_privilege'),
            ('hipaa', '§164.312(d)'): ('critical', 9, 'credential', 'credential_lifecycle_gaps'),
            ('hipaa', '§164.308(a)(3)'): ('high', 8, 'governance', 'orphaned_identities'),
            ('hipaa', '§164.308(a)(4)'): ('high', 7, 'usage', 'dormant_access_accumulation'),
            ('hipaa', '§164.312(c)'): ('medium', 5, 'privilege', 'excessive_permissions_spread'),
            # PCI-DSS
            ('pci_dss', '7.1'): ('critical', 9, 'privilege', 'excessive_standing_privilege'),
            ('pci_dss', '7.2.1'): ('high', 8, 'credential', 'credential_lifecycle_gaps'),
            ('pci_dss', '8.3.6'): ('critical', 9, 'authentication', 'weak_authentication'),
            ('pci_dss', '8.6'): ('high', 7, 'governance', 'orphaned_identities'),
            # NIST
            ('nist_800_53', 'AC-2'): ('high', 8, 'usage', 'dormant_access_accumulation'),
            ('nist_800_53', 'AC-6'): ('critical', 9, 'privilege', 'excessive_standing_privilege'),
            ('nist_800_53', 'IA-5'): ('critical', 9, 'credential', 'credential_lifecycle_gaps'),
            ('nist_800_53', 'AC-17'): ('high', 7, 'authentication', 'weak_authentication'),
            ('nist_800_53', 'AU-6'): ('medium', 6, 'usage', 'dormant_access_accumulation'),
            # CIS Azure
            ('cis_azure', '1.1'): ('critical', 9, 'privilege', 'excessive_standing_privilege'),
            ('cis_azure', '1.2'): ('high', 8, 'usage', 'dormant_access_accumulation'),
            ('cis_azure', '1.3'): ('critical', 9, 'authentication', 'weak_authentication'),
            ('cis_azure', '1.4'): ('high', 7, 'usage', 'dormant_access_accumulation'),
            ('cis_azure', '1.5'): ('medium', 6, 'governance', 'orphaned_identities'),
            # ISO 27001
            ('iso_27001', 'A.5.15'): ('high', 8, 'privilege', 'excessive_standing_privilege'),
            ('iso_27001', 'A.5.16'): ('high', 7, 'usage', 'dormant_access_accumulation'),
            ('iso_27001', 'A.5.17'): ('critical', 9, 'credential', 'credential_lifecycle_gaps'),
            ('iso_27001', 'A.8.2'): ('high', 7, 'privilege', 'excessive_permissions_spread'),
            ('iso_27001', 'A.8.5'): ('medium', 6, 'authentication', 'weak_authentication'),
        }

        for (fw_key, ctrl_id), (sev, wt, pillar, rc_code) in mappings.items():
            rc_id = rc_map.get(rc_code)
            cursor.execute("""
                UPDATE compliance_controls cc SET severity = %s, weight = %s, pillar = %s, root_cause_id = %s
                FROM compliance_frameworks cf
                WHERE cc.framework_id = cf.id AND cf.key = %s AND cc.control_id = %s
            """, (sev, wt, pillar, rc_id, fw_key, ctrl_id))

        self.conn.commit()
        cursor.close()

    # ─── Saved Views (Phase 34) ──────────────────────────────────────

    def _ensure_saved_views_table(self):
        """Create saved_views table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS saved_views (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                filters JSONB NOT NULL DEFAULT '{}',
                sort_field VARCHAR(50),
                sort_direction VARCHAR(10) DEFAULT 'desc',
                is_default BOOLEAN DEFAULT false,
                is_shared BOOLEAN DEFAULT false,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_saved_views_user ON saved_views(user_id)")
        self.conn.commit()
        cursor.close()

    def get_saved_views(self, user_id: int) -> list:
        """Get user's views + shared views, ordered by default first then name."""
        self._ensure_saved_views_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT sv.*, u.display_name as creator_name
            FROM saved_views sv
            JOIN users u ON u.id = sv.user_id
            WHERE sv.user_id = %s OR sv.is_shared = true
            ORDER BY (sv.user_id = %s AND sv.is_default) DESC, sv.name ASC
        """, (user_id, user_id))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            r['created_at'] = r['created_at'].isoformat() if r.get('created_at') else None
            r['updated_at'] = r['updated_at'].isoformat() if r.get('updated_at') else None
        return rows

    def get_saved_view(self, view_id: int) -> dict:
        """Get a single saved view by ID."""
        self._ensure_saved_views_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM saved_views WHERE id = %s", (view_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    def create_saved_view(self, user_id: int, name: str, description: str = None,
                          filters: dict = None, sort_field: str = None,
                          sort_direction: str = 'desc', is_shared: bool = False) -> dict:
        """Create a new saved view."""
        self._ensure_saved_views_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO saved_views (user_id, name, description, filters, sort_field, sort_direction, is_shared)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (user_id, name, description, json.dumps(filters or {}), sort_field, sort_direction, is_shared))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        row['created_at'] = row['created_at'].isoformat() if row.get('created_at') else None
        row['updated_at'] = row['updated_at'].isoformat() if row.get('updated_at') else None
        return row

    def update_saved_view(self, view_id: int, **fields) -> dict:
        """Update specific fields on a saved view."""
        self._ensure_saved_views_table()
        allowed = {'name', 'description', 'filters', 'sort_field', 'sort_direction', 'is_default', 'is_shared'}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_saved_view(view_id)

        set_parts = []
        params = []
        for key, val in updates.items():
            if key == 'filters':
                set_parts.append(f"{key} = %s")
                params.append(json.dumps(val) if isinstance(val, dict) else val)
            else:
                set_parts.append(f"{key} = %s")
                params.append(val)
        set_parts.append("updated_at = NOW()")
        params.append(view_id)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE saved_views SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    def delete_saved_view(self, view_id: int) -> bool:
        """Delete a saved view."""
        self._ensure_saved_views_table()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM saved_views WHERE id = %s", (view_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def set_default_view(self, user_id: int, view_id: int) -> dict:
        """Set a view as default for the user, clearing other defaults."""
        self._ensure_saved_views_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("UPDATE saved_views SET is_default = false WHERE user_id = %s AND is_default = true", (user_id,))
        cursor.execute("""
            UPDATE saved_views SET is_default = true, updated_at = NOW()
            WHERE id = %s AND (user_id = %s OR is_shared = true)
            RETURNING *
        """, (view_id, user_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        result['created_at'] = result['created_at'].isoformat() if result.get('created_at') else None
        result['updated_at'] = result['updated_at'].isoformat() if result.get('updated_at') else None
        return result

    # ===================================================================
    # Access Review Campaigns (Phase 36)
    # ===================================================================

    def _ensure_access_review_tables(self):
        """Create access_review_campaigns, campaign_reviews, and campaign_audit_log tables."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_review_campaigns (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                scope_filters JSONB NOT NULL DEFAULT '{}',
                deadline TIMESTAMPTZ,
                created_by INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                completed_at TIMESTAMPTZ
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_status ON access_review_campaigns(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_created_by ON access_review_campaigns(created_by)")
        # V2 columns on campaigns
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS tenant_id INTEGER")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS campaign_type VARCHAR(100) DEFAULT 'general'")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS scope_clouds TEXT[]")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS scope_description VARCHAR(500)")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS risk_focus VARCHAR(100)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON access_review_campaigns(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_type ON access_review_campaigns(campaign_type)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_reviews (
                id SERIAL PRIMARY KEY,
                campaign_id INTEGER NOT NULL REFERENCES access_review_campaigns(id) ON DELETE CASCADE,
                identity_id TEXT NOT NULL,
                identity_display_name TEXT,
                identity_risk_level VARCHAR(20),
                identity_category VARCHAR(100),
                reviewer_id INTEGER REFERENCES users(id),
                decision VARCHAR(20),
                notes TEXT,
                decided_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaign_reviews_campaign ON campaign_reviews(campaign_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaign_reviews_identity ON campaign_reviews(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaign_reviews_decision ON campaign_reviews(decision)")
        # V2 columns on reviews
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS identity_db_id INTEGER")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS identity_type VARCHAR(100)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS access_role VARCHAR(255)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS access_scope VARCHAR(500)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS cloud_provider VARCHAR(50)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS risk_score INTEGER")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS risk_factors JSONB DEFAULT '[]'")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS last_used_date TIMESTAMPTZ")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS last_used_days INTEGER")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS privilege_level VARCHAR(50)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS credential_risk VARCHAR(255)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS credential_risk_level VARCHAR(50)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS ai_recommendation VARCHAR(100)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS ai_recommendation_reason TEXT")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS decision_by INTEGER REFERENCES users(id)")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS review_due_date TIMESTAMPTZ")
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaign_reviews_risk ON campaign_reviews(risk_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaign_reviews_reviewer ON campaign_reviews(reviewer_id)")

        # V2: Campaign audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_audit_log (
                id SERIAL PRIMARY KEY,
                campaign_id INTEGER NOT NULL REFERENCES access_review_campaigns(id) ON DELETE CASCADE,
                review_id INTEGER REFERENCES campaign_reviews(id) ON DELETE SET NULL,
                action VARCHAR(100) NOT NULL,
                actor_id INTEGER REFERENCES users(id),
                old_value TEXT,
                new_value TEXT,
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_campaign ON campaign_audit_log(campaign_id)")
        self.conn.commit()
        cursor.close()

    def get_campaigns(self, status: str = None) -> list:
        """Get all campaigns with review progress stats."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = """
            SELECT c.*,
                   u.display_name as creator_name,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id) as total_reviews,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision IS NOT NULL) as completed_reviews,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision = 'approve') as approved_count,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision = 'revoke') as revoked_count,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision = 'flag') as flagged_count
            FROM access_review_campaigns c
            JOIN users u ON u.id = c.created_by
        """
        params = []
        if status:
            query += " WHERE c.status = %s"
            params.append(status)
        query += " ORDER BY c.created_at DESC"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('created_at', 'updated_at', 'completed_at', 'deadline'):
                if r.get(ts) and hasattr(r[ts], 'isoformat'):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_campaign(self, campaign_id: int) -> dict:
        """Get a single campaign by ID with stats."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT c.*,
                   u.display_name as creator_name,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id) as total_reviews,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision IS NOT NULL) as completed_reviews,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision = 'approve') as approved_count,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision = 'revoke') as revoked_count,
                   (SELECT COUNT(*) FROM campaign_reviews cr WHERE cr.campaign_id = c.id AND cr.decision = 'flag') as flagged_count
            FROM access_review_campaigns c
            JOIN users u ON u.id = c.created_by
            WHERE c.id = %s
        """, (campaign_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'completed_at', 'deadline'):
            if result.get(ts) and hasattr(result[ts], 'isoformat'):
                result[ts] = result[ts].isoformat()
        return result

    def create_campaign(self, name: str, description: str, scope_filters: dict, deadline: str, created_by: int,
                        campaign_type: str = 'general', scope_clouds: list = None,
                        scope_description: str = None, risk_focus: str = None, tenant_id: int = None) -> dict:
        """Create a new access review campaign with V2 fields."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO access_review_campaigns (name, description, scope_filters, deadline, created_by,
                campaign_type, scope_clouds, scope_description, risk_focus, tenant_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (name, description, json.dumps(scope_filters) if scope_filters else '{}', deadline, created_by,
              campaign_type, scope_clouds, scope_description, risk_focus, tenant_id))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at', 'completed_at', 'deadline'):
            if row.get(ts) and hasattr(row[ts], 'isoformat'):
                row[ts] = row[ts].isoformat()
        return row

    def update_campaign(self, campaign_id: int, **fields) -> dict:
        """Update campaign fields."""
        self._ensure_access_review_tables()
        allowed = {'name', 'description', 'status', 'deadline'}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_campaign(campaign_id)

        set_parts = []
        params = []
        for key, val in updates.items():
            set_parts.append(f"{key} = %s")
            params.append(val)
        set_parts.append("updated_at = NOW()")
        if updates.get('status') == 'completed':
            set_parts.append("completed_at = NOW()")
        params.append(campaign_id)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE access_review_campaigns SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'completed_at', 'deadline'):
            if result.get(ts) and hasattr(result[ts], 'isoformat'):
                result[ts] = result[ts].isoformat()
        return result

    def delete_campaign(self, campaign_id: int) -> bool:
        """Delete a campaign (CASCADE deletes reviews)."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM access_review_campaigns WHERE id = %s", (campaign_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def populate_campaign_reviews(self, campaign_id: int, scope_filters: dict, reviewer_id: int, deadline=None) -> int:
        """Populate campaign_reviews from identities with V2 risk scoring and AI recommendations."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Find latest completed discovery run
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        row = cursor.fetchone()
        latest_run = row['max'] if row else None
        if not latest_run:
            cursor.close()
            return 0

        # Build identity query with scope filters
        where_parts = ["i.discovery_run_id = %s"]
        params = [latest_run]

        risk_levels = scope_filters.get('risk_levels', [])
        if risk_levels:
            placeholders = ','.join(['%s'] * len(risk_levels))
            where_parts.append(f"i.risk_level IN ({placeholders})")
            params.extend(risk_levels)

        categories = scope_filters.get('identity_categories', [])
        if categories:
            placeholders = ','.join(['%s'] * len(categories))
            where_parts.append(f"COALESCE(i.identity_category, '') IN ({placeholders})")
            params.extend(categories)

        identity_ids = scope_filters.get('identity_ids', [])
        if identity_ids:
            placeholders = ','.join(['%s'] * len(identity_ids))
            where_parts.append(f"i.identity_id IN ({placeholders})")
            params.extend(identity_ids)

        where_clause = " AND ".join(where_parts)
        cursor.execute(f"""
            SELECT i.id, i.identity_id, i.display_name, i.risk_level,
                   COALESCE(i.identity_category, '') as identity_category,
                   i.activity_status, i.last_sign_in,
                   i.credential_status, i.credential_expiration,
                   COALESCE(i.risk_score, 0) as existing_risk_score,
                   COALESCE(i.ca_mfa_enforced, false) as mfa_enforced,
                   COALESCE(i.owner_count, 0) as owner_count
            FROM identities i
            WHERE {where_clause}
            ORDER BY COALESCE(i.risk_score, 0) DESC, i.display_name
        """, params)
        identities = cursor.fetchall()

        # Pre-fetch role assignments and credentials for all identities
        id_list = [ident['id'] for ident in identities]
        roles_map = {}
        cred_map = {}
        graph_perms_map = {}
        pim_map = {}

        if id_list:
            ph = ','.join(['%s'] * len(id_list))
            # Top role per identity (highest privilege)
            cursor.execute(f"""
                SELECT ra.identity_db_id, ra.role_name, ra.scope, ra.scope_type
                FROM role_assignments ra WHERE ra.identity_db_id IN ({ph})
                ORDER BY ra.identity_db_id
            """, id_list)
            for r in cursor.fetchall():
                dbid = r['identity_db_id']
                if dbid not in roles_map:
                    roles_map[dbid] = []
                roles_map[dbid].append(r)

            # Entra roles
            cursor.execute(f"""
                SELECT era.identity_db_id, era.role_name
                FROM entra_role_assignments era WHERE era.identity_db_id IN ({ph})
            """, id_list)
            for r in cursor.fetchall():
                dbid = r['identity_db_id']
                if dbid not in roles_map:
                    roles_map[dbid] = []
                roles_map[dbid].append({'role_name': r['role_name'], 'scope': None, 'scope_type': 'tenant'})

            # Credentials
            cursor.execute(f"""
                SELECT c.identity_db_id, c.end_datetime, c.start_datetime, c.credential_type
                FROM credentials c WHERE c.identity_db_id IN ({ph})
                ORDER BY c.end_datetime ASC NULLS LAST
            """, id_list)
            for r in cursor.fetchall():
                dbid = r['identity_db_id']
                if dbid not in cred_map:
                    cred_map[dbid] = r

            # Graph API permissions
            cursor.execute(f"""
                SELECT g.identity_db_id, g.permission_name
                FROM graph_api_permissions g WHERE g.identity_db_id IN ({ph})
            """, id_list)
            for r in cursor.fetchall():
                dbid = r['identity_db_id']
                if dbid not in graph_perms_map:
                    graph_perms_map[dbid] = []
                graph_perms_map[dbid].append(r['permission_name'])

            # PIM eligibility
            cursor.execute(f"""
                SELECT pe.identity_db_id FROM pim_eligible_assignments pe
                WHERE pe.identity_db_id IN ({ph})
            """, id_list)
            for r in cursor.fetchall():
                pim_map[r['identity_db_id']] = True

        count = 0
        for ident in identities:
            dbid = ident['id']
            roles = roles_map.get(dbid, [])
            cred = cred_map.get(dbid)
            graph_perms = graph_perms_map.get(dbid, [])
            is_pim = pim_map.get(dbid, False)

            # Compute V2 fields
            top_role = _pick_top_role(roles) if roles else None
            access_role = top_role['role_name'] if top_role else None
            scope_type = top_role.get('scope_type', 'resource') if top_role else None
            access_scope = _format_scope(top_role.get('scope')) if top_role else None
            cloud_provider = 'Azure'  # Default; multi-cloud when engines exist

            # Identity type mapping
            cat = ident['identity_category']
            type_map = {'service_principal': 'service_principal', 'managed_identity_system': 'managed_identity',
                        'managed_identity_user': 'managed_identity', 'human_user': 'human', 'guest': 'human'}
            identity_type = type_map.get(cat, cat or 'unknown')

            # Usage
            last_used_days = None
            if ident.get('last_sign_in'):
                from datetime import datetime, timezone
                try:
                    delta = datetime.now(timezone.utc) - ident['last_sign_in'].replace(tzinfo=timezone.utc) if ident['last_sign_in'].tzinfo is None else datetime.now(timezone.utc) - ident['last_sign_in']
                    last_used_days = delta.days
                except Exception:
                    pass

            # Risk scoring
            risk_score, risk_factors = _compute_review_risk(
                access_role, scope_type, last_used_days, cred, graph_perms,
                is_pim, ident.get('mfa_enforced', False)
            )

            # Privilege level
            privilege_level = _compute_privilege_level(access_role, is_pim)

            # Credential risk
            cred_risk, cred_risk_level = _compute_credential_risk(cred)

            # AI recommendation
            ai_rec, ai_reason = _generate_ai_recommendation(
                risk_score, risk_factors, identity_type, last_used_days, cred_risk
            )

            cursor.execute("""
                INSERT INTO campaign_reviews (campaign_id, identity_id, identity_display_name,
                    identity_risk_level, identity_category, reviewer_id,
                    identity_db_id, identity_type, access_role, access_scope, cloud_provider,
                    risk_score, risk_factors, last_used_date, last_used_days, privilege_level,
                    credential_risk, credential_risk_level, ai_recommendation, ai_recommendation_reason,
                    review_due_date)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (campaign_id, ident['identity_id'], ident['display_name'],
                  ident['risk_level'], cat, reviewer_id,
                  dbid, identity_type, access_role, access_scope, cloud_provider,
                  risk_score, json.dumps(risk_factors), ident.get('last_sign_in'), last_used_days,
                  privilege_level, cred_risk, cred_risk_level, ai_rec, ai_reason, deadline))
            count += 1

        self.conn.commit()
        cursor.close()
        return count

    def log_campaign_audit(self, campaign_id, review_id, action, actor_id, old_value=None, new_value=None, metadata=None):
        """Write to campaign_audit_log."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO campaign_audit_log (campaign_id, review_id, action, actor_id, old_value, new_value, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (campaign_id, review_id, action, actor_id, old_value, new_value,
              json.dumps(metadata) if metadata else '{}'))
        self.conn.commit()
        cursor.close()

    def get_campaign_metrics(self):
        """Compute dashboard KPIs across all campaigns."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE c.status = 'active') as active_count,
                COUNT(*) FILTER (WHERE c.status = 'active' AND c.deadline < NOW()) as overdue_count
            FROM access_review_campaigns c
        """)
        camp = dict(cursor.fetchone())
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE cr.decision IS NOT NULL) as decided,
                COUNT(*) FILTER (WHERE cr.decision = 'revoke') as revoked,
                COUNT(*) FILTER (WHERE cr.decision IS NULL AND UPPER(cr.identity_risk_level) IN ('CRITICAL','HIGH')) as high_risk_pending,
                COUNT(*) FILTER (WHERE cr.identity_type IN ('service_principal','managed_identity','aws_iam_role','gcp_service_account')) as nhi_count
            FROM campaign_reviews cr
            JOIN access_review_campaigns c ON c.id = cr.campaign_id AND c.status = 'active'
        """)
        rev = dict(cursor.fetchone())
        cursor.close()
        total = rev['total'] or 0
        decided = rev['decided'] or 0
        revoked = rev['revoked'] or 0
        return {
            'active_count': camp['active_count'],
            'overdue_count': camp['overdue_count'],
            'completion_rate': round(decided / total * 100) if total else 0,
            'high_risk_pending': rev['high_risk_pending'],
            'revocation_rate': round(revoked / decided * 100) if decided else 0,
            'risk_reduction': 0,
            'nhi_percentage': round(rev['nhi_count'] / total * 100) if total else 0,
        }

    def get_campaign_reviews(self, campaign_id: int) -> list:
        """Get all reviews for a campaign, pending first."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT cr.*, u.display_name as reviewer_name
            FROM campaign_reviews cr
            LEFT JOIN users u ON u.id = cr.reviewer_id
            WHERE cr.campaign_id = %s
            ORDER BY
                CASE WHEN cr.decision IS NULL THEN 0 ELSE 1 END,
                cr.identity_display_name ASC
        """, (campaign_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('decided_at', 'created_at'):
                if r.get(ts) and hasattr(r[ts], 'isoformat'):
                    r[ts] = r[ts].isoformat()
        return rows

    def update_campaign_review(self, review_id: int, decision: str, notes: str = None, reviewer_id: int = None) -> dict:
        """Set decision on a single review."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE campaign_reviews
            SET decision = %s, notes = %s, reviewer_id = COALESCE(%s, reviewer_id), decided_at = NOW()
            WHERE id = %s
            RETURNING *
        """, (decision, notes, reviewer_id, review_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('decided_at', 'created_at'):
            if result.get(ts) and hasattr(result[ts], 'isoformat'):
                result[ts] = result[ts].isoformat()
        return result

    def bulk_update_campaign_reviews(self, review_ids: list, decision: str, notes: str = None, reviewer_id: int = None) -> int:
        """Bulk set decision on multiple reviews."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE campaign_reviews
            SET decision = %s, notes = %s, reviewer_id = COALESCE(%s, reviewer_id), decided_at = NOW()
            WHERE id = ANY(%s)
        """, (decision, notes, reviewer_id, review_ids))
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    def get_campaign_reviews_v2(self, campaign_id: int, limit: int = 50, offset: int = 0,
                               sort_by: str = 'risk_score', sort_dir: str = 'desc',
                               status_filter: str = None, risk_filter: str = None,
                               type_filter: str = None, search: str = None) -> dict:
        """Get paginated, filtered, sorted reviews for a campaign (V2)."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        where_parts = ["cr.campaign_id = %s"]
        params = [campaign_id]

        if status_filter == 'pending':
            where_parts.append("cr.decision IS NULL")
        elif status_filter == 'decided':
            where_parts.append("cr.decision IS NOT NULL")
        elif status_filter in ('approve', 'revoke', 'flag'):
            where_parts.append("cr.decision = %s")
            params.append(status_filter)

        if risk_filter:
            where_parts.append("UPPER(cr.identity_risk_level) = %s")
            params.append(risk_filter.upper())

        if type_filter:
            where_parts.append("cr.identity_type = %s")
            params.append(type_filter)

        if search:
            where_parts.append("(cr.identity_display_name ILIKE %s OR cr.identity_id ILIKE %s OR cr.access_role ILIKE %s)")
            s = f'%{search}%'
            params.extend([s, s, s])

        where_clause = " AND ".join(where_parts)

        # Count
        cursor.execute(f"SELECT COUNT(*) as cnt FROM campaign_reviews cr WHERE {where_clause}", params)
        total = cursor.fetchone()['cnt']

        # Sort
        allowed_sorts = {
            'risk_score': 'cr.risk_score', 'identity_display_name': 'cr.identity_display_name',
            'decision': 'cr.decision', 'identity_risk_level': 'cr.identity_risk_level',
            'last_used_days': 'cr.last_used_days', 'privilege_level': 'cr.privilege_level',
            'ai_recommendation': 'cr.ai_recommendation', 'credential_risk_level': 'cr.credential_risk_level',
        }
        order_col = allowed_sorts.get(sort_by, 'cr.risk_score')
        direction = 'ASC' if sort_dir.lower() == 'asc' else 'DESC'

        cursor.execute(f"""
            SELECT cr.*, u.display_name as reviewer_name
            FROM campaign_reviews cr
            LEFT JOIN users u ON u.id = cr.reviewer_id
            WHERE {where_clause}
            ORDER BY {order_col} {direction} NULLS LAST, cr.id
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('decided_at', 'created_at', 'last_used_date', 'review_due_date', 'updated_at'):
                if r.get(ts) and hasattr(r[ts], 'isoformat'):
                    r[ts] = r[ts].isoformat()
            if isinstance(r.get('risk_factors'), str):
                try:
                    r['risk_factors'] = json.loads(r['risk_factors'])
                except Exception:
                    pass
        return {'reviews': rows, 'total': total, 'limit': limit, 'offset': offset}

    def get_campaign_audit_log(self, campaign_id: int, limit: int = 100, offset: int = 0) -> dict:
        """Get audit log for a campaign."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT COUNT(*) as cnt FROM campaign_audit_log WHERE campaign_id = %s", (campaign_id,))
        total = cursor.fetchone()['cnt']
        cursor.execute("""
            SELECT cal.*, u.display_name as actor_name, u.username as actor_username
            FROM campaign_audit_log cal
            LEFT JOIN users u ON u.id = cal.actor_id
            WHERE cal.campaign_id = %s
            ORDER BY cal.created_at DESC
            LIMIT %s OFFSET %s
        """, (campaign_id, limit, offset))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
            if isinstance(r.get('metadata'), str):
                try:
                    r['metadata'] = json.loads(r['metadata'])
                except Exception:
                    pass
        return {'entries': rows, 'total': total}

    # ---------------------------------------------------------------
    # Identity Groups (Phase 38)
    # ---------------------------------------------------------------
    def _ensure_identity_group_tables(self):
        """Create identity_groups and identity_group_members tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity_groups (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                color VARCHAR(20) DEFAULT '#3B82F6',
                group_type VARCHAR(10) NOT NULL DEFAULT 'custom',
                auto_criteria JSONB,
                created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_identity_groups_type ON identity_groups(group_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_identity_groups_name ON identity_groups(name)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity_group_members (
                id SERIAL PRIMARY KEY,
                group_id INTEGER NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
                identity_id TEXT NOT NULL,
                added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_members_unique ON identity_group_members(group_id, identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_group_members_identity ON identity_group_members(identity_id)")
        self.conn.commit()
        cursor.close()

    def _build_auto_criteria_where(self, criteria: dict) -> tuple:
        """Build WHERE clause fragments from auto_criteria JSON. Returns (clause_parts, params)."""
        parts = []
        params = []
        allowed = {'identity_category', 'cloud', 'status', 'risk_level', 'activity_status'}
        for key, val in criteria.items():
            if key not in allowed:
                continue
            if isinstance(val, list):
                parts.append(f"COALESCE(i.{key}, '') = ANY(%s)")
                params.append(val)
            else:
                parts.append(f"COALESCE(i.{key}, '') = %s")
                params.append(val)
        return parts, params

    def _get_group_risk_stats(self, cursor, group_id: int = None, auto_criteria: dict = None, latest_run: int = None) -> dict:
        """Compute risk breakdown for a group's members."""
        if latest_run is None:
            cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
            row = cursor.fetchone()
            latest_run = row[0] if row else None
        if not latest_run:
            return {'member_count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'avg_risk_score': 0}

        if auto_criteria:
            where_parts, where_params = self._build_auto_criteria_where(auto_criteria)
            where_clause = (" AND " + " AND ".join(where_parts)) if where_parts else ""
            cursor.execute(f"""
                SELECT COUNT(*) as cnt,
                    COUNT(*) FILTER (WHERE risk_level = 'critical') as critical,
                    COUNT(*) FILTER (WHERE risk_level = 'high') as high,
                    COUNT(*) FILTER (WHERE risk_level = 'medium') as medium,
                    COUNT(*) FILTER (WHERE risk_level = 'low') as low,
                    COUNT(*) FILTER (WHERE risk_level = 'info') as info,
                    COALESCE(AVG(COALESCE(risk_score, 0)), 0) as avg_score
                FROM identities i
                WHERE i.discovery_run_id = %s{where_clause}
            """, [latest_run] + where_params)
        else:
            cursor.execute("""
                SELECT COUNT(*) as cnt,
                    COUNT(*) FILTER (WHERE i.risk_level = 'critical') as critical,
                    COUNT(*) FILTER (WHERE i.risk_level = 'high') as high,
                    COUNT(*) FILTER (WHERE i.risk_level = 'medium') as medium,
                    COUNT(*) FILTER (WHERE i.risk_level = 'low') as low,
                    COUNT(*) FILTER (WHERE i.risk_level = 'info') as info,
                    COALESCE(AVG(COALESCE(i.risk_score, 0)), 0) as avg_score
                FROM identities i
                JOIN identity_group_members m ON m.identity_id = i.identity_id
                WHERE i.discovery_run_id = %s AND m.group_id = %s
            """, (latest_run, group_id))
        row = cursor.fetchone()
        return {
            'member_count': row[0],
            'critical': row[1], 'high': row[2], 'medium': row[3], 'low': row[4], 'info': row[5],
            'avg_risk_score': round(float(row[6]), 1)
        }

    def get_groups(self) -> list:
        """Get all identity groups with summary stats."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        row = cursor.fetchone()
        latest_run = row['max'] if row else None

        cursor.execute("""
            SELECT g.*, u.username as creator_name
            FROM identity_groups g
            LEFT JOIN users u ON u.id = g.created_by
            ORDER BY g.group_type ASC, g.name ASC
        """)
        groups = [dict(r) for r in cursor.fetchall()]
        cursor.close()

        # Switch to regular cursor for risk stats
        cursor2 = self.conn.cursor()
        for g in groups:
            if g['group_type'] == 'auto' and g.get('auto_criteria'):
                stats = self._get_group_risk_stats(cursor2, auto_criteria=g['auto_criteria'], latest_run=latest_run)
            else:
                stats = self._get_group_risk_stats(cursor2, group_id=g['id'], latest_run=latest_run)
            g.update(stats)
            for ts in ('created_at', 'updated_at'):
                if g.get(ts) and hasattr(g[ts], 'isoformat'):
                    g[ts] = g[ts].isoformat()
            if g.get('auto_criteria') and not isinstance(g['auto_criteria'], dict):
                import json as _json
                g['auto_criteria'] = _json.loads(g['auto_criteria']) if isinstance(g['auto_criteria'], str) else g['auto_criteria']
        cursor2.close()
        return groups

    def get_group(self, group_id: int) -> Optional[dict]:
        """Get a single group with its member identities."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT g.*, u.username as creator_name
            FROM identity_groups g
            LEFT JOIN users u ON u.id = g.created_by
            WHERE g.id = %s
        """, (group_id,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            return None
        group = dict(row)
        for ts in ('created_at', 'updated_at'):
            if group.get(ts) and hasattr(group[ts], 'isoformat'):
                group[ts] = group[ts].isoformat()

        # Get latest run
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        lr = cursor.fetchone()
        latest_run = lr['max'] if lr else None

        # Get members
        members = []
        if latest_run:
            if group['group_type'] == 'auto' and group.get('auto_criteria'):
                where_parts, where_params = self._build_auto_criteria_where(group['auto_criteria'])
                where_clause = (" AND " + " AND ".join(where_parts)) if where_parts else ""
                cursor.execute(f"""
                    SELECT i.identity_id, i.display_name, COALESCE(i.identity_category, '') as identity_category,
                        COALESCE(i.cloud, 'azure') as cloud, i.risk_level,
                        COALESCE(i.risk_score, 0) as risk_score, i.activity_status, i.last_seen_auth
                    FROM identities i
                    WHERE i.discovery_run_id = %s{where_clause}
                    ORDER BY i.risk_level DESC NULLS LAST, i.display_name ASC
                """, [latest_run] + where_params)
            else:
                cursor.execute("""
                    SELECT i.identity_id, i.display_name, COALESCE(i.identity_category, '') as identity_category,
                        COALESCE(i.cloud, 'azure') as cloud, i.risk_level,
                        COALESCE(i.risk_score, 0) as risk_score, i.activity_status, i.last_seen_auth
                    FROM identities i
                    JOIN identity_group_members m ON m.identity_id = i.identity_id
                    WHERE i.discovery_run_id = %s AND m.group_id = %s
                    ORDER BY i.risk_level DESC NULLS LAST, i.display_name ASC
                """, (latest_run, group_id))
            members = [dict(r) for r in cursor.fetchall()]
            for m in members:
                if m.get('last_seen_auth') and hasattr(m['last_seen_auth'], 'isoformat'):
                    m['last_seen_auth'] = m['last_seen_auth'].isoformat()

        # Risk stats
        cursor2 = self.conn.cursor()
        if group['group_type'] == 'auto' and group.get('auto_criteria'):
            stats = self._get_group_risk_stats(cursor2, auto_criteria=group['auto_criteria'], latest_run=latest_run)
        else:
            stats = self._get_group_risk_stats(cursor2, group_id=group_id, latest_run=latest_run)
        cursor2.close()

        group.update(stats)
        group['members'] = members
        cursor.close()
        return group

    def create_group(self, data: dict) -> dict:
        """Create a new identity group."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO identity_groups (name, description, color, group_type, auto_criteria, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (
            data['name'], data.get('description'), data.get('color', '#3B82F6'),
            data.get('group_type', 'custom'),
            json.dumps(data['auto_criteria']) if data.get('auto_criteria') else None,
            data.get('created_by')
        ))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at'):
            if row.get(ts) and hasattr(row[ts], 'isoformat'):
                row[ts] = row[ts].isoformat()
        return row

    def update_group(self, group_id: int, data: dict) -> Optional[dict]:
        """Update a group's name, description, or color."""
        self._ensure_identity_group_tables()
        allowed = {'name', 'description', 'color'}
        sets = []
        params = []
        for k in allowed:
            if k in data:
                sets.append(f"{k} = %s")
                params.append(data[k])
        if not sets:
            return self.get_group(group_id)
        sets.append("updated_at = NOW()")
        params.append(group_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE identity_groups SET {', '.join(sets)} WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at'):
            if result.get(ts) and hasattr(result[ts], 'isoformat'):
                result[ts] = result[ts].isoformat()
        return result

    def delete_group(self, group_id: int) -> bool:
        """Delete a custom group. Returns False if not found or is auto group."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor()
        cursor.execute("SELECT group_type FROM identity_groups WHERE id = %s", (group_id,))
        row = cursor.fetchone()
        if not row or row[0] == 'auto':
            cursor.close()
            return False
        cursor.execute("DELETE FROM identity_groups WHERE id = %s", (group_id,))
        self.conn.commit()
        cursor.close()
        return True

    def add_group_members(self, group_id: int, identity_ids: list) -> int:
        """Add identities to a custom group. Returns count of new members added."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor()
        added = 0
        for iid in identity_ids:
            cursor.execute("""
                INSERT INTO identity_group_members (group_id, identity_id)
                VALUES (%s, %s)
                ON CONFLICT (group_id, identity_id) DO NOTHING
            """, (group_id, iid))
            added += cursor.rowcount
        self.conn.commit()
        cursor.close()
        return added

    def remove_group_members(self, group_id: int, identity_ids: list) -> int:
        """Remove identities from a custom group."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            DELETE FROM identity_group_members
            WHERE group_id = %s AND identity_id = ANY(%s)
        """, (group_id, identity_ids))
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    def get_group_comparison(self, group_ids: list) -> list:
        """Get comparison data for 2-3 groups."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        lr = cursor.fetchone()
        latest_run = lr['max'] if lr else None

        results = []
        for gid in group_ids:
            cursor.execute("SELECT * FROM identity_groups WHERE id = %s", (gid,))
            row = cursor.fetchone()
            if not row:
                continue
            group = dict(row)
            for ts in ('created_at', 'updated_at'):
                if group.get(ts) and hasattr(group[ts], 'isoformat'):
                    group[ts] = group[ts].isoformat()

            cursor2 = self.conn.cursor()
            if group['group_type'] == 'auto' and group.get('auto_criteria'):
                stats = self._get_group_risk_stats(cursor2, auto_criteria=group['auto_criteria'], latest_run=latest_run)
                # Category breakdown for auto groups
                where_parts, where_params = self._build_auto_criteria_where(group['auto_criteria'])
                where_clause = (" AND " + " AND ".join(where_parts)) if where_parts else ""
                if latest_run:
                    cursor2.execute(f"""
                        SELECT COALESCE(i.identity_category, 'unknown') as cat, COUNT(*) as cnt
                        FROM identities i WHERE i.discovery_run_id = %s{where_clause}
                        GROUP BY 1
                    """, [latest_run] + where_params)
                    cat_rows = cursor2.fetchall()
                else:
                    cat_rows = []
            else:
                stats = self._get_group_risk_stats(cursor2, group_id=gid, latest_run=latest_run)
                if latest_run:
                    cursor2.execute("""
                        SELECT COALESCE(i.identity_category, 'unknown') as cat, COUNT(*) as cnt
                        FROM identities i
                        JOIN identity_group_members m ON m.identity_id = i.identity_id
                        WHERE i.discovery_run_id = %s AND m.group_id = %s
                        GROUP BY 1
                    """, (latest_run, gid))
                    cat_rows = cursor2.fetchall()
                else:
                    cat_rows = []
            cursor2.close()

            categories = {r[0]: r[1] for r in cat_rows}
            group.update(stats)
            group['category_breakdown'] = categories
            results.append(group)

        cursor.close()
        return results

    def get_identity_groups(self, identity_id: str) -> list:
        """Get all groups an identity belongs to (custom memberships + matching auto groups)."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Custom groups via membership
        cursor.execute("""
            SELECT g.id, g.name, g.color, g.group_type
            FROM identity_groups g
            JOIN identity_group_members m ON m.group_id = g.id
            WHERE m.identity_id = %s
            ORDER BY g.name
        """, (identity_id,))
        custom = [dict(r) for r in cursor.fetchall()]

        # Auto groups: check if identity matches criteria
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
        lr = cursor.fetchone()
        latest_run = lr['max'] if lr else None

        auto = []
        if latest_run:
            cursor.execute("SELECT * FROM identity_groups WHERE group_type = 'auto'")
            auto_groups = [dict(r) for r in cursor.fetchall()]
            for ag in auto_groups:
                if not ag.get('auto_criteria'):
                    continue
                criteria = ag['auto_criteria'] if isinstance(ag['auto_criteria'], dict) else json.loads(ag['auto_criteria'])
                where_parts, where_params = self._build_auto_criteria_where(criteria)
                where_clause = (" AND " + " AND ".join(where_parts)) if where_parts else ""
                cursor.execute(f"""
                    SELECT 1 FROM identities i
                    WHERE i.discovery_run_id = %s AND i.identity_id = %s{where_clause}
                    LIMIT 1
                """, [latest_run, identity_id] + where_params)
                if cursor.fetchone():
                    auto.append({'id': ag['id'], 'name': ag['name'], 'color': ag['color'], 'group_type': 'auto'})

        cursor.close()
        return auto + custom

    def seed_auto_groups(self):
        """Create default auto groups on startup if they don't exist."""
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM identity_groups WHERE group_type = 'auto'")
        count = cursor.fetchone()[0]
        if count > 0:
            cursor.close()
            return

        auto_groups = [
            ('All Service Principals', '#6366F1', {'identity_category': 'service_principal'}),
            ('All Human Users', '#3B82F6', {'identity_category': 'human_user'}),
            ('All Managed Identities', '#8B5CF6', {'identity_category': ['managed_identity_system', 'managed_identity_user']}),
            ('All Guest Users', '#F59E0B', {'identity_category': 'guest'}),
        ]
        for name, color, criteria in auto_groups:
            cursor.execute("""
                INSERT INTO identity_groups (name, color, group_type, auto_criteria)
                VALUES (%s, %s, 'auto', %s)
            """, (name, color, json.dumps(criteria)))
        self.conn.commit()
        cursor.close()

    # ================================================================
    # Phase 40: Anomaly Detection
    # ================================================================

    def _ensure_anomalies_table(self):
        """Create anomalies table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id SERIAL PRIMARY KEY,
                discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE CASCADE,
                anomaly_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL DEFAULT 'medium',
                identity_id TEXT,
                identity_name VARCHAR(255),
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                details JSONB,
                resolved BOOLEAN DEFAULT false,
                resolved_at TIMESTAMPTZ,
                resolved_by VARCHAR(100),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_run_id ON anomalies(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_type ON anomalies(anomaly_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_identity ON anomalies(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_created ON anomalies(created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_resolved ON anomalies(resolved)")
        self.conn.commit()
        cursor.close()

    def save_anomalies(self, run_id: int, anomalies: list) -> int:
        """Batch insert anomaly dicts. Returns count inserted."""
        self._ensure_anomalies_table()
        if not anomalies:
            return 0
        cursor = self.conn.cursor()
        for a in anomalies:
            cursor.execute("""
                INSERT INTO anomalies
                    (discovery_run_id, anomaly_type, severity, identity_id, identity_name,
                     title, description, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                run_id, a['anomaly_type'], a.get('severity', 'medium'),
                a.get('identity_id'), a.get('identity_name'),
                a['title'], a['description'],
                json.dumps(a['details']) if a.get('details') else None,
            ))
        self.conn.commit()
        cursor.close()
        return len(anomalies)

    def get_anomalies(self, limit=50, offset=0, anomaly_type=None, severity=None,
                      identity_id=None, resolved=None, run_id=None) -> list:
        """Get anomalies with optional filters, most recent first."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        conditions = []
        params = []
        if anomaly_type:
            conditions.append("anomaly_type = %s")
            params.append(anomaly_type)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if identity_id:
            conditions.append("identity_id = %s")
            params.append(identity_id)
        if resolved is not None:
            conditions.append("resolved = %s")
            params.append(resolved)
        if run_id:
            conditions.append("discovery_run_id = %s")
            params.append(run_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])
        cursor.execute(f"""
            SELECT * FROM anomalies {where}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts_field in ('created_at', 'resolved_at'):
                if r.get(ts_field):
                    r[ts_field] = r[ts_field].isoformat()
        return rows

    def get_anomaly(self, anomaly_id: int) -> dict:
        """Get a single anomaly by ID."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM anomalies WHERE id = %s", (anomaly_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts_field in ('created_at', 'resolved_at'):
            if result.get(ts_field):
                result[ts_field] = result[ts_field].isoformat()
        return result

    def get_anomaly_stats(self) -> dict:
        """Get anomaly summary: total, unresolved, by_type, by_severity."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT COUNT(*) as total FROM anomalies")
        total = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as unresolved FROM anomalies WHERE resolved = false")
        unresolved = cursor.fetchone()['unresolved']
        cursor.execute("SELECT anomaly_type, COUNT(*) as count FROM anomalies WHERE resolved = false GROUP BY anomaly_type ORDER BY count DESC")
        by_type = {r['anomaly_type']: r['count'] for r in cursor.fetchall()}
        cursor.execute("SELECT severity, COUNT(*) as count FROM anomalies WHERE resolved = false GROUP BY severity ORDER BY count DESC")
        by_severity = {r['severity']: r['count'] for r in cursor.fetchall()}
        cursor.close()
        return {
            'total': total,
            'unresolved': unresolved,
            'by_type': by_type,
            'by_severity': by_severity,
        }

    def get_identity_anomalies(self, identity_id: str, limit=20) -> list:
        """Get anomalies for a specific identity across all runs."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM anomalies
            WHERE identity_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (identity_id, limit))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts_field in ('created_at', 'resolved_at'):
                if r.get(ts_field):
                    r[ts_field] = r[ts_field].isoformat()
        return rows

    def resolve_anomaly(self, anomaly_id: int, resolved_by: str = None) -> dict:
        """Mark an anomaly as resolved with timestamp."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE anomalies
            SET resolved = true, resolved_at = NOW(), resolved_by = %s
            WHERE id = %s
            RETURNING *
        """, (resolved_by, anomaly_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts_field in ('created_at', 'resolved_at'):
            if result.get(ts_field):
                result[ts_field] = result[ts_field].isoformat()
        return result

    def get_anomalies_for_dashboard(self, limit=5) -> list:
        """Get top unresolved anomalies for dashboard, ordered by severity then recency."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT * FROM anomalies
            WHERE resolved = false
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                created_at DESC
            LIMIT %s
        """, (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts_field in ('created_at', 'resolved_at'):
                if r.get(ts_field):
                    r[ts_field] = r[ts_field].isoformat()
        return rows

    def cleanup_old_anomalies(self, days=180) -> int:
        """Delete old resolved anomalies."""
        self._ensure_anomalies_table()
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM anomalies WHERE resolved = true AND created_at < NOW() - INTERVAL '%s days'",
            (days,)
        )
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    # ── Phase 42: API Key Management ─────────────────────────────────

    def _ensure_api_keys_table(self):
        """Create api_keys table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                key_prefix VARCHAR(12) NOT NULL,
                key_hash VARCHAR(64) NOT NULL,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                role VARCHAR(20) NOT NULL DEFAULT 'viewer',
                enabled BOOLEAN DEFAULT true,
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_used_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ,
                usage_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)")
        self.conn.commit()
        cursor.close()

    def create_api_key(self, key_prefix, key_hash, name, description, role, created_by, expires_at=None):
        """Insert a new API key. Returns dict (never includes key_hash)."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO api_keys (key_prefix, key_hash, name, description, role, created_by, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, key_prefix, name, description, role, enabled, created_by,
                      created_at, last_used_at, expires_at, usage_count
        """, (key_prefix, key_hash, name, description, role, created_by, expires_at))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'last_used_at', 'expires_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def get_api_keys(self):
        """List all API keys with creator name. Never returns key_hash."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT ak.id, ak.key_prefix, ak.name, ak.description, ak.role,
                   ak.enabled, ak.created_by, u.display_name as created_by_name,
                   ak.created_at, ak.last_used_at, ak.expires_at, ak.usage_count
            FROM api_keys ak
            LEFT JOIN users u ON u.id = ak.created_by
            ORDER BY ak.id
        """)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('created_at', 'last_used_at', 'expires_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_api_key_by_id(self, key_id):
        """Get single API key by id. Never returns key_hash."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, key_prefix, name, description, role, enabled, created_by,
                   created_at, last_used_at, expires_at, usage_count
            FROM api_keys WHERE id = %s
        """, (key_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'last_used_at', 'expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def get_api_key_by_hash(self, key_hash):
        """Look up API key by hash. Used by auth middleware. Returns full row including role/enabled."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, key_prefix, key_hash, name, role, enabled, created_by,
                   expires_at, usage_count
            FROM api_keys WHERE key_hash = %s
        """, (key_hash,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        # Keep expires_at as datetime for comparison in middleware
        return result

    def update_api_key(self, key_id, **kwargs):
        """Update API key fields. Allowed: name, description, role, enabled."""
        self._ensure_api_keys_table()
        allowed = {'name', 'description', 'role', 'enabled'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_api_key_by_id(key_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            params.append(v)
        params.append(key_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE api_keys SET {', '.join(set_parts)}
            WHERE id = %s
            RETURNING id, key_prefix, name, description, role, enabled, created_by,
                      created_at, last_used_at, expires_at, usage_count
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'last_used_at', 'expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def delete_api_key(self, key_id):
        """Delete API key. Returns True if deleted."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE id = %s", (key_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def increment_api_key_usage(self, key_id):
        """Increment usage count and update last_used_at."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE api_keys SET usage_count = usage_count + 1, last_used_at = NOW() WHERE id = %s",
            (key_id,)
        )
        self.conn.commit()
        cursor.close()

    # ── Phase 43: SOAR Integration ─────────────────────────────────

    def _ensure_soar_tables(self):
        """Create soar_playbooks and soar_actions tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS soar_playbooks (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                enabled BOOLEAN DEFAULT true,
                trigger_type VARCHAR(30) NOT NULL,
                trigger_conditions JSONB NOT NULL DEFAULT '{}',
                action_type VARCHAR(30) NOT NULL,
                action_config JSONB NOT NULL DEFAULT '{}',
                integration VARCHAR(30) NOT NULL DEFAULT 'internal',
                cooldown_minutes INTEGER DEFAULT 60,
                created_by VARCHAR(100),
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                last_triggered_at TIMESTAMPTZ,
                trigger_count INTEGER DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS soar_actions (
                id SERIAL PRIMARY KEY,
                playbook_id INTEGER REFERENCES soar_playbooks(id) ON DELETE SET NULL,
                identity_id TEXT,
                anomaly_id INTEGER,
                trigger_event JSONB,
                action_type VARCHAR(30) NOT NULL,
                integration VARCHAR(30) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                result JSONB,
                executed_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_playbooks_trigger ON soar_playbooks(trigger_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_playbooks_enabled ON soar_playbooks(enabled)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_actions_playbook ON soar_actions(playbook_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_actions_status ON soar_actions(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_actions_created ON soar_actions(created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_soar_actions_identity ON soar_actions(identity_id)")
        self.conn.commit()
        cursor.close()

    def get_soar_playbooks(self):
        """List all SOAR playbooks."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM soar_playbooks ORDER BY created_at DESC")
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('created_at', 'updated_at', 'last_triggered_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_soar_playbook(self, playbook_id):
        """Get single SOAR playbook by ID."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM soar_playbooks WHERE id = %s", (playbook_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_triggered_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def create_soar_playbook(self, name, description, trigger_type, trigger_conditions,
                              action_type, action_config, integration, cooldown_minutes, created_by):
        """Create a new SOAR playbook."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO soar_playbooks (name, description, trigger_type, trigger_conditions,
                action_type, action_config, integration, cooldown_minutes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (name, description, trigger_type, json.dumps(trigger_conditions),
              action_type, json.dumps(action_config), integration, cooldown_minutes, created_by))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at', 'last_triggered_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def update_soar_playbook(self, playbook_id, **kwargs):
        """Update SOAR playbook fields."""
        self._ensure_soar_tables()
        allowed = {'name', 'description', 'enabled', 'trigger_type', 'trigger_conditions',
                   'action_type', 'action_config', 'integration', 'cooldown_minutes'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_soar_playbook(playbook_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            if k in ('trigger_conditions', 'action_config'):
                params.append(json.dumps(v))
            else:
                params.append(v)
        set_parts.append("updated_at = NOW()")
        params.append(playbook_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE soar_playbooks SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_triggered_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def delete_soar_playbook(self, playbook_id):
        """Delete a SOAR playbook. Returns True if deleted."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM soar_playbooks WHERE id = %s", (playbook_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def get_enabled_playbooks_by_trigger(self, trigger_type):
        """Get enabled playbooks matching a trigger type. Used by SOAR engine."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT * FROM soar_playbooks WHERE enabled = true AND trigger_type = %s ORDER BY id",
            (trigger_type,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    def update_soar_playbook_triggered(self, playbook_id):
        """Update last_triggered_at and increment trigger_count."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE soar_playbooks SET last_triggered_at = NOW(), trigger_count = trigger_count + 1 WHERE id = %s",
            (playbook_id,)
        )
        self.conn.commit()
        cursor.close()

    def create_soar_action(self, playbook_id, identity_id, anomaly_id, trigger_event,
                            action_type, integration):
        """Create a SOAR action record. Returns the action ID."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO soar_actions (playbook_id, identity_id, anomaly_id, trigger_event,
                action_type, integration, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'pending')
            RETURNING id
        """, (playbook_id, identity_id, anomaly_id,
              json.dumps(trigger_event) if trigger_event else None,
              action_type, integration))
        action_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return action_id

    def update_soar_action(self, action_id, status, result=None):
        """Update a SOAR action status and result."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor()
        extra = ""
        params = [status]
        if status == 'executing':
            extra = ", executed_at = NOW()"
        elif status in ('success', 'failed'):
            extra = ", completed_at = NOW()"
        if result is not None:
            extra += ", result = %s"
            params.append(json.dumps(result))
        params.append(action_id)
        cursor.execute(f"UPDATE soar_actions SET status = %s{extra} WHERE id = %s", params)
        self.conn.commit()
        cursor.close()

    def get_soar_actions(self, limit=50, offset=0, playbook_id=None, status=None, identity_id=None):
        """Get SOAR action history with optional filters."""
        self._ensure_soar_tables()
        where_parts = []
        params = []
        if playbook_id is not None:
            where_parts.append("sa.playbook_id = %s")
            params.append(playbook_id)
        if status:
            where_parts.append("sa.status = %s")
            params.append(status)
        if identity_id:
            where_parts.append("sa.identity_id = %s")
            params.append(identity_id)
        where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        params.extend([limit, offset])
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            SELECT sa.*, sp.name as playbook_name
            FROM soar_actions sa
            LEFT JOIN soar_playbooks sp ON sp.id = sa.playbook_id
            {where_clause}
            ORDER BY sa.created_at DESC
            LIMIT %s OFFSET %s
        """, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('executed_at', 'completed_at', 'created_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_soar_action_stats(self):
        """Get SOAR action summary stats."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'success') as success_count,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
                COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as recent_24h
            FROM soar_actions
        """)
        stats = dict(cursor.fetchone())
        stats['success_rate'] = round(stats['success_count'] / stats['total'] * 100, 1) if stats['total'] > 0 else 0
        cursor.execute("""
            SELECT integration, COUNT(*) as count
            FROM soar_actions GROUP BY integration ORDER BY count DESC
        """)
        stats['by_integration'] = {r['integration']: r['count'] for r in cursor.fetchall()}
        cursor.close()
        return stats

    # ==================================================================
    # Phase 44: Dashboard Preferences
    # ==================================================================

    def _ensure_dashboard_preferences_table(self):
        """Create dashboard_preferences table if not exists."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_preferences (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                preferences JSONB NOT NULL DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_prefs_user
            ON dashboard_preferences(user_id)
        """)
        self.conn.commit()
        cursor.close()

    def get_dashboard_preferences(self, user_id):
        """Get dashboard preferences for a user. Returns dict or None."""
        self._ensure_dashboard_preferences_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT * FROM dashboard_preferences WHERE user_id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def save_dashboard_preferences(self, user_id, preferences):
        """Upsert dashboard preferences for a user."""
        self._ensure_dashboard_preferences_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO dashboard_preferences (user_id, preferences)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                preferences = EXCLUDED.preferences,
                updated_at = NOW()
            RETURNING *
        """, (user_id, json.dumps(preferences)))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def delete_dashboard_preferences(self, user_id):
        """Delete dashboard preferences for a user (reset to default)."""
        self._ensure_dashboard_preferences_table()
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM dashboard_preferences WHERE user_id = %s",
            (user_id,)
        )
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    # ========================================================================
    # Phase 45: Multi-Tenant Foundation
    # ========================================================================

    _tenants_ensured = False

    def _ensure_tenants_table(self):
        """Create tenants table and run multi-tenant migration (idempotent, runs once per process)."""
        if Database._tenants_ensured:
            return
        cursor = self.conn.cursor()

        # 1. Create tenants table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                slug VARCHAR(100) UNIQUE NOT NULL,
                plan VARCHAR(20) NOT NULL DEFAULT 'free',
                settings JSONB NOT NULL DEFAULT '{}',
                enabled BOOLEAN DEFAULT true,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug)")
        # Phase 77: Add license columns
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_activated_at TIMESTAMPTZ")
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS license_expires_at TIMESTAMPTZ")
        # Phase 78: Add logo_url column
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_url TEXT")
        # Subscription term: 0=monthly, 1/3/5 = year commitments
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_term INTEGER NOT NULL DEFAULT 0")
        # Phase 85: Tenant onboarding metadata
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS primary_cloud VARCHAR(20)")
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS industry VARCHAR(100)")
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS compliance_framework VARCHAR(100)")
        cursor.execute("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active'")
        # Phase 78: Migrate growth→pro plan + API key role renames
        cursor.execute("UPDATE tenants SET plan = 'pro' WHERE plan = 'growth'")
        cursor.execute("UPDATE api_keys SET role = 'reader' WHERE role = 'auditor'")
        cursor.execute("UPDATE api_keys SET role = 'compliance' WHERE role = 'viewer'")
        self.conn.commit()

        # 2. Rename any existing "Default Organization" → "Acme Organization"
        cursor.execute("UPDATE tenants SET name = 'Acme Organization' WHERE slug = 'default' AND name = 'Default Organization'")
        self.conn.commit()

        # 3. Create default tenant if none exist
        cursor.execute("SELECT COUNT(*) FROM tenants")
        tenant_count = cursor.fetchone()[0]

        default_tenant_id = None
        if tenant_count == 0:
            cursor.execute("""
                INSERT INTO tenants (name, slug, plan)
                VALUES ('Acme Organization', 'default', 'enterprise')
                RETURNING id
            """)
            default_tenant_id = cursor.fetchone()[0]
            self.conn.commit()
        else:
            cursor.execute("SELECT id FROM tenants ORDER BY id LIMIT 1")
            row = cursor.fetchone()
            default_tenant_id = row[0] if row else None

        # 4. Add tenant_id + is_superadmin + portal_role columns to users
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id)")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT false")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_role VARCHAR(20)")
        # Phase 77: Add email/phone to users
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50)")
        self.conn.commit()

        if default_tenant_id:
            cursor.execute("UPDATE users SET tenant_id = %s WHERE tenant_id IS NULL", (default_tenant_id,))
            # Promote user id=1 to superadmin with portal_role
            cursor.execute("UPDATE users SET is_superadmin = true, portal_role = 'superadmin' WHERE id = 1 AND is_superadmin = false")
            # Backfill portal_role for existing superadmins
            cursor.execute("UPDATE users SET portal_role = 'superadmin' WHERE is_superadmin = true AND portal_role IS NULL")
            # Phase 76: Migrate support → poweradmin
            cursor.execute("UPDATE users SET portal_role = 'poweradmin' WHERE portal_role = 'support'")
            self.conn.commit()

        # 4. Add tenant_id to discovery_runs
        cursor.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_tenant ON discovery_runs(tenant_id)")
        if default_tenant_id:
            cursor.execute("UPDATE discovery_runs SET tenant_id = %s WHERE tenant_id IS NULL", (default_tenant_id,))
        self.conn.commit()

        # 5. Add tenant_id to settings + migrate PK
        cursor.execute("ALTER TABLE settings ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id)")
        if default_tenant_id:
            cursor.execute("UPDATE settings SET tenant_id = %s WHERE tenant_id IS NULL", (default_tenant_id,))
        # Migrate PK: drop old single-column PK, add composite unique
        try:
            cursor.execute("ALTER TABLE settings DROP CONSTRAINT IF EXISTS settings_pkey")
            cursor.execute("""
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'settings_tenant_key'
                    ) THEN
                        ALTER TABLE settings ADD CONSTRAINT settings_tenant_key UNIQUE (tenant_id, key);
                    END IF;
                END $$
            """)
            self.conn.commit()
        except Exception:
            self.conn.rollback()

        cursor.close()
        Database._tenants_ensured = True

    # ── Tenant CRUD ─────────────────────────────────────────────────────

    def get_tenants(self):
        """Get all tenants."""
        self._ensure_tenants_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT t.*, (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) AS user_count
            FROM tenants t ORDER BY t.id
        """)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for row in rows:
            for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
                if row.get(ts):
                    row[ts] = row[ts].isoformat()
        return rows

    def get_tenant_by_id(self, tenant_id):
        """Get a single tenant by ID."""
        self._ensure_tenants_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM tenants WHERE id = %s", (tenant_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def get_tenant_config(self, tenant_id):
        """Get cloud provider and add-on configuration for a tenant."""
        tenant = self.get_tenant_by_id(tenant_id)
        if not tenant:
            return None
        settings = tenant.get('settings') or {}
        cloud_providers = settings.get('cloud_providers', {
            'azure': {'enabled': True, 'plan': 'pro'},
            'aws': {'enabled': False, 'plan': None},
            'gcp': {'enabled': False, 'plan': None},
        })
        # Ensure all three providers exist with defaults
        for provider in ('azure', 'aws', 'gcp'):
            if provider not in cloud_providers:
                default_enabled = provider == 'azure'
                cloud_providers[provider] = {
                    'enabled': default_enabled,
                    'plan': 'pro' if default_enabled else None,
                }
        addons = settings.get('addons', {
            'extended_retention': False,
        })
        return {
            'tenant_id': tenant_id,
            'tenant_name': tenant.get('name'),
            'cloud_providers': cloud_providers,
            'addons': addons,
        }

    def get_tenant_by_slug(self, slug):
        """Get a tenant by slug."""
        self._ensure_tenants_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM tenants WHERE slug = %s", (slug,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def create_tenant(self, name, slug, plan='free', settings=None,
                      primary_cloud=None, industry=None, compliance_framework=None):
        """Create a new tenant."""
        self._ensure_tenants_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO tenants (name, slug, plan, settings, primary_cloud, industry, compliance_framework)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (name, slug, plan, json.dumps(settings or {}),
              primary_cloud, industry, compliance_framework))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def update_tenant(self, tenant_id, **kwargs):
        """Update tenant fields."""
        self._ensure_tenants_table()
        allowed = {'name', 'plan', 'enabled', 'settings', 'license_activated_at', 'license_expires_at',
                   'subscription_term', 'primary_cloud', 'industry', 'compliance_framework', 'status'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_tenant_by_id(tenant_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            params.append(json.dumps(v) if k == 'settings' else v)
        set_parts.append("updated_at = NOW()")
        params.append(tenant_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE tenants SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def delete_tenant(self, tenant_id):
        """Delete a tenant and all associated data. Returns True if deleted."""
        self._ensure_tenants_table()
        cursor = self.conn.cursor()
        # Remove dependent records first (users FK has no CASCADE)
        cursor.execute("DELETE FROM users WHERE tenant_id = %s", (tenant_id,))
        cursor.execute("DELETE FROM discovery_runs WHERE tenant_id = %s", (tenant_id,))
        cursor.execute("DELETE FROM settings WHERE tenant_id = %s", (tenant_id,))
        cursor.execute("DELETE FROM activity_log WHERE tenant_id = %s", (tenant_id,))
        cursor.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    # ── Phase 54: SSO Methods ──────────────────────────────────────────

    def get_user_by_external_id(self, external_id, tenant_id):
        """Look up an SSO user by their IdP subject ID within a tenant."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.*, t.name AS tenant_name, t.slug AS tenant_slug
            FROM users u
            LEFT JOIN tenants t ON t.id = u.tenant_id
            WHERE u.external_id = %s AND u.tenant_id = %s
        """, (external_id, tenant_id))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def create_sso_user(self, username, display_name, role, tenant_id, external_id):
        """Create SSO user with auth_provider='saml', no usable password."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO users (username, password_hash, display_name, role, tenant_id,
                               auth_provider, external_id)
            VALUES (%s, %s, %s, %s, %s, 'saml', %s)
            RETURNING id, username, display_name, role, enabled, created_at, updated_at,
                      last_login_at, tenant_id, is_superadmin, portal_role, auth_provider, external_id
        """, (username, '!sso-managed', display_name, role, tenant_id, external_id))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def update_sso_user(self, user_id, display_name=None, role=None, external_id=None):
        """Update SSO user attributes on subsequent logins."""
        self._ensure_users_table()
        updates = {}
        if display_name is not None:
            updates['display_name'] = display_name
        if role is not None:
            updates['role'] = role
        if external_id is not None:
            updates['external_id'] = external_id
        if not updates:
            return
        set_parts = [f"{k} = %s" for k in updates]
        set_parts.append("updated_at = NOW()")
        set_parts.append("last_login_at = NOW()")
        params = list(updates.values()) + [user_id]
        cursor = self.conn.cursor()
        cursor.execute(
            f"UPDATE users SET {', '.join(set_parts)} WHERE id = %s",
            params,
        )
        self.conn.commit()
        cursor.close()

    def create_sso_auth_code(self, user_id, tenant_id):
        """Generate and store a one-time SSO auth code. Returns the raw code."""
        import secrets
        self._ensure_users_table()
        code = secrets.token_urlsafe(64)
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO sso_auth_codes (code, user_id, tenant_id, expires_at)
            VALUES (%s, %s, %s, NOW() + INTERVAL '60 seconds')
        """, (code, user_id, tenant_id))
        self.conn.commit()
        cursor.close()
        return code

    def consume_sso_auth_code(self, code):
        """Look up code, verify not expired/used, mark used. Returns {user_id, tenant_id} or None."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE sso_auth_codes
            SET used = true
            WHERE code = %s AND used = false AND expires_at > NOW()
            RETURNING user_id, tenant_id
        """, (code,))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # Service Account Governance (Phase 63)
    # ------------------------------------------------------------------

    _sa_attestations_ensured = False

    def _ensure_sa_attestations_table(self):
        """Create sa_attestations table if it doesn't exist."""
        if Database._sa_attestations_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sa_attestations (
                id SERIAL PRIMARY KEY,
                identity_db_id INTEGER NOT NULL,
                identity_id TEXT NOT NULL,
                attested_by INTEGER NOT NULL REFERENCES users(id),
                status VARCHAR(30) NOT NULL,
                justification TEXT,
                attested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                next_due TIMESTAMPTZ,
                tenant_id INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_att_identity ON sa_attestations(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_att_tenant ON sa_attestations(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_att_attested ON sa_attestations(attested_at DESC)")
        self.conn.commit()
        cursor.close()
        Database._sa_attestations_ensured = True

    def create_sa_attestation(self, identity_id, identity_db_id, attested_by,
                              status, justification, interval_days=90, tenant_id=None):
        """Insert a new attestation. Returns the created row."""
        self._ensure_sa_attestations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO sa_attestations
                (identity_id, identity_db_id, attested_by, status, justification,
                 attested_at, next_due, tenant_id)
            VALUES (%s, %s, %s, %s, %s, NOW(),
                    NOW() + (%s || ' days')::INTERVAL, %s)
            RETURNING *
        """, (identity_id, identity_db_id, attested_by, status, justification,
              str(interval_days), tenant_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return dict(row) if row else None

    def get_latest_attestation(self, identity_id, tenant_id=None):
        """Return the most recent attestation for an identity, or None."""
        self._ensure_sa_attestations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        sql = """
            SELECT sa.*, u.display_name as attester_name
            FROM sa_attestations sa
            LEFT JOIN users u ON u.id = sa.attested_by
            WHERE sa.identity_id = %s
        """
        params = [identity_id]
        if tenant_id is not None:
            sql += " AND sa.tenant_id = %s"
            params.append(tenant_id)
        sql += " ORDER BY sa.attested_at DESC LIMIT 1"
        cursor.execute(sql, params)
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def get_attestations_for_identity(self, identity_id, tenant_id=None):
        """Return full attestation history for an identity."""
        self._ensure_sa_attestations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        sql = """
            SELECT sa.*, u.display_name as attester_name
            FROM sa_attestations sa
            LEFT JOIN users u ON u.id = sa.attested_by
            WHERE sa.identity_id = %s
        """
        params = [identity_id]
        if tenant_id is not None:
            sql += " AND sa.tenant_id = %s"
            params.append(tenant_id)
        sql += " ORDER BY sa.attested_at DESC"
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

    # ── Phase 72: Data Retention & Archival ───────────────────────────

    def cleanup_old_discovery_runs(self, days=90) -> dict:
        """Delete discovery runs and related data older than N days.
        Returns counts of deleted rows per table."""
        cursor = self.conn.cursor()
        counts = {}

        # Find old run IDs first
        cursor.execute(
            "SELECT id FROM discovery_runs WHERE started_at < NOW() - INTERVAL '%s days'",
            (days,)
        )
        old_ids = [r[0] for r in cursor.fetchall()]
        if not old_ids:
            cursor.close()
            return {'discovery_runs': 0, 'risk_scores': 0}

        placeholders = ','.join(['%s'] * len(old_ids))

        # Delete risk_scores linked to old runs
        cursor.execute(f"DELETE FROM risk_scores WHERE run_id IN ({placeholders})", old_ids)
        counts['risk_scores'] = cursor.rowcount

        # Delete the runs themselves
        cursor.execute(f"DELETE FROM discovery_runs WHERE id IN ({placeholders})", old_ids)
        counts['discovery_runs'] = cursor.rowcount

        self.conn.commit()
        cursor.close()
        return counts

    def cleanup_old_drift_reports(self, days=90) -> int:
        """Delete drift reports older than N days."""
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM drift_reports WHERE created_at < NOW() - INTERVAL '%s days'",
            (days,)
        )
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    def cleanup_old_activity_log(self, days=180) -> int:
        """Delete activity log entries older than N days."""
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM activity_log WHERE created_at < NOW() - INTERVAL '%s days'",
            (days,)
        )
        count = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return count

    def cleanup_old_soar_actions(self, days=90) -> int:
        """Delete SOAR action history older than N days."""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM soar_actions WHERE executed_at < NOW() - INTERVAL '%s days'",
                (days,)
            )
            count = cursor.rowcount
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            count = 0
        cursor.close()
        return count

    def get_storage_stats(self) -> dict:
        """Return database storage statistics."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        # Table sizes
        cursor.execute("""
            SELECT relname as table_name,
                   pg_relation_size(oid) as size_bytes,
                   pg_total_relation_size(oid) as total_bytes
            FROM pg_class
            WHERE relkind = 'r'
              AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
            ORDER BY pg_relation_size(oid) DESC
        """)
        tables = []
        total_size = 0
        for row in cursor.fetchall():
            size_mb = round(row['size_bytes'] / (1024 * 1024), 2)
            total_mb = round(row['total_bytes'] / (1024 * 1024), 2)
            tables.append({
                'name': row['table_name'],
                'size_mb': size_mb,
                'total_mb': total_mb,
            })
            total_size += row['total_bytes']

        # Row counts for key retention tables
        row_counts = {}
        for table in ['discovery_runs', 'drift_reports', 'activity_log', 'anomalies', 'soar_actions', 'notifications']:
            try:
                cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
                row_counts[table] = cursor.fetchone()['cnt']
            except Exception:
                self.conn.rollback()
                row_counts[table] = 0

        # Oldest records
        oldest = {}
        for table, col in [('discovery_runs', 'started_at'), ('drift_reports', 'created_at'),
                           ('activity_log', 'created_at'), ('anomalies', 'created_at')]:
            try:
                cursor.execute(f"SELECT MIN({col}) as oldest FROM {table}")
                val = cursor.fetchone()['oldest']
                oldest[table] = val.isoformat() if val else None
            except Exception:
                self.conn.rollback()
                oldest[table] = None

        cursor.close()
        return {
            'tables': tables,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'row_counts': row_counts,
            'oldest_records': oldest,
        }

    # ──────────────────────────────────────────────────────────
    # Phase 79: AI Security Copilot
    # ──────────────────────────────────────────────────────────

    _copilot_ensured = False

    def _ensure_copilot_tables(self):
        if Database._copilot_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS copilot_conversations (
                id SERIAL PRIMARY KEY,
                user_id INT,
                tenant_id INT,
                title TEXT,
                messages JSONB DEFAULT '[]'::jsonb,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        self.conn.commit()
        cursor.close()
        Database._copilot_ensured = True

    def create_copilot_conversation(self, user_id, tenant_id, title, messages=None):
        self._ensure_copilot_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO copilot_conversations (user_id, tenant_id, title, messages)
            VALUES (%s, %s, %s, %s) RETURNING id, title, messages, created_at, updated_at
        """, (user_id, tenant_id, title, json.dumps(messages or [])))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        return row

    def get_copilot_conversation(self, conv_id, user_id):
        self._ensure_copilot_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, user_id, tenant_id, title, messages, created_at, updated_at
            FROM copilot_conversations WHERE id = %s AND user_id = %s
        """, (conv_id, user_id))
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def update_copilot_conversation(self, conv_id, user_id, messages, title=None):
        self._ensure_copilot_tables()
        cursor = self.conn.cursor()
        if title:
            cursor.execute("""
                UPDATE copilot_conversations SET messages = %s, title = %s, updated_at = NOW()
                WHERE id = %s AND user_id = %s
            """, (json.dumps(messages), title, conv_id, user_id))
        else:
            cursor.execute("""
                UPDATE copilot_conversations SET messages = %s, updated_at = NOW()
                WHERE id = %s AND user_id = %s
            """, (json.dumps(messages), conv_id, user_id))
        self.conn.commit()
        cursor.close()

    def list_copilot_conversations(self, user_id, limit=20, offset=0):
        self._ensure_copilot_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, title, created_at, updated_at,
                   jsonb_array_length(messages) as message_count
            FROM copilot_conversations
            WHERE user_id = %s
            ORDER BY updated_at DESC
            LIMIT %s OFFSET %s
        """, (user_id, limit, offset))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    # ================================================================
    # Cloud Subscriptions (per-account monitoring)
    # ================================================================

    def _ensure_cloud_subscriptions_table(self):
        """Create cloud_subscriptions table if it doesn't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_subscriptions (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                cloud VARCHAR(20) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                account_name VARCHAR(500),
                status VARCHAR(20) DEFAULT 'discovered',
                monitored BOOLEAN DEFAULT false,
                activated_at TIMESTAMPTZ,
                activated_by INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(tenant_id, cloud, account_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_subs_tenant ON cloud_subscriptions(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_subs_cloud ON cloud_subscriptions(cloud)")
        self.conn.commit()
        cursor.close()

    def get_cloud_subscriptions(self, tenant_id, cloud=None):
        """List cloud subscriptions for a tenant."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = "SELECT * FROM cloud_subscriptions WHERE tenant_id = %s"
        params = [tenant_id]
        if cloud:
            query += " AND cloud = %s"
            params.append(cloud)
        query += " ORDER BY cloud, account_name"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('activated_at', 'created_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_subscription_stats(self, tenant_id):
        """Summary counts for cloud subscriptions."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE monitored = true) as active,
                COUNT(*) FILTER (WHERE monitored = false) as discovered,
                COUNT(DISTINCT cloud) as clouds
            FROM cloud_subscriptions
            WHERE tenant_id = %s
        """, (tenant_id,))
        row = dict(cursor.fetchone())
        cursor.close()
        return row

    def activate_cloud_subscription(self, sub_id, user_id):
        """Activate a subscription for monitoring."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE cloud_subscriptions
            SET monitored = true, status = 'active', activated_at = NOW(), activated_by = %s
            WHERE id = %s
            RETURNING *
        """, (user_id, sub_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('activated_at', 'created_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def deactivate_cloud_subscription(self, sub_id):
        """Stop monitoring a subscription."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE cloud_subscriptions
            SET monitored = false, status = 'inactive'
            WHERE id = %s
            RETURNING *
        """, (sub_id,))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('activated_at', 'created_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    # ================================================================
    # Identity ↔ Subscription Access (multi-subscription model)
    # ================================================================

    _isa_ensured = False

    def _ensure_identity_subscription_access_table(self):
        """Create identity_subscription_access junction table if it doesn't exist."""
        if Database._isa_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity_subscription_access (
                id BIGSERIAL PRIMARY KEY,
                identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                identity_id TEXT NOT NULL,
                subscription_id TEXT NOT NULL,
                subscription_name TEXT,
                rbac_role TEXT NOT NULL,
                scope TEXT,
                scope_type TEXT,
                risk_level TEXT,
                last_activity TIMESTAMPTZ,
                discovered_at TIMESTAMPTZ DEFAULT NOW(),
                discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
                UNIQUE(identity_db_id, subscription_id, rbac_role, scope)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_isa_identity ON identity_subscription_access(identity_db_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_isa_sub ON identity_subscription_access(subscription_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_isa_identity_id ON identity_subscription_access(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_isa_run ON identity_subscription_access(discovery_run_id)")
        # Add primary_subscription_id and additional_subscription_count to identities if missing
        for col, coltype in [
            ('primary_subscription_id', 'TEXT'),
            ('additional_subscription_count', 'INTEGER DEFAULT 0'),
        ]:
            try:
                cursor.execute(f"ALTER TABLE identities ADD COLUMN IF NOT EXISTS {col} {coltype}")
            except Exception:
                pass
        self.conn.commit()
        cursor.close()
        Database._isa_ensured = True

    def save_identity_subscription_access(self, identity_db_id, identity_id, role_assignment, subscription_id, subscription_name, run_id):
        """Insert one identity ↔ subscription RBAC access row (upsert on conflict)."""
        self._ensure_identity_subscription_access_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO identity_subscription_access
                (identity_db_id, identity_id, subscription_id, subscription_name,
                 rbac_role, scope, scope_type, risk_level, discovery_run_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (identity_db_id, subscription_id, rbac_role, scope) DO UPDATE
            SET risk_level = EXCLUDED.risk_level,
                subscription_name = EXCLUDED.subscription_name,
                discovery_run_id = EXCLUDED.discovery_run_id,
                discovered_at = NOW()
        """, (
            identity_db_id, identity_id, subscription_id, subscription_name,
            role_assignment.get('role_name', 'Unknown'),
            role_assignment.get('scope', ''),
            role_assignment.get('scope_type', 'subscription'),
            role_assignment.get('risk_level', 'info'),
            run_id,
        ))
        self.conn.commit()
        cursor.close()

    def update_identity_subscription_summary(self, identity_db_id):
        """Compute primary_subscription_id and additional_subscription_count from junction table."""
        self._ensure_identity_subscription_access_table()
        cursor = self.conn.cursor()
        # Get distinct subscriptions with their highest-privilege role
        cursor.execute("""
            SELECT subscription_id, subscription_name,
                   MAX(CASE
                       WHEN LOWER(rbac_role) LIKE '%%owner%%' THEN 4
                       WHEN LOWER(rbac_role) LIKE '%%contributor%%' THEN 3
                       WHEN LOWER(rbac_role) LIKE '%%admin%%' THEN 3
                       WHEN LOWER(rbac_role) LIKE '%%writer%%' THEN 2
                       WHEN LOWER(rbac_role) LIKE '%%reader%%' THEN 1
                       ELSE 0
                   END) as role_priority
            FROM identity_subscription_access
            WHERE identity_db_id = %s
            GROUP BY subscription_id, subscription_name
            ORDER BY role_priority DESC, subscription_name ASC
        """, (identity_db_id,))
        rows = cursor.fetchall()
        if rows:
            primary_sub_id = rows[0][0]
            additional_count = max(0, len(rows) - 1)
            cursor.execute("""
                UPDATE identities
                SET primary_subscription_id = %s, additional_subscription_count = %s
                WHERE id = %s
            """, (primary_sub_id, additional_count, identity_db_id))
            self.conn.commit()
        cursor.close()

    def get_identity_subscription_access(self, identity_db_id):
        """Get all subscription access records for an identity."""
        self._ensure_identity_subscription_access_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT subscription_id, subscription_name, rbac_role, scope,
                   scope_type, risk_level, last_activity, discovered_at
            FROM identity_subscription_access
            WHERE identity_db_id = %s
            ORDER BY subscription_name, rbac_role
        """, (identity_db_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('last_activity', 'discovered_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_identities_by_subscription(self, subscription_id):
        """Get all identity IDs that have access to a given subscription."""
        self._ensure_identity_subscription_access_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT DISTINCT identity_id
            FROM identity_subscription_access
            WHERE subscription_id = %s
        """, (subscription_id,))
        ids = [row[0] for row in cursor.fetchall()]
        cursor.close()
        return ids


# ─── Access Review V2 Helper Functions ────────────────────────────────

_PRIVILEGED_ROLES = {
    'Global Administrator': 35, 'Owner': 30, 'User Access Administrator': 25,
    'Privileged Role Administrator': 30, 'Privileged Authentication Administrator': 25,
    'Application Administrator': 20, 'Cloud Application Administrator': 20,
    'Key Vault Secrets Officer': 25, 'Contributor': 15,
    'Hybrid Identity Administrator': 20,
}

_DANGEROUS_GRAPH_PERMS = {
    'Directory.ReadWrite.All', 'Application.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory', 'Mail.ReadWrite',
    'AppRoleAssignment.ReadWrite.All', 'GroupMember.ReadWrite.All',
}


def _pick_top_role(roles):
    """Pick the highest-privilege role from a list."""
    if not roles:
        return None
    best = roles[0]
    best_score = _PRIVILEGED_ROLES.get(best['role_name'], 5)
    for r in roles[1:]:
        s = _PRIVILEGED_ROLES.get(r['role_name'], 5)
        if s > best_score:
            best = r
            best_score = s
    return best


def _format_scope(scope):
    """Format ARM scope into readable string."""
    if not scope:
        return None
    parts = scope.strip('/').split('/')
    if len(parts) >= 2 and parts[0].lower() == 'subscriptions':
        sub = parts[1][:12]
        if len(parts) >= 4 and parts[2].lower() == 'resourcegroups':
            return f"RG: {parts[3]}"
        return f"Sub: {sub}"
    if scope == '/' or scope == '':
        return 'Tenant Root'
    return scope[:60]


def _compute_review_risk(role_name, scope_type, last_used_days, cred, graph_perms, is_pim, mfa_enforced):
    """Composite risk scoring 0-100."""
    score = 0
    factors = []

    # 1. Role privilege
    rp = _PRIVILEGED_ROLES.get(role_name, 5) if role_name else 5
    score += rp
    factors.append({'factor': f'Role: {role_name or "None"}', 'points': rp})

    # 2. Scope level
    scope_points = {'tenant': 20, 'subscription': 15, 'resource_group': 8, 'resource': 5}
    sp = scope_points.get(scope_type, 5) if scope_type else 5
    score += sp
    factors.append({'factor': f'Scope: {scope_type or "unknown"}', 'points': sp})

    # 3. Usage dormancy
    if last_used_days is None or last_used_days > 180:
        dp = 25
        label = f'Dormant ({last_used_days or "Never"}d)'
    elif last_used_days > 90:
        dp = 15
        label = f'Inactive ({last_used_days}d)'
    elif last_used_days > 30:
        dp = 5
        label = f'Low activity ({last_used_days}d)'
    else:
        dp = -5
        label = 'Active usage (mitigating)'
    score += dp
    factors.append({'factor': label, 'points': dp})

    # 4. Credential risk
    if cred and cred.get('end_datetime'):
        from datetime import datetime, timezone
        try:
            exp = cred['end_datetime']
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
            if days_left <= 0:
                score += 20
                factors.append({'factor': 'Secret/cert EXPIRED', 'points': 20})
            elif days_left <= 7:
                score += 15
                factors.append({'factor': f'Secret expiring in {days_left}d', 'points': 15})
            elif days_left <= 30:
                score += 8
                factors.append({'factor': f'Secret expiring in {days_left}d', 'points': 8})
        except Exception:
            pass

    # 5. Dangerous Graph API perms
    if graph_perms:
        gp = sum(7 for p in graph_perms if p in _DANGEROUS_GRAPH_PERMS)
        gp = min(gp, 15)
        if gp > 0:
            score += gp
            factors.append({'factor': 'Dangerous Graph API permissions', 'points': gp})

    # 6. Mitigations
    if is_pim:
        score -= 5
        factors.append({'factor': 'PIM eligible (mitigating)', 'points': -5})
    if mfa_enforced:
        score -= 7
        factors.append({'factor': 'MFA enforced (mitigating)', 'points': -7})

    return min(max(score, 0), 100), factors


def _compute_privilege_level(role_name, is_pim):
    """Compute privilege level badge."""
    if not role_name:
        return 'Standard'
    score = _PRIVILEGED_ROLES.get(role_name, 0)
    if is_pim:
        return 'PIM Eligible'
    if score >= 25:
        return 'Privileged'
    if score >= 15:
        return 'Elevated'
    return 'Standard'


def _compute_credential_risk(cred):
    """Compute credential risk string and level."""
    if not cred or not cred.get('end_datetime'):
        return None, 'na'
    from datetime import datetime, timezone
    try:
        exp = cred['end_datetime']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        days_left = (exp - datetime.now(timezone.utc)).days
        if days_left <= 0:
            return 'Secret EXPIRED', 'critical'
        if days_left <= 7:
            return f'Secret expiring {days_left}d', 'critical'
        if days_left <= 30:
            return f'Secret expiring {days_left}d', 'warning'
        if days_left <= 90:
            return f'Expires in {days_left}d', 'ok'
        return f'Valid ({days_left}d)', 'ok'
    except Exception:
        return None, 'na'


def _generate_ai_recommendation(risk_score, risk_factors, identity_type, last_used_days, credential_risk):
    """Rule-based AI recommendations."""
    if last_used_days is not None and last_used_days > 90 and risk_score >= 40:
        return 'Revoke', f'Unused {last_used_days}d with risk score {risk_score}. Recommend removal.'

    has_priv_role = any('Owner' in f['factor'] or 'Global Admin' in f['factor'] or 'Privileged' in f['factor']
                        for f in risk_factors if f['points'] >= 25)
    if has_priv_role:
        if last_used_days is not None and last_used_days <= 30:
            return 'Convert to PIM', 'Active privileged identity — convert to PIM for JIT activation.'
        return 'Downgrade', f'Privileged role unused {last_used_days or "unknown"}d. Consider lower privilege.'

    if credential_risk and ('expir' in credential_risk.lower() or 'expired' in credential_risk.lower()):
        return 'Rotate Secret', f'Credential risk: {credential_risk}'

    if risk_score <= 30:
        return 'Approve', 'Low risk, appropriately scoped.'

    return 'Downgrade', 'Consider reducing privilege level.'
