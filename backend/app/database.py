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

    def get_settings(self) -> Dict[str, str]:
        """Returns all settings as a key-value dict."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM settings ORDER BY key")
        result = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.close()
        return result

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Returns a single setting value, or default if not found."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = %s", (key,))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else default

    def save_settings(self, settings_dict: Dict[str, str]) -> None:
        """Upsert multiple settings in one call."""
        cursor = self.conn.cursor()
        for key, value in settings_dict.items():
            cursor.execute("""
                INSERT INTO settings (key, value, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = NOW()
            """, (key, value))
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
        self.conn.commit()
        cursor.close()

    def log_activity(self, action_type: str, description: str, metadata: dict = None):
        """Append an entry to the activity log. Never raises — errors are logged only."""
        try:
            self._ensure_activity_log_table()
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO activity_log (action_type, description, metadata, created_at)
                VALUES (%s, %s, %s, NOW())
            """, (
                action_type,
                description,
                json.dumps(metadata) if metadata else None,
            ))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            print(f"Warning: Failed to log activity: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass

    def get_activity_log(self, limit: int = 50, offset: int = 0, action_type: str = None) -> list:
        """Get activity log entries, most recent first."""
        self._ensure_activity_log_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        query = "SELECT id, action_type, description, metadata, created_at FROM activity_log"
        params: list = []

        if action_type:
            query += " WHERE action_type = %s"
            params.append(action_type)

        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
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
            SELECT playbook_id, status, notes, updated_at
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
