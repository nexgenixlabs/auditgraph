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
    """PostgreSQL database handler.

    Connection strategy (Phase 87 — RLS enforcement):
      - organization_id=N   → connects as DB_USER (auditgraph_app, NOBYPASSRLS),
                         sets RLS context to org N. Only sees org N data.
      - organization_id=None → connects as DB_ADMIN_USER (auditgraph_admin, BYPASSRLS).
                         Sees all data. Used for superadmin/system/startup ops.
    """

    def __init__(self, organization_id=None):
        """Initialize database connection.

        Args:
            organization_id: If provided, connects as RLS-enforcing user and sets
                       organization context. None = superadmin/startup (bypasses RLS).
        """
        self.conn = None
        self._organization_id = organization_id
        self.connect()
        if organization_id is not None:
            self.set_organization_context(organization_id)

    def connect(self):
        """Connect to PostgreSQL database.

        Uses DB_USER (auditgraph_app, NOBYPASSRLS) for organization-scoped connections,
        and DB_ADMIN_USER (auditgraph_admin, BYPASSRLS) for system/superadmin ops.
        """
        try:
            if self._organization_id is not None:
                # Organization-scoped: use RLS-enforcing user
                db_user = os.getenv("DB_USER", "auditgraph_app")
                db_password = os.getenv("DB_PASSWORD")
            else:
                # System/superadmin: use BYPASSRLS admin user
                db_user = os.getenv("DB_ADMIN_USER", os.getenv("DB_USER", "auditgraph_admin"))
                db_password = os.getenv("DB_ADMIN_PASSWORD", os.getenv("DB_PASSWORD"))

            self.conn = psycopg2.connect(
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                database=os.getenv("DB_NAME"),
                user=db_user,
                password=db_password,
                sslmode=os.getenv("DB_SSLMODE", "require"),
            )
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            raise

    def set_organization_context(self, organization_id):
        """Set PostgreSQL session variable for RLS organization isolation.

        Uses set_config with is_local=FALSE so the setting persists for
        the entire connection lifetime (not just the current transaction).
        Since each request creates a new Database(), this is safe.
        """
        if organization_id is not None and self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT set_config('app.current_organization_id', %s, FALSE)",
                (str(organization_id),)
            )
            cursor.close()

    def create_discovery_run(self, subscription_id: str, subscription_name: str,
                             organization_id=None, cloud_connection_id=None) -> int:
        """
        Create a new discovery run record

        Returns:
            discovery_run_id
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO discovery_runs (
                subscription_id, subscription_name, started_at, status, organization_id, cloud_connection_id
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """,
            (subscription_id, subscription_name, datetime.utcnow(), "running", organization_id, cloud_connection_id),
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
    _permission_plane_col_ensured = False
    _deleted_at_col_ensured = False
    _ms_flag_backfilled = False
    _spn_exposure_ensured = False
    _app_reg_exposure_ensured = False
    _ice_columns_ensured = False

    def backfill_microsoft_flag(self):
        """Startup backfill of is_microsoft_system for ALL data.

        Ensures every identity has the correct flag. Runs on every startup
        because discovery runs may have stored SPNs with incorrect flags
        (e.g., due to UUID comparison bug in _is_microsoft_system_app).

        Strategy:
        1. SPNs with recognized customer prefixes → false
        2. SPNs with non-Microsoft app_owner_org_id → false
        3. All remaining service_principal SPNs → true
        4. Non-SPN categories → false
        """
        if Database._ms_flag_backfilled:
            return
        cursor = self.conn.cursor()
        try:
            # Add column for Graph API appOwnerOrganizationId
            cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS app_owner_org_id TEXT")
            self.conn.commit()

            customer_prefixes = [
                'spn-', 'app-', 'svc-', 'sa-', 'func-', 'aks-', 'webapp-', 'mi-',
                'aglab', 'auditgraph', 'nexgenix', 'ngh-', 'aglabs',
            ]
            prefix_conditions = " OR ".join([
                f"LOWER(display_name) LIKE '{p}%%'" for p in customer_prefixes
            ])

            # Pass 1: Mark customer-prefix SPNs as NOT Microsoft
            cursor.execute(f"""
                UPDATE identities SET is_microsoft_system = false
                WHERE identity_category = 'service_principal'
                  AND COALESCE(is_microsoft_system, true) = true
                  AND ({prefix_conditions})
            """)
            customer_count = cursor.rowcount

            # Pass 2: SPNs with non-Microsoft app_owner_org_id → NOT Microsoft
            cursor.execute("""
                UPDATE identities SET is_microsoft_system = false
                WHERE identity_category = 'service_principal'
                  AND COALESCE(is_microsoft_system, true) = true
                  AND app_owner_org_id IS NOT NULL
                  AND app_owner_org_id != 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
            """)
            org_count = cursor.rowcount

            # Pass 3: All remaining SPNs without customer prefix AND without
            # non-Microsoft org → Microsoft (catches undetected MS SPNs)
            cursor.execute(f"""
                UPDATE identities SET is_microsoft_system = true
                WHERE identity_category = 'service_principal'
                  AND COALESCE(is_microsoft_system, false) = false
                  AND NOT ({prefix_conditions})
                  AND (app_owner_org_id IS NULL OR app_owner_org_id = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a')
            """)
            ms_count = cursor.rowcount

            # Pass 4: Non-SPN categories → NOT Microsoft
            cursor.execute("""
                UPDATE identities SET is_microsoft_system = false
                WHERE identity_category NOT IN ('service_principal')
                  AND (is_microsoft_system IS NULL OR is_microsoft_system = true)
            """)
            other_count = cursor.rowcount

            self.conn.commit()
            total = customer_count + org_count + ms_count + other_count
            if total > 0:
                print(f"  📋 Backfilled is_microsoft_system: {customer_count} customer-prefix, {org_count} customer-org, {ms_count} → Microsoft, {other_count} non-SPNs")
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ Microsoft flag backfill error: {e}")
        finally:
            cursor.close()
        Database._ms_flag_backfilled = True

    def ensure_deleted_at_column(self):
        """Startup migration: add deleted_at column for identity soft-delete + drift events."""
        if Database._deleted_at_col_ensured:
            return
        cursor = self.conn.cursor()
        try:
            cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_identities_deleted_at ON identities(deleted_at) WHERE deleted_at IS NOT NULL")
            self.conn.commit()
            Database._deleted_at_col_ensured = True
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ deleted_at migration error: {e}")
        finally:
            cursor.close()
        # Also ensure drift_reports.events column
        if not Database._drift_events_col_ensured:
            cursor = self.conn.cursor()
            try:
                cursor.execute("ALTER TABLE drift_reports ADD COLUMN IF NOT EXISTS events JSONB DEFAULT '[]'::jsonb")
                self.conn.commit()
                Database._drift_events_col_ensured = True
            except Exception as e:
                self.conn.rollback()
                print(f"  ⚠️ drift events column migration error: {e}")
            finally:
                cursor.close()

    def ensure_permission_plane_column(self):
        """Startup migration: add permission_plane column and backfill existing data."""
        if Database._permission_plane_col_ensured:
            return
        cursor = self.conn.cursor()
        try:
            cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS permission_plane VARCHAR(50)")
            self.conn.commit()
            # Backfill existing data
            cursor.execute("""
                UPDATE identities SET permission_plane = 'entra_id'
                WHERE permission_plane IS NULL AND COALESCE(source_normalized, 'entra') = 'entra'
            """)
            cursor.execute("""
                UPDATE identities SET permission_plane = 'rbac'
                WHERE permission_plane IS NULL AND source_normalized = 'azure'
            """)
            cursor.execute("""
                UPDATE identities SET permission_plane = 'entra_id'
                WHERE permission_plane IS NULL
            """)
            self.conn.commit()
            backfilled = cursor.rowcount
            if backfilled > 0:
                print(f"  📋 Backfilled permission_plane for existing identities")
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ permission_plane migration error: {e}")
        finally:
            cursor.close()
        Database._permission_plane_col_ensured = True

    def sweep_microsoft_flag(self, run_id: int):
        """Post-discovery sweep: mark remaining undetected Microsoft SPNs for a specific run.

        Called after discovery saves all identities. Catches SPNs that slipped through
        _is_microsoft_system_app() by using the same customer-prefix whitelist approach.
        """
        cursor = self.conn.cursor()
        try:
            # Customer-owned SPNs have recognizable naming prefixes
            customer_prefixes = [
                'spn-', 'app-', 'svc-', 'sa-', 'func-', 'aks-', 'webapp-', 'mi-',
                'aglab', 'auditgraph', 'nexgenix', 'ngh-', 'aglabs',
            ]
            prefix_conditions = " OR ".join([
                f"LOWER(display_name) LIKE '{p}%%'" for p in customer_prefixes
            ])

            # Mark any service_principal with is_microsoft_system=false
            # that does NOT match customer prefixes AND does NOT have a
            # non-Microsoft app_owner_org_id → likely a missed Microsoft SPN
            cursor.execute(f"""
                UPDATE identities SET is_microsoft_system = true
                WHERE discovery_run_id = %s
                  AND identity_category = 'service_principal'
                  AND is_microsoft_system = false
                  AND NOT ({prefix_conditions})
                  AND (app_owner_org_id IS NULL OR app_owner_org_id = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a')
            """, (run_id,))
            swept = cursor.rowcount
            self.conn.commit()
            if swept > 0:
                print(f"  🧹 Post-discovery sweep: marked {swept} additional Microsoft SPNs")
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ Microsoft flag sweep error: {e}")
        finally:
            cursor.close()

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

        # Ensure permission_plane column exists (main migration runs at startup via ensure_permission_plane_column)
        if not Database._permission_plane_col_ensured:
            try:
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS permission_plane VARCHAR(50)")
                self.conn.commit()
            except Exception:
                self.conn.rollback()
            Database._permission_plane_col_ensured = True

        # Ensure deleted_at column exists for soft-delete
        if not Database._deleted_at_col_ensured:
            try:
                cursor.execute("SAVEPOINT deleted_at_ddl")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_identities_deleted_at ON identities(deleted_at) WHERE deleted_at IS NOT NULL")
                cursor.execute("RELEASE SAVEPOINT deleted_at_ddl")
                self.conn.commit()
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT deleted_at_ddl")
                except Exception:
                    self.conn.rollback()
            Database._deleted_at_col_ensured = True

        # Ensure ICE (Identity Correlation Engine) columns exist
        if not Database._ice_columns_ensured:
            try:
                cursor.execute("SAVEPOINT ice_ddl")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS upn VARCHAR(500)")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS employee_id_entra VARCHAR(255)")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS department VARCHAR(255)")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS manager_id VARCHAR(255)")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS manager_upn VARCHAR(500)")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS job_title VARCHAR(255)")
                cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS account_category VARCHAR(50)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_identities_upn ON identities(upn)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_identities_employee_id ON identities(employee_id_entra)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_identities_account_category ON identities(account_category)")
                cursor.execute("RELEASE SAVEPOINT ice_ddl")
                self.conn.commit()
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT ice_ddl")
                except Exception:
                    self.conn.rollback()
            Database._ice_columns_ensured = True

        # Normalize JSON fields
        tags_json = json.dumps(identity_data.get("tags", {}) or {})

        # Calculate normalized fields for multi-cloud support
        identity_type_normalized = self._get_normalized_type(identity_data)
        is_federated = identity_data.get("is_federated", False) or identity_data.get("identity_category") == "guest"

        # Use canonical status resolver
        from app.engines.status_resolver import resolve_status
        status = resolve_status(identity_data)

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
                last_seen_auth,

                app_owner_org_id,

                permission_plane,

                organization_id,

                -- ICE columns
                upn,
                employee_id_entra,
                department,
                manager_id,
                manager_upn,
                job_title,
                account_category
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
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s,
                %s,
                %s,
                %s, %s, %s, %s, %s, %s, %s
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

                app_owner_org_id = EXCLUDED.app_owner_org_id,

                permission_plane = EXCLUDED.permission_plane,

                deleted_at = NULL,

                -- ICE columns
                upn = EXCLUDED.upn,
                employee_id_entra = EXCLUDED.employee_id_entra,
                department = EXCLUDED.department,
                manager_id = EXCLUDED.manager_id,
                manager_upn = EXCLUDED.manager_upn,
                job_title = EXCLUDED.job_title,
                account_category = EXCLUDED.account_category,

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
                identity_data.get("tenant_id"),  # tenant_or_org_id (Azure directory)
                identity_data.get("source", "entra"),  # source_normalized
                is_federated,
                status,
                identity_data.get("last_sign_in"),  # last_seen_auth = last_sign_in

                identity_data.get("app_owner_org_id"),  # appOwnerOrganizationId from Graph API

                identity_data.get("permission_plane", "entra_id"),

                self._organization_id,

                # ICE columns
                identity_data.get("upn"),
                identity_data.get("employee_id_entra"),
                identity_data.get("department"),
                identity_data.get("manager_id"),
                identity_data.get("manager_upn"),
                identity_data.get("job_title"),
                identity_data.get("account_category"),
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
                resource_type, resource_name,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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
                redundant_with, role_type, risk_level, why_critical,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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
                (identity_db_id, permission_name, permission_description, risk_level, organization_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (identity_db_id, permission_name) DO UPDATE
                SET permission_description = EXCLUDED.permission_description,
                    risk_level = EXCLUDED.risk_level,
                    discovered_at = CURRENT_TIMESTAMP
            """,
                (identity_db_id, perm_name, perm_desc, risk, self._organization_id),
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
                        risk_level,
                        organization_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
                        self._organization_id,
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
                    is_primary_owner,
                    organization_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
                    self._organization_id,
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
                assignment_type, start_datetime, end_datetime, member_type,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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
                is_approval_required, created_datetime,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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
                allows_legacy_auth, modified_datetime,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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
                applicable_policy_count, excluded_from_count, risk_flags,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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

    def get_report_data(self, run_ids=None) -> Dict:
        """
        Get comprehensive data for PDF report generation.
        Returns stats, posture, compliance, top risks, and remediation summary.
        If run_ids provided, scope report to those runs (multi-connection support).
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        if run_ids:
            # Multi-connection: aggregate stats across provided run IDs
            cursor.execute("""
                SELECT MAX(id) AS id, MAX(completed_at) AS completed_at,
                       SUM(total_identities) AS total_identities,
                       SUM(critical_count) AS critical_count,
                       SUM(high_count) AS high_count,
                       SUM(medium_count) AS medium_count,
                       SUM(low_count) AS low_count
                FROM discovery_runs WHERE id = ANY(%s)
            """, (run_ids,))
        else:
            cursor.execute("""
                SELECT id, completed_at, total_identities, critical_count, high_count, medium_count, low_count
                FROM discovery_runs WHERE status = 'completed'
                ORDER BY id DESC LIMIT 1
            """)
        run = cursor.fetchone()
        if not run or not run.get('id'):
            cursor.close()
            return None

        use_run_ids = run_ids if run_ids else [run["id"]]

        # Previous run for trend (use oldest run's predecessor)
        oldest_run_id = min(use_run_ids) if use_run_ids else run["id"]
        cursor.execute("""
            SELECT id, total_identities, critical_count, high_count, medium_count
            FROM discovery_runs WHERE status = 'completed' AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (oldest_run_id,))
        prev_run = cursor.fetchone()

        # Top 20 critical/high identities
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, i.risk_reasons,
                   i.activity_status, i.credential_status, i.owner_display_name,
                   COALESCE(i.owner_count, 0) as owner_count,
                   i.ca_coverage_status
            FROM identities i
            WHERE i.discovery_run_id = ANY(%s) AND i.risk_level IN ('critical', 'high')
            ORDER BY
                CASE i.risk_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                COALESCE(i.risk_score, 0) DESC
            LIMIT 20
        """, (use_run_ids,))
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
            FROM identities WHERE discovery_run_id = ANY(%s)
        """, (use_run_ids,))
        cred_row = cursor.fetchone() or {}

        # CA coverage
        cursor.execute("""
            SELECT
                COUNT(*) FILTER (WHERE ca_coverage_status = 'covered') as covered,
                COUNT(*) FILTER (WHERE ca_coverage_status = 'no_coverage' OR ca_coverage_status IS NULL) as not_covered,
                COUNT(*) as total
            FROM identities WHERE discovery_run_id = ANY(%s)
        """, (use_run_ids,))
        ca_row = cursor.fetchone() or {}

        # Ghost identities (disabled/deleted retaining active role assignments)
        ghost_count = 0
        try:
            cursor.execute("""
                SELECT COUNT(DISTINCT i.id) AS ghost_count
                FROM identities i
                WHERE i.discovery_run_id = ANY(%s)
                  AND (i.deleted_at IS NOT NULL OR i.enabled = false
                       OR COALESCE(i.status, 'active') IN ('disabled', 'deleted'))
                  AND (EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                       OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id))
            """, (use_run_ids,))
            ghost_count = cursor.fetchone()['ghost_count'] or 0
        except Exception:
            pass

        cursor.close()

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "run_id": use_run_ids[0] if len(use_run_ids) == 1 else use_run_ids,
            "collected_at": run["completed_at"].isoformat() if run.get("completed_at") else None,
            "stats": {
                "total_identities": run.get("total_identities", 0),
                "critical": run.get("critical_count", 0),
                "high": run.get("high_count", 0),
                "medium": run.get("medium_count", 0),
                "low": run.get("low_count", 0),
                "ghost_count": ghost_count,
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

    _drift_events_col_ensured = False

    def save_drift_report(self, current_run_id: int, previous_run_id: int,
                          changes: Dict, events: list = None) -> int:
        """Persist a drift comparison result. Returns drift_report ID."""
        cursor = self.conn.cursor()

        # Ensure events JSONB column exists
        if not Database._drift_events_col_ensured:
            try:
                cursor.execute("SAVEPOINT drift_events_ddl")
                cursor.execute("ALTER TABLE drift_reports ADD COLUMN IF NOT EXISTS events JSONB DEFAULT '[]'::jsonb")
                cursor.execute("RELEASE SAVEPOINT drift_events_ddl")
                self.conn.commit()
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT drift_events_ddl")
                except Exception:
                    self.conn.rollback()
            Database._drift_events_col_ensured = True

        new_count = len(changes.get('new_identities', []))
        removed_count = len(changes.get('removed_identities', []))
        perm_count = len(changes.get('permission_changes', []))
        risk_count = len(changes.get('risk_changes', []))
        cred_count = len(changes.get('credential_changes', []))
        total = new_count + removed_count + perm_count + risk_count + cred_count

        events_json = json.dumps(events or [], default=str)

        cursor.execute("""
            INSERT INTO drift_reports (
                current_run_id, previous_run_id,
                new_identities_count, removed_identities_count,
                permission_changes_count, risk_changes_count,
                credential_changes_count, total_changes,
                changes, events, organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (current_run_id, previous_run_id) DO UPDATE SET
                new_identities_count = EXCLUDED.new_identities_count,
                removed_identities_count = EXCLUDED.removed_identities_count,
                permission_changes_count = EXCLUDED.permission_changes_count,
                risk_changes_count = EXCLUDED.risk_changes_count,
                credential_changes_count = EXCLUDED.credential_changes_count,
                total_changes = EXCLUDED.total_changes,
                changes = EXCLUDED.changes,
                events = EXCLUDED.events,
                created_at = NOW()
            RETURNING id
        """, (
            current_run_id, previous_run_id,
            new_count, removed_count, perm_count, risk_count, cred_count, total,
            json.dumps(changes, default=str), events_json, self._organization_id
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

    def get_settings(self, organization_id=None) -> Dict[str, str]:
        """Returns all settings as a key-value dict, scoped by organization.
        SECURITY: Returns empty dict when organization_id is None to prevent cross-organization data leak."""
        if organization_id is None:
            import logging
            logging.getLogger('org_isolation').warning(
                'get_settings() called with organization_id=None — returning empty dict')
            return {}
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM settings WHERE organization_id = %s ORDER BY key", (organization_id,))
        result = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.close()
        return result

    def get_setting(self, key: str, default: Optional[str] = None, organization_id=None) -> Optional[str]:
        """Returns a single setting value, or default if not found.
        SECURITY: Returns default when organization_id is None to prevent cross-organization data leak."""
        if organization_id is None:
            import logging
            logging.getLogger('org_isolation').warning(
                f'get_setting({key}) called with organization_id=None — returning default')
            return default
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = %s AND organization_id = %s", (key, organization_id))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else default

    def save_settings(self, settings_dict: Dict[str, str], organization_id=None) -> None:
        """Upsert multiple settings in one call, scoped by organization.
        SECURITY: Rejects writes when organization_id is None to prevent cross-organization data leak."""
        if organization_id is None:
            import logging
            logging.getLogger('org_isolation').warning(
                'save_settings() called with organization_id=None — rejecting write')
            return
        cursor = self.conn.cursor()
        for key, value in settings_dict.items():
            cursor.execute("""
                INSERT INTO settings (key, value, organization_id, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (organization_id, key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = NOW()
            """, (key, value, organization_id))
        self.conn.commit()
        cursor.close()

    # ── System-level setting accessors (for scheduler/background services ONLY) ──
    # These read from organization_id IS NULL rows (system-wide operational settings).
    # NEVER use these in request-scoped handlers — use get_setting(organization_id=...) instead.

    _SYSTEM_SETTING_ALLOWLIST = frozenset([
        'email_enabled', 'email_provider', 'email_to',
        'email_notify_scan_complete', 'email_notify_new_risks', 'email_notify_credential_expiry',
        'email_notify_drift', 'email_notify_compliance',
        'notify_new_identities', 'notify_removed_identities', 'notify_permission_changes',
        'notify_risk_changes', 'notify_credential_changes',
        'retention_enabled', 'retention_discovery_days', 'retention_drift_days',
        'retention_activity_days', 'retention_anomalies_days', 'retention_soar_days',
        'retention_notifications_days',
        'report_schedule_enabled', 'report_schedule_frequency', 'report_email_to',
        'scheduler_interval_hours', 'org_name',
        'slack_webhook_url', 'teams_webhook_url', 'slack_events', 'teams_events',
        'azure_organization_id', 'azure_client_id', 'azure_client_secret',
        'p2_telemetry_enabled',
        'resource_anomaly_score_spike_threshold', 'resource_anomaly_expiry_window_days',
        'resource_anomaly_expiry_threshold', 'resource_anomaly_privilege_creep_threshold',
    ])

    def get_system_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Read a system-level operational setting (organization_id IS NULL).
        Only allowed for keys in the allowlist."""
        if key not in self._SYSTEM_SETTING_ALLOWLIST:
            import logging
            logging.getLogger('org_isolation').warning(
                f'get_system_setting() blocked for non-allowlisted key: {key}')
            return default
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = %s AND organization_id IS NULL", (key,))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else default

    def get_system_settings(self) -> Dict[str, str]:
        """Read all system-level operational settings (organization_id IS NULL).
        Filters to allowlisted keys only."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM settings WHERE organization_id IS NULL ORDER BY key")
        result = {row[0]: row[1] for row in cursor.fetchall()
                  if row[0] in self._SYSTEM_SETTING_ALLOWLIST}
        cursor.close()
        return result

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
        # Phase 46: Add user_id and organization_id columns
        cursor.execute("ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS user_id INTEGER")
        cursor.execute("ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_organization_id ON activity_log(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id)")
        self.conn.commit()
        cursor.close()

    def log_activity(self, action_type: str, description: str, metadata: dict = None,
                     user_id: int = None, organization_id: int = None):
        """Append an entry to the activity log. Never raises — errors are logged only."""
        try:
            self._ensure_activity_log_table()
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO activity_log (action_type, description, metadata, user_id, organization_id, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (
                action_type,
                description,
                json.dumps(metadata) if metadata else None,
                user_id,
                organization_id,
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
                         action_type: str = None, organization_id: int = None) -> list:
        """Get activity log entries, most recent first. Optionally filtered by organization."""
        self._ensure_activity_log_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)

        query = """
            SELECT a.id, a.action_type, a.description, a.metadata, a.created_at,
                   a.user_id, a.organization_id,
                   u.username AS user_username, u.display_name AS user_display_name
            FROM activity_log a
            LEFT JOIN users u ON u.id = a.user_id
        """
        conditions: list = []
        params: list = []

        if action_type:
            conditions.append("a.action_type = %s")
            params.append(action_type)
        if organization_id is not None:
            conditions.append("a.organization_id = %s")
            params.append(organization_id)

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
                start_datetime, end_datetime, thumbprint, issuer, subject,
                organization_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                self._organization_id,
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
        cursor.execute("ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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
                AND i.discovery_run_id = (SELECT MAX(id) FROM discovery_runs WHERE status = 'completed')
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
        cursor.execute("SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'")
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

        cursor.execute("SELECT MAX(id) as max FROM discovery_runs WHERE status = 'completed'")
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
                'permission_plane': 'rbac' if f['source'] == 'azure' else 'entra_id',
                'type': f['finding_type'],
                'risk_level': f['risk_level'],
                'days_since_assigned': f['days_since_assigned'],
                'scope': f['scope'],
                'recommendation': self._role_mining_recommendation(f['finding_type'], f['role_name'], f.get('redundant_with')),
            })

        # Role frequency: top 10
        cursor.execute("""
            SELECT role_name, source, permission_plane, COUNT(*) as assignment_count FROM (
                SELECT r.role_name, 'azure' as source, 'rbac' as permission_plane
                FROM role_assignments r
                JOIN identities i ON r.identity_db_id = i.id WHERE i.discovery_run_id = %s
                UNION ALL
                SELECT e.role_name, 'entra' as source, 'entra_id' as permission_plane
                FROM entra_role_assignments e
                JOIN identities i ON e.identity_db_id = i.id WHERE i.discovery_run_id = %s
            ) combined GROUP BY role_name, source, permission_plane ORDER BY assignment_count DESC LIMIT 10
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
        cursor.execute("ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        cursor.execute("ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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
            WHERE w.organization_id = %s
            ORDER BY w.created_at DESC
        """, (self._organization_id,))
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
        cursor.execute("SELECT * FROM webhooks WHERE id = %s AND organization_id = %s", (webhook_id, self._organization_id))
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
            INSERT INTO webhooks (name, url, secret, event_types, headers, created_at, updated_at, organization_id)
            VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), %s)
            RETURNING *
        """, (name, url, secret or None, event_types, json.dumps(headers) if headers else None, self._organization_id))
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
        params.append(self._organization_id)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE webhooks SET {', '.join(set_parts)}
            WHERE id = %s AND organization_id = %s RETURNING *
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
        cursor.execute("DELETE FROM webhooks WHERE id = %s AND organization_id = %s", (webhook_id, self._organization_id))
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
            WHERE enabled = true AND %s = ANY(event_types) AND organization_id = %s
        """, (event_type, self._organization_id))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    def create_webhook_delivery(self, webhook_id: int, event_type: str, payload: dict) -> int:
        """Create a webhook delivery record."""
        self._ensure_webhook_tables()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status, created_at, organization_id)
            VALUES (%s, %s, %s, 'pending', NOW(), %s)
            RETURNING id
        """, (webhook_id, event_type, json.dumps(payload), self._organization_id))
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
            SELECT d.id, d.event_type, d.status, d.http_status, d.attempts, d.created_at, d.delivered_at
            FROM webhook_deliveries d
            JOIN webhooks w ON w.id = d.webhook_id
            WHERE d.webhook_id = %s AND w.organization_id = %s
            ORDER BY d.created_at DESC
            LIMIT %s
        """, (webhook_id, self._organization_id, limit))
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
        cursor.execute("ALTER TABLE custom_risk_rules ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        self.conn.commit()
        cursor.close()

    def get_custom_risk_rules(self) -> list:
        """Get all custom risk rules ordered by priority."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM custom_risk_rules WHERE organization_id = %s ORDER BY priority, id", (self._organization_id,))
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
        cursor.execute("SELECT * FROM custom_risk_rules WHERE id = %s AND organization_id = %s", (rule_id, self._organization_id))
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
                (name, description, conditions, action_type, points_adjustment, force_level, reason_text, priority, created_at, updated_at, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)
            RETURNING *
        """, (name, description, json.dumps(conditions), action_type,
              points_adjustment or 0, force_level, reason_text, priority or 100, self._organization_id))
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
        params.append(self._organization_id)

        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE custom_risk_rules SET {', '.join(set_parts)}
            WHERE id = %s AND organization_id = %s RETURNING *
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
        cursor.execute("DELETE FROM custom_risk_rules WHERE id = %s AND organization_id = %s", (rule_id, self._organization_id))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def get_enabled_risk_rules(self) -> list:
        """Get only enabled custom risk rules, ordered by priority."""
        self._ensure_custom_risk_rules_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM custom_risk_rules WHERE enabled = true AND organization_id = %s ORDER BY priority, id", (self._organization_id,))
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
        cursor.execute("ALTER TABLE notifications ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications(organization_id)")
        self.conn.commit()
        cursor.close()

    def get_notifications(self, limit=50, offset=0, read=None, severity=None, category=None, organization_id=None) -> list:
        """Get notifications with optional filters."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        conditions = []
        params = []
        if organization_id is not None:
            conditions.append("organization_id = %s")
            params.append(organization_id)
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
        cursor.execute("SELECT * FROM notifications WHERE id = %s AND organization_id = %s", (notification_id, self._organization_id))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts_field in ('created_at', 'read_at', 'action_at'):
            if result.get(ts_field):
                result[ts_field] = result[ts_field].isoformat()
        return result

    def get_notification_stats(self, organization_id=None) -> dict:
        """Get notification statistics (unread count, by severity, by category)."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        org_filter = ""
        org_params: list = []
        if organization_id is not None:
            org_filter = " AND organization_id = %s"
            org_params = [organization_id]
        cursor.execute(f"SELECT COUNT(*) as total FROM notifications WHERE true{org_filter}", org_params)
        total = cursor.fetchone()['total']
        cursor.execute(f"SELECT COUNT(*) as unread FROM notifications WHERE read = false{org_filter}", org_params)
        unread = cursor.fetchone()['unread']
        cursor.execute(f"SELECT severity, COUNT(*) as cnt FROM notifications WHERE read = false{org_filter} GROUP BY severity", org_params)
        by_severity = {r['severity']: r['cnt'] for r in cursor.fetchall()}
        cursor.execute(f"SELECT category, COUNT(*) as cnt FROM notifications WHERE read = false{org_filter} GROUP BY category", org_params)
        by_category = {r['category']: r['cnt'] for r in cursor.fetchall()}
        cursor.close()
        return {'total': total, 'unread': unread, 'by_severity': by_severity, 'by_category': by_category}

    def create_notification(self, event_type, category, severity, title, description,
                            payload=None, related_identity_id=None, related_identity_name=None,
                            related_run_id=None, organization_id=None) -> dict:
        """Create a new notification."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO notifications
                (event_type, category, severity, title, description, payload,
                 related_identity_id, related_identity_name, related_run_id, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (event_type, category, severity, title, description,
              json.dumps(payload) if payload else None,
              related_identity_id, related_identity_name, related_run_id, organization_id))
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
            WHERE id = %s AND organization_id = %s RETURNING *
        """, (notification_id, self._organization_id))
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

    def mark_all_notifications_read(self, organization_id=None) -> int:
        """Mark all unread notifications as read. Returns count updated."""
        self._ensure_notifications_table()
        cursor = self.conn.cursor()
        effective_organization_id = organization_id if organization_id is not None else self._organization_id
        if effective_organization_id is not None:
            cursor.execute("UPDATE notifications SET read = true, read_at = NOW() WHERE read = false AND organization_id = %s", (effective_organization_id,))
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
            WHERE id = %s AND organization_id = %s RETURNING *
        """, (action_type, notification_id, self._organization_id))
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
        cursor.execute("DELETE FROM notifications WHERE id = %s AND organization_id = %s", (notification_id, self._organization_id))
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
                organization_id INTEGER,
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
                organization_id INTEGER,
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
                target_organization_id INTEGER,
                details JSONB DEFAULT '{}',
                ip_address TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_target_user ON admin_audit_log(target_user_id)")
        # Phase 1B: portal column on refresh_tokens
        cursor.execute("ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS portal VARCHAR(10) DEFAULT 'client'")
        self.conn.commit()
        cursor.close()
        # Ensure organizations table + migration (adds organization_id/is_superadmin to users if needed)
        self._ensure_organizations_table()
        Database._users_ensured = True

    def create_user(self, username, password_hash, display_name, role='compliance', created_by=None, organization_id=None, is_superadmin=False, portal_role=None, email=None, phone=None, force_password_change=False, is_root_user=False):
        """Create a new user. Returns user dict (without password_hash)."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO users (username, password_hash, display_name, role, created_by, organization_id, is_superadmin, portal_role, email, phone, force_password_change, is_root_user)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, username, display_name, role, enabled, created_at, updated_at, last_login_at, created_by, organization_id, is_superadmin, portal_role, email, phone, force_password_change, is_root_user
        """, (username, password_hash, display_name, role, created_by, organization_id, is_superadmin, portal_role, email, phone, force_password_change, is_root_user))
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
            SELECT u.*, o.name AS org_name, o.slug AS org_slug
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
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
                   u.organization_id, u.is_superadmin, u.portal_role,
                   u.email, u.phone, u.force_password_change,
                   o.name AS org_name, o.slug AS org_slug
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
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

    def get_users(self, organization_id=None, exclude_portal=False):
        """Get all users. Returns list of user dicts WITHOUT password_hash."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = """
            SELECT u.id, u.username, u.display_name, u.role, u.enabled,
                   u.created_at, u.updated_at, u.last_login_at, u.created_by,
                   u.organization_id, u.is_superadmin, u.portal_role,
                   o.name AS org_name
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
        """
        params = []
        conditions = []
        if organization_id is not None:
            conditions.append("u.organization_id = %s")
            params.append(organization_id)
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
                   u.organization_id, u.is_superadmin, u.portal_role,
                   u.email, u.phone,
                   o.name AS org_name
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
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
        """Update user fields. Allowed: display_name, role, enabled, password_hash, organization_id, is_superadmin, portal_role, email, phone."""
        self._ensure_users_table()
        allowed = {'display_name', 'role', 'enabled', 'password_hash', 'organization_id', 'is_superadmin', 'portal_role', 'email', 'phone'}
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
            RETURNING id, username, display_name, role, enabled, created_at, updated_at, last_login_at, created_by, organization_id, is_superadmin, portal_role, email, phone
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

    def save_refresh_token(self, user_id, token_hash, expires_at, portal='client'):
        """Save a hashed refresh token with portal context."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, portal)
            VALUES (%s, %s, %s, %s)
        """, (user_id, token_hash, expires_at, portal))
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

    def get_user_by_email(self, email, organization_id=None):
        """Lookup user by email (for forgot password). Returns full dict INCLUDING password_hash."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                SELECT u.*, o.name AS org_name, o.slug AS org_slug
                FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
                WHERE LOWER(u.email) = LOWER(%s) AND u.organization_id = %s AND u.enabled = true
            """, (email, organization_id))
        else:
            cursor.execute("""
                SELECT u.*, o.name AS org_name, o.slug AS org_slug
                FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
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
            SELECT u.*, o.name AS org_name, o.slug AS org_slug
            FROM users u LEFT JOIN organizations o ON o.id = u.organization_id
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

    def log_admin_audit(self, admin_user_id, action, target_user_id=None, target_organization_id=None, details=None, ip_address=None):
        """Insert into admin_audit_log."""
        self._ensure_users_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO admin_audit_log (admin_user_id, action, target_user_id, target_organization_id, details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (admin_user_id, action, target_user_id, target_organization_id, json.dumps(details or {}), ip_address))
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
            # Get default organization_id
            default_org_id = None
            try:
                cursor2 = self.conn.cursor()
                cursor2.execute("SELECT id FROM organizations ORDER BY id LIMIT 1")
                row = cursor2.fetchone()
                default_org_id = row[0] if row else None
                cursor2.close()
            except Exception:
                pass
            username = os.getenv('ADMIN_USERNAME', 'techadmin')
            password = os.getenv('ADMIN_PASSWORD')
            if not password:
                import secrets as _secrets
                password = _secrets.token_urlsafe(16)
                print(f"[FIRST RUN] Generated admin password for '{username}': {password}")
                print("[FIRST RUN] Set ADMIN_PASSWORD env var to persist this.")
            hashed = bcrypt_lib.hashpw(password.encode('utf-8'), bcrypt_lib.gensalt()).decode('utf-8')
            self.create_user(username, hashed, 'Administrator', 'admin', organization_id=default_org_id)
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
        # V3 columns — tier hierarchy, scope honesty
        cursor.execute("ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'core'")
        cursor.execute("ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS category VARCHAR(50)")
        cursor.execute("ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS short_name VARCHAR(30)")
        cursor.execute("ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS identity_controls_count INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS total_framework_controls INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS scope_label VARCHAR(255) DEFAULT 'Identity, access, and privilege controls'")
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
        # RLS: Add organization_id to core discovery tables
        for core_tbl in ['identities', 'role_assignments', 'entra_role_assignments',
                         'credentials', 'graph_api_permissions', 'sp_ownership',
                         'sp_app_roles', 'identity_roles', 'role_activity_log',
                         'ca_policies', 'ca_identity_coverage', 'drift_reports']:
            try:
                cursor.execute(f"ALTER TABLE {core_tbl} ADD COLUMN IF NOT EXISTS organization_id INTEGER")
                self.conn.commit()
            except Exception:
                self.conn.rollback()
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
        cursor.execute("ALTER TABLE compliance_snapshots ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        self.conn.commit()
        cursor.close()

    def save_compliance_snapshot(self, run_id, framework_key, framework_name, score, pass_count, warn_count, fail_count, total_controls, metrics):
        """Save or upsert a compliance snapshot for a run+framework."""
        self._ensure_compliance_snapshots_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO compliance_snapshots (run_id, framework_key, framework_name, score, pass_count, warn_count, fail_count, total_controls, metrics, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id, framework_key) DO UPDATE SET
                score = EXCLUDED.score, pass_count = EXCLUDED.pass_count,
                warn_count = EXCLUDED.warn_count, fail_count = EXCLUDED.fail_count,
                total_controls = EXCLUDED.total_controls, metrics = EXCLUDED.metrics
            RETURNING id
        """, (run_id, framework_key, framework_name, score, pass_count, warn_count, fail_count, total_controls, json.dumps(metrics), self._organization_id))
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

    # ─── AGIRS Scoring ─────────────────────────────────────────────

    _agirs_ensured = False

    def _ensure_agirs_scores_table(self):
        if Database._agirs_ensured:
            return
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agirs_scores (
                    id SERIAL PRIMARY KEY,
                    organization_id INTEGER NOT NULL,
                    run_id INTEGER REFERENCES discovery_runs(id) ON DELETE CASCADE,
                    agirs_score NUMERIC(5,2),
                    hiri_score NUMERIC(5,2),
                    nhiri_score NUMERIC(5,2),
                    gei_score NUMERIC(5,2),
                    hiri_breakdown JSONB,
                    nhiri_breakdown JSONB,
                    gei_breakdown JSONB,
                    dangerous_identities JSONB,
                    human_count INTEGER,
                    nhi_count INTEGER,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agirs_scores_org ON agirs_scores(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agirs_scores_run ON agirs_scores(run_id)")
            cursor.execute("ALTER TABLE identities ADD COLUMN IF NOT EXISTS blast_radius_score NUMERIC(7,2) DEFAULT 0")
            self.conn.commit()
            Database._agirs_ensured = True
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ agirs_scores table creation error: {e}")
        finally:
            cursor.close()

    def save_agirs_scores(self, run_id, scores_dict):
        """Persist AGIRS scores for a discovery run."""
        self._ensure_agirs_scores_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO agirs_scores (
                organization_id, run_id, agirs_score, hiri_score, nhiri_score, gei_score,
                hiri_breakdown, nhiri_breakdown, gei_breakdown,
                dangerous_identities, human_count, nhi_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            self._organization_id,
            run_id,
            scores_dict.get('agirs_score'),
            scores_dict.get('hiri_score'),
            scores_dict.get('nhiri_score'),
            scores_dict.get('gei_score'),
            json.dumps(scores_dict.get('hiri_breakdown')),
            json.dumps(scores_dict.get('nhiri_breakdown')),
            json.dumps(scores_dict.get('gei_breakdown')),
            json.dumps(scores_dict.get('dangerous_identities')),
            scores_dict.get('human_count', 0),
            scores_dict.get('nhi_count', 0),
        ))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return row[0] if row else None

    def get_latest_agirs_scores(self):
        """Return the latest AGIRS scores for the current organization (+ previous for delta)."""
        self._ensure_agirs_scores_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT agirs_score, hiri_score, nhiri_score, gei_score,
                   hiri_breakdown, nhiri_breakdown, gei_breakdown,
                   dangerous_identities, human_count, nhi_count, created_at
            FROM agirs_scores
            ORDER BY created_at DESC
            LIMIT 2
        """)
        rows = cursor.fetchall()
        cursor.close()

        if not rows:
            return None, None

        def _row_to_dict(r):
            return {
                'agirs_score': float(r[0]) if r[0] is not None else None,
                'hiri_score': float(r[1]) if r[1] is not None else None,
                'nhiri_score': float(r[2]) if r[2] is not None else None,
                'gei_score': float(r[3]) if r[3] is not None else None,
                'hiri_breakdown': r[4] if isinstance(r[4], dict) else (json.loads(r[4]) if r[4] else None),
                'nhiri_breakdown': r[5] if isinstance(r[5], dict) else (json.loads(r[5]) if r[5] else None),
                'gei_breakdown': r[6] if isinstance(r[6], dict) else (json.loads(r[6]) if r[6] else None),
                'dangerous_identities': r[7] if isinstance(r[7], list) else (json.loads(r[7]) if r[7] else []),
                'human_count': r[8] or 0,
                'nhi_count': r[9] or 0,
                'created_at': r[10].isoformat() if r[10] else None,
            }

        latest = _row_to_dict(rows[0])
        previous = _row_to_dict(rows[1]) if len(rows) > 1 else None
        return latest, previous

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
                organization_id INTEGER,
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
            ('risk_components', 'JSONB DEFAULT \'{}\''),
            ('blast_radius_score', 'INTEGER DEFAULT 0'),
            ('critical_overrides', 'JSONB DEFAULT \'[]\''),
            ('data_classification', 'VARCHAR(20)'),
            ('classification_source', 'VARCHAR(20)'),
            ('classification_confidence', 'VARCHAR(10)'),
            ('classified_by', 'VARCHAR(100)'),
            ('classified_at', 'TIMESTAMPTZ'),
            ('classification_notes', 'TEXT'),
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
                organization_id INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(discovery_run_id, resource_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kv_run ON azure_key_vaults(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kv_risk ON azure_key_vaults(risk_level)")
        # Add columns if upgrading from older schema
        for col, defn in [
            ('secrets_detail', 'JSONB DEFAULT \'[]\''),
            ('keys_detail', 'JSONB DEFAULT \'[]\''),
            ('certs_detail', 'JSONB DEFAULT \'[]\''),
            ('risk_components', 'JSONB DEFAULT \'{}\''),
            ('blast_radius_score', 'INTEGER DEFAULT 0'),
            ('critical_overrides', 'JSONB DEFAULT \'[]\''),
            ('data_classification', 'VARCHAR(20)'),
            ('classification_source', 'VARCHAR(20)'),
            ('classification_confidence', 'VARCHAR(10)'),
            ('classified_by', 'VARCHAR(100)'),
            ('classified_at', 'TIMESTAMPTZ'),
            ('classification_notes', 'TEXT'),
        ]:
            try:
                cursor.execute(f"ALTER TABLE azure_key_vaults ADD COLUMN {col} {defn}")
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
                risk_components, blast_radius_score, critical_overrides,
                tags, organization_id
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s
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
                risk_reasons=EXCLUDED.risk_reasons,
                risk_components=EXCLUDED.risk_components,
                blast_radius_score=EXCLUDED.blast_radius_score,
                critical_overrides=EXCLUDED.critical_overrides,
                tags=EXCLUDED.tags,
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
            json.dumps(data.get('risk_components', {})),
            data.get('blast_radius_score', 0),
            json.dumps(data.get('critical_overrides', [])),
            json.dumps(data.get('tags', {})), data.get('organization_id') or self._organization_id
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
                risk_level, risk_score, risk_reasons,
                risk_components, blast_radius_score, critical_overrides,
                tags, organization_id
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s
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
                risk_reasons=EXCLUDED.risk_reasons,
                risk_components=EXCLUDED.risk_components,
                blast_radius_score=EXCLUDED.blast_radius_score,
                critical_overrides=EXCLUDED.critical_overrides,
                tags=EXCLUDED.tags,
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
            json.dumps(data.get('risk_components', {})),
            data.get('blast_radius_score', 0),
            json.dumps(data.get('critical_overrides', [])),
            json.dumps(data.get('tags', {})), data.get('organization_id') or self._organization_id
        ))
        db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return db_id

    # ──────────────────────────────────────────────────────────
    # Resource Risk History (Phase 89)
    # ──────────────────────────────────────────────────────────

    def _ensure_resource_risk_history_table(self):
        """Create resource_risk_history table for trend tracking."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resource_risk_history (
                id SERIAL PRIMARY KEY,
                discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
                resource_id TEXT NOT NULL,
                resource_type VARCHAR(30) NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_level VARCHAR(20) NOT NULL DEFAULT 'info',
                risk_components JSONB DEFAULT '{}',
                critical_overrides JSONB DEFAULT '[]',
                blast_radius_score INTEGER DEFAULT 0,
                privileged_identity_count INTEGER DEFAULT 0,
                dependency_count INTEGER DEFAULT 0,
                network_exposure_score INTEGER DEFAULT 0,
                organization_id INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(discovery_run_id, resource_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rrh_resource ON resource_risk_history(resource_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rrh_run ON resource_risk_history(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rrh_created ON resource_risk_history(created_at DESC)")
        self.conn.commit()
        cursor.close()

    def save_resource_risk_history(self, run_id: int, resource_id: str, resource_type: str, data: dict) -> int:
        """Upsert a resource risk snapshot for a discovery run."""
        self._ensure_resource_risk_history_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO resource_risk_history
                (discovery_run_id, resource_id, resource_type, risk_score, risk_level,
                 risk_components, critical_overrides, blast_radius_score,
                 privileged_identity_count, dependency_count, network_exposure_score, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (discovery_run_id, resource_id)
            DO UPDATE SET risk_score = EXCLUDED.risk_score,
                         risk_level = EXCLUDED.risk_level,
                         risk_components = EXCLUDED.risk_components,
                         critical_overrides = EXCLUDED.critical_overrides,
                         blast_radius_score = EXCLUDED.blast_radius_score,
                         privileged_identity_count = EXCLUDED.privileged_identity_count,
                         dependency_count = EXCLUDED.dependency_count,
                         network_exposure_score = EXCLUDED.network_exposure_score
            RETURNING id
        """, (
            run_id, resource_id, resource_type,
            data.get('risk_score', 0), data.get('risk_level', 'info'),
            json.dumps(data.get('risk_components', {})),
            json.dumps(data.get('critical_overrides', [])),
            data.get('blast_radius_score', 0),
            data.get('privileged_identity_count', 0),
            data.get('dependency_count', 0),
            data.get('network_exposure_score', 0),
            self._organization_id,
        ))
        db_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return db_id

    def update_resource_risk_scores(self, run_id: int, resource_id: str, resource_type: str, data: dict):
        """Write enhanced risk scores back to the main resource table so list/detail views are consistent."""
        table = 'azure_storage_accounts' if resource_type == 'storage_account' else 'azure_key_vaults'
        cursor = self.conn.cursor()
        cursor.execute(f"""
            UPDATE {table}
            SET risk_score = %s,
                risk_level = %s,
                risk_components = %s,
                blast_radius_score = %s,
                critical_overrides = %s
            WHERE discovery_run_id = %s AND resource_id = %s
        """, (
            data.get('risk_score', 0),
            data.get('risk_level', 'info'),
            json.dumps(data.get('risk_components', {})),
            data.get('blast_radius_score', 0),
            json.dumps(data.get('critical_overrides', [])),
            run_id,
            resource_id,
        ))
        self.conn.commit()
        cursor.close()

    # ──────────────────────────────────────────────────────────
    # Resource Findings Table
    # ──────────────────────────────────────────────────────────

    _resource_findings_ensured = False

    def _ensure_resource_findings_table(self):
        """Create resource_findings table for queryable per-driver findings."""
        if Database._resource_findings_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resource_findings (
                id SERIAL PRIMARY KEY,
                discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
                resource_id TEXT NOT NULL,
                resource_type VARCHAR(30) NOT NULL,
                component VARCHAR(50) NOT NULL,
                finding_key VARCHAR(200) NOT NULL,
                finding_title TEXT NOT NULL,
                points INTEGER NOT NULL DEFAULT 0,
                severity VARCHAR(20) NOT NULL DEFAULT 'low',
                is_critical_override BOOLEAN NOT NULL DEFAULT false,
                metadata JSONB DEFAULT '{}',
                organization_id INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(discovery_run_id, resource_id, finding_key)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rf_resource ON resource_findings(resource_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rf_run ON resource_findings(discovery_run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rf_severity ON resource_findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rf_component ON resource_findings(component)")
        self.conn.commit()
        cursor.close()
        Database._resource_findings_ensured = True

    def save_resource_findings(self, run_id: int, resource_id: str, resource_type: str,
                                findings: list, organization_id: int = None):
        """Upsert findings extracted from risk_components for a resource."""
        self._ensure_resource_findings_table()
        if not findings:
            return
        cursor = self.conn.cursor()
        tid = organization_id or self._organization_id
        for f in findings:
            cursor.execute("""
                INSERT INTO resource_findings
                    (discovery_run_id, resource_id, resource_type, component,
                     finding_key, finding_title, points, severity,
                     is_critical_override, metadata, organization_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (discovery_run_id, resource_id, finding_key)
                DO UPDATE SET points = EXCLUDED.points,
                             severity = EXCLUDED.severity,
                             finding_title = EXCLUDED.finding_title,
                             is_critical_override = EXCLUDED.is_critical_override,
                             metadata = EXCLUDED.metadata
            """, (
                run_id, resource_id, resource_type, f['component'],
                f['finding_key'], f['finding_title'], f['points'], f['severity'],
                f['is_critical_override'], json.dumps(f.get('metadata', {})), tid,
            ))
        self.conn.commit()
        cursor.close()

    def get_resource_findings(self, resource_id: str, run_ids: list = None):
        """Get findings for a resource, optionally filtered by run IDs."""
        self._ensure_resource_findings_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if run_ids:
            cursor.execute("""
                SELECT * FROM resource_findings
                WHERE resource_id = %s AND discovery_run_id = ANY(%s)
                ORDER BY points DESC, component
            """, (resource_id, run_ids))
        else:
            cursor.execute("""
                SELECT * FROM resource_findings
                WHERE resource_id = %s
                ORDER BY created_at DESC, points DESC
                LIMIT 100
            """, (resource_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            if r.get('created_at'):
                r['created_at'] = r['created_at'].isoformat()
        return rows

    def get_resource_risk_trend(self, resource_id: str, limit: int = 10) -> list:
        """Get risk history for a resource, most recent first."""
        self._ensure_resource_risk_history_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT rrh.id, rrh.discovery_run_id, rrh.resource_id, rrh.resource_type,
                   rrh.risk_score, rrh.risk_level, rrh.risk_components, rrh.critical_overrides,
                   rrh.blast_radius_score, rrh.privileged_identity_count,
                   rrh.dependency_count, rrh.network_exposure_score,
                   rrh.created_at, dr.started_at AS run_date
            FROM resource_risk_history rrh
            LEFT JOIN discovery_runs dr ON dr.id = rrh.discovery_run_id
            WHERE rrh.resource_id = %s
            ORDER BY rrh.created_at DESC
            LIMIT %s
        """, (resource_id, limit))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('created_at', 'run_date'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_resource_risk_trend_batch(self, resource_ids: list, limit_per_resource: int = 2) -> dict:
        """Get risk trend for multiple resources (for list view). Returns dict keyed by resource_id."""
        self._ensure_resource_risk_history_table()
        if not resource_ids:
            return {}
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT resource_id, risk_score, risk_level, created_at
            FROM (
                SELECT resource_id, risk_score, risk_level, created_at,
                       ROW_NUMBER() OVER (PARTITION BY resource_id ORDER BY created_at DESC) AS rn
                FROM resource_risk_history
                WHERE resource_id = ANY(%s)
            ) ranked
            WHERE rn <= %s
            ORDER BY resource_id, created_at DESC
        """, (resource_ids, limit_per_resource))
        rows = cursor.fetchall()
        cursor.close()
        result = {}
        for r in rows:
            rid = r['resource_id']
            result.setdefault(rid, []).append({
                'risk_score': r['risk_score'],
                'risk_level': r['risk_level'],
            })
        return result

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
                organization_id INTEGER,
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
                approval_status, organization_id
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
            data.get('organization_id') or self._organization_id,
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
             'Guest accounts and multi-organization apps extend trust boundaries beyond the organization.',
             'trust', 'Review guest accounts quarterly; restrict multi-organization app registrations.', 70),
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

    def _migrate_compliance_v3(self):
        """Idempotent migration: add 5 new frameworks, expand 6 existing to 11-framework 3-tier model."""
        self._ensure_compliance_tables()
        cursor = self.conn.cursor()

        # Check if migration already applied
        cursor.execute("SELECT tier FROM compliance_frameworks WHERE key = 'soc2' LIMIT 1")
        row = cursor.fetchone()
        if row and row[0] and row[0] != 'core':
            # tier already customized => skip (but 'core' is the default so check further)
            pass
        # Better check: see if nist_csf exists
        cursor.execute("SELECT COUNT(*) FROM compliance_frameworks WHERE key = 'nist_csf'")
        if cursor.fetchone()[0] > 0:
            cursor.close()
            return  # already migrated

        # ── Step 1: Update existing 6 frameworks with tier/category/short_name/counts ──
        existing_updates = [
            ('soc2',       'core',      'Core Governance',       'SOC 2',      8,  64),
            ('iso_27001',  'core',      'Core Governance',       'ISO 27001',  12, 93),
            ('hipaa',      'industry',  'Industry Specific',     'HIPAA',      9,  75),
            ('pci_dss',    'industry',  'Industry Specific',     'PCI-DSS',    10, 78),
            ('cis_azure',  'benchmark', 'Technical Benchmarks',  'CIS Azure',  15, 200),
            ('nist_800_53','benchmark', 'Technical Benchmarks',  'NIST 800-53',18, 325),
        ]
        for key, tier, category, short_name, id_count, total in existing_updates:
            cursor.execute("""
                UPDATE compliance_frameworks
                SET tier = %s, category = %s, short_name = %s,
                    identity_controls_count = %s, total_framework_controls = %s
                WHERE key = %s
            """, (tier, category, short_name, id_count, total, key))

        # ── Step 2: Insert 5 new frameworks ──
        new_frameworks = [
            ('nist_csf', 'NIST Cybersecurity Framework', 'Voluntary framework for managing cybersecurity risk — Identify, Protect, Detect, Respond, Recover.',
             'v2.0', True, 15, 'core', 'Core Governance', 'NIST CSF', 15, 108, 'Identity, access, and privilege controls'),
            ('sox', 'SOX (Sarbanes-Oxley)', 'Financial reporting controls — IT General Controls for access management and segregation of duties.',
             'Section 302/404', True, 25, 'industry', 'Industry Specific', 'SOX', 6, 66, 'Identity, access, and privilege controls'),
            ('hitrust', 'HITRUST CSF', 'Common Security Framework harmonizing healthcare and security requirements.',
             'v11', True, 35, 'industry', 'Industry Specific', 'HITRUST', 14, 156, 'Identity, access, and privilege controls'),
            ('gdpr', 'GDPR', 'EU General Data Protection Regulation — data protection and privacy requirements.',
             'Regulation (EU) 2016/679', True, 70, 'privacy', 'Privacy & Data Protection', 'GDPR', 7, 99, 'Identity, access, and privilege controls'),
            ('ccpa', 'CCPA', 'California Consumer Privacy Act — consumer data protection requirements.',
             'AB 375', True, 75, 'privacy', 'Privacy & Data Protection', 'CCPA', 5, 31, 'Identity, access, and privilege controls'),
        ]
        for key, name, desc, version, enabled, d_order, tier, category, short_name, id_count, total, scope in new_frameworks:
            cursor.execute("""
                INSERT INTO compliance_frameworks (key, name, description, version, enabled, display_order,
                    tier, category, short_name, identity_controls_count, total_framework_controls, scope_label)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (key) DO NOTHING
            """, (key, name, desc, version, enabled, d_order, tier, category, short_name, id_count, total, scope))

        # ── Step 3: Add new controls to existing frameworks ──
        # Build framework key → id map
        cursor.execute("SELECT id, key FROM compliance_frameworks")
        fw_map = {row[1]: row[0] for row in cursor.fetchall()}

        def _add_controls(fw_key, controls):
            """Insert controls; skip on conflict."""
            fw_id = fw_map.get(fw_key)
            if not fw_id:
                return
            for i, ctrl in enumerate(controls):
                ctrl_id, name, metric, pass_op, pass_val, warn_op, warn_val, drilldown, severity, weight, pillar = ctrl
                cursor.execute("""
                    INSERT INTO compliance_controls
                        (framework_id, control_id, name, metric, pass_operator, pass_value,
                         warn_operator, warn_value, drilldown_url, display_order, severity, weight, pillar)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (framework_id, control_id) DO NOTHING
                """, (fw_id, ctrl_id, name, metric, pass_op, pass_val, warn_op, warn_val, drilldown,
                      (len(controls) + i + 1) * 10, severity, weight, pillar))

        # SOC 2 +3
        _add_controls('soc2', [
            ('CC6.6', 'MFA Enforcement', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'critical', 9, 'authentication'),
            ('CC7.1', 'Anomaly Monitoring', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 6, 'usage'),
            ('CC8.2', 'Credential Rotation', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'high', 7, 'credential'),
        ])

        # ISO 27001 +7
        _add_controls('iso_27001', [
            ('A.5.18', 'Access Rights', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 7, 'privilege'),
            ('A.6.1', 'Screening', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 5, 'usage'),
            ('A.8.3', 'Access Restriction', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('A.8.6', 'Capacity Management', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'high', 7, 'usage'),
            ('A.5.23', 'Cloud Security', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'high', 7, 'governance'),
            ('A.5.24', 'Incident Management', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'high', 7, 'credential'),
            ('A.5.25', 'Evidence Collection', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'medium', 6, 'credential'),
        ])

        # HIPAA +4
        _add_controls('hipaa', [
            ('§164.308(a)(1)', 'Risk Analysis', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('§164.308(a)(5)', 'Security Awareness', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'high', 8, 'authentication'),
            ('§164.312(e)', 'Transmission Security', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'high', 7, 'credential'),
            ('§164.308(a)(8)', 'Evaluation', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 6, 'usage'),
        ])

        # PCI-DSS +6
        _add_controls('pci_dss', [
            ('8.2.1', 'Unique IDs', 'no_shared_accounts', '==', 0, '<=', 2,
             '/identities?shared_account=true', 'high', 8, 'governance'),
            ('8.3', 'Secure Authentication', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'high', 8, 'credential'),
            ('8.5', 'Shared IDs Prohibited', 'no_shared_accounts', '==', 0, '<=', 2,
             '/identities?shared_account=true', 'high', 7, 'governance'),
            ('10.1', 'Audit Trails', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 6, 'usage'),
            ('10.2', 'Automated Audit', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
            ('7.2.2', 'Role-Based Access', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 7, 'privilege'),
        ])

        # CIS Azure +10
        _add_controls('cis_azure', [
            ('1.6', 'PIM for Global Admin', 'pim_coverage_pct', '>=', 80, '>=', 50,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('1.7', 'Guest Account Review', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?identity_category=guest', 'high', 7, 'usage'),
            ('1.8', 'Credential Rotation Policy', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'high', 8, 'credential'),
            ('1.9', 'Managed Identity Usage', 'managed_identity_pct', '>=', 60, '>=', 30,
             '/identities?identity_category=service_principal', 'medium', 6, 'governance'),
            ('1.10', 'SPN Owner Assignment', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'high', 7, 'governance'),
            ('1.11', 'Dormant Account Cleanup', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'high', 7, 'usage'),
            ('1.12', 'Access Review Completion', 'access_reviews_completed', '>=', 1, None, None,
             '/identities?access_review=pending', 'medium', 5, 'governance'),
            ('1.13', 'Excessive Role Assignments', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 7, 'privilege'),
            ('1.14', 'Credential Rotation Compliance', 'credential_rotation_compliance_pct', '>=', 80, '>=', 50,
             '/identities?credential_rotation=overdue', 'high', 8, 'credential'),
            ('1.15', 'MFA for All Users', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'critical', 9, 'authentication'),
        ])

        # NIST 800-53 +13
        _add_controls('nist_800_53', [
            ('AC-3', 'Access Enforcement', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 8, 'privilege'),
            ('IA-2', 'Identification & Auth', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'critical', 9, 'authentication'),
            ('IA-4', 'Identifier Management', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'high', 7, 'usage'),
            ('IA-8', 'Non-Org User Auth', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?identity_category=guest&mfa_enforced=false', 'high', 7, 'authentication'),
            ('SI-4', 'System Monitoring', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
            ('PM-10', 'Security Authorization', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'high', 7, 'governance'),
            ('AC-5', 'Separation of Duties', 'no_shared_accounts', '==', 0, '<=', 2,
             '/identities?shared_account=true', 'high', 7, 'governance'),
            ('IA-5(1)', 'Password-Based Auth', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'high', 8, 'credential'),
            ('AC-2(3)', 'Disable Inactive Accounts', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'high', 7, 'usage'),
            ('AC-6(5)', 'Privileged Accounts', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('IA-5(6)', 'Credential Protection', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'high', 8, 'credential'),
            ('AC-2(4)', 'Automated Audit Actions', 'credential_rotation_compliance_pct', '>=', 80, '>=', 50,
             '/identities?credential_rotation=overdue', 'high', 7, 'credential'),
            ('SC-12', 'Cryptographic Key Mgmt', 'managed_identity_pct', '>=', 60, '>=', 30,
             '/identities?identity_category=service_principal', 'medium', 6, 'credential'),
        ])

        # ── Step 4: Seed controls for new frameworks ──

        # NIST CSF (15 controls)
        _add_controls('nist_csf', [
            ('PR.AA-1', 'Identity Management', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('PR.AA-2', 'Authentication', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'critical', 9, 'authentication'),
            ('PR.AA-3', 'Credential Lifecycle', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'high', 8, 'credential'),
            ('PR.AA-4', 'Access Reviews', 'access_reviews_completed', '>=', 1, None, None,
             '/identities?access_review=pending', 'medium', 5, 'governance'),
            ('PR.AA-5', 'Least Privilege', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 8, 'privilege'),
            ('PR.AC-1', 'Access Control', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'high', 7, 'usage'),
            ('DE.CM-1', 'Network Monitoring', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 6, 'usage'),
            ('DE.CM-3', 'Personnel Activity', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
            ('RS.AN-1', 'Incident Analysis', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'high', 7, 'governance'),
            ('RS.MI-1', 'Incident Mitigation', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'high', 7, 'credential'),
            ('ID.AM-1', 'Asset Inventory', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 5, 'usage'),
            ('ID.RA-1', 'Risk Assessment', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'high', 7, 'privilege'),
            ('GV.OC-1', 'Org Context', 'pim_coverage_pct', '>=', 80, '>=', 50,
             '/identities?privilege_tier=T0', 'medium', 5, 'governance'),
            ('GV.RM-1', 'Risk Management', 'credential_rotation_compliance_pct', '>=', 80, '>=', 50,
             '/identities?credential_rotation=overdue', 'medium', 5, 'credential'),
            ('GV.SC-1', 'Supply Chain Risk', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'medium', 5, 'governance'),
        ])

        # SOX (6 controls)
        _add_controls('sox', [
            ('SOX-302', 'CEO/CFO Certification', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('SOX-404', 'Internal Controls', 'access_reviews_completed', '>=', 1, None, None,
             '/identities?access_review=pending', 'high', 8, 'governance'),
            ('SOX-IT1', 'Access Provisioning', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 7, 'privilege'),
            ('SOX-IT2', 'Segregation of Duties', 'no_shared_accounts', '==', 0, '<=', 2,
             '/identities?shared_account=true', 'high', 8, 'governance'),
            ('SOX-IT3', 'Dormant Account Review', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'high', 7, 'usage'),
            ('SOX-IT4', 'Credential Management', 'credential_rotation_compliance_pct', '>=', 80, '>=', 50,
             '/identities?credential_rotation=overdue', 'medium', 6, 'credential'),
        ])

        # HITRUST (14 controls)
        _add_controls('hitrust', [
            ('01.b', 'User Registration', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('01.d', 'User Password Mgmt', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'high', 8, 'credential'),
            ('01.e', 'Review of Access Rights', 'access_reviews_completed', '>=', 1, None, None,
             '/identities?access_review=pending', 'high', 7, 'governance'),
            ('01.f', 'Shared Account Control', 'no_shared_accounts', '==', 0, '<=', 2,
             '/identities?shared_account=true', 'high', 7, 'governance'),
            ('01.g', 'Unattended Equipment', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
            ('01.j', 'User Authentication', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'critical', 9, 'authentication'),
            ('01.k', 'Equipment Identification', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'high', 7, 'governance'),
            ('01.l', 'Remote Diagnostic Port', 'no_credential_rotation', '==', 0, '<=', 5,
             '/identities?credential_rotation=overdue', 'high', 7, 'credential'),
            ('01.s', 'Privilege Management', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 8, 'privilege'),
            ('01.t', 'Session Timeout', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 5, 'usage'),
            ('01.v', 'Information Access', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
            ('01.w', 'Sensitive System Isolation', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'high', 7, 'privilege'),
            ('01.x', 'Access Control Policy', 'pim_coverage_pct', '>=', 80, '>=', 50,
             '/identities?privilege_tier=T0', 'medium', 5, 'governance'),
            ('01.y', 'Credential Rotation', 'credential_rotation_compliance_pct', '>=', 80, '>=', 50,
             '/identities?credential_rotation=overdue', 'high', 7, 'credential'),
        ])

        # GDPR (7 controls)
        _add_controls('gdpr', [
            ('Art.5(1)(f)', 'Integrity & Confidentiality', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'critical', 9, 'privilege'),
            ('Art.25', 'Data Protection by Design', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'high', 8, 'authentication'),
            ('Art.32', 'Security of Processing', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'high', 8, 'credential'),
            ('Art.33', 'Breach Notification', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'medium', 6, 'usage'),
            ('Art.35', 'Impact Assessment', 'excessive_permissions', '==', 0, '<=', 5,
             '/identities?excessive_permissions=true', 'high', 7, 'privilege'),
            ('Art.30', 'Records of Processing', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
            ('Art.37', 'Data Protection Officer', 'unowned_spns', '==', 0, '<=', 3,
             '/identities?identity_category=service_principal&has_owner=false', 'medium', 5, 'governance'),
        ])

        # CCPA (5 controls)
        _add_controls('ccpa', [
            ('1798.100', 'Consumer Right to Know', 't0_count', '<=', 2, '<=', 5,
             '/identities?privilege_tier=T0', 'high', 7, 'privilege'),
            ('1798.105', 'Right to Delete', 'stale_accounts', '==', 0, '<=', 3,
             '/identities?activity_status=stale', 'high', 7, 'usage'),
            ('1798.150', 'Data Breach Liability', 'expired_credentials', '==', 0, None, None,
             '/identities?credential_status=expired', 'critical', 9, 'credential'),
            ('1798.185', 'Reasonable Security', 'mfa_not_enforced', '==', 0, '<=', 2,
             '/identities?mfa_enforced=false', 'high', 8, 'authentication'),
            ('1798.140', 'Personal Information', 'dormant_privileged', '==', 0, '<=', 2,
             '/identities?activity_status=stale&has_roles=true', 'medium', 6, 'usage'),
        ])

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
        cursor.execute("ALTER TABLE saved_views ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS campaign_type VARCHAR(100) DEFAULT 'general'")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS scope_clouds TEXT[]")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS scope_description VARCHAR(500)")
        cursor.execute("ALTER TABLE access_review_campaigns ADD COLUMN IF NOT EXISTS risk_focus VARCHAR(100)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_org ON access_review_campaigns(organization_id)")
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
        cursor.execute("ALTER TABLE campaign_reviews ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        cursor.execute("ALTER TABLE campaign_audit_log ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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
                        scope_description: str = None, risk_focus: str = None, organization_id: int = None) -> dict:
        """Create a new access review campaign with V2 fields."""
        self._ensure_access_review_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO access_review_campaigns (name, description, scope_filters, deadline, created_by,
                campaign_type, scope_clouds, scope_description, risk_focus, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (name, description, json.dumps(scope_filters) if scope_filters else '{}', deadline, created_by,
              campaign_type, scope_clouds, scope_description, risk_focus, organization_id))
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
        cursor.execute("ALTER TABLE identity_groups ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        cursor.execute("ALTER TABLE identity_group_members ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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

    def deduplicate_auto_groups(self):
        """Clean up auto groups and ensure every organization has them.

        1. Deletes orphan groups with NULL organization_id
        2. Removes duplicates per (name, organization_id)
        3. Seeds auto groups for any organization that doesn't have them
        """
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor()
        try:
            # Delete auto groups with NULL organization_id (created by old startup seeder)
            cursor.execute("DELETE FROM identity_groups WHERE group_type = 'auto' AND organization_id IS NULL")
            # Delete duplicate auto groups per organization, keeping the lowest id
            cursor.execute("""
                DELETE FROM identity_groups
                WHERE id IN (
                    SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (PARTITION BY name, organization_id ORDER BY id) AS rn
                        FROM identity_groups
                        WHERE group_type = 'auto'
                    ) ranked
                    WHERE rn > 1
                )
            """)
            self.conn.commit()
            # Seed auto groups for all organizations that don't have them yet
            cursor.execute("SELECT id FROM organizations WHERE enabled = true")
            organization_ids = [r[0] for r in cursor.fetchall()]
            cursor.close()
            for tid in organization_ids:
                self.seed_auto_groups_for_organization(tid)
        except Exception:
            self.conn.rollback()
            try:
                cursor.close()
            except Exception:
                pass

    def seed_auto_groups_for_organization(self, organization_id):
        """Create default auto groups for a specific organization if they don't exist.

        Called after discovery completes to ensure each organization has their own
        auto-groups with the correct organization_id for RLS visibility.
        """
        self._ensure_identity_group_tables()
        cursor = self.conn.cursor()
        # Ensure unique index exists for idempotent inserts
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_groups_auto_name_org
            ON identity_groups (name, organization_id) WHERE group_type = 'auto'
        """)
        self.conn.commit()

        auto_groups = [
            ('All Service Principals', '#6366F1', {'identity_category': 'service_principal'}),
            ('All Human Users', '#3B82F6', {'identity_category': 'human_user'}),
            ('All Managed Identities', '#8B5CF6', {'identity_category': ['managed_identity_system', 'managed_identity_user']}),
            ('All Guest Users', '#F59E0B', {'identity_category': 'guest'}),
        ]
        for name, color, criteria in auto_groups:
            cursor.execute("""
                INSERT INTO identity_groups (name, color, group_type, auto_criteria, organization_id)
                VALUES (%s, %s, 'auto', %s, %s)
                ON CONFLICT (name, organization_id) WHERE group_type = 'auto' DO NOTHING
            """, (name, color, json.dumps(criteria), organization_id))
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
        cursor.execute("ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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
                     title, description, details, organization_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                run_id, a['anomaly_type'], a.get('severity', 'medium'),
                a.get('identity_id'), a.get('identity_name'),
                a['title'], a['description'],
                json.dumps(a['details']) if a.get('details') else None,
                self._organization_id,
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
        return self.get_identity_anomalies_multi([identity_id], limit=limit)

    def get_identity_anomalies_multi(self, identity_ids: list, limit=20) -> list:
        """Get anomalies matching any of the given identity IDs.

        Handles the mismatch where some anomaly sources store Entra string
        identity_id and others store DB integer id.
        """
        self._ensure_anomalies_table()
        if not identity_ids:
            return []
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        placeholders = ','.join(['%s'] * len(identity_ids))
        cursor.execute(f"""
            SELECT * FROM anomalies
            WHERE identity_id IN ({placeholders})
            ORDER BY created_at DESC
            LIMIT %s
        """, (*identity_ids, limit))
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
        # P0 organization isolation: add organization_id column
        cursor.execute("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(organization_id)")
        self.conn.commit()
        cursor.close()

    def create_api_key(self, key_prefix, key_hash, name, description, role, created_by, expires_at=None, organization_id=None):
        """Insert a new API key. Returns dict (never includes key_hash)."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO api_keys (key_prefix, key_hash, name, description, role, created_by, expires_at, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, key_prefix, name, description, role, enabled, created_by,
                      created_at, last_used_at, expires_at, usage_count, organization_id
        """, (key_prefix, key_hash, name, description, role, created_by, expires_at, organization_id))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        for ts in ('created_at', 'last_used_at', 'expires_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat()
        return row

    def get_api_keys(self, organization_id=None):
        """List API keys scoped by organization. Never returns key_hash."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                SELECT ak.id, ak.key_prefix, ak.name, ak.description, ak.role,
                       ak.enabled, ak.created_by, u.display_name as created_by_name,
                       ak.created_at, ak.last_used_at, ak.expires_at, ak.usage_count
                FROM api_keys ak
                LEFT JOIN users u ON u.id = ak.created_by
                WHERE ak.organization_id = %s
                ORDER BY ak.id
            """, (organization_id,))
        else:
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

    def get_api_key_by_id(self, key_id, organization_id=None):
        """Get single API key by id, optionally scoped by organization. Never returns key_hash."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                SELECT id, key_prefix, name, description, role, enabled, created_by,
                       created_at, last_used_at, expires_at, usage_count
                FROM api_keys WHERE id = %s AND organization_id = %s
            """, (key_id, organization_id))
        else:
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

    def update_api_key(self, key_id, organization_id=None, **kwargs):
        """Update API key fields. Allowed: name, description, role, enabled."""
        self._ensure_api_keys_table()
        allowed = {'name', 'description', 'role', 'enabled'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_api_key_by_id(key_id, organization_id=organization_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            params.append(v)
        where = "id = %s"
        params.append(key_id)
        if organization_id is not None:
            where += " AND organization_id = %s"
            params.append(organization_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE api_keys SET {', '.join(set_parts)}
            WHERE {where}
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

    def delete_api_key(self, key_id, organization_id=None):
        """Delete API key, scoped by organization. Returns True if deleted."""
        self._ensure_api_keys_table()
        cursor = self.conn.cursor()
        if organization_id is not None:
            cursor.execute("DELETE FROM api_keys WHERE id = %s AND organization_id = %s", (key_id, organization_id))
        else:
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
        cursor.execute("ALTER TABLE soar_playbooks ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        cursor.execute("ALTER TABLE soar_actions ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        self.conn.commit()
        cursor.close()

    def get_soar_playbooks(self):
        """List all SOAR playbooks."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM soar_playbooks WHERE organization_id = %s ORDER BY created_at DESC", (self._organization_id,))
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
        cursor.execute("SELECT * FROM soar_playbooks WHERE id = %s AND organization_id = %s", (playbook_id, self._organization_id))
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
                action_type, action_config, integration, cooldown_minutes, created_by, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (name, description, trigger_type, json.dumps(trigger_conditions),
              action_type, json.dumps(action_config), integration, cooldown_minutes, created_by, self._organization_id))
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
        params.append(self._organization_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE soar_playbooks SET {', '.join(set_parts)}
            WHERE id = %s AND organization_id = %s RETURNING *
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
        cursor.execute("DELETE FROM soar_playbooks WHERE id = %s AND organization_id = %s", (playbook_id, self._organization_id))
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    def get_enabled_playbooks_by_trigger(self, trigger_type):
        """Get enabled playbooks matching a trigger type. Used by SOAR engine."""
        self._ensure_soar_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT * FROM soar_playbooks WHERE enabled = true AND trigger_type = %s AND organization_id = %s ORDER BY id",
            (trigger_type, self._organization_id)
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
                action_type, integration, status, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)
            RETURNING id
        """, (playbook_id, identity_id, anomaly_id,
              json.dumps(trigger_event) if trigger_event else None,
              action_type, integration, self._organization_id))
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
        where_parts = ["sa.organization_id = %s"]
        params = [self._organization_id]
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
            WHERE organization_id = %s
        """, (self._organization_id,))
        stats = dict(cursor.fetchone())
        stats['success_rate'] = round(stats['success_count'] / stats['total'] * 100, 1) if stats['total'] > 0 else 0
        cursor.execute("""
            SELECT integration, COUNT(*) as count
            FROM soar_actions WHERE organization_id = %s GROUP BY integration ORDER BY count DESC
        """, (self._organization_id,))
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
        cursor.execute("ALTER TABLE dashboard_preferences ADD COLUMN IF NOT EXISTS organization_id INTEGER")
        # Composite unique index for multi-organization isolation
        cursor.execute("DROP INDEX IF EXISTS idx_dashboard_prefs_user_org")
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_prefs_user_org
            ON dashboard_preferences(user_id, organization_id)
        """)
        self.conn.commit()
        cursor.close()

    def get_dashboard_preferences(self, user_id):
        """Get dashboard preferences for a user. Returns dict or None."""
        self._ensure_dashboard_preferences_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT * FROM dashboard_preferences WHERE user_id = %s AND organization_id = %s",
            (user_id, self._organization_id)
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
            INSERT INTO dashboard_preferences (user_id, preferences, organization_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, organization_id) DO UPDATE SET
                preferences = EXCLUDED.preferences,
                updated_at = NOW()
            RETURNING *
        """, (user_id, json.dumps(preferences), self._organization_id))
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
            "DELETE FROM dashboard_preferences WHERE user_id = %s AND organization_id = %s",
            (user_id, self._organization_id)
        )
        deleted = cursor.rowcount > 0
        self.conn.commit()
        cursor.close()
        return deleted

    # ========================================================================
    # Phase 45: Multi-Organization Foundation
    # ========================================================================

    _organizations_ensured = False
    _migration_018_ensured = False

    def _run_migration_018_org_rename(self):
        """Phase 2C: Rename tenants→organizations, tenant_id→organization_id across all tables.
        Idempotent — checks column/table existence before each ALTER. Runs as admin (BYPASSRLS)."""
        if Database._migration_018_ensured:
            return
        cursor = self.conn.cursor()

        # 1. Rename tenants table → organizations
        cursor.execute("""
            DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
                    ALTER TABLE tenants RENAME TO organizations;
                END IF;
            END $$
        """)
        self.conn.commit()

        # 2. Rename tenant_id → organization_id on all tables
        tables_with_org_id = [
            'users', 'discovery_runs', 'settings', 'activity_log', 'webhooks',
            'webhook_deliveries', 'custom_risk_rules', 'notifications', 'identities',
            'role_assignments', 'entra_role_assignments', 'credentials',
            'graph_api_permissions', 'sp_app_roles', 'pim_eligible_assignments',
            'pim_activations', 'drift_reports', 'saved_views',
            'access_review_campaigns', 'campaign_reviews', 'campaign_audit_log',
            'identity_groups', 'identity_group_members', 'anomalies', 'api_keys',
            'soar_playbooks', 'soar_actions', 'dashboard_preferences',
            'compliance_snapshots', 'agirs_scores', 'azure_storage_accounts',
            'azure_key_vaults', 'resource_risk_history', 'resource_findings',
            'app_registrations', 'copilot_conversations', 'cloud_connections',
            'cloud_subscriptions', 'billing_events', 'invoices',
            'identity_subscription_access', 'sa_attestations', 'governance_decisions',
            'remediation_actions', 'sso_auth_codes', 'ca_policies',
            'ca_identity_coverage', 'sp_ownership', 'role_activity_log',
            'workload_signin_events', 'workload_activity_stats', 'workload_anomaly_events',
            'rbac_hygiene_scans', 'human_identities', 'identity_links',
            'orphaned_findings', 'scan_schedules',
        ]
        for tbl in tables_with_org_id:
            cursor.execute(f"""
                DO $$ BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = '{tbl}' AND column_name = 'tenant_id'
                    ) THEN
                        ALTER TABLE {tbl} RENAME COLUMN tenant_id TO organization_id;
                    END IF;
                END $$
            """)
        self.conn.commit()

        # 3. Rename entra_tenant_id → azure_directory_id on cloud_connections
        cursor.execute("""
            DO $$ BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'cloud_connections' AND column_name = 'entra_tenant_id'
                ) THEN
                    ALTER TABLE cloud_connections RENAME COLUMN entra_tenant_id TO azure_directory_id;
                END IF;
            END $$
        """)
        self.conn.commit()

        # 4. Drop old RLS policies and create new ones
        for tbl in tables_with_org_id:
            for suffix in ['sel', 'ins', 'upd', 'del']:
                cursor.execute(f"DROP POLICY IF EXISTS tenant_strict_{suffix} ON {tbl}")
                cursor.execute(f"DROP POLICY IF EXISTS org_strict_{suffix} ON {tbl}")
            # Create new policies (only if table has organization_id and RLS enabled)
            cursor.execute(f"""
                DO $$ BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = '{tbl}' AND column_name = 'organization_id'
                    ) THEN
                        CREATE POLICY org_strict_sel ON {tbl} FOR SELECT
                            USING (organization_id = current_setting('app.current_organization_id', true)::integer);
                        CREATE POLICY org_strict_ins ON {tbl} FOR INSERT
                            WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
                        CREATE POLICY org_strict_upd ON {tbl} FOR UPDATE
                            USING (organization_id = current_setting('app.current_organization_id', true)::integer);
                        CREATE POLICY org_strict_del ON {tbl} FOR DELETE
                            USING (organization_id = current_setting('app.current_organization_id', true)::integer);
                    END IF;
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$
            """)
        self.conn.commit()

        # 5. Drop old triggers and create new ones
        for tbl in tables_with_org_id:
            cursor.execute(f"DROP TRIGGER IF EXISTS trg_auto_tenant_id ON {tbl}")
            cursor.execute(f"DROP TRIGGER IF EXISTS trg_auto_organization_id ON {tbl}")
            cursor.execute(f"""
                DO $$ BEGIN
                    CREATE OR REPLACE FUNCTION fn_auto_organization_id_{tbl}() RETURNS trigger AS $fn$
                    BEGIN
                        IF NEW.organization_id IS NULL THEN
                            NEW.organization_id := current_setting('app.current_organization_id', true)::integer;
                        END IF;
                        IF NEW.organization_id IS NULL THEN
                            RAISE EXCEPTION 'organization_id cannot be NULL on {tbl}';
                        END IF;
                        RETURN NEW;
                    END;
                    $fn$ LANGUAGE plpgsql;

                    CREATE TRIGGER trg_auto_organization_id
                        BEFORE INSERT ON {tbl}
                        FOR EACH ROW EXECUTE FUNCTION fn_auto_organization_id_{tbl}();
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$
            """)
        self.conn.commit()

        # 6. Rename settings key
        cursor.execute("UPDATE settings SET key = 'azure_directory_id' WHERE key = 'azure_tenant_id'")
        self.conn.commit()

        # 7. Rename indexes (best-effort, skip if already renamed)
        for tbl in tables_with_org_id:
            old_idx = f"idx_{tbl}_tenant"
            new_idx = f"idx_{tbl}_org"
            cursor.execute(f"""
                DO $$ BEGIN
                    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = '{old_idx}') THEN
                        ALTER INDEX {old_idx} RENAME TO {new_idx};
                    END IF;
                END $$
            """)
        self.conn.commit()

        # 8. Update unique constraint on cloud_connections
        cursor.execute("""
            DO $$ BEGIN
                ALTER TABLE cloud_connections DROP CONSTRAINT IF EXISTS cloud_connections_organization_id_cloud_entra_organization_key;
                ALTER TABLE cloud_connections DROP CONSTRAINT IF EXISTS cloud_connections_tenant_id_cloud_entra_tenant_id_key;
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint WHERE conname = 'cloud_connections_org_cloud_dir_key'
                ) THEN
                    ALTER TABLE cloud_connections
                        ADD CONSTRAINT cloud_connections_org_cloud_dir_key
                        UNIQUE (organization_id, cloud, azure_directory_id);
                END IF;
            EXCEPTION WHEN undefined_table THEN NULL;
            END $$
        """)
        self.conn.commit()

        cursor.close()
        Database._migration_018_ensured = True

    def _ensure_organizations_table(self):
        """Create organizations table and run multi-organization migration (idempotent, runs once per process)."""
        if Database._organizations_ensured:
            return

        # Run migration 018 first (renames tenants→organizations if needed)
        self._run_migration_018_org_rename()

        cursor = self.conn.cursor()

        # 1. Create organizations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
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
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug)")
        # Phase 77: Add license columns
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS license_activated_at TIMESTAMPTZ")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS license_expires_at TIMESTAMPTZ")
        # Phase 78: Add logo_url column
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS logo_url TEXT")
        # Subscription term: 0=monthly, 1/3/5 = year commitments
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subscription_term INTEGER NOT NULL DEFAULT 0")
        # Phase 85: Tenant onboarding metadata
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS primary_cloud VARCHAR(20)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS compliance_framework VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active'")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS onboarding_stage VARCHAR(20) NOT NULL DEFAULT 'active'")
        # Billing columns
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS platform_fee_cents INTEGER NOT NULL DEFAULT 20000")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS discount_pct DECIMAL(5,2) NOT NULL DEFAULT 0")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS trial_expires_at TIMESTAMPTZ")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_status VARCHAR(20) NOT NULL DEFAULT 'active'")
        # Tax configuration
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tax_label VARCHAR(50) NOT NULL DEFAULT 'Tax'")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tax_rate DECIMAL(5,2) NOT NULL DEFAULT 0")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tax_id VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tax_exempt BOOLEAN NOT NULL DEFAULT false")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tax_notes TEXT")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS payment_terms INTEGER NOT NULL DEFAULT 30")
        # Billing address
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_company VARCHAR(255)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_address_line1 VARCHAR(255)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_address_line2 VARCHAR(255)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_city VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_state VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_postal_code VARCHAR(20)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_country VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS billing_email VARCHAR(255)")
        # Backfill: free/trial organizations get 0 platform fee
        cursor.execute("UPDATE organizations SET platform_fee_cents = 0 WHERE plan IN ('free', 'trial') AND platform_fee_cents != 0")
        # Phase 78: Migrate growth→pro plan + API key role renames
        cursor.execute("UPDATE organizations SET plan = 'pro' WHERE plan = 'growth'")
        cursor.execute("UPDATE api_keys SET role = 'reader' WHERE role = 'auditor'")
        cursor.execute("UPDATE api_keys SET role = 'compliance' WHERE role = 'viewer'")
        self.conn.commit()

        # 2. Rename any existing "Default Organization" → "Acme Organization"
        cursor.execute("UPDATE organizations SET name = 'Acme Organization' WHERE slug = 'default' AND name = 'Default Organization'")
        self.conn.commit()

        # 3. Create default organization if none exist
        cursor.execute("SELECT COUNT(*) FROM organizations")
        org_count = cursor.fetchone()[0]

        default_org_id = None
        if org_count == 0:
            cursor.execute("""
                INSERT INTO organizations (name, slug, plan)
                VALUES ('Acme Organization', 'default', 'enterprise')
                RETURNING id
            """)
            default_org_id = cursor.fetchone()[0]
            self.conn.commit()
        else:
            cursor.execute("SELECT id FROM organizations ORDER BY id LIMIT 1")
            row = cursor.fetchone()
            default_org_id = row[0] if row else None

        # 4. Add organization_id + is_superadmin + portal_role columns to users
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id)")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT false")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS portal_role VARCHAR(20)")
        # Phase 77: Add email/phone to users
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50)")
        self.conn.commit()

        if default_org_id:
            cursor.execute("UPDATE users SET organization_id = %s WHERE organization_id IS NULL", (default_org_id,))
            # Promote user id=1 to superadmin with portal_role
            cursor.execute("UPDATE users SET is_superadmin = true, portal_role = 'superadmin' WHERE id = 1 AND is_superadmin = false")
            # Backfill portal_role for existing superadmins
            cursor.execute("UPDATE users SET portal_role = 'superadmin' WHERE is_superadmin = true AND portal_role IS NULL")
            # Phase 76: Migrate support → poweradmin
            cursor.execute("UPDATE users SET portal_role = 'poweradmin' WHERE portal_role = 'support'")
            self.conn.commit()

        # 4. Add organization_id to discovery_runs
        cursor.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_org ON discovery_runs(organization_id)")
        cursor.execute("ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS cloud_connection_id INTEGER")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_connection ON discovery_runs(cloud_connection_id)")
        if default_org_id:
            cursor.execute("UPDATE discovery_runs SET organization_id = %s WHERE organization_id IS NULL", (default_org_id,))
        self.conn.commit()

        # 5. Add organization_id to settings + migrate PK
        cursor.execute("ALTER TABLE settings ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id)")
        if default_org_id:
            cursor.execute("UPDATE settings SET organization_id = %s WHERE organization_id IS NULL", (default_org_id,))
        # Migrate PK: drop old single-column PK, add composite unique
        try:
            cursor.execute("ALTER TABLE settings DROP CONSTRAINT IF EXISTS settings_pkey")
            cursor.execute("""
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'settings_org_key'
                    ) THEN
                        ALTER TABLE settings ADD CONSTRAINT settings_org_key UNIQUE (organization_id, key);
                    END IF;
                END $$
            """)
            self.conn.commit()
        except Exception:
            self.conn.rollback()

        cursor.close()
        Database._organizations_ensured = True

    # ── Organization CRUD ─────────────────────────────────────────────────────

    def get_organizations(self):
        """Get all organizations."""
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT o.*, (SELECT COUNT(*) FROM users u WHERE u.organization_id = o.id) AS user_count
            FROM organizations o ORDER BY o.id
        """)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for row in rows:
            for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
                if row.get(ts):
                    row[ts] = row[ts].isoformat()
        return rows

    def get_organization_by_id(self, organization_id):
        """Get a single organization by ID."""
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM organizations WHERE id = %s", (organization_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at', 'trial_expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        # Ensure Decimal fields are float for JSON serialization
        if result.get('tax_rate') is not None:
            result['tax_rate'] = float(result['tax_rate'])
        if result.get('discount_pct') is not None:
            result['discount_pct'] = float(result['discount_pct'])
        return result

    def get_organization_config(self, organization_id):
        """Get cloud provider and add-on configuration for an organization."""
        org = self.get_organization_by_id(organization_id)
        if not org:
            return None
        settings = org.get('settings') or {}
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
            'organization_id': organization_id,
            'org_name': org.get('name'),
            'cloud_providers': cloud_providers,
            'addons': addons,
        }

    def get_organization_by_slug(self, slug):
        """Get an organization by slug."""
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM organizations WHERE slug = %s", (slug,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def create_organization(self, name, slug, plan='free', settings=None,
                      primary_cloud=None, industry=None, compliance_framework=None):
        """Create a new organization."""
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO organizations (name, slug, plan, settings, primary_cloud, industry, compliance_framework)
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

    def update_organization(self, organization_id, **kwargs):
        """Update organization fields."""
        self._ensure_organizations_table()
        allowed = {'name', 'plan', 'enabled', 'settings', 'license_activated_at', 'license_expires_at',
                   'subscription_term', 'primary_cloud', 'industry', 'compliance_framework', 'status',
                   'onboarding_stage', 'platform_fee_cents', 'discount_pct', 'trial_expires_at',
                   'billing_status', 'tax_label', 'tax_rate', 'tax_id', 'tax_exempt', 'tax_notes',
                   'payment_terms', 'billing_company', 'billing_address_line1', 'billing_address_line2',
                   'billing_city', 'billing_state', 'billing_postal_code', 'billing_country', 'billing_email'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_organization_by_id(organization_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            params.append(json.dumps(v) if k == 'settings' else v)
        set_parts.append("updated_at = NOW()")
        params.append(organization_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE organizations SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'license_activated_at', 'license_expires_at', 'trial_expires_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def delete_organization(self, organization_id):
        """Delete an organization and all associated data using 7-tier cascade.

        Tier 1: Tables with non-CASCADE FK to users (created_by, attested_by, etc.)
        Tier 2: Tables with FK to playbooks/webhooks
        Tier 3: Standalone organization-scoped tables (no cross-table FK)
        Tier 4: risk_scores (FK to discovery_runs)
        Tier 5: discovery_runs — CASCADE auto-deletes identities + 11 children,
                 compliance_snapshots, azure_storage_accounts, azure_key_vaults,
                 app_registrations, anomalies, drift_reports, identity_subscription_access,
                 ca_policies
        Tier 6: users — CASCADE auto-deletes refresh_tokens, sso_auth_codes,
                 dashboard_preferences, saved_views
        Tier 7: settings, activity_log, organizations
        """
        self._ensure_organizations_table()
        cursor = self.conn.cursor()

        # Tier 1 — tables with non-CASCADE FK to users
        tier1_tables = [
            'campaign_audit_log', 'campaign_reviews', 'access_review_campaigns',
            'sa_attestations', 'governance_decisions', 'identity_group_members',
            'identity_groups', 'api_keys',
        ]
        for tbl in tier1_tables:
            try:
                cursor.execute(f"SAVEPOINT sp_{tbl}")
                cursor.execute(f"DELETE FROM {tbl} WHERE organization_id = %s", (organization_id,))
                cursor.execute(f"RELEASE SAVEPOINT sp_{tbl}")
            except Exception:
                cursor.execute(f"ROLLBACK TO SAVEPOINT sp_{tbl}")

        # Tier 2 — tables with FK to playbooks/webhooks
        tier2_tables = [
            'soar_actions', 'soar_playbooks', 'webhook_deliveries', 'webhooks',
        ]
        for tbl in tier2_tables:
            try:
                cursor.execute(f"SAVEPOINT sp_{tbl}")
                cursor.execute(f"DELETE FROM {tbl} WHERE organization_id = %s", (organization_id,))
                cursor.execute(f"RELEASE SAVEPOINT sp_{tbl}")
            except Exception:
                cursor.execute(f"ROLLBACK TO SAVEPOINT sp_{tbl}")

        # Tier 3 — standalone organization-scoped tables
        tier3_tables = [
            'notifications', 'custom_risk_rules', 'copilot_conversations',
            'remediation_actions', 'ca_policies', 'drift_reports',
            'cloud_subscriptions', 'cloud_connections', 'billing_events',
        ]
        for tbl in tier3_tables:
            try:
                cursor.execute(f"SAVEPOINT sp_{tbl}")
                cursor.execute(f"DELETE FROM {tbl} WHERE organization_id = %s", (organization_id,))
                cursor.execute(f"RELEASE SAVEPOINT sp_{tbl}")
            except Exception:
                cursor.execute(f"ROLLBACK TO SAVEPOINT sp_{tbl}")

        # Tier 4 — risk_scores (may not exist; keyed by run_id)
        try:
            cursor.execute("SAVEPOINT sp_risk_scores")
            cursor.execute("""
                DELETE FROM risk_scores
                WHERE run_id IN (SELECT id FROM discovery_runs WHERE organization_id = %s)
            """, (organization_id,))
            cursor.execute("RELEASE SAVEPOINT sp_risk_scores")
        except Exception:
            cursor.execute("ROLLBACK TO SAVEPOINT sp_risk_scores")

        # Tier 5 — discovery_runs (CASCADE deletes identities + 11 children,
        #           compliance_snapshots, azure_storage_accounts, azure_key_vaults,
        #           app_registrations, anomalies, drift_reports, identity_subscription_access,
        #           ca_policies)
        cursor.execute("DELETE FROM discovery_runs WHERE organization_id = %s", (organization_id,))

        # Tier 6 — users (CASCADE deletes refresh_tokens, sso_auth_codes,
        #           dashboard_preferences, saved_views)
        cursor.execute("DELETE FROM users WHERE organization_id = %s", (organization_id,))

        # Tier 7 — settings, activity_log, organizations
        cursor.execute("DELETE FROM settings WHERE organization_id = %s", (organization_id,))
        cursor.execute("DELETE FROM activity_log WHERE organization_id = %s", (organization_id,))
        cursor.execute("DELETE FROM organizations WHERE id = %s", (organization_id,))
        deleted = cursor.rowcount > 0

        self.conn.commit()
        cursor.close()
        return deleted

    # ── Phase 54: SSO Methods ──────────────────────────────────────────

    def get_user_by_external_id(self, external_id, organization_id):
        """Look up an SSO user by their IdP subject ID within an organization."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT u.*, o.name AS org_name, o.slug AS org_slug
            FROM users u
            LEFT JOIN organizations o ON o.id = u.organization_id
            WHERE u.external_id = %s AND u.organization_id = %s
        """, (external_id, organization_id))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def create_sso_user(self, username, display_name, role, organization_id, external_id):
        """Create SSO user with auth_provider='saml', no usable password."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO users (username, password_hash, display_name, role, organization_id,
                               auth_provider, external_id)
            VALUES (%s, %s, %s, %s, %s, 'saml', %s)
            RETURNING id, username, display_name, role, enabled, created_at, updated_at,
                      last_login_at, organization_id, is_superadmin, portal_role, auth_provider, external_id
        """, (username, '!sso-managed', display_name, role, organization_id, external_id))
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

    def create_sso_auth_code(self, user_id, organization_id):
        """Generate and store a one-time SSO auth code. Returns the raw code."""
        import secrets
        self._ensure_users_table()
        code = secrets.token_urlsafe(64)
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO sso_auth_codes (code, user_id, organization_id, expires_at)
            VALUES (%s, %s, %s, NOW() + INTERVAL '60 seconds')
        """, (code, user_id, organization_id))
        self.conn.commit()
        cursor.close()
        return code

    def consume_sso_auth_code(self, code):
        """Look up code, verify not expired/used, mark used. Returns {user_id, organization_id} or None."""
        self._ensure_users_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE sso_auth_codes
            SET used = true
            WHERE code = %s AND used = false AND expires_at > NOW()
            RETURNING user_id, organization_id
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
                organization_id INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_att_identity ON sa_attestations(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_att_org ON sa_attestations(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_att_attested ON sa_attestations(attested_at DESC)")
        self.conn.commit()
        cursor.close()
        Database._sa_attestations_ensured = True

    def create_sa_attestation(self, identity_id, identity_db_id, attested_by,
                              status, justification, interval_days=90, organization_id=None):
        """Insert a new attestation. Returns the created row."""
        self._ensure_sa_attestations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO sa_attestations
                (identity_id, identity_db_id, attested_by, status, justification,
                 attested_at, next_due, organization_id)
            VALUES (%s, %s, %s, %s, %s, NOW(),
                    NOW() + (%s || ' days')::INTERVAL, %s)
            RETURNING *
        """, (identity_id, identity_db_id, attested_by, status, justification,
              str(interval_days), organization_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return dict(row) if row else None

    def get_latest_attestation(self, identity_id, organization_id=None):
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
        if organization_id is not None:
            sql += " AND sa.organization_id = %s"
            params.append(organization_id)
        sql += " ORDER BY sa.attested_at DESC LIMIT 1"
        cursor.execute(sql, params)
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

    def get_attestations_for_identity(self, identity_id, organization_id=None):
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
        if organization_id is not None:
            sql += " AND sa.organization_id = %s"
            params.append(organization_id)
        sql += " ORDER BY sa.attested_at DESC"
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

    # ── Identity Governance V2: Decisions Table ──────────────────────

    _governance_decisions_ensured = False

    def _ensure_governance_decisions_table(self):
        if Database._governance_decisions_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS governance_decisions (
                id SERIAL PRIMARY KEY,
                identity_db_id INTEGER NOT NULL,
                identity_id TEXT NOT NULL,
                decision VARCHAR(50) NOT NULL,
                reason TEXT,
                risk_score_snapshot INTEGER,
                risk_band_snapshot VARCHAR(20),
                risk_factors_snapshot JSONB DEFAULT '[]',
                access_snapshot JSONB DEFAULT '[]',
                decided_by INTEGER NOT NULL REFERENCES users(id),
                exception_expiry TIMESTAMPTZ,
                organization_id INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_gov_dec_identity ON governance_decisions(identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_gov_dec_org ON governance_decisions(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_gov_dec_created ON governance_decisions(created_at DESC)")
        self.conn.commit()
        cursor.close()
        Database._governance_decisions_ensured = True

    def create_governance_decision(self, identity_id, identity_db_id, decision, reason,
                                   risk_score, risk_band, risk_factors, access_snapshot,
                                   decided_by, exception_expiry=None, organization_id=None):
        self._ensure_governance_decisions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO governance_decisions
                (identity_id, identity_db_id, decision, reason,
                 risk_score_snapshot, risk_band_snapshot, risk_factors_snapshot,
                 access_snapshot, decided_by, exception_expiry, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (identity_id, identity_db_id, decision, reason,
              risk_score, risk_band, json.dumps(risk_factors),
              json.dumps(access_snapshot), decided_by, exception_expiry, organization_id))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return dict(row) if row else None

    def get_latest_governance_decision(self, identity_id, organization_id=None):
        self._ensure_governance_decisions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        sql = """
            SELECT gd.*, u.display_name as reviewer_name
            FROM governance_decisions gd
            LEFT JOIN users u ON u.id = gd.decided_by
            WHERE gd.identity_id = %s
        """
        params = [identity_id]
        if organization_id is not None:
            sql += " AND gd.organization_id = %s"
            params.append(organization_id)
        sql += " ORDER BY gd.created_at DESC LIMIT 1"
        cursor.execute(sql, params)
        row = cursor.fetchone()
        cursor.close()
        return dict(row) if row else None

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

    # ─── RBAC Hygiene Methods ────────────────────────────────────────

    def save_rbac_hygiene_scan(self, result: dict, run_id=None) -> int:
        """Persist an RBAC hygiene scan result (v2 with exposure/executive/drift)."""
        _ensure_rbac_hygiene_table(self.conn)
        cursor = self.conn.cursor()
        import json as _json
        summary = {
            'by_rule': result.get('by_rule', {}),
            'by_severity': result.get('by_severity', {}),
            'grade': result.get('grade', 'F'),
            'exposure_index': result.get('exposure_index', {}),
            'tier_distribution': result.get('tier_distribution', {}),
            'executive': result.get('executive', {}),
            'drift': result.get('drift', {}),
        }
        cursor.execute("""
            INSERT INTO rbac_hygiene_scans
                (score, grade, total_assignments, total_findings, summary, findings,
                 discovery_run_id, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            result.get('score', 0),
            result.get('grade', 'F'),
            result.get('total_assignments', 0),
            result.get('total_findings', 0),
            _json.dumps(summary),
            _json.dumps(result.get('findings', [])),
            run_id,
            self._organization_id or 0,
        ))
        scan_id = cursor.fetchone()[0]
        self.conn.commit()
        cursor.close()
        return scan_id

    def get_rbac_hygiene_latest(self) -> dict:
        """Get the most recent RBAC hygiene scan result."""
        _ensure_rbac_hygiene_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, score, grade, total_assignments, total_findings,
                   summary, findings, discovery_run_id, created_at
            FROM rbac_hygiene_scans
            ORDER BY created_at DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return {}
        return dict(row)

    def get_rbac_hygiene_history(self, limit=10) -> list:
        """Get RBAC hygiene scan history (summary only, no findings)."""
        _ensure_rbac_hygiene_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, score, grade, total_assignments, total_findings,
                   summary, created_at
            FROM rbac_hygiene_scans
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

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
                organization_id INT,
                title TEXT,
                messages JSONB DEFAULT '[]'::jsonb,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        # RLS policies for organization isolation (idempotent)
        cursor.execute("ALTER TABLE copilot_conversations ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE copilot_conversations FORCE ROW LEVEL SECURITY")
        for policy_stmt in [
            "CREATE POLICY org_strict_sel ON copilot_conversations FOR SELECT USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
            "CREATE POLICY org_strict_ins ON copilot_conversations FOR INSERT WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer)",
            "CREATE POLICY org_strict_upd ON copilot_conversations FOR UPDATE USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
            "CREATE POLICY org_strict_del ON copilot_conversations FOR DELETE USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
        ]:
            cursor.execute("SAVEPOINT rls_policy")
            try:
                cursor.execute(policy_stmt)
                cursor.execute("RELEASE SAVEPOINT rls_policy")
            except Exception:
                cursor.execute("ROLLBACK TO SAVEPOINT rls_policy")
        self.conn.commit()
        cursor.close()
        Database._copilot_ensured = True

    def create_copilot_conversation(self, user_id, organization_id, title, messages=None):
        self._ensure_copilot_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO copilot_conversations (user_id, organization_id, title, messages)
            VALUES (%s, %s, %s, %s) RETURNING id, title, messages, created_at, updated_at
        """, (user_id, organization_id, title, json.dumps(messages or [])))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        return row

    def get_copilot_conversation(self, conv_id, user_id):
        self._ensure_copilot_tables()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, user_id, organization_id, title, messages, created_at, updated_at
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
    # Cloud Connections (multi-directory / multi-cloud)
    # ================================================================

    _cloud_connections_ensured = False

    def _ensure_cloud_connections_table(self):
        """Create cloud_connections table for multi-Entra / multi-cloud support."""
        if Database._cloud_connections_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_connections (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                cloud VARCHAR(20) NOT NULL DEFAULT 'azure',
                connection_type VARCHAR(30) NOT NULL DEFAULT 'entra',
                label VARCHAR(255) NOT NULL,
                azure_directory_id VARCHAR(100),
                client_id VARCHAR(100),
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                display_order INTEGER NOT NULL DEFAULT 0,
                last_test_at TIMESTAMPTZ,
                last_test_status VARCHAR(20),
                last_discovery_at TIMESTAMPTZ,
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(organization_id, cloud, azure_directory_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_conn_org ON cloud_connections(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_conn_cloud ON cloud_connections(cloud)")
        # RLS policies for organization isolation (idempotent)
        cursor.execute("ALTER TABLE cloud_connections ENABLE ROW LEVEL SECURITY")
        cursor.execute("ALTER TABLE cloud_connections FORCE ROW LEVEL SECURITY")
        for policy_stmt in [
            "CREATE POLICY org_strict_sel ON cloud_connections FOR SELECT USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
            "CREATE POLICY org_strict_ins ON cloud_connections FOR INSERT WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer)",
            "CREATE POLICY org_strict_upd ON cloud_connections FOR UPDATE USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
            "CREATE POLICY org_strict_del ON cloud_connections FOR DELETE USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
        ]:
            cursor.execute("SAVEPOINT rls_policy")
            try:
                cursor.execute(policy_stmt)
                cursor.execute("RELEASE SAVEPOINT rls_policy")
            except Exception:
                cursor.execute("ROLLBACK TO SAVEPOINT rls_policy")
        self.conn.commit()
        cursor.close()
        Database._cloud_connections_ensured = True

    def create_cloud_connection(self, organization_id, cloud, label, azure_directory_id=None,
                                 client_id=None, connection_type='entra', metadata=None):
        """Create a new cloud connection for an organization."""
        self._ensure_cloud_connections_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        # Auto-assign display_order
        cursor.execute("SELECT COALESCE(MAX(display_order), -1) + 1 AS next_order FROM cloud_connections WHERE organization_id = %s", (organization_id,))
        next_order = cursor.fetchone()['next_order']
        cursor.execute("""
            INSERT INTO cloud_connections (organization_id, cloud, connection_type, label, azure_directory_id,
                                           client_id, status, display_order, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s, %s)
            ON CONFLICT (organization_id, cloud, azure_directory_id) DO UPDATE
              SET label = EXCLUDED.label, client_id = EXCLUDED.client_id,
                  updated_at = NOW()
            RETURNING *
        """, (organization_id, cloud, connection_type, label, azure_directory_id,
              client_id, next_order, json.dumps(metadata or {})))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_test_at', 'last_discovery_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def get_cloud_connections(self, organization_id, cloud=None, include_secrets=False):
        """Get all cloud connections for an organization, with computed sub/identity counts.
        Set include_secrets=True to keep client_secret in metadata (for scheduler use).
        """
        self._ensure_cloud_connections_table()
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = """
            SELECT cc.*,
                COALESCE((SELECT COUNT(*) FROM cloud_subscriptions cs
                          WHERE cs.cloud_connection_id = cc.id AND cs.monitored = true), 0) AS sub_count,
                COALESCE((SELECT COUNT(*) FROM cloud_subscriptions cs
                          WHERE cs.cloud_connection_id = cc.id AND cs.monitored = false), 0) AS discovered_count
            FROM cloud_connections cc
            WHERE cc.organization_id = %s
        """
        params: list = [organization_id]
        if cloud:
            query += " AND cc.cloud = %s"
            params.append(cloud)
        query += " ORDER BY cc.display_order, cc.created_at"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for row in rows:
            for ts in ('created_at', 'updated_at', 'last_test_at', 'last_discovery_at'):
                if row.get(ts):
                    row[ts] = row[ts].isoformat()
            if not include_secrets:
                # Strip sensitive metadata from response
                meta = row.get('metadata') or {}
                if isinstance(meta, dict):
                    meta.pop('client_secret', None)
                    row['metadata'] = meta
        return rows

    def get_cloud_connection_by_id(self, connection_id):
        """Get a single cloud connection by ID."""
        self._ensure_cloud_connections_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if self._organization_id is not None:
            cursor.execute("SELECT * FROM cloud_connections WHERE id = %s AND organization_id = %s", (connection_id, self._organization_id))
        else:
            cursor.execute("SELECT * FROM cloud_connections WHERE id = %s", (connection_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_test_at', 'last_discovery_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def update_cloud_connection(self, connection_id, **kwargs):
        """Update a cloud connection."""
        self._ensure_cloud_connections_table()
        allowed = {'label', 'status', 'display_order', 'last_test_at', 'last_test_status',
                   'last_discovery_at', 'metadata', 'azure_directory_id', 'client_id'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_cloud_connection_by_id(connection_id)
        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = %s")
            params.append(json.dumps(v) if k == 'metadata' else v)
        set_parts.append("updated_at = NOW()")
        params.append(connection_id)
        if self._organization_id is not None:
            params.append(self._organization_id)
            org_clause = " AND organization_id = %s"
        else:
            org_clause = ""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE cloud_connections SET {', '.join(set_parts)}
            WHERE id = %s{org_clause} RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        result = dict(row)
        for ts in ('created_at', 'updated_at', 'last_test_at', 'last_discovery_at'):
            if result.get(ts):
                result[ts] = result[ts].isoformat()
        return result

    def delete_cloud_connection(self, connection_id, organization_id=None):
        """Delete a cloud connection. Optionally verify organization ownership."""
        self._ensure_cloud_connections_table()
        cursor = self.conn.cursor()
        if organization_id:
            cursor.execute("DELETE FROM cloud_connections WHERE id = %s AND organization_id = %s", (connection_id, organization_id))
        else:
            cursor.execute("DELETE FROM cloud_connections WHERE id = %s", (connection_id,))
        deleted = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return deleted > 0

    # ================================================================
    # Cloud Subscriptions (per-account monitoring)
    # ================================================================

    _cloud_subscriptions_ensured = False

    def _ensure_cloud_subscriptions_table(self):
        """Create cloud_subscriptions table if it doesn't exist."""
        if Database._cloud_subscriptions_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_subscriptions (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                cloud VARCHAR(20) NOT NULL,
                account_id VARCHAR(255) NOT NULL,
                account_name VARCHAR(500),
                status VARCHAR(20) DEFAULT 'discovered',
                monitored BOOLEAN DEFAULT false,
                activated_at TIMESTAMPTZ,
                activated_by INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(organization_id, cloud, account_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_subs_org ON cloud_subscriptions(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_subs_cloud ON cloud_subscriptions(cloud)")
        # Billing columns
        cursor.execute("ALTER TABLE cloud_subscriptions ADD COLUMN IF NOT EXISTS rate_cents INTEGER NOT NULL DEFAULT 6900")
        cursor.execute("ALTER TABLE cloud_subscriptions ADD COLUMN IF NOT EXISTS discovered_at TIMESTAMPTZ DEFAULT NOW()")
        cursor.execute("ALTER TABLE cloud_subscriptions ADD COLUMN IF NOT EXISTS cloud_connection_id INTEGER")
        # Backfill rates by cloud
        cursor.execute("UPDATE cloud_subscriptions SET rate_cents = 7900 WHERE cloud = 'aws' AND rate_cents = 6900")
        cursor.execute("UPDATE cloud_subscriptions SET rate_cents = 7400 WHERE cloud = 'gcp' AND rate_cents = 6900")
        self.conn.commit()
        cursor.close()
        Database._cloud_subscriptions_ensured = True

    def sync_cloud_subscriptions(self, organization_id=None):
        """Backfill cloud_subscriptions from discovery data if empty.

        Sources: identity_subscription_access (individual rows) and
        discovery_runs (comma-separated fallback). Only runs when the
        table has no rows for the given organization.
        """
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor()

        # Check if any records already exist
        if organization_id is not None and organization_id > 0:
            cursor.execute("SELECT COUNT(*) FROM cloud_subscriptions WHERE organization_id = %s", (organization_id,))
        else:
            cursor.execute("SELECT COUNT(*) FROM cloud_subscriptions")
        if cursor.fetchone()[0] > 0:
            cursor.close()
            return  # Already populated

        # Source 1: identity_subscription_access (clean individual records)
        if organization_id is not None and organization_id > 0:
            cursor.execute("""
                SELECT DISTINCT isa.subscription_id, isa.subscription_name, dr.organization_id
                FROM identity_subscription_access isa
                JOIN discovery_runs dr ON dr.id = isa.discovery_run_id
                WHERE dr.organization_id = %s
                  AND isa.subscription_id IS NOT NULL AND isa.subscription_id != ''
            """, (organization_id,))
        else:
            cursor.execute("""
                SELECT DISTINCT isa.subscription_id, isa.subscription_name, dr.organization_id
                FROM identity_subscription_access isa
                JOIN discovery_runs dr ON dr.id = isa.discovery_run_id
                WHERE isa.subscription_id IS NOT NULL AND isa.subscription_id != ''
            """)
        isa_rows = cursor.fetchall()

        inserted = set()
        for row in isa_rows:
            sub_id, sub_name, run_tid = row[0], row[1], row[2]
            effective_tid = run_tid or (organization_id if organization_id and organization_id > 0 else 1)
            key = (effective_tid, sub_id)
            if key in inserted:
                continue
            try:
                cursor.execute("""
                    INSERT INTO cloud_subscriptions (organization_id, cloud, account_id, account_name, status)
                    VALUES (%s, 'azure', %s, %s, 'discovered')
                    ON CONFLICT (organization_id, cloud, account_id) DO NOTHING
                """, (effective_tid, sub_id, sub_name or sub_id))
                inserted.add(key)
            except Exception:
                self.conn.rollback()

        # Source 2: discovery_runs fallback (comma-separated subscription_ids)
        if not inserted:
            if organization_id is not None and organization_id > 0:
                cursor.execute("""
                    SELECT DISTINCT subscription_id, subscription_name, organization_id
                    FROM discovery_runs
                    WHERE organization_id = %s AND subscription_id IS NOT NULL AND subscription_id != ''
                """, (organization_id,))
            else:
                cursor.execute("""
                    SELECT DISTINCT subscription_id, subscription_name, organization_id
                    FROM discovery_runs
                    WHERE subscription_id IS NOT NULL AND subscription_id != ''
                """)
            for row in cursor.fetchall():
                sub_ids = row[0].split(',')
                sub_names = (row[1] or '').split(', ')
                run_tid = row[2] or (organization_id if organization_id and organization_id > 0 else 1)
                for i, sid in enumerate(sub_ids):
                    sid = sid.strip()
                    if not sid:
                        continue
                    sname = sub_names[i].strip() if i < len(sub_names) else sid
                    key = (run_tid, sid)
                    if key in inserted:
                        continue
                    try:
                        cursor.execute("""
                            INSERT INTO cloud_subscriptions (organization_id, cloud, account_id, account_name, status)
                            VALUES (%s, 'azure', %s, %s, 'discovered')
                            ON CONFLICT (organization_id, cloud, account_id) DO NOTHING
                        """, (run_tid, sid, sname))
                        inserted.add(key)
                    except Exception:
                        self.conn.rollback()

        self.conn.commit()
        cursor.close()

    def insert_discovered_subscriptions(self, organization_id, cloud, connection_id, subs_list):
        """Insert discovered subscriptions for a connection.
        subs_list: list of {'id': sub_id, 'name': display_name}
        Returns count of inserted rows.
        """
        self._ensure_cloud_subscriptions_table()
        if not subs_list:
            return 0
        cursor = self.conn.cursor()
        inserted = 0
        rate = 6900 if cloud == 'azure' else (7900 if cloud == 'aws' else 7400)
        for sub in subs_list:
            sub_id = sub.get('id', '').strip()
            sub_name = sub.get('name', sub_id)
            if not sub_id:
                continue
            try:
                cursor.execute("""
                    INSERT INTO cloud_subscriptions
                        (organization_id, cloud, account_id, account_name, status, cloud_connection_id, rate_cents)
                    VALUES (%s, %s, %s, %s, 'discovered', %s, %s)
                    ON CONFLICT (organization_id, cloud, account_id)
                    DO UPDATE SET cloud_connection_id = EXCLUDED.cloud_connection_id,
                                  account_name = COALESCE(EXCLUDED.account_name, cloud_subscriptions.account_name)
                """, (organization_id, cloud, sub_id, sub_name, connection_id, rate))
                inserted += 1
            except Exception:
                self.conn.rollback()
        self.conn.commit()
        cursor.close()
        return inserted

    def get_cloud_subscriptions(self, organization_id, cloud=None):
        """List cloud subscriptions for an organization with connection_label. None = superadmin (all)."""
        self._ensure_cloud_subscriptions_table()
        self._ensure_cloud_connections_table()
        self.sync_cloud_subscriptions(organization_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            query = """SELECT cs.*, cc.label AS connection_label
                       FROM cloud_subscriptions cs
                       LEFT JOIN cloud_connections cc ON cc.id = cs.cloud_connection_id
                       WHERE cs.organization_id = %s"""
            params: list = [organization_id]
        else:
            query = """SELECT cs.*, cc.label AS connection_label
                       FROM cloud_subscriptions cs
                       LEFT JOIN cloud_connections cc ON cc.id = cs.cloud_connection_id
                       WHERE 1=1"""
            params = []
        if cloud:
            query += " AND cs.cloud = %s"
            params.append(cloud)
        query += " ORDER BY cs.cloud, cs.account_name"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            for ts in ('activated_at', 'created_at', 'discovered_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def get_subscription_stats(self, organization_id):
        """Summary counts for cloud subscriptions. None = superadmin (all)."""
        self._ensure_cloud_subscriptions_table()
        self.sync_cloud_subscriptions(organization_id)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE monitored = true) as active,
                    COUNT(*) FILTER (WHERE monitored = false) as discovered,
                    COUNT(DISTINCT cloud) as clouds
                FROM cloud_subscriptions
                WHERE organization_id = %s
            """, (organization_id,))
        else:
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE monitored = true) as active,
                    COUNT(*) FILTER (WHERE monitored = false) as discovered,
                    COUNT(DISTINCT cloud) as clouds
                FROM cloud_subscriptions
            """)
        row = dict(cursor.fetchone())
        cursor.close()
        return row

    def activate_cloud_subscription(self, sub_id, user_id, organization_id=None):
        """Activate a subscription for monitoring, scoped by organization."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                UPDATE cloud_subscriptions
                SET monitored = true, status = 'active', activated_at = NOW(), activated_by = %s
                WHERE id = %s AND organization_id = %s
                RETURNING *
            """, (user_id, sub_id, organization_id))
        else:
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

    def activate_all_cloud_subscriptions(self, user_id, organization_id=None):
        """Activate all discovered (unmonitored) subscriptions for an organization."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                UPDATE cloud_subscriptions
                SET monitored = true, status = 'active', activated_at = NOW(), activated_by = %s
                WHERE organization_id = %s AND monitored = false
                RETURNING *
            """, (user_id, organization_id))
        else:
            cursor.execute("""
                UPDATE cloud_subscriptions
                SET monitored = true, status = 'active', activated_at = NOW(), activated_by = %s
                WHERE monitored = false
                RETURNING *
            """, (user_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        self.conn.commit()
        cursor.close()
        for r in rows:
            for ts in ('activated_at', 'created_at'):
                if r.get(ts):
                    r[ts] = r[ts].isoformat()
        return rows

    def deactivate_cloud_subscription(self, sub_id, organization_id=None):
        """Stop monitoring a subscription, scoped by organization."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        if organization_id is not None:
            cursor.execute("""
                UPDATE cloud_subscriptions
                SET monitored = false, status = 'inactive'
                WHERE id = %s AND organization_id = %s
                RETURNING *
            """, (sub_id, organization_id))
        else:
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
    # Billing Events (audit trail for billing changes)
    # ================================================================

    _billing_events_ensured = False

    def _ensure_billing_events_table(self):
        """Create billing_events table if it doesn't exist."""
        if Database._billing_events_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS billing_events (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                event_type VARCHAR(50) NOT NULL,
                field_changed VARCHAR(50),
                old_value TEXT,
                new_value TEXT,
                changed_by INTEGER,
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_billing_events_org ON billing_events(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_billing_events_created ON billing_events(created_at DESC)")
        self.conn.commit()
        cursor.close()
        Database._billing_events_ensured = True

    def log_billing_event(self, organization_id, event_type, field_changed=None,
                          old_value=None, new_value=None, changed_by=None, metadata=None):
        """Insert a billing event and return it."""
        self._ensure_billing_events_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO billing_events (organization_id, event_type, field_changed, old_value, new_value, changed_by, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (organization_id, event_type, field_changed,
              str(old_value) if old_value is not None else None,
              str(new_value) if new_value is not None else None,
              changed_by, json.dumps(metadata or {})))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        if row.get('created_at'):
            row['created_at'] = row['created_at'].isoformat()
        return row

    def get_billing_events(self, organization_id=None, limit=50, offset=0):
        """Get billing events with organization name JOIN. Optionally filter by org."""
        self._ensure_billing_events_table()
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = """
            SELECT be.*, o.name as org_name
            FROM billing_events be
            JOIN organizations o ON o.id = be.organization_id
        """
        params = []
        if organization_id is not None:
            query += " WHERE be.organization_id = %s"
            params.append(organization_id)
        query += " ORDER BY be.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            if r.get('created_at'):
                r['created_at'] = r['created_at'].isoformat()
        return rows

    def update_cloud_subscription_rate(self, organization_id, cloud, rate_cents):
        """Update per-subscription rate for all subs of a given cloud for an organization."""
        self._ensure_cloud_subscriptions_table()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE cloud_subscriptions SET rate_cents = %s
            WHERE organization_id = %s AND cloud = %s
        """, (rate_cents, organization_id, cloud))
        updated = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return updated

    # ================================================================
    # Phase 6: Scan Schedules
    # ================================================================

    def _ensure_scan_schedules(self):
        _ensure_scan_schedules_table(self.conn)

    def get_scan_schedules(self, organization_id):
        """Get all scan schedules for an organization."""
        self._ensure_scan_schedules()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT s.*, c.label as connection_label, c.cloud
            FROM scan_schedules s
            LEFT JOIN cloud_connections c ON c.id = s.connection_id
            WHERE s.organization_id = %s
            ORDER BY s.created_at DESC
        """, (organization_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

    def create_scan_schedule(self, organization_id, connection_id, label, frequency,
                             cron_expression, next_run_at, created_by):
        """Create a new scan schedule."""
        self._ensure_scan_schedules()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO scan_schedules
            (organization_id, connection_id, label, frequency, cron_expression,
             next_run_at, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (organization_id, connection_id, label, frequency, cron_expression,
              next_run_at, created_by))
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return dict(row) if row else None

    def update_scan_schedule(self, schedule_id, organization_id, **kwargs):
        """Update a scan schedule."""
        self._ensure_scan_schedules()
        allowed = {'label', 'frequency', 'cron_expression', 'next_run_at', 'enabled', 'connection_id'}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return None
        set_clause = ', '.join(f'{k} = %s' for k in updates)
        values = list(updates.values()) + [schedule_id, organization_id]
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(f"""
            UPDATE scan_schedules SET {set_clause}, updated_at = NOW()
            WHERE id = %s AND organization_id = %s
            RETURNING *
        """, values)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        return dict(row) if row else None

    def delete_scan_schedule(self, schedule_id, organization_id):
        """Delete a scan schedule."""
        self._ensure_scan_schedules()
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM scan_schedules WHERE id = %s AND organization_id = %s",
            (schedule_id, organization_id))
        deleted = cursor.rowcount
        self.conn.commit()
        cursor.close()
        return deleted > 0

    def get_due_scan_schedules(self):
        """Get all enabled schedules that are due (admin connection, no RLS)."""
        self._ensure_scan_schedules()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT s.*, o.name as org_name
            FROM scan_schedules s
            JOIN organizations o ON o.id = s.organization_id
            WHERE s.enabled = true AND s.next_run_at <= NOW()
            ORDER BY s.next_run_at ASC
        """)
        rows = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in rows]

    def mark_scan_schedule_run(self, schedule_id, status, next_run_at):
        """Update schedule after a run completes."""
        self._ensure_scan_schedules()
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE scan_schedules
            SET last_run_at = NOW(), last_run_status = %s,
                next_run_at = %s, updated_at = NOW()
            WHERE id = %s
        """, (status, next_run_at, schedule_id))
        self.conn.commit()
        cursor.close()

    # ================================================================
    # Platform Settings (seller info for invoices)
    # ================================================================

    _platform_settings_ensured = False

    def _ensure_platform_settings_table(self):
        """Create platform_settings table if it doesn't exist."""
        if Database._platform_settings_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS platform_settings (
                key VARCHAR(100) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        # Seed defaults
        for k, v in [
            ('company_name', 'AuditGraph Inc.'),
            ('company_address', ''),
            ('company_email', ''),
            ('company_phone', ''),
            ('company_tax_id', ''),
            ('invoice_prefix', 'AG'),
            ('invoice_footer', 'Thank you for your business.'),
            ('logo_url', ''),
        ]:
            cursor.execute("""
                INSERT INTO platform_settings (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO NOTHING
            """, (k, v))
        self.conn.commit()
        cursor.close()
        Database._platform_settings_ensured = True

    def get_platform_settings(self):
        """Get all platform settings as a dict."""
        self._ensure_platform_settings_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT key, value FROM platform_settings")
        rows = cursor.fetchall()
        cursor.close()
        return {r['key']: r['value'] for r in rows}

    def update_platform_settings(self, data):
        """Update platform settings from a dict of key→value pairs."""
        self._ensure_platform_settings_table()
        allowed = {'company_name', 'company_address', 'company_email', 'company_phone',
                   'company_tax_id', 'invoice_prefix', 'invoice_footer', 'logo_url'}
        cursor = self.conn.cursor()
        for k, v in data.items():
            if k in allowed:
                cursor.execute("""
                    INSERT INTO platform_settings (key, value, updated_at) VALUES (%s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                """, (k, str(v) if v is not None else ''))
        self.conn.commit()
        cursor.close()

    # ================================================================
    # Invoices
    # ================================================================

    _invoices_ensured = False

    def _ensure_invoices_table(self):
        """Create invoices table if it doesn't exist."""
        if Database._invoices_ensured:
            return
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL REFERENCES organizations(id),
                invoice_number VARCHAR(50) UNIQUE NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'draft',
                period_start DATE NOT NULL,
                period_end DATE NOT NULL,
                subtotal_cents INTEGER NOT NULL DEFAULT 0,
                tax_label VARCHAR(50),
                tax_rate DECIMAL(5,2) NOT NULL DEFAULT 0,
                tax_amount_cents INTEGER NOT NULL DEFAULT 0,
                discount_cents INTEGER NOT NULL DEFAULT 0,
                total_cents INTEGER NOT NULL DEFAULT 0,
                line_items JSONB NOT NULL DEFAULT '[]',
                seller_snapshot JSONB NOT NULL DEFAULT '{}',
                buyer_snapshot JSONB NOT NULL DEFAULT '{}',
                issued_at TIMESTAMPTZ,
                due_at TIMESTAMPTZ,
                paid_at TIMESTAMPTZ,
                voided_at TIMESTAMPTZ,
                notes TEXT,
                payment_terms INTEGER NOT NULL DEFAULT 30,
                created_by INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_invoices_org ON invoices(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_invoices_number ON invoices(invoice_number)")
        cursor.execute("ALTER TABLE invoices ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64)")
        self.conn.commit()
        cursor.close()
        Database._invoices_ensured = True

    def get_next_invoice_number(self, prefix='AG'):
        """Generate next sequential invoice number like AG-2026-0001."""
        self._ensure_invoices_table()
        from datetime import datetime
        year = datetime.now().year
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT invoice_number FROM invoices
            WHERE invoice_number LIKE %s
            ORDER BY invoice_number DESC LIMIT 1
        """, (f'{prefix}-{year}-%',))
        row = cursor.fetchone()
        cursor.close()
        if row:
            try:
                seq = int(row[0].split('-')[-1]) + 1
            except (ValueError, IndexError):
                seq = 1
        else:
            seq = 1
        return f'{prefix}-{year}-{seq:04d}'

    def create_invoice(self, organization_id, invoice_number, period_start, period_end,
                       subtotal_cents, tax_label, tax_rate, tax_amount_cents,
                       discount_cents, total_cents, line_items, seller_snapshot,
                       buyer_snapshot, due_at, notes, payment_terms, created_by,
                       content_hash=None):
        """Create a new invoice and return it."""
        self._ensure_invoices_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            INSERT INTO invoices (
                organization_id, invoice_number, period_start, period_end,
                subtotal_cents, tax_label, tax_rate, tax_amount_cents,
                discount_cents, total_cents, line_items, seller_snapshot,
                buyer_snapshot, issued_at, due_at, notes, payment_terms, created_by,
                content_hash
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s, %s)
            RETURNING *
        """, (organization_id, invoice_number, period_start, period_end,
              subtotal_cents, tax_label, tax_rate, tax_amount_cents,
              discount_cents, total_cents, json.dumps(line_items), json.dumps(seller_snapshot),
              json.dumps(buyer_snapshot), due_at, notes, payment_terms, created_by,
              content_hash))
        row = dict(cursor.fetchone())
        self.conn.commit()
        cursor.close()
        return self._serialize_invoice(row)

    def get_invoices(self, organization_id=None, status=None, limit=50, offset=0):
        """Get invoices with organization name JOIN. Optionally filter by org and status."""
        self._ensure_invoices_table()
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        query = """
            SELECT inv.*, o.name as org_name
            FROM invoices inv
            JOIN organizations o ON o.id = inv.organization_id
            WHERE 1=1
        """
        params = []
        if organization_id is not None:
            query += " AND inv.organization_id = %s"
            params.append(organization_id)
        if status:
            query += " AND inv.status = %s"
            params.append(status)
        query += " ORDER BY inv.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return [self._serialize_invoice(r) for r in rows]

    def get_invoice_by_id(self, invoice_id):
        """Get a single invoice by ID with organization name."""
        self._ensure_invoices_table()
        self._ensure_organizations_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT inv.*, o.name as org_name
            FROM invoices inv
            JOIN organizations o ON o.id = inv.organization_id
            WHERE inv.id = %s
        """, (invoice_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            return None
        return self._serialize_invoice(dict(row))

    def update_invoice_status(self, invoice_id, status, paid_at=None, voided_at=None):
        """Update invoice status and optional timestamp fields.

        IMMUTABILITY GUARD: Only status/timestamp fields are modified here.
        Financial fields (subtotal, tax, total, line_items, snapshots, content_hash)
        are NEVER modified after creation. content_hash validates this invariant.
        """
        self._ensure_invoices_table()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        set_parts = ["status = %s", "updated_at = NOW()"]
        params = [status]
        if paid_at:
            set_parts.append("paid_at = %s")
            params.append(paid_at)
        if voided_at:
            set_parts.append("voided_at = %s")
            params.append(voided_at)
        params.append(invoice_id)
        cursor.execute(f"""
            UPDATE invoices SET {', '.join(set_parts)}
            WHERE id = %s RETURNING *
        """, params)
        row = cursor.fetchone()
        self.conn.commit()
        cursor.close()
        if not row:
            return None
        return self._serialize_invoice(dict(row))

    def _serialize_invoice(self, row):
        """Serialize an invoice row for JSON response."""
        for ts in ('created_at', 'updated_at', 'issued_at', 'due_at', 'paid_at', 'voided_at'):
            if row.get(ts):
                row[ts] = row[ts].isoformat() if hasattr(row[ts], 'isoformat') else row[ts]
        for dt in ('period_start', 'period_end'):
            if row.get(dt):
                row[dt] = row[dt].isoformat() if hasattr(row[dt], 'isoformat') else row[dt]
        if row.get('tax_rate') is not None:
            row['tax_rate'] = float(row['tax_rate'])
        return row

    def verify_invoice_integrity(self, invoice_id):
        """Verify invoice content hash matches recomputed hash."""
        from app.pricing import compute_invoice_hash
        invoice = self.get_invoice_by_id(invoice_id)
        if not invoice:
            return None
        stored_hash = invoice.get('content_hash')
        if not stored_hash:
            return {'verified': False, 'reason': 'No content hash stored', 'invoice_id': invoice_id}
        computed_hash = compute_invoice_hash(invoice)
        return {
            'verified': stored_hash == computed_hash,
            'content_hash': stored_hash,
            'computed_hash': computed_hash,
            'invoice_id': invoice_id,
            'invoice_number': invoice.get('invoice_number'),
        }

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
        cursor.execute("ALTER TABLE identity_subscription_access ADD COLUMN IF NOT EXISTS organization_id INTEGER")
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
                 rbac_role, scope, scope_type, risk_level, discovery_run_id,
                 organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            self._organization_id,
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

    # ─── SPN Exposure Intelligence ──────────────────────────────────

    def _ensure_spn_exposure(self):
        """Add exposure columns to identities + create spn_exposure_findings table."""
        if Database._spn_exposure_ensured:
            return
        cursor = self.conn.cursor()
        try:
            # 17 new columns on identities
            exposure_cols = [
                ('exposure_score', 'INTEGER DEFAULT 0'),
                ('exposure_components', "JSONB DEFAULT '{}'::jsonb"),
                ('privilege_score', 'INTEGER DEFAULT 0'),
                ('credential_risk_score', 'INTEGER DEFAULT 0'),
                ('exposure_subscore', 'INTEGER DEFAULT 0'),
                ('lifecycle_score', 'INTEGER DEFAULT 0'),
                ('visibility_score', 'INTEGER DEFAULT 0'),
                ('activity_confidence', 'INTEGER DEFAULT 0'),
                ('lifecycle_state', "VARCHAR(20) DEFAULT 'blind'"),
                ('can_escalate', 'BOOLEAN DEFAULT FALSE'),
                ('effective_scope_flag', "VARCHAR(30) DEFAULT 'resource'"),
                ('credential_age_days', 'INTEGER DEFAULT 0'),
                ('owner_status', "VARCHAR(20) DEFAULT 'unknown'"),
                ('federated_trust', 'BOOLEAN DEFAULT FALSE'),
                ('cross_subscription', 'BOOLEAN DEFAULT FALSE'),
                ('exposure_computed_at', 'TIMESTAMP'),
                ('critical_exposure_overrides', "JSONB DEFAULT '[]'::jsonb"),
            ]
            for col, coltype in exposure_cols:
                cursor.execute("SAVEPOINT sp_col")
                try:
                    cursor.execute(f"ALTER TABLE identities ADD COLUMN IF NOT EXISTS {col} {coltype}")
                except Exception:
                    cursor.execute("ROLLBACK TO SAVEPOINT sp_col")

            # spn_exposure_findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS spn_exposure_findings (
                    id SERIAL PRIMARY KEY,
                    identity_db_id BIGINT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
                    finding_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence JSONB DEFAULT '{}',
                    remediation TEXT,
                    component VARCHAR(30),
                    score_impact INTEGER DEFAULT 0,
                    organization_id INTEGER NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_spn_findings_identity ON spn_exposure_findings(identity_db_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_spn_findings_run ON spn_exposure_findings(discovery_run_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_spn_findings_org ON spn_exposure_findings(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_spn_findings_severity ON spn_exposure_findings(severity)")
            self.conn.commit()
            Database._spn_exposure_ensured = True
        except Exception as e:
            self.conn.rollback()
            if self._organization_id:
                self.set_organization_context(self._organization_id)
            print(f"  ⚠️ SPN exposure schema error: {e}")
        finally:
            cursor.close()

    def save_spn_exposure(self, identity_db_id, exposure_data, findings, run_id):
        """Save computed exposure data: UPDATE identities + INSERT findings."""
        self._ensure_spn_exposure()
        cursor = self.conn.cursor()
        try:
            scores = exposure_data.get('scores', {})
            flags = exposure_data.get('flags', {})
            activity = exposure_data.get('activity_inference', {})
            overrides = exposure_data.get('critical_overrides', [])

            import json as _json
            cursor.execute("""
                UPDATE identities SET
                    exposure_score = %s,
                    exposure_components = %s,
                    privilege_score = %s,
                    credential_risk_score = %s,
                    exposure_subscore = %s,
                    lifecycle_score = %s,
                    visibility_score = %s,
                    activity_confidence = %s,
                    lifecycle_state = %s,
                    can_escalate = %s,
                    effective_scope_flag = %s,
                    credential_age_days = %s,
                    owner_status = %s,
                    federated_trust = %s,
                    cross_subscription = %s,
                    exposure_computed_at = NOW(),
                    critical_exposure_overrides = %s
                WHERE id = %s
            """, (
                scores.get('total', 0),
                _json.dumps(scores),
                scores.get('privilege', 0),
                scores.get('credential_risk', 0),
                scores.get('exposure', 0),
                scores.get('lifecycle', 0),
                scores.get('visibility', 0),
                activity.get('confidence', 0),
                flags.get('lifecycle_state', 'blind'),
                flags.get('can_escalate', False),
                flags.get('effective_scope_flag', 'resource'),
                flags.get('credential_age_days', 0),
                flags.get('owner_status', 'unknown'),
                flags.get('federated_trust', False),
                flags.get('cross_subscription', False),
                _json.dumps(overrides),
                identity_db_id,
            ))

            # Delete old findings for this identity+run, then insert new
            cursor.execute(
                "DELETE FROM spn_exposure_findings WHERE identity_db_id = %s AND discovery_run_id = %s",
                (identity_db_id, run_id))

            organization_id = self._organization_id or 1
            for f in findings:
                evidence_json = _json.dumps(f.get('evidence', {}))
                cursor.execute("""
                    INSERT INTO spn_exposure_findings
                        (identity_db_id, discovery_run_id, finding_type, severity,
                         title, description, evidence, remediation, component,
                         score_impact, organization_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    identity_db_id, run_id, f.get('finding_type', ''),
                    f.get('severity', 'info'), f.get('title', ''),
                    f.get('description', ''), evidence_json,
                    f.get('remediation', ''), f.get('component', ''),
                    f.get('score_impact', 0), organization_id,
                ))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ save_spn_exposure error: {e}")
        finally:
            cursor.close()

    def get_spn_exposure_findings(self, identity_db_id):
        """Get exposure findings for a single identity, ordered by severity."""
        self._ensure_spn_exposure()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        severity_order = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        cursor.execute(f"""
            SELECT finding_type, severity, title, description, evidence,
                   remediation, component, score_impact, created_at
            FROM spn_exposure_findings
            WHERE identity_db_id = %s
            ORDER BY {severity_order}, score_impact DESC
        """, (identity_db_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
        return rows

    # ─── App Registration Exposure Intelligence ──────────────────────

    def _ensure_app_reg_exposure(self):
        """Add 17 exposure columns to app_registrations + create app_reg_exposure_findings table."""
        if Database._app_reg_exposure_ensured:
            return
        cursor = self.conn.cursor()
        try:
            exposure_cols = [
                ('exposure_score', 'INTEGER DEFAULT 0'),
                ('exposure_components', "JSONB DEFAULT '{}'::jsonb"),
                ('privilege_score', 'INTEGER DEFAULT 0'),
                ('credential_risk_score', 'INTEGER DEFAULT 0'),
                ('exposure_subscore', 'INTEGER DEFAULT 0'),
                ('lifecycle_score', 'INTEGER DEFAULT 0'),
                ('visibility_score', 'INTEGER DEFAULT 0'),
                ('activity_confidence', 'INTEGER DEFAULT 0'),
                ('lifecycle_state', "VARCHAR(20) DEFAULT 'blind'"),
                ('can_escalate', 'BOOLEAN DEFAULT FALSE'),
                ('effective_scope_flag', "VARCHAR(30) DEFAULT 'resource'"),
                ('credential_age_days', 'INTEGER DEFAULT 0'),
                ('owner_status', "VARCHAR(20) DEFAULT 'unknown'"),
                ('federated_trust', 'BOOLEAN DEFAULT FALSE'),
                ('cross_subscription', 'BOOLEAN DEFAULT FALSE'),
                ('exposure_computed_at', 'TIMESTAMP'),
                ('critical_exposure_overrides', "JSONB DEFAULT '[]'::jsonb"),
            ]
            for col, coltype in exposure_cols:
                cursor.execute("SAVEPOINT sp_col")
                try:
                    cursor.execute(f"ALTER TABLE app_registrations ADD COLUMN IF NOT EXISTS {col} {coltype}")
                except Exception:
                    cursor.execute("ROLLBACK TO SAVEPOINT sp_col")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_reg_exposure_findings (
                    id SERIAL PRIMARY KEY,
                    app_reg_id BIGINT NOT NULL REFERENCES app_registrations(id) ON DELETE CASCADE,
                    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
                    finding_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence JSONB DEFAULT '{}',
                    remediation TEXT,
                    component VARCHAR(30),
                    score_impact INTEGER DEFAULT 0,
                    organization_id INTEGER NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_areg_findings_appreg ON app_reg_exposure_findings(app_reg_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_areg_findings_run ON app_reg_exposure_findings(discovery_run_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_areg_findings_org ON app_reg_exposure_findings(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_areg_findings_severity ON app_reg_exposure_findings(severity)")
            self.conn.commit()
            Database._app_reg_exposure_ensured = True
        except Exception as e:
            self.conn.rollback()
            if self._organization_id:
                self.set_organization_context(self._organization_id)
            print(f"  ⚠️ App reg exposure schema error: {e}")
        finally:
            cursor.close()

    def save_app_reg_exposure(self, app_reg_id, exposure_data, findings, run_id):
        """Save computed exposure data: UPDATE app_registrations + INSERT findings."""
        self._ensure_app_reg_exposure()
        cursor = self.conn.cursor()
        try:
            scores = exposure_data.get('scores', {})
            flags = exposure_data.get('flags', {})
            activity = exposure_data.get('activity_inference', {})
            overrides = exposure_data.get('critical_overrides', [])

            import json as _json
            cursor.execute("""
                UPDATE app_registrations SET
                    exposure_score = %s,
                    exposure_components = %s,
                    privilege_score = %s,
                    credential_risk_score = %s,
                    exposure_subscore = %s,
                    lifecycle_score = %s,
                    visibility_score = %s,
                    activity_confidence = %s,
                    lifecycle_state = %s,
                    can_escalate = %s,
                    effective_scope_flag = %s,
                    credential_age_days = %s,
                    owner_status = %s,
                    federated_trust = %s,
                    cross_subscription = %s,
                    exposure_computed_at = NOW(),
                    critical_exposure_overrides = %s
                WHERE id = %s
            """, (
                scores.get('total', 0),
                _json.dumps(scores),
                scores.get('privilege', 0),
                scores.get('credential_risk', 0),
                scores.get('exposure', 0),
                scores.get('lifecycle', 0),
                scores.get('visibility', 0),
                activity.get('confidence', 0),
                flags.get('lifecycle_state', 'blind'),
                flags.get('can_escalate', False),
                flags.get('effective_scope_flag', 'resource'),
                flags.get('credential_age_days', 0),
                flags.get('owner_status', 'unknown'),
                flags.get('federated_trust', False),
                flags.get('cross_subscription', False),
                _json.dumps(overrides),
                app_reg_id,
            ))

            cursor.execute(
                "DELETE FROM app_reg_exposure_findings WHERE app_reg_id = %s AND discovery_run_id = %s",
                (app_reg_id, run_id))

            organization_id = self._organization_id or 1
            for f in findings:
                evidence_json = _json.dumps(f.get('evidence', {}))
                cursor.execute("""
                    INSERT INTO app_reg_exposure_findings
                        (app_reg_id, discovery_run_id, finding_type, severity,
                         title, description, evidence, remediation, component,
                         score_impact, organization_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    app_reg_id, run_id, f.get('finding_type', ''),
                    f.get('severity', 'info'), f.get('title', ''),
                    f.get('description', ''), evidence_json,
                    f.get('remediation', ''), f.get('component', ''),
                    f.get('score_impact', 0), organization_id,
                ))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print(f"  ⚠️ save_app_reg_exposure error: {e}")
        finally:
            cursor.close()

    def get_app_reg_exposure_findings(self, app_reg_id):
        """Get exposure findings for a single app registration, ordered by severity."""
        self._ensure_app_reg_exposure()
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        severity_order = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        cursor.execute(f"""
            SELECT finding_type, severity, title, description, evidence,
                   remediation, component, score_impact, created_at
            FROM app_reg_exposure_findings
            WHERE app_reg_id = %s
            ORDER BY {severity_order}, score_impact DESC
        """, (app_reg_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        for r in rows:
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
        return rows

    # ─── Workload Telemetry Tables (P2 Telemetry Pipeline) ──────────────

    _workload_telemetry_ensured = False

    def _ensure_workload_telemetry_tables(self):
        """Create workload sign-in events, activity stats, and anomaly tables."""
        if Database._workload_telemetry_ensured:
            return
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS workload_signin_events (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id INTEGER NOT NULL,
                    identity_db_id BIGINT REFERENCES identities(id) ON DELETE CASCADE,
                    identity_id TEXT NOT NULL,
                    sign_in_id TEXT,
                    created_datetime TIMESTAMPTZ NOT NULL,
                    status TEXT NOT NULL,
                    error_code INTEGER,
                    failure_reason TEXT,
                    resource_display_name TEXT,
                    resource_id TEXT,
                    ip_address TEXT,
                    location_city TEXT,
                    location_country TEXT,
                    app_display_name TEXT,
                    client_app_type TEXT,
                    is_interactive BOOLEAN DEFAULT FALSE,
                    risk_level TEXT,
                    risk_detail TEXT,
                    conditional_access_status TEXT,
                    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
                    ingested_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wse_org ON workload_signin_events(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wse_identity_db ON workload_signin_events(identity_db_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wse_created ON workload_signin_events(created_datetime)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wse_identity_id ON workload_signin_events(identity_id)")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS workload_activity_stats (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id INTEGER NOT NULL,
                    identity_db_id BIGINT REFERENCES identities(id) ON DELETE CASCADE,
                    identity_id TEXT NOT NULL,
                    period_start DATE NOT NULL,
                    period_end DATE NOT NULL,
                    total_sign_ins INTEGER DEFAULT 0,
                    successful_sign_ins INTEGER DEFAULT 0,
                    failed_sign_ins INTEGER DEFAULT 0,
                    unique_resources INTEGER DEFAULT 0,
                    unique_ips INTEGER DEFAULT 0,
                    unique_locations INTEGER DEFAULT 0,
                    peak_hour INTEGER,
                    off_hours_pct REAL DEFAULT 0,
                    avg_daily_sign_ins REAL DEFAULT 0,
                    risk_sign_ins INTEGER DEFAULT 0,
                    ca_failures INTEGER DEFAULT 0,
                    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
                    computed_at TIMESTAMPTZ DEFAULT NOW(),
                    UNIQUE(identity_db_id, period_start, period_end)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_was_org ON workload_activity_stats(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_was_identity_db ON workload_activity_stats(identity_db_id)")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS workload_anomaly_events (
                    id BIGSERIAL PRIMARY KEY,
                    organization_id INTEGER NOT NULL,
                    identity_db_id BIGINT REFERENCES identities(id) ON DELETE CASCADE,
                    identity_id TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence JSONB DEFAULT '{}',
                    baseline JSONB DEFAULT '{}',
                    detected_value JSONB DEFAULT '{}',
                    resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMPTZ,
                    resolved_by TEXT,
                    discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wae_org ON workload_anomaly_events(organization_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wae_identity_db ON workload_anomaly_events(identity_db_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wae_type ON workload_anomaly_events(anomaly_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wae_severity ON workload_anomaly_events(severity)")

            # RLS policies for organization isolation on all 3 workload tables (idempotent)
            for tbl in ('workload_signin_events', 'workload_activity_stats', 'workload_anomaly_events'):
                cursor.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
                cursor.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
                for policy_stmt in [
                    f"CREATE POLICY org_strict_sel ON {tbl} FOR SELECT USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
                    f"CREATE POLICY org_strict_ins ON {tbl} FOR INSERT WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer)",
                    f"CREATE POLICY org_strict_upd ON {tbl} FOR UPDATE USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
                    f"CREATE POLICY org_strict_del ON {tbl} FOR DELETE USING (organization_id = current_setting('app.current_organization_id', true)::integer)",
                ]:
                    cursor.execute("SAVEPOINT rls_policy")
                    try:
                        cursor.execute(policy_stmt)
                        cursor.execute("RELEASE SAVEPOINT rls_policy")
                    except Exception:
                        cursor.execute("ROLLBACK TO SAVEPOINT rls_policy")

            self.conn.commit()
            Database._workload_telemetry_ensured = True
        except Exception as e:
            self.conn.rollback()
            if self._organization_id:
                self.set_organization_context(self._organization_id)
            print(f"  ⚠️ Workload telemetry tables error: {e}")
        finally:
            cursor.close()

    def cleanup_signin_events(self, days=90) -> int:
        """Delete old sign-in events beyond retention period."""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM workload_signin_events WHERE ingested_at < NOW() - INTERVAL '%s days'",
                (days,)
            )
            count = cursor.rowcount
            self.conn.commit()
            return count
        except Exception:
            self.conn.rollback()
            if self._organization_id:
                self.set_organization_context(self._organization_id)
            return 0
        finally:
            cursor.close()

    def cleanup_workload_anomalies(self, days=180) -> int:
        """Delete resolved workload anomalies beyond retention period."""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM workload_anomaly_events WHERE resolved = true AND created_at < NOW() - INTERVAL '%s days'",
                (days,)
            )
            count = cursor.rowcount
            self.conn.commit()
            return count
        except Exception:
            self.conn.rollback()
            if self._organization_id:
                self.set_organization_context(self._organization_id)
            return 0
        finally:
            cursor.close()


    # ─── ICE: Identity Correlation CRUD ──────────────────────────────────

    def save_human_identity(self, organization_id, display_name, employee_id=None,
                            department=None, manager_id=None):
        """Create or update a human identity. Returns id."""
        _ensure_human_identities_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                INSERT INTO human_identities (organization_id, display_name, employee_id, department, manager_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING id
            """, (organization_id, display_name, employee_id, department, manager_id))
            row = cursor.fetchone()
            if row:
                self.conn.commit()
                return row['id']
            # Find existing by employee_id or display_name
            if employee_id:
                cursor.execute(
                    "SELECT id FROM human_identities WHERE organization_id = %s AND employee_id = %s LIMIT 1",
                    (organization_id, employee_id))
            else:
                cursor.execute(
                    "SELECT id FROM human_identities WHERE organization_id = %s AND display_name = %s LIMIT 1",
                    (organization_id, display_name))
            existing = cursor.fetchone()
            if existing:
                cursor.execute("""
                    UPDATE human_identities SET display_name = %s, department = %s,
                    manager_id = %s, updated_at = NOW() WHERE id = %s
                """, (display_name, department, manager_id, existing['id']))
                self.conn.commit()
                return existing['id']
            self.conn.commit()
            return None
        finally:
            cursor.close()

    def save_identity_link(self, organization_id, human_identity_id, identity_db_id,
                           account_type, account_upn, account_object_id,
                           account_enabled, link_method, link_confidence):
        """Create or update an identity link. Returns id."""
        _ensure_identity_links_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                INSERT INTO identity_links (
                    organization_id, human_identity_id, identity_db_id, account_type,
                    account_upn, account_object_id, account_enabled,
                    link_method, link_confidence
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (organization_id, account_object_id) DO UPDATE SET
                    human_identity_id = EXCLUDED.human_identity_id,
                    identity_db_id = EXCLUDED.identity_db_id,
                    account_type = EXCLUDED.account_type,
                    account_upn = EXCLUDED.account_upn,
                    account_enabled = EXCLUDED.account_enabled,
                    link_method = EXCLUDED.link_method,
                    link_confidence = EXCLUDED.link_confidence
                RETURNING id
            """, (organization_id, human_identity_id, identity_db_id, account_type,
                  account_upn, account_object_id, account_enabled,
                  link_method, link_confidence))
            row = cursor.fetchone()
            self.conn.commit()
            return row['id'] if row else None
        finally:
            cursor.close()

    def get_human_identities(self, organization_id, limit=50, offset=0, search=None):
        """List human identities with linked account counts."""
        _ensure_human_identities_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            where = "WHERE h.organization_id = %s"
            params = [organization_id]
            if search:
                where += " AND (h.display_name ILIKE %s OR h.employee_id ILIKE %s)"
                params += [f'%{search}%', f'%{search}%']
            cursor.execute(f"""
                SELECT h.*, COUNT(l.id) as account_count,
                    COALESCE(json_agg(json_build_object(
                        'id', l.id, 'account_type', l.account_type,
                        'account_upn', l.account_upn, 'account_enabled', l.account_enabled,
                        'link_confidence', l.link_confidence, 'verified', l.verified
                    )) FILTER (WHERE l.id IS NOT NULL), '[]') as accounts
                FROM human_identities h
                LEFT JOIN identity_links l ON l.human_identity_id = h.id
                {where}
                GROUP BY h.id
                ORDER BY h.display_name
                LIMIT %s OFFSET %s
            """, params + [limit, offset])
            results = cursor.fetchall()
            # Get total count
            cursor.execute(f"SELECT COUNT(*) as cnt FROM human_identities h {where}", params)
            total = cursor.fetchone()['cnt']
            return [dict(r) for r in results], total
        finally:
            cursor.close()

    def get_human_identity_detail(self, human_id):
        """Get a single human identity with all linked accounts."""
        _ensure_human_identities_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                SELECT h.* FROM human_identities h WHERE h.id = %s
            """, (human_id,))
            human = cursor.fetchone()
            if not human:
                return None
            cursor.execute("""
                SELECT l.*, i.display_name as identity_name, i.risk_score,
                    i.risk_level, i.identity_category, i.enabled as identity_enabled,
                    i.activity_status, i.last_sign_in
                FROM identity_links l
                LEFT JOIN identities i ON i.id = l.identity_db_id
                WHERE l.human_identity_id = %s
                ORDER BY l.account_type
            """, (human_id,))
            accounts = [dict(r) for r in cursor.fetchall()]
            result = dict(human)
            result['accounts'] = accounts
            return result
        finally:
            cursor.close()

    def save_orphaned_finding(self, finding_dict):
        """Save an orphaned privileged account finding. Upserts on open status."""
        _ensure_orphaned_findings_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                INSERT INTO orphaned_privileged_findings (
                    organization_id, discovery_run_id, human_identity_id,
                    regular_link_id, privileged_link_id,
                    regular_upn, regular_object_id,
                    privileged_upn, privileged_object_id,
                    severity, azure_roles, role_count,
                    highest_role_privilege, subscription_count,
                    has_activity_after_disable, days_since_regular_disabled,
                    status, compliance_reference, days_out_of_compliance,
                    remediation_commands
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (organization_id, privileged_object_id) WHERE status = 'open'
                DO UPDATE SET
                    discovery_run_id = EXCLUDED.discovery_run_id,
                    severity = EXCLUDED.severity,
                    azure_roles = EXCLUDED.azure_roles,
                    role_count = EXCLUDED.role_count,
                    highest_role_privilege = EXCLUDED.highest_role_privilege,
                    subscription_count = EXCLUDED.subscription_count,
                    has_activity_after_disable = EXCLUDED.has_activity_after_disable,
                    days_since_regular_disabled = EXCLUDED.days_since_regular_disabled,
                    days_out_of_compliance = EXCLUDED.days_out_of_compliance,
                    remediation_commands = EXCLUDED.remediation_commands,
                    updated_at = NOW()
                RETURNING id
            """, (
                finding_dict['organization_id'],
                finding_dict.get('discovery_run_id'),
                finding_dict.get('human_identity_id'),
                finding_dict.get('regular_link_id'),
                finding_dict.get('privileged_link_id'),
                finding_dict.get('regular_upn'),
                finding_dict.get('regular_object_id'),
                finding_dict.get('privileged_upn'),
                finding_dict.get('privileged_object_id'),
                finding_dict.get('severity', 'high'),
                finding_dict.get('azure_roles', []),
                finding_dict.get('role_count', 0),
                finding_dict.get('highest_role_privilege'),
                finding_dict.get('subscription_count', 0),
                finding_dict.get('has_activity_after_disable', False),
                finding_dict.get('days_since_regular_disabled'),
                finding_dict.get('status', 'open'),
                finding_dict.get('compliance_reference', 'HIPAA §164.312(a)(2)(iii)'),
                finding_dict.get('days_out_of_compliance', 0),
                json.dumps(finding_dict.get('remediation_commands', {})),
            ))
            row = cursor.fetchone()
            self.conn.commit()
            return row['id'] if row else None
        finally:
            cursor.close()

    def get_orphaned_findings(self, organization_id, limit=50, offset=0,
                              status=None, severity=None):
        """List orphaned privileged account findings."""
        _ensure_orphaned_findings_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            where = "WHERE f.organization_id = %s"
            params = [organization_id]
            if status:
                where += " AND f.status = %s"
                params.append(status)
            if severity:
                where += " AND f.severity = %s"
                params.append(severity)
            cursor.execute(f"""
                SELECT f.*, h.display_name as human_name, h.employee_id
                FROM orphaned_privileged_findings f
                LEFT JOIN human_identities h ON h.id = f.human_identity_id
                {where}
                ORDER BY
                    CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                    f.created_at DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])
            results = [dict(r) for r in cursor.fetchall()]
            cursor.execute(f"SELECT COUNT(*) as cnt FROM orphaned_privileged_findings f {where}", params)
            total = cursor.fetchone()['cnt']
            return results, total
        finally:
            cursor.close()

    def get_orphaned_finding_detail(self, finding_id):
        """Get a single orphaned finding with linked identity details."""
        _ensure_orphaned_findings_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                SELECT f.*, h.display_name as human_name, h.employee_id,
                    h.department, h.manager_id,
                    rl.account_upn as regular_account_upn,
                    rl.account_enabled as regular_account_enabled,
                    pl.account_upn as privileged_account_upn,
                    pl.account_enabled as privileged_account_enabled,
                    ri.risk_score as regular_risk_score,
                    pi.risk_score as privileged_risk_score,
                    pi.risk_level as privileged_risk_level,
                    pi.last_sign_in as privileged_last_sign_in
                FROM orphaned_privileged_findings f
                LEFT JOIN human_identities h ON h.id = f.human_identity_id
                LEFT JOIN identity_links rl ON rl.id = f.regular_link_id
                LEFT JOIN identity_links pl ON pl.id = f.privileged_link_id
                LEFT JOIN identities ri ON ri.id = rl.identity_db_id
                LEFT JOIN identities pi ON pi.id = pl.identity_db_id
                WHERE f.id = %s
            """, (finding_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            cursor.close()

    def update_orphaned_finding_status(self, finding_id, new_status, user_id=None,
                                       remediation_action=None):
        """Update the lifecycle status of an orphaned finding."""
        _ensure_orphaned_findings_table(self.conn)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            sets = ["status = %s", "updated_at = NOW()"]
            params = [new_status]
            if new_status == 'acknowledged':
                sets += ["acknowledged_at = NOW()", "acknowledged_by = %s"]
                params.append(str(user_id) if user_id else None)
            elif new_status == 'remediated':
                sets += ["remediated_at = NOW()", "remediated_by = %s", "remediation_action = %s"]
                params += [str(user_id) if user_id else None, remediation_action]
            elif new_status == 'suppressed':
                sets += ["suppressed_at = NOW()", "suppressed_by = %s", "suppression_reason = %s"]
                params += [str(user_id) if user_id else None, remediation_action]
            params.append(finding_id)
            cursor.execute(f"""
                UPDATE orphaned_privileged_findings SET {', '.join(sets)}
                WHERE id = %s RETURNING id
            """, params)
            row = cursor.fetchone()
            self.conn.commit()
            return row is not None
        finally:
            cursor.close()

    def delete_identity_link(self, link_id):
        """Delete an identity link. Cleans up orphaned human_identities."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            # Get human_identity_id before deleting
            cursor.execute("SELECT human_identity_id FROM identity_links WHERE id = %s", (link_id,))
            row = cursor.fetchone()
            if not row:
                return False
            human_id = row['human_identity_id']
            cursor.execute("DELETE FROM identity_links WHERE id = %s", (link_id,))
            # Clean up if this was the last link
            cursor.execute("SELECT COUNT(*) as cnt FROM identity_links WHERE human_identity_id = %s", (human_id,))
            if cursor.fetchone()['cnt'] == 0:
                cursor.execute("DELETE FROM human_identities WHERE id = %s", (human_id,))
            self.conn.commit()
            return True
        finally:
            cursor.close()

    def verify_identity_link(self, link_id, verified_by):
        """Mark an identity link as verified."""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                UPDATE identity_links SET verified = TRUE, verified_at = NOW(), verified_by = %s
                WHERE id = %s RETURNING id
            """, (verified_by, link_id))
            row = cursor.fetchone()
            self.conn.commit()
            return row is not None
        finally:
            cursor.close()


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


# ── Identity Governance V2: Risk Scoring Engine ──────────────────

_GOV_PRIVILEGED_ROLES = {
    'Owner': 30, 'User Access Administrator': 25, 'Contributor': 20,
    'Key Vault Administrator': 20, 'Key Vault Secrets Officer': 20,
    'Global Administrator': 30, 'Privileged Role Administrator': 25,
    'Application Administrator': 20, 'Cloud Application Administrator': 18,
}

_GOV_RISKY_PERMS = {
    'Application.ReadWrite.All': 10, 'Directory.ReadWrite.All': 12,
    'RoleManagement.ReadWrite.Directory': 12, 'AppRoleAssignment.ReadWrite.All': 10,
    'Mail.ReadWrite': 8, 'Sites.ReadWrite.All': 8, 'Files.ReadWrite.All': 8,
    'User.ReadWrite.All': 10, 'Group.ReadWrite.All': 10,
}


def _compute_governance_risk(identity, roles, credentials, graph_perms, attestation,
                             owner_count, policies):
    """Deterministic governance-aware risk scoring (0-100) with 5 signal categories.

    Returns: (score, band, factors_list)
    """
    factors = []
    raw = 0

    # ── 1. PRIVILEGE (max 35) ──
    priv_score = 0
    seen_roles = set()
    has_contributor = False
    has_uaa = False
    for r in (roles or []):
        rn = r.get('role_name', '')
        scope_type = r.get('scope_type', 'resource')
        pts = _GOV_PRIVILEGED_ROLES.get(rn, 0)
        if pts > 0 and rn not in seen_roles:
            seen_roles.add(rn)
            scope_label = r.get('scope', scope_type)
            # Scale: subscription-level is full points, rg is 75%, resource is 50%
            if scope_type == 'subscription':
                factor_pts = pts
            elif scope_type in ('resourceGroup', 'resource_group'):
                factor_pts = int(pts * 0.75)
            else:
                factor_pts = int(pts * 0.5)
            priv_score += factor_pts
            factors.append({'factor': f'{rn} role on {scope_label}', 'impact': factor_pts, 'category': 'privilege'})
            if rn == 'Contributor':
                has_contributor = True
            if rn == 'User Access Administrator':
                has_uaa = True

    # Toxic combination
    if has_contributor and has_uaa:
        factors.append({'factor': 'Toxic combination: Contributor + User Access Administrator', 'impact': 10, 'category': 'privilege'})
        priv_score += 10

    # Reader-only deduction
    if roles and priv_score == 0:
        has_reader = any(r.get('role_name', '') == 'Reader' for r in roles)
        if has_reader:
            factors.append({'factor': 'Reader-only access', 'impact': -5, 'category': 'privilege'})
            priv_score -= 5

    # Graph API permissions
    perm_pts = 0
    for perm in (graph_perms or []):
        pname = perm if isinstance(perm, str) else perm.get('permission_name', '')
        pts = _GOV_RISKY_PERMS.get(pname, 0)
        if pts > 0:
            perm_pts += pts
            factors.append({'factor': f'API permission: {pname}', 'impact': pts, 'category': 'privilege'})
    priv_score += perm_pts
    raw += min(priv_score, 35)

    # ── 2. GOVERNANCE (max 25) ──
    gov_score = 0
    if (owner_count or 0) == 0:
        gov_score += 20
        factors.append({'factor': 'No assigned owner — accountability gap', 'impact': 20, 'category': 'governance'})

    if attestation is None:
        gov_score += 12
        factors.append({'factor': 'Never attested — no review on record', 'impact': 12, 'category': 'governance'})
    else:
        from datetime import datetime, timezone
        next_due = attestation.get('next_due')
        is_overdue = False
        if next_due:
            nd = next_due if hasattr(next_due, 'replace') else None
            if nd and nd.replace(tzinfo=None) < datetime.utcnow():
                is_overdue = True
        if is_overdue:
            gov_score += 10
            factors.append({'factor': 'Attestation overdue (>90 days)', 'impact': 10, 'category': 'governance'})
        else:
            gov_score -= 8
            factors.append({'factor': 'Recently attested with known owner', 'impact': -8, 'category': 'governance'})
    raw += min(max(gov_score, 0), 25)

    # ── 3. USAGE (max 20) ──
    usage_score = 0
    act_status = identity.get('activity_status', '')
    last_sign_in = identity.get('last_sign_in')
    is_dormant = act_status in ('stale', 'never_used')

    if act_status == 'never_used':
        usage_score += 12
        factors.append({'factor': 'Never used — no sign-in record', 'impact': 12, 'category': 'usage'})
    elif is_dormant:
        if priv_score > 0:
            usage_score += 15
            factors.append({'factor': 'Dormant 90+ days with active privileges', 'impact': 15, 'category': 'usage'})
        else:
            usage_score += 8
            factors.append({'factor': 'Dormant 90+ days (reader only)', 'impact': 8, 'category': 'usage'})
    elif act_status == 'active':
        usage_score -= 5
        factors.append({'factor': 'Actively used (within 30 days)', 'impact': -5, 'category': 'usage'})
    elif act_status == 'inactive':
        usage_score += 5
        factors.append({'factor': 'Low frequency usage (30-90 days)', 'impact': 5, 'category': 'usage'})
    raw += min(max(usage_score, 0), 20)

    # ── 4. CREDENTIAL (max 15) ──
    cred_score = 0
    cat = identity.get('identity_category', '')
    is_managed = cat in ('managed_identity_system', 'managed_identity_user')

    if is_managed:
        cred_score -= 10
        factors.append({'factor': 'Platform-managed identity (no user credentials)', 'impact': -10, 'category': 'credential'})
    elif not credentials:
        cred_score += 10
        factors.append({'factor': 'No credentials found — possible orphan', 'impact': 10, 'category': 'credential'})
    else:
        cred_risk = identity.get('credential_risk', '')
        if cred_risk == 'expired':
            cred_score += 10
            factors.append({'factor': 'Expired credential still present', 'impact': 10, 'category': 'credential'})
        elif cred_risk == 'expiring_soon':
            cred_score += 15
            factors.append({'factor': 'Credential expiring within 30 days', 'impact': 15, 'category': 'credential'})

        # Check for old credentials
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        for c in (credentials if isinstance(credentials, list) else [credentials]):
            start = c.get('start_datetime')
            if start and hasattr(start, 'replace'):
                age = (now - (start.replace(tzinfo=timezone.utc) if start.tzinfo is None else start)).days
                if age > 365:
                    cred_score += 10
                    factors.append({'factor': f'Credential age {age}d — not rotated', 'impact': 10, 'category': 'credential'})
                    break

        # Multiple secrets
        cred_count = identity.get('credential_count', 0) or 0
        if cred_count > 2:
            cred_score += 5
            factors.append({'factor': f'{cred_count} credentials — more than needed', 'impact': 5, 'category': 'credential'})

    raw += min(max(cred_score, 0), 15)

    # ── 5. EXPOSURE (max 10) ──
    exposure_score = 0
    sp_type = identity.get('service_principal_type', '') or ''
    is_federated = identity.get('is_federated', False)
    if is_federated or sp_type.lower() == 'socialidp':
        exposure_score += 10
        factors.append({'factor': 'External/third-party application', 'impact': 10, 'category': 'exposure'})
    elif sp_type.lower() in ('application', 'managedidentity'):
        exposure_score -= 3
        factors.append({'factor': 'Internal application only', 'impact': -3, 'category': 'exposure'})
    raw += min(max(exposure_score, 0), 10)

    # Clamp and band
    score = max(0, min(100, raw))
    if score >= 76:
        band = 'Critical'
    elif score >= 51:
        band = 'High'
    elif score >= 26:
        band = 'Medium'
    else:
        band = 'Low'

    # Sort factors by absolute impact DESC
    factors.sort(key=lambda f: abs(f['impact']), reverse=True)

    return score, band, factors


def _compute_gov_recommended_action(score, band, factors, is_dormant, is_unowned, cred_risk, is_managed):
    """Compute recommended governance action and expected risk reduction."""
    if is_dormant and score >= 50:
        reduction = min(score, 45)
        return 'Revoke', f'Remove all access — dormant with elevated risk', reduction
    if is_unowned and score >= 40:
        return 'Assign Owner', 'Assign accountability before next review', 20
    if band == 'Critical':
        return 'Revoke', 'Remove or disable — critical risk', min(score, 50)
    if band == 'High' and is_dormant:
        return 'Revoke', 'Dormant with high risk — recommend removal', min(score, 40)
    if cred_risk == 'expired':
        return 'Rotate', 'Rotate expired credentials immediately', 10
    if cred_risk == 'expiring_soon':
        return 'Rotate', 'Rotate credentials before expiry', 15
    if band == 'High':
        has_priv = any(f['category'] == 'privilege' and f['impact'] >= 20 for f in factors)
        if has_priv:
            return 'Downgrade', 'Reduce privilege level', 20
        return 'Re-attest', 'Review and certify access', 10
    if band == 'Medium':
        if is_unowned:
            return 'Assign Owner', 'Assign owner for accountability', 15
        return 'Re-attest', 'Periodic review recommended', 8
    if is_managed:
        return 'None', 'Low-risk managed identity', 0
    return 'Approve', 'Low risk — approve current access', 0


# ─── RBAC Hygiene Persistence ────────────────────────────────────────

_rbac_hygiene_ensured = False

def _ensure_rbac_hygiene_table(conn):
    """Create rbac_hygiene_scans table for persisting hygiene analysis results."""
    global _rbac_hygiene_ensured
    if _rbac_hygiene_ensured:
        return
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rbac_hygiene_scans (
            id SERIAL PRIMARY KEY,
            score INTEGER NOT NULL DEFAULT 0,
            grade VARCHAR(2) NOT NULL DEFAULT 'F',
            total_assignments INTEGER NOT NULL DEFAULT 0,
            total_findings INTEGER NOT NULL DEFAULT 0,
            summary JSONB NOT NULL DEFAULT '{}',
            findings JSONB NOT NULL DEFAULT '[]',
            discovery_run_id BIGINT REFERENCES discovery_runs(id) ON DELETE CASCADE,
            organization_id INTEGER NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rbac_hygiene_org ON rbac_hygiene_scans(organization_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rbac_hygiene_created ON rbac_hygiene_scans(created_at DESC)")
    conn.commit()
    cursor.close()
    _rbac_hygiene_ensured = True


# ─── ICE: Identity Correlation Engine Tables ─────────────────────────

_human_identities_ensured = False

def _ensure_human_identities_table(conn):
    """Create human_identities table for linking multiple accounts to a real person."""
    global _human_identities_ensured
    if _human_identities_ensured:
        return
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS human_identities (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                display_name VARCHAR(500),
                employee_id VARCHAR(255),
                department VARCHAR(255),
                manager_id VARCHAR(255),
                employment_status VARCHAR(50) DEFAULT 'active',
                status_determined_at TIMESTAMPTZ,
                status_source VARCHAR(100),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_human_identities_org ON human_identities(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_human_identities_employee ON human_identities(employee_id)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  ⚠️ human_identities table creation error: {e}")
    finally:
        cursor.close()
    _human_identities_ensured = True


_identity_links_ensured = False

def _ensure_identity_links_table(conn):
    """Create identity_links table for mapping accounts to human identities."""
    global _identity_links_ensured
    if _identity_links_ensured:
        return
    _ensure_human_identities_table(conn)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity_links (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                human_identity_id INTEGER NOT NULL REFERENCES human_identities(id) ON DELETE CASCADE,
                identity_db_id INTEGER REFERENCES identities(id) ON DELETE SET NULL,
                account_type VARCHAR(50) NOT NULL,
                account_upn VARCHAR(500),
                account_object_id VARCHAR(255),
                account_enabled BOOLEAN DEFAULT TRUE,
                link_method VARCHAR(50) NOT NULL DEFAULT 'naming_convention',
                link_confidence DECIMAL(5,2) DEFAULT 0,
                linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                linked_by VARCHAR(255),
                verified BOOLEAN DEFAULT FALSE,
                verified_at TIMESTAMPTZ,
                verified_by VARCHAR(255),
                UNIQUE(organization_id, account_object_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_identity_links_org ON identity_links(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_identity_links_human ON identity_links(human_identity_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_identity_links_identity ON identity_links(identity_db_id)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  ⚠️ identity_links table creation error: {e}")
    finally:
        cursor.close()
    _identity_links_ensured = True


_orphaned_findings_ensured = False

def _ensure_orphaned_findings_table(conn):
    """Create orphaned_privileged_findings table for orphaned account detection results."""
    global _orphaned_findings_ensured
    if _orphaned_findings_ensured:
        return
    _ensure_identity_links_table(conn)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orphaned_privileged_findings (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE CASCADE,
                human_identity_id INTEGER REFERENCES human_identities(id) ON DELETE CASCADE,
                regular_link_id INTEGER REFERENCES identity_links(id) ON DELETE SET NULL,
                privileged_link_id INTEGER REFERENCES identity_links(id) ON DELETE SET NULL,
                regular_upn VARCHAR(500),
                regular_object_id VARCHAR(255),
                privileged_upn VARCHAR(500),
                privileged_object_id VARCHAR(255),
                severity VARCHAR(20) NOT NULL DEFAULT 'high',
                azure_roles TEXT[],
                role_count INTEGER DEFAULT 0,
                highest_role_privilege VARCHAR(100),
                subscription_count INTEGER DEFAULT 0,
                has_activity_after_disable BOOLEAN DEFAULT FALSE,
                days_since_regular_disabled INTEGER,
                status VARCHAR(50) NOT NULL DEFAULT 'open',
                acknowledged_at TIMESTAMPTZ,
                acknowledged_by VARCHAR(255),
                remediated_at TIMESTAMPTZ,
                remediated_by VARCHAR(255),
                remediation_action TEXT,
                suppressed_at TIMESTAMPTZ,
                suppressed_by VARCHAR(255),
                suppression_reason TEXT,
                compliance_reference VARCHAR(255) DEFAULT 'HIPAA §164.312(a)(2)(iii)',
                days_out_of_compliance INTEGER DEFAULT 0,
                remediation_commands JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orphaned_findings_org ON orphaned_privileged_findings(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orphaned_findings_status ON orphaned_privileged_findings(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_orphaned_findings_severity ON orphaned_privileged_findings(severity)")
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_orphaned_findings_open_unique
            ON orphaned_privileged_findings(organization_id, privileged_object_id)
            WHERE status = 'open'
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  ⚠️ orphaned_privileged_findings table creation error: {e}")
    finally:
        cursor.close()
    _orphaned_findings_ensured = True


# ──────────────────────────────────────────────────────────────────────────────
# Phase 6: Scan Schedules
# ──────────────────────────────────────────────────────────────────────────────

_scan_schedules_ensured = False


def _ensure_scan_schedules_table(conn):
    """Create scan_schedules table for scheduled discovery scans."""
    global _scan_schedules_ensured
    if _scan_schedules_ensured:
        return
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                connection_id INTEGER,
                label VARCHAR(100),
                frequency VARCHAR(20) NOT NULL DEFAULT 'daily',
                cron_expression VARCHAR(100) DEFAULT '0 2 * * *',
                next_run_at TIMESTAMPTZ,
                last_run_at TIMESTAMPTZ,
                last_run_status VARCHAR(20),
                enabled BOOLEAN DEFAULT true,
                created_by INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_schedules_org ON scan_schedules(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_schedules_next ON scan_schedules(next_run_at) WHERE enabled = true")
        cursor.execute("ALTER TABLE scan_schedules ENABLE ROW LEVEL SECURITY")
        # RLS policy
        cursor.execute("""
            DO $$ BEGIN
                CREATE POLICY org_strict_scan_schedules ON scan_schedules
                    USING (organization_id = current_setting('app.current_organization_id', true)::integer)
                    WITH CHECK (organization_id = current_setting('app.current_organization_id', true)::integer);
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  ⚠️ scan_schedules table creation error: {e}")
    finally:
        cursor.close()
    _scan_schedules_ensured = True


# ──────────────────────────────────────────────────────────────────────────────
# Phase 6: Stripe Integration Support
# ──────────────────────────────────────────────────────────────────────────────

_stripe_columns_ensured = False


def _ensure_stripe_columns(conn):
    """Add Stripe-related columns to organizations and cloud_subscriptions."""
    global _stripe_columns_ensured
    if _stripe_columns_ensured:
        return
    cursor = conn.cursor()
    try:
        # Stripe customer ID on organizations
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(100)")
        cursor.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(100)")
        # Stripe price item ID on cloud_subscriptions
        cursor.execute("ALTER TABLE cloud_subscriptions ADD COLUMN IF NOT EXISTS stripe_subscription_item_id VARCHAR(100)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"  ⚠️ stripe columns migration error: {e}")
    finally:
        cursor.close()
    _stripe_columns_ensured = True
