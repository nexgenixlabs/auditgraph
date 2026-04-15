#!/usr/bin/env python3
"""Schema synchronization script.

Compares the current database schema against the expected schema (from localhost dump)
and adds any missing tables, columns, indexes. Safe to run multiple times (idempotent).

Usage:
    python3 scripts/sync_schema.py              # dry-run (show what would change)
    python3 scripts/sync_schema.py --apply       # apply changes

Environment: uses DB_HOST, DB_PORT, DB_NAME, DB_ADMIN_USER, DB_ADMIN_PASSWORD, DB_SSLMODE
"""

import os
import sys
import json
import logging
import argparse

import psycopg2
from psycopg2.extras import RealDictCursor

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("sync_schema")

# ─── Expected schema from localhost dump ─────────────────────────────────────
# This is auto-generated — see the EXPECTED_COLUMNS dict below.

EXPECTED_COLUMNS = {}  # populated by _load_expected_schema()


def _load_expected_schema():
    """Load expected schema from the embedded CSV data."""
    global EXPECTED_COLUMNS
    for line in SCHEMA_CSV.strip().split("\n"):
        parts = line.split("|")
        if len(parts) < 6:
            continue
        table, col, dtype, max_len, default, nullable = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        if table not in EXPECTED_COLUMNS:
            EXPECTED_COLUMNS[table] = {}
        EXPECTED_COLUMNS[table][col] = {
            "type": dtype,
            "max_len": max_len,
            "default": default,
            "nullable": nullable,
        }


def get_current_schema(conn):
    """Get current database schema."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT table_name, column_name, data_type,
               CASE WHEN character_maximum_length IS NOT NULL THEN character_maximum_length::text ELSE '' END,
               COALESCE(column_default, ''),
               is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
    """)
    schema = {}
    for row in cursor.fetchall():
        table, col = row[0], row[1]
        if table not in schema:
            schema[table] = {}
        schema[table][col] = {
            "type": row[2],
            "max_len": row[3],
            "default": row[4],
            "nullable": row[5],
        }
    cursor.close()
    return schema


def get_current_tables(conn):
    """Get list of current tables."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name
    """)
    tables = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return tables


def get_table_ownership(conn):
    """Get table ownership info."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public'
    """)
    ownership = {row[0]: row[1] for row in cursor.fetchall()}
    cursor.close()
    return ownership


def map_type_to_ddl(col_info):
    """Map column info to DDL type string."""
    dtype = col_info["type"]
    max_len = col_info["max_len"]

    type_map = {
        "integer": "INTEGER",
        "bigint": "BIGINT",
        "smallint": "SMALLINT",
        "boolean": "BOOLEAN",
        "text": "TEXT",
        "jsonb": "JSONB",
        "json": "JSON",
        "uuid": "UUID",
        "timestamp with time zone": "TIMESTAMPTZ",
        "timestamp without time zone": "TIMESTAMP",
        "date": "DATE",
        "numeric": "NUMERIC",
        "double precision": "DOUBLE PRECISION",
        "real": "REAL",
        "bytea": "BYTEA",
        "ARRAY": "TEXT[]",
    }

    if dtype == "character varying" and max_len:
        return f"VARCHAR({max_len})"
    elif dtype == "character varying":
        return "VARCHAR"
    elif dtype == "character" and max_len:
        return f"CHAR({max_len})"
    elif dtype in type_map:
        return type_map[dtype]
    else:
        return dtype.upper()


def map_default_to_ddl(col_info):
    """Map column default to DDL default clause."""
    default = col_info["default"]
    if not default:
        return ""
    # Skip serial/sequence defaults (auto-generated)
    if "nextval(" in default:
        return ""
    # Skip gen_random_uuid() — it will be set by CREATE TABLE
    if "gen_random_uuid" in default:
        return ""
    return f" DEFAULT {default}"


def generate_add_column_sql(table, col, col_info):
    """Generate ALTER TABLE ADD COLUMN IF NOT EXISTS SQL."""
    ddl_type = map_type_to_ddl(col_info)
    default = map_default_to_ddl(col_info)
    return f'ALTER TABLE "{table}" ADD COLUMN IF NOT EXISTS "{col}" {ddl_type}{default};'


def compare_schemas(expected, current):
    """Compare expected vs current schema and return changes needed."""
    changes = {
        "missing_tables": [],
        "missing_columns": [],  # (table, col, col_info)
        "total_expected_tables": len(expected),
        "total_current_tables": len(current),
    }

    for table in sorted(expected.keys()):
        if table not in current:
            changes["missing_tables"].append(table)
            continue
        for col in sorted(expected[table].keys()):
            if col not in current[table]:
                changes["missing_columns"].append((table, col, expected[table][col]))

    return changes


def apply_changes(conn, changes, dry_run=True):
    """Apply schema changes."""
    cursor = conn.cursor()

    if changes["missing_tables"]:
        logger.info("Missing tables (%d): %s", len(changes["missing_tables"]),
                     ", ".join(changes["missing_tables"]))
        if not dry_run:
            logger.warning("Cannot auto-create tables — need full CREATE TABLE DDL. "
                          "These tables must be created via startup DDL.")

    if changes["missing_columns"]:
        logger.info("Missing columns (%d):", len(changes["missing_columns"]))
        for table, col, col_info in changes["missing_columns"]:
            sql = generate_add_column_sql(table, col, col_info)
            logger.info("  %s", sql)
            if not dry_run:
                try:
                    cursor.execute(f"SAVEPOINT col_{table}_{col}")
                    cursor.execute(sql)
                    cursor.execute(f"RELEASE SAVEPOINT col_{table}_{col}")
                except Exception as e:
                    cursor.execute(f"ROLLBACK TO SAVEPOINT col_{table}_{col}")
                    logger.error("  FAILED: %s", e)

    if not dry_run:
        conn.commit()
        logger.info("Changes applied.")
    else:
        logger.info("\nDry run complete. Use --apply to apply changes.")

    cursor.close()


def fix_ownership(conn, admin_user, dry_run=True):
    """Fix table ownership — reassign tables not owned by admin_user."""
    ownership = get_table_ownership(conn)
    foreign = {t: o for t, o in ownership.items() if o != admin_user}

    if not foreign:
        logger.info("All tables owned by '%s' ✓", admin_user)
        return

    logger.info("Tables with foreign ownership (%d):", len(foreign))
    cursor = conn.cursor()
    fixed = 0
    for table, owner in sorted(foreign.items()):
        logger.info("  %s: owned by '%s'", table, owner)
        if not dry_run:
            try:
                cursor.execute(f"SAVEPOINT own_{fixed}")
                cursor.execute(f'ALTER TABLE "{table}" OWNER TO {admin_user}')
                cursor.execute(f"RELEASE SAVEPOINT own_{fixed}")
                fixed += 1
                logger.info("    → reassigned to '%s'", admin_user)
            except Exception as e:
                cursor.execute(f"ROLLBACK TO SAVEPOINT own_{fixed}")
                logger.warning("    → FAILED: %s", e)

    if not dry_run and fixed:
        conn.commit()
        logger.info("Reassigned %d tables.", fixed)
    cursor.close()


def fix_grants(conn, app_user, dry_run=True):
    """Grant SELECT/INSERT/UPDATE/DELETE on all tables to app user."""
    cursor = conn.cursor()
    cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    tables = [row[0] for row in cursor.fetchall()]

    granted = 0
    failed = []
    for tbl in tables:
        if not dry_run:
            try:
                cursor.execute(f"SAVEPOINT g_{granted}")
                cursor.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{tbl}" TO {app_user}')
                cursor.execute(f"RELEASE SAVEPOINT g_{granted}")
                granted += 1
            except Exception:
                cursor.execute(f"ROLLBACK TO SAVEPOINT g_{granted}")
                failed.append(tbl)
        else:
            granted += 1

    # Sequences
    cursor.execute("SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public'")
    for row in cursor.fetchall():
        seq = row[0]
        if not dry_run:
            try:
                cursor.execute(f"SAVEPOINT gs")
                cursor.execute(f'GRANT USAGE, SELECT ON SEQUENCE "{seq}" TO {app_user}')
                cursor.execute(f"RELEASE SAVEPOINT gs")
            except Exception:
                cursor.execute(f"ROLLBACK TO SAVEPOINT gs")

    if not dry_run:
        conn.commit()

    logger.info("GRANT: %d tables granted to '%s', %d failed", granted, app_user, len(failed))
    if failed:
        logger.warning("  Failed: %s", ", ".join(failed[:10]))
    cursor.close()


def main():
    parser = argparse.ArgumentParser(description="Sync database schema")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default: dry-run)")
    parser.add_argument("--fix-ownership", action="store_true", help="Fix table ownership")
    parser.add_argument("--fix-grants", action="store_true", help="Fix table grants")
    parser.add_argument("--all", action="store_true", help="Run all checks and fixes")
    args = parser.parse_args()

    dry_run = not args.apply

    # Load expected schema
    _load_expected_schema()

    # Connect to database
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "5432"))
    dbname = os.getenv("DB_NAME", "auditgraph")
    admin_user = os.getenv("DB_ADMIN_USER", os.getenv("DB_USER", "auditgraph"))
    admin_pass = os.getenv("DB_ADMIN_PASSWORD", os.getenv("DB_PASSWORD", "auditgraph"))
    sslmode = os.getenv("DB_SSLMODE", "prefer")
    app_user = os.getenv("DB_USER", admin_user)

    logger.info("Connecting to %s:%d/%s as %s ...", host, port, dbname, admin_user)

    conn = psycopg2.connect(
        host=host, port=port, database=dbname,
        user=admin_user, password=admin_pass,
        sslmode=sslmode, connect_timeout=10,
    )

    # Get current schema
    current = get_current_schema(conn)
    current_tables = get_current_tables(conn)

    logger.info("Expected: %d tables, %d columns",
                len(EXPECTED_COLUMNS),
                sum(len(cols) for cols in EXPECTED_COLUMNS.values()))
    logger.info("Current:  %d tables, %d columns",
                len(current),
                sum(len(cols) for cols in current.values()))

    # Compare
    changes = compare_schemas(EXPECTED_COLUMNS, current)

    if not changes["missing_tables"] and not changes["missing_columns"]:
        logger.info("Schema is in sync ✓")
    else:
        apply_changes(conn, changes, dry_run=dry_run)

    # Ownership
    if args.fix_ownership or args.all:
        fix_ownership(conn, admin_user, dry_run=dry_run)

    # Grants
    if args.fix_grants or args.all:
        if app_user != admin_user:
            fix_grants(conn, app_user, dry_run=dry_run)
        else:
            logger.info("Single-user mode — skipping grants.")

    conn.close()
    logger.info("Done.")


# ─── Embedded schema CSV (from localhost dump) ───────────────────────────────
# Format: table_name|column_name|data_type|max_len|default|nullable

SCHEMA_CSV = r"""
access_review_campaigns|id|integer||nextval('access_review_campaigns_id_seq'::regclass)|NO
access_review_campaigns|name|character varying|255||NO
access_review_campaigns|description|text|||YES
access_review_campaigns|status|character varying|20|'active'::character varying|NO
access_review_campaigns|scope_filters|jsonb||'{}'::jsonb|NO
access_review_campaigns|deadline|timestamp with time zone|||YES
access_review_campaigns|created_by|integer|||NO
access_review_campaigns|created_at|timestamp with time zone||now()|NO
access_review_campaigns|updated_at|timestamp with time zone||now()|NO
access_review_campaigns|completed_at|timestamp with time zone|||YES
access_review_campaigns|organization_id|integer|||YES
access_review_campaigns|campaign_type|character varying|100|'general'::character varying|YES
access_review_campaigns|scope_clouds|ARRAY|||YES
access_review_campaigns|scope_description|character varying|500||YES
access_review_campaigns|risk_focus|character varying|100||YES
access_reviews|id|integer||nextval('access_reviews_id_seq'::regclass)|NO
access_reviews|review_id|uuid||gen_random_uuid()|NO
access_reviews|organization_id|integer|||NO
access_reviews|title|text|||NO
access_reviews|description|text|||YES
access_reviews|review_type|character varying|30|'manual'::character varying|NO
access_reviews|scope|character varying|30|'privileged'::character varying|NO
access_reviews|status|character varying|20|'open'::character varying|NO
access_reviews|created_by|character varying|100||YES
access_reviews|created_by_user_id|integer|||YES
access_reviews|total_assignments|integer||0|NO
access_reviews|completed_assignments|integer||0|NO
access_reviews|approved_count|integer||0|NO
access_reviews|revoked_count|integer||0|NO
access_reviews|flagged_count|integer||0|NO
access_reviews|due_date|timestamp with time zone|||YES
access_reviews|completed_at|timestamp with time zone|||YES
access_reviews|completed_by|character varying|100||YES
access_reviews|compliance_frameworks|jsonb||'[]'::jsonb|YES
access_reviews|settings|jsonb||'{}'::jsonb|YES
access_reviews|created_at|timestamp with time zone||now()|NO
access_reviews|updated_at|timestamp with time zone||now()|NO
access_reviews|review_outcome|text|||YES
access_reviews|review_duration_hours|integer|||YES
activity_log|id|integer||nextval('activity_log_id_seq'::regclass)|NO
activity_log|action_type|character varying|50||NO
activity_log|description|text|||NO
activity_log|metadata|jsonb|||YES
activity_log|created_at|timestamp with time zone||now()|NO
activity_log|user_id|integer|||YES
activity_log|organization_id|integer|||YES
activity_log|integrity_hash|character varying|64||YES
admin_audit_log|id|integer||nextval('admin_audit_log_id_seq'::regclass)|NO
admin_audit_log|admin_user_id|integer|||YES
admin_audit_log|action|text|||NO
admin_audit_log|target_user_id|integer|||YES
admin_audit_log|target_organization_id|integer|||YES
admin_audit_log|details|jsonb||'{}'::jsonb|YES
admin_audit_log|ip_address|text|||YES
admin_audit_log|created_at|timestamp with time zone||now()|YES
agirs_scores|id|integer||nextval('agirs_scores_id_seq'::regclass)|NO
agirs_scores|organization_id|integer|||NO
agirs_scores|run_id|integer|||YES
agirs_scores|agirs_score|numeric|||YES
agirs_scores|hiri_score|numeric|||YES
agirs_scores|nhiri_score|numeric|||YES
agirs_scores|gei_score|numeric|||YES
agirs_scores|hiri_breakdown|jsonb|||YES
agirs_scores|nhiri_breakdown|jsonb|||YES
agirs_scores|gei_breakdown|jsonb|||YES
agirs_scores|dangerous_identities|jsonb|||YES
agirs_scores|human_count|integer|||YES
agirs_scores|nhi_count|integer|||YES
agirs_scores|created_at|timestamp with time zone||now()|YES
anomalies|id|integer||nextval('anomalies_id_seq'::regclass)|NO
anomalies|discovery_run_id|integer|||YES
anomalies|anomaly_type|character varying|50||NO
anomalies|severity|character varying|20|'medium'::character varying|NO
anomalies|identity_id|text|||YES
anomalies|identity_name|character varying|255||YES
anomalies|title|character varying|255||NO
anomalies|description|text|||NO
anomalies|details|jsonb|||YES
anomalies|resolved|boolean||false|YES
anomalies|resolved_at|timestamp with time zone|||YES
anomalies|resolved_by|character varying|100||YES
anomalies|created_at|timestamp with time zone||now()|NO
anomalies|organization_id|integer|||YES
api_keys|id|integer||nextval('api_keys_id_seq'::regclass)|NO
api_keys|key_prefix|character varying|12||NO
api_keys|key_hash|character varying|64||NO
api_keys|name|character varying|255||NO
api_keys|description|text|||YES
api_keys|role|character varying|20|'viewer'::character varying|NO
api_keys|enabled|boolean||true|YES
api_keys|created_by|integer|||YES
api_keys|created_at|timestamp with time zone||now()|NO
api_keys|last_used_at|timestamp with time zone|||YES
api_keys|expires_at|timestamp with time zone|||YES
api_keys|usage_count|integer||0|NO
api_keys|organization_id|integer|||YES
app_reg_exposure_findings|id|integer||nextval('app_reg_exposure_findings_id_seq'::regclass)|NO
app_reg_exposure_findings|app_reg_id|bigint|||NO
app_reg_exposure_findings|discovery_run_id|bigint|||YES
app_reg_exposure_findings|finding_type|character varying|50||NO
app_reg_exposure_findings|severity|character varying|20||NO
app_reg_exposure_findings|title|text|||NO
app_reg_exposure_findings|description|text|||YES
app_reg_exposure_findings|evidence|jsonb||'{}'::jsonb|YES
app_reg_exposure_findings|remediation|text|||YES
app_reg_exposure_findings|component|character varying|30||YES
app_reg_exposure_findings|score_impact|integer||0|YES
app_reg_exposure_findings|organization_id|integer|||NO
app_reg_exposure_findings|created_at|timestamp with time zone||now()|YES
app_registrations|id|integer||nextval('app_registrations_id_seq'::regclass)|NO
app_registrations|discovery_run_id|integer|||NO
app_registrations|app_object_id|text|||NO
app_registrations|app_id|text|||NO
app_registrations|display_name|text|||NO
app_registrations|created_datetime|timestamp with time zone|||YES
app_registrations|sign_in_audience|text|||YES
app_registrations|publisher_domain|text|||YES
app_registrations|app_owner_organization_id|text|||YES
app_registrations|is_third_party|boolean||false|YES
app_registrations|required_permissions|jsonb||'[]'::jsonb|YES
app_registrations|permission_count|integer||0|YES
app_registrations|application_permission_count|integer||0|YES
app_registrations|delegated_permission_count|integer||0|YES
app_registrations|high_risk_permissions|ARRAY||'{}'::text[]|YES
app_registrations|secret_count|integer||0|YES
app_registrations|certificate_count|integer||0|YES
app_registrations|credential_details|jsonb||'[]'::jsonb|YES
app_registrations|next_expiry|timestamp with time zone|||YES
app_registrations|has_expired_credential|boolean||false|YES
app_registrations|has_expiring_soon|boolean||false|YES
app_registrations|owner_count|integer||0|YES
app_registrations|owners|jsonb||'[]'::jsonb|YES
app_registrations|primary_owner|text|||YES
app_registrations|has_service_principal|boolean||false|YES
app_registrations|linked_spn_id|integer|||YES
app_registrations|spn_last_sign_in|timestamp with time zone|||YES
app_registrations|spn_activity_status|text|||YES
app_registrations|redirect_uris|jsonb||'[]'::jsonb|YES
app_registrations|redirect_uri_count|integer||0|YES
app_registrations|has_localhost_redirect|boolean||false|YES
app_registrations|has_http_redirect|boolean||false|YES
app_registrations|risk_level|text||'info'::text|YES
app_registrations|risk_score|integer||0|YES
app_registrations|risk_reasons|jsonb||'[]'::jsonb|YES
app_registrations|approval_status|text||'unknown'::text|YES
app_registrations|organization_id|integer|||YES
app_registrations|created_at|timestamp with time zone||now()|YES
app_registrations|exposure_score|integer||0|YES
app_registrations|exposure_components|jsonb||'{}'::jsonb|YES
app_registrations|privilege_score|integer||0|YES
app_registrations|credential_risk_score|integer||0|YES
app_registrations|exposure_subscore|integer||0|YES
app_registrations|lifecycle_score|integer||0|YES
app_registrations|visibility_score|integer||0|YES
app_registrations|activity_confidence|integer||0|YES
app_registrations|lifecycle_state|character varying|20|'blind'::character varying|YES
app_registrations|can_escalate|boolean||false|YES
app_registrations|effective_scope_flag|character varying|30|'resource'::character varying|YES
app_registrations|credential_age_days|integer||0|YES
app_registrations|owner_status|character varying|20|'unknown'::character varying|YES
app_registrations|federated_trust|boolean||false|YES
app_registrations|cross_subscription|boolean||false|YES
app_registrations|exposure_computed_at|timestamp without time zone|||YES
app_registrations|critical_exposure_overrides|jsonb||'[]'::jsonb|YES
attack_paths|id|integer||nextval('attack_paths_id_seq'::regclass)|NO
attack_paths|path_id|uuid||gen_random_uuid()|NO
attack_paths|organization_id|integer|||NO
attack_paths|discovery_run_id|integer|||YES
attack_paths|source_entity_id|text|||NO
attack_paths|source_entity_name|text|||YES
attack_paths|source_entity_type|character varying|30||YES
attack_paths|path_type|character varying|60||NO
attack_paths|risk_score|integer||0|NO
attack_paths|severity|character varying|20|'medium'::character varying|NO
attack_paths|path_nodes|jsonb||'[]'::jsonb|NO
attack_paths|description|text|||NO
attack_paths|narrative|text|||YES
attack_paths|impact|text|||YES
attack_paths|created_at|timestamp with time zone||now()|NO
attack_paths|path_fingerprint|text|||YES
attack_paths|first_detected_at|timestamp with time zone||now()|NO
attack_paths|last_detected_at|timestamp with time zone||now()|NO
attack_paths|occurrence_count|integer||1|NO
attack_paths|last_seen_run_id|integer|||YES
attack_paths|affected_resource_count|integer||0|NO
azure_key_vaults|id|integer||nextval('azure_key_vaults_id_seq'::regclass)|NO
azure_key_vaults|discovery_run_id|integer|||NO
azure_key_vaults|resource_id|text|||NO
azure_key_vaults|name|text|||NO
azure_key_vaults|location|text|||YES
azure_key_vaults|resource_group|text|||YES
azure_key_vaults|subscription_id|text|||YES
azure_key_vaults|subscription_name|text|||YES
azure_key_vaults|sku|text|||YES
azure_key_vaults|soft_delete_enabled|boolean||false|YES
azure_key_vaults|soft_delete_retention_days|integer||0|YES
azure_key_vaults|purge_protection|boolean||false|YES
azure_key_vaults|enable_rbac_authorization|boolean||false|YES
azure_key_vaults|public_network_access|text||'Enabled'::text|YES
azure_key_vaults|default_network_action|text||'Allow'::text|YES
azure_key_vaults|ip_rules_count|integer||0|YES
azure_key_vaults|vnet_rules_count|integer||0|YES
azure_key_vaults|private_endpoint_count|integer||0|YES
azure_key_vaults|network_rules|jsonb||'{}'::jsonb|YES
azure_key_vaults|secrets_total|integer||0|YES
azure_key_vaults|secrets_expired|integer||0|YES
azure_key_vaults|secrets_expiring_soon|integer||0|YES
azure_key_vaults|keys_total|integer||0|YES
azure_key_vaults|keys_expired|integer||0|YES
azure_key_vaults|keys_expiring_soon|integer||0|YES
azure_key_vaults|certs_total|integer||0|YES
azure_key_vaults|certs_expired|integer||0|YES
azure_key_vaults|certs_expiring_soon|integer||0|YES
azure_key_vaults|access_policy_count|integer||0|YES
azure_key_vaults|access_policies|jsonb||'[]'::jsonb|YES
azure_key_vaults|secrets_detail|jsonb||'[]'::jsonb|YES
azure_key_vaults|keys_detail|jsonb||'[]'::jsonb|YES
azure_key_vaults|certs_detail|jsonb||'[]'::jsonb|YES
azure_key_vaults|risk_level|text||'info'::text|YES
azure_key_vaults|risk_score|integer||0|YES
azure_key_vaults|risk_reasons|jsonb||'[]'::jsonb|YES
azure_key_vaults|tags|jsonb||'{}'::jsonb|YES
azure_key_vaults|organization_id|integer|||YES
azure_key_vaults|created_at|timestamp with time zone||now()|YES
azure_key_vaults|risk_components|jsonb||'{}'::jsonb|YES
azure_key_vaults|blast_radius_score|integer||0|YES
azure_key_vaults|critical_overrides|jsonb||'[]'::jsonb|YES
azure_key_vaults|data_classification|character varying|20||YES
azure_key_vaults|classification_source|character varying|20||YES
azure_key_vaults|classification_confidence|character varying|10||YES
azure_key_vaults|classified_by|character varying|100||YES
azure_key_vaults|classified_at|timestamp with time zone|||YES
azure_key_vaults|classification_notes|text|||YES
azure_storage_accounts|id|integer||nextval('azure_storage_accounts_id_seq'::regclass)|NO
azure_storage_accounts|discovery_run_id|integer|||NO
azure_storage_accounts|resource_id|text|||NO
azure_storage_accounts|name|text|||NO
azure_storage_accounts|location|text|||YES
azure_storage_accounts|resource_group|text|||YES
azure_storage_accounts|subscription_id|text|||YES
azure_storage_accounts|subscription_name|text|||YES
azure_storage_accounts|sku|text|||YES
azure_storage_accounts|kind|text|||YES
azure_storage_accounts|access_tier|text|||YES
azure_storage_accounts|public_blob_access|boolean||false|YES
azure_storage_accounts|https_only|boolean||true|YES
azure_storage_accounts|minimum_tls_version|text||'TLS1_2'::text|YES
azure_storage_accounts|shared_key_access|boolean||true|YES
azure_storage_accounts|allow_cross_tenant_replication|boolean||false|YES
azure_storage_accounts|default_network_action|text||'Allow'::text|YES
azure_storage_accounts|ip_rules_count|integer||0|YES
azure_storage_accounts|vnet_rules_count|integer||0|YES
azure_storage_accounts|private_endpoint_count|integer||0|YES
azure_storage_accounts|bypass_settings|text|||YES
azure_storage_accounts|network_rules|jsonb||'{}'::jsonb|YES
azure_storage_accounts|infrastructure_encryption|boolean||false|YES
azure_storage_accounts|customer_managed_keys|boolean||false|YES
azure_storage_accounts|key_vault_uri|text|||YES
azure_storage_accounts|encryption_details|jsonb||'{}'::jsonb|YES
azure_storage_accounts|key1_created_at|timestamp with time zone|||YES
azure_storage_accounts|key2_created_at|timestamp with time zone|||YES
azure_storage_accounts|key_rotation_stale|boolean||false|YES
azure_storage_accounts|sas_policy_enabled|boolean|||YES
azure_storage_accounts|sas_expiration_period|text|||YES
azure_storage_accounts|risk_level|text||'info'::text|YES
azure_storage_accounts|risk_score|integer||0|YES
azure_storage_accounts|risk_reasons|jsonb||'[]'::jsonb|YES
azure_storage_accounts|tags|jsonb||'{}'::jsonb|YES
azure_storage_accounts|organization_id|integer|||YES
azure_storage_accounts|created_at|timestamp with time zone||now()|YES
azure_storage_accounts|diagnostic_logging_enabled|boolean|||YES
azure_storage_accounts|logging_destinations|jsonb||'[]'::jsonb|YES
azure_storage_accounts|risk_components|jsonb||'{}'::jsonb|YES
azure_storage_accounts|blast_radius_score|integer||0|YES
azure_storage_accounts|critical_overrides|jsonb||'[]'::jsonb|YES
azure_storage_accounts|data_classification|character varying|20||YES
azure_storage_accounts|classification_source|character varying|20||YES
azure_storage_accounts|classification_confidence|character varying|10||YES
azure_storage_accounts|classified_by|character varying|100||YES
azure_storage_accounts|classified_at|timestamp with time zone|||YES
azure_storage_accounts|classification_notes|text|||YES
billing_audit_log|id|integer||nextval('billing_audit_log_id_seq'::regclass)|NO
billing_audit_log|organization_id|integer|||NO
billing_audit_log|action|character varying|50||NO
billing_audit_log|actor_id|integer|||YES
billing_audit_log|details|jsonb||'{}'::jsonb|NO
billing_audit_log|created_at|timestamp with time zone||now()|NO
billing_events|id|integer||nextval('billing_events_id_seq'::regclass)|NO
billing_events|organization_id|integer|||NO
billing_events|event_type|character varying|50||NO
billing_events|field_changed|character varying|50||YES
billing_events|old_value|text|||YES
billing_events|new_value|text|||YES
billing_events|changed_by|integer|||YES
billing_events|metadata|jsonb||'{}'::jsonb|YES
billing_events|created_at|timestamp with time zone||now()|NO
blast_radius_results|id|integer||nextval('blast_radius_results_id_seq'::regclass)|NO
blast_radius_results|result_id|uuid||gen_random_uuid()|NO
blast_radius_results|organization_id|integer|||NO
blast_radius_results|identity_id|integer|||NO
blast_radius_results|identity_name|text|||YES
blast_radius_results|identity_type|text|||YES
blast_radius_results|discovery_run_id|integer|||YES
blast_radius_results|reachable_resource_count|integer||0|NO
blast_radius_results|reachable_subscription_count|integer||0|NO
blast_radius_results|reachable_resource_group_count|integer||0|NO
blast_radius_results|sensitive_resource_count|integer||0|NO
blast_radius_results|sensitive_data_types|jsonb||'[]'::jsonb|YES
blast_radius_results|resource_breakdown|jsonb||'{}'::jsonb|YES
blast_radius_results|privilege_escalation_paths|integer||0|NO
blast_radius_results|risk_domain|text||'identity'::text|NO
blast_radius_results|identity_exposure_level|text||'LOW'::text|NO
blast_radius_results|blast_radius_reduction|integer||0|NO
blast_radius_results|remediation_confidence|text|||YES
blast_radius_results|risk_score|integer||0|NO
blast_radius_results|created_at|timestamp with time zone||now()|NO
ca_identity_coverage|id|integer||nextval('ca_identity_coverage_id_seq'::regclass)|NO
ca_identity_coverage|identity_db_id|integer|||NO
ca_identity_coverage|coverage_status|text|||NO
ca_identity_coverage|mfa_enforced|boolean||false|YES
ca_identity_coverage|applicable_policy_count|integer||0|YES
ca_identity_coverage|excluded_from_count|integer||0|YES
ca_identity_coverage|risk_flags|jsonb||'[]'::jsonb|YES
ca_identity_coverage|organization_id|integer|||YES
ca_policies|id|integer||nextval('ca_policies_id_seq'::regclass)|NO
ca_policies|discovery_run_id|integer|||NO
ca_policies|policy_id|text|||NO
ca_policies|display_name|text|||NO
ca_policies|state|text|||NO
ca_policies|include_users|jsonb||'[]'::jsonb|YES
ca_policies|exclude_users|jsonb||'[]'::jsonb|YES
ca_policies|include_applications|jsonb||'[]'::jsonb|YES
ca_policies|client_app_types|jsonb||'[]'::jsonb|YES
ca_policies|grant_controls|jsonb||'{}'::jsonb|YES
ca_policies|session_controls|jsonb||'{}'::jsonb|YES
ca_policies|requires_mfa|boolean||false|YES
ca_policies|targets_all_users|boolean||false|YES
ca_policies|has_exclusions|boolean||false|YES
ca_policies|allows_legacy_auth|boolean||false|YES
ca_policies|modified_datetime|timestamp with time zone|||YES
ca_policies|organization_id|integer|||YES
campaign_audit_log|id|integer||nextval('campaign_audit_log_id_seq'::regclass)|NO
campaign_audit_log|campaign_id|integer|||NO
campaign_audit_log|review_id|integer|||YES
campaign_audit_log|action|character varying|100||NO
campaign_audit_log|actor_id|integer|||YES
campaign_audit_log|old_value|text|||YES
campaign_audit_log|new_value|text|||YES
campaign_audit_log|metadata|jsonb||'{}'::jsonb|YES
campaign_audit_log|created_at|timestamp with time zone||now()|YES
campaign_audit_log|organization_id|integer|||YES
campaign_reviews|id|integer||nextval('campaign_reviews_id_seq'::regclass)|NO
campaign_reviews|campaign_id|integer|||NO
campaign_reviews|identity_id|text|||NO
campaign_reviews|identity_display_name|text|||YES
campaign_reviews|identity_risk_level|character varying|20||YES
campaign_reviews|identity_category|character varying|100||YES
campaign_reviews|reviewer_id|integer|||YES
campaign_reviews|decision|character varying|20||YES
campaign_reviews|notes|text|||YES
campaign_reviews|decided_at|timestamp with time zone|||YES
campaign_reviews|created_at|timestamp with time zone||now()|NO
campaign_reviews|identity_db_id|integer|||YES
campaign_reviews|identity_type|character varying|100||YES
campaign_reviews|access_role|character varying|255||YES
campaign_reviews|access_scope|character varying|500||YES
campaign_reviews|cloud_provider|character varying|50||YES
campaign_reviews|risk_score|integer|||YES
campaign_reviews|risk_factors|jsonb||'[]'::jsonb|YES
campaign_reviews|last_used_date|timestamp with time zone|||YES
campaign_reviews|last_used_days|integer|||YES
campaign_reviews|privilege_level|character varying|50||YES
campaign_reviews|credential_risk|character varying|255||YES
campaign_reviews|credential_risk_level|character varying|50||YES
campaign_reviews|ai_recommendation|character varying|100||YES
campaign_reviews|ai_recommendation_reason|text|||YES
campaign_reviews|decision_by|integer|||YES
campaign_reviews|review_due_date|timestamp with time zone|||YES
campaign_reviews|updated_at|timestamp with time zone||now()|YES
campaign_reviews|organization_id|integer|||YES
cloud_connections|id|integer||nextval('cloud_connections_id_seq'::regclass)|NO
cloud_connections|organization_id|integer|||NO
cloud_connections|cloud|character varying|20|'azure'::character varying|NO
cloud_connections|connection_type|character varying|30|'entra'::character varying|NO
cloud_connections|label|character varying|255||NO
cloud_connections|azure_directory_id|character varying|100||YES
cloud_connections|client_id|character varying|100||YES
cloud_connections|status|character varying|20|'pending'::character varying|NO
cloud_connections|display_order|integer||0|NO
cloud_connections|last_test_at|timestamp with time zone|||YES
cloud_connections|last_test_status|character varying|20||YES
cloud_connections|last_discovery_at|timestamp with time zone|||YES
cloud_connections|metadata|jsonb||'{}'::jsonb|YES
cloud_connections|created_at|timestamp with time zone||now()|NO
cloud_connections|updated_at|timestamp with time zone||now()|YES
cloud_connections|external_id|character varying|500||YES
cloud_connections|discovered_count|integer||0|YES
cloud_subscriptions|id|integer||nextval('cloud_subscriptions_id_seq'::regclass)|NO
cloud_subscriptions|organization_id|integer|||NO
cloud_subscriptions|cloud|character varying|20||NO
cloud_subscriptions|account_id|character varying|255||NO
cloud_subscriptions|account_name|character varying|500||YES
cloud_subscriptions|status|character varying|20|'discovered'::character varying|YES
cloud_subscriptions|monitored|boolean||false|YES
cloud_subscriptions|activated_at|timestamp with time zone|||YES
cloud_subscriptions|activated_by|integer|||YES
cloud_subscriptions|created_at|timestamp with time zone||now()|YES
cloud_subscriptions|rate_cents|integer||6900|NO
cloud_subscriptions|discovered_at|timestamp with time zone||now()|YES
cloud_subscriptions|cloud_connection_id|integer|||NO
cloud_subscriptions|deleted|boolean||false|YES
cloud_subscriptions|deleted_at|timestamp with time zone|||YES
cloud_subscriptions|stripe_subscription_item_id|character varying|100||YES
compliance_controls|id|integer||nextval('compliance_controls_id_seq'::regclass)|NO
compliance_controls|framework_id|integer|||NO
compliance_controls|control_id|character varying|50||NO
compliance_controls|name|character varying|255||NO
compliance_controls|description|text|||YES
compliance_controls|metric|character varying|50||NO
compliance_controls|pass_operator|character varying|10||NO
compliance_controls|pass_value|numeric|||NO
compliance_controls|warn_operator|character varying|10||YES
compliance_controls|warn_value|numeric|||YES
compliance_controls|drilldown_url|character varying|255||YES
compliance_controls|display_order|integer||100|YES
compliance_controls|severity|character varying|20|'medium'::character varying|YES
compliance_controls|weight|integer||5|YES
compliance_controls|cloud|character varying|20|'azure'::character varying|YES
compliance_controls|pillar|character varying|50||YES
compliance_controls|root_cause_id|integer|||YES
compliance_frameworks|id|integer||nextval('compliance_frameworks_id_seq'::regclass)|NO
compliance_frameworks|key|character varying|50||NO
compliance_frameworks|name|character varying|100||NO
compliance_frameworks|description|text|||YES
compliance_frameworks|version|character varying|50||YES
compliance_frameworks|enabled|boolean||true|YES
compliance_frameworks|display_order|integer||100|YES
compliance_frameworks|created_at|timestamp with time zone||now()|YES
compliance_frameworks|tier|character varying|20|'core'::character varying|YES
compliance_frameworks|category|character varying|50||YES
compliance_frameworks|short_name|character varying|30||YES
compliance_frameworks|identity_controls_count|integer||0|YES
compliance_frameworks|total_framework_controls|integer||0|YES
compliance_frameworks|scope_label|character varying|255|'Identity, access, and privilege controls'::character varying|YES
compliance_root_causes|id|integer||nextval('compliance_root_causes_id_seq'::regclass)|NO
compliance_root_causes|code|character varying|50||NO
compliance_root_causes|title|character varying|255||NO
compliance_root_causes|description|text|||YES
compliance_root_causes|category|character varying|50||YES
compliance_root_causes|recommendation|text|||YES
compliance_root_causes|display_order|integer||100|YES
compliance_snapshots|id|integer||nextval('compliance_snapshots_id_seq'::regclass)|NO
compliance_snapshots|run_id|integer|||NO
compliance_snapshots|framework_key|character varying|50||NO
compliance_snapshots|framework_name|character varying|100||NO
compliance_snapshots|score|integer|||NO
compliance_snapshots|pass_count|integer||0|NO
compliance_snapshots|warn_count|integer||0|NO
compliance_snapshots|fail_count|integer||0|NO
compliance_snapshots|total_controls|integer||0|NO
compliance_snapshots|metrics|jsonb|||YES
compliance_snapshots|created_at|timestamp with time zone||now()|YES
compliance_snapshots|organization_id|integer|||YES
copilot_conversations|id|integer||nextval('copilot_conversations_id_seq'::regclass)|NO
copilot_conversations|user_id|integer|||YES
copilot_conversations|organization_id|integer|||YES
copilot_conversations|title|text|||YES
copilot_conversations|messages|jsonb||'[]'::jsonb|YES
copilot_conversations|created_at|timestamp without time zone||now()|YES
copilot_conversations|updated_at|timestamp without time zone||now()|YES
credentials|id|bigint||nextval('credentials_id_seq'::regclass)|NO
credentials|identity_db_id|bigint|||NO
credentials|credential_type|text|||NO
credentials|key_id|text|||NO
credentials|display_name|text|||YES
credentials|start_datetime|timestamp with time zone|||YES
credentials|end_datetime|timestamp with time zone|||YES
credentials|thumbprint|text|||YES
credentials|issuer|text|||YES
credentials|subject|text|||YES
credentials|discovered_at|timestamp with time zone||now()|NO
credentials|organization_id|integer|||YES
custom_risk_rules|id|integer||nextval('custom_risk_rules_id_seq'::regclass)|NO
custom_risk_rules|name|character varying|255||NO
custom_risk_rules|description|text|||YES
custom_risk_rules|conditions|jsonb|||NO
custom_risk_rules|action_type|character varying|20|'adjust_points'::character varying|NO
custom_risk_rules|points_adjustment|integer||0|YES
custom_risk_rules|force_level|character varying|20||YES
custom_risk_rules|reason_text|text|||YES
custom_risk_rules|enabled|boolean||true|YES
custom_risk_rules|priority|integer||100|YES
custom_risk_rules|created_at|timestamp with time zone||now()|YES
custom_risk_rules|updated_at|timestamp with time zone||now()|YES
custom_risk_rules|organization_id|integer|||YES
dashboard_preferences|id|integer||nextval('dashboard_preferences_id_seq'::regclass)|NO
dashboard_preferences|user_id|integer|||NO
dashboard_preferences|preferences|jsonb||'{}'::jsonb|NO
dashboard_preferences|created_at|timestamp with time zone||now()|NO
dashboard_preferences|updated_at|timestamp with time zone||now()|YES
dashboard_preferences|organization_id|integer|||YES
discovery_integrity_metrics|id|integer||nextval('discovery_integrity_metrics_id_seq'::regclass)|NO
discovery_integrity_metrics|metric_id|uuid||gen_random_uuid()|NO
discovery_integrity_metrics|organization_id|integer|||NO
discovery_integrity_metrics|discovery_run_id|integer|||YES
discovery_integrity_metrics|identities_count|integer||0|YES
discovery_integrity_metrics|resources_count|integer||0|YES
discovery_integrity_metrics|role_assignments_count|integer||0|YES
discovery_integrity_metrics|recorded_at|timestamp with time zone||now()|NO
discovery_runs|id|bigint||nextval('discovery_runs_id_seq'::regclass)|NO
discovery_runs|subscription_id|text|||NO
discovery_runs|subscription_name|text|||YES
discovery_runs|started_at|timestamp with time zone||now()|NO
discovery_runs|completed_at|timestamp with time zone|||YES
discovery_runs|status|text|||NO
discovery_runs|total_identities|integer|||YES
discovery_runs|critical_count|integer|||YES
discovery_runs|high_count|integer|||YES
discovery_runs|medium_count|integer|||YES
discovery_runs|low_count|integer|||YES
discovery_runs|created_at|timestamp with time zone||now()|NO
discovery_runs|organization_id|integer|||YES
discovery_runs|cloud_connection_id|integer|||NO
discovery_runs|snapshot_hash|character varying|64||YES
discovery_runs|snapshot_signature|character varying|64||YES
drift_reports|id|integer||nextval('drift_reports_id_seq'::regclass)|NO
drift_reports|current_run_id|integer|||NO
drift_reports|previous_run_id|integer|||NO
drift_reports|new_identities_count|integer||0|NO
drift_reports|removed_identities_count|integer||0|NO
drift_reports|permission_changes_count|integer||0|NO
drift_reports|risk_changes_count|integer||0|NO
drift_reports|credential_changes_count|integer||0|NO
drift_reports|total_changes|integer||0|NO
drift_reports|changes|jsonb|||NO
drift_reports|created_at|timestamp with time zone||now()|NO
drift_reports|events|jsonb||'[]'::jsonb|YES
drift_reports|organization_id|integer|||YES
entra_role_assignments|id|bigint||nextval('entra_role_assignments_id_seq'::regclass)|NO
entra_role_assignments|identity_db_id|bigint|||YES
entra_role_assignments|role_name|text|||NO
entra_role_assignments|role_definition_id|text|||YES
entra_role_assignments|directory_scope|text|||YES
entra_role_assignments|created_at|timestamp with time zone||now()|NO
entra_role_assignments|organization_id|integer|||YES
entra_role_assignments|usage_status|text||'unknown'::text|YES
entra_role_assignments|assigned_on|timestamp with time zone|||YES
entra_role_assignments|days_since_assigned|integer|||YES
entra_role_assignments|redundant_with|text|||YES
entra_role_assignments|role_type|text||'entra'::text|YES
entra_role_assignments|risk_level|text|||YES
entra_role_assignments|why_critical|text|||YES
fix_recommendations|id|integer||nextval('fix_recommendations_id_seq'::regclass)|NO
fix_recommendations|recommendation_id|uuid||gen_random_uuid()|NO
fix_recommendations|organization_id|integer|||NO
fix_recommendations|discovery_run_id|integer|||YES
fix_recommendations|entity_id|text|||NO
fix_recommendations|entity_type|character varying|30||NO
fix_recommendations|entity_name|text|||YES
fix_recommendations|fix_type|character varying|60||NO
fix_recommendations|title|text|||NO
fix_recommendations|description|text|||NO
fix_recommendations|fix_category|character varying|40||NO
fix_recommendations|priority_score|integer||0|NO
fix_recommendations|effort|character varying|10|'medium'::character varying|NO
fix_recommendations|steps|jsonb||'[]'::jsonb|NO
fix_recommendations|azure_cli_commands|text|||YES
fix_recommendations|compliance_refs|jsonb||'{}'::jsonb|YES
fix_recommendations|linked_finding_types|jsonb||'[]'::jsonb|YES
fix_recommendations|linked_path_types|jsonb||'[]'::jsonb|YES
fix_recommendations|linked_finding_count|integer||0|NO
fix_recommendations|linked_path_count|integer||0|NO
fix_recommendations|status|character varying|20|'open'::character varying|NO
fix_recommendations|status_changed_by|character varying|100||YES
fix_recommendations|status_changed_at|timestamp with time zone|||YES
fix_recommendations|assigned_to|character varying|100||YES
fix_recommendations|recommendation_fingerprint|text|||YES
fix_recommendations|first_detected_at|timestamp with time zone||now()|NO
fix_recommendations|last_detected_at|timestamp with time zone||now()|NO
fix_recommendations|occurrence_count|integer||1|NO
fix_recommendations|created_at|timestamp with time zone||now()|NO
fix_recommendations|risk_reduction_score|integer||0|YES
fix_recommendations|finding_id|integer|||YES
fix_recommendations|attack_path_id|integer|||YES
governance_decisions|id|integer||nextval('governance_decisions_id_seq'::regclass)|NO
governance_decisions|identity_db_id|integer|||NO
governance_decisions|identity_id|text|||NO
governance_decisions|decision|character varying|50||NO
governance_decisions|reason|text|||YES
governance_decisions|risk_score_snapshot|integer|||YES
governance_decisions|risk_band_snapshot|character varying|20||YES
governance_decisions|risk_factors_snapshot|jsonb||'[]'::jsonb|YES
governance_decisions|access_snapshot|jsonb||'[]'::jsonb|YES
governance_decisions|decided_by|integer|||NO
governance_decisions|exception_expiry|timestamp with time zone|||YES
governance_decisions|organization_id|integer|||YES
governance_decisions|created_at|timestamp with time zone||now()|NO
graph_api_permissions|id|bigint||nextval('graph_api_permissions_id_seq'::regclass)|NO
graph_api_permissions|identity_db_id|bigint|||NO
graph_api_permissions|permission_name|text|||NO
graph_api_permissions|permission_description|text|||YES
graph_api_permissions|resource_name|text||'Microsoft Graph'::text|YES
graph_api_permissions|risk_level|text|||YES
graph_api_permissions|discovered_at|timestamp with time zone||now()|NO
graph_api_permissions|organization_id|integer|||YES
human_identities|id|integer||nextval('human_identities_id_seq'::regclass)|NO
human_identities|organization_id|integer|||NO
human_identities|display_name|character varying|500||YES
human_identities|employee_id|character varying|255||YES
human_identities|department|character varying|255||YES
human_identities|manager_id|character varying|255||YES
human_identities|employment_status|character varying|50|'active'::character varying|YES
human_identities|status_determined_at|timestamp with time zone|||YES
human_identities|status_source|character varying|100||YES
human_identities|created_at|timestamp with time zone||now()|NO
human_identities|updated_at|timestamp with time zone||now()|NO
identities|id|bigint||nextval('identities_id_seq'::regclass)|NO
identities|discovery_run_id|bigint|||YES
identities|identity_id|text|||NO
identities|display_name|text|||NO
identities|source|text||'azure'::text|NO
identities|identity_type|text|||NO
identities|identity_category|text||'service_principal'::text|NO
identities|app_id|text|||YES
identities|object_id|text|||YES
identities|entra_object_type|text|||YES
identities|service_principal_type|text|||YES
identities|publisher_name|text|||YES
identities|app_owner_organization_id|text|||YES
identities|alternative_names|jsonb|||YES
identities|created_datetime|timestamp with time zone|||YES
identities|enabled|boolean||true|YES
identities|is_microsoft_system|boolean||false|YES
identities|risk_level|text|||YES
identities|risk_reasons|ARRAY|||YES
identities|credential_expiration|timestamp with time zone|||YES
identities|credential_status|text|||YES
identities|last_sign_in|timestamp with time zone|||YES
identities|activity_status|text|||YES
identities|tags|jsonb|||YES
identities|created_at|timestamp with time zone||now()|NO
identities|primary_subscription_id|text|||YES
identities|additional_subscription_count|integer||0|YES
identities|app_owner_org_id|text|||YES
identities|permission_plane|character varying|50||YES
identities|deleted_at|timestamp with time zone|||YES
identities|exposure_score|integer||0|YES
identities|exposure_components|jsonb||'{}'::jsonb|YES
identities|privilege_score|integer||0|YES
identities|credential_risk_score|integer||0|YES
identities|exposure_subscore|integer||0|YES
identities|lifecycle_score|integer||0|YES
identities|visibility_score|integer||0|YES
identities|activity_confidence|integer||0|YES
identities|lifecycle_state|character varying|20|'blind'::character varying|YES
identities|can_escalate|boolean||false|YES
identities|effective_scope_flag|character varying|30|'resource'::character varying|YES
identities|credential_age_days|integer||0|YES
identities|owner_status|character varying|20|'unknown'::character varying|YES
identities|federated_trust|boolean||false|YES
identities|cross_subscription|boolean||false|YES
identities|exposure_computed_at|timestamp without time zone|||YES
identities|critical_exposure_overrides|jsonb||'[]'::jsonb|YES
identities|organization_id|integer|||YES
identities|risk_factors|jsonb||'[]'::jsonb|YES
identities|upn|character varying|500||YES
identities|employee_id_entra|character varying|255||YES
identities|department|character varying|255||YES
identities|manager_id|character varying|255||YES
identities|manager_upn|character varying|500||YES
identities|job_title|character varying|255||YES
identities|account_category|character varying|50||YES
identities|credential_count|integer||0|YES
identities|next_expiry|timestamp with time zone|||YES
identities|credential_risk|text|||YES
identities|cloud|text||'azure'::text|YES
identities|identity_type_normalized|text|||YES
identities|canonical_name|text|||YES
identities|principal_id|text|||YES
identities|tenant_or_org_id|text|||YES
identities|source_normalized|text|||YES
identities|is_federated|boolean||false|YES
identities|status|text||'active'::text|YES
identities|last_seen_auth|timestamp with time zone|||YES
identities|owner_display_name|text|||YES
identities|owner_count|integer||0|YES
identities|risk_score|integer||0|YES
identities|api_permission_count|integer||0|YES
identities|app_role_count|integer||0|YES
identities|days_since_last_use|integer|||YES
identities|last_activity_source|text|||YES
identities|pim_eligible_count|integer||0|YES
identities|pim_active_count|integer||0|YES
identities|has_permanent_assignment|boolean||false|YES
identities|ca_coverage_status|text|||YES
identities|ca_mfa_enforced|boolean|||YES
identities|blast_radius_score|integer|||YES
identities|privilege_tier|character varying|20||YES
identity_group_members|id|integer||nextval('identity_group_members_id_seq'::regclass)|NO
identity_group_members|group_id|integer|||NO
identity_group_members|identity_id|text|||NO
identity_group_members|added_at|timestamp with time zone||now()|NO
identity_group_members|organization_id|integer|||YES
identity_groups|id|integer||nextval('identity_groups_id_seq'::regclass)|NO
identity_groups|name|character varying|255||NO
identity_groups|description|text|||YES
identity_groups|color|character varying|20|'#3B82F6'::character varying|YES
identity_groups|group_type|character varying|10|'custom'::character varying|NO
identity_groups|auto_criteria|jsonb|||YES
identity_groups|created_by|integer|||YES
identity_groups|created_at|timestamp with time zone||now()|NO
identity_groups|updated_at|timestamp with time zone||now()|NO
identity_groups|organization_id|integer|||YES
identity_links|id|integer||nextval('identity_links_id_seq'::regclass)|NO
identity_links|organization_id|integer|||NO
identity_links|human_identity_id|integer|||NO
identity_links|identity_db_id|integer|||YES
identity_links|account_type|character varying|50||NO
identity_links|account_upn|character varying|500||YES
identity_links|account_object_id|character varying|255||YES
identity_links|account_enabled|boolean||true|YES
identity_links|link_method|character varying|50|'naming_convention'::character varying|NO
identity_links|link_confidence|numeric||0|YES
identity_links|linked_at|timestamp with time zone||now()|NO
identity_links|linked_by|character varying|255||YES
identity_links|verified|boolean||false|YES
identity_links|verified_at|timestamp with time zone|||YES
identity_links|verified_by|character varying|255||YES
identity_roles|id|bigint||nextval('identity_roles_id_seq'::regclass)|NO
identity_roles|identity_db_id|bigint|||NO
identity_roles|role_name|text|||NO
identity_roles|role_type|text|||NO
identity_roles|scope|text|||YES
identity_roles|inherited|boolean||false|YES
identity_roles|created_at|timestamp with time zone||now()|YES
identity_roles|organization_id|integer|||YES
identity_subscription_access|id|bigint||nextval('identity_subscription_access_id_seq'::regclass)|NO
identity_subscription_access|identity_db_id|bigint|||NO
identity_subscription_access|identity_id|text|||NO
identity_subscription_access|subscription_id|text|||NO
identity_subscription_access|subscription_name|text|||YES
identity_subscription_access|rbac_role|text|||NO
identity_subscription_access|scope|text|||YES
identity_subscription_access|scope_type|text|||YES
identity_subscription_access|risk_level|text|||YES
identity_subscription_access|last_activity|timestamp with time zone|||YES
identity_subscription_access|discovered_at|timestamp with time zone||now()|YES
identity_subscription_access|discovery_run_id|bigint|||YES
identity_subscription_access|organization_id|integer|||YES
invoice_documents|id|integer||nextval('invoice_documents_id_seq'::regclass)|NO
invoice_documents|organization_id|integer|||NO
invoice_documents|invoice_id|integer|||YES
invoice_documents|snapshot_id|integer|||YES
invoice_documents|document_type|character varying|20|'invoice'::character varying|NO
invoice_documents|file_name|character varying|255||NO
invoice_documents|content_type|character varying|100|'application/pdf'::character varying|NO
invoice_documents|file_data|bytea|||YES
invoice_documents|file_size|integer|||YES
invoice_documents|generated_by|integer|||YES
invoice_documents|generated_at|timestamp with time zone||now()|NO
invoice_documents|immutable|boolean||true|NO
invoices|id|integer||nextval('invoices_id_seq'::regclass)|NO
invoices|organization_id|integer|||NO
invoices|invoice_number|character varying|50||NO
invoices|status|character varying|20|'draft'::character varying|NO
invoices|period_start|date|||NO
invoices|period_end|date|||NO
invoices|subtotal_cents|integer||0|NO
invoices|tax_label|character varying|50||YES
invoices|tax_rate|numeric||0|NO
invoices|tax_amount_cents|integer||0|NO
invoices|discount_cents|integer||0|NO
invoices|total_cents|integer||0|NO
invoices|line_items|jsonb||'[]'::jsonb|NO
invoices|seller_snapshot|jsonb||'{}'::jsonb|NO
invoices|buyer_snapshot|jsonb||'{}'::jsonb|NO
invoices|issued_at|timestamp with time zone|||YES
invoices|due_at|timestamp with time zone|||YES
invoices|paid_at|timestamp with time zone|||YES
invoices|voided_at|timestamp with time zone|||YES
invoices|notes|text|||YES
invoices|payment_terms|integer||30|NO
invoices|created_by|integer|||YES
invoices|created_at|timestamp with time zone||now()|NO
invoices|updated_at|timestamp with time zone||now()|YES
invoices|content_hash|character varying|64||YES
job_runs|id|integer||nextval('job_runs_id_seq'::regclass)|NO
job_runs|job_id|uuid||gen_random_uuid()|NO
job_runs|organization_id|integer|||YES
job_runs|job_type|text|||NO
job_runs|status|text||'queued'::text|NO
job_runs|started_at|timestamp with time zone|||YES
job_runs|completed_at|timestamp with time zone|||YES
job_runs|duration_ms|integer|||YES
job_runs|error_message|text|||YES
job_runs|metadata|jsonb||'{}'::jsonb|YES
job_runs|created_at|timestamp with time zone||now()|NO
msp_relationships|id|integer||nextval('msp_relationships_id_seq'::regclass)|NO
msp_relationships|msp_organization_id|integer|||NO
msp_relationships|client_organization_id|integer|||NO
msp_relationships|margin_pct|numeric||0|NO
msp_relationships|status|character varying|20|'active'::character varying|NO
msp_relationships|created_at|timestamp with time zone||now()|NO
notifications|id|integer||nextval('notifications_id_seq'::regclass)|NO
notifications|event_type|character varying|50||NO
notifications|category|character varying|30||NO
notifications|severity|character varying|20|'info'::character varying|NO
notifications|title|character varying|255||NO
notifications|description|text|||NO
notifications|payload|jsonb|||YES
notifications|related_identity_id|text|||YES
notifications|related_identity_name|character varying|255||YES
notifications|related_run_id|integer|||YES
notifications|read|boolean||false|YES
notifications|read_at|timestamp with time zone|||YES
notifications|actioned|boolean||false|YES
notifications|action_type|character varying|50||YES
notifications|action_at|timestamp with time zone|||YES
notifications|created_at|timestamp with time zone||now()|NO
notifications|organization_id|integer|||YES
organization_billing_snapshots|id|integer||nextval('organization_billing_snapshots_id_seq'::regclass)|NO
organization_billing_snapshots|organization_id|integer|||NO
organization_billing_snapshots|period_start|date|||NO
organization_billing_snapshots|period_end|date|||NO
organization_billing_snapshots|plan|character varying|20||NO
organization_billing_snapshots|platform_fee_cents|integer||0|NO
organization_billing_snapshots|subscription_total_cents|integer||0|NO
organization_billing_snapshots|gross_cents|integer||0|NO
organization_billing_snapshots|discount_pct|numeric||0|NO
organization_billing_snapshots|discount_cents|integer||0|NO
organization_billing_snapshots|net_cents|integer||0|NO
organization_billing_snapshots|tax_rate|numeric||0|NO
organization_billing_snapshots|tax_cents|integer||0|NO
organization_billing_snapshots|total_cents|integer||0|NO
organization_billing_snapshots|active_subscriptions|integer||0|NO
organization_billing_snapshots|breakdown|jsonb||'{}'::jsonb|NO
organization_billing_snapshots|created_at|timestamp with time zone||now()|NO
organization_billing_snapshots|pricing_version|character varying|20||YES
organization_billing_snapshots|unit_prices|jsonb||'{}'::jsonb|YES
organization_entitlements|id|integer||nextval('organization_entitlements_id_seq'::regclass)|NO
organization_entitlements|organization_id|integer|||NO
organization_entitlements|feature_key|character varying|100||NO
organization_entitlements|enabled|boolean||true|NO
organization_entitlements|granted_by|integer|||YES
organization_entitlements|granted_at|timestamp with time zone||now()|NO
organization_entitlements|expires_at|timestamp with time zone|||YES
organization_entitlements|reason|text|||YES
organization_usage|id|integer||nextval('organization_usage_id_seq'::regclass)|NO
organization_usage|organization_id|integer|||NO
organization_usage|resource_type|character varying|50||NO
organization_usage|resource_id|character varying|255||YES
organization_usage|action|character varying|20||NO
organization_usage|metadata|jsonb||'{}'::jsonb|YES
organization_usage|created_at|timestamp with time zone||now()|NO
organization_usage_counters|id|integer||nextval('organization_usage_counters_id_seq'::regclass)|NO
organization_usage_counters|organization_id|integer|||NO
organization_usage_counters|resource_type|character varying|50||NO
organization_usage_counters|current_count|integer||0|NO
organization_usage_counters|updated_at|timestamp with time zone||now()|NO
organizations|id|integer||nextval('organizations_id_seq'::regclass)|NO
organizations|name|character varying|255||NO
organizations|slug|character varying|100||NO
organizations|plan|character varying|20|'free'::character varying|NO
organizations|settings|jsonb||'{}'::jsonb|NO
organizations|enabled|boolean||true|YES
organizations|created_at|timestamp with time zone||now()|NO
organizations|updated_at|timestamp with time zone||now()|YES
organizations|license_activated_at|timestamp with time zone|||YES
organizations|license_expires_at|timestamp with time zone|||YES
organizations|logo_url|text|||YES
organizations|subscription_term|integer||0|NO
organizations|primary_cloud|character varying|20||YES
organizations|industry|character varying|100||YES
organizations|compliance_framework|character varying|100||YES
organizations|status|character varying|20|'active'::character varying|NO
organizations|onboarding_stage|character varying|20|'active'::character varying|NO
organizations|platform_fee_cents|integer||20000|NO
organizations|discount_pct|numeric||0|NO
organizations|trial_expires_at|timestamp with time zone|||YES
organizations|billing_status|character varying|20|'active'::character varying|NO
organizations|tax_label|character varying|50|'Tax'::character varying|NO
organizations|tax_rate|numeric||0|NO
organizations|tax_id|character varying|100||YES
organizations|tax_exempt|boolean||false|NO
organizations|tax_notes|text|||YES
organizations|payment_terms|integer||30|NO
organizations|billing_company|character varying|255||YES
organizations|billing_address_line1|character varying|255||YES
organizations|billing_address_line2|character varying|255||YES
organizations|billing_city|character varying|100||YES
organizations|billing_state|character varying|100||YES
organizations|billing_postal_code|character varying|20||YES
organizations|billing_country|character varying|100||YES
organizations|billing_email|character varying|255||YES
organizations|stripe_customer_id|character varying|100||YES
organizations|stripe_subscription_id|character varying|100||YES
organizations|plan_type|character varying|20|'self_serve'::character varying|NO
organizations|plan_status|character varying|20|'active'::character varying|NO
organizations|subscription_limit|integer|||YES
organizations|enforcement_mode|character varying|20|'strict'::character varying|NO
organizations|trial_started_at|timestamp with time zone|||YES
organizations|is_demo|boolean||false|YES
orphaned_privileged_findings|id|integer||nextval('orphaned_privileged_findings_id_seq'::regclass)|NO
orphaned_privileged_findings|organization_id|integer|||NO
orphaned_privileged_findings|discovery_run_id|integer|||YES
orphaned_privileged_findings|human_identity_id|integer|||YES
orphaned_privileged_findings|regular_link_id|integer|||YES
orphaned_privileged_findings|privileged_link_id|integer|||YES
orphaned_privileged_findings|regular_upn|character varying|500||YES
orphaned_privileged_findings|regular_object_id|character varying|255||YES
orphaned_privileged_findings|privileged_upn|character varying|500||YES
orphaned_privileged_findings|privileged_object_id|character varying|255||YES
orphaned_privileged_findings|severity|character varying|20|'high'::character varying|NO
orphaned_privileged_findings|azure_roles|ARRAY|||YES
orphaned_privileged_findings|role_count|integer||0|YES
orphaned_privileged_findings|highest_role_privilege|character varying|100||YES
orphaned_privileged_findings|subscription_count|integer||0|YES
orphaned_privileged_findings|has_activity_after_disable|boolean||false|YES
orphaned_privileged_findings|days_since_regular_disabled|integer|||YES
orphaned_privileged_findings|status|character varying|50|'open'::character varying|NO
orphaned_privileged_findings|acknowledged_at|timestamp with time zone|||YES
orphaned_privileged_findings|acknowledged_by|character varying|255||YES
orphaned_privileged_findings|remediated_at|timestamp with time zone|||YES
orphaned_privileged_findings|remediated_by|character varying|255||YES
orphaned_privileged_findings|remediation_action|text|||YES
orphaned_privileged_findings|suppressed_at|timestamp with time zone|||YES
orphaned_privileged_findings|suppressed_by|character varying|255||YES
orphaned_privileged_findings|suppression_reason|text|||YES
orphaned_privileged_findings|compliance_reference|character varying|255|'HIPAA §164.312(a)(2)(iii)'::character varying|YES
orphaned_privileged_findings|days_out_of_compliance|integer||0|YES
orphaned_privileged_findings|remediation_commands|jsonb||'{}'::jsonb|YES
orphaned_privileged_findings|created_at|timestamp with time zone||now()|NO
orphaned_privileged_findings|updated_at|timestamp with time zone||now()|NO
pim_activations|id|integer||nextval('pim_activations_id_seq'::regclass)|NO
pim_activations|identity_db_id|integer|||NO
pim_activations|role_name|text|||NO
pim_activations|role_definition_id|text|||YES
pim_activations|directory_scope|text||'/'::text|YES
pim_activations|status|text|||YES
pim_activations|activation_start|timestamp with time zone|||YES
pim_activations|activation_end|timestamp with time zone|||YES
pim_activations|justification|text|||YES
pim_activations|ticket_number|text|||YES
pim_activations|ticket_system|text|||YES
pim_activations|is_approval_required|boolean||false|YES
pim_activations|created_datetime|timestamp with time zone|||YES
pim_activations|discovered_at|timestamp with time zone||now()|YES
pim_eligible_assignments|id|integer||nextval('pim_eligible_assignments_id_seq'::regclass)|NO
pim_eligible_assignments|identity_db_id|integer|||NO
pim_eligible_assignments|role_name|text|||NO
pim_eligible_assignments|role_definition_id|text|||YES
pim_eligible_assignments|directory_scope|text||'/'::text|YES
pim_eligible_assignments|assignment_type|text||'eligible'::text|YES
pim_eligible_assignments|start_datetime|timestamp with time zone|||YES
pim_eligible_assignments|end_datetime|timestamp with time zone|||YES
pim_eligible_assignments|member_type|text|||YES
pim_eligible_assignments|discovered_at|timestamp with time zone||now()|YES
plans|id|character varying|20||NO
plans|name|character varying|100||NO
plans|platform_fee_cents|integer||0|NO
plans|default_sub_rate_cents|integer||6900|NO
plans|max_subscriptions|integer|||YES
plans|max_identities|integer|||YES
plans|ai_features|boolean||false|NO
plans|trial_days|integer|||YES
plans|enabled|boolean||true|NO
plans|created_at|timestamp with time zone||now()|NO
platform_settings|key|character varying|100||NO
platform_settings|value|text|||YES
platform_settings|updated_at|timestamp with time zone||now()|YES
rbac_hygiene_scans|id|integer||nextval('rbac_hygiene_scans_id_seq'::regclass)|NO
rbac_hygiene_scans|score|integer||0|NO
rbac_hygiene_scans|grade|character varying|2|'F'::character varying|NO
rbac_hygiene_scans|total_assignments|integer||0|NO
rbac_hygiene_scans|total_findings|integer||0|NO
rbac_hygiene_scans|summary|jsonb||'{}'::jsonb|NO
rbac_hygiene_scans|findings|jsonb||'[]'::jsonb|NO
rbac_hygiene_scans|discovery_run_id|bigint|||YES
rbac_hygiene_scans|organization_id|integer|||NO
rbac_hygiene_scans|created_at|timestamp with time zone||now()|NO
refresh_tokens|id|integer||nextval('refresh_tokens_id_seq'::regclass)|NO
refresh_tokens|user_id|integer|||NO
refresh_tokens|token_hash|character varying|255||NO
refresh_tokens|expires_at|timestamp with time zone|||NO
refresh_tokens|created_at|timestamp with time zone||now()|NO
refresh_tokens|revoked|boolean||false|YES
refresh_tokens|portal|character varying|10|'client'::character varying|YES
remediation_actions|id|integer||nextval('remediation_actions_id_seq'::regclass)|NO
remediation_actions|identity_id|text|||NO
remediation_actions|playbook_id|integer|||NO
remediation_actions|status|character varying|20|'open'::character varying|NO
remediation_actions|notes|text|||YES
remediation_actions|created_at|timestamp with time zone||now()|NO
remediation_actions|updated_at|timestamp with time zone||now()|NO
remediation_actions|execution_status|character varying|20|NULL::character varying|YES
remediation_actions|execution_log|jsonb|||YES
remediation_actions|executed_at|timestamp with time zone|||YES
remediation_actions|executed_by|integer|||YES
remediation_actions|organization_id|integer|||YES
remediation_playbooks|id|integer||nextval('remediation_playbooks_id_seq'::regclass)|NO
remediation_playbooks|risk_pattern|character varying|255||NO
remediation_playbooks|pattern_type|character varying|20|'contains'::character varying|YES
remediation_playbooks|title|character varying|255||NO
remediation_playbooks|description|text|||YES
remediation_playbooks|steps|jsonb|||NO
remediation_playbooks|impact|character varying|10|'high'::character varying|YES
remediation_playbooks|effort|character varying|10|'medium'::character varying|YES
remediation_playbooks|priority_score|integer||50|YES
remediation_playbooks|compliance_refs|jsonb|||YES
remediation_playbooks|category|character varying|50||YES
remediation_playbooks|created_at|timestamp without time zone||now()|YES
report_outputs|id|integer||nextval('report_outputs_id_seq'::regclass)|NO
report_outputs|output_id|uuid||gen_random_uuid()|NO
report_outputs|run_id|integer|||NO
report_outputs|organization_id|integer|||NO
report_outputs|format|text||'json'::text|NO
report_outputs|storage_path|text|||YES
report_outputs|file_size_bytes|integer|||YES
report_outputs|created_at|timestamp with time zone||now()|NO
report_runs|id|integer||nextval('report_runs_id_seq'::regclass)|NO
report_runs|run_id|uuid||gen_random_uuid()|NO
report_runs|report_id|integer|||NO
report_runs|organization_id|integer|||NO
report_runs|status|text||'pending'::text|NO
report_runs|record_count|integer||0|YES
report_runs|error_message|text|||YES
report_runs|started_at|timestamp with time zone|||YES
report_runs|generated_at|timestamp with time zone|||YES
report_runs|created_at|timestamp with time zone||now()|NO
report_runs|generation_duration_ms|integer|||YES
report_runs|parameters|jsonb||'{}'::jsonb|YES
report_runs|expires_at|timestamp with time zone|||YES
reports|id|integer||nextval('reports_id_seq'::regclass)|NO
reports|report_id|uuid||gen_random_uuid()|NO
reports|organization_id|integer|||NO
reports|report_type|text|||NO
reports|title|text|||YES
reports|parameters|jsonb||'{}'::jsonb|YES
reports|created_by|integer|||YES
reports|created_by_username|character varying|100||YES
reports|created_at|timestamp with time zone||now()|NO
resource_findings|id|integer||nextval('resource_findings_id_seq'::regclass)|NO
resource_findings|discovery_run_id|integer|||NO
resource_findings|resource_id|text|||NO
resource_findings|resource_type|character varying|30||NO
resource_findings|component|character varying|50||NO
resource_findings|finding_key|character varying|200||NO
resource_findings|finding_title|text|||NO
resource_findings|points|integer||0|NO
resource_findings|severity|character varying|20|'low'::character varying|NO
resource_findings|is_critical_override|boolean||false|NO
resource_findings|metadata|jsonb||'{}'::jsonb|YES
resource_findings|organization_id|integer|||YES
resource_findings|created_at|timestamp with time zone||now()|NO
resource_risk_history|id|integer||nextval('resource_risk_history_id_seq'::regclass)|NO
resource_risk_history|discovery_run_id|integer|||NO
resource_risk_history|resource_id|text|||NO
resource_risk_history|resource_type|character varying|30||NO
resource_risk_history|risk_score|integer||0|NO
resource_risk_history|risk_level|character varying|20|'info'::character varying|NO
resource_risk_history|risk_components|jsonb||'{}'::jsonb|YES
resource_risk_history|critical_overrides|jsonb||'[]'::jsonb|YES
resource_risk_history|blast_radius_score|integer||0|YES
resource_risk_history|privileged_identity_count|integer||0|YES
resource_risk_history|dependency_count|integer||0|YES
resource_risk_history|network_exposure_score|integer||0|YES
resource_risk_history|organization_id|integer|||YES
resource_risk_history|created_at|timestamp with time zone||now()|NO
review_assignments|id|integer||nextval('review_assignments_id_seq'::regclass)|NO
review_assignments|assignment_id|uuid||gen_random_uuid()|NO
review_assignments|review_id|integer|||NO
review_assignments|organization_id|integer|||NO
review_assignments|identity_id|integer|||NO
review_assignments|identity_name|text|||YES
review_assignments|identity_type|character varying|30||YES
review_assignments|role_name|text|||NO
review_assignments|role_type|character varying|20|'rbac'::character varying|NO
review_assignments|scope|text|||YES
review_assignments|risk_level|character varying|20||YES
review_assignments|risk_score|integer||0|YES
review_assignments|blast_radius_score|integer||0|YES
review_assignments|attack_path_count|integer||0|YES
review_assignments|finding_count|integer||0|YES
review_assignments|reviewer|character varying|100||YES
review_assignments|reviewer_user_id|integer|||YES
review_assignments|decision|character varying|20|'pending'::character varying|NO
review_assignments|decision_reason|text|||YES
review_assignments|decision_at|timestamp with time zone|||YES
review_assignments|due_date|timestamp with time zone|||YES
review_assignments|created_at|timestamp with time zone||now()|NO
review_assignments|risk_snapshot|jsonb|||YES
review_evidence|id|integer||nextval('review_evidence_id_seq'::regclass)|NO
review_evidence|evidence_id|uuid||gen_random_uuid()|NO
review_evidence|assignment_id|integer|||NO
review_evidence|organization_id|integer|||NO
review_evidence|evidence_type|character varying|30||NO
review_evidence|source_id|text|||YES
review_evidence|title|text|||NO
review_evidence|detail|jsonb||'{}'::jsonb|YES
review_evidence|added_by|character varying|100||YES
review_evidence|added_at|timestamp with time zone||now()|NO
role_activity_log|id|bigint||nextval('role_activity_log_id_seq'::regclass)|NO
role_activity_log|identity_db_id|bigint|||NO
role_activity_log|role_name|text|||NO
role_activity_log|last_activity_date|timestamp with time zone|||YES
role_activity_log|days_since_last_use|integer|||YES
role_activity_log|created_at|timestamp with time zone||now()|NO
role_activity_log|organization_id|integer|||YES
role_assignments|id|bigint||nextval('role_assignments_id_seq'::regclass)|NO
role_assignments|identity_db_id|bigint|||YES
role_assignments|role_name|text|||NO
role_assignments|scope|text|||NO
role_assignments|scope_type|text|||NO
role_assignments|principal_id|text|||NO
role_assignments|assignment_id|text|||YES
role_assignments|created_on|timestamp with time zone|||YES
role_assignments|created_at|timestamp with time zone||now()|NO
role_assignments|organization_id|integer|||YES
role_assignments|scope_exists|boolean||true|YES
role_assignments|usage_status|text||'unknown'::text|YES
role_assignments|days_since_assigned|integer|||YES
role_assignments|redundant_with|text|||YES
role_assignments|role_type|text||'azure'::text|YES
role_assignments|risk_level|text|||YES
role_assignments|why_critical|text|||YES
role_assignments|resource_type|text|||YES
role_assignments|resource_name|text|||YES
role_attack_patterns|id|bigint||nextval('role_attack_patterns_id_seq'::regclass)|NO
role_attack_patterns|role_name|text|||NO
role_attack_patterns|attack_scenario|text|||NO
role_attack_patterns|real_world_example|text|||YES
role_attack_patterns|company_affected|text|||YES
role_attack_patterns|breach_year|integer|||YES
role_attack_patterns|estimated_cost_usd|bigint|||YES
role_attack_patterns|created_at|timestamp with time zone||now()|NO
role_hipaa_mappings|id|bigint||nextval('role_hipaa_mappings_id_seq'::regclass)|NO
role_hipaa_mappings|role_name|text|||NO
role_hipaa_mappings|hipaa_section|text|||NO
role_hipaa_mappings|violation_explanation|text|||YES
role_hipaa_mappings|violation_risk|text|||YES
role_hipaa_mappings|typical_penalty_min|bigint|||YES
role_hipaa_mappings|typical_penalty_max|bigint|||YES
role_hipaa_mappings|created_at|timestamp with time zone||now()|NO
role_permissions|id|bigint||nextval('role_permissions_id_seq'::regclass)|NO
role_permissions|role_name|text|||NO
role_permissions|role_type|text|||NO
role_permissions|privileged|boolean||false|YES
role_permissions|risk_level|text|||YES
role_permissions|description|text|||YES
role_permissions|why_critical|text|||YES
role_permissions|created_at|timestamp with time zone||now()|NO
sa_attestations|id|integer||nextval('sa_attestations_id_seq'::regclass)|NO
sa_attestations|identity_db_id|integer|||NO
sa_attestations|identity_id|text|||NO
sa_attestations|attested_by|integer|||NO
sa_attestations|status|character varying|30||NO
sa_attestations|justification|text|||YES
sa_attestations|attested_at|timestamp with time zone||now()|NO
sa_attestations|next_due|timestamp with time zone|||YES
sa_attestations|organization_id|integer|||YES
sa_attestations|created_at|timestamp with time zone||now()|NO
saved_views|id|integer||nextval('saved_views_id_seq'::regclass)|NO
saved_views|name|character varying|255||NO
saved_views|description|text|||YES
saved_views|filters|jsonb||'{}'::jsonb|NO
saved_views|sort_field|character varying|50||YES
saved_views|sort_direction|character varying|10|'desc'::character varying|YES
saved_views|is_default|boolean||false|YES
saved_views|is_shared|boolean||false|YES
saved_views|user_id|integer|||NO
saved_views|created_at|timestamp with time zone||now()|NO
saved_views|updated_at|timestamp with time zone||now()|YES
saved_views|organization_id|integer|||YES
scan_schedules|id|integer||nextval('scan_schedules_id_seq'::regclass)|NO
scan_schedules|organization_id|integer|||NO
scan_schedules|connection_id|integer|||YES
scan_schedules|label|character varying|100||YES
scan_schedules|frequency|character varying|20|'daily'::character varying|NO
scan_schedules|cron_expression|character varying|100|'0 2 * * *'::character varying|YES
scan_schedules|next_run_at|timestamp with time zone|||YES
scan_schedules|last_run_at|timestamp with time zone|||YES
scan_schedules|last_run_status|character varying|20||YES
scan_schedules|enabled|boolean||true|YES
scan_schedules|created_by|integer|||YES
scan_schedules|created_at|timestamp with time zone||now()|YES
scan_schedules|updated_at|timestamp with time zone||now()|YES
schema_migrations|version|text|||NO
schema_migrations|description|text||''::text|NO
schema_migrations|applied_at|timestamp with time zone||now()|NO
schema_migrations|checksum|text|||YES
security_findings|id|integer||nextval('security_findings_id_seq'::regclass)|NO
security_findings|finding_id|uuid||gen_random_uuid()|NO
security_findings|organization_id|integer|||NO
security_findings|entity_type|character varying|30||NO
security_findings|entity_id|text|||NO
security_findings|finding_type|character varying|60||NO
security_findings|severity|character varying|20||NO
security_findings|risk_score|integer||0|NO
security_findings|title|text|||NO
security_findings|description|text|||NO
security_findings|recommended_fix|text|||YES
security_findings|status|character varying|20|'open'::character varying|NO
security_findings|status_changed_by|character varying|100||YES
security_findings|status_changed_at|timestamp with time zone|||YES
security_findings|discovery_run_id|integer|||YES
security_findings|metadata|jsonb||'{}'::jsonb|YES
security_findings|created_at|timestamp with time zone||now()|NO
security_findings|finding_fingerprint|text|||YES
security_findings|first_detected_at|timestamp with time zone||now()|NO
security_findings|last_detected_at|timestamp with time zone||now()|NO
security_findings|occurrence_count|integer||1|NO
settings|id|integer||nextval('settings_id_seq'::regclass)|NO
settings|key|character varying|255||NO
settings|value|text|||YES
settings|organization_id|integer|||NO
settings|updated_at|timestamp with time zone||now()|NO
soar_actions|id|integer||nextval('soar_actions_id_seq'::regclass)|NO
soar_actions|playbook_id|integer|||YES
soar_actions|identity_id|text|||YES
soar_actions|anomaly_id|integer|||YES
soar_actions|trigger_event|jsonb|||YES
soar_actions|action_type|character varying|30||NO
soar_actions|integration|character varying|30||NO
soar_actions|status|character varying|20|'pending'::character varying|YES
soar_actions|result|jsonb|||YES
soar_actions|executed_at|timestamp with time zone|||YES
soar_actions|completed_at|timestamp with time zone|||YES
soar_actions|created_at|timestamp with time zone||now()|YES
soar_actions|organization_id|integer|||YES
soar_playbooks|id|integer||nextval('soar_playbooks_id_seq'::regclass)|NO
soar_playbooks|name|character varying|255||NO
soar_playbooks|description|text|||YES
soar_playbooks|enabled|boolean||true|YES
soar_playbooks|trigger_type|character varying|30||NO
soar_playbooks|trigger_conditions|jsonb||'{}'::jsonb|NO
soar_playbooks|action_type|character varying|30||NO
soar_playbooks|action_config|jsonb||'{}'::jsonb|NO
soar_playbooks|integration|character varying|30|'internal'::character varying|NO
soar_playbooks|cooldown_minutes|integer||60|YES
soar_playbooks|created_by|character varying|100||YES
soar_playbooks|created_at|timestamp with time zone||now()|YES
soar_playbooks|updated_at|timestamp with time zone||now()|YES
soar_playbooks|last_triggered_at|timestamp with time zone|||YES
soar_playbooks|trigger_count|integer||0|YES
soar_playbooks|organization_id|integer|||YES
sp_app_roles|id|bigint||nextval('sp_app_roles_id_seq'::regclass)|NO
sp_app_roles|identity_db_id|bigint|||NO
sp_app_roles|app_role_id|text|||NO
sp_app_roles|resource_id|text|||NO
sp_app_roles|resource_display_name|text|||YES
sp_app_roles|principal_display_name|text|||YES
sp_app_roles|created_date_time|timestamp with time zone|||YES
sp_app_roles|risk_level|text|||YES
sp_app_roles|discovered_at|timestamp with time zone||now()|NO
sp_app_roles|organization_id|integer|||YES
sp_ownership|id|bigint||nextval('sp_ownership_id_seq'::regclass)|NO
sp_ownership|identity_db_id|bigint|||NO
sp_ownership|owner_object_id|text|||NO
sp_ownership|owner_display_name|text|||YES
sp_ownership|owner_upn|text|||YES
sp_ownership|owner_type|text||'user'::text|YES
sp_ownership|ownership_type|text||'application'::text|YES
sp_ownership|is_primary_owner|boolean||false|YES
sp_ownership|discovered_at|timestamp with time zone||now()|NO
sp_ownership|organization_id|integer|||YES
spn_exposure_findings|id|integer||nextval('spn_exposure_findings_id_seq'::regclass)|NO
spn_exposure_findings|identity_db_id|bigint|||NO
spn_exposure_findings|discovery_run_id|bigint|||YES
spn_exposure_findings|finding_type|character varying|50||NO
spn_exposure_findings|severity|character varying|20||NO
spn_exposure_findings|title|text|||NO
spn_exposure_findings|description|text|||YES
spn_exposure_findings|evidence|jsonb||'{}'::jsonb|YES
spn_exposure_findings|remediation|text|||YES
spn_exposure_findings|component|character varying|30||YES
spn_exposure_findings|score_impact|integer||0|YES
spn_exposure_findings|organization_id|integer|||NO
spn_exposure_findings|created_at|timestamp with time zone||now()|YES
sso_auth_codes|id|integer||nextval('sso_auth_codes_id_seq'::regclass)|NO
sso_auth_codes|code|character varying|128||NO
sso_auth_codes|user_id|integer|||NO
sso_auth_codes|organization_id|integer|||YES
sso_auth_codes|used|boolean||false|YES
sso_auth_codes|created_at|timestamp with time zone||now()|YES
sso_auth_codes|expires_at|timestamp with time zone|||NO
system_health_metrics|id|integer||nextval('system_health_metrics_id_seq'::regclass)|NO
system_health_metrics|metric_id|uuid||gen_random_uuid()|NO
system_health_metrics|metric_name|text|||NO
system_health_metrics|metric_value|double precision|||NO
system_health_metrics|recorded_at|timestamp with time zone||now()|NO
tenant_health|organization_id|integer|||NO
tenant_health|last_discovery_run|timestamp with time zone|||YES
tenant_health|snapshot_age_hours|integer||0|YES
tenant_health|findings_count|integer||0|YES
tenant_health|critical_risks|integer||0|YES
tenant_health|blast_radius_critical|integer||0|YES
tenant_health|integrity_warning|boolean||false|YES
tenant_health|status|text||'stale'::text|NO
tenant_health|updated_at|timestamp with time zone||now()|NO
users|id|integer||nextval('users_id_seq'::regclass)|NO
users|username|character varying|100||NO
users|password_hash|character varying|255||NO
users|display_name|character varying|255||NO
users|role|character varying|20|'viewer'::character varying|NO
users|enabled|boolean||true|YES
users|created_at|timestamp with time zone||now()|NO
users|updated_at|timestamp with time zone||now()|YES
users|last_login_at|timestamp with time zone|||YES
users|created_by|integer|||YES
users|organization_id|integer|||YES
users|is_superadmin|boolean||false|YES
users|auth_provider|character varying|20|'local'::character varying|YES
users|external_id|character varying|500||YES
users|force_password_change|boolean||false|YES
users|is_root_user|boolean||false|YES
users|password_reset_token|text|||YES
users|password_reset_expires|timestamp with time zone|||YES
users|failed_login_attempts|integer||0|YES
users|locked_until|timestamp with time zone|||YES
users|portal_role|character varying|20||YES
users|email|character varying|255||YES
users|phone|character varying|50||YES
v_critical_identities|id|bigint|||YES
v_critical_identities|discovery_run_id|bigint|||YES
v_critical_identities|identity_id|text|||YES
v_critical_identities|display_name|text|||YES
v_critical_identities|source|text|||YES
v_critical_identities|identity_type|text|||YES
v_critical_identities|identity_category|text|||YES
v_critical_identities|app_id|text|||YES
v_critical_identities|object_id|text|||YES
v_critical_identities|entra_object_type|text|||YES
v_critical_identities|service_principal_type|text|||YES
v_critical_identities|publisher_name|text|||YES
v_critical_identities|app_owner_organization_id|text|||YES
v_critical_identities|alternative_names|jsonb|||YES
v_critical_identities|created_datetime|timestamp with time zone|||YES
v_critical_identities|enabled|boolean|||YES
v_critical_identities|is_microsoft_system|boolean|||YES
v_critical_identities|risk_level|text|||YES
v_critical_identities|risk_reasons|ARRAY|||YES
v_critical_identities|credential_expiration|timestamp with time zone|||YES
v_critical_identities|credential_status|text|||YES
v_critical_identities|last_sign_in|timestamp with time zone|||YES
v_critical_identities|activity_status|text|||YES
v_critical_identities|tags|jsonb|||YES
v_critical_identities|created_at|timestamp with time zone|||YES
v_critical_identities|primary_subscription_id|text|||YES
v_critical_identities|additional_subscription_count|integer|||YES
v_critical_identities|app_owner_org_id|text|||YES
v_critical_identities|permission_plane|character varying|50||YES
v_critical_identities|deleted_at|timestamp with time zone|||YES
v_critical_identities|exposure_score|integer|||YES
v_critical_identities|exposure_components|jsonb|||YES
v_critical_identities|privilege_score|integer|||YES
v_critical_identities|credential_risk_score|integer|||YES
v_critical_identities|exposure_subscore|integer|||YES
v_critical_identities|lifecycle_score|integer|||YES
v_critical_identities|visibility_score|integer|||YES
v_critical_identities|activity_confidence|integer|||YES
v_critical_identities|lifecycle_state|character varying|20||YES
v_critical_identities|can_escalate|boolean|||YES
v_critical_identities|effective_scope_flag|character varying|30||YES
v_critical_identities|credential_age_days|integer|||YES
v_critical_identities|owner_status|character varying|20||YES
v_critical_identities|federated_trust|boolean|||YES
v_critical_identities|cross_subscription|boolean|||YES
v_critical_identities|exposure_computed_at|timestamp without time zone|||YES
v_critical_identities|critical_exposure_overrides|jsonb|||YES
v_critical_identities|organization_id|integer|||YES
v_critical_identities|risk_factors|jsonb|||YES
v_critical_identities|upn|character varying|500||YES
v_critical_identities|employee_id_entra|character varying|255||YES
v_critical_identities|department|character varying|255||YES
v_critical_identities|manager_id|character varying|255||YES
v_critical_identities|manager_upn|character varying|500||YES
v_critical_identities|job_title|character varying|255||YES
v_critical_identities|account_category|character varying|50||YES
v_critical_identities|credential_count|integer|||YES
v_critical_identities|next_expiry|timestamp with time zone|||YES
v_critical_identities|credential_risk|text|||YES
v_critical_identities|cloud|text|||YES
v_critical_identities|identity_type_normalized|text|||YES
v_critical_identities|canonical_name|text|||YES
v_critical_identities|principal_id|text|||YES
v_critical_identities|tenant_or_org_id|text|||YES
v_critical_identities|source_normalized|text|||YES
v_critical_identities|is_federated|boolean|||YES
v_critical_identities|status|text|||YES
v_critical_identities|last_seen_auth|timestamp with time zone|||YES
v_critical_identities|owner_display_name|text|||YES
v_critical_identities|owner_count|integer|||YES
v_critical_identities|risk_score|integer|||YES
v_critical_identities|api_permission_count|integer|||YES
v_critical_identities|app_role_count|integer|||YES
v_critical_identities|days_since_last_use|integer|||YES
v_critical_identities|last_activity_source|text|||YES
v_critical_identities|pim_eligible_count|integer|||YES
v_critical_identities|pim_active_count|integer|||YES
v_critical_identities|has_permanent_assignment|boolean|||YES
v_critical_identities|ca_coverage_status|text|||YES
v_critical_identities|ca_mfa_enforced|boolean|||YES
v_critical_identities|blast_radius_score|integer|||YES
v_latest_identities|id|bigint|||YES
v_latest_identities|discovery_run_id|bigint|||YES
v_latest_identities|identity_id|text|||YES
v_latest_identities|display_name|text|||YES
v_latest_identities|source|text|||YES
v_latest_identities|identity_type|text|||YES
v_latest_identities|identity_category|text|||YES
v_latest_identities|app_id|text|||YES
v_latest_identities|object_id|text|||YES
v_latest_identities|entra_object_type|text|||YES
v_latest_identities|service_principal_type|text|||YES
v_latest_identities|publisher_name|text|||YES
v_latest_identities|app_owner_organization_id|text|||YES
v_latest_identities|alternative_names|jsonb|||YES
v_latest_identities|created_datetime|timestamp with time zone|||YES
v_latest_identities|enabled|boolean|||YES
v_latest_identities|is_microsoft_system|boolean|||YES
v_latest_identities|risk_level|text|||YES
v_latest_identities|risk_reasons|ARRAY|||YES
v_latest_identities|credential_expiration|timestamp with time zone|||YES
v_latest_identities|credential_status|text|||YES
v_latest_identities|last_sign_in|timestamp with time zone|||YES
v_latest_identities|activity_status|text|||YES
v_latest_identities|tags|jsonb|||YES
v_latest_identities|created_at|timestamp with time zone|||YES
v_latest_identities|primary_subscription_id|text|||YES
v_latest_identities|additional_subscription_count|integer|||YES
v_latest_identities|app_owner_org_id|text|||YES
v_latest_identities|permission_plane|character varying|50||YES
v_latest_identities|deleted_at|timestamp with time zone|||YES
v_latest_identities|exposure_score|integer|||YES
v_latest_identities|exposure_components|jsonb|||YES
v_latest_identities|privilege_score|integer|||YES
v_latest_identities|credential_risk_score|integer|||YES
v_latest_identities|exposure_subscore|integer|||YES
v_latest_identities|lifecycle_score|integer|||YES
v_latest_identities|visibility_score|integer|||YES
v_latest_identities|activity_confidence|integer|||YES
v_latest_identities|lifecycle_state|character varying|20||YES
v_latest_identities|can_escalate|boolean|||YES
v_latest_identities|effective_scope_flag|character varying|30||YES
v_latest_identities|credential_age_days|integer|||YES
v_latest_identities|owner_status|character varying|20||YES
v_latest_identities|federated_trust|boolean|||YES
v_latest_identities|cross_subscription|boolean|||YES
v_latest_identities|exposure_computed_at|timestamp without time zone|||YES
v_latest_identities|critical_exposure_overrides|jsonb|||YES
v_latest_identities|organization_id|integer|||YES
v_latest_identities|risk_factors|jsonb|||YES
v_latest_identities|upn|character varying|500||YES
v_latest_identities|employee_id_entra|character varying|255||YES
v_latest_identities|department|character varying|255||YES
v_latest_identities|manager_id|character varying|255||YES
v_latest_identities|manager_upn|character varying|500||YES
v_latest_identities|job_title|character varying|255||YES
v_latest_identities|account_category|character varying|50||YES
v_latest_identities|credential_count|integer|||YES
v_latest_identities|next_expiry|timestamp with time zone|||YES
v_latest_identities|credential_risk|text|||YES
v_latest_identities|cloud|text|||YES
v_latest_identities|identity_type_normalized|text|||YES
v_latest_identities|canonical_name|text|||YES
v_latest_identities|principal_id|text|||YES
v_latest_identities|tenant_or_org_id|text|||YES
v_latest_identities|source_normalized|text|||YES
v_latest_identities|is_federated|boolean|||YES
v_latest_identities|status|text|||YES
v_latest_identities|last_seen_auth|timestamp with time zone|||YES
v_latest_identities|owner_display_name|text|||YES
v_latest_identities|owner_count|integer|||YES
v_latest_identities|risk_score|integer|||YES
v_latest_identities|api_permission_count|integer|||YES
v_latest_identities|app_role_count|integer|||YES
v_latest_identities|days_since_last_use|integer|||YES
v_latest_identities|last_activity_source|text|||YES
v_latest_identities|pim_eligible_count|integer|||YES
v_latest_identities|pim_active_count|integer|||YES
v_latest_identities|has_permanent_assignment|boolean|||YES
v_latest_identities|ca_coverage_status|text|||YES
v_latest_identities|ca_mfa_enforced|boolean|||YES
v_latest_identities|blast_radius_score|integer|||YES
webhook_deliveries|id|integer||nextval('webhook_deliveries_id_seq'::regclass)|NO
webhook_deliveries|webhook_id|integer|||YES
webhook_deliveries|event_type|character varying|50||NO
webhook_deliveries|payload|jsonb|||NO
webhook_deliveries|status|character varying|20|'pending'::character varying|YES
webhook_deliveries|http_status|integer|||YES
webhook_deliveries|response_body|text|||YES
webhook_deliveries|attempts|integer||0|YES
webhook_deliveries|next_retry_at|timestamp with time zone|||YES
webhook_deliveries|created_at|timestamp with time zone||now()|YES
webhook_deliveries|delivered_at|timestamp with time zone|||YES
webhook_deliveries|organization_id|integer|||YES
webhooks|id|integer||nextval('webhooks_id_seq'::regclass)|NO
webhooks|name|character varying|255||NO
webhooks|url|text|||NO
webhooks|secret|character varying|255||YES
webhooks|event_types|ARRAY||'{}'::text[]|NO
webhooks|headers|jsonb|||YES
webhooks|enabled|boolean||true|YES
webhooks|created_at|timestamp with time zone||now()|YES
webhooks|updated_at|timestamp with time zone||now()|YES
webhooks|organization_id|integer|||YES
workload_activity_stats|id|bigint||nextval('workload_activity_stats_id_seq'::regclass)|NO
workload_activity_stats|organization_id|integer|||NO
workload_activity_stats|identity_db_id|bigint|||YES
workload_activity_stats|identity_id|text|||NO
workload_activity_stats|period_start|date|||NO
workload_activity_stats|period_end|date|||NO
workload_activity_stats|total_sign_ins|integer||0|YES
workload_activity_stats|successful_sign_ins|integer||0|YES
workload_activity_stats|failed_sign_ins|integer||0|YES
workload_activity_stats|unique_resources|integer||0|YES
workload_activity_stats|unique_ips|integer||0|YES
workload_activity_stats|unique_locations|integer||0|YES
workload_activity_stats|peak_hour|integer|||YES
workload_activity_stats|off_hours_pct|real||0|YES
workload_activity_stats|avg_daily_sign_ins|real||0|YES
workload_activity_stats|risk_sign_ins|integer||0|YES
workload_activity_stats|ca_failures|integer||0|YES
workload_activity_stats|discovery_run_id|bigint|||YES
workload_activity_stats|computed_at|timestamp with time zone||now()|YES
workload_anomaly_events|id|bigint||nextval('workload_anomaly_events_id_seq'::regclass)|NO
workload_anomaly_events|organization_id|integer|||NO
workload_anomaly_events|identity_db_id|bigint|||YES
workload_anomaly_events|identity_id|text|||NO
workload_anomaly_events|anomaly_type|text|||NO
workload_anomaly_events|severity|text|||NO
workload_anomaly_events|title|text|||NO
workload_anomaly_events|description|text|||YES
workload_anomaly_events|evidence|jsonb||'{}'::jsonb|YES
workload_anomaly_events|baseline|jsonb||'{}'::jsonb|YES
workload_anomaly_events|detected_value|jsonb||'{}'::jsonb|YES
workload_anomaly_events|resolved|boolean||false|YES
workload_anomaly_events|resolved_at|timestamp with time zone|||YES
workload_anomaly_events|resolved_by|text|||YES
workload_anomaly_events|discovery_run_id|bigint|||YES
workload_anomaly_events|created_at|timestamp with time zone||now()|YES
workload_signin_events|id|bigint||nextval('workload_signin_events_id_seq'::regclass)|NO
workload_signin_events|organization_id|integer|||NO
workload_signin_events|identity_db_id|bigint|||YES
workload_signin_events|identity_id|text|||NO
workload_signin_events|sign_in_id|text|||YES
workload_signin_events|created_datetime|timestamp with time zone|||NO
workload_signin_events|status|text|||NO
workload_signin_events|error_code|integer|||YES
workload_signin_events|failure_reason|text|||YES
workload_signin_events|resource_display_name|text|||YES
workload_signin_events|resource_id|text|||YES
workload_signin_events|ip_address|text|||YES
workload_signin_events|location_city|text|||YES
workload_signin_events|location_country|text|||YES
workload_signin_events|app_display_name|text|||YES
workload_signin_events|client_app_type|text|||YES
workload_signin_events|is_interactive|boolean||false|YES
workload_signin_events|risk_level|text|||YES
workload_signin_events|risk_detail|text|||YES
workload_signin_events|conditional_access_status|text|||YES
workload_signin_events|discovery_run_id|bigint|||YES
workload_signin_events|ingested_at|timestamp with time zone||now()|YES
"""

if __name__ == "__main__":
    main()
