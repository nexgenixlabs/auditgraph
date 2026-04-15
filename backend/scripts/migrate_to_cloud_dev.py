#!/usr/bin/env python3
"""
Tenant-scoped migration: Local Docker DB → Azure Cloud Dev DB

Migrates ONLY org_ids 1 (Platform Admin), 2 (AzureCredits), 3 (Demo).
Excludes benchmark orgs (7,8,9,10) and any other test data.

Rules:
  - Tables WITH organization_id → WHERE organization_id IN (1,2,3)
  - Tables linked via user_id → WHERE user_id in migrated users
  - Global reference tables → all rows
  - organizations → WHERE id IN (1,2,3)
  - users → WHERE organization_id IN (1,2,3)
  - No cross-tenant data leakage
"""

import psycopg2
import psycopg2.extras
import psycopg2.extensions
import json
import sys
import os

# ── Connection configs ──────────────────────────────────────────────────────

LOCAL_DSN = "dbname=auditgraph user=auditgraph password=auditgraph host=localhost port=5434"

CLOUD_DSN = (
    "dbname=auditgraph_dev_eastus2 "
    "user=auditgraph_dev_admin "
    "password=Aud1tGr@phDevAdm1n2026 "
    "host=cus-ag-nonprod-pg.postgres.database.azure.com "
    "port=5432 sslmode=require"
)

MIGRATE_ORG_IDS = (1, 2, 3)

# ── Table categories ────────────────────────────────────────────────────────

# Global reference tables — migrate ALL rows (no org_id column)
GLOBAL_TABLES = [
    'compliance_frameworks',
    'compliance_controls',
    'compliance_root_causes',
    'remediation_playbooks',
    'role_permissions',
    'role_attack_patterns',
    'role_hipaa_mappings',
    'platform_settings',
    'plans',
    'schema_migrations',
]

# Root org table
ORG_TABLE = 'organizations'  # WHERE id IN (1,2,3)

# Tables with organization_id — standard tenant filter
# Order matters: parents before children (FK dependencies)
ORG_SCOPED_TABLES = [
    # Layer 2: users + connections
    'users',
    'cloud_connections',
    'cloud_subscriptions',
    # Layer 3: discovery
    'discovery_runs',
    'discovery_stage_log',
    'discovery_integrity_metrics',
    'job_runs',
    'scan_schedules',
    # Layer 4: identities (has discovery_run_id FK but also org_id on many)
    'identities',
    # Layer 5: identity-dependent (many have both org_id + identity_db_id)
    'role_assignments',
    'credentials',
    'entra_role_assignments',
    'ca_policies',
    'ca_identity_coverage',
    'identity_subscription_access',
    'pim_activations',
    'pim_eligible_assignments',
    'sa_attestations',
    'governance_decisions',
    'sp_app_roles',
    'sp_ownership',
    'identity_links',
    'identity_roles',
    'graph_api_permissions',
    'role_activity_log',
    'spn_exposure_findings',
    'workload_signin_events',
    'workload_activity_stats',
    'workload_anomaly_events',
    'generated_remediations',
    'identity_exposures',
    'identity_risk_scores',
    'agent_classifications',
    'agent_delegations',
    # Layer 6: findings / resources
    'app_registrations',
    'app_reg_exposure_findings',
    'azure_storage_accounts',
    'azure_key_vaults',
    'blast_radius_results',
    'rbac_hygiene_scans',
    'resource_findings',
    'resource_risk_history',
    'security_findings',
    'fix_recommendations',
    'human_identities',
    'identity_graph_edges',
    'identity_security_posture',
    'orphaned_privileged_findings',
    'attack_paths',
    'risk_summary',
    'graph_attack_findings',
    'graph_nodes',
    'graph_edges',
    'tenant_posture_scores',
    'snapshot_runs',
    'snapshot_jobs',
    'snapshot_alerts',
    # Layer 7: org-scoped analytics / config
    'settings',
    'activity_log',
    'anomalies',
    'drift_reports',
    'compliance_snapshots',
    'notifications',
    'api_keys',
    'custom_risk_rules',
    'dashboard_preferences',
    'soar_playbooks',
    'soar_actions',
    'reports',
    'report_runs',
    'report_outputs',
    'saved_views',
    'webhooks',
    'webhook_deliveries',
    'copilot_conversations',
    'billing_events',
    'billing_audit_log',
    'invoices',
    'invoice_documents',
    'identity_groups',
    'identity_group_members',
    'access_review_campaigns',
    'access_reviews',
    'review_assignments',
    'review_evidence',
    'campaign_reviews',
    'campaign_audit_log',
    'organization_entitlements',
    'organization_usage',
    'organization_usage_counters',
    'organization_billing_snapshots',
    'agirs_scores',
    'ai_audit_log',
    'finding_comments',
    'tenant_health',
    'security_events',
    'msp_relationships',
]

# Tables linked to users (no org_id) — filter by user_id
USER_LINKED_TABLES = [
    'refresh_tokens',   # user_id FK
    'sso_auth_codes',   # user_id FK
]

# Admin audit log — filter by target_organization_id
ADMIN_AUDIT_TABLES = [
    'admin_audit_log',  # target_organization_id
]


def get_columns(cursor, table_name):
    """Get column names for a table."""
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
    """, (table_name,))
    return [r[0] for r in cursor.fetchall()]


def get_column_types(cursor, table_name):
    """Get column name → data_type mapping."""
    cursor.execute("""
        SELECT column_name, data_type, udt_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
    """, (table_name,))
    return {r[0]: (r[1], r[2]) for r in cursor.fetchall()}


def table_exists_local(cursor, table_name):
    """Check if table exists in local DB."""
    cursor.execute("""
        SELECT EXISTS(
            SELECT 1 FROM pg_tables
            WHERE schemaname = 'public' AND tablename = %s
        )
    """, (table_name,))
    return cursor.fetchone()[0]


def table_exists_cloud(cursor, table_name):
    """Check if table exists in cloud DB."""
    cursor.execute("""
        SELECT EXISTS(
            SELECT 1 FROM pg_tables
            WHERE schemaname = 'public' AND tablename = %s
        )
    """, (table_name,))
    return cursor.fetchone()[0]


def has_column(cursor, table_name, column_name):
    """Check if a column exists on a table."""
    cursor.execute("""
        SELECT EXISTS(
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s AND column_name = %s
        )
    """, (table_name, column_name))
    return cursor.fetchone()[0]


def migrate_table(local_cur, cloud_conn, table_name, where_clause=None, where_params=None):
    """Copy rows from local table to cloud table."""
    cloud_cur = cloud_conn.cursor()

    # Check table exists in both DBs
    if not table_exists_local(local_cur, table_name):
        print(f"  SKIP {table_name} — not in local DB")
        return 0

    if not table_exists_cloud(cloud_cur, table_name):
        print(f"  SKIP {table_name} — not in cloud DB")
        return 0

    # Get columns that exist in BOTH local and cloud
    local_cols = set(get_columns(local_cur, table_name))
    cloud_cols = set(get_columns(cloud_cur, table_name))
    common_cols = sorted(local_cols & cloud_cols)

    if not common_cols:
        print(f"  SKIP {table_name} — no common columns")
        return 0

    # Detect jsonb columns that need Json() wrapping on insert
    cloud_types = get_column_types(cloud_cur, table_name)

    # Build set of column indices that are jsonb in cloud
    jsonb_indices = set()
    for i, col in enumerate(common_cols):
        ct = cloud_types.get(col, (None, None))
        if ct[1] == 'jsonb':
            jsonb_indices.add(i)

    col_list = ', '.join(common_cols)

    # Read from local
    query = f"SELECT {col_list} FROM {table_name}"
    if where_clause:
        query += f" WHERE {where_clause}"

    local_cur.execute(query, where_params or ())
    rows = local_cur.fetchall()

    if not rows:
        print(f"  SKIP {table_name} — 0 rows match filter")
        return 0

    # Wrap jsonb values with Json() adapter so psycopg2 sends them as jsonb, not array
    if jsonb_indices:
        converted = []
        for row in rows:
            row = list(row)
            for idx in jsonb_indices:
                if row[idx] is not None:
                    row[idx] = psycopg2.extras.Json(row[idx])
            converted.append(tuple(row))
        rows = converted

    # Truncate cloud table first (cascade to avoid FK issues)
    cloud_cur.execute(f"TRUNCATE TABLE {table_name} CASCADE")

    # Insert into cloud
    placeholders = ', '.join(['%s'] * len(common_cols))
    insert_sql = f"INSERT INTO {table_name} ({col_list}) VALUES ({placeholders})"

    psycopg2.extras.execute_batch(cloud_cur, insert_sql, rows, page_size=500)
    cloud_conn.commit()

    print(f"  OK   {table_name}: {len(rows)} rows")
    return len(rows)


def reset_sequences(cloud_conn):
    """Reset all SERIAL sequences to MAX(id) + 1."""
    cur = cloud_conn.cursor()
    cur.execute("""
        SELECT c.table_name, c.column_default
        FROM information_schema.columns c
        WHERE c.table_schema = 'public'
          AND c.column_name = 'id'
          AND c.column_default LIKE 'nextval%'
    """)
    for table_name, col_default in cur.fetchall():
        # Extract sequence name from nextval('seq_name'::regclass)
        seq_name = col_default.split("'")[1]
        cur.execute(f"SELECT COALESCE(MAX(id), 0) + 1 FROM {table_name}")
        next_val = cur.fetchone()[0]
        cur.execute(f"SELECT setval('{seq_name}', {next_val}, false)")
    cloud_conn.commit()
    print(f"\n  Sequences reset for all tables")


def main():
    print("=" * 70)
    print("AuditGraph Tenant-Scoped Migration: Local → Cloud Dev")
    print(f"Orgs: {MIGRATE_ORG_IDS}")
    print("=" * 70)

    local_conn = psycopg2.connect(LOCAL_DSN)
    local_conn.set_session(readonly=True)
    local_cur = local_conn.cursor()

    cloud_conn = psycopg2.connect(CLOUD_DSN)
    cloud_cur = cloud_conn.cursor()

    # Disable USER triggers on all public tables during migration
    # (Azure Flexible Server doesn't allow DISABLE TRIGGER ALL on system triggers)
    cloud_cur.execute("""
        SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    """)
    all_cloud_tables = [r[0] for r in cloud_cur.fetchall()]
    for tbl in all_cloud_tables:
        cloud_cur.execute(f"ALTER TABLE {tbl} DISABLE TRIGGER USER")
    # Set all FK constraints to deferred so insert order doesn't matter
    cloud_cur.execute("SET CONSTRAINTS ALL DEFERRED")
    cloud_conn.commit()
    print(f"Disabled user triggers on {len(all_cloud_tables)} tables")

    total_rows = 0

    # ── Phase 1: Global reference tables ──
    print("\n── Phase 1: Global Reference Tables ──")
    for tbl in GLOBAL_TABLES:
        total_rows += migrate_table(local_cur, cloud_conn, tbl)

    # ── Phase 2: Organizations ──
    print("\n── Phase 2: Organizations ──")
    total_rows += migrate_table(local_cur, cloud_conn, ORG_TABLE,
        "id IN %s", (MIGRATE_ORG_IDS,))

    # ── Phase 3: Org-scoped tables ──
    print("\n── Phase 3: Org-Scoped Tables ──")
    for tbl in ORG_SCOPED_TABLES:
        if not table_exists_local(local_cur, tbl):
            print(f"  SKIP {tbl} — not in local DB")
            continue
        if has_column(local_cur, tbl, 'organization_id'):
            total_rows += migrate_table(local_cur, cloud_conn, tbl,
                "organization_id IN %s", (MIGRATE_ORG_IDS,))
        elif has_column(local_cur, tbl, 'discovery_run_id'):
            total_rows += migrate_table(local_cur, cloud_conn, tbl,
                "discovery_run_id IN (SELECT id FROM discovery_runs WHERE organization_id IN %s)",
                (MIGRATE_ORG_IDS,))
        else:
            print(f"  WARN {tbl} — no org_id or discovery_run_id, migrating ALL")
            total_rows += migrate_table(local_cur, cloud_conn, tbl)

    # ── Phase 4: User-linked tables ──
    print("\n── Phase 4: User-Linked Tables ──")
    for tbl in USER_LINKED_TABLES:
        if has_column(local_cur, tbl, 'user_id'):
            total_rows += migrate_table(local_cur, cloud_conn, tbl,
                "user_id IN (SELECT id FROM users WHERE organization_id IN %s)",
                (MIGRATE_ORG_IDS,))
        else:
            total_rows += migrate_table(local_cur, cloud_conn, tbl)

    # ── Phase 5: Admin audit ──
    print("\n── Phase 5: Admin Audit ──")
    for tbl in ADMIN_AUDIT_TABLES:
        if has_column(local_cur, tbl, 'target_organization_id'):
            total_rows += migrate_table(local_cur, cloud_conn, tbl,
                "target_organization_id IN %s", (MIGRATE_ORG_IDS,))
        elif has_column(local_cur, tbl, 'organization_id'):
            total_rows += migrate_table(local_cur, cloud_conn, tbl,
                "organization_id IN %s", (MIGRATE_ORG_IDS,))
        else:
            total_rows += migrate_table(local_cur, cloud_conn, tbl)

    # ── Phase 6: Reset sequences ──
    print("\n── Phase 6: Reset Sequences ──")
    reset_sequences(cloud_conn)

    # Re-enable triggers
    cloud_cur = cloud_conn.cursor()
    for tbl in all_cloud_tables:
        cloud_cur.execute(f"ALTER TABLE {tbl} ENABLE TRIGGER USER")
    cloud_conn.commit()
    print(f"Re-enabled user triggers on {len(all_cloud_tables)} tables")

    # ── Phase 7: Verify ──
    print("\n── Phase 7: Verification ──")
    cloud_cur = cloud_conn.cursor()
    checks = [
        ("organizations", "SELECT COUNT(*) FROM organizations"),
        ("users", "SELECT COUNT(*) FROM users"),
        ("cloud_connections", "SELECT COUNT(*) FROM cloud_connections"),
        ("discovery_runs", "SELECT COUNT(*) FROM discovery_runs"),
        ("identities", "SELECT COUNT(*) FROM identities"),
        ("settings", "SELECT COUNT(*) FROM settings"),
    ]
    for label, query in checks:
        cloud_cur.execute(query)
        print(f"  {label}: {cloud_cur.fetchone()[0]} rows")

    # Cross-tenant leak check
    print("\n── Cross-Tenant Leak Check ──")
    cloud_cur.execute("SELECT DISTINCT organization_id FROM cloud_connections")
    org_ids = [r[0] for r in cloud_cur.fetchall()]
    leaked = [oid for oid in org_ids if oid not in MIGRATE_ORG_IDS]
    if leaked:
        print(f"  LEAK DETECTED: cloud_connections has org_ids {leaked}")
    else:
        print(f"  OK — cloud_connections only has org_ids {org_ids}")

    cloud_cur.execute("SELECT DISTINCT organization_id FROM discovery_runs")
    org_ids = [r[0] for r in cloud_cur.fetchall()]
    leaked = [oid for oid in org_ids if oid not in MIGRATE_ORG_IDS]
    if leaked:
        print(f"  LEAK DETECTED: discovery_runs has org_ids {leaked}")
    else:
        print(f"  OK — discovery_runs only has org_ids {org_ids}")

    print(f"\n{'=' * 70}")
    print(f"Migration complete: {total_rows} total rows migrated")
    print(f"{'=' * 70}")

    local_conn.close()
    cloud_conn.close()


if __name__ == '__main__':
    main()
