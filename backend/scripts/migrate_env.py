#!/usr/bin/env python3
"""
AuditGraph Clean Environment Migration
=======================================
Sets up a target database with complete schema + reference data ONLY.
No tenant/org data — app startup creates admin org + users.

This is the SINGLE migration script for all environments:
  localhost → dev / qa / stg / prod

What it does:
  Phase 1: pg_dump schema from source DB (via Docker)
  Phase 2: DROP everything on target DB
  Phase 3: Load schema into target DB
  Phase 4: Copy reference/seed data (global tables only)
  Phase 5: Grant permissions to target DB users
  Phase 6: Reset sequences
  Phase 7: Verify

Usage:
  python scripts/migrate_env.py --target dev
  python scripts/migrate_env.py --target qa
  python scripts/migrate_env.py --target dev --source-dsn "dbname=... host=..."
"""

import argparse
import os
import subprocess
import sys
import tempfile

import psycopg2
import psycopg2.extras
import psycopg2.extensions


# ── Environment configs ──────────────────────────────────────────────────────

ENVS = {
    "dev": {
        "dsn": (
            "dbname=auditgraph_dev_eastus2 "
            "user=auditgraph_dev_admin "
            "password=Aud1tGr@phDevAdm1n2026 "
            "host=cus-ag-nonprod-pg.postgres.database.azure.com "
            "port=5432 sslmode=require"
        ),
        "app_user": "auditgraph_dev_app",
        "admin_user": "auditgraph_dev_admin",
    },
    # Add qa/stg/prod configs here when ready:
    # "qa": { "dsn": "...", "app_user": "...", "admin_user": "..." },
}

# Default source: local Docker DB
DEFAULT_SOURCE_DSN = "dbname=auditgraph user=auditgraph password=auditgraph host=localhost port=5434"
DOCKER_CONTAINER = "auditgraph-postgres"

# ── Global reference tables — ALL rows, no tenant filter ──────────────────

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


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd, **kwargs):
    """Run shell command, return stdout."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kwargs)
    if result.returncode != 0 and result.stderr:
        # Filter out harmless warnings
        errors = [l for l in result.stderr.strip().split('\n')
                  if not l.startswith('WARNING:') and l.strip()]
        if errors:
            print(f"  STDERR: {'; '.join(errors[:3])}")
    return result


def get_columns(cursor, table_name):
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
    """, (table_name,))
    return [r[0] for r in cursor.fetchall()]


def get_column_types(cursor, table_name):
    cursor.execute("""
        SELECT column_name, udt_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
    """, (table_name,))
    return {r[0]: r[1] for r in cursor.fetchall()}


def table_exists(cursor, table_name):
    cursor.execute("""
        SELECT EXISTS(SELECT 1 FROM pg_tables
        WHERE schemaname = 'public' AND tablename = %s)
    """, (table_name,))
    return cursor.fetchone()[0]


# ── Phase 1: Dump schema ─────────────────────────────────────────────────────

def dump_schema(schema_file):
    """Dump complete schema from local DB via Docker pg_dump.

    IMPORTANT: Run seed scripts (seed_all_32_roles.py, seed_verified_attacks.py)
    on local BEFORE running this migration, so schema-altering seeds (e.g. ALTER
    TABLE ADD COLUMN source) are captured in the dump.
    """
    print("\n── Phase 1: Dump Schema from Local DB ──")

    # Ensure seed scripts that alter schema have been run locally
    print("  Running schema-altering seed scripts on local DB first...")
    seeds = [
        "tools/patches/seed_all_32_roles.py",
        "tools/patches/seed_verified_attacks.py",
    ]
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    venv_python = os.path.join(backend_dir, "venv", "bin", "python")
    if not os.path.exists(venv_python):
        venv_python = "python3"
    for seed in seeds:
        seed_path = os.path.join(backend_dir, seed)
        if os.path.exists(seed_path):
            result = run(f"cd {backend_dir} && {venv_python} {seed}")
            if result.returncode == 0:
                print(f"    OK {seed}")
            else:
                print(f"    WARN {seed} failed (non-fatal)")

    cmd = (
        f"docker exec {DOCKER_CONTAINER} pg_dump -U auditgraph -d auditgraph "
        f"--schema-only --no-owner --no-privileges --no-comments "
        f"--no-tablespaces --no-security-labels"
    )
    result = run(cmd)
    if result.returncode != 0:
        print(f"  FATAL: pg_dump failed: {result.stderr}")
        sys.exit(1)

    schema_sql = result.stdout

    # Strip the \restrict line (psql security feature, not needed)
    lines = schema_sql.split('\n')
    lines = [l for l in lines if not l.startswith('\\restrict')]
    schema_sql = '\n'.join(lines)

    with open(schema_file, 'w') as f:
        f.write(schema_sql)

    # Count objects
    tables = schema_sql.count('CREATE TABLE')
    indexes = schema_sql.count('CREATE INDEX')
    policies = schema_sql.count('CREATE POLICY')
    triggers = schema_sql.count('CREATE TRIGGER')
    functions = schema_sql.count('CREATE FUNCTION')
    print(f"  Dumped: {tables} tables, {indexes} indexes, {policies} RLS policies, "
          f"{triggers} triggers, {functions} functions")
    print(f"  Schema file: {schema_file} ({len(schema_sql)} bytes)")
    return schema_file


# ── Phase 2: Clean target DB ─────────────────────────────────────────────────

def clean_target(target_conn):
    """Drop ALL objects in public schema on target."""
    print("\n── Phase 2: Clean Target DB ──")
    cur = target_conn.cursor()

    # Drop all views first (they depend on tables)
    cur.execute("""
        SELECT table_name FROM information_schema.views
        WHERE table_schema = 'public'
    """)
    views = [r[0] for r in cur.fetchall()]
    for v in views:
        cur.execute(f"DROP VIEW IF EXISTS {v} CASCADE")
    print(f"  Dropped {len(views)} views")

    # Drop all tables
    cur.execute("""
        SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    """)
    tables = [r[0] for r in cur.fetchall()]
    if tables:
        table_list = ', '.join(tables)
        cur.execute(f"DROP TABLE IF EXISTS {table_list} CASCADE")
    print(f"  Dropped {len(tables)} tables")

    # Drop all sequences
    cur.execute("""
        SELECT sequence_name FROM information_schema.sequences
        WHERE sequence_schema = 'public'
    """)
    sequences = [r[0] for r in cur.fetchall()]
    for s in sequences:
        cur.execute(f"DROP SEQUENCE IF EXISTS {s} CASCADE")
    print(f"  Dropped {len(sequences)} sequences")

    # Drop all functions
    cur.execute("""
        SELECT routine_name, routine_schema FROM information_schema.routines
        WHERE routine_schema = 'public' AND routine_type = 'FUNCTION'
    """)
    functions = [r[0] for r in cur.fetchall()]
    for f in set(functions):
        cur.execute(f"DROP FUNCTION IF EXISTS {f} CASCADE")
    print(f"  Dropped {len(set(functions))} functions")

    # Drop all custom types
    cur.execute("""
        SELECT typname FROM pg_type t
        JOIN pg_namespace n ON t.typnamespace = n.oid
        WHERE n.nspname = 'public' AND t.typtype = 'e'
    """)
    types = [r[0] for r in cur.fetchall()]
    for t in types:
        cur.execute(f"DROP TYPE IF EXISTS {t} CASCADE")
    print(f"  Dropped {len(types)} custom types")

    target_conn.commit()

    # Verify clean
    cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'")
    remaining = cur.fetchone()[0]
    if remaining > 0:
        print(f"  WARNING: {remaining} tables still remain!")
    else:
        print(f"  Target DB is clean (0 tables)")


# ── Phase 3: Load schema ─────────────────────────────────────────────────────

def load_schema(target_dsn, schema_file):
    """Load schema dump into target DB via psql."""
    print("\n── Phase 3: Load Schema into Target DB ──")

    # Parse DSN into psql-friendly format
    parts = {}
    for pair in target_dsn.split():
        if '=' in pair:
            k, v = pair.split('=', 1)
            parts[k] = v

    env = os.environ.copy()
    env['PGPASSWORD'] = parts.get('password', '')

    cmd = (
        f"psql -h {parts['host']} -p {parts.get('port', '5432')} "
        f"-U {parts['user']} -d {parts['dbname']} "
        f"--single-transaction --set ON_ERROR_STOP=off "
        f"-f {schema_file}"
    )

    # Add sslmode if present
    if 'sslmode' in parts:
        env['PGSSLMODE'] = parts['sslmode']

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env)

    # Count errors vs warnings
    if result.stderr:
        lines = result.stderr.strip().split('\n')
        errors = [l for l in lines if 'ERROR' in l]
        if errors:
            print(f"  Schema load had {len(errors)} errors:")
            for e in errors[:5]:
                print(f"    {e}")
            if len(errors) > 5:
                print(f"    ... and {len(errors) - 5} more")

    # Verify tables were created
    conn = psycopg2.connect(target_dsn)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'")
    table_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public'")
    index_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM pg_policies")
    policy_count = cur.fetchone()[0]
    conn.close()

    print(f"  Loaded: {table_count} tables, {index_count} indexes, {policy_count} RLS policies")
    return table_count


# ── Phase 4: Copy reference data ─────────────────────────────────────────────

def copy_reference_data(source_dsn, target_conn):
    """Copy global reference tables from source to target."""
    print("\n── Phase 4: Copy Reference/Seed Data ──")

    source_conn = psycopg2.connect(source_dsn)
    source_conn.set_session(readonly=True)
    source_cur = source_conn.cursor()
    target_cur = target_conn.cursor()

    total_rows = 0
    for tbl in GLOBAL_TABLES:
        # Check table exists in both
        if not table_exists(source_cur, tbl):
            print(f"  SKIP {tbl} — not in source DB")
            continue
        if not table_exists(target_cur, tbl):
            print(f"  SKIP {tbl} — not in target DB")
            continue

        # Get common columns
        source_cols = set(get_columns(source_cur, tbl))
        target_cols = set(get_columns(target_cur, tbl))
        common_cols = sorted(source_cols & target_cols)
        if not common_cols:
            print(f"  SKIP {tbl} — no common columns")
            continue

        # Detect jsonb columns
        target_types = get_column_types(target_cur, tbl)
        jsonb_indices = {i for i, col in enumerate(common_cols)
                        if target_types.get(col) == 'jsonb'}

        # Read from source
        col_list = ', '.join(common_cols)
        source_cur.execute(f"SELECT {col_list} FROM {tbl}")
        rows = source_cur.fetchall()

        if not rows:
            print(f"  SKIP {tbl} — 0 rows")
            continue

        # Wrap jsonb values
        if jsonb_indices:
            converted = []
            for row in rows:
                row = list(row)
                for idx in jsonb_indices:
                    if row[idx] is not None:
                        row[idx] = psycopg2.extras.Json(row[idx])
                converted.append(tuple(row))
            rows = converted

        # Truncate and insert
        target_cur.execute(f"TRUNCATE TABLE {tbl} CASCADE")
        placeholders = ', '.join(['%s'] * len(common_cols))
        insert_sql = f"INSERT INTO {tbl} ({col_list}) VALUES ({placeholders})"
        psycopg2.extras.execute_batch(target_cur, insert_sql, rows, page_size=500)
        target_conn.commit()

        total_rows += len(rows)
        print(f"  OK   {tbl}: {len(rows)} rows")

    source_conn.close()
    print(f"  Total reference data: {total_rows} rows")
    return total_rows


# ── Phase 5: Grant permissions ────────────────────────────────────────────────

def grant_permissions(target_conn, app_user, admin_user):
    """Grant proper permissions to app and admin users."""
    print("\n── Phase 5: Grant Permissions ──")
    cur = target_conn.cursor()

    grants = [
        # App user needs full DML on all tables
        f"GRANT USAGE ON SCHEMA public TO {app_user}",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {app_user}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {app_user}",
        f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {app_user}",
        # Set default privileges for future tables
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_user}",
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {app_user}",
        # Admin user gets everything
        f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {admin_user}",
        f"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {admin_user}",
        f"GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO {admin_user}",
    ]

    for sql in grants:
        try:
            cur.execute(sql)
        except Exception as e:
            print(f"  WARN: {sql[:60]}... → {e}")
    target_conn.commit()
    print(f"  Granted permissions to {app_user} (DML) and {admin_user} (ALL)")

    # Verify RLS is enabled on tenant-scoped tables
    cur.execute("""
        SELECT relname, relrowsecurity
        FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity = true
    """)
    rls_tables = cur.fetchall()
    print(f"  RLS enabled on {len(rls_tables)} tables")

    # Verify policies exist
    cur.execute("SELECT COUNT(*) FROM pg_policies")
    policy_count = cur.fetchone()[0]
    print(f"  {policy_count} RLS policies active")


# ── Phase 6: Reset sequences ─────────────────────────────────────────────────

def reset_sequences(target_conn):
    """Reset all SERIAL sequences to MAX(id) + 1."""
    print("\n── Phase 6: Reset Sequences ──")
    cur = target_conn.cursor()
    cur.execute("""
        SELECT c.table_name, c.column_default
        FROM information_schema.columns c
        WHERE c.table_schema = 'public'
          AND c.column_name = 'id'
          AND c.column_default LIKE 'nextval%%'
    """)
    count = 0
    for table_name, col_default in cur.fetchall():
        try:
            seq_name = col_default.split("'")[1]
            cur.execute(f"SELECT COALESCE(MAX(id), 0) + 1 FROM {table_name}")
            next_val = cur.fetchone()[0]
            cur.execute(f"SELECT setval('{seq_name}', {next_val}, false)")
            count += 1
        except Exception as e:
            print(f"  WARN: {table_name} → {e}")
    target_conn.commit()
    print(f"  Reset {count} sequences")


# ── Phase 7: Verify ──────────────────────────────────────────────────────────

def verify(target_conn):
    """Verify migration completeness."""
    print("\n── Phase 7: Verification ──")
    cur = target_conn.cursor()

    # Table count
    cur.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'")
    print(f"  Tables: {cur.fetchone()[0]}")

    # Index count
    cur.execute("SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public'")
    print(f"  Indexes: {cur.fetchone()[0]}")

    # RLS policy count
    cur.execute("SELECT COUNT(*) FROM pg_policies")
    print(f"  RLS Policies: {cur.fetchone()[0]}")

    # Trigger count
    cur.execute("""
        SELECT COUNT(*) FROM pg_trigger t
        JOIN pg_class c ON t.tgrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'public' AND NOT t.tgisinternal
    """)
    print(f"  Triggers: {cur.fetchone()[0]}")

    # Reference data
    for tbl in GLOBAL_TABLES:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {tbl}")
            count = cur.fetchone()[0]
            print(f"  {tbl}: {count} rows")
        except Exception:
            print(f"  {tbl}: TABLE MISSING")
            target_conn.rollback()

    # Confirm NO org data exists
    cur.execute("SELECT COUNT(*) FROM organizations")
    org_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM identities")
    identity_count = cur.fetchone()[0]
    print(f"\n  Organizations: {org_count} (should be 0 — app startup creates admin org)")
    print(f"  Users: {user_count} (should be 0 — app startup creates admin user)")
    print(f"  Identities: {identity_count} (should be 0 — discovery populates)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AuditGraph Clean Environment Migration")
    parser.add_argument('--target', required=True, choices=list(ENVS.keys()),
                        help='Target environment (dev, qa, stg, prod)')
    parser.add_argument('--source-dsn', default=DEFAULT_SOURCE_DSN,
                        help='Source database DSN (default: local Docker DB)')
    parser.add_argument('--skip-schema-dump', action='store_true',
                        help='Skip pg_dump, use existing /tmp/auditgraph_schema.sql')
    args = parser.parse_args()

    env = ENVS[args.target]
    target_dsn = env['dsn']
    app_user = env['app_user']
    admin_user = env['admin_user']

    print("=" * 70)
    print(f"AuditGraph Clean Environment Migration → {args.target.upper()}")
    print(f"Source: {'existing schema file' if args.skip_schema_dump else 'local Docker DB'}")
    print(f"Target: {env['dsn'].split('host=')[1].split()[0] if 'host=' in env['dsn'] else 'unknown'}")
    print("=" * 70)

    schema_file = '/tmp/auditgraph_schema.sql'

    # Phase 1: Dump schema
    if not args.skip_schema_dump:
        dump_schema(schema_file)
    else:
        print(f"\n── Phase 1: Using existing schema file {schema_file} ──")

    # Phase 2: Clean target
    target_conn = psycopg2.connect(target_dsn)
    target_conn.autocommit = False
    clean_target(target_conn)
    target_conn.close()

    # Phase 3: Load schema (uses psql for reliable DDL execution)
    table_count = load_schema(target_dsn, schema_file)
    if table_count == 0:
        print("  FATAL: No tables created. Check schema file and connection.")
        sys.exit(1)

    # Phase 4: Copy reference data
    target_conn = psycopg2.connect(target_dsn)
    copy_reference_data(args.source_dsn, target_conn)

    # Phase 5: Grant permissions
    grant_permissions(target_conn, app_user, admin_user)

    # Phase 6: Reset sequences
    reset_sequences(target_conn)

    # Phase 7: Verify
    verify(target_conn)

    target_conn.close()

    print(f"\n{'=' * 70}")
    print(f"Migration complete! Target DB ({args.target}) is ready.")
    print(f"")
    print(f"Next steps:")
    print(f"  1. Restart the API container (app startup creates admin org + users)")
    print(f"  2. Login to admin portal → create a new organization")
    print(f"  3. Login to client portal → connect cloud → run discovery")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
