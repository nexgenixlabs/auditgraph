#!/usr/bin/env python3
"""
AuditGraph Database Migration Runner

Connects as admin user, runs SQL migration files from backend/migrations/ in order,
and tracks applied versions in a schema_migrations table.

Usage:
    python scripts/run_migrations.py                  # Run SQL migrations only
    python scripts/run_migrations.py --include-ddl    # Also run Python-based DDL via create_app()
    python scripts/run_migrations.py --dry-run        # Show pending migrations without applying

Environment variables:
    DB_HOST, DB_PORT, DB_NAME, DB_ADMIN_USER, DB_ADMIN_PASSWORD, DB_SSLMODE
"""
import os
import sys
import re
import argparse
import psycopg2

# Resolve paths relative to repo root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
MIGRATIONS_DIR = os.path.join(REPO_ROOT, 'backend', 'migrations')


def get_connection():
    """Connect to the database as the admin user."""
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=int(os.environ.get('DB_PORT', '5432')),
        dbname=os.environ.get('DB_NAME', 'auditgraph'),
        user=os.environ.get('DB_ADMIN_USER', os.environ.get('DB_USER', 'auditgraph')),
        password=os.environ.get('DB_ADMIN_PASSWORD', os.environ.get('DB_PASSWORD', '')),
        sslmode=os.environ.get('DB_SSLMODE', 'prefer'),
    )


def ensure_schema_migrations_table(conn):
    """Create the schema_migrations tracking table if it doesn't exist.

    The backend's _ensure_schema_migrations_table() may have created this table
    already with a different shape (version, description, applied_at, checksum).
    We tolerate either by adding our required columns defensively.
    """
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                filename TEXT,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        # Defensive: add filename column if the table was pre-created by app.database
        cur.execute("ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS filename TEXT")
    conn.commit()


def get_applied_versions(conn):
    """Return set of already-applied migration versions."""
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM schema_migrations")
        return {row[0] for row in cur.fetchall()}


def get_pending_migrations(applied_versions):
    """Scan migrations directory and return sorted list of (version, filename, filepath) not yet applied."""
    if not os.path.isdir(MIGRATIONS_DIR):
        print(f"Migrations directory not found: {MIGRATIONS_DIR}")
        return []

    migrations = []
    for fname in sorted(os.listdir(MIGRATIONS_DIR)):
        if not fname.endswith('.sql'):
            continue
        # Extract version number from filename (e.g., "001_create_..." -> "001")
        match = re.match(r'^(\d+)', fname)
        if not match:
            continue
        version = match.group(1)
        if version not in applied_versions:
            migrations.append((version, fname, os.path.join(MIGRATIONS_DIR, fname)))

    return migrations


def apply_migration(conn, version, filename, filepath):
    """Apply a single SQL migration file and record it in schema_migrations.

    Runs in AUTOCOMMIT so migration files that contain explicit BEGIN/COMMIT
    pragmas and `CREATE INDEX CONCURRENTLY` (which forbids a wrapping txn)
    work as the author intended.
    """
    with open(filepath, 'r') as f:
        sql = f.read()

    if not sql.strip():
        print(f"  Skipping empty migration: {filename}")
        return

    # Connection is already in autocommit mode (set in main()).
    with conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(
            "INSERT INTO schema_migrations (version, filename) VALUES (%s, %s)",
            (version, filename)
        )


def run_ddl():
    """Run Python-based DDL by importing create_app() which triggers _ensure_*_table() methods."""
    # Add backend to Python path
    backend_dir = os.path.join(REPO_ROOT, 'backend')
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    print("\nRunning Python-based DDL (create_app)...")
    try:
        from app.main import create_app
        app = create_app()
        with app.app_context():
            print("  DDL initialization complete.")
    except Exception as e:
        print(f"  DDL error: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(description='AuditGraph Database Migration Runner')
    parser.add_argument('--include-ddl', action='store_true',
                        help='Also run Python-based DDL via create_app()')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show pending migrations without applying')
    args = parser.parse_args()

    print(f"Connecting to database...")
    conn = get_connection()
    # AUTOCOMMIT lets migration files use explicit BEGIN/COMMIT and run
    # CREATE INDEX CONCURRENTLY (which forbids a wrapping txn).
    conn.autocommit = True
    print(f"  Host: {os.environ.get('DB_HOST', 'localhost')}")
    print(f"  Database: {os.environ.get('DB_NAME', 'auditgraph')}")
    print(f"  User: {os.environ.get('DB_ADMIN_USER', os.environ.get('DB_USER', 'auditgraph'))}")

    ensure_schema_migrations_table(conn)
    applied = get_applied_versions(conn)
    print(f"  Already applied: {len(applied)} migrations")

    pending = get_pending_migrations(applied)
    if not pending:
        print("\nNo pending SQL migrations.")
    else:
        print(f"\n{'Pending' if args.dry_run else 'Applying'} {len(pending)} migration(s):")
        for version, filename, filepath in pending:
            print(f"  {filename}")
            if not args.dry_run:
                try:
                    apply_migration(conn, version, filename, filepath)
                    print(f"    Applied successfully.")
                except Exception as e:
                    print(f"    FAILED: {e}")
                    conn.rollback()
                    conn.close()
                    sys.exit(1)

    conn.close()

    if args.include_ddl and not args.dry_run:
        run_ddl()

    print("\nDone.")


if __name__ == '__main__':
    main()
