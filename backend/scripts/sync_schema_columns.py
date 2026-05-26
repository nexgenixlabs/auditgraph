#!/usr/bin/env python3
"""
Two-stage schema column sync: dump column definitions from a SOURCE DB,
then apply ADD COLUMN IF NOT EXISTS statements against a TARGET DB.

Mode 1 — dump (run with access to local sandbox):
    LOCAL_DSN=... python3 sync_schema_columns.py dump --out /tmp/cols.json

Mode 2 — apply (run inside VNet, against cloud dev):
    CLOUD_DSN=... python3 sync_schema_columns.py apply --in /tmp/cols.json

The apply mode is purely additive: it adds columns that exist in the dump but
not in the target. It never drops columns, changes types, or alters defaults
on existing columns — that's beyond the scope of "make scan stop failing".
"""
import argparse
import json
import os
import sys

import psycopg2


def fetch_columns(dsn: str) -> dict:
    """Return {table_name: [{name, data_type, udt_name, is_nullable, default}, ...]}."""
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name, data_type, udt_name,
               is_nullable, column_default, character_maximum_length
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
    """)
    out = {}
    for table, col, dtype, udt, nullable, default, maxlen in cur.fetchall():
        out.setdefault(table, []).append({
            "name": col,
            "data_type": dtype,
            "udt_name": udt,
            "is_nullable": nullable,
            "default": default,
            "max_length": maxlen,
        })
    conn.close()
    return out


def render_type(col: dict) -> str:
    """Build the SQL type expression for ADD COLUMN."""
    dt = col["data_type"]
    udt = col["udt_name"]
    maxlen = col["max_length"]
    if dt == "USER-DEFINED":
        return udt
    if dt == "ARRAY":
        # information_schema reports array element via udt like '_int4'
        inner = udt[1:] if udt.startswith("_") else udt
        # map common pg internal names back to SQL types
        inner_map = {
            "int4": "integer", "int8": "bigint", "varchar": "varchar",
            "text": "text", "uuid": "uuid", "bool": "boolean",
        }
        return f"{inner_map.get(inner, inner)}[]"
    if dt == "character varying" and maxlen:
        return f"varchar({maxlen})"
    if dt == "character" and maxlen:
        return f"char({maxlen})"
    if dt == "numeric" and maxlen:
        return f"numeric({maxlen})"
    # For most types, data_type is the SQL name
    return dt


def cmd_dump(args):
    dsn = os.environ.get("LOCAL_DSN")
    if not dsn:
        sys.exit("LOCAL_DSN env var is required")
    print(f"Fetching schema from source...")
    cols = fetch_columns(dsn)
    with open(args.out, "w") as f:
        json.dump(cols, f, indent=2, default=str)
    total = sum(len(v) for v in cols.values())
    print(f"Wrote {len(cols)} tables, {total} columns → {args.out}")


def cmd_apply(args):
    dsn = os.environ.get("CLOUD_DSN")
    if not dsn:
        sys.exit("CLOUD_DSN env var is required")
    with open(args.in_path) as f:
        source = json.load(f)
    print(f"Loaded {len(source)} source tables")

    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    cur = conn.cursor()

    # Fetch current cloud columns
    cur.execute("""
        SELECT table_name, column_name FROM information_schema.columns
        WHERE table_schema = 'public'
    """)
    have = {}
    for table, col in cur.fetchall():
        have.setdefault(table, set()).add(col)

    added = 0
    skipped_table = 0
    failed = []
    for table, cols in sorted(source.items()):
        if table not in have:
            skipped_table += 1
            continue
        existing = have[table]
        for col in cols:
            if col["name"] in existing:
                continue
            type_expr = render_type(col)
            default = col["default"]
            stmt = f'ALTER TABLE "{table}" ADD COLUMN IF NOT EXISTS "{col["name"]}" {type_expr}'
            if default is not None:
                stmt += f" DEFAULT {default}"
            try:
                cur.execute(stmt)
                added += 1
                print(f"  + {table}.{col['name']} ({type_expr})")
            except Exception as e:
                failed.append((table, col["name"], str(e)[:120]))
                print(f"  ✗ {table}.{col['name']}: {str(e)[:120]}")

    print(f"\nAdded {added} columns")
    if skipped_table:
        print(f"Skipped {skipped_table} tables that don't exist in target (created by Python DDL only)")
    if failed:
        print(f"\n{len(failed)} ADD COLUMN statements failed (review and patch manually):")
        for t, c, e in failed[:20]:
            print(f"  {t}.{c}: {e}")
    conn.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    pd = sub.add_parser("dump")
    pd.add_argument("--out", required=True)
    pa = sub.add_parser("apply")
    pa.add_argument("--in", dest="in_path", required=True)
    args = p.parse_args()
    if args.mode == "dump":
        cmd_dump(args)
    elif args.mode == "apply":
        cmd_apply(args)


if __name__ == "__main__":
    main()
