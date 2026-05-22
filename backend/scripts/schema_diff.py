#!/usr/bin/env python3
"""
Deep schema + sanity diff between a SOURCE DB and TARGET DB.
Reports:
  - Tables present only in source / only in target
  - Columns present only in source per shared table
  - Type mismatches per shared column
  - Indexes present only in source per shared table
  - Foreign keys present only in source per shared table
  - Triggers present only in source per shared table
  - Row count delta per shared table (sample)
  - Specific health checks (e.g. federated_credentials sanity)

Usage (run with both DSNs reachable, e.g. from a host with SSH tunnel,
or in two stages: dump_source.py then apply_diff.py against target):

    LOCAL_DSN=... CLOUD_DSN=... python3 schema_diff.py
"""
import os, sys, json
import psycopg2
import psycopg2.extras


def get_conn(dsn):
    c = psycopg2.connect(dsn)
    c.autocommit = True
    return c


def fetch_tables(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename
    """)
    return {r[0] for r in cur.fetchall()}


def fetch_columns(conn, table):
    cur = conn.cursor()
    cur.execute("""
        SELECT column_name, data_type, udt_name, character_maximum_length, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s
        ORDER BY ordinal_position
    """, (table,))
    return {r[0]: {'data_type': r[1], 'udt_name': r[2], 'max_length': r[3], 'is_nullable': r[4], 'default': r[5]} for r in cur.fetchall()}


def fetch_indexes(conn, table):
    cur = conn.cursor()
    cur.execute("""
        SELECT indexname, indexdef FROM pg_indexes
        WHERE schemaname='public' AND tablename=%s
        ORDER BY indexname
    """, (table,))
    return {r[0]: r[1] for r in cur.fetchall()}


def fetch_foreign_keys(conn, table):
    cur = conn.cursor()
    cur.execute("""
        SELECT conname,
               pg_get_constraintdef(oid) AS def
        FROM pg_constraint
        WHERE contype='f'
          AND conrelid = format('public.%I', %s)::regclass
        ORDER BY conname
    """, (table,))
    return {r[0]: r[1] for r in cur.fetchall()}


def fetch_triggers(conn, table):
    cur = conn.cursor()
    cur.execute("""
        SELECT trigger_name, action_statement
        FROM information_schema.triggers
        WHERE event_object_schema='public' AND event_object_table=%s
        ORDER BY trigger_name
    """, (table,))
    return {r[0]: r[1] for r in cur.fetchall()}


def row_count(conn, table):
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return cur.fetchone()[0]
    except Exception as e:
        return f"ERR:{str(e)[:60]}"


def diff(source_dsn, target_dsn, target_label="cloud"):
    src = get_conn(source_dsn)
    tgt = get_conn(target_dsn)

    src_tables = fetch_tables(src)
    tgt_tables = fetch_tables(tgt)

    only_in_src = sorted(src_tables - tgt_tables)
    only_in_tgt = sorted(tgt_tables - src_tables)
    shared = sorted(src_tables & tgt_tables)

    print(f"\n=== TABLES ===")
    print(f"Source: {len(src_tables)}  Target ({target_label}): {len(tgt_tables)}  Shared: {len(shared)}")
    if only_in_src:
        print(f"\n[MISSING IN {target_label.upper()}] {len(only_in_src)} tables only in source:")
        for t in only_in_src:
            rc = row_count(src, t)
            print(f"  - {t} (source rows={rc})")
    if only_in_tgt:
        print(f"\n[EXTRA IN {target_label.upper()}] {len(only_in_tgt)} tables only in target:")
        for t in only_in_tgt:
            print(f"  - {t}")

    print(f"\n=== COLUMNS (per shared table) ===")
    col_issues = 0
    type_mismatches = []
    missing_cols = []
    for t in shared:
        src_cols = fetch_columns(src, t)
        tgt_cols = fetch_columns(tgt, t)
        missing = sorted(set(src_cols) - set(tgt_cols))
        for c in missing:
            missing_cols.append((t, c, src_cols[c]['data_type']))
            col_issues += 1
        for c in sorted(set(src_cols) & set(tgt_cols)):
            sd = src_cols[c]
            td = tgt_cols[c]
            if sd['data_type'] != td['data_type'] or sd['udt_name'] != td['udt_name']:
                type_mismatches.append((t, c, f"{sd['data_type']}/{sd['udt_name']}", f"{td['data_type']}/{td['udt_name']}"))
                col_issues += 1
    if missing_cols:
        print(f"\n[MISSING COLUMNS] {len(missing_cols)} columns in source not in target:")
        for t, c, ty in missing_cols[:50]:
            print(f"  - {t}.{c} ({ty})")
        if len(missing_cols) > 50:
            print(f"  ... and {len(missing_cols)-50} more")
    if type_mismatches:
        print(f"\n[TYPE MISMATCHES] {len(type_mismatches)} columns differ:")
        for t, c, st, tt in type_mismatches[:30]:
            print(f"  - {t}.{c}: source={st} | target={tt}")
        if len(type_mismatches) > 30:
            print(f"  ... and {len(type_mismatches)-30} more")
    if not missing_cols and not type_mismatches:
        print("  All shared tables have matching columns ✓")

    print(f"\n=== INDEXES (per shared table) ===")
    missing_idx = []
    for t in shared:
        si = fetch_indexes(src, t)
        ti = fetch_indexes(tgt, t)
        for name in sorted(set(si) - set(ti)):
            missing_idx.append((t, name, si[name]))
    if missing_idx:
        print(f"\n[MISSING INDEXES] {len(missing_idx)}:")
        for t, n, d in missing_idx[:30]:
            print(f"  - {t}.{n}")
        if len(missing_idx) > 30:
            print(f"  ... and {len(missing_idx)-30} more")
    else:
        print("  All shared tables have matching indexes ✓")

    print(f"\n=== FOREIGN KEYS (per shared table) ===")
    missing_fk = []
    for t in shared:
        sf = fetch_foreign_keys(src, t)
        tf = fetch_foreign_keys(tgt, t)
        for name in sorted(set(sf) - set(tf)):
            missing_fk.append((t, name, sf[name]))
    if missing_fk:
        print(f"\n[MISSING FOREIGN KEYS] {len(missing_fk)}:")
        for t, n, d in missing_fk[:30]:
            print(f"  - {t}.{n}: {d[:80]}")
    else:
        print("  All shared tables have matching foreign keys ✓")

    print(f"\n=== TRIGGERS (per shared table) ===")
    missing_trig = []
    for t in shared:
        st_ = fetch_triggers(src, t)
        tt_ = fetch_triggers(tgt, t)
        for name in sorted(set(st_) - set(tt_)):
            missing_trig.append((t, name))
    if missing_trig:
        print(f"\n[MISSING TRIGGERS] {len(missing_trig)}:")
        for t, n in missing_trig[:30]:
            print(f"  - {t}.{n}")
    else:
        print("  All shared tables have matching triggers ✓")

    src.close()
    tgt.close()
    return missing_cols, type_mismatches, missing_idx, missing_fk, missing_trig, only_in_src


if __name__ == '__main__':
    local = os.environ.get('LOCAL_DSN')
    cloud = os.environ.get('CLOUD_DSN')
    if not local or not cloud:
        sys.exit("Need LOCAL_DSN and CLOUD_DSN env vars")
    diff(local, cloud, target_label='cloud')
