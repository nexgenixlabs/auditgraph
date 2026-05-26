#!/usr/bin/env python3
"""Compare bundled local schema dump against CLOUD_DSN current state."""
import os, sys, json
import psycopg2

cloud_dsn = os.environ.get('CLOUD_DSN') or sys.exit("Need CLOUD_DSN")
local_path = sys.argv[1] if len(sys.argv) > 1 else '/data/local_schema.json'

local = json.load(open(local_path))
c = psycopg2.connect(cloud_dsn); c.autocommit=True; cur = c.cursor()

def cloud_tables():
    cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
    return {r[0] for r in cur.fetchall()}

def cloud_columns(t):
    cur.execute("""SELECT column_name, data_type, udt_name FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s""", (t,))
    return {r[0]: {'data_type': r[1], 'udt': r[2]} for r in cur.fetchall()}

def cloud_indexes(t):
    cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename=%s", (t,))
    return {r[0] for r in cur.fetchall()}

def cloud_fks(t):
    cur.execute("""SELECT conname FROM pg_constraint WHERE contype='f'
        AND conrelid=format('public.%%I',%s)::regclass""", (t,))
    return {r[0] for r in cur.fetchall()}

def cloud_trigs(t):
    cur.execute("""SELECT trigger_name FROM information_schema.triggers
        WHERE event_object_schema='public' AND event_object_table=%s""", (t,))
    return {r[0] for r in cur.fetchall()}

def cloud_count(t):
    try:
        cur.execute(f"SELECT COUNT(*) FROM {t}"); return cur.fetchone()[0]
    except: return -1

local_tables = set(local.keys())
ct = cloud_tables()

print(f"### SUMMARY ###")
print(f"Local tables: {len(local_tables)}  |  Cloud tables: {len(ct)}  |  Shared: {len(local_tables & ct)}")
print()

only_local = sorted(local_tables - ct)
only_cloud = sorted(ct - local_tables)
shared = sorted(local_tables & ct)

if only_local:
    print(f"### MISSING TABLES (in local, not cloud) — {len(only_local)} ###")
    for t in only_local:
        rc = local[t]['row_count']
        print(f"  - {t}  (local rows={rc})")
    print()

if only_cloud:
    print(f"### EXTRA TABLES (in cloud, not local) — {len(only_cloud)} ###")
    for t in only_cloud:
        rc = cloud_count(t)
        print(f"  - {t}  (cloud rows={rc})")
    print()

missing_cols = []
type_mismatches = []
missing_idx = []
missing_fk = []
missing_trig = []
row_deltas = []

for t in shared:
    lcols = local[t]['columns']
    ccols = cloud_columns(t)
    for c_name, c_def in lcols.items():
        if c_name not in ccols:
            missing_cols.append((t, c_name, c_def['data_type']))
        else:
            if lcols[c_name]['data_type'] != ccols[c_name]['data_type'] \
                or lcols[c_name]['udt'] != ccols[c_name]['udt']:
                type_mismatches.append((t, c_name,
                    f"{lcols[c_name]['data_type']}/{lcols[c_name]['udt']}",
                    f"{ccols[c_name]['data_type']}/{ccols[c_name]['udt']}"))

    li = set(local[t]['indexes'].keys())
    ci = cloud_indexes(t)
    for i in sorted(li - ci):
        missing_idx.append((t, i))

    lf = set(local[t]['foreign_keys'].keys())
    cf = cloud_fks(t)
    for f in sorted(lf - cf):
        missing_fk.append((t, f, local[t]['foreign_keys'][f][:80]))

    lt = set(local[t]['triggers'].keys())
    ct_trigs = cloud_trigs(t)
    for tr in sorted(lt - ct_trigs):
        missing_trig.append((t, tr))

    lrc = local[t]['row_count']
    crc = cloud_count(t)
    if isinstance(lrc, int) and isinstance(crc, int) and lrc != crc:
        row_deltas.append((t, lrc, crc, lrc - crc))

# Group missing columns by table for concise output
by_table = {}
for t, c, ty in missing_cols:
    by_table.setdefault(t, []).append(f"{c}({ty})")
print(f"### MISSING COLUMNS — {len(missing_cols)} cols across {len(by_table)} tables ###")
for t in sorted(by_table.keys()):
    cols = by_table[t]
    print(f"COL {t}: {', '.join(cols)}")
print()

print(f"### TYPE MISMATCHES — {len(type_mismatches)} ###")
for t, c, lt_, ct_ in type_mismatches[:40]:
    print(f"TYP {t}.{c}: local={lt_} cloud={ct_}")
print()

print(f"### COUNTS — idx={len(missing_idx)} fk={len(missing_fk)} trig={len(missing_trig)} ###")
print(f"### IMPORTANT MISSING (FK + triggers + first 20 idx) ###")
for t, n in missing_trig:
    print(f"TRG {t}.{n}")
for t, n, d in missing_fk:
    print(f"FK  {t}.{n}: {d[:60]}")
for t, n in missing_idx[:20]:
    print(f"IDX {t}.{n}")

print(f"### ROW DELTAS top 15 ###")
for t, lrc, crc, delta in sorted(row_deltas, key=lambda x: -abs(x[3]))[:15]:
    print(f"ROW {t}: local={lrc} cloud={crc} delta={delta:+d}")
