#!/usr/bin/env python3
"""Dump SOURCE schema (tables, columns, indexes, FKs, triggers, row counts) to JSON."""
import os, sys, json
import psycopg2

dsn = os.environ.get('DSN') or sys.exit("Need DSN env var")
out = sys.argv[1] if len(sys.argv) > 1 else 'schema.json'

c = psycopg2.connect(dsn); c.autocommit=True; cur = c.cursor()

cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
tables = [r[0] for r in cur.fetchall()]

dump = {}
for t in tables:
    cur.execute("""SELECT column_name, data_type, udt_name, character_maximum_length, is_nullable, column_default
        FROM information_schema.columns WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position""", (t,))
    cols = {r[0]: {'data_type': r[1], 'udt': r[2], 'maxlen': r[3], 'nullable': r[4], 'default': r[5]} for r in cur.fetchall()}

    cur.execute("SELECT indexname, indexdef FROM pg_indexes WHERE schemaname='public' AND tablename=%s", (t,))
    idx = {r[0]: r[1] for r in cur.fetchall()}

    cur.execute("""SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
        WHERE contype='f' AND conrelid=format('public.%%I',%s)::regclass""", (t,))
    fks = {r[0]: r[1] for r in cur.fetchall()}

    cur.execute("""SELECT trigger_name, action_statement FROM information_schema.triggers
        WHERE event_object_schema='public' AND event_object_table=%s""", (t,))
    trigs = {r[0]: r[1] for r in cur.fetchall()}

    try:
        cur.execute(f"SELECT COUNT(*) FROM {t}"); rc = cur.fetchone()[0]
    except Exception as e:
        rc = -1

    dump[t] = {'columns': cols, 'indexes': idx, 'foreign_keys': fks, 'triggers': trigs, 'row_count': rc}

with open(out, 'w') as f:
    json.dump(dump, f, default=str)
print(f"Dumped {len(dump)} tables to {out}")
