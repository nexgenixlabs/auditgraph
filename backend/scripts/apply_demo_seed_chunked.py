#!/usr/bin/env python3
"""Apply the replicated-demo SQL to cloud-dev in chunks.

The full SQL is ~900KB which exceeds the OS argv limit when passed
via the existing apply_cloud_migration.py harness (which base64-
encodes and inlines). This wrapper splits the SQL into chunks of
~100 statements each (~80KB each) and applies them serially.
"""
import os
import subprocess
import sys
import tempfile


INPUT_SQL = '/tmp/replicate_demo_to_cloud.sql'
CHUNK_STMTS = 100  # statements per chunk


def parse_statements(sql_text):
    """Strip line-comments first, then split on top-level semicolons.
    The generated SQL has no $$ blocks or multi-line string literals."""
    # Drop full-line comments (the only kind in our generated SQL)
    cleaned_lines = []
    for ln in sql_text.split('\n'):
        if ln.lstrip().startswith('--'):
            continue
        cleaned_lines.append(ln)
    cleaned = '\n'.join(cleaned_lines)

    parts = []
    cur = []
    in_string = False
    for ch in cleaned:
        if ch == "'":
            in_string = not in_string
        cur.append(ch)
        if ch == ';' and not in_string:
            stmt = ''.join(cur).strip()
            if stmt:
                parts.append(stmt)
            cur = []
    if cur:
        rem = ''.join(cur).strip()
        if rem:
            parts.append(rem)
    return parts


def main():
    with open(INPUT_SQL) as f:
        sql = f.read()

    # Strip the BEGIN/COMMIT and verification queries — we'll wrap each
    # chunk in its own BEGIN/COMMIT
    lines = sql.split('\n')
    body = []
    for ln in lines:
        s = ln.strip()
        if s.upper() in ('BEGIN;', 'COMMIT;'):
            continue
        if s.startswith('\\set'):
            continue
        if 'Verification queries' in s:
            break
        body.append(ln)
    body_text = '\n'.join(body)

    stmts = parse_statements(body_text)
    print(f"Total statements: {len(stmts)}", file=sys.stderr)

    chunks = [stmts[i:i+CHUNK_STMTS] for i in range(0, len(stmts), CHUNK_STMTS)]
    print(f"Chunks of {CHUNK_STMTS}: {len(chunks)}", file=sys.stderr)

    for idx, chunk in enumerate(chunks, 1):
        chunk_sql = (
            "\\set ON_ERROR_STOP on\n"
            "BEGIN;\n"
            + '\n'.join(chunk) + '\n'
            "COMMIT;\n"
        )
        with tempfile.NamedTemporaryFile(
                mode='w', suffix=f'.chunk{idx}.sql', delete=False) as tf:
            tf.write(chunk_sql)
            tf_path = tf.name
        size = os.path.getsize(tf_path)
        print(f"\n── Chunk {idx}/{len(chunks)} ({len(chunk)} stmts, {size:,} bytes) ──",
              file=sys.stderr)

        r = subprocess.run([
            './backend/venv/bin/python3',
            'backend/scripts/apply_cloud_migration.py',
            '--rg', 'cus-ag-nonprod-rg',
            '--job', 'migration-migrate',
            '--migration-file', tf_path,
        ], capture_output=True, text=True)
        out = (r.stdout + r.stderr)
        # Show just the bottom of the output (status lines)
        for line in out.split('\n')[-6:]:
            print(f"    {line}", file=sys.stderr)
        if r.returncode != 0:
            sys.exit(f"chunk {idx} failed")
        os.unlink(tf_path)

    print(f"\n✓ All {len(chunks)} chunks applied", file=sys.stderr)


if __name__ == '__main__':
    main()
