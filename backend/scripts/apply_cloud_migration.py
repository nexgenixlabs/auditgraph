#!/usr/bin/env python3
"""
Apply a single SQL migration to the cloud dev DB via the migration-migrate
Container Apps Job — WITHOUT rebuilding the migration image.

Why: the migration image build bundles gitignored data dumps that aren't always
present locally, which blocks `az acr build`. This script instead starts the
EXISTING job image with a per-execution command override that pipes the
migration SQL straight into psql (the job already carries DB creds + psql).

Only use for additive / idempotent migrations (CREATE TABLE IF NOT EXISTS, etc.).

Usage:
  python scripts/apply_cloud_migration.py \
      --rg cus-ag-nonprod-rg --job migration-migrate \
      --migration-file backend/migrations/115_ai_cognitive_services_discovery.sql
"""
from __future__ import annotations
import argparse, json, subprocess, sys, time

API_VERSION = "2024-03-01"


def _run(cmd: list[str], check=True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"  ✗ {' '.join(cmd[:4])}…\n    {r.stderr.strip()}")
    return r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rg", required=True)
    ap.add_argument("--job", required=True)
    ap.add_argument("--migration-file", required=True)
    args = ap.parse_args()

    sql = open(args.migration_file).read()
    if not sql.strip():
        sys.exit("migration file is empty")

    sub = _run(["az", "account", "show", "--query", "id", "-o", "tsv"])
    print(f"  subscription: {_run(['az','account','show','--query','name','-o','tsv'])}")

    meta = json.loads(_run([
        "az", "containerapp", "job", "show", "-g", args.rg, "-n", args.job,
        "--query", "{n:properties.template.containers[0].name,"
                   "i:properties.template.containers[0].image,"
                   "e:properties.template.containers[0].env}",
        "-o", "json",
    ]))
    cname, image, env = meta["n"], meta["i"], (meta.get("e") or [])
    print(f"  job image: {image}")

    # Base64-encode the SQL so NOTHING inside it is touched by the shell.
    # Earlier version used a single-quoted heredoc, but Azure's REST/JSON
    # pipeline turned `DO $$ BEGIN` into `DO $ BEGIN` (the shell still
    # expanded `$$` to PID even though the heredoc was meant to be quoted).
    # Base64 sidesteps it: we decode to a temp file, then `psql -f`.
    import base64 as _b64
    encoded = _b64.b64encode(sql.encode('utf-8')).decode('ascii')
    bash = (
        'set -e; '
        'export DB_PORT="${DB_PORT:-5432}" DB_SSLMODE="${DB_SSLMODE:-require}"; '
        f'echo {encoded} | base64 -d > /tmp/agmig.sql; '
        'PGPASSWORD="$DB_ADMIN_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" '
        '-U "$DB_ADMIN_USER" -d "$DB_NAME" --set ON_ERROR_STOP=1 --no-psqlrc '
        '-f /tmp/agmig.sql; '
        'echo MIGRATION_APPLIED_OK'
    )

    body = {"containers": [{
        "name": cname, "image": image,
        "command": ["/bin/bash"], "args": ["-c", bash],
        "env": env,
    }]}
    uri = (f"https://management.azure.com/subscriptions/{sub}"
           f"/resourceGroups/{args.rg}/providers/Microsoft.App/jobs/{args.job}"
           f"/start?api-version={API_VERSION}")

    print("  starting one-off execution (command override, image unchanged)…")
    raw = _run(["az", "rest", "--method", "POST", "--uri", uri,
                "--body", json.dumps(body), "-o", "json"])
    resp = json.loads(raw) if raw else {}
    exec_name = resp.get("name") or (resp.get("properties") or {}).get("name")
    if not exec_name:
        sys.exit(f"  ✗ could not parse execution name: {raw[:300]}")
    print(f"  execution: {exec_name}")

    # Poll
    t0 = time.time()
    last = ""
    while True:
        st = _run(["az", "containerapp", "job", "execution", "show",
                   "-g", args.rg, "-n", args.job, "--job-execution-name", exec_name,
                   "--query", "properties.status", "-o", "tsv"], check=False)
        if st and st != last:
            print(f"    status: {st}")
            last = st
        if st and st not in ("Running", "Processing", "Pending", ""):
            break
        if time.time() - t0 > 600:
            sys.exit("  ✗ timed out waiting for execution")
        time.sleep(8)

    print(f"  final: {last}")
    if last != "Succeeded":
        sys.exit("  ✗ migration execution did not succeed — check Log Analytics for psql errors")
    print("  ✓ migration applied (look for MIGRATION_APPLIED_OK in LAW logs to confirm)")


if __name__ == "__main__":
    main()
