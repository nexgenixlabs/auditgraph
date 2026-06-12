#!/usr/bin/env python3
"""
Run seed_demo_tenant.py against the cloud dev AuditGraph Demo org.

The local seeder hardcodes `WHERE slug = 'demo'` but cloud dev's demo
organization has slug `auditgraph-demo`. Rather than mutate the cloud DB
slug or rebuild the migration image (blocked by gitignored dumps), we
launch the existing migration-migrate Container Apps Job with a command
override that:

  1. Imports the in-image seed_demo_tenant module
  2. Monkeypatches get_demo_org_id() to look up the cloud slug
  3. Calls main()

The job image already carries backend/scripts/seed_demo_tenant.py
(deploy/migration/Dockerfile COPYs the whole backend/ dir), so no rebuild
is needed. Same idempotency contract as the seeder itself — it deletes
existing demo-org data before re-seeding.

Usage:
  python scripts/seed_cloud_demo_org.py \
      --rg cus-ag-nonprod-rg --job migration-migrate \
      --slug auditgraph-demo
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
    ap.add_argument("--slug", default="auditgraph-demo",
                    help="slug of the demo org in the cloud DB (default: auditgraph-demo)")
    args = ap.parse_args()

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

    # Python script body — monkeypatches the slug lookup then runs main().
    # base64-encode to dodge any shell interpolation of the Python source.
    import base64 as _b64
    py = f"""
import sys
sys.path.insert(0, '/app/backend')
sys.path.insert(0, '/app')
import scripts.seed_demo_tenant as s

def _patched_lookup(db):
    cur = db.conn.cursor()
    cur.execute("SELECT id FROM organizations WHERE slug = %s", ({args.slug!r},))
    row = cur.fetchone()
    cur.close()
    if not row:
        raise RuntimeError("No org found with slug {args.slug}")
    return row[0]

s.get_demo_org_id = _patched_lookup
s.main()
print("SEED_COMPLETE_OK")
"""
    py_encoded = _b64.b64encode(py.encode('utf-8')).decode('ascii')
    bash = (
        'set -e; '
        'cd /app/backend; '
        f'echo {py_encoded} | base64 -d > /tmp/seed_invoke.py; '
        'python3 /tmp/seed_invoke.py'
    )

    body = {"containers": [{
        "name": cname, "image": image,
        "command": ["/bin/bash"], "args": ["-c", bash],
        "env": env,
    }]}
    uri = (f"https://management.azure.com/subscriptions/{sub}"
           f"/resourceGroups/{args.rg}/providers/Microsoft.App/jobs/{args.job}"
           f"/start?api-version={API_VERSION}")

    print(f"  starting seed execution (target slug: {args.slug})…")
    raw = _run(["az", "rest", "--method", "POST", "--uri", uri,
                "--body", json.dumps(body), "-o", "json"])
    resp = json.loads(raw) if raw else {}
    exec_name = resp.get("name") or (resp.get("properties") or {}).get("name")
    if not exec_name:
        sys.exit(f"  ✗ could not parse execution name: {raw[:300]}")
    print(f"  execution: {exec_name}")

    # Poll — seeder takes ~5-15 minutes
    t0 = time.time()
    last = ""
    while True:
        st = _run(["az", "containerapp", "job", "execution", "show",
                   "-g", args.rg, "-n", args.job, "--job-execution-name", exec_name,
                   "--query", "properties.status", "-o", "tsv"], check=False)
        if st and st != last:
            print(f"    status: {st}  ({int(time.time() - t0)}s)")
            last = st
        if st and st not in ("Running", "Processing", "Pending", ""):
            break
        if time.time() - t0 > 1800:  # 30 min
            sys.exit("  ✗ timed out waiting for execution")
        time.sleep(10)

    print(f"  final: {last}")
    if last != "Succeeded":
        sys.exit("  ✗ seed execution did not succeed — check Log Analytics for errors")
    print(f"  ✓ seed complete (look for SEED_COMPLETE_OK in LAW logs to confirm)")
    print(f"  execution name: {exec_name}")


if __name__ == "__main__":
    main()
