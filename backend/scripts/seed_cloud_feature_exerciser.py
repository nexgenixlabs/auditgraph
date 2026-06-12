#!/usr/bin/env python3
"""
Run seed_feature_exerciser.py against the cloud dev AuditGraph Demo org.

The local script hardcodes ``DEMO_ORG_ID = 9`` with a safety check that
the org name contains "demo". Cloud dev's demo org is id=3
"AuditGraph Demo" (slug "auditgraph-demo") which passes the name check
but fails the id check. Rather than rebuild the migration image to ship
an updated script, we launch the existing migration-migrate Container
Apps Job with a command override that imports the in-image
seed_feature_exerciser module, monkeypatches DEMO_ORG_ID to the cloud
org's id, and calls main().

Same pattern as seed_cloud_demo_org.py. Idempotent — the exerciser
UPDATEs existing rows + UPSERTs ~15 named demo-feature-* identities;
re-running it just refreshes the data.

Usage:
  python scripts/seed_cloud_feature_exerciser.py \
      --rg cus-ag-nonprod-rg --job migration-migrate \
      --org-id 3
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
    ap.add_argument("--org-id", type=int, required=True,
                    help="cloud demo org id to target (e.g. 3 on dev cloud)")
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

    # The v38 cloud migration image was built before seed_feature_exerciser.py
    # existed (script first committed 2026-06-10; image is older). Rather
    # than rebuild the migration image (blocked locally because the
    # Dockerfile COPYs gitignored data dumps), we ship the script's
    # CURRENT source into the container via base64, write it to /tmp,
    # then import it with DEMO_ORG_ID monkeypatched.
    import base64 as _b64, os as _os
    here = _os.path.dirname(_os.path.abspath(__file__))
    src_path = _os.path.join(here, 'seed_feature_exerciser.py')
    with open(src_path, 'r') as fh:
        fx_src = fh.read()
    fx_encoded = _b64.b64encode(fx_src.encode('utf-8')).decode('ascii')

    # NOTE on env: the local script defaults DB_PORT=5434 (local docker)
    # and the connect() helper doesn't pass sslmode. Cloud DB listens on
    # 5432 and requires SSL. We monkeypatch both: DEMO_ORG_ID, DB_PORT,
    # and connect() itself. The script's other module-level constants
    # (DB_HOST/NAME/USER/PASS) come from the container env, which is
    # already correct.
    py = f"""
import sys, importlib.util, psycopg2
from psycopg2.extras import RealDictCursor
sys.path.insert(0, '/app/backend')
sys.path.insert(0, '/app')

spec = importlib.util.spec_from_file_location('fx', '/tmp/seed_feature_exerciser.py')
fx = importlib.util.module_from_spec(spec)
sys.modules['fx'] = fx
spec.loader.exec_module(fx)

print(f'[wrapper] original DEMO_ORG_ID = {{fx.DEMO_ORG_ID}}  DB_PORT = {{fx.DB_PORT}}')
fx.DEMO_ORG_ID = {args.org_id}
fx.DB_PORT = 5432

def _patched_connect():
    return psycopg2.connect(
        host=fx.DB_HOST, port=fx.DB_PORT, dbname=fx.DB_NAME,
        user=fx.DB_USER, password=fx.DB_PASS,
        sslmode='require', cursor_factory=RealDictCursor,
    )
fx.connect = _patched_connect
print(f'[wrapper] patched  DEMO_ORG_ID = {{fx.DEMO_ORG_ID}}  DB_PORT = {{fx.DB_PORT}}  sslmode=require')

fx.main()
print('FEATURE_EXERCISER_COMPLETE_OK')
"""
    py_encoded = _b64.b64encode(py.encode('utf-8')).decode('ascii')
    bash = (
        'set -e; '
        'cd /app/backend; '
        f'echo {fx_encoded} | base64 -d > /tmp/seed_feature_exerciser.py; '
        f'echo {py_encoded} | base64 -d > /tmp/fx_invoke.py; '
        'python3 /tmp/fx_invoke.py'
    )

    body = {"containers": [{
        "name": cname, "image": image,
        "command": ["/bin/bash"], "args": ["-c", bash],
        "env": env,
    }]}
    uri = (f"https://management.azure.com/subscriptions/{sub}"
           f"/resourceGroups/{args.rg}/providers/Microsoft.App/jobs/{args.job}"
           f"/start?api-version={API_VERSION}")

    print(f"  starting feature exerciser (target org_id: {args.org_id})…")
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
            print(f"    status: {st}  ({int(time.time() - t0)}s)")
            last = st
        if st and st not in ("Running", "Processing", "Pending", ""):
            break
        if time.time() - t0 > 1800:
            sys.exit("  ✗ timed out waiting for execution")
        time.sleep(10)

    print(f"  final: {last}")
    if last != "Succeeded":
        sys.exit("  ✗ feature exerciser did not succeed — check Log Analytics")
    print(f"  ✓ feature exerciser complete (look for FEATURE_EXERCISER_COMPLETE_OK in LAW)")
    print(f"  execution name: {exec_name}")


if __name__ == "__main__":
    main()
