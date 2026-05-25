#!/usr/bin/env python3
"""
Cloud sibling of `nuke_org.py` — deletes an organization (and all its data)
from the **cloud dev** PostgreSQL by orchestrating the existing
`migration-migrate` Container Apps Job.

Why a wrapper?
  The cloud PG (`cus-ag-nonprod-pg`) is VNet-only — nothing outside `dev-vnet`
  can reach it directly. The migration image already bundles `nuke_org.py` and
  `verify_org_cleanup.py`; we just need to start the job with the right PHASE
  and env vars, then poll execution status and (optionally) tail logs.

Usage:
  python scripts/cloud_nuke_org.py                            # list orgs
  python scripts/cloud_nuke_org.py --org-id 11 --dry-run      # preview
  python scripts/cloud_nuke_org.py --org-id 11 --force        # delete
  python scripts/cloud_nuke_org.py --org-id 11 --force \\
         --verify --fix --restart-api                         # full pipeline

Pre-reqs (one-time):
  az login
  az account set --subscription "AzureSponsorshipCredit"

Defaults match docs/cloud-org-cleanup-runbook.md. Override with --rg/--job/
--api-app/--law for other environments.

How it bypasses run.sh:
  The `az containerapp job` CLI has no `--command/--args` flags, but the
  underlying REST API (`POST .../jobs/{name}/start`) accepts a per-execution
  JobExecutionTemplate body with container command/args overrides. We send
  that via `az rest`, which is a true per-execution override — the job's
  stored template is never mutated. Invokes the bundled `nuke_org.py` /
  `verify_org_cleanup.py` directly, so this works against the currently
  deployed migration image with no rebuild.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from typing import Optional


# ── Defaults (override via CLI flags) ────────────────────────────────────────
DEFAULT_RG       = 'cus-ag-nonprod-rg'
DEFAULT_JOB      = 'migration-migrate'
DEFAULT_API_APP  = 'auditgraph-api'
DEFAULT_LAW      = 'cus-ag-nonprod-law'
DEFAULT_CONTAINER_NAME = 'migration-migrate'  # container name inside the job


# ── Tiny shell helpers ───────────────────────────────────────────────────────
def _run(cmd: list[str], capture: bool = True, check: bool = True) -> str:
    """Run az/etc. Returns stdout (stripped) when capture=True."""
    if not capture:
        rc = subprocess.call(cmd)
        if check and rc != 0:
            sys.exit(f'  ✗ command failed (exit {rc}): {shlex.join(cmd)}')
        return ''
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        sys.exit(
            f'  ✗ command failed (exit {res.returncode}): {shlex.join(cmd)}\n'
            f'    stderr: {res.stderr.strip()}'
        )
    return res.stdout.strip()


def _ok(msg: str)   -> None: print(f'  \033[1;32m✓\033[0m {msg}')
def _warn(msg: str) -> None: print(f'  \033[1;33m⚠\033[0m {msg}')
def _fail(msg: str) -> None: sys.exit(f'  \033[1;31m✗\033[0m {msg}')
def _step(msg: str) -> None: print(f'\n\033[1;34m▸ {msg}\033[0m')


# ── Az helpers ───────────────────────────────────────────────────────────────
def az_check_login() -> None:
    out = _run(['az', 'account', 'show', '--query', 'name', '-o', 'tsv'], check=False)
    if not out:
        _fail('Not logged in to az. Run: az login && az account set --subscription "AzureSponsorshipCredit"')
    print(f'  subscription: {out}')


def az_check_job(rg: str, job: str) -> None:
    out = _run(
        ['az', 'containerapp', 'job', 'show', '-g', rg, '-n', job, '--query', 'name', '-o', 'tsv'],
        check=False,
    )
    if out != job:
        _fail(f'Container Apps Job "{job}" not found in resource group "{rg}".')


_API_VERSION = '2024-03-01'


def az_subscription_id() -> str:
    sub = _run(['az', 'account', 'show', '--query', 'id', '-o', 'tsv'])
    if not sub:
        _fail('Could not resolve subscription id.')
    return sub


def az_job_container_meta(rg: str, job: str) -> tuple[str, str, list[dict]]:
    """Return (container_name, image, env) of the job's first container. The
    per-execution override REPLACES the container spec — so we must forward the
    existing env vars (incl. secretRef entries) or scripts will see no DB creds."""
    raw = _run(
        ['az', 'containerapp', 'job', 'show', '-g', rg, '-n', job,
         '--query', '{n:properties.template.containers[0].name,'
                    'i:properties.template.containers[0].image,'
                    'e:properties.template.containers[0].env}',
         '-o', 'json'],
    )
    d = json.loads(raw)
    name  = d.get('n') or 'migration-migrate'
    image = d.get('i')
    env   = d.get('e') or []
    if not image:
        _fail(f'Could not read container image from job "{job}".')
    return name, image, env


def az_run_bash(rg: str, job: str, bash_cmd: str) -> str:
    """
    Start one job execution with a per-execution container override
    (`/bin/bash -c bash_cmd`) via the ARM REST API. The job's stored template
    is NOT mutated. Returns the execution name.
    """
    sub = az_subscription_id()
    container_name, image, env = az_job_container_meta(rg, job)
    body = {
        'containers': [{
            'name':    container_name,
            'image':   image,
            'command': ['/bin/bash'],
            'args':    ['-c', bash_cmd],
            'env':     env,
        }],
    }
    uri = (
        f'https://management.azure.com/subscriptions/{sub}'
        f'/resourceGroups/{rg}/providers/Microsoft.App/jobs/{job}'
        f'/start?api-version={_API_VERSION}'
    )
    raw = _run(
        ['az', 'rest', '--method', 'POST',
         '--uri', uri,
         '--body', json.dumps(body),
         '-o', 'json'],
    )
    try:
        resp = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        _fail(f'Unexpected response from jobs/start: {raw[:300]}')
    name = resp.get('name') or (resp.get('properties') or {}).get('name')
    if not name:
        _fail(f'Could not parse execution name from response: {raw[:300]}')
    return name


def az_poll_execution(rg: str, job: str, exec_name: str, timeout_s: int = 1800) -> str:
    """Poll until status leaves Running/Pending. Return final status."""
    t0 = time.time()
    last = ''
    while True:
        status = _run(
            ['az', 'containerapp', 'job', 'execution', 'show',
             '-g', rg, '-n', job, '--job-execution-name', exec_name,
             '--query', 'properties.status', '-o', 'tsv'],
            check=False,
        )
        if status and status != last:
            print(f'    status: {status}')
            last = status
        if status and status not in ('Running', 'Processing', 'Pending', ''):
            return status
        if time.time() - t0 > timeout_s:
            _fail(f'Timed out waiting for {exec_name} (last status: {status or "unknown"}).')
        time.sleep(8)


def az_tail_logs(rg: str, law_name: str, container_name: str, since_minutes: int = 5,
                 grep: Optional[str] = None, limit: int = 200) -> None:
    """Pull recent ContainerAppConsoleLogs from Log Analytics."""
    ws_id = _run(
        ['az', 'monitor', 'log-analytics', 'workspace', 'show',
         '-g', rg, '-n', law_name, '--query', 'customerId', '-o', 'tsv'],
        check=False,
    )
    if not ws_id:
        _warn(f'Log Analytics workspace "{law_name}" not found in "{rg}" — skipping log fetch.')
        return
    contains = f' and Log_s contains "{grep}"' if grep else ''
    query = (
        f'ContainerAppConsoleLogs_CL '
        f'| where ContainerName_s == "{container_name}" '
        f'and TimeGenerated > ago({since_minutes}m){contains} '
        f'| order by TimeGenerated asc '
        f'| project TimeGenerated, Log_s '
        f'| take {limit}'
    )
    raw = _run(
        ['az', 'monitor', 'log-analytics', 'query', '-w', ws_id,
         '--analytics-query', query, '-o', 'json'],
        check=False,
    )
    if not raw:
        return
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        print(raw)
        return
    for r in rows:
        line = (r.get('Log_s') or '').rstrip()
        if line:
            print(f'    {line}')


# ── Bash one-liners run inside the container ────────────────────────────────
# DB_HOST/DB_NAME/DB_ADMIN_USER/DB_ADMIN_PASSWORD must already be configured as
# env vars on the migration-migrate CA Job (they are — `migrate` phase needs
# them). DB_PORT and DB_SSLMODE fall back to cloud-safe defaults if unset.
_ENV_PREAMBLE = (
    'export DB_PORT="${DB_PORT:-5432}" DB_SSLMODE="${DB_SSLMODE:-require}" '
    'DB_ADMIN_USER="${DB_ADMIN_USER:-$DB_USER}" '
    'DB_ADMIN_PASSWORD="${DB_ADMIN_PASSWORD:-$DB_PASSWORD}"'
)


def _bash(cmd: str) -> str:
    return f'{_ENV_PREAMBLE} && {cmd}'


# ── Phase orchestrators ──────────────────────────────────────────────────────
def phase_list(args: argparse.Namespace) -> None:
    _step('Listing orgs (nuke_org.py --list)')
    bash_cmd = _bash('python3 /app/backend/scripts/nuke_org.py --list')
    exec_name = az_run_bash(args.rg, args.job, bash_cmd)
    print(f'  execution: {exec_name}')
    status = az_poll_execution(args.rg, args.job, exec_name)
    print(f'  final: {status}')
    _step('Logs (Log Analytics)')
    az_tail_logs(args.rg, args.law, args.container, since_minutes=5)


def phase_nuke(args: argparse.Namespace, org_id: int) -> str:
    _step(f'Nuking org_id={org_id}  dry_run={int(args.dry_run)}  force={int(args.force)}')
    if args.dry_run is False and args.force is False:
        _fail('Refusing to delete without --force. Re-run with --force (or use --dry-run).')
    flags = f'--org-id {org_id}'
    if args.dry_run:
        flags += ' --dry-run'
    if args.force:
        flags += ' --force'
    bash_cmd = _bash(f'python3 /app/backend/scripts/nuke_org.py {flags}')
    exec_name = az_run_bash(args.rg, args.job, bash_cmd)
    print(f'  execution: {exec_name}')
    status = az_poll_execution(args.rg, args.job, exec_name)
    print(f'  final: {status}')
    _step('Logs (Log Analytics — Deleted/Total lines)')
    az_tail_logs(args.rg, args.law, args.container, since_minutes=10, grep='Deleted')
    az_tail_logs(args.rg, args.law, args.container, since_minutes=10, grep='Total')
    if status != 'Succeeded':
        _fail(f'nuke execution ended with status: {status}')
    _ok('nuke complete')
    return status


def phase_verify(args: argparse.Namespace, org_id: int) -> str:
    _step(f'Verifying org_id={org_id}  fix={int(args.fix)}')
    flags = f'--org-id {org_id} --no-prompt'
    if args.fix:
        flags += ' --fix'
    bash_cmd = _bash(f'python3 /app/backend/scripts/verify_org_cleanup.py {flags}')
    exec_name = az_run_bash(args.rg, args.job, bash_cmd)
    print(f'  execution: {exec_name}')
    status = az_poll_execution(args.rg, args.job, exec_name)
    print(f'  final: {status}')
    _step('Logs (Log Analytics — verify summary)')
    az_tail_logs(args.rg, args.law, args.container, since_minutes=10)
    if status != 'Succeeded':
        _warn(f'verify ended with status: {status} (review logs above)')
    return status


def phase_restart_api(args: argparse.Namespace) -> None:
    _step(f'Restarting API container app: {args.api_app}')
    latest = _run(
        ['az', 'containerapp', 'revision', 'list', '-g', args.rg, '-n', args.api_app,
         '--query', '[?properties.active].name | [0]', '-o', 'tsv'],
    )
    if not latest:
        _fail(f'No active revision found on {args.api_app}.')
    print(f'  active revision: {latest}')
    _run(
        ['az', 'containerapp', 'revision', 'restart', '-g', args.rg, '-n', args.api_app,
         '--revision', latest],
    )
    _ok('API restart issued (replicas will recycle in ~30s)')


# ── CLI ──────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='cloud_nuke_org',
        description='Delete an organization from the cloud dev PG via the migration CA Job.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  cloud_nuke_org.py                                # list orgs\n'
            '  cloud_nuke_org.py --org-id 11 --dry-run          # preview delete\n'
            '  cloud_nuke_org.py --org-id 11 --force            # delete\n'
            '  cloud_nuke_org.py --org-id 11 --force \\\n'
            '                    --verify --fix --restart-api   # full pipeline\n'
        ),
    )
    p.add_argument('--org-id',   type=int, help='Organization ID to delete')
    p.add_argument('--list',     action='store_true', help='List orgs in cloud DB (default if no --org-id)')
    p.add_argument('--dry-run',  action='store_true', help='Preview only — no deletion')
    p.add_argument('--force',    action='store_true', help='Required to actually delete (CA Job has no TTY)')
    p.add_argument('--verify',   action='store_true', help='After nuke, run verify-org')
    p.add_argument('--fix',      action='store_true', help='With --verify, auto-fix leaked rows')
    p.add_argument('--restart-api', action='store_true', help='After nuke (+verify), restart API container app')

    p.add_argument('--rg',        default=DEFAULT_RG,            help=f'Resource group (default: {DEFAULT_RG})')
    p.add_argument('--job',       default=DEFAULT_JOB,           help=f'Migration job name (default: {DEFAULT_JOB})')
    p.add_argument('--api-app',   default=DEFAULT_API_APP,       help=f'API container app (default: {DEFAULT_API_APP})')
    p.add_argument('--law',       default=DEFAULT_LAW,           help=f'Log Analytics workspace (default: {DEFAULT_LAW})')
    p.add_argument('--container', default=DEFAULT_CONTAINER_NAME,help=f'Job container name in LAW (default: {DEFAULT_CONTAINER_NAME})')
    return p


def main() -> None:
    args = build_parser().parse_args()

    az_check_login()
    az_check_job(args.rg, args.job)

    # ── List mode (default when no --org-id) ──
    if args.list or args.org_id is None:
        phase_list(args)
        if args.org_id is None:
            print('\n  Next: cloud_nuke_org.py --org-id <ID> --dry-run')
            print('        cloud_nuke_org.py --org-id <ID> --force\n')
        return

    org_id = args.org_id

    # ── Delete ──
    phase_nuke(args, org_id)

    # ── Verify (optional) ──
    if args.verify or args.fix:
        # --fix implies --verify
        phase_verify(args, org_id)

    # ── Restart API (optional) ──
    if args.restart_api:
        phase_restart_api(args)

    print(f'\n  Suggested next checks:')
    print(f'    cloud_nuke_org.py --org-id {org_id} --verify         # confirm no leaks')
    print(f'    open https://dev.app.auditgraph.ai                   # re-enroll via self-signup\n')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit('\n  aborted.')
