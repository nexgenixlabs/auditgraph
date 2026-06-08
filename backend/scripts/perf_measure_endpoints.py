#!/usr/bin/env python3
"""
Measure API endpoint latency against a seeded perf-test org.

Hits each key endpoint N times, computes p50/p95/p99, prints a Markdown
table. Designed to produce the artifact for docs/AG_PERF_BASELINE_*.md.

Usage:
  ./perf_measure_endpoints.py --org-id 99 --runs 20
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.request
import urllib.error

ENDPOINTS = [
    # path, description, expected status
    ('/api/health',                                  'health'),
    ('/api/stats',                                   'stats summary'),
    ('/api/identities?limit=50',                     'identity list (paginated, default 50)'),
    ('/api/identities?limit=500',                    'identity list (heavy, 500 rows)'),
    ('/api/identity-summary',                        'identity category breakdown'),
    ('/api/dashboard/posture',                       'dashboard posture'),
    ('/api/identity-trust/rollup',                   'identity trust org rollup'),
    ('/api/identity-security/pim/overprivilege',     'PIM Overprivilege analysis'),
    ('/api/identity-security/entra-role-activity',   'Entra Role Activity rollup'),
]


ADMIN_HOST_HEADER = 'admin.localhost'   # subdomain check resolves techadmin to superadmin context


def login(base: str, username: str, password: str) -> str:
    req = urllib.request.Request(
        f'{base}/api/auth/login',
        data=json.dumps({'username': username, 'password': password}).encode(),
        headers={'Content-Type': 'application/json', 'Host': ADMIN_HOST_HEADER},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read())
    return body['access_token']


def time_endpoint(base: str, path: str, token: str, org_id: int) -> float | None:
    req = urllib.request.Request(
        f'{base}{path}',
        headers={
            'Authorization': f'Bearer {token}',
            'X-Tenant-Id': str(org_id),
            'Host': ADMIN_HOST_HEADER,
        },
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        return (time.perf_counter() - t0) * 1000  # ms
    except urllib.error.HTTPError as e:
        print(f"    HTTP {e.code} on {path}: {e.read()[:120].decode(errors='ignore')}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"    EXCEPTION on {path}: {e}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base',     default='http://localhost:5001')
    ap.add_argument('--org-id',   type=int, required=True)
    ap.add_argument('--username', default='nexgenadmin')          # need superadmin for X-Org-Id override
    ap.add_argument('--password', default='changeme')
    ap.add_argument('--runs',     type=int, default=10)
    ap.add_argument('--warmup',   type=int, default=2)
    args = ap.parse_args()

    print(f"  base={args.base}  org_id={args.org_id}  runs={args.runs}", file=sys.stderr)
    print(f"  authenticating as {args.username}…", file=sys.stderr)
    token = login(args.base, args.username, args.password)
    print(f"  ok, got token", file=sys.stderr)

    results: list[dict] = []
    for path, desc in ENDPOINTS:
        # warmup
        for _ in range(args.warmup):
            time_endpoint(args.base, path, token, args.org_id)

        # measure
        samples_ms: list[float] = []
        for _ in range(args.runs):
            ms = time_endpoint(args.base, path, token, args.org_id)
            if ms is not None:
                samples_ms.append(ms)
            time.sleep(0.05)

        if not samples_ms:
            results.append({'path': path, 'desc': desc, 'p50': None, 'p95': None,
                            'p99': None, 'min': None, 'max': None, 'n': 0})
            continue

        samples_ms.sort()
        p50 = samples_ms[len(samples_ms) // 2]
        p95 = samples_ms[min(len(samples_ms) - 1, int(len(samples_ms) * 0.95))]
        p99 = samples_ms[min(len(samples_ms) - 1, int(len(samples_ms) * 0.99))]
        results.append({
            'path': path, 'desc': desc,
            'p50': p50, 'p95': p95, 'p99': p99,
            'min': min(samples_ms), 'max': max(samples_ms),
            'n': len(samples_ms),
        })
        print(f"  {path:55}  p50={p50:7.1f}ms  p95={p95:7.1f}ms", file=sys.stderr)

    # Markdown table to stdout
    print()
    print("| Endpoint | Description | n | p50 (ms) | p95 (ms) | p99 (ms) | min | max |")
    print("|---|---|---|---:|---:|---:|---:|---:|")
    for r in results:
        if r['n'] == 0:
            print(f"| `{r['path']}` | {r['desc']} | 0 | FAIL | FAIL | FAIL | – | – |")
        else:
            print(f"| `{r['path']}` | {r['desc']} | {r['n']} | "
                  f"{r['p50']:.1f} | {r['p95']:.1f} | {r['p99']:.1f} | "
                  f"{r['min']:.1f} | {r['max']:.1f} |")


if __name__ == '__main__':
    main()
