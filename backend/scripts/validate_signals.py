#!/usr/bin/env python3
"""12-Signal Validation CLI — pretty-printed diagnostic report.

Usage:
    cd /Users/sangabattula/projects/auditgraph/backend
    source venv/bin/activate
    python scripts/validate_signals.py --org_id 2
"""

import argparse
import sys

import psycopg2

# Allow importing app modules when run from backend/
sys.path.insert(0, '.')

from app.diagnostics.signal_validator import SignalValidator

DB_CONFIG = {
    'host': 'localhost',
    'port': 5434,
    'dbname': 'auditgraph',
    'user': 'auditgraph',
    'password': 'auditgraph',
}

STATUS_COLORS = {
    'PASS': '\033[92m',  # green
    'WARN': '\033[93m',  # yellow
    'FAIL': '\033[91m',  # red
}
RESET = '\033[0m'


def main():
    parser = argparse.ArgumentParser(description='12-Signal Validation Report')
    parser.add_argument('--org_id', type=int, default=2,
                        help='Organization ID to validate (default: 2)')
    args = parser.parse_args()

    try:
        conn = psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f'\n\033[91mCannot connect to database: {e}\033[0m')
        sys.exit(1)

    validator = SignalValidator(conn)
    result = validator.validate_all(args.org_id)
    conn.close()

    # Header
    print(f'\n12-Signal Validation Report  (org_id={args.org_id})')
    print(f'Run at: {result["run_at"]}')
    print('=' * 78)
    print(f'{"Signal":<11}| {"Name":<32}| {"Status":<6}| Detail')
    print('-' * 78)

    for s in result['signals']:
        color = STATUS_COLORS.get(s['status'], '')
        status_str = f'{color}{s["status"]:<6}{RESET}'
        detail = s['detail']
        if len(detail) > 50:
            detail = detail[:47] + '...'
        print(f'Signal {s["signal_number"]:<4}| {s["name"]:<32}| {status_str}| {detail}')

    # Summary
    summary = result['summary']
    print('-' * 78)
    p = f'\033[92m{summary["passed"]} PASS\033[0m'
    w = f'\033[93m{summary["warned"]} WARN\033[0m'
    f_ = f'\033[91m{summary["failed"]} FAIL\033[0m'
    print(f'SUMMARY: {p} | {w} | {f_}')
    print()


if __name__ == '__main__':
    main()
