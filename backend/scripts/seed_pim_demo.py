#!/usr/bin/env python3
"""
Seed the PIM Overprivilege demo personas into a tenant.

5 demo identities, each triggering exactly one finding type from the
PIM Overprivilege catalog:

  demo-pim-dormant-globaladmin  → pim_unused_eligibility (CRITICAL)
  demo-pim-rare-userAdmin       → pim_low_frequency_activation (HIGH)
  demo-pim-weak-mfa-securityAdmin → pim_weak_activation_control (CRITICAL)
  demo-pim-active-appAdmin      → no finding (working as intended)
  demo-pim-stale-billing        → pim_low_frequency_activation (MEDIUM)

Idempotent. Safe to re-run. Targets org_id passed via --org-id.

Usage:
  ./seed_pim_demo.py --org-id 9             # local sandbox
  ./seed_pim_demo.py --org-id 3 --cloud     # cloud-dev (uses admin DB)
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

import psycopg2

# ─────────────────────────────────────────────────────────────────────────
# Demo personas — each crafted to trigger one finding type
# ─────────────────────────────────────────────────────────────────────────

NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc)

PERSONAS = [
    {
        'identity_id':  'demo-pim-dormant-globaladmin@auditgraph-demo.com',
        'display_name': 'Dormant Global Admin (demo)',
        'role_name':    'Global Administrator',
        'role_template_id': '62e90394-69f5-4237-9190-012177145e10',
        'scope':        '/',
        'scope_type':   'directory',
        'assignment_type': 'eligible',
        'eligible_since': NOW - timedelta(days=420),       # eligible >14 months
        'requires_mfa_on_activation': True,
        'requires_approval': True,
        'requires_justification': True,
        'max_activation_minutes': 480,
        'activations': [],                                  # NEVER activated → pim_unused_eligibility CRITICAL
        'story': 'Has Global Admin eligibility for 14 months; never activated; cleanup candidate',
    },
    {
        'identity_id':  'demo-pim-rare-userAdmin@auditgraph-demo.com',
        'display_name': 'Rare-Use User Admin (demo)',
        'role_name':    'User Administrator',
        'role_template_id': 'fe930be7-5e62-47db-91af-98c3a49a38b1',
        'scope':        '/',
        'scope_type':   'directory',
        'assignment_type': 'eligible',
        'eligible_since': NOW - timedelta(days=200),
        'requires_mfa_on_activation': True,
        'requires_approval': False,
        'requires_justification': True,
        'max_activation_minutes': 480,
        'activations': [
            (NOW - timedelta(days=95), 30, 'Quarterly user lifecycle bulk update'),
        ],                                                  # 1 activation 95 days ago → pim_low_frequency_activation HIGH
        'story': 'Activated once 95 days ago; quarterly use pattern; convert to time-bound assignment',
    },
    {
        'identity_id':  'demo-pim-weak-mfa-securityAdmin@auditgraph-demo.com',
        'display_name': 'Security Admin with weak activation policy (demo)',
        'role_name':    'Security Administrator',
        'role_template_id': '194ae4cb-b126-40b2-bd5b-6091b380977d',
        'scope':        '/',
        'scope_type':   'directory',
        'assignment_type': 'eligible',
        'eligible_since': NOW - timedelta(days=180),
        'requires_mfa_on_activation': False,                # ← THE PROBLEM
        'requires_approval': False,
        'requires_justification': True,
        'max_activation_minutes': 720,                      # also concerning: 12h
        'activations': [
            (NOW - timedelta(days=7),  120, 'Investigate sign-in alert'),
            (NOW - timedelta(days=30), 90,  'Conditional Access policy review'),
        ],                                                  # active legit use BUT weak policy → pim_weak_activation_control CRITICAL
        'story': 'Active legitimate Security Admin use, but activation policy bypasses MFA — config tightening',
    },
    {
        'identity_id':  'demo-pim-active-appAdmin@auditgraph-demo.com',
        'display_name': 'Healthy Active App Admin (demo)',
        'role_name':    'Application Administrator',
        'role_template_id': '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
        'scope':        '/',
        'scope_type':   'directory',
        'assignment_type': 'eligible',
        'eligible_since': NOW - timedelta(days=300),
        'requires_mfa_on_activation': True,
        'requires_approval': True,
        'requires_justification': True,
        'max_activation_minutes': 240,
        'activations': [
            (NOW - timedelta(days=2),  45, 'New app registration for partner integration'),
            (NOW - timedelta(days=9),  30, 'Update redirect URI on internal app'),
            (NOW - timedelta(days=16), 60, 'Service principal credential rotation'),
            (NOW - timedelta(days=23), 30, 'Add Graph API permission'),
            (NOW - timedelta(days=30), 45, 'New app registration for vendor'),
        ],                                                  # weekly activations → NO FINDING (control)
        'story': 'Weekly activations, healthy MFA + approval policy — working as intended, no finding',
    },
    {
        'identity_id':  'demo-pim-stale-billing@auditgraph-demo.com',
        'display_name': 'Stale Billing Admin (demo)',
        'role_name':    'Billing Administrator',
        'role_template_id': 'b0f54661-2d74-4c50-afa3-1ec803f12efe',
        'scope':        '/',
        'scope_type':   'directory',
        'assignment_type': 'eligible',
        'eligible_since': NOW - timedelta(days=540),
        'requires_mfa_on_activation': True,
        'requires_approval': False,
        'requires_justification': True,
        'max_activation_minutes': 240,
        'activations': [
            (NOW - timedelta(days=180), 60, 'Annual billing review'),
            (NOW - timedelta(days=360), 60, 'Annual billing review'),
        ],                                                  # 2 activations in ~1 year → pim_low_frequency_activation MEDIUM
        'story': 'Annual-cadence use; consider time-bound annual assignment instead of standing eligibility',
    },
]


# ─────────────────────────────────────────────────────────────────────────
# Identity creation
# ─────────────────────────────────────────────────────────────────────────

def get_or_create_identity(cursor, org_id: int, persona: dict, discovery_run_id: int) -> int:
    """Find or create the identity row, return identity.id."""
    cursor.execute("""
        SELECT id FROM identities
         WHERE organization_id = %s AND identity_id = %s
         ORDER BY discovery_run_id DESC LIMIT 1
    """, (org_id, persona['identity_id']))
    row = cursor.fetchone()
    if row:
        return row[0]

    # Create — minimal columns needed for the platform to render the identity
    cursor.execute("""
        INSERT INTO identities
            (organization_id, identity_id, display_name, identity_category,
             identity_type, source, discovery_run_id, deleted_at,
             risk_level, owner_display_name, owner_status, enabled, activity_status)
        VALUES (%s, %s, %s, 'human_user',
                'human_user', 'entra_id', %s, NULL,
                'high', 'AuditGraph Demo Platform Team', 'resolved', TRUE, 'active')
        RETURNING id
    """, (org_id, persona['identity_id'], persona['display_name'],
          discovery_run_id))
    return cursor.fetchone()[0]


def latest_or_new_discovery_run(cursor, org_id: int) -> int:
    """Return id of most recent discovery_run for org, or create one."""
    cursor.execute("""
        SELECT id FROM discovery_runs
         WHERE organization_id = %s
         ORDER BY id DESC LIMIT 1
    """, (org_id,))
    row = cursor.fetchone()
    if row:
        return row[0]

    # No existing run — create a synthetic one. Requires a cloud_connection_id.
    cursor.execute("""
        SELECT id FROM cloud_connections
         WHERE organization_id = %s LIMIT 1
    """, (org_id,))
    cc_row = cursor.fetchone()
    if not cc_row:
        raise RuntimeError(f"org {org_id} has no cloud_connections row — seed cannot proceed")
    cursor.execute("""
        INSERT INTO discovery_runs
            (organization_id, cloud_connection_id, started_at, completed_at, status)
        VALUES (%s, %s, NOW(), NOW(), 'completed')
        RETURNING id
    """, (org_id, cc_row[0]))
    return cursor.fetchone()[0]


# ─────────────────────────────────────────────────────────────────────────
# PIM data inserts
# ─────────────────────────────────────────────────────────────────────────

def seed_pim_eligibility(cursor, org_id: int, identity_db_id: int,
                          persona: dict, discovery_run_id: int):
    cursor.execute("""
        INSERT INTO pim_eligibility_state
            (organization_id, discovery_run_id, identity_db_id, identity_id,
             role_name, role_template_id, scope, scope_type,
             assignment_type, eligible_since,
             requires_mfa_on_activation, requires_approval,
             requires_justification, max_activation_minutes)
        VALUES (%s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s)
        ON CONFLICT (organization_id, identity_db_id, role_name, scope, assignment_type)
        DO UPDATE SET
            eligible_since = EXCLUDED.eligible_since,
            requires_mfa_on_activation = EXCLUDED.requires_mfa_on_activation,
            requires_approval = EXCLUDED.requires_approval,
            requires_justification = EXCLUDED.requires_justification,
            max_activation_minutes = EXCLUDED.max_activation_minutes,
            discovered_at = NOW()
    """, (org_id, discovery_run_id, identity_db_id, persona['identity_id'],
          persona['role_name'], persona['role_template_id'],
          persona['scope'], persona['scope_type'],
          persona['assignment_type'], persona['eligible_since'],
          persona['requires_mfa_on_activation'], persona['requires_approval'],
          persona['requires_justification'], persona['max_activation_minutes']))


def seed_pim_activations(cursor, org_id: int, identity_db_id: int, persona: dict):
    for i, (activated_at, duration_minutes, justification) in enumerate(persona['activations']):
        event_id = f"demo:{persona['identity_id']}:{int(activated_at.timestamp())}:{i}"
        cursor.execute("""
            INSERT INTO pim_activation_observations
                (organization_id, identity_db_id, identity_id,
                 role_name, role_template_id, scope,
                 activated_at, activation_duration_minutes,
                 justification, audit_event_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (organization_id, audit_event_id) DO NOTHING
        """, (org_id, identity_db_id, persona['identity_id'],
              persona['role_name'], persona['role_template_id'], persona['scope'],
              activated_at, duration_minutes, justification, event_id))


# ─────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--org-id', type=int, required=True)
    ap.add_argument('--db-host', default=os.getenv('DB_HOST', 'localhost'))
    ap.add_argument('--db-port', type=int, default=int(os.getenv('DB_PORT', '5434')))
    ap.add_argument('--db-name', default=os.getenv('DB_NAME', 'auditgraph'))
    ap.add_argument('--db-user', default=os.getenv('DB_ADMIN_USER', 'auditgraph'))
    ap.add_argument('--db-password', default=os.getenv('DB_ADMIN_PASSWORD', 'auditgraph'))
    ap.add_argument('--db-sslmode', default=os.getenv('DB_SSLMODE', 'disable'))
    args = ap.parse_args()

    conn = psycopg2.connect(
        host=args.db_host, port=args.db_port, dbname=args.db_name,
        user=args.db_user, password=args.db_password, sslmode=args.db_sslmode,
    )
    cursor = conn.cursor()

    try:
        discovery_run_id = latest_or_new_discovery_run(cursor, args.org_id)
        print(f"  using discovery_run_id={discovery_run_id}", file=sys.stderr)

        for persona in PERSONAS:
            identity_db_id = get_or_create_identity(
                cursor, args.org_id, persona, discovery_run_id)
            seed_pim_eligibility(cursor, args.org_id, identity_db_id,
                                  persona, discovery_run_id)
            seed_pim_activations(cursor, args.org_id, identity_db_id, persona)
            n_act = len(persona['activations'])
            print(f"  ✓ {persona['identity_id']:50}  role={persona['role_name']:25}  "
                  f"activations={n_act}", file=sys.stderr)

        conn.commit()
        print(f"\n  Seeded {len(PERSONAS)} PIM demo personas for org={args.org_id}",
              file=sys.stderr)
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    main()
