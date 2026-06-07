#!/usr/bin/env python3
"""
Generate idempotent SQL to seed PIM Overprivilege demo personas into
a target org. Output is applied via apply_cloud_migration.py (which runs
SQL through the migration container app job — so no Python execution
needed in the cloud).

Identity lookups use JOIN on identity_id (string), not hardcoded
identity_db_id, so the SQL is portable across local and cloud DBs.

Usage:
  ./generate_pim_demo_sql.py --org-id 3 > /tmp/pim_demo_org3.sql
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone

# Re-import PERSONAS from seed_pim_demo
sys.path.insert(0, '/Users/sangabattula/projects/auditgraph/backend/scripts')
from seed_pim_demo import PERSONAS, NOW  # noqa: E402


def sql_lit(v):
    if v is None:                return 'NULL'
    if isinstance(v, bool):      return 'TRUE' if v else 'FALSE'
    if isinstance(v, (int, float)): return str(v)
    if isinstance(v, datetime):
        return f"'{v.isoformat()}'::timestamptz"
    # string
    return "'" + str(v).replace("'", "''") + "'"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--org-id', type=int, required=True)
    args = ap.parse_args()

    # AG-PILOT-SAFETY (2026-06-07): demo-org allowlist guard. Even though
    # this script only emits SQL to stdout (doesn't write directly), an
    # operator could pipe the output to a customer DB. Guard at source.
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _demo_safety import assert_safe_demo_org
    assert_safe_demo_org(args.org_id, script_name='generate_pim_demo_sql.py')

    org_id = args.org_id

    print("-- AG-PIM-OVERPRIV demo seed — idempotent, multi-replay safe")
    print(f"-- Target org_id = {org_id}")
    print(f"-- Generated {datetime.now(timezone.utc).isoformat()}")
    print()
    print("BEGIN;")
    print()

    # Ensure a discovery_run exists for org (idempotent — only inserts if none)
    print("-- Ensure a discovery_run exists for this org")
    print(f"""
WITH need_run AS (
  SELECT 1 WHERE NOT EXISTS (
    SELECT 1 FROM discovery_runs WHERE organization_id = {org_id}
  )
), have_conn AS (
  SELECT id FROM cloud_connections WHERE organization_id = {org_id} LIMIT 1
)
INSERT INTO discovery_runs (organization_id, cloud_connection_id, started_at, completed_at, status)
SELECT {org_id}, have_conn.id, NOW(), NOW(), 'completed'
FROM need_run, have_conn;
""")

    for p in PERSONAS:
        identity_id = p['identity_id']
        print(f"-- ── {identity_id} — {p['story']}")

        # Create identity if not exists; idempotent on (organization_id, identity_id)
        print(f"""
INSERT INTO identities (
    organization_id, identity_id, display_name, identity_category,
    identity_type, source, discovery_run_id, deleted_at,
    risk_level, owner_display_name, owner_status, enabled, activity_status
)
SELECT {org_id}, {sql_lit(identity_id)}, {sql_lit(p['display_name'])}, 'human_user',
       'human_user', 'entra_id',
       (SELECT id FROM discovery_runs WHERE organization_id = {org_id} ORDER BY id DESC LIMIT 1),
       NULL, 'high', 'AuditGraph Demo Platform Team', 'resolved', TRUE, 'active'
WHERE NOT EXISTS (
    SELECT 1 FROM identities WHERE organization_id = {org_id} AND identity_id = {sql_lit(identity_id)}
);
""")

        # Eligibility row — idempotent via UNIQUE constraint
        print(f"""
INSERT INTO pim_eligibility_state (
    organization_id, discovery_run_id, identity_db_id, identity_id,
    role_name, role_template_id, scope, scope_type,
    assignment_type, eligible_since,
    requires_mfa_on_activation, requires_approval,
    requires_justification, max_activation_minutes
)
SELECT {org_id},
       (SELECT id FROM discovery_runs WHERE organization_id = {org_id} ORDER BY id DESC LIMIT 1),
       i.id, {sql_lit(identity_id)},
       {sql_lit(p['role_name'])}, {sql_lit(p['role_template_id'])},
       {sql_lit(p['scope'])}, {sql_lit(p['scope_type'])},
       {sql_lit(p['assignment_type'])}, {sql_lit(p['eligible_since'])},
       {sql_lit(p['requires_mfa_on_activation'])}, {sql_lit(p['requires_approval'])},
       {sql_lit(p['requires_justification'])}, {sql_lit(p['max_activation_minutes'])}
FROM identities i
WHERE i.organization_id = {org_id} AND i.identity_id = {sql_lit(identity_id)}
ON CONFLICT (organization_id, identity_db_id, role_name, scope, assignment_type)
DO UPDATE SET
    eligible_since = EXCLUDED.eligible_since,
    requires_mfa_on_activation = EXCLUDED.requires_mfa_on_activation,
    requires_approval = EXCLUDED.requires_approval,
    requires_justification = EXCLUDED.requires_justification,
    max_activation_minutes = EXCLUDED.max_activation_minutes;
""")

        # Activation observations
        for i, (activated_at, duration, justification) in enumerate(p['activations']):
            event_id = f"demo:{identity_id}:{int(activated_at.timestamp())}:{i}"
            print(f"""
INSERT INTO pim_activation_observations (
    organization_id, identity_db_id, identity_id,
    role_name, role_template_id, scope,
    activated_at, activation_duration_minutes,
    justification, audit_event_id
)
SELECT {org_id}, i.id, {sql_lit(identity_id)},
       {sql_lit(p['role_name'])}, {sql_lit(p['role_template_id'])}, {sql_lit(p['scope'])},
       {sql_lit(activated_at)}, {sql_lit(duration)},
       {sql_lit(justification)}, {sql_lit(event_id)}
FROM identities i
WHERE i.organization_id = {org_id} AND i.identity_id = {sql_lit(identity_id)}
ON CONFLICT (organization_id, audit_event_id) DO NOTHING;
""")

    print("COMMIT;")
    print(f"-- Seeded {len(PERSONAS)} PIM demo personas for org={org_id}")


if __name__ == '__main__':
    main()
