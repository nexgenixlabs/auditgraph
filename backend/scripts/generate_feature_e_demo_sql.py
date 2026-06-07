#!/usr/bin/env python3
"""Generate idempotent SQL to seed Feature E demo personas into a target org.

Companion to seed_feature_e_demo.py for cloud-dev (where Python execution
isn't available against the DB directly).
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

sys.path.insert(0, '/Users/sangabattula/projects/auditgraph/backend/scripts')
from seed_feature_e_demo import PERSONAS  # noqa: E402


def sql_lit(v):
    if v is None:                       return 'NULL'
    if isinstance(v, bool):             return 'TRUE' if v else 'FALSE'
    if isinstance(v, (int, float)):     return str(v)
    if isinstance(v, datetime):
        return f"'{v.isoformat()}'::timestamptz"
    return "'" + str(v).replace("'", "''") + "'"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--org-id', type=int, required=True)
    args = ap.parse_args()
    org_id = args.org_id

    print(f"-- AG-FEATURE-E-P2 demo seed — idempotent")
    print(f"-- Target org_id = {org_id}")
    print(f"-- Generated {datetime.now(timezone.utc).isoformat()}\n")
    print("BEGIN;\n")

    for p in PERSONAS:
        identity_id = p['identity_id']
        print(f"-- ── {identity_id}")
        print(f"--    {p['story']}")
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
        print(f"""
INSERT INTO entra_role_activity (
    organization_id, discovery_run_id, identity_db_id, identity_id,
    role_name, role_template_id, assignment_principal_type,
    last_action_at, days_since_last_action,
    activities_30d, activities_90d,
    activity_bucket, dormancy_band,
    inferred_from, inference_confidence
)
SELECT {org_id},
       (SELECT id FROM discovery_runs WHERE organization_id = {org_id} ORDER BY id DESC LIMIT 1),
       i.id, {sql_lit(identity_id)},
       {sql_lit(p['role_name'])}, {sql_lit(p['role_template_id'])}, {sql_lit(p['assignment_principal_type'])},
       {sql_lit(p['last_action_at'])}, {sql_lit(p['days_since_last_action'])},
       {sql_lit(p['activities_30d'])}, {sql_lit(p['activities_90d'])},
       {sql_lit(p['activity_bucket'])}, {sql_lit(p['dormancy_band'])},
       {sql_lit(p['inferred_from'])}, {sql_lit(p['inference_confidence'])}
FROM identities i
WHERE i.organization_id = {org_id} AND i.identity_id = {sql_lit(identity_id)}
ON CONFLICT (organization_id, identity_db_id, role_name)
DO UPDATE SET
    last_action_at         = EXCLUDED.last_action_at,
    days_since_last_action = EXCLUDED.days_since_last_action,
    activities_30d         = EXCLUDED.activities_30d,
    activities_90d         = EXCLUDED.activities_90d,
    activity_bucket        = EXCLUDED.activity_bucket,
    dormancy_band          = EXCLUDED.dormancy_band,
    inferred_from          = EXCLUDED.inferred_from,
    inference_confidence   = EXCLUDED.inference_confidence;
""")

    print("COMMIT;")
    print(f"-- Seeded {len(PERSONAS)} Feature E demo personas for org={org_id}")


if __name__ == '__main__':
    main()
