#!/usr/bin/env python3
"""
Replicate the localhost demo (org=9 AuditGraph Demo) data into the
cloud-dev demo tenant (org=3 AuditGraph Demo).

Background
==========
The cloud-dev demo accumulated identities (306 of them) but missed
the secondary tables that make those identities INTERESTING:
  - role_assignments        (humans had 0 roles on cloud)
  - agent_invocations       (multi-hop graph was empty)
  - agent_data_reachability (was partially seeded)

What this script does
=====================
1. Connects to localhost DB (org=9), reads role_assignments,
   agent_invocations, and agent_data_reachability.
2. Generates an idempotent SQL file that:
   - Looks up cloud-dev identity_db_ids by identity_id string
   - Inserts the matching rows with organization_id=3
   - Skips rows that already exist
3. Writes the SQL to /tmp/replicate_demo_to_cloud.sql

The generated SQL is then applied to cloud-dev via the existing
apply_cloud_migration.py harness.

Safety
======
- This script READS from localhost (sandbox); never writes.
- The generated SQL only INSERTS rows; never DELETES or UPDATES.
- Idempotent: uses subselects that return zero rows when the target
  identity is missing on cloud-dev, AND deduplicates against existing
  cloud rows via WHERE NOT EXISTS.
- All inserts are tagged with organization_id=3 (cloud demo).
- Per CLAUDE.md hard rule: no org data deletion. We only ADD.
"""
import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor


LOCAL_DB = {
    'host': 'localhost', 'port': 5434,
    'dbname': 'auditgraph',
    'user': 'auditgraph', 'password': 'auditgraph',
    'sslmode': 'disable',
}
SOURCE_ORG_ID = 9   # local demo
TARGET_ORG_ID = 3   # cloud-dev demo

OUTPUT_SQL = '/tmp/replicate_demo_to_cloud.sql'


def fetch_role_assignments(conn):
    """Read all role_assignments for the source org, keyed by identity_id."""
    sql = """
        SELECT i.identity_id,
               r.role_name, r.scope, r.scope_type, r.principal_id,
               r.role_type, r.principal_type, r.usage_status,
               r.scope_exists, r.resource_name, r.resource_type,
               r.risk_level, r.why_critical
          FROM role_assignments r
          JOIN identities i ON i.id = r.identity_db_id
         WHERE i.organization_id = %s
           AND i.deleted_at IS NULL
         ORDER BY i.identity_id, r.role_name
    """
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(sql, (SOURCE_ORG_ID,))
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_agent_invocations(conn):
    sql = """
        SELECT source_identity_id, target_identity_id, via_mechanism,
               invocation_name, observed_count, confidence, source,
               metadata
          FROM agent_invocations
         WHERE organization_id = %s
         ORDER BY source_identity_id
    """
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(sql, (SOURCE_ORG_ID,))
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_agent_data_reachability(conn):
    sql = """
        SELECT i.identity_id, r.data_classification, r.est_records,
               r.write_resource_count, r.resource_count
          FROM agent_data_reachability r
          JOIN identities i ON i.id = r.identity_db_id
         WHERE r.organization_id = %s
         ORDER BY i.identity_id
    """
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(sql, (SOURCE_ORG_ID,))
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_agent_classifications(conn):
    sql = """
        SELECT i.identity_id, c.agent_identity_type,
               c.classification_confidence, c.classification_reason,
               c.detected_platform, c.pattern_version,
               c.agent_penalty_score, c.agent_penalty_reason,
               c.model_name
          FROM agent_classifications c
          JOIN identities i ON i.id = c.identity_db_id
         WHERE c.organization_id = %s
         ORDER BY i.identity_id
    """
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(sql, (SOURCE_ORG_ID,))
    rows = cur.fetchall()
    cur.close()
    return rows


def quote_sql(v):
    if v is None:
        return 'NULL'
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if isinstance(v, (int, float)):
        return str(v)
    # Escape single quotes by doubling them
    s = str(v).replace("'", "''")
    return f"'{s}'"


def emit_role_assignment_inserts(rows):
    out = []
    out.append("-- ═══ role_assignments ═══")
    out.append(f"-- {len(rows)} rows to attempt; each insert resolves identity_db_id at execution time")
    out.append("")
    for r in rows:
        cols = "identity_db_id, role_name, scope, scope_type, principal_id, role_type, principal_type, usage_status, scope_exists, resource_name, resource_type, risk_level, why_critical, organization_id"
        vals = (
            f"(SELECT id FROM identities WHERE organization_id={TARGET_ORG_ID} "
            f"AND identity_id={quote_sql(r['identity_id'])} ORDER BY discovery_run_id DESC LIMIT 1), "
            f"{quote_sql(r['role_name'])}, {quote_sql(r['scope'])}, {quote_sql(r['scope_type'])}, "
            f"{quote_sql(r['principal_id'])}, {quote_sql(r['role_type'])}, "
            f"{quote_sql(r['principal_type'])}, {quote_sql(r['usage_status'])}, "
            f"{quote_sql(r['scope_exists'])}, {quote_sql(r['resource_name'])}, "
            f"{quote_sql(r['resource_type'])}, {quote_sql(r['risk_level'])}, "
            f"{quote_sql(r['why_critical'])}, {TARGET_ORG_ID}"
        )
        # WHERE NOT EXISTS dedups by (identity, role_name, scope)
        sql = (
            f"INSERT INTO role_assignments ({cols}) "
            f"SELECT {vals} "
            f"WHERE EXISTS (SELECT 1 FROM identities "
            f"  WHERE organization_id={TARGET_ORG_ID} AND identity_id={quote_sql(r['identity_id'])}) "
            f"AND NOT EXISTS ("
            f"  SELECT 1 FROM role_assignments ra "
            f"  JOIN identities i ON i.id = ra.identity_db_id "
            f"  WHERE i.organization_id={TARGET_ORG_ID} "
            f"  AND i.identity_id={quote_sql(r['identity_id'])} "
            f"  AND ra.role_name={quote_sql(r['role_name'])} "
            f"  AND ra.scope={quote_sql(r['scope'])});"
        )
        out.append(sql)
    return out


def emit_agent_invocation_inserts(rows):
    out = []
    out.append("")
    out.append("-- ═══ agent_invocations ═══")
    out.append(f"-- {len(rows)} edges. ON CONFLICT on (org, source, target, mechanism) preserved.")
    out.append("")
    import json
    for r in rows:
        m = r['metadata']
        if m is None or m == {}:
            meta_json = '{}'
        elif isinstance(m, (dict, list)):
            meta_json = json.dumps(m).replace("'", "''")
        else:
            # Already a JSON string from psycopg2 — re-parse + re-emit to be safe
            try:
                meta_json = json.dumps(json.loads(m)).replace("'", "''")
            except Exception:
                meta_json = '{}'
        sql = (
            f"INSERT INTO agent_invocations "
            f"(organization_id, source_identity_db_id, source_identity_id, "
            f" target_identity_db_id, target_identity_id, "
            f" via_mechanism, invocation_name, observed_count, "
            f" confidence, source, metadata) "
            f"SELECT {TARGET_ORG_ID}, "
            f"  src.id, {quote_sql(r['source_identity_id'])}, "
            f"  tgt.id, {quote_sql(r['target_identity_id'])}, "
            f"  {quote_sql(r['via_mechanism'])}, {quote_sql(r['invocation_name'])}, "
            f"  {r['observed_count'] if r['observed_count'] is not None else 1}, "
            f"  {quote_sql(r['confidence'])}, {quote_sql(r['source'])}, "
            f"  '{meta_json}'::jsonb "
            f"FROM identities src, identities tgt "
            f"WHERE src.organization_id = {TARGET_ORG_ID} "
            f"  AND src.identity_id = {quote_sql(r['source_identity_id'])} "
            f"  AND tgt.organization_id = {TARGET_ORG_ID} "
            f"  AND tgt.identity_id = {quote_sql(r['target_identity_id'])} "
            f"ON CONFLICT (organization_id, source_identity_db_id, target_identity_db_id, via_mechanism) "
            f"DO NOTHING;"
        )
        out.append(sql)
    return out


def emit_reachability_inserts(rows):
    out = []
    out.append("")
    out.append("-- ═══ agent_data_reachability ═══")
    out.append(f"-- {len(rows)} rows.")
    out.append("")
    for r in rows:
        sql = (
            f"INSERT INTO agent_data_reachability "
            f"(organization_id, identity_db_id, data_classification, "
            f" est_records, write_resource_count, resource_count) "
            f"SELECT {TARGET_ORG_ID}, i.id, {quote_sql(r['data_classification'])}, "
            f"  {r['est_records']}, {r['write_resource_count'] or 0}, "
            f"  {r['resource_count'] or 0} "
            f"FROM identities i "
            f"WHERE i.organization_id = {TARGET_ORG_ID} "
            f"  AND i.identity_id = {quote_sql(r['identity_id'])} "
            f"AND NOT EXISTS ("
            f"  SELECT 1 FROM agent_data_reachability r "
            f"  JOIN identities i2 ON i2.id = r.identity_db_id "
            f"  WHERE i2.organization_id = {TARGET_ORG_ID} "
            f"  AND i2.identity_id = {quote_sql(r['identity_id'])} "
            f"  AND r.data_classification = {quote_sql(r['data_classification'])});"
        )
        out.append(sql)
    return out


def emit_classification_inserts(rows):
    out = []
    out.append("")
    out.append("-- ═══ agent_classifications (top up) ═══")
    out.append(f"-- {len(rows)} rows.")
    out.append("")
    for r in rows:
        sql = (
            f"INSERT INTO agent_classifications "
            f"(organization_id, identity_db_id, identity_id, "
            f" agent_identity_type, classification_confidence, "
            f" classification_reason, detected_platform, pattern_version, "
            f" agent_penalty_score, agent_penalty_reason, model_name) "
            f"SELECT {TARGET_ORG_ID}, i.id, {quote_sql(r['identity_id'])}, "
            f"  {quote_sql(r['agent_identity_type'])}, "
            f"  {r['classification_confidence'] or 0.5}, "
            f"  {quote_sql(r['classification_reason'])}, "
            f"  {quote_sql(r['detected_platform'])}, "
            f"  {quote_sql(r['pattern_version'])}, "
            f"  {r['agent_penalty_score'] or 0}, "
            f"  {quote_sql(r['agent_penalty_reason'])}, "
            f"  {quote_sql(r['model_name'])} "
            f"FROM identities i "
            f"WHERE i.organization_id = {TARGET_ORG_ID} "
            f"  AND i.identity_id = {quote_sql(r['identity_id'])} "
            f"AND NOT EXISTS ("
            f"  SELECT 1 FROM agent_classifications c "
            f"  JOIN identities i2 ON i2.id = c.identity_db_id "
            f"  WHERE i2.organization_id = {TARGET_ORG_ID} "
            f"  AND i2.identity_id = {quote_sql(r['identity_id'])});"
        )
        out.append(sql)
    return out


def main():
    conn = psycopg2.connect(**LOCAL_DB)
    try:
        print(f"Reading from localhost org={SOURCE_ORG_ID}...", file=sys.stderr)
        roles = fetch_role_assignments(conn)
        invocations = fetch_agent_invocations(conn)
        reachability = fetch_agent_data_reachability(conn)
        classifications = fetch_agent_classifications(conn)
        print(f"  role_assignments:        {len(roles)}", file=sys.stderr)
        print(f"  agent_invocations:       {len(invocations)}", file=sys.stderr)
        print(f"  agent_data_reachability: {len(reachability)}", file=sys.stderr)
        print(f"  agent_classifications:   {len(classifications)}", file=sys.stderr)

        lines = []
        lines.append("-- Generated by replicate_localhost_demo_to_cloud.py")
        lines.append(f"-- Source: localhost org={SOURCE_ORG_ID}")
        lines.append(f"-- Target: cloud-dev org={TARGET_ORG_ID}")
        lines.append("--")
        lines.append("-- Idempotent: each INSERT uses WHERE NOT EXISTS or ON CONFLICT")
        lines.append("-- Skips silently if the target identity is missing on cloud.")
        lines.append("\\set ON_ERROR_STOP on")
        lines.append("BEGIN;")
        lines.append("")
        lines.extend(emit_role_assignment_inserts(roles))
        lines.extend(emit_agent_invocation_inserts(invocations))
        lines.extend(emit_reachability_inserts(reachability))
        lines.extend(emit_classification_inserts(classifications))
        lines.append("")
        lines.append("COMMIT;")
        lines.append("")
        lines.append("-- Verification queries (read-only)")
        lines.append("SELECT 'role_assignments' AS table, count(*) FROM role_assignments r "
                      f"JOIN identities i ON i.id=r.identity_db_id WHERE i.organization_id={TARGET_ORG_ID}")
        lines.append("UNION ALL")
        lines.append(f"SELECT 'agent_invocations', count(*) FROM agent_invocations WHERE organization_id={TARGET_ORG_ID}")
        lines.append("UNION ALL")
        lines.append(f"SELECT 'agent_data_reachability', count(*) FROM agent_data_reachability WHERE organization_id={TARGET_ORG_ID};")

        with open(OUTPUT_SQL, 'w') as f:
            f.write('\n'.join(lines))
        print(f"Wrote {len(lines)} lines to {OUTPUT_SQL}", file=sys.stderr)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
