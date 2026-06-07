#!/usr/bin/env python3
"""
AuditGraph — AIAG Demo Seeder (localhost-only)

Provisions synthetic data on top of the AI Agent test tenant so all six
new AIAG features light up on localhost validation:
  - AG-178 AI Identity Attack Paths
  - AG-179 Trust Score + Board Scorecard
  - AG-180 Data Reachability
  - AG-181 Lifecycle + Drift
  - AG-182 Activity Timeline + Behavior Baseline

What this script writes:
  - 4 AI agent SPNs (via seed_ai_agent_test_tenant.AGENT_IDENTITIES if available;
    falls back to a minimal local definition)
  - 3 azure_cognitive_services_accounts (+ 6 azure_ai_model_deployments)
  - 2 azure_key_vaults (one with KV-Admin grants → triggers attack path)
  - 4 azure_storage_accounts (1 tagged PHI, 1 tagged PCI, 1 SOURCE name pattern, 1 public)
  - 2 azure_sql_databases (1 tagged HR)
  - 2 azure_cosmos_databases
  - role_assignments wiring agents → resources for attack-path detection
  - agent_classifications rows for each AI agent
  - TWO historical discovery runs so lifecycle drift can fire
  - agent_activity_events stub data so behavior baseline has samples

CONSTRAINTS HONORED:
  - NO real PHI / PCI content. Resource names + tag VALUES (e.g.
    "classification=PHI") only; no patient data, no card numbers.
  - Strong APP_ENV + DB_HOST guards refuse to run against prod or cloud.
  - All UUIDs deterministic so re-runs are idempotent (TRUNCATE-then-insert).

Usage:
  cd backend/
  ./venv/bin/python scripts/seed_aiag_demo.py --org-id 9

After seeding, validate per docs/runbooks/aiag_localhost_validation.md.
"""

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("aiag_demo_seeder")

NOW = datetime.now(timezone.utc)

# ─── Deterministic IDs (NOT real Azure resources) ─────────────────────

SUB_ID = "11111111-1111-4111-1111-111111111111"
RG_NAME = "rg-aiag-demo"
RG_ID = f"/subscriptions/{SUB_ID}/resourceGroups/{RG_NAME}"

# Cognitive services accounts (the AI agents will be assigned MIs here)
COG_ACCT_1 = f"{RG_ID}/providers/Microsoft.CognitiveServices/accounts/aiag-openai-prod"
COG_ACCT_2 = f"{RG_ID}/providers/Microsoft.CognitiveServices/accounts/aiag-openai-stg"
COG_ACCT_3 = f"{RG_ID}/providers/Microsoft.CognitiveServices/accounts/aiag-copilot-bot"

# Key Vaults (one PHI-adjacent, one PCI-adjacent)
KV_PHI = f"{RG_ID}/providers/Microsoft.KeyVault/vaults/aiag-vault-phi"
KV_PCI = f"{RG_ID}/providers/Microsoft.KeyVault/vaults/aiag-vault-pci"

# Storage accounts — names + tags drive classification
STORAGE_PHI = f"{RG_ID}/providers/Microsoft.Storage/storageAccounts/aiagphiblob01"
STORAGE_PCI = f"{RG_ID}/providers/Microsoft.Storage/storageAccounts/aiagpci01"
STORAGE_SRC = f"{RG_ID}/providers/Microsoft.Storage/storageAccounts/aiagsrccode01"
STORAGE_PUB = f"{RG_ID}/providers/Microsoft.Storage/storageAccounts/aiagpublic01"

# SQL / Cosmos
SQL_SERVER = f"{RG_ID}/providers/Microsoft.Sql/servers/aiag-sql-prod"
SQL_DB_HR = f"{SQL_SERVER}/databases/hr-analytics"
SQL_DB_GEN = f"{SQL_SERVER}/databases/generic-app"
COSMOS_ACCT = f"{RG_ID}/providers/Microsoft.DocumentDB/databaseAccounts/aiag-cosmos-prod"
COSMOS_DB_PII = f"{COSMOS_ACCT}/sqlDatabases/customer-pii"
COSMOS_DB_GEN = f"{COSMOS_ACCT}/sqlDatabases/generic-app-db"

# AI agents — minimal local definition (4 deterministic SPNs)
AGENTS = [
    {
        "display_name": "ai_startup_alexander_CoS_project",
        "identity_id": "aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001",
        "model_name": "gpt-4o",
        "account_resource_id": COG_ACCT_1,
        "agent_identity_type": "ai_agent",
        "owner": "alexander@example.com",
        "risk_score": 88, "risk_level": "critical",
        # Critical role assignments — drive the attack path detector
        "roles": [
            {"role_name": "Key Vault Administrator", "scope": KV_PHI, "scope_type": "resource"},
            {"role_name": "Storage Blob Data Contributor", "scope": STORAGE_PHI, "scope_type": "resource"},
        ],
    },
    {
        "display_name": "EP.Jason Collins",
        "identity_id": "aa000002-aaaa-4aaa-aaaa-aaaaaaaaa002",
        "model_name": "gpt-4",
        "account_resource_id": COG_ACCT_2,
        "agent_identity_type": "ai_agent",
        "owner": None,  # OWNERLESS — for board scorecard
        "risk_score": 72, "risk_level": "high",
        "roles": [
            {"role_name": "Storage Blob Data Reader", "scope": STORAGE_PCI, "scope_type": "resource"},
        ],
    },
    {
        "display_name": "ContosoHR-CopilotBot-Prod",
        "identity_id": "aa000003-aaaa-4aaa-aaaa-aaaaaaaaa003",
        "model_name": "gpt-4o-mini",
        "account_resource_id": COG_ACCT_3,
        "agent_identity_type": "ai_agent",
        "owner": "hr-admin@example.com",
        "risk_score": 45, "risk_level": "medium",
        "roles": [
            {"role_name": "Reader", "scope": COSMOS_DB_PII, "scope_type": "resource"},
        ],
    },
    {
        "display_name": "ai_startup_alexander_DataMgmt",
        "identity_id": "aa000004-aaaa-4aaa-aaaa-aaaaaaaaa004",
        "model_name": "claude-3-sonnet",
        "account_resource_id": COG_ACCT_1,
        "agent_identity_type": "ai_agent",
        "owner": "alexander@example.com",
        "risk_score": 30, "risk_level": "low",
        "roles": [
            {"role_name": "Reader", "scope": SQL_DB_GEN, "scope_type": "resource"},
        ],
    },
]

# Lifecycle drift target: in run-1 this agent had Reader only;
# in run-2 it has Contributor + KV Admin → AI_PERMISSIONS_ESCALATED
DRIFT_AGENT_ID = AGENTS[0]["identity_id"]


# ─── Helpers ──────────────────────────────────────────────────────────

# Tenants that hold real customer data. The seeder REFUSES to write here.
# Add new entries (locally OR cloud) as customer tenants are onboarded.
FORBIDDEN_ORG_SLUGS = frozenset({
    'virtuallabs',     # local org=10 — real client data (15,678 identities)
    'orangeblack',     # cloud-dev real client
    'azurecredits',    # legacy real client snapshot
})


def _find_org(db, org_id: int) -> int:
    cur = db.conn.cursor()
    cur.execute("SELECT id, name, slug FROM organizations WHERE id = %s", (org_id,))
    row = cur.fetchone()
    if row is None:
        raise RuntimeError(
            f"Organization id={org_id} does not exist locally. "
            "Either pick a different --org-id or create the org first."
        )
    _id, name, slug = row
    if (slug or '').lower() in FORBIDDEN_ORG_SLUGS or (name or '').lower() in FORBIDDEN_ORG_SLUGS:
        raise RuntimeError(
            f"REFUSING TO SEED: org_id={org_id} (name={name!r}, slug={slug!r}) is a "
            f"REAL CUSTOMER tenant. This seeder only writes to dedicated demo orgs.\n"
            f"  Locally, target --org-id 9 (AuditGraph Demo).\n"
            f"  See memory/feedback_no_org_data_deletion.md for the policy."
        )
    logger.info("Org found: id=%s (name=%r, slug=%r) — passes demo-org guard", org_id, name, slug)
    return org_id


def _find_connection_id(db, org_id: int) -> int:
    cur = db.conn.cursor()
    cur.execute(
        "SELECT id FROM cloud_connections WHERE organization_id=%s LIMIT 1",
        (org_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise RuntimeError(
            f"No cloud_connections row for org_id={org_id}. "
            "Seed a connection first or pick a different org."
        )
    return row[0]


def _ensure_run(db, org_id: int, label: str, completed_at: datetime,
                connection_id: int) -> int:
    cur = db.conn.cursor()
    # Schema-tolerant: actual discovery_runs has cloud_connection_id (NOT NULL)
    # and subscription_id (NOT NULL). We pass a synthetic sub id so the row is
    # valid; the seeder rows are clearly demo-only.
    cur.execute("""
        INSERT INTO discovery_runs
            (organization_id, cloud_connection_id, subscription_id,
             started_at, completed_at, status)
        VALUES (%s, %s, %s, %s, %s, 'completed')
        RETURNING id
    """, (org_id, connection_id, SUB_ID,
          completed_at - timedelta(minutes=15), completed_at))
    rid = cur.fetchone()[0]
    db.conn.commit()
    logger.info("Created discovery_run id=%s (%s) [conn=%s]", rid, label, connection_id)
    return rid


def _cleanup_aiag_demo(db, org_id: int):
    """Remove only rows created by this seeder. Does NOT touch real customer data."""
    cur = db.conn.cursor()
    # Set RLS context so policies on org-scoped tables match
    cur.execute("SET LOCAL app.current_organization_id = %s", (str(org_id),))
    cur.execute("SET LOCAL app.current_tenant_id = %s", (str(org_id),))
    # Remove only agents whose identity_id starts with 'aa000' (deterministic seeder UUIDs)
    cur.execute("""
        DELETE FROM identities
        WHERE organization_id = %s
          AND identity_id LIKE 'aa000%%'
    """, (org_id,))
    deleted_identities = cur.rowcount

    # Remove our demo resources
    # Cleanup tuples: (table, key_column, prefix). azure_ai_model_deployments
    # uses account_resource_id (not resource_id) in the schema.
    for table, col, prefix in [
        ("azure_cognitive_services_accounts", "resource_id",         "/subscriptions/11111111-"),
        ("azure_ai_model_deployments",        "account_resource_id", "/subscriptions/11111111-"),
        ("azure_key_vaults",                  "resource_id",         "/subscriptions/11111111-"),
        ("azure_storage_accounts",            "resource_id",         "/subscriptions/11111111-"),
        ("azure_sql_servers",                 "resource_id",         "/subscriptions/11111111-"),
        ("azure_sql_databases",               "resource_id",         "/subscriptions/11111111-"),
        ("azure_cosmos_accounts",             "resource_id",         "/subscriptions/11111111-"),
        ("azure_cosmos_databases",            "resource_id",         "/subscriptions/11111111-"),
    ]:
        try:
            cur.execute(
                f"DELETE FROM {table} WHERE organization_id = %s AND {col} LIKE %s",
                (org_id, prefix + "%"),
            )
        except Exception as e:
            logger.warning("Cleanup %s skipped: %s", table, e)
            try: db.conn.rollback()
            except Exception: pass

    # Remove dependent agent_classifications / lifecycle / activity for our agents
    for table in ("agent_classifications", "ai_agent_lifecycle_events",
                  "agent_activity_events", "agent_behavior_baselines",
                  "agent_behavior_anomalies", "agent_data_reachability"):
        try:
            cur.execute(
                f"DELETE FROM {table} WHERE organization_id = %s AND identity_id LIKE 'aa000%%'",
                (org_id,),
            )
        except Exception as e:
            logger.warning("Cleanup %s skipped: %s", table, e)
            try: db.conn.rollback()
            except Exception: pass

    db.conn.commit()
    logger.info("Cleanup removed %d demo identities + dependent rows", deleted_identities)


def _set_org_context(cur, org_id: int):
    """Set both possible RLS settings — different tables use different keys."""
    cur.execute("SET LOCAL app.current_organization_id = %s", (str(org_id),))
    cur.execute("SET LOCAL app.current_tenant_id = %s", (str(org_id),))


def _try_insert(cur, label: str, sql: str, params: tuple):
    """Run an INSERT inside a savepoint so a single column mismatch
    doesn't poison the rest of the transaction. Returns True on success."""
    import re
    sp = "sp_" + re.sub(r"[^a-zA-Z0-9_]", "_", label)[:48]
    try:
        cur.execute(f"SAVEPOINT {sp}")
        cur.execute(sql, params)
        cur.execute(f"RELEASE SAVEPOINT {sp}")
        return True
    except Exception as e:
        try: cur.execute(f"ROLLBACK TO SAVEPOINT {sp}")
        except Exception: pass
        msg = str(e).splitlines()[0]
        logger.warning("INSERT %s skipped: %s", label, msg)
        return False


def _seed_resources(db, run_id: int, org_id: int):
    cur = db.conn.cursor()
    _set_org_context(cur, org_id)

    # Cognitive services accounts — schema uses `name` (not account_name)
    cog_rows = [
        (COG_ACCT_1, "aiag-openai-prod", "OpenAI", "Disabled", 1),
        (COG_ACCT_2, "aiag-openai-stg",  "OpenAI", "Enabled",  0),
        (COG_ACCT_3, "aiag-copilot-bot", "CognitiveServices", "Disabled", 1),
    ]
    for rid, name, kind, pna, pe in cog_rows:
        _try_insert(cur, f"cog_{name}", """
            INSERT INTO azure_cognitive_services_accounts
                (organization_id, discovery_run_id, subscription_id, resource_id,
                 resource_group, name, kind, public_network_access,
                 network_acls_default_action, private_endpoint_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (org_id, run_id, SUB_ID, rid, RG_NAME, name, kind, pna,
              'Deny' if pna == 'Disabled' else 'Allow', pe))

    # Model deployments
    deps = [
        (COG_ACCT_1, "gpt-4o-prod", "gpt-4o", "2024-08-06", "Standard", 100),
        (COG_ACCT_1, "gpt-4-prod",  "gpt-4",  "0613",       "Standard", 50),
        (COG_ACCT_2, "gpt-4o-stg",  "gpt-4o", "2024-08-06", "Standard", 25),
        (COG_ACCT_2, "gpt-4o-mini", "gpt-4o-mini", "2024-07-18", "Standard", 100),
        (COG_ACCT_3, "claude-sonnet", "claude-3-sonnet", "20240229", "Standard", 50),
        (COG_ACCT_3, "embedding-3", "text-embedding-3-large", "1", "Standard", 100),
    ]
    for acct, dname, mname, mver, sku, cap in deps:
        _try_insert(cur, f"dep_{dname}", """
            INSERT INTO azure_ai_model_deployments
                (organization_id, discovery_run_id, account_resource_id,
                 deployment_name, model_name, model_version, sku_name, sku_capacity)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (org_id, run_id, acct, dname, mname, mver, sku, cap))

    # Key Vaults — schema uses `name` (not vault_name)
    for kv_id, name, pna, dna, pe, secrets in [
        (KV_PHI, "aiag-vault-phi", "Disabled", "Deny",  1, 14),
        (KV_PCI, "aiag-vault-pci", "Enabled",  "Allow", 0, 8),
    ]:
        _try_insert(cur, f"kv_{name}", """
            INSERT INTO azure_key_vaults
                (organization_id, discovery_run_id, subscription_id, resource_id,
                 resource_group, name, location, public_network_access,
                 default_network_action, private_endpoint_count, secrets_total)
            VALUES (%s, %s, %s, %s, %s, %s, 'eastus', %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (org_id, run_id, SUB_ID, kv_id, RG_NAME, name, pna, dna, pe, secrets))

    # Storage accounts — schema uses `name`. Classification + records on top.
    for rid, name, pba, dna, cls, src, est in [
        (STORAGE_PHI, "aiagphiblob01", False, "Deny",  "PHI",    "tag",          120000),
        (STORAGE_PCI, "aiagpci01",     False, "Deny",  "PCI",    "tag",          45000),
        (STORAGE_SRC, "aiagsrccode01", False, "Allow", "SOURCE", "name_pattern", None),
        (STORAGE_PUB, "aiagpublic01",  True,  "Allow", None,     None,           None),
    ]:
        _try_insert(cur, f"sa_{name}", """
            INSERT INTO azure_storage_accounts
                (organization_id, discovery_run_id, subscription_id, resource_id,
                 resource_group, name, location, public_blob_access,
                 default_network_action, private_endpoint_count,
                 data_classification, classification_source, classification_confidence,
                 record_count_estimate)
            VALUES (%s, %s, %s, %s, %s, %s, 'eastus', %s, %s, 0, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (org_id, run_id, SUB_ID, rid, RG_NAME, name, pba, dna,
              cls, src, ('high' if src == 'tag' else 'medium' if src else None),
              est))

    # SQL — table from migration 121 (already has discovered_at)
    _try_insert(cur, "sql_srv", """
        INSERT INTO azure_sql_servers
            (organization_id, discovery_run_id, subscription_id, resource_id,
             resource_group, server_name, location, public_network_access)
        VALUES (%s, %s, %s, %s, %s, 'aiag-sql-prod', 'eastus', 'Enabled')
        ON CONFLICT DO NOTHING
    """, (org_id, run_id, SUB_ID, SQL_SERVER, RG_NAME))
    _try_insert(cur, "sql_db_hr", """
        INSERT INTO azure_sql_databases
            (organization_id, discovery_run_id, subscription_id, resource_id,
             server_resource_id, database_name, sku_name, sku_tier, capacity,
             data_classification, classification_source, classification_confidence,
             record_count_estimate)
        VALUES (%s, %s, %s, %s, %s, 'hr-analytics', 'GP_Gen5', 'GeneralPurpose',
                4, 'HR', 'tag', 'high', 250000)
        ON CONFLICT DO NOTHING
    """, (org_id, run_id, SUB_ID, SQL_DB_HR, SQL_SERVER))
    _try_insert(cur, "sql_db_gen", """
        INSERT INTO azure_sql_databases
            (organization_id, discovery_run_id, subscription_id, resource_id,
             server_resource_id, database_name, sku_name)
        VALUES (%s, %s, %s, %s, %s, 'generic-app', 'S0')
        ON CONFLICT DO NOTHING
    """, (org_id, run_id, SUB_ID, SQL_DB_GEN, SQL_SERVER))

    # Cosmos
    _try_insert(cur, "cosmos_acct", """
        INSERT INTO azure_cosmos_accounts
            (organization_id, discovery_run_id, subscription_id, resource_id,
             resource_group, account_name, location, kind, public_network_access)
        VALUES (%s, %s, %s, %s, %s, 'aiag-cosmos-prod', 'eastus',
                'GlobalDocumentDB', 'Enabled')
        ON CONFLICT DO NOTHING
    """, (org_id, run_id, SUB_ID, COSMOS_ACCT, RG_NAME))
    _try_insert(cur, "cosmos_db_pii", """
        INSERT INTO azure_cosmos_databases
            (organization_id, discovery_run_id, subscription_id, resource_id,
             account_resource_id, database_name, api_kind,
             data_classification, classification_source, classification_confidence,
             record_count_estimate)
        VALUES (%s, %s, %s, %s, %s, 'customer-pii', 'sql', 'PII', 'tag',
                'high', 80000)
        ON CONFLICT DO NOTHING
    """, (org_id, run_id, SUB_ID, COSMOS_DB_PII, COSMOS_ACCT))
    _try_insert(cur, "cosmos_db_gen", """
        INSERT INTO azure_cosmos_databases
            (organization_id, discovery_run_id, subscription_id, resource_id,
             account_resource_id, database_name, api_kind)
        VALUES (%s, %s, %s, %s, %s, 'generic-app-db', 'sql')
        ON CONFLICT DO NOTHING
    """, (org_id, run_id, SUB_ID, COSMOS_DB_GEN, COSMOS_ACCT))

    db.conn.commit()
    logger.info("Resources seeded (cog svc, KV, storage, SQL, Cosmos)")


def _seed_agents(db, run_id: int, org_id: int, *, escalate: bool):
    """Insert AI agents + role_assignments + agent_classifications.

    escalate=True: assigns the high-risk roles that trigger AI_PERMISSIONS_ESCALATED
    on the drift agent. Set False for the first historical run.
    """
    cur = db.conn.cursor()
    _set_org_context(cur, org_id)
    for agent in AGENTS:
        cur.execute("""
            INSERT INTO identities
                (organization_id, discovery_run_id, identity_id, display_name,
                 identity_type, identity_category, risk_score, risk_level,
                 agent_identity_type, activity_status, last_sign_in,
                 created_datetime)
            VALUES (%s, %s, %s, %s, 'service_principal', 'service_principal',
                    %s, %s, %s, 'active', %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING id
        """, (org_id, run_id, agent["identity_id"], agent["display_name"],
              agent["risk_score"], agent["risk_level"], agent["agent_identity_type"],
              NOW - timedelta(hours=2), NOW - timedelta(days=30)))
        row = cur.fetchone()
        if row is None:
            cur.execute("SELECT id FROM identities WHERE identity_id=%s AND organization_id=%s AND discovery_run_id=%s",
                        (agent["identity_id"], org_id, run_id))
            row = cur.fetchone()
        identity_db_id = row[0]

        # agent_classifications row — with the AG-177 enrichment columns
        cur.execute("""
            INSERT INTO agent_classifications
                (identity_db_id, identity_id, agent_identity_type,
                 classification_confidence, classification_reason,
                 detected_platform, pattern_version, discovery_run_id,
                 organization_id, model_name, owner_display_name_at_classify,
                 account_resource_id)
            VALUES (%s, %s, 'ai_agent', 0.95, 'aiag_demo_seeder',
                    'azure_openai', '1.0.0', %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (identity_db_id, agent["identity_id"], run_id, org_id,
              agent["model_name"], agent["owner"], agent["account_resource_id"]))

        # Role assignments — escalation logic for the drift agent
        roles = agent["roles"]
        if not escalate and agent["identity_id"] == DRIFT_AGENT_ID:
            # In the FIRST historical run, drift agent only had Reader
            roles = [{"role_name": "Reader", "scope": COG_ACCT_1, "scope_type": "resource"}]

        for r in roles:
            _try_insert(cur, f"ra_{agent['identity_id'][:8]}_{r['role_name'][:8]}", """
                INSERT INTO role_assignments
                    (organization_id, identity_db_id, role_name,
                     scope, scope_type, principal_id, assignment_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (org_id, identity_db_id, r["role_name"], r["scope"], r["scope_type"],
                  agent["identity_id"], str(uuid.uuid4())))

    db.conn.commit()
    logger.info("Agents + classifications + role_assignments seeded (escalate=%s)", escalate)


def _seed_activity_events(db, org_id: int):
    """Seed a 20-day stream of activity events per agent so behavior_baseline
    has enough samples to be 'is_active' = True."""
    cur = db.conn.cursor()
    _set_org_context(cur, org_id)
    for agent in AGENTS:
        cur.execute("SELECT id FROM identities WHERE identity_id=%s AND organization_id=%s ORDER BY discovery_run_id DESC LIMIT 1",
                    (agent["identity_id"], org_id))
        row = cur.fetchone()
        if row is None: continue
        identity_db_id = row[0]
        # 20 daily samples: model_call category, varying volume.
        # Agent #1 (alexander) gets a volume spike on day 20 → triggers anomaly.
        base = 200 if agent["identity_id"] == DRIFT_AGENT_ID else 100
        for day in range(20):
            ts = NOW - timedelta(days=19 - day)
            metric = base if day < 19 else (base * 5 if agent["identity_id"] == DRIFT_AGENT_ID else base)
            cur.execute("""
                INSERT INTO agent_activity_events
                    (organization_id, identity_db_id, identity_id, category,
                     occurred_at, source, operation_name, metric_value, severity)
                VALUES (%s, %s, %s, 'model_call', %s, 'azure_monitor',
                        'POST /chat/completions', %s, 'info')
            """, (org_id, identity_db_id, agent["identity_id"], ts, metric))
    db.conn.commit()
    logger.info("Activity events seeded (20d × %d agents)", len(AGENTS))


# ─── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Seed AIAG demo data (localhost only)")
    parser.add_argument("--org-id", type=int, default=9,
                        help="Organization ID to seed (default 10)")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Don't remove existing aaa0*-prefixed demo rows first")
    args = parser.parse_args()

    # AG-PILOT-SAFETY (2026-06-07): demo-org allowlist guard. Prevents
    # accidental writes to a customer tenant via typo or stale --org-id.
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _demo_safety import assert_safe_demo_org
    assert_safe_demo_org(args.org_id, script_name='seed_aiag_demo.py')

    logger.info("=" * 60)
    logger.info("  AuditGraph — AIAG Demo Seeder (localhost only)")
    logger.info("=" * 60)

    db = Database()
    try:
        org_id = _find_org(db, args.org_id)
        conn_id = _find_connection_id(db, org_id)
        logger.info("Using cloud_connection_id=%s", conn_id)
        if not args.no_cleanup:
            _cleanup_aiag_demo(db, org_id)

        # Historical run (T-2 days)
        prev_run = _ensure_run(db, org_id, "previous",
                               completed_at=NOW - timedelta(days=2),
                               connection_id=conn_id)
        _seed_resources(db, prev_run, org_id)
        _seed_agents(db, prev_run, org_id, escalate=False)

        # Current run (now)
        curr_run = _ensure_run(db, org_id, "current", completed_at=NOW,
                               connection_id=conn_id)
        _seed_resources(db, curr_run, org_id)
        _seed_agents(db, curr_run, org_id, escalate=True)

        # Activity events for behavior baseline
        _seed_activity_events(db, org_id)

        logger.info("=" * 60)
        logger.info("  Seed complete. Now run the AIAG engines:")
        logger.info("")
        logger.info("  python -c \"")
        logger.info("  from app.database import Database")
        logger.info("  from app.engines.ai.data_reachability_engine import refresh_data_reachability")
        logger.info("  from app.engines.ai.ai_lifecycle_engine import AILifecycleEngine")
        logger.info("  from app.engines.ai.agent_behavior_engine import AgentBehaviorEngine")
        logger.info("  from app.engines.attack_path_engine import AttackPathEngine")
        logger.info("  db = Database()")
        logger.info(f"  refresh_data_reachability(db, {curr_run}, {org_id})")
        logger.info(f"  AILifecycleEngine(db).analyze({curr_run}, {prev_run}, {org_id})")
        logger.info(f"  AgentBehaviorEngine(db).refresh_baselines({org_id})")
        logger.info(f"  AgentBehaviorEngine(db).detect_anomalies({org_id})")
        logger.info(f"  AttackPathEngine(db)._detect_ai_agent_exfiltration({curr_run})")
        logger.info("  \"")
        logger.info("")
        logger.info("  Then visit http://localhost:3000 and follow the runbook.")
        logger.info("=" * 60)
    finally:
        db.close()


if __name__ == "__main__":
    # Same production guard as seed_ai_agent_test_tenant.py
    _APP_ENV = os.environ.get('APP_ENV', 'production')
    _DB_HOST = os.environ.get('DB_HOST', '')
    if _APP_ENV == 'production' or 'prod' in _DB_HOST.lower() or 'azure.com' in _DB_HOST.lower():
        print("ERROR: Refusing to seed against production / cloud.")
        print(f"  APP_ENV={_APP_ENV}")
        print(f"  DB_HOST={_DB_HOST}")
        print("Set APP_ENV=local + DB_HOST=localhost to run.")
        sys.exit(1)
    _confirm = input(
        f"Seeding demo data into {_DB_HOST or 'localhost'} (APP_ENV={_APP_ENV}). "
        "Type 'yes' to continue: "
    )
    if _confirm.strip().lower() != 'yes':
        print("Aborted.")
        sys.exit(0)
    main()
