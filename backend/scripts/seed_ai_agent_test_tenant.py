#!/usr/bin/env python3
"""
AuditGraph — AI Agent Test Tenant Seeder

Provisions 4 synthetic AI agent Service Principals for QA testing
across all AI Agent Governance phases.

Usage:
  cd backend/
  ./venv/bin/python scripts/seed_ai_agent_test_tenant.py

Idempotent — deletes existing AI agent test data before re-seeding.
Requires Azure credentials in .env (AZURE_TENANT_ID, AZURE_CLIENT_ID,
AZURE_CLIENT_SECRET) OR can run in local-only mode (--local) to seed
directly into the database without Azure Graph API calls.

This script is the source of truth for all QA testing across phases.
"""

import argparse
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

# Ensure the backend package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("ai_agent_seeder")

# ─── Constants ────────────────────────────────────────────────────────

NOW = datetime.now(timezone.utc)
RUN_START = NOW - timedelta(hours=1)
RUN_END = NOW - timedelta(minutes=45)

# Deterministic UUIDs for reproducibility across test runs.
# These are NOT real Azure object IDs; they're test-only fixtures.
COPILOT_BOT_OBJ_ID = "aa000001-aaaa-4aaa-aaaa-aaaaaaaaa001"
COPILOT_BOT_APP_ID = "aa000001-aaaa-4aaa-aaaa-aaaaaaaaa101"

OPENAI_APP_OBJ_ID = "aa000002-aaaa-4aaa-aaaa-aaaaaaaaa002"
OPENAI_APP_APP_ID = "aa000002-aaaa-4aaa-aaaa-aaaaaaaaa102"

POWER_AUTO_OBJ_ID = "aa000003-aaaa-4aaa-aaaa-aaaaaaaaa003"
POWER_AUTO_APP_ID = "aa000003-aaaa-4aaa-aaaa-aaaaaaaaa103"

ORPHANED_BOT_OBJ_ID = "aa000004-aaaa-4aaa-aaaa-aaaaaaaaa004"
ORPHANED_BOT_APP_ID = "aa000004-aaaa-4aaa-aaaa-aaaaaaaaa104"

TEST_SUBSCRIPTION_ID = "sub-test-ai-agent-00000001"
TEST_SUBSCRIPTION_NAME = "AI-Agent-Test-Sub"
TEST_RG_NAME = "rg-ai-agents-test"
TEST_STORAGE_ACCOUNT = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/aiagenttest"

# ─── AI Agent Identity Definitions ──────────────────────────────────

AGENT_IDENTITIES = [
    {
        "label": "Copilot Studio Bot",
        "display_name": "ContosoHR-CopilotBot-Prod",
        "object_id": COPILOT_BOT_OBJ_ID,
        "app_id": COPILOT_BOT_APP_ID,
        "identity_type": "service_principal",
        "identity_category": "service_principal",
        "risk_score": 72,
        "risk_level": "high",
        "activity_status": "active",
        "last_sign_in": NOW - timedelta(hours=3),
        "api_permissions": [
            {"resource": "Microsoft Graph", "permission": "User.Read.All", "type": "Application", "status": "Granted"},
            {"resource": "Microsoft Graph", "permission": "Group.Read.All", "type": "Application", "status": "Granted"},
        ],
        "role_assignments": [
            {
                "role_name": "Contributor",
                "role_id": "b24988ac-6180-42a0-ab88-20f7382dd24c",
                "scope": f"/subscriptions/{TEST_SUBSCRIPTION_ID}/resourceGroups/{TEST_RG_NAME}",
                "scope_type": "resource_group",
            },
        ],
        "notes": "Copilot Studio chatbot for HR self-service. Has Graph read access for user/group lookups.",
    },
    {
        "label": "Azure OpenAI App",
        "display_name": "AuditGraph-OpenAI-Integration",
        "object_id": OPENAI_APP_OBJ_ID,
        "app_id": OPENAI_APP_APP_ID,
        "identity_type": "service_principal",
        "identity_category": "service_principal",
        "risk_score": 55,
        "risk_level": "medium",
        "activity_status": "active",
        "last_sign_in": NOW - timedelta(hours=6),
        "api_permissions": [
            {"resource": "Azure OpenAI Service", "permission": "user_impersonation", "type": "Delegated", "status": "Granted"},
        ],
        "role_assignments": [
            {
                "role_name": "Reader",
                "role_id": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
                "scope": f"/subscriptions/{TEST_SUBSCRIPTION_ID}",
                "scope_type": "subscription",
            },
        ],
        "notes": "Azure OpenAI integration SPN. Delegated user_impersonation for AI completions.",
    },
    {
        "label": "Power Automate AI Flow",
        "display_name": "PA-AIFlow-InvoiceProcessor",
        "object_id": POWER_AUTO_OBJ_ID,
        "app_id": POWER_AUTO_APP_ID,
        "identity_type": "service_principal",
        "identity_category": "service_principal",
        "risk_score": 65,
        "risk_level": "high",
        "activity_status": "active",
        "last_sign_in": NOW - timedelta(days=2),
        "api_permissions": [
            {"resource": "SharePoint", "permission": "Sites.ReadWrite.All", "type": "Application", "status": "Granted"},
            {"resource": "Exchange", "permission": "Mail.Send", "type": "Application", "status": "Granted"},
        ],
        "role_assignments": [
            {
                "role_name": "Contributor",
                "role_id": "b24988ac-6180-42a0-ab88-20f7382dd24c",
                "scope": TEST_STORAGE_ACCOUNT.format(sub=TEST_SUBSCRIPTION_ID, rg=TEST_RG_NAME),
                "scope_type": "resource",
            },
        ],
        "notes": "Power Automate AI flow for invoice processing. SharePoint + Exchange + storage access.",
    },
    {
        "label": "Orphaned Agent (Retired)",
        "display_name": "OldBot-RetiredJan2026",
        "object_id": ORPHANED_BOT_OBJ_ID,
        "app_id": ORPHANED_BOT_APP_ID,
        "identity_type": "service_principal",
        "identity_category": "service_principal",
        "risk_score": 88,
        "risk_level": "critical",
        "activity_status": "stale",
        "last_sign_in": NOW - timedelta(days=60),
        "api_permissions": [
            {"resource": "Microsoft Graph", "permission": "Directory.ReadWrite.All", "type": "Application", "status": "Granted"},
        ],
        "role_assignments": [
            {
                "role_name": "Owner",
                "role_id": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "scope": f"/subscriptions/{TEST_SUBSCRIPTION_ID}/resourceGroups/{TEST_RG_NAME}",
                "scope_type": "resource_group",
            },
        ],
        "notes": "Retired agent bot. Last sign-in 60 days ago. Still has Owner role (over-privileged orphan).",
    },
]


def _find_or_create_test_org(db):
    """Find or create a test organization for AI agent seeding."""
    cursor = db.conn.cursor()
    cursor.execute(
        "SELECT id FROM organizations WHERE slug = %s",
        ("ai-agent-test",),
    )
    row = cursor.fetchone()
    if row:
        org_id = row[0]
        logger.info("Using existing test org id=%s (slug=ai-agent-test)", org_id)
    else:
        cursor.execute(
            """INSERT INTO organizations (name, slug, plan, created_at)
               VALUES (%s, %s, %s, NOW()) RETURNING id""",
            ("AI Agent Test Org", "ai-agent-test", "trial"),
        )
        org_id = cursor.fetchone()[0]
        db._commit()
        logger.info("Created test org id=%s (slug=ai-agent-test)", org_id)
    cursor.close()
    return org_id


def _create_discovery_run(db, org_id):
    """Create a discovery run for the AI agent test data."""
    cursor = db.conn.cursor()
    cursor.execute(
        """INSERT INTO discovery_runs
           (status, started_at, completed_at, organization_id,
            identities_found, identities_updated, identities_removed,
            cloud_provider, subscription_name)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
           RETURNING id""",
        ("completed", RUN_START, RUN_END, org_id,
         len(AGENT_IDENTITIES), 0, 0, "azure", TEST_SUBSCRIPTION_NAME),
    )
    run_id = cursor.fetchone()[0]
    db._commit()
    cursor.close()
    logger.info("Created discovery run id=%s", run_id)
    return run_id


def _seed_identities(db, run_id, org_id):
    """Insert AI agent identities + role assignments + permissions."""
    cursor = db.conn.cursor()

    for agent in AGENT_IDENTITIES:
        # Insert identity
        cursor.execute(
            """INSERT INTO identities
               (identity_id, display_name, identity_type, identity_category,
                risk_score, risk_level, discovery_run_id,
                app_id, object_id, activity_status,
                last_sign_in_date, created_at, organization_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
               RETURNING id""",
            (
                agent["object_id"],
                agent["display_name"],
                agent["identity_type"],
                agent["identity_category"],
                agent["risk_score"],
                agent["risk_level"],
                run_id,
                agent["app_id"],
                agent["object_id"],
                agent["activity_status"],
                agent["last_sign_in"],
                org_id,
            ),
        )
        identity_db_id = cursor.fetchone()[0]
        logger.info(
            "  Seeded identity: %s (db_id=%s, risk=%s)",
            agent["display_name"], identity_db_id, agent["risk_level"],
        )

        # Insert role assignments
        for ra in agent.get("role_assignments", []):
            cursor.execute(
                """INSERT INTO role_assignments
                   (identity_db_id, role_name, role_definition_id,
                    scope, scope_type, discovery_run_id, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                (
                    identity_db_id,
                    ra["role_name"],
                    ra["role_id"],
                    ra["scope"],
                    ra.get("scope_type", "resource_group"),
                    run_id,
                ),
            )

        # Insert permissions as JSON in identity_permissions
        if agent.get("api_permissions"):
            cursor.execute(
                """INSERT INTO identity_permissions
                   (identity_db_id, permissions, discovery_run_id, created_at)
                   VALUES (%s, %s, %s, NOW())""",
                (
                    identity_db_id,
                    json.dumps(agent["api_permissions"]),
                    run_id,
                ),
            )

    db._commit()
    cursor.close()
    logger.info("Seeded %d AI agent identities", len(AGENT_IDENTITIES))


def _cleanup_previous(db, org_id):
    """Delete previous AI agent test data for idempotency."""
    cursor = db.conn.cursor()

    # Find previous test discovery runs
    cursor.execute(
        """SELECT id FROM discovery_runs
           WHERE organization_id = %s AND subscription_name = %s""",
        (org_id, TEST_SUBSCRIPTION_NAME),
    )
    run_ids = [r[0] for r in cursor.fetchall()]

    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))

        # Delete dependent rows first
        for table in ["identity_permissions", "role_assignments", "credentials"]:
            cursor.execute(
                f"""DELETE FROM {table}
                    WHERE identity_db_id IN (
                        SELECT id FROM identities WHERE discovery_run_id IN ({placeholders})
                    )""",
                run_ids,
            )

        cursor.execute(
            f"DELETE FROM identities WHERE discovery_run_id IN ({placeholders})",
            run_ids,
        )
        cursor.execute(
            f"DELETE FROM discovery_runs WHERE id IN ({placeholders})",
            run_ids,
        )
        db._commit()
        logger.info("Cleaned up %d previous test run(s)", len(run_ids))

    cursor.close()


def seed_local(db):
    """Seed AI agent identities directly into the local database."""
    # Use admin connection (bypasses RLS)
    org_id = _find_or_create_test_org(db)
    _cleanup_previous(db, org_id)
    run_id = _create_discovery_run(db, org_id)
    _seed_identities(db, run_id, org_id)
    return org_id, run_id


def main():
    parser = argparse.ArgumentParser(
        description="Seed AI agent test identities for QA testing"
    )
    parser.add_argument(
        "--local", action="store_true", default=True,
        help="Seed directly into local DB (default, no Azure API calls)",
    )
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("  AuditGraph — AI Agent Test Tenant Seeder")
    logger.info("=" * 60)

    db = Database(_admin_reason="ai_agent_test_seeder: seed test data")
    try:
        org_id, run_id = seed_local(db)

        logger.info("=" * 60)
        logger.info("  Seeding complete!")
        logger.info("  Organization ID: %s", org_id)
        logger.info("  Discovery Run ID: %s", run_id)
        logger.info("  Identities seeded: %d", len(AGENT_IDENTITIES))
        logger.info("")
        logger.info("  Agent SPNs:")
        for a in AGENT_IDENTITIES:
            logger.info("    - %s (%s, risk=%s)", a["display_name"], a["label"], a["risk_level"])
        logger.info("=" * 60)
    finally:
        db.close()


if __name__ == "__main__":
    # AG-105: Production guard — refuse to seed in production environments
    _APP_ENV = os.environ.get('APP_ENV', 'production')
    _DB_HOST = os.environ.get('DB_HOST', '')
    if _APP_ENV == 'production' or 'prod' in _DB_HOST.lower():
        print("ERROR: Refusing to run seed script in production.")
        print(f"  APP_ENV={_APP_ENV}")
        print(f"  DB_HOST={_DB_HOST}")
        print("Set APP_ENV=local to run seed scripts.")
        sys.exit(1)
    _confirm = input(
        f"Seeding DB at {_DB_HOST} (APP_ENV={_APP_ENV}). "
        "Type 'yes' to continue: "
    )
    if _confirm.strip().lower() != 'yes':
        print("Aborted.")
        sys.exit(0)

    main()
