#!/usr/bin/env python3
"""
AuditGraph Demo Organization Seeder
====================================
Creates a complete "AuditGraph Demo" organization with 280 realistic synthetic
identities spanning human users, service principals, managed identities, and
AI agents — showcasing every AuditGraph capability.

Run from backend/: python3 scripts/seed_demo_org.py

IDEMPOTENT — deletes existing "auditgraph-demo" org data before re-seeding.
"""

import os
import sys
import json
import uuid
import random
import hashlib
import logging
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
logger = logging.getLogger("demo_org_seeder")

# ─── Constants ──────────────────────────────────────────────────────

NOW = datetime.now(timezone.utc)
RUN_START = NOW - timedelta(hours=2)
RUN_END = NOW - timedelta(hours=1)
DOMAIN = "auditgraph-demo.com"

SUBS = [
    ("/subscriptions/sub-demo-prod-0001", "AuditDemo-Production"),
    ("/subscriptions/sub-demo-dev-0001", "AuditDemo-Development"),
]
RGS = ["rg-core-prod", "rg-data-prod", "rg-networking-prod", "rg-app-prod",
       "rg-monitoring-prod", "rg-ml-prod", "rg-security-prod", "rg-devops"]

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5434"))
DB_NAME = os.environ.get("DB_NAME", "auditgraph")
DB_USER = os.environ.get("DB_ADMIN_USER", "auditgraph")
DB_PASS = os.environ.get("DB_ADMIN_PASSWORD", "auditgraph")


# ─── Helpers ────────────────────────────────────────────────────────

def _uuid():
    return str(uuid.uuid4())


def _past(days_min=1, days_max=365):
    return NOW - timedelta(days=random.randint(days_min, days_max),
                           hours=random.randint(0, 23),
                           minutes=random.randint(0, 59))


def _future(days_min=1, days_max=365):
    return NOW + timedelta(days=random.randint(days_min, days_max))


def _risk_level(score):
    if score >= 800:
        return "critical"
    if score >= 600:
        return "high"
    if score >= 300:
        return "medium"
    return "low"


def _hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def _fingerprint(*parts):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()


def get_conn():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS,
    )


# ═══════════════════════════════════════════════════════════════════
#  IDENTITY DEFINITIONS
# ═══════════════════════════════════════════════════════════════════

# ── 20 Privileged Admin Users ──────────────────────────────────────
ADMIN_USERS = [
    ("admin_sarah.chen", "Sarah Chen"),
    ("admin_marcus.johnson", "Marcus Johnson"),
    ("admin_priya.patel", "Priya Patel"),
    ("admin_james.rodriguez", "James Rodriguez"),
    ("admin_emily.watson", "Emily Watson"),
    ("admin_david.kim", "David Kim"),
    ("admin_alexandra.torres", "Alexandra Torres"),
    ("admin_michael.brown", "Michael Brown"),
    ("admin_jessica.lee", "Jessica Lee"),
    ("admin_robert.martinez", "Robert Martinez"),
    ("admin_jennifer.davis", "Jennifer Davis"),
    ("admin_chris.wilson", "Chris Wilson"),
    ("admin_amanda.thompson", "Amanda Thompson"),
    ("admin_daniel.anderson", "Daniel Anderson"),
    ("admin_stephanie.jackson", "Stephanie Jackson"),
    ("admin_matthew.white", "Matthew White"),
    ("admin_ashley.harris", "Ashley Harris"),
    ("admin_joshua.clark", "Joshua Clark"),
    ("admin_brittany.lewis", "Brittany Lewis"),
    ("admin_andrew.robinson", "Andrew Robinson"),
]

# ── 100 Regular Users (departments) ───────────────────────────────
_ENG_NAMES = [
    "alex.rivera", "jordan.patel", "taylor.nguyen", "casey.murphy",
    "riley.chen", "drew.jackson", "blake.kumar", "quinn.garcia",
    "avery.williams", "parker.shah", "logan.thompson", "harper.lee",
    "emerson.davis", "rowan.miller", "kai.suzuki", "sage.brown",
    "finley.wilson", "dakota.moore", "hayden.taylor", "cameron.white",
    "reese.martinez", "skyler.jones", "jamie.robinson", "spencer.harris",
    "addison.clark", "charlie.lewis", "sam.walker", "robin.hall",
    "kit.allen", "ash.young",
]
_FIN_NAMES = [
    "morgan.price", "peyton.stewart", "alexis.sanders", "kendall.bennett",
    "eden.brooks", "lane.cook", "noel.reed", "tatum.morgan",
    "vera.bailey", "willow.murphy", "holly.howard", "ivy.ward",
    "jade.torres", "kira.james", "lark.watson", "marina.campbell",
    "pearl.ross", "rosa.peterson", "fern.gray", "wren.sanders",
]
_OPS_NAMES = [
    "august.carter", "phoenix.mitchell", "shea.perez", "briar.roberts",
    "cedar.turner", "darcy.phillips", "elliot.campbell", "forrest.parker",
    "glenn.evans", "haven.edwards", "juniper.collins", "kestrel.stewart",
    "laurel.morris", "maple.rogers", "nova.reed", "olive.cook",
    "piper.morgan", "rain.bailey", "sierra.bell", "terra.murphy",
    "scout.howard", "birch.ward", "clover.cox", "dawn.long",
    "aria.foster",
]
_HR_NAMES = [
    "chelsea.grant", "dylan.powell", "grace.russell", "henry.foster",
    "isla.butler", "leo.simmons", "mila.hayes", "owen.bryant",
    "ruby.alexander", "theo.russell", "zoe.sullivan", "nina.jenkins",
    "eli.perry", "cora.powell", "felix.barnes",
]
_MKT_NAMES = [
    "lily.west", "noah.hart", "stella.weaver", "oscar.chambers",
    "hannah.watts", "lucas.arnold", "nora.black", "ezra.stone",
    "vivian.fox", "miles.lambert",
]

REGULAR_USERS = (
    [(n, "Engineering") for n in _ENG_NAMES] +
    [(n, "Finance") for n in _FIN_NAMES] +
    [(n, "Operations") for n in _OPS_NAMES] +
    [(n, "HR") for n in _HR_NAMES] +
    [(n, "Marketing") for n in _MKT_NAMES]
)

# ── 30 Ghost Users (disabled + live RBAC) ─────────────────────────
GHOST_ADMIN = [
    "admin_john.smith", "admin_sarah.brown", "admin_michael.davis",
    "admin_lisa.taylor", "admin_robert.clark", "admin_karen.moore",
    "admin_steven.hall", "admin_nancy.allen", "admin_thomas.wright",
    "admin_patricia.young",
]
GHOST_REGULAR = [
    "michael.davis", "lisa.taylor", "robert.clark", "karen.moore",
    "steven.hall", "nancy.allen", "thomas.wright", "patricia.young",
    "george.king", "betty.scott", "richard.green", "dorothy.adams",
    "charles.nelson", "margaret.hill", "joseph.baker", "sandra.gonzalez",
    "mark.hernandez", "donna.mitchell", "paul.perez", "carol.roberts",
]

# ── 30 System Managed Identities ──────────────────────────────────
SYSTEM_MIS = [
    "prod-aks-cluster-identity", "prod-sql-server-mi", "prod-keyvault-accessor",
    "prod-apim-gateway-mi", "prod-servicebus-processor",
    "edhc-prod-data-factory-mi", "edhc-prod-backup-vault-mi",
    "edhc-prod-monitoring-mi",
    "webapp-prod-identity-01", "webapp-prod-identity-02",
    "webapp-prod-identity-03", "webapp-prod-identity-04",
    "webapp-prod-identity-05", "webapp-prod-identity-06",
    "webapp-prod-identity-07", "webapp-prod-identity-08",
    "webapp-prod-identity-09", "webapp-prod-identity-10",
    "func-prod-processor-mi", "func-prod-scheduler-mi",
    "container-app-prod-mi", "iot-hub-prod-mi",
    "stream-analytics-prod-mi", "cognitive-services-prod-mi",
    "batch-processing-prod-mi", "vm-monitoring-prod-mi",
    # AI agent system MIs (4)
    "ml-prod-training-identity", "ml-inference-cluster-mi",
    "ai-studio-prod-identity", "ai-search-service-mi",
]

# ── 40 User Assigned Managed Identities ───────────────────────────
USER_MIS = [
    "shared-webapp-identity", "shared-function-identity",
    "shared-devops-pipeline-mi", "ml-training-identity",
    "data-pipeline-identity-01", "data-pipeline-identity-02",
    "data-pipeline-identity-03", "data-pipeline-identity-04",
    "data-pipeline-identity-05", "data-pipeline-identity-06",
    "data-pipeline-identity-07", "data-pipeline-identity-08",
    "data-pipeline-identity-09", "data-pipeline-identity-10",
    "integration-service-mi-01", "integration-service-mi-02",
    "integration-service-mi-03", "integration-service-mi-04",
    "integration-service-mi-05", "integration-service-mi-06",
    "integration-service-mi-07", "integration-service-mi-08",
    "integration-service-mi-09", "integration-service-mi-10",
    "etl-shared-identity", "reporting-shared-mi",
    "cicd-runner-identity", "staging-deployer-mi",
    "qa-automation-identity", "load-test-runner-mi",
    "log-aggregator-mi", "cert-rotation-identity",
    "dns-updater-mi", "backup-orchestrator-mi",
    "cost-analytics-mi", "compliance-scanner-mi",
    "vulnerability-scanner-mi", "secret-rotator-mi",
    "event-processor-mi", "notification-dispatcher-mi",
]

# ── 60 Service Principals ─────────────────────────────────────────
# 15 owned
OWNED_SPNS = [
    "app-finance-reporting", "app-hr-integration", "app-crm-connector",
    "app-bi-dashboard", "app-monitoring-agent", "app-backup-service",
    "app-email-gateway", "app-webhook-processor", "app-api-gateway",
    "app-auth-service", "app-inventory-sync", "app-payroll-connector",
    "app-document-manager", "app-notification-hub", "app-analytics-engine",
]
# 25 orphaned
ORPHANED_SPNS = [
    "legacy-bi-connector", "old-reporting-spn", "test-automation-sp",
    "temp-migration-tool",
    "abandoned-integration-01", "abandoned-integration-02",
    "abandoned-integration-03", "abandoned-integration-04",
    "abandoned-integration-05", "abandoned-integration-06",
    "abandoned-integration-07", "abandoned-integration-08",
    "abandoned-integration-09", "abandoned-integration-10",
    "orphaned-pipeline-sp-01", "orphaned-pipeline-sp-02",
    "orphaned-pipeline-sp-03", "orphaned-pipeline-sp-04",
    "orphaned-pipeline-sp-05", "orphaned-pipeline-sp-06",
    "orphaned-pipeline-sp-07", "orphaned-pipeline-sp-08",
    "orphaned-pipeline-sp-09", "orphaned-pipeline-sp-10",
    "decommissioned-sync-sp",
]
# 20 overpermissive (includes 6 AI agent SPNs)
OVERPERM_SPNS = [
    "terraform-automation-sp", "devops-pipeline-sp",
    "databricks-connector-sp", "snowflake-integration-sp",
    "azure-devops-sp", "github-actions-sp", "ansible-automation-sp",
    "pulumi-deploy-sp", "jenkins-cicd-sp", "argocd-deploy-sp",
    "crossplane-operator-sp", "vault-unsealer-sp",
    "backup-admin-sp", "disaster-recovery-sp",
    # AI agent SPNs (6)
    "customer-service-bot", "hr-assistant-bot",
    "sales-automation-agent", "openai-prod-connector-sp",
    "gpt4-inference-service-sp", "claude-automation-connector-sp",
]

# AI agent identities (subset of above)
AI_AGENT_SPNS = {
    "customer-service-bot": ("copilot_studio", 0.98),
    "hr-assistant-bot": ("copilot_studio", 0.98),
    "sales-automation-agent": ("copilot_studio", 0.98),
    "openai-prod-connector-sp": ("azure_openai", 1.0),
    "gpt4-inference-service-sp": ("azure_openai", 1.0),
    "claude-automation-connector-sp": ("anthropic", 0.85),
}
AI_AGENT_SYS_MIS = {
    "ml-prod-training-identity": ("azure_ml", 0.95),
    "ml-inference-cluster-mi": ("azure_ml", 0.95),
    "ai-studio-prod-identity": ("azure_ai_studio", 0.85),
    "ai-search-service-mi": ("azure_ai_studio", 0.85),
}


# ═══════════════════════════════════════════════════════════════════
#  PART 1 — ORG + USER + CLOUD CONNECTION
# ═══════════════════════════════════════════════════════════════════

def setup_org(conn):
    """Create or re-use the auditgraph-demo organization. Returns org_id."""
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Check existing
    cur.execute("SELECT id FROM organizations WHERE slug = 'auditgraph-demo'")
    row = cur.fetchone()
    if row:
        org_id = row["id"]
        logger.info("Found existing org id=%s, will clean and re-seed", org_id)
        clean_all(conn, org_id)
        return org_id

    # Create new
    cur.execute("""
        INSERT INTO organizations (name, slug, plan, status, onboarding_stage,
                                   primary_cloud, enabled, is_demo, created_at)
        VALUES ('AuditGraph Demo', 'auditgraph-demo', 'pro', 'active', 'active',
                'azure', true, true, NOW())
        RETURNING id
    """)
    org_id = cur.fetchone()["id"]
    conn.commit()
    logger.info("Created organization 'AuditGraph Demo' id=%s", org_id)
    return org_id


def setup_user(conn, org_id):
    """Create the demoadmin user."""
    cur = conn.cursor()
    pw_hash = _hash_pw("changeme")
    cur.execute("""
        INSERT INTO users (username, password_hash, display_name, role, enabled,
                           organization_id, email, created_at)
        VALUES ('demoadmin', %s, 'Demo Admin', 'admin', true, %s,
                'demoadmin@auditgraph-demo.com', NOW())
        ON CONFLICT DO NOTHING
    """, (pw_hash, org_id))
    conn.commit()
    logger.info("Created user demoadmin (org_id=%s)", org_id)


def setup_cloud_connection(conn, org_id):
    """Create Azure cloud connection. Returns cc_id."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cloud_connections
            (organization_id, cloud, connection_type, label,
             azure_directory_id, status, created_at)
        VALUES (%s, 'azure', 'entra', 'Primary (Azure)',
                'demo-tenant-id-0001', 'connected', NOW())
        RETURNING id
    """, (org_id,))
    cc_id = cur.fetchone()[0]
    conn.commit()
    logger.info("Created cloud_connection id=%s", cc_id)
    return cc_id


# ═══════════════════════════════════════════════════════════════════
#  CLEANUP
# ═══════════════════════════════════════════════════════════════════

def clean_all(conn, org_id):
    """Remove all data for the demo org (idempotent re-seed)."""
    cur = conn.cursor()
    logger.info("Cleaning existing data for org_id=%s...", org_id)

    # Tables with organization_id
    org_tables = [
        "lineage_verdicts", "agent_classifications",
        "graph_attack_findings", "attack_paths", "security_findings",
        "blast_radius_results", "fix_recommendations",
        "review_evidence", "review_assignments", "access_reviews",
        "report_outputs", "report_runs", "reports",
        "tenant_health", "job_runs", "discovery_integrity_metrics",
        "remediation_actions", "generated_remediations", "drift_reports",
        "sp_ownership", "graph_api_permissions",
    ]
    for t in org_tables:
        try:
            cur.execute(f"DELETE FROM {t} WHERE organization_id = %s", (org_id,))
        except Exception:
            conn.rollback()

    # Tables linked via discovery_run_id
    cur.execute("SELECT id FROM discovery_runs WHERE organization_id = %s", (org_id,))
    run_ids = [r[0] for r in cur.fetchall()]
    if run_ids:
        run_tables = [
            "azure_storage_accounts", "azure_key_vaults", "credentials",
            "entra_role_assignments", "role_assignments",
            "pim_eligible_assignments", "pim_activations",
            "identity_subscription_access",
        ]
        for t in run_tables:
            try:
                cur.execute(f"DELETE FROM {t} WHERE discovery_run_id = ANY(%s)", (run_ids,))
            except Exception:
                conn.rollback()
        # identities last (FKs)
        try:
            cur.execute("DELETE FROM identities WHERE discovery_run_id = ANY(%s)", (run_ids,))
        except Exception:
            conn.rollback()
        cur.execute("DELETE FROM discovery_runs WHERE organization_id = %s", (org_id,))

    # Cloud subscriptions
    try:
        cur.execute("DELETE FROM cloud_subscriptions WHERE organization_id = %s", (org_id,))
    except Exception:
        conn.rollback()

    # Entra groups + memberships
    try:
        cur.execute("""
            DELETE FROM entra_group_memberships WHERE group_db_id IN
            (SELECT id FROM entra_groups WHERE organization_id = %s)
        """, (org_id,))
        cur.execute("DELETE FROM entra_groups WHERE organization_id = %s", (org_id,))
    except Exception:
        conn.rollback()

    # Cloud connections
    try:
        cur.execute("DELETE FROM cloud_connections WHERE organization_id = %s", (org_id,))
    except Exception:
        conn.rollback()

    # Users
    try:
        cur.execute("DELETE FROM users WHERE organization_id = %s", (org_id,))
    except Exception:
        conn.rollback()

    # Settings
    try:
        cur.execute("DELETE FROM settings WHERE organization_id = %s", (org_id,))
    except Exception:
        conn.rollback()

    conn.commit()
    logger.info("Cleaned all demo org data.")


# ═══════════════════════════════════════════════════════════════════
#  PART 2 — DISCOVERY RUN
# ═══════════════════════════════════════════════════════════════════

def create_discovery_run(conn, org_id, cc_id):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO discovery_runs
            (subscription_id, subscription_name, started_at, completed_at,
             status, total_identities, critical_count, high_count,
             medium_count, low_count, organization_id, cloud_connection_id)
        VALUES ('sub-demo-prod-0001', 'AuditDemo-Production',
                %s, %s, 'completed', 280, 25, 55, 120, 80, %s, %s)
        RETURNING id
    """, (RUN_START, RUN_END, org_id, cc_id))
    run_id = cur.fetchone()[0]
    conn.commit()
    logger.info("Created discovery_run id=%s", run_id)
    return run_id


# ═══════════════════════════════════════════════════════════════════
#  PART 3-7 — IDENTITIES (280 total)
# ═══════════════════════════════════════════════════════════════════

def seed_identities(conn, org_id, run_id):
    """Seed all 280 identities. Returns {identity_id: db_id} map."""
    cur = conn.cursor()
    identity_map = {}
    counters = {"human_user": 0, "managed_identity_system": 0,
                "managed_identity_user": 0, "service_principal": 0}

    def _insert(identity_id, display_name, category, **kw):
        risk_score = kw.get("risk_score", random.randint(80, 300))
        risk = _risk_level(risk_score)
        obj_id = _uuid()
        app_id = _uuid() if category == "service_principal" else None
        enabled = kw.get("enabled", True)
        cred_count = kw.get("credential_count", 0)
        owner_count = kw.get("owner_count", random.randint(0, 2))
        activity = kw.get("activity_status", "active")
        last_act = kw.get("last_activity_date")
        last_src = kw.get("last_activity_source", "Azure sign-in")
        privilege_tier = kw.get("privilege_tier", "T3")
        lifecycle = kw.get("lifecycle_state", "Active")
        eff_scope = kw.get("effective_scope_flag", "none")
        access_tier = kw.get("access_tier", "data_plane")
        rec_action = kw.get("recommended_action")
        blast = kw.get("blast_radius_score", 0)
        lineage_sig = kw.get("lineage_signals")
        lineage_nar = kw.get("lineage_narrative")
        status = kw.get("status", "active" if enabled else "disabled")

        identity_type = {
            "service_principal": "ServicePrincipal",
            "managed_identity_system": "ManagedIdentity",
            "managed_identity_user": "ManagedIdentity",
            "human_user": "User",
            "guest": "User",
        }.get(category, "User")

        # Prevent _backfill_is_microsoft_system from reclassifying demo SPNs
        app_owner_org = 'demo-tenant-id-0001' if category == 'service_principal' else None

        cur.execute("""
            INSERT INTO identities
                (discovery_run_id, identity_id, display_name, source, identity_type,
                 identity_category, app_id, object_id, enabled, is_microsoft_system,
                 risk_level, risk_score, risk_reasons,
                 credential_count, owner_count, activity_status,
                 last_activity_date, last_activity_source,
                 privilege_tier, lifecycle_state, effective_scope_flag,
                 access_tier, recommended_action, blast_radius_score,
                 lineage_signals, lineage_narrative,
                 cloud, status, organization_id,
                 app_owner_org_id,
                 created_datetime, created_at)
            VALUES (%s,%s,%s,'azure',%s,%s,%s,%s,%s,false,
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    'azure',%s,%s,%s,%s,NOW())
            RETURNING id
        """, (
            run_id, identity_id, display_name, identity_type, category,
            app_id, obj_id, enabled,
            risk, risk_score, kw.get("risk_reasons", []),
            cred_count, owner_count, activity,
            last_act, last_src,
            privilege_tier, lifecycle, eff_scope,
            access_tier, rec_action, blast,
            json.dumps(lineage_sig) if lineage_sig else None,
            lineage_nar,
            status, org_id,
            app_owner_org,
            _past(30, 730),
        ))
        db_id = cur.fetchone()[0]
        identity_map[identity_id] = db_id
        counters[category] = counters.get(category, 0) + 1
        return db_id

    # ── Part 3a: 20 Admin Users (privileged) ──────────────────────
    for uname, dname in ADMIN_USERS:
        iid = f"{uname}@{DOMAIN}"
        _insert(iid, dname,
                "human_user",
                risk_score=random.randint(600, 900),
                privilege_tier=random.choice(["T0", "T0", "T1"]),
                lifecycle_state="Active",
                effective_scope_flag="subscription",
                access_tier="control_plane",
                owner_count=0,
                activity_status="active",
                last_activity_date=_past(1, 30),
                last_activity_source="P2 sign-in",
                recommended_action="NEEDS_REVIEW",
                lineage_narrative="Privileged admin account with broad access",
                risk_reasons=["privileged_admin", "broad_access"])

    # ── Part 3b: 100 Regular Users ────────────────────────────────
    for uname, dept in REGULAR_USERS:
        iid = f"{uname}@{DOMAIN}"
        is_stale = random.random() < 0.2
        _insert(iid, uname.replace(".", " ").title(),
                "human_user",
                risk_score=random.randint(80, 300),
                privilege_tier="T3",
                lifecycle_state="Active" if not is_stale else "Dormant",
                effective_scope_flag=random.choice(["resource_group", "resource"]),
                access_tier=random.choice(["control_plane"] * 3 + ["data_plane"] * 7),
                owner_count=1,
                activity_status="active" if not is_stale else "stale",
                last_activity_date=_past(1, 90),
                last_activity_source="Azure sign-in",
                lineage_narrative=f"{dept} department staff",
                risk_reasons=["workforce_access"])

    # ── Part 3c: 30 Ghost Users (disabled + live RBAC) ────────────
    for uname in GHOST_ADMIN:
        iid = f"{uname}@{DOMAIN}"
        _insert(iid, uname.replace("admin_", "").replace(".", " ").title() + " (former)",
                "human_user",
                enabled=False,
                risk_score=random.randint(500, 800),
                privilege_tier=random.choice(["T0", "T1"]),
                lifecycle_state="Disabled",
                effective_scope_flag="subscription",
                access_tier="control_plane",
                owner_count=0,
                activity_status="stale",
                last_activity_date=_past(90, 400),
                last_activity_source="Azure sign-in",
                recommended_action="GHOST_ACCESS",
                lineage_narrative="Former admin — disabled but RBAC roles still active",
                risk_reasons=["ghost_identity", "live_rbac_on_disabled_account"],
                status="disabled")

    for uname in GHOST_REGULAR:
        iid = f"{uname}@{DOMAIN}"
        _insert(iid, uname.replace(".", " ").title() + " (former)",
                "human_user",
                enabled=False,
                risk_score=random.randint(400, 650),
                privilege_tier="T2",
                lifecycle_state="Disabled",
                effective_scope_flag="resource_group",
                access_tier="data_plane",
                owner_count=0,
                activity_status="stale",
                last_activity_date=_past(90, 400),
                last_activity_source="Azure sign-in",
                recommended_action="GHOST_ACCESS",
                lineage_narrative="Former employee — disabled but RBAC roles never cleaned up",
                risk_reasons=["ghost_identity", "live_rbac_on_disabled_account"],
                status="disabled")

    # ── Part 4: 30 System Managed Identities ──────────────────────
    high_risk_sys_mi = {
        "prod-aks-cluster-identity", "prod-keyvault-accessor",
        "prod-sql-server-mi", "prod-apim-gateway-mi",
        "prod-servicebus-processor", "edhc-prod-data-factory-mi",
        "ml-prod-training-identity", "ml-inference-cluster-mi",
        "ai-studio-prod-identity", "ai-search-service-mi",
    }
    for mi_name in SYSTEM_MIS:
        is_high = mi_name in high_risk_sys_mi
        is_ai = mi_name in AI_AGENT_SYS_MIS
        never_used = random.random() < 0.15 and not is_high
        _insert(mi_name, mi_name,
                "managed_identity_system",
                risk_score=random.randint(500, 950) if is_high else random.randint(100, 450),
                privilege_tier="T0" if is_high else random.choice(["T1", "T2", "T3"]),
                lifecycle_state="Active" if not never_used else "Provisioned",
                effective_scope_flag="subscription" if is_high else "resource_group",
                access_tier="control_plane" if is_high else "data_plane",
                owner_count=1 if random.random() < 0.17 else 0,
                activity_status="active" if not never_used else "never_used",
                last_activity_date=_past(1, 14) if is_ai else (_past(1, 60) if not never_used else None),
                last_activity_source="ARM activity" if not never_used else None,
                recommended_action="ORPHANED" if random.random() < 0.5 else None,
                blast_radius_score=random.randint(50, 95) if is_high else random.randint(0, 40),
                lineage_narrative="System-assigned MI for " + mi_name.replace("-", " "),
                risk_reasons=["overly_privileged_nhi", "no_owner"] if is_high else ["standard_access"],
                credential_count=0)

    # ── Part 5: 40 User Assigned Managed Identities ───────────────
    for i, mi_name in enumerate(USER_MIS):
        never_used = random.random() < 0.30
        has_owner = random.random() < 0.375  # 15/40
        hi_priv = i < 5
        _insert(mi_name, mi_name,
                "managed_identity_user",
                risk_score=random.randint(400, 700) if hi_priv else random.randint(100, 400),
                privilege_tier="T1" if hi_priv else random.choice(["T2", "T3"]),
                lifecycle_state="Active" if not never_used else "Provisioned",
                effective_scope_flag="subscription" if hi_priv else "resource_group",
                access_tier="control_plane" if hi_priv else "data_plane",
                owner_count=1 if has_owner else 0,
                activity_status="active" if not never_used else "never_used",
                last_activity_date=_past(1, 60) if not never_used else None,
                last_activity_source="ARM activity" if not never_used else None,
                recommended_action="UNUSED" if never_used else None,
                lineage_narrative="User-assigned MI: " + mi_name.replace("-", " "),
                risk_reasons=["shared_identity"] if "shared" in mi_name else ["standard_access"],
                credential_count=0)

    # ── Part 6a: 15 Owned SPNs ────────────────────────────────────
    for i, sp_name in enumerate(OWNED_SPNS):
        _insert(sp_name, sp_name.replace("-", " ").title(),
                "service_principal",
                risk_score=random.randint(100, 400),
                privilege_tier=random.choice(["T2", "T3"]),
                lifecycle_state="Active",
                effective_scope_flag="resource_group",
                access_tier="data_plane",
                owner_count=1,
                activity_status="active",
                last_activity_date=_past(1, 30),
                last_activity_source="ARM activity",
                recommended_action="NEEDS_REVIEW" if i < 5 else None,
                lineage_narrative="Business application SPN with assigned owner",
                risk_reasons=["standard_access"],
                credential_count=random.randint(1, 3))

    # ── Part 6b: 25 Orphaned SPNs ─────────────────────────────────
    for i, sp_name in enumerate(ORPHANED_SPNS):
        has_valid_creds = i < 15
        _insert(sp_name, sp_name.replace("-", " ").title(),
                "service_principal",
                risk_score=random.randint(450, 750) if has_valid_creds else random.randint(350, 550),
                privilege_tier=random.choice(["T1", "T2"]),
                lifecycle_state="Active" if has_valid_creds else "Dormant",
                effective_scope_flag="resource_group",
                access_tier="control_plane" if i < 8 else "data_plane",
                owner_count=0,
                activity_status="stale",
                last_activity_date=_past(60, 300),
                last_activity_source="AuditGraph snapshot",
                recommended_action="ORPHANED",
                blast_radius_score=random.randint(10, 45),
                lineage_narrative="Orphaned SPN — no owner, potentially abandoned",
                risk_reasons=["orphaned_service_principal",
                              "active_credentials_unowned_spn"] if has_valid_creds else
                             ["orphaned_service_principal"],
                credential_count=random.randint(1, 3))

    # ── Part 6c: 20 Overpermissive SPNs (incl. AI agents) ────────
    for i, sp_name in enumerate(OVERPERM_SPNS):
        is_ai = sp_name in AI_AGENT_SPNS
        is_sub_owner = i < 5
        _insert(sp_name, sp_name.replace("-", " ").title(),
                "service_principal",
                risk_score=random.randint(600, 900) if is_sub_owner else random.randint(500, 750),
                privilege_tier="T0" if is_sub_owner else "T1",
                lifecycle_state="Active",
                effective_scope_flag="subscription" if is_sub_owner else "resource_group",
                access_tier="control_plane",
                owner_count=1 if i < 10 and not is_ai else 0,
                activity_status="active",
                last_activity_date=_past(1, 7) if is_ai else _past(1, 30),
                last_activity_source="ARM activity",
                recommended_action=None,
                blast_radius_score=random.randint(60, 95) if is_sub_owner else random.randint(30, 65),
                lineage_narrative="Overpermissive automation SPN with broad access",
                risk_reasons=["overly_broad_rbac",
                              "subscription_owner"] if is_sub_owner else ["overly_broad_rbac"],
                credential_count=random.randint(1, 4))

    conn.commit()
    cur.close()
    total = sum(counters.values())
    logger.info("Seeded %d identities: %s", total,
                ", ".join(f"{v} {k}" for k, v in counters.items()))
    return identity_map


# ═══════════════════════════════════════════════════════════════════
#  CREDENTIALS
# ═══════════════════════════════════════════════════════════════════

def seed_credentials(conn, identity_map, run_id):
    cur = conn.cursor()
    count = 0
    cred_id = 1
    spn_names = OWNED_SPNS + ORPHANED_SPNS + OVERPERM_SPNS

    for i, sp_name in enumerate(spn_names):
        db_id = identity_map.get(sp_name)
        if not db_id:
            continue
        n_creds = random.randint(1, 3)
        for j in range(n_creds):
            cred_type = random.choice(["secret", "secret", "certificate"])
            start = _past(60, 400)
            # Expiry logic
            if sp_name in ORPHANED_SPNS and i < 10 and j == 0:
                end = _past(1, 30)  # expired
            elif sp_name in OWNED_SPNS and i < 5 and j == 0:
                end = _future(1, 30)  # expiring soon
            else:
                end = _future(30, 365)

            cur.execute("""
                INSERT INTO credentials
                    (id, identity_db_id, credential_type, key_id, display_name,
                     start_datetime, end_datetime, discovered_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (cred_id, db_id, cred_type, _uuid(),
                  f"{sp_name} {cred_type.title()} #{j+1}", start, end))
            cred_id += 1
            count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d credentials.", count)


# ═══════════════════════════════════════════════════════════════════
#  ROLE ASSIGNMENTS (RBAC + Entra)
# ═══════════════════════════════════════════════════════════════════

def seed_role_assignments(conn, identity_map, run_id, org_id):
    cur = conn.cursor()
    rbac_count = 0
    entra_count = 0

    def _rbac(identity_id, role, sub_idx=0, scope_type="subscription"):
        nonlocal rbac_count
        db_id = identity_map.get(identity_id)
        if not db_id:
            return
        sub_scope, sub_name = SUBS[sub_idx % len(SUBS)]
        if scope_type == "subscription":
            scope = sub_scope
        elif scope_type == "resource_group":
            scope = f"{sub_scope}/resourceGroups/{random.choice(RGS)}"
        else:
            scope = (f"{sub_scope}/resourceGroups/{random.choice(RGS)}"
                     f"/providers/Microsoft.Storage/storageAccounts/demostorage")
        cur.execute("""
            INSERT INTO role_assignments
                (identity_db_id, role_name, scope, scope_type, principal_id,
                 assignment_id, created_on, created_at, organization_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,NOW(),%s)
        """, (db_id, role, scope, scope_type, _uuid(), _uuid(),
              _past(30, 365), org_id))
        rbac_count += 1

    def _entra(identity_id, role_name):
        nonlocal entra_count
        db_id = identity_map.get(identity_id)
        if not db_id:
            return
        cur.execute("""
            INSERT INTO entra_role_assignments
                (identity_db_id, role_name, role_definition_id,
                 directory_scope, organization_id)
            VALUES (%s,%s,%s,'/',%s)
        """, (db_id, role_name, _uuid(), org_id))
        entra_count += 1

    # ── Admin users: 5-12 roles each ──────────────────────────────
    admin_roles = ["Contributor", "User Access Administrator",
                   "Key Vault Administrator", "Security Administrator",
                   "Monitoring Contributor", "Network Contributor",
                   "Storage Account Contributor", "SQL Server Contributor"]
    for uname, _ in ADMIN_USERS:
        iid = f"{uname}@{DOMAIN}"
        n_roles = random.randint(5, 12)
        for role in random.sample(admin_roles, min(n_roles, len(admin_roles))):
            _rbac(iid, role, random.randint(0, 1), "subscription")
        # Top 4 admins get Global Admin
        if uname in ("admin_sarah.chen", "admin_marcus.johnson",
                      "admin_priya.patel", "admin_james.rodriguez"):
            _entra(iid, "Global Administrator")
        else:
            _entra(iid, random.choice(["User Administrator",
                                        "Security Administrator",
                                        "Exchange Administrator"]))

    # ── Regular users: 1-3 roles ──────────────────────────────────
    regular_roles = ["Reader", "Storage File Data SMB Share Reader",
                     "Monitoring Reader", "Log Analytics Reader",
                     "Storage Blob Data Reader", "Key Vault Secrets User"]
    for uname, _ in REGULAR_USERS:
        iid = f"{uname}@{DOMAIN}"
        for role in random.sample(regular_roles, random.randint(1, 3)):
            _rbac(iid, role, random.randint(0, 1), "resource_group")

    # ── Ghost users: 2-8 roles STILL ACTIVE ───────────────────────
    ghost_roles = ["Contributor", "Reader", "Key Vault Secrets User",
                   "Storage Blob Data Contributor", "SQL DB Contributor",
                   "Network Contributor", "Monitoring Reader", "Backup Operator"]
    for uname in GHOST_ADMIN:
        iid = f"{uname}@{DOMAIN}"
        for role in random.sample(ghost_roles, random.randint(4, 8)):
            _rbac(iid, role, random.randint(0, 1),
                  random.choice(["subscription", "resource_group"]))
    for uname in GHOST_REGULAR:
        iid = f"{uname}@{DOMAIN}"
        for role in random.sample(ghost_roles[:4], random.randint(2, 4)):
            _rbac(iid, role, random.randint(0, 1), "resource_group")

    # ── System MIs: role assignments ──────────────────────────────
    _rbac("prod-aks-cluster-identity", "Owner", 0, "subscription")
    for rg in random.sample(RGS, 3):
        _rbac("prod-aks-cluster-identity", "Contributor", 0, "resource_group")
    _rbac("prod-keyvault-accessor", "Key Vault Administrator", 0, "resource")
    _rbac("prod-keyvault-accessor", "Storage Blob Data Contributor", 0, "resource_group")
    _rbac("prod-keyvault-accessor", "Cognitive Services Contributor", 0, "resource_group")
    _rbac("prod-sql-server-mi", "SQL Server Contributor", 0, "resource_group")
    _rbac("prod-sql-server-mi", "Storage Account Contributor", 0, "resource_group")
    _rbac("prod-sql-server-mi", "Backup Contributor", 0, "resource_group")
    for mi_name in SYSTEM_MIS:
        if mi_name.startswith("webapp-prod"):
            _rbac(mi_name, "Reader", 0, "resource_group")
        elif mi_name not in ("prod-aks-cluster-identity", "prod-keyvault-accessor",
                              "prod-sql-server-mi"):
            _rbac(mi_name, random.choice(["Reader", "Contributor", "Monitoring Reader"]),
                  random.randint(0, 1), "resource_group")

    # ── User MIs: messy roles ─────────────────────────────────────
    for mi_name in USER_MIS:
        n = random.randint(1, 10)
        for _ in range(n):
            _rbac(mi_name,
                  random.choice(["Reader", "Contributor", "Owner",
                                 "Storage Blob Data Reader", "Key Vault Secrets User"]),
                  random.randint(0, 1),
                  random.choice(["subscription", "resource_group", "resource_group"]))

    # ── Overpermissive SPNs: explosive roles ──────────────────────
    for i, sp_name in enumerate(OVERPERM_SPNS):
        if i < 5:
            _rbac(sp_name, "Owner", 0, "subscription")
            _rbac(sp_name, "Contributor", 1, "subscription")
        elif i < 13:
            _rbac(sp_name, "Contributor", 0, "subscription")
            _rbac(sp_name, "User Access Administrator", 0, "subscription")
        else:
            _rbac(sp_name, "Contributor", 0, "resource_group")
            _rbac(sp_name, "Reader", 1, "subscription")

    # ── Owned SPNs: moderate roles ────────────────────────────────
    for sp_name in OWNED_SPNS:
        _rbac(sp_name, random.choice(["Reader", "Contributor"]),
              random.randint(0, 1), "resource_group")

    # ── Orphaned SPNs: mixed roles ────────────────────────────────
    for sp_name in ORPHANED_SPNS:
        for _ in range(random.randint(2, 8)):
            _rbac(sp_name, random.choice(["Contributor", "Reader",
                                           "Key Vault Secrets User",
                                           "Storage Blob Data Contributor"]),
                  random.randint(0, 1), "resource_group")

    # ── AI agent roles ────────────────────────────────────────────
    _rbac("openai-prod-connector-sp", "Cognitive Services OpenAI Contributor", 0, "resource_group")
    _rbac("gpt4-inference-service-sp", "Cognitive Services OpenAI Contributor", 0, "resource_group")
    _rbac("ml-prod-training-identity", "AzureML Data Scientist", 0, "resource_group")
    _rbac("ml-prod-training-identity", "Storage Blob Data Contributor", 0, "resource_group")
    _rbac("ml-inference-cluster-mi", "AzureML Data Scientist", 0, "resource_group")
    _rbac("ai-studio-prod-identity", "Azure AI Developer", 0, "resource_group")
    _rbac("ai-studio-prod-identity", "Cognitive Services Contributor", 0, "resource_group")
    _rbac("ai-search-service-mi", "Cognitive Services Contributor", 0, "resource_group")

    conn.commit()
    cur.close()
    logger.info("Seeded %d RBAC + %d Entra role assignments.", rbac_count, entra_count)


# ═══════════════════════════════════════════════════════════════════
#  PART 7 — AI AGENT CLASSIFICATIONS
# ═══════════════════════════════════════════════════════════════════

def seed_agent_classifications(conn, identity_map, run_id, org_id):
    cur = conn.cursor()
    count = 0

    all_agents = {**AI_AGENT_SPNS, **AI_AGENT_SYS_MIS}
    for agent_name, (platform, confidence) in all_agents.items():
        db_id = identity_map.get(agent_name)
        if not db_id:
            continue
        cur.execute("""
            INSERT INTO agent_classifications
                (identity_db_id, identity_id, agent_identity_type,
                 classification_confidence, classification_reason,
                 detected_platform, pattern_version,
                 discovery_run_id, organization_id, classified_at)
            VALUES (%s,%s,'ai_agent',%s,%s,%s,'v2.0',%s,%s,NOW())
            ON CONFLICT DO NOTHING
        """, (db_id, agent_name, confidence,
              f"Detected as {platform} agent via pattern matching",
              platform, run_id, org_id))
        count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d agent classifications.", count)


# ═══════════════════════════════════════════════════════════════════
#  PART 8 — SECURITY FINDINGS
# ═══════════════════════════════════════════════════════════════════

def seed_security_findings(conn, org_id, run_id, identity_map):
    cur = conn.cursor()
    count = 0

    def _finding(entity_id, ftype, sev, score, title, desc):
        nonlocal count
        if entity_id not in identity_map:
            return
        fp = _fingerprint(entity_id, ftype)
        cur.execute("""
            INSERT INTO security_findings
                (organization_id, entity_type, entity_id, finding_type, severity,
                 risk_score, title, description, recommended_fix,
                 discovery_run_id, metadata, finding_fingerprint,
                 status, first_detected_at, last_detected_at)
            VALUES (%s,'identity',%s,%s,%s,%s,%s,%s,%s,%s,'{}',%s,'open',NOW(),NOW())
            ON CONFLICT DO NOTHING
        """, (org_id, entity_id, ftype, sev, score, title, desc,
              f"Remediate: {title}", run_id, fp))
        count += 1

    # Critical: subscription owners (5 overpermissive SPNs)
    for sp in OVERPERM_SPNS[:5]:
        _finding(sp, "subscription_owner", "critical", 95,
                 f"Subscription Owner: {sp}",
                 f"{sp} has Owner role at subscription scope, granting full control.")

    # Critical: ghost identities with active roles
    for g in (GHOST_ADMIN[:5] + GHOST_REGULAR[:5]):
        iid = f"{g}@{DOMAIN}"
        _finding(iid, "ghost_identity_with_active_roles", "critical", 90,
                 f"Disabled account retains roles: {g}",
                 f"Account {g} is disabled but still has active RBAC assignments.")

    # Critical: active creds on unowned SPNs
    for sp in ORPHANED_SPNS[:5]:
        _finding(sp, "active_credentials_unowned_spn", "critical", 92,
                 f"Active credentials on orphaned SPN: {sp}",
                 f"Orphaned SPN {sp} has valid credentials with no owner.")

    # High: overly broad RBAC
    for sp in OVERPERM_SPNS[5:]:
        _finding(sp, "overly_broad_rbac", "high", 78,
                 f"Overly broad RBAC: {sp}",
                 f"{sp} has broad subscription-level access beyond minimum required.")

    # High: dormant privileged
    for u, _ in ADMIN_USERS[10:]:
        iid = f"{u}@{DOMAIN}"
        _finding(iid, "dormant_privileged_identity", "high", 75,
                 f"Dormant privileged identity: {u}",
                 f"Privileged identity {u} has not signed in recently but retains elevated roles.")

    # High: orphaned SPNs
    for sp in ORPHANED_SPNS[:10]:
        _finding(sp, "orphaned_service_principal", "high", 70,
                 f"Orphaned service principal: {sp}",
                 f"SPN {sp} has no owner and may be abandoned.")

    # Medium: stale credentials
    for sp in ORPHANED_SPNS[10:20]:
        _finding(sp, "stale_credentials", "medium", 55,
                 f"Stale credentials: {sp}",
                 f"SPN {sp} has credentials that have not been rotated.")

    # Medium: excessive API permissions
    for sp in OVERPERM_SPNS[:8]:
        _finding(sp, "excessive_api_permissions", "medium", 60,
                 f"Excessive API permissions: {sp}",
                 f"{sp} has broad Microsoft Graph API permissions beyond minimum required.")

    # Medium: unowned managed identities
    for mi in SYSTEM_MIS[:20]:
        _finding(mi, "unowned_managed_identity", "medium", 50,
                 f"Unowned managed identity: {mi}",
                 f"Managed identity {mi} has no assigned owner for governance tracking.")

    conn.commit()
    cur.close()
    logger.info("Seeded %d security findings.", count)


# ═══════════════════════════════════════════════════════════════════
#  PART 9 — ATTACK PATHS
# ═══════════════════════════════════════════════════════════════════

def seed_attack_paths(conn, org_id, run_id, identity_map):
    cur = conn.cursor()
    count = 0

    def _path(source, ptype, score, sev, desc, narrative, impact, nodes, resources):
        nonlocal count
        if source not in identity_map:
            return
        fp = _fingerprint(source, ptype, desc[:40])
        cur.execute("""
            INSERT INTO attack_paths
                (organization_id, discovery_run_id, source_entity_id,
                 source_entity_name, source_entity_type, path_type,
                 risk_score, severity, path_nodes, description,
                 narrative, impact, path_fingerprint,
                 affected_resource_count,
                 first_detected_at, last_detected_at, last_seen_run_id)
            VALUES (%s,%s,%s,%s,'identity',%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    NOW(),NOW(),%s)
            ON CONFLICT DO NOTHING
        """, (org_id, run_id, source, nodes[0]["label"] if nodes else source,
              ptype, score, sev, json.dumps(nodes), desc, narrative, impact,
              fp, resources, run_id))
        count += 1

    # Pattern 1: Subscription Owner paths (~100 paths via 5 SPNs × 20 paths)
    for sp in OVERPERM_SPNS[:5]:
        sp_label = sp.replace("-", " ").title()
        for rg in RGS:
            for resource_type in ["Storage", "KeyVault"]:
                for sub_idx in range(len(SUBS)):
                    sub_scope, sub_name = SUBS[sub_idx]
                    _path(sp, "direct_escalation", 95, "critical",
                          f"{sp} owns {sub_name} — full control of all resources",
                          f"{sp} has Owner role on {sub_name}. Can modify/delete all resources "
                          f"including {rg}/{resource_type}.",
                          f"Full subscription takeover via {sp}",
                          [{"id": sp, "type": "identity", "label": sp_label},
                           {"id": "owner-role", "type": "role", "label": "Owner"},
                           {"id": sub_scope, "type": "subscription", "label": sub_name},
                           {"id": f"{rg}/{resource_type}", "type": "resource", "label": f"{rg}/{resource_type}"}],
                          random.randint(20, 50))

    # Pattern 2: Lateral movement via admin accounts (50 paths)
    for uname, dname in ADMIN_USERS[:10]:
        iid = f"{uname}@{DOMAIN}"
        for rg in random.sample(RGS, min(5, len(RGS))):
            _path(iid, "lateral_movement", 82, "high",
                  f"{dname} can pivot via {rg} to Key Vault secrets",
                  f"{uname} has Contributor on {rg}, enabling access to secrets "
                  f"that could be used for lateral movement to other subscriptions.",
                  f"Lateral movement via {dname}'s broad access",
                  [{"id": iid, "type": "identity", "label": dname},
                   {"id": "contributor", "type": "role", "label": "Contributor"},
                   {"id": rg, "type": "resource_group", "label": rg},
                   {"id": f"kv-{rg}", "type": "resource", "label": f"Key Vault in {rg}"}],
                  random.randint(10, 25))

    # Pattern 3: AI agent blast radius (10-20 paths)
    for agent_name in list(AI_AGENT_SPNS.keys()) + list(AI_AGENT_SYS_MIS.keys()):
        platform = AI_AGENT_SPNS.get(agent_name, AI_AGENT_SYS_MIS.get(agent_name, ("unknown", 0)))[0]
        _path(agent_name, "lateral_movement", 72, "high",
              f"AI agent {agent_name} can access model endpoints",
              f"{agent_name} ({platform}) has Cognitive Services Contributor, "
              f"enabling access to AI model endpoints and training data.",
              f"AI model access via {agent_name}",
              [{"id": agent_name, "type": "identity", "label": agent_name},
               {"id": "cs-contrib", "type": "role", "label": "Cognitive Services Contributor"},
               {"id": "ai-resource", "type": "resource", "label": f"{platform} endpoint"}],
              random.randint(5, 15))

    conn.commit()
    cur.close()
    logger.info("Seeded %d attack paths.", count)


# ═══════════════════════════════════════════════════════════════════
#  PART 10 — DRIFT HISTORY
# ═══════════════════════════════════════════════════════════════════

def seed_drift_reports(conn, org_id, run_id):
    cur = conn.cursor()

    # We need a "previous" run for drift comparison.
    # Use status='baseline' so _latest_run_ids() ignores these
    # (it only picks 'completed' or 'partial' runs).
    cur.execute("""
        INSERT INTO discovery_runs
            (subscription_id, subscription_name, started_at, completed_at,
             status, total_identities, critical_count, high_count,
             medium_count, low_count, organization_id, cloud_connection_id)
        VALUES ('sub-demo-prod-0001', 'AuditDemo-Production',
                %s, %s, 'baseline', 275, 22, 50, 118, 85, %s,
                (SELECT id FROM cloud_connections WHERE organization_id = %s LIMIT 1))
        RETURNING id
    """, (RUN_START - timedelta(days=2), RUN_END - timedelta(days=2), org_id, org_id))
    prev_run_id = cur.fetchone()[0]

    # Drift report 1: 2 days ago
    changes_1 = {
        "new_identities": [
            {"identity_id": "new-service-sp-01", "display_name": "New Service SP",
             "category": "service_principal", "risk_level": "medium"},
            {"identity_id": "new-user-01@auditgraph-demo.com", "display_name": "New User",
             "category": "human_user", "risk_level": "low"},
            {"identity_id": "new-mi-01", "display_name": "New MI",
             "category": "managed_identity_system", "risk_level": "low"},
        ],
        "removed_identities": [],
        "permission_changes": [
            {"identity_id": "prod-aks-cluster-identity",
             "change": "Added Owner on AuditDemo-Production",
             "severity": "critical"},
        ],
        "risk_changes": [
            {"identity_id": "prod-aks-cluster-identity",
             "previous_risk": "medium", "current_risk": "critical",
             "previous_score": 450, "current_score": 850},
            {"identity_id": "terraform-automation-sp",
             "previous_risk": "high", "current_risk": "critical",
             "previous_score": 650, "current_score": 880},
        ],
        "credential_changes": [],
    }
    events_1 = [
        {"event_type": "role_assigned", "identity_id": "prod-aks-cluster-identity",
         "identity_name": "prod-aks-cluster-identity", "severity": "critical",
         "detail": "Added Owner on AuditDemo-Production", "role_name": "Owner",
         "scope": "AuditDemo-Production"},
        {"event_type": "risk_escalated", "identity_id": "prod-aks-cluster-identity",
         "identity_name": "prod-aks-cluster-identity", "severity": "critical",
         "detail": "Risk level escalated from medium to critical (450 → 850)",
         "previous_risk": "medium", "current_risk": "critical"},
        {"event_type": "risk_escalated", "identity_id": "terraform-automation-sp",
         "identity_name": "Terraform Automation SP", "severity": "high",
         "detail": "Risk level escalated from high to critical (650 → 880)",
         "previous_risk": "high", "current_risk": "critical"},
        {"event_type": "identity_added", "identity_id": "new-service-sp-01",
         "identity_name": "New Service SP", "severity": "medium",
         "detail": "New service_principal discovered", "category": "service_principal"},
        {"event_type": "identity_added", "identity_id": "new-user-01@auditgraph-demo.com",
         "identity_name": "New User", "severity": "low",
         "detail": "New human_user discovered", "category": "human_user"},
        {"event_type": "identity_added", "identity_id": "new-mi-01",
         "identity_name": "New MI", "severity": "low",
         "detail": "New managed_identity_system discovered", "category": "managed_identity_system"},
    ]
    cur.execute("""
        INSERT INTO drift_reports
            (current_run_id, previous_run_id, new_identities_count,
             removed_identities_count, permission_changes_count,
             risk_changes_count, credential_changes_count,
             total_changes, changes, events, max_severity,
             privilege_escalation_count, organization_id, created_at)
        VALUES (%s, %s, 3, 0, 1, 2, 0, 6, %s, %s, 'critical', 2, %s, %s)
    """, (run_id, prev_run_id, json.dumps(changes_1), json.dumps(events_1),
          org_id, NOW - timedelta(days=2)))

    # Previous previous run for drift report 2 (baseline status)
    cur.execute("""
        INSERT INTO discovery_runs
            (subscription_id, subscription_name, started_at, completed_at,
             status, total_identities, critical_count, high_count,
             medium_count, low_count, organization_id, cloud_connection_id)
        VALUES ('sub-demo-prod-0001', 'AuditDemo-Production',
                %s, %s, 'baseline', 280, 20, 48, 115, 97, %s,
                (SELECT id FROM cloud_connections WHERE organization_id = %s LIMIT 1))
        RETURNING id
    """, (RUN_START - timedelta(days=9), RUN_END - timedelta(days=9), org_id, org_id))
    prev_prev_run_id = cur.fetchone()[0]

    changes_2 = {
        "new_identities": [],
        "removed_identities": [
            {"identity_id": f"{g}@{DOMAIN}", "display_name": g.replace(".", " ").title(),
             "category": "human_user"}
            for g in GHOST_REGULAR[:5]
        ],
        "permission_changes": [],
        "risk_changes": [],
        "credential_changes": [
            {"identity_id": sp, "change": "Credential rotated",
             "severity": "low"}
            for sp in OWNED_SPNS[:10]
        ],
    }
    events_2 = [
        {"event_type": "identity_removed", "identity_id": f"{g}@{DOMAIN}",
         "identity_name": g.replace(".", " ").title(), "severity": "medium",
         "detail": "Identity removed from directory"}
        for g in GHOST_REGULAR[:5]
    ] + [
        {"event_type": "spn_credential_added", "identity_id": sp,
         "identity_name": sp.replace("-", " ").title(), "severity": "low",
         "detail": "Credential rotated"}
        for sp in OWNED_SPNS[:10]
    ]
    cur.execute("""
        INSERT INTO drift_reports
            (current_run_id, previous_run_id, new_identities_count,
             removed_identities_count, permission_changes_count,
             risk_changes_count, credential_changes_count,
             total_changes, changes, events, max_severity,
             privilege_escalation_count, organization_id, created_at)
        VALUES (%s, %s, 0, 5, 0, 0, 10, 15, %s, %s, 'medium', 0, %s, %s)
    """, (prev_run_id, prev_prev_run_id, json.dumps(changes_2), json.dumps(events_2),
          org_id, NOW - timedelta(days=7)))

    conn.commit()
    cur.close()
    logger.info("Seeded 2 drift reports.")


# ═══════════════════════════════════════════════════════════════════
#  PART 10b — GENERATED REMEDIATIONS (CISO Priority Actions)
# ═══════════════════════════════════════════════════════════════════

def seed_generated_remediations(conn, org_id, run_id, identity_map):
    """Seed generated_remediations for the CISO Priority Actions panel.

    Creates per-identity rows for 3 action types:
      1. reduce_privilege — SPNs with Owner at subscription scope
      2. disable_identity — ghost/disabled users still holding roles
      3. remove_identity — unowned SPNs
    """
    cur = conn.cursor()
    count = 0

    # 1. reduce_privilege: SPNs with Owner at sub scope
    cur.execute("""
        SELECT i.id, i.identity_id, i.display_name, ra.role_name, ra.scope
        FROM identities i
        JOIN role_assignments ra ON ra.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND ra.role_name = 'Owner'
          AND ra.scope ~ '^/subscriptions/[^/]+$'
    """, (run_id,))
    for r in cur.fetchall():
        cur.execute("""
            INSERT INTO generated_remediations (
                organization_id, discovery_run_id, identity_db_id, identity_id,
                identity_name, condition_key, title, description, action_type,
                priority, risk_reduction, blast_radius, automation_ready,
                confidence, status, role_name, scope
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (organization_id, discovery_run_id, identity_id, condition_key) DO NOTHING
        """, (org_id, run_id, r[0], r[1], r[2],
              'privilege_drift_reduce_privilege',
              'Downgrade Excessive Privileges',
              f'{r[2]} holds {r[3]} at subscription scope. Reduce to least-privilege role.',
              'reduce_privilege', 'critical', 90, 'high', True, 92, 'new', r[3], r[4]))
        count += 1

    # 2. disable_identity: ghost users still holding roles
    cur.execute("""
        SELECT i.id, i.identity_id, i.display_name,
               (SELECT ra.role_name FROM role_assignments ra WHERE ra.identity_db_id = i.id LIMIT 1),
               (SELECT ra.scope FROM role_assignments ra WHERE ra.identity_db_id = i.id LIMIT 1)
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.enabled = false
          AND EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
    """, (run_id,))
    for r in cur.fetchall():
        cur.execute("""
            INSERT INTO generated_remediations (
                organization_id, discovery_run_id, identity_db_id, identity_id,
                identity_name, condition_key, title, description, action_type,
                priority, risk_reduction, blast_radius, automation_ready,
                confidence, status, role_name, scope
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (organization_id, discovery_run_id, identity_id, condition_key) DO NOTHING
        """, (org_id, run_id, r[0], r[1], r[2],
              'ghost_identity_disable_identity',
              'Revoke Ghost Identity Access',
              f'{r[2]} \u2014 disabled account still holds Azure roles. Revoke access immediately.',
              'disable_identity', 'high', 70, 'medium', True, 88, 'new', r[3], r[4]))
        count += 1

    # 3. remove_identity: unowned SPNs
    cur.execute("""
        SELECT i.id, i.identity_id, i.display_name,
               (SELECT ra.role_name FROM role_assignments ra WHERE ra.identity_db_id = i.id LIMIT 1),
               (SELECT ra.scope FROM role_assignments ra WHERE ra.identity_db_id = i.id LIMIT 1)
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND COALESCE(i.owner_count, 0) = 0
          AND COALESCE(i.is_microsoft_system, false) = false
        LIMIT 25
    """, (run_id,))
    for r in cur.fetchall():
        cur.execute("""
            INSERT INTO generated_remediations (
                organization_id, discovery_run_id, identity_db_id, identity_id,
                identity_name, condition_key, title, description, action_type,
                priority, risk_reduction, blast_radius, automation_ready,
                confidence, status, role_name, scope
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (organization_id, discovery_run_id, identity_id, condition_key) DO NOTHING
        """, (org_id, run_id, r[0], r[1], r[2],
              'identity_exposures_remove_identity',
              'Remove Orphaned Service Principal',
              f'{r[2]} \u2014 ownerless SPN. No assigned owner creates accountability gap.',
              'remove_identity', 'high', 65, 'medium', True, 85, 'new', r[3], r[4]))
        count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d generated remediation items.", count)


# ═══════════════════════════════════════════════════════════════════
#  PART 11 — LINEAGE VERDICTS
# ═══════════════════════════════════════════════════════════════════

def seed_lineage_verdicts(conn, identity_map, run_id, org_id):
    cur = conn.cursor()
    count = 0

    # NHI verdicts distribution
    nhi_ids = (list(SYSTEM_MIS) + list(USER_MIS) +
               list(OWNED_SPNS) + list(ORPHANED_SPNS) + list(OVERPERM_SPNS))
    verdicts = (["ORPHANED"] * 30 + ["AT_RISK"] * 20 + ["STALE"] * 15 +
                ["UNUSED"] * 10 + ["NEEDS_REVIEW"] * 15 + ["HEALTHY"] * 10)
    random.shuffle(verdicts)

    for i, nhi_name in enumerate(nhi_ids):
        db_id = identity_map.get(nhi_name)
        if not db_id:
            continue
        verdict = verdicts[i % len(verdicts)]
        # Override for specific types
        if nhi_name in ORPHANED_SPNS:
            verdict = "ORPHANED"
        elif nhi_name in OVERPERM_SPNS[:5]:
            verdict = "AT_RISK"

        cur.execute("""
            INSERT INTO lineage_verdicts
                (discovery_run_id, organization_id, identity_id,
                 verdict, confidence_score, verdict_source, scored_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT DO NOTHING
        """, (run_id, org_id, db_id, verdict,
              round(random.uniform(0.7, 1.0), 2),
              random.choice(["Role Pattern", "Inferred from roles", "Verified Origin"])))
        count += 1

    # Ghost users get GHOST_MSI verdict
    for g in GHOST_ADMIN + GHOST_REGULAR:
        iid = f"{g}@{DOMAIN}"
        db_id = identity_map.get(iid)
        if not db_id:
            continue
        cur.execute("""
            INSERT INTO lineage_verdicts
                (discovery_run_id, organization_id, identity_id,
                 verdict, confidence_score, verdict_source, scored_at)
            VALUES (%s, %s, %s, 'GHOST_MSI', 0.95, 'Lineage Engine', NOW())
            ON CONFLICT DO NOTHING
        """, (run_id, org_id, db_id))
        count += 1

    # Human users: HEALTHY or STALE
    for uname, _ in ADMIN_USERS:
        iid = f"{uname}@{DOMAIN}"
        db_id = identity_map.get(iid)
        if db_id:
            cur.execute("""
                INSERT INTO lineage_verdicts
                    (discovery_run_id, organization_id, identity_id,
                     verdict, confidence_score, verdict_source, scored_at)
                VALUES (%s, %s, %s, 'NEEDS_REVIEW', 0.85, 'Role Pattern', NOW())
                ON CONFLICT DO NOTHING
            """, (run_id, org_id, db_id))
            count += 1

    for uname, _ in REGULAR_USERS:
        iid = f"{uname}@{DOMAIN}"
        db_id = identity_map.get(iid)
        if db_id:
            verdict = random.choice(["HEALTHY", "HEALTHY", "STALE"])
            cur.execute("""
                INSERT INTO lineage_verdicts
                    (discovery_run_id, organization_id, identity_id,
                     verdict, confidence_score, verdict_source, scored_at)
                VALUES (%s, %s, %s, %s, %s, 'Verified Origin', NOW())
                ON CONFLICT DO NOTHING
            """, (run_id, org_id, db_id, verdict, round(random.uniform(0.75, 1.0), 2)))
            count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d lineage verdicts.", count)


# ═══════════════════════════════════════════════════════════════════
#  PART 12 — SP OWNERSHIP
# ═══════════════════════════════════════════════════════════════════

def seed_sp_ownership(conn, identity_map, org_id):
    cur = conn.cursor()
    count = 0
    own_id = 1

    # Owned SPNs get owners from admin users
    for i, sp_name in enumerate(OWNED_SPNS):
        db_id = identity_map.get(sp_name)
        if not db_id:
            continue
        owner_uname, owner_dname = ADMIN_USERS[i % len(ADMIN_USERS)]
        cur.execute("""
            INSERT INTO sp_ownership
                (id, identity_db_id, owner_object_id, owner_display_name,
                 owner_upn, owner_type, ownership_type, is_primary_owner,
                 discovered_at)
            VALUES (%s, %s, %s, %s, %s, 'user', 'application', true, NOW())
            ON CONFLICT DO NOTHING
        """, (own_id, db_id, _uuid(), owner_dname, f"{owner_uname}@{DOMAIN}"))
        count += 1
        own_id += 1

    # Some overpermissive SPNs have owners too (first 10)
    for i, sp_name in enumerate(OVERPERM_SPNS[:10]):
        if sp_name in AI_AGENT_SPNS:
            continue
        db_id = identity_map.get(sp_name)
        if not db_id:
            continue
        owner_uname, owner_dname = ADMIN_USERS[(i + 5) % len(ADMIN_USERS)]
        cur.execute("""
            INSERT INTO sp_ownership
                (id, identity_db_id, owner_object_id, owner_display_name,
                 owner_upn, owner_type, ownership_type, is_primary_owner,
                 discovered_at)
            VALUES (%s, %s, %s, %s, %s, 'user', 'application', true, NOW())
            ON CONFLICT DO NOTHING
        """, (own_id, db_id, _uuid(), owner_dname, f"{owner_uname}@{DOMAIN}"))
        count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d sp_ownership records.", count)


# ═══════════════════════════════════════════════════════════════════
#  GRAPH API PERMISSIONS (for overpermissive SPNs)
# ═══════════════════════════════════════════════════════════════════

def seed_graph_api_permissions(conn, identity_map):
    cur = conn.cursor()
    count = 0
    perm_id = 1

    perms = {
        "User.ReadWrite.All": ("Read and write all users' full profiles", "high"),
        "Directory.ReadWrite.All": ("Read and write directory data", "critical"),
        "Application.ReadWrite.All": ("Read and write all apps", "critical"),
        "Group.ReadWrite.All": ("Read and write all groups", "high"),
        "Mail.ReadWrite": ("Read and write user mail", "medium"),
        "Files.ReadWrite.All": ("Read and write all files", "high"),
        "Sites.ReadWrite.All": ("Read and write all site collections", "high"),
        "RoleManagement.ReadWrite.Directory": ("Read and write role management", "critical"),
    }

    for i, sp_name in enumerate(OVERPERM_SPNS[:8]):
        db_id = identity_map.get(sp_name)
        if not db_id:
            continue
        # Each SPN gets 2-5 random permissions
        for perm_name, (desc, risk) in random.sample(list(perms.items()),
                                                      random.randint(2, 5)):
            cur.execute("""
                INSERT INTO graph_api_permissions
                    (id, identity_db_id, permission_name, permission_description,
                     resource_name, risk_level, discovered_at)
                VALUES (%s, %s, %s, %s, 'Microsoft Graph', %s, NOW())
                ON CONFLICT DO NOTHING
            """, (perm_id, db_id, perm_name, desc, risk))
            perm_id += 1
            count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d graph API permissions.", count)


# ═══════════════════════════════════════════════════════════════════
#  BLAST RADIUS
# ═══════════════════════════════════════════════════════════════════

def seed_blast_radius(conn, org_id, run_id, identity_map):
    cur = conn.cursor()
    count = 0

    blast_defs = [
        ("terraform-automation-sp", 213, 2, 5, 5, 92, "CRITICAL"),
        ("devops-pipeline-sp", 184, 2, 4, 3, 88, "CRITICAL"),
        ("databricks-connector-sp", 98, 1, 3, 2, 78, "HIGH"),
        ("prod-aks-cluster-identity", 213, 2, 5, 4, 95, "CRITICAL"),
        ("prod-keyvault-accessor", 65, 1, 2, 3, 82, "CRITICAL"),
    ]
    # Add top admin users
    for uname, dname in ADMIN_USERS[:4]:
        blast_defs.append((f"{uname}@{DOMAIN}", 300, 2, 8, 0, 85, "CRITICAL"))

    for (iid, reach, subs, rgs, sens, score, level) in blast_defs:
        db_id = identity_map.get(iid)
        if not db_id:
            continue
        cat = "service_principal"
        if "@" in iid:
            cat = "human_user"
        elif "identity" in iid or "-mi" in iid:
            cat = "managed_identity_system"
        cur.execute("""
            INSERT INTO blast_radius_results
                (organization_id, identity_id, identity_name, identity_type,
                 discovery_run_id, reachable_resource_count,
                 reachable_subscription_count, reachable_resource_group_count,
                 sensitive_resource_count, sensitive_data_types,
                 resource_breakdown, privilege_escalation_paths,
                 risk_domain, identity_exposure_level, risk_score)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'identity',%s,%s)
            ON CONFLICT DO NOTHING
        """, (org_id, db_id, iid, cat, run_id,
              reach, subs, rgs, sens,
              json.dumps(["PII", "PHI", "Financial"] if sens > 0 else []),
              json.dumps({"storage": random.randint(5, 20),
                          "keyvault": random.randint(2, 10),
                          "compute": random.randint(10, 45)}),
              random.randint(0, 3), level, score))
        count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d blast radius results.", count)


# ═══════════════════════════════════════════════════════════════════
#  TENANT HEALTH
# ═══════════════════════════════════════════════════════════════════

def seed_tenant_health(conn, org_id, run_id):
    cur = conn.cursor()
    # Delete existing then insert (no unique constraint on organization_id)
    cur.execute("DELETE FROM tenant_health WHERE organization_id = %s", (org_id,))
    cur.execute("""
        INSERT INTO tenant_health
            (organization_id, last_discovery_run, snapshot_age_hours,
             findings_count, critical_risks, blast_radius_critical,
             integrity_warning, status, updated_at)
        VALUES (%s, %s, 1, 85, 25, 5, false, 'healthy', NOW())
    """, (org_id, RUN_END))
    conn.commit()
    cur.close()
    logger.info("Seeded tenant_health.")


# ═══════════════════════════════════════════════════════════════════
#  FIX RECOMMENDATIONS (REMEDIATION)
# ═══════════════════════════════════════════════════════════════════

def seed_fix_recommendations(conn, org_id, run_id, identity_map):
    cur = conn.cursor()
    count = 0

    recs = []

    # Critical: downgrade subscription owners (6)
    for sp in OVERPERM_SPNS[:5]:
        recs.append({
            "entity": sp, "type": "narrow_scope",
            "title": f"Downgrade subscription Owner: {sp}",
            "desc": f"{sp} has Owner at subscription scope. Reduce to minimum required role.",
            "category": "access_control", "priority": 95, "effort": "medium",
            "steps": ["Audit current resource usage", "Create custom role",
                      "Replace Owner with scoped role", "Verify application functionality"],
            "cli": f"az role assignment delete --assignee {sp} --role Owner",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["AC-6"]},
        })
    recs.append({
        "entity": "prod-aks-cluster-identity", "type": "narrow_scope",
        "title": "Remove subscription Owner from AKS cluster MI",
        "desc": "prod-aks-cluster-identity has Owner at subscription scope.",
        "category": "access_control", "priority": 95, "effort": "high",
        "steps": ["Review AKS required permissions", "Create minimal custom role",
                  "Test cluster operations", "Remove Owner assignment"],
        "cli": "az role assignment delete --assignee prod-aks-cluster-identity --role Owner",
        "compliance": {"SOC2": ["CC6.1"], "NIST": ["AC-6"]},
    })

    # High: revoke ghost user access (10) + remove orphaned SPNs (15)
    for g in (GHOST_ADMIN[:5] + GHOST_REGULAR[:5]):
        iid = f"{g}@{DOMAIN}"
        recs.append({
            "entity": iid, "type": "remove_role",
            "title": f"Revoke all roles from disabled account: {g}",
            "desc": f"Disabled account {g} retains active RBAC assignments.",
            "category": "access_control", "priority": 80, "effort": "low",
            "steps": ["Verify account is disabled", "Remove all RBAC assignments",
                      "Log remediation action", "Update offboarding checklist"],
            "cli": f"az role assignment list --assignee {iid} --query '[].id' -o tsv | xargs -I{{}} az role assignment delete --ids {{}}",
            "compliance": {"SOC2": ["CC6.2"], "NIST": ["AC-2(3)"]},
        })

    for sp in ORPHANED_SPNS[:15]:
        recs.append({
            "entity": sp, "type": "remove_role",
            "title": f"Remove orphaned SPN: {sp}",
            "desc": f"SPN {sp} has no owner and appears abandoned.",
            "category": "access_control", "priority": 75, "effort": "medium",
            "steps": ["Verify SPN is not in use", "Disable SPN first",
                      "Wait 14 days for complaints", "Delete SPN"],
            "cli": f"az ad sp delete --id {sp}",
            "compliance": {"SOC2": ["CC6.1"]},
        })

    # Medium: assign owners (20) + rotate creds (10) + reduce API perms (10)
    for mi in SYSTEM_MIS[:20]:
        recs.append({
            "entity": mi, "type": "assign_owner",
            "title": f"Assign owner to {mi}",
            "desc": f"Managed identity {mi} has no assigned owner.",
            "category": "governance", "priority": 60, "effort": "low",
            "steps": ["Identify responsible team", "Assign owner in Entra ID",
                      "Document ownership in CMDB"],
            "cli": f"# Manual: Assign owner via Azure Portal or Graph API",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["AC-2"]},
        })

    for sp in OWNED_SPNS[:10]:
        recs.append({
            "entity": sp, "type": "rotate_credential",
            "title": f"Rotate expiring credentials: {sp}",
            "desc": f"SPN {sp} has credentials expiring within 30 days.",
            "category": "credential_hygiene", "priority": 65, "effort": "low",
            "steps": ["Generate new credential", "Update application config",
                      "Verify application connectivity", "Remove old credential"],
            "cli": f"az ad sp credential reset --id {sp}",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["IA-5"]},
        })

    for sp in OVERPERM_SPNS[:10]:
        recs.append({
            "entity": sp, "type": "reduce_permissions",
            "title": f"Reduce excessive API permissions: {sp}",
            "desc": f"{sp} has broad Graph API permissions beyond minimum required.",
            "category": "access_control", "priority": 60, "effort": "medium",
            "steps": ["Audit actual permission usage", "Identify minimum required",
                      "Remove excessive permissions", "Test application"],
            "cli": f"# Review permissions in Azure Portal > App Registrations",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["AC-6"]},
        })

    for r in recs:
        entity = r["entity"]
        if entity not in identity_map and not entity.endswith(f"@{DOMAIN}"):
            continue
        fp = _fingerprint(entity, r["type"])
        cur.execute("""
            INSERT INTO fix_recommendations
                (organization_id, discovery_run_id, entity_id, entity_type,
                 entity_name, fix_type, title, description, fix_category,
                 priority_score, effort, steps, azure_cli_commands,
                 compliance_refs, status, recommendation_fingerprint,
                 first_detected_at, last_detected_at)
            VALUES (%s,%s,%s,'identity',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    'open',%s,NOW(),NOW())
            ON CONFLICT DO NOTHING
        """, (org_id, run_id, entity, entity,
              r["type"], r["title"], r["desc"], r["category"],
              r["priority"], r["effort"],
              json.dumps(r["steps"]), r["cli"],
              json.dumps(r["compliance"]), fp))
        count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d fix recommendations.", count)


# ═══════════════════════════════════════════════════════════════════
#  CLOUD SUBSCRIPTIONS
# ═══════════════════════════════════════════════════════════════════

def seed_cloud_subscriptions(conn, org_id, cc_id):
    """Create monitored cloud subscriptions so _monitored_sub_ids() returns data."""
    cur = conn.cursor()
    for sub_id, sub_name in SUBS:
        account_id = sub_id.replace("/subscriptions/", "")
        cur.execute("""
            INSERT INTO cloud_subscriptions
                (organization_id, cloud_connection_id, account_id, account_name,
                 cloud, monitored, deleted, created_at)
            VALUES (%s, %s, %s, %s, 'azure', true, false, NOW())
            ON CONFLICT DO NOTHING
        """, (org_id, cc_id, account_id, sub_name))
    conn.commit()
    cur.close()
    logger.info("Seeded %d cloud subscriptions.", len(SUBS))


# ═══════════════════════════════════════════════════════════════════
#  ENTRA GROUPS + MEMBERSHIPS
# ═══════════════════════════════════════════════════════════════════

ENTRA_GROUPS = [
    # (display_name, description, security_enabled, mail_enabled, member_count)
    ("sg-prod-subscription-readers", "Production subscription readers", True, False, 45),
    ("sg-prod-key-vault-users", "Key Vault access group", True, False, 20),
    ("sg-devops-contributors", "DevOps team contributors", True, False, 15),
    ("sg-data-team-storage", "Data team storage access", True, False, 25),
    ("sg-admin-team", "Platform admin team", True, False, 10),
    ("sg-all-employees", "All company employees", True, True, 120),
    ("sg-engineering-dept", "Engineering department", True, True, 30),
    ("sg-finance-dept", "Finance department", True, True, 20),
    ("sg-vpn-access", "VPN access group", True, False, 80),
    ("sg-shared-drives", "Shared drives access", True, False, 90),
]


def seed_entra_groups(conn, org_id, run_id, identity_map):
    """Create 10 Entra groups with realistic memberships."""
    cur = conn.cursor()
    group_count = 0
    membership_count = 0

    # Build identity lists by category for membership assignment
    all_human_ids = (
        [f"{u}@{DOMAIN}" for u, _ in ADMIN_USERS] +
        [f"{u}@{DOMAIN}" for u, _ in REGULAR_USERS] +
        [f"{u}@{DOMAIN}" for u in GHOST_ADMIN] +
        [f"{u}@{DOMAIN}" for u in GHOST_REGULAR]
    )
    all_nhi_ids = list(SYSTEM_MIS) + list(USER_MIS) + list(OWNED_SPNS)

    for grp_name, grp_desc, sec_enabled, mail_enabled, member_target in ENTRA_GROUPS:
        group_id = _uuid()
        cur.execute("""
            INSERT INTO entra_groups
                (group_id, display_name, description, mail_enabled,
                 security_enabled, member_count, organization_id,
                 discovery_run_id, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (group_id, grp_name, grp_desc, mail_enabled, sec_enabled,
              member_target, org_id, run_id))
        grp_db_id = cur.fetchone()[0]
        group_count += 1

        # Assign members from identity_map
        if grp_name in ("sg-admin-team",):
            pool = [f"{u}@{DOMAIN}" for u, _ in ADMIN_USERS]
        elif grp_name in ("sg-engineering-dept",):
            pool = [f"{u}@{DOMAIN}" for u in _ENG_NAMES]
        elif grp_name in ("sg-finance-dept",):
            pool = [f"{u}@{DOMAIN}" for u in _FIN_NAMES]
        elif grp_name in ("sg-devops-contributors",):
            pool = all_nhi_ids[:30]
        elif grp_name in ("sg-data-team-storage",):
            pool = [f"{u}@{DOMAIN}" for u in _ENG_NAMES[:15]] + all_nhi_ids[:10]
        elif grp_name in ("sg-prod-key-vault-users",):
            pool = [f"{u}@{DOMAIN}" for u, _ in ADMIN_USERS[:10]] + all_nhi_ids[:10]
        else:
            pool = all_human_ids + all_nhi_ids

        # Sample up to member_target from available pool
        sample_size = min(member_target, len(pool))
        members = random.sample(pool, sample_size)

        for member_iid in members:
            db_id = identity_map.get(member_iid)
            if not db_id:
                continue
            member_type = "user" if "@" in member_iid else "servicePrincipal"
            cur.execute("""
                INSERT INTO entra_group_memberships
                    (group_db_id, member_identity_id, member_type,
                     organization_id, discovery_run_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (grp_db_id, db_id, member_type, org_id, run_id))
            membership_count += 1

    conn.commit()
    cur.close()
    logger.info("Seeded %d entra groups with %d memberships.", group_count, membership_count)


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    logger.info("=" * 65)
    logger.info("  AuditGraph Demo Organization Seeder")
    logger.info("=" * 65)
    logger.info("Target: %s:%s/%s", DB_HOST, DB_PORT, DB_NAME)

    conn = get_conn()
    try:
        # Set RLS bypass (we connect as admin user)
        cur = conn.cursor()

        # Part 1: Org + User + Cloud Connection
        org_id = setup_org(conn)
        cur.execute("SELECT set_config('app.current_organization_id', %s, false)",
                    (str(org_id),))
        conn.commit()

        setup_user(conn, org_id)
        cc_id = setup_cloud_connection(conn, org_id)

        # Cloud Subscriptions (required for _monitored_sub_ids)
        seed_cloud_subscriptions(conn, org_id, cc_id)

        # Part 2: Discovery Run
        run_id = create_discovery_run(conn, org_id, cc_id)

        # Parts 3-7: Identities (280 total)
        identity_map = seed_identities(conn, org_id, run_id)

        # Credentials for SPNs
        seed_credentials(conn, identity_map, run_id)

        # Role assignments (RBAC + Entra)
        seed_role_assignments(conn, identity_map, run_id, org_id)

        # SP Ownership
        seed_sp_ownership(conn, identity_map, org_id)

        # Graph API Permissions
        seed_graph_api_permissions(conn, identity_map)

        # AI Agent Classifications
        seed_agent_classifications(conn, identity_map, run_id, org_id)

        # Security Findings
        seed_security_findings(conn, org_id, run_id, identity_map)

        # Attack Paths
        seed_attack_paths(conn, org_id, run_id, identity_map)

        # Blast Radius
        seed_blast_radius(conn, org_id, run_id, identity_map)

        # Drift Reports
        seed_drift_reports(conn, org_id, run_id)

        # Generated Remediations (CISO Priority Actions)
        seed_generated_remediations(conn, org_id, run_id, identity_map)

        # Lineage Verdicts
        seed_lineage_verdicts(conn, identity_map, run_id, org_id)

        # Fix Recommendations (Remediation)
        seed_fix_recommendations(conn, org_id, run_id, identity_map)

        # Entra Groups + Memberships
        seed_entra_groups(conn, org_id, run_id, identity_map)

        # Tenant Health
        seed_tenant_health(conn, org_id, run_id)

        cur.close()

        # ── Final summary ─────────────────────────────────────────
        logger.info("")
        logger.info("=" * 65)
        logger.info("  SEEDING COMPLETE")
        logger.info("=" * 65)
        logger.info("")
        logger.info("  Organization: AuditGraph Demo (id=%s)", org_id)
        logger.info("  Slug: auditgraph-demo")
        logger.info("  Discovery Run: #%s", run_id)
        logger.info("  Total Identities: %d", len(identity_map))
        logger.info("    Human Users (active):  120")
        logger.info("    Human Users (ghost):   30")
        logger.info("    System MIs:            30")
        logger.info("    User MIs:              40")
        logger.info("    Service Principals:    60")
        logger.info("    AI Agents:             10 (classified)")
        logger.info("")
        logger.info("  Login: demoadmin / changeme")
        logger.info("")

    finally:
        conn.close()


if __name__ == "__main__":
    # AG-105: Production guard — refuse to seed in production environments.
    # Word-boundary 'prod' match so 'nonprod' / 'cus-ag-nonprod-pg' don't
    # trip the guard. The non-prod cloud env is an explicit allow target
    # for the demo-tenant seed endpoint (superadmin-gated, scoped to org=9).
    import re as _re
    _APP_ENV = os.environ.get('APP_ENV', 'production')
    _DB_HOST = os.environ.get('DB_HOST', '')
    _host_prod = bool(_re.search(r'(?<![a-z])prod(?!\w)', _DB_HOST.lower()))
    if _APP_ENV == 'production' or _host_prod:
        print("ERROR: Refusing to run seed script in production.")
        print(f"  APP_ENV={_APP_ENV}")
        print(f"  DB_HOST={_DB_HOST}")
        print("Set APP_ENV=local to run seed scripts.")
        sys.exit(1)
    # Skip interactive confirmation when stdin isn't a TTY (subprocess /
    # CI invocation). External access control already gates this path.
    if sys.stdin.isatty():
        _confirm = input(
            f"Seeding DB at {_DB_HOST} (APP_ENV={_APP_ENV}). "
            "Type 'yes' to continue: "
        )
        if _confirm.strip().lower() != 'yes':
            print("Aborted.")
            sys.exit(0)
    else:
        print(f"Non-interactive run; seeding {_DB_HOST} (APP_ENV={_APP_ENV})")

    main()
