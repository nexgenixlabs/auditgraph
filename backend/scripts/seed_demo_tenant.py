#!/usr/bin/env python3
"""
AuditGraph Demo Tenant Data Seeder

Populates the demo organization with realistic cloud identity security data.
Run from backend/: ./venv/bin/python scripts/seed_demo_tenant.py

Idempotent — deletes existing demo data before re-seeding.
"""

import os
import sys
import json
import uuid
import random
import hashlib
import logging
from datetime import datetime, timedelta, timezone

# Ensure the backend package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from psycopg2.extras import RealDictCursor
from app.database import Database

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
logger = logging.getLogger("demo_seeder")

# ─── Helpers ──────────────────────────────────────────────────────────

NOW = datetime.now(timezone.utc)
RUN_START = NOW - timedelta(hours=2)
RUN_END = NOW - timedelta(hours=1, minutes=45)


def _uuid():
    return str(uuid.uuid4())


def _past(days_min=1, days_max=365):
    return NOW - timedelta(days=random.randint(days_min, days_max))


def _future(days_min=1, days_max=365):
    return NOW + timedelta(days=random.randint(days_min, days_max))


def _risk_level(score):
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ─── Identity Definitions ────────────────────────────────────────────

HUMAN_USERS = [
    ("john.carter@auditgraph.ai", "John Carter", "admin", 92),
    ("sarah.chen@auditgraph.ai", "Sarah Chen", "admin", 85),
    ("mike.johnson@auditgraph.ai", "Mike Johnson", "admin", 78),
    ("emily.davis@auditgraph.ai", "Emily Davis", "security_admin", 55),
    ("david.wilson@auditgraph.ai", "David Wilson", "compliance", 42),
    ("jessica.taylor@auditgraph.ai", "Jessica Taylor", "reader", 25),
    ("robert.brown@auditgraph.ai", "Robert Brown", "admin", 88),
    ("amanda.garcia@auditgraph.ai", "Amanda Garcia", "security_admin", 68),
    ("james.martinez@auditgraph.ai", "James Martinez", "compliance", 35),
    ("linda.anderson@auditgraph.ai", "Linda Anderson", "reader", 15),
    ("chris.thomas@auditgraph.ai", "Chris Thomas", "admin", 72),
    ("patricia.jackson@auditgraph.ai", "Patricia Jackson", "security_admin", 61),
    ("daniel.white@auditgraph.ai", "Daniel White", "admin", 90),
    ("nancy.harris@auditgraph.ai", "Nancy Harris", "compliance", 48),
    ("matthew.clark@auditgraph.ai", "Matthew Clark", "reader", 20),
    ("karen.lewis@auditgraph.ai", "Karen Lewis", "admin", 75),
    ("steven.robinson@auditgraph.ai", "Steven Robinson", "security_admin", 58),
    ("betty.walker@auditgraph.ai", "Betty Walker", "compliance", 30),
    ("paul.hall@auditgraph.ai", "Paul Hall", "reader", 12),
    ("helen.allen@auditgraph.ai", "Helen Allen", "admin", 82),
]

# Generate additional users to reach 120
_FIRST = ["Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Drew", "Blake",
           "Quinn", "Avery", "Parker", "Logan", "Harper", "Emerson", "Rowan",
           "Kai", "Sage", "Finley", "Dakota", "River", "Hayden", "Cameron",
           "Reese", "Skyler", "Jamie", "Peyton", "Alexis", "Kendall", "Spencer",
           "Addison", "Charlie", "Frankie", "Sam", "Robin", "Kit", "Ash",
           "Lee", "Val", "Ari", "Jules", "Nico", "Remy", "Sasha", "Blair",
           "Eden", "Lane", "August", "Phoenix", "Shea", "Indigo", "Payton",
           "Oakley", "Winter", "Briar", "Cypress", "Aiden", "Bellamy", "Cedar",
           "Darcy", "Elliot", "Forrest", "Glenn", "Holly", "Ivory", "Jade",
           "Kira", "Lark", "Marina", "Noel", "Onyx", "Pearl", "Rosa", "Scout",
           "Tatum", "Uma", "Vera", "Willow", "Xena", "Yara", "Zara", "Fern",
           "Haven", "Ivy", "Juniper", "Kestrel", "Laurel", "Maple", "Nova",
           "Olive", "Piper", "Rain", "Sierra", "Terra", "Wren", "Zelda",
           "Aria", "Birch", "Clover", "Dawn"]
_LAST = ["Smith", "Jones", "Williams", "Brown", "Taylor", "Davies", "Wilson",
          "Evans", "Thomas", "Roberts", "Johnson", "Walker", "Wright", "Thompson",
          "White", "Hughes", "Edwards", "Green", "Hall", "Lewis"]

for i in range(100):
    first = _FIRST[i % len(_FIRST)]
    last = _LAST[i % len(_LAST)]
    score = random.randint(5, 70)
    HUMAN_USERS.append((
        f"{first.lower()}.{last.lower()}{i}@auditgraph.ai",
        f"{first} {last}",
        random.choice(["admin", "security_admin", "compliance", "reader"]),
        score,
    ))


SERVICE_PRINCIPALS = [
    ("terraform-sp", "Terraform Automation", 95, True),
    ("ci-cd-service", "CI/CD Pipeline Service", 88, True),
    ("monitoring-sp", "Azure Monitor Service", 45, False),
    ("backup-agent", "Backup Agent Service", 52, False),
    ("key-rotation-sp", "Key Rotation Automation", 72, True),
    ("data-pipeline-sp", "Data Pipeline ETL", 82, True),
    ("aks-cluster-sp", "AKS Cluster Identity", 78, True),
    ("function-app-sp", "Azure Functions Runtime", 55, False),
    ("logic-app-sp", "Logic App Connector", 40, False),
    ("devops-agent", "Azure DevOps Agent", 85, True),
    ("graph-api-reader", "Graph API Reader Service", 68, False),
    ("sql-admin-sp", "SQL Database Admin", 90, True),
    ("cosmos-writer-sp", "Cosmos DB Writer", 65, False),
    ("apim-gateway-sp", "API Management Gateway", 60, False),
    ("app-gateway-sp", "Application Gateway Manager", 58, False),
    ("event-hub-sp", "Event Hub Publisher", 42, False),
    ("service-bus-sp", "Service Bus Consumer", 38, False),
    ("synapse-analytics-sp", "Synapse Analytics Workspace", 75, True),
    ("purview-scanner-sp", "Purview Data Scanner", 50, False),
    ("sentinel-automation-sp", "Sentinel SOAR Automation", 70, True),
    ("dns-manager-sp", "DNS Zone Manager", 48, False),
    ("container-registry-sp", "ACR Pull Service", 35, False),
    ("storage-lifecycle-sp", "Storage Lifecycle Manager", 44, False),
    ("adf-pipeline-sp", "Data Factory Pipeline", 62, False),
    ("mlops-training-sp", "ML Ops Training Pipeline", 58, False),
    ("defender-scanner-sp", "Defender for Cloud Scanner", 32, False),
    ("cost-management-sp", "Cost Management Reporter", 28, False),
    ("identity-governance-sp", "Identity Governance Worker", 55, False),
    ("compliance-audit-sp", "Compliance Audit Reader", 30, False),
    ("network-watcher-sp", "Network Watcher Agent", 25, False),
    ("load-balancer-sp", "Load Balancer Health Probe", 20, False),
    ("redis-cache-sp", "Redis Cache Manager", 45, False),
    ("signalr-sp", "SignalR Service Connection", 38, False),
    ("notification-hub-sp", "Notification Hub Publisher", 22, False),
    ("media-services-sp", "Media Services Encoder", 35, False),
]

MANAGED_IDENTITIES = [
    ("aks-pod-identity", "AKS Pod Managed Identity", "managed_identity_system", 62),
    ("webapp-prod-identity", "Production Web App Identity", "managed_identity_system", 55),
    ("func-app-identity", "Function App System Identity", "managed_identity_system", 40),
    ("vm-monitoring-identity", "VM Monitoring Identity", "managed_identity_system", 35),
    ("container-instance-id", "Container Instance Identity", "managed_identity_system", 30),
    ("logic-app-managed-id", "Logic App Managed Identity", "managed_identity_system", 25),
    ("batch-account-id", "Batch Account Identity", "managed_identity_system", 28),
    ("app-service-staging-id", "App Service Staging Identity", "managed_identity_user", 45),
    ("data-factory-managed-id", "Data Factory Managed Identity", "managed_identity_user", 50),
    ("synapse-managed-id", "Synapse Managed Identity", "managed_identity_user", 58),
    ("ml-workspace-id", "ML Workspace Identity", "managed_identity_user", 42),
    ("stream-analytics-id", "Stream Analytics Identity", "managed_identity_system", 22),
    ("cognitive-services-id", "Cognitive Services Identity", "managed_identity_system", 18),
    ("iot-hub-identity", "IoT Hub Device Identity", "managed_identity_system", 32),
    ("api-management-id", "API Management Managed Identity", "managed_identity_system", 48),
]

GUEST_USERS = [
    ("guest_vendor_acme@ext.com", "Vendor ACME Admin", 85, "Owner"),
    ("guest_auditor_pwc@ext.com", "PwC External Auditor", 45, "Reader"),
    ("guest_consultant_mck@ext.com", "McKinsey Consultant", 72, "Contributor"),
    ("guest_partner_tech@ext.com", "Tech Partner Engineer", 68, "Contributor"),
    ("guest_contractor_dev@ext.com", "External Developer", 78, "Contributor"),
    ("guest_auditor_ey@ext.com", "EY Compliance Auditor", 40, "Reader"),
    ("guest_vendor_cloud@ext.com", "Cloud Vendor Support", 55, "Reader"),
    ("guest_partner_security@ext.com", "Security Partner", 62, "Security Reader"),
    ("guest_consultant_bain@ext.com", "Bain Consultant", 35, "Reader"),
    ("guest_vendor_sap@ext.com", "SAP Integration Admin", 82, "Contributor"),
    ("guest_temp_intern@ext.com", "Temporary Intern", 30, "Reader"),
    ("guest_agency_marketer@ext.com", "Marketing Agency", 25, "Reader"),
    ("guest_legal_counsel@ext.com", "External Legal Counsel", 20, "Reader"),
    ("guest_board_member@ext.com", "Board Member Observer", 15, "Reader"),
    ("guest_pentest_team@ext.com", "Penetration Tester", 90, "Owner"),
    ("guest_mssp_analyst@ext.com", "MSSP SOC Analyst", 50, "Security Reader"),
    ("guest_vendor_oracle@ext.com", "Oracle DBA Consultant", 75, "Contributor"),
    ("guest_freelance_dev@ext.com", "Freelance Developer", 65, "Contributor"),
    ("guest_supplier_api@ext.com", "Supplier API Integration", 42, "Reader"),
    ("guest_insurance_adj@ext.com", "Insurance Adjuster", 18, "Reader"),
    ("guest_analytics_firm@ext.com", "Analytics Firm Partner", 48, "Reader"),
    ("guest_hr_vendor@ext.com", "HR Platform Vendor", 55, "Contributor"),
    ("guest_it_staffing@ext.com", "IT Staffing Agency", 38, "Reader"),
    ("guest_cloud_architect@ext.com", "Cloud Architect Consultant", 70, "Contributor"),
    ("guest_data_engineer@ext.com", "Freelance Data Engineer", 60, "Contributor"),
    ("guest_qa_contractor@ext.com", "QA Contractor", 32, "Reader"),
    ("guest_devrel_partner@ext.com", "DevRel Partner", 28, "Reader"),
    ("guest_infra_vendor@ext.com", "Infrastructure Vendor", 45, "Reader"),
    ("guest_bizdev_partner@ext.com", "BizDev Partner Contact", 22, "Reader"),
    ("guest_design_agency@ext.com", "Design Agency", 15, "Reader"),
]

# ─── Resource Definitions ────────────────────────────────────────────

STORAGE_ACCOUNTS = [
    ("prodcoredata", "Production Core Data", "eastus", True, False, 92, "critical"),
    ("devtestblobs", "Dev Test Blobs", "eastus", True, True, 78, "high"),
    ("logsarchive", "Log Archive Storage", "westus2", False, False, 35, "medium"),
    ("backupvault01", "Backup Vault Primary", "eastus", False, False, 25, "low"),
    ("mediaassets", "Media Asset Storage", "centralus", True, False, 65, "high"),
    ("datalakeprod", "Production Data Lake", "eastus2", False, False, 45, "medium"),
    ("publicwebcontent", "Public Website Content", "westus", True, True, 88, "critical"),
    ("tempprocessing", "Temporary Processing", "eastus", True, False, 52, "medium"),
    ("compliancelogs", "Compliance Audit Logs", "eastus", False, False, 30, "low"),
    ("mltrainingdata", "ML Training Data", "southcentralus", False, False, 40, "medium"),
    ("stagingartifacts", "Staging Artifacts", "eastus", True, False, 55, "medium"),
    ("customerexports", "Customer Data Exports", "eastus", False, False, 48, "medium"),
    ("cdnorigin", "CDN Origin Storage", "westus2", True, True, 72, "high"),
    ("etlstagingzone", "ETL Staging Zone", "eastus2", False, False, 38, "medium"),
    ("diagnosticdata", "Diagnostic Telemetry", "centralus", False, False, 22, "low"),
    ("funkystorage01", "Function App Storage", "eastus", False, False, 18, "low"),
    ("blobarchive2024", "2024 Archive Blobs", "westus", False, False, 12, "low"),
    ("apimcache", "APIM Response Cache", "eastus", False, False, 28, "low"),
    ("appinsightsblob", "App Insights Export", "eastus", False, False, 20, "low"),
    ("terraformstate", "Terraform State", "eastus", False, False, 82, "critical"),
]

KEY_VAULTS = [
    ("kv-prod-secrets", "Production Secrets Vault", "eastus", True, True, 15, 3, 2, 4, 1, 0, 88, "critical"),
    ("kv-dev-secrets", "Development Secrets", "eastus", False, False, 8, 1, 4, 2, 0, 0, 65, "high"),
    ("kv-cert-mgmt", "Certificate Management", "eastus", True, True, 5, 0, 0, 12, 3, 2, 72, "high"),
    ("kv-encryption", "Encryption Key Vault", "westus2", True, True, 2, 0, 0, 0, 0, 0, 30, "low"),
    ("kv-staging", "Staging Environment", "eastus", False, False, 10, 2, 1, 3, 1, 0, 58, "medium"),
    ("kv-cicd-tokens", "CI/CD API Tokens", "centralus", True, False, 22, 5, 8, 1, 0, 0, 85, "critical"),
    ("kv-data-encryption", "Data Encryption Keys", "eastus2", True, True, 3, 0, 0, 8, 0, 0, 35, "medium"),
    ("kv-ssl-certs", "SSL/TLS Certificates", "westus", True, True, 1, 0, 0, 15, 4, 3, 78, "high"),
    ("kv-backup-keys", "Backup Encryption Keys", "eastus", True, True, 4, 0, 0, 2, 0, 0, 25, "low"),
    ("kv-app-config", "App Configuration Secrets", "eastus", False, False, 18, 3, 6, 0, 0, 0, 70, "high"),
]

# ─── Seeding Functions ────────────────────────────────────────────────

def get_demo_org_id(db):
    """Get the demo organization ID."""
    cursor = db.conn.cursor()
    cursor.execute("SELECT id FROM organizations WHERE slug = 'demo'")
    row = cursor.fetchone()
    cursor.close()
    if not row:
        raise RuntimeError("Demo organization not found. Run the backend first to seed it.")
    return row[0]


def clean_demo_data(db, org_id):
    """Remove existing demo data to allow re-seeding."""
    cursor = db.conn.cursor()
    logger.info("Cleaning existing demo data for org_id=%s...", org_id)

    # Delete in dependency order
    tables_with_org = [
        "review_evidence",
        "review_assignments",
        "access_reviews",
        "report_outputs",
        "report_runs",
        "reports",
        "fix_recommendations",
        "blast_radius_results",
        "attack_paths",
        "security_findings",
        "tenant_health",
        "job_runs",
        "discovery_integrity_metrics",
    ]
    for t in tables_with_org:
        try:
            cursor.execute(f"DELETE FROM {t} WHERE organization_id = %s", (org_id,))
        except Exception:
            db.conn.rollback()

    # Delete resources linked via discovery_run
    cursor.execute("SELECT id FROM discovery_runs WHERE organization_id = %s", (org_id,))
    run_ids = [r[0] for r in cursor.fetchall()]
    if run_ids:
        for t in ["azure_storage_accounts", "azure_key_vaults", "credentials",
                   "entra_role_assignments", "role_assignments", "identities"]:
            try:
                cursor.execute(
                    f"DELETE FROM {t} WHERE discovery_run_id = ANY(%s)", (run_ids,)
                )
            except Exception:
                db.conn.rollback()
        cursor.execute("DELETE FROM discovery_runs WHERE organization_id = %s", (org_id,))

    # Clean demo cloud connection (will be re-created)
    try:
        cursor.execute("DELETE FROM cloud_connections WHERE organization_id = %s AND label = 'Demo Environment'", (org_id,))
    except Exception:
        db.conn.rollback()

    db.conn.commit()
    cursor.close()
    logger.info("Cleaned existing demo data.")


def seed_cloud_connection(db, org_id):
    """Create a demo cloud connection so _latest_run_ids() can find demo runs."""
    cursor = db.conn.cursor()
    cursor.execute("""
        INSERT INTO cloud_connections
            (organization_id, cloud, connection_type, label,
             azure_directory_id, status)
        VALUES (%s, 'azure', 'entra', 'Demo Environment',
                'demo-0000-0000-0000-000000000000', 'connected')
        RETURNING id
    """, (org_id,))
    cc_id = cursor.fetchone()[0]
    db.conn.commit()
    cursor.close()
    logger.info("Created cloud_connection id=%s for demo org", cc_id)
    return cc_id


def seed_discovery_run(db, org_id, cloud_connection_id):
    """Create a completed discovery run for the demo org."""
    cursor = db.conn.cursor()
    cursor.execute("""
        INSERT INTO discovery_runs
            (subscription_id, subscription_name, started_at, completed_at,
             status, total_identities, critical_count, high_count,
             medium_count, low_count, organization_id, cloud_connection_id)
        VALUES (%s, %s, %s, %s, 'completed', 200, 18, 42, 85, 55, %s, %s)
        RETURNING id
    """, (
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "AuditGraph Demo Subscription",
        RUN_START, RUN_END, org_id, cloud_connection_id,
    ))
    run_id = cursor.fetchone()[0]
    db.conn.commit()
    cursor.close()
    logger.info("Created discovery_run id=%s (cloud_connection_id=%s)", run_id, cloud_connection_id)
    return run_id


def seed_identities(db, org_id, run_id):
    """Seed ~200 identities. Returns {identity_id: db_id} mapping."""
    cursor = db.conn.cursor()
    identity_map = {}

    def _insert(identity_id, display_name, category, risk_score, **extra):
        risk = _risk_level(risk_score)
        obj_id = _uuid()
        app_id = _uuid() if category in ("service_principal",) else None
        activity = random.choice(["active", "active", "active", "inactive", "stale", "never_used"])
        if risk_score >= 80:
            activity = random.choice(["active", "active", "stale"])
        last_sign_in = _past(1, 90) if activity != "never_used" else None
        cred_count = extra.get("cred_count", random.randint(0, 3))
        cred_exp = _future(1, 180) if cred_count > 0 else None
        # Expired creds for some high risk
        if extra.get("expired_cred"):
            cred_exp = _past(1, 60)
        cred_status = "valid"
        if cred_exp and cred_exp < NOW:
            cred_status = "expired"
        elif cred_exp and cred_exp < NOW + timedelta(days=30):
            cred_status = "expiring_soon"
        owner_count = extra.get("owner_count", random.randint(0, 2))
        enabled = extra.get("enabled", True)

        cursor.execute("""
            INSERT INTO identities
                (discovery_run_id, identity_id, display_name, source, identity_type,
                 identity_category, app_id, object_id, enabled, is_microsoft_system,
                 risk_level, risk_score, risk_reasons,
                 credential_expiration, credential_status, credential_count,
                 last_sign_in, activity_status, owner_count, cloud,
                 created_datetime, created_at)
            VALUES (%s,%s,%s,'azure',%s,%s,%s,%s,%s,false,
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,'azure',%s,NOW())
            RETURNING id
        """, (
            run_id, identity_id, display_name,
            "ServicePrincipal" if category == "service_principal" else
            "ManagedIdentity" if category.startswith("managed_identity") else
            "User",
            category, app_id, obj_id, enabled,
            risk, risk_score,
            extra.get("risk_reasons", [f"score_{risk_score}"]),
            cred_exp, cred_status, cred_count,
            last_sign_in, activity, owner_count,
            _past(30, 730),
        ))
        db_id = cursor.fetchone()[0]
        identity_map[identity_id] = db_id
        return db_id

    # Part 1a: Human users (120)
    for uname, dname, _, score in HUMAN_USERS:
        _insert(uname, dname, "human_user", score,
                cred_count=1, owner_count=1)

    # Part 1b: Service principals (35)
    for sp_id, sp_name, score, has_expired in SERVICE_PRINCIPALS:
        _insert(sp_id, sp_name, "service_principal", score,
                cred_count=random.randint(1, 4),
                expired_cred=has_expired and random.random() < 0.3,
                owner_count=0 if random.random() < 0.3 else 1)

    # Part 1c: Managed identities (15)
    for mi_id, mi_name, mi_cat, score in MANAGED_IDENTITIES:
        _insert(mi_id, mi_name, mi_cat, score,
                cred_count=0, owner_count=0)

    # Part 1d: Guest users (30)
    for g_id, g_name, score, _ in GUEST_USERS:
        _insert(g_id, g_name, "guest", score,
                cred_count=0, owner_count=0,
                risk_reasons=["external_identity", f"score_{score}"])

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d identities.", len(identity_map))
    return identity_map


def seed_credentials(db, identity_map, run_id):
    """Seed credentials for service principals (Part 5)."""
    cursor = db.conn.cursor()
    count = 0

    for sp_id, sp_name, score, has_expired in SERVICE_PRINCIPALS:
        db_id = identity_map.get(sp_id)
        if not db_id:
            continue
        n_creds = random.randint(1, 3)
        for j in range(n_creds):
            cred_type = random.choice(["secret", "secret", "certificate"])
            start = _past(60, 400)
            if has_expired and j == 0 and random.random() < 0.5:
                end = _past(1, 30)  # Expired
            elif score >= 70 and j == 0:
                end = _future(1, 30)  # Expiring soon
            else:
                end = _future(30, 365)

            cursor.execute("""
                INSERT INTO credentials
                    (identity_db_id, credential_type, key_id, display_name,
                     start_datetime, end_datetime, discovered_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, (
                db_id, cred_type, _uuid(),
                f"{sp_name} {cred_type.title()} #{j+1}",
                start, end,
            ))
            count += 1

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d credentials.", count)


def seed_role_assignments(db, identity_map, run_id, org_id=None):
    """Seed RBAC + Entra role assignments (Part 6)."""
    cursor = db.conn.cursor()
    rbac_count = 0
    entra_count = 0
    logger.info("seed_role_assignments: org_id=%s, identity_map size=%d, run_id=%s",
                org_id, len(identity_map), run_id)

    SUBS = [
        ("/subscriptions/sub-prod-001", "NGH-Production"),
        ("/subscriptions/sub-dev-002", "NGH-Development"),
        ("/subscriptions/sub-staging-003", "NGH-Staging"),
    ]
    RGS = ["rg-core", "rg-data", "rg-networking", "rg-app", "rg-monitoring"]

    # Risky assignments (Part 6 examples)
    risky_rbac = [
        ("guest_vendor_acme@ext.com", "Owner", 0, "subscription"),
        ("guest_pentest_team@ext.com", "Owner", 0, "subscription"),
        ("guest_contractor_dev@ext.com", "Contributor", 0, "subscription"),
        ("terraform-sp", "Contributor", 0, "subscription"),
        ("terraform-sp", "User Access Administrator", 0, "subscription"),
        ("ci-cd-service", "Contributor", 0, "subscription"),
        ("ci-cd-service", "Contributor", 1, "subscription"),
        ("devops-agent", "Owner", 1, "subscription"),
        ("sql-admin-sp", "Contributor", 0, "subscription"),
        ("data-pipeline-sp", "Key Vault Secrets Officer", 0, "resource"),
        ("aks-cluster-sp", "Contributor", 0, "subscription"),
        ("guest_vendor_sap@ext.com", "Contributor", 0, "resource_group"),
        ("guest_consultant_mck@ext.com", "Contributor", 1, "resource_group"),
    ]

    for identity_id, role, sub_idx, scope_type in risky_rbac:
        db_id = identity_map.get(identity_id)
        if not db_id:
            logger.warning("  Risky RBAC: identity_id=%s NOT FOUND in identity_map", identity_id)
            continue
        sub_scope, sub_name = SUBS[sub_idx % len(SUBS)]
        if scope_type == "subscription":
            scope = sub_scope
        elif scope_type == "resource_group":
            scope = f"{sub_scope}/resourceGroups/{random.choice(RGS)}"
        else:
            scope = f"{sub_scope}/resourceGroups/{random.choice(RGS)}/providers/Microsoft.Storage/storageAccounts/prodcoredata"

        try:
            cursor.execute("""
                INSERT INTO role_assignments
                    (identity_db_id, role_name, scope, scope_type, principal_id,
                     assignment_id, created_on, created_at, organization_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (
                db_id, role, scope, scope_type, _uuid(), _uuid(),
                _past(30, 365), org_id,
            ))
            rbac_count += 1
        except Exception as e:
            logger.error("  RBAC INSERT FAILED for %s/%s: %s", identity_id, role, e)
            db.conn.rollback()
            raise

    # Normal RBAC for remaining identities
    for identity_id, db_id in identity_map.items():
        if rbac_count > 350:
            break
        if random.random() < 0.4:
            continue  # Skip some
        role = random.choice(["Reader", "Contributor", "Reader", "Reader",
                              "Storage Blob Data Reader", "Key Vault Secrets User",
                              "Monitoring Reader", "Log Analytics Reader"])
        sub_scope, sub_name = random.choice(SUBS)
        scope_type = random.choice(["subscription", "resource_group", "resource_group"])
        if scope_type == "resource_group":
            scope = f"{sub_scope}/resourceGroups/{random.choice(RGS)}"
        else:
            scope = sub_scope

        cursor.execute("""
            INSERT INTO role_assignments
                (identity_db_id, role_name, scope, scope_type, principal_id,
                 assignment_id, created_on, created_at, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s)
        """, (db_id, role, scope, scope_type, _uuid(), _uuid(), _past(30, 365), org_id))
        rbac_count += 1

    # Entra directory roles
    ENTRA_ROLES = [
        ("Global Administrator", "/"),
        ("User Administrator", "/"),
        ("Security Administrator", "/"),
        ("Exchange Administrator", "/"),
        ("Application Administrator", "/"),
        ("Privileged Role Administrator", "/"),
        ("Cloud Application Administrator", "/"),
        ("Conditional Access Administrator", "/"),
    ]

    # Assign Global Admin to top risk users
    ga_users = ["john.carter@auditgraph.ai", "daniel.white@auditgraph.ai",
                "sarah.chen@auditgraph.ai", "robert.brown@auditgraph.ai"]
    for uid in ga_users:
        db_id = identity_map.get(uid)
        if db_id:
            cursor.execute("""
                INSERT INTO entra_role_assignments
                    (identity_db_id, role_name, role_definition_id, directory_scope,
                     organization_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (db_id, "Global Administrator", _uuid(), "/", org_id))
            entra_count += 1

    # Random Entra roles for some identities
    for identity_id, db_id in random.sample(list(identity_map.items()), min(40, len(identity_map))):
        role_name, scope = random.choice(ENTRA_ROLES[1:])  # Not GA
        cursor.execute("""
            INSERT INTO entra_role_assignments
                (identity_db_id, role_name, role_definition_id, directory_scope,
                 organization_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (db_id, role_name, _uuid(), scope, org_id))
        entra_count += 1

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d RBAC + %d Entra role assignments.", rbac_count, entra_count)


def seed_storage_accounts(db, org_id, run_id):
    """Seed 20 storage accounts (Part 2 + Part 3)."""
    cursor = db.conn.cursor()

    for name, desc, location, shared_key, public_blob, risk_score, risk in STORAGE_ACCOUNTS:
        resource_id = f"/subscriptions/sub-prod-001/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/{name}"
        key1_age = _past(30, 400)
        key2_age = _past(30, 400)
        rotation_stale = (NOW - key1_age).days > 90

        risk_reasons = []
        if public_blob:
            risk_reasons.append("Public blob access enabled")
        if shared_key:
            risk_reasons.append("Shared key access enabled")
        if rotation_stale:
            risk_reasons.append("Access keys not rotated in 90+ days")

        cursor.execute("""
            INSERT INTO azure_storage_accounts
                (discovery_run_id, resource_id, name, location, resource_group,
                 subscription_id, subscription_name, sku, kind, access_tier,
                 public_blob_access, https_only, minimum_tls_version,
                 shared_key_access, default_network_action,
                 key1_created_at, key2_created_at, key_rotation_stale,
                 sas_policy_enabled, sas_expiration_period,
                 risk_level, risk_score, risk_reasons, organization_id)
            VALUES (%s,%s,%s,%s,'rg-data',%s,'AuditGraph Demo Subscription',
                    'Standard_LRS','StorageV2','Hot',
                    %s,true,'TLS1_2',%s,'Allow',
                    %s,%s,%s,%s,%s,%s,%s,%s,%s)
            -- data is cleaned before seeding, no conflict expected
        """, (
            run_id, resource_id, name, location,
            "sub-prod-001",
            public_blob, shared_key,
            key1_age, key2_age, rotation_stale,
            random.random() < 0.3,  # sas_policy_enabled
            "P30D" if random.random() < 0.5 else "P365D",
            risk, risk_score,
            json.dumps(risk_reasons),
            org_id,
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d storage accounts.", len(STORAGE_ACCOUNTS))


def seed_key_vaults(db, org_id, run_id):
    """Seed 10 key vaults (Part 4)."""
    cursor = db.conn.cursor()

    for (name, desc, loc, soft_del, purge_prot,
         secrets_total, secrets_expired, secrets_expiring,
         certs_total, certs_expired, certs_expiring,
         risk_score, risk) in KEY_VAULTS:

        resource_id = f"/subscriptions/sub-prod-001/resourceGroups/rg-core/providers/Microsoft.KeyVault/vaults/{name}"
        keys_total = random.randint(0, 6)

        risk_reasons = []
        if not purge_prot:
            risk_reasons.append("Purge protection disabled")
        if secrets_expired > 0:
            risk_reasons.append(f"{secrets_expired} expired secret(s)")
        if certs_expired > 0:
            risk_reasons.append(f"{certs_expired} expired certificate(s)")
        if secrets_expiring > 0:
            risk_reasons.append(f"{secrets_expiring} secret(s) expiring soon")

        # Build secrets detail JSONB
        secrets_detail = []
        for i in range(secrets_total):
            exp = _past(1, 30) if i < secrets_expired else (
                _future(1, 30) if i < secrets_expired + secrets_expiring else
                _future(60, 365)
            )
            secrets_detail.append({
                "name": f"secret-{name}-{i}",
                "enabled": True,
                "expires": exp.isoformat(),
                "content_type": random.choice(["password", "connection-string", "api-key"]),
            })

        certs_detail = []
        for i in range(certs_total):
            exp = _past(1, 30) if i < certs_expired else (
                _future(1, 30) if i < certs_expired + certs_expiring else
                _future(60, 365)
            )
            certs_detail.append({
                "name": f"cert-{name}-{i}",
                "enabled": True,
                "expires": exp.isoformat(),
                "subject": f"CN=*.{name}.auditgraph.ai",
            })

        cursor.execute("""
            INSERT INTO azure_key_vaults
                (discovery_run_id, resource_id, name, location, resource_group,
                 subscription_id, subscription_name, sku,
                 soft_delete_enabled, soft_delete_retention_days, purge_protection,
                 enable_rbac_authorization, public_network_access,
                 secrets_total, secrets_expired, secrets_expiring_soon,
                 keys_total, keys_expired, keys_expiring_soon,
                 certs_total, certs_expired, certs_expiring_soon,
                 secrets_detail, certs_detail,
                 risk_level, risk_score, risk_reasons, organization_id)
            VALUES (%s,%s,%s,%s,'rg-core',%s,'AuditGraph Demo Subscription','standard',
                    %s,90,%s,%s,'Enabled',
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s)
            -- data is cleaned before seeding, no conflict expected
        """, (
            run_id, resource_id, name, loc,
            "sub-prod-001",
            soft_del, purge_prot,
            random.random() < 0.4,  # rbac auth
            secrets_total, secrets_expired, secrets_expiring,
            keys_total, random.randint(0, 1), random.randint(0, 1),
            certs_total, certs_expired, certs_expiring,
            json.dumps(secrets_detail), json.dumps(certs_detail),
            risk, risk_score, json.dumps(risk_reasons), org_id,
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d key vaults.", len(KEY_VAULTS))


def seed_security_findings(db, org_id, run_id, identity_map):
    """Seed security findings (Part 3 + Part 4 + Part 5 risks)."""
    cursor = db.conn.cursor()
    findings = []

    FINDING_DEFS = [
        # Storage risks (Part 3)
        ("storage_public_access", "critical", 95, "Public blob access enabled",
         "Storage account has public blob access enabled, exposing data to the internet.",
         "Disable public blob access", "service_principal"),
        ("sas_key_long_lived", "high", 72, "SAS key with long-lived expiry",
         "SAS key expiry exceeds 90 days, increasing risk of key compromise.",
         "Set SAS expiry to 30 days maximum", "service_principal"),
        ("access_keys_not_rotated", "medium", 55, "Storage access keys not rotated",
         "Access keys have not been rotated in over 90 days.",
         "Rotate storage access keys every 90 days", "service_principal"),
        # Key vault risks (Part 4)
        ("kv_no_purge_protection", "high", 70, "Key Vault purge protection disabled",
         "Key Vault does not have purge protection enabled, allowing permanent deletion.",
         "Enable purge protection on key vault", "service_principal"),
        ("secret_older_180_days", "medium", 60, "Secret not rotated in 180+ days",
         "Key vault secret has not been rotated in over 180 days.",
         "Rotate secret and enforce rotation policy", "service_principal"),
        ("kv_no_private_endpoint", "medium", 55, "Key Vault lacks private endpoint",
         "Key vault is accessible over public network without private endpoint.",
         "Configure private endpoint for key vault", "service_principal"),
        # Credential hygiene (Part 5)
        ("spn_secret_expired", "critical", 90, "Service principal secret expired",
         "Service principal has an expired secret credential. App may fail authentication.",
         "Rotate expired service principal secret", "service_principal"),
        ("secret_expiring_soon", "high", 68, "Credential expiring within 30 days",
         "Service principal credential will expire within 30 days.",
         "Rotate credential before expiration", "service_principal"),
        # Identity risks
        ("user_without_mfa", "high", 75, "User without MFA enforcement",
         "User account does not have MFA enforced via conditional access.",
         "Enable MFA for this user account", "human_user"),
        ("dormant_privileged_identity", "high", 80, "Dormant privileged identity",
         "Privileged identity has not signed in for over 90 days but retains elevated roles.",
         "Remove unused privileged role assignment", "human_user"),
        ("overly_broad_rbac", "high", 78, "Overly broad RBAC assignment",
         "Identity has subscription-level Owner or Contributor role with no scope restriction.",
         "Narrow RBAC scope to resource group level", "service_principal"),
        ("guest_admin", "critical", 92, "Guest user with admin privileges",
         "External guest identity holds Owner or Global Administrator role.",
         "Remove administrative role from guest", "guest"),
        ("disabled_account_active_role", "high", 72, "Disabled account with active roles",
         "Account is disabled but still has active RBAC or Entra role assignments.",
         "Remove all role assignments from disabled account", "human_user"),
        ("subscription_owner", "high", 70, "Direct subscription Owner assignment",
         "Identity has Owner role directly on a subscription (not via PIM).",
         "Convert to PIM-eligible assignment", "service_principal"),
    ]

    # Distribute findings across identities
    all_ids = list(identity_map.items())
    for ftype, sev, score, title, desc, fix, target_cat in FINDING_DEFS:
        # Pick 3-8 identities for each finding type
        n = random.randint(3, 8)
        candidates = [
            (iid, dbid) for iid, dbid in all_ids
            if any(cat in iid for cat in ["sp", "service", "guest", "vendor", "@"])
        ]
        if target_cat == "human_user":
            candidates = [(iid, dbid) for iid, dbid in all_ids if "@auditgraph.ai" in iid]
        elif target_cat == "guest":
            candidates = [(iid, dbid) for iid, dbid in all_ids if "guest_" in iid]

        chosen = random.sample(candidates, min(n, len(candidates)))
        for entity_id, _ in chosen:
            fp = hashlib.sha256(f"{entity_id}:{ftype}".encode()).hexdigest()
            findings.append((
                org_id, "identity", entity_id, ftype, sev, score + random.randint(-5, 5),
                title, desc, fix, run_id, json.dumps({}), fp,
            ))

    for f in findings:
        cursor.execute("""
            INSERT INTO security_findings
                (organization_id, entity_type, entity_id, finding_type, severity,
                 risk_score, title, description, recommended_fix,
                 discovery_run_id, metadata, finding_fingerprint,
                 status, first_detected_at, last_detected_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    'open', NOW(), NOW())
            -- data is cleaned before seeding, no conflict expected
        """, f)

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d security findings.", len(findings))


def seed_attack_paths(db, org_id, run_id, identity_map):
    """Seed 8 attack paths (Part 7)."""
    cursor = db.conn.cursor()

    paths = [
        {
            "source": "guest_vendor_acme@ext.com",
            "type": "direct_escalation",
            "score": 95, "sev": "critical",
            "desc": "Guest vendor has direct Owner role on production subscription",
            "narrative": "External vendor guest_vendor_acme@ext.com holds Owner role on sub-prod-001. "
                         "This grants full control over all resources including key vaults and storage accounts. "
                         "A compromised vendor account could exfiltrate all production data.",
            "impact": "Full subscription takeover via compromised vendor credentials",
            "nodes": [
                {"id": "guest_vendor_acme@ext.com", "type": "identity", "label": "Vendor ACME Admin"},
                {"id": "owner-role", "type": "role", "label": "Owner"},
                {"id": "sub-prod-001", "type": "subscription", "label": "NGH-Production"},
            ],
            "resources": 213,
        },
        {
            "source": "terraform-sp",
            "type": "lateral_movement",
            "score": 92, "sev": "critical",
            "desc": "Terraform SP can access Key Vault secrets and pivot to other subscriptions",
            "narrative": "terraform-sp has Contributor + User Access Administrator on sub-prod-001. "
                         "It can assign itself Key Vault access, read all secrets, and use those "
                         "credentials to access other subscriptions.",
            "impact": "Cross-subscription lateral movement via secret exfiltration",
            "nodes": [
                {"id": "terraform-sp", "type": "identity", "label": "Terraform Automation"},
                {"id": "contributor", "type": "role", "label": "Contributor"},
                {"id": "kv-prod-secrets", "type": "resource", "label": "Production Secrets Vault"},
                {"id": "sub-dev-002", "type": "subscription", "label": "NGH-Development"},
            ],
            "resources": 156,
        },
        {
            "source": "ci-cd-service",
            "type": "lateral_movement",
            "score": 88, "sev": "critical",
            "desc": "CI/CD service principal spans multiple subscriptions with Contributor",
            "narrative": "ci-cd-service has Contributor on both Production and Development subscriptions. "
                         "A compromised pipeline could deploy malicious code across environments.",
            "impact": "Cross-environment deployment of malicious artifacts",
            "nodes": [
                {"id": "ci-cd-service", "type": "identity", "label": "CI/CD Pipeline Service"},
                {"id": "contributor", "type": "role", "label": "Contributor"},
                {"id": "sub-prod-001", "type": "subscription", "label": "NGH-Production"},
                {"id": "sub-dev-002", "type": "subscription", "label": "NGH-Development"},
            ],
            "resources": 184,
        },
        {
            "source": "guest_pentest_team@ext.com",
            "type": "direct_escalation",
            "score": 90, "sev": "critical",
            "desc": "Pentest team guest retains Owner role after engagement ended",
            "narrative": "guest_pentest_team@ext.com was granted Owner during a penetration test "
                         "but the role was never revoked. This stale privileged access poses extreme risk.",
            "impact": "Stale Owner access from former pentest engagement",
            "nodes": [
                {"id": "guest_pentest_team@ext.com", "type": "identity", "label": "Penetration Tester"},
                {"id": "owner-role", "type": "role", "label": "Owner"},
                {"id": "sub-prod-001", "type": "subscription", "label": "NGH-Production"},
            ],
            "resources": 213,
        },
        {
            "source": "devops-agent",
            "type": "ownership_chain",
            "score": 82, "sev": "high",
            "desc": "DevOps agent can modify code repositories and deployment pipelines",
            "narrative": "devops-agent owns the Development subscription and has read access to "
                         "key vaults containing deployment secrets. It can modify CI/CD pipelines "
                         "to inject malicious code.",
            "impact": "Supply chain compromise via deployment pipeline manipulation",
            "nodes": [
                {"id": "devops-agent", "type": "identity", "label": "Azure DevOps Agent"},
                {"id": "owner-role", "type": "role", "label": "Owner"},
                {"id": "sub-dev-002", "type": "subscription", "label": "NGH-Development"},
                {"id": "kv-cicd-tokens", "type": "resource", "label": "CI/CD API Tokens"},
            ],
            "resources": 98,
        },
        {
            "source": "sql-admin-sp",
            "type": "sensitive_data_exposure",
            "score": 85, "sev": "critical",
            "desc": "SQL admin SP has access to production databases and backup storage",
            "narrative": "sql-admin-sp has Contributor on the production subscription. Combined with "
                         "Storage Blob Data Contributor, it can export database backups and "
                         "access customer PII/PHI data.",
            "impact": "Database exfiltration and customer data breach",
            "nodes": [
                {"id": "sql-admin-sp", "type": "identity", "label": "SQL Database Admin"},
                {"id": "contributor", "type": "role", "label": "Contributor"},
                {"id": "prodcoredata", "type": "resource", "label": "Production Core Data"},
            ],
            "resources": 45,
        },
        {
            "source": "john.carter@auditgraph.ai",
            "type": "pim_escalation",
            "score": 78, "sev": "high",
            "desc": "Global Admin with permanent assignment (not PIM-eligible)",
            "narrative": "john.carter@auditgraph.ai has permanent Global Administrator role "
                         "without PIM. This means the admin privileges are always active, "
                         "increasing the window for credential compromise.",
            "impact": "Permanent Global Admin without just-in-time activation",
            "nodes": [
                {"id": "john.carter@auditgraph.ai", "type": "identity", "label": "John Carter"},
                {"id": "global-admin", "type": "role", "label": "Global Administrator"},
                {"id": "tenant-root", "type": "scope", "label": "Tenant Root"},
            ],
            "resources": 0,
        },
        {
            "source": "data-pipeline-sp",
            "type": "sensitive_data_exposure",
            "score": 75, "sev": "high",
            "desc": "Data pipeline SP has Key Vault Secrets Officer accessing sensitive secrets",
            "narrative": "data-pipeline-sp holds Key Vault Secrets Officer on the production vault, "
                         "allowing it to read, write, and delete all secrets including database "
                         "connection strings and API keys.",
            "impact": "Secret exfiltration via over-privileged data pipeline",
            "nodes": [
                {"id": "data-pipeline-sp", "type": "identity", "label": "Data Pipeline ETL"},
                {"id": "kv-secrets-officer", "type": "role", "label": "Key Vault Secrets Officer"},
                {"id": "kv-prod-secrets", "type": "resource", "label": "Production Secrets Vault"},
            ],
            "resources": 15,
        },
    ]

    for p in paths:
        fp = hashlib.sha256(f"{p['source']}:{p['type']}:{p['desc'][:50]}".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO attack_paths
                (organization_id, discovery_run_id, source_entity_id, source_entity_name,
                 source_entity_type, path_type, risk_score, severity,
                 path_nodes, description, narrative, impact,
                 path_fingerprint, affected_resource_count,
                 first_detected_at, last_detected_at, last_seen_run_id)
            VALUES (%s,%s,%s,%s,'identity',%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW(),%s)
            -- data is cleaned before seeding, no conflict expected
        """, (
            org_id, run_id, p["source"],
            p["nodes"][0]["label"] if p["nodes"] else p["source"],
            p["type"], p["score"], p["sev"],
            json.dumps(p["nodes"]), p["desc"], p["narrative"], p["impact"],
            fp, p["resources"], run_id,
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d attack paths.", len(paths))


def seed_blast_radius(db, org_id, run_id, identity_map):
    """Seed blast radius results (Part 8)."""
    cursor = db.conn.cursor()

    blast = [
        ("terraform-sp", "Terraform Automation", "service_principal",
         213, 3, 5, 5, 92, "CRITICAL", {"storage": 20, "keyvault": 10, "compute": 45, "database": 15, "network": 30}),
        ("ci-cd-service", "CI/CD Pipeline Service", "service_principal",
         184, 2, 4, 3, 88, "CRITICAL", {"storage": 15, "compute": 40, "database": 10, "keyvault": 8}),
        ("guest_vendor_acme@ext.com", "Vendor ACME Admin", "guest",
         213, 3, 5, 2, 90, "CRITICAL", {"storage": 20, "keyvault": 10, "compute": 45}),
        ("devops-agent", "Azure DevOps Agent", "service_principal",
         98, 1, 3, 4, 78, "HIGH", {"compute": 30, "storage": 12, "keyvault": 6}),
        ("sql-admin-sp", "SQL Database Admin", "service_principal",
         45, 1, 2, 2, 82, "CRITICAL", {"database": 15, "storage": 10}),
        ("john.carter@auditgraph.ai", "John Carter", "human_user",
         300, 3, 8, 0, 85, "CRITICAL", {"all": 300}),
        ("data-pipeline-sp", "Data Pipeline ETL", "service_principal",
         65, 1, 3, 1, 72, "HIGH", {"storage": 20, "keyvault": 5, "database": 10}),
        ("aks-cluster-sp", "AKS Cluster Identity", "service_principal",
         78, 1, 2, 2, 68, "HIGH", {"compute": 25, "network": 15, "storage": 8}),
        ("guest_pentest_team@ext.com", "Penetration Tester", "guest",
         213, 3, 5, 0, 88, "CRITICAL", {"storage": 20, "keyvault": 10, "compute": 45}),
        ("synapse-analytics-sp", "Synapse Analytics Workspace", "service_principal",
         42, 1, 2, 1, 65, "HIGH", {"database": 12, "storage": 15}),
    ]

    for (iid, iname, itype, reach, subs, rgs, sens, score, level, breakdown) in blast:
        db_id = identity_map.get(iid)
        if not db_id:
            continue
        cursor.execute("""
            INSERT INTO blast_radius_results
                (organization_id, identity_id, identity_name, identity_type,
                 discovery_run_id, reachable_resource_count,
                 reachable_subscription_count, reachable_resource_group_count,
                 sensitive_resource_count, sensitive_data_types,
                 resource_breakdown, privilege_escalation_paths,
                 risk_domain, identity_exposure_level,
                 risk_score)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'identity',%s,%s)
            -- data is cleaned before seeding, no conflict expected
        """, (
            org_id, db_id, iname, itype, run_id,
            reach, subs, rgs, sens,
            json.dumps(["PII", "PHI", "Financial"] if sens > 0 else []),
            json.dumps(breakdown),
            random.randint(0, 3),
            level, score,
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d blast radius results.", len(blast))


def seed_fix_recommendations(db, org_id, run_id, identity_map):
    """Seed fix recommendations (Part 9)."""
    cursor = db.conn.cursor()

    recs = [
        {
            "entity": "prodcoredata", "type": "rotate_storage_keys",
            "title": "Rotate storage account access keys",
            "desc": "Storage account 'prodcoredata' access keys have not been rotated in 120+ days.",
            "category": "credential_hygiene", "priority": 85, "effort": "low",
            "steps": ["Navigate to Storage Account > Access Keys",
                      "Click 'Rotate key' for Key1",
                      "Update all applications using Key1",
                      "Rotate Key2 after verification"],
            "cli": "az storage account keys renew --account-name prodcoredata --key key1",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["IA-5"], "CIS": ["3.1"]},
        },
        {
            "entity": "guest_vendor_acme@ext.com", "type": "remove_role",
            "title": "Remove Owner role from guest vendor",
            "desc": "External guest guest_vendor_acme@ext.com has Owner role on production subscription.",
            "category": "access_control", "priority": 95, "effort": "low",
            "steps": ["Navigate to Subscription > IAM",
                      "Find guest_vendor_acme@ext.com",
                      "Remove Owner role assignment",
                      "Assign Reader if read access still needed"],
            "cli": "az role assignment delete --assignee guest_vendor_acme@ext.com --role Owner",
            "compliance": {"SOC2": ["CC6.1", "CC6.3"], "HIPAA": ["164.312(a)"], "NIST": ["AC-6"]},
        },
        {
            "entity": "kv-ssl-certs", "type": "rotate_credential",
            "title": "Rotate expired SSL/TLS certificates",
            "desc": "Key vault 'kv-ssl-certs' has 4 expired certificates requiring immediate renewal.",
            "category": "credential_hygiene", "priority": 88, "effort": "medium",
            "steps": ["Identify expired certificates in kv-ssl-certs",
                      "Generate new CSR or use auto-renewal",
                      "Upload renewed certificate",
                      "Update application bindings"],
            "cli": "az keyvault certificate create --vault-name kv-ssl-certs --name <cert-name> --policy @policy.json",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["SC-17"], "CIS": ["8.4"]},
        },
        {
            "entity": "kv-prod-secrets", "type": "enable_purge_protection",
            "title": "Restrict Key Vault network access",
            "desc": "Production secrets vault 'kv-prod-secrets' is accessible over public network.",
            "category": "network_security", "priority": 82, "effort": "medium",
            "steps": ["Configure private endpoint for the vault",
                      "Set default network action to Deny",
                      "Add necessary VNet rules",
                      "Test application connectivity"],
            "cli": "az keyvault update --name kv-prod-secrets --default-action Deny",
            "compliance": {"SOC2": ["CC6.6"], "NIST": ["SC-7"], "CIS": ["8.7"]},
        },
        {
            "entity": "terraform-sp", "type": "narrow_scope",
            "title": "Narrow Terraform SP RBAC scope",
            "desc": "terraform-sp has Contributor + User Access Administrator at subscription scope.",
            "category": "access_control", "priority": 90, "effort": "high",
            "steps": ["Audit current Terraform resource deployments",
                      "Identify minimum required resource groups",
                      "Create custom role with specific permissions",
                      "Replace subscription-level assignments with RG-scoped"],
            "cli": "az role assignment delete --assignee terraform-sp --role 'User Access Administrator'",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["AC-6"], "CIS": ["1.23"]},
        },
        {
            "entity": "ci-cd-service", "type": "narrow_scope",
            "title": "Restrict CI/CD service principal to single subscription",
            "desc": "ci-cd-service has Contributor on both Production and Development subscriptions.",
            "category": "access_control", "priority": 85, "effort": "medium",
            "steps": ["Create separate SPs for prod and dev pipelines",
                      "Assign minimum necessary roles per environment",
                      "Update pipeline service connections",
                      "Remove cross-subscription Contributor"],
            "cli": "az role assignment delete --assignee ci-cd-service --scope /subscriptions/sub-dev-002",
            "compliance": {"SOC2": ["CC6.3"], "NIST": ["AC-6(3)"]},
        },
        {
            "entity": "guest_pentest_team@ext.com", "type": "remove_role",
            "title": "Revoke stale pentest team access",
            "desc": "Penetration tester guest retains Owner role after engagement completed.",
            "category": "access_control", "priority": 92, "effort": "low",
            "steps": ["Verify penetration test engagement has concluded",
                      "Remove Owner role from guest account",
                      "Disable or delete the guest account",
                      "Document in access review records"],
            "cli": "az role assignment delete --assignee guest_pentest_team@ext.com --role Owner",
            "compliance": {"SOC2": ["CC6.2"], "NIST": ["AC-2(3)"]},
        },
        {
            "entity": "devtestblobs", "type": "disable_public_access",
            "title": "Disable public blob access on dev storage",
            "desc": "Storage account 'devtestblobs' has public blob access enabled.",
            "category": "data_protection", "priority": 88, "effort": "low",
            "steps": ["Navigate to devtestblobs > Configuration",
                      "Set 'Allow Blob public access' to Disabled",
                      "Verify no public containers are in use",
                      "Update any external links to use SAS tokens"],
            "cli": "az storage account update --name devtestblobs --allow-blob-public-access false",
            "compliance": {"SOC2": ["CC6.6"], "HIPAA": ["164.312(e)"], "CIS": ["3.6"]},
        },
        {
            "entity": "john.carter@auditgraph.ai", "type": "enable_pim",
            "title": "Convert Global Admin to PIM-eligible",
            "desc": "john.carter@auditgraph.ai has permanent Global Administrator assignment.",
            "category": "access_control", "priority": 80, "effort": "medium",
            "steps": ["Open PIM > Azure AD Roles",
                      "Find Global Administrator role",
                      "Remove permanent assignment for John Carter",
                      "Add as PIM-eligible with 8-hour max activation"],
            "cli": "# Use Azure Portal: PIM > Azure AD Roles > Global Administrator > Edit",
            "compliance": {"SOC2": ["CC6.1"], "NIST": ["AC-6(1)"], "CIS": ["1.1"]},
        },
        {
            "entity": "publicwebcontent", "type": "disable_public_access",
            "title": "Review public access on web content storage",
            "desc": "Storage account 'publicwebcontent' has both public blob access and shared key access.",
            "category": "data_protection", "priority": 75, "effort": "medium",
            "steps": ["Evaluate if public access is business-required",
                      "If CDN is used, restrict to CDN-only access",
                      "Disable shared key access if possible",
                      "Enable diagnostic logging for audit trail"],
            "cli": "az storage account update --name publicwebcontent --allow-shared-key-access false",
            "compliance": {"SOC2": ["CC6.6"], "CIS": ["3.2"]},
        },
    ]

    for r in recs:
        fp = hashlib.sha256(f"{r['entity']}:{r['type']}".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO fix_recommendations
                (organization_id, discovery_run_id, entity_id, entity_type, entity_name,
                 fix_type, title, description, fix_category,
                 priority_score, effort, steps, azure_cli_commands,
                 compliance_refs, status, recommendation_fingerprint,
                 first_detected_at, last_detected_at)
            VALUES (%s,%s,%s,'identity',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'open',%s,NOW(),NOW())
            -- data is cleaned before seeding, no conflict expected
        """, (
            org_id, run_id, r["entity"], r["entity"],
            r["type"], r["title"], r["desc"], r["category"],
            r["priority"], r["effort"],
            json.dumps(r["steps"]), r["cli"],
            json.dumps(r["compliance"]), fp,
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d fix recommendations.", len(recs))


def seed_access_review(db, org_id, run_id, identity_map):
    """Seed an access review campaign with 120 assignments (Part 10)."""
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # Create the review
    cursor.execute("""
        INSERT INTO access_reviews
            (organization_id, title, description, review_type, scope, status,
             created_by, total_assignments, completed_assignments,
             approved_count, revoked_count, flagged_count,
             due_date, completed_at, completed_by,
             compliance_frameworks, created_at, updated_at)
        VALUES (%s, %s, %s, 'periodic', 'privileged', 'completed',
                'demo@auditgraph.ai', 120, 120, 110, 8, 2,
                %s, %s, 'demo@auditgraph.ai',
                %s, %s, %s)
        RETURNING id
    """, (
        org_id,
        "Q3 2025 Privileged Access Review",
        "Quarterly review of all privileged role assignments across Azure subscriptions and Entra ID. "
        "Covers Owner, Contributor, User Access Administrator, and Global Administrator roles.",
        NOW - timedelta(days=7),   # due_date
        NOW - timedelta(days=2),   # completed_at
        json.dumps(["SOC2", "HIPAA", "NIST"]),
        NOW - timedelta(days=30),  # created_at
        NOW - timedelta(days=2),   # updated_at
    ))
    review_id = cursor.fetchone()["id"]

    # Create 120 assignments — distribute decisions
    all_identity_ids = list(identity_map.items())
    selected = random.sample(all_identity_ids, min(120, len(all_identity_ids)))

    decisions = (["approved"] * 110 + ["revoked"] * 8 + ["flagged"] * 2)
    random.shuffle(decisions)

    roles = ["Owner", "Contributor", "User Access Administrator", "Reader",
             "Key Vault Secrets Officer", "Storage Blob Data Contributor",
             "Global Administrator", "Security Administrator"]

    for i, ((identity_id, db_id), decision) in enumerate(zip(selected, decisions)):
        role = roles[i % len(roles)]
        risk_score = random.randint(10, 95)
        cursor.execute("""
            INSERT INTO review_assignments
                (review_id, organization_id, identity_id, identity_name,
                 identity_type, role_name, role_type, scope,
                 risk_level, risk_score, blast_radius_score,
                 reviewer, decision, decision_reason, decision_at, due_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            review_id, org_id, db_id, identity_id,
            "user", role,
            "entra" if role in ("Global Administrator", "Security Administrator") else "rbac",
            "/subscriptions/sub-prod-001" if role not in ("Global Administrator", "Security Administrator") else "/",
            _risk_level(risk_score), risk_score,
            random.randint(0, 90),
            "demo@auditgraph.ai",
            decision,
            "Approved - role still required" if decision == "approved" else
            "Revoked - no longer needed" if decision == "revoked" else
            "Flagged for manager review",
            NOW - timedelta(days=random.randint(2, 25)),
            NOW - timedelta(days=7),
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded access review with %d assignments (110 approved, 8 revoked, 2 flagged).", len(selected))


def seed_reports(db, org_id):
    """Seed pre-created reports (Part 11)."""
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    reports = [
        ("identity_risk", "Identity Risk Report",
         "Comprehensive analysis of identity risk scores, privileged access patterns, and credential hygiene across the organization."),
        ("attack_surface", "Attack Surface Report",
         "Analysis of attack paths, blast radius metrics, and lateral movement vectors identified during the latest discovery scan."),
        ("access_review_evidence", "Access Review Evidence Report",
         "Evidence package for Q3 2025 Privileged Access Review including all decisions, justifications, and compliance mappings."),
    ]

    for rtype, title, desc in reports:
        cursor.execute("""
            INSERT INTO reports
                (organization_id, report_type, title, parameters,
                 created_by_username, created_at)
            VALUES (%s, %s, %s, %s, 'demo@auditgraph.ai', %s)
            RETURNING id
        """, (
            org_id, rtype, title,
            json.dumps({"description": desc}),
            NOW - timedelta(days=random.randint(1, 14)),
        ))
        report_id = cursor.fetchone()["id"]

        # Create a completed run for each
        cursor.execute("""
            INSERT INTO report_runs
                (report_id, organization_id, status, record_count,
                 started_at, generated_at, generation_duration_ms,
                 parameters, created_at)
            VALUES (%s, %s, 'completed', %s, %s, %s, %s, %s, %s)
        """, (
            report_id, org_id,
            random.randint(50, 200),
            NOW - timedelta(hours=random.randint(1, 48)),
            NOW - timedelta(hours=random.randint(0, 47)),
            random.randint(2000, 15000),
            json.dumps({"format": "json"}),
            NOW - timedelta(hours=random.randint(1, 48)),
        ))

    db.conn.commit()
    cursor.close()
    logger.info("Seeded %d reports with completed runs.", len(reports))


def seed_tenant_health(db, org_id, run_id):
    """Seed tenant health record for the demo org."""
    cursor = db.conn.cursor()
    cursor.execute("""
        INSERT INTO tenant_health
            (organization_id, last_discovery_run, snapshot_age_hours,
             findings_count, critical_risks, blast_radius_critical,
             integrity_warning, status, updated_at)
        VALUES (%s, %s, 2, 72, 18, 5, false, 'healthy', NOW())
        ON CONFLICT (organization_id) DO UPDATE SET
            last_discovery_run = EXCLUDED.last_discovery_run,
            snapshot_age_hours = EXCLUDED.snapshot_age_hours,
            findings_count = EXCLUDED.findings_count,
            critical_risks = EXCLUDED.critical_risks,
            blast_radius_critical = EXCLUDED.blast_radius_critical,
            status = EXCLUDED.status,
            updated_at = NOW()
    """, (org_id, RUN_END))
    db.conn.commit()
    cursor.close()
    logger.info("Seeded tenant_health for demo org.")


# ─── Main ─────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("AuditGraph Demo Tenant Data Seeder")
    logger.info("=" * 60)

    db = Database()
    try:
        org_id = get_demo_org_id(db)
        logger.info("Demo organization id=%s", org_id)

        # Set RLS session context so auto-fill triggers can resolve organization_id
        cursor = db.conn.cursor()
        cursor.execute("SELECT set_config('app.current_organization_id', %s, false)", (str(org_id),))
        cursor.close()
        db.conn.commit()

        clean_demo_data(db, org_id)

        cc_id = seed_cloud_connection(db, org_id)
        run_id = seed_discovery_run(db, org_id, cc_id)
        identity_map = seed_identities(db, org_id, run_id)
        seed_credentials(db, identity_map, run_id)
        seed_role_assignments(db, identity_map, run_id, org_id)
        seed_storage_accounts(db, org_id, run_id)
        seed_key_vaults(db, org_id, run_id)
        seed_security_findings(db, org_id, run_id, identity_map)
        seed_attack_paths(db, org_id, run_id, identity_map)
        seed_blast_radius(db, org_id, run_id, identity_map)
        seed_fix_recommendations(db, org_id, run_id, identity_map)
        seed_access_review(db, org_id, run_id, identity_map)
        seed_reports(db, org_id)
        seed_tenant_health(db, org_id, run_id)

        logger.info("=" * 60)
        logger.info("Demo data seeding COMPLETE")
        logger.info("=" * 60)
        logger.info("Summary:")
        logger.info("  Organization: AuditGraph Demo (id=%s)", org_id)
        logger.info("  Discovery Run: #%s", run_id)
        logger.info("  Identities: %d (120 users, 35 SPs, 15 MI, 30 guests)", len(identity_map))
        logger.info("  Storage Accounts: %d", len(STORAGE_ACCOUNTS))
        logger.info("  Key Vaults: %d", len(KEY_VAULTS))
        logger.info("  Attack Paths: 8")
        logger.info("  Blast Radius: 10 critical identities")
        logger.info("  Fix Recommendations: 10")
        logger.info("  Access Review: Q3 2025 (120 assignments)")
        logger.info("  Reports: 3 pre-created")
        logger.info("")
        logger.info("Login credentials:")
        logger.info("  demo@auditgraph.ai / DemoAdmin@2026")
        logger.info("  analyst@auditgraph.ai / DemoAnalyst@2026")
        logger.info("  viewer@auditgraph.ai / DemoViewer@2026")

    finally:
        db.close()


if __name__ == "__main__":
    main()
