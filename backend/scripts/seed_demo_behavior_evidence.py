#!/usr/bin/env python3
"""
Demo Org Behavior-Evidence Enhancer
====================================
Augments the existing AuditGraph Demo org (id=9) with the behavior-evidence
signals seed_demo_org.py doesn't populate:

  - identities.last_observed_ip / source / date / operation     (Feature D banner)
  - identities.signin_ips / signin_locations (aggregate buckets) (Feature D rich panel)
  - role_assignments.last_used_at + last_used_operation         (Feature E ARM evidence)
  - identity_subscription_access.last_activity                   (Feature E Phase 1 propagation)
  - pim_eligible_assignments                                     (PIM tab + Should-Be-PIM combo)
  - anomalies                                                    (Anomalies tab demo)

IDEMPOTENT — re-running clears the seeded rows it owns (marked with the
sentinel string DEMO_ENHANCE_TAG below) before re-writing.

Run from backend/: venv/bin/python scripts/seed_demo_behavior_evidence.py
"""

import logging
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Database  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("demo_behavior_seed")

DEMO_ORG_ID = 9
NOW = datetime.now(timezone.utc)

# Tag we use to identify rows owned by this enhancer (for idempotent cleanup).
DEMO_ENHANCE_TAG = "demo-behavior-seed-v1"

# Realistic IP pools — mix of Azure datacenter ranges, IPv6, residential ISPs.
AZURE_DC_IPS = [
    "104.210.141.149", "104.210.141.156", "104.210.141.159",
    "20.190.157.98", "20.190.157.115", "40.126.32.142",
    "13.86.71.124", "13.86.71.130", "52.224.107.207",
]
EXTERNAL_IPS = [
    "151.240.220.10", "185.228.195.56", "23.93.67.39",
    "98.51.100.42", "203.0.113.14", "192.0.2.55",
    "2603:80a0:2140:23d:5cab:eecc:7989:9aa2",
    "2a04:4e41:3a02:15cd::c1b5:5cd",
]
ARM_OPS = [
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Resources/deployments/write",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Sql/servers/databases/read",
]
DIRECTORY_OPS = [
    "Update", "Add member to group", "Reset user password",
    "Add app role assignment", "Update conditional access policy",
]


def main():
    db = Database(_admin_reason="demo behavior-evidence seed for org=9")
    cur = db.conn.cursor()

    # ── 0. Clean up any prior enhancer run ──
    log.info("Cleaning prior demo-enhance rows (idempotent reset)…")
    cur.execute("SET app.current_organization_id = %s", (str(DEMO_ORG_ID),))
    cur.execute("DELETE FROM anomalies WHERE organization_id = %s AND resolved_by = %s",
                (DEMO_ORG_ID, DEMO_ENHANCE_TAG))
    cur.execute("""DELETE FROM pim_eligible_assignments
                    WHERE identity_db_id IN (SELECT id FROM identities WHERE organization_id = %s)
                      AND role_definition_id LIKE 'demo-enhance-%%'""",
                (DEMO_ORG_ID,))
    # Reset the per-identity scalar columns we own
    cur.execute("""UPDATE identities
                      SET last_observed_ip = NULL,
                          last_observed_ip_source = NULL,
                          last_observed_ip_date = NULL,
                          last_observed_operation = NULL,
                          signin_ips = NULL,
                          signin_locations = NULL,
                          signin_total_events_30d = NULL,
                          signin_success_count_30d = NULL,
                          signin_failure_count_30d = NULL
                    WHERE organization_id = %s""", (DEMO_ORG_ID,))
    cur.execute("""UPDATE role_assignments ra
                      SET last_used_at = NULL, last_used_operation = NULL, usage_status = NULL
                     FROM identities i
                    WHERE LOWER(ra.principal_id) = LOWER(i.object_id)
                      AND i.organization_id = %s""", (DEMO_ORG_ID,))
    cur.execute("""UPDATE identity_subscription_access isa
                      SET last_activity = NULL
                     FROM identities i
                    WHERE isa.identity_db_id = i.id AND i.organization_id = %s""",
                (DEMO_ORG_ID,))
    db._commit()

    # ── 1. Get all demo-org identities (most recent run) ──
    cur.execute("""
        SELECT id, identity_id, display_name, identity_type, risk_level, object_id
          FROM identities
         WHERE organization_id = %s
           AND discovery_run_id = (SELECT MAX(id) FROM discovery_runs
                                    WHERE organization_id = %s AND status='completed')
    """, (DEMO_ORG_ID, DEMO_ORG_ID))
    identities = cur.fetchall()
    if not identities:
        log.error("No identities found in demo org. Run seed_demo_org.py first.")
        return
    log.info("Found %d demo identities to enrich.", len(identities))

    # ── 2. last_observed_ip on a diverse spread (Feature D banner) ──
    log.info("Seeding last_observed_ip on diverse identities…")
    ip_updates = 0
    for ident in identities:
        id_db, _, _, itype, risk, _ = ident
        # Coverage rule: 100% of critical/high, 60% of medium, 30% of low —
        # mimics real-world "more activity from privileged identities".
        roll = random.random()
        if risk == "critical":
            should_have = True
        elif risk == "high":
            should_have = roll < 0.9
        elif risk == "medium":
            should_have = roll < 0.6
        else:
            should_have = roll < 0.3
        if not should_have:
            continue
        # SPNs + managed identities skew toward Azure datacenter IPs; humans
        # split between Azure (VPN'd) and external (residential / coffee shop).
        if itype in ("service_principal", "managed_identity_user", "managed_identity_system"):
            ip = random.choice(AZURE_DC_IPS)
            src = "arm_activity_log"
            op = random.choice(ARM_OPS)
        else:
            ip = random.choice(AZURE_DC_IPS + EXTERNAL_IPS)
            src = random.choice(["directory_audit_log", "arm_activity_log"])
            op = random.choice(DIRECTORY_OPS if src == "directory_audit_log" else ARM_OPS)
        # Recency: critical/high in last 7 days, others in last 60.
        max_days = 7 if risk in ("critical", "high") else 60
        when = NOW - timedelta(days=random.randint(0, max_days),
                               hours=random.randint(0, 23))
        cur.execute("""UPDATE identities
                          SET last_observed_ip = %s,
                              last_observed_ip_source = %s,
                              last_observed_ip_date = %s,
                              last_observed_operation = %s
                        WHERE id = %s""",
                    (ip, src, when, op, id_db))
        ip_updates += 1
    db._commit()
    log.info("  → %d identities now have last_observed_ip", ip_updates)

    # ── 3. signin_ips/locations aggregate (Feature D rich panel) on a subset ──
    log.info("Seeding signin_ips/locations on critical+high SPNs…")
    bucket_updates = 0
    cur.execute("""SELECT id FROM identities
                    WHERE organization_id = %s
                      AND identity_type IN ('service_principal','managed_identity_user')
                      AND risk_level IN ('critical','high')""",
                (DEMO_ORG_ID,))
    for row in cur.fetchall():
        id_db = row[0]
        ips = []
        for ip in random.sample(AZURE_DC_IPS, k=random.randint(2, 4)):
            ips.append({"ip": ip, "classification": "azure_datacenter",
                        "count": random.randint(50, 500)})
        # ~30% chance an external IP shows up — signal worth flagging
        if random.random() < 0.3:
            ips.append({"ip": random.choice(EXTERNAL_IPS), "classification": "external",
                        "count": random.randint(5, 40)})
        locs = [
            {"city": "Chicago", "country": "United States", "count": random.randint(80, 400)},
            {"city": "Dublin", "country": "Ireland", "count": random.randint(20, 100)},
        ]
        total = sum(b["count"] for b in ips)
        cur.execute("""UPDATE identities
                          SET signin_ips = %s::jsonb,
                              signin_locations = %s::jsonb,
                              signin_total_events_30d = %s,
                              signin_success_count_30d = %s,
                              signin_failure_count_30d = %s
                        WHERE id = %s""",
                    (__import__("json").dumps(ips), __import__("json").dumps(locs),
                     total, int(total * 0.95), int(total * 0.05), id_db))
        bucket_updates += 1
    db._commit()
    log.info("  → %d identities now have aggregated signin buckets", bucket_updates)

    # ── 4. role_assignments.last_used_at (Feature E ARM evidence) ──
    log.info("Seeding role_assignments.last_used_at on existing roles…")
    cur.execute("""SELECT ra.id, ra.role_name, i.risk_level
                     FROM role_assignments ra
                     JOIN identities i ON LOWER(ra.principal_id) = LOWER(i.object_id)
                    WHERE i.organization_id = %s""", (DEMO_ORG_ID,))
    role_rows = cur.fetchall()
    role_updates = 0
    for ra_id, role_name, risk in role_rows:
        # Coverage 90% for critical/high identities' roles, 50% otherwise —
        # reflects ARM Activity Log's natural skew toward active operators.
        if risk in ("critical", "high"):
            should = random.random() < 0.9
        else:
            should = random.random() < 0.5
        if not should:
            continue
        max_days = 14 if risk in ("critical", "high") else 90
        when = NOW - timedelta(days=random.randint(0, max_days),
                               hours=random.randint(0, 23))
        op = random.choice(ARM_OPS)
        if when > NOW - timedelta(days=30):
            status = "active"
        elif when > NOW - timedelta(days=90):
            status = "dormant"
        else:
            status = "stale"
        cur.execute("""UPDATE role_assignments
                          SET last_used_at = %s,
                              last_used_operation = %s,
                              usage_status = %s
                        WHERE id = %s""",
                    (when, op, status, ra_id))
        role_updates += 1
    db._commit()
    log.info("  → %d role assignments now have last_used_at", role_updates)

    # ── 5. Propagate to identity_subscription_access (Phase 1 backfill) ──
    log.info("Propagating ARM last-used to identity_subscription_access…")
    cur.execute("""
        UPDATE identity_subscription_access isa
           SET last_activity = ra.last_used_at
          FROM identities i, role_assignments ra
         WHERE i.id = isa.identity_db_id
           AND i.organization_id = %s
           AND LOWER(ra.principal_id) = LOWER(i.object_id)
           AND LOWER(ra.scope) = LOWER(isa.scope)
           AND LOWER(ra.role_name) = LOWER(isa.rbac_role)
           AND ra.last_used_at IS NOT NULL
           AND (isa.last_activity IS NULL OR ra.last_used_at > isa.last_activity)
    """, (DEMO_ORG_ID,))
    log.info("  → %d ISA rows propagated", cur.rowcount)
    db._commit()

    # ── 6. PIM eligible assignments (PIM tab + Should-Be-PIM combo) ──
    log.info("Seeding pim_eligible_assignments on a privileged subset…")
    # Pick humans + SPNs with critical/high risk to get the PIM tab populated.
    cur.execute("""SELECT id FROM identities
                    WHERE organization_id = %s
                      AND risk_level IN ('critical','high')
                      AND identity_type IN ('human_user','service_principal')
                    LIMIT 15""", (DEMO_ORG_ID,))
    pim_seeds = cur.fetchall()
    pim_count = 0
    eligible_roles = [
        ("Global Administrator", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"),
        ("Privileged Role Administrator", "e8611ab8-c189-46e8-94e1-60213ab1f814"),
        ("Application Administrator", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"),
        ("User Administrator", "fe930be7-5e62-47db-91af-98c3a49a38b1"),
        ("Security Administrator", "194ae4cb-b126-40b2-bd5b-6091b380977d"),
    ]
    for (id_db,) in pim_seeds:
        # 1-2 eligible roles per identity
        for role_name, role_def_id in random.sample(eligible_roles, k=random.randint(1, 2)):
            atype = random.choice(["time_bound_eligible", "permanent_eligible"])
            end_dt = NOW + timedelta(days=180) if atype == "time_bound_eligible" else None
            cur.execute("""INSERT INTO pim_eligible_assignments
                             (identity_db_id, role_name,
                              role_definition_id, directory_scope, assignment_type,
                              start_datetime, end_datetime, member_type, discovered_at)
                           VALUES (%s, %s, %s, '/', %s, %s, %s, 'Direct', NOW())
                           ON CONFLICT DO NOTHING""",
                        (id_db, role_name,
                         f"demo-enhance-{role_def_id}", atype,
                         NOW - timedelta(days=90), end_dt))
            pim_count += 1
    db._commit()
    log.info("  → %d PIM eligible assignments created", pim_count)

    # ── 7. Anomalies (Anomalies tab demo) ──
    log.info("Seeding anomalies for diverse scenarios…")
    cur.execute("""SELECT id, identity_id, display_name, identity_type
                     FROM identities
                    WHERE organization_id = %s AND risk_level IN ('critical','high')
                    LIMIT 8""", (DEMO_ORG_ID,))
    anomaly_targets = cur.fetchall()
    # Latest discovery run for FK
    cur.execute("""SELECT id FROM discovery_runs
                    WHERE organization_id = %s AND status='completed'
                    ORDER BY id DESC LIMIT 1""", (DEMO_ORG_ID,))
    run_id_row = cur.fetchone()
    run_id = run_id_row[0] if run_id_row else None
    anomaly_templates = [
        ("permission_escalation", "high",
         "Privilege escalation: Reader → Contributor",
         "Identity gained Contributor on production subscription within 24h of being added as Reader."),
        ("dormant_reactivation", "medium",
         "Dormant identity re-activated",
         "Identity went 90+ days without sign-in then performed 12 ARM operations in last hour."),
        ("credential_surge", "high",
         "Sudden credential rotation",
         "3 new client secrets created on this SPN in the last 24h (baseline: 0/month)."),
        ("off_hours_pim", "medium",
         "PIM activation at unusual hour",
         "Privileged Role Administrator activated at 03:47 UTC; identity's typical activity window is 13:00-21:00 UTC."),
        ("risk_score_spike", "high",
         "Risk score jumped 4.2 CVSS in one scan",
         "New Owner-on-subscription assignment + new admin app role detected since previous scan."),
    ]
    anomaly_count = 0
    for ident in anomaly_targets[:5]:
        id_db, identity_id, display_name, _itype = ident
        template = anomaly_templates[anomaly_count % len(anomaly_templates)]
        atype, sev, title, desc = template
        cur.execute("""INSERT INTO anomalies
                         (discovery_run_id, anomaly_type, severity,
                          identity_id, identity_name, title, description,
                          details, resolved, resolved_by, created_at,
                          organization_id)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, FALSE, %s, %s, %s)""",
                    (run_id, atype, sev,
                     identity_id, display_name, title, desc,
                     '{"source":"' + DEMO_ENHANCE_TAG + '"}',
                     DEMO_ENHANCE_TAG, NOW - timedelta(hours=random.randint(1, 48)),
                     DEMO_ORG_ID))
        anomaly_count += 1
    db._commit()
    log.info("  → %d anomalies created", anomaly_count)

    cur.close()
    log.info("Demo behavior-evidence seed complete.")


if __name__ == "__main__":
    random.seed(42)  # deterministic for repeatable demos
    main()
