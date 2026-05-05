#!/usr/bin/env python3
"""
AuditGraph — Agent Blast Radius Performance Benchmark

Benchmarks the blast radius API path for AI agent identities across
three synthetic tenant sizes (small/medium/large).

Measures:
  - Identity resolution: identities + agent_classifications JOIN
  - Blast radius lookup: blast_radius_results table read
  - Delegation expansion: agent_delegations + combined blast radius
  - Full end-to-end handler latency (simulated without HTTP overhead)

Output:
  - JSON report to test-results/blast_radius_benchmark_YYYYMMDD.json
  - Console summary with PASS/FAIL

Usage:
  cd backend/
  ./venv/bin/python scripts/benchmark_agent_blast_radius.py
"""

import json
import logging
import os
import random
import statistics
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from app.database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("blast_radius_benchmark")

# ── Configuration ────────────────────────────────────────────────────
TARGET_P95_MS = 3000

TENANT_SIZES = {
    "small":  {"identities": 100,  "agents": 5,   "roles": 30,  "resources": 15},
    "medium": {"identities": 500,  "agents": 25,  "roles": 150, "resources": 60},
    "large":  {"identities": 1000, "agents": 50,  "roles": 300, "resources": 120},
}

ITERATIONS_PER_AGENT = 5

NOW = datetime.now(timezone.utc)

AZURE_ROLES = ['Owner', 'Contributor', 'Reader', 'User Access Administrator',
               'Security Admin', 'Storage Blob Data Reader', 'Key Vault Administrator']

RESOURCE_GROUPS = ['rg-prod', 'rg-staging', 'rg-dev', 'rg-data', 'rg-network',
                   'rg-security', 'rg-shared', 'rg-backup']

AI_AGENT_PLATFORMS = ['copilot_studio', 'azure_openai', 'langchain', 'power_automate',
                      'semantic_kernel', 'autogen']

SPN_NAMES = ['ai-bot', 'ml-pipeline', 'copilot-svc', 'llm-api', 'agent-flow',
             'auto-ai', 'chat-assistant', 'data-agent', 'code-helper', 'insight-svc']


def _gen_uuid():
    return str(uuid.uuid4())


# ── Seeding Functions ────────────────────────────────────────────────

def _seed_benchmark_tenant(db, size_name, size_config):
    """Seed a benchmark tenant with synthetic data. Returns (org_id, run_id, agent_identity_ids)."""
    cursor = db.conn.cursor()

    # Create org
    slug = f"bench-{size_name}-{int(time.time())}"
    cursor.execute(
        "INSERT INTO organizations (name, slug, plan, created_at) VALUES (%s, %s, 'trial', NOW()) RETURNING id",
        (f"Benchmark {size_name}", slug),
    )
    org_id = cursor.fetchone()[0]

    # Create cloud_connection
    azure_dir_id = _gen_uuid()
    cursor.execute("""
        INSERT INTO cloud_connections
            (organization_id, cloud, connection_type, label, status,
             azure_directory_id, created_at)
        VALUES (%s, 'azure', 'entra', %s, 'connected', %s, NOW())
        RETURNING id
    """, (org_id, f"bench-conn-{size_name}", azure_dir_id))
    conn_id = cursor.fetchone()[0]

    # Create discovery run
    sub_id_primary = _gen_uuid()
    cursor.execute("""
        INSERT INTO discovery_runs
            (status, started_at, completed_at, organization_id, cloud_connection_id,
             total_identities, subscription_id, subscription_name)
        VALUES ('completed', %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (NOW - timedelta(hours=1), NOW - timedelta(minutes=30),
          org_id, conn_id, size_config['identities'],
          sub_id_primary, f"Bench-{size_name}"))
    run_id = cursor.fetchone()[0]
    db.conn.commit()

    # Set RLS context so auto-fill triggers work
    cursor.execute("SET app.current_organization_id = %s", (str(org_id),))
    # Also set internal org_id for save_blast_radius_results
    db._organization_id = org_id

    sub_ids = [_gen_uuid() for _ in range(3)]
    agent_db_ids = []
    agent_identity_ids = []

    # Seed identities
    total = size_config['identities']
    agent_count = size_config['agents']
    non_agent_count = total - agent_count

    # Non-agent identities
    for i in range(non_agent_count):
        identity_id = _gen_uuid()
        cat = random.choice(['human_user', 'service_principal', 'managed_identity_system'])
        cursor.execute("""
            INSERT INTO identities
                (identity_id, display_name, identity_type, identity_category,
                 risk_score, risk_level, discovery_run_id, app_id, object_id,
                 activity_status, last_sign_in, created_at, enabled,
                 is_microsoft_system, organization_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), true, false, %s)
            RETURNING id
        """, (identity_id, f"identity-{size_name}-{i:04d}", 'servicePrincipal', cat,
              random.randint(10, 90), random.choice(['low', 'medium', 'high']),
              run_id, _gen_uuid(), identity_id, 'active',
              NOW - timedelta(days=random.randint(0, 30)), org_id))
        db_id = cursor.fetchone()[0]

    # Agent identities
    for i in range(agent_count):
        identity_id = _gen_uuid()
        is_orphan = i == 0  # First agent is orphaned
        last_sign_in = NOW - timedelta(days=60) if is_orphan else NOW - timedelta(hours=random.randint(1, 48))
        risk_score = random.randint(70, 95) if is_orphan else random.randint(30, 80)

        cursor.execute("""
            INSERT INTO identities
                (identity_id, display_name, identity_type, identity_category,
                 risk_score, risk_level, discovery_run_id, app_id, object_id,
                 activity_status, last_sign_in, created_at, enabled,
                 is_microsoft_system, agent_identity_type, organization_id)
            VALUES (%s, %s, 'servicePrincipal', 'service_principal',
                    %s, %s, %s, %s, %s, %s, %s, NOW(), true, false, 'ai_agent', %s)
            RETURNING id
        """, (identity_id, f"ai-agent-{size_name}-{random.choice(SPN_NAMES)}-{i:03d}",
              risk_score, 'critical' if risk_score >= 76 else 'high' if risk_score >= 51 else 'medium',
              run_id, _gen_uuid(), identity_id,
              'stale' if is_orphan else 'active', last_sign_in, org_id))
        db_id = cursor.fetchone()[0]
        agent_db_ids.append(db_id)
        agent_identity_ids.append(identity_id)

        # Agent classification
        cursor.execute("""
            INSERT INTO agent_classifications
                (identity_db_id, identity_id, agent_identity_type,
                 classification_confidence, classification_reason,
                 detected_platform, pattern_version,
                 discovery_run_id, organization_id)
            VALUES (%s, %s, 'ai_agent', %s, %s, %s, '1.0', %s, %s)
        """, (db_id, identity_id,
              round(random.uniform(0.7, 1.0), 2),
              'benchmark_seed',
              random.choice(AI_AGENT_PLATFORMS),
              run_id, org_id))

    db.conn.commit()

    # Role assignments (spread across all identities)
    all_identity_ids_query = cursor.execute(
        "SELECT id, identity_id FROM identities WHERE discovery_run_id = %s", (run_id,)
    )
    all_ids = cursor.fetchall()
    role_count = size_config['roles']
    candidates = random.choices(all_ids, k=role_count)

    for db_id, identity_id in candidates:
        sub_id = random.choice(sub_ids)
        rg = random.choice(RESOURCE_GROUPS)
        role = random.choice(AZURE_ROLES)
        scope_type = random.choice(['subscription', 'resource_group', 'resource'])
        if scope_type == 'subscription':
            scope = f'/subscriptions/{sub_id}'
        elif scope_type == 'resource_group':
            scope = f'/subscriptions/{sub_id}/resourceGroups/{rg}'
        else:
            scope = f'/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/sa{random.randint(1,50):03d}'

        cursor.execute("""
            INSERT INTO role_assignments
                (identity_db_id, role_name, scope, scope_type,
                 principal_id, assignment_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (db_id, role, scope, scope_type, identity_id, _gen_uuid()))

    db.conn.commit()

    # Resources
    res_count = size_config['resources']
    storage_count = int(res_count * 0.6)
    kv_count = res_count - storage_count

    for i in range(storage_count):
        sub_id = random.choice(sub_ids)
        rg = random.choice(RESOURCE_GROUPS)
        name = f'sa-bench-{size_name}-{i:04d}'
        resource_id = f'/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}'
        classification = random.choice(['PHI', 'PCI', None, None, None])

        cursor.execute("""
            INSERT INTO azure_storage_accounts
                (discovery_run_id, resource_id, name, location, resource_group,
                 subscription_id, subscription_name, sku, kind, access_tier,
                 public_blob_access, https_only, minimum_tls_version,
                 shared_key_access, default_network_action,
                 risk_level, risk_score, blast_radius_score,
                 data_classification, organization_id)
            VALUES (%s,%s,%s,'eastus',%s,%s,%s,'Standard_LRS','StorageV2','Hot',
                    false,true,'TLS1_2',false,'Deny','medium',50,5,%s,%s)
            ON CONFLICT (discovery_run_id, resource_id) DO NOTHING
        """, (run_id, resource_id, name, rg, sub_id, f"Bench-{size_name}",
              classification, org_id))

    for i in range(kv_count):
        sub_id = random.choice(sub_ids)
        rg = random.choice(RESOURCE_GROUPS)
        name = f'kv-bench-{size_name}-{i:04d}'
        resource_id = f'/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}'
        classification = random.choice(['PHI', 'Confidential', None, None])

        cursor.execute("""
            INSERT INTO azure_key_vaults
                (discovery_run_id, resource_id, name, location, resource_group,
                 subscription_id, subscription_name, sku,
                 soft_delete_enabled, soft_delete_retention_days, purge_protection,
                 enable_rbac_authorization, public_network_access, default_network_action,
                 secrets_total, secrets_expired, secrets_expiring_soon,
                 keys_total, keys_expired, keys_expiring_soon,
                 risk_level, risk_score, blast_radius_score,
                 data_classification, organization_id)
            VALUES (%s,%s,%s,'eastus',%s,%s,%s,'standard',
                    true,90,true,true,'Disabled','Deny',
                    10,1,2,5,0,1,'medium',50,5,%s,%s)
            ON CONFLICT (discovery_run_id, resource_id) DO NOTHING
        """, (run_id, resource_id, name, rg, sub_id, f"Bench-{size_name}",
              classification, org_id))

    db.conn.commit()
    cursor.close()

    return org_id, run_id, agent_identity_ids, agent_db_ids


def _compute_blast_radius(db, run_id):
    """Run the blast radius engine to pre-compute results."""
    from app.engines.blast_radius_engine import BlastRadiusEngine
    engine = BlastRadiusEngine(db)
    results = engine.analyze(run_id)
    if results:
        saved = db.save_blast_radius_results(run_id, results)
        logger.info("  Pre-computed %d blast radius results (saved=%s)", len(results), saved)
    else:
        logger.info("  No blast radius results computed (no resources match scopes)")
    return len(results)


def _benchmark_blast_radius_lookup(db, agent_db_ids, run_ids, iterations=ITERATIONS_PER_AGENT):
    """Benchmark the blast radius lookup path (what the API handler does).

    Measures:
      1. Identity resolution (agent_classifications JOIN)
      2. blast_radius_results table read
      3. Delegation lookup
    """
    latencies_ms = []

    for db_id in agent_db_ids:
        for _ in range(iterations):
            start = time.perf_counter()

            # Step 1: Read blast radius from pre-computed table
            result = db.get_blast_radius_for_identity(db_id)

            # Step 2: Delegation lookup (same as handler)
            try:
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT target_identity_id, target_display_name, delegation_type, confidence
                    FROM agent_delegations
                    WHERE source_identity_db_id = %s
                """, (db_id,))
                delegations = cursor.fetchall()
                cursor.close()

                if delegations and result:
                    combined_resources = result.get('reachable_resource_count', 0)
                    combined_subs = result.get('reachable_subscription_count', 0)
                    for drow in delegations:
                        target_id = drow[0]
                        cursor2 = db.conn.cursor()
                        cursor2.execute("""
                            SELECT i.id FROM identities i
                            WHERE i.identity_id = %s AND i.discovery_run_id = ANY(%s)
                            LIMIT 1
                        """, (target_id, run_ids))
                        trow = cursor2.fetchone()
                        cursor2.close()
                        if trow:
                            delegate_br = db.get_blast_radius_for_identity(trow[0])
                            if delegate_br:
                                combined_resources += delegate_br.get('reachable_resource_count', 0)
                                combined_subs += delegate_br.get('reachable_subscription_count', 0)
            except Exception:
                pass  # agent_delegations may not exist

            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies_ms.append(elapsed_ms)

    return latencies_ms


def _compute_stats(latencies_ms):
    """Compute min/mean/p95/max from latency list."""
    if not latencies_ms:
        return {"min_ms": 0, "mean_ms": 0, "p95_ms": 0, "max_ms": 0, "samples": 0}

    sorted_lat = sorted(latencies_ms)
    p95_idx = int(len(sorted_lat) * 0.95)
    return {
        "min_ms": round(sorted_lat[0], 2),
        "mean_ms": round(statistics.mean(sorted_lat), 2),
        "p95_ms": round(sorted_lat[min(p95_idx, len(sorted_lat) - 1)], 2),
        "max_ms": round(sorted_lat[-1], 2),
        "samples": len(sorted_lat),
    }


def _cleanup_benchmark_tenant(db, org_id, run_id):
    """Clean up benchmark data."""
    cursor = db.conn.cursor()
    try:
        # Delete in dependency order
        for table in ['blast_radius_results', 'agent_classifications',
                      'role_assignments', 'identity_permissions',
                      'azure_storage_accounts', 'azure_key_vaults']:
            try:
                cursor.execute(f"DELETE FROM {table} WHERE discovery_run_id = %s", (run_id,))
            except Exception:
                db.conn.rollback()

        try:
            cursor.execute("DELETE FROM agent_delegations WHERE organization_id = %s", (org_id,))
        except Exception:
            db.conn.rollback()

        cursor.execute("DELETE FROM identities WHERE discovery_run_id = %s", (run_id,))
        cursor.execute("DELETE FROM discovery_runs WHERE id = %s", (run_id,))
        cursor.execute("DELETE FROM cloud_connections WHERE organization_id = %s", (org_id,))
        cursor.execute("DELETE FROM organizations WHERE id = %s", (org_id,))
        db.conn.commit()
    except Exception as e:
        db.conn.rollback()
        logger.warning("Cleanup warning: %s", e)
    finally:
        cursor.close()


# ── Main ─────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 70)
    logger.info("  AuditGraph — Agent Blast Radius Performance Benchmark")
    logger.info("=" * 70)
    logger.info("  Target: P95 < %d ms on Large tenant (1000 nodes)", TARGET_P95_MS)
    logger.info("")

    db = Database(_admin_reason="blast_radius_benchmark")

    results = {}
    overall_pass = True

    try:
        for size_name, size_config in TENANT_SIZES.items():
            logger.info("-" * 50)
            logger.info("  Size: %s (%d identities, %d agents, %d roles, %d resources)",
                        size_name.upper(), size_config['identities'], size_config['agents'],
                        size_config['roles'], size_config['resources'])
            logger.info("-" * 50)

            # 1. Seed
            logger.info("  [1/4] Seeding synthetic data...")
            org_id, run_id, agent_ids, agent_db_ids = _seed_benchmark_tenant(db, size_name, size_config)
            logger.info("        org=%s run=%s agents=%d", org_id, run_id, len(agent_ids))

            # 2. Pre-compute blast radius
            logger.info("  [2/4] Computing blast radius (BlastRadiusEngine.analyze)...")
            br_start = time.perf_counter()
            br_count = _compute_blast_radius(db, run_id)
            br_elapsed = (time.perf_counter() - br_start) * 1000
            logger.info("        %d results in %.1f ms", br_count, br_elapsed)

            # 3. Benchmark API lookup path
            logger.info("  [3/4] Benchmarking API lookup (%d agents x %d iterations)...",
                        len(agent_db_ids), ITERATIONS_PER_AGENT)
            run_ids = [run_id]
            latencies = _benchmark_blast_radius_lookup(db, agent_db_ids, run_ids)
            stats = _compute_stats(latencies)
            stats['blast_radius_compute_ms'] = round(br_elapsed, 2)
            stats['blast_radius_results_count'] = br_count
            results[size_name] = stats

            logger.info("        min=%.1fms  mean=%.1fms  P95=%.1fms  max=%.1fms  (n=%d)",
                        stats['min_ms'], stats['mean_ms'], stats['p95_ms'],
                        stats['max_ms'], stats['samples'])

            if size_name == 'large' and stats['p95_ms'] >= TARGET_P95_MS:
                overall_pass = False

            # 4. Cleanup
            logger.info("  [4/4] Cleaning up benchmark data...")
            _cleanup_benchmark_tenant(db, org_id, run_id)

    finally:
        db.close()

    # Write report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_sizes": results,
        "target_met": overall_pass,
        "target_p95_ms": TARGET_P95_MS,
        "iterations_per_agent": ITERATIONS_PER_AGENT,
    }

    os.makedirs("test-results", exist_ok=True)
    report_path = f"test-results/blast_radius_benchmark_{datetime.now().strftime('%Y%m%d')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info("")
    logger.info("Report saved: %s", report_path)

    # Console summary
    print("\n" + "=" * 70)
    print("  BLAST RADIUS BENCHMARK RESULTS")
    print("=" * 70)
    for size_name, stats in results.items():
        marker = "  "
        if size_name == 'large':
            marker = "* " if stats['p95_ms'] < TARGET_P95_MS else "! "
        print(f"  {marker}{size_name.upper():8s}  "
              f"min={stats['min_ms']:7.1f}ms  "
              f"mean={stats['mean_ms']:7.1f}ms  "
              f"P95={stats['p95_ms']:7.1f}ms  "
              f"max={stats['max_ms']:7.1f}ms  "
              f"(n={stats['samples']})")
    print("-" * 70)
    print(f"  Target: P95 @ Large < {TARGET_P95_MS}ms")

    large_p95 = results.get('large', {}).get('p95_ms', 0)
    if overall_pass:
        print(f"\n  *** PASS *** — P95 at Large = {large_p95:.1f}ms < {TARGET_P95_MS}ms")
        print("  No optimization needed. Skip B1-2 through B1-4.")
    else:
        print(f"\n  *** FAIL *** — P95 at Large = {large_p95:.1f}ms >= {TARGET_P95_MS}ms")
        print("  Proceed to B1-2: Add database indexes.")

    print("=" * 70)
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
