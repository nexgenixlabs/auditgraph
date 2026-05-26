#!/usr/bin/env python3
"""
Backfill post-processing for orgs whose first scan missed Tier 1-5 jobs.

Prior to the first-scan gate fix in scheduler.py, orgs with only one
completed discovery run would exit _send_change_notification_if_needed()
early, skipping agent classification, attack paths, posture scoring,
security findings, blast radius, and all other post-processing.

This script:
  1. Finds all orgs with exactly 1 completed discovery run (affected orgs)
  2. Re-runs the critical post-processing pipeline for each
  3. Prints a summary of results

Safe to run multiple times — all writes use INSERT ... ON CONFLICT or
are idempotent UPSERTs.

Usage (from backend/):
    source venv/bin/activate
    PYTHONPATH=. python scripts/backfill_first_scan_orgs.py

    # Backfill a specific org only:
    PYTHONPATH=. python scripts/backfill_first_scan_orgs.py --org-id 11

    # Dry-run (show affected orgs without modifying data):
    PYTHONPATH=. python scripts/backfill_first_scan_orgs.py --dry-run
"""

import argparse
import os
import sys
import logging
import time

# Ensure the backend package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("backfill_first_scan")


def find_affected_orgs(db):
    """Find orgs with exactly 1 completed discovery run (missed post-processing)."""
    cursor = db.conn.cursor()
    cursor.execute("""
        SELECT organization_id,
               COUNT(*) AS run_count,
               MAX(id)  AS latest_run_id
        FROM discovery_runs
        WHERE status = 'completed'
          AND COALESCE(total_identities, 0) > 0
        GROUP BY organization_id
        HAVING COUNT(*) = 1
        ORDER BY organization_id
    """)
    rows = cursor.fetchall()
    cursor.close()
    return [
        {"org_id": r[0], "run_count": r[1], "latest_run_id": r[2]}
        for r in rows
    ]


def backfill_org(org_id, run_id):
    """Run the critical post-processing pipeline for a single org+run."""
    results = {
        "org_id": org_id,
        "run_id": run_id,
        "agent_classification": None,
        "security_findings": None,
        "identity_exposures": None,
        "attack_paths": None,
        "blast_radius": None,
        "posture_score": None,
        "errors": [],
    }

    # ── 1. Agent Classification ─────────────────────────────────────
    try:
        from app.config import FEATURE_AI_AGENT_GOVERNANCE
        if FEATURE_AI_AGENT_GOVERNANCE:
            from app.services.agent_classifier import classify_tenant
            db = Database(organization_id=org_id)
            stats = classify_tenant(db, org_id, run_id=run_id)
            db.close()
            results["agent_classification"] = stats
            logger.info(
                "  [agent_classification] org=%d: %d evaluated, %d ai_agent, %d possible",
                org_id, stats.get("total_evaluated", 0),
                stats.get("ai_agent", 0), stats.get("possible_ai_agent", 0),
            )
        else:
            logger.info("  [agent_classification] FEATURE_AI_AGENT_GOVERNANCE disabled — skipped")
    except Exception as e:
        logger.error("  [agent_classification] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"agent_classification: {e}")

    # ── 2. Security Findings (run-scoped) ───────────────────────────
    try:
        from app.engines.security_findings import SecurityFindingsEngine
        db = Database(organization_id=org_id)
        engine = SecurityFindingsEngine(db)
        findings = engine.analyze(run_id)
        count = len(findings) if findings else 0
        db.close()
        results["security_findings"] = count
        logger.info("  [security_findings] org=%d: %d findings", org_id, count)
    except Exception as e:
        logger.error("  [security_findings] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"security_findings: {e}")

    # ── 3. Identity Exposure Detection ──────────────────────────────
    try:
        from app.engines.identity_exposure_engine import IdentityExposureEngine
        db = Database(organization_id=org_id)
        engine = IdentityExposureEngine(db)
        exposures = engine.analyze(run_id)
        if exposures:
            count = db.save_identity_exposures(run_id, exposures)
        else:
            count = 0
        db.close()
        results["identity_exposures"] = count
        logger.info("  [identity_exposures] org=%d: %d exposures", org_id, count)
    except Exception as e:
        logger.error("  [identity_exposures] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"identity_exposures: {e}")

    # ── 4. Attack Path Analysis ─────────────────────────────────────
    try:
        from app.engines.attack_path_engine import AttackPathEngine
        db = Database(organization_id=org_id)
        engine = AttackPathEngine(db)
        paths = engine.analyze(run_id)
        if paths:
            count = db.save_attack_paths(run_id, paths)
        else:
            count = 0
        db.close()
        results["attack_paths"] = count
        logger.info("  [attack_paths] org=%d: %d paths", org_id, count)
    except Exception as e:
        logger.error("  [attack_paths] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"attack_paths: {e}")

    # ── 5. Blast Radius Analysis ────────────────────────────────────
    try:
        from app.engines.blast_radius_engine import BlastRadiusEngine
        db = Database(organization_id=org_id)
        engine = BlastRadiusEngine(db)
        br_results = engine.analyze(run_id)
        if br_results:
            count = db.save_blast_radius_results(run_id, br_results)
        else:
            count = 0
        db.close()
        results["blast_radius"] = count
        logger.info("  [blast_radius] org=%d: %d results", org_id, count)
    except Exception as e:
        logger.error("  [blast_radius] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"blast_radius: {e}")

    # ── 6. Posture Score ────────────────────────────────────────────
    try:
        db = Database(organization_id=org_id)
        result = db.compute_posture_score(org_id, run_id)
        score = result.get("posture_score", 0)
        db.close()
        results["posture_score"] = score
        logger.info("  [posture_score] org=%d: score=%d", org_id, score)
    except Exception as e:
        logger.error("  [posture_score] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"posture_score: {e}")

    # ── 7. Connection-scoped security findings engine ───────────────
    try:
        from app.engines.security_findings_engine import generate_security_findings
        from app.engines.identity_graph_builder import build_identity_graph
        admin_db = Database()
        connections = admin_db.get_cloud_connections(org_id)
        admin_db.close()
        for conn in connections:
            if conn.get("status") == "connected":
                db = Database(organization_id=org_id)
                build_identity_graph(conn["id"], db)
                generate_security_findings(conn["id"], db)
                db.close()
        logger.info("  [connection_findings] org=%d: processed %d connections",
                     org_id, len(connections))
    except Exception as e:
        logger.error("  [connection_findings] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"connection_findings: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Backfill post-processing for first-scan orgs")
    parser.add_argument("--org-id", type=int, help="Backfill a specific org only")
    parser.add_argument("--dry-run", action="store_true", help="Show affected orgs without modifying data")
    args = parser.parse_args()

    start = time.monotonic()

    # Find affected orgs
    admin_db = Database()
    if args.org_id:
        # Verify the org exists and has a completed run
        cursor = admin_db.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE organization_id = %s AND status = 'completed'
              AND COALESCE(total_identities, 0) > 0
            ORDER BY id DESC LIMIT 1
        """, (args.org_id,))
        row = cursor.fetchone()
        cursor.close()
        if not row:
            logger.error("No completed discovery run with identities for org %d", args.org_id)
            admin_db.close()
            sys.exit(1)
        affected = [{"org_id": args.org_id, "run_count": 1, "latest_run_id": row[0]}]
    else:
        affected = find_affected_orgs(admin_db)
    admin_db.close()

    if not affected:
        logger.info("No affected orgs found — all orgs have 2+ completed runs or have been backfilled.")
        return

    logger.info("Found %d affected org(s):", len(affected))
    for org in affected:
        logger.info("  org_id=%-6d  run_id=%-8d", org["org_id"], org["latest_run_id"])

    if args.dry_run:
        logger.info("Dry run — no changes made.")
        return

    # Process each org
    all_results = []
    for org in affected:
        logger.info("\n── Processing org %d (run %d) ──", org["org_id"], org["latest_run_id"])
        result = backfill_org(org["org_id"], org["latest_run_id"])
        all_results.append(result)

    # Summary
    elapsed = round(time.monotonic() - start, 1)
    logger.info("\n" + "=" * 60)
    logger.info("BACKFILL SUMMARY")
    logger.info("=" * 60)
    logger.info("Orgs processed:  %d", len(all_results))
    logger.info("Total time:      %.1fs", elapsed)
    logger.info("-" * 60)

    total_agents = 0
    total_errors = 0
    for r in all_results:
        ac = r["agent_classification"]
        agents = ac.get("ai_agent", 0) if ac else 0
        possible = ac.get("possible_ai_agent", 0) if ac else 0
        total_agents += agents + possible
        err_count = len(r["errors"])
        total_errors += err_count
        status = "OK" if err_count == 0 else f"{err_count} ERROR(S)"
        logger.info(
            "  org=%-6d  run=%-8d  agents=%-4d  possible=%-4d  "
            "paths=%-4s  score=%-4s  [%s]",
            r["org_id"], r["run_id"], agents, possible,
            r["attack_paths"] if r["attack_paths"] is not None else "ERR",
            r["posture_score"] if r["posture_score"] is not None else "ERR",
            status,
        )
        if r["errors"]:
            for e in r["errors"]:
                logger.error("    -> %s", e)

    logger.info("-" * 60)
    logger.info("Total AI agents classified: %d", total_agents)
    logger.info("Total errors:              %d", total_errors)
    if total_errors == 0:
        logger.info("All orgs backfilled successfully.")
    else:
        logger.warning("Some jobs failed — review errors above.")


if __name__ == "__main__":
    main()
