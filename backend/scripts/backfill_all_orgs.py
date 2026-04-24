#!/usr/bin/env python3
"""
Backfill AI agent classification + post-processing for ALL affected orgs.

Finds every org that has at least 1 completed discovery run but 0 rows
in agent_classifications, then runs the full classification pipeline
and critical post-processing jobs for each.

This is the permanent fix for the scheduler bug where post-processing
(Tiers 1-5) was gated behind drift pairs — meaning first scans and
some subsequent scans never triggered agent classification.

Safe to run multiple times (idempotent):
  - agent_classifications uses INSERT ... ON CONFLICT (identity_db_id, discovery_run_id)
  - attack_paths, blast_radius, etc. all use upsert or idempotent saves

Regression-safe:
  - Only targets orgs with 0 agent_classifications rows
  - Orgs like org=8 (abcd) with existing classifications are skipped

Usage (from backend/):
    source venv/bin/activate
    PYTHONPATH=. python scripts/backfill_all_orgs.py

    # Backfill a specific org only (even if it already has classifications):
    PYTHONPATH=. python scripts/backfill_all_orgs.py --org-id 10

    # Dry-run (show affected orgs without modifying data):
    PYTHONPATH=. python scripts/backfill_all_orgs.py --dry-run
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
logger = logging.getLogger("backfill_all_orgs")


def ensure_tables_exist():
    """Pre-flight: ensure all required tables exist using admin (DDL-capable) connection.

    This prevents 'permission denied' and 'must be owner' errors when the
    per-org backfill steps run with app-user (NOBYPASSRLS) connections that
    cannot execute DDL (CREATE TABLE / ALTER TABLE).
    """
    logger.info("Pre-flight: ensuring all required tables exist (admin DDL)...")
    admin_db = Database()
    try:
        # Call every _ensure_* method that the backfill pipeline touches.
        # These are idempotent — they skip if the table already exists.
        admin_db._ensure_agent_classifications_table()
        admin_db._ensure_security_findings_table()
        admin_db._ensure_identity_exposures_table()
        admin_db._ensure_attack_paths_table()
        admin_db._ensure_blast_radius_table()
        admin_db._ensure_platform_ops_tables()
        logger.info("Pre-flight: all tables verified.")
    except Exception as e:
        logger.warning("Pre-flight DDL partially failed (tables may already exist): %s", e)
        try:
            admin_db.conn.rollback()
        except Exception:
            pass
    finally:
        admin_db.close()


def find_affected_orgs(db):
    """Find orgs with completed runs but 0 agent_classifications."""
    cursor = db.conn.cursor()
    cursor.execute("""
        SELECT DISTINCT dr.organization_id,
               (SELECT MAX(dr2.id) FROM discovery_runs dr2
                WHERE dr2.organization_id = dr.organization_id
                  AND dr2.status = 'completed'
                  AND COALESCE(dr2.total_identities, 0) > 0) AS latest_run_id,
               (SELECT t.name FROM organizations t
                WHERE t.id = dr.organization_id) AS org_name
        FROM discovery_runs dr
        LEFT JOIN agent_classifications ac
            ON ac.organization_id = dr.organization_id
        WHERE dr.status = 'completed'
          AND COALESCE(dr.total_identities, 0) > 0
          AND ac.id IS NULL
        ORDER BY dr.organization_id
    """)
    rows = cursor.fetchall()
    cursor.close()
    return [
        {"org_id": r[0], "latest_run_id": r[1], "org_name": r[2] or f"org-{r[0]}"}
        for r in rows
        if r[1] is not None
    ]


def _safe_db(org_id):
    """Create a Database connection with organization context and verify RLS is set."""
    db = Database(organization_id=org_id)
    # Belt-and-suspenders: verify the session variable is actually set
    cursor = db.conn.cursor()
    cursor.execute("SELECT current_setting('app.current_organization_id', true)")
    val = cursor.fetchone()[0]
    cursor.close()
    if val != str(org_id):
        logger.warning("RLS context mismatch: expected %s, got %s — re-setting", org_id, val)
        db.set_organization_context(org_id)
    return db


def backfill_org(org_id, run_id):
    """Run the full classification + post-processing pipeline for a single org.

    Each step uses its own Database connection with try/finally cleanup.
    RLS context is re-established before save operations as a safety measure
    against engine-internal rollbacks that could theoretically clear session vars.
    """
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

    # ── 1. Agent Classification (primary objective) ─────────────────
    db = None
    try:
        from app.config import FEATURE_AI_AGENT_GOVERNANCE
        if FEATURE_AI_AGENT_GOVERNANCE:
            from app.services.agent_classifier import classify_tenant
            db = _safe_db(org_id)
            stats = classify_tenant(db, org_id, run_id=run_id)
            results["agent_classification"] = stats
            logger.info(
                "  [agent_classification] org=%d: %d evaluated, %d ai_agent, "
                "%d possible, %d ai_privileged_human",
                org_id, stats.get("total_evaluated", 0),
                stats.get("ai_agent", 0), stats.get("possible_ai_agent", 0),
                stats.get("ai_privileged_human", 0),
            )
        else:
            logger.info("  [agent_classification] FEATURE_AI_AGENT_GOVERNANCE disabled — skipped")
    except Exception as e:
        logger.error("  [agent_classification] org=%d FAILED: %s", org_id, e)
        logger.exception(e)
        results["errors"].append(f"agent_classification: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # ── 2. Security Findings (run-scoped) ───────────────────────────
    db = None
    try:
        from app.engines.security_findings import SecurityFindingsEngine
        db = _safe_db(org_id)
        engine = SecurityFindingsEngine(db)
        findings = engine.analyze(run_id)
        count = len(findings) if findings else 0
        results["security_findings"] = count
        logger.info("  [security_findings] org=%d: %d findings", org_id, count)
    except Exception as e:
        logger.error("  [security_findings] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"security_findings: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # ── 3. Identity Exposure Detection ──────────────────────────────
    db = None
    try:
        from app.engines.identity_exposure_engine import IdentityExposureEngine
        db = _safe_db(org_id)
        engine = IdentityExposureEngine(db)
        exposures = engine.analyze(run_id)
        if exposures:
            # Clear any aborted transaction from engine internals + re-establish RLS
            try:
                db.conn.rollback()
            except Exception:
                pass
            db.set_organization_context(org_id)
            count = db.save_identity_exposures(run_id, exposures)
        else:
            count = 0
        results["identity_exposures"] = count
        logger.info("  [identity_exposures] org=%d: %d exposures", org_id, count)
    except Exception as e:
        logger.error("  [identity_exposures] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"identity_exposures: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # ── 4. Attack Path Analysis ─────────────────────────────────────
    db = None
    try:
        from app.engines.attack_path_engine import AttackPathEngine
        db = _safe_db(org_id)
        engine = AttackPathEngine(db)
        paths = engine.analyze(run_id)
        if paths:
            # Clear any aborted transaction from engine internals + re-establish RLS
            try:
                db.conn.rollback()
            except Exception:
                pass
            db.set_organization_context(org_id)
            count = db.save_attack_paths(run_id, paths)
        else:
            count = 0
        results["attack_paths"] = count
        logger.info("  [attack_paths] org=%d: %d paths", org_id, count)
    except Exception as e:
        logger.error("  [attack_paths] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"attack_paths: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # ── 5. Blast Radius Analysis ────────────────────────────────────
    db = None
    try:
        from app.engines.blast_radius_engine import BlastRadiusEngine
        db = _safe_db(org_id)
        engine = BlastRadiusEngine(db)
        br_results = engine.analyze(run_id)
        if br_results:
            # Clear any aborted transaction from engine internals + re-establish RLS
            try:
                db.conn.rollback()
            except Exception:
                pass
            db.set_organization_context(org_id)
            count = db.save_blast_radius_results(run_id, br_results)
        else:
            count = 0
        results["blast_radius"] = count
        logger.info("  [blast_radius] org=%d: %d results", org_id, count)
    except Exception as e:
        logger.error("  [blast_radius] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"blast_radius: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # ── 6. Posture Score ────────────────────────────────────────────
    db = None
    try:
        db = _safe_db(org_id)
        result = db.compute_posture_score(org_id, run_id)
        score = result.get("posture_score", 0)
        results["posture_score"] = score
        logger.info("  [posture_score] org=%d: score=%d", org_id, score)
    except Exception as e:
        logger.error("  [posture_score] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"posture_score: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # ── 7. Connection-scoped security findings + identity graph ─────
    admin_db = None
    try:
        from app.engines.security_findings_engine import generate_security_findings
        from app.engines.identity_graph_builder import build_identity_graph
        admin_db = Database()
        connections = admin_db.get_cloud_connections(org_id)
        admin_db.close()
        admin_db = None
        conn_count = 0
        for conn in connections:
            if conn.get("status") == "connected":
                db = None
                try:
                    db = _safe_db(org_id)
                    build_identity_graph(conn["id"], db)
                    generate_security_findings(conn["id"], db)
                    conn_count += 1
                finally:
                    if db:
                        try:
                            db.close()
                        except Exception:
                            pass
        logger.info("  [connection_findings] org=%d: processed %d connections", org_id, conn_count)
    except Exception as e:
        logger.error("  [connection_findings] org=%d FAILED: %s", org_id, e)
        results["errors"].append(f"connection_findings: {e}")
    finally:
        if admin_db:
            try:
                admin_db.close()
            except Exception:
                pass

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Backfill AI classification + post-processing for all affected orgs"
    )
    parser.add_argument(
        "--org-id", type=int,
        help="Backfill a specific org (even if it already has classifications)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show affected orgs without modifying data",
    )
    args = parser.parse_args()

    start = time.monotonic()

    # ── Pre-flight: ensure all tables exist via admin DDL ─────────
    ensure_tables_exist()

    # ── Find affected orgs ──────────────────────────────────────────
    admin_db = Database()

    if args.org_id:
        # Force-backfill a specific org regardless of existing classifications
        cursor = admin_db.conn.cursor()
        cursor.execute("""
            SELECT MAX(id) FROM discovery_runs
            WHERE organization_id = %s AND status = 'completed'
              AND COALESCE(total_identities, 0) > 0
        """, (args.org_id,))
        row = cursor.fetchone()
        run_id = row[0] if row else None
        cursor.execute("""
            SELECT name FROM organizations WHERE id = %s
        """, (args.org_id,))
        name_row = cursor.fetchone()
        cursor.close()

        if not run_id:
            logger.error("No completed discovery run with identities for org %d", args.org_id)
            admin_db.close()
            sys.exit(1)

        affected = [{
            "org_id": args.org_id,
            "latest_run_id": run_id,
            "org_name": name_row[0] if name_row else f"org-{args.org_id}",
        }]
    else:
        affected = find_affected_orgs(admin_db)

    # Also check which orgs already have classifications (for regression report)
    cursor = admin_db.conn.cursor()
    cursor.execute("""
        SELECT organization_id, COUNT(*) FROM agent_classifications
        GROUP BY organization_id
        ORDER BY organization_id
    """)
    existing_classifications = {r[0]: r[1] for r in cursor.fetchall()}
    cursor.close()
    admin_db.close()

    if not affected:
        logger.info("No affected orgs found — all orgs with completed runs already have classifications.")
        if existing_classifications:
            logger.info("Existing classifications (regression check):")
            for oid, cnt in sorted(existing_classifications.items()):
                logger.info("  org=%-6d  classifications=%d", oid, cnt)
        return

    logger.info("Found %d org(s) needing backfill:", len(affected))
    for org in affected:
        logger.info("  org_id=%-6d  run_id=%-8d  name=%s", org["org_id"], org["latest_run_id"], org["org_name"])

    if existing_classifications:
        logger.info("Existing classifications (will NOT be modified):")
        for oid, cnt in sorted(existing_classifications.items()):
            logger.info("  org=%-6d  classifications=%d", oid, cnt)

    if args.dry_run:
        logger.info("Dry run — no changes made.")
        return

    # ── Process each org ────────────────────────────────────────────
    all_results = []
    for org in affected:
        logger.info("\n── Processing org %d '%s' (run %d) ──",
                    org["org_id"], org["org_name"], org["latest_run_id"])
        result = backfill_org(org["org_id"], org["latest_run_id"])
        all_results.append(result)

    # ── Summary ─────────────────────────────────────────────────────
    elapsed = round(time.monotonic() - start, 1)
    print()
    logger.info("=" * 72)
    logger.info("BACKFILL SUMMARY")
    logger.info("=" * 72)
    logger.info("%-8s %-20s %-6s %-8s %-8s %-6s %-6s %s",
                "org_id", "org_name", "run", "agents", "possible", "paths", "score", "status")
    logger.info("-" * 72)

    total_agents = 0
    total_errors = 0
    for r in all_results:
        org = next(o for o in affected if o["org_id"] == r["org_id"])
        ac = r["agent_classification"]
        agents = ac.get("ai_agent", 0) if ac else 0
        possible = ac.get("possible_ai_agent", 0) if ac else 0
        total_agents += agents + possible
        err_count = len(r["errors"])
        total_errors += err_count
        status = "OK" if err_count == 0 else f"{err_count} ERR"
        logger.info(
            "%-8d %-20s %-6d %-8d %-8d %-6s %-6s %s",
            r["org_id"],
            (org["org_name"] or "")[:20],
            r["run_id"],
            agents,
            possible,
            r["attack_paths"] if r["attack_paths"] is not None else "ERR",
            r["posture_score"] if r["posture_score"] is not None else "ERR",
            status,
        )
        if r["errors"]:
            for e in r["errors"]:
                logger.error("    -> %s", e)

    logger.info("-" * 72)
    logger.info("Orgs processed:            %d", len(all_results))
    logger.info("Total AI agents classified: %d", total_agents)
    logger.info("Total errors:              %d", total_errors)
    logger.info("Total time:                %.1fs", elapsed)

    # Regression check: verify existing orgs weren't touched
    if existing_classifications and not args.org_id:
        logger.info("\nRegression check — verifying existing classifications untouched:")
        admin_db = Database()
        cursor = admin_db.conn.cursor()
        cursor.execute("""
            SELECT organization_id, COUNT(*) FROM agent_classifications
            GROUP BY organization_id
            ORDER BY organization_id
        """)
        post_counts = {r[0]: r[1] for r in cursor.fetchall()}
        cursor.close()
        admin_db.close()

        all_ok = True
        for oid, pre_count in existing_classifications.items():
            post_count = post_counts.get(oid, 0)
            if post_count != pre_count:
                logger.warning("  REGRESSION: org=%d had %d classifications, now has %d",
                              oid, pre_count, post_count)
                all_ok = False
            else:
                logger.info("  org=%-6d  classifications=%d (unchanged)", oid, pre_count)

        if all_ok:
            logger.info("  All existing classifications intact.")
        else:
            logger.warning("  REGRESSION DETECTED — review above.")

    if total_errors == 0:
        logger.info("\nAll orgs backfilled successfully.")
    else:
        logger.warning("\nSome jobs failed — review errors above.")


if __name__ == "__main__":
    main()
