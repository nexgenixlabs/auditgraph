#!/usr/bin/env python3
"""
Backfill derived security data for existing discovery runs.

Runs the identity graph builder, security findings engine, and security
posture engine for every cloud connection that has a completed discovery run.

Usage (from backend/):
    source venv/bin/activate
    PYTHONPATH=. python scripts/backfill_security_data.py
"""

import os
import sys
import logging

# Ensure the backend package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Database
from app.engines.identity_graph_builder import build_identity_graph
from app.engines.security_findings_engine import generate_security_findings
from app.engines.security_posture_engine import compute_security_posture

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
logger = logging.getLogger("backfill")


def backfill():
    """Query all cloud connections and run the 3 derived-data pipelines."""
    db = Database()
    cursor = db.conn.cursor()

    # Ensure target tables exist
    for ddl in [
        """CREATE TABLE IF NOT EXISTS identity_graph_edges (
               id SERIAL PRIMARY KEY,
               connection_id INT NOT NULL,
               source_id TEXT NOT NULL,
               target_id TEXT NOT NULL,
               edge_type TEXT NOT NULL,
               created_at TIMESTAMP DEFAULT NOW()
           )""",
        "CREATE INDEX IF NOT EXISTS idx_graph_conn ON identity_graph_edges(connection_id)",
        """CREATE TABLE IF NOT EXISTS identity_security_posture (
               id SERIAL PRIMARY KEY,
               connection_id INT,
               risk_score INT,
               findings_count INT,
               high_severity INT,
               medium_severity INT,
               low_severity INT,
               created_at TIMESTAMP DEFAULT NOW()
           )""",
        "CREATE INDEX IF NOT EXISTS idx_posture_conn ON identity_security_posture(connection_id)",
    ]:
        cursor.execute(ddl)
    db._commit()

    # Get all cloud connections
    cursor.execute("SELECT id, label, cloud FROM cloud_connections ORDER BY id")
    connections = cursor.fetchall()
    cursor.close()

    if not connections:
        logger.warning("No cloud connections found — nothing to backfill")
        db.close()
        return

    logger.info("Found %d cloud connection(s)", len(connections))
    print("-" * 60)

    total_edges = 0
    total_findings = 0

    for conn_id, label, cloud in connections:
        label = label or f"connection-{conn_id}"
        logger.info("Processing connection %d: %s (%s)", conn_id, label, cloud or "unknown")

        # Use a tenant-scoped DB for the connection
        # Look up org_id from the connection
        org_cursor = db.conn.cursor()
        org_cursor.execute("SELECT organization_id FROM cloud_connections WHERE id = %s", (conn_id,))
        org_row = org_cursor.fetchone()
        org_cursor.close()

        if not org_row:
            logger.warning("  Skipping connection %d — no organization_id", conn_id)
            continue

        org_id = org_row[0]
        tenant_db = Database(organization_id=org_id)

        try:
            # 1. Identity Graph
            graph_result = build_identity_graph(conn_id, tenant_db)
            edges = graph_result.get('edge_count', 0)
            total_edges += edges
            logger.info("  Graph edges: %d", edges)

            # 2. Security Findings
            findings_result = generate_security_findings(conn_id, tenant_db)
            findings = findings_result.get('findings_count', 0)
            total_findings += findings
            logger.info("  Security findings: %d", findings)

            # 3. Security Posture
            posture_result = compute_security_posture(conn_id, tenant_db)
            risk_score = posture_result.get('risk_score', 0)
            logger.info("  Posture risk score: %d (H=%d M=%d L=%d)",
                        risk_score,
                        posture_result.get('high_severity', 0),
                        posture_result.get('medium_severity', 0),
                        posture_result.get('low_severity', 0))
        except Exception as e:
            logger.error("  Failed for connection %d: %s", conn_id, e)
        finally:
            tenant_db.close()

        print("-" * 60)

    db.close()

    print()
    logger.info("Backfill complete:")
    logger.info("  Total graph edges: %d", total_edges)
    logger.info("  Total security findings: %d", total_findings)
    logger.info("  Connections processed: %d", len(connections))


if __name__ == "__main__":
    backfill()
