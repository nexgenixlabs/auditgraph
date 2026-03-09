"""
Security Posture Engine

Aggregates security_findings for a cloud connection into a single posture
snapshot stored in identity_security_posture.

Risk score formula:
  risk_score = (high * 10) + (medium * 5) + (low * 2)
"""

import logging

logger = logging.getLogger(__name__)


def compute_security_posture(connection_id, db):
    """Compute and store an aggregated security posture snapshot.

    1. Resolve the latest completed discovery run for this connection.
    2. Count findings by severity from security_findings.
    3. Calculate composite risk_score.
    4. Insert into identity_security_posture.

    Returns dict with risk_score and findings_count.
    """
    from psycopg2.extras import RealDictCursor

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # Find latest completed run
    cursor.execute("""
        SELECT id FROM discovery_runs
        WHERE cloud_connection_id = %s AND status = 'completed'
        ORDER BY id DESC LIMIT 1
    """, (connection_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        logger.debug(f"No completed run for connection {connection_id}, skipping posture")
        return {'risk_score': 0, 'findings_count': 0}

    run_id = row['id']

    # Aggregate findings by severity
    cursor.execute("""
        SELECT
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical_count,
            COUNT(*) FILTER (WHERE severity = 'high')     AS high_count,
            COUNT(*) FILTER (WHERE severity = 'medium')   AS medium_count,
            COUNT(*) FILTER (WHERE severity = 'low')      AS low_count,
            COUNT(*)                                       AS total_count
        FROM security_findings
        WHERE discovery_run_id = %s
    """, (run_id,))
    stats = cursor.fetchone()

    # critical is treated as high for the risk formula
    high_severity = (stats['critical_count'] or 0) + (stats['high_count'] or 0)
    medium_severity = stats['medium_count'] or 0
    low_severity = stats['low_count'] or 0
    findings_count = stats['total_count'] or 0

    risk_score = (high_severity * 10) + (medium_severity * 5) + (low_severity * 2)

    # Insert posture snapshot (append-only for trend tracking)
    cursor.execute("""
        INSERT INTO identity_security_posture
            (connection_id, risk_score, findings_count,
             high_severity, medium_severity, low_severity)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (connection_id, risk_score, findings_count,
          high_severity, medium_severity, low_severity))

    db._commit()
    cursor.close()

    logger.info(f"Security posture for connection {connection_id}: "
                f"risk_score={risk_score}, findings={findings_count} "
                f"(H={high_severity}, M={medium_severity}, L={low_severity})")

    return {
        'risk_score': risk_score,
        'findings_count': findings_count,
        'high_severity': high_severity,
        'medium_severity': medium_severity,
        'low_severity': low_severity,
    }
