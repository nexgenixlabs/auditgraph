"""
AttackPathDetector — Detects new attack paths between drift snapshots.

Compares attack_paths between current and previous runs using path_fingerprint.
New fingerprints represent newly discovered attack paths and are appended
as ATTACK_PATH_CREATED events.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

MAX_NEW_EVENTS = 50  # Cap to prevent event bloat


class AttackPathDetector:
    """Detects new attack paths and appends them as drift events."""

    def __init__(self, db):
        self.db = db

    def enrich(self, events: list, current_run_id: int, previous_run_id: int) -> list:
        """Append ATTACK_PATH_CREATED events for new attack paths. Returns the list."""
        if not previous_run_id:
            return events

        try:
            cursor = self.db.conn.cursor()

            # Get fingerprints from previous run
            cursor.execute("""
                SELECT DISTINCT path_fingerprint FROM attack_paths
                WHERE discovery_run_id = %s AND path_fingerprint IS NOT NULL
            """, (previous_run_id,))
            prev_fps = {row[0] for row in cursor.fetchall()}

            # Get fingerprints + details from current run
            cursor.execute("""
                SELECT DISTINCT ON (path_fingerprint)
                       path_fingerprint, path_type, description, severity,
                       risk_score, source_entity_id, source_entity_name, narrative
                FROM attack_paths
                WHERE discovery_run_id = %s AND path_fingerprint IS NOT NULL
                ORDER BY path_fingerprint, risk_score DESC
            """, (current_run_id,))
            current_paths = cursor.fetchall()
            cursor.close()
        except Exception as e:
            logger.warning(f"AttackPathDetector: query failed: {e}")
            return events

        # Find new fingerprints
        new_count = 0
        for row in current_paths:
            fp, path_type, description, severity, risk_score, source_id, source_name, narrative = row
            if fp in prev_fps:
                continue

            if new_count >= MAX_NEW_EVENTS:
                logger.info(f"AttackPathDetector: capped at {MAX_NEW_EVENTS} new events")
                break

            events.append({
                'event_type': 'attack_path_created',
                'severity': 'critical',
                'identity_id': source_id or '',
                'display_name': source_name or 'Unknown',
                'description': description or f'New {path_type} attack path detected',
                'details': {
                    'path_type': path_type,
                    'path_fingerprint': fp,
                    'risk_score': risk_score,
                    'narrative': narrative,
                    'original_severity': severity,
                },
                'timestamp': datetime.utcnow().isoformat(),
            })
            new_count += 1

        if new_count:
            logger.info(f"AttackPathDetector: appended {new_count} new attack path event(s)")
        return events
