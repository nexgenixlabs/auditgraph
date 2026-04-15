"""
IdentityResurrectionDetector — Detects resurrected identities in drift events.

For each identity_added event, checks if a previously soft-deleted identity
matches by app_id (preferred) or display_name + identity_category (fallback).
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class IdentityResurrectionDetector:
    """Detects identity resurrections and appends events."""

    def __init__(self, db):
        self.db = db

    def enrich(self, events: list, current_run_id: int) -> list:
        """Check identity_added events for resurrection. Appends IDENTITY_RESURRECTION events."""
        added_events = [e for e in events if e.get('event_type') == 'identity_added']
        if not added_events:
            return events

        resurrection_events = []
        for event in added_events:
            details = event.get('details', {})
            identity_id = event.get('identity_id', '')
            display_name = event.get('display_name', '')
            app_id = details.get('app_id', '')
            category = details.get('identity_category', '')

            match = None

            # Try app_id match first (most specific, for SPNs)
            if app_id:
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        SELECT identity_id, display_name, deleted_at
                        FROM identities
                        WHERE deleted_at IS NOT NULL
                          AND app_id = %s
                          AND identity_id != %s
                        ORDER BY deleted_at DESC
                        LIMIT 1
                    """, (app_id, identity_id))
                    row = cursor.fetchone()
                    cursor.close()
                    if row:
                        match = {
                            'previous_identity_id': row[0],
                            'previous_display_name': row[1],
                            'deleted_at': row[2].isoformat() if row[2] else None,
                            'match_type': 'app_id',
                        }
                except Exception as e:
                    logger.debug(f"IdentityResurrectionDetector: app_id query failed: {e}")

            # Fallback: display_name + category match
            if not match and display_name and category:
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        SELECT identity_id, display_name, deleted_at
                        FROM identities
                        WHERE deleted_at IS NOT NULL
                          AND display_name = %s
                          AND identity_category = %s
                          AND identity_id != %s
                        ORDER BY deleted_at DESC
                        LIMIT 1
                    """, (display_name, category, identity_id))
                    row = cursor.fetchone()
                    cursor.close()
                    if row:
                        match = {
                            'previous_identity_id': row[0],
                            'previous_display_name': row[1],
                            'deleted_at': row[2].isoformat() if row[2] else None,
                            'match_type': 'display_name_category',
                        }
                except Exception as e:
                    logger.debug(f"IdentityResurrectionDetector: name/category query failed: {e}")

            if match:
                resurrection_events.append({
                    'event_type': 'identity_resurrection',
                    'severity': 'high',
                    'identity_id': identity_id,
                    'display_name': display_name,
                    'description': (
                        f'{display_name} was previously deleted '
                        f'({match["deleted_at"] or "unknown date"}) and has reappeared'
                    ),
                    'details': {
                        'identity_category': category,
                        'resurrection': match,
                    },
                    'timestamp': datetime.utcnow().isoformat(),
                })

        events.extend(resurrection_events)
        if resurrection_events:
            logger.info(f"IdentityResurrectionDetector: {len(resurrection_events)} resurrection(s) detected")
        return events
