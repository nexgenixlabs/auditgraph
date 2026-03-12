"""
BlastRadiusCalculator — Correlates blast radius data with drift events.

Looks up blast_radius_results for identities referenced in drift events
and annotates events with blast radius metadata.
"""

import logging

logger = logging.getLogger(__name__)


class BlastRadiusCalculator:
    """Enriches drift events with blast radius data from the latest analysis."""

    def __init__(self, db):
        self.db = db

    def enrich(self, events: list, current_run_id: int) -> list:
        """Mutate events in-place with blast radius data. Returns the list."""
        # Collect unique identity_ids (Azure GUID strings) from events
        ext_ids = set()
        for event in events:
            iid = event.get('identity_id')
            if iid:
                ext_ids.add(iid)

        if not ext_ids:
            return events

        # Bulk query: JOIN through identities table to map GUID → blast radius
        # blast_radius_results.identity_id is an INTEGER (DB PK from identities.id),
        # but drift events use Azure GUID strings in identity_id
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT i.identity_id AS ext_id,
                       br.reachable_resource_count,
                       br.sensitive_resource_count,
                       br.reachable_subscription_count,
                       br.risk_score,
                       br.identity_exposure_level
                FROM blast_radius_results br
                JOIN identities i ON i.id = br.identity_id
                WHERE br.discovery_run_id = %s
                  AND i.identity_id = ANY(%s)
            """, (current_run_id, list(ext_ids)))
            rows = cursor.fetchall()
            cursor.close()
        except Exception as e:
            logger.warning(f"BlastRadiusCalculator: query failed: {e}")
            return events

        # Build lookup map
        br_map = {}
        for row in rows:
            br_map[row[0]] = {
                'resource_count': row[1] or 0,
                'sensitive_resource_count': row[2] or 0,
                'subscriptions_affected': row[3] or 0,
                'risk_score': row[4] or 0,
                'exposure_level': (row[5] or 'unknown').lower(),
            }

        # Annotate events
        enriched = 0
        for event in events:
            iid = event.get('identity_id')
            if iid and iid in br_map:
                event.setdefault('details', {})['blast_radius'] = br_map[iid]
                enriched += 1

        if enriched:
            logger.info(f"BlastRadiusCalculator: annotated {enriched} event(s) with blast radius data")
        return events
