"""
Zombie Persona Detector — finds linked identity pairs where one account
is disabled/deleted but the correlated account is still active.

A "zombie persona" is a human whose access was supposedly terminated
(disabled account) but who retains access via a correlated active account
(e.g., harish.s@ disabled + ep.harish.s@ still active).
"""
import logging
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


class ZombiePersonaDetector:
    """Detect zombie persona patterns from identity_links."""

    def __init__(self, db):
        self.db = db

    def detect(self, run_id):
        """Find linked identity pairs where one is disabled but the other is active.

        Returns a list of anomaly dicts suitable for db.save_anomalies().
        """
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                SELECT DISTINCT ON (hi.id)
                    hi.id AS human_id,
                    hi.display_name AS human_name,
                    i_disabled.id AS disabled_id,
                    i_disabled.display_name AS disabled_name,
                    i_disabled.object_id AS disabled_oid,
                    i_disabled.upn AS disabled_upn,
                    i_active.id AS active_id,
                    i_active.display_name AS active_name,
                    i_active.object_id AS active_oid,
                    i_active.upn AS active_upn,
                    i_active.risk_score AS active_risk,
                    i_active.tier AS active_tier,
                    il_disabled.link_method,
                    il_disabled.link_confidence
                FROM identity_links il_disabled
                JOIN identity_links il_active
                    ON il_disabled.human_identity_id = il_active.human_identity_id
                    AND il_disabled.identity_db_id != il_active.identity_db_id
                JOIN identities i_disabled ON i_disabled.id = il_disabled.identity_db_id
                JOIN identities i_active ON i_active.id = il_active.identity_db_id
                JOIN human_identities hi ON hi.id = il_disabled.human_identity_id
                WHERE (i_disabled.enabled = FALSE OR i_disabled.deleted_at IS NOT NULL)
                  AND i_active.enabled = TRUE
                  AND i_active.deleted_at IS NULL
                ORDER BY hi.id, COALESCE(i_active.risk_score, 0) DESC
            """)
            pairs = cursor.fetchall()
        except Exception as e:
            logger.error(f"Zombie persona query failed: {e}")
            return []
        finally:
            cursor.close()

        if not pairs:
            return []

        anomalies = []
        for p in pairs:
            tier = p.get('active_tier') or ''
            if tier in ('T0', 'T1'):
                severity = 'critical'
            elif tier == 'T2':
                severity = 'high'
            else:
                severity = 'medium'

            anomalies.append({
                'identity_db_id': p['active_id'],
                'identity_name': p['active_name'] or p['active_upn'] or 'Unknown',
                'anomaly_type': 'zombie_persona',
                'severity': severity,
                'description': (
                    f"Zombie persona detected: {p['disabled_name'] or p['disabled_upn'] or 'Unknown'} "
                    f"is disabled/deleted but correlated account "
                    f"{p['active_name'] or p['active_upn'] or 'Unknown'} remains active "
                    f"(linked via {p['link_method']}, confidence {p['link_confidence']}%)"
                ),
                'details': {
                    'human_identity_id': p['human_id'],
                    'human_name': p['human_name'],
                    'disabled_account': {
                        'id': p['disabled_id'],
                        'object_id': p['disabled_oid'],
                        'display_name': p['disabled_name'],
                        'upn': p['disabled_upn'],
                    },
                    'active_account': {
                        'id': p['active_id'],
                        'object_id': p['active_oid'],
                        'display_name': p['active_name'],
                        'upn': p['active_upn'],
                        'risk_score': p['active_risk'],
                        'privilege_tier': tier,
                    },
                    'link_method': p['link_method'],
                    'link_confidence': p['link_confidence'],
                },
            })

        logger.info(f"Zombie persona detection: {len(anomalies)} zombie pairs found")
        return anomalies
