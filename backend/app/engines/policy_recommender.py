"""Phase 11: IAM Policy Recommendation Engine.

Analyzes risk findings, IAM graph relationships, identity activity patterns,
and credential lifecycle data to produce actionable remediation recommendations.
"""

import logging

logger = logging.getLogger(__name__)


class PolicyRecommender:
    """Generates policy recommendations based on detected IAM risks."""

    def __init__(self, db):
        self.db = db

    def generate_policy_recommendations(self, connection_id, org_id):
        """Analyze findings and generate remediation recommendations.

        Workflow:
        1. Retrieve active findings for this connection
        2. Analyze context (identities, roles, credentials)
        3. Generate recommendations via rule evaluators
        4. Insert/upsert into policy_recommendations
        """
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            return []

        recommendations = []
        for evaluator in EVALUATORS:
            try:
                results = evaluator(self, run_id, connection_id, org_id)
                recommendations.extend(results)
            except Exception as e:
                logger.error(f"Recommendation evaluator failed: {e}")

        if recommendations:
            self.db.save_policy_recommendations(connection_id, org_id, recommendations)

        return recommendations

    def _get_latest_run_id(self, connection_id):
        """Get the latest completed discovery run for a connection."""
        cursor = self.db.conn.cursor()
        cursor.execute(
            "SELECT id FROM discovery_runs WHERE cloud_connection_id = %s "
            "AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (connection_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None

    # ── Rule Evaluators ──────────────────────────────────────────────────

    def _eval_excess_privilege_identity(self, run_id, connection_id, org_id):
        """Recommend downgrading Owner role for inactive/low-activity identities."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT i.identity_id, i.display_name, i.identity_category,
                   i.activity_status, i.last_sign_in_date
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND ra.role_name = 'Owner'
              AND i.activity_status IN ('inactive', 'stale')
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()

        results = []
        for row in rows:
            results.append({
                'recommendation_type': 'excess_privilege_identity',
                'severity': 'high',
                'identity_id': row['identity_id'],
                'description': f"Identity '{row.get('display_name', row['identity_id'])}' has Owner role but is {row['activity_status']}",
                'recommended_action': 'Replace Owner with Contributor or Reader role',
                'confidence_score': 85,
                'metadata': {
                    'roles': ['Owner'],
                    'activity_status': row['activity_status'],
                    'last_signin': str(row['last_sign_in_date']) if row.get('last_sign_in_date') else None,
                    'identity_category': row.get('identity_category'),
                },
            })
        return results

    def _eval_service_principal_secret_rotation(self, run_id, connection_id, org_id):
        """Recommend rotating old service principal secrets."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT i.identity_id, i.display_name,
                   i.credential_expiration
            FROM identities i
            WHERE i.discovery_run_id = %s
              AND i.identity_category = 'service_principal'
              AND i.credential_expiration IS NOT NULL
              AND i.credential_expiration < NOW() + INTERVAL '180 days'
              AND i.credential_expiration > NOW() - INTERVAL '365 days'
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()

        results = []
        for row in rows:
            age_days = None
            if row.get('credential_expiration'):
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                exp = row['credential_expiration']
                if hasattr(exp, 'tzinfo') and exp.tzinfo is None:
                    from datetime import timezone as tz
                    exp = exp.replace(tzinfo=tz.utc)
                age_days = (now - exp).days if exp < now else None

            results.append({
                'recommendation_type': 'service_principal_secret_rotation',
                'severity': 'high',
                'identity_id': row['identity_id'],
                'description': f"Service principal '{row.get('display_name', row['identity_id'])}' has credential older than 180 days",
                'recommended_action': 'Rotate credential and enforce expiration policy',
                'confidence_score': 90,
                'metadata': {
                    'credential_age_days': age_days,
                    'credential_expiration': str(row['credential_expiration']) if row.get('credential_expiration') else None,
                },
            })
        return results

    def _eval_guest_user_privilege_review(self, run_id, connection_id, org_id):
        """Recommend reviewing guest users with elevated privileges."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT i.identity_id, i.display_name, ra.role_name
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND i.identity_category = 'guest'
              AND ra.role_name IN ('Owner', 'Contributor')
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()

        results = []
        seen = set()
        for row in rows:
            key = row['identity_id']
            if key in seen:
                continue
            seen.add(key)
            results.append({
                'recommendation_type': 'guest_user_privilege_review',
                'severity': 'medium',
                'identity_id': row['identity_id'],
                'description': f"Guest user '{row.get('display_name', row['identity_id'])}' has {row['role_name']} role",
                'recommended_action': 'Review external user privileges and restrict to minimum required access',
                'confidence_score': 80,
                'metadata': {
                    'roles': [row['role_name']],
                    'identity_category': 'guest',
                },
            })
        return results

    def _eval_unused_identity_cleanup(self, run_id, connection_id, org_id):
        """Recommend disabling identities with no recent sign-in."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT i.identity_id, i.display_name, i.identity_category,
                   i.last_sign_in_date
            FROM identities i
            WHERE i.discovery_run_id = %s
              AND (i.last_sign_in_date IS NULL
                   OR i.last_sign_in_date < NOW() - INTERVAL '90 days')
              AND i.activity_status IN ('inactive', 'stale', 'never_used')
              AND i.identity_category NOT IN ('managed_identity_system', 'managed_identity_user')
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()

        results = []
        for row in rows:
            results.append({
                'recommendation_type': 'unused_identity_cleanup',
                'severity': 'medium',
                'identity_id': row['identity_id'],
                'description': f"Identity '{row.get('display_name', row['identity_id'])}' has not signed in for over 90 days",
                'recommended_action': 'Disable or remove unused identity to reduce attack surface',
                'confidence_score': 75,
                'metadata': {
                    'last_signin': str(row['last_sign_in_date']) if row.get('last_sign_in_date') else None,
                    'identity_category': row.get('identity_category'),
                },
            })
        return results

    def _eval_service_principal_excess_privilege(self, run_id, connection_id, org_id):
        """Recommend replacing Owner role on service principals."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT i.identity_id, i.display_name, ra.role_name, ra.scope
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND i.identity_category = 'service_principal'
              AND ra.role_name = 'Owner'
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()

        results = []
        seen = set()
        for row in rows:
            key = row['identity_id']
            if key in seen:
                continue
            seen.add(key)
            results.append({
                'recommendation_type': 'service_principal_excess_privilege',
                'severity': 'high',
                'identity_id': row['identity_id'],
                'description': f"Service principal '{row.get('display_name', row['identity_id'])}' has Owner role",
                'recommended_action': 'Replace Owner with least-privilege role appropriate for workload',
                'confidence_score': 90,
                'metadata': {
                    'roles': ['Owner'],
                    'scope': row.get('scope'),
                    'identity_category': 'service_principal',
                },
            })
        return results


# Evaluator registry — list of bound method references
EVALUATORS = [
    PolicyRecommender._eval_excess_privilege_identity,
    PolicyRecommender._eval_service_principal_secret_rotation,
    PolicyRecommender._eval_guest_user_privilege_review,
    PolicyRecommender._eval_unused_identity_cleanup,
    PolicyRecommender._eval_service_principal_excess_privilege,
]
