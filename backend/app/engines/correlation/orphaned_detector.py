"""
Orphaned Privileged Account Detector

Detects cases where a regular account is disabled but the corresponding
privileged account remains active with Azure RBAC or Entra roles.
This is a critical HIPAA violation (§164.312(a)(2)(iii)).
"""
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone

from app.engines.correlation.remediation import generate_remediation_commands


CRITICAL_ROLES = {
    'owner', 'global administrator', 'user access administrator',
    'privileged role administrator', 'privileged authentication administrator',
    'contributor', 'key vault secrets officer', 'application administrator',
}


class OrphanedAccountDetector:
    """Detects orphaned privileged accounts where the paired regular account is disabled."""

    def __init__(self, db):
        self.db = db

    def detect(self, run_id):
        """Find orphaned privileged accounts and save findings.

        Returns list of anomaly dicts suitable for db.save_anomalies().
        """
        org_id = self.db._organization_id
        if not org_id:
            return []

        pairs = self._find_orphaned_pairs(org_id)
        if not pairs:
            return []

        anomalies = []
        for pair in pairs:
            roles = self._get_privileged_roles(pair['privileged_identity_db_id'])
            role_names = [r.get('role_name', '') for r in roles]
            role_count = len(role_names)

            # Determine severity
            has_critical = any(rn.lower() in CRITICAL_ROLES for rn in role_names)
            severity = 'critical' if has_critical else 'high'

            # Highest privilege role
            highest = self._pick_highest_role(role_names)

            # Count distinct subscriptions
            subs = set()
            for r in roles:
                scope = r.get('scope', '')
                if '/subscriptions/' in scope:
                    parts = scope.split('/subscriptions/')
                    if len(parts) > 1:
                        sub_id = parts[1].split('/')[0]
                        subs.add(sub_id)

            # Days since regular disabled
            days_disabled = self._compute_days_disabled(pair)

            # Generate remediation commands
            finding_data = {
                'organization_id': org_id,
                'discovery_run_id': run_id,
                'human_identity_id': pair['human_identity_id'],
                'regular_link_id': pair['regular_link_id'],
                'privileged_link_id': pair['privileged_link_id'],
                'regular_upn': pair['regular_upn'],
                'regular_object_id': pair['regular_object_id'],
                'privileged_upn': pair['privileged_upn'],
                'privileged_object_id': pair['privileged_object_id'],
                'severity': severity,
                'azure_roles': role_names,
                'role_count': role_count,
                'highest_role_privilege': highest,
                'subscription_count': len(subs),
                'has_activity_after_disable': False,
                'days_since_regular_disabled': days_disabled,
                'days_out_of_compliance': days_disabled or 0,
                'remediation_commands': generate_remediation_commands({
                    'privileged_object_id': pair['privileged_object_id'],
                    'privileged_upn': pair['privileged_upn'],
                    'roles': roles,
                    'severity': severity,
                }),
            }

            finding_id = self.db.save_orphaned_finding(finding_data)

            # Build anomaly dict for save_anomalies()
            anomalies.append({
                'identity_db_id': pair['privileged_identity_db_id'],
                'identity_name': pair['privileged_upn'] or 'Unknown',
                'type': 'orphaned_privileged',
                'severity': severity,
                'description': (
                    f"Privileged account {pair['privileged_upn']} remains active with "
                    f"{role_count} role(s) (highest: {highest}) while regular account "
                    f"{pair['regular_upn']} is disabled. "
                    f"HIPAA §164.312(a)(2)(iii) violation."
                ),
                'details': {
                    'finding_id': finding_id,
                    'regular_upn': pair['regular_upn'],
                    'privileged_upn': pair['privileged_upn'],
                    'role_count': role_count,
                    'highest_role': highest,
                    'days_since_disabled': days_disabled,
                    'subscription_count': len(subs),
                },
            })

        return anomalies

    def _find_orphaned_pairs(self, org_id):
        """Find linked pairs where regular is disabled and privileged is enabled."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("""
                SELECT
                    h.id as human_identity_id,
                    h.display_name,
                    rl.id as regular_link_id,
                    rl.account_upn as regular_upn,
                    rl.account_object_id as regular_object_id,
                    rl.identity_db_id as regular_identity_db_id,
                    pl.id as privileged_link_id,
                    pl.account_upn as privileged_upn,
                    pl.account_object_id as privileged_object_id,
                    pl.identity_db_id as privileged_identity_db_id
                FROM human_identities h
                JOIN identity_links rl ON rl.human_identity_id = h.id AND rl.account_type = 'regular'
                JOIN identity_links pl ON pl.human_identity_id = h.id AND pl.account_type = 'privileged'
                JOIN identities ri ON ri.id = rl.identity_db_id
                JOIN identities pi ON pi.id = pl.identity_db_id
                WHERE h.organization_id = %s
                  AND ri.enabled = FALSE
                  AND pi.enabled = TRUE
                  AND pi.deleted_at IS NULL
            """, (org_id,))
            return [dict(r) for r in cursor.fetchall()]
        except Exception:
            return []
        finally:
            cursor.close()

    def _get_privileged_roles(self, identity_db_id):
        """Get all role assignments for the privileged identity."""
        if not identity_db_id:
            return []
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            # Azure RBAC roles
            cursor.execute("""
                SELECT role_name, scope, scope_type, risk_level
                FROM role_assignments WHERE identity_db_id = %s
            """, (identity_db_id,))
            rbac = [dict(r) for r in cursor.fetchall()]

            # Entra directory roles
            cursor.execute("""
                SELECT role_name, directory_scope as scope, 'entra' as scope_type, risk_level
                FROM entra_role_assignments WHERE identity_db_id = %s
            """, (identity_db_id,))
            entra = [dict(r) for r in cursor.fetchall()]

            return rbac + entra
        finally:
            cursor.close()

    def _pick_highest_role(self, role_names):
        """Pick the highest-privilege role."""
        priority = [
            'Global Administrator', 'Owner', 'User Access Administrator',
            'Privileged Role Administrator', 'Contributor',
            'Application Administrator', 'Key Vault Secrets Officer',
        ]
        for p in priority:
            for rn in role_names:
                if rn.lower() == p.lower():
                    return rn
        return role_names[0] if role_names else 'Unknown'

    def _compute_days_disabled(self, pair):
        """Estimate days since regular account was disabled."""
        # We don't have exact disable timestamp, but last_sign_in gives a lower bound
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute(
                "SELECT last_sign_in FROM identities WHERE id = %s",
                (pair.get('regular_identity_db_id'),))
            row = cursor.fetchone()
            if row and row.get('last_sign_in'):
                last = row['last_sign_in']
                if isinstance(last, str):
                    from dateutil import parser
                    last = parser.parse(last)
                if hasattr(last, 'tzinfo') and last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - last).days
        except Exception:
            pass
        finally:
            cursor.close()
        return None
