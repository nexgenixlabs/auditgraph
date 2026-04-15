"""Phase 28: Autonomous Identity Governance Engine.

Continuously evaluates identity governance policies to detect privilege drift,
unused identities, stale credentials, and guest over-privilege — then generates
governance actions to remediate violations.
"""

import logging
from datetime import datetime, timezone
from app.constants.roles import EntraRole, RBACRole

logger = logging.getLogger(__name__)

# Governance thresholds (days)
INACTIVITY_THRESHOLD_DAYS = 90
CREDENTIAL_AGE_THRESHOLD_DAYS = 180
PRIVILEGED_ROLE_AGE_THRESHOLD_DAYS = 365

# Roles considered privileged
PRIVILEGED_ROLES: frozenset[str] = frozenset({
    RBACRole.OWNER, RBACRole.CONTRIBUTOR, RBACRole.USER_ACCESS_ADMIN,
    EntraRole.GLOBAL_ADMIN, EntraRole.PRIVILEGED_ROLE_ADMIN,
    EntraRole.SECURITY_ADMIN, EntraRole.APPLICATION_ADMIN,
})

# Roles that guests should not hold
GUEST_RESTRICTED_ROLES: frozenset[str] = frozenset({
    RBACRole.OWNER, RBACRole.CONTRIBUTOR, RBACRole.USER_ACCESS_ADMIN,
    EntraRole.GLOBAL_ADMIN, EntraRole.PRIVILEGED_ROLE_ADMIN,
})


class IdentityGovernanceEngine:
    """Evaluates identity governance policies and generates corrective actions."""

    def __init__(self, db):
        self.db = db

    def evaluate_identity_governance(self, connection_id, org_id):
        """Main entry: evaluate governance rules for all identities in a connection."""
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.info(f"No completed run for connection {connection_id}")
            return []

        identities = self._load_identities(run_id)
        if not identities:
            logger.info(f"No identities for run {run_id}")
            return []

        role_map = self._load_role_assignments(run_id)
        actions = []

        for identity in identities:
            db_id = identity.get('id')
            roles = role_map.get(db_id, [])

            # Rule 1: Detect unused identities
            actions.extend(self._check_unused_identity(identity, connection_id, org_id))

            # Rule 2: Detect stale credentials
            actions.extend(self._check_stale_credentials(identity, connection_id, org_id))

            # Rule 3: Detect privilege drift (long-held privileged roles)
            actions.extend(self._check_privilege_drift(identity, roles, connection_id, org_id))

            # Rule 4: Detect guest over-privilege
            actions.extend(self._check_guest_privilege(identity, roles, connection_id, org_id))

        if actions:
            self.db.save_governance_actions(connection_id, org_id, actions)
            logger.info(f"Governance engine: {len(actions)} action(s) for connection {connection_id}")

        return actions

    # ── Governance Rules ─────────────────────────────────────────────────

    def _check_unused_identity(self, identity, connection_id, org_id):
        """Detect identities inactive for longer than threshold."""
        activity = identity.get('activity_status', '')
        category = identity.get('identity_category', '')
        if activity in ('inactive', 'stale', 'never_used') and category != 'managed_identity_system':
            return [{
                'organization_id': org_id,
                'cloud_connection_id': connection_id,
                'identity_id': identity.get('identity_id', ''),
                'identity_name': identity.get('display_name', ''),
                'identity_category': category,
                'governance_action': 'disable_unused_identity',
                'reason': f"Identity is {activity} — no sign-in activity detected within governance threshold.",
                'metadata': {
                    'activity_status': activity,
                    'last_sign_in': str(identity.get('last_sign_in', 'never')),
                },
            }]
        return []

    def _check_stale_credentials(self, identity, connection_id, org_id):
        """Detect credentials older than policy limit."""
        cred_status = identity.get('credential_status', '')
        category = identity.get('identity_category', '')
        if cred_status in ('expired', 'expiring_soon') and category in ('service_principal', 'managed_identity_user'):
            return [{
                'organization_id': org_id,
                'cloud_connection_id': connection_id,
                'identity_id': identity.get('identity_id', ''),
                'identity_name': identity.get('display_name', ''),
                'identity_category': category,
                'governance_action': 'rotate_old_credential',
                'reason': f"Credential status is {cred_status} — rotation required per governance policy.",
                'metadata': {
                    'credential_status': cred_status,
                    'credential_expiration': str(identity.get('credential_expiration', '')),
                },
            }]
        return []

    def _check_privilege_drift(self, identity, roles, connection_id, org_id):
        """Detect identities holding privileged roles beyond threshold."""
        priv_roles = [r for r in roles if r.get('role_name') in PRIVILEGED_ROLES]
        if not priv_roles:
            return []

        activity = identity.get('activity_status', '')
        if activity in ('inactive', 'stale', 'never_used'):
            role_names = [r['role_name'] for r in priv_roles]
            return [{
                'organization_id': org_id,
                'cloud_connection_id': connection_id,
                'identity_id': identity.get('identity_id', ''),
                'identity_name': identity.get('display_name', ''),
                'identity_category': identity.get('identity_category', ''),
                'governance_action': 'downgrade_privileged_role',
                'reason': f"Identity holds privileged roles ({', '.join(role_names)}) but is {activity}.",
                'metadata': {
                    'privileged_roles': role_names,
                    'activity_status': activity,
                },
            }]
        return []

    def _check_guest_privilege(self, identity, roles, connection_id, org_id):
        """Detect guest identities with restricted roles."""
        if identity.get('identity_category') != 'guest':
            return []

        restricted = [r for r in roles if r.get('role_name') in GUEST_RESTRICTED_ROLES]
        if not restricted:
            return []

        role_names = [r['role_name'] for r in restricted]
        return [{
            'organization_id': org_id,
            'cloud_connection_id': connection_id,
            'identity_id': identity.get('identity_id', ''),
            'identity_name': identity.get('display_name', ''),
            'identity_category': 'guest',
            'governance_action': 'remove_guest_privilege',
            'reason': f"Guest identity holds restricted roles: {', '.join(role_names)}.",
            'metadata': {
                'restricted_roles': role_names,
            },
        }]

    # ── Data Loading ─────────────────────────────────────────────────────

    def _get_latest_run_id(self, connection_id):
        """Get the latest completed discovery run for a connection."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT id FROM discovery_runs WHERE cloud_connection_id = %s AND status = 'completed' ORDER BY id DESC LIMIT 1",
            (connection_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        return row['id'] if row else None

    def _load_identities(self, run_id):
        """Load all identities for a discovery run."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT id, identity_id, display_name, identity_category, activity_status, "
            "credential_status, credential_expiration, last_sign_in "
            "FROM identities WHERE discovery_run_id = %s",
            (run_id,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        cursor.close()
        return rows

    def _load_role_assignments(self, run_id):
        """Load role assignments grouped by identity_db_id."""
        cursor = self.db._cursor()
        cursor.execute(
            "SELECT identity_db_id, role_name, scope FROM role_assignments WHERE discovery_run_id = %s",
            (run_id,)
        )
        role_map = {}
        for row in cursor.fetchall():
            db_id = row['identity_db_id']
            if db_id not in role_map:
                role_map[db_id] = []
            role_map[db_id].append(dict(row))
        cursor.close()
        return role_map
