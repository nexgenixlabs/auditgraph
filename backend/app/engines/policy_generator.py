"""Phase 19: Automated Least-Privilege Policy Generator.

Analyzes identity activity and access patterns to generate optimized
least-privilege IAM policies. Identifies unused permissions, over-privileged
roles, and suggests minimal role replacements.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Azure built-in role hierarchy (higher privilege → lower alternatives)
ROLE_DOWNGRADE_MAP = {
    'Owner': ['Contributor', 'Reader'],
    'Contributor': ['Reader'],
    'User Access Administrator': ['Reader'],
    'Security Admin': ['Security Reader'],
    'Key Vault Administrator': ['Key Vault Secrets User', 'Key Vault Reader'],
    'Storage Blob Data Owner': ['Storage Blob Data Contributor', 'Storage Blob Data Reader'],
    'SQL Server Contributor': ['SQL DB Contributor', 'SQL Security Manager'],
}

# High-privilege roles that warrant least-privilege analysis
HIGH_PRIVILEGE_ROLES = {
    'Owner', 'Contributor', 'User Access Administrator',
    'Security Admin', 'Key Vault Administrator',
    'Storage Blob Data Owner', 'SQL Server Contributor',
    'Global Administrator', 'Privileged Role Administrator',
}

# Activity-based role suggestions
ACTIVITY_ROLE_MAP = {
    'key_vault_access': 'Key Vault Secrets User',
    'storage_read': 'Storage Blob Data Reader',
    'storage_write': 'Storage Blob Data Contributor',
    'sql_read': 'SQL DB Contributor',
    'compute_manage': 'Virtual Machine Contributor',
    'network_read': 'Network Contributor',
    'monitoring': 'Monitoring Reader',
}

# Confidence thresholds
MIN_CONFIDENCE = 0.3
HIGH_CONFIDENCE = 0.8


class PolicyGenerator:
    """Generates least-privilege policies based on identity activity analysis."""

    def __init__(self, db):
        self.db = db

    def generate_least_privilege_policy(self, identity_id, org_id, connection_id=None):
        """Generate a least-privilege policy for an identity.

        Steps:
        1. Collect identity details and current roles
        2. Analyze activity patterns and resource access
        3. Determine required vs unused permissions
        4. Generate minimal policy recommendation
        5. Store generated policy

        Args:
            identity_id: The identity to analyze
            org_id: Organization ID
            connection_id: Optional cloud connection ID

        Returns:
            Generated policy dict with current roles, suggested roles, and confidence.
        """
        # 1. Load identity details
        identity = self._load_identity(identity_id)
        if not identity:
            return None

        cloud_provider = identity.get('source', 'azure_ad')
        conn_id = connection_id or identity.get('cloud_connection_id')

        # 2. Get current role assignments
        current_roles = self._get_current_roles(identity_id)

        # 3. Analyze activity
        activity = self._analyze_activity(identity_id, identity)

        # 4. Check for risk findings
        risk_indicators = self._get_risk_indicators(identity_id)

        # 5. Generate policy recommendation
        policy = self._generate_policy(
            identity, current_roles, activity, risk_indicators, cloud_provider
        )

        # 6. Store the generated policy
        if policy and conn_id:
            self._save_policy(org_id, conn_id, identity_id, cloud_provider, policy)

        return policy

    def generate_policies_for_connection(self, connection_id, org_id):
        """Generate policies for all over-privileged identities in a connection.

        Returns:
            List of generated policies.
        """
        identities = self._get_over_privileged_identities(connection_id)
        policies = []

        for identity in identities:
            try:
                policy = self.generate_least_privilege_policy(
                    identity['identity_id'], org_id, connection_id
                )
                if policy:
                    policies.append(policy)
            except Exception as e:
                logger.warning(f"Policy generation failed for {identity.get('identity_id')}: {e}")

        logger.info(f"Generated {len(policies)} policies for connection {connection_id}")
        return policies

    def _load_identity(self, identity_id):
        """Load identity details from the database."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, identity_id, display_name, identity_category,
                       activity_status, last_sign_in, risk_level, source,
                       credential_status, credential_count
                FROM identities
                WHERE identity_id = %s
                ORDER BY id DESC LIMIT 1
            """, (identity_id,))
            row = cursor.fetchone()
            cursor.close()
            return dict(row) if row else None
        except Exception:
            return None

    def _get_current_roles(self, identity_id):
        """Get current role assignments for an identity."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT ra.role_name, ra.scope, ra.scope_type,
                       ra.assignment_type
                FROM role_assignments ra
                JOIN identities i ON ra.identity_db_id = i.id
                WHERE i.identity_id = %s
                ORDER BY ra.role_name
            """, (identity_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return rows
        except Exception:
            return []

    def _analyze_activity(self, identity_id, identity):
        """Analyze identity activity patterns.

        Returns dict with:
        - is_active: bool
        - is_inactive: bool
        - activity_status: str
        - has_recent_sign_in: bool
        - risk_signals: list
        """
        activity = {
            'is_active': identity.get('activity_status') == 'active',
            'is_inactive': identity.get('activity_status') in ('inactive', 'stale', 'never_used'),
            'activity_status': identity.get('activity_status', 'unknown'),
            'has_recent_sign_in': identity.get('last_sign_in') is not None,
            'risk_signals': [],
        }

        # Check for risk findings related to this identity
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT rf.severity, rr.rule_key, rr.rule_name
                FROM risk_findings rf
                JOIN risk_rules rr ON rf.rule_id = rr.id
                WHERE rf.identity_id = %s AND rf.status = 'open'
            """, (identity_id,))
            findings = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            activity['risk_signals'] = [f['rule_key'] for f in findings]
        except Exception:
            pass

        return activity

    def _get_risk_indicators(self, identity_id):
        """Get risk-related data for policy decisions."""
        indicators = {
            'has_attack_paths': False,
            'attack_path_count': 0,
            'risk_finding_count': 0,
            'is_over_privileged': False,
        }

        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

            # Check attack simulations
            cursor.execute("""
                SELECT COUNT(*) AS cnt FROM attack_simulations
                WHERE identity_id = %s AND blast_radius > 0
            """, (identity_id,))
            row = cursor.fetchone()
            if row and row['cnt'] > 0:
                indicators['has_attack_paths'] = True
                indicators['attack_path_count'] = row['cnt']

            # Check risk findings
            cursor.execute("""
                SELECT COUNT(*) AS cnt FROM risk_findings
                WHERE identity_id = %s AND status = 'open'
            """, (identity_id,))
            row = cursor.fetchone()
            indicators['risk_finding_count'] = row['cnt'] if row else 0

            cursor.close()
        except Exception:
            pass

        return indicators

    def _get_over_privileged_identities(self, connection_id):
        """Find identities with high-privilege roles in a connection."""
        try:
            from psycopg2.extras import RealDictCursor
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT DISTINCT i.identity_id, i.display_name, i.identity_category,
                       i.activity_status, i.risk_level
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                JOIN discovery_runs dr ON i.discovery_run_id = dr.id
                WHERE dr.cloud_connection_id = %s
                  AND ra.role_name IN ('Owner', 'Contributor', 'User Access Administrator',
                                       'Security Admin', 'Key Vault Administrator',
                                       'Global Administrator')
                ORDER BY i.identity_id
                LIMIT 100
            """, (connection_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            cursor.close()
            return rows
        except Exception:
            return []

    def _generate_policy(self, identity, current_roles, activity, risk_indicators, cloud_provider):
        """Generate the actual policy recommendation."""
        if not current_roles:
            return None

        current_role_names = [r['role_name'] for r in current_roles]
        high_priv_roles = [r for r in current_role_names if r in HIGH_PRIVILEGE_ROLES]

        if not high_priv_roles:
            return None

        # Determine suggested roles
        suggested_roles = []
        removed_roles = []
        confidence = 0.5  # Base confidence

        for role in high_priv_roles:
            downgrades = ROLE_DOWNGRADE_MAP.get(role, [])
            if downgrades:
                # If identity is inactive, suggest Reader only
                if activity['is_inactive']:
                    suggested_roles.append('Reader')
                    removed_roles.append(role)
                    confidence = max(confidence, HIGH_CONFIDENCE)
                # If identity has attack paths, strongly suggest downgrade
                elif risk_indicators.get('has_attack_paths'):
                    suggested_roles.extend(downgrades[:1])
                    removed_roles.append(role)
                    confidence = max(confidence, 0.7)
                # If identity is active but has risk findings, suggest mid-level
                elif risk_indicators.get('risk_finding_count', 0) > 0:
                    suggested_roles.extend(downgrades[:1])
                    removed_roles.append(role)
                    confidence = max(confidence, 0.6)
                # Active identity with no issues — lower confidence suggestion
                else:
                    suggested_roles.extend(downgrades[:1])
                    removed_roles.append(role)
                    confidence = MIN_CONFIDENCE

        # De-duplicate suggested roles
        suggested_roles = list(dict.fromkeys(suggested_roles))

        # Keep non-high-priv roles as-is
        kept_roles = [r for r in current_role_names if r not in removed_roles]

        # Build policy
        policy = {
            'identity_id': identity.get('identity_id'),
            'display_name': identity.get('display_name'),
            'identity_category': identity.get('identity_category'),
            'cloud_provider': cloud_provider,
            'policy_type': 'role_replacement' if removed_roles else 'least_privilege',
            'current_roles': current_role_names,
            'suggested_roles': suggested_roles + kept_roles,
            'removed_roles': removed_roles,
            'added_roles': [r for r in suggested_roles if r not in current_role_names],
            'confidence_score': round(confidence, 2),
            'rationale': self._build_rationale(
                identity, removed_roles, suggested_roles, activity, risk_indicators
            ),
        }

        return policy

    def _build_rationale(self, identity, removed_roles, suggested_roles, activity, risk_indicators):
        """Build human-readable rationale for the policy change."""
        reasons = []

        if activity['is_inactive']:
            reasons.append(
                f"Identity is {activity['activity_status']} — "
                f"high-privilege roles ({', '.join(removed_roles)}) are unnecessary"
            )

        if risk_indicators.get('has_attack_paths'):
            reasons.append(
                f"Identity has {risk_indicators['attack_path_count']} attack path(s) — "
                f"reducing privileges limits blast radius"
            )

        if risk_indicators.get('risk_finding_count', 0) > 0:
            reasons.append(
                f"{risk_indicators['risk_finding_count']} open risk finding(s) "
                f"associated with this identity"
            )

        if not reasons:
            reasons.append(
                f"Roles {', '.join(removed_roles)} can be replaced with "
                f"{', '.join(suggested_roles)} based on least-privilege principle"
            )

        return '; '.join(reasons)

    def _save_policy(self, org_id, connection_id, identity_id, cloud_provider, policy):
        """Persist the generated policy."""
        try:
            self.db.save_generated_policy(
                org_id=org_id,
                connection_id=connection_id,
                identity_id=identity_id,
                cloud_provider=cloud_provider,
                policy_type=policy['policy_type'],
                generated_policy=policy,
                confidence_score=policy['confidence_score'],
            )
        except Exception as e:
            logger.warning(f"Failed to save generated policy for {identity_id}: {e}")
