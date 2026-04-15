"""
Phase 6: Risk Detection Engine — Rules-Based Risk Evaluator

Evaluates discovered identity data against configurable risk rules stored in
the risk_rules table, producing security findings scoped to cloud_connection_id.
Complements the existing SecurityFindingsEngine (discovery_run_id scoped, hardcoded).
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Rule Evaluator Registry ─────────────────────────────────────────────────

EVALUATORS = {}


def _register(rule_key):
    """Decorator to register an evaluator function for a rule_key."""
    def decorator(fn):
        EVALUATORS[rule_key] = fn
        return fn
    return decorator


class RiskEvaluator:
    """Rules-based risk evaluator that produces findings per cloud connection."""

    def __init__(self, db):
        self.db = db

    def evaluate_risks(self, connection_id, org_id):
        """Run all enabled rules against the latest discovery run for a connection.

        Returns list of finding dicts that were saved.
        """
        rules = self.db.get_risk_rules(enabled_only=True)
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.debug(f"No completed run for connection {connection_id}, skipping risk evaluation")
            return []

        findings = []
        for rule in rules:
            evaluator = EVALUATORS.get(rule['rule_key'])
            if evaluator:
                try:
                    rule_findings = evaluator(self, run_id, connection_id, rule)
                    findings.extend(rule_findings)
                except Exception as e:
                    logger.error(f"Rule evaluator '{rule['rule_key']}' failed: {e}")

        if findings:
            self.db.save_risk_findings(connection_id, org_id, findings)
            logger.info(f"Risk evaluation: {len(findings)} finding(s) for connection {connection_id}")
        else:
            logger.debug(f"Risk evaluation: no findings for connection {connection_id}")

        return findings

    def _get_latest_run_id(self, connection_id):
        """Get the most recent completed discovery run for a connection."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE cloud_connection_id = %s AND status = 'completed'
            ORDER BY id DESC LIMIT 1
        """, (connection_id,))
        row = cursor.fetchone()
        cursor.close()
        return row['id'] if row else None

    def _make_finding(self, rule, identity_id=None, resource_id=None, metadata=None):
        """Build a finding dict ready for save_risk_findings."""
        return {
            'rule_id': rule['id'],
            'severity': rule['severity'],
            'identity_id': identity_id,
            'resource_id': resource_id,
            'metadata': metadata or {},
        }


# ── Rule Evaluators ─────────────────────────────────────────────────────────


@_register('disabled_user_with_role')
def _eval_disabled_user_with_role(self, run_id, connection_id, rule):
    """Disabled users that still have active role assignments."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.activity_status = 'disabled'
          AND EXISTS (
              SELECT 1 FROM role_assignments ra
              WHERE ra.identity_db_id = i.id
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'reason': 'Disabled user still has active role assignments',
        })
        for r in rows
    ]


@_register('guest_high_privilege')
def _eval_guest_high_privilege(self, run_id, connection_id, rule):
    """Guest users with Owner or Contributor roles."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'guest'
          AND EXISTS (
              SELECT 1 FROM role_assignments ra
              WHERE ra.identity_db_id = i.id
                AND ra.role_name IN ('Owner', 'Contributor')
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'reason': 'Guest user has high-privilege role (Owner/Contributor)',
        })
        for r in rows
    ]


@_register('spn_owner')
def _eval_spn_owner(self, run_id, connection_id, rule):
    """Service principals with Owner role."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND EXISTS (
              SELECT 1 FROM role_assignments ra
              WHERE ra.identity_db_id = i.id
                AND ra.role_name = 'Owner'
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'reason': 'Service principal has Owner role assignment',
        })
        for r in rows
    ]


@_register('expired_spn_secret')
def _eval_expired_spn_secret(self, run_id, connection_id, rule):
    """Service principals with expired credentials."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND i.credential_status = 'expired'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'reason': 'Service principal has expired credentials',
        })
        for r in rows
    ]


@_register('spn_secret_expiring')
def _eval_spn_secret_expiring(self, run_id, connection_id, rule):
    """Service principals with credentials expiring within 30 days."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id, i.credential_expiration
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND i.credential_expiration < NOW() + INTERVAL '30 days'
          AND i.credential_status != 'expired'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'credential_expiration': str(r['credential_expiration']) if r['credential_expiration'] else None,
            'reason': 'Service principal credential expiring within 30 days',
        })
        for r in rows
    ]


@_register('inactive_privileged')
def _eval_inactive_privileged(self, run_id, connection_id, rule):
    """Inactive/stale identities with privileged role assignments."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id, i.last_sign_in
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.activity_status IN ('inactive', 'stale')
          AND (i.last_sign_in IS NULL OR i.last_sign_in < NOW() - INTERVAL '90 days')
          AND EXISTS (
              SELECT 1 FROM role_assignments ra
              WHERE ra.identity_db_id = i.id
                AND ra.role_name IN ('Owner', 'Contributor')
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'last_sign_in': str(r['last_sign_in']) if r['last_sign_in'] else 'never',
            'reason': 'Inactive identity with privileged role (Owner/Contributor)',
        })
        for r in rows
    ]


# ── Phase 17: Cloud-Specific Risk Evaluators ─────────────────────────────


@_register('aws_access_key_stale')
def _eval_aws_access_key_stale(self, run_id, connection_id, rule):
    """AWS IAM users with access keys older than 90 days."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.source = 'aws_iam'
          AND i.identity_category = 'iam_user'
          AND i.credential_status = 'active'
          AND i.created_datetime < NOW() - INTERVAL '90 days'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'cloud': 'aws',
            'reason': 'AWS IAM user has access key older than 90 days',
        })
        for r in rows
    ]


@_register('aws_user_admin_policy')
def _eval_aws_user_admin_policy(self, run_id, connection_id, rule):
    """AWS IAM users with AdministratorAccess or equivalent policy."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.source = 'aws_iam'
          AND i.identity_category = 'iam_user'
          AND EXISTS (
              SELECT 1 FROM role_assignments ra
              WHERE ra.identity_db_id = i.id
                AND ra.role_name IN ('AdministratorAccess', 'IAMFullAccess', 'PowerUserAccess')
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'cloud': 'aws',
            'reason': 'AWS IAM user has admin-level policy attached',
        })
        for r in rows
    ]


@_register('gcp_sa_key_exposure')
def _eval_gcp_sa_key_exposure(self, run_id, connection_id, rule):
    """GCP service accounts with user-managed keys (potential key exposure)."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id, i.tags
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.source = 'gcp_iam'
          AND i.identity_category = 'gcp_service_account'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    findings = []
    for r in rows:
        tags = r.get('tags') or {}
        if isinstance(tags, str):
            import json
            tags = json.loads(tags)
        key_count = tags.get('user_managed_key_count', 0)
        if key_count > 0:
            findings.append(self._make_finding(rule, identity_id=r['identity_id'], metadata={
                'display_name': r['display_name'],
                'cloud': 'gcp',
                'user_managed_key_count': key_count,
                'reason': f'GCP service account has {key_count} user-managed key(s)',
            }))
    return findings


@_register('gcp_owner_on_project')
def _eval_gcp_owner_on_project(self, run_id, connection_id, rule):
    """Identities with Owner role binding on a GCP project."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.id, i.display_name, i.identity_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.source = 'gcp_iam'
          AND EXISTS (
              SELECT 1 FROM role_assignments ra
              WHERE ra.identity_db_id = i.id
                AND ra.role_name = 'roles/owner'
          )
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, identity_id=r['identity_id'], metadata={
            'display_name': r['display_name'],
            'cloud': 'gcp',
            'reason': 'Identity has Owner role binding on GCP project',
        })
        for r in rows
    ]
