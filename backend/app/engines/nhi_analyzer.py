"""
Phase 9: Non-Human Identity Security Analytics

Analyzes service principals, managed identities, and automation identities
for security risks including credential hygiene, dormancy, and over-privilege.
Findings are stored in the risk_findings table with nhi_security category.
"""

import logging

logger = logging.getLogger(__name__)


class NHIAnalyzer:
    """Analyzes non-human identities for security risks."""

    def __init__(self, db):
        self.db = db

    def analyze_nhi_security(self, connection_id, org_id):
        """Run all NHI security rules for a cloud connection.

        Returns list of findings saved to risk_findings.
        """
        run_id = self._get_latest_run_id(connection_id)
        if not run_id:
            logger.debug(f"No completed run for connection {connection_id}, skipping NHI analysis")
            return []

        rules = self._get_nhi_rules()

        findings = []
        for rule in rules:
            analyzer = ANALYZERS.get(rule['rule_key'])
            if analyzer:
                try:
                    rule_findings = analyzer(self, run_id, connection_id, org_id, rule)
                    findings.extend(rule_findings)
                except Exception as e:
                    logger.error(f"NHI analyzer '{rule['rule_key']}' failed: {e}")
                    # 2026-06-12 — rollback the failed transaction so the
                    # next rule starts clean. Without this, a single SQL
                    # error (e.g. missing column) cascades and aborts
                    # every subsequent rule with "current transaction is
                    # aborted, commands ignored until end of transaction
                    # block." Cloud devpilot was producing 0 NHI findings
                    # because rule 12 hit a missing column and rules
                    # 13–15 cascaded.
                    try: self.db.conn.rollback()
                    except Exception: pass

        if findings:
            self.db.save_risk_findings(connection_id, org_id, findings)
            logger.info(f"NHI analysis: {len(findings)} finding(s) for connection {connection_id}")
        else:
            logger.debug(f"NHI analysis: no findings for connection {connection_id}")

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

    def _get_nhi_rules(self):
        """Get enabled NHI-related risk rules."""
        rules = self.db.get_risk_rules(enabled_only=True)
        return [r for r in rules if r['rule_key'] in ANALYZERS]

    def _make_finding(self, rule, identity_id, metadata=None):
        """Build a finding dict with nhi_security category."""
        meta = metadata or {}
        meta['finding_category'] = 'nhi_security'
        return {
            'rule_id': rule['id'],
            'severity': rule['severity'],
            'identity_id': identity_id,
            'resource_id': None,
            'metadata': meta,
        }

    def get_nhi_findings(self):
        """Get all NHI-category risk findings."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT rf.*, rr.rule_key, rr.rule_name, rr.rule_type
            FROM risk_findings rf
            LEFT JOIN risk_rules rr ON rr.id = rf.rule_id
            WHERE rf.metadata->>'finding_category' = 'nhi_security'
            ORDER BY
                CASE rf.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 ELSE 4
                END,
                rf.detected_at DESC
        """)
        rows = cursor.fetchall()
        cursor.close()
        results = []
        for r in rows:
            d = dict(r)
            d['id'] = str(d['id'])
            if d.get('detected_at'):
                d['detected_at'] = d['detected_at'].isoformat()
            if d.get('resolved_at'):
                d['resolved_at'] = d['resolved_at'].isoformat()
            results.append(d)
        return results


# ── NHI Analyzer Registry ───────────────────────────────────────────────────

ANALYZERS = {}


def _register(rule_key):
    """Decorator to register an NHI analyzer for a rule_key."""
    def decorator(fn):
        ANALYZERS[rule_key] = fn
        return fn
    return decorator


# ── Rule 1: SPN Secret Without Expiry ────────────────────────────────────────

@_register('spn_secret_without_expiry')
def _analyze_secret_no_expiry(self, run_id, connection_id, org_id, rule):
    """Service principals with secrets that have no expiration date."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND i.credential_expiration IS NULL
          AND i.credential_count > 0
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, r['identity_id'], {
            'display_name': r['display_name'],
            'identity_type': r['identity_category'],
            'reason': 'Service principal secret has no expiration date',
        })
        for r in rows
    ]


# ── Rule 2: SPN Secret Older Than 180 Days ──────────────────────────────────

@_register('spn_secret_older_than_180_days')
def _analyze_secret_old(self, run_id, connection_id, org_id, rule):
    """Service principals with secrets created more than 180 days ago."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category,
               i.credential_created_at
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND i.credential_created_at IS NOT NULL
          AND i.credential_created_at < NOW() - INTERVAL '180 days'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, r['identity_id'], {
            'display_name': r['display_name'],
            'identity_type': r['identity_category'],
            'secret_age': str(r['credential_created_at']) if r.get('credential_created_at') else None,
            'reason': 'Service principal secret is older than 180 days',
        })
        for r in rows
    ]


# ── Rule 3: Unused Service Principal ─────────────────────────────────────────

@_register('unused_service_principal')
def _analyze_unused_spn(self, run_id, connection_id, org_id, rule):
    """Service principals with no sign-in activity in 90+ days."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category,
               i.last_sign_in
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND (i.last_sign_in IS NULL OR i.last_sign_in < NOW() - INTERVAL '90 days')
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    return [
        self._make_finding(rule, r['identity_id'], {
            'display_name': r['display_name'],
            'identity_type': r['identity_category'],
            'last_signin': str(r['last_sign_in']) if r.get('last_sign_in') else 'never',
            'reason': 'Service principal has no sign-in activity in 90+ days',
        })
        for r in rows
    ]


# ── Rule 4: SPN Owner Role ──────────────────────────────────────────────────

@_register('spn_owner_role')
def _analyze_spn_owner(self, run_id, connection_id, org_id, rule):
    """Service principals with Owner role assignment."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category,
               ra.role_name, ra.scope
        FROM identities i
        JOIN role_assignments ra ON ra.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
          AND i.identity_category = 'service_principal'
          AND ra.role_name = 'Owner'
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    seen = set()
    findings = []
    for r in rows:
        if r['identity_id'] in seen:
            continue
        seen.add(r['identity_id'])
        findings.append(self._make_finding(rule, r['identity_id'], {
            'display_name': r['display_name'],
            'identity_type': r['identity_category'],
            'roles': ['Owner'],
            'reason': 'Service principal has Owner role assignment',
        }))
    return findings


# ── Rule 5: Managed Identity High Privilege ──────────────────────────────────

@_register('managed_identity_high_privilege')
def _analyze_mi_high_priv(self, run_id, connection_id, org_id, rule):
    """Managed identities with Contributor or Owner roles."""
    from psycopg2.extras import RealDictCursor
    cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT i.identity_id, i.display_name, i.identity_category,
               ra.role_name, ra.scope
        FROM identities i
        JOIN role_assignments ra ON ra.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
          AND i.identity_category IN ('managed_identity_system', 'managed_identity_user')
          AND ra.role_name IN ('Contributor', 'Owner')
    """, (run_id,))
    rows = cursor.fetchall()
    cursor.close()

    seen = set()
    findings = []
    for r in rows:
        if r['identity_id'] in seen:
            continue
        seen.add(r['identity_id'])
        findings.append(self._make_finding(rule, r['identity_id'], {
            'display_name': r['display_name'],
            'identity_type': r['identity_category'],
            'roles': [r['role_name']],
            'reason': f'Managed identity has {r["role_name"]} role assignment',
        }))
    return findings
