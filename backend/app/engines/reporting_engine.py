"""
Phase 7: Reporting Engine

Generates executive security reports and compliance evidence using
existing platform data. Reads from upstream engines' outputs (SELECT only):
  - blast_radius_results
  - attack_paths
  - security_findings
  - fix_recommendations
  - access_reviews / review_assignments / review_evidence
  - compliance_snapshots

Does NOT modify any upstream tables.

Supported report types:
  1. identity_risk       — top risk identities with blast radius + attack paths
  2. attack_surface      — attack surface overview with exposure metrics
  3. remediation_progress — fix recommendation status + risk reduction tracking
  4. access_review_evidence — access review campaigns + decisions + risk snapshots
  5. compliance_evidence — findings mapped to compliance frameworks

Export formats: json, csv, pdf
"""

import csv
import io
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────

VALID_REPORT_TYPES = (
    'identity_risk',
    'attack_surface',
    'remediation_progress',
    'access_review_evidence',
    'compliance_evidence',
)

VALID_EXPORT_FORMATS = ('json', 'csv', 'pdf')

REPORT_STORAGE_DIR = os.environ.get(
    'REPORT_STORAGE_DIR',
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'report_outputs'),
)

# ── Compliance framework mapping for findings ────────────────────────

_FINDING_COMPLIANCE_MAP = {
    'dormant_privileged_identity': {'SOC2': ['CC6.1'], 'NIST': ['AC-2(3)'], 'HIPAA': ['164.312(a)(1)'], 'CIS': ['1.1.4']},
    'user_without_mfa':           {'SOC2': ['CC6.1'], 'NIST': ['IA-2(1)'], 'HIPAA': ['164.312(d)'], 'CIS': ['1.1.1']},
    'overly_broad_rbac':          {'SOC2': ['CC6.3'], 'NIST': ['AC-6(1)'], 'HIPAA': ['164.312(a)(1)'], 'CIS': ['1.3']},
    'spn_secret_expired':         {'SOC2': ['CC6.1'], 'NIST': ['IA-5(1)'], 'HIPAA': ['164.312(d)'], 'CIS': ['1.11']},
    'storage_public_access':      {'SOC2': ['CC6.6'], 'NIST': ['AC-3'], 'HIPAA': ['164.312(e)(1)'], 'CIS': ['3.7']},
    'kv_no_purge_protection':     {'SOC2': ['CC6.7'], 'NIST': ['CP-9'], 'HIPAA': ['164.312(c)(1)'], 'CIS': ['8.4']},
    'kv_no_private_endpoint':     {'SOC2': ['CC6.6'], 'NIST': ['SC-7'], 'HIPAA': ['164.312(e)(1)'], 'CIS': ['8.5']},
    'guest_admin':                {'SOC2': ['CC6.1'], 'NIST': ['AC-2(7)'], 'HIPAA': ['164.312(a)(1)'], 'CIS': ['1.3']},
    'subscription_owner':         {'SOC2': ['CC6.3'], 'NIST': ['AC-6(5)'], 'CIS': ['1.3']},
    'spn_without_owner':          {'SOC2': ['CC6.1'], 'NIST': ['AC-2(4)'], 'CIS': ['1.14']},
    'disabled_account_active_role': {'SOC2': ['CC6.2'], 'NIST': ['AC-2(3)'], 'HIPAA': ['164.312(a)(1)'], 'CIS': ['1.1.4']},
    'sensitive_data_access':      {'SOC2': ['CC6.5'], 'NIST': ['AC-4'], 'HIPAA': ['164.312(a)(1)']},
    'secret_older_180_days':      {'SOC2': ['CC6.1'], 'NIST': ['IA-5(1)'], 'CIS': ['1.11']},
    'managed_identity_subscription_scope': {'SOC2': ['CC6.3'], 'NIST': ['AC-6(1)'], 'CIS': ['1.3']},
}


class ReportingEngine:
    """Generates report datasets from existing engine outputs."""

    def __init__(self, db):
        self.db = db

    def generate(self, report_type: str, parameters: Optional[Dict] = None) -> Dict:
        """
        Generate a report dataset.

        Args:
            report_type: One of VALID_REPORT_TYPES
            parameters: Optional filters (limit, run_id, framework, etc.)

        Returns:
            Dict with 'records' list and 'summary' dict
        """
        params = parameters or {}

        generators = {
            'identity_risk': self._identity_risk,
            'attack_surface': self._attack_surface,
            'remediation_progress': self._remediation_progress,
            'access_review_evidence': self._access_review_evidence,
            'compliance_evidence': self._compliance_evidence,
        }

        gen = generators.get(report_type)
        if not gen:
            raise ValueError(f"Unknown report_type: {report_type}")

        return gen(params)

    # ── Report generators ─────────────────────────────────────────────

    def _identity_risk(self, params: Dict) -> Dict:
        """Top risk identities with blast radius + attack path + finding data."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        limit = min(params.get('limit', 100), 500)

        cursor.execute("""
            SELECT br.identity_id, br.identity_name, br.identity_type,
                   br.risk_score as blast_radius_score,
                   br.identity_exposure_level,
                   br.reachable_resource_count,
                   br.sensitive_resource_count,
                   br.privilege_escalation_paths
            FROM blast_radius_results br
            ORDER BY br.risk_score DESC
            LIMIT %s
        """, (limit,))
        br_rows = [dict(r) for r in cursor.fetchall()]

        # Enrich with attack path and finding counts
        identity_ids = [r['identity_id'] for r in br_rows]
        ap_counts = {}
        f_counts = {}

        if identity_ids:
            ph = ','.join(['%s'] * len(identity_ids))
            cursor.execute(f"""
                SELECT source_entity_id::integer as iid, COUNT(*) as cnt
                FROM attack_paths
                WHERE source_entity_id IN ({ph})
                GROUP BY source_entity_id
            """, identity_ids)
            ap_counts = {r['iid']: r['cnt'] for r in cursor.fetchall()}

            str_ids = [str(i) for i in identity_ids]
            ph2 = ','.join(['%s'] * len(str_ids))
            cursor.execute(f"""
                SELECT entity_id, COUNT(*) as cnt
                FROM security_findings
                WHERE entity_id IN ({ph2}) AND status = 'open'
                GROUP BY entity_id
            """, str_ids)
            f_counts = {int(r['entity_id']): r['cnt'] for r in cursor.fetchall()}

        records = []
        for row in br_rows:
            iid = row['identity_id']
            row['attack_path_count'] = ap_counts.get(iid, 0)
            row['finding_count'] = f_counts.get(iid, 0)
            records.append(row)

        cursor.close()

        # Summary
        critical = sum(1 for r in records if r.get('identity_exposure_level') == 'CRITICAL')
        high = sum(1 for r in records if r.get('identity_exposure_level') == 'HIGH')

        return {
            'records': records,
            'summary': {
                'total_identities': len(records),
                'critical_exposure': critical,
                'high_exposure': high,
                'avg_blast_radius': round(sum(r.get('blast_radius_score', 0) for r in records) / max(len(records), 1), 1),
                'total_attack_paths': sum(r.get('attack_path_count', 0) for r in records),
                'total_open_findings': sum(r.get('finding_count', 0) for r in records),
            },
        }

    def _attack_surface(self, params: Dict) -> Dict:
        """Attack surface overview with path types and exposure metrics."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        limit = min(params.get('limit', 200), 1000)

        cursor.execute("""
            SELECT id, path_type, severity, source_entity_id, source_entity_name,
                   target_entity_id, target_entity_name, impact,
                   path_fingerprint, created_at
            FROM attack_paths
            ORDER BY severity_rank ASC, created_at DESC
            LIMIT %s
        """, (limit,))
        paths = []
        for r in cursor.fetchall():
            d = dict(r)
            if d.get('created_at'):
                d['created_at'] = d['created_at'].isoformat()
            paths.append(d)

        # Severity distribution
        cursor.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM attack_paths
            GROUP BY severity ORDER BY cnt DESC
        """)
        by_severity = {r['severity']: r['cnt'] for r in cursor.fetchall()}

        # Type distribution
        cursor.execute("""
            SELECT path_type, COUNT(*) as cnt
            FROM attack_paths
            GROUP BY path_type ORDER BY cnt DESC
        """)
        by_type = {r['path_type']: r['cnt'] for r in cursor.fetchall()}

        # Blast radius exposure summary
        cursor.execute("""
            SELECT identity_exposure_level, COUNT(*) as cnt
            FROM blast_radius_results
            GROUP BY identity_exposure_level
        """)
        exposure_dist = {r['identity_exposure_level']: r['cnt'] for r in cursor.fetchall()}

        cursor.close()

        return {
            'records': paths,
            'summary': {
                'total_attack_paths': sum(by_severity.values()),
                'by_severity': by_severity,
                'by_type': by_type,
                'exposure_distribution': exposure_dist,
            },
        }

    def _remediation_progress(self, params: Dict) -> Dict:
        """Fix recommendation status and risk reduction tracking."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        limit = min(params.get('limit', 200), 1000)
        status_filter = params.get('status')

        conditions = []
        p = []
        if status_filter:
            conditions.append("status = %s")
            p.append(status_filter)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cursor.execute(f"""
            SELECT id, fix_type, title, fix_category, priority_score,
                   effort, status, entity_id, entity_name, entity_type,
                   risk_reduction_score, linked_finding_count, linked_path_count,
                   created_at
            FROM fix_recommendations {where}
            ORDER BY priority_score DESC
            LIMIT %s
        """, p + [limit])
        records = []
        for r in cursor.fetchall():
            d = dict(r)
            if d.get('created_at'):
                d['created_at'] = d['created_at'].isoformat()
            records.append(d)

        # Status breakdown
        cursor.execute("""
            SELECT status, COUNT(*) as cnt
            FROM fix_recommendations
            GROUP BY status ORDER BY cnt DESC
        """)
        by_status = {r['status']: r['cnt'] for r in cursor.fetchall()}

        # Category breakdown
        cursor.execute("""
            SELECT fix_category, COUNT(*) as cnt
            FROM fix_recommendations WHERE status = 'open'
            GROUP BY fix_category ORDER BY cnt DESC
        """)
        by_category = {r['fix_category']: r['cnt'] for r in cursor.fetchall()}

        # Risk reduction totals
        cursor.execute("""
            SELECT COALESCE(SUM(risk_reduction_score), 0) as completed_reduction
            FROM fix_recommendations WHERE status = 'completed'
        """)
        completed_reduction = cursor.fetchone()['completed_reduction']
        cursor.execute("""
            SELECT COALESCE(SUM(risk_reduction_score), 0) as potential_reduction
            FROM fix_recommendations WHERE status = 'open'
        """)
        potential_reduction = cursor.fetchone()['potential_reduction']

        cursor.close()

        return {
            'records': records,
            'summary': {
                'total_recommendations': sum(by_status.values()),
                'by_status': by_status,
                'by_category': by_category,
                'completed_risk_reduction': completed_reduction,
                'potential_risk_reduction': potential_reduction,
            },
        }

    def _access_review_evidence(self, params: Dict) -> Dict:
        """Access review campaigns with decisions, risk snapshots, and evidence."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        limit = min(params.get('limit', 50), 200)

        cursor.execute("""
            SELECT id, title, review_type, scope, status,
                   total_assignments, completed_assignments,
                   approved_count, revoked_count, flagged_count,
                   review_outcome, review_duration_hours,
                   created_at, completed_at
            FROM access_reviews
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        reviews = []
        review_ids = []
        for r in cursor.fetchall():
            d = dict(r)
            if d.get('created_at'):
                d['created_at'] = d['created_at'].isoformat()
            if d.get('completed_at'):
                d['completed_at'] = d['completed_at'].isoformat()
            d['assignments'] = []
            reviews.append(d)
            review_ids.append(d['id'])

        # Load assignments with risk snapshots for each review
        if review_ids:
            ph = ','.join(['%s'] * len(review_ids))
            cursor.execute(f"""
                SELECT review_id, identity_name, identity_type, role_name, role_type,
                       decision, decision_reason, risk_score, risk_snapshot,
                       decision_at, created_at
                FROM review_assignments
                WHERE review_id IN ({ph})
                ORDER BY risk_score DESC
            """, review_ids)
            assignments_by_review = {}
            for r in cursor.fetchall():
                d = dict(r)
                if d.get('decision_at'):
                    d['decision_at'] = d['decision_at'].isoformat()
                if d.get('created_at'):
                    d['created_at'] = d['created_at'].isoformat()
                if isinstance(d.get('risk_snapshot'), str):
                    d['risk_snapshot'] = json.loads(d['risk_snapshot'])
                rid = d.pop('review_id')
                assignments_by_review.setdefault(rid, []).append(d)

            for rv in reviews:
                rv['assignments'] = assignments_by_review.get(rv['id'], [])

        cursor.close()

        # Summary
        completed = [r for r in reviews if r.get('status') == 'completed']
        durations = [r['review_duration_hours'] for r in completed if r.get('review_duration_hours') is not None]

        return {
            'records': reviews,
            'summary': {
                'total_reviews': len(reviews),
                'completed_reviews': len(completed),
                'total_approved': sum(r.get('approved_count', 0) for r in reviews),
                'total_revoked': sum(r.get('revoked_count', 0) for r in reviews),
                'total_flagged': sum(r.get('flagged_count', 0) for r in reviews),
                'avg_duration_hours': round(sum(durations) / max(len(durations), 1), 1) if durations else None,
            },
        }

    def _compliance_evidence(self, params: Dict) -> Dict:
        """Security findings mapped to compliance frameworks."""
        from psycopg2.extras import RealDictCursor
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        framework = params.get('framework')  # optional filter: SOC2, HIPAA, NIST, CIS
        limit = min(params.get('limit', 300), 1000)

        cursor.execute("""
            SELECT id, finding_type, severity, status, title, description,
                   entity_id, entity_name, entity_type,
                   risk_score, created_at
            FROM security_findings
            ORDER BY risk_score DESC, created_at DESC
            LIMIT %s
        """, (limit,))
        records = []
        framework_counts = {}
        for r in cursor.fetchall():
            d = dict(r)
            if d.get('created_at'):
                d['created_at'] = d['created_at'].isoformat()

            # Map finding_type to compliance refs
            refs = _FINDING_COMPLIANCE_MAP.get(d.get('finding_type'), {})
            d['compliance_refs'] = refs

            # If framework filter, skip findings that don't map
            if framework and framework not in refs:
                continue

            # Count per framework
            for fw in refs:
                framework_counts[fw] = framework_counts.get(fw, 0) + 1

            records.append(d)

        # Severity distribution
        cursor.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM security_findings
            GROUP BY severity ORDER BY cnt DESC
        """)
        by_severity = {r['severity']: r['cnt'] for r in cursor.fetchall()}

        # Status distribution
        cursor.execute("""
            SELECT status, COUNT(*) as cnt
            FROM security_findings
            GROUP BY status ORDER BY cnt DESC
        """)
        by_status = {r['status']: r['cnt'] for r in cursor.fetchall()}

        cursor.close()

        return {
            'records': records,
            'summary': {
                'total_findings': len(records),
                'by_severity': by_severity,
                'by_status': by_status,
                'by_framework': framework_counts,
                'framework_filter': framework,
            },
        }

    # ── Export helpers ─────────────────────────────────────────────────

    @staticmethod
    def export_json(data: Dict, filepath: str) -> int:
        """Write report data as JSON. Returns file size in bytes."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        content = json.dumps(data, indent=2, default=str)
        with open(filepath, 'w') as f:
            f.write(content)
        return os.path.getsize(filepath)

    @staticmethod
    def export_csv(records: List[Dict], filepath: str) -> int:
        """Write report records as CSV. Returns file size in bytes."""
        if not records:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write('')
            return 0

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        fieldnames = list(records[0].keys())
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for rec in records:
            # Flatten nested dicts/lists for CSV
            flat = {}
            for k, v in rec.items():
                if isinstance(v, (dict, list)):
                    flat[k] = json.dumps(v, default=str)
                else:
                    flat[k] = v
            writer.writerow(flat)

        with open(filepath, 'w') as f:
            f.write(buf.getvalue())
        return os.path.getsize(filepath)

    @staticmethod
    def export_pdf(data: Dict, filepath: str, report_type: str) -> int:
        """Write a simple text-based PDF report. Returns file size in bytes."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Simple text-based PDF (no external dependency required)
        lines = []
        lines.append(f"AuditGraph Report: {report_type}")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
        lines.append("=" * 60)
        lines.append("")

        summary = data.get('summary', {})
        lines.append("SUMMARY")
        lines.append("-" * 40)
        for k, v in summary.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

        records = data.get('records', [])
        lines.append(f"RECORDS ({len(records)} total)")
        lines.append("-" * 40)
        for i, rec in enumerate(records[:50]):  # Cap PDF to 50 records
            lines.append(f"  [{i+1}] {json.dumps(rec, default=str)[:200]}")

        if len(records) > 50:
            lines.append(f"  ... and {len(records) - 50} more records (see JSON/CSV export for full data)")

        content = '\n'.join(lines)

        # Write as plain text with .pdf extension
        # (A production system would use a PDF library like reportlab)
        with open(filepath, 'w') as f:
            f.write(content)
        return os.path.getsize(filepath)
