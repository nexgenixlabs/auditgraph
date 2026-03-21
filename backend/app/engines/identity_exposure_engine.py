"""
Identity Exposure Detection Engine

Detects 5 identity exposure patterns and persists results to identity_exposures table:
1. Dormant Privileged — last sign-in > 90 days AND privileged role
2. Long-Lived Credential — credential age > 180 days
3. SP Secret Exposure — secret expiration > 1 year
4. External Privileged User — guest account with privileged role
5. Orphaned Identity — service principal with no recent activity
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

PRIVILEGED_ROLE_NAMES = {
    'Global Administrator', 'Privileged Role Administrator', 'Owner',
    'User Access Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'Contributor',
    'Key Vault Administrator', 'Key Vault Secrets Officer',
    'Security Administrator', 'Compliance Administrator',
    'AdministratorAccess', 'IAMFullAccess', 'PowerUserAccess',
    'roles/owner', 'roles/editor', 'roles/iam.securityAdmin',
}


def _fingerprint(identity_id: str, exposure_type: str) -> str:
    payload = json.dumps({'identity_id': identity_id, 'exposure_type': exposure_type},
                         sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


class IdentityExposureEngine:
    """Detect identity exposure patterns and return structured results."""

    def __init__(self, db):
        self.db = db

    def analyze(self, run_id: int) -> List[Dict]:
        """Run all 5 detection rules against a discovery run.

        Returns list of exposure dicts ready for save_identity_exposures().
        """
        exposures: List[Dict] = []

        detectors = [
            ('dormant_privileged', self._detect_dormant_privileged),
            ('long_lived_credential', self._detect_long_lived_credential),
            ('spn_secret_exposure', self._detect_spn_secret_exposure),
            ('external_privileged', self._detect_external_privileged),
            ('orphaned_identity', self._detect_orphaned_identity),
        ]

        rule_counts: Dict[str, int] = {}
        for name, detector in detectors:
            try:
                results = detector(run_id)
                rule_counts[name] = len(results)
                exposures.extend(results)
            except Exception as e:
                rule_counts[name] = -1
                logger.error(f"  Exposure detector '{name}' failed: {e}")

        # Always log per-rule counts
        for name, count in rule_counts.items():
            label = name.replace('_', ' ').title()
            if count < 0:
                logger.warning(f"  {label}: ERROR")
            else:
                logger.info(f"  {label}: {count}")

        if not exposures:
            # Check whether we have sufficient telemetry to draw conclusions
            has_telemetry = self._has_telemetry(run_id)
            if has_telemetry:
                logger.info(f"Identity exposure engine: 0 exposures for run #{run_id} (clean environment)")
            else:
                logger.warning(f"Identity exposure engine: 0 exposures for run #{run_id} — insufficient telemetry")
        else:
            logger.info(f"Identity exposure engine: {len(exposures)} total for run #{run_id}")

        return exposures

    def _has_telemetry(self, run_id: int) -> bool:
        """Check whether the discovery run has enough data for meaningful detection.

        Returns False if identities lack sign-in data AND credentials are absent,
        which means the engine cannot distinguish clean from uninstrumented.
        """
        try:
            cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(last_sign_in) as with_signin,
                    COUNT(activity_status) FILTER (WHERE activity_status NOT IN ('unknown')) as with_activity
                FROM identities
                WHERE discovery_run_id = %s
            """, (run_id,))
            row = cursor.fetchone()
            cursor.close()

            if not row or row['total'] == 0:
                return False
            # If <10% of identities have sign-in or activity data, telemetry is insufficient
            coverage = (row['with_signin'] + row['with_activity']) / (row['total'] * 2)
            return coverage >= 0.10
        except Exception as e:
            logger.warning(f"Telemetry check failed: {e}")
            return False

    def _detect_dormant_privileged(self, run_id: int) -> List[Dict]:
        """Dormant Privileged: last sign-in > 90 days AND has a privileged role."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, COALESCE(i.cloud, 'azure') as cloud,
                   i.last_sign_in, i.activity_status,
                   array_agg(DISTINCT ra.role_name) FILTER (WHERE ra.role_name IS NOT NULL) as roles
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND ra.role_name = ANY(%s)
              AND (i.last_sign_in IS NULL OR i.last_sign_in < %s)
              AND i.enabled IS NOT false
            GROUP BY i.id, i.identity_id, i.display_name, i.identity_category,
                     i.risk_level, i.risk_score, i.cloud, i.last_sign_in, i.activity_status
        """, (run_id, list(PRIVILEGED_ROLE_NAMES), cutoff))

        results = []
        for row in cursor.fetchall():
            days = None
            if row['last_sign_in']:
                days = (datetime.now(timezone.utc) - row['last_sign_in'].replace(tzinfo=timezone.utc)).days
            roles = row['roles'] or []
            results.append({
                'identity_db_id': row['id'],
                'identity_id': row['identity_id'],
                'identity_name': row['display_name'],
                'identity_category': row['identity_category'],
                'cloud': row['cloud'],
                'exposure_type': 'dormant_privileged',
                'severity': 'critical',
                'risk_score': min(100, (row.get('risk_score') or 0) + 30),
                'description': f"Dormant identity (no sign-in for {days or '90+'} days) with privileged roles: {', '.join(roles[:5])}",
                'details': {
                    'last_sign_in': row['last_sign_in'].isoformat() if row['last_sign_in'] else None,
                    'days_inactive': days,
                    'roles': roles,
                    'activity_status': row['activity_status'],
                },
                'fingerprint': _fingerprint(row['identity_id'] or str(row['id']), 'dormant_privileged'),
            })
        cursor.close()
        return results

    def _detect_long_lived_credential(self, run_id: int) -> List[Dict]:
        """Long-Lived Credential: credential age > 180 days."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        cutoff_180 = datetime.now(timezone.utc) - timedelta(days=180)

        # Check credentials table for old start_datetime
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, COALESCE(i.cloud, 'azure') as cloud,
                   MIN(c.start_datetime) as oldest_credential,
                   COUNT(c.id) as cred_count,
                   COUNT(c.id) FILTER (WHERE c.start_datetime < %s) as old_cred_count
            FROM identities i
            JOIN credentials c ON c.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND c.start_datetime IS NOT NULL
              AND c.start_datetime < %s
            GROUP BY i.id, i.identity_id, i.display_name, i.identity_category,
                     i.risk_level, i.risk_score, i.cloud
        """, (cutoff_180, run_id, cutoff_180))

        results = []
        for row in cursor.fetchall():
            age_days = (datetime.now(timezone.utc) - row['oldest_credential'].replace(tzinfo=timezone.utc)).days if row['oldest_credential'] else 180
            sev = 'critical' if age_days > 365 else 'high'
            results.append({
                'identity_db_id': row['id'],
                'identity_id': row['identity_id'],
                'identity_name': row['display_name'],
                'identity_category': row['identity_category'],
                'cloud': row['cloud'],
                'exposure_type': 'long_lived_credential',
                'severity': sev,
                'risk_score': min(100, 40 + (age_days // 30) * 5),
                'description': f"Credential age {age_days} days (> 180 day threshold). "
                               f"{row['old_cred_count']} of {row['cred_count']} credentials exceed rotation policy.",
                'details': {
                    'oldest_credential_date': row['oldest_credential'].isoformat() if row['oldest_credential'] else None,
                    'age_days': age_days,
                    'old_credential_count': row['old_cred_count'],
                    'total_credential_count': row['cred_count'],
                },
                'fingerprint': _fingerprint(row['identity_id'] or str(row['id']), 'long_lived_credential'),
            })
        cursor.close()
        return results

    def _detect_spn_secret_exposure(self, run_id: int) -> List[Dict]:
        """SP Secret Exposure: service principal with secret expiration > 1 year."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)
        one_year_out = datetime.now(timezone.utc) + timedelta(days=365)

        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name,
                   i.risk_level, i.risk_score, COALESCE(i.cloud, 'azure') as cloud,
                   MAX(c.end_datetime) as furthest_expiry,
                   COUNT(c.id) as secret_count,
                   COUNT(c.id) FILTER (WHERE c.end_datetime > %s) as long_lived_count
            FROM identities i
            JOIN credentials c ON c.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND i.identity_category = 'service_principal'
              AND c.end_datetime IS NOT NULL
              AND c.end_datetime > %s
            GROUP BY i.id, i.identity_id, i.display_name,
                     i.risk_level, i.risk_score, i.cloud
        """, (one_year_out, run_id, one_year_out))

        results = []
        for row in cursor.fetchall():
            expiry = row['furthest_expiry']
            days_until = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days if expiry else 365
            results.append({
                'identity_db_id': row['id'],
                'identity_id': row['identity_id'],
                'identity_name': row['display_name'],
                'identity_category': 'service_principal',
                'cloud': row['cloud'],
                'exposure_type': 'spn_secret_exposure',
                'severity': 'high',
                'risk_score': min(100, 50 + (days_until // 365) * 10),
                'description': f"SPN has {row['long_lived_count']} secret(s) with expiration > 1 year "
                               f"(furthest: {days_until} days out).",
                'details': {
                    'furthest_expiry': expiry.isoformat() if expiry else None,
                    'days_until_expiry': days_until,
                    'long_lived_secret_count': row['long_lived_count'],
                    'total_secret_count': row['secret_count'],
                },
                'fingerprint': _fingerprint(row['identity_id'] or str(row['id']), 'spn_secret_exposure'),
            })
        cursor.close()
        return results

    def _detect_external_privileged(self, run_id: int) -> List[Dict]:
        """External Privileged User: guest account with privileged role."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.risk_level, i.risk_score, COALESCE(i.cloud, 'azure') as cloud,
                   array_agg(DISTINCT ra.role_name) FILTER (WHERE ra.role_name IS NOT NULL) as roles
            FROM identities i
            JOIN role_assignments ra ON ra.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
              AND i.identity_category IN ('guest', 'gcp_domain', 'gcp_member')
              AND ra.role_name = ANY(%s)
            GROUP BY i.id, i.identity_id, i.display_name, i.identity_category,
                     i.risk_level, i.risk_score, i.cloud
        """, (run_id, list(PRIVILEGED_ROLE_NAMES)))

        results = []
        for row in cursor.fetchall():
            roles = row['roles'] or []
            results.append({
                'identity_db_id': row['id'],
                'identity_id': row['identity_id'],
                'identity_name': row['display_name'],
                'identity_category': row['identity_category'],
                'cloud': row['cloud'],
                'exposure_type': 'external_privileged',
                'severity': 'critical',
                'risk_score': min(100, (row.get('risk_score') or 0) + 40),
                'description': f"External/guest identity with privileged roles: {', '.join(roles[:5])}",
                'details': {
                    'roles': roles,
                    'identity_type': row['identity_category'],
                },
                'fingerprint': _fingerprint(row['identity_id'] or str(row['id']), 'external_privileged'),
            })
        cursor.close()
        return results

    def _detect_orphaned_identity(self, run_id: int) -> List[Dict]:
        """Orphaned Identity: service principal with no recent activity."""
        cursor = self.db.conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name,
                   i.risk_level, i.risk_score, COALESCE(i.cloud, 'azure') as cloud,
                   i.activity_status, i.last_sign_in, i.owner_count
            FROM identities i
            WHERE i.discovery_run_id = %s
              AND i.identity_category = 'service_principal'
              AND i.activity_status IN ('stale', 'inactive', 'never_used')
              AND i.enabled IS NOT false
              AND COALESCE(i.is_microsoft_system, FALSE) = FALSE
        """, (run_id,))

        results = []
        for row in cursor.fetchall():
            days = None
            if row['last_sign_in']:
                days = (datetime.now(timezone.utc) - row['last_sign_in'].replace(tzinfo=timezone.utc)).days
            results.append({
                'identity_db_id': row['id'],
                'identity_id': row['identity_id'],
                'identity_name': row['display_name'],
                'identity_category': 'service_principal',
                'cloud': row['cloud'],
                'exposure_type': 'orphaned_identity',
                'severity': 'high' if (row.get('owner_count') or 0) == 0 else 'medium',
                'risk_score': min(100, 35 + (20 if (row.get('owner_count') or 0) == 0 else 0)),
                'description': f"Service principal with no recent activity (status: {row['activity_status']})"
                               f"{', no owner assigned' if (row.get('owner_count') or 0) == 0 else ''}.",
                'details': {
                    'activity_status': row['activity_status'],
                    'last_sign_in': row['last_sign_in'].isoformat() if row['last_sign_in'] else None,
                    'days_inactive': days,
                    'owner_count': row.get('owner_count', 0),
                },
                'fingerprint': _fingerprint(row['identity_id'] or str(row['id']), 'orphaned_identity'),
            })
        cursor.close()
        return results
