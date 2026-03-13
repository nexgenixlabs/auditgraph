"""
Phase 2: Security Findings Engine

Policy-based security findings engine that evaluates the current snapshot state
and generates actionable findings. Distinct from:
- AnomalyDetector (compares two runs for temporal patterns)
- DriftDetector (detects changes between runs)
- resource_findings (CIS-specific, tightly coupled to resource risk scoring)

Runs 14 detection rules against the latest discovery snapshot, returns findings
with UPSERT semantics for persistence.
"""

import hashlib
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def compute_finding_fingerprint(entity_id: str, finding_type: str) -> str:
    """Compute a deterministic SHA-256 fingerprint for a security finding.

    Stable across snapshots — same entity + finding type always produces
    the same hash, enabling cross-run deduplication.
    """
    payload = json.dumps({
        'entity_id': entity_id,
        'finding_type': finding_type,
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()

# Admin Entra roles that flag a guest as high-risk
_ADMIN_ENTRA_ROLES = {
    'Global Administrator', 'Privileged Role Administrator',
    'Privileged Authentication Administrator', 'User Access Administrator',
    'Application Administrator', 'Cloud Application Administrator',
    'Exchange Administrator', 'SharePoint Administrator',
    'Security Administrator', 'Compliance Administrator',
    'Intune Administrator', 'Hybrid Identity Administrator',
}

# Broad RBAC roles flagged for subscription-scope overprivilege
_BROAD_RBAC_ROLES = {'Owner', 'Contributor', 'User Access Administrator'}


class SecurityFindingsEngine:
    """Evaluate snapshot state against 15 security detection rules."""

    def __init__(self, db):
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, run_id: int) -> List[Dict]:
        """Run all detection rules against a single discovery run.

        Returns list of finding dicts ready for save_security_findings().
        """
        findings: List[Dict] = []

        detectors = [
            ('unused_service_principal', self._detect_unused_spn),
            ('dormant_privileged_identity', self._detect_dormant_privileged),
            ('disabled_account_active_role', self._detect_disabled_active_role),
            ('guest_admin', self._detect_guest_admin),
            ('user_without_mfa', self._detect_no_mfa),
            ('spn_without_owner', self._detect_spn_no_owner),
            ('spn_secret_expired', self._detect_spn_expired_secret),
            ('secret_older_180_days', self._detect_old_secrets),
            ('managed_identity_subscription_scope', self._detect_mi_sub_scope),
            ('subscription_owner', self._detect_sub_owner),
            ('sensitive_data_access', self._detect_sensitive_data_access),
            ('overly_broad_rbac', self._detect_broad_rbac),
            ('storage_public_access', self._detect_storage_public),
            ('kv_no_purge_protection', self._detect_kv_no_purge),
            ('kv_no_private_endpoint', self._detect_kv_no_private),
        ]

        for name, detector in detectors:
            try:
                logger.info(f"Running rule {name}")
                results = detector(run_id)
                findings.extend(results)
                logger.info(f"{len(results)} findings generated")
            except Exception as e:
                logger.error(f"  Security finding detector '{name}' failed: {e}")

        logger.info(f"Security findings engine: {len(findings)} total finding(s) for run #{run_id}")
        return findings

    def analyze_multi(self, run_ids: List[int]) -> List[Dict]:
        """Run analysis across multiple run IDs (e.g. multi-subscription)."""
        all_findings: List[Dict] = []
        for rid in run_ids:
            all_findings.extend(self.analyze(rid))
        return all_findings

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_finding(
        finding_type: str,
        entity_type: str,
        entity_id: str,
        severity: str,
        risk_score: int,
        title: str,
        description: str,
        recommended_fix: str = None,
        metadata: dict = None,
        identity_name: str = None,
    ) -> Dict:
        meta = metadata or {}
        if identity_name:
            meta['display_name'] = identity_name
        return {
            'finding_type': finding_type,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'severity': severity,
            'risk_score': risk_score,
            'title': title,
            'description': description,
            'recommended_fix': recommended_fix,
            'metadata': meta,
            'finding_fingerprint': compute_finding_fingerprint(entity_id, finding_type),
            'identity_name': identity_name or '',
        }

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _detect_unused_spn(self, run_id: int) -> List[Dict]:
        """Rule 0: Service principal inactive for 90+ days."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.activity_status, i.last_sign_in
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category = 'service_principal'
                  AND i.activity_status IN ('stale', 'dormant', 'never_used')
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, activity_status, last_sign_in = row
            findings.append(self._build_finding(
                finding_type='unused_service_principal',
                entity_type='service_principal',
                entity_id=identity_id,
                severity='high',
                risk_score=70,
                title=f'Unused service principal: {display_name}',
                description=(
                    f'Service principal {display_name} has not been used in over 90 days '
                    f'(status: {activity_status}). Last activity: '
                    f'{last_sign_in.isoformat() if last_sign_in else "never"}. '
                    f'Unused SPNs may represent abandoned automation with stale permissions.'
                ),
                recommended_fix='Review whether this service principal is still needed. If unused, disable or delete it.',
                metadata={'activity_status': activity_status},
                identity_name=display_name,
            ))
        return findings

    def _detect_dormant_privileged(self, run_id: int) -> List[Dict]:
        """Rule 1: Dormant identity with privileged roles (RBAC or Entra)."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT DISTINCT i.identity_id, i.display_name, i.activity_status,
                       i.identity_category, i.last_sign_in
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.activity_status IN ('inactive', 'stale', 'never_used', 'dormant')
                  AND (
                      EXISTS (
                          SELECT 1 FROM role_assignments ra
                          WHERE ra.identity_db_id = i.id
                            AND ra.role_name IN ('Owner', 'Contributor', 'User Access Administrator')
                      )
                      OR EXISTS (
                          SELECT 1 FROM entra_role_assignments era
                          WHERE era.identity_db_id = i.id
                      )
                  )
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, activity_status, category, last_sign_in = row
            findings.append(self._build_finding(
                finding_type='dormant_privileged_identity',
                entity_type='identity',
                entity_id=identity_id,
                severity='high',
                risk_score=80,
                title=f'Dormant privileged identity: {display_name}',
                description=(
                    f'{display_name} ({category}) is {activity_status} but holds '
                    f'privileged role assignments. Last sign-in: '
                    f'{last_sign_in.isoformat() if last_sign_in else "never"}.'
                ),
                recommended_fix='Remove privileged role assignments or disable the identity.',
                metadata={'activity_status': activity_status, 'category': category},
                identity_name=display_name,
            ))
        return findings

    def _detect_disabled_active_role(self, run_id: int) -> List[Dict]:
        """Rule 2: Disabled account that still has active role assignments."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT DISTINCT i.identity_id, i.display_name, i.identity_category
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.enabled = FALSE
                  AND (
                      EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                      OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id)
                  )
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, category = row
            findings.append(self._build_finding(
                finding_type='disabled_account_active_role',
                entity_type='identity',
                entity_id=identity_id,
                severity='critical',
                risk_score=95,
                title=f'Disabled account retains roles: {display_name}',
                description=(
                    f'{display_name} ({category}) is disabled but still has active '
                    f'RBAC or Entra role assignments that could be exploited.'
                ),
                recommended_fix='Remove all role assignments from the disabled account.',
                metadata={'category': category},
                identity_name=display_name,
            ))
        return findings

    def _detect_guest_admin(self, run_id: int) -> List[Dict]:
        """Rule 3: Guest user with administrative Entra roles."""
        cursor = self.db.conn.cursor()
        try:
            placeholders = ','.join(['%s'] * len(_ADMIN_ENTRA_ROLES))
            cursor.execute(f"""
                SELECT DISTINCT i.identity_id, i.display_name,
                       array_agg(DISTINCT era.role_name) as admin_roles
                FROM identities i
                JOIN entra_role_assignments era ON era.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category = 'guest'
                  AND era.role_name IN ({placeholders})
                GROUP BY i.identity_id, i.display_name
            """, (run_id, *_ADMIN_ENTRA_ROLES))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, admin_roles = row
            roles_str = ', '.join(admin_roles) if admin_roles else 'admin roles'
            findings.append(self._build_finding(
                finding_type='guest_admin',
                entity_type='identity',
                entity_id=identity_id,
                severity='critical',
                risk_score=95,
                title=f'Guest user with admin roles: {display_name}',
                description=(
                    f'External guest {display_name} holds administrative Entra roles: '
                    f'{roles_str}. Guests with admin access pose significant risk.'
                ),
                recommended_fix='Remove administrative roles from guest accounts or convert to member.',
                metadata={'admin_roles': admin_roles},
                identity_name=display_name,
            ))
        return findings

    def _detect_no_mfa(self, run_id: int) -> List[Dict]:
        """Rule 4: Human user without MFA enforcement."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.identity_id, i.display_name
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category IN ('human_user', 'guest')
                  AND (i.ca_mfa_enforced = FALSE OR i.ca_mfa_enforced IS NULL)
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name = row
            findings.append(self._build_finding(
                finding_type='user_without_mfa',
                entity_type='identity',
                entity_id=identity_id,
                severity='high',
                risk_score=70,
                title=f'No MFA enforcement: {display_name}',
                description=(
                    f'{display_name} does not have MFA enforced via conditional access policies. '
                    f'Accounts without MFA are vulnerable to credential theft.'
                ),
                recommended_fix='Enable MFA via conditional access policy for all human users.',
                identity_name=display_name,
            ))
        return findings

    def _detect_spn_no_owner(self, run_id: int) -> List[Dict]:
        """Rule 5: Service principal without an assigned owner."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.identity_id, i.display_name
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category = 'service_principal'
                  AND COALESCE(i.owner_count, 0) = 0
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name = row
            findings.append(self._build_finding(
                finding_type='spn_without_owner',
                entity_type='service_principal',
                entity_id=identity_id,
                severity='medium',
                risk_score=55,
                title=f'Unowned service principal: {display_name}',
                description=(
                    f'{display_name} has no assigned owner. Unowned service principals '
                    f'lack accountability and may indicate unmanaged automation.'
                ),
                recommended_fix='Assign an owner to this service principal in Entra ID.',
                identity_name=display_name,
            ))
        return findings

    def _detect_spn_expired_secret(self, run_id: int) -> List[Dict]:
        """Rule 6: Service principal with expired credential."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.credential_status
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category = 'service_principal'
                  AND i.credential_status = 'expired'
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, _ = row
            findings.append(self._build_finding(
                finding_type='spn_secret_expired',
                entity_type='service_principal',
                entity_id=identity_id,
                severity='critical',
                risk_score=90,
                title=f'Expired service principal credential: {display_name}',
                description=(
                    f'{display_name} has expired credentials. Expired secrets indicate '
                    f'a rotation failure or abandoned application, posing authentication '
                    f'and security risks.'
                ),
                recommended_fix='Rotate or remove the expired credential. If the SPN is unused, disable it.',
                identity_name=display_name,
            ))
        return findings

    def _detect_old_secrets(self, run_id: int) -> List[Dict]:
        """Rule 7: Service principal credential older than 180 days."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.credential_expiration
                FROM identities i
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category = 'service_principal'
                  AND i.credential_expiration IS NOT NULL
                  AND i.credential_expiration < NOW() + INTERVAL '180 days'
                  AND i.credential_status != 'expired'
                  AND i.created_datetime IS NOT NULL
                  AND i.created_datetime < NOW() - INTERVAL '180 days'
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, cred_exp = row
            findings.append(self._build_finding(
                finding_type='secret_older_180_days',
                entity_type='service_principal',
                entity_id=identity_id,
                severity='medium',
                risk_score=50,
                title=f'Credential older than 180 days: {display_name}',
                description=(
                    f'{display_name} has a credential that is over 180 days old. '
                    f'Long-lived secrets increase exposure window if compromised.'
                ),
                recommended_fix='Rotate credentials to a maximum 90-day lifetime.',
                metadata={
                    'credential_expiration': cred_exp.isoformat() if cred_exp else None,
                },
                identity_name=display_name,
            ))
        return findings

    def _detect_mi_sub_scope(self, run_id: int) -> List[Dict]:
        """Rule 8: Managed identity with subscription-scope role assignment."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT DISTINCT i.identity_id, i.display_name,
                       array_agg(DISTINCT ra.role_name) as roles
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND i.identity_category IN ('managed_identity_system', 'managed_identity_user')
                  AND ra.scope_type = 'subscription'
                GROUP BY i.identity_id, i.display_name
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, roles = row
            roles_str = ', '.join(roles) if roles else 'roles'
            findings.append(self._build_finding(
                finding_type='managed_identity_subscription_scope',
                entity_type='managed_identity',
                entity_id=identity_id,
                severity='medium',
                risk_score=55,
                title=f'Managed identity with subscription-scope access: {display_name}',
                description=(
                    f'{display_name} has subscription-level role assignments ({roles_str}). '
                    f'Managed identities should follow least privilege with resource-group or resource scope.'
                ),
                recommended_fix='Narrow scope to resource group or individual resource level.',
                metadata={'roles': roles},
                identity_name=display_name,
            ))
        return findings

    def _detect_sub_owner(self, run_id: int) -> List[Dict]:
        """Rule 9: Identity with Owner role at subscription scope."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT DISTINCT i.identity_id, i.display_name, i.identity_category,
                       ra.scope
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND ra.role_name = 'Owner'
                  AND ra.scope_type = 'subscription'
            """, (run_id,))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, category, scope = row
            findings.append(self._build_finding(
                finding_type='subscription_owner',
                entity_type='role_assignment',
                entity_id=identity_id,
                severity='high',
                risk_score=80,
                title=f'Subscription Owner: {display_name}',
                description=(
                    f'{display_name} ({category}) has Owner role at subscription scope '
                    f'({scope}). Subscription Owners have full control including '
                    f'RBAC management.'
                ),
                recommended_fix='Use PIM for just-in-time Owner activation. Reduce standing Owner assignments.',
                metadata={'category': category, 'scope': scope},
                identity_name=display_name,
            ))
        return findings

    def _detect_sensitive_data_access(self, run_id: int) -> List[Dict]:
        """Rule 10: Identity with RBAC access to classified sensitive resources."""
        cursor = self.db.conn.cursor()
        try:
            # Get classified resources
            classified = []
            for table, rtype in [('azure_storage_accounts', 'storage_account'),
                                  ('azure_key_vaults', 'key_vault')]:
                try:
                    cursor.execute(f"""
                        SELECT resource_id, name, data_classification,
                               resource_group, subscription_id
                        FROM {table}
                        WHERE discovery_run_id = %s
                          AND data_classification IS NOT NULL
                    """, (run_id,))
                    for r in cursor.fetchall():
                        classified.append({
                            'resource_id': r[0], 'name': r[1],
                            'classification': r[2], 'rg': r[3],
                            'sub': r[4], 'type': rtype,
                        })
                except Exception:
                    pass  # Table may not exist yet

            if not classified:
                return []

            # Get identities with role assignments
            cursor.execute("""
                SELECT i.identity_id, i.display_name, i.identity_category,
                       ra.role_name, ra.scope, ra.scope_type
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
            """, (run_id,))
            assignments = cursor.fetchall()
        finally:
            cursor.close()

        # Match scope hierarchy: subscription → RG → resource
        findings = []
        seen = set()
        for identity_id, display_name, category, role_name, scope, scope_type in assignments:
            scope_lower = (scope or '').lower()
            for res in classified:
                res_id_lower = (res['resource_id'] or '').lower()
                res_sub = (res['sub'] or '').lower()
                res_rg = (res['rg'] or '').lower()

                match = False
                if scope_type == 'subscription' and res_sub and res_sub in scope_lower:
                    match = True
                elif scope_type == 'resource_group' and res_rg and res_rg.lower() in scope_lower:
                    match = True
                elif res_id_lower and res_id_lower in scope_lower:
                    match = True

                if match:
                    key = (identity_id, res['resource_id'])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._build_finding(
                        finding_type='sensitive_data_access',
                        entity_type='identity',
                        entity_id=identity_id,
                        severity='medium',
                        risk_score=60,
                        title=f'Access to sensitive resource: {display_name} \u2192 {res["name"]}',
                        description=(
                            f'{display_name} ({category}) has {role_name} access to '
                            f'{res["name"]} (classified: {res["classification"]}) '
                            f'via {scope_type} scope.'
                        ),
                        recommended_fix='Review whether this identity requires access to sensitive data.',
                        metadata={
                            'resource_name': res['name'],
                            'classification': res['classification'],
                            'role': role_name,
                            'scope_type': scope_type,
                        },
                        identity_name=display_name,
                    ))
        return findings

    def _detect_broad_rbac(self, run_id: int) -> List[Dict]:
        """Rule 11: Overly broad RBAC — Contributor/Owner at subscription scope."""
        cursor = self.db.conn.cursor()
        try:
            placeholders = ','.join(['%s'] * len(_BROAD_RBAC_ROLES))
            cursor.execute(f"""
                SELECT DISTINCT i.identity_id, i.display_name, i.identity_category,
                       ra.role_name, ra.scope
                FROM identities i
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE i.discovery_run_id = %s
                  AND i.is_microsoft_system = FALSE
                  AND ra.role_name IN ({placeholders})
                  AND ra.scope_type = 'subscription'
            """, (run_id, *_BROAD_RBAC_ROLES))
            rows = cursor.fetchall()
        finally:
            cursor.close()

        findings = []
        for row in rows:
            identity_id, display_name, category, role_name, scope = row
            findings.append(self._build_finding(
                finding_type='overly_broad_rbac',
                entity_type='role_assignment',
                entity_id=identity_id,
                severity='high',
                risk_score=75,
                title=f'Broad subscription-level {role_name}: {display_name}',
                description=(
                    f'{display_name} ({category}) has {role_name} at subscription scope '
                    f'({scope}). Broad roles at subscription level violate least privilege.'
                ),
                recommended_fix='Narrow to resource group scope or use more specific built-in roles.',
                metadata={'role_name': role_name, 'category': category, 'scope': scope},
                identity_name=display_name,
            ))
        return findings

    def _detect_storage_public(self, run_id: int) -> List[Dict]:
        """Rule 12: Storage account with public blob access enabled."""
        cursor = self.db.conn.cursor()
        try:
            try:
                cursor.execute("""
                    SELECT resource_id, name, resource_group, subscription_name
                    FROM azure_storage_accounts
                    WHERE discovery_run_id = %s
                      AND public_blob_access = TRUE
                """, (run_id,))
                rows = cursor.fetchall()
            except Exception:
                return []  # Table may not exist
        finally:
            cursor.close()

        findings = []
        for row in rows:
            resource_id, name, rg, sub = row
            findings.append(self._build_finding(
                finding_type='storage_public_access',
                entity_type='storage_account',
                entity_id=resource_id or name,
                severity='critical',
                risk_score=90,
                title=f'Public blob access enabled: {name}',
                description=(
                    f'Storage account {name} in {rg or "unknown RG"} '
                    f'({sub or "unknown subscription"}) has public blob access enabled. '
                    f'This allows anonymous internet access to blob data.'
                ),
                recommended_fix='Disable public blob access. Use private endpoints or SAS tokens.',
                metadata={'resource_group': rg, 'subscription': sub},
            ))
        return findings

    def _detect_kv_no_purge(self, run_id: int) -> List[Dict]:
        """Rule 13: Key vault without purge protection."""
        cursor = self.db.conn.cursor()
        try:
            try:
                cursor.execute("""
                    SELECT resource_id, name, resource_group, subscription_name
                    FROM azure_key_vaults
                    WHERE discovery_run_id = %s
                      AND (purge_protection = FALSE OR purge_protection IS NULL)
                """, (run_id,))
                rows = cursor.fetchall()
            except Exception:
                return []
        finally:
            cursor.close()

        findings = []
        for row in rows:
            resource_id, name, rg, sub = row
            findings.append(self._build_finding(
                finding_type='kv_no_purge_protection',
                entity_type='key_vault',
                entity_id=resource_id or name,
                severity='high',
                risk_score=70,
                title=f'No purge protection: {name}',
                description=(
                    f'Key vault {name} in {rg or "unknown RG"} does not have '
                    f'purge protection enabled. Deleted secrets can be permanently '
                    f'destroyed without recovery.'
                ),
                recommended_fix='Enable purge protection on the key vault.',
                metadata={'resource_group': rg, 'subscription': sub},
            ))
        return findings

    def _detect_kv_no_private(self, run_id: int) -> List[Dict]:
        """Rule 14: Key vault without private endpoint."""
        cursor = self.db.conn.cursor()
        try:
            try:
                cursor.execute("""
                    SELECT resource_id, name, resource_group, subscription_name
                    FROM azure_key_vaults
                    WHERE discovery_run_id = %s
                      AND COALESCE(private_endpoint_count, 0) = 0
                """, (run_id,))
                rows = cursor.fetchall()
            except Exception:
                return []
        finally:
            cursor.close()

        findings = []
        for row in rows:
            resource_id, name, rg, sub = row
            findings.append(self._build_finding(
                finding_type='kv_no_private_endpoint',
                entity_type='key_vault',
                entity_id=resource_id or name,
                severity='medium',
                risk_score=55,
                title=f'No private endpoint: {name}',
                description=(
                    f'Key vault {name} in {rg or "unknown RG"} has no private endpoint. '
                    f'Traffic to the vault traverses the public internet.'
                ),
                recommended_fix='Configure a private endpoint for the key vault.',
                metadata={'resource_group': rg, 'subscription': sub},
            ))
        return findings
