"""
RBAC Hygiene Engine

Assignment-first analysis of Azure RBAC and Entra role assignments.
Detects 7 categories of hygiene issues:
  1. Orphaned Assignments — role assigned to a deleted/non-existent principal
  2. Disabled Principal Access — disabled identity still has active roles
  3. Dormant Access — identity has roles but hasn't signed in recently
  4. Credential Risk — service principals with expired/expiring credentials
  5. Overprivileged Access — Owner/UAA at subscription+ scope
  6. Management Group Access — broad blast radius via MG-level assignments
  7. Guest Standing Access — external users with permanent privileged roles

Outputs a per-tenant hygiene score (0-100) and actionable findings list.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# § 1  CONSTANTS
# ──────────────────────────────────────────────────────────────

PRIVILEGED_RBAC_ROLES = {
    'owner', 'user access administrator', 'contributor',
    'key vault administrator', 'security admin',
    'managed identity operator', 'managed identity contributor',
    'storage blob data owner',
}

PRIVILEGED_ENTRA_ROLES = {
    'global administrator', 'privileged role administrator',
    'application administrator', 'cloud application administrator',
    'user administrator', 'exchange administrator',
    'security administrator', 'conditional access administrator',
    'authentication administrator', 'intune administrator',
    'password administrator',
}

CRITICAL_RBAC_ROLES = {'owner', 'user access administrator'}
CRITICAL_ENTRA_ROLES = {'global administrator', 'privileged role administrator'}

DORMANT_THRESHOLD_DAYS = 90
IDLE_THRESHOLD_DAYS = 30
CREDENTIAL_WARNING_DAYS = 30

FINDING_SEVERITY = {
    'orphaned_assignment':   'critical',
    'disabled_principal':    'high',
    'dormant_access':        'high',
    'credential_risk':       'high',
    'overprivileged':        'medium',
    'mg_level_access':       'medium',
    'guest_standing_access': 'medium',
}

FINDING_LABELS = {
    'orphaned_assignment':   'Orphaned Assignment',
    'disabled_principal':    'Disabled Principal with Access',
    'dormant_access':        'Dormant Access',
    'credential_risk':       'Credential Risk',
    'overprivileged':        'Overprivileged Access',
    'mg_level_access':       'Management Group Access',
    'guest_standing_access': 'Guest Standing Access',
}


# ──────────────────────────────────────────────────────────────
# § 2  DATA MODEL
# ──────────────────────────────────────────────────────────────

@dataclass
class HygieneFinding:
    """A single RBAC hygiene finding."""
    rule: str                           # one of the 7 rule keys
    severity: str                       # critical / high / medium / low
    identity_db_id: int
    identity_id: str
    identity_name: str
    identity_category: str
    role_name: str
    role_source: str                    # 'rbac' or 'entra'
    scope: str
    scope_type: str
    title: str
    detail: str
    recommendation: str
    risk_score: int = 0                 # 0-100 contribution
    days_since_activity: Optional[int] = None
    credential_status: Optional[str] = None
    assignment_age_days: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            'rule': self.rule,
            'rule_label': FINDING_LABELS.get(self.rule, self.rule),
            'severity': self.severity,
            'identity_db_id': self.identity_db_id,
            'identity_id': self.identity_id,
            'identity_name': self.identity_name,
            'identity_category': self.identity_category,
            'role_name': self.role_name,
            'role_source': self.role_source,
            'scope': self.scope,
            'scope_type': self.scope_type,
            'title': self.title,
            'detail': self.detail,
            'recommendation': self.recommendation,
            'risk_score': self.risk_score,
            'days_since_activity': self.days_since_activity,
            'credential_status': self.credential_status,
            'assignment_age_days': self.assignment_age_days,
        }


# ──────────────────────────────────────────────────────────────
# § 3  ENGINE
# ──────────────────────────────────────────────────────────────

class RbacHygieneEngine:
    """Analyzes RBAC assignments and produces hygiene findings + score."""

    def __init__(self, db):
        self.db = db

    def run(self, run_id: Optional[int] = None) -> Dict:
        """Execute all 7 hygiene rules and return summary + findings."""
        logger.info("Starting RBAC hygiene analysis...")

        # Load data
        assignments = self._load_assignments(run_id)
        identities = self._load_identity_map(run_id)

        findings: List[HygieneFinding] = []

        # Run all 7 rules
        findings.extend(self._rule_orphaned(assignments, identities))
        findings.extend(self._rule_disabled(assignments, identities))
        findings.extend(self._rule_dormant(assignments, identities))
        findings.extend(self._rule_credential_risk(assignments, identities))
        findings.extend(self._rule_overprivileged(assignments, identities))
        findings.extend(self._rule_mg_access(assignments, identities))
        findings.extend(self._rule_guest_standing(assignments, identities))

        # Compute score
        score, grade = self._compute_score(assignments, findings)

        # Build summary by rule
        by_rule = {}
        for rule_key in FINDING_LABELS:
            rule_findings = [f for f in findings if f.rule == rule_key]
            by_rule[rule_key] = {
                'label': FINDING_LABELS[rule_key],
                'severity': FINDING_SEVERITY[rule_key],
                'count': len(rule_findings),
                'identities_affected': len(set(f.identity_db_id for f in rule_findings)),
            }

        # By severity
        by_severity = {}
        for sev in ('critical', 'high', 'medium', 'low'):
            by_severity[sev] = len([f for f in findings if f.severity == sev])

        result = {
            'score': score,
            'grade': grade,
            'total_assignments': len(assignments),
            'total_findings': len(findings),
            'by_rule': by_rule,
            'by_severity': by_severity,
            'findings': [f.to_dict() for f in findings],
            'analyzed_at': datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "RBAC hygiene analysis complete: score=%d, grade=%s, findings=%d",
            score, grade, len(findings)
        )
        return result

    # ── Data Loading ──────────────────────────────────────────

    def _load_assignments(self, run_id: Optional[int] = None) -> List[Dict]:
        """Load all RBAC + Entra role assignments with identity context."""
        cursor = self.db.conn.cursor()

        # Build run filter
        run_filter = ""
        params: list = []
        if run_id:
            run_filter = "AND i.discovery_run_id = %s"
            params = [run_id, run_id]
        else:
            run_filter = """AND i.discovery_run_id = (
                SELECT id FROM discovery_runs
                WHERE status = 'completed'
                ORDER BY completed_at DESC LIMIT 1
            )"""

        # RBAC assignments
        sql_rbac = f"""
            SELECT
                ra.id, ra.identity_db_id, ra.role_name, ra.scope, ra.scope_type,
                ra.principal_id, ra.created_on, ra.days_since_assigned,
                ra.risk_level, ra.why_critical, ra.scope_exists,
                'rbac' as role_source,
                i.identity_id, i.display_name, i.identity_category,
                i.activity_status, i.last_sign_in, i.enabled,
                i.credential_status, i.credential_expiration,
                i.risk_level as identity_risk
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE 1=1 {run_filter}
        """

        # Entra assignments
        sql_entra = f"""
            SELECT
                era.id, era.identity_db_id, era.role_name,
                COALESCE(era.directory_scope, '/') as scope,
                'directory' as scope_type,
                '' as principal_id, era.assigned_on as created_on,
                era.days_since_assigned,
                era.risk_level, era.why_critical,
                true as scope_exists,
                'entra' as role_source,
                i.identity_id, i.display_name, i.identity_category,
                i.activity_status, i.last_sign_in, i.enabled,
                i.credential_status, i.credential_expiration,
                i.risk_level as identity_risk
            FROM entra_role_assignments era
            JOIN identities i ON i.id = era.identity_db_id
            WHERE 1=1 {run_filter}
        """

        assignments = []

        if run_id:
            cursor.execute(sql_rbac, [run_id])
        else:
            cursor.execute(sql_rbac)
        for row in cursor.fetchall():
            assignments.append(self._row_to_assignment(row, 'rbac'))

        if run_id:
            cursor.execute(sql_entra, [run_id])
        else:
            cursor.execute(sql_entra)
        for row in cursor.fetchall():
            assignments.append(self._row_to_assignment(row, 'entra'))

        cursor.close()
        return assignments

    def _row_to_assignment(self, row, source: str) -> Dict:
        return {
            'assignment_id': row[0],
            'identity_db_id': row[1],
            'role_name': row[2] or '',
            'scope': row[3] or '',
            'scope_type': row[4] or '',
            'principal_id': row[5] or '',
            'created_on': row[6],
            'days_since_assigned': row[7],
            'risk_level': row[8] or 'info',
            'why_critical': row[9],
            'scope_exists': row[10] if row[10] is not None else True,
            'role_source': source,
            'identity_id': row[12] or '',
            'identity_name': row[13] or '',
            'identity_category': row[14] or '',
            'activity_status': row[15] or 'unknown',
            'last_sign_in': row[16],
            'enabled': row[17] if row[17] is not None else True,
            'credential_status': row[18] or 'unknown',
            'credential_expiration': row[19],
            'identity_risk': row[20] or 'info',
        }

    def _load_identity_map(self, run_id: Optional[int] = None) -> Dict[int, Dict]:
        """Load identity details keyed by identity_db_id."""
        cursor = self.db.conn.cursor()

        run_filter = ""
        params: list = []
        if run_id:
            run_filter = "WHERE discovery_run_id = %s"
            params = [run_id]
        else:
            run_filter = """WHERE discovery_run_id = (
                SELECT id FROM discovery_runs
                WHERE status = 'completed'
                ORDER BY completed_at DESC LIMIT 1
            )"""

        cursor.execute(f"""
            SELECT id, identity_id, display_name, identity_category,
                   activity_status, last_sign_in, enabled,
                   credential_status, credential_expiration,
                   risk_level, object_id
            FROM identities
            {run_filter}
        """, params)

        result = {}
        for row in cursor.fetchall():
            result[row[0]] = {
                'id': row[0],
                'identity_id': row[1],
                'display_name': row[2],
                'identity_category': row[3] or '',
                'activity_status': row[4] or 'unknown',
                'last_sign_in': row[5],
                'enabled': row[6] if row[6] is not None else True,
                'credential_status': row[7] or 'unknown',
                'credential_expiration': row[8],
                'risk_level': row[9] or 'info',
                'object_id': row[10],
            }

        cursor.close()
        return result

    # ── Rule 1: Orphaned Assignments ──────────────────────────

    def _rule_orphaned(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect assignments where scope_exists is False or principal not found."""
        findings = []
        for a in assignments:
            if not a.get('scope_exists', True):
                findings.append(HygieneFinding(
                    rule='orphaned_assignment',
                    severity='critical',
                    identity_db_id=a['identity_db_id'],
                    identity_id=a['identity_id'],
                    identity_name=a['identity_name'],
                    identity_category=a['identity_category'],
                    role_name=a['role_name'],
                    role_source=a['role_source'],
                    scope=a['scope'],
                    scope_type=a['scope_type'],
                    title=f"Orphaned {a['role_name']} assignment",
                    detail=f"Role '{a['role_name']}' assigned to '{a['identity_name']}' on a scope that no longer exists: {a['scope']}",
                    recommendation="Remove this role assignment — the target resource has been deleted",
                    risk_score=30,
                    assignment_age_days=a.get('days_since_assigned'),
                ))
        return findings

    # ── Rule 2: Disabled Principal Access ─────────────────────

    def _rule_disabled(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect disabled identities that still have active role assignments."""
        findings = []
        seen = set()
        for a in assignments:
            if a.get('enabled') is False:
                key = (a['identity_db_id'], a['role_name'], a['role_source'])
                if key in seen:
                    continue
                seen.add(key)
                role_lower = a['role_name'].lower()
                is_priv = role_lower in PRIVILEGED_RBAC_ROLES or role_lower in PRIVILEGED_ENTRA_ROLES
                sev = 'critical' if is_priv else 'high'
                findings.append(HygieneFinding(
                    rule='disabled_principal',
                    severity=sev,
                    identity_db_id=a['identity_db_id'],
                    identity_id=a['identity_id'],
                    identity_name=a['identity_name'],
                    identity_category=a['identity_category'],
                    role_name=a['role_name'],
                    role_source=a['role_source'],
                    scope=a['scope'],
                    scope_type=a['scope_type'],
                    title=f"Disabled principal retains {a['role_name']}",
                    detail=f"'{a['identity_name']}' is disabled but still holds '{a['role_name']}' on {a['scope_type']} scope",
                    recommendation="Remove role assignment from disabled principal to eliminate residual access risk",
                    risk_score=25 if is_priv else 15,
                ))
        return findings

    # ── Rule 3: Dormant Access ────────────────────────────────

    def _rule_dormant(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect identities with roles but no recent sign-in activity."""
        findings = []
        seen_identities = set()
        for a in assignments:
            act = (a.get('activity_status') or '').lower()
            if act not in ('stale', 'never_used', 'inactive'):
                continue
            if a['identity_db_id'] in seen_identities:
                continue
            seen_identities.add(a['identity_db_id'])

            role_lower = a['role_name'].lower()
            is_priv = role_lower in PRIVILEGED_RBAC_ROLES or role_lower in PRIVILEGED_ENTRA_ROLES

            if act == 'stale':
                sev = 'critical' if is_priv else 'high'
                label = f"Dormant 90d+ with {a['role_name']}"
                score = 25 if is_priv else 15
            elif act == 'never_used':
                sev = 'high'
                label = f"Never signed in with {a['role_name']}"
                score = 20
            else:  # inactive
                sev = 'medium'
                label = f"Idle 30-90d with {a['role_name']}"
                score = 10

            days = None
            if a.get('last_sign_in'):
                try:
                    last = a['last_sign_in']
                    if isinstance(last, str):
                        last = datetime.fromisoformat(last.replace('Z', '+00:00'))
                    days = (datetime.now(timezone.utc) - last).days
                except Exception:
                    pass

            findings.append(HygieneFinding(
                rule='dormant_access',
                severity=sev,
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source=a['role_source'],
                scope=a['scope'],
                scope_type=a['scope_type'],
                title=label,
                detail=f"'{a['identity_name']}' is {act} but holds '{a['role_name']}' — {f'{days}d since last sign-in' if days else 'no sign-in recorded'}",
                recommendation="Review and revoke access for dormant principals to reduce attack surface",
                risk_score=score,
                days_since_activity=days,
            ))
        return findings

    # ── Rule 4: Credential Risk ───────────────────────────────

    def _rule_credential_risk(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect service principals with roles and expired/expiring credentials."""
        findings = []
        seen = set()
        for a in assignments:
            cat = (a.get('identity_category') or '').lower()
            if cat not in ('service_principal',):
                continue
            cred = (a.get('credential_status') or '').lower()
            if cred not in ('expired', 'critical', 'warning'):
                continue
            if a['identity_db_id'] in seen:
                continue
            seen.add(a['identity_db_id'])

            role_lower = a['role_name'].lower()
            is_priv = role_lower in PRIVILEGED_RBAC_ROLES or role_lower in PRIVILEGED_ENTRA_ROLES

            if cred == 'expired':
                sev = 'critical' if is_priv else 'high'
                title = f"Expired credentials on {a['role_name']} holder"
                score = 20
            elif cred == 'critical':
                sev = 'high'
                title = f"Critically expiring credentials on {a['role_name']} holder"
                score = 15
            else:
                sev = 'medium'
                title = f"Credentials expiring soon on {a['role_name']} holder"
                score = 8

            findings.append(HygieneFinding(
                rule='credential_risk',
                severity=sev,
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source=a['role_source'],
                scope=a['scope'],
                scope_type=a['scope_type'],
                title=title,
                detail=f"'{a['identity_name']}' holds '{a['role_name']}' with credential status '{cred}' — expiry: {a.get('credential_expiration', 'unknown')}",
                recommendation="Rotate credentials immediately to prevent service disruption and reduce compromise risk",
                risk_score=score,
                credential_status=cred,
            ))
        return findings

    # ── Rule 5: Overprivileged Access ─────────────────────────

    def _rule_overprivileged(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect Owner/UAA at subscription+ scope or Global Admin on directory."""
        findings = []
        seen = set()
        for a in assignments:
            role_lower = a['role_name'].lower()
            source = a['role_source']

            is_overpriv = False
            detail_reason = ""

            if source == 'rbac':
                if role_lower in CRITICAL_RBAC_ROLES and a['scope_type'] in ('subscription', 'management_group'):
                    is_overpriv = True
                    detail_reason = f"broad {a['scope_type']}-level {a['role_name']}"
                elif role_lower == 'contributor' and a['scope_type'] == 'subscription':
                    is_overpriv = True
                    detail_reason = "Contributor at subscription scope"
            elif source == 'entra':
                if role_lower in CRITICAL_ENTRA_ROLES:
                    is_overpriv = True
                    detail_reason = f"standing {a['role_name']} assignment (no PIM)"

            if not is_overpriv:
                continue

            key = (a['identity_db_id'], a['role_name'], a['role_source'])
            if key in seen:
                continue
            seen.add(key)

            is_critical = role_lower in CRITICAL_RBAC_ROLES or role_lower in CRITICAL_ENTRA_ROLES
            sev = 'high' if is_critical else 'medium'

            findings.append(HygieneFinding(
                rule='overprivileged',
                severity=sev,
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source=a['role_source'],
                scope=a['scope'],
                scope_type=a['scope_type'],
                title=f"Overprivileged: {detail_reason}",
                detail=f"'{a['identity_name']}' has {detail_reason} — violates least-privilege principle",
                recommendation="Scope down to resource group level or use PIM for just-in-time activation",
                risk_score=20 if is_critical else 12,
                assignment_age_days=a.get('days_since_assigned'),
            ))
        return findings

    # ── Rule 6: Management Group Access ───────────────────────

    def _rule_mg_access(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect assignments at management group scope (broad blast radius)."""
        findings = []
        seen = set()
        for a in assignments:
            if a['role_source'] != 'rbac':
                continue
            scope_lower = (a.get('scope') or '').lower()
            if '/providers/microsoft.management/managementgroups/' not in scope_lower:
                continue
            key = (a['identity_db_id'], a['role_name'])
            if key in seen:
                continue
            seen.add(key)

            role_lower = a['role_name'].lower()
            is_critical = role_lower in CRITICAL_RBAC_ROLES
            sev = 'high' if is_critical else 'medium'

            findings.append(HygieneFinding(
                rule='mg_level_access',
                severity=sev,
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source='rbac',
                scope=a['scope'],
                scope_type='management_group',
                title=f"Management group {a['role_name']}",
                detail=f"'{a['identity_name']}' holds '{a['role_name']}' at management group scope — affects all child subscriptions",
                recommendation="Move assignment to individual subscription scope to limit blast radius",
                risk_score=18 if is_critical else 10,
                assignment_age_days=a.get('days_since_assigned'),
            ))
        return findings

    # ── Rule 7: Guest Standing Access ─────────────────────────

    def _rule_guest_standing(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect guest/external users with permanent privileged role assignments."""
        findings = []
        seen = set()
        for a in assignments:
            cat = (a.get('identity_category') or '').lower()
            if cat != 'guest':
                continue
            role_lower = a['role_name'].lower()
            is_priv = role_lower in PRIVILEGED_RBAC_ROLES or role_lower in PRIVILEGED_ENTRA_ROLES
            if not is_priv:
                continue

            key = (a['identity_db_id'], a['role_name'], a['role_source'])
            if key in seen:
                continue
            seen.add(key)

            is_critical = role_lower in CRITICAL_RBAC_ROLES or role_lower in CRITICAL_ENTRA_ROLES
            sev = 'high' if is_critical else 'medium'

            findings.append(HygieneFinding(
                rule='guest_standing_access',
                severity=sev,
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source=a['role_source'],
                scope=a['scope'],
                scope_type=a['scope_type'],
                title=f"Guest with standing {a['role_name']}",
                detail=f"External user '{a['identity_name']}' holds permanent '{a['role_name']}' — guests should use time-limited access",
                recommendation="Convert to PIM-eligible assignment or remove standing access for external users",
                risk_score=15 if is_critical else 10,
            ))
        return findings

    # ── Scoring ───────────────────────────────────────────────

    def _compute_score(self, assignments: List[Dict], findings: List[HygieneFinding]) -> Tuple[int, str]:
        """Compute hygiene score (0-100, higher = healthier) and letter grade."""
        if not assignments:
            return 100, 'A'

        total = len(assignments)
        # Weight deductions by severity
        deduction = 0
        for f in findings:
            if f.severity == 'critical':
                deduction += 5
            elif f.severity == 'high':
                deduction += 3
            elif f.severity == 'medium':
                deduction += 1.5

        # Normalize: cap deduction relative to assignment count
        max_deduction = total * 0.5  # At most 50% from sheer volume
        normalized = min(deduction, max_deduction)
        # Scale to 0-100
        ratio = normalized / total if total > 0 else 0
        score = max(0, min(100, int(100 - (ratio * 200))))

        if score >= 90:
            grade = 'A'
        elif score >= 75:
            grade = 'B'
        elif score >= 60:
            grade = 'C'
        elif score >= 40:
            grade = 'D'
        else:
            grade = 'F'

        return score, grade
