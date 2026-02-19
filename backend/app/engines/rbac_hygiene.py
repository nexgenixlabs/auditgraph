"""
RBAC Hygiene Engine v2

Assignment-first analysis of Azure RBAC and Entra role assignments.
Detects 10 categories of hygiene issues:
  1. Orphaned Assignments — role assigned to a deleted/non-existent principal
  2. Disabled Principal Access — disabled identity still has active roles
  3. Dormant Access — identity has roles but hasn't signed in recently
  4. Credential Risk — service principals with expired/expiring credentials
  5. Overprivileged Access — Owner/UAA at subscription+ scope
  6. Management Group Access — broad blast radius via MG-level assignments
  7. Guest Standing Access — external users with permanent privileged roles
  8. Permanent Global Admin — standing GA without PIM activation
  9. Broad Scope Age — high-priv assignment at sub+ scope for 180+ days
 10. Owner Without PIM — Owner role without PIM eligibility

v2 additions:
  - 4-tier role sensitivity model (T1-T4) with weights
  - Per-assignment weighted risk scoring
  - % Exposure Index hygiene score
  - Drift detection (scan-over-scan comparison)
  - PIM eligibility integration
  - Executive summary metrics
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# § 1  ROLE SENSITIVITY TIERS
# ──────────────────────────────────────────────────────────────

# T1 = Critical control plane (weight 30)
# T2 = Elevated privilege (weight 20)
# T3 = Targeted write access (weight 10)
# T4 = Read-only / low privilege (weight 5)

TIER_WEIGHTS = {'T1': 30, 'T2': 20, 'T3': 10, 'T4': 5}

# RBAC roles by tier
T1_RBAC = {'owner', 'user access administrator'}
T2_RBAC = {
    'contributor', 'key vault administrator', 'security admin',
    'managed identity operator', 'managed identity contributor',
    'storage blob data owner', 'virtual machine contributor',
}
T3_RBAC = {
    'key vault secrets officer', 'key vault crypto officer',
    'storage blob data contributor', 'network contributor',
    'sql db contributor', 'web plan contributor',
    'logic app contributor', 'automation contributor',
    'data factory contributor', 'cosmos db account reader role',
}
T4_RBAC = {
    'reader', 'storage blob data reader', 'key vault reader',
    'key vault secrets user', 'monitoring reader',
    'security reader', 'log analytics reader',
    'cost management reader', 'billing reader',
}

# Entra roles by tier
T1_ENTRA = {'global administrator', 'privileged role administrator'}
T2_ENTRA = {
    'application administrator', 'cloud application administrator',
    'user administrator', 'exchange administrator',
    'security administrator', 'conditional access administrator',
    'authentication administrator', 'intune administrator',
    'password administrator', 'groups administrator',
}
T3_ENTRA = {
    'directory readers', 'reports reader', 'message center reader',
    'helpdesk administrator', 'license administrator',
    'service support administrator', 'compliance administrator',
}
T4_ENTRA = {
    'directory readers', 'usage summary reports reader',
    'message center reader',
}

# Combined sets for quick lookup
PRIVILEGED_RBAC_ROLES = T1_RBAC | T2_RBAC
PRIVILEGED_ENTRA_ROLES = T1_ENTRA | T2_ENTRA
CRITICAL_RBAC_ROLES = T1_RBAC
CRITICAL_ENTRA_ROLES = T1_ENTRA

# ──────────────────────────────────────────────────────────────
# § 2  SCORING WEIGHTS
# ──────────────────────────────────────────────────────────────

SCOPE_WEIGHTS = {
    'management_group': 25,
    'subscription': 15,
    'resource_group': 5,
    'resource': 0,
    'directory': 20,  # Entra directory scope
}

IDENTITY_WEIGHTS = {
    'service_principal': 10,
    'guest': 8,
    'managed_identity_user': 3,
    'managed_identity_system': 2,
    'human_user': 5,
}

HEALTH_MODIFIERS = {
    'expired': 15,
    'critical': 10,
    'warning': 5,
    'stale': 12,
    'never_used': 10,
    'inactive': 5,
    'disabled': 8,
}

ACCESS_MODIFIERS = {
    'no_pim': 10,       # standing assignment without PIM eligible
    'orphaned_scope': 15,
}

DORMANT_THRESHOLD_DAYS = 90
IDLE_THRESHOLD_DAYS = 30
CREDENTIAL_WARNING_DAYS = 30
BROAD_SCOPE_AGE_DAYS = 180

# ──────────────────────────────────────────────────────────────
# § 3  FINDING CONSTANTS
# ──────────────────────────────────────────────────────────────

FINDING_SEVERITY = {
    'orphaned_assignment':   'critical',
    'disabled_principal':    'high',
    'dormant_access':        'high',
    'credential_risk':       'high',
    'overprivileged':        'medium',
    'mg_level_access':       'medium',
    'guest_standing_access': 'medium',
    'permanent_ga':          'critical',
    'broad_scope_age':       'high',
    'owner_without_pim':     'high',
}

FINDING_LABELS = {
    'orphaned_assignment':   'Orphaned Assignment',
    'disabled_principal':    'Disabled Principal with Access',
    'dormant_access':        'Dormant Access',
    'credential_risk':       'Credential Risk',
    'overprivileged':        'Overprivileged Access',
    'mg_level_access':       'Management Group Access',
    'guest_standing_access': 'Guest Standing Access',
    'permanent_ga':          'Permanent Global Admin',
    'broad_scope_age':       'Broad Scope Stale Assignment',
    'owner_without_pim':     'Owner Without PIM',
}


def classify_role_tier(role_name: str, source: str) -> str:
    """Return tier T1-T4 for a role name."""
    rl = role_name.lower()
    if source == 'rbac':
        if rl in T1_RBAC:
            return 'T1'
        if rl in T2_RBAC:
            return 'T2'
        if rl in T3_RBAC:
            return 'T3'
        return 'T4'
    else:  # entra
        if rl in T1_ENTRA:
            return 'T1'
        if rl in T2_ENTRA:
            return 'T2'
        if rl in T3_ENTRA:
            return 'T3'
        return 'T4'


def compute_assignment_risk(
    role_name: str,
    source: str,
    scope_type: str,
    identity_category: str,
    activity_status: str,
    credential_status: str,
    enabled: bool,
    is_pim_eligible: bool,
    scope_exists: bool,
) -> Tuple[int, str, str]:
    """Compute per-assignment risk score (0-100), risk_level, and tier."""
    tier = classify_role_tier(role_name, source)
    role_w = TIER_WEIGHTS.get(tier, 5)
    scope_w = SCOPE_WEIGHTS.get(scope_type, 0)
    identity_w = IDENTITY_WEIGHTS.get(identity_category, 5)

    # Health modifier
    health_m = 0
    act = (activity_status or '').lower()
    cred = (credential_status or '').lower()
    if not enabled:
        health_m += HEALTH_MODIFIERS['disabled']
    if act in HEALTH_MODIFIERS:
        health_m += HEALTH_MODIFIERS[act]
    if cred in HEALTH_MODIFIERS:
        health_m += HEALTH_MODIFIERS[cred]

    # Access modifiers
    access_m = 0
    if not is_pim_eligible and tier in ('T1', 'T2'):
        access_m += ACCESS_MODIFIERS['no_pim']
    if not scope_exists:
        access_m += ACCESS_MODIFIERS['orphaned_scope']

    total = min(100, role_w + scope_w + identity_w + health_m + access_m)

    if total >= 60:
        level = 'critical'
    elif total >= 40:
        level = 'high'
    elif total >= 20:
        level = 'medium'
    else:
        level = 'low'

    return total, level, tier


# ──────────────────────────────────────────────────────────────
# § 4  DATA MODEL
# ──────────────────────────────────────────────────────────────

@dataclass
class HygieneFinding:
    """A single RBAC hygiene finding."""
    rule: str
    severity: str
    identity_db_id: int
    identity_id: str
    identity_name: str
    identity_category: str
    role_name: str
    role_source: str
    scope: str
    scope_type: str
    title: str
    detail: str
    recommendation: str
    risk_score: int = 0
    risk_level: str = 'low'
    role_tier: str = 'T4'
    days_since_activity: Optional[int] = None
    credential_status: Optional[str] = None
    assignment_age_days: Optional[int] = None
    is_pim_eligible: bool = False
    identity_risk: str = 'info'

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
            'risk_level': self.risk_level,
            'role_tier': self.role_tier,
            'days_since_activity': self.days_since_activity,
            'credential_status': self.credential_status,
            'assignment_age_days': self.assignment_age_days,
            'is_pim_eligible': self.is_pim_eligible,
            'identity_risk': self.identity_risk,
        }


# ──────────────────────────────────────────────────────────────
# § 5  ENGINE
# ──────────────────────────────────────────────────────────────

class RbacHygieneEngine:
    """Analyzes RBAC assignments and produces hygiene findings + score."""

    def __init__(self, db):
        self.db = db

    def run(self, run_id: Optional[int] = None) -> Dict:
        """Execute all 10 hygiene rules and return summary + findings."""
        logger.info("Starting RBAC hygiene analysis v2...")

        # Load data
        assignments = self._load_assignments(run_id)
        identities = self._load_identity_map(run_id)
        pim_eligible = self._load_pim_eligible(run_id)

        # Enrich assignments with PIM data and per-assignment risk scores
        for a in assignments:
            obj_id = identities.get(a['identity_db_id'], {}).get('object_id', '')
            a['is_pim_eligible'] = obj_id in pim_eligible if obj_id else False

            risk, level, tier = compute_assignment_risk(
                role_name=a['role_name'],
                source=a['role_source'],
                scope_type=a['scope_type'],
                identity_category=a['identity_category'],
                activity_status=a['activity_status'],
                credential_status=a['credential_status'],
                enabled=a.get('enabled', True),
                is_pim_eligible=a['is_pim_eligible'],
                scope_exists=a.get('scope_exists', True),
            )
            a['assignment_risk_score'] = risk
            a['assignment_risk_level'] = level
            a['role_tier'] = tier

        findings: List[HygieneFinding] = []

        # Run all 10 rules
        findings.extend(self._rule_orphaned(assignments, identities))
        findings.extend(self._rule_disabled(assignments, identities))
        findings.extend(self._rule_dormant(assignments, identities))
        findings.extend(self._rule_credential_risk(assignments, identities))
        findings.extend(self._rule_overprivileged(assignments, identities))
        findings.extend(self._rule_mg_access(assignments, identities))
        findings.extend(self._rule_guest_standing(assignments, identities))
        findings.extend(self._rule_permanent_ga(assignments, identities))
        findings.extend(self._rule_broad_scope_age(assignments, identities))
        findings.extend(self._rule_owner_without_pim(assignments, identities))

        # Compute score using % exposure index
        score, grade, exposure_index = self._compute_score(assignments, findings)

        # Tier distribution
        tier_dist = {'T1': 0, 'T2': 0, 'T3': 0, 'T4': 0}
        for a in assignments:
            t = a.get('role_tier', 'T4')
            tier_dist[t] = tier_dist.get(t, 0) + 1

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

        # Executive metrics
        executive = self._compute_executive_metrics(assignments, findings, tier_dist)

        # Drift detection
        drift = self._compute_drift(assignments, findings)

        result = {
            'score': score,
            'grade': grade,
            'exposure_index': exposure_index,
            'total_assignments': len(assignments),
            'total_findings': len(findings),
            'tier_distribution': tier_dist,
            'by_rule': by_rule,
            'by_severity': by_severity,
            'executive': executive,
            'drift': drift,
            'findings': [f.to_dict() for f in findings],
            'analyzed_at': datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "RBAC hygiene v2 analysis complete: score=%d, grade=%s, findings=%d",
            score, grade, len(findings)
        )
        return result

    # ── Data Loading ──────────────────────────────────────────

    def _load_assignments(self, run_id: Optional[int] = None) -> List[Dict]:
        """Load all RBAC + Entra role assignments with identity context."""
        cursor = self.db.conn.cursor()

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

    def _load_pim_eligible(self, run_id: Optional[int] = None) -> set:
        """Load set of object_ids that have PIM eligible assignments. Graceful degradation."""
        try:
            cursor = self.db.conn.cursor()
            # Check if table exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'pim_eligible_assignments'
                )
            """)
            if not cursor.fetchone()[0]:
                cursor.close()
                return set()

            # Get object_ids with PIM eligible assignments
            if run_id:
                cursor.execute("""
                    SELECT DISTINCT i.object_id
                    FROM pim_eligible_assignments pea
                    JOIN identities i ON i.id = pea.identity_db_id
                    WHERE i.discovery_run_id = %s AND i.object_id IS NOT NULL
                """, (run_id,))
            else:
                cursor.execute("""
                    SELECT DISTINCT i.object_id
                    FROM pim_eligible_assignments pea
                    JOIN identities i ON i.id = pea.identity_db_id
                    WHERE i.discovery_run_id = (
                        SELECT id FROM discovery_runs
                        WHERE status = 'completed'
                        ORDER BY completed_at DESC LIMIT 1
                    ) AND i.object_id IS NOT NULL
                """)

            result = {row[0] for row in cursor.fetchall()}
            cursor.close()
            logger.info("Loaded %d PIM-eligible identities", len(result))
            return result
        except Exception as e:
            logger.warning("PIM eligibility check failed (graceful degradation): %s", e)
            return set()

    # ── Rule 1: Orphaned Assignments ──────────────────────────

    def _rule_orphaned(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        findings = []
        for a in assignments:
            if not a.get('scope_exists', True):
                tier = a.get('role_tier', 'T4')
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
                    risk_score=a.get('assignment_risk_score', 30),
                    risk_level=a.get('assignment_risk_level', 'high'),
                    role_tier=tier,
                    assignment_age_days=a.get('days_since_assigned'),
                    is_pim_eligible=a.get('is_pim_eligible', False),
                    identity_risk=a.get('identity_risk', 'info'),
                ))
        return findings

    # ── Rule 2: Disabled Principal Access ─────────────────────

    def _rule_disabled(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
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
                    risk_score=a.get('assignment_risk_score', 25),
                    risk_level=a.get('assignment_risk_level', 'high'),
                    role_tier=a.get('role_tier', 'T4'),
                    is_pim_eligible=a.get('is_pim_eligible', False),
                    identity_risk=a.get('identity_risk', 'info'),
                ))
        return findings

    # ── Rule 3: Dormant Access ────────────────────────────────

    def _rule_dormant(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
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
            elif act == 'never_used':
                sev = 'high'
                label = f"Never signed in with {a['role_name']}"
            else:
                sev = 'medium'
                label = f"Idle 30-90d with {a['role_name']}"

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
                risk_score=a.get('assignment_risk_score', 15),
                risk_level=a.get('assignment_risk_level', 'medium'),
                role_tier=a.get('role_tier', 'T4'),
                days_since_activity=days,
                is_pim_eligible=a.get('is_pim_eligible', False),
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 4: Credential Risk ───────────────────────────────

    def _rule_credential_risk(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
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
            elif cred == 'critical':
                sev = 'high'
                title = f"Critically expiring credentials on {a['role_name']} holder"
            else:
                sev = 'medium'
                title = f"Credentials expiring soon on {a['role_name']} holder"

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
                risk_score=a.get('assignment_risk_score', 15),
                risk_level=a.get('assignment_risk_level', 'high'),
                role_tier=a.get('role_tier', 'T4'),
                credential_status=cred,
                is_pim_eligible=a.get('is_pim_eligible', False),
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 5: Overprivileged Access ─────────────────────────

    def _rule_overprivileged(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
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
                risk_score=a.get('assignment_risk_score', 20),
                risk_level=a.get('assignment_risk_level', 'high'),
                role_tier=a.get('role_tier', 'T4'),
                assignment_age_days=a.get('days_since_assigned'),
                is_pim_eligible=a.get('is_pim_eligible', False),
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 6: Management Group Access ───────────────────────

    def _rule_mg_access(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
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
                risk_score=a.get('assignment_risk_score', 18),
                risk_level=a.get('assignment_risk_level', 'medium'),
                role_tier=a.get('role_tier', 'T4'),
                assignment_age_days=a.get('days_since_assigned'),
                is_pim_eligible=a.get('is_pim_eligible', False),
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 7: Guest Standing Access ─────────────────────────

    def _rule_guest_standing(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
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
                risk_score=a.get('assignment_risk_score', 15),
                risk_level=a.get('assignment_risk_level', 'medium'),
                role_tier=a.get('role_tier', 'T4'),
                is_pim_eligible=a.get('is_pim_eligible', False),
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 8: Permanent Global Admin ────────────────────────

    def _rule_permanent_ga(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect standing Global Admin assignments without PIM activation."""
        findings = []
        seen = set()
        for a in assignments:
            if a['role_source'] != 'entra':
                continue
            role_lower = a['role_name'].lower()
            if role_lower != 'global administrator':
                continue
            if a.get('is_pim_eligible', False):
                continue  # Has PIM — acceptable
            if a['identity_db_id'] in seen:
                continue
            seen.add(a['identity_db_id'])

            findings.append(HygieneFinding(
                rule='permanent_ga',
                severity='critical',
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source='entra',
                scope=a['scope'],
                scope_type='directory',
                title=f"Permanent Global Admin: {a['identity_name']}",
                detail=f"'{a['identity_name']}' holds standing Global Administrator without PIM — highest privilege with no activation barrier",
                recommendation="Convert to PIM-eligible assignment requiring just-in-time activation with MFA and approval",
                risk_score=a.get('assignment_risk_score', 45),
                risk_level='critical',
                role_tier='T1',
                is_pim_eligible=False,
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 9: Broad Scope Age ───────────────────────────────

    def _rule_broad_scope_age(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect high-privilege assignments at subscription+ scope older than 180 days."""
        findings = []
        seen = set()
        for a in assignments:
            if a['role_source'] != 'rbac':
                continue
            role_lower = a['role_name'].lower()
            if role_lower not in PRIVILEGED_RBAC_ROLES:
                continue
            if a['scope_type'] not in ('subscription', 'management_group'):
                continue
            days = a.get('days_since_assigned')
            if days is None or days < BROAD_SCOPE_AGE_DAYS:
                continue

            key = (a['identity_db_id'], a['role_name'], a['scope_type'])
            if key in seen:
                continue
            seen.add(key)

            findings.append(HygieneFinding(
                rule='broad_scope_age',
                severity='high',
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name=a['role_name'],
                role_source='rbac',
                scope=a['scope'],
                scope_type=a['scope_type'],
                title=f"{a['role_name']} at {a['scope_type']} for {days}d",
                detail=f"'{a['identity_name']}' has held '{a['role_name']}' at {a['scope_type']} scope for {days} days — stale broad-scope assignment",
                recommendation=f"Review and scope down after {BROAD_SCOPE_AGE_DAYS}+ days — consider PIM or resource-group-level assignment",
                risk_score=a.get('assignment_risk_score', 25),
                risk_level=a.get('assignment_risk_level', 'high'),
                role_tier=a.get('role_tier', 'T4'),
                assignment_age_days=days,
                is_pim_eligible=a.get('is_pim_eligible', False),
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Rule 10: Owner Without PIM ────────────────────────────

    def _rule_owner_without_pim(self, assignments: List[Dict], identities: Dict) -> List[HygieneFinding]:
        """Detect Owner role assignments where identity has no PIM eligibility."""
        findings = []
        seen = set()
        for a in assignments:
            if a['role_source'] != 'rbac':
                continue
            role_lower = a['role_name'].lower()
            if role_lower != 'owner':
                continue
            if a.get('is_pim_eligible', False):
                continue  # PIM covers this
            if a['scope_type'] not in ('subscription', 'management_group', 'resource_group'):
                continue

            key = (a['identity_db_id'], a['scope'])
            if key in seen:
                continue
            seen.add(key)

            findings.append(HygieneFinding(
                rule='owner_without_pim',
                severity='high',
                identity_db_id=a['identity_db_id'],
                identity_id=a['identity_id'],
                identity_name=a['identity_name'],
                identity_category=a['identity_category'],
                role_name='Owner',
                role_source='rbac',
                scope=a['scope'],
                scope_type=a['scope_type'],
                title=f"Owner without PIM on {a['scope_type']}",
                detail=f"'{a['identity_name']}' holds standing Owner on {a['scope_type']} without PIM eligibility — full control with no activation barrier",
                recommendation="Enable PIM for Owner assignments to require just-in-time activation",
                risk_score=a.get('assignment_risk_score', 35),
                risk_level=a.get('assignment_risk_level', 'high'),
                role_tier='T1',
                assignment_age_days=a.get('days_since_assigned'),
                is_pim_eligible=False,
                identity_risk=a.get('identity_risk', 'info'),
            ))
        return findings

    # ── Scoring: % Exposure Index ─────────────────────────────

    def _compute_score(self, assignments: List[Dict], findings: List[HygieneFinding]) -> Tuple[int, str, Dict]:
        """Compute hygiene score using % exposure index model."""
        if not assignments:
            return 100, 'A', {
                'privilege_density': 0,
                'broad_scope_density': 0,
                'unhealthy_principals': 0,
                'permanent_high_priv': 0,
                'nhi_with_secrets': 0,
            }

        total = len(assignments)
        unique_identities = set(a['identity_db_id'] for a in assignments)
        total_identities = len(unique_identities) or 1

        # 1. Privilege density: % of assignments that are T1/T2
        high_priv_count = sum(1 for a in assignments if a.get('role_tier') in ('T1', 'T2'))
        privilege_density = high_priv_count / total * 100 if total else 0

        # 2. Broad scope density: % of assignments at subscription+ scope
        broad_scope_count = sum(1 for a in assignments if a['scope_type'] in ('subscription', 'management_group'))
        broad_scope_density = broad_scope_count / total * 100 if total else 0

        # 3. Unhealthy principals: % of unique identities with findings
        unhealthy_ids = set(f.identity_db_id for f in findings)
        unhealthy_pct = len(unhealthy_ids) / total_identities * 100

        # 4. Permanent high-priv: % of T1/T2 without PIM
        t1t2 = [a for a in assignments if a.get('role_tier') in ('T1', 'T2')]
        perm_high = sum(1 for a in t1t2 if not a.get('is_pim_eligible', False))
        perm_high_pct = (perm_high / len(t1t2) * 100) if t1t2 else 0

        # 5. NHI with secrets: % of NHI identities with credential issues
        nhi_ids = set()
        nhi_cred_issue = set()
        for a in assignments:
            cat = (a.get('identity_category') or '').lower()
            if cat in ('service_principal', 'managed_identity_user'):
                nhi_ids.add(a['identity_db_id'])
                cred = (a.get('credential_status') or '').lower()
                if cred in ('expired', 'critical', 'warning'):
                    nhi_cred_issue.add(a['identity_db_id'])
        nhi_secret_pct = (len(nhi_cred_issue) / len(nhi_ids) * 100) if nhi_ids else 0

        exposure_index = {
            'privilege_density': round(privilege_density, 1),
            'broad_scope_density': round(broad_scope_density, 1),
            'unhealthy_principals': round(unhealthy_pct, 1),
            'permanent_high_priv': round(perm_high_pct, 1),
            'nhi_with_secrets': round(nhi_secret_pct, 1),
        }

        # Weighted composite score: lower exposure = higher score
        # Each metric contributes to exposure (0-100), weighted:
        weighted_exposure = (
            privilege_density * 0.20 +
            broad_scope_density * 0.20 +
            unhealthy_pct * 0.25 +
            perm_high_pct * 0.20 +
            nhi_secret_pct * 0.15
        )

        score = max(0, min(100, int(100 - weighted_exposure)))

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

        return score, grade, exposure_index

    # ── Executive Metrics ─────────────────────────────────────

    def _compute_executive_metrics(self, assignments: List[Dict], findings: List[HygieneFinding], tier_dist: Dict) -> Dict:
        """Compute CISO-level executive metrics."""
        total = len(assignments) or 1

        # Standing privilege ratio (T1+T2 without PIM / total)
        t1t2_standing = sum(
            1 for a in assignments
            if a.get('role_tier') in ('T1', 'T2') and not a.get('is_pim_eligible', False)
        )
        standing_priv_ratio = round(t1t2_standing / total * 100, 1)

        # Broad scope ratio
        broad = sum(1 for a in assignments if a['scope_type'] in ('subscription', 'management_group'))
        broad_scope_ratio = round(broad / total * 100, 1)

        # Unhealthy identity ratio
        unique_ids = set(a['identity_db_id'] for a in assignments)
        finding_ids = set(f.identity_db_id for f in findings)
        unhealthy_ratio = round(len(finding_ids) / len(unique_ids) * 100, 1) if unique_ids else 0

        # Top risk identities (by cumulative finding risk)
        risk_by_identity: Dict[int, Dict] = {}
        for f in findings:
            if f.identity_db_id not in risk_by_identity:
                risk_by_identity[f.identity_db_id] = {
                    'identity_db_id': f.identity_db_id,
                    'identity_id': f.identity_id,
                    'identity_name': f.identity_name,
                    'identity_category': f.identity_category,
                    'total_risk': 0,
                    'finding_count': 0,
                    'highest_severity': 'low',
                }
            entry = risk_by_identity[f.identity_db_id]
            entry['total_risk'] += f.risk_score
            entry['finding_count'] += 1
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            if sev_order.get(f.severity, 9) < sev_order.get(entry['highest_severity'], 9):
                entry['highest_severity'] = f.severity

        top_risk = sorted(
            risk_by_identity.values(),
            key=lambda x: (-x['total_risk'], -x['finding_count'])
        )[:5]

        # Scope breakdown for broad assignments
        scope_breakdown = {}
        for a in assignments:
            st = a['scope_type']
            scope_breakdown[st] = scope_breakdown.get(st, 0) + 1

        return {
            'standing_priv_ratio': standing_priv_ratio,
            'broad_scope_ratio': broad_scope_ratio,
            'unhealthy_ratio': unhealthy_ratio,
            'top_risk_identities': top_risk,
            'scope_breakdown': scope_breakdown,
            'tier_distribution': tier_dist,
            'total_identities': len(set(a['identity_db_id'] for a in assignments)),
            'pim_coverage': self._pim_coverage_pct(assignments),
        }

    def _pim_coverage_pct(self, assignments: List[Dict]) -> float:
        """% of T1+T2 assignments that are PIM eligible."""
        t1t2 = [a for a in assignments if a.get('role_tier') in ('T1', 'T2')]
        if not t1t2:
            return 100.0
        pim_count = sum(1 for a in t1t2 if a.get('is_pim_eligible', False))
        return round(pim_count / len(t1t2) * 100, 1)

    # ── Drift Detection ───────────────────────────────────────

    def _compute_drift(self, assignments: List[Dict], findings: List[HygieneFinding]) -> Dict:
        """Compare current scan against previous scan for drift detection."""
        try:
            prev = self.db.get_rbac_hygiene_latest()
            if not prev or not prev.get('findings'):
                return {
                    'has_previous': False,
                    'new_findings': 0,
                    'resolved_findings': 0,
                    'score_delta': 0,
                    'new_privileged': [],
                    'scope_escalations': [],
                }

            prev_findings = prev.get('findings', [])
            prev_score = prev.get('score', 0)

            # Build fingerprint sets for comparison
            def fingerprint(f):
                rule = f.get('rule', f.rule if hasattr(f, 'rule') else '')
                iid = f.get('identity_db_id', getattr(f, 'identity_db_id', 0))
                rn = f.get('role_name', getattr(f, 'role_name', ''))
                rs = f.get('role_source', getattr(f, 'role_source', ''))
                return (rule, iid, rn, rs)

            current_fps = set()
            current_map = {}
            for f in findings:
                fp = fingerprint(f)
                current_fps.add(fp)
                current_map[fp] = f

            prev_fps = set()
            for f in prev_findings:
                prev_fps.add(fingerprint(f))

            new_fps = current_fps - prev_fps
            resolved_fps = prev_fps - current_fps

            # New privileged assignments (T1/T2 that didn't exist before)
            new_privileged = []
            for fp in new_fps:
                f = current_map.get(fp)
                if f and getattr(f, 'role_tier', 'T4') in ('T1', 'T2'):
                    new_privileged.append({
                        'identity_name': f.identity_name,
                        'role_name': f.role_name,
                        'role_tier': f.role_tier,
                        'scope_type': f.scope_type,
                        'rule': f.rule,
                    })

            # Scope escalations: findings where same identity+role now has broader scope
            scope_escalations = []
            prev_by_ir = {}
            for f in prev_findings:
                key = (f.get('identity_db_id'), f.get('role_name'))
                prev_by_ir[key] = f
            scope_hierarchy = {'resource': 0, 'resource_group': 1, 'subscription': 2, 'management_group': 3, 'directory': 3}
            for f in findings:
                key = (f.identity_db_id, f.role_name)
                prev_f = prev_by_ir.get(key)
                if prev_f:
                    old_level = scope_hierarchy.get(prev_f.get('scope_type', ''), 0)
                    new_level = scope_hierarchy.get(f.scope_type, 0)
                    if new_level > old_level:
                        scope_escalations.append({
                            'identity_name': f.identity_name,
                            'role_name': f.role_name,
                            'old_scope': prev_f.get('scope_type', ''),
                            'new_scope': f.scope_type,
                        })

            current_score = self._compute_score(assignments, findings)[0]

            return {
                'has_previous': True,
                'new_findings': len(new_fps),
                'resolved_findings': len(resolved_fps),
                'score_delta': current_score - prev_score,
                'new_privileged': new_privileged[:10],
                'scope_escalations': scope_escalations[:10],
                'previous_score': prev_score,
                'previous_total_findings': len(prev_findings),
            }
        except Exception as e:
            logger.warning("Drift detection failed: %s", e)
            return {
                'has_previous': False,
                'new_findings': 0,
                'resolved_findings': 0,
                'score_delta': 0,
                'new_privileged': [],
                'scope_escalations': [],
            }
