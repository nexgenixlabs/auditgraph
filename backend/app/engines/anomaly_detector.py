"""
Anomaly Detection Engine

Detects behavioral anomalies in identity security data by comparing
discovery runs and analyzing PIM activation patterns. Runs after drift
detection in the scheduler pipeline.

Anomaly Types:
    - permission_escalation: Identity gains critical/high-risk roles between runs
    - risk_score_spike: Risk score increases dramatically between runs
    - dormant_reactivation: Previously dormant identity becomes active
    - credential_surge: Credential count jumps significantly between runs
    - off_hours_pim: PIM activations outside business hours
    - excessive_pim_usage: Unusual PIM activation frequency or always-active pattern
    - excessive_api_permission: SPN has dangerous Application permissions (Mail.Send, etc.)

Usage:
    detector = AnomalyDetector(db)
    anomalies = detector.analyze(current_run_id, previous_run_id, settings)
"""
import logging
from typing import Dict, List, Optional
from app.database import Database
from app.constants.roles import EntraRole, RBACRole

logger = logging.getLogger(__name__)

# Roles considered critical for escalation detection
CRITICAL_ROLES: frozenset[str] = frozenset({
    EntraRole.GLOBAL_ADMIN, EntraRole.PRIVILEGED_ROLE_ADMIN,
    EntraRole.PRIVILEGED_AUTH_ADMIN, EntraRole.EXCHANGE_ADMIN,
    EntraRole.SHAREPOINT_ADMIN, EntraRole.APPLICATION_ADMIN,
    EntraRole.CLOUD_APP_ADMIN,
    RBACRole.USER_ACCESS_ADMIN, RBACRole.OWNER, RBACRole.CONTRIBUTOR,
})

HIGH_RISK_ROLES: frozenset[str] = frozenset({
    EntraRole.SECURITY_ADMIN, EntraRole.COMPLIANCE_ADMIN,
    EntraRole.CONDITIONAL_ACCESS_ADMIN, EntraRole.AUTH_ADMIN,
    EntraRole.GROUPS_ADMIN, EntraRole.DIRECTORY_WRITERS,
    EntraRole.INTUNE_ADMIN, EntraRole.AZURE_INFO_PROTECTION_ADMIN,
})

RISK_LEVEL_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


class AnomalyDetector:
    """Detect behavioral anomalies in identity data."""

    def __init__(self, db: Database):
        self.db = db

    def analyze(self, current_run_id: int, previous_run_id: int,
                settings: Optional[Dict] = None) -> List[Dict]:
        """
        Run all anomaly detectors and return combined results.

        Args:
            current_run_id: Latest completed discovery run
            previous_run_id: Previous discovery run for comparison
            settings: Optional dict of configurable thresholds

        Returns:
            List of anomaly dicts ready for save_anomalies()
        """
        settings = settings or {}
        anomalies = []

        detectors = [
            ('permission_escalation', self._detect_permission_escalation),
            ('risk_score_spike', self._detect_risk_score_spike),
            ('dormant_reactivation', self._detect_dormant_reactivation),
            ('credential_surge', self._detect_credential_surge),
            ('off_hours_pim', self._detect_off_hours_pim),
            ('excessive_pim_usage', self._detect_excessive_pim_usage),
            ('excessive_api_permission', self._detect_excessive_api_permissions),
            # AG-AI (2026-06-01): runaway AI agent detection — fires when an
            # AI agent's signal profile triggers any policy violation or
            # attack scenario. Composes existing ai_risk + ai_governance +
            # ai_attack_scenarios modules so it stays in sync with the
            # AI Security pages.
            ('ai_agent_runaway', self._detect_ai_agent_runaway),
            # AG-JML-Mover (2026-06-01): when department or job_title
            # changes across runs AND any privileged roles from the prior
            # job are still attached, surface as mover_stale_access. The
            # "M" of JML observability — CIEM detects what IGA misses,
            # without becoming IGA.
            ('mover_stale_access', self._detect_mover_stale_access),
            # AG-44 (2026-06-02): when an identity's agent_classification
            # transitions from None/unknown to ai_agent or possible_ai_agent
            # between scans, surface it as "new AI agent behavior". Demo
            # story Step 1 — "This SPN started calling Azure Cognitive
            # Services 6 days ago." Cross-run delta over the static
            # classifier output already written by services/agent_classifier.
            ('new_ai_agent_behavior', self._detect_new_ai_agent_behavior),
        ]

        for name, detector in detectors:
            try:
                # Ensure clean transaction state before each detector so a
                # failure in one detector doesn't poison all subsequent ones.
                try:
                    self.db.conn.rollback()
                except Exception:
                    pass
                if name in ('off_hours_pim', 'excessive_pim_usage',
                            'excessive_api_permission', 'ai_agent_runaway'):
                    results = detector(current_run_id, settings)
                else:
                    results = detector(current_run_id, previous_run_id)
                anomalies.extend(results)
                if results:
                    logger.info(f"  Anomaly detector '{name}': {len(results)} findings")
            except Exception as e:
                logger.error(f"  Anomaly detector '{name}' failed: {e}")
                try:
                    self.db.conn.rollback()
                except Exception:
                    pass

        return anomalies

    def _get_run_identities(self, run_id: int) -> Dict[str, Dict]:
        """Get identity data for a run, keyed by identity_id."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT identity_id, display_name, risk_level, risk_score,
                   activity_status, credential_count, identity_category
            FROM identities
            WHERE discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        result = {}
        for row in rows:
            result[row[0]] = {
                'identity_id': row[0],
                'display_name': row[1],
                'risk_level': row[2],
                'risk_score': row[3] or 0,
                'activity_status': row[4],
                'credential_count': row[5] or 0,
                'identity_category': row[6],
            }
        return result

    def _get_run_roles(self, run_id: int) -> Dict[str, List[str]]:
        """Get role assignments per identity for a run."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT i.identity_id, ra.role_name
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        roles = {}
        for identity_id, role_name in rows:
            roles.setdefault(identity_id, []).append(role_name)
        return roles

    def _get_run_identity_hr_fields(self, run_id: int) -> Dict[str, Dict]:
        """Get HR-derived identity fields (department, job_title, manager_upn)
        per identity for a run. Used by the mover-stale-access detector.

        Returned dict is keyed by identity_id → {department, job_title,
        manager_upn, display_name}. Missing fields default to empty string
        so the diff comparison is case-stable.
        """
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT identity_id, display_name,
                   COALESCE(department, ''), COALESCE(job_title, ''),
                   COALESCE(manager_upn, ''), COALESCE(enabled, true)
              FROM identities
             WHERE discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        return {
            row[0]: {
                'identity_id': row[0],
                'display_name': row[1],
                'department': row[2],
                'job_title': row[3],
                'manager_upn': row[4],
                'enabled': bool(row[5]),
            }
            for row in rows
        }

    def _get_run_entra_roles(self, run_id: int) -> Dict[str, List[str]]:
        """Get Entra role assignments per identity for a run."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT i.identity_id, era.role_name
            FROM entra_role_assignments era
            JOIN identities i ON i.id = era.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        rows = cursor.fetchall()
        cursor.close()
        roles = {}
        for identity_id, role_name in rows:
            roles.setdefault(identity_id, []).append(role_name)
        return roles

    def _detect_permission_escalation(self, current_run_id: int,
                                       previous_run_id: int) -> List[Dict]:
        """Detect identities that gained critical/high-risk roles between runs."""
        anomalies = []

        prev_roles = self._get_run_roles(previous_run_id)
        curr_roles = self._get_run_roles(current_run_id)
        prev_entra = self._get_run_entra_roles(previous_run_id)
        curr_entra = self._get_run_entra_roles(current_run_id)
        curr_identities = self._get_run_identities(current_run_id)

        for identity_id, identity in curr_identities.items():
            # Check RBAC role gains
            old_rbac = set(prev_roles.get(identity_id, []))
            new_rbac = set(curr_roles.get(identity_id, []))
            gained_rbac = new_rbac - old_rbac

            # Check Entra role gains
            old_entra = set(prev_entra.get(identity_id, []))
            new_entra = set(curr_entra.get(identity_id, []))
            gained_entra = new_entra - old_entra

            gained_all = gained_rbac | gained_entra
            if not gained_all:
                continue

            critical_gained = gained_all & CRITICAL_ROLES
            high_gained = gained_all & HIGH_RISK_ROLES

            if critical_gained:
                anomalies.append({
                    'anomaly_type': 'permission_escalation',
                    'severity': 'critical',
                    'identity_id': identity_id,
                    'identity_name': identity['display_name'],
                    'title': f"Critical role escalation: {identity['display_name']}",
                    'description': f"Gained critical roles: {', '.join(sorted(critical_gained))}",
                    'details': {
                        'gained_roles': sorted(critical_gained | high_gained),
                        'all_gained': sorted(gained_all),
                        'previous_rbac_roles': sorted(old_rbac),
                        'current_rbac_roles': sorted(new_rbac),
                    },
                })
            elif high_gained:
                anomalies.append({
                    'anomaly_type': 'permission_escalation',
                    'severity': 'high',
                    'identity_id': identity_id,
                    'identity_name': identity['display_name'],
                    'title': f"High-risk role escalation: {identity['display_name']}",
                    'description': f"Gained high-risk roles: {', '.join(sorted(high_gained))}",
                    'details': {
                        'gained_roles': sorted(high_gained),
                        'all_gained': sorted(gained_all),
                    },
                })

        return anomalies

    def _detect_risk_score_spike(self, current_run_id: int,
                                  previous_run_id: int) -> List[Dict]:
        """Detect identities with dramatic risk score increases."""
        anomalies = []
        prev = self._get_run_identities(previous_run_id)
        curr = self._get_run_identities(current_run_id)

        for identity_id, curr_identity in curr.items():
            prev_identity = prev.get(identity_id)
            if not prev_identity:
                continue

            score_delta = curr_identity['risk_score'] - prev_identity['risk_score']
            old_level = prev_identity['risk_level'] or 'low'
            new_level = curr_identity['risk_level'] or 'low'
            level_delta = RISK_LEVEL_ORDER.get(new_level, 0) - RISK_LEVEL_ORDER.get(old_level, 0)

            if score_delta >= 100 or level_delta >= 2:
                severity = 'critical' if (score_delta >= 200 or level_delta >= 3) else \
                           'high' if score_delta >= 100 else 'medium'
                anomalies.append({
                    'anomaly_type': 'risk_score_spike',
                    'severity': severity,
                    'identity_id': identity_id,
                    'identity_name': curr_identity['display_name'],
                    'title': f"Risk spike: {curr_identity['display_name']}",
                    'description': (
                        f"Risk score jumped from {prev_identity['risk_score']} to "
                        f"{curr_identity['risk_score']} (+{score_delta}), "
                        f"level {old_level} -> {new_level}"
                    ),
                    'details': {
                        'old_score': prev_identity['risk_score'],
                        'new_score': curr_identity['risk_score'],
                        'score_delta': score_delta,
                        'old_level': old_level,
                        'new_level': new_level,
                    },
                })

        return anomalies

    def _detect_dormant_reactivation(self, current_run_id: int,
                                      previous_run_id: int) -> List[Dict]:
        """Detect previously dormant/never-used identities that became active."""
        anomalies = []
        prev = self._get_run_identities(previous_run_id)
        curr = self._get_run_identities(current_run_id)
        dormant_statuses = {'stale', 'never_used', 'inactive'}

        for identity_id, curr_identity in curr.items():
            prev_identity = prev.get(identity_id)
            if not prev_identity:
                continue

            old_status = prev_identity.get('activity_status', '')
            new_status = curr_identity.get('activity_status', '')

            if old_status in dormant_statuses and new_status == 'active':
                anomalies.append({
                    'anomaly_type': 'dormant_reactivation',
                    'severity': 'high',
                    'identity_id': identity_id,
                    'identity_name': curr_identity['display_name'],
                    'title': f"Dormant identity reactivated: {curr_identity['display_name']}",
                    'description': (
                        f"Activity status changed from '{old_status}' to 'active'. "
                        f"Previously dormant identities becoming active may indicate compromise."
                    ),
                    'details': {
                        'old_status': old_status,
                        'new_status': new_status,
                        'identity_category': curr_identity.get('identity_category'),
                    },
                })

        return anomalies

    def _detect_credential_surge(self, current_run_id: int,
                                  previous_run_id: int) -> List[Dict]:
        """Detect identities with sudden credential count increases."""
        anomalies = []
        prev = self._get_run_identities(previous_run_id)
        curr = self._get_run_identities(current_run_id)

        for identity_id, curr_identity in curr.items():
            prev_identity = prev.get(identity_id)
            if not prev_identity:
                continue

            old_count = prev_identity['credential_count']
            new_count = curr_identity['credential_count']
            delta = new_count - old_count

            if delta >= 2:
                severity = 'high' if delta >= 4 else 'medium'
                anomalies.append({
                    'anomaly_type': 'credential_surge',
                    'severity': severity,
                    'identity_id': identity_id,
                    'identity_name': curr_identity['display_name'],
                    'title': f"Credential surge: {curr_identity['display_name']}",
                    'description': (
                        f"Credential count increased from {old_count} to {new_count} "
                        f"(+{delta}). Rapid credential creation may indicate key rotation "
                        f"issues or unauthorized access."
                    ),
                    'details': {
                        'old_count': old_count,
                        'new_count': new_count,
                        'delta': delta,
                    },
                })

        return anomalies

    def _detect_off_hours_pim(self, current_run_id: int,
                               settings: Dict) -> List[Dict]:
        """Detect PIM activations outside business hours."""
        anomalies = []
        hours_start = int(settings.get('anomaly_pim_hours_start', 6))
        hours_end = int(settings.get('anomaly_pim_hours_end', 20))

        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT pa.role_name, pa.activation_start,
                   i.display_name, i.identity_id
            FROM pim_activations pa
            JOIN identities i ON i.id = pa.identity_db_id
            WHERE i.discovery_run_id = %s
              AND pa.activation_start IS NOT NULL
              AND (EXTRACT(HOUR FROM pa.activation_start) < %s
                   OR EXTRACT(HOUR FROM pa.activation_start) >= %s)
        """, (current_run_id, hours_start, hours_end))
        rows = cursor.fetchall()
        cursor.close()

        seen = set()
        for row in rows:
            role_name, activation_start, display_name, identity_id = row
            key = (identity_id, role_name, str(activation_start))
            if key in seen:
                continue
            seen.add(key)

            hour = activation_start.hour if activation_start else None
            severity = 'high' if role_name in CRITICAL_ROLES else 'medium'

            anomalies.append({
                'anomaly_type': 'off_hours_pim',
                'severity': severity,
                'identity_id': identity_id,
                'identity_name': display_name,
                'title': f"Off-hours PIM activation: {display_name}",
                'description': (
                    f"PIM role '{role_name}' activated at {activation_start.strftime('%H:%M UTC') if activation_start else 'unknown'} "
                    f"(outside {hours_start:02d}:00-{hours_end:02d}:00 window)."
                ),
                'details': {
                    'role_name': role_name,
                    'activation_time': activation_start.isoformat() if activation_start else None,
                    'hour': hour,
                    'business_hours': f"{hours_start:02d}:00-{hours_end:02d}:00",
                },
            })

        return anomalies

    def _detect_excessive_pim_usage(self, current_run_id: int,
                                     settings: Dict) -> List[Dict]:
        """Detect identities with unusually high PIM activation frequency.

        Counts activations per identity per role in the last 30 days from
        the pim_activations table (the eligible_assignments table does not
        store frequency; we compute it here).
        """
        anomalies = []
        threshold = int(settings.get('anomaly_pim_frequency_threshold', 10))

        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT i.identity_id, i.display_name, pa.role_name,
                   COUNT(*) as activation_count
            FROM pim_activations pa
            JOIN identities i ON i.id = pa.identity_db_id
            WHERE i.discovery_run_id = %s
              AND pa.activation_start >= NOW() - INTERVAL '30 days'
            GROUP BY i.identity_id, i.display_name, pa.role_name
            HAVING COUNT(*) > %s
        """, (current_run_id, threshold))
        rows = cursor.fetchall()
        cursor.close()

        for row in rows:
            identity_id, display_name, role_name, freq = row

            severity = 'high' if freq > threshold * 2 else 'medium'
            desc = (
                f"PIM role '{role_name}' activated {freq} times in 30 days "
                f"(threshold: {threshold}). Excessive activations may indicate "
                f"the role should be permanently assigned or reviewed."
            )

            anomalies.append({
                'anomaly_type': 'excessive_pim_usage',
                'severity': severity,
                'identity_id': identity_id,
                'identity_name': display_name,
                'title': f"Excessive PIM usage: {display_name}",
                'description': desc,
                'details': {
                    'role_name': role_name,
                    'activation_frequency_30d': freq,
                    'threshold': threshold,
                },
            })

        return anomalies

    # ── Excessive API Permissions ────────────────────────────────────────

    # Application permissions that are excessive for automation/workload SPNs.
    # These grant tenant-wide capabilities rarely needed for their classified
    # function and represent a high-risk attack surface if compromised.
    EXCESSIVE_SPN_PERMISSIONS = {
        'Mail.Send': {
            'severity': 'high',
            'description': (
                'Mail.Send (Application) permission grants the ability to send '
                'email as any user in the tenant without a mailbox. If this '
                'service principal is compromised, an attacker can send phishing '
                'emails from any organizational address. Remove per CIS v8 §5.5 '
                'least privilege for service accounts.'
            ),
            'standards': 'CIS v8 §5.5, NIST SP 800-207 §3.3',
            'mitre': 'T1566 (Phishing via compromised service account)',
        },
        'Mail.ReadWrite': {
            'severity': 'high',
            'description': (
                'Mail.ReadWrite (Application) permission grants read/write access '
                'to all mailboxes in the tenant. Not required for standard workload '
                'identities. Remove per CIS v8 §5.5 least privilege.'
            ),
            'standards': 'CIS v8 §5.5, NIST SP 800-207 §3.3',
            'mitre': 'T1114 (Email Collection)',
        },
        'Exchange.ManageAsApp': {
            'severity': 'critical',
            'description': (
                'Exchange.ManageAsApp grants full Exchange Online administration. '
                'This is an extremely high-privilege permission rarely needed by '
                'automation workloads. Remove immediately per CIS v8 §5.5.'
            ),
            'standards': 'CIS v8 §5.5, NIST SP 800-207 §3.3',
            'mitre': 'T1098 (Account Manipulation)',
        },
    }

    def _detect_excessive_api_permissions(self, current_run_id: int,
                                          settings: Optional[Dict] = None) -> List[Dict]:
        """Detect service principals with excessive API permissions.

        Checks graph_api_permissions for dangerous Application permissions
        on service principal identities that indicate over-privileging.
        """
        anomalies = []
        perm_names = tuple(self.EXCESSIVE_SPN_PERMISSIONS.keys())
        if not perm_names:
            return anomalies

        cursor = self.db.conn.cursor()
        placeholders = ','.join(['%s'] * len(perm_names))
        cursor.execute(f"""
            SELECT i.identity_id, i.display_name, i.identity_category,
                   gp.permission_name
            FROM graph_api_permissions gp
            JOIN identities i ON i.id = gp.identity_db_id
            WHERE i.discovery_run_id = %s
              AND i.identity_category IN ('service_principal', 'managed_identity_system', 'managed_identity_user')
              AND gp.permission_name IN ({placeholders})
        """, (current_run_id, *perm_names))
        rows = cursor.fetchall()
        cursor.close()

        # Deduplicate: one anomaly per (identity_id, permission_name)
        seen = set()
        for identity_id, display_name, category, perm_name in rows:
            key = (identity_id, perm_name)
            if key in seen:
                continue
            seen.add(key)

            rule = self.EXCESSIVE_SPN_PERMISSIONS.get(perm_name, {})
            severity = rule.get('severity', 'high')
            desc = rule.get('description', f'{perm_name} is excessive for this workload identity.')
            standards = rule.get('standards', '')
            mitre = rule.get('mitre', '')

            anomalies.append({
                'anomaly_type': 'excessive_api_permission',
                'severity': severity,
                'identity_id': identity_id,
                'identity_name': display_name,
                'title': f"Excessive API permission: {perm_name} on {display_name}",
                'description': desc,
                'details': {
                    'permission_name': perm_name,
                    'identity_category': category,
                    'standards': standards,
                    'mitre_technique': mitre,
                },
            })

        return anomalies

    # ── AI Agent Runaway Detection ────────────────────────────────────────

    def _detect_ai_agent_runaway(self, current_run_id: int,
                                 settings: Optional[Dict] = None) -> List[Dict]:
        """Detect AI agents whose risk profile indicates 'runaway' behavior.

        AG-AI (2026-06-01): for each AI agent identity in the current run,
        evaluate the existing ai_risk signals + ai_governance policies +
        ai_attack_scenarios chains. Emit an anomaly when:

          (a) ANY attack scenario activates (critical → high severity)
              — e.g. AI_DATA_EXFILTRATION requires sensitive_data_access
              + unrestricted_egress, both deterministic from RBAC + scope.

          (b) A high/critical policy fires for an agent that's also
              dormant or ownerless — the "stewardless + powerful" pattern
              that produces the runaway-agent risk story.

        Composes existing modules (no duplication): same signals/policies/
        scenarios the AI Security pages already render. This detector
        promotes them into the standard Anomalies feed so they appear
        alongside permission-escalation, credential-surge, etc.
        """
        from app.constants.ai_risk import detect_signals, aggregate_access_levels, compute_signal_score
        from app.constants.ai_governance import evaluate_agent_policies
        from app.constants.ai_attack_scenarios import evaluate_scenarios

        anomalies: List[Dict] = []
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                       i.agent_identity_type, i.owner_display_name,
                       i.credential_count, i.credential_risk,
                       i.last_sign_in, i.last_activity_date, i.risk_score
                  FROM identities i
                 WHERE i.discovery_run_id = %s
                   AND i.agent_identity_type IS NOT NULL
            """, (current_run_id,))
            agents = cursor.fetchall()
        except Exception:
            cursor.close()
            return anomalies

        # Pull the run's org_id so we can fetch active exceptions for this
        # tenant only. Approved + non-expired exceptions suppress matching
        # policy violations — anomalies must NOT fire for explicitly
        # risk-accepted agents.
        run_org_id = None
        try:
            cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (current_run_id,))
            row = cursor.fetchone()
            if row:
                run_org_id = row[0] if isinstance(row, (tuple, list)) else row.get('organization_id')
        except Exception:
            run_org_id = None
        active_map: Dict = {}
        if run_org_id is not None:
            try:
                active_excs = self.db.list_active_ai_governance_exceptions(run_org_id)
                active_map = {
                    (e['identity_id'], e['policy_id']): e.get('expires_at')
                    for e in active_excs
                }
            except Exception:
                active_map = {}

        for row in agents:
            db_id, identity_id, display_name, category, agent_type, \
                owner_name, cred_count, cred_risk, last_signin, last_act, risk_score = row

            # Fetch role assignments for signal computation
            cursor.execute("""
                SELECT role_name, scope, scope_type
                  FROM role_assignments
                 WHERE identity_db_id = %s
            """, (db_id,))
            role_rows = cursor.fetchall()
            role_assignments = [
                {'role_name': r[0], 'scope': r[1], 'scope_type': r[2]}
                for r in role_rows
            ]

            agent_meta = {
                'display_name': display_name,
                'owner_display_name': owner_name,
                'credential_count': cred_count or 0,
                'credential_risk': cred_risk,
                'last_sign_in': last_signin,
                'last_activity_date': last_act,
                'detected_platform': '',  # not yet wired
            }
            try:
                access_levels = aggregate_access_levels(role_assignments)
                fired = detect_signals(agent_meta, role_assignments, access_levels)
            except Exception:
                continue
            if not fired:
                continue

            fired_keys = {s['key'] for s in fired}
            try:
                violations = evaluate_agent_policies(
                    fired_keys,
                    identity_id=identity_id,
                    active_exceptions=active_map,
                )
                scenarios = evaluate_scenarios(fired_keys)
            except Exception:
                continue

            # Drop suppressed violations — an approved exception means this
            # policy fire is intentionally risk-accepted; anomalies should not
            # surface it. Scenarios still fire because they may chain on signals
            # unrelated to the policy under exception.
            violations = [v for v in (violations or []) if not v.get('suppressed_by_exception')]

            active_scenarios = [s for s in (scenarios or []) if s.get('active')] if scenarios else []
            if not violations and not active_scenarios:
                continue

            # Compute composite CVSS score for the anomaly severity tier
            try:
                score_info = compute_signal_score(fired)
                cvss = score_info.get('score') or 0
            except Exception:
                cvss = 0

            if active_scenarios:
                lead = active_scenarios[0]
                lead_name = lead.get('title') or lead.get('name') or lead.get('key') or lead.get('id')
                title = f"Runaway AI agent: {display_name} — {lead_name}"
                severity = lead.get('severity') or 'critical'
                desc = (
                    f"AI agent crossed attack scenario \"{lead_name}\". "
                    f"{lead.get('description', '')} "
                    f"Composite signal score: {cvss}."
                )
            else:
                top = max(violations, key=lambda v: {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}.get((v.get('severity') or 'medium').lower(), 0))
                top_name = top.get('name') or top.get('id') or top.get('policy_key')
                title = f"AI agent policy violation: {display_name} — {top_name}"
                severity = top.get('severity') or 'high'
                desc = (
                    f"AI agent violates governance policy \"{top_name}\". "
                    f"{top.get('rationale') or top.get('description', '')} "
                    f"Composite signal score: {cvss}."
                )

            anomalies.append({
                'anomaly_type': 'ai_agent_runaway',
                'severity': severity,
                'identity_id': identity_id,
                'identity_name': display_name,
                'title': title,
                'description': desc,
                'details': {
                    'agent_identity_type': agent_type,
                    'identity_category': category,
                    'cvss_score': cvss,
                    'fired_signals': [
                        {'key': s['key'], 'evidence': s.get('evidence', '')}
                        for s in fired
                    ],
                    'policy_violations': [
                        {'policy_id': v.get('id'), 'name': v.get('name'),
                         'severity': v.get('severity'),
                         'framework': v.get('framework', []),
                         'remediation': v.get('remediation')}
                        for v in (violations or [])
                    ],
                    'active_scenarios': [
                        {'id': s.get('id'), 'name': s.get('name') or s.get('title'),
                         'severity': s.get('severity'),
                         'description': s.get('description')}
                        for s in active_scenarios
                    ],
                    'owner_present': bool(owner_name),
                },
            })

        cursor.close()
        return anomalies

    # ── JML Observability: Mover stale-access ─────────────────────────────

    def _detect_mover_stale_access(self, current_run_id: int,
                                   previous_run_id: int) -> List[Dict]:
        """Detect identities whose department or job_title changed across
        runs but whose privileged roles from the prior job are still
        attached.

        AG-JML (2026-06-01): the "Mover" half of JML observability.
        AuditGraph doesn't write to HRIS / Workday / AD (that would be
        IGA territory — SailPoint/Saviynt) — we just SURFACE the
        observability gap: "Bharath moved Sales → Engineering 60 days
        ago and still has Salesforce Sales Admin." The customer's
        existing IGA (or manual offboarding) decides what to do.

        The signal that makes this a real anomaly (vs noise) is the
        INTERSECTION: roles that existed BEFORE the job change AND still
        exist AFTER. A role granted post-move is the user's new job;
        a role from the old job that lingered is the stale-access risk.
        We only flag privileged roles to keep signal-to-noise high.
        """
        anomalies: List[Dict] = []
        if previous_run_id is None:
            return anomalies

        try:
            prev_hr = self._get_run_identity_hr_fields(previous_run_id)
            curr_hr = self._get_run_identity_hr_fields(current_run_id)
        except Exception as e:
            logger.warning("[mover_stale_access] HR field fetch failed: %s", e)
            return anomalies

        # Movers: identities present in both runs with any HR field change.
        movers: Dict[str, Dict] = {}
        for ident_id, curr in curr_hr.items():
            prev = prev_hr.get(ident_id)
            if not prev:
                continue
            dept_changed = (prev['department'] or '').strip().lower() != (curr['department'] or '').strip().lower()
            title_changed = (prev['job_title'] or '').strip().lower() != (curr['job_title'] or '').strip().lower()
            manager_changed = (prev['manager_upn'] or '').strip().lower() != (curr['manager_upn'] or '').strip().lower()
            if not (dept_changed or title_changed or manager_changed):
                continue
            movers[ident_id] = {
                'prev': prev,
                'curr': curr,
                'dept_changed': dept_changed,
                'title_changed': title_changed,
                'manager_changed': manager_changed,
            }

        if not movers:
            return anomalies

        # Only compare roles for the movers (small set; faster than fetching
        # all run roles when only a few percent of identities moved).
        prev_rbac = self._get_run_roles(previous_run_id)
        curr_rbac = self._get_run_roles(current_run_id)
        prev_entra = self._get_run_entra_roles(previous_run_id)
        curr_entra = self._get_run_entra_roles(current_run_id)

        for ident_id, mv in movers.items():
            prev_roles = set(prev_rbac.get(ident_id, [])) | set(prev_entra.get(ident_id, []))
            curr_roles = set(curr_rbac.get(ident_id, [])) | set(curr_entra.get(ident_id, []))
            # Stale = present BEFORE and STILL present AFTER (intersection).
            stale = prev_roles & curr_roles
            # Filter to privileged only (CRITICAL_ROLES + HIGH_RISK_ROLES
            # define what a CISO actually cares about for a movers query).
            stale_priv = sorted(stale & (CRITICAL_ROLES | HIGH_RISK_ROLES))
            if not stale_priv:
                continue

            # Severity: critical if any CRITICAL_ROLES survived the move,
            # else high. This is the classic mover risk pattern.
            sev = 'critical' if (stale & CRITICAL_ROLES) else 'high'

            change_parts = []
            if mv['dept_changed']:
                change_parts.append(
                    f"department: \"{mv['prev']['department'] or '(empty)'}\" → "
                    f"\"{mv['curr']['department'] or '(empty)'}\""
                )
            if mv['title_changed']:
                change_parts.append(
                    f"title: \"{mv['prev']['job_title'] or '(empty)'}\" → "
                    f"\"{mv['curr']['job_title'] or '(empty)'}\""
                )
            if mv['manager_changed']:
                change_parts.append(
                    f"manager: \"{mv['prev']['manager_upn'] or '(empty)'}\" → "
                    f"\"{mv['curr']['manager_upn'] or '(empty)'}\""
                )
            change_summary = '; '.join(change_parts)

            anomalies.append({
                'anomaly_type': 'mover_stale_access',
                'severity': sev,
                'identity_id': ident_id,
                'identity_name': mv['curr']['display_name'],
                'title': f"Mover with stale access: {mv['curr']['display_name']}",
                'description': (
                    f"Identity moved ({change_summary}) since the prior scan, "
                    f"but {len(stale_priv)} privileged role(s) from the prior "
                    f"job are still attached: {', '.join(stale_priv[:5])}"
                    + (f" (+{len(stale_priv) - 5} more)" if len(stale_priv) > 5 else "")
                    + ". Review whether the user still needs these roles in "
                    "their new role; remove or convert to PIM-eligible."
                ),
                'details': {
                    'department_changed': mv['dept_changed'],
                    'title_changed': mv['title_changed'],
                    'manager_changed': mv['manager_changed'],
                    'prev_department': mv['prev']['department'],
                    'curr_department': mv['curr']['department'],
                    'prev_job_title': mv['prev']['job_title'],
                    'curr_job_title': mv['curr']['job_title'],
                    'prev_manager_upn': mv['prev']['manager_upn'],
                    'curr_manager_upn': mv['curr']['manager_upn'],
                    'stale_privileged_roles': stale_priv,
                    'frameworks': {
                        'nist': ['AC-2 (Account Management)', 'AC-6 (Least Privilege)'],
                        'cis': ['CIS Azure 1.22', 'CIS Azure 1.23'],
                        'mitre': ['T1078.004'],
                    },
                },
            })

        return anomalies

    def _detect_new_ai_agent_behavior(self, current_run_id: int,
                                       previous_run_id: int) -> List[Dict]:
        """Detect identities that flipped from non-AI to AI between scans.

        AG-44 (2026-06-02): the temporal companion to the static
        agent_classifier. The static classifier writes per-run snapshots
        to agent_classifications (identity_db_id, discovery_run_id) →
        (agent_identity_type, detected_platform, confidence, reason). This
        detector compares the LATEST classification per identity_id across
        the two runs and surfaces transitions:

          previous: None / 'unknown'
          current:  'ai_agent' or 'possible_ai_agent'

        Why temporal: a SPN that was a vanilla automation account last
        scan and now triggers ai_agent classification means SOMETHING
        CHANGED — new role on Cognitive Services, new app_id match, new
        AI workload binding. The demo narration is "This SPN started
        calling Azure Cognitive Services 6 days ago", which is exactly
        this transition.

        Severity: critical when the new classification is high-confidence
        ai_agent AND the identity holds any privileged role; else high
        for ai_agent transitions; medium for possible_ai_agent.

        NIST / CIS / MITRE framework refs included on the anomaly so the
        compliance tab can map the finding to controls.
        """
        anomalies: List[Dict] = []
        if previous_run_id is None:
            # First scan in the org's history — no baseline to compare
            # against; static classifier output is the whole story.
            return anomalies

        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                SELECT identity_id, agent_identity_type, detected_platform,
                       classification_confidence, classification_reason
                  FROM agent_classifications
                 WHERE discovery_run_id = %s
            """, (previous_run_id,))
            prev_map = {
                r[0]: {
                    'agent_identity_type': r[1],
                    'detected_platform': r[2],
                    'classification_confidence': float(r[3]) if r[3] is not None else 0.0,
                    'classification_reason': r[4],
                }
                for r in cursor.fetchall()
            }

            cursor.execute("""
                SELECT i.id, ac.identity_id, ac.agent_identity_type,
                       ac.detected_platform, ac.classification_confidence,
                       ac.classification_reason, i.display_name,
                       i.identity_category, i.risk_level
                  FROM agent_classifications ac
                  JOIN identities i ON i.id = ac.identity_db_id
                 WHERE ac.discovery_run_id = %s
            """, (current_run_id,))
            current_rows = cursor.fetchall()
        except Exception as e:
            logger.warning("[new_ai_agent_behavior] fetch failed: %s", e)
            cursor.close()
            return anomalies

        for row in current_rows:
            (identity_db_id, identity_id, curr_type, curr_platform,
             curr_conf, curr_reason, display_name, identity_category,
             risk_level) = row
            curr_type = (curr_type or '').lower()
            if curr_type not in ('ai_agent', 'possible_ai_agent'):
                continue

            prev = prev_map.get(identity_id)
            prev_type = (prev.get('agent_identity_type') if prev else None) or 'unknown'
            prev_type = prev_type.lower()
            # Only fire on TRANSITIONS — already-classified agents are
            # the static classifier's job, not the temporal detector's.
            if prev_type in ('ai_agent', 'possible_ai_agent'):
                continue
            # Also skip humans — ai_privileged_human is a different story.
            if identity_category == 'human_user':
                continue

            # Severity:
            #   critical = confirmed ai_agent + privileged risk + high confidence
            #   high     = ai_agent (any other condition)
            #   medium   = possible_ai_agent
            risk_norm = (risk_level or '').lower()
            curr_conf_f = float(curr_conf) if curr_conf is not None else 0.0
            if curr_type == 'ai_agent' and curr_conf_f >= 0.8 and risk_norm in ('critical', 'high'):
                sev = 'critical'
            elif curr_type == 'ai_agent':
                sev = 'high'
            else:
                sev = 'medium'

            platform_phrase = (
                f' on platform {curr_platform}' if curr_platform else ''
            )
            title = (
                f"AI agent behavior emerged: {display_name or identity_id} "
                f"(was {prev_type}, now {curr_type}{platform_phrase})"
            )
            description = (
                f"Between the previous and current discovery, this identity "
                f"transitioned from {prev_type} to {curr_type}{platform_phrase}. "
                f"Classifier rationale: {curr_reason or 'no reason recorded'}."
            )
            anomalies.append({
                'discovery_run_id': current_run_id,
                'anomaly_type': 'new_ai_agent_behavior',
                'severity': sev,
                'identity_id': identity_id,
                'identity_name': display_name,
                'title': title,
                'description': description,
                'details': {
                    'previous_agent_identity_type': prev_type,
                    'current_agent_identity_type': curr_type,
                    'current_classification_confidence': curr_conf_f,
                    'current_classification_reason': curr_reason,
                    'detected_platform': curr_platform,
                    'previous_run_id': previous_run_id,
                    'risk_level_at_emergence': risk_norm or None,
                    'frameworks': {
                        'nist': ['AC-2 (Account Management)', 'AC-6 (Least Privilege)',
                                 'CM-3 (Configuration Change Control)'],
                        'cis': ['CIS Azure 1.21'],
                        'mitre': ['T1078.004 (Cloud Accounts)', 'T1098.001 (Additional Cloud Credentials)'],
                    },
                },
            })

        cursor.close()
        return anomalies
