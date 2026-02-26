"""
Drift Detection Engine

This module provides the DriftDetector class that compares two discovery runs
to identify security-relevant changes in the Azure environment. Drift detection
is essential for monitoring unauthorized changes, detecting privilege escalation,
and maintaining compliance.

Change Types Detected (Legacy 5-bucket):
    - New Identities: SPNs, users, or managed identities added since last run
    - Removed Identities: Identities deleted or deprovisioned
    - Permission Changes: Role assignments added or removed
    - Risk Changes: Risk level escalations or de-escalations
    - Credential Changes: Credential status deterioration (warning -> expired)

Enhanced Typed Events (13 types via drift_events.py):
    - identity_added, identity_removed, identity_disabled, identity_reactivated
    - role_assigned, role_removed, privilege_escalated, privilege_deescalated
    - risk_escalated, risk_deescalated
    - spn_credential_expired, spn_credential_added
    - mfa_disabled, owner_changed, microsoft_spn_modified

Usage:
    detector = DriftDetector(db)
    changes = detector.compare_runs(current_run_id, previous_run_id)  # legacy format
    result = detector.compare_runs_v2(current_run_id, previous_run_id)  # typed events + legacy
"""
import logging
from typing import Dict, List, Optional
from datetime import datetime
from app.database import Database
from app.engines.drift_events import DriftEventType, build_event

logger = logging.getLogger(__name__)

# Critical roles for privilege escalation detection
CRITICAL_ROLES = {
    'Global Administrator', 'Privileged Role Administrator',
    'Owner', 'User Access Administrator', 'Contributor',
    'Application Administrator', 'Cloud Application Administrator',
}


class DriftDetector:
    """Detect changes between discovery runs"""

    def __init__(self, db: Database):
        self.db = db

    def compare_runs(self, current_run_id: int, previous_run_id: int) -> Dict:
        """
        Compare two discovery runs and detect changes (legacy 5-bucket format).

        Returns:
            Dictionary with 5 change-type lists (backward compatible)
        """
        result = self._compare_runs_internal(current_run_id, previous_run_id)
        return result['legacy']

    def compare_runs_v2(self, current_run_id: int, previous_run_id: int) -> Dict:
        """
        Compare two runs and return both typed events and legacy format.

        Returns:
            {'events': [...], 'legacy': {...}}
        """
        return self._compare_runs_internal(current_run_id, previous_run_id)

    def _compare_runs_internal(self, current_run_id: int, previous_run_id: int) -> Dict:
        """Internal comparison that produces both events and legacy format."""
        print(f"\n🔄 Comparing Discovery Runs...")
        print(f"  Current:  Run #{current_run_id}")
        print(f"  Previous: Run #{previous_run_id}")

        # Get run timestamps for change reason computation
        prev_run_ts = self._get_run_timestamp(previous_run_id)
        first_run_ts = self._get_first_run_timestamp()

        # Get identities from both runs
        current_identities = self._get_run_identities(current_run_id)
        previous_identities = self._get_run_identities(previous_run_id)

        # Collect typed events
        events = []

        # Detect changes (legacy + events)
        new_identities = self._detect_new_identities(current_identities, previous_identities, prev_run_ts, first_run_ts, events)
        removed_identities = self._detect_removed_identities(current_identities, previous_identities, events)
        permission_changes = self._detect_permission_changes(current_identities, previous_identities, events)
        risk_changes = self._detect_risk_changes(current_identities, previous_identities, events)
        credential_changes = self._detect_credential_changes(current_identities, previous_identities, events)

        # New Phase 5 detectors
        self._detect_status_transitions(current_identities, previous_identities, events)
        self._detect_mfa_changes(current_identities, previous_identities, events)
        self._detect_owner_changes(current_identities, previous_identities, events)
        self._detect_microsoft_changes(current_identities, previous_identities, events)

        # Classification changes (Phase 3)
        classification_changes = self._detect_classification_changes(current_run_id, previous_run_id, events)

        # Soft-delete removed identities
        self._soft_delete_removed_identities(removed_identities)

        # Reactivate returned identities
        self._reactivate_returned_identities(new_identities)

        # Split Microsoft removals from customer removals
        microsoft_removed = [r for r in removed_identities if r.get('is_microsoft_system')]
        customer_removed = [r for r in removed_identities if not r.get('is_microsoft_system')]

        legacy = {
            'new_identities': new_identities,
            'removed_identities': customer_removed,
            'microsoft_removed_identities': microsoft_removed,
            'permission_changes': permission_changes,
            'risk_changes': risk_changes,
            'credential_changes': credential_changes,
            'classification_changes': classification_changes,
        }

        return {'events': events, 'legacy': legacy}

    def _get_run_timestamp(self, run_id: int) -> Optional[datetime]:
        """Get the started_at timestamp of a discovery run."""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT started_at FROM discovery_runs WHERE id = %s", (run_id,))
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None

    def _get_first_run_timestamp(self) -> Optional[datetime]:
        """Get the started_at timestamp of the very first discovery run."""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT started_at FROM discovery_runs ORDER BY id ASC LIMIT 1")
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None

    def _get_run_identities(self, run_id: int) -> Dict[str, Dict]:
        """
        Get all identities from a discovery run.

        Returns:
            Dict mapping identity_id to identity data
        """
        cursor = self.db.conn.cursor()

        cursor.execute("""
            SELECT
                i.identity_id,
                i.display_name,
                i.identity_type,
                i.identity_category,
                i.risk_level,
                i.credential_status,
                i.activity_status,
                i.credential_expiration,
                array_agg(
                    json_build_object(
                        'role_name', r.role_name,
                        'scope', r.scope,
                        'scope_type', r.scope_type
                    )
                ) FILTER (WHERE r.id IS NOT NULL) as roles,
                i.created_datetime,
                i.enabled,
                i.risk_score,
                i.risk_reasons,
                i.id as db_id,
                COALESCE(i.is_microsoft_system, false) as is_microsoft_system,
                COALESCE(i.ca_mfa_enforced, false) as ca_mfa_enforced,
                i.owner_display_name
            FROM identities i
            LEFT JOIN role_assignments r ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY i.id, i.identity_id, i.display_name, i.identity_type, i.identity_category,
                     i.risk_level, i.credential_status, i.activity_status, i.credential_expiration,
                     i.created_datetime, i.enabled, i.risk_score, i.risk_reasons,
                     i.is_microsoft_system, i.ca_mfa_enforced, i.owner_display_name
        """, (run_id,))

        identities = {}
        for row in cursor.fetchall():
            identities[row[0]] = {
                'identity_id': row[0],
                'display_name': row[1],
                'identity_type': row[2],
                'identity_category': row[3],
                'risk_level': row[4],
                'credential_status': row[5],
                'activity_status': row[6],
                'credential_expiration': row[7],
                'roles': row[8] if row[8] else [],
                'created_datetime': row[9],
                'enabled': row[10],
                'risk_score': row[11],
                'risk_reasons': row[12],
                'db_id': row[13],
                'is_microsoft_system': row[14],
                'ca_mfa_enforced': row[15],
                'owner_display_name': row[16],
            }

        cursor.close()
        return identities

    def _detect_new_identities(self, current: Dict, previous: Dict,
                               prev_run_ts: Optional[datetime] = None,
                               first_run_ts: Optional[datetime] = None,
                               events: list = None) -> List[Dict]:
        """Detect newly added identities with change reasons."""
        new = []
        for identity_id, data in current.items():
            if identity_id not in previous:
                reason = self._compute_new_identity_reason(data, prev_run_ts, first_run_ts)
                entry = dict(data)
                entry['change_reason'] = reason
                new.append(entry)

                if events is not None:
                    events.append(build_event(
                        DriftEventType.IDENTITY_ADDED,
                        identity_id,
                        data['display_name'],
                        reason,
                        details={
                            'identity_type': data.get('identity_type', ''),
                            'identity_category': data.get('identity_category', ''),
                            'risk_level': data.get('risk_level', 'info'),
                            'credential_status': data.get('credential_status', ''),
                            'is_microsoft_system': data.get('is_microsoft_system', False),
                        },
                    ))
        return new

    def _compute_new_identity_reason(self, data: Dict,
                                     prev_run_ts: Optional[datetime],
                                     first_run_ts: Optional[datetime]) -> str:
        """Determine why this identity appeared as new."""
        created_dt = data.get('created_datetime')

        if created_dt and prev_run_ts:
            created_naive = created_dt.replace(tzinfo=None) if hasattr(created_dt, 'replace') and created_dt.tzinfo else created_dt
            prev_naive = prev_run_ts.replace(tzinfo=None) if hasattr(prev_run_ts, 'replace') and prev_run_ts.tzinfo else prev_run_ts

            if isinstance(created_naive, datetime) and isinstance(prev_naive, datetime):
                if created_naive > prev_naive:
                    return f"Created in Entra ID on {created_naive.strftime('%Y-%m-%d')}"

                if first_run_ts:
                    first_naive = first_run_ts.replace(tzinfo=None) if hasattr(first_run_ts, 'replace') and first_run_ts.tzinfo else first_run_ts
                    if isinstance(first_naive, datetime) and created_naive < first_naive:
                        return "First discovered — existed before monitoring started"

        roles = data.get('roles', [])
        if roles:
            return "Moved into monitored scope — added to monitored subscription"

        return "First discovered in this scan"

    def _detect_removed_identities(self, current: Dict, previous: Dict,
                                    events: list = None) -> List[Dict]:
        """Detect removed identities with change reasons."""
        removed = []
        for identity_id, data in previous.items():
            if identity_id not in current:
                entry = dict(data)
                enabled = data.get('enabled')
                if enabled is False:
                    entry['change_reason'] = "Disabled — account status changed to disabled"
                elif data.get('roles'):
                    entry['change_reason'] = "Removed from monitored scope — no longer has RBAC on any monitored subscription"
                else:
                    entry['change_reason'] = "Deleted from Entra ID"
                removed.append(entry)

                if events is not None:
                    events.append(build_event(
                        DriftEventType.IDENTITY_REMOVED,
                        identity_id,
                        data['display_name'],
                        entry['change_reason'],
                        details={
                            'identity_type': data.get('identity_type', ''),
                            'identity_category': data.get('identity_category', ''),
                            'risk_level': data.get('risk_level', 'info'),
                            'credential_status': data.get('credential_status', ''),
                            'is_microsoft_system': data.get('is_microsoft_system', False),
                        },
                    ))
        return removed

    def _soft_delete_removed_identities(self, removed_list: List[Dict]):
        """Mark removed identities as soft-deleted in the database."""
        if not removed_list:
            return
        cursor = self.db.conn.cursor()
        try:
            for entry in removed_list:
                db_id = entry.get('db_id')
                if db_id:
                    cursor.execute("""
                        UPDATE identities SET status = 'deleted', deleted_at = NOW()
                        WHERE id = %s AND deleted_at IS NULL
                    """, (db_id,))
            self.db.conn.commit()
            logger.info(f"Soft-deleted {len(removed_list)} removed identities")
        except Exception as e:
            self.db.conn.rollback()
            logger.error(f"Error soft-deleting identities: {e}")
        finally:
            cursor.close()

    def _reactivate_returned_identities(self, new_list: List[Dict]):
        """Clear soft-delete for identities that reappear in a new run."""
        if not new_list:
            return
        cursor = self.db.conn.cursor()
        try:
            reactivated = 0
            for entry in new_list:
                identity_id = entry.get('identity_id')
                if identity_id:
                    cursor.execute("""
                        UPDATE identities SET deleted_at = NULL,
                            status = CASE WHEN enabled = false THEN 'disabled' ELSE 'active' END
                        WHERE identity_id = %s AND deleted_at IS NOT NULL
                    """, (identity_id,))
                    reactivated += cursor.rowcount
            self.db.conn.commit()
            if reactivated > 0:
                logger.info(f"Reactivated {reactivated} returned identities")
        except Exception as e:
            self.db.conn.rollback()
            logger.error(f"Error reactivating identities: {e}")
        finally:
            cursor.close()

    def _detect_permission_changes(self, current: Dict, previous: Dict,
                                    events: list = None) -> List[Dict]:
        """Detect permission/role changes with change_reason summary."""
        changes = []

        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_roles = set(self._role_signature(r) for r in current[identity_id]['roles'])
            prev_roles = set(self._role_signature(r) for r in previous[identity_id]['roles'])

            added_roles = curr_roles - prev_roles
            removed_roles = prev_roles - curr_roles

            if added_roles or removed_roles:
                parts = []
                for sig in sorted(added_roles):
                    parts.append(f"+ Added: {sig.replace(':', ' on ', 1)}")
                for sig in sorted(removed_roles):
                    parts.append(f"- Removed: {sig.replace(':', ' on ', 1)}")
                changes.append({
                    'identity': current[identity_id],
                    'added_roles': list(added_roles),
                    'removed_roles': list(removed_roles),
                    'change_reason': '; '.join(parts),
                })

                if events is not None:
                    curr_data = current[identity_id]
                    # Emit per-role typed events
                    for sig in added_roles:
                        role_name = sig.split(':')[0]
                        is_escalation = role_name in CRITICAL_ROLES
                        events.append(build_event(
                            DriftEventType.PRIVILEGE_ESCALATED if is_escalation else DriftEventType.ROLE_ASSIGNED,
                            identity_id,
                            curr_data['display_name'],
                            f"Role assigned: {sig.replace(':', ' on ', 1)}",
                            details={
                                'role_name': role_name,
                                'role_signature': sig,
                                'risk_level': curr_data.get('risk_level', 'info'),
                                'added_roles': list(added_roles),
                                'removed_roles': [],
                            },
                        ))
                    for sig in removed_roles:
                        role_name = sig.split(':')[0]
                        is_deescalation = role_name in CRITICAL_ROLES
                        events.append(build_event(
                            DriftEventType.PRIVILEGE_DEESCALATED if is_deescalation else DriftEventType.ROLE_REMOVED,
                            identity_id,
                            curr_data['display_name'],
                            f"Role removed: {sig.replace(':', ' on ', 1)}",
                            details={
                                'role_name': role_name,
                                'role_signature': sig,
                                'risk_level': curr_data.get('risk_level', 'info'),
                                'added_roles': [],
                                'removed_roles': list(removed_roles),
                            },
                        ))

        return changes

    def _detect_risk_changes(self, current: Dict, previous: Dict,
                              events: list = None) -> List[Dict]:
        """Detect risk level changes with before/after scores and reasons."""
        changes = []

        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_data = current[identity_id]
            prev_data = previous[identity_id]
            curr_risk = curr_data['risk_level']
            prev_risk = prev_data['risk_level']

            if curr_risk != prev_risk:
                prev_score = prev_data.get('risk_score', 0) or 0
                curr_score = curr_data.get('risk_score', 0) or 0
                reason = self._compute_risk_change_reason(curr_data, prev_data)
                severity = self._compare_risk_severity(prev_risk, curr_risk)

                change_reason = f"Risk score changed: {prev_score} → {curr_score} ({(prev_risk or 'unknown').upper()} → {(curr_risk or 'unknown').upper()})" + (f". Reason: {reason}" if reason else "")

                changes.append({
                    'identity': curr_data,
                    'previous_risk': prev_risk,
                    'current_risk': curr_risk,
                    'previous_score': prev_score,
                    'current_score': curr_score,
                    'severity': severity,
                    'change_reason': change_reason,
                })

                if events is not None:
                    event_type = DriftEventType.RISK_ESCALATED if severity == 'escalation' else DriftEventType.RISK_DEESCALATED
                    events.append(build_event(
                        event_type,
                        identity_id,
                        curr_data['display_name'],
                        change_reason,
                        details={
                            'previous_risk': prev_risk,
                            'current_risk': curr_risk,
                            'previous_score': prev_score,
                            'current_score': curr_score,
                            'severity': severity,
                        },
                    ))

        return changes

    def _compute_risk_change_reason(self, curr_data: Dict, prev_data: Dict) -> str:
        """Determine what caused a risk level change by comparing role sets and risk_reasons."""
        curr_roles = set(self._role_signature(r) for r in curr_data.get('roles', []))
        prev_roles = set(self._role_signature(r) for r in prev_data.get('roles', []))
        added = curr_roles - prev_roles
        if added:
            first = sorted(added)[0]
            role_name = first.split(':')[0]
            return f"Role added — {role_name}"

        curr_reasons = curr_data.get('risk_reasons') or []
        prev_reasons = prev_data.get('risk_reasons') or []
        if isinstance(curr_reasons, list) and isinstance(prev_reasons, list):
            new_reasons = set(str(r) for r in curr_reasons) - set(str(r) for r in prev_reasons)
            if new_reasons:
                return sorted(new_reasons)[0]

        curr_cred = curr_data.get('credential_status', '')
        prev_cred = prev_data.get('credential_status', '')
        if curr_cred != prev_cred and self._is_credential_deterioration(prev_cred, curr_cred):
            return f"Credential status: {prev_cred} → {curr_cred}"

        return ""

    def _detect_credential_changes(self, current: Dict, previous: Dict,
                                    events: list = None) -> List[Dict]:
        """Detect credential status changes with specifics."""
        changes = []

        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_data = current[identity_id]
            prev_data = previous[identity_id]
            curr_status = curr_data['credential_status']
            prev_status = prev_data['credential_status']

            if self._is_credential_deterioration(prev_status, curr_status):
                reason = self._compute_credential_change_reason(curr_data, prev_data)
                changes.append({
                    'identity': curr_data,
                    'previous_status': prev_status,
                    'current_status': curr_status,
                    'change_reason': reason,
                })

                if events is not None:
                    event_type = DriftEventType.SPN_CREDENTIAL_EXPIRED if curr_status == 'expired' else DriftEventType.SPN_CREDENTIAL_ADDED
                    events.append(build_event(
                        event_type,
                        identity_id,
                        curr_data['display_name'],
                        reason,
                        details={
                            'previous_status': prev_status,
                            'current_status': curr_status,
                            'risk_level': curr_data.get('risk_level', 'info'),
                        },
                    ))

        return changes

    def _compute_credential_change_reason(self, curr_data: Dict, prev_data: Dict) -> str:
        """Build a specific reason for credential status change."""
        prev_status = prev_data.get('credential_status', '')
        curr_status = curr_data.get('credential_status', '')
        expiry = curr_data.get('credential_expiration')

        if curr_status == 'expired':
            if expiry:
                exp_str = expiry.strftime('%Y-%m-%d') if hasattr(expiry, 'strftime') else str(expiry)[:10]
                return f"Credential expired on {exp_str}"
            return "Credential expired"
        elif curr_status == 'critical':
            if expiry:
                exp_str = expiry.strftime('%Y-%m-%d') if hasattr(expiry, 'strftime') else str(expiry)[:10]
                return f"Credential expiring soon: {exp_str}"
            return f"Credential status deteriorated: {prev_status} → {curr_status}"
        elif curr_status == 'warning':
            if expiry:
                exp_str = expiry.strftime('%Y-%m-%d') if hasattr(expiry, 'strftime') else str(expiry)[:10]
                return f"Credential approaching expiry: {exp_str}"
            return f"Credential status: {prev_status} → {curr_status}"
        return f"Credential status changed: {prev_status} → {curr_status}"

    # ── New Phase 5 Detectors ────────────────────────────────────────

    def _detect_status_transitions(self, current: Dict, previous: Dict,
                                    events: list):
        """Detect enabled→disabled and disabled→enabled transitions."""
        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_enabled = current[identity_id].get('enabled')
            prev_enabled = previous[identity_id].get('enabled')

            if prev_enabled is True and curr_enabled is False:
                events.append(build_event(
                    DriftEventType.IDENTITY_DISABLED,
                    identity_id,
                    current[identity_id]['display_name'],
                    f"{current[identity_id]['display_name']} was disabled",
                    details={
                        'identity_type': current[identity_id].get('identity_type', ''),
                        'risk_level': current[identity_id].get('risk_level', 'info'),
                    },
                ))
            elif prev_enabled is False and curr_enabled is True:
                events.append(build_event(
                    DriftEventType.IDENTITY_REACTIVATED,
                    identity_id,
                    current[identity_id]['display_name'],
                    f"{current[identity_id]['display_name']} was re-enabled",
                    details={
                        'identity_type': current[identity_id].get('identity_type', ''),
                        'risk_level': current[identity_id].get('risk_level', 'info'),
                    },
                ))

    def _detect_mfa_changes(self, current: Dict, previous: Dict,
                             events: list):
        """Detect MFA enforcement changes."""
        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_mfa = current[identity_id].get('ca_mfa_enforced', False)
            prev_mfa = previous[identity_id].get('ca_mfa_enforced', False)

            if prev_mfa is True and curr_mfa is False:
                events.append(build_event(
                    DriftEventType.MFA_DISABLED,
                    identity_id,
                    current[identity_id]['display_name'],
                    f"MFA enforcement removed for {current[identity_id]['display_name']}",
                    details={
                        'risk_level': current[identity_id].get('risk_level', 'info'),
                    },
                ))

    def _detect_owner_changes(self, current: Dict, previous: Dict,
                               events: list):
        """Detect owner changes."""
        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_owner = current[identity_id].get('owner_display_name') or ''
            prev_owner = previous[identity_id].get('owner_display_name') or ''

            if curr_owner != prev_owner and (curr_owner or prev_owner):
                events.append(build_event(
                    DriftEventType.OWNER_CHANGED,
                    identity_id,
                    current[identity_id]['display_name'],
                    f"Owner changed: '{prev_owner or 'none'}' → '{curr_owner or 'none'}'",
                    details={
                        'previous_owner': prev_owner,
                        'current_owner': curr_owner,
                        'risk_level': current[identity_id].get('risk_level', 'info'),
                    },
                ))

    def _detect_microsoft_changes(self, current: Dict, previous: Dict,
                                   events: list):
        """Detect modifications to Microsoft first-party SPNs."""
        for identity_id in set(current.keys()) & set(previous.keys()):
            if not current[identity_id].get('is_microsoft_system'):
                continue

            curr_data = current[identity_id]
            prev_data = previous[identity_id]

            # Check for role or risk changes on Microsoft SPNs
            curr_roles = set(self._role_signature(r) for r in curr_data.get('roles', []))
            prev_roles = set(self._role_signature(r) for r in prev_data.get('roles', []))
            role_changed = curr_roles != prev_roles

            risk_changed = curr_data.get('risk_level') != prev_data.get('risk_level')

            if role_changed or risk_changed:
                events.append(build_event(
                    DriftEventType.MICROSOFT_SPN_MODIFIED,
                    identity_id,
                    curr_data['display_name'],
                    f"Microsoft SPN '{curr_data['display_name']}' modified"
                    + (" (role change)" if role_changed else "")
                    + (" (risk change)" if risk_changed else ""),
                    details={
                        'role_changed': role_changed,
                        'risk_changed': risk_changed,
                        'is_microsoft_system': True,
                    },
                ))

    def _detect_classification_changes(self, current_run_id: int, previous_run_id: int,
                                        events: list) -> list:
        """Detect changes in data classification between runs (Phase 3)."""
        classification_changes = []
        cursor = self.db.conn.cursor()
        try:
            def _get_classifications(run_id):
                """Get classified resources from a run, keyed by resource_id."""
                result = {}
                for table, rtype in [('azure_storage_accounts', 'storage_account'),
                                     ('azure_key_vaults', 'key_vault')]:
                    cursor.execute(f"""
                        SELECT resource_id, name, data_classification, classification_source
                        FROM {table}
                        WHERE discovery_run_id = %s AND data_classification IS NOT NULL
                    """, (run_id,))
                    for row in cursor.fetchall():
                        result[row[0]] = {
                            'resource_id': row[0],
                            'name': row[1],
                            'classification': row[2],
                            'source': row[3],
                            'resource_type': rtype,
                        }
                return result

            curr_class = _get_classifications(current_run_id)
            prev_class = _get_classifications(previous_run_id)

            curr_keys = set(curr_class.keys())
            prev_keys = set(prev_class.keys())

            # Newly classified
            for rid in curr_keys - prev_keys:
                r = curr_class[rid]
                classification_changes.append({
                    'change_type': 'classified',
                    'resource_id': rid,
                    'resource_name': r['name'],
                    'resource_type': r['resource_type'],
                    'new_classification': r['classification'],
                    'previous_classification': None,
                })
                events.append(build_event(
                    DriftEventType.CLASSIFICATION_ADDED,
                    rid,
                    r['name'],
                    f"Resource '{r['name']}' classified as {r['classification']}",
                    details={'classification': r['classification'], 'resource_type': r['resource_type']},
                ))

            # Declassified
            for rid in prev_keys - curr_keys:
                r = prev_class[rid]
                classification_changes.append({
                    'change_type': 'declassified',
                    'resource_id': rid,
                    'resource_name': r['name'],
                    'resource_type': r['resource_type'],
                    'new_classification': None,
                    'previous_classification': r['classification'],
                })
                events.append(build_event(
                    DriftEventType.CLASSIFICATION_REMOVED,
                    rid,
                    r['name'],
                    f"Resource '{r['name']}' declassified (was {r['classification']})",
                    details={'previous_classification': r['classification'], 'resource_type': r['resource_type']},
                ))

            # Changed classification
            for rid in curr_keys & prev_keys:
                if curr_class[rid]['classification'] != prev_class[rid]['classification']:
                    classification_changes.append({
                        'change_type': 'reclassified',
                        'resource_id': rid,
                        'resource_name': curr_class[rid]['name'],
                        'resource_type': curr_class[rid]['resource_type'],
                        'new_classification': curr_class[rid]['classification'],
                        'previous_classification': prev_class[rid]['classification'],
                    })
                    events.append(build_event(
                        DriftEventType.CLASSIFICATION_CHANGED,
                        rid,
                        curr_class[rid]['name'],
                        f"Resource '{curr_class[rid]['name']}' reclassified: {prev_class[rid]['classification']} -> {curr_class[rid]['classification']}",
                        details={
                            'previous_classification': prev_class[rid]['classification'],
                            'new_classification': curr_class[rid]['classification'],
                            'resource_type': curr_class[rid]['resource_type'],
                        },
                    ))
        except Exception as e:
            print(f"  ⚠️  Classification change detection error: {e}")
        finally:
            cursor.close()

        return classification_changes

    # ── Helpers ─────────────────────────────────────────────────────

    def _role_signature(self, role: Dict) -> str:
        """Create a unique signature for a role assignment"""
        return f"{role['role_name']}:{role['scope_type']}:{role['scope']}"

    def _compare_risk_severity(self, prev: str, curr: str) -> str:
        """Compare risk levels and determine if escalation or de-escalation"""
        risk_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

        prev_level = risk_order.get(prev.lower() if prev else 'info', 0)
        curr_level = risk_order.get(curr.lower() if curr else 'info', 0)

        if curr_level > prev_level:
            return 'escalation'
        elif curr_level < prev_level:
            return 'de-escalation'
        return 'unchanged'

    def _is_credential_deterioration(self, prev: str, curr: str) -> bool:
        """Check if credential status got worse"""
        status_order = {'good': 0, 'unknown': 1, 'warning': 2, 'critical': 3, 'expired': 4}

        prev_level = status_order.get(prev, 1)
        curr_level = status_order.get(curr, 1)

        return curr_level > prev_level

    def print_drift_report(self, changes: Dict, current_run_id: int, previous_run_id: int):
        """Print a formatted drift detection report"""
        print("\n" + "="*60)
        print("🔄 Drift Detection Report")
        print("="*60)
        print(f"Comparing: Run #{current_run_id} vs Run #{previous_run_id}\n")

        total_changes = sum([
            len(changes.get('new_identities', [])),
            len(changes.get('removed_identities', [])),
            len(changes.get('permission_changes', [])),
            len(changes.get('risk_changes', [])),
            len(changes.get('credential_changes', []))
        ])

        if total_changes == 0:
            print("✅ No changes detected - environment is stable")
            return

        print(f"⚠️  {total_changes} changes detected:\n")

        if changes.get('new_identities'):
            print(f"🆕 New Identities: {len(changes['new_identities'])}")
            for identity in changes['new_identities']:
                print(f"  + {identity['display_name']} ({identity['risk_level']} risk)")
            print()

        if changes.get('removed_identities'):
            print(f"❌ Removed Identities: {len(changes['removed_identities'])}")
            for identity in changes['removed_identities']:
                print(f"  - {identity['display_name']}")
            print()

        ms_removed = changes.get('microsoft_removed_identities', [])
        if ms_removed:
            print(f"🏢 Microsoft Removed: {len(ms_removed)}")
            for identity in ms_removed[:5]:
                print(f"  - {identity['display_name']}")
            if len(ms_removed) > 5:
                print(f"  ... and {len(ms_removed) - 5} more")
            print()

        if changes.get('permission_changes'):
            print(f"⚠️  Permission Changes: {len(changes['permission_changes'])}")
            for change in changes['permission_changes']:
                identity = change['identity']
                print(f"  • {identity['display_name']}:")
                for role in change['added_roles']:
                    print(f"    + Added: {role}")
                for role in change['removed_roles']:
                    print(f"    - Removed: {role}")
            print()

        if changes.get('risk_changes'):
            print(f"📊 Risk Level Changes: {len(changes['risk_changes'])}")
            for change in changes['risk_changes']:
                identity = change['identity']
                severity = change['severity']
                icon = "⬆️" if severity == 'escalation' else "⬇️"
                print(f"  {icon} {identity['display_name']}: {change['previous_risk']} → {change['current_risk']}")
            print()

        if changes.get('credential_changes'):
            print(f"🔑 Credential Status Changes: {len(changes['credential_changes'])}")
            for change in changes['credential_changes']:
                identity = change['identity']
                print(f"  ⚠️  {identity['display_name']}: {change['previous_status']} → {change['current_status']}")
            print()
