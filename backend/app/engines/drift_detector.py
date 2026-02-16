"""
Drift Detection Engine

This module provides the DriftDetector class that compares two discovery runs
to identify security-relevant changes in the Azure environment. Drift detection
is essential for monitoring unauthorized changes, detecting privilege escalation,
and maintaining compliance.

Change Types Detected:
    - New Identities: SPNs, users, or managed identities added since last run
    - Removed Identities: Identities deleted or deprovisioned
    - Permission Changes: Role assignments added or removed
    - Risk Changes: Risk level escalations or de-escalations
    - Credential Changes: Credential status deterioration (warning -> expired)

Use Cases:
    - Security Monitoring: Detect unauthorized privilege grants
    - Compliance Auditing: Track changes for audit trails
    - Change Management: Verify expected vs unexpected changes
    - Incident Response: Identify compromised account activity

Report Format:
    {
        'new_identities': [...],
        'removed_identities': [...],
        'permission_changes': [...],
        'risk_changes': [...],
        'credential_changes': [...]
    }

Usage:
    detector = DriftDetector(db)
    changes = detector.compare_runs(current_run_id, previous_run_id)
    detector.print_drift_report(changes, current_run_id, previous_run_id)
"""
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from app.database import Database


class DriftDetector:
    """Detect changes between discovery runs"""
    
    def __init__(self, db: Database):
        """
        Initialize drift detector
        
        Args:
            db: Database instance
        """
        self.db = db
    
    def compare_runs(self, current_run_id: int, previous_run_id: int) -> Dict:
        """
        Compare two discovery runs and detect changes

        Args:
            current_run_id: ID of current/latest discovery run
            previous_run_id: ID of previous discovery run to compare against

        Returns:
            Dictionary containing all detected changes
        """
        print(f"\n🔄 Comparing Discovery Runs...")
        print(f"  Current:  Run #{current_run_id}")
        print(f"  Previous: Run #{previous_run_id}")

        # Get run timestamps for change reason computation
        prev_run_ts = self._get_run_timestamp(previous_run_id)
        first_run_ts = self._get_first_run_timestamp()

        # Get identities from both runs
        current_identities = self._get_run_identities(current_run_id)
        previous_identities = self._get_run_identities(previous_run_id)

        # Detect changes
        changes = {
            'new_identities': self._detect_new_identities(current_identities, previous_identities, prev_run_ts, first_run_ts),
            'removed_identities': self._detect_removed_identities(current_identities, previous_identities),
            'permission_changes': self._detect_permission_changes(current_identities, previous_identities),
            'risk_changes': self._detect_risk_changes(current_identities, previous_identities),
            'credential_changes': self._detect_credential_changes(current_identities, previous_identities)
        }

        return changes

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
        Get all identities from a discovery run

        Returns:
            Dict mapping identity_id to identity data
        """
        cursor = self.db.conn.cursor()

        # Get identities with role assignments + extra fields for change reasons
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
                i.id as db_id
            FROM identities i
            LEFT JOIN role_assignments r ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY i.id, i.identity_id, i.display_name, i.identity_type, i.identity_category,
                     i.risk_level, i.credential_status, i.activity_status, i.credential_expiration,
                     i.created_datetime, i.enabled, i.risk_score, i.risk_reasons
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
            }

        cursor.close()
        return identities
    
    def _detect_new_identities(self, current: Dict, previous: Dict,
                               prev_run_ts: Optional[datetime] = None,
                               first_run_ts: Optional[datetime] = None) -> List[Dict]:
        """Detect newly added identities with change reasons."""
        new = []
        for identity_id, data in current.items():
            if identity_id not in previous:
                reason = self._compute_new_identity_reason(data, prev_run_ts, first_run_ts)
                entry = dict(data)
                entry['change_reason'] = reason
                new.append(entry)
        return new

    def _compute_new_identity_reason(self, data: Dict,
                                     prev_run_ts: Optional[datetime],
                                     first_run_ts: Optional[datetime]) -> str:
        """Determine why this identity appeared as new."""
        created_dt = data.get('created_datetime')

        # If identity was previously disabled (enabled=True now, but we can't check
        # previous state since it wasn't in the previous run — use heuristic)
        if created_dt and prev_run_ts:
            # Timezone-naive comparison
            created_naive = created_dt.replace(tzinfo=None) if hasattr(created_dt, 'replace') and created_dt.tzinfo else created_dt
            prev_naive = prev_run_ts.replace(tzinfo=None) if hasattr(prev_run_ts, 'replace') and prev_run_ts.tzinfo else prev_run_ts

            if isinstance(created_naive, datetime) and isinstance(prev_naive, datetime):
                if created_naive > prev_naive:
                    return f"Created in Entra ID on {created_naive.strftime('%Y-%m-%d')}"

                if first_run_ts:
                    first_naive = first_run_ts.replace(tzinfo=None) if hasattr(first_run_ts, 'replace') and first_run_ts.tzinfo else first_run_ts
                    if isinstance(first_naive, datetime) and created_naive < first_naive:
                        return "First discovered — existed before monitoring started"

        # Check if identity has RBAC roles (moved into monitored scope)
        roles = data.get('roles', [])
        if roles:
            return "Moved into monitored scope — added to monitored subscription"

        return "First discovered in this scan"
    
    def _detect_removed_identities(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect removed identities with change reasons."""
        removed = []
        for identity_id, data in previous.items():
            if identity_id not in current:
                entry = dict(data)
                # Check if identity was disabled (still in Entra but disabled)
                enabled = data.get('enabled')
                if enabled is False:
                    entry['change_reason'] = "Disabled — account status changed to disabled"
                elif data.get('roles'):
                    entry['change_reason'] = "Removed from monitored scope — no longer has RBAC on any monitored subscription"
                else:
                    entry['change_reason'] = "Deleted from Entra ID"
                removed.append(entry)
        return removed
    
    def _detect_permission_changes(self, current: Dict, previous: Dict) -> List[Dict]:
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

        return changes
    
    def _detect_risk_changes(self, current: Dict, previous: Dict) -> List[Dict]:
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

                changes.append({
                    'identity': curr_data,
                    'previous_risk': prev_risk,
                    'current_risk': curr_risk,
                    'previous_score': prev_score,
                    'current_score': curr_score,
                    'severity': self._compare_risk_severity(prev_risk, curr_risk),
                    'change_reason': f"Risk score changed: {prev_score} \u2192 {curr_score} ({(prev_risk or 'unknown').upper()} \u2192 {(curr_risk or 'unknown').upper()})" + (f". Reason: {reason}" if reason else ""),
                })

        return changes

    def _compute_risk_change_reason(self, curr_data: Dict, prev_data: Dict) -> str:
        """Determine what caused a risk level change by comparing role sets and risk_reasons."""
        # Compare roles to find newly added ones
        curr_roles = set(self._role_signature(r) for r in curr_data.get('roles', []))
        prev_roles = set(self._role_signature(r) for r in prev_data.get('roles', []))
        added = curr_roles - prev_roles
        if added:
            # Extract just the role name from the first added role signature
            first = sorted(added)[0]
            role_name = first.split(':')[0]
            return f"Role added — {role_name}"

        # Check Entra role changes via risk_reasons
        curr_reasons = curr_data.get('risk_reasons') or []
        prev_reasons = prev_data.get('risk_reasons') or []
        if isinstance(curr_reasons, list) and isinstance(prev_reasons, list):
            new_reasons = set(str(r) for r in curr_reasons) - set(str(r) for r in prev_reasons)
            if new_reasons:
                return sorted(new_reasons)[0]

        # Credential deterioration
        curr_cred = curr_data.get('credential_status', '')
        prev_cred = prev_data.get('credential_status', '')
        if curr_cred != prev_cred and self._is_credential_deterioration(prev_cred, curr_cred):
            return f"Credential status: {prev_cred} \u2192 {curr_cred}"

        return ""
    
    def _detect_credential_changes(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect credential status changes with specifics."""
        changes = []

        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_data = current[identity_id]
            prev_data = previous[identity_id]
            curr_status = curr_data['credential_status']
            prev_status = prev_data['credential_status']

            # Alert on credential status deterioration
            if self._is_credential_deterioration(prev_status, curr_status):
                reason = self._compute_credential_change_reason(curr_data, prev_data)
                changes.append({
                    'identity': curr_data,
                    'previous_status': prev_status,
                    'current_status': curr_status,
                    'change_reason': reason,
                })

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
            return f"Credential status deteriorated: {prev_status} \u2192 {curr_status}"
        elif curr_status == 'warning':
            if expiry:
                exp_str = expiry.strftime('%Y-%m-%d') if hasattr(expiry, 'strftime') else str(expiry)[:10]
                return f"Credential approaching expiry: {exp_str}"
            return f"Credential status: {prev_status} \u2192 {curr_status}"
        return f"Credential status changed: {prev_status} \u2192 {curr_status}"
    
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
            len(changes['new_identities']),
            len(changes['removed_identities']),
            len(changes['permission_changes']),
            len(changes['risk_changes']),
            len(changes['credential_changes'])
        ])
        
        if total_changes == 0:
            print("✅ No changes detected - environment is stable")
            return
        
        print(f"⚠️  {total_changes} changes detected:\n")
        
        # New identities
        if changes['new_identities']:
            print(f"🆕 New Identities: {len(changes['new_identities'])}")
            for identity in changes['new_identities']:
                print(f"  + {identity['display_name']} ({identity['risk_level']} risk)")
            print()
        
        # Removed identities
        if changes['removed_identities']:
            print(f"❌ Removed Identities: {len(changes['removed_identities'])}")
            for identity in changes['removed_identities']:
                print(f"  - {identity['display_name']}")
            print()
        
        # Permission changes
        if changes['permission_changes']:
            print(f"⚠️  Permission Changes: {len(changes['permission_changes'])}")
            for change in changes['permission_changes']:
                identity = change['identity']
                print(f"  • {identity['display_name']}:")
                for role in change['added_roles']:
                    print(f"    + Added: {role}")
                for role in change['removed_roles']:
                    print(f"    - Removed: {role}")
            print()
        
        # Risk changes
        if changes['risk_changes']:
            print(f"📊 Risk Level Changes: {len(changes['risk_changes'])}")
            for change in changes['risk_changes']:
                identity = change['identity']
                severity = change['severity']
                icon = "⬆️" if severity == 'escalation' else "⬇️"
                print(f"  {icon} {identity['display_name']}: {change['previous_risk']} → {change['current_risk']}")
            print()
        
        # Credential changes
        if changes['credential_changes']:
            print(f"🔑 Credential Status Changes: {len(changes['credential_changes'])}")
            for change in changes['credential_changes']:
                identity = change['identity']
                print(f"  ⚠️  {identity['display_name']}: {change['previous_status']} → {change['current_status']}")
            print()
