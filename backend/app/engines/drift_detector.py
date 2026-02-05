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
        
        # Get identities from both runs
        current_identities = self._get_run_identities(current_run_id)
        previous_identities = self._get_run_identities(previous_run_id)
        
        # Detect changes
        changes = {
            'new_identities': self._detect_new_identities(current_identities, previous_identities),
            'removed_identities': self._detect_removed_identities(current_identities, previous_identities),
            'permission_changes': self._detect_permission_changes(current_identities, previous_identities),
            'risk_changes': self._detect_risk_changes(current_identities, previous_identities),
            'credential_changes': self._detect_credential_changes(current_identities, previous_identities)
        }
        
        return changes
    
    def _get_run_identities(self, run_id: int) -> Dict[str, Dict]:
        """
        Get all identities from a discovery run
        
        Returns:
            Dict mapping identity_id to identity data
        """
        cursor = self.db.conn.cursor()
        
        # Get identities with their role assignments
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
                ) FILTER (WHERE r.id IS NOT NULL) as roles
            FROM identities i
            LEFT JOIN role_assignments r ON r.identity_db_id = i.id
            WHERE i.discovery_run_id = %s
            GROUP BY i.id, i.identity_id, i.display_name, i.identity_type, i.identity_category,
                     i.risk_level, i.credential_status, i.activity_status, i.credential_expiration
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
                'roles': row[8] if row[8] else []
            }
        
        cursor.close()
        return identities
    
    def _detect_new_identities(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect newly added identities"""
        new = []
        for identity_id, data in current.items():
            if identity_id not in previous:
                new.append(data)
        return new
    
    def _detect_removed_identities(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect removed identities"""
        removed = []
        for identity_id, data in previous.items():
            if identity_id not in current:
                removed.append(data)
        return removed
    
    def _detect_permission_changes(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect permission/role changes"""
        changes = []
        
        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_roles = set(self._role_signature(r) for r in current[identity_id]['roles'])
            prev_roles = set(self._role_signature(r) for r in previous[identity_id]['roles'])
            
            added_roles = curr_roles - prev_roles
            removed_roles = prev_roles - curr_roles
            
            if added_roles or removed_roles:
                changes.append({
                    'identity': current[identity_id],
                    'added_roles': list(added_roles),
                    'removed_roles': list(removed_roles)
                })
        
        return changes
    
    def _detect_risk_changes(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect risk level changes"""
        changes = []
        
        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_risk = current[identity_id]['risk_level']
            prev_risk = previous[identity_id]['risk_level']
            
            if curr_risk != prev_risk:
                changes.append({
                    'identity': current[identity_id],
                    'previous_risk': prev_risk,
                    'current_risk': curr_risk,
                    'severity': self._compare_risk_severity(prev_risk, curr_risk)
                })
        
        return changes
    
    def _detect_credential_changes(self, current: Dict, previous: Dict) -> List[Dict]:
        """Detect credential status changes"""
        changes = []
        
        for identity_id in set(current.keys()) & set(previous.keys()):
            curr_status = current[identity_id]['credential_status']
            prev_status = previous[identity_id]['credential_status']
            
            # Alert on credential status deterioration
            if self._is_credential_deterioration(prev_status, curr_status):
                changes.append({
                    'identity': current[identity_id],
                    'previous_status': prev_status,
                    'current_status': curr_status
                })
        
        return changes
    
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
