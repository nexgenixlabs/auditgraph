"""
Custom Risk Rule Engine for AuditGraph.

Evaluates user-defined rules against identity data after default risk scoring.
Rules can adjust points or force a specific risk level.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class RiskRuleEngine:
    """Evaluates custom risk rules against identity data."""

    SUPPORTED_FIELDS = {
        'identity_category', 'identity_type', 'display_name', 'enabled',
        'activity_status', 'role_count', 'api_permission_count',
        'has_write_permissions', 'has_entra_role', 'has_rbac_role',
        'risk_score', 'credential_status', 'app_role_count',
    }

    SUPPORTED_OPS = {'eq', 'neq', 'gt', 'lt', 'gte', 'lte', 'in', 'contains'}

    def evaluate_rules(self, identity: dict, rules: list):
        """
        Apply custom rules to an identity after default scoring.

        Returns:
            (points_adjustment: int, extra_reasons: list[str], force_level: str|None)
        """
        total_adj = 0
        extra_reasons = []
        force_level = None

        for rule in rules:
            try:
                if self._matches(identity, rule):
                    action = rule.get('action_type', 'adjust_points')
                    reason = rule.get('reason_text') or rule.get('name', 'Custom rule')
                    tagged = f"[Custom Rule] {reason}"

                    if action == 'force_level' and rule.get('force_level'):
                        force_level = rule['force_level']
                        extra_reasons.append(tagged)
                    elif action == 'adjust_points':
                        adj = rule.get('points_adjustment', 0)
                        if adj != 0:
                            total_adj += adj
                            extra_reasons.append(f"{tagged} ({'+' if adj > 0 else ''}{adj} pts)")
            except Exception as e:
                logger.warning(f"Error evaluating rule #{rule.get('id')}: {e}")

        return total_adj, extra_reasons, force_level

    def _matches(self, identity: dict, rule: dict) -> bool:
        """Check if all conditions in a rule match the identity."""
        conditions = rule.get('conditions', {})
        all_conditions = conditions.get('all', [])

        if not all_conditions:
            return False

        return all(self._check_condition(identity, cond) for cond in all_conditions)

    def _check_condition(self, identity: dict, condition: dict) -> bool:
        """Check a single condition against identity data."""
        field = condition.get('field', '')
        op = condition.get('op', 'eq')
        expected = condition.get('value')

        actual = self._get_field_value(identity, field, expected)

        if op == 'eq':
            return self._normalize(actual) == self._normalize(expected)
        elif op == 'neq':
            return self._normalize(actual) != self._normalize(expected)
        elif op == 'gt':
            return self._to_num(actual) > self._to_num(expected)
        elif op == 'lt':
            return self._to_num(actual) < self._to_num(expected)
        elif op == 'gte':
            return self._to_num(actual) >= self._to_num(expected)
        elif op == 'lte':
            return self._to_num(actual) <= self._to_num(expected)
        elif op == 'in':
            if isinstance(expected, list):
                return self._normalize(actual) in [self._normalize(v) for v in expected]
            return False
        elif op == 'contains':
            return str(expected).lower() in str(actual).lower()

        return False

    def _get_field_value(self, identity: dict, field: str, condition_value=None):
        """Extract a field value, handling computed fields."""
        # Direct fields
        if field in ('identity_category', 'identity_type', 'display_name',
                     'enabled', 'activity_status', 'risk_score',
                     'role_count', 'api_permission_count', 'app_role_count'):
            return identity.get(field)

        # Computed: has_write_permissions
        if field == 'has_write_permissions':
            permissions = identity.get('_permissions', [])
            for p in permissions:
                pname = (p.get('permission_name') or '').lower()
                if '.write' in pname or '.readwrite' in pname:
                    return True
            return False

        # Computed: has_entra_role (substring match against condition_value)
        if field == 'has_entra_role':
            entra_roles = identity.get('entra_roles', [])
            search = str(condition_value).lower() if condition_value else ''
            for r in entra_roles:
                if search in (r.get('role_name') or '').lower():
                    return True
            return False

        # Computed: has_rbac_role (substring match)
        if field == 'has_rbac_role':
            roles = identity.get('roles', [])
            search = str(condition_value).lower() if condition_value else ''
            for r in roles:
                if search in (r.get('role_name') or '').lower():
                    return True
            return False

        # Computed: credential_status
        if field == 'credential_status':
            creds = identity.get('_credentials', [])
            if not creds:
                return 'none'
            has_expired = False
            has_expiring = False
            for c in creds:
                end_date = c.get('end_datetime')
                if end_date:
                    try:
                        if isinstance(end_date, str):
                            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        else:
                            end_dt = end_date
                        now = datetime.now(timezone.utc)
                        if end_dt < now:
                            has_expired = True
                        elif (end_dt - now).days < 30:
                            has_expiring = True
                    except Exception:
                        pass
            if has_expired:
                return 'expired'
            if has_expiring:
                return 'expiring_soon'
            return 'healthy'

        return identity.get(field)

    @staticmethod
    def _normalize(val):
        """Normalize a value for comparison."""
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.lower().strip()
        return val

    @staticmethod
    def _to_num(val):
        """Convert to number for comparison."""
        try:
            return float(val)
        except (TypeError, ValueError):
            return 0
