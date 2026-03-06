"""
AuditGraph — Structured Security Event Logger

Emits machine-parseable security events for SIEM ingestion,
Azure Monitor alerts, and compliance audit trails.

Event Types:
    TENANT_CONTEXT_VIOLATION  — RLS context lost, mismatch, or bypass attempt
    RLS_DRIFT_DETECTED        — FORCE RLS or policy removed from a table
    ADMIN_GUARD_BLOCKED       — Unauthorized Database() in request context
    POOL_EXHAUSTION           — Connection pool hit capacity
    SLOW_QUERY                — Query exceeded DB_SLOW_QUERY_MS threshold
    AUTH_FAILURE              — Login failure, invalid token, expired session
    SECRET_ROTATION           — Credential rotation event (success or failure)
    MIGRATION_APPLIED         — Schema migration completed
    STARTUP_VALIDATION        — Startup checks passed or failed

All events are JSON-structured and include:
    - event_type: categorized event name
    - severity: critical / high / medium / low / info
    - tenant_id: affected org (if applicable)
    - timestamp: ISO 8601 UTC
    - correlation_id: request_id or job_id for tracing
    - details: event-specific payload
"""

import logging
import time
from datetime import datetime, timezone

_security_logger = logging.getLogger('auditgraph.security')


class SecurityEventLogger:
    """Structured security event emitter.

    Usage:
        SecurityEventLogger.tenant_violation(org_id=42, detail="context LOST")
        SecurityEventLogger.pool_exhaustion(pool='app', active=20, max=20)
    """

    @staticmethod
    def _emit(event_type, severity, details, tenant_id=None):
        """Core emit method — writes structured log entry."""
        correlation_id = None
        try:
            from flask import g
            correlation_id = getattr(g, 'request_id', None)
        except (ImportError, RuntimeError):
            pass

        event = {
            'event_type': event_type,
            'severity': severity,
            'tenant_id': tenant_id,
            'correlation_id': correlation_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': details,
        }

        # Route to appropriate log level based on severity
        level_map = {
            'critical': logging.CRITICAL,
            'high': logging.ERROR,
            'medium': logging.WARNING,
            'low': logging.INFO,
            'info': logging.INFO,
        }
        level = level_map.get(severity, logging.WARNING)

        # Use extra_data so JSONFormatter includes the structured fields
        _security_logger.log(
            level,
            "SECURITY_EVENT: %s [%s] tenant=%s",
            event_type, severity, tenant_id or 'N/A',
            extra={'extra_data': event},
        )
        return event

    # ----- Tenant Isolation Events -----

    @staticmethod
    def tenant_violation(org_id, detail, violation_type='unknown'):
        """Tenant context lost, mismatch, or bypass attempt."""
        return SecurityEventLogger._emit(
            'TENANT_CONTEXT_VIOLATION', 'critical',
            {'violation_type': violation_type, 'detail': detail},
            tenant_id=org_id,
        )

    @staticmethod
    def rls_drift(table, issue, severity_level='critical'):
        """RLS policy or FORCE RLS removed from a table."""
        return SecurityEventLogger._emit(
            'RLS_DRIFT_DETECTED', severity_level,
            {'table': table, 'issue': issue},
        )

    @staticmethod
    def admin_guard_blocked(caller_info=None):
        """Database() created without _admin_reason inside request context."""
        return SecurityEventLogger._emit(
            'ADMIN_GUARD_BLOCKED', 'high',
            {'caller': caller_info or 'unknown'},
        )

    # ----- Infrastructure Events -----

    @staticmethod
    def pool_exhaustion(pool_name, active, max_size):
        """Connection pool hit capacity — fallback to direct connections."""
        return SecurityEventLogger._emit(
            'POOL_EXHAUSTION', 'high',
            {'pool': pool_name, 'active': active, 'max': max_size,
             'utilization_pct': round(active / max_size * 100, 1) if max_size > 0 else 0},
        )

    @staticmethod
    def slow_query(elapsed_ms, sql_preview, org_id=None, endpoint=None):
        """Query exceeded the slow query threshold."""
        return SecurityEventLogger._emit(
            'SLOW_QUERY', 'medium',
            {'elapsed_ms': round(elapsed_ms, 1), 'sql': sql_preview, 'endpoint': endpoint},
            tenant_id=org_id,
        )

    @staticmethod
    def tenant_skew(org_id, metric, value, threshold):
        """A tenant is consuming disproportionate resources."""
        return SecurityEventLogger._emit(
            'TENANT_SKEW', 'medium',
            {'metric': metric, 'value': value, 'threshold': threshold},
            tenant_id=org_id,
        )

    # ----- Auth Events -----

    @staticmethod
    def auth_failure(username, reason, ip_address=None):
        """Authentication failure (login, token, session)."""
        return SecurityEventLogger._emit(
            'AUTH_FAILURE', 'medium',
            {'username': username, 'reason': reason, 'ip': ip_address},
        )

    @staticmethod
    def auth_success(user_id, username, ip_address=None):
        """Successful authentication."""
        return SecurityEventLogger._emit(
            'AUTH_SUCCESS', 'info',
            {'user_id': user_id, 'username': username, 'ip': ip_address},
        )

    # ----- Operational Events -----

    @staticmethod
    def secret_rotation(secret_name, status, detail=None):
        """Credential rotation event (scheduled or manual)."""
        severity = 'info' if status == 'success' else 'high'
        return SecurityEventLogger._emit(
            'SECRET_ROTATION', severity,
            {'secret_name': secret_name, 'status': status, 'detail': detail},
        )

    @staticmethod
    def migration_applied(version, description):
        """Schema migration completed."""
        return SecurityEventLogger._emit(
            'MIGRATION_APPLIED', 'info',
            {'version': version, 'description': description},
        )

    @staticmethod
    def startup_validation(check_name, passed, detail=None):
        """Startup validation result."""
        severity = 'info' if passed else 'critical'
        return SecurityEventLogger._emit(
            'STARTUP_VALIDATION', severity,
            {'check': check_name, 'passed': passed, 'detail': detail},
        )
