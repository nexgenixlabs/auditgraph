"""
Tenant-scope enforcement — SSOT for cross-tenant isolation at application layer.

AG-94: CWE-639 (Authorization Bypass Through User-Controlled Key)
       CWE-284 (Improper Access Control)
       OWASP A01:2021 — Broken Access Control

Every Database method that queries a tenant-scoped table MUST use one of:

  1. @requires_org_id — enforces org_id: int is keyword-only, non-None,
     positive integer BEFORE any SQL executes. For standard tenant-scoped ops.

  2. @cross_org(reason=..., audit_event=...) — explicitly marks methods
     that intentionally span orgs (superadmin analytics, billing rollups).
     Emits an audit log entry per call. Nothing else may omit org_id.

Pattern:
    from app.security.tenant_scope import requires_org_id

    @requires_org_id
    def get_latest_discovery_run(self, *, org_id: int) -> Optional[Dict]:
        cursor.execute(
            "SELECT ... FROM discovery_runs WHERE organization_id = %s ...",
            (org_id,),
        )

See docs/security/tenant-isolation.md for full threat model.
"""

import functools
import inspect
import logging
import os
import threading
import time
from typing import FrozenSet, Optional

logger = logging.getLogger(__name__)

_CACHE_TTL = max(5, int(os.environ.get('TENANT_SCOPE_CACHE_TTL_SEC', '60')))


# ── Exception types ────────────────────────────────────────────────────────

class TenantScopeError(Exception):
    """Raised when a tenant-scoped operation is invoked without valid org_id.

    This is a SECURITY exception — callers must return 403 or 422,
    never 500. Do NOT catch with generic Exception handlers.
    """


# ── Tenant-table registry ─────────────────────────────────────────────────

_lock = threading.Lock()
_tenant_tables_cache: Optional[FrozenSet[str]] = None
_tenant_tables_cache_ts: float = 0.0

# Hardcoded baseline from integrity.py — used when no DB connection available.
# Must be kept in sync with information_schema; the CI drift test verifies.
_BASELINE_TENANT_TABLES = frozenset({
    'activity_log', 'agirs_scores', 'anomalies', 'api_keys',
    'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
    'cloud_connections', 'compliance_framework_config', 'compliance_snapshots',
    'copilot_conversations', 'credentials',
    'dashboard_preferences', 'discovery_runs', 'discovery_stage_log',
    'drift_reports', 'entra_role_assignments',
    'graph_api_permissions', 'graph_attack_findings', 'graph_edges',
    'identities',
    'identity_exposures', 'identity_groups', 'identity_group_members',
    'identity_subscription_access',
    'job_runs', 'notifications',
    'pim_activations', 'pim_eligible_assignments', 'posture_scores',
    'remediation_actions', 'remediation_playbooks',
    'risk_rules', 'risk_scores', 'risk_summary',
    'role_assignments',
    'sa_attestations', 'saved_views', 'scan_schedules',
    'security_findings', 'settings', 'snapshot_jobs', 'snapshot_runs',
    'soar_actions', 'soar_playbooks',
    'sp_app_roles', 'webhooks',
    'workload_activity_stats', 'workload_anomaly_events', 'workload_signin_events',
})


def _load_tenant_tables(conn) -> FrozenSet[str]:
    """Load table names that have an organization_id column from information_schema."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT table_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND column_name = 'organization_id' "
        "ORDER BY table_name"
    )
    names = frozenset(r[0] for r in cursor.fetchall())
    cursor.close()
    return names


def tenant_tables(conn=None) -> FrozenSet[str]:
    """Get the set of tenant-scoped table names.

    Uses a TTL cache. Falls back to the hardcoded baseline if no
    connection is available.
    """
    global _tenant_tables_cache, _tenant_tables_cache_ts
    now = time.monotonic()

    if _tenant_tables_cache is not None and (now - _tenant_tables_cache_ts) < _CACHE_TTL:
        return _tenant_tables_cache

    if conn is None:
        return _tenant_tables_cache or _BASELINE_TENANT_TABLES

    with _lock:
        if _tenant_tables_cache is not None and (time.monotonic() - _tenant_tables_cache_ts) < _CACHE_TTL:
            return _tenant_tables_cache
        _tenant_tables_cache = _load_tenant_tables(conn)
        _tenant_tables_cache_ts = time.monotonic()
        return _tenant_tables_cache


def is_tenant_table(name: str, conn=None) -> bool:
    """Check if a table is tenant-scoped (has organization_id column)."""
    return name in tenant_tables(conn)


def invalidate_cache():
    """Clear the tenant-table cache. Call after schema migrations."""
    global _tenant_tables_cache, _tenant_tables_cache_ts
    with _lock:
        _tenant_tables_cache = None
        _tenant_tables_cache_ts = 0.0


# ── @requires_org_id decorator ────────────────────────────────────────────

def _validate_org_id(org_id, func_name: str):
    """Validate org_id is a positive integer. Raises TenantScopeError if not."""
    if org_id is None:
        _log_violation(func_name, reason="org_id is None")
        raise TenantScopeError(
            f"{func_name}() requires org_id but received None. "
            "Pass the authenticated user's organization_id."
        )
    if not isinstance(org_id, int):
        _log_violation(func_name, reason=f"org_id is {type(org_id).__name__}, not int")
        raise TenantScopeError(
            f"{func_name}() requires org_id to be int, got {type(org_id).__name__}"
        )
    if org_id <= 0:
        _log_violation(func_name, reason=f"org_id is {org_id} (must be > 0)")
        raise TenantScopeError(
            f"{func_name}() requires org_id > 0, got {org_id}"
        )


def _log_violation(func_name: str, reason: str = "", table: str = "",
                   org_id=None, caller: str = ""):
    """Structured WARN log for SIEM alerting on tenant scope violations."""
    import traceback
    if not caller:
        frames = traceback.extract_stack(limit=5)
        caller = f"{frames[-3].filename}:{frames[-3].lineno}" if len(frames) >= 3 else "unknown"

    # Try to get request_id from Flask context
    request_id = ""
    try:
        from flask import g
        request_id = getattr(g, 'request_id', '')
    except (ImportError, RuntimeError):
        pass

    logger.warning(
        "tenant_scope_violation: %s — %s",
        func_name, reason,
        extra={
            "event": "tenant_scope_violation",
            "function": func_name,
            "table": table,
            "org_id": org_id,
            "caller": caller,
            "request_id": request_id,
            "reason": reason,
        },
    )


def requires_org_id(func):
    """Decorator: enforces org_id keyword argument is present, int, and > 0.

    The decorated function MUST have `org_id` as a keyword-only parameter
    with no default value. This is verified at decoration time (import).

    At call time, validates org_id before the function body executes.
    Raises TenantScopeError on violation — callers should return 403/422.
    """
    sig = inspect.signature(func)
    param = sig.parameters.get('org_id')
    if param is None:
        raise TypeError(
            f"@requires_org_id: {func.__qualname__} must have an 'org_id' parameter"
        )
    if param.kind != inspect.Parameter.KEYWORD_ONLY:
        raise TypeError(
            f"@requires_org_id: {func.__qualname__} 'org_id' must be keyword-only "
            f"(use *, org_id: int). Got kind={param.kind.name}"
        )
    if param.default is not inspect.Parameter.empty:
        raise TypeError(
            f"@requires_org_id: {func.__qualname__} 'org_id' must not have a default value"
        )

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        org_id = kwargs.get('org_id', inspect.Parameter.empty)
        if org_id is inspect.Parameter.empty:
            _log_violation(func.__qualname__, reason="org_id not passed as keyword arg")
            raise TenantScopeError(
                f"{func.__qualname__}() missing required keyword argument: 'org_id'"
            )
        _validate_org_id(org_id, func.__qualname__)
        return func(*args, **kwargs)

    # Preserve the original signature for introspection
    wrapper.__wrapped__ = func
    return wrapper


# ── @cross_org decorator ──────────────────────────────────────────────────

def cross_org(*, reason: str, audit_event: str):
    """Decorator: marks a method as intentionally cross-org (unscoped).

    Args:
        reason: Human-readable justification (e.g., "superadmin platform analytics").
        audit_event: Machine-parseable event name for audit log entries.

    Every call emits a structured audit log entry with: function, reason,
    caller user_id, request_id, timestamp. This is NOT silent.
    """
    if not reason or not reason.strip():
        raise TypeError("@cross_org requires a non-empty 'reason' string")
    if not audit_event or not audit_event.strip():
        raise TypeError("@cross_org requires a non-empty 'audit_event' string")

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Emit audit log
            user_id = None
            request_id = ""
            try:
                from flask import g
                user = getattr(g, 'current_user', None)
                user_id = user.get('id') if user else None
                request_id = getattr(g, 'request_id', '')
            except (ImportError, RuntimeError):
                pass

            logger.info(
                "cross_org_access: %s — %s",
                func.__qualname__, reason,
                extra={
                    "event": audit_event,
                    "function": func.__qualname__,
                    "reason": reason,
                    "user_id": user_id,
                    "request_id": request_id,
                },
            )
            return func(*args, **kwargs)

        wrapper.__wrapped__ = func
        wrapper._cross_org_reason = reason
        wrapper._cross_org_audit_event = audit_event
        return wrapper
    return decorator
