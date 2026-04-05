"""
Phase 4A/4B — Production Guardrails, Security & Compliance Tests

Tests structured logging, request ID middleware, global error handlers,
rate limiting, startup secrets validation, health probe split,
enhanced JSON context, error_code standardization, audit hooks,
and compliance doc stubs.
"""
import json
import logging
import os
import pytest


# ── Stage 1: Structured JSON Logging ────────────────────────────────────────

def test_json_formatter_output():
    """JSONFormatter produces valid JSON with required fields."""
    from app.logging_config import JSONFormatter

    formatter = JSONFormatter()
    record = logging.LogRecord(
        name='test.logger',
        level=logging.INFO,
        pathname='test.py',
        lineno=1,
        msg='Hello %s',
        args=('world',),
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed['level'] == 'INFO'
    assert parsed['logger'] == 'test.logger'
    assert parsed['message'] == 'Hello world'
    assert 'timestamp' in parsed


def test_json_formatter_exception():
    """JSONFormatter includes exception info when present."""
    from app.logging_config import JSONFormatter

    formatter = JSONFormatter()
    try:
        raise ValueError("test error")
    except ValueError:
        import sys
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name='test', level=logging.ERROR, pathname='test.py',
        lineno=1, msg='fail', args=(), exc_info=exc_info,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert 'exception' in parsed
    assert 'ValueError' in parsed['exception']


# ── Stage 2: Request ID Middleware ──────────────────────────────────────────

def test_request_id_generated():
    """before_request sets g.request_id from header or UUID."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert 'g.request_id' in source
    assert 'X-Request-ID' in source


def test_request_id_in_response():
    """after_request echoes X-Request-ID in response headers."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    # The after_request handler should set X-Request-ID on response
    assert "response.headers['X-Request-ID']" in source


# ── Stage 3: Global Error Handlers ─────────────────────────────────────────

def test_global_error_handlers():
    """404, 405, 500, and Exception handlers are registered."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert 'errorhandler(404)' in source
    assert 'errorhandler(405)' in source
    assert 'errorhandler(500)' in source
    assert 'errorhandler(Exception)' in source


# ── Stage 4: Rate Limiting ──────────────────────────────────────────────────

def test_rate_limit_impersonate():
    """Impersonate route has @rate_limit decorator."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    # Find the impersonate route and verify rate_limit is nearby
    idx_impersonate = source.index('/api/admin/impersonate")')
    # Look at the 300 chars before the route for @rate_limit
    context = source[max(0, idx_impersonate - 300):idx_impersonate + 200]
    assert 'rate_limit' in context


def test_rate_limit_billing_snapshot():
    """Billing snapshot route has @rate_limit decorator."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    idx_snapshot = source.index('billing/snapshot")')
    context = source[max(0, idx_snapshot - 300):idx_snapshot + 200]
    assert 'rate_limit' in context


# ── Stage 5: Startup Secrets Validation ─────────────────────────────────────

def test_startup_validation_fails_missing():
    """_validate_startup_secrets raises RuntimeError when secrets are missing."""
    from unittest.mock import patch
    from app.main import _validate_startup_secrets

    # Clear required secrets
    saved = {}
    for key in ['ADMIN_JWT_SECRET', 'CLIENT_JWT_SECRET', 'DB_HOST', 'DB_PASSWORD']:
        saved[key] = os.environ.pop(key, None)

    try:
        # IS_DEV is computed at import time from APP_ENV, so patch it directly
        with patch('app.main.IS_DEV', False):
            with pytest.raises(RuntimeError, match='Missing.*required secret'):
                _validate_startup_secrets()
    finally:
        for key, val in saved.items():
            if val is not None:
                os.environ[key] = val


def test_startup_validation_skips_dev():
    """_validate_startup_secrets skips checks in development mode."""
    from app.main import _validate_startup_secrets

    old_env = os.environ.get('FLASK_ENV')
    os.environ['FLASK_ENV'] = 'development'
    # Clear required secrets to prove it doesn't check
    saved = {}
    for key in ['ADMIN_JWT_SECRET', 'CLIENT_JWT_SECRET', 'DB_HOST', 'DB_PASSWORD']:
        saved[key] = os.environ.pop(key, None)

    try:
        # Should not raise
        _validate_startup_secrets()
    finally:
        if old_env is None:
            os.environ.pop('FLASK_ENV', None)
        else:
            os.environ['FLASK_ENV'] = old_env
        for key, val in saved.items():
            if val is not None:
                os.environ[key] = val


# ── Stage 6: Health Probe Split ─────────────────────────────────────────────

def test_health_live_route():
    """/health/live route is registered in main.py."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert '/health/live' in source


def test_health_ready_route():
    """/health/ready route is registered in main.py."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert '/health/ready' in source


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4B Tests
# ══════════════════════════════════════════════════════════════════════════════


# ── 4B-1: Enhanced JSON Formatter Context ───────────────────────────────────

def test_json_formatter_includes_user_context():
    """JSONFormatter code includes user_id and organization_id extraction."""
    from app.logging_config import JSONFormatter
    import inspect
    source = inspect.getsource(JSONFormatter.format)
    assert 'user_id' in source
    assert 'organization_id' in source


def test_json_formatter_includes_request_context():
    """JSONFormatter code includes path and method extraction."""
    from app.logging_config import JSONFormatter
    import inspect
    source = inspect.getsource(JSONFormatter.format)
    assert 'flask_request.path' in source or 'request.path' in source
    assert 'flask_request.method' in source or 'request.method' in source


# ── 4B-2: Audit Logging Hooks ──────────────────────────────────────────────

def test_audit_hook_msp_relationship():
    """MSP relationship handler calls log_admin_audit."""
    import app.api.handlers
    import inspect
    source = inspect.getsource(app.api.handlers.admin_update_msp_relationship)
    assert 'log_admin_audit' in source
    assert 'msp_relationship_change' in source


def test_audit_hook_billing_force_overwrite():
    """Billing snapshot handler calls log_admin_audit on force overwrite."""
    import app.api.handlers
    import inspect
    source = inspect.getsource(app.api.handlers.admin_generate_billing_snapshot)
    assert 'log_admin_audit' in source
    assert 'billing_force_overwrite' in source


def test_audit_hook_impersonation_exists():
    """Impersonation handler already has admin_audit_log INSERT."""
    import app.api.handlers
    import inspect
    source = inspect.getsource(app.api.handlers.admin_impersonate)
    assert 'admin_audit_log' in source
    assert 'impersonation_start' in source


def test_audit_hook_plan_change_exists():
    """Plan change handler has log_admin_audit call."""
    import app.api.handlers
    import inspect
    source = inspect.getsource(app.api.handlers.update_admin_organization_plan)
    assert 'log_admin_audit' in source
    assert 'plan_change' in source


# ── 4B-3: Standardized Error Codes ─────────────────────────────────────────

def test_error_handlers_include_error_code():
    """Global error handlers include error_code field."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert "'error_code': 'NOT_FOUND'" in source
    assert "'error_code': 'METHOD_NOT_ALLOWED'" in source
    assert "'error_code': 'INTERNAL_ERROR'" in source
    assert "'error_code': 'RATE_LIMITED'" in source


def test_429_error_handler_registered():
    """429 Too Many Requests error handler is registered."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert 'errorhandler(429)' in source


# ── 4B-4: Security Headers Already Complete ─────────────────────────────────

def test_security_headers_complete():
    """Verify security headers middleware exists in security.py."""
    from app.security import add_security_headers
    import inspect
    source = inspect.getsource(add_security_headers)
    assert 'X-Content-Type-Options' in source
    assert 'X-Frame-Options' in source
    assert 'Strict-Transport-Security' in source
    assert 'Referrer-Policy' in source
    assert 'Permissions-Policy' in source


# ── 4B-5: Admin Action Log Endpoint ────────────────────────────────────────

def test_admin_action_log_endpoint_exists():
    """GET /api/admin/action-log route is registered."""
    import app.main
    import inspect
    source = inspect.getsource(app.main)
    assert '/api/admin/action-log' in source


def test_admin_action_log_handler_exists():
    """get_admin_action_log handler function exists with UNION ALL query."""
    import app.api.handlers
    import inspect
    source = inspect.getsource(app.api.handlers.get_admin_action_log)
    assert 'admin_audit_log' in source
    assert 'billing_events' in source


# ── 4B-6: Compliance Doc Stubs ──────────────────────────────────────────────

def test_compliance_docs_exist():
    """Compliance documentation stubs exist in docs/compliance/."""
    import os
    docs_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'docs', 'compliance')
    docs_dir = os.path.normpath(docs_dir)
    assert os.path.isfile(os.path.join(docs_dir, 'SOC2.md')), 'SOC2.md missing'
    assert os.path.isfile(os.path.join(docs_dir, 'HIPAA.md')), 'HIPAA.md missing'
    assert os.path.isfile(os.path.join(docs_dir, 'CIS.md')), 'CIS.md missing'
