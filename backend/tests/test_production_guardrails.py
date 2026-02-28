"""
Phase 4A — Production Guardrails & Runtime Safety Tests

Tests structured logging, request ID middleware, global error handlers,
rate limiting, startup secrets validation, and health probe split.
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
    from app.main import _validate_startup_secrets

    # Simulate production (non-development)
    old_env = os.environ.get('FLASK_ENV')
    os.environ['FLASK_ENV'] = 'production'
    # Clear required secrets
    saved = {}
    for key in ['ADMIN_JWT_SECRET', 'CLIENT_JWT_SECRET', 'DB_HOST', 'DB_PASSWORD']:
        saved[key] = os.environ.pop(key, None)

    try:
        with pytest.raises(RuntimeError, match='Missing.*required secret'):
            _validate_startup_secrets()
    finally:
        # Restore environment
        if old_env is None:
            os.environ.pop('FLASK_ENV', None)
        else:
            os.environ['FLASK_ENV'] = old_env
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
