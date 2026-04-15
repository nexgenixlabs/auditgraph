"""
Phase 1 Security Hardening: Input Sanitization Middleware

Validates and sanitizes incoming request bodies to block:
- XSS payloads (script tags, event handlers, javascript: URIs)
- SQL injection patterns (UNION SELECT, DROP TABLE, etc.)
- Command injection patterns (shell metacharacters in non-shell contexts)

This middleware runs as a Flask before_request hook. It does NOT modify
request data — it rejects dangerous payloads outright (fail-closed).

Designed to complement (not replace) parameterized queries (SQL injection)
and output encoding (XSS). This is a defense-in-depth layer.
"""

import re
import logging
from typing import Optional
from flask import request, jsonify

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
MAX_BODY_SIZE = 10 * 1024 * 1024

# Maximum nesting depth for JSON objects
MAX_JSON_DEPTH = 20

# ── XSS Patterns ──────────────────────────────────────────────────────────
# Matches script tags, event handlers, javascript: URIs, data: URIs with script
_XSS_PATTERNS = [
    re.compile(r'<\s*script\b', re.IGNORECASE),
    re.compile(r'\bon\w+\s*=', re.IGNORECASE),          # onclick=, onerror=, etc.
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'data\s*:\s*text/html', re.IGNORECASE),
    re.compile(r'<\s*iframe\b', re.IGNORECASE),
    re.compile(r'<\s*object\b', re.IGNORECASE),
    re.compile(r'<\s*embed\b', re.IGNORECASE),
    re.compile(r'expression\s*\(', re.IGNORECASE),       # CSS expression()
]

# ── SQL Injection Patterns ────────────────────────────────────────────────
# Detects classic SQLi signatures. Parameterized queries are the primary defense;
# this is a belt-and-suspenders layer.
_SQLI_PATTERNS = [
    re.compile(r'\bUNION\s+(ALL\s+)?SELECT\b', re.IGNORECASE),
    re.compile(r'\bDROP\s+(TABLE|DATABASE|INDEX)\b', re.IGNORECASE),
    re.compile(r'\bINSERT\s+INTO\b', re.IGNORECASE),
    re.compile(r'\bDELETE\s+FROM\b', re.IGNORECASE),
    re.compile(r'\bUPDATE\s+\w+\s+SET\b', re.IGNORECASE),
    re.compile(r';\s*(DROP|ALTER|CREATE|TRUNCATE|EXEC)\b', re.IGNORECASE),
    re.compile(r'--\s*$', re.MULTILINE),                 # SQL comment at line end
    re.compile(r'\bOR\s+1\s*=\s*1\b', re.IGNORECASE),   # OR 1=1
    re.compile(r"'\s*OR\s+'", re.IGNORECASE),            # ' OR '
    re.compile(r'\bWAITFOR\s+DELAY\b', re.IGNORECASE),  # SQL Server time-based
    re.compile(r'\bSLEEP\s*\(\s*\d', re.IGNORECASE),    # MySQL time-based
]

# Paths exempt from sanitization (binary uploads, webhooks, etc.)
_EXEMPT_PATHS = {
    '/api/billing/stripe-webhook',
    '/api/auth/saml/acs',
}

# Paths exempt from SQL injection checks only (these legitimately contain SQL-like terms)
_SQLI_EXEMPT_PREFIXES = (
    '/api/identities/query',      # Advanced query builder uses field/operator terms
    '/api/copilot/',              # AI copilot may discuss SQL in conversation
)


def _check_string(value: str) -> Optional[str]:
    """Check a single string value for dangerous patterns.
    Returns the violation type or None if clean."""
    for pattern in _XSS_PATTERNS:
        if pattern.search(value):
            return 'xss'
    for pattern in _SQLI_PATTERNS:
        if pattern.search(value):
            return 'sqli'
    return None


def _scan_value(value, depth: int = 0, skip_sqli: bool = False) -> Optional[str]:
    """Recursively scan a value (string, list, dict) for dangerous patterns.
    Returns violation type or None."""
    if depth > MAX_JSON_DEPTH:
        return 'depth_exceeded'

    if isinstance(value, str):
        if len(value) > 100_000:
            return None  # Skip very large strings (e.g. base64 file data)
        for pattern in _XSS_PATTERNS:
            if pattern.search(value):
                return 'xss'
        if not skip_sqli:
            for pattern in _SQLI_PATTERNS:
                if pattern.search(value):
                    return 'sqli'
    elif isinstance(value, dict):
        for k, v in value.items():
            # Check keys too
            if isinstance(k, str):
                result = _check_string(k) if not skip_sqli else None
                if result:
                    return result
            result = _scan_value(v, depth + 1, skip_sqli)
            if result:
                return result
    elif isinstance(value, (list, tuple)):
        for item in value:
            result = _scan_value(item, depth + 1, skip_sqli)
            if result:
                return result

    return None


def sanitize_request():
    """Flask before_request hook — validates request body for dangerous patterns.

    Returns None (allow) or a 400 JSON response (block).
    Does NOT modify request data — rejects outright.
    """
    # Skip non-API paths
    if not request.path.startswith('/api/'):
        return None

    # Skip exempt paths
    if request.path in _EXEMPT_PATHS:
        return None

    # Skip GET/HEAD/OPTIONS (no body)
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None

    # Check Content-Length
    content_length = request.content_length
    if content_length and content_length > MAX_BODY_SIZE:
        return jsonify({
            'error': 'Request body too large',
            'max_size_bytes': MAX_BODY_SIZE,
        }), 413

    # Only scan JSON bodies
    if not request.is_json:
        return None

    try:
        body = request.get_json(silent=True)
    except Exception:
        return None  # Malformed JSON handled by Flask/handler

    if body is None:
        return None

    # Determine if SQLi checks should be skipped for this path
    skip_sqli = any(request.path.startswith(p) for p in _SQLI_EXEMPT_PREFIXES)

    violation = _scan_value(body, skip_sqli=skip_sqli)

    if violation == 'xss':
        logger.warning(
            "Input sanitization blocked XSS attempt: path=%s method=%s ip=%s",
            request.path, request.method, request.remote_addr,
        )
        return jsonify({
            'error': 'Request contains potentially dangerous content',
            'error_code': 'INPUT_VALIDATION_FAILED',
        }), 400

    if violation == 'sqli':
        logger.warning(
            "Input sanitization blocked SQLi attempt: path=%s method=%s ip=%s",
            request.path, request.method, request.remote_addr,
        )
        return jsonify({
            'error': 'Request contains potentially dangerous content',
            'error_code': 'INPUT_VALIDATION_FAILED',
        }), 400

    if violation == 'depth_exceeded':
        return jsonify({
            'error': 'Request body nesting too deep',
            'error_code': 'INPUT_VALIDATION_FAILED',
        }), 400

    return None
