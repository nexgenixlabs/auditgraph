"""
Phase 4A/4B — Structured JSON Logging + Secret Redaction

Provides JSON-formatted log output for production and human-readable
format for development. Injects request context (request_id, user_id,
organization_id, path, method) from flask.g when available.

Secret Redaction (Phase OPS-1):
    All log output is scanned for known secret patterns and redacted
    before emission. This prevents credential leaks in container logs,
    log aggregators (ELK, Azure Monitor), and error tracking services.
"""
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Secret Redaction Filter — prevents credentials in log output
# ---------------------------------------------------------------------------

# Patterns that indicate a secret value follows (key=value, key: value, etc.)
_SECRET_KEY_PATTERNS = [
    'password', 'passwd', 'pwd',
    'secret', 'token', 'api_key', 'apikey',
    'client_secret', 'client_id',
    'db_password', 'db_admin_password',
    'jwt_secret', 'admin_jwt_secret', 'client_jwt_secret',
    'copilot_api_key', 'stripe_secret',
    'connection_string', 'conn_str',
]

# Compiled regex: matches key=value or key: value patterns
_SECRET_KV_RE = re.compile(
    r'(?i)(' + '|'.join(re.escape(k) for k in _SECRET_KEY_PATTERNS) + r')'
    r'[\s]*[=:]\s*["\']?([^\s"\',;}{)\]]+)',
)

# Bearer token pattern
_BEARER_RE = re.compile(r'Bearer\s+([A-Za-z0-9_\-\.]+)', re.IGNORECASE)

# Azure connection string pattern
_CONNSTR_RE = re.compile(
    r'(AccountKey|SharedAccessSignature|Password|pwd)=([^;]+)',
    re.IGNORECASE,
)

# ag_ API key pattern (AuditGraph API keys)
_AG_KEY_RE = re.compile(r'\bag_[0-9a-f]{32,}\b')


def redact_secrets(text):
    """Replace secret values in text with [REDACTED].

    Scans for: key=value credential patterns, Bearer tokens,
    Azure connection strings, and AuditGraph API keys.
    """
    if not isinstance(text, str):
        return text
    text = _SECRET_KV_RE.sub(r'\1=[REDACTED]', text)
    text = _BEARER_RE.sub('Bearer [REDACTED]', text)
    text = _CONNSTR_RE.sub(r'\1=[REDACTED]', text)
    text = _AG_KEY_RE.sub('[REDACTED_API_KEY]', text)
    return text


class SecretRedactionFilter(logging.Filter):
    """Logging filter that redacts secrets from log messages and args."""

    def filter(self, record):
        if record.msg and isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_secrets(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(a) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


class JSONFormatter(logging.Formatter):
    """Outputs structured JSON log lines for production observability."""

    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Inject request context from Flask g/request if available
        try:
            from flask import g, request as flask_request
            request_id = getattr(g, 'request_id', None)
            if request_id:
                log_entry['request_id'] = request_id

            # Phase 4B: Auto-attach user and org context
            current_user = getattr(g, 'current_user', None)
            if current_user and isinstance(current_user, dict):
                uid = current_user.get('id')
                if uid:
                    log_entry['user_id'] = uid
                org_id = current_user.get('organization_id')
                if org_id:
                    log_entry['organization_id'] = org_id

            # Phase 4B: Auto-attach request path and method
            try:
                log_entry['path'] = flask_request.path
                log_entry['method'] = flask_request.method
            except RuntimeError:
                pass
        except RuntimeError:
            pass  # Outside request context

        if record.exc_info and record.exc_info[0] is not None:
            log_entry['exception'] = self.formatException(record.exc_info)

        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)

        # Final redaction pass on the entire JSON payload
        raw = json.dumps(log_entry, default=str)
        return redact_secrets(raw)


def configure_logging():
    """Configure root logger based on environment.

    Production (FLASK_ENV != 'development'): JSON to stdout + secret redaction
    Development: human-readable format + secret redaction
    """
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Remove existing handlers to avoid duplicates
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)

    # Secret redaction filter — applied in ALL environments
    handler.addFilter(SecretRedactionFilter())

    if os.getenv('FLASK_ENV') == 'development':
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s [%(name)s] %(message)s',
            datefmt='%H:%M:%S'
        )
    else:
        formatter = JSONFormatter()

    handler.setFormatter(formatter)
    root.addHandler(handler)
