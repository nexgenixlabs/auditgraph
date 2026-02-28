"""
Phase 4A — Structured JSON Logging

Provides JSON-formatted log output for production and human-readable
format for development. Injects request_id from flask.g when available.
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Outputs structured JSON log lines for production observability."""

    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Inject request_id from Flask g if available
        try:
            from flask import g
            request_id = getattr(g, 'request_id', None)
            if request_id:
                log_entry['request_id'] = request_id
        except RuntimeError:
            pass  # Outside request context

        if record.exc_info and record.exc_info[0] is not None:
            log_entry['exception'] = self.formatException(record.exc_info)

        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)

        return json.dumps(log_entry, default=str)


def configure_logging():
    """Configure root logger based on environment.

    Production (FLASK_ENV != 'development'): JSON to stdout
    Development: human-readable format (default behavior)
    """
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Remove existing handlers to avoid duplicates
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)

    if os.getenv('FLASK_ENV') == 'development':
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s [%(name)s] %(message)s',
            datefmt='%H:%M:%S'
        )
    else:
        formatter = JSONFormatter()

    handler.setFormatter(formatter)
    root.addHandler(handler)
