"""
JSON Request Validation — Schema-based validation for POST/PUT endpoints.

Uses jsonschema to validate incoming request bodies against defined schemas.
Invalid payloads are rejected with HTTP 400 and structured error messages.
"""
import logging
from functools import wraps
from flask import request, jsonify, g
from jsonschema import validate, ValidationError, Draft7Validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request Schemas — one per endpoint that accepts JSON body
# ---------------------------------------------------------------------------

LOGIN_SCHEMA = {
    'type': 'object',
    'required': ['username', 'password'],
    'properties': {
        'username': {'type': 'string', 'minLength': 1, 'maxLength': 255},
        'password': {'type': 'string', 'minLength': 1, 'maxLength': 255},
        'org_slug': {'type': 'string', 'maxLength': 255},
    },
    'additionalProperties': False,
}

REFRESH_SCHEMA = {
    'type': 'object',
    'properties': {
        'refresh_token': {'type': 'string', 'minLength': 1},
    },
    'additionalProperties': False,
}

CREATE_CONNECTION_SCHEMA = {
    'type': 'object',
    'required': ['label'],
    'properties': {
        'label': {'type': 'string', 'minLength': 1, 'maxLength': 255},
        'cloud': {'type': 'string', 'enum': ['azure', 'aws', 'gcp']},
        'azure_directory_id': {'type': 'string', 'maxLength': 100},
        'client_id': {'type': 'string', 'maxLength': 100},
        'azure_client_id': {'type': 'string', 'maxLength': 100},
        'client_secret': {'type': 'string', 'maxLength': 500},
        'connection_type': {'type': 'string', 'maxLength': 50},
        'status': {'type': 'string', 'maxLength': 20},
        'metadata': {'type': 'object'},
    },
    'additionalProperties': False,
}

TRIGGER_RUN_SCHEMA = {
    'type': 'object',
    'properties': {
        'connection_id': {'type': ['integer', 'string']},
        'scan_mode': {'type': 'string', 'maxLength': 50},
        'force': {'type': 'boolean'},
    },
    'additionalProperties': False,
}

COPILOT_CHAT_SCHEMA = {
    'type': 'object',
    'required': ['message'],
    'properties': {
        'message': {'type': 'string', 'minLength': 1, 'maxLength': 10000},
        'conversation_id': {'type': ['string', 'integer', 'null']},
        'context': {'type': 'object'},
    },
    'additionalProperties': False,
}

CREATE_USER_SCHEMA = {
    'type': 'object',
    'required': ['username', 'password', 'role'],
    'properties': {
        'username': {'type': 'string', 'minLength': 1, 'maxLength': 255},
        'password': {'type': 'string', 'minLength': 1, 'maxLength': 255},
        'role': {'type': 'string', 'enum': ['admin', 'security_admin', 'compliance', 'reader', 'auditor', 'viewer']},
        'email': {'type': 'string', 'maxLength': 255},
        'phone': {'type': 'string', 'maxLength': 50},
        'display_name': {'type': 'string', 'maxLength': 255},
        'portal_role': {'type': 'string', 'maxLength': 50},
        'is_superadmin': {'type': 'boolean'},
        'organization_id': {'type': 'integer'},
    },
    'additionalProperties': False,
}

CREATE_WEBHOOK_SCHEMA = {
    'type': 'object',
    'required': ['url'],
    'properties': {
        'url': {'type': 'string', 'format': 'uri', 'maxLength': 2048},
        'events': {'type': 'array', 'items': {'type': 'string'}},
        'secret': {'type': 'string', 'maxLength': 255},
        'active': {'type': 'boolean'},
        'name': {'type': 'string', 'maxLength': 255},
        'description': {'type': 'string', 'maxLength': 1000},
    },
    'additionalProperties': False,
}

SAVE_SETTINGS_SCHEMA = {
    'type': 'object',
    'additionalProperties': {'type': ['string', 'boolean', 'integer', 'null']},
}

CHANGE_PASSWORD_SCHEMA = {
    'type': 'object',
    'required': ['current_password', 'new_password'],
    'properties': {
        'current_password': {'type': 'string', 'minLength': 1},
        'new_password': {'type': 'string', 'minLength': 1},
    },
    'additionalProperties': False,
}

ROTATE_CREDENTIALS_SCHEMA = {
    'type': 'object',
    'properties': {
        'client_secret': {'type': 'string', 'maxLength': 500},
        'credential_expires_at': {'type': 'string', 'maxLength': 50},
    },
    'additionalProperties': False,
}


# ---------------------------------------------------------------------------
# Validation Decorator
# ---------------------------------------------------------------------------

def validate_json(schema):
    """Decorator that validates the request JSON body against a schema.

    Usage:
        @validate_json(LOGIN_SCHEMA)
        def auth_login():
            ...

    Returns 400 with structured error on validation failure.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True)
            if data is None:
                return jsonify({
                    'error': 'Request body must be valid JSON',
                    'error_code': 'INVALID_JSON',
                    'request_id': getattr(g, 'request_id', None),
                }), 400

            try:
                validate(instance=data, schema=schema)
            except ValidationError as e:
                # Extract a user-friendly error message
                path = '.'.join(str(p) for p in e.absolute_path) if e.absolute_path else '(root)'
                logger.warning(
                    "JSON validation failed: path=%s message=%s",
                    path, e.message,
                )
                return jsonify({
                    'error': f'Validation error at {path}: {e.message}',
                    'error_code': 'VALIDATION_ERROR',
                    'field': path,
                    'request_id': getattr(g, 'request_id', None),
                }), 400

            return f(*args, **kwargs)
        return wrapper
    return decorator
