"""
Idempotency Key Support — Prevents duplicate resource creation.

Clients send an `Idempotency-Key` header with a unique value (UUID recommended).
The server stores processed keys in the database and returns the cached response
if the same key is resubmitted.

Supported endpoints:
    POST /api/client/connections
    POST /api/runs/trigger

Keys expire after 24 hours to prevent unbounded growth.
"""
import json
import logging
import time
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

# Key expiry: 24 hours
KEY_TTL_SECONDS = 86400


def idempotent(f):
    """Decorator that enforces idempotency via the Idempotency-Key header.

    If the key was already processed, returns the cached response.
    If the key is new, processes the request and caches the response.
    If no key is provided, the request proceeds normally (no idempotency).
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        idem_key = request.headers.get('Idempotency-Key', '').strip()
        if not idem_key:
            return f(*args, **kwargs)

        if len(idem_key) > 255:
            return jsonify({
                'error': 'Idempotency-Key too long (max 255 chars)',
                'error_code': 'INVALID_IDEMPOTENCY_KEY',
            }), 400

        org_id = getattr(g, 'org_id', None) or 0
        endpoint = request.endpoint or request.path

        # Check if this key was already processed
        from app.database import Database
        db = Database(_admin_reason='idempotency: check key')
        try:
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT response_status, response_body
                FROM idempotency_keys
                WHERE idempotency_key = %s
                  AND organization_id = %s
                  AND endpoint = %s
                  AND created_at > NOW() - INTERVAL '24 hours'
            """, (idem_key, org_id, endpoint))
            existing = cursor.fetchone()
            cursor.close()

            if existing:
                logger.info(
                    "Idempotency key hit: key=%s endpoint=%s org=%s",
                    idem_key, endpoint, org_id,
                )
                cached_status = existing[0]
                cached_body = existing[1]
                try:
                    body = json.loads(cached_body)
                    resp = jsonify(body)
                except (json.JSONDecodeError, TypeError):
                    resp = jsonify({'cached': True, 'raw': cached_body})
                resp.status_code = cached_status
                resp.headers['X-Idempotency-Key'] = idem_key
                resp.headers['X-Idempotent-Replayed'] = 'true'
                return resp
        finally:
            db.close()

        # Execute the actual handler
        response = f(*args, **kwargs)

        # Cache the response
        try:
            if hasattr(response, '__iter__') and not hasattr(response, 'status_code'):
                # Tuple response (body, status_code)
                if isinstance(response, tuple):
                    resp_obj, status_code = response[0], response[1] if len(response) > 1 else 200
                    if hasattr(resp_obj, 'get_json'):
                        body_str = json.dumps(resp_obj.get_json())
                    else:
                        body_str = str(resp_obj)
                else:
                    body_str = str(response)
                    status_code = 200
            elif hasattr(response, 'get_json'):
                body_str = json.dumps(response.get_json())
                status_code = response.status_code
            else:
                body_str = str(response)
                status_code = 200

            db2 = Database(_admin_reason='idempotency: store key')
            try:
                cursor = db2.conn.cursor()
                cursor.execute("""
                    INSERT INTO idempotency_keys
                        (idempotency_key, organization_id, endpoint,
                         response_status, response_body)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (idempotency_key, organization_id, endpoint) DO NOTHING
                """, (idem_key, org_id, endpoint, status_code, body_str))
                db2.conn.commit()
                cursor.close()
            finally:
                db2.close()

        except Exception as e:
            logger.warning("Failed to cache idempotency key: %s", e)

        # Tag response with idempotency header
        if hasattr(response, 'headers'):
            response.headers['X-Idempotency-Key'] = idem_key

        return response

    return wrapper
