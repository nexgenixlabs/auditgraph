"""
Phase 17: SCIM 2.0 Provisioning
Provides automated user provisioning/deprovisioning for enterprise IdPs
(Azure AD, Okta, etc.) via the SCIM 2.0 standard.
"""
import hashlib
import logging
import json
from datetime import datetime, timezone
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

SCIM_SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
SCIM_SCHEMA_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
SCIM_SCHEMA_PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
SCIM_SCHEMA_SP_CONFIG = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
SCIM_SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema'


def _log_scim(db, action, description, meta=None):
    """Log SCIM activity."""
    try:
        org_id = getattr(g, 'scim_org_id', None)
        cursor = db.conn.cursor()
        cursor.execute("""
            INSERT INTO activity_log (action, description, organization_id, metadata, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """, (action, description, org_id, json.dumps(meta or {})))
        db._commit()
        cursor.close()
    except Exception as e:
        logger.warning(f"Failed to log SCIM activity: {e}")


def scim_auth_required():
    """Decorator — validates SCIM bearer token, sets g.scim_org_id."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth.startswith('Bearer ') or auth.startswith('Bearer ag_'):
                return _scim_error('Unauthorized', 401)

            token = auth[7:]
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            from app.database import Database
            db = Database(_admin_reason='SCIM auth: validate token')
            try:
                org = db.find_org_by_scim_token(token_hash)
                if not org:
                    return _scim_error('Invalid SCIM token', 401)
                g.scim_org_id = org['organization_id']
                g.scim_db = db
            except Exception:
                db.close()
                return _scim_error('Authentication failed', 401)

            try:
                result = f(*args, **kwargs)
            finally:
                if hasattr(g, 'scim_db') and g.scim_db:
                    g.scim_db.close()
            return result
        return wrapper
    return decorator


def _scim_error(detail, status=400):
    """Return a SCIM-formatted error response."""
    return jsonify({
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
        'detail': detail,
        'status': status,
    }), status


def user_to_scim(user_row):
    """Convert a DB user row to SCIM 2.0 User resource."""
    return {
        'schemas': [SCIM_SCHEMA_USER],
        'id': str(user_row['id']),
        'userName': user_row.get('username', ''),
        'displayName': user_row.get('display_name', ''),
        'name': {
            'formatted': user_row.get('display_name', ''),
        },
        'emails': [{
            'value': user_row.get('email') or user_row.get('username', ''),
            'primary': True,
        }] if user_row.get('email') or user_row.get('username') else [],
        'active': user_row.get('enabled', True),
        'externalId': user_row.get('external_id', ''),
        'roles': [{
            'value': user_row.get('role', 'reader'),
            'primary': True,
        }],
        'meta': {
            'resourceType': 'User',
            'created': user_row.get('created_at', ''),
            'lastModified': user_row.get('updated_at', '') or user_row.get('created_at', ''),
        },
    }


def scim_to_user(scim_body):
    """Extract user fields from a SCIM User resource body."""
    username = scim_body.get('userName', '')
    display_name = scim_body.get('displayName', '')
    if not display_name:
        name = scim_body.get('name', {})
        display_name = name.get('formatted', '') or f"{name.get('givenName', '')} {name.get('familyName', '')}".strip()

    email = ''
    emails = scim_body.get('emails', [])
    if emails:
        primary = next((e for e in emails if e.get('primary')), emails[0])
        email = primary.get('value', '')

    active = scim_body.get('active', True)
    external_id = scim_body.get('externalId', '')

    # Extract role from SCIM roles attribute
    role = 'reader'
    roles = scim_body.get('roles', [])
    if roles:
        role = roles[0].get('value', 'reader')
    # Validate role
    valid_roles = {'owner', 'admin', 'security_admin', 'security_analyst', 'compliance', 'reader'}
    if role not in valid_roles:
        role = 'reader'

    return {
        'username': username or email,
        'display_name': display_name or username or email,
        'email': email or username,
        'active': active,
        'external_id': external_id,
        'role': role,
    }


def parse_scim_filter(filter_str):
    """Minimal SCIM filter parser for eq operator."""
    if not filter_str:
        return None
    # Support: userName eq "value" or externalId eq "value"
    import re
    m = re.match(r'(\w+)\s+eq\s+"([^"]*)"', filter_str.strip())
    if m:
        attr = m.group(1)
        val = m.group(2)
        col_map = {'userName': 'username', 'externalId': 'external_id'}
        col = col_map.get(attr)
        if col:
            return (col, val)
    return None


# ── SCIM Endpoints ──

@scim_auth_required()
def scim_list_users():
    """GET /api/scim/v2/Users — list/filter users."""
    db = g.scim_db
    org_id = g.scim_org_id

    filter_str = request.args.get('filter', '')
    start_index = int(request.args.get('startIndex', '1'))
    count = min(int(request.args.get('count', '100')), 200)

    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    from psycopg2 import sql as psql

    where_parts = [psql.SQL("organization_id = %s")]
    params = [org_id]

    parsed = parse_scim_filter(filter_str)
    if parsed:
        col, val = parsed
        where_parts.append(psql.SQL("{} = %s").format(psql.Identifier(col)))
        params.append(val)

    where_composed = psql.SQL(" AND ").join(where_parts)

    cursor.execute(psql.SQL("SELECT COUNT(*) FROM users WHERE {}").format(where_composed), params)
    total = cursor.fetchone()['count']

    offset = max(0, start_index - 1)
    cursor.execute(
        psql.SQL("SELECT * FROM users WHERE {} ORDER BY id LIMIT %s OFFSET %s").format(where_composed),
        params + [count, offset],
    )
    rows = [dict(r) for r in cursor.fetchall()]
    cursor.close()

    # Convert timestamps to strings
    for r in rows:
        for ts in ('created_at', 'updated_at', 'last_login_at'):
            if r.get(ts) and hasattr(r[ts], 'isoformat'):
                r[ts] = r[ts].isoformat()

    return jsonify({
        'schemas': [SCIM_SCHEMA_LIST],
        'totalResults': total,
        'startIndex': start_index,
        'itemsPerPage': count,
        'Resources': [user_to_scim(r) for r in rows],
    })


@scim_auth_required()
def scim_create_user():
    """POST /api/scim/v2/Users — create user via SCIM."""
    db = g.scim_db
    org_id = g.scim_org_id
    body = request.get_json(silent=True) or {}
    user_data = scim_to_user(body)

    if not user_data['username']:
        return _scim_error('userName is required', 400)

    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = %s AND organization_id = %s",
                   (user_data['username'], org_id))
    if cursor.fetchone():
        cursor.close()
        return _scim_error('User already exists', 409)

    cursor.execute("""
        INSERT INTO users (username, password_hash, display_name, role, organization_id,
                           enabled, auth_provider, external_id, email)
        VALUES (%s, '!scim-managed', %s, %s, %s, %s, 'scim', %s, %s)
        RETURNING *
    """, (user_data['username'], user_data['display_name'], user_data['role'],
          org_id, user_data['active'], user_data['external_id'], user_data['email']))
    row = dict(cursor.fetchone())
    db._commit()
    cursor.close()

    for ts in ('created_at', 'updated_at', 'last_login_at'):
        if row.get(ts) and hasattr(row[ts], 'isoformat'):
            row[ts] = row[ts].isoformat()

    _log_scim(db, 'scim_user_created', f"SCIM created user {user_data['username']}")
    return jsonify(user_to_scim(row)), 201


@scim_auth_required()
def scim_get_user(user_id):
    """GET /api/scim/v2/Users/<id> — get single user."""
    db = g.scim_db
    org_id = g.scim_org_id

    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s AND organization_id = %s", (user_id, org_id))
    row = cursor.fetchone()
    cursor.close()

    if not row:
        return _scim_error('User not found', 404)

    row = dict(row)
    for ts in ('created_at', 'updated_at', 'last_login_at'):
        if row.get(ts) and hasattr(row[ts], 'isoformat'):
            row[ts] = row[ts].isoformat()

    return jsonify(user_to_scim(row))


@scim_auth_required()
def scim_replace_user(user_id):
    """PUT /api/scim/v2/Users/<id> — full replace user."""
    db = g.scim_db
    org_id = g.scim_org_id
    body = request.get_json(silent=True) or {}
    user_data = scim_to_user(body)

    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("SELECT id FROM users WHERE id = %s AND organization_id = %s", (user_id, org_id))
    if not cursor.fetchone():
        cursor.close()
        return _scim_error('User not found', 404)

    cursor.execute("""
        UPDATE users SET username = %s, display_name = %s, role = %s,
                         enabled = %s, external_id = %s, email = %s, updated_at = NOW()
        WHERE id = %s AND organization_id = %s
        RETURNING *
    """, (user_data['username'], user_data['display_name'], user_data['role'],
          user_data['active'], user_data['external_id'], user_data['email'],
          user_id, org_id))
    row = dict(cursor.fetchone())
    db._commit()
    cursor.close()

    for ts in ('created_at', 'updated_at', 'last_login_at'):
        if row.get(ts) and hasattr(row[ts], 'isoformat'):
            row[ts] = row[ts].isoformat()

    _log_scim(db, 'scim_user_updated', f"SCIM replaced user {user_data['username']}")
    return jsonify(user_to_scim(row))


@scim_auth_required()
def scim_patch_user(user_id):
    """PATCH /api/scim/v2/Users/<id> — partial update (commonly active=false for deprovisioning)."""
    db = g.scim_db
    org_id = g.scim_org_id
    body = request.get_json(silent=True) or {}

    from psycopg2.extras import RealDictCursor
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("SELECT * FROM users WHERE id = %s AND organization_id = %s", (user_id, org_id))
    existing = cursor.fetchone()
    if not existing:
        cursor.close()
        return _scim_error('User not found', 404)

    operations = body.get('Operations', [])
    updates = {}
    for op in operations:
        op_type = op.get('op', '').lower()
        path = op.get('path', '')
        value = op.get('value')

        if op_type == 'replace':
            if path == 'active' or (not path and isinstance(value, dict) and 'active' in value):
                active = value if isinstance(value, bool) else value.get('active', True)
                updates['enabled'] = active
                if not active:
                    _log_scim(db, 'scim_user_deactivated', f"SCIM deactivated user {existing['username']}")
            elif path == 'displayName':
                updates['display_name'] = value
            elif path == 'userName':
                updates['username'] = value

    if updates:
        set_parts = [f"{k} = %s" for k in updates]
        set_parts.append("updated_at = NOW()")
        params = list(updates.values()) + [user_id, org_id]
        cursor.execute(
            f"UPDATE users SET {', '.join(set_parts)} WHERE id = %s AND organization_id = %s RETURNING *",
            params,
        )
        row = dict(cursor.fetchone())
        db._commit()
    else:
        row = dict(existing)

    cursor.close()

    for ts in ('created_at', 'updated_at', 'last_login_at'):
        if row.get(ts) and hasattr(row[ts], 'isoformat'):
            row[ts] = row[ts].isoformat()

    return jsonify(user_to_scim(row))


@scim_auth_required()
def scim_delete_user(user_id):
    """DELETE /api/scim/v2/Users/<id> — hard-delete user."""
    db = g.scim_db
    org_id = g.scim_org_id

    cursor = db.conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = %s AND organization_id = %s", (user_id, org_id))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        return _scim_error('User not found', 404)

    username = row[0]
    cursor.execute("DELETE FROM users WHERE id = %s AND organization_id = %s", (user_id, org_id))
    db._commit()
    cursor.close()

    _log_scim(db, 'scim_user_deleted', f"SCIM deleted user {username}")
    return '', 204


def scim_service_provider_config():
    """GET /api/scim/v2/ServiceProviderConfig — SCIM capabilities."""
    # No auth required — spec says this should be public
    return jsonify({
        'schemas': [SCIM_SCHEMA_SP_CONFIG],
        'documentationUri': 'https://docs.auditgraph.ai/scim',
        'patch': {'supported': True},
        'bulk': {'supported': False, 'maxOperations': 0, 'maxPayloadSize': 0},
        'filter': {'supported': True, 'maxResults': 200},
        'changePassword': {'supported': False},
        'sort': {'supported': False},
        'etag': {'supported': False},
        'authenticationSchemes': [{
            'type': 'oauthbearertoken',
            'name': 'OAuth Bearer Token',
            'description': 'Authentication using a bearer token',
        }],
    })


def scim_schemas():
    """GET /api/scim/v2/Schemas — SCIM User schema definition."""
    return jsonify({
        'schemas': [SCIM_SCHEMA_LIST],
        'totalResults': 1,
        'Resources': [{
            'schemas': [SCIM_SCHEMA_SCHEMA],
            'id': SCIM_SCHEMA_USER,
            'name': 'User',
            'description': 'User Account',
            'attributes': [
                {'name': 'userName', 'type': 'string', 'required': True, 'uniqueness': 'server'},
                {'name': 'displayName', 'type': 'string', 'required': False},
                {'name': 'emails', 'type': 'complex', 'multiValued': True, 'required': False},
                {'name': 'active', 'type': 'boolean', 'required': False},
                {'name': 'externalId', 'type': 'string', 'required': False},
                {'name': 'roles', 'type': 'complex', 'multiValued': True, 'required': False},
            ],
        }],
    })
