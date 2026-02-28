"""Route decorator for entitlement enforcement."""

import logging
from functools import wraps
from flask import g, jsonify

from app.database import Database

logger = logging.getLogger(__name__)


def require_entitlement(feature_key):
    """Decorator that gates a route behind a plan feature.

    - Superadmins bypass all gates (logged for audit trail).
    - Logs 'entitlement_blocked' to activity_log on denial.
    - Uses the entitlements engine (per-org overrides, trial expiry, plan check).
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401

            # Superadmins bypass all feature gates — log for audit trail
            if user.get('is_superadmin'):
                logger.info(
                    f"[entitlement_bypass] superadmin user_id={user.get('id')} "
                    f"bypassed gate for feature={feature_key}"
                )
                return f(*args, **kwargs)

            organization_id = user.get('organization_id')
            if not organization_id:
                return f(*args, **kwargs)  # No org context — allow

            from app.entitlements.service import is_feature_enabled
            db = Database()
            try:
                allowed, err = is_feature_enabled(db, organization_id, feature_key)
                if not allowed:
                    # Log denial
                    try:
                        cursor = db.conn.cursor()
                        cursor.execute(
                            """INSERT INTO activity_log (action, description, user_id, organization_id, metadata, created_at)
                               VALUES (%s, %s, %s, %s, %s, NOW())""",
                            ('entitlement_blocked',
                             f'Feature "{feature_key}" blocked for {err.get("current_plan", "unknown")} plan',
                             user.get('id'),
                             organization_id,
                             '{}')
                        )
                        db.conn.commit()
                        cursor.close()
                    except Exception:
                        pass
                    return jsonify(err), 403
                return f(*args, **kwargs)
            finally:
                db.close()
        return wrapper
    return decorator
