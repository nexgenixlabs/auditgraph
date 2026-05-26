"""Diagnostic API routes — internal/admin only."""

from flask import jsonify, request, g

from app.diagnostics.signal_validator import SignalValidator


def register_diagnostic_routes(app):
    """Register diagnostic endpoints on the Flask app."""

    @app.get("/api/diagnostics/signal-validation")
    def signal_validation():
        # Require admin role or superadmin
        user = getattr(g, 'current_user', None)
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        role = user.get('role', '')
        if role not in ('admin', 'owner') and not user.get('is_superadmin'):
            return jsonify({'error': 'Admin role required'}), 403

        org_id = request.args.get('org_id', type=int)
        if not org_id:
            # Fall back to authenticated user's org
            org_id = user.get('organization_id')
        if not org_id:
            return jsonify({'error': 'org_id parameter required'}), 400

        from app.api.handlers import _db
        db = _db()
        try:
            validator = SignalValidator(db.conn)
            result = validator.validate_all(org_id)
            return jsonify(result)
        finally:
            db.close()
