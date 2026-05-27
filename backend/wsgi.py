"""WSGI entry point with startup proxy.

Gunicorn workers start accepting connections immediately with a minimal
stub app that responds to health probes.  The real Flask app (create_app)
is initialized in a background thread.  Once ready, all requests are
forwarded to the real app transparently.
"""
import json
import logging
import threading

logger = logging.getLogger(__name__)

# Mutable container — set by the background thread once create_app() finishes
_real_app = [None]


def _stub_app(environ, start_response):
    """Minimal WSGI app that serves health probes during startup."""
    path = environ.get('PATH_INFO', '/')

    if path in ('/health', '/health/live'):
        status = '200 OK'
        body = json.dumps({"status": "starting", "message": "App is initializing"})
    elif path in ('/health/ready', '/api/health'):
        status = '503 Service Unavailable'
        body = json.dumps({"status": "starting", "message": "App is initializing"})
    else:
        status = '503 Service Unavailable'
        body = json.dumps({"status": "starting"})

    start_response(status, [
        ('Content-Type', 'application/json'),
        ('Content-Length', str(len(body))),
    ])
    return [body.encode()]


def _boot():
    """Initialize the real Flask app in a background thread."""
    try:
        from app.main import create_app
        _real_app[0] = create_app()
        logger.info("Background startup complete — real app is ready")
    except Exception:
        logger.exception("FATAL: create_app() failed in background thread")


# Start real app initialization in background
_thread = threading.Thread(target=_boot, daemon=True, name='startup-init')
_thread.start()


class _StartupProxy:
    """WSGI middleware: stub responses during startup, real app after."""

    def __call__(self, environ, start_response):
        real = _real_app[0]
        if real is not None:
            return real(environ, start_response)
        return _stub_app(environ, start_response)


app = _StartupProxy()

if __name__ == "__main__":
    # Local dev: block until real app is ready, then run Flask dev server
    _thread.join()
    if _real_app[0]:
        _real_app[0].run(host="0.0.0.0", port=5001, debug=False, use_reloader=False)
