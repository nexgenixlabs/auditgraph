"""
Phase 3 FastAPI ↔ Flask WSGI mount (A3).

This module mounts the Phase 3 FastAPI routers (identities, resources,
snapshots) under the existing Flask WSGI stack using ``a2wsgi`` to bridge
ASGI → WSGI. It is **strictly additive**: the Flask app factory remains
the single entry point, gunicorn configuration is unchanged, and no new
process or daemon is introduced.

Dispatch strategy
-----------------
We do **not** use ``werkzeug.middleware.dispatcher.DispatcherMiddleware``.
``DispatcherMiddleware`` strips the mount prefix from ``PATH_INFO`` before
delegating, which would force the Phase 3 routers to be re-registered with
bare prefixes like ``/identities`` instead of ``/api/v1/identities``. The
A3 task rules forbid mutating the router definitions.

Instead we install :class:`Phase3Dispatcher`, a small WSGI middleware that:

1. Walks the FastAPI app's ``routes`` once at install time and caches a
   list of ``(methods, path_regex)`` tuples using Starlette's compiled
   regex patterns (``Route.path_regex``).
2. On each request, checks ``(REQUEST_METHOD, PATH_INFO)`` against the
   cached patterns.
3. If a Phase 3 route matches, delegates to the a2wsgi-wrapped FastAPI
   app — passing the full unmodified ``PATH_INFO`` so FastAPI sees the
   same ``/api/v1/identities/...`` path its routers were defined with.
4. Otherwise, falls through to the original Flask WSGI callable.

This means legacy Flask routes at ``/api/v1/...`` paths (created by
:func:`app.main._register_v1_routes`) still serve traffic for every
endpoint Phase 3 does not explicitly own. See the ``SHADOWED_ROUTES``
module-level constant for the exact set of Flask mirrors that are
shadowed by Phase 3.

Known limitation — a2wsgi + streaming
-------------------------------------
``a2wsgi.ASGIMiddleware`` does not support ASGI streaming responses or
WebSockets. A grep of ``app/api/routes/*`` at A3 install time confirmed
that **no Phase 3 route uses ``StreamingResponse`` or WebSockets**; every
handler returns a standard Pydantic response model. If a future Phase 3
handler needs streaming, it must either be served via a separate ASGI
process (uvicorn sidecar) or the mount strategy must change.

CORS
----
Flask's ``CORS(app, resources={r"/*": ...})`` runs inside Flask's request
pipeline — which the dispatcher bypasses for Phase 3 paths. We therefore
attach a ``CORSMiddleware`` directly to the FastAPI app, wired to the
same ``ALLOWED_ORIGINS`` env var Flask reads. CORS preflight (OPTIONS)
on Phase 3 paths is handled inside FastAPI.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

#: Routes where Phase 3 FastAPI takes ownership from the Flask v1 mirror
#: created by ``_register_v1_routes``. Each tuple is
#: ``(method, flask_origin_path, phase3_path)``. The set is computed by
#: a runtime audit (see the A3 report) so it is exhaustive for the
#: current Flask url_map.
#:
#: How we resolve these: the :class:`Phase3Dispatcher` delegates all
#: method+path tuples whose regex matches a Phase 3 route, so FastAPI
#: wins on the 4 literal-literal shadows below. The underlying Flask
#: handlers remain reachable at their **non-v1** paths (e.g.
#: ``/api/identities``) — client callers that still use the ``/api/``
#: prefix are unaffected.
SHADOWED_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("GET", "/api/identities",                            "/api/v1/identities"),
    ("GET", "/api/identities/<identity_id>",              "/api/v1/identities/{identity_id}"),
    ("GET", "/api/identities/<identity_id>/attack-paths", "/api/v1/identities/{identity_id}/attack-paths"),
    ("GET", "/api/snapshots",                             "/api/v1/snapshots"),
)

#: Paths where Phase 3's parameterized regex *accidentally* matches a
#: literal Flask endpoint (e.g. Phase 3 ``/snapshots/{snapshot_id}``
#: regex matches Flask's literal ``/snapshots/state``). These are NOT
#: "Phase 3 ownership" cases — the Flask endpoint is a distinct feature
#: that happens to live at a URL Phase 3's wildcard would swallow.
#:
#: :class:`Phase3Dispatcher` preserves Flask behavior on these by
#: checking a ``(method, path)`` set at dispatch time before delegating
#: any *parameterized* Phase 3 match.
PARAM_OVERLAP_FALLTHROUGH: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/snapshots/state"),
    ("GET", "/api/v1/snapshots/compare"),
)


# ---------------------------------------------------------------------------
# FastAPI app construction
#
# Built lazily on first install so tests and scripts that import this
# module without calling ``install()`` pay nothing.
# ---------------------------------------------------------------------------


_fastapi_app: Any = None
_phase3_wsgi: Optional[Callable] = None


def _build_fastapi_app() -> Any:
    """Construct the Phase 3 FastAPI app with the 3 routers + CORS.

    Uses deferred imports so this module can be imported without pulling
    FastAPI / starlette / a2wsgi into the parent process until install
    time.
    """
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    from app.api.routes.identities import router as identities_router
    from app.api.routes.posture import router as posture_router
    from app.api.routes.resources import router as resources_router
    from app.api.routes.snapshots import router as snapshots_router

    app = FastAPI(
        title="AuditGraph Phase 3 API",
        version="3.0",
        # Serve OpenAPI under the mounted prefix so it isn't shadowed by
        # Flask's own /docs or root. Keeping them under /api/v1 means they
        # only work if the dispatcher delegates — which it will, because
        # these paths are unknown to Flask and do not overlap SHADOWED_ROUTES.
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
        openapi_url="/api/v1/openapi.json",
    )

    allowed_origins: List[str] = [
        o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        # Match Flask's ALLOWED_ORIGINS list. If unset (should not happen
        # in production — Flask would already have crashed at startup),
        # fall back to a safe default.
        allow_origins=allowed_origins or ["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-Portal-Context",
            "X-Organization-Id",
            "X-API-Key",
            "Idempotency-Key",
            "X-CSRF-Token",
            "X-Tenant-ID",
            "X-Request-ID",
        ],
        expose_headers=["X-Request-ID"],
    )

    app.include_router(identities_router)
    app.include_router(resources_router)
    app.include_router(snapshots_router)
    app.include_router(posture_router)

    return app


def _build_phase3_wsgi() -> Callable:
    """Return the a2wsgi-wrapped Phase 3 FastAPI app (cached)."""
    global _fastapi_app, _phase3_wsgi
    if _phase3_wsgi is not None:
        return _phase3_wsgi

    from a2wsgi import ASGIMiddleware

    _fastapi_app = _build_fastapi_app()
    _phase3_wsgi = ASGIMiddleware(_fastapi_app)
    logger.info(
        "Phase 3 FastAPI built: %d routes wrapped by a2wsgi.ASGIMiddleware",
        sum(1 for _ in _iter_starlette_routes(_fastapi_app)),
    )
    return _phase3_wsgi


def _iter_starlette_routes(fastapi_app: Any) -> Iterable[Any]:
    """Yield all Starlette ``Route`` objects from the FastAPI app."""
    from starlette.routing import Route

    for r in fastapi_app.routes:
        if isinstance(r, Route):
            yield r


# ---------------------------------------------------------------------------
# Dispatcher middleware
# ---------------------------------------------------------------------------


class Phase3Dispatcher:
    """WSGI middleware: route (method, path) to FastAPI iff a Phase 3 route matches.

    Unlike :class:`werkzeug.middleware.dispatcher.DispatcherMiddleware` this
    **does not strip any prefix** from ``PATH_INFO``. The FastAPI routers
    are defined with full path prefixes like ``/api/v1/identities`` and
    must see the unmodified path.

    Dispatch rules
    --------------
    1. ``PATH_INFO`` not starting with ``/api/v1/`` → straight to Flask.
    2. ``(method, PATH_INFO)`` is in :data:`PARAM_OVERLAP_FALLTHROUGH`
       (literal Flask endpoint accidentally captured by a Phase 3
       wildcard) → straight to Flask.
    3. Any Phase 3 route's compiled regex matches and method is one of
       the route's declared methods (or ``OPTIONS`` for CORS preflight)
       → delegate to FastAPI via a2wsgi.
    4. Otherwise → fall through to Flask. Unknown ``/api/v1/`` paths
       Flask defined (via ``_register_v1_routes``) keep working.

    OPTIONS preflight is always delegated to FastAPI when the path
    matches a Phase 3 regex, so CORS runs through the ``CORSMiddleware``
    attached in :func:`_build_fastapi_app` with a single, consistent
    policy.
    """

    def __init__(
        self,
        flask_wsgi: Callable,
        fastapi_app: Any,
        phase3_wsgi: Callable,
    ) -> None:
        self._flask_wsgi = flask_wsgi
        self._phase3_wsgi = phase3_wsgi
        self._patterns: List[Tuple[frozenset[str], re.Pattern[str], bool]] = []

        for route in _iter_starlette_routes(fastapi_app):
            methods = frozenset((route.methods or ()))
            # ``Route.path_regex`` is a compiled regex anchored at start;
            # Starlette's ``compile_path`` appends ``$`` so ``.match``
            # behaves like ``.fullmatch`` for path equality.
            is_literal = "{" not in route.path
            self._patterns.append((methods, route.path_regex, is_literal))

        # Set form: (method, path) — O(1) fallthrough lookup on hot path.
        self._param_fallthrough: frozenset[tuple[str, str]] = frozenset(
            PARAM_OVERLAP_FALLTHROUGH
        )

        logger.info(
            "Phase3Dispatcher installed with %d FastAPI patterns "
            "(%d literal, %d parameterized) + %d accidental-overlap fallthroughs",
            len(self._patterns),
            sum(1 for _, _, lit in self._patterns if lit),
            sum(1 for _, _, lit in self._patterns if not lit),
            len(self._param_fallthrough),
        )

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")

        # Short-circuit: if the path doesn't start with /api/v1/ there is
        # definitionally no Phase 3 match. Saves a regex sweep on every
        # legacy /api/ and static request.
        if not path.startswith("/api/v1/") and path != "/api/v1":
            return self._flask_wsgi(environ, start_response)

        # Rule 2: Flask literal accidentally captured by a Phase 3 wildcard.
        if (method, path) in self._param_fallthrough:
            return self._flask_wsgi(environ, start_response)

        # Rule 3: Phase 3 pattern match.
        for methods, pattern, _is_literal in self._patterns:
            if not pattern.match(path):
                continue
            if method == "OPTIONS" or not methods or method in methods:
                return self._phase3_wsgi(environ, start_response)
            # Method mismatch — keep scanning in case another route has
            # the same path but different methods (e.g. GET + POST on
            # the same template).

        # Rule 4: fall through to Flask.
        return self._flask_wsgi(environ, start_response)


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------


def install(flask_app: Any) -> Any:
    """Mount the Phase 3 dispatcher onto ``flask_app.wsgi_app``.

    Idempotent: if :class:`Phase3Dispatcher` is already installed, the
    call is a no-op.

    Call this from :func:`app.main.create_app` after all Flask routes,
    blueprints, and middlewares are registered (in particular after
    :func:`app.main._register_v1_routes`).
    """
    if isinstance(flask_app.wsgi_app, Phase3Dispatcher):
        logger.info("Phase3Dispatcher already installed; skipping re-install")
        return flask_app

    phase3_wsgi = _build_phase3_wsgi()
    assert _fastapi_app is not None  # set by _build_phase3_wsgi

    flask_app.wsgi_app = Phase3Dispatcher(
        flask_wsgi=flask_app.wsgi_app,
        fastapi_app=_fastapi_app,
        phase3_wsgi=phase3_wsgi,
    )
    logger.info(
        "Phase 3 FastAPI mounted under Flask WSGI: %d shadowed Flask v1 mirrors",
        len(SHADOWED_ROUTES),
    )
    return flask_app


__all__ = [
    "SHADOWED_ROUTES",
    "Phase3Dispatcher",
    "install",
]
