"""
FastAPI dependency layer for Phase 3 async routes.

This module is **additive** infrastructure that lives alongside the legacy
Flask + synchronous psycopg2 stack. Nothing in here mutates Flask's app
object, Blueprint registry, SQLAlchemy ``Base``, or the sync session
factory. Importing this module has no effect on Flask request handling.

Exports
-------
``CurrentUser``
    Frozen dataclass projection of the JWT principal. ``organization_id``
    is always a non-empty ``str`` — this is where blocker #5 (org_id
    int→str normalization) is resolved, at the router boundary, so the
    Phase 3 engines downstream never see an ``int``.

``get_async_db`` / ``get_db``
    FastAPI dependency that yields a
    :class:`sqlalchemy.ext.asyncio.AsyncSession`. The session is closed
    in a ``finally`` block so exceptions during request handling never
    leak a connection. ``get_db`` is a compatibility alias because the
    existing Phase 3 route files already do ``from app.api.deps import
    get_db``; re-pointing them to ``get_async_db`` is out of scope for
    A2.

``get_current_user``
    FastAPI dependency that validates a Bearer JWT using the same
    secrets as the Flask auth middleware (read from env — we avoid
    importing ``app.api.auth`` so this module does not drag in Flask).

``get_current_user_org_id``
    Thin dependency returning ``CurrentUser.organization_id`` as ``str``.
    The Phase 3 spec names this dependency explicitly as the blocker #5
    resolution point.

Circular-dependency notes
-------------------------
This module imports only from:

* standard library
* ``jwt``, ``fastapi``, ``sqlalchemy``
* ``app.config`` (pure env reader — no Flask, no DB)

It deliberately does **not** import from ``app.api.auth``,
``app.database``, ``app.main``, or any FastAPI route module. Any Phase 3
route file is free to ``from app.api.deps import ...`` without risk of
an import cycle.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import (
    DB_HOST,
    DB_NAME,
    DB_PASSWORD,
    DB_POOL_MAX,
    DB_POOL_MIN,
    DB_PORT,
    DB_SSLMODE,
    DB_USER,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JWT constants
#
# We duplicate (not import) ``ADMIN_JWT_SECRET`` / ``CLIENT_JWT_SECRET`` /
# ``JWT_ALGORITHM`` / ``TOKEN_SCHEMA_VERSION`` from ``app.api.auth`` on
# purpose: importing ``app.api.auth`` would pull Flask + Database into
# the FastAPI boundary and hard-fail at import time if the Flask env
# vars are missing. Duplicating 4 constants is cheaper than that
# coupling. The resolution rules match ``app.api.auth`` exactly:
#
# * ``ADMIN_JWT_SECRET`` / ``CLIENT_JWT_SECRET`` env vars are preferred.
# * In dev (``APP_ENV in {local, dev}`` or ``FLASK_ENV == development``)
#   we fall back to ``JWT_SECRET`` so a single-key dev setup still works.
# * ``TOKEN_SCHEMA_VERSION`` is pinned at 1 and must match the Flask
#   middleware; bump both in lock-step on any schema change.
# ---------------------------------------------------------------------------

_IS_DEV: bool = (
    os.getenv("APP_ENV", "local") in ("local", "dev")
    or os.getenv("FLASK_ENV") == "development"
)
_JWT_FALLBACK: Optional[str] = os.getenv("JWT_SECRET") if _IS_DEV else None

ADMIN_JWT_SECRET: Optional[str] = os.getenv("ADMIN_JWT_SECRET") or _JWT_FALLBACK
CLIENT_JWT_SECRET: Optional[str] = os.getenv("CLIENT_JWT_SECRET") or _JWT_FALLBACK

JWT_ALGORITHM: str = "HS256"
TOKEN_SCHEMA_VERSION: int = 1

#: Logical audience strings accepted by Phase 3 routes. Flask picks one
#: based on host; the FastAPI boundary accepts either and lets downstream
#: tenant-binding guards (e.g. ``_current_org_id``) enforce scope.
_ACCEPTED_AUDIENCES: tuple[str, ...] = (
    "auditgraph-tenant",
    "auditgraph-platform",
)


# ---------------------------------------------------------------------------
# Async engine / session factory
#
# SQLAlchemy's ``URL.create`` handles passwords containing ``@``, ``/``,
# and other URL-unsafe characters correctly, so we never hand-build the
# connection string. ``asyncpg`` ignores libpq-style ``sslmode``, so we
# translate ``DB_SSLMODE`` into ``connect_args={"ssl": bool}``.
# ---------------------------------------------------------------------------


def _build_async_url() -> URL:
    """Return the SQLAlchemy URL for the async engine.

    Reuses the same ``DB_*`` constants as the sync Flask stack — there
    is exactly one source of truth for the Postgres target.
    """
    return URL.create(
        drivername="postgresql+asyncpg",
        username=DB_USER or None,
        password=DB_PASSWORD or None,
        host=DB_HOST or None,
        port=int(DB_PORT) if DB_PORT else None,
        database=DB_NAME or None,
    )


def _async_connect_args() -> dict[str, Any]:
    """Translate ``DB_SSLMODE`` into asyncpg ``connect_args``."""
    args: dict[str, Any] = {}
    mode = (DB_SSLMODE or "").strip().lower()
    if mode in ("require", "verify-ca", "verify-full"):
        args["ssl"] = True
    elif mode in ("disable", "allow"):
        args["ssl"] = False
    # "prefer" and unset fall through → asyncpg default (no ssl)
    return args


_async_engine: AsyncEngine = create_async_engine(
    _build_async_url(),
    connect_args=_async_connect_args(),
    pool_pre_ping=True,
    pool_size=max(int(DB_POOL_MIN), 1),
    max_overflow=max(int(DB_POOL_MAX) - int(DB_POOL_MIN), 0),
    future=True,
)

_async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=_async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_async_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a SQLAlchemy ``AsyncSession``.

    No transaction is started here — routes or engines open their own
    ``session.begin()`` when they need one. The ``finally`` guarantees
    the session (and its underlying connection) is returned to the pool
    even when the request handler raises.
    """
    session: AsyncSession = _async_session_factory()
    try:
        yield session
    finally:
        await session.close()


#: Compatibility alias. Existing Phase 3 route files already import
#: ``get_db`` (see ``app/api/routes/{identities,resources,snapshots}.py``).
#: Re-pointing them to ``get_async_db`` is out of scope for A2 and would
#: bloat the diff; keep the alias forever as part of the public API.
get_db = get_async_db


# ---------------------------------------------------------------------------
# Current user
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CurrentUser:
    """Minimal principal projection for Phase 3 FastAPI routes.

    Only the fields actually consumed by Phase 3 handlers are exposed.
    Additional JWT claims (impersonation, portal_role, etc.) are
    intentionally dropped — if a route needs them it should add them
    here, not reach into the raw payload.

    ``organization_id`` is always a **non-empty ``str``**. The
    :func:`get_current_user` dependency guarantees this post-condition
    and :func:`get_current_user_org_id` re-asserts it defensively.
    """

    user_id: int
    username: str
    role: str
    organization_id: str
    is_superadmin: bool = False
    portal: str = "client"


_bearer_scheme = HTTPBearer(auto_error=False)


def _decode_jwt(token: str) -> dict[str, Any]:
    """Decode a JWT using either portal secret + any accepted audience.

    Tries ``ADMIN_JWT_SECRET`` first, then ``CLIENT_JWT_SECRET``. Raises
    ``jwt.InvalidTokenError`` (or a subclass) on final failure so the
    caller can map it to a 401.
    """
    last_err: Optional[Exception] = None
    for secret in (ADMIN_JWT_SECRET, CLIENT_JWT_SECRET):
        if not secret:
            continue
        for aud in _ACCEPTED_AUDIENCES:
            try:
                return jwt.decode(
                    token,
                    secret,
                    algorithms=[JWT_ALGORITHM],
                    audience=aud,
                )
            except jwt.ExpiredSignatureError:
                # Don't try other secrets / auds — signed-but-expired
                # is a definitive failure mode.
                raise
            except jwt.InvalidAudienceError as exc:
                last_err = exc
                continue
            except jwt.InvalidSignatureError as exc:
                # Wrong secret; stop trying auds with this secret and
                # fall through to the next secret in the outer loop.
                last_err = exc
                break
            except jwt.InvalidTokenError as exc:
                last_err = exc
                continue
    if last_err is not None:
        raise last_err
    raise jwt.InvalidTokenError("No JWT secret is configured")


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> CurrentUser:
    """FastAPI dependency that validates the Bearer JWT.

    * 401 on missing, malformed, expired, or unsigned token.
    * 401 on ``type != "access"`` or ``ver != TOKEN_SCHEMA_VERSION``.
    * 403 on a valid token that carries no ``org_id`` / ``tenant_id``
      claim — Phase 3 engines refuse to run without a tenant binding.

    Phase S1 cookie fallback
    ------------------------
    When no ``Authorization: Bearer`` header is present, falls back to
    reading the JWT from httpOnly cookies (``ag_client_access`` /
    ``ag_admin_access``), matching Flask's auth middleware behaviour.
    Mutating methods (POST/PUT/DELETE/PATCH) require a valid CSRF
    double-submit token when using cookie auth.

    Returns
    -------
    CurrentUser
        ``organization_id`` is guaranteed to be a non-empty ``str``,
        even if the JWT carried an ``int`` claim.
    """
    token: Optional[str] = None

    if credentials is not None and credentials.credentials:
        token = credentials.credentials
    else:
        # Phase S1 cookie fallback — mirrors Flask auth.py line ~358
        for portal in ("client", "admin"):
            cookie_name = f"ag_{portal}_access"
            cookie_token = request.cookies.get(cookie_name)
            if cookie_token:
                token = cookie_token
                # CSRF double-submit validation for mutating methods
                if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                    csrf_header = request.headers.get("X-CSRF-Token", "")
                    csrf_cookie = request.cookies.get("csrf_token", "")
                    if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="CSRF token mismatch",
                        )
                break

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = _decode_jwt(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    if payload.get("ver") != TOKEN_SCHEMA_VERSION:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported token version",
        )

    # Phase 2C compat: prefer ``org_id``, fall back to legacy ``tenant_id``.
    raw_org = payload.get("org_id")
    if raw_org is None:
        raw_org = payload.get("tenant_id")
    if raw_org is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has no organization binding",
        )

    # Blocker #5 resolution: the Flask middleware stores org_id as int
    # (see auth.py line ~433 and ~463). Engines want str. Normalize here.
    org_str = str(raw_org).strip()
    if not org_str:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has empty organization binding",
        )

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has no subject",
        )

    return CurrentUser(
        user_id=user_id,
        username=str(payload.get("username") or ""),
        role=str(payload.get("role") or "viewer"),
        organization_id=org_str,
        is_superadmin=bool(payload.get("is_superadmin", False)),
        portal=str(payload.get("portal") or "client"),
    )


async def get_current_user_org_id(
    current_user: CurrentUser = Depends(get_current_user),
) -> str:
    """FastAPI dependency returning ``organization_id`` as ``str``.

    This is the canonical boundary where blocker #5 is resolved: the
    JWT may carry an ``int`` (Flask tokens do), but Phase 3 engines
    expect ``str``. Normalization happens exactly once here, and every
    downstream caller can rely on the type.

    Post-condition
    --------------
    Returns a non-empty ``str``. The assertion below is defense in
    depth — :class:`CurrentUser` construction already guarantees it,
    but tests that monkey-patch :func:`get_current_user` with a custom
    principal factory get an immediate AssertionError if they violate
    the contract.
    """
    org = current_user.organization_id
    assert isinstance(org, str) and org, (
        "get_current_user_org_id post-condition violated: expected "
        f"non-empty str, got {type(org).__name__}={org!r}"
    )
    return org


__all__ = [
    "CurrentUser",
    "get_async_db",
    "get_db",
    "get_current_user",
    "get_current_user_org_id",
]
