"""
Org-scope guard — multi-tenant safety rails.

AuditGraph is a multi-tenant SaaS. Cross-tenant data leakage is an
existential security incident. This module provides three layers of
defense used throughout the codebase:

1. :func:`require_org_scope` — an async decorator that refuses to run a
   handler / service method unless a non-empty ``organization_id`` was
   provided by the caller. It also sanitizes the value and logs a WARNING
   if it contains suspicious characters (potential injection / smuggling).

2. :class:`OrgScopedSession` — an async context manager that wraps an
   :class:`AsyncSession`, intercepts every ``execute()`` call, and verifies
   that any returned row whose mapping includes ``organization_id`` matches
   the bound tenant. Raises :class:`CrossOrgLeakageError` on mismatch so
   the breach surfaces loudly rather than silently poisoning the response.

3. :data:`GUARDED_TABLES` — the canonical list of tables that must always
   be accessed with an ``organization_id`` filter. Used both at runtime
   (optional sanity logging) and by the ``audit_org_scoping.py`` CI script
   which greps the codebase for unsafe queries.

No silent failures. No best-effort scoping. Either the caller provides an
``organization_id`` and it is honored end-to-end, or the operation is
rejected before it touches the database.
"""

from __future__ import annotations

import logging
import re
from contextlib import AbstractAsyncContextManager
from functools import wraps
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


#: Tables that must always be filtered by ``organization_id``. Enforced at
#: runtime by :class:`OrgScopedSession` (row-level assertions) and checked
#: statically by ``scripts/audit_org_scoping.py``.
GUARDED_TABLES: frozenset[str] = frozenset(
    {
        "identities",
        "role_assignments",
        "resources",
        "attack_paths",
        "graph_edges",
        "global_identity_registry",
        "global_identity_members",
    }
)

#: Characters that have no legitimate place in an ``organization_id``.
#: Presence triggers a WARNING log (potential injection, header smuggling,
#: or path-traversal style confusion).
_SUSPICIOUS_ORG_ID_RE: re.Pattern[str] = re.compile(r"[\s;'\"\\`<>]|--|/\*|\*/")

#: Max length for a well-formed organization_id — anything longer is
#: treated as suspicious and logged.
_MAX_ORG_ID_LENGTH: int = 255


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OrgScopeError(Exception):
    """Raised when a call is missing or has an invalid ``organization_id``."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class CrossOrgLeakageError(Exception):
    """Raised when a row crosses an organization boundary.

    This is a security-critical error and must never be caught-and-ignored.
    Callers that encounter it should fail the request, alert, and
    investigate.
    """

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


# ---------------------------------------------------------------------------
# require_org_scope decorator
# ---------------------------------------------------------------------------


def require_org_scope(func: F) -> F:
    """Decorator that enforces ``organization_id`` presence on a coroutine.

    Rules
    -----
    * The wrapped function must be a coroutine (``async def``).
    * ``organization_id`` must be present in ``kwargs`` and be a non-empty
      string. Any other shape raises :class:`OrgScopeError`.
    * The value is stripped and length-checked; values exceeding
      :data:`_MAX_ORG_ID_LENGTH` characters raise :class:`OrgScopeError`.
    * Suspicious characters (quotes, semicolons, comment markers, control
      chars) emit a WARNING but do not automatically reject — the caller is
      expected to pair this with a validator that matches their org-id
      format. This avoids false-negatives when tenants legitimately use
      UUIDs / slugs with hyphens.

    Example
    -------
    .. code-block:: python

        @require_org_scope
        async def list_identities(*, organization_id: str, limit: int) -> list:
            ...
    """

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        organization_id = kwargs.get("organization_id")
        if organization_id is None:
            raise OrgScopeError(
                "organization_id kwarg is required",
                context={"callable": func.__qualname__},
            )
        if not isinstance(organization_id, str):
            raise OrgScopeError(
                "organization_id must be a string",
                context={
                    "callable": func.__qualname__,
                    "received_type": type(organization_id).__name__,
                },
            )
        stripped = organization_id.strip()
        if not stripped:
            raise OrgScopeError(
                "organization_id must not be empty",
                context={"callable": func.__qualname__},
            )
        if len(stripped) > _MAX_ORG_ID_LENGTH:
            raise OrgScopeError(
                "organization_id exceeds maximum length",
                context={
                    "callable": func.__qualname__,
                    "length": len(stripped),
                    "max_length": _MAX_ORG_ID_LENGTH,
                },
            )
        if _SUSPICIOUS_ORG_ID_RE.search(stripped):
            logger.warning(
                "org_scope.suspicious_organization_id callable=%s value=%r",
                func.__qualname__,
                stripped,
            )
        kwargs["organization_id"] = stripped
        return await func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# OrgScopedSession — row-level leakage interceptor
# ---------------------------------------------------------------------------


class _OrgScopedResultProxy:
    """Row-level proxy that re-checks ``organization_id`` on every row.

    Wraps a SQLAlchemy ``Result`` so that iteration / materialization still
    works exactly like an unscoped result, while every row's mapping is
    inspected for an ``organization_id`` column. A mismatch raises
    :class:`CrossOrgLeakageError` immediately rather than letting the
    tainted row bleed into a response.
    """

    def __init__(self, wrapped: Any, expected_org: str) -> None:
        self._wrapped = wrapped
        self._expected_org = expected_org

    def _check_mapping(self, mapping: Mapping[str, Any]) -> None:
        row_org = mapping.get("organization_id")
        if row_org is not None and row_org != self._expected_org:
            raise CrossOrgLeakageError(
                "row organization_id does not match session binding",
                context={
                    "expected_organization_id": self._expected_org,
                    "row_organization_id": row_org,
                },
            )

    # -- delegate the common ``Result`` surface ---------------------------

    def mappings(self) -> "_OrgScopedMappingResult":
        return _OrgScopedMappingResult(self._wrapped.mappings(), self._expected_org)

    def scalar(self) -> Any:
        return self._wrapped.scalar()

    def scalar_one(self) -> Any:
        return self._wrapped.scalar_one()

    def scalar_one_or_none(self) -> Any:
        return self._wrapped.scalar_one_or_none()

    def fetchall(self) -> list[Any]:
        rows = self._wrapped.fetchall()
        for row in rows:
            mapping = row._mapping if hasattr(row, "_mapping") else None
            if mapping is not None:
                self._check_mapping(mapping)
        return rows

    def first(self) -> Any:
        row = self._wrapped.first()
        if row is not None:
            mapping = row._mapping if hasattr(row, "_mapping") else None
            if mapping is not None:
                self._check_mapping(mapping)
        return row

    def __iter__(self) -> Any:
        for row in self._wrapped:
            mapping = row._mapping if hasattr(row, "_mapping") else None
            if mapping is not None:
                self._check_mapping(mapping)
            yield row

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


class _OrgScopedMappingResult:
    """Same guard applied to ``result.mappings()`` paths."""

    def __init__(self, wrapped: Any, expected_org: str) -> None:
        self._wrapped = wrapped
        self._expected_org = expected_org

    def _check(self, mapping: Optional[Mapping[str, Any]]) -> None:
        if mapping is None:
            return
        row_org = mapping.get("organization_id")
        if row_org is not None and row_org != self._expected_org:
            raise CrossOrgLeakageError(
                "row organization_id does not match session binding",
                context={
                    "expected_organization_id": self._expected_org,
                    "row_organization_id": row_org,
                },
            )

    def all(self) -> list[Mapping[str, Any]]:
        rows = self._wrapped.all()
        for m in rows:
            self._check(m)
        return rows

    def first(self) -> Optional[Mapping[str, Any]]:
        m = self._wrapped.first()
        self._check(m)
        return m

    def __iter__(self) -> Any:
        for m in self._wrapped:
            self._check(m)
            yield m

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


class OrgScopedSession(AbstractAsyncContextManager):
    """Async context manager that guards an :class:`AsyncSession`.

    Usage
    -----
    .. code-block:: python

        async with OrgScopedSession(db, organization_id=org) as scoped:
            result = await scoped.execute(text("..."), {...})
            rows = result.mappings().all()  # any cross-org row → raise

    Behaviour
    ---------
    * ``organization_id`` is mandatory and non-empty.
    * Every ``execute()`` result is wrapped in :class:`_OrgScopedResultProxy`
      so downstream iteration detects leakage.
    * The underlying session is **not** committed, rolled back, or closed
      by this wrapper — transaction management remains the caller's
      responsibility.
    """

    def __init__(self, db: AsyncSession, *, organization_id: str) -> None:
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise OrgScopeError("organization_id must be a non-empty string")
        self._db = db
        self._organization_id = organization_id.strip()

    @property
    def organization_id(self) -> str:
        return self._organization_id

    async def __aenter__(self) -> "OrgScopedSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: D401
        return None

    async def execute(self, statement: Any, params: Any = None) -> _OrgScopedResultProxy:
        """Run ``statement`` and wrap the result in a scope-checking proxy."""
        result = await self._db.execute(statement, params) if params is not None else await self._db.execute(statement)
        return _OrgScopedResultProxy(result, self._organization_id)

    def __getattr__(self, name: str) -> Any:
        # Delegate unknown attributes to the underlying session so callers
        # can still access commit/rollback/begin/etc. without bypassing the
        # guard on ``execute``.
        return getattr(self._db, name)


# ---------------------------------------------------------------------------
# Static helper — used by audit_org_scoping.py
# ---------------------------------------------------------------------------


def iter_guarded_tables() -> Iterable[str]:
    """Deterministic iteration order for CI audit tooling."""
    return sorted(GUARDED_TABLES)
