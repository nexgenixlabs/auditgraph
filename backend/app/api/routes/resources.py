"""
Phase 1 REST API — Resource routes.

AuditGraph's G1 patch promoted cloud resources from raw path strings to
typed, tenant-scoped graph nodes. These routes expose the ``resources``
table through three endpoints — list, detail (+ identities with access),
and reverse lookup (which identities can reach this resource).

All routes are tenant-scoped by construction: ``organization_id`` is
drawn from :func:`get_current_user` and is never accepted from a URL,
query, or body. The only knob a caller has is *filtering* inside their
own organization.

Error mapping
-------------
* 403 :class:`OrgScopeError`         — missing / invalid org binding
* 404 :class:`ResourceNotFoundError` — resource does not exist for the org
* 422 Pydantic validation            — handled by FastAPI
* 500 :class:`SQLAlchemyError`       — wrapped DB failure with request_id
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Generic, Optional, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db  # type: ignore[import-not-found]
from app.middleware.org_scope_guard import CrossOrgLeakageError, OrgScopeError
from app.schemas.identity import (
    CloudProvider,
    DataContext,
    DataMode,
    GovernanceClassification,
    IdentityType,
    LifecycleState,
    PrivilegeLevel,
    Resource,
    ResourceType,
    RiskLabel,
    SensitivityLevel,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/resources", tags=["resources"])


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------


MAX_PAGE_LIMIT: int = 200
DEFAULT_PAGE_LIMIT: int = 50


# ---------------------------------------------------------------------------
# DTO envelopes — mirrored locally so resources.py has no cross-route deps
# ---------------------------------------------------------------------------


T = TypeVar("T")


class DataContextDTO(BaseModel):
    """Pydantic projection of the frozen :class:`DataContext` dataclass.

    Kept locally so :class:`PaginatedResponse` can declare a Pydantic-
    native field without importing from ``identities.py``.
    """

    data_mode: DataMode
    snapshot_id: Optional[int] = None
    snapshot_date: Optional[datetime] = None
    computed_at: datetime
    is_stale: bool = False

    @classmethod
    def from_context(cls, ctx: DataContext) -> "DataContextDTO":
        return cls(
            data_mode=ctx.data_mode,
            snapshot_id=ctx.snapshot_id,
            snapshot_date=ctx.snapshot_date,
            computed_at=ctx.computed_at,
            is_stale=bool(ctx.is_stale),
        )


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated envelope — every list response carries a context."""

    items: list[T]
    total: int
    offset: int
    limit: int
    data_context: DataContextDTO


class IdentityListRowDTO(BaseModel):
    """Flattened identity row for reverse-lookup responses.

    Mirrors the frontend ``IdentityListRow`` interface one-for-one — kept
    independent of the ``identities`` route module so resources.py stays
    self-contained.
    """

    identity_id: str
    global_identity_id: str
    organization_id: str
    display_name: str
    identity_type: IdentityType
    cloud_provider: CloudProvider
    risk_label: RiskLabel
    risk_score: float
    governance: GovernanceClassification
    lifecycle_state: LifecycleState
    is_dormant: bool
    privilege_level: PrivilegeLevel
    last_seen: Optional[datetime] = None
    data_context: DataContextDTO


class ResourceDetailResponse(BaseModel):
    """Detail envelope for ``GET /api/v1/resources/{resource_id}``."""

    resource: Resource
    identities: list[IdentityListRowDTO]
    total_identities: int
    data_context: DataContextDTO


# ---------------------------------------------------------------------------
# Error envelope helpers
# ---------------------------------------------------------------------------


def _error_body(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"error": code, "detail": detail}
    body.update(extra)
    return body


def _request_id(request: Request) -> str:
    rid = request.headers.get("X-Request-Id")
    return rid or str(uuid.uuid4())


def _raise_not_found(resource_id: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error_body(
            "resource_not_found",
            f"resource '{resource_id}' not found for this organization",
        ),
    )


def _raise_org_scope(reason: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_error_body("org_scope_error", reason),
    )


def _raise_internal(request: Request, exc: Exception) -> None:
    rid = _request_id(request)
    logger.exception("resource_route.internal request_id=%s err=%s", rid, exc)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body(
            "internal_error",
            "an internal error occurred — see server logs",
            request_id=rid,
        ),
    )


def _raise_validation(detail: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=_error_body("validation_error", detail),
    )


def _org_id_as_int(organization_id: str) -> int:
    """Coerce the str JWT org claim to int for INTEGER-typed DB columns.

    ``resources.organization_id`` (migration 086), ``identity_list`` /
    ``snapshots`` / ``role_assignments`` are all INTEGER. asyncpg refuses
    to silently coerce str→int, so the handler must cast once at entry.
    A non-integer claim is treated as a scope error — a well-formed
    token from our issuer always has a numeric org id.
    """
    try:
        return int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover — satisfies type checker


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


async def _current_org_id(current_user: Any = Depends(get_current_user)) -> str:
    """Extract ``organization_id`` from the authenticated principal only.

    We never fall back to a URL path, query string, or request body for
    the tenant id — that is the whole point of tenant isolation.
    """
    org_id = getattr(current_user, "organization_id", None)
    if not isinstance(org_id, str) or not org_id.strip():
        _raise_org_scope("authenticated user has no organization binding")
    return org_id.strip()


def _live_context() -> DataContextDTO:
    """Fresh live data context — every response carries one."""
    return DataContextDTO(
        data_mode=DataMode.LIVE,
        snapshot_id=None,
        snapshot_date=None,
        computed_at=datetime.now(timezone.utc),
        is_stale=False,
    )


# ---------------------------------------------------------------------------
# Row → model projection
# ---------------------------------------------------------------------------


def _row_to_resource(row: Any, organization_id: str) -> Resource:
    """Map a ``resources`` table row onto the canonical :class:`Resource`.

    Note the intentional column → field remapping: the DB uses ``cloud_id``
    for the provider-native path while the Pydantic model uses ``cloud_id``
    for the :class:`CloudProvider` enum. We reconcile that here so routes
    stay consistent with the schema contract.
    """
    # DB returns INTEGER org, JWT binding is str — compare as str so the
    # tripwire never false-positives on a pure type mismatch.
    if str(row.get("organization_id")) != str(organization_id):
        # Defense-in-depth scope leak tripwire.
        logger.error(
            "resource_list.scope_leak expected=%s row=%s",
            organization_id,
            row.get("organization_id"),
        )
        _raise_org_scope("row organization_id mismatch")

    gid_raw = row.get("global_identity_id")
    if gid_raw is None:
        # The Pydantic Resource requires a global_identity_id. Resources
        # that have not yet been correlated get a deterministic UUID
        # derived from (organization_id, cloud_provider, cloud_id) so
        # the response is stable across calls without leaking state.
        gid = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{organization_id}|{row['cloud_provider']}|{row['cloud_id']}",
        )
    elif isinstance(gid_raw, uuid.UUID):
        gid = gid_raw
    else:
        gid = uuid.UUID(str(gid_raw))

    return Resource(
        organization_id=str(row["organization_id"]),
        id=str(row["cloud_id"]),
        global_identity_id=gid,
        cloud_id=CloudProvider(row["cloud_provider"]),
        type=ResourceType(row["type"]),
        name=row["name"],
        sensitivity=SensitivityLevel(row["sensitivity"]),
    )


def _row_to_identity_dto(
    row: Any,
    organization_id: str,
    data_context: DataContextDTO,
) -> IdentityListRowDTO:
    """Map an identity_list row to :class:`IdentityListRowDTO`."""
    # DB returns INTEGER org, JWT binding is str — compare as str.
    if str(row.get("organization_id")) != str(organization_id):
        logger.error(
            "resource_identities.scope_leak expected=%s row=%s",
            organization_id,
            row.get("organization_id"),
        )
        _raise_org_scope("row organization_id mismatch")

    return IdentityListRowDTO(
        identity_id=row["identity_id"],
        global_identity_id=str(row["global_identity_id"]),
        organization_id=str(row["organization_id"]),
        display_name=row["display_name"],
        identity_type=IdentityType(row["identity_type"]),
        cloud_provider=CloudProvider(row["cloud_provider"]),
        risk_label=RiskLabel(row["risk_label"]),
        risk_score=float(row["risk_score"] or 0.0),
        governance=GovernanceClassification(row["governance"]),
        lifecycle_state=LifecycleState(row["lifecycle_state"]),
        is_dormant=bool(row["is_dormant"]),
        privilege_level=PrivilegeLevel(row["privilege_level"]),
        last_seen=row.get("last_seen"),
        data_context=data_context,
    )


# ---------------------------------------------------------------------------
# Shared SQL — reverse-lookup of identities with access to a resource
# ---------------------------------------------------------------------------


#: SQL fragment joining ``identity_list`` to ``role_assignments`` via scope
#: containment. A role assignment whose ``scope`` is a prefix of the target
#: resource's ``cloud_id`` grants access to that resource (RBAC inheritance).
#:
#: The query is purposefully left as a ``text()`` template so each call site
#: can splice the correct WHERE clause. Every caller MUST filter on
#: ``organization_id`` — the CI auditor will fail the build otherwise.
_IDENTITIES_FOR_RESOURCE_SQL = """
    SELECT DISTINCT
        il.identity_id,
        il.global_identity_id,
        il.organization_id,
        il.display_name,
        il.identity_type,
        il.cloud_provider,
        il.risk_label,
        il.risk_score,
        il.governance,
        il.lifecycle_state,
        il.is_dormant,
        il.privilege_level,
        il.last_seen
    FROM identity_list il
    JOIN role_assignments ra
      ON ra.identity_id = il.identity_id
     AND ra.organization_id = il.organization_id
    WHERE il.organization_id = :org
      AND ra.organization_id = :org
      AND (
          ra.scope = :cloud_id
          OR :cloud_id LIKE ra.scope || '/%'
      )
    ORDER BY il.risk_score DESC, il.display_name ASC
    LIMIT :limit OFFSET :offset
"""


# ---------------------------------------------------------------------------
# GET /api/v1/resources
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=PaginatedResponse[Resource],
    summary="List resources",
    description=(
        "Paginated list of typed resources for the authenticated "
        "organization. Supports filtering by resource type, sensitivity, "
        "and cloud provider. Always scoped to ``current_user."
        "organization_id``."
    ),
)
async def list_resources(
    request: Request,
    type: Optional[ResourceType] = Query(None, alias="type"),
    sensitivity: Optional[SensitivityLevel] = Query(None),
    cloud_provider: Optional[CloudProvider] = Query(None),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[Resource]:
    # resources.organization_id is INTEGER per migration 086; asyncpg
    # does not coerce str→int silently, so the binding must be int.
    org_int = _org_id_as_int(organization_id)
    filters: list[str] = ["organization_id = :org"]
    params: dict[str, Any] = {
        "org": org_int,
        "limit": limit,
        "offset": offset,
    }

    if type is not None:
        filters.append("type = :type")
        params["type"] = type.value
    if sensitivity is not None:
        filters.append("sensitivity = :sensitivity")
        params["sensitivity"] = sensitivity.value
    if cloud_provider is not None:
        filters.append("cloud_provider = :cloud_provider")
        params["cloud_provider"] = cloud_provider.value

    where_sql = " AND ".join(filters)

    try:
        total_result = await db.execute(
            text(f"SELECT COUNT(*) FROM resources WHERE {where_sql}"),
            params,
        )
        total = int(total_result.scalar() or 0)

        result = await db.execute(
            text(
                f"""
                SELECT id, organization_id, cloud_id, cloud_provider, type,
                       name, sensitivity, global_identity_id, resource_group,
                       subscription_id, discovered_at, last_seen
                FROM resources
                WHERE {where_sql}
                ORDER BY
                    CASE sensitivity
                        WHEN 'Critical' THEN 0
                        WHEN 'High'     THEN 1
                        WHEN 'Medium'   THEN 2
                        WHEN 'Low'      THEN 3
                        ELSE 4
                    END,
                    name ASC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
        rows = result.mappings().all()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    data_context = _live_context()
    items = [_row_to_resource(row, organization_id) for row in rows]

    return PaginatedResponse[Resource](
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        data_context=data_context,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/resources/{resource_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{resource_id}",
    response_model=ResourceDetailResponse,
    summary="Get resource detail + identities with access",
    description=(
        "Return the full :class:`Resource` plus every identity that can "
        "reach it via an RBAC role assignment scope. Powers the CISO "
        "blast-radius drill-down. ``resource_id`` is the resources table "
        "surrogate primary key (not the provider-native path)."
    ),
)
async def get_resource(
    request: Request,
    resource_id: str = Path(..., min_length=1, max_length=500),
    identity_limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    identity_offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ResourceDetailResponse:
    org_int = _org_id_as_int(organization_id)
    try:
        resource_result = await db.execute(
            text(
                """
                SELECT id, organization_id, cloud_id, cloud_provider, type,
                       name, sensitivity, global_identity_id, resource_group,
                       subscription_id, discovered_at, last_seen
                FROM resources
                WHERE organization_id = :org
                  AND id = :resource_id
                """
            ),
            {"org": org_int, "resource_id": resource_id},
        )
        resource_row = resource_result.mappings().first()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    if resource_row is None:
        _raise_not_found(resource_id)
        raise  # pragma: no cover

    resource = _row_to_resource(resource_row, organization_id)

    # Reverse lookup — identities with access to this resource.
    try:
        identities_result = await db.execute(
            text(_IDENTITIES_FOR_RESOURCE_SQL),
            {
                "org": org_int,
                "cloud_id": resource_row["cloud_id"],
                "limit": identity_limit,
                "offset": identity_offset,
            },
        )
        identity_rows = identities_result.mappings().all()

        total_result = await db.execute(
            text(
                """
                SELECT COUNT(DISTINCT il.identity_id)
                FROM identity_list il
                JOIN role_assignments ra
                  ON ra.identity_id = il.identity_id
                 AND ra.organization_id = il.organization_id
                WHERE il.organization_id = :org
                  AND ra.organization_id = :org
                  AND (
                      ra.scope = :cloud_id
                      OR :cloud_id LIKE ra.scope || '/%'
                  )
                """
            ),
            {
                "org": org_int,
                "cloud_id": resource_row["cloud_id"],
            },
        )
        total_identities = int(total_result.scalar() or 0)
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    data_context = _live_context()
    identities = [
        _row_to_identity_dto(row, organization_id, data_context)
        for row in identity_rows
    ]

    return ResourceDetailResponse(
        resource=resource,
        identities=identities,
        total_identities=total_identities,
        data_context=data_context,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/resources/{resource_id}/identities
# ---------------------------------------------------------------------------


@router.get(
    "/{resource_id}/identities",
    response_model=PaginatedResponse[IdentityListRowDTO],
    summary="List identities that can access a resource",
    description=(
        "Reverse blast-radius lookup: return every identity in the "
        "caller's organization that can reach the given resource via an "
        "RBAC role assignment whose scope contains the resource. "
        "This is the ``who can reach this resource?`` query powering the "
        "CISO blast-radius surface."
    ),
)
async def list_identities_for_resource(
    request: Request,
    resource_id: str = Path(..., min_length=1, max_length=500),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[IdentityListRowDTO]:
    org_int = _org_id_as_int(organization_id)
    # Resolve the resource first — prevents leaking existence of other
    # tenants' ids via the access list.
    try:
        resource_result = await db.execute(
            text(
                """
                SELECT cloud_id
                FROM resources
                WHERE organization_id = :org
                  AND id = :resource_id
                """
            ),
            {"org": org_int, "resource_id": resource_id},
        )
        resource_row = resource_result.mappings().first()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    if resource_row is None:
        _raise_not_found(resource_id)
        raise  # pragma: no cover

    cloud_id = resource_row["cloud_id"]

    try:
        identities_result = await db.execute(
            text(_IDENTITIES_FOR_RESOURCE_SQL),
            {
                "org": org_int,
                "cloud_id": cloud_id,
                "limit": limit,
                "offset": offset,
            },
        )
        identity_rows = identities_result.mappings().all()

        total_result = await db.execute(
            text(
                """
                SELECT COUNT(DISTINCT il.identity_id)
                FROM identity_list il
                JOIN role_assignments ra
                  ON ra.identity_id = il.identity_id
                 AND ra.organization_id = il.organization_id
                WHERE il.organization_id = :org
                  AND ra.organization_id = :org
                  AND (
                      ra.scope = :cloud_id
                      OR :cloud_id LIKE ra.scope || '/%'
                  )
                """
            ),
            {"org": org_int, "cloud_id": cloud_id},
        )
        total = int(total_result.scalar() or 0)
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover
    except (OrgScopeError, CrossOrgLeakageError) as exc:
        _raise_org_scope(str(exc))
        raise  # pragma: no cover

    data_context = _live_context()
    items = [
        _row_to_identity_dto(row, organization_id, data_context)
        for row in identity_rows
    ]

    return PaginatedResponse[IdentityListRowDTO](
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        data_context=data_context,
    )
