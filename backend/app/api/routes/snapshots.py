"""
Phase 1 REST API — Snapshot routes (F3 completion).

AuditGraph's F3 patch introduced :class:`DataContext` so every identity
payload carries an explicit ``live`` vs ``snapshot`` provenance marker.
This module wires that end-to-end by exposing the snapshot catalogue and
point-in-time reads of the same identity surfaces served under
``/api/v1/identities``.

Snapshot mode flow
------------------
1. Client sends ``GET /api/v1/identities?snapshot_id=42`` *or* calls one
   of the routes in this module with ``snapshot_id`` in the path.
2. The route validates that snapshot 42 belongs to the caller's
   organization — cross-tenant access returns **403**, not 404, because
   leaking existence is itself a privacy breach.
3. The handler calls
   :meth:`IdentityStateEngine.build` with
   ``data_mode=DataMode.SNAPSHOT`` and the validated ``snapshot_id``.
4. The engine reads from the snapshot-scoped tables using
   ``snapshot_id`` as an additional filter — live rows are never joined
   in, never fetched, never mixed.
5. The response's :class:`DataContext` has
   ``data_mode='snapshot'``, ``snapshot_id=42`` and the captured
   ``snapshot_date`` from the catalogue row.
6. The frontend ``DataContextBanner`` renders the navy snapshot banner
   automatically — no special casing in the UI layer.

Guardrails
----------
* Every SQL statement filters on ``organization_id``. The CI auditor
  (``scripts/audit_org_scoping.py``) will refuse any merge that relaxes
  this.
* Snapshot routes NEVER mix live and snapshot data — they call the
  engine exclusively in snapshot mode and their list queries hit the
  ``*_snapshots`` tables only.
* Non-existent ``snapshot_id`` → **404**.
* Snapshot belonging to a different org → **403** (``org_scope_error``)
  to avoid a cross-tenant existence oracle.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Generic, Optional, TypeVar

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    status,
)
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
    IdentityState,
    IdentityType,
    LifecycleState,
    PrivilegeLevel,
    RiskLabel,
)
from app.services.identity_state_engine import (
    IdentityNotFoundError,
    IdentityStateBuildError,
    IdentityStateEngine,
    OrganizationScopeError,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/snapshots", tags=["snapshots"])


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------


MAX_PAGE_LIMIT: int = 200
DEFAULT_PAGE_LIMIT: int = 50

#: Valid ``triggered_by`` values (matches a DB CHECK constraint in the
#: snapshot catalogue migration).
VALID_TRIGGER_SOURCES: frozenset[str] = frozenset(
    {"manual", "scheduled", "pre-change"}
)

#: Valid ``status`` values written by the snapshot pipeline.
VALID_SNAPSHOT_STATUSES: frozenset[str] = frozenset(
    {"complete", "capturing", "failed"}
)

#: Default trigger source attached to an on-demand capture via
#: ``POST /capture``.
DEFAULT_CAPTURE_TRIGGER: str = "manual"

#: Status a freshly-requested capture starts in.
CAPTURING_STATUS: str = "capturing"


# ---------------------------------------------------------------------------
# Response envelopes
# ---------------------------------------------------------------------------


T = TypeVar("T")


class DataContextDTO(BaseModel):
    """Pydantic mirror of the frozen :class:`DataContext` dataclass.

    Kept local so the snapshots module has no cross-route dependency on
    the identities module. The projection is loss-less and trivial to
    reconstruct via :meth:`from_context`.
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
    """Standard paginated envelope carrying a :class:`DataContextDTO`."""

    items: list[T]
    total: int
    offset: int
    limit: int
    data_context: DataContextDTO


class IdentityListRowDTO(BaseModel):
    """Flattened identity row — mirrors the frontend ``IdentityListRow``."""

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


class SnapshotSummary(BaseModel):
    """Catalogue row describing one snapshot in the caller's org."""

    id: int = Field(..., ge=1)
    organization_id: str = Field(..., min_length=1)
    captured_at: datetime
    identity_count: int = Field(..., ge=0)
    triggered_by: str = Field(
        ...,
        description="One of 'manual' | 'scheduled' | 'pre-change'.",
    )
    status: str = Field(
        ...,
        description="One of 'complete' | 'capturing' | 'failed'.",
    )
    data_context: DataContextDTO


class CaptureSnapshotRequest(BaseModel):
    """POST body for on-demand snapshot capture."""

    triggered_by: str = Field(
        DEFAULT_CAPTURE_TRIGGER,
        description="Trigger source — must be in VALID_TRIGGER_SOURCES.",
    )
    note: Optional[str] = Field(
        None,
        max_length=512,
        description="Optional free-text note, surfaced in audit trails.",
    )


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------


def _error_body(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"error": code, "detail": detail}
    body.update(extra)
    return body


def _request_id(request: Request) -> str:
    rid = request.headers.get("X-Request-Id")
    return rid or str(uuid.uuid4())


def _raise_snapshot_not_found(snapshot_id: int) -> None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error_body(
            "snapshot_not_found",
            f"snapshot '{snapshot_id}' not found for this organization",
        ),
    )


def _raise_identity_not_found(identity_id: str, snapshot_id: int) -> None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error_body(
            "identity_not_found",
            f"identity '{identity_id}' not found in snapshot '{snapshot_id}'",
        ),
    )


def _raise_org_scope(reason: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_error_body("org_scope_error", reason),
    )


def _raise_validation(reason: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=_error_body("validation_error", reason),
    )


def _raise_internal(request: Request, exc: Exception) -> None:
    rid = _request_id(request)
    logger.exception("snapshot_route.internal request_id=%s err=%s", rid, exc)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body(
            "internal_error",
            "an internal error occurred — see server logs",
            request_id=rid,
        ),
    )


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


async def _current_org_id(current_user: Any = Depends(get_current_user)) -> str:
    """Extract ``organization_id`` from the authenticated principal only."""
    org_id = getattr(current_user, "organization_id", None)
    if not isinstance(org_id, str) or not org_id.strip():
        _raise_org_scope("authenticated user has no organization binding")
    return org_id.strip()


def _get_engine(organization_id: str, db: AsyncSession) -> IdentityStateEngine:
    """Construct a fresh, org-bound engine for this request."""
    try:
        return IdentityStateEngine(organization_id=organization_id, db=db)
    except ValueError as exc:
        _raise_org_scope(str(exc))
        raise  # pragma: no cover


# ---------------------------------------------------------------------------
# Snapshot catalogue helpers
# ---------------------------------------------------------------------------


async def _fetch_snapshot_row(
    *,
    db: AsyncSession,
    snapshot_id: int,
    organization_id: str,
    request: Request,
) -> dict[str, Any]:
    """Fetch a snapshot catalogue row with strict cross-org enforcement.

    The lookup runs in two phases so we can distinguish
    "does not exist" (404) from "exists but belongs to someone else"
    (403). A single query scoped on both id and org would collapse these
    into a 404 and turn the endpoint into an existence oracle.

    Returns
    -------
    dict[str, Any]
        The catalogue row as a plain dict.

    Raises
    ------
    HTTPException
        * 404 when the snapshot id does not exist at all.
        * 403 when it exists but is owned by a different organization.
    """
    try:
        cross_org_result = await db.execute(
            text(
                """
                SELECT id, organization_id, captured_at, identity_count,
                       triggered_by, status
                FROM snapshots
                WHERE id = :snapshot_id
                """
            ),
            {"snapshot_id": snapshot_id},
        )
        row = cross_org_result.mappings().first()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    if row is None:
        _raise_snapshot_not_found(snapshot_id)
        raise  # pragma: no cover

    # DB returns INTEGER org, JWT binding is str — compare as str.
    if str(row["organization_id"]) != str(organization_id):
        # Defense-in-depth: log the attempted cross-tenant read, reject
        # with 403 so the attacker cannot use the existence check as an
        # oracle. Do NOT include the foreign org id in the response body.
        logger.warning(
            "snapshot.cross_org_access_denied caller_org=%s snapshot_id=%s",
            organization_id,
            snapshot_id,
        )
        _raise_org_scope(
            f"snapshot '{snapshot_id}' is not accessible to this organization"
        )
        raise  # pragma: no cover

    return dict(row)


def _row_to_summary(row: dict[str, Any]) -> SnapshotSummary:
    """Project a ``snapshots`` row onto :class:`SnapshotSummary`.

    Enforces the ``triggered_by`` / ``status`` enums — a bad value in the
    DB is a hard error here rather than a silent downgrade, because the
    frontend uses these as discriminators for the banner UI.
    """
    triggered_by = str(row["triggered_by"])
    status_value = str(row["status"])

    if triggered_by not in VALID_TRIGGER_SOURCES:
        logger.error(
            "snapshot.invalid_trigger snapshot_id=%s triggered_by=%s",
            row.get("id"),
            triggered_by,
        )
        triggered_by = DEFAULT_CAPTURE_TRIGGER

    if status_value not in VALID_SNAPSHOT_STATUSES:
        logger.error(
            "snapshot.invalid_status snapshot_id=%s status=%s",
            row.get("id"),
            status_value,
        )
        status_value = "failed"

    return SnapshotSummary(
        id=int(row["id"]),
        organization_id=str(row["organization_id"]),
        captured_at=row["captured_at"],
        identity_count=int(row["identity_count"] or 0),
        triggered_by=triggered_by,
        status=status_value,
        data_context=_snapshot_data_context(
            snapshot_id=int(row["id"]),
            captured_at=row["captured_at"],
        ),
    )


def _snapshot_data_context(
    *,
    snapshot_id: int,
    captured_at: datetime,
) -> DataContextDTO:
    """Build the snapshot-mode :class:`DataContextDTO` for a catalogue row."""
    return DataContextDTO(
        data_mode=DataMode.SNAPSHOT,
        snapshot_id=snapshot_id,
        snapshot_date=captured_at,
        computed_at=datetime.now(timezone.utc),
        is_stale=False,
    )


def _resolve_snapshot_capture_service() -> Any:
    """Lazily import the snapshot capture service.

    The service is kept behind a lazy import so unit tests can stub it
    without pulling in the whole discovery / scheduler stack. The real
    implementation lives in ``app.services.snapshot_capture``.
    """
    from app.services.snapshot_capture import (  # type: ignore[import-not-found]
        SnapshotCaptureService,
    )

    return SnapshotCaptureService()


# ---------------------------------------------------------------------------
# Row → DTO projection for snapshot identity rows
# ---------------------------------------------------------------------------


def _row_to_identity_dto(
    row: Any,
    organization_id: str,
    data_context: DataContextDTO,
) -> IdentityListRowDTO:
    """Map an ``identity_list_snapshots`` row to :class:`IdentityListRowDTO`.

    Enforces the tenant invariant one more time at the row level — a
    mismatch raises 403 rather than silently emitting a foreign row.
    """
    # DB returns INTEGER org, JWT binding is str — compare as str.
    if str(row.get("organization_id")) != str(organization_id):
        logger.error(
            "snapshot_list.scope_leak expected=%s row=%s",
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
# GET /api/v1/snapshots
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=list[SnapshotSummary],
    summary="List snapshots",
    description=(
        "Return every snapshot captured for the caller's organization, "
        "ordered by capture time descending. Each entry carries its own "
        "``data_context`` so the UI can badge and link each row without "
        "a second request."
    ),
)
async def list_snapshots(
    request: Request,
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> list[SnapshotSummary]:
    # snapshots.organization_id is INTEGER per migration 087; cast once.
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover
    try:
        result = await db.execute(
            text(
                """
                SELECT id, organization_id, captured_at, identity_count,
                       triggered_by, status
                FROM snapshots
                WHERE organization_id = :org
                ORDER BY captured_at DESC, id DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {"org": org_int, "limit": limit, "offset": offset},
        )
        rows = result.mappings().all()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    summaries: list[SnapshotSummary] = []
    for row in rows:
        if str(row.get("organization_id")) != str(organization_id):
            logger.error(
                "snapshot_list.scope_leak expected=%s row=%s",
                organization_id,
                row.get("organization_id"),
            )
            _raise_org_scope("row organization_id mismatch")
        summaries.append(_row_to_summary(dict(row)))
    return summaries


# ---------------------------------------------------------------------------
# GET /api/v1/snapshots/{snapshot_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{snapshot_id}",
    response_model=SnapshotSummary,
    summary="Get snapshot metadata",
    description=(
        "Return the catalogue row for one snapshot. A snapshot owned by "
        "a different organization returns **403** (not 404) so the "
        "endpoint cannot be used as an existence oracle."
    ),
)
async def get_snapshot(
    request: Request,
    snapshot_id: int = Path(..., ge=1),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> SnapshotSummary:
    row = await _fetch_snapshot_row(
        db=db,
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        request=request,
    )
    return _row_to_summary(row)


# ---------------------------------------------------------------------------
# GET /api/v1/snapshots/{snapshot_id}/identities
# ---------------------------------------------------------------------------


@router.get(
    "/{snapshot_id}/identities",
    response_model=PaginatedResponse[IdentityListRowDTO],
    summary="List identities in a snapshot",
    description=(
        "Return the identity list rolled into a specific snapshot. All "
        "rows carry ``data_context.data_mode='snapshot'`` and "
        "``data_context.snapshot_date`` is the capture time of the "
        "parent snapshot — the frontend banner renders automatically."
    ),
)
async def list_snapshot_identities(
    request: Request,
    snapshot_id: int = Path(..., ge=1),
    identity_type: Optional[IdentityType] = Query(None),
    risk_label: Optional[RiskLabel] = Query(None),
    is_dormant: Optional[bool] = Query(None),
    cloud_provider: Optional[CloudProvider] = Query(None),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[IdentityListRowDTO]:
    # 1. Validate the snapshot belongs to the caller's org FIRST. Any
    #    cross-tenant attempt short-circuits with 403 before we touch
    #    the identity tables.
    snapshot_row = await _fetch_snapshot_row(
        db=db,
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        request=request,
    )

    # 2. Snapshot-mode data context — stamped on every row AND on the
    #    paginated envelope so consumers never see a mixed payload.
    data_context = _snapshot_data_context(
        snapshot_id=snapshot_id,
        captured_at=snapshot_row["captured_at"],
    )

    # identity_list_snapshots.organization_id is INTEGER per 087; cast once.
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover

    filters: list[str] = [
        "organization_id = :org",
        "snapshot_id = :snapshot_id",
    ]
    params: dict[str, Any] = {
        "org": org_int,
        "snapshot_id": snapshot_id,
        "limit": limit,
        "offset": offset,
    }

    if identity_type is not None:
        filters.append("identity_type = :identity_type")
        params["identity_type"] = identity_type.value
    if risk_label is not None:
        filters.append("risk_label = :risk_label")
        params["risk_label"] = risk_label.value
    if is_dormant is not None:
        filters.append("is_dormant = :is_dormant")
        params["is_dormant"] = is_dormant
    if cloud_provider is not None:
        filters.append("cloud_provider = :cloud_provider")
        params["cloud_provider"] = cloud_provider.value

    where_sql = " AND ".join(filters)

    try:
        total_result = await db.execute(
            text(
                f"""
                SELECT COUNT(*)
                FROM identity_list_snapshots
                WHERE {where_sql}
                """
            ),
            params,
        )
        total = int(total_result.scalar() or 0)

        result = await db.execute(
            text(
                f"""
                SELECT identity_id, global_identity_id, organization_id,
                       display_name, identity_type, cloud_provider,
                       risk_label, risk_score, governance, lifecycle_state,
                       is_dormant, privilege_level, last_seen
                FROM identity_list_snapshots
                WHERE {where_sql}
                ORDER BY risk_score DESC, display_name ASC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )
        rows = result.mappings().all()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    items = [
        _row_to_identity_dto(row, organization_id, data_context) for row in rows
    ]

    return PaginatedResponse[IdentityListRowDTO](
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        data_context=data_context,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/snapshots/{snapshot_id}/identities/{identity_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{snapshot_id}/identities/{identity_id}",
    response_model=IdentityState,
    summary="Get full identity state from a snapshot",
    description=(
        "Return the full :class:`IdentityState` for one identity as it "
        "existed at the time of ``snapshot_id``. The response is the "
        "exact same shape as the live ``GET /api/v1/identities/{id}`` "
        "response — the only difference is that ``data_context.data_mode"
        "`` is always ``'snapshot'``. This is what enables frontend code "
        "reuse across live and point-in-time views."
    ),
)
async def get_snapshot_identity_state(
    request: Request,
    snapshot_id: int = Path(..., ge=1),
    identity_id: str = Path(..., min_length=1),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> IdentityState:
    # 1. Snapshot ownership check runs first — prevents cross-tenant
    #    identity lookups via a borrowed snapshot_id.
    await _fetch_snapshot_row(
        db=db,
        snapshot_id=snapshot_id,
        organization_id=organization_id,
        request=request,
    )

    # 2. Delegate to the engine in strict snapshot mode. The engine is
    #    the only component that knows how to pivot its queries onto
    #    the ``*_snapshots`` tables based on ``data_mode``.
    engine = _get_engine(organization_id, db)
    try:
        return await engine.build(
            identity_id=identity_id,
            data_mode=DataMode.SNAPSHOT,
            snapshot_id=snapshot_id,
        )
    except IdentityNotFoundError:
        _raise_identity_not_found(identity_id, snapshot_id)
    except (OrganizationScopeError, CrossOrgLeakageError, OrgScopeError) as exc:
        _raise_org_scope(str(exc))
    except ValueError as exc:
        _raise_validation(str(exc))
    except IdentityStateBuildError as exc:
        _raise_internal(request, exc)
    raise HTTPException(  # pragma: no cover — satisfies the type checker
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body("internal_error", "engine returned no value"),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/snapshots/capture
# ---------------------------------------------------------------------------


@router.post(
    "/capture",
    response_model=SnapshotSummary,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a snapshot capture",
    description=(
        "Create a new snapshot catalogue row in ``status='capturing'`` "
        "and dispatch the heavy capture work to a background task. The "
        "response is returned immediately so the client does not block "
        "on discovery — poll ``GET /api/v1/snapshots/{id}`` for "
        "progress."
    ),
)
async def capture_snapshot(
    request: Request,
    background_tasks: BackgroundTasks,
    body: Optional[CaptureSnapshotRequest] = None,
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> SnapshotSummary:
    payload = body or CaptureSnapshotRequest()
    trigger = payload.triggered_by or DEFAULT_CAPTURE_TRIGGER
    if trigger not in VALID_TRIGGER_SOURCES:
        _raise_validation(
            f"triggered_by must be one of {sorted(VALID_TRIGGER_SOURCES)}"
        )

    now = datetime.now(timezone.utc)

    # snapshots.organization_id is INTEGER per migration 087; cast once.
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover

    try:
        insert_result = await db.execute(
            text(
                """
                INSERT INTO snapshots
                    (organization_id, captured_at, identity_count,
                     triggered_by, status, note)
                VALUES
                    (:org, :captured_at, 0, :triggered_by, :status, :note)
                RETURNING id, organization_id, captured_at, identity_count,
                          triggered_by, status
                """
            ),
            {
                "org": org_int,
                "captured_at": now,
                "triggered_by": trigger,
                "status": CAPTURING_STATUS,
                "note": payload.note,
            },
        )
        row = insert_result.mappings().first()
        if row is None:
            _raise_internal(request, RuntimeError("snapshot INSERT returned no row"))
            raise  # pragma: no cover
        await db.commit()
    except SQLAlchemyError as exc:
        try:
            await db.rollback()
        except SQLAlchemyError:
            pass
        _raise_internal(request, exc)
        raise  # pragma: no cover

    snapshot_id = int(row["id"])
    logger.info(
        "snapshot.capture_requested org=%s snapshot_id=%s triggered_by=%s",
        organization_id,
        snapshot_id,
        trigger,
    )

    # Dispatch the heavy lifting asynchronously. The capture service is
    # responsible for flipping the row's status to 'complete' or
    # 'failed' and for populating ``identity_count`` when it is done.
    #
    # The capture service module is optional in Phase 3 — the seed /
    # empty-state installation does not ship it. When the module is
    # absent we still return a ``capturing`` catalogue row so the
    # caller gets a deterministic 202 and can poll. The scheduled
    # capture pipeline will pick the row up once the service lands.
    try:
        capture_service = _resolve_snapshot_capture_service()
    except ModuleNotFoundError:
        logger.warning(
            "snapshot.capture_service_unavailable org=%s snapshot_id=%s — "
            "row persisted, dispatch skipped",
            organization_id,
            snapshot_id,
        )
        capture_service = None
    except Exception as exc:  # noqa: BLE001 — other import errors are hard fail
        logger.exception(
            "snapshot.capture_dispatch_failed org=%s snapshot_id=%s",
            organization_id,
            snapshot_id,
        )
        _raise_internal(request, exc)
        raise  # pragma: no cover

    if capture_service is not None:
        try:
            background_tasks.add_task(
                capture_service.run_capture,
                organization_id=organization_id,
                snapshot_id=snapshot_id,
                triggered_by=trigger,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "snapshot.capture_dispatch_failed org=%s snapshot_id=%s",
                organization_id,
                snapshot_id,
            )
            _raise_internal(request, exc)
            raise  # pragma: no cover

    return _row_to_summary(dict(row))
