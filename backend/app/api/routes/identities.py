"""
Phase 1 REST API — Identity routes.

All routes are tenant-scoped by construction: ``organization_id`` is drawn
from the authenticated principal (:func:`get_current_user`) and is never
accepted from a URL path, query string, or request body. Business logic
lives in :class:`IdentityStateEngine` and :class:`GlobalIdentityRegistry`;
the handlers below are thin adapters that translate HTTP → engine → HTTP
and make sure every response carries a :class:`DataContext`.

Error mapping
-------------
* 403 :class:`OrgScopeError`   — missing / invalid org binding on the caller
* 404 :class:`IdentityNotFoundError` — identity does not exist for the org
* 422 Pydantic validation      — supplied by FastAPI automatically
* 500 :class:`IdentityStateBuildError` — wrapped DB or engine failure,
      includes a stable ``request_id`` for correlation with server logs
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
    AttackPathsBlock,
    CloudProvider,
    DataContext,
    DataMode,
    GovernanceClassification,
    IdentityState,
    IdentityType,
    LifecycleState,
    PrivilegeLevel,
    RemediationAction,
    RemediationBlock,
    RiskLabel,
    RolesBlock,
)


class DataContextDTO(BaseModel):
    """Pydantic mirror of :class:`DataContext` for response serialization.

    :class:`DataContext` is a frozen ``@dataclass`` so it stays cheap to
    construct inside the engine. FastAPI's response-model machinery needs
    a Pydantic type to generate an OpenAPI schema, so we project the
    dataclass onto this DTO at the HTTP boundary.
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
from app.services.global_identity_registry import (
    GlobalIdentityRegistry,
    RegistryResolutionError,
)
from app.services.identity_state_engine import (
    IdentityNotFoundError,
    IdentityStateBuildError,
    IdentityStateEngine,
    OrganizationScopeError,
)
from app.services.whatif_service import (
    SimulationType,
    WhatIfError,
    WhatIfIdentityNotFound,
    WhatIfResult,
    WhatIfService,
)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defensive enum helpers — consolidated in enum_aliases.py.
# DB columns are VARCHAR without CHECK constraints, so values not in the
# Python enum must not 500 the list endpoint.
# ---------------------------------------------------------------------------

from app.api.rate_limit import rate_limit  # type: ignore[import-not-found]
from app.services.builders.enum_aliases import safe_enum as _safe_enum  # noqa: E402

router = APIRouter(prefix="/api/v1/identities", tags=["identities"])


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------


#: Maximum page size accepted by the list endpoint. Anything larger is
#: clamped by FastAPI's ``Query(..., le=...)`` and returns a 422.
MAX_PAGE_LIMIT: int = 200

#: Default page size when ``limit`` is omitted.
DEFAULT_PAGE_LIMIT: int = 50


# ---------------------------------------------------------------------------
# Response envelopes
# ---------------------------------------------------------------------------


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated response envelope used across identity endpoints.

    Every list response carries a :class:`DataContext` so consumers can
    badge stale / snapshot-sourced pages without a second round-trip.
    """

    items: list[T]
    total: int
    offset: int
    limit: int
    data_context: DataContextDTO


class IdentityListRowDTO(BaseModel):
    """Flattened row returned by ``GET /api/v1/identities``.

    Mirrors the frontend ``IdentityListRow`` interface one-for-one.
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


class ExecuteRemediationRequest(BaseModel):
    """POST body for remediation execution."""

    action_id: int = Field(..., ge=0, description="Remediation action identifier.")
    confirm: bool = Field(..., description="Must be true — guards against accidental execution.")


class ExecuteRemediationResult(BaseModel):
    """Outcome of a single remediation execution."""

    success: bool
    command_executed: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None
    data_context: DataContextDTO


# ---------------------------------------------------------------------------
# Error envelope helpers
# ---------------------------------------------------------------------------


def _error_body(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    """Stable ``{error, detail, ...}`` shape for every error response."""
    body: dict[str, Any] = {"error": code, "detail": detail}
    body.update(extra)
    return body


def _request_id(request: Request) -> str:
    """Return the correlation id for this request.

    Prefers a propagated ``X-Request-Id`` header and falls back to a fresh
    UUID so every 500 response is traceable in the server logs.
    """
    rid = request.headers.get("X-Request-Id")
    if rid:
        return rid
    return str(uuid.uuid4())


def _raise_not_found(identity_id: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=_error_body(
            "identity_not_found",
            f"identity '{identity_id}' not found for this organization",
        ),
    )


def _raise_org_scope(reason: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_error_body("org_scope_error", reason),
    )


def _raise_internal(request: Request, exc: Exception) -> None:
    rid = _request_id(request)
    logger.exception("identity_route.internal request_id=%s err=%s", rid, exc)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body(
            "internal_error",
            "an internal error occurred — see server logs",
            request_id=rid,
        ),
    )


# ---------------------------------------------------------------------------
# Shared dependencies
# ---------------------------------------------------------------------------


def _resolve_data_mode(snapshot_id: Optional[int]) -> DataMode:
    """Map the optional ``snapshot_id`` query param to a :class:`DataMode`."""
    return DataMode.SNAPSHOT if snapshot_id is not None else DataMode.LIVE


def _build_list_context(
    data_mode: DataMode, snapshot_id: Optional[int]
) -> DataContextDTO:
    """Fresh data context for list-style responses (never stale at emit)."""
    return DataContextDTO(
        data_mode=data_mode,
        snapshot_id=snapshot_id,
        snapshot_date=None,
        computed_at=datetime.now(timezone.utc),
        is_stale=False,
    )


async def _current_org_id(current_user: Any = Depends(get_current_user)) -> str:
    """Extract ``organization_id`` from the authenticated principal.

    Raises 403 if the principal is missing or lacks an org binding — we
    refuse to fall back to any other source (URL path, query, body).
    """
    org_id = getattr(current_user, "organization_id", None)
    if not isinstance(org_id, str) or not org_id.strip():
        _raise_org_scope("authenticated user has no organization binding")
    return org_id.strip()


def _get_engine(
    organization_id: str, db: AsyncSession
) -> IdentityStateEngine:
    """Construct a fresh, org-bound engine for this request."""
    try:
        return IdentityStateEngine(organization_id=organization_id, db=db)
    except ValueError as exc:
        # This path only fires if the dependency tree passed a bad org id —
        # still map it to a 403 so the client sees a stable error shape.
        _raise_org_scope(str(exc))
        raise  # pragma: no cover — _raise_org_scope already raises


# ---------------------------------------------------------------------------
# GET /api/v1/identities
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=PaginatedResponse[IdentityListRowDTO],
    summary="List identities",
    description=(
        "Paginated list of identities for the authenticated organization. "
        "Supports filtering by identity type, risk label, dormancy, and "
        "cloud provider. Pass ``snapshot_id`` to read from a point-in-time "
        "snapshot instead of live data. Every row carries a ``data_context``."
    ),
)
async def list_identities(
    request: Request,
    snapshot_id: Optional[int] = Query(
        None, ge=0, description="Optional snapshot id — switches to snapshot mode."
    ),
    identity_type: Optional[IdentityType] = Query(None),
    risk_label: Optional[RiskLabel] = Query(None),
    is_dormant: Optional[bool] = Query(None),
    cloud_provider: Optional[CloudProvider] = Query(None),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[IdentityListRowDTO]:
    data_mode = _resolve_data_mode(snapshot_id)

    # identity_list.organization_id is INTEGER per migration 087; the JWT
    # claim is str and asyncpg refuses str→int coercion, so cast once.
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover

    filters: list[str] = ["organization_id = :org"]
    params: dict[str, Any] = {"org": org_int, "limit": limit, "offset": offset}

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
    if snapshot_id is not None:
        filters.append("snapshot_id = :snapshot_id")
        params["snapshot_id"] = snapshot_id

    source_table = (
        "identity_list_snapshots" if data_mode == DataMode.SNAPSHOT else "identity_list"
    )
    where_sql = " AND ".join(filters)

    try:
        total_result = await db.execute(
            text(f"SELECT COUNT(*) FROM {source_table} WHERE {where_sql}"),
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
                FROM {source_table}
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

    data_context = _build_list_context(data_mode, snapshot_id)

    items: list[IdentityListRowDTO] = []
    for row in rows:
        # DB returns INTEGER org, JWT binding is str — compare as str.
        if str(row.get("organization_id")) != str(organization_id):
            # Defense-in-depth scope leak tripwire.
            logger.error(
                "identity_list.scope_leak expected=%s row=%s",
                organization_id,
                row.get("organization_id"),
            )
            _raise_org_scope("row organization_id mismatch")
        try:
            items.append(
                IdentityListRowDTO(
                    identity_id=row["identity_id"],
                    global_identity_id=str(row["global_identity_id"]),
                    organization_id=str(row["organization_id"]),
                    display_name=row["display_name"],
                    identity_type=_safe_enum(IdentityType, row["identity_type"], IdentityType.SERVICE_PRINCIPAL),
                    cloud_provider=_safe_enum(CloudProvider, row["cloud_provider"], CloudProvider.AZURE),
                    risk_label=_safe_enum(RiskLabel, row["risk_label"], RiskLabel.LOW),
                    risk_score=float(row["risk_score"] or 0.0),
                    governance=_safe_enum(GovernanceClassification, row["governance"], GovernanceClassification.UNGOVERNED),
                    lifecycle_state=_safe_enum(LifecycleState, row["lifecycle_state"], LifecycleState.PROVISIONED),
                    is_dormant=bool(row["is_dormant"]),
                    privilege_level=_safe_enum(PrivilegeLevel, row["privilege_level"], PrivilegeLevel.STANDARD),
                    last_seen=row["last_seen"],
                    data_context=data_context,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "identity_list: skipping malformed row identity_id=%s err=%s",
                row.get("identity_id", "?"),
                exc,
            )
            continue

    return PaginatedResponse[IdentityListRowDTO](
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        data_context=data_context,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/identities/{identity_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{identity_id}",
    response_model=IdentityState,
    summary="Get full identity state",
    description=(
        "Return the complete :class:`IdentityState` for one identity — all "
        "B01–B09 blocks plus a top-level ``data_context``. Pass "
        "``snapshot_id`` to read from a stored snapshot; otherwise the "
        "engine runs in live mode."
    ),
)
async def get_identity_state(
    request: Request,
    identity_id: str = Path(..., min_length=1),
    snapshot_id: Optional[int] = Query(None, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> IdentityState:
    data_mode = _resolve_data_mode(snapshot_id)
    engine = _get_engine(organization_id, db)
    try:
        return await engine.build(
            identity_id=identity_id,
            data_mode=data_mode,
            snapshot_id=snapshot_id,
        )
    except IdentityNotFoundError:
        _raise_not_found(identity_id)
    except (OrganizationScopeError, CrossOrgLeakageError) as exc:
        _raise_org_scope(str(exc))
    except IdentityStateBuildError as exc:
        _raise_internal(request, exc)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_error_body("validation_error", str(exc)),
        )
    raise HTTPException(  # pragma: no cover — unreachable, satisfies type checker
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body("internal_error", "engine returned no value"),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/identities/{identity_id}/roles
# ---------------------------------------------------------------------------


@router.get(
    "/{identity_id}/roles",
    response_model=RolesBlock,
    summary="Get role assignments for an identity",
    description=(
        "Return the :class:`RolesBlock` for the identity — every assignment "
        "has its usage signal EMBEDDED (``role.usage``). A separate "
        "``role_usage`` dict is never returned and never accepted."
    ),
)
async def get_identity_roles(
    request: Request,
    identity_id: str = Path(..., min_length=1),
    snapshot_id: Optional[int] = Query(None, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> RolesBlock:
    state = await _build_state_or_raise(
        request, organization_id, db, identity_id, snapshot_id
    )
    return state.roles


# ---------------------------------------------------------------------------
# GET /api/v1/identities/{identity_id}/attack-paths
# ---------------------------------------------------------------------------


@router.get(
    "/{identity_id}/attack-paths",
    response_model=AttackPathsBlock,
    summary="Get attack paths for an identity",
    description=(
        "Return the :class:`AttackPathsBlock` for the identity. Each "
        "``AttackPath`` carries a typed ``Resource`` target — never a "
        "raw string path."
    ),
)
async def get_identity_attack_paths(
    request: Request,
    identity_id: str = Path(..., min_length=1),
    snapshot_id: Optional[int] = Query(None, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> AttackPathsBlock:
    state = await _build_state_or_raise(
        request, organization_id, db, identity_id, snapshot_id
    )
    return state.attack_paths


# ---------------------------------------------------------------------------
# GET /api/v1/identities/{identity_id}/remediation
# ---------------------------------------------------------------------------


@router.get(
    "/{identity_id}/remediation",
    response_model=RemediationBlock,
    summary="Get remediation actions for an identity",
    description=(
        "Return the :class:`RemediationBlock` for the identity, including "
        "per-priority counts and the ordered list of actions."
    ),
)
async def get_identity_remediation(
    request: Request,
    identity_id: str = Path(..., min_length=1),
    snapshot_id: Optional[int] = Query(None, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> RemediationBlock:
    state = await _build_state_or_raise(
        request, organization_id, db, identity_id, snapshot_id
    )
    return state.remediation


# ---------------------------------------------------------------------------
# POST /api/v1/identities/{identity_id}/remediation/{action_id}/execute
# ---------------------------------------------------------------------------


@router.post(
    "/{identity_id}/remediation/{action_id}/execute",
    response_model=ExecuteRemediationResult,
    summary="Execute an auto-fixable remediation action",
    description=(
        "Execute one remediation action. The request body **must** set "
        "``confirm=True`` and the target action **must** be "
        "``auto_fixable``. Any other action is rejected with 422."
    ),
)
async def execute_remediation(
    request: Request,
    body: ExecuteRemediationRequest,
    identity_id: str = Path(..., min_length=1),
    action_id: int = Path(..., ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ExecuteRemediationResult:
    if body.action_id != action_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_error_body(
                "validation_error",
                "action_id in body must match action_id in path",
            ),
        )
    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_error_body(
                "confirmation_required",
                "remediation execution requires confirm=true",
            ),
        )

    state = await _build_state_or_raise(
        request, organization_id, db, identity_id, snapshot_id=None
    )

    action = _find_action(state.remediation, action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_error_body(
                "remediation_action_not_found",
                f"action {action_id} not found on identity '{identity_id}'",
            ),
        )
    if not action.auto_fixable:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_error_body(
                "action_not_auto_fixable",
                "only auto_fixable=true actions may be executed via the API",
            ),
        )

    # Delegate the actual execution to a dedicated service. Kept behind a
    # thin lookup so the route handler carries no business logic.
    try:
        executor = _resolve_remediation_executor()
        result = await executor.execute(
            organization_id=organization_id,
            identity_id=identity_id,
            action=action,
            db=db,
        )
    except Exception as exc:  # noqa: BLE001 — mapped to 500 below
        _raise_internal(request, exc)
        raise  # pragma: no cover

    return ExecuteRemediationResult(
        success=bool(result.get("success", False)),
        command_executed=result.get("command_executed") or action.fix_command,
        output=result.get("output"),
        error=result.get("error"),
        data_context=DataContextDTO.from_context(state.data_context),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/identities/global/{global_identity_id}
# ---------------------------------------------------------------------------


@router.get(
    "/global/{global_identity_id}",
    response_model=PaginatedResponse[IdentityListRowDTO],
    summary="Get cross-cloud projections of a global identity",
    description=(
        "Return every cloud member bound to the supplied "
        "``global_identity_id`` within the caller's organization. "
        "Supports F1 — the stable cross-cloud identity correlation UUID. "
        "A global id that belongs to a different organization returns an "
        "empty list (never foreign data)."
    ),
)
async def get_global_identity_peers(
    request: Request,
    global_identity_id: uuid.UUID = Path(...),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[IdentityListRowDTO]:
    registry = GlobalIdentityRegistry()
    try:
        peers = await registry.get_peers(
            organization_id=organization_id,
            global_identity_id=global_identity_id,
            db=db,
        )
    except RegistryResolutionError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    if not peers:
        _raise_not_found(str(global_identity_id))

    # Project registry rows onto IdentityListRowDTO via the live list view.
    cloud_ids = [p["cloud_id"] for p in peers]
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover
    try:
        result = await db.execute(
            text(
                """
                SELECT identity_id, global_identity_id, organization_id,
                       display_name, identity_type, cloud_provider,
                       risk_label, risk_score, governance, lifecycle_state,
                       is_dormant, privilege_level, last_seen
                FROM identity_list
                WHERE organization_id = :org
                  AND identity_id = ANY(:cloud_ids)
                """
            ),
            {"org": org_int, "cloud_ids": cloud_ids},
        )
        rows = result.mappings().all()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    data_context = _build_list_context(DataMode.LIVE, None)
    items: list[IdentityListRowDTO] = []
    for row in rows:
        # DB returns INTEGER org, JWT binding is str — compare as str.
        if str(row.get("organization_id")) != str(organization_id):
            _raise_org_scope("row organization_id mismatch")
        try:
            items.append(
                IdentityListRowDTO(
                    identity_id=row["identity_id"],
                    global_identity_id=str(row["global_identity_id"]),
                    organization_id=str(row["organization_id"]),
                    display_name=row["display_name"],
                    identity_type=_safe_enum(IdentityType, row["identity_type"], IdentityType.SERVICE_PRINCIPAL),
                    cloud_provider=_safe_enum(CloudProvider, row["cloud_provider"], CloudProvider.AZURE),
                    risk_label=_safe_enum(RiskLabel, row["risk_label"], RiskLabel.LOW),
                    risk_score=float(row["risk_score"] or 0.0),
                    governance=_safe_enum(GovernanceClassification, row["governance"], GovernanceClassification.UNGOVERNED),
                    lifecycle_state=_safe_enum(LifecycleState, row["lifecycle_state"], LifecycleState.PROVISIONED),
                    is_dormant=bool(row["is_dormant"]),
                    privilege_level=_safe_enum(PrivilegeLevel, row["privilege_level"], PrivilegeLevel.STANDARD),
                    last_seen=row["last_seen"],
                    data_context=data_context,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "identity_list: skipping malformed row identity_id=%s err=%s",
                row.get("identity_id", "?"),
                exc,
            )
            continue

    return PaginatedResponse[IdentityListRowDTO](
        items=items,
        total=len(items),
        offset=0,
        limit=len(items),
        data_context=data_context,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _build_state_or_raise(
    request: Request,
    organization_id: str,
    db: AsyncSession,
    identity_id: str,
    snapshot_id: Optional[int],
) -> IdentityState:
    """Run the engine with full HTTP error mapping.

    Centralizes the exception → HTTP code translation so every sub-endpoint
    (roles, attack paths, remediation) returns consistent error bodies.
    """
    data_mode = _resolve_data_mode(snapshot_id)
    engine = _get_engine(organization_id, db)
    try:
        return await engine.build(
            identity_id=identity_id,
            data_mode=data_mode,
            snapshot_id=snapshot_id,
        )
    except IdentityNotFoundError:
        _raise_not_found(identity_id)
    except (OrganizationScopeError, CrossOrgLeakageError, OrgScopeError) as exc:
        _raise_org_scope(str(exc))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_error_body("validation_error", str(exc)),
        )
    except IdentityStateBuildError as exc:
        _raise_internal(request, exc)
    raise HTTPException(  # pragma: no cover
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body("internal_error", "engine returned no value"),
    )


def _find_action(
    remediation: RemediationBlock, action_id: int
) -> Optional[RemediationAction]:
    """Return the action whose positional index matches ``action_id``.

    Remediation actions do not carry a persistent id in the model today;
    we use the ordered position inside the block as a stable short-lived
    handle so the execute route can address a single action without a
    schema change.
    """
    if action_id < 0 or action_id >= len(remediation.actions):
        return None
    return remediation.actions[action_id]


def _resolve_remediation_executor() -> Any:
    """Import the remediation executor lazily.

    The executor is injected at module import time in production so the
    route handler stays free of business logic. Lazy import keeps this
    module usable in unit tests that stub the service.
    """
    from app.services.remediation_executor import (  # type: ignore[import-not-found]
        RemediationExecutor,
    )

    return RemediationExecutor()


# ---------------------------------------------------------------------------
# What-if simulations (E1)
#
# GET  /api/v1/identities/{identity_id}/simulations  — list persisted runs
# POST /api/v1/identities/{identity_id}/simulate     — run + persist a new one
#
# Delegates all business logic to :class:`WhatIfService`. The handler is a
# thin HTTP adapter: validates inputs, maps service exceptions to stable
# error envelopes, and returns the Pydantic result model verbatim.
# ---------------------------------------------------------------------------


class WhatIfSimulateRequest(BaseModel):
    """POST body for ``/identities/{id}/simulate``."""

    simulation_type: SimulationType = Field(
        ...,
        description=(
            "One of ``ROLE_REMOVAL``, ``PRIVILEGE_REDUCTION``, "
            "``OWNERSHIP_ASSIGNMENT``."
        ),
    )
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Simulation-specific input parameters. Examples: "
            "``{'role': 'Owner'}`` for ROLE_REMOVAL, "
            "``{'target_level': 'standard'}`` for PRIVILEGE_REDUCTION, "
            "``{'owner': 'alice@example.com'}`` for OWNERSHIP_ASSIGNMENT."
        ),
    )


class WhatIfSimulationListItem(BaseModel):
    """Row shape returned by ``GET /identities/{id}/simulations``.

    Mirrors ``whatif_simulations`` columns plus a parsed copy of the
    result_payload so the client does not need to run Pydantic itself.
    """

    id: str
    organization_id: int
    identity_id: str
    simulation_type: SimulationType
    input_payload: dict[str, Any]
    result_payload: dict[str, Any]
    blast_radius_before: int
    blast_radius_after: int
    score_delta: float
    simulated_at: datetime
    simulated_by: Optional[int] = None


class WhatIfSimulationListResponse(BaseModel):
    """Response body for ``GET /identities/{id}/simulations``."""

    identity_id: str
    organization_id: int
    total: int
    items: list[WhatIfSimulationListItem]


@router.get(
    "/{identity_id}/simulations",
    response_model=WhatIfSimulationListResponse,
    summary="List persisted what-if simulations for an identity",
    description=(
        "Return all persisted what-if simulation runs for ``identity_id`` "
        "ordered newest first. Each row includes the full Pydantic-validated "
        "``result_payload`` so the client can render the before/after diff "
        "without a second round trip."
    ),
)
async def list_identity_simulations(
    request: Request,
    identity_id: str = Path(..., min_length=1, max_length=255),
    limit: int = Query(DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    offset: int = Query(0, ge=0),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> WhatIfSimulationListResponse:
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover

    service = WhatIfService(db)
    try:
        rows = await service.list_for_identity(
            organization_id=org_int,
            identity_id=identity_id,
            limit=limit,
            offset=offset,
        )
    except WhatIfError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    items: list[WhatIfSimulationListItem] = []
    for r in rows:
        raw_input = r.get("input_payload") or {}
        raw_result = r.get("result_payload") or {}
        # asyncpg already decodes JSONB into dict — defensive fallback for
        # legacy drivers that hand back a string.
        if isinstance(raw_input, str):
            import json as _json
            try:
                raw_input = _json.loads(raw_input)
            except Exception:  # noqa: BLE001
                raw_input = {}
        if isinstance(raw_result, str):
            import json as _json
            try:
                raw_result = _json.loads(raw_result)
            except Exception:  # noqa: BLE001
                raw_result = {}

        items.append(
            WhatIfSimulationListItem(
                id=str(r["id"]),
                organization_id=int(r["organization_id"]),
                identity_id=str(r["identity_id"]),
                simulation_type=r["simulation_type"],
                input_payload=raw_input if isinstance(raw_input, dict) else {},
                result_payload=raw_result if isinstance(raw_result, dict) else {},
                blast_radius_before=int(r["blast_radius_before"] or 0),
                blast_radius_after=int(r["blast_radius_after"] or 0),
                score_delta=float(r["score_delta"] or 0.0),
                simulated_at=r["simulated_at"],
                simulated_by=(
                    int(r["simulated_by"]) if r.get("simulated_by") is not None else None
                ),
            )
        )

    return WhatIfSimulationListResponse(
        identity_id=identity_id,
        organization_id=org_int,
        total=len(items),
        items=items,
    )


@router.post(
    "/{identity_id}/simulate",
    response_model=WhatIfResult,
    summary="Run a what-if simulation and persist the result",
    description=(
        "Run a hypothetical remediation against ``identity_id`` and persist "
        "the result to ``whatif_simulations``. Returns the validated "
        "Pydantic ``WhatIfResult`` containing the before/after snapshots, "
        "score delta, and narrative."
    ),
)
async def simulate_identity_whatif(
    request: Request,
    body: WhatIfSimulateRequest,
    identity_id: str = Path(..., min_length=1, max_length=255),
    organization_id: str = Depends(_current_org_id),
    current_user: Any = Depends(get_current_user),
    _rl: None = Depends(rate_limit("simulate", max_calls=10, window_seconds=60)),
    db: AsyncSession = Depends(get_db),
) -> WhatIfResult:
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover

    simulated_by = getattr(current_user, "user_id", None)
    if simulated_by is not None:
        try:
            simulated_by = int(simulated_by)
        except (TypeError, ValueError):
            simulated_by = None

    service = WhatIfService(db)
    try:
        return await service.simulate(
            organization_id=org_int,
            identity_id=identity_id,
            simulation_type=body.simulation_type,
            payload=body.payload,
            simulated_by=simulated_by,
        )
    except WhatIfIdentityNotFound:
        _raise_not_found(identity_id)
        raise  # pragma: no cover
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_error_body("validation_error", str(exc)),
        )
    except WhatIfError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover


# ---------------------------------------------------------------------------
# GET /api/v1/identities/{identity_id}/simulations/{simulation_id}/export
# ---------------------------------------------------------------------------


class SimulationFindingArtifact(BaseModel):
    """Structured finding artifact for a completed simulation."""

    finding_type: str = "WHAT_IF_SIMULATION"
    generated_at: datetime
    generated_by: str
    organization_id: int
    identity: dict[str, Any]
    simulation: dict[str, Any]
    recommendation: str
    evidence_references: list[str]


def _derive_recommendation(
    simulation_type: str,
    score_delta: float,
    blast_before: int,
    blast_after: int,
) -> str:
    """Engine-derived recommendation from simulation result."""
    action = {
        "ROLE_REMOVAL": "removing this role assignment",
        "PRIVILEGE_REDUCTION": "reducing privilege level",
        "OWNERSHIP_ASSIGNMENT": "assigning ownership",
    }.get(simulation_type, "this remediation")

    if score_delta <= -10:
        return (
            f"Urgent: {action} reduces risk by "
            f"{abs(score_delta):.1f} points and blast radius from "
            f"{blast_before} to {blast_after} — execute immediately."
        )
    if score_delta <= -5:
        return (
            f"Advisory: {action} would reduce risk by "
            f"{abs(score_delta):.1f} points. Schedule for next maintenance window."
        )
    return (
        f"No action required: {action} produces a delta of "
        f"{score_delta:+.1f} points — risk change is negligible."
    )


def _derive_confidence(result_payload: dict[str, Any]) -> str:
    """Derive confidence from the result payload data quality."""
    before = result_payload.get("before", {})
    after = result_payload.get("after", {})
    # HIGH if both snapshots have real risk scores and governance data
    if (
        before.get("risk_score", 0) > 0
        and before.get("governance")
        and after.get("governance")
    ):
        return "HIGH"
    if before.get("risk_score", 0) > 0:
        return "MEDIUM"
    return "LOW"


@router.get(
    "/{identity_id}/simulations/{simulation_id}/export",
    response_model=SimulationFindingArtifact,
    summary="Export simulation as structured finding artifact",
    description=(
        "Return a structured JSON finding artifact for a completed "
        "simulation. Includes engine-derived recommendation based "
        "on the score delta magnitude."
    ),
)
async def export_simulation_finding(
    request: Request,
    identity_id: str = Path(..., min_length=1, max_length=255),
    simulation_id: str = Path(..., min_length=1, max_length=64),
    organization_id: str = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> SimulationFindingArtifact:
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover

    # Fetch the specific simulation row
    try:
        res = await db.execute(
            text(
                """
                SELECT id, organization_id, identity_id, simulation_type,
                       input_payload, result_payload,
                       blast_radius_before, blast_radius_after,
                       score_delta, simulated_at, simulated_by
                FROM whatif_simulations
                WHERE id = CAST(:sim_id AS uuid)
                  AND organization_id = :org
                  AND identity_id = :identity_id
                """
            ),
            {
                "sim_id": simulation_id,
                "org": org_int,
                "identity_id": identity_id,
            },
        )
        row = res.mappings().first()
    except SQLAlchemyError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_error_body(
                "simulation_not_found",
                f"simulation {simulation_id!r} not found for identity {identity_id!r}",
            ),
        )

    result_payload = row["result_payload"] or {}
    if isinstance(result_payload, str):
        import json as _json
        result_payload = _json.loads(result_payload)

    sim_type = str(row["simulation_type"])
    score_delta = float(row["score_delta"])
    blast_before = int(row["blast_radius_before"])
    blast_after = int(row["blast_radius_after"])

    return SimulationFindingArtifact(
        finding_type="WHAT_IF_SIMULATION",
        generated_at=datetime.now(timezone.utc),
        generated_by=result_payload.get("engine_version", "whatif-service@1.0.0"),
        organization_id=org_int,
        identity={
            "id": identity_id,
            "name": result_payload.get("identity_display_name", identity_id),
            "type": result_payload.get("before", {}).get("privilege_level", "unknown"),
        },
        simulation={
            "type": sim_type,
            "input": row["input_payload"] or {},
            "result": {
                "score_before": result_payload.get("before", {}).get("risk_score", 0),
                "score_after": result_payload.get("after", {}).get("risk_score", 0),
                "delta": score_delta,
                "blast_radius_before": blast_before,
                "blast_radius_after": blast_after,
                "confidence": _derive_confidence(result_payload),
            },
        },
        recommendation=_derive_recommendation(
            sim_type, score_delta, blast_before, blast_after,
        ),
        evidence_references=[
            str(row["id"]),
            f"identity:{identity_id}",
        ],
    )
