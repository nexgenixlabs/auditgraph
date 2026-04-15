"""
Phase 3 REST API — Posture score routes.

Thin FastAPI adapter over :class:`PostureScoreEngine`. Provides:

* ``GET  /api/v1/posture/score``           — latest row (with ``data_freshness``)
* ``GET  /api/v1/posture/score/history``   — trend for the last N days
* ``POST /api/v1/posture/score/recompute`` — force a fresh posture score compute
* ``GET  /api/v1/posture/actions``         — top priority remediation actions

Every response is tenant-scoped by construction: ``organization_id`` is
drawn from the authenticated principal via :func:`get_current_user` and
is never accepted from a URL path, query string, or request body.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db  # type: ignore[import-not-found]
from app.api.rate_limit import rate_limit  # type: ignore[import-not-found]
from app.services.posture_score_engine import (
    ENGINE_VERSION,
    PostureScoreEngine,
    PostureScoreError,
)
from app.services.whatif_service import (
    SimulationType as WhatIfSimulationType,
    WhatIfError,
    WhatIfIdentityNotFound,
    WhatIfService,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/posture", tags=["posture"])


#: Cutoff for the "live" vs "stale" data freshness badge. Scores older
#: than this are considered stale and the dashboard should trigger a
#: recompute rather than render the row blind.
FRESHNESS_WINDOW = timedelta(hours=24)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class DimensionScores(BaseModel):
    """5 CVSS-aligned posture sub-scores — higher is better."""

    attack_surface: float = Field(..., ge=0.0, le=100.0)
    privilege: float = Field(..., ge=0.0, le=100.0)
    credentials: float = Field(..., ge=0.0, le=100.0)
    activity: float = Field(..., ge=0.0, le=100.0)
    governance: float = Field(..., ge=0.0, le=100.0)


class PostureScoreResponse(BaseModel):
    """Response body for ``GET /api/v1/posture/score``."""

    organization_id: int
    score_date: datetime
    overall_score: float = Field(..., ge=0.0, le=100.0)
    dimension_scores: DimensionScores
    identity_count: int = Field(..., ge=0)
    governed_count: int = Field(..., ge=0)
    orphaned_count: int = Field(..., ge=0)
    stale_count: int = Field(..., ge=0)
    at_risk_count: int = Field(..., ge=0)
    computed_by: str
    data_freshness: Literal["live", "stale"]


class PostureScoreHistoryRow(BaseModel):
    """Single history entry."""

    score_date: datetime
    overall_score: float = Field(..., ge=0.0, le=100.0)
    dimension_scores: DimensionScores
    identity_count: int = Field(..., ge=0)
    at_risk_count: int = Field(..., ge=0)


class PostureScoreHistoryResponse(BaseModel):
    """Response body for ``GET /api/v1/posture/score/history``."""

    organization_id: int
    days: int
    engine_version: str
    items: list[PostureScoreHistoryRow]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error_body(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"error": code, "detail": detail}
    body.update(extra)
    return body


def _raise_org_scope(reason: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_error_body("org_scope_error", reason),
    )


def _raise_internal(request: Request, exc: Exception) -> None:
    rid = request.headers.get("X-Request-Id") or "-"
    logger.exception(
        "posture_route.internal request_id=%s err=%s", rid, exc
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_error_body(
            "internal_error",
            "an internal error occurred — see server logs",
            request_id=rid,
        ),
    )


async def _current_org_id(current_user: Any = Depends(get_current_user)) -> int:
    """Extract the authenticated org_id as an int."""
    org_id = getattr(current_user, "organization_id", None)
    if not isinstance(org_id, str) or not org_id.strip():
        _raise_org_scope("authenticated user has no organization binding")
    try:
        return int(org_id.strip())
    except (TypeError, ValueError):
        _raise_org_scope("organization_id must be an integer")
        raise  # pragma: no cover


def _freshness(score_date: datetime) -> Literal["live", "stale"]:
    """Classify a posture row as ``"live"`` if younger than 24h."""
    now = datetime.now(timezone.utc)
    # Handle naive datetimes defensively — the DB column is timestamptz so
    # this should never fire, but aging a naive datetime against a timezone
    # aware ``now`` raises.
    if score_date.tzinfo is None:
        score_date = score_date.replace(tzinfo=timezone.utc)
    return "live" if (now - score_date) <= FRESHNESS_WINDOW else "stale"


def _row_to_dimensions(raw: Any) -> DimensionScores:
    """Coerce the raw JSONB ``dimension_scores`` into a typed DTO.

    Postgres returns ``dict`` for JSONB via asyncpg — no parsing needed.
    Missing keys are filled with ``0.0`` so a historical row written by
    an older engine version (which might lack a new dimension) still
    validates.
    """
    if isinstance(raw, dict):
        d = raw
    else:
        d = {}
    return DimensionScores(
        attack_surface=float(d.get("attack_surface") or 0.0),
        privilege=float(d.get("privilege") or 0.0),
        credentials=float(d.get("credentials") or 0.0),
        activity=float(d.get("activity") or 0.0),
        governance=float(d.get("governance") or 0.0),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/posture/score
# ---------------------------------------------------------------------------


@router.get(
    "/score",
    response_model=PostureScoreResponse,
    summary="Latest posture score",
    description=(
        "Return the most recent posture score row for the authenticated "
        "organization. If no row exists yet, ``PostureScoreEngine.compute`` "
        "is invoked inline so the very first call produces a row."
    ),
)
async def get_latest_posture_score(
    request: Request,
    organization_id: int = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PostureScoreResponse:
    engine = PostureScoreEngine(db)
    try:
        row = await engine.get_latest(organization_id)
        if row is None:
            row = await engine.compute(organization_id)
    except PostureScoreError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    score_date = row["score_date"]
    return PostureScoreResponse(
        organization_id=int(row["organization_id"]),
        score_date=score_date,
        overall_score=float(row["overall_score"]),
        dimension_scores=_row_to_dimensions(row["dimension_scores"]),
        identity_count=int(row["identity_count"] or 0),
        governed_count=int(row["governed_count"] or 0),
        orphaned_count=int(row["orphaned_count"] or 0),
        stale_count=int(row["stale_count"] or 0),
        at_risk_count=int(row["at_risk_count"] or 0),
        computed_by=str(row["computed_by"] or ENGINE_VERSION),
        data_freshness=_freshness(score_date),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/posture/score/history
# ---------------------------------------------------------------------------


@router.get(
    "/score/history",
    response_model=PostureScoreHistoryResponse,
    summary="Posture score history (trend)",
    description=(
        "Return the last ``days`` daily posture score rows in chronological "
        "order (ascending). Used by the CISO dashboard trend chart."
    ),
)
async def get_posture_score_history(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    organization_id: int = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> PostureScoreHistoryResponse:
    engine = PostureScoreEngine(db)
    try:
        rows = await engine.get_history(organization_id, days=days)
    except PostureScoreError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    items = [
        PostureScoreHistoryRow(
            score_date=r["score_date"],
            overall_score=float(r["overall_score"]),
            dimension_scores=_row_to_dimensions(r["dimension_scores"]),
            identity_count=int(r["identity_count"] or 0),
            at_risk_count=int(r["at_risk_count"] or 0),
        )
        for r in rows
    ]
    return PostureScoreHistoryResponse(
        organization_id=organization_id,
        days=days,
        engine_version=ENGINE_VERSION,
        items=items,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/posture/score/recompute
# ---------------------------------------------------------------------------


@router.post(
    "/score/recompute",
    response_model=PostureScoreResponse,
    summary="Recompute posture score",
    description=(
        "Trigger a fresh posture score computation for the authenticated "
        "organization. Idempotent per UTC calendar day — re-running on the "
        "same day overwrites the existing row."
    ),
)
async def recompute_posture_score(
    request: Request,
    organization_id: int = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
    _rl: None = Depends(rate_limit("recompute", max_calls=3, window_seconds=60)),
) -> PostureScoreResponse:
    engine = PostureScoreEngine(db)
    try:
        row = await engine.compute(organization_id)
    except PostureScoreError as exc:
        _raise_internal(request, exc)
        raise  # pragma: no cover

    score_date = row["score_date"]
    return PostureScoreResponse(
        organization_id=int(row["organization_id"]),
        score_date=score_date,
        overall_score=float(row["overall_score"]),
        dimension_scores=_row_to_dimensions(row["dimension_scores"]),
        identity_count=int(row["identity_count"] or 0),
        governed_count=int(row["governed_count"] or 0),
        orphaned_count=int(row["orphaned_count"] or 0),
        stale_count=int(row["stale_count"] or 0),
        at_risk_count=int(row["at_risk_count"] or 0),
        computed_by=str(row["computed_by"] or ENGINE_VERSION),
        data_freshness=_freshness(score_date),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/posture/actions
# ---------------------------------------------------------------------------


class PriorityActionItem(BaseModel):
    """Single priority action derived from current identity state."""

    action_type: str
    description: str
    affected_identity_count: int = Field(..., ge=0)
    estimated_score_impact: float
    identity_filter: str  # query string for list page


class PriorityActionsResponse(BaseModel):
    """Response body for ``GET /api/v1/posture/actions``."""

    organization_id: int
    actions: list[PriorityActionItem]


@router.get(
    "/actions",
    response_model=PriorityActionsResponse,
    summary="Top priority remediation actions",
    description=(
        "Return the top 5 highest-priority remediation actions derived from "
        "the current identity state. Computed on request, not stored. "
        "Cacheable for 5 minutes."
    ),
)
async def get_posture_actions(
    request: Request,
    organization_id: int = Depends(_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        actions = await _compute_priority_actions(organization_id, db)
    except Exception as exc:  # noqa: BLE001
        _raise_internal(request, exc)
        raise  # pragma: no cover

    resp = PriorityActionsResponse(
        organization_id=organization_id,
        actions=actions,
    )
    return JSONResponse(
        content=resp.model_dump(mode="json"),
        headers={"Cache-Control": "max-age=300"},
    )


async def _compute_priority_actions(
    org_id: int, db: AsyncSession
) -> list[PriorityActionItem]:
    """Derive top 5 priority actions from current identity data.

    Each action is computed from a SQL count against identity_list.
    Actions are sorted by estimated_score_impact descending.
    """
    actions: list[PriorityActionItem] = []

    # 1. Ungoverned identities — assign owners
    result = await db.execute(
        text(
            "SELECT COUNT(*) FROM identity_list "
            "WHERE organization_id = :org AND governance = 'Ungoverned'"
        ),
        {"org": org_id},
    )
    ungoverned = int(result.scalar() or 0)
    if ungoverned > 0:
        actions.append(PriorityActionItem(
            action_type="assign_owners",
            description=f"Assign owners to {ungoverned} ungoverned identities",
            affected_identity_count=ungoverned,
            estimated_score_impact=min(ungoverned * 2.0, 30.0),
            identity_filter="governance=ungoverned",
        ))

    # 2. Highly privileged identities — review privilege
    result = await db.execute(
        text(
            "SELECT COUNT(*) FROM identity_list "
            "WHERE organization_id = :org AND privilege_level = 'highly_privileged'"
        ),
        {"org": org_id},
    )
    highly_priv = int(result.scalar() or 0)
    if highly_priv > 0:
        actions.append(PriorityActionItem(
            action_type="review_privilege",
            description=f"Review {highly_priv} highly privileged identities for least-privilege",
            affected_identity_count=highly_priv,
            estimated_score_impact=min(highly_priv * 5.0, 25.0),
            identity_filter="privilege_level=highly_privileged",
        ))

    # 3. Dormant identities — disable or remove
    result = await db.execute(
        text(
            "SELECT COUNT(*) FROM identity_list "
            "WHERE organization_id = :org AND is_dormant = true"
        ),
        {"org": org_id},
    )
    dormant = int(result.scalar() or 0)
    if dormant > 0:
        actions.append(PriorityActionItem(
            action_type="disable_dormant",
            description=f"Disable or remove {dormant} dormant identities",
            affected_identity_count=dormant,
            estimated_score_impact=min(dormant * 1.5, 15.0),
            identity_filter="is_dormant=true",
        ))

    # 4. Critical risk identities — immediate remediation
    result = await db.execute(
        text(
            "SELECT COUNT(*) FROM identity_list "
            "WHERE organization_id = :org AND risk_label = 'Critical'"
        ),
        {"org": org_id},
    )
    critical = int(result.scalar() or 0)
    if critical > 0:
        actions.append(PriorityActionItem(
            action_type="remediate_critical",
            description=f"Remediate {critical} critical-risk identities immediately",
            affected_identity_count=critical,
            estimated_score_impact=min(critical * 8.0, 40.0),
            identity_filter="risk_label=critical",
        ))

    # 5. Orphaned identities — assign ownership
    result = await db.execute(
        text(
            "SELECT COUNT(*) FROM identity_list "
            "WHERE organization_id = :org AND governance = 'Orphaned'"
        ),
        {"org": org_id},
    )
    orphaned = int(result.scalar() or 0)
    if orphaned > 0:
        actions.append(PriorityActionItem(
            action_type="resolve_orphans",
            description=f"Resolve {orphaned} orphaned identities — assign or decommission",
            affected_identity_count=orphaned,
            estimated_score_impact=min(orphaned * 3.0, 20.0),
            identity_filter="governance=orphaned",
        ))

    # Sort by impact descending, take top 5
    actions.sort(key=lambda a: a.estimated_score_impact, reverse=True)
    return actions[:5]


# ---------------------------------------------------------------------------
# POST /api/v1/posture/simulate/bulk
# ---------------------------------------------------------------------------


class BulkSimulationRequest(BaseModel):
    """Request body for bulk simulation."""

    identity_ids: list[str] = Field(
        ..., min_length=1, max_length=50,
        description="List of identity IDs to simulate (max 50).",
    )
    simulation_type: WhatIfSimulationType
    payload: dict[str, Any] = Field(default_factory=dict)


class BulkSimulationResult(BaseModel):
    """Response body for bulk simulation."""

    total: int
    completed: int
    failed: int
    aggregate_score_delta: float
    aggregate_blast_radius_delta: int
    simulation_ids: list[str]
    failures: list[dict[str, str]] = Field(default_factory=list)


@router.post(
    "/simulate/bulk",
    response_model=BulkSimulationResult,
    summary="Run bulk what-if simulation",
    description=(
        "Run a what-if simulation against up to 50 identities. Each "
        "simulation runs independently — one failure does not abort "
        "the others. Returns 207 Multi-Status if any simulations failed."
    ),
)
async def bulk_simulate(
    request: Request,
    body: BulkSimulationRequest,
    organization_id: int = Depends(_current_org_id),
    current_user: Any = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _rl: None = Depends(rate_limit("bulk_simulate", max_calls=5, window_seconds=60)),
) -> JSONResponse:
    simulated_by = getattr(current_user, "user_id", None)
    if simulated_by is not None:
        try:
            simulated_by = int(simulated_by)
        except (TypeError, ValueError):
            simulated_by = None

    service = WhatIfService(db)
    simulation_ids: list[str] = []
    failures: list[dict[str, str]] = []
    aggregate_score_delta = 0.0
    aggregate_blast_delta = 0

    for identity_id in body.identity_ids:
        try:
            result = await service.simulate(
                organization_id=organization_id,
                identity_id=identity_id,
                simulation_type=body.simulation_type,
                payload=body.payload,
                simulated_by=simulated_by,
            )
            simulation_ids.append(result.simulation_id or "")
            aggregate_score_delta += result.score_delta
            aggregate_blast_delta += (
                result.blast_radius_after - result.blast_radius_before
            )
        except (WhatIfIdentityNotFound, WhatIfError, ValueError) as exc:
            failures.append({
                "identity_id": identity_id,
                "error": str(exc),
            })

    completed = len(simulation_ids)
    failed = len(failures)

    resp = BulkSimulationResult(
        total=len(body.identity_ids),
        completed=completed,
        failed=failed,
        aggregate_score_delta=round(aggregate_score_delta, 2),
        aggregate_blast_radius_delta=aggregate_blast_delta,
        simulation_ids=simulation_ids,
        failures=failures,
    )

    http_status = 207 if failed > 0 and completed > 0 else (
        200 if failed == 0 else 500
    )
    return JSONResponse(
        content=resp.model_dump(mode="json"),
        status_code=http_status,
    )
