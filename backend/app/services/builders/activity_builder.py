"""
ActivityBuilder + RolesLoader
=============================

B02 activity-state builder and the colocated B07 role-assignment loader.

Phase 1
-------
* :class:`ActivityBuilder.build` reads ``identity_activity`` /
  ``identity_activity_snapshots`` and emits ``lifecycle_state``,
  ``last_sign_in_at``, ``last_activity_at``, plus a boolean
  ``is_dormant`` derived from the lifecycle state. No 6-signal
  ActivitySignals yet — the builder refuses to invent confidence
  it does not have.
* :class:`RolesLoader.load` reads ``identity_role_assignments`` /
  ``identity_role_assignments_snapshots`` and projects each row onto
  a :class:`RoleAssignment` with its embedded :class:`RoleUsage`.

Why RolesLoader is colocated with ActivityBuilder
-------------------------------------------------
Every ``RoleAssignment`` carries a ``used`` / ``confidence`` /
``evidence`` triple inside its embedded :class:`RoleUsage`. That is
semantically an activity signal attached to each assignment, not a
static privilege attribute, so it belongs in the activity module
rather than the profile module.

Phase 2 hook
------------
:meth:`ActivityBuilder.build_full` is declared today as a
``NotImplementedError`` so downstream callers can migrate imports
without waiting for the 6-signal ActivitySignals (B15) work to land.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import (
    ActivityState,
    BUILDER_STALENESS_HOURS,
    BuilderDataSource,
    Confidence,
    DataMode,
    LifecycleState,
    RoleAssignment,
    RoleSource,
    RoleUsage,
    RolesBlock,
    ScopeBreadth,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ActivityBuildError(Exception):
    """Generic failure inside the activity / roles loaders."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class OrganizationScopeError(ActivityBuildError):
    """A DB row leaked across the org boundary — hard security failure."""


# ---------------------------------------------------------------------------
# Internal helpers (duplicated per module so each builder is independently
# testable without reaching into a sibling module's private surface)
# ---------------------------------------------------------------------------


def _require_org(organization_id: str) -> str:
    if not isinstance(organization_id, str) or not organization_id.strip():
        raise ValueError("organization_id is required and must be a non-empty string")
    return organization_id


def _source_table(live: str, snap: str, data_mode: DataMode) -> str:
    return snap if data_mode == DataMode.SNAPSHOT else live


def _snapshot_params(
    *,
    identity_id: str,
    organization_id: str,
    snapshot_id: Optional[int],
) -> tuple[str, dict[str, Any]]:
    """Build common params dict, casting org id to int for asyncpg strict typing."""
    try:
        org_int = int(organization_id)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"organization_id must be numeric for DB binding, got {organization_id!r}"
        ) from exc
    params: dict[str, Any] = {"id": identity_id, "org": org_int}
    snap_clause = ""
    if snapshot_id is not None:
        params["sid"] = snapshot_id
        snap_clause = " AND snapshot_id = :sid"
    return snap_clause, params


def _assert_row_scope(
    row: Mapping[str, Any],
    *,
    expected_org: str,
    identity_id: str,
) -> None:
    if not isinstance(row, Mapping):
        return
    row_org = row.get("organization_id")
    if row_org is None:
        return
    if str(row_org) != str(expected_org):
        raise OrganizationScopeError(
            "row organization_id does not match builder binding",
            context={
                "expected_organization_id": expected_org,
                "row_organization_id": row_org,
                "identity_id": identity_id,
            },
        )


# ===========================================================================
# ActivityBuilder — B02
# ===========================================================================


class ActivityBuilder:
    """Loads the B02 :class:`ActivityState` for an identity.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the builder.
    db:
        Async SQLAlchemy session managed by the caller. The builder
        never commits or rolls back on its own.

    Notes
    -----
    Phase 1 only derives ``is_dormant`` from the lifecycle state
    returned by the persistence layer. The 6-signal ActivitySignals
    (B15) work will be exposed via :meth:`build_full` in Phase 2.
    """

    def __init__(self, organization_id: str, db: AsyncSession) -> None:
        self._organization_id = _require_org(organization_id)
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        self._db = db

    async def build(
        self,
        identity_id: str,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> ActivityState:
        """Read the activity row and project it onto :class:`ActivityState`.

        When no activity row exists for the identity, the builder
        returns a :class:`LifecycleState.PROVISIONED` default with
        ``activity_confidence=Confidence.NONE`` — we never invent a
        ``last_sign_in_at`` the infrastructure has not actually seen.
        """
        if not identity_id:
            raise ValueError("identity_id is required")

        table = _source_table(
            "identity_activity", "identity_activity_snapshots", data_mode
        )
        snap_clause, params = _snapshot_params(
            identity_id=identity_id,
            organization_id=self._organization_id,
            snapshot_id=snapshot_id,
        )

        try:
            result = await self._db.execute(
                text(
                    f"""
                    SELECT organization_id, lifecycle_state, last_sign_in_at,
                           last_activity_at, activity_confidence, has_p2_telemetry,
                           updated_at
                    FROM {table}
                    WHERE identity_id     = :id
                      AND organization_id = CAST(:org AS INTEGER)
                      {snap_clause}
                    LIMIT 1
                    """
                ),
                params,
            )
            row = result.mappings().first()
        except SQLAlchemyError as exc:
            raise ActivityBuildError(
                "database error loading activity state",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        if row is None:
            return ActivityState(
                organization_id=self._organization_id,
                lifecycle_state=LifecycleState.PROVISIONED,
                last_sign_in_at=None,
                last_activity_at=None,
                days_since_last_activity=None,
                activity_confidence=Confidence.NONE,
                is_dormant=False,
                has_p2_telemetry=False,
                data_source=BuilderDataSource.NONE,
                missing_signals=[
                    "last_sign_in_at",
                    "last_activity_at",
                    "lifecycle_state",
                ],
            )

        _assert_row_scope(
            row, expected_org=self._organization_id, identity_id=identity_id
        )

        last_activity = row["last_activity_at"] or row["last_sign_in_at"]
        days_since: Optional[int] = None
        if last_activity is not None:
            days_since = max(0, (datetime.now(timezone.utc) - last_activity).days)

        lifecycle = LifecycleState(row["lifecycle_state"])
        is_dormant = lifecycle == LifecycleState.DORMANT

        # E2: determine data_source from row content + staleness
        missing: list[str] = []
        if row["last_sign_in_at"] is None:
            missing.append("last_sign_in_at")
        if row["last_activity_at"] is None:
            missing.append("last_activity_at")

        now = datetime.now(timezone.utc)
        updated_at = row["updated_at"]
        if updated_at is not None:
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            age = now - updated_at
            is_stale = age > timedelta(hours=BUILDER_STALENESS_HOURS)
        else:
            is_stale = False

        if is_stale:
            ds = BuilderDataSource.STALE
        elif missing:
            ds = BuilderDataSource.PARTIAL
        else:
            ds = BuilderDataSource.FULL

        return ActivityState(
            organization_id=self._organization_id,
            lifecycle_state=lifecycle,
            last_sign_in_at=row["last_sign_in_at"],
            last_activity_at=row["last_activity_at"],
            days_since_last_activity=days_since,
            activity_confidence=Confidence(row["activity_confidence"]),
            is_dormant=is_dormant,
            has_p2_telemetry=bool(row["has_p2_telemetry"]),
            data_source=ds,
            missing_signals=missing,
        )

    async def build_full(
        self,
        identity_id: str,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> ActivityState:
        """Phase 2 entry point for the 6-signal ActivitySignals (B15).

        Declared today as a ``NotImplementedError`` so downstream
        callers can migrate imports ahead of the implementation
        landing.
        """
        raise NotImplementedError(
            "Phase 2: ActivityBuilder.build_full() will implement the "
            "6-signal B15 ActivitySignals work"
        )


# ===========================================================================
# RolesLoader — B07
# ===========================================================================


class RolesLoader:
    """Loads the B07 :class:`RolesBlock` with per-assignment usage telemetry.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the loader.
    db:
        Async SQLAlchemy session managed by the caller.
    """

    def __init__(self, organization_id: str, db: AsyncSession) -> None:
        self._organization_id = _require_org(organization_id)
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        self._db = db

    async def load(
        self,
        identity_id: str,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> RolesBlock:
        """Read the role-assignment rows and project each onto :class:`RoleAssignment`."""
        if not identity_id:
            raise ValueError("identity_id is required")

        table = _source_table(
            "identity_role_assignments",
            "identity_role_assignments_snapshots",
            data_mode,
        )
        snap_clause, params = _snapshot_params(
            identity_id=identity_id,
            organization_id=self._organization_id,
            snapshot_id=snapshot_id,
        )

        try:
            result = await self._db.execute(
                text(
                    f"""
                    SELECT organization_id, role_name, role_key, scope,
                           scope_level, source, usage_used, usage_confidence,
                           usage_evidence
                    FROM {table}
                    WHERE identity_id     = :id
                      AND organization_id = CAST(:org AS INTEGER)
                      {snap_clause}
                    """
                ),
                params,
            )
            rows = result.mappings().all()
        except SQLAlchemyError as exc:
            raise ActivityBuildError(
                "database error loading role assignments",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        roles: list[RoleAssignment] = []
        for row in rows:
            _assert_row_scope(
                row, expected_org=self._organization_id, identity_id=identity_id
            )
            roles.append(
                RoleAssignment(
                    organization_id=self._organization_id,
                    role_name=row["role_name"],
                    role_key=str(row["role_key"]).lower(),
                    scope=row["scope"],
                    scope_level=ScopeBreadth(row["scope_level"]),
                    source=RoleSource(row["source"]),
                    usage=RoleUsage(
                        organization_id=self._organization_id,
                        used=bool(row["usage_used"]),
                        confidence=Confidence(row["usage_confidence"]),
                        evidence=row["usage_evidence"] or "",
                    ),
                )
            )

        return RolesBlock(organization_id=self._organization_id, roles=roles)
