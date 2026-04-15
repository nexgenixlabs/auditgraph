"""
IdentityProfileBuilder + colocated DB loaders
=============================================

DB-backed loaders that feed the identity state orchestrator:

* :class:`IdentityProfileBuilder` — B01 profile (main class). Owns the
  F1 registry resolution and the F3 :class:`DataContext` stamping.
* :class:`OwnershipBuilder` — B03 ownership block.
* :class:`PrivilegeBuilder` — B05 privilege block.
* :class:`CredentialLoader` — credential rotation status (a scalar
  input to both B06 risk scoring and B09 remediation).

Why these four classes share a file
-----------------------------------
They are the single-query, org-bound, read-only loaders that together
populate the identity's static identity data. Colocating them lets the
orchestrator import a small, coherent surface without stripping
business logic back into the orchestrator itself — every SQL statement
and every scope guard lives here.

Every loader:
  * binds ``organization_id`` at construction time,
  * threads that org id into every query,
  * re-verifies the returned row's ``organization_id`` before
    emitting a domain object.

Module-level constants
----------------------
``OWNERSHIP_RECENT_DAYS`` is the single source of truth for the
"recent review" threshold. It is duplicated deliberately in
:mod:`governance_engine` as ``GOVERNANCE_RECENT_REVIEW_DAYS`` — the
two windows are conceptually the same today but the governance engine
reserves the right to tighten its value independently.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import (
    BuilderDataSource,
    CloudProvider,
    Confidence,
    DataContext,
    DataMode,
    IdentityOwner,
    IdentityProfile,
    IdentitySource,
    IdentityStatus,
    IdentityType,
    OwnerQuality,
    OwnershipBlock,
    PrivilegeBlock,
    PrivilegeLevel,
    RotationStatus,
    ScopeBreadth,
)
from app.services.global_identity_registry import GlobalIdentityRegistry


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defensive enum helpers (consolidated in enum_aliases.py)
# ---------------------------------------------------------------------------

from app.services.builders.enum_aliases import safe_enum as _safe_enum  # noqa: E402
from app.services.builders.enum_aliases import safe_identity_type as _safe_identity_type  # noqa: E402


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


#: Ownership "recent activity" window. An owner whose last_active_days is
#: within this threshold counts as an active owner.
OWNERSHIP_RECENT_DAYS: int = 90


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProfileBuildError(Exception):
    """Generic failure inside a profile-adjacent loader."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class IdentityNotFoundError(ProfileBuildError):
    """The requested identity does not exist under this organization."""


class OrganizationScopeError(ProfileBuildError):
    """A DB row leaked across the org boundary — hard security failure."""


# ---------------------------------------------------------------------------
# Internal helpers
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
    """Build the common ``WHERE`` tail + parameter dict shared by every loader.

    ``organization_id`` is cast to ``int`` on the way out because the
    DB column is ``INTEGER`` and asyncpg refuses to coerce ``str`` → ``int``
    at bind time (even with an explicit SQL CAST). The Python-side str
    invariant from deps.py is preserved — the ``int()`` happens only at
    the SQL boundary.
    """
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
    """Raise :class:`OrganizationScopeError` if ``row`` crosses tenant lines.

    The DB column is ``INTEGER`` so the returned value is ``int``, while
    ``expected_org`` is the str-normalized principal from the JWT
    boundary. Compare both as strings to avoid spurious type mismatches.
    """
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
# IdentityProfileBuilder — B01
# ===========================================================================


class IdentityProfileBuilder:
    """Builds B01 :class:`IdentityProfile` from raw DB row + registry resolution.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the builder.
    registry:
        :class:`GlobalIdentityRegistry` used to resolve the F1
        ``global_identity_id`` when the row does not carry one.
    db:
        Async SQLAlchemy session managed by the caller. The builder
        never commits or rolls back on its own.

    Raises
    ------
    ValueError
        If ``organization_id`` is empty or ``db`` / ``registry`` is
        ``None``.
    """

    def __init__(
        self,
        organization_id: str,
        registry: GlobalIdentityRegistry,
        db: AsyncSession,
    ) -> None:
        self._organization_id: str = _require_org(organization_id)
        if registry is None:
            raise ValueError("registry (GlobalIdentityRegistry) is required")
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        self._registry: GlobalIdentityRegistry = registry
        self._db: AsyncSession = db

    async def build(
        self,
        identity_id: str,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> IdentityProfile:
        """Read the identity row and project it onto :class:`IdentityProfile`.

        * Reads from ``identities`` (live) or ``identity_snapshots_rows``
          (snapshot) based on ``data_mode``.
        * Resolves the F1 ``global_identity_id`` via the registry if the
          row does not already carry one.
        * Stamps a fresh :class:`DataContext` matching the requested
          mode. The orchestrator will later overwrite ``is_stale`` once
          it knows the wall-clock age of the full build.
        """
        if not identity_id:
            raise ValueError("identity_id is required")

        table = _source_table("identities", "identity_snapshots_rows", data_mode)
        snap_clause, params = _snapshot_params(
            identity_id=identity_id,
            organization_id=self._organization_id,
            snapshot_id=snapshot_id,
        )

        try:
            result = await self._db.execute(
                text(
                    f"""
                    SELECT organization_id, global_identity_id, identity_id,
                           object_id, display_name, user_principal_name,
                           identity_type, cloud_id, source, status,
                           is_federated_identity, federated_from,
                           created_at, last_modified_at, discovered_at
                    FROM {table}
                    WHERE identity_id      = :id
                      AND organization_id  = CAST(:org AS INTEGER)
                      {snap_clause}
                    LIMIT 1
                    """
                ),
                params,
            )
            row = result.mappings().first()
        except SQLAlchemyError as exc:
            raise ProfileBuildError(
                "database error loading identity profile",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        if row is None:
            raise IdentityNotFoundError(
                "identity not found",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            )
        _assert_row_scope(
            row, expected_org=self._organization_id, identity_id=identity_id
        )

        gid = row["global_identity_id"]
        if gid is None:
            gid = await self._resolve_global_identity_id(row, identity_id)

        data_context = DataContext(
            data_mode=data_mode,
            snapshot_id=snapshot_id,
            snapshot_date=None,
            computed_at=datetime.now(timezone.utc),
            is_stale=False,
        )

        return IdentityProfile(
            organization_id=self._organization_id,
            global_identity_id=gid,
            identity_id=row["identity_id"],
            object_id=row["object_id"],
            display_name=row["display_name"],
            user_principal_name=row["user_principal_name"],
            identity_type=_safe_identity_type(row["identity_type"]),
            cloud_id=_safe_enum(CloudProvider, row["cloud_id"], CloudProvider.AZURE),
            source=_safe_enum(IdentitySource, row["source"], IdentitySource.AZURE_AD),
            status=_safe_enum(IdentityStatus, row["status"], IdentityStatus.ACTIVE),
            is_federated_identity=bool(row["is_federated_identity"]),
            federated_from=row["federated_from"],
            created_at=row["created_at"],
            last_modified_at=row["last_modified_at"],
            discovered_at=row["discovered_at"],
            data_context=data_context,
        )

    async def _resolve_global_identity_id(
        self,
        row: Mapping[str, Any],
        identity_id: str,
    ) -> uuid.UUID:
        """Safe fallback when the DB row has no ``global_identity_id``.

        Phase 1 behavior matches the legacy monolith: we emit a fresh
        :func:`uuid.uuid4` so the profile remains buildable. The
        ``registry`` dependency is held on the builder so a future
        Phase 2 implementation can call ``registry.resolve(...)`` with
        the full provider context without changing the constructor.
        """
        logger.debug(
            "identity_profile.missing_global_identity_id org=%s id=%s — "
            "falling back to fresh uuid4()",
            self._organization_id,
            identity_id,
        )
        return uuid.uuid4()


# ===========================================================================
# OwnershipBuilder — B03
# ===========================================================================


class OwnershipBuilder:
    """Builds the B03 :class:`OwnershipBlock` for an identity.

    Emits ``OwnerQuality``, the latest review timestamp, and the
    ``requires_attestation`` flag derived from
    :data:`OWNERSHIP_RECENT_DAYS`.
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
    ) -> OwnershipBlock:
        table = _source_table(
            "identity_owners", "identity_owners_snapshots", data_mode
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
                    SELECT organization_id, owner_id, owner_name, owner_type,
                           last_active_days, has_reviewed, last_review_at
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
            raise ProfileBuildError(
                "database error loading ownership",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        # E2 State 0: no rows
        if not rows:
            return OwnershipBlock(
                organization_id=self._organization_id,
                owner_quality=OwnerQuality.NO_OWNER,
                owners=[],
                last_review_at=None,
                days_since_last_review=None,
                requires_attestation=True,
                confidence=Confidence.NONE,
                data_source=BuilderDataSource.NONE,
                missing_signals=["owners", "last_review_at"],
            )

        owners: list[IdentityOwner] = []
        latest_review: Optional[datetime] = None
        has_missing_type = False

        for row in rows:
            _assert_row_scope(
                row, expected_org=self._organization_id, identity_id=identity_id
            )
            if row["last_review_at"] is not None:
                if latest_review is None or row["last_review_at"] > latest_review:
                    latest_review = row["last_review_at"]
            if not row["owner_type"]:
                has_missing_type = True
            owners.append(
                IdentityOwner(
                    organization_id=self._organization_id,
                    id=row["owner_id"],
                    name=row["owner_name"],
                    type=row["owner_type"] or "unknown",
                    last_active_days=row["last_active_days"],
                    has_reviewed=bool(row["has_reviewed"]),
                )
            )

        owner_quality = self._derive_owner_quality(owners)
        days_since_review: Optional[int] = None
        if latest_review is not None:
            days_since_review = max(
                0, (datetime.now(timezone.utc) - latest_review).days
            )

        requires_attestation = (
            owner_quality != OwnerQuality.ACTIVE_OWNER
            or (
                days_since_review is not None
                and days_since_review > OWNERSHIP_RECENT_DAYS
            )
        )

        # E2: derive data_source + confidence
        missing: list[str] = []
        if has_missing_type:
            missing.append("owner_type")
        if latest_review is None:
            missing.append("last_review_at")

        if missing:
            ds = BuilderDataSource.PARTIAL
            conf = Confidence.LOW
        else:
            ds = BuilderDataSource.FULL
            conf = Confidence.HIGH

        return OwnershipBlock(
            organization_id=self._organization_id,
            owner_quality=owner_quality,
            owners=owners,
            last_review_at=latest_review,
            days_since_last_review=days_since_review,
            requires_attestation=requires_attestation,
            confidence=conf,
            data_source=ds,
            missing_signals=missing,
        )

    @staticmethod
    def _derive_owner_quality(owners: list[IdentityOwner]) -> OwnerQuality:
        if not owners:
            return OwnerQuality.NO_OWNER
        has_active = any(
            o.last_active_days is not None
            and o.last_active_days <= OWNERSHIP_RECENT_DAYS
            for o in owners
        )
        return OwnerQuality.ACTIVE_OWNER if has_active else OwnerQuality.INACTIVE_OWNER


# ===========================================================================
# PrivilegeBuilder — B05
# ===========================================================================


class PrivilegeBuilder:
    """Builds the B05 :class:`PrivilegeBlock` summary row."""

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
    ) -> PrivilegeBlock:
        table = _source_table(
            "identity_privilege_summary",
            "identity_privilege_summary_snapshots",
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
                    SELECT organization_id, privilege_level, scope_breadth,
                           highly_privileged_role_count, privileged_role_count,
                           standard_role_count, total_role_count,
                           can_escalate, blast_radius_resource_count
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
            raise ProfileBuildError(
                "database error loading privilege summary",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        if row is None:
            return PrivilegeBlock(
                organization_id=self._organization_id,
                privilege_level=PrivilegeLevel.STANDARD,
                scope_breadth=ScopeBreadth.RESOURCE,
                highly_privileged_role_count=0,
                privileged_role_count=0,
                standard_role_count=0,
                total_role_count=0,
                can_escalate=False,
                blast_radius_resource_count=0,
                confidence=Confidence.NONE,
                data_source=BuilderDataSource.NONE,
                missing_signals=[
                    "privilege_level",
                    "scope_breadth",
                    "total_role_count",
                ],
            )
        _assert_row_scope(
            row, expected_org=self._organization_id, identity_id=identity_id
        )

        return PrivilegeBlock(
            organization_id=self._organization_id,
            privilege_level=PrivilegeLevel(row["privilege_level"]),
            scope_breadth=ScopeBreadth(row["scope_breadth"]),
            highly_privileged_role_count=int(row["highly_privileged_role_count"] or 0),
            privileged_role_count=int(row["privileged_role_count"] or 0),
            standard_role_count=int(row["standard_role_count"] or 0),
            total_role_count=int(row["total_role_count"] or 0),
            can_escalate=bool(row["can_escalate"]),
            blast_radius_resource_count=int(row["blast_radius_resource_count"] or 0),
            confidence=Confidence.HIGH,
            data_source=BuilderDataSource.FULL,
            missing_signals=[],
        )


# ===========================================================================
# CredentialLoader — scalar input to B06 + B09
# ===========================================================================


class CredentialLoader:
    """Loads the identity's most severe :class:`RotationStatus`.

    Returns :attr:`RotationStatus.NO_CREDENTIALS` when the identity has
    no credential rows — a signal the risk engine treats as mild
    (service principals with managed identity only, etc.).
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
    ) -> RotationStatus:
        table = _source_table(
            "identity_credentials", "identity_credentials_snapshots", data_mode
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
                    SELECT organization_id, rotation_status
                    FROM {table}
                    WHERE identity_id     = :id
                      AND organization_id = CAST(:org AS INTEGER)
                      {snap_clause}
                    ORDER BY rotation_status_priority DESC
                    LIMIT 1
                    """
                ),
                params,
            )
            row = result.mappings().first()
        except SQLAlchemyError as exc:
            raise ProfileBuildError(
                "database error loading credential status",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        if row is None:
            return RotationStatus.NO_CREDENTIALS
        _assert_row_scope(
            row, expected_org=self._organization_id, identity_id=identity_id
        )
        return RotationStatus(row["rotation_status"])
