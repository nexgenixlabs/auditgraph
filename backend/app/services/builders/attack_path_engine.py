"""
AttackPathEngine — B08
======================

Phase 1 loader for the B08 :class:`AttackPathsBlock`.

Phase 1
-------
:meth:`AttackPathEngine.compute` is a direct read of the pre-computed
``identity_attack_paths`` / ``identity_attack_paths_snapshots`` table.
The discovery pipeline is responsible for populating that table; this
engine only projects rows onto the canonical schema and enforces the
same organization-scope guard as every other builder.

Phase 2 hook
------------
:meth:`AttackPathEngine.compute_graph` is declared today as a
``NotImplementedError`` so callers can migrate imports ahead of the
graph-traversal implementation landing. The Phase 2 work will walk
the role/permission graph at build time instead of relying on
pre-materialized rows.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import (
    AttackPath,
    AttackPathsBlock,
    CloudProvider,
    DataMode,
    PrivilegeBlock,
    Resource,
    ResourceType,
    RiskLabel,
    SensitivityLevel,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AttackPathBuildError(Exception):
    """Generic failure while loading attack paths."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class OrganizationScopeError(AttackPathBuildError):
    """A DB row leaked across the org boundary — hard security failure."""


# ---------------------------------------------------------------------------
# Internal helpers (duplicated per module so each engine is independently
# testable without reaching into a sibling module's private surface)
# ---------------------------------------------------------------------------


def _require_org(organization_id: str) -> str:
    if not isinstance(organization_id, str) or not organization_id.strip():
        raise ValueError("organization_id is required and must be a non-empty string")
    return organization_id


def _source_table(live: str, snap: str, data_mode: DataMode) -> str:
    return snap if data_mode == DataMode.SNAPSHOT else live


def _assert_row_scope(
    row: Mapping[str, Any],
    *,
    expected_org: str,
    identity_id: str,
) -> None:
    row_org = row.get("organization_id") if isinstance(row, Mapping) else None
    if row_org is not None and row_org != expected_org:
        raise OrganizationScopeError(
            "row organization_id does not match engine binding",
            context={
                "expected_organization_id": expected_org,
                "row_organization_id": row_org,
                "identity_id": identity_id,
            },
        )


# ===========================================================================
# AttackPathEngine
# ===========================================================================


class AttackPathEngine:
    """Loads the B08 :class:`AttackPathsBlock` for an identity.

    Parameters
    ----------
    organization_id:
        Owning tenant. Threaded into every query and re-verified on
        every row.
    db:
        Async SQLAlchemy session managed by the caller.
    """

    def __init__(self, organization_id: str, db: AsyncSession) -> None:
        self._organization_id = _require_org(organization_id)
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        self._db = db

    async def compute(
        self,
        identity_id: str,
        privilege: PrivilegeBlock,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> AttackPathsBlock:
        """Read the materialized attack-path rows for ``identity_id``.

        ``privilege`` is accepted for symmetry with the Phase 2 hook
        (:meth:`compute_graph`), which will need the privilege block
        as a traversal-priors input. In Phase 1 the privilege block
        is not read.
        """
        _ = privilege  # reserved for Phase 2 graph traversal
        if not identity_id:
            raise ValueError("identity_id is required")

        table = _source_table(
            "identity_attack_paths", "identity_attack_paths_snapshots", data_mode
        )
        snap_clause = " AND snapshot_id = :sid" if data_mode == DataMode.SNAPSHOT else ""
        try:
            org_int = int(self._organization_id)
        except (TypeError, ValueError) as exc:
            raise AttackPathBuildError(
                "organization_id must be numeric for DB binding",
                context={"organization_id": self._organization_id},
            ) from exc
        params: dict[str, Any] = {
            "id": identity_id,
            "org": org_int,
        }
        if snapshot_id is not None:
            params["sid"] = snapshot_id

        try:
            result = await self._db.execute(
                text(
                    f"""
                    SELECT organization_id, path_id, path_type,
                           source_identity_uuid, target_resource_id,
                           target_global_identity_id, target_cloud_id,
                           target_type, target_name, target_sensitivity,
                           severity, score, chain, mitre_techniques
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
            raise AttackPathBuildError(
                "database error loading attack paths",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                },
            ) from exc

        paths: list[AttackPath] = []
        for row in rows:
            _assert_row_scope(
                row, expected_org=self._organization_id, identity_id=identity_id
            )
            target = Resource(
                organization_id=self._organization_id,
                id=row["target_resource_id"],
                global_identity_id=row["target_global_identity_id"],
                cloud_id=CloudProvider(row["target_cloud_id"]),
                type=ResourceType(row["target_type"]),
                name=row["target_name"],
                sensitivity=SensitivityLevel(row["target_sensitivity"]),
            )
            paths.append(
                AttackPath(
                    organization_id=self._organization_id,
                    path_id=row["path_id"],
                    path_type=row["path_type"],
                    source_identity_id=row["source_identity_uuid"],
                    target=target,
                    severity=RiskLabel(row["severity"]),
                    score=float(row["score"]),
                    chain=list(row["chain"] or []),
                    mitre_techniques=list(row["mitre_techniques"] or []),
                )
            )

        return AttackPathsBlock(
            organization_id=self._organization_id,
            paths=paths,
        )

    async def compute_graph(
        self,
        identity_id: str,
        privilege: PrivilegeBlock,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> AttackPathsBlock:
        """Phase 2 hook for graph-traversal attack-path computation.

        Not implemented yet — declared so callers can migrate imports
        ahead of the graph-traversal implementation landing. Phase 2
        will walk the role / permission graph at build time instead
        of reading pre-materialized rows.
        """
        raise NotImplementedError(
            "Phase 2: AttackPathEngine.compute_graph() will walk the role "
            "graph at build time instead of reading pre-materialized rows"
        )
