"""
ResourceBatchLoader — batch resource fetcher for graph traversal.

Single SQL surface for all resource lookups in the graph pipeline.
Never fetches per-resource. Always batches.

Design rules
------------
* **Never ``SELECT *``** — every column is enumerated so schema drift
  surfaces as a KeyError in tests instead of a silent payload change.
* **Every query is tenant-scoped.** ``WHERE organization_id = :org``
  is non-negotiable. Every returned row is *also* re-verified via
  :meth:`_assert_org_scope` — defense in depth against RLS regressions.
* **Empty input never touches the DB** — callers may pass an empty list
  safely and get back an empty dict.
* **Dedupe on the way in.** Callers commonly pass overlapping ids;
  :meth:`_prepare_ids` dedupes + preserves order for stable traces.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import DataMode, SensitivityLevel


logger = logging.getLogger(__name__)


#: Hard cap on how many ids may be passed into a single batch. Callers
#: that need more must chunk — this keeps any one query bounded.
MAX_BATCH_SIZE: int = 500


#: Canonical sensitivity ordering. Higher rank = more sensitive.
#: Import from here — never redefine locally.
SENSITIVITY_RANK: dict[SensitivityLevel, int] = {
    SensitivityLevel.CRITICAL: 5,
    SensitivityLevel.HIGH: 4,
    SensitivityLevel.MEDIUM: 3,
    SensitivityLevel.LOW: 2,
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class BatchSizeExceededError(ValueError):
    """Raised when a caller passes more than :data:`MAX_BATCH_SIZE` ids."""


class ResourceScopeError(RuntimeError):
    """A DB row leaked across the org boundary — hard security failure."""


# ---------------------------------------------------------------------------
# ResourceBatchLoader
# ---------------------------------------------------------------------------


class ResourceBatchLoader:
    """Batch resource loader. Every public method issues exactly one query.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the loader and
        threaded into every query and row-level check.
    db:
        Async SQLAlchemy session managed by the caller. The loader
        never commits or rolls back on its own.
    """

    #: Columns projected by :meth:`fetch` and
    #: :meth:`fetch_above_sensitivity`. Enumerated on purpose.
    _FULL_COLUMNS: tuple[str, ...] = (
        "organization_id",
        "id",
        "global_identity_id",
        "cloud_id",
        "cloud_provider",
        "type",
        "name",
        "sensitivity",
    )

    def __init__(self, organization_id: str, db: AsyncSession) -> None:
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise ValueError("organization_id is required and must be a non-empty string")
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        self._org_id: str = organization_id
        self._db: AsyncSession = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch(
        self,
        resource_ids: list[str],
        data_mode: DataMode = DataMode.LIVE,
        snapshot_id: Optional[int] = None,
    ) -> dict[str, dict[str, Any]]:
        """Batch-load resource rows by id.

        Parameters
        ----------
        resource_ids:
            Provider-native ids to fetch. Deduped. Empty list returns
            ``{}`` without touching the DB.
        data_mode:
            :attr:`DataMode.LIVE` queries ``resources``;
            :attr:`DataMode.SNAPSHOT` queries ``resource_snapshots``
            at ``snapshot_id``.
        snapshot_id:
            Required iff ``data_mode == DataMode.SNAPSHOT``.

        Returns
        -------
        dict
            Mapping ``{resource_id: row_dict}``. Missing ids are absent
            from the result — not an error. Every row has been
            org-scope verified.

        Raises
        ------
        BatchSizeExceededError
            ``len(resource_ids) > MAX_BATCH_SIZE``.
        ValueError
            Invariant violation on ``data_mode`` / ``snapshot_id``.
        ResourceScopeError
            A row leaked across the org boundary.
        """
        self._validate_mode(data_mode, snapshot_id)
        ids = self._prepare_ids(resource_ids)
        if not ids:
            return {}

        table, snap_clause = self._table_for(data_mode)
        columns_sql = ", ".join(self._FULL_COLUMNS)
        params: dict[str, Any] = {"org": int(self._org_id), "ids": ids}
        if data_mode == DataMode.SNAPSHOT:
            params["sid"] = snapshot_id

        sql = text(
            f"""
            SELECT {columns_sql}
            FROM {table}
            WHERE organization_id = CAST(:org AS INTEGER)
              AND id = ANY(:ids)
              {snap_clause}
            """
        )

        try:
            result = await self._db.execute(sql, params)
            rows = result.mappings().all()
        except SQLAlchemyError as exc:
            raise RuntimeError(
                "database error during ResourceBatchLoader.fetch"
            ) from exc

        out: dict[str, dict[str, Any]] = {}
        for row in rows:
            self._assert_org_scope(row, resource_id=row.get("id"))
            out[row["id"]] = dict(row)
        return out

    async def fetch_sensitivity(
        self,
        resource_ids: list[str],
        data_mode: DataMode = DataMode.LIVE,
        snapshot_id: Optional[int] = None,
    ) -> dict[str, SensitivityLevel]:
        """Lightweight projection — ``{id: sensitivity}`` only.

        Uses the same batch pattern as :meth:`fetch` but projects
        only ``id`` + ``sensitivity`` for callers that just need to
        bucket by sensitivity (histograms, priority queues).
        """
        self._validate_mode(data_mode, snapshot_id)
        ids = self._prepare_ids(resource_ids)
        if not ids:
            return {}

        table, snap_clause = self._table_for(data_mode)
        params: dict[str, Any] = {"org": int(self._org_id), "ids": ids}
        if data_mode == DataMode.SNAPSHOT:
            params["sid"] = snapshot_id

        sql = text(
            f"""
            SELECT organization_id, id, sensitivity
            FROM {table}
            WHERE organization_id = CAST(:org AS INTEGER)
              AND id = ANY(:ids)
              {snap_clause}
            """
        )

        try:
            result = await self._db.execute(sql, params)
            rows = result.mappings().all()
        except SQLAlchemyError as exc:
            raise RuntimeError(
                "database error during ResourceBatchLoader.fetch_sensitivity"
            ) from exc

        out: dict[str, SensitivityLevel] = {}
        for row in rows:
            self._assert_org_scope(row, resource_id=row.get("id"))
            raw = row.get("sensitivity")
            try:
                out[row["id"]] = SensitivityLevel(raw) if raw is not None else SensitivityLevel.LOW
            except ValueError:
                logger.warning(
                    "ResourceBatchLoader: unknown sensitivity=%s for id=%s — defaulting to LOW",
                    raw,
                    row.get("id"),
                )
                out[row["id"]] = SensitivityLevel.LOW
        return out

    async def fetch_above_sensitivity(
        self,
        resource_ids: list[str],
        min_sensitivity: SensitivityLevel,
        data_mode: DataMode = DataMode.LIVE,
        snapshot_id: Optional[int] = None,
    ) -> dict[str, dict[str, Any]]:
        """Batch-load + sensitivity floor in a single query.

        Only rows whose ``sensitivity`` rank is ``>=
        SENSITIVITY_RANK[min_sensitivity]`` are returned. The floor
        is applied in SQL (not post-filtered in Python) so the query
        payload stays small.
        """
        self._validate_mode(data_mode, snapshot_id)
        ids = self._prepare_ids(resource_ids)
        if not ids:
            return {}

        floor_rank = SENSITIVITY_RANK[min_sensitivity]
        qualifying = [
            level.value
            for level, rank in SENSITIVITY_RANK.items()
            if rank >= floor_rank
        ]

        table, snap_clause = self._table_for(data_mode)
        columns_sql = ", ".join(self._FULL_COLUMNS)
        params: dict[str, Any] = {
            "org": int(self._org_id),
            "ids": ids,
            "sensitive_values": qualifying,
        }
        if data_mode == DataMode.SNAPSHOT:
            params["sid"] = snapshot_id

        sql = text(
            f"""
            SELECT {columns_sql}
            FROM {table}
            WHERE organization_id = CAST(:org AS INTEGER)
              AND id = ANY(:ids)
              AND sensitivity = ANY(:sensitive_values)
              {snap_clause}
            """
        )

        try:
            result = await self._db.execute(sql, params)
            rows = result.mappings().all()
        except SQLAlchemyError as exc:
            raise RuntimeError(
                "database error during ResourceBatchLoader.fetch_above_sensitivity"
            ) from exc

        out: dict[str, dict[str, Any]] = {}
        for row in rows:
            self._assert_org_scope(row, resource_id=row.get("id"))
            out[row["id"]] = dict(row)
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prepare_ids(self, resource_ids: list[str]) -> list[str]:
        """Dedupe + validate + size-gate the input id list.

        Preserves first-seen order for deterministic traces.
        """
        if resource_ids is None:
            return []
        if len(resource_ids) > MAX_BATCH_SIZE:
            raise BatchSizeExceededError(
                f"resource_ids exceeds MAX_BATCH_SIZE={MAX_BATCH_SIZE} "
                f"(got {len(resource_ids)})"
            )
        seen: set[str] = set()
        deduped: list[str] = []
        for rid in resource_ids:
            if not isinstance(rid, str) or not rid:
                continue
            if rid in seen:
                continue
            seen.add(rid)
            deduped.append(rid)
        return deduped

    def _assert_org_scope(
        self,
        row: Mapping[str, Any],
        *,
        resource_id: Optional[str],
    ) -> None:
        """Raise :class:`ResourceScopeError` if ``row`` crosses the org line."""
        if not isinstance(row, Mapping):
            return
        row_org = row.get("organization_id")
        if row_org is None:
            return
        if str(row_org) != str(self._org_id):
            raise ResourceScopeError(
                f"row organization_id={row_org!r} does not match loader "
                f"binding={self._org_id!r} for resource_id={resource_id!r}"
            )

    @staticmethod
    def _validate_mode(data_mode: DataMode, snapshot_id: Optional[int]) -> None:
        if not isinstance(data_mode, DataMode):
            raise ValueError("data_mode must be a DataMode enum value")
        if data_mode == DataMode.SNAPSHOT and snapshot_id is None:
            raise ValueError("snapshot_id is required when data_mode == SNAPSHOT")
        if data_mode == DataMode.LIVE and snapshot_id is not None:
            raise ValueError("snapshot_id must be None when data_mode == LIVE")

    @staticmethod
    def _table_for(data_mode: DataMode) -> tuple[str, str]:
        """Return ``(table_name, optional_snapshot_clause)`` for the mode."""
        if data_mode == DataMode.SNAPSHOT:
            return "resource_snapshots", "AND snapshot_id = :sid"
        return "resources", ""


__all__ = [
    "ResourceBatchLoader",
    "BatchSizeExceededError",
    "ResourceScopeError",
    "MAX_BATCH_SIZE",
    "SENSITIVITY_RANK",
]
