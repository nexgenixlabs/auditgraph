"""
IdentityBlastRadiusEngine — aggregate reachability for one identity.

Phase 3 replacement for the legacy scoring-only
``app.engines.blast_radius_engine.BlastRadiusEngine``. The legacy
engine computes a *number* (privileged count × dependency factor ×
exposure); this engine walks the actual graph and returns the
concrete set of reachable resources bucketed by sensitivity.

Design rules
------------
* **Only call path for Phase 3 blast radius.** Wired into
  :class:`IdentityStateEngine` under the ``USE_BLAST_RADIUS``
  feature flag. The legacy engine is never called from here.
* **One BFS per invocation.** We rely on
  :class:`GraphTraversalEngine` for the actual walk and this
  module is pure orchestration + bucketing on top.
* **One SQL surface for resources.** All resource lookups go
  through :class:`ResourceBatchLoader` — never per-resource, always
  batched to :data:`MAX_BATCH_SIZE`.
* **Histogram tracks every first-edge type per resource** — if a
  resource is reachable via both HAS_ROLE and MEMBER_OF it
  contributes to *both* histogram buckets. This fixes the B08
  under-count bug where only one edge was recorded.
* **Malformed rows are skipped, never raise.** Org-boundary
  violations log ERROR and return None so a single bad row can
  never poison the entire blast radius.
* **All imports are module-level except metrics.** Metrics
  imports are lazy inside the emission try/except so a broken
  metrics backend can never take down the hot path.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import (
    BlastRadiusResult,
    BuilderDataSource,
    CloudProvider,
    DataMode,
    Resource,
    ResourceType,
    SensitivityLevel,
)
from app.services.graph.graph_traversal_engine import GraphTraversalEngine
from app.services.graph.resource_batch_loader import (
    MAX_BATCH_SIZE,
    ResourceBatchLoader,
)
from app.services.graph.traversal_policy import (
    FULL_BLAST_RADIUS_POLICY,
    TraversalPolicy,
)


logger = logging.getLogger(__name__)


#: Node type marker for resource leaves returned by the traversal
#: engine. Kept at module scope so tests can reference it without
#: reaching into private names.
_RESOURCE_NODE_TYPE: str = "resource"


# ---------------------------------------------------------------------------
# IdentityBlastRadiusEngine
# ---------------------------------------------------------------------------


class IdentityBlastRadiusEngine:
    """Compute aggregate reachability (blast radius) for a single identity.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the engine and
        threaded into every downstream builder.
    db:
        Async SQLAlchemy session managed by the caller. The engine
        never commits or rolls back on its own.
    """

    def __init__(self, organization_id: str, db: AsyncSession) -> None:
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise ValueError(
                "organization_id is required and must be a non-empty string"
            )
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        self._org_id: str = organization_id
        self._db: AsyncSession = db

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def compute(
        self,
        identity_id: str,
        *,
        data_mode: DataMode = DataMode.LIVE,
        snapshot_id: Optional[int] = None,
        policy: TraversalPolicy = FULL_BLAST_RADIUS_POLICY,
    ) -> BlastRadiusResult:
        """Walk the graph from ``identity_id`` and return a
        :class:`BlastRadiusResult`.

        Raises
        ------
        ValueError
            If ``identity_id`` is empty or if the
            ``data_mode`` / ``snapshot_id`` invariant is violated.
        """
        if not identity_id:
            raise ValueError("identity_id is required")
        if data_mode == DataMode.SNAPSHOT and snapshot_id is None:
            raise ValueError("snapshot_id is required when data_mode == SNAPSHOT")
        if data_mode == DataMode.LIVE and snapshot_id is not None:
            raise ValueError("snapshot_id must be None when data_mode == LIVE")

        _start = time.perf_counter()

        # 1. BFS via GraphTraversalEngine
        traversal_engine = GraphTraversalEngine(self._org_id, self._db)
        traversal_result = await traversal_engine.traverse_from(
            start_node_id=identity_id,
            policy=policy,
            data_mode=data_mode,
            snapshot_id=snapshot_id,
        )

        # 2. Collect resource leaves — record EVERY first-edge type
        #    per resource so the histogram cannot under-count.
        per_resource_first_edges: dict[str, set[str]] = {}
        for path in getattr(traversal_result, "paths", []):
            target = getattr(path, "target_node", None)
            if target is None:
                continue
            if getattr(target, "node_type", None) != _RESOURCE_NODE_TYPE:
                continue
            node_id = getattr(target, "node_id", None)
            if not node_id:
                continue
            edges = getattr(path, "edges", None) or []
            if not edges:
                continue
            first_edge = edges[0]
            first_edge_value = getattr(first_edge, "value", None) or str(first_edge)
            per_resource_first_edges.setdefault(node_id, set()).add(first_edge_value)

        # 3. Batch fetch — chunk into MAX_BATCH_SIZE slices,
        #    log + continue on any batch failure. A single broken
        #    batch must never abort the whole blast radius.
        resource_rows: dict[str, dict[str, Any]] = {}
        loader = ResourceBatchLoader(self._org_id, self._db)
        all_ids = list(per_resource_first_edges.keys())
        for offset in range(0, len(all_ids), MAX_BATCH_SIZE):
            chunk = all_ids[offset : offset + MAX_BATCH_SIZE]
            try:
                rows = await loader.fetch(
                    chunk, data_mode=data_mode, snapshot_id=snapshot_id
                )
                resource_rows.update(rows)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "identity_blast_radius: batch fetch failed "
                    "org=%s identity=%s chunk_size=%d err=%s — continuing",
                    self._org_id,
                    identity_id,
                    len(chunk),
                    exc,
                )
                continue

        # 4. Pure bucketing
        critical, high, medium, by_path_type = await self._bucket_resources(
            resource_rows, per_resource_first_edges
        )

        # 5. Build result. total_reachable counts *every* resource
        #    the BFS reached, including low/info tiers that are not
        #    listed in the bucket arrays.
        total_reachable = len(per_resource_first_edges)

        # E2: derive data_source from traversal results
        is_truncated = bool(getattr(traversal_result, "truncated", False))
        if total_reachable == 0:
            _ds = BuilderDataSource.NONE
            _missing = ["graph_edges"]
        elif is_truncated:
            _ds = BuilderDataSource.PARTIAL
            _missing = ["truncated_frontier"]
        else:
            _ds = BuilderDataSource.FULL
            _missing = []

        result = BlastRadiusResult(
            organization_id=self._org_id,
            identity_id=identity_id,
            critical_resources=critical,
            high_resources=high,
            medium_resources=medium,
            total_reachable=total_reachable,
            reachable_by_path_type=by_path_type,
            traversal_depth=int(getattr(traversal_result, "traversal_depth", 0) or 0),
            policy_name=policy.name,
            truncated=is_truncated,
            data_source=_ds,
            missing_signals=_missing,
        )

        # 6. Fire-and-forget BFS metric
        try:
            from app.services.graph.metrics import BFSMetric, get_metrics

            _reachable = getattr(traversal_result, "reachable_nodes", None)
            if isinstance(_reachable, dict):
                _nodes_visited = sum(
                    len(v) if hasattr(v, "__len__") else 1 for v in _reachable.values()
                )
            elif _reachable is not None and hasattr(_reachable, "__len__"):
                _nodes_visited = len(_reachable)
            else:
                _nodes_visited = 0

            get_metrics().bfs(
                BFSMetric(
                    organization_id=self._org_id,
                    policy_name=policy.name,
                    start_node_id=identity_id,
                    nodes_visited=_nodes_visited,
                    edges_traversed=int(
                        getattr(traversal_result, "edge_count_traversed", 0) or 0
                    ),
                    depth_reached=int(
                        getattr(traversal_result, "traversal_depth", 0) or 0
                    ),
                    paths_found=len(getattr(traversal_result, "paths", []) or []),
                    truncated=bool(getattr(traversal_result, "truncated", False)),
                    duration_ms=(time.perf_counter() - _start) * 1000.0,
                )
            )
        except Exception:  # noqa: BLE001
            pass

        # 7. Fire-and-forget PolicyUsage metric
        try:
            from app.services.graph.metrics import PolicyUsageMetric, get_metrics

            _truncated = bool(getattr(traversal_result, "truncated", False))
            _paths = getattr(traversal_result, "paths", []) or []
            get_metrics().policy_usage(
                PolicyUsageMetric(
                    organization_id=self._org_id,
                    policy_name=policy.name,
                    triggered_by="blast_radius",
                    identity_id=identity_id,
                    edge_types_used=sorted(
                        {
                            e
                            for _rid, edges in per_resource_first_edges.items()
                            for e in edges
                        }
                    ),
                    sequences_completed=0 if _truncated else len(_paths),
                    sequences_truncated=1 if _truncated else 0,
                )
            )
        except Exception:  # noqa: BLE001
            pass

        # 8. Return
        return result

    # ------------------------------------------------------------------
    # Pure bucketing
    # ------------------------------------------------------------------

    async def _bucket_resources(
        self,
        resource_rows: dict[str, dict[str, Any]],
        per_resource_first_edges: dict[str, set[str]],
    ) -> tuple[list[Resource], list[Resource], list[Resource], dict[str, int]]:
        """Split reachable resources into sensitivity buckets and
        build the first-edge-type histogram.

        No DB access — this is a pure transform over the two inputs.

        Histogram rule (fixes the B08 under-count bug)
        ----------------------------------------------
        For each resource the traversal reached, we iterate over
        **every** first-edge type seen for that resource, not just
        the first-observed one. A resource reachable via both
        ``HAS_ROLE`` and ``MEMBER_OF`` contributes +1 to each
        histogram bucket.
        """
        critical: list[Resource] = []
        high: list[Resource] = []
        medium: list[Resource] = []
        by_path_type: dict[str, int] = {}

        for node_id, edge_types in per_resource_first_edges.items():
            # Histogram: every edge type contributes, not just one
            for edge_type in edge_types:
                by_path_type[edge_type] = by_path_type.get(edge_type, 0) + 1

            row = resource_rows.get(node_id)
            if row is None:
                # Row missing from the fetch (either unknown id or
                # the batch failed) — we still counted the node in
                # total_reachable + histogram above, so just skip
                # the bucket assignment.
                continue

            resource = self._build_resource(row, self._org_id)
            if resource is None:
                continue

            if resource.sensitivity == SensitivityLevel.CRITICAL:
                critical.append(resource)
            elif resource.sensitivity == SensitivityLevel.HIGH:
                high.append(resource)
            elif resource.sensitivity == SensitivityLevel.MEDIUM:
                medium.append(resource)
            # LOW contributes to total_reachable but is not listed.

        return critical, high, medium, by_path_type

    # ------------------------------------------------------------------
    # Row → Resource conversion (defensive)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_resource(
        row: dict[str, Any],
        organization_id: str,
    ) -> Optional[Resource]:
        """Convert a DB row to a :class:`Resource` with defensive
        enum parsing.

        Every enum conversion is wrapped in its own try/except with
        a safe default so a single unknown value cannot take down
        the whole blast radius. Org-boundary violations log ERROR
        and return ``None`` — never raise.
        """
        try:
            # Org-scope guard — hard security boundary
            row_org = row.get("organization_id")
            # DB column is INTEGER, binding comes from JWT as str — compare as str.
            if row_org is not None and str(row_org) != str(organization_id):
                logger.error(
                    "identity_blast_radius: row organization_id=%r does not "
                    "match engine binding=%r for resource_id=%r — dropping row",
                    row_org,
                    organization_id,
                    row.get("id") or row.get("resource_id"),
                )
                return None

            # CloudProvider — use cloud_provider column, NOT cloud_id
            # (cloud_id is a resource path like /subscriptions/.../...)
            cp_raw = row.get("cloud_provider") or "azure"
            try:
                cloud_provider = CloudProvider(cp_raw)
            except ValueError:
                logger.warning(
                    "identity_blast_radius: unknown cloud_provider=%r "
                    "for resource_id=%r — defaulting to azure",
                    cp_raw,
                    row.get("id") or row.get("resource_id"),
                )
                cloud_provider = CloudProvider.AZURE

            # ResourceType — unknown types default to STORAGE
            rt_raw = row.get("type") or "storage"
            try:
                resource_type = ResourceType(rt_raw)
            except ValueError:
                logger.warning(
                    "identity_blast_radius: unknown resource type=%r "
                    "for resource_id=%r — defaulting to storage",
                    rt_raw,
                    row.get("id") or row.get("resource_id"),
                )
                resource_type = ResourceType.STORAGE

            # SensitivityLevel — unknown values default to LOW
            sens_raw = row.get("sensitivity") or "Low"
            try:
                sensitivity = SensitivityLevel(sens_raw)
            except ValueError:
                logger.warning(
                    "identity_blast_radius: unknown sensitivity=%r "
                    "for resource_id=%r — defaulting to low",
                    sens_raw,
                    row.get("id") or row.get("resource_id"),
                )
                sensitivity = SensitivityLevel.LOW

            # Name fallback — empty string breaks UI dedup/grouping
            rid = row.get("id") or row.get("resource_id") or "unknown"
            name = row.get("name") or f"resource-{rid}"

            # global_identity_id is required by the Resource schema
            # (cross-cloud UUID). Fall back to None → Pydantic will
            # reject, which we catch below as a malformed row.
            gid = row.get("global_identity_id")

            return Resource(
                organization_id=organization_id,
                id=rid,
                global_identity_id=gid,
                cloud_id=cloud_provider,
                type=resource_type,
                name=name,
                sensitivity=sensitivity,
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "identity_blast_radius: skipping malformed resource row "
                "err=%s row_keys=%s",
                exc,
                list(row.keys()) if isinstance(row, dict) else "<non-dict>",
            )
            return None


__all__ = [
    "IdentityBlastRadiusEngine",
]
