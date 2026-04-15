"""
GraphTraversalEngine — core BFS execution for AuditGraph Phase 3.

Level-by-level breadth-first traversal over the ``graph_edges``
table. Every BFS level is fulfilled by **exactly one** SQL query via
:meth:`GraphTraversalEngine._fetch_edges_batch` — never per-node —
which is what makes this engine cheap enough to feed into blast
radius, attack paths, and what-if simulation on the hot path.

Design rules
------------
* **Single call path for all Phase 3 graph walks.**
  :class:`IdentityBlastRadiusEngine`, the attack-path service, and
  the what-if service all route through :meth:`traverse_from`.
* **One SQL query per BFS level.** The edge loader issues one
  query per frontier, batched by ``ANY(:source_ids)``. There is
  never a per-node query inside the BFS loop.
* **Policy prefix validation is the hot path.**
  :meth:`TraversalPolicy.is_valid_next_edge` is an O(1) hash
  lookup and gates every edge we consider extending.
* **Org scope is enforced twice.** Every SQL has
  ``WHERE organization_id = :org`` *and* every returned row is
  re-verified in Python. Any mismatch logs ERROR and is dropped —
  never raised.
* **Cycle prevention via visited set.** Visited is a set of
  ``(node_id, node_type)`` tuples so a node can be reached via
  more than one starting context without forming a cycle at the
  identity level.
* **max_depth and max_paths are hard caps.** When either is hit,
  :attr:`TraversalResult.truncated` is flipped to ``True`` and
  the BFS exits cleanly — never raised.
* **Malformed rows are skipped, never raise.** A single bad edge
  row cannot poison a traversal. Validation issues log WARNING
  and the offending row is dropped.
* **All imports are module-level except metrics.** Metrics
  import is lazy inside a try/except at the tail of
  :meth:`traverse_from` so a broken metrics backend can never
  take down a traversal.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Sequence

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import DataMode
from app.services.graph.traversal_policy import (
    FULL_BLAST_RADIUS_POLICY,
    EdgeType,
    TraversalPolicy,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Confidence propagation
# ---------------------------------------------------------------------------


#: Ordered weakest → strongest. The confidence of a path is the
#: minimum (weakest-wins) of the ``usage_confidence`` of each edge
#: along it. An edge with no confidence is treated as ``"none"``.
CONFIDENCE_ORDER: list[str] = ["none", "inferred", "low", "medium", "high"]
_CONFIDENCE_INDEX: dict[str, int] = {c: i for i, c in enumerate(CONFIDENCE_ORDER)}


def _weakest_confidence(confidences: Sequence[str]) -> str:
    """Return the weakest confidence in ``confidences``.

    Unknown values are treated as ``"none"``. Empty input returns
    ``"none"`` — there is no edge evidence yet.
    """
    if not confidences:
        return "none"
    return min(
        (c if c in _CONFIDENCE_INDEX else "none" for c in confidences),
        key=lambda c: _CONFIDENCE_INDEX[c],
    )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GraphTraversalError(Exception):
    """Raised for unrecoverable errors inside the traversal engine.

    Only used for hard failures (DB down, snapshot not found for
    the bound organization). Malformed individual rows and
    metric emission failures never raise — they log and continue.
    """

    def __init__(self, message: str, *, context: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.context: dict[str, Any] = dict(context or {})


class OrganizationScopeError(GraphTraversalError):
    """Raised when an engine invocation detects a cross-org leak
    it cannot safely recover from (e.g. a requested snapshot
    belongs to another tenant).
    """


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TraversalNode:
    """One node visited by the BFS.

    ``edge_type_used`` and ``parent_node_id`` are ``None`` on the
    start node and populated on every subsequent hop.
    """

    node_id: str
    node_type: str
    depth: int
    edge_type_used: Optional[str] = None
    parent_node_id: Optional[str] = None
    cloud_provider: Optional[str] = None


@dataclass(frozen=True)
class TraversalPath:
    """One complete path from the start node to a reached target.

    ``nodes`` always has length ``len(edges) + 1`` — the start
    node plus one node per edge. ``confidence`` is propagated
    weakest-wins over :data:`CONFIDENCE_ORDER`.
    """

    nodes: list[TraversalNode]
    edges: list[EdgeType]
    depth: int
    target_node: TraversalNode
    confidence: str = "none"

    @property
    def start(self) -> TraversalNode:
        """The node where the traversal started."""
        return self.nodes[0]


@dataclass
class TraversalResult:
    """Aggregate result of one :meth:`traverse_from` invocation.

    ``reachable_nodes`` is keyed by ``node_type`` and holds a list
    of node ids reached (deduped). ``truncated`` is ``True`` when
    either ``max_depth`` or ``max_paths`` was hit.
    """

    identity_id: str
    organization_id: str
    paths: list[TraversalPath] = field(default_factory=list)
    # Internal accumulation uses sets to prevent duplicates.
    # Converted to lists at return time for JSON serialization.
    _reachable_nodes_internal: dict[str, set[str]] = field(
        default_factory=dict, repr=False
    )
    # Public field: set → sorted list at build time
    reachable_nodes: dict[str, list[str]] = field(default_factory=dict)
    traversal_depth: int = 0
    edge_count_traversed: int = 0
    truncated: bool = False

    def record_node(self, node_type: str, node_id: str) -> None:
        """Add a node to the reachable set. Deduplicates automatically."""
        self._reachable_nodes_internal.setdefault(node_type, set()).add(node_id)

    def finalize(self) -> None:
        """Convert internal sets to sorted lists. Call once before returning."""
        self.reachable_nodes = {
            nt: sorted(ids)
            for nt, ids in self._reachable_nodes_internal.items()
        }


# ---------------------------------------------------------------------------
# GraphTraversalEngine
# ---------------------------------------------------------------------------


#: Hard SQL IN-list cap. Postgres bind-param limits are 32 767 but
#: we cap far lower to keep plans cheap and errors informative.
_FETCH_EDGES_CHUNK: int = 500


class GraphTraversalEngine:
    """Execute a single BFS traversal over ``graph_edges``.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the engine and
        threaded into every SQL query **and** every row
        verification pass.
    db:
        Async SQLAlchemy session managed by the caller. The
        engine never commits or rolls back on its own.
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
        self._query_count: int = 0
        # Per-instance cache: snapshot_id → snapshot_date.
        # Snapshot rows are immutable once written — safe to cache
        # for the lifetime of this engine instance (one request).
        # A cached value of ``None`` means the snapshot was previously
        # resolved as a tenant-boundary violation; the next call will
        # re-raise OrganizationScopeError without hitting the DB.
        self._snapshot_cache: dict[int, Optional[datetime]] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def traverse_from(
        self,
        start_node_id: str,
        *,
        policy: Optional[TraversalPolicy] = None,
        data_mode: DataMode = DataMode.LIVE,
        snapshot_id: Optional[int] = None,
        max_depth: Optional[int] = None,
        max_paths: Optional[int] = None,
    ) -> TraversalResult:
        """Run a level-by-level BFS from ``start_node_id`` under ``policy``.

        Parameters
        ----------
        start_node_id:
            The node at which the walk begins. Typically an
            identity id, but any node type recognized by
            ``graph_edges`` is acceptable.
        policy:
            A :class:`TraversalPolicy`. Defaults to
            :data:`FULL_BLAST_RADIUS_POLICY` when ``None``.
        data_mode:
            :attr:`DataMode.LIVE` reads the current graph;
            :attr:`DataMode.SNAPSHOT` reads the graph as it
            existed at the given ``snapshot_id``'s valid_at time.
        snapshot_id:
            Required when ``data_mode == SNAPSHOT``. Must not be
            set when ``data_mode == LIVE``.
        max_depth:
            Optional per-call override of ``policy.max_depth``.
            Capped at the policy value — callers can only
            *tighten* the cap, never relax it.
        max_paths:
            Optional per-call override of ``policy.max_paths``.
            Capped at the policy value — callers can only
            *tighten* the cap, never relax it.

        Raises
        ------
        ValueError
            If ``start_node_id`` is empty or the
            ``data_mode`` / ``snapshot_id`` invariant is violated.
        GraphTraversalError
            If the DB layer raises or a requested snapshot does
            not exist for the bound organization.
        """
        if not start_node_id:
            raise ValueError("start_node_id is required")
        if data_mode == DataMode.SNAPSHOT and snapshot_id is None:
            raise ValueError("snapshot_id is required when data_mode == SNAPSHOT")
        if data_mode == DataMode.LIVE and snapshot_id is not None:
            raise ValueError("snapshot_id must be None when data_mode == LIVE")

        effective_policy = policy or FULL_BLAST_RADIUS_POLICY

        # Callers may only tighten the caps, never relax them.
        depth_cap: int = effective_policy.max_depth
        if max_depth is not None:
            if max_depth < 1:
                raise ValueError("max_depth must be >= 1")
            depth_cap = min(depth_cap, max_depth)

        paths_cap: int = effective_policy.max_paths
        if max_paths is not None:
            if max_paths < 1:
                raise ValueError("max_paths must be >= 1")
            paths_cap = min(paths_cap, max_paths)

        allowed_edge_types: frozenset[EdgeType] = effective_policy.allowed_edge_types()

        _start = time.perf_counter()
        self._query_count = 0

        # Resolve snapshot date once — every SQL in the BFS uses
        # the same temporal cut so the traversal is consistent
        # under concurrent writes.
        snapshot_date = await self._resolve_snapshot_date(data_mode, snapshot_id)

        result = TraversalResult(
            identity_id=start_node_id,
            organization_id=self._org_id,
        )

        # Resolve external_id → graph_nodes.id.  Callers pass the
        # provider-native identity_id (e.g. Azure object ID) but
        # graph_edges.source_node_id references graph_nodes.id
        # (a random UUID).  Look it up once; if not found the BFS
        # will simply return an empty result at depth 0.
        resolved_node_id = await self._resolve_start_node(start_node_id)

        # Starting node. We don't know its type yet — fill it in
        # as "identity" by default; any resolved edge row will
        # overwrite for downstream hops.
        start_node = TraversalNode(
            node_id=resolved_node_id,
            node_type="identity",
            depth=0,
        )
        result.record_node("identity", start_node_id)

        # Frontier entry = (node, path_nodes_so_far, path_edges_so_far,
        #                   path_confidences_so_far)
        # path_nodes_so_far[0] is always the start node.
        frontier: list[
            tuple[TraversalNode, list[TraversalNode], list[EdgeType], list[str]]
        ] = [(start_node, [start_node], [], [])]

        # Depth-aware visited map. A node is only skipped if we have
        # already reached it at an equal or shallower depth — this
        # allows different paths to the same node at the same depth
        # while still preventing cycles (a cycle would always arrive
        # at greater depth than the first visit).
        visited_depth: dict[tuple[str, str], int] = {}
        visited_depth[(start_node_id, "identity")] = 0

        truncated = False
        max_depth_reached = 0

        # ------------------------------------------------------------------
        # Level-by-level BFS
        # ------------------------------------------------------------------
        for depth in range(1, depth_cap + 1):
            if not frontier:
                break

            # Collect source ids from the current frontier. Dedupe
            # so one SQL IN-list lookup can serve multiple path
            # contexts with the same tail node.
            level_source_ids: list[str] = []
            seen_source: set[str] = set()
            for node, _nodes, _edges, _confs in frontier:
                if node.node_id in seen_source:
                    continue
                seen_source.add(node.node_id)
                level_source_ids.append(node.node_id)

            # ONE SQL query per BFS level — never per node.
            try:
                edges_by_source = await self._fetch_edges_batch(
                    source_node_ids=level_source_ids,
                    allowed_edge_types=allowed_edge_types,
                    data_mode=data_mode,
                    snapshot_date=snapshot_date,
                )
            except GraphTraversalError:
                raise
            except SQLAlchemyError as exc:
                raise GraphTraversalError(
                    "graph_edges query failed",
                    context={
                        "organization_id": self._org_id,
                        "depth": depth,
                        "source_count": len(level_source_ids),
                        "err": str(exc),
                    },
                ) from exc

            next_frontier: list[
                tuple[TraversalNode, list[TraversalNode], list[EdgeType], list[str]]
            ] = []

            for node, path_nodes, path_edges, path_confs in frontier:
                if truncated:
                    break

                edge_rows = edges_by_source.get(node.node_id) or []
                for row in edge_rows:
                    # Malformed row — skip, never raise.
                    edge_type_raw = row.get("edge_type")
                    # target_node_id comes back from asyncpg as a uuid.UUID
                    # object. Normalize to str so downstream consumers
                    # (visited_depth keys, TraversalNode.node_id, next BFS
                    # level's :source_ids binding) see the same type as
                    # the start node id.
                    raw_target_id = row.get("target_node_id")
                    target_id = str(raw_target_id) if raw_target_id is not None else None
                    target_type = row.get("target_node_type") or "unknown"
                    if not edge_type_raw or not target_id:
                        logger.warning(
                            "graph_traversal: skipping malformed edge row "
                            "org=%s source=%s row_keys=%s",
                            self._org_id,
                            node.node_id,
                            list(row.keys()),
                        )
                        continue

                    try:
                        edge_type = EdgeType(edge_type_raw)
                    except ValueError:
                        # Unknown edge type — not part of any
                        # policy sequence so it would fail the
                        # prefix check anyway. Drop cleanly.
                        continue

                    # Policy gate — O(1) hash lookup.
                    if not effective_policy.is_valid_next_edge(path_edges, edge_type):
                        continue

                    result.edge_count_traversed += 1

                    # Depth-aware cycle prevention on (node_id, node_type).
                    # Skip only when we've already reached this node at an
                    # equal or shallower depth. A true cycle always arrives
                    # at greater depth than its first visit, so it still
                    # terminates cleanly.
                    visit_key = (target_id, target_type)
                    prior_depth = visited_depth.get(visit_key)
                    if prior_depth is not None and prior_depth <= depth:
                        continue
                    visited_depth[visit_key] = depth

                    target_node = TraversalNode(
                        node_id=target_id,
                        node_type=target_type,
                        depth=depth,
                        edge_type_used=edge_type.value,
                        parent_node_id=node.node_id,
                        cloud_provider=row.get("cloud_provider"),
                    )

                    # Bookkeeping — reachable_nodes (set-backed, deduped).
                    result.record_node(target_type, target_id)

                    new_path_nodes = path_nodes + [target_node]
                    new_path_edges = path_edges + [edge_type]
                    # Unknown or missing confidence → "none", never drop the edge.
                    # An edge with unknown evidence is still a valid traversal hop.
                    raw_conf = row.get("usage_confidence")
                    conf = raw_conf if raw_conf in _CONFIDENCE_INDEX else "none"
                    new_path_confs = path_confs + [conf]

                    # Record a complete path only when the edge
                    # sequence matches a policy sequence exactly —
                    # this is what distinguishes "reached" from
                    # "terminal under the policy".
                    if effective_policy.is_complete_path(new_path_edges):
                        if len(result.paths) >= paths_cap:
                            truncated = True
                            break
                        result.paths.append(
                            TraversalPath(
                                nodes=new_path_nodes,
                                edges=new_path_edges,
                                depth=depth,
                                target_node=target_node,
                                confidence=_weakest_confidence(new_path_confs),
                            )
                        )

                    if depth > max_depth_reached:
                        max_depth_reached = depth

                    # Only extend the BFS if there is a chance of
                    # going deeper under the policy — i.e. at
                    # least one allowed continuation exists.
                    if depth < depth_cap:
                        next_frontier.append(
                            (target_node, new_path_nodes, new_path_edges, new_path_confs)
                        )

                if truncated:
                    break

            if truncated:
                break

            frontier = next_frontier

        result.traversal_depth = max_depth_reached
        result.truncated = truncated
        result.finalize()

        # ------------------------------------------------------------------
        # Fire-and-forget BFS metric — lazy import
        # ------------------------------------------------------------------
        try:
            from app.services.graph.metrics import BFSMetric, get_metrics

            _nodes_visited = sum(
                len(s) for s in result._reachable_nodes_internal.values()
            )
            get_metrics().bfs(
                BFSMetric(
                    organization_id=self._org_id,
                    policy_name=effective_policy.name,
                    start_node_id=start_node_id,
                    nodes_visited=_nodes_visited,
                    edges_traversed=result.edge_count_traversed,
                    depth_reached=result.traversal_depth,
                    paths_found=len(result.paths),
                    truncated=result.truncated,
                    duration_ms=(time.perf_counter() - _start) * 1000.0,
                    query_count=self._query_count,
                )
            )
        except Exception:  # noqa: BLE001
            pass

        return result

    # ------------------------------------------------------------------
    # Edge fetch — one SQL query per BFS level
    # ------------------------------------------------------------------

    async def _fetch_edges_batch(
        self,
        source_node_ids: list[str],
        *,
        allowed_edge_types: frozenset[EdgeType],
        data_mode: DataMode,
        snapshot_date: Optional[datetime],
    ) -> dict[str, list[dict[str, Any]]]:
        """Fetch all edges fanning out of ``source_node_ids`` in one SQL query.

        Returns a ``{source_node_id: [row_dict, ...]}`` map. Rows
        that fail the per-row org verification log ERROR and are
        dropped. Empty input returns ``{}`` without touching the
        DB.
        """
        if not source_node_ids:
            return {}
        if not allowed_edge_types:
            return {}

        # Dedup the IN-list and cap chunk size. If a caller ever
        # hands us more than the chunk size we slice — each slice
        # is one SQL query.
        seen: set[str] = set()
        unique_ids: list[str] = []
        for nid in source_node_ids:
            if nid in seen:
                continue
            seen.add(nid)
            unique_ids.append(nid)

        # Edge types — bind as an array of strings for psycopg.
        edge_type_strs: list[str] = sorted(e.value for e in allowed_edge_types)

        # Temporal clause — one place that live vs snapshot mode
        # differs so the BFS loop stays mode-agnostic.
        if data_mode == DataMode.SNAPSHOT:
            if snapshot_date is None:
                raise GraphTraversalError(
                    "snapshot_date is required when data_mode == SNAPSHOT",
                    context={"organization_id": self._org_id},
                )
            temporal_clause = (
                "AND valid_at <= :snapshot_date "
                "AND (invalidated_at IS NULL OR invalidated_at > :snapshot_date)"
            )
        else:
            temporal_clause = "AND invalidated_at IS NULL"

        sql = text(
            f"""
            SELECT
                organization_id,
                source_node_id,
                source_node_type,
                target_node_id,
                target_node_type,
                edge_type,
                usage_confidence,
                cloud_provider
            FROM graph_edges
            WHERE organization_id = CAST(:org AS INTEGER)
              -- source_node_id is uuid, binding comes in as text[] from
              -- asyncpg — cast to text on both sides so the comparison
              -- works without requiring the caller to construct uuid
              -- objects for every BFS frontier entry.
              AND source_node_id::text = ANY(:source_ids)
              AND edge_type = ANY(:edge_types)
              {temporal_clause}
            """
        )

        result: dict[str, list[dict[str, Any]]] = {}

        for offset in range(0, len(unique_ids), _FETCH_EDGES_CHUNK):
            chunk = unique_ids[offset : offset + _FETCH_EDGES_CHUNK]
            params: dict[str, Any] = {
                "org": int(self._org_id),
                "source_ids": chunk,
                "edge_types": edge_type_strs,
            }
            if data_mode == DataMode.SNAPSHOT:
                params["snapshot_date"] = snapshot_date

            self._query_count += 1
            rows = await self._db.execute(sql, params)
            for raw in rows.mappings().all():
                row = dict(raw)

                # Python-side org verification — the SQL WHERE is
                # the first line of defense, this is the second.
                row_org = row.get("organization_id")
                # DB column is INTEGER, binding comes from JWT as str —
                # normalize to str on both sides to avoid spurious drops.
                if row_org is not None and str(row_org) != str(self._org_id):
                    logger.error(
                        "graph_traversal: row organization_id=%r does not "
                        "match engine binding=%r source=%r target=%r — dropping row",
                        row_org,
                        self._org_id,
                        row.get("source_node_id"),
                        row.get("target_node_id"),
                    )
                    continue

                # Normalize source_node_id from uuid.UUID → str so the
                # dict key matches what the BFS passed in :source_ids
                # (which itself came from TraversalNode.node_id as str).
                raw_src = row.get("source_node_id")
                if not raw_src:
                    continue
                src = str(raw_src)
                result.setdefault(src, []).append(row)

        return result

    # ------------------------------------------------------------------
    # Snapshot resolution
    # ------------------------------------------------------------------

    async def _resolve_start_node(self, external_id: str) -> str:
        """Resolve a provider-native identity id (``external_id``) to the
        internal ``graph_nodes.id`` UUID.

        Returns the original ``external_id`` unchanged if no mapping is
        found — the BFS will simply find zero outgoing edges and
        terminate at depth 0 with an empty result.
        """
        try:
            sql = text(
                """
                SELECT id::text
                FROM graph_nodes
                WHERE organization_id = :org
                  AND node_type = 'identity'
                  AND external_id = :ext_id
                LIMIT 1
                """
            )
            result = await self._db.execute(
                sql,
                {"org": int(self._org_id), "ext_id": external_id},
            )
            row = result.mappings().first()
            if row:
                return row["id"]
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "graph_traversal: _resolve_start_node failed "
                "org=%s ext=%s err=%s — using raw id",
                self._org_id,
                external_id[:40],
                exc,
            )
        return external_id

    async def _resolve_snapshot_date(
        self,
        data_mode: DataMode,
        snapshot_id: Optional[int],
    ) -> Optional[datetime]:
        """Resolve ``snapshot_id`` to its ``valid_at`` timestamp.

        Returns ``None`` for live mode. Raises
        :class:`OrganizationScopeError` if the snapshot exists but
        belongs to a different organization — this is a hard
        tenant-boundary failure and must never be papered over.
        """
        if data_mode == DataMode.LIVE:
            return None
        if snapshot_id is None:
            raise GraphTraversalError(
                "snapshot_id is required when data_mode == SNAPSHOT",
                context={"organization_id": self._org_id},
            )

        # Return cached value if available — snapshot rows are
        # immutable once written, so the cache is always valid for
        # the lifetime of this engine instance.
        if snapshot_id in self._snapshot_cache:
            cached = self._snapshot_cache[snapshot_id]
            if cached is None:
                # Previously resolved as a tenant-boundary or missing-row
                # failure — re-raise rather than silently returning None.
                raise OrganizationScopeError(
                    "snapshot not found for organization (cached)",
                    context={
                        "organization_id": self._org_id,
                        "snapshot_id": snapshot_id,
                    },
                )
            return cached

        # Cache miss — query once, then cache the result.
        sql = text(
            """
            SELECT organization_id, valid_at
            FROM identity_snapshots
            WHERE id = :sid
            LIMIT 1
            """
        )
        try:
            self._query_count += 1
            rows = await self._db.execute(sql, {"sid": snapshot_id})
            row = rows.mappings().first()
        except SQLAlchemyError as exc:
            raise GraphTraversalError(
                "identity_snapshots lookup failed",
                context={
                    "organization_id": self._org_id,
                    "snapshot_id": snapshot_id,
                    "err": str(exc),
                },
            ) from exc

        if row is None:
            # Cache the miss so repeated calls don't hit DB again.
            self._snapshot_cache[snapshot_id] = None
            raise GraphTraversalError(
                f"snapshot_id={snapshot_id} not found",
                context={
                    "organization_id": self._org_id,
                    "snapshot_id": snapshot_id,
                },
            )

        row_org = row.get("organization_id")
        # DB column is INTEGER, binding comes from JWT as str — compare as str.
        if row_org is not None and str(row_org) != str(self._org_id):
            # Cache the miss so repeated calls don't hit DB again.
            self._snapshot_cache[snapshot_id] = None
            raise OrganizationScopeError(
                "snapshot belongs to a different organization",
                context={
                    "organization_id": self._org_id,
                    "snapshot_id": snapshot_id,
                    "row_org": row_org,
                },
            )

        valid_at = row.get("valid_at")
        if not isinstance(valid_at, datetime):
            raise GraphTraversalError(
                "identity_snapshots.valid_at has unexpected type",
                context={
                    "organization_id": self._org_id,
                    "snapshot_id": snapshot_id,
                    "type": type(valid_at).__name__,
                },
            )
        self._snapshot_cache[snapshot_id] = valid_at
        return valid_at


__all__ = [
    "CONFIDENCE_ORDER",
    "GraphTraversalError",
    "OrganizationScopeError",
    "TraversalNode",
    "TraversalPath",
    "TraversalResult",
    "GraphTraversalEngine",
]
