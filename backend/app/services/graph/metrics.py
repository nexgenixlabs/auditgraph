"""
AuditGraph observability metrics.

Structured log lines, no external SDK required. Every public
method on :class:`AuditGraphMetrics` is fire-and-forget:
emission failures are swallowed so a broken metrics backend
can never take down the hot path.

Replace :meth:`AuditGraphMetrics._emit` with a real metrics
client (OTLP, StatsD, Datadog) when one lands — call sites do
not need to change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional


logger = logging.getLogger("auditgraph.metrics")


# ---------------------------------------------------------------------------
# Metric dataclasses
# ---------------------------------------------------------------------------


@dataclass
class BFSMetric:
    """One BFS traversal invocation."""

    organization_id: str
    policy_name: str
    start_node_id: str
    nodes_visited: int
    edges_traversed: int
    depth_reached: int
    paths_found: int
    truncated: bool
    duration_ms: float
    query_count: int = 0


@dataclass
class PostureMetric:
    """One posture-score computation."""

    organization_id: str
    score: float
    critical_count: int
    attack_path_count: int
    duration_ms: float


@dataclass
class WhatIfMetric:
    """One what-if simulation invocation."""

    organization_id: str
    identity_id: str
    simulation_type: str
    risk_delta: float
    paths_eliminated: int
    paths_added: int
    duration_ms: float


@dataclass
class DriftMetric:
    """One drift computation between two identity states."""

    organization_id: str
    identity_id: str
    direction: str
    change_count: int
    risk_score_delta: float
    blast_radius_delta: Optional[int]
    duration_ms: float


@dataclass
class PolicyUsageMetric:
    """Which traversal policy ran and which edges were actually walked."""

    organization_id: str
    policy_name: str
    triggered_by: str  # "attack_path" | "blast_radius" | "what_if" | "drift"
    identity_id: str
    edge_types_used: list[str]
    sequences_completed: int
    sequences_truncated: int


# ---------------------------------------------------------------------------
# AuditGraphMetrics
# ---------------------------------------------------------------------------


class AuditGraphMetrics:
    """Emit structured log lines. Never raises. No blocking I/O.

    Every public method wraps its body in ``try/except Exception:
    pass`` so a broken emitter can never take down the hot path.
    Swap :meth:`_emit` for a real metrics client when one lands.
    """

    def bfs(self, m: BFSMetric) -> None:
        """Record a BFS traversal. Never raises."""
        try:
            self._emit(
                "bfs",
                org=m.organization_id,
                policy=m.policy_name,
                start=m.start_node_id,
                nodes=m.nodes_visited,
                edges=m.edges_traversed,
                depth=m.depth_reached,
                paths=m.paths_found,
                truncated=int(m.truncated),
                duration_ms=round(m.duration_ms, 2),
                queries=m.query_count,
            )
        except Exception:  # noqa: BLE001
            pass

    def posture(self, m: PostureMetric) -> None:
        """Record a posture-score computation. Never raises."""
        try:
            self._emit(
                "posture",
                org=m.organization_id,
                score=round(m.score, 2),
                critical=m.critical_count,
                attack_paths=m.attack_path_count,
                duration_ms=round(m.duration_ms, 2),
            )
        except Exception:  # noqa: BLE001
            pass

    def what_if(self, m: WhatIfMetric) -> None:
        """Record a what-if simulation. Never raises."""
        try:
            self._emit(
                "what_if",
                org=m.organization_id,
                identity=m.identity_id,
                sim_type=m.simulation_type,
                risk_delta=round(m.risk_delta, 2),
                paths_eliminated=m.paths_eliminated,
                paths_added=m.paths_added,
                duration_ms=round(m.duration_ms, 2),
            )
        except Exception:  # noqa: BLE001
            pass

    def drift(self, m: DriftMetric) -> None:
        """Record a drift computation. Never raises."""
        try:
            self._emit(
                "drift",
                org=m.organization_id,
                identity=m.identity_id,
                direction=m.direction,
                changes=m.change_count,
                risk_delta=round(m.risk_score_delta, 2),
                blast_delta=m.blast_radius_delta,
                duration_ms=round(m.duration_ms, 2),
            )
        except Exception:  # noqa: BLE001
            pass

    def policy_usage(self, m: PolicyUsageMetric) -> None:
        """Record which traversal policy ran and which edges fired.
        Never raises.
        """
        try:
            self._emit(
                "policy_usage",
                org=m.organization_id,
                policy=m.policy_name,
                trigger=m.triggered_by,
                identity=m.identity_id,
                edge_types=",".join(sorted(m.edge_types_used)),
                completed=m.sequences_completed,
                truncated=m.sequences_truncated,
            )
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _emit(metric_name: str, **kwargs: object) -> None:
        """Structured log line. Replace with a real metrics client.

        Output format::

            metric=<name> k1=v1 k2=v2 ...
        """
        parts = " ".join(f"{k}={v}" for k, v in kwargs.items())
        logger.info("metric=%s %s", metric_name, parts)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


_metrics = AuditGraphMetrics()


def get_metrics() -> AuditGraphMetrics:
    """Return the process-wide :class:`AuditGraphMetrics` singleton."""
    return _metrics


__all__ = [
    "BFSMetric",
    "PostureMetric",
    "WhatIfMetric",
    "DriftMetric",
    "PolicyUsageMetric",
    "AuditGraphMetrics",
    "get_metrics",
]
