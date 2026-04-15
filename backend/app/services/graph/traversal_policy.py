"""
TraversalPolicy — declarative BFS traversal strategy.
Single source of truth for which edge sequences are valid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Sequence


class EdgeType(str, Enum):
    HAS_ROLE = "HAS_ROLE"
    HAS_PERMISSION = "HAS_PERMISSION"
    CAN_ACCESS = "CAN_ACCESS"
    MEMBER_OF = "MEMBER_OF"
    OWNS = "OWNS"
    TRUSTS = "TRUSTS"
    DELEGATES_TO = "DELEGATES_TO"
    BOUND_TO = "BOUND_TO"
    PART_OF = "PART_OF"


@dataclass(frozen=True)
class TraversalPolicy:
    """Frozen declarative BFS policy.

    Precomputes the set of valid sequence *prefixes* in
    :meth:`__post_init__` so :meth:`is_valid_next_edge` runs in
    O(1) on the BFS hot path.

    Fields
    ------
    name:
        Stable identifier, stamped onto :class:`BlastRadiusResult`
        and every metric emission.
    allowed_edge_sequences:
        One or more valid edge-type sequences. At least one is
        required. Each sequence is evaluated left-to-right.
    max_depth:
        Hard cap on path length. Defaults to 6.
    max_paths:
        Hard cap on number of paths returned per traversal.
        Defaults to 50.
    include_cross_cloud:
        Whether the traversal should follow cross-cloud edges
        (AZURE → AWS, etc.). Defaults to ``False``.
    description:
        Human-readable explanation for the policy.
    """

    name: str
    allowed_edge_sequences: list[list[EdgeType]]
    max_depth: int = 6
    max_paths: int = 50
    include_cross_cloud: bool = False
    description: str = ""
    _sequence_tuples: FrozenSet[tuple] = field(
        default_factory=frozenset, init=False, repr=False, compare=False
    )
    _valid_prefixes: FrozenSet[tuple] = field(
        default_factory=frozenset, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("TraversalPolicy.name is required")
        if not self.allowed_edge_sequences:
            raise ValueError(
                f"{self.name}: at least one allowed_edge_sequence is required"
            )
        if self.max_depth < 1:
            raise ValueError(f"{self.name}: max_depth must be >= 1")
        if self.max_paths < 1:
            raise ValueError(f"{self.name}: max_paths must be >= 1")

        # Normalize to tuples for hashability + precompute every
        # prefix of every sequence so is_valid_next_edge() can
        # answer in one hash lookup.
        normalized: list[tuple[EdgeType, ...]] = []
        for seq in self.allowed_edge_sequences:
            if not seq:
                raise ValueError(
                    f"{self.name}: allowed_edge_sequences contains an empty sequence"
                )
            normalized.append(tuple(seq))

        prefixes: set[tuple[EdgeType, ...]] = {()}
        for seq in normalized:
            for length in range(1, len(seq) + 1):
                prefixes.add(seq[:length])

        object.__setattr__(self, "_sequence_tuples", frozenset(normalized))
        object.__setattr__(self, "_valid_prefixes", frozenset(prefixes))

    def is_valid_next_edge(
        self,
        current_path_edges: Sequence[EdgeType],
        candidate_edge: EdgeType,
    ) -> bool:
        """Return ``True`` iff appending ``candidate_edge`` to
        ``current_path_edges`` yields a prefix of some allowed
        sequence **and** stays within ``max_depth``.
        """
        if len(current_path_edges) >= self.max_depth:
            return False
        candidate_prefix = tuple(current_path_edges) + (candidate_edge,)
        return candidate_prefix in self._valid_prefixes

    def is_complete_path(self, path_edges: Sequence[EdgeType]) -> bool:
        """Return ``True`` iff ``path_edges`` exactly matches one
        of the allowed sequences.
        """
        return tuple(path_edges) in self._sequence_tuples

    def allowed_edge_types(self) -> frozenset[EdgeType]:
        """Flat set of every edge type appearing in any allowed
        sequence — useful for SQL pre-filters.
        """
        return frozenset(
            edge for seq in self.allowed_edge_sequences for edge in seq
        )


# ---------------------------------------------------------------------------
# Pre-defined policies — import these, never construct ad-hoc
# ---------------------------------------------------------------------------


STANDARD_ATTACK_PATH_POLICY = TraversalPolicy(
    name="standard_attack_path",
    description="Direct role assignment → permission → resource. Phase 1/2 behavior.",
    allowed_edge_sequences=[
        [EdgeType.HAS_ROLE, EdgeType.HAS_PERMISSION, EdgeType.CAN_ACCESS],
    ],
)


GROUP_AWARE_ATTACK_PATH_POLICY = TraversalPolicy(
    name="group_aware_attack_path",
    description="Adds group membership as a role acquisition path.",
    allowed_edge_sequences=[
        [EdgeType.HAS_ROLE, EdgeType.HAS_PERMISSION, EdgeType.CAN_ACCESS],
        [
            EdgeType.MEMBER_OF,
            EdgeType.HAS_ROLE,
            EdgeType.HAS_PERMISSION,
            EdgeType.CAN_ACCESS,
        ],
    ],
)


FULL_BLAST_RADIUS_POLICY = TraversalPolicy(
    name="full_blast_radius",
    description=(
        "All paths: direct roles, group inheritance, MSI trusts, "
        "delegation, ownership."
    ),
    max_depth=8,
    max_paths=200,
    allowed_edge_sequences=[
        [EdgeType.HAS_ROLE, EdgeType.HAS_PERMISSION, EdgeType.CAN_ACCESS],
        [EdgeType.HAS_ROLE, EdgeType.CAN_ACCESS],
        [
            EdgeType.MEMBER_OF,
            EdgeType.HAS_ROLE,
            EdgeType.HAS_PERMISSION,
            EdgeType.CAN_ACCESS,
        ],
        [EdgeType.MEMBER_OF, EdgeType.HAS_ROLE, EdgeType.CAN_ACCESS],
        [EdgeType.TRUSTS],
        [
            EdgeType.DELEGATES_TO,
            EdgeType.HAS_ROLE,
            EdgeType.HAS_PERMISSION,
            EdgeType.CAN_ACCESS,
        ],
        [EdgeType.DELEGATES_TO, EdgeType.HAS_ROLE, EdgeType.CAN_ACCESS],
        [EdgeType.OWNS],
    ],
)


BUILTIN_POLICIES: dict[str, TraversalPolicy] = {
    p.name: p
    for p in (
        STANDARD_ATTACK_PATH_POLICY,
        GROUP_AWARE_ATTACK_PATH_POLICY,
        FULL_BLAST_RADIUS_POLICY,
    )
}


__all__ = [
    "EdgeType",
    "TraversalPolicy",
    "STANDARD_ATTACK_PATH_POLICY",
    "GROUP_AWARE_ATTACK_PATH_POLICY",
    "FULL_BLAST_RADIUS_POLICY",
    "BUILTIN_POLICIES",
]
