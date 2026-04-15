"""
WhatIfService — Phase 3 hypothetical identity remediation simulator
====================================================================

Persists every ``simulate()`` call into ``whatif_simulations`` (migration
088). Each row is a forensic record of a hypothetical change the
operator considered — what they would have done, and what the score /
blast-radius delta would have been if they had.

Contract (E1)
-------------
* Three simulation types are recognized:

  - ``ROLE_REMOVAL``         — remove one named role from the identity
  - ``PRIVILEGE_REDUCTION``  — downgrade the identity's privilege level
  - ``OWNERSHIP_ASSIGNMENT`` — assign a new owner to an orphaned identity

* Every ``simulate()`` call produces a :class:`WhatIfResult` which is
  validated through Pydantic **before** the row is written. If the result
  cannot be serialized against the contract, the service fails loudly
  instead of writing garbage JSON — this is the "fail-hard" rule from
  the E1 spec.

* ``result_payload`` is the Pydantic model dumped as JSON. Consumers of
  ``GET /identities/{id}/simulations`` re-parse it through the same
  model so a contract drift in either direction is caught.

* No uniqueness constraint on ``(organization_id, identity_id)`` — a
  single identity can be simulated many times under different inputs.

MVP scoring model
-----------------
The before/after numbers come from the current ``identity_list`` row.
``blast_radius_before`` is ``risk_score`` rounded to int (a proxy — the
full blast radius engine is plumbed through the Phase 3 identity state
engine, which is more work than E1 needs). Each simulation type applies
a deterministic delta so the persisted trail is predictable and
round-trippable in tests.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


#: Version string persisted in the ``result_payload.engine_version`` field
#: so consumers can invalidate cached results when the scoring logic
#: changes. Bump alongside :data:`PostureScoreEngine.ENGINE_VERSION`
#: when cross-engine math changes.
ENGINE_VERSION: str = "whatif-service@1.0.0"


#: The three recognized simulation types. Adding a fourth requires a
#: bump of :data:`ENGINE_VERSION` and a matching branch in
#: :meth:`WhatIfService._simulate_type`.
SimulationType = Literal[
    "ROLE_REMOVAL",
    "PRIVILEGE_REDUCTION",
    "OWNERSHIP_ASSIGNMENT",
]


__all__ = [
    "ENGINE_VERSION",
    "SimulationType",
    "WhatIfResult",
    "WhatIfService",
    "WhatIfError",
    "WhatIfIdentityNotFound",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class WhatIfError(Exception):
    """Raised when the service cannot compute or persist a simulation."""


class WhatIfIdentityNotFound(WhatIfError):
    """Raised when the target identity is not visible to this org."""


# ---------------------------------------------------------------------------
# Pydantic contract
# ---------------------------------------------------------------------------


class WhatIfResult(BaseModel):
    """Pydantic contract for a ``WhatIfService.simulate()`` result.

    Persisted verbatim into ``whatif_simulations.result_payload``. Every
    field is required — there is no "optional" telemetry here. Adding a
    field is a version bump; removing one is a migration.
    """

    simulation_id: Optional[str] = Field(
        default=None,
        description=(
            "UUID assigned when the row is persisted. Populated by the "
            "service after the INSERT returns its id — clients never set it."
        ),
    )
    simulation_type: SimulationType
    organization_id: int = Field(..., ge=1)
    identity_id: str = Field(..., min_length=1)
    identity_display_name: str
    before: "WhatIfSnapshot"
    after: "WhatIfSnapshot"
    blast_radius_before: int = Field(..., ge=0)
    blast_radius_after: int = Field(..., ge=0)
    score_delta: float
    narrative: str = Field(
        ...,
        description=(
            "Human-readable one-sentence explanation of what the "
            "simulation modelled and what the delta means."
        ),
    )
    simulated_at: datetime
    engine_version: str = Field(default=ENGINE_VERSION)

    model_config = {"protected_namespaces": ()}


class WhatIfSnapshot(BaseModel):
    """Compact before/after projection used inside :class:`WhatIfResult`.

    Only the fields that actually change under one of the three E1
    simulation types are captured — keeping the JSON small means the
    ``whatif_simulations.result_payload`` index stays cheap.
    """

    risk_score: float = Field(..., ge=0.0)  # no upper bound — legacy data may exceed 100
    risk_label: str
    privilege_level: str
    governance: str
    is_dormant: bool

    model_config = {"protected_namespaces": ()}


# Forward-ref resolution so the nested snapshot type on ``WhatIfResult``
# can reference ``WhatIfSnapshot`` defined below.
WhatIfResult.model_rebuild()


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class WhatIfService:
    """Simulates hypothetical remediations and persists every run."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # -- public -------------------------------------------------------------

    async def simulate(
        self,
        *,
        organization_id: int | str,
        identity_id: str,
        simulation_type: SimulationType,
        payload: dict[str, Any],
        simulated_by: Optional[int] = None,
    ) -> WhatIfResult:
        """Run a what-if simulation and persist its result.

        Raises
        ------
        ValueError
            If ``simulation_type`` is not a recognized literal.
        WhatIfIdentityNotFound
            If no row for ``(organization_id, identity_id)`` exists in
            ``identity_list``.
        WhatIfError
            On any persistence failure or contract violation.
        """
        if simulation_type not in (
            "ROLE_REMOVAL",
            "PRIVILEGE_REDUCTION",
            "OWNERSHIP_ASSIGNMENT",
        ):
            raise ValueError(f"unknown simulation_type: {simulation_type!r}")
        org_int = self._coerce_org(organization_id)
        if not identity_id:
            raise ValueError("identity_id is required")

        current = await self._load_identity(org_int, identity_id)
        if current is None:
            raise WhatIfIdentityNotFound(
                f"identity {identity_id!r} not found for org {org_int}"
            )

        before = self._snapshot(current)
        after, narrative = self._simulate_type(simulation_type, before, payload)
        score_delta = round(after.risk_score - before.risk_score, 2)

        # Blast radius proxy — see module docstring. When the full
        # BlastRadiusEngine is wired through the what-if path, replace
        # these with the real before/after totals.
        blast_before = int(round(before.risk_score))
        blast_after = int(round(after.risk_score))

        now = datetime.now(timezone.utc)

        # Build and VALIDATE the result before touching the DB.
        # Pydantic validation is the "fail-loudly" gate.
        try:
            result = WhatIfResult(
                simulation_type=simulation_type,
                organization_id=org_int,
                identity_id=identity_id,
                identity_display_name=str(current.get("display_name") or identity_id),
                before=before,
                after=after,
                blast_radius_before=blast_before,
                blast_radius_after=blast_after,
                score_delta=score_delta,
                narrative=narrative,
                simulated_at=now,
                engine_version=ENGINE_VERSION,
            )
        except ValidationError as exc:
            raise WhatIfError(
                f"whatif result failed contract validation: {exc}"
            ) from exc

        simulation_id = await self._persist(
            org_int=org_int,
            identity_id=identity_id,
            simulation_type=simulation_type,
            input_payload=payload or {},
            result=result,
            blast_before=blast_before,
            blast_after=blast_after,
            score_delta=score_delta,
            simulated_at=now,
            simulated_by=simulated_by,
        )

        # Return a copy with the freshly-assigned UUID so the caller
        # can surface it in the HTTP response body.
        return result.model_copy(update={"simulation_id": simulation_id})

    async def list_for_identity(
        self,
        *,
        organization_id: int | str,
        identity_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return persisted simulations for one identity, newest first."""
        org_int = self._coerce_org(organization_id)
        try:
            res = await self._db.execute(
                text(
                    """
                    SELECT id, organization_id, identity_id, simulation_type,
                           input_payload, result_payload, blast_radius_before,
                           blast_radius_after, score_delta, simulated_at,
                           simulated_by
                    FROM whatif_simulations
                    WHERE organization_id = :org
                      AND identity_id     = :identity_id
                    ORDER BY simulated_at DESC, id DESC
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {
                    "org": org_int,
                    "identity_id": identity_id,
                    "limit": int(limit),
                    "offset": int(offset),
                },
            )
            rows = res.mappings().all()
        except SQLAlchemyError as exc:
            raise WhatIfError(
                f"failed to list simulations for {identity_id!r}: {exc}"
            ) from exc
        return [dict(r) for r in rows]

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _coerce_org(organization_id: int | str) -> int:
        try:
            return int(organization_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"organization_id must be an integer, got {organization_id!r}"
            ) from exc

    async def _load_identity(
        self, org_int: int, identity_id: str
    ) -> Optional[dict[str, Any]]:
        try:
            res = await self._db.execute(
                text(
                    """
                    SELECT identity_id, display_name, risk_score, risk_label,
                           privilege_level, governance, is_dormant
                    FROM identity_list
                    WHERE organization_id = :org
                      AND identity_id     = :identity_id
                    """
                ),
                {"org": org_int, "identity_id": identity_id},
            )
            row = res.mappings().first()
        except SQLAlchemyError as exc:
            raise WhatIfError(
                f"failed to load identity_list row for {identity_id!r}: {exc}"
            ) from exc
        return dict(row) if row else None

    @staticmethod
    def _snapshot(row: dict[str, Any]) -> WhatIfSnapshot:
        return WhatIfSnapshot(
            risk_score=float(row.get("risk_score") or 0.0),
            risk_label=str(row.get("risk_label") or "Low"),
            privilege_level=str(row.get("privilege_level") or "standard"),
            governance=str(row.get("governance") or "Governed"),
            is_dormant=bool(row.get("is_dormant") or False),
        )

    def _simulate_type(
        self,
        simulation_type: SimulationType,
        before: WhatIfSnapshot,
        payload: dict[str, Any],
    ) -> tuple[WhatIfSnapshot, str]:
        """Apply the deterministic delta for one simulation type.

        Each branch returns the ``after`` snapshot and a short narrative.
        The deltas are intentionally simple — see the module docstring
        for the MVP-scoring caveat.
        """
        if simulation_type == "ROLE_REMOVAL":
            role = str(payload.get("role") or "unknown-role")
            # Removing a role reduces risk by 15 points, floored at 0.
            after_score = max(0.0, round(before.risk_score - 15.0, 2))
            after = before.model_copy(
                update={
                    "risk_score": after_score,
                    "risk_label": self._label_for(after_score),
                }
            )
            narrative = (
                f"Removing role '{role}' would reduce risk score by "
                f"{round(before.risk_score - after_score, 2)}."
            )
            return after, narrative

        if simulation_type == "PRIVILEGE_REDUCTION":
            target = str(payload.get("target_level") or "standard")
            # Downgrading privilege reduces risk by 25 points.
            after_score = max(0.0, round(before.risk_score - 25.0, 2))
            after = before.model_copy(
                update={
                    "risk_score": after_score,
                    "risk_label": self._label_for(after_score),
                    "privilege_level": target,
                }
            )
            narrative = (
                f"Downgrading privilege to '{target}' would reduce risk "
                f"score by {round(before.risk_score - after_score, 2)}."
            )
            return after, narrative

        if simulation_type == "OWNERSHIP_ASSIGNMENT":
            owner = str(payload.get("owner") or "unassigned")
            # Fixing orphan governance gives a flat 10-point credit.
            after_score = max(0.0, round(before.risk_score - 10.0, 2))
            after = before.model_copy(
                update={
                    "risk_score": after_score,
                    "risk_label": self._label_for(after_score),
                    "governance": "Governed",
                }
            )
            narrative = (
                f"Assigning owner '{owner}' would move governance to "
                f"'Governed' and reduce risk score by "
                f"{round(before.risk_score - after_score, 2)}."
            )
            return after, narrative

        # _simulate_type is only called after simulate() has validated
        # the literal, so this branch is unreachable.
        raise ValueError(
            f"unreachable: unknown simulation_type {simulation_type!r}"
        )

    @staticmethod
    def _label_for(score: float) -> str:
        """Map a numeric risk score back to a coarse label bucket.

        Buckets are the same as the rest of the Phase 3 pipeline:

        ======  ==============
        Score   Label
        ======  ==============
        ≥ 80    ``Critical``
        ≥ 60    ``High``
        ≥ 40    ``Medium``
        ≥ 20    ``Low``
        <  20   ``Info``
        ======  ==============
        """
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 40:
            return "Medium"
        if score >= 20:
            return "Low"
        return "Info"

    async def _persist(
        self,
        *,
        org_int: int,
        identity_id: str,
        simulation_type: SimulationType,
        input_payload: dict[str, Any],
        result: WhatIfResult,
        blast_before: int,
        blast_after: int,
        score_delta: float,
        simulated_at: datetime,
        simulated_by: Optional[int],
    ) -> str:
        """Insert the row and return the generated ``id`` as a string."""
        try:
            res = await self._db.execute(
                text(
                    """
                    INSERT INTO whatif_simulations (
                        organization_id, identity_id, simulation_type,
                        input_payload, result_payload,
                        blast_radius_before, blast_radius_after,
                        score_delta, simulated_at, simulated_by
                    )
                    VALUES (
                        :org, :identity_id, :simulation_type,
                        CAST(:input_payload  AS jsonb),
                        CAST(:result_payload AS jsonb),
                        :blast_before, :blast_after,
                        :score_delta, :simulated_at, :simulated_by
                    )
                    RETURNING id
                    """
                ),
                {
                    "org": org_int,
                    "identity_id": identity_id,
                    "simulation_type": simulation_type,
                    "input_payload": json.dumps(input_payload),
                    "result_payload": result.model_dump_json(),
                    "blast_before": blast_before,
                    "blast_after": blast_after,
                    "score_delta": score_delta,
                    "simulated_at": simulated_at,
                    "simulated_by": simulated_by,
                },
            )
            row = res.first()
            await self._db.commit()
        except SQLAlchemyError as exc:
            await self._db.rollback()
            raise WhatIfError(
                f"failed to persist simulation for {identity_id!r}: {exc}"
            ) from exc
        if row is None:
            raise WhatIfError("INSERT RETURNING id produced no row")
        return str(row[0])
