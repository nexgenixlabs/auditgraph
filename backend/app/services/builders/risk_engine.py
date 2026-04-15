"""
RiskEngine + RemediationEngine — B06 + B09 pure scoring
=======================================================

Both engines in this module are **pure**: they take already-built
blocks and produce a new block, with no DB I/O and no side effects.

RiskEngine
----------
CVSS v3.1-aligned: five independent dimensions
(privilege / activity / governance / credential / exposure), each
scored 0–10 from a single-source-of-truth lookup table, blended via
``max * FINAL_SCORE_MAX_WEIGHT + mean * FINAL_SCORE_MEAN_WEIGHT`` and
scaled to 0–100. The label comes from :data:`RISK_LABEL_THRESHOLDS`,
and every scoring table is exported at module scope so tests can
reason about them without reaching into private helpers.

RemediationEngine
-----------------
Colocated with :class:`RiskEngine` because the two share the same
scoring tables: the P0/P1 cutoffs are derived from the same 0–100
score. :class:`RemediationEngine` consumes a :class:`RiskScoreBlock`,
the :class:`AttackPathsBlock`, and a :class:`RotationStatus` scalar,
and produces a bucketed :class:`RemediationBlock`.

Phase 2 hook
------------
:meth:`RiskEngine.score_with_confidence` is declared today as a
``NotImplementedError`` stub so confidence-weighted scoring can
migrate its imports ahead of the implementation landing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Mapping, Optional

from app.schemas.identity import (
    ActivityState,
    AttackPathsBlock,
    GovernanceBlock,
    GovernanceClassification,
    IdentityProfile,
    PrivilegeBlock,
    PrivilegeLevel,
    RemediationAction,
    RemediationBlock,
    RiskFactor,
    RiskLabel,
    RiskScoreBlock,
    RotationStatus,
    ScopeBreadth,
)


# ---------------------------------------------------------------------------
# Scoring tables — single source of truth. No magic numbers inline below.
# ---------------------------------------------------------------------------


#: Risk-label thresholds (0–100 normalized score). Walked top-down —
#: the first row whose threshold the score clears wins.
RISK_LABEL_THRESHOLDS: tuple[tuple[float, RiskLabel], ...] = (
    (75.0, RiskLabel.CRITICAL),
    (50.0, RiskLabel.HIGH),
    (25.0, RiskLabel.MEDIUM),
    (10.0, RiskLabel.LOW),
)

#: Blend weights for the final score. The two weights must sum to 1.0.
FINAL_SCORE_MAX_WEIGHT: float = 0.4
FINAL_SCORE_MEAN_WEIGHT: float = 0.6

#: Cap on any individual dimension before blending.
MAX_DIMENSION: float = 10.0

#: Multiply blended 0–10 → 0–100.
FINAL_SCORE_SCALE: float = 10.0


PRIVILEGE_LEVEL_SCORES: Mapping[PrivilegeLevel, float] = {
    PrivilegeLevel.HIGHLY_PRIVILEGED: 9.0,
    PrivilegeLevel.PRIVILEGED: 6.0,
    PrivilegeLevel.STANDARD: 2.0,
}

SCOPE_BREADTH_MULTIPLIERS: Mapping[ScopeBreadth, float] = {
    ScopeBreadth.TENANT_WIDE: 1.10,
    ScopeBreadth.SUBSCRIPTION: 1.00,
    ScopeBreadth.RESOURCE_GROUP: 0.85,
    ScopeBreadth.RESOURCE: 0.70,
}

GOVERNANCE_SCORES: Mapping[GovernanceClassification, float] = {
    GovernanceClassification.ORPHANED: 10.0,
    GovernanceClassification.POLICY_VIOLATION: 8.0,
    GovernanceClassification.UNGOVERNED: 6.0,
    GovernanceClassification.GOVERNED: 1.0,
}

CREDENTIAL_SCORES: Mapping[RotationStatus, float] = {
    RotationStatus.EXPIRED: 10.0,
    RotationStatus.EXPIRING_SOON: 6.0,
    RotationStatus.NO_CREDENTIALS: 3.0,
    RotationStatus.CURRENT: 1.0,
}

EXPOSURE_SEVERITY_SCORES: Mapping[RiskLabel, float] = {
    RiskLabel.CRITICAL: 10.0,
    RiskLabel.HIGH: 7.5,
    RiskLabel.MEDIUM: 5.0,
    RiskLabel.LOW: 2.5,
    RiskLabel.INFO: 1.0,
}

# Activity scoring — declared as constants so the rules are auditable.
ACTIVITY_SCORE_NEVER_AUTHED: float = 9.0
ACTIVITY_SCORE_DORMANT: float = 8.0
ACTIVITY_STALE_DAYS: int = 90
ACTIVITY_SCORE_STALE: float = 5.0
ACTIVITY_SCORE_ACTIVE: float = 1.0

#: Version tag embedded in every :class:`RiskScoreBlock` so downstream
#: consumers can distinguish scoring-model upgrades from data changes.
RISK_MODEL_VERSION: str = "cvss3.1-blend-v1"

#: 0–100 thresholds for remediation bucketing. P0 means "fix now",
#: P1 means "fix this sprint", P2 means "track but don't block".
REMEDIATION_P0_SCORE: float = 75.0
REMEDIATION_P1_SCORE: float = 50.0


def _require_org(organization_id: str) -> str:
    if not isinstance(organization_id, str) or not organization_id.strip():
        raise ValueError("organization_id is required and must be a non-empty string")
    return organization_id


# ===========================================================================
# RiskEngine — B06
# ===========================================================================


class RiskEngine:
    """Pure CVSS v3.1-aligned scorer for the B06 :class:`RiskScoreBlock`.

    Parameters
    ----------
    organization_id:
        Owning tenant. Stamped onto the :class:`RiskScoreBlock` and
        every :class:`RiskFactor` the engine produces.

    Notes
    -----
    The engine holds no DB session and no hidden state — it's a
    stateless transform over already-built blocks. Call it as many
    times as you like; there is no init cost.
    """

    def __init__(self, organization_id: str) -> None:
        self._organization_id = _require_org(organization_id)

    def score(
        self,
        profile: IdentityProfile,
        activity: ActivityState,
        governance: GovernanceBlock,
        privilege: PrivilegeBlock,
        attack_paths: AttackPathsBlock,
        credential_status: RotationStatus,
    ) -> RiskScoreBlock:
        """Compute the blended 0–100 score and contributing factors.

        The ``profile`` parameter is accepted for symmetry with the
        Phase 2 hook (:meth:`score_with_confidence`) and for future
        identity-type-specific tweaks; today it is not read. Tests
        should still pass a real :class:`IdentityProfile` so the call
        shape matches production.
        """
        _ = profile  # reserved for Phase 2 confidence weighting

        privilege_score = self._score_privilege(privilege)
        activity_score = self._score_activity(activity)
        governance_score = self._score_governance(governance)
        credential_score = self._score_credential(credential_status)
        exposure_score = self._score_exposure(attack_paths)

        dimensions: list[tuple[str, float]] = [
            ("privilege", privilege_score),
            ("activity", activity_score),
            ("governance", governance_score),
            ("credential", credential_score),
            ("exposure", exposure_score),
        ]
        values = [v for _, v in dimensions]

        blended = (max(values) * FINAL_SCORE_MAX_WEIGHT) + (
            mean(values) * FINAL_SCORE_MEAN_WEIGHT
        )
        normalized = round(min(blended * FINAL_SCORE_SCALE, 100.0), 2)
        label = self._label_for_score(normalized)

        factors = [
            RiskFactor(
                organization_id=self._organization_id,
                dimension=name,
                label=self._label_for_score(value * FINAL_SCORE_SCALE).value,
                contribution=round(value, 2),
                severity=self._label_for_score(value * FINAL_SCORE_SCALE),
            )
            for name, value in dimensions
        ]

        return RiskScoreBlock(
            organization_id=self._organization_id,
            score=normalized,
            label=label,
            factors=factors,
            computed_at=datetime.now(timezone.utc),
            model_version=RISK_MODEL_VERSION,
        )

    def score_with_confidence(
        self,
        profile: IdentityProfile,
        activity: ActivityState,
        governance: GovernanceBlock,
        privilege: PrivilegeBlock,
        attack_paths: AttackPathsBlock,
        credential_status: RotationStatus,
    ) -> RiskScoreBlock:
        """Phase 2 hook for confidence-weighted scoring.

        Not implemented yet — declared so callers can migrate imports
        ahead of the implementation landing. Phase 2 will weight each
        dimension by its source :class:`Confidence` enum before the
        max/mean blend.
        """
        raise NotImplementedError(
            "Phase 2: RiskEngine.score_with_confidence() will weight each "
            "dimension by its source confidence (Confidence enum)"
        )

    # ------------------------------------------------------------------
    # Dimension scorers (pure functions)
    # ------------------------------------------------------------------

    @staticmethod
    def _score_privilege(privilege: PrivilegeBlock) -> float:
        base = PRIVILEGE_LEVEL_SCORES[privilege.privilege_level]
        multiplier = SCOPE_BREADTH_MULTIPLIERS[privilege.scope_breadth]
        return min(MAX_DIMENSION, base * multiplier)

    @staticmethod
    def _score_activity(activity: ActivityState) -> float:
        if activity.last_sign_in_at is None and activity.last_activity_at is None:
            return ACTIVITY_SCORE_NEVER_AUTHED
        if activity.is_dormant:
            return ACTIVITY_SCORE_DORMANT
        if (
            activity.days_since_last_activity is not None
            and activity.days_since_last_activity > ACTIVITY_STALE_DAYS
        ):
            return ACTIVITY_SCORE_STALE
        return ACTIVITY_SCORE_ACTIVE

    @staticmethod
    def _score_governance(governance: GovernanceBlock) -> float:
        return GOVERNANCE_SCORES[governance.classification]

    @staticmethod
    def _score_credential(status: RotationStatus) -> float:
        return CREDENTIAL_SCORES[status]

    @staticmethod
    def _score_exposure(attack_paths: AttackPathsBlock) -> float:
        if not attack_paths.paths:
            return 0.0
        return max(EXPOSURE_SEVERITY_SCORES[p.severity] for p in attack_paths.paths)

    @staticmethod
    def _label_for_score(score: float) -> RiskLabel:
        for threshold, label in RISK_LABEL_THRESHOLDS:
            if score >= threshold:
                return label
        return RiskLabel.INFO


# ===========================================================================
# RemediationEngine — B09 (colocated)
# ===========================================================================


class RemediationEngine:
    """Pure bucketer for the B09 :class:`RemediationBlock`.

    Parameters
    ----------
    organization_id:
        Owning tenant. Stamped onto the :class:`RemediationBlock`
        and every :class:`RemediationAction` the engine emits.
    """

    def __init__(self, organization_id: str) -> None:
        self._organization_id = _require_org(organization_id)

    def compute(
        self,
        risk_score: RiskScoreBlock,
        attack_paths: AttackPathsBlock,
        credentials: Optional[RotationStatus] = None,
    ) -> RemediationBlock:
        """Bucket remediation actions into P0 / P1 / P2.

        Rules (all additive — an identity can trigger more than one)
        -----------------------------------------------------------
        * ``score >= REMEDIATION_P0_SCORE`` → P0 "immediate review".
        * ``credentials == EXPIRED`` → P0 rotate credential.
        * ``credentials == EXPIRING_SOON`` → P1 schedule rotation.
        * Each Critical attack path → P0; each High → P1.
        * Score in ``[REMEDIATION_P1_SCORE, REMEDIATION_P0_SCORE)``
          with no existing P0/P1 → P1 "review this sprint".
        """
        actions: list[RemediationAction] = []

        if risk_score.score >= REMEDIATION_P0_SCORE:
            actions.append(
                RemediationAction(
                    organization_id=self._organization_id,
                    priority=0,
                    description="Immediate review — identity is in Critical risk tier.",
                    auto_fixable=False,
                    fix_command=None,
                )
            )

        if credentials == RotationStatus.EXPIRED:
            actions.append(
                RemediationAction(
                    organization_id=self._organization_id,
                    priority=0,
                    description="Rotate expired credential.",
                    auto_fixable=True,
                    fix_command="rotate_credential",
                )
            )
        elif credentials == RotationStatus.EXPIRING_SOON:
            actions.append(
                RemediationAction(
                    organization_id=self._organization_id,
                    priority=1,
                    description="Schedule credential rotation before expiry.",
                    auto_fixable=True,
                    fix_command="schedule_rotation",
                )
            )

        for path in attack_paths.paths:
            if path.severity in (RiskLabel.CRITICAL, RiskLabel.HIGH):
                actions.append(
                    RemediationAction(
                        organization_id=self._organization_id,
                        priority=0 if path.severity == RiskLabel.CRITICAL else 1,
                        description=(
                            f"Break attack path {path.path_id} "
                            f"({path.path_type}) → {path.target.name}"
                        ),
                        auto_fixable=False,
                        fix_command=None,
                    )
                )

        if (
            REMEDIATION_P1_SCORE <= risk_score.score < REMEDIATION_P0_SCORE
            and not any(a.priority <= 1 for a in actions)
        ):
            actions.append(
                RemediationAction(
                    organization_id=self._organization_id,
                    priority=1,
                    description="Review elevated-risk identity within this sprint.",
                    auto_fixable=False,
                    fix_command=None,
                )
            )

        p0 = sum(1 for a in actions if a.priority == 0)
        p1 = sum(1 for a in actions if a.priority == 1)
        p2 = sum(1 for a in actions if a.priority >= 2)

        return RemediationBlock(
            organization_id=self._organization_id,
            p0_count=p0,
            p1_count=p1,
            p2_count=p2,
            actions=actions,
        )
