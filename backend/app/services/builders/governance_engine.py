"""
GovernanceEngine — B04 pure derivation
======================================

:class:`GovernanceEngine` is a pure, in-memory derivation of the
:class:`GovernanceBlock` from three already-computed inputs: the
identity profile (B01), its activity state (B02), and its ownership
block (B03). It **never** touches the database.

Why this engine is pure
-----------------------
* The classification rules are deterministic and can be unit-tested
  without any fixtures, doubles, or DB stand-ins.
* The inputs already carry ``organization_id``; this engine just
  stamps the same id onto its output.
* The orchestrator calls this engine after the DB loaders finish —
  there is never a reason to re-query the database from here.

Thresholds
----------
Two thresholds govern the derivation:

* :data:`GOVERNANCE_RECENT_REVIEW_DAYS` — how recently an access
  review must have run for the identity to count as governed.
* :data:`GOVERNANCE_NO_CRED_ACTIVITY_DAYS` — how long an identity
  must have been idle before it counts as orphaned (not merely
  ungoverned).

Both are exported as module-level constants so tests and the
orchestrator can inspect them without reaching into private names.
"""

from __future__ import annotations

from typing import Optional

from app.schemas.identity import (
    ActivityState,
    BuilderDataSource,
    Confidence,
    GovernanceBlock,
    GovernanceClassification,
    IdentityProfile,
    IdentityType,
    OwnerQuality,
    OwnershipBlock,
)


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


#: Recent-review window. An access review newer than this classifies
#: the identity as governed (assuming the other invariants also hold).
GOVERNANCE_RECENT_REVIEW_DAYS: int = 90

#: Idle-activity window. Together with "no owner" and "never authed",
#: this is the threshold at which the engine classifies an identity
#: as orphaned rather than merely ungoverned.
GOVERNANCE_NO_CRED_ACTIVITY_DAYS: int = 180


def _require_org(organization_id: str) -> str:
    if not isinstance(organization_id, str) or not organization_id.strip():
        raise ValueError("organization_id is required and must be a non-empty string")
    return organization_id


# ---------------------------------------------------------------------------
# GovernanceEngine
# ---------------------------------------------------------------------------


class GovernanceEngine:
    """Pure derivation of the B04 :class:`GovernanceBlock`.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the engine and
        stamped onto the :class:`GovernanceBlock` :meth:`derive`
        returns.

    Notes
    -----
    The engine does not take a DB session — it is stateless apart
    from its ``organization_id`` binding. It can be instantiated
    cheaply and disposed of after a single ``derive()`` call.
    """

    def __init__(self, organization_id: str) -> None:
        self._organization_id = _require_org(organization_id)

    def derive(
        self,
        profile: IdentityProfile,
        activity: ActivityState,
        ownership: OwnershipBlock,
    ) -> GovernanceBlock:
        """Derive a :class:`GovernanceBlock` from the three upstream blocks.

        Classification rules (evaluated top-down — the first match wins)
        -----------------------------------------------------------------
        1. **Orphaned** — no owner, never authed, and no activity for
           longer than :data:`GOVERNANCE_NO_CRED_ACTIVITY_DAYS`.
        2. **PolicyViolation** — guest user without any owner, OR
           any identity whose access review is older than
           :data:`GOVERNANCE_RECENT_REVIEW_DAYS`.
        3. **Governed** — has an active owner AND a recent review.
        4. **Ungoverned** — every other configuration.

        The engine also emits a ``policy_violations`` list of short
        machine-readable codes so the API layer can surface them
        without re-running the derivation.
        """
        classification = self._classify(profile, activity, ownership)

        policy_violations: list[str] = []
        if classification == GovernanceClassification.POLICY_VIOLATION:
            if profile.identity_type == IdentityType.GUEST_USER and not ownership.owners:
                policy_violations.append("guest_without_owner_review")
            if (
                ownership.days_since_last_review is not None
                and ownership.days_since_last_review > GOVERNANCE_RECENT_REVIEW_DAYS
            ):
                policy_violations.append("review_overdue")

        # E2: derive data_source from upstream blocks
        ds, missing = self._derive_data_source(activity, ownership)

        return GovernanceBlock(
            organization_id=self._organization_id,
            classification=classification,
            is_governed=(classification == GovernanceClassification.GOVERNED),
            policy_violations=policy_violations,
            has_lifecycle_policy=classification == GovernanceClassification.GOVERNED,
            has_access_review=ownership.last_review_at is not None,
            governance_confidence=(
                Confidence.HIGH if ownership.owners else Confidence.LOW
            ),
            data_source=ds,
            missing_signals=missing,
        )

    @staticmethod
    def _classify(
        profile: IdentityProfile,
        activity: ActivityState,
        ownership: OwnershipBlock,
    ) -> GovernanceClassification:
        has_owner = bool(ownership.owners)
        has_active_owner = ownership.owner_quality == OwnerQuality.ACTIVE_OWNER
        never_authed = (
            activity.last_sign_in_at is None and activity.last_activity_at is None
        )
        no_recent_activity = (
            activity.days_since_last_activity is None
            or activity.days_since_last_activity > GOVERNANCE_NO_CRED_ACTIVITY_DAYS
        )

        # 1. Orphaned — strongest condition first.
        if not has_owner and never_authed and no_recent_activity:
            return GovernanceClassification.ORPHANED

        # 2. Policy violations — guest without owner, or overdue review.
        if profile.identity_type == IdentityType.GUEST_USER and not has_owner:
            return GovernanceClassification.POLICY_VIOLATION
        if (
            ownership.days_since_last_review is not None
            and ownership.days_since_last_review > GOVERNANCE_RECENT_REVIEW_DAYS
        ):
            return GovernanceClassification.POLICY_VIOLATION

        # 3. Governed — active owner AND recent review.
        recent_review: Optional[int] = ownership.days_since_last_review
        if (
            has_active_owner
            and ownership.last_review_at is not None
            and recent_review is not None
            and recent_review <= GOVERNANCE_RECENT_REVIEW_DAYS
        ):
            return GovernanceClassification.GOVERNED

        # 4. Everything else is ungoverned.
        return GovernanceClassification.UNGOVERNED

    @staticmethod
    def _derive_data_source(
        activity: ActivityState,
        ownership: OwnershipBlock,
    ) -> tuple[BuilderDataSource, list[str]]:
        """E2: compute governance data_source from upstream blocks.

        Both activity and ownership must be FULL for governance to be FULL.
        If either is NONE the governance block is NONE (cannot derive from
        nothing). Otherwise PARTIAL.
        """
        a_ds = activity.data_source
        o_ds = ownership.data_source

        missing: list[str] = []
        if a_ds == BuilderDataSource.NONE:
            missing.append("activity")
        if o_ds == BuilderDataSource.NONE:
            missing.append("ownership")

        if a_ds == BuilderDataSource.NONE and o_ds == BuilderDataSource.NONE:
            return BuilderDataSource.NONE, missing
        if a_ds == BuilderDataSource.FULL and o_ds == BuilderDataSource.FULL:
            return BuilderDataSource.FULL, []
        return BuilderDataSource.PARTIAL, missing
