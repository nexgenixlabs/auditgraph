"""
PostureScoreEngine — Phase 3 posture scoring with persistence
=============================================================

Computes a single 0-100 posture score for an organization from the
Phase 3 ``identity_list`` projection, along with five CVSS-aligned
dimension sub-scores, and upserts the result into ``posture_scores``.

Contract
--------
* Exactly one row per ``(organization_id, score_date::date)`` — a
  second call on the same UTC day overwrites the previous row.
* Scoring is **additive only** against the state of ``identity_list``
  at call time. The engine never mutates source data.
* ``computed_by`` is the ``ENGINE_VERSION`` constant — bump it whenever
  the scoring algorithm (not just SQL) changes so downstream consumers
  can invalidate caches or re-score historical rows if they care to.

Dimensions
----------
All five sub-scores are 0-100 where **higher is better** (safer posture).
They are deliberately simple percentage-style ratios — the point of E1
is to get *persisted, trendable* numbers wired end-to-end, not a new
risk model. The legacy ``Database.compute_posture_score`` in
``app/database.py`` remains the canonical place for heavyweight scoring
logic; this engine reuses the Phase 3 projection so the CISO dashboard
and ``/posture/score`` endpoints can read live scores without the
legacy pipeline running.

* **attack_surface**   — 100 − (at-risk count / total) × 100
* **privilege**        — 100 − (privileged count / total) × 100
* **credentials**      — 100 − (critical+high risk count / total) × 100
* **activity**         — 100 − (dormant+stale count / total) × 100
* **governance**       — (governed count / total) × 100

The overall score is the arithmetic mean of the five dimensions, rounded
to two decimals.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


#: Version string persisted in ``posture_scores.computed_by``. Bump this
#: whenever the scoring algorithm changes so consumers can tell at a
#: glance which version produced a historical row. Format: ``name@x.y.z``.
ENGINE_VERSION: str = "posture-engine@1.0.0"


__all__ = [
    "ENGINE_VERSION",
    "PostureScoreEngine",
    "PostureScoreError",
]


class PostureScoreError(Exception):
    """Raised when the engine cannot compute or persist a posture score."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PostureScoreEngine:
    """Computes and persists posture scores for one organization at a time."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # -- public -------------------------------------------------------------

    async def compute(self, organization_id: int | str) -> dict[str, Any]:
        """Compute the posture score for ``organization_id`` and upsert
        it into ``posture_scores``.

        Returns the persisted row as a plain dict. Idempotent per UTC day:
        re-running the same day overwrites the row in place.
        """
        org_int = self._coerce_org(organization_id)

        counts = await self._load_counts(org_int)
        dimensions = self._compute_dimensions(counts)
        overall = round(
            sum(dimensions.values()) / len(dimensions),
            2,
        )

        now = datetime.now(timezone.utc)

        row = {
            "organization_id": org_int,
            "score_date": now,
            "overall_score": overall,
            "dimension_scores": dimensions,
            "identity_count": counts["total"],
            "governed_count": counts["governed"],
            "orphaned_count": counts["orphaned"],
            "stale_count": counts["stale_or_dormant"],
            "at_risk_count": counts["at_risk"],
            "computed_by": ENGINE_VERSION,
        }

        await self._upsert(row)
        return row

    async def get_latest(self, organization_id: int | str) -> Optional[dict[str, Any]]:
        """Return the most recent posture row for the org, or ``None``."""
        org_int = self._coerce_org(organization_id)
        try:
            result = await self._db.execute(
                text(
                    """
                    SELECT id, organization_id, score_date, overall_score,
                           dimension_scores, identity_count, governed_count,
                           orphaned_count, stale_count, at_risk_count,
                           computed_by, created_at
                    FROM posture_scores
                    WHERE organization_id = :org
                    ORDER BY score_date DESC, id DESC
                    LIMIT 1
                    """
                ),
                {"org": org_int},
            )
            row = result.mappings().first()
        except SQLAlchemyError as exc:
            raise PostureScoreError(
                f"failed to load latest posture score for org {org_int}: {exc}"
            ) from exc
        return dict(row) if row else None

    async def get_history(
        self, organization_id: int | str, days: int = 30
    ) -> list[dict[str, Any]]:
        """Return posture rows for the last ``days`` days, ascending."""
        if days <= 0:
            raise ValueError("days must be > 0")
        org_int = self._coerce_org(organization_id)
        try:
            result = await self._db.execute(
                text(
                    """
                    SELECT id, organization_id, score_date, overall_score,
                           dimension_scores, identity_count, governed_count,
                           orphaned_count, stale_count, at_risk_count,
                           computed_by, created_at
                    FROM posture_scores
                    WHERE organization_id = :org
                      AND score_date >= (now() - make_interval(days => :days))
                    ORDER BY score_date ASC, id ASC
                    """
                ),
                {"org": org_int, "days": int(days)},
            )
            rows = result.mappings().all()
        except SQLAlchemyError as exc:
            raise PostureScoreError(
                f"failed to load posture history for org {org_int}: {exc}"
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

    async def _load_counts(self, org_int: int) -> dict[str, int]:
        """Aggregate the counts used to derive the 5 dimensions + headline
        metrics. All counts are read from ``identity_list`` — the Phase 3
        projection populated by the builder pipeline.
        """
        try:
            result = await self._db.execute(
                text(
                    """
                    SELECT
                        COUNT(*)                                       AS total,
                        COUNT(*) FILTER (
                            WHERE governance = 'Governed'
                        )                                              AS governed,
                        COUNT(*) FILTER (
                            WHERE governance = 'Orphaned'
                        )                                              AS orphaned,
                        COUNT(*) FILTER (
                            WHERE is_dormant = TRUE
                               OR lifecycle_state = 'Stale'
                               OR lifecycle_state = 'Dormant'
                        )                                              AS stale_or_dormant,
                        COUNT(*) FILTER (
                            WHERE risk_label IN ('High', 'Critical')
                        )                                              AS at_risk,
                        COUNT(*) FILTER (
                            WHERE privilege_level IN ('privileged', 'admin')
                        )                                              AS privileged,
                        COUNT(*) FILTER (
                            WHERE risk_label = 'Critical'
                        )                                              AS critical
                    FROM identity_list
                    WHERE organization_id = :org
                    """
                ),
                {"org": org_int},
            )
            row = result.mappings().first() or {}
        except SQLAlchemyError as exc:
            raise PostureScoreError(
                f"failed to aggregate identity_list for org {org_int}: {exc}"
            ) from exc

        return {
            "total": int(row.get("total") or 0),
            "governed": int(row.get("governed") or 0),
            "orphaned": int(row.get("orphaned") or 0),
            "stale_or_dormant": int(row.get("stale_or_dormant") or 0),
            "at_risk": int(row.get("at_risk") or 0),
            "privileged": int(row.get("privileged") or 0),
            "critical": int(row.get("critical") or 0),
        }

    @staticmethod
    def _compute_dimensions(counts: dict[str, int]) -> dict[str, float]:
        """Derive the 5 CVSS-aligned dimension sub-scores from the raw counts.

        Empty org (total == 0) scores 100 across every dimension — a
        vacuous-truth "perfect" posture. This is the only sensible default
        because any other value would falsely claim risk exists.
        """
        total = counts["total"]
        if total == 0:
            return {
                "attack_surface": 100.0,
                "privilege": 100.0,
                "credentials": 100.0,
                "activity": 100.0,
                "governance": 100.0,
            }

        def _pct_good(bad: int) -> float:
            return round(max(0.0, 100.0 - (bad / total) * 100.0), 2)

        return {
            "attack_surface": _pct_good(counts["at_risk"]),
            "privilege": _pct_good(counts["privileged"]),
            "credentials": _pct_good(counts["critical"]),
            "activity": _pct_good(counts["stale_or_dormant"]),
            "governance": round((counts["governed"] / total) * 100.0, 2),
        }

    async def _upsert(self, row: dict[str, Any]) -> None:
        """Upsert the row keyed on ``(organization_id, score_date::date)``.

        The unique index on the expression is from migration 088; this
        ``ON CONFLICT`` clause targets that index by its expression list
        so re-running the engine on the same UTC day overwrites rather
        than appends.
        """
        try:
            await self._db.execute(
                text(
                    """
                    INSERT INTO posture_scores (
                        organization_id, score_date, overall_score,
                        dimension_scores, identity_count, governed_count,
                        orphaned_count, stale_count, at_risk_count,
                        computed_by
                    )
                    VALUES (
                        :organization_id, :score_date, :overall_score,
                        CAST(:dimension_scores AS jsonb), :identity_count,
                        :governed_count, :orphaned_count, :stale_count,
                        :at_risk_count, :computed_by
                    )
                    ON CONFLICT (organization_id, ((score_date AT TIME ZONE 'UTC')::date))
                    DO UPDATE SET
                        overall_score    = EXCLUDED.overall_score,
                        dimension_scores = EXCLUDED.dimension_scores,
                        identity_count   = EXCLUDED.identity_count,
                        governed_count   = EXCLUDED.governed_count,
                        orphaned_count   = EXCLUDED.orphaned_count,
                        stale_count      = EXCLUDED.stale_count,
                        at_risk_count    = EXCLUDED.at_risk_count,
                        computed_by      = EXCLUDED.computed_by,
                        score_date       = EXCLUDED.score_date
                    """
                ),
                {
                    **row,
                    "dimension_scores": json.dumps(row["dimension_scores"]),
                },
            )
            await self._db.commit()
        except SQLAlchemyError as exc:
            await self._db.rollback()
            raise PostureScoreError(
                f"failed to upsert posture score for org "
                f"{row.get('organization_id')}: {exc}"
            ) from exc
