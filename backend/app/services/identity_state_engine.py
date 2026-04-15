"""
IdentityStateEngine — pure orchestrator
=======================================

Thin wiring layer that composes the focused builders in
:mod:`app.services.builders` into a full :class:`IdentityState`.

Design contract
---------------
* **Zero business logic.** Every decision — SQL, thresholds, scoring
  tables, classification rules — lives in the builders. The engine
  only orchestrates the calls in the correct order and plumbs the
  outputs through.
* **Dependency injection.** Every builder can be overridden via the
  constructor so tests can pass in fakes without monkeypatching.
  The engine instantiates standard implementations for anything
  left ``None``.
* **Single public method.** :meth:`build` is the only entry point;
  the engine is stateless across calls except for its
  ``organization_id`` binding and its DB session.
* **Re-exports.** The exception types raised by the builders are
  re-exported here for backwards compatibility with callers that
  wrote ``except IdentityStateBuildError:`` against the old
  monolith.

Builder wiring order (matches the data-flow graph)
--------------------------------------------------
1.  profile         — :class:`IdentityProfileBuilder`
2.  activity        — :class:`ActivityBuilder`
3.  ownership       — :class:`OwnershipBuilder`   (colocated w/ profile)
4.  governance      — :class:`GovernanceEngine`   (pure; needs 1–3)
5.  privilege       — :class:`PrivilegeBuilder`   (colocated w/ profile)
6.  roles           — :class:`RolesLoader`        (colocated w/ activity)
7.  attack_paths    — :class:`AttackPathEngine`
8.  credentials     — :class:`CredentialLoader`   (colocated w/ profile)
9.  risk            — :class:`RiskEngine`         (pure; needs 1–8)
10. remediation     — :class:`RemediationEngine`  (pure; needs 7, 8, 9)

Snapshot metadata
-----------------
The orchestrator owns exactly one DB query of its own: the
``identity_snapshots`` lookup for the snapshot's timestamp. This is
build-level provenance, not block data, and it would be awkward to
push it into any of the builders — it does not belong to any single
block.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import (
    DataContext,
    DataMode,
    IdentityState,
)
from app.services.builders.activity_builder import (
    ActivityBuilder,
    RolesLoader,
)
from app.services.builders.attack_path_engine import AttackPathEngine
from app.services.builders.governance_engine import GovernanceEngine
from app.services.builders.identity_profile_builder import (
    CredentialLoader,
    IdentityNotFoundError,
    IdentityProfileBuilder,
    OrganizationScopeError,
    OwnershipBuilder,
    PrivilegeBuilder,
    ProfileBuildError,
)
from app.services.builders.identity_blast_radius_engine import (
    IdentityBlastRadiusEngine,
)
from app.services.builders.risk_engine import (
    RemediationEngine,
    RiskEngine,
)
from app.services.global_identity_registry import GlobalIdentityRegistry
from app.config.feature_flags import FeatureFlags


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestration-level tunables
# ---------------------------------------------------------------------------


#: Live payloads older than this are marked stale when the build
#: finishes. Snapshot mode never applies this check — snapshots are
#: always "as-of" their capture time by definition.
STALENESS_THRESHOLD_MINUTES: int = 15


# ---------------------------------------------------------------------------
# Re-exported exceptions (backwards compatibility with the old monolith)
# ---------------------------------------------------------------------------


#: Alias for :class:`ProfileBuildError`. The old monolith exposed
#: ``IdentityStateBuildError`` as the base class for every build
#: failure; preserving the name here keeps existing ``except`` clauses
#: working without forcing a rename.
IdentityStateBuildError = ProfileBuildError


__all__ = [
    "IdentityStateEngine",
    "IdentityStateBuildError",
    "IdentityNotFoundError",
    "OrganizationScopeError",
    "STALENESS_THRESHOLD_MINUTES",
]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class IdentityStateEngine:
    """Composes the ten block builders into a single :class:`IdentityState`.

    Parameters
    ----------
    organization_id:
        Owning tenant. Bound for the lifetime of the engine and
        threaded into every builder.
    db:
        Async SQLAlchemy session managed by the caller. The engine
        never commits or rolls back on its own.
    registry:
        Optional :class:`GlobalIdentityRegistry`. Defaults to a
        default-constructed instance. Passing a prebuilt registry in
        tests lets them avoid the registry's own DB bootstrap.
    profile_builder, activity_builder, ownership_builder,
    privilege_builder, credential_loader, roles_loader,
    attack_path_engine, governance_engine, risk_engine,
    remediation_engine:
        Optional builder overrides for dependency injection. Any
        builder left ``None`` is instantiated with the same
        ``organization_id`` / ``db`` the engine is bound to. Passing
        fakes in tests avoids monkeypatching and keeps every test
        fully hermetic.
    """

    def __init__(
        self,
        organization_id: str,
        db: AsyncSession,
        *,
        registry: Optional[GlobalIdentityRegistry] = None,
        profile_builder: Optional[IdentityProfileBuilder] = None,
        activity_builder: Optional[ActivityBuilder] = None,
        ownership_builder: Optional[OwnershipBuilder] = None,
        privilege_builder: Optional[PrivilegeBuilder] = None,
        credential_loader: Optional[CredentialLoader] = None,
        roles_loader: Optional[RolesLoader] = None,
        attack_path_engine: Optional[AttackPathEngine] = None,
        blast_radius_engine: Optional[IdentityBlastRadiusEngine] = None,
        governance_engine: Optional[GovernanceEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        remediation_engine: Optional[RemediationEngine] = None,
    ) -> None:
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise ValueError("organization_id is required and must be a non-empty string")
        if db is None:
            raise ValueError("db (AsyncSession) is required")

        self._organization_id: str = organization_id
        self._db: AsyncSession = db
        self._registry: GlobalIdentityRegistry = registry or GlobalIdentityRegistry()

        # DB-backed builders — every one gets the same (org, db) pair.
        self._profile_builder = profile_builder or IdentityProfileBuilder(
            organization_id, self._registry, db
        )
        self._activity_builder = activity_builder or ActivityBuilder(
            organization_id, db
        )
        self._ownership_builder = ownership_builder or OwnershipBuilder(
            organization_id, db
        )
        self._privilege_builder = privilege_builder or PrivilegeBuilder(
            organization_id, db
        )
        self._credential_loader = credential_loader or CredentialLoader(
            organization_id, db
        )
        self._roles_loader = roles_loader or RolesLoader(organization_id, db)
        self._attack_path_engine = attack_path_engine or AttackPathEngine(
            organization_id, db
        )
        self._blast_radius_engine = blast_radius_engine or IdentityBlastRadiusEngine(
            organization_id, db
        )

        # Pure engines — no db needed.
        self._governance_engine = governance_engine or GovernanceEngine(organization_id)
        self._risk_engine = risk_engine or RiskEngine(organization_id)
        self._remediation_engine = remediation_engine or RemediationEngine(
            organization_id
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def build(
        self,
        identity_id: str,
        data_mode: DataMode,
        snapshot_id: Optional[int] = None,
    ) -> IdentityState:
        """Build a complete :class:`IdentityState` for ``identity_id``.

        Parameters
        ----------
        identity_id:
            Provider-native identity id (object id, ARN, etc.).
        data_mode:
            Mandatory — :attr:`DataMode.LIVE` reads current tables,
            :attr:`DataMode.SNAPSHOT` reads the snapshot tables at
            ``snapshot_id``.
        snapshot_id:
            Required iff ``data_mode == DataMode.SNAPSHOT``. Must be
            ``None`` in live mode.

        Raises
        ------
        ValueError
            If ``data_mode`` / ``snapshot_id`` invariants are violated.
        IdentityNotFoundError
            If no row exists for ``identity_id`` under this org.
        OrganizationScopeError
            If any DB row crosses the organization boundary.
        IdentityStateBuildError
            On any other underlying failure, with the original
            exception chained.
        """
        if not identity_id:
            raise ValueError("identity_id is required")
        if not isinstance(data_mode, DataMode):
            raise ValueError("data_mode must be a DataMode enum value")
        if data_mode == DataMode.SNAPSHOT and snapshot_id is None:
            raise ValueError("snapshot_id required for snapshot mode")
        if data_mode == DataMode.LIVE and snapshot_id is not None:
            raise ValueError("snapshot_id must be None in live mode")

        computed_at = datetime.now(timezone.utc)
        snapshot_date = (
            await self._load_snapshot_date(snapshot_id) if snapshot_id else None
        )

        initial_context = DataContext(
            data_mode=data_mode,
            snapshot_id=snapshot_id,
            snapshot_date=snapshot_date,
            computed_at=computed_at,
            is_stale=False,
        )

        logger.debug(
            "identity_state.build start org=%s id=%s mode=%s snapshot=%s",
            self._organization_id,
            identity_id,
            data_mode.value,
            snapshot_id,
        )

        try:
            # 1. IdentityProfile (B01) — source of truth for type + cloud
            profile = await self._profile_builder.build(
                identity_id, data_mode, snapshot_id
            )
            # 2. ActivityState (B02)
            activity = await self._activity_builder.build(
                identity_id, data_mode, snapshot_id
            )
            # 3. OwnershipBlock (B03)
            ownership = await self._ownership_builder.build(
                identity_id, data_mode, snapshot_id
            )
            # 4. GovernanceBlock (B04) — pure derivation of 1–3
            governance = self._governance_engine.derive(
                profile, activity, ownership
            )
            # 5. PrivilegeBlock (B05)
            privilege = await self._privilege_builder.build(
                identity_id, data_mode, snapshot_id
            )
            # 6. RolesBlock (B07)
            roles = await self._roles_loader.load(
                identity_id, data_mode, snapshot_id
            )
            # 7. AttackPathsBlock (B08)
            attack_paths = await self._attack_path_engine.compute(
                identity_id, privilege, data_mode, snapshot_id
            )
            # 8. Credential status — scalar input to risk + remediation
            credential_status = await self._credential_loader.load(
                identity_id, data_mode, snapshot_id
            )
            # 9. RiskScoreBlock (B06) — pure scoring over 1–8
            risk_score = self._risk_engine.score(
                profile,
                activity,
                governance,
                privilege,
                attack_paths,
                credential_status,
            )
            # 10. RemediationBlock (B09) — pure bucketing of 7, 8, 9
            remediation = self._remediation_engine.compute(
                risk_score, attack_paths, credential_status
            )
        except (IdentityNotFoundError, OrganizationScopeError, ValueError):
            # Propagate domain / invariant errors untouched.
            raise
        except SQLAlchemyError as exc:
            raise IdentityStateBuildError(
                "database error during identity state build",
                context={
                    "organization_id": self._organization_id,
                    "identity_id": identity_id,
                    "data_mode": data_mode.value,
                    "snapshot_id": snapshot_id,
                },
            ) from exc

        # 7b. BlastRadiusResult — Phase 3 enrichment.
        # Gated by USE_BLAST_RADIUS, independent of
        # USE_GRAPH_ATTACK_PATHS. Never fails the build — wrapped
        # in its own try/except so a blast radius failure
        # degrades gracefully to ``blast_radius=None``.
        blast_radius = None
        if FeatureFlags.USE_BLAST_RADIUS:
            try:
                blast_radius = await self._blast_radius_engine.compute(
                    identity_id=identity_id,
                    data_mode=data_mode,
                    snapshot_id=snapshot_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "blast_radius.compute failed org=%s id=%s err=%s",
                    self._organization_id,
                    identity_id,
                    exc,
                )

        # 7c. Dual-run: staging/canary only. Compares the new
        # engine against the legacy one and logs divergence —
        # never raises, never blocks the build.
        if FeatureFlags.BLAST_RADIUS_DUAL_RUN:
            try:
                await self._compare_blast_radius_engines(
                    identity_id=identity_id,
                    new_result=blast_radius,
                )
            except Exception:  # noqa: BLE001
                pass

        # Finalize staleness (live mode only) against the final wall clock.
        final_is_stale = False
        if data_mode == DataMode.LIVE:
            age = datetime.now(timezone.utc) - initial_context.computed_at
            final_is_stale = age > timedelta(minutes=STALENESS_THRESHOLD_MINUTES)

        final_context = DataContext(
            data_mode=initial_context.data_mode,
            snapshot_id=initial_context.snapshot_id,
            snapshot_date=initial_context.snapshot_date,
            computed_at=initial_context.computed_at,
            is_stale=final_is_stale,
        )

        # Profile carries its own data_context — keep them in lock-step.
        profile = profile.model_copy(update={"data_context": final_context})

        state = IdentityState(
            organization_id=self._organization_id,
            profile=profile,
            activity=activity,
            ownership=ownership,
            governance=governance,
            privilege=privilege,
            risk=risk_score,
            roles=roles,
            attack_paths=attack_paths,
            blast_radius=blast_radius,  # Phase 3 — None when flag off
            remediation=remediation,
            data_context=final_context,
        )

        logger.debug(
            "identity_state.build done org=%s id=%s risk=%s label=%s",
            self._organization_id,
            identity_id,
            risk_score.score,
            risk_score.label.value,
        )
        return state

    # ------------------------------------------------------------------
    # Dual-run comparison (staging/canary only)
    # ------------------------------------------------------------------

    async def _compare_blast_radius_engines(
        self,
        identity_id: str,
        new_result: Any,
    ) -> None:
        """Dual-run comparison for Phase 3 blast radius migration.

        Lazy-imports the legacy engine so production builds never
        pay the import cost when the flag is off. Never raises:
        all failures are logged at WARNING and swallowed.

        Match rule
        ----------
        * ``new_critical == legacy_critical`` (exact match required)
        * ``abs(new_total - legacy_total) / max(legacy_total, 1) * 100 <= 10.0``

        IMPORTANT
        ---------
        The legacy engine lives at
        ``app.engines.blast_radius_engine.BlastRadiusEngine`` and
        was verified to have constructor ``(organization_id, db)``
        and method ``compute_blast_radius(identity_id)``. If that
        changes, this method must be updated before re-enabling
        :attr:`FeatureFlags.BLAST_RADIUS_DUAL_RUN`.
        """
        try:
            # Lazy import — only paid when the flag is on
            from app.engines.blast_radius_engine import (
                BlastRadiusEngine as LegacyEngine,
            )

            legacy_engine = LegacyEngine(self._organization_id, self._db)
            legacy_result = await legacy_engine.compute_blast_radius(identity_id)

            new_total = int(getattr(new_result, "total_reachable", 0) or 0)
            legacy_total = int(getattr(legacy_result, "total_reachable", 0) or 0)
            new_critical = len(getattr(new_result, "critical_resources", []) or [])
            legacy_critical = len(
                getattr(legacy_result, "critical_resources", []) or []
            )
            new_high = len(getattr(new_result, "high_resources", []) or [])
            legacy_high = len(getattr(legacy_result, "high_resources", []) or [])

            diff_pct = (
                abs(new_total - legacy_total) / max(legacy_total, 1) * 100.0
            )
            match = (new_critical == legacy_critical) and (diff_pct <= 10.0)

            logger.info(
                "blast_radius.dual_run org=%s id=%s "
                "new_total=%d legacy_total=%d "
                "new_critical=%d legacy_critical=%d "
                "new_high=%d legacy_high=%d "
                "match=%s diff_pct=%.2f",
                self._organization_id,
                identity_id,
                new_total,
                legacy_total,
                new_critical,
                legacy_critical,
                new_high,
                legacy_high,
                "true" if match else "false",
                diff_pct,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "blast_radius.dual_run failed org=%s id=%s err=%s",
                self._organization_id,
                identity_id,
                exc,
            )

    # ------------------------------------------------------------------
    # Snapshot metadata (orchestration-level concern)
    # ------------------------------------------------------------------

    async def _load_snapshot_date(
        self,
        snapshot_id: Optional[int],
    ) -> Optional[datetime]:
        """Resolve the snapshot_date for the given ``snapshot_id``.

        Reads ``identity_snapshots`` directly — this is the single
        orchestration-level query the engine makes on its own behalf,
        because it is build-level provenance rather than block data.
        """
        if snapshot_id is None:
            return None
        # ``identity_snapshots.organization_id`` is INTEGER. asyncpg
        # refuses to coerce a str bind param, so cast the engine's
        # str org_id once at the binding site. A malformed org_id
        # surfaces as an IdentityStateBuildError — the engine never
        # silently continues with a wrong-typed scope.
        try:
            org_int = int(self._organization_id)
        except (TypeError, ValueError) as exc:
            raise IdentityStateBuildError(
                "organization_id must be an integer for snapshot lookup",
                context={
                    "organization_id": self._organization_id,
                    "snapshot_id": snapshot_id,
                },
            ) from exc
        result = await self._db.execute(
            text(
                """
                SELECT snapshot_date, organization_id
                FROM identity_snapshots
                WHERE snapshot_id     = :sid
                  AND organization_id = :org
                """
            ),
            {"sid": snapshot_id, "org": org_int},
        )
        row = result.mappings().first()
        if row is None:
            # No ``identity_snapshots`` row means there is no identity
            # state captured under this snapshot_id for this org — the
            # caller asked for a point-in-time view that does not
            # exist. Map to :class:`IdentityNotFoundError` so the
            # route layer responds with 404 (matches the live-mode
            # contract where a missing identity is not a 5xx).
            raise IdentityNotFoundError(
                "no identity state captured for this snapshot",
                context={
                    "organization_id": self._organization_id,
                    "snapshot_id": snapshot_id,
                },
            )
        # DB returns INTEGER, engine holds str — compare as str so the
        # scope tripwire only triggers on a genuine cross-tenant leak.
        self._assert_row_scope(row, identity_id="<snapshot>")
        return row["snapshot_date"]

    def _assert_row_scope(
        self,
        row: Mapping[str, Any],
        *,
        identity_id: str,
    ) -> None:
        """Raise :class:`OrganizationScopeError` if ``row`` crosses the org line.

        Several Phase 3 tables (``identity_snapshots``, ``snapshots``,
        ``identity_list``) store ``organization_id`` as INTEGER while
        the engine's binding is the str JWT claim. Compare as str so
        the tripwire never false-positives on a pure type mismatch —
        it must only fire on a genuine cross-tenant leak.
        """
        row_org = row.get("organization_id") if isinstance(row, Mapping) else None
        if row_org is not None and str(row_org) != str(self._organization_id):
            raise OrganizationScopeError(
                "row organization_id does not match engine binding",
                context={
                    "engine_organization_id": self._organization_id,
                    "row_organization_id": row_org,
                    "identity_id": identity_id,
                },
            )
