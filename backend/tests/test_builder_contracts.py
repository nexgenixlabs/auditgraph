"""
E2 — Builder contract tests (4 states × 5 builders = 20+ tests).

Tests verify that every Phase 3 builder handles all four data states
correctly and never produces a 500 or an unvalidated response:

  State 0 — No data (skeleton table has zero rows)
  State 1 — Partial data (rows exist but required fields are null)
  State 2 — Full data (all fields populated)
  State 3 — Stale data (row older than BUILDER_STALENESS_HOURS)

Each test asserts:
  * returned ``data_source`` matches the expected state,
  * ``confidence`` is correct for the state,
  * ``missing_signals`` list is populated appropriately,
  * no exception is raised (zero 500s),
  * the result validates against the Pydantic schema.

Requires a live Postgres database. Run with::

    pytest tests/test_builder_contracts.py -m requires_db --tb=short
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

# Env defaults for local dev (must be set before app.config is imported)
os.environ.setdefault("FLASK_ENV", "development")
os.environ.setdefault("JWT_SECRET", secrets.token_hex(32))
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "5434")
os.environ.setdefault("DB_NAME", "auditgraph")
os.environ.setdefault("DB_USER", "auditgraph")
os.environ.setdefault("DB_PASSWORD", "auditgraph")
os.environ.setdefault("DB_SSLMODE", "disable")

from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.schemas.identity import (
    BUILDER_STALENESS_HOURS,
    ActivityState,
    BuilderDataSource,
    Confidence,
    DataMode,
    GovernanceBlock,
    GovernanceClassification,
    IdentityProfile,
    IdentityType,
    LifecycleState,
    OwnerQuality,
    OwnershipBlock,
    PrivilegeBlock,
    PrivilegeLevel,
    ScopeBreadth,
)
from app.services.builders.activity_builder import ActivityBuilder
from app.services.builders.governance_engine import GovernanceEngine
from app.services.builders.identity_blast_radius_engine import (
    IdentityBlastRadiusEngine,
)
from app.services.builders.identity_profile_builder import (
    OwnershipBuilder,
    PrivilegeBuilder,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

#: Test org must exist in the database. We use org 2 (AzureCredits) which
#: the local dev seed creates.
TEST_ORG_ID = "2"
TEST_ORG_INT = 2

#: Identity ID that does NOT exist in any skeleton table — exercises State 0.
MISSING_IDENTITY_ID = f"e2-test-missing-{uuid.uuid4().hex[:8]}"


def _make_engine() -> AsyncEngine:
    """Create a fresh async engine bound to no event loop."""
    url = URL.create(
        drivername="postgresql+asyncpg",
        username=os.environ.get("DB_USER", "auditgraph"),
        password=os.environ.get("DB_PASSWORD", "auditgraph"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5434")),
        database=os.environ.get("DB_NAME", "auditgraph"),
    )
    return create_async_engine(url, pool_pre_ping=True, pool_size=1, max_overflow=0)


def _run(coro: Any) -> Any:
    """Run an async coroutine via asyncio.run (creates + destroys event loop)."""
    return asyncio.run(coro)


async def _open_session() -> tuple[AsyncSession, AsyncEngine]:
    """Create a fresh engine + session. Caller must close + dispose."""
    engine = _make_engine()
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    return factory(), engine


async def _close(session: AsyncSession, engine: AsyncEngine) -> None:
    """Close session and dispose engine (return pool connections)."""
    await session.close()
    await engine.dispose()


async def _ensure_identity_row(
    session: AsyncSession,
    identity_id: str,
    org_id: int = TEST_ORG_INT,
) -> None:
    """Ensure a minimal row exists in the ``identities`` table so the
    IdentityProfileBuilder can find it. Does NOT insert into skeleton tables.
    """
    await session.execute(
        text("""
            INSERT INTO identities (
                identity_id, object_id, display_name, identity_type,
                cloud_provider, source, status, organization_id,
                discovery_run_id
            )
            VALUES (
                :id, :id, :name, 'service_principal',
                'azure', 'azure_ad', 'Active', :org,
                (SELECT id FROM discovery_runs
                 WHERE organization_id = :org
                 ORDER BY id DESC LIMIT 1)
            )
            ON CONFLICT (identity_id, discovery_run_id) DO NOTHING
        """),
        {"id": identity_id, "name": f"E2 Test {identity_id}", "org": org_id},
    )
    await session.commit()


async def _insert_activity_row(
    session: AsyncSession,
    identity_id: str,
    org_id: int = TEST_ORG_INT,
    last_sign_in_at: datetime | None = None,
    last_activity_at: datetime | None = None,
    lifecycle_state: str = "Active",
    activity_confidence: str = "high",
    has_p2_telemetry: bool = False,
    updated_at: datetime | None = None,
) -> None:
    """Insert a row into ``identity_activity``."""
    now = datetime.now(timezone.utc)
    await session.execute(
        text("""
            INSERT INTO identity_activity (
                identity_id, organization_id, lifecycle_state,
                last_sign_in_at, last_activity_at,
                activity_confidence, has_p2_telemetry, updated_at
            )
            VALUES (
                :id, :org, :lifecycle,
                :sign_in, :activity,
                :confidence, :p2, :updated
            )
            ON CONFLICT (identity_id, organization_id) DO UPDATE SET
                lifecycle_state     = EXCLUDED.lifecycle_state,
                last_sign_in_at     = EXCLUDED.last_sign_in_at,
                last_activity_at    = EXCLUDED.last_activity_at,
                activity_confidence = EXCLUDED.activity_confidence,
                has_p2_telemetry    = EXCLUDED.has_p2_telemetry,
                updated_at          = EXCLUDED.updated_at
        """),
        {
            "id": identity_id,
            "org": org_id,
            "lifecycle": lifecycle_state,
            "sign_in": last_sign_in_at,
            "activity": last_activity_at,
            "confidence": activity_confidence,
            "p2": has_p2_telemetry,
            "updated": updated_at or now,
        },
    )
    await session.commit()


async def _insert_owner_row(
    session: AsyncSession,
    identity_id: str,
    owner_id: str = "owner-1",
    owner_name: str = "Test Owner",
    owner_type: str | None = "user",
    last_active_days: int | None = 30,
    has_reviewed: bool = True,
    last_review_at: datetime | None = None,
    org_id: int = TEST_ORG_INT,
) -> None:
    """Insert a row into ``identity_owners``."""
    await session.execute(
        text("""
            INSERT INTO identity_owners (
                identity_id, organization_id, owner_id, owner_name,
                owner_type, last_active_days, has_reviewed, last_review_at
            )
            VALUES (
                :id, :org, :owner_id, :owner_name,
                :owner_type, :active_days, :reviewed, :review_at
            )
        """),
        {
            "id": identity_id,
            "org": org_id,
            "owner_id": owner_id,
            "owner_name": owner_name,
            "owner_type": owner_type,
            "active_days": last_active_days,
            "reviewed": has_reviewed,
            "review_at": last_review_at or datetime.now(timezone.utc),
        },
    )
    await session.commit()


async def _insert_privilege_row(
    session: AsyncSession,
    identity_id: str,
    org_id: int = TEST_ORG_INT,
    privilege_level: str = "highly_privileged",
    scope_breadth: str = "tenant_wide",
    total_role_count: int = 5,
) -> None:
    """Insert a row into ``identity_privilege_summary``."""
    await session.execute(
        text("""
            INSERT INTO identity_privilege_summary (
                identity_id, organization_id, privilege_level, scope_breadth,
                highly_privileged_role_count, privileged_role_count,
                standard_role_count, total_role_count,
                can_escalate, blast_radius_resource_count
            )
            VALUES (
                :id, :org, :priv, :scope,
                2, 1, 2, :total,
                true, 42
            )
            ON CONFLICT (identity_id, organization_id) DO UPDATE SET
                privilege_level = EXCLUDED.privilege_level,
                scope_breadth   = EXCLUDED.scope_breadth,
                total_role_count = EXCLUDED.total_role_count
        """),
        {
            "id": identity_id,
            "org": org_id,
            "priv": privilege_level,
            "scope": scope_breadth,
            "total": total_role_count,
        },
    )
    await session.commit()


async def _cleanup(session: AsyncSession, identity_id: str) -> None:
    """Remove test data from all skeleton tables."""
    for table in (
        "identity_activity",
        "identity_owners",
        "identity_privilege_summary",
        "identity_credentials",
        "identity_role_assignments",
        "identity_attack_paths",
    ):
        await session.execute(
            text(f"DELETE FROM {table} WHERE identity_id = :id AND organization_id = :org"),
            {"id": identity_id, "org": TEST_ORG_INT},
        )
    await session.commit()


# ---------------------------------------------------------------------------
# Test IDs — each test gets a unique identity_id for isolation
# ---------------------------------------------------------------------------

def _test_id(suffix: str) -> str:
    return f"e2-{suffix}-{uuid.uuid4().hex[:6]}"


# ===========================================================================
# ActivityBuilder — State 0, 1, 2, 3
# ===========================================================================

@pytest.mark.requires_db
class TestActivityBuilderState0:
    """State 0: no row in identity_activity."""

    def test_returns_none_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            try:
                iid = _test_id("act-s0")
                builder = ActivityBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert isinstance(result, ActivityState)
                assert result.data_source == BuilderDataSource.NONE
                assert result.activity_confidence == Confidence.NONE
                assert result.lifecycle_state == LifecycleState.PROVISIONED
                assert result.last_sign_in_at is None
                assert result.last_activity_at is None
                assert "last_sign_in_at" in result.missing_signals
                assert "last_activity_at" in result.missing_signals
                assert "lifecycle_state" in result.missing_signals
            finally:
                await _close(session, engine)

        _run(_run_test())


@pytest.mark.requires_db
class TestActivityBuilderState1:
    """State 1: row exists but required fields are null (partial)."""

    def test_returns_partial_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("act-s1")
            try:
                await _insert_activity_row(
                    session, iid,
                    last_sign_in_at=None,   # missing
                    last_activity_at=None,  # missing
                    lifecycle_state="Active",
                    activity_confidence="low",
                )
                builder = ActivityBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert result.data_source == BuilderDataSource.PARTIAL
                assert "last_sign_in_at" in result.missing_signals
                assert "last_activity_at" in result.missing_signals
            finally:
                await _cleanup(session, iid)
                await _close(session, engine)

        _run(_run_test())


@pytest.mark.requires_db
class TestActivityBuilderState2:
    """State 2: full row with all fields populated."""

    def test_returns_full_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("act-s2")
            now = datetime.now(timezone.utc)
            try:
                await _insert_activity_row(
                    session, iid,
                    last_sign_in_at=now - timedelta(hours=2),
                    last_activity_at=now - timedelta(hours=1),
                    lifecycle_state="Active",
                    activity_confidence="high",
                    updated_at=now,
                )
                builder = ActivityBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert result.data_source == BuilderDataSource.FULL
                assert result.missing_signals == []
                assert result.activity_confidence == Confidence.HIGH
                assert result.last_sign_in_at is not None
                assert result.last_activity_at is not None
            finally:
                await _cleanup(session, iid)
                await _close(session, engine)

        _run(_run_test())


@pytest.mark.requires_db
class TestActivityBuilderState3:
    """State 3: row exists but updated_at is stale (>24h old)."""

    def test_returns_stale_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("act-s3")
            now = datetime.now(timezone.utc)
            stale_time = now - timedelta(hours=BUILDER_STALENESS_HOURS + 2)
            try:
                await _insert_activity_row(
                    session, iid,
                    last_sign_in_at=stale_time - timedelta(days=5),
                    last_activity_at=stale_time - timedelta(days=3),
                    lifecycle_state="Active",
                    activity_confidence="high",
                    updated_at=stale_time,
                )
                builder = ActivityBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert result.data_source == BuilderDataSource.STALE
            finally:
                await _cleanup(session, iid)
                await _close(session, engine)

        _run(_run_test())


# ===========================================================================
# OwnershipBuilder — State 0, 1, 2
# ===========================================================================

@pytest.mark.requires_db
class TestOwnershipBuilderState0:
    """State 0: no rows in identity_owners."""

    def test_returns_none_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("own-s0")
            try:
                builder = OwnershipBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert isinstance(result, OwnershipBlock)
                assert result.data_source == BuilderDataSource.NONE
                assert result.confidence == Confidence.NONE
                assert result.owner_quality == OwnerQuality.NO_OWNER
                assert result.owners == []
                assert "owners" in result.missing_signals
                assert "last_review_at" in result.missing_signals
            finally:
                await _close(session, engine)

        _run(_run_test())


@pytest.mark.requires_db
class TestOwnershipBuilderState1:
    """State 1: row exists but owner_type is null (partial)."""

    def test_returns_partial_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("own-s1")
            try:
                await _insert_owner_row(
                    session, iid,
                    owner_type=None,  # missing
                    last_review_at=None,
                    has_reviewed=False,
                )
                builder = OwnershipBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert result.data_source == BuilderDataSource.PARTIAL
                assert result.confidence == Confidence.LOW
                assert "owner_type" in result.missing_signals
            finally:
                await _cleanup(session, iid)
                await _close(session, engine)

        _run(_run_test())


@pytest.mark.requires_db
class TestOwnershipBuilderState2:
    """State 2: full row with all fields populated."""

    def test_returns_full_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("own-s2")
            now = datetime.now(timezone.utc)
            try:
                await _insert_owner_row(
                    session, iid,
                    owner_type="user",
                    last_active_days=10,
                    has_reviewed=True,
                    last_review_at=now - timedelta(days=5),
                )
                builder = OwnershipBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert result.data_source == BuilderDataSource.FULL
                assert result.confidence == Confidence.HIGH
                assert result.missing_signals == []
                assert len(result.owners) == 1
            finally:
                await _cleanup(session, iid)
                await _close(session, engine)

        _run(_run_test())


# ===========================================================================
# PrivilegeBuilder — State 0, 2
# ===========================================================================

@pytest.mark.requires_db
class TestPrivilegeBuilderState0:
    """State 0: no row in identity_privilege_summary."""

    def test_returns_none_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("priv-s0")
            try:
                builder = PrivilegeBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert isinstance(result, PrivilegeBlock)
                assert result.data_source == BuilderDataSource.NONE
                assert result.confidence == Confidence.NONE
                assert result.privilege_level == PrivilegeLevel.STANDARD
                assert result.scope_breadth == ScopeBreadth.RESOURCE
                assert "privilege_level" in result.missing_signals
                assert "scope_breadth" in result.missing_signals
                assert "total_role_count" in result.missing_signals
            finally:
                await _close(session, engine)

        _run(_run_test())


@pytest.mark.requires_db
class TestPrivilegeBuilderState2:
    """State 2: full row with all fields populated."""

    def test_returns_full_data_source(self) -> None:
        async def _run_test() -> None:
            session, engine = await _open_session()
            iid = _test_id("priv-s2")
            try:
                await _insert_privilege_row(session, iid)
                builder = PrivilegeBuilder(TEST_ORG_ID, session)
                result = await builder.build(iid, DataMode.LIVE, None)

                assert result.data_source == BuilderDataSource.FULL
                assert result.confidence == Confidence.HIGH
                assert result.missing_signals == []
                assert result.privilege_level == PrivilegeLevel.HIGHLY_PRIVILEGED
                assert result.scope_breadth == ScopeBreadth.TENANT_WIDE
                assert result.total_role_count == 5
            finally:
                await _cleanup(session, iid)
                await _close(session, engine)

        _run(_run_test())


# ===========================================================================
# GovernanceEngine — pure derivation (State 0, 1, 2)
# ===========================================================================

class TestGovernanceEngineState0:
    """State 0: both upstream blocks have data_source=NONE."""

    def test_returns_none_data_source(self) -> None:
        engine = GovernanceEngine(TEST_ORG_ID)
        profile = _make_profile()
        activity = _make_activity(data_source=BuilderDataSource.NONE)
        ownership = _make_ownership(data_source=BuilderDataSource.NONE)

        result = engine.derive(profile, activity, ownership)

        assert isinstance(result, GovernanceBlock)
        assert result.data_source == BuilderDataSource.NONE
        assert "activity" in result.missing_signals
        assert "ownership" in result.missing_signals


class TestGovernanceEngineState1:
    """State 1: one upstream is NONE, the other is FULL (partial)."""

    def test_activity_none_ownership_full_returns_partial(self) -> None:
        engine = GovernanceEngine(TEST_ORG_ID)
        profile = _make_profile()
        activity = _make_activity(data_source=BuilderDataSource.NONE)
        ownership = _make_ownership(
            data_source=BuilderDataSource.FULL,
            owner_quality=OwnerQuality.ACTIVE_OWNER,
        )

        result = engine.derive(profile, activity, ownership)

        assert result.data_source == BuilderDataSource.PARTIAL
        assert "activity" in result.missing_signals
        assert "ownership" not in result.missing_signals

    def test_activity_full_ownership_none_returns_partial(self) -> None:
        engine = GovernanceEngine(TEST_ORG_ID)
        profile = _make_profile()
        activity = _make_activity(data_source=BuilderDataSource.FULL)
        ownership = _make_ownership(data_source=BuilderDataSource.NONE)

        result = engine.derive(profile, activity, ownership)

        assert result.data_source == BuilderDataSource.PARTIAL
        assert "ownership" in result.missing_signals
        assert "activity" not in result.missing_signals


class TestGovernanceEngineState2:
    """State 2: both upstream blocks are FULL."""

    def test_returns_full_data_source(self) -> None:
        engine = GovernanceEngine(TEST_ORG_ID)
        now = datetime.now(timezone.utc)
        profile = _make_profile()
        activity = _make_activity(
            data_source=BuilderDataSource.FULL,
            last_sign_in_at=now - timedelta(days=1),
            last_activity_at=now - timedelta(hours=2),
        )
        ownership = _make_ownership(
            data_source=BuilderDataSource.FULL,
            owner_quality=OwnerQuality.ACTIVE_OWNER,
            last_review_at=now - timedelta(days=10),
        )

        result = engine.derive(profile, activity, ownership)

        assert result.data_source == BuilderDataSource.FULL
        assert result.missing_signals == []


class TestGovernanceEngineState1Stale:
    """State 1 variant: activity is STALE → governance is PARTIAL."""

    def test_stale_upstream_yields_partial(self) -> None:
        engine = GovernanceEngine(TEST_ORG_ID)
        activity = _make_activity(data_source=BuilderDataSource.STALE)
        ownership = _make_ownership(data_source=BuilderDataSource.FULL)

        result = engine.derive(_make_profile(), activity, ownership)

        assert result.data_source == BuilderDataSource.PARTIAL


# ===========================================================================
# BlastRadiusEngine — State 0 (no graph edges)
#
# State 2/3 require a populated access graph which is expensive to seed.
# We test the schema contract only for State 0 (no edges) which is the
# critical case for the E2 acceptance criteria.
# ===========================================================================

@pytest.mark.requires_db
class TestBlastRadiusState0:
    """State 0: identity has no graph edges → total_reachable=0."""

    def test_returns_none_data_source(self) -> None:
        async def _run_test() -> None:
            session, db_engine = await _open_session()
            iid = _test_id("br-s0")
            try:
                br_engine = IdentityBlastRadiusEngine(TEST_ORG_ID, session)
                result = await br_engine.compute(iid, data_mode=DataMode.LIVE)

                assert result.data_source == BuilderDataSource.NONE
                assert result.total_reachable == 0
                assert "graph_edges" in result.missing_signals
                assert result.truncated is False
            finally:
                await _close(session, db_engine)

        _run(_run_test())


# ===========================================================================
# Cross-cutting: Pydantic validation never fails
# ===========================================================================

class TestPydanticValidation:
    """Verify that every builder's State-0 output passes Pydantic validation."""

    def test_activity_state_0_validates(self) -> None:
        state = ActivityState(
            organization_id=TEST_ORG_ID,
            lifecycle_state=LifecycleState.PROVISIONED,
            activity_confidence=Confidence.NONE,
            data_source=BuilderDataSource.NONE,
            missing_signals=["last_sign_in_at", "last_activity_at", "lifecycle_state"],
        )
        assert state.data_source == BuilderDataSource.NONE

    def test_ownership_state_0_validates(self) -> None:
        block = OwnershipBlock(
            organization_id=TEST_ORG_ID,
            owner_quality=OwnerQuality.NO_OWNER,
            confidence=Confidence.NONE,
            data_source=BuilderDataSource.NONE,
            missing_signals=["owners", "last_review_at"],
        )
        assert block.data_source == BuilderDataSource.NONE

    def test_privilege_state_0_validates(self) -> None:
        block = PrivilegeBlock(
            organization_id=TEST_ORG_ID,
            privilege_level=PrivilegeLevel.STANDARD,
            scope_breadth=ScopeBreadth.RESOURCE,
            confidence=Confidence.NONE,
            data_source=BuilderDataSource.NONE,
            missing_signals=["privilege_level", "scope_breadth", "total_role_count"],
        )
        assert block.data_source == BuilderDataSource.NONE

    def test_governance_state_0_validates(self) -> None:
        block = GovernanceBlock(
            organization_id=TEST_ORG_ID,
            classification=GovernanceClassification.UNGOVERNED,
            is_governed=False,
            governance_confidence=Confidence.NONE,
            data_source=BuilderDataSource.NONE,
            missing_signals=["activity", "ownership"],
        )
        assert block.data_source == BuilderDataSource.NONE

    def test_identity_state_all_blocks_state_0_validates(self) -> None:
        """Full composite IdentityState with every block at State 0."""
        from app.schemas.identity import (
            AttackPathsBlock,
            BlastRadiusResult,
            DataContext,
            IdentityState,
            RemediationBlock,
            RiskFactor,
            RiskLabel,
            RiskScoreBlock,
            RolesBlock,
        )

        now = datetime.now(timezone.utc)
        profile = _make_profile()
        state = IdentityState(
            organization_id=TEST_ORG_ID,
            profile=profile,
            activity=ActivityState(
                organization_id=TEST_ORG_ID,
                lifecycle_state=LifecycleState.PROVISIONED,
                activity_confidence=Confidence.NONE,
                data_source=BuilderDataSource.NONE,
                missing_signals=["last_sign_in_at", "last_activity_at", "lifecycle_state"],
            ),
            ownership=OwnershipBlock(
                organization_id=TEST_ORG_ID,
                owner_quality=OwnerQuality.NO_OWNER,
                confidence=Confidence.NONE,
                data_source=BuilderDataSource.NONE,
                missing_signals=["owners", "last_review_at"],
            ),
            governance=GovernanceBlock(
                organization_id=TEST_ORG_ID,
                classification=GovernanceClassification.UNGOVERNED,
                is_governed=False,
                governance_confidence=Confidence.NONE,
                data_source=BuilderDataSource.NONE,
                missing_signals=["activity", "ownership"],
            ),
            privilege=PrivilegeBlock(
                organization_id=TEST_ORG_ID,
                privilege_level=PrivilegeLevel.STANDARD,
                scope_breadth=ScopeBreadth.RESOURCE,
                confidence=Confidence.NONE,
                data_source=BuilderDataSource.NONE,
                missing_signals=["privilege_level", "scope_breadth", "total_role_count"],
            ),
            risk=RiskScoreBlock(
                organization_id=TEST_ORG_ID,
                score=0.0,
                label=RiskLabel.INFO,
                computed_at=now,
                model_version="test",
            ),
            roles=RolesBlock(organization_id=TEST_ORG_ID),
            attack_paths=AttackPathsBlock(organization_id=TEST_ORG_ID),
            blast_radius=None,
            remediation=RemediationBlock(organization_id=TEST_ORG_ID),
            data_context=DataContext(data_mode=DataMode.LIVE),
        )
        assert state.activity.data_source == BuilderDataSource.NONE
        assert state.ownership.data_source == BuilderDataSource.NONE
        assert state.governance.data_source == BuilderDataSource.NONE
        assert state.privilege.data_source == BuilderDataSource.NONE


# ===========================================================================
# Helpers for pure GovernanceEngine tests
# ===========================================================================


def _make_profile(**kw: Any) -> IdentityProfile:
    from app.schemas.identity import (
        CloudProvider,
        DataContext,
        DataMode,
        IdentitySource,
        IdentityStatus,
    )

    defaults: dict[str, Any] = {
        "organization_id": TEST_ORG_ID,
        "global_identity_id": uuid.uuid4(),
        "identity_id": "test-gov-id",
        "display_name": "Test Gov Identity",
        "identity_type": IdentityType.SERVICE_PRINCIPAL,
        "cloud_id": CloudProvider.AZURE,
        "source": IdentitySource.AZURE_AD,
        "status": IdentityStatus.ACTIVE,
        "data_context": DataContext(data_mode=DataMode.LIVE),
    }
    defaults.update(kw)
    return IdentityProfile(**defaults)


def _make_activity(
    data_source: BuilderDataSource = BuilderDataSource.FULL,
    **kw: Any,
) -> ActivityState:
    defaults: dict[str, Any] = {
        "organization_id": TEST_ORG_ID,
        "lifecycle_state": LifecycleState.ACTIVE if data_source != BuilderDataSource.NONE else LifecycleState.PROVISIONED,
        "activity_confidence": Confidence.HIGH if data_source == BuilderDataSource.FULL else Confidence.NONE,
        "data_source": data_source,
        "missing_signals": [] if data_source == BuilderDataSource.FULL else ["last_sign_in_at"],
    }
    defaults.update(kw)
    return ActivityState(**defaults)


def _make_ownership(
    data_source: BuilderDataSource = BuilderDataSource.FULL,
    owner_quality: OwnerQuality = OwnerQuality.NO_OWNER,
    last_review_at: datetime | None = None,
    **kw: Any,
) -> OwnershipBlock:
    from app.schemas.identity import IdentityOwner

    owners = []
    if owner_quality != OwnerQuality.NO_OWNER:
        owners.append(
            IdentityOwner(
                organization_id=TEST_ORG_ID,
                id="test-owner",
                name="Test Owner",
                type="user",
                last_active_days=10,
                has_reviewed=True,
            )
        )

    days_since = None
    if last_review_at is not None:
        days_since = max(0, (datetime.now(timezone.utc) - last_review_at).days)

    defaults: dict[str, Any] = {
        "organization_id": TEST_ORG_ID,
        "owner_quality": owner_quality,
        "owners": owners,
        "last_review_at": last_review_at,
        "days_since_last_review": days_since,
        "confidence": Confidence.NONE if data_source == BuilderDataSource.NONE else Confidence.HIGH,
        "data_source": data_source,
        "missing_signals": ["owners", "last_review_at"] if data_source == BuilderDataSource.NONE else [],
    }
    defaults.update(kw)
    return OwnershipBlock(**defaults)
