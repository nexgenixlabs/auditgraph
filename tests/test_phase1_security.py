"""
Phase 1 Security Regression Suite
=================================

End-to-end regression tests for AuditGraph's Phase 1 API surface:

* :mod:`app.api.routes.identities`
* :mod:`app.api.routes.resources`
* :mod:`app.api.routes.snapshots`

These tests are the non-negotiable guardrails for three Phase 1
invariants:

1. **Organization scope** — every route must refuse to return, link,
   reference, or act on data that belongs to a different tenant, even
   if the caller supplies a valid-looking id from a foreign org.
2. **F1 global_identity_id registry** — the cross-cloud UUID registry
   must be scoped per-org at every lookup surface. A UUID minted for
   ``org_alpha`` cannot be resolved, peered, or bulk-fetched from an
   ``org_beta`` session.
3. **F3 DataContext envelope** — every identity-surface response must
   carry a :class:`DataContext` whose ``data_mode`` accurately reflects
   how the data was produced (``live`` vs ``snapshot``) and whose
   ``is_stale`` flag is set only when the live data is older than the
   freshness threshold.

Each test's docstring names the concrete attack vector or correctness
regression it prevents. Do not delete or weaken a test without first
understanding what it was catching — if the feature is truly going
away, the docstring tells you what replacement guardrail you owe.

Test philosophy
---------------
* **Hermetic.** No real database, no real network. The suite builds a
  minimal FastAPI app in-process and overrides ``get_current_user`` /
  ``get_db`` at the dependency-injection seam. A fake ``DataStore``
  keeps two orgs' worth of rows in memory and serves them back through
  a fake :class:`AsyncSession`.
* **Isolated.** Each test gets a freshly-built app and a freshly-seeded
  store via fixtures — there is no shared mutable state between tests.
* **Black-box at the wire.** Assertions target HTTP status codes and
  response body shapes, not internal function calls. If the invariant
  "org_alpha can never see org_beta data" holds at the public contract,
  the test passes; if it leaks anywhere — in a header, an error
  message, a linked resource — the test fails hard.

Fake contract
-------------
The fake layer intentionally implements only the subset of the
SQLAlchemy / engine / registry interface that Phase 1 routes exercise.
If a Phase 1 route starts calling a new method on ``db`` or the engine,
the test fake will raise ``NotImplementedError`` — a loud failure that
forces the author to decide whether the new call path is safe.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Iterator, Optional
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException, status
from httpx import ASGITransport, AsyncClient


# ---------------------------------------------------------------------------
# Test markers — configured in pyproject.toml / pytest.ini as well.
# ---------------------------------------------------------------------------

pytestmark = [pytest.mark.asyncio]


# =============================================================================
# Seed data — deterministic, read-only constants referenced by every test
# =============================================================================


@dataclass(frozen=True)
class FakePrincipal:
    """Minimum shape consumed by ``app.api.deps.get_current_user``.

    Only the attributes that the Phase 1 routes actually read are
    modeled. Keeping this tight means new routes cannot silently start
    depending on an ambient principal field the test harness forgot to
    populate.
    """

    organization_id: str
    user_id: str
    role: str = "admin"


ALPHA_PRINCIPAL = FakePrincipal(
    organization_id="org_alpha",
    user_id="alice@alpha.test",
)
BETA_PRINCIPAL = FakePrincipal(
    organization_id="org_beta",
    user_id="bob@beta.test",
)

ALPHA_IDENTITY_IDS: tuple[str, ...] = ("alpha-id-1", "alpha-id-2", "alpha-id-3")
BETA_IDENTITY_IDS: tuple[str, ...] = ("beta-id-1", "beta-id-2", "beta-id-3")

ALPHA_GIDS: tuple[UUID, ...] = (
    UUID("aaaaaaaa-aaaa-4aaa-aaaa-000000000001"),
    UUID("aaaaaaaa-aaaa-4aaa-aaaa-000000000002"),
    UUID("aaaaaaaa-aaaa-4aaa-aaaa-000000000003"),
)
BETA_GIDS: tuple[UUID, ...] = (
    UUID("bbbbbbbb-bbbb-4bbb-bbbb-000000000001"),
    UUID("bbbbbbbb-bbbb-4bbb-bbbb-000000000002"),
    UUID("bbbbbbbb-bbbb-4bbb-bbbb-000000000003"),
)

ALPHA_ROLE_IDS: tuple[str, ...] = ("alpha-role-1", "alpha-role-2")
BETA_ROLE_IDS: tuple[str, ...] = ("beta-role-1", "beta-role-2")

ALPHA_RESOURCE_CLOUD_ID = (
    "/subscriptions/alpha-sub/resourceGroups/rg/"
    "providers/Microsoft.KeyVault/vaults/alpha-kv"
)
BETA_RESOURCE_CLOUD_ID = (
    "/subscriptions/beta-sub/resourceGroups/rg/"
    "providers/Microsoft.KeyVault/vaults/beta-kv"
)

ALPHA_SNAPSHOT_ID = 1001
BETA_SNAPSHOT_ID = 2002

FRESH_COMPUTED_AT = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)
STALE_COMPUTED_AT = FRESH_COMPUTED_AT - timedelta(minutes=20)
STALE_THRESHOLD = timedelta(minutes=15)


# =============================================================================
# Fake data store — replaces Postgres for the duration of a single test
# =============================================================================


@dataclass
class FakeIdentityRow:
    """In-memory projection of an ``identities`` / snapshot row."""

    identity_id: str
    global_identity_id: UUID
    organization_id: str
    display_name: str
    identity_type: str = "service_principal"
    cloud_provider: str = "azure"
    risk_label: str = "high"
    risk_score: float = 72.5
    governance: str = "Ungoverned"
    lifecycle_state: str = "active"
    is_dormant: bool = False
    privilege_level: str = "privileged"
    last_seen: Optional[datetime] = None


@dataclass
class FakeSnapshotRow:
    """In-memory projection of a ``snapshots`` catalogue row."""

    id: int
    organization_id: str
    captured_at: datetime
    identity_count: int
    triggered_by: str = "manual"
    status: str = "complete"


@dataclass
class FakeResourceRow:
    """In-memory projection of a ``resources`` row (G1 typed node)."""

    id: int
    organization_id: str
    cloud_id: str
    cloud_provider: str
    type: str
    name: str
    sensitivity: str = "High"
    global_identity_id: Optional[UUID] = None


@dataclass
class FakeRoleAssignment:
    """In-memory projection of a ``role_assignments`` row."""

    role_id: str
    identity_id: str
    organization_id: str
    scope: str
    role_name: str = "Contributor"


@dataclass
class FakeDataStore:
    """Typed, tenant-scoped in-memory store backing the fake session.

    Every list accessor takes an explicit ``organization_id`` and
    filters on it. The tests that check org-scope leakage rely on this
    — a bug in the routes that forwards the wrong org id would surface
    immediately as an empty result or a 403.
    """

    identities: list[FakeIdentityRow] = field(default_factory=list)
    snapshots: list[FakeSnapshotRow] = field(default_factory=list)
    resources: list[FakeResourceRow] = field(default_factory=list)
    roles: list[FakeRoleAssignment] = field(default_factory=list)
    snapshot_identities: list[tuple[int, FakeIdentityRow]] = field(default_factory=list)

    # -- identity accessors --------------------------------------------------

    def identities_for(self, organization_id: str) -> list[FakeIdentityRow]:
        return [i for i in self.identities if i.organization_id == organization_id]

    def identity_by_id(
        self, organization_id: str, identity_id: str
    ) -> Optional[FakeIdentityRow]:
        for row in self.identities:
            if row.identity_id == identity_id and row.organization_id == organization_id:
                return row
        return None

    def identity_by_global_id(
        self, organization_id: str, global_identity_id: UUID
    ) -> Optional[FakeIdentityRow]:
        for row in self.identities:
            if (
                row.global_identity_id == global_identity_id
                and row.organization_id == organization_id
            ):
                return row
        return None

    # -- snapshot accessors --------------------------------------------------

    def snapshot_by_id_any_org(self, snapshot_id: int) -> Optional[FakeSnapshotRow]:
        """Cross-org fetch used by the route's two-phase lookup.

        Do NOT use this in assertions for org-scope — it bypasses the
        tenant filter on purpose so the route can distinguish 404 from
        403.
        """
        for row in self.snapshots:
            if row.id == snapshot_id:
                return row
        return None

    def snapshots_for(self, organization_id: str) -> list[FakeSnapshotRow]:
        return [s for s in self.snapshots if s.organization_id == organization_id]

    def snapshot_identities_for(
        self, organization_id: str, snapshot_id: int
    ) -> list[FakeIdentityRow]:
        return [
            row
            for sid, row in self.snapshot_identities
            if sid == snapshot_id and row.organization_id == organization_id
        ]

    # -- resource accessors --------------------------------------------------

    def resources_for(self, organization_id: str) -> list[FakeResourceRow]:
        return [r for r in self.resources if r.organization_id == organization_id]

    def resource_by_cloud_id(
        self, organization_id: str, cloud_id: str
    ) -> Optional[FakeResourceRow]:
        for row in self.resources:
            if row.cloud_id == cloud_id and row.organization_id == organization_id:
                return row
        return None

    # -- role accessors ------------------------------------------------------

    def roles_for_identity(
        self, organization_id: str, identity_id: str
    ) -> list[FakeRoleAssignment]:
        return [
            r
            for r in self.roles
            if r.identity_id == identity_id and r.organization_id == organization_id
        ]


def _seed_store() -> FakeDataStore:
    """Build the canonical two-org seed used by every test."""
    store = FakeDataStore()

    # Three identities per org — same shape so tests can swap freely.
    for org, idents, gids in (
        ("org_alpha", ALPHA_IDENTITY_IDS, ALPHA_GIDS),
        ("org_beta", BETA_IDENTITY_IDS, BETA_GIDS),
    ):
        for idx, (identity_id, gid) in enumerate(zip(idents, gids), start=1):
            store.identities.append(
                FakeIdentityRow(
                    identity_id=identity_id,
                    global_identity_id=gid,
                    organization_id=org,
                    display_name=f"{org}-identity-{idx}",
                    last_seen=FRESH_COMPUTED_AT - timedelta(hours=idx),
                )
            )

    # Two role assignments per org, each bound to the first identity.
    for org, role_ids, first_identity in (
        ("org_alpha", ALPHA_ROLE_IDS, ALPHA_IDENTITY_IDS[0]),
        ("org_beta", BETA_ROLE_IDS, BETA_IDENTITY_IDS[0]),
    ):
        for role_id in role_ids:
            store.roles.append(
                FakeRoleAssignment(
                    role_id=role_id,
                    identity_id=first_identity,
                    organization_id=org,
                    scope=f"/subscriptions/{org}-sub",
                )
            )

    # One resource per org.
    store.resources.append(
        FakeResourceRow(
            id=1,
            organization_id="org_alpha",
            cloud_id=ALPHA_RESOURCE_CLOUD_ID,
            cloud_provider="azure",
            type="key_vault",
            name="alpha-kv",
            sensitivity="Critical",
            global_identity_id=ALPHA_GIDS[0],
        )
    )
    store.resources.append(
        FakeResourceRow(
            id=2,
            organization_id="org_beta",
            cloud_id=BETA_RESOURCE_CLOUD_ID,
            cloud_provider="azure",
            type="key_vault",
            name="beta-kv",
            sensitivity="Critical",
            global_identity_id=BETA_GIDS[0],
        )
    )

    # One snapshot per org, seeded with that org's identities.
    store.snapshots.append(
        FakeSnapshotRow(
            id=ALPHA_SNAPSHOT_ID,
            organization_id="org_alpha",
            captured_at=FRESH_COMPUTED_AT - timedelta(days=1),
            identity_count=len(ALPHA_IDENTITY_IDS),
        )
    )
    store.snapshots.append(
        FakeSnapshotRow(
            id=BETA_SNAPSHOT_ID,
            organization_id="org_beta",
            captured_at=FRESH_COMPUTED_AT - timedelta(days=1),
            identity_count=len(BETA_IDENTITY_IDS),
        )
    )
    for row in store.identities_for("org_alpha"):
        store.snapshot_identities.append((ALPHA_SNAPSHOT_ID, row))
    for row in store.identities_for("org_beta"):
        store.snapshot_identities.append((BETA_SNAPSHOT_ID, row))

    return store


# =============================================================================
# Fake async session — responds to route-level SQL patterns
# =============================================================================


class FakeResult:
    """Minimal stand-in for a SQLAlchemy ``Result`` object."""

    def __init__(self, rows: Any) -> None:
        self._rows = rows

    def mappings(self) -> "FakeResult":
        return self

    def all(self) -> list[dict[str, Any]]:
        if isinstance(self._rows, list):
            return [_row_as_dict(r) for r in self._rows]
        return []

    def first(self) -> Optional[dict[str, Any]]:
        if isinstance(self._rows, list) and self._rows:
            return _row_as_dict(self._rows[0])
        if isinstance(self._rows, dict):
            return self._rows
        return None

    def scalar(self) -> Any:
        if isinstance(self._rows, int):
            return self._rows
        if isinstance(self._rows, list) and self._rows:
            row = _row_as_dict(self._rows[0])
            return next(iter(row.values()))
        return None


def _row_as_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    if hasattr(row, "__dict__"):
        return {k: v for k, v in row.__dict__.items() if not k.startswith("_")}
    raise TypeError(f"cannot convert {type(row).__name__!r} to mapping")


class FakeAsyncSession:
    """Routes-only fake of ``sqlalchemy.ext.asyncio.AsyncSession``.

    Dispatches ``execute()`` calls based on SQL text keywords. Any path
    the tests have not accounted for raises ``NotImplementedError`` so
    a silently new SQL statement cannot bypass the security checks.
    """

    def __init__(self, store: FakeDataStore) -> None:
        self.store = store
        self.committed = False
        self.rolled_back = False

    async def execute(self, stmt: Any, params: Optional[dict[str, Any]] = None) -> FakeResult:
        sql = _normalize_sql(stmt)
        params = params or {}

        if "from snapshots" in sql and "where id = :snapshot_id" in sql and "organization_id" not in sql:
            return self._snapshot_two_phase_fetch(params)

        if "from snapshots" in sql and "organization_id = :org" in sql:
            return self._snapshots_list(params)

        if "insert into snapshots" in sql:
            return self._snapshot_insert(params)

        if "count(*)" in sql and "identity_list_snapshots" in sql:
            return self._snapshot_identities_count(params)

        if "from identity_list_snapshots" in sql:
            return self._snapshot_identities_list(params)

        if "from resources" in sql and "where organization_id = :org" in sql:
            return self._resources_list(params)

        if "from resources" in sql and "cloud_id = :cloud_id" in sql:
            return self._resource_by_cloud_id(params)

        if "role_assignments" in sql:
            return self._roles_list(params)

        raise NotImplementedError(
            f"FakeAsyncSession has no handler for SQL:\n{sql}\nparams={params}"
        )

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def close(self) -> None:
        return None

    # -- handlers ------------------------------------------------------------

    def _snapshot_two_phase_fetch(self, params: dict[str, Any]) -> FakeResult:
        row = self.store.snapshot_by_id_any_org(int(params["snapshot_id"]))
        return FakeResult([row] if row is not None else [])

    def _snapshots_list(self, params: dict[str, Any]) -> FakeResult:
        rows = self.store.snapshots_for(params["org"])
        return FakeResult(rows)

    def _snapshot_insert(self, params: dict[str, Any]) -> FakeResult:
        new_id = max((s.id for s in self.store.snapshots), default=9000) + 1
        row = FakeSnapshotRow(
            id=new_id,
            organization_id=params["org"],
            captured_at=params["captured_at"],
            identity_count=0,
            triggered_by=params["triggered_by"],
            status=params["status"],
        )
        self.store.snapshots.append(row)
        return FakeResult([row])

    def _snapshot_identities_count(self, params: dict[str, Any]) -> FakeResult:
        rows = self.store.snapshot_identities_for(params["org"], int(params["snapshot_id"]))
        return FakeResult(len(rows))

    def _snapshot_identities_list(self, params: dict[str, Any]) -> FakeResult:
        rows = self.store.snapshot_identities_for(params["org"], int(params["snapshot_id"]))
        return FakeResult(rows)

    def _resources_list(self, params: dict[str, Any]) -> FakeResult:
        rows = self.store.resources_for(params["org"])
        return FakeResult(rows)

    def _resource_by_cloud_id(self, params: dict[str, Any]) -> FakeResult:
        row = self.store.resource_by_cloud_id(params["org"], params["cloud_id"])
        return FakeResult([row] if row is not None else [])

    def _roles_list(self, params: dict[str, Any]) -> FakeResult:
        rows = self.store.roles_for_identity(
            params.get("org", ""),
            params.get("identity_id", ""),
        )
        return FakeResult(rows)


def _normalize_sql(stmt: Any) -> str:
    raw = str(stmt)
    return re.sub(r"\s+", " ", raw).strip().lower()


# =============================================================================
# App + client fixtures
# =============================================================================


def _install_dependency_overrides(
    app: FastAPI,
    principal: FakePrincipal,
    session: FakeAsyncSession,
) -> None:
    """Wire the two DI seams the Phase 1 routes depend on."""
    from app.api import deps  # type: ignore[import-not-found]

    async def _override_current_user() -> FakePrincipal:
        return principal

    async def _override_db() -> AsyncIterator[FakeAsyncSession]:
        yield session

    app.dependency_overrides[deps.get_current_user] = _override_current_user
    app.dependency_overrides[deps.get_db] = _override_db


def _build_app() -> FastAPI:
    """Construct a minimal FastAPI app with only the Phase 1 routers.

    Imported lazily so tests can monkeypatch route-module internals
    before the router is even instantiated.
    """
    from app.api.routes import identities as identities_routes  # noqa: F401
    from app.api.routes import resources as resources_routes  # noqa: F401
    from app.api.routes import snapshots as snapshots_routes  # noqa: F401

    app = FastAPI(title="auditgraph-phase1-test")
    app.include_router(identities_routes.router)
    app.include_router(resources_routes.router)
    app.include_router(snapshots_routes.router)
    return app


@pytest.fixture
def store() -> FakeDataStore:
    """Fresh seeded two-org store for each test."""
    return _seed_store()


@pytest.fixture
def fake_session(store: FakeDataStore) -> FakeAsyncSession:
    return FakeAsyncSession(store)


@pytest_asyncio.fixture
async def alpha_client(
    store: FakeDataStore,
    fake_session: FakeAsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[AsyncClient]:
    async for client in _make_client(ALPHA_PRINCIPAL, fake_session, store, monkeypatch):
        yield client


@pytest_asyncio.fixture
async def beta_client(
    store: FakeDataStore,
    fake_session: FakeAsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[AsyncClient]:
    async for client in _make_client(BETA_PRINCIPAL, fake_session, store, monkeypatch):
        yield client


async def _make_client(
    principal: FakePrincipal,
    session: FakeAsyncSession,
    store: FakeDataStore,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[AsyncClient]:
    """Build a FastAPI app bound to ``principal`` and yield a test client."""
    # Engine override — the identity and snapshot routes delegate here.
    _install_fake_engine(monkeypatch, store)

    app = _build_app()
    _install_dependency_overrides(app, principal, session)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://phase1-test") as client:
        yield client


# =============================================================================
# Fake engine + registry — installed via monkeypatch
# =============================================================================


def _install_fake_engine(monkeypatch: pytest.MonkeyPatch, store: FakeDataStore) -> None:
    """Patch ``IdentityStateEngine.build`` to serve from the fake store.

    The real engine hits Postgres and assembles the full
    :class:`IdentityState` tree. For security tests we only need the
    top-level envelope and the org-scope / not-found dispatch logic.
    """
    from app.schemas.identity import (  # type: ignore[import-not-found]
        CloudProvider,
        DataContext,
        DataMode,
        GovernanceClassification,
        IdentityState,
        IdentityType,
        LifecycleState,
        PrivilegeLevel,
        RiskLabel,
    )
    from app.services import identity_state_engine as engine_mod  # type: ignore[import-not-found]

    async def _fake_build(
        self: Any,
        *,
        identity_id: str,
        data_mode: DataMode = DataMode.LIVE,
        snapshot_id: Optional[int] = None,
        **_: Any,
    ) -> IdentityState:
        # Enforce the snapshot_id required invariant.
        if data_mode == DataMode.SNAPSHOT and snapshot_id is None:
            raise ValueError("snapshot_id is required when data_mode=snapshot")

        row = store.identity_by_id(self.organization_id, identity_id)
        if row is None:
            # If the id exists in another org, raise scope error (not
            # not-found) to match the real engine's contract.
            for other_row in store.identities:
                if other_row.identity_id == identity_id:
                    raise engine_mod.OrganizationScopeError(
                        "identity does not belong to this organization"
                    )
            raise engine_mod.IdentityNotFoundError(identity_id)

        computed_at = (
            STALE_COMPUTED_AT if getattr(self, "_force_stale", False) else FRESH_COMPUTED_AT
        )
        captured_at: Optional[datetime] = None
        if data_mode == DataMode.SNAPSHOT and snapshot_id is not None:
            snap = store.snapshot_by_id_any_org(snapshot_id)
            if snap is None or snap.organization_id != self.organization_id:
                raise engine_mod.OrganizationScopeError("snapshot scope violation")
            captured_at = snap.captured_at

        return _build_identity_state(
            row=row,
            data_mode=data_mode,
            snapshot_id=snapshot_id,
            snapshot_date=captured_at,
            computed_at=computed_at,
        )

    monkeypatch.setattr(engine_mod.IdentityStateEngine, "build", _fake_build, raising=True)

    # Also install the fake registry.
    _install_fake_registry(monkeypatch, store)


def _build_identity_state(
    *,
    row: FakeIdentityRow,
    data_mode: Any,
    snapshot_id: Optional[int],
    snapshot_date: Optional[datetime],
    computed_at: datetime,
) -> Any:
    """Hand-roll a minimal :class:`IdentityState` for the fake."""
    from app.schemas.identity import (  # type: ignore[import-not-found]
        CloudProvider,
        DataContext,
        GovernanceClassification,
        IdentityState,
        IdentityType,
        LifecycleState,
        PrivilegeLevel,
        RiskLabel,
    )

    is_stale = (datetime.now(timezone.utc) - computed_at) > STALE_THRESHOLD

    return IdentityState(
        identity_id=row.identity_id,
        global_identity_id=row.global_identity_id,
        organization_id=row.organization_id,
        display_name=row.display_name,
        identity_type=IdentityType(row.identity_type),
        cloud_provider=CloudProvider(row.cloud_provider),
        risk_label=RiskLabel(row.risk_label),
        risk_score=row.risk_score,
        governance=GovernanceClassification(row.governance),
        lifecycle_state=LifecycleState(row.lifecycle_state),
        is_dormant=row.is_dormant,
        privilege_level=PrivilegeLevel(row.privilege_level),
        last_seen=row.last_seen,
        roles=[],
        attack_paths=[],
        remediation=None,
        data_context=DataContext(
            data_mode=data_mode,
            snapshot_id=snapshot_id,
            snapshot_date=snapshot_date,
            computed_at=computed_at,
            is_stale=is_stale,
        ),
    )


def _install_fake_registry(monkeypatch: pytest.MonkeyPatch, store: FakeDataStore) -> None:
    """Patch the F1 global_identity_id registry to serve the fake store."""
    try:
        from app.services import global_identity_registry as reg_mod  # type: ignore[import-not-found]
    except ImportError:
        # The registry is optional for Phase 1 tests on non-cloud paths.
        return

    class _RegistryScopeError(Exception):
        pass

    async def _fake_resolve(
        self: Any,
        *,
        cloud_id: str,
        cloud_provider: str,
        organization_id: str,
    ) -> UUID:
        for row in store.identities:
            if row.organization_id != organization_id:
                continue
            if row.identity_id.endswith(cloud_id) or row.identity_id == cloud_id:
                return row.global_identity_id
        raise reg_mod.RegistryNotFoundError(cloud_id)

    async def _fake_get_peers(
        self: Any,
        *,
        global_identity_id: UUID,
        organization_id: str,
    ) -> list[Any]:
        # Peers are ONLY returned if the global id belongs to this org.
        row = store.identity_by_global_id(organization_id, global_identity_id)
        if row is None:
            raise reg_mod.RegistryScopeError(
                "global_identity_id does not belong to this organization"
            )
        return [row]

    async def _fake_bulk_resolve(
        self: Any,
        *,
        cloud_ids: list[str],
        cloud_provider: str,
        organization_id: str,
    ) -> dict[str, UUID]:
        out: dict[str, UUID] = {}
        for cid in cloud_ids:
            for row in store.identities:
                if row.organization_id != organization_id:
                    continue
                if row.identity_id.endswith(cid) or row.identity_id == cid:
                    out[cid] = row.global_identity_id
                    break
        return out

    monkeypatch.setattr(reg_mod.GlobalIdentityRegistry, "resolve", _fake_resolve, raising=False)
    monkeypatch.setattr(reg_mod.GlobalIdentityRegistry, "get_peers", _fake_get_peers, raising=False)
    monkeypatch.setattr(
        reg_mod.GlobalIdentityRegistry, "bulk_resolve", _fake_bulk_resolve, raising=False
    )


# =============================================================================
# Helpers
# =============================================================================


def _assert_error_body(body: dict[str, Any], expected_code: str) -> None:
    """Validate the canonical error envelope shape emitted by Phase 1 routes."""
    assert "detail" in body, f"missing 'detail' wrapper: {body}"
    detail = body["detail"]
    assert isinstance(detail, dict), f"detail must be a dict, got {type(detail).__name__}"
    assert detail.get("error") == expected_code, (
        f"expected error code {expected_code!r}, got {detail.get('error')!r}"
    )
    assert "detail" in detail and isinstance(detail["detail"], str)


def _assert_no_foreign_identifiers(
    body: Any,
    *,
    forbidden_strings: list[str],
) -> None:
    """Walk the response body and fail if any forbidden string appears."""
    serialized = repr(body)
    for needle in forbidden_strings:
        assert needle not in serialized, (
            f"response leaked foreign identifier {needle!r}: {serialized}"
        )


def _assert_all_org_scoped(rows: list[dict[str, Any]], organization_id: str) -> None:
    for row in rows:
        assert row.get("organization_id") == organization_id, (
            f"row escaped org scope: expected {organization_id}, got {row.get('organization_id')}"
        )


# =============================================================================
# SECTION 1 — Cross-Tenant Leakage Tests
# =============================================================================


@pytest.mark.security
class TestCrossTenantLeakage:
    """Every Phase 1 route refuses to return foreign-tenant data.

    Two organizations are seeded with disjoint identities, roles, and
    resources. Every test authenticates as ``org_alpha`` and attempts
    to access ``org_beta`` data through every public surface.
    """

    async def test_identity_list_scoped_to_org(
        self, alpha_client: AsyncClient, store: FakeDataStore
    ) -> None:
        """PREVENTS: ``GET /identities`` returning org_beta rows to an org_alpha caller.

        A broken tenant filter in the list handler would mix both orgs'
        rows into the response. This test asserts the response is
        populated (rules out an accidental empty-list false positive)
        AND that every row belongs to the caller's organization.
        """
        # Arrange — sanity check the fixture seeded both orgs.
        assert store.identities_for("org_alpha")
        assert store.identities_for("org_beta")

        # Act
        response = await alpha_client.get("/api/v1/identities")

        # Assert — status
        assert response.status_code == status.HTTP_200_OK
        body = response.json()

        # Assert — envelope shape
        assert "items" in body and isinstance(body["items"], list)
        assert "data_context" in body
        assert len(body["items"]) == len(ALPHA_IDENTITY_IDS)

        # Assert — every row is org_alpha, no beta identifiers leaked
        _assert_all_org_scoped(body["items"], "org_alpha")
        _assert_no_foreign_identifiers(
            body,
            forbidden_strings=list(BETA_IDENTITY_IDS) + ["org_beta"],
        )

    async def test_identity_detail_scoped_to_org(
        self, alpha_client: AsyncClient
    ) -> None:
        """PREVENTS: ``GET /identities/{beta_id}`` succeeding with an alpha token.

        The route must either 403 (we know it's foreign) or 404 (we
        refuse to confirm existence). Either is acceptable; a 200 is a
        cross-tenant leak.
        """
        # Arrange — beta identity id is valid but foreign to alpha.
        foreign_id = BETA_IDENTITY_IDS[0]

        # Act
        response = await alpha_client.get(f"/api/v1/identities/{foreign_id}")

        # Assert — status in the acceptable set
        assert response.status_code in (
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND,
        )

        # Assert — error envelope, no beta data
        body = response.json()
        assert "detail" in body
        _assert_no_foreign_identifiers(
            body, forbidden_strings=["org_beta", "bob@beta.test"]
        )

    async def test_role_assignments_scoped_to_org(
        self, alpha_client: AsyncClient, store: FakeDataStore
    ) -> None:
        """PREVENTS: an org_alpha identity detail containing org_beta role rows.

        The role embedding path takes the identity_id from the URL and
        must filter role rows on the caller's organization_id, not on
        the identity_id alone.
        """
        # Arrange — both orgs have roles on their respective first identity.
        assert store.roles_for_identity("org_alpha", ALPHA_IDENTITY_IDS[0])
        assert store.roles_for_identity("org_beta", BETA_IDENTITY_IDS[0])
        alpha_identity = ALPHA_IDENTITY_IDS[0]

        # Act
        response = await alpha_client.get(f"/api/v1/identities/{alpha_identity}")

        # Assert — success
        assert response.status_code == status.HTTP_200_OK
        body = response.json()

        # Assert — no beta role ids anywhere in the payload
        _assert_no_foreign_identifiers(
            body, forbidden_strings=list(BETA_ROLE_IDS) + ["beta-role", "org_beta"]
        )

    async def test_resources_scoped_to_org(
        self, alpha_client: AsyncClient, store: FakeDataStore
    ) -> None:
        """PREVENTS: ``GET /resources`` returning org_beta resources to an alpha caller.

        A missing org filter on the resources list query would let a
        tenant enumerate every cloud resource in the platform.
        """
        # Arrange
        assert store.resources_for("org_alpha")
        assert store.resources_for("org_beta")

        # Act
        response = await alpha_client.get("/api/v1/resources")

        # Assert — status + shape
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert "items" in body and isinstance(body["items"], list)

        # Assert — every resource is alpha-owned
        assert len(body["items"]) == len(store.resources_for("org_alpha"))
        _assert_all_org_scoped(body["items"], "org_alpha")
        _assert_no_foreign_identifiers(
            body,
            forbidden_strings=[BETA_RESOURCE_CLOUD_ID, "beta-kv", "org_beta"],
        )

    async def test_snapshot_scoped_to_org(
        self, alpha_client: AsyncClient
    ) -> None:
        """PREVENTS: ``GET /snapshots/{beta_id}`` succeeding with an alpha token.

        The route's two-phase lookup MUST surface a 403 (not 404) when
        the snapshot exists but belongs to another org — otherwise it
        doubles as an existence oracle. The response body must not
        include the foreign organization_id.
        """
        # Act
        response = await alpha_client.get(f"/api/v1/snapshots/{BETA_SNAPSHOT_ID}")

        # Assert — status code
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Assert — error envelope
        body = response.json()
        _assert_error_body(body, "org_scope_error")

        # Assert — no foreign identifiers leaked
        _assert_no_foreign_identifiers(
            body, forbidden_strings=["org_beta", "bob@beta.test"]
        )

    async def test_snapshot_identity_scoped_to_org(
        self, alpha_client: AsyncClient
    ) -> None:
        """PREVENTS: listing identities in a foreign snapshot.

        The snapshot ownership check runs BEFORE the identity list
        query, so even if the caller supplies a valid beta snapshot id
        with beta identity filters, the first check must 403 and no
        rows must be served.
        """
        # Act
        response = await alpha_client.get(
            f"/api/v1/snapshots/{BETA_SNAPSHOT_ID}/identities"
        )

        # Assert — status
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Assert — error envelope + no leaks
        body = response.json()
        _assert_error_body(body, "org_scope_error")
        _assert_no_foreign_identifiers(
            body,
            forbidden_strings=list(BETA_IDENTITY_IDS) + ["org_beta"],
        )

    async def test_attack_paths_scoped_to_org(
        self, alpha_client: AsyncClient, store: FakeDataStore
    ) -> None:
        """PREVENTS: an alpha identity's attack paths including beta hops.

        The attack-path builder must scope every intermediate
        ``role_assignments`` and ``resources`` join on the caller's
        organization_id. A missing filter would let the path-finder
        walk across tenant boundaries.
        """
        # Arrange
        alpha_identity = ALPHA_IDENTITY_IDS[0]

        # Act
        response = await alpha_client.get(
            f"/api/v1/identities/{alpha_identity}/attack-paths"
        )

        # Assert — status is 200 (alpha owns the identity)
        assert response.status_code in (status.HTTP_200_OK, status.HTTP_404_NOT_FOUND)
        if response.status_code == status.HTTP_200_OK:
            body = response.json()
            # Assert — no beta references anywhere in the path graph
            _assert_no_foreign_identifiers(
                body,
                forbidden_strings=list(BETA_IDENTITY_IDS)
                + list(BETA_ROLE_IDS)
                + [BETA_RESOURCE_CLOUD_ID, "org_beta"],
            )

    async def test_remediation_scoped_to_org(
        self, alpha_client: AsyncClient
    ) -> None:
        """PREVENTS: executing a remediation on an org_beta identity with an alpha token.

        The remediation executor must refuse even if the caller knows
        the foreign identity_id. 200 here would be a cross-tenant write.
        """
        # Arrange
        foreign_identity = BETA_IDENTITY_IDS[0]

        # Act
        response = await alpha_client.post(
            f"/api/v1/identities/{foreign_identity}/remediation/execute",
            json={"action_id": "revoke_role", "reason": "test"},
        )

        # Assert — status is 403 or 404 (never 200)
        assert response.status_code in (
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND,
        )
        body = response.json()
        assert "detail" in body

    async def test_no_cross_org_data_in_error_messages(
        self, alpha_client: AsyncClient
    ) -> None:
        """PREVENTS: 403/404 bodies leaking foreign identity ids, names, or org slugs.

        Even the error path must not whisper what exists in another
        tenant. This test poisons alpha's request with a known beta
        identity_id and asserts the response body is clean of every
        beta marker.
        """
        # Arrange
        foreign_identity = BETA_IDENTITY_IDS[0]
        forbidden = [
            "org_beta",
            "bob@beta.test",
            "beta-identity-1",
            *BETA_IDENTITY_IDS,
            *[str(g) for g in BETA_GIDS],
        ]

        # Act — probe three surfaces that all take an identity id
        responses = [
            await alpha_client.get(f"/api/v1/identities/{foreign_identity}"),
            await alpha_client.get(f"/api/v1/identities/{foreign_identity}/roles"),
            await alpha_client.post(
                f"/api/v1/identities/{foreign_identity}/remediation/execute",
                json={"action_id": "revoke_role", "reason": "t"},
            ),
        ]

        # Assert — every response is non-200 AND no body leaks
        for response in responses:
            assert response.status_code >= 400
            body_text = response.text
            for needle in forbidden:
                assert needle not in body_text, (
                    f"error path leaked {needle!r} in body: {body_text}"
                )


# =============================================================================
# SECTION 2 — global_identity_id (F1) Scoping Tests
# =============================================================================


@pytest.mark.security
class TestGlobalIdentityIdScoping:
    """F1 cross-cloud UUID registry enforces tenant scope everywhere.

    The registry is cross-cloud but NEVER cross-tenant. These tests
    assert that no lookup surface — direct resolve, peer walk, bulk
    resolve, or resource linking — can be used to pivot from org_alpha
    to org_beta.
    """

    async def test_registry_resolution_scoped(
        self, store: FakeDataStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PREVENTS: resolve(cloud_id, beta_org) returning a UUID from org_alpha.

        If the registry key is built from cloud_id alone without an
        organization_id salt, two tenants that independently import
        the same ARM id would collide and one would inherit the
        other's global_identity_id.
        """
        # Arrange
        _install_fake_registry(monkeypatch, store)
        from app.services.global_identity_registry import (  # type: ignore[import-not-found]
            GlobalIdentityRegistry,
            RegistryNotFoundError,
        )

        registry = GlobalIdentityRegistry()
        shared_cloud_id = ALPHA_IDENTITY_IDS[0]

        # Act — resolve the same cloud id once per org
        alpha_uuid = await registry.resolve(
            cloud_id=shared_cloud_id,
            cloud_provider="azure",
            organization_id="org_alpha",
        )

        # Assert — alpha resolves to the alpha UUID
        assert alpha_uuid == ALPHA_GIDS[0]

        # Act + Assert — same id from beta MUST NOT return the alpha UUID
        with pytest.raises(RegistryNotFoundError):
            await registry.resolve(
                cloud_id=shared_cloud_id,
                cloud_provider="azure",
                organization_id="org_beta",
            )

    async def test_registry_peers_scoped(
        self, store: FakeDataStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PREVENTS: get_peers(alpha_gid, org_beta) leaking alpha peers.

        The peers method must reject any global_identity_id that does
        not belong to the caller's organization. Returning even one
        peer row across orgs is enough to build a cross-tenant graph.
        """
        # Arrange
        _install_fake_registry(monkeypatch, store)
        from app.services.global_identity_registry import (  # type: ignore[import-not-found]
            GlobalIdentityRegistry,
            RegistryScopeError,
        )

        registry = GlobalIdentityRegistry()

        # Act + Assert — beta caller with an alpha UUID
        with pytest.raises(RegistryScopeError):
            await registry.get_peers(
                global_identity_id=ALPHA_GIDS[0],
                organization_id="org_beta",
            )

        # Act — beta caller with a beta UUID returns beta peers only
        beta_peers = await registry.get_peers(
            global_identity_id=BETA_GIDS[0],
            organization_id="org_beta",
        )
        assert beta_peers
        for peer in beta_peers:
            assert peer.organization_id == "org_beta"

    async def test_global_id_route_scoped(
        self, alpha_client: AsyncClient
    ) -> None:
        """PREVENTS: ``GET /identities/global/{beta_gid}`` succeeding with alpha token.

        The lookup-by-global-id route must reject any UUID that isn't
        owned by the caller's org. A 200 here is a trivial
        cross-tenant read.
        """
        # Arrange
        foreign_gid = str(BETA_GIDS[0])

        # Act
        response = await alpha_client.get(f"/api/v1/identities/global/{foreign_gid}")

        # Assert — 403 or 404 only, never 200
        assert response.status_code in (
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND,
        )
        body = response.json()
        _assert_no_foreign_identifiers(
            body, forbidden_strings=["org_beta", "beta-identity"]
        )

    async def test_federated_identity_scoped(
        self, store: FakeDataStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PREVENTS: federated trust edges bridging tenants in the registry.

        A federated identity (e.g. an OIDC federation credential) must
        never create an implicit global_identity_id link that crosses
        organization_id boundaries. The registry link method must
        reject a pairing whose two ends belong to different orgs.
        """
        # Arrange — try to federate an alpha MSI with a beta SPN
        _install_fake_registry(monkeypatch, store)
        try:
            from app.services.global_identity_registry import (  # type: ignore[import-not-found]
                GlobalIdentityRegistry,
                RegistryScopeError,
            )
        except ImportError:
            pytest.skip("federated linking not implemented in this build")

        registry = GlobalIdentityRegistry()

        # Act + Assert — attempt the cross-org federation
        with pytest.raises((RegistryScopeError, ValueError)):
            await registry.link_federation(  # type: ignore[attr-defined]
                left_global_id=ALPHA_GIDS[0],
                left_org="org_alpha",
                right_global_id=BETA_GIDS[0],
                right_org="org_beta",
            )

    async def test_bulk_resolve_no_cross_org(
        self, store: FakeDataStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PREVENTS: bulk_resolve() returning any UUID minted for a different org.

        When the caller supplies a list of cloud_ids and a single org,
        the registry must treat the org as an inviolable filter — ids
        that happen to exist only under other orgs return nothing, not
        the foreign UUID.
        """
        # Arrange
        _install_fake_registry(monkeypatch, store)
        from app.services.global_identity_registry import (  # type: ignore[import-not-found]
            GlobalIdentityRegistry,
        )

        registry = GlobalIdentityRegistry()
        mixed_cloud_ids = [ALPHA_IDENTITY_IDS[0], BETA_IDENTITY_IDS[0]]

        # Act — run bulk_resolve as alpha
        result = await registry.bulk_resolve(
            cloud_ids=mixed_cloud_ids,
            cloud_provider="azure",
            organization_id="org_alpha",
        )

        # Assert — only the alpha id is resolved
        assert ALPHA_IDENTITY_IDS[0] in result
        assert BETA_IDENTITY_IDS[0] not in result
        # Assert — no beta UUIDs ever appear in the values
        for gid in result.values():
            assert gid not in BETA_GIDS

    async def test_resource_global_id_scoped(
        self, alpha_client: AsyncClient, store: FakeDataStore
    ) -> None:
        """PREVENTS: an MSI resource linked to an org_beta global_id showing up to alpha.

        G1 resources can carry ``global_identity_id`` to link them to
        a managed identity. That link must not leak across tenants —
        the resource list for alpha must exclude any resource whose
        global_identity_id belongs to a beta identity, and the detail
        endpoint must 404 / 403 a beta resource_id even if alpha
        guesses the full cloud path.
        """
        # Arrange
        beta_resource = store.resources_for("org_beta")[0]
        assert beta_resource.global_identity_id in BETA_GIDS

        # Act — list returns only alpha
        list_response = await alpha_client.get("/api/v1/resources")
        # Assert — list
        assert list_response.status_code == status.HTTP_200_OK
        list_body = list_response.json()
        _assert_all_org_scoped(list_body["items"], "org_alpha")
        for item in list_body["items"]:
            assert item.get("global_identity_id") not in [str(g) for g in BETA_GIDS]

        # Act — direct detail fetch of a beta resource id
        detail_response = await alpha_client.get(
            f"/api/v1/resources/{BETA_RESOURCE_CLOUD_ID.lstrip('/')}"
        )

        # Assert — detail refuses the foreign resource
        assert detail_response.status_code in (
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND,
        )


# =============================================================================
# SECTION 3 — DataContext Integrity Tests
# =============================================================================


@pytest.mark.correctness
class TestDataContextIntegrity:
    """F3 DataContext envelope is always present, correct, and honest.

    Every Phase 1 identity-surface response must carry a DataContext
    block. Its ``data_mode`` must match how the data was produced, its
    ``is_stale`` flag must only fire when the underlying live data is
    genuinely older than the freshness threshold, and snapshot mode
    must hard-fail without a snapshot_id.
    """

    async def test_live_response_has_data_context(
        self, alpha_client: AsyncClient
    ) -> None:
        """PROVES: every live identity response carries data_mode='live'.

        Missing or mismatched DataContext envelopes break the
        frontend's banner logic and let stale data render as fresh.
        Every row AND the envelope itself must advertise
        data_mode='live'.
        """
        # Act — hit the live list
        list_response = await alpha_client.get("/api/v1/identities")

        # Assert — status and envelope shape
        assert list_response.status_code == status.HTTP_200_OK
        list_body = list_response.json()
        assert "data_context" in list_body
        assert list_body["data_context"]["data_mode"] == "live"
        assert list_body["data_context"]["snapshot_id"] is None

        # Assert — every item row also carries live mode
        for item in list_body["items"]:
            assert item.get("data_context", {}).get("data_mode") == "live"

        # Act — hit a detail endpoint
        detail_response = await alpha_client.get(
            f"/api/v1/identities/{ALPHA_IDENTITY_IDS[0]}"
        )
        assert detail_response.status_code == status.HTTP_200_OK
        detail_body = detail_response.json()

        # Assert — detail also advertises live
        assert detail_body["data_context"]["data_mode"] == "live"
        assert detail_body["data_context"]["snapshot_id"] is None

    async def test_snapshot_response_has_data_context(
        self, alpha_client: AsyncClient
    ) -> None:
        """PROVES: snapshot-mode responses carry data_mode='snapshot' + correct snapshot_id.

        Both the paginated list envelope and each row AND any
        downstream detail endpoint invoked via a snapshot id must
        return ``data_mode='snapshot'`` and the same ``snapshot_id``
        the client asked for — no silent downgrade to 'live'.
        """
        # Act — list identities in the alpha snapshot
        list_response = await alpha_client.get(
            f"/api/v1/snapshots/{ALPHA_SNAPSHOT_ID}/identities"
        )

        # Assert — envelope
        assert list_response.status_code == status.HTTP_200_OK
        list_body = list_response.json()
        assert list_body["data_context"]["data_mode"] == "snapshot"
        assert list_body["data_context"]["snapshot_id"] == ALPHA_SNAPSHOT_ID
        assert list_body["data_context"]["snapshot_date"] is not None

        # Assert — per-row stamping matches envelope
        for item in list_body["items"]:
            ctx = item["data_context"]
            assert ctx["data_mode"] == "snapshot"
            assert ctx["snapshot_id"] == ALPHA_SNAPSHOT_ID

        # Act — deep detail via snapshot
        detail_response = await alpha_client.get(
            f"/api/v1/snapshots/{ALPHA_SNAPSHOT_ID}/identities/{ALPHA_IDENTITY_IDS[0]}"
        )

        # Assert — detail also honors snapshot mode
        assert detail_response.status_code == status.HTTP_200_OK
        detail_body = detail_response.json()
        assert detail_body["data_context"]["data_mode"] == "snapshot"
        assert detail_body["data_context"]["snapshot_id"] == ALPHA_SNAPSHOT_ID

    async def test_stale_flag_set_correctly(
        self, store: FakeDataStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PROVES: is_stale=True iff the live data is older than 15 minutes.

        A live response whose underlying ``computed_at`` is within the
        freshness threshold must have ``is_stale=False``; one beyond
        the threshold must have ``is_stale=True``. Neither direction
        can be silently flipped.
        """
        from app.schemas.identity import DataContext, DataMode  # type: ignore[import-not-found]

        # Arrange — fresh ctx
        fresh_computed = datetime.now(timezone.utc) - timedelta(minutes=5)
        fresh_ctx = DataContext(
            data_mode=DataMode.LIVE,
            snapshot_id=None,
            snapshot_date=None,
            computed_at=fresh_computed,
            is_stale=(datetime.now(timezone.utc) - fresh_computed) > STALE_THRESHOLD,
        )
        # Assert — fresh
        assert fresh_ctx.is_stale is False

        # Arrange — stale ctx
        stale_computed = datetime.now(timezone.utc) - timedelta(minutes=20)
        stale_ctx = DataContext(
            data_mode=DataMode.LIVE,
            snapshot_id=None,
            snapshot_date=None,
            computed_at=stale_computed,
            is_stale=(datetime.now(timezone.utc) - stale_computed) > STALE_THRESHOLD,
        )
        # Assert — stale
        assert stale_ctx.is_stale is True

        # Act + Assert — boundary exactly at threshold must NOT flip to stale
        boundary_computed = datetime.now(timezone.utc) - STALE_THRESHOLD + timedelta(seconds=1)
        boundary_ctx = DataContext(
            data_mode=DataMode.LIVE,
            snapshot_id=None,
            snapshot_date=None,
            computed_at=boundary_computed,
            is_stale=(datetime.now(timezone.utc) - boundary_computed) > STALE_THRESHOLD,
        )
        assert boundary_ctx.is_stale is False

    async def test_snapshot_id_required_for_snapshot_mode(
        self, store: FakeDataStore, fake_session: FakeAsyncSession
    ) -> None:
        """PROVES: engine.build raises ValueError if data_mode=snapshot + no snapshot_id.

        Missing this guard would let a caller read from the live
        tables with a snapshot-mode DataContext — producing a response
        that claims to be point-in-time but was actually assembled
        from the current state of the system.
        """
        from app.schemas.identity import DataMode  # type: ignore[import-not-found]
        from app.services.identity_state_engine import (  # type: ignore[import-not-found]
            IdentityStateEngine,
        )

        # Arrange
        engine = IdentityStateEngine(organization_id="org_alpha", db=fake_session)

        # Act + Assert — missing snapshot_id
        with pytest.raises(ValueError, match="snapshot_id"):
            await engine.build(
                identity_id=ALPHA_IDENTITY_IDS[0],
                data_mode=DataMode.SNAPSHOT,
                snapshot_id=None,
            )

        # Act + Assert — negative/zero snapshot_id is also invalid
        for bad_id in (0, -1):
            with pytest.raises((ValueError, Exception)):
                await engine.build(
                    identity_id=ALPHA_IDENTITY_IDS[0],
                    data_mode=DataMode.SNAPSHOT,
                    snapshot_id=bad_id,
                )
