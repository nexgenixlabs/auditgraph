"""
Cross-tenant leakage regression tests
=====================================

These tests lock in AuditGraph's multi-tenant perimeter. Every test below
is a regression fence for a specific attack vector — if any assertion
fails, a real horizontal privilege escalation is shipping.

Fixtures assumed (provided by ``tests/conftest.py``):

* ``client`` — :class:`httpx.AsyncClient` bound to the FastAPI app.
* ``org_a`` / ``org_b`` — dicts like ``{"id": str, "token": str}`` for two
  independently provisioned tenants seeded with disjoint data.
* ``org_a_identity`` / ``org_b_identity`` — seeded identity records,
  each carrying its own ``global_identity_id`` and ``organization_id``.
* ``async_session`` — :class:`AsyncSession` to the test database.

The tests only rely on the public HTTP contract and the
:class:`IdentityStateEngine` service. If the fixture module is missing
(e.g. the repo is checked out outside the test environment) the tests
are skipped rather than failing with import errors.
"""

from __future__ import annotations

import importlib.util
import uuid

import pytest


# ---------------------------------------------------------------------------
# Optional import — skip the entire module if the backend isn't installed.
# ---------------------------------------------------------------------------


_has_backend = importlib.util.find_spec("app") is not None
pytestmark = [
    pytest.mark.skipif(
        not _has_backend,
        reason="backend package not importable — run inside the backend venv",
    ),
    pytest.mark.asyncio,
]


if _has_backend:  # pragma: no cover — import-guarded
    from app.schemas.identity import DataMode  # type: ignore[import-not-found]
    from app.services.identity_state_engine import (  # type: ignore[import-not-found]
        IdentityNotFoundError,
        IdentityStateEngine,
        OrganizationScopeError,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _assert_error_shape(body: dict) -> None:
    """Every error response must have a stable ``{error, detail}`` shape."""
    assert isinstance(body, dict), f"error body must be a dict, got {type(body)}"
    assert "error" in body, f"error body missing 'error' key: {body}"
    assert "detail" in body, f"error body missing 'detail' key: {body}"


def _assert_list_shape(body: dict) -> None:
    """Every list endpoint must return ``{items: [...], total: int}``."""
    assert isinstance(body, dict)
    assert "items" in body and isinstance(body["items"], list)
    assert "total" in body and isinstance(body["total"], int)


# ---------------------------------------------------------------------------
# 1. Identity list — horizontal privilege escalation via enumeration
# ---------------------------------------------------------------------------


async def test_cannot_read_other_org_identities(client, org_a, org_b, org_b_identity):
    """
    PREVENTS: horizontal privilege escalation via the identity list.

    Attack vector: an attacker authenticated as tenant A calls
    ``GET /api/identities`` hoping to receive tenant B's identities either
    by omitting a filter, by spoofing an ``X-Tenant-Id`` header, or by
    passing ``organization_id=<org_b>`` as a query string.
    """
    # Arrange — org A is authenticated; org B has a distinct seeded identity.
    headers = _auth(org_a["token"])

    # Act — first the plain list, then the spoofing attempts.
    plain = await client.get("/api/identities", headers=headers)
    spoof_header = await client.get(
        "/api/identities",
        headers={**headers, "X-Tenant-Id": org_b["id"]},
    )
    spoof_query = await client.get(
        "/api/identities",
        headers=headers,
        params={"organization_id": org_b["id"]},
    )

    # Assert — every response is 200 but the bodies are strictly org A.
    assert plain.status_code == 200
    body = plain.json()
    _assert_list_shape(body)
    assert all(i["organization_id"] == org_a["id"] for i in body["items"])
    assert org_b_identity["identity_id"] not in {i["identity_id"] for i in body["items"]}

    # Spoofing attempts are either ignored (same result as plain) or rejected.
    for spoof in (spoof_header, spoof_query):
        assert spoof.status_code in (200, 403)
        if spoof.status_code == 200:
            spoof_body = spoof.json()
            _assert_list_shape(spoof_body)
            assert all(i["organization_id"] == org_a["id"] for i in spoof_body["items"])
        else:
            _assert_error_shape(spoof.json())


# ---------------------------------------------------------------------------
# 2. Role enumeration across tenant boundary
# ---------------------------------------------------------------------------


async def test_cannot_read_other_org_roles(client, org_a, org_b, org_b_identity):
    """
    PREVENTS: role enumeration across the tenant boundary.

    Attack vector: tenant A requests the role assignments of a tenant B
    identity by passing its ``identity_id`` directly to
    ``GET /api/identities/{id}/roles``. The endpoint must return 404
    (indistinguishable from "not found") rather than 200 with foreign data.
    """
    # Arrange
    headers = _auth(org_a["token"])
    foreign_id = org_b_identity["identity_id"]

    # Act
    response = await client.get(f"/api/identities/{foreign_id}/roles", headers=headers)

    # Assert
    assert response.status_code == 404, (
        "cross-org role lookup must return 404, not 200/403, "
        "to avoid existence oracle"
    )
    body = response.json()
    _assert_error_shape(body)
    # Body must not contain any tenant B fingerprints.
    serialized = str(body).lower()
    assert org_b["id"].lower() not in serialized


# ---------------------------------------------------------------------------
# 3. Resource discovery across tenant boundary
# ---------------------------------------------------------------------------


async def test_cannot_read_other_org_resources(client, org_a, org_b):
    """
    PREVENTS: resource discovery across the tenant boundary.

    Attack vector: tenant A calls ``GET /api/resources`` and hopes to see
    tenant B's storage accounts / key vaults, either via the default list
    or by passing a guessed resource id to the detail endpoint.
    """
    # Arrange
    headers_a = _auth(org_a["token"])
    headers_b = _auth(org_b["token"])

    # Act — org A and org B both list resources.
    list_a = await client.get("/api/resources", headers=headers_a)
    list_b = await client.get("/api/resources", headers=headers_b)

    # Assert — strict org partitioning.
    assert list_a.status_code == 200
    assert list_b.status_code == 200
    body_a = list_a.json()
    body_b = list_b.json()
    _assert_list_shape(body_a)
    _assert_list_shape(body_b)
    ids_a = {r["id"] for r in body_a["items"]}
    ids_b = {r["id"] for r in body_b["items"]}
    assert ids_a.isdisjoint(ids_b), "resource ids must not overlap across tenants"
    assert all(r["organization_id"] == org_a["id"] for r in body_a["items"])
    assert all(r["organization_id"] == org_b["id"] for r in body_b["items"])

    # Cross-fetch attempt: tenant A asks for a tenant-B resource by id.
    if ids_b:
        target = next(iter(ids_b))
        cross = await client.get(f"/api/resources/{target}", headers=headers_a)
        assert cross.status_code == 404
        _assert_error_shape(cross.json())


# ---------------------------------------------------------------------------
# 4. Global identity registry scoping
# ---------------------------------------------------------------------------


async def test_global_identity_registry_scoped(client, org_a, org_b, org_b_identity):
    """
    PREVENTS: UUID harvesting via the global identity registry.

    Attack vector: tenant A enumerates ``global_identity_id`` values to
    correlate tenant B identities across clouds. The registry and any
    endpoint that exposes a global id must refuse to serve metadata for a
    global id that lives in a different tenant.
    """
    # Arrange
    headers_a = _auth(org_a["token"])
    foreign_gid = org_b_identity["global_identity_id"]

    # Act
    peers = await client.get(
        f"/api/global-identities/{foreign_gid}/peers", headers=headers_a
    )
    detail = await client.get(
        f"/api/global-identities/{foreign_gid}", headers=headers_a
    )

    # Assert — must be 404, never 200, never 500.
    for response in (peers, detail):
        assert response.status_code == 404, (
            f"cross-org global identity lookup returned {response.status_code} "
            f"— expected 404 to avoid existence oracle"
        )
        _assert_error_shape(response.json())


# ---------------------------------------------------------------------------
# 5. IdentityStateEngine requires org context
# ---------------------------------------------------------------------------


async def test_identity_state_engine_enforces_org(async_session):
    """
    PREVENTS: engine instantiation without organization context.

    Attack vector: a refactor accidentally constructs
    :class:`IdentityStateEngine` with an empty / ``None`` ``organization_id``,
    which would cause every downstream query to run unscoped.
    """
    # Arrange / Act / Assert — empty string
    with pytest.raises(ValueError, match="organization_id"):
        IdentityStateEngine(organization_id="", db=async_session)

    # Arrange / Act / Assert — whitespace-only string
    with pytest.raises(ValueError, match="organization_id"):
        IdentityStateEngine(organization_id="   ", db=async_session)

    # Arrange / Act / Assert — None
    with pytest.raises((ValueError, TypeError)):
        IdentityStateEngine(organization_id=None, db=async_session)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 6. Cross-tenant leakage via global_identity_id
# ---------------------------------------------------------------------------


async def test_cross_tenant_leakage_via_global_id(
    async_session, org_a, org_b, org_b_identity
):
    """
    PREVENTS: using a ``global_identity_id`` from org A to access org B data.

    Attack vector: an attacker learns a valid ``global_identity_id`` (e.g.
    from a shared log) and hands it to an engine bound to a *different*
    organization. The engine must either raise
    :class:`IdentityNotFoundError` (row not visible) or
    :class:`OrganizationScopeError` (row visible but rejected). It must
    never return an :class:`IdentityState` carrying foreign data.
    """
    # Arrange — engine is bound to org A, but we probe a tenant-B identity.
    engine = IdentityStateEngine(organization_id=org_a["id"], db=async_session)
    foreign_identity_id = org_b_identity["identity_id"]

    # Act / Assert
    with pytest.raises((IdentityNotFoundError, OrganizationScopeError)) as excinfo:
        await engine.build(
            identity_id=foreign_identity_id,
            data_mode=DataMode.LIVE,
            snapshot_id=None,
        )

    # Error context must record both the engine org and the foreign id so
    # incident responders can reconstruct the attempted crossing.
    ctx = getattr(excinfo.value, "context", {}) or {}
    assert ctx.get("organization_id") == org_a["id"]
    assert ctx.get("identity_id") == foreign_identity_id
    # And of course it must never leak tenant B's id in the raised error.
    assert org_b["id"] not in str(excinfo.value)
