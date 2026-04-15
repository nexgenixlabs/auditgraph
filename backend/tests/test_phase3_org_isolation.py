"""
Org Isolation Regression Suite — Phase 3 Endpoints
====================================================

Verifies that every Phase 3 API endpoint enforces organization_id scoping
from the JWT. Two test users from different orgs must never see each
other's data.

Requires a running Flask server on port 5001 with at least org_id=2 (spadmin).
"""

from __future__ import annotations

import os
from typing import Optional

import pytest
import requests

BASE = os.environ.get("TEST_API_URL", "http://localhost:5001")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _login(username: str, password: str) -> str:
    """Log in and return the access_token, or skip if user does not exist."""
    resp = requests.post(
        f"{BASE}/api/auth/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    if resp.status_code != 200:
        pytest.skip(f"Cannot log in as {username} (status={resp.status_code})")
    return resp.json()["access_token"]


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def org2_token() -> str:
    """Token for org_id=2 (spadmin)."""
    return _login("spadmin", "changeme")


@pytest.fixture(scope="module")
def org1_token() -> str:
    """Token for org_id=1 (techadmin) — different org, should see no Phase 3 data."""
    return _login("techadmin", "changeme")


@pytest.fixture(scope="module")
def org2_headers(org2_token: str) -> dict[str, str]:
    return _headers(org2_token)


@pytest.fixture(scope="module")
def org1_headers(org1_token: str) -> dict[str, str]:
    return _headers(org1_token)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(path: str, headers: dict[str, str]) -> requests.Response:
    return requests.get(f"{BASE}{path}", headers=headers, timeout=10)


def _post(path: str, headers: dict[str, str], json: dict | None = None) -> requests.Response:
    return requests.post(f"{BASE}{path}", headers=headers, json=json or {}, timeout=10)


# ---------------------------------------------------------------------------
# 1. Identity List — org-scoped
# ---------------------------------------------------------------------------


class TestIdentityListIsolation:
    """GET /api/v1/identities must return only the calling org's identities."""

    def test_org2_sees_data(self, org2_headers: dict[str, str]):
        """Org 2 (spadmin) should see its identities."""
        resp = _get("/api/v1/identities?limit=5", org2_headers)
        assert resp.status_code == 200
        data = resp.json()
        for item in data.get("items", []):
            assert item["organization_id"] == "2", (
                f"Expected org_id=2, got {item['organization_id']}"
            )

    def test_org1_cannot_see_org2(self, org1_headers: dict[str, str]):
        """Org 1 (techadmin) must NOT see org 2's identities."""
        resp = _get("/api/v1/identities?limit=100", org1_headers)
        assert resp.status_code == 200
        data = resp.json()
        for item in data.get("items", []):
            assert item["organization_id"] != "2", (
                f"Org 1 saw org 2's identity: {item['identity_id']}"
            )


# ---------------------------------------------------------------------------
# 2. Identity Detail — org-scoped
# ---------------------------------------------------------------------------


class TestIdentityDetailIsolation:
    """GET /api/v1/identities/{id} must reject cross-org access."""

    def _get_org2_identity_id(self, org2_headers: dict[str, str]) -> str:
        resp = _get("/api/v1/identities?limit=1", org2_headers)
        items = resp.json().get("items", [])
        if not items:
            pytest.skip("No identities in org 2")
        return items[0]["identity_id"]

    def test_org2_can_read_own(self, org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _get(f"/api/v1/identities/{iid}", org2_headers)
        assert resp.status_code == 200

    def test_org1_cannot_read_org2(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _get(f"/api/v1/identities/{iid}", org1_headers)
        assert resp.status_code in (404, 403), (
            f"Expected 404/403 for cross-org access, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# 3. Roles — org-scoped
# ---------------------------------------------------------------------------


class TestRolesIsolation:
    def _get_org2_identity_id(self, org2_headers: dict[str, str]) -> str:
        resp = _get("/api/v1/identities?limit=1", org2_headers)
        items = resp.json().get("items", [])
        if not items:
            pytest.skip("No identities in org 2")
        return items[0]["identity_id"]

    def test_org1_cannot_read_org2_roles(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _get(f"/api/v1/identities/{iid}/roles", org1_headers)
        assert resp.status_code in (404, 403)


# ---------------------------------------------------------------------------
# 4. Attack Paths — org-scoped
# ---------------------------------------------------------------------------


class TestAttackPathIsolation:
    def _get_org2_identity_id(self, org2_headers: dict[str, str]) -> str:
        resp = _get("/api/v1/identities?limit=1", org2_headers)
        items = resp.json().get("items", [])
        if not items:
            pytest.skip("No identities in org 2")
        return items[0]["identity_id"]

    def test_org1_cannot_read_org2_attack_paths(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _get(f"/api/v1/identities/{iid}/attack-paths", org1_headers)
        assert resp.status_code in (404, 403)


# ---------------------------------------------------------------------------
# 5. Remediation — org-scoped
# ---------------------------------------------------------------------------


class TestRemediationIsolation:
    def _get_org2_identity_id(self, org2_headers: dict[str, str]) -> str:
        resp = _get("/api/v1/identities?limit=1", org2_headers)
        items = resp.json().get("items", [])
        if not items:
            pytest.skip("No identities in org 2")
        return items[0]["identity_id"]

    def test_org1_cannot_read_org2_remediation(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _get(f"/api/v1/identities/{iid}/remediation", org1_headers)
        assert resp.status_code in (404, 403)


# ---------------------------------------------------------------------------
# 6. Simulations — org-scoped
# ---------------------------------------------------------------------------


class TestSimulationIsolation:
    def _get_org2_identity_id(self, org2_headers: dict[str, str]) -> str:
        resp = _get("/api/v1/identities?limit=1", org2_headers)
        items = resp.json().get("items", [])
        if not items:
            pytest.skip("No identities in org 2")
        return items[0]["identity_id"]

    def test_org1_cannot_list_org2_simulations(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _get(f"/api/v1/identities/{iid}/simulations", org1_headers)
        assert resp.status_code in (404, 403)

    def test_org1_cannot_simulate_org2(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        iid = self._get_org2_identity_id(org2_headers)
        resp = _post(
            f"/api/v1/identities/{iid}/simulate",
            org1_headers,
            json={"simulation_type": "ROLE_REMOVAL", "payload": {"role_key": "Reader"}},
        )
        assert resp.status_code in (404, 403)


# ---------------------------------------------------------------------------
# 7. Posture — org-scoped
# ---------------------------------------------------------------------------


class TestPostureIsolation:
    """Posture endpoints derive org_id from JWT — results must differ by org."""

    def test_org2_posture_score(self, org2_headers: dict[str, str]):
        resp = _get("/api/v1/posture/score", org2_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == 2

    def test_org1_posture_score_different_org(self, org1_headers: dict[str, str]):
        resp = _get("/api/v1/posture/score", org1_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == 1, (
            f"Org 1 posture should report org_id=1, got {data['organization_id']}"
        )

    def test_posture_actions_org_scoped(self, org2_headers: dict[str, str]):
        resp = _get("/api/v1/posture/actions", org2_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == 2

    def test_posture_history_org_scoped(self, org2_headers: dict[str, str]):
        resp = _get("/api/v1/posture/score/history?days=7", org2_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == 2


# ---------------------------------------------------------------------------
# 8. Global Identity — org-scoped
# ---------------------------------------------------------------------------


class TestGlobalIdentityIsolation:
    def _get_org2_global_id(self, org2_headers: dict[str, str]) -> str:
        resp = _get("/api/v1/identities?limit=1", org2_headers)
        items = resp.json().get("items", [])
        if not items:
            pytest.skip("No identities in org 2")
        return items[0]["global_identity_id"]

    def test_org1_cannot_see_org2_via_global(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        gid = self._get_org2_global_id(org2_headers)
        resp = _get(f"/api/v1/identities/global/{gid}", org1_headers)
        assert resp.status_code == 200
        data = resp.json()
        for item in data.get("items", []):
            assert item["organization_id"] != "2", (
                "Org 1 saw org 2 data via global lookup"
            )


# ---------------------------------------------------------------------------
# 9. Unauthenticated access — all routes must reject
# ---------------------------------------------------------------------------


class TestUnauthenticatedRejection:
    """All Phase 3 routes must return 401/403 without a Bearer token."""

    PATHS = [
        ("GET", "/api/v1/identities"),
        ("GET", "/api/v1/identities/some-id"),
        ("GET", "/api/v1/identities/some-id/roles"),
        ("GET", "/api/v1/identities/some-id/attack-paths"),
        ("GET", "/api/v1/identities/some-id/remediation"),
        ("GET", "/api/v1/identities/some-id/simulations"),
        ("GET", "/api/v1/posture/score"),
        ("GET", "/api/v1/posture/score/history"),
        ("GET", "/api/v1/posture/actions"),
    ]

    @pytest.mark.parametrize("method,path", PATHS)
    def test_no_token_rejected(self, method: str, path: str):
        if method == "GET":
            resp = requests.get(f"{BASE}{path}", timeout=10)
        else:
            resp = requests.post(f"{BASE}{path}", json={}, timeout=10)
        assert resp.status_code in (401, 403), (
            f"{method} {path} returned {resp.status_code} without auth"
        )


# ---------------------------------------------------------------------------
# 10. Bulk Simulation — org-scoped
# ---------------------------------------------------------------------------


class TestBulkSimulationIsolation:
    def _get_org2_identity_ids(self, org2_headers: dict[str, str]) -> list[str]:
        resp = _get("/api/v1/identities?limit=3", org2_headers)
        items = resp.json().get("items", [])
        return [i["identity_id"] for i in items if i.get("risk_score", 0) <= 100]

    def test_org1_cannot_bulk_simulate_org2(self, org1_headers: dict[str, str], org2_headers: dict[str, str]):
        ids = self._get_org2_identity_ids(org2_headers)
        if not ids:
            pytest.skip("No identities for bulk simulation")
        resp = _post(
            "/api/v1/posture/simulate/bulk",
            org1_headers,
            json={
                "identity_ids": ids,
                "simulation_type": "ROLE_REMOVAL",
                "payload": {"role_key": "Reader"},
            },
        )
        # Should either fail entirely or return 0 completed
        if resp.status_code == 200:
            data = resp.json()
            assert data["completed"] == 0, (
                "Org 1 successfully simulated org 2 identities"
            )
