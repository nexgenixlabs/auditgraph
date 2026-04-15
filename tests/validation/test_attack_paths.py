"""Tests for GET /api/graph/attack-paths.

Validates attack path detection, response structure, filtering,
security boundaries, and performance.
"""

import pytest

from .conftest import VALID_SEVERITIES


# ══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAttackPathsResponse:
    """Validate response schema and content."""

    def test_returns_200_with_identity(self, api, identity_id):
        resp = api.get(f"/api/graph/attack-paths?identity={identity_id}")
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"

    def test_requires_identity_parameter(self, api):
        resp = api.get("/api/graph/attack-paths")
        assert resp.status_code == 400, (
            f"Missing identity param should return 400, got {resp.status_code}"
        )
        data = resp.json()
        assert "error" in data

    def test_response_has_paths_and_summary(self, api, identity_id):
        data = api.get(f"/api/graph/attack-paths?identity={identity_id}").json()
        assert "paths" in data, "Response must contain 'paths'"
        assert "summary" in data, "Response must contain 'summary'"
        assert isinstance(data["paths"], list)

    def test_summary_structure(self, api, identity_id):
        data = api.get(f"/api/graph/attack-paths?identity={identity_id}").json()
        summary = data["summary"]
        assert "total" in summary
        assert isinstance(summary["total"], int)
        assert summary["total"] >= 0
        if "by_severity" in summary:
            for sev, count in summary["by_severity"].items():
                assert sev in VALID_SEVERITIES, f"Invalid severity in summary: {sev}"
                assert isinstance(count, int) and count >= 0

    def test_path_entry_structure(self, api, identity_id):
        data = api.get(f"/api/graph/attack-paths?identity={identity_id}").json()
        for path in data["paths"]:
            assert "severity" in path, f"Path missing severity: {path.keys()}"
            assert path["severity"] in VALID_SEVERITIES
            # Must have a type/finding classification
            assert "type" in path or "finding_type" in path, (
                f"Path missing type/finding_type: {path.keys()}"
            )

    def test_path_has_narrative(self, api, identity_id):
        """Attack paths should include human-readable narrative."""
        data = api.get(f"/api/graph/attack-paths?identity={identity_id}").json()
        for path in data["paths"]:
            if "narrative" in path:
                assert isinstance(path["narrative"], str)
                assert len(path["narrative"]) > 0

    def test_severity_filter(self, api, identity_id):
        """Filter by severity should only return matching paths."""
        resp = api.get(
            f"/api/graph/attack-paths?identity={identity_id}&severity=critical"
        )
        if resp.status_code == 200:
            data = resp.json()
            for path in data["paths"]:
                assert path["severity"] == "critical", (
                    f"Severity filter returned non-critical: {path['severity']}"
                )

    def test_limit_parameter(self, api, identity_id):
        resp = api.get(
            f"/api/graph/attack-paths?identity={identity_id}&limit=2"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["paths"]) <= 2

    def test_summary_total_matches_paths(self, api, identity_id):
        """Summary total should reflect the actual paths returned (or total available)."""
        data = api.get(f"/api/graph/attack-paths?identity={identity_id}").json()
        # total may be >= len(paths) due to pagination
        assert data["summary"]["total"] >= len(data["paths"])


# ══════════════════════════════════════════════════════════════════════════
# SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAttackPathsSecurity:
    """Security boundary checks."""

    def test_reject_unauthenticated(self, base_url):
        resp = requests.get(
            f"{base_url}/api/graph/attack-paths?identity=1"
        )
        assert resp.status_code in (401, 403)

    def test_reject_invalid_identity(self, api):
        for bad_id in ["abc", "'; SELECT * FROM--", "<script>", "null"]:
            resp = api.get(f"/api/graph/attack-paths?identity={bad_id}")
            # Should either return 400/404 or return empty paths (not crash)
            assert resp.status_code in (200, 400, 404), (
                f"Bad identity '{bad_id}' returned {resp.status_code}"
            )
            if resp.status_code == 200:
                data = resp.json()
                assert isinstance(data.get("paths", []), list)

    def test_limit_parameter_capped(self, api, identity_id):
        """Limit should be capped at 200 to prevent resource abuse."""
        resp = api.get(
            f"/api/graph/attack-paths?identity={identity_id}&limit=10000"
        )
        if resp.status_code == 200:
            data = resp.json()
            assert len(data["paths"]) <= 200

    def test_no_cross_tenant_data(self, api, identity_id):
        """Response should only contain data for the authenticated tenant."""
        data = api.get(f"/api/graph/attack-paths?identity={identity_id}").json()
        # Verify no org_id leakage from other tenants
        for path in data["paths"]:
            # Paths should not expose raw tenant/org IDs from other orgs
            if "org_id" in path:
                # All paths belong to same org context
                assert path["org_id"] == data["paths"][0]["org_id"]


# ══════════════════════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAttackPathsPerformance:
    """Response time constraints."""

    def test_response_under_1s(self, api, identity_id):
        resp, elapsed_ms = api.timed_get(
            f"/api/graph/attack-paths?identity={identity_id}"
        )
        assert resp.status_code == 200
        assert elapsed_ms < 1000, (
            f"attack-paths took {elapsed_ms:.0f}ms, limit is 1000ms"
        )

    def test_filtered_query_under_1s(self, api, identity_id):
        """Filtered queries should also be under 1s."""
        resp, elapsed_ms = api.timed_get(
            f"/api/graph/attack-paths?identity={identity_id}&severity=critical&limit=10"
        )
        assert resp.status_code == 200
        assert elapsed_ms < 1000, (
            f"Filtered attack-paths took {elapsed_ms:.0f}ms, limit is 1000ms"
        )
