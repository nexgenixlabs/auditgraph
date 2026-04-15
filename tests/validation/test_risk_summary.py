"""Tests for GET /api/identities/{id}/risk-summary.

Validates identity risk scoring response structure, field constraints,
error handling, and performance.
"""

import pytest

from .conftest import (
    VALID_ACTIVITY_STATUSES,
    VALID_IDENTITY_CATEGORIES,
    VALID_RISK_LEVELS,
    VALID_SEVERITIES,
)


# ══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestRiskSummaryResponse:
    """Validate response schema and field values."""

    def test_returns_200(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/risk-summary")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    def test_response_has_required_fields(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        required = {
            "identity_id", "identity_name", "identity_category",
            "risk_level", "risk_score", "risk_drivers", "recommended_actions",
        }
        missing = required - set(data.keys())
        assert not missing, f"Missing required fields: {missing}"

    def test_risk_score_is_bounded(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        score = data["risk_score"]
        assert isinstance(score, (int, float)), f"risk_score is {type(score)}"
        assert 0 <= score <= 100, f"risk_score {score} out of 0-100 range"

    def test_risk_level_is_valid(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        assert data["risk_level"] in VALID_RISK_LEVELS, (
            f"Invalid risk_level: {data['risk_level']}"
        )

    def test_identity_category_is_valid(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        assert data["identity_category"] in VALID_IDENTITY_CATEGORIES, (
            f"Invalid identity_category: {data['identity_category']}"
        )

    def test_activity_status_is_valid(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        if "activity_status" in data and data["activity_status"] is not None:
            assert data["activity_status"] in VALID_ACTIVITY_STATUSES

    def test_risk_drivers_structure(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        drivers = data["risk_drivers"]
        assert isinstance(drivers, list), "risk_drivers must be a list"
        for d in drivers:
            assert "driver" in d, f"risk_driver missing 'driver' key: {d}"
            assert "severity" in d, f"risk_driver missing 'severity' key: {d}"
            assert d["severity"] in VALID_SEVERITIES, (
                f"Invalid driver severity: {d['severity']}"
            )

    def test_recommended_actions_structure(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        actions = data["recommended_actions"]
        assert isinstance(actions, list), "recommended_actions must be a list"
        for a in actions:
            assert "priority" in a, f"action missing 'priority': {a}"
            assert "action" in a, f"action missing 'action': {a}"

    def test_blast_radius_bounded(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        if "blast_radius_score" in data and data["blast_radius_score"] is not None:
            br = data["blast_radius_score"]
            assert 0 <= br <= 100, f"blast_radius_score {br} out of range"

    def test_privilege_tier_bounded(self, api, identity_id):
        data = api.get(f"/api/identities/{identity_id}/risk-summary").json()
        if "privilege_tier" in data and data["privilege_tier"] is not None:
            pt = data["privilege_tier"]
            assert pt in (0, 1, 2, 3), f"Invalid privilege_tier: {pt}"


# ══════════════════════════════════════════════════════════════════════════
# SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestRiskSummarySecurity:
    """Security boundary checks."""

    def test_reject_unauthenticated(self, base_url):
        resp = requests.get(f"{base_url}/api/identities/1/risk-summary")
        assert resp.status_code in (401, 403), (
            f"Unauthenticated request should be rejected, got {resp.status_code}"
        )

    def test_reject_invalid_identity_id(self, api):
        for bad_id in ["0", "-1", "abc", "'; DROP TABLE--", "99999999"]:
            resp = api.get(f"/api/identities/{bad_id}/risk-summary")
            assert resp.status_code in (400, 404), (
                f"Invalid identity_id '{bad_id}' got {resp.status_code}"
            )

    def test_reject_path_traversal(self, api):
        resp = api.get("/api/identities/../../etc/passwd/risk-summary")
        assert resp.status_code in (400, 404), (
            f"Path traversal attempt got {resp.status_code}"
        )


# ══════════════════════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestRiskSummaryPerformance:
    """Response time constraints."""

    def test_response_under_500ms(self, api, identity_id):
        resp, elapsed_ms = api.timed_get(
            f"/api/identities/{identity_id}/risk-summary"
        )
        assert resp.status_code == 200
        assert elapsed_ms < 500, (
            f"risk-summary took {elapsed_ms:.0f}ms, limit is 500ms"
        )

    def test_consistent_performance_3_calls(self, api, identity_id):
        """Three sequential calls should all be under 500ms."""
        times = []
        for _ in range(3):
            resp, elapsed_ms = api.timed_get(
                f"/api/identities/{identity_id}/risk-summary"
            )
            assert resp.status_code == 200
            times.append(elapsed_ms)

        avg = sum(times) / len(times)
        assert avg < 500, (
            f"Average response time {avg:.0f}ms exceeds 500ms (times: {[f'{t:.0f}' for t in times]})"
        )
