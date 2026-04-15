"""Tests for POST /api/ai/remediation-plan.

Validates AI-generated remediation plans: response structure,
action type safety, priority ordering, and feature gating.
"""

import pytest

from .conftest import VALID_ACTION_TYPES, VALID_SEVERITIES


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def valid_remediation_body():
    return {
        "agirs_score": 35,
        "top_risk_identities": [
            {
                "name": "svc-deploy-prod",
                "identity_name": "svc-deploy-prod",
                "risk_drivers": ["owner_role", "no_mfa", "stale_credentials"],
            },
            {
                "name": "admin-jdoe",
                "identity_name": "John Doe",
                "risk_drivers": ["global_admin", "excessive_permissions"],
            },
        ],
        "attack_paths": [
            "svc-deploy-prod → Owner → Subscription-Prod → Key Vault",
            "admin-jdoe → Global Admin → All Resources",
        ],
        "risk_drivers": [
            "owner_role", "no_mfa", "stale_credentials",
            "global_admin", "excessive_permissions",
        ],
    }


# ══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestRemediationPlanResponse:
    """Validate response schema and content quality."""

    def test_returns_200(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        # 200 success or 403 if feature not enabled (both valid)
        assert resp.status_code in (200, 403), (
            f"Expected 200 or 403, got {resp.status_code}: {resp.text}"
        )

    def test_response_has_required_fields(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled for test tenant")
        data = resp.json()
        required = {"plan_summary", "projected_score", "remediation_actions"}
        missing = required - set(data.keys())
        assert not missing, f"Missing fields: {missing}"

    def test_projected_score_bounded(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        score = data["projected_score"]
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100, f"projected_score {score} out of 0-100 range"

    def test_projected_score_improves(self, api, valid_remediation_body):
        """Projected score should be >= input AGIRS score (improvement)."""
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        assert data["projected_score"] >= valid_remediation_body["agirs_score"], (
            f"Projected {data['projected_score']} < input {valid_remediation_body['agirs_score']}"
        )

    def test_remediation_actions_structure(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        actions = data["remediation_actions"]
        assert isinstance(actions, list)
        assert len(actions) > 0, "Should produce at least one remediation action"
        for action in actions:
            assert "action_type" in action, f"Action missing action_type: {action}"
            assert "title" in action or "description" in action, (
                f"Action missing title/description: {action}"
            )

    def test_action_types_are_valid(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        for action in data["remediation_actions"]:
            assert action["action_type"] in VALID_ACTION_TYPES, (
                f"Invalid action_type: {action['action_type']}. "
                f"Allowed: {VALID_ACTION_TYPES}"
            )

    def test_actions_have_priorities(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        for action in data["remediation_actions"]:
            if "priority" in action:
                assert isinstance(action["priority"], int)
                assert 1 <= action["priority"] <= 5

    def test_plan_summary_is_nonempty(self, api, valid_remediation_body):
        resp = api.post("/api/ai/remediation-plan", json=valid_remediation_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        assert isinstance(data["plan_summary"], str)
        assert len(data["plan_summary"]) > 10, "plan_summary too short"


# ══════════════════════════════════════════════════════════════════════════
# VALIDATION / SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestRemediationPlanValidation:
    """Input validation and security checks."""

    def test_reject_unauthenticated(self, base_url, valid_remediation_body):
        resp = requests.post(
            f"{base_url}/api/ai/remediation-plan",
            json=valid_remediation_body,
        )
        assert resp.status_code in (401, 403)

    def test_reject_empty_body(self, api):
        resp = api.post("/api/ai/remediation-plan", json={})
        assert resp.status_code in (400, 403), (
            f"Empty body should be rejected, got {resp.status_code}"
        )

    def test_reject_missing_agirs_score(self, api):
        resp = api.post("/api/ai/remediation-plan", json={
            "top_risk_identities": [],
            "attack_paths": [],
        })
        assert resp.status_code in (400, 403)

    def test_reject_no_body(self, api):
        resp = api.post("/api/ai/remediation-plan")
        assert resp.status_code in (400, 403, 415)

    def test_rejects_negative_score(self, api):
        resp = api.post("/api/ai/remediation-plan", json={
            "agirs_score": -10,
            "top_risk_identities": [],
        })
        # Should either reject or clamp to 0
        if resp.status_code == 200:
            data = resp.json()
            assert data["projected_score"] >= 0

    def test_handles_extreme_score(self, api):
        resp = api.post("/api/ai/remediation-plan", json={
            "agirs_score": 100,
            "top_risk_identities": [],
        })
        if resp.status_code == 200:
            data = resp.json()
            assert data["projected_score"] <= 100
