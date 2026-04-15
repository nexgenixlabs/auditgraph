"""Tests for POST /api/ai/least-privilege-role.

Validates least-privilege role generation: wildcard rejection,
role definition structure, risk reduction scoring, and safety constraints.
"""

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def valid_lp_body():
    return {
        "identity_id": "svc-deploy-prod-001",
        "current_role": "Contributor",
        "observed_actions": [
            "Microsoft.Storage/storageAccounts/read",
            "Microsoft.Storage/storageAccounts/listKeys/action",
            "Microsoft.KeyVault/vaults/read",
            "Microsoft.KeyVault/vaults/secrets/read",
        ],
        "resource_types": ["Microsoft.Storage/storageAccounts", "Microsoft.KeyVault/vaults"],
        "resource_scope": "/subscriptions/abc-123/resourceGroups/prod-rg",
        "resource_criticality": "high",
    }


@pytest.fixture
def minimal_lp_body():
    return {
        "identity_id": "svc-test",
        "current_role": "Reader",
        "observed_actions": ["Microsoft.Storage/storageAccounts/read"],
    }


# ══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestLeastPrivilegeResponse:
    """Validate response schema and role definition quality."""

    def test_returns_200(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        assert resp.status_code in (200, 403), (
            f"Expected 200 or 403, got {resp.status_code}: {resp.text}"
        )

    def test_response_has_required_fields(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        assert "role_definition" in data
        assert "risk_reduction_score" in data
        assert "privilege_reduction_percent" in data

    def test_role_definition_structure(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        role = resp.json()["role_definition"]
        assert "name" in role, "role_definition missing 'name'"
        assert "actions" in role, "role_definition missing 'actions'"
        assert isinstance(role["actions"], list)
        assert len(role["actions"]) > 0, "Role must define at least one action"

    def test_generated_actions_are_specific(self, api, valid_lp_body):
        """Generated role actions should be specific, not wildcards."""
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        role = resp.json()["role_definition"]
        for action in role["actions"]:
            assert "*" not in action, (
                f"Generated role contains wildcard action: {action}"
            )

    def test_risk_reduction_bounded(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        rr = data["risk_reduction_score"]
        assert isinstance(rr, (int, float))
        assert 0 <= rr <= 100, f"risk_reduction_score {rr} out of range"

    def test_privilege_reduction_bounded(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        pr = data["privilege_reduction_percent"]
        assert isinstance(pr, (int, float))
        assert 0 <= pr <= 100, f"privilege_reduction_percent {pr} out of range"

    def test_assignable_scopes(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        role = resp.json()["role_definition"]
        if "assignableScopes" in role:
            scopes = role["assignableScopes"]
            assert isinstance(scopes, list)
            for scope in scopes:
                assert isinstance(scope, str)
                # Scopes should be ARM paths
                assert scope.startswith("/"), f"Scope not an ARM path: {scope}"

    def test_minimal_request(self, api, minimal_lp_body):
        """Should work with only required fields."""
        resp = api.post("/api/ai/least-privilege-role", json=minimal_lp_body)
        assert resp.status_code in (200, 403)

    def test_analysis_included(self, api, valid_lp_body):
        resp = api.post("/api/ai/least-privilege-role", json=valid_lp_body)
        if resp.status_code == 403:
            pytest.skip("ai_copilot feature not enabled")
        data = resp.json()
        if "analysis" in data:
            assert isinstance(data["analysis"], str)
            assert len(data["analysis"]) > 0


# ══════════════════════════════════════════════════════════════════════════
# SECURITY TESTS — WILDCARD & INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════


class TestLeastPrivilegeSecurity:
    """Wildcard rejection, injection prevention, input validation."""

    def test_reject_unauthenticated(self, base_url, valid_lp_body):
        resp = requests.post(
            f"{base_url}/api/ai/least-privilege-role",
            json=valid_lp_body,
        )
        assert resp.status_code in (401, 403)

    def test_reject_wildcard_star(self, api):
        """Must reject observed_actions containing '*'."""
        resp = api.post("/api/ai/least-privilege-role", json={
            "identity_id": "test",
            "current_role": "Owner",
            "observed_actions": ["*"],
        })
        assert resp.status_code == 400, (
            f"Wildcard '*' should be rejected with 400, got {resp.status_code}"
        )
        data = resp.json()
        assert "wildcard" in data.get("error", "").lower() or "error" in data

    def test_reject_wildcard_in_action(self, api):
        """Reject actions with trailing wildcards like 'Microsoft.Storage/*'."""
        resp = api.post("/api/ai/least-privilege-role", json={
            "identity_id": "test",
            "current_role": "Contributor",
            "observed_actions": [
                "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Compute/*",
            ],
        })
        assert resp.status_code == 400, (
            f"Wildcard 'Microsoft.Compute/*' should be rejected, got {resp.status_code}"
        )

    def test_reject_multiple_wildcards(self, api):
        """All wildcard variants should be rejected."""
        wildcard_actions = [
            ["*/read"],
            ["Microsoft.*/storageAccounts/read"],
            ["Microsoft.Storage/*/read"],
        ]
        for actions in wildcard_actions:
            resp = api.post("/api/ai/least-privilege-role", json={
                "identity_id": "test",
                "current_role": "Owner",
                "observed_actions": actions,
            })
            assert resp.status_code == 400, (
                f"Wildcard action {actions} should be rejected, got {resp.status_code}"
            )

    def test_reject_missing_identity_id(self, api):
        resp = api.post("/api/ai/least-privilege-role", json={
            "current_role": "Reader",
            "observed_actions": ["Microsoft.Storage/storageAccounts/read"],
        })
        assert resp.status_code in (400, 403)

    def test_reject_missing_current_role(self, api):
        resp = api.post("/api/ai/least-privilege-role", json={
            "identity_id": "test",
            "observed_actions": ["Microsoft.Storage/storageAccounts/read"],
        })
        assert resp.status_code in (400, 403)

    def test_reject_non_array_actions(self, api):
        resp = api.post("/api/ai/least-privilege-role", json={
            "identity_id": "test",
            "current_role": "Reader",
            "observed_actions": "Microsoft.Storage/storageAccounts/read",
        })
        assert resp.status_code in (400, 403)

    def test_reject_empty_body(self, api):
        resp = api.post("/api/ai/least-privilege-role", json={})
        assert resp.status_code in (400, 403)

    def test_validate_resource_criticality_values(self, api, valid_lp_body):
        """Only valid criticality levels should be accepted."""
        for criticality in ["critical", "high", "medium", "low"]:
            body = {**valid_lp_body, "resource_criticality": criticality}
            resp = api.post("/api/ai/least-privilege-role", json=body)
            assert resp.status_code in (200, 403), (
                f"Valid criticality '{criticality}' got {resp.status_code}"
            )
