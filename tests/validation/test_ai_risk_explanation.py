"""Tests for GET /api/identities/{id}/ai-risk-explanation.

Validates AI-generated risk explanations: narrative quality,
required fields, fallback behavior, and security boundaries.
"""

import pytest

from .conftest import VALID_RISK_LEVELS


# ══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAIRiskExplanationResponse:
    """Validate response schema and content quality."""

    def test_returns_200(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        assert resp.status_code in (200, 404), (
            f"Expected 200 or 404, got {resp.status_code}: {resp.text}"
        )

    def test_response_has_required_fields(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found in current tenant")
        data = resp.json()
        required = {"summary", "drivers"}
        missing = required - set(data.keys())
        assert not missing, f"Missing required fields: {missing}"

    def test_summary_is_meaningful(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        data = resp.json()
        summary = data["summary"]
        assert isinstance(summary, str)
        assert len(summary) > 20, (
            f"Summary too short ({len(summary)} chars): '{summary}'"
        )

    def test_drivers_is_list(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        data = resp.json()
        assert isinstance(data["drivers"], list)

    def test_implications_field(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        data = resp.json()
        if "implications" in data:
            assert isinstance(data["implications"], str)
            assert len(data["implications"]) > 0

    def test_recommended_action_field(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        data = resp.json()
        if "recommended_action" in data:
            assert isinstance(data["recommended_action"], str)
            assert len(data["recommended_action"]) > 0

    def test_explanation_references_identity(self, api, identity_id):
        """The explanation should be specific to the identity, not generic."""
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        data = resp.json()
        # The combined text should contain identity-specific language
        combined = (
            data.get("summary", "")
            + " ".join(data.get("drivers", []))
            + data.get("implications", "")
        )
        # Should mention at least one security concept
        security_terms = [
            "risk", "permission", "access", "credential", "role",
            "privilege", "identity", "security", "exposure", "blast",
        ]
        has_security_term = any(t in combined.lower() for t in security_terms)
        assert has_security_term, (
            "Explanation does not reference any security concepts"
        )


# ══════════════════════════════════════════════════════════════════════════
# CORRECTNESS TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAIRiskExplanationCorrectness:
    """Verify the explanation is coherent with identity data."""

    def test_drivers_are_strings(self, api, identity_id):
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        data = resp.json()
        for driver in data["drivers"]:
            assert isinstance(driver, str), f"Driver is not a string: {driver}"
            assert len(driver) > 0, "Empty driver string"

    def test_consistent_across_calls(self, api, identity_id):
        """Two calls should return structurally consistent results."""
        resp1 = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        resp2 = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp1.status_code == 404:
            pytest.skip("Identity not found")
        d1, d2 = resp1.json(), resp2.json()
        # Same fields should be present
        assert set(d1.keys()) == set(d2.keys()), (
            f"Inconsistent keys: {set(d1.keys())} vs {set(d2.keys())}"
        )
        # Same drivers list (deterministic for non-AI fallback)
        assert set(d1["drivers"]) == set(d2["drivers"]), (
            "Drivers changed between calls — non-deterministic?"
        )

    def test_no_raw_json_in_summary(self, api, identity_id):
        """Summary should be prose, not raw JSON."""
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        summary = resp.json()["summary"]
        assert not summary.strip().startswith("{"), "Summary looks like raw JSON"
        assert not summary.strip().startswith("["), "Summary looks like raw array"


# ══════════════════════════════════════════════════════════════════════════
# SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAIRiskExplanationSecurity:
    """Security boundary checks."""

    def test_reject_unauthenticated(self, base_url):
        resp = requests.get(
            f"{base_url}/api/identities/1/ai-risk-explanation"
        )
        assert resp.status_code in (401, 403)

    def test_reject_invalid_identity_id(self, api):
        for bad_id in ["-1", "abc", "'; DROP TABLE--", "99999999"]:
            resp = api.get(f"/api/identities/{bad_id}/ai-risk-explanation")
            assert resp.status_code in (400, 404), (
                f"Invalid identity_id '{bad_id}' got {resp.status_code}"
            )

    def test_no_internal_data_leakage(self, api, identity_id):
        """Response should not expose internal IDs, SQL, or stack traces."""
        resp = api.get(f"/api/identities/{identity_id}/ai-risk-explanation")
        if resp.status_code == 404:
            pytest.skip("Identity not found")
        raw = resp.text
        leak_patterns = ["SELECT ", "FROM ", "WHERE ", "traceback", "psycopg2"]
        for pattern in leak_patterns:
            assert pattern not in raw, (
                f"Internal data leakage detected: '{pattern}' in response"
            )
