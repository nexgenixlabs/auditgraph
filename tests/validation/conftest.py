"""Shared fixtures for AuditGraph API validation tests.

Configuration via environment variables:
    AUDITGRAPH_BASE_URL   - API base URL (default: http://localhost:5001)
    AUDITGRAPH_API_TOKEN  - JWT Bearer token for authentication
    AUDITGRAPH_IDENTITY_ID - A valid identity DB id for testing (default: 1)
"""

import os
import time

import pytest
import requests


# ── Configuration ─────────────────────────────────────────────────────────

BASE_URL = os.getenv("AUDITGRAPH_BASE_URL", "http://localhost:5001").rstrip("/")
API_TOKEN = os.getenv("AUDITGRAPH_API_TOKEN", "")
IDENTITY_ID = os.getenv("AUDITGRAPH_IDENTITY_ID", "1")


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def auth_headers():
    """Standard auth headers for all requests."""
    if not API_TOKEN:
        pytest.skip("AUDITGRAPH_API_TOKEN not set")
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
    }


@pytest.fixture(scope="session")
def identity_id():
    """A valid identity ID for testing (path parameter)."""
    return IDENTITY_ID


@pytest.fixture(scope="session")
def api(base_url, auth_headers):
    """Convenience wrapper around requests with auth + base URL."""
    return APIClient(base_url, auth_headers)


class APIClient:
    """Thin wrapper that auto-injects base URL and auth headers."""

    def __init__(self, base_url: str, headers: dict):
        self.base_url = base_url
        self.headers = headers
        self.session = requests.Session()
        self.session.headers.update(headers)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(f"{self.base_url}{path}", **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", **kwargs)

    def timed_get(self, path: str, **kwargs) -> tuple[requests.Response, float]:
        """GET with elapsed time in milliseconds."""
        start = time.perf_counter()
        resp = self.get(path, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return resp, elapsed_ms

    def timed_post(self, path: str, **kwargs) -> tuple[requests.Response, float]:
        """POST with elapsed time in milliseconds."""
        start = time.perf_counter()
        resp = self.post(path, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return resp, elapsed_ms


# ── Helpers ───────────────────────────────────────────────────────────────

VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "info"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_ACTION_TYPES = {
    "flag_for_review",
    "create_ticket",
    "disable_identity",
    "remove_role",
    "rotate_credential",
}
VALID_IDENTITY_CATEGORIES = {
    "service_principal",
    "managed_identity_system",
    "managed_identity_user",
    "human_user",
    "guest",
    "microsoft_internal",
}
VALID_ACTIVITY_STATUSES = {
    "active", "inactive", "stale", "never_used",
    "recently_created", "unknown",
}
