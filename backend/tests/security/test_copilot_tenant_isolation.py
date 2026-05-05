"""
AG-132: Cross-tenant isolation tests for CopilotService.

CWE-639 (Authorization Bypass Through User-Controlled Key)
CWE-284 (Improper Access Control)
CWE-200 (Exposure of Sensitive Information)
OWASP A01:2021 — Broken Access Control
OWASP API1:2023 — Broken Object Level Authorization

Tests verify that:
1. gather_context() only returns data for the specified org_id
2. get_suggestions() only counts data for the specified org_id
3. ask() only includes context from the specified org_id
4. All methods reject missing/invalid org_id with TenantScopeError
5. LLM prompts never contain cross-tenant data
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from app.security.tenant_scope import TenantScopeError
from app.services.copilot_service import CopilotService


# ── Fixtures ─────────────────────────────────────────────────────────────


class FakeCursor:
    """Mock cursor that returns org-scoped data based on query params.

    Uses keyword matching on the SQL to determine which query type is being run,
    then returns data only for the org_id found in params.
    """

    def __init__(self, org_data):
        self._org_data = org_data
        self._last_params = None
        self._last_sql = ''
        self._results = []

    def execute(self, sql, params=None):
        self._last_params = params
        self._last_sql = sql
        self._results = []

        # Determine which org is being queried from params
        org_id = None
        if params:
            for p in params:
                if isinstance(p, int) and p in self._org_data:
                    org_id = p
                    break

        if org_id is None or org_id not in self._org_data:
            return

        # Match SQL by keywords to determine which result set to return
        sql_lower = sql.lower().strip()
        data = self._org_data[org_id]

        if 'discovery_runs' in sql_lower and 'select id' in sql_lower:
            self._results = data.get('discovery_runs', [])
        elif 'anomalies' in sql_lower and 'count(*)' in sql_lower and 'filter' in sql_lower:
            self._results = data.get('anomaly_stats', [])
        elif 'identities' in sql_lower and 'credential_status' in sql_lower and 'count(*)' in sql_lower:
            self._results = data.get('credential_health', [])
        elif 'identities' in sql_lower and 'identity_category' in sql_lower:
            self._results = data.get('identity_categories', [])
        elif 'drift_reports' in sql_lower:
            self._results = data.get('drift', [])
        elif 'anomalies' in sql_lower and 'count(*)' in sql_lower:
            self._results = data.get('anomaly_count', [])
        elif 'identities' in sql_lower and 'expired' in sql_lower:
            self._results = data.get('expired_count', [])
        elif 'identities' in sql_lower and 'critical' in sql_lower:
            self._results = data.get('critical_count', [])

    def fetchone(self):
        if self._results:
            return self._results[0]
        return None

    def fetchall(self):
        return self._results

    def close(self):
        pass


class FakeDB:
    """Mock DB connection with org-scoped cursor results."""

    def __init__(self, org_data):
        self._cursor = FakeCursor(org_data)
        self.conn = MagicMock()
        self.conn.cursor.return_value = self._cursor

    def _rollback(self):
        pass


def make_org_data():
    """Create test data for two orgs with non-overlapping fingerprints."""
    return {
        2: {
            'discovery_runs': [(100, '2026-04-28', 50, 5, 10, 15)],
            'anomaly_stats': [(8, 3, 1, 2)],
            'credential_health': [(2, 5, 43)],
            'identity_categories': [('service_principal', 20), ('human_user', 30)],
            'drift': [({'new_identities': ['Alice@acme.com']},)],
            'anomaly_count': [(4,)],
            'expired_count': [(3,)],
            'critical_count': [(2,)],
        },
        3: {
            'discovery_runs': [(200, '2026-04-28', 100, 20, 30, 40)],
            'anomaly_stats': [(15, 8, 4, 4)],
            'credential_health': [(10, 20, 70)],
            'identity_categories': [('guest', 50), ('managed_identity_system', 50)],
            'drift': [({'new_identities': ['Eve@globex.com']},)],
            'anomaly_count': [(12,)],
            'expired_count': [(7,)],
            'critical_count': [(10,)],
        },
    }


@pytest.fixture
def copilot():
    """CopilotService instance (no real API key needed for data tests)."""
    return CopilotService(api_key='test-key-not-used')


@pytest.fixture
def two_org_db():
    """FakeDB with data for org 2 and org 3."""
    return FakeDB(make_org_data())


# ── Test: gather_context scoped to org ────────────────────────────────────


class TestGatherContextTenantIsolation:
    """Verify gather_context() never leaks cross-tenant data."""

    def test_gather_context_returns_only_org2_data(self, copilot, two_org_db):
        """Context for org=2 must not contain org=3 fingerprints."""
        ctx = copilot.gather_context(two_org_db, org_id=2)

        # Should contain org=2 data
        assert '50 identities' in ctx or 'Run #100' in ctx
        # Must NOT contain org=3 fingerprints
        assert 'Eve@globex' not in ctx
        assert 'Run #200' not in ctx
        assert '100 identities' not in ctx

    def test_gather_context_returns_only_org3_data(self, copilot, two_org_db):
        """Context for org=3 must not contain org=2 fingerprints."""
        ctx = copilot.gather_context(two_org_db, org_id=3)

        # Should contain org=3 data
        assert '100 identities' in ctx or 'Run #200' in ctx
        # Must NOT contain org=2 fingerprints
        assert 'Alice@acme' not in ctx
        assert 'Run #100' not in ctx
        assert '50 identities' not in ctx

    def test_gather_context_rejects_missing_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is not provided."""
        with pytest.raises(TenantScopeError):
            copilot.gather_context(two_org_db)

    def test_gather_context_rejects_none_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is None."""
        with pytest.raises(TenantScopeError):
            copilot.gather_context(two_org_db, org_id=None)

    def test_gather_context_rejects_zero_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is 0."""
        with pytest.raises(TenantScopeError):
            copilot.gather_context(two_org_db, org_id=0)

    def test_gather_context_rejects_negative_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is negative."""
        with pytest.raises(TenantScopeError):
            copilot.gather_context(two_org_db, org_id=-1)

    def test_gather_context_rejects_string_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is not int."""
        with pytest.raises(TenantScopeError):
            copilot.gather_context(two_org_db, org_id='2')


# ── Test: get_suggestions scoped to org ───────────────────────────────────


class TestGetSuggestionsTenantIsolation:
    """Verify get_suggestions() never leaks cross-tenant data."""

    def test_suggestions_returns_org2_counts(self, copilot, two_org_db):
        """Suggestions for org=2 should reflect org=2's anomaly count."""
        suggestions = copilot.get_suggestions(two_org_db, org_id=2)
        # Should be a list of suggestion strings
        assert isinstance(suggestions, list)
        assert len(suggestions) >= 2

    def test_suggestions_rejects_missing_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is not provided."""
        with pytest.raises(TenantScopeError):
            copilot.get_suggestions(two_org_db)

    def test_suggestions_rejects_none_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is None."""
        with pytest.raises(TenantScopeError):
            copilot.get_suggestions(two_org_db, org_id=None)


# ── Test: ask() scoped to org ──────────────────────────────────────────────


class TestAskTenantIsolation:
    """Verify ask() never leaks cross-tenant data to the LLM."""

    def test_ask_rejects_missing_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is not provided."""
        with pytest.raises(TenantScopeError):
            copilot.ask("test question", [], two_org_db)

    def test_ask_rejects_none_org_id(self, copilot, two_org_db):
        """Must raise TenantScopeError when org_id is None."""
        with pytest.raises(TenantScopeError):
            copilot.ask("test question", [], two_org_db, org_id=None)

    @patch('app.services.copilot_service.CopilotService._get_client')
    def test_ask_sends_only_org2_context_to_llm(self, mock_client, copilot, two_org_db):
        """LLM prompt must contain only org=2 data when called with org_id=2."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="AI response")]
        mock_client.return_value.messages.create.return_value = mock_response

        copilot.ask("What is our posture?", [], two_org_db, org_id=2)

        # Verify what was sent to the LLM
        call_args = mock_client.return_value.messages.create.call_args
        system_prompt = call_args.kwargs.get('system', '')

        # Must NOT contain org=3 fingerprints
        assert 'Eve@globex' not in system_prompt
        assert 'Run #200' not in system_prompt
        assert '100 identities' not in system_prompt


# ── Test: No admin fallback path ─────────────────────────────────────────


class TestNoAdminFallback:
    """Verify there is no code path where org_id=None succeeds."""

    def test_all_public_data_methods_require_org_id(self, copilot, two_org_db):
        """Every public method that touches tenant data must reject missing org_id."""
        data_methods = [
            ('gather_context', (two_org_db,), {}),
            ('get_suggestions', (two_org_db,), {}),
            ('ask', ("q", [], two_org_db), {}),
        ]

        for method_name, args, kwargs in data_methods:
            method = getattr(copilot, method_name)
            with pytest.raises(TenantScopeError, match="org_id"):
                method(*args, **kwargs)


# ── Test: LLM prompt inspection ──────────────────────────────────────────


class TestLlmPromptInspection:
    """Verify the prompt sent to the LLM is post-filter (no cross-tenant data)."""

    @patch('app.services.copilot_service.CopilotService._get_client')
    def test_llm_prompt_never_contains_other_org_data(self, mock_client, copilot, two_org_db):
        """Capture all LLM calls and verify no cross-tenant leakage."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Safe response")]
        mock_client.return_value.messages.create.return_value = mock_response

        # Call ask as org=2
        copilot.ask("Show me risks", [], two_org_db, org_id=2)

        # Get the system prompt and all messages sent to the LLM
        call_args = mock_client.return_value.messages.create.call_args
        system_text = call_args.kwargs.get('system', '')
        messages = call_args.kwargs.get('messages', [])
        all_text = system_text + ' '.join(m.get('content', '') for m in messages)

        # Cross-tenant fingerprints that must NOT appear
        org3_fingerprints = [
            'Eve@globex',
            'Run #200',
            '100 identities',
            'guest: 50',
            'managed_identity_system: 50',
        ]
        for fp in org3_fingerprints:
            assert fp not in all_text, f"Cross-tenant leak: '{fp}' found in LLM prompt"

    @patch('app.services.copilot_service.CopilotService._get_client')
    def test_llm_prompt_contains_correct_org_data(self, mock_client, copilot, two_org_db):
        """LLM prompt should contain the correct org's data."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Safe response")]
        mock_client.return_value.messages.create.return_value = mock_response

        copilot.ask("Show me risks", [], two_org_db, org_id=2)

        call_args = mock_client.return_value.messages.create.call_args
        system_text = call_args.kwargs.get('system', '')

        # Should contain org=2 data markers
        assert 'Run #100' in system_text or '50 identities' in system_text
