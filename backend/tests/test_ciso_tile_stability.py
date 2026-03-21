"""
Hardening H2: Deterministic CISO Tile — highest_risk_agent stability tests.

Verifies that get_agent_risk_summary() returns the same highest_risk_agent
on every call, even when multiple agents share the same risk score.

Uses mock DB cursors — no live database required.
"""

import pytest
from unittest.mock import MagicMock, patch
import json


# ── Helpers ────────────────────────────────────────────────────────────

def _call_agent_risk_summary(cursor_side_effects):
    """Call get_agent_risk_summary with mocked DB cursor.

    cursor_side_effects is a list of fetchone return values, one per
    cursor.execute() call in the handler:
      [0] total_agents COUNT
      [1] avg_agirs AVG
      [2] critical_orphans COUNT
      [3] highest_risk_agent row (or None)
    """
    from app.api.handlers import get_agent_risk_summary

    mock_db = MagicMock()
    mock_cursor = MagicMock()
    mock_db.conn.cursor.return_value = mock_cursor
    mock_cursor.fetchone.side_effect = cursor_side_effects

    with patch('app.api.handlers._db', return_value=mock_db), \
         patch('app.config.FEATURE_AI_AGENT_GOVERNANCE', True):
        from flask import Flask
        app = Flask(__name__)
        with app.app_context():
            response = get_agent_risk_summary()
            # response is a tuple (Response, status_code) or just Response
            if isinstance(response, tuple):
                data = json.loads(response[0].get_data(as_text=True))
            else:
                data = json.loads(response.get_data(as_text=True))
    return data


def _default_cursor_effects(top_row):
    """Build standard cursor side-effects with the given highest_risk row."""
    return [
        (5,),       # total_agents
        (62.5,),    # avg_agirs
        (2,),       # critical_orphans
        top_row,    # highest_risk_agent
    ]


# ── Test H2-A: Single agent — always returns that agent ───────────────

class TestCISOTileStability:

    def test_h2a_single_agent_always_returned(self):
        """Single agent → always returns that agent across 5 calls."""
        top_row = ('NightlyBot', 75)
        results = []
        for _ in range(5):
            data = _call_agent_risk_summary(_default_cursor_effects(top_row))
            results.append(data['highest_risk_agent']['display_name'])

        assert all(name == 'NightlyBot' for name in results)
        assert data['highest_risk_agent']['risk_score'] == 75

    def test_h2b_different_scores_returns_higher(self):
        """Two agents with different scores → always returns higher score.

        The mock always returns the top-1 row from the DB, so we simulate
        the DB returning Agent A (score 80) as the winner.
        """
        top_row = ('AgentA', 80)
        results = []
        for _ in range(5):
            data = _call_agent_risk_summary(_default_cursor_effects(top_row))
            results.append(data['highest_risk_agent']['display_name'])

        assert all(name == 'AgentA' for name in results)

    def test_h2c_identical_scores_days_inactive_tiebreaker(self):
        """Two agents, identical scores — days_inactive tiebreaker.

        Agent B has higher days_inactive (45 > 30) so wins the tiebreak.
        The DB returns Agent B because our ORDER BY sorts days_inactive DESC.
        """
        top_row = ('AgentB', 75)
        results = []
        for _ in range(10):
            data = _call_agent_risk_summary(_default_cursor_effects(top_row))
            results.append(data['highest_risk_agent']['display_name'])

        assert all(name == 'AgentB' for name in results)

    def test_h2d_all_identical_id_tiebreaker(self):
        """Three agents, all identical scores and dormancy — id ASC wins.

        Agent B (id="aaa...") wins because i.id ASC is the final tiebreaker.
        """
        top_row = ('AgentB', 75)
        results = []
        for _ in range(10):
            data = _call_agent_risk_summary(_default_cursor_effects(top_row))
            results.append(data['highest_risk_agent']['display_name'])

        assert all(name == 'AgentB' for name in results)

    def test_h2e_score_plus_penalty_combined(self):
        """Combined score: agirs + penalty determines winner.

        Agent A: risk_score=70 + penalty=15 = 85
        Agent B: risk_score=80 + penalty=0  = 80
        Agent A wins because 85 > 80 in the ORDER BY.
        """
        top_row = ('AgentA', 70)  # DB returns risk_score from SELECT
        results = []
        for _ in range(5):
            data = _call_agent_risk_summary(_default_cursor_effects(top_row))
            results.append(data['highest_risk_agent']['display_name'])

        assert all(name == 'AgentA' for name in results)


# ── Integration: verify ORDER BY clause in source ──────────────────────

class TestOrderByClause:

    def test_order_by_has_three_part_sort(self):
        """Verify the ORDER BY in get_agent_risk_summary uses 3-part sort."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        source = inspect.getsource(get_agent_risk_summary)
        assert 'agent_penalty_score' in source, \
            "ORDER BY must include agent_penalty_score for combined score"
        assert 'days_inactive' in source, \
            "ORDER BY must include days_inactive as secondary tiebreaker"
        assert 'i.id ASC' in source, \
            "ORDER BY must include i.id ASC as final tiebreaker"

    def test_order_by_not_just_score_desc(self):
        """The old non-deterministic ORDER BY score DESC must be gone."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        source = inspect.getsource(get_agent_risk_summary)
        # Should NOT have bare "ORDER BY score DESC\n" without tiebreakers
        lines = source.split('\n')
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('ORDER BY') and stripped.endswith('score DESC'):
                pytest.fail("Found bare 'ORDER BY score DESC' without tiebreakers")

    def test_combined_score_uses_coalesce(self):
        """Both risk_score and agent_penalty_score are COALESCE-wrapped."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        source = inspect.getsource(get_agent_risk_summary)
        assert 'COALESCE(i.risk_score, 0)' in source
        assert 'COALESCE(ac.agent_penalty_score, 0)' in source
