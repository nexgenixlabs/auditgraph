"""
Tests for attack path engine fixes:
1. BFS min_depth=1 for PRIVILEGE_ESCALATION (catches direct escalation)
2. trigger_attack_path_analysis uses _latest_run_ids (connection-aware)
3. Scheduler auto-trigger is in post-discovery pipeline
"""
import inspect
import pytest


class TestBfsMinDepth:
    """Verify BFS PRIVILEGE_ESCALATION uses min_depth=1 to catch direct escalation."""

    def test_privilege_escalation_min_depth_is_1(self):
        """The PRIVILEGE_ESCALATION BFS call must specify min_depth=1."""
        from app.engines.graph_attack_engine import GraphAttackEngine
        src = inspect.getsource(GraphAttackEngine._discover_attack_paths)
        # Find the PRIVILEGE_ESCALATION BFS call
        lines = src.split('\n')
        in_priv_esc_block = False
        found_min_depth_1 = False
        for line in lines:
            if 'FINDING_PRIVILEGE_ESCALATION' in line:
                in_priv_esc_block = True
            if in_priv_esc_block and 'min_depth=1' in line:
                found_min_depth_1 = True
                break
            if in_priv_esc_block and ')' in line and 'min_depth' not in line and 'FINDING' not in line:
                # Reached end of call without finding min_depth=1
                break
        assert found_min_depth_1, \
            "PRIVILEGE_ESCALATION BFS must use min_depth=1 to catch direct escalation paths"

    def test_default_min_depth_is_2(self):
        """The _bfs_to_targets default min_depth is 2 (unchanged for other path types)."""
        from app.engines.graph_attack_engine import GraphAttackEngine
        sig = inspect.signature(GraphAttackEngine._bfs_to_targets)
        assert sig.parameters['min_depth'].default == 2


class TestTriggerHandler:
    """Verify trigger_attack_path_analysis uses _latest_run_ids for run selection."""

    def test_trigger_uses_latest_run_ids(self):
        """trigger_attack_path_analysis must call _latest_run_ids for consistent run scoping."""
        from app.api import handlers
        src = inspect.getsource(handlers.trigger_attack_path_analysis)
        assert '_latest_run_ids' in src, \
            "trigger_attack_path_analysis must use _latest_run_ids for run selection"

    def test_trigger_does_not_use_adhoc_run_query(self):
        """Should NOT use ad-hoc 'SELECT id FROM discovery_runs ORDER BY id DESC LIMIT 1'."""
        from app.api import handlers
        src = inspect.getsource(handlers.trigger_attack_path_analysis)
        assert 'ORDER BY id DESC LIMIT 1' not in src, \
            "trigger_attack_path_analysis should use _latest_run_ids, not ad-hoc queries"

    def test_trigger_loops_over_run_ids(self):
        """Should iterate over all run_ids (one per connection), not just a single run."""
        from app.api import handlers
        src = inspect.getsource(handlers.trigger_attack_path_analysis)
        assert 'for run_id in run_ids' in src, \
            "trigger_attack_path_analysis should loop over all connection run_ids"


class TestSchedulerAutoTrigger:
    """Verify attack path analysis is in the post-discovery pipeline."""

    def test_scheduler_calls_attack_path_analysis(self):
        """The scheduler pipeline must include _run_attack_path_analysis."""
        from app import scheduler
        src = inspect.getsource(scheduler)
        assert '_run_attack_path_analysis' in src

    def test_scheduler_tracks_attack_paths_job(self):
        """Attack paths must be tracked via _track_job in the pipeline."""
        from app import scheduler
        src = inspect.getsource(scheduler)
        assert "_track_job('attack_paths'" in src

    def test_scheduler_runs_bfs_after_pattern(self):
        """_run_attack_path_analysis must also invoke BFS engine."""
        from app import scheduler
        src = inspect.getsource(scheduler._run_attack_path_analysis)
        assert '_run_bfs_attack_paths' in src
