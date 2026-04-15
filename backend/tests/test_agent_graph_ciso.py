"""
Phase 3: AI Agent Graph + CISO Tile — QA Tests

Tests node types, blast radius, delegation, CISO summary, and feature flag gating.
Pure function tests + schema checks — no database required.
"""

import pytest
from datetime import datetime, timezone


# =====================================================================
# Test 1 — Graph node type registration
# =====================================================================

class TestGraphNodeType:
    """Verify ai_agent node type is available in the graph system."""

    def test_agent_graph_info_lookup_exists(self):
        """The graph-data handler must look up agent_classifications."""
        import inspect
        from app.api.handlers import get_identity_graph_data
        src = inspect.getsource(get_identity_graph_data)
        assert 'agent_graph_info' in src
        assert 'ai_agent' in src

    def test_center_node_type_variable_exists(self):
        """The handler uses _center_node_type for conditional node type selection."""
        import inspect
        from app.api.handlers import get_identity_graph_data
        src = inspect.getsource(get_identity_graph_data)
        assert '_center_node_type' in src

    def test_agent_info_in_response(self):
        """The graph-data response includes agent_info when available."""
        import inspect
        from app.api.handlers import get_identity_graph_data
        src = inspect.getsource(get_identity_graph_data)
        assert 'agent_info' in src


# =====================================================================
# Test 2 — Blast radius API
# =====================================================================

class TestBlastRadiusAPI:
    """Verify agent blast radius endpoint exists and is properly gated."""

    def test_handler_exists(self):
        """get_agent_blast_radius handler must exist."""
        from app.api.handlers import get_agent_blast_radius
        assert callable(get_agent_blast_radius)

    def test_handler_checks_feature_flag(self):
        """Handler must check FEATURE_AI_AGENT_GOVERNANCE."""
        import inspect
        from app.api.handlers import get_agent_blast_radius
        src = inspect.getsource(get_agent_blast_radius)
        assert 'FEATURE_AI_AGENT_GOVERNANCE' in src

    def test_handler_returns_same_shape(self):
        """Handler response includes standard blast radius fields."""
        import inspect
        from app.api.handlers import get_agent_blast_radius
        src = inspect.getsource(get_agent_blast_radius)
        assert 'reachable_resource_count' in src
        assert 'reachable_subscription_count' in src
        assert 'identity_exposure_level' in src

    def test_combined_blast_radius_support(self):
        """Handler computes combined blast radius for delegations."""
        import inspect
        from app.api.handlers import get_agent_blast_radius
        src = inspect.getsource(get_agent_blast_radius)
        assert 'combined_blast_radius' in src
        assert 'delegations' in src


# =====================================================================
# Test 3 — Agent delegation
# =====================================================================

class TestAgentDelegation:
    """Verify delegation edge infrastructure."""

    def test_delegation_table_in_ddl(self):
        """agent_delegations table must be created in DDL."""
        import inspect
        from app.database import Database
        src = inspect.getsource(Database._ensure_agent_classifications_table)
        assert 'agent_delegations' in src
        assert 'source_identity_db_id' in src
        assert 'target_identity_db_id' in src
        assert 'delegation_type' in src

    def test_db_methods_exist(self):
        """Database must have delegation CRUD methods."""
        from app.database import Database
        assert hasattr(Database, 'upsert_agent_delegation')
        assert hasattr(Database, 'get_agent_delegations')
        assert hasattr(Database, 'delete_agent_delegation')

    def test_delegation_handlers_exist(self):
        """Delegation API handlers must exist."""
        from app.api.handlers import get_agent_delegations
        from app.api.handlers import manage_agent_delegation
        from app.api.handlers import delete_agent_delegation
        assert callable(get_agent_delegations)
        assert callable(manage_agent_delegation)
        assert callable(delete_agent_delegation)

    def test_self_delegation_rejected(self):
        """manage_agent_delegation source must check source != target."""
        import inspect
        from app.api.handlers import manage_agent_delegation
        src = inspect.getsource(manage_agent_delegation)
        assert 'Cannot delegate to self' in src


# =====================================================================
# Test 4 — CISO tile endpoint
# =====================================================================

class TestCISOTile:
    """Verify CISO dashboard agent risk summary endpoint."""

    def test_handler_exists(self):
        """get_agent_risk_summary handler must exist."""
        from app.api.handlers import get_agent_risk_summary
        assert callable(get_agent_risk_summary)

    def test_response_shape(self):
        """Handler response must include all 4 metrics."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        src = inspect.getsource(get_agent_risk_summary)
        assert 'total_agents' in src
        assert 'avg_agirs' in src
        assert 'critical_orphans' in src
        assert 'highest_risk_agent' in src

    def test_feature_flag_gating(self):
        """Handler must check FEATURE_AI_AGENT_GOVERNANCE."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        src = inspect.getsource(get_agent_risk_summary)
        assert 'FEATURE_AI_AGENT_GOVERNANCE' in src

    def test_orphan_finding_type_query(self):
        """Handler must query security_findings for orphaned_ai_agent_spn."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        src = inspect.getsource(get_agent_risk_summary)
        assert 'orphaned_ai_agent_spn' in src


# =====================================================================
# Test 5 — Feature flag controls all Phase 3 features
# =====================================================================

class TestFeatureFlag:
    """Verify feature flag gates all new functionality."""

    def test_flag_exists(self):
        """FEATURE_AI_AGENT_GOVERNANCE must be defined in config."""
        from app.config import FEATURE_AI_AGENT_GOVERNANCE
        assert FEATURE_AI_AGENT_GOVERNANCE is not None

    def test_blast_radius_gated(self):
        """Agent blast radius handler checks feature flag."""
        import inspect
        from app.api.handlers import get_agent_blast_radius
        src = inspect.getsource(get_agent_blast_radius)
        assert 'FEATURE_AI_AGENT_GOVERNANCE' in src

    def test_delegation_gated(self):
        """Delegation handlers check feature flag."""
        import inspect
        from app.api.handlers import get_agent_delegations
        src = inspect.getsource(get_agent_delegations)
        assert 'FEATURE_AI_AGENT_GOVERNANCE' in src

    def test_ciso_tile_gated(self):
        """CISO tile handler checks feature flag."""
        import inspect
        from app.api.handlers import get_agent_risk_summary
        src = inspect.getsource(get_agent_risk_summary)
        assert 'FEATURE_AI_AGENT_GOVERNANCE' in src

    def test_graph_node_gated(self):
        """Graph node type selection checks feature flag."""
        import inspect
        from app.api.handlers import get_identity_graph_data
        src = inspect.getsource(get_identity_graph_data)
        assert 'FEATURE_AI_AGENT_GOVERNANCE' in src


# =====================================================================
# Test 6 — Route registration
# =====================================================================

class TestRouteRegistration:
    """Verify all Phase 3 routes are registered in main.py."""

    def test_routes_in_main(self):
        """All new routes must be registered."""
        import inspect
        from app.main import create_app
        src = inspect.getsource(create_app)
        assert '/api/dashboard/agent-risk-summary' in src
        assert '/api/agent-identities/<identity_id>/blast-radius' in src
        assert '/api/agent-identities/delegations' in src
        assert '/api/agent-identities/scan-orphans' in src


# =====================================================================
# Test 7 — Orphan detector integration (from Phase 2, regression)
# =====================================================================

class TestOrphanDetectorRegression:
    """Ensure Phase 2 orphan detection still works after Phase 3 changes."""

    def test_detector_import(self):
        """AgentOrphanDetector must be importable."""
        from app.engines.agent_orphan_detector import AgentOrphanDetector
        assert AgentOrphanDetector is not None

    def test_finding_type_unchanged(self):
        """FINDING_TYPE constant must not have changed."""
        from app.engines.agent_orphan_detector import FINDING_TYPE
        assert FINDING_TYPE == 'orphaned_ai_agent_spn'

    def test_is_orphaned_still_works(self):
        """Phase 2 is_orphaned function works after Phase 3 additions."""
        from app.engines.agent_orphan_detector import AgentOrphanDetector
        assert AgentOrphanDetector.is_orphaned('ai_agent', 31, True, None, ['Owner']) is True
        assert AgentOrphanDetector.is_orphaned('ai_agent', 29, True, None, ['Owner']) is False

    def test_scheduler_hook_exists(self):
        """Scheduler must call _run_agent_orphan_detection."""
        import inspect
        import app.scheduler as sched
        src = inspect.getsource(sched)
        assert '_run_agent_orphan_detection' in src
        assert 'agent_orphan_detection' in src


# =====================================================================
# Test 8 — Performance: index exists
# =====================================================================

class TestPerformance:
    """Verify performance optimizations are in place."""

    def test_agent_type_index(self):
        """Partial index on identities.agent_identity_type must exist in DDL."""
        import inspect
        from app.database import Database
        src = inspect.getsource(Database._ensure_agent_classifications_table)
        assert 'idx_identities_agent_identity_type' in src

    def test_delegation_indexes(self):
        """Delegation table must have source and target indexes."""
        import inspect
        from app.database import Database
        src = inspect.getsource(Database._ensure_agent_classifications_table)
        assert 'idx_agent_deleg_source' in src
        assert 'idx_agent_deleg_target' in src
