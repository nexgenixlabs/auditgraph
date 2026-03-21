"""
Phase 2: Orphaned AI Agent SPN Detection — QA Tests (30 scenarios)

Tests the static is_orphaned() and _has_elevated_role() methods directly.
Pure functions — no database required.

Scenarios 1–20: Original true positive / true negative tests.
Scenarios 21–30: Client credential (servicePrincipalSignIn) tests.
"""

import pytest
from datetime import datetime, timezone, timedelta

from app.engines.agent_orphan_detector import (
    AgentOrphanDetector,
    FINDING_TYPE,
    FINDING_CODE,
    ORPHAN_INACTIVE_DAYS,
    AGIRS_PENALTY_SCORE,
    _ELEVATED_RBAC_ROLES,
    _WRITE_ROLE_TOKENS,
)
from app.engines.security_findings import compute_finding_fingerprint


def _compute_effective_days_inactive(interactive_sign_in, sp_sign_in):
    """Helper: compute days_inactive using the same dual-source logic as the detector."""
    now = datetime.now(timezone.utc)
    candidates = [t for t in [interactive_sign_in, sp_sign_in] if t is not None]
    last_active = max(candidates) if candidates else None
    if last_active is None:
        return None  # maps to 999 in the detector
    return (now - last_active).days


def _compute_activity_source(interactive_sign_in, sp_sign_in):
    """Helper: compute activity_detection_source."""
    candidates = [t for t in [interactive_sign_in, sp_sign_in] if t is not None]
    last_active = max(candidates) if candidates else None
    if sp_sign_in and sp_sign_in == last_active:
        return "service_principal_sign_in"
    elif interactive_sign_in and interactive_sign_in == last_active:
        return "interactive_sign_in"
    else:
        return "no_activity_recorded"


# =====================================================================
# True Positives — Should be detected as orphaned (10 scenarios)
# =====================================================================

class TestTruePositives:
    """Identities that SHOULD be flagged as orphaned AI agent SPNs."""

    def test_01_ai_agent_31d_owner(self):
        """ai_agent inactive 31 days with Owner role."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=31,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True

    def test_02_ai_agent_90d_contributor(self):
        """ai_agent inactive 90 days with Contributor role."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=90,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Contributor'],
        ) is True

    def test_03_ai_agent_never_signed_in_owner(self):
        """ai_agent that never signed in with Owner role."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=None,  # never signed in
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True

    def test_04_ai_agent_45d_custom_write_role(self):
        """ai_agent inactive 45 days with custom write role."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=45,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Custom Data Write Role'],
        ) is True

    def test_05_ai_agent_35d_uaa(self):
        """ai_agent inactive 35 days with User Access Administrator."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=35,
            enabled=True,
            deleted_at=None,
            rbac_roles=['User Access Administrator'],
        ) is True

    def test_06_possible_agent_60d_contributor(self):
        """possible_ai_agent inactive 60 days with Contributor role."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='possible_ai_agent',
            days_inactive=60,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Contributor'],
        ) is True

    def test_07_ai_agent_31d_reader_plus_contributor(self):
        """ai_agent with Reader + Contributor — Contributor elevates."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=31,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Reader', 'Contributor'],
        ) is True

    def test_08_ai_agent_200d_reader_plus_owner(self):
        """ai_agent inactive 200 days with Reader + Owner."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=200,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Reader', 'Owner'],
        ) is True

    def test_09_ai_agent_32d_owner_sub_scope(self):
        """ai_agent inactive 32 days with Owner at subscription scope."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=32,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True

    def test_10_ai_agent_never_signed_in_multi_contributor(self):
        """ai_agent never signed in with Contributor across 5 RGs."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=None,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Contributor', 'Contributor', 'Contributor',
                        'Contributor', 'Contributor'],
        ) is True


# =====================================================================
# True Negatives — Should NOT be detected as orphaned (10 scenarios)
# =====================================================================

class TestTrueNegatives:
    """Identities that should NOT be flagged as orphaned."""

    def test_11_ai_agent_29d_owner_below_threshold(self):
        """ai_agent inactive only 29 days — below 30-day threshold."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=29,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_12_ai_agent_60d_reader_only(self):
        """ai_agent inactive 60 days but only Reader — not elevated."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=60,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Reader'],
        ) is False

    def test_13_unknown_60d_owner(self):
        """unknown classification with Owner — not an agent."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='unknown',
            days_inactive=60,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_14_ai_agent_0d_owner_active(self):
        """ai_agent active yesterday with Owner — recently active."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=0,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_15_ai_agent_60d_owner_disabled(self):
        """ai_agent inactive 60 days with Owner but DISABLED."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=60,
            enabled=False,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_16_ai_agent_60d_no_roles(self):
        """ai_agent inactive 60 days but no role assignments."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=60,
            enabled=True,
            deleted_at=None,
            rbac_roles=[],
        ) is False

    def test_17_not_agent_60d_owner(self):
        """Non-agent type 'unknown' should not be flagged."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='unknown',
            days_inactive=60,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_18_ai_agent_60d_reader_not_elevated(self):
        """ai_agent inactive 60 days with Reader — read-only, not elevated."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=60,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Reader'],
        ) is False

    def test_19_ai_agent_30d_exactly_owner_boundary(self):
        """ai_agent inactive exactly 30 days — boundary: need >30."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=30,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_20_ai_agent_30d_exactly_contributor_boundary(self):
        """ai_agent inactive exactly 30 days with Contributor — boundary."""
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=30,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Contributor'],
        ) is False


# =====================================================================
# Elevated Role Detection Tests
# =====================================================================

class TestElevatedRoleDetection:
    """Test _has_elevated_role() static method."""

    def test_named_elevated_roles(self):
        """All 3 named elevated roles should be detected."""
        for role in _ELEVATED_RBAC_ROLES:
            assert AgentOrphanDetector._has_elevated_role([role]) is True

    def test_custom_write_tokens(self):
        """Custom roles with write tokens should be elevated."""
        for token in _WRITE_ROLE_TOKENS:
            role_name = f'Custom {token.capitalize()} Role'
            assert AgentOrphanDetector._has_elevated_role([role_name]) is True, \
                f"Role '{role_name}' should be elevated"

    def test_reader_not_elevated(self):
        """Reader role is not elevated."""
        assert AgentOrphanDetector._has_elevated_role(['Reader']) is False

    def test_empty_roles_not_elevated(self):
        """Empty role list is not elevated."""
        assert AgentOrphanDetector._has_elevated_role([]) is False

    def test_none_roles_not_elevated(self):
        """None role list is not elevated."""
        assert AgentOrphanDetector._has_elevated_role(None) is False

    def test_mixed_roles_elevated(self):
        """Mix of Reader + Owner should be elevated (Owner matches)."""
        assert AgentOrphanDetector._has_elevated_role(['Reader', 'Owner']) is True


# =====================================================================
# Finding Shape Tests
# =====================================================================

class TestFindingShape:
    """Verify the structure of generated findings."""

    def test_finding_has_required_fields(self):
        """Finding dict must have all fields for save_security_findings()."""
        finding = AgentOrphanDetector._build_finding(
            entity_id='test-entity-id',
            display_name='TestBot',
            detected_platform='copilot_studio',
            days_inactive=45,
            rbac_roles=['Owner'],
        )
        required = [
            'finding_type', 'entity_type', 'entity_id', 'severity',
            'risk_score', 'title', 'description', 'recommended_fix',
            'metadata', 'finding_fingerprint', 'identity_name',
        ]
        for field in required:
            assert field in finding, f"Missing field: {field}"

    def test_finding_type_is_correct(self):
        """Finding type must be FINDING_TYPE constant."""
        finding = AgentOrphanDetector._build_finding(
            entity_id='x', display_name='X',
            detected_platform=None, days_inactive=31, rbac_roles=['Owner'],
        )
        assert finding['finding_type'] == FINDING_TYPE

    def test_finding_fingerprint_is_deterministic(self):
        """Same entity_id + finding_type must produce same fingerprint."""
        f1 = AgentOrphanDetector._build_finding(
            entity_id='abc-123', display_name='Bot1',
            detected_platform='test', days_inactive=50, rbac_roles=['Owner'],
        )
        f2 = AgentOrphanDetector._build_finding(
            entity_id='abc-123', display_name='Bot1',
            detected_platform='test', days_inactive=50, rbac_roles=['Owner'],
        )
        assert f1['finding_fingerprint'] == f2['finding_fingerprint']

    def test_finding_metadata_has_code(self):
        """Metadata must include finding_code and agirs_penalty."""
        finding = AgentOrphanDetector._build_finding(
            entity_id='x', display_name='X',
            detected_platform=None, days_inactive=31, rbac_roles=['Owner'],
        )
        meta = finding['metadata']
        assert meta['finding_code'] == FINDING_CODE
        assert meta['agirs_penalty'] == AGIRS_PENALTY_SCORE
        assert meta['category'] == 'AI Agent Governance'
        assert meta['recommended_action'] == 'disable_spn'


# =====================================================================
# Feature Flag & Constants Tests
# =====================================================================

class TestFeatureFlag:
    """Verify feature flag and constants are correctly defined."""

    def test_feature_flag_exists(self):
        """FEATURE_AI_AGENT_GOVERNANCE must exist in config."""
        from app.config import FEATURE_AI_AGENT_GOVERNANCE
        assert FEATURE_AI_AGENT_GOVERNANCE is not None

    def test_constants_defined(self):
        """Core constants must be defined."""
        assert FINDING_TYPE == 'orphaned_ai_agent_spn'
        assert FINDING_CODE == 'IASM-AG-001'
        assert ORPHAN_INACTIVE_DAYS == 30
        assert AGIRS_PENALTY_SCORE == 15

    def test_elevated_roles_set(self):
        """Elevated roles set must contain 3 named roles."""
        assert 'Owner' in _ELEVATED_RBAC_ROLES
        assert 'Contributor' in _ELEVATED_RBAC_ROLES
        assert 'User Access Administrator' in _ELEVATED_RBAC_ROLES

    def test_write_tokens_set(self):
        """Write token set must contain key tokens."""
        assert 'write' in _WRITE_ROLE_TOKENS
        assert 'admin' in _WRITE_ROLE_TOKENS
        assert 'delete' in _WRITE_ROLE_TOKENS


# =====================================================================
# Migration / Schema Tests
# =====================================================================

class TestMigration:
    """Verify schema additions are present in database.py."""

    def test_penalty_columns_in_ddl(self):
        """database.py must reference agent_penalty_score and agent_penalty_reason."""
        import inspect
        from app.database import Database
        source = inspect.getsource(Database._ensure_agent_classifications_table)
        assert 'agent_penalty_score' in source
        assert 'agent_penalty_reason' in source

    def test_sp_signin_column_in_ddl(self):
        """database.py must reference last_service_principal_sign_in."""
        import inspect
        from app.database import Database
        source = inspect.getsource(Database._ensure_agent_classifications_table)
        assert 'last_service_principal_sign_in' in source

    def test_db_methods_exist(self):
        """Database must have update/clear/get penalty methods."""
        from app.database import Database
        assert hasattr(Database, 'update_agent_penalty')
        assert hasattr(Database, 'clear_agent_penalty')
        assert hasattr(Database, 'get_agent_penalty')


# =====================================================================
# Client Credential Sign-In Scenarios (10 new scenarios: 21–30)
# =====================================================================

class TestClientCredentialTruePositives:
    """Scenarios where client credential auth still results in orphan detection."""

    def test_21_sp_sign_in_45d_ago_orphaned(self):
        """ai_agent, lastSignInDateTime=NULL, sp_sign_in=45 days ago, Owner.
        SP sign-in is beyond 30 days → orphaned."""
        now = datetime.now(timezone.utc)
        sp_sign_in = now - timedelta(days=45)
        days_inactive = _compute_effective_days_inactive(None, sp_sign_in)
        assert days_inactive >= 45
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True
        assert _compute_activity_source(None, sp_sign_in) == "service_principal_sign_in"

    def test_22_no_activity_at_all_orphaned(self):
        """ai_agent, lastSignInDateTime=NULL, sp_sign_in=NULL, Owner.
        No activity at all → days_inactive=None → orphaned."""
        days_inactive = _compute_effective_days_inactive(None, None)
        assert days_inactive is None
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True
        assert _compute_activity_source(None, None) == "no_activity_recorded"

    def test_23_both_beyond_threshold_orphaned(self):
        """ai_agent, lastSignInDateTime=60d ago, sp_sign_in=40d ago, Owner.
        Both beyond 30 days, effective = max(60d ago, 40d ago) = 40d ago → orphaned."""
        now = datetime.now(timezone.utc)
        interactive = now - timedelta(days=60)
        sp = now - timedelta(days=40)
        days_inactive = _compute_effective_days_inactive(interactive, sp)
        assert 39 <= days_inactive <= 41  # ~40 days
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True
        assert _compute_activity_source(interactive, sp) == "service_principal_sign_in"


class TestClientCredentialTrueNegatives:
    """Scenarios where client credential auth prevents false orphan detection."""

    def test_24_only_sp_sign_in_yesterday_not_orphaned(self):
        """ai_agent, lastSignInDateTime=NULL, sp_sign_in=yesterday, Owner.
        Active via client creds → NOT orphaned."""
        now = datetime.now(timezone.utc)
        sp_sign_in = now - timedelta(days=1)
        days_inactive = _compute_effective_days_inactive(None, sp_sign_in)
        assert days_inactive <= 1
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False
        assert _compute_activity_source(None, sp_sign_in) == "service_principal_sign_in"

    def test_25_old_interactive_recent_sp_not_orphaned(self):
        """ai_agent, lastSignInDateTime=60d ago, sp_sign_in=2d ago, Owner.
        SP sign-in is recent → NOT orphaned."""
        now = datetime.now(timezone.utc)
        interactive = now - timedelta(days=60)
        sp = now - timedelta(days=2)
        days_inactive = _compute_effective_days_inactive(interactive, sp)
        assert days_inactive <= 2
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False

    def test_26_recent_interactive_no_sp_not_orphaned(self):
        """ai_agent, lastSignInDateTime=5d ago, sp_sign_in=NULL, Owner.
        Recent interactive sign-in → NOT orphaned."""
        now = datetime.now(timezone.utc)
        interactive = now - timedelta(days=5)
        days_inactive = _compute_effective_days_inactive(interactive, None)
        assert days_inactive <= 5
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False
        assert _compute_activity_source(interactive, None) == "interactive_sign_in"

    def test_27_sp_sign_in_29d_boundary_not_orphaned(self):
        """ai_agent, lastSignInDateTime=NULL, sp_sign_in=29d ago, Owner.
        SP sign-in within 30 days (boundary) → NOT orphaned."""
        now = datetime.now(timezone.utc)
        sp_sign_in = now - timedelta(days=29)
        days_inactive = _compute_effective_days_inactive(None, sp_sign_in)
        assert days_inactive <= 30
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is False


class TestGraphApiUnavailable:
    """Scenarios where Graph API is unavailable (graceful degradation)."""

    def test_28_graph_403_falls_back_to_interactive(self):
        """ai_agent, lastSignInDateTime=45d ago, sp_sign_in=Graph API 403.
        Graceful degradation: sp_sign_in is None, uses interactive=45d → orphaned."""
        now = datetime.now(timezone.utc)
        interactive = now - timedelta(days=45)
        sp_sign_in = None  # Graph API returned 403
        days_inactive = _compute_effective_days_inactive(interactive, sp_sign_in)
        assert days_inactive >= 45
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True
        assert _compute_activity_source(interactive, sp_sign_in) == "interactive_sign_in"

    def test_29_graph_error_no_interactive_orphaned(self):
        """ai_agent, lastSignInDateTime=NULL, sp_sign_in=Graph API error.
        No usable signal → days_inactive=None → orphaned."""
        sp_sign_in = None  # Graph API error
        days_inactive = _compute_effective_days_inactive(None, sp_sign_in)
        assert days_inactive is None
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True
        assert _compute_activity_source(None, sp_sign_in) == "no_activity_recorded"

    def test_30_graph_empty_result_same_as_null(self):
        """ai_agent, lastSignInDateTime=NULL, sp_sign_in=Graph returns empty.
        Same as NULL sp_sign_in → orphaned."""
        sp_sign_in = None  # Graph API returned empty result set
        days_inactive = _compute_effective_days_inactive(None, sp_sign_in)
        assert days_inactive is None
        assert AgentOrphanDetector.is_orphaned(
            agent_identity_type='ai_agent',
            days_inactive=days_inactive,
            enabled=True,
            deleted_at=None,
            rbac_roles=['Owner'],
        ) is True


# =====================================================================
# Finding Shape Tests — Activity Detection Source Fields
# =====================================================================

class TestFindingActivitySource:
    """Verify _build_finding() includes activity detection source fields."""

    def test_finding_metadata_has_activity_source_fields(self):
        """Finding metadata must include all 4 new activity fields."""
        now = datetime.now(timezone.utc)
        sp_dt = now - timedelta(days=2)
        interactive_dt = now - timedelta(days=60)
        finding = AgentOrphanDetector._build_finding(
            entity_id='test-sp-signin',
            display_name='TestBot',
            detected_platform='copilot_studio',
            days_inactive=45,
            rbac_roles=['Owner'],
            activity_detection_source='service_principal_sign_in',
            last_interactive_sign_in=interactive_dt,
            last_service_principal_sign_in=sp_dt,
            effective_last_active=sp_dt,
        )
        meta = finding['metadata']
        assert meta['activity_detection_source'] == 'service_principal_sign_in'
        assert meta['last_interactive_sign_in'] == interactive_dt.isoformat()
        assert meta['last_service_principal_sign_in'] == sp_dt.isoformat()
        assert meta['effective_last_active'] == sp_dt.isoformat()

    def test_finding_metadata_null_activity_fields(self):
        """Finding with no activity data must have null activity fields."""
        finding = AgentOrphanDetector._build_finding(
            entity_id='test-no-activity',
            display_name='GhostBot',
            detected_platform=None,
            days_inactive=999,
            rbac_roles=['Owner'],
            activity_detection_source='no_activity_recorded',
        )
        meta = finding['metadata']
        assert meta['activity_detection_source'] == 'no_activity_recorded'
        assert meta['last_interactive_sign_in'] is None
        assert meta['last_service_principal_sign_in'] is None
        assert meta['effective_last_active'] is None

    def test_finding_defaults_no_activity_recorded(self):
        """Finding built without new kwargs defaults to no_activity_recorded."""
        finding = AgentOrphanDetector._build_finding(
            entity_id='test-default',
            display_name='DefaultBot',
            detected_platform=None,
            days_inactive=31,
            rbac_roles=['Owner'],
        )
        meta = finding['metadata']
        assert meta['activity_detection_source'] == 'no_activity_recorded'
        assert meta['last_interactive_sign_in'] is None
        assert meta['last_service_principal_sign_in'] is None
        assert meta['effective_last_active'] is None
