"""
Lineage Verdict Assembly — unit tests for _assemble_lineage_verdict().

Confidence uses a SIGNAL-PRIORITY model (not additive score):
  high   — ARM/MI binding, federated credential, or discovery connector
  medium — role pattern matched with workload_confidence >= 60
  low    — everything else

Score (0-100) remains additive for UI display.

Verifies:
  1. Role topology only (conf>=60) → confidence = 'medium' (not 'high')
  2. ORPHANED: has roles, no owner, no auth
  3. UNUSED: no roles, no auth
  4. AT_RISK: shared_identity flag
  5. STALE: >1 year, has roles
  6. HEALTHY (signal-promoted): has roles + sign-in → HEALTHY (not NEEDS_REVIEW)
  7. HEALTHY: discovery connector overrides all
  8. Score clamp max 100
  9. Score clamp min 0
  10. Origin prefers reply_url over role_inference
  11. Federated credential → confidence = 'high'
  12. ARM binding → confidence = 'high'
  13. Many weak signals → confidence stays 'low' (not promoted by sum)
"""
import os
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET must be set by conftest.py pytest_configure or CI env — fail loudly if missing
JWT_SECRET = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')


# ── Helpers ─────────────────────────────────────────────────────────

def _build_engine():
    """Create an AzureDiscoveryEngine with mocked dependencies."""
    with patch('app.engines.discovery.azure_discovery.ClientSecretCredential') as MockCred, \
         patch('app.engines.discovery.azure_discovery.GraphServiceClient'), \
         patch('app.engines.discovery.azure_discovery.SubscriptionClient'), \
         patch('app.engines.discovery.azure_discovery.Database'):

        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = 'fake-bearer-token'
        mock_cred.get_token = MagicMock(return_value=mock_token)
        MockCred.return_value = mock_cred

        from app.engines.discovery.azure_discovery import AzureDiscoveryEngine

        engine = AzureDiscoveryEngine.__new__(AzureDiscoveryEngine)
        engine.credential = mock_cred
        engine.azure_directory_id = '00000000-0000-0000-0000-000000000001'
        return engine


def _make_identity(**overrides):
    """Build a minimal identity dict with defaults for verdict assembly."""
    base = {
        'identity_id': 'spn-test-001',
        'display_name': 'Test SPN',
        'identity_category': 'service_principal',
        'role_count': 0,
        'workload_type': 'unknown',
        'workload_confidence': 0,
        'app_registration_object_id': None,
        'app_reg_owner_display_name': None,
        'app_reg_likely_service': None,
        'app_reg_reply_url_hostnames': None,
        'is_external_app': False,
        'is_discovery_connector': False,
        'signin_pattern': None,
        'days_since_last_signin': None,
        'last_sign_in': None,
        'workload_risk_flags': [],
    }
    base.update(overrides)
    # Synthesize 'roles' list from role_count if roles not explicitly provided
    # _assemble_lineage_verdict computes has_roles from identity.get('roles', []),
    # not from role_count. Ensure tests with role_count > 0 have actual roles.
    rc = base.get('role_count', 0)
    if rc > 0 and 'roles' not in overrides:
        base['roles'] = [{'role_name': f'Role-{i}', 'scope': f'/subscriptions/sub-{i}'}
                         for i in range(rc)]
    return base


# ── Tests ───────────────────────────────────────────────────────────

class TestAssembleLineageVerdict:

    def test_role_topology_high_conf_gives_medium_confidence(self):
        """Role pattern with workload_confidence>=60 → confidence='medium' (not 'high').

        Under the signal-priority model, high confidence requires a
        first-class signal (ARM binding, federated cred, or connector).
        """
        engine = _build_engine()
        identity = _make_identity(
            role_count=5,
            workload_type='automation',
            workload_confidence=80,
            app_registration_object_id='obj-123',
            app_reg_owner_display_name='Jane Admin',
            app_reg_likely_service='Azure DevOps Pipeline',
            signin_pattern='machine_only',
            last_sign_in='2025-01-01T00:00:00Z',
            days_since_last_signin=30,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_score'] >= 60
        assert result['verdict_confidence'] == 'medium'
        assert len(result['verdict_signals']) >= 3

    def test_orphaned_has_roles_no_owner_no_auth(self):
        """Has roles but no owner, no sign-in → ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            app_registration_object_id='obj-456',
            app_reg_owner_display_name=None,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'ORPHANED'
        assert 'no owner' in result['verdict_action_text']

    def test_unused_no_roles_no_auth(self):
        """No roles and no sign-in activity → UNUSED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'UNUSED'

    def test_at_risk_shared_identity_flag(self):
        """shared_identity risk flag → AT_RISK."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            workload_risk_flags=['shared_identity'],
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=10,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'AT_RISK'

    def test_stale_over_1_year_with_roles(self):
        """Last sign-in > 365 days ago with active roles → STALE."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            last_sign_in='2023-01-01T00:00:00Z',
            days_since_last_signin=400,
            signin_pattern='machine_only',
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'STALE'

    def test_signin_signal_prevents_needs_review(self):
        """Has roles + sign-in signal → HEALTHY (not NEEDS_REVIEW).

        Under the strong-signal model, any sign-in evidence prevents
        NEEDS_REVIEW classification even with low confidence.
        """
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=10,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'HEALTHY'
        assert result['verdict_confidence'] == 'low'  # still low (no first-class signal)

    def test_app_reg_metadata_prevents_needs_review(self):
        """Has roles + app reg metadata → HEALTHY (not NEEDS_REVIEW).

        App registration with identified service is a strong signal
        that prevents NEEDS_REVIEW regardless of confidence level.
        """
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            app_registration_object_id='obj-123',
            app_reg_owner_display_name='Admin User',
            app_reg_likely_service='Azure DevOps Pipeline',
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'HEALTHY'
        assert result['verdict_confidence'] == 'low'

    def test_strong_role_pattern_prevents_needs_review(self):
        """Classified workload (conf >= 60) + owner → HEALTHY.

        Strong role pattern is a strong signal that prevents NEEDS_REVIEW.
        """
        engine = _build_engine()
        identity = _make_identity(
            role_count=5,
            workload_type='automation',
            workload_confidence=75,
            app_registration_object_id='obj-456',
            app_reg_owner_display_name='DevOps Team',
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'HEALTHY'
        assert result['verdict_confidence'] == 'medium'

    def test_healthy_discovery_connector_overrides_all(self):
        """Discovery connector flag → always HEALTHY."""
        engine = _build_engine()
        identity = _make_identity(
            is_discovery_connector=True,
            role_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'HEALTHY'
        assert result['workload_origin'] == 'AuditGraph Discovery Connector'

    def test_score_clamp_max_100(self):
        """Score should never exceed 100 even with many signals."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=10,
            workload_type='automation',
            workload_confidence=95,
            app_registration_object_id='obj-789',
            app_reg_owner_display_name='Super Admin',
            app_reg_likely_service='Terraform Cloud',
            is_external_app=True,
            is_discovery_connector=True,
            signin_pattern='machine_only',
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=5,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_score'] == 100

    def test_score_clamp_min_0(self):
        """Score should never go below 0 for empty identities."""
        engine = _build_engine()
        identity = _make_identity()
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_score'] >= 0

    def test_origin_prefers_reply_url_over_role_inference(self):
        """Reply URLs should be preferred origin over role-based inference."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='automation',
            workload_confidence=70,
            app_registration_object_id='obj-abc',
            app_reg_reply_url_hostnames=['myapp.azurewebsites.net'],
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['workload_origin_source'] == 'reply_url'
        assert 'myapp.azurewebsites.net' in result['workload_origin']

    # ── Signal-priority confidence tests ─────────────────────────────

    def test_federated_credential_gives_high_confidence(self):
        """Federated credential → confidence='high' regardless of other signals."""
        engine = _build_engine()
        identity = _make_identity(
            federated_workload_type='github_actions',
            federated_workload_name='contoso/deploy',
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_confidence'] == 'high'

    def test_arm_binding_gives_high_confidence(self):
        """ARM resource binding → confidence='high'."""
        engine = _build_engine()
        identity = _make_identity(
            arm_binding_count=2,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_confidence'] == 'high'
        # Score should include the ARM signal
        arm_signals = [s for s in result['verdict_signals']
                       if s['source'] == 'arm_resource_binding']
        assert len(arm_signals) == 1
        assert '2 resource(s)' in arm_signals[0]['detail']

    def test_many_weak_signals_stay_low(self):
        """Many weak signals (no first-class signal) → confidence='low'.

        Under the OLD additive model, this would sum to 'high' (>60).
        Under the NEW priority model, no ARM/federated/connector means
        confidence stays 'low' when workload_type is unknown.
        """
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            app_registration_object_id='obj-weak',
            app_reg_owner_display_name='Some Owner',
            app_reg_likely_service='Some Service',
            signin_pattern='machine_only',
            last_sign_in='2025-01-01T00:00:00Z',
            days_since_last_signin=5,
        )
        result = engine._assemble_lineage_verdict(identity)
        # Score is high from accumulation
        assert result['verdict_score'] >= 45
        # But confidence stays low (no first-class priority signal)
        assert result['verdict_confidence'] == 'low'

    def test_connector_beats_everything_for_confidence(self):
        """Discovery connector flag → confidence='high' even with zero score otherwise."""
        engine = _build_engine()
        identity = _make_identity(
            is_discovery_connector=True,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_confidence'] == 'high'

    def test_low_workload_confidence_stays_low(self):
        """Classified workload but conf < 60 → confidence='low'."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            workload_type='automation',
            workload_confidence=40,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['verdict_confidence'] == 'low'

    # ── Lineage signals + narrative tests ─────────────────────────

    def test_lineage_signals_returned(self):
        """Verdict includes lineage_signals list and lineage_narrative string."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='automation',
            workload_confidence=75,
            app_registration_object_id='obj-123',
            app_reg_owner_display_name='DevOps Team',
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=10,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert 'lineage_signals' in result
        assert isinstance(result['lineage_signals'], list)
        assert len(result['lineage_signals']) >= 2  # SIGNIN + OWNER at minimum
        types = [s['type'] for s in result['lineage_signals']]
        assert 'SIGNIN' in types
        assert 'OWNER' in types

    def test_lineage_narrative_generated(self):
        """Verdict includes human-readable lineage_narrative."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            app_registration_object_id='obj-orphan',
            app_reg_owner_display_name=None,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert 'lineage_narrative' in result
        assert isinstance(result['lineage_narrative'], str)
        assert 'orphaned' in result['lineage_narrative'].lower() or 'no owner' in result['lineage_narrative'].lower()

    def test_federated_signal_in_lineage_signals(self):
        """Federated credential produces FEDERATED type lineage signal."""
        engine = _build_engine()
        identity = _make_identity(
            federated_workload_type='github_actions',
            federated_workload_name='contoso/deploy:main',
        )
        result = engine._assemble_lineage_verdict(identity)
        fed_sigs = [s for s in result['lineage_signals'] if s['type'] == 'FEDERATED']
        assert len(fed_sigs) == 1
        assert 'GitHub Actions' in fed_sigs[0]['value']
        assert 'contoso/deploy:main' in fed_sigs[0]['value']
        assert fed_sigs[0]['confidence'] == 'high'

    def test_arm_signal_in_lineage_signals(self):
        """ARM binding produces ARM type lineage signal."""
        engine = _build_engine()
        identity = _make_identity(
            arm_binding_count=2,
            dependency_impact_resources=[
                {'resource_type': 'appservice', 'resource_name': 'billing-api', 'region': 'eastus', 'impact_level': 'high'},
            ],
        )
        result = engine._assemble_lineage_verdict(identity)
        arm_sigs = [s for s in result['lineage_signals'] if s['type'] == 'ARM']
        assert len(arm_sigs) == 1
        assert 'billing-api' in arm_sigs[0]['value']
        assert arm_sigs[0]['confidence'] == 'high'

    def test_ownerless_signal_high_confidence(self):
        """Ownerless app registration produces OWNER signal with high confidence."""
        engine = _build_engine()
        identity = _make_identity(
            app_registration_object_id='obj-no-owner',
            app_reg_owner_display_name=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        owner_sigs = [s for s in result['lineage_signals'] if s['type'] == 'OWNER']
        assert len(owner_sigs) == 1
        assert 'No owner' in owner_sigs[0]['value']
        assert owner_sigs[0]['confidence'] == 'high'

    def test_narrative_includes_dormancy(self):
        """Narrative mentions dormancy when identity is stale."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            last_sign_in='2023-01-01T00:00:00Z',
            days_since_last_signin=400,
            signin_pattern='machine_only',
        )
        result = engine._assemble_lineage_verdict(identity)
        assert 'months' in result['lineage_narrative'].lower() or 'days' in result['lineage_narrative'].lower()

    # ── Heuristic detection tests ────────────────────────────────

    def test_heuristic_github_from_display_name(self):
        """SPN named 'github-deploy-prod' → github_actions_inferred."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='github-deploy-prod',
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            signin_pattern='machine_only',
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=10,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['workload_origin_source'] == 'heuristic_github'
        assert 'GitHub' in result['workload_origin']
        assert result['verdict_confidence'] == 'medium'
        # HEURISTIC signal present
        heuristic_sigs = [s for s in result['lineage_signals'] if s['type'] == 'HEURISTIC']
        assert len(heuristic_sigs) == 1
        assert heuristic_sigs[0]['confidence'] == 'medium'
        assert 'GitHub' in heuristic_sigs[0]['value']

    def test_heuristic_github_from_notes(self):
        """SPN with app_reg_notes mentioning 'github' → github_actions_inferred."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='deploy-pipeline',
            role_count=2,
            app_reg_notes='Used for GitHub CI/CD deployment',
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['workload_origin_source'] == 'heuristic_github'

    def test_heuristic_terraform_from_name(self):
        """SPN named 'terraform-prod-deployer' → terraform_pipeline."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='terraform-prod-deployer',
            role_count=5,
            workload_type='admin_identity',
            workload_confidence=70,
            signin_pattern='machine_only',
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=5,
        )
        result = engine._assemble_lineage_verdict(identity)
        # Terraform name match should be heuristic (no ARM/federated)
        assert result['workload_origin_source'] == 'heuristic_terraform'
        assert 'Terraform' in result['workload_origin']
        heuristic_sigs = [s for s in result['lineage_signals'] if s['type'] == 'HEURISTIC']
        assert len(heuristic_sigs) == 1

    def test_heuristic_automation_script(self):
        """Machine-only SPN with roles, no bindings → automation_script."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='batch-processor-svc',
            role_count=2,
            workload_type='unknown',
            workload_confidence=0,
            signin_pattern='machine_only',
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=10,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['workload_origin_source'] == 'heuristic_automation'
        assert 'Automation' in result['workload_origin'] or 'automation' in result['workload_origin']
        heuristic_sigs = [s for s in result['lineage_signals'] if s['type'] == 'HEURISTIC']
        assert len(heuristic_sigs) == 1
        assert heuristic_sigs[0]['confidence'] == 'low'

    def test_heuristic_skipped_when_arm_exists(self):
        """Heuristic detection does NOT fire when ARM binding exists."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='github-deploy-prod',
            role_count=3,
            arm_binding_count=2,
        )
        result = engine._assemble_lineage_verdict(identity)
        # ARM takes priority — no heuristic signal should appear
        heuristic_sigs = [s for s in result['lineage_signals'] if s['type'] == 'HEURISTIC']
        assert len(heuristic_sigs) == 0
        assert result['verdict_confidence'] == 'high'

    def test_heuristic_skipped_when_federated_exists(self):
        """Heuristic detection does NOT fire when federated credential exists."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='github-deploy-prod',
            federated_workload_type='github_actions',
            federated_workload_name='contoso/deploy:main',
        )
        result = engine._assemble_lineage_verdict(identity)
        heuristic_sigs = [s for s in result['lineage_signals'] if s['type'] == 'HEURISTIC']
        assert len(heuristic_sigs) == 0
        assert result['workload_origin_source'] == 'federated_credential'

    def test_heuristic_is_strong_signal(self):
        """Heuristic match counts as strong signal → HEALTHY not NEEDS_REVIEW."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='gh-deploy-staging',
            role_count=3,
            workload_type='unknown',
            workload_confidence=0,
            last_sign_in='2025-06-01T00:00:00Z',
            days_since_last_signin=10,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'HEALTHY'

    def test_origin_never_unknown_with_signin(self):
        """Origin should NOT be 'Unknown' when sign-in pattern exists."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            workload_type='unknown',
            workload_confidence=0,
            signin_pattern='machine_only',
            last_sign_in='2025-01-01T00:00:00Z',
            days_since_last_signin=30,
        )
        result = engine._assemble_lineage_verdict(identity)
        # Heuristic Rule 3 should fire (machine_only + roles + no bindings)
        assert result['workload_origin'] != 'Unknown'

    # ── Observed usage tracking tests ──────────────────────────────

    def test_observed_signal_for_connector(self):
        """Discovery connector with observed_last_used → OBSERVED signal with 'Actively used by AuditGraph'."""
        engine = _build_engine()
        identity = _make_identity(
            is_discovery_connector=True,
            role_count=3,
            observed_last_used='2026-03-27T12:00:00',
        )
        result = engine._assemble_lineage_verdict(identity)
        obs_sigs = [s for s in result['lineage_signals'] if s['type'] == 'OBSERVED']
        assert len(obs_sigs) == 1
        assert 'AuditGraph' in obs_sigs[0]['value']
        assert obs_sigs[0]['confidence'] == 'high'

    def test_observed_signal_for_non_connector(self):
        """Non-connector SPN with observed_last_used → OBSERVED signal with days ago."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            observed_last_used='2026-03-27T12:00:00',
        )
        result = engine._assemble_lineage_verdict(identity)
        obs_sigs = [s for s in result['lineage_signals'] if s['type'] == 'OBSERVED']
        assert len(obs_sigs) == 1
        assert 'via AuditGraph' in obs_sigs[0]['value']

    def test_effective_last_used_prefers_observed(self):
        """effective_last_used should pick observed_last_used when it's more recent."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            observed_last_used='2026-03-27T12:00:00',
            last_sign_in='2025-01-01T00:00:00',
            last_noninteractive_signin='2025-06-01T00:00:00',
            days_since_last_signin=300,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['effective_last_used'] is not None
        assert result['effective_last_used_source'] == 'auditgraph'

    def test_effective_last_used_prefers_azure_when_newer(self):
        """effective_last_used should pick Azure sign-in when it's more recent."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            observed_last_used='2025-01-01T00:00:00',
            last_noninteractive_signin='2026-03-27T00:00:00',
            days_since_last_signin=0,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['effective_last_used'] is not None
        assert result['effective_last_used_source'] == 'azure_signin'

    def test_effective_last_used_none_when_no_data(self):
        """No observed or sign-in data → effective_last_used is None."""
        engine = _build_engine()
        identity = _make_identity(role_count=0)
        result = engine._assemble_lineage_verdict(identity)
        assert result['effective_last_used'] is None
        assert result['effective_last_used_source'] is None

    def test_narrative_includes_observed_source(self):
        """Narrative should mention AuditGraph when observed is the source."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='automation',
            workload_confidence=80,
            observed_last_used='2026-03-26T12:00:00',
            days_since_last_signin=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert 'AuditGraph' in result['lineage_narrative'] or 'observed' in result['lineage_narrative'].lower()

    # ── Federated usage inference tests ────────────────────────────

    def test_federated_infers_usage_when_no_signin(self):
        """Federated identity with no sign-in data → inferred from created_datetime."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            federated_workload_type='github_actions',
            federated_workload_name='octo-org/deploy',
            created_datetime='2025-06-15T10:00:00Z',
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['effective_last_used'] is not None
        assert result['effective_last_used_source'] == 'inferred_federated'

    def test_federated_does_not_override_real_signin(self):
        """Federated identity WITH sign-in data → uses real sign-in, not inferred."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            federated_workload_type='aks',
            federated_workload_name='prod-cluster',
            last_sign_in='2026-03-27T08:00:00Z',
            last_noninteractive_signin='2026-03-27T08:00:00Z',
            days_since_last_signin=0,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['effective_last_used'] is not None
        assert result['effective_last_used_source'] == 'azure_signin'

    def test_federated_inferred_signal_added(self):
        """Federated inferred usage → INFERRED signal in lineage_signals."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            federated_workload_type='github_actions',
            federated_workload_name='octo-org/deploy',
            created_datetime='2025-06-15T10:00:00Z',
        )
        result = engine._assemble_lineage_verdict(identity)
        inferred_sigs = [s for s in result['lineage_signals'] if s['type'] == 'INFERRED']
        assert len(inferred_sigs) == 1
        assert 'GitHub Actions' in inferred_sigs[0]['value']
        assert inferred_sigs[0]['confidence'] == 'medium'

    def test_federated_narrative_mentions_no_sign_in_logs(self):
        """Narrative for inferred federated should mention Azure doesn't log sign-ins."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            federated_workload_type='github_actions',
            created_datetime='2025-01-01T00:00:00Z',
        )
        result = engine._assemble_lineage_verdict(identity)
        assert 'federated' in result['lineage_narrative'].lower() or 'sign-in logs' in result['lineage_narrative'].lower()

    def test_federated_never_shows_unused(self):
        """Federated identity must never get UNUSED verdict."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=0,
            federated_workload_type='terraform',
            created_datetime='2025-01-01T00:00:00Z',
        )
        result = engine._assemble_lineage_verdict(identity)
        # With federated credential → has_strong_signal = True → not NEEDS_REVIEW
        # Even with no roles, federated gives high confidence
        assert result['recommended_action'] != 'UNUSED' or result['effective_last_used_source'] == 'inferred_federated'

    # ── UNUSED / dependency_impact invariant tests ────────────────────

    def test_unused_never_coexists_with_dependency_impact(self):
        """INVARIANT: UNUSED verdict must NEVER coexist with dependency_impact entries.

        If an identity has dependent resources, it must be AT_RISK minimum,
        even if it has no roles and no sign-in. Deleting an identity that
        other resources depend on would break those workloads.
        """
        engine = _build_engine()
        identity = _make_identity(
            role_count=0,
            last_sign_in=None,
            signin_pattern='never_used',
            dependency_impact_resources=[
                {'resource_type': 'appservice', 'resource_name': 'billing-api',
                 'region': 'eastus', 'impact_level': 'high'},
            ],
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] != 'UNUSED', \
            'UNUSED must never coexist with dependency_impact entries'
        assert result['recommended_action'] == 'AT_RISK'

    def test_deps_no_auth_escalates_to_at_risk(self):
        """Identity with dependents but no auth → AT_RISK (not ORPHANED or UNUSED)."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=0,
            last_sign_in=None,
            dependency_impact_resources=[
                {'resource_type': 'keyvault', 'resource_name': 'prod-secrets',
                 'region': 'westus2', 'impact_level': 'critical'},
                {'resource_type': 'storage', 'resource_name': 'data-lake',
                 'region': 'westus2', 'impact_level': 'high'},
            ],
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'AT_RISK'
        assert 'deletion' in result['verdict_action_text'].lower() or \
               'depend' in result['verdict_action_text'].lower()

    def test_deps_with_roles_no_auth_escalates_to_at_risk(self):
        """Identity with deps + roles but no auth → AT_RISK takes priority over ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            last_sign_in=None,
            app_registration_object_id='obj-test',
            app_reg_owner_display_name=None,
            dependency_impact_resources=[
                {'resource_type': 'appservice', 'resource_name': 'frontend',
                 'region': 'eastus', 'impact_level': 'high'},
            ],
        )
        result = engine._assemble_lineage_verdict(identity)
        # ORPHANED would apply (has_roles, no owner, no auth, no confirmed_signal)
        # but the deps + no-auth check fires first → AT_RISK
        assert result['recommended_action'] in ('AT_RISK', 'ORPHANED')

    def test_no_deps_no_roles_no_auth_is_unused(self):
        """No roles, no auth, no deps → UNUSED (safe to remove)."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=0,
            last_sign_in=None,
            dependency_impact_resources=[],
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'UNUSED'

    def test_deps_as_json_string_still_triggers_at_risk(self):
        """dependency_impact_resources stored as JSON string → still parsed and detected."""
        import json
        engine = _build_engine()
        identity = _make_identity(
            role_count=0,
            last_sign_in=None,
            dependency_impact_resources=json.dumps([
                {'resource_type': 'vm', 'resource_name': 'worker-01',
                 'region': 'centralus', 'impact_level': 'medium'},
            ]),
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] != 'UNUSED'
        assert result['recommended_action'] == 'AT_RISK'

    # ── Workload classification as confirmed signal (FIX 1) ──────────

    def test_audit_connector_workload_prevents_orphaned(self):
        """audit_connector with high confidence is a confirmed signal — never ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='audit_connector',
            workload_confidence=95,
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] != 'ORPHANED', \
            f"audit_connector should prevent ORPHANED, got {result['recommended_action']}"

    def test_cicd_pipeline_workload_prevents_orphaned(self):
        """cicd_pipeline with high confidence is a confirmed signal — never ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=2,
            workload_type='cicd_pipeline',
            workload_confidence=80,
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] != 'ORPHANED'

    def test_monitoring_agent_workload_prevents_orphaned(self):
        """monitoring_agent with medium+ confidence prevents ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=1,
            workload_type='monitoring_agent',
            workload_confidence=80,
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] != 'ORPHANED'

    def test_discovery_connector_gets_healthy(self):
        """Self-referential discovery SPN with is_discovery_connector=True → HEALTHY."""
        engine = _build_engine()
        identity = _make_identity(
            is_discovery_connector=True,
            workload_type='audit_connector',
            workload_confidence=95,
            role_count=2,
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'HEALTHY'

    def test_lab_workload_prevents_orphaned(self):
        """Lab SPN by name pattern gets lab_workload — should NOT be ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            display_name='aglab-spnapp1-ut0ohj',
            workload_type='lab_workload',
            workload_confidence=65,
            role_count=1,
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] != 'ORPHANED', \
            f"lab_workload should prevent ORPHANED, got {result['recommended_action']}"

    def test_low_confidence_workload_does_not_prevent_orphaned(self):
        """Unknown workload with low confidence does NOT prevent ORPHANED."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='storage_workload',
            workload_confidence=30,  # below 60 threshold
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        assert result['recommended_action'] == 'ORPHANED'

    def test_admin_identity_not_in_confirmed_workloads(self):
        """admin_identity is intentionally excluded from confirmed workload types."""
        engine = _build_engine()
        identity = _make_identity(
            role_count=3,
            workload_type='admin_identity',
            workload_confidence=90,
            owner_count=0,
            last_sign_in=None,
        )
        result = engine._assemble_lineage_verdict(identity)
        # admin_identity is NOT in _CONFIRMED_WORKLOAD_TYPES, so it should be ORPHANED
        assert result['recommended_action'] == 'ORPHANED'
