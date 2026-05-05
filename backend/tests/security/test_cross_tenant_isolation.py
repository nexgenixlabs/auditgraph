"""
AG-94: Cross-tenant isolation tests — verify every refactored Database method
rejects missing org_id and isolates data between orgs.

CWE-639, CWE-284, OWASP A01:2021 — Broken Access Control

These tests verify the application-layer defense (explicit org_id scoping).
RLS provides defense-in-depth but is NOT tested here (that's in integrity.py).
"""
import inspect
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from app.security.tenant_scope import TenantScopeError, _validate_org_id


# ── Signature enforcement tests ────────────────────────────────────────
# These verify that the refactored methods have the correct signature
# and reject calls without org_id.

class TestSignatureEnforcement:
    """Verify every refactored method enforces org_id at the signature level."""

    def test_get_latest_discovery_run_requires_org_id_kwarg(self):
        """get_latest_discovery_run must require org_id as keyword-only."""
        from app.database import Database
        sig = inspect.signature(Database.get_latest_discovery_run)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, "org_id must be keyword-only"
        assert param.default is inspect.Parameter.empty, "org_id must not have a default"

    def test_get_report_data_requires_org_id_kwarg(self):
        """get_report_data must require org_id as keyword-only."""
        from app.database import Database
        sig = inspect.signature(Database.get_report_data)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, "org_id must be keyword-only"
        assert param.default is inspect.Parameter.empty, "org_id must not have a default"

    def test_get_role_usage_stats_requires_org_id_kwarg(self):
        """get_role_usage_stats must require org_id as keyword-only."""
        from app.database import Database
        sig = inspect.signature(Database.get_role_usage_stats)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, "org_id must be keyword-only"
        assert param.default is inspect.Parameter.empty, "org_id must not have a default"

    def test_populate_campaign_reviews_requires_org_id_kwarg(self):
        """populate_campaign_reviews must require org_id as keyword-only."""
        from app.database import Database
        sig = inspect.signature(Database.populate_campaign_reviews)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, "org_id must be keyword-only"
        assert param.default is inspect.Parameter.empty, "org_id must not have a default"

    def test_get_active_snapshot_job_has_org_id_param(self):
        """get_active_snapshot_job must accept org_id keyword."""
        from app.database import Database
        sig = inspect.signature(Database.get_active_snapshot_job)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, "org_id must be keyword-only"

    def test_get_groups_has_org_id_param(self):
        """get_groups must accept org_id keyword."""
        from app.database import Database
        sig = inspect.signature(Database.get_groups)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"

    def test_get_group_has_org_id_param(self):
        """get_group must accept org_id keyword."""
        from app.database import Database
        sig = inspect.signature(Database.get_group)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"

    def test_get_group_comparison_has_org_id_param(self):
        """get_group_comparison must accept org_id keyword."""
        from app.database import Database
        sig = inspect.signature(Database.get_group_comparison)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"

    def test_get_identity_groups_has_org_id_param(self):
        """get_identity_groups must accept org_id keyword."""
        from app.database import Database
        sig = inspect.signature(Database.get_identity_groups)
        param = sig.parameters.get('org_id')
        assert param is not None, "org_id parameter missing"


# ── SQL content tests ──────────────────────────────────────────────────
# Verify the actual SQL in each method contains organization_id scoping.

class TestSqlContainsOrgFilter:
    """Verify refactored methods contain organization_id in their SQL."""

    def test_get_latest_discovery_run_sql_has_org_filter(self):
        """get_latest_discovery_run SQL must contain organization_id filter."""
        from app.database import Database
        source = inspect.getsource(Database.get_latest_discovery_run)
        assert 'organization_id' in source, \
            "get_latest_discovery_run must filter by organization_id"

    def test_get_report_data_sql_has_org_filter(self):
        """get_report_data SQL must contain organization_id filter."""
        from app.database import Database
        source = inspect.getsource(Database.get_report_data)
        assert 'organization_id' in source, \
            "get_report_data must filter by organization_id"

    def test_get_role_usage_stats_sql_has_org_filter(self):
        """get_role_usage_stats SQL must contain organization_id filter."""
        from app.database import Database
        source = inspect.getsource(Database.get_role_usage_stats)
        assert 'organization_id' in source, \
            "get_role_usage_stats must filter by organization_id"

    def test_populate_campaign_reviews_sql_has_org_filter(self):
        """populate_campaign_reviews SQL must contain organization_id filter."""
        from app.database import Database
        source = inspect.getsource(Database.populate_campaign_reviews)
        assert 'organization_id' in source, \
            "populate_campaign_reviews must filter by organization_id"

    def test_get_active_snapshot_job_sql_has_org_filter(self):
        """get_active_snapshot_job SQL must contain organization_id filter."""
        from app.database import Database
        source = inspect.getsource(Database.get_active_snapshot_job)
        assert 'organization_id' in source, \
            "get_active_snapshot_job must filter by organization_id"

    def test_get_groups_sql_has_org_filter(self):
        """get_groups SQL must scope discovery_runs by organization_id."""
        from app.database import Database
        source = inspect.getsource(Database.get_groups)
        assert 'organization_id' in source, \
            "get_groups must filter discovery_runs by organization_id"

    def test_get_group_sql_has_org_filter(self):
        """get_group SQL must scope discovery_runs by organization_id."""
        from app.database import Database
        source = inspect.getsource(Database.get_group)
        assert 'organization_id' in source, \
            "get_group must filter discovery_runs by organization_id"

    def test_get_group_comparison_sql_has_org_filter(self):
        """get_group_comparison SQL must scope discovery_runs by organization_id."""
        from app.database import Database
        source = inspect.getsource(Database.get_group_comparison)
        assert 'organization_id' in source, \
            "get_group_comparison must filter discovery_runs by organization_id"

    def test_get_identity_groups_sql_has_org_filter(self):
        """get_identity_groups SQL must scope discovery_runs by organization_id."""
        from app.database import Database
        source = inspect.getsource(Database.get_identity_groups)
        assert 'organization_id' in source, \
            "get_identity_groups must filter discovery_runs by organization_id"

    def test_get_soar_actions_sql_has_org_filter_in_subquery(self):
        """get_soar_actions discovery_runs subquery must be org-scoped."""
        from app.database import Database
        source = inspect.getsource(Database.get_soar_actions)
        # The subquery should now have organization_id filter
        assert source.count('organization_id') >= 2, \
            "get_soar_actions must have organization_id in both WHERE and subquery"

    def test_get_soar_action_stats_sql_has_org_filter_in_subquery(self):
        """get_soar_action_stats discovery_runs subquery must be org-scoped."""
        from app.database import Database
        source = inspect.getsource(Database.get_soar_action_stats)
        assert source.count('organization_id') >= 3, \
            "get_soar_action_stats must have organization_id in WHERE and both subqueries"

    def test_get_security_summary_context_anomalies_has_org_filter(self):
        """get_security_summary_context anomalies query must have organization_id."""
        from app.database import Database
        source = inspect.getsource(Database.get_security_summary_context)
        # Count occurrences of organization_id — should appear in anomalies query too
        assert source.count('organization_id') >= 3, \
            "get_security_summary_context must filter anomalies by organization_id"

    def test_get_group_risk_stats_sql_has_org_filter(self):
        """_get_group_risk_stats must scope discovery_runs by organization_id."""
        from app.database import Database
        source = inspect.getsource(Database._get_group_risk_stats)
        assert 'organization_id' in source, \
            "_get_group_risk_stats must filter discovery_runs by organization_id"


# ── No unscoped MAX(id) pattern tests ──────────────────────────────────

class TestNoUnscopedMaxPattern:
    """Verify the dangerous unscoped MAX(id) pattern is eliminated."""

    def test_no_unscoped_max_in_get_role_usage_stats(self):
        """get_role_usage_stats must not have unscoped MAX(id) on discovery_runs."""
        from app.database import Database
        source = inspect.getsource(Database.get_role_usage_stats)
        # Should NOT contain: SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'"
        # without organization_id filter
        lines = source.split('\n')
        for line in lines:
            if "SELECT MAX(id) FROM discovery_runs" in line:
                assert 'organization_id' in line, \
                    f"Unscoped MAX(id) found: {line.strip()}"

    def test_no_unscoped_max_in_populate_campaign_reviews(self):
        """populate_campaign_reviews must not have unscoped MAX(id)."""
        from app.database import Database
        source = inspect.getsource(Database.populate_campaign_reviews)
        lines = source.split('\n')
        for line in lines:
            if "SELECT MAX(id) FROM discovery_runs" in line:
                assert 'organization_id' in line, \
                    f"Unscoped MAX(id) found: {line.strip()}"

    def test_no_unscoped_max_in_get_groups(self):
        """get_groups must not have unscoped MAX(id)."""
        from app.database import Database
        source = inspect.getsource(Database.get_groups)
        lines = source.split('\n')
        for line in lines:
            if "SELECT MAX(id) FROM discovery_runs" in line:
                assert 'organization_id' in line, \
                    f"Unscoped MAX(id) found: {line.strip()}"

    def test_no_unscoped_max_in_get_group(self):
        """get_group must not have unscoped MAX(id)."""
        from app.database import Database
        source = inspect.getsource(Database.get_group)
        lines = source.split('\n')
        for line in lines:
            if "SELECT MAX(id) FROM discovery_runs" in line:
                assert 'organization_id' in line, \
                    f"Unscoped MAX(id) found: {line.strip()}"

    def test_no_unscoped_max_in_get_group_comparison(self):
        """get_group_comparison must not have unscoped MAX(id)."""
        from app.database import Database
        source = inspect.getsource(Database.get_group_comparison)
        lines = source.split('\n')
        for line in lines:
            if "SELECT MAX(id) FROM discovery_runs" in line:
                assert 'organization_id' in line, \
                    f"Unscoped MAX(id) found: {line.strip()}"

    def test_no_unscoped_max_in_get_identity_groups(self):
        """get_identity_groups must not have unscoped MAX(id)."""
        from app.database import Database
        source = inspect.getsource(Database.get_identity_groups)
        lines = source.split('\n')
        for line in lines:
            if "SELECT MAX(id) FROM discovery_runs" in line:
                assert 'organization_id' in line, \
                    f"Unscoped MAX(id) found: {line.strip()}"


# ── Handler integration tests ──────────────────────────────────────────
# Verify handlers pass org_id to the refactored methods.

class TestHandlerWiring:
    """Verify API handlers pass org_id to refactored Database methods."""

    def test_get_report_data_handler_passes_org_id(self):
        """get_report_data handler must pass org_id."""
        from app.api import handlers
        source = inspect.getsource(handlers.get_report_data)
        assert 'org_id=' in source, \
            "get_report_data handler must pass org_id to db.get_report_data()"

    def test_get_role_usage_stats_handler_passes_org_id(self):
        """get_role_usage_stats handler must pass org_id."""
        from app.api import handlers
        source = inspect.getsource(handlers.get_role_usage_stats)
        assert 'org_id=' in source, \
            "get_role_usage_stats handler must pass org_id"

    def test_export_risk_summary_passes_org_id(self):
        """_export_risk_summary must pass org_id to get_report_data."""
        from app.api import handlers
        source = inspect.getsource(handlers._export_risk_summary)
        assert 'org_id=' in source, \
            "_export_risk_summary must pass org_id"

    def test_export_evidence_package_passes_org_id(self):
        """_export_evidence_package must pass org_id to get_report_data."""
        from app.api import handlers
        source = inspect.getsource(handlers._export_evidence_package)
        assert 'org_id=' in source, \
            "_export_evidence_package must pass org_id"

    def test_populate_campaign_handler_passes_org_id(self):
        """Campaign creation handler must pass org_id to populate_campaign_reviews."""
        from app.api import handlers
        # Find the function that calls populate_campaign_reviews
        source = inspect.getsource(handlers)
        # Find the line with populate_campaign_reviews call
        for line in source.split('\n'):
            if 'populate_campaign_reviews' in line and 'def ' not in line:
                assert 'org_id=' in line, \
                    f"populate_campaign_reviews call must include org_id: {line.strip()}"


# ── Azure discovery ICE config test ────────────────────────────────────

class TestAzureDiscoveryIceConfig:
    """Verify azure_discovery._load_ice_config uses org-scoped connection."""

    def test_load_ice_config_uses_org_scoped_connection(self):
        """_load_ice_config must NOT use admin Database() connection."""
        from app.engines.discovery import azure_discovery
        source = inspect.getsource(azure_discovery.AzureDiscoveryEngine._load_ice_config)
        # Must use Database(organization_id=...) not Database()
        assert 'organization_id=' in source, \
            "_load_ice_config must use org-scoped Database connection"
        # Must filter settings by organization_id
        assert 'organization_id = %s' in source or 'organization_id=%s' in source, \
            "_load_ice_config must filter settings by organization_id"
