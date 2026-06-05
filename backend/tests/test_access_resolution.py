"""Unit tests for services/access_resolution.py.

Covers the pure (no-DB) scope-matching and role→access-level derivation logic,
plus the batch helper exercised against a stub cursor.
"""
from __future__ import annotations

import pytest

from app.services.access_resolution import (
    _derivation_for,
    _level_from_role,
    _normalize,
    _scope_covers,
    resolve_agent_resource_access,
    resolve_agent_resource_access_batch,
)


SUB    = "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RG     = f"{SUB}/resourceGroups/prod-rg"
STG    = f"{RG}/providers/Microsoft.Storage/storageAccounts/prodstg"
KV     = f"{RG}/providers/Microsoft.KeyVault/vaults/prod-kv"
SQLSRV = f"{RG}/providers/Microsoft.Sql/servers/prod-sql"
SQLDB  = f"{SQLSRV}/databases/customers"
MG     = "/providers/Microsoft.Management/managementGroups/contoso-root"


# ─────────────────────────────────────────────────────────────────────────────
# _normalize
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalize:
    def test_lowercases(self):
        assert _normalize("/SUBSCRIPTIONS/ABC") == "/subscriptions/abc"

    def test_strips_trailing_slash(self):
        assert _normalize("/subscriptions/abc/") == "/subscriptions/abc"

    def test_preserves_root(self):
        assert _normalize("/") == "/"

    def test_collapses_double_leading_slash(self):
        assert _normalize("//subscriptions/abc") == "/subscriptions/abc"

    def test_empty_inputs(self):
        assert _normalize("") == ""
        assert _normalize(None) == ""
        assert _normalize("   ") == ""


# ─────────────────────────────────────────────────────────────────────────────
# _scope_covers
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeCovers:
    # Exact ----------------------------------------------------------------
    def test_exact_match(self):
        assert _scope_covers(STG, STG) is True

    def test_exact_match_case_insensitive(self):
        assert _scope_covers(STG.upper(), STG.lower()) is True

    # Root + management group ---------------------------------------------
    def test_root_covers_everything(self):
        assert _scope_covers("/", STG) is True
        assert _scope_covers("/", SUB) is True

    def test_management_group_covers_subscription(self):
        assert _scope_covers(MG, SUB) is True
        assert _scope_covers(MG, STG) is True

    # Subscription --------------------------------------------------------
    def test_subscription_covers_resource(self):
        assert _scope_covers(SUB, STG) is True

    def test_subscription_covers_rg(self):
        assert _scope_covers(SUB, RG) is True

    def test_subscription_does_not_cover_other_subscription(self):
        other = "/subscriptions/11111111-2222-3333-4444-555555555555"
        assert _scope_covers(SUB, other) is False
        assert _scope_covers(SUB, f"{other}/resourceGroups/foo") is False

    # Resource group ------------------------------------------------------
    def test_rg_covers_resource(self):
        assert _scope_covers(RG, STG) is True
        assert _scope_covers(RG, KV) is True

    def test_rg_does_not_cover_sibling_rg(self):
        other_rg = f"{SUB}/resourceGroups/dev-rg"
        assert _scope_covers(RG, other_rg) is False
        assert _scope_covers(RG, f"{other_rg}/providers/Microsoft.Storage/storageAccounts/devstg") is False

    def test_rg_does_not_cover_parent_subscription(self):
        assert _scope_covers(RG, SUB) is False

    # Nested resource types ----------------------------------------------
    def test_sql_server_covers_database(self):
        assert _scope_covers(SQLSRV, SQLDB) is True

    def test_resource_does_not_cover_sibling(self):
        other_db = f"{SQLSRV}/databases/orders"
        # Sibling at same level is NOT covered by SQLDB
        assert _scope_covers(SQLDB, other_db) is False

    def test_storage_does_not_cover_keyvault(self):
        assert _scope_covers(STG, KV) is False

    # Substring traps (regression for the buggy `scope in resource_id` style) ---
    def test_substring_match_is_not_a_cover(self):
        # Old buggy code used `if res_id in scope` which inverts the relation;
        # ensure we require proper hierarchy.
        assert _scope_covers(STG, SUB) is False  # resource cannot cover sub
        assert _scope_covers(STG, RG) is False   # resource cannot cover rg

    def test_prefix_without_segment_boundary_does_not_match(self):
        # Two RGs whose names share a prefix should NOT cover each other.
        rg_a = f"{SUB}/resourceGroups/prod"
        rg_a_resource = f"{rg_a}/providers/Microsoft.Storage/storageAccounts/x"
        rg_ab_resource = f"{SUB}/resourceGroups/prod-extra/providers/Microsoft.Storage/storageAccounts/y"
        assert _scope_covers(rg_a, rg_a_resource) is True
        assert _scope_covers(rg_a, rg_ab_resource) is False

    # Empties -------------------------------------------------------------
    def test_empty_scope_or_resource(self):
        assert _scope_covers("", STG) is False
        assert _scope_covers(SUB, "") is False
        assert _scope_covers(None, STG) is False
        assert _scope_covers(SUB, None) is False


# ─────────────────────────────────────────────────────────────────────────────
# _derivation_for
# ─────────────────────────────────────────────────────────────────────────────

class TestDerivationFor:
    def test_exact(self):
        assert _derivation_for(STG, STG) == "exact"

    def test_root(self):
        assert _derivation_for("/", STG) == "root"

    def test_management_group(self):
        assert _derivation_for(MG, STG) == "management_group"

    def test_subscription(self):
        assert _derivation_for(SUB, STG) == "subscription"
        assert _derivation_for(SUB, RG) == "subscription"

    def test_resource_group(self):
        assert _derivation_for(RG, STG) == "resource_group"

    def test_nested_resource(self):
        assert _derivation_for(SQLSRV, SQLDB) == "nested"

    def test_no_match(self):
        assert _derivation_for(STG, KV) == ""


# ─────────────────────────────────────────────────────────────────────────────
# _level_from_role
# ─────────────────────────────────────────────────────────────────────────────

class TestLevelFromRole:
    # Owner-equivalents
    @pytest.mark.parametrize("role", [
        "Owner",
        "User Access Administrator",
        "Role Based Access Control Administrator",
    ])
    def test_azure_owner_roles(self, role):
        assert _level_from_role(role) == "owner"

    @pytest.mark.parametrize("role", [
        "AdministratorAccess",
        "IAMFullAccess",
        "AWSOrganizationsFullAccess",
    ])
    def test_aws_owner_roles(self, role):
        assert _level_from_role(role) == "owner"

    @pytest.mark.parametrize("role", [
        "roles/owner",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountKeyAdmin",
    ])
    def test_gcp_owner_roles(self, role):
        assert _level_from_role(role) == "owner"

    # Contributor-equivalents
    @pytest.mark.parametrize("role", [
        "Contributor",
        "Storage Account Contributor",
        "Storage Blob Data Contributor",
        "Key Vault Administrator",
        "Key Vault Secrets Officer",
        "Virtual Machine Contributor",
    ])
    def test_azure_contributor_roles(self, role):
        assert _level_from_role(role) == "contributor"

    @pytest.mark.parametrize("role", [
        "AmazonS3FullAccess",
        "AmazonEC2FullAccess",
        "PowerUserAccess",
    ])
    def test_aws_contributor_roles(self, role):
        assert _level_from_role(role) == "contributor"

    @pytest.mark.parametrize("role", [
        "roles/editor",
        "roles/storage.admin",
        "roles/compute.admin",
    ])
    def test_gcp_contributor_roles(self, role):
        assert _level_from_role(role) == "contributor"

    # Reader-equivalents
    @pytest.mark.parametrize("role", [
        "Reader",
        "Storage Blob Data Reader",
        "Key Vault Reader",
        "Key Vault Secrets User",
        "Monitoring Reader",
    ])
    def test_azure_reader_roles(self, role):
        assert _level_from_role(role) == "reader"

    @pytest.mark.parametrize("role", [
        "ReadOnlyAccess",
        "AmazonS3ReadOnlyAccess",
        "IAMReadOnlyAccess",
        "SecurityAudit",
    ])
    def test_aws_reader_roles(self, role):
        assert _level_from_role(role) == "reader"

    @pytest.mark.parametrize("role", [
        "roles/viewer",
    ])
    def test_gcp_reader_roles(self, role):
        assert _level_from_role(role) == "reader"

    # Custom / unknown — fallback patterns
    def test_custom_contributor_role(self):
        assert _level_from_role("CompanyXContributor") == "contributor"

    def test_custom_reader_role(self):
        assert _level_from_role("CompanyXReader") == "reader"

    def test_unknown_role_defaults_to_reader(self):
        assert _level_from_role("SomeRandomCustomRole") == "reader"

    def test_empty_role(self):
        assert _level_from_role("") == "reader"


# ─────────────────────────────────────────────────────────────────────────────
# Strongest-result selection (via single-identity resolver, with a stub cursor)
# ─────────────────────────────────────────────────────────────────────────────

class _StubCursor:
    """Minimal cursor that yields the rows it was configured with on fetchall()."""

    def __init__(self, rows: list[tuple]):
        self._rows = rows
        self.last_query: str | None = None
        self.last_params: tuple | None = None

    def execute(self, query, params=None):
        self.last_query = query
        self.last_params = params

    def fetchall(self):
        return list(self._rows)


class TestResolveAgentResourceAccess:
    def test_no_assignments_returns_none(self):
        cur = _StubCursor([])
        assert resolve_agent_resource_access(cur, 42, STG) is None

    def test_no_matching_scope_returns_none(self):
        other_sub = "/subscriptions/zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
        cur = _StubCursor([("Reader", other_sub)])
        assert resolve_agent_resource_access(cur, 42, STG) is None

    def test_direct_resource_match(self):
        cur = _StubCursor([("Contributor", STG)])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["access_level"] == "contributor"
        assert result["derivation_path"] == "exact"
        assert result["scope"] == STG

    def test_subscription_covers_resource(self):
        cur = _StubCursor([("Reader", SUB)])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["access_level"] == "reader"
        assert result["derivation_path"] == "subscription"

    def test_rg_covers_resource(self):
        cur = _StubCursor([("Contributor", RG)])
        result = resolve_agent_resource_access(cur, 42, KV)
        assert result is not None
        assert result["access_level"] == "contributor"
        assert result["derivation_path"] == "resource_group"

    def test_strongest_access_level_wins(self):
        # Reader at sub + Owner at RG → Owner wins
        cur = _StubCursor([
            ("Reader", SUB),
            ("Owner", RG),
        ])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["access_level"] == "owner"
        assert result["role_name"] == "Owner"
        assert result["derivation_path"] == "resource_group"

    def test_specificity_tiebreaks_within_same_level(self):
        # Reader at sub + Reader at exact resource → exact wins on path rank
        cur = _StubCursor([
            ("Reader", SUB),
            ("Reader", STG),
        ])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["derivation_path"] == "exact"

    def test_nested_resource_type(self):
        # SQL server-level role grants access to its databases
        cur = _StubCursor([("SQL DB Contributor", SQLSRV)])
        result = resolve_agent_resource_access(cur, 42, SQLDB)
        assert result is not None
        assert result["derivation_path"] == "nested"
        assert result["access_level"] == "contributor"

    def test_root_scope_match(self):
        cur = _StubCursor([("Owner", "/")])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["derivation_path"] == "root"
        assert result["access_level"] == "owner"

    def test_management_group_match(self):
        cur = _StubCursor([("Owner", MG)])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["derivation_path"] == "management_group"

    def test_invalid_inputs_return_none(self):
        cur = _StubCursor([("Owner", "/")])
        assert resolve_agent_resource_access(cur, 0, STG) is None
        assert resolve_agent_resource_access(cur, 42, "") is None


# ─────────────────────────────────────────────────────────────────────────────
# Batch helper
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveBatch:
    def test_empty_inputs(self):
        cur = _StubCursor([])
        assert resolve_agent_resource_access_batch(cur, [], [STG]) == {}
        assert resolve_agent_resource_access_batch(cur, [1], []) == {}

    def test_single_query_for_n_identities(self):
        # Each identity has one assignment; verify the SQL is parameterised
        # once (no N+1).
        cur = _StubCursor([
            (1, "Reader", SUB),
            (2, "Owner",  RG),
        ])
        result = resolve_agent_resource_access_batch(cur, [1, 2], [STG, KV])
        assert "ANY" in (cur.last_query or "")
        assert cur.last_params == ([1, 2],)
        # Identity 1: reader on sub → covers both STG and KV
        assert result[(1, STG)]["access_level"] == "reader"
        assert result[(1, KV)]["access_level"] == "reader"
        # Identity 2: owner on RG → covers both
        assert result[(2, STG)]["access_level"] == "owner"
        assert result[(2, KV)]["access_level"] == "owner"

    def test_sparse_result(self):
        # Identity 1 covers STG (sub scope on a different sub-id) → no match
        other_sub = "/subscriptions/zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
        cur = _StubCursor([
            (1, "Reader", other_sub),
            (2, "Owner",  STG),
        ])
        result = resolve_agent_resource_access_batch(cur, [1, 2], [STG])
        assert (1, STG) not in result
        assert result[(2, STG)]["access_level"] == "owner"

    def test_strongest_pick_in_batch(self):
        cur = _StubCursor([
            (1, "Reader", SUB),
            (1, "Owner",  RG),
        ])
        result = resolve_agent_resource_access_batch(cur, [1], [STG])
        assert result[(1, STG)]["access_level"] == "owner"
        assert result[(1, STG)]["derivation_path"] == "resource_group"


# ─────────────────────────────────────────────────────────────────────────────
# Row-extraction helpers (cursor flexibility)
# ─────────────────────────────────────────────────────────────────────────────

class TestRowFlexibility:
    def test_dict_rows_work(self):
        cur = _StubCursor([{"role_name": "Owner", "scope": SUB}])
        result = resolve_agent_resource_access(cur, 42, STG)
        assert result is not None
        assert result["access_level"] == "owner"

    def test_dict_rows_batch(self):
        cur = _StubCursor([
            {"identity_db_id": 1, "role_name": "Reader", "scope": RG},
        ])
        result = resolve_agent_resource_access_batch(cur, [1], [STG])
        assert result[(1, STG)]["access_level"] == "reader"
