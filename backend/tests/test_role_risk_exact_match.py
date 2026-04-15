"""
Role Risk Exact-Match Tests

Verifies that _calculate_role_risk uses exact role name matching, not substring
matching. Scoped contributor roles (e.g., Log Analytics Contributor) must NOT
inherit the full Contributor description or score.
"""
import os
import inspect

os.environ.setdefault('FLASK_ENV', 'development')
# JWT_SECRET set by conftest.py pytest_configure — KeyError if missing
_JWT = os.environ["JWT_SECRET"]
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_PORT', '5432')
os.environ.setdefault('DB_NAME', 'auditgraph')
os.environ.setdefault('ADMIN_JWT_SECRET', 'admin-test-key-role')
os.environ.setdefault('TENANT_JWT_SECRET', 'tenant-test-key-role')

from app.engines.discovery.azure_discovery import AzureDiscoveryEngine


def _get_role_risk(role_name, scope_type='subscription'):
    """Helper: call _calculate_role_risk on an AzureDiscoveryEngine instance."""
    engine = AzureDiscoveryEngine.__new__(AzureDiscoveryEngine)
    return engine._calculate_role_risk(role_name, scope_type)


# ── Test 1: Exact "Contributor" gets full Contributor description ──

def test_exact_contributor_gets_full_description():
    level, desc = _get_role_risk('Contributor', 'subscription')
    assert level == 'high', f"Exact Contributor should be 'high', got '{level}'"
    assert 'create/modify/delete all resources' in desc


# ── Test 2: Log Analytics Contributor does NOT get Contributor description ──

def test_log_analytics_contributor_differs_from_contributor():
    contrib_level, contrib_desc = _get_role_risk('Contributor', 'subscription')
    lac_level, lac_desc = _get_role_risk('Log Analytics Contributor', 'subscription')
    assert lac_desc != contrib_desc, \
        f"Log Analytics Contributor must NOT inherit Contributor's description. Got: {lac_desc}"
    assert 'Log Analytics' in lac_desc, \
        f"Description should mention Log Analytics, got: {lac_desc}"


# ── Test 3: Scoped contributors score lower than full Contributor ──

def test_scoped_contributors_lower_risk_than_contributor():
    contrib_level, _ = _get_role_risk('Contributor', 'subscription')
    scoped_roles = [
        'Log Analytics Contributor',
        'Monitoring Contributor',
        'Backup Contributor',
        'Site Recovery Contributor',
    ]
    risk_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    contrib_rank = risk_order[contrib_level]
    for role in scoped_roles:
        level, _ = _get_role_risk(role, 'subscription')
        rank = risk_order[level]
        assert rank < contrib_rank, \
            f"{role} risk '{level}' should be lower than Contributor '{contrib_level}'"


# ── Test 4: Storage Blob Data Contributor is NOT full Contributor ──

def test_storage_blob_data_contributor():
    level, desc = _get_role_risk('Storage Blob Data Contributor')
    assert 'create/modify/delete all resources' not in desc, \
        f"Storage Blob Data Contributor should not get full Contributor description: {desc}"
    assert 'blob' in desc.lower() or 'storage' in desc.lower() or 'data' in desc.lower(), \
        f"Description should mention storage/blob/data, got: {desc}"


# ── Test 5: Network Contributor is NOT full Contributor ──

def test_network_contributor():
    level, desc = _get_role_risk('Network Contributor')
    assert 'create/modify/delete all resources' not in desc
    assert 'network' in desc.lower()


# ── Test 6: SQL DB Contributor is NOT full Contributor ──

def test_sql_db_contributor():
    level, desc = _get_role_risk('SQL DB Contributor')
    assert 'create/modify/delete all resources' not in desc


# ── Test 7: Exact "Owner" gets full Owner description ──

def test_exact_owner():
    level, desc = _get_role_risk('Owner', 'subscription')
    assert level == 'critical'
    assert 'Full control' in desc


# ── Test 8: Storage Blob Data Owner is NOT full Owner ──

def test_storage_blob_data_owner():
    level, desc = _get_role_risk('Storage Blob Data Owner', 'subscription')
    assert level != 'critical', \
        f"Storage Blob Data Owner should not be critical: {desc}"
    assert 'Full control including IAM' not in desc


# ── Test 9: Unknown contributor role gets safe fallback ──

def test_unknown_contributor_fallback():
    level, desc = _get_role_risk('Blockchain Member Node Contributor', 'subscription')
    assert level == 'low', \
        f"Unknown *Contributor role should default to low, got '{level}'"
    assert 'create/modify/delete all resources' not in desc, \
        "Unknown Contributor must NOT inherit full Contributor description"
    assert 'Blockchain Member Node Contributor' in desc, \
        "Fallback description should include the actual role name"


# ── Test 10: No substring matching in _calculate_role_risk ──

def test_no_substring_matching():
    """The function must NOT use 'contributor' in role_lower substring matching."""
    src = inspect.getsource(AzureDiscoveryEngine._calculate_role_risk)
    # Must not contain the old substring pattern
    assert "'contributor' in role_lower" not in src, \
        "_calculate_role_risk still uses 'contributor' in role_lower substring match"
    assert "'owner' in role_lower" not in src, \
        "_calculate_role_risk still uses 'owner' in role_lower substring match"


# ── Test 11: V2 risk factor scoring uses exact match ──

def test_v2_risk_factors_no_substring():
    """The V2 risk factor scoring must NOT use 'contributor' in role_name substring matching."""
    src = inspect.getsource(AzureDiscoveryEngine._calculate_risks)
    assert "'contributor' in role_name" not in src, \
        "V2 risk factor scoring still uses 'contributor' in role_name substring match"
    assert "'owner' in role_name" not in src, \
        "V2 risk factor scoring still uses 'owner' in role_name substring match"


# ── Test 12: Role risk map exists as class attribute ──

def test_role_risk_map_exists():
    """_ROLE_RISK_EXACT must exist as a class-level dict."""
    assert hasattr(AzureDiscoveryEngine, '_ROLE_RISK_EXACT')
    role_map = AzureDiscoveryEngine._ROLE_RISK_EXACT
    assert isinstance(role_map, dict)
    assert 'contributor' in role_map
    assert 'owner' in role_map
    assert 'log analytics contributor' in role_map
    assert 'storage blob data contributor' in role_map


# ── Test 13: Scoped contributor catalog entries exist ──

def test_scoped_contributor_catalog_entries():
    """risk_catalog must have SCOPED_CONTRIBUTOR with points < SUBSCRIPTION_CONTRIBUTOR."""
    from app.engines.risk_catalog import RISK_FACTOR_CATALOG
    assert 'SCOPED_CONTRIBUTOR' in RISK_FACTOR_CATALOG
    assert 'SUBSCRIPTION_CONTRIBUTOR' in RISK_FACTOR_CATALOG
    scoped_pts = RISK_FACTOR_CATALOG['SCOPED_CONTRIBUTOR']['points']
    contrib_pts = RISK_FACTOR_CATALOG['SUBSCRIPTION_CONTRIBUTOR']['points']
    assert scoped_pts < contrib_pts, \
        f"SCOPED_CONTRIBUTOR ({scoped_pts}) must score lower than SUBSCRIPTION_CONTRIBUTOR ({contrib_pts})"
