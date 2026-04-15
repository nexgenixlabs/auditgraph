"""
Discovery Pipeline Validator

Provides stage definitions, pipeline gating logic, count validation,
and snapshot completeness checks for the discovery pipeline.
"""

import logging

logger = logging.getLogger(__name__)

# Ordered list of discovery pipeline stages: (order, key, display_name)
DISCOVERY_STAGES = [
    (1, 'identities',         'Identity Discovery'),
    (2, 'service_principals',  'Service Principal Discovery'),
    (3, 'resources',           'Resource Discovery'),
    (4, 'role_assignments',    'Role Assignment Discovery'),
    (5, 'graph_edges',         'Graph Edge Build'),
    (6, 'risk_engine',         'Risk Engine Computation'),
    (7, 'snapshot_commit',     'Snapshot Commit + Integrity Hash'),
]


def log_stage(db, run_id, org_id, stage_name, stage_order, status, count=None, error=None):
    """Convenience wrapper around db.log_discovery_stage()."""
    try:
        db.log_discovery_stage(run_id, org_id, stage_name, stage_order, status, count, error)
    except Exception as e:
        logger.warning("Failed to log stage %s for run %s: %s", stage_name, run_id, e)


def validate_pipeline_completion(db, run_id, org_id) -> tuple:
    """Check that all required pipeline stages completed successfully.

    Returns:
        (is_valid: bool, errors: list[str])
    """
    stages = db.get_discovery_stages(run_id)
    errors = []
    for order, key, display_name in DISCOVERY_STAGES:
        s = stages.get(key)
        if not s:
            errors.append(f"Stage '{display_name}' ({key}) missing")
        elif s['status'] == 'failed':
            err_msg = s.get('error_message', 'unknown error')
            errors.append(f"Stage '{display_name}' failed: {err_msg}")
    return (len(errors) == 0, errors)


def validate_identity_counts(db, run_id, expected_from_api: dict) -> dict:
    """Compare discovered identity count against Azure Graph API page totals."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s", (run_id,))
        actual = cursor.fetchone()[0] or 0
    finally:
        cursor.close()
    expected = expected_from_api.get('total_identities', 0)
    return {
        'check': 'identity_count',
        'expected': expected,
        'actual': actual,
        'match': actual == expected,
        'delta': actual - expected,
    }


def validate_spn_counts(db, run_id, expected_from_api: dict) -> dict:
    """Compare discovered SPN count against expected."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT COUNT(*) FROM identities
            WHERE discovery_run_id = %s AND identity_category = 'service_principal'
        """, (run_id,))
        actual = cursor.fetchone()[0] or 0
    finally:
        cursor.close()
    expected = expected_from_api.get('total_spns', 0)
    return {
        'check': 'spn_count',
        'expected': expected,
        'actual': actual,
        'match': actual == expected,
        'delta': actual - expected,
    }


def validate_resource_counts(db, run_id, expected_from_api: dict) -> dict:
    """Compare discovered resource counts against expected."""
    cursor = db.conn.cursor()
    sa_count = kv_count = 0
    try:
        try:
            cursor.execute("SAVEPOINT val_sa")
            cursor.execute("SELECT COUNT(*) FROM azure_storage_accounts WHERE discovery_run_id = %s", (run_id,))
            sa_count = cursor.fetchone()[0] or 0
            cursor.execute("RELEASE SAVEPOINT val_sa")
        except Exception:
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT val_sa")
            except Exception:
                pass
        try:
            cursor.execute("SAVEPOINT val_kv")
            cursor.execute("SELECT COUNT(*) FROM azure_key_vaults WHERE discovery_run_id = %s", (run_id,))
            kv_count = cursor.fetchone()[0] or 0
            cursor.execute("RELEASE SAVEPOINT val_kv")
        except Exception:
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT val_kv")
            except Exception:
                pass
    finally:
        cursor.close()
    actual = sa_count + kv_count
    expected = expected_from_api.get('total_resources', 0)
    return {
        'check': 'resource_count',
        'expected': expected,
        'actual': actual,
        'match': actual == expected,
        'delta': actual - expected,
        'breakdown': {'storage_accounts': sa_count, 'key_vaults': kv_count},
    }


def validate_role_assignments(db, run_id, expected_from_api: dict) -> dict:
    """Compare discovered role assignment count against expected."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT COUNT(*) FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = %s
        """, (run_id,))
        actual = cursor.fetchone()[0] or 0
    finally:
        cursor.close()
    expected = expected_from_api.get('total_role_assignments', 0)
    return {
        'check': 'role_assignment_count',
        'expected': expected,
        'actual': actual,
        'match': actual == expected,
        'delta': actual - expected,
    }


# Required components: snapshot is invalid if any has 0 rows
REQUIRED_COMPONENTS = [
    ('identities', "SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s"),
    ('role_assignments',
     "SELECT COUNT(*) FROM role_assignments ra JOIN identities i ON i.id = ra.identity_db_id WHERE i.discovery_run_id = %s"),
    ('entra_roles',
     "SELECT COUNT(*) FROM entra_role_assignments era JOIN identities i ON i.id = era.identity_db_id WHERE i.discovery_run_id = %s"),
]

# Optional components: logged but do not invalidate the snapshot
OPTIONAL_COMPONENTS = [
    ('storage_accounts', "SELECT COUNT(*) FROM azure_storage_accounts WHERE discovery_run_id = %s", 'run_id'),
    ('key_vaults', "SELECT COUNT(*) FROM azure_key_vaults WHERE discovery_run_id = %s", 'run_id'),
    ('attack_paths', "SELECT COUNT(*) FROM graph_attack_findings WHERE organization_id = %s", 'org_id'),
    ('risk_summary', "SELECT COUNT(*) FROM risk_summary WHERE discovery_run_id = %s", 'run_id'),
]


def validate_snapshot_completeness(db, run_id, org_id) -> dict:
    """Check that a snapshot contains all required components."""
    results = {'valid': True, 'components': {}, 'missing': []}
    cursor = db.conn.cursor()
    try:
        for name, sql in REQUIRED_COMPONENTS:
            try:
                cursor.execute("SAVEPOINT val_%s" % name[:8])
                cursor.execute(sql, (run_id,))
                count = cursor.fetchone()[0] or 0
                results['components'][name] = count
                if count == 0:
                    results['missing'].append(name)
                    results['valid'] = False
                cursor.execute("RELEASE SAVEPOINT val_%s" % name[:8])
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT val_%s" % name[:8])
                except Exception:
                    pass
                results['components'][name] = 0
                results['missing'].append(name)
                results['valid'] = False

        for entry in OPTIONAL_COMPONENTS:
            name, sql, param_type = entry
            param = org_id if param_type == 'org_id' else run_id
            try:
                cursor.execute("SAVEPOINT val_%s" % name[:8])
                cursor.execute(sql, (param,))
                count = cursor.fetchone()[0] or 0
                results['components'][name] = count
                cursor.execute("RELEASE SAVEPOINT val_%s" % name[:8])
            except Exception:
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT val_%s" % name[:8])
                except Exception:
                    pass
                results['components'][name] = 0

        return results
    finally:
        cursor.close()


def run_all_count_validations(db, run_id, expected_from_api: dict) -> list:
    """Run all count validation checks. Returns list of result dicts."""
    results = []
    if expected_from_api:
        results.append(validate_identity_counts(db, run_id, expected_from_api))
        results.append(validate_spn_counts(db, run_id, expected_from_api))
        results.append(validate_resource_counts(db, run_id, expected_from_api))
        results.append(validate_role_assignments(db, run_id, expected_from_api))

        # Log results
        for r in results:
            if not r['match']:
                logger.warning(
                    "Count mismatch for %s: expected=%d actual=%d delta=%d",
                    r['check'], r['expected'], r['actual'], r['delta']
                )
    return results
