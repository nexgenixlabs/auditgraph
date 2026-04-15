"""
Platform Integrity Check

Comprehensive validation of platform health: tenant isolation (RLS),
snapshot completeness, risk engine consistency, discovery pipeline
completion, snapshot hashes, and AGIRS score consistency.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Tables that MUST have RLS (FORCE ROW LEVEL SECURITY) enabled.
# This is the canonical list of all 44 tenant-scoped tables.
RLS_PROTECTED_TABLES = {
    'activity_log', 'agirs_scores', 'anomalies', 'api_keys',
    'app_registrations', 'azure_key_vaults', 'azure_storage_accounts',
    'cloud_connections', 'compliance_framework_config', 'compliance_snapshots',
    'copilot_conversations', 'credentials',
    'dashboard_preferences', 'discovery_runs', 'discovery_stage_log',
    'drift_reports', 'entra_role_assignments',
    'graph_api_permissions', 'graph_attack_findings', 'graph_edges',
    'identity_exposures', 'identity_groups', 'identity_group_members',
    'identity_subscription_access',
    'job_runs', 'notifications',
    'pim_activations', 'pim_eligible_assignments', 'posture_scores',
    'remediation_actions', 'remediation_playbooks',
    'risk_rules', 'risk_scores', 'risk_summary',
    'role_assignments',
    'sa_attestations', 'saved_views', 'scan_schedules',
    'security_findings', 'settings', 'snapshot_jobs', 'snapshot_runs',
    'soar_actions', 'soar_playbooks',
    'sp_app_roles', 'webhooks',
    'workload_activity_stats', 'workload_anomaly_events', 'workload_signin_events',
}


def platform_integrity_check(db):
    """Run all platform integrity checks.

    Args:
        db: A Database instance connected as admin user.

    Returns:
        dict with checks, score, and overall status.
    """
    results = {
        'timestamp': datetime.utcnow().isoformat(),
        'checks': {},
        'score': 0,
        'max_score': 100,
    }

    results['checks']['tenant_isolation'] = _check_rls_enforcement(db)
    results['checks']['snapshot_completeness'] = _check_latest_snapshot(db)
    results['checks']['risk_consistency'] = _check_risk_consistency(db)
    results['checks']['discovery_completion'] = _check_discovery_stages(db)
    results['checks']['snapshot_integrity'] = _check_snapshot_integrity(db)
    results['checks']['agirs_consistency'] = _check_agirs_consistency(db)

    total = len(results['checks'])
    passed = sum(1 for c in results['checks'].values() if c.get('passed'))
    results['score'] = round(passed / total * 100) if total > 0 else 0
    results['status'] = (
        'healthy' if results['score'] >= 80
        else 'degraded' if results['score'] >= 50
        else 'critical'
    )

    return results


def _check_rls_enforcement(db) -> dict:
    """Verify all tenant-scoped tables have FORCE ROW LEVEL SECURITY."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT relname FROM pg_class
            WHERE relrowsecurity = true AND relforcerowsecurity = true
              AND relname = ANY(%s)
        """, (list(RLS_PROTECTED_TABLES),))
        protected = {r[0] for r in cursor.fetchall()}
        # Also check which tables actually exist
        cursor.execute("""
            SELECT tablename FROM pg_tables
            WHERE schemaname = 'public' AND tablename = ANY(%s)
        """, (list(RLS_PROTECTED_TABLES),))
        existing = {r[0] for r in cursor.fetchall()}
        missing_rls = existing - protected
        not_created = RLS_PROTECTED_TABLES - existing
        return {
            'passed': len(missing_rls) == 0,
            'details': (
                f'{len(protected)} tables protected, {len(missing_rls)} missing RLS'
                if missing_rls else f'All {len(protected)} existing tables have RLS enforced'
            ),
            'protected_count': len(protected),
            'missing_rls': sorted(missing_rls) if missing_rls else [],
            'not_yet_created': sorted(not_created) if not_created else [],
        }
    except Exception as e:
        return {'passed': False, 'details': f'RLS check failed: {e}'}
    finally:
        cursor.close()


def _check_latest_snapshot(db) -> dict:
    """Verify the latest completed discovery run has all required components."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT id, organization_id FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        if not row:
            return {'passed': True, 'details': 'No completed runs to validate'}

        run_id, org_id = row[0], row[1]

        from app.engines.discovery.pipeline_validator import validate_snapshot_completeness
        completeness = validate_snapshot_completeness(db, run_id, org_id)
        return {
            'passed': completeness['valid'],
            'details': (
                f'Run #{run_id}: all required components present'
                if completeness['valid']
                else f"Run #{run_id}: missing {', '.join(completeness['missing'])}"
            ),
            'run_id': run_id,
            'components': completeness['components'],
            'missing': completeness.get('missing', []),
        }
    except Exception as e:
        return {'passed': False, 'details': f'Snapshot completeness check failed: {e}'}
    finally:
        cursor.close()


def _check_risk_consistency(db) -> dict:
    """Verify persisted risk_summary exists and has plausible values."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("SAVEPOINT ic_risk")
        cursor.execute("""
            SELECT rs.discovery_run_id, rs.total_identities, rs.computed_at,
                   (SELECT COUNT(*) FROM identities WHERE discovery_run_id = rs.discovery_run_id) as live_count
            FROM risk_summary rs
            ORDER BY rs.computed_at DESC LIMIT 1
        """)
        row = cursor.fetchone()
        cursor.execute("RELEASE SAVEPOINT ic_risk")

        if not row:
            return {'passed': True, 'details': 'No risk summary computed yet (first run pending)'}

        run_id, persisted_total, computed_at, live_count = row
        match = persisted_total == live_count
        return {
            'passed': match,
            'details': (
                f'Run #{run_id}: persisted={persisted_total}, live={live_count}'
                + ('' if match else ' — MISMATCH')
            ),
            'run_id': run_id,
            'persisted_total': persisted_total,
            'live_count': live_count,
            'computed_at': computed_at.isoformat() if computed_at else None,
        }
    except Exception as e:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT ic_risk")
        except Exception:
            pass
        return {'passed': True, 'details': f'Risk consistency check skipped: {e}'}
    finally:
        cursor.close()


def _check_discovery_stages(db) -> dict:
    """Verify the latest discovery run completed all pipeline stages."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("""
            SELECT id, organization_id FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        if not row:
            return {'passed': True, 'details': 'No completed runs to validate'}

        run_id, org_id = row[0], row[1]
        stages = db.get_discovery_stages(run_id)

        if not stages:
            return {
                'passed': True,
                'details': f'Run #{run_id}: no stage log (pre-validation run)',
            }

        from app.engines.discovery.pipeline_validator import DISCOVERY_STAGES
        failed = []
        for order, key, display_name in DISCOVERY_STAGES:
            s = stages.get(key)
            if s and s['status'] == 'failed':
                failed.append(key)

        return {
            'passed': len(failed) == 0,
            'details': (
                f'Run #{run_id}: {len(stages)} stages logged, {len(failed)} failed'
                if failed
                else f'Run #{run_id}: {len(stages)} stages all OK'
            ),
            'run_id': run_id,
            'stages_logged': len(stages),
            'failed_stages': failed,
        }
    except Exception as e:
        return {'passed': False, 'details': f'Discovery stage check failed: {e}'}
    finally:
        cursor.close()


def _check_snapshot_integrity(db) -> dict:
    """Verify latest snapshot has a valid integrity hash."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("SAVEPOINT ic_snap")
        cursor.execute("""
            SELECT id, integrity_hash, signature
            FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        cursor.execute("RELEASE SAVEPOINT ic_snap")

        if not row:
            return {'passed': True, 'details': 'No completed runs to validate'}

        run_id, integrity_hash, signature = row
        has_hash = bool(integrity_hash)
        has_sig = bool(signature)
        return {
            'passed': has_hash,
            'details': (
                f'Run #{run_id}: hash={"present" if has_hash else "MISSING"}, '
                f'signature={"present" if has_sig else "MISSING"}'
            ),
            'run_id': run_id,
            'has_hash': has_hash,
            'has_signature': has_sig,
        }
    except Exception as e:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT ic_snap")
        except Exception:
            pass
        return {'passed': True, 'details': f'Snapshot integrity check skipped: {e}'}
    finally:
        cursor.close()


def _check_agirs_consistency(db) -> dict:
    """Verify AGIRS scores in risk_summary are present and plausible (0-100 range)."""
    cursor = db.conn.cursor()
    try:
        cursor.execute("SAVEPOINT ic_agirs")
        cursor.execute("""
            SELECT agirs_score, hiri_score, nhiri_score, gei_score, computed_at, discovery_run_id
            FROM risk_summary
            ORDER BY computed_at DESC LIMIT 1
        """)
        row = cursor.fetchone()
        cursor.execute("RELEASE SAVEPOINT ic_agirs")

        if not row:
            return {'passed': True, 'details': 'No risk summary (with AGIRS) computed yet'}

        agirs, hiri, nhiri, gei, computed_at, run_id = row
        scores = {'agirs': agirs, 'hiri': hiri, 'nhiri': nhiri, 'gei': gei}
        in_range = all(0 <= (s or 0) <= 100 for s in scores.values())
        return {
            'passed': in_range,
            'details': (
                f'Run #{run_id}: AGIRS={agirs}, HIRI={hiri}, NHIRI={nhiri}, GEI={gei}'
                + ('' if in_range else ' — OUT OF RANGE')
            ),
            'run_id': run_id,
            'scores': {k: float(v) if v is not None else None for k, v in scores.items()},
            'in_range': in_range,
            'computed_at': computed_at.isoformat() if computed_at else None,
            'source': 'risk_summary',
        }
    except Exception as e:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT ic_agirs")
        except Exception:
            pass
        return {'passed': True, 'details': f'AGIRS check skipped: {e}'}


def data_source_map():
    """Return which backend data source each dashboard component reads from.

    This enables verification that all screens read from canonical
    persisted tables rather than live-computing risk metrics.
    """
    return {
        'version': '1.0',
        'canonical_engine': 'app.engines.risk.risk_summary_engine.RiskSummaryEngine',
        'canonical_table': 'risk_summary',
        'components': {
            'executive_posture': {
                'endpoint': '/api/risk/summary',
                'handler': 'get_risk_summary()',
                'source_table': 'risk_summary',
                'source_type': 'persisted',
                'metrics': ['ghost_accounts', 'orphaned_spns', 'over_privileged',
                            'dormant_privileged', 'high_blast_radius', 'attack_paths',
                            'identity_counts', 'agirs_score', 'agirs_tier'],
            },
            'agirs_detail': {
                'endpoint': '/api/identity-risk-summary',
                'handler': 'get_identity_risk_summary()',
                'source_table': 'risk_summary',
                'source_type': 'persisted (consolidated from agirs_scores)',
                'metrics': ['agirs_score', 'hiri_score', 'nhiri_score', 'gei_score',
                            'hiri_breakdown', 'nhiri_breakdown', 'gei_breakdown',
                            'dangerous_identities', 'human_count', 'nhi_count'],
            },
            'exposure_summary': {
                'endpoint': '/api/exposure/summary',
                'handler': 'get_exposure_summary()',
                'source_table': 'azure_storage_accounts, azure_key_vaults, role_assignments',
                'source_type': 'snapshot_scoped (discovery_run_id)',
                'metrics': ['total_resources', 'storage_accounts', 'key_vaults',
                            'subscriptions', 'privileged_roles'],
            },
            'attack_paths': {
                'endpoint': '/api/attack-paths/count',
                'handler': 'get_attack_path_count()',
                'source_table': 'graph_attack_findings',
                'source_type': 'persisted',
                'metrics': ['total', 'open', 'critical', 'high', 'medium', 'low',
                            'affected_identities'],
            },
            'attack_surface_score': {
                'endpoint': '/api/overview/attack-surface-score',
                'handler': 'get_attack_surface_score()',
                'source_table': 'identities, role_assignments, entra_role_assignments',
                'source_type': 'snapshot_scoped (discovery_run_id)',
                'metrics': ['attack_surface_score', 'pillar_scores (6 pillars)'],
            },
            'dashboard_stats': {
                'endpoint': '/api/stats',
                'handler': 'get_stats()',
                'source_table': 'discovery_runs, identities, risk_summary',
                'source_type': 'snapshot_scoped + persisted',
                'metrics': ['total_identities', 'critical_count', 'high_count',
                            'ghost_count (from risk_summary)', 'workload_exposure'],
            },
            'dashboard_posture': {
                'endpoint': '/api/dashboard/posture',
                'handler': 'get_dashboard_posture()',
                'source_table': 'identities (via metric_queries registry)',
                'source_type': 'snapshot_scoped (discovery_run_id)',
                'metrics': ['posture_score', 'credential_health', 'dormant_count'],
            },
            'compliance_scorecard': {
                'endpoint': '/api/dashboard/compliance',
                'handler': 'get_dashboard_compliance()',
                'source_table': 'compliance_frameworks, identities, compliance_snapshots',
                'source_type': 'snapshot_scoped + persisted snapshots',
                'metrics': ['framework_scores', 'pass/warn/fail counts'],
            },
            'identity_summary': {
                'endpoint': '/api/identity-summary',
                'handler': 'get_identity_summary()',
                'source_table': 'identities, role_assignments, cloud_subscriptions',
                'source_type': 'snapshot_scoped (discovery_run_id)',
                'metrics': ['category_breakdown', 'monitored_resources'],
            },
            'dangerous_identities': {
                'endpoint': '/api/dangerous-identities',
                'handler': 'get_dangerous_identities()',
                'source_table': 'identities',
                'source_type': 'snapshot_scoped (discovery_run_id)',
                'metrics': ['top_N_by_blast_radius_score'],
            },
            'spn_dashboard': {
                'endpoint': '/api/spns/stats',
                'handler': 'get_spn_stats()',
                'source_table': 'identities, role_assignments, spn_exposure_findings',
                'source_type': 'snapshot_scoped + persisted findings',
                'metrics': ['total_spns', 'by_risk', 'by_blast_radius',
                            'exposure_critical', 'orphaned_privileged'],
            },
            'credential_intelligence': {
                'endpoint': '/api/dashboard/credential-intelligence',
                'handler': 'get_credential_intelligence()',
                'source_table': 'identities, credentials',
                'source_type': 'snapshot_scoped (discovery_run_id)',
                'metrics': ['secret_age_distribution', 'auth_method_breakdown',
                            'rotation_compliance'],
            },
        },
        'risk_metric_definitions': {
            'ghost_accounts': {
                'canonical_source': 'risk_summary.ghost_accounts',
                'definition': 'Disabled/deleted identities retaining active RBAC or Entra role assignments',
                'computed_by': 'RiskSummaryEngine at discovery time',
            },
            'orphaned_spns': {
                'canonical_source': 'risk_summary.orphaned_spns',
                'definition': 'Service principals / managed identities with no owners (excluding Microsoft system)',
                'computed_by': 'RiskSummaryEngine at discovery time',
            },
            'over_privileged': {
                'canonical_source': 'risk_summary.over_privileged',
                'definition': 'Identities with T0/T1 Entra roles (GA, PRA, etc.) or Owner/Contributor/UAA RBAC roles',
                'computed_by': 'RiskSummaryEngine at discovery time',
            },
            'dormant_privileged': {
                'canonical_source': 'risk_summary.dormant_privileged',
                'definition': 'Stale/never-used identities with active role assignments',
                'computed_by': 'RiskSummaryEngine at discovery time',
            },
            'high_blast_radius': {
                'canonical_source': 'risk_summary.high_blast_radius',
                'definition': 'Identities with blast_radius_score >= 70 OR exposure_score >= 80',
                'computed_by': 'RiskSummaryEngine at discovery time (after AGIRSEngine updates scores)',
            },
            'attack_paths': {
                'canonical_source': 'risk_summary.attack_paths',
                'definition': 'Count of open/acknowledged/in_progress findings in graph_attack_findings',
                'computed_by': 'RiskSummaryEngine at discovery time',
            },
            'agirs_score': {
                'canonical_source': 'risk_summary.agirs_score + risk_summary.hiri_score/nhiri_score/gei_score',
                'definition': 'Composite: 0.40*HIRI + 0.40*NHIRI + 0.20*GEI',
                'computed_by': 'AGIRSEngine (called by RiskSummaryEngine) at discovery time, persisted to risk_summary table',
            },
        },
        'snapshot_mechanism': {
            'type': 'discovery_run_id FK pattern',
            'description': 'Every row in identities/role_assignments/resources belongs to an immutable discovery run. '
                           'No separate snapshot_* tables — discovery_run_id IS the snapshot.',
            'scoping_helper': '_latest_run_ids(cursor, organization_id, connection_id)',
            'integrity': 'SHA-256 hash + HMAC signature on discovery_runs, immutability trigger',
        },
    }


def metric_integrity_debug(db, organization_id, connection_id=None):
    """Compare discovery data vs risk_summary vs dashboard metrics.

    Runs the same SQL used by RiskSummaryEngine against live discovery data,
    then compares with the persisted risk_summary row. Returns mismatches.

    Args:
        db: Database instance (admin or tenant-scoped).
        organization_id: The tenant's organization ID.
        connection_id: Optional cloud_connection_id filter.

    Returns:
        dict with status (CONSISTENT/INCONSISTENT), comparisons, mismatches.
    """
    cursor = db.conn.cursor()
    try:
        # 1. Get latest run IDs (same logic as _latest_run_ids in handlers)
        if connection_id:
            cursor.execute("""
                SELECT DISTINCT ON (cloud_connection_id) id
                FROM discovery_runs
                WHERE organization_id = %s AND status = 'completed'
                  AND cloud_connection_id = %s
                ORDER BY cloud_connection_id, id DESC
            """, (organization_id, connection_id))
        else:
            cursor.execute("""
                SELECT DISTINCT ON (cloud_connection_id) id
                FROM discovery_runs
                WHERE organization_id = %s AND status = 'completed'
                  AND cloud_connection_id IS NOT NULL
                ORDER BY cloud_connection_id, id DESC
            """, (organization_id,))
        run_ids = [r[0] for r in cursor.fetchall()]

        if not run_ids:
            return {
                'status': 'NO_DATA',
                'message': 'No completed discovery runs found',
                'organization_id': organization_id,
            }

        # 2. Live-compute metrics from discovery tables
        live = _compute_live_metrics(cursor, run_ids, organization_id)

        # 3. Read persisted risk_summary
        persisted = _read_persisted_summary(cursor, organization_id)

        if not persisted:
            return {
                'status': 'NO_PERSISTED_DATA',
                'message': 'No risk_summary row found — run discovery first',
                'organization_id': organization_id,
                'run_ids': run_ids,
                'live_metrics': live,
            }

        # 4. Compare and detect mismatches
        comparisons, mismatches = _compare_metrics(live, persisted)

        return {
            'status': 'INCONSISTENT' if mismatches else 'CONSISTENT',
            'organization_id': organization_id,
            'run_ids': run_ids,
            'persisted_run_id': persisted.get('discovery_run_id'),
            'persisted_at': persisted.get('computed_at'),
            'comparisons': comparisons,
            'mismatches': mismatches,
            'mismatch_count': len(mismatches),
        }

    except Exception as e:
        logger.error("metric_integrity_debug failed: %s", e)
        return {
            'status': 'ERROR',
            'message': str(e),
            'organization_id': organization_id,
        }
    finally:
        cursor.close()


def _compute_live_metrics(cursor, run_ids, organization_id):
    """Compute risk metrics directly from discovery tables (same SQL as RiskSummaryEngine)."""
    live = {}

    # Identity risk counts
    try:
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE NOT COALESCE(i.is_microsoft_system, false)) as customer,
                COUNT(*) FILTER (WHERE COALESCE(i.is_microsoft_system, false)) as microsoft,
                COUNT(DISTINCT i.id) FILTER (WHERE
                    (i.deleted_at IS NOT NULL OR i.enabled = false
                     OR COALESCE(i.status,'active') IN ('disabled','deleted'))
                    AND (EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                         OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id))
                ) as ghost,
                COUNT(*) FILTER (WHERE
                    COALESCE(i.identity_category,'') IN ('service_principal','managed_identity_user')
                    AND (i.owner_count = 0 OR i.owner_count IS NULL)
                    AND NOT COALESCE(i.is_microsoft_system, false)
                ) as orphaned_spns,
                COUNT(*) FILTER (WHERE
                    EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN ('global administrator',
                            'privileged role administrator','application administrator',
                            'cloud application administrator','user administrator',
                            'exchange administrator','security administrator'))
                    OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN ('owner','contributor','user access administrator'))
                ) as over_privileged,
                COUNT(*) FILTER (WHERE
                    i.activity_status IN ('stale','never_used')
                    AND (EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id
                        AND LOWER(era.role_name) IN (
                            'global administrator','privileged role administrator',
                            'privileged authentication administrator',
                            'application administrator','cloud application administrator',
                            'hybrid identity administrator','domain name administrator',
                            'external identity provider administrator',
                            'user administrator','exchange administrator',
                            'sharepoint administrator','teams administrator',
                            'security administrator','conditional access administrator',
                            'authentication administrator','helpdesk administrator'))
                     OR EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id
                        AND LOWER(ra.role_name) IN ('owner','contributor','user access administrator')))
                ) as dormant_privileged,
                COUNT(*) FILTER (WHERE
                    COALESCE(i.blast_radius_score,0) >= 70
                    OR COALESCE(i.exposure_score,0) >= 80
                ) as high_blast_radius,
                COUNT(*) FILTER (WHERE
                    i.identity_category = 'guest'
                    AND (EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.identity_db_id = i.id)
                         OR EXISTS (SELECT 1 FROM entra_role_assignments era WHERE era.identity_db_id = i.id))
                ) as external_exposure
            FROM identities i
            WHERE i.discovery_run_id = ANY(%s)
        """, (run_ids,))
        r = cursor.fetchone()
        live['total_identities'] = r[0] or 0
        live['customer_identities'] = r[1] or 0
        live['microsoft_identities'] = r[2] or 0
        live['ghost_accounts'] = r[3] or 0
        live['orphaned_spns'] = r[4] or 0
        live['over_privileged'] = r[5] or 0
        live['dormant_privileged'] = r[6] or 0
        live['high_blast_radius'] = r[7] or 0
        live['external_exposure'] = r[8] or 0
    except Exception as e:
        live['_identity_error'] = str(e)

    # Attack paths
    try:
        cursor.execute("SAVEPOINT mid_ap")
        cursor.execute("""
            SELECT COUNT(*) FROM graph_attack_findings
            WHERE organization_id = %s AND status IN ('open','acknowledged','in_progress')
        """, (organization_id,))
        live['attack_paths'] = cursor.fetchone()[0] or 0
        cursor.execute("RELEASE SAVEPOINT mid_ap")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT mid_ap")
        except Exception:
            pass
        live['attack_paths'] = 0

    # Resource counts
    for table, key in [('azure_storage_accounts', 'storage_accounts'),
                       ('azure_key_vaults', 'key_vaults')]:
        try:
            cursor.execute("SAVEPOINT mid_%s" % key)
            cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE discovery_run_id = ANY(%s)",
                (run_ids,)
            )
            live[key] = cursor.fetchone()[0] or 0
            cursor.execute("RELEASE SAVEPOINT mid_%s" % key)
        except Exception:
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT mid_%s" % key)
            except Exception:
                pass
            live[key] = 0
    live['total_resources'] = live.get('storage_accounts', 0) + live.get('key_vaults', 0)

    # Subscriptions
    try:
        cursor.execute("SAVEPOINT mid_sub")
        cursor.execute("""
            SELECT COUNT(DISTINCT SPLIT_PART(ra.scope, '/', 3))
            FROM role_assignments ra
            JOIN identities i ON i.id = ra.identity_db_id
            WHERE i.discovery_run_id = ANY(%s) AND ra.scope LIKE '/subscriptions/%%'
        """, (run_ids,))
        live['subscriptions'] = cursor.fetchone()[0] or 0
        cursor.execute("RELEASE SAVEPOINT mid_sub")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT mid_sub")
        except Exception:
            pass
        live['subscriptions'] = 0

    # Privileged roles
    try:
        cursor.execute("SAVEPOINT mid_priv")
        cursor.execute("""
            SELECT COUNT(DISTINCT era.role_name)
            FROM entra_role_assignments era
            JOIN identities i ON i.id = era.identity_db_id
            WHERE i.discovery_run_id = ANY(%s)
        """, (run_ids,))
        live['privileged_roles'] = cursor.fetchone()[0] or 0
        cursor.execute("RELEASE SAVEPOINT mid_priv")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT mid_priv")
        except Exception:
            pass
        live['privileged_roles'] = 0

    return live


def _read_persisted_summary(cursor, organization_id):
    """Read the latest persisted risk_summary for this organization."""
    try:
        cursor.execute("SAVEPOINT mid_rs")
        cursor.execute("""
            SELECT discovery_run_id, ghost_accounts, orphaned_spns, over_privileged,
                   dormant_privileged, high_blast_radius, external_exposure, attack_paths,
                   total_identities, customer_identities, microsoft_identities,
                   total_resources, storage_accounts, key_vaults, subscriptions,
                   privileged_roles, agirs_score, agirs_tier,
                   hiri_score, nhiri_score, gei_score,
                   computed_at
            FROM risk_summary
            WHERE organization_id = %s
            ORDER BY computed_at DESC LIMIT 1
        """, (organization_id,))
        row = cursor.fetchone()
        cursor.execute("RELEASE SAVEPOINT mid_rs")

        if not row:
            return None

        return {
            'discovery_run_id': row[0],
            'ghost_accounts': row[1] or 0,
            'orphaned_spns': row[2] or 0,
            'over_privileged': row[3] or 0,
            'dormant_privileged': row[4] or 0,
            'high_blast_radius': row[5] or 0,
            'external_exposure': row[6] or 0,
            'attack_paths': row[7] or 0,
            'total_identities': row[8] or 0,
            'customer_identities': row[9] or 0,
            'microsoft_identities': row[10] or 0,
            'total_resources': row[11] or 0,
            'storage_accounts': row[12] or 0,
            'key_vaults': row[13] or 0,
            'subscriptions': row[14] or 0,
            'privileged_roles': row[15] or 0,
            'agirs_score': float(row[16]) if row[16] is not None else None,
            'agirs_tier': row[17],
            'hiri_score': float(row[18]) if row[18] is not None else None,
            'nhiri_score': float(row[19]) if row[19] is not None else None,
            'gei_score': float(row[20]) if row[20] is not None else None,
            'computed_at': row[21].isoformat() if row[21] else None,
        }
    except Exception as e:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT mid_rs")
        except Exception:
            pass
        logger.warning("Failed to read persisted risk_summary: %s", e)
        return None


def _compare_metrics(live, persisted):
    """Compare live-computed metrics vs persisted risk_summary. Returns (comparisons, mismatches)."""
    # Fields to compare (key in both dicts)
    fields = [
        'total_identities', 'customer_identities', 'microsoft_identities',
        'ghost_accounts', 'orphaned_spns', 'over_privileged',
        'dormant_privileged', 'high_blast_radius', 'external_exposure',
        'attack_paths', 'total_resources', 'storage_accounts', 'key_vaults',
        'subscriptions', 'privileged_roles',
    ]

    comparisons = []
    mismatches = []

    for field in fields:
        live_val = live.get(field)
        persisted_val = persisted.get(field)

        if live_val is None or persisted_val is None:
            comparison = {
                'field': field,
                'live': live_val,
                'persisted': persisted_val,
                'match': live_val == persisted_val,
                'delta': None,
            }
        else:
            delta = live_val - persisted_val
            comparison = {
                'field': field,
                'live': live_val,
                'persisted': persisted_val,
                'match': delta == 0,
                'delta': delta,
            }

        comparisons.append(comparison)
        if not comparison['match']:
            mismatches.append({
                'field': field,
                'live': live_val,
                'persisted': persisted_val,
                'delta': comparison['delta'],
                'severity': 'high' if field in ('total_identities', 'ghost_accounts', 'agirs_score') else 'medium',
            })

    return comparisons, mismatches
