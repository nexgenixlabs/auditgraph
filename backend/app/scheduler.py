"""
AuditGraph Scheduled Discovery

This module manages automated background discovery runs using APScheduler.
It provides functions to start, stop, and manually trigger discovery jobs,
enabling continuous monitoring of Azure identity security posture.

Key Functions:
    - start_scheduler(): Initialize and start the background scheduler
    - stop_scheduler(): Gracefully shutdown the scheduler
    - run_scheduled_discovery(): Execute a discovery run (called by scheduler)
    - trigger_manual_discovery(): Immediately run discovery (API endpoint)
    - get_next_run_time(): Get the next scheduled execution time

Schedule Configuration:
    - Discovery interval configurable via DISCOVERY_INTERVAL_HOURS env var (default: 12)
    - Supported values: 6, 12, 24 hours
    - Job ID: 'scheduled_discovery'
    - Timezone: UTC

Lifecycle Management:
    - Scheduler is started when Flask app initializes (create_app)
    - Scheduler is stopped via atexit hook on app shutdown
    - Singleton pattern prevents multiple scheduler instances

Error Handling:
    - Discovery failures are logged but don't crash the scheduler
    - Missing credentials are logged and the job exits gracefully
    - Email notifications sent when identity changes are detected

Usage:
    # Typically called from main.py
    from app.scheduler import start_scheduler, stop_scheduler
    start_scheduler()
    atexit.register(stop_scheduler)
"""
import os
import json
import logging
import threading
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from app.config import AZURE_DISCOVERY_ENABLED, AWS_DISCOVERY_ENABLED

if AZURE_DISCOVERY_ENABLED:
    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
else:
    AzureDiscoveryEngine = None
from app.engines.drift_detector import DriftDetector
from app.engines.anomaly_detector import AnomalyDetector
from app.services.email_service import EmailService
from app.database import Database
from app.engines.platform_health import (
    DISCOVERY_JOB, GRAPH_BUILD_JOB, FINDINGS_ANALYSIS_JOB, RISK_SCORE_JOB,
)
from typing import Dict


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Phase 78: Scan mode definitions
SCAN_MODES = {
    'quick': {
        'label': 'Quick Scan',
        'description': 'Identities only — fastest, lightweight check',
        'skip_roles': True,
        'skip_credentials': True,
        'skip_pim': True,
        'skip_ca': True,
        'skip_resources': True,
    },
    'standard': {
        'label': 'Standard Scan',
        'description': 'Identities + roles + credentials — recommended for daily runs',
        'skip_roles': False,
        'skip_credentials': False,
        'skip_pim': True,
        'skip_ca': True,
        'skip_resources': True,
    },
    'deep': {
        'label': 'Deep Audit',
        'description': 'Full audit — identities, roles, credentials, PIM, CA, resources',
        'skip_roles': False,
        'skip_credentials': False,
        'skip_pim': False,
        'skip_ca': False,
        'skip_resources': False,
    },
}


def run_scheduled_discovery(scan_mode: str = 'deep'):
    """
    Runs the discovery process for ALL enabled organizations.
    Each organization's Azure credentials are read from org-scoped settings.
    Called by the scheduler.
    """
    logger.info("=" * 70)
    logger.info("SCHEDULED DISCOVERY STARTED (multi-org)")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    # Get list of enabled organizations
    admin_db = Database()  # No org context → superadmin/startup path
    try:
        cursor = admin_db.conn.cursor()
        cursor.execute("SELECT id, name FROM organizations WHERE enabled = TRUE ORDER BY id")
        orgs = cursor.fetchall()
        cursor.close()
    finally:
        admin_db.close()

    if not orgs:
        logger.warning("No enabled organizations found, skipping discovery")
        return

    for db_org_id, org_name in orgs:
        logger.info(f"▶ Running discovery for organization: {org_name} (id={db_org_id})")
        try:
            _track_job(DISCOVERY_JOB, db_org_id,
                       _run_org_discovery, db_org_id, org_name, scan_mode)
        except Exception as e:
            logger.error(f"❌ Discovery FAILED for organization {org_name}: {str(e)}")
            logger.exception(e)
            _dispatch_notification('scan_failed', {
                'title': f'Discovery Scan Failed — {org_name}',
                'description': f'Discovery failed for organization {org_name}: {str(e)[:200]}',
                'severity': 'critical',
            }, db_org_id=db_org_id)
        # CONTEXT SAFETY: Reset any lingering org context after each iteration.
        # Each _run_org_discovery creates/closes its own Database connections,
        # but this ensures no thread-local state leaks between org iterations.

    logger.info("=" * 70)
    logger.info("SCHEDULED DISCOVERY COMPLETED (all organizations)")
    logger.info("=" * 70)


def _run_org_discovery(db_org_id: int, org_name: str, scan_mode: str = 'deep',
                       connection_id: int = None):
    """Run discovery for a single organization using their cloud connections.
    If connection_id is provided, only scan that specific connection.
    Otherwise scan ALL connected connections for the organization.
    Requires at least one connected cloud_connection — legacy settings path is deprecated.
    """
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    import time as _time

    # Demo tenant guard — block real cloud discovery for demo orgs
    admin_db = Database()
    try:
        org = admin_db.get_organization_by_id(db_org_id)
        if org and org.get('is_demo'):
            logger.info("SNAPSHOT_SKIP tenant_id=%d org=%s reason=demo_tenant", db_org_id, org_name)
            admin_db.close()
            return
        connections = admin_db.get_cloud_connections(db_org_id,
                                                     include_secrets=True)
    finally:
        admin_db.close()

    # Filter to specific connection if requested
    if connection_id:
        connections = [c for c in connections if c['id'] == connection_id]
        if not connections:
            logger.warning("SNAPSHOT_SKIP tenant_id=%d org=%s reason=connection_not_found connection_id=%d",
                          db_org_id, org_name, connection_id)
            return

    # Filter to only connected connections
    connected = [c for c in connections if c.get('status') == 'connected']

    if not connected:
        logger.warning(
            "SNAPSHOT_SKIP tenant_id=%d org=%s reason=no_connected_connections",
            db_org_id, db_org_id
        )
        return

    # Phase 7: Create org-level snapshot_run
    snapshot_run_id = None
    try:
        sr_db = Database()
        snapshot_run_id = sr_db.create_snapshot_run(
            organization_id=db_org_id,
            scan_mode=scan_mode,
            connections_total=len(connected),
            triggered_by='scheduler',
        )
        sr_db.close()
        logger.info("SNAPSHOT_RUN_START snapshot_run_id=%s tenant_id=%d org=%s connections=%d scan_mode=%s",
                    snapshot_run_id, db_org_id, org_name, len(connected), scan_mode)
    except Exception as e:
        logger.warning("SNAPSHOT_RUN_CREATE_FAILED tenant_id=%d error=%s", db_org_id, str(e)[:200])

    run_start = _time.monotonic()
    conn_completed = 0
    conn_failed = 0
    total_identities = 0
    total_spns = 0
    total_roles = 0

    for conn in connected:
        try:
            _run_connection_discovery(db_org_id, org_name, conn, scan_mode)
            conn_completed += 1
            # Collect metrics from the latest discovery run
            try:
                mdb = Database()
                cursor = mdb.conn.cursor()
                cursor.execute("""
                    SELECT total_identities, critical_count, high_count
                    FROM discovery_runs
                    WHERE organization_id = %s AND status = 'completed'
                    ORDER BY id DESC LIMIT 1
                """, (db_org_id,))
                dr = cursor.fetchone()
                if dr:
                    total_identities += (dr[0] or 0)
                # Count SPNs
                cursor.execute("""
                    SELECT COUNT(*) FROM identities
                    WHERE discovery_run_id = (
                        SELECT id FROM discovery_runs
                        WHERE organization_id = %s AND status = 'completed'
                        ORDER BY id DESC LIMIT 1
                    ) AND identity_category = 'service_principal'
                """, (db_org_id,))
                spn_row = cursor.fetchone()
                total_spns += (spn_row[0] or 0) if spn_row else 0
                cursor.close()
                mdb.close()
            except Exception:
                pass
        except Exception as e:
            conn_failed += 1
            logger.error("SNAPSHOT_CONNECTION_FAILED tenant_id=%d org=%s connection_id=%d error=%s",
                        db_org_id, org_name, conn['id'], str(e)[:200])

    # Phase 7: Complete snapshot_run
    elapsed = _time.monotonic() - run_start
    run_status = 'failed' if conn_failed == len(connected) else 'completed'
    error_msg = None
    if conn_failed > 0:
        error_msg = f"{conn_failed}/{len(connected)} connections failed"
        if conn_completed > 0:
            run_status = 'completed'  # partial success

    if snapshot_run_id:
        try:
            sr_db = Database()
            sr_db.complete_snapshot_run(
                snapshot_run_id, status=run_status, error_message=error_msg,
                identities_found=total_identities, spns_found=total_spns,
                roles_found=total_roles, connections_completed=conn_completed,
                connections_failed=conn_failed,
            )
            sr_db.close()
            logger.info(
                "SNAPSHOT_RUN_COMPLETE snapshot_run_id=%s tenant_id=%d status=%s "
                "duration=%.1fs identities=%d spns=%d connections_ok=%d connections_fail=%d",
                snapshot_run_id, db_org_id, run_status, elapsed,
                total_identities, total_spns, conn_completed, conn_failed
            )
        except Exception as e:
            logger.warning("SNAPSHOT_RUN_COMPLETE_FAILED snapshot_run_id=%s error=%s",
                          snapshot_run_id, str(e)[:200])

    # Phase 7: Create alert on failure
    if conn_failed > 0:
        severity = 'critical' if conn_failed == len(connected) else 'warning'
        try:
            alert_db = Database()
            alert_db.create_snapshot_alert(
                organization_id=db_org_id,
                severity=severity,
                message=f"Snapshot {'fully' if run_status == 'failed' else 'partially'} failed for {org_name}: {error_msg}",
                alert_type='snapshot_failure',
                snapshot_run_id=snapshot_run_id,
                metadata={'connections_failed': conn_failed, 'connections_total': len(connected)},
            )
            alert_db.close()
            logger.info("SNAPSHOT_ALERT_CREATED tenant_id=%d severity=%s snapshot_run_id=%s",
                        db_org_id, severity, snapshot_run_id)
        except Exception as e:
            logger.warning("SNAPSHOT_ALERT_CREATE_FAILED tenant_id=%d error=%s", db_org_id, str(e)[:200])

    if run_status == 'failed':
        return  # Skip post-pipeline steps on total failure

    logger.info("SNAPSHOT_COMPLETE tenant_id=%d org=%s duration=%.1fs", db_org_id, org_name, elapsed)

    # Log activity (with organization context)
    try:
        act_db = Database(organization_id=db_org_id)
        act_db.log_activity('discovery_completed', f'Scheduled discovery run completed for {org_name}')
        act_db.close()
    except Exception:
        pass

    # Auto-advance onboarding stage to 'active' after first successful discovery
    try:
        admin_db = Database()
        org = admin_db.get_organization_by_id(db_org_id)
        if org and org.get('onboarding_stage') in ('connections', 'locked', 'authenticating', 'password_change'):
            admin_db.update_organization(db_org_id, onboarding_stage='active')
            logger.info(f"  ✓ Organization {org_name} onboarding stage advanced to 'active'")
        admin_db.close()
    except Exception as e:
        logger.warning(f"  ⚠ Failed to advance onboarding stage for {org_name}: {e}")

    # Check for identity changes and send email notification
    _send_change_notification_if_needed(db_org_id=db_org_id)

    # Prune old identity runs to prevent unbounded accumulation
    # (keep latest 2 completed runs per connection for drift detection)
    try:
        prune_db = Database()
        result = prune_db.prune_old_identity_runs(db_org_id, keep_latest=2)
        prune_db.close()
        if result['identities_deleted'] > 0:
            logger.info("IDENTITY_PRUNE tenant_id=%d deleted=%d runs_archived=%d",
                        db_org_id, result['identities_deleted'], result['runs_pruned'])
    except Exception as e:
        logger.warning("Identity pruning failed for tenant %d: %s", db_org_id, e)

    # Phase 83: Dispatch scan_complete notification
    _dispatch_notification('scan_complete', {
        'title': f'Discovery Scan Complete — {org_name}',
        'description': f'Scheduled discovery run completed for {org_name}.',
        'severity': 'info',
    }, db_org_id=db_org_id)

    # V2.13 (2026-06-12) — persist board scorecard snapshot per discovery run.
    # Migration 220 switched ai_board_scorecard_snapshots from per-day
    # UPSERT to per-run INSERT so multi-scan-per-day cadences (6h, 12h)
    # actually accumulate trend points. A 6h-cadence tenant lights up
    # trend on the 2nd scan; a 24h-cadence tenant on day 2. Without
    # this hook the table stays empty and every trend chart reads
    # "Baseline established. Trend data available after next scan"
    # forever — the bug the founder reported on 2026-06-12.
    try:
        from app.engines.scoring.board_scorecard_engine import persist_board_scorecard_snapshot
        snap_db = Database(organization_id=db_org_id)
        try:
            cur = snap_db.conn.cursor()
            # Latest completed discovery_run for this tenant — used as
            # the per-run identifier so re-firing the hook for the same
            # run does NOT create duplicate snapshots (migration 220
            # adds a partial unique index on (org, discovery_run_id)).
            cur.execute("""
                SELECT id FROM discovery_runs
                WHERE organization_id = %s AND status = 'completed'
                ORDER BY id DESC LIMIT 1
            """, (db_org_id,))
            _row = cur.fetchone()
            _latest_run_id = _row[0] if _row else None
            persist_board_scorecard_snapshot(cur, db_org_id, discovery_run_id=_latest_run_id)
            snap_db.conn.commit()
            cur.close()
        finally:
            snap_db.close()
    except Exception as e:
        logger.warning("board_scorecard snapshot persistence failed tenant=%d: %s", db_org_id, e)

    # Background owned objects enrichment (deferred from main scan pipeline)
    for conn in connected:
        if conn.get('cloud', 'azure') == 'azure':
            _launch_owned_objects_background(db_org_id, conn)

    # Background IP enrichment (deferred from main scan pipeline — saves ~121s)
    for conn in connected:
        if conn.get('cloud', 'azure') == 'azure':
            _launch_ip_enrichment_background(db_org_id, conn)

    # Background sign-in intelligence (deferred from main scan pipeline — saves ~205s)
    for conn in connected:
        if conn.get('cloud', 'azure') == 'azure':
            _launch_signin_intelligence_background(db_org_id, conn)


def _classify_discovery_error(error):
    """Classify a discovery error as retryable or not. Returns (error_type, is_retryable)."""
    msg = str(error).lower()
    if 'throttl' in msg or '429' in msg or 'rate limit' in msg or 'too many requests' in msg:
        return 'throttling', True
    if 'timeout' in msg or 'timed out' in msg or 'connection reset' in msg:
        return 'network_timeout', True
    if 'temporarily unavailable' in msg or '503' in msg or '502' in msg:
        return 'temporary_auth_failure', True
    if 'invalid' in msg and ('credential' in msg or 'secret' in msg or 'client' in msg):
        return 'invalid_credentials', False
    if 'unauthorized' in msg or '401' in msg or 'forbidden' in msg or '403' in msg:
        return 'auth_failure', False
    if 'not found' in msg and 'connection' in msg:
        return 'connection_deleted', False
    return 'unknown', False


def _run_connection_discovery(db_org_id: int, org_name: str, conn: dict, scan_mode: str = 'deep'):
    """Run discovery for a single cloud connection with job lifecycle tracking."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    import time as _time
    if not AZURE_DISCOVERY_ENABLED and conn.get('cloud', 'azure') == 'azure':
        logger.info(f"  ⏭ Azure discovery disabled (APP_ENV=local), skipping connection '{conn.get('label', 'Unknown')}'")
        return
    conn_id = conn['id']
    label = conn.get('label', 'Unknown')
    cloud = conn.get('cloud', 'azure')

    metadata = conn.get('metadata') or {}

    # Decrypt any encrypted credential fields in metadata
    from app.encryption import decrypt_field
    for _cred_key in ('client_secret', 'secret_access_key'):
        if _cred_key in metadata:
            metadata[_cred_key] = decrypt_field(metadata[_cred_key])

    # Phase 3: Concurrency guard — skip if a job is already active for this connection
    job_id = None
    try:
        guard_db = Database()
        active = guard_db.get_active_snapshot_job(conn_id, org_id=db_org_id)
        guard_db.close()
        if active:
            logger.info(
                "  DISCOVERY_SKIPPED connection_id=%d org_id=%d — active job %s (status=%s)",
                conn_id, db_org_id, active['id'], active['status']
            )
            return
    except Exception as e:
        logger.warning(f"  ⚠ Concurrency guard check failed: {e}")

    # Phase 3: Create snapshot job
    try:
        jdb = Database()
        job_id = jdb.create_snapshot_job(db_org_id, conn_id, scan_mode)
        jdb.close()
        logger.info("  snapshot_job_id=%s created for connection_id=%d", job_id, conn_id)
    except Exception as e:
        logger.warning(f"  ⚠ Failed to create snapshot job: {e}")
        job_id = None

    # Phase 5: Mark snapshot started timestamp on connection
    try:
        tsdb = Database()
        tsdb.update_snapshot_timestamps(conn_id, started=True)
        tsdb.close()
    except Exception:
        pass

    start_time = _time.monotonic()
    logger.info(
        "  DISCOVERY_START connection_id=%d org_id=%d cloud=%s label=%s snapshot_job_id=%s",
        conn_id, db_org_id, cloud, label, job_id
    )

    if cloud == 'azure':
        azure_directory_id = conn.get('azure_directory_id')
        client_id = conn.get('client_id')
        client_secret = metadata.get('client_secret')
        if not all([azure_directory_id, client_id, client_secret]):
            logger.warning(f"  ⏭ Skipping '{label}' — incomplete Azure credentials")
            if job_id:
                try:
                    fdb = Database()
                    fdb.complete_snapshot_job(job_id, 'failed', 'Incomplete Azure credentials')
                    fdb.close()
                except Exception:
                    pass
            return
        engine = AzureDiscoveryEngine(
            azure_directory_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
            db_org_id=db_org_id,
            cloud_connection_id=conn_id,
        )
        client_secret = None  # AG-116: zero after SDK init — prevent memory retention
    elif cloud == 'aws':
        if not AWS_DISCOVERY_ENABLED:
            logger.info(f"  ⏭ AWS discovery disabled (APP_ENV=local), skipping connection '{label}'")
            if job_id:
                try:
                    fdb = Database()
                    fdb.complete_snapshot_job(job_id, 'failed', 'AWS discovery disabled')
                    fdb.close()
                except Exception:
                    pass
            return
        access_key_id = metadata.get('access_key_id') or conn.get('client_id')
        secret_access_key = metadata.get('secret_access_key') or metadata.get('client_secret')
        region = metadata.get('region', 'us-east-1')
        if not all([access_key_id, secret_access_key]):
            logger.warning(f"  ⏭ Skipping '{label}' — incomplete AWS credentials")
            if job_id:
                try:
                    fdb = Database()
                    fdb.complete_snapshot_job(job_id, 'failed', 'Incomplete AWS credentials')
                    fdb.close()
                except Exception:
                    pass
            return
        from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
        engine = AWSDiscoveryEngine(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region=region,
            db_org_id=db_org_id,
            cloud_connection_id=conn_id,
        )
    else:
        logger.info(f"  ⏭ Skipping unsupported cloud '{cloud}' for connection '{label}'")
        if job_id:
            try:
                fdb = Database()
                fdb.complete_snapshot_job(job_id, 'failed', f'Unsupported cloud: {cloud}')
                fdb.close()
            except Exception:
                pass
        return

    # Phase 3: Inject job_id into engine for progress reporting
    if job_id:
        engine.snapshot_job_id = job_id

    subs_count = len(getattr(engine, 'subscriptions', []))
    logger.info(
        "    ✓ %s engine initialized for '%s' subscriptions_found=%d",
        cloud.upper(), label, subs_count
    )

    # Phase 3: Start job (queued→running)
    if job_id:
        try:
            sdb = Database()
            sdb.start_snapshot_job(job_id, started_by='scheduler')
            sdb.close()
        except Exception as e:
            logger.warning(f"  ⚠ Failed to start snapshot job: {e}")

    # Phase 4: Heartbeat thread — sends heartbeat every 20s while discovery runs
    import threading
    heartbeat_stop = threading.Event()

    def _heartbeat_loop():
        while not heartbeat_stop.is_set():
            if heartbeat_stop.wait(timeout=20):
                break
            if job_id:
                try:
                    hdb = Database()
                    hdb.update_snapshot_job_heartbeat(job_id)
                    hdb.close()
                except Exception:
                    pass

    heartbeat_thread = None
    if job_id:
        heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
        heartbeat_thread.start()

    # Phase 1 Security: Audit log snapshot_started
    try:
        act_db = Database(organization_id=db_org_id)
        act_db.log_activity('snapshot_started',
                            f'Discovery scan started for connection "{label}" ({cloud})',
                            {'connection_id': conn_id, 'cloud': cloud, 'scan_mode': scan_mode,
                             'snapshot_job_id': job_id})
        act_db.close()
    except Exception:
        pass

    try:
        from app.resilience import resilient_call, CircuitBreakerOpenError
        breaker_name = f'{cloud}_api'
        try:
            resilient_call(breaker_name, engine.run_discovery)
        except CircuitBreakerOpenError:
            logger.error(
                "  DISCOVERY_BLOCKED connection_id=%d cloud=%s — circuit breaker OPEN",
                conn_id, cloud,
            )
            if job_id:
                try:
                    fdb = Database()
                    fdb.complete_snapshot_job(job_id, 'failed', f'{cloud} API circuit breaker open')
                    fdb.close()
                except Exception:
                    pass
            return
        elapsed = _time.monotonic() - start_time
        logger.info(
            "  DISCOVERY_COMPLETE connection_id=%d org_id=%d cloud=%s duration=%.1fs snapshot_job_id=%s",
            conn_id, db_org_id, cloud, elapsed, job_id
        )

        # Phase 4: Record metrics + mark completed
        if job_id:
            try:
                cdb = Database()
                # Collect metrics from engine
                ident_count = getattr(engine, '_identities_saved_count', 0) or len(getattr(engine, '_identities', []))
                res_count = getattr(engine, '_resources_saved_count', 0)
                sub_count = len(getattr(engine, 'subscriptions', []))
                cdb.update_snapshot_job_metrics(job_id, identities=ident_count,
                                                resources=res_count, subscriptions=sub_count)
                cdb.complete_snapshot_job(job_id, 'completed')
                cdb.close()
            except Exception as e:
                logger.warning(f"  ⚠ Failed to complete snapshot job: {e}")

        # ── Pipeline health metrics collection ──
        # Captures stage-level ingestion counts from the discovery engine
        # to detect silent persistence failures (like the Entra role bug).
        try:
            _collect_discovery_pipeline_metrics(engine, db_org_id, conn_id)
        except Exception as _phm_err:
            logger.debug("Pipeline health metrics collection failed (non-blocking): %s", _phm_err)

        # Invalidate CISO dashboard cache after discovery completes
        try:
            from app.api.handlers import _ciso_cache_invalidate
            _ciso_cache_invalidate(db_org_id)
        except Exception:
            pass  # non-critical — cache will expire via TTL
    except Exception as e:
        elapsed = _time.monotonic() - start_time
        error_type, is_retryable = _classify_discovery_error(e)
        logger.error(
            "  DISCOVERY_FAILED connection_id=%d org_id=%d cloud=%s duration=%.1fs error=%s error_type=%s retryable=%s snapshot_job_id=%s",
            conn_id, db_org_id, cloud, elapsed, str(e)[:200], error_type, is_retryable, job_id
        )

        # Phase 4/7: Mark job failed with error classification + exponential backoff retry
        if job_id:
            try:
                fdb = Database()
                fdb.complete_snapshot_job(job_id, 'failed', str(e)[:500], error_type=error_type)
                # Phase 7: Auto-retry with exponential backoff for retryable errors
                if is_retryable:
                    retry_result = fdb.retry_snapshot_job_with_backoff(job_id)
                    if retry_result:
                        logger.info(
                            "DISCOVERY_RETRY_SCHEDULED job=%s retry_count=%d "
                            "delay_seconds=%d error_type=%s tenant_id=%d",
                            job_id, retry_result['retry_count'],
                            retry_result['delay_seconds'], error_type, db_org_id
                        )
                    else:
                        logger.warning(
                            "DISCOVERY_RETRY_EXHAUSTED job=%s tenant_id=%d error_type=%s",
                            job_id, db_org_id, error_type
                        )
                # Phase 7: Create snapshot alert on connection failure
                try:
                    severity = 'critical' if not is_retryable else 'warning'
                    fdb.create_snapshot_alert(
                        organization_id=db_org_id,
                        severity=severity,
                        message=f"Discovery failed for connection '{label}' ({cloud}): {str(e)[:200]}",
                        alert_type='connection_failure',
                        snapshot_job_id=job_id,
                        metadata={
                            'connection_id': conn_id, 'cloud': cloud,
                            'error_type': error_type, 'retryable': is_retryable,
                            'duration_seconds': round(elapsed, 1),
                        },
                    )
                except Exception:
                    pass
                # Update connection status on credential/auth failures
                if error_type in ('invalid_credentials', 'auth_failure'):
                    try:
                        fdb.update_cloud_connection(conn_id,
                            status='auth_failed',
                            last_test_status='failed',
                            last_test_at=datetime.utcnow())
                        logger.warning(
                            "CONNECTION_STATUS_DEGRADED connection_id=%d status=auth_failed error_type=%s",
                            conn_id, error_type)
                    except Exception:
                        pass
                fdb.close()
            except Exception as fe:
                logger.warning("DISCOVERY_FAIL_TRACK_ERROR job=%s error=%s", job_id, str(fe)[:200])
        raise
    finally:
        # Phase 4: Stop heartbeat thread
        heartbeat_stop.set()
        if heartbeat_thread:
            heartbeat_thread.join(timeout=5)

    # Update last_discovery_at + last_snapshot_completed_at on the connection
    try:
        admin_db = Database()
        admin_db.update_cloud_connection(conn_id, last_discovery_at=datetime.utcnow())
        admin_db.update_snapshot_timestamps(conn_id, completed=True)
        admin_db.close()
    except Exception as e:
        logger.warning(f"    ⚠ Failed to update last_discovery_at for connection {conn_id}: {e}")


def _run_legacy_settings_discovery(db_org_id: int, org_name: str, scan_mode: str = 'deep'):
    """DEPRECATED: Legacy settings-based discovery no longer supported."""
    logger.warning(
        "  ⚠ DEPRECATED: Legacy settings discovery skipped for %s. "
        "Configure cloud_connections for org %d.", org_name, db_org_id
    )
    return


def _collect_discovery_pipeline_metrics(engine, db_org_id: int, conn_id: int):
    """Collect pipeline health metrics from the completed discovery engine.

    Extracts stage-level counts (fetched/persisted/failed) from engine
    attributes and persists them to pipeline_stage_metrics for health monitoring.
    """
    from app.engines.pipeline_health import PipelineHealthTracker

    # Resolve latest run_id for this org
    mdb = Database()
    try:
        cursor = mdb.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE organization_id = %s AND status = 'completed'
            ORDER BY id DESC LIMIT 1
        """, (db_org_id,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            return
        run_id = row[0]
        cursor.close()

        tracker = PipelineHealthTracker(run_id=run_id, org_id=db_org_id, db=mdb)

        # ── Identity Discovery ──
        identities_fetched = getattr(engine, '_all_principal_count', 0) or len(getattr(engine, '_identities', []))
        identities_saved = getattr(engine, '_identities_saved_count', 0)
        with tracker.stage('identity_discovery') as s:
            s.fetched = identities_fetched
            s.matched = identities_fetched
            s.persisted = identities_saved
            s.failed = max(0, identities_fetched - identities_saved)

        # ── RBAC Collection ──
        rbac_fetched = getattr(engine, '_role_assignments_fetched', 0)
        rbac_saved = getattr(engine, '_role_assignments_saved', 0)
        with tracker.stage('rbac_collection') as s:
            s.fetched = rbac_fetched
            s.matched = rbac_fetched
            s.persisted = rbac_saved
            s.failed = max(0, rbac_fetched - rbac_saved) if rbac_fetched > 0 else 0

        # ── Entra Role Collection ──
        entra_fetched = getattr(engine, '_entra_roles_fetched', 0)
        entra_matched = getattr(engine, '_entra_roles_matched', 0)
        entra_saved = getattr(engine, '_entra_roles_saved', 0)
        entra_failed = getattr(engine, '_entra_roles_failed', 0)
        with tracker.stage('entra_role_collection') as s:
            s.fetched = entra_fetched
            s.matched = entra_matched
            s.persisted = entra_saved
            s.failed = entra_failed

        # ── Credential Collection ──
        creds_fetched = getattr(engine, '_credentials_fetched', 0)
        creds_saved = getattr(engine, '_credentials_saved', 0)
        with tracker.stage('credential_collection') as s:
            s.fetched = creds_fetched
            s.matched = creds_fetched
            s.persisted = creds_saved
            s.failed = max(0, creds_fetched - creds_saved) if creds_fetched > 0 else 0

        # ── App Registration Discovery ──
        apps_fetched = getattr(engine, '_app_registrations_fetched', 0)
        apps_saved = getattr(engine, '_app_registrations_saved', 0)
        with tracker.stage('app_registration_discovery') as s:
            s.fetched = apps_fetched
            s.matched = apps_fetched
            s.persisted = apps_saved
            s.failed = max(0, apps_fetched - apps_saved) if apps_fetched > 0 else 0

        tracker.finalize()

    except Exception as e:
        logger.debug("_collect_discovery_pipeline_metrics error: %s", e)
        try:
            mdb.conn.rollback()
        except Exception:
            pass
    finally:
        mdb.close()


def run_continuous_discovery():
    """Phase 5: Check all cloud connections with continuous discovery enabled.
    Triggers discovery for connections that are due based on their interval.
    Runs every 5 minutes via scheduler."""
    logger.info("🔄 CONTINUOUS_DISCOVERY checking for due connections")
    triggered = 0

    try:
        admin_db = Database()
        due_connections = admin_db.get_connections_due_for_discovery()
        admin_db.close()

        if not due_connections:
            logger.info("  No connections due for continuous discovery")
            return

        logger.info("  Found %d connection(s) due for discovery", len(due_connections))

        for conn in due_connections:
            conn_id = conn['id']
            org_id = conn['organization_id']

            # Look up org name
            try:
                adb = Database()
                org = adb.get_organization_by_id(org_id)
                org_name = org['name'] if org else f'org-{org_id}'
                adb.close()
            except Exception:
                org_name = f'org-{org_id}'

            logger.info("  🔄 CONTINUOUS_TRIGGER connection_id=%d org=%s label=%s interval=%d min",
                         conn_id, org_name, conn.get('label', '?'), conn.get('discovery_interval_minutes', 0))

            try:
                _run_connection_discovery(org_id, org_name, conn, scan_mode='deep')
                triggered += 1
            except Exception as e:
                logger.error("  CONTINUOUS_DISCOVERY_FAILED connection_id=%d error=%s",
                             conn_id, str(e)[:200])

    except Exception as e:
        logger.error("CONTINUOUS_DISCOVERY error: %s", str(e)[:200])

    logger.info("🔄 CONTINUOUS_DISCOVERY complete: triggered=%d", triggered)


def run_stale_execution_recovery():
    """W3: Reset jobs stuck in 'executing' state.
    Runs every 5 minutes. Uses admin connection to scan all orgs."""
    try:
        from app.engines.execution.executor import ExecutionService

        # Admin connection to find stale jobs across all orgs
        db = Database()
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT DISTINCT organization_id
            FROM approval_requests
            WHERE status = 'executing'
        """)
        orgs = cursor.fetchall()
        cursor.close()
        db.close()

        total = 0
        for org_row in orgs:
            org_id = org_row[0] if isinstance(org_row, (tuple, list)) else org_row['organization_id']
            org_db = Database(organization_id=org_id)
            try:
                count = ExecutionService.recover_stale_executions(
                    org_db, stale_threshold_minutes=5)
                total += count
            finally:
                org_db.close()

        if total > 0:
            logger.info("Stale execution recovery: %s jobs reset to queued", total)
    except Exception as e:
        logger.error("Stale recovery scheduler error: %s", e)


def run_snapshot_job_maintenance():
    """Phase 4: Periodic maintenance — detect zombies, enforce runtime limits,
    retry eligible failed jobs. Runs every 5 minutes via scheduler."""
    logger.info("🔧 SNAPSHOT_MAINTENANCE starting")
    recovered = 0
    timed_out = 0
    retried = 0

    try:
        db = Database()

        # 1. Detect and recover zombie jobs (stale heartbeat > 5 minutes)
        zombies = db.get_zombie_snapshot_jobs(stale_minutes=5)
        for z in zombies:
            try:
                db.complete_snapshot_job(z['id'], 'failed',
                                        'Worker heartbeat lost — job recovered by maintenance',
                                        error_type='zombie')
                logger.warning("  ☠ ZOMBIE_RECOVERED job=%s connection=%s stage=%s",
                               z['id'], z.get('cloud_connection_id'), z.get('stage'))
                recovered += 1
            except Exception as e:
                logger.warning(f"  ⚠ Failed to recover zombie job {z['id']}: {e}")

        # 2. Enforce runtime limit (90 minutes max)
        overtime = db.get_runtime_exceeded_jobs(max_runtime_minutes=90)
        for ot in overtime:
            try:
                # Check if partial results exist — mark as 'partial' instead of 'failed'
                run_id = ot.get('discovery_run_id')
                partial_count = 0
                if run_id:
                    try:
                        cnt_cursor = db.conn.cursor()
                        cnt_cursor.execute(
                            "SELECT COUNT(*) FROM identities WHERE discovery_run_id = %s",
                            (run_id,))
                        partial_count = cnt_cursor.fetchone()[0]
                        cnt_cursor.close()
                    except Exception:
                        try:
                            db.conn.rollback()
                        except Exception:
                            pass

                if partial_count > 0:
                    final_status = 'partial'
                    msg = f'Discovery exceeded 90-minute runtime limit ({partial_count} identities saved before timeout)'
                else:
                    final_status = 'failed'
                    msg = 'Discovery exceeded 90-minute runtime limit'

                db.complete_snapshot_job(ot['id'], final_status,
                                        msg,
                                        error_type='runtime_exceeded')
                logger.warning("  ⏰ RUNTIME_EXCEEDED job=%s connection=%s",
                               ot['id'], ot.get('cloud_connection_id'))
                timed_out += 1
            except Exception as e:
                logger.warning(f"  ⚠ Failed to timeout job {ot['id']}: {e}")

        # 3. Retry eligible failed jobs (retryable error types, under max_retries)
        retryable = db.get_retryable_failed_jobs()
        for rj in retryable:
            try:
                new_count = db.retry_snapshot_job(rj['id'])
                if new_count is not None:
                    logger.info("  🔄 MAINTENANCE_RETRY job=%s retry_count=%d error_type=%s",
                                rj['id'], new_count, rj.get('error_type'))
                    retried += 1
            except Exception as e:
                logger.warning(f"  ⚠ Failed to retry job {rj['id']}: {e}")

        db.close()
    except Exception as e:
        logger.error(f"  SNAPSHOT_MAINTENANCE failed: {e}")

    logger.info("🔧 SNAPSHOT_MAINTENANCE complete: recovered=%d timed_out=%d retried=%d",
                recovered, timed_out, retried)


def _send_change_notification_if_needed(db_org_id: int = None):
    """
    Compare discovery runs PER-CONNECTION and send email if changes detected.
    Each connection's latest run is compared against that same connection's
    previous run (not against a different connection's run).
    Called after each successful organization discovery cycle.
    """
    try:
        db = Database(organization_id=db_org_id)

        # Get the two most recent completed runs PER CONNECTION
        # Guard: only compare runs that actually discovered identities
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT cloud_connection_id, id,
                   ROW_NUMBER() OVER (PARTITION BY cloud_connection_id ORDER BY id DESC) as rn
            FROM discovery_runs
            WHERE status = 'completed'
              AND cloud_connection_id IS NOT NULL AND cloud_connection_id > 0
              AND completed_at IS NOT NULL
              AND COALESCE(total_identities, 0) > 0
            ORDER BY cloud_connection_id, id DESC
        """)
        rows = cursor.fetchall()
        cursor.close()

        # Group by connection: {conn_id: [run_ids ordered desc]}
        conn_runs: dict = {}
        for conn_id, run_id, rn in rows:
            if rn <= 2:
                conn_runs.setdefault(conn_id, []).append(run_id)

        # Build per-connection drift pairs
        pairs = []
        for conn_id, run_ids in conn_runs.items():
            if len(run_ids) >= 2:
                pairs.append((conn_id, run_ids[0], run_ids[1]))

        if not pairs:
            logger.info("Not enough per-connection discovery runs for comparison - skipping drift/notification")
            # First scan for this org — no drift pairs, but post-processing
            # (agent classification, attack paths, risk scoring, etc.) must
            # still run.  Resolve current_run_id from the latest completed
            # run so tiered post-processing has a valid reference.
            cursor = db.conn.cursor()
            cursor.execute("""
                SELECT id FROM discovery_runs
                WHERE organization_id = %s AND status = 'completed'
                  AND COALESCE(total_identities, 0) > 0
                ORDER BY id DESC LIMIT 1
            """, (db_org_id,))
            _first_row = cursor.fetchone()
            cursor.close()
            if not _first_row:
                logger.info("No completed discovery run with identities for org %s — skipping post-processing", db_org_id)
                db.close()
                return
            current_run_id = _first_row[0]
            previous_run_id = None

        if pairs:
            # ── Drift detection & notification (requires 2+ runs) ──
            detector = DriftDetector(db)
            changes: dict = {
                'new_identities': [], 'removed_identities': [],
                'microsoft_removed_identities': [],
                'permission_changes': [], 'risk_changes': [], 'credential_changes': [],
            }
            all_events: list = []
            latest_current_run_id = 0
            latest_previous_run_id = 0
            for conn_id, current_run_id, previous_run_id in pairs:
                logger.info(f"Comparing runs for connection {conn_id}: #{current_run_id} vs #{previous_run_id}")
                result = detector.compare_runs_v2(current_run_id, previous_run_id)
                conn_changes = result['legacy']
                conn_events = result['events']

                # Persist per-connection drift report with typed events
                report_id = db.save_drift_report(current_run_id, previous_run_id, conn_changes, events=conn_events)
                logger.info(f"Drift report #{report_id} saved for connection {conn_id} (runs #{current_run_id} vs #{previous_run_id})")

                # Aggregate into combined changes
                for key in changes:
                    changes[key].extend(conn_changes.get(key, []))
                all_events.extend(conn_events)

                if current_run_id > latest_current_run_id:
                    latest_current_run_id = current_run_id
                    latest_previous_run_id = previous_run_id

            current_run_id = latest_current_run_id
            previous_run_id = latest_previous_run_id

            # Check if there are ANY significant changes (all 5 types)
            new_count = len(changes.get('new_identities', []))
            removed_count = len(changes.get('removed_identities', []))
            perm_count = len(changes.get('permission_changes', []))
            risk_count = len(changes.get('risk_changes', []))
            cred_count = len(changes.get('credential_changes', []))
            total_changes = new_count + removed_count + perm_count + risk_count + cred_count

            if total_changes > 0:
                logger.info(
                    f"Changes detected: {new_count} new, {removed_count} removed, "
                    f"{perm_count} permission, {risk_count} risk, {cred_count} credential"
                )

                # Phase 15: Check notification settings before sending email
                email_enabled = db.get_system_setting('email_enabled', 'true') == 'true'
                if not email_enabled:
                    logger.info("Email notifications disabled in settings - skipping")
                else:
                    # Filter changes based on per-type notification flags
                    filtered_changes = {}
                    notify_map = {
                        'new_identities': 'notify_new_identities',
                        'removed_identities': 'notify_removed_identities',
                        'permission_changes': 'notify_permission_changes',
                        'risk_changes': 'notify_risk_changes',
                        'credential_changes': 'notify_credential_changes',
                    }
                    for change_key, setting_key in notify_map.items():
                        if db.get_system_setting(setting_key, 'true') == 'true':
                            filtered_changes[change_key] = changes.get(change_key, [])
                        else:
                            filtered_changes[change_key] = []

                    # Only send if there are still notifiable changes
                    notifiable_count = sum(len(v) for v in filtered_changes.values())
                    if notifiable_count > 0:
                        category_counts = _get_category_counts(db, current_run_id, previous_run_id)

                        email_service = EmailService()
                        success = email_service.send_identity_change_report(
                            changes=filtered_changes,
                            current_run_id=current_run_id,
                            previous_run_id=previous_run_id,
                            category_counts=category_counts
                        )

                        if success:
                            logger.info("Change report email sent successfully")
                        else:
                            logger.warning("Failed to send change report email")
                    else:
                        logger.info("No notifiable changes after filtering by settings")
            else:
                logger.info("No changes detected - no email notification needed")

            # Phase 83: Dispatch drift notification
            if total_changes > 0:
                _dispatch_notification('drift_detected', {
                    'title': f'{total_changes} Changes Detected in Discovery',
                    'description': f'Run #{current_run_id}: {new_count} new, {removed_count} removed, {perm_count} permission, {risk_count} risk, {cred_count} credential changes.',
                    'severity': 'high' if new_count + removed_count > 0 else 'medium',
                }, db_org_id=db_org_id)

            # Phase 43: SOAR evaluation for drift and change events
            _evaluate_soar_triggers_for_changes(changes, db)

            # Phase 28: Fire webhook events
            _fire_webhook_events(current_run_id, changes, db)

            # Phase 30: Generate in-app notifications
            _generate_notifications(current_run_id, changes, db)

        # ── Post-processing: runs on EVERY scan including first ──────

        # Ghost identity detection (disabled/deleted identities retaining roles)
        _run_ghost_detection(current_run_id, db)

        # Identity Correlation Engine — link regular ↔ privileged accounts
        _run_identity_correlation(current_run_id, db)

        # Phase 40: Run anomaly detection
        _run_anomaly_detection(current_run_id, previous_run_id, db)

        # Phase 89: Run resource anomaly detection
        _run_resource_anomaly_detection(current_run_id, previous_run_id, db)

        # AG-86: Refresh Shadow App verdicts (per-org allowlist comparison).
        # Cheap UPDATE-only pass; safe to run after every discovery.
        try:
            from app.engines.shadow_app_detector import refresh_shadow_verdicts
            org_id = getattr(db, '_organization_id', None)
            if org_id:
                shadow_counts = refresh_shadow_verdicts(db, current_run_id, org_id)
                logger.info(
                    "[AG-86] Shadow verdicts refreshed: %s for run #%s",
                    shadow_counts, current_run_id,
                )
        except Exception as _sa_err:
            logger.warning("[AG-86] Shadow verdict refresh failed: %s", _sa_err)

        # AG-180 (Tier 2A): Refresh Data Reachability rollup per AI agent.
        # AG-181 (Tier 2C): AI Lifecycle event detection (J/M/L + drift).
        # AG-182 (Tier 3A): Refresh behavior baselines + run anomaly detection.
        # All three are graceful no-ops when there are no AI agents / no events.
        try:
            org_id = getattr(db, '_organization_id', None)
            if org_id:
                # T2A: classify any new resources first, then compute reachability
                from app.engines.ai.data_reachability_engine import (
                    classify_undiscovered_resources,
                    refresh_data_reachability,
                )
                classified = classify_undiscovered_resources(db, current_run_id, org_id)
                logger.info("[AG-180] Auto-classified %d new resources for run #%s",
                            classified, current_run_id)
                dr_result = refresh_data_reachability(db, current_run_id, org_id)
                logger.info("[AG-180] Data reachability: %s for run #%s",
                            dr_result, current_run_id)

                # T2C: lifecycle event detection comparing current vs previous run
                from app.engines.ai.ai_lifecycle_engine import AILifecycleEngine
                lifecycle = AILifecycleEngine(db)
                events = lifecycle.analyze(current_run_id, previous_run_id, org_id)
                logger.info("[AG-181] AI lifecycle: %d events written for run #%s",
                            len(events) if events else 0, current_run_id)

                # T3A: behavior baseline refresh + anomaly detection
                from app.engines.ai.agent_behavior_engine import AgentBehaviorEngine
                behavior = AgentBehaviorEngine(db)
                baseline_result = behavior.refresh_baselines(org_id, window_days=14)
                logger.info("[AG-182] Baselines: %s for run #%s",
                            baseline_result, current_run_id)
                anomalies = behavior.detect_anomalies(org_id, lookback_hours=24)
                if anomalies:
                    logger.info("[AG-182] %d behavior anomalies detected for run #%s",
                                len(anomalies), current_run_id)
        except Exception as _aiag_err:
            logger.warning("[AIAG-T2T3] Tier 2/3 engine refresh failed: %s", _aiag_err)
            logger.exception(_aiag_err)

        # ── Tiered Parallel Post-Processing ─────────────────────────
        # Jobs grouped by dependency.  Within each tier, jobs run
        # concurrently in a ThreadPoolExecutor with per-job DB
        # connections.  This collapses ~33 sequential jobs into
        # 4 tiers, reducing wall-clock time by ~4-5×.
        import time as _pp_time
        from concurrent.futures import ThreadPoolExecutor, as_completed
        _pp_start = _pp_time.monotonic()
        POST_PROCESSING_WORKERS = 6

        def _parallel_job(job_type, func, *args_template):
            """Run a tracked job with its own DB connection.

            Replaces any `db` argument with a fresh per-thread connection
            so concurrent jobs don't share a psycopg2 connection.
            """
            job_db = Database(organization_id=db_org_id)
            try:
                real_args = tuple(
                    job_db if (a is db) else a for a in args_template
                )
                _track_job(job_type, db_org_id, func, *real_args)
            except Exception as e:
                logger.error("Post-processing job %s failed: %s", job_type, e)
            finally:
                try:
                    job_db.close()
                except Exception:
                    pass

        def _run_tier(tier_name, jobs):
            """Execute a list of (job_type, func, *args) tuples in parallel."""
            tier_start = _pp_time.monotonic()
            with ThreadPoolExecutor(max_workers=POST_PROCESSING_WORKERS) as executor:
                futures = {}
                for job_spec in jobs:
                    job_type, func = job_spec[0], job_spec[1]
                    args = job_spec[2:]
                    fut = executor.submit(_parallel_job, job_type, func, *args)
                    futures[fut] = job_type
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        logger.error("Tier %s job %s exception: %s",
                                     tier_name, futures[fut], e)
            tier_elapsed = round(_pp_time.monotonic() - tier_start, 1)
            logger.info("[post-processing] %s complete: %d jobs in %.1fs",
                        tier_name, len(jobs), tier_elapsed)

        # ── Tier 1: Independent foundation jobs (no dependencies) ──
        _run_tier('tier1_foundation', [
            ('identity_exposures', _run_identity_exposure_detection, current_run_id, db),
            ('security_findings', _run_security_findings, current_run_id, db),
            ('identity_graph_builder', _run_identity_graph_builder, db_org_id, db),
            ('security_findings_engine', _run_security_findings_engine, db_org_id, db),
            ('nhi_security', _run_nhi_analysis, db_org_id, db),
            ('agent_classification', _run_agent_classification, current_run_id, db_org_id, db),
            ('nhi_signin_enrichment', _run_nhi_signin_enrichment, current_run_id, db_org_id, db),
        ])

        # ── Tier 2: Depend on findings/graph/agents from Tier 1 ──
        _run_tier('tier2_analysis', [
            ('connection_security_posture', _run_connection_security_posture, db_org_id, db),
            ('attack_paths', _run_attack_path_analysis, current_run_id, db),
            ('fix_recommendations', _run_fix_recommendations, current_run_id, db),
            ('blast_radius', _run_blast_radius_analysis, current_run_id, db),
            ('risk_evaluation', _run_risk_evaluation, db_org_id, db),
            ('iam_graph', _run_iam_graph_build, db_org_id, db),
            ('escalation_detection', _run_escalation_detection, db_org_id, db),
            ('agent_sp_signin_enrichment', _run_agent_sp_signin_enrichment, current_run_id, db_org_id, db),
            ('agent_orphan_detection', _run_agent_orphan_detection, current_run_id, db_org_id, db),
            ('policy_recommendations', _run_policy_recommendations, db_org_id, db),
            ('auto_remediation', _run_auto_remediation, db_org_id, db),
            # AG-193 — apply CISO-asserted Data Trust Zones after every scan
            ('data_trust_zones', _run_data_trust_zones_classification, db_org_id, db),
            # AG-193 Sprint B — compute per-entity reachable classified exposure
            # AFTER classification so reach numbers are fresh.
            ('reach_attribution', _run_reach_attribution, db_org_id, db),
        ])

        # ── Tier 3: Depend on attack paths/blast radius/IAM graph from Tier 2 ──
        _run_tier('tier3_enrichment', [
            ('drift_intelligence', _run_drift_intelligence, db_org_id, db),
            ('posture_metrics', _run_posture_metrics, db_org_id, db),
            ('security_advisor', _run_security_advisor, db_org_id, db),
            ('graph_visualization', _run_graph_visualization, db_org_id, db),
            ('risk_forecast', _run_risk_forecast, db_org_id, db),
            ('policy_generation', _run_policy_generation, db_org_id, db),
            ('threat_detection', _run_threat_detection, db_org_id, db),
            ('activity_ingestion', _run_activity_ingestion, db_org_id, db),
            ('attack_replay', _run_attack_replay, db_org_id, db),
            ('security_orchestration', _run_security_orchestration, db_org_id, db),
            ('attack_prediction', _run_attack_prediction, db_org_id, db),
            ('graph_intelligence', _run_graph_intelligence, db_org_id, db),
            ('identity_governance', _run_identity_governance, db_org_id, db),
            ('integration_dispatch', _run_integration_dispatch, db_org_id, db),
            ('governance_analytics', _run_governance_analytics, db_org_id, db),
            ('security_strategy', _run_security_strategy, db_org_id, db),
            ('security_posture', _run_security_posture, db_org_id, db),
        ])

        # ── Tier 4: Final aggregation (depends on all above) ──
        _run_tier('tier4_finalization', [
            ('graph_attack_engine', _run_graph_attack_engine, current_run_id, db_org_id, db),
            ('findings_normalization', _run_findings_normalization, current_run_id, db),
        ])

        # ── Tier 5: Scoring + SLA (depends on findings normalization) ──
        _run_tier('tier5_scoring', [
            ('posture_score', _run_posture_score, current_run_id, db_org_id, db),
            ('sla_check', _run_sla_check, db_org_id, db),
        ])

        _pp_elapsed = round(_pp_time.monotonic() - _pp_start, 1)
        logger.info("[post-processing] ALL tiers complete in %.1fs org=%s",
                    _pp_elapsed, db_org_id)

        # ── Sequential finalization (lightweight, uses shared db) ──
        _save_compliance_snapshot(current_run_id, db)
        _compute_risk_summary(current_run_id, db_org_id, db)

        try:
            db.cleanup_microsoft_remediations()
        except Exception as e:
            logger.warning(f"Microsoft remediation cleanup failed (non-blocking): {e}")

        _validate_snapshot(current_run_id, db_org_id, db)
        _run_platform_health_check(current_run_id, db_org_id, db)

        # ── Pipeline health tracker for post-processing stages ──
        from app.engines.pipeline_health import PipelineHealthTracker
        _pp_tracker = PipelineHealthTracker(
            run_id=current_run_id, org_id=db_org_id, db=db
        )

        # ── Optimization recommendation materialization ──
        try:
            with _pp_tracker.stage('optimization_materialization') as _stg:
                _opt_result = _run_optimization_materialization(current_run_id, db_org_id, db)
                if isinstance(_opt_result, dict):
                    _stg.fetched = _opt_result.get('total_identities', 0)
                    _stg.persisted = _opt_result.get('upserted', 0)
        except Exception as e:
            logger.warning("Optimization materialization failed (non-blocking): %s", e)

        # ── Privilege drift detection ──
        try:
            with _pp_tracker.stage('privilege_drift_detection') as _stg:
                _run_privilege_drift_detection(current_run_id, previous_run_id, db_org_id, db)
        except Exception as e:
            logger.warning("Privilege drift detection failed (non-blocking): %s", e)

        # ── Workload attribution ──
        try:
            with _pp_tracker.stage('workload_attribution') as _stg:
                _run_workload_attribution(current_run_id, db_org_id, db)
        except Exception as e:
            logger.warning("Workload attribution failed (non-blocking): %s", e)

        # ── Azure Resource Graph inventory enumeration ──
        try:
            with _pp_tracker.stage('resource_inventory') as _stg:
                _run_resource_inventory_collection(current_run_id, db_org_id, db)
                # Pull stats from the collector's return value if available
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM discovered_resources
                    WHERE discovery_run_id = %s AND discovery_source LIKE '%%inventory%%'
                """, (current_run_id,))
                inv_row = cursor.fetchone()
                _stg.persisted = inv_row[0] if inv_row else 0
                _stg.fetched = _stg.persisted  # Resource Graph fetched = persisted for now
                cursor.close()
        except Exception as e:
            logger.warning("Resource inventory collection failed (non-blocking): %s", e)

        # ── Resource scope extraction ──
        try:
            with _pp_tracker.stage('resource_scope_extraction') as _stg:
                _run_resource_scope_extraction(current_run_id, db_org_id, db)
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM discovered_resources
                    WHERE discovery_run_id = %s
                """, (current_run_id,))
                _stg.persisted = (cursor.fetchone()[0] or 0)
                _stg.fetched = _stg.persisted
                cursor.close()
        except Exception as e:
            logger.warning("Resource scope extraction failed (non-blocking): %s", e)

        # ── Reachability computation ──
        try:
            with _pp_tracker.stage('reachability_computation') as _stg:
                _run_reachability_computation(current_run_id, db_org_id, db)
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM identity_reachability
                    WHERE discovery_run_id = %s
                """, (current_run_id,))
                _stg.persisted = (cursor.fetchone()[0] or 0)
                _stg.fetched = _stg.persisted
                cursor.close()
        except Exception as e:
            logger.warning("Reachability computation failed (non-blocking): %s", e)

        # ── Finalize pipeline health and persist summary ──
        try:
            _pp_tracker.finalize()
        except Exception as e:
            logger.warning("Pipeline health finalization failed: %s", e)

        db.close()

    except Exception as e:
        logger.error(f"Error during change detection/notification: {e}")
        logger.exception(e)


def _run_optimization_materialization(current_run_id, db_org_id, db):
    """Materialize optimization recommendations for all identities in a run.

    Iterates every identity in the completed discovery run, applies the
    canonical role usage classification logic, computes optimization
    candidates, and upserts them into optimization_recommendations.

    Stale recommendations (from previous runs, still in 'open' status)
    are auto-closed after the current batch is written.
    """
    from datetime import datetime, timezone
    from psycopg2.extras import RealDictCursor
    from app.api.handlers import _compute_identity_optimization
    _OBSERVATION_WINDOW_DAYS = 90
    _now = datetime.now(timezone.utc)

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Fetch all identities in this run
        cursor.execute("""
            SELECT id, identity_id, display_name, identity_category,
                   is_microsoft_system, is_discovery_connector,
                   telemetry_coverage, last_activity_date,
                   last_sign_in, last_noninteractive_signin,
                   auth_activity
            FROM identities
            WHERE discovery_run_id = %s
        """, (current_run_id,))
        identity_rows = [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        logger.error("Optimization materialization: failed to fetch identities: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass
        cursor.close()
        return

    upserted = 0
    identities_processed = 0

    for ident in identity_rows:
        identity_db_id = ident['id']
        try:
            roles = db.get_identity_roles_enriched(identity_db_id)
        except Exception as e:
            logger.warning("Optimization materialization: roles fetch failed for identity %s: %s",
                           identity_db_id, e)
            try:
                db.conn.rollback()
            except Exception:
                pass
            continue

        if not roles:
            continue

        # ── Determine effective last activity (mirrors identity detail handler) ──
        _last_activity = ident.get('last_activity_date')
        _last_sign_in = ident.get('last_sign_in')
        _last_ni = ident.get('last_noninteractive_signin')
        eff_last = None
        for dt_val in [_last_activity, _last_sign_in, _last_ni]:
            if dt_val and hasattr(dt_val, 'date'):
                if eff_last is None or dt_val > eff_last:
                    eff_last = dt_val
        identity_has_effective_activity = bool(eff_last)

        _tel_cov = (ident.get('telemetry_coverage') or '').lower()

        # Build auth_activity dict for _compute_identity_optimization
        auth_activity_raw = ident.get('auth_activity')
        if isinstance(auth_activity_raw, str):
            try:
                import json as _json
                auth_activity_raw = _json.loads(auth_activity_raw)
            except Exception:
                auth_activity_raw = {}
        if not isinstance(auth_activity_raw, dict):
            auth_activity_raw = {}
        auth_activity_raw['any_activity_observed'] = identity_has_effective_activity
        ident['auth_activity'] = auth_activity_raw

        # ── Role usage classification (mirrors identity detail enrichment) ──
        _role_p1_cache = {}
        for _ri, _r in enumerate(roles):
            _rp1 = _r.get("last_used_at")
            _best = None
            if _rp1 and hasattr(_rp1, 'date'):
                _best = (_now - _rp1).days
            if _best is None:
                _rp1b = _r.get("last_activity_date")
                if _rp1b and hasattr(_rp1b, 'date'):
                    _best = (_now - _rp1b).days
            _role_p1_cache[_ri] = _best

        _scope_role_map = {}
        for _ri, _r in enumerate(roles):
            _scope = (_r.get("scope") or '/').lower().rstrip('/') or '/'
            _scope_role_map.setdefault(_scope, []).append(_ri)

        def _count_p1_peers(role_scope, role_index):
            scope = (role_scope or '/').lower().rstrip('/') or '/'
            count = 0
            for s, role_indices in _scope_role_map.items():
                if s == scope:
                    overlap = True
                elif s == '/' or scope == '/':
                    overlap = True
                else:
                    overlap = (scope.startswith(s + '/') or s.startswith(scope + '/'))
                if not overlap:
                    continue
                for ri in role_indices:
                    if ri == role_index:
                        continue
                    pd = _role_p1_cache.get(ri)
                    if pd is not None and pd <= _OBSERVATION_WINDOW_DAYS:
                        count += 1
            return count

        _roles_proven = 0
        _roles_likely = 0
        _roles_unknown = 0
        _roles_no_observed_usage = 0

        for _role_idx, role in enumerate(roles):
            p1 = role.get("last_used_at")
            _p1_delta = (_now - p1).days if p1 and hasattr(p1, 'date') else None

            p1b = role.get("last_activity_date")
            _p1b_delta = None
            if p1b and hasattr(p1b, 'date'):
                _p1b_delta = (_now - p1b).days

            _best_role_delta = _p1_delta if _p1_delta is not None else _p1b_delta

            _eff_tel_cov = _tel_cov
            if not _eff_tel_cov and identity_has_effective_activity:
                _eff_tel_cov = 'partial'

            if _best_role_delta is not None and _best_role_delta <= _OBSERVATION_WINDOW_DAYS:
                _oc = _count_p1_peers(role.get("scope"), _role_idx)
                if _oc == 0:
                    role["role_usage_classification"] = "proven"
                    _roles_proven += 1
                else:
                    role["role_usage_classification"] = "likely"
                    role["overlap_count"] = _oc
                    _roles_likely += 1
            elif identity_has_effective_activity and _eff_tel_cov in ('full', 'partial'):
                role["role_usage_classification"] = "unknown"
                _roles_unknown += 1
            elif _eff_tel_cov == 'blind':
                role["role_usage_classification"] = "telemetry_blind"
            elif _eff_tel_cov in ('full', 'partial'):
                role["role_usage_classification"] = "no_observed_usage"
                _roles_no_observed_usage += 1
            else:
                role["role_usage_classification"] = "insufficient_coverage"

            # Build display fields needed by _compute_identity_optimization
            if _best_role_delta is not None:
                role["days_since_last_used"] = _best_role_delta
                role["last_used_display"] = f"{_best_role_delta} days ago" if _best_role_delta > 0 else "Today"
                role["last_used_source"] = "Role-level activity record"
            elif identity_has_effective_activity:
                role["days_since_last_used"] = None
                role["last_used_display"] = "Log-independent mode"
                role["last_used_source"] = "Log-independent mode"
            else:
                role["days_since_last_used"] = None
                role["last_used_display"] = "Never used"
                role["last_used_source"] = "Log-independent mode"

        # Build role_usage_summary for _compute_identity_optimization
        ident['role_usage_summary'] = {
            'roles_proven': _roles_proven,
            'roles_likely': _roles_likely,
            'roles_unknown': _roles_unknown,
            'roles_no_observed_usage': _roles_no_observed_usage,
        }
        ident['last_seen_display'] = (
            eff_last.strftime("%Y-%m-%d") if eff_last else None
        )

        # ── Compute optimization candidates ──
        opt = _compute_identity_optimization(roles, ident, _OBSERVATION_WINDOW_DAYS)

        # ── Upsert each candidate ──
        all_candidates = (
            opt.get('candidate_remove', [])
            + opt.get('candidate_review', [])
            + opt.get('insufficient_evidence', [])
            + opt.get('scope_narrowing', [])
        )
        for cand in all_candidates:
            cand['identity_id'] = ident.get('identity_id')
            cand['identity_db_id'] = identity_db_id
            cand['display_name'] = ident.get('display_name')
            cand['identity_category'] = ident.get('identity_category')
            cand['discovery_run_id'] = current_run_id
            cand['observation_window_days'] = _OBSERVATION_WINDOW_DAYS
            try:
                db.upsert_optimization_recommendation(db_org_id, cand)
                upserted += 1
            except Exception as e:
                logger.warning("Optimization materialization: upsert failed: %s", e)
                try:
                    db.conn.rollback()
                except Exception:
                    pass

        identities_processed += 1

    # ── Close stale recommendations ──
    try:
        closed = db.close_stale_recommendations(db_org_id, current_run_id)
        logger.info(
            "Optimization materialization complete: %d identities processed, "
            "%d candidates upserted, %d stale closed (org=%s, run=%s)",
            identities_processed, upserted, len(closed), db_org_id, current_run_id,
        )
    except Exception as e:
        logger.warning("Optimization materialization: stale cleanup failed: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass

    cursor.close()


def _run_privilege_drift_detection(current_run_id, previous_run_id, db_org_id, db):
    """Compute and persist classified privilege drift events between two runs.

    Compares role assignments (both Azure RBAC and Entra directory) between
    the current and previous discovery runs.  Classifies each change into
    one of 6 drift types and persists to privilege_drift_events.

    Drift Types:
        privilege_added    — New role assignment on an identity
        privilege_removed  — Role assignment removed
        scope_expanded     — Same role, broader scope
        scope_reduced      — Same role, narrower scope
        risk_increased     — Identity risk level escalated
        risk_reduced       — Identity risk level de-escalated
    """
    from psycopg2.extras import RealDictCursor

    if not previous_run_id:
        logger.info("Privilege drift: no previous run — skipping (run=%s)", current_run_id)
        return

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    try:
        # ── Load identities + combined roles from BOTH runs ──
        def _load_run_snapshot(run_id):
            """Load identity→{meta, roles} map for a run.

            Includes both Azure RBAC and Entra directory roles in a single
            pass via UNION ALL.
            """
            cursor.execute("""
                SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                       i.risk_level, i.risk_score,
                       COALESCE(i.is_microsoft_system, false) as is_microsoft_system
                FROM identities i
                WHERE i.discovery_run_id = %s
            """, (run_id,))
            identities = {}
            for row in cursor.fetchall():
                identities[row['identity_id']] = {
                    'db_id': row['id'],
                    'identity_id': row['identity_id'],
                    'display_name': row['display_name'],
                    'identity_category': row['identity_category'],
                    'risk_level': row['risk_level'],
                    'risk_score': row['risk_score'] or 0,
                    'is_microsoft_system': row['is_microsoft_system'],
                    'roles': set(),
                    'role_details': {},  # signature → role dict
                }

            # Azure RBAC roles
            db_ids = [v['db_id'] for v in identities.values()]
            if db_ids:
                cursor.execute("""
                    SELECT ra.identity_db_id, ra.role_name, ra.scope, ra.scope_type
                    FROM role_assignments ra
                    WHERE ra.identity_db_id = ANY(%s)
                """, (db_ids,))
                # Map db_id → identity_id for reverse lookup
                dbid_to_iid = {v['db_id']: k for k, v in identities.items()}
                for row in cursor.fetchall():
                    iid = dbid_to_iid.get(row['identity_db_id'])
                    if iid:
                        sig = f"azure:{row['role_name']}:{row['scope_type'] or ''}:{row['scope'] or '/'}"
                        identities[iid]['roles'].add(sig)
                        identities[iid]['role_details'][sig] = {
                            'role_name': row['role_name'],
                            'role_type': 'azure',
                            'scope': row['scope'] or '/',
                            'scope_type': row['scope_type'] or '',
                        }

                # Entra directory roles
                cursor.execute("""
                    SELECT era.identity_db_id, era.role_name,
                           COALESCE(era.directory_scope, '/') as scope
                    FROM entra_role_assignments era
                    WHERE era.identity_db_id = ANY(%s)
                """, (db_ids,))
                for row in cursor.fetchall():
                    iid = dbid_to_iid.get(row['identity_db_id'])
                    if iid:
                        sig = f"entra:{row['role_name']}:directory:{row['scope']}"
                        identities[iid]['roles'].add(sig)
                        identities[iid]['role_details'][sig] = {
                            'role_name': row['role_name'],
                            'role_type': 'entra',
                            'scope': row['scope'],
                            'scope_type': 'directory',
                        }

            return identities

        current_snap = _load_run_snapshot(current_run_id)
        previous_snap = _load_run_snapshot(previous_run_id)

    except Exception as e:
        logger.error("Privilege drift: snapshot load failed: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass
        cursor.close()
        return

    # ── Privileged role check (reuse handlers constants) ──
    from app.api.handlers import _PRIV_ENTRA, _PRIV_ARM

    def _is_priv(sig):
        parts = sig.split(':', 3)
        rtype = parts[0]  # azure or entra
        rname = parts[1].lower() if len(parts) > 1 else ''
        if rtype == 'entra':
            return rname in _PRIV_ENTRA
        return rname in _PRIV_ARM

    # ── Scope hierarchy for expansion/reduction detection ──
    SCOPE_RANK = {
        'management_group': 4,
        'subscription': 3,
        'resource_group': 2,
        'resource': 1,
        'directory': 3,  # Entra directory scope = tenant-wide
        '': 0,
    }

    drift_events = []

    # Identities present in both runs — detect role and risk changes
    common_ids = set(current_snap.keys()) & set(previous_snap.keys())
    for iid in common_ids:
        curr = current_snap[iid]
        prev = previous_snap[iid]

        # Skip Microsoft system identities
        if curr.get('is_microsoft_system'):
            continue

        curr_roles = curr['roles']
        prev_roles = prev['roles']

        added_sigs = curr_roles - prev_roles
        removed_sigs = prev_roles - curr_roles

        # ── Detect scope changes ──
        # Group by (role_type, role_name) to find same role at different scopes
        def _role_key(sig):
            parts = sig.split(':', 3)
            return (parts[0], parts[1])  # (type, name)

        added_by_key = {}
        for sig in added_sigs:
            k = _role_key(sig)
            added_by_key.setdefault(k, []).append(sig)

        removed_by_key = {}
        for sig in removed_sigs:
            k = _role_key(sig)
            removed_by_key.setdefault(k, []).append(sig)

        # Match same role added+removed = scope change
        matched_added = set()
        matched_removed = set()

        for rkey in set(added_by_key.keys()) & set(removed_by_key.keys()):
            a_sigs = added_by_key[rkey]
            r_sigs = removed_by_key[rkey]
            pairs = min(len(a_sigs), len(r_sigs))
            for i in range(pairs):
                a_detail = curr['role_details'][a_sigs[i]]
                r_detail = prev['role_details'][r_sigs[i]]
                a_rank = SCOPE_RANK.get(a_detail.get('scope_type', '').lower(), 0)
                r_rank = SCOPE_RANK.get(r_detail.get('scope_type', '').lower(), 0)

                if a_rank > r_rank:
                    dt = 'scope_expanded'
                elif a_rank < r_rank:
                    dt = 'scope_reduced'
                else:
                    # Same scope type but different scope path —
                    # compare path depth (shorter = broader)
                    a_depth = a_detail['scope'].count('/')
                    r_depth = r_detail['scope'].count('/')
                    if a_depth < r_depth:
                        dt = 'scope_expanded'
                    elif a_depth > r_depth:
                        dt = 'scope_reduced'
                    else:
                        # Same depth, different path — treat as add+remove
                        continue

                drift_events.append({
                    'identity_id': iid,
                    'identity_db_id': curr['db_id'],
                    'display_name': curr['display_name'],
                    'identity_category': curr['identity_category'],
                    'drift_type': dt,
                    'role_name': a_detail['role_name'],
                    'role_type': a_detail['role_type'],
                    'scope': a_detail['scope'],
                    'prior_scope': r_detail['scope'],
                    'is_privileged': _is_priv(a_sigs[i]),
                    'details': {
                        'current_scope_type': a_detail.get('scope_type'),
                        'prior_scope_type': r_detail.get('scope_type'),
                    },
                    'discovery_run_id': current_run_id,
                    'previous_run_id': previous_run_id,
                })
                matched_added.add(a_sigs[i])
                matched_removed.add(r_sigs[i])

        # ── Pure additions ──
        for sig in added_sigs - matched_added:
            detail = curr['role_details'][sig]
            drift_events.append({
                'identity_id': iid,
                'identity_db_id': curr['db_id'],
                'display_name': curr['display_name'],
                'identity_category': curr['identity_category'],
                'drift_type': 'privilege_added',
                'role_name': detail['role_name'],
                'role_type': detail['role_type'],
                'scope': detail['scope'],
                'is_privileged': _is_priv(sig),
                'details': {'scope_type': detail.get('scope_type')},
                'discovery_run_id': current_run_id,
                'previous_run_id': previous_run_id,
            })

        # ── Pure removals ──
        for sig in removed_sigs - matched_removed:
            detail = prev['role_details'][sig]
            drift_events.append({
                'identity_id': iid,
                'identity_db_id': prev['db_id'],
                'display_name': prev['display_name'],
                'identity_category': prev['identity_category'],
                'drift_type': 'privilege_removed',
                'role_name': detail['role_name'],
                'role_type': detail['role_type'],
                'scope': detail['scope'],
                'is_privileged': _is_priv(sig),
                'details': {'scope_type': detail.get('scope_type')},
                'discovery_run_id': current_run_id,
                'previous_run_id': previous_run_id,
            })

        # ── Risk level changes ──
        curr_risk = (curr.get('risk_level') or 'info').lower()
        prev_risk = (prev.get('risk_level') or 'info').lower()
        if curr_risk != prev_risk:
            risk_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            if risk_order.get(curr_risk, 0) > risk_order.get(prev_risk, 0):
                dt = 'risk_increased'
            else:
                dt = 'risk_reduced'
            drift_events.append({
                'identity_id': iid,
                'identity_db_id': curr['db_id'],
                'display_name': curr['display_name'],
                'identity_category': curr['identity_category'],
                'drift_type': dt,
                'prior_risk_level': prev_risk,
                'current_risk_level': curr_risk,
                'prior_risk_score': prev.get('risk_score', 0),
                'current_risk_score': curr.get('risk_score', 0),
                'is_privileged': any(_is_priv(s) for s in curr_roles),
                'details': {
                    'prior_role_count': len(prev_roles),
                    'current_role_count': len(curr_roles),
                },
                'discovery_run_id': current_run_id,
                'previous_run_id': previous_run_id,
            })

    # ── New identities with privileged roles ──
    new_ids = set(current_snap.keys()) - set(previous_snap.keys())
    for iid in new_ids:
        curr = current_snap[iid]
        if curr.get('is_microsoft_system'):
            continue
        for sig in curr['roles']:
            if _is_priv(sig):
                detail = curr['role_details'][sig]
                drift_events.append({
                    'identity_id': iid,
                    'identity_db_id': curr['db_id'],
                    'display_name': curr['display_name'],
                    'identity_category': curr['identity_category'],
                    'drift_type': 'privilege_added',
                    'role_name': detail['role_name'],
                    'role_type': detail['role_type'],
                    'scope': detail['scope'],
                    'is_privileged': True,
                    'details': {
                        'scope_type': detail.get('scope_type'),
                        'new_identity': True,
                    },
                    'discovery_run_id': current_run_id,
                    'previous_run_id': previous_run_id,
                })

    # ── Persist ──
    try:
        inserted = db.save_privilege_drift_events(db_org_id, drift_events)
        logger.info(
            "Privilege drift detection complete: %d events persisted "
            "(run=%s vs prev=%s, org=%s)",
            inserted, current_run_id, previous_run_id, db_org_id,
        )
    except Exception as e:
        logger.warning("Privilege drift: persist failed: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass

    cursor.close()


def _run_workload_attribution(current_run_id, db_org_id, db):
    """Infer and persist parent workload attributions for all identities.

    Synthesizes signals from multiple sources in priority order:
      1. Managed identity bindings (system-assigned) — confidence 95
      2. Managed identity bindings (user-assigned)  — confidence 90
      3. ARM resource associations (discovery)       — confidence 85
      4. identity_lineage_bindings table             — confidence from binding
      5. Workload type inference (from roles)        — confidence from inference
      6. Display name pattern matching               — confidence 60-70

    Only processes NHI identities (service_principal, managed_identity_*).
    """
    from psycopg2.extras import RealDictCursor

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # ── AI workload indicators (for is_ai_workload flag) ──
    AI_WORKLOAD_TYPES = frozenset({
        'ai_service', 'ml_workload', 'ml_workspace', 'cognitive_services',
    })
    AI_NAME_SIGNALS = (
        'openai', 'cognitive', 'aiservice', 'azure-ai', '-ml-', 'aml-',
        'copilot', 'bot-', 'luis-', 'language-', 'form-recognizer',
        'document-intelligence', 'speech-', 'vision-', 'anomaly-detector',
    )
    AI_RESOURCE_TYPES = frozenset({
        'cognitiveservices', 'machinelearningservices', 'botservice',
        'openai', 'search', 'cognitiveservices/accounts',
    })

    # ── Workload type mapping from ARM resource types ──
    RESOURCE_TYPE_MAP = {
        'sites': 'app_service',
        'functionapp': 'function_app',
        'managedclusters': 'aks',
        'virtualmachines': 'vm',
        'containerapps': 'container_app',
        'workflows': 'logic_app',
        'automationaccounts': 'automation',
        'factories': 'data_factory',
        'staticsites': 'static_web_app',
        'accounts': 'cognitive_service',
        'workspaces': 'ml_workspace',
    }

    # ── Display name patterns for workload inference ──
    import re as _re
    DISPLAY_NAME_PATTERNS = [
        (_re.compile(r'(?:aks|kubernetes)[\-_]', _re.I), 'aks', 70),
        (_re.compile(r'(?:webapp|appservice|app[\-_]service)', _re.I), 'app_service', 65),
        (_re.compile(r'(?:func[\-_]|function[\-_]|azurefunc)', _re.I), 'function_app', 65),
        (_re.compile(r'(?:devops|pipeline|github[\-_]action|azdo)', _re.I), 'cicd_pipeline', 65),
        (_re.compile(r'(?:terraform|pulumi|bicep|arm[\-_]deploy)', _re.I), 'cicd_pipeline', 60),
        (_re.compile(r'(?:datafactory|adf[\-_])', _re.I), 'data_factory', 65),
        (_re.compile(r'(?:logic[\-_]app|workflow)', _re.I), 'logic_app', 60),
        (_re.compile(r'(?:automation[\-_]|runbook)', _re.I), 'automation', 60),
        (_re.compile(r'(?:vm[\-_]|virtual[\-_]machine)', _re.I), 'vm', 55),
    ]

    try:
        # Fetch NHI identities from current run
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name, i.identity_category,
                   i.workload_type, i.workload_origin, i.workload_origin_source,
                   i.associated_resource_id, i.associated_resource_type,
                   i.associated_resource_name, i.associated_resource_group,
                   i.associated_subscription_id,
                   i.agent_identity_type
            FROM identities i
            WHERE i.discovery_run_id = %s
              AND i.identity_category IN (
                  'service_principal', 'managed_identity_system',
                  'managed_identity_user', 'workload_identity'
              )
              AND NOT COALESCE(i.is_microsoft_system, false)
        """, (current_run_id,))
        identities = [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        logger.error("Workload attribution: identity fetch failed: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass
        cursor.close()
        return

    # Fetch existing lineage bindings for these identities
    db_ids = [i['id'] for i in identities]
    lineage_bindings = {}
    if db_ids:
        try:
            cursor.execute("""
                SELECT spn_id, resource_id, resource_type, resource_name,
                       resource_group, subscription_id, binding_method,
                       confidence_score, binding_evidence
                FROM identity_lineage_bindings
                WHERE spn_id = ANY(%s)
            """, (db_ids,))
            for row in cursor.fetchall():
                lid = row['spn_id']
                lineage_bindings.setdefault(lid, []).append(dict(row))
        except Exception as e:
            logger.warning("Workload attribution: lineage bindings fetch failed: %s", e)
            try:
                db.conn.rollback()
            except Exception:
                pass

    upserted = 0

    for ident in identities:
        idb_id = ident['id']
        iid = ident['identity_id']
        display_name = (ident.get('display_name') or '').lower()
        category = ident.get('identity_category', '')
        attributions = []  # list of attribution dicts to upsert

        def _is_ai(wtype, resource_type_raw='', name=''):
            """Check if workload is AI-related."""
            if wtype in AI_WORKLOAD_TYPES:
                return True
            rt_lower = (resource_type_raw or '').lower()
            if any(art in rt_lower for art in AI_RESOURCE_TYPES):
                return True
            n_lower = (name or display_name).lower()
            if any(sig in n_lower for sig in AI_NAME_SIGNALS):
                return True
            return False

        # ── Signal 1: System-assigned managed identity ──
        # Category = managed_identity_system AND has associated_resource_id
        if category == 'managed_identity_system' and ident.get('associated_resource_id'):
            res_type_raw = (ident.get('associated_resource_type') or '').lower()
            wtype = RESOURCE_TYPE_MAP.get(res_type_raw, res_type_raw or 'unknown')
            attributions.append({
                'identity_id': iid,
                'identity_db_id': idb_id,
                'workload_type': wtype,
                'workload_name': ident.get('associated_resource_name'),
                'workload_resource_id': ident.get('associated_resource_id'),
                'workload_resource_group': ident.get('associated_resource_group'),
                'workload_subscription_id': ident.get('associated_subscription_id'),
                'attribution_confidence': 95,
                'attribution_basis': 'managed_identity_system',
                'attribution_signals': [{
                    'signal': 'system_assigned_mi_binding',
                    'resource_id': ident.get('associated_resource_id'),
                    'confidence': 95,
                }],
                'is_ai_workload': _is_ai(wtype, res_type_raw, ident.get('associated_resource_name')),
                'discovery_run_id': current_run_id,
            })

        # ── Signal 2: Lineage bindings (MI and other) ──
        for binding in lineage_bindings.get(idb_id, []):
            method = binding.get('binding_method', '')
            res_type_raw = (binding.get('resource_type') or '').lower()
            wtype = RESOURCE_TYPE_MAP.get(res_type_raw, res_type_raw or 'unknown')
            confidence = binding.get('confidence_score', 0)

            if method == 'ManagedIdentitySystemAssigned':
                basis = 'managed_identity_system'
                confidence = max(confidence, 95)
            elif method == 'ManagedIdentityUserAssigned':
                basis = 'managed_identity_user'
                confidence = max(confidence, 90)
            elif method == 'FederatedCredential':
                basis = 'federated_credential'
                confidence = max(confidence, 80)
            elif method == 'HardcodedClientId':
                basis = 'arm_resource_binding'
                confidence = max(confidence, 75)
            elif method == 'WorkloadIdentityAnnotation':
                basis = 'arm_resource_binding'
                confidence = max(confidence, 85)
            else:
                basis = 'arm_resource_binding'
                confidence = max(confidence, 70)

            attributions.append({
                'identity_id': iid,
                'identity_db_id': idb_id,
                'workload_type': wtype,
                'workload_name': binding.get('resource_name'),
                'workload_resource_id': binding.get('resource_id', ''),
                'workload_resource_group': binding.get('resource_group'),
                'workload_subscription_id': binding.get('subscription_id'),
                'attribution_confidence': confidence,
                'attribution_basis': basis,
                'attribution_signals': [{
                    'signal': f'lineage_binding_{method}',
                    'resource_id': binding.get('resource_id'),
                    'binding_method': method,
                    'confidence': confidence,
                }],
                'is_ai_workload': _is_ai(wtype, res_type_raw, binding.get('resource_name')),
                'discovery_run_id': current_run_id,
            })

        # ── Signal 3: ARM resource association (identity columns) ──
        if (ident.get('associated_resource_id')
                and category != 'managed_identity_system'):
            # Avoid duplicating the system MI attribution already added
            res_type_raw = (ident.get('associated_resource_type') or '').lower()
            wtype = RESOURCE_TYPE_MAP.get(res_type_raw, res_type_raw or 'unknown')
            attributions.append({
                'identity_id': iid,
                'identity_db_id': idb_id,
                'workload_type': wtype,
                'workload_name': ident.get('associated_resource_name'),
                'workload_resource_id': ident.get('associated_resource_id'),
                'workload_resource_group': ident.get('associated_resource_group'),
                'workload_subscription_id': ident.get('associated_subscription_id'),
                'attribution_confidence': 85,
                'attribution_basis': 'arm_resource_binding',
                'attribution_signals': [{
                    'signal': 'identity_associated_resource',
                    'source': ident.get('workload_origin_source', 'discovery'),
                    'confidence': 85,
                }],
                'is_ai_workload': _is_ai(wtype, res_type_raw, ident.get('associated_resource_name')),
                'discovery_run_id': current_run_id,
            })

        # ── Signal 4: Workload type from role inference ──
        wt = (ident.get('workload_type') or '').lower()
        if wt and wt != 'unknown' and not attributions:
            # Only use role-inferred workload if no stronger signals exist
            attributions.append({
                'identity_id': iid,
                'identity_db_id': idb_id,
                'workload_type': wt,
                'workload_name': ident.get('workload_origin'),
                'workload_resource_id': '',
                'attribution_confidence': 65,
                'attribution_basis': 'workload_type_inference',
                'attribution_signals': [{
                    'signal': 'role_topology_inference',
                    'workload_type': wt,
                    'source': ident.get('workload_origin_source', 'role_inference'),
                    'confidence': 65,
                }],
                'is_ai_workload': _is_ai(wt),
                'discovery_run_id': current_run_id,
            })

        # ── Signal 5: Display name pattern matching ──
        if not attributions and display_name:
            for pattern, wtype, confidence in DISPLAY_NAME_PATTERNS:
                if pattern.search(display_name):
                    attributions.append({
                        'identity_id': iid,
                        'identity_db_id': idb_id,
                        'workload_type': wtype,
                        'workload_name': None,
                        'workload_resource_id': '',
                        'attribution_confidence': confidence,
                        'attribution_basis': 'display_name_pattern',
                        'attribution_signals': [{
                            'signal': 'display_name_match',
                            'pattern': pattern.pattern,
                            'display_name': ident.get('display_name'),
                            'confidence': confidence,
                        }],
                        'is_ai_workload': _is_ai(wtype),
                        'discovery_run_id': current_run_id,
                    })
                    break  # First match wins

        # ── Signal 6: AI classification as compound signal ──
        agent_type = ident.get('agent_identity_type') or ''
        if agent_type in ('ai_agent', 'possible_ai_agent') and not any(
            a.get('is_ai_workload') for a in attributions
        ):
            # Mark existing attributions as AI if identity is AI-classified
            for a in attributions:
                a['is_ai_workload'] = True
            # If no attributions at all, create a minimal AI workload attribution
            if not attributions:
                attributions.append({
                    'identity_id': iid,
                    'identity_db_id': idb_id,
                    'workload_type': 'ai_service',
                    'workload_name': None,
                    'workload_resource_id': '',
                    'attribution_confidence': 50,
                    'attribution_basis': 'ai_classification',
                    'attribution_signals': [{
                        'signal': 'agent_classification',
                        'agent_identity_type': agent_type,
                        'confidence': 50,
                    }],
                    'is_ai_workload': True,
                    'discovery_run_id': current_run_id,
                })

        # ── Persist attributions ──
        for attr in attributions:
            try:
                db.upsert_workload_attribution(db_org_id, attr)
                upserted += 1
            except Exception as e:
                logger.warning("Workload attribution: upsert failed: %s", e)
                try:
                    db.conn.rollback()
                except Exception:
                    pass

    logger.info(
        "Workload attribution complete: %d identities processed, "
        "%d attributions upserted (org=%s, run=%s)",
        len(identities), upserted, db_org_id, current_run_id,
    )
    cursor.close()


def _run_resource_inventory_collection(current_run_id, db_org_id, db):
    """Enumerate full Azure resource inventory via Resource Graph.

    Queries Azure Resource Graph for all resources across connected subscriptions.
    Enriches discovered_resources with metadata (location, tags, sku, kind).
    Runs BEFORE scope extraction so the merge step can augment existing rows.
    """
    if not AZURE_DISCOVERY_ENABLED:
        return

    from psycopg2.extras import RealDictCursor

    # Look up the cloud_connection_id for this run
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("""
            SELECT cloud_connection_id FROM discovery_runs
            WHERE id = %s
        """, (current_run_id,))
        row = cursor.fetchone()
        cursor.close()
    except Exception as e:
        logger.debug("Resource inventory: failed to get cloud_connection_id: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass
        return

    if not row or not row.get('cloud_connection_id'):
        logger.debug("Resource inventory: no cloud_connection_id for run %s", current_run_id)
        return

    conn_id = row['cloud_connection_id']

    # Retrieve connection credentials (admin context, bypasses RLS)
    admin_db = Database()
    try:
        connections = admin_db.get_cloud_connections(db_org_id, include_secrets=True)
    finally:
        admin_db.close()

    conn = next((c for c in connections if c['id'] == conn_id), None)
    if not conn:
        logger.debug("Resource inventory: connection %d not found for org %d", conn_id, db_org_id)
        return

    metadata = conn.get('metadata') or {}
    azure_directory_id = conn.get('azure_directory_id')
    client_id = conn.get('client_id')
    client_secret = metadata.get('client_secret')

    if not all([azure_directory_id, client_id, client_secret]):
        logger.debug("Resource inventory: incomplete credentials for connection %d", conn_id)
        return

    # Build credential and get subscription list
    try:
        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
            connection_timeout=10,
            read_timeout=30,
        )
    except Exception as e:
        logger.warning("Resource inventory: credential creation failed: %s", e)
        return
    client_secret = None  # AG-116: zero after SDK init — prevent memory retention

    # Get monitored subscription IDs from cloud_subscriptions
    sub_ids = []
    try:
        sub_cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        sub_cursor.execute("""
            SELECT account_id FROM cloud_subscriptions
            WHERE cloud_connection_id = %s AND monitored = true AND deleted = false
        """, (conn_id,))
        sub_ids = [r['account_id'] for r in sub_cursor.fetchall() if r.get('account_id')]
        sub_cursor.close()
    except Exception as e:
        logger.debug("Resource inventory: failed to get subscriptions: %s", e)
        try:
            db.conn.rollback()
        except Exception:
            pass

    if not sub_ids:
        # Fallback: extract subscription IDs from role_assignments scopes
        import re
        _sub_re = re.compile(r'/subscriptions/([^/]+)', re.IGNORECASE)
        try:
            sub_cursor = db.conn.cursor()
            sub_cursor.execute("""
                SELECT DISTINCT ra.scope FROM role_assignments ra
                JOIN identities i ON i.id = ra.identity_db_id
                WHERE i.discovery_run_id = %s
                  AND ra.scope LIKE '/subscriptions/%%'
            """, (current_run_id,))
            seen = set()
            for r in sub_cursor.fetchall():
                m = _sub_re.match(r[0] or '')
                if m:
                    seen.add(m.group(1).lower())
            sub_ids = list(seen)
            sub_cursor.close()
        except Exception as e:
            logger.debug("Resource inventory: fallback subscription query failed: %s", e)
            try:
                db.conn.rollback()
            except Exception:
                pass

    if not sub_ids:
        logger.info("Resource inventory: no subscriptions found for org %d", db_org_id)
        return

    # Run the collector
    from app.engines.resource_inventory_collector import ResourceInventoryCollector
    collector = ResourceInventoryCollector(credential, sub_ids, db, db_org_id)
    stats = collector.collect_and_persist(current_run_id)
    logger.info(
        "Resource inventory collection: %d enumerated, %d persisted "
        "(org=%s, run=%s, subs=%d)",
        stats.get('total_resources', 0), stats.get('persisted', 0),
        db_org_id, current_run_id, len(sub_ids),
    )


def _run_resource_scope_extraction(current_run_id, db_org_id, db):
    """Extract discovered resources from RBAC scope data.

    Parses ARM resource IDs from role_assignments.scope to build a canonical
    resource inventory. Zero additional Azure API calls — uses data already
    collected during discovery.
    """
    from app.engines.resource_scope_extractor import ResourceScopeExtractor

    extractor = ResourceScopeExtractor(db)
    stats = extractor.extract_and_persist(current_run_id, db_org_id)
    logger.info(
        "Resource scope extraction: %d resources (%d high-value), %d types "
        "(org=%s, run=%s)",
        stats['total_resources'], stats['high_value_count'],
        len(stats.get('by_type', {})), db_org_id, current_run_id,
    )


def _run_reachability_computation(current_run_id, db_org_id, db):
    """Compute per-identity reachability metrics and risk flags.

    Uses centralized thresholds from app.constants.blast_radius_policy.
    For each non-system identity in the run:
      1. Loads RBAC + Entra role assignments
      2. Expands scopes → reachable subscriptions, resource groups
      3. Enumerates reachable resources (storage accounts + key vaults)
      4. Computes: reachable_privileged_resource_count, high_value_targets
      5. Cross-references blast_radius_results for risk_score / exposure_level
      6. Computes risk flags using configurable thresholds
      7. Persists into identity_reachability table
    """
    from psycopg2.extras import RealDictCursor
    from app.constants.blast_radius_policy import (
        get_thresholds, SCOPE_RANK, DORMANT_ACTIVITY_STATUSES,
        AI_IDENTITY_TYPES, MAX_REACHABLE_RESOURCES_PER_IDENTITY,
    )
    from app.constants.roles import PRIVILEGED_RBAC_ROLES, PRIVILEGED_ENTRA_ROLES

    # Load thresholds (with optional tenant overrides from settings)
    thresholds = get_thresholds(db, db_org_id)

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # ── Load identities for this run ──
    cursor.execute("""
        SELECT i.id, i.identity_id, i.display_name, i.identity_category,
               COALESCE(i.agent_identity_type, '') as agent_identity_type,
               COALESCE(i.activity_status, 'unknown') as activity_status
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND NOT COALESCE(i.is_microsoft_system, false)
        ORDER BY i.id
    """, (current_run_id,))
    identities = cursor.fetchall()

    if not identities:
        cursor.close()
        logger.info("Reachability: no identities for run #%s", current_run_id)
        return

    identity_ids = [r['id'] for r in identities]

    # ── Load RBAC role assignments (grouped by identity) ──
    rbac_by_id = {}
    cursor.execute("""
        SELECT ra.identity_db_id, ra.role_name, ra.scope, ra.scope_type
        FROM role_assignments ra
        WHERE ra.identity_db_id = ANY(%s)
    """, (identity_ids,))
    for ra in cursor.fetchall():
        rbac_by_id.setdefault(ra['identity_db_id'], []).append(dict(ra))

    # ── Load Entra role assignments ──
    entra_by_id = {}
    try:
        cursor.execute("SAVEPOINT _reach_entra")
        cursor.execute("""
            SELECT era.identity_db_id, era.role_name
            FROM entra_role_assignments era
            WHERE era.identity_db_id = ANY(%s)
        """, (identity_ids,))
        for era in cursor.fetchall():
            entra_by_id.setdefault(era['identity_db_id'], []).append(dict(era))
        cursor.execute("RELEASE SAVEPOINT _reach_entra")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT _reach_entra")
        except Exception:
            pass

    # ── Load group-inherited RBAC ──
    try:
        cursor.execute("SAVEPOINT _reach_group_rbac")
        cursor.execute("""
            SELECT eg.identity_db_id, eg.rbac_roles
            FROM entra_groups eg
            WHERE eg.identity_db_id = ANY(%s)
              AND eg.rbac_roles IS NOT NULL
              AND eg.rbac_roles != '[]'::jsonb
        """, (identity_ids,))
        for gr in cursor.fetchall():
            roles = gr['rbac_roles']
            if isinstance(roles, str):
                import json as _json
                roles = _json.loads(roles)
            if isinstance(roles, list):
                for role in roles:
                    if isinstance(role, dict):
                        rbac_by_id.setdefault(gr['identity_db_id'], []).append(role)
        cursor.execute("RELEASE SAVEPOINT _reach_group_rbac")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT _reach_group_rbac")
        except Exception:
            pass

    # ── Load resources (from discovered_resources, fallback to legacy tables) ──
    resources = []
    try:
        cursor.execute("SAVEPOINT _reach_resources")
        cursor.execute("""
            SELECT resource_id, subscription_id, resource_group,
                   resource_type, data_classification, risk_level,
                   is_high_value
            FROM discovered_resources
            WHERE discovery_run_id = %s AND organization_id = %s
        """, (current_run_id, db_org_id))
        resources = [dict(r) for r in cursor.fetchall()]
        cursor.execute("RELEASE SAVEPOINT _reach_resources")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT _reach_resources")
        except Exception:
            pass

    # Fallback to legacy tables if discovered_resources is empty
    if not resources:
        try:
            cursor.execute("SAVEPOINT _reach_resources_legacy")
            cursor.execute("""
                SELECT resource_id, subscription_id, resource_group,
                       'storage_account' as resource_type, data_classification,
                       risk_level
                FROM azure_storage_accounts
                WHERE discovery_run_id = %s
            """, (current_run_id,))
            resources.extend([dict(r) for r in cursor.fetchall()])
            cursor.execute("""
                SELECT resource_id, subscription_id, resource_group,
                       'key_vault' as resource_type, data_classification,
                       risk_level
                FROM azure_key_vaults
                WHERE discovery_run_id = %s
            """, (current_run_id,))
            resources.extend([dict(r) for r in cursor.fetchall()])
            cursor.execute("RELEASE SAVEPOINT _reach_resources_legacy")
        except Exception:
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT _reach_resources_legacy")
            except Exception:
                pass

    # ── Load existing blast radius results for cross-reference ──
    br_by_id = {}
    try:
        cursor.execute("SAVEPOINT _reach_br")
        cursor.execute("""
            SELECT identity_id, risk_score, identity_exposure_level
            FROM blast_radius_results
            WHERE discovery_run_id = %s
        """, (current_run_id,))
        for br in cursor.fetchall():
            br_by_id[br['identity_id']] = dict(br)
        cursor.execute("RELEASE SAVEPOINT _reach_br")
    except Exception:
        try:
            cursor.execute("ROLLBACK TO SAVEPOINT _reach_br")
        except Exception:
            pass

    # ── Process each identity ──
    results = []
    for ident in identities:
        idb_id = ident['id']
        rbac = rbac_by_id.get(idb_id, [])
        entra = entra_by_id.get(idb_id, [])

        # Expand scopes → reachable resources
        scopes = {'subscription': set(), 'resource_group': set(), 'resource': set(), 'management_group': set()}
        for ra in rbac:
            st = ra.get('scope_type', '')
            scope = (ra.get('scope') or '').lower()
            if st in scopes and scope:
                scopes[st].add(scope)
                if st in ('subscription', 'management_group'):
                    scopes['subscription'].add(scope)

        # Enumerate reachable resources
        reachable = []
        for res in resources:
            if len(reachable) >= MAX_REACHABLE_RESOURCES_PER_IDENTITY:
                break
            res_id = (res.get('resource_id') or '').lower()
            res_sub = (res.get('subscription_id') or '').lower()
            res_rg = (res.get('resource_group') or '').lower()

            matched = False
            for sub_scope in scopes.get('subscription', set()):
                if res_sub and res_sub in sub_scope:
                    matched = True
                    break
            if not matched:
                for mg_scope in scopes.get('management_group', set()):
                    if res_sub and res_sub in mg_scope:
                        matched = True
                        break
            if not matched:
                for rg_scope in scopes.get('resource_group', set()):
                    if res_rg and res_rg.lower() in rg_scope:
                        matched = True
                        break
            if not matched:
                for r_scope in scopes.get('resource', set()):
                    if res_id and res_id in r_scope:
                        matched = True
                        break
            if matched:
                reachable.append(res)

        # ── Compute reachability metrics ──
        sub_ids = set()
        rg_ids = set()
        for r in reachable:
            if r.get('subscription_id'):
                sub_ids.add(r['subscription_id'])
            if r.get('resource_group'):
                rg_ids.add(r['resource_group'])

        reachable_resource_count = len(reachable)
        subscriptions_reachable = len(sub_ids)
        resource_groups_reachable = len(rg_ids)

        # Privileged resource count: resources reachable via privileged RBAC roles
        priv_scopes = {'subscription': set(), 'resource_group': set(), 'resource': set(), 'management_group': set()}
        for ra in rbac:
            if ra.get('role_name') in PRIVILEGED_RBAC_ROLES:
                st = ra.get('scope_type', '')
                scope = (ra.get('scope') or '').lower()
                if st in priv_scopes and scope:
                    priv_scopes[st].add(scope)
                    if st in ('subscription', 'management_group'):
                        priv_scopes['subscription'].add(scope)

        priv_reachable = 0
        for res in reachable:
            res_id = (res.get('resource_id') or '').lower()
            res_sub = (res.get('subscription_id') or '').lower()
            res_rg = (res.get('resource_group') or '').lower()
            matched = False
            for sub_scope in priv_scopes.get('subscription', set()):
                if res_sub and res_sub in sub_scope:
                    matched = True
                    break
            if not matched:
                for rg_scope in priv_scopes.get('resource_group', set()):
                    if res_rg and res_rg.lower() in rg_scope:
                        matched = True
                        break
            if not matched:
                for r_scope in priv_scopes.get('resource', set()):
                    if res_id and res_id in r_scope:
                        matched = True
                        break
            if matched:
                priv_reachable += 1

        # High-value targets: is_high_value flag, key vaults, or classified data
        hvt = 0
        for r in reachable:
            if r.get('is_high_value'):
                hvt += 1
            elif r.get('resource_type') == 'key_vault':
                hvt += 1
            elif r.get('data_classification'):
                hvt += 1

        # Privileged role analysis
        priv_role_names = set()
        for ra in rbac:
            if ra.get('role_name') in PRIVILEGED_RBAC_ROLES:
                priv_role_names.add(ra['role_name'])
        for era in entra:
            if era.get('role_name') in PRIVILEGED_ENTRA_ROLES:
                priv_role_names.add(era['role_name'])
        has_privileged = bool(priv_role_names)

        # Highest scope type
        highest_scope = None
        max_rank = 0
        for ra in rbac:
            st = ra.get('scope_type', '')
            rank = SCOPE_RANK.get(st, 0)
            if rank > max_rank:
                max_rank = rank
                highest_scope = st

        # Cross-reference blast radius results
        br = br_by_id.get(idb_id, {})
        br_risk_score = br.get('risk_score', 0)
        br_exposure = br.get('identity_exposure_level', 'LOW')

        agent_type = ident.get('agent_identity_type', '') or ''
        activity = ident.get('activity_status', 'unknown') or 'unknown'

        # ── Risk flags (using centralized thresholds) ──
        flags = []

        t_broad = thresholds['broad_blast_radius_threshold']
        t_broad_crit = thresholds['broad_blast_radius_critical_threshold']
        flag_broad = reachable_resource_count >= t_broad
        if flag_broad:
            flags.append({
                'flag': 'broad_blast_radius',
                'flag_reason': f'Identity can reach {reachable_resource_count} resources '
                               f'across {subscriptions_reachable} subscriptions',
                'trigger_metric': reachable_resource_count,
                'threshold_used': t_broad,
                'threshold_source': 'blast_radius_policy',
                'severity': 'high' if reachable_resource_count >= t_broad_crit else 'medium',
            })

        t_priv_sub = thresholds['privileged_wide_reach_subscription_threshold']
        t_priv_crit = thresholds['privileged_wide_reach_critical_subscription_threshold']
        flag_priv_wide = has_privileged and subscriptions_reachable >= t_priv_sub
        if flag_priv_wide:
            flags.append({
                'flag': 'privileged_wide_reach',
                'flag_reason': f'Privileged identity spans {subscriptions_reachable} subscriptions '
                               f'with roles: {", ".join(sorted(priv_role_names))}',
                'trigger_metric': subscriptions_reachable,
                'threshold_used': t_priv_sub,
                'threshold_source': 'blast_radius_policy',
                'severity': 'critical' if subscriptions_reachable >= t_priv_crit else 'high',
            })

        t_ai = thresholds['ai_excessive_blast_threshold']
        flag_ai = agent_type in AI_IDENTITY_TYPES and reachable_resource_count >= t_ai
        if flag_ai:
            flags.append({
                'flag': 'ai_excessive_blast',
                'flag_reason': f'AI agent identity ({agent_type}) can reach '
                               f'{reachable_resource_count} resources',
                'trigger_metric': reachable_resource_count,
                'threshold_used': t_ai,
                'threshold_source': 'blast_radius_policy',
                'severity': 'high',
            })

        t_dormant = thresholds['dormant_high_blast_threshold']
        t_dormant_sev = thresholds['dormant_high_blast_severe_threshold']
        flag_dormant = activity in DORMANT_ACTIVITY_STATUSES and reachable_resource_count >= t_dormant
        if flag_dormant:
            flags.append({
                'flag': 'dormant_high_blast',
                'flag_reason': f'{activity} identity can reach {reachable_resource_count} resources '
                               f'including {hvt} high-value targets',
                'trigger_metric': reachable_resource_count,
                'threshold_used': t_dormant,
                'threshold_source': 'blast_radius_policy',
                'severity': 'high' if reachable_resource_count >= t_dormant_sev else 'medium',
            })

        results.append({
            'organization_id': db_org_id,
            'identity_id': ident['identity_id'],
            'identity_db_id': idb_id,
            'display_name': ident['display_name'],
            'identity_category': ident['identity_category'],
            'reachable_resource_count': reachable_resource_count,
            'reachable_privileged_resource_count': priv_reachable,
            'subscriptions_reachable': subscriptions_reachable,
            'resource_groups_reachable': resource_groups_reachable,
            'high_value_targets_reachable': hvt,
            'has_privileged_roles': has_privileged,
            'privileged_role_names': sorted(priv_role_names),
            'highest_scope_type': highest_scope,
            'flag_broad_blast_radius': flag_broad,
            'flag_privileged_wide_reach': flag_priv_wide,
            'flag_ai_excessive_blast': flag_ai,
            'flag_dormant_high_blast': flag_dormant,
            'risk_flag_count': len(flags),
            'risk_flag_details': flags,
            'blast_radius_risk_score': br_risk_score,
            'blast_radius_exposure_level': br_exposure,
            'agent_identity_type': agent_type or None,
            'activity_status': activity,
        })

    # ── Persist ──
    cursor.close()
    count = db.save_identity_reachability(current_run_id, results)
    flagged = sum(1 for r in results if r['risk_flag_count'] > 0)
    logger.info(
        "Reachability computation complete: %d identities, %d flagged "
        "(org=%s, run=%s)",
        len(results), flagged, db_org_id, current_run_id,
    )


def _dispatch_notification(event_type: str, event_data: dict, db_org_id: int = None):
    """Phase 83: Dispatch notification to Slack/Teams if configured."""
    try:
        from app.services.notification_dispatcher import NotificationDispatcher
        db = Database(organization_id=db_org_id)
        dispatcher = NotificationDispatcher()
        dispatcher.dispatch(event_type, event_data, db)
        db.close()
    except Exception as e:
        logger.warning(f"Failed to dispatch {event_type} notification: {e}")


def _launch_owned_objects_background(db_org_id: int, conn: dict):
    """Launch background thread to enrich SPNs with owned/created objects.

    Runs after scan completes so it doesn't block the main pipeline (~12 min savings).
    Uses parallel Graph API calls with semaphore throttling.
    """
    import threading

    azure_directory_id = conn.get('azure_directory_id')
    client_id = conn.get('client_id')
    metadata = conn.get('metadata') or {}

    # Decrypt credential if encrypted
    from app.encryption import decrypt_field
    raw_secret = metadata.get('client_secret')
    client_secret = decrypt_field(raw_secret) if raw_secret else None

    if not all([azure_directory_id, client_id, client_secret]):
        logger.warning("[owned_objects_bg] Skipping — incomplete credentials for connection %s", conn.get('id'))
        return

    def _run():
        nonlocal client_secret
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Find latest completed run for this org
            db = Database()
            try:
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT id FROM discovery_runs
                    WHERE organization_id = %s AND status = 'completed'
                    ORDER BY id DESC LIMIT 1
                """, (db_org_id,))
                row = cursor.fetchone()
                cursor.close()
                run_id = row[0] if row else None
            except Exception as e:
                logger.error("[owned_objects_bg] Failed to find run_id: %s", e)
                db.close()
                return
            finally:
                try:
                    db.conn.rollback()
                except Exception:
                    pass
            db.close()

            if not run_id:
                logger.warning("[owned_objects_bg] No completed run found for org=%s", db_org_id)
                return

            from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
            loop.run_until_complete(
                AzureDiscoveryEngine.enrich_owned_objects_background(
                    azure_directory_id=azure_directory_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    db_org_id=db_org_id,
                    run_id=run_id,
                )
            )
            loop.close()
        except Exception as e:
            logger.error("[owned_objects_bg] Background enrichment failed: %s", e)
        finally:
            client_secret = None  # AG-116: zero secret after background work completes

    t = threading.Thread(target=_run, name=f"owned_objects_bg_org{db_org_id}", daemon=True)
    t.start()
    logger.info("[owned_objects_bg] Background thread launched for org=%s connection=%s",
                db_org_id, conn.get('id'))


def _launch_ip_enrichment_background(db_org_id: int, conn: dict):
    """Launch background thread to enrich identities with last observed IP.

    Runs after scan completes so it doesn't block the main pipeline (~121s savings).
    Uses parallel API calls with semaphore throttling.
    """
    import threading

    azure_directory_id = conn.get('azure_directory_id')
    client_id = conn.get('client_id')
    metadata = conn.get('metadata') or {}

    from app.encryption import decrypt_field
    raw_secret = metadata.get('client_secret')
    client_secret = decrypt_field(raw_secret) if raw_secret else None

    if not all([azure_directory_id, client_id, client_secret]):
        logger.warning("[ip_enrichment_bg] Skipping — incomplete credentials for connection %s", conn.get('id'))
        return

    def _run():
        nonlocal client_secret
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Find latest completed run for this org
            db = Database()
            try:
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT id FROM discovery_runs
                    WHERE organization_id = %s AND status = 'completed'
                    ORDER BY id DESC LIMIT 1
                """, (db_org_id,))
                row = cursor.fetchone()
                cursor.close()
                run_id = row[0] if row else None
            except Exception as e:
                logger.error("[ip_enrichment_bg] Failed to find run_id: %s", e)
                db.close()
                return
            finally:
                try:
                    db.conn.rollback()
                except Exception:
                    pass
            db.close()

            if not run_id:
                logger.warning("[ip_enrichment_bg] No completed run found for org=%s", db_org_id)
                return

            # Fetch subscription IDs using the service principal
            sub_ids = []
            try:
                from azure.identity import ClientSecretCredential
                from azure.mgmt.resource import SubscriptionClient
                cred = ClientSecretCredential(
                    tenant_id=azure_directory_id,
                    client_id=client_id,
                    client_secret=client_secret,
                )
                sub_client = SubscriptionClient(cred)
                for sub in sub_client.subscriptions.list():
                    if sub.state and sub.state.lower() == 'enabled':
                        sub_ids.append(sub.subscription_id)
                logger.info("[ip_enrichment_bg] Found %d subscriptions for ARM queries", len(sub_ids))
            except Exception as e:
                logger.warning("[ip_enrichment_bg] Failed to list subscriptions: %s", e)

            from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
            loop.run_until_complete(
                AzureDiscoveryEngine.enrich_ips_background(
                    azure_directory_id=azure_directory_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    db_org_id=db_org_id,
                    run_id=run_id,
                    subscription_ids=sub_ids,
                )
            )
            loop.close()
        except Exception as e:
            logger.error("[ip_enrichment_bg] Background enrichment failed: %s", e)
        finally:
            client_secret = None  # AG-116: zero secret after background work completes

    t = threading.Thread(target=_run, name=f"ip_enrichment_bg_org{db_org_id}", daemon=True)
    t.start()
    logger.info("[ip_enrichment_bg] Background thread launched for org=%s connection=%s",
                db_org_id, conn.get('id'))


def _launch_signin_intelligence_background(db_org_id: int, conn: dict):
    """Launch background thread to enrich SPNs with sign-in intelligence.

    Runs after scan completes so it doesn't block the main pipeline (~205s savings).
    Uses parallel API calls with semaphore throttling.
    """
    import threading

    azure_directory_id = conn.get('azure_directory_id')
    client_id = conn.get('client_id')
    metadata = conn.get('metadata') or {}

    from app.encryption import decrypt_field
    raw_secret = metadata.get('client_secret')
    client_secret = decrypt_field(raw_secret) if raw_secret else None

    if not all([azure_directory_id, client_id, client_secret]):
        logger.warning("[signin_intel_bg] Skipping — incomplete credentials for connection %s", conn.get('id'))
        return

    connection_id = conn.get('id')

    def _run():
        nonlocal client_secret
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Find latest completed run for this org
            db = Database()
            try:
                cursor = db.conn.cursor()
                cursor.execute("""
                    SELECT id FROM discovery_runs
                    WHERE organization_id = %s AND status = 'completed'
                    ORDER BY id DESC LIMIT 1
                """, (db_org_id,))
                row = cursor.fetchone()
                cursor.close()
                run_id = row[0] if row else None
            except Exception as e:
                logger.error("[signin_intel_bg] Failed to find run_id: %s", e)
                db.close()
                return
            finally:
                try:
                    db.conn.rollback()
                except Exception:
                    pass
            db.close()

            if not run_id:
                logger.warning("[signin_intel_bg] No completed run found for org=%s", db_org_id)
                return

            from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
            loop.run_until_complete(
                AzureDiscoveryEngine.enrich_signin_intelligence_background(
                    azure_directory_id=azure_directory_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    db_org_id=db_org_id,
                    run_id=run_id,
                    cloud_connection_id=connection_id,
                )
            )
            loop.close()
        except Exception as e:
            logger.error("[signin_intel_bg] Background enrichment failed: %s", e)
        finally:
            client_secret = None  # AG-116: zero secret after background work completes

    t = threading.Thread(target=_run, name=f"signin_intel_bg_org{db_org_id}", daemon=True)
    t.start()
    logger.info("[signin_intel_bg] Background thread launched for org=%s connection=%s",
                db_org_id, conn.get('id'))


def _save_compliance_snapshot(run_id: int, db: Database):
    """Compute and persist compliance scores for a completed discovery run."""
    try:
        from app.api.handlers import _compute_compliance_metrics, _evaluate_control
        cursor = db.conn.cursor()
        metrics = _compute_compliance_metrics(cursor, run_id)
        cursor.close()

        frameworks = db.get_compliance_frameworks(enabled_only=True)
        for fw in frameworks:
            pass_count = 0
            for ctrl in fw['controls']:
                status, _value = _evaluate_control(ctrl, metrics)
                if status == 'pass':
                    pass_count += 1
            total = len(fw['controls'])
            warn_count = sum(1 for c in fw['controls'] if _evaluate_control(c, metrics)[0] == 'warn')
            fail_count = total - pass_count - warn_count
            score = round(pass_count / total * 100) if total else 0
            db.save_compliance_snapshot(
                run_id, fw['key'], fw['name'], score,
                pass_count, warn_count, fail_count, total, metrics
            )
        logger.info(f"Compliance snapshots saved for run #{run_id} ({len(frameworks)} frameworks)")
    except Exception as e:
        logger.error(f"Error saving compliance snapshot: {e}")


def _compute_risk_summary(run_id: int, organization_id: int, db: Database):
    """Compute and persist canonical risk summary (includes AGIRS computation)."""
    try:
        from app.engines.risk.risk_summary_engine import RiskSummaryEngine
        from app.engines.discovery.pipeline_validator import log_stage

        log_stage(db, run_id, organization_id, 'risk_engine', 6, 'running')

        # Get all latest run IDs for this org
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT DISTINCT ON (cloud_connection_id) id
            FROM discovery_runs
            WHERE organization_id = %s AND status = 'completed'
              AND cloud_connection_id IS NOT NULL
            ORDER BY cloud_connection_id, id DESC
        """, (organization_id,))
        run_ids = [r[0] for r in cursor.fetchall()]
        cursor.close()

        if not run_ids:
            run_ids = [run_id]

        engine = RiskSummaryEngine(db, organization_id, run_ids)
        summary = engine.compute()
        engine.persist(summary)

        # Invalidate CISO dashboard cache after risk recomputation
        try:
            from app.api.handlers import _ciso_cache_invalidate
            _ciso_cache_invalidate(organization_id)
        except Exception:
            pass  # non-critical — cache will expire via TTL

        log_stage(db, run_id, organization_id, 'risk_engine', 6, 'completed',
                  count=summary.get('total_identities', 0))

        # Step 5: Explicit AGIRS pipeline log
        agirs = summary.get('agirs_score')
        hiri = summary.get('hiri_score')
        nhiri = summary.get('nhiri_score')
        gei = summary.get('gei_score')
        logger.info(
            "Risk summary computed for run #%d: total=%d ghost=%d orphaned=%d over_priv=%d "
            "AGIRS=%.2f (HIRI=%.2f NHIRI=%.2f GEI=%.2f tier=%s)",
            run_id,
            summary.get('total_identities', 0),
            summary.get('ghost_accounts', 0),
            summary.get('orphaned_spns', 0),
            summary.get('over_privileged', 0),
            agirs or 0, hiri or 0, nhiri or 0, gei or 0,
            summary.get('agirs_tier', 'N/A'),
        )
        if agirs is None or agirs == 0:
            logger.error(
                "AGIRS STILL ZERO after risk summary for run #%d — "
                "check AGIRSEngine logs above for root cause",
                run_id,
            )
    except Exception as e:
        logger.error(f"Error computing risk summary: {e}")
        try:
            from app.engines.discovery.pipeline_validator import log_stage
            log_stage(db, run_id, organization_id, 'risk_engine', 6, 'failed', error=str(e))
        except Exception:
            pass


def _validate_snapshot(run_id: int, organization_id: int, db: Database):
    """Validate snapshot completeness and log results (non-blocking)."""
    try:
        from app.engines.discovery.pipeline_validator import (
            validate_snapshot_completeness, log_stage
        )

        log_stage(db, run_id, organization_id, 'snapshot_commit', 7, 'running')
        result = validate_snapshot_completeness(db, run_id, organization_id)

        if result['valid']:
            log_stage(db, run_id, organization_id, 'snapshot_commit', 7, 'completed',
                      count=sum(result['components'].values()))
            logger.info("Snapshot validation passed for run #%d: %s", run_id, result['components'])
        else:
            log_stage(db, run_id, organization_id, 'snapshot_commit', 7, 'failed',
                      error=f"Missing: {', '.join(result['missing'])}")
            logger.warning("Snapshot validation failed for run #%d: missing %s", run_id, result['missing'])
    except Exception as e:
        logger.error(f"Error validating snapshot: {e}")


def _fire_webhook_events(current_run_id: int, changes: dict, db: Database):
    """Fire webhook events for discovery completion and detected changes."""
    try:
        from app.services.webhook_service import WebhookService
        wh_service = WebhookService()

        # Get run summary for the payload
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT total_identities, critical_count, high_count, medium_count, low_count
            FROM discovery_runs WHERE id = %s
        """, (current_run_id,))
        run_row = cursor.fetchone()
        cursor.close()

        run_summary = {}
        if run_row:
            run_summary = {
                'total_identities': run_row[0] or 0,
                'critical': run_row[1] or 0,
                'high': run_row[2] or 0,
                'medium': run_row[3] or 0,
                'low': run_row[4] or 0,
            }

        # Always fire discovery_completed
        wh_service.trigger_event('discovery_completed', {
            'run_id': current_run_id,
            'summary': run_summary,
        })

        # Fire per-change-type events
        new_ids = changes.get('new_identities', [])
        if new_ids:
            wh_service.trigger_event('new_identities', {
                'run_id': current_run_id,
                'count': len(new_ids),
                'identities': [{'display_name': i.get('display_name'), 'risk_level': i.get('risk_level')} for i in new_ids[:20]],
            })

        removed_ids = changes.get('removed_identities', [])
        if removed_ids:
            wh_service.trigger_event('removed_identities', {
                'run_id': current_run_id,
                'count': len(removed_ids),
                'identities': [{'display_name': i.get('display_name')} for i in removed_ids[:20]],
            })

        perm_changes = changes.get('permission_changes', [])
        if perm_changes:
            wh_service.trigger_event('permission_changes', {
                'run_id': current_run_id,
                'count': len(perm_changes),
                'changes': [{'display_name': c.get('display_name'), 'summary': c.get('summary', '')} for c in perm_changes[:20]],
            })

        risk_changes = changes.get('risk_changes', [])
        if risk_changes:
            # Check for escalations (risk increased)
            escalations = [c for c in risk_changes if c.get('direction') == 'increased' or c.get('new_risk') in ('critical', 'high')]
            if escalations:
                wh_service.trigger_event('risk_escalation', {
                    'run_id': current_run_id,
                    'count': len(escalations),
                    'escalations': [{'display_name': c.get('display_name'), 'old_risk': c.get('old_risk'), 'new_risk': c.get('new_risk')} for c in escalations[:20]],
                })

        cred_changes = changes.get('credential_changes', [])
        if cred_changes:
            wh_service.trigger_event('credential_changes', {
                'run_id': current_run_id,
                'count': len(cred_changes),
                'changes': [{'display_name': c.get('display_name'), 'summary': c.get('summary', '')} for c in cred_changes[:20]],
            })

        # Fire drift_detected if any changes at all
        total_changes = len(new_ids) + len(removed_ids) + len(perm_changes) + len(risk_changes) + len(cred_changes)
        if total_changes > 0:
            wh_service.trigger_event('drift_detected', {
                'run_id': current_run_id,
                'total_changes': total_changes,
                'breakdown': {
                    'new_identities': len(new_ids),
                    'removed_identities': len(removed_ids),
                    'permission_changes': len(perm_changes),
                    'risk_changes': len(risk_changes),
                    'credential_changes': len(cred_changes),
                },
            })

        logger.info(f"Webhook events fired for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Error firing webhook events: {e}")


def _generate_notifications(current_run_id: int, changes: dict, db: Database):
    """Generate in-app notifications from discovery changes."""
    try:
        from app.services.notification_service import NotificationService
        notifier = NotificationService()

        # Look up organization_id from the discovery run
        cursor = db.conn.cursor()
        cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (current_run_id,))
        run_org = cursor.fetchone()
        oid = run_org[0] if run_org else None
        cursor.close()

        # Get run summary
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT total_identities, critical_count, high_count, medium_count, low_count
            FROM discovery_runs WHERE id = %s
        """, (current_run_id,))
        run_row = cursor.fetchone()
        cursor.close()

        summary = {}
        if run_row:
            summary = {
                'total_identities': run_row[0] or 0,
                'critical': run_row[1] or 0,
                'high': run_row[2] or 0,
                'medium': run_row[3] or 0,
                'low': run_row[4] or 0,
            }

        notifier.notify_discovery_completed(current_run_id, summary, organization_id=oid)

        new_ids = changes.get('new_identities', [])
        if new_ids:
            notifier.notify_new_identities(current_run_id, new_ids, organization_id=oid)

        removed_ids = changes.get('removed_identities', [])
        if removed_ids:
            notifier.notify_removed_identities(current_run_id, removed_ids, organization_id=oid)

        risk_changes = changes.get('risk_changes', [])
        escalations = [c for c in risk_changes if c.get('direction') == 'increased' or c.get('new_risk') in ('critical', 'high')]
        if escalations:
            notifier.notify_risk_escalations(current_run_id, escalations, organization_id=oid)

        perm_changes = changes.get('permission_changes', [])
        if perm_changes:
            notifier.notify_permission_changes(current_run_id, perm_changes, organization_id=oid)

        cred_changes = changes.get('credential_changes', [])
        if cred_changes:
            notifier.notify_credential_changes(current_run_id, cred_changes, organization_id=oid)

        # Cleanup old notifications
        cleaned = db.cleanup_old_notifications(days=90)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old notifications")

        logger.info(f"In-app notifications generated for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Error generating notifications: {e}")


def _run_ghost_detection(current_run_id: int, db: Database):
    """Detect disabled/deleted identities retaining active role assignments."""
    try:
        from app.engines.ghost_detector import GhostIdentityDetector
        ghost_detector = GhostIdentityDetector(db)
        ghost_anomalies = ghost_detector.detect(current_run_id)
        if ghost_anomalies:
            count = db.save_anomalies(current_run_id, ghost_anomalies)
            logger.info(f"Ghost detection: {count} ghost identities found for run #{current_run_id}")
            _generate_anomaly_notifications(current_run_id, ghost_anomalies, db)
            critical_ghosts = [a for a in ghost_anomalies if a.get('severity') == 'critical']
            if critical_ghosts:
                _dispatch_notification('anomaly_detected', {
                    'title': f'{len(critical_ghosts)} Critical Ghost Identities Detected',
                    'description': f'Run #{current_run_id}: {", ".join(a["identity_name"] for a in critical_ghosts[:3])} retain active roles despite being disabled/deleted',
                    'severity': 'critical',
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Ghost detection: no ghost identities found for run #{current_run_id}")
    except Exception as e:
        logger.error(f"Ghost detection failed: {e}")
        logger.exception(e)


def _run_identity_correlation(current_run_id: int, db: Database):
    """Run Identity Correlation Engine: link regular ↔ privileged accounts, detect orphans + zombies."""
    try:
        from app.engines.correlation.identity_correlator import IdentityCorrelator
        from app.engines.correlation.orphaned_detector import OrphanedAccountDetector
        from app.engines.correlation.zombie_detector import ZombiePersonaDetector

        correlator = IdentityCorrelator(db)
        result = correlator.correlate(current_run_id)
        logger.info(f"ICE correlation: {result}")

        # Always run orphan detection (existing links from prior runs should be re-checked)
        if result.get('status') == 'completed':
            detector = OrphanedAccountDetector(db)
            orphan_anomalies = detector.detect(current_run_id)
            if orphan_anomalies:
                count = db.save_anomalies(current_run_id, orphan_anomalies)
                logger.info(f"ICE orphan detection: {count} orphaned privileged accounts found")
                _generate_anomaly_notifications(current_run_id, orphan_anomalies, db)
                critical = [a for a in orphan_anomalies if a.get('severity') == 'critical']
                if critical:
                    _dispatch_notification('anomaly_detected', {
                        'title': f'{len(critical)} Orphaned Privileged Accounts Detected',
                        'description': (
                            f'Run #{current_run_id}: '
                            f'{", ".join(a["identity_name"] for a in critical[:3])} '
                            f'retain active roles while paired regular accounts are disabled'
                        ),
                        'severity': 'critical',
                    }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
            else:
                logger.info("ICE orphan detection: no orphaned privileged accounts found")

            # Zombie persona detection: disabled account with correlated active account
            zombie = ZombiePersonaDetector(db)
            zombie_anomalies = zombie.detect(current_run_id)
            if zombie_anomalies:
                count = db.save_anomalies(current_run_id, zombie_anomalies)
                logger.info(f"ICE zombie detection: {count} zombie personas found")
                _generate_anomaly_notifications(current_run_id, zombie_anomalies, db)
                critical = [a for a in zombie_anomalies if a.get('severity') == 'critical']
                if critical:
                    _dispatch_notification('anomaly_detected', {
                        'title': f'{len(critical)} Zombie Personas Detected',
                        'description': (
                            f'Run #{current_run_id}: '
                            f'{", ".join(a["identity_name"] for a in critical[:3])} '
                            f'retain access via correlated active accounts'
                        ),
                        'severity': 'critical',
                    }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
            else:
                logger.info("ICE zombie detection: no zombie personas found")
    except Exception as e:
        logger.error(f"Identity correlation failed: {e}")
        logger.exception(e)


def _run_anomaly_detection(current_run_id: int, previous_run_id: int, db: Database):
    """Run anomaly detection after drift analysis and persist results."""
    try:
        # Load configurable thresholds from settings
        settings = {}
        for key in ('anomaly_pim_hours_start', 'anomaly_pim_hours_end',
                     'anomaly_pim_frequency_threshold', 'anomaly_risk_spike_threshold'):
            val = db.get_system_setting(key, None)
            if val is not None:
                settings[key] = val

        detector = AnomalyDetector(db)
        anomalies = detector.analyze(current_run_id, previous_run_id, settings)

        if anomalies:
            count = db.save_anomalies(current_run_id, anomalies)
            logger.info(f"Anomaly detection: {count} anomalies saved for run #{current_run_id}")
            _generate_anomaly_notifications(current_run_id, anomalies, db)
            # Phase 43: SOAR evaluation for anomalies
            _evaluate_soar_triggers('anomaly', anomalies, db)
            # Phase 83: Dispatch anomaly notifications for critical/high
            critical_anomalies = [a for a in anomalies if a.get('severity') in ('critical', 'high')]
            if critical_anomalies:
                _dispatch_notification('anomaly_detected', {
                    'title': f'{len(critical_anomalies)} Critical/High Anomalies Detected',
                    'description': f'Run #{current_run_id}: {", ".join(a["title"] for a in critical_anomalies[:3])}',
                    'severity': critical_anomalies[0].get('severity', 'high'),
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Anomaly detection: no anomalies found for run #{current_run_id}")

        # Cleanup old resolved anomalies
        cleaned = db.cleanup_old_anomalies(days=180)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old resolved anomalies")

    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        logger.exception(e)


def _run_resource_anomaly_detection(current_run_id: int, previous_run_id: int, db: Database):
    """Run resource anomaly detection after identity anomaly detection."""
    try:
        from app.engines.resource_anomaly_detector import ResourceAnomalyDetector

        settings = {}
        for key in ('resource_anomaly_score_spike_threshold', 'resource_anomaly_expiry_window_days',
                     'resource_anomaly_expiry_threshold', 'resource_anomaly_privilege_creep_threshold'):
            val = db.get_system_setting(key, None)
            if val is not None:
                settings[key] = val

        detector = ResourceAnomalyDetector(db)
        anomalies = detector.analyze(current_run_id, previous_run_id, settings)

        if anomalies:
            count = db.save_anomalies(current_run_id, anomalies)
            logger.info(f"Resource anomaly detection: {count} anomalies saved for run #{current_run_id}")
            _generate_anomaly_notifications(current_run_id, anomalies, db)
            critical_anomalies = [a for a in anomalies if a.get('severity') in ('critical', 'high')]
            if critical_anomalies:
                _dispatch_notification('anomaly_detected', {
                    'title': f'{len(critical_anomalies)} Resource Anomalies Detected',
                    'description': f'Run #{current_run_id}: {", ".join(a["title"] for a in critical_anomalies[:3])}',
                    'severity': critical_anomalies[0].get('severity', 'high'),
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Resource anomaly detection: no anomalies found for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Resource anomaly detection failed: {e}")
        logger.exception(e)


def _run_security_findings(current_run_id: int, db: Database):
    """Run security findings engine after resource anomaly detection."""
    try:
        from app.engines.security_findings import SecurityFindingsEngine

        engine = SecurityFindingsEngine(db)
        findings = engine.analyze(current_run_id)

        # Validation: log severity distribution
        if findings:
            sev_counts = {}
            for f in findings:
                sev = f.get('severity', 'unknown')
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            logger.info(f"Security findings distribution for run #{current_run_id}: {sev_counts}")

            count = db.save_security_findings(current_run_id, findings)
            logger.info(f"Security findings engine: {count} finding(s) saved for run #{current_run_id}")

            # Create in-app notifications for critical/high findings
            for f in findings:
                if f.get('severity') in ('critical', 'high'):
                    try:
                        db.create_notification(
                            event_type='security_finding',
                            category='security',
                            severity=f['severity'],
                            title=f['title'],
                            description=f['description'],
                            payload=f.get('metadata'),
                            related_identity_id=f.get('entity_id'),
                            related_run_id=current_run_id,
                        )
                    except Exception:
                        pass  # Non-critical

            # Dispatch Slack/Teams for critical findings
            critical = [f for f in findings if f.get('severity') == 'critical']
            if critical:
                _dispatch_notification('security_finding', {
                    'title': f'{len(critical)} Critical Security Finding(s)',
                    'description': f'Run #{current_run_id}: {", ".join(f["title"] for f in critical[:3])}',
                    'severity': 'critical',
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Security findings engine: no findings for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Security findings engine failed: {e}")
        logger.exception(e)


def _run_identity_exposure_detection(current_run_id: int, db: Database):
    """Run identity exposure detection engine and persist results."""
    try:
        from app.engines.identity_exposure_engine import IdentityExposureEngine

        engine = IdentityExposureEngine(db)
        exposures = engine.analyze(current_run_id)

        if exposures:
            count = db.save_identity_exposures(current_run_id, exposures)
            logger.info(f"Identity exposure detection: {count} exposure(s) saved for run #{current_run_id}")
        else:
            logger.info(f"Identity exposure detection: no exposures found for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Identity exposure detection failed: {e}")
        logger.exception(e)


def _run_findings_normalization(current_run_id: int, db: Database):
    """Normalize risk_findings, attack_paths, graph_attack_findings into unified security_findings."""
    try:
        count = db.normalize_findings_to_security_findings(current_run_id)
        logger.info(f"Findings normalization: {count} finding(s) normalized for run #{current_run_id}")
    except Exception as e:
        logger.error(f"Findings normalization failed: {e}")
        logger.exception(e)


def _run_attack_path_analysis(current_run_id: int, db: Database):
    """Run attack path analysis after security findings engine."""
    try:
        from app.engines.attack_path_engine import AttackPathEngine

        engine = AttackPathEngine(db)
        paths = engine.analyze(current_run_id)

        if paths:
            count = db.save_attack_paths(current_run_id, paths)
            logger.info(f"Attack path analysis: {count} path(s) saved for run #{current_run_id}")

            # Create in-app notifications for critical paths
            critical_paths = [p for p in paths if p.get('severity') == 'critical']
            for p in critical_paths:
                try:
                    db.create_notification(
                        event_type='attack_path_detected',
                        category='security',
                        severity='critical',
                        title=p.get('description', 'Critical attack path detected'),
                        description=p.get('narrative', ''),
                        payload={'path_type': p['path_type'], 'risk_score': p['risk_score']},
                        related_identity_id=p.get('source_entity_id'),
                        related_run_id=current_run_id,
                    )
                except Exception:
                    pass  # Non-critical

            # Dispatch Slack/Teams for critical paths
            if critical_paths:
                _dispatch_notification('attack_path_detected', {
                    'title': f'{len(critical_paths)} Critical Attack Path(s) Detected',
                    'description': f'Run #{current_run_id}: {", ".join(p["description"] for p in critical_paths[:3])}',
                    'severity': 'critical',
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Attack path analysis: no paths found for run #{current_run_id}")

        # BFS graph engine — converts BFS paths into attack_paths table format
        _run_bfs_attack_paths(current_run_id, db)

    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}")
        logger.exception(e)


def _convert_bfs_path_to_attack_path(bfs_path: dict) -> dict:
    """Convert a BFS GraphAttackEngine path dict into save_attack_paths() format."""
    from app.engines.attack_path_engine import compute_path_fingerprint
    nodes = bfs_path.get('attack_path_nodes', [])
    # Convert BFS node format {id, type, name, cloud} → {type, id, label, detail}
    path_nodes = []
    for n in nodes:
        path_nodes.append({
            'type': n.get('type', ''),
            'id': n.get('id', ''),
            'label': n.get('name', ''),
            'detail': n.get('cloud', 'azure'),
        })
    source_name = bfs_path.get('source_name', '')
    source_type = bfs_path.get('source_type', '')
    # Extract source_entity_id: strip "identity:" prefix if present
    raw_src = bfs_path.get('source_identity', '')
    source_entity_id = raw_src.replace('identity:', '') if raw_src.startswith('identity:') else raw_src
    finding_type = bfs_path.get('finding_type', 'PRIVILEGE_ESCALATION')
    target = bfs_path.get('target_privilege', '')
    description = f'{source_name} → {target} ({finding_type})'
    fp = compute_path_fingerprint(source_entity_id, finding_type, path_nodes)
    return {
        'path_type': finding_type.lower(),
        'source_entity_id': source_entity_id,
        'source_entity_name': source_name,
        'source_entity_type': source_type,
        'risk_score': bfs_path.get('risk_score', 0),
        'severity': bfs_path.get('severity', 'medium'),
        'path_nodes': path_nodes,
        'path_length': len(path_nodes),
        'path_fingerprint': fp,
        'description': description,
        'narrative': f'{source_name} can reach {target} through a {bfs_path.get("depth", len(nodes))}-step path.',
        'impact': f'Escalation to {target}',
        'affected_resource_count': 0,
    }


def _run_bfs_attack_paths(current_run_id: int, db: Database):
    """Run BFS GraphAttackEngine and save discovered paths to attack_paths table."""
    try:
        from app.engines.graph_attack_engine import GraphAttackEngine
        org_id = db._organization_id if hasattr(db, '_organization_id') else 1
        engine = GraphAttackEngine(db)
        result = engine.analyze(org_id, current_run_id)
        bfs_paths = result.get('paths', [])
        if bfs_paths:
            converted = [_convert_bfs_path_to_attack_path(p) for p in bfs_paths]
            count = db.save_attack_paths(current_run_id, converted)
            logger.info(f"BFS attack path analysis: {count} path(s) saved for run #{current_run_id}")
        else:
            logger.info(f"BFS attack path analysis: no paths for run #{current_run_id}")
    except Exception as e:
        logger.error(f"BFS attack path analysis failed (non-critical): {e}")


def _run_fix_recommendations(current_run_id: int, db: Database):
    """Run fix recommendations engine after attack path analysis."""
    try:
        from app.engines.fix_recommendation_engine import FixRecommendationEngine

        engine = FixRecommendationEngine(db)
        recommendations = engine.analyze(current_run_id)

        if recommendations:
            count = db.save_fix_recommendations(current_run_id, recommendations)
            logger.info(f"Fix recommendations: {count} recommendation(s) saved for run #{current_run_id}")

            # Create in-app notifications for high-priority recommendations (>= 85)
            for r in recommendations:
                if r.get('priority_score', 0) >= 85:
                    try:
                        db.create_notification(
                            event_type='fix_recommendation',
                            category='security',
                            severity='high',
                            title=r['title'],
                            description=r['description'],
                            payload={
                                'fix_type': r['fix_type'],
                                'priority_score': r['priority_score'],
                                'fix_category': r['fix_category'],
                            },
                            related_identity_id=r.get('entity_id'),
                            related_run_id=current_run_id,
                        )
                    except Exception:
                        pass  # Non-critical

            # Dispatch Slack/Teams for high-priority recommendations
            high_priority = [r for r in recommendations if r.get('priority_score', 0) >= 85]
            if high_priority:
                _dispatch_notification('fix_recommendation', {
                    'title': f'{len(high_priority)} High-Priority Fix Recommendation(s)',
                    'description': f'Run #{current_run_id}: {", ".join(r["title"] for r in high_priority[:3])}',
                    'severity': 'high',
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Fix recommendations: no recommendations for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Fix recommendations engine failed: {e}")
        logger.exception(e)


def _run_blast_radius_analysis(current_run_id: int, db: Database):
    """Run blast radius engine after fix recommendations."""
    try:
        from app.engines.blast_radius_engine import BlastRadiusEngine

        engine = BlastRadiusEngine(db)
        results = engine.analyze(current_run_id)

        if results:
            count = db.save_blast_radius_results(current_run_id, results)
            logger.info(f"Blast radius: {count} result(s) saved for run #{current_run_id}")

            # Create in-app notifications for CRITICAL exposure identities
            critical = [r for r in results if r.get('identity_exposure_level') == 'CRITICAL']
            for r in critical:
                try:
                    db.create_notification(
                        event_type='blast_radius_critical',
                        category='security',
                        severity='critical',
                        title=f'Critical blast radius: {r.get("identity_name", "Unknown")}',
                        description=(
                            f'{r.get("identity_name")} can reach {r.get("reachable_resource_count", 0)} resources '
                            f'with {r.get("sensitive_resource_count", 0)} sensitive assets'
                        ),
                        payload={
                            'identity_id': r['identity_id'],
                            'risk_score': r['risk_score'],
                            'reachable_resource_count': r['reachable_resource_count'],
                        },
                        related_run_id=current_run_id,
                    )
                except Exception:
                    pass  # Non-critical

            # Dispatch Slack/Teams for critical blast radius
            if critical:
                _dispatch_notification('blast_radius_critical', {
                    'title': f'{len(critical)} Identity(s) with CRITICAL Blast Radius',
                    'description': f'Run #{current_run_id}: {", ".join(r.get("identity_name", "?") for r in critical[:3])}',
                    'severity': 'critical',
                }, db_org_id=db._organization_id if hasattr(db, '_organization_id') else None)
        else:
            logger.info(f"Blast radius: no results for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Blast radius engine failed: {e}")
        logger.exception(e)


def _run_drift_intelligence(db_org_id: int, db: Database):
    """Enrich recent un-enriched drift reports with security intelligence."""
    try:
        from app.engines.analysis import DriftIntelligenceEngine

        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT id, current_run_id, previous_run_id, events
            FROM drift_reports
            WHERE max_severity IS NULL
              AND events IS NOT NULL
              AND created_at > NOW() - INTERVAL '1 hour'
            ORDER BY created_at DESC
            LIMIT 10
        """)
        reports = cursor.fetchall()
        cursor.close()

        if not reports:
            logger.info("Drift intelligence: no un-enriched reports found")
            return

        intel = DriftIntelligenceEngine(db)
        for report_id, current_run_id, previous_run_id, events_json in reports:
            try:
                events = events_json if isinstance(events_json, list) else json.loads(events_json or '[]')
                if not events:
                    continue

                result = intel.enrich(events, current_run_id, previous_run_id)
                db.update_drift_report_intelligence(
                    report_id,
                    result['events'],
                    result['max_severity'],
                    result['privilege_escalation_count'],
                    result['attack_path_created_count'],
                    result['identity_resurrection_count'],
                )
                logger.info(
                    f"Drift intelligence: enriched report #{report_id} "
                    f"(max_severity={result['max_severity']}, "
                    f"priv_esc={result['privilege_escalation_count']}, "
                    f"attack_paths={result['attack_path_created_count']}, "
                    f"resurrections={result['identity_resurrection_count']})"
                )
            except Exception as e:
                logger.warning(f"Drift intelligence: failed for report #{report_id}: {e}")

    except Exception as e:
        logger.error(f"Drift intelligence engine failed: {e}")
        logger.exception(e)


def _run_risk_evaluation(db_org_id, db):
    """Phase 6: Run rules-based risk evaluation against all connected connections."""
    try:
        from app.engines.risk_evaluator import RiskEvaluator
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        evaluator = RiskEvaluator(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                findings = evaluator.evaluate_risks(conn['id'], db_org_id)
                total += len(findings)
        logger.info(f"Risk evaluation: {total} finding(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Risk evaluation failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_iam_graph_build(db_org_id, db):
    """Phase 7: Build IAM relationship graph for all connected connections."""
    try:
        from app.engines.graph_builder import GraphBuilder
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        builder = GraphBuilder(db)
        total_nodes = 0
        total_edges = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                result = builder.build_iam_graph(conn['id'], db_org_id)
                total_nodes += result.get('node_count', 0)
                total_edges += result.get('edge_count', 0)
        logger.info(f"IAM graph: {total_nodes} nodes, {total_edges} edges for org {db_org_id}")
    except Exception as e:
        logger.error(f"IAM graph build failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_identity_graph_builder(db_org_id, db):
    """Build identity graph edges for all connected connections."""
    try:
        from app.engines.identity_graph_builder import build_identity_graph
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        total_edges = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                result = build_identity_graph(conn['id'], db)
                total_edges += result.get('edge_count', 0)
        logger.info(f"Identity graph builder: {total_edges} edges for org {db_org_id}")
    except Exception as e:
        logger.error(f"Identity graph builder failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_security_findings_engine(db_org_id, db):
    """Run connection-scoped security findings engine for all connections."""
    try:
        from app.engines.security_findings_engine import generate_security_findings
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        total_findings = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                result = generate_security_findings(conn['id'], db)
                total_findings += result.get('findings_count', 0)
        logger.info(f"Security findings engine (connection): {total_findings} finding(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Security findings engine (connection) failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_connection_security_posture(db_org_id, db):
    """Compute connection-scoped security posture snapshots from security_findings."""
    try:
        from app.engines.security_posture_engine import compute_security_posture
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        for conn in connections:
            if conn.get('status') == 'connected':
                compute_security_posture(conn['id'], db)
        logger.info(f"Connection security posture computed for org {db_org_id}")
    except Exception as e:
        logger.error(f"Connection security posture failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_escalation_detection(db_org_id, db):
    """Phase 8: Detect privilege escalation paths for all connected connections."""
    try:
        from app.engines.escalation_detector import EscalationDetector
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        detector = EscalationDetector(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                findings = detector.detect_privilege_escalation(conn['id'], db_org_id)
                total += len(findings)
        logger.info(f"Escalation detection: {total} finding(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Escalation detection failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_nhi_analysis(db_org_id, db):
    """Phase 9: Analyze non-human identities for security risks."""
    try:
        from app.engines.nhi_analyzer import NHIAnalyzer
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        analyzer = NHIAnalyzer(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                findings = analyzer.analyze_nhi_security(conn['id'], db_org_id)
                total += len(findings)
        logger.info(f"NHI analysis: {total} finding(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"NHI analysis failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_policy_recommendations(db_org_id, db):
    """Phase 11: Generate policy recommendations from risk findings."""
    try:
        from app.engines.policy_recommender import PolicyRecommender
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        recommender = PolicyRecommender(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                recs = recommender.generate_policy_recommendations(conn['id'], db_org_id)
                total += len(recs)
        logger.info(f"Policy recommendations: {total} recommendation(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Policy recommendations failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_auto_remediation(db_org_id, db):
    """Phase 12: Execute approved remediation actions."""
    try:
        from app.engines.remediation_engine import RemediationEngine
        engine = RemediationEngine(db)
        approved_actions = db.get_auto_remediation_actions(status='approved')
        total = 0
        for action in approved_actions:
            engine.execute_remediation(action['id'])
            total += 1
        if total > 0:
            logger.info(f"Auto remediation: executed {total} action(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Auto remediation failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_posture_metrics(db_org_id, db):
    """Phase 14: Collect tenant posture metrics for benchmarking."""
    try:
        from app.engines.benchmark_engine import BenchmarkEngine
        engine = BenchmarkEngine(db)
        result = engine.collect_tenant_posture(db_org_id)
        if result:
            logger.info(f"Posture metrics collected for org {db_org_id}")
    except Exception as e:
        logger.error(f"Posture metrics collection failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_benchmark_computation():
    """Phase 14: Compute cross-tenant security benchmarks (admin context)."""
    try:
        from app.engines.benchmark_engine import BenchmarkEngine
        admin_db = Database()
        engine = BenchmarkEngine(admin_db)
        benchmarks = engine.compute_security_benchmarks()
        admin_db.close()
        logger.info(f"Security benchmarks computed: {len(benchmarks)} metrics")
    except Exception as e:
        logger.error(f"Benchmark computation failed: {e}")
        logger.exception(e)


def _run_risk_forecast(db_org_id, db):
    """Phase 18: Generate risk forecast for tenant."""
    try:
        from app.engines.risk_forecaster import RiskForecaster
        forecaster = RiskForecaster(db)
        forecast = forecaster.generate_risk_forecast(db_org_id)
        logger.info(f"Risk forecast for org {db_org_id}: current={forecast.get('current_risk_score', 0)}, "
                    f"predicted={forecast.get('predicted_risk_score', 0)}, trend={forecast.get('trend_direction', 'stable')}")
    except Exception as e:
        logger.error(f"Risk forecast failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_policy_generation(db_org_id, db):
    """Phase 19: Generate least-privilege policies for tenant."""
    try:
        from app.engines.policy_generator import PolicyGenerator
        from app.database import Database
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        generator = PolicyGenerator(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                policies = generator.generate_policies_for_connection(conn['id'], db_org_id)
                total += len(policies)
        logger.info(f"Policy generation: {total} policy/policies for org {db_org_id}")
    except Exception as e:
        logger.error(f"Policy generation failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_threat_detection(db_org_id, db):
    """Phase 20: Detect identity threats for tenant."""
    try:
        from app.engines.identity_threat_detector import IdentityThreatDetector
        from app.database import Database
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        detector = IdentityThreatDetector(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                events = detector.detect_identity_threats(conn['id'], db_org_id)
                total += len(events)
        logger.info(f"Threat detection: {total} event(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Threat detection failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_activity_ingestion(db_org_id, db):
    """Phase 21: Ingest identity activity into data lake for tenant."""
    try:
        from app.engines.activity_ingestor import ActivityIngestor
        from app.database import Database
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        ingestor = ActivityIngestor(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                counts = ingestor.ingest_identity_activity(conn['id'], db_org_id)
                total += counts.get('total', 0)
        logger.info(f"Activity ingestion: {total} record(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Activity ingestion failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_attack_replay(db_org_id, db):
    """Phase 23: Detect identity attack incidents and generate replay timelines."""
    try:
        from app.engines.attack_replay_engine import AttackReplayEngine
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        engine = AttackReplayEngine(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                incidents = engine.detect_incidents_for_connection(conn['id'], db_org_id)
                total += len(incidents)
        logger.info(f"Attack replay: {total} incident(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Attack replay failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_security_orchestration(db_org_id, db):
    """Phase 24: Evaluate incidents and create automated response actions."""
    try:
        from app.engines.security_orchestrator import SecurityOrchestrator
        orchestrator = SecurityOrchestrator(db)
        actions = orchestrator.execute_security_responses(db_org_id)
        logger.info(f"Security orchestration: {len(actions)} action(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Security orchestration failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_attack_prediction(db_org_id, db):
    """Phase 26: Generate identity attack predictions."""
    try:
        from app.engines.attack_predictor import AttackPredictor
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        predictor = AttackPredictor(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                predictions = predictor.predict_identity_attacks(conn['id'], db_org_id)
                total += len(predictions)
        logger.info(f"Attack prediction: {total} prediction(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Attack prediction failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_graph_intelligence(db_org_id, db):
    """Phase 27: Compute identity graph intelligence metrics for tenant."""
    try:
        from app.engines.graph_intelligence import GraphIntelligenceEngine
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        engine = GraphIntelligenceEngine(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                insights = engine.compute_graph_insights(conn['id'], db_org_id)
                total += len(insights)
        logger.info(f"Graph intelligence: {total} insight(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Graph intelligence failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_identity_governance(db_org_id, db):
    """Phase 28: Evaluate identity governance policies for tenant."""
    try:
        from app.engines.identity_governance_engine import IdentityGovernanceEngine
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        engine = IdentityGovernanceEngine(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                actions = engine.evaluate_identity_governance(conn['id'], db_org_id)
                total += len(actions)
        logger.info(f"Identity governance: {total} action(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Identity governance failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_graph_attack_engine(current_run_id, db_org_id, db):
    """Phase 8 (v2): BFS graph attack path discovery + identity risk scoring."""
    try:
        import time as _time
        from app.engines.graph_attack_engine import GraphAttackEngine
        _t0 = _time.monotonic()
        engine = GraphAttackEngine(db)
        result = engine.analyze(db_org_id, current_run_id)
        analysis_duration_ms = int((_time.monotonic() - _t0) * 1000)
        # Persist results
        db.upsert_identity_risk_scores(result['risk_scores'])
        db.save_graph_attack_findings(result['findings'])

        # Persist full graph snapshot for historical comparison
        try:
            snapshot = engine.graph.to_snapshot()
            snap_result = db.persist_graph_snapshot(
                db_org_id, current_run_id,
                snapshot['nodes'], snapshot['edges'],
                analysis_duration_ms=analysis_duration_ms,
            )
            logger.info(
                "GRAPH_SNAPSHOT_PERSISTED org_id=%d run_id=%d nodes=%d edges=%d duration_ms=%d",
                db_org_id, current_run_id,
                snap_result['nodes'], snap_result['edges'],
                analysis_duration_ms,
            )
        except Exception as snap_err:
            logger.error("Graph snapshot persistence failed: %s", snap_err)

        stats = result['stats']
        logger.info(
            "GRAPH_ATTACK_ENGINE org_id=%d run_id=%d paths=%d findings=%d scored=%d",
            db_org_id, current_run_id,
            stats['paths_discovered'], stats['findings_generated'],
            stats['identities_scored'],
        )
        # Phase 10: Auto-resolve findings whose attack paths no longer exist
        current_fps = {f['fingerprint'] for f in result['findings']}
        resolved = db.auto_resolve_findings(db_org_id, current_run_id, current_fps)
        if resolved > 0:
            logger.info("FINDINGS_AUTO_RESOLVED org_id=%d count=%d", db_org_id, resolved)

        # Phase 11: Backfill SLA deadlines on new findings
        sla_count = db.backfill_finding_slas(db_org_id)
        if sla_count > 0:
            logger.info("SLA_BACKFILL org_id=%d count=%d", db_org_id, sla_count)

        # Phase 11: Dispatch webhooks for new findings
        if stats['findings_generated'] > 0:
            db.dispatch_security_webhooks(db_org_id, 'finding.created', {
                'count': stats['findings_generated'],
                'run_id': current_run_id,
            })
        if stats['paths_discovered'] > 0:
            db.dispatch_security_webhooks(db_org_id, 'attack_path.detected', {
                'count': stats['paths_discovered'],
                'run_id': current_run_id,
            })

        # Phase 11: Slack notification for critical findings
        critical = [f for f in result['findings'] if f.get('severity') == 'critical']
        if critical:
            db.send_slack_notification(
                db_org_id,
                f":rotating_light: {len(critical)} critical finding(s) discovered in latest scan",
            )

        # Phase 11: Auto-create Jira tickets for critical findings
        for finding in critical[:5]:  # Cap at 5 tickets per run
            try:
                db.create_jira_ticket(db_org_id, finding)
            except Exception:
                pass  # Non-blocking
    except Exception as e:
        logger.error(f"Graph attack engine failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_posture_score(current_run_id, db_org_id, db):
    """Phase 9: Compute and persist security posture score for tenant."""
    try:
        result = db.compute_posture_score(db_org_id, current_run_id)
        score = result.get('posture_score', 0)
        logger.info("POSTURE_SCORE org_id=%d run_id=%d score=%d",
                    db_org_id, current_run_id, score)
        if score < 50:
            db.record_security_event(
                db_org_id, 'posture_degraded', 'warning',
                f'Security posture score dropped to {score}/100',
                f'Critical findings: {result.get("critical_findings", 0)}, '
                f'Attack paths: {result.get("attack_paths_count", 0)}',
            )
            # Phase 11: Webhook + Slack for posture degradation
            db.dispatch_security_webhooks(db_org_id, 'posture.score_changed', {
                'score': score, 'run_id': current_run_id,
            })
            db.send_slack_notification(
                db_org_id,
                f":warning: Security posture score dropped to {score}/100",
            )
    except Exception as e:
        logger.error(f"Posture score computation failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_sla_check(db_org_id, db):
    """Phase 11: Check for SLA breaches on open findings."""
    try:
        breached = db.check_sla_breaches(db_org_id)
        if breached:
            logger.info("SLA_BREACHED org_id=%d count=%d", db_org_id, len(breached))
            for f in breached:
                db.record_security_event(
                    db_org_id, 'sla_breached', 'warning',
                    f'SLA breached: {f["title"]} ({f["severity"]})',
                    f'Deadline was {f["sla_deadline"]}',
                    finding_id=f['id'],
                    identity_id=f.get('identity_id'),
                )
            # Notify via Slack
            db.send_slack_notification(
                db_org_id,
                f":clock1: {len(breached)} finding(s) have breached their SLA deadline",
            )
    except Exception as e:
        logger.error(f"SLA check failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_integration_dispatch(db_org_id, db):
    """Phase 30: Dispatch security events to configured integrations."""
    try:
        from app.engines.integration_dispatcher import IntegrationDispatcher
        dispatcher = IntegrationDispatcher(db)
        events = dispatcher.dispatch_integration_events(db_org_id)
        logger.info(f"Integration dispatch: {len(events)} event(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Integration dispatch failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_security_posture(db_org_id, db):
    """Phase 33: Compute identity security posture snapshot."""
    try:
        from app.engines.security_command_center import SecurityCommandCenter
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        center = SecurityCommandCenter(db)
        for conn in connections:
            if conn.get('status') == 'connected':
                posture = center.compute_security_posture(conn['id'], db_org_id)
                logger.info(f"Security posture: risk_score={posture['risk_score']} for connection {conn['id']}")
    except Exception as e:
        logger.error(f"Security posture failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_security_strategy(db_org_id, db):
    """Phase 32: Generate strategic security recommendations."""
    try:
        from app.engines.security_strategy_advisor import SecurityStrategyAdvisor
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        advisor = SecurityStrategyAdvisor(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                recs = advisor.generate_security_strategy(conn['id'], db_org_id)
                total += len(recs)
        logger.info(f"Security strategy: {total} recommendation(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Security strategy failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_governance_analytics(db_org_id, db):
    """Phase 31: Compute governance posture metrics and trends."""
    try:
        from app.engines.governance_analytics import GovernanceAnalyticsEngine
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        engine = GovernanceAnalyticsEngine(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                metrics = engine.compute_governance_metrics(conn['id'], db_org_id)
                total += len(metrics)
        logger.info(f"Governance analytics: {total} metric(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Governance analytics failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_graph_visualization(db_org_id, db):
    """Phase 16: Generate and cache identity graph visualizations for tenant."""
    try:
        from app.engines.graph_visualizer import GraphVisualizer
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id)
        admin_db.close()
        visualizer = GraphVisualizer(db)
        total = 0
        for conn in connections:
            if conn.get('status') == 'connected':
                visualizer.generate_identity_graph(conn['id'], db_org_id)
                total += 1
        logger.info(f"Graph visualization: cached {total} graph(s) for org {db_org_id}")
    except Exception as e:
        logger.error(f"Graph visualization failed for org {db_org_id}: {e}")
        logger.exception(e)


def _run_security_advisor(db_org_id, db):
    """Phase 15: Generate AI Security Advisor report for tenant."""
    try:
        from app.engines.security_advisor import SecurityAdvisor
        advisor = SecurityAdvisor(db)
        report = advisor.generate_security_advisor_report(db_org_id)
        logger.info(f"Security advisor report generated for org {db_org_id}: risk_score={report.get('risk_score', 0)}")
    except Exception as e:
        logger.error(f"Security advisor failed for org {db_org_id}: {e}")
        logger.exception(e)


def run_periodic_access_reviews():
    """
    Phase 6: Periodic access review generation.
    Creates a quarterly access review campaign for each tenant with privileged scope.
    Runs as a standalone scheduled job (not part of discovery pipeline).
    """
    logger.info("=" * 50)
    logger.info("PERIODIC ACCESS REVIEW CHECK")
    logger.info("=" * 50)

    try:
        from psycopg2.extras import RealDictCursor as _RDC

        db_admin = Database()
        db_admin._ensure_tenants_table()
        cursor = db_admin.conn.cursor(cursor_factory=_RDC)
        cursor.execute("SELECT id FROM tenants WHERE active = true")
        tenant_ids = [r['id'] for r in cursor.fetchall()]
        cursor.close()
        db_admin.close()

        for tid in tenant_ids:
            try:
                db = Database(organization_id=tid)

                # Check if there is already an open/in_progress periodic review
                db._ensure_access_reviews_tables()
                cursor = db.conn.cursor(cursor_factory=_RDC)
                cursor.execute("""
                    SELECT id FROM access_reviews
                    WHERE review_type = 'periodic'
                      AND status IN ('open', 'in_progress')
                    LIMIT 1
                """)
                existing = cursor.fetchone()
                cursor.close()

                if existing:
                    logger.info(f"Tenant {tid}: periodic review #{existing['id']} already open, skipping")
                    db.close()
                    continue

                # Create new periodic review
                from datetime import datetime, timedelta
                due = datetime.utcnow() + timedelta(days=30)

                now = datetime.utcnow()
                quarter = (now.month - 1) // 3 + 1
                review = db.create_access_review(
                    title=f"Quarterly Privileged Access Review — {now.year}-Q{quarter}",
                    description='Auto-generated periodic review of privileged identities for compliance.',
                    review_type='periodic',
                    scope='privileged',
                    created_by='system',
                    due_date=due.isoformat(),
                    compliance_frameworks=['SOC2', 'HIPAA', 'ISO27001', 'NIST'],
                )

                from app.engines.access_review_engine import AccessReviewEngine
                engine = AccessReviewEngine(db)
                assignments = engine.generate_assignments(review['id'], 'privileged')

                if assignments:
                    for a in assignments:
                        a['due_date'] = due.isoformat()
                    saved = db.save_review_assignments(assignments)
                    logger.info(f"Tenant {tid}: created periodic review #{review['id']} with {saved} assignments")

                    # Update status
                    cursor = db.conn.cursor()
                    cursor.execute("""
                        UPDATE access_reviews SET status = 'in_progress', updated_at = NOW()
                        WHERE id = %s
                    """, (review['id'],))
                    db._commit()
                    cursor.close()
                else:
                    logger.info(f"Tenant {tid}: no privileged assignments found, review #{review['id']} stays open")

                db.close()

            except Exception as e:
                logger.error(f"Periodic review failed for tenant {tid}: {e}")

    except Exception as e:
        logger.error(f"Periodic access review job failed: {e}")
        logger.exception(e)


def _generate_anomaly_notifications(current_run_id: int, anomalies: list, db: Database):
    """Create in-app notifications for each detected anomaly."""
    try:
        for a in anomalies:
            db.create_notification(
                event_type='anomaly_detected',
                category='anomaly',
                severity=a.get('severity', 'medium'),
                title=a['title'],
                description=a['description'],
                payload=a.get('details'),
                related_identity_id=a.get('identity_id'),
                related_identity_name=a.get('identity_name'),
                related_run_id=current_run_id,
            )
        logger.info(f"Created {len(anomalies)} anomaly notifications for run #{current_run_id}")
    except Exception as e:
        logger.error(f"Error creating anomaly notifications: {e}")


def _evaluate_soar_triggers(trigger_type: str, events: list, db: Database):
    """Evaluate SOAR playbooks for a given trigger type and event list."""
    try:
        from app.engines.soar_engine import SoarEngine
        engine = SoarEngine(db)
        count = engine.evaluate_triggers(trigger_type, events)
        if count > 0:
            logger.info(f"SOAR: executed {count} action(s) for trigger '{trigger_type}'")
    except Exception as e:
        logger.error(f"SOAR evaluation failed for '{trigger_type}': {e}")


def _evaluate_soar_triggers_for_changes(changes: dict, db: Database):
    """Map drift changes to SOAR trigger types and evaluate playbooks."""
    try:
        from app.engines.soar_engine import SoarEngine
        engine = SoarEngine(db)
        total = 0

        # New identities → new_identity trigger
        new_ids = changes.get('new_identities', [])
        if new_ids:
            count = engine.evaluate_triggers('new_identity', new_ids)
            total += count

        # Risk changes (escalations) → risk_escalation trigger
        risk_changes = changes.get('risk_changes', [])
        escalations = [c for c in risk_changes
                       if c.get('direction') == 'increased'
                       or c.get('new_risk') in ('critical', 'high')]
        if escalations:
            events = []
            for c in escalations:
                events.append({
                    'identity_id': c.get('identity_id'),
                    'identity_name': c.get('display_name', ''),
                    'risk_level': c.get('new_risk', ''),
                    'previous_risk_level': c.get('old_risk', ''),
                    'risk_score': c.get('new_score', 0),
                })
            count = engine.evaluate_triggers('risk_escalation', events)
            total += count

        # Overall drift → drift trigger
        new_count = len(new_ids)
        removed_count = len(changes.get('removed_identities', []))
        perm_count = len(changes.get('permission_changes', []))
        risk_count = len(risk_changes)
        cred_count = len(changes.get('credential_changes', []))
        drift_total = new_count + removed_count + perm_count + risk_count + cred_count
        if drift_total > 0:
            drift_event = {
                'total_changes': drift_total,
                'breakdown': {
                    'new_identities': new_count,
                    'removed_identities': removed_count,
                    'permission_changes': perm_count,
                    'risk_changes': risk_count,
                    'credential_changes': cred_count,
                },
            }
            count = engine.evaluate_triggers('drift', [drift_event])
            total += count

        if total > 0:
            logger.info(f"SOAR: executed {total} total action(s) from drift changes")

    except Exception as e:
        logger.error(f"SOAR evaluation for changes failed: {e}")


def _get_category_counts(db: Database, current_run_id: int, previous_run_id: int) -> Dict:
    """
    Get identity counts by category for both runs.

    Args:
        db: Database instance
        current_run_id: Latest discovery run ID
        previous_run_id: Previous discovery run ID

    Returns:
        {
            'before': {'service_principal': 10, 'human_user': 5, ...},
            'after': {'service_principal': 12, 'human_user': 5, ...}
        }
    """
    cursor = db.conn.cursor()

    counts = {'before': {}, 'after': {}}

    for run_id, key in [(previous_run_id, 'before'), (current_run_id, 'after')]:
        cursor.execute("""
            SELECT
                COALESCE(identity_category, 'unknown') as category,
                COUNT(*) as count
            FROM identities
            WHERE discovery_run_id = %s
            GROUP BY identity_category
        """, (run_id,))

        for row in cursor.fetchall():
            category = row[0] or 'unknown'
            counts[key][category] = row[1]

    cursor.close()
    return counts


def run_scheduled_report():
    """
    Send the scheduled executive summary report email.
    Called by the scheduler on the configured cadence.
    Loops per-organization so each organization's settings and data are scoped.
    """
    logger.info("=" * 70)
    logger.info("SCHEDULED REPORT EMAIL STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    try:
        # Get organization list (organizations table has no RLS)
        admin_db = Database()
        cursor = admin_db.conn.cursor()
        cursor.execute("SELECT id, name FROM organizations WHERE enabled = TRUE ORDER BY id")
        orgs = cursor.fetchall()
        cursor.close()
        admin_db.close()

        for db_org_id, org_name in orgs:
            try:
                db = Database(organization_id=db_org_id)
                enabled = db.get_system_setting('report_schedule_enabled', 'false')

                if enabled != 'true':
                    logger.info(f"Scheduled reports disabled for {org_name} - skipping")
                    db.close()
                    continue

                # Phase 23: Check plan entitlement for scheduled_reports
                from app.api.handlers import TIER_LIMITS
                ent_cursor = db.conn.cursor()
                ent_cursor.execute("SELECT plan FROM organizations WHERE id = %s", (db_org_id,))
                ent_row = ent_cursor.fetchone()
                ent_cursor.close()
                if ent_row:
                    t_plan = ent_row[0] or 'free'
                    t_limits = TIER_LIMITS.get(t_plan, TIER_LIMITS['free'])
                    if 'scheduled_reports' in t_limits.get('blocked_features', []):
                        logger.info(f"Scheduled reports not available on {t_plan} plan for {org_name} - skipping")
                        db.close()
                        continue

                email_service = EmailService()
                if not email_service.credentials_configured:
                    logger.warning(f"Azure credentials not configured for {org_name} - skipping")
                    db.close()
                    continue

                success = email_service.send_scheduled_report(organization_id=db_org_id)

                if success:
                    db.log_activity('report_emailed', f'Scheduled executive summary report sent for {org_name}')
                    logger.info(f"✅ Scheduled report email sent for {org_name}")
                else:
                    db.log_activity('report_email_failed', f'Scheduled report email failed for {org_name}')
                    logger.warning(f"Failed to send scheduled report email for {org_name}")
                db.close()
            except Exception as e:
                logger.error(f"Scheduled report failed for {org_name}: {e}")

    except Exception as e:
        logger.error(f"Scheduled report failed: {e}")
        logger.exception(e)


def run_data_retention():
    """
    Run data retention cleanup based on configured policies.
    Called daily by the scheduler at 03:00 UTC.
    Loops per-organization so each organization's retention settings are respected.
    """
    logger.info("=" * 70)
    logger.info("DATA RETENTION CLEANUP STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    try:
        # Get organization list (organizations table has no RLS)
        admin_db = Database()
        cursor = admin_db.conn.cursor()
        cursor.execute("SELECT id, name FROM organizations WHERE enabled = TRUE ORDER BY id")
        orgs = cursor.fetchall()
        cursor.close()
        admin_db.close()

        for db_org_id, org_name in orgs:
            try:
                db = Database(organization_id=db_org_id)
                enabled = db.get_system_setting('retention_enabled', 'false')

                if enabled != 'true':
                    logger.info(f"Data retention disabled for {org_name} - skipping")
                    db.close()
                    continue

                discovery_days = int(db.get_system_setting('retention_discovery_days', '90'))
                drift_days = int(db.get_system_setting('retention_drift_days', '90'))
                activity_days = int(db.get_system_setting('retention_activity_days', '180'))
                anomalies_days = int(db.get_system_setting('retention_anomalies_days', '90'))
                soar_days = int(db.get_system_setting('retention_soar_days', '90'))
                notif_days = int(db.get_system_setting('retention_notifications_days', '90'))

                results = {}
                run_counts = db.cleanup_old_discovery_runs(days=discovery_days)
                results['discovery_runs'] = run_counts.get('discovery_runs', 0)
                results['risk_scores'] = run_counts.get('risk_scores', 0)
                results['drift_reports'] = db.cleanup_old_drift_reports(days=drift_days)
                results['activity_log'] = db.cleanup_old_activity_log(days=activity_days)
                results['anomalies'] = db.cleanup_old_anomalies(days=anomalies_days)
                results['soar_actions'] = db.cleanup_old_soar_actions(days=soar_days)
                results['notifications'] = db.cleanup_old_notifications(days=notif_days)

                # P2 telemetry retention
                signin_days = int(db.get_system_setting('retention_signin_events_days', '90'))
                wl_anomaly_days = int(db.get_system_setting('retention_workload_anomalies_days', '180'))
                try:
                    results['signin_events'] = db.cleanup_signin_events(days=signin_days)
                    results['workload_anomalies'] = db.cleanup_workload_anomalies(days=wl_anomaly_days)
                except Exception:
                    pass  # Tables may not exist yet

                # Graph snapshot retention
                graph_days = int(db.get_system_setting('retention_graph_days', '90'))
                try:
                    results['graph_snapshots'] = db.cleanup_old_graph_snapshots(days=graph_days)
                except Exception:
                    pass  # Table may not exist yet

                total = sum(results.values())
                if total > 0:
                    db.log_activity('data_retention', f'Scheduled cleanup for {org_name}: {total} records deleted',
                                    json.dumps(results))
                    logger.info(f"✅ Data retention for {org_name}: {total} records deleted")
                    for table, count in results.items():
                        if count > 0:
                            logger.info(f"   {table}: {count} deleted")
                else:
                    logger.info(f"Data retention for {org_name}: no records to clean up")

                db.close()
            except Exception as e:
                logger.error(f"Data retention failed for {org_name}: {e}")
            # CONTEXT SAFETY: each iteration creates/closes its own Database(org).
            # No lingering context to reset, but comment documents the guarantee.

    except Exception as e:
        logger.error(f"Data retention failed: {e}")
        logger.exception(e)


def run_rls_audit_job():
    """Nightly RLS isolation audit — validates drift and logs findings.

    Called by the scheduler at 04:30 UTC daily.
    Runs validate_rls_drift() and enforce_force_rls(), then records
    any findings in the admin_audit_log table.
    """
    logger.info("=" * 70)
    logger.info("RLS ISOLATION AUDIT STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    try:
        # Step 1: Enforce FORCE RLS on all tenant tables (idempotent)
        Database.enforce_force_rls()

        # Step 2: Run comprehensive drift detection
        drift_result = Database.validate_rls_drift()

        if drift_result.get('skipped'):
            logger.info("RLS audit skipped: %s", drift_result.get('reason', 'unknown'))
            return

        # Step 3: Log findings to admin_audit_log
        if not drift_result['ok'] or drift_result['summary']['issues_found'] > 0:
            db = Database(_admin_reason='rls_audit_job')
            try:
                cursor = db.conn.cursor()
                # Ensure admin_audit_log table exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS admin_audit_log (
                        id SERIAL PRIMARY KEY,
                        action TEXT NOT NULL,
                        actor TEXT NOT NULL DEFAULT 'system',
                        details JSONB,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
                cursor.execute(
                    """INSERT INTO admin_audit_log (action, actor, details)
                       VALUES (%s, %s, %s)""",
                    (
                        'rls_drift_detected',
                        'scheduler:rls_audit',
                        json.dumps(drift_result, default=str),
                    ),
                )
                db._commit()
                cursor.close()

                logger.error(
                    "RLS AUDIT FAILED — %d findings (%d critical). Details logged to admin_audit_log.",
                    drift_result['summary']['issues_found'],
                    drift_result['summary']['critical'],
                )
            finally:
                db.close()
        else:
            logger.info(
                "RLS AUDIT PASSED — %d tables checked, 0 issues",
                drift_result['summary']['tables_checked'],
            )

    except Exception as e:
        logger.error("RLS audit job failed: %s", e)
        logger.exception(e)


def mark_overdue_invoices():
    """Mark sent invoices past due_at as overdue. Runs daily at 02:00 UTC."""
    from psycopg2.extras import RealDictCursor
    logger.info("Checking for overdue invoices...")
    db = Database()
    try:
        cursor = db.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            UPDATE invoices SET status = 'overdue', updated_at = NOW()
            WHERE status = 'sent' AND due_at < NOW()
            RETURNING id, organization_id, invoice_number
        """)
        rows = cursor.fetchall()
        db._commit()
        cursor.close()
        if rows:
            logger.info(f"Marked {len(rows)} invoices as overdue")
            for r in rows:
                logger.info(f"  Invoice {r['invoice_number']} (organization {r['organization_id']})")
        else:
            logger.info("No overdue invoices found")
    except Exception as e:
        logger.error(f"Failed to mark overdue invoices: {e}")
    finally:
        db.close()


def expire_ai_governance_exceptions_job():
    """Transition any approved AI governance exception whose expires_at has
    passed into 'expired' status.

    Per-org loop so we can write an activity_log row per tenant (auditors care
    when a risk-accepted exception lapses — the policy is back in violation as
    of NOW). Runs daily at 02:30 UTC.
    """
    from psycopg2.extras import RealDictCursor
    logger.info("Checking for AI governance exceptions past expiry...")
    admin_db = Database()
    try:
        cursor = admin_db.conn.cursor(cursor_factory=RealDictCursor)
        # Snapshot rows that will be expired so we can log per-org transitions
        # BEFORE the bulk UPDATE flips them. Using the admin connection because
        # we cross organizations.
        cursor.execute("""
            SELECT id, organization_id, identity_id, policy_id
              FROM ai_governance_exceptions
             WHERE status = 'approved'
               AND expires_at <= NOW()
        """)
        about_to_expire = cursor.fetchall()
        cursor.close()

        if not about_to_expire:
            logger.info("No AI governance exceptions to expire")
            return

        # Bulk update via the admin connection. Returns the number of rows
        # transitioned for the scheduler log line.
        total = admin_db.expire_overdue_ai_governance_exceptions(org_id=None)
        logger.info(f"Expired {total} AI governance exception(s)")

        # Log per-org so each tenant's activity log captures the transitions.
        # Group rows by org_id and emit a single activity_log row per org.
        by_org: Dict = {}
        for r in about_to_expire:
            by_org.setdefault(r['organization_id'], []).append(r)
        for org_id, rows in by_org.items():
            try:
                tdb = Database(organization_id=org_id)
                try:
                    tdb.log_activity(
                        'ai_governance_exception_expired',
                        f"{len(rows)} exception(s) expired",
                        {
                            'count': len(rows),
                            'exceptions': [
                                {'exception_id': r['id'],
                                 'identity_id': r['identity_id'],
                                 'policy_id': r['policy_id']}
                                for r in rows
                            ],
                        },
                        user_id=None,
                        organization_id=org_id,
                    )
                finally:
                    tdb.close()
            except Exception as e:
                logger.warning(f"Failed to log expiry transitions for org {org_id}: {e}")
    except Exception as e:
        logger.error(f"AI governance exception expiry sweep failed: {e}")
    finally:
        admin_db.close()


def run_monthly_billing_snapshots():
    """Phase 3B: Generate billing snapshots for all active organizations.
    Runs on the 1st of each month at 04:00 UTC, snapshotting the previous month."""
    from app.database import Database
    from app.billing.service import calculate_monthly_snapshot, store_billing_snapshot

    logger.info("=" * 70)
    logger.info("MONTHLY BILLING SNAPSHOT STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    try:
        admin_db = Database()
        cursor = admin_db.conn.cursor()
        cursor.execute("SELECT id, name FROM organizations WHERE enabled = TRUE ORDER BY id")
        orgs = cursor.fetchall()
        cursor.close()
        admin_db.close()

        success_count = 0
        for org_id, org_name in orgs:
            try:
                db = Database()
                snapshot = calculate_monthly_snapshot(db, org_id)
                if snapshot:
                    store_billing_snapshot(db, snapshot)
                    success_count += 1
                    logger.info(f"  Snapshot generated for org {org_id} ({org_name}): ${snapshot['total_cents'] / 100:,.2f}")
                db.close()
            except Exception as e:
                logger.error(f"  Failed to snapshot org {org_id} ({org_name}): {e}")

        logger.info(f"Billing snapshot complete: {success_count}/{len(orgs)} organizations")
    except Exception as e:
        logger.error(f"Monthly billing snapshot failed: {e}")


def check_scan_schedules():
    """Phase 6: Check for due scan schedules and trigger discovery runs."""
    from app.database import Database
    db = Database()  # admin connection to see all organizations
    try:
        due_schedules = db.get_due_scan_schedules()
        if not due_schedules:
            return

        logger.info(f"Found {len(due_schedules)} due scan schedules")

        for sched in due_schedules:
            org_id = sched['organization_id']
            schedule_id = sched['id']
            org_name = sched.get('organization_name', f'Organization {org_id}')

            logger.info(f"Triggering scheduled scan for {org_name} (schedule {schedule_id})")

            try:
                # Trigger discovery for this organization
                org_db = Database(organization_id=org_id)
                try:
                    # Import and run discovery (same as manual trigger)
                    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
                    connections = org_db.get_cloud_connections(org_id)

                    ran = False
                    for conn_row in connections:
                        if conn_row.get('cloud') == 'azure' and conn_row.get('enabled'):
                            try:
                                metadata = conn_row.get('metadata') or {}
                                _cs = metadata.get('client_secret')
                                engine = AzureDiscoveryEngine(
                                    azure_directory_id=conn_row.get('azure_directory_id'),
                                    client_id=conn_row.get('client_id'),
                                    client_secret=_cs,
                                    db_org_id=org_id,
                                    cloud_connection_id=conn_row['id'],
                                )
                                _cs = None  # AG-116: zero after SDK init
                                engine.run_discovery()
                                ran = True
                            except Exception as de:
                                logger.error(f"Discovery error for organization {org_id}: {de}")
                    if not ran:
                        logger.warning(f"No enabled Azure connections for organization {org_id}")

                finally:
                    org_db.close()

                # Calculate next run
                from datetime import datetime, timedelta, timezone
                now = datetime.now(timezone.utc)
                freq = sched.get('frequency', 'daily')
                if freq == 'hourly':
                    next_run = now + timedelta(hours=1)
                elif freq == 'weekly':
                    next_run = now + timedelta(days=7)
                elif freq == 'monthly':
                    next_run = now + timedelta(days=30)
                else:
                    next_run = now + timedelta(days=1)

                db.mark_scan_schedule_run(schedule_id, 'completed', next_run)
                logger.info(f"Scheduled scan completed for {org_name}, next: {next_run}")

            except Exception as e:
                logger.error(f"Scheduled scan failed for {org_name}: {e}")
                from datetime import datetime, timedelta, timezone
                now = datetime.now(timezone.utc)
                next_run = now + timedelta(hours=1)  # Retry in 1 hour on failure
                try:
                    db.mark_scan_schedule_run(schedule_id, 'failed', next_run)
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"Scan schedule checker error: {e}")
    finally:
        db.close()


# Global scheduler instance
scheduler = None
_scheduler_lock = threading.Lock()


def start_scheduler():
    """
    Start the background scheduler.
    Called when the Flask app starts.
    """
    global scheduler

    with _scheduler_lock:
        if scheduler is not None:
            logger.warning("Scheduler already running")
            return

        logger.info("=" * 70)
        logger.info("INITIALIZING DISCOVERY SCHEDULER")
        logger.info("[SCHEDULER] Post-processing gate: FIRST-SCAN-AWARE = True")
        logger.info("[SCHEDULER] File: %s", __file__)
        logger.info("=" * 70)

        # Create scheduler (inside lock to prevent double-init race)
        scheduler = BackgroundScheduler(timezone="UTC")

    # Get configurable interval (default: 12 hours)
    interval_hours = int(os.getenv('DISCOVERY_INTERVAL_HOURS', '12'))
    if interval_hours not in [6, 12, 24]:
        logger.warning(f"Invalid DISCOVERY_INTERVAL_HOURS={interval_hours}, using 12")
        interval_hours = 12

    # Schedule based on interval
    trigger = CronTrigger(hour=f"*/{interval_hours}", minute=0, timezone="UTC")

    scheduler.add_job(
        func=run_scheduled_discovery,
        trigger=trigger,
        id='scheduled_discovery',
        name=f'Identity Discovery (Every {interval_hours} Hours)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )
    
    # Phase 18: Add scheduled report job
    # Use defaults — actual per-org behavior is in run_scheduled_report()
    report_freq = 'weekly'
    report_enabled = True  # Always schedule; per-org check at execution time

    if report_freq == 'monthly':
        report_trigger = CronTrigger(day=1, hour=8, minute=0, timezone="UTC")
        report_name = 'Executive Report (Monthly, 1st @ 08:00 UTC)'
    else:
        report_trigger = CronTrigger(day_of_week='mon', hour=8, minute=0, timezone="UTC")
        report_name = 'Executive Report (Weekly, Mon @ 08:00 UTC)'

    scheduler.add_job(
        func=run_scheduled_report,
        trigger=report_trigger,
        id='scheduled_report',
        name=report_name,
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 72: Data retention cleanup — daily at 3:00 AM UTC
    scheduler.add_job(
        func=run_data_retention,
        trigger=CronTrigger(hour=3, minute=0, timezone="UTC"),
        id='data_retention',
        name='Data Retention Cleanup (Daily, 03:00 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Invoice auto-overdue — daily at 2:00 AM UTC
    scheduler.add_job(
        func=mark_overdue_invoices,
        trigger=CronTrigger(hour=2, minute=0, timezone="UTC"),
        id='mark_overdue_invoices',
        name='Invoice Auto-Overdue (Daily, 02:00 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # AI governance exception expiry sweep — daily at 02:30 UTC.
    # Picks up between the invoice sweep and the RLS audit so the daily
    # 02:00-04:30 maintenance band stays cohesive.
    scheduler.add_job(
        func=expire_ai_governance_exceptions_job,
        trigger=CronTrigger(hour=2, minute=30, timezone="UTC"),
        id='expire_ai_governance_exceptions',
        name='AI Governance Exception Expiry (Daily, 02:30 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Enterprise isolation: Nightly RLS audit — daily at 4:30 AM UTC
    scheduler.add_job(
        func=run_rls_audit_job,
        trigger=CronTrigger(hour=4, minute=30, timezone="UTC"),
        id='rls_audit',
        name='RLS Isolation Audit (Daily, 04:30 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 3B: Monthly billing snapshots — 1st of each month at 04:00 UTC
    scheduler.add_job(
        func=run_monthly_billing_snapshots,
        trigger=CronTrigger(day=1, hour=4, minute=0, timezone="UTC"),
        id='monthly_billing_snapshots',
        name='Monthly Billing Snapshots (1st, 04:00 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 6: Scan schedule checker — every 60 seconds
    scheduler.add_job(
        func=check_scan_schedules,
        trigger=IntervalTrigger(seconds=60),
        id='check_scan_schedules',
        name='Scan Schedule Checker (every 60s)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 6: Periodic access reviews — quarterly (1st of Jan/Apr/Jul/Oct at 06:00 UTC)
    scheduler.add_job(
        func=run_periodic_access_reviews,
        trigger=CronTrigger(month='1,4,7,10', day=1, hour=6, minute=0, timezone="UTC"),
        id='periodic_access_reviews',
        name='Periodic Access Reviews (Quarterly, 1st @ 06:00 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 4: Snapshot job maintenance — every 5 minutes
    scheduler.add_job(
        func=run_snapshot_job_maintenance,
        trigger=IntervalTrigger(minutes=5),
        id='snapshot_job_maintenance',
        name='Snapshot Job Maintenance (every 5 min)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 5: Continuous discovery — every 5 minutes
    scheduler.add_job(
        func=run_continuous_discovery,
        trigger=IntervalTrigger(minutes=5),
        id='continuous_discovery',
        name='Continuous Discovery (every 5 min)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # W3: Stale execution recovery — every 5 minutes
    scheduler.add_job(
        func=run_stale_execution_recovery,
        trigger=IntervalTrigger(minutes=5),
        id='stale_execution_recovery',
        name='Stale Execution Recovery (every 5 min)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Phase 13: Trial expiration check — daily at 05:00 UTC
    scheduler.add_job(
        func=run_trial_expiration,
        trigger=CronTrigger(hour=5, minute=0),
        id='trial_expiration',
        name='Trial Expiration Check (Daily, 05:00 UTC)',
        replace_existing=True,
        max_instances=1,
        coalesce=True
    )

    # Start the scheduler
    scheduler.start()

    logger.info("✅ Scheduler started")
    logger.info(f"📅 Discovery: Every {interval_hours} hours")
    logger.info(f"📊 Report: {report_name} (enabled={report_enabled})")
    logger.info("🗑️ Retention: Daily at 03:00 UTC")
    logger.info("📋 Invoice overdue: Daily at 02:00 UTC")
    logger.info("🔒 RLS audit: Daily at 04:30 UTC")
    logger.info("🔄 Scan schedules: Every 60 seconds")
    logger.info("🔧 Snapshot maintenance: Every 5 minutes")

    # Get next run times
    job = scheduler.get_job('scheduled_discovery')
    if job:
        logger.info(f"🕐 Next discovery: {job.next_run_time}")
    report_job = scheduler.get_job('scheduled_report')
    if report_job:
        logger.info(f"📧 Next report: {report_job.next_run_time}")

    logger.info("=" * 70)


def stop_scheduler():
    """
    Stop the scheduler.
    Called when the Flask app shuts down.
    """
    global scheduler

    with _scheduler_lock:
        if scheduler is not None:
            logger.info("Stopping scheduler...")
            scheduler.shutdown()
            scheduler = None
            logger.info("✓ Scheduler stopped")


def get_next_run_time():
    """
    Get the next scheduled run time.
    Returns datetime or None.
    """
    global scheduler
    
    if scheduler is None:
        return None
    
    job = scheduler.get_job('scheduled_discovery')
    if job:
        return job.next_run_time

    return None


def get_next_report_time():
    """
    Get the next scheduled report delivery time.
    Returns datetime or None.
    """
    global scheduler

    if scheduler is None:
        return None

    job = scheduler.get_job('scheduled_report')
    if job:
        return job.next_run_time

    return None


# ── Phase 8: Platform Operations & Health Monitoring ─────────────────

def _track_job(job_type: str, org_id: int, func, *args, **kwargs):
    """Wrap an engine call with job_runs tracking.

    Creates a job_run record before calling *func*, then marks it
    completed or failed once it returns.  Non-blocking: if the
    tracking DB call itself fails we log and continue.
    """
    import time as _time
    job_run = None
    db_track = None
    try:
        db_track = Database()
        job_run = db_track.create_job_run(job_type, organization_id=org_id)
        db_track.close()
        db_track = None
        logger.info("JOB_START job_id=%s job_type=%s tenant_id=%d",
                    job_run['job_id'], job_type, org_id)
    except Exception as e:
        logger.warning("JOB_TRACK_FAILED action=create job_type=%s tenant_id=%d error=%s",
                       job_type, org_id, str(e)[:200])
        if db_track:
            db_track.close()

    # Execute the actual engine function
    job_start = _time.monotonic()
    result = None
    error = None
    try:
        result = func(*args, **kwargs)
    except Exception as e:
        error = str(e)[:500]
        raise  # Re-raise so outer handler sees it
    finally:
        duration_s = round(_time.monotonic() - job_start, 1)
        if job_run:
            try:
                db_track = Database()
                status = 'failed' if error else 'completed'
                db_track.complete_job_run(
                    str(job_run['job_id']), status=status, error_message=error,
                )
                # Structured log (Phase 7)
                if error:
                    logger.error(
                        "JOB_FAILED job_id=%s job_type=%s tenant_id=%d duration=%.1fs error=%s",
                        job_run['job_id'], job_type, org_id, duration_s, error[:200]
                    )
                else:
                    logger.info(
                        "JOB_COMPLETE job_id=%s job_type=%s tenant_id=%d duration=%.1fs",
                        job_run['job_id'], job_type, org_id, duration_s
                    )
                # Activity log
                event = 'job_failed' if error else 'job_completed'
                db_track.log_activity(event,
                    f'{job_type} job {status}' + (f': {error[:120]}' if error else ''),
                    {'job_id': str(job_run['job_id']), 'job_type': job_type,
                     'duration_seconds': duration_s})
                db_track.close()
            except Exception as te:
                logger.warning("JOB_TRACK_FAILED action=complete job_type=%s error=%s",
                               job_type, str(te)[:200])
                if db_track:
                    db_track.close()

    return result


def _run_platform_health_check(current_run_id: int, org_id: int, db: Database):
    """Post-pipeline: evaluate tenant health + discovery integrity.

    Called at the end of each per-org pipeline run, after all engines.
    Lightweight SELECT-only queries; does not block the pipeline.
    """
    try:
        from app.engines.platform_health import PlatformHealthEngine

        engine = PlatformHealthEngine(db)

        # Part 6: Discovery integrity check
        integrity = engine.check_discovery_integrity(org_id, current_run_id)
        db.save_integrity_metrics(integrity)

        if integrity.get('integrity_warning'):
            logger.warning(
                f"Phase 8 INTEGRITY WARNING (org={org_id}, run={current_run_id}): "
                + "; ".join(integrity.get('warnings', []))
            )
            # Part 11: audit log
            try:
                db.log_activity('integrity_warning_detected',
                    f'Discovery integrity warning for run #{current_run_id}',
                    {'warnings': integrity['warnings'], 'run_id': current_run_id})
            except Exception:
                pass

        # Part 5: Tenant health evaluation
        health = engine.evaluate_tenant_health(org_id)
        if integrity.get('integrity_warning'):
            health['integrity_warning'] = True
            if health['status'] == 'healthy':
                health['status'] = 'warning'

        db.upsert_tenant_health(health)
        logger.info(
            "TENANT_HEALTH_UPDATED tenant_id=%d status=%s snapshot_age=%dh "
            "findings=%d critical=%d",
            org_id, health['status'], health['snapshot_age_hours'],
            health.get('findings_count', 0), health.get('critical_risks', 0)
        )

        # Phase 7: Create alert if health is critical
        if health['status'] == 'critical':
            try:
                alert_db = Database()
                alert_db.create_snapshot_alert(
                    organization_id=org_id,
                    severity='critical',
                    message=f"Tenant health is CRITICAL: snapshot age {health['snapshot_age_hours']}h",
                    alert_type='health_critical',
                    metadata={'snapshot_age_hours': health['snapshot_age_hours'],
                              'findings_count': health.get('findings_count', 0)},
                )
                alert_db.close()
            except Exception:
                pass

        # Part 11: audit log
        try:
            db.log_activity('tenant_health_updated',
                f'Tenant health evaluated: {health["status"]}',
                {'organization_id': org_id, 'status': health['status'],
                 'findings_count': health['findings_count'],
                 'critical_risks': health['critical_risks']})
        except Exception:
            pass

        # Record system-level metrics
        try:
            admin_db = Database()
            failure_rate = admin_db.get_job_failure_rate(hours=24)
            admin_db.record_system_metric('job_failure_rate', failure_rate)
            admin_db.close()
        except Exception:
            pass

    except Exception as e:
        logger.error(f"Phase 8: platform health check failed for org={org_id}: {e}")
        logger.exception(e)


def trigger_manual_discovery(scan_mode: str = 'deep', db_org_id: int = None,
                             org_name: str = None, connection_id: int = None):
    """
    Trigger discovery immediately (manual override).
    If db_org_id is provided, runs for that single organization only.
    If connection_id is also provided, only scans that specific connection.
    Otherwise runs for all organizations (scheduled behavior).
    """
    if db_org_id is not None:
        suffix = f" connection={connection_id}" if connection_id else ""
        logger.info(f"🔄 MANUAL DISCOVERY TRIGGERED for organization {org_name or db_org_id} (mode={scan_mode}){suffix}")
        _run_org_discovery(db_org_id, org_name or str(db_org_id), scan_mode,
                           connection_id=connection_id)
    else:
        logger.info(f"🔄 MANUAL DISCOVERY TRIGGERED for all organizations (mode={scan_mode})")
        run_scheduled_discovery(scan_mode=scan_mode)


def run_trial_expiration():
    """Phase 13: Check for expired trials and downgrade to free plan."""
    from app.database import Database
    db = Database(_admin_reason='trial_expiration: check expired trials')
    try:
        expired = db.expire_trials()
        if expired:
            for org in expired:
                logger.info(f"Trial expired: {org['name']} (ID={org['id']}) → downgraded to free")
                try:
                    db.record_security_event(
                        org_id=org['id'],
                        event_type='trial_expired',
                        severity='info',
                        title=f'Trial expired for {org["name"]}',
                        description='Organization downgraded from trial to free plan. '
                                    'New discovery scans are disabled on the free plan.',
                    )
                except Exception:
                    pass
            logger.info(f"Trial expiration: {len(expired)} orgs downgraded to free")
        else:
            logger.debug("Trial expiration: no expired trials found")
    except Exception as e:
        logger.error(f"Trial expiration error: {e}")
    finally:
        db.close()


# For testing the scheduler in isolation
def _run_agent_classification(current_run_id, db_org_id, db):
    """AI Agent Governance: classify agent identities after discovery.

    Gated by FEATURE_AI_AGENT_GOVERNANCE flag — no-op when disabled.
    """
    from app.config import FEATURE_AI_AGENT_GOVERNANCE
    if not FEATURE_AI_AGENT_GOVERNANCE:
        logger.info("[CLASSIFY] FEATURE_AI_AGENT_GOVERNANCE=False — skipping org=%s run=%s",
                     db_org_id, current_run_id)
        return

    logger.info("[CLASSIFY] Starting agent classification org=%s run=%s", db_org_id, current_run_id)
    try:
        from app.services.agent_classifier import classify_tenant
        stats = classify_tenant(db, db_org_id, run_id=current_run_id)
        logger.info(
            "[CLASSIFY] Result org=%s run=%s: %d evaluated, %d ai_agent, %d possible, %d unknown (patterns v%s)",
            db_org_id, current_run_id,
            stats.get('total_evaluated', 0), stats.get('ai_agent', 0),
            stats.get('possible_ai_agent', 0), stats.get('unknown', 0),
            stats.get('pattern_version', '?'),
        )
    except Exception as e:
        logger.error("[CLASSIFY] FAILED org=%s run=%s: %s", db_org_id, current_run_id, e)
        logger.exception(e)


def _run_agent_sp_signin_enrichment(current_run_id, db_org_id, db):
    """AI Agent Governance Phase 2 B2-5: enrich agent SPNs with SP sign-in data.

    For each ai_agent identity, fetches the most recent servicePrincipalSignIn
    from Microsoft Graph and stores it on agent_classifications. This runs
    BEFORE orphan detection so the detector has accurate activity data.

    Gated by FEATURE_AI_AGENT_GOVERNANCE flag. Non-blocking on failure.
    """
    import os
    import time as _time
    from app.config import FEATURE_AI_AGENT_GOVERNANCE
    if not FEATURE_AI_AGENT_GOVERNANCE:
        return

    batch_size = int(os.environ.get('AGENT_ENRICH_BATCH_SIZE', '50'))

    try:
        # Get Azure credential from org's cloud connection
        admin_db = Database()
        connections = admin_db.get_cloud_connections(db_org_id, include_secrets=True)
        admin_db.close()

        azure_conn = None
        for conn in connections:
            if conn.get('cloud', 'azure') == 'azure' and conn.get('status') == 'connected':
                azure_conn = conn
                break

        if not azure_conn:
            logger.info("SP sign-in enrichment: no Azure connection for org %s, skipping", db_org_id)
            return

        metadata = azure_conn.get('metadata') or {}
        from app.encryption import decrypt_field
        for _cred_key in ('client_secret',):
            if _cred_key in metadata:
                metadata[_cred_key] = decrypt_field(metadata[_cred_key])

        azure_directory_id = azure_conn.get('azure_directory_id')
        client_id = azure_conn.get('client_id')
        client_secret = metadata.get('client_secret')

        if not all([azure_directory_id, client_id, client_secret]):
            logger.info("SP sign-in enrichment: incomplete Azure credentials for org %s, skipping", db_org_id)
            return

        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client_secret = None  # AG-116: zero after SDK init — prevent memory retention

        from app.engines.discovery.activity_tracker import ActivityTracker
        tracker = ActivityTracker(credential)

        # Find ai_agent SPNs, prioritize those with oldest (or NULL) enrichment
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT ac.id, ac.identity_id, i.object_id, i.display_name,
                   ac.last_service_principal_sign_in
            FROM agent_classifications ac
            JOIN identities i ON i.id = ac.identity_db_id
            WHERE ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
              AND i.discovery_run_id = %s
              AND NOT COALESCE(i.is_microsoft_system, false)
              AND i.deleted_at IS NULL
            ORDER BY ac.last_service_principal_sign_in ASC NULLS FIRST
            LIMIT %s
        """, (current_run_id, batch_size))
        agents = cursor.fetchall()
        cursor.close()

        enriched = 0
        skipped = 0
        for ac_id, identity_id, object_id, display_name, existing_sp_sign_in in agents:
            if not object_id:
                skipped += 1
                continue

            try:
                sp_last_sign_in = tracker.get_service_principal_last_sign_in(object_id)
                if sp_last_sign_in is not None:
                    update_cursor = db.conn.cursor()
                    update_cursor.execute("""
                        UPDATE agent_classifications
                        SET last_service_principal_sign_in = %s,
                            updated_at = NOW()
                        WHERE id = %s
                    """, (sp_last_sign_in, ac_id))
                    db.conn.commit()
                    update_cursor.close()
                    enriched += 1
                    logger.debug(
                        "Enriched %s: last SP sign-in = %s",
                        display_name, sp_last_sign_in.isoformat(),
                    )
                else:
                    skipped += 1
            except Exception as e:
                logger.warning(
                    "SP sign-in enrichment failed for %s (%s): %s",
                    display_name, identity_id, e,
                )
                skipped += 1

            # Rate limit: 100ms between Graph API calls
            _time.sleep(0.1)

        logger.info(
            "SP sign-in enrichment for org %s: %d enriched, %d skipped (of %d total)",
            db_org_id, enriched, skipped, len(agents),
        )

    except Exception as e:
        logger.warning("SP sign-in enrichment failed (non-blocking): %s", e)


def _run_nhi_signin_enrichment(current_run_id, db_org_id, db):
    """Enrich ALL NHI identities with sign-in data from auditLogs/signIns.

    The Graph API signInActivity property on servicePrincipals requires Entra ID P2
    licensing, which many tenants don't have. This job uses the auditLogs/signIns
    endpoint (requires AuditLog.Read.All) as a fallback to fill signin_pattern for
    identities that still show 'never_used' from the inline discovery enrichment.

    Processes in batches, prioritizing identities with no sign-in data (NULL or
    'never_used' signin_pattern). Non-blocking on failure.
    """
    import time as _time

    batch_size = 200

    try:
        # Get Azure credentials for this org
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT cc.azure_directory_id, cc.client_id, cc.metadata
            FROM cloud_connections cc
            WHERE cc.organization_id = %s AND cc.provider = 'azure'
              AND cc.status = 'connected'
            LIMIT 1
        """, (db_org_id,))
        azure_conn_row = cursor.fetchone()
        cursor.close()

        if not azure_conn_row:
            return

        azure_directory_id, client_id, metadata = azure_conn_row
        if isinstance(metadata, str):
            import json as _json
            metadata = _json.loads(metadata)
        metadata = metadata or {}
        from app.encryption import decrypt_field
        if 'client_secret' in metadata:
            metadata['client_secret'] = decrypt_field(metadata['client_secret'])
        client_secret = metadata.get('client_secret')

        if not all([azure_directory_id, client_id, client_secret]):
            return

        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client_secret = None  # AG-116: zero after SDK init — prevent memory retention

        from app.engines.discovery.activity_tracker import ActivityTracker
        tracker = ActivityTracker(credential)

        # First call: check if we even have AuditLog.Read.All
        # Use the discovery connector itself as a test probe
        _test = tracker.get_last_sign_in(client_id)
        if tracker.has_auditlog_access is False:
            logger.info(
                "NHI signin enrichment: AuditLog.Read.All not granted for org %s, skipping",
                db_org_id,
            )
            return

        # Find NHIs with no real sign-in data, from current run
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT i.id, i.identity_id, i.object_id, i.app_id, i.display_name,
                   i.created_datetime
            FROM identities i
            WHERE i.discovery_run_id = %s
              AND i.identity_category IN (
                  'service_principal', 'managed_identity_system', 'managed_identity_user'
              )
              AND NOT COALESCE(i.is_microsoft_system, false)
              AND i.deleted_at IS NULL
              AND (i.signin_pattern IS NULL OR i.signin_pattern = 'never_used')
              AND i.last_sign_in IS NULL
            ORDER BY i.id
            LIMIT %s
        """, (current_run_id, batch_size))
        identities = cursor.fetchall()
        cursor.close()

        if not identities:
            logger.info("NHI signin enrichment: no unenriched identities for org %s", db_org_id)
            return

        logger.info(
            "NHI signin enrichment: processing %d identities for org %s (run %s)",
            len(identities), db_org_id, current_run_id,
        )

        enriched = 0
        skipped = 0
        for db_id, identity_id, object_id, app_id, display_name, created_dt in identities:
            # Try object_id first (SP sign-in), then app_id (app sign-in)
            last_seen = None
            source = None

            if object_id:
                last_seen = tracker.get_service_principal_last_sign_in(object_id)
                if last_seen:
                    source = 'sp_signin'

            if not last_seen and app_id:
                last_seen = tracker.get_last_sign_in(app_id)
                if last_seen:
                    source = 'app_signin'

            if last_seen:
                from datetime import datetime as _dt, timezone as _tz
                now = _dt.now(_tz.utc)
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=_tz.utc)
                days_since = (now - last_seen).days

                # Reclassify pattern based on actual sign-in data
                pattern = 'machine_only'  # SP/app sign-ins are non-interactive

                ucursor = db.conn.cursor()
                ucursor.execute("""
                    UPDATE identities SET
                        signin_pattern = %s,
                        last_sign_in = %s,
                        last_noninteractive_signin = %s,
                        days_since_last_signin = %s,
                        activity_status = CASE
                            WHEN %s <= 30 THEN 'active'
                            WHEN %s <= 90 THEN 'inactive'
                            ELSE 'stale'
                        END
                    WHERE id = %s
                """, (pattern, last_seen, last_seen, days_since,
                      days_since, days_since, db_id))
                db.conn.commit()
                ucursor.close()
                enriched += 1

                if enriched <= 5:
                    logger.info(
                        "  Enriched %s: %s=%s (%d days ago)",
                        display_name, source, last_seen.isoformat(), days_since,
                    )
            else:
                skipped += 1

            # Rate limit: 150ms between Graph API calls (two calls per identity possible)
            _time.sleep(0.15)

        logger.info(
            "NHI signin enrichment for org %s: %d enriched, %d still never_used (of %d)",
            db_org_id, enriched, skipped, len(identities),
        )

    except Exception as e:
        logger.warning("NHI signin enrichment failed (non-blocking): %s", e)


def _run_agent_orphan_detection(current_run_id, db_org_id, db):
    """AI Agent Governance Phase 2: detect orphaned AI agent SPNs.

    Runs auto-resolve BEFORE detection. Saves findings, fires alerts.
    Gated by FEATURE_AI_AGENT_GOVERNANCE flag.
    """
    from app.config import FEATURE_AI_AGENT_GOVERNANCE
    if not FEATURE_AI_AGENT_GOVERNANCE:
        return

    try:
        from app.engines.agent_orphan_detector import AgentOrphanDetector

        detector = AgentOrphanDetector(db)

        # Auto-resolve first
        resolved = detector.auto_resolve(current_run_id)
        if resolved:
            logger.info("Orphan auto-resolve for org %s: %d resolved", db_org_id, resolved)

        # Detect new orphans
        findings = detector.analyze(current_run_id)

        if findings:
            saved = db.save_security_findings(current_run_id, findings)
            logger.info(
                "Orphan detection for org %s: %d findings saved",
                db_org_id, saved,
            )

            # In-app notifications
            for f in findings:
                try:
                    db.create_notification(
                        event_type='orphaned_agent_detected',
                        category='ai_agent_governance',
                        severity='critical',
                        title=f['title'],
                        description=f['description'],
                        payload=f.get('metadata'),
                        related_identity_id=f.get('entity_id'),
                        related_identity_name=f.get('identity_name'),
                        related_run_id=current_run_id,
                        organization_id=db_org_id,
                    )
                except Exception as e:
                    logger.warning("Failed to create orphan notification: %s", e)

            # Slack/Teams dispatch
            _dispatch_notification('orphaned_agent_detected', {
                'title': f'Orphaned AI Agent SPNs Detected ({len(findings)})',
                'description': (
                    f'{len(findings)} orphaned AI agent SPN(s) found with elevated '
                    f'permissions. Immediate review recommended.'
                ),
                'severity': 'critical',
            }, db_org_id=db_org_id)

            # Email alert — dedup guard: only alert for findings not yet alerted
            try:
                from app.services.email_service import get_email_service

                # Filter to findings that haven't been alerted yet
                new_findings = []
                cursor = db.conn.cursor()
                for f in findings:
                    fp = f.get('finding_fingerprint')
                    if not fp:
                        new_findings.append(f)
                        continue
                    cursor.execute("""
                        SELECT alert_sent_at
                        FROM security_findings
                        WHERE finding_fingerprint = %s
                          AND organization_id = %s
                          AND status = 'open'
                        ORDER BY created_at DESC
                        LIMIT 1
                    """, (fp, db_org_id))
                    row = cursor.fetchone()
                    if row is None or row[0] is None:
                        # No finding row or alert_sent_at is NULL → needs alerting
                        new_findings.append(f)
                    else:
                        display = f.get('metadata', {}).get('display_name', f.get('entity_id', '?'))
                        logger.info(
                            "Orphan alert already sent for %s at %s, skipping.",
                            display, row[0],
                        )
                cursor.close()

                if new_findings:
                    email_svc = get_email_service()
                    sent = email_svc.send_orphan_agent_alert(new_findings, current_run_id, db_org_id)

                    # Stamp alert_sent_at on the findings we just alerted
                    if sent:
                        stamp_cursor = db.conn.cursor()
                        for f in new_findings:
                            fp = f.get('finding_fingerprint')
                            if fp:
                                stamp_cursor.execute("""
                                    UPDATE security_findings
                                    SET alert_sent_at = NOW()
                                    WHERE finding_fingerprint = %s
                                      AND organization_id = %s
                                      AND status = 'open'
                                """, (fp, db_org_id))
                        db.conn.commit()
                        stamp_cursor.close()
                        logger.info(
                            "Orphan alert sent for %d new finding(s), %d skipped (already alerted).",
                            len(new_findings), len(findings) - len(new_findings),
                        )
                else:
                    logger.info(
                        "All %d orphan finding(s) already alerted — no email sent.",
                        len(findings),
                    )
            except Exception as e:
                logger.warning("Orphan email alert failed (non-blocking): %s", e)

    except Exception as e:
        logger.warning("Agent orphan detection failed (non-blocking): %s", e)


if __name__ == "__main__":
    print("Testing scheduler...")
    print("Starting scheduler (will run every 6 hours)")
    print("Press Ctrl+C to stop")
    
    start_scheduler()
    
    # Keep running
    try:
        import time
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nStopping scheduler...")
        stop_scheduler()
        print("Done!")

# AG-193 — Data Trust Zones post-discovery hook
def _run_data_trust_zones_classification(db_org_id, db):
    """Apply CISO-asserted Data Trust Zones to all resources after discovery.

    Idempotent: re-runs leave classifications untouched when nothing
    changed. Higher-precedence tiers (manual, regex_override, purview)
    are preserved.
    """
    try:
        from app.engines.discovery.scope_classifier import apply_scope_classification
        result = apply_scope_classification(db, db_org_id)
        if result.get('rules_active', 0) == 0:
            logger.info("DTZ: org=%s no active zones; skip", db_org_id)
            return
        logger.info(
            "DTZ: org=%s rules=%d tables=%d rows_updated=%d by_class=%s",
            db_org_id, result['rules_active'], len(result['tables_walked']),
            result['rows_updated'], result.get('by_classification'),
        )
    except Exception as e:
        logger.error("Data Trust Zones classification failed org=%s: %s", db_org_id, e)
        logger.exception(e)


# AG-193 Sprint B — reach attribution post-discovery hook
def _run_reach_attribution(db_org_id, db):
    """Compute per-entity reachable classified exposure.

    For each identity (and AI model deployment), walk RBAC scope to
    classified resources and sum their dollar exposure. The result is
    cached on identities.reachable_classified_exposure and
    azure_ai_model_deployments.reachable_classified_exposure for fast
    dashboard reads.

    Depends on data_trust_zones having run first so the classifications
    we attribute against are fresh.
    """
    try:
        from app.engines.discovery.reach_attributor import compute_all_reach
        result = compute_all_reach(db, db_org_id)
        logger.info(
            "REACH: org=%s identity=%s ai_model=%s",
            db_org_id,
            result.get('identity'),
            result.get('ai_model'),
        )
    except Exception as e:
        logger.error("Reach attribution failed org=%s: %s", db_org_id, e)
        logger.exception(e)
