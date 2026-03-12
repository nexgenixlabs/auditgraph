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

    # Phase 83: Dispatch scan_complete notification
    _dispatch_notification('scan_complete', {
        'title': f'Discovery Scan Complete — {org_name}',
        'description': f'Scheduled discovery run completed for {org_name}.',
        'severity': 'info',
    }, db_org_id=db_org_id)


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
    import time as _time
    if not AZURE_DISCOVERY_ENABLED and conn.get('cloud', 'azure') == 'azure':
        logger.info(f"  ⏭ Azure discovery disabled (APP_ENV=local), skipping connection '{conn.get('label', 'Unknown')}'")
        return
    conn_id = conn['id']
    label = conn.get('label', 'Unknown')
    cloud = conn.get('cloud', 'azure')

    metadata = conn.get('metadata') or {}

    # Phase 3: Concurrency guard — skip if a job is already active for this connection
    job_id = None
    try:
        guard_db = Database()
        active = guard_db.get_active_snapshot_job(conn_id)
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
        engine.run_discovery()
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

        # 2. Enforce runtime limit (30 minutes max)
        overtime = db.get_runtime_exceeded_jobs(max_runtime_minutes=30)
        for ot in overtime:
            try:
                db.complete_snapshot_job(ot['id'], 'failed',
                                        'Discovery exceeded 30-minute runtime limit',
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
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT cloud_connection_id, id,
                   ROW_NUMBER() OVER (PARTITION BY cloud_connection_id ORDER BY id DESC) as rn
            FROM discovery_runs
            WHERE status = 'completed'
              AND cloud_connection_id IS NOT NULL AND cloud_connection_id > 0
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
            logger.info("Not enough per-connection discovery runs for comparison - skipping change notification")
            db.close()
            return

        # Compare runs per-connection and aggregate changes
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

        # Ghost identity detection (disabled/deleted identities retaining roles)
        _run_ghost_detection(current_run_id, db)

        # Identity Correlation Engine — link regular ↔ privileged accounts
        _run_identity_correlation(current_run_id, db)

        # Phase 40: Run anomaly detection
        _run_anomaly_detection(current_run_id, previous_run_id, db)

        # Phase 89: Run resource anomaly detection
        _run_resource_anomaly_detection(current_run_id, previous_run_id, db)

        # Identity exposure detection (persisted to identity_exposures)
        _track_job('identity_exposures', db_org_id,
                   _run_identity_exposure_detection, current_run_id, db)

        # Phase 2: Security findings engine (tracked by Phase 8)
        _track_job('security_findings', db_org_id,
                   _run_security_findings, current_run_id, db)

        # Identity graph edges (identity→role→scope)
        _track_job('identity_graph_builder', db_org_id,
                   _run_identity_graph_builder, db_org_id, db)

        # Connection-scoped security findings (3 rules)
        _track_job('security_findings_engine', db_org_id,
                   _run_security_findings_engine, db_org_id, db)

        # Connection-scoped security posture aggregation (from findings)
        _track_job('connection_security_posture', db_org_id,
                   _run_connection_security_posture, db_org_id, db)

        # Phase 3: Attack path analysis (tracked by Phase 8)
        _track_job('attack_paths', db_org_id,
                   _run_attack_path_analysis, current_run_id, db)

        # Phase 4: Fix recommendations (tracked by Phase 8)
        _track_job('fix_recommendations', db_org_id,
                   _run_fix_recommendations, current_run_id, db)

        # Phase 5: Blast radius analysis (tracked by Phase 8)
        _track_job('blast_radius', db_org_id,
                   _run_blast_radius_analysis, current_run_id, db)

        # Drift intelligence enrichment (after attack paths + blast radius)
        _track_job('drift_intelligence', db_org_id,
                   _run_drift_intelligence, db_org_id, db)

        # Phase 6: Risk evaluation (rules-based findings per connection)
        _track_job('risk_evaluation', db_org_id,
                   _run_risk_evaluation, db_org_id, db)

        # Phase 7: IAM graph rebuild (relationship graph per connection)
        _track_job('iam_graph', db_org_id,
                   _run_iam_graph_build, db_org_id, db)

        # Phase 8: Privilege escalation detection (after graph build)
        _track_job('escalation_detection', db_org_id,
                   _run_escalation_detection, db_org_id, db)

        # Phase 9: Non-human identity security analysis
        _track_job('nhi_security', db_org_id,
                   _run_nhi_analysis, db_org_id, db)

        # Phase 11: Policy Recommendation Engine
        _track_job('policy_recommendations', db_org_id,
                   _run_policy_recommendations, db_org_id, db)

        # Phase 12: Automated Remediation (process approved actions)
        _track_job('auto_remediation', db_org_id,
                   _run_auto_remediation, db_org_id, db)

        # Phase 14: Collect tenant posture metrics for benchmarking
        _track_job('posture_metrics', db_org_id,
                   _run_posture_metrics, db_org_id, db)

        # Phase 15: AI Security Advisor report
        _track_job('security_advisor', db_org_id,
                   _run_security_advisor, db_org_id, db)

        # Phase 16: Graph visualization cache
        _track_job('graph_visualization', db_org_id,
                   _run_graph_visualization, db_org_id, db)

        # Phase 18: Risk forecasting
        _track_job('risk_forecast', db_org_id,
                   _run_risk_forecast, db_org_id, db)

        # Phase 19: Least-privilege policy generation
        _track_job('policy_generation', db_org_id,
                   _run_policy_generation, db_org_id, db)

        # Phase 20: Continuous identity threat detection
        _track_job('threat_detection', db_org_id,
                   _run_threat_detection, db_org_id, db)

        # Phase 21: Identity activity data lake ingestion
        _track_job('activity_ingestion', db_org_id,
                   _run_activity_ingestion, db_org_id, db)

        # Phase 23: Identity attack replay & forensics
        _track_job('attack_replay', db_org_id,
                   _run_attack_replay, db_org_id, db)

        # Phase 24: Autonomous security response orchestration
        _track_job('security_orchestration', db_org_id,
                   _run_security_orchestration, db_org_id, db)

        # Phase 26: Identity attack prediction
        _track_job('attack_prediction', db_org_id,
                   _run_attack_prediction, db_org_id, db)

        # Phase 27: Identity graph intelligence
        _track_job('graph_intelligence', db_org_id,
                   _run_graph_intelligence, db_org_id, db)

        # Phase 28: Identity governance
        _track_job('identity_governance', db_org_id,
                   _run_identity_governance, db_org_id, db)

        # Phase 30: Enterprise integrations dispatch
        _track_job('integration_dispatch', db_org_id,
                   _run_integration_dispatch, db_org_id, db)

        # Phase 31: Governance analytics
        _track_job('governance_analytics', db_org_id,
                   _run_governance_analytics, db_org_id, db)

        # Phase 32: Security strategy advisor
        _track_job('security_strategy', db_org_id,
                   _run_security_strategy, db_org_id, db)

        # Phase 33: Security command center posture
        _track_job('security_posture', db_org_id,
                   _run_security_posture, db_org_id, db)

        # Phase 8 (v2): BFS graph attack engine (after graph intelligence)
        _track_job('graph_attack_engine', db_org_id,
                   _run_graph_attack_engine, current_run_id, db_org_id, db)

        # Normalize all risk pipelines into unified security_findings
        _track_job('findings_normalization', db_org_id,
                   _run_findings_normalization, current_run_id, db)

        # Phase 9: Compute security posture score (after graph attack engine)
        _track_job('posture_score', db_org_id,
                   _run_posture_score, current_run_id, db_org_id, db)

        # Phase 11: SLA breach check (after findings are persisted)
        _track_job('sla_check', db_org_id,
                   _run_sla_check, db_org_id, db)

        # Phase 51: Save compliance snapshot
        _save_compliance_snapshot(current_run_id, db)

        # AGIRS: Compute and persist AGIRS scores
        _compute_agirs_scores(current_run_id, db_org_id, db)

        # Phase 8: Evaluate tenant health + discovery integrity (non-blocking)
        _run_platform_health_check(current_run_id, db_org_id, db)

        db.close()

    except Exception as e:
        logger.error(f"Error during change detection/notification: {e}")
        logger.exception(e)


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


def _compute_agirs_scores(run_id: int, organization_id: int, db: Database):
    """Compute and persist AGIRS (AuditGraph Identity Risk Score) for the run."""
    try:
        from app.engines.risk.agirs_engine import AGIRSEngine
        engine = AGIRSEngine(db)
        result = engine.compute(organization_id, run_id)
        if result.get('agirs_score') is not None:
            logger.info(
                f"AGIRS computed for run #{run_id}: "
                f"{result['agirs_score']:.1f} "
                f"(HIRI={result['hiri_score']:.1f}, "
                f"NHIRI={result['nhiri_score']:.1f}, "
                f"GEI={result['gei_score']:.1f})"
            )
        else:
            logger.info(f"AGIRS: no data to compute for run #{run_id}")
    except Exception as e:
        logger.error(f"Error computing AGIRS scores: {e}")


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
                                engine = AzureDiscoveryEngine(conn_row, org_db)
                                engine.discover()
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


def start_scheduler():
    """
    Start the background scheduler.
    Called when the Flask app starts.
    """
    global scheduler
    
    if scheduler is not None:
        logger.warning("Scheduler already running")
        return
    
    logger.info("=" * 70)
    logger.info("INITIALIZING DISCOVERY SCHEDULER")
    logger.info("=" * 70)

    # Create scheduler
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