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
from dotenv import load_dotenv

from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
from app.engines.discovery.aws_discovery import AWSDiscoveryEngine
from app.engines.drift_detector import DriftDetector
from app.engines.anomaly_detector import AnomalyDetector
from app.services.email_service import EmailService
from app.database import Database
from typing import Dict

# Load environment
load_dotenv()

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
            _run_org_discovery(db_org_id, org_name, scan_mode)
        except Exception as e:
            logger.error(f"❌ Discovery FAILED for organization {org_name}: {str(e)}")
            logger.exception(e)
            _dispatch_notification('scan_failed', {
                'title': f'Discovery Scan Failed — {org_name}',
                'description': f'Discovery failed for organization {org_name}: {str(e)[:200]}',
                'severity': 'critical',
            }, db_org_id=db_org_id)

    logger.info("=" * 70)
    logger.info("SCHEDULED DISCOVERY COMPLETED (all organizations)")
    logger.info("=" * 70)


def _run_org_discovery(db_org_id: int, org_name: str, scan_mode: str = 'deep',
                       connection_id: int = None):
    """Run discovery for a single organization using their cloud connections.
    If connection_id is provided, only scan that specific connection.
    Otherwise scan ALL connected connections for the organization.
    Falls back to legacy settings-based credentials if no connections exist.
    """
    admin_db = Database()
    try:
        connections = admin_db.get_cloud_connections(db_org_id,
                                                     include_secrets=True)
    finally:
        admin_db.close()

    # Filter to specific connection if requested
    if connection_id:
        connections = [c for c in connections if c['id'] == connection_id]
        if not connections:
            logger.warning(f"  ⚠ Connection {connection_id} not found for organization {org_name}")
            return

    # Filter to only connected connections
    connected = [c for c in connections if c.get('status') == 'connected']

    if connected:
        logger.info(f"  Found {len(connected)} connected connection(s) for {org_name}")
        any_ran = False
        for conn in connected:
            _run_connection_discovery(db_org_id, org_name, conn, scan_mode)
            any_ran = True
        if not any_ran:
            logger.info(f"  All connections skipped (missing credentials), trying legacy settings for {org_name}")
            _run_legacy_settings_discovery(db_org_id, org_name, scan_mode)
    else:
        # Fallback: legacy settings-based credentials
        logger.info(f"  No cloud_connections found, trying legacy settings for {org_name}")
        _run_legacy_settings_discovery(db_org_id, org_name, scan_mode)

    logger.info(f"  ✅ Discovery completed for {org_name}")

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
        if org and org.get('onboarding_stage') in ('locked', 'authenticating', 'password_change'):
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


def _run_connection_discovery(db_org_id: int, org_name: str, conn: dict, scan_mode: str = 'deep'):
    """Run discovery for a single cloud connection."""
    conn_id = conn['id']
    label = conn.get('label', 'Unknown')
    cloud = conn.get('cloud', 'azure')

    metadata = conn.get('metadata') or {}

    logger.info(f"  ▶ Scanning connection '{label}' (id={conn_id}, cloud={cloud})")

    if cloud == 'azure':
        azure_directory_id = conn.get('azure_directory_id')
        client_id = conn.get('client_id')
        client_secret = metadata.get('client_secret')
        if not all([azure_directory_id, client_id, client_secret]):
            logger.warning(f"  ⏭ Skipping '{label}' — incomplete Azure credentials")
            return
        engine = AzureDiscoveryEngine(
            tenant_id=azure_directory_id,
            client_id=client_id,
            client_secret=client_secret,
            db_org_id=db_org_id,
            cloud_connection_id=conn_id,
        )
    elif cloud == 'aws':
        access_key_id = metadata.get('access_key_id') or conn.get('client_id')
        secret_access_key = metadata.get('secret_access_key') or metadata.get('client_secret')
        region = metadata.get('region', 'us-east-1')
        if not all([access_key_id, secret_access_key]):
            logger.warning(f"  ⏭ Skipping '{label}' — incomplete AWS credentials")
            return
        engine = AWSDiscoveryEngine(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region=region,
            db_org_id=db_org_id,
            cloud_connection_id=conn_id,
        )
    else:
        logger.info(f"  ⏭ Skipping unsupported cloud '{cloud}' for connection '{label}'")
        return

    logger.info(f"    ✓ {cloud.upper()} engine initialized for '{label}'")

    engine.run_discovery()
    logger.info(f"    ✅ Discovery completed for connection '{label}'")

    # Update last_discovery_at on the connection
    try:
        admin_db = Database()
        admin_db.update_cloud_connection(conn_id, last_discovery_at=datetime.utcnow())
        admin_db.close()
    except Exception as e:
        logger.warning(f"    ⚠ Failed to update last_discovery_at for connection {conn_id}: {e}")


def _run_legacy_settings_discovery(db_org_id: int, org_name: str, scan_mode: str = 'deep'):
    """Fallback: run discovery using legacy settings-table credentials (single connection)."""
    settings_db = Database(organization_id=db_org_id)
    try:
        settings = settings_db.get_settings(organization_id=db_org_id)
    finally:
        settings_db.close()

    azure_directory_id = settings.get('azure_directory_id')
    azure_client_id = settings.get('azure_client_id')
    azure_client_secret = settings.get('azure_client_secret')

    if not all([azure_directory_id, azure_client_id, azure_client_secret]):
        logger.info(f"  ⏭ Skipping organization {org_name} — no Azure credentials configured")
        return

    logger.info(f"  ✓ Azure credentials loaded from settings for {org_name}")

    engine = AzureDiscoveryEngine(
        tenant_id=azure_directory_id,
        client_id=azure_client_id,
        client_secret=azure_client_secret,
        db_org_id=db_org_id,
    )
    logger.info(f"  ✓ Discovery engine initialized for {org_name}")
    engine.run_discovery()


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

        # Phase 51: Save compliance snapshot
        _save_compliance_snapshot(current_run_id, db)

        # AGIRS: Compute and persist AGIRS scores
        _compute_agirs_scores(current_run_id, db_org_id, db)

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

    except Exception as e:
        logger.error(f"Data retention failed: {e}")
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
        db.conn.commit()
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

    # Start the scheduler
    scheduler.start()

    logger.info("✅ Scheduler started")
    logger.info(f"📅 Discovery: Every {interval_hours} hours")
    logger.info(f"📊 Report: {report_name} (enabled={report_enabled})")
    logger.info("🗑️ Retention: Daily at 03:00 UTC")
    logger.info("📋 Invoice overdue: Daily at 02:00 UTC")
    logger.info("🔄 Scan schedules: Every 60 seconds")

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