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
from dotenv import load_dotenv

from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
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
    Runs the discovery process.
    Called by the scheduler.
    """
    logger.info("=" * 70)
    logger.info("SCHEDULED DISCOVERY STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)
    
    try:
        # Get credentials from environment
        tenant_id = os.getenv("AZURE_TENANT_ID")
        client_id = os.getenv("AZURE_CLIENT_ID")
        client_secret = os.getenv("AZURE_CLIENT_SECRET")

        # Phase 48: Fallback to DB settings (onboarding wizard stores creds here)
        if not all([tenant_id, client_id, client_secret]):
            try:
                settings_db = Database()
                settings = settings_db.get_settings()
                tenant_id = tenant_id or settings.get('azure_tenant_id')
                client_id = client_id or settings.get('azure_client_id')
                client_secret = client_secret or settings.get('azure_client_secret')
                settings_db.close()
            except Exception:
                pass

        # Validate
        if not all([tenant_id, client_id, client_secret]):
            logger.error("❌ Missing Azure credentials in environment and DB settings")
            return
        
        logger.info("✓ Azure credentials loaded")
        
        # Initialize discovery engine
        engine = AzureDiscoveryEngine(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        logger.info("✓ Discovery engine initialized")
        
        # Run discovery
        logger.info("▶ Starting discovery...")
        engine.run_discovery()
        
        logger.info("✅ SCHEDULED DISCOVERY COMPLETED SUCCESSFULLY")
        logger.info("=" * 70)

        # Log activity
        try:
            act_db = Database()
            act_db.log_activity('discovery_completed', 'Scheduled discovery run completed')
            act_db.close()
        except Exception:
            pass

        # Check for identity changes and send email notification
        _send_change_notification_if_needed()

    except Exception as e:
        logger.error(f"❌ SCHEDULED DISCOVERY FAILED: {str(e)}")
        logger.exception(e)


def _send_change_notification_if_needed():
    """
    Compare the two most recent discovery runs and send email if changes detected.
    Called after each successful discovery run.
    """
    try:
        db = Database()

        # Get the two most recent completed runs
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE status = 'completed'
            ORDER BY id DESC
            LIMIT 2
        """)
        runs = cursor.fetchall()
        cursor.close()

        if len(runs) < 2:
            logger.info("Not enough discovery runs for comparison - skipping change notification")
            db.close()
            return

        current_run_id = runs[0][0]
        previous_run_id = runs[1][0]

        logger.info(f"Comparing runs: #{current_run_id} vs #{previous_run_id}")

        # Compare runs for changes
        detector = DriftDetector(db)
        changes = detector.compare_runs(current_run_id, previous_run_id)

        # Phase 14: Persist drift report
        report_id = db.save_drift_report(current_run_id, previous_run_id, changes)
        logger.info(f"Drift report #{report_id} saved for runs #{current_run_id} vs #{previous_run_id}")

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
            email_enabled = db.get_setting('email_enabled', 'true') == 'true'
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
                    if db.get_setting(setting_key, 'true') == 'true':
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

        # Phase 43: SOAR evaluation for drift and change events
        _evaluate_soar_triggers_for_changes(changes, db)

        # Phase 28: Fire webhook events
        _fire_webhook_events(current_run_id, changes, db)

        # Phase 30: Generate in-app notifications
        _generate_notifications(current_run_id, changes, db)

        # Phase 40: Run anomaly detection
        _run_anomaly_detection(current_run_id, previous_run_id, db)

        # Phase 51: Save compliance snapshot
        _save_compliance_snapshot(current_run_id, db)

        db.close()

    except Exception as e:
        logger.error(f"Error during change detection/notification: {e}")
        logger.exception(e)


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

        notifier.notify_discovery_completed(current_run_id, summary)

        new_ids = changes.get('new_identities', [])
        if new_ids:
            notifier.notify_new_identities(current_run_id, new_ids)

        removed_ids = changes.get('removed_identities', [])
        if removed_ids:
            notifier.notify_removed_identities(current_run_id, removed_ids)

        risk_changes = changes.get('risk_changes', [])
        escalations = [c for c in risk_changes if c.get('direction') == 'increased' or c.get('new_risk') in ('critical', 'high')]
        if escalations:
            notifier.notify_risk_escalations(current_run_id, escalations)

        perm_changes = changes.get('permission_changes', [])
        if perm_changes:
            notifier.notify_permission_changes(current_run_id, perm_changes)

        cred_changes = changes.get('credential_changes', [])
        if cred_changes:
            notifier.notify_credential_changes(current_run_id, cred_changes)

        # Cleanup old notifications
        cleaned = db.cleanup_old_notifications(days=90)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old notifications")

        logger.info(f"In-app notifications generated for run #{current_run_id}")

    except Exception as e:
        logger.error(f"Error generating notifications: {e}")


def _run_anomaly_detection(current_run_id: int, previous_run_id: int, db: Database):
    """Run anomaly detection after drift analysis and persist results."""
    try:
        # Load configurable thresholds from settings
        settings = {}
        for key in ('anomaly_pim_hours_start', 'anomaly_pim_hours_end',
                     'anomaly_pim_frequency_threshold', 'anomaly_risk_spike_threshold'):
            val = db.get_setting(key, None)
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
        else:
            logger.info(f"Anomaly detection: no anomalies found for run #{current_run_id}")

        # Cleanup old resolved anomalies
        cleaned = db.cleanup_old_anomalies(days=180)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old resolved anomalies")

    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
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
    """
    logger.info("=" * 70)
    logger.info("SCHEDULED REPORT EMAIL STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    try:
        db = Database()
        enabled = db.get_setting('report_schedule_enabled', 'false')
        db.close()

        if enabled != 'true':
            logger.info("Scheduled reports disabled in settings - skipping")
            return

        email_service = EmailService()
        if not email_service.credentials_configured:
            logger.warning("Azure credentials not configured - skipping scheduled report")
            return

        success = email_service.send_scheduled_report()

        act_db = Database()
        if success:
            act_db.log_activity('report_emailed', 'Scheduled executive summary report sent')
            logger.info("✅ Scheduled report email sent successfully")
        else:
            act_db.log_activity('report_email_failed', 'Scheduled report email failed to send')
            logger.warning("Failed to send scheduled report email")
        act_db.close()

    except Exception as e:
        logger.error(f"Scheduled report failed: {e}")
        logger.exception(e)


def run_data_retention():
    """
    Run data retention cleanup based on configured policies.
    Called daily by the scheduler at 03:00 UTC.
    """
    logger.info("=" * 70)
    logger.info("DATA RETENTION CLEANUP STARTED")
    logger.info(f"Time: {datetime.utcnow().isoformat()}")
    logger.info("=" * 70)

    try:
        db = Database()
        enabled = db.get_setting('retention_enabled', 'false')

        if enabled != 'true':
            logger.info("Data retention disabled in settings - skipping")
            db.close()
            return

        discovery_days = int(db.get_setting('retention_discovery_days', '90'))
        drift_days = int(db.get_setting('retention_drift_days', '90'))
        activity_days = int(db.get_setting('retention_activity_days', '180'))
        anomalies_days = int(db.get_setting('retention_anomalies_days', '90'))
        soar_days = int(db.get_setting('retention_soar_days', '90'))
        notif_days = int(db.get_setting('retention_notifications_days', '90'))

        results = {}
        run_counts = db.cleanup_old_discovery_runs(days=discovery_days)
        results['discovery_runs'] = run_counts.get('discovery_runs', 0)
        results['risk_scores'] = run_counts.get('risk_scores', 0)
        results['drift_reports'] = db.cleanup_old_drift_reports(days=drift_days)
        results['activity_log'] = db.cleanup_old_activity_log(days=activity_days)
        results['anomalies'] = db.cleanup_old_anomalies(days=anomalies_days)
        results['soar_actions'] = db.cleanup_old_soar_actions(days=soar_days)
        results['notifications'] = db.cleanup_old_notifications(days=notif_days)

        total = sum(results.values())
        if total > 0:
            db.log_activity('data_retention', f'Scheduled cleanup: {total} records deleted',
                            json.dumps(results))
            logger.info(f"✅ Data retention: {total} records deleted")
            for table, count in results.items():
                if count > 0:
                    logger.info(f"   {table}: {count} deleted")
        else:
            logger.info("Data retention: no records to clean up")

        db.close()

    except Exception as e:
        logger.error(f"Data retention failed: {e}")
        logger.exception(e)


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
    try:
        report_db = Database()
        report_freq = report_db.get_setting('report_schedule_frequency', 'weekly')
        report_enabled = report_db.get_setting('report_schedule_enabled', 'false') == 'true'
        report_db.close()
    except Exception:
        report_freq = 'weekly'
        report_enabled = False

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

    # Start the scheduler
    scheduler.start()

    logger.info("✅ Scheduler started")
    logger.info(f"📅 Discovery: Every {interval_hours} hours")
    logger.info(f"📊 Report: {report_name} (enabled={report_enabled})")
    logger.info("🗑️ Retention: Daily at 03:00 UTC")

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


def trigger_manual_discovery(scan_mode: str = 'deep'):
    """
    Trigger discovery immediately (manual override).
    Used by API endpoint or admin panel.
    """
    logger.info(f"🔄 MANUAL DISCOVERY TRIGGERED (mode={scan_mode})")
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