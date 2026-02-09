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
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv

from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
from app.engines.drift_detector import DriftDetector
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


def run_scheduled_discovery():
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
        
        # Validate
        if not all([tenant_id, client_id, client_secret]):
            logger.error("❌ Missing Azure credentials in environment")
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

        db.close()

    except Exception as e:
        logger.error(f"Error during change detection/notification: {e}")
        logger.exception(e)


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
    
    # Start the scheduler
    scheduler.start()
    
    logger.info("✅ Scheduler started")
    logger.info(f"📅 Schedule: Every {interval_hours} hours")

    # Get next run time
    job = scheduler.get_job('scheduled_discovery')
    if job:
        next_run = job.next_run_time
        logger.info(f"🕐 Next scheduled run: {next_run}")
    
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


def trigger_manual_discovery():
    """
    Trigger discovery immediately (manual override).
    Used by API endpoint or admin panel.
    """
    logger.info("🔄 MANUAL DISCOVERY TRIGGERED")
    run_scheduled_discovery()


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