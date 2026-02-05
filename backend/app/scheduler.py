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
    - Discovery runs every 6 hours (configurable via CronTrigger)
    - Job ID: 'discovery_every_6h'
    - Timezone: UTC

Lifecycle Management:
    - Scheduler is started when Flask app initializes (create_app)
    - Scheduler is stopped via atexit hook on app shutdown
    - Singleton pattern prevents multiple scheduler instances

Error Handling:
    - Discovery failures are logged but don't crash the scheduler
    - Missing credentials are logged and the job exits gracefully
    - TODO: Email notifications for success/failure (Week 7 Part 2)

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
        
        # TODO: Send email notification (Week 7 Part 2)
        
    except Exception as e:
        logger.error(f"❌ SCHEDULED DISCOVERY FAILED: {str(e)}")
        logger.exception(e)
        # TODO: Send failure notification (Week 7 Part 2)


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
    
    # Schedule: Every 6 hours (UTC)
    trigger = CronTrigger(hour="*/6", minute=0, timezone="UTC")
    
    scheduler.add_job(
        func=run_scheduled_discovery,
        trigger=trigger,
        id='discovery_every_6h',
        name='Identity Discovery (Every 6 Hours)',
        replace_existing=True
    ,
        max_instances=1,
        coalesce=True
    )
    
    # Start the scheduler
    scheduler.start()
    
    logger.info("✅ Scheduler started")
    logger.info("📅 Schedule: Every 6 hours")
    
    # Get next run time
    job = scheduler.get_job('discovery_every_6h')
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
    
    job = scheduler.get_job('discovery_every_6h')
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