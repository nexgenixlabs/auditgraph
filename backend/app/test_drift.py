#!/usr/bin/env python3
"""
Test Drift Detection
Compares the last two discovery runs to detect changes
"""
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Database
from app.engines.drift_detector import DriftDetector

# Load environment variables
load_dotenv()

print("="*70)
print("                    AuditGraph Drift Detection Test")
print("="*70)
print()

# Initialize database
db = Database()

# Get the last two completed discovery runs
cursor = db.conn.cursor()
cursor.execute("""
    SELECT id, started_at, total_identities, critical_count
    FROM discovery_runs
    WHERE status = 'completed'
    ORDER BY id DESC
    LIMIT 2
""")

runs = cursor.fetchall()
cursor.close()

if len(runs) < 2:
    print("❌ Need at least 2 completed discovery runs to compare")
    print(f"   Currently have {len(runs)} completed run(s)")
    print("\n💡 Run discovery again to create a second run:")
    print("   python app/test_discovery.py")
    db.close()
    exit(1)

# Get the two most recent runs
current_run = runs[0]
previous_run = runs[1]

print(f"Found {len(runs)} completed discovery runs")
print(f"  Latest:   Run #{current_run[0]} - {current_run[1]} - {current_run[2]} identities")
print(f"  Previous: Run #{previous_run[0]} - {previous_run[1]} - {previous_run[2]} identities")
print()

# Initialize drift detector
detector = DriftDetector(db)

# Compare the runs
changes = detector.compare_runs(
    current_run_id=current_run[0],
    previous_run_id=previous_run[0]
)

# Print the drift report
detector.print_drift_report(changes, current_run[0], previous_run[0])

print("\n" + "="*70)
print()

# Close database
db.close()
