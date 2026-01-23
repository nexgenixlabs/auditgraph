"""
AuditGraph REST API
Provides HTTP endpoints for frontend access
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
from app.database import Database
from app.engines.drift_detector import DriftDetector
from dotenv import load_dotenv

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# Database connection
db = Database()


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'AuditGraph API',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/api/identities', methods=['GET'])
def get_identities():
    """
    Get all identities from the latest discovery run
    
    Query params:
        risk_level: Filter by risk level (critical, high, medium, low, info)
    """
    risk_filter = request.args.get('risk_level')
    
    cursor = db.conn.cursor()
    
    # Get latest completed run
    cursor.execute("""
        SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'
    """)
    latest_run = cursor.fetchone()[0]
    
    if not latest_run:
        return jsonify({'error': 'No completed discovery runs found'}), 404
    
    # Build query with optional risk filter
    query = """
        SELECT 
            i.identity_id,
            i.display_name,
            i.identity_type,
            i.risk_level,
            i.credential_status,
            i.activity_status,
            i.credential_expiration,
            i.created_datetime,
            COUNT(r.id) as role_count
        FROM identities i
        LEFT JOIN role_assignments r ON r.identity_db_id = i.id
        WHERE i.discovery_run_id = %s
    """
    
    params = [latest_run]
    
    if risk_filter:
        query += " AND LOWER(i.risk_level) = %s"
        params.append(risk_filter.lower())
    
    query += " GROUP BY i.id ORDER BY i.risk_level DESC, i.display_name"
    
    cursor.execute(query, params)
    
    identities = []
    for row in cursor.fetchall():
        identities.append({
            'identity_id': row[0],
            'display_name': row[1],
            'identity_type': row[2],
            'risk_level': row[3],
            'credential_status': row[4],
            'activity_status': row[5],
            'credential_expiration': row[6].isoformat() if row[6] else None,
            'created_datetime': row[7].isoformat() if row[7] else None,
            'role_count': row[8]
        })
    
    cursor.close()
    
    return jsonify({
        'count': len(identities),
        'run_id': latest_run,
        'identities': identities
    })


@app.route('/api/identities/<identity_id>', methods=['GET'])
def get_identity_details(identity_id):
    """Get detailed information about a specific identity"""
    cursor = db.conn.cursor()
    
    # Get latest run
    cursor.execute("""
        SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'
    """)
    latest_run = cursor.fetchone()[0]
    
    # Get identity details
    cursor.execute("""
        SELECT 
            i.identity_id,
            i.display_name,
            i.identity_type,
            i.app_id,
            i.object_id,
            i.risk_level,
            i.risk_reasons,
            i.credential_status,
            i.credential_expiration,
            i.activity_status,
            i.last_sign_in,
            i.created_datetime,
            i.enabled
        FROM identities i
        WHERE i.discovery_run_id = %s AND i.identity_id = %s
    """, (latest_run, identity_id))
    
    row = cursor.fetchone()
    
    if not row:
        cursor.close()
        return jsonify({'error': 'Identity not found'}), 404
    
    identity = {
        'identity_id': row[0],
        'display_name': row[1],
        'identity_type': row[2],
        'app_id': row[3],
        'object_id': row[4],
        'risk_level': row[5],
        'risk_reasons': row[6],
        'credential_status': row[7],
        'credential_expiration': row[8].isoformat() if row[8] else None,
        'activity_status': row[9],
        'last_sign_in': row[10].isoformat() if row[10] else None,
        'created_datetime': row[11].isoformat() if row[11] else None,
        'enabled': row[12]
    }
    
    # Get role assignments
    cursor.execute("""
        SELECT 
            i.id
        FROM identities i
        WHERE i.discovery_run_id = %s AND i.identity_id = %s
    """, (latest_run, identity_id))
    
    identity_db_id = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT role_name, scope, scope_type, created_on
        FROM role_assignments
        WHERE identity_db_id = %s
    """, (identity_db_id,))
    
    roles = []
    for role_row in cursor.fetchall():
        roles.append({
            'role_name': role_row[0],
            'scope': role_row[1],
            'scope_type': role_row[2],
            'created_on': role_row[3].isoformat() if role_row[3] else None
        })
    
    identity['roles'] = roles
    cursor.close()
    
    return jsonify(identity)


@app.route('/api/risks', methods=['GET'])
def get_risks():
    """Get all critical and high risk identities"""
    cursor = db.conn.cursor()
    
    # Get latest run
    cursor.execute("""
        SELECT MAX(id) FROM discovery_runs WHERE status = 'completed'
    """)
    latest_run = cursor.fetchone()[0]
    
    # Get high-risk identities
    cursor.execute("""
        SELECT 
            i.identity_id,
            i.display_name,
            i.risk_level,
            i.risk_reasons,
            COUNT(r.id) as role_count
        FROM identities i
        LEFT JOIN role_assignments r ON r.identity_db_id = i.id
        WHERE i.discovery_run_id = %s 
        AND i.risk_level IN ('critical', 'high')
        GROUP BY i.id
        ORDER BY 
            CASE i.risk_level 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
            END,
            i.display_name
    """, (latest_run,))
    
    risks = []
    for row in cursor.fetchall():
        risks.append({
            'identity_id': row[0],
            'display_name': row[1],
            'risk_level': row[2],
            'risk_reasons': row[3],
            'role_count': row[4]
        })
    
    cursor.close()
    
    return jsonify({
        'count': len(risks),
        'run_id': latest_run,
        'risks': risks
    })


@app.route('/api/runs', methods=['GET'])
def get_discovery_runs():
    """Get discovery run history"""
    cursor = db.conn.cursor()
    
    cursor.execute("""
        SELECT 
            id,
            subscription_id,
            subscription_name,
            started_at,
            completed_at,
            status,
            total_identities,
            critical_count,
            high_count,
            medium_count
        FROM discovery_runs
        ORDER BY id DESC
        LIMIT 20
    """)
    
    runs = []
    for row in cursor.fetchall():
        runs.append({
            'id': row[0],
            'subscription_id': row[1],
            'subscription_name': row[2],
            'started_at': row[3].isoformat() if row[3] else None,
            'completed_at': row[4].isoformat() if row[4] else None,
            'status': row[5],
            'total_identities': row[6],
            'critical_count': row[7],
            'high_count': row[8],
            'medium_count': row[9]
        })
    
    cursor.close()
    
    return jsonify({
        'count': len(runs),
        'runs': runs
    })


@app.route('/api/drift/<int:run_id>', methods=['GET'])
def get_drift_report(run_id):
    """Get drift detection report for a specific run"""
    cursor = db.conn.cursor()
    
    # Check if run exists
    cursor.execute("""
        SELECT id FROM discovery_runs WHERE id = %s
    """, (run_id,))
    
    if not cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Run not found'}), 404
    
    # Get previous run
    cursor.execute("""
        SELECT id FROM discovery_runs
        WHERE status = 'completed' AND id < %s
        ORDER BY id DESC
        LIMIT 1
    """, (run_id,))
    
    previous = cursor.fetchone()
    cursor.close()
    
    if not previous:
        return jsonify({
            'run_id': run_id,
            'message': 'No previous run to compare',
            'changes': None
        })
    
    previous_run_id = previous[0]
    
    # Run drift detection
    detector = DriftDetector(db)
    changes = detector.compare_runs(run_id, previous_run_id)
    
    # Format response
    return jsonify({
        'current_run_id': run_id,
        'previous_run_id': previous_run_id,
        'changes': {
            'new_identities': len(changes['new_identities']),
            'removed_identities': len(changes['removed_identities']),
            'permission_changes': len(changes['permission_changes']),
            'risk_changes': len(changes['risk_changes']),
            'credential_changes': len(changes['credential_changes']),
            'details': changes
        }
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    cursor = db.conn.cursor()
    
    # Get latest run
    cursor.execute("""
        SELECT 
            id,
            total_identities,
            critical_count,
            high_count,
            medium_count,
            completed_at
        FROM discovery_runs
        WHERE status = 'completed'
        ORDER BY id DESC
        LIMIT 1
    """)
    
    latest = cursor.fetchone()
    
    if not latest:
        cursor.close()
        return jsonify({'error': 'No completed runs found'}), 404
    
    # Get total runs
    cursor.execute("SELECT COUNT(*) FROM discovery_runs WHERE status = 'completed'")
    total_runs = cursor.fetchone()[0]
    
    cursor.close()
    
    return jsonify({
        'latest_run': {
            'id': latest[0],
            'total_identities': latest[1],
            'critical_count': latest[2],
            'high_count': latest[3],
            'medium_count': latest[4],
            'completed_at': latest[5].isoformat() if latest[5] else None
        },
        'total_discovery_runs': total_runs
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 AuditGraph API Server Starting...")
    print("="*60)
    print(f"API will be available at: http://localhost:5000")
    print(f"Endpoints:")
    print(f"  GET /api/health")
    print(f"  GET /api/identities")
    print(f"  GET /api/identities/<id>")
    print(f"  GET /api/risks")
    print(f"  GET /api/runs")
    print(f"  GET /api/drift/<run_id>")
    print(f"  GET /api/stats")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
