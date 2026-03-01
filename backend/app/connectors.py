"""FIX1C — Canonical connector retrieval layer.
All connector access MUST go through these functions.
"""
from psycopg2.extras import RealDictCursor


def get_connectors(db, org_id, cloud=None):
    """All connectors for an organization, optionally filtered by cloud provider."""
    return db.get_cloud_connections(org_id, cloud=cloud)


def get_connector(db, org_id, cloud, external_id):
    """Single connector by org + cloud + external_id."""
    db._ensure_cloud_connections_table()
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT * FROM cloud_connections
        WHERE organization_id = %s AND cloud = %s AND external_id = %s
    """, (org_id, cloud, external_id))
    row = cursor.fetchone()
    cursor.close()
    return dict(row) if row else None


def validate_connector_unique(db, cloud, external_id):
    """Check if cloud+external_id is already used globally.
    Returns existing organization_id or None.
    Should be called with admin DB (bypass RLS) for cross-org visibility.
    """
    if not external_id:
        return None
    db._ensure_cloud_connections_table()
    cursor = db.conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT organization_id FROM cloud_connections
        WHERE cloud = %s AND external_id = %s
        LIMIT 1
    """, (cloud, external_id))
    row = cursor.fetchone()
    cursor.close()
    return row['organization_id'] if row else None
