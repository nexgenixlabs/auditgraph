"""
Security Findings Engine (connection-scoped)

Generates security findings from role_assignments + identities for a given
cloud connection. Complements the run-scoped SecurityFindingsEngine by
providing a connection-level entry point for the post-discovery pipeline.

Rules:
  1) High Privilege Identity — Owner / User Access Administrator / Global Administrator
  2) Guest with Privileged Role — guest + Owner or Contributor
  3) Service Principal Owner — service_principal + Owner
"""

import logging

logger = logging.getLogger(__name__)

# Roles that constitute high-privilege access
HIGH_PRIVILEGE_ROLES = {'Owner', 'User Access Administrator', 'Global Administrator'}

# Roles that are dangerous for guest identities
GUEST_DANGEROUS_ROLES = {'Owner', 'Contributor'}


def generate_security_findings(connection_id, db):
    """Generate security findings for a cloud connection.

    1. Resolve latest completed discovery run for this connection.
    2. Query role_assignments JOIN identities.
    3. Apply 3 detection rules.
    4. Insert findings into security_findings table.

    Returns dict with findings_count.
    """
    from psycopg2.extras import RealDictCursor

    cursor = db.conn.cursor(cursor_factory=RealDictCursor)

    # Find latest completed run for this connection
    cursor.execute("""
        SELECT id FROM discovery_runs
        WHERE cloud_connection_id = %s AND status = 'completed'
        ORDER BY id DESC LIMIT 1
    """, (connection_id,))
    row = cursor.fetchone()

    # Fallback: if no run by connection_id, try latest run with role_assignments
    if not row:
        logger.info(f"No run for connection {connection_id} by cloud_connection_id, trying fallback")
        try:
            cursor.execute("""
                SELECT DISTINCT dr.id
                FROM discovery_runs dr
                JOIN identities i ON i.discovery_run_id = dr.id
                JOIN role_assignments ra ON ra.identity_db_id = i.id
                WHERE dr.status = 'completed'
                ORDER BY dr.id DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
        except Exception:
            pass

    if not row:
        cursor.close()
        logger.debug(f"No completed run with assignments for connection {connection_id}, skipping")
        return {'findings_count': 0}

    run_id = row['id']

    # Fetch role assignments with identity metadata
    cursor.execute("""
        SELECT i.identity_id,
               i.display_name,
               i.identity_category,
               ra.role_name,
               ra.scope
        FROM role_assignments ra
        JOIN identities i ON i.id = ra.identity_db_id
        WHERE i.discovery_run_id = %s
          AND i.is_microsoft_system = FALSE
    """, (run_id,))
    assignments = cursor.fetchall()

    if not assignments:
        cursor.close()
        logger.info(f"No role assignments for run #{run_id}, skipping findings")
        return {'findings_count': 0}

    # Get organization_id from the run
    cursor.execute("SELECT organization_id FROM discovery_runs WHERE id = %s", (run_id,))
    run_row = cursor.fetchone()
    org_id = run_row['organization_id'] if run_row else None

    findings = []
    seen = set()  # Deduplicate by (identity_id, finding_type)

    for ra in assignments:
        identity_id = ra['identity_id']
        display_name = ra['display_name'] or 'Unknown'
        category = ra['identity_category'] or ''
        role_name = ra['role_name'] or ''
        scope = ra['scope'] or ''

        # Rule 1: High Privilege Identity
        if role_name in HIGH_PRIVILEGE_ROLES:
            key = (identity_id, 'high_privilege_identity')
            if key not in seen:
                seen.add(key)
                findings.append({
                    'identity_id': identity_id,
                    'finding_type': 'high_privilege_identity',
                    'severity': 'high',
                    'description': (
                        f'{display_name} has high-privilege role "{role_name}" '
                        f'at scope {scope}. Review whether this level of access is justified.'
                    ),
                })

        # Rule 2: Guest with Privileged Role
        if category == 'guest' and role_name in GUEST_DANGEROUS_ROLES:
            key = (identity_id, 'guest_privilege')
            if key not in seen:
                seen.add(key)
                findings.append({
                    'identity_id': identity_id,
                    'finding_type': 'guest_privilege',
                    'severity': 'high',
                    'description': (
                        f'Guest user {display_name} holds "{role_name}" role '
                        f'at scope {scope}. External guests with privileged '
                        f'access pose significant risk.'
                    ),
                })

        # Rule 3: Service Principal Owner
        if category == 'service_principal' and role_name == 'Owner':
            key = (identity_id, 'spn_high_privilege')
            if key not in seen:
                seen.add(key)
                findings.append({
                    'identity_id': identity_id,
                    'finding_type': 'spn_high_privilege',
                    'severity': 'high',
                    'description': (
                        f'Service principal {display_name} has Owner role '
                        f'at scope {scope}. Service principals with Owner '
                        f'access can modify all resources including RBAC.'
                    ),
                })

    # Delete existing findings from this engine for this connection
    cursor.execute("""
        DELETE FROM security_findings
        WHERE discovery_run_id = %s
          AND finding_type IN ('high_privilege_identity', 'guest_privilege', 'spn_high_privilege')
    """, (run_id,))

    # Insert new findings
    inserted = 0
    for f in findings:
        try:
            cursor.execute("""
                INSERT INTO security_findings
                    (discovery_run_id, organization_id, entity_type, entity_id,
                     finding_type, severity, risk_score, title, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                run_id,
                org_id,
                'identity',
                f['identity_id'],
                f['finding_type'],
                f['severity'],
                80 if f['severity'] == 'high' else 50,
                f'{f["finding_type"].replace("_", " ").title()}: {f["identity_id"][:40]}',
                f['description'],
            ))
            inserted += 1
        except Exception as e:
            logger.warning(f"Failed to insert finding: {e}")

    db._commit()
    cursor.close()

    logger.info(f"Security findings engine: {inserted} finding(s) for connection {connection_id} "
                f"(run #{run_id})")

    return {'findings_count': inserted}
