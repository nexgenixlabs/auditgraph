"""AI Agent Identity Classifier — Phase 1.

Evaluates Service Principals against ai_agent_patterns.json to determine
which are AI agent identities. Classification is additive only — it writes
to the agent_classifications table and sets agent_identity_type on identities.

No existing identity fields, AGIRS scoring, or blast radius logic is modified.
"""

import json
import logging
from datetime import datetime, timezone

from app.engines.discovery.agent_pattern_loader import (
    get_version,
    match_app_id,
    match_display_name,
    match_permissions,
)

logger = logging.getLogger(__name__)

# Confidence thresholds
AUTO_CLASSIFY_THRESHOLD = 0.8    # >= 0.8 → ai_agent
POSSIBLE_THRESHOLD = 0.6        # 0.6–0.79 → possible_ai_agent


def classify_identity(display_name, app_id=None, permissions=None):
    """Classify a single identity against the AI agent pattern library.

    Args:
        display_name: SPN display name
        app_id: Azure application ID (optional)
        permissions: list of permission strings or dicts (optional)

    Returns:
        dict with classification result:
            agent_identity_type: 'ai_agent' | 'possible_ai_agent' | 'unknown'
            classification_confidence: 0.0–1.0
            classification_reason: human-readable reason string
            detected_platform: platform name or None
    """
    # 1. Check app_id against known_app_ids (exact match, highest priority)
    if app_id:
        platform = match_app_id(app_id)
        if platform:
            return {
                'agent_identity_type': 'ai_agent',
                'classification_confidence': 1.0,
                'classification_reason': f'app_id_match: {platform}',
                'detected_platform': platform,
            }

    # 2. Check display_name against patterns (regex)
    if display_name:
        platform, confidence = match_display_name(display_name)
        if platform and confidence >= AUTO_CLASSIFY_THRESHOLD:
            return {
                'agent_identity_type': 'ai_agent',
                'classification_confidence': confidence,
                'classification_reason': f'display_name_match: {platform}',
                'detected_platform': platform,
            }
        if platform and confidence >= POSSIBLE_THRESHOLD:
            return {
                'agent_identity_type': 'possible_ai_agent',
                'classification_confidence': confidence,
                'classification_reason': f'display_name_match: {platform} (below auto-classify threshold)',
                'detected_platform': platform,
            }

    # 3. Check API permissions against permission signals
    if permissions:
        perm_strings = []
        for p in permissions:
            if isinstance(p, dict):
                perm_strings.append(p.get('permission', ''))
                perm_strings.append(p.get('resource', ''))
            else:
                perm_strings.append(str(p))

        matches = match_permissions(perm_strings)
        if matches:
            best = max(matches, key=lambda m: m[1])
            perm_name, confidence, platform = best
            return {
                'agent_identity_type': 'ai_agent',
                'classification_confidence': confidence,
                'classification_reason': f'permission_match: {perm_name}',
                'detected_platform': platform,
            }

    # 4. No match
    return {
        'agent_identity_type': 'unknown',
        'classification_confidence': 0.0,
        'classification_reason': None,
        'detected_platform': None,
    }


def classify_tenant(db, organization_id, run_id=None):
    """Run the AI agent classifier for all SPNs in a tenant.

    Reads identities from the latest discovery run (or specified run_id),
    classifies each one, stores results in agent_classifications table,
    and updates identities.agent_identity_type for matched records.

    Args:
        db: Database connection (must be admin or have org context set)
        organization_id: tenant/org ID
        run_id: specific discovery run ID (optional, defaults to latest)

    Returns:
        dict with summary stats:
            total_evaluated: int
            ai_agent: int
            possible_ai_agent: int
            unknown: int
            run_id: int
            pattern_version: str
    """
    cursor = db.conn.cursor()
    pattern_version = get_version()
    now = datetime.now(timezone.utc)

    # Find the latest completed run for this org if not specified
    if not run_id:
        cursor.execute("""
            SELECT id FROM discovery_runs
            WHERE organization_id = %s AND status = 'completed'
            ORDER BY id DESC LIMIT 1
        """, (organization_id,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            logger.info("No completed discovery run for org %s — skipping classification", organization_id)
            return {'total_evaluated': 0, 'ai_agent': 0, 'possible_ai_agent': 0,
                    'unknown': 0, 'run_id': None, 'pattern_version': pattern_version}
        run_id = row[0]

    # Fetch all SPNs from this run
    cursor.execute("""
        SELECT i.id, i.identity_id, i.display_name, i.app_id
        FROM identities i
        WHERE i.discovery_run_id = %s
          AND COALESCE(i.identity_category, '') IN ('service_principal', 'ServicePrincipal', '')
          AND NOT COALESCE(i.is_microsoft_system, false)
    """, (run_id,))
    identities = cursor.fetchall()

    stats = {'total_evaluated': len(identities), 'ai_agent': 0,
             'possible_ai_agent': 0, 'unknown': 0,
             'run_id': run_id, 'pattern_version': pattern_version}

    for identity_db_id, identity_id, display_name, app_id in identities:
        # Fetch permissions for this identity
        permissions = _get_identity_permissions(cursor, identity_db_id)

        # Classify
        result = classify_identity(display_name, app_id, permissions)
        agent_type = result['agent_identity_type']
        stats[agent_type] = stats.get(agent_type, 0) + 1

        # Upsert into agent_classifications
        cursor.execute("""
            INSERT INTO agent_classifications
                (identity_db_id, identity_id, agent_identity_type,
                 classification_confidence, classification_reason,
                 detected_platform, pattern_version, classified_at,
                 discovery_run_id, organization_id, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (identity_db_id, discovery_run_id)
            DO UPDATE SET
                agent_identity_type = EXCLUDED.agent_identity_type,
                classification_confidence = EXCLUDED.classification_confidence,
                classification_reason = EXCLUDED.classification_reason,
                detected_platform = EXCLUDED.detected_platform,
                pattern_version = EXCLUDED.pattern_version,
                classified_at = EXCLUDED.classified_at,
                updated_at = EXCLUDED.updated_at
        """, (
            identity_db_id, identity_id, agent_type,
            result['classification_confidence'],
            result['classification_reason'],
            result['detected_platform'],
            pattern_version, now, run_id, organization_id, now,
        ))

        # Update identities.agent_identity_type (lightweight)
        if agent_type in ('ai_agent', 'possible_ai_agent'):
            cursor.execute("""
                UPDATE identities SET agent_identity_type = %s
                WHERE id = %s
            """, (agent_type, identity_db_id))

    db._commit()
    cursor.close()

    logger.info(
        "Agent classification complete for org %s run %s: "
        "%d evaluated, %d ai_agent, %d possible, %d unknown (patterns v%s)",
        organization_id, run_id,
        stats['total_evaluated'], stats['ai_agent'],
        stats['possible_ai_agent'], stats['unknown'], pattern_version,
    )
    return stats


def _get_identity_permissions(cursor, identity_db_id):
    """Fetch permissions for an identity from identity_permissions table."""
    try:
        cursor.execute("""
            SELECT permissions FROM identity_permissions
            WHERE identity_db_id = %s
            ORDER BY id DESC LIMIT 1
        """, (identity_db_id,))
        row = cursor.fetchone()
        if row and row[0]:
            perms = row[0]
            if isinstance(perms, str):
                perms = json.loads(perms)
            return perms if isinstance(perms, list) else []
    except Exception:
        pass
    return []
