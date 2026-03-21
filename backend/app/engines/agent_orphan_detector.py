"""
Phase 2: Orphaned AI Agent SPN Detection Engine

Detects service principals classified as AI agents that are orphaned —
decommissioned agent with its SPN still active and holding elevated
permissions. Surfaces as finding type IASM-AG-001 with AGIRS penalty.

Orphan criteria (ALL must be true):
  1. Classified as ai_agent or possible_ai_agent
  2. Inactive for > ORPHAN_INACTIVE_DAYS (or never signed in)
  3. Still enabled (not disabled)
  4. Not soft-deleted
  5. Holds at least one elevated RBAC role
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from app.engines.security_findings import compute_finding_fingerprint

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────
FINDING_TYPE = 'orphaned_ai_agent_spn'
FINDING_CODE = 'IASM-AG-001'
ORPHAN_INACTIVE_DAYS = 30
AGIRS_PENALTY_SCORE = 15

# Named elevated RBAC roles (case-sensitive match)
_ELEVATED_RBAC_ROLES = {'Owner', 'Contributor', 'User Access Administrator'}

# Tokens in custom role names that indicate write/modify capability
_WRITE_ROLE_TOKENS = {'write', 'modify', 'delete', 'manage', 'admin', 'operator'}


class AgentOrphanDetector:
    """Detect orphaned AI agent SPNs with elevated permissions."""

    def __init__(self, db):
        self.db = db

    # ── Public API ─────────────────────────────────────────────────────

    def analyze(self, run_id: int) -> List[Dict]:
        """Run orphan detection for a discovery run.

        Returns list of finding dicts ready for save_security_findings().
        """
        findings = []
        try:
            orphans = self._detect_orphaned_agents(run_id)
            for orphan in orphans:
                finding = self._build_finding(
                    entity_id=orphan['identity_id'],
                    display_name=orphan['display_name'],
                    detected_platform=orphan.get('detected_platform'),
                    days_inactive=orphan['days_inactive'],
                    rbac_roles=orphan['rbac_roles'],
                    identity_db_id=orphan['identity_db_id'],
                    activity_detection_source=orphan.get('activity_detection_source', 'no_activity_recorded'),
                    last_interactive_sign_in=orphan.get('last_interactive_sign_in'),
                    last_service_principal_sign_in=orphan.get('last_service_principal_sign_in'),
                    effective_last_active=orphan.get('effective_last_active'),
                )
                findings.append(finding)

                # Apply AGIRS penalty on the agent_classifications row
                try:
                    self.db.update_agent_penalty(
                        orphan['identity_db_id'],
                        run_id,
                        AGIRS_PENALTY_SCORE,
                        f'{FINDING_CODE}: Orphaned AI agent SPN with elevated permissions '
                        f'(inactive {orphan["days_inactive"]}+ days)',
                    )
                except Exception as e:
                    logger.warning("Failed to set agent penalty for %s: %s",
                                   orphan['identity_id'], e)

            logger.info(
                "Orphan detection for run %d: %d orphaned agent(s) found",
                run_id, len(findings),
            )
        except Exception as e:
            logger.error("Orphan detection failed for run %d: %s", run_id, e)

        return findings

    def auto_resolve(self, run_id: int) -> int:
        """Resolve open orphan findings where SPN is now active/disabled/deleted/reclassified.

        Returns count of resolved findings.
        """
        resolved = 0
        cursor = self.db.conn.cursor()
        try:
            # Find open orphan findings for this org
            cursor.execute("""
                SELECT sf.id, sf.entity_id, sf.finding_fingerprint
                FROM security_findings sf
                WHERE sf.finding_type = %s
                  AND sf.status = 'open'
            """, (FINDING_TYPE,))
            open_findings = cursor.fetchall()

            for finding_id, entity_id, fingerprint in open_findings:
                # Check current identity state (including SP sign-in)
                cursor.execute("""
                    SELECT i.id, i.last_sign_in, i.enabled, i.deleted_at,
                           COALESCE(ac.agent_identity_type, 'unknown') as agent_type,
                           ac.discovery_run_id as ac_run_id,
                           ac.last_service_principal_sign_in
                    FROM identities i
                    LEFT JOIN agent_classifications ac ON ac.identity_db_id = i.id
                    WHERE i.identity_id = %s
                    ORDER BY i.discovery_run_id DESC
                    LIMIT 1
                """, (entity_id,))
                row = cursor.fetchone()

                if not row:
                    continue

                (identity_db_id, last_sign_in, enabled, deleted_at,
                 agent_type, ac_run_id, last_sp_sign_in) = row

                # Compute effective last activity (same logic as detection)
                candidates = [t for t in [last_sign_in, last_sp_sign_in] if t is not None]
                effective_last_active = max(candidates) if candidates else None

                # Determine if finding should be resolved
                should_resolve = False
                resolve_reason = None

                if deleted_at is not None:
                    should_resolve = True
                    resolve_reason = 'Identity deleted'
                elif not enabled:
                    should_resolve = True
                    resolve_reason = 'Identity disabled'
                elif agent_type not in ('ai_agent', 'possible_ai_agent'):
                    should_resolve = True
                    resolve_reason = f'Reclassified as {agent_type}'
                elif effective_last_active is not None:
                    days_since = (datetime.now(timezone.utc) - effective_last_active).days
                    if days_since <= ORPHAN_INACTIVE_DAYS:
                        source = 'SP sign-in' if last_sp_sign_in == effective_last_active else 'interactive sign-in'
                        should_resolve = True
                        resolve_reason = f'Active within {ORPHAN_INACTIVE_DAYS} days via {source} (last seen {days_since}d ago)'

                if should_resolve:
                    cursor.execute("""
                        UPDATE security_findings
                        SET status = 'resolved',
                            resolved_at = NOW(),
                            resolution_note = %s
                        WHERE id = %s
                    """, (resolve_reason, finding_id))

                    # Clear the penalty
                    try:
                        if ac_run_id:
                            self.db.clear_agent_penalty(identity_db_id, ac_run_id)
                    except Exception:
                        pass

                    resolved += 1

            if resolved > 0:
                self.db.conn.commit()
                logger.info("Auto-resolved %d orphan findings", resolved)

        except Exception as e:
            logger.error("auto_resolve failed: %s", e)
            try:
                self.db.conn.rollback()
            except Exception:
                pass
        finally:
            cursor.close()

        return resolved

    # ── Detection query ────────────────────────────────────────────────

    def _detect_orphaned_agents(self, run_id: int) -> List[Dict]:
        """Query for orphaned AI agent SPNs in a discovery run."""
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("""
                WITH agent_spns AS (
                    SELECT
                        i.id AS identity_db_id,
                        i.identity_id,
                        i.display_name,
                        i.last_sign_in,
                        i.enabled,
                        i.deleted_at,
                        ac.agent_identity_type,
                        ac.detected_platform,
                        ac.last_service_principal_sign_in
                    FROM identities i
                    JOIN agent_classifications ac ON ac.identity_db_id = i.id
                    WHERE i.discovery_run_id = %s
                      AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
                      AND COALESCE(i.enabled, true) = true
                      AND i.deleted_at IS NULL
                      AND NOT COALESCE(i.is_microsoft_system, false)
                ),
                agent_roles AS (
                    SELECT
                        a.identity_db_id,
                        array_agg(DISTINCT ra.role_name) AS rbac_roles
                    FROM agent_spns a
                    JOIN role_assignments ra ON ra.identity_db_id = a.identity_db_id
                    GROUP BY a.identity_db_id
                )
                SELECT
                    a.identity_db_id,
                    a.identity_id,
                    a.display_name,
                    a.last_sign_in,
                    a.agent_identity_type,
                    a.detected_platform,
                    COALESCE(ar.rbac_roles, ARRAY[]::TEXT[]) AS rbac_roles,
                    a.last_service_principal_sign_in
                FROM agent_spns a
                LEFT JOIN agent_roles ar ON ar.identity_db_id = a.identity_db_id
            """, (run_id,))

            orphans = []
            now = datetime.now(timezone.utc)

            for row in cursor.fetchall():
                (identity_db_id, identity_id, display_name,
                 last_sign_in, agent_type, detected_platform, rbac_roles,
                 last_sp_sign_in) = row

                # Compute effective last activity using whichever is more recent
                interactive_sign_in = last_sign_in
                sp_sign_in = last_sp_sign_in

                candidates = [t for t in [interactive_sign_in, sp_sign_in] if t is not None]
                last_active = max(candidates) if candidates else None

                if last_active is None:
                    days_inactive = None  # never signed in via any method
                else:
                    days_inactive = (now - last_active).days

                # Determine which source was used (for audit trail)
                activity_source = (
                    "service_principal_sign_in" if sp_sign_in and sp_sign_in == last_active
                    else "interactive_sign_in" if interactive_sign_in and interactive_sign_in == last_active
                    else "no_activity_recorded"
                )

                # Apply orphan criteria via static method
                if self.is_orphaned(
                    agent_type, days_inactive, True, None, rbac_roles
                ):
                    orphans.append({
                        'identity_db_id': identity_db_id,
                        'identity_id': identity_id,
                        'display_name': display_name,
                        'detected_platform': detected_platform,
                        'days_inactive': days_inactive if days_inactive is not None else 999,
                        'rbac_roles': list(rbac_roles) if rbac_roles else [],
                        'activity_detection_source': activity_source,
                        'last_interactive_sign_in': interactive_sign_in,
                        'last_service_principal_sign_in': sp_sign_in,
                        'effective_last_active': last_active,
                    })

            return orphans
        finally:
            cursor.close()

    # ── Static helpers (pure functions, testable without DB) ───────────

    @staticmethod
    def is_orphaned(agent_identity_type, days_inactive, enabled, deleted_at, rbac_roles):
        """Evaluate all 5 orphan criteria. Pure function.

        Args:
            agent_identity_type: 'ai_agent', 'possible_ai_agent', or 'unknown'
            days_inactive: int (days since last sign-in) or None (never signed in)
            enabled: bool
            deleted_at: datetime or None
            rbac_roles: list of role name strings

        Returns:
            True if identity meets ALL orphan criteria.
        """
        # 1. Must be classified as agent
        if agent_identity_type not in ('ai_agent', 'possible_ai_agent'):
            return False

        # 2. Must be inactive > ORPHAN_INACTIVE_DAYS (None = never signed in = orphan)
        if days_inactive is not None and days_inactive <= ORPHAN_INACTIVE_DAYS:
            return False

        # 3. Must still be enabled
        if not enabled:
            return False

        # 4. Must not be deleted
        if deleted_at is not None:
            return False

        # 5. Must hold at least one elevated role
        if not AgentOrphanDetector._has_elevated_role(rbac_roles):
            return False

        return True

    @staticmethod
    def _has_elevated_role(rbac_roles):
        """Check if any role is elevated (named role or custom write role).

        Returns True if at least one role is in _ELEVATED_RBAC_ROLES or
        contains a write-indicating token.
        """
        if not rbac_roles:
            return False

        for role in rbac_roles:
            # Check named elevated roles
            if role in _ELEVATED_RBAC_ROLES:
                return True
            # Check custom roles with write tokens
            role_lower = role.lower()
            for token in _WRITE_ROLE_TOKENS:
                if token in role_lower:
                    return True

        return False

    @staticmethod
    def _build_finding(entity_id, display_name, detected_platform,
                       days_inactive, rbac_roles, identity_db_id=None,
                       activity_detection_source='no_activity_recorded',
                       last_interactive_sign_in=None,
                       last_service_principal_sign_in=None,
                       effective_last_active=None):
        """Produce a finding dict compatible with save_security_findings()."""
        inactive_desc = f'{days_inactive} days' if days_inactive != 999 else 'never signed in'
        roles_str = ', '.join(rbac_roles[:5]) if rbac_roles else 'elevated roles'

        return {
            'finding_type': FINDING_TYPE,
            'entity_type': 'service_principal',
            'entity_id': entity_id,
            'severity': 'critical',
            'risk_score': 90,
            'title': f'Orphaned AI agent SPN: {display_name}',
            'description': (
                f'AI agent SPN "{display_name}" is orphaned — inactive for '
                f'{inactive_desc} but still enabled with elevated permissions '
                f'({roles_str}). Decommissioned agents with standing access '
                f'pose a lateral movement risk.'
            ),
            'recommended_fix': (
                'Disable the service principal in Entra ID and remove elevated '
                'role assignments. If the agent is decommissioned, delete the SPN.'
            ),
            'metadata': {
                'finding_code': FINDING_CODE,
                'display_name': display_name,
                'detected_platform': detected_platform,
                'days_inactive': days_inactive,
                'rbac_roles': rbac_roles,
                'agirs_penalty': AGIRS_PENALTY_SCORE,
                'category': 'AI Agent Governance',
                'recommended_action': 'disable_spn',
                'activity_detection_source': activity_detection_source,
                'last_interactive_sign_in': (
                    last_interactive_sign_in.isoformat()
                    if last_interactive_sign_in else None
                ),
                'last_service_principal_sign_in': (
                    last_service_principal_sign_in.isoformat()
                    if last_service_principal_sign_in else None
                ),
                'effective_last_active': (
                    effective_last_active.isoformat()
                    if effective_last_active else None
                ),
            },
            'finding_fingerprint': compute_finding_fingerprint(
                entity_id, FINDING_TYPE
            ),
            'identity_name': display_name,
        }
