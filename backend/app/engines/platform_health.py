"""
AuditGraph — Platform Health Engine (Phase 8)

Evaluates tenant health, records discovery integrity metrics, and detects
silent discovery regressions.  SELECT-only against upstream tables.
"""

import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Safety thresholds (Part 9) ────────────────────────────────────────
MAX_JOB_RUNTIME_MS = 600_000      # 10 minutes
MAX_SNAPSHOT_AGE_HOURS = 48        # stale after 48 h
MAX_JOB_FAILURE_RATE = 0.25       # 25 %
INTEGRITY_DROP_THRESHOLD = 0.50   # 50 % drop → warning

# ── Valid constants ───────────────────────────────────────────────────
VALID_JOB_TYPES = (
    'discovery', 'security_findings', 'attack_paths',
    'fix_recommendations', 'blast_radius', 'access_reviews',
    'report_generation',
)

VALID_JOB_STATUSES = ('queued', 'running', 'completed', 'failed')
VALID_HEALTH_STATUSES = ('healthy', 'warning', 'stale')


class PlatformHealthEngine:
    """Evaluates tenant health and discovery integrity."""

    def __init__(self, db):
        self.db = db

    # ── Part 5: Tenant health evaluation ─────────────────────────────
    def evaluate_tenant_health(self, organization_id: int) -> dict:
        """Compute health snapshot for a single tenant after pipeline run."""
        cursor = self.db.conn.cursor()

        # 1. Last completed discovery run
        cursor.execute("""
            SELECT MAX(completed_at) FROM discovery_runs
            WHERE organization_id = %s AND status = 'completed'
        """, (organization_id,))
        row = cursor.fetchone()
        last_run = row[0] if row else None

        # 2. Snapshot age
        snapshot_age_hours = 999
        if last_run:
            delta = datetime.now(timezone.utc) - last_run.replace(tzinfo=timezone.utc) \
                if last_run.tzinfo is None else datetime.now(timezone.utc) - last_run
            snapshot_age_hours = int(delta.total_seconds() / 3600)

        # 3. Findings count (latest run)
        cursor.execute("""
            SELECT COUNT(*) FROM security_findings
            WHERE organization_id = %s AND status = 'open'
        """, (organization_id,))
        findings_count = cursor.fetchone()[0] or 0

        # 4. Critical risks (identities)
        cursor.execute("""
            SELECT COUNT(*) FROM identities i
            JOIN discovery_runs dr ON dr.id = i.discovery_run_id
            WHERE dr.organization_id = %s AND i.risk_level = 'critical'
        """, (organization_id,))
        critical_risks = cursor.fetchone()[0] or 0

        # 5. Blast radius critical
        cursor.execute("""
            SELECT COUNT(*) FROM blast_radius_results
            WHERE organization_id = %s AND risk_level = 'critical'
        """, (organization_id,))
        blast_radius_critical = cursor.fetchone()[0] or 0

        cursor.close()

        # 6. Determine status
        if snapshot_age_hours < 24:
            status = 'healthy'
        elif snapshot_age_hours < MAX_SNAPSHOT_AGE_HOURS:
            status = 'warning'
        else:
            status = 'stale'

        return {
            'organization_id': organization_id,
            'last_discovery_run': last_run.isoformat() if last_run else None,
            'snapshot_age_hours': snapshot_age_hours,
            'findings_count': findings_count,
            'critical_risks': critical_risks,
            'blast_radius_critical': blast_radius_critical,
            'integrity_warning': False,
            'status': status,
        }

    # ── Part 6: Data integrity monitor ───────────────────────────────
    def check_discovery_integrity(self, organization_id: int,
                                  current_run_id: int) -> dict:
        """Compare current discovery counts against previous run.
        Returns integrity metrics + warning flag.
        """
        cursor = self.db.conn.cursor()

        # Current run counts
        cursor.execute("""
            SELECT COUNT(*) FROM identities
            WHERE discovery_run_id = %s
        """, (current_run_id,))
        identities_count = cursor.fetchone()[0] or 0

        cursor.execute("""
            SELECT
                COALESCE(SUM(
                    CASE WHEN azure_storage_accounts.id IS NOT NULL THEN 1 ELSE 0 END
                ), 0) +
                COALESCE(SUM(
                    CASE WHEN azure_key_vaults.id IS NOT NULL THEN 1 ELSE 0 END
                ), 0)
            FROM (SELECT 1) AS dummy
            LEFT JOIN azure_storage_accounts ON azure_storage_accounts.discovery_run_id = %s
            LEFT JOIN azure_key_vaults ON azure_key_vaults.discovery_run_id = %s
        """, (current_run_id, current_run_id))
        # Simplified resource count
        cursor.execute("""
            SELECT
                (SELECT COUNT(*) FROM azure_storage_accounts WHERE discovery_run_id = %s) +
                (SELECT COUNT(*) FROM azure_key_vaults WHERE discovery_run_id = %s)
        """, (current_run_id, current_run_id))
        resources_count = cursor.fetchone()[0] or 0

        cursor.execute("""
            SELECT COUNT(*) FROM role_assignments
            WHERE discovery_run_id = %s
        """, (current_run_id,))
        role_assignments_count = cursor.fetchone()[0] or 0

        # Previous run metrics
        cursor.execute("""
            SELECT identities_count, resources_count, role_assignments_count
            FROM discovery_integrity_metrics
            WHERE organization_id = %s AND discovery_run_id < %s
            ORDER BY discovery_run_id DESC LIMIT 1
        """, (organization_id, current_run_id))
        prev = cursor.fetchone()
        cursor.close()

        integrity_warning = False
        warnings = []

        if prev:
            prev_identities, prev_resources, prev_roles = prev
            if prev_identities and prev_identities > 0:
                drop = 1 - (identities_count / prev_identities)
                if drop > INTEGRITY_DROP_THRESHOLD:
                    integrity_warning = True
                    warnings.append(
                        f"identities dropped {drop:.0%} ({prev_identities}→{identities_count})"
                    )
            if prev_resources and prev_resources > 0:
                drop = 1 - (resources_count / prev_resources)
                if drop > INTEGRITY_DROP_THRESHOLD:
                    integrity_warning = True
                    warnings.append(
                        f"resources dropped {drop:.0%} ({prev_resources}→{resources_count})"
                    )
            if prev_roles and prev_roles > 0:
                drop = 1 - (role_assignments_count / prev_roles)
                if drop > INTEGRITY_DROP_THRESHOLD:
                    integrity_warning = True
                    warnings.append(
                        f"role_assignments dropped {drop:.0%} ({prev_roles}→{role_assignments_count})"
                    )

        return {
            'organization_id': organization_id,
            'discovery_run_id': current_run_id,
            'identities_count': identities_count,
            'resources_count': resources_count,
            'role_assignments_count': role_assignments_count,
            'integrity_warning': integrity_warning,
            'warnings': warnings,
        }
