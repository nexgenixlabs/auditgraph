"""
SnapshotCaptureService — copies live Phase 3 projection tables into
their ``_snapshots`` counterparts for a given organization, then
flips the ``snapshots`` catalogue row to ``status='complete'``.

Called as a FastAPI background task from
``app/api/routes/snapshots.py:capture_snapshot``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

# (live_table, snapshot_table, columns_without_org_and_identity)
# Every pair shares (organization_id, identity_id); the snapshot
# twin adds snapshot_id. We list only the *extra* payload columns.
_TABLE_PAIRS: list[Tuple[str, str, list[str]]] = [
    (
        "identity_list",
        "identity_list_snapshots",
        [
            "global_identity_id",
            "display_name",
            "identity_type",
            "cloud_provider",
            "risk_label",
            "risk_score",
            "governance",
            "lifecycle_state",
            "is_dormant",
            "privilege_level",
            "last_seen",
            "env_tier",
        ],
    ),
    (
        "identity_activity",
        "identity_activity_snapshots",
        [
            "lifecycle_state",
            "last_sign_in_at",
            "last_activity_at",
            "activity_confidence",
            "has_p2_telemetry",
        ],
    ),
    (
        "identity_owners",
        "identity_owners_snapshots",
        [
            "owner_id",
            "owner_name",
            "owner_type",
            "last_active_days",
            "has_reviewed",
            "last_review_at",
        ],
    ),
    (
        "identity_privilege_summary",
        "identity_privilege_summary_snapshots",
        [
            "privilege_level",
            "scope_breadth",
            "highly_privileged_role_count",
            "privileged_role_count",
            "standard_role_count",
            "total_role_count",
            "can_escalate",
            "blast_radius_resource_count",
        ],
    ),
    (
        "identity_credentials",
        "identity_credentials_snapshots",
        [
            "credential_key",
            "rotation_status",
            "rotation_status_priority",
        ],
    ),
    (
        "identity_role_assignments",
        "identity_role_assignments_snapshots",
        [
            "role_key",
            "role_name",
            "scope",
            "scope_level",
            "source",
            "usage_used",
            "usage_confidence",
            "usage_evidence",
        ],
    ),
    (
        "identity_attack_paths",
        "identity_attack_paths_snapshots",
        [
            "path_id",
            "path_type",
            "source_identity_uuid",
            "target_resource_id",
            "target_global_identity_id",
            "target_cloud_id",
            "target_type",
            "target_name",
            "target_sensitivity",
            "severity",
            "score",
            "chain",
            "mitre_techniques",
        ],
    ),
]

# resources table uses 'id' instead of 'identity_id'
_RESOURCE_PAIR = (
    "resources",
    "resource_snapshots",
    [
        "id",
        "global_identity_id",
        "cloud_id",
        "cloud_provider",
        "type",
        "name",
        "sensitivity",
    ],
)


class SnapshotCaptureService:
    """Stateless service — instantiated per capture request."""

    async def run_capture(
        self,
        *,
        organization_id: str,
        snapshot_id: int,
        triggered_by: str = "manual",
    ) -> None:
        """Copy live tables → snapshot tables, update catalogue row."""
        # Lazy import to avoid circular dependency at module level
        from app.api.deps import _async_session_factory

        org_int = int(organization_id)
        total_identities = 0

        session = _async_session_factory()
        try:
            # -- identity-keyed tables --
            for live, snap, extra_cols in _TABLE_PAIRS:
                copied = await self._copy_table(
                    session,
                    live_table=live,
                    snap_table=snap,
                    extra_cols=extra_cols,
                    org_id=org_int,
                    snapshot_id=snapshot_id,
                    id_col="identity_id",
                )
                if live == "identity_list":
                    total_identities = copied
                logger.info(
                    "snapshot.copy org=%s snap=%s %s → %s rows=%d",
                    org_int,
                    snapshot_id,
                    live,
                    snap,
                    copied,
                )

            # -- resources (uses 'id' not 'identity_id') --
            live_r, snap_r, extra_r = _RESOURCE_PAIR
            copied_r = await self._copy_resources(
                session,
                org_id=org_int,
                snapshot_id=snapshot_id,
            )
            logger.info(
                "snapshot.copy org=%s snap=%s resources → resource_snapshots rows=%d",
                org_int,
                snapshot_id,
                copied_r,
            )

            # -- update catalogue --
            await session.execute(
                text(
                    """
                    UPDATE snapshots
                       SET status = 'complete',
                           identity_count = :cnt
                     WHERE id = :sid AND organization_id = :org
                    """
                ),
                {"cnt": total_identities, "sid": snapshot_id, "org": org_int},
            )
            await session.commit()
            logger.info(
                "snapshot.capture_complete org=%s snapshot_id=%s identities=%d",
                org_int,
                snapshot_id,
                total_identities,
            )

        except Exception:
            logger.exception(
                "snapshot.capture_failed org=%s snapshot_id=%s",
                org_int,
                snapshot_id,
            )
            try:
                await session.rollback()
            except SQLAlchemyError:
                pass
            # Mark as failed so the UI doesn't poll forever
            try:
                await session.execute(
                    text(
                        """
                        UPDATE snapshots
                           SET status = 'failed'
                         WHERE id = :sid AND organization_id = :org
                        """
                    ),
                    {"sid": snapshot_id, "org": org_int},
                )
                await session.commit()
            except SQLAlchemyError:
                pass
        finally:
            await session.close()

    # ------------------------------------------------------------------

    async def _copy_table(
        self,
        session: Any,
        *,
        live_table: str,
        snap_table: str,
        extra_cols: list[str],
        org_id: int,
        snapshot_id: int,
        id_col: str = "identity_id",
    ) -> int:
        """INSERT INTO snap SELECT … FROM live WHERE org = :org."""
        all_cols = ["organization_id", id_col] + extra_cols
        src_select = ", ".join(all_cols)
        dst_cols = ", ".join(["organization_id", id_col, "snapshot_id"] + extra_cols)
        src_with_snap = ", ".join(
            [f"organization_id", f"{id_col}", f":snap AS snapshot_id"] + extra_cols
        )

        sql = f"""
            INSERT INTO {snap_table} ({dst_cols})
            SELECT {src_with_snap}
              FROM {live_table}
             WHERE organization_id = :org
        """
        result = await session.execute(
            text(sql), {"org": org_id, "snap": snapshot_id}
        )
        return result.rowcount or 0

    async def _copy_resources(
        self,
        session: Any,
        *,
        org_id: int,
        snapshot_id: int,
    ) -> int:
        """Copy resources → resource_snapshots."""
        sql = """
            INSERT INTO resource_snapshots
                (organization_id, id, snapshot_id,
                 global_identity_id, cloud_id, cloud_provider,
                 type, name, sensitivity)
            SELECT
                organization_id, id, :snap,
                global_identity_id, cloud_id, cloud_provider,
                type, name, sensitivity
            FROM resources
            WHERE organization_id = :org
        """
        result = await session.execute(
            text(sql), {"org": org_id, "snap": snapshot_id}
        )
        return result.rowcount or 0
