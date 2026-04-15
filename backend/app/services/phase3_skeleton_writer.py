"""
Phase3SkeletonWriter — populate Phase 3 builder input tables from discovery.

Translates Azure discovery output into the skeleton tables that the Phase 3
builders read:

* ``identity_activity``          — B02 ActivityBuilder
* ``identity_role_assignments``  — B07 RolesLoader
* ``identity_privilege_summary`` — B05 PrivilegeBuilder
* ``identity_list``              — route projection for GET /api/v1/identities

Design rules
------------
* **Sync DB** — uses the same :class:`Database` (psycopg2) that the
  discovery pipeline owns.
* **Idempotent** — every row upserts on the table's natural key. Re-running
  produces the same state.
* **Error-isolated** — failures are logged and swallowed. A broken writer
  must never abort discovery.
* **Zero rows on no-logs tenants** — ``identity_activity`` may have zero
  rows if the Azure tenant has no sign-in logs (common on free-tier).
  This is expected behavior, not an error.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Privilege classification constants
# ---------------------------------------------------------------------------

#: Azure RBAC role names classified as highly-privileged.
_HIGHLY_PRIVILEGED_ROLES: frozenset[str] = frozenset({
    "owner",
    "user access administrator",
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "exchange administrator",
    "sharepoint administrator",
    "intune administrator",
    "cloud application administrator",
    "application administrator",
})

#: Azure RBAC role names classified as privileged (but not highly).
_PRIVILEGED_ROLES: frozenset[str] = frozenset({
    "contributor",
    "key vault administrator",
    "storage blob data owner",
    "storage blob data contributor",
    "virtual machine contributor",
    "network contributor",
    "sql server contributor",
    "sql db contributor",
    "managed identity contributor",
    "role based access control administrator",
})


# ---------------------------------------------------------------------------
# Phase3SkeletonWriter
# ---------------------------------------------------------------------------


class Phase3SkeletonWriter:
    """Populate Phase 3 builder skeleton tables from Azure discovery output.

    Parameters
    ----------
    organization_id:
        Owning tenant (integer).
    cloud_connection_id:
        ``cloud_connections.id`` for this connection.
    db:
        Sync :class:`Database` instance (caller-owned).
    """

    def __init__(
        self,
        organization_id: int,
        cloud_connection_id: int,
        db: Any,
    ) -> None:
        if organization_id is None:
            raise ValueError("organization_id is required")
        if cloud_connection_id is None:
            raise ValueError("cloud_connection_id is required")
        if db is None:
            raise ValueError("db (Database) is required")
        self._org_id = int(organization_id)
        self._conn_id = int(cloud_connection_id)
        self._db = db

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def write_from_discovery(
        self,
        final_identities: list[dict[str, Any]],
        *,
        discovery_run_id: Optional[int] = None,
    ) -> dict[str, int]:
        """Populate all skeleton tables from a completed discovery run.

        Returns a summary dict with row counts per table.
        """
        _start = time.perf_counter()
        summary = {
            "identity_role_assignments": 0,
            "identity_activity": 0,
            "identity_privilege_summary": 0,
            "identity_list": 0,
        }

        try:
            summary["identity_role_assignments"] = self._write_role_assignments(
                final_identities
            )
            summary["identity_activity"] = self._write_activity(
                final_identities
            )
            summary["identity_privilege_summary"] = self._write_privilege_summary(
                final_identities
            )
            summary["identity_list"] = self._write_identity_list(
                final_identities
            )
            self._db.safe_commit()

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "phase3_skeleton_writer: write_from_discovery failed "
                "org=%s conn=%s err=%s",
                self._org_id,
                self._conn_id,
                exc,
            )
            try:
                self._db._rollback()
            except Exception:  # noqa: BLE001
                pass
            return summary

        elapsed = (time.perf_counter() - _start) * 1000

        # ── Emit warnings for zero-row tables ──
        warnings: list[str] = []
        if summary["identity_list"] == 0:
            warnings.append(
                "identity_list produced 0 rows — Phase 3 list endpoint will "
                "return empty results for org %s" % self._org_id
            )
        if summary["identity_role_assignments"] == 0 and summary["identity_list"] > 0:
            warnings.append(
                "identity_role_assignments produced 0 rows — role data "
                "may be missing from discovery results"
            )
        if summary["identity_activity"] == 0 and summary["identity_list"] > 0:
            warnings.append(
                "identity_activity produced 0 rows — lifecycle state "
                "inference will rely on heuristics only"
            )
        for w in warnings:
            logger.warning("phase3_skeleton_writer: %s", w)
        summary["warnings"] = warnings

        logger.info(
            "phase3_skeleton_writer: completed org=%s conn=%s "
            "roles=%d activity=%d privilege=%d list=%d in %.1fms",
            self._org_id,
            self._conn_id,
            summary["identity_role_assignments"],
            summary["identity_activity"],
            summary["identity_privilege_summary"],
            summary["identity_list"],
            elapsed,
        )
        return summary

    # ------------------------------------------------------------------
    # identity_role_assignments (B07 RolesLoader input)
    # ------------------------------------------------------------------

    def _write_role_assignments(
        self, identities: list[dict[str, Any]]
    ) -> int:
        """Populate identity_role_assignments from discovery role data.

        Upserts on (organization_id, identity_id, role_key, scope).
        """
        count = 0
        cursor = self._db.conn.cursor()

        for ident in identities:
            iid = ident.get("identity_id")
            if not iid:
                continue

            confidence = self._derive_confidence(ident)

            # Azure RBAC roles
            for role in ident.get("roles", []):
                role_name = role.get("role_name")
                scope = role.get("scope", "")
                if not role_name:
                    continue

                role_key = role_name.lower().replace(" ", "_")
                scope_level = _derive_scope_level(role.get("scope_type") or scope)
                usage_used = role.get("usage_status", "") == "active"

                try:
                    cursor.execute(
                        """
                        INSERT INTO identity_role_assignments
                            (organization_id, identity_id, role_key, role_name,
                             scope, scope_level, source, usage_used,
                             usage_confidence, usage_evidence)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (organization_id, identity_id, role_key, scope)
                        DO UPDATE SET
                            role_name        = EXCLUDED.role_name,
                            scope_level      = EXCLUDED.scope_level,
                            usage_used       = EXCLUDED.usage_used,
                            usage_confidence = EXCLUDED.usage_confidence,
                            usage_evidence   = EXCLUDED.usage_evidence
                        """,
                        (
                            self._org_id,
                            iid,
                            role_key,
                            role_name,
                            scope,
                            scope_level,
                            "azure_rbac",
                            usage_used,
                            confidence,
                            role.get("usage_status", ""),
                        ),
                    )
                    count += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "phase3_skeleton_writer: role_assignment upsert failed "
                        "identity=%s role=%s err=%s",
                        iid[:30],
                        role_name,
                        exc,
                    )
                    try:
                        self._db._rollback()
                    except Exception:  # noqa: BLE001
                        pass

            # Entra directory roles
            for role in ident.get("entra_roles", []):
                role_name = role.get("role_name")
                if not role_name:
                    continue

                role_key = f"entra:{role_name.lower().replace(' ', '_')}"
                scope = role.get("directory_scope", "/")

                try:
                    cursor.execute(
                        """
                        INSERT INTO identity_role_assignments
                            (organization_id, identity_id, role_key, role_name,
                             scope, scope_level, source, usage_used,
                             usage_confidence, usage_evidence)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (organization_id, identity_id, role_key, scope)
                        DO UPDATE SET
                            role_name        = EXCLUDED.role_name,
                            usage_used       = EXCLUDED.usage_used,
                            usage_confidence = EXCLUDED.usage_confidence,
                            usage_evidence   = EXCLUDED.usage_evidence
                        """,
                        (
                            self._org_id,
                            iid,
                            role_key,
                            role_name,
                            scope,
                            "tenant_wide",
                            "azure_rbac",
                            role.get("usage_status", "") == "active",
                            confidence,
                            role.get("usage_status", ""),
                        ),
                    )
                    count += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "phase3_skeleton_writer: entra_role upsert failed "
                        "identity=%s role=%s err=%s",
                        iid[:30],
                        role_name,
                        exc,
                    )
                    try:
                        self._db._rollback()
                    except Exception:  # noqa: BLE001
                        pass

        cursor.close()
        return count

    # ------------------------------------------------------------------
    # identity_activity (B02 ActivityBuilder input)
    # ------------------------------------------------------------------

    def _write_activity(
        self, identities: list[dict[str, Any]]
    ) -> int:
        """Populate identity_activity from discovery activity signals.

        Upserts on (organization_id, identity_id).

        If the Azure tenant has no sign-in logs (common on free-tier),
        the writer runs cleanly and writes zero rows. AuditGraph delivers
        full Tier 1 analysis without activity logs.
        """
        count = 0
        cursor = self._db.conn.cursor()

        for ident in identities:
            iid = ident.get("identity_id")
            if not iid:
                continue

            # Derive activity fields from discovery output
            last_sign_in = ident.get("last_sign_in") or ident.get("last_sign_in_at")
            last_activity = (
                ident.get("last_activity_at")
                or ident.get("last_activity_date")
                or last_sign_in
            )

            # Skip if no activity data at all — the builder handles
            # missing rows gracefully (State 0 / data_source=NONE).
            # We only write rows when we have at least one signal.
            has_any_signal = last_sign_in is not None or last_activity is not None

            # Determine lifecycle state
            lifecycle_state = _derive_lifecycle_state(
                ident, last_sign_in, last_activity
            )

            # Determine confidence
            has_p2 = bool(ident.get("has_p2_telemetry", False))
            if has_p2:
                confidence = "high"
            elif has_any_signal:
                confidence = "medium"
            else:
                confidence = "none"

            # Normalize timestamps
            last_sign_in_ts = _to_timestamp(last_sign_in)
            last_activity_ts = _to_timestamp(last_activity)

            # Write even for no-signal identities so the builder can
            # distinguish "we scanned and found nothing" from "never scanned"
            try:
                cursor.execute(
                    """
                    INSERT INTO identity_activity
                        (organization_id, identity_id, lifecycle_state,
                         last_sign_in_at, last_activity_at,
                         activity_confidence, has_p2_telemetry, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (organization_id, identity_id)
                    DO UPDATE SET
                        lifecycle_state     = EXCLUDED.lifecycle_state,
                        last_sign_in_at     = EXCLUDED.last_sign_in_at,
                        last_activity_at    = EXCLUDED.last_activity_at,
                        activity_confidence = EXCLUDED.activity_confidence,
                        has_p2_telemetry    = EXCLUDED.has_p2_telemetry,
                        updated_at          = NOW()
                    """,
                    (
                        self._org_id,
                        iid,
                        lifecycle_state,
                        last_sign_in_ts,
                        last_activity_ts,
                        confidence,
                        has_p2,
                    ),
                )
                count += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "phase3_skeleton_writer: activity upsert failed "
                    "identity=%s err=%s",
                    iid[:30],
                    exc,
                )
                try:
                    self._db._rollback()
                except Exception:  # noqa: BLE001
                    pass

        cursor.close()
        return count

    # ------------------------------------------------------------------
    # identity_privilege_summary (B05 PrivilegeBuilder input)
    # ------------------------------------------------------------------

    def _write_privilege_summary(
        self, identities: list[dict[str, Any]]
    ) -> int:
        """Derive and populate identity_privilege_summary from role data.

        Upserts on (organization_id, identity_id).
        """
        count = 0
        cursor = self._db.conn.cursor()

        for ident in identities:
            iid = ident.get("identity_id")
            if not iid:
                continue

            all_roles = list(ident.get("roles", []))
            all_roles.extend(ident.get("entra_roles", []))

            if not all_roles:
                continue

            # Classify roles
            highly_priv = 0
            priv = 0
            standard = 0
            widest_scope = "resource"
            can_escalate = False

            for role in all_roles:
                rn = (role.get("role_name") or "").lower()
                if rn in _HIGHLY_PRIVILEGED_ROLES:
                    highly_priv += 1
                elif rn in _PRIVILEGED_ROLES:
                    priv += 1
                else:
                    standard += 1

                # Determine scope breadth
                st = role.get("scope_type", "")
                if st == "subscription" or role.get("directory_scope") == "/":
                    widest_scope = _wider_scope(widest_scope, "subscription")
                elif st == "resource_group":
                    widest_scope = _wider_scope(widest_scope, "resource_group")

                # Check for escalation roles
                if rn in {"user access administrator", "owner",
                           "privileged role administrator"}:
                    can_escalate = True

            # Determine overall privilege level
            if highly_priv > 0:
                privilege_level = "highly_privileged"
            elif priv > 0:
                privilege_level = "privileged"
            else:
                privilege_level = "standard"

            # Entra directory-level roles → tenant_wide scope
            for role in ident.get("entra_roles", []):
                if role.get("directory_scope") == "/":
                    widest_scope = "tenant_wide"
                    break

            total = highly_priv + priv + standard

            try:
                cursor.execute(
                    """
                    INSERT INTO identity_privilege_summary
                        (organization_id, identity_id, privilege_level,
                         scope_breadth, highly_privileged_role_count,
                         privileged_role_count, standard_role_count,
                         total_role_count, can_escalate,
                         blast_radius_resource_count)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0)
                    ON CONFLICT (organization_id, identity_id)
                    DO UPDATE SET
                        privilege_level              = EXCLUDED.privilege_level,
                        scope_breadth                = EXCLUDED.scope_breadth,
                        highly_privileged_role_count  = EXCLUDED.highly_privileged_role_count,
                        privileged_role_count         = EXCLUDED.privileged_role_count,
                        standard_role_count           = EXCLUDED.standard_role_count,
                        total_role_count              = EXCLUDED.total_role_count,
                        can_escalate                  = EXCLUDED.can_escalate
                    """,
                    (
                        self._org_id,
                        iid,
                        privilege_level,
                        widest_scope,
                        highly_priv,
                        priv,
                        standard,
                        total,
                        can_escalate,
                    ),
                )
                count += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "phase3_skeleton_writer: privilege_summary upsert failed "
                    "identity=%s err=%s",
                    iid[:30],
                    exc,
                )
                try:
                    self._db._rollback()
                except Exception:  # noqa: BLE001
                    pass

        cursor.close()
        return count

    # ------------------------------------------------------------------
    # identity_list (route projection for GET /api/v1/identities)
    # ------------------------------------------------------------------

    def _write_identity_list(
        self, identities: list[dict[str, Any]]
    ) -> int:
        """Populate identity_list — the projection table behind the list endpoint.

        Upserts on (organization_id, identity_id).
        """
        count = 0
        cursor = self._db.conn.cursor()

        for ident in identities:
            iid = ident.get("identity_id")
            if not iid:
                continue

            gid = ident.get("global_identity_id")
            if not gid:
                # Use a deterministic UUID from the identity_id
                import uuid
                gid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"auditgraph:{iid}"))

            identity_type = _map_category_to_type(
                ident.get("identity_category", "service_principal")
            )
            risk_level = ident.get("risk_level", "low")
            risk_label = _capitalize_risk(risk_level)
            risk_score = float(ident.get("risk_score", 0) or 0)

            # Derive governance from ownership/review data via SSOT service
            from app.services.governance_service import (
                derive_governance_state,
                _resolve_privilege_tier_int,
            )
            _priv_tier = _resolve_privilege_tier_int(
                ident.get("privilege_tier")
            )
            governance = derive_governance_state(ident, _priv_tier)

            # Derive lifecycle
            last_activity = (
                ident.get("last_activity_at")
                or ident.get("last_activity_date")
                or ident.get("last_sign_in")
            )
            lifecycle_state = _derive_lifecycle_state(
                ident, ident.get("last_sign_in"), last_activity
            )
            lifecycle_label = _capitalize_lifecycle(lifecycle_state)

            is_dormant = lifecycle_state in ("DORMANT", "Dormant")

            # Derive privilege level
            all_roles = list(ident.get("roles", []))
            all_roles.extend(ident.get("entra_roles", []))
            priv_level = "standard"
            for role in all_roles:
                rn = (role.get("role_name") or "").lower()
                if rn in _HIGHLY_PRIVILEGED_ROLES:
                    priv_level = "highly_privileged"
                    break
                if rn in _PRIVILEGED_ROLES:
                    priv_level = "privileged"

            last_seen_ts = _to_timestamp(last_activity)

            try:
                is_ms = bool(ident.get("is_microsoft_system", False))
                cursor.execute(
                    """
                    INSERT INTO identity_list
                        (organization_id, identity_id, global_identity_id,
                         display_name, identity_type, cloud_provider,
                         risk_label, risk_score, governance, lifecycle_state,
                         is_dormant, privilege_level, last_seen,
                         is_microsoft_system)
                    VALUES (%s, %s, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (organization_id, identity_id)
                    DO UPDATE SET
                        global_identity_id = EXCLUDED.global_identity_id,
                        display_name       = EXCLUDED.display_name,
                        identity_type      = EXCLUDED.identity_type,
                        risk_label         = EXCLUDED.risk_label,
                        risk_score         = EXCLUDED.risk_score,
                        governance         = EXCLUDED.governance,
                        lifecycle_state    = EXCLUDED.lifecycle_state,
                        is_dormant         = EXCLUDED.is_dormant,
                        privilege_level    = EXCLUDED.privilege_level,
                        last_seen          = EXCLUDED.last_seen,
                        is_microsoft_system = EXCLUDED.is_microsoft_system
                    """,
                    (
                        self._org_id,
                        iid,
                        str(gid),
                        ident.get("display_name", ""),
                        identity_type,
                        "azure",
                        risk_label,
                        risk_score,
                        governance,
                        lifecycle_label,
                        is_dormant,
                        priv_level,
                        last_seen_ts,
                        is_ms,
                    ),
                )
                count += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "phase3_skeleton_writer: identity_list upsert failed "
                    "identity=%s err=%s",
                    iid[:30],
                    exc,
                )
                try:
                    self._db._rollback()
                except Exception:  # noqa: BLE001
                    pass

        cursor.close()
        return count

    # ------------------------------------------------------------------
    # Confidence derivation (shared with Phase3GraphWriter)
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_confidence(identity: dict[str, Any]) -> str:
        """Derive usage_confidence from identity activity recency."""
        last_activity = (
            identity.get("last_activity_at")
            or identity.get("last_activity_date")
            or identity.get("last_sign_in")
        )
        if not last_activity:
            return "none"

        if isinstance(last_activity, str):
            try:
                last_activity = datetime.fromisoformat(
                    last_activity.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                return "none"

        if not isinstance(last_activity, datetime):
            return "none"

        now = datetime.now(timezone.utc)
        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)

        days = (now - last_activity).days
        if days <= 30:
            return "high"
        if days <= 90:
            return "medium"
        if days <= 180:
            return "low"
        return "none"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _derive_scope_level(scope_or_type: str) -> str:
    """Map an Azure scope string or scope_type to a ScopeBreadth value."""
    s = (scope_or_type or "").lower()
    if s in ("subscription", "tenant_wide"):
        return s
    if s == "resource_group":
        return "resource_group"
    if s == "resource":
        return "resource"
    # Infer from ARM path
    if "/resourcegroups/" in s.lower() and s.count("/") > 4:
        return "resource"
    if "/resourcegroups/" in s.lower():
        return "resource_group"
    if "/subscriptions/" in s.lower() and s.count("/") <= 3:
        return "subscription"
    return "resource"


def _derive_lifecycle_state(
    ident: dict[str, Any],
    last_sign_in: Any,
    last_activity: Any,
) -> str:
    """Derive lifecycle state from activity signals."""
    # Check explicit status
    status = (ident.get("status") or "").lower()
    if status == "disabled":
        return "Disabled"

    account_enabled = ident.get("account_enabled")
    if account_enabled is False:
        return "Disabled"

    # Check for activity
    if last_sign_in is None and last_activity is None:
        return "Provisioned"

    # Check how recent
    ref = _to_timestamp(last_activity or last_sign_in)
    if ref is None:
        return "Provisioned"

    now = datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)

    days = (now - ref).days
    if days <= 90:
        return "Active"
    if days <= 180:
        return "Active"
    return "Dormant"


def _to_timestamp(val: Any) -> Optional[datetime]:
    """Normalize a value to a timezone-aware datetime or None."""
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None
    return None


def _wider_scope(current: str, candidate: str) -> str:
    """Return the wider of two scope levels."""
    order = {"resource": 0, "resource_group": 1, "subscription": 2, "tenant_wide": 3}
    if order.get(candidate, 0) > order.get(current, 0):
        return candidate
    return current


def _map_category_to_type(category: str) -> str:
    """Map legacy identity_category to Phase 3 identity_type."""
    mapping = {
        "service_principal": "service_principal",
        "managed_identity_system": "managed_identity",
        "managed_identity_user": "managed_identity",
        "human_user": "human_user",
        "guest": "guest_user",
        "microsoft_internal": "service_principal",
        "user": "human_user",
    }
    return mapping.get(category, "service_principal")


def _capitalize_risk(level: str) -> str:
    """Convert risk_level to capitalized RiskLabel enum value."""
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    return mapping.get((level or "").lower(), "Low")


def _capitalize_lifecycle(state: str) -> str:
    """Ensure lifecycle state matches LifecycleState enum casing."""
    mapping = {
        "active": "Active",
        "dormant": "Dormant",
        "provisioned": "Provisioned",
        "disabled": "Disabled",
        "expired": "Expired",
    }
    return mapping.get((state or "").lower(), state)


__all__ = ["Phase3SkeletonWriter"]
