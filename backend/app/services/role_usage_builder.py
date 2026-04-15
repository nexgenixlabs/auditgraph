"""
RoleUsageBuilder
================

Canonical role-usage assembly for AuditGraph. This service replaces the
historical anti-pattern:

.. code-block:: python

    # OLD — fragile, key-mismatch prone, silent drop-outs
    role_usage_dict = {role_id: {"used": True, "confidence": "high"}}
    role.last_used_at = role_usage_dict.get(role.id, {}).get("used")

with a pattern where usage is **always** embedded on the assignment:

.. code-block:: python

    # NEW — usage is a first-class field, never None
    role.usage = RoleUsage(
        used=True,
        confidence=Confidence.HIGH,
        evidence="arm_activity_log@2026-04-08T12:00:00Z",
    )

Guarantees
----------
* Every returned :class:`RoleAssignment` has a fully populated
  :class:`RoleUsage` — never ``None``, even when there is zero evidence
  (fallback: ``Confidence.NONE`` with a descriptive ``evidence`` string).
* ``role_key`` is normalized to lowercase at the builder (never in the API
  layer) using a deterministic ``snake_case`` derivation from the role name.
* ``organization_id`` is threaded into every DB query — empty input is
  rejected up front.
* DB access is batched: one query per table regardless of how many roles
  the identity holds (no N+1).

Confidence policy (documented contract)
---------------------------------------
* **high**      — ARM activity log entry observed within
  :data:`USAGE_RECENT_DAYS` days *and* within the role's scope.
* **medium**    — ARM activity log exists but is older than
  :data:`USAGE_RECENT_DAYS` days OR falls outside the exact role scope.
* **low**       — an audit-log row exists but only as indirect evidence
  (e.g. a wider scope container activity).
* **inferred**  — no direct evidence, but the role name is in
  :data:`TYPICALLY_USED_ROLE_NAMES` (Owner / Contributor / Reader / …);
  used=False, surfaces as "probably exercised but unproven".
* **none**      — no evidence of any kind; used=False.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.identity import (
    Confidence,
    RoleAssignment,
    RoleSource,
    RoleUsage,
    ScopeBreadth,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunables — no magic numbers inline below this block
# ---------------------------------------------------------------------------


#: Any ARM activity within this many days is considered "recent" evidence.
USAGE_RECENT_DAYS: int = 30

#: Role names that are typically exercised in practice. When there is no
#: direct evidence, these roles are surfaced as ``inferred`` rather than
#: ``none`` to avoid under-flagging the audit picture.
TYPICALLY_USED_ROLE_NAMES: frozenset[str] = frozenset(
    {
        "owner",
        "contributor",
        "reader",
        "user_access_administrator",
        "security_admin",
    }
)

#: Provider-specific role-source default used when the DB row is missing a
#: ``source`` column. Azure is the only cloud that maps to a single source.
_PROVIDER_DEFAULT_ROLE_SOURCE: dict[str, RoleSource] = {
    "azure": RoleSource.AZURE_RBAC,
    "aws": RoleSource.AWS_IAM,
    "gcp": RoleSource.GCP_IAM,
}

#: Regex used to snake_case role names for ``role_key`` normalization.
_NON_WORD_RE: re.Pattern[str] = re.compile(r"[^a-z0-9]+")


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class RoleUsageBuilder:
    """Assemble :class:`RoleAssignment` lists with embedded :class:`RoleUsage`.

    The builder is intentionally stateless — pass a fresh :class:`AsyncSession`
    on every call. Batching is handled internally so that the DB sees at most
    two round-trips per identity regardless of role count.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def build_roles_with_usage(
        self,
        organization_id: str,
        identity_id: str,
        cloud_provider: str,
        db: AsyncSession,
    ) -> list[RoleAssignment]:
        """Fetch role assignments for an identity and embed usage signals.

        Contract / expected behaviour:

        * Role with ARM log evidence in-scope & recent  → ``used=True``,
          ``confidence=HIGH``.
        * Role with ARM log evidence older than the recency window or on a
          different scope → ``used=True``, ``confidence=MEDIUM``.
        * Role with only indirect audit evidence → ``used=False``,
          ``confidence=LOW``.
        * Role with no evidence whose name is in
          :data:`TYPICALLY_USED_ROLE_NAMES` → ``used=False``,
          ``confidence=INFERRED``.
        * Role with no evidence of any kind → ``used=False``,
          ``confidence=NONE``.
        * Empty role list → returns ``[]`` (never raises).

        Raises
        ------
        ValueError
            If ``organization_id`` / ``identity_id`` / ``db`` are missing.
        """
        self._require(organization_id, "organization_id")
        self._require(identity_id, "identity_id")
        self._require(cloud_provider, "cloud_provider")
        if db is None:
            raise ValueError("db (AsyncSession) is required")

        try:
            role_rows = await self._fetch_role_rows(
                organization_id=organization_id,
                identity_id=identity_id,
                db=db,
            )
        except SQLAlchemyError as exc:
            logger.error(
                "role_usage.fetch_roles failed org=%s identity=%s err=%s",
                organization_id,
                identity_id,
                exc,
            )
            raise

        if not role_rows:
            return []

        scopes = sorted({str(r["scope"] or "/") for r in role_rows})

        try:
            arm_by_scope = await self._fetch_arm_activity_batch(
                organization_id=organization_id,
                identity_id=identity_id,
                scopes=scopes,
                db=db,
            )
        except SQLAlchemyError as exc:
            logger.error(
                "role_usage.fetch_arm failed org=%s identity=%s err=%s",
                organization_id,
                identity_id,
                exc,
            )
            raise

        try:
            audit_by_scope = await self._fetch_audit_evidence_batch(
                organization_id=organization_id,
                identity_id=identity_id,
                scopes=scopes,
                db=db,
            )
        except SQLAlchemyError as exc:
            logger.error(
                "role_usage.fetch_audit failed org=%s identity=%s err=%s",
                organization_id,
                identity_id,
                exc,
            )
            raise

        assignments: list[RoleAssignment] = []
        for row in role_rows:
            if row.get("organization_id") != organization_id:
                # Defensive — should be impossible given the WHERE clause.
                logger.error(
                    "role_usage.scope_leak org=%s row_org=%s identity=%s",
                    organization_id,
                    row.get("organization_id"),
                    identity_id,
                )
                continue

            scope = str(row["scope"] or "/")
            role_name = str(row.get("role_name") or "unknown")
            role_key = self._normalize_role_key(row.get("role_key"), role_name)

            usage = self._derive_usage(
                organization_id=organization_id,
                role_name=role_name,
                scope=scope,
                arm_evidence=arm_by_scope.get(scope),
                audit_evidence=audit_by_scope.get(scope),
            )

            assignments.append(
                RoleAssignment(
                    organization_id=organization_id,
                    role_name=role_name,
                    role_key=role_key,
                    scope=scope,
                    scope_level=self._parse_scope_level(
                        row.get("scope_level"), cloud_provider
                    ),
                    source=self._parse_role_source(row.get("source"), cloud_provider),
                    usage=usage,
                )
            )

        logger.debug(
            "role_usage.build org=%s identity=%s roles=%d",
            organization_id,
            identity_id,
            len(assignments),
        )
        return assignments

    async def check_role_used_in_scope(
        self,
        organization_id: str,
        identity_id: str,
        role_scope: str,
        db: AsyncSession,
    ) -> tuple[bool, Confidence, str]:
        """Single-scope lookup against ARM activity logs.

        Thin wrapper around :meth:`_fetch_arm_activity_batch` intended for
        callers that already know they want exactly one scope (e.g. unit
        tests, admin tooling). For discovery scans use
        :meth:`build_roles_with_usage`.

        Returns
        -------
        tuple[bool, Confidence, str]
            ``(used, confidence, evidence)`` — ``confidence`` is always a
            valid enum value; ``evidence`` is always a non-empty string.
        """
        self._require(organization_id, "organization_id")
        self._require(identity_id, "identity_id")
        self._require(role_scope, "role_scope")
        if db is None:
            raise ValueError("db (AsyncSession) is required")

        arm_by_scope = await self._fetch_arm_activity_batch(
            organization_id=organization_id,
            identity_id=identity_id,
            scopes=[role_scope],
            db=db,
        )
        evidence = arm_by_scope.get(role_scope)
        usage = self._derive_usage(
            organization_id=organization_id,
            role_name="",
            scope=role_scope,
            arm_evidence=evidence,
            audit_evidence=None,
        )
        return usage.used, usage.confidence, usage.evidence

    # ------------------------------------------------------------------
    # Evidence evaluation
    # ------------------------------------------------------------------

    def _derive_usage(
        self,
        *,
        organization_id: str,
        role_name: str,
        scope: str,
        arm_evidence: Optional[dict],
        audit_evidence: Optional[dict],
    ) -> RoleUsage:
        """Pure function: evidence dicts → :class:`RoleUsage`.

        ``arm_evidence`` shape (when present):
          ``{"last_operation_time": datetime, "operation_scope": str}``

        ``audit_evidence`` shape (when present):
          ``{"last_seen": datetime, "source": str}``
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=USAGE_RECENT_DAYS)

        if arm_evidence is not None:
            last_op: Optional[datetime] = arm_evidence.get("last_operation_time")
            op_scope = str(arm_evidence.get("operation_scope") or scope)
            scope_matches = op_scope.lower() == scope.lower()

            if last_op is not None:
                if last_op.tzinfo is None:
                    last_op = last_op.replace(tzinfo=timezone.utc)
                if last_op >= cutoff and scope_matches:
                    return RoleUsage(
                        organization_id=organization_id,
                        used=True,
                        confidence=Confidence.HIGH,
                        evidence=f"arm_activity_log@{last_op.isoformat()}",
                    )
                return RoleUsage(
                    organization_id=organization_id,
                    used=True,
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        f"arm_activity_log@{last_op.isoformat()}"
                        f" scope_match={scope_matches}"
                    ),
                )

        if audit_evidence is not None:
            last_seen: Optional[datetime] = audit_evidence.get("last_seen")
            source = str(audit_evidence.get("source") or "audit_log")
            if last_seen is not None:
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                return RoleUsage(
                    organization_id=organization_id,
                    used=False,
                    confidence=Confidence.LOW,
                    evidence=f"{source}@{last_seen.isoformat()}",
                )

        if role_name and self._normalize_role_key(None, role_name) in TYPICALLY_USED_ROLE_NAMES:
            return RoleUsage(
                organization_id=organization_id,
                used=False,
                confidence=Confidence.INFERRED,
                evidence=f"typically_exercised_role:{role_name}",
            )

        return RoleUsage(
            organization_id=organization_id,
            used=False,
            confidence=Confidence.NONE,
            evidence="no_evidence_observed",
        )

    # ------------------------------------------------------------------
    # DB access — batched, org-scoped
    # ------------------------------------------------------------------

    async def _fetch_role_rows(
        self,
        *,
        organization_id: str,
        identity_id: str,
        db: AsyncSession,
    ) -> list[dict]:
        result = await db.execute(
            text(
                """
                SELECT organization_id, role_name, role_key, scope, scope_level,
                       source
                FROM identity_role_assignments
                WHERE organization_id = :org
                  AND identity_id     = :id
                """
            ),
            {"org": organization_id, "id": identity_id},
        )
        return [dict(r) for r in result.mappings().all()]

    async def _fetch_arm_activity_batch(
        self,
        *,
        organization_id: str,
        identity_id: str,
        scopes: list[str],
        db: AsyncSession,
    ) -> dict[str, dict]:
        """One query → dict keyed by scope with the freshest ARM row."""
        if not scopes:
            return {}
        result = await db.execute(
            text(
                """
                SELECT operation_scope,
                       MAX(operation_time) AS last_operation_time
                FROM arm_activity_log
                WHERE organization_id = :org
                  AND identity_id     = :id
                  AND operation_scope = ANY(:scopes)
                GROUP BY operation_scope
                """
            ),
            {"org": organization_id, "id": identity_id, "scopes": scopes},
        )
        out: dict[str, dict] = {}
        for row in result.mappings().all():
            scope_val = str(row["operation_scope"])
            out[scope_val] = {
                "last_operation_time": row["last_operation_time"],
                "operation_scope": scope_val,
            }
        return out

    async def _fetch_audit_evidence_batch(
        self,
        *,
        organization_id: str,
        identity_id: str,
        scopes: list[str],
        db: AsyncSession,
    ) -> dict[str, dict]:
        """One query → dict keyed by scope with indirect audit-log evidence."""
        if not scopes:
            return {}
        result = await db.execute(
            text(
                """
                SELECT target_scope,
                       MAX(seen_at) AS last_seen,
                       MAX(source)  AS source
                FROM identity_audit_log
                WHERE organization_id = :org
                  AND identity_id     = :id
                  AND target_scope    = ANY(:scopes)
                GROUP BY target_scope
                """
            ),
            {"org": organization_id, "id": identity_id, "scopes": scopes},
        )
        out: dict[str, dict] = {}
        for row in result.mappings().all():
            scope_val = str(row["target_scope"])
            out[scope_val] = {
                "last_seen": row["last_seen"],
                "source": row["source"],
            }
        return out

    # ------------------------------------------------------------------
    # Pure helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _require(value: Any, name: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required and must be a non-empty string")

    @staticmethod
    def _normalize_role_key(raw_key: Any, role_name: str) -> str:
        """Return a deterministic lowercase ``role_key``.

        Prefers the provided ``raw_key`` if non-empty; otherwise derives a
        snake_case key from the role name (``"User Access Administrator"``
        → ``"user_access_administrator"``).
        """
        if isinstance(raw_key, str) and raw_key.strip():
            return raw_key.strip().lower()
        stripped = (role_name or "").strip().lower()
        if not stripped:
            return "unknown"
        return _NON_WORD_RE.sub("_", stripped).strip("_") or "unknown"

    @staticmethod
    def _parse_scope_level(raw: Any, cloud_provider: str) -> ScopeBreadth:
        if isinstance(raw, str) and raw.strip():
            try:
                return ScopeBreadth(raw)
            except ValueError:
                pass
        return ScopeBreadth.RESOURCE

    @staticmethod
    def _parse_role_source(raw: Any, cloud_provider: str) -> RoleSource:
        if isinstance(raw, str) and raw.strip():
            try:
                return RoleSource(raw)
            except ValueError:
                pass
        return _PROVIDER_DEFAULT_ROLE_SOURCE.get(
            cloud_provider.lower(), RoleSource.AZURE_RBAC
        )
