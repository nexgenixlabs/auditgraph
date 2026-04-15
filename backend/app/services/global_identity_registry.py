"""
GlobalIdentityRegistry — cross-cloud identity correlation service.

The registry assigns a stable, cross-cloud UUID (``global_identity_id``) to
every cloud-native identity so that downstream engines (risk scoring, attack
path analysis, blast radius) can reason about "the same principal" regardless
of which cloud surfaced it.

Guarantees
----------
* **Hard organization scoping** — every query filters by ``organization_id``.
  The service will never return or attach a ``global_identity_id`` that
  belongs to a different tenant, even if a caller passes a matching UUID.
* **No silent failures** — every database error is wrapped in a
  :class:`RegistryResolutionError` that preserves the original context.
* **Safe federation** — ``federated_from`` can only attach a member to an
  existing global identity *within the same organization*; any mismatch
  raises :class:`CrossOrgLeakageError`.
* **Batch-friendly** — :meth:`GlobalIdentityRegistry.bulk_resolve` uses
  ``INSERT ... ON CONFLICT DO UPDATE`` to avoid N+1 round-trips during
  discovery scans.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RegistryResolutionError(Exception):
    """Raised when the registry cannot resolve or persist an identity."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class CrossOrgLeakageError(RegistryResolutionError):
    """Raised when an operation would cross an organization boundary.

    This is a security-critical error: it means a caller attempted to bind
    a cloud identity to a global identity owned by a different tenant. The
    registry refuses the operation and surfaces the violation loudly.
    """


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_VALID_PROVIDERS = frozenset({"azure", "aws", "gcp"})


def _require_org(organization_id: str) -> str:
    if not isinstance(organization_id, str) or not organization_id.strip():
        raise ValueError("organization_id is required and must be a non-empty string")
    return organization_id


def _require_provider(cloud_provider: str) -> str:
    if cloud_provider not in _VALID_PROVIDERS:
        raise ValueError(
            f"cloud_provider must be one of {sorted(_VALID_PROVIDERS)}, "
            f"got {cloud_provider!r}"
        )
    return cloud_provider


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class GlobalIdentityRegistry:
    """Async service for resolving cloud identities to stable global UUIDs.

    All methods take an :class:`AsyncSession` so that the caller controls the
    transaction boundary (e.g. a discovery scan can resolve thousands of
    identities inside a single transaction).
    """

    # ------------------------------------------------------------------
    # resolve — single identity
    # ------------------------------------------------------------------

    async def resolve(
        self,
        organization_id: str,
        cloud_id: str,
        cloud_provider: str,
        identity_type: str,
        canonical_name: str,
        canonical_email: Optional[str] = None,
        federated_from: Optional[uuid.UUID] = None,
        db: AsyncSession = None,
    ) -> uuid.UUID:
        """Resolve or create a ``global_identity_id`` for a single cloud identity.

        Resolution order:

        1. Look up ``(organization_id, cloud_id, cloud_provider)`` in
           ``global_identity_members``. If a row exists, bump ``last_seen`` on
           the parent registry row and return its id.
        2. If no member exists and ``federated_from`` is provided, verify that
           the referenced global identity belongs to the same organization,
           then attach a new member row to it.
        3. Otherwise, create a fresh registry entry and attach this identity
           as its primary member.

        Parameters
        ----------
        organization_id:
            Owning tenant. Mandatory — empty values raise ``ValueError``.
        cloud_id:
            Provider-native identifier (ARM id, IAM ARN, GCP resource name).
        cloud_provider:
            One of ``azure``, ``aws``, ``gcp``.
        identity_type:
            Logical identity type (e.g. ``human_user``, ``service_principal``).
        canonical_name:
            Display/canonical name used when creating a new registry row.
        canonical_email:
            Canonical email if known (used for new registry rows only).
        federated_from:
            Existing ``global_identity_id`` to attach this cloud identity to.
            Must belong to the same organization.
        db:
            Async SQLAlchemy session managed by the caller.

        Returns
        -------
        uuid.UUID
            The stable global identity id for this cloud identity.

        Raises
        ------
        ValueError
            If required arguments are missing or invalid.
        CrossOrgLeakageError
            If ``federated_from`` points to a global identity in a different
            organization.
        RegistryResolutionError
            On any underlying database failure (original exception chained).
        """
        _require_org(organization_id)
        _require_provider(cloud_provider)

        if db is None:
            raise ValueError("db (AsyncSession) is required")
        if not cloud_id:
            raise ValueError("cloud_id is required")
        if not identity_type:
            raise ValueError("identity_type is required")
        if not canonical_name:
            raise ValueError("canonical_name is required")

        logger.debug(
            "registry.resolve start org=%s provider=%s cloud_id=%s federated_from=%s",
            organization_id,
            cloud_provider,
            cloud_id,
            federated_from,
        )

        try:
            # Step 1 — existing member lookup (strictly org-scoped).
            existing = await db.execute(
                text(
                    """
                    SELECT global_identity_id
                    FROM global_identity_members
                    WHERE organization_id = :org
                      AND cloud_id        = :cloud_id
                      AND cloud_provider  = :provider
                    """
                ),
                {
                    "org": organization_id,
                    "cloud_id": cloud_id,
                    "provider": cloud_provider,
                },
            )
            row = existing.first()
            if row is not None:
                gid: uuid.UUID = row[0]
                await db.execute(
                    text(
                        """
                        UPDATE global_identity_registry
                        SET last_seen = now()
                        WHERE global_identity_id = :gid
                          AND organization_id   = :org
                        """
                    ),
                    {"gid": gid, "org": organization_id},
                )
                logger.debug(
                    "registry.resolve hit gid=%s org=%s cloud_id=%s",
                    gid,
                    organization_id,
                    cloud_id,
                )
                return gid

            # Step 2 — federation attach.
            if federated_from is not None:
                parent = await db.execute(
                    text(
                        """
                        SELECT global_identity_id, organization_id
                        FROM global_identity_registry
                        WHERE global_identity_id = :gid
                        """
                    ),
                    {"gid": federated_from},
                )
                parent_row = parent.first()
                if parent_row is None:
                    raise RegistryResolutionError(
                        "federated_from references unknown global_identity_id",
                        context={
                            "organization_id": organization_id,
                            "federated_from": str(federated_from),
                        },
                    )
                if parent_row[1] != organization_id:
                    raise CrossOrgLeakageError(
                        "federated_from belongs to a different organization",
                        context={
                            "requested_org": organization_id,
                            "owning_org": parent_row[1],
                            "federated_from": str(federated_from),
                        },
                    )

                await db.execute(
                    text(
                        """
                        INSERT INTO global_identity_members (
                            global_identity_id, organization_id, cloud_id,
                            cloud_provider, identity_type, is_primary
                        ) VALUES (
                            :gid, :org, :cloud_id, :provider, :itype, false
                        )
                        """
                    ),
                    {
                        "gid": federated_from,
                        "org": organization_id,
                        "cloud_id": cloud_id,
                        "provider": cloud_provider,
                        "itype": identity_type,
                    },
                )
                await db.execute(
                    text(
                        """
                        UPDATE global_identity_registry
                        SET last_seen = now()
                        WHERE global_identity_id = :gid
                          AND organization_id   = :org
                        """
                    ),
                    {"gid": federated_from, "org": organization_id},
                )
                logger.debug(
                    "registry.resolve federated gid=%s org=%s cloud_id=%s",
                    federated_from,
                    organization_id,
                    cloud_id,
                )
                return federated_from

            # Step 3 — brand-new registry entry.
            created = await db.execute(
                text(
                    """
                    INSERT INTO global_identity_registry (
                        organization_id, canonical_name, canonical_email, last_seen
                    ) VALUES (
                        :org, :name, :email, now()
                    )
                    RETURNING global_identity_id
                    """
                ),
                {
                    "org": organization_id,
                    "name": canonical_name,
                    "email": canonical_email,
                },
            )
            new_gid: uuid.UUID = created.scalar_one()

            await db.execute(
                text(
                    """
                    INSERT INTO global_identity_members (
                        global_identity_id, organization_id, cloud_id,
                        cloud_provider, identity_type, is_primary
                    ) VALUES (
                        :gid, :org, :cloud_id, :provider, :itype, true
                    )
                    """
                ),
                {
                    "gid": new_gid,
                    "org": organization_id,
                    "cloud_id": cloud_id,
                    "provider": cloud_provider,
                    "itype": identity_type,
                },
            )
            logger.debug(
                "registry.resolve created gid=%s org=%s cloud_id=%s",
                new_gid,
                organization_id,
                cloud_id,
            )
            return new_gid

        except CrossOrgLeakageError:
            raise
        except RegistryResolutionError:
            raise
        except SQLAlchemyError as exc:
            raise RegistryResolutionError(
                "database error while resolving global identity",
                context={
                    "organization_id": organization_id,
                    "cloud_id": cloud_id,
                    "cloud_provider": cloud_provider,
                },
            ) from exc

    # ------------------------------------------------------------------
    # get_peers — siblings under the same global identity
    # ------------------------------------------------------------------

    async def get_peers(
        self,
        organization_id: str,
        global_identity_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Return every cloud member bound to this global identity.

        The lookup is strictly scoped to ``organization_id``; a caller
        supplying a valid UUID that belongs to another tenant receives an
        empty list (never a cross-org row).

        Parameters
        ----------
        organization_id:
            Owning tenant — mandatory.
        global_identity_id:
            The stable global UUID to expand.
        db:
            Async SQLAlchemy session.

        Returns
        -------
        list[dict]
            One dict per member with keys: ``cloud_id``, ``cloud_provider``,
            ``identity_type``, ``is_primary``, ``discovered_at``.

        Raises
        ------
        ValueError
            If ``organization_id`` or ``db`` is missing.
        RegistryResolutionError
            On database failure.
        """
        _require_org(organization_id)
        if db is None:
            raise ValueError("db (AsyncSession) is required")

        # ``global_identity_members.organization_id`` is INTEGER (migration
        # 087). asyncpg type-infers bound parameters at prepare-statement
        # time, *before* any SQL CAST applies, so a str binding fails even
        # with CAST(:org AS INTEGER) in the query. Coerce in Python.
        try:
            org_int = int(organization_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"organization_id must be an integer, got {organization_id!r}"
            ) from exc

        try:
            result = await db.execute(
                text(
                    """
                    SELECT cloud_id, cloud_provider, identity_type,
                           is_primary, discovered_at
                    FROM global_identity_members
                    WHERE organization_id    = :org
                      AND global_identity_id = :gid
                    ORDER BY is_primary DESC, discovered_at ASC
                    """
                ),
                {"org": org_int, "gid": global_identity_id},
            )
            peers = [
                {
                    "cloud_id": r[0],
                    "cloud_provider": r[1],
                    "identity_type": r[2],
                    "is_primary": r[3],
                    "discovered_at": r[4],
                }
                for r in result.fetchall()
            ]
            logger.debug(
                "registry.get_peers gid=%s org=%s count=%d",
                global_identity_id,
                organization_id,
                len(peers),
            )
            return peers
        except SQLAlchemyError as exc:
            raise RegistryResolutionError(
                "database error while fetching global identity peers",
                context={
                    "organization_id": organization_id,
                    "global_identity_id": str(global_identity_id),
                },
            ) from exc

    # ------------------------------------------------------------------
    # bulk_resolve — batch path for discovery scans
    # ------------------------------------------------------------------

    async def bulk_resolve(
        self,
        organization_id: str,
        identities: list[dict],
        db: AsyncSession,
    ) -> dict[str, uuid.UUID]:
        """Batch-resolve identities during a discovery scan.

        Avoids N+1 round-trips by issuing per-row upserts against the
        members table with ``INSERT ... ON CONFLICT DO UPDATE``. For each
        input row this method:

        1. Ensures a ``global_identity_registry`` row exists (inserted on
           first sight, ``last_seen`` bumped otherwise).
        2. Ensures a ``global_identity_members`` row exists for the
           ``(organization_id, cloud_id, cloud_provider)`` tuple.
        3. Returns the resolved ``global_identity_id`` keyed by ``cloud_id``.

        Parameters
        ----------
        organization_id:
            Owning tenant — mandatory.
        identities:
            List of dicts, each with keys: ``cloud_id``, ``cloud_provider``,
            ``identity_type``, ``canonical_name``. Optional: ``canonical_email``.
        db:
            Async SQLAlchemy session managed by the caller.

        Returns
        -------
        dict[str, uuid.UUID]
            Mapping of ``cloud_id`` → ``global_identity_id``.

        Raises
        ------
        ValueError
            On missing organization_id, missing session, or malformed rows.
        RegistryResolutionError
            On database failure (original exception chained).
        """
        _require_org(organization_id)
        if db is None:
            raise ValueError("db (AsyncSession) is required")
        if not identities:
            return {}

        result: dict[str, uuid.UUID] = {}

        try:
            for idx, ident in enumerate(identities):
                cloud_id = ident.get("cloud_id")
                cloud_provider = ident.get("cloud_provider")
                identity_type = ident.get("identity_type")
                canonical_name = ident.get("canonical_name")
                canonical_email = ident.get("canonical_email")

                if not cloud_id or not identity_type or not canonical_name:
                    raise ValueError(
                        f"identities[{idx}] missing required keys "
                        "(cloud_id/identity_type/canonical_name)"
                    )
                _require_provider(cloud_provider)

                # Fast path: upsert member row. If a member already exists for
                # this (org, cloud_id, provider), keep its existing global id
                # and just bump discovered_at. Otherwise we need a new
                # registry row first — handled in the fallback branch below.
                existing = await db.execute(
                    text(
                        """
                        SELECT global_identity_id
                        FROM global_identity_members
                        WHERE organization_id = :org
                          AND cloud_id        = :cloud_id
                          AND cloud_provider  = :provider
                        """
                    ),
                    {
                        "org": organization_id,
                        "cloud_id": cloud_id,
                        "provider": cloud_provider,
                    },
                )
                existing_row = existing.first()

                if existing_row is not None:
                    gid: uuid.UUID = existing_row[0]
                    await db.execute(
                        text(
                            """
                            UPDATE global_identity_registry
                            SET last_seen = now()
                            WHERE global_identity_id = :gid
                              AND organization_id   = :org
                            """
                        ),
                        {"gid": gid, "org": organization_id},
                    )
                else:
                    created = await db.execute(
                        text(
                            """
                            INSERT INTO global_identity_registry (
                                organization_id, canonical_name,
                                canonical_email, last_seen
                            ) VALUES (
                                :org, :name, :email, now()
                            )
                            RETURNING global_identity_id
                            """
                        ),
                        {
                            "org": organization_id,
                            "name": canonical_name,
                            "email": canonical_email,
                        },
                    )
                    gid = created.scalar_one()

                    await db.execute(
                        text(
                            """
                            INSERT INTO global_identity_members (
                                global_identity_id, organization_id, cloud_id,
                                cloud_provider, identity_type, is_primary
                            ) VALUES (
                                :gid, :org, :cloud_id, :provider, :itype, true
                            )
                            ON CONFLICT (organization_id, cloud_id, cloud_provider)
                            DO UPDATE SET
                                identity_type  = EXCLUDED.identity_type,
                                discovered_at  = now()
                            """
                        ),
                        {
                            "gid": gid,
                            "org": organization_id,
                            "cloud_id": cloud_id,
                            "provider": cloud_provider,
                            "itype": identity_type,
                        },
                    )

                result[cloud_id] = gid

            logger.debug(
                "registry.bulk_resolve org=%s resolved=%d",
                organization_id,
                len(result),
            )
            return result

        except ValueError:
            raise
        except SQLAlchemyError as exc:
            raise RegistryResolutionError(
                "database error during bulk_resolve",
                context={
                    "organization_id": organization_id,
                    "batch_size": len(identities),
                },
            ) from exc
