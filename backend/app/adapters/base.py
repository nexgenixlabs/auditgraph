"""
CloudAdapterBase
================

Abstract contract every cloud adapter (Azure / AWS / GCP / future) must
satisfy. The goal is **zero core-model changes per new cloud**: to light up
a new provider the implementer follows the same five steps:

    1. Subclass :class:`CloudAdapterBase`
    2. Register the subclass in the adapter registry
    3. Add a provider metadata dataclass (provider_id, default scopes, etc.)
    4. Implement a discovery connector (SDK calls → adapter methods)
    5. Add role-name → canonical constants (provider role table)

Everything tenant-scoped. Every discovery method receives an
``organization_id`` and every produced :class:`IdentityProfile` carries it.
The base class owns the F1 global-identity-id resolution (so all adapters
correlate through the same :class:`GlobalIdentityRegistry`) and leaves the
cloud-specific field mapping to the subclasses.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Optional

from app.schemas.identity import (
    Confidence,
    IdentityProfile,
    IdentityType,
    ResourceType,
    RoleSource,
)
from app.services.global_identity_registry import GlobalIdentityRegistry


# ---------------------------------------------------------------------------
# Canonical activity-signal container (input to ActivityState builder)
# ---------------------------------------------------------------------------


@dataclass
class ActivitySignals:
    """Canonical activity signals extracted from a raw cloud row.

    Every adapter normalizes its provider-specific fields into this shape so
    the identity state engine can reason about activity uniformly. Any signal
    that is unknown should be left as ``None`` — never fabricated.
    """

    interactive_signin_at: Optional[datetime] = None
    control_plane_at: Optional[datetime] = None
    token_issuance_at: Optional[datetime] = None
    lineage_activity_at: Optional[datetime] = None
    confidence: Confidence = Confidence.NONE
    evidence: str = ""

    @property
    def last_activity_at(self) -> Optional[datetime]:
        """Return the most recent non-null signal, if any."""
        candidates = [
            v
            for v in (
                self.interactive_signin_at,
                self.control_plane_at,
                self.token_issuance_at,
                self.lineage_activity_at,
            )
            if v is not None
        ]
        return max(candidates) if candidates else None


# ---------------------------------------------------------------------------
# Discovery result container
# ---------------------------------------------------------------------------


@dataclass
class DiscoveryScanResult:
    """Outcome of a discovery scan — always partial-tolerant.

    ``identities`` contains everything that was successfully normalized.
    ``scan_errors`` collects per-identity failures so the caller can surface
    them without losing the rest of the scan.
    """

    organization_id: str
    cloud_provider: str
    connector_id: int
    identities: list[IdentityProfile] = field(default_factory=list)
    scan_errors: list[dict] = field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    def record_error(self, *, identity_id: Optional[str], stage: str, error: str) -> None:
        self.scan_errors.append(
            {
                "identity_id": identity_id,
                "stage": stage,
                "error": error,
            }
        )


# ---------------------------------------------------------------------------
# Base adapter
# ---------------------------------------------------------------------------


class CloudAdapterBase(ABC):
    """Abstract cloud adapter. Subclass per provider."""

    #: Must be set by subclasses — used by the registry when resolving UUIDs.
    CLOUD_PROVIDER: ClassVar[str] = ""

    def __init__(self) -> None:
        # Tracks the identity type currently being processed so that
        # :meth:`resolve_global_identity_id` can forward it to the registry
        # without each caller having to repeat itself. Subclasses set it
        # before invoking the helper.
        self._current_identity_type: str = ""

    # ------------------------------------------------------------------
    # Abstract surface — every cloud must implement these
    # ------------------------------------------------------------------

    @abstractmethod
    async def discover_identities(
        self, organization_id: str, connector_id: int
    ) -> list[IdentityProfile]:
        """Discover all identities in this cloud tenant/account.

        Implementations must enforce ``organization_id`` scoping end-to-end
        and must never return an :class:`IdentityProfile` whose
        ``organization_id`` differs from the argument.
        """

    @abstractmethod
    def resolve_activity_signals(self, raw_row: dict) -> ActivitySignals:
        """Map cloud-specific fields to canonical :class:`ActivitySignals`."""

    @abstractmethod
    def resolve_role_source(self, role: dict) -> RoleSource:
        """Map a cloud role row to the canonical :class:`RoleSource` enum."""

    @abstractmethod
    def resolve_access_origin(self, raw_row: dict) -> str:
        """Derive the connection origin (IP, pipeline id, workload name)."""

    @abstractmethod
    def resolve_sensitive_resource_type(self, resource: dict) -> ResourceType:
        """Map a cloud resource type string to the canonical enum."""

    # ------------------------------------------------------------------
    # F1 — shared implementation (do not override lightly)
    # ------------------------------------------------------------------

    async def resolve_global_identity_id(
        self,
        organization_id: str,
        cloud_id: str,
        canonical_name: str,
        canonical_email: Optional[str],
        registry: GlobalIdentityRegistry,
        db: Any,
        federated_from: Optional[uuid.UUID] = None,
    ) -> uuid.UUID:
        """Resolve-or-create a stable global identity id (F1).

        Delegates to :class:`GlobalIdentityRegistry` — every adapter shares
        the exact same correlation path so cross-cloud merges are
        deterministic.
        """
        if not self.CLOUD_PROVIDER:
            raise ValueError(
                f"{type(self).__name__}.CLOUD_PROVIDER must be set before "
                "resolve_global_identity_id is called"
            )
        if not self._current_identity_type:
            raise ValueError(
                "CloudAdapterBase._current_identity_type must be set by the "
                "subclass before calling resolve_global_identity_id"
            )

        return await registry.resolve(
            organization_id=organization_id,
            cloud_id=cloud_id,
            cloud_provider=self.CLOUD_PROVIDER,
            identity_type=self._current_identity_type,
            canonical_name=canonical_name,
            canonical_email=canonical_email,
            federated_from=federated_from,
            db=db,
        )
