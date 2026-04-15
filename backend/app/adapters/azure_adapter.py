"""
AzureAdapter
============

Azure implementation of :class:`CloudAdapterBase`.

Scope (v1)
----------
Discovers 5 identity types:

1. ``human_user``        — Entra (Azure AD) users with ``userType == "Member"``
2. ``guest_user``        — Entra users with ``userType == "Guest"``
3. ``service_principal`` — SPNs, with Microsoft first-party excluded
4. ``managed_identity``  — System-assigned + user-assigned MSIs
5. ``app_registration``  — App registrations that hold credentials

Field mappings
--------------

========================  =============================================================
Canonical signal          Azure source
========================  =============================================================
interactive_signin        ``user.signInActivity.lastSignInDateTime``
control_plane             ``arm_activity_log.last_operation_time``
token_issuance            ``service_principal.tokenIssuancePolicy`` / ``app_token_last_issued``
lineage_activity          ``identity_lineage_graph.last_seen`` (inferred)
global_identity_id        :class:`GlobalIdentityRegistry` lookup/create (F1)
========================  =============================================================

Error handling
--------------
* :class:`GraphAPIError` wraps every Microsoft Graph exception.
* :class:`ARMAPIError` wraps every ARM exception.
* Per-identity failures are logged, recorded on
  :class:`DiscoveryScanResult.scan_errors`, and **the scan continues** —
  partial results are always preferred over an aborted scan.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, ClassVar, Iterable, Mapping, Optional

from app.adapters.base import (
    ActivitySignals,
    CloudAdapterBase,
    DiscoveryScanResult,
)
from app.schemas.identity import (
    CloudProvider,
    Confidence,
    DataContext,
    DataMode,
    IdentityProfile,
    IdentitySource,
    IdentityStatus,
    IdentityType,
    ResourceType,
    RoleAssignment,
    RoleSource,
    RoleUsage,
    ScopeBreadth,
)
from app.services.global_identity_registry import GlobalIdentityRegistry


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — all tunables live here, nothing hardcoded inline
# ---------------------------------------------------------------------------


#: Microsoft first-party tenant ids excluded from SPN discovery.
MICROSOFT_TENANT_IDS: frozenset[str] = frozenset(
    {
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        "72f988bf-86f1-41af-91ab-2d7cd011db47",
        "33e01921-4d64-4f8c-a055-5bdaffd5e33d",
        "47912173-f83e-423a-8aef-9f4e5e65f88e",
    }
)

#: How recent an ARM activity must be for a role to count as "used".
ROLE_USAGE_RECENCY_DAYS: int = 30

#: Scope marker strings used to derive :class:`ScopeBreadth`, checked from
#: most-specific to least-specific.
_SCOPE_MANAGEMENT_GROUP_MARKER: str = "/providers/microsoft.management/managementgroups/"
_SCOPE_SUBSCRIPTION_MARKER: str = "/subscriptions/"
_SCOPE_RESOURCE_GROUP_MARKER: str = "/resourcegroups/"
_SCOPE_RESOURCE_PROVIDER_MARKER: str = "/providers/"

#: Azure resource type string → canonical :class:`ResourceType`.
_AZURE_RESOURCE_TYPE_MAP: Mapping[str, ResourceType] = {
    "microsoft.keyvault/vaults": ResourceType.KEY_VAULT,
    "microsoft.storage/storageaccounts": ResourceType.STORAGE,
    "microsoft.sql/servers/databases": ResourceType.DATABASE,
    "microsoft.documentdb/databaseaccounts": ResourceType.DATABASE,
    "microsoft.dbforpostgresql/servers": ResourceType.DATABASE,
    "microsoft.dbformysql/servers": ResourceType.DATABASE,
    "microsoft.keyvault/vaults/secrets": ResourceType.SECRET,
    "microsoft.keyvault/vaults/certificates": ResourceType.CERTIFICATE_STORE,
    "microsoft.authorization/roledefinitions": ResourceType.IAM_SYSTEM,
    "microsoft.managedidentity/userassignedidentities": ResourceType.IAM_SYSTEM,
}

#: Azure RBAC role-source tag. Everything else gets mapped by the lookup.
_AZURE_ROLE_TYPE_MAP: Mapping[str, RoleSource] = {
    "azure_rbac": RoleSource.AZURE_RBAC,
    "rbac": RoleSource.AZURE_RBAC,
    "builtinrole": RoleSource.AZURE_RBAC,
    "customrole": RoleSource.AZURE_RBAC,
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GraphAPIError(Exception):
    """Wraps any Microsoft Graph SDK / HTTP exception."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class ARMAPIError(Exception):
    """Wraps any Azure Resource Manager SDK / HTTP exception."""

    def __init__(self, message: str, *, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


@dataclass
class AzureAdapterDependencies:
    """Everything the adapter needs injected from the caller.

    Splitting these out keeps the adapter testable without importing real
    Azure SDK clients. Each callable corresponds to one Graph or ARM call
    and returns already-decoded dicts.
    """

    graph_list_users: Callable[[int], Awaitable[list[dict]]]
    graph_list_service_principals: Callable[[int], Awaitable[list[dict]]]
    graph_list_managed_identities: Callable[[int], Awaitable[list[dict]]]
    graph_list_app_registrations: Callable[[int], Awaitable[list[dict]]]
    arm_list_role_assignments: Callable[[int, str], Awaitable[list[dict]]]
    arm_get_last_activity: Callable[[int, str, str], Awaitable[Optional[datetime]]]
    registry: GlobalIdentityRegistry
    db: Any


class AzureAdapter(CloudAdapterBase):
    """Azure cloud adapter — Entra + ARM discovery."""

    CLOUD_PROVIDER: ClassVar[str] = "azure"

    def __init__(self, deps: AzureAdapterDependencies) -> None:
        super().__init__()
        self._deps = deps

    # ------------------------------------------------------------------
    # discover_identities — top-level scan (partial-tolerant)
    # ------------------------------------------------------------------

    async def discover_identities(
        self, organization_id: str, connector_id: int
    ) -> list[IdentityProfile]:
        """Run a full Azure identity scan for this organization/connector.

        The public contract returns a plain list of :class:`IdentityProfile`
        so it matches the base class signature. Callers that want the
        per-identity error stream should use :meth:`run_scan` instead, which
        returns the full :class:`DiscoveryScanResult`.
        """
        result = await self.run_scan(organization_id, connector_id)
        return result.identities

    async def run_scan(
        self, organization_id: str, connector_id: int
    ) -> DiscoveryScanResult:
        """Run the scan and return identities + per-identity errors."""
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise ValueError("organization_id is required")

        result = DiscoveryScanResult(
            organization_id=organization_id,
            cloud_provider=self.CLOUD_PROVIDER,
            connector_id=connector_id,
            started_at=datetime.now(timezone.utc),
        )

        # --- 1. Entra users (member + guest) ------------------------------
        try:
            users = await self._deps.graph_list_users(connector_id)
        except Exception as exc:  # noqa: BLE001 — wrapped into GraphAPIError
            raise GraphAPIError(
                "failed to list Entra users",
                context={"organization_id": organization_id, "connector_id": connector_id},
            ) from exc

        for user in users:
            try:
                identity_type = (
                    IdentityType.GUEST_USER
                    if str(user.get("userType", "")).lower() == "guest"
                    else IdentityType.HUMAN_USER
                )
                profile = await self._user_to_profile(
                    organization_id, connector_id, user, identity_type
                )
                result.identities.append(profile)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "azure.discover user=%s error=%s",
                    user.get("id"),
                    exc,
                )
                result.record_error(
                    identity_id=user.get("id"),
                    stage="user",
                    error=str(exc),
                )

        # --- 2. Service principals (Microsoft first-party excluded) -------
        try:
            spns = await self._deps.graph_list_service_principals(connector_id)
        except Exception as exc:  # noqa: BLE001
            raise GraphAPIError(
                "failed to list service principals",
                context={"organization_id": organization_id, "connector_id": connector_id},
            ) from exc

        for spn in spns:
            try:
                if self._is_microsoft_first_party(spn):
                    continue
                profile = await self._spn_to_profile(organization_id, connector_id, spn)
                result.identities.append(profile)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "azure.discover spn=%s error=%s", spn.get("id"), exc
                )
                result.record_error(
                    identity_id=spn.get("id"),
                    stage="service_principal",
                    error=str(exc),
                )

        # --- 3. Managed identities ----------------------------------------
        try:
            msis = await self._deps.graph_list_managed_identities(connector_id)
        except Exception as exc:  # noqa: BLE001
            raise GraphAPIError(
                "failed to list managed identities",
                context={"organization_id": organization_id, "connector_id": connector_id},
            ) from exc

        for msi in msis:
            try:
                profile = await self._msi_to_profile(organization_id, connector_id, msi)
                result.identities.append(profile)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "azure.discover msi=%s error=%s", msi.get("id"), exc
                )
                result.record_error(
                    identity_id=msi.get("id"),
                    stage="managed_identity",
                    error=str(exc),
                )

        # --- 4. App registrations -----------------------------------------
        try:
            apps = await self._deps.graph_list_app_registrations(connector_id)
        except Exception as exc:  # noqa: BLE001
            raise GraphAPIError(
                "failed to list app registrations",
                context={"organization_id": organization_id, "connector_id": connector_id},
            ) from exc

        for app in apps:
            try:
                profile = await self._app_to_profile(organization_id, connector_id, app)
                result.identities.append(profile)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "azure.discover app=%s error=%s", app.get("id"), exc
                )
                result.record_error(
                    identity_id=app.get("id"),
                    stage="app_registration",
                    error=str(exc),
                )

        result.finished_at = datetime.now(timezone.utc)
        logger.info(
            "azure.scan done org=%s connector=%s identities=%d errors=%d",
            organization_id,
            connector_id,
            len(result.identities),
            len(result.scan_errors),
        )
        return result

    # ------------------------------------------------------------------
    # Per-identity normalizers
    # ------------------------------------------------------------------

    async def _user_to_profile(
        self,
        organization_id: str,
        connector_id: int,
        user: dict,
        identity_type: IdentityType,
    ) -> IdentityProfile:
        self._current_identity_type = identity_type.value
        object_id = user["id"]
        upn = user.get("userPrincipalName") or ""
        display_name = user.get("displayName") or upn or object_id

        gid = await self.resolve_global_identity_id(
            organization_id=organization_id,
            cloud_id=object_id,
            canonical_name=display_name,
            canonical_email=user.get("mail") or upn,
            registry=self._deps.registry,
            db=self._deps.db,
        )

        return IdentityProfile(
            organization_id=organization_id,
            global_identity_id=gid,
            identity_id=object_id,
            object_id=object_id,
            display_name=display_name,
            user_principal_name=upn or None,
            identity_type=identity_type,
            cloud_id=CloudProvider.AZURE,
            source=IdentitySource.AZURE_AD,
            status=self._status_from_user(user),
            is_federated_identity=bool(user.get("externalUserState")),
            federated_from=None,
            created_at=_parse_datetime(user.get("createdDateTime")),
            last_modified_at=_parse_datetime(user.get("lastModifiedDateTime")),
            discovered_at=datetime.now(timezone.utc),
            data_context=_live_context(),
        )

    async def _spn_to_profile(
        self, organization_id: str, connector_id: int, spn: dict
    ) -> IdentityProfile:
        self._current_identity_type = IdentityType.SERVICE_PRINCIPAL.value
        object_id = spn["id"]
        display_name = spn.get("displayName") or object_id

        gid = await self.resolve_global_identity_id(
            organization_id=organization_id,
            cloud_id=object_id,
            canonical_name=display_name,
            canonical_email=None,
            registry=self._deps.registry,
            db=self._deps.db,
        )

        return IdentityProfile(
            organization_id=organization_id,
            global_identity_id=gid,
            identity_id=object_id,
            object_id=object_id,
            display_name=display_name,
            user_principal_name=None,
            identity_type=IdentityType.SERVICE_PRINCIPAL,
            cloud_id=CloudProvider.AZURE,
            source=IdentitySource.AZURE_AD,
            status=self._status_from_spn(spn),
            is_federated_identity=False,
            federated_from=None,
            created_at=_parse_datetime(spn.get("createdDateTime")),
            last_modified_at=None,
            discovered_at=datetime.now(timezone.utc),
            data_context=_live_context(),
        )

    async def _msi_to_profile(
        self, organization_id: str, connector_id: int, msi: dict
    ) -> IdentityProfile:
        self._current_identity_type = IdentityType.MANAGED_IDENTITY.value
        object_id = msi["id"]
        display_name = msi.get("displayName") or msi.get("name") or object_id

        gid = await self.resolve_global_identity_id(
            organization_id=organization_id,
            cloud_id=object_id,
            canonical_name=display_name,
            canonical_email=None,
            registry=self._deps.registry,
            db=self._deps.db,
        )

        return IdentityProfile(
            organization_id=organization_id,
            global_identity_id=gid,
            identity_id=object_id,
            object_id=object_id,
            display_name=display_name,
            user_principal_name=None,
            identity_type=IdentityType.MANAGED_IDENTITY,
            cloud_id=CloudProvider.AZURE,
            source=IdentitySource.AZURE_AD,
            status=IdentityStatus.ACTIVE,
            is_federated_identity=False,
            federated_from=None,
            created_at=_parse_datetime(msi.get("createdDateTime")),
            last_modified_at=None,
            discovered_at=datetime.now(timezone.utc),
            data_context=_live_context(),
        )

    async def _app_to_profile(
        self, organization_id: str, connector_id: int, app: dict
    ) -> IdentityProfile:
        self._current_identity_type = IdentityType.APP_REGISTRATION.value
        object_id = app["id"]
        display_name = app.get("displayName") or object_id

        gid = await self.resolve_global_identity_id(
            organization_id=organization_id,
            cloud_id=object_id,
            canonical_name=display_name,
            canonical_email=None,
            registry=self._deps.registry,
            db=self._deps.db,
        )

        return IdentityProfile(
            organization_id=organization_id,
            global_identity_id=gid,
            identity_id=object_id,
            object_id=object_id,
            display_name=display_name,
            user_principal_name=None,
            identity_type=IdentityType.APP_REGISTRATION,
            cloud_id=CloudProvider.AZURE,
            source=IdentitySource.AZURE_AD,
            status=IdentityStatus.ACTIVE,
            is_federated_identity=False,
            federated_from=None,
            created_at=_parse_datetime(app.get("createdDateTime")),
            last_modified_at=None,
            discovered_at=datetime.now(timezone.utc),
            data_context=_live_context(),
        )

    # ------------------------------------------------------------------
    # Abstract method implementations
    # ------------------------------------------------------------------

    def resolve_activity_signals(self, raw_row: dict) -> ActivitySignals:
        """Map Entra / ARM fields onto the canonical :class:`ActivitySignals`."""
        sign_in_container = raw_row.get("signInActivity") or {}
        interactive = _parse_datetime(sign_in_container.get("lastSignInDateTime"))

        arm_container = raw_row.get("arm_activity_log") or {}
        control_plane = _parse_datetime(arm_container.get("last_operation_time"))

        token_container = (
            raw_row.get("tokenIssuancePolicy")
            or raw_row.get("token_issuance")
            or {}
        )
        token_issuance = _parse_datetime(
            raw_row.get("app_token_last_issued")
            or token_container.get("last_issued_at")
        )

        lineage_container = raw_row.get("identity_lineage_graph") or {}
        lineage_activity = _parse_datetime(lineage_container.get("last_seen"))

        has_any = any(
            (interactive, control_plane, token_issuance, lineage_activity)
        )
        if interactive or control_plane:
            confidence = Confidence.HIGH
        elif token_issuance:
            confidence = Confidence.MEDIUM
        elif lineage_activity:
            confidence = Confidence.INFERRED
        else:
            confidence = Confidence.NONE

        evidence_parts: list[str] = []
        if interactive:
            evidence_parts.append("signInActivity.lastSignInDateTime")
        if control_plane:
            evidence_parts.append("arm_activity_log.last_operation_time")
        if token_issuance:
            evidence_parts.append("app_token_last_issued")
        if lineage_activity:
            evidence_parts.append("lineage_graph.last_seen")

        return ActivitySignals(
            interactive_signin_at=interactive,
            control_plane_at=control_plane,
            token_issuance_at=token_issuance,
            lineage_activity_at=lineage_activity,
            confidence=confidence if has_any else Confidence.NONE,
            evidence=",".join(evidence_parts),
        )

    def resolve_role_source(self, role: dict) -> RoleSource:
        """Map an Azure role row to :class:`RoleSource`.

        Azure RBAC is always ``azure_rbac``; anything unrecognized defaults
        to ``azure_rbac`` so callers still get a valid enum rather than an
        exception deep inside the scan loop.
        """
        raw = str(role.get("type") or role.get("source") or "azure_rbac").lower()
        return _AZURE_ROLE_TYPE_MAP.get(raw, RoleSource.AZURE_RBAC)

    def resolve_access_origin(self, raw_row: dict) -> str:
        """Derive a compact "who connected from where" string."""
        sign_in = raw_row.get("signInActivity") or {}
        if sign_in.get("lastSignInIpAddress"):
            return f"ip:{sign_in['lastSignInIpAddress']}"
        if raw_row.get("pipelineId"):
            return f"pipeline:{raw_row['pipelineId']}"
        if raw_row.get("workloadName"):
            return f"workload:{raw_row['workloadName']}"
        if raw_row.get("federatedCredentialSubject"):
            return f"federated:{raw_row['federatedCredentialSubject']}"
        return "unknown"

    def resolve_sensitive_resource_type(self, resource: dict) -> ResourceType:
        """Map an Azure resource type string to :class:`ResourceType`."""
        raw_type = str(resource.get("type") or "").lower()
        if raw_type in _AZURE_RESOURCE_TYPE_MAP:
            return _AZURE_RESOURCE_TYPE_MAP[raw_type]
        # Fall back to a best-effort prefix match so unknown sub-types still
        # land in the closest canonical bucket.
        for prefix, canonical in _AZURE_RESOURCE_TYPE_MAP.items():
            if raw_type.startswith(prefix):
                return canonical
        return ResourceType.IAM_SYSTEM

    # ------------------------------------------------------------------
    # Role assignment processing
    # ------------------------------------------------------------------

    async def build_role_assignments(
        self,
        organization_id: str,
        connector_id: int,
        identity_id: str,
        raw_assignments: Iterable[dict],
    ) -> list[RoleAssignment]:
        """Normalize Azure role rows into :class:`RoleAssignment` list.

        Each assignment embeds a :class:`RoleUsage` computed from the most
        recent ARM activity within its scope:

        * ``used = True`` if an ARM log entry is observed within
          :data:`ROLE_USAGE_RECENCY_DAYS` days of the scan time.
        * ``confidence = high`` when ARM-log evidence exists,
          ``inferred`` otherwise.
        """
        assignments: list[RoleAssignment] = []
        recency_cutoff = datetime.now(timezone.utc) - timedelta(
            days=ROLE_USAGE_RECENCY_DAYS
        )

        for raw in raw_assignments:
            try:
                scope = str(raw.get("scope") or "/")
                scope_level = self._scope_to_breadth(scope)
                role_source = self.resolve_role_source(raw)
                role_key = str(raw.get("roleDefinitionId") or raw.get("role_key") or "").lower()
                role_name = str(raw.get("roleDefinitionName") or raw.get("role_name") or "unknown")

                try:
                    last_activity = await self._deps.arm_get_last_activity(
                        connector_id, identity_id, scope
                    )
                except Exception as exc:  # noqa: BLE001
                    raise ARMAPIError(
                        "failed to fetch ARM activity for role assignment",
                        context={
                            "organization_id": organization_id,
                            "identity_id": identity_id,
                            "scope": scope,
                        },
                    ) from exc

                used = last_activity is not None and last_activity >= recency_cutoff
                if last_activity is not None:
                    confidence = Confidence.HIGH
                    evidence = f"arm_activity_log@{last_activity.isoformat()}"
                else:
                    confidence = Confidence.INFERRED
                    evidence = "no_arm_activity_observed"

                usage = RoleUsage(
                    organization_id=organization_id,
                    used=used,
                    confidence=confidence,
                    evidence=evidence,
                )

                assignments.append(
                    RoleAssignment(
                        organization_id=organization_id,
                        role_name=role_name,
                        role_key=role_key,
                        scope=scope,
                        scope_level=scope_level,
                        source=role_source,
                        usage=usage,
                    )
                )
            except ARMAPIError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "azure.role_assignment identity=%s scope=%s error=%s",
                    identity_id,
                    raw.get("scope"),
                    exc,
                )
                # Per-assignment failure — skip and continue the scan.
                continue

        return assignments

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_microsoft_first_party(spn: dict) -> bool:
        tenant_id = str(spn.get("appOwnerOrganizationId") or "").lower()
        if tenant_id in {t.lower() for t in MICROSOFT_TENANT_IDS}:
            return True
        tags = spn.get("tags") or []
        return "WindowsAzureActiveDirectoryIntegratedApp" in tags and tenant_id in {
            t.lower() for t in MICROSOFT_TENANT_IDS
        }

    @staticmethod
    def _status_from_user(user: dict) -> IdentityStatus:
        if user.get("accountEnabled") is False:
            return IdentityStatus.DISABLED
        return IdentityStatus.ACTIVE

    @staticmethod
    def _status_from_spn(spn: dict) -> IdentityStatus:
        if spn.get("accountEnabled") is False:
            return IdentityStatus.DISABLED
        return IdentityStatus.ACTIVE

    @staticmethod
    def _scope_to_breadth(scope: str) -> ScopeBreadth:
        """Map an Azure scope path to a canonical :class:`ScopeBreadth`.

        Most-specific marker wins: a path that contains both
        ``/resourcegroups/`` and a later ``/providers/<namespace>/`` segment
        resolves to :attr:`ScopeBreadth.RESOURCE`.
        """
        normalized = scope.lower().rstrip("/") + "/"

        if _SCOPE_MANAGEMENT_GROUP_MARKER in normalized:
            return ScopeBreadth.TENANT_WIDE

        rg_index = normalized.find(_SCOPE_RESOURCE_GROUP_MARKER)
        if rg_index >= 0:
            # Resource-group scope unless a provider path sits below the RG.
            tail = normalized[rg_index + len(_SCOPE_RESOURCE_GROUP_MARKER):]
            if _SCOPE_RESOURCE_PROVIDER_MARKER.lstrip("/") in tail:
                return ScopeBreadth.RESOURCE
            return ScopeBreadth.RESOURCE_GROUP

        if normalized.startswith(_SCOPE_SUBSCRIPTION_MARKER):
            return ScopeBreadth.SUBSCRIPTION

        return ScopeBreadth.RESOURCE


# ---------------------------------------------------------------------------
# Module-local helpers
# ---------------------------------------------------------------------------


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Parse Azure ISO-8601 datetimes into timezone-aware ``datetime``.

    Returns ``None`` for missing or unparseable values rather than raising —
    discovery must be tolerant of sparsely populated Graph responses.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def _live_context() -> DataContext:
    """Build a fresh live-mode :class:`DataContext` for a just-discovered row."""
    return DataContext(
        data_mode=DataMode.LIVE,
        snapshot_id=None,
        snapshot_date=None,
        computed_at=datetime.now(timezone.utc),
        is_stale=False,
    )
